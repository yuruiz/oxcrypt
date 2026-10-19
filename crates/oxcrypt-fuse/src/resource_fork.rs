//! Resource-fork entry updates that preserve opaque AppleDouble metadata offsets.
use std::ops::Range;

pub(crate) const MAX_SIDECAR_SIZE: usize = 64 * 1024 * 1024;

struct Layout {
    descriptor: usize,
    resource: Range<usize>,
    metadata_end: usize,
}

fn number(bytes: &[u8], offset: usize) -> Result<u32, i32> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(libc::EINVAL)?
            .try_into()
            .map_err(|_| libc::EINVAL)?,
    ))
}

fn layout(bytes: &[u8]) -> Result<Layout, i32> {
    if bytes.len() > MAX_SIDECAR_SIZE {
        return Err(libc::E2BIG);
    }
    if number(bytes, 0)? != 0x0005_1607 || number(bytes, 4)? != 0x0002_0000 {
        return Err(libc::EINVAL);
    }
    let count = usize::from(u16::from_be_bytes(
        bytes
            .get(24..26)
            .ok_or(libc::EINVAL)?
            .try_into()
            .map_err(|_| libc::EINVAL)?,
    ));
    let table_end = 26 + count * 12;
    if table_end > bytes.len() {
        return Err(libc::EINVAL);
    }
    let mut resource = None;
    let mut metadata_end = table_end;
    let mut ranges = Vec::new();
    for index in 0..count {
        let descriptor = 26 + index * 12;
        let id = number(bytes, descriptor)?;
        let start = usize::try_from(number(bytes, descriptor + 4)?).map_err(|_| libc::E2BIG)?;
        let len = usize::try_from(number(bytes, descriptor + 8)?).map_err(|_| libc::E2BIG)?;
        let end = start.checked_add(len).ok_or(libc::EINVAL)?;
        if start < table_end || end > bytes.len() {
            return Err(libc::EINVAL);
        }
        if len > 0 {
            if ranges
                .iter()
                .any(|other: &Range<usize>| start < other.end && other.start < end)
            {
                return Err(libc::EINVAL);
            }
            ranges.push(start..end);
        }
        if id == 2 {
            if resource.replace((descriptor, start..end)).is_some() {
                return Err(libc::EINVAL);
            }
        } else {
            metadata_end = metadata_end.max(end);
        }
    }
    let (descriptor, resource) = resource.ok_or(libc::EINVAL)?;
    Ok(Layout {
        descriptor,
        resource,
        metadata_end,
    })
}

pub(crate) fn empty() -> Vec<u8> {
    let mut bytes = vec![0; 82];
    bytes[0..4].copy_from_slice(&0x0005_1607u32.to_be_bytes());
    bytes[4..8].copy_from_slice(&0x0002_0000u32.to_be_bytes());
    bytes[8..24].copy_from_slice(b"Mac OS X        ");
    bytes[24..26].copy_from_slice(&2u16.to_be_bytes());
    for (index, id, offset, len) in [(26, 9u32, 50u32, 32u32), (38, 2, 82, 0)] {
        bytes[index..index + 4].copy_from_slice(&id.to_be_bytes());
        bytes[index + 4..index + 8].copy_from_slice(&offset.to_be_bytes());
        bytes[index + 8..index + 12].copy_from_slice(&len.to_be_bytes());
    }
    bytes
}

fn is_empty_placeholder(value: &[u8]) -> bool {
    if value.len() != 286 {
        return false;
    }
    let mut empty = [0u8; 286];
    for (offset, number) in [
        (0, 256u32),
        (4, 256),
        (12, 30),
        (256, 256),
        (260, 256),
        (268, 30),
    ] {
        empty[offset..offset + 4].copy_from_slice(&number.to_be_bytes());
    }
    let tag = b"This resource fork intentionally left blank   ";
    empty[16..16 + tag.len()].copy_from_slice(tag);
    empty[280..282].copy_from_slice(&28u16.to_be_bytes());
    empty[282..284].copy_from_slice(&30u16.to_be_bytes());
    empty[284..286].copy_from_slice(&u16::MAX.to_be_bytes());
    value == empty
}

pub(crate) fn resource(bytes: &[u8]) -> Result<&[u8], i32> {
    let layout = layout(bytes)?;
    let value = &bytes[layout.resource];
    // AppleDouble represents an absent resource fork with a canonical placeholder.
    Ok(if is_empty_placeholder(value) {
        &value[..0]
    } else {
        value
    })
}

pub(crate) fn replace(bytes: &[u8], value: &[u8], position: u32) -> Result<Vec<u8>, i32> {
    let layout = layout(bytes)?;
    let existing = resource(bytes)?;
    let position = usize::try_from(position).map_err(|_| libc::E2BIG)?;
    let end = position.checked_add(value.len()).ok_or(libc::E2BIG)?;
    let length = if position == 0 {
        end
    } else {
        end.max(existing.len())
    };
    let offset = layout.resource.start.max(layout.metadata_end);
    let total = offset.checked_add(length).ok_or(libc::E2BIG)?;
    if total > MAX_SIDECAR_SIZE {
        return Err(libc::E2BIG);
    }
    let mut output = Vec::new();
    output.try_reserve_exact(total).map_err(|_| libc::ENOMEM)?;
    output.extend_from_slice(&bytes[..offset]);
    output.resize(total, 0);
    if position != 0 {
        output[offset..offset + existing.len()].copy_from_slice(existing);
    }
    output[offset + position..offset + end].copy_from_slice(value);
    let descriptor = layout.descriptor;
    output[descriptor + 4..descriptor + 8].copy_from_slice(
        &u32::try_from(offset)
            .map_err(|_| libc::E2BIG)?
            .to_be_bytes(),
    );
    output[descriptor + 8..descriptor + 12].copy_from_slice(
        &u32::try_from(length)
            .map_err(|_| libc::E2BIG)?
            .to_be_bytes(),
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use crate::resource_fork::*;
    #[test]
    fn replacing_and_positioned_writes_preserve_finder_info() {
        let mut bytes = empty();
        bytes[50..82].fill(7);
        let bytes = replace(&bytes, b"abcdef", 0).unwrap();
        let bytes = replace(&bytes, b"XY", 3).unwrap();
        assert_eq!(resource(&bytes).unwrap(), b"abcXYf");
        assert_eq!(&bytes[50..82], &[7; 32]);
        let bytes = replace(&bytes, b"z", 0).unwrap();
        assert_eq!(resource(&bytes).unwrap(), b"z");
        assert!(
            resource(&replace(&bytes, b"", 0).unwrap())
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn rejects_malformed_and_oversized_entries() {
        for len in 0..82 {
            assert!(resource(&empty()[..len]).is_err());
        }
        let mut overlap = empty();
        overlap[42..46].copy_from_slice(&50u32.to_be_bytes());
        overlap[46..50].copy_from_slice(&10u32.to_be_bytes());
        assert_eq!(resource(&overlap), Err(libc::EINVAL));
        assert_eq!(replace(&empty(), b"x", u32::MAX), Err(libc::E2BIG));
    }
}
