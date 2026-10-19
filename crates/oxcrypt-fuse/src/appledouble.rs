//! macOS AppleDouble FinderInfo, resource forks and packed ATTR entries.
//! Layout follows Apple's copyfile.c attr_header_t and attr_entry_t.
use crate::resource_fork::{MAX_SIDECAR_SIZE, empty, resource};
use std::collections::BTreeMap;
pub(crate) const FINDER: &str = "com.apple.FinderInfo";
pub(crate) const RESOURCE: &str = "com.apple.ResourceFork";

fn u32_at(bytes: &[u8], offset: usize) -> Result<usize, i32> {
    let value = u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(libc::EINVAL)?
            .try_into()
            .map_err(|_| libc::EINVAL)?,
    );
    usize::try_from(value).map_err(|_| libc::E2BIG)
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<usize, i32> {
    Ok(usize::from(u16::from_be_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(libc::EINVAL)?
            .try_into()
            .map_err(|_| libc::EINVAL)?,
    )))
}
fn put(bytes: &mut [u8], offset: usize, value: usize) -> Result<(), i32> {
    bytes[offset..offset + 4]
        .copy_from_slice(&u32::try_from(value).map_err(|_| libc::E2BIG)?.to_be_bytes());
    Ok(())
}

pub(crate) fn decode(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, i32> {
    if u16_at(bytes, 24)? != 2 {
        return Err(libc::EINVAL);
    }
    let fork = resource(bytes)?;
    let finder_descriptor = [26, 38]
        .into_iter()
        .find(|offset| u32_at(bytes, *offset).ok() == Some(9))
        .ok_or(libc::EINVAL)?;
    let begin = u32_at(bytes, finder_descriptor + 4)?;
    let end = begin
        .checked_add(u32_at(bytes, finder_descriptor + 8)?)
        .ok_or(libc::EINVAL)?;
    let finder = bytes
        .get(begin..begin + 32)
        .filter(|_| begin + 32 <= end)
        .ok_or(libc::EINVAL)?;
    let mut attributes = BTreeMap::new();
    if finder.iter().any(|value| *value != 0) {
        attributes.insert(FINDER.into(), finder.to_vec());
    }
    if !fork.is_empty() {
        attributes.insert(RESOURCE.into(), fork.to_vec());
    }
    let header = begin + 34;
    if end < header + 36 {
        return Ok(attributes);
    }
    if u32_at(bytes, header)? != 0x4154_5452 {
        return Err(libc::EINVAL);
    }
    let total = u32_at(bytes, header + 8)?;
    let data_start = u32_at(bytes, header + 12)?;
    let data_end = data_start
        .checked_add(u32_at(bytes, header + 16)?)
        .ok_or(libc::EINVAL)?;
    if total > bytes.len() || data_end > total || data_end > end || data_start < header + 36 {
        return Err(libc::EINVAL);
    }
    let count = u16_at(bytes, header + 34)?;
    let mut cursor = header + 36;
    let mut ranges = Vec::<std::ops::Range<usize>>::new();
    for _ in 0..count {
        let offset = u32_at(bytes, cursor)?;
        let length = u32_at(bytes, cursor + 4)?;
        let name_len = usize::from(*bytes.get(cursor + 10).ok_or(libc::EINVAL)?);
        let next = cursor
            .checked_add((11 + name_len + 3) & !3)
            .ok_or(libc::EINVAL)?;
        if name_len < 2 || next > data_start || next > 65536 + 18 {
            return Err(libc::EINVAL);
        }
        let name = bytes
            .get(cursor + 11..cursor + 11 + name_len)
            .ok_or(libc::EINVAL)?;
        if name.last() != Some(&0) || name[..name.len() - 1].contains(&0) {
            return Err(libc::EINVAL);
        }
        let name = std::str::from_utf8(&name[..name.len() - 1]).map_err(|_| libc::EINVAL)?;
        let limit = offset.checked_add(length).ok_or(libc::EINVAL)?;
        if offset < data_start
            || limit > data_end
            || ranges
                .iter()
                .any(|range| offset < range.end && range.start < limit)
        {
            return Err(libc::EINVAL);
        }
        if name == FINDER
            || name == RESOURCE
            || attributes
                .insert(name.into(), bytes[offset..limit].to_vec())
                .is_some()
        {
            return Err(libc::EINVAL);
        }
        if length > 0 {
            ranges.push(offset..limit);
        }
        cursor = next;
    }
    Ok(attributes)
}

pub(crate) fn encode(attributes: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, i32> {
    let finder = attributes.get(FINDER);
    if finder.is_some_and(|value| value.len() != 32) {
        return Err(libc::EINVAL);
    }
    let fork = attributes.get(RESOURCE).map_or(&[][..], Vec::as_slice);
    let ordinary: Vec<_> = attributes
        .iter()
        .filter(|(name, _)| name.as_str() != FINDER && name.as_str() != RESOURCE)
        .collect();
    if ordinary.is_empty() {
        let mut bytes = empty();
        if let Some(finder) = finder {
            bytes[50..82].copy_from_slice(finder);
        }
        return crate::resource_fork::replace(&bytes, fork, 0);
    }
    let mut data_start = 120usize;
    for (name, value) in &ordinary {
        if name.is_empty()
            || name.len() >= 128
            || name.as_bytes().contains(&0)
            || value.len() > 16 * 1024 * 1024
        {
            return Err(libc::E2BIG);
        }
        data_start = data_start
            .checked_add((12 + name.len() + 3) & !3)
            .ok_or(libc::E2BIG)?;
    }
    if data_start > 65536 + 18 || ordinary.len() > u16::MAX as usize {
        return Err(libc::E2BIG);
    }
    let total = ordinary.iter().try_fold(data_start, |sum, (_, value)| {
        sum.checked_add(value.len()).ok_or(libc::E2BIG)
    })?;
    let size = total.checked_add(fork.len()).ok_or(libc::E2BIG)?;
    if size > MAX_SIDECAR_SIZE {
        return Err(libc::E2BIG);
    }
    let mut bytes = vec![0; size];
    bytes[..82].copy_from_slice(&empty());
    if let Some(finder) = finder {
        bytes[50..82].copy_from_slice(finder);
    }
    put(&mut bytes, 34, total - 50)?;
    put(&mut bytes, 42, total)?;
    put(&mut bytes, 46, fork.len())?;
    put(&mut bytes, 84, 0x4154_5452)?;
    put(&mut bytes, 92, total)?;
    put(&mut bytes, 96, data_start)?;
    put(&mut bytes, 100, total - data_start)?;
    bytes[118..120].copy_from_slice(
        &u16::try_from(ordinary.len())
            .map_err(|_| libc::E2BIG)?
            .to_be_bytes(),
    );
    let mut cursor = 120;
    let mut offset = data_start;
    for (name, value) in ordinary {
        put(&mut bytes, cursor, offset)?;
        put(&mut bytes, cursor + 4, value.len())?;
        bytes[cursor + 10] = u8::try_from(name.len() + 1).map_err(|_| libc::E2BIG)?;
        bytes[cursor + 11..cursor + 11 + name.len()].copy_from_slice(name.as_bytes());
        bytes[offset..offset + value.len()].copy_from_slice(value);
        offset += value.len();
        cursor += (12 + name.len() + 3) & !3;
    }
    bytes[total..].copy_from_slice(fork);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use crate::appledouble::*;
    #[test]
    fn round_trip_finder_resource_and_attributes() {
        let mut attributes = BTreeMap::new();
        attributes.insert(FINDER.into(), vec![7; 32]);
        attributes.insert(RESOURCE.into(), vec![8; 70000]);
        attributes.insert("user.empty".into(), Vec::new());
        attributes.insert("user.note".into(), b"metadata".to_vec());
        let encoded = encode(&attributes).unwrap();
        assert_eq!(decode(&encoded).unwrap(), attributes);
        attributes.remove(RESOURCE);
        assert_eq!(decode(&encode(&attributes).unwrap()).unwrap(), attributes);
    }
    #[test]
    fn malformed_offsets_are_rejected() {
        let mut attributes = BTreeMap::new();
        attributes.insert("user.test".into(), vec![1; 4]);
        let mut bytes = encode(&attributes).unwrap();
        put(&mut bytes, 120, usize::MAX.min(u32::MAX as usize)).unwrap();
        assert!(decode(&bytes).is_err());
    }
    #[test]
    fn apple_tools_accept_output_and_their_output_is_decoded() {
        use std::{fs, io::Read, process::Command};
        let root = tempfile::tempdir().unwrap();
        let payload = root.path().join("payload");
        fs::create_dir(&payload).unwrap();
        let file = payload.join("note");
        fs::write(&file, b"data fork").unwrap();
        let mut attributes = BTreeMap::new();
        attributes.insert(FINDER.into(), vec![7; 32]);
        attributes.insert(RESOURCE.into(), vec![8; 70000]);
        attributes.insert("user.note".into(), b"metadata".to_vec());
        fs::write(payload.join("._note"), encode(&attributes).unwrap()).unwrap();
        let result = Command::new("/usr/sbin/dot_clean")
            .args(["-m", "--keep=dotbar"])
            .arg(&payload)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        for (name, expected) in &attributes {
            let result = Command::new("/usr/bin/xattr")
                .args(["-px", name])
                .arg(&file)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let hex: String = String::from_utf8(result.stdout)
                .unwrap()
                .split_whitespace()
                .collect();
            let bytes: Vec<_> = (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                .collect();
            assert_eq!(&bytes, expected);
        }
        let archive_path = root.path().join("metadata.zip");
        let result = Command::new("/usr/bin/ditto")
            .args(["-c", "-k", "--sequesterRsrc"])
            .arg(&payload)
            .arg(&archive_path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let mut archive = zip::ZipArchive::new(fs::File::open(archive_path).unwrap()).unwrap();
        let mut found = false;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).unwrap();
            if entry.name().unwrap().ends_with("/._note") {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                let decoded = decode(&bytes).unwrap();
                for (name, value) in &attributes {
                    assert_eq!(decoded.get(name), Some(value));
                }
                found = true;
            }
        }
        assert!(found, "ditto must emit an AppleDouble companion");
    }
}
