//! Real macFUSE metadata checks. Mount failures must fail, never silently skip.
#![cfg(all(target_os = "macos", feature = "fuse-tests"))]

use oxcrypt_fuse::FuseBackend;
use oxcrypt_mount::{MountBackend, testing::TempVault};
use std::{fs, path::Path, process::Command};

fn trace_if_requested() {
    if std::env::var_os("OXCRYPT_TEST_TRACE").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                "oxcrypt_fuse::filesystem=trace,oxcrypt_core::vault::operations_async=debug",
            )
            .with_test_writer()
            .try_init();
    }
}

fn xattr(args: &[&str], path: &Path) -> Vec<u8> {
    let output = Command::new("/usr/bin/xattr")
        .args(args)
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "xattr {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn finder_attributes_survive_remount() {
    trace_if_requested();
    let vault = TempVault::new();
    let mount_dir = tempfile::tempdir().unwrap();
    let backend = FuseBackend::new();
    let mount = backend
        .mount(
            "oxcrypt-xattr-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let directory = mount.mountpoint().join("notes");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("note.md");
    fs::write(&path, b"private note").unwrap();
    let tags = "<?xml version=\"1.0\"?><plist version=\"1.0\"><array><string>Red\n6</string></array></plist>";
    let attr = "com.apple.metadata:_kMDItemUserTags";
    xattr(&["-w", attr, tags], &path);
    let first = xattr(&["-p", attr], &path);
    assert!(first.starts_with(tags.as_bytes()));
    let finder_info = "5445585474747874000000000000000000000000000000000000000000000000";
    xattr(&["-wx", "com.apple.FinderInfo", finder_info], &path);
    assert_eq!(
        fs::remove_dir(&directory).unwrap_err().raw_os_error(),
        Some(libc::ENOTEMPTY)
    );
    assert_eq!(xattr(&["-p", attr], &path), first);
    xattr(
        &["-wx", "com.apple.ResourceFork", "00112233aabbccdd"],
        &path,
    );
    xattr(&["-w", "user.oxcrypt.test", "after-resource"], &path);
    let resource = xattr(&["-px", "com.apple.ResourceFork"], &path);
    assert_eq!(
        String::from_utf8_lossy(&resource)
            .split_whitespace()
            .collect::<String>()
            .to_lowercase(),
        "00112233aabbccdd"
    );
    xattr(
        &["-w", "user.oxcrypt.directory", "directory metadata"],
        &directory,
    );
    mount.unmount().unwrap();

    let mount = backend
        .mount(
            "oxcrypt-xattr-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let directory = mount.mountpoint().join("notes");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("note.md");
    assert_eq!(fs::read(&path).unwrap(), b"private note");
    assert_eq!(xattr(&["-p", attr], &path), first);
    assert_eq!(xattr(&["-px", "com.apple.ResourceFork"], &path), resource);
    assert!(xattr(&["-p", "user.oxcrypt.test"], &path).starts_with(b"after-resource"));
    xattr(&["-d", "com.apple.ResourceFork"], &path);
    let hex = String::from_utf8(xattr(&["-px", "com.apple.FinderInfo"], &path)).unwrap();
    assert_eq!(
        hex.split_whitespace().collect::<String>().to_lowercase(),
        finder_info
    );
    xattr(&["-d", attr], &path);
    let list = String::from_utf8(xattr(&[], &path)).unwrap();
    assert!(!list.lines().any(|name| name == attr));
    assert!(
        xattr(&["-p", "user.oxcrypt.directory"], &directory).starts_with(b"directory metadata")
    );
    let renamed = mount.mountpoint().join("renamed-notes");
    fs::rename(&directory, &renamed).unwrap();
    assert!(xattr(&["-p", "user.oxcrypt.directory"], &renamed).starts_with(b"directory metadata"));
    mount.unmount().unwrap();
}

fn resource_set(path: &Path, data: &[u8], position: u32, flags: i32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // The temporary path and borrowed buffers remain valid throughout the syscall.
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"com.apple.ResourceFork".as_ptr(),
            data.as_ptr().cast(),
            data.len(),
            position,
            flags,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn resource_read(path: &Path, position: u32, count: usize) -> std::io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut data = vec![0; count];
    // The output allocation is sized to the supplied length.
    let result = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"com.apple.ResourceFork".as_ptr(),
            data.as_mut_ptr().cast(),
            data.len(),
            position,
            0,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    data.truncate(usize::try_from(result).unwrap());
    Ok(data)
}

#[test]
fn positioned_resource_io_and_rename_preserve_metadata() {
    trace_if_requested();
    let vault = TempVault::new();
    let mount_dir = tempfile::tempdir().unwrap();
    let backend = FuseBackend::new();
    let mount = backend
        .mount(
            "oxcrypt-resource-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let path = mount.mountpoint().join("original");
    fs::write(&path, b"data fork").unwrap();
    let mut expected: Vec<_> = (0..70000).map(|i| u8::try_from(i % 251).unwrap()).collect();
    resource_set(&path, &expected, 0, 2).unwrap();
    assert_eq!(
        resource_set(&path, b"duplicate", 0, 2)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EEXIST)
    );
    resource_set(&path, b"positioned edit", 32763, 0).unwrap();
    expected[32763..32763 + b"positioned edit".len()].copy_from_slice(b"positioned edit");
    assert_eq!(
        resource_read(&path, 32760, 40).unwrap(),
        expected[32760..32800]
    );
    xattr(
        &["-w", "user.oxcrypt.test", "metadata beside resource"],
        &path,
    );
    assert_eq!(resource_read(&path, 0, expected.len()).unwrap(), expected);
    let renamed = mount.mountpoint().join("renamed");
    fs::rename(&path, &renamed).unwrap();
    assert_eq!(
        resource_read(&renamed, 0, expected.len()).unwrap(),
        expected
    );
    assert!(xattr(&["-p", "user.oxcrypt.test"], &renamed).starts_with(b"metadata beside resource"));
    let copied = mount.mountpoint().join("copied");
    let output = Command::new("/bin/cp")
        .arg("-p")
        .arg(&renamed)
        .arg(&copied)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cp: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(resource_read(&copied, 0, expected.len()).unwrap(), expected);
    mount.unmount().unwrap();
    let mount = backend
        .mount(
            "oxcrypt-resource-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    assert_eq!(
        resource_read(&mount.mountpoint().join("renamed"), 0, expected.len()).unwrap(),
        expected
    );
    assert_eq!(
        resource_read(&mount.mountpoint().join("copied"), 0, expected.len()).unwrap(),
        expected
    );
    mount.unmount().unwrap();
}
