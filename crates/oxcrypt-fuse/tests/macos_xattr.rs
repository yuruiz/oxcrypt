//! Real macFUSE metadata checks. Mount failures must fail, never silently skip.
#![cfg(all(target_os = "macos", feature = "fuse-tests"))]

use oxcrypt_fuse::FuseBackend;
use oxcrypt_mount::{MountBackend, testing::TempVault};
use std::{fs, path::Path, process::Command};

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
    let hex = String::from_utf8(xattr(&["-px", "com.apple.FinderInfo"], &path)).unwrap();
    assert_eq!(
        hex.split_whitespace().collect::<String>().to_lowercase(),
        finder_info
    );
    xattr(&["-d", attr], &path);
    let list = String::from_utf8(xattr(&[], &path)).unwrap();
    assert!(!list.lines().any(|name| name == attr));
    mount.unmount().unwrap();
}
