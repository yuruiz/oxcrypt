//! Strict end-to-end checks using only newly created vaults and mountpoints.
#![cfg(all(target_os = "macos", feature = "fuse-tests"))]

use oxcrypt_fuse::FuseBackend;
use oxcrypt_mount::{MountBackend, testing::TempVault};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
};

#[test]
fn edits_atomic_save_and_long_names_survive_remount() {
    let vault = TempVault::new();
    let mount_dir = tempfile::tempdir().unwrap();
    let backend = FuseBackend::new();
    let mount = backend
        .mount(
            "oxcrypt-macos-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let root = mount.mountpoint();
    fs::create_dir(root.join("notes")).unwrap();
    let path = root.join("notes/large.bin");
    let mut expected: Vec<u8> = (0..(2 * 1024 * 1024 + 17))
        .map(|i| (i % 251) as u8)
        .collect();
    eprintln!("write large file: {}", path.display());
    fs::write(&path, &expected).unwrap();
    eprintln!("edit large file");
    {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let edit = b"edited across an encryption chunk boundary";
        file.seek(SeekFrom::Start(32760)).unwrap();
        file.write_all(edit).unwrap();
        expected[32760..32760 + edit.len()].copy_from_slice(edit);
        file.sync_all().unwrap();
    }
    eprintln!("atomic save");
    fs::write(root.join("notes/note.md"), b"old note").unwrap();
    {
        let mut file = fs::File::create(root.join("notes/note.tmp")).unwrap();
        file.write_all(b"saved note").unwrap();
        file.sync_all().unwrap();
    }
    fs::rename(root.join("notes/note.tmp"), root.join("notes/note.md")).unwrap();
    eprintln!("long filename");
    let long_name = format!("{}-笔记.md", "a".repeat(180));
    fs::write(root.join("notes").join(&long_name), b"long unicode name").unwrap();
    eprintln!("directory rename");
    fs::rename(root.join("notes"), root.join("archive")).unwrap();
    fs::File::open(root.join("archive"))
        .unwrap()
        .sync_all()
        .unwrap();
    eprintln!("unmount");
    mount.unmount().unwrap();

    let mount = backend
        .mount(
            "oxcrypt-macos-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let root = mount.mountpoint();
    assert_eq!(fs::read(root.join("archive/large.bin")).unwrap(), expected);
    assert_eq!(
        fs::read(root.join("archive/note.md")).unwrap(),
        b"saved note"
    );
    assert_eq!(
        fs::read(root.join("archive").join(&long_name)).unwrap(),
        b"long unicode name"
    );
    assert!(!root.join("notes").exists());
    assert!(!root.join("archive/note.tmp").exists());
    eprintln!("unmount");
    mount.unmount().unwrap();
}
