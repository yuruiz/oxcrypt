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

#[test]
fn concurrent_reads_on_one_handle_complete_without_eagain() {
    if std::env::var_os("OXCRYPT_TEST_TRACE").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                "oxcrypt_fuse::filesystem=trace,oxcrypt_core::vault::operations_async=debug",
            )
            .with_test_writer()
            .try_init();
    }
    use std::os::unix::fs::FileExt;
    use std::sync::{Arc, Barrier};
    let vault = TempVault::new();
    let mount_dir = tempfile::tempdir().unwrap();
    let mount = FuseBackend::new()
        .mount(
            "oxcrypt-read-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let data: Arc<Vec<u8>> = Arc::new(
        (0..(4 * 1024 * 1024))
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect(),
    );
    let path = mount.mountpoint().join("large");
    fs::write(&path, data.as_slice()).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), data.len() as u64);
    let file = Arc::new(fs::File::open(path).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|thread| {
            let file = Arc::clone(&file);
            let data = Arc::clone(&data);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for iteration in 0..64 {
                    let offset = (thread * 23131 + iteration * 16381) % (data.len() - 4096);
                    let mut bytes = [0; 4096];
                    file.read_exact_at(&mut bytes, offset as u64).unwrap();
                    assert_eq!(bytes.as_slice(), &data[offset..offset + bytes.len()]);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    drop(file);
    mount.unmount().unwrap();
}

#[test]
fn open_writer_follows_rename_across_directories_and_remount() {
    use std::os::unix::fs::FileExt;
    let vault = TempVault::new();
    let mount_dir = tempfile::tempdir().unwrap();
    let backend = FuseBackend::new();
    let mount = backend
        .mount(
            "oxcrypt-rename-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let root = mount.mountpoint();
    fs::create_dir(root.join("destination")).unwrap();
    fs::write(root.join("before"), b"original").unwrap();
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("before"))
        .unwrap();
    fs::rename(root.join("before"), root.join("middle")).unwrap();
    file.write_all_at(b"FIRST!!!", 0).unwrap();
    file.sync_all().unwrap();
    fs::rename(root.join("middle"), root.join("destination/after")).unwrap();
    file.write_all_at(b"UPDATED!", 0).unwrap();
    file.sync_all().unwrap();
    drop(file);
    mount.unmount().unwrap();
    let mount = backend
        .mount(
            "oxcrypt-rename-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let root = mount.mountpoint();
    let content = fs::read(root.join("destination/after")).unwrap();
    let old_exists = root.join("before").exists() || root.join("middle").exists();
    mount.unmount().unwrap();
    assert_eq!(content, b"UPDATED!");
    assert!(!old_exists);
}

#[test]
fn failed_replacement_preserves_target_after_remount() {
    let vault = TempVault::new();
    let mount_dir = tempfile::tempdir().unwrap();
    let backend = FuseBackend::new();
    let mount = backend
        .mount(
            "oxcrypt-replace-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let root = mount.mountpoint();
    fs::write(root.join("source"), b"new").unwrap();
    fs::write(root.join("target"), b"must survive").unwrap();
    fs::metadata(root.join("source")).unwrap();
    let ops =
        oxcrypt_core::vault::VaultOperations::open(vault.path(), TempVault::password()).unwrap();
    let source = ops
        .find_file(&oxcrypt_core::vault::DirId::root(), "source")
        .unwrap()
        .unwrap();
    fs::remove_file(source.encrypted_path).unwrap();
    let rename = fs::rename(root.join("source"), root.join("target"));
    mount.unmount().unwrap();
    let mount = backend
        .mount(
            "oxcrypt-replace-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let result = fs::read(mount.mountpoint().join("target"));
    mount.unmount().unwrap();
    assert!(rename.is_err());
    assert_eq!(result.unwrap(), b"must survive");
}

#[test]
fn replaced_open_writer_cannot_overwrite_replacement() {
    use std::os::unix::fs::FileExt;
    let vault = TempVault::new();
    let mount_dir = tempfile::tempdir().unwrap();
    let backend = FuseBackend::new();
    let mount = backend
        .mount(
            "oxcrypt-orphan-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let root = mount.mountpoint();
    fs::write(root.join("target"), b"old target").unwrap();
    fs::write(root.join("source"), b"saved version").unwrap();
    let old = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("target"))
        .unwrap();
    fs::rename(root.join("source"), root.join("target")).unwrap();
    old.write_all_at(b"orphan", 0).unwrap();
    old.sync_all().unwrap();
    drop(old);
    mount.unmount().unwrap();
    let mount = backend
        .mount(
            "oxcrypt-orphan-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let result = fs::read(mount.mountpoint().join("target"));
    mount.unmount().unwrap();
    assert_eq!(result.unwrap(), b"saved version");
}

#[test]
fn unlinked_open_file_is_independent_of_recreated_name() {
    use std::os::unix::fs::FileExt;
    let vault = TempVault::new();
    let mount_dir = tempfile::tempdir().unwrap();
    let mount = FuseBackend::new()
        .mount(
            "oxcrypt-unlink-test",
            vault.path(),
            TempVault::password(),
            mount_dir.path(),
        )
        .unwrap();
    let path = mount.mountpoint().join("note");
    fs::write(&path, b"old data").unwrap();
    let old = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"new data").unwrap();
    old.write_all_at(b"orphan!!", 0).unwrap();
    old.sync_all().unwrap();
    let mut actual = [0; 8];
    old.read_exact_at(&mut actual, 0).unwrap();
    drop(old);
    let visible = fs::read(&path).unwrap();
    mount.unmount().unwrap();
    assert_eq!(&actual, b"orphan!!");
    assert_eq!(visible, b"new data");
}
