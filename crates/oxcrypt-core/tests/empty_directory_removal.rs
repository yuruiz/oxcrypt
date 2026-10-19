use oxcrypt_core::vault::{DirId, VaultCreator};

#[test]
fn lazy_empty_directory_without_content_storage_is_removable() {
    let temp = tempfile::tempdir().unwrap();
    let ops = VaultCreator::new(&temp.path().join("vault"), "test-password")
        .create()
        .unwrap();
    let directory = ops.create_directory(&DirId::root(), "lazy").unwrap();
    let storage = ops.calculate_directory_storage_path(&directory).unwrap();
    std::fs::remove_dir_all(&storage).unwrap();
    let _ = std::fs::remove_dir(storage.parent().unwrap());
    ops.delete_directory(&DirId::root(), "lazy").unwrap();
    assert!(
        ops.find_directory(&DirId::root(), "lazy")
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "async")]
#[tokio::test]
async fn async_lazy_empty_directory_without_content_storage_is_removable() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let sync = VaultCreator::new(&path, "test-password").create().unwrap();
    let directory = sync.create_directory(&DirId::root(), "lazy").unwrap();
    let storage = sync.calculate_directory_storage_path(&directory).unwrap();
    std::fs::remove_dir_all(&storage).unwrap();
    let _ = std::fs::remove_dir(storage.parent().unwrap());
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    ops.delete_directory(&DirId::root(), "lazy").await.unwrap();
    assert!(
        ops.find_directory(&DirId::root(), "lazy")
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn directory_cleanup_does_not_follow_a_storage_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let ops = VaultCreator::new(&temp.path().join("vault"), "test-password")
        .create()
        .unwrap();
    let directory = ops.create_directory(&DirId::root(), "linked").unwrap();
    let storage = ops.calculate_directory_storage_path(&directory).unwrap();
    std::fs::remove_dir_all(&storage).unwrap();
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("dirid.c9r"), b"outside backup").unwrap();
    std::os::unix::fs::symlink(&outside, storage).unwrap();
    assert!(ops.delete_directory(&DirId::root(), "linked").is_err());
    assert_eq!(
        std::fs::read(outside.join("dirid.c9r")).unwrap(),
        b"outside backup"
    );
}

#[test]
fn sync_rmdir_preserves_symlinks_and_unrecognized_entries() {
    let temp = tempfile::tempdir().unwrap();
    let ops = VaultCreator::new(&temp.path().join("vault"), "test-password")
        .create()
        .unwrap();
    let root = DirId::root();
    for name in ["short".to_owned(), "x".repeat(200)] {
        let directory = ops.create_directory(&root, &name).unwrap();
        ops.create_symlink(&directory, "only-child", "target")
            .unwrap();
        assert!(ops.delete_directory(&root, &name).is_err());
        assert_eq!(
            ops.read_symlink(&directory, "only-child").unwrap(),
            "target"
        );
        ops.delete_symlink(&directory, "only-child").unwrap();
        let unknown = ops
            .calculate_directory_storage_path(&directory)
            .unwrap()
            .join("unrecognized");
        std::fs::write(&unknown, b"must not disappear").unwrap();
        assert!(ops.delete_directory(&root, &name).is_err());
        assert_eq!(std::fs::read(&unknown).unwrap(), b"must not disappear");
        std::fs::remove_file(unknown).unwrap();
        ops.delete_directory(&root, &name).unwrap();
        assert!(ops.find_directory(&root, &name).unwrap().is_none());
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn async_rmdir_preserves_symlinks_and_unrecognized_entries() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    let root = DirId::root();
    for name in ["short".to_owned(), "x".repeat(200)] {
        let directory = ops.create_directory(&root, &name).await.unwrap();
        ops.create_symlink(&directory, "only-child", "target")
            .await
            .unwrap();
        assert!(ops.delete_directory(&root, &name).await.is_err());
        assert_eq!(
            ops.read_symlink(&directory, "only-child").await.unwrap(),
            "target"
        );
        ops.delete_symlink(&directory, "only-child").await.unwrap();
        let unknown = ops
            .as_sync()
            .unwrap()
            .calculate_directory_storage_path(&directory)
            .unwrap()
            .join("unrecognized");
        std::fs::write(&unknown, b"must not disappear").unwrap();
        assert!(ops.delete_directory(&root, &name).await.is_err());
        assert_eq!(std::fs::read(&unknown).unwrap(), b"must not disappear");
        std::fs::remove_file(unknown).unwrap();
        ops.delete_directory(&root, &name).await.unwrap();
        assert!(ops.find_directory(&root, &name).await.unwrap().is_none());
    }
}
