use oxcrypt_core::vault::{DirId, VaultCreator};

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
