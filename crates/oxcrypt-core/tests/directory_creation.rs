use oxcrypt_core::vault::{DirId, VaultCreator};

#[test]
fn duplicate_sync_mkdir_preserves_directory_identity_and_children() {
    let temp = tempfile::tempdir().unwrap();
    let ops = VaultCreator::new(&temp.path().join("vault"), "test-password")
        .create()
        .unwrap();
    let root = DirId::root();
    for name in ["short".to_owned(), "x".repeat(200)] {
        let original = ops.create_directory(&root, &name).unwrap();
        ops.write_file(&original, "child", b"preserved").unwrap();
        assert!(ops.create_directory(&root, &name).is_err());
        assert_eq!(
            ops.find_directory(&root, &name)
                .unwrap()
                .unwrap()
                .directory_id,
            original
        );
        assert_eq!(
            ops.read_file(&original, "child").unwrap().content,
            b"preserved"
        );
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn duplicate_async_mkdir_preserves_directory_identity_and_children() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    let root = DirId::root();
    for name in ["short".to_owned(), "x".repeat(200)] {
        let original = ops.create_directory(&root, &name).await.unwrap();
        ops.write_file(&original, "child", b"preserved")
            .await
            .unwrap();
        assert!(ops.create_directory(&root, &name).await.is_err());
        assert_eq!(
            ops.find_directory(&root, &name)
                .await
                .unwrap()
                .unwrap()
                .directory_id,
            original
        );
        assert_eq!(
            ops.read_file(&original, "child").await.unwrap().content,
            b"preserved"
        );
    }
}

#[test]
fn sync_mkdir_cannot_adopt_a_file_or_symlink_entry() {
    let temp = tempfile::tempdir().unwrap();
    let ops = VaultCreator::new(&temp.path().join("vault"), "test-password")
        .create()
        .unwrap();
    let root = DirId::root();
    for name in ["short".to_owned(), "x".repeat(200)] {
        ops.write_file(&root, &name, b"preserved").unwrap();
        assert!(ops.create_directory(&root, &name).is_err());
        assert_eq!(ops.read_file(&root, &name).unwrap().content, b"preserved");
        assert!(ops.find_directory(&root, &name).unwrap().is_none());
        ops.delete_file(&root, &name).unwrap();
        ops.create_symlink(&root, &name, "target").unwrap();
        assert!(ops.create_directory(&root, &name).is_err());
        assert_eq!(ops.read_symlink(&root, &name).unwrap(), "target");
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn async_mkdir_cannot_adopt_a_file_or_symlink_entry() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    let root = DirId::root();
    for name in ["short".to_owned(), "x".repeat(200)] {
        ops.write_file(&root, &name, b"preserved").await.unwrap();
        assert!(ops.create_directory(&root, &name).await.is_err());
        assert_eq!(
            ops.read_file(&root, &name).await.unwrap().content,
            b"preserved"
        );
        assert!(ops.find_directory(&root, &name).await.unwrap().is_none());
        ops.delete_file(&root, &name).await.unwrap();
        ops.create_symlink(&root, &name, "target").await.unwrap();
        assert!(ops.create_directory(&root, &name).await.is_err());
        assert_eq!(ops.read_symlink(&root, &name).await.unwrap(), "target");
    }
}
