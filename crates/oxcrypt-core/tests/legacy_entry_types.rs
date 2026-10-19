use oxcrypt_core::vault::{DirId, VaultCreator};

#[test]
fn sync_long_file_write_cannot_adopt_directory_or_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let ops = VaultCreator::new(&temp.path().join("vault"), "test-password")
        .create()
        .unwrap();
    let root = DirId::root();
    let directory_name = "d".repeat(200);
    let directory = ops.create_directory(&root, &directory_name).unwrap();
    ops.write_file(&directory, "child", b"preserved").unwrap();
    assert!(
        ops.write_file(&root, &directory_name, b"wrong type")
            .is_err()
    );
    assert_eq!(
        ops.find_directory(&root, &directory_name)
            .unwrap()
            .unwrap()
            .directory_id,
        directory
    );
    assert_eq!(
        ops.read_file(&directory, "child").unwrap().content,
        b"preserved"
    );
    let link = "s".repeat(200);
    ops.create_symlink(&root, &link, "target").unwrap();
    assert!(ops.write_file(&root, &link, b"wrong type").is_err());
    assert_eq!(ops.read_symlink(&root, &link).unwrap(), "target");
}

#[cfg(feature = "async")]
#[tokio::test]
async fn buffered_and_streaming_writes_reject_incompatible_entries() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    let root = DirId::root();
    let directory_name = "d".repeat(200);
    let directory = ops.create_directory(&root, &directory_name).await.unwrap();
    let link = "s".repeat(200);
    ops.create_symlink(&root, &link, "target").await.unwrap();
    for name in [&directory_name, &link] {
        assert!(ops.write_file(&root, name, b"wrong type").await.is_err());
        assert!(ops.create_file(&root, name).await.is_err());
        assert!(
            ops.write_file(&root, name, &vec![7; 1024 * 1024])
                .await
                .is_err()
        );
    }
    assert_eq!(
        ops.find_directory(&root, &directory_name)
            .await
            .unwrap()
            .unwrap()
            .directory_id,
        directory
    );
    assert_eq!(ops.read_symlink(&root, &link).await.unwrap(), "target");
}

#[cfg(feature = "async")]
#[tokio::test]
async fn legacy_directory_and_symlink_renames_preserve_other_entry_types() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    let root = DirId::root();
    let directory = ops.create_directory(&root, "directory").await.unwrap();
    ops.write_file(&directory, "child", b"preserved")
        .await
        .unwrap();
    ops.create_symlink(&root, "link", "target").await.unwrap();
    assert!(
        ops.rename_directory(&root, "directory", "link")
            .await
            .is_err()
    );
    assert!(
        ops.rename_symlink(&root, "link", "directory")
            .await
            .is_err()
    );
    assert_eq!(ops.read_symlink(&root, "link").await.unwrap(), "target");
    assert_eq!(
        ops.read_file(&directory, "child").await.unwrap().content,
        b"preserved"
    );
}
