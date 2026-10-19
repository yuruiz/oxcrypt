use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperations};

#[test]
fn sync_symlink_create_and_delete_survive_reopening() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let ops = VaultCreator::new(&path, "test-password").create().unwrap();
    for name in ["link".to_owned(), "x".repeat(200)] {
        ops.create_symlink(&DirId::root(), &name, "../资料/报告.txt")
            .unwrap();
        let reopened = VaultOperations::open(&path, "test-password").unwrap();
        assert_eq!(
            reopened.read_symlink(&DirId::root(), &name).unwrap(),
            "../资料/报告.txt"
        );
        reopened.delete_symlink(&DirId::root(), &name).unwrap();
        assert!(ops.find_symlink(&DirId::root(), &name).unwrap().is_none());
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn async_symlink_rename_and_move_preserve_complete_targets() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    let root = DirId::root();
    let directory = ops.create_directory(&root, "directory").await.unwrap();
    let long = "x".repeat(200);
    ops.create_symlink(&root, "link", "../资料/报告.txt")
        .await
        .unwrap();
    ops.rename_symlink(&root, "link", &long).await.unwrap();
    let reopened = VaultOperationsAsync::open(&path, "test-password").unwrap();
    assert_eq!(
        reopened.read_symlink(&root, &long).await.unwrap(),
        "../资料/报告.txt"
    );
    assert!(
        reopened
            .find_symlink(&root, "link")
            .await
            .unwrap()
            .is_none()
    );
    ops.move_and_rename_symlink(&root, &long, &directory, "moved")
        .await
        .unwrap();
    assert_eq!(
        reopened.read_symlink(&directory, "moved").await.unwrap(),
        "../资料/报告.txt"
    );
    assert!(reopened.find_symlink(&root, &long).await.unwrap().is_none());
    assert!(
        ops.move_and_rename_symlink(&directory, "moved", &root, "directory")
            .await
            .is_err()
    );
    assert_eq!(
        reopened.read_symlink(&directory, "moved").await.unwrap(),
        "../资料/报告.txt"
    );
    ops.delete_symlink(&directory, "moved").await.unwrap();
    ops.delete_directory(&root, "directory").await.unwrap();
}
