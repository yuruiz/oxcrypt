#![cfg(all(unix, feature = "async"))]
use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};

fn vault() -> (tempfile::TempDir, VaultOperationsAsync) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    (temp, ops)
}

#[tokio::test]
async fn replacement_supports_all_filename_representations() {
    let (_temp, ops) = vault();
    for source_long in [false, true] {
        for target_long in [false, true] {
            let source = if source_long {
                "s".repeat(200)
            } else {
                "source".into()
            };
            let target = if target_long {
                "t".repeat(200)
            } else {
                "target".into()
            };
            ops.write_file(&DirId::root(), &source, b"new content")
                .await
                .unwrap();
            ops.write_file(&DirId::root(), &target, b"old content")
                .await
                .unwrap();
            ops.rename_entry_atomic(&DirId::root(), &source, &DirId::root(), &target)
                .await
                .unwrap();
            assert_eq!(
                ops.read_file(&DirId::root(), &target)
                    .await
                    .unwrap()
                    .content,
                b"new content"
            );
            assert!(
                ops.find_file(&DirId::root(), &source)
                    .await
                    .unwrap()
                    .is_none()
            );
            ops.delete_file(&DirId::root(), &target).await.unwrap();
        }
    }
}

#[tokio::test]
async fn missing_source_preserves_target() {
    let (_temp, ops) = vault();
    ops.write_file(&DirId::root(), "target", b"must survive")
        .await
        .unwrap();
    assert!(
        ops.rename_entry_atomic(&DirId::root(), "missing", &DirId::root(), "target")
            .await
            .is_err()
    );
    assert_eq!(
        ops.read_file(&DirId::root(), "target")
            .await
            .unwrap()
            .content,
        b"must survive"
    );
}

#[tokio::test]
async fn directory_replacement_preserves_children_and_rejects_nonempty_target() {
    let (_temp, ops) = vault();
    let source = ops
        .create_directory(&DirId::root(), "source")
        .await
        .unwrap();
    ops.create_directory(&DirId::root(), "target")
        .await
        .unwrap();
    ops.write_file(&source, "child", b"child data")
        .await
        .unwrap();
    ops.rename_entry_atomic(&DirId::root(), "source", &DirId::root(), "target")
        .await
        .unwrap();
    let target = ops
        .find_directory(&DirId::root(), "target")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ops.read_file(&target.directory_id, "child")
            .await
            .unwrap()
            .content,
        b"child data"
    );
    ops.create_directory(&DirId::root(), "other").await.unwrap();
    assert!(
        ops.rename_entry_atomic(&DirId::root(), "other", &DirId::root(), "target")
            .await
            .is_err()
    );
    assert_eq!(
        ops.read_file(&target.directory_id, "child")
            .await
            .unwrap()
            .content,
        b"child data"
    );
}
