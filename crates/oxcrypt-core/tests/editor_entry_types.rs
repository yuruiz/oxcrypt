#![cfg(feature = "async")]
use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};

fn vault() -> (tempfile::TempDir, VaultOperationsAsync) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = VaultOperationsAsync::open(&path, "test-password").unwrap();
    (temp, ops)
}

#[tokio::test]
async fn pending_creation_cannot_merge_with_directory_or_symlink() {
    let (_temp, ops) = vault();
    let root = DirId::root();
    for long in [false, true] {
        for directory in [false, true] {
            let name = if long {
                "x".repeat(200)
            } else {
                "short".into()
            };
            let editor = ops.edit_file(&root, &name, true, false).await.unwrap();
            editor.lock().write(0, b"pending").unwrap();
            if directory {
                ops.create_directory(&root, &name).await.unwrap();
            } else {
                ops.create_symlink(&root, &name, "destination")
                    .await
                    .unwrap();
            }
            assert!(
                ops.commit_editor(&root, &name, editor.clone())
                    .await
                    .is_err()
            );
            assert_eq!(editor.lock().read(0, 7).unwrap(), b"pending");
            assert!(ops.find_file(&root, &name).await.unwrap().is_none());
            if directory {
                assert!(ops.find_directory(&root, &name).await.unwrap().is_some());
                ops.delete_directory(&root, &name).await.unwrap();
            } else {
                assert_eq!(ops.read_symlink(&root, &name).await.unwrap(), "destination");
                ops.delete_symlink(&root, &name).await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn competing_creators_keep_the_first_committed_file() {
    let (_temp, ops) = vault();
    let root = DirId::root();
    let name = "x".repeat(200);
    let first = ops.edit_file(&root, &name, true, false).await.unwrap();
    let second = ops.edit_file(&root, &name, true, false).await.unwrap();
    first.lock().write(0, b"first").unwrap();
    second.lock().write(0, b"second").unwrap();
    ops.commit_editor(&root, &name, first).await.unwrap();
    assert!(
        ops.commit_editor(&root, &name, second.clone())
            .await
            .is_err()
    );
    assert_eq!(ops.read_file(&root, &name).await.unwrap().content, b"first");
    assert_eq!(second.lock().read(0, 6).unwrap(), b"second");
}

#[tokio::test]
async fn stale_commit_does_not_leave_an_empty_shortened_entry() {
    let (_temp, ops) = vault();
    let root = DirId::root();
    let name = "x".repeat(200);
    ops.write_file(&root, &name, b"original").await.unwrap();
    let editor = ops.edit_file(&root, &name, false, false).await.unwrap();
    editor.lock().write(0, b"changed!").unwrap();
    ops.delete_file(&root, &name).await.unwrap();
    assert!(ops.commit_editor(&root, &name, editor).await.is_err());
    let fresh = ops.edit_file(&root, &name, true, false).await.unwrap();
    fresh.lock().write(0, b"fresh").unwrap();
    ops.commit_editor(&root, &name, fresh).await.unwrap();
    assert_eq!(ops.read_file(&root, &name).await.unwrap().content, b"fresh");
}
