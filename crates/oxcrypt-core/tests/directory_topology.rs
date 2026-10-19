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
async fn directory_cannot_move_into_itself_or_a_descendant() {
    let (_temp, ops) = vault();
    let root = DirId::root();
    for long in [false, true] {
        let name = if long { "a".repeat(200) } else { "a".into() };
        let a = ops.create_directory(&root, &name).await.unwrap();
        let b = ops.create_directory(&a, "b").await.unwrap();
        ops.write_file(&b, "important", b"preserved").await.unwrap();
        for destination in [&a, &b] {
            assert!(
                ops.rename_entry_atomic(&root, &name, destination, "nested")
                    .await
                    .is_err()
            );
            assert!(
                ops.move_and_rename_directory(&root, &name, destination, "nested")
                    .await
                    .is_err()
            );
            assert_eq!(
                ops.find_directory(&root, &name)
                    .await
                    .unwrap()
                    .unwrap()
                    .directory_id,
                a
            );
            assert_eq!(
                ops.read_file(&b, "important").await.unwrap().content,
                b"preserved"
            );
        }
    }
}

#[tokio::test]
async fn competing_moves_cannot_create_a_cycle() {
    let (_temp, ops) = vault();
    let root = DirId::root();
    let a = ops.create_directory(&root, "a").await.unwrap();
    let b = ops.create_directory(&root, "b").await.unwrap();
    let (left, right) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            ops.rename_entry_atomic(&root, "a", &b, "a"),
            ops.rename_entry_atomic(&root, "b", &a, "b")
        )
    })
    .await
    .unwrap();
    assert_ne!(left.is_ok(), right.is_ok());
    let reachable = ops.list_directories(&root).await.unwrap();
    assert_eq!(reachable.len(), 1);
    assert_eq!(
        ops.list_directories(&reachable[0].directory_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn replacing_an_ancestor_returns_an_error_without_relocking_it() {
    let (_temp, ops) = vault();
    let root = DirId::root();
    let a = ops.create_directory(&root, "a").await.unwrap();
    let b = ops.create_directory(&a, "b").await.unwrap();
    let c = ops.create_directory(&b, "c").await.unwrap();
    for (parent, name) in [(&a, "b"), (&b, "c")] {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ops.rename_entry_atomic(parent, name, &root, "a"),
        )
        .await;
        assert!(result.unwrap().is_err());
    }
    assert_eq!(
        ops.find_directory(&root, "a")
            .await
            .unwrap()
            .unwrap()
            .directory_id,
        a
    );
    ops.write_file(&c, "still-usable", b"intact").await.unwrap();
    assert_eq!(
        ops.read_file(&c, "still-usable").await.unwrap().content,
        b"intact"
    );
}
