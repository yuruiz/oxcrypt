use oxcrypt_core::{
    crypto::keys::MasterKey,
    vault::{DirId, VaultOperations, VaultPath},
};

#[test]
fn vault_paths_and_joins_have_the_same_identity_as_filename_encryption() {
    let a = VaultPath::new("/café/报告");
    let b = VaultPath::root().join("cafe\u{301}").join("报告");
    assert_eq!(a, b);
}

#[test]
fn sync_legacy_rename_accepts_a_decomposed_source_name() {
    let temp = tempfile::tempdir().unwrap();
    let ops = VaultOperations::new(temp.path(), MasterKey::random().unwrap());
    ops.write_file(&DirId::root(), "café", b"preserved")
        .unwrap();
    ops.rename_file(&DirId::root(), "cafe\u{301}", "renamed")
        .unwrap();
    assert_eq!(
        ops.read_file(&DirId::root(), "renamed").unwrap().content,
        b"preserved"
    );
}

#[cfg(feature = "async")]
#[tokio::test]
async fn atomic_rename_to_unicode_alias_preserves_files_and_directory_trees() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    use std::sync::Arc;
    let temp = tempfile::tempdir().unwrap();
    let ops = VaultOperationsAsync::new(temp.path(), Arc::new(MasterKey::random().unwrap()));
    let root = DirId::root();
    for suffix in [String::new(), "x".repeat(180)] {
        let nfc = format!("café{suffix}");
        let nfd = format!("cafe\u{301}{suffix}");
        ops.write_file(&root, &nfc, b"preserved").await.unwrap();
        ops.rename_entry_atomic(&root, &nfc, &root, &nfd)
            .await
            .unwrap();
        assert_eq!(
            ops.read_file(&root, &nfc).await.unwrap().content,
            b"preserved"
        );
        assert!(
            ops.copy_file_ciphertext(&root, &nfc, &root, &nfd)
                .await
                .is_err()
        );
        ops.delete_file(&root, &nfc).await.unwrap();
        let dir = ops.create_directory(&root, &nfc).await.unwrap();
        ops.write_file(&dir, "child", b"tree").await.unwrap();
        ops.rename_entry_atomic(&root, &nfc, &root, &nfd)
            .await
            .unwrap();
        assert_eq!(ops.read_file(&dir, "child").await.unwrap().content, b"tree");
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn unicode_aliases_share_file_locks_and_ordered_acquisition_deduplicates_them() {
    use oxcrypt_core::vault::locks::VaultLockManager;
    use std::{sync::Arc, time::Duration};
    let locks = VaultLockManager::new();
    let root = DirId::root();
    assert!(Arc::ptr_eq(
        &locks.file_lock(&root, "café"),
        &locks.file_lock(&root, "cafe\u{301}")
    ));
    let guards = tokio::time::timeout(
        Duration::from_secs(1),
        locks.lock_files_write_ordered(&root, &["café", "cafe\u{301}"]),
    )
    .await
    .unwrap();
    assert_eq!(guards.len(), 1);
}
