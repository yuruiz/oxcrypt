#![cfg(feature = "async")]
use oxcrypt_core::{
    crypto::keys::MasterKey,
    vault::{DirId, VaultOperationsAsync, config::CipherCombo},
};
use std::{
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

#[tokio::test]
async fn exact_creation_metadata_is_published_with_the_authenticated_file() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let temp = tempfile::tempdir().unwrap();
        let ops = VaultOperationsAsync::with_options(
            temp.path(),
            Arc::new(MasterKey::random().unwrap()),
            220,
            cipher,
        );
        let root = DirId::root();
        for name in ["file".to_owned(), "x".repeat(200)] {
            let editor = ops.edit_file(&root, &name, true, false).await.unwrap();
            let accessed = UNIX_EPOCH + Duration::new(u64::from(u32::MAX), 100_000_000);
            let modified = UNIX_EPOCH + Duration::new(0, 200_000_000);
            editor
                .lock()
                .set_initial_times_exact(accessed, modified)
                .unwrap();
            assert!(ops.find_file(&root, &name).await.unwrap().is_none());
            let path = ops.commit_editor(&root, &name, editor).await.unwrap();
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!(metadata.accessed().unwrap(), accessed);
            assert_eq!(metadata.modified().unwrap(), modified);
            let existing = ops.edit_file(&root, &name, false, false).await.unwrap();
            assert_eq!(
                existing
                    .lock()
                    .set_initial_times_exact(accessed, modified)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::AlreadyExists
            );
            assert!(
                ops.read_file(&root, &name)
                    .await
                    .unwrap()
                    .content
                    .is_empty()
            );
        }
    }
}
