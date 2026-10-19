use nfsserve::{
    nfs::{filename3, sattr3, set_size3},
    vfs::NFSFileSystem,
};
use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};
use oxcrypt_nfs::CryptomatorNFS;
use std::sync::Arc;

fn fixture() -> (tempfile::TempDir, Arc<VaultOperationsAsync>, CryptomatorNFS) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "test-password").unwrap());
    let nfs = CryptomatorNFS::new(Arc::clone(&ops));
    (temp, ops, nfs)
}

#[tokio::test]
async fn unchecked_create_without_size_preserves_existing_file_and_handle() {
    let (_temp, ops, nfs) = fixture();
    ops.write_file(&DirId::root(), "note", b"preserved")
        .await
        .unwrap();
    let name = filename3::from(b"note".to_vec());
    let original = nfs.lookup(nfs.root_dir(), &name).await.unwrap();
    let (created, attrs) = nfs
        .create(nfs.root_dir(), &name, sattr3::default())
        .await
        .unwrap();
    assert_eq!(created, original);
    assert_eq!(attrs.size, 9);
    assert_eq!(
        ops.read_file(&DirId::root(), "note").await.unwrap().content,
        b"preserved"
    );
}

#[tokio::test]
async fn unchecked_create_applies_only_the_requested_resize() {
    let (_temp, ops, nfs) = fixture();
    ops.write_file(&DirId::root(), "note", b"prefix")
        .await
        .unwrap();
    let name = filename3::from(b"note".to_vec());
    let (id, attrs) = nfs
        .create(
            nfs.root_dir(),
            &name,
            sattr3 {
                size: set_size3::size(12),
                ..sattr3::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(attrs.size, 12);
    assert_eq!(
        ops.read_file(&DirId::root(), "note").await.unwrap().content,
        b"prefix\0\0\0\0\0\0"
    );
    let (same_id, attrs) = nfs
        .create(
            nfs.root_dir(),
            &name,
            sattr3 {
                size: set_size3::size(0),
                ..sattr3::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(same_id, id);
    assert_eq!(attrs.size, 0);
    assert!(
        ops.read_file(&DirId::root(), "note")
            .await
            .unwrap()
            .content
            .is_empty()
    );
}

#[tokio::test]
async fn creating_after_external_deletion_expires_the_old_handle() {
    use nfsserve::nfs::nfsstat3;
    let (_temp, ops, nfs) = fixture();
    ops.write_file(&DirId::root(), "note", b"original")
        .await
        .unwrap();
    let name = filename3::from(b"note".to_vec());
    let old = nfs.lookup(nfs.root_dir(), &name).await.unwrap();
    ops.delete_file(&DirId::root(), "note").await.unwrap();
    let (new, _) = nfs
        .create(nfs.root_dir(), &name, sattr3::default())
        .await
        .unwrap();
    assert_ne!(old, new);
    assert!(matches!(
        nfs.write(old, 0, b"wrong file").await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert!(
        ops.read_file(&DirId::root(), "note")
            .await
            .unwrap()
            .content
            .is_empty()
    );
}
