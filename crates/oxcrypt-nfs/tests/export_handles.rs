use nfsserve::{
    nfs::{filename3, nfs_fh3, nfsstat3, sattr3},
    vfs::NFSFileSystem,
};
use oxcrypt_core::{crypto::keys::MasterKey, vault::VaultOperationsAsync};
use oxcrypt_nfs::CryptomatorNFS;
use std::sync::Arc;

fn fixture() -> (tempfile::TempDir, Arc<VaultOperationsAsync>, CryptomatorNFS) {
    let temp = tempfile::tempdir().unwrap();
    let ops = Arc::new(VaultOperationsAsync::new(
        temp.path(),
        Arc::new(MasterKey::random().unwrap()),
    ));
    let nfs = CryptomatorNFS::new(Arc::clone(&ops));
    (temp, ops, nfs)
}

#[test]
fn separate_exports_reject_each_others_handles() {
    let (_a, _ops_a, first) = fixture();
    let (_b, _ops_b, second) = fixture();
    let handle = first.id_to_fh(first.root_dir());
    assert_eq!(first.fh_to_id(&handle).unwrap(), first.root_dir());
    assert!(matches!(
        second.fh_to_id(&handle),
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert_ne!(first.serverid(), second.serverid());
}

#[test]
fn remount_rejects_handles_from_previous_instance() {
    let (_temp, ops, first) = fixture();
    let handle = first.id_to_fh(first.root_dir());
    drop(first);
    let remount = CryptomatorNFS::new(ops);
    assert!(matches!(
        remount.fh_to_id(&handle),
        Err(nfsstat3::NFS3ERR_STALE)
    ));
}

#[tokio::test]
async fn valid_handles_roundtrip_and_deleted_handles_become_stale() {
    let (_temp, _ops, nfs) = fixture();
    let name = filename3::from(b"file".to_vec());
    let (id, _) = nfs
        .create(nfs.root_dir(), &name, sattr3::default())
        .await
        .unwrap();
    let handle = nfs.id_to_fh(id);
    assert_eq!(nfs.fh_to_id(&handle).unwrap(), id);
    nfs.remove(nfs.root_dir(), &name).await.unwrap();
    assert!(matches!(
        nfs.fh_to_id(&handle),
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    for len in [0, 1, 16, 25, 64] {
        assert!(matches!(
            nfs.fh_to_id(&nfs_fh3 { data: vec![0; len] }),
            Err(nfsstat3::NFS3ERR_BADHANDLE)
        ));
    }
}
