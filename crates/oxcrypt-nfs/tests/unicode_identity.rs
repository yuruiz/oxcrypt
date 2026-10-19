use nfsserve::{
    nfs::{filename3, sattr3},
    vfs::NFSFileSystem,
};
use oxcrypt_core::{crypto::keys::MasterKey, vault::VaultOperationsAsync};
use oxcrypt_nfs::CryptomatorNFS;
use std::sync::Arc;

#[tokio::test]
async fn canonically_equivalent_names_share_one_inode_and_pending_edits() {
    let temp = tempfile::tempdir().unwrap();
    let key = Arc::new(MasterKey::random().unwrap());
    let ops = Arc::new(VaultOperationsAsync::new(temp.path(), key));
    let nfs = CryptomatorNFS::new(ops);
    let nfc = filename3::from("café.txt".as_bytes());
    let nfd = filename3::from("cafe\u{301}.txt".as_bytes());
    let (id, _) = nfs
        .create(nfs.root_dir(), &nfc, sattr3::default())
        .await
        .unwrap();
    let alias = nfs.lookup(nfs.root_dir(), &nfd).await.unwrap();
    assert_eq!(id, alias);
    nfs.write(id, 0, b"preserved").await.unwrap();
    nfs.rename(nfs.root_dir(), &nfc, nfs.root_dir(), &nfd)
        .await
        .unwrap();
    assert_eq!(nfs.lookup(nfs.root_dir(), &nfc).await.unwrap(), id);
    assert_eq!(nfs.read(alias, 0, 32).await.unwrap().0, b"preserved");
}
