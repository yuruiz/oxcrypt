use nfsserve::{nfs::filename3, vfs::NFSFileSystem};
use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};
use oxcrypt_nfs::CryptomatorNFS;
use std::sync::Arc;

fn vault() -> (tempfile::TempDir, Arc<VaultOperationsAsync>, CryptomatorNFS) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "review-password")
        .create()
        .unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "review-password").unwrap());
    let nfs = CryptomatorNFS::new(Arc::clone(&ops));
    (temp, ops, nfs)
}

fn name(value: &str) -> filename3 {
    filename3::from(value.as_bytes().to_vec())
}

#[tokio::test]
async fn cross_directory_move_preserves_source_handle_and_expires_replaced_handle() {
    use nfsserve::nfs::nfsstat3;
    let (_temp, ops, nfs) = vault();
    let root = DirId::root();
    let directory = ops.create_directory(&root, "directory").await.unwrap();
    ops.write_file(&root, "source", b"source").await.unwrap();
    ops.write_file(&directory, "target", b"target")
        .await
        .unwrap();
    let parent = nfs
        .lookup(nfs.root_dir(), &name("directory"))
        .await
        .unwrap();
    let source = nfs.lookup(nfs.root_dir(), &name("source")).await.unwrap();
    let target = nfs.lookup(parent, &name("target")).await.unwrap();
    nfs.rename(nfs.root_dir(), &name("source"), parent, &name("target"))
        .await
        .unwrap();
    assert_eq!(nfs.lookup(parent, &name("target")).await.unwrap(), source);
    assert!(matches!(
        nfs.write(target, 0, b"BAD").await,
        Err(nfsstat3::NFS3ERR_STALE)
    ));
    assert_eq!(nfs.read(source, 0, 6).await.unwrap().0, b"source");
    nfs.write(source, 0, b"edited").await.unwrap();
    assert_eq!(
        ops.read_file(&directory, "target").await.unwrap().content,
        b"edited"
    );
}

#[tokio::test]
async fn moving_directory_updates_cached_descendant_paths() {
    let (_temp, ops, nfs) = vault();
    let root = DirId::root();
    let a = ops.create_directory(&root, "a").await.unwrap();
    let b = ops.create_directory(&a, "b").await.unwrap();
    ops.write_file(&b, "file", b"data").await.unwrap();
    let a_id = nfs.lookup(nfs.root_dir(), &name("a")).await.unwrap();
    let b_id = nfs.lookup(a_id, &name("b")).await.unwrap();
    let file_id = nfs.lookup(b_id, &name("file")).await.unwrap();
    nfs.rename(nfs.root_dir(), &name("a"), nfs.root_dir(), &name("moved"))
        .await
        .unwrap();
    assert_eq!(nfs.lookup(a_id, &name("b")).await.unwrap(), b_id);
    assert_eq!(nfs.lookup(b_id, &name("..")).await.unwrap(), a_id);
    assert_eq!(nfs.lookup(b_id, &name("file")).await.unwrap(), file_id);
    nfs.rename(b_id, &name("file"), a_id, &name("out"))
        .await
        .unwrap();
    nfs.write(file_id, 0, b"edit").await.unwrap();
    assert_eq!(ops.read_file(&a, "out").await.unwrap().content, b"edit");
}

#[tokio::test]
async fn renamed_symlink_handle_follows_its_new_name() {
    let (_temp, ops, nfs) = vault();
    ops.create_symlink(&DirId::root(), "link", "destination")
        .await
        .unwrap();
    let id = nfs.lookup(nfs.root_dir(), &name("link")).await.unwrap();
    nfs.rename(
        nfs.root_dir(),
        &name("link"),
        nfs.root_dir(),
        &name("moved"),
    )
    .await
    .unwrap();
    assert_eq!(nfs.readlink(id).await.unwrap().as_ref(), b"destination");
}

#[tokio::test]
async fn concurrent_renames_and_writes_keep_one_file_identity() {
    let (_temp, ops, nfs) = vault();
    ops.write_file(&DirId::root(), "a", b"data").await.unwrap();
    let id = nfs.lookup(nfs.root_dir(), &name("a")).await.unwrap();
    let rename = async {
        for _ in 0..10 {
            nfs.rename(nfs.root_dir(), &name("a"), nfs.root_dir(), &name("b"))
                .await
                .unwrap();
            nfs.rename(nfs.root_dir(), &name("b"), nfs.root_dir(), &name("a"))
                .await
                .unwrap();
        }
    };
    let write = async {
        for _ in 0..20 {
            nfs.write(id, 0, b"edit").await.unwrap();
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(rename, write);
    })
    .await
    .unwrap();
    assert_eq!(
        ops.read_file(&DirId::root(), "a").await.unwrap().content,
        b"edit"
    );
}

#[tokio::test]
async fn file_handle_after_rename_must_not_write_recreated_old_name() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "review-password")
        .create()
        .unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "review-password").unwrap());
    let root = DirId::root();
    ops.write_file(&root, "old", b"original").await.unwrap();
    let nfs = CryptomatorNFS::new(Arc::clone(&ops));
    let old = filename3::from(b"old".to_vec());
    let new = filename3::from(b"new".to_vec());
    let id = nfs.lookup(nfs.root_dir(), &old).await.unwrap();
    nfs.rename(nfs.root_dir(), &old, nfs.root_dir(), &new)
        .await
        .unwrap();
    ops.write_file(&root, "old", b"innocent").await.unwrap();
    nfs.write(id, 0, b"MODIFIED").await.unwrap();
    let old_data = ops.read_file(&root, "old").await.unwrap().content;
    let renamed_data = ops.read_file(&root, "new").await.unwrap().content;
    assert_eq!(
        old_data, b"innocent",
        "stale file handle wrote old name; renamed file={renamed_data:?}"
    );
    assert_eq!(renamed_data, b"MODIFIED");
}
