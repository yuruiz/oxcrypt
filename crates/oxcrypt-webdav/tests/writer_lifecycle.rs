use bytes::Bytes;
use dav_server::{
    davpath::DavPath,
    fs::{DavFileSystem, OpenOptions},
};
use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};
use oxcrypt_webdav::CryptomatorWebDav;
use std::{sync::Arc, time::Duration};

fn vault() -> (tempfile::TempDir, Arc<VaultOperationsAsync>) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "review-password")
        .create()
        .unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "review-password").unwrap());
    (temp, ops)
}

#[tokio::test]
async fn reopening_must_not_discard_failed_webdav_writeback() {
    let (_temp, ops) = vault();
    let root = DirId::root();
    let path = ops.write_file(&root, "note", b"old").await.unwrap();
    let fs = CryptomatorWebDav::new(Arc::clone(&ops));
    let dav_path = DavPath::new("/note").unwrap();
    let mut first = fs
        .open(
            &dav_path,
            OpenOptions {
                write: true,
                truncate: true,
                ..OpenOptions::default()
            },
        )
        .await
        .unwrap();
    first
        .write_bytes(Bytes::from_static(b"pending"))
        .await
        .unwrap();
    let backup = path.with_extension("review-backup");
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(first.flush().await.is_err());
    drop(first);
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    let second = fs
        .open(
            &dav_path,
            OpenOptions {
                write: true,
                ..OpenOptions::default()
            },
        )
        .await
        .unwrap();
    drop(second);
    fs.rename(&dav_path, &DavPath::new("/moved").unwrap())
        .await
        .unwrap();
    assert_eq!(
        ops.read_file(&root, "moved").await.unwrap().content,
        b"pending"
    );
}

#[tokio::test]
async fn writes_after_a_flush_remain_recoverable_after_drop() {
    let (_temp, ops) = vault();
    let path = ops
        .write_file(&DirId::root(), "note", b"old")
        .await
        .unwrap();
    let fs = CryptomatorWebDav::new(Arc::clone(&ops));
    let dav_path = DavPath::new("/note").unwrap();
    let mut writer = fs
        .open(
            &dav_path,
            OpenOptions {
                write: true,
                ..OpenOptions::default()
            },
        )
        .await
        .unwrap();
    writer
        .write_bytes(Bytes::from_static(b"first"))
        .await
        .unwrap();
    writer.flush().await.unwrap();
    writer.seek(std::io::SeekFrom::Start(0)).await.unwrap();
    writer
        .write_bytes(Bytes::from_static(b"later"))
        .await
        .unwrap();
    let backup = path.with_extension("test-backup");
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(writer.flush().await.is_err());
    drop(writer);
    // A new writer must not replace the still-uncommittable edits.
    assert!(
        fs.open(
            &dav_path,
            OpenOptions {
                write: true,
                ..OpenOptions::default()
            }
        )
        .await
        .is_err()
    );
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    let mut reader = fs
        .open(
            &dav_path,
            OpenOptions {
                read: true,
                ..OpenOptions::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(reader.read_bytes(5).await.unwrap().as_ref(), b"later");
}

#[tokio::test]
async fn same_path_writers_serialize_without_blocking_unrelated_uploads() {
    let (_temp, ops) = vault();
    let fs = CryptomatorWebDav::new(Arc::clone(&ops));
    let path = DavPath::new("/note").unwrap();
    let mut first = fs
        .open(
            &path,
            OpenOptions {
                write: true,
                create: true,
                ..OpenOptions::default()
            },
        )
        .await
        .unwrap();
    first
        .write_bytes(Bytes::from_static(b"first"))
        .await
        .unwrap();
    let next = fs.open(
        &path,
        OpenOptions {
            write: true,
            ..OpenOptions::default()
        },
    );
    tokio::pin!(next);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut next)
            .await
            .is_err()
    );
    let other_path = DavPath::new("/other").unwrap();
    let other = tokio::time::timeout(
        Duration::from_secs(2),
        fs.open(
            &other_path,
            OpenOptions {
                write: true,
                create: true,
                ..OpenOptions::default()
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    drop(other);
    drop(first);
    let mut second = tokio::time::timeout(Duration::from_secs(2), next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.read_bytes(5).await.unwrap().as_ref(), b"first");
    second.seek(std::io::SeekFrom::Start(0)).await.unwrap();
    second
        .write_bytes(Bytes::from_static(b"later"))
        .await
        .unwrap();
    second.flush().await.unwrap();
    assert_eq!(
        ops.read_file(&DirId::root(), "note").await.unwrap().content,
        b"later"
    );
}

#[tokio::test]
async fn directory_move_waits_for_upload_and_persists_abandoned_edits() {
    let (_temp, ops) = vault();
    let a = ops.create_directory(&DirId::root(), "a").await.unwrap();
    let fs = CryptomatorWebDav::new(Arc::clone(&ops));
    let path = DavPath::new("/a/note").unwrap();
    let mut writer = fs
        .open(
            &path,
            OpenOptions {
                write: true,
                create: true,
                ..OpenOptions::default()
            },
        )
        .await
        .unwrap();
    writer
        .write_bytes(Bytes::from_static(b"retained"))
        .await
        .unwrap();
    let source = DavPath::new("/a").unwrap();
    let destination = DavPath::new("/moved").unwrap();
    let rename = fs.rename(&source, &destination);
    tokio::pin!(rename);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut rename)
            .await
            .is_err()
    );
    drop(writer);
    tokio::time::timeout(Duration::from_secs(2), rename)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ops.find_directory(&DirId::root(), "moved")
            .await
            .unwrap()
            .unwrap()
            .directory_id,
        a
    );
    assert_eq!(
        ops.read_file(&a, "note").await.unwrap().content,
        b"retained"
    );
}
