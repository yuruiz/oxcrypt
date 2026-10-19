use nfsserve::{
    nfs::{filename3, nfstime3, sattr3, set_atime, set_mtime, set_size3},
    vfs::NFSFileSystem,
};
use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};
use oxcrypt_nfs::CryptomatorNFS;
use std::sync::Arc;

fn name(value: &str) -> filename3 {
    value.as_bytes().to_vec().into()
}

#[tokio::test]
async fn explicit_times_survive_resize_and_server_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "test-password").unwrap());
    ops.write_file(&DirId::root(), "file", b"data")
        .await
        .unwrap();
    let nfs = CryptomatorNFS::new(Arc::clone(&ops));
    let id = nfs.lookup(nfs.root_dir(), &name("file")).await.unwrap();
    let times = sattr3 {
        size: set_size3::size(17),
        atime: set_atime::SET_TO_CLIENT_TIME(nfstime3 {
            seconds: 946684700,
            nseconds: 123_000_000,
        }),
        mtime: set_mtime::SET_TO_CLIENT_TIME(nfstime3 {
            seconds: 946684800,
            nseconds: 456_000_000,
        }),
        ..sattr3::default()
    };
    let updated = nfs.setattr(id, times).await.unwrap();
    assert_eq!(updated.size, 17);
    assert_eq!(
        (updated.atime.seconds, updated.atime.nseconds),
        (946684700, 123_000_000)
    );
    assert_eq!(
        (updated.mtime.seconds, updated.mtime.nseconds),
        (946684800, 456_000_000)
    );
    let reopened = CryptomatorNFS::new(Arc::clone(&ops));
    let id = reopened
        .lookup(reopened.root_dir(), &name("file"))
        .await
        .unwrap();
    let saved = reopened.getattr(id).await.unwrap();
    assert_eq!(
        (saved.atime.seconds, saved.atime.nseconds),
        (946684700, 123_000_000)
    );
    assert_eq!(
        (saved.mtime.seconds, saved.mtime.nseconds),
        (946684800, 456_000_000)
    );
    let content = ops.read_file(&DirId::root(), "file").await.unwrap().content;
    assert_eq!(&content[..4], b"data");
    assert!(content[4..].iter().all(|byte| *byte == 0));
}

#[tokio::test]
async fn invalid_timestamp_does_not_apply_resize() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "test-password").unwrap());
    ops.write_file(&DirId::root(), "file", b"preserved")
        .await
        .unwrap();
    let nfs = CryptomatorNFS::new(Arc::clone(&ops));
    let id = nfs.lookup(nfs.root_dir(), &name("file")).await.unwrap();
    let result = nfs
        .setattr(
            id,
            sattr3 {
                size: set_size3::size(0),
                mtime: set_mtime::SET_TO_CLIENT_TIME(nfstime3 {
                    seconds: 1,
                    nseconds: 1_000_000_000,
                }),
                ..sattr3::default()
            },
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        ops.read_file(&DirId::root(), "file").await.unwrap().content,
        b"preserved"
    );
}

#[tokio::test]
async fn creation_and_non_file_timestamps_are_persisted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "test-password").unwrap());
    let nfs = CryptomatorNFS::new(ops);
    let requested = sattr3 {
        atime: set_atime::SET_TO_CLIENT_TIME(nfstime3 {
            seconds: 946684700,
            nseconds: 0,
        }),
        mtime: set_mtime::SET_TO_CLIENT_TIME(nfstime3 {
            seconds: 946684800,
            nseconds: 0,
        }),
        ..sattr3::default()
    };
    let (file, attr) = nfs
        .create(
            nfs.root_dir(),
            &name("file"),
            sattr3 {
                size: set_size3::size(9),
                ..requested
            },
        )
        .await
        .unwrap();
    assert_eq!(attr.size, 9);
    assert_eq!(attr.mtime.seconds, 946684800);
    let (directory, _) = nfs.mkdir(nfs.root_dir(), &name("directory")).await.unwrap();
    let (link, attr) = nfs
        .symlink(
            nfs.root_dir(),
            &name("link"),
            &b"target".to_vec().into(),
            &requested,
        )
        .await
        .unwrap();
    assert_eq!(attr.mtime.seconds, 946684800);
    for id in [directory, link] {
        let attr = nfs.setattr(id, requested).await.unwrap();
        assert_eq!(attr.atime.seconds, 946684700);
        assert_eq!(attr.mtime.seconds, 946684800);
        assert_eq!(nfs.getattr(id).await.unwrap().mtime.seconds, 946684800);
    }
    let attr = nfs
        .setattr(
            file,
            sattr3 {
                atime: set_atime::SET_TO_SERVER_TIME,
                ..sattr3::default()
            },
        )
        .await
        .unwrap();
    assert!(attr.atime.seconds > 946684800);
    assert_eq!(
        attr.mtime.seconds, 946684800,
        "DONT_CHANGE must preserve mtime"
    );
    let written = nfs.write(file, 0, b"changed").await.unwrap();
    assert!(written.mtime.seconds > 946684800);
    assert_eq!(written.atime.seconds, attr.atime.seconds);
}
