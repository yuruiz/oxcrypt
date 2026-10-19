use bytes::Bytes;
use dav_server::{
    davpath::DavPath,
    fs::{DavFileSystem, OpenOptions},
};
use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};
use oxcrypt_webdav::{CryptomatorWebDav, ServerConfig, WebDavServer};
use std::sync::Arc;

fn vault() -> (tempfile::TempDir, Arc<VaultOperationsAsync>) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "test-password").unwrap());
    (temp, ops)
}

#[tokio::test]
async fn stop_retries_retained_failed_writeback() {
    let (temp, ops) = vault();
    let path = ops
        .write_file(&DirId::root(), "note", b"original")
        .await
        .unwrap();
    let fs = CryptomatorWebDav::new(Arc::clone(&ops))
        .with_recovery_directory(temp.path().join("recovery"));
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
        .write_bytes(Bytes::from_static(b"retained"))
        .await
        .unwrap();
    let backup = path.with_extension("test-backup");
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(writer.flush().await.is_err());
    drop(writer);
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(backup, &path).unwrap();
    let mut server = WebDavServer::start(fs, ServerConfig::default())
        .await
        .unwrap();
    server.stop().await.unwrap();
    assert_eq!(
        ops.read_file(&DirId::root(), "note").await.unwrap().content,
        b"retained"
    );
}

#[tokio::test]
async fn stop_saves_encrypted_recovery_and_reports_its_location() {
    let (temp, ops) = vault();
    let recovery = temp.path().join("recovery");
    let path = ops
        .write_file(&DirId::root(), "note", b"original")
        .await
        .unwrap();
    let fs = CryptomatorWebDav::new(Arc::clone(&ops)).with_recovery_directory(&recovery);
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
        .write_bytes(Bytes::from_static(b"retained"))
        .await
        .unwrap();
    std::fs::rename(&path, path.with_extension("backup")).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(writer.flush().await.is_err());
    drop(writer);
    let mut server = WebDavServer::start(fs, ServerConfig::default())
        .await
        .unwrap();
    let error = server.stop().await.unwrap_err();
    assert!(error.to_string().contains("encrypted recovery:"));
    let saved: Vec<_> = std::fs::read_dir(&recovery)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(saved.len(), 1);
    let output = temp.path().join("recovered");
    oxcrypt_core::fs::recovery::export(&saved[0], ops.master_key(), &output).unwrap();
    assert_eq!(std::fs::read(output).unwrap(), b"retained");
    server.stop().await.unwrap();
}

#[tokio::test]
async fn failed_recovery_keeps_buffers_for_a_shutdown_retry() {
    let (temp, ops) = vault();
    let recovery = temp.path().join("unavailable-recovery");
    std::fs::write(&recovery, b"obstruction").unwrap();
    let path = ops
        .write_file(&DirId::root(), "note", b"original")
        .await
        .unwrap();
    let fs = CryptomatorWebDav::new(Arc::clone(&ops)).with_recovery_directory(&recovery);
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
        .write_bytes(Bytes::from_static(b"retained"))
        .await
        .unwrap();
    let backup = path.with_extension("backup");
    std::fs::rename(&path, &backup).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(writer.flush().await.is_err());
    drop(writer);
    let mut server = WebDavServer::start(fs, ServerConfig::default())
        .await
        .unwrap();
    assert!(
        server
            .stop()
            .await
            .unwrap_err()
            .to_string()
            .contains("edits retained for retry")
    );
    std::fs::remove_dir(&path).unwrap();
    std::fs::rename(backup, &path).unwrap();
    server.stop().await.unwrap();
    assert_eq!(
        ops.read_file(&DirId::root(), "note").await.unwrap().content,
        b"retained"
    );
}

#[tokio::test]
async fn graceful_stop_waits_for_an_inflight_http_upload() {
    let (temp, ops) = vault();
    let fs = CryptomatorWebDav::new(Arc::clone(&ops))
        .with_recovery_directory(temp.path().join("recovery"));
    let stats = fs.stats();
    let mut server = WebDavServer::start(fs, ServerConfig::default())
        .await
        .unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(2);
    let stream = futures::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|bytes| (Ok::<_, std::io::Error>(bytes), receiver))
    });
    let url = format!("{}/note", server.url());
    let upload = tokio::spawn(async move {
        reqwest::Client::new()
            .put(url)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .unwrap()
    });
    sender.send(Bytes::from_static(b"first-")).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while stats.bytes_written() < 6 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let stop = server.stop();
    tokio::pin!(stop);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut stop)
            .await
            .is_err()
    );
    sender.send(Bytes::from_static(b"second")).await.unwrap();
    drop(sender);
    assert!(upload.await.unwrap().status().is_success());
    stop.await.unwrap();
    assert_eq!(
        ops.read_file(&DirId::root(), "note").await.unwrap().content,
        b"first-second"
    );
}

#[tokio::test]
async fn interrupted_upload_is_archived_without_replacing_original() {
    let (temp, ops) = vault();
    ops.write_file(&DirId::root(), "note", b"original")
        .await
        .unwrap();
    let recovery = temp.path().join("recovery");
    let fs = CryptomatorWebDav::new(Arc::clone(&ops)).with_recovery_directory(&recovery);
    let stats = fs.stats();
    let config = ServerConfig {
        shutdown_timeout: std::time::Duration::from_millis(200),
        ..ServerConfig::default()
    };
    let mut server = WebDavServer::start(fs, config).await.unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(2);
    let stream = futures::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|bytes| (Ok::<_, std::io::Error>(bytes), receiver))
    });
    let url = format!("{}/note", server.url());
    let upload = tokio::spawn(async move {
        reqwest::Client::new()
            .put(url)
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
    });
    sender.send(Bytes::from_static(b"partial")).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while stats.bytes_written() < 7 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(server.stop().await.is_err());
    drop(sender);
    let _ = upload.await.unwrap();
    assert_eq!(
        ops.read_file(&DirId::root(), "note").await.unwrap().content,
        b"original"
    );
    let saved = std::fs::read_dir(recovery)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let output = temp.path().join("recovered");
    oxcrypt_core::fs::recovery::export(&saved, ops.master_key(), &output).unwrap();
    assert_eq!(std::fs::read(output).unwrap(), b"partial");
}

#[tokio::test]
async fn disconnected_partial_upload_is_not_published_during_shutdown() {
    use tokio::io::AsyncWriteExt;
    let (temp, ops) = vault();
    ops.write_file(&DirId::root(), "note", b"original")
        .await
        .unwrap();
    let recovery = temp.path().join("recovery");
    let fs = CryptomatorWebDav::new(Arc::clone(&ops)).with_recovery_directory(&recovery);
    let stats = fs.stats();
    let mut server = WebDavServer::start(fs, ServerConfig::default())
        .await
        .unwrap();
    let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    stream
        .write_all(b"PUT /note HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\npartial")
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while stats.bytes_written() < 7 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stream.shutdown().await.unwrap();
    drop(stream);
    assert!(server.stop().await.is_err());
    assert_eq!(
        ops.read_file(&DirId::root(), "note").await.unwrap().content,
        b"original"
    );
    let saved = std::fs::read_dir(recovery)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let output = temp.path().join("recovered");
    oxcrypt_core::fs::recovery::export(&saved, ops.master_key(), &output).unwrap();
    assert_eq!(std::fs::read(output).unwrap(), b"partial");
}
