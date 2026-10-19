use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};
use oxcrypt_webdav::{CryptomatorWebDav, ServerConfig, WebDavServer};
use std::sync::Arc;

fn url(base: &str, components: &[&str]) -> reqwest::Url {
    let mut url = reqwest::Url::parse(base).unwrap();
    url.path_segments_mut().unwrap().clear().extend(components);
    url
}

#[tokio::test]
async fn http_and_native_vault_operations_share_unicode_and_literal_percent_names() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    VaultCreator::new(&path, "test-password").create().unwrap();
    let ops = Arc::new(VaultOperationsAsync::open(&path, "test-password").unwrap());
    let server = WebDavServer::start(
        CryptomatorWebDav::new(Arc::clone(&ops)),
        ServerConfig::default(),
    )
    .await
    .unwrap();
    let client = reqwest::Client::new();
    let root = DirId::root();
    for name in ["résumé 笔记.txt", "100% complete.txt", "x#?+.txt"] {
        ops.write_file(&root, name, b"native").await.unwrap();
        let source = url(&server.url(), &[name]);
        let response = client.get(source.clone()).send().await.unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "cannot read native name {name}"
        );
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"native");
        assert!(
            client
                .put(source.clone())
                .body("webdav")
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert_eq!(ops.read_file(&root, name).await.unwrap().content, b"webdav");
        let moved = format!("{name}.moved");
        let destination = url(&server.url(), &[&moved]);
        assert!(
            client
                .request(reqwest::Method::from_bytes(b"MOVE").unwrap(), source)
                .header("Destination", destination.as_str())
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
        );
        assert_eq!(
            ops.read_file(&root, &moved).await.unwrap().content,
            b"webdav"
        );
        assert!(ops.find_file(&root, name).await.unwrap().is_none());
    }
    let directory = ops.create_directory(&root, "目录 空间").await.unwrap();
    ops.write_file(&directory, "name%.txt", b"nested")
        .await
        .unwrap();
    let response = client
        .get(url(&server.url(), &["目录 空间", "name%.txt"]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"nested");
    server.stop().await;
}
