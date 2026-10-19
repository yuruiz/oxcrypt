use dav_server::{
    davpath::DavPath,
    fs::{DavFileSystem, ReadDirMeta},
};
use futures::StreamExt;
use oxcrypt_core::{
    crypto::keys::MasterKey,
    vault::{DirId, VaultOperationsAsync, config::CipherCombo},
};
use oxcrypt_webdav::{CryptomatorWebDav, ServerConfig, WebDavServer};
use std::sync::Arc;

#[tokio::test]
async fn configured_cipher_sizes_match_metadata_listings_and_http_ranges() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let temp = tempfile::tempdir().unwrap();
        let ops = Arc::new(VaultOperationsAsync::with_options(
            temp.path(),
            Arc::new(MasterKey::random().unwrap()),
            220,
            cipher,
        ));
        let fs = CryptomatorWebDav::new(Arc::clone(&ops))
            .with_recovery_directory(temp.path().join("recovery"));
        for size in [0, 1, 32768, 32769] {
            let name = format!("file-{size}");
            ops.write_file(&DirId::root(), &name, &vec![42; size])
                .await
                .unwrap();
            assert_eq!(
                fs.metadata(&DavPath::new(&format!("/{name}")).unwrap())
                    .await
                    .unwrap()
                    .len(),
                size as u64
            );
        }
        let mut entries = fs
            .read_dir(&DavPath::new("/").unwrap(), ReadDirMeta::Data)
            .await
            .unwrap();
        while let Some(entry) = entries.next().await {
            let entry = entry.unwrap();
            let name = String::from_utf8(entry.name()).unwrap();
            let size: u64 = name.strip_prefix("file-").unwrap().parse().unwrap();
            assert_eq!(entry.metadata().await.unwrap().len(), size);
        }
        let mut server = WebDavServer::start(fs, ServerConfig::default())
            .await
            .unwrap();
        let client = reqwest::Client::new();
        let url = format!("{}/file-32769", server.url());
        let head = client.head(&url).send().await.unwrap();
        assert_eq!(head.headers()["content-length"], "32769");
        let range = client
            .get(url)
            .header("Range", "bytes=32760-32768")
            .send()
            .await
            .unwrap();
        assert_eq!(range.status(), reqwest::StatusCode::PARTIAL_CONTENT);
        assert_eq!(range.headers()["content-range"], "bytes 32760-32768/32769");
        assert_eq!(range.bytes().await.unwrap().as_ref(), &[42; 9]);
        server.stop().await.unwrap();
    }
}
