#![cfg(feature = "async")]
use oxcrypt_core::{
    crypto::keys::MasterKey,
    fs::{
        file, file_ctrmac,
        streaming::{
            VaultFileReader, VaultFileReaderSync, VaultFileWriter, editor::VaultFileEditor,
        },
    },
    vault::config::CipherCombo,
};
use std::fs;

fn legacy_empty(cipher: CipherCombo, key: &MasterKey) -> Vec<u8> {
    let content_key = [7; 32];
    match cipher {
        CipherCombo::SivGcm => {
            use aes_gcm::{
                Aes256Gcm, KeyInit, Nonce,
                aead::{Aead, Payload},
            };
            let mut header = file::encrypt_file_header(&content_key, key).unwrap();
            let mut aad = vec![0; 8];
            aad.extend_from_slice(&header[..12]);
            let nonce = [2; 12];
            let tag = Aes256Gcm::new_from_slice(&content_key)
                .unwrap()
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &[],
                        aad: &aad,
                    },
                )
                .unwrap();
            header.extend_from_slice(&nonce);
            header.extend_from_slice(&tag);
            header
        }
        CipherCombo::SivCtrMac => {
            let mut header = file_ctrmac::encrypt_header(&content_key, key).unwrap();
            let nonce = [2; 16];
            let tag = key
                .with_mac_key(|mac| {
                    let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, mac);
                    let mut hmac = ring::hmac::Context::with_key(&hmac_key);
                    hmac.update(&header[..16]);
                    hmac.update(&[0; 8]);
                    hmac.update(&nonce);
                    hmac.sign().as_ref().to_vec()
                })
                .unwrap();
            header.extend_from_slice(&nonce);
            header.extend_from_slice(&tag);
            header
        }
    }
}

#[tokio::test]
async fn new_empty_files_match_cryptomator_size_rules() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let key = MasterKey::random().unwrap();
        let bytes = cipher.encrypt_file(&[], &key).unwrap();
        assert_eq!(
            bytes.len(),
            if cipher == CipherCombo::SivGcm {
                68
            } else {
                88
            }
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty");
        fs::write(&path, bytes).unwrap();
        assert_eq!(
            VaultFileReaderSync::open_with_cipher(&path, &key, cipher)
                .unwrap()
                .plaintext_size(),
            0
        );
        assert_eq!(
            VaultFileReader::open_with_cipher(&path, &key, cipher)
                .await
                .unwrap()
                .plaintext_size(),
            0
        );
    }
}

#[tokio::test]
async fn streaming_empty_output_is_header_only() {
    let key = MasterKey::random().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("empty");
    VaultFileWriter::create(&path, &key)
        .await
        .unwrap()
        .finish()
        .await
        .unwrap();
    assert_eq!(fs::metadata(path).unwrap().len(), 68);
}

#[tokio::test]
async fn legacy_empty_chunks_are_authenticated_and_explicit_truncate_normalizes_them() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let key = MasterKey::random().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty");
        let original = legacy_empty(cipher, &key);
        fs::write(&path, &original).unwrap();
        assert_eq!(
            VaultFileReaderSync::open_with_cipher(&path, &key, cipher)
                .unwrap()
                .plaintext_size(),
            0
        );
        assert_eq!(
            VaultFileReader::open_with_cipher(&path, &key, cipher)
                .await
                .unwrap()
                .plaintext_size(),
            0
        );
        let mut editor = VaultFileEditor::open(&path, &key, cipher, directory.path()).unwrap();
        editor.resize(0).unwrap();
        editor.commit(&path, directory.path()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            if cipher == CipherCombo::SivGcm {
                68
            } else {
                88
            }
        );
        let mut damaged = original;
        *damaged.last_mut().unwrap() ^= 1;
        fs::write(&path, damaged).unwrap();
        assert!(VaultFileReaderSync::open_with_cipher(&path, &key, cipher).is_err());
        assert!(
            VaultFileReader::open_with_cipher(&path, &key, cipher)
                .await
                .is_err()
        );
    }
}
