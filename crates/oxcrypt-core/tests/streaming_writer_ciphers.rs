#![cfg(feature = "async")]
use oxcrypt_core::{
    crypto::keys::MasterKey,
    vault::{DirId, VaultOperationsAsync, config::CipherCombo},
};
use std::sync::Arc;

#[tokio::test]
async fn vault_streaming_writer_uses_the_configured_cipher() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let temp = tempfile::tempdir().unwrap();
        let key = Arc::new(MasterKey::random().unwrap());
        let ops = VaultOperationsAsync::with_options(temp.path(), Arc::clone(&key), 220, cipher);
        for size in [0, 1, 32767, 32768, 32769, 131089] {
            let expected: Vec<u8> = (0..size)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            let name = format!("file-{size}");
            let mut writer = ops.create_file(&DirId::root(), &name).await.unwrap();
            for part in expected.chunks(17003) {
                writer.write(part).await.unwrap();
            }
            let path = writer.finish().await.unwrap();
            let encrypted = std::fs::read(path).unwrap();
            assert_eq!(
                cipher.decrypt_file(&encrypted, &key).unwrap().content,
                expected
            );
            assert_eq!(
                ops.read_file(&DirId::root(), &name).await.unwrap().content,
                expected
            );
            if size == 0 {
                assert_eq!(
                    encrypted.len(),
                    if cipher == CipherCombo::SivGcm {
                        68
                    } else {
                        88
                    }
                );
            }
        }
    }
}

#[tokio::test]
async fn large_buffered_write_and_shortened_names_use_the_configured_cipher() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let temp = tempfile::tempdir().unwrap();
        let key = Arc::new(MasterKey::random().unwrap());
        let ops = VaultOperationsAsync::with_options(temp.path(), Arc::clone(&key), 220, cipher);
        let data = vec![42; 2 * 1024 * 1024 + 3];
        let name = "x".repeat(200);
        let path = ops.write_file(&DirId::root(), &name, &data).await.unwrap();
        assert_eq!(
            cipher
                .decrypt_file(&std::fs::read(path).unwrap(), &key)
                .unwrap()
                .content,
            data
        );
        let mut reader = ops.open_file_unlocked(&DirId::root(), &name).await.unwrap();
        assert_eq!(reader.read_range(32760, 40).await.unwrap(), vec![42; 40]);
    }
}
