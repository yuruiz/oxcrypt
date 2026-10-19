use oxcrypt_core::{
    crypto::keys::MasterKey,
    vault::{DirId, VaultOperations, config::CipherCombo},
};

#[test]
fn sync_symlinks_use_the_vault_cipher() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let temp = tempfile::tempdir().unwrap();
        let ops =
            VaultOperations::with_options(temp.path(), MasterKey::random().unwrap(), 220, cipher);
        for name in ["link".to_owned(), "x".repeat(200)] {
            let target = "../资料/报告.txt";
            ops.create_symlink(&DirId::root(), &name, target).unwrap();
            let info = ops.find_symlink(&DirId::root(), &name).unwrap().unwrap();
            let raw = std::fs::read(info.encrypted_path.join("symlink.c9r")).unwrap();
            assert_eq!(
                cipher.decrypt_file(&raw, ops.master_key()).unwrap().content,
                target.as_bytes()
            );
            assert_eq!(ops.read_symlink(&DirId::root(), &name).unwrap(), target);
        }
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn async_symlinks_read_native_cipher_and_write_compatible_payloads() {
    use oxcrypt_core::vault::VaultOperationsAsync;
    use std::sync::Arc;
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let temp = tempfile::tempdir().unwrap();
        let key = Arc::new(MasterKey::random().unwrap());
        let ops = VaultOperationsAsync::with_options(temp.path(), Arc::clone(&key), 220, cipher);
        for name in ["link".to_owned(), "x".repeat(200)] {
            let target = "../资料/报告.txt";
            ops.create_symlink(&DirId::root(), &name, target)
                .await
                .unwrap();
            let info = ops
                .find_symlink(&DirId::root(), &name)
                .await
                .unwrap()
                .unwrap();
            let payload = info.encrypted_path.join("symlink.c9r");
            let raw = std::fs::read(&payload).unwrap();
            assert_eq!(
                cipher.decrypt_file(&raw, &key).unwrap().content,
                target.as_bytes()
            );
            let native = cipher.encrypt_file(b"../native-target", &key).unwrap();
            std::fs::write(&payload, native).unwrap();
            assert_eq!(
                ops.read_symlink(&DirId::root(), &name).await.unwrap(),
                "../native-target"
            );
        }
    }
}

#[test]
fn authenticated_gcm_symlink_compatibility_never_accepts_tampering() {
    use oxcrypt_core::fs::symlink::{decrypt_symlink_target_with_cipher, encrypt_symlink_target};
    let key = MasterKey::random().unwrap();
    let other = MasterKey::random().unwrap();
    let raw = encrypt_symlink_target("../old-target", &key).unwrap();
    assert_eq!(
        decrypt_symlink_target_with_cipher(&raw, &key, CipherCombo::SivCtrMac).unwrap(),
        "../old-target"
    );
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let raw = cipher.encrypt_file(b"../target", &key).unwrap();
        assert!(decrypt_symlink_target_with_cipher(&raw, &other, CipherCombo::SivCtrMac).is_err());
        for index in [20, raw.len() - 1] {
            let mut tampered = raw.clone();
            tampered[index] ^= 1;
            assert!(
                decrypt_symlink_target_with_cipher(&tampered, &key, CipherCombo::SivCtrMac)
                    .is_err()
            );
        }
    }
}
