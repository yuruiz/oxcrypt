#![cfg(feature = "async")]
use oxcrypt_core::{
    crypto::keys::MasterKey,
    fs::streaming::{chunk_to_encrypted_offset_for_cipher, editor::VaultFileEditor},
    vault::config::CipherCombo,
};
use std::fs;

#[test]
fn random_edits_preserve_untouched_ciphertext_for_both_ciphers() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("file");
        let key = MasterKey::random().unwrap();
        let mut expected = vec![7u8; 8 * 32768 + 17];
        let initial = cipher.encrypt_file(&expected, &key).unwrap();
        fs::write(&path, &initial).unwrap();
        let mut editor = VaultFileEditor::open(&path, &key, cipher, directory.path()).unwrap();
        assert_eq!(editor.stats().decrypted_chunks, 0);
        editor.write(32768 + 13, b"changed").unwrap();
        expected[32768 + 13..32768 + 20].copy_from_slice(b"changed");
        assert_eq!(fs::read(&path).unwrap(), initial);
        editor.commit(&path, directory.path()).unwrap();
        assert_eq!(editor.stats().decrypted_chunks, 1);
        assert_eq!(editor.stats().encrypted_chunks, 1);
        let committed = fs::read(&path).unwrap();
        let first = chunk_to_encrypted_offset_for_cipher(1, cipher) as usize;
        let next = chunk_to_encrypted_offset_for_cipher(2, cipher) as usize;
        assert_eq!(&committed[..first], &initial[..first]);
        assert_eq!(&committed[next..], &initial[next..]);
        assert_eq!(
            cipher.decrypt_file(&committed, &key).unwrap().content,
            expected
        );
        editor.write(3 * 32768, &[9; 32768]).unwrap();
        editor.commit(&path, directory.path()).unwrap();
        assert_eq!(
            editor.stats().decrypted_chunks,
            1,
            "full chunk overwrite must not read old plaintext"
        );
        assert_eq!(editor.stats().encrypted_chunks, 2);
    }
}

#[test]
fn resize_and_sparse_writes_round_trip_with_bounded_chunks() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("file");
        let key = MasterKey::random().unwrap();
        let mut editor = VaultFileEditor::create(&key, cipher, directory.path()).unwrap();
        let mut expected = Vec::new();
        for (offset, length, value) in [(0usize, 70000usize, 3u8), (32760, 50, 4), (150000, 20, 5)]
        {
            expected.resize(expected.len().max(offset + length), 0);
            expected[offset..offset + length].fill(value);
            editor.write(offset as u64, &vec![value; length]).unwrap();
            assert_eq!(editor.read(0, expected.len()).unwrap(), expected);
            editor.commit(&path, directory.path()).unwrap();
            assert_eq!(
                cipher
                    .decrypt_file(&fs::read(&path).unwrap(), &key)
                    .unwrap()
                    .content,
                expected
            );
        }
        for size in [32775, 65536, 32768, 0, 17] {
            expected.resize(size, 0);
            editor.resize(size as u64).unwrap();
            editor.commit(&path, directory.path()).unwrap();
            assert_eq!(
                cipher
                    .decrypt_file(&fs::read(&path).unwrap(), &key)
                    .unwrap()
                    .content,
                expected
            );
        }
    }
}

#[test]
fn stale_editors_cannot_overwrite_newer_commits() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file");
    let key = MasterKey::random().unwrap();
    let cipher = CipherCombo::SivGcm;
    fs::write(&path, cipher.encrypt_file(b"original", &key).unwrap()).unwrap();
    let mut first = VaultFileEditor::open(&path, &key, cipher, directory.path()).unwrap();
    let mut second = VaultFileEditor::open(&path, &key, cipher, directory.path()).unwrap();
    first.write(0, b"first!!!").unwrap();
    first.commit(&path, directory.path()).unwrap();
    second.write(0, b"second!!").unwrap();
    assert!(second.commit(&path, directory.path()).is_err());
    assert_eq!(second.read(0, 8).unwrap(), b"second!!");
    assert_eq!(
        cipher
            .decrypt_file(&fs::read(&path).unwrap(), &key)
            .unwrap()
            .content,
        b"first!!!"
    );
}

#[tokio::test]
async fn large_random_write_keeps_only_one_plaintext_chunk() {
    use oxcrypt_core::fs::streaming::VaultFileWriter;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("large");
    let key = MasterKey::random().unwrap();
    let mut writer = VaultFileWriter::create(&path, &key).await.unwrap();
    let chunk = vec![13; 32768];
    for _ in 0..1024 {
        writer.write(&chunk).await.unwrap();
    }
    writer.finish().await.unwrap();
    let mut editor =
        VaultFileEditor::open(&path, &key, CipherCombo::SivGcm, directory.path()).unwrap();
    assert_eq!(editor.buffered_plaintext_bytes(), 0);
    editor.write(17 * 1024 * 1024 + 123, b"x").unwrap();
    assert!(editor.buffered_plaintext_bytes() <= 32768);
    editor.commit(&path, directory.path()).unwrap();
    let stats = editor.stats();
    assert_eq!(stats.decrypted_chunks, 1);
    assert_eq!(stats.encrypted_chunks, 1);
    assert_eq!(editor.buffered_plaintext_bytes(), 0);
    eprintln!("32 MiB edit: {stats:?}");
}

#[test]
fn corrupt_target_chunk_is_not_silently_replaced_by_partial_write() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file");
    let key = MasterKey::random().unwrap();
    let mut encrypted = CipherCombo::SivGcm
        .encrypt_file(&vec![3; 65536], &key)
        .unwrap();
    *encrypted.last_mut().unwrap() ^= 1;
    fs::write(&path, &encrypted).unwrap();
    let mut editor =
        VaultFileEditor::open(&path, &key, CipherCombo::SivGcm, directory.path()).unwrap();
    assert!(editor.write(32769, b"x").is_err());
    assert!(!editor.is_dirty());
    assert_eq!(fs::read(&path).unwrap(), encrypted);
}
