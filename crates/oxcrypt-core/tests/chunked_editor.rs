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

#[tokio::test]
async fn malformed_tail_is_not_treated_as_an_empty_file() {
    use oxcrypt_core::fs::streaming::{VaultFileReader, VaultFileReaderSync};
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("malformed");
        let key = MasterKey::random().unwrap();
        let mut data = cipher.encrypt_file(b"original", &key).unwrap();
        data.truncate(if cipher == CipherCombo::SivGcm {
            69
        } else {
            89
        });
        fs::write(&path, &data).unwrap();
        assert!(VaultFileReaderSync::open_with_cipher(&path, &key, cipher).is_err());
        assert!(
            VaultFileReader::open_with_cipher(&path, &key, cipher)
                .await
                .is_err()
        );
        assert!(VaultFileEditor::open(&path, &key, cipher, directory.path()).is_err());
        assert_eq!(fs::read(path).unwrap(), data);
    }
}

#[test]
fn unchanged_partial_write_does_not_stage_or_encrypt() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file");
    let key = MasterKey::random().unwrap();
    fs::write(
        &path,
        CipherCombo::SivGcm
            .encrypt_file(b"unchanged", &key)
            .unwrap(),
    )
    .unwrap();
    let mut editor =
        VaultFileEditor::open(&path, &key, CipherCombo::SivGcm, directory.path()).unwrap();
    assert_eq!(editor.write(2, b"changed").unwrap(), 7);
    assert!(!editor.is_dirty());
    assert_eq!(editor.stats().encrypted_chunks, 0);
    assert_eq!(editor.stats().copied_ciphertext_bytes, 0);
}

#[test]
fn write_reports_an_accepted_prefix_before_a_later_chunk_failure() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file");
    let key = MasterKey::random().unwrap();
    let mut encrypted = CipherCombo::SivGcm
        .encrypt_file(&vec![3; 65536], &key)
        .unwrap();
    *encrypted.last_mut().unwrap() ^= 1;
    fs::write(&path, encrypted).unwrap();
    let mut editor =
        VaultFileEditor::open(&path, &key, CipherCombo::SivGcm, directory.path()).unwrap();
    assert_eq!(editor.write(0, &vec![9; 32769]).unwrap(), 32768);
    assert!(editor.write(32768, b"x").is_err());
    assert_eq!(editor.read(0, 32768).unwrap(), vec![9; 32768]);
}

#[test]
fn overlapping_reads_reuse_authenticated_chunks_and_writes_invalidate_them() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("file");
    let key = MasterKey::random().unwrap();
    fs::write(
        &path,
        CipherCombo::SivGcm
            .encrypt_file(&vec![3; 65536], &key)
            .unwrap(),
    )
    .unwrap();
    let mut editor =
        VaultFileEditor::open(&path, &key, CipherCombo::SivGcm, directory.path()).unwrap();
    for offset in 0..100 {
        assert_eq!(editor.read(offset, 4).unwrap(), vec![3; 4]);
    }
    assert_eq!(editor.stats().decrypted_chunks, 1);
    editor.write(0, b"edit").unwrap();
    editor.commit(&path, directory.path()).unwrap();
    assert_eq!(editor.read(0, 4).unwrap(), b"edit");
    editor.resize(2).unwrap();
    editor.resize(8).unwrap();
    assert_eq!(editor.read(0, 8).unwrap(), b"ed\0\0\0\0\0\0");
}
