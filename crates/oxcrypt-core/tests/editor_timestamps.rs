#![cfg(feature = "async")]
use oxcrypt_core::{
    crypto::keys::MasterKey, fs::streaming::editor::VaultFileEditor, vault::config::CipherCombo,
};
use std::{
    fs,
    time::{Duration, SystemTime},
};

#[test]
fn explicit_times_survive_dirty_commit_and_retry() {
    for cipher in [CipherCombo::SivGcm, CipherCombo::SivCtrMac] {
        for new in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("file");
            let key = MasterKey::random().unwrap();
            let mut editor = if new {
                VaultFileEditor::create(&key, cipher, temp.path()).unwrap()
            } else {
                fs::write(&path, cipher.encrypt_file(b"original", &key).unwrap()).unwrap();
                VaultFileEditor::open(&path, &key, cipher, temp.path()).unwrap()
            };
            editor.write(0, b"modified").unwrap();
            let atime = SystemTime::UNIX_EPOCH + Duration::from_secs(946684700);
            let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(946684800);
            editor.set_times(Some(atime), Some(mtime)).unwrap();
            let backup = temp.path().join("backup");
            if !new {
                fs::rename(&path, &backup).unwrap();
            }
            fs::create_dir(&path).unwrap();
            assert!(editor.commit(&path, temp.path()).is_err());
            fs::remove_dir(&path).unwrap();
            if !new {
                fs::rename(&backup, &path).unwrap();
            }
            editor.commit(&path, temp.path()).unwrap();
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.modified().unwrap(), mtime);
            assert_eq!(metadata.accessed().unwrap(), atime);
            assert_eq!(
                cipher
                    .decrypt_file(&fs::read(&path).unwrap(), &key)
                    .unwrap()
                    .content,
                b"modified"
            );
        }
    }
}

#[test]
fn later_content_write_supersedes_explicit_mtime_but_not_atime() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("file");
    let key = MasterKey::random().unwrap();
    let mut editor = VaultFileEditor::create(&key, CipherCombo::SivGcm, temp.path()).unwrap();
    editor.write(0, b"initial").unwrap();
    let requested = SystemTime::UNIX_EPOCH + Duration::from_secs(946684800);
    editor.set_times(Some(requested), Some(requested)).unwrap();
    editor.write(0, b"changed").unwrap();
    editor.commit(&path, temp.path()).unwrap();
    let metadata = fs::metadata(&path).unwrap();
    assert!(metadata.modified().unwrap() > requested);
    assert_eq!(metadata.accessed().unwrap(), requested);
}
