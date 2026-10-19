use oxcrypt_core::vault::{PasswordValidator, VaultCreator, VaultOperations};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

fn fixture() -> (tempfile::TempDir, PathBuf, VaultOperations) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let ops = VaultCreator::new(&path, "password").create().unwrap();
    (temp, path, ops)
}

fn original_key_path(path: &Path) -> PathBuf {
    let root = path.join("masterkey.cryptomator");
    if root.exists() {
        root
    } else {
        path.join("masterkey/masterkey.cryptomator")
    }
}

fn set_key_id(path: &Path, ops: &VaultOperations, kid: &str) {
    let token = std::fs::read_to_string(path.join("vault.cryptomator")).unwrap();
    let claims =
        oxcrypt_core::vault::config::validate_vault_claims(&token, ops.master_key()).unwrap();
    let mut header = jsonwebtoken::decode_header(&token).unwrap();
    header.kid = Some(kid.into());
    let key = ops.master_key().create_jwt_encoding_key().unwrap();
    let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    std::fs::write(path.join("vault.cryptomator"), token).unwrap();
}

#[cfg(feature = "async")]
#[tokio::test]
async fn password_change_supports_the_standard_root_masterkey() {
    let (_temp, path, ops) = fixture();
    let original = original_key_path(&path);
    if original != path.join("masterkey.cryptomator") {
        std::fs::rename(original, path.join("masterkey.cryptomator")).unwrap();
    }
    set_key_id(&path, &ops, "masterkeyfile:masterkey.cryptomator");
    assert!(VaultOperations::open(&path, "password").is_ok());
    oxcrypt_core::vault::change_password_async(&path, "password", "new-password")
        .await
        .unwrap();
    assert!(VaultOperations::open(&path, "new-password").is_ok());
}

#[test]
fn key_ids_cannot_escape_the_vault_even_with_a_valid_signature() {
    let (temp, path, ops) = fixture();
    std::fs::copy(original_key_path(&path), temp.path().join("outside.key")).unwrap();
    set_key_id(&path, &ops, "masterkeyfile:../outside.key");
    assert!(VaultOperations::open(&path, "password").is_err());
    assert!(
        PasswordValidator::new(&path)
            .validate("password", Duration::from_secs(2))
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn key_ids_cannot_follow_symlinks_outside_the_vault() {
    let (temp, path, ops) = fixture();
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::copy(original_key_path(&path), outside.join("key")).unwrap();
    std::os::unix::fs::symlink(outside, path.join("linked")).unwrap();
    set_key_id(&path, &ops, "masterkeyfile:linked/key");
    assert!(VaultOperations::open(&path, "password").is_err());
    assert!(
        PasswordValidator::new(&path)
            .validate("password", Duration::from_secs(2))
            .is_err()
    );
}

#[test]
fn encoded_relative_key_paths_are_decoded_once() {
    let (_temp, path, ops) = fixture();
    std::fs::create_dir(path.join("my keys")).unwrap();
    std::fs::rename(
        original_key_path(&path),
        path.join("my keys/key file.cryptomator"),
    )
    .unwrap();
    set_key_id(
        &path,
        &ops,
        "masterkeyfile:my%20keys/key%20file.cryptomator",
    );
    assert!(VaultOperations::open(&path, "password").is_ok());
    assert!(
        PasswordValidator::new(&path)
            .validate("password", Duration::from_secs(2))
            .is_ok()
    );
}

#[cfg(feature = "async")]
#[tokio::test]
async fn legacy_nested_key_layout_remains_readable_and_updatable() {
    let (_temp, path, ops) = fixture();
    std::fs::create_dir_all(path.join("masterkey")).unwrap();
    let nested = path.join("masterkey/masterkey.cryptomator");
    let original = original_key_path(&path);
    if original != nested {
        std::fs::rename(original, &nested).unwrap();
    }
    set_key_id(&path, &ops, "masterkeyfile:masterkey/masterkey.cryptomator");
    assert!(VaultOperations::open(&path, "password").is_ok());
    oxcrypt_core::vault::change_password_async(&path, "password", "updated")
        .await
        .unwrap();
    assert!(VaultOperations::open(&path, "updated").is_ok());
}

#[test]
fn new_vaults_use_the_standard_root_key_location() {
    let (_temp, path, _ops) = fixture();
    assert!(path.join("masterkey.cryptomator").is_file());
    let token = std::fs::read_to_string(path.join("vault.cryptomator")).unwrap();
    assert_eq!(
        jsonwebtoken::decode_header(&token).unwrap().kid.as_deref(),
        Some("masterkeyfile:masterkey.cryptomator")
    );
}
