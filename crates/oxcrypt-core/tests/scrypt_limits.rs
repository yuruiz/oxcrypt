use oxcrypt_core::{crypto::CryptoError, vault::master_key::MasterKeyFile};

fn keyfile(n: i32, r: i32) -> MasterKeyFile {
    serde_json::from_value(serde_json::json!({
        "version": 999,
        "scryptSalt": "AAAAAAAAAAA=",
        "scryptCostParam": n,
        "scryptBlockSize": r,
        "primaryMasterKey": "",
        "hmacMasterKey": "",
        "versionMac": ""
    }))
    .unwrap()
}

#[test]
fn nonpositive_cost_is_rejected_without_panicking() {
    for n in [0, -1, i32::MIN] {
        let result = std::panic::catch_unwind(|| keyfile(n, 1).derive_key("password"));
        assert!(result.is_ok(), "N={n} must not panic");
        assert!(matches!(
            result.unwrap(),
            Err(CryptoError::InvalidScryptParams(_))
        ));
    }
}

#[test]
fn non_power_of_two_cost_is_not_silently_rounded_down() {
    for n in [1, 3, 5, 7] {
        assert!(
            matches!(
                keyfile(n, 1).derive_key("password"),
                Err(CryptoError::InvalidScryptParams(_))
            ),
            "N={n} must be rejected"
        );
    }
}

#[test]
fn oversized_and_invalid_block_parameters_fail_before_allocation() {
    for (n, r) in [
        (2, 0),
        (2, -1),
        (2, i32::MIN),
        (1 << 30, 8),
        (2, i32::MAX),
        (1 << 30, i32::MAX),
    ] {
        assert!(matches!(
            keyfile(n, r).derive_key("password"),
            Err(CryptoError::InvalidScryptParams(_))
        ));
    }
}

#[test]
fn explicit_budget_includes_all_buffers_without_changing_the_kdf() {
    use oxcrypt_core::vault::master_key::ScryptLimits;
    use secrecy::ExposeSecret;
    let key = keyfile(16, 1);
    let required = 128 * (16 + 2);
    assert!(
        key.derive_key_with_pepper_and_limits(
            "password",
            b"pepper",
            ScryptLimits {
                max_memory_bytes: required - 1
            }
        )
        .is_err()
    );
    let limited = key
        .derive_key_with_pepper_and_limits(
            "password",
            b"pepper",
            ScryptLimits {
                max_memory_bytes: required,
            },
        )
        .unwrap();
    let default = key.derive_key_with_pepper("password", b"pepper").unwrap();
    assert_eq!(limited.expose_secret(), default.expose_secret());
}

#[test]
fn standard_cryptomator_parameters_and_pepper_still_unlock() {
    use oxcrypt_core::{
        crypto::keys::MasterKey,
        vault::master_key::{ScryptLimits, create_masterkey_file_with_pepper},
    };
    let original = MasterKey::random().unwrap();
    let json = create_masterkey_file_with_pepper(&original, "password", b"pepper").unwrap();
    let key: MasterKeyFile = serde_json::from_str(&json).unwrap();
    key.unlock_with_pepper("password", b"pepper").unwrap();
    assert!(key.unlock_with_pepper("wrong", b"pepper").is_err());
    assert!(
        key.unlock_with_pepper_and_limits(
            "password",
            b"pepper",
            ScryptLimits {
                max_memory_bytes: 1
            }
        )
        .is_err()
    );
    // Test the standard N explicitly even when the suite enables fast creation.
    assert!(keyfile(32768, 8).derive_key("password").is_ok());
}
