use oxcrypt_core::{
    fs::{
        file::FileContext,
        name::NameContext,
        symlink::{SymlinkContext, SymlinkError},
    },
    vault::operations::VaultOpContext,
};

#[test]
fn unicode_file_and_vault_directory_contexts_format_without_panics() {
    let value = format!("a{}", "资料🦀".repeat(20));
    assert!(
        FileContext::new()
            .with_dir_id(&value)
            .to_string()
            .ends_with("...")
    );
    assert!(
        VaultOpContext::new()
            .with_dir_id(&value)
            .to_string()
            .ends_with("...")
    );
}

#[test]
fn unicode_filename_errors_remain_printable() {
    let value = "资料🦀".repeat(20);
    assert!(
        NameContext::new()
            .with_encrypted_name(&value)
            .to_string()
            .contains("...")
    );
    assert!(
        NameContext::new()
            .with_dir_id(format!("a{value}"))
            .to_string()
            .contains("...")
    );
}

#[test]
fn unicode_symlink_errors_remain_printable() {
    let value = "资料🦀".repeat(20);
    for context in [
        SymlinkContext::new().with_target(&value),
        SymlinkContext::new().with_encrypted_name(&value),
        SymlinkContext::new().with_dir_id(format!("a{value}")),
    ] {
        let error = SymlinkError::DecryptionFailed {
            reason: "authentication failed".into(),
            context,
        };
        assert!(error.to_string().contains("..."));
    }
}

#[test]
fn ascii_and_short_unicode_contexts_keep_readable_output() {
    assert_eq!(
        FileContext::new().with_dir_id("123456789").to_string(),
        "in directory 12345678..."
    );
    assert_eq!(
        VaultOpContext::new().with_dir_id("").to_string(),
        "in directory <root>"
    );
    assert_eq!(
        SymlinkContext::new().with_target("资料/报告").to_string(),
        "-> '资料/报告'"
    );
}
