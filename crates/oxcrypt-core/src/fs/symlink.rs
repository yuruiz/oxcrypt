//! Symlink encryption and decryption for Cryptomator vaults.
//!
//! Cryptomator stores symlinks in `.c9r` directories containing a `symlink.c9r` file.
//! The symlink target path is encrypted as file content (with a header and authenticated chunks),
//! the same way regular files are encrypted.
//!
//! # Reference Implementation
//! - Java: Symlink handling in [`CryptoFileSystemImpl`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoFileSystemImpl.java)
//! - Java: Symlink file type detection in [`CryptoPathMapper`](https://github.com/cryptomator/cryptofs/blob/develop/src/main/java/org/cryptomator/cryptofs/CryptoPathMapper.java)
//!
//! # Symlink Structure
//!
//! Regular symlink (short name):
//! ```text
//! {encrypted-name}.c9r/
//!   └── symlink.c9r    # Contains encrypted target path (as file content)
//! ```
//!
//! Long name symlink (>220 chars encrypted):
//! ```text
//! {sha1-hash}.c9s/
//!   ├── name.c9s       # Contains original encrypted name
//!   └── symlink.c9r    # Contains encrypted target path (as file content)
//! ```
//!
//! # Encryption Method
//!
//! Unlike filenames (which use AES-SIV with parent dir ID as AAD), symlink targets
//! are encrypted as file content:
//! - A file header containing the encrypted content key
//! - Authenticated content chunks using the configured GCM or CTRMAC cipher
//!
//! This matches the official Cryptomator implementation where symlink targets
//! go through `openCryptoFiles.writeCiphertextFile()`.

use std::fmt;
use thiserror::Error;

use crate::crypto::keys::MasterKey;
use crate::fs::file::{FileDecryptionError, FileEncryptionError};

use crate::vault::config::CipherCombo;

/// Context for symlink operations, providing debugging information.
#[derive(Debug, Clone, Default)]
pub struct SymlinkContext {
    /// The cleartext symlink name (if available)
    pub name: Option<String>,
    /// The encrypted symlink name (if available)
    pub encrypted_name: Option<String>,
    /// The parent directory ID
    pub dir_id: Option<String>,
    /// The symlink target (if available)
    pub target: Option<String>,
}

impl SymlinkContext {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_encrypted_name(mut self, name: impl Into<String>) -> Self {
        self.encrypted_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_dir_id(mut self, dir_id: impl Into<String>) -> Self {
        self.dir_id = Some(dir_id.into());
        self
    }

    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }
}

impl fmt::Display for SymlinkContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if let Some(ref name) = self.name {
            parts.push(format!("symlink '{name}'"));
        } else if let Some(ref enc_name) = self.encrypted_name {
            let display_name = if enc_name.len() > 40 {
                format!("{}...", &enc_name[..37])
            } else {
                enc_name.clone()
            };
            parts.push(format!("encrypted symlink '{display_name}'"));
        }

        if let Some(ref dir_id) = self.dir_id {
            let display_id = if dir_id.is_empty() {
                "<root>".to_string()
            } else if dir_id.len() > 12 {
                format!("{}...", &dir_id[..12])
            } else {
                dir_id.clone()
            };
            parts.push(format!("in directory {display_id}"));
        }

        if let Some(ref target) = self.target {
            let display_target = if target.len() > 40 {
                format!("{}...", &target[..37])
            } else {
                target.clone()
            };
            parts.push(format!("-> '{display_target}'"));
        }

        if parts.is_empty() {
            write!(f, "(no context)")
        } else {
            write!(f, "{}", parts.join(" "))
        }
    }
}

/// Errors that can occur during symlink operations.
#[derive(Error, Debug)]
pub enum SymlinkError {
    /// Decryption failed - the symlink target file is invalid or tampered.
    ///
    /// **[INTEGRITY VIOLATION]** This indicates either:
    /// - The encrypted symlink target was tampered with
    /// - The wrong master key was used
    /// - The file is corrupted
    #[error("[INTEGRITY VIOLATION] Failed to decrypt symlink target for {context}: {reason}")]
    DecryptionFailed {
        reason: String,
        context: SymlinkContext,
    },

    /// UTF-8 decoding failed after decryption.
    #[error("Invalid UTF-8 after decryption for {context}: {reason}")]
    Utf8Decode {
        reason: String,
        context: SymlinkContext,
    },

    /// Encryption failed unexpectedly.
    #[error("Encryption failure for {context}: {reason}")]
    EncryptionFailed {
        reason: String,
        context: SymlinkContext,
    },

    /// The encrypted data is too small to contain a valid file header.
    #[error("Invalid symlink file for {context}: too small ({size} bytes, minimum 68)")]
    TooSmall {
        size: usize,
        context: SymlinkContext,
    },

    /// IO error during symlink operations.
    #[error("IO error for {context}: {source}")]
    Io {
        #[source]
        source: std::io::Error,
        context: SymlinkContext,
    },
}

impl From<std::io::Error> for SymlinkError {
    fn from(source: std::io::Error) -> Self {
        SymlinkError::Io {
            source,
            context: SymlinkContext::new(),
        }
    }
}

impl From<FileDecryptionError> for SymlinkError {
    fn from(e: FileDecryptionError) -> Self {
        SymlinkError::DecryptionFailed {
            reason: e.to_string(),
            context: SymlinkContext::new(),
        }
    }
}

impl From<FileEncryptionError> for SymlinkError {
    fn from(e: FileEncryptionError) -> Self {
        SymlinkError::EncryptionFailed {
            reason: e.to_string(),
            context: SymlinkContext::new(),
        }
    }
}

impl SymlinkError {
    /// Add or update context on an existing error
    #[must_use]
    pub fn with_context(self, new_context: SymlinkContext) -> Self {
        match self {
            SymlinkError::DecryptionFailed { reason, .. } => SymlinkError::DecryptionFailed {
                reason,
                context: new_context,
            },
            SymlinkError::Utf8Decode { reason, .. } => SymlinkError::Utf8Decode {
                reason,
                context: new_context,
            },
            SymlinkError::EncryptionFailed { reason, .. } => SymlinkError::EncryptionFailed {
                reason,
                context: new_context,
            },
            SymlinkError::TooSmall { size, .. } => SymlinkError::TooSmall {
                size,
                context: new_context,
            },
            SymlinkError::Io { source, .. } => SymlinkError::Io {
                source,
                context: new_context,
            },
        }
    }
}

/// Encrypt a symlink target path using file content encryption.
///
/// The target path is encrypted as file content (header + AES-GCM chunks),
/// matching the official Cryptomator implementation.
///
/// # Reference Implementation
/// - Java: Symlink creation uses file content encryption via [`FileContentCryptorImpl`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileContentCryptorImpl.java)
///
/// # Arguments
///
/// * `target` - The symlink target path (can be relative or absolute)
/// * `master_key` - The vault's master key
///
/// # Returns
///
/// The encrypted target as raw bytes (to be written to `symlink.c9r`).
/// This includes the 68-byte header followed by encrypted content.
///
/// # Errors
///
/// Returns `SymlinkError::EncryptionFailed` if encryption fails.
pub fn encrypt_symlink_target(
    target: &str,
    master_key: &MasterKey,
) -> Result<Vec<u8>, SymlinkError> {
    encrypt_symlink_target_with_cipher(target, master_key, CipherCombo::SivGcm)
}

/// Encrypt the target with the vault's configured file-content cipher.
pub fn encrypt_symlink_target_with_cipher(
    target: &str,
    master_key: &MasterKey,
    cipher: CipherCombo,
) -> Result<Vec<u8>, SymlinkError> {
    cipher
        .encrypt_file(target.as_bytes(), master_key)
        .map_err(|error| SymlinkError::EncryptionFailed {
            reason: error.to_string(),
            context: SymlinkContext::new().with_target(target),
        })
}

/// Decrypt a symlink target path from file content encryption.
///
/// # Reference Implementation
/// - Java: Symlink target decryption uses [`FileContentCryptorImpl`](https://github.com/cryptomator/cryptolib/blob/develop/src/main/java/org/cryptomator/cryptolib/v2/FileContentCryptorImpl.java)
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted data from `symlink.c9r` (header + content)
/// * `master_key` - The vault's master key
///
/// # Returns
///
/// The decrypted symlink target path.
///
/// # Errors
///
/// - `SymlinkError::TooSmall`: The file is too small to contain a valid header
/// - `SymlinkError::DecryptionFailed`: **[INTEGRITY VIOLATION]** - The ciphertext is
///   invalid, tampered, or the wrong key was used
/// - `SymlinkError::Utf8Decode`: The decrypted bytes are not valid UTF-8
pub fn decrypt_symlink_target(
    encrypted_data: &[u8],
    master_key: &MasterKey,
) -> Result<String, SymlinkError> {
    decrypt_symlink_target_with_cipher(encrypted_data, master_key, CipherCombo::SivGcm)
}

/// Decrypt a target using the configured cipher. CTRMAC vaults also accept
/// authenticated GCM symlink payloads for compatibility with mixed-cipher vaults.
/// Both paths authenticate the complete header and content before returning data.
pub fn decrypt_symlink_target_with_cipher(
    encrypted_data: &[u8],
    master_key: &MasterKey,
    cipher: CipherCombo,
) -> Result<String, SymlinkError> {
    let context = SymlinkContext::new();
    if encrypted_data.len() < 68 {
        return Err(SymlinkError::TooSmall {
            size: encrypted_data.len(),
            context,
        });
    }
    let decrypted = cipher
        .decrypt_file(encrypted_data, master_key)
        .or_else(|error| {
            if cipher == CipherCombo::SivCtrMac {
                CipherCombo::SivGcm
                    .decrypt_file(encrypted_data, master_key)
                    .map_err(|_| error)
            } else {
                Err(error)
            }
        })?;
    String::from_utf8(decrypted.content).map_err(|error| SymlinkError::Utf8Decode {
        reason: error.to_string(),
        context,
    })
}

#[cfg(test)]
mod tests {
    use crate::fs::symlink::*;

    fn create_test_master_key() -> MasterKey {
        let mut aes_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        for i in 0..32 {
            // Safe cast: loop variable i is always 0-31, fits safely in u8
            aes_key[i] = i as u8;
            // Safe cast: (32 + i) is always 32-63, fits safely in u8
            mac_key[i] = (32 + i) as u8;
        }

        MasterKey::new(aes_key, mac_key).expect("Failed to create test master key")
    }

    fn create_different_master_key() -> MasterKey {
        let mut aes_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        for i in 0..32 {
            // Safe cast: (i + 100) wraps around u8 (100-131 mod 256), intentionally checking wraparound
            aes_key[i] = (i + 100) as u8;
            // Safe cast: (i + 200) wraps around u8 (200-231 mod 256), intentionally checking wraparound
            mac_key[i] = (i + 200) as u8;
        }

        MasterKey::new(aes_key, mac_key).expect("Failed to create different master key")
    }

    #[test]
    fn test_symlink_target_roundtrip() {
        let master_key = create_test_master_key();

        let test_targets = vec![
            "../other_file.txt",
            "/absolute/path/to/file",
            "relative/path",
            ".",
            "..",
            "file with spaces.txt",
            "unicode-cafe-target",
            "special!@#$%^&*()_+-=[]{}|;':\",./<>?",
            "", // Empty target
        ];

        for target in test_targets {
            let encrypted = encrypt_symlink_target(target, &master_key)
                .unwrap_or_else(|e| panic!("Failed to encrypt target '{target}': {e}"));
            let decrypted = decrypt_symlink_target(&encrypted, &master_key)
                .unwrap_or_else(|e| panic!("Failed to decrypt target '{target}': {e}"));

            assert_eq!(target, decrypted, "Roundtrip failed for target '{target}'");
        }
    }

    #[test]
    fn test_symlink_encryption_is_not_deterministic() {
        // Unlike AES-SIV (used for filenames), file content encryption uses
        // random nonces, so the same input produces different output each time.
        let master_key = create_test_master_key();
        let target = "../linked_file.txt";

        let encrypted1 = encrypt_symlink_target(target, &master_key).unwrap();
        let encrypted2 = encrypt_symlink_target(target, &master_key).unwrap();

        // The encrypted outputs should be different (random nonces)
        assert_ne!(
            encrypted1, encrypted2,
            "Encryption should use random nonces"
        );

        // But both should decrypt to the same value
        let decrypted1 = decrypt_symlink_target(&encrypted1, &master_key).unwrap();
        let decrypted2 = decrypt_symlink_target(&encrypted2, &master_key).unwrap();
        assert_eq!(decrypted1, target);
        assert_eq!(decrypted2, target);
    }

    #[test]
    fn test_symlink_decryption_with_wrong_key_fails() {
        let master_key1 = create_test_master_key();
        let master_key2 = create_different_master_key();
        let target = "../linked_file.txt";

        let encrypted = encrypt_symlink_target(target, &master_key1).unwrap();

        // Should succeed with correct key
        let decrypted = decrypt_symlink_target(&encrypted, &master_key1);
        assert!(decrypted.is_ok());
        assert_eq!(target, decrypted.unwrap());

        // Should fail with wrong key
        let failed = decrypt_symlink_target(&encrypted, &master_key2);
        assert!(failed.is_err());
        assert!(matches!(
            failed.unwrap_err(),
            SymlinkError::DecryptionFailed { .. }
        ));
    }

    #[test]
    fn test_symlink_decryption_with_tampered_data_fails() {
        let master_key = create_test_master_key();
        let target = "../linked_file.txt";

        let mut encrypted = encrypt_symlink_target(target, &master_key).unwrap();

        // Tamper with the encrypted data (after the header)
        if encrypted.len() > 68 {
            encrypted[70] ^= 0xFF;
        }

        let failed = decrypt_symlink_target(&encrypted, &master_key);
        assert!(failed.is_err());
        assert!(matches!(
            failed.unwrap_err(),
            SymlinkError::DecryptionFailed { .. }
        ));
    }

    #[test]
    fn test_symlink_decryption_with_tampered_header_fails() {
        let master_key = create_test_master_key();
        let target = "../linked_file.txt";

        let mut encrypted = encrypt_symlink_target(target, &master_key).unwrap();

        // Tamper with the header
        encrypted[20] ^= 0xFF;

        let failed = decrypt_symlink_target(&encrypted, &master_key);
        assert!(failed.is_err());
        assert!(matches!(
            failed.unwrap_err(),
            SymlinkError::DecryptionFailed { .. }
        ));
    }

    #[test]
    fn test_symlink_too_small_fails() {
        let master_key = create_test_master_key();

        // Try to decrypt data that's too small
        let too_small = vec![0u8; 50];
        let failed = decrypt_symlink_target(&too_small, &master_key);
        assert!(failed.is_err());
        assert!(matches!(
            failed.unwrap_err(),
            SymlinkError::TooSmall { size: 50, .. }
        ));
    }

    #[test]
    fn test_long_symlink_target() {
        let master_key = create_test_master_key();

        // Create a very long target path
        let long_target = format!("/very/long/path/{}", "a".repeat(500));

        let encrypted = encrypt_symlink_target(&long_target, &master_key).unwrap();
        let decrypted = decrypt_symlink_target(&encrypted, &master_key).unwrap();

        assert_eq!(long_target, decrypted);
    }

    #[test]
    fn test_encrypted_size_includes_overhead() {
        let master_key = create_test_master_key();
        let target = "short";

        let encrypted = encrypt_symlink_target(target, &master_key).unwrap();

        // Minimum size: 68-byte header + 12-byte chunk nonce + encrypted payload + 16-byte tag
        // For "short" (5 bytes): 68 + 12 + 5 + 16 = 101 bytes
        assert!(
            encrypted.len() >= 68 + 28,
            "Encrypted data should include header + chunk overhead"
        );

        // The encrypted size should be: header (68) + chunk_nonce (12) + content + tag (16)
        // = 68 + 12 + 5 + 16 = 101
        assert_eq!(encrypted.len(), 101);
    }
}
