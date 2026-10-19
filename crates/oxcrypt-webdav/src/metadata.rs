//! WebDAV metadata implementation for vault entries.
//!
//! This module provides the `DavMetaData` trait implementation for vault
//! files, directories, and symlinks.

#![allow(dead_code)] // Metadata fields used for Debug/Clone traits

use dav_server::fs::{DavMetaData, FsError};
use oxcrypt_core::vault::operations::{VaultDirectoryInfo, VaultFileInfo, VaultSymlinkInfo};
use oxcrypt_core::{
    fs::streaming::encrypted_to_plaintext_size_or_zero_for_cipher, vault::config::CipherCombo,
};
use std::time::SystemTime;

/// Metadata for a vault entry (file, directory, or symlink).
#[derive(Debug, Clone)]
pub enum CryptomatorMetaData {
    /// Root directory metadata.
    Root,
    /// File metadata.
    File(FileMetaData),
    /// Directory metadata.
    Directory(DirectoryMetaData),
    /// Symlink metadata (exposed as regular file in WebDAV).
    Symlink(SymlinkMetaData),
}

/// Metadata for a file.
#[derive(Debug, Clone)]
pub struct FileMetaData {
    /// Decrypted filename.
    pub name: String,
    /// Plaintext file size (computed from encrypted size).
    pub size: u64,
    /// Modification time (from encrypted file).
    pub modified: SystemTime,
}

/// Metadata for a directory.
#[derive(Debug, Clone)]
pub struct DirectoryMetaData {
    /// Decrypted directory name.
    pub name: String,
    /// Modification time (from encrypted directory structure).
    pub modified: SystemTime,
}

/// Metadata for a symlink (treated as a regular file in WebDAV).
#[derive(Debug, Clone)]
pub struct SymlinkMetaData {
    /// Decrypted symlink name.
    pub name: String,
    /// Target path length (symlink content size).
    pub size: u64,
    /// Modification time.
    pub modified: SystemTime,
}

impl CryptomatorMetaData {
    /// Create metadata for the root directory.
    pub fn root() -> Self {
        CryptomatorMetaData::Root
    }

    /// Create metadata from a VaultFileInfo.
    pub fn from_file(info: &VaultFileInfo, cipher: CipherCombo) -> Self {
        let plaintext_size =
            encrypted_to_plaintext_size_or_zero_for_cipher(info.encrypted_size, cipher);

        // Try to get the modification time from the encrypted file
        let modified = std::fs::metadata(&info.encrypted_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        CryptomatorMetaData::File(FileMetaData {
            name: info.name.clone(),
            size: plaintext_size,
            modified,
        })
    }

    /// Create metadata from a VaultDirectoryInfo.
    pub fn from_directory(info: &VaultDirectoryInfo) -> Self {
        let modified = std::fs::metadata(&info.encrypted_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        CryptomatorMetaData::Directory(DirectoryMetaData {
            name: info.name.clone(),
            modified,
        })
    }

    /// Create metadata from a VaultSymlinkInfo.
    pub fn from_symlink(info: &VaultSymlinkInfo) -> Self {
        let modified = std::fs::metadata(&info.encrypted_path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        CryptomatorMetaData::Symlink(SymlinkMetaData {
            name: info.name.clone(),
            size: info.target.len() as u64,
            modified,
        })
    }

    /// Create metadata with a specific size (for write buffers).
    pub fn file_with_size(name: String, size: u64) -> Self {
        CryptomatorMetaData::File(FileMetaData {
            name,
            size,
            modified: SystemTime::now(),
        })
    }
}

impl DavMetaData for CryptomatorMetaData {
    fn len(&self) -> u64 {
        match self {
            CryptomatorMetaData::File(f) => f.size,
            CryptomatorMetaData::Symlink(s) => s.size,
            CryptomatorMetaData::Root | CryptomatorMetaData::Directory(_) => 0,
        }
    }

    fn modified(&self) -> Result<SystemTime, FsError> {
        let time = match self {
            CryptomatorMetaData::Root => SystemTime::now(),
            CryptomatorMetaData::File(f) => f.modified,
            CryptomatorMetaData::Directory(d) => d.modified,
            CryptomatorMetaData::Symlink(s) => s.modified,
        };
        Ok(time)
    }

    fn is_dir(&self) -> bool {
        matches!(
            self,
            CryptomatorMetaData::Root | CryptomatorMetaData::Directory(_)
        )
    }

    fn is_file(&self) -> bool {
        matches!(
            self,
            CryptomatorMetaData::File(_) | CryptomatorMetaData::Symlink(_)
        )
    }

    fn is_symlink(&self) -> bool {
        // WebDAV doesn't support symlinks natively, so we expose them as files
        false
    }

    fn created(&self) -> Result<SystemTime, FsError> {
        // Cryptomator doesn't store creation time, return modification time
        self.modified()
    }

    fn accessed(&self) -> Result<SystemTime, FsError> {
        // Cryptomator doesn't store access time, return modification time
        self.modified()
    }

    fn status_changed(&self) -> Result<SystemTime, FsError> {
        // Cryptomator doesn't store status change time, return modification time
        self.modified()
    }

    fn executable(&self) -> Result<bool, FsError> {
        // Cryptomator doesn't store executable bit
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::metadata::*;

    #[test]
    fn test_root_metadata() {
        let meta = CryptomatorMetaData::root();
        assert!(meta.is_dir());
        assert!(!meta.is_file());
        assert_eq!(meta.len(), 0);
    }

    #[test]
    fn test_file_metadata() {
        let meta = CryptomatorMetaData::file_with_size("test.txt".to_string(), 1024);
        assert!(meta.is_file());
        assert!(!meta.is_dir());
        assert_eq!(meta.len(), 1024);
    }

    #[test]
    fn file_metadata_uses_the_configured_cipher_overhead() {
        for (cipher, encrypted, expected) in [
            (CipherCombo::SivGcm, 68, 0),
            (CipherCombo::SivGcm, 50, 0),
            (CipherCombo::SivGcm, 103, 7),
            (CipherCombo::SivGcm, 196, 100),
            (CipherCombo::SivGcm, 32864, 32768),
            (CipherCombo::SivGcm, 32992, 32868),
            (CipherCombo::SivCtrMac, 88, 0),
            (CipherCombo::SivCtrMac, 136, 0),
            (CipherCombo::SivCtrMac, 137, 1),
            (CipherCombo::SivCtrMac, 32904, 32768),
            (CipherCombo::SivCtrMac, 33052, 32868),
        ] {
            let info = VaultFileInfo {
                name: "test".into(),
                encrypted_name: "encrypted.c9r".into(),
                encrypted_path: "/nonexistent/oxcrypt-metadata-test".into(),
                encrypted_size: encrypted,
                is_shortened: false,
            };
            assert_eq!(
                CryptomatorMetaData::from_file(&info, cipher).len(),
                expected
            );
        }
    }
}
