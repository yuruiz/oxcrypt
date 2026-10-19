//! Encrypted emergency copies for writes that cannot reach their vault pathname.
use crate::{
    crypto::keys::MasterKey,
    vault::{DirId, config::CipherCombo},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
};

/// Authenticated destination information stored alongside an emergency copy.
#[derive(Serialize, Deserialize)]
pub struct RecoveryMetadata {
    /// Intended vault directory ID.
    pub directory_id: String,
    /// Intended cleartext filename (encrypted on disk).
    pub filename: String,
}

/// Persistent per-user storage, separate from the potentially unavailable vault.
pub fn default_directory() -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support/oxcrypt/recovery"));
    #[cfg(target_os = "windows")]
    let root =
        std::env::var_os("LOCALAPPDATA").map(|home| PathBuf::from(home).join("oxcrypt/recovery"));
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .map(|path| path.join("oxcrypt/recovery"));
    root.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "user recovery directory unavailable",
        )
    })
}

/// Save data and its destination encrypted under the vault key on the local
/// recovery volume. The directory is retained until explicitly recovered.
pub async fn save(
    root: &Path,
    master_key: &MasterKey,
    dir: &DirId,
    name: &str,
    content: &[u8],
) -> io::Result<PathBuf> {
    std::fs::create_dir_all(root)?;
    if std::fs::symlink_metadata(root)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recovery root must not be a symlink",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let directory = tempfile::Builder::new()
        .prefix("oxcrypt-recovery-")
        .tempdir_in(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let metadata = RecoveryMetadata {
        directory_id: dir.as_str().to_owned(),
        filename: name.to_owned(),
    };
    let encoded = serde_json::to_vec(&metadata).map_err(io::Error::other)?;
    let encrypted = CipherCombo::SivGcm
        .encrypt_file(&encoded, master_key)
        .map_err(io::Error::other)?;
    let metadata_path = directory.path().join("metadata.c9r");
    std::fs::write(&metadata_path, encrypted)?;
    std::fs::File::open(metadata_path)?.sync_all()?;
    let mut writer = crate::fs::streaming::VaultFileWriter::create(
        directory.path().join("data.c9r"),
        master_key,
    )
    .await
    .map_err(io::Error::other)?;
    writer.write(content).await.map_err(io::Error::other)?;
    writer.finish().await.map_err(io::Error::other)?;
    crate::fs::durability::sync_directory_chain(directory.path(), root)?;
    Ok(directory.keep())
}

/// Verify and read the destination metadata of a recovery copy.
pub fn metadata(path: &Path, master_key: &MasterKey) -> io::Result<RecoveryMetadata> {
    let file = path.join("metadata.c9r");
    if std::fs::metadata(&file)?.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery metadata too large",
        ));
    }
    let plaintext = CipherCombo::SivGcm
        .decrypt_file(&std::fs::read(file)?, master_key)
        .map_err(io::Error::other)?;
    serde_json::from_slice(&plaintext.content).map_err(io::Error::other)
}

/// Export an emergency copy to a newly created local file, never overwriting.
/// Retain the encrypted source so the caller controls its eventual removal.
pub fn export(
    path: &Path,
    master_key: &MasterKey,
    destination: &Path,
) -> io::Result<RecoveryMetadata> {
    use std::io::Write;
    let metadata = metadata(path, master_key)?;
    let mut reader =
        crate::fs::streaming::VaultFileReaderSync::open(path.join("data.c9r"), master_key)
            .map_err(io::Error::other)?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    let mut offset = 0;
    while offset < reader.plaintext_size() {
        let bytes = reader.read_range(offset, 32768).map_err(io::Error::other)?;
        output.write_all(&bytes)?;
        offset += bytes.len() as u64;
    }
    output.as_file().sync_all()?;
    output
        .persist_noclobber(destination)
        .map_err(|error| error.error)?;
    Ok(metadata)
}
