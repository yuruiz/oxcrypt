//! Namespace synchronization for atomic file replacement.

use std::io;
use std::path::Path;

/// Validate directory components before destructive cleanup. Missing storage is
/// allowed for lazily allocated empty directories; symlinks are not directories.
pub(crate) fn directory_exists_checked(directory: &Path, root: &Path) -> io::Result<bool> {
    let relative = directory.strip_prefix(root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory is outside vault root",
        )
    })?;
    let mut current = std::fs::canonicalize(root)?;
    for component in relative.components() {
        match component {
            std::path::Component::Normal(name) => current.push(name),
            std::path::Component::CurDir => continue,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid directory path",
                ));
            }
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "encrypted directory path contains a non-directory entry",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

#[cfg(feature = "async")]
pub(crate) async fn directory_exists_checked_async(
    directory: &Path,
    root: &Path,
) -> io::Result<bool> {
    let directory = directory.to_owned();
    let root = root.to_owned();
    tokio::task::spawn_blocking(move || directory_exists_checked(&directory, &root))
        .await
        .map_err(io::Error::other)?
}

/// Sync directory entries from a changed directory through its vault root.
/// Unix provides directory synchronization; other platforms retain their native
/// rename guarantees without claiming an additional directory flush primitive.
pub(crate) fn sync_directory_chain(directory: &Path, root: &Path) -> io::Result<()> {
    if !directory.starts_with(root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory is outside vault root",
        ));
    }
    #[cfg(unix)]
    {
        let mut current = directory;
        loop {
            std::fs::File::open(current)?.sync_all()?;
            if current == root {
                break;
            }
            current = current.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing directory parent")
            })?;
        }
    }
    Ok(())
}

#[cfg(feature = "async")]
pub(crate) async fn sync_directory_chain_async(directory: &Path, root: &Path) -> io::Result<()> {
    let directory = directory.to_path_buf();
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || sync_directory_chain(&directory, &root))
        .await
        .map_err(io::Error::other)?
}
