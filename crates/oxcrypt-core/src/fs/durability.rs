//! Namespace synchronization for atomic file replacement.

use std::io;
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) enum AtomicWriteMode {
    CreateNew,
    #[cfg(feature = "async")]
    Replace,
}

/// Publish a fully synced metadata file using an exclusively created temporary
/// file. Initialization uses no-clobber publication; updates replace atomically.
pub(crate) fn write_atomic(
    path: &Path,
    data: &[u8],
    root: &Path,
    mode: AtomicWriteMode,
) -> io::Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing metadata parent"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(data)?;
    temporary.as_file().sync_all()?;
    match mode {
        #[cfg(feature = "async")]
        AtomicWriteMode::Replace => {
            temporary.persist(path).map_err(|error| error.error)?;
        }
        AtomicWriteMode::CreateNew => {
            temporary
                .persist_noclobber(path)
                .map_err(|error| error.error)?;
        }
    }
    sync_directory_chain(parent, root)
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
