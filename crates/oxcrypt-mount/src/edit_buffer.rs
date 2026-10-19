//! Shared file identity and bounded-memory encrypted editing for mount backends.
use oxcrypt_core::{
    fs::streaming::editor::VaultFileEditor,
    vault::{DirId, VaultOperationsAsync},
};
use parking_lot::{Mutex, RwLock};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// A shared open-file state. All handles of an inode observe the same edits.
#[derive(Debug)]
pub struct EditBuffer {
    inner: Arc<Mutex<VaultFileEditor>>,
    location: RwLock<(DirId, String)>,
    detached: AtomicBool,
}

impl EditBuffer {
    /// Open an editor without decrypting the whole file.
    pub async fn open(
        ops: &VaultOperationsAsync,
        dir: DirId,
        name: String,
        create: bool,
        truncate: bool,
    ) -> Result<Self, oxcrypt_core::error::VaultWriteError> {
        Ok(Self {
            inner: ops.edit_file(&dir, &name, create, truncate).await?,
            location: RwLock::new((dir, name)),
            detached: AtomicBool::new(false),
        })
    }
    /// Current length visible to every open handle.
    pub fn len(&self) -> u64 {
        self.inner.lock().len()
    }
    /// Whether the file is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Whether edits have not been committed.
    pub fn is_dirty(&self) -> bool {
        self.inner.lock().is_dirty()
    }
    /// Read only the necessary authenticated chunks.
    pub fn read(&self, offset: u64, size: usize) -> io::Result<Vec<u8>> {
        self.inner.lock().read(offset, size)
    }
    /// Edit only overlapping chunks.
    pub fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<usize> {
        self.inner.lock().write(offset, bytes)
    }
    /// Change the file length with authenticated zero extension.
    pub fn truncate(&self, size: u64) -> io::Result<()> {
        self.inner.lock().resize(size)
    }
    /// Keep editor conflict tracking consistent with local timestamp changes.
    pub fn set_times(
        &self,
        accessed: Option<std::time::SystemTime>,
        modified: Option<std::time::SystemTime>,
    ) -> io::Result<()> {
        self.inner.lock().set_times(accessed, modified)
    }
    /// Current namespace location.
    pub fn location(&self) -> (DirId, String) {
        self.location.read().clone()
    }
    /// Refresh a backing inode after a validated namespace representation change.
    pub fn follow_rename(&self, destination: &Path) -> io::Result<()> {
        self.inner.lock().follow_rename(destination)
    }
    /// Follow a rename while preserving all open handles and dirty chunks.
    pub fn relocate(&self, dir: DirId, name: String) {
        *self.location.write() = (dir, name);
    }
    /// Detach an overwritten inode from its former pathname.
    pub fn detach(&self) {
        self.detached.store(true, Ordering::Release);
    }
    /// Whether the file has been overwritten or unlinked.
    pub fn is_detached(&self) -> bool {
        self.detached.load(Ordering::Acquire)
    }
    /// Commit changed chunks atomically; keep the stage on any failure.
    pub async fn commit(
        &self,
        ops: &VaultOperationsAsync,
    ) -> Result<Option<PathBuf>, oxcrypt_core::error::VaultWriteError> {
        if self.is_detached() || !self.is_dirty() {
            return Ok(None);
        }
        let (dir, name) = self.location();
        ops.commit_editor(&dir, &name, Arc::clone(&self.inner))
            .await
            .map(Some)
    }
    /// Save the staged ciphertext without decrypting or re-encrypting it.
    pub fn recover(&self, ops: &VaultOperationsAsync, root: &Path) -> io::Result<PathBuf> {
        let (dir, name) = self.location();
        oxcrypt_core::fs::recovery::save_editor(
            root,
            ops.master_key(),
            &dir,
            &name,
            &mut self.inner.lock(),
        )
    }
}
