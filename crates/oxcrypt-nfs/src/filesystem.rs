//! NFS filesystem implementation for Cryptomator vaults.
//!
//! This module implements the `NFSFileSystem` trait from `nfsserve` to provide
//! an NFS server backend for Cryptomator vaults.

use crate::error::vault_error_to_nfsstat;
use crate::inode::{InodeEntry, InodeKind, NfsInodeTable, ROOT_FILEID};
use async_trait::async_trait;
use dashmap::DashMap;
use nfsserve::nfs::{
    fattr3, fileid3, filename3, ftype3, nfspath3, nfsstat3, nfsstring, nfstime3, sattr3, set_size3,
    specdata3,
};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use oxcrypt_core::fs::streaming::encrypted_to_plaintext_size_or_zero_for_cipher;
use oxcrypt_core::vault::operations_async::VaultOperationsAsync;
use oxcrypt_core::vault::path::{DirId, VaultPath};
use oxcrypt_mount::{EditBuffer, VaultStats};
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, trace};

/// NFS filesystem implementation for Cryptomator vaults.
///
/// This implements the `NFSFileSystem` trait to provide NFS access to vault contents.
/// It uses shared utilities from `oxcrypt-mount`:
/// - `WriteBuffer` for buffering writes until flush/commit
/// - `VaultErrorCategory` for error mapping (via `vault_error_to_nfsstat`)
///
/// # Write Buffering
///
/// NFS clients may split large writes into multiple WRITE RPCs. To handle this correctly,
/// we buffer writes in memory per-file and only flush to the vault when:
/// - A write completes (FILE_SYNC in nfsserve)
/// - A read is requested (read-after-write consistency)
/// - setattr with truncate is called
/// - The file is removed
/// - A rename operation occurs
///
/// NFS filesystem with streaming reads and serialized chunk commits.
pub struct CryptomatorNFS {
    /// Vault operations for reading/writing encrypted files.
    ops: Arc<VaultOperationsAsync>,
    /// Mapping between NFS file IDs and vault paths.
    inodes: NfsInodeTable,
    /// Write buffers for files with pending writes.
    /// Key: file ID, Value: WriteBuffer containing pending data.
    flush_lock: Arc<tokio::sync::Mutex<()>>,
    /// Pending encrypted edits, retained after write-back failures.
    editors: Arc<DashMap<fileid3, Arc<EditBuffer>>>,
    /// Server generation number (for cookieverf3).
    generation: u64,
    /// UID for all files (from process).
    uid: u32,
    /// GID for all files (from process).
    gid: u32,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

/// Shared by RPC requests and the mount lifecycle.
#[derive(Clone)]
pub(crate) struct NfsWriteback {
    ops: Arc<VaultOperationsAsync>,
    editors: Arc<DashMap<fileid3, Arc<EditBuffer>>>,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl NfsWriteback {
    pub(crate) async fn flush_all(&self) -> Result<(), nfsstat3> {
        let ids: Vec<_> = self.editors.iter().map(|entry| *entry.key()).collect();
        let mut failure = None;
        for id in ids {
            if let Err(error) = self.flush(id).await {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    async fn flush(&self, id: fileid3) -> Result<u64, nfsstat3> {
        // Prevent an older snapshot from overwriting a newer one on disk.
        let _guard = self.lock.lock().await;
        self.flush_unlocked(id).await
    }

    async fn flush_unlocked(&self, id: fileid3) -> Result<u64, nfsstat3> {
        let editor = self.editors.get(&id).map(|entry| Arc::clone(entry.value()));
        if let Some(editor) = editor {
            editor
                .commit(&self.ops)
                .await
                .map_err(|error| vault_error_to_nfsstat(&error))?;
            self.editors.remove(&id);
            return Ok(editor.len());
        }
        Ok(0)
    }
}

impl CryptomatorNFS {
    /// Creates a new NFS filesystem for the given vault.
    pub fn new(ops: Arc<VaultOperationsAsync>) -> Self {
        let generation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            ops,
            inodes: NfsInodeTable::new(),
            flush_lock: Arc::new(tokio::sync::Mutex::new(())),
            editors: Arc::new(DashMap::new()),
            generation,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            stats: Arc::new(VaultStats::new()),
        }
    }

    /// Get the statistics for this filesystem.
    pub fn stats(&self) -> Arc<VaultStats> {
        Arc::clone(&self.stats)
    }

    pub(crate) fn writeback(&self) -> NfsWriteback {
        NfsWriteback {
            ops: Arc::clone(&self.ops),
            editors: Arc::clone(&self.editors),
            lock: Arc::clone(&self.flush_lock),
        }
    }

    /// Persist every pending buffer and report failures to the caller.
    pub async fn flush_all_buffers(&self) -> Result<(), nfsstat3> {
        self.writeback().flush_all().await
    }

    async fn flush_buffer(&self, id: fileid3) -> Result<u64, nfsstat3> {
        self.writeback().flush(id).await
    }

    async fn editor(
        &self,
        id: fileid3,
        dir: &DirId,
        name: &str,
    ) -> Result<Arc<EditBuffer>, nfsstat3> {
        if let Some(editor) = self.editors.get(&id) {
            return Ok(Arc::clone(editor.value()));
        }
        let editor = Arc::new(
            EditBuffer::open(&self.ops, dir.clone(), name.to_owned(), false, false)
                .await
                .map_err(|error| vault_error_to_nfsstat(&error))?,
        );
        self.editors.insert(id, Arc::clone(&editor));
        Ok(editor)
    }

    /// Creates file attributes for a directory.
    fn dir_attr(&self, fileid: u64, mtime: Option<nfstime3>) -> fattr3 {
        let time = mtime.unwrap_or_else(Self::current_time);
        fattr3 {
            ftype: ftype3::NF3DIR,
            mode: 0o755,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            size: 4096,
            used: 4096,
            rdev: specdata3::default(),
            fsid: 0,
            fileid,
            atime: time,
            mtime: time,
            ctime: time,
        }
    }

    /// Creates file attributes for a regular file.
    fn file_attr(&self, fileid: u64, size: u64, mtime: Option<nfstime3>) -> fattr3 {
        let time = mtime.unwrap_or_else(Self::current_time);
        fattr3 {
            ftype: ftype3::NF3REG,
            mode: 0o644,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            size,
            used: size,
            rdev: specdata3::default(),
            fsid: 0,
            fileid,
            atime: time,
            mtime: time,
            ctime: time,
        }
    }

    /// Creates file attributes for a symlink.
    fn symlink_attr(&self, fileid: u64, target_len: u64, mtime: Option<nfstime3>) -> fattr3 {
        let time = mtime.unwrap_or_else(Self::current_time);
        fattr3 {
            ftype: ftype3::NF3LNK,
            mode: 0o777,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            size: target_len,
            used: target_len,
            rdev: specdata3::default(),
            fsid: 0,
            fileid,
            atime: time,
            mtime: time,
            ctime: time,
        }
    }

    /// Gets the current time as NFS time.
    fn current_time() -> nfstime3 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        // Safe cast: NFS seconds field is u32, wraps at 32-bit boundary (acceptable for NFS)
        #[allow(clippy::cast_possible_truncation)]
        nfstime3 {
            seconds: now.as_secs() as u32,
            nseconds: now.subsec_nanos(),
        }
    }

    /// Converts SystemTime to NFS time format.
    fn system_time_to_nfs(t: SystemTime) -> nfstime3 {
        let duration = t.duration_since(UNIX_EPOCH).unwrap_or_default();
        // Safe cast: NFS seconds field is u32, wraps at 32-bit boundary (acceptable for NFS)
        #[allow(clippy::cast_possible_truncation)]
        nfstime3 {
            seconds: duration.as_secs() as u32,
            nseconds: duration.subsec_nanos(),
        }
    }

    /// Gets mtime from an encrypted file path.
    #[inline]
    fn get_mtime(path: &std::path::Path) -> Option<nfstime3> {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .map(Self::system_time_to_nfs)
    }

    /// Applies timestamp updates from setattr to the encrypted file.
    /// Timestamps are stored on the encrypted .c9r files.
    ///
    /// NOTE: This is currently a stub. A full implementation would require:
    /// 1. Caching encrypted_path in InodeKind, OR
    /// 2. Doing an async vault lookup here (which requires &self and async context)
    ///
    /// getattr already correctly reads timestamps from encrypted files.
    /// setattr silently accepts timestamp changes (previous behavior).
    fn apply_timestamps(_entry: &InodeEntry, _setattr: &sattr3) {
        // TODO: Implement timestamp updates when encrypted_path is available in InodeKind
        // For now, timestamps are silently accepted but not persisted.
        // This is consistent with previous behavior and with how we handle chmod/chown.
    }

    /// Gets an inode entry or returns NFS3ERR_STALE.
    fn get_entry(
        &self,
        id: fileid3,
    ) -> Result<dashmap::mapref::one::Ref<'_, u64, InodeEntry>, nfsstat3> {
        self.inodes.get(id).ok_or(nfsstat3::NFS3ERR_STALE)
    }

    /// Gets a directory entry or returns NFS3ERR_NOTDIR/NFS3ERR_STALE.
    fn get_dir_entry(&self, id: fileid3) -> Result<DirId, nfsstat3> {
        let entry = self.get_entry(id)?;
        entry.dir_id().ok_or(nfsstat3::NFS3ERR_NOTDIR)
    }

    /// Converts a filename3 to a Rust string.
    fn filename_to_str(filename: &filename3) -> Result<&str, nfsstat3> {
        std::str::from_utf8(filename).map_err(|_| nfsstat3::NFS3ERR_INVAL)
    }

    /// Gets the parent path for a directory entry.
    fn get_parent_path(&self, dirid: fileid3) -> Result<VaultPath, nfsstat3> {
        let entry = self.get_entry(dirid)?;
        Ok(entry.path.clone())
    }
}

#[async_trait]
impl NFSFileSystem for CryptomatorNFS {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_FILEID
    }

    fn serverid(&self) -> [u8; 8] {
        self.generation.to_be_bytes()
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = Self::filename_to_str(filename)?;
        trace!(dirid, name, "lookup");

        // Handle special names
        if name == "." {
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(dirid);
        }

        let parent_path = self.get_parent_path(dirid)?;
        let dir_id = self.get_dir_entry(dirid)?;

        // Handle ".." - go to parent
        if name == ".." {
            if let Some(parent) = parent_path.parent()
                && let Some(id) = self.inodes.get_id(&parent)
            {
                self.stats.record_metadata_latency(start.elapsed());
                return Ok(id);
            }
            // At root, ".." is root itself
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(ROOT_FILEID);
        }

        let child_path = parent_path.join(name);

        // Check if we already have this entry
        if let Some(id) = self.inodes.get_id(&child_path) {
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(id);
        }

        // Try to look up as directory first
        if let Ok(Some(dir_info)) = self.ops.find_directory(&dir_id, name).await {
            let kind = InodeKind::Directory {
                dir_id: dir_info.directory_id,
            };
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(self.inodes.get_or_insert(&child_path, kind));
        }

        // Try as file
        if let Ok(Some(_file_info)) = self.ops.find_file(&dir_id, name).await {
            let kind = InodeKind::File {
                dir_id: dir_id.clone(),
                name: name.to_string(),
            };
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(self.inodes.get_or_insert(&child_path, kind));
        }

        // Try as symlink - use O(1) lookup instead of reading the full target
        if self
            .ops
            .find_symlink(&dir_id, name)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            let kind = InodeKind::Symlink {
                dir_id: dir_id.clone(),
                name: name.to_string(),
            };
            self.stats.record_metadata_latency(start.elapsed());
            return Ok(self.inodes.get_or_insert(&child_path, kind));
        }

        self.stats.record_metadata_latency(start.elapsed());
        self.stats.record_error();
        Err(nfsstat3::NFS3ERR_NOENT)
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(id, "getattr");

        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_metadata_latency(start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        };

        let result = match &entry.kind {
            InodeKind::Root | InodeKind::Directory { .. } => Ok(self.dir_attr(id, None)),
            InodeKind::File { dir_id, name } => {
                // Check if we have a buffer with pending writes - use that size
                if let Some(buffer) = self.editors.get(&id) {
                    return {
                        self.stats.record_metadata_latency(start.elapsed());
                        // Buffer has pending changes, use current time
                        Ok(self.file_attr(id, buffer.len(), None))
                    };
                }

                // Get file info from vault
                match self.ops.find_file(dir_id, name).await {
                    Ok(Some(file_info)) => {
                        // Convert encrypted size to plaintext size
                        let cipher = self.ops.cipher_combo();
                        let size = encrypted_to_plaintext_size_or_zero_for_cipher(
                            file_info.encrypted_size,
                            cipher,
                        );
                        // Read mtime from encrypted file
                        let mtime = Self::get_mtime(&file_info.encrypted_path);
                        Ok(self.file_attr(id, size, mtime))
                    }
                    Ok(None) => {
                        self.stats.record_error();
                        Err(nfsstat3::NFS3ERR_NOENT)
                    }
                    Err(e) => {
                        self.stats.record_error();
                        Err(vault_error_to_nfsstat(&e))
                    }
                }
            }
            InodeKind::Symlink { dir_id, name } => {
                // Get symlink target length using O(1) lookup
                match self.ops.find_symlink(dir_id, name).await {
                    Ok(Some(symlink_info)) => {
                        // Read mtime from encrypted symlink file
                        let mtime = Self::get_mtime(&symlink_info.encrypted_path);
                        Ok(self.symlink_attr(id, symlink_info.target.len() as u64, mtime))
                    }
                    Ok(None) => {
                        self.stats.record_error();
                        Err(nfsstat3::NFS3ERR_NOENT)
                    }
                    Err(e) => {
                        self.stats.record_error();
                        Err(vault_error_to_nfsstat(&e))
                    }
                }
            }
        };

        self.stats.record_metadata_latency(start.elapsed());
        result
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(id, ?setattr, "setattr");

        // Get entry to find encrypted path for timestamp/size updates
        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_metadata_latency(start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        };

        // Handle size changes (truncate)
        // Cryptomator doesn't store Unix permissions, so chmod/chown are silently ignored.
        // This matches the behavior of vfat and other filesystems without permission support.
        if let set_size3::size(size) = setattr.size {
            if let Some((dir_id, name)) = entry.file_info() {
                let dir_id = dir_id.clone();
                let name = name.to_string();
                drop(entry); // Release the borrow before async operations

                let _mutation = self.flush_lock.lock().await;
                let editor = self.editor(id, &dir_id, &name).await?;
                editor
                    .truncate(size)
                    .map_err(|error| vault_error_to_nfsstat(&error))?;
                self.writeback().flush_unlocked(id).await?;

                // Re-get entry for timestamp handling
                let entry = match self.get_entry(id) {
                    Ok(e) => e,
                    Err(e) => {
                        self.stats.record_metadata_latency(start.elapsed());
                        self.stats.record_error();
                        return Err(e);
                    }
                };
                // Handle timestamp updates after truncate
                Self::apply_timestamps(&entry, &setattr);
            }
        } else {
            // No size change - just handle timestamps
            Self::apply_timestamps(&entry, &setattr);
            drop(entry);
        }

        self.stats.record_metadata_latency(start.elapsed());
        // Return current attributes (getattr records its own metadata op)
        self.getattr(id).await
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        let op_start = Instant::now();
        trace!(id, offset, count, "read");

        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_read_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        };
        let (dir_id, name) = match entry.file_info() {
            Some((d, n)) => (d.clone(), n.to_string()),
            None => {
                self.stats.record_read_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }
        };
        drop(entry); // Release the borrow before async operations

        if self.editors.contains_key(&id) {
            self.flush_buffer(id).await?;
        }
        let mut reader = self
            .ops
            .open_file_unlocked(&dir_id, &name)
            .await
            .map_err(|error| vault_error_to_nfsstat(&error))?;
        let size = reader.plaintext_size();
        let data = reader
            .read_range(offset, count as usize)
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?;
        let eof = offset.saturating_add(data.len() as u64) >= size;
        self.stats.record_read(data.len() as u64);
        self.stats.record_decrypted(data.len() as u64);
        self.stats.record_read_latency(op_start.elapsed());
        Ok((data, eof))
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        let op_start = Instant::now();
        debug!(id, offset, data_len = data.len(), "write");

        // Log large writes that might be slow
        if data.len() > 65536 {
            debug!(
                id,
                offset,
                data_len = data.len(),
                "Large write operation (>64KB)"
            );
        }

        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_write_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(e);
            }
        };
        let (dir_id, name) = match entry.file_info() {
            Some((d, n)) => (d.clone(), n.to_string()),
            None => {
                self.stats.record_write_latency(op_start.elapsed());
                self.stats.record_error();
                return Err(nfsstat3::NFS3ERR_ISDIR);
            }
        };
        drop(entry); // Release the borrow before async operations

        let _mutation = self.flush_lock.lock().await;
        let editor = self.editor(id, &dir_id, &name).await?;
        let mut written = 0;
        while written < data.len() {
            let count = editor
                .write(offset + written as u64, &data[written..])
                .map_err(|error| vault_error_to_nfsstat(&error))?;
            if count == 0 {
                return Err(nfsstat3::NFS3ERR_IO);
            }
            written += count;
        }
        let new_size = editor.len();
        self.writeback().flush_unlocked(id).await?;
        self.stats.record_write(data.len() as u64);
        self.stats.record_write_latency(op_start.elapsed());
        Ok(self.file_attr(id, new_size, None))
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        _attr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(dirid, name, "create");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Create empty file
        if let Err(e) = self.ops.write_file(&dir_id, name, &[]).await {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(vault_error_to_nfsstat(&e));
        }

        // Register in inode table
        let child_path = parent_path.join(name);
        let kind = InodeKind::File {
            dir_id: dir_id.clone(),
            name: name.to_string(),
        };
        let id = self.inodes.get_or_insert(&child_path, kind);

        // Newly created file, use current time
        let attr = self.file_attr(id, 0, None);
        self.stats.record_metadata_latency(start.elapsed());
        Ok((id, attr))
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(dirid, name, "create_exclusive");

        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Check if any entry already exists
        match self.ops.find_file(&dir_id, name).await {
            Ok(Some(_)) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(nfsstat3::NFS3ERR_EXIST);
            }
            Ok(None) => {}
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        }

        match self.ops.find_directory(&dir_id, name).await {
            Ok(Some(_)) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(nfsstat3::NFS3ERR_EXIST);
            }
            Ok(None) => {}
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        }

        match self.ops.find_symlink(&dir_id, name).await {
            Ok(Some(_)) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(nfsstat3::NFS3ERR_EXIST);
            }
            Ok(None) => {}
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        }

        // Create using regular create (which has its own stats recording)
        match self.create(dirid, filename, sattr3::default()).await {
            Ok((id, _)) => {
                self.stats.record_metadata_latency(start.elapsed());
                Ok(id)
            }
            Err(e) => {
                // Error already recorded in create()
                self.stats.record_metadata_latency(start.elapsed());
                Err(e)
            }
        }
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(dirname) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(dirid, name, "mkdir");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let parent_dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Create directory in vault
        let new_dir_id = match self.ops.create_directory(&parent_dir_id, name).await {
            Ok(id) => id,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        };

        // Register in inode table
        let child_path = parent_path.join(name);
        let kind = InodeKind::Directory { dir_id: new_dir_id };
        let id = self.inodes.get_or_insert(&child_path, kind);

        // Newly created directory, use current time
        let attr = self.dir_attr(id, None);
        self.stats.record_metadata_latency(start.elapsed());
        Ok((id, attr))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(dirid, name, "remove");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Get file ID to discard any pending write buffer and read cache
        let child_path = parent_path.join(name);
        if let Some(file_id) = self.inodes.get_id(&child_path) {
            // Discard pending writes - file is being deleted
            self.editors.remove(&file_id);
            // Invalidate read cache for the deleted file
        }

        // Try to remove as file first
        if let Ok(Some(_)) = self.ops.find_file(&dir_id, name).await {
            if let Err(e) = self.ops.delete_file(&dir_id, name).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        } else if self
            .ops
            .find_symlink(&dir_id, name)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            // It's a symlink - use O(1) lookup
            if let Err(e) = self.ops.delete_symlink(&dir_id, name).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        } else if let Ok(Some(_)) = self.ops.find_directory(&dir_id, name).await {
            // It's a directory
            if let Err(e) = self.ops.delete_directory(&dir_id, name).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        } else {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(nfsstat3::NFS3ERR_NOENT);
        }

        // Remove from inode table
        self.inodes.remove(&child_path);

        self.stats.record_metadata_latency(start.elapsed());
        Ok(())
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let _mutation = self.flush_lock.lock().await;
        let start = Instant::now();
        self.stats.record_metadata_op();

        let from_name = match Self::filename_to_str(from_filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let to_name = match Self::filename_to_str(to_filename) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        debug!(from_dirid, from_name, to_dirid, to_name, "rename");

        let from_parent_path = match self.get_parent_path(from_dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let from_dir_id = match self.get_dir_entry(from_dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let to_dir_id = match self.get_dir_entry(to_dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Flush any pending writes for the source file before rename
        let from_path = from_parent_path.join(from_name);
        if let Some(file_id) = self.inodes.get_id(&from_path)
            && (self.editors.contains_key(&file_id))
        {
            debug!(file_id, "Flushing buffer before rename");
            // Invalidate read cache since we're writing new content

            if let Err(e) = self.writeback().flush_unlocked(file_id).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        }

        self.ops
            .rename_entry_atomic(&from_dir_id, from_name, &to_dir_id, to_name)
            .await
            .map_err(|error| vault_error_to_nfsstat(&error))?;

        // Update inode table
        let old_path = from_parent_path.join(from_name);
        let to_parent_path = match self.get_parent_path(to_dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let new_path = to_parent_path.join(to_name);

        if let Some(id) = self.inodes.get_id(&old_path) {
            self.inodes.update_path(id, &old_path, &new_path);
        }

        self.stats.record_metadata_latency(start.elapsed());
        Ok(())
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(dirid, start_after, max_entries, "readdir");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let cipher = self.ops.cipher_combo();

        // Build entry list from vault
        let mut entries: Vec<DirEntry> = Vec::new();

        // List files
        let files = match self.ops.list_files(&dir_id).await {
            Ok(f) => f,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        };

        for file_info in files {
            let child_path = parent_path.join(&file_info.name);
            let kind = InodeKind::File {
                dir_id: dir_id.clone(),
                name: file_info.name.clone(),
            };
            let id = self.inodes.get_or_insert(&child_path, kind);
            // Convert encrypted size to plaintext size
            let size =
                encrypted_to_plaintext_size_or_zero_for_cipher(file_info.encrypted_size, cipher);
            // Read mtime from encrypted file
            let mtime = Self::get_mtime(&file_info.encrypted_path);
            let attr = self.file_attr(id, size, mtime);
            entries.push(DirEntry {
                fileid: id,
                name: nfsstring(file_info.name.as_bytes().to_vec()),
                attr,
            });
        }

        // List directories
        let dirs = match self.ops.list_directories(&dir_id).await {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        };

        for dir_info in dirs {
            let child_path = parent_path.join(&dir_info.name);
            let kind = InodeKind::Directory {
                dir_id: dir_info.directory_id,
            };
            let id = self.inodes.get_or_insert(&child_path, kind);
            // Read mtime from encrypted directory
            let mtime = Self::get_mtime(&dir_info.encrypted_path);
            let attr = self.dir_attr(id, mtime);
            entries.push(DirEntry {
                fileid: id,
                name: nfsstring(dir_info.name.as_bytes().to_vec()),
                attr,
            });
        }

        // List symlinks
        let symlinks = match self.ops.list_symlinks(&dir_id).await {
            Ok(s) => s,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(vault_error_to_nfsstat(&e));
            }
        };

        for symlink_info in symlinks {
            let child_path = parent_path.join(&symlink_info.name);
            let kind = InodeKind::Symlink {
                dir_id: dir_id.clone(),
                name: symlink_info.name.clone(),
            };
            let id = self.inodes.get_or_insert(&child_path, kind);
            // Read mtime from encrypted symlink file
            let mtime = Self::get_mtime(&symlink_info.encrypted_path);
            let attr = self.symlink_attr(id, symlink_info.target.len() as u64, mtime);
            entries.push(DirEntry {
                fileid: id,
                name: nfsstring(symlink_info.name.as_bytes().to_vec()),
                attr,
            });
        }

        // Sort entries by name for deterministic ordering
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        // Handle pagination
        let start_idx = if start_after == 0 {
            0
        } else {
            entries
                .iter()
                .position(|e| e.fileid == start_after)
                .map_or(0, |i| i + 1)
        };

        let result_entries: Vec<DirEntry> = entries
            .into_iter()
            .skip(start_idx)
            .take(max_entries)
            .collect();

        let end = result_entries.len() < max_entries;

        self.stats.record_metadata_latency(start.elapsed());
        Ok(ReadDirResult {
            entries: result_entries,
            end,
        })
    }

    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink_target: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();

        let name = match Self::filename_to_str(linkname) {
            Ok(n) => n,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let Ok(target) = std::str::from_utf8(symlink_target) else {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(nfsstat3::NFS3ERR_INVAL);
        };
        debug!(dirid, name, target, "symlink");

        let parent_path = match self.get_parent_path(dirid) {
            Ok(p) => p,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };
        let dir_id = match self.get_dir_entry(dirid) {
            Ok(d) => d,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        // Create symlink in vault
        if let Err(e) = self.ops.create_symlink(&dir_id, name, target).await {
            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            return Err(vault_error_to_nfsstat(&e));
        }

        // Register in inode table
        let child_path = parent_path.join(name);
        let kind = InodeKind::Symlink {
            dir_id: dir_id.clone(),
            name: name.to_string(),
        };
        let id = self.inodes.get_or_insert(&child_path, kind);

        // Newly created symlink, use current time
        let attr = self.symlink_attr(id, target.len() as u64, None);
        self.stats.record_metadata_latency(start.elapsed());
        Ok((id, attr))
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        let start = Instant::now();
        self.stats.record_metadata_op();
        trace!(id, "readlink");

        let entry = match self.get_entry(id) {
            Ok(e) => e,
            Err(e) => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }
        };

        match &entry.kind {
            InodeKind::Symlink { dir_id, name } => {
                let target = match self.ops.read_symlink(dir_id, name).await {
                    Ok(t) => t,
                    Err(e) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(vault_error_to_nfsstat(&e));
                    }
                };
                self.stats.record_metadata_latency(start.elapsed());
                Ok(nfsstring(target.into_bytes()))
            }
            _ => {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                Err(nfsstat3::NFS3ERR_INVAL)
            }
        }
    }
}

/// Newtype wrapper around Arc<CryptomatorNFS> to allow shared ownership
/// while implementing the NFSFileSystem trait (orphan rule workaround).
#[allow(dead_code)]
pub struct ArcNfs(pub Arc<CryptomatorNFS>);

#[allow(dead_code)]
impl ArcNfs {
    /// Create a new ArcNfs from a CryptomatorNFS instance
    pub fn new(nfs: CryptomatorNFS) -> Self {
        Self(Arc::new(nfs))
    }

    /// Get a clone of the inner Arc for shared access
    pub fn clone_inner(&self) -> Arc<CryptomatorNFS> {
        Arc::clone(&self.0)
    }
}

// Implement NFSFileSystem for ArcNfs to allow shared ownership
// This delegates all calls to the inner CryptomatorNFS implementation
#[async_trait]
impl NFSFileSystem for ArcNfs {
    fn capabilities(&self) -> VFSCapabilities {
        self.0.capabilities()
    }

    fn root_dir(&self) -> fileid3 {
        self.0.root_dir()
    }

    fn serverid(&self) -> [u8; 8] {
        self.0.serverid()
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        self.0.lookup(dirid, filename).await
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        self.0.getattr(id).await
    }

    async fn setattr(&self, id: fileid3, setattr: sattr3) -> Result<fattr3, nfsstat3> {
        self.0.setattr(id, setattr).await
    }

    async fn read(
        &self,
        id: fileid3,
        offset: u64,
        count: u32,
    ) -> Result<(Vec<u8>, bool), nfsstat3> {
        self.0.read(id, offset, count).await
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        self.0.write(id, offset, data).await
    }

    async fn create(
        &self,
        dirid: fileid3,
        filename: &filename3,
        setattr: sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        self.0.create(dirid, filename, setattr).await
    }

    async fn create_exclusive(
        &self,
        dirid: fileid3,
        filename: &filename3,
    ) -> Result<fileid3, nfsstat3> {
        self.0.create_exclusive(dirid, filename).await
    }

    async fn mkdir(
        &self,
        dirid: fileid3,
        dirname: &filename3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        self.0.mkdir(dirid, dirname).await
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        self.0.remove(dirid, filename).await
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        self.0
            .rename(from_dirid, from_filename, to_dirid, to_filename)
            .await
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        self.0.readdir(dirid, start_after, max_entries).await
    }

    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        self.0.symlink(dirid, linkname, symlink, attr).await
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        self.0.readlink(id).await
    }
}

#[cfg(test)]
mod writeback_tests {
    use crate::filesystem::*;
    use oxcrypt_mount::testing::TempVault;

    #[tokio::test]
    async fn resize_preserves_prefix_and_zero_fills_extension() {
        let vault = TempVault::new();
        let ops =
            Arc::new(VaultOperationsAsync::open(vault.path(), TempVault::password()).unwrap());
        let filesystem = CryptomatorNFS::new(Arc::clone(&ops));
        let (id, _) = filesystem
            .create(ROOT_FILEID, &b"note"[..].into(), sattr3::default())
            .await
            .unwrap();
        filesystem.write(id, 0, b"abc").await.unwrap();
        for size in [4096, 2, 64, 0] {
            let attr = filesystem
                .setattr(
                    id,
                    sattr3 {
                        size: set_size3::size(size),
                        ..sattr3::default()
                    },
                )
                .await
                .unwrap();
            let data = ops.read_file(&DirId::root(), "note").await.unwrap().content;
            assert_eq!(attr.size, size);
            assert_eq!(data.len() as u64, size);
            if size > 0 {
                assert_eq!(&data[..2], b"ab");
                let prefix = if size == 4096 { 3 } else { 2 };
                assert!(data[prefix..].iter().all(|byte| *byte == 0));
            }
        }
    }

    #[tokio::test]
    async fn cancelled_flush_keeps_the_buffer() {
        let vault = TempVault::new();
        let ops =
            Arc::new(VaultOperationsAsync::open(vault.path(), TempVault::password()).unwrap());
        let filesystem = CryptomatorNFS::new(Arc::clone(&ops));
        let buffer = Arc::new(
            EditBuffer::open(&ops, DirId::root(), "note".into(), true, false)
                .await
                .unwrap(),
        );
        buffer.write(0, b"pending").unwrap();
        filesystem.editors.insert(42, buffer);
        let writer = ops
            .create_file(&DirId::root(), "lock-holder")
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), filesystem.flush_buffer(42))
                .await
                .is_err()
        );
        assert_eq!(
            filesystem.editors.get(&42).unwrap().read(0, 100).unwrap(),
            b"pending"
        );
        drop(writer);
        filesystem.flush_all_buffers().await.unwrap();
        assert_eq!(
            ops.read_file(&DirId::root(), "note").await.unwrap().content,
            b"pending"
        );
    }

    #[tokio::test]
    async fn write_does_not_replace_unreadable_existing_content() {
        let vault = TempVault::new();
        let ops =
            Arc::new(VaultOperationsAsync::open(vault.path(), TempVault::password()).unwrap());
        let filesystem = CryptomatorNFS::new(Arc::clone(&ops));
        let (id, _) = filesystem
            .create(ROOT_FILEID, &b"note"[..].into(), sattr3::default())
            .await
            .unwrap();
        let path = ops
            .write_file(&DirId::root(), "note", b"original")
            .await
            .unwrap();
        let mut corrupt = std::fs::read(&path).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert!(filesystem.write(id, 0, b"edit").await.is_err());
        assert_eq!(std::fs::read(path).unwrap(), corrupt);
    }

    #[tokio::test]
    async fn failed_flush_is_retained_and_shutdown_reports_it() {
        let vault = TempVault::new();
        let ops =
            Arc::new(VaultOperationsAsync::open(vault.path(), TempVault::password()).unwrap());
        let filesystem = CryptomatorNFS::new(Arc::clone(&ops));
        let path = ops
            .write_file(&DirId::root(), "note", b"old")
            .await
            .unwrap();
        let buffer = Arc::new(
            EditBuffer::open(&ops, DirId::root(), "note".into(), false, true)
                .await
                .unwrap(),
        );
        buffer.write(0, b"pending note").unwrap();
        let backup = path.with_extension("fault-backup");
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        filesystem.editors.insert(42, buffer);
        assert!(filesystem.flush_all_buffers().await.is_err());
        assert_eq!(
            filesystem.editors.get(&42).unwrap().read(0, 100).unwrap(),
            b"pending note"
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        filesystem.flush_all_buffers().await.unwrap();
        assert!(filesystem.editors.is_empty());
        assert_eq!(
            ops.read_file(&DirId::root(), "note").await.unwrap().content,
            b"pending note"
        );
    }

    #[tokio::test]
    async fn small_write_is_persisted_before_file_sync_acknowledgement() {
        let vault = TempVault::new();
        let ops =
            Arc::new(VaultOperationsAsync::open(vault.path(), TempVault::password()).unwrap());
        let filesystem = CryptomatorNFS::new(Arc::clone(&ops));
        let (id, _) = filesystem
            .create(ROOT_FILEID, &b"note"[..].into(), sattr3::default())
            .await
            .unwrap();
        filesystem
            .write(id, 0, b"small durable write")
            .await
            .unwrap();
        assert_eq!(
            ops.read_file(&DirId::root(), "note").await.unwrap().content,
            b"small durable write"
        );
    }
}
