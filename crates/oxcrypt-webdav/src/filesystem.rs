//! WebDAV filesystem implementation for Cryptomator vaults.
//!
//! This module provides the `DavFileSystem` trait implementation that wraps
//! `VaultOperationsAsync` to expose vault contents via WebDAV.

use crate::dir_entry::CryptomatorDirEntry;
use crate::error::{WebDavError, vault_error_to_fs_error, write_error_to_fs_error};
use crate::file::{CryptomatorFile, PendingWrite, WriteBufferTable};
use crate::metadata::CryptomatorMetaData;
use dav_server::davpath::DavPath;
use dav_server::fs::{
    DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsStream, OpenOptions,
    ReadDirMeta,
};
use futures::stream;
use oxcrypt_core::vault::DirId;
use oxcrypt_core::vault::operations_async::VaultOperationsAsync;
use oxcrypt_mount::moka_cache::SyncTtlCache;
use oxcrypt_mount::{EditBuffer, HandleTable, VaultStats};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, instrument, trace};

/// Type alias for metadata cache (path -> CryptomatorMetaData).
type MetadataCache = SyncTtlCache<String, CryptomatorMetaData>;

/// Type alias for path resolution cache (path -> DirId).
type PathResolutionCache = SyncTtlCache<String, DirId>;

/// TTL for path resolution cache entries (5 seconds - longer than metadata).
/// Path structure changes less frequently than file contents.
const PATH_CACHE_TTL: Duration = Duration::from_secs(5);

/// WebDAV filesystem backed by a Cryptomator vault.
///
/// Implements the `DavFileSystem` trait from dav-server to expose
/// an encrypted vault as a WebDAV resource.
///
/// # Performance Optimizations
///
/// This implementation includes several caches to reduce vault operations:
/// - **Path resolution cache**: Maps vault paths to directory IDs (5s TTL)
/// - **Metadata cache**: Caches file/directory metadata (1s TTL)
/// - **File info cache**: At VaultOperationsAsync level, caches encrypted paths
#[derive(Clone)]
pub struct CryptomatorWebDav {
    /// Shared vault operations (thread-safe via Arc).
    ops: Arc<VaultOperationsAsync>,
    /// Write buffer table for pending PUT operations.
    write_buffers: Arc<WriteBufferTable>,
    flush_lock: Arc<tokio::sync::Mutex<()>>,
    path_locks: Arc<crate::path_locks::PathLocks>,
    recovery_root: Option<PathBuf>,
    /// Metadata cache to reduce vault operations.
    metadata_cache: Arc<MetadataCache>,
    /// Path resolution cache (vault_path -> DirId).
    path_cache: Arc<PathResolutionCache>,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

impl CryptomatorWebDav {
    /// Create a new WebDAV filesystem from vault operations.
    pub fn new(ops: Arc<VaultOperationsAsync>) -> Self {
        // Create stats first so we can connect caches to it
        let stats = Arc::new(VaultStats::new());

        // Create metadata cache and connect it to stats for hit/miss tracking
        let mut metadata_cache = SyncTtlCache::with_defaults();
        metadata_cache.set_stats(stats.cache_stats());

        // Create path resolution cache with longer TTL (5s)
        // Path structure changes less frequently than file contents
        let path_cache = SyncTtlCache::new(PATH_CACHE_TTL);

        Self {
            ops,
            write_buffers: Arc::new(HandleTable::new()),
            flush_lock: Arc::new(tokio::sync::Mutex::new(())),
            path_locks: Arc::new(crate::path_locks::PathLocks::default()),
            recovery_root: None,
            metadata_cache: Arc::new(metadata_cache),
            path_cache: Arc::new(path_cache),
            stats,
        }
    }

    /// Select persistent storage for encrypted copies of writes that cannot be committed.
    #[must_use]
    pub fn with_recovery_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.recovery_root = Some(directory.into());
        self
    }

    /// Drain retained edits after request workers have stopped. Interrupted uploads
    /// are archived without replacing their original files. Failed archives remain
    /// in the table so an explicit shutdown can be retried.
    pub(crate) async fn finish_writeback(&self, interrupted: bool) -> std::io::Result<()> {
        let _paths = self
            .path_locks
            .acquire(&[("", true)])
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let _flush = self.flush_lock.lock().await;
        let mut pending = Vec::new();
        self.write_buffers.retain(|path, editor| {
            pending.push((path.clone(), Arc::clone(editor)));
            true
        });
        let mut errors = Vec::new();
        for (path, editor) in pending {
            let commit = if !editor.is_dirty() {
                Ok(())
            } else if interrupted || !editor.ready_to_commit() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "upload did not complete before shutdown",
                ))
            } else {
                editor
                    .commit(&self.ops)
                    .await
                    .map(|_| ())
                    .map_err(|error| std::io::Error::other(error.to_string()))
            };
            let mut safe_to_release = commit.is_ok();
            if let Err(failure) = commit {
                let root = self
                    .recovery_root
                    .clone()
                    .map_or_else(oxcrypt_core::fs::recovery::default_directory, Ok);
                let recovery = match root {
                    Ok(root) => {
                        let buffer = Arc::clone(&editor);
                        let ops = Arc::clone(&self.ops);
                        tokio::task::spawn_blocking(move || buffer.recover(&ops, &root))
                            .await
                            .map_err(std::io::Error::other)
                            .and_then(|result| result)
                    }
                    Err(error) => Err(error),
                };
                match recovery {
                    Ok(saved) => {
                        safe_to_release = true;
                        errors.push(format!(
                            "{path}: {failure}; encrypted recovery: {}",
                            saved.display()
                        ));
                    }
                    Err(error) => errors.push(format!(
                        "{path}: {failure}; recovery failed: {error}; edits retained for retry"
                    )),
                }
            }
            if safe_to_release {
                self.write_buffers
                    .retain(|key, current| key != &path || !Arc::ptr_eq(current, &editor));
                self.metadata_cache.invalidate(&path);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            let report = errors.join("; ");
            tracing::error!(%report, "WebDAV writeback requires recovery or retry");
            Err(std::io::Error::other(report))
        }
    }

    /// Open a vault and create a WebDAV filesystem.
    pub fn open(vault_path: &Path, password: &str) -> Result<Self, WebDavError> {
        let ops = VaultOperationsAsync::open(vault_path, password)
            .map_err(|e| WebDavError::Server(e.to_string()))?
            .into_shared();

        Ok(Self::new(ops))
    }

    /// Get the statistics for this filesystem.
    pub fn stats(&self) -> Arc<VaultStats> {
        Arc::clone(&self.stats)
    }

    /// Parse a WebDAV path to a vault path string.
    fn parse_path(path: &DavPath) -> Result<String, FsError> {
        // DavPath already contains decoded, normalized path bytes. URL-encoding
        // them again would store percent escapes as literal vault filenames.
        let path_str = std::str::from_utf8(path.as_bytes()).map_err(|_| FsError::Forbidden)?;
        // Remove leading slash if present, then re-add it for consistency
        // Also remove trailing slash which would cause parsing issues
        let normalized = path_str.trim_start_matches('/').trim_end_matches('/');
        let normalized = oxcrypt_core::fs::name::normalize_filename(normalized);
        tracing::trace!(raw_path = %path_str, normalized = %normalized, "parse_path");
        if normalized.is_empty() {
            Ok(String::new())
        } else {
            Ok(format!("/{normalized}"))
        }
    }

    /// Split a path into parent directory ID and filename.
    async fn resolve_path(&self, path: &str) -> Result<(DirId, String), FsError> {
        if path.is_empty() || path == "/" {
            return Err(FsError::GeneralFailure); // Can't split root
        }

        let path = path.trim_start_matches('/');
        let components: Vec<&str> = path.split('/').collect();

        if components.is_empty() {
            return Err(FsError::GeneralFailure);
        }

        let filename = components.last().unwrap().to_string();
        let parent_path = if components.len() == 1 {
            String::new() // Parent is root
        } else {
            format!("/{}", components[..components.len() - 1].join("/"))
        };

        let parent_dir_id = self.resolve_dir_path(&parent_path).await?;
        Ok((parent_dir_id, filename))
    }

    /// Resolve a path to a directory ID (cached).
    async fn resolve_dir_path(&self, path: &str) -> Result<DirId, FsError> {
        if path.is_empty() || path == "/" {
            return Ok(DirId::root());
        }

        // Check path resolution cache first
        let path_key = path.to_string();
        if let Some(cached) = self.path_cache.get(&path_key) {
            trace!(path = %path, "path resolution cache hit");
            return Ok(cached.value);
        }

        // Cache miss - resolve path
        let (dir_id, _is_dir) = self
            .ops
            .resolve_path(path)
            .await
            .map_err(vault_error_to_fs_error)?;

        // Cache the resolved directory ID
        self.path_cache.insert(path_key, dir_id.clone());
        trace!(path = %path, dir_id = %dir_id.as_str(), "path resolution cache miss, cached");

        Ok(dir_id)
    }

    /// Find metadata for a path (file, directory, or symlink).
    ///
    /// Uses O(1) direct lookups (`find_directory`, `find_file`, `find_symlink`)
    /// instead of listing the entire parent directory. This is critical for
    /// performance when directories contain many files.
    async fn find_entry(&self, path: &str) -> Result<CryptomatorMetaData, FsError> {
        if path.is_empty() || path == "/" {
            return Ok(CryptomatorMetaData::root());
        }

        // Check cache first
        let path_key = path.to_string();
        if let Some(cached) = self.metadata_cache.get(&path_key) {
            trace!(path = %path, "metadata cache hit");
            return Ok(cached.value);
        }

        let (parent_dir_id, name) = self.resolve_path(path).await?;

        // Try O(1) lookup for directories first (most common for path resolution)
        // Note: find_directory may return ENOTDIR if the encrypted file is a regular file
        // In that case, we treat it as "not a directory" and continue to file lookup
        match self.ops.find_directory(&parent_dir_id, &name).await {
            Ok(Some(dir_info)) => {
                let meta = CryptomatorMetaData::from_directory(&dir_info);
                self.metadata_cache.insert(path.to_string(), meta.clone());
                trace!(path = %path, "found directory via O(1) lookup");
                return Ok(meta);
            }
            Ok(None) => {} // Not a directory, continue to file lookup
            Err(e) => {
                // ENOTDIR (error code 20) means we tried to open a file as a directory
                // This is expected when the path is a file, so we treat it as "not found"
                // and continue to the next lookup
                use oxcrypt_core::vault::operations::VaultOperationError;
                if matches!(e, VaultOperationError::Io { ref source, .. } if source.raw_os_error() == Some(20))
                {
                    // Not a directory - continue to file lookup
                } else {
                    // Other errors should be propagated
                    return Err(vault_error_to_fs_error(e));
                }
            }
        }

        // Try O(1) lookup for files
        match self.ops.find_file(&parent_dir_id, &name).await {
            Ok(Some(file_info)) => {
                let meta = CryptomatorMetaData::from_file(&file_info, self.ops.cipher_combo());
                self.metadata_cache.insert(path.to_string(), meta.clone());
                trace!(path = %path, "found file via O(1) lookup");
                return Ok(meta);
            }
            Ok(None) => {} // Not a file, continue to symlink lookup
            Err(e) => {
                // Similar to directories, ENOTDIR means we tried to read a directory as a file
                use oxcrypt_core::vault::operations::VaultOperationError;
                if matches!(e, VaultOperationError::Io { ref source, .. } if source.raw_os_error() == Some(20))
                {
                    // Not a file - continue to symlink lookup
                } else {
                    return Err(vault_error_to_fs_error(e));
                }
            }
        }

        // Try O(1) lookup for symlinks
        match self.ops.find_symlink(&parent_dir_id, &name).await {
            Ok(Some(symlink_info)) => {
                let meta = CryptomatorMetaData::from_symlink(&symlink_info);
                self.metadata_cache.insert(path.to_string(), meta.clone());
                trace!(path = %path, "found symlink via O(1) lookup");
                return Ok(meta);
            }
            Ok(None) => {} // Not a symlink
            Err(e) => {
                use oxcrypt_core::vault::operations::VaultOperationError;
                if matches!(e, VaultOperationError::Io { ref source, .. } if source.raw_os_error() == Some(20))
                {
                    // Not a symlink
                } else {
                    return Err(vault_error_to_fs_error(e));
                }
            }
        }

        Err(FsError::NotFound)
    }

    /// Flush a write buffer to the vault.
    async fn flush_write_buffer(&self, path: &str) -> Result<(), FsError> {
        let _guard = self.flush_lock.lock().await;
        self.flush_write_buffer_unlocked(path).await
    }

    async fn flush_write_buffer_unlocked(&self, path: &str) -> Result<(), FsError> {
        let path_key = path.to_string();
        let Some(buffer) = self
            .write_buffers
            .get(&path_key)
            .map(|entry| Arc::clone(entry.value()))
        else {
            return Ok(());
        };
        buffer.request_commit();
        buffer
            .commit(&self.ops)
            .await
            .map_err(write_error_to_fs_error)?;
        self.write_buffers
            .retain(|key, current| key != &path_key || !Arc::ptr_eq(current, &buffer));
        self.metadata_cache.invalidate(&path_key);
        Ok(())
    }

    fn join_path(parent: &str, name: &str) -> String {
        if parent.is_empty() {
            format!("/{name}")
        } else {
            format!("{}/{}", parent.trim_end_matches('/'), name)
        }
    }

    /// Flush retained edits before a tree is moved, copied, or removed.
    /// The caller holds a path lock excluding writers throughout this subtree.
    async fn flush_tree(&self, root: &str) -> Result<(), FsError> {
        let _guard = self.flush_lock.lock().await;
        let prefix = format!("{root}/");
        let mut paths = Vec::new();
        self.write_buffers.retain(|path, _| {
            if path == root || path.starts_with(&prefix) {
                paths.push(path.clone());
            }
            true
        });
        for path in paths {
            self.flush_write_buffer_unlocked(&path).await?;
        }
        Ok(())
    }

    async fn delete_directory_contents_recursive(
        &self,
        dir_id: &DirId,
        dir_path: &str,
    ) -> Result<(), FsError> {
        let mut stack: Vec<(DirId, String, DirId, String, bool)> = Vec::new();

        let (files, dirs, symlinks) = self
            .ops
            .list_all(dir_id)
            .await
            .map_err(vault_error_to_fs_error)?;

        for file in files {
            let file_path = Self::join_path(dir_path, &file.name);
            self.flush_write_buffer(&file_path).await?;
            self.ops
                .delete_file(dir_id, &file.name)
                .await
                .map_err(write_error_to_fs_error)?;
            self.metadata_cache.invalidate(&file_path);
        }

        for symlink in symlinks {
            let symlink_path = Self::join_path(dir_path, &symlink.name);
            self.ops
                .delete_symlink(dir_id, &symlink.name)
                .await
                .map_err(write_error_to_fs_error)?;
            self.metadata_cache.invalidate(&symlink_path);
        }

        for dir in dirs {
            let child_path = Self::join_path(dir_path, &dir.name);
            stack.push((
                dir_id.clone(),
                dir.name,
                dir.directory_id,
                child_path,
                false,
            ));
        }

        while let Some((parent_dir_id, dir_name, current_dir_id, current_path, visited)) =
            stack.pop()
        {
            if visited {
                self.ops
                    .delete_directory(&parent_dir_id, &dir_name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                self.metadata_cache.invalidate_prefix(&current_path);
                self.path_cache.invalidate_prefix(&current_path);
                continue;
            }

            stack.push((
                parent_dir_id.clone(),
                dir_name.clone(),
                current_dir_id.clone(),
                current_path.clone(),
                true,
            ));

            let (files, dirs, symlinks) = self
                .ops
                .list_all(&current_dir_id)
                .await
                .map_err(vault_error_to_fs_error)?;

            for file in files {
                let file_path = Self::join_path(&current_path, &file.name);
                self.flush_write_buffer(&file_path).await?;
                self.ops
                    .delete_file(&current_dir_id, &file.name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                self.metadata_cache.invalidate(&file_path);
            }

            for symlink in symlinks {
                let symlink_path = Self::join_path(&current_path, &symlink.name);
                self.ops
                    .delete_symlink(&current_dir_id, &symlink.name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                self.metadata_cache.invalidate(&symlink_path);
            }

            for dir in dirs {
                let child_path = Self::join_path(&current_path, &dir.name);
                stack.push((
                    current_dir_id.clone(),
                    dir.name,
                    dir.directory_id,
                    child_path,
                    false,
                ));
            }
        }

        Ok(())
    }

    async fn delete_directory_recursive(
        &self,
        parent_dir_id: &DirId,
        dir_name: &str,
        dir_path: &str,
    ) -> Result<(), FsError> {
        let dirs = self
            .ops
            .list_directories(parent_dir_id)
            .await
            .map_err(vault_error_to_fs_error)?;
        let dir_info = dirs
            .into_iter()
            .find(|dir| dir.name == dir_name)
            .ok_or(FsError::NotFound)?;

        self.delete_directory_contents_recursive(&dir_info.directory_id, dir_path)
            .await?;
        self.ops
            .delete_directory(parent_dir_id, dir_name)
            .await
            .map_err(write_error_to_fs_error)?;
        Ok(())
    }

    async fn copy_directory_recursive(
        &self,
        from_dir_id: &DirId,
        to_dir_id: &DirId,
        from_path: &str,
        to_path: &str,
    ) -> Result<(), FsError> {
        let mut stack: Vec<(DirId, DirId, String, String)> = Vec::new();
        stack.push((
            from_dir_id.clone(),
            to_dir_id.clone(),
            from_path.to_string(),
            to_path.to_string(),
        ));

        while let Some((current_from_id, current_to_id, current_from_path, current_to_path)) =
            stack.pop()
        {
            let (files, dirs, symlinks) = self
                .ops
                .list_all(&current_from_id)
                .await
                .map_err(vault_error_to_fs_error)?;

            for file in files {
                let source_path = Self::join_path(&current_from_path, &file.name);
                self.flush_write_buffer(&source_path).await?;
                self.ops
                    .copy_file_ciphertext(&current_from_id, &file.name, &current_to_id, &file.name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                let dest_path = Self::join_path(&current_to_path, &file.name);
                self.metadata_cache.invalidate(&dest_path);
            }

            for symlink in symlinks {
                let target = self
                    .ops
                    .read_symlink(&current_from_id, &symlink.name)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                self.ops
                    .create_symlink(&current_to_id, &symlink.name, &target)
                    .await
                    .map_err(write_error_to_fs_error)?;
                let dest_path = Self::join_path(&current_to_path, &symlink.name);
                self.metadata_cache.invalidate(&dest_path);
            }

            for dir in dirs {
                let new_dir_id = self
                    .ops
                    .create_directory(&current_to_id, &dir.name)
                    .await
                    .map_err(write_error_to_fs_error)?;
                let child_from_path = Self::join_path(&current_from_path, &dir.name);
                let child_to_path = Self::join_path(&current_to_path, &dir.name);
                stack.push((
                    dir.directory_id,
                    new_dir_id,
                    child_from_path,
                    child_to_path.clone(),
                ));
                self.metadata_cache.invalidate_prefix(&child_to_path);
                self.path_cache.invalidate_prefix(&child_to_path);
            }
        }

        Ok(())
    }
}

impl DavFileSystem for CryptomatorWebDav {
    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            let vault_path = Self::parse_path(path)?;
            debug!(vault_path = %vault_path, options = ?options, "Opening file");

            let writing = options.write || options.create || options.create_new;
            let path_guards = self.path_locks.acquire(&[(&vault_path, writing)]).await?;
            let (dir_id, filename) = self.resolve_path(&vault_path).await?;
            if options.write || options.create || options.create_new {
                let _guard = self.flush_lock.lock().await;
                if options.create_new {
                    if self.write_buffers.contains(&vault_path) {
                        return Err(FsError::Exists);
                    }
                    match self.find_entry(&vault_path).await {
                        Ok(_) => return Err(FsError::Exists),
                        Err(FsError::NotFound) => {}
                        Err(error) => return Err(error),
                    }
                }
                // A previous request may have dropped after a failed flush.
                // Persist that data before opening a replacement writer.
                self.flush_write_buffer_unlocked(&vault_path).await?;
                let editor = Arc::new(PendingWrite::new(
                    EditBuffer::open(
                        &self.ops,
                        dir_id,
                        filename.clone(),
                        options.create || options.create_new,
                        options.truncate,
                    )
                    .await
                    .map_err(write_error_to_fs_error)?,
                ));
                self.write_buffers
                    .insert(vault_path.clone(), Arc::clone(&editor));
                let mut file = CryptomatorFile::writer(
                    editor,
                    filename,
                    Arc::clone(&self.ops),
                    vault_path,
                    Arc::clone(&self.metadata_cache),
                    Arc::clone(&self.stats),
                    Arc::clone(&self.write_buffers),
                    Arc::clone(&self.flush_lock),
                    path_guards,
                );
                if options.append {
                    file.seek(std::io::SeekFrom::End(0)).await?;
                }
                Ok(Box::new(file) as Box<dyn DavFile>)
            } else {
                self.flush_write_buffer(&vault_path).await?;
                let reader = self
                    .ops
                    .open_file_unlocked(&dir_id, &filename)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                Ok(Box::new(CryptomatorFile::reader(
                    reader,
                    filename,
                    Arc::clone(&self.stats),
                )) as Box<dyn DavFile>)
            }
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let vault_path = Self::parse_path(path)?;
            let _paths = self.path_locks.acquire(&[(&vault_path, false)]).await?;
            debug!(vault_path = %vault_path, "Reading directory");

            let dir_id = match self.resolve_dir_path(&vault_path).await {
                Ok(id) => id,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            // Use list_all for efficiency (single lock, concurrent fetches)
            let (files, dirs, symlinks) = match self.ops.list_all(&dir_id).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(vault_error_to_fs_error(e));
                }
            };

            let mut entries: Vec<Box<dyn DavDirEntry>> = Vec::new();

            // Add directories
            for dir_info in dirs {
                entries.push(Box::new(CryptomatorDirEntry::directory(dir_info)));
            }

            // Add files
            for file_info in files {
                entries.push(Box::new(CryptomatorDirEntry::file(
                    file_info,
                    self.ops.cipher_combo(),
                )));
            }

            // Add symlinks (as files - WebDAV doesn't support symlinks)
            for symlink_info in symlinks {
                entries.push(Box::new(CryptomatorDirEntry::symlink(symlink_info)));
            }

            trace!(count = entries.len(), "Directory entries found");

            self.stats.record_metadata_latency(start.elapsed());
            Ok(Box::pin(stream::iter(entries.into_iter().map(Ok))) as FsStream<_>)
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let _meta_start = Instant::now();
            let vault_path = Self::parse_path(path)?;
            let _paths = self.path_locks.acquire(&[(&vault_path, false)]).await?;
            trace!(vault_path = %vault_path, "Getting metadata");

            let meta = self.find_entry(&vault_path).await?;
            Ok(Box::new(meta) as Box<dyn DavMetaData>)
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let vault_path = Self::parse_path(path)?;
            let _paths = self.path_locks.acquire(&[(&vault_path, true)]).await?;
            self.flush_tree(&vault_path).await?;
            debug!(vault_path = %vault_path, "Creating directory");

            // Check if the path already exists (RFC 4918: MKCOL on existing resource returns 405)
            if self.find_entry(&vault_path).await.is_ok() {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(FsError::Exists);
            }

            let (parent_dir_id, name) = match self.resolve_path(&vault_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            if let Err(e) = self.ops.create_directory(&parent_dir_id, &name).await {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(write_error_to_fs_error(e));
            }

            // Invalidate caches for the new directory
            self.metadata_cache.invalidate(&vault_path);
            // Don't need to invalidate path_cache - new dir won't be in it yet

            self.stats.record_metadata_latency(start.elapsed());
            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let vault_path = Self::parse_path(path)?;
            let _paths = self.path_locks.acquire(&[(&vault_path, true)]).await?;
            self.flush_tree(&vault_path).await?;
            debug!(vault_path = %vault_path, "Removing directory");

            let (parent_dir_id, name) = match self.resolve_path(&vault_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            if let Err(e) = self
                .delete_directory_recursive(&parent_dir_id, &name, &vault_path)
                .await
            {
                self.stats.record_error();
                self.stats.record_metadata_latency(start.elapsed());
                return Err(e);
            }

            // Invalidate caches for the directory and all children
            self.metadata_cache.invalidate_prefix(&vault_path);
            self.path_cache.invalidate_prefix(&vault_path);

            self.stats.record_metadata_latency(start.elapsed());
            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(path = %path.as_url_string()))]
    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let vault_path = Self::parse_path(path)?;
            let _paths = self.path_locks.acquire(&[(&vault_path, true)]).await?;
            debug!(vault_path = %vault_path, "Removing file");

            // First flush any pending writes
            self.flush_tree(&vault_path).await?;

            let (parent_dir_id, name) = match self.resolve_path(&vault_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            // Try to delete as file first
            if self.ops.delete_file(&parent_dir_id, &name).await.is_ok() {
                self.metadata_cache.invalidate(&vault_path);
                self.stats.record_metadata_latency(start.elapsed());
                return Ok(());
            }

            // Try as symlink
            if self.ops.delete_symlink(&parent_dir_id, &name).await.is_ok() {
                self.metadata_cache.invalidate(&vault_path);
                self.stats.record_metadata_latency(start.elapsed());
                return Ok(());
            }

            // Try as directory (WebDAV DELETE can target directories too)
            if self
                .delete_directory_recursive(&parent_dir_id, &name, &vault_path)
                .await
                .is_ok()
            {
                self.metadata_cache.invalidate_prefix(&vault_path);
                self.path_cache.invalidate_prefix(&vault_path);
                self.stats.record_metadata_latency(start.elapsed());
                return Ok(());
            }

            self.stats.record_error();
            self.stats.record_metadata_latency(start.elapsed());
            Err(FsError::NotFound)
        })
    }

    #[instrument(level = "debug", skip(self), fields(from = %from.as_url_string(), to = %to.as_url_string()))]
    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let from_path = Self::parse_path(from)?;
            let to_path = Self::parse_path(to)?;
            let _paths = self
                .path_locks
                .acquire(&[(&from_path, true), (&to_path, true)])
                .await?;
            debug!(from = %from_path, to = %to_path, "Renaming/moving");

            // Flush any pending writes on source
            self.flush_tree(&from_path).await?;
            self.flush_tree(&to_path).await?;

            let (from_dir_id, from_name) = match self.resolve_path(&from_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };
            let (to_dir_id, to_name) = match self.resolve_path(&to_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            // Determine if source is a directory or file
            let source_meta = match self.find_entry(&from_path).await {
                Ok(meta) => meta,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            self.ops
                .rename_entry_atomic(&from_dir_id, &from_name, &to_dir_id, &to_name)
                .await
                .map_err(write_error_to_fs_error)?;

            // Invalidate caches for both source and destination
            self.metadata_cache.invalidate(&from_path);
            self.metadata_cache.invalidate(&to_path);
            // For directory renames, also invalidate path cache
            if source_meta.is_dir() {
                self.path_cache.invalidate_prefix(&from_path);
                self.path_cache.invalidate_prefix(&to_path);
            }

            self.stats.record_metadata_latency(start.elapsed());
            Ok(())
        })
    }

    #[instrument(level = "debug", skip(self), fields(from = %from.as_url_string(), to = %to.as_url_string()))]
    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            let start = Instant::now();
            self.stats.record_metadata_op();
            let from_path = Self::parse_path(from)?;
            let to_path = Self::parse_path(to)?;
            let _paths = self
                .path_locks
                .acquire(&[(&from_path, false), (&to_path, true)])
                .await?;
            debug!(from = %from_path, to = %to_path, "Copying");

            self.flush_tree(&from_path).await?;
            self.flush_tree(&to_path).await?;

            let source_meta = match self.find_entry(&from_path).await {
                Ok(meta) => meta,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            let (from_dir_id, from_name) = match self.resolve_path(&from_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };
            let (to_dir_id, to_name) = match self.resolve_path(&to_path).await {
                Ok(result) => result,
                Err(e) => {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
            };

            if source_meta.is_dir() {
                let dirs = match self.ops.list_directories(&from_dir_id).await {
                    Ok(dirs) => dirs,
                    Err(e) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(vault_error_to_fs_error(e));
                    }
                };
                let source_dir = dirs
                    .into_iter()
                    .find(|dir| dir.name == from_name)
                    .ok_or(FsError::NotFound)?;
                let new_dir_id = match self.ops.create_directory(&to_dir_id, &to_name).await {
                    Ok(new_dir_id) => new_dir_id,
                    Err(e) => {
                        self.stats.record_error();
                        self.stats.record_metadata_latency(start.elapsed());
                        return Err(write_error_to_fs_error(e));
                    }
                };
                if let Err(e) = self
                    .copy_directory_recursive(
                        &source_dir.directory_id,
                        &new_dir_id,
                        &from_path,
                        &to_path,
                    )
                    .await
                {
                    self.stats.record_error();
                    self.stats.record_metadata_latency(start.elapsed());
                    return Err(e);
                }
                self.metadata_cache.invalidate_prefix(&to_path);
                self.path_cache.invalidate_prefix(&to_path);
            } else if source_meta.is_symlink() {
                let target = self
                    .ops
                    .read_symlink(&from_dir_id, &from_name)
                    .await
                    .map_err(vault_error_to_fs_error)?;
                self.ops
                    .create_symlink(&to_dir_id, &to_name, &target)
                    .await
                    .map_err(write_error_to_fs_error)?;
                self.metadata_cache.invalidate(&to_path);
            } else {
                self.flush_write_buffer(&from_path).await?;
                self.ops
                    .copy_file_ciphertext(&from_dir_id, &from_name, &to_dir_id, &to_name)
                    .await
                    .map_err(write_error_to_fs_error)?;

                // Invalidate cache for the destination
                self.metadata_cache.invalidate(&to_path);
            }

            self.stats.record_metadata_latency(start.elapsed());
            Ok(())
        })
    }

    fn have_props<'a>(
        &'a self,
        _path: &'a DavPath,
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        // We don't support WebDAV properties beyond the basics
        Box::pin(async { false })
    }
}

#[cfg(test)]
mod tests {
    use crate::filesystem::*;

    #[tokio::test]
    async fn put_handle_can_retry_a_failed_flush() {
        let vault = oxcrypt_mount::testing::TempVault::new();
        let ops = Arc::new(
            VaultOperationsAsync::open(vault.path(), oxcrypt_mount::testing::TempVault::password())
                .unwrap(),
        );
        let fs = CryptomatorWebDav::new(Arc::clone(&ops));
        let path = ops
            .write_file(&DirId::root(), "note", b"old")
            .await
            .unwrap();
        let dav_path = DavPath::new("/note").unwrap();
        let mut file = fs
            .open(
                &dav_path,
                OpenOptions {
                    write: true,
                    truncate: true,
                    ..OpenOptions::default()
                },
            )
            .await
            .unwrap();
        file.write_bytes(bytes::Bytes::from_static(b"pending"))
            .await
            .unwrap();
        let backup = path.with_extension("fault-backup");
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(file.flush().await.is_err());
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        file.flush().await.unwrap();
        assert_eq!(
            ops.read_file(&DirId::root(), "note").await.unwrap().content,
            b"pending"
        );
    }

    #[tokio::test]
    async fn flush_error_preserves_pending_bytes_for_retry() {
        let vault = oxcrypt_mount::testing::TempVault::new();
        let ops = Arc::new(
            VaultOperationsAsync::open(vault.path(), oxcrypt_mount::testing::TempVault::password())
                .unwrap(),
        );
        let fs = CryptomatorWebDav::new(Arc::clone(&ops));
        let path = ops
            .write_file(&DirId::root(), "note", b"old")
            .await
            .unwrap();
        let buffer = Arc::new(PendingWrite::new(
            EditBuffer::open(&ops, DirId::root(), "note".into(), false, true)
                .await
                .unwrap(),
        ));
        buffer.write(0, b"pending").unwrap();
        let backup = path.with_extension("fault-backup");
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        fs.write_buffers.insert("/note".into(), buffer);
        assert!(fs.flush_write_buffer("/note").await.is_err());
        assert_eq!(
            fs.write_buffers
                .get(&"/note".into())
                .unwrap()
                .read(0, 7)
                .unwrap(),
            b"pending"
        );
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        fs.flush_write_buffer("/note").await.unwrap();
        assert_eq!(
            ops.read_file(&DirId::root(), "note").await.unwrap().content,
            b"pending"
        );
    }

    #[tokio::test]
    async fn create_permission_does_not_hide_authentication_failure() {
        let vault = oxcrypt_mount::testing::TempVault::new();
        let ops = Arc::new(
            VaultOperationsAsync::open(vault.path(), oxcrypt_mount::testing::TempVault::password())
                .unwrap(),
        );
        let fs = CryptomatorWebDav::new(Arc::clone(&ops));
        let path = ops
            .write_file(&DirId::root(), "note", b"original")
            .await
            .unwrap();
        let mut corrupt = std::fs::read(&path).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        let options = OpenOptions {
            write: true,
            create: true,
            ..OpenOptions::default()
        };
        let mut handle = fs
            .open(&DavPath::new("/note").unwrap(), options)
            .await
            .unwrap();
        assert!(
            handle
                .write_bytes(bytes::Bytes::from_static(b"edit"))
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }

    #[test]
    fn test_parse_path() {
        assert_eq!(
            CryptomatorWebDav::parse_path(&DavPath::new("/").unwrap()).unwrap(),
            ""
        );
        assert_eq!(
            CryptomatorWebDav::parse_path(&DavPath::new("/test.txt").unwrap()).unwrap(),
            "/test.txt"
        );
        assert_eq!(
            CryptomatorWebDav::parse_path(&DavPath::new("/foo/bar/baz.txt").unwrap()).unwrap(),
            "/foo/bar/baz.txt"
        );
    }
}
