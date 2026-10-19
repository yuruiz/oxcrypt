//! FUSE filesystem implementation for Cryptomator vaults.
//!
//! This module implements the fuser `Filesystem` trait for mounting
//! Cryptomator vaults as native filesystems.
//!
//! # FUSE API Compliance Audit
//!
//! ## Reference Documents
//! - libfuse `fuse_lowlevel_ops`: <https://libfuse.github.io/doxygen/structfuse__lowlevel__ops.html>
//! - fuser crate: <https://docs.rs/fuser/latest/fuser/trait.Filesystem.html>
//! - libfuse header: `include/fuse_lowlevel.h`
//!
//! ## Audit Summary
//!
//! | Operation | Status | Notes |
//! |-----------|--------|-------|
//! | init/destroy | OK | |
//! | lookup | OK | Correctly increments nlookup via `get_or_insert` |
//! | forget/batch_forget | OK | Correctly decrements nlookup, evicts at 0 |
//! | getattr | OK | |
//! | setattr | PARTIAL | Does not handle setuid/setgid bit reset |
//! | readlink | OK | |
//! | open/release | OK | |
//! | read/write | OK | |
//! | flush/fsync | OK | |
//! | opendir/releasedir | OK | |
//! | readdir | OK | Uses `get_or_insert_no_lookup_inc` (per spec) |
//! | readdirplus | OK | Correctly increments nlookup for non-. entries |
//! | create | OK | |
//! | mkdir/rmdir | OK | |
//! | unlink | OK | |
//! | symlink | OK | |
//! | rename | OK | RENAME_NOREPLACE and RENAME_EXCHANGE supported (Linux only) |
//! | access | OK | |
//! | statfs | OK | |
//! | fallocate | OK | Only mode=0 supported (correct for non-sparse FS) |
//! | copy_file_range | OK | |
//! | lseek | OK | SEEK_DATA/SEEK_HOLE handled correctly for non-sparse |
//!
//! ## Notes
//!
//! - RENAME_EXCHANGE for directories requires same parent (cross-parent returns EXDEV)
//! - RENAME_EXCHANGE for files works across directories with re-encryption

use crate::attr::{AttrCache, DEFAULT_ATTR_TTL, DirCache, DirListingEntry};
use crate::config::MountConfig;
use crate::error::{FuseError, FuseResult, ToErrno};
#[cfg(test)]
use crate::handles::WriteBuffer;
use crate::handles::{FuseHandle, FuseHandleTable};
use crate::inode::{InodeKind, InodeTable};
use crate::scheduler::{
    DirectoryEntry, DirectoryEntryPlus, FuseScheduler, HazardousOp, HazardousOpHandler,
    HazardousReply, HazardousResult, RequestId, SchedulerConfig, SchedulerShared,
};
use dashmap::DashMap;

use filetime::FileTime;
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyLseek, ReplyOpen, ReplyWrite, TimeOrNow,
};
use libc::c_int;
use oxcrypt_core::fs::encrypted_to_plaintext_size_or_zero;
use oxcrypt_core::vault::{DirId, SyncFirstResult, VaultOperationsAsync, VaultPath};
use oxcrypt_mount::VaultStats;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::runtime::{Handle, Runtime};
use tracing::{debug, error, info, trace, warn};

/// Block size for filesystem statistics.
const BLOCK_SIZE: u32 = 4096;

/// Number of synthetic entries ("." and "..") pinned to the front of every
/// directory listing. They are excluded from sorting so that a name ordering
/// before "." cannot displace them.
const SPECIAL_ENTRY_COUNT: usize = 2;

/// Truncated hash of an entry name, used to anchor a readdir cookie to the entry
/// that produced it.
fn readdir_name_hash(name: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish() & 0x7FFF_FFFF
}

/// Offset cookie reported for the entry at `idx`, named `name`.
///
/// The cookie packs the entry's position in the canonical listing with a hash of
/// its name: `hash << 32 | idx`. The position makes resuming an unchanged
/// directory exact, while the name anchor lets a scan that raced with a
/// modification find its place again instead of skipping entries.
///
/// Cookies are never 0, since the kernel reserves that for "start from the
/// beginning".
fn readdir_offset_at(idx: usize, name: &str) -> i64 {
    let idx = u64::try_from(idx)
        .unwrap_or(u64::from(u32::MAX))
        .min(u64::from(u32::MAX));
    let packed = (readdir_name_hash(name) << 32) | (idx + 1);
    i64::try_from(packed).unwrap_or(i64::MAX)
}

/// Index to resume a directory scan from, given the kernel's `offset` cookie.
///
/// Offset 0 starts a fresh scan. Otherwise the cookie's packed position is
/// trusted only when the name still hashes to the same anchor; if the listing
/// shifted underneath us the anchor is searched for by name, and only when it
/// has disappeared entirely does the scan restart. Restarting repeats entries,
/// but never drops them, which is what recursive deletion depends on.
fn readdir_resume_index<T>(offset: i64, entries: &[T], name_of: impl Fn(&T) -> &str) -> usize {
    if offset == 0 {
        return 0;
    }
    let Ok(packed) = u64::try_from(offset) else {
        return 0;
    };
    let anchor_hash = packed >> 32;
    let idx = (packed & 0xFFFF_FFFF) as usize;

    if idx > 0
        && let Some(entry) = entries.get(idx - 1)
        && readdir_name_hash(name_of(entry)) == anchor_hash
    {
        return idx;
    }

    entries
        .iter()
        .position(|e| readdir_name_hash(name_of(e)) == anchor_hash)
        .map_or(0, |found| found + 1)
}

/// Default file permissions (rw-r--r--).
const DEFAULT_FILE_PERM: u16 = 0o644;

/// Default directory permissions (rwxr-xr-x).
const DEFAULT_DIR_PERM: u16 = 0o755;

#[cfg(test)]
fn read_result<T>(
    result: Result<
        Result<T, oxcrypt_core::error::VaultOperationError>,
        crate::async_bridge::BridgeError,
    >,
) -> Result<T, c_int> {
    result
        .map_err(|error| error.to_errno())?
        .map_err(|error| crate::error::vault_error_to_errno(&error))
}

/// Keep the authoritative buffer available until persistence succeeds. A timeout
/// can drop the future, so recovery must not depend on that future returning data.
fn persist_write_buffer(
    handles: &FuseHandleTable,
    fh: u64,
    persist: impl FnOnce(DirId, String, Arc<Vec<u8>>) -> Result<PathBuf, c_int>,
) -> Result<Option<(PathBuf, bool)>, c_int> {
    let mut handle = handles.get_mut(&fh).ok_or(libc::EBADF)?;
    let Some(buffer) = handle
        .as_write_buffer_mut()
        .filter(|b| b.is_dirty() && !b.is_detached())
    else {
        return Ok(None);
    };
    let revision = buffer.revision();
    let dir_id = buffer.dir_id().clone();
    let name = buffer.filename().to_owned();
    let content = buffer.snapshot();
    drop(handle);

    let path = persist(dir_id, name, content)?;
    let clean = handles.get_mut(&fh).is_some_and(|mut handle| {
        handle
            .as_write_buffer_mut()
            .is_some_and(|buffer| buffer.mark_clean_if_revision(revision))
    });
    Ok(Some((path, clean)))
}

struct HazardousHandler {
    /// Sync vault operations for direct blocking I/O in executor threads.
    /// Per the runtime spec, executor threads should NOT use tokio.
    sync_ops: Arc<oxcrypt_core::vault::VaultOperations>,
    /// Async vault operations (kept for write operations that need async locks).
    ops: Arc<VaultOperationsAsync>,
    handle: Handle,
    stats: Arc<crate::async_bridge::BridgeStats>,
    default_timeout: Duration,
    write_timeout: Duration,
    handle_table: Arc<FuseHandleTable>,
    inodes: Arc<InodeTable>,
    dir_cache: Arc<DirCache>,
    attr_cache: Arc<AttrCache>,
    open_handle_tracker: Arc<crate::handles::OpenHandleTracker>,
    buffer_sizes: Arc<DashMap<u64, u64>>,
    scheduler_shared: Option<SchedulerShared>,
    vault_stats: Arc<VaultStats>,
    uid: u32,
    gid: u32,
}

impl HazardousHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        sync_ops: Arc<oxcrypt_core::vault::VaultOperations>,
        ops: Arc<VaultOperationsAsync>,
        handle: Handle,
        stats: Arc<crate::async_bridge::BridgeStats>,
        default_timeout: Duration,
        write_timeout: Duration,
        handle_table: Arc<FuseHandleTable>,
        inodes: Arc<InodeTable>,
        dir_cache: Arc<DirCache>,
        attr_cache: Arc<AttrCache>,
        open_handle_tracker: Arc<crate::handles::OpenHandleTracker>,
        buffer_sizes: Arc<DashMap<u64, u64>>,
        scheduler_shared: Option<SchedulerShared>,
        vault_stats: Arc<VaultStats>,
        uid: u32,
        gid: u32,
    ) -> Self {
        Self {
            sync_ops,
            ops,
            handle,
            stats,
            default_timeout,
            write_timeout,
            handle_table,
            inodes,
            dir_cache,
            attr_cache,
            open_handle_tracker,
            buffer_sizes,
            scheduler_shared,
            vault_stats,
            uid,
            gid,
        }
    }

    fn exec_with_timeout<F, T>(
        &self,
        future: F,
        timeout: Duration,
    ) -> Result<T, crate::async_bridge::BridgeError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        crate::async_bridge::execute(&self.handle, timeout, Some(&self.stats), future)
    }

    fn exec<F, T>(&self, future: F) -> Result<T, crate::async_bridge::BridgeError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.exec_with_timeout(future, self.default_timeout)
    }

    fn effective_file_size(&self, inode: u64, disk_size: u64) -> u64 {
        if let Some(editor) = self
            .handle_table
            .editors
            .get(&inode)
            .and_then(|entry| entry.value().upgrade())
        {
            return editor.len();
        }
        self.buffer_sizes
            .get(&inode)
            .map_or(disk_size, |s| (*s).max(disk_size))
    }

    fn make_dir_attr(&self, inode: u64, mtime: Option<SystemTime>) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: fuser::INodeNo(inode),
            size: 0,
            blocks: 0,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::Directory,
            perm: DEFAULT_DIR_PERM,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    fn make_file_attr(&self, inode: u64, size: u64, mtime: Option<SystemTime>) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: fuser::INodeNo(inode),
            size,
            blocks: size.div_ceil(u64::from(BLOCK_SIZE)),
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: DEFAULT_FILE_PERM,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    fn make_symlink_attr(
        &self,
        inode: u64,
        target_len: u64,
        mtime: Option<SystemTime>,
    ) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: fuser::INodeNo(inode),
            size: target_len,
            blocks: 0,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    fn list_directory(&self, dir_id: &DirId) -> FuseResult<Vec<DirListingEntry>> {
        // Use sync ops directly - we're in an executor thread, no tokio needed
        let (files, dirs, symlinks) = self
            .sync_ops
            .list_all(dir_id)
            .map_err(|e| FuseError::Vault(Box::new(e)))?;

        let entries: Vec<DirListingEntry> = dirs
            .into_iter()
            .map(|d| DirListingEntry {
                inode: 0,
                file_type: FileType::Directory,
                dir_id: Some(d.directory_id),
                name: d.name,
            })
            .chain(files.into_iter().map(|f| DirListingEntry {
                inode: 0,
                file_type: FileType::RegularFile,
                dir_id: None,
                name: f.name,
            }))
            .chain(symlinks.into_iter().map(|s| DirListingEntry {
                inode: 0,
                file_type: FileType::Symlink,
                dir_id: None,
                name: s.name,
            }))
            .collect();

        Ok(entries)
    }

    fn flush_handle(&self, ino: u64, fh: u64) -> Result<Option<PathBuf>, c_int> {
        let _namespace = self.handle_table.namespace.lock();
        self.flush_handle_unlocked(ino, fh)
    }

    fn flush_handle_unlocked(&self, ino: u64, fh: u64) -> Result<Option<PathBuf>, c_int> {
        let editor = self
            .handle_table
            .get(&fh)
            .and_then(|handle| handle.editor())
            .map(|(editor, _)| editor);
        if let Some(editor) = editor {
            let ops = Arc::clone(&self.ops);
            let result = self
                .exec_with_timeout(async move { editor.commit(&ops).await }, self.write_timeout)
                .map_err(|error| error.to_errno())?
                .map_err(|error| crate::error::write_error_to_errno(&error))?;
            self.attr_cache.invalidate(ino);
            return Ok(result);
        }
        let ops = Arc::clone(&self.ops);
        let result = persist_write_buffer(&self.handle_table, fh, |dir_id, filename, content| {
            self.exec_with_timeout(
                async move { ops.write_file(&dir_id, &filename, &content).await },
                self.write_timeout,
            )
            .map_err(|error| error.to_errno())?
            .map_err(|error| crate::error::write_error_to_errno(&error))
        })?;
        if let Some((path, clean)) = result {
            if clean && let Some(ref shared) = self.scheduler_shared {
                shared.release_all_file_write_bytes(ino);
            }
            if let Some(ref shared) = self.scheduler_shared {
                shared.invalidate_read_cache_inode(ino);
            }
            self.attr_cache.invalidate(ino);
            return Ok(Some(path));
        }
        Ok(None)
    }

    fn sync_handle_to_disk(
        &self,
        fh: u64,
        datasync: bool,
        known_path: Option<PathBuf>,
    ) -> Result<(), c_int> {
        // If we already have the encrypted path from a preceding flush, use it directly
        let encrypted_path = if let Some(path) = known_path {
            path
        } else {
            // Need to look up the file - this path is taken when fsync is called
            // without a preceding write (e.g., fsync on a read-only handle)
            let handle = self.handle_table.get(&fh).ok_or(libc::EBADF)?;

            let (dir_id, filename) = match handle.value() {
                FuseHandle::WriteBuffer(buffer) => {
                    if buffer.is_detached() {
                        return Ok(());
                    }
                    (buffer.dir_id().clone(), buffer.filename().to_string())
                }
                _ => return Ok(()),
            };
            drop(handle);

            let ops = Arc::clone(&self.ops);

            let find_result = self.exec_with_timeout(
                async move { ops.find_file(&dir_id, &filename).await },
                self.default_timeout,
            );

            match find_result {
                Ok(Ok(Some(info))) => info.encrypted_path,
                Ok(Ok(None)) => return Ok(()),
                Ok(Err(_)) => return Err(libc::EIO),
                Err(e) => return Err(e.to_errno()),
            }
        };

        let ops_for_sync = Arc::clone(&self.ops);
        let sync_result = self.exec_with_timeout(
            async move {
                ops_for_sync
                    .sync_encrypted_file(&encrypted_path, datasync)
                    .await
            },
            self.write_timeout,
        );

        match sync_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(libc::EIO),
            Err(e) => Err(e.to_errno()),
        }
    }

    fn wait_pending_writes(&self, ino: u64) -> Result<(), c_int> {
        if let Some(ref shared) = self.scheduler_shared
            && shared.has_pending_writes(ino)
            && !shared.wait_pending_writes(ino, self.write_timeout)
        {
            return Err(libc::ETIMEDOUT);
        }
        Ok(())
    }

    fn recover_handle(&self, fh: u64) -> Result<PathBuf, i32> {
        let root = self
            .handle_table
            .recovery_root
            .lock()
            .clone()
            .ok_or(libc::EIO)?;
        if let Some((editor, _)) = self
            .handle_table
            .get(&fh)
            .and_then(|handle| handle.editor())
        {
            let ops = Arc::clone(&self.ops);
            return self
                .exec_with_timeout(
                    async move {
                        tokio::task::spawn_blocking(move || editor.recover(&ops, &root))
                            .await
                            .map_err(std::io::Error::other)?
                    },
                    self.write_timeout,
                )
                .map_err(|error| error.to_errno())?
                .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO));
        }
        let (dir, name, content) = self
            .handle_table
            .get_mut(&fh)
            .and_then(|mut handle| {
                handle.as_write_buffer_mut().map(|buffer| {
                    (
                        buffer.dir_id().clone(),
                        buffer.filename().to_owned(),
                        buffer.snapshot(),
                    )
                })
            })
            .ok_or(libc::EBADF)?;
        let key = Arc::clone(self.ops.master_key());
        self.exec_with_timeout(async move { oxcrypt_core::fs::recovery::save(&root, &key, &dir, &name, &content).await }, self.write_timeout)
            .map_err(|error| error.to_errno())?.map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))
    }

    fn op_release(&self, ino: u64, fh: u64) -> Result<(), i32> {
        self.wait_pending_writes(ino)?;
        let _namespace = self.handle_table.namespace.lock();
        if !self.handle_table.contains(&fh) {
            return Ok(());
        }
        let mut release_error = None;
        if let Err(errno) = self.flush_handle_unlocked(ino, fh) {
            match self.recover_handle(fh) {
                Ok(path) => {
                    let message = format!(
                        "Write-back failed (errno {errno}); encrypted recovery copy: {}",
                        path.display()
                    );
                    error!("{message}");
                    self.handle_table.close_reports.lock().push(message);
                }
                Err(failure) => {
                    error!(
                        failure,
                        fh, "Cannot save recovery copy; retaining pending write handle"
                    );
                    self.handle_table.pending_releases.lock().insert(fh, ino);
                    return Err(errno);
                }
            }
            release_error = Some(errno);
        }
        self.handle_table.remove(&fh);
        self.handle_table.pending_releases.lock().remove(&fh);
        self.vault_stats.record_file_close();

        let deferred = self.open_handle_tracker.remove_handle(ino);
        if !self.open_handle_tracker.has_open_handles(ino) {
            self.handle_table.editors.remove(&ino);
            self.buffer_sizes.remove(&ino);
        }

        if let Some(deferred) = deferred {
            let file_path = self.inodes.get(ino).map(|entry| entry.path.clone());
            let ops = Arc::clone(&self.ops);
            let delete_result =
                self.exec(async move { ops.delete_file(&deferred.dir_id, &deferred.name).await });
            if let Ok(Ok(())) = delete_result
                && let Some(path) = file_path
            {
                self.inodes.invalidate_path(&path);
            }
        }

        release_error.map_or(Ok(()), Err)
    }

    fn op_flush(&self, ino: u64, fh: u64) -> Result<(), i32> {
        self.wait_pending_writes(ino)?;
        self.flush_handle(ino, fh).map(|_| ())
    }

    fn op_fsync(&self, ino: u64, fh: u64, datasync: bool) -> Result<(), i32> {
        self.wait_pending_writes(ino)?;
        let encrypted_path = self.flush_handle(ino, fh)?;
        self.sync_handle_to_disk(fh, datasync, encrypted_path)
    }

    fn op_readdir(&self, ino: u64, offset: i64) -> Result<Vec<DirectoryEntry>, i32> {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(entry) = self.inodes.get(ino) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            return Err(libc::ENOENT);
        };

        let Some(dir_id) = entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            return Err(libc::ENOTDIR);
        };
        let current_path = entry.path.clone();
        drop(entry);

        let parent_inode = current_path
            .parent()
            .and_then(|parent| self.inodes.get_inode(&parent))
            .unwrap_or(crate::inode::ROOT_INODE);

        let entries = if let Some(cached) = self.dir_cache.get(ino) {
            cached
        } else {
            match self.list_directory(&dir_id) {
                Ok(entries) => {
                    self.dir_cache.insert(ino, entries.clone());
                    entries
                }
                Err(e) => {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    return Err(e.to_errno());
                }
            }
        };

        let mut all_entries = vec![
            DirListingEntry {
                inode: ino,
                file_type: FileType::Directory,
                dir_id: Some(dir_id.clone()),
                name: ".".to_string(),
            },
            DirListingEntry {
                inode: parent_inode,
                file_type: FileType::Directory,
                dir_id: None,
                name: "..".to_string(),
            },
        ];
        all_entries.extend(entries);
        // "." and ".." stay pinned at the front; everything after them is sorted so
        // that every readdir path agrees on one canonical order.
        all_entries[SPECIAL_ENTRY_COUNT..].sort_by(|a, b| a.name.cmp(&b.name));

        let start_idx = readdir_resume_index(offset, &all_entries, |e| e.name.as_str());

        let mut out = Vec::new();
        for (idx, entry) in all_entries.into_iter().enumerate().skip(start_idx) {
            let entry_inode = if entry.name == "." {
                ino
            } else if entry.name == ".." {
                parent_inode
            } else {
                let child_path = current_path.join(&entry.name);
                let kind = match entry.file_type {
                    FileType::Directory => InodeKind::Directory {
                        dir_id: entry.dir_id.clone().unwrap_or_else(DirId::root),
                    },
                    FileType::Symlink => InodeKind::Symlink {
                        dir_id: dir_id.clone(),
                        name: entry.name.clone(),
                    },
                    _ => InodeKind::File {
                        dir_id: dir_id.clone(),
                        name: entry.name.clone(),
                    },
                };
                self.inodes.get_or_insert_no_lookup_inc(&child_path, &kind)
            };

            let next_offset = readdir_offset_at(idx, &entry.name);
            out.push(DirectoryEntry {
                inode: entry_inode,
                offset: next_offset,
                file_type: entry.file_type,
                name: entry.name,
            });
        }

        self.vault_stats.record_metadata_latency(start.elapsed());
        Ok(out)
    }

    fn op_readdirplus(&self, ino: u64, offset: i64) -> Result<Vec<DirectoryEntryPlus>, i32> {
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(entry) = self.inodes.get(ino) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            return Err(libc::ENOENT);
        };

        let Some(dir_id) = entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            return Err(libc::ENOTDIR);
        };
        let current_path = entry.path.clone();
        drop(entry);

        let parent_inode = current_path
            .parent()
            .and_then(|parent| self.inodes.get_inode(&parent))
            .unwrap_or(crate::inode::ROOT_INODE);

        // Use sync ops directly - we're in an executor thread, no tokio needed
        let (files, dirs, symlinks) = match self.sync_ops.list_all(&dir_id) {
            Ok(result) => result,
            Err(e) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                return Err(crate::error::vault_error_to_errno(&e));
            }
        };

        let mut all_entries: Vec<(String, FileType, u64, Option<DirId>)> = [
            (".".to_string(), FileType::Directory, 0, None),
            ("..".to_string(), FileType::Directory, 0, None),
        ]
        .into_iter()
        .chain(
            dirs.into_iter()
                .map(|d| (d.name, FileType::Directory, 0, Some(d.directory_id))),
        )
        .chain(files.into_iter().map(|f| {
            let plaintext_size = encrypted_to_plaintext_size_or_zero(f.encrypted_size);
            (f.name, FileType::RegularFile, plaintext_size, None)
        }))
        .chain(symlinks.into_iter().map(|s| {
            let target_len = s.target.len() as u64;
            (s.name, FileType::Symlink, target_len, None)
        }))
        .collect();

        all_entries[SPECIAL_ENTRY_COUNT..].sort_by(|a, b| a.0.cmp(&b.0));

        let start_idx = readdir_resume_index(offset, &all_entries, |e| e.0.as_str());

        let mut out = Vec::new();
        for (idx, (name, file_type, size, maybe_subdir_id)) in
            all_entries.into_iter().enumerate().skip(start_idx)
        {
            let (entry_inode, attr) = if name == "." {
                (ino, self.make_dir_attr(ino, None))
            } else if name == ".." {
                (parent_inode, self.make_dir_attr(parent_inode, None))
            } else {
                let child_path = current_path.join(&name);
                let kind = match file_type {
                    FileType::Directory => InodeKind::Directory {
                        dir_id: maybe_subdir_id.clone().unwrap_or_else(DirId::root),
                    },
                    FileType::Symlink => InodeKind::Symlink {
                        dir_id: dir_id.clone(),
                        name: name.clone(),
                    },
                    _ => InodeKind::File {
                        dir_id: dir_id.clone(),
                        name: name.clone(),
                    },
                };
                let entry_inode = self.inodes.get_or_insert(&child_path, &kind);

                let attr = match file_type {
                    FileType::Directory => self.make_dir_attr(entry_inode, None),
                    FileType::Symlink => self.make_symlink_attr(entry_inode, size, None),
                    _ => {
                        let effective_size = self.effective_file_size(entry_inode, size);
                        self.make_file_attr(entry_inode, effective_size, None)
                    }
                };

                self.attr_cache.insert(entry_inode, attr);
                (entry_inode, attr)
            };

            let next_offset = readdir_offset_at(idx, &name);
            out.push(DirectoryEntryPlus {
                inode: entry_inode,
                offset: next_offset,
                name,
                ttl: DEFAULT_ATTR_TTL,
                attr,
                generation: 0,
            });
        }

        self.vault_stats.record_metadata_latency(start.elapsed());
        Ok(out)
    }
}

impl HazardousOpHandler for HazardousHandler {
    fn execute(&self, request_id: RequestId, op: HazardousOp) -> HazardousResult {
        match op {
            HazardousOp::Release { ino, fh, .. } => HazardousResult::Empty {
                id: request_id,
                result: self.op_release(ino, fh),
            },
            HazardousOp::Flush { ino, fh, .. } => HazardousResult::Empty {
                id: request_id,
                result: self.op_flush(ino, fh),
            },
            HazardousOp::Fsync { ino, fh, datasync } => HazardousResult::Empty {
                id: request_id,
                result: self.op_fsync(ino, fh, datasync),
            },
            HazardousOp::Readdir { ino, offset, .. } => HazardousResult::Directory {
                id: request_id,
                result: self.op_readdir(ino, offset),
            },
            HazardousOp::ReaddirPlus { ino, offset, .. } => HazardousResult::DirectoryPlus {
                id: request_id,
                result: self.op_readdirplus(ino, offset),
            },
        }
    }
}

/// FUSE filesystem for Cryptomator vaults.
///
/// Implements the fuser `Filesystem` trait to provide a mountable filesystem
/// backed by an encrypted Cryptomator vault.
pub struct CryptomatorFS {
    #[cfg(target_os = "macos")]
    resource_lock: parking_lot::Mutex<()>,
    /// Handle to tokio runtime for async operations.
    /// Points to either our owned runtime or an external one.
    handle: Handle,
    /// Owned tokio runtime (when we create our own).
    /// Must be kept alive for the handle to remain valid.
    /// IMPORTANT: Declared after handle so it drops last (Rust drops fields in declaration order).
    _owned_runtime: Option<Runtime>,
    /// Default timeout for I/O operations.
    default_timeout: Duration,
    /// Extended timeout for write/data operations (5 minutes).
    write_timeout: Duration,
    /// Statistics for async bridge operations.
    stats: Arc<crate::async_bridge::BridgeStats>,
    /// Async vault operations (shared via Arc for thread safety).
    ops: Arc<VaultOperationsAsync>,
    /// Inode table for path/inode mapping.
    inodes: Arc<InodeTable>,
    /// Attribute cache for file metadata.
    attr_cache: Arc<AttrCache>,
    /// Directory listing cache.
    dir_cache: Arc<DirCache>,
    /// File handle table for open files (shared with scheduler for reader restoration).
    handle_table: Arc<FuseHandleTable>,
    /// User ID to use for file ownership.
    uid: u32,
    /// Group ID to use for file ownership.
    gid: u32,
    /// Path to the vault root (for statfs).
    vault_path: PathBuf,
    /// Statistics for monitoring vault activity.
    vault_stats: Arc<VaultStats>,
    /// Mount configuration (TTLs, concurrency, etc.).
    #[allow(dead_code)]
    config: MountConfig,
    /// Open handle tracker for POSIX-compliant deferred deletion.
    open_handle_tracker: Arc<crate::handles::OpenHandleTracker>,
    /// Kernel notifier for cache invalidation (injected post-mount).
    ///
    /// The notifier only exists once a session has been spawned, which consumes
    /// the filesystem, so the cell is shared rather than owned: the caller keeps
    /// a handle to it across the move and fills it in afterwards.
    notifier: Arc<OnceLock<fuser::Notifier>>,
    /// Tracks current WriteBuffer sizes per inode for mmap consistency.
    ///
    /// When a file is opened for writing, the WriteBuffer may grow beyond
    /// what's on disk. For mmap to work correctly, getattr must return the
    /// current buffer size, not the on-disk size. This map tracks the
    /// maximum known buffer size per inode.
    ///
    /// Updated by: write(), setattr() (extend), fallocate(), copy_file_range()
    /// Checked by: getattr(), lookup(), readdir()
    /// Cleared by: release() (after flush to disk)
    buffer_sizes: Arc<DashMap<u64, u64>>,
    /// Cached sync operations for fast path (sync VaultOperations instance).
    ///
    /// Lazily created on first use to avoid async overhead for metadata operations.
    /// Shares the same master key and vault configuration as the async ops.
    /// Wrapped in Arc for cheap cloning.
    sync_ops_cache: std::sync::Mutex<Option<Arc<oxcrypt_core::vault::VaultOperations>>>,
    /// Scheduler for async FUSE request handling.
    ///
    /// Created during construction but started in `init()`. Handles reads
    /// asynchronously to prevent blocking FUSE callback threads on slow I/O.
    scheduler: Option<Arc<FuseScheduler>>,
    /// Shared scheduler state for hazardous operations.
    #[allow(dead_code)]
    scheduler_shared: Option<SchedulerShared>,
    /// Hazardous operation handler.
    hazardous_handler: Option<Arc<dyn HazardousOpHandler>>,
}

impl CryptomatorFS {
    fn editor_for_inode(
        &self,
        ino: u64,
        dir: DirId,
        name: String,
    ) -> Result<Arc<oxcrypt_mount::EditBuffer>, i32> {
        if let Some(editor) = self
            .handle_table
            .editors
            .get(&ino)
            .and_then(|entry| entry.value().upgrade())
        {
            return Ok(editor);
        }
        let ops = self.ops_clone();
        let editor = self
            .exec(
                async move { oxcrypt_mount::EditBuffer::open(&ops, dir, name, false, false).await },
            )
            .map_err(|error| error.to_errno())?
            .map_err(|error| crate::error::write_error_to_errno(&error))?;
        let editor = Arc::new(editor);
        self.handle_table
            .editors
            .insert(ino, Arc::downgrade(&editor));
        Ok(editor)
    }

    #[cfg(target_os = "macos")]
    fn resource_sidecar(
        &self,
        ino: u64,
        create: bool,
    ) -> Result<(DirId, String, VaultPath, Vec<u8>), i32> {
        let entry = self.inodes.get(ino).ok_or(libc::ENOENT)?;
        let InodeKind::File { dir_id, name } = &entry.kind else {
            return Err(libc::EISDIR);
        };
        if name.starts_with("._") {
            return Err(libc::ENOTSUP);
        }
        let dir_id = dir_id.clone();
        let name = format!("._{name}");
        let path = entry.path.parent().ok_or(libc::EINVAL)?.join(&name);
        drop(entry);
        if let Some(inode) = self.inodes.get_inode(&path)
            && self.open_handle_tracker.has_open_handles(inode)
        {
            return Err(libc::EBUSY);
        }
        let ops = self.ops_clone();
        let directory = dir_id.clone();
        let filename = name.clone();
        let data = self
            .exec(async move {
                let info = ops
                    .find_file(&directory, &filename)
                    .await
                    .map_err(|error| crate::error::vault_error_to_errno(&error))?;
                let Some(info) = info else {
                    return if create {
                        Ok(crate::resource_fork::empty())
                    } else {
                        Err(libc::ENOATTR)
                    };
                };
                if info.encrypted_size
                    > (crate::resource_fork::MAX_SIDECAR_SIZE + 128 * 1024) as u64
                {
                    return Err(libc::E2BIG);
                }
                ops.read_file(&directory, &filename)
                    .await
                    .map(|file| file.content)
                    .map_err(|error| crate::error::vault_error_to_errno(&error))
            })
            .map_err(|error| error.to_errno())??;
        Ok((dir_id, name, path, data))
    }

    #[cfg(target_os = "macos")]
    fn write_resource(
        &self,
        ino: u64,
        value: &[u8],
        flags: i32,
        position: u32,
        remove: bool,
    ) -> Result<(), i32> {
        let _guard = self.resource_lock.lock();
        let (directory, filename, path, data) = self.resource_sidecar(ino, !remove)?;
        let exists = !crate::resource_fork::resource(&data)?.is_empty();
        trace!(
            flags,
            position,
            value_len = value.len(),
            exists,
            "resource fork update"
        );
        if flags & 6 == 6 {
            return Err(libc::EINVAL);
        }
        if flags & 2 != 0 && exists {
            return Err(libc::EEXIST);
        }
        if (flags & 4 != 0 || remove) && !exists {
            return Err(libc::ENOATTR);
        }
        let data = crate::resource_fork::replace(&data, value, position)?;
        let ops = self.ops_clone();
        let name_for_write = filename.clone();
        self.exec_with_timeout(
            async move { ops.write_file(&directory, &name_for_write, &data).await },
            self.write_timeout,
        )
        .map_err(|error| error.to_errno())?
        .map_err(|error| crate::error::write_error_to_errno(&error))?;
        if let Some(inode) = self.inodes.get_inode(&path) {
            self.attr_cache.invalidate(inode);
            if let Some(scheduler) = &self.scheduler {
                scheduler.invalidate_read_cache_inode(inode);
            }
            self.notify_detached(move |notifier| {
                let _ = notifier.inval_inode(fuser::INodeNo(inode), 0, 0);
            });
        }
        if let Some(parent) = path.parent().and_then(|path| self.inodes.get_inode(&path)) {
            self.attr_cache.remove_negative(parent, &filename);
            self.dir_cache.invalidate(parent);
            self.notify_detached(move |notifier| {
                let _ = notifier.inval_entry(fuser::INodeNo(parent), OsStr::new(&filename));
            });
        }
        Ok(())
    }

    /// Creates a new CryptomatorFS from a vault path and password.
    ///
    /// Uses the default configuration optimized for network filesystems
    /// (60s cache TTL). Use [`with_config`](Self::with_config) for custom settings.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the Cryptomator vault root directory
    /// * `password` - The vault password
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The vault configuration cannot be read
    /// - The master key cannot be extracted (wrong password)
    /// - The async vault operations cannot be initialized
    pub fn new(vault_path: &Path, password: &str) -> Result<Self, FuseError> {
        Self::with_config(vault_path, password, MountConfig::default())
    }

    /// Creates a new CryptomatorFS with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the Cryptomator vault root directory
    /// * `password` - The vault password
    /// * `config` - Mount configuration (TTLs, concurrency, etc.)
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be opened.
    pub fn with_config(
        vault_path: &Path,
        password: &str,
        config: MountConfig,
    ) -> Result<Self, FuseError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .max_blocking_threads(2048)
            .build()
            .map_err(|e| {
                FuseError::Io(std::io::Error::other(format!(
                    "Failed to create tokio runtime: {e}"
                )))
            })?;
        let handle = runtime.handle().clone();
        Self::with_runtime_internal(vault_path, password, Some(runtime), handle, config)
    }

    /// Creates a new CryptomatorFS using an external tokio runtime handle.
    ///
    /// This is useful when you want the filesystem to use a runtime that has
    /// additional instrumentation (e.g., tokio-console) or when integrating
    /// with an existing async application.
    ///
    /// # Arguments
    ///
    /// * `vault_path` - Path to the Cryptomator vault root directory
    /// * `password` - The vault password
    /// * `handle` - Handle to an existing tokio runtime
    ///
    /// # Errors
    ///
    /// Returns an error if the vault cannot be opened.
    ///
    /// # Panics
    ///
    /// The external runtime must remain alive for the lifetime of this filesystem.
    /// If the runtime is dropped, subsequent operations will panic.
    pub fn with_runtime_handle(
        vault_path: &Path,
        password: &str,
        handle: Handle,
    ) -> Result<Self, FuseError> {
        Self::with_runtime_internal(vault_path, password, None, handle, MountConfig::default())
    }

    /// Creates a new CryptomatorFS with an external runtime and custom configuration.
    ///
    /// Combines the benefits of [`with_runtime_handle`](Self::with_runtime_handle)
    /// (external runtime for tokio-console) with custom configuration.
    pub fn with_runtime_handle_and_config(
        vault_path: &Path,
        password: &str,
        handle: Handle,
        config: MountConfig,
    ) -> Result<Self, FuseError> {
        Self::with_runtime_internal(vault_path, password, None, handle, config)
    }

    /// Internal constructor used by all public constructors.
    fn with_runtime_internal(
        vault_path: &Path,
        password: &str,
        owned_runtime: Option<Runtime>,
        handle: Handle,
        config: MountConfig,
    ) -> Result<Self, FuseError> {
        // Open vault - extracts key, reads config, configures cipher combo automatically
        let ops = VaultOperationsAsync::open(vault_path, password)
            .map_err(|e| {
                FuseError::Io(std::io::Error::other(format!("Failed to open vault: {e}")))
            })?
            .into_shared();

        // Create sync ops for HazardousHandler (executor threads use sync I/O per spec)
        let sync_ops = Arc::new(ops.as_sync().map_err(|e| {
            FuseError::Io(std::io::Error::other(format!(
                "Failed to create sync operations: {e}"
            )))
        })?);

        // Get current user/group
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let vault_stats = Arc::new(VaultStats::new());

        // Create attribute cache with configured TTLs
        let mut attr_cache = AttrCache::new(config.attr_ttl, config.negative_ttl);
        attr_cache.set_stats(vault_stats.cache_stats());
        let attr_cache = Arc::new(attr_cache);

        // Initialize async bridge with timeouts
        let default_timeout = config.io_timeout;
        let write_timeout = Duration::from_secs(300); // 5 minutes for data operations
        let stats = crate::async_bridge::BridgeStats::new();

        info!(
            vault_path = %vault_path.display(),
            uid = uid,
            gid = gid,
            attr_ttl_secs = config.attr_ttl.as_secs(),
            negative_ttl_ms = config.negative_ttl.as_millis(),
            default_timeout_secs = default_timeout.as_secs(),
            write_timeout_secs = write_timeout.as_secs(),
            "CryptomatorFS initialized"
        );

        // Create handle table (shared with scheduler for reader restoration).
        // It carries the vault's lock metrics so handle traffic is profiled.
        let handle_table =
            Arc::new(FuseHandleTable::new_auto_id().with_metrics(Arc::clone(ops.lock_metrics())));

        // Create scheduler (but don't start yet - started in init())
        let buffer_sizes = Arc::new(DashMap::new());
        let scheduler = FuseScheduler::with_config(
            SchedulerConfig::default().with_base_timeout(default_timeout),
            Arc::clone(&handle_table),
            Arc::clone(&vault_stats),
            Arc::clone(&attr_cache),
            Arc::clone(&buffer_sizes),
        );

        let scheduler_shared = Some(scheduler.shared_state());
        let inodes = Arc::new(InodeTable::new());
        let dir_cache = Arc::new(DirCache::new(config.attr_ttl));
        let open_handle_tracker = Arc::new(crate::handles::OpenHandleTracker::new());
        let hazardous_handler: Option<Arc<dyn HazardousOpHandler>> =
            Some(Arc::new(HazardousHandler::new(
                Arc::clone(&sync_ops),
                Arc::clone(&ops),
                handle.clone(),
                Arc::clone(&stats),
                default_timeout,
                write_timeout,
                Arc::clone(&handle_table),
                Arc::clone(&inodes),
                Arc::clone(&dir_cache),
                Arc::clone(&attr_cache),
                Arc::clone(&open_handle_tracker),
                Arc::clone(&buffer_sizes),
                scheduler_shared.clone(),
                Arc::clone(&vault_stats),
                uid,
                gid,
            )));

        Ok(Self {
            #[cfg(target_os = "macos")]
            resource_lock: parking_lot::Mutex::new(()),
            ops,
            inodes,
            attr_cache,
            dir_cache,
            handle_table,
            _owned_runtime: owned_runtime,
            handle,
            default_timeout,
            write_timeout,
            stats,
            uid,
            gid,
            vault_path: vault_path.to_path_buf(),
            vault_stats,
            config,
            open_handle_tracker,
            notifier: Arc::new(OnceLock::new()),
            buffer_sizes,
            sync_ops_cache: std::sync::Mutex::new(None),
            scheduler: Some(Arc::new(scheduler)),
            scheduler_shared,
            hazardous_handler,
        })
    }

    /// Returns a clone of the vault stats Arc for external access.
    ///
    /// This allows the mount handle to expose stats to the GUI.
    pub(crate) fn close_reports(&self) -> Arc<parking_lot::Mutex<Vec<String>>> {
        Arc::clone(&self.handle_table.close_reports)
    }

    pub fn stats(&self) -> Arc<VaultStats> {
        Arc::clone(&self.vault_stats)
    }

    /// Returns async bridge statistics for monitoring operation performance.
    pub fn bridge_stats(&self) -> &crate::async_bridge::BridgeStats {
        &self.stats
    }

    /// Returns a reference to the lock metrics for profiling.
    pub fn lock_metrics(&self) -> &Arc<oxcrypt_core::vault::lock_metrics::LockMetrics> {
        self.ops.lock_metrics()
    }

    /// Returns the cell holding the kernel cache invalidation notifier.
    ///
    /// Spawning a session consumes the filesystem, so a caller that wants to
    /// inject the notifier afterwards must clone this handle beforehand and set
    /// it through the clone; the notifier the session hands back is the same one
    /// this filesystem then reads.
    pub fn notifier_cell(&self) -> Arc<OnceLock<fuser::Notifier>> {
        Arc::clone(&self.notifier)
    }

    /// Sends a kernel notification without blocking the request being served.
    ///
    /// While the kernel processes a notification it may need locks that the
    /// operation in flight is holding, so notifying from inside a request
    /// handler stalls until that request times out. Dispatching the
    /// notification lets the handler reply first and the kernel make progress.
    fn notify_detached(&self, notify: impl FnOnce(&fuser::Notifier) + Send + 'static) {
        let Some(notifier) = self.notifier.get() else {
            return;
        };
        let notifier = notifier.clone();
        self.handle.spawn_blocking(move || notify(&notifier));
    }

    /// Returns a scheduler stats collector for monitoring scheduler health.
    ///
    /// The collector holds Arc references to scheduler components and can produce
    /// snapshots even after the filesystem is moved into a FUSE session.
    /// Returns `None` if the scheduler hasn't been initialized.
    pub fn scheduler_stats_collector(&self) -> Option<crate::scheduler::SchedulerStatsCollector> {
        self.scheduler
            .as_ref()
            .map(|scheduler| scheduler.stats_collector())
    }

    /// Creates a new CryptomatorFS with custom UID/GID.
    pub fn with_ownership(
        vault_path: &Path,
        password: &str,
        uid: u32,
        gid: u32,
    ) -> Result<Self, FuseError> {
        let mut fs = Self::new(vault_path, password)?;
        fs.uid = uid;
        fs.gid = gid;
        Ok(fs)
    }

    /// Existing-file mutations require an authenticated read of the old data.
    /// Creation is handled separately by `create`; even ENOENT is an error here.
    #[cfg(test)]
    fn read_for_modify(&self, dir_id: &DirId, filename: &str) -> Result<Vec<u8>, c_int> {
        let ops = self.ops_clone();
        let dir_id = dir_id.clone();
        let filename = filename.to_owned();
        read_result(self.exec(async move { ops.read_file(&dir_id, &filename).await }))
            .map(|file| file.content)
    }

    /// Gets a clone of the vault operations Arc for use in async context.
    ///
    /// This is now infallible since Arc::clone() never fails.
    fn ops_clone(&self) -> Arc<VaultOperationsAsync> {
        Arc::clone(&self.ops)
    }

    /// Gets or creates a cached sync operations instance for fast path.
    ///
    /// On first call, creates a `VaultOperations` instance by cloning the master key.
    /// Subsequent calls return an Arc clone of the cached instance (cheap Arc::clone).
    ///
    /// Used by sync fast paths to avoid async task spawning overhead.
    fn get_or_create_sync_ops(&self) -> FuseResult<Arc<oxcrypt_core::vault::VaultOperations>> {
        let mut cache = self.sync_ops_cache.lock().unwrap();
        if cache.is_none() {
            let sync_ops = self.ops.as_sync().map_err(|e| {
                FuseError::Io(std::io::Error::other(format!(
                    "Failed to create sync operations: {e}"
                )))
            })?;
            *cache = Some(Arc::new(sync_ops));
        }
        Ok(Arc::clone(cache.as_ref().unwrap()))
    }

    /// Executes an async operation using the spawn+oneshot pattern.
    ///
    /// Spawns the future on the tokio runtime and blocks on a oneshot channel.
    /// Operations that exceed the configured timeout will return ETIMEDOUT.
    fn exec<F, T>(&self, future: F) -> Result<T, crate::async_bridge::BridgeError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        crate::async_bridge::execute(
            &self.handle,
            self.default_timeout,
            Some(&self.stats),
            future,
        )
    }

    /// Executes an async operation that returns a Result, flattening bridge errors.
    ///
    /// This is a convenience wrapper for operations that already return Result.
    #[allow(dead_code)]
    fn exec_result<F, T, E>(&self, future: F) -> Result<T, i32>
    where
        F: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: ToErrno + Send + 'static,
    {
        match self.exec(future) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(e)) => Err(e.to_errno()),
            Err(bridge_err) => Err(bridge_err.to_errno()),
        }
    }

    /// Executes an async operation with a custom timeout.
    ///
    /// Used for operations that need longer timeouts (e.g., write operations).
    #[allow(dead_code)]
    fn exec_with_timeout<F, T>(
        &self,
        future: F,
        timeout: Duration,
    ) -> Result<T, crate::async_bridge::BridgeError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        crate::async_bridge::execute(&self.handle, timeout, Some(&self.stats), future)
    }

    /// Execute operation with sync-first pattern for reduced async overhead.
    ///
    /// This method implements the sync-first optimization: it first attempts the
    /// synchronous operation (which avoids task spawn + channel allocation overhead).
    /// If the sync path would block (e.g., lock contention), it falls back to the
    /// async path via `exec()`.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The success type of the operation
    /// * `E` - The error type of the operation (must implement `ToErrno`)
    /// * `F` - The async fallback future type
    ///
    /// # Arguments
    ///
    /// * `sync_result` - Result of the sync-first attempt
    /// * `async_fallback` - Closure producing an async future for fallback
    ///
    /// # Returns
    ///
    /// Returns the operation result or an errno on failure.
    #[allow(dead_code)]
    fn sync_first_exec<T, E, F, Fut>(
        &self,
        sync_result: SyncFirstResult<T, E>,
        async_fallback: F,
    ) -> Result<T, i32>
    where
        E: ToErrno + Send + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
    {
        match sync_result {
            SyncFirstResult::Done(result) => {
                // Fast path: completed synchronously
                self.vault_stats.record_sync_first_hit();
                result.map_err(|e| e.to_errno())
            }
            SyncFirstResult::WouldBlock => {
                // Slow path: fall back to async
                self.vault_stats.record_sync_first_miss();
                match self.exec(async_fallback()) {
                    Ok(Ok(value)) => Ok(value),
                    Ok(Err(e)) => Err(e.to_errno()),
                    Err(bridge_err) => Err(bridge_err.to_errno()),
                }
            }
        }
    }

    /// Flush a write buffer to the vault without closing the handle.
    ///
    /// This is used by both `flush()` and `fsync()` FUSE operations.
    /// Returns:
    /// - `Ok(Some(path))` if a dirty buffer was written to the given encrypted path
    /// - `Ok(None)` if the handle is a reader or the buffer was clean
    /// - `Err(errno)` on write failure
    #[allow(dead_code)]
    fn flush_handle(&self, ino: u64, fh: u64) -> Result<Option<PathBuf>, c_int> {
        let _namespace = self.handle_table.namespace.lock();
        self.flush_handle_unlocked(ino, fh)
    }

    fn flush_handle_unlocked(&self, ino: u64, fh: u64) -> Result<Option<PathBuf>, c_int> {
        let editor = self
            .handle_table
            .get(&fh)
            .and_then(|handle| handle.editor())
            .map(|(editor, _)| editor);
        if let Some(editor) = editor {
            let ops = Arc::clone(&self.ops);
            let result = self
                .exec_with_timeout(async move { editor.commit(&ops).await }, self.write_timeout)
                .map_err(|error| error.to_errno())?
                .map_err(|error| crate::error::write_error_to_errno(&error))?;
            self.attr_cache.invalidate(ino);
            return Ok(result);
        }
        let ops = self.ops_clone();
        let result = persist_write_buffer(&self.handle_table, fh, |dir_id, filename, content| {
            self.exec_with_timeout(
                async move { ops.write_file(&dir_id, &filename, &content).await },
                self.write_timeout,
            )
            .map_err(|error| error.to_errno())?
            .map_err(|error| crate::error::write_error_to_errno(&error))
        })?;
        if let Some((path, clean)) = result {
            if let Some(ref scheduler) = self.scheduler {
                if clean {
                    scheduler.release_all_file_write_bytes(ino);
                }
                scheduler.invalidate_read_cache_inode(ino);
            }
            self.attr_cache.invalidate(ino);
            return Ok(Some(path));
        }
        Ok(None)
    }

    /// Sync a file handle's data to disk.
    ///
    /// This looks up the encrypted path for the file and calls fsync/fdatasync
    /// on the underlying storage. Used by the `fsync()` FUSE operation.
    ///
    /// # Arguments
    /// * `fh` - File handle
    /// * `datasync` - If true, only sync data (fdatasync). If false, sync data+metadata.
    #[allow(dead_code)]
    fn sync_handle_to_disk(&self, fh: u64, datasync: bool) -> Result<(), c_int> {
        let handle = self.handle_table.get(&fh).ok_or(libc::EBADF)?;

        // Only WriteBuffers need syncing (readers don't modify anything)
        let (dir_id, filename) = match handle.value() {
            FuseHandle::WriteBuffer(buffer) => {
                (buffer.dir_id().clone(), buffer.filename().to_string())
            }
            _ => return Ok(()), // Readers don't need sync
        };
        drop(handle);

        // Find the encrypted path
        let ops = self.ops_clone();
        let ops_for_sync = self.ops_clone();

        let find_result = self.exec_with_timeout(
            async move { ops.find_file(&dir_id, &filename).await },
            self.default_timeout,
        );

        let encrypted_path = match find_result {
            Ok(Ok(Some(info))) => info.encrypted_path,
            Ok(Ok(None)) => {
                // File doesn't exist in vault yet (opened for write but never written)
                // Nothing to sync - this is fine
                return Ok(());
            }
            Ok(Err(_)) => return Err(libc::EIO),
            Err(e) => return Err(e.to_errno()),
        };

        // Sync the encrypted file to disk
        let sync_result = self.exec_with_timeout(
            async move {
                ops_for_sync
                    .sync_encrypted_file(&encrypted_path, datasync)
                    .await
            },
            self.write_timeout,
        );

        match sync_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(libc::EIO),
            Err(e) => Err(e.to_errno()),
        }
    }

    /// Creates a FileAttr for a directory.
    ///
    /// The `mtime` parameter should be read from the encrypted file's metadata
    /// for accurate timestamps. Falls back to current time if None.
    fn make_dir_attr(&self, inode: u64, mtime: Option<SystemTime>) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: fuser::INodeNo(inode),
            size: 0,
            blocks: 0,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::Directory,
            perm: DEFAULT_DIR_PERM,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Creates a FileAttr for a regular file.
    ///
    /// The `mtime` parameter should be read from the encrypted file's metadata
    /// for accurate timestamps. Falls back to current time if None.
    fn make_file_attr(&self, inode: u64, size: u64, mtime: Option<SystemTime>) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: fuser::INodeNo(inode),
            size,
            blocks: size.div_ceil(u64::from(BLOCK_SIZE)),
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::RegularFile,
            perm: DEFAULT_FILE_PERM,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Returns the effective file size for an inode, accounting for in-memory buffers.
    ///
    /// For mmap to work correctly, the kernel must know the current file size
    /// even before it's flushed to disk. This returns max(disk_size, buffer_size)
    /// to ensure the kernel sees the true current size.
    #[inline]
    fn effective_file_size(&self, inode: u64, disk_size: u64) -> u64 {
        if let Some(editor) = self
            .handle_table
            .editors
            .get(&inode)
            .and_then(|entry| entry.value().upgrade())
        {
            return editor.len();
        }
        self.buffer_sizes
            .get(&inode)
            .map_or(disk_size, |s| (*s).max(disk_size))
    }

    /// Updates the tracked buffer size for an inode.
    ///
    /// Called after write operations that may extend the file.
    #[inline]
    fn update_buffer_size(&self, inode: u64, new_size: u64) {
        self.buffer_sizes
            .entry(inode)
            .and_modify(|s| *s = (*s).max(new_size))
            .or_insert(new_size);
    }

    /// Sets the exact tracked buffer size for an inode.
    /// Unlike update_buffer_size, this doesn't use max() - it sets the exact value.
    /// Use this for truncate operations where the size is being reduced.
    #[inline]
    fn set_buffer_size(&self, inode: u64, size: u64) {
        self.buffer_sizes.insert(inode, size);
    }

    /// Clears the tracked buffer size for an inode.
    ///
    /// Called after release() flushes the buffer to disk.
    #[inline]
    #[allow(dead_code)]
    fn clear_buffer_size(&self, inode: u64) {
        self.buffer_sizes.remove(&inode);
    }

    /// Creates a FileAttr for a symlink.
    ///
    /// The `mtime` parameter should be read from the encrypted file's metadata
    /// for accurate timestamps. Falls back to current time if None.
    fn make_symlink_attr(
        &self,
        inode: u64,
        target_len: u64,
        mtime: Option<SystemTime>,
    ) -> FileAttr {
        let time = mtime.unwrap_or_else(SystemTime::now);
        FileAttr {
            ino: fuser::INodeNo(inode),
            size: target_len,
            blocks: 0,
            atime: time,
            mtime: time,
            ctime: time,
            crtime: time,
            kind: FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Reads the modification time from an encrypted file path.
    ///
    /// Returns `None` if the file doesn't exist or the metadata can't be read.
    #[inline]
    fn get_mtime(path: &Path) -> Option<SystemTime> {
        std::fs::metadata(path).and_then(|m| m.modified()).ok()
    }

    /// Looks up a child entry in a directory using O(1) path lookups.
    ///
    /// Uses `find_file`, `find_directory`, and `find_symlink` which calculate
    /// the expected encrypted path directly instead of listing all entries.
    /// All three lookups run in parallel to minimize latency on network filesystems.
    /// Try sync lookup of a child entry (fast path).
    ///
    /// Attempts to look up a child entry using sync operations without async overhead.
    /// Returns `Ok(Some(...))` if successful, `Ok(None)` if lock contended (use async path).
    ///
    /// This is an optimization to avoid async task spawning for metadata operations
    /// when directory locks are available immediately.
    fn try_lookup_child_sync(
        &self,
        _parent_inode: u64,
        name: &str,
        parent_path: &VaultPath,
        dir_id: &DirId,
    ) -> FuseResult<Option<(u64, FileAttr, FileType)>> {
        // Try non-blocking lock
        // Contended → use async path
        let Some(_guard) = self.ops.try_directory_read_sync(dir_id) else {
            return Ok(None);
        };

        // Get sync ops (cached)
        let sync_ops = self.get_or_create_sync_ops()?;
        let child_path = parent_path.join(name);

        // Try file first (most common case)
        if let Ok(Some(file_info)) = sync_ops.find_file(dir_id, name) {
            let inode = self.inodes.get_or_insert(
                &child_path,
                &InodeKind::File {
                    dir_id: dir_id.clone(),
                    name: name.to_string(),
                },
            );
            let disk_size = encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
            let effective_size = self.effective_file_size(inode, disk_size);
            let mtime = Self::get_mtime(&file_info.encrypted_path);
            let attr = self.make_file_attr(inode, effective_size, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok(Some((inode, attr, FileType::RegularFile)));
        }

        // Try directory
        if let Ok(Some(dir_info)) = sync_ops.find_directory(dir_id, name) {
            let correct_kind = InodeKind::Directory {
                dir_id: dir_info.directory_id.clone(),
            };
            let inode = self.inodes.get_or_insert(&child_path, &correct_kind);
            self.inodes.update_kind(inode, correct_kind);
            let mtime = Self::get_mtime(&dir_info.encrypted_path);
            let attr = self.make_dir_attr(inode, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok(Some((inode, attr, FileType::Directory)));
        }

        // Try symlink
        if let Ok(Some(symlink_info)) = sync_ops.find_symlink(dir_id, name) {
            let inode = self.inodes.get_or_insert(
                &child_path,
                &InodeKind::Symlink {
                    dir_id: dir_id.clone(),
                    name: name.to_string(),
                },
            );
            let mtime = Self::get_mtime(&symlink_info.encrypted_path);
            let attr = self.make_symlink_attr(inode, symlink_info.target.len() as u64, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok(Some((inode, attr, FileType::Symlink)));
        }

        // Not found - return None to use async path which will handle errors properly
        Ok(None)
    }

    fn lookup_child(&self, parent_inode: u64, name: &str) -> FuseResult<(u64, FileAttr, FileType)> {
        let parent_entry = self
            .inodes
            .get(parent_inode)
            .ok_or(FuseError::InvalidInode(parent_inode))?;

        let dir_id = parent_entry.dir_id().ok_or(FuseError::PathResolution(
            "Parent is not a directory".to_string(),
        ))?;

        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        let child_path = parent_path.join(name);

        // Fast path: If the inode already exists in our table (e.g., from create() before
        // release() has flushed to vault), return it immediately without going to the vault.
        // This prevents a race condition where lookup during write returns ENOENT because
        // the file isn't in the vault yet, which would add a negative cache entry.
        //
        // IMPORTANT: Skip this fast path if the inode is marked for deferred deletion,
        // as those files should appear as ENOENT even though they still exist in the vault.
        if let Some(existing_inode) = self.inodes.get_inode(&child_path) {
            // Check if file is marked for deferred deletion
            if self
                .open_handle_tracker
                .is_marked_for_deletion(existing_inode)
            {
                return Err(FuseError::PathResolution(
                    "File marked for deletion".to_string(),
                ));
            }

            if let Some(entry) = self.inodes.get(existing_inode) {
                let (attr, file_type) = match &entry.kind {
                    InodeKind::File { .. } => {
                        // Check attr cache first, otherwise use effective size (for mmap consistency)
                        // For fast path fallback, use None for mtime - the full lookup will set it properly
                        let attr = self.attr_cache.get(existing_inode).map_or_else(
                            || {
                                // Use effective size to account for in-memory buffer
                                let size = self.effective_file_size(existing_inode, 0);
                                self.make_file_attr(existing_inode, size, None)
                            },
                            |cached| cached.value,
                        );
                        (attr, FileType::RegularFile)
                    }
                    InodeKind::Directory { .. } => {
                        let attr = self.attr_cache.get(existing_inode).map_or_else(
                            || self.make_dir_attr(existing_inode, None),
                            |cached| cached.value,
                        );
                        (attr, FileType::Directory)
                    }
                    InodeKind::Symlink { .. } => {
                        // Use size 0 for symlink if not cached (rare case)
                        let attr = self.attr_cache.get(existing_inode).map_or_else(
                            || self.make_symlink_attr(existing_inode, 0, None),
                            |cached| cached.value,
                        );
                        (attr, FileType::Symlink)
                    }
                    InodeKind::Root => {
                        let attr = self.make_dir_attr(existing_inode, None);
                        (attr, FileType::Directory)
                    }
                };
                return Ok((existing_inode, attr, file_type));
            }
        }

        // Try sync fast path (avoids async task overhead if lock available)
        if let Some(result) =
            self.try_lookup_child_sync(parent_inode, name, &parent_path, &dir_id)?
        {
            self.vault_stats.record_sync_first_hit();
            return Ok(result);
        }

        // Sync path was contended, fall back to async
        self.vault_stats.record_sync_first_miss();

        // Clone ops for async use
        let ops = self.ops_clone();
        let name_owned = name.to_string();

        // Run all three lookups in parallel - critical for high-latency backends like Google Drive
        // This reduces 3 sequential network round-trips to 1 parallel operation
        // Uses async bridge to prevent slow cloud storage from blocking FUSE thread
        let dir_id_for_lookup = dir_id.clone();
        let (file_result, dir_result, symlink_result) = self
            .exec(async move {
                tokio::join!(
                    ops.find_file(&dir_id_for_lookup, &name_owned),
                    ops.find_directory(&dir_id_for_lookup, &name_owned),
                    ops.find_symlink(&dir_id_for_lookup, &name_owned)
                )
            })
            .map_err(FuseError::Bridge)?;

        // Check file result first (most common case)

        if let Ok(Some(file_info)) = file_result {
            let inode = self.inodes.get_or_insert(
                &child_path,
                &InodeKind::File {
                    dir_id,
                    name: name.to_string(),
                },
            );
            let disk_size = encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
            // Use effective size to account for in-memory buffer (mmap consistency)
            let effective_size = self.effective_file_size(inode, disk_size);
            let mtime = Self::get_mtime(&file_info.encrypted_path);
            let attr = self.make_file_attr(inode, effective_size, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::RegularFile));
        }

        // Check directory result
        if let Ok(Some(dir_info)) = dir_result {
            let correct_kind = InodeKind::Directory {
                dir_id: dir_info.directory_id.clone(),
            };
            let inode = self.inodes.get_or_insert(&child_path, &correct_kind);
            // Always update the kind to ensure correct DirId (may have been placeholder)
            self.inodes.update_kind(inode, correct_kind);
            let mtime = Self::get_mtime(&dir_info.encrypted_path);
            let attr = self.make_dir_attr(inode, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::Directory));
        }

        // Check symlink result
        if let Ok(Some(symlink_info)) = symlink_result {
            let inode = self.inodes.get_or_insert(
                &child_path,
                &InodeKind::Symlink {
                    dir_id: dir_id.clone(),
                    name: name.to_string(),
                },
            );
            let mtime = Self::get_mtime(&symlink_info.encrypted_path);
            let attr = self.make_symlink_attr(inode, symlink_info.target.len() as u64, mtime);
            self.attr_cache.insert(inode, attr);
            return Ok((inode, attr, FileType::Symlink));
        }

        // Propagate any errors from the lookups
        file_result?;
        dir_result?;
        symlink_result?;

        // Not found
        Err(FuseError::PathResolution(format!("'{name}' not found")))
    }

    /// Lists all entries in a directory.
    ///
    /// Uses `list_all` to fetch files, directories, and symlinks in a single
    /// operation with parallel I/O, replacing 3 sequential blocking calls.
    /// Uses the async bridge to prevent slow cloud storage from blocking the FUSE thread.
    #[allow(dead_code)]
    fn list_directory(&self, dir_id: &DirId) -> FuseResult<Vec<DirListingEntry>> {
        let ops = self.ops_clone();
        let dir_id = dir_id.clone();

        // Execute with timeout to prevent slow cloud storage from blocking FUSE
        let (files, dirs, symlinks) = self
            .exec(async move { ops.list_all(&dir_id).await })
            .map_err(FuseError::Bridge)??;

        // Build entries using iterator chain instead of three separate loops
        let entries: Vec<DirListingEntry> = dirs
            .into_iter()
            .map(|d| DirListingEntry {
                inode: 0, // Will be resolved on lookup
                file_type: FileType::Directory,
                dir_id: Some(d.directory_id),
                name: d.name,
            })
            .chain(files.into_iter().map(|f| DirListingEntry {
                inode: 0,
                file_type: FileType::RegularFile,
                dir_id: None,
                name: f.name,
            }))
            .chain(symlinks.into_iter().map(|s| DirListingEntry {
                inode: 0,
                file_type: FileType::Symlink,
                dir_id: None,
                name: s.name,
            }))
            .collect();

        Ok(entries)
    }

    /// Helper for copy_file_range: write data to destination and reply.
    ///
    /// Used for synchronous copy paths (ReadBuffer/WriteBuffer sources).
    fn copy_file_range_write_dest(
        &self,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        data: &[u8],
        reply: ReplyWrite,
    ) {
        let Some(mut handle) = self.handle_table.get_mut(&fh_out) else {
            reply.error(fuser::Errno::from_i32(libc::EBADF));
            return;
        };

        let Some(buffer) = handle.as_write_buffer_mut() else {
            // Destination must be opened for writing
            reply.error(fuser::Errno::from_i32(libc::EBADF));
            return;
        };

        // FUSE guarantees offset_out is non-negative
        let old_size = buffer.len();
        let bytes_written = buffer.write(u64::try_from(offset_out).unwrap_or(0), data);
        let new_size = buffer.len();
        drop(handle);

        // Track buffer size for mmap consistency
        self.update_buffer_size(ino_out, new_size);
        // Invalidate attr cache for destination
        self.attr_cache.invalidate(ino_out);
        // Invalidate read cache for destination inode
        if let Some(ref scheduler) = self.scheduler {
            scheduler.invalidate_read_cache_inode(ino_out);
        }
        // Track write bytes for budget enforcement (delta only)
        if let Some(ref scheduler) = self.scheduler
            && new_size > old_size
        {
            scheduler.add_write_bytes(ino_out, new_size - old_size);
        }

        // FUSE kernel caps request sizes well below u32::MAX in practice.
        // Truncation here would cause offset desync, but kernel limits prevent this.
        #[allow(clippy::cast_possible_truncation)]
        reply.written(bytes_written as u32);
    }
}

impl Drop for CryptomatorFS {
    fn drop(&mut self) {
        tracing::debug!("CryptomatorFS::drop - starting shutdown");

        // 1. Clear handle table (flushes buffers, closes files)
        // This ensures no more file operations are pending
        self.handle_table.clear();

        // 2. Executor, handle, and runtime will drop in correct order
        // The field reordering ensures:
        //   - executor drops first (closes task channel, workers exit)
        //   - handle drops second (releases runtime handle)
        //   - _owned_runtime drops LAST (actual runtime shutdown)
        // This prevents panics from block_on() calls on dropped runtimes

        tracing::info!("CryptomatorFS::drop - shutdown complete");
    }
}

impl Filesystem for CryptomatorFS {
    /// Initialize the filesystem.
    ///
    /// # FUSE Spec
    /// Called once when the filesystem is mounted. The `config` parameter allows
    /// setting capabilities and connection parameters. This is the place to:
    /// - Enable async reads (`FUSE_ASYNC_READ`)
    /// - Set max_write, max_readahead
    /// - Enable writeback caching if supported
    ///
    /// # Implementation
    /// - Enables `FUSE_ASYNC_READ` for better read performance
    /// - Returns `Ok(())` to allow mount to proceed
    ///
    /// # Compliance: ✓ COMPLIANT
    fn init(&mut self, _req: &fuser::Request, config: &mut KernelConfig) -> std::io::Result<()> {
        info!("FUSE filesystem initialized");

        // Start the scheduler for async request handling
        if let Some(ref mut scheduler) = self.scheduler {
            let scheduler = Arc::get_mut(scheduler).ok_or_else(|| {
                std::io::Error::other("scheduler shared before filesystem initialization")
            })?;
            scheduler.start();
            info!("FUSE scheduler started");
        }

        // Enable async reads for better performance with concurrent readers
        config
            .add_capabilities(fuser::InitFlags::FUSE_ASYNC_READ)
            .ok();

        // Enable writeback cache for better mmap support.
        // This ensures the kernel keeps the page cache consistent and enables
        // all mmap modes, which prevents SIGBUS crashes with applications like
        // SQLite that use mmap for WAL shared memory files.
        config
            .add_capabilities(fuser::InitFlags::FUSE_WRITEBACK_CACHE)
            .ok();

        // Increase max background requests from default 16 to 32.
        // This improves throughput when the underlying vault storage is on a slow
        // backend (e.g., Google Drive, network storage) where some files are cached
        // and others are not. More pending requests reduces stalls from head-of-line
        // blocking. The congestion threshold auto-adjusts to 3/4 of this value (24).
        if let Err(e) = config.set_max_background(32) {
            warn!("Failed to set max_background to 32, got: {}", e);
        }

        Ok(())
    }

    /// Clean up the filesystem on unmount.
    ///
    /// # FUSE Spec
    /// Called when the filesystem is unmounted. All open files have been released
    /// and all pending operations completed. This is the last callback before the
    /// filesystem is destroyed.
    ///
    /// # Implementation
    /// - Logs unmount; Rust's RAII handles cleanup of VaultOperationsAsync,
    ///   InodeTable, caches, and handle table.
    ///
    /// # Compliance: ✓ COMPLIANT
    fn destroy(&mut self) {
        let pending: Vec<_> = self
            .handle_table
            .pending_releases
            .lock()
            .iter()
            .map(|(fh, ino)| (*fh, *ino))
            .collect();
        if let Some(handler) = &self.hazardous_handler {
            for (fh, ino) in pending {
                if let HazardousResult::Empty {
                    result: Err(errno), ..
                } = handler.execute(
                    RequestId(0),
                    HazardousOp::Release {
                        ino,
                        fh,
                        flags: 0,
                        lock_owner: None,
                        flush: false,
                    },
                ) && self.handle_table.contains(&fh)
                {
                    let message = format!(
                        "Unmount with unresolved write handle {fh} (errno {errno}); vault and recovery storage both failed"
                    );
                    error!("{message}");
                    self.handle_table.close_reports.lock().push(message);
                }
            }
        }
        info!("FUSE filesystem destroyed");
    }

    /// Look up a directory entry by name and get its attributes.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.lookup`)
    ///
    /// The lookup count of the found inode is incremented by one for each successful
    /// call to `fuse_reply_entry`. The filesystem should track lookup counts and only
    /// evict inodes when the count reaches zero (via `forget`).
    ///
    /// Valid replies: `fuse_reply_entry` (success) or `fuse_reply_err` (failure).
    ///
    /// The `generation` number in the reply should be non-zero and unique across
    /// the filesystem's lifetime if the FS will be exported over NFS.
    ///
    /// # Implementation Notes
    ///
    /// - Calls `get_or_insert` which increments nlookup (correct per spec)
    /// - Uses negative cache to avoid repeated lookups for missing entries
    /// - Generation is always 0 (acceptable since we don't support NFS export)
    fn lookup(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        let parent = parent.0;
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        trace!(parent = parent, name = name_str, "lookup");

        // Check negative cache
        if self.attr_cache.is_negative(parent, name_str) {
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        }

        match self.lookup_child(parent, name_str) {
            Ok((_inode, attr, _file_type)) => {
                // nlookup is incremented in lookup_child via get_or_insert (correct per spec)
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.entry(&DEFAULT_ATTR_TTL, &attr, fuser::Generation(0));
            }
            Err(e) => {
                // Add to negative cache
                self.attr_cache
                    .insert_negative(parent, name_str.to_string());
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(fuser::Errno::from_i32(e.to_errno()));
            }
        }
        // Track inode table size for memory monitoring
        self.vault_stats.set_inode_count(self.inodes.len() as u64);
    }

    /// Forget about an inode.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.forget`)
    ///
    /// Called when the kernel removes an inode from its internal caches. The `nlookup`
    /// parameter indicates how many lookup references to release. The filesystem should
    /// defer actual inode removal until the lookup count reaches zero.
    ///
    /// On unmount, the kernel may not send forget messages for all referenced inodes;
    /// the lookup count implicitly drops to zero.
    ///
    /// Valid reply: none (no response needed).
    ///
    /// # Implementation Notes
    ///
    /// - Root inode (1) is never evicted
    /// - When nlookup reaches 0, inode is removed from the path↔inode mappings
    fn forget(&self, _req: &fuser::Request, ino: fuser::INodeNo, nlookup: u64) {
        let ino = ino.0;
        trace!(inode = ino, nlookup = nlookup, "forget");
        self.inodes.forget(ino, nlookup);
        // Track inode table size for memory monitoring
        self.vault_stats.set_inode_count(self.inodes.len() as u64);
    }

    /// Batch forget for multiple inodes.
    ///
    /// # FUSE Spec
    ///
    /// Semantically identical to multiple individual `forget` calls, but batched for
    /// performance. Each entry specifies a nodeid and its nlookup decrement count.
    fn batch_forget(&self, _req: &fuser::Request, nodes: &[fuser::ForgetOne]) {
        trace!(count = nodes.len(), "batch_forget");
        for node in nodes {
            self.inodes.forget(node.nodeid().0, node.nlookup());
        }
        // Track inode table size for memory monitoring
        self.vault_stats.set_inode_count(self.inodes.len() as u64);
    }

    fn getattr(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _fh: Option<fuser::FileHandle>,
        reply: ReplyAttr,
    ) {
        let ino = ino.0;
        let start = Instant::now();
        self.vault_stats.record_metadata_op();
        trace!(inode = ino, "getattr");

        // Check cache first
        if let Some(cached) = self.attr_cache.get(ino) {
            self.vault_stats.record_metadata_latency(start.elapsed());
            // CRITICAL for mmap: When there's an active write buffer, the cached
            // attr might have a stale size. We need to:
            // 1. Return zero TTL to prevent kernel from caching
            // 2. Update the size to reflect the current buffer size
            if let Some(buffer_size) = self.buffer_sizes.get(&ino) {
                let effective_size = (*buffer_size).max(cached.value.size);
                debug!(
                    inode = ino,
                    cached_size = cached.value.size,
                    effective_size,
                    "getattr: cache hit but updating size and using zero TTL for actively buffered file"
                );
                let mut attr = cached.value;
                attr.size = effective_size;
                reply.attr(&Duration::ZERO, &attr);
            } else {
                reply.attr(&cached.time_remaining(), &cached.value);
            }
            return;
        }

        // Get inode entry
        let Some(entry) = self.inodes.get(ino) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let attr = match &entry.kind {
            InodeKind::Root | InodeKind::Directory { .. } => self.make_dir_attr(ino, None),
            InodeKind::File { dir_id, name } => {
                // Try sync-first pattern to avoid async overhead
                let sync_result = self.ops.try_find_file_sync(dir_id, name);
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                let result = match sync_result {
                    SyncFirstResult::Done(result) => {
                        self.vault_stats.record_sync_first_hit();
                        result
                    }
                    SyncFirstResult::WouldBlock => {
                        // Fall back to async path
                        self.vault_stats.record_sync_first_miss();
                        let ops = self.ops_clone();
                        match self.exec(async move { ops.find_file(&dir_id, &name).await }) {
                            Ok(r) => r,
                            Err(exec_err) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                                return;
                            }
                        }
                    }
                };

                match result {
                    Ok(Some(info)) => {
                        let disk_size = encrypted_to_plaintext_size_or_zero(info.encrypted_size);
                        // Use effective size to account for in-memory buffer (mmap consistency)
                        let effective_size = self.effective_file_size(ino, disk_size);
                        if effective_size != disk_size {
                            debug!(
                                inode = ino,
                                disk_size,
                                effective_size,
                                "getattr: using effective size from buffer"
                            );
                        }
                        let mtime = Self::get_mtime(&info.encrypted_path);
                        self.make_file_attr(ino, effective_size, mtime)
                    }
                    Ok(None) => {
                        // File not found in vault, but might be newly created
                        // (exists only in WriteBuffer, not yet flushed to disk)
                        // Check if there's an active write buffer for this inode
                        if let Some(buffer_size) = self.buffer_sizes.get(&ino) {
                            // File exists in memory but not yet on disk - return synthetic attr
                            debug!(
                                inode = ino,
                                buffer_size = *buffer_size,
                                "getattr: file not in vault but has active buffer"
                            );
                            self.make_file_attr(ino, *buffer_size, None)
                        } else {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(libc::ENOENT));
                            return;
                        }
                    }
                    Err(e) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(crate::error::vault_error_to_errno(
                            &e,
                        )));
                        return;
                    }
                }
            }
            InodeKind::Symlink { dir_id, name } => {
                // Try sync-first pattern to avoid async overhead
                let sync_result = self.ops.try_find_symlink_sync(dir_id, name);
                let dir_id = dir_id.clone();
                let name = name.clone();
                drop(entry);

                let result = match sync_result {
                    SyncFirstResult::Done(result) => {
                        self.vault_stats.record_sync_first_hit();
                        result
                    }
                    SyncFirstResult::WouldBlock => {
                        // Fall back to async path
                        self.vault_stats.record_sync_first_miss();
                        let ops = self.ops_clone();
                        match self.exec(async move { ops.find_symlink(&dir_id, &name).await }) {
                            Ok(r) => r,
                            Err(exec_err) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                                return;
                            }
                        }
                    }
                };

                match result {
                    Ok(Some(info)) => {
                        let mtime = Self::get_mtime(&info.encrypted_path);
                        self.make_symlink_attr(ino, info.target.len() as u64, mtime)
                    }
                    Ok(None) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(libc::ENOENT));
                        return;
                    }
                    Err(e) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(crate::error::vault_error_to_errno(
                            &e,
                        )));
                        return;
                    }
                }
            }
        };

        self.attr_cache.insert(ino, attr);
        self.vault_stats.record_metadata_latency(start.elapsed());

        // Use zero TTL for files with active write buffers to prevent kernel from
        // caching stale size, which causes SIGBUS when mmap accesses extended regions.
        let ttl = if self.buffer_sizes.contains_key(&ino) {
            debug!(
                inode = ino,
                "getattr: using zero TTL for actively buffered file"
            );
            Duration::ZERO
        } else {
            DEFAULT_ATTR_TTL
        };
        reply.attr(&ttl, &attr);
    }

    fn readlink(&self, _req: &fuser::Request, ino: fuser::INodeNo, reply: ReplyData) {
        let ino = ino.0;
        trace!(inode = ino, "readlink");

        let Some(entry) = self.inodes.get(ino) else {
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let (dir_id, name) = match &entry.kind {
            InodeKind::Symlink { dir_id, name } => (dir_id.clone(), name.clone()),
            _ => {
                reply.error(fuser::Errno::from_i32(libc::EINVAL));
                return;
            }
        };
        drop(entry);

        let ops = self.ops_clone();

        match self.exec(async move { ops.read_symlink(&dir_id, &name).await }) {
            Ok(Ok(target)) => {
                reply.data(target.as_bytes());
            }
            Ok(Err(e)) => {
                reply.error(fuser::Errno::from_i32(crate::error::vault_error_to_errno(
                    &e,
                )));
            }
            Err(exec_err) => {
                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
            }
        }
    }

    /// Open a file.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.open`)
    ///
    /// Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY, O_TRUNC which are
    /// filtered by the kernel) are available in `flags`. The filesystem may store an
    /// arbitrary file handle in the reply; this handle will be passed to subsequent
    /// read/write/flush/release calls.
    ///
    /// Access mode should be checked unless `default_permissions` mount option is set.
    ///
    /// **Writeback caching note**: The kernel may send read requests even for O_WRONLY
    /// files when writeback caching is enabled.
    ///
    /// Valid replies: `fuse_reply_open` (success) or `fuse_reply_err` (failure).
    ///
    /// # Implementation Notes
    ///
    /// - For read-only opens: creates a streaming VaultFileReader
    /// - For write opens: creates a WriteBuffer with existing content (or empty if O_TRUNC)
    /// - File handles are stored in FuseHandleTable
    fn open(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        flags: fuser::OpenFlags,
        reply: ReplyOpen,
    ) {
        let ino = ino.0;
        let flags = flags.0;
        trace!(inode = ino, flags = flags, "open");
        let _namespace = self.handle_table.namespace.lock();

        let Some(entry) = self.inodes.get(ino) else {
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let (dir_id, name) = match &entry.kind {
            InodeKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            InodeKind::Directory { .. } | InodeKind::Root => {
                reply.error(fuser::Errno::from_i32(libc::EISDIR));
                return;
            }
            InodeKind::Symlink { .. } => {
                reply.error(fuser::Errno::from_i32(libc::EINVAL));
                return;
            }
        };
        drop(entry);

        #[cfg(target_os = "macos")]
        let _resource_guard = name.starts_with("._").then(|| self.resource_lock.lock());

        let open_flags = fuser::FopenFlags::empty();
        // Check if opening for write
        let is_write = (flags & libc::O_ACCMODE) != libc::O_RDONLY;
        let is_trunc = (flags & libc::O_TRUNC) != 0;

        let existing = self
            .handle_table
            .editors
            .get(&ino)
            .and_then(|entry| entry.value().upgrade());
        let editor = if let Some(editor) = existing {
            editor
        } else {
            let ops = self.ops_clone();
            match self.exec(async move {
                oxcrypt_mount::EditBuffer::open(&ops, dir_id, name, false, false).await
            }) {
                Ok(Ok(editor)) => Arc::new(editor),
                Ok(Err(error)) => {
                    reply.error(fuser::Errno::from_i32(crate::error::write_error_to_errno(
                        &error,
                    )));
                    return;
                }
                Err(error) => {
                    reply.error(fuser::Errno::from_i32(error.to_errno()));
                    return;
                }
            }
        };
        if is_trunc
            && is_write
            && let Err(error) = editor.truncate(0)
        {
            reply.error(fuser::Errno::from_i32(
                error.raw_os_error().unwrap_or(libc::EIO),
            ));
            return;
        }
        self.handle_table
            .editors
            .insert(ino, Arc::downgrade(&editor));
        self.set_buffer_size(ino, editor.len());
        let fh = self.handle_table.insert_auto(FuseHandle::Editor {
            buffer: editor,
            writable: is_write,
        });
        self.open_handle_tracker.add_handle(ino);
        self.vault_stats.record_file_open();
        reply.opened(fuser::FileHandle(fh), open_flags);
    }

    fn read(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        let offset = offset.cast_signed();
        trace!(inode = ino, fh = fh, offset = offset, size = size, "read");

        // Get the handle from our table
        let Some(mut handle) = self.handle_table.get_mut(&fh) else {
            reply.error(fuser::Errno::from_i32(libc::EBADF));
            return;
        };

        match &mut *handle {
            FuseHandle::Editor { buffer, .. } => {
                let buffer = Arc::clone(buffer);
                drop(handle);
                let Some(permit) = self.handle_table.reader_wait_slot() else {
                    reply.error(fuser::Errno::from_i32(libc::EAGAIN));
                    return;
                };
                let stats = Arc::clone(&self.vault_stats);
                let task = self.handle.spawn_blocking(move || {
                    let _permit = permit;
                    buffer.read(u64::try_from(offset).unwrap_or(0), size as usize)
                });
                let timeout = self.default_timeout;
                self.handle.spawn(async move {
                    match tokio::time::timeout(timeout, task).await {
                        Ok(Ok(Ok(data))) => {
                            stats.record_read(data.len() as u64);
                            reply.data(&data);
                        }
                        Ok(Ok(Err(error))) => reply.error(fuser::Errno::from_i32(
                            error.raw_os_error().unwrap_or(libc::EIO),
                        )),
                        Ok(Err(_)) => reply.error(fuser::Errno::from_i32(libc::EIO)),
                        Err(_) => reply.error(fuser::Errno::from_i32(libc::ETIMEDOUT)),
                    }
                });
            }

            FuseHandle::Reader(_) => {
                // Async read path: loan reader to scheduler, return immediately
                // Take the reader by replacing with ReaderLoaned placeholder
                let old_handle = std::mem::replace(&mut *handle, FuseHandle::ReaderLoaned);
                let FuseHandle::Reader(reader) = old_handle else {
                    unreachable!("just matched Reader variant")
                };

                // Drop the handle lock before enqueuing to avoid deadlock
                drop(handle);

                // Enqueue to scheduler - it will reply and restore the reader
                let scheduler = self.scheduler.as_ref().expect("scheduler not initialized");

                let offset_u64 = u64::try_from(offset).unwrap_or(0);
                let size_usize = usize::try_from(size).unwrap_or(0);

                self.vault_stats.start_read();
                match scheduler.try_enqueue_read(ino, fh, reader, offset_u64, size_usize, reply) {
                    Ok(request_id) => {
                        trace!(
                            ?request_id,
                            fh, offset_u64, size_usize, "Read enqueued to scheduler"
                        );
                        // Return immediately - scheduler will reply asynchronously
                        // Stats will be updated when the dispatcher receives the result
                    }
                    Err(e) => {
                        // Enqueue failed - scheduler already replied with error.
                        // Rejected work restores its reader where available; late
                        // completions wake any deferred reads.
                        self.vault_stats.finish_read();
                        warn!(error = %e, fh, "Failed to enqueue read request (scheduler replied with error)");
                    }
                }
            }
            FuseHandle::ReaderLoaned => {
                drop(handle);
                let Some(permit) = self.handle_table.reader_wait_slot() else {
                    reply.error(fuser::Errno::from_i32(libc::EAGAIN));
                    return;
                };
                let Some(scheduler) = self.scheduler.as_ref().map(Arc::clone) else {
                    reply.error(fuser::Errno::from_i32(libc::EIO));
                    return;
                };
                let handles = Arc::clone(&self.handle_table);
                let stats = Arc::clone(&self.vault_stats);
                let timeout = self.default_timeout;
                self.handle.spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(timeout, handles.wait_for_reader(fh)).await {
                        Ok(Ok(reader)) => {
                            stats.start_read();
                            if scheduler
                                .try_enqueue_read(
                                    ino,
                                    fh,
                                    reader,
                                    u64::try_from(offset).unwrap_or(0),
                                    size as usize,
                                    reply,
                                )
                                .is_err()
                            {
                                stats.finish_read();
                            }
                        }
                        Ok(Err(error)) => reply.error(fuser::Errno::from_i32(error)),
                        Err(_) => reply.error(fuser::Errno::from_i32(libc::ETIMEDOUT)),
                    }
                });
            }
            FuseHandle::ReadBuffer(content) => {
                // Read from in-memory buffer (preferred path, no locks held)
                // FUSE guarantees offset is non-negative (it's from kernel read requests)
                // On 32-bit: offsets beyond 4GB would fail earlier in VFS layer
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let offset = offset as usize;
                let end = std::cmp::min(offset + size as usize, content.len());
                let data = if offset < content.len() {
                    &content[offset..end]
                } else {
                    &[]
                };
                self.vault_stats.record_read(data.len() as u64);
                reply.data(data);
            }
            FuseHandle::WriteBuffer(buffer) => {
                // Read from write buffer (for read-after-write in same handle)
                // FUSE guarantees offset is non-negative (it's from kernel read requests)
                #[allow(clippy::cast_sign_loss)]
                let offset_u64 = offset as u64;
                let data = buffer.read(offset_u64, size as usize);
                self.vault_stats.record_read(data.len() as u64);
                reply.data(data);
            }
        }
    }

    /// Release an open file.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.release`)
    ///
    /// Called when ALL references to an open file are gone (all file descriptors
    /// closed and all memory mappings unmapped). There is exactly ONE `release` call
    /// for every `open` call.
    ///
    /// The filesystem may reply with an error, but it will NOT propagate to the
    /// triggering `close()` or `munmap()` call.
    ///
    /// Valid reply: `fuse_reply_err` (0 for success, errors ignored by caller).
    ///
    /// # Implementation Notes
    ///
    /// - Removes file handle from handle table
    /// - For write buffers: writes dirty data to vault before releasing
    /// - For readers: simply drops the handle
    fn release(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        flags: fuser::OpenFlags,
        lock_owner: Option<fuser::LockOwner>,
        flush: bool,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        let flags = flags.0;
        let lock_owner = lock_owner.map(|l| l.0);
        trace!(fh = fh, "release (enqueuing to hazardous lane)");

        let op = HazardousOp::Release {
            ino,
            fh,
            flags,
            lock_owner,
            flush,
        };
        let reply_handle = HazardousReply::Empty(reply);

        if let Some(ref scheduler) = self.scheduler {
            let handler = self
                .hazardous_handler
                .as_ref()
                .expect("hazardous handler not initialized");
            if let Err(e) = scheduler.try_enqueue_hazardous(op, reply_handle, Arc::clone(handler)) {
                error!(?e, "Failed to enqueue release");
                // Reply is already sent by try_enqueue_hazardous in error case
            }
        } else {
            error!("Scheduler missing in release");
            // If scheduler is missing, we can't do anything async.
            // Just reply ok to unblock kernel, but this leaks handles/memory.
            // In practice scheduler is always present.
            if let HazardousReply::Empty(r) = reply_handle {
                r.ok();
            }
        }
    }

    fn opendir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _flags: fuser::OpenFlags,
        reply: ReplyOpen,
    ) {
        let ino = ino.0;
        trace!(inode = ino, "opendir");

        // Verify it's a directory
        let Some(entry) = self.inodes.get(ino) else {
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        match &entry.kind {
            InodeKind::Root | InodeKind::Directory { .. } => {
                self.vault_stats.record_dir_open();
                reply.opened(fuser::FileHandle(0), fuser::FopenFlags::empty());
            }
            _ => {
                reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            }
        }
    }

    /// Read directory entries.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.readdir`)
    ///
    /// Send a buffer filled with directory entries using `reply.add()`. The `offset`
    /// parameter is the offset of the next entry to return; it should be a value
    /// previously returned by a `reply.add()` call (typically the entry index + 1).
    ///
    /// **IMPORTANT**: Per the spec, "Returning a directory entry from readdir() does
    /// NOT affect its lookup count." This is different from `readdirplus`.
    ///
    /// # Implementation Notes
    ///
    /// Uses `get_or_insert_no_lookup_inc()` which allocates or retrieves inodes WITHOUT
    /// incrementing the nlookup count, as required by the FUSE specification.
    fn readdir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        let offset = offset.cast_signed();
        // FAST PATH: Check dir_cache before enqueueing to scheduler.
        // This avoids scheduler overhead for cached directory listings.
        if let Some(cached_entries) = self.dir_cache.get(ino) {
            trace!(
                inode = ino,
                offset = offset,
                entries = cached_entries.len(),
                "readdir cache hit - fast path"
            );

            // Look up parent inode for ".." entry
            let parent_inode = self
                .inodes
                .get(ino)
                .and_then(|entry| entry.path.parent())
                .and_then(|parent| self.inodes.get_inode(&parent))
                .unwrap_or(crate::inode::ROOT_INODE);

            // Get dir_id for "." entry
            let dir_id = self.inodes.get(ino).and_then(|entry| entry.dir_id());

            // Build full entry list with "." and ".."
            let mut all_entries: Vec<(String, FileType, Option<DirId>)> = vec![
                (".".to_string(), FileType::Directory, dir_id),
                ("..".to_string(), FileType::Directory, None),
            ];
            all_entries.extend(
                cached_entries
                    .iter()
                    .map(|e| (e.name.clone(), e.file_type, e.dir_id.clone())),
            );
            all_entries[SPECIAL_ENTRY_COUNT..].sort_by(|a, b| a.0.cmp(&b.0));

            // Find starting position based on offset
            let start_idx = readdir_resume_index(offset, &all_entries, |e| e.0.as_str());

            // Build response
            for (idx, (name, file_type, maybe_subdir_id)) in
                all_entries.into_iter().enumerate().skip(start_idx)
            {
                let entry_inode = if name == "." {
                    ino
                } else if name == ".." {
                    parent_inode
                } else {
                    // Get or create inode for entry (no nlookup increment for readdir)
                    let entry_path = self
                        .inodes
                        .get(ino)
                        .map_or_else(VaultPath::root, |e| e.path.join(&name));
                    let kind = match file_type {
                        FileType::Directory => InodeKind::Directory {
                            dir_id: maybe_subdir_id.unwrap_or_else(DirId::root),
                        },
                        FileType::Symlink => {
                            // For symlinks we need to look up the dir_id from parent
                            let parent_dir_id = self
                                .inodes
                                .get(ino)
                                .and_then(|e| e.dir_id())
                                .unwrap_or_else(DirId::root);
                            InodeKind::Symlink {
                                dir_id: parent_dir_id,
                                name: name.clone(),
                            }
                        }
                        _ => {
                            let parent_dir_id = self
                                .inodes
                                .get(ino)
                                .and_then(|e| e.dir_id())
                                .unwrap_or_else(DirId::root);
                            InodeKind::File {
                                dir_id: parent_dir_id,
                                name: name.clone(),
                            }
                        }
                    };
                    self.inodes.get_or_insert_no_lookup_inc(&entry_path, &kind)
                };

                if reply.add(
                    fuser::INodeNo(entry_inode),
                    readdir_offset_at(idx, &name).cast_unsigned(),
                    file_type,
                    &name,
                ) {
                    break; // Buffer full
                }
            }

            reply.ok();
            self.vault_stats.record_metadata_op();
            return;
        }

        // SLOW PATH: Cache miss - enqueue to scheduler
        trace!(
            inode = ino,
            offset = offset,
            "readdir cache miss - enqueuing to scheduler"
        );

        let op = HazardousOp::Readdir { ino, fh, offset };
        let reply_handle = HazardousReply::Directory(reply);

        if let Some(ref scheduler) = self.scheduler {
            let handler = self
                .hazardous_handler
                .as_ref()
                .expect("hazardous handler not initialized");
            if let Err(e) = scheduler.try_enqueue_hazardous(op, reply_handle, Arc::clone(handler)) {
                error!(?e, "Failed to enqueue readdir");
            }
        } else {
            error!("Scheduler missing in readdir");
            if let HazardousReply::Directory(r) = reply_handle {
                r.error(fuser::Errno::from_i32(libc::EIO));
            }
        }
    }

    /// Read directory entries with attributes (readdirplus).
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.readdirplus`)
    ///
    /// Like `readdir`, but also returns file attributes for each entry. This allows
    /// the kernel to cache attributes, avoiding subsequent `getattr` calls.
    ///
    /// **IMPORTANT**: Unlike `readdir`, "the lookup count of every entry returned by
    /// readdirplus(), except '.' and '..', is incremented by one" on success.
    ///
    /// # Implementation Notes
    ///
    /// - Correctly increments nlookup via `get_or_insert()` for non-. entries
    /// - "." and ".." use existing inodes without incrementing nlookup
    fn readdirplus(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        reply: ReplyDirectoryPlus,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        let offset = offset.cast_signed();
        trace!(
            inode = ino,
            offset = offset,
            "readdirplus (enqueuing to hazardous lane)"
        );

        let op = HazardousOp::ReaddirPlus { ino, fh, offset };
        let reply_handle = HazardousReply::DirectoryPlus(reply);

        if let Some(ref scheduler) = self.scheduler {
            let handler = self
                .hazardous_handler
                .as_ref()
                .expect("hazardous handler not initialized");
            if let Err(e) = scheduler.try_enqueue_hazardous(op, reply_handle, Arc::clone(handler)) {
                error!(?e, "Failed to enqueue readdirplus");
            }
        } else {
            error!("Scheduler missing in readdirplus");
            if let HazardousReply::DirectoryPlus(r) = reply_handle {
                r.error(fuser::Errno::from_i32(libc::EIO));
            }
        }
    }

    fn releasedir(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        _fh: fuser::FileHandle,
        _flags: fuser::OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.vault_stats.record_dir_close();
        reply.ok();
    }

    /// Flush cached data for an open file.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.flush`)
    ///
    /// Called on each `close()` of an opened file. May be called multiple times for
    /// the same file handle if the descriptor was duplicated (via `dup()`).
    ///
    /// **Note**: This is NOT the same as `fsync`. The POSIX `close()` does not
    /// guarantee that delayed I/O has completed. Flush should also release any
    /// POSIX locks belonging to the `lock_owner`.
    ///
    /// Valid reply: `fuse_reply_err` (0 for success).
    ///
    /// # Implementation Notes
    ///
    /// - Writes dirty buffer contents to the vault
    /// - Does not release the file handle (that's `release`'s job)
    /// - Lock release is a no-op since we don't implement POSIX locks
    fn flush(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        let lock_owner = lock_owner.0;
        trace!(inode = ino, fh = fh, "flush (enqueuing to hazardous lane)");

        let op = HazardousOp::Flush {
            ino,
            fh,
            lock_owner,
        };
        let reply_handle = HazardousReply::Empty(reply);

        if let Some(ref scheduler) = self.scheduler {
            let handler = self
                .hazardous_handler
                .as_ref()
                .expect("hazardous handler not initialized");
            if let Err(e) = scheduler.try_enqueue_hazardous(op, reply_handle, Arc::clone(handler)) {
                error!(?e, "Failed to enqueue flush");
            }
        } else {
            error!("Scheduler missing in flush");
            if let HazardousReply::Empty(r) = reply_handle {
                r.error(fuser::Errno::from_i32(libc::EIO));
            }
        }
    }

    fn fsync(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        trace!(inode = ino, fh = fh, "fsync (enqueuing to hazardous lane)");

        let op = HazardousOp::Fsync { ino, fh, datasync };
        let reply_handle = HazardousReply::Empty(reply);

        if let Some(ref scheduler) = self.scheduler {
            let handler = self
                .hazardous_handler
                .as_ref()
                .expect("hazardous handler not initialized");
            if let Err(e) = scheduler.try_enqueue_hazardous(op, reply_handle, Arc::clone(handler)) {
                error!(?e, "Failed to enqueue fsync");
            }
        } else {
            error!("Scheduler missing in fsync");
            if let HazardousReply::Empty(r) = reply_handle {
                r.error(fuser::Errno::from_i32(libc::EIO));
            }
        }
    }

    fn fsyncdir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _fh: fuser::FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        trace!(inode = ino, "fsyncdir");
        let Some(entry) = self.inodes.get(ino) else {
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };
        let Some(dir_id) = entry.dir_id() else {
            reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            return;
        };
        drop(entry);
        let ops = self.ops_clone();
        match self.exec(async move { ops.sync_directory(&dir_id).await }) {
            Ok(Ok(())) => reply.ok(),
            Ok(Err(error)) => reply.error(fuser::Errno::from_i32(
                crate::error::write_error_to_errno(&error),
            )),
            Err(error) => reply.error(fuser::Errno::from_i32(error.to_errno())),
        }
    }

    fn access(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        mask: fuser::AccessFlags,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        let mask = mask.bits();
        trace!(inode = ino, mask = mask, "access");

        // Cryptomator doesn't store Unix permissions, so we use synthetic defaults:
        // - Files: 644 (rw-r--r--)
        // - Directories: 755 (rwxr-xr-x)
        // All files are owned by the mounting user.
        //
        // Simply verify the inode exists and return success.
        // The mounting user has full access to everything.
        if self.inodes.get(ino).is_some() {
            reply.ok();
        } else {
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
        }
    }

    /// Set file attributes.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.setattr`)
    ///
    /// Modifies file attributes. The bitmask indicates which fields are valid.
    /// Must reply with the new attributes on success.
    ///
    /// **setuid/setgid note**: When FUSE_CAP_HANDLE_KILLPRIV is enabled, the
    /// filesystem must reset setuid/setgid bits when the file size or owner changes.
    /// This is a security requirement to prevent privilege escalation.
    ///
    /// # Implementation Notes
    ///
    /// - chmod/chown are silently accepted but ignored (Cryptomator doesn't store Unix permissions)
    ///   This matches the behavior of vfat and other filesystems without permission support.
    /// - truncate (size change) is fully supported
    /// - atime/mtime changes are silently accepted for compatibility (touch, tar, rsync)
    ///   but not actually stored (Cryptomator doesn't preserve timestamps)
    ///
    /// # Partial Compliance
    ///
    /// Does not handle setuid/setgid bit reset on truncate. This is acceptable because:
    /// 1. Cryptomator doesn't store Unix permissions at all
    /// 2. Our synthetic permissions never include setuid/setgid bits
    fn setattr(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<fuser::FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let ino = ino.0;
        let start = Instant::now();
        self.vault_stats.record_metadata_op();
        trace!(
            inode = ino,
            mode = ?mode,
            uid = ?uid,
            gid = ?gid,
            size = ?size,
            "setattr"
        );

        // Cryptomator doesn't store Unix permissions or timestamps.
        // We silently ignore chmod/chown/atime/mtime changes for compatibility.
        // This matches the behavior of vfat and other filesystems without permission support.
        // Only truncate (size change) is actually processed.

        // Get current inode info
        let Some(entry) = self.inodes.get(ino) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        // Handle size change (truncate)
        if let Some(new_size) = size {
            match &entry.kind {
                InodeKind::File { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    drop(entry);
                    let _namespace = self.handle_table.namespace.lock();
                    let result = (|| {
                        let editor = self.editor_for_inode(ino, dir_id, name)?;
                        editor
                            .truncate(new_size)
                            .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
                        let ops = self.ops_clone();
                        self.exec_with_timeout(
                            async move { editor.commit(&ops).await },
                            self.write_timeout,
                        )
                        .map_err(|error| error.to_errno())?
                        .map_err(|error| crate::error::write_error_to_errno(&error))?;
                        Ok::<(), i32>(())
                    })();
                    match result {
                        Ok(()) => {
                            self.set_buffer_size(ino, new_size);
                            let attr = self.make_file_attr(ino, new_size, None);
                            self.attr_cache.insert(ino, attr);
                            reply.attr(&Duration::ZERO, &attr);
                        }
                        Err(errno) => reply.error(fuser::Errno::from_i32(errno)),
                    }
                    return;
                }
                InodeKind::Directory { .. } | InodeKind::Root => {
                    // Can't truncate directories
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(fuser::Errno::from_i32(libc::EISDIR));
                    return;
                }
                InodeKind::Symlink { .. } => {
                    // Can't truncate symlinks
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(fuser::Errno::from_i32(libc::EINVAL));
                    return;
                }
            }
        }

        // Handle atime/mtime changes - update timestamps on encrypted files
        // (touch, tar, rsync use these)
        if atime.is_some() || mtime.is_some() {
            // Convert TimeOrNow to FileTime
            let atime_ft = atime.map(|t| match t {
                TimeOrNow::Now => FileTime::now(),
                TimeOrNow::SpecificTime(st) => FileTime::from(st),
            });
            let mtime_ft = mtime.map(|t| match t {
                TimeOrNow::Now => FileTime::now(),
                TimeOrNow::SpecificTime(st) => FileTime::from(st),
            });

            let attr = match &entry.kind {
                InodeKind::Root | InodeKind::Directory { .. } => {
                    // For directories, we don't have easy access to the encrypted path
                    // without the parent info. Timestamps on directories are less
                    // critical than on files, so we just silently succeed here.
                    drop(entry);
                    self.make_dir_attr(ino, None)
                }
                InodeKind::File { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    drop(entry);

                    if let Some(editor) = self
                        .handle_table
                        .editors
                        .get(&ino)
                        .and_then(|entry| entry.value().upgrade())
                    {
                        match editor.set_times(atime_ft.map(Into::into), mtime_ft.map(Into::into)) {
                            Ok(()) => {
                                let attr = self.make_file_attr(
                                    ino,
                                    editor.len(),
                                    mtime_ft.map(Into::into),
                                );
                                self.attr_cache.insert(ino, attr);
                                reply.attr(&Duration::ZERO, &attr);
                            }
                            Err(error) => reply.error(fuser::Errno::from_i32(
                                error.raw_os_error().unwrap_or(libc::EIO),
                            )),
                        }
                        return;
                    }
                    let ops = self.ops_clone();
                    match self.exec(async move { ops.find_file(&dir_id, &name).await }) {
                        Ok(Ok(Some(file_info))) => {
                            // Update timestamps on the encrypted file
                            if let Err(e) = filetime::set_file_times(
                                &file_info.encrypted_path,
                                atime_ft.unwrap_or(FileTime::now()),
                                mtime_ft.unwrap_or(FileTime::now()),
                            ) {
                                warn!("Failed to set file times: {:?}", e);
                            }
                            let file_size =
                                encrypted_to_plaintext_size_or_zero(file_info.encrypted_size);
                            let new_mtime = Self::get_mtime(&file_info.encrypted_path);
                            self.make_file_attr(ino, file_size, new_mtime)
                        }
                        Ok(Ok(None)) => self.make_file_attr(ino, 0, None),
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(
                                crate::error::vault_error_to_errno(&e),
                            ));
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                            return;
                        }
                    }
                }
                InodeKind::Symlink { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    drop(entry);

                    let ops = self.ops_clone();
                    match self.exec(async move { ops.find_symlink(&dir_id, &name).await }) {
                        Ok(Ok(Some(info))) => {
                            // Update timestamps on the encrypted symlink file
                            if let Err(e) = filetime::set_file_times(
                                &info.encrypted_path,
                                atime_ft.unwrap_or(FileTime::now()),
                                mtime_ft.unwrap_or(FileTime::now()),
                            ) {
                                warn!("Failed to set symlink times: {:?}", e);
                            }
                            let new_mtime = Self::get_mtime(&info.encrypted_path);
                            self.make_symlink_attr(ino, info.target.len() as u64, new_mtime)
                        }
                        Ok(Ok(None)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(libc::ENOENT));
                            return;
                        }
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(
                                crate::error::vault_error_to_errno(&e),
                            ));
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                            return;
                        }
                    }
                }
            };

            self.attr_cache.insert(ino, attr);
            self.vault_stats.record_metadata_latency(start.elapsed());
            // Use zero TTL if file has active buffer to prevent kernel caching stale size
            let ttl = if self.buffer_sizes.contains_key(&ino) {
                Duration::ZERO
            } else {
                DEFAULT_ATTR_TTL
            };
            reply.attr(&ttl, &attr);
            return;
        }

        // No size/time changes requested (chmod or chown) - return current attributes
        // Cryptomator doesn't store permissions, so we silently succeed with current attrs.
        // This is similar to vfat and other filesystems without permission support.
        //
        // IMPORTANT: We avoid expensive file lookups here because:
        // 1. chmod/chown don't actually change anything in Cryptomator vaults
        // 2. During bulk operations (like tar extraction), files may have just been
        //    created and closed, and doing a lookup can fail due to timing issues
        // 3. The kernel just needs us to return success with valid attrs
        if let Some(cached) = self.attr_cache.get(ino) {
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.attr(&cached.time_remaining(), &cached.value);
        } else {
            // No cache hit - return synthetic attrs based on inode type
            // This avoids expensive vault I/O for mode-only changes
            let attr = match &entry.kind {
                InodeKind::Root | InodeKind::Directory { .. } => {
                    drop(entry);
                    self.make_dir_attr(ino, None)
                }
                InodeKind::File { .. } => {
                    drop(entry);
                    // Use buffer size if available, otherwise size 0
                    // (the actual size will be fetched on next getattr)
                    let size = self.buffer_sizes.get(&ino).map_or(0, |r| *r);
                    self.make_file_attr(ino, size, None)
                }
                InodeKind::Symlink { .. } => {
                    drop(entry);
                    // Symlink with unknown target length - use 0
                    // (the actual size will be fetched on next getattr)
                    self.make_symlink_attr(ino, 0, None)
                }
            };
            // Don't cache this synthetic attr - let getattr do the real lookup
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.attr(&Duration::ZERO, &attr);
        }
    }

    fn statfs(&self, _req: &fuser::Request, _ino: fuser::INodeNo, reply: fuser::ReplyStatfs) {
        // Query real filesystem statistics from underlying storage
        match nix::sys::statvfs::statvfs(&self.vault_path) {
            Ok(stat) => {
                // On Linux, cap name_max at 254 because Nautilus (GNOME Files) tests
                // namelen+1 when checking filename validity. Using 255 causes Nautilus
                // to incorrectly reject valid filenames at the boundary.
                // See: https://github.com/cryptomator/fuse-nio-adapter (DEFAULT_MAX_FILENAMELENGTH)
                // name_max from statvfs is typically 255, which fits in u32
                #[allow(clippy::cast_possible_truncation)]
                #[cfg(target_os = "linux")]
                let name_max = std::cmp::min(stat.name_max() as u32, 254);
                #[allow(clippy::cast_possible_truncation)]
                #[cfg(not(target_os = "linux"))]
                let name_max = stat.name_max() as u32;

                // fragment_size is typically 4096-8192, which fits in u32
                #[allow(clippy::cast_possible_truncation)]
                let fragment_size = stat.fragment_size() as u32;

                // statvfs counters are u32 on macOS but already u64 on Linux,
                // where these conversions are identities
                #[allow(clippy::useless_conversion)]
                reply.statfs(
                    u64::from(stat.blocks()),           // Total blocks
                    u64::from(stat.blocks_free()),      // Free blocks
                    u64::from(stat.blocks_available()), // Available blocks (non-root)
                    u64::from(stat.files()),            // Total inodes
                    u64::from(stat.files_free()),       // Free inodes
                    fragment_size,                      // Block size
                    name_max,                           // Max filename length
                    fragment_size,                      // Fragment size
                );
            }
            Err(e) => {
                debug!(error = %e, "Failed to get statfs, using defaults");
                // On Linux, use 254 for namelen (Nautilus compatibility).
                #[cfg(target_os = "linux")]
                let default_namelen = 254u32;
                #[cfg(not(target_os = "linux"))]
                let default_namelen = 255u32;

                // Fallback to reasonable defaults
                reply.statfs(
                    1000000,         // blocks
                    500000,          // bfree
                    500000,          // bavail
                    1000000,         // files
                    500000,          // ffree
                    BLOCK_SIZE,      // bsize
                    default_namelen, // namelen
                    BLOCK_SIZE,      // frsize
                );
            }
        }
    }

    // ==================== Write Operations ====================

    /// Create and open a file atomically.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.create`)
    ///
    /// Atomically creates and opens a new file. If the filesystem does not implement
    /// this, the kernel will fall back to `mknod` + `open`.
    ///
    /// This is preferred over mknod+open because it's atomic and avoids race conditions
    /// where another process could modify the file between creation and opening.
    ///
    /// Valid replies: `fuse_reply_create` (success) or `fuse_reply_err` (failure).
    ///
    /// # Implementation Notes
    ///
    /// - Creates a WriteBuffer marked dirty (ensures file is written even if empty)
    /// - Allocates inode via `get_or_insert` (increments nlookup, correct per spec)
    /// - Invalidates parent's negative cache and dir listing cache
    fn create(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let _namespace = self.handle_table.namespace.lock();
        let parent = parent.0;
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        trace!(parent = parent, name = name_str, "create");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let Some(dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            return;
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        #[cfg(target_os = "macos")]
        let _resource_guard = name_str
            .starts_with("._")
            .then(|| self.resource_lock.lock());

        // Check if entry already exists (file, directory, or symlink)
        // This is needed because macOS FUSE doesn't always call lookup before create
        let child_path = parent_path.join(name_str);
        if self.inodes.get_inode(&child_path).is_some() {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EEXIST));
            return;
        }

        // Also check in the vault in case inode table is stale
        let ops = self.ops_clone();
        let dir_id_check = dir_id.clone();
        let name_check = name_str.to_string();
        let exists = match self.exec(async move {
            tokio::join!(
                ops.find_file(&dir_id_check, &name_check),
                ops.find_directory(&dir_id_check, &name_check),
                ops.find_symlink(&dir_id_check, &name_check)
            )
        }) {
            Ok((file_res, dir_res, sym_res)) => {
                matches!(file_res, Ok(Some(_)))
                    || matches!(dir_res, Ok(Some(_)))
                    || matches!(sym_res, Ok(Some(_)))
            }
            Err(_) => false, // On operation error, proceed and let vault handle it
        };

        if exists {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EEXIST));
            return;
        }

        // Create the file with a new WriteBuffer marked dirty
        // (File will be written to vault on release, even if empty)
        let ops = self.ops_clone();
        let directory = dir_id.clone();
        let filename = name_str.to_owned();
        let editor = match self.exec(async move {
            let editor =
                oxcrypt_mount::EditBuffer::open(&ops, directory, filename, true, true).await?;
            editor.commit(&ops).await?;
            Ok::<_, oxcrypt_core::error::VaultWriteError>(editor)
        }) {
            Ok(Ok(editor)) => Arc::new(editor),
            Ok(Err(error)) => {
                reply.error(fuser::Errno::from_i32(crate::error::write_error_to_errno(
                    &error,
                )));
                return;
            }
            Err(error) => {
                reply.error(fuser::Errno::from_i32(error.to_errno()));
                return;
            }
        };
        let fh = self.handle_table.insert_auto(FuseHandle::Editor {
            buffer: Arc::clone(&editor),
            writable: true,
        });

        // Allocate inode
        let inode = self.inodes.get_or_insert(
            &child_path,
            &InodeKind::File {
                dir_id: dir_id.clone(),
                name: name_str.to_string(),
            },
        );

        self.handle_table
            .editors
            .insert(inode, Arc::downgrade(&editor));
        self.open_handle_tracker.add_handle(inode);

        // Just created, so mtime = now is correct
        let attr = self.make_file_attr(inode, 0, None);
        self.attr_cache.insert(inode, attr);

        // Invalidate parent's negative cache and dir cache
        self.attr_cache.remove_negative(parent, name_str);
        self.dir_cache.invalidate(parent);

        self.vault_stats.record_metadata_latency(start.elapsed());
        reply.created(
            &DEFAULT_ATTR_TTL,
            &attr,
            fuser::Generation(0),
            fuser::FileHandle(fh),
            fuser::FopenFlags::empty(),
        );
    }

    fn write(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        let offset = offset.cast_signed();
        trace!(
            inode = ino,
            fh = fh,
            offset = offset,
            size = data.len(),
            "write"
        );

        // Get the handle from our table
        let Some(mut handle) = self.handle_table.get_mut(&fh) else {
            reply.error(fuser::Errno::from_i32(libc::EBADF));
            return;
        };

        if let Some((editor, writable)) = handle.editor() {
            drop(handle);
            if !writable {
                reply.error(fuser::Errno::from_i32(libc::EBADF));
                return;
            }
            match editor.write(u64::try_from(offset).unwrap_or(u64::MAX), data) {
                Ok(written) => {
                    self.set_buffer_size(ino, editor.len());
                    self.attr_cache.invalidate(ino);
                    self.vault_stats.record_write(written as u64);
                    reply.written(u32::try_from(written).unwrap_or(u32::MAX));
                }
                Err(error) => reply.error(fuser::Errno::from_i32(
                    error.raw_os_error().unwrap_or(libc::EIO),
                )),
            }
            return;
        }

        let Some(_buffer) = handle.as_write_buffer_mut() else {
            // Trying to write to a read-only handle
            reply.error(fuser::Errno::from_i32(libc::EBADF));
            return;
        };

        // Check write budget before proceeding
        // This prevents unbounded dirty data accumulation under slow backends
        if let Some(ref scheduler) = self.scheduler {
            let write_size = data.len() as u64;
            if scheduler.check_write_budget(ino, write_size).is_err() {
                // Budget exceeded - auto-flush to release budget before rejecting
                debug!(
                    ino,
                    write_size, "Write budget exceeded, auto-flushing to release budget"
                );
                drop(handle); // Release lock before flushing

                // Flush the buffer to disk - this releases the write budget
                match self.flush_handle(ino, fh) {
                    Ok(_) => {
                        // Flush succeeded, budget released. Re-acquire handle and continue.
                        debug!(ino, "Auto-flush succeeded, continuing write");
                    }
                    Err(errno) => {
                        // Flush failed - can't continue with write
                        warn!(ino, errno, "Auto-flush failed during write budget recovery");
                        reply.error(fuser::Errno::from_i32(errno));
                        return;
                    }
                }

                // Re-acquire handle after flush
                let Some(reacquired) = self.handle_table.get_mut(&fh) else {
                    reply.error(fuser::Errno::from_i32(libc::EBADF));
                    return;
                };
                handle = reacquired;

                // Re-check that we still have a write buffer
                if handle.as_write_buffer_mut().is_none() {
                    reply.error(fuser::Errno::from_i32(libc::EBADF));
                    return;
                }
            }
        }

        // Re-get buffer reference (may have been invalidated by auto-flush path)
        let Some(buffer) = handle.as_write_buffer_mut() else {
            reply.error(fuser::Errno::from_i32(libc::EBADF));
            return;
        };

        // Track buffer size before write for delta calculation
        let old_size = buffer.len();

        // Write data at offset (WriteBuffer handles buffer expansion)
        self.vault_stats.start_write();
        // FUSE guarantees offset is non-negative (it's from kernel write requests)
        #[allow(clippy::cast_sign_loss)]
        let bytes_written = buffer.write(offset as u64, data);
        let new_size = buffer.len();
        self.vault_stats.finish_write();
        self.vault_stats.record_write(bytes_written as u64);
        self.vault_stats.record_encrypted(bytes_written as u64);

        // Track buffer size for mmap consistency (getattr must see current size)
        self.update_buffer_size(ino, new_size);

        // Track write bytes for budget enforcement
        // Only track the delta (new bytes added), not overwrites
        if let Some(ref scheduler) = self.scheduler
            && new_size > old_size
        {
            scheduler.add_write_bytes(ino, new_size - old_size);
        }

        // Invalidate attr cache for this inode (will be recalculated with effective_file_size)
        self.attr_cache.invalidate(ino);
        // Invalidate read cache for this inode (global cache)
        if let Some(ref scheduler) = self.scheduler {
            scheduler.invalidate_read_cache_inode(ino);
        }
        // bytes_written is from buffer.write() which returns amount written (limited by data.len())
        // data.len() is u32 from FUSE API, so bytes_written will fit in u32
        #[allow(clippy::cast_possible_truncation)]
        reply.written(bytes_written as u32);
    }

    /// mknod - Create file node (debug implementation)
    ///
    /// This is called when the kernel can't use create() for some reason.
    /// Adding this to debug if macOS is using mknod instead of create.
    fn mknod(
        &self,
        _req: &fuser::Request,
        _parent: fuser::INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        // mknod is not used for regular files when create() is implemented
        // Returning ENOSYS causes the kernel to fall back to create() for regular files
        reply.error(fuser::Errno::from_i32(libc::ENOSYS));
    }

    fn mkdir(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent = parent.0;
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        trace!(parent = parent, name = name_str, "mkdir");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let Some(parent_dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            return;
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Check if entry already exists (file, directory, or symlink)
        // This is needed because macOS FUSE doesn't always call lookup before mkdir
        let child_path = parent_path.join(name_str);
        if self.inodes.get_inode(&child_path).is_some() {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EEXIST));
            return;
        }

        // Also check in the vault in case inode table is stale
        let ops = self.ops_clone();
        let dir_id_check = parent_dir_id.clone();
        let name_check = name_str.to_string();
        let exists = match self.exec(async move {
            tokio::join!(
                ops.find_file(&dir_id_check, &name_check),
                ops.find_directory(&dir_id_check, &name_check),
                ops.find_symlink(&dir_id_check, &name_check)
            )
        }) {
            Ok((file_res, dir_res, sym_res)) => {
                matches!(file_res, Ok(Some(_)))
                    || matches!(dir_res, Ok(Some(_)))
                    || matches!(sym_res, Ok(Some(_)))
            }
            Err(_) => false, // On operation error, proceed and let vault handle it
        };

        if exists {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EEXIST));
            return;
        }

        let ops = self.ops_clone();
        let parent_dir_id_clone = parent_dir_id.clone();
        let name_owned = name_str.to_string();

        // Create directory
        match self.exec(async move {
            ops.create_directory(&parent_dir_id_clone, &name_owned)
                .await
        }) {
            Ok(Ok(new_dir_id)) => {
                // Allocate inode
                let child_path = parent_path.join(name_str);
                let inode = self.inodes.get_or_insert(
                    &child_path,
                    &InodeKind::Directory {
                        dir_id: new_dir_id.clone(),
                    },
                );

                // DEBUG: Track inode allocation and vault UUID
                tracing::info!(
                    "mkdir: allocated inode={} with dir_id={} for path={}",
                    inode,
                    new_dir_id,
                    child_path
                );

                // Just created, so mtime = now is correct
                let attr = self.make_dir_attr(inode, None);
                self.attr_cache.insert(inode, attr);

                // Invalidate parent caches
                self.attr_cache.remove_negative(parent, name_str);
                self.dir_cache.invalidate(parent);

                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.entry(&DEFAULT_ATTR_TTL, &attr, fuser::Generation(0));
            }
            Ok(Err(e)) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(fuser::Errno::from_i32(crate::error::write_error_to_errno(
                    &e,
                )));
            }
            Err(exec_err) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
            }
        }
    }

    /// Remove a file or symlink.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.unlink`)
    ///
    /// Removes a file. If the inode's lookup count is nonzero, the filesystem should
    /// defer actual inode removal until the count reaches zero (via `forget`).
    ///
    /// Valid reply: `fuse_reply_err` (0 for success).
    ///
    /// # Implementation Notes
    ///
    /// - Tries to delete as file first, then as symlink
    /// - Invalidates path mapping (but inode entry remains until `forget`)
    /// - Invalidates parent's directory cache
    fn unlink(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
        let _namespace = self.handle_table.namespace.lock();
        let parent = parent.0;
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        trace!(parent = parent, name = name_str, "unlink");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let Some(dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            return;
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Get the child's inode to check for open handles (POSIX compliance)
        let child_path = parent_path.join(name_str);
        let child_inode = self.inodes.get_inode(&child_path);

        // Check if file has open handles - if so, defer deletion
        if let Some(ino) = child_inode
            && self.open_handle_tracker.has_open_handles(ino)
            && self
                .handle_table
                .editors
                .get(&ino)
                .and_then(|entry| entry.value().upgrade())
                .is_none()
        {
            // POSIX: unlink removes directory entry immediately but defers file deletion
            self.open_handle_tracker
                .mark_for_deletion(ino, dir_id.clone(), name_str.to_string());
            // Invalidate directory cache (file disappears from directory listings)
            // but KEEP the inode path mapping so lookup can find it and return ENOENT
            self.dir_cache.invalidate(parent);

            // Notify kernel to invalidate its dcache entry for this file
            // This forces the kernel to call lookup() again, which will return ENOENT
            let entry_name = name.to_os_string();
            self.notify_detached(move |notifier| {
                if let Err(e) = notifier.inval_entry(fuser::INodeNo(parent), &entry_name) {
                    trace!("Failed to notify kernel of deferred deletion: {e}");
                }
            });

            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.ok();
            return;
        }

        let ops = self.ops_clone();
        let dir_id_file = dir_id.clone();
        let name_file = name_str.to_string();

        // No open handles - proceed with actual deletion
        // Try to delete as file first
        match self.exec(async move { ops.delete_file(&dir_id_file, &name_file).await }) {
            Ok(Ok(())) => {
                self.handle_table.detach_writers(&dir_id, name_str);
                // Invalidate caches
                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                self.vault_stats.record_metadata_latency(start.elapsed());

                // Notify kernel of deletion (file deletion)
                if let Some(ino) = child_inode {
                    let entry_name = name.to_os_string();
                    self.notify_detached(move |notifier| {
                        if let Err(e) = notifier.delete(
                            fuser::INodeNo(parent),
                            fuser::INodeNo(ino),
                            &entry_name,
                        ) {
                            trace!("Failed to notify kernel of deletion (file): {e}");
                        }
                    });
                }

                reply.ok();
            }
            Ok(Err(_)) | Err(_) => {
                // Try as symlink
                let ops = self.ops_clone();
                let dir_id_symlink = dir_id.clone();
                let name_symlink = name_str.to_string();

                match self
                    .exec(async move { ops.delete_symlink(&dir_id_symlink, &name_symlink).await })
                {
                    Ok(Ok(())) => {
                        self.inodes.invalidate_path(&child_path);
                        self.dir_cache.invalidate(parent);
                        self.vault_stats.record_metadata_latency(start.elapsed());

                        // Notify kernel of deletion (symlink deletion)
                        if let Some(ino) = child_inode {
                            let entry_name = name.to_os_string();
                            self.notify_detached(move |notifier| {
                                if let Err(e) = notifier.delete(
                                    fuser::INodeNo(parent),
                                    fuser::INodeNo(ino),
                                    &entry_name,
                                ) {
                                    trace!("Failed to notify kernel of deletion (symlink): {e}");
                                }
                            });
                        }

                        reply.ok();
                    }
                    Ok(Err(e)) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(crate::error::write_error_to_errno(
                            &e,
                        )));
                    }
                    Err(exec_err) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                    }
                }
            }
        }
    }

    /// Remove a directory.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.rmdir`)
    ///
    /// Removes an empty directory. If the inode's lookup count is nonzero, the
    /// filesystem should defer actual inode removal until the count reaches zero.
    ///
    /// Valid reply: `fuse_reply_err` (0 for success, ENOTEMPTY if not empty).
    ///
    /// # Implementation Notes
    ///
    /// - Preserves all directory entries, including AppleDouble metadata, on failure
    /// - Delegates to vault's `delete_directory` which checks for empty
    /// - Invalidates path mapping and parent's directory cache
    fn rmdir(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
        let parent = parent.0;
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        trace!(parent = parent, name = name_str, "rmdir");

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let Some(parent_dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            return;
        };
        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // AppleDouble files contain user metadata. Like all directory entries,
        // they must be removed explicitly before rmdir can succeed.

        let ops = self.ops_clone();
        let parent_dir_id_clone = parent_dir_id.clone();
        let name_owned = name_str.to_string();

        // Delete directory
        match self.exec(async move {
            ops.delete_directory(&parent_dir_id_clone, &name_owned)
                .await
        }) {
            Ok(Ok(())) => {
                // Invalidate caches
                let child_path = parent_path.join(name_str);

                // Get child inode before invalidating path
                let child_inode = self.inodes.get_inode(&child_path);

                // DEBUG: Track inode invalidation
                if let Some(ino) = child_inode
                    && let Some(entry) = self.inodes.get(ino)
                {
                    tracing::info!(
                        "rmdir: invalidating inode={} with dir_id={:?} for path={}",
                        ino,
                        entry.dir_id(),
                        child_path
                    );
                }

                self.inodes.invalidate_path(&child_path);
                self.dir_cache.invalidate(parent);
                self.vault_stats.record_metadata_latency(start.elapsed());

                // Notify kernel of deletion to evict from dcache
                // This prevents kernel from caching stale inode numbers across iterations
                if let Some(ino) = child_inode {
                    let entry_name = name.to_os_string();
                    self.notify_detached(move |notifier| {
                        if let Err(e) = notifier.delete(
                            fuser::INodeNo(parent),
                            fuser::INodeNo(ino),
                            &entry_name,
                        ) {
                            trace!("Failed to notify kernel of directory deletion: {e}");
                        }
                    });
                }

                reply.ok();
            }
            Ok(Err(e)) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(fuser::Errno::from_i32(crate::error::write_error_to_errno(
                    &e,
                )));
            }
            Err(exec_err) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
            }
        }
    }

    fn symlink(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let parent = parent.0;
        let Some(name_str) = link_name.to_str() else {
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        let Some(target_str) = target.to_str() else {
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        trace!(
            parent = parent,
            name = name_str,
            target = target_str,
            "symlink"
        );

        // Get parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            // DEBUG: Track failed parent lookup
            tracing::error!(
                "symlink: parent inode={} NOT FOUND in InodeTable (kernel passed stale inode?)",
                parent
            );
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let Some(dir_id) = parent_entry.dir_id() else {
            reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            return;
        };

        // DEBUG: Track parent lookup and vault UUID extraction
        tracing::info!(
            "symlink: parent inode={} found, dir_id={}, path={}",
            parent,
            dir_id,
            parent_entry.path
        );

        let parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Check if entry already exists (file, directory, or symlink)
        // This is needed because macOS FUSE doesn't always call lookup before symlink
        let child_path = parent_path.join(name_str);
        if self.inodes.get_inode(&child_path).is_some() {
            reply.error(fuser::Errno::from_i32(libc::EEXIST));
            return;
        }

        // Also check in the vault in case inode table is stale
        let ops = self.ops_clone();
        let dir_id_check = dir_id.clone();
        let name_check = name_str.to_string();
        let exists = match self.exec(async move {
            tokio::join!(
                ops.find_file(&dir_id_check, &name_check),
                ops.find_directory(&dir_id_check, &name_check),
                ops.find_symlink(&dir_id_check, &name_check)
            )
        }) {
            Ok((file_res, dir_res, sym_res)) => {
                matches!(file_res, Ok(Some(_)))
                    || matches!(dir_res, Ok(Some(_)))
                    || matches!(sym_res, Ok(Some(_)))
            }
            Err(_) => false, // On operation error, proceed and let vault handle it
        };

        if exists {
            reply.error(fuser::Errno::from_i32(libc::EEXIST));
            return;
        }

        let ops = self.ops_clone();
        let dir_id_clone = dir_id.clone();
        let name_owned = name_str.to_string();
        let target_owned = target_str.to_string();

        // Create symlink
        match self.exec(async move {
            ops.create_symlink(&dir_id_clone, &name_owned, &target_owned)
                .await
        }) {
            Ok(Ok(())) => {
                // Allocate inode
                let child_path = parent_path.join(name_str);
                let inode = self.inodes.get_or_insert(
                    &child_path,
                    &InodeKind::Symlink {
                        dir_id: dir_id.clone(),
                        name: name_str.to_string(),
                    },
                );

                // Just created, so mtime = now is correct
                let attr = self.make_symlink_attr(inode, target_str.len() as u64, None);
                self.attr_cache.insert(inode, attr);

                // Invalidate parent caches
                self.attr_cache.remove_negative(parent, name_str);
                self.dir_cache.invalidate(parent);

                reply.entry(&DEFAULT_ATTR_TTL, &attr, fuser::Generation(0));
            }
            Ok(Err(e)) => {
                reply.error(fuser::Errno::from_i32(crate::error::write_error_to_errno(
                    &e,
                )));
            }
            Err(exec_err) => {
                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
            }
        }
    }

    /// Create a hard link (not supported).
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.link`)
    ///
    /// Creates a hard link from `newparent/newname` pointing to the existing inode `ino`.
    /// The target inode's link count should be incremented on success.
    ///
    /// # Implementation
    ///
    /// Cryptomator Vault Format 8 does not support hard links - each file has exactly one
    /// encrypted representation in the vault. Hardlinks are typically used for:
    /// - Space optimization (multiple names pointing to same data)
    /// - Atomic file replacement (link then unlink pattern)
    ///
    /// Applications that use hardlinks (like git's object database) gracefully fall back
    /// to file copies when link() returns ENOSYS. This is expected behavior and not an error.
    ///
    /// **Returns**: ENOSYS (function not implemented) without logging, since this is
    /// expected and applications handle it gracefully.
    fn link(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        _newparent: fuser::INodeNo,
        _newname: &OsStr,
        reply: ReplyEntry,
    ) {
        // Silently return ENOSYS - hardlinks not supported by Cryptomator format.
        // No trace/warn logging since this is expected (git operations frequently try
        // to use hardlinks as an optimization, then fall back to copying).
        reply.error(fuser::Errno::from_i32(libc::ENOSYS));
    }

    /// Rename a file or directory.
    ///
    /// # FUSE Spec (libfuse `fuse_lowlevel_ops.rename`)
    ///
    /// Atomically renames a file/directory from `name` in `parent` to `newname` in
    /// `newparent`. If the target exists, it should be atomically replaced.
    ///
    /// The `flags` parameter supports:
    /// - `RENAME_NOREPLACE` (1): Fail with EEXIST if target already exists
    /// - `RENAME_EXCHANGE` (2): Atomically exchange source and target (both must exist)
    ///
    /// Both flags are honoured on Linux, which is the only platform whose kernel
    /// sends them. Elsewhere the parameter is always empty and a rename replaces
    /// an existing target, as POSIX requires.
    // The flags parameter is only inspected on Linux (RENAME_EXCHANGE /
    // RENAME_NOREPLACE); the underscore keeps macOS builds warning-free.
    #[allow(clippy::used_underscore_binding)]
    fn rename(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &OsStr,
        newparent: fuser::INodeNo,
        newname: &OsStr,
        _flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let _namespace = self.handle_table.namespace.lock();
        let parent = parent.0;
        let newparent = newparent.0;
        let start = Instant::now();
        self.vault_stats.record_metadata_op();

        let Some(name_str) = name.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        let Some(newname_str) = newname.to_str() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };

        trace!(
            parent = parent,
            name = name_str,
            newparent = newparent,
            newname = newname_str,
            "rename"
        );

        // Get source parent directory
        let Some(parent_entry) = self.inodes.get(parent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let Some(src_dir_id) = parent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            return;
        };
        let src_parent_path = parent_entry.path.clone();
        drop(parent_entry);

        // Get destination parent directory
        let Some(newparent_entry) = self.inodes.get(newparent) else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let Some(dest_dir_id) = newparent_entry.dir_id() else {
            self.vault_stats.record_error();
            self.vault_stats.record_metadata_latency(start.elapsed());
            reply.error(fuser::Errno::from_i32(libc::ENOTDIR));
            return;
        };
        let dest_parent_path = newparent_entry.path.clone();
        drop(newparent_entry);

        if parent == newparent && name_str == newname_str {
            reply.ok();
            return;
        }
        // Persist newly created files before moving their backing entry. The
        // namespace guard prevents a concurrent commit from using the old name.
        let src_inode = self
            .inodes
            .get_inode(&src_parent_path.join(name_str))
            .unwrap_or(0);
        for fh in self.handle_table.writer_handles(&src_dir_id, name_str) {
            if let Err(errno) = self.flush_handle_unlocked(src_inode, fh) {
                reply.error(fuser::Errno::from_i32(errno));
                return;
            }
        }

        // Handle rename flags
        #[cfg(target_os = "linux")]
        {
            // RENAME_EXCHANGE: atomic swap of source and target
            if _flags.contains(fuser::RenameFlags::RENAME_EXCHANGE) {
                trace!("rename: handling RENAME_EXCHANGE");

                // Build paths for both entries
                let src_path = src_parent_path.join(name_str);
                let dest_path = dest_parent_path.join(newname_str);

                // Look up both inodes - both must exist for exchange
                let Some(src_inode) = self.inodes.get_inode(&src_path) else {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(fuser::Errno::from_i32(libc::ENOENT));
                    return;
                };

                let Some(dest_inode) = self.inodes.get_inode(&dest_path) else {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(fuser::Errno::from_i32(libc::ENOENT));
                    return;
                };

                // Get entry kinds
                let Some(src_entry) = self.inodes.get(src_inode) else {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(fuser::Errno::from_i32(libc::ENOENT));
                    return;
                };
                let src_is_dir = src_entry.kind.is_directory();
                let src_is_file = src_entry.kind.is_file();
                drop(src_entry);

                let Some(dest_entry) = self.inodes.get(dest_inode) else {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(fuser::Errno::from_i32(libc::ENOENT));
                    return;
                };
                let dest_is_dir = dest_entry.kind.is_directory();
                drop(dest_entry);

                // Both must be same type (file/file or dir/dir)
                if src_is_dir != dest_is_dir {
                    debug!(
                        "rename: RENAME_EXCHANGE type mismatch (src_is_dir={}, dest_is_dir={})",
                        src_is_dir, dest_is_dir
                    );
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(fuser::Errno::from_i32(libc::EINVAL));
                    return;
                }

                // Perform the swap
                let result = if src_is_file {
                    // File swap - can be cross-directory
                    let ops = self.ops_clone();
                    let src_dir = src_dir_id.clone();
                    let dest_dir = dest_dir_id.clone();
                    let name_a = name_str.to_string();
                    let name_b = newname_str.to_string();

                    self.exec(async move {
                        ops.atomic_swap_files(&src_dir, &name_a, &dest_dir, &name_b)
                            .await
                    })
                } else if src_is_dir {
                    // Directory swap - must be same parent
                    if parent != newparent {
                        debug!("rename: RENAME_EXCHANGE cross-directory dir swap not supported");
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(libc::EXDEV));
                        return;
                    }

                    let ops = self.ops_clone();
                    let parent_dir = src_dir_id.clone();
                    let name_a = name_str.to_string();
                    let name_b = newname_str.to_string();

                    self.exec(async move {
                        ops.atomic_swap_directories(&parent_dir, &name_a, &name_b)
                            .await
                    })
                } else {
                    // Symlink - treat like file swap
                    let ops = self.ops_clone();
                    let src_dir = src_dir_id.clone();
                    let dest_dir = dest_dir_id.clone();
                    let name_a = name_str.to_string();
                    let name_b = newname_str.to_string();

                    self.exec(async move {
                        ops.atomic_swap_files(&src_dir, &name_a, &dest_dir, &name_b)
                            .await
                    })
                };

                match result {
                    Ok(Ok(())) => {
                        self.handle_table.exchange_writers(
                            &src_dir_id,
                            name_str,
                            &dest_dir_id,
                            newname_str,
                        );
                        // Update inode mappings - swap the paths
                        self.inodes
                            .swap_paths(src_inode, dest_inode, &src_path, &dest_path);

                        // Also swap the InodeKind entries - each inode now has the other's name/location
                        // src_inode was at (src_dir_id, name_str), now at (dest_dir_id, newname_str)
                        // dest_inode was at (dest_dir_id, newname_str), now at (src_dir_id, name_str)
                        if src_is_file {
                            self.inodes.update_kind(
                                src_inode,
                                InodeKind::File {
                                    dir_id: dest_dir_id.clone(),
                                    name: newname_str.to_string(),
                                },
                            );
                            self.inodes.update_kind(
                                dest_inode,
                                InodeKind::File {
                                    dir_id: src_dir_id.clone(),
                                    name: name_str.to_string(),
                                },
                            );
                        } else if src_is_dir {
                            // For directories, the dir_id (the directory's own ID) doesn't change,
                            // only the path. The swap_paths already handled path updates.
                            // InodeKind::Directory { dir_id } stays the same for each.
                        } else {
                            // Symlinks
                            self.inodes.update_kind(
                                src_inode,
                                InodeKind::Symlink {
                                    dir_id: dest_dir_id.clone(),
                                    name: newname_str.to_string(),
                                },
                            );
                            self.inodes.update_kind(
                                dest_inode,
                                InodeKind::Symlink {
                                    dir_id: src_dir_id.clone(),
                                    name: name_str.to_string(),
                                },
                            );
                        }

                        // Invalidate attribute caches for both inodes
                        self.attr_cache.invalidate(src_inode);
                        self.attr_cache.invalidate(dest_inode);

                        // Invalidate directory caches for both parents
                        self.dir_cache.invalidate(parent);
                        if parent != newparent {
                            self.dir_cache.invalidate(newparent);
                        }

                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.ok();
                    }
                    Ok(Err(e)) => {
                        error!("rename: RENAME_EXCHANGE failed: {}", e);
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(crate::error::write_error_to_errno(
                            &e,
                        )));
                    }
                    Err(exec_err) => {
                        error!("rename: RENAME_EXCHANGE exec error: {:?}", exec_err);
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                    }
                }
                return;
            }

            // RENAME_NOREPLACE: fail if target exists (check file, dir, and symlink)
            if _flags.contains(fuser::RenameFlags::RENAME_NOREPLACE) {
                // Use O(1) lookups to check if target exists as file, directory, or symlink
                let ops_file = self.ops_clone();
                let dest_dir_id_file = dest_dir_id.clone();
                let newname_file = newname_str.to_string();

                let target_exists = match self
                    .exec(async move { ops_file.find_file(&dest_dir_id_file, &newname_file).await })
                {
                    Ok(Ok(Some(_))) => true,
                    Ok(Ok(None)) => {
                        let ops_dir = self.ops_clone();
                        let dest_dir_id_dir = dest_dir_id.clone();
                        let newname_dir = newname_str.to_string();
                        match self.exec(async move {
                            ops_dir.find_directory(&dest_dir_id_dir, &newname_dir).await
                        }) {
                            Ok(Ok(Some(_))) => true,
                            Ok(Ok(None)) => {
                                let ops_sym = self.ops_clone();
                                let dest_dir_id_sym = dest_dir_id.clone();
                                let newname_sym = newname_str.to_string();
                                match self.exec(async move {
                                    ops_sym.find_symlink(&dest_dir_id_sym, &newname_sym).await
                                }) {
                                    Ok(Ok(Some(_))) => true,
                                    Ok(Ok(None)) => false,
                                    Ok(Err(e)) => {
                                        self.vault_stats.record_error();
                                        self.vault_stats.record_metadata_latency(start.elapsed());
                                        reply.error(fuser::Errno::from_i32(e.to_errno()));
                                        return;
                                    }
                                    Err(exec_err) => {
                                        self.vault_stats.record_error();
                                        self.vault_stats.record_metadata_latency(start.elapsed());
                                        reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                                        return;
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(fuser::Errno::from_i32(e.to_errno()));
                                return;
                            }
                            Err(exec_err) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                                return;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(e.to_errno()));
                        return;
                    }
                    Err(exec_err) => {
                        self.vault_stats.record_error();
                        self.vault_stats.record_metadata_latency(start.elapsed());
                        reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                        return;
                    }
                };

                if target_exists {
                    self.vault_stats.record_error();
                    self.vault_stats.record_metadata_latency(start.elapsed());
                    reply.error(fuser::Errno::from_i32(libc::EEXIST));
                    return;
                }
            }
        }

        // Step 1: Determine source entry type (file, directory, or symlink)
        #[derive(Debug, Clone, Copy, PartialEq)]
        enum SourceType {
            File,
            Directory,
            Symlink,
        }

        // First try cached inode lookup for entry type
        let source_type = {
            let src_path = src_parent_path.join(name_str);
            if let Some(inode) = self.inodes.get_inode(&src_path) {
                if let Some(entry) = self.inodes.get(inode) {
                    if entry.kind.is_directory() {
                        Some(SourceType::Directory)
                    } else if entry.kind.is_symlink() {
                        Some(SourceType::Symlink)
                    } else {
                        Some(SourceType::File)
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Fallback to vault ops if not in cache
        let source_type = match source_type {
            Some(t) => t,
            None => {
                // Check if it's a file
                let ops_f = self.ops_clone();
                let src_dir_f = src_dir_id.clone();
                let name_f = name_str.to_string();
                let is_file =
                    match self.exec(async move { ops_f.find_file(&src_dir_f, &name_f).await }) {
                        Ok(Ok(Some(_))) => true,
                        Ok(Ok(None)) => false,
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(e.to_errno()));
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                            return;
                        }
                    };

                if is_file {
                    SourceType::File
                } else {
                    // Check if it's a directory
                    let ops_d = self.ops_clone();
                    let src_dir_d = src_dir_id.clone();
                    let name_d = name_str.to_string();
                    let is_dir = match self
                        .exec(async move { ops_d.find_directory(&src_dir_d, &name_d).await })
                    {
                        Ok(Ok(Some(_))) => true,
                        Ok(Ok(None)) => false,
                        Ok(Err(e)) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(e.to_errno()));
                            return;
                        }
                        Err(exec_err) => {
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                            return;
                        }
                    };

                    if is_dir {
                        SourceType::Directory
                    } else {
                        // Check if it's a symlink
                        let ops_s = self.ops_clone();
                        let src_dir_s = src_dir_id.clone();
                        let name_s = name_str.to_string();
                        let is_sym = match self
                            .exec(async move { ops_s.find_symlink(&src_dir_s, &name_s).await })
                        {
                            Ok(Ok(Some(_))) => true,
                            Ok(Ok(None)) => false,
                            Ok(Err(e)) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(fuser::Errno::from_i32(e.to_errno()));
                                return;
                            }
                            Err(exec_err) => {
                                self.vault_stats.record_error();
                                self.vault_stats.record_metadata_latency(start.elapsed());
                                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                                return;
                            }
                        };

                        if is_sym {
                            SourceType::Symlink
                        } else {
                            // Source doesn't exist
                            self.vault_stats.record_error();
                            self.vault_stats.record_metadata_latency(start.elapsed());
                            reply.error(fuser::Errno::from_i32(libc::ENOENT));
                            return;
                        }
                    }
                }
            }
        };

        trace!("rename: source type = {:?}", source_type);

        let overwritten_path = dest_parent_path.join(newname_str);
        let overwritten_inode = self.inodes.get_inode(&overwritten_path);
        let ops = self.ops_clone();
        let src = src_dir_id.clone();
        let dest = dest_dir_id.clone();
        let name_owned = name_str.to_owned();
        let newname_owned = newname_str.to_owned();
        let result = self.exec(async move {
            ops.rename_entry_atomic(&src, &name_owned, &dest, &newname_owned)
                .await
        });

        match result {
            Ok(Ok(())) => {
                self.handle_table.detach_writers(&dest_dir_id, newname_str);
                if let Some(inode) = overwritten_inode {
                    self.inodes.invalidate_path(&overwritten_path);
                    self.attr_cache.invalidate(inode);
                }
                self.handle_table.relocate_writers(
                    &src_dir_id,
                    name_str,
                    &dest_dir_id,
                    newname_str,
                );
                // Update inode mapping
                let old_path = src_parent_path.join(name_str);
                let new_path = dest_parent_path.join(newname_str);

                if let Some(inode) = self.inodes.get_inode(&old_path) {
                    self.inodes.update_path(inode, &old_path, new_path);

                    // Also update the InodeKind with the new name and parent dir_id
                    // This is critical: InodeKind::File/Symlink stores the name used for vault lookups
                    let new_kind = match source_type {
                        SourceType::File => InodeKind::File {
                            dir_id: dest_dir_id.clone(),
                            name: newname_str.to_string(),
                        },
                        SourceType::Directory => {
                            // For directories, we need to preserve the original dir_id
                            // (the directory's own ID doesn't change on rename)
                            if let Some(entry) = self.inodes.get(inode) {
                                if let Some(original_dir_id) = entry.dir_id() {
                                    InodeKind::Directory {
                                        dir_id: original_dir_id,
                                    }
                                } else {
                                    // Shouldn't happen - directory should have dir_id
                                    InodeKind::Directory {
                                        dir_id: DirId::root(),
                                    }
                                }
                            } else {
                                InodeKind::Directory {
                                    dir_id: DirId::root(),
                                }
                            }
                        }
                        SourceType::Symlink => InodeKind::Symlink {
                            dir_id: dest_dir_id.clone(),
                            name: newname_str.to_string(),
                        },
                    };
                    self.inodes.update_kind(inode, new_kind);

                    self.attr_cache.invalidate(inode);
                }

                // Invalidate caches
                self.dir_cache.invalidate(parent);
                if parent != newparent {
                    self.dir_cache.invalidate(newparent);
                }

                // Invalidate negative cache for the new name (it now exists)
                self.attr_cache.remove_negative(newparent, newname_str);

                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.ok();
            }
            Ok(Err(e)) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(fuser::Errno::from_i32(crate::error::write_error_to_errno(
                    &e,
                )));
            }
            Err(exec_err) => {
                self.vault_stats.record_error();
                self.vault_stats.record_metadata_latency(start.elapsed());
                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
            }
        }
    }

    fn fallocate(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        let offset = offset.cast_signed();
        let length = length.cast_signed();
        trace!(
            inode = ino,
            fh = fh,
            offset = offset,
            length = length,
            mode = mode,
            "fallocate"
        );

        // Only support mode=0 (allocate space / extend file)
        // FALLOC_FL_PUNCH_HOLE and other modes are not supported
        // because Cryptomator doesn't support sparse files.
        if mode != 0 {
            reply.error(fuser::Errno::from_i32(libc::ENOTSUP));
            return;
        }

        // Get inode info
        let Some(entry) = self.inodes.get(ino) else {
            reply.error(fuser::Errno::from_i32(libc::ENOENT));
            return;
        };

        let (dir_id, name) = match &entry.kind {
            InodeKind::File { dir_id, name } => (dir_id.clone(), name.clone()),
            InodeKind::Directory { .. } | InodeKind::Root => {
                reply.error(fuser::Errno::from_i32(libc::EISDIR));
                return;
            }
            InodeKind::Symlink { .. } => {
                reply.error(fuser::Errno::from_i32(libc::EINVAL));
                return;
            }
        };
        drop(entry);

        let Some(new_size) = u64::try_from(offset).ok().and_then(|offset| {
            u64::try_from(length)
                .ok()
                .and_then(|length| offset.checked_add(length))
        }) else {
            reply.error(fuser::Errno::from_i32(libc::EFBIG));
            return;
        };
        let _namespace = self.handle_table.namespace.lock();
        let result = (|| {
            let editor = self.editor_for_inode(ino, dir_id, name)?;
            if new_size > editor.len() {
                editor
                    .truncate(new_size)
                    .map_err(|error| error.raw_os_error().unwrap_or(libc::EIO))?;
            }
            let size = editor.len();
            let ops = self.ops_clone();
            self.exec_with_timeout(async move { editor.commit(&ops).await }, self.write_timeout)
                .map_err(|error| error.to_errno())?
                .map_err(|error| crate::error::write_error_to_errno(&error))?;
            Ok::<u64, i32>(size)
        })();
        match result {
            Ok(size) => {
                self.set_buffer_size(ino, size);
                self.attr_cache.invalidate(ino);
                reply.ok();
            }
            Err(errno) => reply.error(fuser::Errno::from_i32(errno)),
        }
    }

    fn copy_file_range(
        &self,
        _req: &fuser::Request,
        ino_in: fuser::INodeNo,
        fh_in: fuser::FileHandle,
        offset_in: u64,
        ino_out: fuser::INodeNo,
        fh_out: fuser::FileHandle,
        offset_out: u64,
        len: u64,
        _flags: fuser::CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        let Some(input_end) = offset_in.checked_add(len) else {
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };
        let Some(output_end) = offset_out.checked_add(len) else {
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        };
        if ino_in == ino_out && offset_in < output_end && offset_out < input_end {
            reply.error(fuser::Errno::from_i32(libc::EINVAL));
            return;
        }
        let ino_in = ino_in.0;
        let fh_in = fh_in.0;
        let offset_in = offset_in.cast_signed();
        let ino_out = ino_out.0;
        let fh_out = fh_out.0;
        let offset_out = offset_out.cast_signed();
        trace!(
            ino_in = ino_in,
            ino_out = ino_out,
            offset_in = offset_in,
            offset_out = offset_out,
            len = len,
            "copy_file_range"
        );

        // Get source handle
        let Some(mut handle_in) = self.handle_table.get_mut(&fh_in) else {
            reply.error(fuser::Errno::from_i32(libc::EBADF));
            return;
        };

        match &mut *handle_in {
            FuseHandle::Editor { buffer, .. } => {
                let source = Arc::clone(buffer);
                drop(handle_in);
                let target = self
                    .handle_table
                    .get(&fh_out)
                    .and_then(|handle| handle.editor());
                let Some((target, true)) = target else {
                    reply.error(fuser::Errno::from_i32(libc::EBADF));
                    return;
                };
                let result = (|| {
                    let mut copied = 0u64;
                    let length = len.min(u64::from(u32::MAX));
                    while copied < length {
                        let data = source.read(
                            u64::try_from(offset_in)
                                .unwrap_or(u64::MAX)
                                .saturating_add(copied),
                            (length - copied).min(32768) as usize,
                        )?;
                        if data.is_empty() {
                            break;
                        }
                        target.write(
                            u64::try_from(offset_out)
                                .unwrap_or(u64::MAX)
                                .saturating_add(copied),
                            &data,
                        )?;
                        copied += data.len() as u64;
                    }
                    Ok::<_, std::io::Error>(copied)
                })();
                match result {
                    Ok(copied) => {
                        self.set_buffer_size(ino_out, target.len());
                        self.attr_cache.invalidate(ino_out);
                        reply.written(u32::try_from(copied).unwrap_or(u32::MAX));
                    }
                    Err(error) => reply.error(fuser::Errno::from_i32(
                        error.raw_os_error().unwrap_or(libc::EIO),
                    )),
                }
            }
            FuseHandle::Reader(_) => {
                // Async copy path: loan reader to scheduler, return immediately
                // Take the reader by replacing with ReaderLoaned placeholder
                let old_handle = std::mem::replace(&mut *handle_in, FuseHandle::ReaderLoaned);
                let FuseHandle::Reader(reader) = old_handle else {
                    unreachable!("just matched Reader variant")
                };

                // Drop the handle lock before enqueuing to avoid deadlock
                drop(handle_in);

                // Enqueue to scheduler - it will read, write to dest, and reply
                let scheduler = self.scheduler.as_ref().expect("scheduler not initialized");

                // FUSE guarantees offsets are non-negative
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let offset_in_u64 = offset_in as u64;
                #[allow(clippy::cast_sign_loss)]
                let offset_out_u64 = offset_out as u64;
                #[allow(clippy::cast_possible_truncation)]
                let len_usize = len as usize;

                match scheduler.try_enqueue_copy_range(
                    fh_in,
                    reader,
                    offset_in_u64,
                    fh_out,
                    ino_out,
                    offset_out_u64,
                    len_usize,
                    reply,
                ) {
                    Ok(request_id) => {
                        trace!(
                            ?request_id,
                            fh_in,
                            fh_out,
                            offset_in_u64,
                            offset_out_u64,
                            len_usize,
                            "copy_file_range enqueued to scheduler"
                        );
                        // Return immediately - scheduler will reply asynchronously
                    }
                    Err(e) => {
                        // Enqueue failed - scheduler already replied with error.
                        warn!(
                            error = %e,
                            fh_in,
                            fh_out,
                            "Failed to enqueue copy_file_range (scheduler replied with error)"
                        );
                    }
                }
            }
            FuseHandle::ReaderLoaned => {
                // Reader is busy with async operation - return EAGAIN
                trace!(
                    fh_in,
                    "copy_file_range while reader is loaned, returning EAGAIN"
                );
                reply.error(fuser::Errno::from_i32(libc::EAGAIN));
            }
            FuseHandle::ReadBuffer(content) => {
                // Synchronous path for in-memory buffers (fast)
                // FUSE guarantees offset_in is non-negative
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let offset = offset_in as usize;
                #[allow(clippy::cast_possible_truncation)]
                let end = std::cmp::min(offset + len as usize, content.len());
                let data = if offset < content.len() {
                    content[offset..end].to_vec()
                } else {
                    Vec::new()
                };
                drop(handle_in);
                self.copy_file_range_write_dest(ino_out, fh_out, offset_out, &data, reply);
            }
            FuseHandle::WriteBuffer(buffer) => {
                // Synchronous path for in-memory buffers (fast)
                // FUSE guarantees offset_in is non-negative
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let data = buffer.read(offset_in as u64, len as usize).to_vec();
                drop(handle_in);
                self.copy_file_range_write_dest(ino_out, fh_out, offset_out, &data, reply);
            }
        }
    }

    fn lseek(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        fh: fuser::FileHandle,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        let ino = ino.0;
        let fh = fh.0;
        trace!(
            inode = ino,
            fh = fh,
            offset = offset,
            whence = whence,
            "lseek"
        );

        // Get file size for SEEK_END calculations
        let file_size = {
            let Some(entry) = self.inodes.get(ino) else {
                reply.error(fuser::Errno::from_i32(libc::ENOENT));
                return;
            };

            match &entry.kind {
                InodeKind::File { dir_id, name } => {
                    let dir_id = dir_id.clone();
                    let name = name.clone();
                    drop(entry);

                    // Check if we have an open buffer with the size
                    if let Some(mut handle) = self.handle_table.get_mut(&fh) {
                        if let Some((editor, _)) = handle.editor() {
                            editor.len()
                        } else if let Some(buffer) = handle.as_write_buffer_mut() {
                            buffer.len()
                        } else if let Some(reader) = handle.as_reader_mut() {
                            // Get size from reader
                            reader.plaintext_size()
                        } else {
                            0
                        }
                    } else {
                        // Fall back to O(1) find_file lookup
                        let ops = self.ops_clone();

                        match self.exec(async move { ops.find_file(&dir_id, &name).await }) {
                            Ok(Ok(Some(file_info))) => {
                                encrypted_to_plaintext_size_or_zero(file_info.encrypted_size)
                            }
                            Ok(Ok(None)) => 0,
                            Ok(Err(e)) => {
                                reply.error(fuser::Errno::from_i32(
                                    crate::error::vault_error_to_errno(&e),
                                ));
                                return;
                            }
                            Err(exec_err) => {
                                reply.error(fuser::Errno::from_i32(exec_err.to_errno()));
                                return;
                            }
                        }
                    }
                }
                _ => {
                    reply.error(fuser::Errno::from_i32(libc::EINVAL));
                    return;
                }
            }
        };

        // SEEK_SET = 0, SEEK_CUR = 1, SEEK_END = 2, SEEK_DATA = 3, SEEK_HOLE = 4
        match whence {
            libc::SEEK_SET => {
                reply.offset(offset);
            }
            libc::SEEK_CUR => {
                // We don't track current position in FUSE - return offset as-is
                // (the kernel tracks the actual file position)
                reply.offset(offset);
            }
            libc::SEEK_END => {
                // File sizes in practice fit in i64; wrapping is extremely unlikely
                #[allow(clippy::cast_possible_wrap)]
                let new_offset = (file_size as i64) + offset;
                if new_offset < 0 {
                    reply.error(fuser::Errno::from_i32(libc::EINVAL));
                } else {
                    reply.offset(new_offset);
                }
            }
            libc::SEEK_DATA => {
                // Cryptomator doesn't support sparse files - entire file is data
                // FUSE guarantees offset is non-negative
                #[allow(clippy::cast_sign_loss)]
                if offset as u64 >= file_size {
                    reply.error(fuser::Errno::from_i32(libc::ENXIO));
                } else {
                    reply.offset(offset);
                }
            }
            libc::SEEK_HOLE => {
                // Cryptomator doesn't support sparse files - hole is at EOF
                // FUSE guarantees offset is non-negative
                #[allow(clippy::cast_sign_loss)]
                if offset as u64 >= file_size {
                    reply.error(fuser::Errno::from_i32(libc::ENXIO));
                } else {
                    // File sizes in practice fit in i64; wrapping is extremely unlikely
                    #[allow(clippy::cast_possible_wrap)]
                    reply.offset(file_size as i64);
                }
            }
            _ => {
                reply.error(fuser::Errno::from_i32(libc::EINVAL));
            }
        }
    }

    // ==================== Extended Attributes ====================
    //
    // Resource forks are handled natively using standard encrypted AppleDouble
    // entries. Other attributes use macFUSE sidecar fallback through ENOTSUP.

    fn getxattr(
        &self,
        req: &fuser::Request,
        ino: fuser::INodeNo,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        self.getxattr_with_position(req, ino, name, size, 0, reply);
    }

    #[allow(clippy::used_underscore_binding)]
    fn getxattr_with_position(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        _name: &OsStr,
        _size: u32,
        _position: u32,
        reply: fuser::ReplyXattr,
    ) {
        #[cfg(target_os = "macos")]
        if _name == OsStr::new("com.apple.ResourceFork") {
            let _guard = self.resource_lock.lock();
            let result = self
                .resource_sidecar(_ino.0, false)
                .and_then(|(_, _, _, data)| {
                    let resource = crate::resource_fork::resource(&data)?;
                    if resource.is_empty() {
                        return Err(libc::ENOATTR);
                    }
                    Ok(resource.to_vec())
                });
            trace!(inode = _ino.0, position = _position, size = _size, result = ?result.as_ref().map(Vec::len), "native resource read");
            match result {
                Ok(data) if _size == 0 => reply.size(u32::try_from(data.len()).unwrap_or(u32::MAX)),
                Ok(data) => {
                    let start = (_position as usize).min(data.len());
                    let end = start.saturating_add(_size as usize).min(data.len());
                    reply.data(&data[start..end]);
                }
                Err(error) => reply.error(fuser::Errno::from_i32(error)),
            }
            return;
        }
        reply.error(fuser::Errno::from_i32(libc::ENOTSUP));
    }

    #[allow(clippy::used_underscore_binding)]
    fn setxattr(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        _name: &OsStr,
        _value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        #[cfg(target_os = "macos")]
        if _name == OsStr::new("com.apple.ResourceFork") {
            match self.write_resource(_ino.0, _value, _flags, _position, false) {
                Ok(()) => reply.ok(),
                Err(error) => reply.error(fuser::Errno::from_i32(error)),
            }
            return;
        }
        reply.error(fuser::Errno::from_i32(libc::ENOTSUP));
    }

    fn listxattr(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        _size: u32,
        reply: fuser::ReplyXattr,
    ) {
        reply.error(fuser::Errno::from_i32(libc::ENOTSUP));
    }

    #[allow(clippy::used_underscore_binding)]
    fn removexattr(
        &self,
        _req: &fuser::Request,
        _ino: fuser::INodeNo,
        _name: &OsStr,
        reply: ReplyEmpty,
    ) {
        #[cfg(target_os = "macos")]
        if _name == OsStr::new("com.apple.ResourceFork") {
            match self.write_resource(_ino.0, &[], 0, 0, true) {
                Ok(()) => reply.ok(),
                Err(error) => reply.error(fuser::Errno::from_i32(error)),
            }
            return;
        }
        reply.error(fuser::Errno::from_i32(libc::ENOTSUP));
    }
}

#[cfg(test)]
mod tests {
    use crate::filesystem::*;

    #[test]
    fn modification_read_preserves_io_and_bridge_errors() {
        use oxcrypt_core::vault::operations::{VaultOpContext, VaultOperationError};
        for errno in [libc::EIO, libc::EACCES, libc::ENOENT] {
            let result = read_result::<Vec<u8>>(Ok(Err(VaultOperationError::Io {
                source: std::io::Error::from_raw_os_error(errno),
                context: VaultOpContext::new(),
            })));
            assert_eq!(result, Err(errno));
        }
        assert_eq!(
            read_result::<Vec<u8>>(Err(crate::async_bridge::BridgeError::Timeout(
                Duration::from_millis(1)
            ))),
            Err(libc::ETIMEDOUT)
        );
        assert_eq!(
            read_result::<Vec<u8>>(Err(crate::async_bridge::BridgeError::Cancelled)),
            Err(libc::ECANCELED)
        );
    }

    #[test]
    fn modification_read_rejects_corruption_without_changing_ciphertext() {
        use oxcrypt_mount::testing::TempVault;
        let vault = TempVault::new();
        let fs = CryptomatorFS::new(vault.path(), TempVault::password()).unwrap();
        let ops = fs.ops_clone();
        let path = fs
            .exec(async move {
                ops.write_file(&DirId::root(), "note.md", b"original note")
                    .await
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            fs.read_for_modify(&DirId::root(), "note.md").unwrap(),
            b"original note"
        );
        assert_eq!(
            fs.read_for_modify(&DirId::root(), "missing.md"),
            Err(libc::ENOENT)
        );
        let mut corrupted = std::fs::read(&path).unwrap();
        *corrupted.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupted).unwrap();
        assert!(fs.read_for_modify(&DirId::root(), "note.md").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupted);
        assert!(fs.handle_table.is_empty());
    }

    #[test]
    fn failed_release_preserves_an_authenticated_recovery_copy() {
        use oxcrypt_mount::testing::TempVault;
        let vault = TempVault::new();
        let fs = CryptomatorFS::new(vault.path(), TempVault::password()).unwrap();
        let recovery_root = tempfile::tempdir().unwrap();
        *fs.handle_table.recovery_root.lock() = Some(recovery_root.path().to_path_buf());
        let ops = fs.ops_clone();
        let write_ops = Arc::clone(&ops);
        let path = fs
            .exec(async move { write_ops.write_file(&DirId::root(), "note", b"old").await })
            .unwrap()
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let mut buffer = WriteBuffer::new_for_create(DirId::root(), "note".into());
        buffer.write(0, b"pending data must survive close");
        let fh = fs.handle_table.insert_auto(FuseHandle::WriteBuffer(buffer));
        fs.open_handle_tracker.add_handle(42);
        let handler = fs.hazardous_handler.as_ref().unwrap();
        assert!(matches!(
            handler.execute(
                RequestId(0),
                HazardousOp::Release {
                    ino: 42,
                    fh,
                    flags: 0,
                    lock_owner: None,
                    flush: false
                }
            ),
            HazardousResult::Empty { result: Err(_), .. }
        ));
        assert!(!fs.handle_table.contains(&fh));
        let reports = fs.handle_table.close_reports.lock();
        let recovery = PathBuf::from(
            reports[0]
                .split("encrypted recovery copy: ")
                .nth(1)
                .unwrap(),
        );
        let output = tempfile::tempdir().unwrap();
        let dest = output.path().join("recovered");
        let metadata =
            oxcrypt_core::fs::recovery::export(&recovery, ops.master_key(), &dest).unwrap();
        assert_eq!(metadata.filename, "note");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"pending data must survive close"
        );
        assert!(oxcrypt_core::fs::recovery::export(&recovery, ops.master_key(), &dest).is_err());
        let wrong_key = oxcrypt_core::crypto::keys::MasterKey::random().unwrap();
        assert!(oxcrypt_core::fs::recovery::metadata(&recovery, &wrong_key).is_err());
        std::fs::remove_dir_all(recovery).unwrap();
    }

    fn dirty_handle() -> (FuseHandleTable, u64) {
        let handles = FuseHandleTable::new_auto_id();
        let mut buffer = WriteBuffer::new_for_create(DirId::root(), "note.md".into());
        buffer.write(0, b"important note");
        let fh = handles.insert_auto(FuseHandle::WriteBuffer(buffer));
        (handles, fh)
    }

    #[test]
    fn failed_flush_preserves_data_for_retry() {
        for errno in [libc::ENOSPC, libc::EIO, libc::ETIMEDOUT, libc::ECANCELED] {
            let (handles, fh) = dirty_handle();
            assert_eq!(
                persist_write_buffer(&handles, fh, |_, _, content| {
                    assert_eq!(content.as_slice(), b"important note");
                    Err(errno)
                }),
                Err(errno)
            );
            {
                let mut handle = handles.get_mut(&fh).unwrap();
                let buffer = handle.as_write_buffer_mut().unwrap();
                assert!(buffer.is_dirty());
                assert_eq!(buffer.content(), b"important note");
            }
            let result = persist_write_buffer(&handles, fh, |_, _, content| {
                assert_eq!(content.as_slice(), b"important note");
                Ok(PathBuf::from("persisted.c9r"))
            })
            .unwrap();
            assert_eq!(result, Some((PathBuf::from("persisted.c9r"), true)));
            assert!(
                persist_write_buffer(&handles, fh, |_, _, _| panic!("clean buffer"))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn flush_completion_preserves_concurrent_write() {
        let (handles, fh) = dirty_handle();
        let result = persist_write_buffer(&handles, fh, |_, _, snapshot| {
            let mut handle = handles.get_mut(&fh).unwrap();
            handle.as_write_buffer_mut().unwrap().write(0, b"updated");
            assert_eq!(snapshot.as_slice(), b"important note");
            Ok(PathBuf::from("persisted.c9r"))
        })
        .unwrap();
        assert_eq!(result.unwrap().1, false);
        let mut handle = handles.get_mut(&fh).unwrap();
        let buffer = handle.as_write_buffer_mut().unwrap();
        assert!(buffer.is_dirty());
        assert_eq!(buffer.content(), b"updatednt note");
    }

    #[test]
    fn test_notifier_cell_initially_empty() {
        // Create a test vault path (doesn't need to exist for this test)
        let _vault_path = Path::new("/tmp/test_vault");

        // We can't actually create a CryptomatorFS without a real vault,
        // but we can test that OnceLock starts empty
        let notifier: OnceLock<fuser::Notifier> = OnceLock::new();
        assert!(notifier.get().is_none());
    }

    #[test]
    fn test_block_size_constant() {
        assert_eq!(BLOCK_SIZE, 4096);
    }

    #[test]
    fn test_default_permissions() {
        assert_eq!(DEFAULT_FILE_PERM, 0o644);
        assert_eq!(DEFAULT_DIR_PERM, 0o755);
    }
}
