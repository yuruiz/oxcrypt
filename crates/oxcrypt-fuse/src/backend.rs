//! FUSE backend implementation of MountBackend trait.
//!
//! Provides a unified mounting interface for FUSE-based filesystem mounts.

use crate::scheduler::SchedulerStatsCollector;
use crate::{CryptomatorFS, MountConfig};
use fuser::{BackgroundSession, MountOption};
use oxcrypt_mount::{
    BackendType, MountBackend, MountError, MountHandle, MountOptions, SchedulerStatsSnapshot,
    VaultStats, find_available_mountpoint,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Selects a non-default macFUSE mounting backend, from `OXCRYPT_MACFUSE_BACKEND`.
///
/// macFUSE 5.1+ can mount through FSKit instead of its kernel extension via
/// `-o backend=fskit`, but that backend is unreachable from this crate:
/// an FSKit-backed mount is driven by macFUSE's MFMount channel API and has
/// no file descriptor, so `fuse_session_fd()` returns -1 and fuser rejects the
/// mount. Only the kernel extension yields the descriptor fuser reads FUSE
/// messages from. An unrecognised value silently falls back to the kernel
/// extension, so `kext` is the only meaningful setting today.
#[cfg(target_os = "macos")]
fn macfuse_backend_option() -> Option<MountOption> {
    std::env::var("OXCRYPT_MACFUSE_BACKEND")
        .ok()
        .filter(|backend| !backend.is_empty())
        .map(|backend| MountOption::CUSTOM(format!("backend={backend}")))
}

/// Mount options that only apply on macOS: the volume name Finder displays,
/// AppleDouble fallback for extended attributes, a bound on
/// how long the kernel waits on the daemon before ejecting the volume (which keeps
/// an unresponsive mount from wedging into a ghost mount), and any macFUSE backend
/// override. Empty on every other platform.
#[cfg(target_os = "macos")]
fn platform_mount_options(vault_id: &str) -> Vec<MountOption> {
    let mut options = vec![
        MountOption::CUSTOM(format!("volname={vault_id}")),
        MountOption::CUSTOM("daemon_timeout=30".to_string()),
    ];
    options.extend(macfuse_backend_option());
    options
}

#[cfg(not(target_os = "macos"))]
fn platform_mount_options(_vault_id: &str) -> Vec<MountOption> {
    Vec::new()
}

/// Handle to a FUSE-mounted filesystem.
///
/// Wraps the fuser `BackgroundSession`. Dropping this handle triggers unmount.
pub struct FuseMountHandle {
    session: Option<BackgroundSession>,
    close_reports: Arc<parking_lot::Mutex<Vec<String>>>,
    mountpoint: PathBuf,
    /// Statistics for monitoring vault activity
    stats: Arc<VaultStats>,
    /// Lock contention metrics for profiling
    lock_metrics: Arc<oxcrypt_core::vault::lock_metrics::LockMetrics>,
    /// Scheduler stats collector for detailed scheduler metrics
    scheduler_collector: Option<SchedulerStatsCollector>,
}

impl FuseMountHandle {
    /// Get lock contention metrics for profiling fast path performance.
    ///
    /// Returns metrics about sync fast path hit rate and async lock acquisitions.
    pub fn lock_metrics(&self) -> &Arc<oxcrypt_core::vault::lock_metrics::LockMetrics> {
        &self.lock_metrics
    }

    /// Force unmount the filesystem using system tools.
    /// This is a fallback when the normal unmount is blocked.
    fn force_unmount_impl(&self) -> std::io::Result<()> {
        oxcrypt_mount::force_unmount(&self.mountpoint).map_err(std::io::Error::other)
    }

    fn finish_session(&mut self, force: bool) -> Result<(), MountError> {
        let mut failures = Vec::new();
        if let Some(session) = self.session.take() {
            let forced = if force {
                Some(self.force_unmount_impl())
            } else {
                None
            };
            let externally_unmounted = forced.as_ref().is_some_and(Result::is_ok);
            if let Some(Err(error)) = forced {
                failures.push(format!("force unmount failed: {error}"));
            }
            let result = cleanup_owned(
                &oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL,
                JOIN_TIMEOUT,
                session,
                move |session| {
                    if externally_unmounted {
                        session.join()
                    } else {
                        session.umount_and_join()
                    }
                },
            );
            if let Err(error) = result {
                failures.push(format!("FUSE session shutdown did not complete: {error}"));
                if !force && let Err(error) = self.force_unmount_impl() {
                    failures.push(format!("fallback force unmount failed: {error}"));
                }
            }
        }
        failures.extend(self.close_reports.lock().iter().cloned());
        if failures.is_empty() {
            Ok(())
        } else {
            Err(MountError::UnmountFailed(failures.join("; ")))
        }
    }
}

impl MountHandle for FuseMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn stats(&self) -> Option<Arc<VaultStats>> {
        Some(Arc::clone(&self.stats))
    }

    fn lock_metrics(&self) -> Option<Arc<oxcrypt_core::vault::lock_metrics::LockMetrics>> {
        Some(Arc::clone(&self.lock_metrics))
    }

    fn scheduler_stats(&self) -> Option<SchedulerStatsSnapshot> {
        self.scheduler_collector
            .as_ref()
            .map(SchedulerStatsCollector::to_mount_snapshot)
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        tracing::info!(mountpoint = %self.mountpoint.display(), "Unmounting FUSE filesystem");
        self.finish_session(false)?;
        tracing::info!(mountpoint = %self.mountpoint.display(), "FUSE unmount successful");
        Ok(())
    }

    fn force_unmount(mut self: Box<Self>) -> Result<(), MountError> {
        tracing::info!(mountpoint = %self.mountpoint.display(), "Force unmounting FUSE filesystem");
        self.finish_session(true)?;
        tracing::info!(mountpoint = %self.mountpoint.display(), "FUSE force unmount successful");
        Ok(())
    }
}

const JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Transfer a resource with a potentially blocking destructor to a bounded
/// worker. If no worker can be started, retaining the resource until process
/// exit is preferable to running that destructor on the caller's thread. The
/// returned error leaves the mount registered for explicit recovery.
fn cleanup_owned<T, F>(
    pool: &oxcrypt_mount::BoundedFsPool,
    timeout: Duration,
    resource: T,
    cleanup: F,
) -> std::io::Result<()>
where
    T: Send + 'static,
    F: FnOnce(T) -> std::io::Result<()> + Send + 'static,
{
    let resource = std::mem::ManuallyDrop::new(resource);
    pool.run_with_timeout(timeout, move || {
        cleanup(std::mem::ManuallyDrop::into_inner(resource))
    })
}

impl Drop for FuseMountHandle {
    fn drop(&mut self) {
        if self.session.is_some()
            && let Err(error) = self.finish_session(false)
        {
            tracing::error!(mountpoint = %self.mountpoint.display(), %error, "FUSE cleanup incomplete; mount may require manual recovery");
        }
    }
}

/// Probe only through bounded filesystem calls: a path may be below a ghost
/// mount even when it is not itself listed in the system mount table.
fn prepare_mountpoint(path: &Path) -> std::io::Result<()> {
    let fs = oxcrypt_mount::TimeoutFs::default();
    match fs.metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("Mountpoint is not a directory: {}", path.display()),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs.create_dir_all(path),
        Err(error) => Err(error),
    }
}

/// FUSE-based mounting backend.
///
/// Uses the `oxcrypt-fuse` crate to create a FUSE filesystem and mount it
/// using macFUSE (macOS) or libfuse (Linux).
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseBackend {
    /// Timeout for waiting for mount readiness
    pub mount_timeout: Duration,
    /// Polling interval when waiting for mount
    pub poll_interval: Duration,
}

impl FuseBackend {
    /// Create a new FUSE backend with default settings.
    pub fn new() -> Self {
        Self {
            mount_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_millis(50),
        }
    }

    /// Create a new FUSE backend with custom timeouts.
    pub fn with_timeouts(mount_timeout: Duration, poll_interval: Duration) -> Self {
        Self {
            mount_timeout,
            poll_interval,
        }
    }

    /// Wait for the mount to become ready by polling until the mount is active.
    ///
    /// Uses device ID comparison (stat-based) rather than mount table parsing,
    /// since the mount command can block on ghost mounts. A mount is detected
    /// when the path's device ID differs from its parent's.
    fn wait_for_mount(&self, mount_point: &Path) -> Result<(), MountError> {
        use oxcrypt_mount::TimeoutFs;
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        let deadline = Instant::now() + self.mount_timeout;
        let fs = TimeoutFs::new(Duration::from_millis(500));

        // Get parent path for device comparison
        let parent = mount_point.parent().unwrap_or(Path::new("/"));

        while Instant::now() < deadline {
            // Check if mount point has different device ID than parent (indicates active mount)
            #[cfg(unix)]
            {
                if let (Ok(path_meta), Ok(parent_meta)) =
                    (fs.metadata(mount_point), fs.metadata(parent))
                    && path_meta.dev() != parent_meta.dev()
                {
                    tracing::debug!(
                        "FUSE mount confirmed active at {} (dev {} != parent dev {})",
                        mount_point.display(),
                        path_meta.dev(),
                        parent_meta.dev()
                    );
                    return Ok(());
                }
            }

            // Non-unix fallback: just check if directory exists
            #[cfg(not(unix))]
            {
                if fs.is_dir(mount_point) {
                    return Ok(());
                }
            }

            std::thread::sleep(self.poll_interval);
        }

        Err(MountError::Mount(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "FUSE mount did not become ready within {:?}",
                self.mount_timeout
            ),
        )))
    }

    /// Try to mount with a timeout to handle cases where the mount syscall
    /// itself blocks (e.g., stale mount at mountpoint).
    fn spawn_mount_with_timeout(
        &self,
        fs: CryptomatorFS,
        mountpoint: &Path,
        options: &[MountOption],
    ) -> Result<BackgroundSession, MountError> {
        let mountpoint = mountpoint.to_path_buf();
        // The session ACL stays at its default `SessionACL::Owner`, restricting the
        // mount to the user who created it.
        let mut config = fuser::Config::default();
        config.mount_options = options.to_vec();

        oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL
            .run_with_timeout(self.mount_timeout, move || {
                fuser::spawn_mount(fs, &mountpoint, &config)
            })
            .map_err(MountError::Mount)
    }
}

impl MountBackend for FuseBackend {
    fn name(&self) -> &'static str {
        "FUSE"
    }

    fn id(&self) -> &'static str {
        "fuse"
    }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            // Check for macFUSE installation
            Path::new("/Library/Filesystems/macfuse.fs").exists()
        }
        #[cfg(target_os = "linux")]
        {
            // Check for FUSE kernel module
            Path::new("/dev/fuse").exists()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }

    fn unavailable_reason(&self) -> Option<String> {
        if self.is_available() {
            return None;
        }

        #[cfg(target_os = "macos")]
        {
            Some(
                "macFUSE is not installed. Download it from https://osxfuse.github.io/".to_string(),
            )
        }
        #[cfg(target_os = "linux")]
        {
            Some("FUSE is not available. Ensure the fuse kernel module is loaded.".to_string())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Some("FUSE is not supported on this platform.".to_string())
        }
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Fuse
    }

    fn description(&self) -> &'static str {
        "Uses macFUSE (macOS) or libfuse (Linux) for filesystem mounting"
    }

    fn mount(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        tracing::info!(
            vault_id = %vault_id,
            vault_path = %vault_path.display(),
            mountpoint = %mountpoint.display(),
            "Starting FUSE mount"
        );

        if !self.is_available() {
            return Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ));
        }

        // Find an available mount point (one that's not already a mount point)
        let actual_mountpoint = find_available_mountpoint(mountpoint)
            .map_err(|e| MountError::Mount(std::io::Error::other(e.to_string())))?;

        // Log if we're using an alternative mountpoint
        if actual_mountpoint != mountpoint {
            tracing::info!(
                "Using alternative mount point {} (original {} already mounted)",
                actual_mountpoint.display(),
                mountpoint.display()
            );
        }

        // Create mount point directory if it doesn't exist
        prepare_mountpoint(&actual_mountpoint)?;

        // Create the CryptomatorFS filesystem
        let fs = CryptomatorFS::new(vault_path, password)
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        // Capture stats, lock metrics, and scheduler collector before spawning
        // (spawn_mount2 takes ownership of fs)
        let stats = fs.stats();
        let close_reports = fs.close_reports();
        let lock_metrics = Arc::clone(fs.lock_metrics());
        let scheduler_collector = fs.scheduler_stats_collector();
        // Share the notifier cell so it stays reachable once `fs` has been moved
        // into the session below.
        let notifier_cell = fs.notifier_cell();

        // Configure mount options
        let mut options = vec![
            MountOption::FSName(format!("cryptomator:{vault_id}")),
            MountOption::Subtype("oxcrypt".to_string()),
            // Let kernel handle permission checks - avoids access() calls for every operation
            MountOption::DefaultPermissions,
        ];

        // `auto_unmount` is deliberately not used. It is implemented by the setuid
        // `fusermount` helper, which holds the mount itself, so it only works with a
        // non-owner session ACL (`allow_other`). This filesystem reports world-readable
        // modes (0o644 files, 0o755 directories) and enables `default_permissions`, so
        // `allow_other` would let any local user read decrypted vault contents.
        // Unmounting is handled explicitly instead; a mount left behind by a crash is
        // recoverable with `fusermount -u`, leaked plaintext is not. macFUSE's libfuse3
        // rejects `auto_unmount` outright in any case.

        options.extend(platform_mount_options(vault_id));

        // Mount the filesystem with timeout protection
        let session = self.spawn_mount_with_timeout(fs, &actual_mountpoint, &options)?;

        // Inject notifier for kernel cache invalidation
        {
            let notifier = session.notifier();
            tracing::debug!("Injecting kernel notifier for cache invalidation");
            if notifier_cell.set(notifier).is_err() {
                tracing::warn!("Failed to set notifier - already initialized");
            } else {
                tracing::info!("Successfully injected kernel notifier for cache invalidation");
            }
        }

        // Wait for mount to become ready (also with timeout protection)
        if let Err(error) = self.wait_for_mount(&actual_mountpoint) {
            if let Err(cleanup_error) = cleanup_owned(
                &oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL,
                JOIN_TIMEOUT,
                session,
                BackgroundSession::umount_and_join,
            ) {
                return Err(MountError::UnmountFailed(format!(
                    "{error}; mount readiness cleanup failed: {cleanup_error}"
                )));
            }
            return Err(error);
        }

        tracing::info!(
            mountpoint = %actual_mountpoint.display(),
            vault_id = %vault_id,
            "FUSE mount successful"
        );

        Ok(Box::new(FuseMountHandle {
            session: Some(session),
            close_reports,
            mountpoint: actual_mountpoint,
            stats,
            lock_metrics,
            scheduler_collector,
        }))
    }

    fn mount_with_options(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
        options: &MountOptions,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        tracing::info!(
            vault_id = %vault_id,
            vault_path = %vault_path.display(),
            mountpoint = %mountpoint.display(),
            local_mode = options.local_mode,
            "Starting FUSE mount with options"
        );

        if !self.is_available() {
            return Err(MountError::BackendUnavailable(
                self.unavailable_reason().unwrap_or_default(),
            ));
        }

        // Find an available mount point (one that's not already a mount point)
        let actual_mountpoint = find_available_mountpoint(mountpoint)
            .map_err(|e| MountError::Mount(std::io::Error::other(e.to_string())))?;

        // Log if we're using an alternative mountpoint
        if actual_mountpoint != mountpoint {
            tracing::info!(
                "Using alternative mount point {} (original {} already mounted)",
                actual_mountpoint.display(),
                mountpoint.display()
            );
        }

        // Create mount point directory if it doesn't exist
        prepare_mountpoint(&actual_mountpoint)?;

        // Convert MountOptions to MountConfig
        let mut config = if options.local_mode {
            MountConfig::local()
        } else {
            MountConfig::default()
        };

        // Apply custom TTL if specified
        if let Some(ttl) = options.attr_ttl {
            config = config.attr_ttl(ttl);
        }

        tracing::info!(
            "Mounting vault {} with {} mode (cache TTL: {:?})",
            vault_id,
            if options.local_mode {
                "local"
            } else {
                "network"
            },
            config.attr_ttl
        );

        // Create the CryptomatorFS filesystem with config
        let fs = CryptomatorFS::with_config(vault_path, password, config)
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        // Capture stats, lock metrics, and scheduler collector before spawning
        // (spawn_mount2 takes ownership of fs)
        let stats = fs.stats();
        let close_reports = fs.close_reports();
        let lock_metrics = Arc::clone(fs.lock_metrics());
        let scheduler_collector = fs.scheduler_stats_collector();
        // Share the notifier cell so it stays reachable once `fs` has been moved
        // into the session below.
        let notifier_cell = fs.notifier_cell();

        // Configure mount options
        let mut mount_options = vec![
            MountOption::FSName(format!("cryptomator:{vault_id}")),
            MountOption::Subtype("oxcrypt".to_string()),
        ];

        // `auto_unmount` is deliberately not used. It is implemented by the setuid
        // `fusermount` helper, which holds the mount itself, so it only works with a
        // non-owner session ACL (`allow_other`), which would expose decrypted vault
        // contents to every local user. Unmounting is handled explicitly instead.
        // macFUSE's libfuse3 rejects `auto_unmount` outright in any case.

        mount_options.extend(platform_mount_options(vault_id));

        // Mount the filesystem with timeout protection
        let session = self.spawn_mount_with_timeout(fs, &actual_mountpoint, &mount_options)?;

        // Inject notifier for kernel cache invalidation
        {
            let notifier = session.notifier();
            tracing::debug!("Injecting kernel notifier for cache invalidation");
            if notifier_cell.set(notifier).is_err() {
                tracing::warn!("Failed to set notifier - already initialized");
            } else {
                tracing::info!("Successfully injected kernel notifier for cache invalidation");
            }
        }

        // Wait for mount to become ready (also with timeout protection)
        if let Err(error) = self.wait_for_mount(&actual_mountpoint) {
            if let Err(cleanup_error) = cleanup_owned(
                &oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL,
                JOIN_TIMEOUT,
                session,
                BackgroundSession::umount_and_join,
            ) {
                return Err(MountError::UnmountFailed(format!(
                    "{error}; mount readiness cleanup failed: {cleanup_error}"
                )));
            }
            return Err(error);
        }

        tracing::info!(
            mountpoint = %actual_mountpoint.display(),
            vault_id = %vault_id,
            local_mode = options.local_mode,
            "FUSE mount successful"
        );

        Ok(Box::new(FuseMountHandle {
            session: Some(session),
            close_reports,
            mountpoint: actual_mountpoint,
            stats,
            lock_metrics,
            scheduler_collector,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn finder_metadata_is_not_blocked() {
        let options = platform_mount_options("test");

        assert!(!options.iter().any(|option| matches!(option,
            MountOption::CUSTOM(value) if value == "noappledouble" || value == "noapplexattr")));
    }

    #[test]
    fn fuse_backend_id() {
        let backend = FuseBackend::new();
        assert_eq!(backend.id(), "fuse");
        assert_eq!(backend.name(), "FUSE");
    }

    #[test]
    fn fuse_backend_availability_check() {
        let backend = FuseBackend::new();
        // Just verify the method doesn't panic
        let _ = backend.is_available();
        let _ = backend.unavailable_reason();
    }

    #[test]
    fn fuse_backend_custom_timeouts() {
        let backend =
            FuseBackend::with_timeouts(Duration::from_secs(5), Duration::from_millis(100));
        assert_eq!(backend.mount_timeout, Duration::from_secs(5));
        assert_eq!(backend.poll_interval, Duration::from_millis(100));
    }

    #[test]
    fn session_cleanup_propagates_errors_and_bounds_a_stalled_worker() {
        let pool = oxcrypt_mount::BoundedFsPool::new(1);
        let error = cleanup_owned(&pool, Duration::from_secs(1), (), |()| {
            Err(std::io::Error::other("session error"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "session error");
        let (release, wait) = mpsc::channel();
        let started = Instant::now();
        let error = cleanup_owned(&pool, Duration::from_millis(20), (), move |()| {
            wait.recv().unwrap();
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(pool.blocked_count(), 1);
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while pool.blocked_count() != 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(pool.blocked_count(), 0);
    }

    #[test]
    fn rejected_cleanup_never_runs_a_blocking_destructor_on_the_caller() {
        struct MustNotDrop;
        impl Drop for MustNotDrop {
            fn drop(&mut self) {
                panic!("resource destructor ran on rejected cleanup");
            }
        }
        let pool = oxcrypt_mount::BoundedFsPool::new(0);
        let error =
            cleanup_owned(&pool, Duration::from_millis(20), MustNotDrop, |_| Ok(())).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ResourceBusy);
    }

    #[test]
    fn mountpoint_preflight_creates_missing_directories_and_rejects_files() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("new/mount");
        prepare_mountpoint(&directory).unwrap();
        assert!(directory.is_dir());
        prepare_mountpoint(&directory).unwrap();
        let file = temporary.path().join("file");
        std::fs::write(&file, b"not a directory").unwrap();
        assert_eq!(
            prepare_mountpoint(&file).unwrap_err().kind(),
            std::io::ErrorKind::NotADirectory
        );
        assert_eq!(
            prepare_mountpoint(&file.join("child")).unwrap_err().kind(),
            std::io::ErrorKind::NotADirectory
        );
    }
}
