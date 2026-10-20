//! Mount command - mount a Cryptomator vault as a filesystem.
//!
//! Supports multiple backends via feature flags:
//! - `fuse`: FUSE backend (macOS with macFUSE, Linux with libfuse)
//! - `fskit`: FSKit backend (macOS 15.4+ only)
//! - `webdav`: WebDAV backend (cross-platform)
//! - `nfs`: NFS backend (cross-platform)
//! - `fileprovider`: File Provider backend (macOS 13+ cloud storage integration)

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::instrument;

use oxcrypt_mount::{
    BackendInfo, BackendType, MountBackend, MountHandle, VaultStats, daemon,
    first_available_backend, list_backend_info, select_backend, signal,
};

use crate::ipc::{self, IpcServer};

#[cfg(feature = "fuse")]
use oxcrypt_fuse::FuseBackend;

#[cfg(feature = "fskit")]
use oxcrypt_fskit::FskitBackend;

#[cfg(feature = "webdav")]
use oxcrypt_webdav::WebDavBackend;

#[cfg(feature = "nfs")]
use oxcrypt_nfs::NfsBackend;

#[cfg(feature = "fileprovider")]
use oxcrypt_fileprovider::FileProviderBackend;

/// Backend selection for mount command
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum BackendArg {
    /// Use FUSE backend (requires macFUSE on macOS or libfuse on Linux)
    #[cfg(feature = "fuse")]
    Fuse,
    /// Use FSKit backend (native macOS 15.4+ integration)
    #[cfg(feature = "fskit")]
    Fskit,
    /// Use WebDAV backend (no kernel extensions required)
    #[cfg(feature = "webdav")]
    Webdav,
    /// Use NFS backend (local NFSv3 server, no kernel extensions)
    #[cfg(feature = "nfs")]
    Nfs,
    /// Use File Provider backend (macOS 13+ cloud storage integration)
    #[cfg(feature = "fileprovider")]
    FileProvider,
}

impl From<BackendArg> for BackendType {
    fn from(arg: BackendArg) -> Self {
        match arg {
            #[cfg(feature = "fuse")]
            BackendArg::Fuse => BackendType::Fuse,
            #[cfg(feature = "fskit")]
            BackendArg::Fskit => BackendType::FSKit,
            #[cfg(feature = "webdav")]
            BackendArg::Webdav => BackendType::WebDav,
            #[cfg(feature = "nfs")]
            BackendArg::Nfs => BackendType::Nfs,
            #[cfg(feature = "fileprovider")]
            BackendArg::FileProvider => BackendType::FileProvider,
        }
    }
}

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Path to the Cryptomator vault
    pub vault: PathBuf,

    /// Mount directory, or a drive letter such as X: for Windows WebDAV
    #[arg(value_name = "MOUNTPOINT")]
    pub mountpoint: Option<PathBuf>,

    /// Backend to use for mounting (if not specified, uses first available)
    #[arg(short, long, value_enum)]
    pub backend: Option<BackendArg>,

    /// Run in foreground instead of daemon mode
    #[arg(short, long)]
    pub foreground: bool,

    /// Internal flag: this process is the daemon child (don't spawn again)
    #[arg(long, hide = true)]
    pub internal_daemon_child: bool,
}

/// Build the list of available backends based on enabled features
fn build_backends(_args: &Args) -> Vec<Box<dyn MountBackend>> {
    let mut backends: Vec<Box<dyn MountBackend>> = Vec::new();

    // FSKit first on macOS 15.4+ (preferred native backend)
    #[cfg(feature = "fskit")]
    {
        backends.push(Box::new(FskitBackend::new()));
    }

    #[cfg(feature = "fuse")]
    {
        backends.push(Box::new(FuseBackend::new()));
    }

    #[cfg(feature = "webdav")]
    {
        backends.push(Box::new(WebDavBackend::new()));
    }

    #[cfg(feature = "nfs")]
    {
        backends.push(Box::new(NfsBackend::new()));
    }

    #[cfg(feature = "fileprovider")]
    {
        backends.push(Box::new(FileProviderBackend::new()));
    }

    backends
}

#[instrument(level = "info", name = "cmd::mount", skip_all, fields(vault = %args.vault.display()))]
pub fn execute(args: &Args, password: &str) -> Result<()> {
    let filesystem = oxcrypt_mount::TimeoutFs::default();
    let vault_metadata = filesystem
        .metadata(&args.vault)
        .with_context(|| format!("Failed to inspect vault: {}", args.vault.display()))?;
    if !vault_metadata.is_dir() {
        anyhow::bail!("Vault path is not a directory: {}", args.vault.display());
    }

    // Compute mountpoint - default to ~/Vaults/<vault-name>
    let mountpoint = match args.mountpoint.clone() {
        Some(mp) => mp,
        None => default_mountpoint(&args.vault)?,
    };

    // Handle daemon mode: spawn child process and exit (unless foreground or already child)
    if !args.foreground && !args.internal_daemon_child {
        return spawn_daemon_mount(args, &mountpoint, password);
    }

    // If running as daemon child, set up file logging (stderr may be closed)
    let _log_guard = if args.internal_daemon_child {
        Some(setup_daemon_logging(&args.vault)?)
    } else {
        None
    };

    // Get backend
    let backends = build_backends(args);
    if backends.is_empty() {
        anyhow::bail!(
            "No mount backends enabled. Rebuild with --features fuse, --features fskit, or --features webdav"
        );
    }

    let backend = match args.backend {
        Some(arg) => {
            let backend_type: BackendType = arg.into();
            select_backend(&backends, backend_type).context("Failed to get mount backend")?
        }
        None => first_available_backend(&backends).context("No mount backend available")?,
    };

    // WebDAV manages platform-specific mapping itself; an unused Windows drive
    // is not a directory that can be created before `net use` maps it.
    if !matches!(
        backend.backend_type(),
        BackendType::WebDav | BackendType::FSKit
    ) {
        match filesystem.metadata(&mountpoint) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => anyhow::bail!("Mountpoint is not a directory: {}", mountpoint.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                filesystem.create_dir_all(&mountpoint).with_context(|| {
                    format!("Failed to create mountpoint: {}", mountpoint.display())
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to inspect mountpoint: {}", mountpoint.display())
                });
            }
        }
    }

    eprintln!("Using {} backend", backend.name());

    // Generate a vault ID from the path
    let vault_id = args
        .vault
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");

    // Mount the vault
    eprintln!("Mounting vault at {}...", mountpoint.display());
    let handle: Box<dyn MountHandle> = backend
        .mount(vault_id, &args.vault, password, &mountpoint)
        .context("Failed to mount vault")?;
    // FSKit chooses a path under /Volumes; FUSE may select an available suffix.
    let mountpoint = handle.mountpoint().to_path_buf();

    if let Some(location) = handle.display_location() {
        eprintln!("Vault available at {location}");
    } else {
        eprintln!("Vault mounted at {}", handle.mountpoint().display());
    }

    // Get stats from the mount handle (if supported by backend)
    let stats: Option<Arc<VaultStats>> = handle.stats();

    // Generate a unique mount ID for the IPC socket
    let mount_id = uuid::Uuid::new_v4().to_string();

    // Set up IPC server (only if stats are available and in daemon mode)
    let ipc_server: Option<IpcServer> = if args.internal_daemon_child {
        match ipc::socket_path_for_mount(&mount_id) {
            Ok(socket_path) => match IpcServer::new(socket_path.clone()) {
                Ok(server) => {
                    tracing::info!("IPC server started at {}", socket_path.display());
                    Some(server)
                }
                Err(e) => {
                    tracing::warn!("Failed to start IPC server: {}", e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Failed to determine socket path: {}", e);
                None
            }
        }
    } else {
        None
    };

    let socket_path = ipc_server.as_ref().map(|s| s.socket_path().to_path_buf());

    // Register in state file
    let state_manager =
        crate::state::MountStateManager::new().context("Failed to initialize state manager")?;
    let mut mount_entry = crate::state::MountEntry::new(
        args.vault.clone(),
        mountpoint.clone(),
        backend.id(),
        std::process::id(),
        args.internal_daemon_child,
        socket_path.clone(),
    );
    mount_entry.display_location = handle.display_location();
    signal::install_signal_handler().context("Failed to set signal handler")?;
    if let Err(error) = state_manager.add_mount(mount_entry) {
        handle
            .unmount()
            .context("Failed to unmount after state registration failed")?;
        return Err(error).context("Failed to register mount in state file");
    }

    if args.internal_daemon_child {
        eprintln!("Daemon mount started (PID: {})", std::process::id());
        if let Some(ref path) = socket_path {
            eprintln!("IPC socket: {}", path.display());
        }
    } else {
        eprintln!("Press Ctrl+C to unmount and exit");
    }

    // Main loop: wait for signal while handling IPC requests
    // Use event-driven wait with periodic wakeups for IPC polling
    while !signal::shutdown_requested() {
        if let (Some(server), Some(stats)) = (&ipc_server, &stats) {
            // Process any pending IPC requests
            if let Err(e) = server.try_accept(|request| ipc::handle_request(&request, stats)) {
                tracing::debug!("IPC accept error: {}", e);
            }
            // Wait with timeout to allow periodic IPC polling
            signal::wait_for_shutdown_timeout(std::time::Duration::from_millis(100));
        } else {
            // No IPC server - just block until shutdown signal
            signal::wait_for_shutdown();
        }
    }

    // Clean up IPC server socket
    if let Some(server) = ipc_server {
        let socket_path = server.socket_path().to_path_buf();
        drop(server);
        if let Err(e) = std::fs::remove_file(&socket_path) {
            tracing::debug!("Failed to remove IPC socket: {}", e);
        }
    }

    // Unmount first, then remove from state file
    // (If we remove state first and unmount crashes, the orphaned mount becomes invisible)
    eprintln!("Unmounting...");
    handle.unmount().context("Failed to unmount")?;
    eprintln!("Unmounted successfully");

    // Remove from state file after successful unmount
    state_manager
        .remove_by_mountpoint(&mountpoint)
        .context("Failed to remove stopped mount from state file")?;

    Ok(())
}

/// Choose a mount location usable by the platform's filesystem client.
fn default_mountpoint(vault: &std::path::Path) -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let _ = vault;
        for letter in ('D'..='Z').rev() {
            let path = PathBuf::from(format!("{letter}:\\"));
            if !path.exists() {
                return Ok(path);
            }
        }
        anyhow::bail!("No free drive letter; specify a mountpoint explicitly");
    }
    #[cfg(not(target_os = "windows"))]
    {
        let vault_name = vault
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault");
        Ok(directories::BaseDirs::new()
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
            .home_dir()
            .join("Vaults")
            .join(vault_name))
    }
}

/// Spawn a daemon process to run the mount in background.
fn spawn_daemon_mount(args: &Args, mountpoint: &PathBuf, password: &str) -> Result<()> {
    use std::process::Command;

    // Build command to re-invoke ourselves with --internal-daemon-child
    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    let mut cmd = Command::new(&exe);

    cmd.arg("mount");
    cmd.arg(&args.vault);
    cmd.arg(mountpoint);
    cmd.arg("--internal-daemon-child");

    if let Some(backend) = &args.backend {
        let backend_str = match backend {
            #[cfg(feature = "fuse")]
            BackendArg::Fuse => "fuse",
            #[cfg(feature = "fskit")]
            BackendArg::Fskit => "fskit",
            #[cfg(feature = "webdav")]
            BackendArg::Webdav => "webdav",
            #[cfg(feature = "nfs")]
            BackendArg::Nfs => "nfs",
            #[cfg(feature = "fileprovider")]
            BackendArg::FileProvider => "file-provider",
        };
        cmd.arg("--backend").arg(backend_str);
    }

    // Pass password via env var (not in command line args for security)
    cmd.env("OXCRYPT_PASSWORD", password);

    let manager = crate::state::MountStateManager::new()?;
    let existing_mount_ids: std::collections::HashSet<_> = manager
        .list_mounts()?
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    // Spawn using proper daemonization
    let pid = daemon::spawn_as_daemon(&mut cmd).context("Failed to spawn daemon process")?;
    let started = std::time::Instant::now();
    let entry = loop {
        if let Some(entry) = manager
            .list_mounts()?
            .into_iter()
            .find(|entry| entry.pid == pid && !existing_mount_ids.contains(&entry.id))
        {
            if daemon_running(pid) {
                break entry;
            }
        }
        if !daemon_running(pid) {
            anyhow::bail!(
                "Mount process exited before becoming ready; see logs in {}",
                get_daemon_log_directory().display()
            );
        }
        if started.elapsed() >= std::time::Duration::from_secs(30) {
            anyhow::bail!(
                "Mount process {pid} has not reported readiness. Check 'oxcrypt mounts --include-stale' and logs in {}",
                get_daemon_log_directory().display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    eprintln!("Mount started in background (PID: {pid})");
    eprintln!("Location: {}", entry.location());
    eprintln!();
    eprintln!("Use 'oxcrypt mounts' to list active mounts");
    eprintln!(
        "Use 'oxcrypt unmount {}' to stop",
        entry.mountpoint.display()
    );

    Ok(())
}

/// Reap a child that failed before registration so a zombie is not mistaken
/// for a daemon that is still starting.
fn daemon_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use nix::{
            sys::wait::{WaitPidFlag, WaitStatus, waitpid},
            unistd::Pid,
        };
        let Ok(raw_pid) = i32::try_from(pid) else {
            return false;
        };
        match waitpid(Pid::from_raw(raw_pid), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => return true,
            Ok(_) => return false,
            Err(nix::errno::Errno::ECHILD) => {}
            Err(_) => return crate::state::is_process_alive(pid),
        }
    }
    crate::state::is_process_alive(pid)
}

/// List available backends and their status
pub fn list_backends() -> Vec<BackendInfo> {
    // Create a default Args for listing purposes (config doesn't matter for display)
    let default_args = Args {
        vault: PathBuf::new(),
        mountpoint: None,
        backend: None,
        foreground: false,
        internal_daemon_child: false,
    };
    list_backend_info(&build_backends(&default_args))
}

/// Set up file-based logging for daemon processes.
///
/// When running as a daemon, stderr may be closed or redirected to /dev/null,
/// so we need to log to a file instead. Logs are written to:
/// - macOS: `~/Library/Application Support/com.oxidized.oxcrypt/logs/`
/// - Linux: `$XDG_STATE_HOME/oxcrypt/logs/` (defaults to `~/.local/state/oxcrypt/logs/`)
///
/// Returns a guard that must be kept alive for the duration of the daemon.
fn setup_daemon_logging(
    vault_path: &std::path::Path,
) -> Result<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::{
        EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt,
    };

    // Get the log directory
    let log_dir = get_daemon_log_directory();

    // Create log directory if it doesn't exist
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;

    // Use vault name for the log file
    let vault_name = vault_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault");
    let log_filename = format!("daemon-{vault_name}.log");

    // Create rolling file appender (daily rotation)
    let file_appender = RollingFileAppender::new(Rotation::DAILY, &log_dir, &log_filename);

    // Make file appender non-blocking
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Set up tracing with file output only (no stderr in daemon mode)
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_filter(filter);

    tracing_subscriber::registry().with(file_layer).init();

    tracing::info!(
        "Daemon started for vault: {} (PID: {})",
        vault_path.display(),
        std::process::id()
    );
    tracing::info!("Log file: {}/{}", log_dir.display(), log_filename);

    Ok(guard)
}

/// Get the platform-appropriate log directory for daemon processes.
fn get_daemon_log_directory() -> PathBuf {
    if let Some(config) = std::env::var_os("OXCRYPT_CONFIG_DIR").filter(|value| !value.is_empty()) {
        return PathBuf::from(config).join("logs");
    }
    // Use directories crate to get platform-appropriate paths
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "oxidized", "oxcrypt") {
        // On macOS: ~/Library/Application Support/com.oxidized.oxcrypt/logs/
        // On Linux: ~/.local/share/oxcrypt/logs/
        #[cfg(target_os = "linux")]
        {
            // On Linux, prefer state dir for logs
            if let Some(state_dir) = directories::BaseDirs::new()
                .and_then(|d| d.state_dir().map(std::path::Path::to_path_buf))
            {
                return state_dir.join("oxcrypt").join("logs");
            }
        }
        return proj_dirs.data_dir().join("logs");
    }

    // Fallback to temp directory
    std::env::temp_dir().join("oxcrypt").join("logs")
}
