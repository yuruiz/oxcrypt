//! Mount state persistence for crash recovery.
//!
//! Persists active mount information to a shared state file that's compatible
//! with the CLI's mount tracking. This allows:
//! - Recovery of mount state after GUI crash/restart
//! - Cleanup of orphaned mounts from either CLI or GUI
//!
//! State is persisted to `~/.config/oxcrypt/mounts.json` (same location as CLI).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// A single mount entry in the state file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEntry {
    /// Unique identifier for this mount session
    pub id: String,
    /// Path to the vault directory
    pub vault_path: PathBuf,
    /// Where the vault is mounted
    pub mountpoint: PathBuf,
    /// Backend location when no operating-system mount was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_location: Option<String>,
    /// Backend used (fuse, fileprovider, webdav, nfs)
    pub backend: String,
    /// Process ID of the mount process
    pub pid: u32,
    /// When the mount was started
    pub started_at: DateTime<Utc>,
    /// Whether this was a daemon mount (background)
    pub is_daemon: bool,
    /// Path to the IPC socket for this mount (if running as daemon)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
}

impl MountEntry {
    pub fn is_server_only(&self) -> bool {
        self.backend.eq_ignore_ascii_case("webdav") && self.display_location.is_some()
    }

    /// Capture the actual location reported by the live backend handle.
    pub fn from_gui_handle(
        vault_path: PathBuf,
        backend: &str,
        handle: &dyn oxcrypt_mount::MountHandle,
    ) -> Self {
        let mut entry = Self::new_gui_mount(vault_path, handle.mountpoint().to_path_buf(), backend);
        entry.display_location = handle.display_location();
        entry
    }

    /// Create a new mount entry for a GUI mount (non-daemon).
    pub fn new_gui_mount(
        vault_path: PathBuf,
        mountpoint: PathBuf,
        backend: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vault_path,
            mountpoint,
            display_location: None,
            backend: backend.into(),
            pid: std::process::id(),
            started_at: Utc::now(),
            is_daemon: false, // GUI mounts are not daemons
            socket_path: None,
        }
    }
}

/// The complete mount state stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MountState {
    /// Schema version for future migrations
    #[serde(default = "default_version")]
    pub version: u32,
    /// Active mount entries
    #[serde(default)]
    pub mounts: Vec<MountEntry>,
}

fn default_version() -> u32 {
    1
}

/// Manages the mount state file for the Desktop app.
pub struct DesktopMountState {
    state_path: PathBuf,
    lock_path: PathBuf,
}

/// Default timeout for acquiring the state file lock.
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl DesktopMountState {
    /// Create a new state manager, initializing the config directory if needed.
    pub fn new() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("com", "oxcrypt", "oxcrypt")
            .context("Failed to determine config directory")?;
        let config_dir = dirs.config_dir();

        // Ensure config directory exists
        std::fs::create_dir_all(config_dir)
            .with_context(|| format!("Failed to create config dir: {}", config_dir.display()))?;

        let state_path = config_dir.join("mounts.json");
        let lock_path = config_dir.join("mounts.lock");

        Ok(Self {
            state_path,
            lock_path,
        })
    }

    /// Execute a function while holding an exclusive lock on the state file.
    fn with_lock<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut MountState) -> Result<R>,
    {
        // Create/open lock file
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.lock_path)
            .with_context(|| format!("Failed to open lock file: {}", self.lock_path.display()))?;

        // Try to acquire lock with timeout
        let start = std::time::Instant::now();
        loop {
            match lock_file.try_lock_exclusive() {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > LOCK_TIMEOUT {
                        anyhow::bail!("Timed out waiting for state file lock");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Failed to lock: {}", self.lock_path.display()));
                }
            }
        }

        // Load state
        let mut state = self.load_internal()?;
        let result = f(&mut state)?;
        self.save_internal(&state)?;
        Ok(result)
    }

    fn load_internal(&self) -> Result<MountState> {
        if !self.state_path.exists() {
            return Ok(MountState::default());
        }

        let contents = std::fs::read_to_string(&self.state_path)
            .with_context(|| format!("Failed to read state file: {}", self.state_path.display()))?;

        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file: {}", self.state_path.display()))
    }

    fn save_internal(&self, state: &MountState) -> Result<()> {
        use std::io::Write;
        let contents = serde_json::to_vec_pretty(state)?;
        let temporary = self
            .state_path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&contents)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.state_path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
            .with_context(|| format!("Failed to write mount state: {}", self.state_path.display()))
    }

    /// Add a mount to the state file.
    pub fn add_mount(&self, entry: MountEntry) -> Result<()> {
        self.with_lock(|state| {
            anyhow::ensure!(
                !state
                    .mounts
                    .iter()
                    .any(|existing| existing.mountpoint == entry.mountpoint
                        && is_process_alive(existing.pid)),
                "Mountpoint {} already has a running mount process",
                entry.mountpoint.display()
            );
            state.mounts.retain(|m| m.mountpoint != entry.mountpoint);
            state.mounts.push(entry);
            Ok(())
        })
    }

    /// Remove a mount from the state file by mountpoint.
    pub fn remove_mount(&self, mountpoint: &Path) -> Result<()> {
        let mountpoint = mountpoint.to_path_buf();
        self.with_lock(|state| {
            state.mounts.retain(|m| m.mountpoint != mountpoint);
            Ok(())
        })
    }

    /// Find active mounts for the current process.
    ///
    /// Returns mounts from the state file that:
    /// 1. Were created by this process (PID matches)
    /// 2. Are still mounted in the system
    ///
    /// This is used on startup to recover mount state after a crash.
    pub fn find_our_active_mounts(&self) -> Result<Vec<MountEntry>> {
        let state = self.load_internal()?;
        let system_mounts = if state.mounts.iter().any(|entry| !entry.is_server_only()) {
            get_system_mounts()?
        } else {
            std::collections::HashSet::new()
        };
        let our_pid = std::process::id();

        let active: Vec<MountEntry> = state
            .mounts
            .into_iter()
            .filter(|m| {
                // Only our mounts
                if m.pid != our_pid {
                    return false;
                }
                // Must be in system mounts
                if m.is_server_only() {
                    return true;
                }
                let canonical = mount_comparison_path(&m.mountpoint);
                system_mounts.contains(&canonical)
            })
            .collect();

        Ok(active)
    }

    /// Find mounts for a specific vault path that are still active.
    ///
    /// Used to recover mount state on startup - checks if a vault we know about
    /// has an active mount from any process.
    pub fn find_active_mount_for_vault(&self, vault_path: &Path) -> Result<Option<MountEntry>> {
        let state = self.load_internal()?;
        let mut system_mounts = None;

        for entry in state.mounts {
            // Check if this entry is for our vault
            if entry.vault_path != vault_path {
                continue;
            }

            // Check if process is alive
            if !is_process_alive(entry.pid) {
                continue;
            }

            // Check if mount is in system
            if entry.is_server_only() {
                return Ok(Some(entry));
            }
            let system_mounts = match &mut system_mounts {
                Some(mounts) => mounts,
                slot @ None => slot.insert(get_system_mounts()?),
            };
            let canonical = mount_comparison_path(&entry.mountpoint);
            if system_mounts.contains(&canonical) {
                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    /// Query the mount table before discarding an orphan's recovery record.
    pub fn mountpoint_is_active(&self, mountpoint: &Path) -> Result<bool> {
        let mounts = get_system_mounts()?;
        #[cfg(windows)]
        {
            Ok(mounts.contains(&windows_mount_path(mountpoint)))
        }
        #[cfg(not(windows))]
        {
            if mounts.contains(&oxcrypt_mount::normalize_mount_path(mountpoint)) {
                return Ok(true);
            }
            match oxcrypt_mount::TimeoutFs::default().canonicalize(mountpoint) {
                Ok(path) => Ok(mounts.contains(&oxcrypt_mount::normalize_mount_path(&path))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error).context("Cannot resolve orphan mountpoint safely"),
            }
        }
    }

    /// Find orphaned mounts - entries where the process is dead but a mount may still exist.
    ///
    /// Returns mount entries that:
    /// 1. Have a dead process (PID no longer alive)
    /// 2. Optionally match one of the known vault paths
    ///
    /// Used on startup to clean up mounts from crashed sessions.
    pub fn find_orphaned_mounts(&self, known_vault_paths: &[PathBuf]) -> Result<Vec<MountEntry>> {
        let state = self.load_internal()?;

        let orphans: Vec<MountEntry> = state
            .mounts
            .into_iter()
            .filter(|m| {
                // Process must be dead
                if is_process_alive(m.pid) {
                    return false;
                }
                // If we have known vault paths, only include matching ones
                // Otherwise include all orphans
                known_vault_paths.is_empty() || known_vault_paths.iter().any(|p| p == &m.vault_path)
            })
            .collect();

        Ok(orphans)
    }
}

/// Check if a process is alive.
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    pid > 0
        && matches!(
            kill(Pid::from_raw(pid), None),
            Ok(()) | Err(nix::errno::Errno::EPERM)
        )
}

#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL
        .run_with_timeout(std::time::Duration::from_secs(5), move || {
            std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
                .stdin(std::process::Stdio::null())
                .output()
        })
        .map(|output| tasklist_reports_alive(pid, output.status.success(), &output.stdout))
        .unwrap_or(true)
}

#[cfg(any(windows, test))]
fn tasklist_reports_alive(pid: u32, success: bool, output: &[u8]) -> bool {
    // Inspection failure is not evidence that the process is dead.
    if !success {
        return true;
    }
    let Ok(output) = std::str::from_utf8(output) else {
        return true;
    };
    output.lines().any(|line| {
        line.strip_prefix('"')
            .and_then(|line| line.split_once("\",\""))
            .and_then(|(_, fields)| fields.split('"').next())
            .and_then(|value| value.parse::<u32>().ok())
            == Some(pid)
    })
}

#[cfg(any(windows, test))]
fn windows_mount_path(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    let text = text
        .strip_prefix(r"\\?\")
        .unwrap_or(text)
        .trim_end_matches(['/', '\\']);
    let bytes = text.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        PathBuf::from(format!("{}:", (bytes[0] as char).to_ascii_uppercase()))
    } else {
        path.to_path_buf()
    }
}

fn mount_comparison_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        windows_mount_path(path)
    }
    #[cfg(not(windows))]
    {
        oxcrypt_mount::TimeoutFs::default()
            .canonicalize(path)
            .map(|resolved| oxcrypt_mount::normalize_mount_path(&resolved))
            .unwrap_or_else(|_| oxcrypt_mount::normalize_mount_path(path))
    }
}

#[cfg(not(any(unix, windows)))]
pub fn is_process_alive(_pid: u32) -> bool {
    true
}

/// Get system mounts (canonicalized paths).
fn get_system_mounts() -> Result<std::collections::HashSet<PathBuf>> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mounts = oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL
            .run_with_timeout(std::time::Duration::from_secs(5), || {
                oxcrypt_mount::get_system_mounts_detailed().map_err(std::io::Error::other)
            })?;
        Ok(mounts
            .into_iter()
            .map(|mount| oxcrypt_mount::normalize_mount_path(&mount.mountpoint))
            .collect())
    }
    #[cfg(target_os = "windows")]
    {
        let output = oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL
            .run_with_timeout(std::time::Duration::from_secs(5), || {
                std::process::Command::new("net").arg("use").output()
            })?;
        anyhow::ensure!(
            output.status.success(),
            "net use failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .filter(|part| part.len() == 2 && part.ends_with(':'))
            .map(|part| windows_mount_path(Path::new(part)))
            .collect())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Ok(std::collections::HashSet::new())
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::mount_state::{DesktopMountState, MountEntry, MountState};

    #[test]
    fn desktop_writes_preserve_cli_server_locations() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = DesktopMountState {
            state_path: temporary.path().join("mounts.json"),
            lock_path: temporary.path().join("mounts.lock"),
        };
        let mut server =
            MountEntry::new_gui_mount("/vault".into(), "/logical-location".into(), "webdav");
        server.display_location = Some("http://127.0.0.1:12345".into());
        server.is_daemon = true;
        manager.add_mount(server).unwrap();
        manager
            .add_mount(MountEntry::new_gui_mount(
                "/other-vault".into(),
                "/other-mount".into(),
                "fuse",
            ))
            .unwrap();
        let state: MountState =
            serde_json::from_slice(&std::fs::read(&manager.state_path).unwrap()).unwrap();
        assert_eq!(
            state.mounts[0].display_location.as_deref(),
            Some("http://127.0.0.1:12345")
        );
        assert!(state.mounts[0].is_server_only());
        assert!(state.mounts[1].display_location.is_none());
    }

    #[test]
    fn failed_desktop_state_write_is_not_reported_as_success() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = DesktopMountState {
            state_path: temporary.path().join("mounts.json"),
            lock_path: temporary.path().join("mounts.lock"),
        };
        let result = manager.with_lock(|_| {
            std::fs::create_dir(&manager.state_path)?;
            Ok(())
        });
        assert!(result.is_err());
    }

    #[test]
    fn gui_handle_location_is_preserved_and_recovers_without_an_os_mount() {
        struct ServerHandle(std::path::PathBuf);
        impl oxcrypt_mount::MountHandle for ServerHandle {
            fn mountpoint(&self) -> &std::path::Path {
                &self.0
            }
            fn display_location(&self) -> Option<String> {
                Some("http://127.0.0.1:23456".into())
            }
            fn unmount(self: Box<Self>) -> Result<(), oxcrypt_mount::MountError> {
                Ok(())
            }
            fn force_unmount(self: Box<Self>) -> Result<(), oxcrypt_mount::MountError> {
                Ok(())
            }
        }
        let temporary = tempfile::tempdir().unwrap();
        let manager = DesktopMountState {
            state_path: temporary.path().join("mounts.json"),
            lock_path: temporary.path().join("mounts.lock"),
        };
        let vault = temporary.path().join("vault");
        let handle = ServerHandle(temporary.path().join("absent-mount"));
        let entry = MountEntry::from_gui_handle(vault.clone(), "webdav", &handle);
        assert!(entry.is_server_only());
        manager.add_mount(entry).unwrap();
        assert_eq!(manager.find_our_active_mounts().unwrap().len(), 1);
        assert_eq!(
            manager
                .find_active_mount_for_vault(&vault)
                .unwrap()
                .unwrap()
                .display_location
                .as_deref(),
            Some("http://127.0.0.1:23456")
        );
        manager
            .with_lock(|state| {
                state.mounts[0].pid = u32::MAX;
                Ok(())
            })
            .unwrap();
        assert!(
            manager
                .find_active_mount_for_vault(&vault)
                .unwrap()
                .is_none()
        );
        let orphan = manager
            .find_orphaned_mounts(&[vault])
            .unwrap()
            .pop()
            .unwrap();
        assert!(orphan.is_server_only());
    }

    #[test]
    fn windows_drive_comparison_and_unknown_process_state_are_conservative() {
        use std::path::{Path, PathBuf};
        for spelling in ["X:", "x:/", "X:\\", r"\\?\x:\"] {
            assert_eq!(
                crate::backend::mount_state::windows_mount_path(Path::new(spelling)),
                PathBuf::from("X:")
            );
        }
        assert_eq!(
            crate::backend::mount_state::windows_mount_path(Path::new(r"X:\folder")),
            PathBuf::from(r"X:\folder")
        );
        assert!(crate::backend::mount_state::tasklist_reports_alive(
            42, false, b""
        ));
        assert!(crate::backend::mount_state::tasklist_reports_alive(
            42,
            true,
            &[0xff]
        ));
        assert!(crate::backend::mount_state::tasklist_reports_alive(
            42,
            true,
            b"\"odd,name.exe\",\"42\",\"Console\""
        ));
        assert!(!crate::backend::mount_state::tasklist_reports_alive(
            42,
            true,
            b"\"other.exe\",\"142\",\"Console\""
        ));
        assert!(!crate::backend::mount_state::tasklist_reports_alive(
            42,
            true,
            b"INFO: No tasks are running which match the specified criteria."
        ));
    }

    #[test]
    fn gui_registration_cleans_up_duplicate_and_preserves_cli_owner() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        struct NewHandle {
            path: std::path::PathBuf,
            stopped: Arc<AtomicBool>,
        }
        impl oxcrypt_mount::MountHandle for NewHandle {
            fn mountpoint(&self) -> &std::path::Path {
                &self.path
            }
            fn display_location(&self) -> Option<String> {
                Some("http://127.0.0.1:23456".into())
            }
            fn unmount(self: Box<Self>) -> Result<(), oxcrypt_mount::MountError> {
                self.stopped.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn force_unmount(self: Box<Self>) -> Result<(), oxcrypt_mount::MountError> {
                self.unmount()
            }
        }
        let temporary = tempfile::tempdir().unwrap();
        let state_path = temporary.path().join("mounts.json");
        let manager = DesktopMountState {
            state_path: state_path.clone(),
            lock_path: temporary.path().join("mounts.lock"),
        };
        let mountpoint = temporary.path().join("logical-mountpoint");
        let mut cli_entry = MountEntry::new_gui_mount(
            temporary.path().join("cli-vault"),
            mountpoint.clone(),
            "webdav",
        );
        cli_entry.is_daemon = true;
        cli_entry.display_location = Some("http://127.0.0.1:12345".into());
        let owner = cli_entry.id.clone();
        manager.add_mount(cli_entry).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let result = crate::backend::register_gui_mount(
            Ok(manager),
            &temporary.path().join("gui-vault"),
            "webdav",
            Box::new(NewHandle {
                path: mountpoint,
                stopped: Arc::clone(&stopped),
            }),
        );
        assert!(result.is_err());
        assert!(stopped.load(Ordering::SeqCst));
        let state: MountState =
            serde_json::from_slice(&std::fs::read(state_path).unwrap()).unwrap();
        assert_eq!(state.mounts.len(), 1);
        assert_eq!(state.mounts[0].id, owner);
        assert_eq!(
            state.mounts[0].display_location.as_deref(),
            Some("http://127.0.0.1:12345")
        );
    }
}
