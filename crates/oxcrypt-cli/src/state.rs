//! Mount state management for tracking active daemon mounts.
//!
//! State is persisted to `~/.config/oxcrypt/mounts.json` (Linux/macOS)
//! or `%APPDATA%\oxcrypt\oxcrypt\mounts.json` (Windows).
//!
//! # Concurrency Safety
//!
//! The state file is protected by advisory file locking to prevent races
//! between multiple CLI/GUI instances. Use `with_lock()` for safe
//! read-modify-write operations.

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
    /// URL or other backend location when no OS mount was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_location: Option<String>,
    /// Backend used (fuse, fskit, webdav, nfs)
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

    pub fn location(&self) -> String {
        self.display_location
            .clone()
            .unwrap_or_else(|| self.mountpoint.display().to_string())
    }

    /// Create a new mount entry with auto-generated ID and current timestamp.
    #[allow(dead_code)]
    pub fn new(
        vault_path: PathBuf,
        mountpoint: PathBuf,
        backend: impl Into<String>,
        pid: u32,
        is_daemon: bool,
        socket_path: Option<PathBuf>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vault_path,
            mountpoint,
            display_location: None,
            backend: backend.into(),
            pid,
            started_at: Utc::now(),
            is_daemon,
            socket_path,
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

/// Manages the mount state file.
pub struct MountStateManager {
    state_path: PathBuf,
    lock_path: PathBuf,
}

/// Default timeout for acquiring the state file lock.
const LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl MountStateManager {
    /// Create a new state manager, initializing the config directory if needed.
    pub fn new() -> Result<Self> {
        let config_dir = if let Some(dir) = config_dir_override() {
            dir
        } else {
            let dirs = directories::ProjectDirs::from("com", "oxcrypt", "oxcrypt")
                .context("Failed to determine config directory")?;
            dirs.config_dir().to_path_buf()
        };

        // Ensure config directory exists
        std::fs::create_dir_all(&config_dir)
            .with_context(|| format!("Failed to create config dir: {}", config_dir.display()))?;

        let state_path = config_dir.join("mounts.json");
        let lock_path = config_dir.join("mounts.lock");

        Ok(Self {
            state_path,
            lock_path,
        })
    }

    /// Get the path to the state file.
    #[allow(dead_code)]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Execute a function while holding an exclusive lock on the state file.
    ///
    /// This prevents races between multiple CLI/GUI instances when modifying state.
    /// The lock is automatically released when the function returns.
    ///
    /// # Example
    ///
    /// ```ignore
    /// state_manager.with_lock(|state| {
    ///     state.mounts.push(new_entry);
    ///     Ok(())
    /// })?;
    /// ```
    pub fn with_lock<F, R>(&self, f: F) -> Result<R>
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

        // Try to acquire lock with timeout using polling
        let start = std::time::Instant::now();
        loop {
            match lock_file.try_lock_exclusive() {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > LOCK_TIMEOUT {
                        anyhow::bail!(
                            "Timed out waiting for state file lock after {LOCK_TIMEOUT:?}. \
                             Another oxcrypt process may be holding the lock."
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Failed to lock: {}", self.lock_path.display()));
                }
            }
        }

        // Load state, execute function, save if modified
        let mut state = self.load_internal()?;
        let result = f(&mut state)?;
        self.save_internal(&state)?;
        Ok(result)
    }

    /// Internal load without locking (for use within with_lock).
    fn load_internal(&self) -> Result<MountState> {
        if !self.state_path.exists() {
            return Ok(MountState::default());
        }

        let contents = std::fs::read_to_string(&self.state_path)
            .with_context(|| format!("Failed to read state file: {}", self.state_path.display()))?;

        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file: {}", self.state_path.display()))
    }

    /// Internal save without locking (for use within with_lock).
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
        result.with_context(|| format!("Failed to write state file: {}", self.state_path.display()))
    }

    /// Load the current state, returning default if file doesn't exist.
    pub fn load(&self) -> Result<MountState> {
        if !self.state_path.exists() {
            return Ok(MountState::default());
        }

        let contents = std::fs::read_to_string(&self.state_path)
            .with_context(|| format!("Failed to read state file: {}", self.state_path.display()))?;

        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file: {}", self.state_path.display()))
    }

    /// Save the state to disk.
    #[allow(dead_code)]
    pub fn save(&self, state: &MountState) -> Result<()> {
        self.with_lock(|current| {
            *current = state.clone();
            Ok(())
        })
    }

    /// Add a new mount entry (thread-safe with file locking).
    #[allow(dead_code)]
    pub fn add_mount(&self, entry: MountEntry) -> Result<()> {
        self.with_lock(|state| {
            anyhow::ensure!(
                !state
                    .mounts
                    .iter()
                    .any(|current| current.mountpoint == entry.mountpoint
                        && is_process_alive(current.pid)),
                "Mountpoint {} already has a running mount process",
                entry.mountpoint.display()
            );
            state.mounts.retain(|m| m.mountpoint != entry.mountpoint);

            state.mounts.push(entry);
            Ok(())
        })
    }

    /// Remove a mount entry by ID (thread-safe with file locking).
    #[allow(dead_code)]
    pub fn remove_mount(&self, id: &str) -> Result<bool> {
        self.with_lock(|state| {
            let initial_len = state.mounts.len();
            state.mounts.retain(|m| m.id != id);
            Ok(state.mounts.len() != initial_len)
        })
    }

    /// Remove a mount entry by mountpoint path (thread-safe with file locking).
    pub fn remove_by_mountpoint(&self, mountpoint: &Path) -> Result<bool> {
        let mountpoint = mountpoint.to_path_buf();
        self.with_lock(|state| {
            let initial_len = state.mounts.len();
            state.mounts.retain(|m| m.mountpoint != mountpoint);
            Ok(state.mounts.len() != initial_len)
        })
    }

    /// Find a mount entry by mountpoint path.
    #[allow(dead_code)]
    pub fn find_by_mountpoint(&self, mountpoint: &Path) -> Result<Option<MountEntry>> {
        let state = self.load()?;
        Ok(state
            .mounts
            .into_iter()
            .find(|m| m.mountpoint == mountpoint))
    }

    /// List all mount entries from the state file.
    ///
    /// This returns a snapshot of the current mounts. The state may change
    /// after this returns if another process modifies it.
    pub fn list_mounts(&self) -> Result<Vec<MountEntry>> {
        let state = self.load()?;
        Ok(state.mounts)
    }

    /// Remove stale entries (process dead or not in system mounts).
    /// Returns the entries that were removed.
    /// Thread-safe with file locking.
    pub fn cleanup_stale(&self) -> Result<Vec<MountEntry>> {
        self.with_lock(|state| {
            let (active, stale) = partition_entries(std::mem::take(&mut state.mounts))?;
            state.mounts = active;
            Ok(stale)
        })
    }

    /// Validate entries and partition into active vs stale.
    pub fn validate_entries(&self) -> Result<(Vec<MountEntry>, Vec<MountEntry>)> {
        partition_entries(self.load()?.mounts)
    }
}

fn partition_entries(entries: Vec<MountEntry>) -> Result<(Vec<MountEntry>, Vec<MountEntry>)> {
    let system_mounts = if entries
        .iter()
        .any(|entry| !entry.is_server_only() && is_process_alive(entry.pid))
    {
        get_system_mounts()?
    } else {
        std::collections::HashSet::new()
    };
    Ok(entries.into_iter().partition(|entry| {
        is_process_alive(entry.pid)
            && (entry.is_server_only() || {
                let path = mount_comparison_path(&entry.mountpoint);
                system_mounts.contains(&path)
            })
    }))
}

/// Bound subprocess waits with the shared worker limit used for ghost mounts.
/// A stuck kernel operation must not block the CLI indefinitely.
pub fn command_output(mut command: std::process::Command) -> std::io::Result<std::process::Output> {
    command.stdin(std::process::Stdio::null());
    oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL
        .run_with_timeout(std::time::Duration::from_secs(10), move || command.output())
}

fn config_dir_override() -> Option<PathBuf> {
    let dir = std::env::var_os("OXCRYPT_CONFIG_DIR")?;
    if dir.is_empty() {
        None
    } else {
        Some(PathBuf::from(dir))
    }
}

/// Check if a process with the given PID is alive.
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    // kill(pid, 0) checks if process exists without sending a signal
    // Returns Ok(()) if process exists, Err with ESRCH if it doesn't
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    matches!(
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
    // Assume alive on unsupported platforms
    true
}

/// Get the set of currently mounted filesystem paths.
///
/// Paths are canonicalized to handle symlinks (e.g., /tmp -> /private/tmp on macOS).
pub fn get_system_mounts() -> Result<std::collections::HashSet<PathBuf>> {
    let mut mounts = std::collections::HashSet::new();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        for mount in oxcrypt_mount::get_system_mounts_detailed()? {
            mounts.insert(mount_comparison_path(&mount.mountpoint));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Parse `net use` for network drives
        let mut command = std::process::Command::new("net");
        command.arg("use");
        let output = command_output(command).context("Failed to run net use command")?;
        anyhow::ensure!(
            output.status.success(),
            "net use failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Look for drive letters like "OK           Z:        \\server\share"
            let parts: Vec<&str> = line.split_whitespace().collect();
            for part in parts {
                if part.len() == 2 && part.ends_with(':') {
                    mounts.insert(windows_mount_path(Path::new(part)));
                }
            }
        }
    }

    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use crate::state::*;

    #[test]
    fn test_mount_entry_creation() {
        let entry = MountEntry::new(
            PathBuf::from("/home/user/vault"),
            PathBuf::from("/mnt/vault"),
            "fuse",
            12345,
            true,
            None,
        );
        assert_ne!(entry.id, "");
        assert_eq!(entry.backend, "fuse");
        assert_eq!(entry.pid, 12345);
        assert!(entry.is_daemon);
        assert!(entry.socket_path.is_none());
    }

    #[test]
    fn test_state_serialization() {
        let mut state = MountState::default();
        state.mounts.push(MountEntry::new(
            PathBuf::from("/vault"),
            PathBuf::from("/mnt"),
            "fuse",
            1234,
            false,
            None,
        ));

        let json = serde_json::to_string(&state).unwrap();
        let loaded: MountState = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.mounts.len(), 1);
        assert_eq!(loaded.mounts[0].backend, "fuse");
    }

    #[test]
    #[cfg(unix)]
    fn test_is_process_alive() {
        // Current process should be alive
        let pid = std::process::id();
        assert!(is_process_alive(pid));

        // Very high PID should not exist
        assert!(!is_process_alive(u32::MAX - 1));
    }

    fn isolated_manager(dir: &Path) -> MountStateManager {
        MountStateManager {
            state_path: dir.join("mounts.json"),
            lock_path: dir.join("mounts.lock"),
        }
    }

    #[test]
    fn old_state_without_display_location_remains_readable() {
        let mut entry = serde_json::to_value(MountEntry::new(
            "/vault".into(),
            "/mount".into(),
            "webdav",
            42,
            true,
            None,
        ))
        .unwrap();
        entry.as_object_mut().unwrap().remove("display_location");
        let loaded: MountEntry = serde_json::from_value(entry).unwrap();
        assert!(loaded.display_location.is_none());
        assert!(!loaded.is_server_only());
        assert_eq!(loaded.location(), "/mount");
    }

    #[test]
    fn live_server_only_mount_survives_validation_and_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let manager = isolated_manager(dir.path());
        let mut entry = MountEntry::new(
            dir.path().join("vault"),
            dir.path().join("absent-mount"),
            "webdav",
            std::process::id(),
            true,
            None,
        );
        entry.display_location = Some("http://127.0.0.1:43210".to_owned());
        manager.add_mount(entry.clone()).unwrap();
        assert!(
            manager.add_mount(entry).is_err(),
            "a live mount must not be overwritten"
        );
        let (active, stale) = manager.validate_entries().unwrap();
        assert_eq!(active.len(), 1);
        assert!(stale.is_empty());
        assert_eq!(active[0].location(), "http://127.0.0.1:43210");
        assert!(manager.cleanup_stale().unwrap().is_empty());
        assert_eq!(manager.list_mounts().unwrap().len(), 1);
        manager
            .with_lock(|state| {
                state.mounts[0].pid = u32::MAX;
                Ok(())
            })
            .unwrap();
        assert_eq!(manager.cleanup_stale().unwrap().len(), 1);
    }

    #[test]
    fn state_write_failure_is_reported_and_failed_mutations_are_not_saved() {
        let dir = tempfile::tempdir().unwrap();
        let manager = isolated_manager(dir.path());
        let result: Result<()> = manager.with_lock(|state| {
            state.version = 99;
            anyhow::bail!("mutation failed")
        });
        assert!(result.is_err());
        assert!(!manager.state_path.exists());
        let result = manager.with_lock(|_| {
            std::fs::create_dir(&manager.state_path)?;
            Ok(())
        });
        assert!(
            result.is_err(),
            "save failure must not be returned as success"
        );
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "tmp")
        }));
    }

    #[test]
    fn windows_drive_comparison_and_unknown_process_state_are_conservative() {
        use std::path::{Path, PathBuf};
        for spelling in ["X:", "x:/", "X:\\", r"\\?\x:\"] {
            assert_eq!(
                crate::state::windows_mount_path(Path::new(spelling)),
                PathBuf::from("X:")
            );
        }
        assert_eq!(
            crate::state::windows_mount_path(Path::new(r"X:\folder")),
            PathBuf::from(r"X:\folder")
        );
        assert!(crate::state::tasklist_reports_alive(42, false, b""));
        assert!(crate::state::tasklist_reports_alive(42, true, &[0xff]));
        assert!(crate::state::tasklist_reports_alive(
            42,
            true,
            b"\"odd,name.exe\",\"42\",\"Console\""
        ));
        assert!(!crate::state::tasklist_reports_alive(
            42,
            true,
            b"\"other.exe\",\"142\",\"Console\""
        ));
        assert!(!crate::state::tasklist_reports_alive(
            42,
            true,
            b"INFO: No tasks are running which match the specified criteria."
        ));
    }
}
