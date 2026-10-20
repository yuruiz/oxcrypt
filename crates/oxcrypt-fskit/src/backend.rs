//! FSKit mount backend implementation.
//!
//! This module provides a `MountBackend` implementation for FSKit,
//! allowing CLI and desktop apps to mount Cryptomator vaults using
//! Apple's native FSKit framework (macOS 27+).

use std::path::Path;
use std::sync::Arc;

use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle, MountOptions};
use secrecy::SecretString;

use crate::xpc::{FskitClient, FskitError, MountInfo};

const EXPERIMENTAL_SETTING: &str = "OXCRYPT_EXPERIMENTAL_FSKIT";

fn experimental_enabled(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

/// Thread-safe wrapper for FskitClient.
///
/// # Safety
///
/// NSXPCConnection is documented as thread-safe by Apple. All methods
/// can be called from any thread. The underlying Mach ports are also
/// thread-safe. We wrap the client to provide Send + Sync.
struct ThreadSafeClient(FskitClient);

// SAFETY: NSXPCConnection is thread-safe per Apple documentation.
// All public methods synchronize internally via the XPC runtime.
unsafe impl Send for ThreadSafeClient {}
unsafe impl Sync for ThreadSafeClient {}

impl std::ops::Deref for ThreadSafeClient {
    type Target = FskitClient;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// FSKit-based mount backend for macOS 27+.
///
/// This backend uses Apple's FSKit framework via XPC communication
/// with the FSKit extension. It provides native filesystem integration
/// without requiring kernel extensions like macFUSE.
///
/// # Availability
///
/// The FSKit backend requires:
/// - macOS 27 or later
/// - The FSKit extension to be installed and enabled in System Settings
///
/// Use [`is_available()`](MountBackend::is_available) to check before attempting to mount.
pub struct FskitBackend {
    // No cached state - connections are created per-mount for simplicity
}

impl FskitBackend {
    /// Create a new FSKit backend.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for FskitBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MountBackend for FskitBackend {
    fn name(&self) -> &'static str {
        "FSKit"
    }

    fn id(&self) -> &'static str {
        "fskit"
    }

    fn is_available(&self) -> bool {
        experimental_enabled(std::env::var_os(EXPERIMENTAL_SETTING).as_deref())
            && FskitClient::is_available()
    }

    fn unavailable_reason(&self) -> Option<String> {
        if !experimental_enabled(std::env::var_os(EXPERIMENTAL_SETTING).as_deref()) {
            return Some(format!(
                "Native FSKit mounting is experimental and disabled. For development, set {EXPERIMENTAL_SETTING}=1; a signed, enabled extension and running host service are also required."
            ));
        }
        if self.is_available() {
            return None;
        }

        // Check macOS version first
        if !check_macos_version() {
            return Some("Requires macOS 27 or later".to_string());
        }

        // Extension not installed/enabled
        Some(
            "FSKit extension not available. \
             Enable in System Settings → General → Login Items & Extensions → File System Extensions. \
             Note: The extension must be running (activated by FSKit) before CLI can connect."
                .to_string(),
        )
    }

    fn backend_type(&self) -> BackendType {
        BackendType::FSKit
    }

    fn description(&self) -> &'static str {
        "Apple's native FSKit framework (macOS 27+)"
    }

    fn mount(
        &self,
        _vault_id: &str,
        vault_path: &Path,
        password: &str,
        _mountpoint: &Path,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        if !self.is_available() {
            return Err(MountError::BackendUnavailable(
                self.unavailable_reason()
                    .unwrap_or_else(|| "FSKit backend unavailable".into()),
            ));
        }
        // We need a mutable reference to ensure client
        // This is a bit awkward - ideally we'd use interior mutability
        // For now, create a new client for each mount
        let client = FskitClient::connect().map_err(|e| match e {
            FskitError::ExtensionNotAvailable => {
                MountError::BackendUnavailable("FSKit extension not available".to_string())
            }
            e => MountError::BackendUnavailable(e.to_string()),
        })?;

        let password = SecretString::from(password.to_string());

        let info = client.mount(vault_path, &password).map_err(|e| match e {
            FskitError::InvalidVault(path) => {
                MountError::FilesystemCreation(format!("Invalid vault: {}", path.display()))
            }
            FskitError::AuthFailed => MountError::FilesystemCreation(
                "Authentication failed (wrong password?)".to_string(),
            ),
            FskitError::MountFailed(msg) => MountError::Mount(std::io::Error::other(msg)),
            e => MountError::Mount(std::io::Error::other(e.to_string())),
        })?;

        Ok(Box::new(FskitMountHandle {
            client: Arc::new(ThreadSafeClient(client)),
            info,
            active: true,
        }))
    }

    fn mount_with_options(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
        _options: &MountOptions,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        // FSKit doesn't support mount options yet - ignore them
        self.mount(vault_id, vault_path, password, mountpoint)
    }
}

/// Handle to a mounted FSKit filesystem.
///
/// The filesystem is automatically unmounted when this handle is dropped.
pub struct FskitMountHandle {
    client: Arc<ThreadSafeClient>,
    info: MountInfo,
    active: bool,
}

impl MountHandle for FskitMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.info.mountpoint
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        self.client
            .unmount(&self.info.mountpoint)
            .map_err(|e| MountError::UnmountFailed(e.to_string()))?;
        self.active = false;
        Ok(())
    }

    fn force_unmount(self: Box<Self>) -> Result<(), MountError> {
        // FSKit unmount is always "forceful" from our perspective
        self.unmount()
    }

    // TODO: Implement stats() by converting XPC VaultStats to oxcrypt_mount::VaultStats.
    // Currently uses default (returns None) because oxcrypt_mount::VaultStats uses
    // atomics for real-time updates, while XPC provides snapshots.
}

impl Drop for FskitMountHandle {
    fn drop(&mut self) {
        // Best-effort unmount on drop
        if self.active {
            let _ = self.client.unmount(&self.info.mountpoint);
        }
    }
}

/// Check if we're running on macOS 27+.
fn check_macos_version() -> bool {
    use std::process::Command;

    let output = Command::new("sw_vers").arg("-productVersion").output().ok();

    let Some(output) = output else {
        return false;
    };

    if !output.status.success() {
        return false;
    }

    let version_str = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = version_str.trim().split('.').collect();

    if parts.len() < 2 {
        return false;
    }

    let major: i64 = parts[0].parse().unwrap_or(0);

    major >= 27
}

#[cfg(test)]
mod readiness_tests {
    use crate::backend::experimental_enabled;
    use std::ffi::OsStr;
    #[test]
    fn experimental_backend_requires_explicit_opt_in() {
        assert!(!experimental_enabled(None));
        assert!(!experimental_enabled(Some(OsStr::new("0"))));
        assert!(experimental_enabled(Some(OsStr::new("1"))));
    }
}
