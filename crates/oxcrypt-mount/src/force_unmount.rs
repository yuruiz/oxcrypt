//! Platform-specific force unmount utilities.
//!
//! This module provides utilities to forcibly unmount filesystems when
//! graceful unmount is not possible (e.g., stale mounts, crashed daemons).
//!
//! # Safety
//!
//! **IMPORTANT**: Callers must verify that the mount belongs to them before
//! calling these functions. These functions will attempt to unmount ANY path
//! without verification.
//!
//! Use `mount_markers::is_our_mount()` before calling `force_unmount()`.
//!
//! # Platform Support
//!
//! - **macOS**: Uses `diskutil unmount force`, falls back to `umount -f`
//! - **Linux**: Uses `fusermount -uz` (lazy unmount), falls back to `umount -l`
//! - **Other**: Returns an error (unsupported)

use std::path::Path;
use std::process::Command;

use anyhow::Result;

/// Force unmount a filesystem at the given path.
///
/// # Safety
///
/// **Caller must verify ownership** before calling this function!
/// Use `mount_markers::is_our_mount()` to verify the mount has our markers.
///
/// # Behavior
///
/// - On macOS: Tries `diskutil unmount force`, then `umount -f`
/// - On Linux: Tries `fusermount -uz`, then `umount -l`
/// - Other platforms: Returns error
///
/// # Errors
///
/// Returns an error if all unmount attempts fail.
pub fn force_unmount(mountpoint: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        force_unmount_macos(mountpoint)
    }

    #[cfg(target_os = "linux")]
    {
        force_unmount_linux(mountpoint)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!(
            "Force unmount not supported on this platform for {}",
            mountpoint.display()
        )
    }
}

/// Attempt a lazy/deferred unmount.
///
/// This immediately removes the mount from the namespace but allows
/// existing file handles to continue until they're closed.
///
/// # Safety
///
/// Same as `force_unmount` - caller must verify ownership.
pub fn lazy_unmount(mountpoint: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // macOS doesn't have true lazy unmount, use force unmount
        force_unmount_macos(mountpoint)
    }

    #[cfg(target_os = "linux")]
    {
        lazy_unmount_linux(mountpoint)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!(
            "Lazy unmount not supported on this platform for {}",
            mountpoint.display()
        )
    }
}

/// Each blocked command retains a shared pool slot until it actually exits.
/// Timing out the caller never creates an untracked command waiter.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn attempt_unmount(mountpoint: &Path, commands: &[(&str, &[&str])]) -> Result<()> {
    let mut errors = Vec::new();
    for (program, args) in commands {
        let program_name = (*program).to_owned();
        let arguments: Vec<_> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let path = mountpoint.to_path_buf();
        let result = crate::bounded_pool::BOUNDED_FS_POOL.run_with_timeout(
            std::time::Duration::from_secs(3),
            move || {
                Command::new(program_name)
                    .args(arguments)
                    .arg(path)
                    .stdin(std::process::Stdio::null())
                    .output()
            },
        );
        match result {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => errors.push(format!(
                "{program}: {} ({})",
                String::from_utf8_lossy(&output.stderr).trim(),
                output.status
            )),
            Err(error) => errors.push(format!("{program}: {error}")),
        }
    }
    anyhow::bail!(
        "Failed to unmount {}: {}",
        mountpoint.display(),
        errors.join("; ")
    )
}

#[cfg(target_os = "macos")]
fn force_unmount_macos(mountpoint: &Path) -> Result<()> {
    // Do not probe the mounted path: metadata calls can block on ghost mounts.
    attempt_unmount(
        mountpoint,
        &[("diskutil", &["unmount", "force"]), ("umount", &["-f"])],
    )
}

#[cfg(target_os = "linux")]
fn force_unmount_linux(mountpoint: &Path) -> Result<()> {
    attempt_unmount(
        mountpoint,
        &[
            ("fusermount", &["-uz"]),
            ("umount", &["-l"]),
            ("umount", &["-f"]),
        ],
    )
}

#[cfg(target_os = "linux")]
fn lazy_unmount_linux(mountpoint: &Path) -> Result<()> {
    attempt_unmount(mountpoint, &[("fusermount", &["-uz"]), ("umount", &["-l"])])
}

#[cfg(test)]
mod tests {
    use crate::force_unmount::force_unmount;
    use std::path::Path;

    #[test]
    fn test_force_unmount_nonexistent_path() {
        // Trying to unmount a path that isn't mounted should fail
        let result = force_unmount(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_err());
    }

    // Note: Actual unmount tests would require creating real mounts,
    // which is done in integration tests rather than unit tests.
}
