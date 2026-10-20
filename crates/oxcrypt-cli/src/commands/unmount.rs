//! Unmount command - unmount a previously mounted Cryptomator vault.
//!
//! Uses platform-specific tools:
//! - macOS: `umount` or `diskutil unmount`
//! - Linux: `fusermount -u` or `umount`
//!
//! For daemon mounts, attempts graceful shutdown via SIGTERM before
//! falling back to platform unmount tools.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tracing::instrument;

use crate::state::{MountStateManager, is_process_alive};

#[derive(ClapArgs, Clone)]
pub struct Args {
    /// Directory where the vault is mounted
    pub mountpoint: PathBuf,

    /// Force unmount even if the filesystem is busy
    #[arg(short, long)]
    pub force: bool,
}

#[instrument(level = "info", name = "cmd::unmount", skip_all, fields(mountpoint = %args.mountpoint.display(), force = args.force))]
pub fn execute(args: &Args) -> Result<()> {
    let mountpoint = &args.mountpoint;

    // Server-only WebDAV entries have a URL but no filesystem mountpoint.
    let manager = MountStateManager::new()?;
    let mount_entry = manager.find_by_mountpoint(mountpoint)?;
    if mount_entry.is_none() && !oxcrypt_mount::TimeoutFs::default().exists(mountpoint) {
        anyhow::bail!("Mountpoint does not exist: {}", mountpoint.display());
    }

    // If this is a daemon mount with a live process, try graceful shutdown first
    if let Some(ref entry) = mount_entry
        && entry.is_daemon
        && is_process_alive(entry.pid)
    {
        eprintln!(
            "Sending shutdown signal to daemon process (PID: {})...",
            entry.pid
        );

        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;

            let raw_pid = i32::try_from(entry.pid).context("Invalid daemon process ID")?;
            anyhow::ensure!(raw_pid > 0, "Invalid daemon process ID");
            let pid = Pid::from_raw(raw_pid);

            // Send SIGTERM for graceful shutdown
            if kill(pid, Signal::SIGTERM).is_ok() {
                // Wait up to 3 seconds for graceful shutdown
                for _ in 0..30 {
                    std::thread::sleep(Duration::from_millis(100));
                    if !is_process_alive(entry.pid) {
                        eprintln!("Daemon process exited gracefully");
                        // Clean up state file
                        manager.remove_by_mountpoint(mountpoint)?;
                        // Check if mountpoint is still mounted
                        if entry.is_server_only() || !is_still_mounted(mountpoint) {
                            eprintln!("Unmounted successfully");
                            return Ok(());
                        }
                        break;
                    }
                }

                // If still alive after 3 seconds, send SIGKILL
                if is_process_alive(entry.pid) {
                    eprintln!("Daemon not responding to SIGTERM, sending SIGKILL...");
                    if kill(pid, Signal::SIGKILL).is_ok() {
                        // Wait briefly for SIGKILL to take effect
                        for _ in 0..10 {
                            std::thread::sleep(Duration::from_millis(100));
                            if !is_process_alive(entry.pid) {
                                eprintln!("Daemon process killed");
                                manager.remove_by_mountpoint(mountpoint)?;
                                break;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            let mut command = Command::new("taskkill");
            command.args(["/PID", &entry.pid.to_string(), "/T", "/F"]);
            let output = crate::state::command_output(command).context("Failed to stop daemon")?;
            anyhow::ensure!(
                output.status.success(),
                "Failed to stop daemon: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    if let Some(entry) = &mount_entry
        && entry.is_server_only()
    {
        anyhow::ensure!(
            !is_process_alive(entry.pid),
            "WebDAV process {} is still running",
            entry.pid
        );
        manager.remove_mount(&entry.id)?;
        eprintln!("WebDAV server stopped");
        return Ok(());
    }

    eprintln!("Unmounting {}...", mountpoint.display());

    #[cfg(target_os = "macos")]
    {
        unmount_macos(mountpoint, args.force)?;
    }

    #[cfg(target_os = "linux")]
    {
        unmount_linux(mountpoint, args.force)?;
    }

    #[cfg(target_os = "windows")]
    {
        unmount_windows(mountpoint, args.force)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        anyhow::bail!("Unmount is not supported on this platform");
    }

    // Remove from state file after successful unmount
    manager.remove_by_mountpoint(mountpoint)?;

    eprintln!("Unmounted successfully");
    Ok(())
}

/// Check if a path is still mounted (platform-specific).
#[allow(dead_code)]
fn is_still_mounted(mountpoint: &PathBuf) -> bool {
    if let Ok(system_mounts) = crate::state::get_system_mounts() {
        let canonical = oxcrypt_mount::TimeoutFs::default()
            .canonicalize(mountpoint)
            .unwrap_or_else(|_| mountpoint.clone());
        system_mounts.contains(&canonical)
    } else {
        // If we can't check, assume it's still mounted
        true
    }
}

#[cfg(target_os = "macos")]
fn unmount_macos(mountpoint: &PathBuf, force: bool) -> Result<()> {
    // Try diskutil first (handles FUSE and FSKit)
    let mut cmd = Command::new("diskutil");
    cmd.arg("unmount");
    if force {
        cmd.arg("force");
    }
    cmd.arg(mountpoint);

    let output = crate::state::command_output(cmd).context("Failed to execute diskutil unmount")?;

    if output.status.success() {
        return Ok(());
    }

    // Fall back to umount
    let mut cmd = Command::new("umount");
    if force {
        cmd.arg("-f");
    }
    cmd.arg(mountpoint);

    let output = crate::state::command_output(cmd).context("Failed to execute umount")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to unmount: {}", stderr.trim());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn unmount_linux(mountpoint: &PathBuf, force: bool) -> Result<()> {
    // Try fusermount first (for FUSE mounts)
    let mut cmd = Command::new("fusermount");
    cmd.arg("-u");
    if force {
        cmd.arg("-z"); // lazy unmount
    }
    cmd.arg(mountpoint);

    let output = crate::state::command_output(cmd);

    if let Ok(output) = output
        && output.status.success()
    {
        return Ok(());
    }

    // Fall back to umount
    let mut cmd = Command::new("umount");
    if force {
        cmd.arg("-l"); // lazy unmount
    }
    cmd.arg(mountpoint);

    let output = crate::state::command_output(cmd).context("Failed to execute umount")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to unmount: {}", stderr.trim());
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn unmount_windows(mountpoint: &PathBuf, _force: bool) -> Result<()> {
    // On Windows, WebDAV mounts are typically mapped as network drives
    // Try `net use /delete` for network drives
    let mountpoint_str = mountpoint.to_string_lossy();

    // Check if it looks like a drive letter (e.g., "Z:" or "Z:\")
    if mountpoint_str.len() >= 2 && mountpoint_str.chars().nth(1) == Some(':') {
        let drive = &mountpoint_str[..2];
        let mut cmd = Command::new("net");
        cmd.args(["use", drive, "/delete", "/yes"]);

        let output = crate::state::command_output(cmd).context("Failed to execute net use")?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // If it's not a network drive, the error is expected
        if !stderr.contains("network connection could not be found") {
            anyhow::bail!("Failed to unmount: {}", stderr.trim());
        }
    }

    // For non-drive paths or if net use failed, inform the user
    anyhow::bail!(
        "Cannot unmount {}: On Windows, unmount network drives via File Explorer or use 'net use X: /delete'",
        mountpoint.display()
    );
}
