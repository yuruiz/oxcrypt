//! HTTP server lifecycle management for WebDAV.
//!
//! This module provides the HTTP server that serves WebDAV requests
//! and handles the server lifecycle (start, stop).

use crate::filesystem::CryptomatorWebDav;
use dav_server::{DavHandler, fakels::FakeLs};
use hyper::Request;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

/// Configuration for the WebDAV server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Port to bind to (0 = auto-assign).
    pub port: u16,
    /// Bind address.
    pub bind_address: std::net::IpAddr,
    /// Time allowed for active requests and pending writeback during shutdown.
    pub shutdown_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 0, // Auto-assign
            bind_address: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

/// A running WebDAV server instance.
pub struct WebDavServer {
    /// The actual bound address.
    pub addr: SocketAddr,
    /// Shutdown signal sender.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Server task handle.
    server_handle: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    filesystem: CryptomatorWebDav,
    shutdown_timeout: Duration,
    interrupted: Arc<AtomicBool>,
}

impl WebDavServer {
    /// Start a new WebDAV server.
    pub async fn start(
        fs: CryptomatorWebDav,
        config: ServerConfig,
    ) -> Result<Self, std::io::Error> {
        let addr = SocketAddr::new(config.bind_address, config.port);
        let listener = TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;

        info!(addr = %actual_addr, "Starting WebDAV server");

        // Build the DAV handler with FakeLs (minimal lock support for macOS/Windows)
        let dav_handler = DavHandler::builder()
            .filesystem(Box::new(fs.clone()))
            .locksystem(FakeLs::new())
            .build_handler();

        let dav_handler = Arc::new(dav_handler);

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let writeback = fs.clone();
        let shutdown_timeout = config.shutdown_timeout;
        let interrupted = Arc::new(AtomicBool::new(true));
        let interruption = Arc::clone(&interrupted);
        let server_handle = tokio::spawn(async move {
            let interrupted =
                run_server(listener, dav_handler, shutdown_rx, shutdown_timeout).await;
            interruption.store(interrupted, Ordering::Release);
            let result =
                tokio::time::timeout(shutdown_timeout, writeback.finish_writeback(interrupted))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "pending WebDAV writes did not drain; retry shutdown",
                        )
                    })?;
            if interrupted {
                let detail = result
                    .err()
                    .map_or_else(String::new, |error| format!(": {error}"));
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    format!("WebDAV requests were interrupted{detail}"),
                ))
            } else {
                result
            }
        });

        Ok(Self {
            addr: actual_addr,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
            filesystem: fs,
            shutdown_timeout,
            interrupted,
        })
    }

    /// Get the URL for this server.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop accepting requests, drain active requests, then persist or recover edits.
    /// On failure the server retains unarchived buffers and this method can be retried.
    pub async fn stop(&mut self) -> std::io::Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let result = if let Some(handle) = self.server_handle.as_mut() {
            let completion = handle.await;
            self.server_handle.take();
            completion.map_err(std::io::Error::other)?
        } else {
            tokio::time::timeout(
                self.shutdown_timeout,
                self.filesystem
                    .finish_writeback(self.interrupted.load(Ordering::Acquire)),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "pending WebDAV writes did not drain; retry shutdown",
                )
            })?
        };
        if result.is_ok() {
            info!("WebDAV server stopped");
        }
        result
    }

    /// Request graceful cleanup on drop while the owning runtime remains alive.
    /// Call stop().await to observe durability failures before dropping the runtime.
    fn stop_sync(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Dropping a JoinHandle detaches the cleanup task instead of aborting it.
        self.server_handle.take();
    }
}

impl Drop for WebDavServer {
    fn drop(&mut self) {
        self.stop_sync();
    }
}

/// Reject overlapping trees before downstream overwrite handling.
fn validate_copy_move_paths<B>(request: &Request<B>) -> Result<(), hyper::StatusCode> {
    use dav_server::davpath::DavPath;
    use hyper::StatusCode;
    let method = request.method().as_str();
    if method != "MOVE" && method != "COPY" {
        return Ok(());
    }
    let Some(destination) = request.headers().get("Destination") else {
        return Ok(());
    };
    let destination = destination.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
    let destination: hyper::Uri = destination.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let source = DavPath::new(request.uri().path()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let target = DavPath::new(destination.path()).map_err(|_| StatusCode::BAD_REQUEST)?;
    let source = source
        .as_bytes()
        .strip_suffix(b"/")
        .unwrap_or(source.as_bytes());
    let target = target
        .as_bytes()
        .strip_suffix(b"/")
        .unwrap_or(target.as_bytes());
    let descendant = |path: &[u8], parent: &[u8]| {
        path.strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with(b"/"))
    };
    // dav-server can recursively delete an overwritten destination before
    // calling the filesystem. Reject overlapping trees before that deletion.
    if source == target
        || descendant(source, target)
        || (method == "MOVE" && descendant(target, source))
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

async fn run_server(
    listener: TcpListener,
    handler: Arc<DavHandler>,
    mut shutdown: oneshot::Receiver<()>,
    timeout: Duration,
) -> bool {
    let mut connections = JoinSet::new();
    let (drain, drain_rx) = watch::channel(false);
    let mut interrupted = false;
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            result = connections.join_next(), if !connections.is_empty() => {
                if result.is_some_and(|result| result.is_err()) { interrupted = true; }
            },
            accepted = listener.accept() => {
                let (stream, peer_addr) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => { error!(%error, "Failed to accept connection"); continue; }
                };
                let handler = Arc::clone(&handler);
                let mut drain_rx = drain_rx.clone();
                connections.spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let handler = Arc::clone(&handler);
                        async move {
                            if let Err(status) = validate_copy_move_paths(&req) {
                                let mut response = hyper::Response::new(dav_server::body::Body::empty());
                                *response.status_mut() = status;
                                return Ok::<_, Infallible>(response);
                            }
                            Ok::<_, Infallible>(handler.handle(req).await)
                        }
                    });
                    let builder = auto::Builder::new(TokioExecutor::new());
                    let connection = builder.serve_connection(TokioIo::new(stream), service);
                    tokio::pin!(connection);
                    let result = tokio::select! {
                        result = &mut connection => result,
                        _ = drain_rx.changed() => {
                            connection.as_mut().graceful_shutdown();
                            connection.await
                        }
                    };
                    if let Err(error) = result { warn!(peer = %peer_addr, %error, "HTTP connection ended"); }
                });
            }
        }
    }
    drop(listener);
    let _ = drain.send(true);
    if tokio::time::timeout(timeout, async {
        while let Some(result) = connections.join_next().await {
            if result.is_err() {
                interrupted = true;
            }
        }
    })
    .await
    .is_err()
    {
        interrupted = true;
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    interrupted
}

/// Timeout for auto-mount operations (15 seconds).
#[cfg(target_os = "macos")]
const AUTO_MOUNT_TIMEOUT_SECS: u64 = 15;

/// Attempt to auto-mount via macOS mount_webdav command.
#[cfg(target_os = "macos")]
pub async fn auto_mount_macos(
    url: &str,
    mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    use tokio::process::Command;
    use tokio::time::{Duration, timeout};

    debug!(url = %url, mountpoint = %mountpoint.display(), "Attempting auto-mount on macOS");

    // Create mountpoint if it doesn't exist
    tokio::fs::create_dir_all(mountpoint).await?;

    // Use mount_webdav command with timeout
    // The -S flag suppresses authentication dialogs
    let mount_future = Command::new("mount_webdav")
        .arg("-S") // Suppress authentication dialog
        .arg(url)
        .arg(mountpoint)
        .status();

    let status = match timeout(Duration::from_secs(AUTO_MOUNT_TIMEOUT_SECS), mount_future).await {
        Ok(result) => result?,
        Err(_) => {
            warn!(
                url = %url,
                mountpoint = %mountpoint.display(),
                timeout_secs = AUTO_MOUNT_TIMEOUT_SECS,
                "Auto-mount timed out"
            );
            return Err(std::io::Error::other(format!(
                "mount_webdav timed out after {AUTO_MOUNT_TIMEOUT_SECS}s"
            )));
        }
    };

    if status.success() {
        info!(mountpoint = %mountpoint.display(), "Auto-mount successful");
        Ok(())
    } else {
        warn!(
            status = ?status,
            "Auto-mount failed, user can mount manually via Finder"
        );
        Err(std::io::Error::other("mount_webdav failed"))
    }
}

/// Attempt to unmount a macOS WebDAV mount.
#[cfg(target_os = "macos")]
pub fn unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    debug!(mountpoint = %mountpoint.display(), "Unmounting on macOS");

    // Use shared force_unmount utility (has built-in timeouts and fallbacks)
    oxcrypt_mount::force_unmount(mountpoint).map_err(|e| std::io::Error::other(e.to_string()))
}

/// Force unmount a macOS WebDAV mount, even if busy.
#[cfg(target_os = "macos")]
pub fn force_unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    debug!(mountpoint = %mountpoint.display(), "Force unmounting on macOS");

    // Use shared force_unmount utility (has built-in timeouts and fallbacks)
    oxcrypt_mount::force_unmount(mountpoint).map_err(|e| std::io::Error::other(e.to_string()))
}

/// Attempt to unmount on Linux (for manually mounted WebDAV shares).
#[cfg(target_os = "linux")]
pub fn unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    debug!(mountpoint = %mountpoint.display(), "Unmounting on Linux");

    // Use shared lazy_unmount utility (has built-in timeouts and fallbacks)
    oxcrypt_mount::lazy_unmount(mountpoint).map_err(|e| std::io::Error::other(e.to_string()))
}

/// Force unmount on Linux.
#[cfg(target_os = "linux")]
pub fn force_unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    debug!(mountpoint = %mountpoint.display(), "Force unmounting on Linux");

    // Use shared lazy_unmount utility (has built-in timeouts and fallbacks)
    oxcrypt_mount::lazy_unmount(mountpoint).map_err(|e| std::io::Error::other(e.to_string()))
}

#[cfg(target_os = "linux")]
// async for signature parity with the macOS variant, which callers .await
#[allow(clippy::unused_async)]
pub async fn auto_mount_macos(
    _url: &str,
    _mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    // No auto-mount on Linux - user mounts manually via davfs2 or file manager
    Ok(())
}

/// Attempt to unmount on Windows (for mapped network drives).
#[cfg(target_os = "windows")]
pub fn unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    use std::process::Command;

    debug!(mountpoint = %mountpoint.display(), "Unmounting on Windows");

    // Use net use to disconnect the mapped drive
    let status = Command::new("net")
        .args(["use", "/delete"])
        .arg(mountpoint)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("unmount failed"))
    }
}

/// Force unmount on Windows.
#[cfg(target_os = "windows")]
pub fn force_unmount_macos(mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    use std::process::Command;

    debug!(mountpoint = %mountpoint.display(), "Force unmounting on Windows");

    // Use /y to force without prompting
    let status = Command::new("net")
        .args(["use", "/delete", "/y"])
        .arg(mountpoint)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("force unmount failed"))
    }
}

#[cfg(target_os = "windows")]
pub async fn auto_mount_macos(
    _url: &str,
    _mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    // TODO: Could implement auto-mount via `net use` on Windows
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub async fn auto_mount_macos(
    _url: &str,
    _mountpoint: &std::path::Path,
) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn unmount_macos(_mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn force_unmount_macos(_mountpoint: &std::path::Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 0);
        assert_eq!(
            config.bind_address,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }
}
