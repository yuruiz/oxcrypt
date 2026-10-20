//! WebDAV mount backend implementation.
//!
//! This module implements the `MountBackend` trait from `oxcrypt-core`
//! to provide WebDAV-based mounting as an alternative to FUSE and FSKit.

use crate::filesystem::CryptomatorWebDav;
use crate::server::{
    ServerConfig, WebDavServer, auto_mount_macos, force_unmount_macos, unmount_macos,
};
use oxcrypt_mount::{BackendType, MountBackend, MountError, MountHandle, VaultStats};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tracing::{info, warn};

/// WebDAV-based mounting backend.
///
/// Instead of kernel-level mounting like FUSE or FSKit, this backend
/// starts a local WebDAV server. Users can mount via:
/// - macOS Finder: Cmd+K → enter server URL
/// - Windows Explorer: Map Network Drive → enter URL
/// - Linux: File manager or mount.davfs
///
/// # Advantages
///
/// - No kernel extensions required (no macFUSE needed)
/// - No macOS version requirements (unlike FSKit)
/// - Cross-platform (works anywhere with WebDAV client)
/// - Easier debugging (standard HTTP tools)
///
/// # Limitations
///
/// - HTTP overhead vs kernel-level performance
/// - macOS Finder has some UTF-8 quirks with WebDAV
#[derive(Debug, Clone)]
pub struct WebDavBackend {
    /// Server configuration.
    config: ServerConfig,
}

impl Default for WebDavBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl WebDavBackend {
    /// Create a new WebDAV backend with default configuration.
    pub fn new() -> Self {
        Self {
            config: ServerConfig::default(),
        }
    }

    /// Set the port for the WebDAV server.
    ///
    /// Use 0 for auto-assignment (recommended).
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Set the bind address for the WebDAV server.
    ///
    /// Default is localhost (127.0.0.1) for security.
    #[must_use]
    pub fn with_bind_address(mut self, addr: std::net::IpAddr) -> Self {
        self.config.bind_address = addr;
        self
    }
}

impl MountBackend for WebDavBackend {
    fn name(&self) -> &'static str {
        "WebDAV"
    }

    fn id(&self) -> &'static str {
        "webdav"
    }

    fn is_available(&self) -> bool {
        // WebDAV is always available - it's just HTTP
        true
    }

    fn unavailable_reason(&self) -> Option<String> {
        // Always available
        None
    }

    fn backend_type(&self) -> BackendType {
        BackendType::WebDav
    }

    fn description(&self) -> &'static str {
        "Starts a local WebDAV server (no kernel extensions required)"
    }

    fn mount(
        &self,
        vault_id: &str,
        vault_path: &Path,
        password: &str,
        mountpoint: &Path,
    ) -> Result<Box<dyn MountHandle>, MountError> {
        info!(
            vault_id = %vault_id,
            vault_path = %vault_path.display(),
            mountpoint = %mountpoint.display(),
            "Mounting vault via WebDAV"
        );

        // Create a new Tokio runtime for the server
        let runtime = Runtime::new().map_err(|e| {
            MountError::Mount(std::io::Error::other(format!(
                "Failed to create tokio runtime: {e}"
            )))
        })?;

        // Create the filesystem
        let fs = CryptomatorWebDav::open(vault_path, password)
            .map_err(|e| MountError::FilesystemCreation(e.to_string()))?;

        // Capture stats before starting server
        let stats = fs.stats();

        // Start the server
        let config = self.config.clone();
        let server = runtime
            .block_on(async { WebDavServer::start(fs, config).await })
            .map_err(|e| {
                MountError::Mount(std::io::Error::other(format!(
                    "Failed to start WebDAV server: {e}"
                )))
            })?;

        let url = server.url();
        info!(url = %url, "WebDAV server started");

        let auto_mounted = match runtime.block_on(auto_mount_macos(&url, mountpoint)) {
            Ok(()) => {
                info!(mountpoint = %mountpoint.display(), "Auto-mounted successfully");
                true
            }
            Err(error) => {
                warn!(%error, "Auto-mount failed, mount manually using: {}", url);
                false
            }
        };

        Ok(Box::new(WebDavMountHandle {
            server: Some(server),
            runtime: Some(runtime),
            url,
            mountpoint: mountpoint.to_path_buf(),
            auto_mounted,
            stats,
        }))
    }
}

/// Handle to a running WebDAV mount.
pub struct WebDavMountHandle {
    /// The WebDAV server.
    server: Option<WebDavServer>,
    /// The Tokio runtime.
    runtime: Option<Runtime>,
    /// The server URL.
    url: String,
    /// The mountpoint path.
    mountpoint: PathBuf,
    /// Whether auto-mount succeeded.
    auto_mounted: bool,
    /// Statistics for monitoring vault activity.
    stats: Arc<VaultStats>,
}

impl WebDavMountHandle {
    /// Get the server URL.
    pub fn url(&self) -> &str {
        &self.url
    }
    fn unmount_client(
        &mut self,
        unmount: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<(), MountError> {
        if self.auto_mounted {
            unmount(&self.mountpoint).map_err(MountError::Mount)?;
            self.auto_mounted = false;
        }
        Ok(())
    }

    fn stop_server(&mut self) -> Result<(), MountError> {
        if let (Some(server), Some(runtime)) = (self.server.as_mut(), self.runtime.as_ref()) {
            runtime.block_on(server.stop()).map_err(MountError::Mount)?;
        }
        // Drop the server before its runtime; failed shutdowns retain both for retry.
        self.server.take();
        self.runtime.take();
        Ok(())
    }
}

impl MountHandle for WebDavMountHandle {
    fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn display_location(&self) -> Option<String> {
        (!self.auto_mounted).then(|| self.url.clone())
    }

    fn stats(&self) -> Option<Arc<VaultStats>> {
        Some(Arc::clone(&self.stats))
    }

    fn unmount(mut self: Box<Self>) -> Result<(), MountError> {
        info!(url = %self.url, "Unmounting WebDAV");

        let unmount_result = self.unmount_client(unmount_macos);
        // Even if the OS client cannot detach, drain writes before stopping HTTP.
        self.stop_server()?;
        unmount_result?;
        info!("WebDAV unmounted successfully");
        Ok(())
    }

    fn force_unmount(mut self: Box<Self>) -> Result<(), MountError> {
        info!(url = %self.url, "Force unmounting WebDAV");

        let unmount_result = self.unmount_client(force_unmount_macos);
        self.stop_server()?;
        unmount_result?;
        info!("WebDAV force unmounted successfully");
        Ok(())
    }
}

impl Drop for WebDavMountHandle {
    fn drop(&mut self) {
        if let Err(error) = self.unmount_client(unmount_macos) {
            warn!(%error, "Failed to detach WebDAV client during cleanup");
        }
        if let Err(error) = self.stop_server() {
            warn!(%error, "Failed to persist or recover WebDAV writes during cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::{WebDavBackend, WebDavMountHandle};
    use oxcrypt_mount::MountBackend;
    use std::{path::PathBuf, sync::Arc};

    #[test]
    fn client_unmount_failures_propagate_and_success_is_not_repeated() {
        let mut handle = WebDavMountHandle {
            server: None,
            runtime: None,
            url: "http://127.0.0.1:8080".into(),
            mountpoint: PathBuf::from("unused-test-mount"),
            auto_mounted: true,
            stats: Arc::new(oxcrypt_mount::VaultStats::new()),
        };
        let result = handle.unmount_client(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "busy",
            ))
        });
        assert!(result.is_err());
        assert!(handle.auto_mounted);
        handle.unmount_client(|_| Ok(())).unwrap();
        assert!(!handle.auto_mounted);
        handle
            .unmount_client(|_| panic!("must not unmount twice"))
            .unwrap();
    }

    #[test]
    fn dropping_a_mount_archives_failed_writes_before_dropping_its_runtime() {
        use crate::{CryptomatorWebDav, ServerConfig, WebDavServer};
        use bytes::Bytes;
        use dav_server::{
            davpath::DavPath,
            fs::{DavFileSystem, OpenOptions},
        };
        use oxcrypt_core::vault::{DirId, VaultCreator, VaultOperationsAsync};
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("vault");
        let recovery = temp.path().join("recovery");
        VaultCreator::new(&vault, "test-password").create().unwrap();
        let ops = Arc::new(VaultOperationsAsync::open(&vault, "test-password").unwrap());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (server, stats) = runtime.block_on(async {
            let path = ops
                .write_file(&DirId::root(), "note", b"original")
                .await
                .unwrap();
            let filesystem =
                CryptomatorWebDav::new(Arc::clone(&ops)).with_recovery_directory(&recovery);
            let mut writer = filesystem
                .open(
                    &DavPath::new("/note").unwrap(),
                    OpenOptions {
                        write: true,
                        ..OpenOptions::default()
                    },
                )
                .await
                .unwrap();
            writer
                .write_bytes(Bytes::from_static(b"retained"))
                .await
                .unwrap();
            std::fs::rename(&path, path.with_extension("backup")).unwrap();
            std::fs::create_dir(&path).unwrap();
            assert!(writer.flush().await.is_err());
            drop(writer);
            let stats = filesystem.stats();
            let server = WebDavServer::start(filesystem, ServerConfig::default())
                .await
                .unwrap();
            (server, stats)
        });
        let handle = WebDavMountHandle {
            url: server.url(),
            server: Some(server),
            runtime: Some(runtime),
            mountpoint: temp.path().join("unused"),
            auto_mounted: false,
            stats,
        };
        drop(handle);
        let copies: Vec<_> = std::fs::read_dir(&recovery)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(copies.len(), 1);
        let output = temp.path().join("recovered");
        oxcrypt_core::fs::recovery::export(&copies[0], ops.master_key(), &output).unwrap();
        assert_eq!(std::fs::read(output).unwrap(), b"retained");
    }

    #[test]
    fn test_backend_metadata() {
        let backend = WebDavBackend::new();
        assert_eq!(backend.name(), "WebDAV");
        assert_eq!(backend.id(), "webdav");
        assert!(backend.is_available());
        assert!(backend.unavailable_reason().is_none());
    }

    #[test]
    fn test_backend_config() {
        let backend = WebDavBackend::new()
            .with_port(8080)
            .with_bind_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        assert_eq!(backend.config.port, 8080);
        assert_eq!(
            backend.config.bind_address,
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        );
    }
}
