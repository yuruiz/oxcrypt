//! FSEvents watcher for detecting vault changes.
//!
//! When a vault is stored on a cloud service (Google Drive, Dropbox, etc.),
//! this watcher detects changes to the encrypted files and signals the
//! File Provider extension to refresh its working set.

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::xpc::XpcClient;

/// Error type for watcher operations.
#[derive(Debug, Error)]
pub enum WatchError {
    /// The vault path could not be resolved.
    #[error("failed to resolve vault path: {0}")]
    PathError(#[from] std::io::Error),
    /// Failed to create watcher
    #[error("failed to create watcher: {0}")]
    WatcherError(#[from] notify::Error),

    /// Failed to connect to XPC service
    #[error("failed to connect to XPC service: {0}")]
    XpcError(#[from] crate::xpc::XpcError),
}

/// FSEvents watcher for vault changes.
///
/// This watcher monitors the vault directory for changes and signals
/// the File Provider extension when the working set needs to be refreshed.
pub struct VaultWatcher {
    watcher: RecommendedWatcher,
    domain_id: String,
}

impl VaultWatcher {
    /// Create a new watcher for the given vault.
    ///
    /// The watcher will signal the File Provider extension via XPC when
    /// changes are detected in the vault's `/d/` directory.
    pub fn new(vault_path: &Path, domain_id: &str) -> Result<Self, WatchError> {
        info!("Starting vault watcher for: {:?}", vault_path);

        let (tx, rx) = mpsc::sync_channel(1);
        let watcher = vault_watcher(vault_path, tx)?;

        let domain_id = domain_id.to_string();
        let worker_domain = domain_id.clone();
        std::thread::spawn(move || {
            signal_loop(&rx, Duration::from_millis(500), || {
                debug!(domain_id = %worker_domain, "Signaling File Provider");
                match XpcClient::connect().and_then(|client| client.signal_changes(&worker_domain))
                {
                    Ok(()) => true,
                    Err(error) => {
                        warn!(%error, "Failed to signal changes; will retry");
                        false
                    }
                }
            });
            info!("Vault watcher thread exiting");
        });

        Ok(Self { watcher, domain_id })
    }

    /// Start watching the vault directory.
    pub fn start(&mut self, vault_path: &Path) -> Result<(), WatchError> {
        self.watcher.watch(vault_path, RecursiveMode::Recursive)?;
        info!("Watching vault: {:?}", vault_path);
        Ok(())
    }

    /// Stop watching the vault directory.
    pub fn stop(&mut self, vault_path: &Path) -> Result<(), WatchError> {
        self.watcher.unwatch(vault_path)?;
        info!("Stopped watching vault: {:?}", vault_path);
        Ok(())
    }

    /// Get the domain ID this watcher is associated with.
    pub fn domain_id(&self) -> &str {
        &self.domain_id
    }
}

fn vault_watcher(
    vault_path: &Path,
    tx: mpsc::SyncSender<()>,
) -> Result<RecommendedWatcher, WatchError> {
    // FSEvents reports canonical paths, including /private/var for /var.
    let data_path = std::fs::canonicalize(vault_path)?.join("d");
    let watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
        let changed = match res {
            Ok(event) => affects_vault(&event, &data_path),
            Err(error) => {
                warn!(%error, "Vault watcher lost events; requesting a refresh");
                true
            }
        };
        if changed {
            // A queued event already represents all changes until the next refresh.
            let _ = tx.try_send(());
        }
    })?;

    Ok(watcher)
}

fn affects_vault(event: &Event, data_path: &Path) -> bool {
    event.need_rescan()
        || (!matches!(event.kind, EventKind::Access(_))
            && event.paths.iter().any(|path| path.starts_with(data_path)))
}

// The deadline is measured from the first event so continuous writes cannot
// postpone refresh forever. A failed notification remains pending for retry.
fn signal_loop(rx: &mpsc::Receiver<()>, interval: Duration, mut signal: impl FnMut() -> bool) {
    let mut deadline: Option<Instant> = None;
    loop {
        if let Some(due) = deadline {
            if Instant::now() >= due {
                deadline = if signal() {
                    None
                } else {
                    Some(Instant::now() + interval)
                };
                continue;
            }
            match rx.recv_timeout(due.saturating_duration_since(Instant::now())) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        } else if rx.recv().is_ok() {
            deadline = Some(Instant::now() + interval);
        } else {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::watcher::{affects_vault, signal_loop, vault_watcher};
    use notify::{
        Event, EventKind,
        event::{AccessKind, CreateKind, Flag},
    };
    use std::{path::Path, sync::mpsc, thread, time::Duration};

    #[test]
    fn event_filter_tracks_the_actual_data_directory() {
        let root = Path::new("/vault/d");
        for path in ["/vault/d", "/vault/d/AB/file"] {
            assert!(affects_vault(
                &Event::new(EventKind::Create(CreateKind::File)).add_path(path.into()),
                root
            ));
        }
        assert!(!affects_vault(
            &Event::new(EventKind::Create(CreateKind::File)).add_path("/other/d/file".into()),
            root
        ));
        assert!(!affects_vault(
            &Event::new(EventKind::Access(AccessKind::Any)).add_path("/vault/d/file".into()),
            root
        ));
        assert!(affects_vault(
            &Event::new(EventKind::Other).set_flag(Flag::Rescan),
            root
        ));
    }

    #[test]
    fn filesystem_events_through_a_vault_alias_are_delivered() {
        use notify::Watcher;
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("vault");
        std::fs::create_dir_all(vault.join("d")).unwrap();
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&vault, &alias).unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let mut watcher = vault_watcher(&alias, tx).unwrap();
        watcher
            .watch(&alias, notify::RecursiveMode::Recursive)
            .unwrap();
        std::fs::write(alias.join("d/encrypted-file"), b"change").unwrap();
        rx.recv_timeout(Duration::from_secs(5))
            .expect("canonical FSEvents path must match the vault alias");
    }

    #[test]
    fn first_event_and_failed_notifications_are_not_lost() {
        let (tx, rx) = mpsc::sync_channel(1);
        let (called, calls) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut attempts = 0;
            signal_loop(&rx, Duration::from_millis(10), || {
                attempts += 1;
                called.send(attempts).unwrap();
                attempts > 1
            });
        });
        tx.send(()).unwrap();
        assert_eq!(calls.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
        assert_eq!(calls.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
        // A new burst after success must also result in a notification.
        tx.send(()).unwrap();
        assert_eq!(calls.recv_timeout(Duration::from_secs(2)).unwrap(), 3);
        drop(tx);
        worker.join().unwrap();
    }
}
