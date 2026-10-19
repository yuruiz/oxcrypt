//! Ordered path locks keep uploads and namespace operations from invalidating each other.
use dav_server::fs::FsError;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

#[derive(Default)]
pub(crate) struct PathLocks {
    locks: Mutex<HashMap<String, Weak<RwLock<()>>>>,
}

#[derive(Debug, Default)]
pub(crate) struct PathGuards {
    read: Vec<OwnedRwLockReadGuard<()>>,
    write: Vec<OwnedRwLockWriteGuard<()>>,
}

impl PathLocks {
    /// Lock each target in the requested mode and all its ancestors for reading.
    /// A directory write lock excludes operations anywhere below that directory.
    pub(crate) async fn acquire(&self, paths: &[(&str, bool)]) -> Result<PathGuards, FsError> {
        let mut desired = BTreeMap::<String, bool>::new();
        for (path, write) in paths {
            let mut path = path.trim_end_matches('/');
            desired
                .entry(path.to_owned())
                .and_modify(|mode| *mode |= write)
                .or_insert(*write);
            while let Some((parent, _)) = path.rsplit_once('/') {
                desired.entry(parent.to_owned()).or_insert(false);
                path = parent;
            }
        }
        let locks: Vec<_> = {
            let mut registry = self.locks.lock().map_err(|_| FsError::GeneralFailure)?;
            registry.retain(|_, lock| lock.strong_count() > 0);
            desired
                .into_iter()
                .map(|(path, write)| {
                    let slot = registry.entry(path).or_default();
                    let lock = slot.upgrade().unwrap_or_else(|| {
                        let lock = Arc::new(RwLock::new(()));
                        *slot = Arc::downgrade(&lock);
                        lock
                    });
                    (lock, write)
                })
                .collect()
        };
        let mut guards = PathGuards::default();
        for (lock, write) in locks {
            if write {
                guards.write.push(lock.write_owned().await);
            } else {
                guards.read.push(lock.read_owned().await);
            }
        }
        Ok(guards)
    }
}
