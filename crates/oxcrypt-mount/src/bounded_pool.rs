//! Bounded thread pool for timeout-wrapped filesystem operations.
//!
//! When filesystem operations timeout (e.g., due to ghost FUSE mounts), the spawned
//! thread may be stuck in kernel D-state (uninterruptible sleep) forever. This module
//! provides a thread pool that tracks these "leaked" threads and refuses new operations
//! once a threshold is reached, preventing unbounded resource consumption.
//!
//! # Thread Leak Problem
//!
//! The pattern `spawn thread + channel + recv_timeout` is used throughout the codebase
//! to avoid blocking on ghost mounts. However, when the timeout expires, the spawned
//! thread is still blocked in a kernel syscall and cannot be killed. These threads
//! accumulate until process exit.
//!
//! # Solution
//!
//! This module tracks the number of potentially-leaked threads and rejects new
//! operations once a threshold is reached. This provides:
//!
//! 1. **Bounded resource usage** - At most `MAX_LEAKED_THREADS` threads can leak
//! 2. **Early failure** - Operations fail fast instead of spawning more threads
//! 3. **Observability** - The blocked count can be monitored for diagnostics
//!
//! # Example
//!
//! ```ignore
//! use oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL;
//! use std::time::Duration;
//!
//! let result = BOUNDED_FS_POOL.run_with_timeout(Duration::from_secs(2), || {
//!     std::fs::metadata("/some/path")
//! });
//! ```

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

/// Maximum threads that can be leaked before we start rejecting operations.
///
/// This is a balance between:
/// - Too low: Legitimate operations may be rejected
/// - Too high: Too many leaked threads consume resources
///
/// 32 threads is enough to handle multiple ghost mount encounters while
/// still providing protection against runaway resource consumption.
pub const MAX_LEAKED_THREADS: usize = 32;

/// A thread pool that tracks and limits leaked threads from timeout operations.
///
/// When operations time out, the spawned thread may be stuck in D-state
/// on a ghost mount. This pool tracks those "leaked" threads and refuses
/// new operations once a threshold is reached, preventing unbounded resource
/// consumption.
#[derive(Debug, Clone)]
pub struct BoundedFsPool {
    max_leaked: usize,
    blocked: Arc<AtomicUsize>,
}

impl Default for BoundedFsPool {
    fn default() -> Self {
        Self::new(MAX_LEAKED_THREADS)
    }
}

impl BoundedFsPool {
    /// Create a new pool with a custom max leaked thread limit.
    pub fn new(max_leaked: usize) -> Self {
        Self {
            max_leaked,
            blocked: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Run an operation with timeout, tracking potential thread leaks.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for the operation
    /// * `op` - The operation to run (typically a blocking filesystem call)
    ///
    /// # Returns
    ///
    /// - `Ok(T)` if the operation completed within the timeout
    /// - `Err(TimedOut)` if the operation timed out (thread may be leaked)
    /// - `Err(ResourceBusy)` if too many threads are already blocked
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe. Multiple threads can call it concurrently.
    pub fn run_with_timeout<T, F>(&self, timeout: Duration, op: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        self.blocked
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.max_leaked).then(|| count + 1)
            })
            .map_err(|count| {
                io::Error::new(
                    io::ErrorKind::ResourceBusy,
                    format!(
                        "Too many blocked filesystem threads ({count}/{}); possible ghost mounts",
                        self.max_leaked
                    ),
                )
            })?;

        // The reservation follows the worker, including spawn failure, panic and
        // completion after the caller has already timed out.
        let slot = WorkerSlot(Arc::clone(&self.blocked));
        // A rendezvous prevents queued file handles from being dropped on the
        // caller when its receive deadline expires.
        let (tx, rx) = mpsc::sync_channel(0);
        std::thread::Builder::new()
            .name("oxcrypt-fs-check".into())
            .spawn(move || {
                let reservation = slot;
                let result = op();
                // On failed delivery tuple fields drop left to right, keeping
                // the reservation through any blocking result destructor.
                let _ = tx.send((result, reservation));
            })?;

        match rx.recv_timeout(timeout) {
            Ok((result, reservation)) => {
                drop(reservation);
                result
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Thread is blocked - count stays elevated (leak tracked)
                // Note: we don't decrement here because the thread is still running
                tracing::warn!(
                    blocked_threads = self.blocked.load(Ordering::Acquire),
                    max_allowed = self.max_leaked,
                    "Filesystem operation timed out. Thread may be blocked on ghost mount."
                );
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Filesystem operation timed out - path may be on a stale mount",
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
                "Filesystem operation thread terminated unexpectedly",
            )),
        }
    }

    /// Get the current count of blocked/leaked threads.
    ///
    /// This can be used for monitoring and diagnostics.
    pub fn blocked_count(&self) -> usize {
        self.blocked.load(Ordering::Acquire)
    }

    /// Get the maximum allowed blocked threads for this pool.
    pub fn max_allowed(&self) -> usize {
        self.max_leaked
    }

    /// Check if the pool is healthy (no blocked threads).
    pub fn is_healthy(&self) -> bool {
        self.blocked_count() == 0
    }

    /// Check if the pool is degraded (some blocked threads but under threshold).
    pub fn is_degraded(&self) -> bool {
        let count = self.blocked_count();
        count > 0 && count < self.max_leaked
    }

    /// Check if the pool is exhausted (at or above threshold).
    pub fn is_exhausted(&self) -> bool {
        self.blocked_count() >= self.max_leaked
    }
}

struct WorkerSlot(Arc<AtomicUsize>);

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Global bounded filesystem pool instance.
///
/// Use this for all timeout-wrapped filesystem operations to ensure
/// consistent leak tracking across the application.
///
/// # Example
///
/// ```ignore
/// use oxcrypt_mount::bounded_pool::BOUNDED_FS_POOL;
/// use std::time::Duration;
///
/// let accessible = BOUNDED_FS_POOL
///     .run_with_timeout(Duration::from_millis(500), || {
///         std::fs::metadata("/some/path").map(|_| true)
///     })
///     .unwrap_or(false);
/// ```
pub static BOUNDED_FS_POOL: std::sync::LazyLock<BoundedFsPool> =
    std::sync::LazyLock::new(BoundedFsPool::default);

/// Diagnostic information about blocked threads.
#[derive(Debug, Clone)]
pub struct BlockedThreadDiagnostics {
    /// Current number of blocked/leaked threads
    pub blocked_count: usize,
    /// Maximum allowed before rejection
    pub max_allowed: usize,
    /// Health status: "healthy", "degraded", or "exhausted"
    pub status: &'static str,
}

/// Get diagnostic information about potentially-blocked threads.
///
/// This is useful for health checks and monitoring.
pub fn get_blocked_thread_diagnostics() -> BlockedThreadDiagnostics {
    let blocked_count = BOUNDED_FS_POOL.blocked_count();
    let status = if blocked_count == 0 {
        "healthy"
    } else if blocked_count < MAX_LEAKED_THREADS {
        "degraded"
    } else {
        "exhausted"
    };

    BlockedThreadDiagnostics {
        blocked_count,
        max_allowed: MAX_LEAKED_THREADS,
        status,
    }
}

/// Check whether the shared pool has recovered.
///
/// Active worker reservations cannot be reset: even a timed-out thread retains
/// its slot until it exits. This function never forgets live workers or allows
/// their eventual completion to underflow the counter.
pub fn reset_blocked_count() {
    let count = BOUNDED_FS_POOL.blocked_count();
    if count != 0 {
        tracing::warn!(
            blocked_threads = count,
            "Cannot reset reservations held by filesystem workers"
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::bounded_pool::{BoundedFsPool, MAX_LEAKED_THREADS, get_blocked_thread_diagnostics};
    use std::time::Duration;
    use std::{
        io,
        sync::{Arc, Barrier, Condvar, Mutex},
        thread,
    };

    #[test]
    fn concurrent_reservations_never_exceed_capacity() {
        let pool = BoundedFsPool::new(2);
        let start = Arc::new(Barrier::new(13));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let mut workers = Vec::new();
        for _ in 0..12 {
            let pool = pool.clone();
            let start = Arc::clone(&start);
            let release = Arc::clone(&release);
            workers.push(thread::spawn(move || {
                start.wait();
                pool.run_with_timeout(Duration::from_millis(30), move || {
                    let (lock, wake) = &*release;
                    let _guard = wake
                        .wait_while(lock.lock().unwrap(), |done| !*done)
                        .unwrap();
                    Ok(())
                })
            }));
        }
        start.wait();
        let errors: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap_err().kind())
            .collect();
        assert_eq!(
            errors
                .iter()
                .filter(|kind| **kind == io::ErrorKind::TimedOut)
                .count(),
            2
        );
        assert_eq!(
            errors
                .iter()
                .filter(|kind| **kind == io::ErrorKind::ResourceBusy)
                .count(),
            10
        );
        assert_eq!(pool.blocked_count(), 2);
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while pool.blocked_count() != 0 && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(pool.blocked_count(), 0);
    }

    #[test]
    fn panicking_workers_release_their_reservation() {
        let pool = BoundedFsPool::new(1);
        let result: io::Result<()> =
            pool.run_with_timeout(Duration::from_secs(1), || panic!("worker failure"));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(pool.blocked_count(), 0);
        pool.run_with_timeout(Duration::from_secs(1), || Ok(()))
            .unwrap();
    }

    #[test]
    fn panic_after_caller_timeout_still_releases_capacity() {
        let pool = BoundedFsPool::new(1);
        let (release, wait) = std::sync::mpsc::channel();
        let result: io::Result<()> = pool.run_with_timeout(Duration::from_millis(10), move || {
            wait.recv().unwrap();
            panic!("failure after timeout");
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(pool.blocked_count(), 1);
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while pool.blocked_count() != 0 && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(pool.blocked_count(), 0);
        pool.run_with_timeout(Duration::from_secs(1), || Ok(()))
            .unwrap();
    }

    #[test]
    fn timed_out_result_destructors_retain_the_worker_slot() {
        struct SlowDrop {
            entered: std::sync::mpsc::Sender<()>,
            release: Arc<(Mutex<bool>, Condvar)>,
        }
        impl Drop for SlowDrop {
            fn drop(&mut self) {
                self.entered.send(()).unwrap();
                let (lock, wake) = &*self.release;
                let _guard = wake
                    .wait_while(lock.lock().unwrap(), |done| !*done)
                    .unwrap();
            }
        }
        let pool = BoundedFsPool::new(1);
        let (complete, completion) = std::sync::mpsc::channel();
        let (entered, dropped) = std::sync::mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_release = Arc::clone(&release);
        let result = pool.run_with_timeout(Duration::from_millis(10), move || {
            completion.recv().unwrap();
            Ok(SlowDrop {
                entered,
                release: worker_release,
            })
        });
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        complete.send(()).unwrap();
        dropped.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(pool.blocked_count(), 1);
        assert_eq!(
            pool.run_with_timeout(Duration::from_millis(10), || Ok(()))
                .unwrap_err()
                .kind(),
            io::ErrorKind::ResourceBusy
        );
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while pool.blocked_count() != 0 && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(pool.blocked_count(), 0);
    }

    #[test]
    fn successful_calls_immediately_release_capacity_for_the_next_call() {
        let pool = BoundedFsPool::new(1);
        for value in 0..100 {
            assert_eq!(
                pool.run_with_timeout(Duration::from_secs(1), move || Ok(value))
                    .unwrap(),
                value
            );
            assert_eq!(pool.blocked_count(), 0);
        }
    }

    #[test]
    fn test_successful_operation() {
        let pool = BoundedFsPool::new(10);
        let result = pool.run_with_timeout(Duration::from_secs(1), || Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_failed_operation() {
        let pool = BoundedFsPool::new(10);
        let result: io::Result<i32> = pool.run_with_timeout(Duration::from_secs(1), || {
            Err(io::Error::new(io::ErrorKind::NotFound, "not found"))
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_timeout() {
        let pool = BoundedFsPool::new(10);
        let result: io::Result<i32> = pool.run_with_timeout(Duration::from_millis(10), || {
            thread::sleep(Duration::from_secs(10));
            Ok(42)
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_pool_status() {
        let pool = BoundedFsPool::new(10);
        assert!(pool.is_healthy());
        assert!(!pool.is_degraded());
        assert!(!pool.is_exhausted());
    }

    #[test]
    fn test_diagnostics() {
        let diag = get_blocked_thread_diagnostics();
        assert_eq!(diag.max_allowed, MAX_LEAKED_THREADS);
        // Note: blocked_count depends on other tests, so we just check it doesn't panic
    }
}
