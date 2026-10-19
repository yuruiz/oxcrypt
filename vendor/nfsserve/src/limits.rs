//! Bounds for untrusted RPC framing and queued work.
pub(crate) const MAX_RPC_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_FRAGMENTS: usize = 128;
pub(crate) const MAX_REQUESTS: usize = 16;
pub(crate) const MAX_CONNECTIONS: usize = 64;
