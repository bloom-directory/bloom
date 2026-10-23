//! Per-key write locks for handlers that offer a conditional write.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::handler::HandlerError;

/// How long a conditional write waits for the writes already running under
/// its key before it gives up without writing.
pub const CONDITIONAL_WRITE_WAIT: Duration = Duration::from_secs(2);

/// Lets a handler keep a conditional write's check and write together.
/// Ordinary writes under a key share its lock, so they still run together; a
/// conditional write holds it alone while it reads, compares and writes.
/// These locks belong to the handler, never to the VFS as a whole, so a
/// handler callback that writes elsewhere through the VFS is never held up.
/// A callback must not write under the key it is serving.
#[derive(Clone, Default)]
pub struct WriteLocks {
    locks: Arc<Mutex<HashMap<String, Arc<RwLock<()>>>>>,
}

impl WriteLocks {
    fn lock(&self, key: &str) -> Arc<RwLock<()>> {
        self.locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key.to_owned())
            .or_default()
            .clone()
    }

    /// Hold `key` for an ordinary write.
    pub async fn shared(&self, key: &str) -> OwnedRwLockReadGuard<()> {
        self.lock(key).read_owned().await
    }

    /// Hold `key` alone for a conditional write. Waits at most
    /// [`CONDITIONAL_WRITE_WAIT`] for writes already running under it, and
    /// otherwise fails as busy, so the caller writes nothing.
    pub async fn exclusive(&self, key: &str) -> Result<OwnedRwLockWriteGuard<()>, HandlerError> {
        tokio::time::timeout(CONDITIONAL_WRITE_WAIT, self.lock(key).write_owned())
            .await
            .map_err(|_| {
                HandlerError::backend(format!(
                    "other writes to {key} kept running, so it was not checked or written"
                ))
            })
    }
}
