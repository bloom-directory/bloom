//! NFSv4.1 session, object, and server-side state management.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use embednfs_proto::{ServerOwner4, Verifier4};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::internal::ServerObject;

mod clients;
mod filehandles;
mod locks;
mod metadata;
mod model;
mod opens;
mod sequence;
mod stateids;
#[cfg(test)]
mod tests;

const MAX_FORE_CHAN_SLOTS: u32 = 64;
const MAX_REQUEST_SIZE: u32 = 1_049_620;
const MAX_CACHED_RESPONSE: u32 = 6144;
const SYNTH_FILEID_BASE: u64 = 1u64 << 63;
pub(crate) const DEFAULT_LEASE_TIME_SECS: u32 = 90;

type NowFn = Arc<dyn Fn() -> Instant + Send + Sync>;

#[derive(Clone)]
struct StateConfig {
    lease_duration: Duration,
    revoked_retention: Duration,
    now: NowFn,
}

impl StateConfig {
    fn default_now() -> Instant {
        Instant::now()
    }

    fn now(&self) -> Instant {
        (self.now)()
    }
}

impl Default for StateConfig {
    fn default() -> Self {
        let lease_duration = Duration::from_secs(u64::from(DEFAULT_LEASE_TIME_SECS));
        Self {
            lease_duration,
            revoked_retention: lease_duration,
            now: Arc::new(Self::default_now),
        }
    }
}

use model::StateInner;
pub(crate) use model::{ResolvedStateid, SequenceReplay, SynthMeta};
pub(crate) use stateids::{CurrentStateidMode, NormalizedStateid};

/// Manages all server-side state.
pub(crate) struct StateManager {
    inner: Arc<RwLock<StateInner>>,
    /// Lock-free file handle mappings (hot path).
    fh_to_object: DashMap<Vec<u8>, ServerObject>,
    object_to_fh: DashMap<ServerObject, Vec<u8>>,
    next_fh: AtomicU64,
    next_clientid: AtomicU64,
    next_stateid: AtomicU32,
    next_changeid: AtomicU64,
    next_synth_fileid: AtomicU64,
    next_connectionid: AtomicU64,
    config: StateConfig,
    /// Server boot verifier (changes each restart).
    pub(crate) write_verifier: Verifier4,
    pub(crate) server_owner: ServerOwner4,
}

impl StateManager {
    pub(crate) fn new() -> Self {
        Self::with_config(StateConfig::default())
    }

    fn with_config(config: StateConfig) -> Self {
        let boot_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let verifier_value =
            boot_time.as_secs().rotate_left(32) ^ u64::from(boot_time.subsec_nanos());
        let mut write_verifier = [0u8; 8];
        write_verifier.copy_from_slice(&verifier_value.to_be_bytes());

        // Generate a unique server_owner per StateManager instance so the
        // Linux NFSv4.1 client does not treat two independent embednfs
        // servers (e.g., running on different loopback ports in the same
        // test process) as trunking-compatible siblings of one another.
        //
        // RFC 5661 §2.10.5: clients identify servers by the
        // `server_owner.major_id` plus `server_scope`. If both fields
        // match between two EXCHANGE_ID replies, the client assumes the
        // responses come from the same server (or trunking peers of it)
        // and may reuse the existing session/nfs_client for subsequent
        // operations — silently routing traffic for one mount onto the
        // transport already established for another.
        //
        // `clients.rs` continues to return a hardcoded server_scope of
        // `"embednfs"`, but we make `major_id` carry a monotonically
        // increasing counter so every server instance in the process gets
        // a distinct identity. The atomic is process-global; wraparound
        // is not a concern for any realistic deployment.
        static NEXT_SERVER_OWNER_ID: AtomicU64 = AtomicU64::new(1);
        let instance_id = NEXT_SERVER_OWNER_ID.fetch_add(1, Ordering::Relaxed);
        let mut major_id = Vec::with_capacity(24);
        major_id.extend_from_slice(b"embednfs-");
        major_id.extend_from_slice(instance_id.to_string().as_bytes());
        let server_owner = ServerOwner4 {
            minor_id: 0,
            major_id: Bytes::from(major_id),
        };

        Self {
            inner: Arc::new(RwLock::new(StateInner {
                clients: HashMap::new(),
                sessions: HashMap::new(),
                open_files: HashMap::new(),
                lock_files: HashMap::new(),
                metadata: HashMap::new(),
            })),
            fh_to_object: DashMap::new(),
            object_to_fh: DashMap::new(),
            next_fh: AtomicU64::new(1),
            next_clientid: AtomicU64::new(1),
            next_stateid: AtomicU32::new(1),
            next_changeid: AtomicU64::new(2),
            next_synth_fileid: AtomicU64::new(SYNTH_FILEID_BASE),
            next_connectionid: AtomicU64::new(1),
            config,
            write_verifier,
            server_owner,
        }
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}
