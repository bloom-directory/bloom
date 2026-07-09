use std::collections::{HashMap, HashSet};
use std::time::Instant;

use embednfs_proto::{
    ClientOwner4, Clientid4, NfsLockType4, SequenceRes4, Sequenceid4, Sessionid4, Slotid4,
    StateOwner4,
};

use crate::internal::ServerObject;

/// Server-owned metadata tracked for each visible object.
#[derive(Debug, Clone)]
pub(crate) struct SynthMeta {
    pub fileid: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub owner: String,
    pub owner_group: String,
    pub atime_sec: i64,
    pub atime_nsec: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub crtime_sec: i64,
    pub crtime_nsec: u32,
    pub change_id: u64,
    pub archive: bool,
    pub hidden: bool,
    pub system: bool,
    pub named_attr_count: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct LockRange {
    pub locktype: NfsLockType4,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug)]
pub(super) struct LockFileState {
    pub object: ServerObject,
    pub owner: StateOwner4,
    pub open_state_other: [u8; 12],
    pub ranges: Vec<LockRange>,
    pub active: bool,
    pub stateid_seq: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedOpenState {
    pub other: [u8; 12],
    pub object: ServerObject,
    pub share_access: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedLockState {
    pub other: [u8; 12],
    pub object: ServerObject,
    pub owner: StateOwner4,
    pub open_state: ResolvedOpenState,
}

#[derive(Debug, Clone)]
pub(crate) enum ResolvedStateid {
    Anonymous,
    Bypass,
    Open(ResolvedOpenState),
    Lock(ResolvedLockState),
}

pub(super) struct StateInner {
    pub clients: HashMap<Clientid4, ClientState>,
    pub sessions: HashMap<Sessionid4, SessionState>,
    pub open_files: HashMap<[u8; 12], OpenFileState>,
    pub lock_files: HashMap<[u8; 12], LockFileState>,
    pub metadata: HashMap<ServerObject, SynthMeta>,
}

#[derive(Debug)]
pub(super) struct ClientState {
    pub clientid: Clientid4,
    pub owner: ClientOwner4,
    pub confirmed: bool,
    pub reclaim_complete_global: bool,
    pub sequence_id: Sequenceid4,
    pub replaced_clientid: Option<Clientid4>,
    pub lease_state: ClientLeaseState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientLeaseState {
    Active { deadline: Instant },
    Revoked { since: Instant, status_flags: u32 },
}

pub(super) struct SessionState {
    pub clientid: Clientid4,
    pub slots: Vec<SlotState>,
    pub connections: HashSet<u64>,
}

#[derive(Clone)]
pub(super) struct CachedReplay {
    pub fingerprint: Vec<u8>,
    pub response: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct SlotState {
    pub sequence_id: Sequenceid4,
    pub in_progress: Option<Vec<u8>>,
    pub cached_reply: Option<CachedReplay>,
}

pub(crate) struct SequenceCacheToken {
    pub sessionid: Sessionid4,
    pub slotid: Slotid4,
    pub fingerprint: Vec<u8>,
}

pub(crate) enum SequenceReplay {
    Execute(SequenceRes4, SequenceCacheToken),
    Replay(Vec<u8>),
    StatusOnly(SequenceRes4),
    Error(embednfs_proto::NfsStat4),
}

#[derive(Debug)]
pub(super) struct OpenFileState {
    pub object: ServerObject,
    pub clientid: Clientid4,
    pub stateid_seq: u32,
    pub active: bool,
    pub share_access: u32,
    pub share_deny: u32,
}
