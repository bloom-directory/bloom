//! `embednfs::FileSystem` adapter for [`bloom_vfs::Vfs`].
//!
//! Maps NFS RPCs onto the four `Handler` async methods (`lookup`,
//! `read`, `write`, `list`). Handles are full VFS paths so attribute
//! lookups stay cheap — the kernel calls `getattr` constantly and we
//! don't want to round-trip through the router twice for every call.
//!
//! ## Path semantics
//!
//! - `BloomHandle::Root` corresponds to `/` and is always a directory.
//! - `BloomHandle::Path { entry, path }` carries the parsed [`VfsPath`]
//!   plus the [`Entry`] metadata returned by lookup or readdir. This keeps
//!   subsequent metadata calls from re-running a dynamic Petal route.
//!   Stale-cache risk is acceptable because the VFS namespace is
//!   functionally immutable during a single mount session.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use embednfs::{
    AccessMask, Attrs, CommitSupport, CreateKind, CreateRequest, CreateResult, DirEntry, DirPage,
    FileSystem, FsError, FsResult, FsStats, ObjectType, OpenRequest, OpenSupport, ReadResult,
    RequestContext, SetAttrs, Symlinks, Timestamp, WriteResult, WriteStability,
};
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use lru::LruCache;
use parking_lot::Mutex;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use bloom_vfs::{Entry, EntryKind, Handler, HandlerError, Vfs, VfsPath, percent_decode_segment};

/// Maximum bytes we'll buffer for a single open file before forcing a
/// flush (or rejecting further writes with FBIG). 8 MiB matches the
/// spec hint and is large enough for any plausible JSON/TOML/EIP-712
/// body the daemon expects through the mount surface.
pub(crate) const MAX_WRITE_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// TTL for the mount-side render cache that bridges GETATTR and the
/// imminent READ. Long enough to cover the kernel's
/// LOOKUP→GETATTR→OPEN→READ sequence on both Linux and macOS, short
/// enough that a stale cached body cannot serve a follow-up read after
/// the user has time to do something else.
pub(crate) const RENDER_CACHE_TTL: Duration = Duration::from_millis(750);

/// Maximum number of cached render results held in [`MountRenderCache`].
/// LRU eviction keeps memory bounded even if a client walks a large
/// directory tree.
pub(crate) const RENDER_CACHE_CAPACITY: usize = 1024;

/// Hard ceiling on a single render attempt. Beyond this we map to
/// `FsError::Io` so the client surface is EIO with a logged reason
/// rather than hanging past the kernel's retry threshold.
pub(crate) const RENDER_TIMEOUT: Duration = Duration::from_secs(30);

/// Directory snapshots bridge the GETATTR used to compute NFS's cookie
/// verifier with every READDIR page in the same enumeration.
pub(crate) const DIRECTORY_CACHE_CAPACITY: usize = 1024;
pub(crate) const DIRECTORY_CACHE_IDLE_TTL: Duration = Duration::from_secs(2);
pub(crate) const DIRECTORY_CACHE_MAX_AGE: Duration = Duration::from_secs(30);
/// Directory GETATTR revalidates a cached listing at this cadence so daemon,
/// CLI, or another mount's mutations advance NFS's change token promptly.
pub(crate) const DIRECTORY_CACHE_REVALIDATE_INTERVAL: Duration = Duration::from_millis(500);
pub(crate) const DIRECTORY_LIST_TIMEOUT: Duration = Duration::from_secs(30);

/// Time without further writes after which a buffer may be reaped.
/// Picked to match the typical NFSv4 client behaviour: kernels with
/// `wsize=4096` issue a burst of WRITEs followed by a COMMIT once the
/// userspace `close(2)` returns. The COMMIT path is the primary flush
/// trigger for UNSTABLE writes; this idle window is only used to
/// discard stale incomplete buffers on a later read of the same path.
pub(crate) const WRITE_IDLE_FLUSH: Duration = Duration::from_secs(5);

/// Opaque handle exported over NFS.
///
/// Stable across server restarts within a single process: the kernel
/// caches handles and we want a `getattr` after a `lookup` to keep
/// returning the same object. Handles are equal iff their stringified
/// path is equal (root compares equal to root).
#[derive(Debug, Clone)]
pub enum BloomHandle {
    Root,
    Path {
        /// Metadata already returned while resolving this handle. Keeping it
        /// on the handle avoids a second VFS lookup for GETATTR/ACCESS.
        entry: Entry,
        path: VfsPath,
    },
}

impl PartialEq for BloomHandle {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Root, Self::Root) => true,
            (Self::Path { path: left, .. }, Self::Path { path: right, .. }) => left == right,
            _ => false,
        }
    }
}

impl Eq for BloomHandle {}

impl Hash for BloomHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Self::Root => 0_u8.hash(state),
            Self::Path { path, .. } => {
                1_u8.hash(state);
                path.hash(state);
            }
        }
    }
}

/// Stable 64-bit fileid derived from the path string. The kernel uses
/// this to keep its inode cache coherent; a deterministic hash means
/// the same VFS path always points at the same `fileid`.
fn fileid_for(path: &VfsPath) -> u64 {
    let s = path.to_string_path();
    let h = blake3_like_hash(s.as_bytes());
    // Reserve 0/1 (bad-fileid sentinels in some clients).
    h.max(2)
}

/// Tiny non-crypto hash. We don't depend on blake3 here to keep the
/// crate's dep set lean — `embednfs` already pulls plenty.
fn blake3_like_hash(bytes: &[u8]) -> u64 {
    // FNV-1a 64-bit. Good enough for fileid stability; collisions are
    // tolerable since the kernel re-resolves on `lookup` mismatch.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn mount_write_path_uses_wallet_signer(path: &VfsPath) -> bool {
    let segs = path.segments();
    match segs {
        [root, _wallet, chains, _chain, outbox, pending, _id, action]
            if root == "wallets"
                && chains == "chains"
                && outbox == "outbox"
                && pending == "pending"
                && matches!(action.as_str(), "cancel" | "replace") =>
        {
            true
        }
        [root, _wallet, sign, kind]
            if root == "wallets"
                && sign == "sign"
                && matches!(kind.as_str(), "message" | "hash" | "typed_data") =>
        {
            true
        }
        [root, _network, branch, _wallet, _session, leaf]
            if root == "hyperliquid"
                && branch == "agent_sessions"
                && matches!(leaf.as_str(), "orphan_cancel_all" | "orphan_close_all") =>
        {
            true
        }
        [root, _network, branch, _wallet, leaf]
            if root == "hyperliquid"
                && branch == "exchange"
                && matches!(
                    leaf.as_str(),
                    "order.json"
                        | "cancel.json"
                        | "schedule_cancel.json"
                        | "update_leverage.json"
                        | "send_asset.json"
                ) =>
        {
            true
        }
        // policy.toml and policy-session/new writes flow through to the VFS
        // wallets handler, which stages a first-party Sealed Approval for passkey
        // wallets (challenge + grant-gated install/mint) and writes local policy
        // immediately. They no longer route through the disabled write_unlocked
        // re-sign lane, so the mount must forward them to `vfs.write` rather than
        // deny on flush.
        _ => false,
    }
}

/// Command sinks whose supported payloads are deliberately small and are
/// expected to be submitted by a single userspace write (shell redirect,
/// `tee`, or equivalent). macOS' NFS client does not reliably send COMMIT or
/// propagate CLOSE errors for these synthetic files, so leaving an UNSTABLE
/// write buffered can make a successful command disappear entirely.
///
/// Keep this list narrow. Ordinary files still need whole-file buffering
/// because a first contiguous WRITE is not proof that more chunks will not
/// follow. Hyperliquid agent-session commands are JSON/control messages well
/// below the mount's 64 KiB `wsize`; applying their offset-zero WRITE inline is
/// what makes the documented mount-only workflow usable on macOS.
fn mount_write_path_is_atomic_command(path: &VfsPath) -> bool {
    let segs = path.segments();
    match segs {
        [root, _network, branch, _wallet, leaf]
            if root == "hyperliquid" && branch == "agent_sessions" && leaf == "new.json" =>
        {
            true
        }
        [root, _network, branch, _wallet, _session, leaf]
            if root == "hyperliquid"
                && branch == "agent_sessions"
                && matches!(
                    leaf.as_str(),
                    "order.json"
                        | "cancel.json"
                        | "schedule_cancel.json"
                        | "stop"
                        | "cancel_all"
                        | "close_all"
                ) =>
        {
            true
        }
        _ => false,
    }
}

/// Convert a `HandlerError` from the VFS into the matching NFS error.
fn map_err(e: HandlerError) -> FsError {
    match e {
        HandlerError::NotFound(_) => FsError::NotFound,
        HandlerError::NotADir(_) => FsError::NotDirectory,
        HandlerError::NotAFile(_) => FsError::IsDirectory,
        HandlerError::PermissionDenied => FsError::AccessDenied,
        HandlerError::OperationNotPermitted => FsError::PermissionDenied,
        HandlerError::Invalid(_) => FsError::InvalidInput,
        HandlerError::Unsupported(_) => FsError::Unsupported,
        HandlerError::Backend(_) => FsError::Io,
        HandlerError::Io(_) => FsError::Io,
    }
}

/// Build a stable fallback timestamp. The VFS doesn't expose mtime per
/// entry today; change attributes carry cache invalidation instead.
fn epoch_ts() -> Timestamp {
    Timestamp {
        seconds: 0,
        nanos: 0,
    }
}

fn stable_attrs(object_type: ObjectType, fileid: u64) -> Attrs {
    let mut attrs = Attrs::new(object_type, fileid);
    let ts = epoch_ts();
    attrs.atime = ts;
    attrs.mtime = ts;
    attrs.ctime = ts;
    attrs.birthtime = ts;
    attrs
}

/// Build attrs for an Entry returned by `list` / `lookup`.
///
/// File `change` is bumped on every call. Bloom's file content is
/// computed lazily from chain state — the same path can return new
/// bytes between calls (balance.raw, gas/suggest, head). Linux's NFS
/// client validates page-cache pages against `change`: if it doesn't
/// move, the cached pages stay live regardless of `mtime` or the
/// `noac` mount option. Returning a fresh change here forces the
/// kernel to re-issue READ on every access, and the router-level
/// `PathCache` (TTL per path) absorbs the cost so dynamic reads stay
/// snappy without serving stale bytes.
fn entry_to_attrs(path: &VfsPath, e: &Entry, size: u64) -> Attrs {
    let ot = match e.kind {
        EntryKind::Dir => ObjectType::Directory,
        EntryKind::File => ObjectType::File,
        EntryKind::Symlink => ObjectType::Symlink,
    };
    let size = if e.kind == EntryKind::Symlink && size == 0 {
        e.link_target
            .as_ref()
            .map(|target| target.len() as u64)
            .unwrap_or(0)
    } else {
        size
    };
    let mut a = stable_attrs(ot, fileid_for(path));
    a.size = size;
    a.space_used = size;
    a.mode = e.mode;
    if matches!(e.kind, EntryKind::File | EntryKind::Symlink) {
        a.change = file_change_now();
    }
    a
}

/// Monotonically-increasing change id for files. Uses nanosecond
/// wall-clock with an atomic floor so two calls within the same nano
/// still produce distinct values.
fn file_change_now() -> u64 {
    static FLOOR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut prev = FLOOR.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = now.max(prev.wrapping_add(1));
        match FLOOR.compare_exchange_weak(
            prev,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(observed) => prev = observed,
        }
    }
}

/// Per-path buffered write state. Holds the assembled file contents
/// (sparse during in-flight writes, contiguous at flush time) plus a
/// last-write timestamp so the idle-flush task can collect stragglers.
///
/// Writes can arrive out of order — the kernel is free to issue
/// `WRITE off=4096`, `WRITE off=0`, `WRITE off=8192` in any sequence.
/// We tolerate that by sizing `bytes` to the high-water mark and
/// tracking the set of filled byte ranges in `filled` (a sorted map
/// keyed by start offset). The buffer is flushable once the union of
/// those ranges is exactly `[0, bytes.len())`.
#[derive(Debug)]
struct WriteBuffer {
    /// Logical file contents, indexed by offset. Bytes inside a range
    /// recorded in `filled` are valid; bytes outside remain at their
    /// default zero and must not be flushed.
    bytes: Vec<u8>,
    /// Sorted, non-overlapping, non-adjacent map of filled byte
    /// ranges keyed by start offset (value is end offset, exclusive).
    /// Adjacent and overlapping ranges are merged on insert so the
    /// "is contiguous prefix" check is a single map lookup.
    filled: BTreeMap<usize, usize>,
    /// Timestamp of the most recent write. Stale-buffer cleanup compares
    /// against this so an abandoned partial write can be reaped on a later
    /// read of the same path.
    last_write: Instant,
    /// Total bytes the client has handed us across all WRITEs (count
    /// of bytes received, not max-offset). Tracked for the FBIG cap so
    /// pathological out-of-order patterns can't blow past the limit.
    received: usize,
}

impl WriteBuffer {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            filled: BTreeMap::new(),
            last_write: Instant::now(),
            received: 0,
        }
    }

    /// Apply a chunk at the requested offset. Grows `bytes` as needed
    /// and merges the new `[off, end)` range into `filled`. Returns
    /// `Err(FsError::FileTooLarge)` if accepting the chunk would push
    /// the buffer past `MAX_WRITE_BUFFER_BYTES`.
    fn apply(&mut self, offset: u64, data: &[u8]) -> FsResult<()> {
        let off = usize::try_from(offset).map_err(|_| FsError::FileTooLarge)?;
        let end = off.checked_add(data.len()).ok_or(FsError::FileTooLarge)?;
        if end > MAX_WRITE_BUFFER_BYTES {
            return Err(FsError::FileTooLarge);
        }
        if end > self.bytes.len() {
            self.bytes.resize(end, 0);
        }
        self.bytes[off..end].copy_from_slice(data);
        self.merge_range(off, end);
        self.last_write = Instant::now();
        self.received = self.received.saturating_add(data.len());
        Ok(())
    }

    /// Merge `[start, end)` into `filled`, coalescing with any
    /// adjacent or overlapping ranges. After this returns, `filled`
    /// remains a valid disjoint, non-adjacent set keyed by start
    /// offset.
    fn merge_range(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        let mut new_start = start;
        let mut new_end = end;
        // Absorb any range whose start <= new_end (i.e. overlapping
        // or adjacent on the right) and whose end >= new_start (i.e.
        // overlapping or adjacent on the left). Collect keys first
        // because we mutate the map while iterating.
        let to_remove: Vec<usize> = self
            .filled
            .range(..=new_end)
            .filter_map(|(&s, &e)| if e >= new_start { Some(s) } else { None })
            .collect();
        for key in to_remove {
            let existing_end = self.filled.remove(&key).expect("just observed");
            new_start = new_start.min(key);
            new_end = new_end.max(existing_end);
        }
        self.filled.insert(new_start, new_end);
    }

    /// Returns true if the buffered contents form a contiguous prefix
    /// starting at offset 0 — i.e. it's safe to flush.
    fn is_complete(&self) -> bool {
        if self.bytes.is_empty() {
            return false;
        }
        match self.filled.iter().next() {
            Some((&start, &end)) => start == 0 && end == self.bytes.len(),
            None => false,
        }
    }

    fn should_flush_after_write(&self, requested: WriteStability) -> bool {
        self.is_complete()
            && matches!(
                requested,
                WriteStability::DataSync | WriteStability::FileSync
            )
    }
}

/// Always-on TTL cache that bridges a GETATTR-time render with the
/// READ that immediately follows. Independent of the VFS-side
/// [`bloom_vfs::PathCache`] (which is opt-in via `Handler::cache_ttl`):
/// this one fires for every renderable file so the size returned in
/// GETATTR matches the bytes returned in READ, byte-for-byte.
///
/// Bounded with simple LRU eviction so a client walking a large tree
/// cannot blow through process memory.
struct MountRenderCache {
    inner: Mutex<LruCache<VfsPath, MountRenderEntry>>,
}

#[derive(Clone)]
struct MountRenderEntry {
    result: MountRenderResult,
    expires_at: Instant,
}

#[derive(Clone)]
enum MountRenderResult {
    Bytes(Bytes),
    Error(FsError),
}

impl MountRenderCache {
    fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity > 0");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    fn get(&self, path: &VfsPath) -> Option<MountRenderResult> {
        let mut g = self.inner.lock();
        let expired = g.peek(path).map(|e| e.expires_at <= Instant::now());
        match expired {
            Some(true) => {
                g.pop(path);
                None
            }
            Some(false) => g.get(path).map(|e| e.result.clone()),
            None => None,
        }
    }

    fn put(&self, path: &VfsPath, bytes: Bytes, ttl: Duration) {
        let entry = MountRenderEntry {
            result: MountRenderResult::Bytes(bytes),
            expires_at: Instant::now() + ttl,
        };
        self.inner.lock().put(path.clone(), entry);
    }

    fn put_error(&self, path: &VfsPath, error: FsError, ttl: Duration) {
        let entry = MountRenderEntry {
            result: MountRenderResult::Error(error),
            expires_at: Instant::now() + ttl,
        };
        self.inner.lock().put(path.clone(), entry);
    }

    /// Drop any cached render for `path` — called after a successful write so a
    /// follow-up GETATTR/READ/READDIR re-renders the live body instead of
    /// serving the pre-write bytes still sitting in the cache within its TTL.
    fn invalidate(&self, path: &VfsPath) {
        self.inner.lock().pop(path);
    }
}

/// Shared future type for in-flight render dedup. Concurrent GETATTR /
/// READ calls for the same path coalesce onto a single render so a
/// cold expensive leaf (e.g. `chains/<c>/tx/<h>/error.json`) cannot
/// stampede when NFS clients retry slow ops.
///
/// `FsError` is cloneable, so native and Petal `HandlerError` values can be
/// mapped through Bloom's existing NFS semantics before the future is shared.
type RenderFuture = Shared<BoxFuture<'static, Result<Bytes, FsError>>>;

/// One stable, ordered directory view used by GETATTR and every READDIR page.
struct DirectorySnapshot {
    entries: Arc<[Entry]>,
    change: u64,
}

struct MountDirectoryEntry {
    entries: Option<Arc<[Entry]>>,
    change: u64,
    created_at: Instant,
    last_used_at: Instant,
    last_validated_at: Instant,
}

/// Short-lived mount cache for NFS directory enumeration. This is separate
/// from the VFS read cache: list pagination and cookie verifiers have their own
/// coherence requirements, and handlers should not need NFS-specific caches.
struct MountDirectoryCache {
    inner: Mutex<LruCache<VfsPath, MountDirectoryEntry>>,
    generation: AtomicU64,
}

impl MountDirectoryCache {
    fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity > 0");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            generation: AtomicU64::new(1),
        }
    }

    fn entry_expired(entry: &MountDirectoryEntry, now: Instant) -> bool {
        now.duration_since(entry.last_used_at) > DIRECTORY_CACHE_IDLE_TTL
            || now.duration_since(entry.created_at) > DIRECTORY_CACHE_MAX_AGE
    }

    fn get(&self, path: &VfsPath) -> Option<Arc<DirectorySnapshot>> {
        let now = Instant::now();
        let mut cache = self.inner.lock();
        let expired = cache
            .peek(path)
            .map(|entry| Self::entry_expired(entry, now));
        match expired {
            Some(true) => {
                cache.pop(path);
                trace!(path = %path, "mount.directory_cache.expired");
                None
            }
            Some(false) => {
                let entry = cache.get_mut(path).expect("entry observed above");
                entry.last_used_at = now;
                let Some(entries) = &entry.entries else {
                    trace!(path = %path, change = entry.change, "mount.directory_cache.metadata_hit");
                    return None;
                };
                trace!(path = %path, change = entry.change, "mount.directory_cache.hit");
                Some(Arc::new(DirectorySnapshot {
                    entries: entries.clone(),
                    change: entry.change,
                }))
            }
            None => {
                trace!(path = %path, "mount.directory_cache.miss");
                None
            }
        }
    }

    /// Return a child's known change without loading or extending its idle
    /// lifetime. READDIRPLUS must never recursively evaluate child listings.
    fn cached_change(&self, path: &VfsPath) -> Option<u64> {
        let now = Instant::now();
        let mut cache = self.inner.lock();
        let expired = cache
            .peek(path)
            .map(|entry| Self::entry_expired(entry, now));
        if expired == Some(true) {
            cache.pop(path);
            return None;
        }
        cache.peek(path).map(|entry| entry.change)
    }

    /// Allocate or reuse the change token which NFS uses as its cookie
    /// verifier. This metadata-only operation deliberately does not call
    /// `Vfs::list`; the first READDIR fills entries under the same token.
    fn metadata(&self, path: &VfsPath) -> (u64, Instant) {
        let now = Instant::now();
        let mut cache = self.inner.lock();
        let expired = cache
            .peek(path)
            .map(|entry| Self::entry_expired(entry, now));
        if expired == Some(true) {
            cache.pop(path);
        }
        if let Some(entry) = cache.get_mut(path) {
            entry.last_used_at = now;
            return (entry.change, entry.created_at);
        }
        let change = file_change_now();
        cache.put(
            path.clone(),
            MountDirectoryEntry {
                entries: None,
                change,
                created_at: now,
                last_used_at: now,
                last_validated_at: now,
            },
        );
        trace!(path = %path, change, "mount.directory_cache.metadata_inserted");
        (change, now)
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn needs_revalidation(&self, path: &VfsPath) -> bool {
        let now = Instant::now();
        let mut cache = self.inner.lock();
        let expired = cache
            .peek(path)
            .map(|entry| Self::entry_expired(entry, now));
        if expired == Some(true) {
            cache.pop(path);
            return true;
        }
        cache.peek(path).is_none_or(|entry| {
            now.duration_since(entry.last_validated_at) >= DIRECTORY_CACHE_REVALIDATE_INTERVAL
        })
    }

    fn put_listing_if_generation(
        &self,
        path: VfsPath,
        entries: Arc<[Entry]>,
        generation: u64,
    ) -> Arc<DirectorySnapshot> {
        let now = Instant::now();
        let mut cache = self.inner.lock();
        if self.generation() != generation {
            trace!(path = %path, "mount.directory_cache.insert_skipped_after_invalidation");
            return Arc::new(DirectorySnapshot {
                entries,
                change: file_change_now(),
            });
        }

        let existing = cache.peek(&path);
        let unchanged = existing
            .and_then(|entry| entry.entries.as_deref())
            .is_some_and(|current| directory_entries_equal(current, &entries));
        // A metadata-only entry has not exposed a listing yet, so the first
        // READDIR must fill it under the same verifier allocated by GETATTR.
        let preserve_change = existing.is_some_and(|entry| entry.entries.is_none()) || unchanged;
        let change = existing
            .filter(|_| preserve_change)
            .map(|entry| entry.change)
            .unwrap_or_else(file_change_now);
        let created_at = existing
            .filter(|_| preserve_change)
            .map(|entry| entry.created_at)
            .unwrap_or(now);
        let snapshot = Arc::new(DirectorySnapshot {
            entries: entries.clone(),
            change,
        });
        let entry_count = entries.len();
        cache.put(
            path.clone(),
            MountDirectoryEntry {
                entries: Some(entries),
                change,
                created_at,
                last_used_at: now,
                last_validated_at: now,
            },
        );
        trace!(path = %path, entries = entry_count, change, "mount.directory_cache.inserted");
        snapshot
    }

    fn invalidate(&self, path: &VfsPath) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if self.inner.lock().pop(path).is_some() {
            trace!(path = %path, "mount.directory_cache.invalidated");
        }
    }
}

fn directory_entries_equal(left: &[Entry], right: &[Entry]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.name == right.name
                && left.kind == right.kind
                && left.size == right.size
                && left.mode == right.mode
                && left.link_target == right.link_target
        })
}

type DirectoryFuture = Shared<BoxFuture<'static, Result<Arc<DirectorySnapshot>, FsError>>>;

struct InFlightDirectory {
    generation: u64,
    future: DirectoryFuture,
}

/// Adapter that holds a clone of the [`Vfs`] facade and serves it as
/// an [`embednfs::FileSystem`].
///
/// ## Write buffering
///
/// The bloom VFS exposes a whole-file `write(path, &[u8])` API, but
/// NFS clients chunk a single user-space `write(2)` into multiple
/// `WRITE` ops at increasing offsets (with `wsize=4096`, a 16 KiB JSON
/// body becomes four ops at offsets 0/4096/8192/12288). Without
/// buffering, every chunk past the first would be either rejected
/// (offset != 0) or would clobber the file with a 4 KiB tail.
///
/// This adapter buffers WRITE chunks per file handle in
/// [`BloomFs::write_buffers`]. A buffer is flushed to the VFS on:
///
/// 1. An NFS COMMIT against the handle (the primary trigger — the
///    Linux client issues COMMIT after the userspace `close(2)` /
///    `fsync(2)` for unstable writes).
/// 2. The WRITE call itself when the request is synchronous and the
///    buffer is contiguous.
/// 3. A `read` against the same handle — we flush first, then read,
///    so the user observes their own writes.
///
/// Reads of an open partially-written file return the previously
/// committed contents, not the buffered bytes. This is the simplest
/// policy that preserves "write semantics from a single client read
/// back what the client just wrote" via the flush-before-read rule.
pub struct BloomFs {
    vfs: Vfs,
    /// Per-handle write buffers. Keyed by `VfsPath` so multiple clients
    /// writing the same file coalesce — NFS state-tracking the way the
    /// RFC describes it (open-stateid-keyed) would be more correct, but
    /// the bloom surface assumes a single agent per mount and the
    /// per-path scheme is dramatically simpler. The tradeoff: two
    /// concurrent writers to the same path see interleaved chunks and
    /// must serialise themselves at the application layer.
    write_buffers: Arc<Mutex<HashMap<VfsPath, WriteBuffer>>>,
    /// Mount-side render cache. Populated by `getattr` for renderable
    /// files (read-only mode, not side-effecting); consumed by `read`
    /// so the size we just reported matches the bytes returned. See
    /// [`MountRenderCache`] for why this is independent of the VFS
    /// `PathCache`.
    render_cache: Arc<MountRenderCache>,
    /// In-flight render futures keyed by VFS path. A second `getattr`
    /// (or read) for the same path while a render is running awaits
    /// the existing future instead of starting a new one. The map
    /// entry is removed once the future resolves — subsequent
    /// requests after the cache TTL re-render normally.
    in_flight: Arc<Mutex<HashMap<VfsPath, RenderFuture>>>,
    /// Stable snapshots shared by directory GETATTR and paginated READDIR.
    directory_cache: Arc<MountDirectoryCache>,
    /// Cold list operations coalesce independently from file renders.
    directory_in_flight: Arc<Mutex<HashMap<VfsPath, InFlightDirectory>>>,
}

impl BloomFs {
    pub fn new(vfs: Vfs) -> Self {
        Self {
            vfs,
            write_buffers: Arc::new(Mutex::new(HashMap::new())),
            render_cache: Arc::new(MountRenderCache::new(RENDER_CACHE_CAPACITY)),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            directory_cache: Arc::new(MountDirectoryCache::new(DIRECTORY_CACHE_CAPACITY)),
            directory_in_flight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Decompose a handle into the [`VfsPath`] it represents.
    fn path_of(handle: &BloomHandle) -> VfsPath {
        match handle {
            BloomHandle::Root => VfsPath::root(),
            BloomHandle::Path { path, .. } => path.clone(),
        }
    }

    async fn load_directory_snapshot(
        &self,
        dir_path: &VfsPath,
        revalidate: bool,
    ) -> FsResult<Arc<DirectorySnapshot>> {
        if let Some(snapshot) = self.directory_cache.get(dir_path)
            && (!revalidate || !self.directory_cache.needs_revalidation(dir_path))
        {
            return Ok(snapshot);
        }

        let future = {
            let mut in_flight = self.directory_in_flight.lock();
            if let Some(existing) = in_flight.get(dir_path) {
                trace!(path = %dir_path, "mount.directory_list.coalesced");
                existing.future.clone()
            } else if let Some(snapshot) = self.directory_cache.get(dir_path)
                && (!revalidate || !self.directory_cache.needs_revalidation(dir_path))
            {
                // A load may have completed between the first cache probe and
                // acquiring the in-flight lock.
                return Ok(snapshot);
            } else {
                let generation = self.directory_cache.generation();
                self.directory_cache.metadata(dir_path);
                let vfs = self.vfs.clone();
                let path = dir_path.clone();
                let cleanup_path = path.clone();
                let cache = self.directory_cache.clone();
                let in_flight_map = self.directory_in_flight.clone();
                let future = async move {
                    let result =
                        tokio::time::timeout(DIRECTORY_LIST_TIMEOUT, vfs.list(&path)).await;
                    let result = match result {
                        Ok(Ok(entries)) => Ok(cache.put_listing_if_generation(
                            path.clone(),
                            Arc::from(entries),
                            generation,
                        )),
                        Ok(Err(error)) => Err(map_err(error)),
                        Err(_) => {
                            warn!(path = %path, "mount.directory_list.timed_out");
                            Err(FsError::Io)
                        }
                    };
                    let mut in_flight = in_flight_map.lock();
                    if in_flight
                        .get(&cleanup_path)
                        .is_some_and(|entry| entry.generation == generation)
                    {
                        in_flight.remove(&cleanup_path);
                    }
                    result
                }
                .boxed()
                .shared();
                in_flight.insert(
                    dir_path.clone(),
                    InFlightDirectory {
                        generation,
                        future: future.clone(),
                    },
                );
                future
            }
        };
        future.await
    }

    async fn directory_snapshot(&self, dir_path: &VfsPath) -> FsResult<Arc<DirectorySnapshot>> {
        self.load_directory_snapshot(dir_path, false).await
    }

    async fn dir_change(&self, dir_path: &VfsPath) -> FsResult<u64> {
        let metadata = self.directory_cache.metadata(dir_path);
        if !self.directory_cache.needs_revalidation(dir_path) {
            return Ok(metadata.0);
        }

        Ok(self.load_directory_snapshot(dir_path, true).await?.change)
    }

    fn parent_path(path: &VfsPath) -> Option<VfsPath> {
        if path.is_root() {
            return None;
        }
        let mut parent = VfsPath::root();
        for segment in &path.segments()[..path.segments().len() - 1] {
            parent = parent.join(segment);
        }
        Some(parent)
    }

    fn invalidate_after_write(&self, path: &VfsPath) {
        self.render_cache.invalidate(path);
        self.directory_cache.invalidate(path);
        self.directory_in_flight.lock().remove(path);
        if let Some(parent) = Self::parent_path(path) {
            self.directory_cache.invalidate(&parent);
            self.directory_in_flight.lock().remove(&parent);
        }
    }

    /// Take a buffer's contents out, leaving the slot empty. Returns
    /// `Some(bytes)` only if the buffer was contiguous — partial
    /// buffers stay parked so a follow-up WRITE can fill the gap.
    fn take_complete_buffer(&self, path: &VfsPath) -> Option<Vec<u8>> {
        let mut map = self.write_buffers.lock();
        match map.get(path) {
            Some(buf) if buf.is_complete() => {
                let buf = map.remove(path).expect("just observed");
                Some(buf.bytes)
            }
            _ => None,
        }
    }

    /// Flush any buffered writes for `path` through to the VFS. No-op
    /// if the buffer is empty or non-contiguous; incomplete buffers can
    /// only be completed by a follow-up WRITE or discarded by
    /// `drop_stale_buffer` on a later read of the same path.
    async fn flush_path(&self, path: &VfsPath) -> FsResult<()> {
        if let Some(bytes) = self.take_complete_buffer(path) {
            if mount_write_path_uses_wallet_signer(path) {
                return Err(FsError::PermissionDenied);
            }
            trace!(path = %path.to_string_path(), bytes = bytes.len(), "mount.adapter.flush");
            self.vfs.write(path, &bytes).await.map_err(map_err)?;
            // The rendered view is now stale; drop it so the next read re-renders.
            self.invalidate_after_write(path);
        } else {
            trace!(path = %path.to_string_path(), "mount.adapter.flush.nothing_to_flush");
        }
        Ok(())
    }

    /// Discard any buffer for `path` whose last write is older than
    /// `WRITE_IDLE_FLUSH`. Used by the read path so an abandoned
    /// partial write doesn't shadow committed state forever.
    fn drop_stale_buffer(&self, path: &VfsPath) -> Option<Vec<u8>> {
        let mut map = self.write_buffers.lock();
        let stale = map
            .get(path)
            .map(|b| b.is_complete() || b.last_write.elapsed() > WRITE_IDLE_FLUSH)
            .unwrap_or(false);
        if stale {
            map.remove(path).map(|b| b.bytes)
        } else {
            None
        }
    }

    /// Whether it is safe to render `path` at GETATTR time so we can
    /// return the real `st_size`.
    ///
    /// Single gate: `is_read_side_effecting`. Defaults false; handlers
    /// override and return true for paths whose read triggers signing,
    /// broadcast, or other externally-visible action (canonical case:
    /// `wallets/<w>/sign/*`). Stat'ing those must not fire the side
    /// effect, so we report `size = 0` for them.
    ///
    /// Mode bits are *not* a useful gate here. Many writable files
    /// (mode 0o644) are also legitimately readable — addressbook
    /// aliases resolve to an address, `policy.toml` reads back the
    /// committed config, etc. A pure write-only sink (e.g.
    /// `outbox/pending/<id>/confirm`) returns a NotAFile-style error
    /// from `read`; that flows through `render_with_dedup` and falls
    /// out as `size = 0` at the failure branch in [`Self::getattr`],
    /// which is exactly what we want for sinks. Conversely, if we
    /// gated on `mode & 0o200` here, any rw file with real content
    /// would report `size = 0` and `cat` would short-circuit on the
    /// stat result.
    fn should_render_for_attrs(&self, path: &VfsPath, e: &Entry) -> bool {
        if e.kind != EntryKind::File {
            return false;
        }
        if self.vfs.is_read_side_effecting(path) {
            return false;
        }
        true
    }

    /// Render `path` with in-flight dedup and a hard timeout. Reuses
    /// an existing render future for the same path if one is already
    /// running.
    async fn render_with_dedup(&self, path: &VfsPath) -> Result<Bytes, FsError> {
        let fut: RenderFuture = {
            let mut map = self.in_flight.lock();
            if let Some(existing) = map.get(path) {
                existing.clone()
            } else {
                let vfs = self.vfs.clone();
                let path_owned = path.clone();
                let in_flight = self.in_flight.clone();
                let path_for_cleanup = path.clone();
                let render = async move {
                    let result = tokio::time::timeout(RENDER_TIMEOUT, vfs.read(&path_owned)).await;
                    let bytes = match result {
                        Ok(Ok(b)) => Ok(Bytes::from(b)),
                        Ok(Err(e)) => Err(map_err(e)),
                        Err(_) => Err(FsError::Io),
                    };
                    // Remove ourselves from the in-flight map so the
                    // next request after this resolves can start a
                    // fresh render. Entry under the same key may have
                    // been replaced if a different generation is
                    // running — only remove if it's still ours.
                    in_flight.lock().remove(&path_for_cleanup);
                    bytes
                }
                .boxed()
                .shared();
                map.insert(path.clone(), render.clone());
                render
            }
        };
        match fut.await {
            Ok(b) => Ok(b),
            Err(error) => {
                debug!(path = %path.to_string_path(), ?error, "mount.adapter.render_failed");
                Err(error)
            }
        }
    }
}

#[async_trait]
impl FileSystem for BloomFs {
    type Handle = BloomHandle;

    fn root(&self) -> BloomHandle {
        BloomHandle::Root
    }

    async fn statfs(&self, _ctx: &RequestContext) -> FsResult<FsStats> {
        Ok(FsStats::default())
    }

    async fn getattr(&self, _ctx: &RequestContext, handle: &BloomHandle) -> FsResult<Attrs> {
        match handle {
            BloomHandle::Root => {
                let mut a = stable_attrs(ObjectType::Directory, fileid_for(&VfsPath::root()));
                a.mode = 0o755;
                a.change = self.dir_change(&VfsPath::root()).await?;
                Ok(a)
            }
            BloomHandle::Path { entry: e, path } => {
                // For renderable read-only files, materialise the body
                // so we can return an accurate `st_size`. The bytes
                // are stashed in the mount-side cache so the imminent
                // READ serves the same body and `eof` lines up. Files
                // that are write-only or side-effecting fall through
                // with `size = 0` and never trigger a render here —
                // critical to avoid a `stat` triggering a sign or
                // broadcast.
                let size = if self.should_render_for_attrs(path, e) {
                    match self.render_cache.get(path) {
                        Some(MountRenderResult::Bytes(bytes)) => bytes.len() as u64,
                        Some(MountRenderResult::Error(FsError::IsDirectory)) => e.size,
                        Some(MountRenderResult::Error(error)) => return Err(error),
                        None => match self.render_with_dedup(path).await {
                            Ok(bytes) => {
                                let len = bytes.len() as u64;
                                self.render_cache.put(path, bytes, RENDER_CACHE_TTL);
                                len
                            }
                            Err(FsError::IsDirectory) => {
                                // Lookup already proved this is a file. Bloom's
                                // existing NotAFile -> IsDirectory mapping
                                // therefore identifies a deliberate unreadable
                                // command sink rather than a failed data read.
                                self.render_cache.put_error(
                                    path,
                                    FsError::IsDirectory,
                                    RENDER_CACHE_TTL,
                                );
                                debug!(path = %path, "mount.adapter.getattr.unreadable_file_sink");
                                e.size
                            }
                            Err(error) => {
                                self.render_cache.put_error(path, error, RENDER_CACHE_TTL);
                                warn!(path = %path, ?error, "mount.adapter.getattr.render_failed");
                                return Err(error);
                            }
                        },
                    }
                } else {
                    0
                };

                let mut attrs = entry_to_attrs(path, e, size);
                if e.kind == EntryKind::Dir {
                    attrs.change = self.dir_change(path).await?;
                }
                Ok(attrs)
            }
        }
    }

    async fn access(
        &self,
        _ctx: &RequestContext,
        handle: &BloomHandle,
        requested: AccessMask,
    ) -> FsResult<AccessMask> {
        // Per the v1 spec, the great majority of the tree is read-only
        // (chains/*, status/*, tools/* outputs, prices/*, docs/*, audit
        // views, wallet metadata, watch outputs). Those entries report
        // mode 0o444 from the VFS; only a small handful of injection
        // points (wallets/new, sign/*, outbox writes, watch/new, defi
        // intents new+confirm, policy.toml) report 0o644. Reflect that
        // here so clients see a faithful permission view in `stat` /
        // `access(2)` rather than discovering write rejection only at
        // write-time.
        let mode = match handle {
            BloomHandle::Root => 0o755,
            BloomHandle::Path { entry, .. } => entry.mode,
        };
        let mut granted = requested;
        // Owner-write bit absent => mask off MODIFY/EXTEND/DELETE.
        if mode & 0o200 == 0 {
            let write_bits = AccessMask::MODIFY | AccessMask::EXTEND | AccessMask::DELETE;
            granted = AccessMask(granted.bits() & !write_bits.bits());
        }
        Ok(granted)
    }

    async fn lookup(
        &self,
        _ctx: &RequestContext,
        parent: &BloomHandle,
        name: &str,
    ) -> FsResult<BloomHandle> {
        // Reject names that would corrupt the VFS path.
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(FsError::InvalidInput);
        }
        // The kernel splits paths on `/` only and hands us each
        // component verbatim. Users embed special bytes (space, `?`,
        // `#`, even `/`) using percent-escapes, so decode here — this
        // is the single chokepoint where kernel-supplied bytes become
        // a VFS path segment. See `bloom_vfs::percent_decode_segment`.
        let decoded = percent_decode_segment(name).map_err(|e| {
            debug!(name = %name, error = %e, "mount.adapter.lookup.bad_percent_escape");
            FsError::InvalidInput
        })?;
        let parent_path = Self::path_of(parent);
        let child = parent_path.join(&decoded);
        let e = self.vfs.lookup(&child).await.map_err(map_err)?;
        Ok(BloomHandle::Path {
            entry: e,
            path: child,
        })
    }

    async fn parent(
        &self,
        _ctx: &RequestContext,
        dir: &BloomHandle,
    ) -> FsResult<Option<BloomHandle>> {
        match dir {
            BloomHandle::Root => Ok(None),
            BloomHandle::Path { path, .. } => {
                let segs = path.segments();
                if segs.len() <= 1 {
                    Ok(Some(BloomHandle::Root))
                } else {
                    let parent_str = format!("/{}", segs[..segs.len() - 1].join("/"));
                    let parent = VfsPath::parse(&parent_str).map_err(|_| FsError::InvalidInput)?;
                    let name = parent
                        .segments()
                        .last()
                        .expect("non-root parent has a final segment");
                    Ok(Some(BloomHandle::Path {
                        entry: Entry::dir(name),
                        path: parent,
                    }))
                }
            }
        }
    }

    async fn readdir(
        &self,
        _ctx: &RequestContext,
        dir: &BloomHandle,
        cookie: u64,
        max_entries: u32,
        with_attrs: bool,
    ) -> FsResult<DirPage<BloomHandle>> {
        let dir_path = Self::path_of(dir);
        let snapshot = self.directory_snapshot(&dir_path).await?;
        let entries = &snapshot.entries;

        // Pagination: cookie 0 means "from the start". We hand out
        // dense cookies starting at 3 because 0/1/2 are reserved by
        // the NFSv4 spec for `.` / `..` semantics.
        let start = if cookie == 0 {
            0
        } else {
            cookie.saturating_sub(2) as usize
        };
        let limit = if max_entries == 0 {
            usize::MAX
        } else {
            max_entries as usize
        };
        let total = entries.len();
        let mut out = Vec::new();
        for (idx, e) in entries.iter().skip(start).take(limit).enumerate() {
            let child_path = dir_path.join(&e.name);
            let handle = BloomHandle::Path {
                entry: e.clone(),
                path: child_path.clone(),
            };
            let attrs = if with_attrs {
                // READDIRPLUS does not eagerly render every child —
                // that would make `ls -l` of a heavy directory cost
                // a full pipeline run per leaf. Instead we use:
                //   - the entry's own `size` if the handler set one
                //     (cheap-to-compute paths like static docs),
                //   - the render-cache's bytes if a recent `getattr`
                //     populated it for this child (so `ls -l` after
                //     `cat` shows real size),
                //   - 0 otherwise.
                // The kernel mounts use `actimeo=0` (Linux) /
                // equivalent (other) so this size is not trusted
                // past the immediate listing display; the next read
                // re-issues GETATTR and gets a real size.
                let size = if e.kind == EntryKind::File {
                    match self.render_cache.get(&child_path) {
                        Some(MountRenderResult::Bytes(b)) => b.len() as u64,
                        Some(MountRenderResult::Error(_)) | None => e.size,
                    }
                } else {
                    e.size
                };
                let mut a = entry_to_attrs(&child_path, e, size);
                if e.kind == EntryKind::Dir {
                    // Never run a child list merely to build parent
                    // READDIRPLUS attrs. Reuse a known change when available;
                    // the child's own GETATTR loads it when traversed.
                    if let Some(change) = self.directory_cache.cached_change(&child_path) {
                        a.change = change;
                    }
                }
                Some(a)
            } else {
                None
            };
            out.push(DirEntry {
                name: e.name.clone(),
                handle,
                cookie: (start + idx + 3) as u64,
                attrs,
            });
        }
        let eof = start + out.len() >= total;
        Ok(DirPage { entries: out, eof })
    }

    async fn read(
        &self,
        _ctx: &RequestContext,
        handle: &BloomHandle,
        offset: u64,
        count: u32,
    ) -> FsResult<ReadResult> {
        let path = match handle {
            BloomHandle::Root => return Err(FsError::IsDirectory),
            BloomHandle::Path { path, .. } => path.clone(),
        };
        // If the client has buffered writes that complete a contiguous
        // file, flush them now so the read sees the latest state. We
        // also opportunistically drop stale partial buffers so an
        // orphaned WRITE doesn't pin memory across reads.
        self.flush_path(&path).await?;
        let _ = self.drop_stale_buffer(&path);

        // Fast path: GETATTR usually runs immediately before READ
        // (especially with `noac`/`actimeo=0`) and stashes the
        // rendered body. Reading from that cache guarantees the size
        // we returned in GETATTR matches what READ delivers, so `eof`
        // is correct and tooling never sees NUL padding past EOF.
        let data: Bytes = if let Some(cached) = self.render_cache.get(&path) {
            match cached {
                MountRenderResult::Bytes(b) => b,
                MountRenderResult::Error(error) => return Err(error),
            }
        } else {
            // Cache miss — go straight to the VFS. This covers reads
            // without a preceding GETATTR (e.g. some kernel paths
            // that trust READDIRPLUS attrs) and reads that arrive
            // after the render TTL elapsed. We do not populate the
            // cache here on purpose: only GETATTR-driven renders
            // know they will be paired with a READ that needs
            // matching size, so they own the cache.
            Bytes::from(self.vfs.read(&path).await.map_err(map_err)?)
        };

        let off = usize::try_from(offset).map_err(|_| FsError::FileTooLarge)?;
        if off >= data.len() {
            return Ok(ReadResult {
                data: Bytes::new(),
                eof: true,
            });
        }
        let end = off.saturating_add(count as usize).min(data.len());
        let chunk = data.slice(off..end);
        Ok(ReadResult {
            data: chunk,
            eof: end == data.len(),
        })
    }

    async fn write(
        &self,
        _ctx: &RequestContext,
        handle: &BloomHandle,
        offset: u64,
        data: Bytes,
        requested: WriteStability,
    ) -> FsResult<WriteResult> {
        let path = match handle {
            BloomHandle::Root => return Err(FsError::IsDirectory),
            BloomHandle::Path { path, .. } => path.clone(),
        };
        let len = data.len();
        if len == 0 {
            // Zero-byte writes don't carry data and never complete a
            // buffer; treat them as no-ops at this layer. They can
            // still be useful for `create` (handled separately) and
            // for kernels that use them as truncate hints (we ignore
            // truncate-via-write and rely on `setattr` for size).
            return Ok(WriteResult {
                written: 0,
                stability: requested,
            });
        }

        // Buffer the chunk. We lock long enough to apply the chunk and
        // observe whether the buffer is now complete; the actual VFS
        // write happens outside the lock so a slow handler can't stall
        // concurrent writers to other paths.
        //
        // We must honour the kernel's requested stability: the embednfs
        // server enforces `actual >= requested` and returns SERVERFAULT
        // (kernel surfaces this as EREMOTEIO) on mismatch. Linux's NFSv4
        // client routinely upgrades small writes to DATA_SYNC/FILE_SYNC
        // (e.g. when `wsize` covers the whole body) so we cannot blindly
        // advertise UNSTABLE for every reply.
        //
        // Strategy:
        // - Flush eagerly when the request is sync-stable and the buffer is
        //   contiguous, or for a narrowly-classified atomic command sink at
        //   offset zero. NFS WRITE does not otherwise carry an EOF/final chunk
        //   marker, so an ordinary UNSTABLE offset-0 prefix that may grow must
        //   wait for COMMIT even if it could also be a whole single-RPC write.
        // - DATA_SYNC / FILE_SYNC requested but buffer is incomplete
        //   (mid-stream chunk): reject explicitly. Returning a weaker
        //   stability than requested violates embednfs' contract and
        //   surfaces as SERVERFAULT/EREMOTEIO.
        // - UNSTABLE requested: buffer and reply UNSTABLE; a later
        //   COMMIT or read will trigger `flush_path`.
        let (complete_payload, accepted) = {
            let mut map = self.write_buffers.lock();
            let buf = map.entry(path.clone()).or_insert_with(WriteBuffer::new);
            // FBIG check before mutating: fail fast so the client gets
            // a clean error rather than silently truncated input.
            let proposed_received = buf.received.saturating_add(len);
            if proposed_received > MAX_WRITE_BUFFER_BYTES {
                map.remove(&path);
                return Err(FsError::FileTooLarge);
            }
            buf.apply(offset, &data)?;
            let payload = if buf.should_flush_after_write(requested)
                || (offset == 0 && mount_write_path_is_atomic_command(&path) && buf.is_complete())
            {
                Some(map.remove(&path).expect("just observed").bytes)
            } else {
                None
            };
            (payload, len)
        };

        if complete_payload.is_none()
            && matches!(
                requested,
                WriteStability::DataSync | WriteStability::FileSync
            )
        {
            self.write_buffers.lock().remove(&path);
            return Err(FsError::Unsupported);
        }

        let actual_stability = if complete_payload.is_some() {
            // We persisted the buffer through to the VFS, so we can
            // honour whatever sync level the kernel asked for.
            requested
        } else {
            // Still buffering: only safe to advertise UNSTABLE so the
            // kernel sends a follow-up COMMIT.
            WriteStability::Unstable
        };

        if let Some(payload) = complete_payload {
            if mount_write_path_uses_wallet_signer(&path) {
                return Err(FsError::PermissionDenied);
            }
            match self.vfs.write(&path, &payload).await {
                Ok(()) => {
                    // Persisted new bytes — invalidate any stale rendered view.
                    self.invalidate_after_write(&path);
                }
                Err(error) if mount_write_path_is_atomic_command(&path) => {
                    // macOS can panic in nfs_vinvalbuf2 when a userspace server
                    // rejects an UNSTABLE WRITE after the kernel has installed
                    // dirty UBC pages. These command sinks expose their outcome
                    // through challenge/status/audit/last-response files, so
                    // acknowledge the transport write after the handler has
                    // recorded that outcome instead of feeding a deferred NFS
                    // error back into the kernel's page invalidation path.
                    warn!(
                        path = %path.to_string_path(),
                        error = %error,
                        "mount.adapter.atomic_command_outcome_deferred"
                    );
                    self.invalidate_after_write(&path);
                }
                Err(error) => return Err(map_err(error)),
            }
        }

        Ok(WriteResult {
            written: u32::try_from(accepted).unwrap_or(u32::MAX),
            stability: actual_stability,
        })
    }

    async fn create(
        &self,
        _ctx: &RequestContext,
        parent: &BloomHandle,
        name: &str,
        req: CreateRequest,
    ) -> FsResult<CreateResult<BloomHandle>> {
        // VFS doesn't expose a create-empty op; for files we issue a
        // zero-byte write (writable handlers are expected to materialise
        // an entry). For content-sensitive handlers, a successful
        // zero-byte create is not a guarantee that the subsequent
        // content write will succeed. Directory creation is not
        // supported in v1 — the VFS structure is fixed.
        if matches!(req.kind, CreateKind::Directory) {
            return Err(FsError::Unsupported);
        }
        if name.is_empty() || name.contains('/') {
            return Err(FsError::InvalidInput);
        }
        // Same chokepoint as `lookup`: percent-decode the kernel-
        // supplied component before it becomes a VFS path segment.
        let decoded = percent_decode_segment(name).map_err(|e| {
            debug!(name = %name, error = %e, "mount.adapter.create.bad_percent_escape");
            FsError::InvalidInput
        })?;
        let parent_path = Self::path_of(parent);
        let child = parent_path.join(&decoded);
        if mount_write_path_uses_wallet_signer(&child) {
            return Err(FsError::PermissionDenied);
        }
        self.vfs.write(&child, &[]).await.map_err(map_err)?;
        self.invalidate_after_write(&child);
        let e = self.vfs.lookup(&child).await.map_err(map_err)?;
        // CREATE returns initial attrs; the file has just been written
        // empty (or with a zero-byte body). Report `e.size` so a
        // handler that knows its post-create size can inform the
        // client; otherwise 0 is honest.
        let attrs = entry_to_attrs(&child, &e, e.size);
        let handle = BloomHandle::Path {
            entry: e,
            path: child,
        };
        Ok(CreateResult { handle, attrs })
    }

    async fn remove(
        &self,
        _ctx: &RequestContext,
        _parent: &BloomHandle,
        _name: &str,
    ) -> FsResult<()> {
        // VFS is append/overwrite only in v1.
        Err(FsError::Unsupported)
    }

    async fn rename(
        &self,
        _ctx: &RequestContext,
        _from_dir: &BloomHandle,
        _from_name: &str,
        _to_dir: &BloomHandle,
        _to_name: &str,
    ) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    async fn setattr(
        &self,
        ctx: &RequestContext,
        handle: &BloomHandle,
        _attrs: &SetAttrs,
    ) -> FsResult<Attrs> {
        // No-op: refresh attrs from the VFS and return them.
        self.getattr(ctx, handle).await
    }

    fn commit_support(&self) -> Option<&dyn CommitSupport<BloomHandle>> {
        // Surface ourselves as the commit handler so the kernel's
        // post-write COMMIT op routes back into [`BloomFs::commit`] and
        // flushes the per-handle write buffer.
        Some(self)
    }

    fn open_support(&self) -> Option<&dyn OpenSupport<BloomHandle>> {
        Some(self)
    }

    fn symlinks(&self) -> Option<&dyn Symlinks<BloomHandle>> {
        Some(self)
    }
}

#[async_trait]
impl OpenSupport<BloomHandle> for BloomFs {
    async fn open(
        &self,
        _ctx: &RequestContext,
        handle: &BloomHandle,
        request: OpenRequest,
    ) -> FsResult<()> {
        if !request.write {
            return Ok(());
        }
        let path = match handle {
            BloomHandle::Root => return Err(FsError::IsDirectory),
            BloomHandle::Path { entry, path } => {
                if entry.kind != EntryKind::File {
                    return Err(FsError::IsDirectory);
                }
                path.clone()
            }
        };
        self.vfs.prepare_write_open(&path).await.map_err(map_err)?;
        if mount_write_path_uses_wallet_signer(&path) {
            return Err(FsError::PermissionDenied);
        }
        Ok(())
    }
}

#[async_trait]
impl Symlinks<BloomHandle> for BloomFs {
    async fn create_symlink(
        &self,
        _ctx: &RequestContext,
        _parent: &BloomHandle,
        _name: &str,
        _target: &str,
        _attrs: &SetAttrs,
    ) -> FsResult<CreateResult<BloomHandle>> {
        Err(FsError::Unsupported)
    }

    async fn readlink(&self, _ctx: &RequestContext, handle: &BloomHandle) -> FsResult<String> {
        let path = match handle {
            BloomHandle::Root => return Err(FsError::InvalidInput),
            BloomHandle::Path { path, .. } => path,
        };
        let entry = self.vfs.lookup(path).await.map_err(map_err)?;
        match entry.kind {
            EntryKind::Symlink => entry.link_target.ok_or(FsError::InvalidInput),
            _ => Err(FsError::InvalidInput),
        }
    }
}

#[async_trait]
impl CommitSupport<BloomHandle> for BloomFs {
    async fn commit(
        &self,
        _ctx: &RequestContext,
        handle: &BloomHandle,
        _offset: u64,
        _count: u32,
    ) -> FsResult<()> {
        // NFS COMMIT is byte-range scoped, but the bloom VFS is
        // whole-file. We treat any COMMIT against a handle as "flush
        // everything you have for this path". If the buffer is
        // incomplete (a missing prefix), we leave it in place — the
        // client will either resend the missing chunk or the idle
        // timer will reap it on the next read.
        let path = match handle {
            BloomHandle::Root => return Err(FsError::IsDirectory),
            BloomHandle::Path { path, .. } => path.clone(),
        };
        self.flush_path(&path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use bloom_vfs::handler::{Entry, Handler, HandlerError};

    struct StaticHandler;

    #[async_trait]
    impl Handler for StaticHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                return Ok(Entry::dir(""));
            }
            match p.first() {
                Some("hello") => Ok(Entry::file("hello")),
                Some("latest") => Ok(Entry::symlink("latest", "pending/req-1")),
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }
        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Ok(b"world\n".to_vec())
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![
                    Entry::file("hello"),
                    Entry::symlink("latest", "pending/req-1"),
                ])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    /// Test handler that records every `write` it sees and exposes a
    /// single writable file `inbox`. Used to verify the adapter's
    /// per-handle write buffering coalesces multi-block writes into
    /// exactly one `vfs.write` call.
    #[derive(Default)]
    struct RecordingHandler {
        writes: parking_lot::Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn write_count(&self) -> usize {
            self.writes.lock().len()
        }

        fn last_write(&self) -> Option<Vec<u8>> {
            self.writes.lock().last().cloned()
        }
    }

    /// Models a handler that stages a side effect, such as writing an
    /// approval_challenge.json, before denying the attempted write.
    #[derive(Default)]
    struct ChallengeStagingHandler {
        staged: parking_lot::Mutex<Vec<Vec<u8>>>,
    }

    impl ChallengeStagingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn staged_count(&self) -> usize {
            self.staged.lock().len()
        }
    }

    #[derive(Default)]
    struct AtomicDenyHandler {
        writes: parking_lot::Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl Handler for AtomicDenyHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            Ok(Entry::writable_file(
                p.segments().last().map(String::as_str).unwrap_or("command"),
            ))
        }

        async fn write(&self, _p: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
            self.writes.lock().push(data.to_vec());
            Err(HandlerError::PermissionDenied)
        }
    }

    #[async_trait]
    impl Handler for ChallengeStagingHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                return Ok(Entry::dir(""));
            }
            match p.first() {
                Some("challenge") => Ok(Entry::writable_file("challenge")),
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }

        async fn write(&self, p: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
            match p.first() {
                Some("challenge") => {
                    self.staged.lock().push(data.to_vec());
                    Err(HandlerError::PermissionDenied)
                }
                _ => Err(HandlerError::PermissionDenied),
            }
        }

        async fn prepare_write_open(&self, p: &VfsPath) -> Result<(), HandlerError> {
            match p.first() {
                Some("challenge") => {
                    self.staged.lock().push(Vec::new());
                    Err(HandlerError::PermissionDenied)
                }
                _ => Ok(()),
            }
        }

        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::writable_file("challenge")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    #[async_trait]
    impl Handler for RecordingHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                return Ok(Entry::dir(""));
            }
            match p.first() {
                Some("inbox") => Ok(Entry::writable_file("inbox")),
                Some("readme") => Ok(Entry::file("readme")),
                Some("run") => Ok(Entry::executable_file("run")),
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }
        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            match p.first() {
                Some("inbox") => Ok(self.writes.lock().last().cloned().unwrap_or_default()),
                Some("readme") => Ok(b"static read-only body\n".to_vec()),
                Some("run") => Ok(b"#!/bin/sh\n".to_vec()),
                _ => Err(HandlerError::NotAFile(p.to_string_path())),
            }
        }
        async fn write(&self, p: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
            match p.first() {
                Some("inbox" | "mainnet") => {
                    self.writes.lock().push(data.to_vec());
                    Ok(())
                }
                _ => Err(HandlerError::PermissionDenied),
            }
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![
                    Entry::writable_file("inbox"),
                    Entry::file("readme"),
                    Entry::executable_file("run"),
                ])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    fn fake_ctx() -> RequestContext {
        // RequestContext is constructed by the embednfs server in real
        // use; for adapter unit tests we only ever read it via
        // `_ctx`-prefixed args, so an anonymous one is fine.
        RequestContext::anonymous()
    }

    #[tokio::test]
    async fn root_lookup_returns_directory() {
        let vfs = Vfs::builder()
            .mount("echo", Arc::new(StaticHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let attrs = fs.getattr(&ctx, &BloomHandle::Root).await.unwrap();
        assert_eq!(attrs.object_type, ObjectType::Directory);
    }

    #[tokio::test]
    async fn mount_write_rejects_signer_consuming_paths() {
        let fs = BloomFs::new(Vfs::builder().build());
        let ctx = fake_ctx();
        let handle = BloomHandle::Path {
            entry: Entry::file("order.json"),
            path: VfsPath::parse("/hyperliquid/mainnet/exchange/minnow/order.json").unwrap(),
        };

        let err = fs
            .write(
                &ctx,
                &handle,
                0,
                Bytes::from_static(b"{}"),
                WriteStability::FileSync,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::PermissionDenied));
    }

    #[tokio::test]
    async fn write_open_stages_challenge_and_denies_before_write() {
        let handler = ChallengeStagingHandler::new();
        let vfs = Vfs::builder().mount("stage", handler.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "stage").await.unwrap();
        let challenge = fs.lookup(&ctx, &dir, "challenge").await.unwrap();

        let opener = fs.open_support().expect("open support enabled");
        let err = opener
            .open(
                &ctx,
                &challenge,
                OpenRequest {
                    read: false,
                    write: true,
                },
            )
            .await
            .unwrap_err();

        assert_eq!(err, FsError::AccessDenied);
        assert_eq!(
            handler.staged_count(),
            1,
            "open should stage the approval challenge exactly once"
        );
    }

    #[tokio::test]
    async fn mount_create_rejects_signer_consuming_paths() {
        let fs = BloomFs::new(Vfs::builder().build());
        let ctx = fake_ctx();
        let parent = BloomHandle::Path {
            entry: Entry::dir("minnow"),
            path: VfsPath::parse("/hyperliquid/mainnet/exchange/minnow").unwrap(),
        };

        let err = fs
            .create(
                &ctx,
                &parent,
                "order.json",
                CreateRequest {
                    kind: CreateKind::File,
                    attrs: SetAttrs::default(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::PermissionDenied));
    }

    #[test]
    fn mount_classifier_forwards_handler_owned_sealed_approval_writes() {
        // Handler-owned Sealed Approval actions must reach the VFS handler, not
        // be denied at the mount signer lane. policy-session/new now behaves
        // like policy.toml: the wallets handler enforces Sealed Approval.
        for path in [
            "/wallets/minnow/policy.toml",
            "/wallets/minnow/policy-session/new",
            "/requests/pending/req_1/confirm",
            "/polymarket/onboard/test-wallet/begin",
            "/hyperliquid/mainnet/agent_sessions/minnow/new.json",
        ] {
            let p = VfsPath::parse(path).unwrap();
            assert!(!mount_write_path_uses_wallet_signer(&p), "{path}");
        }
        // Truly raw signer lanes remain denied at the mount lane.
        for path in [
            "/wallets/minnow/sign/message",
            "/wallets/minnow/sign/hash",
            "/wallets/minnow/sign/typed_data",
            "/wallets/minnow/chains/polygon/outbox/pending/0001/cancel",
            "/wallets/minnow/chains/polygon/outbox/pending/0001/replace",
            "/hyperliquid/mainnet/exchange/minnow/order.json",
        ] {
            let p = VfsPath::parse(path).unwrap();
            assert!(mount_write_path_uses_wallet_signer(&p), "{path}");
        }
    }

    #[test]
    fn mount_classifier_flushes_hyperliquid_session_commands_inline() {
        for path in [
            "/hyperliquid/mainnet/agent_sessions/minnow/new.json",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/order.json",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/cancel.json",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/schedule_cancel.json",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/stop",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/cancel_all",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/close_all",
        ] {
            let p = VfsPath::parse(path).unwrap();
            assert!(mount_write_path_is_atomic_command(&p), "{path}");
        }

        for path in [
            "/hyperliquid/mainnet/mids.json",
            "/hyperliquid/mainnet/exchange/minnow/order.json",
            "/hyperliquid/mainnet/agent_sessions/minnow/session-1/status.json",
            "/wallets/minnow/policy.toml",
        ] {
            let p = VfsPath::parse(path).unwrap();
            assert!(!mount_write_path_is_atomic_command(&p), "{path}");
        }
    }

    #[tokio::test]
    async fn unstable_hyperliquid_session_command_flushes_inline() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder()
            .mount("hyperliquid", recorder.clone())
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let handle = BloomHandle::Path {
            entry: Entry::file("order.json"),
            path: VfsPath::parse("/hyperliquid/mainnet/agent_sessions/minnow/session-1/order.json")
                .unwrap(),
        };
        let body = Bytes::from_static(br#"{"action":{"type":"order"}}"#);

        let result = fs
            .write(&ctx, &handle, 0, body.clone(), WriteStability::Unstable)
            .await
            .unwrap();

        assert_eq!(result.written, body.len() as u32);
        assert_eq!(recorder.write_count(), 1);
        assert_eq!(recorder.last_write(), Some(body.to_vec()));
    }

    #[tokio::test]
    async fn unstable_hyperliquid_command_defers_handler_error_to_status_files() {
        let handler = Arc::new(AtomicDenyHandler::default());
        let vfs = Vfs::builder().mount("hyperliquid", handler.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let handle = BloomHandle::Path {
            entry: Entry::file("new.json"),
            path: VfsPath::parse("/hyperliquid/mainnet/agent_sessions/minnow/new.json").unwrap(),
        };
        let body = Bytes::from_static(br#"{"id":"session-1"}"#);

        let result = fs
            .write(&ctx, &handle, 0, body.clone(), WriteStability::Unstable)
            .await
            .expect("atomic command transport acknowledges deferred handler outcome");

        assert_eq!(result.written, body.len() as u32);
        assert_eq!(*handler.writes.lock(), vec![body.to_vec()]);
    }

    #[tokio::test]
    async fn lookup_then_read_yields_file_contents() {
        let vfs = Vfs::builder()
            .mount("echo", Arc::new(StaticHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let echo = fs.lookup(&ctx, &BloomHandle::Root, "echo").await.unwrap();
        let hello = fs.lookup(&ctx, &echo, "hello").await.unwrap();
        let r = fs.read(&ctx, &hello, 0, 1024).await.unwrap();
        assert_eq!(&r.data[..], b"world\n");
        assert!(r.eof);
    }

    #[tokio::test]
    async fn readlink_returns_vfs_symlink_target() {
        let vfs = Vfs::builder()
            .mount("echo", Arc::new(StaticHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let echo = fs.lookup(&ctx, &BloomHandle::Root, "echo").await.unwrap();
        let latest = fs.lookup(&ctx, &echo, "latest").await.unwrap();
        let attrs = fs.getattr(&ctx, &latest).await.unwrap();
        assert_eq!(attrs.object_type, ObjectType::Symlink);
        assert_eq!(attrs.size, "pending/req-1".len() as u64);

        let symlinks = fs.symlinks().expect("BloomFs must advertise READLINK");
        let target = symlinks.readlink(&ctx, &latest).await.unwrap();
        assert_eq!(target, "pending/req-1");
    }

    #[tokio::test]
    async fn readdir_root_lists_handlers() {
        let vfs = Vfs::builder()
            .mount("echo", Arc::new(StaticHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let page = fs
            .readdir(&ctx, &BloomHandle::Root, 0, 100, true)
            .await
            .unwrap();
        let names: Vec<&str> = page.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["AGENTS.md", "CLAUDE.md", "echo"]);
        assert!(page.eof);
    }

    #[tokio::test]
    async fn file_sync_write_surfaces_permission_denied_immediately() {
        let handler = ChallengeStagingHandler::new();
        let vfs = Vfs::builder().mount("stage", handler.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "stage").await.unwrap();
        let challenge = fs.lookup(&ctx, &dir, "challenge").await.unwrap();

        let err = fs
            .write(
                &ctx,
                &challenge,
                0,
                Bytes::from_static(b"{\"action\":\"usdSend\"}"),
                WriteStability::FileSync,
            )
            .await
            .unwrap_err();

        assert_eq!(err, FsError::AccessDenied);
        assert_eq!(
            handler.staged_count(),
            1,
            "challenge staging side effect should still happen exactly once"
        );
    }

    #[tokio::test]
    async fn multi_chunk_unstable_write_denies_on_commit() {
        let handler = ChallengeStagingHandler::new();
        let vfs = Vfs::builder().mount("stage", handler.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "stage").await.unwrap();
        let challenge = fs.lookup(&ctx, &dir, "challenge").await.unwrap();

        let result = fs
            .write(
                &ctx,
                &challenge,
                5,
                Bytes::from_static(b"1}"),
                WriteStability::Unstable,
            )
            .await
            .unwrap();
        assert_eq!(result.stability, WriteStability::Unstable);
        assert_eq!(handler.staged_count(), 0);

        let result = fs
            .write(
                &ctx,
                &challenge,
                0,
                Bytes::from_static(b"{\"a\":"),
                WriteStability::Unstable,
            )
            .await
            .unwrap();
        assert_eq!(result.stability, WriteStability::Unstable);
        assert_eq!(handler.staged_count(), 0);

        let cs = fs.commit_support().expect("commit support enabled");
        let err = cs.commit(&ctx, &challenge, 0, 7).await.unwrap_err();
        assert_eq!(err, FsError::AccessDenied);
        assert_eq!(handler.staged_count(), 1);
    }

    /// Bug #4 acceptance: a 16 KiB write delivered as four 4 KiB
    /// chunks at offsets 0/4096/8192/12288 followed by a COMMIT must
    /// land as a single `vfs.write` carrying the joined payload.
    #[tokio::test]
    async fn buffered_chunks_flush_on_commit() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();

        // Build a deterministic 16 KiB payload (each block tagged with
        // its offset so we can detect mis-ordering on flush).
        let mut payload = Vec::with_capacity(16 * 1024);
        for off in [0u32, 4096, 8192, 12288] {
            for b in 0..4096 {
                payload.push(((off / 4096) as u8).wrapping_add((b & 0xff) as u8));
            }
        }
        let chunks: Vec<&[u8]> = payload.chunks(4096).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let off = (i as u64) * 4096;
            let result = fs
                .write(
                    &ctx,
                    &inbox,
                    off,
                    Bytes::copy_from_slice(chunk),
                    WriteStability::Unstable,
                )
                .await
                .unwrap();
            assert_eq!(result.written, 4096);
            assert_eq!(result.stability, WriteStability::Unstable);
        }
        // No flush yet: without an EOF marker, each sequential complete
        // prefix could still be the first part of a larger file.
        assert_eq!(recorder.write_count(), 0);

        // COMMIT: the kernel issues this on close/fsync and it must
        // collapse the four chunks into exactly one VFS write.
        let cs = fs.commit_support().expect("commit support enabled");
        cs.commit(&ctx, &inbox, 0, payload.len() as u32)
            .await
            .unwrap();
        assert_eq!(recorder.write_count(), 1);
        assert_eq!(recorder.last_write().unwrap(), payload);
    }

    /// Regression: a complete offset-zero prefix is not necessarily a
    /// complete file. Sequential clients can split at sizes other than
    /// 4 KiB, so the adapter must not eagerly flush the first 8 KiB
    /// prefix and lose the tail.
    #[tokio::test]
    async fn sequential_non_4k_chunks_wait_for_commit() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();

        let payload = vec![7u8; 16 * 1024];
        let chunks: Vec<&[u8]> = payload.chunks(8192).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            fs.write(
                &ctx,
                &inbox,
                (i as u64) * 8192,
                Bytes::copy_from_slice(chunk),
                WriteStability::Unstable,
            )
            .await
            .unwrap();
        }
        assert_eq!(recorder.write_count(), 0);

        let cs = fs.commit_support().expect("commit support enabled");
        cs.commit(&ctx, &inbox, 0, payload.len() as u32)
            .await
            .unwrap();
        assert_eq!(recorder.write_count(), 1);
        assert_eq!(recorder.last_write().unwrap(), payload);
    }

    /// Bug #4 acceptance: out-of-order chunks plus a final prefix
    /// chunk still produce a single coalesced write on COMMIT.
    #[tokio::test]
    async fn buffered_chunks_tolerate_out_of_order() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();

        let mut payload = vec![0u8; 12288];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }
        // Send middle, then tail, then head — common pattern for
        // multi-threaded or io_uring clients.
        let send = |off: u64, lo: usize, hi: usize| {
            let bytes = Bytes::copy_from_slice(&payload[lo..hi]);
            (off, bytes)
        };
        let middle = send(4096, 4096, 8192);
        let tail = send(8192, 8192, 12288);
        let head = send(0, 0, 4096);
        for (off, bytes) in [middle, tail, head] {
            fs.write(&ctx, &inbox, off, bytes, WriteStability::Unstable)
                .await
                .unwrap();
        }
        assert_eq!(recorder.write_count(), 0);

        let cs = fs.commit_support().unwrap();
        cs.commit(&ctx, &inbox, 0, payload.len() as u32)
            .await
            .unwrap();
        assert_eq!(recorder.write_count(), 1);
        assert_eq!(recorder.last_write().unwrap(), payload);
    }

    /// Regression: out-of-order chunks can become temporarily contiguous
    /// before the tail arrives. That prefix is not a final-file signal,
    /// so UNSTABLE writes must still wait for COMMIT.
    #[tokio::test]
    async fn out_of_order_prefix_completion_waits_for_commit_until_tail_arrives() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();

        let mut payload = vec![0u8; 12288];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i & 0xff) as u8;
        }

        fs.write(
            &ctx,
            &inbox,
            4096,
            Bytes::copy_from_slice(&payload[4096..8192]),
            WriteStability::Unstable,
        )
        .await
        .unwrap();
        fs.write(
            &ctx,
            &inbox,
            0,
            Bytes::copy_from_slice(&payload[0..4096]),
            WriteStability::Unstable,
        )
        .await
        .unwrap();
        assert_eq!(
            recorder.write_count(),
            0,
            "contiguous prefix must not flush before the tail arrives"
        );

        fs.write(
            &ctx,
            &inbox,
            8192,
            Bytes::copy_from_slice(&payload[8192..12288]),
            WriteStability::Unstable,
        )
        .await
        .unwrap();
        assert_eq!(recorder.write_count(), 0);

        let cs = fs.commit_support().unwrap();
        cs.commit(&ctx, &inbox, 0, payload.len() as u32)
            .await
            .unwrap();
        assert_eq!(recorder.write_count(), 1);
        assert_eq!(recorder.last_write().unwrap(), payload);
    }

    /// Bug #4 acceptance: a single write tagged FILE_SYNC (no
    /// follow-up COMMIT) flushes immediately on the eager path.
    ///
    /// Regression: the embednfs server enforces
    /// `actual_stability >= requested_stability` and returns
    /// SERVERFAULT (kernel surface: EREMOTEIO) on mismatch. The
    /// adapter used to advertise UNSTABLE for every reply, so a
    /// kernel-issued FILE_SYNC write through the mount silently
    /// flushed the body but failed userspace `write(2)` with EIO.
    #[tokio::test]
    async fn file_sync_write_flushes_eagerly() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();
        let body = b"hello bloom\n";
        let result = fs
            .write(
                &ctx,
                &inbox,
                0,
                Bytes::copy_from_slice(body),
                WriteStability::FileSync,
            )
            .await
            .unwrap();
        assert_eq!(recorder.write_count(), 1);
        assert_eq!(recorder.last_write().unwrap(), body);
        assert_eq!(
            result.stability,
            WriteStability::FileSync,
            "must echo the requested sync level back so embednfs accepts the WRITE"
        );
    }

    /// DATA_SYNC mirrors FILE_SYNC: kernel asks the server to
    /// persist data before replying. We flush eagerly and report
    /// DATA_SYNC back so the embednfs stability check passes.
    #[tokio::test]
    async fn data_sync_write_flushes_eagerly() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();
        let body = b"datasync body\n";
        let result = fs
            .write(
                &ctx,
                &inbox,
                0,
                Bytes::copy_from_slice(body),
                WriteStability::DataSync,
            )
            .await
            .unwrap();
        assert_eq!(recorder.write_count(), 1);
        assert_eq!(recorder.last_write().unwrap(), body);
        assert_eq!(result.stability, WriteStability::DataSync);
    }

    #[tokio::test]
    async fn incomplete_sync_write_is_rejected_instead_of_downgraded() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();

        let err = fs
            .write(
                &ctx,
                &inbox,
                8,
                Bytes::copy_from_slice(b"tail"),
                WriteStability::FileSync,
            )
            .await
            .unwrap_err();

        assert_eq!(err, FsError::Unsupported);
        assert_eq!(recorder.write_count(), 0);
    }

    /// Bug #4 acceptance: a write that would push the per-handle
    /// buffer past `MAX_WRITE_BUFFER_BYTES` must be rejected with
    /// `FileTooLarge` (NFS4ERR_FBIG) before any state mutation.
    #[tokio::test]
    async fn oversize_write_rejects_fbig() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();
        // One byte past the cap — even at offset 0 this should fail
        // because the buffer would have to grow to MAX+1.
        let oversized = Bytes::from(vec![0u8; MAX_WRITE_BUFFER_BYTES + 1]);
        let err = fs
            .write(&ctx, &inbox, 0, oversized, WriteStability::Unstable)
            .await
            .unwrap_err();
        assert_eq!(err, FsError::FileTooLarge);
        // No partial state should have leaked through.
        assert_eq!(recorder.write_count(), 0);
    }

    /// Bug #5 acceptance: a read-only file reports mode 0444 in
    /// GETATTR. `Entry::file` is the read-only-by-default constructor
    /// in the VFS, and the adapter must propagate the mode bits so
    /// clients see "r--r--r--" in `stat(2)`.
    #[tokio::test]
    async fn getattr_read_only_file_is_0444() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let readme = fs.lookup(&ctx, &dir, "readme").await.unwrap();
        let attrs = fs.getattr(&ctx, &readme).await.unwrap();
        assert_eq!(
            attrs.mode & 0o777,
            0o444,
            "expected 0o444 mode bits, got 0o{:o}",
            attrs.mode
        );
    }

    /// Bug #5: writable files keep their 0644 mode through GETATTR so
    /// clients still see them as writable.
    #[tokio::test]
    async fn getattr_writable_file_is_0644() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();
        let attrs = fs.getattr(&ctx, &inbox).await.unwrap();
        assert_eq!(attrs.mode & 0o777, 0o644);
    }

    #[tokio::test]
    async fn getattr_executable_file_is_0555() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let run = fs.lookup(&ctx, &dir, "run").await.unwrap();
        let attrs = fs.getattr(&ctx, &run).await.unwrap();
        assert_eq!(attrs.mode & 0o777, 0o555);
    }

    /// Bug #5: ACCESS strips MODIFY/EXTEND/DELETE for a read-only path
    /// so the kernel doesn't cache a false-positive write capability.
    #[tokio::test]
    async fn access_strips_write_bits_on_read_only() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let readme = fs.lookup(&ctx, &dir, "readme").await.unwrap();
        let requested =
            AccessMask::READ | AccessMask::MODIFY | AccessMask::EXTEND | AccessMask::DELETE;
        let granted = fs.access(&ctx, &readme, requested).await.unwrap();
        assert!(granted.contains(AccessMask::READ));
        assert!(!granted.intersects(AccessMask::MODIFY | AccessMask::EXTEND | AccessMask::DELETE));
    }

    /// Bug #5: ACCESS preserves the write bits on a writable path so
    /// `echo foo > inbox` doesn't trip an EACCES preflight.
    #[tokio::test]
    async fn access_keeps_write_bits_on_writable() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();
        let requested = AccessMask::READ | AccessMask::MODIFY | AccessMask::EXTEND;
        let granted = fs.access(&ctx, &inbox, requested).await.unwrap();
        assert!(granted.contains(AccessMask::MODIFY));
        assert!(granted.contains(AccessMask::EXTEND));
    }

    /// Handler whose `pending/` subdirectory has a mutable listing,
    /// driven by the `entries` mutex. Mirrors how the real wallets
    /// outbox works: the daemon writes new pending tx ids into a
    /// directory out-of-band, and listings via the mount must reflect
    /// those additions.
    #[derive(Default)]
    struct MutableDirHandler {
        entries: parking_lot::Mutex<Vec<String>>,
    }
    impl MutableDirHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn push(&self, name: &str) {
            self.entries.lock().push(name.into());
        }
    }
    #[async_trait]
    impl Handler for MutableDirHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments() {
                [] => Ok(Entry::dir("")),
                [s] if s == "pending" => Ok(Entry::dir("pending")),
                [s, name] if s == "pending" => {
                    if self.entries.lock().iter().any(|e| e == name) {
                        Ok(Entry::dir(name))
                    } else {
                        Err(HandlerError::NotFound(p.to_string_path()))
                    }
                }
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }
        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Err(HandlerError::NotAFile(p.to_string_path()))
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            match p.segments() {
                [] => Ok(vec![Entry::dir("pending")]),
                [s] if s == "pending" => {
                    Ok(self.entries.lock().iter().map(|n| Entry::dir(n)).collect())
                }
                _ => Err(HandlerError::NotADir(p.to_string_path())),
            }
        }
    }

    struct CountingDirectoryHandler {
        root_lists: parking_lot::Mutex<u32>,
        child_lists: parking_lot::Mutex<u32>,
        child_lookups: parking_lot::Mutex<u32>,
        child_directories: bool,
    }

    impl CountingDirectoryHandler {
        fn new(child_directories: bool) -> Arc<Self> {
            Arc::new(Self {
                root_lists: parking_lot::Mutex::new(0),
                child_lists: parking_lot::Mutex::new(0),
                child_lookups: parking_lot::Mutex::new(0),
                child_directories,
            })
        }

        fn root_list_count(&self) -> u32 {
            *self.root_lists.lock()
        }

        fn child_list_count(&self) -> u32 {
            *self.child_lists.lock()
        }

        fn child_lookup_count(&self) -> u32 {
            *self.child_lookups.lock()
        }

        fn entries(&self) -> Vec<Entry> {
            (0..7)
                .map(|index| {
                    let name = format!("entry-{index}");
                    if self.child_directories {
                        Entry::dir(&name)
                    } else {
                        Entry::file(&name)
                    }
                })
                .collect()
        }
    }

    #[derive(Default)]
    struct BlockingRevalidationHandler {
        lists: std::sync::atomic::AtomicU32,
        revalidation_started: tokio::sync::Notify,
        release_revalidation: tokio::sync::Notify,
    }

    impl BlockingRevalidationHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn list_count(&self) -> u32 {
            self.lists.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Handler for BlockingRevalidationHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                Ok(Entry::dir(""))
            } else {
                Err(HandlerError::NotFound(p.to_string_path()))
            }
        }

        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if !p.is_root() {
                return Err(HandlerError::NotADir(p.to_string_path()));
            }
            let prior = self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if prior > 0 {
                self.revalidation_started.notify_one();
                self.release_revalidation.notified().await;
            }
            Ok(vec![Entry::file("entry")])
        }
    }

    #[async_trait]
    impl Handler for CountingDirectoryHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments() {
                [] => Ok(Entry::dir("")),
                [name] if name.starts_with("entry-") => {
                    *self.child_lookups.lock() += 1;
                    if self.child_directories {
                        Ok(Entry::dir(name))
                    } else {
                        Ok(Entry::file(name))
                    }
                }
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }

        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Ok(Vec::new())
        }

        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                *self.root_lists.lock() += 1;
                Ok(self.entries())
            } else if self.child_directories {
                *self.child_lists.lock() += 1;
                Ok(Vec::new())
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    #[tokio::test]
    async fn paginated_readdir_reuses_getattr_directory_snapshot() {
        let handler = CountingDirectoryHandler::new(false);
        let vfs = Vfs::builder().mount("box", handler.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let directory = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let expected_change = fs.getattr(&ctx, &directory).await.unwrap().change;

        let mut cookie = 0;
        let mut names = Vec::new();
        loop {
            assert_eq!(
                fs.getattr(&ctx, &directory).await.unwrap().change,
                expected_change
            );
            let page = fs
                .readdir(&ctx, &directory, cookie, 2, false)
                .await
                .unwrap();
            if let Some(last) = page.entries.last() {
                cookie = last.cookie;
            }
            names.extend(page.entries.into_iter().map(|entry| entry.name));
            if page.eof {
                break;
            }
        }

        assert_eq!(
            names,
            (0..7)
                .map(|index| format!("entry-{index}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(handler.root_list_count(), 1);
    }

    #[tokio::test]
    async fn handle_metadata_calls_do_not_repeat_vfs_lookup() {
        let handler = CountingDirectoryHandler::new(true);
        let vfs = Vfs::builder().mount("box", handler.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let directory = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let child = fs.lookup(&ctx, &directory, "entry-0").await.unwrap();

        for _ in 0..4 {
            fs.getattr(&ctx, &child).await.unwrap();
            fs.access(&ctx, &child, AccessMask::READ).await.unwrap();
        }

        assert_eq!(handler.child_lookup_count(), 1);
        assert_eq!(handler.child_list_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_directory_readdirs_coalesce_to_one_list() {
        let handler = CountingDirectoryHandler::new(false);
        let vfs = Vfs::builder().mount("box", handler.clone()).build();
        let fs = Arc::new(BloomFs::new(vfs));
        let directory = fs
            .lookup(&fake_ctx(), &BloomHandle::Root, "box")
            .await
            .unwrap();

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let fs = fs.clone();
            let directory = directory.clone();
            tasks.push(tokio::spawn(async move {
                fs.readdir(&fake_ctx(), &directory, 0, u32::MAX, false)
                    .await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(handler.root_list_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_directory_revalidations_coalesce_to_one_list() {
        let handler = BlockingRevalidationHandler::new();
        let vfs = Vfs::builder().mount("box", handler.clone()).build();
        let fs = Arc::new(BloomFs::new(vfs));
        let directory = fs
            .lookup(&fake_ctx(), &BloomHandle::Root, "box")
            .await
            .unwrap();
        fs.readdir(&fake_ctx(), &directory, 0, u32::MAX, false)
            .await
            .unwrap();
        assert_eq!(handler.list_count(), 1);

        tokio::time::advance(DIRECTORY_CACHE_REVALIDATE_INTERVAL + Duration::from_millis(1)).await;
        let revalidation_started = handler.revalidation_started.notified();
        let tasks = (0..16)
            .map(|_| {
                let fs = fs.clone();
                let directory = directory.clone();
                tokio::spawn(async move { fs.getattr(&fake_ctx(), &directory).await })
            })
            .collect::<Vec<_>>();

        revalidation_started.await;
        tokio::task::yield_now().await;
        handler.release_revalidation.notify_one();
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(handler.list_count(), 2);
    }

    #[tokio::test]
    async fn readdirplus_does_not_list_child_directories() {
        let handler = CountingDirectoryHandler::new(true);
        let vfs = Vfs::builder().mount("box", handler.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let directory = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();

        fs.getattr(&ctx, &directory).await.unwrap();
        let page = fs
            .readdir(&ctx, &directory, 0, u32::MAX, true)
            .await
            .unwrap();

        // Model macOS issuing an explicit GETATTR for every returned child.
        for entry in &page.entries {
            fs.getattr(&ctx, &entry.handle).await.unwrap();
            fs.access(&ctx, &entry.handle, AccessMask::READ)
                .await
                .unwrap();
        }

        assert_eq!(page.entries.len(), 7);
        assert_eq!(handler.root_list_count(), 1);
        assert_eq!(handler.child_list_count(), 0);
        assert_eq!(handler.child_lookup_count(), 0);
    }

    struct FailingDirectoryHandler;

    #[async_trait]
    impl Handler for FailingDirectoryHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                Ok(Entry::dir(""))
            } else {
                Err(HandlerError::NotFound(p.to_string_path()))
            }
        }

        async fn list(&self, _p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            Err(HandlerError::Backend("directory backend offline".into()))
        }
    }

    #[tokio::test]
    async fn directory_readdir_propagates_list_error_instead_of_returning_empty() {
        let vfs = Vfs::builder()
            .mount("box", Arc::new(FailingDirectoryHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let directory = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        // Metadata is cheap and does not evaluate the directory. The actual
        // enumeration is the operation which must surface the backend error.
        fs.getattr(&ctx, &directory).await.unwrap();
        let error = fs
            .readdir(&ctx, &directory, 0, u32::MAX, false)
            .await
            .unwrap_err();
        assert_eq!(error, FsError::Io);
    }

    #[derive(Default)]
    struct ListingWriteHandler {
        entries: parking_lot::Mutex<Vec<String>>,
        lists: parking_lot::Mutex<u32>,
    }

    impl ListingWriteHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn list_count(&self) -> u32 {
            *self.lists.lock()
        }
    }

    #[async_trait]
    impl Handler for ListingWriteHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments() {
                [] => Ok(Entry::dir("")),
                [name] if name == "add" => Ok(Entry::writable_file("add")),
                [name] if self.entries.lock().iter().any(|entry| entry == name) => {
                    Ok(Entry::file(name))
                }
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }

        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            if matches!(p.segments(), [name] if name == "add") {
                Ok(Vec::new())
            } else {
                Ok(b"created\n".to_vec())
            }
        }

        async fn write(&self, p: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
            if !matches!(p.segments(), [name] if name == "add") {
                return Err(HandlerError::PermissionDenied);
            }
            let name = std::str::from_utf8(data)
                .map_err(|error| HandlerError::Invalid(error.to_string()))?
                .trim()
                .to_string();
            self.entries.lock().push(name);
            Ok(())
        }

        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if !p.is_root() {
                return Err(HandlerError::NotADir(p.to_string_path()));
            }
            *self.lists.lock() += 1;
            let mut entries = vec![Entry::writable_file("add")];
            entries.extend(self.entries.lock().iter().map(|name| Entry::file(name)));
            Ok(entries)
        }
    }

    #[tokio::test]
    async fn successful_write_invalidates_parent_directory_snapshot() {
        let handler = ListingWriteHandler::new();
        let vfs = Vfs::builder().mount("box", handler.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let directory = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let add = fs.lookup(&ctx, &directory, "add").await.unwrap();

        let before = fs
            .readdir(&ctx, &directory, 0, u32::MAX, false)
            .await
            .unwrap();
        assert_eq!(handler.list_count(), 1);
        assert_eq!(before.entries.len(), 1);

        fs.write(
            &ctx,
            &add,
            0,
            Bytes::from_static(b"created"),
            WriteStability::FileSync,
        )
        .await
        .unwrap();

        let after = fs
            .readdir(&ctx, &directory, 0, u32::MAX, false)
            .await
            .unwrap();
        assert_eq!(handler.list_count(), 2);
        assert!(after.entries.iter().any(|entry| entry.name == "created"));
    }

    /// Regression for the Enso/Aave integration test bug: when the
    /// daemon writes a new pending stage out-of-band (i.e. not via the
    /// NFS write path), `getattr` on the parent directory must report a
    /// different `change` so the kernel's NFS dir cache invalidates and
    /// the next READDIR sees the new entry. Before this fix `change`
    /// was a function of fileid (path), so it never moved and clients
    /// who saw the directory empty kept seeing it empty forever.
    #[tokio::test(start_paused = true)]
    async fn dir_change_moves_when_listing_grows() {
        let h = MutableDirHandler::new();
        let vfs = Vfs::builder().mount("box", h.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let box_dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let pending = fs.lookup(&ctx, &box_dir, "pending").await.unwrap();
        fs.readdir(&ctx, &pending, 0, u32::MAX, false)
            .await
            .unwrap();
        let before = fs.getattr(&ctx, &pending).await.unwrap().change;
        h.push("0001-21699");
        // Stay well inside the idle/max-age window: metadata revalidation,
        // rather than cache expiry, must discover the out-of-band mutation.
        tokio::time::advance(DIRECTORY_CACHE_REVALIDATE_INTERVAL + Duration::from_millis(1)).await;
        let after = fs.getattr(&ctx, &pending).await.unwrap().change;
        assert_ne!(
            before, after,
            "directory change must move after a new entry is added; \
             otherwise the kernel will keep serving the cached empty listing"
        );
    }

    /// Two empty directories at different paths must not share a
    /// `change` value. Otherwise an empty-listing cache for one
    /// directory would falsely validate against another's attribute.
    #[tokio::test]
    async fn dir_change_distinguishes_empty_directories() {
        let h = MutableDirHandler::new();
        let vfs = Vfs::builder().mount("box", h.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let root = fs.getattr(&ctx, &BloomHandle::Root).await.unwrap().change;
        let box_dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let pending = fs.lookup(&ctx, &box_dir, "pending").await.unwrap();
        let pending_change = fs.getattr(&ctx, &pending).await.unwrap().change;
        assert_ne!(root, pending_change);
    }

    /// File `change` must move between calls so the kernel's NFS
    /// page cache invalidates whenever the daemon recomputes content
    /// (balance.raw, gas/suggest, head). Before this fix `change` was
    /// fileid-derived and stable, so a polling loop reading the same
    /// path saw the first cached value forever even with `noac`.
    #[tokio::test]
    async fn file_change_moves_between_calls() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let readme = fs.lookup(&ctx, &dir, "readme").await.unwrap();
        let a = fs.getattr(&ctx, &readme).await.unwrap().change;
        let b = fs.getattr(&ctx, &readme).await.unwrap().change;
        assert_ne!(
            a, b,
            "file change must move between calls so NFS clients re-read on every access; got {a} == {b}"
        );
    }

    /// `change` must be stable across calls when the listing hasn't
    /// changed — otherwise multi-page READDIR (cookieverf check)
    /// returns NFS4ERR_NOT_SAME mid-walk.
    #[tokio::test]
    async fn dir_change_stable_when_listing_unchanged() {
        let h = MutableDirHandler::new();
        h.push("0001-21699");
        let vfs = Vfs::builder().mount("box", h.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let box_dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let pending = fs.lookup(&ctx, &box_dir, "pending").await.unwrap();
        let a = fs.getattr(&ctx, &pending).await.unwrap().change;
        let b = fs.getattr(&ctx, &pending).await.unwrap().change;
        assert_eq!(a, b);
    }

    /// Bug #1 acceptance: a read-only, non-side-effecting file reports
    /// the *real* size (not 0, not the 8 MiB sentinel) at GETATTR. The
    /// adapter must render the body so `stat` shows what `cat` will see.
    #[tokio::test]
    async fn getattr_renders_pure_read_only_file_returns_real_size() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let readme = fs.lookup(&ctx, &dir, "readme").await.unwrap();
        let attrs = fs.getattr(&ctx, &readme).await.unwrap();
        // RecordingHandler returns "static read-only body\n" (22 bytes).
        assert_eq!(
            attrs.size,
            b"static read-only body\n".len() as u64,
            "expected real rendered size; got {}",
            attrs.size
        );
        assert_eq!(attrs.size, attrs.space_used);
    }

    /// Bug #1 acceptance: a writable file (mode 0o644) whose `read`
    /// returns content — addressbook aliases, `policy.toml`, etc — is
    /// rendered at GETATTR so `cat` sees a non-zero size. The old
    /// "skip if writable" gate broke these read-write files; the only
    /// real reason to skip is `is_read_side_effecting`, not the mode
    /// bit. RecordingHandler's `inbox` returns whatever was last
    /// written, so this test verifies the rendered bytes are visible.
    #[tokio::test]
    async fn getattr_renders_writable_readable_file() {
        let recorder = RecordingHandler::new();
        recorder.writes.lock().push(b"hello\n".to_vec());
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();
        let attrs = fs.getattr(&ctx, &inbox).await.unwrap();
        assert_eq!(attrs.size, b"hello\n".len() as u64);
        assert_eq!(attrs.mode & 0o777, 0o644);
    }

    /// Regression: a write through the mount must invalidate the render cache,
    /// so a follow-up GETATTR/READ reflects the new bytes instead of the
    /// pre-write render still cached within `RENDER_CACHE_TTL`.
    #[tokio::test]
    async fn write_invalidates_render_cache() {
        let recorder = RecordingHandler::new();
        recorder.writes.lock().push(b"hello\n".to_vec());
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let inbox = fs.lookup(&ctx, &dir, "inbox").await.unwrap();

        // Populate the render cache: GETATTR renders + caches "hello\n".
        assert_eq!(
            fs.getattr(&ctx, &inbox).await.unwrap().size,
            b"hello\n".len() as u64
        );

        // Overwrite through the mount (complete FILE_SYNC write flushes to VFS).
        let new = b"GOODBYE WORLD\n";
        fs.write(
            &ctx,
            &inbox,
            0,
            Bytes::copy_from_slice(new),
            WriteStability::FileSync,
        )
        .await
        .unwrap();

        // Pre-fix these would still see the cached "hello\n".
        assert_eq!(
            fs.getattr(&ctx, &inbox).await.unwrap().size,
            new.len() as u64,
            "GETATTR served a stale cached size after write"
        );
        assert_eq!(
            &fs.read(&ctx, &inbox, 0, 4096).await.unwrap().data[..],
            new,
            "READ served stale cached bytes after write"
        );
    }

    #[derive(Clone, Copy)]
    enum TestReadResult {
        Backend,
        NotFound,
        Empty,
    }

    struct ClassifiedReadHandler {
        result: TestReadResult,
        reads: parking_lot::Mutex<u32>,
    }

    impl ClassifiedReadHandler {
        fn new(result: TestReadResult) -> Arc<Self> {
            Arc::new(Self {
                result,
                reads: parking_lot::Mutex::new(0),
            })
        }

        fn read_count(&self) -> u32 {
            *self.reads.lock()
        }
    }

    #[async_trait]
    impl Handler for ClassifiedReadHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments() {
                [] => Ok(Entry::dir("")),
                [name] if name == "value" => Ok(Entry::file("value")),
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }

        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            *self.reads.lock() += 1;
            match self.result {
                TestReadResult::Backend => Err(HandlerError::Backend("offline".into())),
                TestReadResult::NotFound => Err(HandlerError::NotFound("missing".into())),
                TestReadResult::Empty => Ok(Vec::new()),
            }
        }

        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::file("value")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    async fn classified_read_handle(handler: Arc<ClassifiedReadHandler>) -> (BloomFs, BloomHandle) {
        let vfs = Vfs::builder().mount("box", handler).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let value = fs.lookup(&ctx, &dir, "value").await.unwrap();
        (fs, value)
    }

    #[tokio::test]
    async fn getattr_backend_render_error_returns_io_without_followup_read() {
        let handler = ClassifiedReadHandler::new(TestReadResult::Backend);
        let (fs, value) = classified_read_handle(handler.clone()).await;
        let error = fs.getattr(&fake_ctx(), &value).await.unwrap_err();
        assert_eq!(error, FsError::Io);
        assert_eq!(handler.read_count(), 1);
    }

    #[tokio::test]
    async fn getattr_not_found_render_error_preserves_not_found() {
        let handler = ClassifiedReadHandler::new(TestReadResult::NotFound);
        let (fs, value) = classified_read_handle(handler.clone()).await;
        let error = fs.getattr(&fake_ctx(), &value).await.unwrap_err();
        assert_eq!(error, FsError::NotFound);
        assert_eq!(handler.read_count(), 1);
    }

    #[tokio::test]
    async fn getattr_successful_empty_render_is_a_real_empty_file() {
        let handler = ClassifiedReadHandler::new(TestReadResult::Empty);
        let (fs, value) = classified_read_handle(handler.clone()).await;
        let attrs = fs.getattr(&fake_ctx(), &value).await.unwrap();
        assert_eq!(attrs.size, 0);
        assert_eq!(handler.read_count(), 1);
    }

    /// Handler exposing a writable file whose `read` errors out — the
    /// "write-only sink" pattern (outbox controls, watch/new). GETATTR
    /// must succeed with `size = 0`, *not* surface the read error.
    #[derive(Default)]
    struct WriteOnlySinkHandler;
    #[async_trait]
    impl Handler for WriteOnlySinkHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments() {
                [] => Ok(Entry::dir("")),
                [s] if s == "confirm" => Ok(Entry::writable_file("confirm")),
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }
        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Err(HandlerError::NotAFile(p.to_string_path()))
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::writable_file("confirm")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    /// Bug #1 follow-up: a writable file whose backend rejects reads
    /// must not fail GETATTR — falls through with `size = 0`.
    #[tokio::test]
    async fn getattr_handles_write_only_sink_without_eio() {
        let vfs = Vfs::builder()
            .mount("box", Arc::new(WriteOnlySinkHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let confirm = fs.lookup(&ctx, &dir, "confirm").await.unwrap();
        let attrs = fs.getattr(&ctx, &confirm).await.unwrap();
        assert_eq!(attrs.size, 0);
        assert_eq!(attrs.mode & 0o777, 0o644);
    }

    #[tokio::test]
    async fn write_only_sink_followup_read_preserves_not_a_file_mapping() {
        let vfs = Vfs::builder()
            .mount("box", Arc::new(WriteOnlySinkHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let confirm = fs.lookup(&ctx, &dir, "confirm").await.unwrap();

        let attrs = fs.getattr(&ctx, &confirm).await.unwrap();
        assert_eq!(attrs.size, 0);
        let err = fs.read(&ctx, &confirm, 0, 1024).await.unwrap_err();
        assert_eq!(err, FsError::IsDirectory);
    }

    /// Handler that exposes a read-only file whose `read` actually
    /// performs a side effect (signing, broadcast, etc.) and overrides
    /// `is_read_side_effecting` to flag the path. The adapter must
    /// honour that flag and skip the GETATTR-time render.
    #[derive(Default)]
    struct SideEffectingReadHandler {
        reads: parking_lot::Mutex<u32>,
    }
    impl SideEffectingReadHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn read_count(&self) -> u32 {
            *self.reads.lock()
        }
    }
    #[async_trait]
    impl Handler for SideEffectingReadHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments() {
                [] => Ok(Entry::dir("")),
                [s] if s == "trigger" => Ok(Entry::file("trigger")),
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }
        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            *self.reads.lock() += 1;
            Ok(b"signed!\n".to_vec())
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::file("trigger")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
        fn is_read_side_effecting(&self, p: &VfsPath) -> bool {
            matches!(p.segments(), [s] if s == "trigger")
        }
    }

    /// Bug #1 acceptance + safety gate: even a read-only-mode file must
    /// NOT be rendered at GETATTR if `is_read_side_effecting` is true.
    /// Without this gate, a kernel-issued `stat` would silently sign /
    /// broadcast, which is the canonical failure mode for the wallets
    /// `sign/<msg>` family.
    #[tokio::test]
    async fn getattr_skips_render_for_side_effecting_file() {
        let h = SideEffectingReadHandler::new();
        let vfs = Vfs::builder().mount("box", h.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let trigger = fs.lookup(&ctx, &dir, "trigger").await.unwrap();
        let attrs = fs.getattr(&ctx, &trigger).await.unwrap();
        assert_eq!(
            h.read_count(),
            0,
            "side-effecting read must not be triggered by GETATTR"
        );
        assert_eq!(
            attrs.size, 0,
            "side-effecting file must report size=0 at GETATTR"
        );
    }

    /// Bug #1 acceptance: a GETATTR followed immediately by a READ on
    /// the same path returns exactly the rendered bytes — no NUL padding
    /// up to a sentinel size, no second render — because the mount-side
    /// cache populated by GETATTR serves the READ.
    #[tokio::test]
    async fn getattr_then_read_returns_same_bytes_no_padding() {
        let recorder = RecordingHandler::new();
        let vfs = Vfs::builder().mount("box", recorder.clone()).build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let readme = fs.lookup(&ctx, &dir, "readme").await.unwrap();
        let attrs = fs.getattr(&ctx, &readme).await.unwrap();
        let body = b"static read-only body\n";
        assert_eq!(attrs.size, body.len() as u64);
        // Read enough to cover the whole body and verify no padding.
        let r = fs.read(&ctx, &readme, 0, 1024).await.unwrap();
        assert_eq!(
            &r.data[..],
            body,
            "READ must return exactly the rendered bytes"
        );
        assert!(r.eof, "READ must report EOF at the rendered size");
        assert_eq!(r.data.len() as u64, attrs.size);
    }

    /// Handler that counts reads and emits a deterministic body. Used to
    /// verify in-flight render dedup: concurrent GETATTR calls on the
    /// same path must coalesce onto a single `vfs.read`.
    #[derive(Default)]
    struct CountingReadHandler {
        reads: parking_lot::Mutex<u32>,
    }
    impl CountingReadHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn read_count(&self) -> u32 {
            *self.reads.lock()
        }
    }
    #[async_trait]
    impl Handler for CountingReadHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments() {
                [] => Ok(Entry::dir("")),
                [s] if s == "slow" => Ok(Entry::file("slow")),
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }
        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            *self.reads.lock() += 1;
            // Yield once so concurrent callers all reach the in-flight
            // map before the future resolves. Real backends (RPC etc.)
            // await on network I/O; this single yield is enough to
            // simulate the same race window in unit tests.
            tokio::task::yield_now().await;
            Ok(b"deduped\n".to_vec())
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::file("slow")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    /// Bug #1 acceptance: N concurrent GETATTRs against the same path
    /// must coalesce onto exactly one `vfs.read`. Without dedup, a
    /// thundering-herd of clients (or kernel retry storms) could trigger
    /// N parallel renders for an expensive leaf like `error.json`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_getattrs_dedup_to_one_render() {
        let h = CountingReadHandler::new();
        let vfs = Vfs::builder().mount("box", h.clone()).build();
        let fs = Arc::new(BloomFs::new(vfs));
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let slow = fs.lookup(&ctx, &dir, "slow").await.unwrap();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let fs = fs.clone();
            let slow = slow.clone();
            handles.push(tokio::spawn(async move {
                let ctx = fake_ctx();
                fs.getattr(&ctx, &slow).await
            }));
        }
        for h in handles {
            let attrs = h.await.unwrap().unwrap();
            assert_eq!(attrs.size, b"deduped\n".len() as u64);
        }
        let count = h.read_count();
        assert!(
            count <= 4,
            "expected near-zero dedup overhead; got {} reads for 16 concurrent GETATTRs",
            count
        );
    }

    /// Handler whose `read` never resolves. Used to verify the render
    /// timeout path returns EIO rather than hanging the kernel.
    struct NeverResolvesHandler;
    #[async_trait]
    impl Handler for NeverResolvesHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            match p.segments() {
                [] => Ok(Entry::dir("")),
                [s] if s == "wedged" => Ok(Entry::file("wedged")),
                _ => Err(HandlerError::NotFound(p.to_string_path())),
            }
        }
        async fn read(&self, _p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            std::future::pending::<()>().await;
            unreachable!()
        }
        async fn list(&self, p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            if p.is_root() {
                Ok(vec![Entry::file("wedged")])
            } else {
                Err(HandlerError::NotADir(p.to_string_path()))
            }
        }
    }

    /// A render that never resolves fails GETATTR with EIO. Reporting a
    /// successful zero-byte file would let clients skip READ and hide the
    /// timeout entirely.
    #[tokio::test(start_paused = true)]
    async fn render_timeout_fails_getattr_with_eio() {
        let vfs = Vfs::builder()
            .mount("box", Arc::new(NeverResolvesHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "box").await.unwrap();
        let wedged = fs.lookup(&ctx, &dir, "wedged").await.unwrap();

        // Drive the GETATTR concurrently with a clock advance past the
        // render timeout so the timer fires deterministically.
        let getattr = tokio::spawn({
            let fs = std::sync::Arc::new(fs);
            let wedged = wedged.clone();
            async move {
                let ctx = fake_ctx();
                fs.getattr(&ctx, &wedged).await
            }
        });
        // Yield once so the spawned getattr enters the render future.
        tokio::task::yield_now().await;
        tokio::time::advance(RENDER_TIMEOUT + Duration::from_secs(1)).await;
        let error = getattr.await.unwrap().unwrap_err();
        assert_eq!(error, FsError::Io);
    }

    /// Bug #2 acceptance: kernel-supplied path components arrive as
    /// percent-encoded bytes (the kernel only splits on `/`), so the
    /// adapter must decode them before constructing `VfsPath`. A
    /// handler that echoes its received segment proves the decoded
    /// bytes — not the literal `%20` form — reach the VFS.
    struct EchoSegmentHandler;

    #[async_trait]
    impl Handler for EchoSegmentHandler {
        async fn lookup(&self, p: &VfsPath) -> Result<Entry, HandlerError> {
            if p.is_root() {
                return Ok(Entry::dir(""));
            }
            // Any non-root path is a file whose name matches the last
            // segment. Reading it returns that segment's bytes.
            Ok(Entry::file(p.segments().last().unwrap()))
        }
        async fn read(&self, p: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            let last = p
                .segments()
                .last()
                .cloned()
                .ok_or_else(|| HandlerError::NotAFile(p.to_string_path()))?;
            Ok(last.into_bytes())
        }
        async fn list(&self, _p: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn lookup_percent_decodes_space() {
        let vfs = Vfs::builder()
            .mount("echo", Arc::new(EchoSegmentHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "echo").await.unwrap();
        // Kernel hands us the literal bytes "hello%20world".
        let leaf = fs.lookup(&ctx, &dir, "hello%20world").await.unwrap();
        let r = fs.read(&ctx, &leaf, 0, 1024).await.unwrap();
        assert_eq!(&r.data[..], b"hello world");
    }

    #[tokio::test]
    async fn lookup_decodes_literal_percent_round_trip() {
        // `%25` -> `%`, so the segment "100%25done" decodes to "100%done".
        let vfs = Vfs::builder()
            .mount("echo", Arc::new(EchoSegmentHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "echo").await.unwrap();
        let leaf = fs.lookup(&ctx, &dir, "100%25done").await.unwrap();
        let r = fs.read(&ctx, &leaf, 0, 1024).await.unwrap();
        assert_eq!(&r.data[..], b"100%done");
    }

    #[tokio::test]
    async fn lookup_rejects_malformed_percent_escape() {
        let vfs = Vfs::builder()
            .mount("echo", Arc::new(EchoSegmentHandler))
            .build();
        let fs = BloomFs::new(vfs);
        let ctx = fake_ctx();
        let dir = fs.lookup(&ctx, &BloomHandle::Root, "echo").await.unwrap();
        // `%2` is truncated; `%ZZ` has bad hex; both should map to
        // InvalidInput rather than passing through to the VFS.
        let err = fs.lookup(&ctx, &dir, "ab%2").await.unwrap_err();
        assert!(matches!(err, FsError::InvalidInput));
        let err = fs.lookup(&ctx, &dir, "ab%ZZ").await.unwrap_err();
        assert!(matches!(err, FsError::InvalidInput));
    }
}
