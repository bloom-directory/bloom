//! Router-level per-path TTL cache.
//!
//! The router consults this cache before dispatching a `read` to the
//! per-prefix handler. Handlers opt in to caching by overriding
//! [`crate::Handler::cache_ttl`]; without that override the cache is a
//! no-op for that path.
//!
//! Capacity is bounded with simple LRU eviction (default 4096 entries).
//! Writes invalidate the exact path *and* every cached entry whose
//! top-level prefix (handler-mount segment) matches the write path —
//! e.g. a write to `wallets/alice/sign/message` flushes every cached
//! `wallets/...` read.

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;

/// Default LRU capacity. Holds at most `DEFAULT_CAPACITY` entries
/// across the whole VFS; older entries are evicted first.
pub const DEFAULT_CAPACITY: usize = 4096;

#[derive(Clone)]
struct Entry {
    bytes: Vec<u8>,
    expires_at: Instant,
}

/// Path-keyed TTL cache used by [`crate::Vfs`]. Cheap to clone — the
/// inner state lives behind a [`std::sync::Arc`] when wired into the
/// router.
pub struct PathCache {
    inner: Mutex<LruCache<String, Entry>>,
}

impl PathCache {
    /// New cache with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// New cache with a specific capacity. Capacity of 0 is treated as
    /// 1 (LruCache requires `NonZeroUsize`).
    pub fn with_capacity(cap: usize) -> Self {
        let cap = NonZeroUsize::new(cap.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up `path`. Returns `Some(bytes)` only if present and the
    /// entry has not yet expired. Expired entries are evicted on
    /// access so a subsequent miss won't see stale data.
    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        let mut g = self.inner.lock();
        let expired = g.peek(path).map(|e| e.expires_at <= Instant::now());
        match expired {
            Some(true) => {
                g.pop(path);
                None
            }
            Some(false) => g.get(path).map(|e| e.bytes.clone()),
            None => None,
        }
    }

    /// Insert `(path, bytes)` valid for `ttl` from now.
    pub fn put(&self, path: &str, bytes: Vec<u8>, ttl: Duration) {
        let entry = Entry {
            bytes,
            expires_at: Instant::now() + ttl,
        };
        self.inner.lock().put(path.to_string(), entry);
    }

    /// Drop the exact-path entry plus every entry under the same
    /// top-level prefix (e.g. `wallets/`). The top-level prefix is
    /// the substring up to (and including) the first `/`. If the path
    /// has no `/`, the whole prefix is the path itself.
    pub fn invalidate(&self, path: &str) {
        let prefix = top_prefix(path);
        let mut g = self.inner.lock();
        // Collect keys first to avoid mutating while iterating.
        let to_remove: Vec<String> = g
            .iter()
            .filter_map(|(k, _)| {
                if k == path || top_prefix(k) == prefix {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in to_remove {
            g.pop(&k);
        }
    }

    /// Number of currently-cached entries (test helper).
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Whether the cache is empty (test helper).
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl Default for PathCache {
    fn default() -> Self {
        Self::new()
    }
}

fn top_prefix(path: &str) -> &str {
    match path.find('/') {
        Some(i) => &path[..i],
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn hit_within_ttl_miss_after() {
        let c = PathCache::with_capacity(8);
        c.put("a/b", b"v".to_vec(), Duration::from_millis(50));
        assert_eq!(c.get("a/b").as_deref(), Some(&b"v"[..]));
        sleep(Duration::from_millis(70));
        assert!(c.get("a/b").is_none());
    }

    #[test]
    fn invalidate_drops_same_prefix() {
        let c = PathCache::with_capacity(8);
        c.put(
            "wallets/alice/address",
            b"x".to_vec(),
            Duration::from_secs(60),
        );
        c.put(
            "wallets/alice/sign/message",
            b"y".to_vec(),
            Duration::from_secs(60),
        );
        c.put(
            "chains/eth/head/number",
            b"z".to_vec(),
            Duration::from_secs(60),
        );
        c.invalidate("wallets/alice/sign/message");
        assert!(c.get("wallets/alice/address").is_none());
        assert!(c.get("wallets/alice/sign/message").is_none());
        assert_eq!(c.get("chains/eth/head/number").as_deref(), Some(&b"z"[..]));
    }

    #[test]
    fn lru_evicts_oldest() {
        let c = PathCache::with_capacity(2);
        c.put("a", b"1".to_vec(), Duration::from_secs(60));
        c.put("b", b"2".to_vec(), Duration::from_secs(60));
        // Touch a so it's MRU.
        let _ = c.get("a");
        c.put("c", b"3".to_vec(), Duration::from_secs(60));
        // b should be evicted.
        assert!(c.get("b").is_none());
        assert!(c.get("a").is_some());
        assert!(c.get("c").is_some());
    }
}
