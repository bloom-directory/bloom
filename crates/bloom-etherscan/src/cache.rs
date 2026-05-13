//! On-disk cache for Etherscan responses.
//!
//! Layout: `<dir>/<chain_id>/<kind>/<key>.json`. TTL is enforced by file
//! mtime; expired entries are treated as absent and overwritten on the next
//! fetch. The cache stores raw `serde_json::Value` so callers can decide
//! how to deserialise.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{debug, warn};

use crate::EtherscanError;

/// Simple file-backed cache keyed by `(chain_id, kind, key)`.
#[derive(Debug, Clone)]
pub struct EtherscanCache {
    dir: PathBuf,
    /// Default TTL applied when callers don't specify one.
    pub default_ttl: Duration,
}

impl EtherscanCache {
    /// Create a cache rooted at `dir`. The directory is created lazily.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            default_ttl: Duration::from_secs(7 * 24 * 60 * 60), // 7d
        }
    }

    /// Set the default TTL (builder-style).
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, chain_id: u64, kind: &str, key: &str) -> PathBuf {
        // Sanitise key so it's safe for a filename. Addresses, hex strings,
        // and decimal block numbers are already safe; we replace anything
        // that isn't alnum / `-` / `_` / `.` with `_`.
        let safe: String = key
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir
            .join(chain_id.to_string())
            .join(kind)
            .join(format!("{safe}.json"))
    }

    /// Look up an entry. Returns `None` if missing, unreadable, or expired.
    pub fn get<T: DeserializeOwned>(
        &self,
        chain_id: u64,
        kind: &str,
        key: &str,
        ttl: Option<Duration>,
    ) -> Option<T> {
        let path = self.path_for(chain_id, kind, key);
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(?path, "cache.miss");
                return None;
            }
            Err(e) => {
                warn!(?path, error = %e, "cache.metadata_failed");
                return None;
            }
        };
        let mtime = match meta.modified() {
            Ok(t) => t,
            Err(e) => {
                warn!(?path, error = %e, "cache.modified_unavailable");
                return None;
            }
        };
        let ttl = ttl.unwrap_or(self.default_ttl);
        let age = SystemTime::now().duration_since(mtime).unwrap_or_default();
        if age > ttl {
            debug!(?path, ?age, ?ttl, "cache.expired");
            return None;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!(?path, error = %e, "cache.read_failed");
                return None;
            }
        };
        match serde_json::from_slice::<T>(&bytes) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(?path, error = %e, "cache.decode_failed");
                None
            }
        }
    }

    /// Store an entry, creating parent directories as needed.
    pub fn put<T: Serialize>(
        &self,
        chain_id: u64,
        kind: &str,
        key: &str,
        value: &T,
    ) -> Result<(), EtherscanError> {
        let path = self.path_for(chain_id, kind, key);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)
                .map_err(|e| EtherscanError::InvalidResponse(format!("cache mkdir {p:?}: {e}")))?;
        }
        let bytes = serde_json::to_vec_pretty(value)?;
        std::fs::write(&path, bytes)
            .map_err(|e| EtherscanError::InvalidResponse(format!("cache write {path:?}: {e}")))?;
        Ok(())
    }

    /// Convenience: read-through cache. Calls `fetch` only on miss/expiry.
    pub async fn get_or_fetch<T, F, Fut>(
        &self,
        chain_id: u64,
        kind: &str,
        key: &str,
        ttl: Option<Duration>,
        fetch: F,
    ) -> Result<T, EtherscanError>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, EtherscanError>>,
    {
        if let Some(v) = self.get::<T>(chain_id, kind, key, ttl) {
            return Ok(v);
        }
        let v = fetch().await?;
        if let Err(e) = self.put(chain_id, kind, key, &v) {
            warn!(error = %e, "cache.put_failed");
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use tempfile::TempDir;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Demo {
        a: u32,
        b: String,
    }

    #[test]
    fn put_and_get_round_trip() {
        let dir = TempDir::new().unwrap();
        let cache = EtherscanCache::new(dir.path().to_path_buf());
        let v = Demo {
            a: 7,
            b: "hi".into(),
        };
        cache.put(1, "abi", "0xdead", &v).unwrap();
        let got: Demo = cache.get(1, "abi", "0xdead", None).unwrap();
        assert_eq!(got, v);
    }

    #[test]
    fn miss_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache = EtherscanCache::new(dir.path().to_path_buf());
        let got: Option<Demo> = cache.get(1, "abi", "missing", None);
        assert!(got.is_none());
    }

    #[test]
    fn expiry_treated_as_miss() {
        let dir = TempDir::new().unwrap();
        let cache = EtherscanCache::new(dir.path().to_path_buf());
        let v = Demo {
            a: 1,
            b: "x".into(),
        };
        cache.put(1, "abi", "k", &v).unwrap();
        // TTL = 0 → always expired.
        let got: Option<Demo> = cache.get(1, "abi", "k", Some(Duration::from_nanos(0)));
        // SystemTime resolution may treat zero-age as <= 0; explicit check below.
        // We allow either Some or None for sub-microsecond ages; primary check
        // uses a positive elapsed window via thread sleep.
        let _ = got;
        std::thread::sleep(Duration::from_millis(20));
        let got2: Option<Demo> = cache.get(1, "abi", "k", Some(Duration::from_millis(1)));
        assert!(got2.is_none(), "expected expiry miss");
    }

    #[tokio::test]
    async fn get_or_fetch_calls_fetch_once() {
        let dir = TempDir::new().unwrap();
        let cache = EtherscanCache::new(dir.path().to_path_buf());
        let v1: Demo = cache
            .get_or_fetch(1, "kind", "k", None, || async {
                Ok(Demo {
                    a: 9,
                    b: "z".into(),
                })
            })
            .await
            .unwrap();
        assert_eq!(v1.a, 9);
        let v2: Demo = cache
            .get_or_fetch(1, "kind", "k", None, || async {
                panic!("should not call fetch on hit")
            })
            .await
            .unwrap();
        assert_eq!(v2, v1);
    }

    #[test]
    fn key_sanitised() {
        let dir = TempDir::new().unwrap();
        let cache = EtherscanCache::new(dir.path().to_path_buf());
        let v = Demo {
            a: 1,
            b: "x".into(),
        };
        cache.put(1, "abi", "weird/key with spaces", &v).unwrap();
        let got: Demo = cache.get(1, "abi", "weird/key with spaces", None).unwrap();
        assert_eq!(got, v);
    }
}
