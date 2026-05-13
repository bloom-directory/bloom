//! Subscription registry and executor for bloom.
//!
//! This crate provides:
//!
//! - [`WatchRegistry`]: a persisted, in-memory registry of declarative watch
//!   specs. Each spec is written to `<root>/<wallet>/<id>.toml`.
//! - [`WatchExecutor`]: a polling executor that runs in a background tokio
//!   task. On each tick it walks the registry and, for each [`WatchSpec`],
//!   queries the configured chain via [`bloom_chain::ChainClient`] and
//!   appends a JSON line to the watch's per-watch live log when state
//!   changes. When the live file grows past 1 MB, it is rotated into
//!   `history.jsonl.<n>` and a sentinel is appended to the new live file
//!   so tailing agents can follow the rotation.

pub mod executor;

pub use executor::{ROTATE_THRESHOLD_BYTES, WatchExecutor};

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WatchKind {
    Balance {
        address: String,
        threshold_wei: String,
        comparator: String,
    },
    Block {
        chain: String,
    },
    GasPrice {
        chain: String,
        threshold_gwei: f64,
    },
    Event {
        chain: String,
        contract: String,
        topic0: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WatchSpec {
    pub id: String,
    pub wallet: String,
    #[serde(with = "u128_string")]
    pub created_ms: u128,
    pub kind: WatchKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

mod u128_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum WatchError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("toml: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("invalid id '{0}'")]
    InvalidId(String),
    #[error("invalid wallet '{0}'")]
    InvalidWallet(String),
}

struct Inner {
    root: PathBuf,
    specs: RwLock<HashMap<String, WatchSpec>>, // key: "<wallet>/<id>"
}

#[derive(Clone)]
pub struct WatchRegistry {
    inner: Arc<Inner>,
}

fn is_valid_segment(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn validate_wallet(w: &str) -> Result<(), WatchError> {
    if is_valid_segment(w) {
        Ok(())
    } else {
        Err(WatchError::InvalidWallet(w.to_string()))
    }
}

fn validate_id(id: &str) -> Result<(), WatchError> {
    if is_valid_segment(id) {
        Ok(())
    } else {
        Err(WatchError::InvalidId(id.to_string()))
    }
}

fn key(wallet: &str, id: &str) -> String {
    format!("{}/{}", wallet, id)
}

impl WatchRegistry {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, WatchError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let mut specs: HashMap<String, WatchSpec> = HashMap::new();

        for wallet_entry in fs::read_dir(&root)? {
            let wallet_entry = wallet_entry?;
            if !wallet_entry.file_type()?.is_dir() {
                debug!(path = %wallet_entry.path().display(), "watch.registry.scan.skip_non_dir");
                continue;
            }
            let wallet_name = match wallet_entry.file_name().into_string() {
                Ok(n) => n,
                Err(os) => {
                    debug!(name = ?os, "watch.registry.scan.non_utf8_wallet");
                    continue;
                }
            };
            if !is_valid_segment(&wallet_name) {
                debug!(wallet = %wallet_name, "watch.registry.scan.invalid_wallet_name");
                continue;
            }
            for spec_entry in fs::read_dir(wallet_entry.path())? {
                let spec_entry = spec_entry?;
                let path = spec_entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                    continue;
                }
                let body = fs::read_to_string(&path)?;
                let spec: WatchSpec = toml::from_str(&body)?;
                specs.insert(key(&spec.wallet, &spec.id), spec);
            }
        }
        debug!(count = specs.len(), "watch.registry.loaded");

        Ok(Self {
            inner: Arc::new(Inner {
                root,
                specs: RwLock::new(specs),
            }),
        })
    }

    fn spec_path(root: &Path, wallet: &str, id: &str) -> PathBuf {
        root.join(wallet).join(format!("{}.toml", id))
    }

    pub fn add(&self, spec: WatchSpec) -> Result<(), WatchError> {
        validate_wallet(&spec.wallet)?;
        validate_id(&spec.id)?;

        let dir = self.inner.root.join(&spec.wallet);
        fs::create_dir_all(&dir)?;
        let path = Self::spec_path(&self.inner.root, &spec.wallet, &spec.id);
        let body = toml::to_string_pretty(&spec)?;
        fs::write(&path, body)?;
        self.inner
            .specs
            .write()
            .insert(key(&spec.wallet, &spec.id), spec);
        Ok(())
    }

    pub fn remove(&self, wallet: &str, id: &str) -> Result<bool, WatchError> {
        validate_wallet(wallet)?;
        validate_id(id)?;

        let removed = self.inner.specs.write().remove(&key(wallet, id)).is_some();
        let path = Self::spec_path(&self.inner.root, wallet, id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(removed),
            Err(e) => Err(WatchError::Io(e)),
        }
    }

    pub fn list(&self, wallet: Option<&str>) -> Vec<WatchSpec> {
        let guard = self.inner.specs.read();
        let mut out: Vec<WatchSpec> = guard
            .values()
            .filter(|s| match wallet {
                Some(w) => s.wallet == w,
                None => true,
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn get(&self, wallet: &str, id: &str) -> Option<WatchSpec> {
        self.inner.specs.read().get(&key(wallet, id)).cloned()
    }

    /// Path to the on-disk root for spec files (the directory passed to
    /// `WatchRegistry::new`). Useful for executors and handlers that need
    /// to place sibling per-watch artefacts (live logs, history).
    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    /// Find a watch spec by id alone (scans every wallet). Returns the
    /// first match. Allocated ids are unique across wallets in practice
    /// because [`WatchRegistry::allocate_id`] increments globally.
    pub fn find_by_id(&self, id: &str) -> Option<WatchSpec> {
        self.inner
            .specs
            .read()
            .values()
            .find(|s| s.id == id)
            .cloned()
    }

    /// List every spec across all wallets, sorted by id.
    pub fn list_all(&self) -> Vec<WatchSpec> {
        self.list(None)
    }

    pub fn allocate_id(&self) -> String {
        let guard = self.inner.specs.read();
        let mut next: u32 = 1;
        for spec in guard.values() {
            if let Some(rest) = spec.id.strip_prefix("w-")
                && let Ok(n) = rest.parse::<u32>()
                && n >= next
            {
                next = n + 1;
            }
        }
        format!("w-{:04}", next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_spec(wallet: &str, id: &str) -> WatchSpec {
        WatchSpec {
            id: id.to_string(),
            wallet: wallet.to_string(),
            created_ms: 1_700_000_000_000,
            kind: WatchKind::Balance {
                address: "0xabc".into(),
                threshold_wei: "1000000000000000000".into(),
                comparator: "<".into(),
            },
            note: Some("test".into()),
        }
    }

    #[test]
    fn add_then_list_returns_spec() {
        let dir = tempdir().unwrap();
        let reg = WatchRegistry::new(dir.path()).unwrap();
        let spec = sample_spec("alice", "w-0001");
        reg.add(spec.clone()).unwrap();

        let listed = reg.list(Some("alice"));
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], spec);
        assert_eq!(reg.get("alice", "w-0001"), Some(spec));
    }

    #[test]
    fn remove_returns_true_and_spec_gone() {
        let dir = tempdir().unwrap();
        let reg = WatchRegistry::new(dir.path()).unwrap();
        let spec = sample_spec("alice", "w-0001");
        reg.add(spec).unwrap();

        let removed = reg.remove("alice", "w-0001").unwrap();
        assert!(removed);
        assert!(reg.get("alice", "w-0001").is_none());
        assert!(reg.list(None).is_empty());

        // Removing again returns false.
        let removed_again = reg.remove("alice", "w-0001").unwrap();
        assert!(!removed_again);
    }

    #[test]
    fn invalid_wallet_rejected() {
        let dir = tempdir().unwrap();
        let reg = WatchRegistry::new(dir.path()).unwrap();
        let bad = WatchSpec {
            wallet: "../evil".into(),
            ..sample_spec("alice", "w-0001")
        };
        let err = reg.add(bad).unwrap_err();
        assert!(matches!(err, WatchError::InvalidWallet(_)));

        let bad_id = WatchSpec {
            id: "..".into(),
            ..sample_spec("alice", "w-0001")
        };
        let err = reg.add(bad_id).unwrap_err();
        assert!(matches!(err, WatchError::InvalidId(_)));

        let empty = WatchSpec {
            wallet: "".into(),
            ..sample_spec("alice", "w-0001")
        };
        assert!(matches!(
            reg.add(empty).unwrap_err(),
            WatchError::InvalidWallet(_)
        ));
    }

    #[test]
    fn round_trip_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let spec_a = sample_spec("alice", "w-0001");
        let spec_b = WatchSpec {
            id: "w-0002".into(),
            wallet: "bob".into(),
            created_ms: 1_700_000_000_001,
            kind: WatchKind::GasPrice {
                chain: "mainnet".into(),
                threshold_gwei: 25.5,
            },
            note: None,
        };

        {
            let reg = WatchRegistry::new(&path).unwrap();
            reg.add(spec_a.clone()).unwrap();
            reg.add(spec_b.clone()).unwrap();
            drop(reg);
        }

        let reg2 = WatchRegistry::new(&path).unwrap();
        let all = reg2.list(None);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], spec_a);
        assert_eq!(all[1], spec_b);

        // allocate_id should pick up next free slot.
        assert_eq!(reg2.allocate_id(), "w-0003");
    }

    #[test]
    fn allocate_id_starts_at_one() {
        let dir = tempdir().unwrap();
        let reg = WatchRegistry::new(dir.path()).unwrap();
        assert_eq!(reg.allocate_id(), "w-0001");
    }
}
