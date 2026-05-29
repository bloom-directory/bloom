//! Content-addressed state-blob store.
//!
//! Blobs live at `<bloom_home>/chain/state_blobs/<hex_hash>`.
//! Each blob is the canonical `bloom_chain_state::State::to_blob` encoding of
//! the full state at a given height. Blobs are named by their domain-separated
//! state-blob hash (content-addressed).
//!
//! The node pins the last 256 state blobs; older ones are GC'd (spec §6.3).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bloom_chain_state::State;
use bloom_chain_types::types::Hash32;
use tracing::debug;

/// Number of state blobs to retain (spec §6.3).
const BLOB_RETENTION: usize = 256;

fn blob_retention() -> usize {
    std::env::var("BLOOM_STATE_BLOB_RETENTION")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(BLOB_RETENTION)
}

/// Content-addressed blob store.
pub struct StateBlobStore {
    root: PathBuf,
}

impl StateBlobStore {
    /// Open (or create) the blob store at `root`.
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)
            .with_context(|| format!("create state_blobs dir: {}", root.display()))?;
        Ok(StateBlobStore {
            root: root.to_path_buf(),
        })
    }

    fn path_for(&self, hash: &Hash32) -> PathBuf {
        self.root.join(hex::encode(hash.0))
    }

    /// Store a blob, keyed by its BLAKE3 hash.
    ///
    /// Returns the hash of the stored data.
    pub fn put(&self, data: &[u8]) -> Result<Hash32> {
        let hash = State::blob_hash(data);
        let path = self.path_for(&hash);
        if !path.exists() {
            let tmp_path = self.root.join(format!(".{}.tmp", hex::encode(hash.0)));
            write_atomic(&tmp_path, &path, data)
                .with_context(|| format!("write state blob {}", hex::encode(hash.0)))?;
            debug!(hash = %hex::encode(hash.0), bytes = data.len(), "state_blob.put");
        }
        Ok(hash)
    }

    /// Retrieve a blob by hash.  Returns `None` if not present.
    pub fn get(&self, hash: &Hash32) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(hash);
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read blob {}", hex::encode(hash.0))),
        }
    }

    /// Check whether a blob is present.
    pub fn has(&self, hash: &Hash32) -> bool {
        self.path_for(hash).exists()
    }

    /// Prune blobs beyond the retention window.
    ///
    /// `pinned`: set of hashes to keep regardless of age.  The implementation
    /// keeps the `BLOB_RETENTION` most recently modified files.
    ///
    /// Returns the valid blob hashes removed during this pass so callers can
    /// keep secondary indexes in sync.
    pub fn gc(&self, pinned: &[Hash32]) -> Result<Vec<Hash32>> {
        let pinned_set: std::collections::HashSet<String> =
            pinned.iter().map(|h| hex::encode(h.0)).collect();

        // Collect all blob files with their modification time.
        let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_file() {
                let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                entries.push((mtime, entry.path()));
            }
        }

        let retention = blob_retention();
        if entries.len() <= retention {
            return Ok(Vec::new());
        }

        // Sort newest first.
        entries.sort_by_key(|b| std::cmp::Reverse(b.0));

        // Remove files beyond retention, unless pinned.
        let mut removed = Vec::new();
        for (_, path) in entries.into_iter().skip(retention) {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if pinned_set.contains(&name) {
                continue;
            }
            let removed_file = match std::fs::remove_file(&path) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            };
            if removed_file {
                if let Some(hash) = hash_from_blob_filename(&name) {
                    removed.push(hash);
                }
                debug!(blob = %name, "state_blob.gc");
            }
        }
        Ok(removed)
    }
}

fn hash_from_blob_filename(name: &str) -> Option<Hash32> {
    if name.len() != 64 {
        return None;
    }
    let bytes = hex::decode(name).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Hash32(arr))
}

fn write_atomic(tmp_path: &Path, final_path: &Path, bytes: &[u8]) -> Result<()> {
    {
        let mut file = std::fs::File::create(tmp_path)
            .with_context(|| format!("create temp file {}", tmp_path.display()))?;
        use std::io::Write;
        file.write_all(bytes)
            .with_context(|| format!("write temp file {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync temp file {}", tmp_path.display()))?;
    }
    std::fs::rename(tmp_path, final_path).with_context(|| {
        format!(
            "rename temp file {} -> {}",
            tmp_path.display(),
            final_path.display()
        )
    })?;
    if let Some(parent) = final_path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}
