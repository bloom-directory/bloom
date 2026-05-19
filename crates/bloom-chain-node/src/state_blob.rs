//! Content-addressed state-blob store.
//!
//! Blobs live at `<bloom_home>/chain/state_blobs/<hex_hash>`.
//! Each blob is the SSZ serialisation of the full state trie at a given height.
//! Blobs are named by their BLAKE3 hash (content-addressed).
//!
//! The node pins the last 256 state blobs; older ones are GC'd (spec §6.3).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bloom_chain_types::types::Hash32;
use tracing::debug;

/// Number of state blobs to retain (spec §6.3).
const BLOB_RETENTION: usize = 256;

/// Content-addressed blob store.
pub struct StateBlobStore {
    root: PathBuf,
}

impl StateBlobStore {
    /// Open (or create) the blob store at `root`.
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)
            .with_context(|| format!("create state_blobs dir: {}", root.display()))?;
        Ok(StateBlobStore { root: root.to_path_buf() })
    }

    fn path_for(&self, hash: &Hash32) -> PathBuf {
        self.root.join(hex::encode(&hash.0))
    }

    /// Store a blob, keyed by its BLAKE3 hash.
    ///
    /// Returns the hash of the stored data.
    pub fn put(&self, data: &[u8]) -> Result<Hash32> {
        let hash_bytes = *blake3::hash(data).as_bytes();
        let hash = Hash32(hash_bytes);
        let path = self.path_for(&hash);
        if !path.exists() {
            std::fs::write(&path, data)
                .with_context(|| format!("write state blob {}", hex::encode(hash_bytes)))?;
            debug!(hash = %hex::encode(hash_bytes), bytes = data.len(), "state_blob.put");
        }
        Ok(hash)
    }

    /// Retrieve a blob by hash.  Returns `None` if not present.
    pub fn get(&self, hash: &Hash32) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(hash);
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read blob {}", hex::encode(&hash.0))),
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
    pub fn gc(&self, pinned: &[Hash32]) -> Result<()> {
        let pinned_set: std::collections::HashSet<String> =
            pinned.iter().map(|h| hex::encode(&h.0)).collect();

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

        if entries.len() <= BLOB_RETENTION {
            return Ok(());
        }

        // Sort newest first.
        entries.sort_by(|a, b| b.0.cmp(&a.0));

        // Remove files beyond retention, unless pinned.
        for (_, path) in entries.into_iter().skip(BLOB_RETENTION) {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if pinned_set.contains(&name) {
                continue;
            }
            let _ = std::fs::remove_file(&path);
            debug!(blob = %name, "state_blob.gc");
        }
        Ok(())
    }
}
