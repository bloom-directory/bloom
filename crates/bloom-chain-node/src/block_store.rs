//! Flat-file block store: `<bloom_home>/chain/blocks/<height>`.
//!
//! Each file contains one SSZ-encoded `Block`.  Rolling-window prune at
//! 512 blocks (2× the 256-block state-blob retention window per spec §14).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bloom_chain_types::block::Block;
use bloom_chain_types::ssz::{Decode, Encode};
use tracing::debug;

/// Rolling window: blocks older than this many blocks are eligible for pruning.
const PRUNE_WINDOW: u64 = 512;

fn prune_window() -> u64 {
    std::env::var("BLOOM_BLOCK_PRUNE_WINDOW")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(PRUNE_WINDOW)
}

/// Block store backed by plain files under `<root>/`.
pub struct BlockStore {
    root: PathBuf,
}

impl BlockStore {
    /// Open (or create) the block store at `root`.
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)
            .with_context(|| format!("create block store dir: {}", root.display()))?;
        Ok(BlockStore {
            root: root.to_path_buf(),
        })
    }

    fn path_for(&self, height: u64) -> PathBuf {
        self.root.join(height.to_string())
    }

    /// Store a block at `height`.
    pub fn put(&self, height: u64, block: &Block) -> Result<()> {
        let path = self.path_for(height);
        let tmp_path = self.root.join(format!(".{height}.tmp"));
        let bytes = block.as_ssz_bytes();
        write_atomic(&tmp_path, &path, &bytes)
            .with_context(|| format!("write block {height}: {}", path.display()))?;
        debug!(height, bytes = bytes.len(), "block_store.put");
        Ok(())
    }

    /// Retrieve a block by height.  Returns `None` if not present.
    pub fn get(&self, height: u64) -> Result<Option<Block>> {
        let path = self.path_for(height);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let block = Block::from_ssz_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("block {height} SSZ decode: {:?}", e))?;
                Ok(Some(block))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read block {height}")),
        }
    }

    /// Retrieve a block by its `header.block_hash()`.  Returns `None` if no
    /// block in the store matches.
    ///
    /// v0 walks the on-disk window (≤ 512 blocks) instead of maintaining a
    /// dedicated hash → height index — at this size a linear scan is
    /// cheaper than the durability story for a separate index. If the
    /// retention window grows, this should become an LRU-backed index.
    pub fn get_by_hash(
        &self,
        block_hash: &bloom_chain_types::types::Hash32,
    ) -> Result<Option<Block>> {
        for entry in std::fs::read_dir(&self.root)
            .with_context(|| format!("read block store dir: {}", self.root.display()))?
        {
            let entry = entry?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let Ok(height) = name.parse::<u64>() else {
                continue;
            };
            // Re-use `get` so SSZ decode failures surface with the height.
            if let Some(block) = self.get(height)?
                && &block.header.block_hash() == block_hash
            {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    /// Return the latest stored height, or `None` if the store is empty.
    pub fn latest_height(&self) -> Result<Option<u64>> {
        let mut max: Option<u64> = None;
        for entry in std::fs::read_dir(&self.root)
            .with_context(|| format!("read block store dir: {}", self.root.display()))?
        {
            let entry = entry?;
            if let Ok(name) = entry.file_name().into_string()
                && let Ok(h) = name.parse::<u64>()
            {
                max = Some(max.map_or(h, |m: u64| m.max(h)));
            }
        }
        Ok(max)
    }

    /// Prune blocks older than `current_height - PRUNE_WINDOW`.
    pub fn prune(&self, current_height: u64) -> Result<()> {
        let window = prune_window();
        if current_height < window {
            return Ok(());
        }
        let prune_before = current_height - window;
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if let Ok(name) = entry.file_name().into_string()
                && let Ok(h) = name.parse::<u64>()
                && h < prune_before
            {
                let path = entry.path();
                let _ = std::fs::remove_file(&path);
                debug!(height = h, "block_store.pruned");
            }
        }
        Ok(())
    }
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
