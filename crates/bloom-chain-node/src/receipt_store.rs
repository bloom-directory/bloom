//! Flat-file receipt store: `<bloom_home>/chain/receipts/<tx_hash_hex>`.
//!
//! Each file is one SSZ-encoded [`Receipt`].  Without receipts, a CLI that
//! waits on nonce advancement cannot distinguish a successful tx from a
//! silent revert — the consensus driver bumps the nonce *before* executing
//! the petal, so even reverted txs look "applied".
//!
//! The store mirrors `BlockStore`'s rolling-window prune: receipts older
//! than `PRUNE_WINDOW` blocks behind tip are deleted.  Indexing is keyed by
//! `tx_hash` so reverts surface even if the caller doesn't know which block
//! their tx landed in.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bloom_chain_types::receipt::Receipt;
use bloom_chain_types::ssz::{Decode, Encode};
use bloom_chain_types::types::Hash32;
use tracing::debug;

/// Receipts for blocks older than this many behind tip are eligible for
/// pruning.  Matches `BlockStore::PRUNE_WINDOW`.
const PRUNE_WINDOW: u64 = 512;

/// Receipt store backed by plain files under `<root>/`.
pub struct ReceiptStore {
    root: PathBuf,
    /// Sidecar: tx_hash → height, so prune-by-block-height is cheap.
    /// Stored under `<root>/_height/<tx_hash_hex>`.
    height_root: PathBuf,
}

impl ReceiptStore {
    /// Open (or create) the receipt store at `root`.
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)
            .with_context(|| format!("create receipt store dir: {}", root.display()))?;
        let height_root = root.join("_height");
        std::fs::create_dir_all(&height_root)
            .with_context(|| format!("create receipt height dir: {}", height_root.display()))?;
        Ok(ReceiptStore {
            root: root.to_path_buf(),
            height_root,
        })
    }

    fn path_for(&self, tx_hash: &Hash32) -> PathBuf {
        self.root.join(hex::encode(tx_hash.0))
    }

    fn height_path_for(&self, tx_hash: &Hash32) -> PathBuf {
        self.height_root.join(hex::encode(tx_hash.0))
    }

    /// Persist a receipt under its `tx_hash`.  Idempotent.
    pub fn put(&self, height: u64, receipt: &Receipt) -> Result<()> {
        let path = self.path_for(&receipt.tx_hash);
        let bytes = receipt.as_ssz_bytes();
        std::fs::write(&path, &bytes)
            .with_context(|| format!("write receipt {}", path.display()))?;
        std::fs::write(
            self.height_path_for(&receipt.tx_hash),
            height.to_string().as_bytes(),
        )
        .with_context(|| {
            format!(
                "write receipt height sidecar for {}",
                hex::encode(receipt.tx_hash.0)
            )
        })?;
        debug!(tx_hash = %hex::encode(receipt.tx_hash.0), height, "receipt_store.put");
        Ok(())
    }

    /// Look up a receipt by `tx_hash`.  Returns `None` if not present.
    pub fn get(&self, tx_hash: &Hash32) -> Result<Option<Receipt>> {
        let path = self.path_for(tx_hash);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let r = Receipt::from_ssz_bytes(&bytes)
                    .map_err(|e| anyhow::anyhow!("receipt SSZ decode: {:?}", e))?;
                Ok(Some(r))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read receipt {}", path.display())),
        }
    }

    /// Prune receipts for blocks older than `current_height - PRUNE_WINDOW`.
    pub fn prune(&self, current_height: u64) -> Result<()> {
        if current_height < PRUNE_WINDOW {
            return Ok(());
        }
        let prune_before = current_height - PRUNE_WINDOW;
        for entry in std::fs::read_dir(&self.height_root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Read sidecar to learn the recorded height.
            let h: u64 = match std::fs::read_to_string(entry.path()) {
                Ok(s) => match s.trim().parse() {
                    Ok(h) => h,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            if h < prune_before {
                let _ = std::fs::remove_file(self.root.join(name));
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_types::receipt::Log;
    use bloom_chain_types::types::{Address, Hash32};
    use tempfile::TempDir;

    fn mk_receipt(byte: u8, success: bool) -> Receipt {
        Receipt {
            tx_hash: Hash32([byte; 32]),
            success,
            fuel_used: 12_345,
            return_data: if success {
                b"ok".to_vec()
            } else {
                b"reverted: insufficient balance".to_vec()
            },
            logs: vec![Log {
                address: Address([byte; 32]),
                topics: vec![Hash32([0xAA; 32])],
                data: vec![1, 2, 3],
            }],
            invariant_outcomes: vec![],
        }
    }

    #[test]
    fn roundtrip_put_get() {
        let td = TempDir::new().unwrap();
        let store = ReceiptStore::open(td.path()).unwrap();
        let r = mk_receipt(0x11, true);
        store.put(7, &r).unwrap();
        let got = store.get(&r.tx_hash).unwrap().expect("present");
        assert_eq!(got, r);
    }

    #[test]
    fn missing_returns_none() {
        let td = TempDir::new().unwrap();
        let store = ReceiptStore::open(td.path()).unwrap();
        assert!(store.get(&Hash32([0xFF; 32])).unwrap().is_none());
    }

    #[test]
    fn prune_drops_old_receipts() {
        let td = TempDir::new().unwrap();
        let store = ReceiptStore::open(td.path()).unwrap();
        let old = mk_receipt(0x01, true);
        let new_ = mk_receipt(0x02, false);
        store.put(10, &old).unwrap();
        store.put(1000, &new_).unwrap();
        store.prune(1000).unwrap();
        assert!(
            store.get(&old.tx_hash).unwrap().is_none(),
            "old receipt should be pruned"
        );
        assert!(
            store.get(&new_.tx_hash).unwrap().is_some(),
            "recent receipt should remain"
        );
    }
}
