//! Sled-backed persistent mempool mirror.
//!
//! The in-memory `Mempool` (from `bloom-chain-consensus`) is the authoritative
//! view during node operation.  This module writes admitted txs to sled so
//! that a restarted node can reload its pending-tx set without losing work.
//!
//! Key schema: `<sender_hex>/<nonce_be8>` → SSZ-encoded `Tx`.

use std::path::Path;

use anyhow::{Context, Result};
use bloom_chain_types::{tx::Tx, types::Address};
use bloom_chain_types::ssz::{Decode, Encode};
use tracing::debug;

/// Sled-backed store for pending txs.
pub struct MempoolPersist {
    db: sled::Db,
}

impl MempoolPersist {
    /// Open (or create) the sled database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let db = sled::open(path)
            .with_context(|| format!("open mempool.sled: {}", path.display()))?;
        Ok(MempoolPersist { db })
    }

    fn key(sender: &Address, nonce: u64) -> Vec<u8> {
        let mut k = Vec::with_capacity(32 + 8);
        k.extend_from_slice(&sender.0);
        k.extend_from_slice(&nonce.to_be_bytes());
        k
    }

    /// Persist a tx.
    pub fn put(&self, tx: &Tx) -> Result<()> {
        let key = Self::key(&tx.sender, tx.nonce);
        let val = tx.as_ssz_bytes();
        self.db
            .insert(&key, val)
            .context("mempool_persist.put")?;
        debug!(sender = %hex::encode(&tx.sender.0), nonce = tx.nonce, "mempool_persist.put");
        Ok(())
    }

    /// Remove a tx (called when it's included in a block or evicted).
    pub fn remove(&self, sender: &Address, nonce: u64) -> Result<()> {
        let key = Self::key(sender, nonce);
        self.db.remove(&key).context("mempool_persist.remove")?;
        Ok(())
    }

    /// Load all persisted txs.  Corrupted entries are logged and skipped.
    pub fn load_all(&self) -> Result<Vec<Tx>> {
        let mut txs = Vec::new();
        for item in self.db.iter() {
            let (_k, v) = item.context("mempool_persist.load_all iter")?;
            match Tx::from_ssz_bytes(&v) {
                Ok(tx) => txs.push(tx),
                Err(e) => {
                    tracing::warn!("mempool_persist: corrupt tx entry skipped: {:?}", e);
                }
            }
        }
        Ok(txs)
    }

    /// Flush all pending sled writes.
    pub fn flush(&self) -> Result<()> {
        self.db.flush().context("mempool_persist.flush")?;
        Ok(())
    }
}
