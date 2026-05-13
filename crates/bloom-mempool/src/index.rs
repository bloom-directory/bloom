//! Bounded in-memory index of observed pending txs.
//!
//! Keyed by hash (primary), with a secondary `(address, nonce)` map
//! that powers the nonce-conflict check at stage time.

use alloy::primitives::{Address, B256};
use parking_lot::RwLock;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

use crate::provider::PendingTx;

#[derive(Debug, Clone)]
pub struct PendingTxRecord {
    pub tx: PendingTx,
    pub inserted_at: SystemTime,
}

#[derive(Debug)]
pub struct PendingTxIndex {
    inner: RwLock<Inner>,
    capacity: usize,
}

#[derive(Debug, Default)]
struct Inner {
    by_hash: BTreeMap<B256, PendingTxRecord>,
    by_addr_nonce: BTreeMap<(Address, u64), B256>,
    order: VecDeque<B256>,
    evictions_total: u64,
}

impl PendingTxIndex {
    pub fn new(capacity: usize) -> Arc<Self> {
        assert!(capacity > 0, "PendingTxIndex capacity must be > 0");
        Arc::new(Self {
            inner: RwLock::new(Inner::default()),
            capacity,
        })
    }

    pub fn insert(&self, tx: PendingTx) {
        let mut g = self.inner.write();
        let hash = tx.hash;
        let from = tx.from;
        let nonce = tx.nonce;
        let inserted_at = SystemTime::now();

        if let std::collections::btree_map::Entry::Occupied(mut e) = g.by_hash.entry(hash) {
            e.insert(PendingTxRecord { tx, inserted_at });
            return;
        }

        // Nonce-replacement: an earlier tx with the same (from, nonce) but a
        // different hash is being superseded. Drop the stale hash from
        // by_hash/order so len()/snapshot() reflect one tx per (addr, nonce);
        // otherwise the stale entry would only age out via LRU.
        if let Some(&prior) = g.by_addr_nonce.get(&(from, nonce))
            && prior != hash
        {
            g.by_hash.remove(&prior);
            g.order.retain(|h| h != &prior);
        }

        while g.order.len() >= self.capacity {
            if let Some(victim) = g.order.pop_front() {
                if let Some(rec) = g.by_hash.remove(&victim) {
                    // Guard: only drop the secondary index entry if it still
                    // points at this victim. A nonce-replacement insert may have
                    // re-pointed (addr, nonce) at a newer hash.
                    if g.by_addr_nonce.get(&(rec.tx.from, rec.tx.nonce)) == Some(&victim) {
                        g.by_addr_nonce.remove(&(rec.tx.from, rec.tx.nonce));
                    }
                    g.evictions_total += 1;
                }
            } else {
                break;
            }
        }

        g.by_hash.insert(hash, PendingTxRecord { tx, inserted_at });
        g.by_addr_nonce.insert((from, nonce), hash);
        g.order.push_back(hash);
    }

    pub fn lookup_by_hash(&self, hash: &B256) -> Option<PendingTxRecord> {
        self.inner.read().by_hash.get(hash).cloned()
    }

    pub fn lookup_by_addr_nonce(&self, addr: Address, nonce: u64) -> Option<PendingTxRecord> {
        let g = self.inner.read();
        let hash = g.by_addr_nonce.get(&(addr, nonce))?;
        g.by_hash.get(hash).cloned()
    }

    pub fn remove(&self, hash: &B256) -> Option<PendingTxRecord> {
        let mut g = self.inner.write();
        let rec = g.by_hash.remove(hash)?;
        if g.by_addr_nonce.get(&(rec.tx.from, rec.tx.nonce)) == Some(hash) {
            g.by_addr_nonce.remove(&(rec.tx.from, rec.tx.nonce));
        }
        g.order.retain(|h| h != hash);
        Some(rec)
    }

    pub fn len(&self) -> usize {
        self.inner.read().by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn evictions_total(&self) -> u64 {
        self.inner.read().evictions_total
    }

    /// Snapshot of all observed nonces for a single address. Used by
    /// the VFS `by_address/<a>/nonces.json` handler.
    pub fn observed_nonces(&self, addr: Address) -> Vec<u64> {
        let g = self.inner.read();
        g.by_addr_nonce
            .range((addr, 0)..=(addr, u64::MAX))
            .map(|((_, n), _)| *n)
            .collect()
    }

    /// Full snapshot of all currently-indexed pending txs. Used by the
    /// VFS `wallets/<w>/chains/<c>/pending_external.jsonl` handler to
    /// filter txs that look like they were sent from a managed wallet.
    pub fn snapshot(&self) -> Vec<PendingTx> {
        self.inner
            .read()
            .by_hash
            .values()
            .map(|r| r.tx.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{PendingTx, TxFees};
    use alloy::primitives::{Bytes, U256};

    fn make_tx(hash_byte: u8, addr_byte: u8, nonce: u64) -> PendingTx {
        let mut hash = [0u8; 32];
        hash[0] = hash_byte;
        let mut addr = [0u8; 20];
        addr[0] = addr_byte;
        PendingTx {
            hash: B256::from(hash),
            from: Address::from(addr),
            to: None,
            nonce,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: SystemTime::now(),
        }
    }

    #[test]
    fn insert_and_lookup_by_hash() {
        let idx = PendingTxIndex::new(8);
        let tx = make_tx(1, 1, 0);
        idx.insert(tx.clone());
        let got = idx.lookup_by_hash(&tx.hash).unwrap();
        assert_eq!(got.tx.nonce, 0);
    }

    #[test]
    fn insert_and_lookup_by_addr_nonce() {
        let idx = PendingTxIndex::new(8);
        let tx = make_tx(2, 3, 42);
        idx.insert(tx.clone());
        let got = idx.lookup_by_addr_nonce(tx.from, 42).unwrap();
        assert_eq!(got.tx.hash, tx.hash);
        assert!(idx.lookup_by_addr_nonce(tx.from, 43).is_none());
    }

    #[test]
    fn lru_evicts_oldest_at_capacity() {
        let idx = PendingTxIndex::new(2);
        let a = make_tx(1, 1, 0);
        let b = make_tx(2, 2, 0);
        let c = make_tx(3, 3, 0);
        idx.insert(a.clone());
        idx.insert(b.clone());
        idx.insert(c.clone());
        assert_eq!(idx.len(), 2);
        assert!(idx.lookup_by_hash(&a.hash).is_none(), "a should be evicted");
        assert!(idx.lookup_by_hash(&b.hash).is_some());
        assert!(idx.lookup_by_hash(&c.hash).is_some());
        assert_eq!(idx.evictions_total(), 1);
    }

    #[test]
    fn duplicate_insert_updates_in_place_no_eviction() {
        let idx = PendingTxIndex::new(2);
        let a = make_tx(1, 1, 0);
        idx.insert(a.clone());
        idx.insert(a.clone());
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.evictions_total(), 0);
    }

    #[test]
    fn observed_nonces_returns_sorted_dedup() {
        let idx = PendingTxIndex::new(8);
        idx.insert(make_tx(1, 7, 3));
        idx.insert(make_tx(2, 7, 1));
        idx.insert(make_tx(3, 7, 2));
        idx.insert(make_tx(4, 9, 5));
        let mut addr = [0u8; 20];
        addr[0] = 7;
        let ns = idx.observed_nonces(Address::from(addr));
        assert_eq!(ns, vec![1, 2, 3]);
    }

    #[test]
    fn snapshot_returns_all_indexed_txs() {
        let idx = PendingTxIndex::new(8);
        idx.insert(make_tx(1, 1, 0));
        idx.insert(make_tx(2, 1, 1));
        idx.insert(make_tx(3, 2, 0));
        let snap = idx.snapshot();
        assert_eq!(snap.len(), 3);
    }

    #[test]
    fn nonce_replacement_keeps_secondary_index_consistent() {
        let idx = PendingTxIndex::new(8);
        let a = make_tx(1, 7, 5); // (addr=7, nonce=5) -> hash a
        let b = make_tx(2, 7, 5); // same (addr, nonce), new hash b
        idx.insert(a.clone());
        idx.insert(b.clone());
        // by_addr_nonce should now point at b's hash:
        let got = idx.lookup_by_addr_nonce(b.from, 5).unwrap();
        assert_eq!(got.tx.hash, b.hash);

        // Same-nonce replacement drops the stale hash entirely — len() must
        // not over-report and the old hash must not be reachable.
        assert_eq!(idx.len(), 1);
        assert!(idx.lookup_by_hash(&a.hash).is_none());
        assert_eq!(
            idx.evictions_total(),
            0,
            "replacement is not a capacity eviction"
        );

        // Removing the (now absent) older hash a must be a no-op and leave
        // the by_addr_nonce entry pointing at b intact.
        assert!(idx.remove(&a.hash).is_none());
        let still = idx.lookup_by_addr_nonce(b.from, 5).unwrap();
        assert_eq!(still.tx.hash, b.hash);
    }
}
