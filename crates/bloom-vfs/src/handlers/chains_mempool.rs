//! Handler for `chains/<chain>/mempool/...`. Backed by a
//! `PendingTxIndex` (populated by a `MempoolStream` in Phase 4 — wiring
//! lands in Task 4.6).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use bloom_mempool::{PendingTx, PendingTxIndex};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const RECENT_RING_CAPACITY: usize = 500;

fn is_hash_segment(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_hash(s: &str) -> Result<alloy::primitives::B256, HandlerError> {
    let bytes = alloy::hex::decode(&s[2..]).map_err(|e| HandlerError::invalid(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| HandlerError::invalid("hash must be 32 bytes"))?;
    Ok(alloy::primitives::B256::from(arr))
}

struct RingBuffer {
    items: std::collections::VecDeque<PendingTx>,
    capacity: usize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            items: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, tx: PendingTx) {
        if self.items.len() == self.capacity {
            self.items.pop_front();
        }
        self.items.push_back(tx);
    }

    fn snapshot(&self) -> Vec<PendingTx> {
        self.items.iter().cloned().collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SubscriptionState {
    Subscribed,
    Disconnected,
    NotConfigured,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStatus {
    pub provider: String,
    pub subscribed: bool,
    pub observed_pending: u64,
    pub uptime_sec: u64,
    pub dropped_count: u64,
    pub evictions_total: u64,
    pub stale_for_secs: u64,
}

pub struct MempoolHandler {
    /// Chain name — unused in Task 2.1 but consumed in Tasks 2.4–2.7
    /// when the handler gains by_address/<chain>/... routing.
    #[allow(dead_code)]
    chain_name: String,
    index: Arc<PendingTxIndex>,
    provider_id: String,
    started_at: SystemTime,
    state: RwLock<SubscriptionState>,
    dropped: AtomicU64,
    last_event_at: RwLock<SystemTime>,
    recent: RwLock<RingBuffer>,
    live_tx: tokio::sync::broadcast::Sender<PendingTx>,
}

impl MempoolHandler {
    pub fn new(
        chain_name: impl Into<String>,
        provider_id: impl Into<String>,
        index: Arc<PendingTxIndex>,
    ) -> Self {
        Self {
            chain_name: chain_name.into(),
            index,
            provider_id: provider_id.into(),
            started_at: SystemTime::now(),
            state: RwLock::new(SubscriptionState::Disconnected),
            dropped: AtomicU64::new(0),
            last_event_at: RwLock::new(SystemTime::now()),
            recent: RwLock::new(RingBuffer::new(RECENT_RING_CAPACITY)),
            live_tx: tokio::sync::broadcast::channel(4096).0,
        }
    }

    pub fn set_state(&self, state: SubscriptionState) {
        *self.state.write() = state;
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn is_subscribed(&self) -> bool {
        matches!(*self.state.read(), SubscriptionState::Subscribed)
    }

    pub fn note_event(&self) {
        *self.last_event_at.write() = SystemTime::now();
    }

    pub fn increment_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }

    pub fn ingest(&self, tx: PendingTx) {
        self.recent.write().push(tx.clone());
        self.index.insert(tx.clone());
        let _ = self.live_tx.send(tx);
        self.note_event();
    }

    fn status(&self) -> MempoolStatus {
        let subscribed = matches!(*self.state.read(), SubscriptionState::Subscribed);
        MempoolStatus {
            provider: self.provider_id.clone(),
            subscribed,
            observed_pending: self.index.len() as u64,
            uptime_sec: self.started_at.elapsed().map(|d| d.as_secs()).unwrap_or(0),
            dropped_count: self.dropped.load(Ordering::Relaxed),
            evictions_total: self.index.evictions_total(),
            stale_for_secs: self
                .last_event_at
                .read()
                .elapsed()
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

impl bloom_mempool::stream::MempoolSink for MempoolHandler {
    fn ingest(&self, tx: PendingTx) {
        MempoolHandler::ingest(self, tx);
    }

    fn set_subscribed(&self) {
        self.set_state(SubscriptionState::Subscribed);
    }

    fn set_disconnected(&self) {
        self.set_state(SubscriptionState::Disconnected);
    }

    fn increment_dropped(&self, n: u64) {
        MempoolHandler::increment_dropped(self, n);
    }
}

#[async_trait]
impl Handler for MempoolHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        let strs: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
        match strs.as_slice() {
            [chain] => Ok(Entry::dir(chain)),
            [_chain, "mempool"] => Ok(Entry::dir("mempool")),
            [_chain, "mempool", "status.json"] => Ok(Entry::read_only_file("status.json")),
            [_chain, "mempool", "recent.jsonl"] => Ok(Entry::read_only_file("recent.jsonl")),
            [_chain, "mempool", "live"] => Ok(Entry::read_only_file("live")),
            [_chain, "mempool", "by_address"] => Ok(Entry::dir("by_address")),
            [_chain, "mempool", "by_address", addr] => {
                // Validate the address segment is a real address before claiming the dir exists.
                let _: alloy::primitives::Address = addr
                    .parse()
                    .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
                Ok(Entry::dir(addr))
            }
            [_chain, "mempool", "by_address", addr, "pending.jsonl"] => {
                let _: alloy::primitives::Address = addr
                    .parse()
                    .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
                Ok(Entry::read_only_file("pending.jsonl"))
            }
            [_chain, "mempool", "by_address", addr, "nonces.json"] => {
                let _: alloy::primitives::Address = addr
                    .parse()
                    .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
                Ok(Entry::read_only_file("nonces.json"))
            }
            [_chain, "mempool", "by_pool"] => Ok(Entry::dir("by_pool")),
            [_chain, "mempool", "by_pool", pool] => {
                let _: alloy::primitives::Address = pool
                    .parse()
                    .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
                Ok(Entry::dir(pool))
            }
            [_chain, "mempool", "by_pool", pool, "recent.jsonl"] => {
                let _: alloy::primitives::Address = pool
                    .parse()
                    .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
                Ok(Entry::read_only_file("recent.jsonl"))
            }
            [_chain, "mempool", hash] if is_hash_segment(hash) => {
                let parsed_hash = parse_hash(hash)?;
                if self.index.lookup_by_hash(&parsed_hash).is_none() {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                Ok(Entry::dir(hash))
            }
            [_chain, "mempool", hash, leaf]
                if is_hash_segment(hash)
                    && matches!(*leaf, "tx.json" | "decoded.json" | "status") =>
            {
                let parsed_hash = parse_hash(hash)?;
                if self.index.lookup_by_hash(&parsed_hash).is_none() {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                Ok(Entry::read_only_file(leaf))
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        let strs: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
        match strs.as_slice() {
            [_chain, "mempool"] => Ok(vec![
                Entry::read_only_file("status.json"),
                Entry::read_only_file("recent.jsonl"),
                Entry::read_only_file("live"),
                Entry::dir("by_address"),
                Entry::dir("by_pool"),
            ]),
            [_chain, "mempool", hash] if is_hash_segment(hash) => {
                let parsed_hash = parse_hash(hash)?;
                if self.index.lookup_by_hash(&parsed_hash).is_none() {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                Ok(vec![
                    Entry::read_only_file("tx.json"),
                    Entry::read_only_file("decoded.json"),
                    Entry::read_only_file("status"),
                ])
            }
            [_chain, "mempool", "by_address", _addr] => Ok(vec![
                Entry::read_only_file("pending.jsonl"),
                Entry::read_only_file("nonces.json"),
            ]),
            [_chain, "mempool", "by_pool", _pool] => {
                Ok(vec![Entry::read_only_file("recent.jsonl")])
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        let strs: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
        match strs.as_slice() {
            [_chain, "mempool", "status.json"] => {
                let s = self.status();
                serde_json::to_vec_pretty(&s).map_err(|e| HandlerError::backend(e.to_string()))
            }
            [_chain, "mempool", "recent.jsonl"] => {
                let items = self.recent.read().snapshot();
                let mut out = Vec::new();
                for it in &items {
                    serde_json::to_writer(&mut out, it)
                        .map_err(|e| HandlerError::backend(e.to_string()))?;
                    out.push(b'\n');
                }
                Ok(out)
            }
            [_chain, "mempool", "by_address", addr, "pending.jsonl"] => {
                let addr: alloy::primitives::Address = addr
                    .parse()
                    .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
                let items = self.index.snapshot();
                let mut out = Vec::new();
                for it in items
                    .iter()
                    .filter(|t| t.from == addr || t.to == Some(addr))
                {
                    serde_json::to_writer(&mut out, it)
                        .map_err(|e| HandlerError::backend(e.to_string()))?;
                    out.push(b'\n');
                }
                Ok(out)
            }
            [_chain, "mempool", "by_address", addr, "nonces.json"] => {
                let addr: alloy::primitives::Address = addr
                    .parse()
                    .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
                let observed = self.index.observed_nonces(addr);
                let next_unused = observed.last().map(|n| n.saturating_add(1)).unwrap_or(0);
                let body = serde_json::json!({
                    "observed": observed,
                    "next_unused": next_unused,
                });
                serde_json::to_vec_pretty(&body).map_err(|e| HandlerError::backend(e.to_string()))
            }
            [_chain, "mempool", "by_pool", pool, "recent.jsonl"] => {
                let pool: alloy::primitives::Address = pool
                    .parse()
                    .map_err(|e: alloy::hex::FromHexError| HandlerError::invalid(e.to_string()))?;
                let items = self.recent.read().snapshot();
                let mut out = Vec::new();
                for it in &items {
                    let to_match = it.to == Some(pool);
                    let path_match = bloom_mempool::decode_swap_path(&it.input)
                        .map(|p| p.contains(&pool))
                        .unwrap_or(false);
                    if to_match || path_match {
                        serde_json::to_writer(&mut out, it)
                            .map_err(|e| HandlerError::backend(e.to_string()))?;
                        out.push(b'\n');
                    }
                }
                Ok(out)
            }
            [_chain, "mempool", "live"] => {
                let mut rx = self.live_tx.subscribe();
                let mut out = Vec::new();
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
                while let Some(remaining) =
                    deadline.checked_duration_since(tokio::time::Instant::now())
                {
                    let recv = tokio::time::timeout(remaining, rx.recv()).await;
                    match recv {
                        Ok(Ok(tx)) => {
                            serde_json::to_writer(&mut out, &tx)
                                .map_err(|e| HandlerError::backend(e.to_string()))?;
                            out.push(b'\n');
                            // Drain a 200ms burst window to coalesce.
                            let burst_end =
                                tokio::time::Instant::now() + std::time::Duration::from_millis(200);
                            while let Some(remaining) =
                                burst_end.checked_duration_since(tokio::time::Instant::now())
                            {
                                match tokio::time::timeout(remaining, rx.recv()).await {
                                    Ok(Ok(more)) => {
                                        serde_json::to_writer(&mut out, &more)
                                            .map_err(|e| HandlerError::backend(e.to_string()))?;
                                        out.push(b'\n');
                                    }
                                    _ => break,
                                }
                            }
                            break;
                        }
                        Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                            self.increment_dropped(n);
                            let lagged = serde_json::json!({"kind": "lagged", "skipped": n});
                            serde_json::to_writer(&mut out, &lagged)
                                .map_err(|e| HandlerError::backend(e.to_string()))?;
                            out.push(b'\n');
                        }
                        Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                        Err(_) => break,
                    }
                }
                Ok(out)
            }
            [_chain, "mempool", hash, leaf] if is_hash_segment(hash) => {
                let h_bytes = parse_hash(hash)?;
                let rec = self
                    .index
                    .lookup_by_hash(&h_bytes)
                    .ok_or_else(|| HandlerError::not_found(path.to_string_path()))?;
                match *leaf {
                    "tx.json" => serde_json::to_vec_pretty(&rec.tx)
                        .map_err(|e| HandlerError::backend(e.to_string())),
                    "decoded.json" => {
                        let decoded = bloom_mempool::decode_swap_path(&rec.tx.input)
                            .map(|p| serde_json::json!({"kind": "swap", "path": p}))
                            .unwrap_or(serde_json::Value::Null);
                        serde_json::to_vec_pretty(&decoded)
                            .map_err(|e| HandlerError::backend(e.to_string()))
                    }
                    "status" => Ok(b"pending\n".to_vec()),
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn write(&self, _path: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
        Err(HandlerError::invalid("mempool is read-only"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handler() -> MempoolHandler {
        // PendingTxIndex::new already returns Arc<PendingTxIndex>.
        MempoolHandler::new("ethereum", "mock", PendingTxIndex::new(64))
    }

    #[tokio::test]
    async fn status_json_returns_disconnected_by_default() {
        let h = make_handler();
        let p = VfsPath::parse("ethereum/mempool/status.json").unwrap();
        let body = h.read(&p).await.unwrap();
        let s: MempoolStatus = serde_json::from_slice(&body).unwrap();
        assert_eq!(s.provider, "mock");
        assert!(!s.subscribed);
        assert_eq!(s.observed_pending, 0);
    }

    #[tokio::test]
    async fn status_json_reflects_subscribed_state() {
        let h = make_handler();
        h.set_state(SubscriptionState::Subscribed);
        let p = VfsPath::parse("ethereum/mempool/status.json").unwrap();
        let body = h.read(&p).await.unwrap();
        let s: MempoolStatus = serde_json::from_slice(&body).unwrap();
        assert!(s.subscribed);
    }

    use alloy::primitives::{Address, B256, Bytes, U256};
    use bloom_mempool::TxFees;

    fn fixture_tx(hash_byte: u8) -> PendingTx {
        let mut h = [0u8; 32];
        h[0] = hash_byte;
        PendingTx {
            hash: B256::from(h),
            from: Address::ZERO,
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: std::time::SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn live_tail_emits_ingested_items() {
        let h = Arc::new(make_handler());
        let h2 = Arc::clone(&h);
        let reader = tokio::spawn(async move {
            let p = VfsPath::parse("ethereum/mempool/live").unwrap();
            h2.read(&p).await.unwrap()
        });
        // Give the reader a chance to subscribe before we publish.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        h.ingest(fixture_tx(7));
        let body = tokio::time::timeout(std::time::Duration::from_secs(5), reader)
            .await
            .expect("reader timeout")
            .expect("join");
        let lines: Vec<&[u8]> = body
            .split(|c| *c == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert!(!lines.is_empty());
        let first: PendingTx = serde_json::from_slice(lines[0]).unwrap();
        let mut expected = [0u8; 32];
        expected[0] = 7;
        assert_eq!(first.hash, B256::from(expected));
    }

    #[tokio::test]
    async fn recent_jsonl_returns_ingested_items_in_order() {
        let h = make_handler();
        h.ingest(fixture_tx(1));
        h.ingest(fixture_tx(2));
        let p = VfsPath::parse("ethereum/mempool/recent.jsonl").unwrap();
        let body = h.read(&p).await.unwrap();
        let lines: Vec<&[u8]> = body
            .split(|c| *c == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        let first: PendingTx = serde_json::from_slice(lines[0]).unwrap();
        let second: PendingTx = serde_json::from_slice(lines[1]).unwrap();
        assert_eq!(
            first.hash,
            B256::from({
                let mut a = [0u8; 32];
                a[0] = 1;
                a
            })
        );
        assert_eq!(
            second.hash,
            B256::from({
                let mut a = [0u8; 32];
                a[0] = 2;
                a
            })
        );
    }

    #[tokio::test]
    async fn by_address_pending_filters_by_from_or_to() {
        let h = make_handler();
        let mut from_a = [0u8; 20];
        from_a[0] = 1;
        let a = Address::from(from_a);
        let mut t1 = fixture_tx(1);
        t1.from = a;
        let mut t2 = fixture_tx(2);
        t2.to = Some(a);
        let mut t3 = fixture_tx(3); // unrelated
        let mut other = [0u8; 20];
        other[0] = 9;
        t3.from = Address::from(other);
        h.ingest(t1);
        h.ingest(t2);
        h.ingest(t3);
        let p =
            VfsPath::parse(&format!("ethereum/mempool/by_address/{a:?}/pending.jsonl")).unwrap();
        let body = h.read(&p).await.unwrap();
        let lines: Vec<&[u8]> = body
            .split(|c| *c == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn by_address_nonces_json_reports_observed_and_next_unused() {
        let h = make_handler();
        let mut a = [0u8; 20];
        a[0] = 1;
        let addr = Address::from(a);
        let mut t1 = fixture_tx(1);
        t1.from = addr;
        t1.nonce = 4;
        let mut t2 = fixture_tx(2);
        t2.from = addr;
        t2.nonce = 6;
        h.ingest(t1);
        h.ingest(t2);
        let p =
            VfsPath::parse(&format!("ethereum/mempool/by_address/{addr:?}/nonces.json")).unwrap();
        let body = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["next_unused"], 7);
        assert_eq!(v["observed"], serde_json::json!([4, 6]));
    }

    #[tokio::test]
    async fn by_pool_includes_txs_with_pool_in_swap_path() {
        let h = make_handler();
        let mut pool_bytes = [0u8; 20];
        pool_bytes[19] = 2; // matches the second address in uniswap_v2_swap.hex (0x00…02)
        let pool = Address::from(pool_bytes);
        let mut t = fixture_tx(1);
        t.input = Bytes::from(
            alloy::hex::decode(
                std::fs::read_to_string("../bloom-mempool/tests/fixtures/uniswap_v2_swap.hex")
                    .unwrap()
                    .trim(),
            )
            .unwrap(),
        );
        h.ingest(t);
        let p = VfsPath::parse(&format!("ethereum/mempool/by_pool/{pool:?}/recent.jsonl")).unwrap();
        let body = h.read(&p).await.unwrap();
        let lines: Vec<&[u8]> = body
            .split(|c| *c == b'\n')
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(lines.len(), 1);
    }

    #[tokio::test]
    async fn tx_hash_subtree_returns_tx_json_and_status() {
        let h = make_handler();
        let t = fixture_tx(0xab);
        let hash = t.hash;
        h.ingest(t.clone());
        let hex_hash = format!("0x{}", alloy::hex::encode(hash.as_slice()));
        let p_tx = VfsPath::parse(&format!("ethereum/mempool/{hex_hash}/tx.json")).unwrap();
        let p_st = VfsPath::parse(&format!("ethereum/mempool/{hex_hash}/status")).unwrap();
        let body_tx = h.read(&p_tx).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_tx).unwrap();
        assert_eq!(v["nonce"], 0);
        let body_st = h.read(&p_st).await.unwrap();
        assert_eq!(String::from_utf8(body_st).unwrap().trim(), "pending");
    }

    #[tokio::test]
    async fn tx_hash_subtree_not_found_for_unknown_hash() {
        let h = make_handler();
        let p = VfsPath::parse(
            "ethereum/mempool/0x0000000000000000000000000000000000000000000000000000000000000000/tx.json",
        )
        .unwrap();
        let err = h.read(&p).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)));
    }

    #[tokio::test]
    async fn tx_hash_subtree_decoded_json_returns_null_for_unknown_calldata() {
        let h = make_handler();
        let t = fixture_tx(0xcd); // input is Bytes::new(), not a known swap selector
        let hash = t.hash;
        h.ingest(t);
        let hex_hash = format!("0x{}", alloy::hex::encode(hash.as_slice()));
        let p = VfsPath::parse(&format!("ethereum/mempool/{hex_hash}/decoded.json")).unwrap();
        let body = h.read(&p).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            v.is_null(),
            "expected JSON null for non-DEX calldata, got: {v}"
        );
    }
}
