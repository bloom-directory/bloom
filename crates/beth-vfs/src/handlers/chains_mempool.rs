//! Handler for `chains/<chain>/mempool/...`. Backed by a
//! `PendingTxIndex` (populated by a `MempoolStream` in Phase 4 — wiring
//! lands in Task 4.6).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use beth_mempool::PendingTxIndex;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

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
        }
    }

    pub fn set_state(&self, state: SubscriptionState) {
        *self.state.write() = state;
    }

    pub fn note_event(&self) {
        *self.last_event_at.write() = SystemTime::now();
    }

    pub fn increment_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
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

#[async_trait]
impl Handler for MempoolHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        let strs: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
        match strs.as_slice() {
            [chain] => Ok(Entry::dir(chain)),
            [_chain, "mempool"] => Ok(Entry::dir("mempool")),
            [_chain, "mempool", "status.json"] => Ok(Entry::read_only_file("status.json")),
            [_chain, "mempool", "by_address"] => Ok(Entry::dir("by_address")),
            [_chain, "mempool", "by_pool"] => Ok(Entry::dir("by_pool")),
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        let strs: Vec<&str> = segs.iter().map(|s| s.as_str()).collect();
        match strs.as_slice() {
            [_chain, "mempool"] => Ok(vec![
                Entry::read_only_file("status.json"),
                Entry::dir("by_address"),
                Entry::dir("by_pool"),
            ]),
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
}
