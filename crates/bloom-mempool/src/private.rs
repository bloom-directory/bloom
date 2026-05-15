//! Private orderflow — pluggable provider trait + mock for tests.
//! See Phase 4 for real adapters (MEV-Blocker, Flashbots Protect).

use alloy::primitives::{B256, Bytes, keccak256};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;
use thiserror::Error;

pub const MAINNET_CHAIN_ID: u64 = 1;
pub const SEPOLIA_CHAIN_ID: u64 = 11155111;

#[derive(Debug, Error)]
pub enum PrivateRpcError {
    #[error("http transport error: {0}")]
    Transport(String),
    #[error("provider returned an error: {0}")]
    ProviderError(String),
    #[error("provider does not support chain id {0}")]
    UnsupportedChain(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[async_trait]
pub trait PrivateRpcProvider: Send + Sync {
    fn id(&self) -> &'static str;

    /// The chain ids this provider can serve.
    fn supported_chains(&self) -> &'static [u64];

    /// Submit a signed raw tx privately. MUST return the tx hash on
    /// success. MUST NOT silently fall back to the public mempool.
    async fn submit(&self, signed_raw_tx: &Bytes) -> Result<B256, PrivateRpcError>;

    /// Cheap probe (e.g. `eth_blockNumber`) for status surface and
    /// daemon health.
    async fn health(&self) -> Result<HealthStatus, PrivateRpcError>;
}

/// Captures all submitted raw txs in memory. Used by `bloom-tx`
/// integration tests to assert that the broadcast routes correctly
/// when a wallet has `private.enabled = true`.
pub struct MockPrivateRpcProvider {
    id: &'static str,
    supported: &'static [u64],
    submissions: Arc<Mutex<Vec<Bytes>>>,
    health: HealthStatus,
}

impl MockPrivateRpcProvider {
    pub fn new(id: &'static str) -> Self {
        Self {
            id,
            supported: &[MAINNET_CHAIN_ID],
            submissions: Arc::new(Mutex::new(Vec::new())),
            health: HealthStatus::Healthy,
        }
    }

    pub fn with_supported_chains(mut self, ids: &'static [u64]) -> Self {
        self.supported = ids;
        self
    }

    pub fn with_health(mut self, h: HealthStatus) -> Self {
        self.health = h;
        self
    }

    pub fn submissions(&self) -> Vec<Bytes> {
        self.submissions.lock().clone()
    }
}

#[async_trait]
impl PrivateRpcProvider for MockPrivateRpcProvider {
    fn id(&self) -> &'static str {
        self.id
    }

    fn supported_chains(&self) -> &'static [u64] {
        self.supported
    }

    async fn submit(&self, signed_raw_tx: &Bytes) -> Result<B256, PrivateRpcError> {
        self.submissions.lock().push(signed_raw_tx.clone());
        Ok(keccak256(signed_raw_tx))
    }

    async fn health(&self) -> Result<HealthStatus, PrivateRpcError> {
        Ok(self.health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_chain_id_is_one() {
        assert_eq!(MAINNET_CHAIN_ID, 1);
    }

    #[test]
    fn sepolia_chain_id_matches_public_chain_id() {
        assert_eq!(SEPOLIA_CHAIN_ID, 11155111);
    }

    #[tokio::test]
    async fn mock_records_submissions_and_returns_keccak_hash() {
        let p = MockPrivateRpcProvider::new("mock");
        let raw = Bytes::from_static(b"\x01\x02\x03");
        let h = p.submit(&raw).await.unwrap();
        assert_eq!(h, keccak256(&raw));
        assert_eq!(p.submissions().len(), 1);
    }

    #[tokio::test]
    async fn mock_default_supports_mainnet_only() {
        let p = MockPrivateRpcProvider::new("mock");
        assert_eq!(p.supported_chains(), &[MAINNET_CHAIN_ID]);
    }
}
