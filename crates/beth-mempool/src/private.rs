//! Private orderflow — pluggable provider trait + mock for tests.
//! See Phase 4 for real adapters (MEV-Blocker, Flashbots Protect).

use alloy::primitives::{B256, Bytes};
use async_trait::async_trait;
use thiserror::Error;

pub const MAINNET_CHAIN_ID: u64 = 1;

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

    /// The chain ids this provider can serve. v1 implementations
    /// return `&[MAINNET_CHAIN_ID]`.
    fn supported_chains(&self) -> &'static [u64];

    /// Submit a signed raw tx privately. MUST return the tx hash on
    /// success. MUST NOT silently fall back to the public mempool.
    async fn submit(&self, signed_raw_tx: &Bytes) -> Result<B256, PrivateRpcError>;

    /// Cheap probe (e.g. `eth_blockNumber`) for status surface and
    /// daemon health.
    async fn health(&self) -> Result<HealthStatus, PrivateRpcError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_chain_id_is_one() {
        assert_eq!(MAINNET_CHAIN_ID, 1);
    }
}
