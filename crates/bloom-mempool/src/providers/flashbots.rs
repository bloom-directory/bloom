//! Flashbots Protect private orderflow adapter.
//!
//! Speaks `eth_sendRawTransaction` over JSON-RPC against
//! `https://rpc.flashbots.net/fast` (or a configured URL). No auth.

use alloy::primitives::{B256, Bytes};
use async_trait::async_trait;

use super::json_rpc;
use crate::private::{
    HealthStatus, MAINNET_CHAIN_ID, PrivateRpcError, PrivateRpcProvider, SEPOLIA_CHAIN_ID,
};

pub const DEFAULT_URL: &str = "https://rpc.flashbots.net/fast";
pub const SEPOLIA_URL: &str = "https://relay-sepolia.flashbots.net";

pub struct FlashbotsProvider {
    url: String,
    http: reqwest::Client,
}

impl FlashbotsProvider {
    pub fn new(url: impl Into<String>) -> Result<Self, PrivateRpcError> {
        Ok(Self {
            url: url.into(),
            http: json_rpc::http_client()?,
        })
    }

    pub fn default_endpoint() -> Result<Self, PrivateRpcError> {
        Self::new(DEFAULT_URL)
    }
}

#[async_trait]
impl PrivateRpcProvider for FlashbotsProvider {
    fn id(&self) -> &'static str {
        "flashbots"
    }

    fn supported_chains(&self) -> &'static [u64] {
        &[MAINNET_CHAIN_ID, SEPOLIA_CHAIN_ID]
    }

    async fn submit(&self, signed_raw_tx: &Bytes) -> Result<B256, PrivateRpcError> {
        json_rpc::send_raw_transaction(&self.http, &self.url, signed_raw_tx).await
    }

    async fn health(&self) -> Result<HealthStatus, PrivateRpcError> {
        json_rpc::health(&self.http, &self.url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_supported_chains() {
        let p = FlashbotsProvider::default_endpoint().unwrap();
        assert_eq!(p.id(), "flashbots");
        assert_eq!(p.supported_chains(), &[MAINNET_CHAIN_ID, SEPOLIA_CHAIN_ID]);
    }

    #[cfg(feature = "live-providers")]
    #[tokio::test]
    async fn health_against_live_endpoint() {
        if std::env::var_os("BLOOM_RUN_LIVE_TESTS").is_none() {
            eprintln!("skip: BLOOM_RUN_LIVE_TESTS is not set");
            return;
        }
        let p = FlashbotsProvider::default_endpoint().unwrap();
        let status = p.health().await.expect("health probe");
        assert_eq!(status, HealthStatus::Healthy);
    }
}
