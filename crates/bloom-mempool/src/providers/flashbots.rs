//! Flashbots Protect private orderflow adapter.
//!
//! Speaks `eth_sendRawTransaction` over JSON-RPC against
//! `https://rpc.flashbots.net/fast` (or a configured URL). No auth.

use alloy::primitives::{B256, Bytes};
use async_trait::async_trait;

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
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?;
        Ok(Self {
            url: url.into(),
            http,
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
        let raw_hex = format!("0x{}", hex::encode(signed_raw_tx.as_ref()));
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [raw_hex],
        });
        let resp: serde_json::Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?
            .json()
            .await
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?;
        if let Some(err) = resp.get("error") {
            return Err(PrivateRpcError::ProviderError(err.to_string()));
        }
        let hash_str = resp
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PrivateRpcError::ProviderError("missing result".into()))?;
        hash_str
            .parse()
            .map_err(|e| PrivateRpcError::ProviderError(format!("{e}")))
    }

    async fn health(&self) -> Result<HealthStatus, PrivateRpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": [],
        });
        let resp: serde_json::Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?
            .json()
            .await
            .map_err(|e| PrivateRpcError::Transport(e.to_string()))?;
        if resp.get("error").is_some() {
            Ok(HealthStatus::Unhealthy)
        } else if resp.get("result").is_some() {
            Ok(HealthStatus::Healthy)
        } else {
            Ok(HealthStatus::Degraded)
        }
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
    #[ignore = "hits live Flashbots Protect endpoint over the network"]
    async fn health_against_live_endpoint() {
        let p = FlashbotsProvider::default_endpoint().unwrap();
        let status = p.health().await.expect("health probe");
        assert_eq!(status, HealthStatus::Healthy);
    }
}
