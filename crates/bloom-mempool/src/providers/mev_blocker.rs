//! MEV-Blocker private orderflow adapter.
//!
//! Speaks `eth_sendRawTransaction` over JSON-RPC against
//! `https://rpc.mevblocker.io` (or a configured URL). No auth.

use alloy::primitives::{B256, Bytes};
use async_trait::async_trait;

use super::json_rpc;
use crate::private::{HealthStatus, MAINNET_CHAIN_ID, PrivateRpcError, PrivateRpcProvider};

pub const DEFAULT_URL: &str = "https://rpc.mevblocker.io";

pub struct MevBlockerProvider {
    url: String,
    http: reqwest::Client,
}

impl MevBlockerProvider {
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
impl PrivateRpcProvider for MevBlockerProvider {
    fn id(&self) -> &'static str {
        "mev_blocker"
    }

    fn supported_chains(&self) -> &'static [u64] {
        &[MAINNET_CHAIN_ID]
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
        let p = MevBlockerProvider::default_endpoint().unwrap();
        assert_eq!(p.id(), "mev_blocker");
        assert_eq!(p.supported_chains(), &[MAINNET_CHAIN_ID]);
    }
}
