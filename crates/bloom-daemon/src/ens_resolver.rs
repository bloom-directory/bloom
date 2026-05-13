//! Adapter wiring `bloom_ens::EnsClient` into the `RecipientResolver` trait
//! that `bloom_tx::TxEngine` consumes. Lives in the daemon crate (not bloom-tx)
//! to avoid pulling bloom-ens into bloom-tx and creating a dep cycle.

use alloy::primitives::Address;
use async_trait::async_trait;
use bloom_ens::EnsClient;
use bloom_tx::tx_engine::RecipientResolver;

pub struct EnsAdapter {
    client: EnsClient,
}

impl EnsAdapter {
    pub fn new(client: EnsClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl RecipientResolver for EnsAdapter {
    async fn resolve_name(&self, name: &str) -> Result<Address, String> {
        self.client.resolve(name).await.map_err(|e| e.to_string())
    }
}
