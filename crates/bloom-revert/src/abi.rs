//! ABI source abstraction.
//!
//! [`AbiSource`] is the trait the [`super::EtherscanAbiDecoder`] talks to.
//! Pulling the network-bound part behind a trait keeps the decoder
//! testable: unit tests supply a `StubAbiSource` and never touch the
//! Etherscan client. The production wiring is [`EtherscanAbiSource`].

use std::sync::Arc;

use alloy::json_abi::JsonAbi;
use alloy::primitives::Address;
use async_trait::async_trait;
use bloom_etherscan::EtherscanClient;

/// Look up the JSON ABI for a contract.
#[async_trait]
pub trait AbiSource: Send + Sync {
    /// Resolve `addr` on `chain_id` to its `JsonAbi`. Implementations
    /// transparently follow proxy delegation (EIP-1967 etc.) and return
    /// `Ok(None)` when no ABI is available (unverified contract, source
    /// disabled for this chain, etc.).
    async fn abi_for(&self, chain_id: u64, addr: Address) -> Option<JsonAbi>;
}

/// Production [`AbiSource`] backed by `bloom-etherscan`. Delegates to the
/// new `json_abi_for` helper which handles proxy resolution and caching.
#[derive(Clone)]
pub struct EtherscanAbiSource {
    client: Arc<EtherscanClient>,
}

impl EtherscanAbiSource {
    pub fn new(client: Arc<EtherscanClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AbiSource for EtherscanAbiSource {
    async fn abi_for(&self, chain_id: u64, addr: Address) -> Option<JsonAbi> {
        match self.client.json_abi_for(chain_id, addr).await {
            Ok(Some(abi)) => {
                tracing::debug!(
                    %addr,
                    chain_id,
                    errors = abi.errors().count(),
                    "abi_for.fetched"
                );
                Some(abi)
            }
            Ok(None) => {
                tracing::debug!(%addr, chain_id, "abi_for.unavailable");
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, %addr, chain_id, "abi_for.fetch_failed");
                None
            }
        }
    }
}
