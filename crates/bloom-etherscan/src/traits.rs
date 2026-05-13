//! Backend-neutral data-source traits used by the VFS handlers.
//!
//! The VFS only needs two narrow surfaces today:
//!
//! - [`ContractMetadataSource`] — verified source + ABI lookup.
//! - [`AddressHistorySource`] — paginated transaction / transfer feeds.
//!
//! Both keep the existing `bloom-etherscan` DTOs (`ContractSource`,
//! `TxRecord`, `TokenTransfer`) as their return types — neutral wire DTOs
//! are a future concern. Errors are mapped onto a backend-agnostic
//! [`DataSourceError`] so handler code never spells "etherscan".
//!
//! Lives in `bloom-etherscan` because:
//! - the crate already owns the response types and the `async-trait` dep,
//! - `bloom-vfs` already depends on `bloom-etherscan`,
//! - putting it in `bloom-proto` would force `bloom-proto` (a small,
//!   sync-only types crate) to take an `async-trait` + alloy dependency
//!   it doesn't otherwise need.
//!
//! A future local indexer can `impl ContractMetadataSource for IndexerClient`
//! (and likewise for history) without touching the VFS.

use async_trait::async_trait;
use thiserror::Error;

use bloom_proto::prelude::Address;

use crate::{ContractSource, EtherscanClient, EtherscanError, Sort, TokenTransfer, TxRecord};

/// Backend-neutral error returned by the data-source traits.
///
/// Variants are deliberately coarse: handler code only cares whether a
/// fault is retryable (`RateLimit`, `Transport`), structural (`NotFound`,
/// `Unsupported`), or "ask the operator" (`Backend`).
#[derive(Debug, Error)]
pub enum DataSourceError {
    /// The requested record does not exist (e.g. unverified contract).
    #[error("not found: {0}")]
    NotFound(String),
    /// The upstream rate-limited us. Caller may retry after a backoff.
    #[error("rate limited")]
    RateLimit,
    /// The endpoint isn't supported on this chain by the chosen backend.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Backend-side fault with a human description (auth, schema, etc.).
    #[error("backend: {0}")]
    Backend(String),
    /// Network / transport failure talking to the backend.
    #[error("transport: {0}")]
    Transport(String),
}

impl From<EtherscanError> for DataSourceError {
    fn from(e: EtherscanError) -> Self {
        match e {
            EtherscanError::Disabled => DataSourceError::Unsupported(
                "etherscan endpoint not supported on this chain".into(),
            ),
            EtherscanError::RateLimit => DataSourceError::RateLimit,
            EtherscanError::Api { status, message } => {
                let m = message.to_ascii_lowercase();
                if m.contains("not verified") || m.contains("not found") {
                    DataSourceError::NotFound(format!("{status}: {message}"))
                } else {
                    DataSourceError::Backend(format!("etherscan {status}: {message}"))
                }
            }
            EtherscanError::Http(e) => DataSourceError::Transport(e.to_string()),
            other => DataSourceError::Backend(other.to_string()),
        }
    }
}

/// Lookup of verified contract metadata (source + ABI) for one address.
#[async_trait]
pub trait ContractMetadataSource: Send + Sync {
    /// Verified source-code record for `addr` on `chain_id`.
    async fn get_source_code(
        &self,
        chain_id: u64,
        addr: Address,
    ) -> Result<ContractSource, DataSourceError>;

    /// Parsed ABI as returned by the backend (already JSON-decoded).
    async fn get_abi(
        &self,
        chain_id: u64,
        addr: Address,
    ) -> Result<serde_json::Value, DataSourceError>;
}

/// Paginated history feeds for an address: native txs, internal txs,
/// ERC-20 and ERC-721 transfers.
#[async_trait]
pub trait AddressHistorySource: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn get_tx_list(
        &self,
        chain_id: u64,
        addr: Address,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TxRecord>, DataSourceError>;

    #[allow(clippy::too_many_arguments)]
    async fn get_internal_tx_list(
        &self,
        chain_id: u64,
        addr: Address,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TxRecord>, DataSourceError>;

    #[allow(clippy::too_many_arguments)]
    async fn get_token_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, DataSourceError>;

    #[allow(clippy::too_many_arguments)]
    async fn get_nft_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, DataSourceError>;

    /// ERC-1155 transfer feed (`token1155tx`). Returns the same
    /// `TokenTransfer` shape as `get_nft_tx` with `token_id` and
    /// `token_value` populated for each row.
    #[allow(clippy::too_many_arguments)]
    async fn get_nft1155_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, DataSourceError>;
}

#[async_trait]
impl ContractMetadataSource for EtherscanClient {
    async fn get_source_code(
        &self,
        chain_id: u64,
        addr: Address,
    ) -> Result<ContractSource, DataSourceError> {
        EtherscanClient::get_source_code(self, chain_id, addr)
            .await
            .map_err(DataSourceError::from)
    }

    async fn get_abi(
        &self,
        chain_id: u64,
        addr: Address,
    ) -> Result<serde_json::Value, DataSourceError> {
        EtherscanClient::get_abi(self, chain_id, addr)
            .await
            .map_err(DataSourceError::from)
    }
}

#[async_trait]
impl AddressHistorySource for EtherscanClient {
    async fn get_tx_list(
        &self,
        chain_id: u64,
        addr: Address,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TxRecord>, DataSourceError> {
        EtherscanClient::get_tx_list(
            self,
            chain_id,
            addr,
            start_block,
            end_block,
            page,
            page_size,
            sort,
        )
        .await
        .map_err(DataSourceError::from)
    }

    async fn get_internal_tx_list(
        &self,
        chain_id: u64,
        addr: Address,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TxRecord>, DataSourceError> {
        EtherscanClient::get_internal_tx_list(
            self,
            chain_id,
            addr,
            start_block,
            end_block,
            page,
            page_size,
            sort,
        )
        .await
        .map_err(DataSourceError::from)
    }

    async fn get_token_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, DataSourceError> {
        EtherscanClient::get_token_tx(
            self,
            chain_id,
            addr,
            contract_addr_filter,
            start_block,
            end_block,
            page,
            page_size,
            sort,
        )
        .await
        .map_err(DataSourceError::from)
    }

    async fn get_nft_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, DataSourceError> {
        EtherscanClient::get_nft_tx(
            self,
            chain_id,
            addr,
            contract_addr_filter,
            start_block,
            end_block,
            page,
            page_size,
            sort,
        )
        .await
        .map_err(DataSourceError::from)
    }

    async fn get_nft1155_tx(
        &self,
        chain_id: u64,
        addr: Address,
        contract_addr_filter: Option<Address>,
        start_block: u64,
        end_block: u64,
        page: u32,
        page_size: u32,
        sort: Sort,
    ) -> Result<Vec<TokenTransfer>, DataSourceError> {
        EtherscanClient::get_nft1155_tx(
            self,
            chain_id,
            addr,
            contract_addr_filter,
            start_block,
            end_block,
            page,
            page_size,
            sort,
        )
        .await
        .map_err(DataSourceError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etherscan_disabled_maps_to_unsupported() {
        let e: DataSourceError = EtherscanError::Disabled.into();
        assert!(matches!(e, DataSourceError::Unsupported(_)));
    }

    #[test]
    fn etherscan_rate_limit_maps_to_rate_limit() {
        let e: DataSourceError = EtherscanError::RateLimit.into();
        assert!(matches!(e, DataSourceError::RateLimit));
    }

    #[test]
    fn etherscan_not_verified_maps_to_not_found() {
        let e: DataSourceError = EtherscanError::Api {
            status: "0".into(),
            message: "Contract source code not verified".into(),
        }
        .into();
        match e {
            DataSourceError::NotFound(s) => {
                assert!(s.to_ascii_lowercase().contains("not verified"))
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn etherscan_other_api_error_maps_to_backend() {
        let e: DataSourceError = EtherscanError::Api {
            status: "0".into(),
            message: "Invalid API Key".into(),
        }
        .into();
        match e {
            DataSourceError::Backend(s) => {
                assert!(s.contains("etherscan"));
                assert!(s.contains("Invalid API Key"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }
}
