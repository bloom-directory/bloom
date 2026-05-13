//! Core domain types for mempool observability: [`TxFees`] and [`PendingTx`].
//!
//! The `MempoolProvider` trait and implementations arrive in Tasks 1.4–1.5.

use alloy::primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Fees normalised across legacy (gasPrice) and EIP-1559
/// (maxFeePerGas / maxPriorityFeePerGas) txs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TxFees {
    Legacy {
        #[serde(with = "u128_as_str")]
        gas_price: u128,
    },
    Eip1559 {
        #[serde(with = "u128_as_str")]
        max_fee_per_gas: u128,
        #[serde(with = "u128_as_str")]
        max_priority_fee_per_gas: u128,
    },
}

impl TxFees {
    /// The fee the user has authorised the protocol to charge per gas.
    pub fn max_fee_per_gas(&self) -> u128 {
        match self {
            Self::Legacy { gas_price } => *gas_price,
            Self::Eip1559 {
                max_fee_per_gas, ..
            } => *max_fee_per_gas,
        }
    }

    /// Tip to the builder/miner.
    pub fn max_priority_fee_per_gas(&self) -> u128 {
        match self {
            Self::Legacy { gas_price } => *gas_price,
            Self::Eip1559 {
                max_priority_fee_per_gas,
                ..
            } => *max_priority_fee_per_gas,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTx {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub nonce: u64,
    pub value: U256,
    pub gas_limit: u64,
    pub fees: TxFees,
    pub input: Bytes,
    #[serde(with = "system_time_secs")]
    pub observed_at: SystemTime,
}

// serde_json supports u128 directly, but serde's internally-tagged
// enum (#[serde(tag = "kind")]) routes through a `Content` deserializer
// that doesn't implement `deserialize_u128`, so we string-encode here.
mod u128_as_str {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

mod system_time_secs {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        let secs = t
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        secs.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

use async_trait::async_trait;
use futures::stream::{self, BoxStream};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("websocket transport error: {0}")]
    Transport(String),
    #[error("provider returned malformed data: {0}")]
    Decode(String),
    #[error("provider not configured")]
    NotConfigured,
}

#[async_trait]
pub trait MempoolProvider: Send + Sync {
    fn id(&self) -> &'static str;

    /// Open a long-lived subscription. The returned stream lives until
    /// the caller drops it; the provider is responsible for cleanup.
    async fn subscribe(&self) -> Result<BoxStream<'static, PendingTx>, MempoolError>;

    /// True = stream already includes full tx fields; False = the
    /// stream yields hash-only `PendingTx`s with `input.is_empty()`
    /// and the daemon must follow up via `eth_getTransactionByHash`
    /// before storing in the index.
    fn delivers_bodies(&self) -> bool;
}

/// Conformance test suite. Any `MempoolProvider` implementation
/// should be exercised via `provider_test_suite!(MyProvider, build_fn, suite_mod_name)`
/// where `build_fn` is a `fn() -> MyProvider` and `suite_mod_name` is a unique
/// identifier for the generated test module.
///
/// Note: the `${ty}` metavariable expression form (macro_metavar_expr) is not yet
/// stable in Rust 1.91; the explicit `$mod_name:ident` fallback is used instead.
///
/// The suite runs two checks:
///   1. `id()` is non-empty.
///   2. `subscribe()` returns a stream that yields at least 1 item
///      when the upstream produces items.
#[macro_export]
macro_rules! provider_test_suite {
    ($t:ty, $build:expr, $mod_name:ident) => {
        #[allow(non_snake_case)]
        mod $mod_name {
            #[tokio::test]
            async fn id_is_non_empty() {
                let p: $t = $build();
                assert!(!<$t as $crate::provider::MempoolProvider>::id(&p).is_empty());
            }

            #[tokio::test]
            async fn subscribe_yields_when_upstream_has_items() {
                use futures::StreamExt;
                let p: $t = $build();
                let mut s = <$t as $crate::provider::MempoolProvider>::subscribe(&p)
                    .await
                    .unwrap();
                let first = tokio::time::timeout(std::time::Duration::from_secs(2), s.next())
                    .await
                    .expect("provider must yield first item within 2s")
                    .expect("stream ended before yielding any item");
                assert_ne!(first.hash, alloy::primitives::B256::ZERO);
            }
        }
    };
}

/// In-memory mock that yields a fixed sequence of `PendingTx`s. Used
/// by integration tests in this crate and by `bloom-vfs` / `bloom-tx`
/// integration suites.
pub struct MockMempoolProvider {
    id: &'static str,
    fixtures: Vec<PendingTx>,
    delivers_bodies: bool,
}

impl MockMempoolProvider {
    pub fn new(id: &'static str, fixtures: Vec<PendingTx>) -> Self {
        Self {
            id,
            fixtures,
            delivers_bodies: true,
        }
    }

    pub fn with_hashes_only(mut self) -> Self {
        self.delivers_bodies = false;
        self
    }
}

#[async_trait]
impl MempoolProvider for MockMempoolProvider {
    fn id(&self) -> &'static str {
        self.id
    }

    async fn subscribe(&self) -> Result<BoxStream<'static, PendingTx>, MempoolError> {
        let items = self.fixtures.clone();
        Ok(Box::pin(stream::iter(items)))
    }

    fn delivers_bodies(&self) -> bool {
        self.delivers_bodies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_fees_legacy_normalises_to_same_value() {
        let f = TxFees::Legacy { gas_price: 5 };
        assert_eq!(f.max_fee_per_gas(), 5);
        assert_eq!(f.max_priority_fee_per_gas(), 5);
    }

    #[test]
    fn tx_fees_eip1559_returns_distinct_fields() {
        let f = TxFees::Eip1559 {
            max_fee_per_gas: 50,
            max_priority_fee_per_gas: 2,
        };
        assert_eq!(f.max_fee_per_gas(), 50);
        assert_eq!(f.max_priority_fee_per_gas(), 2);
    }

    #[test]
    fn pending_tx_round_trips_through_json() {
        let tx = PendingTx {
            hash: B256::ZERO,
            from: Address::ZERO,
            to: None,
            nonce: 7,
            value: U256::from(10u64),
            gas_limit: 21_000,
            fees: TxFees::Eip1559 {
                max_fee_per_gas: 50,
                max_priority_fee_per_gas: 2,
            },
            input: Bytes::new(),
            observed_at: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        };
        let s = serde_json::to_string(&tx).unwrap();
        let back: PendingTx = serde_json::from_str(&s).unwrap();
        assert_eq!(back.nonce, 7);
        assert_eq!(back.gas_limit, 21_000);
        assert_eq!(back.fees, tx.fees);
    }

    #[test]
    fn tx_fees_legacy_round_trips_through_json_at_u128_max() {
        let f = TxFees::Legacy {
            gas_price: u128::MAX,
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: TxFees = serde_json::from_str(&s).unwrap();
        assert_eq!(back, f);
    }

    fn one_fixture() -> Vec<PendingTx> {
        vec![PendingTx {
            hash: B256::from([1u8; 32]),
            from: Address::from([2u8; 20]),
            to: None,
            nonce: 0,
            value: U256::ZERO,
            gas_limit: 21_000,
            fees: TxFees::Legacy { gas_price: 1 },
            input: Bytes::new(),
            observed_at: SystemTime::now(),
        }]
    }

    #[tokio::test]
    async fn mock_yields_fixture_items() {
        use futures::StreamExt;
        let p = MockMempoolProvider::new("mock", one_fixture());
        let mut s = p.subscribe().await.unwrap();
        let first = s.next().await.unwrap();
        assert_eq!(first.hash, B256::from([1u8; 32]));
    }

    fn build_mock() -> crate::provider::MockMempoolProvider {
        crate::provider::MockMempoolProvider::new("mock", one_fixture())
    }

    crate::provider_test_suite!(
        crate::provider::MockMempoolProvider,
        super::build_mock,
        mock_provider_conformance
    );
}
