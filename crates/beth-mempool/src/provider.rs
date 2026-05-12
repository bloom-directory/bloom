//! `MempoolProvider` trait + the `PendingTx` domain type.

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
    }
}
