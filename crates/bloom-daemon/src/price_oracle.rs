//! Adapter that lets the policy USD-cap path consult [`PricesClient`].
//!
//! Lives here (rather than in bloom-tx) because the prices crate pulls
//! reqwest+rustls and we don't want that on tx-engine consumers that
//! only care about staging.

use alloy::primitives::U256;
use async_trait::async_trait;
use bloom_prices::{CoinId, PricesClient};
use bloom_tx::oracle::PriceOracle;

/// Maps a chain's native symbol to a CoinId via the chain name when
/// possible, falling back to the bare symbol. Most ETH-style L2s already
/// resolve to ethereum's coingecko slug inside [`bloom_prices`].
pub struct PricesOracle {
    client: PricesClient,
}

impl PricesOracle {
    pub fn new(client: PricesClient) -> Self {
        Self { client }
    }

    fn coin_for_chain(chain_name: &str) -> CoinId {
        let s = chain_name.trim().to_ascii_lowercase();
        match s.as_str() {
            "ethereum" | "mainnet" | "optimism" | "arbitrum" | "base" | "anvil" | "local" => {
                CoinId::Native("ethereum".into())
            }
            "polygon" | "matic" => CoinId::Native("polygon".into()),
            other => CoinId::Native(other.to_string()),
        }
    }

    fn wei_to_units(value_wei: U256, native_decimals: u8) -> Option<f64> {
        let scale = 10f64.powi(native_decimals as i32);
        let v: f64 = format!("{}", value_wei).parse().ok()?;
        Some(v / scale)
    }
}

#[async_trait]
impl PriceOracle for PricesOracle {
    async fn native_usd(
        &self,
        chain_name: &str,
        value_wei: U256,
        native_decimals: u8,
    ) -> Option<f64> {
        let coin = Self::coin_for_chain(chain_name);
        let units = Self::wei_to_units(value_wei, native_decimals)?;
        match self.client.current(coin).await {
            Ok(q) => Some(units * q.price),
            Err(e) => {
                tracing::warn!(error=%e, chain=chain_name, "prices.oracle.lookup_failed");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wei_scaling_round_trip() {
        let one_eth = U256::from(1u64) * U256::from(10u64).pow(U256::from(18u64));
        let u = PricesOracle::wei_to_units(one_eth, 18).unwrap();
        assert!((u - 1.0).abs() < 1e-9);
    }

    #[test]
    fn coin_for_known_l2_resolves_to_ethereum() {
        match PricesOracle::coin_for_chain("base") {
            CoinId::Native(s) => assert_eq!(s, "ethereum"),
            _ => panic!("expected Native"),
        }
        match PricesOracle::coin_for_chain("polygon") {
            CoinId::Native(s) => assert_eq!(s, "polygon"),
            _ => panic!("expected Native"),
        }
    }
}
