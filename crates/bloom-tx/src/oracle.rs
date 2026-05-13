//! USD price oracle abstraction used by the policy USD-cap path.
//!
//! Lives in bloom-tx so the engine doesn't have to depend on the prices
//! crate (which pulls reqwest/rustls). Daemons wire a concrete
//! implementation in via [`crate::tx_engine::TxEngine::with_price_oracle`].

use std::sync::Arc;

use alloy::primitives::U256;
use async_trait::async_trait;

/// Convert native-asset wei into USD.
///
/// `chain_name` lets implementations distinguish "ETH on mainnet" from
/// "ETH on Base" if their backing API treats them differently. `value_wei`
/// is the raw on-chain value of the staged tx; `native_decimals` is the
/// chain's native-asset decimal count (always 18 for ETH-style chains
/// today, but kept explicit so non-ETH chains slot in cleanly).
///
/// Implementations should return `None` when the oracle is unavailable
/// or doesn't recognise the chain — the caller treats that as "no USD
/// data, surface a Warn check" rather than a failure.
#[async_trait]
pub trait PriceOracle: Send + Sync {
    async fn native_usd(
        &self,
        chain_name: &str,
        value_wei: U256,
        native_decimals: u8,
    ) -> Option<f64>;
}

/// Type alias to keep call sites short.
pub type DynPriceOracle = Arc<dyn PriceOracle>;

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic in-test oracle: always returns the configured
    /// price-per-native-unit. Exposed so unit tests in this crate
    /// (and downstream consumers) can plug it in without bringing up
    /// HTTP fixtures.
    pub struct FakeOracle {
        pub price_per_unit: f64,
    }

    #[async_trait]
    impl PriceOracle for FakeOracle {
        async fn native_usd(
            &self,
            _chain_name: &str,
            value_wei: U256,
            native_decimals: u8,
        ) -> Option<f64> {
            let scale = 10f64.powi(native_decimals as i32);
            // Lossy but bounded: we only need ~6 sig figs for USD caps.
            let units: f64 = format!("{}", value_wei).parse::<f64>().ok()? / scale;
            Some(units * self.price_per_unit)
        }
    }

    #[tokio::test]
    async fn fake_oracle_scales_wei_to_usd() {
        let o = FakeOracle {
            price_per_unit: 2_500.0,
        };
        // 1 ETH at $2500 = $2500.
        let one_eth = U256::from(1u64) * U256::from(10u64).pow(U256::from(18u64));
        let usd = o.native_usd("ethereum", one_eth, 18).await.unwrap();
        assert!((usd - 2_500.0).abs() < 0.001);
    }
}
