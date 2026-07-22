//! USD price oracle abstraction used by the policy USD-cap path.
//!
//! Lives in bloom-tx so the engine doesn't have to depend on the prices
//! crate (which pulls reqwest/rustls). Daemons wire a concrete
//! implementation in via [`crate::tx_engine::TxEngine::with_price_oracle`].

use std::sync::Arc;

pub use bloom_auth_api::{AuthApiError, PriceOracle, ValuationQuote};

/// Type alias to keep call sites short.
pub type DynPriceOracle = Arc<dyn PriceOracle>;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// A deterministic in-test oracle: always returns the configured
    /// price-per-unit. Exposed so unit tests in this crate
    /// (and downstream consumers) can plug it in without bringing up
    /// HTTP fixtures.
    pub struct FakeOracle {
        pub price_per_unit: f64,
    }

    #[async_trait]
    impl PriceOracle for FakeOracle {
        async fn quote_usd(
            &self,
            asset_id: &str,
            amount_base_units: &str,
            asset_decimals: u8,
            now_ms: u64,
        ) -> Result<ValuationQuote, AuthApiError> {
            let amount = amount_base_units
                .parse::<f64>()
                .map_err(|e| AuthApiError::Denied(e.to_string()))?;
            let decimals = asset_decimals;
            Ok(ValuationQuote {
                asset_id: asset_id.into(),
                amount_base_units: amount_base_units.into(),
                usd_micro: (amount / 10f64.powi(decimals.into())
                    * self.price_per_unit
                    * 1_000_000.0)
                    .round() as i128,
                source: "test-oracle".into(),
                quote_timestamp_ms: now_ms,
                fetched_at_ms: now_ms,
                max_age_ms: 30_000,
                confidence_ppm: None,
                stablecoin_assumption: false,
            })
        }
    }

    #[tokio::test]
    async fn fake_oracle_scales_wei_to_usd() {
        let o = FakeOracle {
            price_per_unit: 2_500.0,
        };
        // 1 ETH at $2500 = $2500.
        let quote = o
            .quote_usd("native:ethereum", "1000000000000000000", 18, 1_000)
            .await
            .unwrap();
        assert_eq!(quote.usd_micro, 2_500_000_000);
    }
}
