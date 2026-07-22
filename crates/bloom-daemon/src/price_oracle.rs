//! Adapter that lets the policy USD-cap path consult [`PricesClient`].
//!
//! Lives here (rather than in bloom-tx) because the prices crate pulls
//! reqwest+rustls and we don't want that on tx-engine consumers that
//! only care about staging.

use alloy::primitives::U256;
use async_trait::async_trait;
use bloom_auth_api::{AuthApiError, PriceOracle, ValuationQuote};
use bloom_prices::{CoinId, PricesClient};

/// Maps a chain's native symbol to a CoinId via the chain name when
/// possible, falling back to the bare symbol. Most ETH-style L2s already
/// resolve to ethereum's coingecko slug inside [`bloom_prices`].
pub struct PricesOracle {
    client: PricesClient,
    source: String,
}

impl PricesOracle {
    pub fn new(client: PricesClient) -> Self {
        Self {
            client,
            source: "bloom-prices:defillama".into(),
        }
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

    fn coin_for_asset(asset_id: &str) -> Result<CoinId, AuthApiError> {
        if let Some(chain) = asset_id.strip_prefix("native:") {
            return Ok(Self::coin_for_chain(chain));
        }
        let (chain, address) = asset_id
            .split_once(':')
            .ok_or_else(|| AuthApiError::Denied(format!("invalid price asset id: {asset_id}")))?;
        let chain = chain.trim().to_ascii_lowercase();
        let chain = match chain.as_str() {
            "mainnet" | "anvil" | "local" => "ethereum".to_string(),
            other => other.to_string(),
        };
        CoinId::parse(&format!("{chain}:{address}"))
            .map_err(|error| AuthApiError::Denied(format!("invalid price asset id: {error}")))
    }

    fn amount_to_usd_micro(
        amount_base_units: &str,
        decimals: u8,
        price_usd: f64,
    ) -> Result<i128, AuthApiError> {
        if !price_usd.is_finite() || price_usd <= 0.0 {
            return Err(AuthApiError::Denied("price quote is invalid".into()));
        }
        let amount = U256::from_str_radix(amount_base_units, 10)
            .map_err(|_| AuthApiError::Denied("amount_base_units is invalid".into()))?;
        if amount.is_zero() {
            return Ok(0);
        }
        // PriceQuote currently exposes f64, so use its exact binary rational
        // representation while keeping the token amount and micro-USD result
        // in integer arithmetic. Converting the full U256 amount to f64 loses
        // low bits at amounts above 2^53.
        let bits = price_usd.to_bits();
        let exponent = ((bits >> 52) & 0x7ff) as i32;
        let fraction = bits & ((1u64 << 52) - 1);
        let (mantissa, binary_exponent) = if exponent == 0 {
            (fraction, 1 - 1023 - 52)
        } else {
            ((1u64 << 52) | fraction, exponent - 1023 - 52)
        };
        let mut numerator = amount
            .checked_mul(U256::from(mantissa))
            .and_then(|value| value.checked_mul(U256::from(1_000_000u64)))
            .ok_or_else(|| AuthApiError::Denied("computed USD value is invalid".into()))?;
        let mut denominator = U256::from(10).pow(U256::from(decimals));
        if binary_exponent >= 0 {
            numerator = numerator
                .checked_shl(binary_exponent as usize)
                .ok_or_else(|| AuthApiError::Denied("computed USD value is invalid".into()))?;
        } else {
            // A denominator this large means the exact value is below one
            // micro-dollar. Round conservatively upward rather than to zero.
            denominator = match denominator.checked_shl((-binary_exponent) as usize) {
                Some(value) => value,
                None => return Ok(1),
            };
        }
        let quotient = numerator / denominator;
        let remainder = numerator % denominator;
        let rounded = if remainder > U256::ZERO {
            quotient
                .checked_add(U256::from(1u8))
                .ok_or_else(|| AuthApiError::Denied("computed USD value is invalid".into()))?
        } else {
            quotient
        };
        if rounded > U256::from(i128::MAX as u128) {
            return Err(AuthApiError::Denied("computed USD value is invalid".into()));
        }
        Ok(rounded.to::<u128>() as i128)
    }
}

#[async_trait]
impl PriceOracle for PricesOracle {
    async fn quote_usd(
        &self,
        asset_id: &str,
        amount_base_units: &str,
        asset_decimals: u8,
        now_ms: u64,
    ) -> Result<ValuationQuote, AuthApiError> {
        let coin = Self::coin_for_asset(asset_id)?;
        let quote =
            self.client.current(coin).await.map_err(|error| {
                AuthApiError::Denied(format!("price oracle unavailable: {error}"))
            })?;
        if let Some(provider_decimals) = quote.decimals
            && provider_decimals != asset_decimals
        {
            return Err(AuthApiError::Denied(format!(
                "price quote decimals mismatch: provider={provider_decimals} trusted={asset_decimals}"
            )));
        }
        if quote.timestamp == 0 {
            return Err(AuthApiError::Denied("price quote timestamp missing".into()));
        }
        let confidence_ppm = match quote.confidence {
            Some(confidence) if confidence.is_finite() && confidence >= 0.0 => {
                Some((confidence.min(1.0) * 1_000_000.0).round() as u32)
            }
            Some(_) => {
                return Err(AuthApiError::Denied(
                    "price quote confidence is invalid".into(),
                ));
            }
            None => None,
        };
        Ok(ValuationQuote {
            asset_id: asset_id.into(),
            amount_base_units: amount_base_units.into(),
            usd_micro: Self::amount_to_usd_micro(amount_base_units, asset_decimals, quote.price)?,
            source: self.source.clone(),
            quote_timestamp_ms: quote.timestamp.saturating_mul(1_000),
            fetched_at_ms: now_ms,
            max_age_ms: self.client.ttl().as_millis().try_into().unwrap_or(u64::MAX),
            confidence_ppm,
            stablecoin_assumption: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn one_shot_price_server(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
        format!("http://{addr}")
    }

    #[test]
    fn asset_ids_distinguish_native_and_erc20() {
        assert!(matches!(
            PricesOracle::coin_for_asset("native:base").unwrap(),
            CoinId::Native(_)
        ));
        assert!(matches!(
            PricesOracle::coin_for_asset("base:0x0000000000000000000000000000000000000001")
                .unwrap(),
            CoinId::Erc20 { .. }
        ));
    }

    #[test]
    fn token_amount_uses_base_units_and_quote_decimals() {
        let usd = PricesOracle::amount_to_usd_micro("1000000", 6, 1.25).unwrap();
        assert_eq!(usd, 1_250_000);
    }

    #[test]
    fn token_amount_preserves_micro_usd_precision_for_large_base_units() {
        // 2^53 + 1 cannot be represented exactly by f64. A token amount
        // this large is unusual but valid, and micro-USD is the policy unit.
        let usd = PricesOracle::amount_to_usd_micro("9007199254740993", 6, 1.0).unwrap();
        assert_eq!(usd, 9_007_199_254_740_993);
    }

    #[test]
    fn token_amount_rejects_nonpositive_or_non_finite_prices() {
        assert!(PricesOracle::amount_to_usd_micro("1", 0, f64::NAN).is_err());
        assert!(PricesOracle::amount_to_usd_micro("1", 0, f64::INFINITY).is_err());
        assert!(PricesOracle::amount_to_usd_micro("1", 0, -1.0).is_err());
        assert!(PricesOracle::amount_to_usd_micro("1", 0, 0.0).is_err());
    }

    #[test]
    fn positive_dust_rounds_up_to_one_micro_usd() {
        assert_eq!(
            PricesOracle::amount_to_usd_micro("1", 18, 0.000_001).unwrap(),
            1
        );
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

    #[tokio::test]
    async fn native_quote_uses_trusted_decimals_when_provider_omits_them() {
        let body = r#"{"coins":{"coingecko:ethereum":{"price":3500.5,"timestamp":1700000000}}}"#;
        let url = one_shot_price_server(body).await;
        let oracle = PricesOracle::new(PricesClient::with_base_url(url));

        let quote = oracle
            .quote_usd("native:anvil", "1000000000000000000", 18, 1_700_000_000_000)
            .await
            .unwrap();

        assert_eq!(quote.asset_id, "native:anvil");
        assert_eq!(quote.amount_base_units, "1000000000000000000");
        assert_eq!(quote.usd_micro, 3_500_500_000);
    }

    #[tokio::test]
    async fn native_quote_uses_configured_decimals_over_provider_metadata() {
        let body = r#"{"coins":{"coingecko:ethereum":{"price":3500.5,"timestamp":1700000000}}}"#;
        let url = one_shot_price_server(body).await;
        let oracle = PricesOracle::new(PricesClient::with_base_url(url));

        let quote = oracle
            .quote_usd("native:anvil", "1000000000", 9, 1_700_000_000_000)
            .await
            .unwrap();

        assert_eq!(quote.usd_micro, 3_500_500_000);
    }

    #[tokio::test]
    async fn token_quote_rejects_provider_decimal_mismatch() {
        let body = r#"{"coins":{"ethereum:0x0000000000000000000000000000000000000001":{"price":1.0,"timestamp":1700000000,"decimals":18}}}"#;
        let url = one_shot_price_server(body).await;
        let oracle = PricesOracle::new(PricesClient::with_base_url(url));

        let error = oracle
            .quote_usd(
                "ethereum:0x0000000000000000000000000000000000000001",
                "1000000",
                6,
                1_700_000_000_000,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("decimals mismatch"));
    }
}
