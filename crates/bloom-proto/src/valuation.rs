//! Key-free price-valuation snapshots used by staging and policy projection.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValuationQuote {
    pub asset_id: String,
    pub amount_base_units: String,
    pub usd_micro: i128,
    pub source: String,
    pub quote_timestamp_ms: u64,
    pub fetched_at_ms: u64,
    pub max_age_ms: u64,
    pub confidence_ppm: Option<u32>,
    pub stablecoin_assumption: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValuationPolicy {
    pub volatile_max_age_ms: u64,
    pub stablecoin_max_age_ms: u64,
    #[serde(default = "default_observation_max_age_ms")]
    pub observation_max_age_ms: u64,
    #[serde(default = "default_future_tolerance_ms")]
    pub future_tolerance_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence_ppm: Option<u32>,
    #[serde(default)]
    pub stablecoin_asset_allowlist: Vec<String>,
}

impl Default for ValuationPolicy {
    fn default() -> Self {
        Self {
            volatile_max_age_ms: 30_000,
            stablecoin_max_age_ms: 120_000,
            observation_max_age_ms: default_observation_max_age_ms(),
            future_tolerance_ms: default_future_tolerance_ms(),
            min_confidence_ppm: None,
            stablecoin_asset_allowlist: Vec::new(),
        }
    }
}

const fn default_observation_max_age_ms() -> u64 {
    5 * 60 * 1_000
}

const fn default_future_tolerance_ms() -> u64 {
    60 * 1_000
}

impl ValuationPolicy {
    pub fn max_age_for(&self, quote: &ValuationQuote) -> u64 {
        let policy_age = if quote.stablecoin_assumption {
            self.stablecoin_max_age_ms
        } else {
            self.volatile_max_age_ms
        };
        quote.max_age_ms.min(policy_age)
    }

    pub fn stablecoin_allowed(&self, asset_id: &str) -> bool {
        self.stablecoin_asset_allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(asset_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("valuation denied: {0}")]
pub struct ValuationError(pub String);

impl ValuationError {
    pub fn denied(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl ValuationQuote {
    pub fn validate_for_authorization(
        &self,
        policy: &ValuationPolicy,
        now_ms: u64,
    ) -> Result<(), ValuationError> {
        if self.asset_id.trim().is_empty() {
            return Err(ValuationError::denied("valuation asset_id is empty"));
        }
        if self.amount_base_units.trim().is_empty() {
            return Err(ValuationError::denied(
                "valuation amount_base_units is empty",
            ));
        }
        if self.source.trim().is_empty() {
            return Err(ValuationError::denied("valuation source is empty"));
        }
        if self.usd_micro < 0 {
            return Err(ValuationError::denied("valuation is negative"));
        }
        if self.quote_timestamp_ms == 0 {
            return Err(ValuationError::denied(
                "valuation quote timestamp is missing",
            ));
        }
        if self.fetched_at_ms == 0 {
            return Err(ValuationError::denied(
                "valuation fetched timestamp is missing",
            ));
        }
        if self.quote_timestamp_ms > now_ms.saturating_add(policy.future_tolerance_ms) {
            return Err(ValuationError::denied(
                "valuation quote timestamp is in the future",
            ));
        }
        let observation_age_ms = now_ms.saturating_sub(self.quote_timestamp_ms);
        if observation_age_ms > policy.observation_max_age_ms {
            return Err(ValuationError::denied(format!(
                "valuation market observation is stale: age_ms={observation_age_ms} max_age_ms={}",
                policy.observation_max_age_ms
            )));
        }
        let max_age_ms = policy.max_age_for(self);
        if now_ms.saturating_sub(self.fetched_at_ms) > max_age_ms {
            return Err(ValuationError::denied(format!(
                "valuation quote is stale: age_ms={} max_age_ms={max_age_ms}",
                now_ms.saturating_sub(self.fetched_at_ms)
            )));
        }
        if let Some(min_confidence) = policy.min_confidence_ppm {
            match self.confidence_ppm {
                Some(confidence) if confidence >= min_confidence => {}
                Some(confidence) => {
                    return Err(ValuationError::denied(format!(
                        "valuation confidence {confidence}ppm below required {min_confidence}ppm"
                    )));
                }
                None => {
                    return Err(ValuationError::denied("valuation confidence is missing"));
                }
            }
        }
        if self.stablecoin_assumption && !policy.stablecoin_allowed(&self.asset_id) {
            return Err(ValuationError::denied(format!(
                "stablecoin shortcut is not allowed for {}",
                self.asset_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote() -> ValuationQuote {
        ValuationQuote {
            asset_id: "native:ethereum".into(),
            amount_base_units: "1".into(),
            usd_micro: 1,
            source: "test".into(),
            quote_timestamp_ms: 10_000,
            fetched_at_ms: 10_000,
            max_age_ms: 30_000,
            confidence_ppm: None,
            stablecoin_assumption: false,
        }
    }

    #[test]
    fn valuation_freshness_fails_closed() {
        assert!(
            quote()
                .validate_for_authorization(&ValuationPolicy::default(), 20_000)
                .is_ok()
        );
        assert!(
            quote()
                .validate_for_authorization(&ValuationPolicy::default(), 40_001)
                .is_err()
        );
    }
}
