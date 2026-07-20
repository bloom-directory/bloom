//! Polymarket wallet-policy schema consumed by the external Polymarket Petal.
//!
//! Bloom owns serialization of the wallet policy but not venue evaluation;
//! the installed Petal owns Polymarket semantics and enforcement.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

/// `[polymarket]` section of a wallet's policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymarketPolicy {
    /// Master gate. Defaults to **true**; wallet policy can disable trading.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hard cap per order, micro-USD (TOML: decimal string, e.g. `"10"`).
    #[serde(default, with = "crate::serde_micro")]
    pub max_order_usd: Option<u64>,
    /// Hard cap on posted exposure per trailing 24 h, micro-USD.
    #[serde(default, with = "crate::serde_micro")]
    pub max_daily_usd: Option<u64>,
    /// Orders above this require an explicit risk acknowledgement.
    #[serde(default, with = "crate::serde_micro")]
    pub require_flag_above_usd: Option<u64>,
    /// Hard cap on the limit price per share (micro, `"0.75"` → 750000).
    #[serde(default, with = "crate::serde_micro")]
    pub max_price: Option<u64>,
    /// Whether neg-risk markets may be traded.
    #[serde(default = "default_true")]
    pub allow_neg_risk: bool,
    #[serde(default)]
    pub allowed_slugs: BTreeSet<String>,
    #[serde(default)]
    pub denied_slugs: BTreeSet<String>,
    #[serde(default)]
    pub allowed_condition_ids: BTreeSet<String>,
    #[serde(default)]
    pub denied_condition_ids: BTreeSet<String>,
}

impl Default for PolymarketPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_order_usd: None,
            max_daily_usd: None,
            require_flag_above_usd: None,
            max_price: None,
            allow_neg_risk: true,
            allowed_slugs: BTreeSet::new(),
            denied_slugs: BTreeSet::new(),
            allowed_condition_ids: BTreeSet::new(),
            denied_condition_ids: BTreeSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preserves_enabled_policy_compatibility() {
        let policy = PolymarketPolicy::default();
        assert!(policy.enabled);
        assert!(policy.max_order_usd.is_none());
        assert!(policy.max_daily_usd.is_none());
    }

    #[test]
    fn decimal_caps_round_trip() {
        let policy: PolymarketPolicy =
            toml::from_str("enabled = true\nmax_order_usd = \"10\"\nmax_price = \"0.75\"\n")
                .unwrap();
        assert_eq!(policy.max_order_usd, Some(10_000_000));
        assert_eq!(policy.max_price, Some(750_000));
        let encoded = toml::to_string(&policy).unwrap();
        let decoded: PolymarketPolicy = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.max_order_usd, policy.max_order_usd);
        assert_eq!(decoded.max_price, policy.max_price);
    }
}
