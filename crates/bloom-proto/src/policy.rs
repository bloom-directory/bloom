//! Per-wallet policy: caps, allow/deny lists, automation knobs.
//!
//! See spec §6.3. The on-disk representation is `policy.toml`. The
//! `Policy` type is the *parsed* form used by the tx engine.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub caps: PolicyCaps,
    /// Legacy per-section allow/deny — kept for backward compatibility
    /// with existing policy.toml files that use `[contracts]`/`[tokens]`
    /// blocks.
    #[serde(default)]
    pub contracts: PolicyAllowDeny,
    #[serde(default)]
    pub tokens: PolicyAllowDeny,
    /// First-class allow lists. Address strings (or alias names) listed
    /// here form a strict allowlist when non-empty.
    #[serde(default)]
    pub allowlists: PolicyLists,
    /// First-class deny lists. Any hit is a hard block regardless of
    /// allowlist state.
    #[serde(default)]
    pub denylists: PolicyLists,
    /// Per-chain caps. The chain name keys match `ChainSpec::name`.
    /// When evaluating a tx, the global caps and the per-chain caps are
    /// both considered; the **more restrictive** of the two wins for
    /// each individual cap.
    #[serde(default)]
    pub per_chain: BTreeMap<String, PolicyCaps>,
    #[serde(default)]
    pub automation: PolicyAutomation,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PolicyCaps {
    /// Hard cap: any tx whose value > this is rejected.
    #[serde(default)]
    pub max_value_eth: Option<f64>,
    /// Soft cap: tx > this requires explicit override (write `override`
    /// to confirm rather than `y`).
    #[serde(default)]
    pub require_override_above_eth: Option<f64>,
    /// USD caps (only enforced when prices are configured).
    #[serde(default)]
    pub per_tx_usd: Option<f64>,
    #[serde(default)]
    pub per_day_usd: Option<f64>,
    #[serde(default)]
    pub require_confirm_above_usd: Option<f64>,
}

impl PolicyCaps {
    /// Merge two cap sets, picking the **more restrictive** value for
    /// each field. `None` means "unconstrained" — any concrete value is
    /// stricter than `None`. When both sides have a value the **min** is
    /// taken (smaller cap = stricter).
    pub fn most_restrictive(a: &PolicyCaps, b: &PolicyCaps) -> PolicyCaps {
        fn min_opt(x: Option<f64>, y: Option<f64>) -> Option<f64> {
            match (x, y) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            }
        }
        PolicyCaps {
            max_value_eth: min_opt(a.max_value_eth, b.max_value_eth),
            require_override_above_eth: min_opt(
                a.require_override_above_eth,
                b.require_override_above_eth,
            ),
            per_tx_usd: min_opt(a.per_tx_usd, b.per_tx_usd),
            per_day_usd: min_opt(a.per_day_usd, b.per_day_usd),
            require_confirm_above_usd: min_opt(
                a.require_confirm_above_usd,
                b.require_confirm_above_usd,
            ),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PolicyAllowDeny {
    #[serde(default)]
    pub allow: BTreeSet<String>,
    #[serde(default)]
    pub deny: BTreeSet<String>,
}

/// Strict allow / deny address sets, partitioned by what the address
/// represents in a tx. Addresses are compared **case-insensitively**.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PolicyLists {
    #[serde(default)]
    pub contracts: BTreeSet<String>,
    #[serde(default)]
    pub tokens: BTreeSet<String>,
    #[serde(default)]
    pub recipients: BTreeSet<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PolicyAutomation {
    #[serde(default)]
    pub auto_confirm_below_eth: Option<f64>,
    /// Optional sentinel string that, when written to `confirm`, bypasses
    /// soft warnings. Defaults to `"override"` when `None`.
    #[serde(default)]
    pub override_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub rule: String,
    pub outcome: PolicyOutcome,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    /// Rule passed.
    Pass,
    /// Soft warning. Confirm still allowed but plan.md highlights it.
    Warn,
    /// Hard violation. Confirm rejected unless an "override" sentinel is
    /// written.
    Deny,
}

impl Policy {
    /// Default permissive policy. Useful in tests / on dev chains.
    pub fn permissive() -> Self {
        Policy::default()
    }

    /// The effective override sentinel for this policy.
    pub fn override_sentinel(&self) -> &str {
        self.automation
            .override_token
            .as_deref()
            .unwrap_or("override")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn most_restrictive_picks_smaller_cap() {
        let a = PolicyCaps {
            max_value_eth: Some(1.0),
            ..Default::default()
        };
        let b = PolicyCaps {
            max_value_eth: Some(0.25),
            ..Default::default()
        };
        let m = PolicyCaps::most_restrictive(&a, &b);
        assert_eq!(m.max_value_eth, Some(0.25));
    }

    #[test]
    fn most_restrictive_treats_none_as_unconstrained() {
        let a = PolicyCaps::default();
        let b = PolicyCaps {
            max_value_eth: Some(0.5),
            ..Default::default()
        };
        assert_eq!(
            PolicyCaps::most_restrictive(&a, &b).max_value_eth,
            Some(0.5)
        );
    }
}
