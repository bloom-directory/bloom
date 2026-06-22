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
    #[serde(default)]
    pub private: PrivatePolicy,
    #[serde(default)]
    pub mev: MevPolicy,
    #[serde(default)]
    pub bump: BumpPolicy,
    /// Broadcast approval policy (`[approval]`). This is separate from normal
    /// tx policy: passing caps/allowlists does not itself authorize a daemon to
    /// broadcast with a cached signer.
    #[serde(default)]
    pub approval: ApprovalPolicy,
    /// Cross-surface spending limits used by the agent-autonomy evaluator.
    /// These are parsed from signed `policy.toml` and apply to CLI, VFS, IPC,
    /// and daemon surfaces alike.
    #[serde(default)]
    pub limits: LimitsPolicy,
    /// Polymarket order policy (`[polymarket]`). Defaults to disabled —
    /// trading requires an explicit opt-in in the policy file.
    #[serde(default)]
    pub polymarket: crate::polymarket_policy::PolymarketPolicy,
    /// Generic DeFi route policy (`[defi]`). Defaults to disabled — the
    /// open-ended `defi/intents` route surface refuses until opted in.
    #[serde(default)]
    pub defi: crate::defi_policy::DefiPolicy,
    /// Paid HTTP request policy (`[payments]`). Defaults to disabled — paid
    /// request confirmation requires explicit wallet policy opt-in.
    #[serde(default)]
    pub payments: PaymentsPolicy,
    /// Hyperliquid action policy (`[hyperliquid]`). Caps default to
    /// unconfigured (no constraint); unknown action kinds always deny.
    #[serde(default)]
    pub hyperliquid: crate::hyperliquid_policy::HyperliquidPolicy,
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
pub struct PrivatePolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_private_provider")]
    pub provider: String,
}

impl Default for PrivatePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_private_provider(),
        }
    }
}

fn default_private_provider() -> String {
    "mev_blocker".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevPolicy {
    #[serde(default = "default_max_slippage_bps")]
    pub max_slippage_bps: u32,
    #[serde(default)]
    pub fail_on_high_risk: bool,
}

impl Default for MevPolicy {
    fn default() -> Self {
        Self {
            max_slippage_bps: 100,
            fail_on_high_risk: false,
        }
    }
}

fn default_max_slippage_bps() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BumpPolicy {
    #[serde(default = "default_stuck_after_secs")]
    pub stuck_after_secs: u64,
    #[serde(default = "default_basefee_overrun_pct")]
    pub basefee_overrun_pct: u32,
}

impl Default for BumpPolicy {
    fn default() -> Self {
        Self {
            stuck_after_secs: 90,
            basefee_overrun_pct: 20,
        }
    }
}

fn default_stuck_after_secs() -> u64 {
    90
}

fn default_basefee_overrun_pct() -> u32 {
    20
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalPolicy {
    /// Agent autonomy mode. When absent (the default), `effective_agent_autonomy()`
    /// maps the legacy `require_broadcast_approval` flag conservatively — normal
    /// wallet behavior: no autonomous value movement; a fresh reviewed user
    /// signature is required for broadcasts.
    #[serde(default)]
    pub agent_autonomy: Option<AgentAutonomyMode>,
    /// Legacy boolean from the first approval model. It no longer grants
    /// broadcast authority when false; only `agent_autonomy = "under_policy"`
    /// can authorize agent execution without fresh review.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_broadcast_approval: bool,
    /// Legacy prompt-all flag for policies that predate `agent_autonomy`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub always_prompt_for_broadcast: bool,
}

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentAutonomyMode {
    /// Agents may prepare/draft, but value movement needs fresh approval.
    #[default]
    Disabled,
    /// Agents may execute without a fresh prompt only when every policy,
    /// verification, valuation, and budget check passes.
    UnderPolicy,
    /// Every value-moving action needs fresh approval.
    PromptAll,
}

impl Policy {
    pub fn effective_agent_autonomy(&self) -> AgentAutonomyMode {
        if let Some(mode) = &self.approval.agent_autonomy {
            return mode.clone();
        }
        if self.approval.require_broadcast_approval || self.approval.always_prompt_for_broadcast {
            AgentAutonomyMode::PromptAll
        } else {
            AgentAutonomyMode::Disabled
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_require_plan")]
    pub require_plan: bool,
    #[serde(default)]
    pub require_confirm_for_new_merchant: bool,
    #[serde(default)]
    pub http: PaymentsHttpPolicy,
    #[serde(default)]
    pub sessions: PaymentsSessionsPolicy,
    #[serde(default)]
    pub assets: PolicyAllowDeny,
    #[serde(default)]
    pub networks: PolicyAllowDeny,
}

fn default_require_plan() -> bool {
    true
}

impl Default for PaymentsPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            require_plan: default_require_plan(),
            require_confirm_for_new_merchant: false,
            http: PaymentsHttpPolicy::default(),
            sessions: PaymentsSessionsPolicy::default(),
            assets: PolicyAllowDeny::default(),
            networks: PolicyAllowDeny::default(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PaymentsHttpPolicy {
    #[serde(default)]
    pub per_request_usd: Option<f64>,
    #[serde(default)]
    pub per_day_usd: Option<f64>,
    #[serde(default)]
    pub allow_hosts: BTreeSet<String>,
    #[serde(default)]
    pub deny_hosts: BTreeSet<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PaymentsSessionsPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max_deposit_usd: Option<f64>,
    #[serde(default)]
    pub max_session_spend_usd: Option<f64>,
    #[serde(default = "default_true")]
    pub require_confirm_to_open: bool,
    #[serde(default = "default_true")]
    pub require_confirm_to_top_up: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LimitsPolicy {
    /// Decimal USD strings. They are parsed to integer micro-USD by the
    /// evaluator; invalid values deny autonomy rather than silently passing.
    #[serde(default)]
    pub max_tx_usd: Option<String>,
    #[serde(default)]
    pub max_day_usd: Option<String>,
    #[serde(default)]
    pub max_week_usd: Option<String>,
    #[serde(default)]
    pub max_month_usd: Option<String>,
}

impl LimitsPolicy {
    fn parse_micro_usd(v: &Option<String>, field: &str) -> Result<Option<i128>, String> {
        let Some(raw) = v.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        parse_decimal_micro(raw)
            .map(Some)
            .map_err(|e| format!("{field}: {e}"))
    }

    pub fn max_tx_micro_usd(&self) -> Result<Option<i128>, String> {
        Self::parse_micro_usd(&self.max_tx_usd, "limits.max_tx_usd")
    }

    pub fn max_day_micro_usd(&self) -> Result<Option<i128>, String> {
        Self::parse_micro_usd(&self.max_day_usd, "limits.max_day_usd")
    }

    pub fn max_week_micro_usd(&self) -> Result<Option<i128>, String> {
        Self::parse_micro_usd(&self.max_week_usd, "limits.max_week_usd")
    }

    pub fn max_month_micro_usd(&self) -> Result<Option<i128>, String> {
        Self::parse_micro_usd(&self.max_month_usd, "limits.max_month_usd")
    }
}

fn parse_decimal_micro(raw: &str) -> Result<i128, String> {
    if raw.starts_with('-') {
        return Err("negative USD limits are not allowed".into());
    }
    let (whole, frac) = raw.split_once('.').unwrap_or((raw, ""));
    if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err("expected decimal USD string".into());
    }
    if frac.len() > 6 || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err("expected at most 6 decimal places".into());
    }
    let whole: i128 = whole
        .parse()
        .map_err(|_| "USD value is too large".to_string())?;
    let mut frac_s = frac.to_string();
    while frac_s.len() < 6 {
        frac_s.push('0');
    }
    let frac: i128 = if frac_s.is_empty() {
        0
    } else {
        frac_s
            .parse()
            .map_err(|_| "USD value is too large".to_string())?
    };
    whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| "USD value is too large".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastApprovalDecision {
    ApprovedFreshReview,
    /// Legacy variant retained for API compatibility. The evaluator no longer
    /// returns it: broadcasts require fresh review or the newer autonomy
    /// evaluator.
    ApprovedPolicyOptOut,
    NeedsFreshReview {
        reason: String,
    },
    Denied {
        reason: String,
    },
}

pub fn evaluate_broadcast_approval(
    policy: &Policy,
    reviewed_intent_hash: Option<&str>,
) -> BroadcastApprovalDecision {
    match reviewed_intent_hash
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(_) => BroadcastApprovalDecision::ApprovedFreshReview,
        None => BroadcastApprovalDecision::NeedsFreshReview {
            reason: match policy.effective_agent_autonomy() {
                AgentAutonomyMode::UnderPolicy => {
                    "legacy approval evaluator cannot grant under-policy autonomy; use \
                     evaluate_action_authorization"
                        .into()
                }
                AgentAutonomyMode::Disabled => {
                    "agent_autonomy=disabled; fresh reviewed user signature required".into()
                }
                AgentAutonomyMode::PromptAll => {
                    "agent_autonomy=prompt_all; fresh reviewed user signature required".into()
                }
            },
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationSurface {
    Cli,
    Vfs,
    Ipc,
    DaemonTask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub spent_day_micro_usd: i128,
    pub spent_week_micro_usd: i128,
    pub spent_month_micro_usd: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationSubject {
    pub kind: String,
    pub wallet: String,
    pub chain: Option<String>,
    pub subject_hash: String,
    pub total_value_usd_micro: Option<i128>,
    pub value_moving: bool,
    pub calldata_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutonomyDecision {
    ApprovedAutonomous {
        reason: String,
        debit_micro_usd: i128,
    },
    ApprovedFreshReview {
        review_hash: String,
    },
    ApprovedCapability {
        capability_id: String,
        debit_micro_usd: i128,
    },
    NeedsFreshReview {
        reason: String,
    },
    Denied {
        reason: String,
    },
}

pub fn evaluate_action_authorization(
    policy: &Policy,
    policy_checks: &[PolicyCheck],
    subject: &AuthorizationSubject,
    budget: Option<&BudgetSnapshot>,
    reviewed_intent_hash: Option<&str>,
    _surface: AuthorizationSurface,
) -> AutonomyDecision {
    if let Some(deny) = policy_checks
        .iter()
        .find(|c| matches!(c.outcome, PolicyOutcome::Deny))
    {
        return AutonomyDecision::Denied {
            reason: format!("policy denied: {}: {}", deny.rule, deny.message),
        };
    }

    if let Some(hash) = reviewed_intent_hash
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return AutonomyDecision::ApprovedFreshReview {
            review_hash: hash.to_string(),
        };
    }

    if !subject.value_moving {
        return AutonomyDecision::ApprovedAutonomous {
            reason: "non-value-moving action".into(),
            debit_micro_usd: 0,
        };
    }

    match policy.effective_agent_autonomy() {
        AgentAutonomyMode::Disabled => AutonomyDecision::NeedsFreshReview {
            reason: "agent_autonomy=disabled".into(),
        },
        AgentAutonomyMode::PromptAll => AutonomyDecision::NeedsFreshReview {
            reason: "agent_autonomy=prompt_all".into(),
        },
        AgentAutonomyMode::UnderPolicy => {
            if let Some(warn) = policy_checks
                .iter()
                .find(|c| matches!(c.outcome, PolicyOutcome::Warn))
            {
                return AutonomyDecision::NeedsFreshReview {
                    reason: format!(
                        "policy warning requires review: {}: {}",
                        warn.rule, warn.message
                    ),
                };
            }
            if !subject.calldata_verified {
                return AutonomyDecision::Denied {
                    reason: "calldata/order facts are not verified".into(),
                };
            }
            let Some(value) = subject.total_value_usd_micro else {
                return AutonomyDecision::Denied {
                    reason: "USD valuation unavailable".into(),
                };
            };
            let Some(snapshot) = budget else {
                return AutonomyDecision::Denied {
                    reason: "budget ledger unavailable".into(),
                };
            };
            if let Err(reason) = check_limits(policy, value, snapshot) {
                return AutonomyDecision::Denied { reason };
            }
            AutonomyDecision::ApprovedAutonomous {
                reason: "agent_autonomy=under_policy".into(),
                debit_micro_usd: value,
            }
        }
    }
}

fn check_limits(policy: &Policy, value: i128, snapshot: &BudgetSnapshot) -> Result<(), String> {
    if let Some(max) = policy.limits.max_tx_micro_usd()? {
        if value > max {
            return Err(format!(
                "limits.max_tx_usd exceeded: {value} > {max} micro-USD"
            ));
        }
    } else {
        return Err("limits.max_tx_usd is required for under_policy autonomy".into());
    }
    if let Some(max) = policy.limits.max_day_micro_usd()? {
        let total = snapshot.spent_day_micro_usd.saturating_add(value);
        if total > max {
            return Err(format!(
                "limits.max_day_usd exceeded: {total} > {max} micro-USD"
            ));
        }
    } else {
        return Err("limits.max_day_usd is required for under_policy autonomy".into());
    }
    if let Some(max) = policy.limits.max_week_micro_usd()? {
        let total = snapshot.spent_week_micro_usd.saturating_add(value);
        if total > max {
            return Err(format!(
                "limits.max_week_usd exceeded: {total} > {max} micro-USD"
            ));
        }
    }
    if let Some(max) = policy.limits.max_month_micro_usd()? {
        let total = snapshot.spent_month_micro_usd.saturating_add(value);
        if total > max {
            return Err(format!(
                "limits.max_month_usd exceeded: {total} > {max} micro-USD"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub rule: String,
    pub outcome: PolicyOutcome,
    pub message: String,
}

impl PolicyCheck {
    /// Construct a check with a `"<venue>.<rule>"` namespaced rule field.
    pub fn for_venue(
        venue: &str,
        rule: &str,
        outcome: PolicyOutcome,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule: format!("{venue}.{rule}"),
            outcome,
            message: message.into(),
        }
    }
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

/// True when any check is a hard denial.
pub fn has_deny(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(|c| c.outcome == PolicyOutcome::Deny)
}

/// True when any check is a soft warning.
pub fn has_warn(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(|c| c.outcome == PolicyOutcome::Warn)
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

    #[test]
    fn policy_defaults_when_new_sections_missing() {
        let toml_src = "[caps]\nmax_value_eth = 0.1\n";
        let p: Policy = toml::from_str(toml_src).unwrap();
        assert!(!p.private.enabled);
        assert_eq!(p.private.provider, "mev_blocker");
        assert_eq!(p.mev.max_slippage_bps, 100);
        assert!(!p.mev.fail_on_high_risk);
        assert_eq!(p.bump.stuck_after_secs, 90);
        assert_eq!(p.bump.basefee_overrun_pct, 20);
        assert!(!p.payments.enabled);
        assert!(p.payments.require_plan);
    }

    #[test]
    fn policy_parses_new_sections_when_present() {
        let toml_src = r#"
[caps]
max_value_eth = 0.1

[private]
enabled = true
provider = "flashbots"

[mev]
max_slippage_bps = 250
fail_on_high_risk = true

[bump]
stuck_after_secs = 30
basefee_overrun_pct = 50
"#;
        let p: Policy = toml::from_str(toml_src).unwrap();
        assert!(p.private.enabled);
        assert_eq!(p.private.provider, "flashbots");
        assert_eq!(p.mev.max_slippage_bps, 250);
        assert!(p.mev.fail_on_high_risk);
        assert_eq!(p.bump.stuck_after_secs, 30);
        assert_eq!(p.bump.basefee_overrun_pct, 50);
    }

    #[test]
    fn broadcast_approval_false_is_not_an_opt_out() {
        let p = Policy::default();
        assert!(matches!(
            evaluate_broadcast_approval(&p, None),
            BroadcastApprovalDecision::NeedsFreshReview { reason }
                if reason.contains("agent_autonomy=disabled")
        ));
    }

    #[test]
    fn broadcast_approval_requires_review_regardless_of_legacy_bool() {
        let mut p = Policy::default();
        p.approval.require_broadcast_approval = true;
        assert!(matches!(
            evaluate_broadcast_approval(&p, None),
            BroadcastApprovalDecision::NeedsFreshReview { .. }
        ));
        assert_eq!(
            evaluate_broadcast_approval(&p, Some("abc123")),
            BroadcastApprovalDecision::ApprovedFreshReview
        );
    }

    #[test]
    fn generated_disabled_policy_omits_legacy_approval_booleans() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::Disabled);
        let toml = toml::to_string_pretty(&p).unwrap();
        assert!(toml.contains("agent_autonomy = \"disabled\""));
        assert!(!toml.contains("require_broadcast_approval"));
        assert!(!toml.contains("always_prompt_for_broadcast"));
    }

    fn auth_subject(value: Option<i128>) -> AuthorizationSubject {
        AuthorizationSubject {
            kind: "evm_tx".into(),
            wallet: "alice".into(),
            chain: Some("anvil".into()),
            subject_hash: "hash".into(),
            total_value_usd_micro: value,
            value_moving: true,
            calldata_verified: true,
        }
    }

    fn budget() -> BudgetSnapshot {
        BudgetSnapshot {
            spent_day_micro_usd: 0,
            spent_week_micro_usd: 0,
            spent_month_micro_usd: 0,
        }
    }

    #[test]
    fn autonomy_disabled_needs_review() {
        let p = Policy::default();
        assert!(matches!(
            evaluate_action_authorization(
                &p,
                &[],
                &auth_subject(Some(1)),
                Some(&budget()),
                None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::NeedsFreshReview { .. }
        ));
    }

    #[test]
    fn under_policy_denies_unknown_usd() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        assert!(matches!(
            evaluate_action_authorization(
                &p,
                &[],
                &auth_subject(None),
                Some(&budget()),
                None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason } if reason.contains("USD valuation")
        ));
    }

    #[test]
    fn under_policy_allows_within_limits() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        assert!(matches!(
            evaluate_action_authorization(
                &p,
                &[],
                &auth_subject(Some(2_500_000)),
                Some(&budget()),
                None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::ApprovedAutonomous { .. }
        ));
    }

    #[test]
    fn under_policy_day_cap_blocks_repetition() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        let b = BudgetSnapshot {
            spent_day_micro_usd: 9_000_000,
            spent_week_micro_usd: 9_000_000,
            spent_month_micro_usd: 9_000_000,
        };
        assert!(matches!(
            evaluate_action_authorization(
                &p,
                &[],
                &auth_subject(Some(2_000_000)),
                Some(&b),
                None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason } if reason.contains("max_day")
        ));
    }
}
