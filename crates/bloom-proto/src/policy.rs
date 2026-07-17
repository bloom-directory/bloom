//! Per-wallet policy: caps, allow/deny lists, automation knobs.
//!
//! See spec §6.3. The on-disk representation is `policy.toml`. The
//! `Policy` type is the *parsed* form used by the tx engine.

use std::collections::{BTreeMap, BTreeSet};

use bloom_auth_api::AssuranceLevel;
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
    /// Polymarket order policy (`[polymarket]`). Trading is enabled by default;
    /// wallet policy can disable it or apply exposure limits.
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
    /// Assurance level for approval/session grants. `standard` allows
    /// password/passphrase or passkey bounded grants. `hardened` requires
    /// passkey/WebAuthn for grant minting and out-of-policy approvals.
    #[serde(default)]
    pub assurance: AssuranceLevel,
    /// Step-up policy and ceilings for approval-renderable soft violations.
    #[serde(default)]
    pub step_up: ApprovalStepUpPolicy,
    /// Legacy boolean from the first approval model. It no longer grants
    /// broadcast authority when false; only `agent_autonomy = "under_policy"`
    /// can authorize agent execution without fresh review.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_broadcast_approval: bool,
    /// Legacy prompt-all flag for policies that predate `agent_autonomy`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub always_prompt_for_broadcast: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalStepUpPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_step_up_ttl_secs")]
    pub ttl_secs: u64,
    /// In hardened mode, approvals above this require WebAuthn user
    /// verification. Decimal USD string, parsed to integer micro-USD.
    #[serde(default)]
    pub uv_above_usd: Option<String>,
    #[serde(default)]
    pub rule_ceilings: BTreeMap<String, StepUpRuleCeiling>,
}

impl Default for ApprovalStepUpPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_secs: default_step_up_ttl_secs(),
            uv_above_usd: None,
            rule_ceilings: BTreeMap::new(),
        }
    }
}

impl ApprovalStepUpPolicy {
    pub fn uv_above_micro_usd(&self) -> Result<Option<i128>, String> {
        LimitsPolicy::parse_micro_usd(&self.uv_above_usd, "approval.step_up.uv_above_usd")
    }
}

fn default_step_up_ttl_secs() -> u64 {
    120
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepUpRuleCeiling {
    #[serde(default)]
    pub max_usd: Option<String>,
    #[serde(default)]
    pub max_u32: Option<u32>,
    #[serde(default)]
    pub max_bps: Option<u32>,
    #[serde(default)]
    pub max_count: Option<u64>,
}

impl StepUpRuleCeiling {
    pub fn max_micro_usd(&self, rule: &str) -> Result<Option<i128>, String> {
        LimitsPolicy::parse_micro_usd(&self.max_usd, rule)
    }

    pub fn has_any_limit(&self) -> bool {
        self.max_usd.is_some()
            || self.max_u32.is_some()
            || self.max_bps.is_some()
            || self.max_count.is_some()
    }
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

    /// Load/sign-time consistency check: an `under_policy` autonomy mode
    /// requires `limits.max_tx_usd` and `limits.max_day_usd` to be set —
    /// otherwise every broadcast-time authorization fails inside `check_limits`
    /// (see the `None` arms that return "… is required for under_policy
    /// autonomy"). Surfacing this at sign time prevents signing a policy that
    /// would brick every subsequent broadcast.
    pub fn validate_autonomy_limits(&self) -> Result<(), String> {
        if matches!(
            self.effective_agent_autonomy(),
            AgentAutonomyMode::UnderPolicy
        ) {
            if self.limits.max_tx_micro_usd()?.is_none() {
                return Err("limits.max_tx_usd is required for under_policy autonomy".into());
            }
            if self.limits.max_day_micro_usd()?.is_none() {
                return Err("limits.max_day_usd is required for under_policy autonomy".into());
            }
        }
        Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEditClass {
    NotExpanding,
    AuthorityExpanding { reasons: Vec<String> },
}

impl PolicyEditClass {
    pub fn is_authority_expanding(&self) -> bool {
        matches!(self, PolicyEditClass::AuthorityExpanding { .. })
    }
}

/// Classify whether a policy edit expands authority and therefore requires
/// hardened step-up even when the wallet normally uses standard mode.
pub fn classify_policy_edit(before: &Policy, after: &Policy) -> PolicyEditClass {
    let mut reasons = Vec::new();

    if before.approval.assurance == AssuranceLevel::Hardened
        && after.approval.assurance == AssuranceLevel::Standard
    {
        reasons.push("approval.assurance hardened -> standard".to_string());
    }

    if autonomy_rank(after.effective_agent_autonomy())
        > autonomy_rank(before.effective_agent_autonomy())
    {
        reasons.push("approval.agent_autonomy expands autonomous signing".to_string());
    }

    check_limit_increase(
        "limits.max_tx_usd",
        before.limits.max_tx_micro_usd(),
        after.limits.max_tx_micro_usd(),
        &mut reasons,
    );
    check_limit_increase(
        "limits.max_day_usd",
        before.limits.max_day_micro_usd(),
        after.limits.max_day_micro_usd(),
        &mut reasons,
    );
    check_limit_increase(
        "limits.max_week_usd",
        before.limits.max_week_micro_usd(),
        after.limits.max_week_micro_usd(),
        &mut reasons,
    );
    check_limit_increase(
        "limits.max_month_usd",
        before.limits.max_month_micro_usd(),
        after.limits.max_month_micro_usd(),
        &mut reasons,
    );

    if after.approval.step_up.ttl_secs > before.approval.step_up.ttl_secs {
        reasons.push("approval.step_up.ttl_secs increased".to_string());
    }
    check_limit_increase(
        "approval.step_up.uv_above_usd",
        before.approval.step_up.uv_above_micro_usd(),
        after.approval.step_up.uv_above_micro_usd(),
        &mut reasons,
    );

    for (rule, after_ceiling) in &after.approval.step_up.rule_ceilings {
        match before.approval.step_up.rule_ceilings.get(rule) {
            Some(before_ceiling) => {
                check_rule_ceiling_increase(rule, before_ceiling, after_ceiling, &mut reasons);
            }
            None if after_ceiling.has_any_limit() => {
                reasons.push(format!("approval.step_up.rule_ceilings.{rule} added"));
            }
            None => {}
        }
    }

    check_allow_expansion(
        "allowlists.recipients",
        &before.allowlists.recipients,
        &after.allowlists.recipients,
        &mut reasons,
    );
    check_allow_expansion(
        "allowlists.contracts",
        &before.allowlists.contracts,
        &after.allowlists.contracts,
        &mut reasons,
    );
    check_allow_expansion(
        "allowlists.tokens",
        &before.allowlists.tokens,
        &after.allowlists.tokens,
        &mut reasons,
    );
    check_allow_expansion(
        "contracts.allow",
        &before.contracts.allow,
        &after.contracts.allow,
        &mut reasons,
    );
    check_allow_expansion(
        "tokens.allow",
        &before.tokens.allow,
        &after.tokens.allow,
        &mut reasons,
    );

    check_deny_removal(
        "denylists.recipients",
        &before.denylists.recipients,
        &after.denylists.recipients,
        &mut reasons,
    );
    check_deny_removal(
        "denylists.contracts",
        &before.denylists.contracts,
        &after.denylists.contracts,
        &mut reasons,
    );
    check_deny_removal(
        "denylists.tokens",
        &before.denylists.tokens,
        &after.denylists.tokens,
        &mut reasons,
    );
    check_deny_removal(
        "contracts.deny",
        &before.contracts.deny,
        &after.contracts.deny,
        &mut reasons,
    );
    check_deny_removal(
        "tokens.deny",
        &before.tokens.deny,
        &after.tokens.deny,
        &mut reasons,
    );

    if reasons.is_empty() {
        PolicyEditClass::NotExpanding
    } else {
        PolicyEditClass::AuthorityExpanding { reasons }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpRuleCeilingValidation {
    pub unknown_rules: Vec<String>,
}

impl StepUpRuleCeilingValidation {
    pub fn is_ok(&self) -> bool {
        self.unknown_rules.is_empty()
    }
}

pub fn validate_step_up_rule_ceilings<'a>(
    policy: &Policy,
    emitted_rule_ids: impl IntoIterator<Item = &'a str>,
) -> StepUpRuleCeilingValidation {
    let emitted: BTreeSet<String> = emitted_rule_ids
        .into_iter()
        .map(|rule| rule.trim().to_string())
        .collect();
    let unknown_rules = policy
        .approval
        .step_up
        .rule_ceilings
        .keys()
        .filter(|rule| !emitted.contains(rule.as_str()))
        .cloned()
        .collect();
    StepUpRuleCeilingValidation { unknown_rules }
}

pub fn evaluate_action_authorization(
    policy: &Policy,
    policy_checks: &[PolicyCheck],
    subject: &AuthorizationSubject,
    budget: Option<&BudgetSnapshot>,
    fresh_review_intent_hash: Option<&str>,
    _surface: AuthorizationSurface,
) -> AutonomyDecision {
    if let Some(deny) = policy_checks.iter().find(|c| c.is_hard_violation()) {
        return AutonomyDecision::Denied {
            reason: format!("policy denied: {}: {}", deny.rule, deny.message),
        };
    }

    if let Some(hash) = fresh_review_intent_hash
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
            if let Some(warn) = policy_checks.iter().find(|c| c.is_soft_violation()) {
                return AutonomyDecision::NeedsFreshReview {
                    reason: format!(
                        "soft policy violation requires review: {}: {}",
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

fn autonomy_rank(mode: AgentAutonomyMode) -> u8 {
    match mode {
        AgentAutonomyMode::Disabled => 0,
        AgentAutonomyMode::PromptAll => 0,
        AgentAutonomyMode::UnderPolicy => 1,
    }
}

fn check_limit_increase(
    field: &str,
    before: Result<Option<i128>, String>,
    after: Result<Option<i128>, String>,
    reasons: &mut Vec<String>,
) {
    let (Ok(before), Ok(after)) = (before, after) else {
        reasons.push(format!("{field} parse changed or invalid"));
        return;
    };
    if option_cap_expands_i128(before, after) {
        reasons.push(format!("{field} increased"));
    }
}

fn option_cap_expands_i128(before: Option<i128>, after: Option<i128>) -> bool {
    match (before, after) {
        (Some(b), Some(a)) => a > b,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn option_cap_expands_u64(before: Option<u64>, after: Option<u64>) -> bool {
    match (before, after) {
        (Some(b), Some(a)) => a > b,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn option_cap_expands_u32(before: Option<u32>, after: Option<u32>) -> bool {
    match (before, after) {
        (Some(b), Some(a)) => a > b,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn check_rule_ceiling_increase(
    rule: &str,
    before: &StepUpRuleCeiling,
    after: &StepUpRuleCeiling,
    reasons: &mut Vec<String>,
) {
    check_limit_increase(
        &format!("approval.step_up.rule_ceilings.{rule}.max_usd"),
        before.max_micro_usd(rule),
        after.max_micro_usd(rule),
        reasons,
    );
    if option_cap_expands_u32(before.max_u32, after.max_u32) {
        reasons.push(format!(
            "approval.step_up.rule_ceilings.{rule}.max_u32 increased"
        ));
    }
    if option_cap_expands_u32(before.max_bps, after.max_bps) {
        reasons.push(format!(
            "approval.step_up.rule_ceilings.{rule}.max_bps increased"
        ));
    }
    if option_cap_expands_u64(before.max_count, after.max_count) {
        reasons.push(format!(
            "approval.step_up.rule_ceilings.{rule}.max_count increased"
        ));
    }
}

fn check_allow_expansion(
    field: &str,
    before: &BTreeSet<String>,
    after: &BTreeSet<String>,
    reasons: &mut Vec<String>,
) {
    if before.is_empty() {
        return;
    }
    if after.is_empty() || after.iter().any(|v| !before.contains(v)) {
        reasons.push(format!("{field} expanded"));
    }
}

fn check_deny_removal(
    field: &str,
    before: &BTreeSet<String>,
    after: &BTreeSet<String>,
    reasons: &mut Vec<String>,
) {
    if before.iter().any(|v| !after.contains(v)) {
        reasons.push(format!("{field} removed entries"));
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
    #[serde(default)]
    pub class: PolicyRuleClass,
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
            class: PolicyRuleClass::for_outcome(outcome),
            message: message.into(),
        }
    }

    pub fn hard(
        rule: impl Into<String>,
        outcome: PolicyOutcome,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule: rule.into(),
            outcome,
            class: PolicyRuleClass::Hard,
            message: message.into(),
        }
    }

    pub fn soft(
        rule: impl Into<String>,
        outcome: PolicyOutcome,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule: rule.into(),
            outcome,
            class: PolicyRuleClass::Soft,
            message: message.into(),
        }
    }

    pub fn informational(
        rule: impl Into<String>,
        outcome: PolicyOutcome,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule: rule.into(),
            outcome,
            class: PolicyRuleClass::Informational,
            message: message.into(),
        }
    }

    pub fn is_hard_violation(&self) -> bool {
        self.outcome == PolicyOutcome::Deny && self.class == PolicyRuleClass::Hard
    }

    pub fn is_soft_violation(&self) -> bool {
        self.outcome != PolicyOutcome::Pass && self.class == PolicyRuleClass::Soft
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleClass {
    Informational,
    Soft,
    #[default]
    Hard,
}

impl PolicyRuleClass {
    pub fn for_outcome(outcome: PolicyOutcome) -> Self {
        match outcome {
            PolicyOutcome::Pass => Self::Informational,
            PolicyOutcome::Warn => Self::Soft,
            PolicyOutcome::Deny => Self::Hard,
        }
    }
}

/// True when any check is a hard denial.
pub fn has_deny(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(PolicyCheck::is_hard_violation)
}

/// True when any check is a soft warning.
pub fn has_warn(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(|c| c.outcome == PolicyOutcome::Warn)
}

pub fn has_soft_violation(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(PolicyCheck::is_soft_violation)
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
        assert_eq!(p.approval.assurance, AssuranceLevel::Standard);
        assert!(!p.approval.step_up.enabled);
        assert_eq!(p.approval.step_up.ttl_secs, 120);
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

[approval]
assurance = "hardened"

[approval.step_up]
enabled = true
ttl_secs = 90
uv_above_usd = "250"

[approval.step_up.rule_ceilings]
"limits.max_tx_usd" = { max_usd = "500" }
"hyperliquid.max_leverage" = { max_u32 = 3 }
"#;
        let p: Policy = toml::from_str(toml_src).unwrap();
        assert!(p.private.enabled);
        assert_eq!(p.private.provider, "flashbots");
        assert_eq!(p.mev.max_slippage_bps, 250);
        assert!(p.mev.fail_on_high_risk);
        assert_eq!(p.bump.stuck_after_secs, 30);
        assert_eq!(p.bump.basefee_overrun_pct, 50);
        assert_eq!(p.approval.assurance, AssuranceLevel::Hardened);
        assert!(p.approval.step_up.enabled);
        assert_eq!(p.approval.step_up.ttl_secs, 90);
        assert_eq!(
            p.approval.step_up.uv_above_micro_usd().unwrap(),
            Some(250_000_000)
        );
        assert_eq!(
            p.approval
                .step_up
                .rule_ceilings
                .get("limits.max_tx_usd")
                .unwrap()
                .max_micro_usd("limits.max_tx_usd")
                .unwrap(),
            Some(500_000_000)
        );
        assert_eq!(
            p.approval
                .step_up
                .rule_ceilings
                .get("hyperliquid.max_leverage")
                .unwrap()
                .max_u32,
            Some(3)
        );
    }

    #[test]
    fn approval_step_up_invalid_usd_fails_closed_when_parsed() {
        let p: Policy = toml::from_str(
            r#"
[approval.step_up]
uv_above_usd = "1.0000001"
"#,
        )
        .unwrap();
        let err = p.approval.step_up.uv_above_micro_usd().unwrap_err();
        assert!(err.contains("at most 6 decimal places"), "{err}");
    }

    #[test]
    fn policy_check_constructors_assign_rule_classes() {
        let pass = PolicyCheck::for_venue("defi", "receiver", PolicyOutcome::Pass, "ok");
        let warn = PolicyCheck::soft("caps.soft", PolicyOutcome::Warn, "review");
        let deny = PolicyCheck::hard("geo.block", PolicyOutcome::Deny, "blocked");

        assert_eq!(pass.class, PolicyRuleClass::Informational);
        assert_eq!(warn.class, PolicyRuleClass::Soft);
        assert_eq!(deny.class, PolicyRuleClass::Hard);
        assert!(!has_deny(std::slice::from_ref(&warn)));
        assert!(has_soft_violation(&[warn]));
        assert!(has_deny(&[deny]));
    }

    #[test]
    fn legacy_policy_check_json_defaults_to_hard() {
        let check: PolicyCheck = serde_json::from_str(
            r#"{"rule":"legacy.deny","outcome":"deny","message":"old record"}"#,
        )
        .unwrap();
        assert_eq!(check.class, PolicyRuleClass::Hard);
        assert!(check.is_hard_violation());
    }

    #[test]
    fn soft_deny_requires_review_instead_of_hard_denying() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_day_usd = Some("100".into());
        let subject = AuthorizationSubject {
            kind: "test".into(),
            wallet: "my-wallet".into(),
            chain: Some("base".into()),
            subject_hash: "0".repeat(64),
            value_moving: true,
            total_value_usd_micro: Some(1_000_000),
            calldata_verified: true,
        };
        let budget = BudgetSnapshot {
            spent_day_micro_usd: 0,
            spent_week_micro_usd: 0,
            spent_month_micro_usd: 0,
        };
        let checks = vec![PolicyCheck::soft(
            "limits.max_tx_usd",
            PolicyOutcome::Deny,
            "can be escalated within ceiling",
        )];

        assert!(matches!(
            evaluate_action_authorization(
                &p,
                &checks,
                &subject,
                Some(&budget),
                None,
                AuthorizationSurface::Vfs
            ),
            AutonomyDecision::NeedsFreshReview { reason }
                if reason.contains("soft policy violation")
        ));
    }

    #[test]
    fn step_up_rule_ceiling_validation_rejects_unknown_rule_ids() {
        let mut p = Policy::default();
        p.approval.step_up.rule_ceilings.insert(
            "limits.max_tx_usd".into(),
            StepUpRuleCeiling {
                max_usd: Some("25".into()),
                ..StepUpRuleCeiling::default()
            },
        );
        p.approval.step_up.rule_ceilings.insert(
            "unknown.rule".into(),
            StepUpRuleCeiling {
                max_usd: Some("25".into()),
                ..StepUpRuleCeiling::default()
            },
        );

        let validation = validate_step_up_rule_ceilings(&p, ["limits.max_tx_usd"]);
        assert_eq!(validation.unknown_rules, vec!["unknown.rule".to_string()]);
        assert!(!validation.is_ok());
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

    #[test]
    fn under_policy_denies_unverified_calldata() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        let subject = AuthorizationSubject {
            calldata_verified: false,
            ..auth_subject(Some(1_000_000))
        };
        assert!(matches!(
            evaluate_action_authorization(
                &p, &[], &subject, Some(&budget()), None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason }
                if reason.contains("calldata/order facts")
        ));
    }

    #[test]
    fn under_policy_denies_missing_budget() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        assert!(matches!(
            evaluate_action_authorization(
                &p, &[], &auth_subject(Some(1_000_000)), None, None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason }
                if reason.contains("budget ledger")
        ));
    }

    #[test]
    fn under_policy_denies_missing_max_tx_usd() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_day_usd = Some("10".into());
        assert!(matches!(
            evaluate_action_authorization(
                &p, &[], &auth_subject(Some(1_000_000)), Some(&budget()), None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason }
                if reason.contains("max_tx_usd is required")
        ));
    }

    #[test]
    fn under_policy_denies_missing_max_day_usd() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        assert!(matches!(
            evaluate_action_authorization(
                &p, &[], &auth_subject(Some(1_000_000)), Some(&budget()), None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason }
                if reason.contains("max_day_usd is required")
        ));
    }

    #[test]
    fn under_policy_denies_week_cap_exceeded() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("100".into());
        p.limits.max_week_usd = Some("10".into());
        let b = BudgetSnapshot {
            spent_week_micro_usd: 9_000_000,
            ..budget()
        };
        assert!(matches!(
            evaluate_action_authorization(
                &p, &[], &auth_subject(Some(2_000_000)), Some(&b), None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason }
                if reason.contains("max_week_usd exceeded")
        ));
    }

    #[test]
    fn under_policy_denies_month_cap_exceeded() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("100".into());
        p.limits.max_week_usd = Some("100".into());
        p.limits.max_month_usd = Some("10".into());
        let b = BudgetSnapshot {
            spent_month_micro_usd: 9_000_000,
            ..budget()
        };
        assert!(matches!(
            evaluate_action_authorization(
                &p, &[], &auth_subject(Some(2_000_000)), Some(&b), None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason }
                if reason.contains("max_month_usd exceeded")
        ));
    }

    #[test]
    fn under_policy_denies_hard_violation() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        let checks = vec![PolicyCheck::hard(
            "denylist.recipients",
            PolicyOutcome::Deny,
            "recipient is on denylist",
        )];
        assert!(matches!(
            evaluate_action_authorization(
                &p, &checks, &auth_subject(Some(1_000_000)),
                Some(&budget()), None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::Denied { reason }
                if reason.contains("policy denied")
        ));
    }

    #[test]
    fn fresh_review_intent_hash_short_circuits_to_approved_fresh_review() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        // Even with no budget and no USD value, a verified fresh-review hash approves.
        assert!(matches!(
            evaluate_action_authorization(
                &p, &[], &auth_subject(None), None,
                Some("abc123"),
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::ApprovedFreshReview { review_hash }
                if review_hash == "abc123"
        ));
    }

    #[test]
    fn non_value_moving_auto_approves() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        let subject = AuthorizationSubject {
            value_moving: false,
            ..auth_subject(None)
        };
        assert!(matches!(
            evaluate_action_authorization(&p, &[], &subject, None, None, AuthorizationSurface::Vfs,),
            AutonomyDecision::ApprovedAutonomous { .. }
        ));
    }

    #[test]
    fn prompt_all_needs_review() {
        let mut p = Policy::default();
        p.approval.agent_autonomy = Some(AgentAutonomyMode::PromptAll);
        p.limits.max_tx_usd = Some("3".into());
        p.limits.max_day_usd = Some("10".into());
        assert!(matches!(
            evaluate_action_authorization(
                &p, &[], &auth_subject(Some(1_000_000)),
                Some(&budget()), None,
                AuthorizationSurface::Vfs,
            ),
            AutonomyDecision::NeedsFreshReview { reason }
                if reason.contains("prompt_all")
        ));
    }

    #[test]
    fn policy_edit_classifier_flags_authority_expansion() {
        let mut before = Policy::default();
        before.approval.assurance = AssuranceLevel::Hardened;
        before.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        before.limits.max_tx_usd = Some("10".into());
        before.allowlists.recipients.insert("alice".into());
        before.approval.step_up.rule_ceilings.insert(
            "limits.max_tx_usd".into(),
            StepUpRuleCeiling {
                max_usd: Some("25".into()),
                ..StepUpRuleCeiling::default()
            },
        );

        let mut after = before.clone();
        after.approval.assurance = AssuranceLevel::Standard;
        after.limits.max_tx_usd = Some("20".into());
        after.allowlists.recipients.insert("bob".into());
        after
            .approval
            .step_up
            .rule_ceilings
            .get_mut("limits.max_tx_usd")
            .unwrap()
            .max_usd = Some("50".into());

        let class = classify_policy_edit(&before, &after);
        let PolicyEditClass::AuthorityExpanding { reasons } = class else {
            panic!("expected authority expansion");
        };
        assert!(
            reasons.iter().any(|r| r.contains("hardened -> standard")),
            "{reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| r.contains("limits.max_tx_usd")),
            "{reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| r.contains("allowlists.recipients")),
            "{reasons:?}"
        );
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("rule_ceilings.limits.max_tx_usd")),
            "{reasons:?}"
        );
    }

    #[test]
    fn policy_edit_classifier_allows_tightening() {
        let mut before = Policy::default();
        before.approval.assurance = AssuranceLevel::Standard;
        before.approval.agent_autonomy = Some(AgentAutonomyMode::UnderPolicy);
        before.limits.max_tx_usd = Some("10".into());
        before.limits.max_day_usd = Some("100".into());

        let mut after = before.clone();
        after.approval.assurance = AssuranceLevel::Hardened;
        after.limits.max_tx_usd = Some("5".into());
        after.denylists.recipients.insert("blocked".into());

        assert_eq!(
            classify_policy_edit(&before, &after),
            PolicyEditClass::NotExpanding
        );
    }
}
