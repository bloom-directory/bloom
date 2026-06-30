//! First-class Hyperliquid action policy.
//!
//! Hyperliquid exchange actions (orders, leverage changes, and — once
//! implemented — withdrawals/transfers) move real money but never flow through
//! the EVM [`crate::policy::PolicyCaps`]. This section is the hard boundary for
//! them: without it, any action signs the moment the wallet is unlocked.
//!
//! The evaluator is **pure over a pre-fetched context snapshot**
//! ([`HyperliquidActionCtx`]), exactly like [`crate::polymarket_policy`]:
//! request-derivable caps (asset, order type, leverage, notional) are checked
//! from the action itself, while position/loss/cumulative-notional caps require
//! the caller (daemon) to populate live clearinghouse state. When a stateful cap
//! is configured but its snapshot is unavailable (`snapshot_readable = false`),
//! the action is **denied** — fail closed, mirroring
//! `PolymarketOrderCtx.receipt_store_readable`.
//!
//! Money is integer **micro-USD** (6 dp) end to end; no floats touch decisions.
//! Unknown / not-yet-supported action kinds **default-deny**, so new actions
//! (e.g. `withdraw3`, `usdSend`) are safe until they are explicitly mapped here.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::policy::{PolicyCheck, PolicyOutcome};

fn default_true() -> bool {
    true
}

/// `[hyperliquid]` section of a wallet's policy file. All caps default to
/// unconfigured (no constraint); a `None`/empty value never restricts. The
/// boundary is opt-in per cap — except unknown action kinds, which always deny.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperliquidPolicy {
    /// Tradable coins (e.g. `"BTC"`). Empty = unrestricted.
    #[serde(default)]
    pub allowed_assets: BTreeSet<String>,
    /// Permitted order types (`"limit"`, `"trigger"`, `"twap"`). Empty =
    /// unrestricted.
    #[serde(default)]
    pub allowed_order_types: BTreeSet<String>,
    /// Max per-order notional, micro-USD (TOML decimal string, e.g. `"500"`).
    #[serde(default, with = "crate::serde_micro")]
    pub max_notional_usd: Option<u64>,
    /// Max absolute position notional per asset, micro-USD (needs snapshot).
    #[serde(default, with = "crate::serde_micro")]
    pub max_position_usd: Option<u64>,
    /// Max tolerated loss before a new action may add more risk, micro-USD
    /// (needs snapshot). The pure per-action evaluator intentionally keys off
    /// the current unrealized-loss estimate only; realized session drawdown is
    /// a session-lifecycle concern enforced by the monitoring loop.
    #[serde(default, with = "crate::serde_micro")]
    pub max_loss_usd: Option<u64>,
    /// Max leverage multiplier.
    #[serde(default)]
    pub max_leverage: Option<u32>,
    /// Max single withdrawal, micro-USD (enforced once a withdraw action lands).
    #[serde(default, with = "crate::serde_micro")]
    pub withdrawal_cap_usd: Option<u64>,
    /// Max single transfer, micro-USD (enforced once a transfer action lands).
    #[serde(default, with = "crate::serde_micro")]
    pub transfer_cap_usd: Option<u64>,
    /// Max bounded-session duration in seconds (consumed by Phase 2 sessions).
    #[serde(default)]
    pub max_session_secs: Option<u64>,
    #[serde(default = "default_true")]
    pub allow_reduce_only: bool,
    #[serde(default = "default_true")]
    pub allow_trigger_orders: bool,
    #[serde(default = "default_true")]
    pub allow_twap: bool,
    #[serde(default = "default_true")]
    pub allow_builder_fees: bool,
    #[serde(default = "default_true")]
    pub allow_vault_or_subaccount: bool,
}

impl HyperliquidPolicy {
    /// True when the wallet has opted into *any* Hyperliquid constraint (a cap,
    /// an allowlist, or a disabled action class). Used by `status` to show
    /// whether a trading boundary is actually in force.
    pub fn is_configured(&self) -> bool {
        !self.allowed_assets.is_empty()
            || !self.allowed_order_types.is_empty()
            || self.max_notional_usd.is_some()
            || self.max_position_usd.is_some()
            || self.max_loss_usd.is_some()
            || self.max_leverage.is_some()
            || self.withdrawal_cap_usd.is_some()
            || self.transfer_cap_usd.is_some()
            || self.max_session_secs.is_some()
            || !self.allow_reduce_only
            || !self.allow_trigger_orders
            || !self.allow_twap
            || !self.allow_builder_fees
            || !self.allow_vault_or_subaccount
    }

    /// True when the policy contains at least one trading constraint. Transfer
    /// and session-only fields do not make owner-signed orders safe by
    /// themselves.
    pub fn is_trading_configured(&self) -> bool {
        !self.allowed_assets.is_empty()
            || !self.allowed_order_types.is_empty()
            || self.max_notional_usd.is_some()
            || self.max_position_usd.is_some()
            || self.max_loss_usd.is_some()
            || self.max_leverage.is_some()
            || !self.allow_reduce_only
            || !self.allow_trigger_orders
            || !self.allow_twap
            || !self.allow_builder_fees
            || !self.allow_vault_or_subaccount
    }

    /// True when the policy has the minimum caps required to mint a bounded
    /// trading session. Without all four of these an agent session would have
    /// no meaningful per-order size, position, or loss limit.
    pub fn is_session_capable(&self) -> bool {
        !self.allowed_assets.is_empty()
            && self.max_notional_usd.is_some()
            && self.max_position_usd.is_some()
            && self.max_loss_usd.is_some()
    }
}

impl Default for HyperliquidPolicy {
    fn default() -> Self {
        Self {
            allowed_assets: BTreeSet::new(),
            allowed_order_types: BTreeSet::new(),
            max_notional_usd: None,
            max_position_usd: None,
            max_loss_usd: None,
            max_leverage: None,
            withdrawal_cap_usd: None,
            transfer_cap_usd: None,
            max_session_secs: None,
            allow_reduce_only: true,
            allow_trigger_orders: true,
            allow_twap: true,
            allow_builder_fees: true,
            allow_vault_or_subaccount: true,
        }
    }
}

/// Everything `evaluate_hyperliquid_action` needs about one action. The caller
/// maps an `ExchangeAction` here and populates the live snapshot fields.
#[derive(Debug, Clone, Default)]
pub struct HyperliquidActionCtx {
    pub wallet: String,
    /// `ExchangeAction::kind()` — `"order"`, `"cancel"`, `"scheduleCancel"`,
    /// `"cancelByCloid"`, `"updateLeverage"`, or a withdraw/transfer kind.
    pub action_kind: String,
    pub asset: Option<String>,
    pub reduce_only: bool,
    /// `"limit"`, `"trigger"`, `"twap"`.
    pub order_type: Option<String>,
    pub builder_fee: bool,
    pub vault_or_subaccount: bool,
    pub leverage: Option<u32>,
    /// Order notional (size × price), micro-USD, when computable.
    pub notional_microusd: Option<u64>,
    // ── caller-fetched live snapshot ──
    /// Current absolute position notional for `asset`, micro-USD.
    pub position_microusd: Option<u64>,
    /// Notional of this wallet's already-resting (unfilled) open orders for
    /// `asset`, micro-USD. Counted toward the `max_position_usd` projection so a
    /// burst of individually-under-cap orders can't collectively breach the cap
    /// on fill. `None` means the caller couldn't read open orders; when a
    /// position cap is configured this fails closed.
    pub resting_notional_microusd: Option<u64>,
    /// Estimated unrealized loss, micro-USD (the per-action loss signal; the
    /// session monitor's account-value drawdown is the real loss stop).
    pub est_unrealized_loss_microusd: Option<u64>,
    /// Whether the live clearinghouse snapshot could be read. When false and a
    /// stateful cap (position/loss) is configured, deny (fail closed).
    pub snapshot_readable: bool,
}

use crate::serde_micro::fmt_usd;

fn check(rule: &str, outcome: PolicyOutcome, message: impl Into<String>) -> PolicyCheck {
    PolicyCheck::for_venue("hyperliquid", rule, outcome, message)
}

/// Is this action risk-reducing (cancels, reduce-only orders)? Such actions
/// bypass risk-*adding* caps (notional/position) but still face asset/type gates.
fn is_risk_reducing(ctx: &HyperliquidActionCtx) -> bool {
    matches!(
        ctx.action_kind.as_str(),
        "cancel" | "cancelByCloid" | "scheduleCancel"
    ) || (ctx.action_kind == "order" && ctx.reduce_only)
}

/// Asset allowlist gate. Fail closed: when an allowlist is set but the coin
/// couldn't be resolved (`ctx.asset == None` — a perp-meta lookup failure or a
/// spot order), deny rather than silently skip the gate. Shared by the order
/// path and the updateLeverage path.
fn push_asset_check(
    out: &mut Vec<PolicyCheck>,
    policy: &HyperliquidPolicy,
    ctx: &HyperliquidActionCtx,
) {
    match (&ctx.asset, policy.allowed_assets.is_empty()) {
        (Some(asset), false) if !policy.allowed_assets.contains(asset) => out.push(check(
            "asset",
            PolicyOutcome::Deny,
            format!("'{asset}' is not on the allowed_assets allowlist"),
        )),
        (Some(asset), _) => out.push(check(
            "asset",
            PolicyOutcome::Pass,
            format!("'{asset}' permitted"),
        )),
        (None, false) => out.push(check(
            "asset",
            PolicyOutcome::Deny,
            "asset could not be resolved while an allowed_assets allowlist is set (fail closed)",
        )),
        (None, true) => {}
    }
}

/// Vault/subaccount gate. Shared by the order path and the updateLeverage path.
fn push_vault_check(
    out: &mut Vec<PolicyCheck>,
    policy: &HyperliquidPolicy,
    ctx: &HyperliquidActionCtx,
) {
    if ctx.vault_or_subaccount && !policy.allow_vault_or_subaccount {
        out.push(check(
            "vault",
            PolicyOutcome::Deny,
            "vault/subaccount actions are disabled by policy",
        ));
    }
}

/// Evaluate one Hyperliquid action. Returns the full check list (passes
/// included). Deny-level outcomes are not CLI-bypassable; `Warn` is.
pub fn evaluate_hyperliquid_action(
    policy: &HyperliquidPolicy,
    ctx: &HyperliquidActionCtx,
) -> Vec<PolicyCheck> {
    let mut out = Vec::new();

    // Action-kind gate: known kinds proceed; anything else default-denies so a
    // newly added action can't sign before it is mapped into this evaluator.
    match ctx.action_kind.as_str() {
        "order" | "cancel" | "cancelByCloid" | "scheduleCancel" | "updateLeverage" => {
            out.push(check(
                "action",
                PolicyOutcome::Pass,
                format!("action '{}' is recognized", ctx.action_kind),
            ));
        }
        "usdSend" => {
            // Owner-signed internal USDC transfer. Requires transfer_cap_usd;
            // no cap configured = deny (transfers are opt-in, not default-allow).
            return match policy.transfer_cap_usd {
                None => vec![check(
                    "action",
                    PolicyOutcome::Deny,
                    "usdSend requires transfer_cap_usd in the wallet [hyperliquid] policy",
                )],
                Some(cap) => match ctx.notional_microusd {
                    Some(amount) if amount > cap => vec![check(
                        "transfer_cap_usd",
                        PolicyOutcome::Deny,
                        format!("transfer {} exceeds cap {}", fmt_usd(amount), fmt_usd(cap)),
                    )],
                    Some(amount) => vec![check(
                        "transfer_cap_usd",
                        PolicyOutcome::Pass,
                        format!("transfer {} within cap {}", fmt_usd(amount), fmt_usd(cap)),
                    )],
                    None => vec![check(
                        "transfer_cap_usd",
                        PolicyOutcome::Deny,
                        "transfer amount unknown; fail closed",
                    )],
                },
            };
        }
        "withdraw" | "withdraw3" | "spotSend" | "usdClassTransfer" | "agentSendAsset" => {
            // Not yet policy-enforced; deny until mapped.
            return vec![check(
                "action",
                PolicyOutcome::Deny,
                format!(
                    "action '{}' (withdraw/transfer) is not yet policy-enforced; denied",
                    ctx.action_kind
                ),
            )];
        }
        other => {
            return vec![check(
                "action",
                PolicyOutcome::Deny,
                format!("unknown/unsupported action '{other}'; denied (default-deny)"),
            )];
        }
    }

    // updateLeverage: gate on max_leverage, but still honor the asset allowlist
    // and the vault/subaccount gate — a leverage change targets a specific coin
    // and can be aimed at a vault/subaccount, so those bounds must apply here too.
    if ctx.action_kind == "updateLeverage" {
        out.push(leverage_check(policy, ctx.leverage));
        push_asset_check(&mut out, policy, ctx);
        push_vault_check(&mut out, policy, ctx);
        return out;
    }

    // Cancels are risk-reducing; only the action gate above applies.
    if matches!(
        ctx.action_kind.as_str(),
        "cancel" | "cancelByCloid" | "scheduleCancel"
    ) {
        out.push(check(
            "caps",
            PolicyOutcome::Pass,
            "cancel is risk-reducing",
        ));
        return out;
    }

    // ── order ──
    push_asset_check(&mut out, policy, ctx);

    // Order-type allowlist + per-type allow flags.
    if let Some(ot) = &ctx.order_type {
        if !policy.allowed_order_types.is_empty() && !policy.allowed_order_types.contains(ot) {
            out.push(check(
                "order_type",
                PolicyOutcome::Deny,
                format!("order type '{ot}' is not on the allowed_order_types allowlist"),
            ));
        } else if ot == "trigger" && !policy.allow_trigger_orders {
            out.push(check(
                "order_type",
                PolicyOutcome::Deny,
                "trigger orders are disabled by policy",
            ));
        } else if ot == "twap" && !policy.allow_twap {
            out.push(check(
                "order_type",
                PolicyOutcome::Deny,
                "TWAP orders are disabled by policy",
            ));
        } else {
            out.push(check(
                "order_type",
                PolicyOutcome::Pass,
                format!("'{ot}' permitted"),
            ));
        }
    }

    if ctx.reduce_only && !policy.allow_reduce_only {
        out.push(check(
            "reduce_only",
            PolicyOutcome::Deny,
            "reduce-only orders are disabled by policy",
        ));
    }
    if ctx.builder_fee && !policy.allow_builder_fees {
        out.push(check(
            "builder_fee",
            PolicyOutcome::Deny,
            "builder-fee orders are disabled by policy",
        ));
    }
    push_vault_check(&mut out, policy, ctx);

    // Risk-adding caps below apply only to risk-adding orders.
    if is_risk_reducing(ctx) {
        out.push(check(
            "caps",
            PolicyOutcome::Pass,
            "reduce-only order is risk-reducing; notional/position caps not applied",
        ));
        return out;
    }

    // max_notional (request-derivable for perps: size × price).
    if let Some(cap) = policy.max_notional_usd {
        match ctx.notional_microusd {
            Some(n) if n > cap => out.push(check(
                "max_notional_usd",
                PolicyOutcome::Deny,
                format!("order notional {} exceeds cap {}", fmt_usd(n), fmt_usd(cap)),
            )),
            Some(n) => out.push(check(
                "max_notional_usd",
                PolicyOutcome::Pass,
                format!("{} <= {}", fmt_usd(n), fmt_usd(cap)),
            )),
            None => out.push(check(
                "max_notional_usd",
                PolicyOutcome::Deny,
                "notional cap configured but order notional is unknown (fail closed)",
            )),
        }
    }

    // Stateful caps need the live snapshot. Fail closed if unavailable.
    let stateful_configured = policy.max_position_usd.is_some() || policy.max_loss_usd.is_some();
    if stateful_configured && !ctx.snapshot_readable {
        out.push(check(
            "snapshot",
            PolicyOutcome::Deny,
            "position/loss caps configured but live account snapshot is unavailable (fail closed)",
        ));
        return out;
    }

    if let Some(cap) = policy.max_position_usd {
        // Projected exposure ≈ current position + already-resting open-order
        // notional + this order's notional. Resting orders must be counted so
        // a series of individually-under-cap orders can't collectively breach
        // the cap once they fill. Fail closed when the resting figure is
        // unavailable, and when the current position is unavailable, because a
        // configured cap we can't fully evaluate must not silently pass.
        match (ctx.position_microusd, ctx.resting_notional_microusd) {
            (None, _) => out.push(check(
                "max_position_usd",
                PolicyOutcome::Deny,
                "position cap configured but current position is unavailable (fail closed)",
            )),
            (_, None) => out.push(check(
                "max_position_usd",
                PolicyOutcome::Deny,
                "position cap configured but resting open-order notional is unavailable (fail closed)",
            )),
            (Some(position), Some(resting)) => {
                let projected = position
                    .saturating_add(resting)
                    .saturating_add(ctx.notional_microusd.unwrap_or(0));
                if projected > cap {
                    out.push(check(
                        "max_position_usd",
                        PolicyOutcome::Deny,
                        format!(
                            "projected position {} exceeds cap {}",
                            fmt_usd(projected),
                            fmt_usd(cap)
                        ),
                    ));
                } else {
                    out.push(check(
                        "max_position_usd",
                        PolicyOutcome::Pass,
                        format!("{} <= {}", fmt_usd(projected), fmt_usd(cap)),
                    ));
                }
            }
        }
    }

    if let Some(cap) = policy.max_loss_usd {
        // This gate answers "is the account already too underwater to add more
        // risk right now?" It intentionally uses the current unrealized-loss
        // snapshot only. Session-level realized + unrealized drawdown belongs
        // to the Hyperliquid session monitor, which can halt and flatten
        // independently of this pure action evaluator.
        match ctx.est_unrealized_loss_microusd {
            None => out.push(check(
                "max_loss_usd",
                PolicyOutcome::Deny,
                "loss cap configured but unrealized-loss snapshot is unavailable (fail closed)",
            )),
            Some(loss) if loss > cap => out.push(check(
                "max_loss_usd",
                PolicyOutcome::Deny,
                format!(
                    "session loss {} exceeds cap {} — refusing new risk",
                    fmt_usd(loss),
                    fmt_usd(cap)
                ),
            )),
            Some(loss) => out.push(check(
                "max_loss_usd",
                PolicyOutcome::Pass,
                format!("loss {} <= {}", fmt_usd(loss), fmt_usd(cap)),
            )),
        }
    }

    out
}

fn leverage_check(policy: &HyperliquidPolicy, leverage: Option<u32>) -> PolicyCheck {
    match (policy.max_leverage, leverage) {
        (Some(max), Some(lev)) if lev > max => check(
            "max_leverage",
            PolicyOutcome::Deny,
            format!("leverage {lev}x exceeds cap {max}x"),
        ),
        (Some(max), Some(lev)) => check(
            "max_leverage",
            PolicyOutcome::Pass,
            format!("{lev}x <= {max}x"),
        ),
        (Some(_), None) => check(
            "max_leverage",
            PolicyOutcome::Deny,
            "leverage cap configured but requested leverage is unknown (fail closed)",
        ),
        (None, _) => check("max_leverage", PolicyOutcome::Pass, "no leverage cap"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serde_micro::MICRO_USD;

    fn order_ctx(asset: &str) -> HyperliquidActionCtx {
        HyperliquidActionCtx {
            wallet: "alice".into(),
            action_kind: "order".into(),
            asset: Some(asset.into()),
            order_type: Some("limit".into()),
            notional_microusd: Some(100 * MICRO_USD),
            snapshot_readable: true,
            ..Default::default()
        }
    }

    fn denied(checks: &[PolicyCheck]) -> bool {
        checks.iter().any(|c| c.outcome == PolicyOutcome::Deny)
    }

    #[test]
    fn permissive_default_allows_a_plain_order() {
        let p = HyperliquidPolicy::default();
        assert!(!denied(&evaluate_hyperliquid_action(&p, &order_ctx("BTC"))));
    }

    #[test]
    fn unknown_action_is_denied() {
        let p = HyperliquidPolicy::default();
        let mut ctx = order_ctx("BTC");
        ctx.action_kind = "frobnicate".into();
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn withdraw_transfer_kinds_default_deny() {
        let p = HyperliquidPolicy::default();
        for kind in ["withdraw3", "spotSend", "usdClassTransfer"] {
            let mut ctx = order_ctx("BTC");
            ctx.action_kind = kind.into();
            assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)), "{kind}");
        }
        // usdSend without transfer_cap_usd is also denied.
        let mut ctx = order_ctx("BTC");
        ctx.action_kind = "usdSend".into();
        ctx.notional_microusd = Some(100 * MICRO_USD);
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn usd_send_allowed_within_transfer_cap() {
        let p = HyperliquidPolicy {
            transfer_cap_usd: Some(200 * MICRO_USD),
            ..Default::default()
        };
        let mut ctx = order_ctx("BTC");
        ctx.action_kind = "usdSend".into();
        ctx.notional_microusd = Some(100 * MICRO_USD);
        assert!(!denied(&evaluate_hyperliquid_action(&p, &ctx)));

        // Over the cap.
        let mut ctx2 = order_ctx("BTC");
        ctx2.action_kind = "usdSend".into();
        ctx2.notional_microusd = Some(300 * MICRO_USD);
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx2)));
    }

    #[test]
    fn disallowed_asset_and_order_type() {
        let p = HyperliquidPolicy {
            allowed_assets: BTreeSet::from(["BTC".to_string()]),
            ..Default::default()
        };
        assert!(denied(&evaluate_hyperliquid_action(&p, &order_ctx("ETH"))));
        let p2 = HyperliquidPolicy {
            allowed_order_types: BTreeSet::from(["limit".to_string()]),
            ..Default::default()
        };
        let mut ctx = order_ctx("BTC");
        ctx.order_type = Some("trigger".into());
        assert!(denied(&evaluate_hyperliquid_action(&p2, &ctx)));
    }

    #[test]
    fn notional_cap_denies_oversized_order() {
        let p = HyperliquidPolicy {
            max_notional_usd: Some(50 * MICRO_USD),
            ..Default::default()
        };
        assert!(denied(&evaluate_hyperliquid_action(&p, &order_ctx("BTC")))); // 100 > 50
    }

    #[test]
    fn leverage_cap_gates_update_leverage() {
        let p = HyperliquidPolicy {
            max_leverage: Some(5),
            ..Default::default()
        };
        let ctx = HyperliquidActionCtx {
            action_kind: "updateLeverage".into(),
            leverage: Some(10),
            snapshot_readable: true,
            ..Default::default()
        };
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn stateful_caps_fail_closed_without_snapshot() {
        let p = HyperliquidPolicy {
            max_position_usd: Some(1_000 * MICRO_USD),
            ..Default::default()
        };
        let mut ctx = order_ctx("BTC");
        ctx.snapshot_readable = false;
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn loss_cap_fails_closed_without_loss_snapshot() {
        let p = HyperliquidPolicy {
            max_loss_usd: Some(20 * MICRO_USD),
            ..Default::default()
        };
        let mut ctx = order_ctx("BTC");
        ctx.est_unrealized_loss_microusd = None;
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn loss_cap_denies_new_risk_over_unrealized_threshold() {
        let p = HyperliquidPolicy {
            max_loss_usd: Some(20 * MICRO_USD),
            ..Default::default()
        };
        let mut ctx = order_ctx("BTC");
        ctx.est_unrealized_loss_microusd = Some(25 * MICRO_USD); // 25 > 20
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn reduce_only_order_bypasses_risk_adding_caps() {
        let p = HyperliquidPolicy {
            max_notional_usd: Some(50 * MICRO_USD),
            max_position_usd: Some(MICRO_USD),
            ..Default::default()
        };
        let mut ctx = order_ctx("BTC"); // 100 notional, over both caps
        ctx.reduce_only = true;
        assert!(!denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn reduce_only_close_on_delisted_asset_is_denied() {
        // A reduce-only close on an asset no longer in the allowlist is DENIED by
        // trading policy — which is exactly why monitor-forced session cleanup
        // (and owner orphan recovery) must bypass `enforce_hyperliquid_policy`
        // rather than route the flatten through it.
        let p = HyperliquidPolicy {
            allowed_assets: BTreeSet::from(["BTC".to_string()]),
            ..Default::default()
        };
        let mut ctx = order_ctx("ETH");
        ctx.reduce_only = true;
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn cancel_is_always_allowed() {
        let p = HyperliquidPolicy::default();
        let ctx = HyperliquidActionCtx {
            action_kind: "cancel".into(),
            snapshot_readable: false,
            ..Default::default()
        };
        assert!(!denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn is_session_capable_requires_all_critical_caps() {
        // Default policy with no caps is NOT session-capable.
        assert!(!HyperliquidPolicy::default().is_session_capable());

        // allowed_assets alone is not enough.
        let p = HyperliquidPolicy {
            allowed_assets: BTreeSet::from(["BTC".to_string()]),
            ..Default::default()
        };
        assert!(!p.is_session_capable());

        // Adding max_notional_usd is still not enough.
        let p = HyperliquidPolicy {
            allowed_assets: BTreeSet::from(["BTC".to_string()]),
            max_notional_usd: Some(100 * MICRO_USD),
            ..Default::default()
        };
        assert!(!p.is_session_capable());

        // Adding max_position_usd is still not enough.
        let p = HyperliquidPolicy {
            allowed_assets: BTreeSet::from(["BTC".to_string()]),
            max_notional_usd: Some(100 * MICRO_USD),
            max_position_usd: Some(500 * MICRO_USD),
            ..Default::default()
        };
        assert!(!p.is_session_capable());

        // All four required caps → session-capable.
        let p = HyperliquidPolicy {
            allowed_assets: BTreeSet::from(["BTC".to_string()]),
            max_notional_usd: Some(100 * MICRO_USD),
            max_position_usd: Some(500 * MICRO_USD),
            max_loss_usd: Some(50 * MICRO_USD),
            ..Default::default()
        };
        assert!(p.is_session_capable());
    }

    #[test]
    fn update_leverage_honors_asset_allowlist() {
        // updateLeverage on a coin outside allowed_assets must be denied even
        // though the leverage itself is within cap.
        let p = HyperliquidPolicy {
            allowed_assets: BTreeSet::from(["BTC".to_string()]),
            max_leverage: Some(10),
            ..Default::default()
        };
        let ctx = HyperliquidActionCtx {
            action_kind: "updateLeverage".into(),
            asset: Some("ETH".into()),
            leverage: Some(5),
            snapshot_readable: true,
            ..Default::default()
        };
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));

        // Same change on an allowlisted coin within the leverage cap passes.
        let ctx_ok = HyperliquidActionCtx {
            action_kind: "updateLeverage".into(),
            asset: Some("BTC".into()),
            leverage: Some(5),
            snapshot_readable: true,
            ..Default::default()
        };
        assert!(!denied(&evaluate_hyperliquid_action(&p, &ctx_ok)));
    }

    #[test]
    fn update_leverage_honors_vault_gate() {
        let p = HyperliquidPolicy {
            allow_vault_or_subaccount: false,
            ..Default::default()
        };
        let ctx = HyperliquidActionCtx {
            action_kind: "updateLeverage".into(),
            asset: Some("BTC".into()),
            leverage: Some(2),
            vault_or_subaccount: true,
            snapshot_readable: true,
            ..Default::default()
        };
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn max_position_counts_resting_open_orders() {
        let p = HyperliquidPolicy {
            max_position_usd: Some(1_000 * MICRO_USD),
            ..Default::default()
        };
        // position 0 + resting 950 + this order 100 = 1050 > 1000 → denied,
        // even though the new order alone (100) is far under the cap.
        let mut ctx = order_ctx("BTC");
        ctx.position_microusd = Some(0);
        ctx.resting_notional_microusd = Some(950 * MICRO_USD);
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));

        // position 0 + resting 800 + 100 = 900 <= 1000 → allowed.
        let mut ctx_ok = order_ctx("BTC");
        ctx_ok.position_microusd = Some(0);
        ctx_ok.resting_notional_microusd = Some(800 * MICRO_USD);
        assert!(!denied(&evaluate_hyperliquid_action(&p, &ctx_ok)));
    }

    #[test]
    fn max_position_fails_closed_without_resting_notional() {
        let p = HyperliquidPolicy {
            max_position_usd: Some(1_000 * MICRO_USD),
            ..Default::default()
        };
        // Snapshot readable but resting open-order notional unavailable → deny.
        let mut ctx = order_ctx("BTC");
        ctx.position_microusd = Some(0);
        ctx.resting_notional_microusd = None;
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn max_position_fails_closed_without_current_position() {
        let p = HyperliquidPolicy {
            max_position_usd: Some(1_000 * MICRO_USD),
            ..Default::default()
        };
        let mut ctx = order_ctx("BTC");
        ctx.position_microusd = None;
        ctx.resting_notional_microusd = Some(0);
        assert!(denied(&evaluate_hyperliquid_action(&p, &ctx)));
    }

    #[test]
    fn is_configured_still_true_with_any_field() {
        // is_configured() is the weaker gate for one-shot trades.
        // It should remain true with just one field set.
        let p = HyperliquidPolicy {
            max_session_secs: Some(3600),
            ..Default::default()
        };
        assert!(p.is_configured());
        assert!(!p.is_session_capable()); // but NOT session-capable
    }

    #[test]
    fn trading_config_excludes_transfer_and_session_only_fields() {
        let transfer_only = HyperliquidPolicy {
            transfer_cap_usd: Some(100 * MICRO_USD),
            withdrawal_cap_usd: Some(100 * MICRO_USD),
            max_session_secs: Some(60),
            ..Default::default()
        };
        assert!(transfer_only.is_configured());
        assert!(!transfer_only.is_trading_configured());
        assert!(!transfer_only.is_session_capable());

        let session_capable = HyperliquidPolicy {
            allowed_assets: BTreeSet::from(["BTC".to_string()]),
            max_notional_usd: Some(10 * MICRO_USD),
            max_position_usd: Some(100 * MICRO_USD),
            max_loss_usd: Some(5 * MICRO_USD),
            ..Default::default()
        };
        assert!(session_capable.is_trading_configured());
        assert!(session_capable.is_session_capable());
    }
}
