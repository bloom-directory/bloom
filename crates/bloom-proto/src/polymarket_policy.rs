//! First-class Polymarket order policy.
//!
//! A Polymarket order has `value_wei = 0` but creates real USD exposure, so
//! the EVM caps in [`crate::policy::PolicyCaps`] never see it. This section
//! models that risk directly.
//!
//! Money is **integer micro-USD** (6 dp, matching pUSD) end to end: TOML
//! accepts decimal strings (`max_order_usd = "10"`), and all comparison and
//! accumulation is integer math — no floats touch policy decisions. Prices
//! are micro-probabilities on the same scale (`"0.75"` → `750_000`).
//!
//! Semantics:
//! - `enabled = false` (the default) refuses all order placement. Fail closed.
//! - **Deny-level outcomes cannot be bypassed from the command line.** They
//!   change only by editing the wallet's policy file — a separate, auditable
//!   capability boundary. Only `require_flag_above_usd` produces a `Warn`,
//!   acknowledged with an explicit CLI flag.
//! - Hard market invariants (closed / inactive / no order book / non-binary)
//!   are not policy knobs; they always deny.
//! - Allow/deny lists: an empty allowlist means unrestricted; a non-empty
//!   allowlist is allowlist-only; deny always wins over allow. The same rules
//!   apply independently to slugs and condition ids.
//! - The daily cap counts **posted** order amounts over the trailing 24 h. If
//!   the receipt store backing that number is unreadable, orders are refused
//!   rather than silently uncapped.
//! - Money caps apply to BUY orders (risk-adding). SELL orders are
//!   risk-reducing and only pass through the enabled / market-invariant /
//!   list / neg-risk gates.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::policy::{PolicyCheck, PolicyOutcome};

fn default_true() -> bool {
    true
}

/// `[polymarket]` section of a wallet's policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymarketPolicy {
    /// Master gate. Defaults to **false**: a wallet cannot place Polymarket
    /// orders until its owner opts in via the policy file.
    #[serde(default)]
    pub enabled: bool,
    /// Hard cap per order, micro-USD (TOML: decimal string, e.g. `"10"`).
    #[serde(default, with = "crate::serde_micro")]
    pub max_order_usd: Option<u64>,
    /// Hard cap on posted exposure per trailing 24 h, micro-USD.
    #[serde(default, with = "crate::serde_micro")]
    pub max_daily_usd: Option<u64>,
    /// Orders above this require the explicit `--confirm-risk` flag (Warn).
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
            enabled: false,
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

/// Order side for policy purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicySide {
    Buy,
    Sell,
}

/// Everything `evaluate_polymarket_order` needs to know about one order.
#[derive(Debug, Clone)]
pub struct PolymarketOrderCtx {
    pub wallet: String,
    pub slug: String,
    pub condition_id: String,
    pub side: PolicySide,
    /// USD leg of the order in micro-USD (spend for buys, proceeds for sells).
    pub amount_microusd: u64,
    /// Limit price in micro-units.
    pub limit_price_micro: u64,
    pub active: bool,
    pub closed: bool,
    pub order_book_enabled: bool,
    pub binary_outcomes: bool,
    pub neg_risk: bool,
    /// Whether the durable receipt store could be read. When false and a
    /// daily cap is configured, the order is refused (fail closed).
    pub receipt_store_readable: bool,
    /// Posted exposure over the trailing 24 h, micro-USD. `None` = unknown.
    pub daily_posted_microusd: Option<u64>,
}

use crate::serde_micro::fmt_usd;

fn check(rule: &str, outcome: PolicyOutcome, message: impl Into<String>) -> PolicyCheck {
    PolicyCheck::for_venue("polymarket", rule, outcome, message)
}

/// Evaluate one Polymarket order against policy. Returns the full check list
/// (passes included) so plans can render the whole picture. Deny-level
/// failures must never be bypassable by CLI flags; `Warn` is acknowledged by
/// `--confirm-risk`.
pub fn evaluate_polymarket_order(
    policy: &PolymarketPolicy,
    ctx: &PolymarketOrderCtx,
) -> Vec<PolicyCheck> {
    let mut out = Vec::new();

    // Master gate.
    if !policy.enabled {
        out.push(check(
            "enabled",
            PolicyOutcome::Deny,
            "Polymarket trading is disabled for this wallet; set [polymarket] enabled = true \
             in the wallet policy to opt in",
        ));
    } else {
        out.push(check("enabled", PolicyOutcome::Pass, "trading enabled"));
    }

    // Hard market invariants — not knobs.
    if ctx.closed || !ctx.active {
        out.push(check(
            "market",
            PolicyOutcome::Deny,
            format!(
                "market is not tradable (active={}, closed={})",
                ctx.active, ctx.closed
            ),
        ));
    } else if !ctx.order_book_enabled {
        out.push(check(
            "market",
            PolicyOutcome::Deny,
            "market has no order book enabled",
        ));
    } else if !ctx.binary_outcomes {
        out.push(check(
            "market",
            PolicyOutcome::Deny,
            "market is malformed or not a binary YES/NO market",
        ));
    } else {
        out.push(check(
            "market",
            PolicyOutcome::Pass,
            "active, order book enabled, binary outcomes",
        ));
    }

    // Deny wins over allow; empty allowlist = unrestricted.
    let list = |name: &str, value: &str, allowed: &BTreeSet<String>, denied: &BTreeSet<String>| {
        if denied.contains(value) {
            check(
                name,
                PolicyOutcome::Deny,
                format!("'{value}' is denylisted"),
            )
        } else if !allowed.is_empty() && !allowed.contains(value) {
            check(
                name,
                PolicyOutcome::Deny,
                format!("'{value}' is not on the allowlist (allowlist-only mode)"),
            )
        } else {
            check(name, PolicyOutcome::Pass, format!("'{value}' permitted"))
        }
    };
    out.push(list(
        "slug",
        &ctx.slug,
        &policy.allowed_slugs,
        &policy.denied_slugs,
    ));
    out.push(list(
        "condition_id",
        &ctx.condition_id,
        &policy.allowed_condition_ids,
        &policy.denied_condition_ids,
    ));

    if ctx.neg_risk && !policy.allow_neg_risk {
        out.push(check(
            "neg_risk",
            PolicyOutcome::Deny,
            "neg-risk markets are disabled by policy (allow_neg_risk = false)",
        ));
    } else {
        out.push(check(
            "neg_risk",
            PolicyOutcome::Pass,
            format!("neg_risk={} permitted", ctx.neg_risk),
        ));
    }

    // Money caps apply to risk-adding (BUY) orders only.
    if ctx.side == PolicySide::Sell {
        out.push(check(
            "caps",
            PolicyOutcome::Pass,
            "sell orders are risk-reducing; USD caps not applied",
        ));
        return out;
    }

    if let Some(cap) = policy.max_order_usd {
        if ctx.amount_microusd > cap {
            out.push(check(
                "max_order_usd",
                PolicyOutcome::Deny,
                format!(
                    "order {} USD exceeds max_order_usd {}",
                    fmt_usd(ctx.amount_microusd),
                    fmt_usd(cap)
                ),
            ));
        } else {
            out.push(check(
                "max_order_usd",
                PolicyOutcome::Pass,
                format!("{} <= {}", fmt_usd(ctx.amount_microusd), fmt_usd(cap)),
            ));
        }
    }

    if let Some(cap) = policy.max_daily_usd {
        match (ctx.receipt_store_readable, ctx.daily_posted_microusd) {
            (false, _) | (_, None) => {
                out.push(check(
                    "max_daily_usd",
                    PolicyOutcome::Deny,
                    "daily cap configured but posted exposure is unknown (receipt store \
                     unreadable) — refusing rather than trading uncapped",
                ));
            }
            (true, Some(daily)) => {
                let total = daily.saturating_add(ctx.amount_microusd);
                if total > cap {
                    out.push(check(
                        "max_daily_usd",
                        PolicyOutcome::Deny,
                        format!(
                            "posted {} USD + order {} USD exceeds max_daily_usd {}",
                            fmt_usd(daily),
                            fmt_usd(ctx.amount_microusd),
                            fmt_usd(cap)
                        ),
                    ));
                } else {
                    out.push(check(
                        "max_daily_usd",
                        PolicyOutcome::Pass,
                        format!(
                            "{} + {} <= {}",
                            fmt_usd(daily),
                            fmt_usd(ctx.amount_microusd),
                            fmt_usd(cap)
                        ),
                    ));
                }
            }
        }
    }

    if let Some(maxp) = policy.max_price {
        if ctx.limit_price_micro > maxp {
            out.push(check(
                "max_price",
                PolicyOutcome::Deny,
                format!(
                    "limit price {} exceeds policy max_price {}",
                    fmt_usd(ctx.limit_price_micro),
                    fmt_usd(maxp)
                ),
            ));
        } else {
            out.push(check(
                "max_price",
                PolicyOutcome::Pass,
                format!("{} <= {}", fmt_usd(ctx.limit_price_micro), fmt_usd(maxp)),
            ));
        }
    }

    if let Some(threshold) = policy.require_flag_above_usd
        && ctx.amount_microusd > threshold
    {
        out.push(check(
            "require_flag_above_usd",
            PolicyOutcome::Warn,
            format!(
                "order {} USD is above {} — pass --confirm-risk to acknowledge",
                fmt_usd(ctx.amount_microusd),
                fmt_usd(threshold)
            ),
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{has_deny, has_warn};
    use crate::serde_micro::MICRO_USD;

    fn open_ctx() -> PolymarketOrderCtx {
        PolymarketOrderCtx {
            wallet: "w".into(),
            slug: "test-market".into(),
            condition_id: "0xcond".into(),
            side: PolicySide::Buy,
            amount_microusd: 10 * MICRO_USD,
            limit_price_micro: 695_000,
            active: true,
            closed: false,
            order_book_enabled: true,
            binary_outcomes: true,
            neg_risk: true,
            receipt_store_readable: true,
            daily_posted_microusd: Some(0),
        }
    }

    fn enabled_policy() -> PolymarketPolicy {
        PolymarketPolicy {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn disabled_by_default_denies() {
        let checks = evaluate_polymarket_order(&PolymarketPolicy::default(), &open_ctx());
        assert!(has_deny(&checks));
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "polymarket.enabled" && c.outcome == PolicyOutcome::Deny)
        );
    }

    #[test]
    fn clean_order_passes_when_enabled() {
        let checks = evaluate_polymarket_order(&enabled_policy(), &open_ctx());
        assert!(!has_deny(&checks), "{checks:?}");
        assert!(!has_warn(&checks));
    }

    #[test]
    fn hard_market_invariants_always_deny() {
        let p = enabled_policy();
        for mutate in [
            (|c: &mut PolymarketOrderCtx| c.closed = true) as fn(&mut PolymarketOrderCtx),
            |c| c.active = false,
            |c| c.order_book_enabled = false,
            |c| c.binary_outcomes = false,
        ] {
            let mut ctx = open_ctx();
            mutate(&mut ctx);
            assert!(
                has_deny(&evaluate_polymarket_order(&p, &ctx)),
                "expected deny for mutated ctx"
            );
        }
    }

    #[test]
    fn max_order_cap() {
        let p = PolymarketPolicy {
            max_order_usd: Some(5 * MICRO_USD),
            ..enabled_policy()
        };
        assert!(has_deny(&evaluate_polymarket_order(&p, &open_ctx())));
        let mut small = open_ctx();
        small.amount_microusd = 5 * MICRO_USD;
        assert!(!has_deny(&evaluate_polymarket_order(&p, &small)));
    }

    #[test]
    fn daily_cap_counts_posted_plus_order() {
        let p = PolymarketPolicy {
            max_daily_usd: Some(25 * MICRO_USD),
            ..enabled_policy()
        };
        let mut ctx = open_ctx();
        ctx.daily_posted_microusd = Some(20 * MICRO_USD);
        assert!(has_deny(&evaluate_polymarket_order(&p, &ctx))); // 20+10 > 25
        ctx.daily_posted_microusd = Some(15 * MICRO_USD);
        assert!(!has_deny(&evaluate_polymarket_order(&p, &ctx))); // 15+10 <= 25
    }

    #[test]
    fn daily_cap_fails_closed_when_receipts_unreadable() {
        let p = PolymarketPolicy {
            max_daily_usd: Some(1_000 * MICRO_USD),
            ..enabled_policy()
        };
        let mut ctx = open_ctx();
        ctx.receipt_store_readable = false;
        assert!(has_deny(&evaluate_polymarket_order(&p, &ctx)));
        let mut ctx = open_ctx();
        ctx.daily_posted_microusd = None;
        assert!(has_deny(&evaluate_polymarket_order(&p, &ctx)));
        // ...but only when a daily cap is actually configured.
        let mut ctx = open_ctx();
        ctx.receipt_store_readable = false;
        assert!(!has_deny(&evaluate_polymarket_order(
            &enabled_policy(),
            &ctx
        )));
    }

    #[test]
    fn max_price_cap() {
        let p = PolymarketPolicy {
            max_price: Some(650_000),
            ..enabled_policy()
        };
        assert!(has_deny(&evaluate_polymarket_order(&p, &open_ctx()))); // 0.695 > 0.65
    }

    #[test]
    fn deny_list_wins_over_allow_list() {
        let mut p = enabled_policy();
        p.allowed_slugs.insert("test-market".into());
        p.denied_slugs.insert("test-market".into());
        assert!(has_deny(&evaluate_polymarket_order(&p, &open_ctx())));
    }

    #[test]
    fn nonempty_allowlist_is_allowlist_only() {
        let mut p = enabled_policy();
        p.allowed_slugs.insert("some-other-market".into());
        assert!(has_deny(&evaluate_polymarket_order(&p, &open_ctx())));
        p.allowed_slugs.insert("test-market".into());
        assert!(!has_deny(&evaluate_polymarket_order(&p, &open_ctx())));
    }

    #[test]
    fn denied_condition_id() {
        let mut p = enabled_policy();
        p.denied_condition_ids.insert("0xcond".into());
        assert!(has_deny(&evaluate_polymarket_order(&p, &open_ctx())));
    }

    #[test]
    fn neg_risk_refusal() {
        let p = PolymarketPolicy {
            allow_neg_risk: false,
            ..enabled_policy()
        };
        assert!(has_deny(&evaluate_polymarket_order(&p, &open_ctx())));
        let mut ctx = open_ctx();
        ctx.neg_risk = false;
        assert!(!has_deny(&evaluate_polymarket_order(&p, &ctx)));
    }

    #[test]
    fn require_flag_is_warn_not_deny() {
        let p = PolymarketPolicy {
            require_flag_above_usd: Some(5 * MICRO_USD),
            ..enabled_policy()
        };
        let checks = evaluate_polymarket_order(&p, &open_ctx());
        assert!(!has_deny(&checks));
        assert!(has_warn(&checks));
    }

    #[test]
    fn sell_orders_skip_money_caps_but_not_gates() {
        let p = PolymarketPolicy {
            max_order_usd: Some(MICRO_USD), // $1 — the $10 sell would deny if applied
            ..enabled_policy()
        };
        let mut ctx = open_ctx();
        ctx.side = PolicySide::Sell;
        assert!(!has_deny(&evaluate_polymarket_order(&p, &ctx)));
        // enabled gate still applies to sells
        let disabled = PolymarketPolicy::default();
        assert!(has_deny(&evaluate_polymarket_order(&disabled, &ctx)));
    }

    #[test]
    fn toml_round_trip_with_decimal_strings() {
        let src = r#"
enabled = true
max_order_usd = "10"
max_daily_usd = "25.5"
require_flag_above_usd = 5
max_price = "0.75"
allow_neg_risk = true
denied_slugs = ["bad-market"]
"#;
        let p: PolymarketPolicy = toml::from_str(src).unwrap();
        assert!(p.enabled);
        assert_eq!(p.max_order_usd, Some(10 * MICRO_USD));
        assert_eq!(p.max_daily_usd, Some(25_500_000));
        assert_eq!(p.require_flag_above_usd, Some(5 * MICRO_USD));
        assert_eq!(p.max_price, Some(750_000));
        assert!(p.denied_slugs.contains("bad-market"));
        // floats round-trip via shortest repr, no binary dust
        let p2: PolymarketPolicy = toml::from_str("enabled = true\nmax_price = 0.1\n").unwrap();
        assert_eq!(p2.max_price, Some(100_000));
    }

    #[test]
    fn default_section_parses_from_policy_toml() {
        let p: crate::policy::Policy = toml::from_str("[caps]\nmax_value_eth = 0.1\n").unwrap();
        assert!(!p.polymarket.enabled, "polymarket must default to disabled");
        assert!(p.polymarket.allow_neg_risk);
    }
}
