//! Translate per-wallet policy into a list of `PolicyCheck` entries
//! attached to a staged tx.
//!
//! Rules covered:
//! - global + per-chain caps (the *more restrictive* of the two wins).
//! - first-class allow / deny lists for contracts, tokens, recipients
//!   (case-insensitive address compares).
//! - legacy `[contracts]` / `[tokens]` allow/deny blocks from the spec
//!   §6.3, treated alongside the first-class lists. Token symbols (e.g.
//!   `USDC`) match against `AddressContext::token_symbol`; addresses are
//!   compared as-hex.
//! - per-tx USD caps (`caps.per_tx_usd` / `caps.require_confirm_above_usd`)
//!   when a USD price is in the context.
//! - rolling 24h `caps.per_day_usd`, summed from the outbox by
//!   `tx_engine::stage` and surfaced via `ctx.usd_spent_last_24h`.
//! - automation: `auto_confirm_below_eth`.

use alloy::primitives::{Address, U256};
use bloom_proto::policy::{PolicyAllowDeny, PolicyCaps, PolicyLists};
use bloom_proto::{Policy, PolicyCheck, PolicyOutcome, format_units};

const ETHER: u128 = 1_000_000_000_000_000_000;

/// Addresses + tags involved in a tx, used by allow/deny list checks.
#[derive(Debug, Clone, Default)]
pub struct AddressContext {
    /// The contract being called (if any).
    pub contract: Option<Address>,
    /// The token being moved (for ERC-20 transfers).
    pub token: Option<Address>,
    /// The user-facing recipient. For ERC-20 sends this is the
    /// address inside the calldata, not the contract `to`.
    pub recipient: Option<Address>,
    /// Best-effort symbol for the token being moved (e.g. `USDC`,
    /// `WETH`). Used for spec-style `[tokens] allow=["USDC"]` matches.
    pub token_symbol: Option<String>,
    /// Whether the destination is a contract — `true` for ERC-20 / call /
    /// raw-data txs, `false` for plain native sends. Drives `[contracts]`
    /// allow/deny evaluation.
    pub destination_is_contract: bool,
    /// Per-tx USD value of this tx, when prices are wired. `None` skips
    /// any USD-cap checks (so a missing oracle never silently passes a
    /// dollar-denominated rule).
    pub usd_value: Option<f64>,
    /// USD already spent by this wallet in the trailing 24h window
    /// (sum of historical staged tx `usd_value` for ids past their
    /// pending state). `None` when the rolling window can't be
    /// computed — `caps.per_day_usd` then surfaces a soft Warn rather
    /// than hard-passing.
    pub usd_spent_last_24h: Option<f64>,
}

/// Run policy checks against a staged tx.
///
/// `chain_name` is the filesystem-friendly chain name; it is matched
/// against `policy.per_chain` for any per-chain overrides.
pub fn evaluate(
    policy: &Policy,
    chain_name: &str,
    value_wei: U256,
    native_decimals: u8,
    ctx: AddressContext,
) -> Vec<PolicyCheck> {
    let mut out = Vec::new();
    let value_human = format_units(value_wei, native_decimals);
    let value_f = value_human.parse::<f64>().unwrap_or(0.0);

    // Effective caps = most restrictive of (global, per-chain).
    let effective_caps = match policy.per_chain.get(chain_name) {
        Some(per) => PolicyCaps::most_restrictive(&policy.caps, per),
        None => policy.caps.clone(),
    };

    if let Some(max) = effective_caps.max_value_eth {
        if value_f > max {
            out.push(PolicyCheck::hard(
                "caps.max_value_eth",
                PolicyOutcome::Deny,
                format!("value {} > max {}", value_human, max),
            ));
        } else {
            out.push(PolicyCheck::informational(
                "caps.max_value_eth",
                PolicyOutcome::Pass,
                format!("value {} <= max {}", value_human, max),
            ));
        }
    }

    if let Some(soft) = effective_caps.require_override_above_eth
        && value_f > soft
    {
        out.push(PolicyCheck::soft(
            "caps.require_override_above_eth",
            PolicyOutcome::Warn,
            format!(
                "value {} > soft {} — write `override` to confirm",
                value_human, soft
            ),
        ));
    }

    if let Some(auto_below) = policy.automation.auto_confirm_below_eth
        && value_f <= auto_below
    {
        out.push(PolicyCheck::informational(
            "automation.auto_confirm_below_eth",
            PolicyOutcome::Pass,
            "value within auto-confirm threshold",
        ));
    }

    // ----- USD caps -----------------------------------------------------------
    // Only enforced when the caller has a quote. Without prices we leave
    // these rules silent rather than auto-passing or auto-failing — the
    // spec wants the cap respected; an absent oracle is the operator's
    // problem to resolve, not a license to skip the rule. We surface a
    // single "skipped" pass-result so plan.md makes the gap visible.
    let any_usd_rule = effective_caps.per_tx_usd.is_some()
        || effective_caps.require_confirm_above_usd.is_some()
        || effective_caps.per_day_usd.is_some();
    match (any_usd_rule, ctx.usd_value) {
        (true, Some(usd)) => {
            if let Some(max_usd) = effective_caps.per_tx_usd {
                if usd > max_usd {
                    out.push(PolicyCheck::hard(
                        "caps.per_tx_usd",
                        PolicyOutcome::Deny,
                        format!("usd {usd:.2} > max {max_usd:.2}"),
                    ));
                } else {
                    out.push(PolicyCheck::informational(
                        "caps.per_tx_usd",
                        PolicyOutcome::Pass,
                        format!("usd {usd:.2} <= max {max_usd:.2}"),
                    ));
                }
            }
            if let Some(soft_usd) = effective_caps.require_confirm_above_usd
                && usd > soft_usd
            {
                out.push(PolicyCheck::soft(
                    "caps.require_confirm_above_usd",
                    PolicyOutcome::Warn,
                    format!("usd {usd:.2} > soft {soft_usd:.2} — write override token to confirm"),
                ));
            }
            // The rolling counter is sourced from the outbox itself by
            // tx_engine::stage (sum of usd_value across this wallet's
            // sent / pending entries created in the trailing 24h
            // window). When it's unavailable the caller has no way to
            // know whether the proposed send breaks the cap, so we
            // soft-warn rather than silently passing.
            if let Some(per_day) = effective_caps.per_day_usd {
                match ctx.usd_spent_last_24h {
                    Some(prior) => {
                        let total = prior + usd;
                        if total > per_day {
                            out.push(PolicyCheck::hard(
                                "caps.per_day_usd",
                                PolicyOutcome::Deny,
                                format!(
                                    "rolling 24h usd {prior:.2} + {usd:.2} > cap {per_day:.2}"
                                ),
                            ));
                        } else {
                            out.push(PolicyCheck::informational(
                                "caps.per_day_usd",
                                PolicyOutcome::Pass,
                                format!(
                                    "rolling 24h usd {total:.2} <= cap {per_day:.2}"
                                ),
                            ));
                        }
                    }
                    None => out.push(PolicyCheck::soft(
                        "caps.per_day_usd",
                        PolicyOutcome::Warn,
                        format!(
                            "per_day_usd cap {per_day:.2} configured but rolling-window state unavailable"
                        ),
                    )),
                }
            }
        }
        (true, None) => {
            out.push(PolicyCheck::soft(
                "caps.usd",
                PolicyOutcome::Warn,
                "USD caps configured but no price quote available; rule skipped",
            ));
        }
        (false, _) => {}
    }

    // ----- allow / deny lists -------------------------------------------------
    check_lists(
        &mut out,
        "denylists.contracts",
        &policy.denylists.contracts,
        ctx.contract,
        ListMode::Deny,
    );
    check_lists(
        &mut out,
        "denylists.tokens",
        &policy.denylists.tokens,
        ctx.token,
        ListMode::Deny,
    );
    check_lists(
        &mut out,
        "denylists.recipients",
        &policy.denylists.recipients,
        ctx.recipient,
        ListMode::Deny,
    );

    check_lists(
        &mut out,
        "allowlists.contracts",
        &policy.allowlists.contracts,
        ctx.contract,
        ListMode::Allow,
    );
    check_lists(
        &mut out,
        "allowlists.tokens",
        &policy.allowlists.tokens,
        ctx.token,
        ListMode::Allow,
    );
    check_lists(
        &mut out,
        "allowlists.recipients",
        &policy.allowlists.recipients,
        ctx.recipient,
        ListMode::Allow,
    );

    // ----- spec §6.3 legacy `[contracts]` / `[tokens]` blocks ---------------
    // The spec describes:
    //
    //   [contracts]
    //   allow = ["uniswap-v2", "0x..."]
    //   deny  = ["0xevilcontract..."]
    //   [tokens]
    //   allow = ["ETH", "USDC", ...]
    //
    // These are honoured for tx kinds where they make sense:
    //  - `[contracts]` only fires when the destination is a contract
    //    (i.e. `destination_is_contract` is true: ERC-20 / call / raw
    //    data). A plain native send to an EOA bypasses contract lists
    //    even if the lists are non-empty.
    //  - `[tokens]` fires for ERC-20 transfers; the symbol or token
    //    address must appear in the allow set (when non-empty), and
    //    must not appear in the deny set.
    if ctx.destination_is_contract {
        check_allow_deny(
            &mut out,
            "contracts",
            &policy.contracts,
            // Match by contract address only; symbol matching is for
            // tokens.
            address_lc(ctx.contract).as_deref(),
            None,
        );
    }
    if ctx.token.is_some() {
        check_allow_deny(
            &mut out,
            "tokens",
            &policy.tokens,
            address_lc(ctx.token).as_deref(),
            ctx.token_symbol.as_deref(),
        );
    }

    let _ = ETHER;
    let _ = PolicyLists::default; // make import deterministic
    out
}

fn address_lc(a: Option<Address>) -> Option<String> {
    a.map(|x| format!("{x:#x}").to_ascii_lowercase())
}

/// Enforce a spec-style `[section] allow=[..] deny=[..]` block. `target`
/// is the address (lower-cased hex) of the contract or token; `symbol`
/// is an optional secondary key (e.g. `USDC`) checked alongside.
fn check_allow_deny(
    out: &mut Vec<PolicyCheck>,
    section: &str,
    block: &PolicyAllowDeny,
    target: Option<&str>,
    symbol: Option<&str>,
) {
    let matches_one = |entry: &str| -> bool {
        let e = entry.trim();
        if let Some(t) = target
            && e.eq_ignore_ascii_case(t)
        {
            return true;
        }
        if let Some(s) = symbol
            && e.eq_ignore_ascii_case(s)
        {
            return true;
        }
        false
    };

    if !block.deny.is_empty() && block.deny.iter().any(|s| matches_one(s)) {
        out.push(PolicyCheck::hard(
            format!("{section}.deny"),
            PolicyOutcome::Deny,
            format!(
                "{} on deny list",
                target.unwrap_or_else(|| symbol.unwrap_or("(unknown)"))
            ),
        ));
    }
    if !block.allow.is_empty() {
        let hit = block.allow.iter().any(|s| matches_one(s));
        if hit {
            out.push(PolicyCheck::informational(
                format!("{section}.allow"),
                PolicyOutcome::Pass,
                format!(
                    "{} on allow list",
                    target.unwrap_or_else(|| symbol.unwrap_or("(unknown)"))
                ),
            ));
        } else {
            out.push(PolicyCheck::hard(
                format!("{section}.allow"),
                PolicyOutcome::Deny,
                format!(
                    "{} not on allow list",
                    target.unwrap_or_else(|| symbol.unwrap_or("(unknown)"))
                ),
            ));
        }
    }
}

#[derive(Copy, Clone)]
enum ListMode {
    Allow,
    Deny,
}

fn check_lists(
    out: &mut Vec<PolicyCheck>,
    rule: &str,
    list: &std::collections::BTreeSet<String>,
    addr: Option<Address>,
    mode: ListMode,
) {
    if list.is_empty() {
        return;
    }
    let target = match addr {
        Some(a) => a,
        None => {
            // Allowlist with nothing to check is a hard miss — we can't
            // confirm the tx falls inside the list.
            if matches!(mode, ListMode::Allow) {
                out.push(PolicyCheck::hard(
                    rule,
                    PolicyOutcome::Deny,
                    "allowlist set but tx has no relevant address",
                ));
            }
            return;
        }
    };
    let target_lc = format!("{target:#x}").to_ascii_lowercase();
    let hit = list
        .iter()
        .any(|s| s.trim().to_ascii_lowercase() == target_lc);
    match (mode, hit) {
        (ListMode::Deny, true) => out.push(PolicyCheck::hard(
            rule,
            PolicyOutcome::Deny,
            format!("{} is denylisted", target_lc),
        )),
        (ListMode::Deny, false) => {}
        (ListMode::Allow, true) => out.push(PolicyCheck::informational(
            rule,
            PolicyOutcome::Pass,
            format!("{} is on allowlist", target_lc),
        )),
        (ListMode::Allow, false) => out.push(PolicyCheck::hard(
            rule,
            PolicyOutcome::Deny,
            format!("{} not on allowlist", target_lc),
        )),
    }
}

/// Returns true if any check is `Deny`.
pub fn has_hard_violation(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(|c| c.outcome == PolicyOutcome::Deny)
}

/// Returns true if any check is `Warn`.
pub fn has_warning(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(|c| c.outcome == PolicyOutcome::Warn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::policy::{PolicyAutomation, PolicyCaps, PolicyLists};
    use std::collections::BTreeSet;

    fn addr(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[test]
    fn caps_max_value() {
        let p = Policy {
            caps: PolicyCaps {
                max_value_eth: Some(0.5),
                ..Default::default()
            },
            ..Default::default()
        };
        let value = U256::from(700_000_000_000_000_000u128); // 0.7 eth
        let checks = evaluate(&p, "anvil", value, 18, AddressContext::default());
        assert!(has_hard_violation(&checks));
    }

    #[test]
    fn caps_pass() {
        let p = Policy {
            caps: PolicyCaps {
                max_value_eth: Some(1.0),
                ..Default::default()
            },
            ..Default::default()
        };
        let value = U256::from(500_000_000_000_000_000u128);
        let checks = evaluate(&p, "anvil", value, 18, AddressContext::default());
        assert!(!has_hard_violation(&checks));
    }

    #[test]
    fn soft_warn() {
        let p = Policy {
            caps: PolicyCaps {
                require_override_above_eth: Some(0.1),
                ..Default::default()
            },
            ..Default::default()
        };
        let value = U256::from(500_000_000_000_000_000u128);
        let checks = evaluate(&p, "anvil", value, 18, AddressContext::default());
        assert!(has_warning(&checks));
    }

    #[test]
    fn denylist_recipient_is_hard_block() {
        let mut deny = BTreeSet::new();
        deny.insert("0x000000000000000000000000000000000000dead".to_string());
        let p = Policy {
            denylists: PolicyLists {
                recipients: deny,
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = AddressContext {
            recipient: Some(addr("0x000000000000000000000000000000000000dead")),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx);
        assert!(
            has_hard_violation(&checks),
            "expected hard violation: {checks:?}"
        );
    }

    #[test]
    fn allowlist_miss_is_hard_block() {
        let mut allow = BTreeSet::new();
        allow.insert("0x0000000000000000000000000000000000001111".to_string());
        let p = Policy {
            allowlists: PolicyLists {
                contracts: allow,
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = AddressContext {
            contract: Some(addr("0x0000000000000000000000000000000000002222")),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx);
        assert!(has_hard_violation(&checks), "checks: {checks:?}");
    }

    #[test]
    fn allowlist_hit_passes() {
        let mut allow = BTreeSet::new();
        allow.insert("0x0000000000000000000000000000000000001111".to_string());
        let p = Policy {
            allowlists: PolicyLists {
                contracts: allow,
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = AddressContext {
            contract: Some(addr("0x0000000000000000000000000000000000001111")),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx);
        assert!(!has_hard_violation(&checks), "checks: {checks:?}");
    }

    #[test]
    fn per_chain_override_is_more_restrictive() {
        // Global allows 1 ETH, per-chain caps anvil at 0.1.
        let mut per_chain = std::collections::BTreeMap::new();
        per_chain.insert(
            "anvil".to_string(),
            PolicyCaps {
                max_value_eth: Some(0.1),
                ..Default::default()
            },
        );
        let p = Policy {
            caps: PolicyCaps {
                max_value_eth: Some(1.0),
                ..Default::default()
            },
            per_chain,
            ..Default::default()
        };
        // 0.5 ETH passes global but fails per-chain.
        let value = U256::from(500_000_000_000_000_000u128);
        let checks = evaluate(&p, "anvil", value, 18, AddressContext::default());
        assert!(has_hard_violation(&checks), "{checks:?}");

        // On a different chain (no override) it should pass.
        let checks = evaluate(&p, "ethereum", value, 18, AddressContext::default());
        assert!(!has_hard_violation(&checks), "{checks:?}");
    }

    #[test]
    fn override_token_default_is_override() {
        let p = Policy::default();
        assert_eq!(p.override_sentinel(), "override");
        let p2 = Policy {
            automation: PolicyAutomation {
                override_token: Some("yolo".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(p2.override_sentinel(), "yolo");
    }

    /// Fix #11: spec §6.3 `[contracts] deny=[..]` must hard-block any tx
    /// whose destination is a contract listed in deny. Plain native sends
    /// (`destination_is_contract=false`) bypass the contracts block.
    #[test]
    fn legacy_contracts_deny_blocks_contract_call() {
        let mut deny = std::collections::BTreeSet::new();
        deny.insert("0x000000000000000000000000000000000000beef".to_string());
        let p = Policy {
            contracts: PolicyAllowDeny {
                deny,
                ..Default::default()
            },
            ..Default::default()
        };
        let target = addr("0x000000000000000000000000000000000000beef");
        // As contract call → blocked.
        let ctx = AddressContext {
            contract: Some(target),
            destination_is_contract: true,
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx);
        assert!(has_hard_violation(&checks), "{checks:?}");

        // As plain EOA send (heuristic says not a contract) → allowed.
        let ctx2 = AddressContext {
            recipient: Some(target),
            destination_is_contract: false,
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx2);
        assert!(!has_hard_violation(&checks), "{checks:?}");
    }

    /// Fix #11: `[tokens] allow=[..]` accepts symbol matches as well as
    /// hex-address matches. A non-listed token must hard-block.
    #[test]
    fn legacy_tokens_allow_matches_symbol() {
        let mut allow = std::collections::BTreeSet::new();
        allow.insert("USDC".to_string());
        let p = Policy {
            tokens: PolicyAllowDeny {
                allow,
                ..Default::default()
            },
            ..Default::default()
        };
        // Symbol match passes.
        let usdc = addr("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let ctx_pass = AddressContext {
            token: Some(usdc),
            token_symbol: Some("USDC".into()),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx_pass);
        assert!(!has_hard_violation(&checks), "{checks:?}");

        // Different token symbol — blocked.
        let weth = addr("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
        let ctx_fail = AddressContext {
            token: Some(weth),
            token_symbol: Some("WETH".into()),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx_fail);
        assert!(has_hard_violation(&checks), "{checks:?}");
    }

    /// Fix #11: USD caps configured but no price fires a Warn rather
    /// than silently passing.
    #[test]
    fn usd_cap_without_price_warns() {
        let p = Policy {
            caps: PolicyCaps {
                per_tx_usd: Some(100.0),
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = AddressContext {
            usd_value: None,
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx);
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "caps.usd" && matches!(c.outcome, PolicyOutcome::Warn))
        );
    }

    /// Fix #11: USD caps with a quote enforce per-tx max as a hard cap.
    #[test]
    fn usd_per_tx_cap_blocks_when_over() {
        let p = Policy {
            caps: PolicyCaps {
                per_tx_usd: Some(100.0),
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx_fail = AddressContext {
            usd_value: Some(150.0),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx_fail);
        assert!(has_hard_violation(&checks), "{checks:?}");

        let ctx_pass = AddressContext {
            usd_value: Some(50.0),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx_pass);
        assert!(!has_hard_violation(&checks), "{checks:?}");
    }

    /// per_day_usd: total of (rolling spend + this tx) over the cap is
    /// a hard block; under is a Pass that names the running total.
    #[test]
    fn usd_per_day_cap_uses_rolling_window() {
        let p = Policy {
            caps: PolicyCaps {
                per_day_usd: Some(200.0),
                ..Default::default()
            },
            ..Default::default()
        };

        // Rolling 180 + new 50 = 230 → over cap.
        let ctx_over = AddressContext {
            usd_value: Some(50.0),
            usd_spent_last_24h: Some(180.0),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx_over);
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "caps.per_day_usd" && matches!(c.outcome, PolicyOutcome::Deny)),
            "{checks:?}"
        );

        // Rolling 100 + new 50 = 150 → fine.
        let ctx_under = AddressContext {
            usd_value: Some(50.0),
            usd_spent_last_24h: Some(100.0),
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx_under);
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "caps.per_day_usd" && matches!(c.outcome, PolicyOutcome::Pass)),
            "{checks:?}"
        );
    }

    /// per_day_usd configured but the rolling counter is unavailable
    /// must Warn rather than silently pass — operators need to see
    /// that the cap was unenforced.
    #[test]
    fn usd_per_day_cap_warns_when_state_missing() {
        let p = Policy {
            caps: PolicyCaps {
                per_day_usd: Some(200.0),
                ..Default::default()
            },
            ..Default::default()
        };
        let ctx = AddressContext {
            usd_value: Some(50.0),
            usd_spent_last_24h: None,
            ..Default::default()
        };
        let checks = evaluate(&p, "anvil", U256::ZERO, 18, ctx);
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "caps.per_day_usd" && matches!(c.outcome, PolicyOutcome::Warn)),
            "{checks:?}"
        );
    }
}
