//! First-class DeFi route policy (`[defi]`).
//!
//! The generic Enso/DeFi route surface (`defi/intents/...`) hands
//! Enso-returned calldata to the tx engine. EVM caps gate value broadly, but
//! not *route shape*: which chains, which receiver, which router/protocols,
//! and how much output is actually guaranteed. This section adds those gates.
//!
//! Design follows [`crate::polymarket_policy`]: default-deny master gate,
//! deny-beats-allow, empty-allowlist semantics, integer micro-USD money (no
//! `f64` in decisions), and `PolicyCheck` output so plans render uniformly.
//!
//! Three findings from the red-team are baked in:
//!
//! - **B1 (enforce the bytes, not the request).** Policy is evaluated against
//!   route *facts* the caller has actually verified — a `min_out_enforced`
//!   flag the caller sets only when the guaranteed-output floor is enforced
//!   (calldata or simulated balance delta), and a `receiver_verified` flag set
//!   only when the destination receiver is proven, not merely requested. When
//!   either is unverified, the relevant check is a hard refusal, never a
//!   silent pass. Bloom must not present the *appearance* of enforcement over
//!   un-decoded calldata.
//! - **B3 (classification, not literals).** Receiver allowlist entries may be
//!   raw `chain:token:address` literals OR classification tokens
//!   (`class:<receiver_class>`), so a resolver (durable onboarding state,
//!   addressbook) is the single source of truth and a hand-typed address can't
//!   silently disagree with what bloom resolved.
//! - **S1 (no unit-unverified money knobs).** There is deliberately no
//!   `max_price_impact_*` / `max_route_fee_*` field: Enso's `priceImpact` unit
//!   is unverified (observed raw `291`, `15`), so it is display-only
//!   ("Enso-reported") and never a threshold.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::policy::{PolicyCheck, PolicyOutcome};

fn default_true() -> bool {
    true
}

/// `[defi]` section of a wallet's policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefiPolicy {
    /// Master gate. Defaults to **false**: the generic DeFi route surface
    /// refuses all value-moving routes until the owner opts in. (Note: the
    /// purpose-built `bloom polymarket fund` command has its own validations
    /// and is not gated by this flag — see the command docs.)
    #[serde(default)]
    pub enabled: bool,
    /// Source chains a route may originate on. Empty ⇒ none allowed.
    #[serde(default)]
    pub allowed_source_chains: BTreeSet<String>,
    /// Destination chains a cross-chain route may settle on. Empty ⇒ none.
    #[serde(default)]
    pub allowed_destination_chains: BTreeSet<String>,
    /// Receiver allowlist. Entries are either:
    /// - a literal `"<chain>:<token>:<address>"` (all lower-case), or
    /// - a classification token `"class:<receiver_class>"`
    ///   (e.g. `"class:polymarket_deposit_wallet"`, `"class:wallet_eoa"`).
    ///
    /// Empty ⇒ unknown receivers refuse. Deny always wins.
    #[serde(default)]
    pub allowed_receivers: BTreeSet<String>,
    /// Receivers that always refuse, same key forms as `allowed_receivers`.
    #[serde(default)]
    pub denied_receivers: BTreeSet<String>,
    /// Router contract allowlist, keyed `"<chain>:<address>"` (lower-case).
    /// Empty ⇒ no router allowed (fail closed once `enabled`).
    #[serde(default)]
    pub allowed_routers: BTreeSet<String>,
    /// Protocol names that always refuse (lower-case, normalized).
    #[serde(default)]
    pub denied_protocols: BTreeSet<String>,
    /// Whether a route whose protocol metadata bloom could not parse may
    /// proceed. Defaults to **false** (unknown protocols fail closed).
    #[serde(default)]
    pub allow_unknown_protocols: bool,
    /// Whether bloom must have *verified* the receiver and minimum-output
    /// floor (by decoding router calldata or simulating the balance delta)
    /// before a route may proceed.
    ///
    /// **Default `true`** — when bloom has not verified them, the route refuses
    /// (B1: never enforce policy against un-decoded calldata).
    ///
    /// Setting `false` is an **acknowledged-residual-risk** opt-in that
    /// downgrades the `receiver_verified` and `min_output` checks from Deny to
    /// **Warn** (never silent Pass — the warnings always appear in `plan.md` /
    /// `policy_check.json`, naming that the receiver/min-output are quote-only
    /// and not calldata-verified). The accepted risk is concrete: **a stale
    /// quote or a sandwich attack can defeat the Enso quote floor and deliver
    /// near-zero output with every other policy check still passing.**
    ///
    /// Boundaries:
    /// - This is a **policy-file setting only**. It must **never** be exposed
    ///   as a CLI flag (`--trust-route` / `--no-verify` etc.) — flipping it is
    ///   an operator act in the wallet's `policy.toml`, signature-gated for
    ///   passkey wallets (`bloom wallet sign-policy`), so an agent cannot flip
    ///   it mid-run.
    /// - **Do not set `false` for wallets driven by autonomous/unattended
    ///   agents.** It is intended for operator-initiated routes where a human
    ///   reviews the rendered plan before confirming.
    #[serde(default = "default_true")]
    pub require_calldata_verification: bool,
    /// Hard cap on route input value, micro-USD. `None` ⇒ uncapped (but the
    /// master gate + receiver/router gates still apply).
    #[serde(default, with = "micro_opt")]
    pub max_input_usd: Option<u64>,
    /// Hard cap on native value attached to the route tx, in wei (decimal
    /// string). `None` ⇒ uncapped. Note a native-in route (e.g. POL→pUSD)
    /// has non-zero tx value; set this to allow it.
    #[serde(default, with = "wei_opt")]
    pub max_native_value_wei: Option<alloy::primitives::U256>,
}

impl Default for DefiPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_source_chains: BTreeSet::new(),
            allowed_destination_chains: BTreeSet::new(),
            allowed_receivers: BTreeSet::new(),
            denied_receivers: BTreeSet::new(),
            allowed_routers: BTreeSet::new(),
            denied_protocols: BTreeSet::new(),
            allow_unknown_protocols: false,
            require_calldata_verification: true,
            max_input_usd: None,
            max_native_value_wei: None,
        }
    }
}

/// Serde for `Option<u64>` micro-USD (decimal string ⇒ 6-dp integer). Mirrors
/// `polymarket_policy::micro_opt`; kept local to avoid widening that module's
/// visibility.
mod micro_opt {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            None => s.serialize_none(),
            Some(micro) => s.serialize_some(&crate::units::format_units(
                alloy::primitives::U256::from(*micro),
                6,
            )),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            S(String),
            I(i64),
            F(f64),
        }
        let parse = |s: &str| -> Result<u64, String> {
            let v = crate::units::parse_units(s.trim(), 6)
                .map_err(|e| format!("bad USD amount '{s}': {e}"))?;
            u64::try_from(v).map_err(|_| format!("USD amount '{s}' too large"))
        };
        match Option::<Raw>::deserialize(d)? {
            None => Ok(None),
            Some(Raw::S(s)) => parse(&s).map(Some).map_err(D::Error::custom),
            Some(Raw::I(i)) => {
                if i < 0 {
                    return Err(D::Error::custom("USD amount cannot be negative"));
                }
                (i as u64)
                    .checked_mul(1_000_000)
                    .map(Some)
                    .ok_or_else(|| D::Error::custom("USD amount too large"))
            }
            Some(Raw::F(f)) => parse(&format!("{f}")).map(Some).map_err(D::Error::custom),
        }
    }
}

/// Serde for `Option<U256>` wei from a decimal string.
mod wei_opt {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        v: &Option<alloy::primitives::U256>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            None => s.serialize_none(),
            Some(w) => s.serialize_some(&w.to_string()),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<alloy::primitives::U256>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => alloy::primitives::U256::from_str_radix(s.trim(), 10)
                .map(Some)
                .map_err(|e| D::Error::custom(format!("bad wei value '{s}': {e}"))),
        }
    }
}

/// What bloom believes a route receiver address is. Resolved from durable
/// state / addressbook, never guessed from the route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverClass {
    /// The wallet's own owner EOA.
    WalletEoa,
    /// This wallet's Polymarket deposit wallet (resolved from onboarding
    /// state / the live factory — not a hardcoded address).
    PolymarketDepositWallet,
    /// A named entry in the wallet's address book.
    AddressbookAlias,
    /// A well-known system/contract address.
    KnownSystemAddress,
    /// Unrecognized — fails closed unless explicitly allowlisted by literal.
    Unknown,
}

impl ReceiverClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiverClass::WalletEoa => "wallet_eoa",
            ReceiverClass::PolymarketDepositWallet => "polymarket_deposit_wallet",
            ReceiverClass::AddressbookAlias => "addressbook_alias",
            ReceiverClass::KnownSystemAddress => "known_system_address",
            ReceiverClass::Unknown => "unknown",
        }
    }
}

/// Everything `evaluate_defi_route` needs about one route. All fields the
/// caller has *verified* — unverified facts are represented by `false` flags,
/// never by optimistic values.
#[derive(Debug, Clone)]
pub struct DefiRouteCtx {
    pub wallet: String,
    /// Source chain name (matches `ChainSpec::name`).
    pub source_chain: String,
    /// Destination chain name; equals `source_chain` for same-chain routes.
    pub destination_chain: String,
    pub cross_chain: bool,
    /// Receiver address, lower-case hex `0x…`.
    pub receiver: String,
    /// Output token at the destination, lower-case hex `0x…`.
    pub token_out: String,
    pub receiver_class: ReceiverClass,
    /// Router/verifying contract the tx calls, lower-case hex `0x…`.
    pub router: String,
    /// Parsed protocol names (lower-case). Empty with
    /// `protocols_unknown=true` means bloom could not parse the route.
    pub protocols: Vec<String>,
    pub protocols_unknown: bool,
    /// Input value in micro-USD when known; `None` when bloom has no price.
    pub input_microusd: Option<u64>,
    /// Native value attached to the route tx, wei.
    pub native_value_wei: alloy::primitives::U256,
    /// **B1**: true only when the guaranteed-output floor is actually
    /// enforced (in calldata, or by a simulated balance-delta assertion),
    /// not merely present in the quote.
    pub min_out_enforced: bool,
    /// **B1**: true only when the destination receiver is *proven* (e.g. the
    /// route is same-chain and the simulated transfer credits `receiver`),
    /// not merely the address bloom requested from Enso.
    pub receiver_verified: bool,
}

fn check(rule: &str, outcome: PolicyOutcome, message: impl Into<String>) -> PolicyCheck {
    PolicyCheck {
        rule: format!("defi.{rule}"),
        outcome,
        message: message.into(),
    }
}

fn fmt_usd(micro: u64) -> String {
    crate::units::format_units(alloy::primitives::U256::from(micro), 6)
}

fn receiver_literal(ctx: &DefiRouteCtx) -> String {
    format!(
        "{}:{}:{}",
        ctx.destination_chain.to_lowercase(),
        ctx.token_out.to_lowercase(),
        ctx.receiver.to_lowercase()
    )
}

/// Whether `set` matches this receiver, by literal `chain:token:addr` or by
/// `class:<receiver_class>`.
fn receiver_set_matches(set: &BTreeSet<String>, ctx: &DefiRouteCtx) -> bool {
    if set.contains(&receiver_literal(ctx)) {
        return true;
    }
    let class_tok = format!("class:{}", ctx.receiver_class.as_str());
    set.contains(&class_tok)
}

/// Evaluate one DeFi route against policy. Returns the full check list
/// (passes included) so plans render the whole picture. Deny-level failures
/// must never be bypassable by CLI flags.
pub fn evaluate_defi_route(policy: &DefiPolicy, ctx: &DefiRouteCtx) -> Vec<PolicyCheck> {
    let mut out = Vec::new();

    // ── master gate ───────────────────────────────────────────────────────
    if !policy.enabled {
        out.push(check(
            "enabled",
            PolicyOutcome::Deny,
            "generic DeFi routes are disabled for this wallet; set [defi] enabled = true \
             in the wallet policy to opt in",
        ));
    } else {
        out.push(check("enabled", PolicyOutcome::Pass, "DeFi routes enabled"));
    }

    // ── chains (empty allowlist = none) ───────────────────────────────────
    let src = ctx.source_chain.to_lowercase();
    if policy
        .allowed_source_chains
        .iter()
        .any(|c| c.to_lowercase() == src)
    {
        out.push(check(
            "source_chain",
            PolicyOutcome::Pass,
            format!("source chain {} allowed", ctx.source_chain),
        ));
    } else {
        out.push(check(
            "source_chain",
            PolicyOutcome::Deny,
            format!(
                "source chain {} not allowed; add it to [defi] allowed_source_chains",
                ctx.source_chain
            ),
        ));
    }
    if ctx.cross_chain {
        let dst = ctx.destination_chain.to_lowercase();
        if policy
            .allowed_destination_chains
            .iter()
            .any(|c| c.to_lowercase() == dst)
        {
            out.push(check(
                "destination_chain",
                PolicyOutcome::Pass,
                format!("destination chain {} allowed", ctx.destination_chain),
            ));
        } else {
            out.push(check(
                "destination_chain",
                PolicyOutcome::Deny,
                format!(
                    "destination chain {} not allowed; add it to [defi] allowed_destination_chains",
                    ctx.destination_chain
                ),
            ));
        }
    }

    // ── receiver (deny wins; empty allowlist = unknown refuses) ───────────
    if receiver_set_matches(&policy.denied_receivers, ctx) {
        out.push(check(
            "receiver",
            PolicyOutcome::Deny,
            format!(
                "receiver {} ({}) is denylisted",
                ctx.receiver,
                ctx.receiver_class.as_str()
            ),
        ));
    } else if receiver_set_matches(&policy.allowed_receivers, ctx) {
        out.push(check(
            "receiver",
            PolicyOutcome::Pass,
            format!(
                "receiver {} permitted ({})",
                ctx.receiver,
                ctx.receiver_class.as_str()
            ),
        ));
    } else {
        out.push(check(
            "receiver",
            PolicyOutcome::Deny,
            format!(
                "receiver {} ({}) is not allowlisted; add \"{}\" or \"class:{}\" to \
                 [defi] allowed_receivers",
                ctx.receiver,
                ctx.receiver_class.as_str(),
                receiver_literal(ctx),
                ctx.receiver_class.as_str()
            ),
        ));
    }

    // ── B1: the destination receiver must be *proven*, not just requested ─
    // For cross-chain routes the staged tx is on the source chain and the
    // destination credit happens later (settlement) — the receiver gate above
    // is then advisory until wait_settlement confirms it. Surface that
    // honestly rather than implying enforcement.
    // Cross-chain is always settlement-deferred (Warn): the staged tx is on
    // the source chain and the destination credit cannot be proven until
    // wait_settlement. Same-chain: Deny unless the user opted out of
    // verification, in which case Warn.
    if !ctx.receiver_verified {
        let outcome = if ctx.cross_chain || !policy.require_calldata_verification {
            PolicyOutcome::Warn
        } else {
            PolicyOutcome::Deny
        };
        let msg = if ctx.cross_chain {
            "cross-chain receiver is from the route request, not yet proven on the \
             destination chain — enforced at settlement (wait_settlement)"
        } else if policy.require_calldata_verification {
            "route receiver is unverified (calldata not decoded / not simulated); \
             refusing rather than enforcing policy against an unproven destination \
             (set [defi] require_calldata_verification = false to accept this risk)"
        } else {
            "route receiver is the requested address but not calldata-verified \
             (require_calldata_verification = false)"
        };
        out.push(check("receiver_verified", outcome, msg));
    }

    // ── B1: guaranteed-output floor must be enforced, not quote-only ──────
    if !ctx.min_out_enforced {
        let outcome = if policy.require_calldata_verification {
            PolicyOutcome::Deny
        } else {
            PolicyOutcome::Warn
        };
        let msg = if policy.require_calldata_verification {
            "no verified minimum-output floor (slippage/min-out is quote-only, not \
             calldata-decoded or simulated) — refusing: a stale quote or sandwich could \
             deliver near-zero output with every other check passing (set [defi] \
             require_calldata_verification = false to accept the quote floor)"
        } else {
            "minimum-output is the Enso quote floor, not calldata-verified \
             (require_calldata_verification = false)"
        };
        out.push(check("min_output", outcome, msg));
    } else {
        out.push(check(
            "min_output",
            PolicyOutcome::Pass,
            "minimum-output floor is enforced",
        ));
    }

    // ── router allowlist (empty = none once enabled) ──────────────────────
    let router_key = format!(
        "{}:{}",
        ctx.source_chain.to_lowercase(),
        ctx.router.to_lowercase()
    );
    if policy.allowed_routers.contains(&router_key) {
        out.push(check(
            "router",
            PolicyOutcome::Pass,
            format!("router {} allowlisted", ctx.router),
        ));
    } else {
        out.push(check(
            "router",
            PolicyOutcome::Deny,
            format!(
                "router {} not allowlisted; add \"{}\" to [defi] allowed_routers",
                ctx.router, router_key
            ),
        ));
    }

    // ── protocols (deny by name; unknown fails closed) ────────────────────
    if ctx.protocols_unknown {
        out.push(check(
            "protocols",
            if policy.allow_unknown_protocols {
                PolicyOutcome::Warn
            } else {
                PolicyOutcome::Deny
            },
            if policy.allow_unknown_protocols {
                "route protocol metadata could not be parsed; allowed by \
                 allow_unknown_protocols = true"
                    .to_string()
            } else {
                "route protocol metadata could not be parsed; refusing (set [defi] \
                 allow_unknown_protocols = true to permit unparsed routes)"
                    .to_string()
            },
        ));
    } else {
        let mut denied_hit = None;
        for p in &ctx.protocols {
            if policy.denied_protocols.contains(&p.to_lowercase()) {
                denied_hit = Some(p.clone());
                break;
            }
        }
        match denied_hit {
            Some(p) => out.push(check(
                "protocols",
                PolicyOutcome::Deny,
                format!("route uses denied protocol '{p}'"),
            )),
            None => out.push(check(
                "protocols",
                PolicyOutcome::Pass,
                if ctx.protocols.is_empty() {
                    "no protocol restrictions".to_string()
                } else {
                    format!("protocols permitted: {}", ctx.protocols.join(" -> "))
                },
            )),
        }
    }

    // ── input value cap (micro-USD) ───────────────────────────────────────
    if let Some(cap) = policy.max_input_usd {
        match ctx.input_microusd {
            Some(v) if v > cap => out.push(check(
                "max_input_usd",
                PolicyOutcome::Deny,
                format!(
                    "route input {} USD exceeds max_input_usd {}",
                    fmt_usd(v),
                    fmt_usd(cap)
                ),
            )),
            Some(v) => out.push(check(
                "max_input_usd",
                PolicyOutcome::Pass,
                format!("{} <= {}", fmt_usd(v), fmt_usd(cap)),
            )),
            None => out.push(check(
                "max_input_usd",
                PolicyOutcome::Deny,
                "max_input_usd is set but the route input USD value is unknown (no price) \
                 — refusing rather than trading uncapped",
            )),
        }
    }

    // ── native value cap (wei) ────────────────────────────────────────────
    if let Some(cap) = policy.max_native_value_wei {
        if ctx.native_value_wei > cap {
            out.push(check(
                "max_native_value",
                PolicyOutcome::Deny,
                format!(
                    "route attaches {} wei native value, exceeding max_native_value {} wei",
                    ctx.native_value_wei, cap
                ),
            ));
        } else {
            out.push(check(
                "max_native_value",
                PolicyOutcome::Pass,
                format!("{} <= {} wei", ctx.native_value_wei, cap),
            ));
        }
    } else if ctx.native_value_wei > alloy::primitives::U256::ZERO {
        // Native-in route with no cap configured: surface it, don't deny.
        out.push(check(
            "max_native_value",
            PolicyOutcome::Warn,
            format!(
                "route attaches {} wei native value and no max_native_value is set",
                ctx.native_value_wei
            ),
        ));
    }

    out
}

/// Any Deny in the set? Deny-level failures are never CLI-bypassable.
pub fn has_deny(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(|c| c.outcome == PolicyOutcome::Deny)
}

/// Any Warn in the set?
pub fn has_warn(checks: &[PolicyCheck]) -> bool {
    checks.iter().any(|c| c.outcome == PolicyOutcome::Warn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    fn enabled_policy() -> DefiPolicy {
        DefiPolicy {
            enabled: true,
            allowed_source_chains: ["polygon".into()].into_iter().collect(),
            allowed_destination_chains: BTreeSet::new(),
            allowed_receivers: ["class:polymarket_deposit_wallet".into()]
                .into_iter()
                .collect(),
            denied_receivers: BTreeSet::new(),
            allowed_routers: ["polygon:0xf75584ef6673ad213a685a1b58cc0330b8ea22cf".into()]
                .into_iter()
                .collect(),
            denied_protocols: BTreeSet::new(),
            allow_unknown_protocols: false,
            require_calldata_verification: true,
            max_input_usd: None,
            max_native_value_wei: None,
        }
    }

    fn clean_ctx() -> DefiRouteCtx {
        DefiRouteCtx {
            wallet: "minnow".into(),
            source_chain: "polygon".into(),
            destination_chain: "polygon".into(),
            cross_chain: false,
            receiver: "0x1000000000000000000000000000000000000001".into(),
            token_out: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
            receiver_class: ReceiverClass::PolymarketDepositWallet,
            router: "0xf75584ef6673ad213a685a1b58cc0330b8ea22cf".into(),
            protocols: vec!["enso".into()],
            protocols_unknown: false,
            input_microusd: Some(4_000_000),
            native_value_wei: U256::ZERO,
            min_out_enforced: true,
            receiver_verified: true,
        }
    }

    #[test]
    fn disabled_by_default_denies() {
        let checks = evaluate_defi_route(&DefiPolicy::default(), &clean_ctx());
        assert!(has_deny(&checks));
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "defi.enabled" && c.outcome == PolicyOutcome::Deny)
        );
    }

    #[test]
    fn clean_route_passes_when_enabled() {
        let checks = evaluate_defi_route(&enabled_policy(), &clean_ctx());
        assert!(!has_deny(&checks), "{checks:?}");
    }

    #[test]
    fn class_allowlist_matches_resolved_receiver() {
        // The allowlist holds a class token, not the literal address — so a
        // wrong/typo'd address can't disagree with what bloom resolved (B3).
        let p = enabled_policy();
        let mut ctx = clean_ctx();
        ctx.receiver = "0xWHATEVER_THE_RESOLVER_SAYS".to_lowercase();
        // still classified as deposit wallet ⇒ still allowed
        assert!(!has_deny(&evaluate_defi_route(&p, &ctx)));
        // but reclassified as unknown ⇒ refused
        ctx.receiver_class = ReceiverClass::Unknown;
        assert!(has_deny(&evaluate_defi_route(&p, &ctx)));
    }

    #[test]
    fn unverified_min_output_refuses_same_chain() {
        let mut ctx = clean_ctx();
        ctx.min_out_enforced = false;
        let checks = evaluate_defi_route(&enabled_policy(), &ctx);
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "defi.min_output" && c.outcome == PolicyOutcome::Deny)
        );
    }

    #[test]
    fn unverified_receiver_denies_same_chain_warns_cross_chain() {
        let mut ctx = clean_ctx();
        ctx.receiver_verified = false;
        let same = evaluate_defi_route(&enabled_policy(), &ctx);
        assert!(
            same.iter()
                .any(|c| c.rule == "defi.receiver_verified" && c.outcome == PolicyOutcome::Deny)
        );

        ctx.cross_chain = true;
        let mut p = enabled_policy();
        p.allowed_destination_chains = ["polygon".into()].into_iter().collect();
        let cross = evaluate_defi_route(&p, &ctx);
        assert!(
            cross
                .iter()
                .any(|c| c.rule == "defi.receiver_verified" && c.outcome == PolicyOutcome::Warn)
        );
    }

    #[test]
    fn require_calldata_verification_defaults_true() {
        assert!(DefiPolicy::default().require_calldata_verification);
        // and a bare [defi] table parses to the secure default
        let p: DefiPolicy = toml::from_str("enabled = true\n").unwrap();
        assert!(p.require_calldata_verification);
    }

    #[test]
    fn opt_out_downgrades_b1_denials_to_warn() {
        let mut p = enabled_policy();
        p.require_calldata_verification = false;
        let mut ctx = clean_ctx();
        ctx.min_out_enforced = false;
        ctx.receiver_verified = false;
        let checks = evaluate_defi_route(&p, &ctx);
        assert!(!has_deny(&checks), "{checks:?}");
        assert!(has_warn(&checks));
    }

    #[test]
    fn deny_receiver_wins_over_allow() {
        let mut p = enabled_policy();
        p.denied_receivers = ["class:polymarket_deposit_wallet".into()]
            .into_iter()
            .collect();
        assert!(has_deny(&evaluate_defi_route(&p, &clean_ctx())));
    }

    #[test]
    fn empty_allowlist_refuses_unknown_receiver_and_router() {
        let mut p = enabled_policy();
        p.allowed_receivers = BTreeSet::new();
        p.allowed_routers = BTreeSet::new();
        let checks = evaluate_defi_route(&p, &clean_ctx());
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "defi.receiver" && c.outcome == PolicyOutcome::Deny)
        );
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "defi.router" && c.outcome == PolicyOutcome::Deny)
        );
    }

    #[test]
    fn unknown_protocols_fail_closed_unless_allowed() {
        let mut ctx = clean_ctx();
        ctx.protocols_unknown = true;
        ctx.protocols.clear();
        assert!(has_deny(&evaluate_defi_route(&enabled_policy(), &ctx)));
        let mut p = enabled_policy();
        p.allow_unknown_protocols = true;
        let checks = evaluate_defi_route(&p, &ctx);
        assert!(!has_deny(&checks));
        assert!(has_warn(&checks));
    }

    #[test]
    fn denied_protocol_refuses() {
        let mut p = enabled_policy();
        p.denied_protocols = ["stargate".into()].into_iter().collect();
        let mut ctx = clean_ctx();
        ctx.protocols = vec!["stargate".into(), "odos".into()];
        assert!(has_deny(&evaluate_defi_route(&p, &ctx)));
    }

    #[test]
    fn destination_chain_must_be_allowed_cross_chain() {
        let mut ctx = clean_ctx();
        ctx.cross_chain = true;
        ctx.destination_chain = "base".into();
        // no allowed_destination_chains ⇒ deny
        assert!(has_deny(&evaluate_defi_route(&enabled_policy(), &ctx)));
    }

    #[test]
    fn native_value_cap_and_uncapped_warn() {
        let mut ctx = clean_ctx();
        ctx.native_value_wei = U256::from(50u64) * U256::from(10u64).pow(U256::from(18u64));
        // no cap set ⇒ warn, not deny
        let checks = evaluate_defi_route(&enabled_policy(), &ctx);
        assert!(!has_deny(&checks));
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "defi.max_native_value" && c.outcome == PolicyOutcome::Warn)
        );
        // cap below value ⇒ deny
        let mut p = enabled_policy();
        p.max_native_value_wei = Some(U256::from(10u64).pow(U256::from(18u64)));
        assert!(has_deny(&evaluate_defi_route(&p, &ctx)));
    }

    #[test]
    fn max_input_usd_fails_closed_without_price() {
        let mut p = enabled_policy();
        p.max_input_usd = Some(10_000_000);
        let mut ctx = clean_ctx();
        ctx.input_microusd = None;
        assert!(has_deny(&evaluate_defi_route(&p, &ctx)));
    }

    #[test]
    fn toml_round_trip() {
        let src = r#"
enabled = true
allowed_source_chains = ["polygon", "base"]
allowed_destination_chains = ["polygon"]
allowed_receivers = ["class:polymarket_deposit_wallet"]
allowed_routers = ["polygon:0xabc"]
denied_protocols = ["sketchybridge"]
max_input_usd = "25"
max_native_value_wei = "75000000000000000000"
"#;
        let p: DefiPolicy = toml::from_str(src).unwrap();
        assert!(p.enabled);
        assert_eq!(p.max_input_usd, Some(25_000_000));
        assert_eq!(
            p.max_native_value_wei,
            Some(U256::from(75u64) * U256::from(10u64).pow(U256::from(18u64)))
        );
        assert!(
            p.allowed_receivers
                .contains("class:polymarket_deposit_wallet")
        );
    }
}
