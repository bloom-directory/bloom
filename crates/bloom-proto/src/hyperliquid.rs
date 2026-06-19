//! Hyperliquid deposit rules — a first-class "deposit to Hyperliquid" goal.
//!
//! Hyperliquid credits collateral from **native USDC on Arbitrum** sent to
//! its Bridge2 contract. The rules below are sourced from the mirrored
//! Bridge2 docs and exist so a deposit goal can be validated *before* any
//! funds move, rather than learning the hard way that a deposit was not
//! credited:
//!
//! - the deposit must land as Arbitrum-native USDC at the bridge;
//! - a deposit **under 5 USDC is not credited** (and the funds are not
//!   automatically returned) — so we refuse below the minimum;
//! - Base (or any non-Arbitrum) USDC sent directly to the bridge is **not**
//!   a valid deposit path;
//! - dust amounts (e.g. leftover on Polygon) may cost more in gas/bridging
//!   than they are worth — surfaced as a warning, not a hard error.

/// Hyperliquid Bridge2 contract on Arbitrum (mainnet). Native USDC sent here
/// is credited to the sender's Hyperliquid account.
pub const MAINNET_BRIDGE: &str = "0x2df1c51e09aecf9cacb7bc98cb1742757f163df7";

/// Arbitrum One — the only chain whose native USDC the bridge credits.
pub const DEPOSIT_CHAIN_ID: u64 = 42161;

/// Minimum credited deposit, in USDC base units (6 decimals): 5 USDC.
/// Deposits below this are not credited by the bridge.
pub const MIN_DEPOSIT_USDC_6DP: u128 = 5_000_000;

/// Below this (10 USDC) on a non-Arbitrum source chain, a bridge+deposit is
/// likely to cost more in gas than it is worth — warn the caller.
pub const DUST_WARN_USDC_6DP: u128 = 10_000_000;

/// Outcome of validating a proposed Hyperliquid deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositCheck {
    /// The deposit is valid. `warning` is `Some` for an allowed-but-questionable
    /// deposit (e.g. dust that may not be worth bridging).
    Ok { warning: Option<String> },
    /// The deposit must be rejected; the string explains why.
    Reject(String),
}

/// Validate a proposed deposit.
///
/// * `source_chain_id` — the chain the funds start on.
/// * `is_usdc` — whether the token being deposited is USDC.
/// * `amount_6dp` — the deposit amount in USDC base units (6 decimals).
/// * `direct_to_bridge` — true when the plan sends the source token *directly*
///   to the bridge with no bridging leg (only valid from Arbitrum).
pub fn check_deposit(
    source_chain_id: u64,
    is_usdc: bool,
    amount_6dp: u128,
    direct_to_bridge: bool,
) -> DepositCheck {
    if !is_usdc {
        return DepositCheck::Reject(
            "Hyperliquid deposits must be USDC; only native USDC is credited.".into(),
        );
    }
    // A direct send to the bridge is only valid from Arbitrum. Sending e.g.
    // Base USDC straight to the Arbitrum bridge address does not credit.
    if direct_to_bridge && source_chain_id != DEPOSIT_CHAIN_ID {
        return DepositCheck::Reject(format!(
            "direct deposit from chain {source_chain_id} is not a valid path — the bridge only \
             credits native USDC on Arbitrum (chain {DEPOSIT_CHAIN_ID}). Bridge to Arbitrum USDC \
             first, then deposit."
        ));
    }
    if amount_6dp < MIN_DEPOSIT_USDC_6DP {
        return DepositCheck::Reject(format!(
            "deposit of {} USDC is below Hyperliquid's {} USDC minimum and would not be credited \
             (funds are not auto-returned).",
            render_usdc(amount_6dp),
            render_usdc(MIN_DEPOSIT_USDC_6DP),
        ));
    }
    // Allowed, but warn on cross-chain dust where gas likely exceeds value.
    if source_chain_id != DEPOSIT_CHAIN_ID && amount_6dp < DUST_WARN_USDC_6DP {
        return DepositCheck::Ok {
            warning: Some(format!(
                "bridging {} USDC from chain {source_chain_id} may cost more in gas than it is \
                 worth; consider depositing a larger amount.",
                render_usdc(amount_6dp),
            )),
        };
    }
    DepositCheck::Ok { warning: None }
}

/// Render a 6-decimal USDC base-unit amount as a human string.
fn render_usdc(amount_6dp: u128) -> String {
    let whole = amount_6dp / 1_000_000;
    let frac = amount_6dp % 1_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{frac:06}")
            .trim_end_matches('0')
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrum_usdc_above_min_is_ok() {
        assert_eq!(
            check_deposit(DEPOSIT_CHAIN_ID, true, 6_000_000, true),
            DepositCheck::Ok { warning: None }
        );
    }

    #[test]
    fn below_five_usdc_is_rejected() {
        let r = check_deposit(DEPOSIT_CHAIN_ID, true, 4_999_999, true);
        match r {
            DepositCheck::Reject(msg) => assert!(msg.contains("minimum")),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn base_direct_deposit_is_rejected() {
        // Base = 8453; a direct send to the Arbitrum bridge must be refused.
        let r = check_deposit(8453, true, 6_000_000, true);
        match r {
            DepositCheck::Reject(msg) => assert!(msg.contains("Arbitrum")),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn polygon_dust_warns_but_allows() {
        // Polygon = 137, bridged (not direct), above min but below dust line.
        let r = check_deposit(137, true, 6_000_000, false);
        match r {
            DepositCheck::Ok { warning: Some(w) } => assert!(w.contains("gas")),
            other => panic!("expected ok-with-warning, got {other:?}"),
        }
    }

    #[test]
    fn non_usdc_is_rejected() {
        assert!(matches!(
            check_deposit(DEPOSIT_CHAIN_ID, false, 9_000_000, true),
            DepositCheck::Reject(_)
        ));
    }

    #[test]
    fn renders_usdc_amounts() {
        assert_eq!(render_usdc(5_000_000), "5");
        assert_eq!(render_usdc(4_999_999), "4.999999");
        assert_eq!(render_usdc(1_500_000), "1.5");
    }
}
