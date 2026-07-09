//! Shared balance rendering — the convention used by native and ERC-20 reads.
//!
//! - `balance`      → human display *with symbol* ("23739.58 POL")
//! - `balance.raw`  → raw integer base units ("23739589974494571130021")
//! - `balance.json` → structured facts (symbol, decimals, raw, formatted, display)
//!
//! Centralized so native (wallet + address) and token reads stay identical in
//! shape and an agent never has to infer units from a bare integer.

use alloy::primitives::U256;
use bloom_proto::format_units;
use std::time::Duration;

/// Live balance/nonce reads change with the chain head but are expensive enough
/// to cache briefly during agent bursts and mounted filesystem probes.
pub(crate) const LIVE_BALANCE_TTL: Duration = Duration::from_secs(5);

/// ERC-20 metadata is effectively static for normal tokens. Keep this separate
/// from live balance TTLs so display leaves can refresh balances without
/// repeatedly calling `symbol()` and `decimals()`.
pub(crate) const TOKEN_METADATA_TTL: Duration = Duration::from_secs(7 * 86_400);

/// `"<formatted> <symbol>\n"` for the `balance` leaf.
pub(crate) fn display_line(raw: U256, decimals: u8, symbol: &str) -> Vec<u8> {
    format!("{} {}\n", format_units(raw, decimals), symbol).into_bytes()
}

/// `"<raw>\n"` for the `balance.raw` leaf.
pub(crate) fn raw_line(raw: U256) -> Vec<u8> {
    format!("{raw}\n").into_bytes()
}

/// Pretty JSON facts for the `balance.json` leaf. `asset` is `"native"` or
/// `"erc20"`; `token_address` is included only for tokens.
pub(crate) fn balance_json(
    chain: &str,
    asset: &str,
    token_address: Option<&str>,
    symbol: &str,
    decimals: u8,
    raw: U256,
) -> Vec<u8> {
    let formatted = format_units(raw, decimals);
    let mut obj = serde_json::json!({
        "chain": chain,
        "asset": asset,
        "symbol": symbol,
        "decimals": decimals,
        "raw": raw.to_string(),
        "formatted": formatted,
        "display": format!("{formatted} {symbol}"),
    });
    if let Some(addr) = token_address {
        obj["address"] = serde_json::Value::String(addr.to_string());
    }
    let mut v = serde_json::to_vec_pretty(&obj).expect("balance json serializes");
    v.push(b'\n');
    v
}

/// Pretty JSON facts for the ERC-20 `balance.json` leaf, with explicit
/// metadata provenance. Unlike [`balance_json`] (native, where decimals
/// and symbol come from the chain spec and are always known), token
/// metadata is read on-chain and can be unresolved. When `symbol` or
/// `decimals` is `None` they are emitted as `null`, `formatted`/`display`
/// are omitted (can't compute without decimals), and `metadata_status` is
/// `"fallback"` — so an agent never mistakes degraded metadata for real
/// values. `raw` is always present.
pub(crate) fn token_balance_json(
    chain: &str,
    token_address: &str,
    symbol: Option<&str>,
    decimals: Option<u8>,
    raw: U256,
) -> Vec<u8> {
    let metadata_status = if symbol.is_some() && decimals.is_some() {
        "ok"
    } else {
        "fallback"
    };
    let formatted = decimals.map(|d| format_units(raw, d));
    let display = match (formatted.as_deref(), symbol) {
        (Some(f), Some(s)) => Some(format!("{f} {s}")),
        _ => None,
    };
    let obj = serde_json::json!({
        "chain": chain,
        "asset": "erc20",
        "address": token_address,
        "symbol": symbol,
        "decimals": decimals,
        "raw": raw.to_string(),
        "formatted": formatted,
        "display": display,
        "metadata_status": metadata_status,
    });
    let mut v = serde_json::to_vec_pretty(&obj).expect("token balance json serializes");
    v.push(b'\n');
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_balance_json_ok_when_metadata_resolved() {
        let bytes = token_balance_json(
            "base",
            "0xToken",
            Some("USDC"),
            Some(6),
            U256::from(1_500_000u64),
        );
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["metadata_status"], "ok");
        assert_eq!(v["symbol"], "USDC");
        assert_eq!(v["decimals"], 6);
        assert_eq!(v["formatted"], "1.5");
        assert_eq!(v["display"], "1.5 USDC");
        assert_eq!(v["raw"], "1500000");
    }

    #[test]
    fn token_balance_json_flags_fallback_with_nulls() {
        let bytes = token_balance_json("base", "0xToken", None, None, U256::from(42u64));
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["metadata_status"], "fallback");
        assert!(v["symbol"].is_null(), "symbol must be null, not '?'");
        assert!(v["decimals"].is_null(), "decimals must be null, not 18");
        assert!(v["formatted"].is_null());
        assert!(v["display"].is_null());
        // The raw integer is still trustworthy and present.
        assert_eq!(v["raw"], "42");
    }
}
