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
