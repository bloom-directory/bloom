//! Polymarket V2 order building, signing, and wire encoding (EOA path,
//! signatureType 0).
//!
//! Every byte-exact convention here is copied from the official
//! `Polymarket/rs-clob-client-v2` SDK (`src/clob/order_builder.rs`,
//! `src/clob/types/mod.rs`, `src/clob/client.rs`), which is the reference for
//! what the live CLOB accepts:
//!
//! - The signed struct is the **V2** `Order` (no `taker`/`expiration`/`nonce`/
//!   `feeRateBps`; adds `timestamp` in **milliseconds**, `metadata`, `builder`).
//!   The Solidity type name must be exactly `Order` — it is hashed into the
//!   on-chain EIP-712 typehash.
//! - EIP-712 domain: name `"Polymarket CTF Exchange"`, version `"2"` for both
//!   the normal and neg-risk exchanges; only the verifying contract differs.
//! - `salt` is a random integer masked to JS `Number.MAX_SAFE_INTEGER`
//!   (2^53 - 1) and is serialized as a JSON **number**, not a string.
//! - `expiration` is not part of the signed struct; it travels in the wire
//!   body and must be `0` for all order types except GTD.
//! - Wire `side` is `"BUY"`/`"SELL"`; the signed struct carries `uint8`.
//! - The POST body `owner` is the **CLOB API key**, not an address.
//! - Amount math (from the SDK's limit-order builder): prices must be on-tick
//!   and within `[tick, 1 - tick]`; share sizes are quantized to 2 decimal
//!   places (`LOT_SIZE_SCALE`); the USD leg is `trunc(size * price, tick
//!   decimals + 2)`. All math here is integer micro-units (6 dp) — no floats.

use std::borrow::Cow;

use alloy::dyn_abi::Eip712Domain;
use alloy::primitives::{Address, B256, U256};
use alloy::sol_types::SolStruct;
use serde::{Deserialize, Serialize};

use crate::eip712::{CTF_EXCHANGE_V2, NEG_RISK_EXCHANGE_V2};
use crate::signer::{KeystoreSigner, OnboardSigner};
use crate::types::Side;
use crate::{PolymarketError, Result};

// Inside a module so `sol!` emits the Solidity type name `Order` without
// clashing with anything else; the typehash depends on that exact name.
mod sol_defs {
    alloy::sol! {
        /// Polymarket CTF Exchange **V2** order struct.
        #[derive(Debug, PartialEq)]
        struct Order {
            uint256 salt;
            address maker;
            address signer;
            uint256 tokenId;
            uint256 makerAmount;
            uint256 takerAmount;
            uint8   side;           // 0 = BUY, 1 = SELL
            uint8   signatureType;  // 0 = EOA
            uint256 timestamp;      // unix milliseconds
            bytes32 metadata;
            bytes32 builder;        // builder attribution code (zero if none)
        }
    }
}
pub use sol_defs::Order;

/// One USD / one share in 6-dp fixed point.
pub const MICRO: u64 = 1_000_000;
/// Share sizes are quantized to 2 decimal places (SDK `LOT_SIZE_SCALE`).
const LOT_SIZE_SCALE: u32 = 2;
const LOT_UNIT: u64 = 10_000; // 10^(6 - LOT_SIZE_SCALE)
/// Salts are masked to JS `Number.MAX_SAFE_INTEGER` like the official clients.
const JS_SAFE_INTEGER_MAX: u64 = (1 << 53) - 1;

/// CLOB order types. Serialized exactly as the API expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderType {
    /// Good 'til cancelled — rests on the book. Refused by bloom unless
    /// cancel support is available to the caller.
    GTC,
    /// Fill or kill — all-or-nothing, never rests.
    FOK,
    /// Good 'til date — requires a non-zero expiration.
    GTD,
    /// Fill and kill — fills what it can immediately, never rests.
    FAK,
}

impl OrderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrderType::GTC => "GTC",
            OrderType::FOK => "FOK",
            OrderType::GTD => "GTD",
            OrderType::FAK => "FAK",
        }
    }

    /// Whether an unfilled remainder can rest on the book.
    pub fn can_rest(&self) -> bool {
        matches!(self, OrderType::GTC | OrderType::GTD)
    }
}

impl std::str::FromStr for OrderType {
    type Err = PolymarketError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "GTC" => Ok(OrderType::GTC),
            "FOK" => Ok(OrderType::FOK),
            "GTD" => Ok(OrderType::GTD),
            "FAK" => Ok(OrderType::FAK),
            other => Err(PolymarketError::invalid(format!(
                "unknown order type '{other}' (expected GTC, FOK, GTD, or FAK)"
            ))),
        }
    }
}

/// EIP-712 domain for the V2 exchanges. Name and version are identical for the
/// normal and neg-risk exchanges; only the verifying contract differs.
pub fn ctf_exchange_domain(chain_id: u64, neg_risk: bool) -> Eip712Domain {
    Eip712Domain {
        name: Some(Cow::Borrowed("Polymarket CTF Exchange")),
        version: Some(Cow::Borrowed("2")),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: Some(if neg_risk {
            NEG_RISK_EXCHANGE_V2
        } else {
            CTF_EXCHANGE_V2
        }),
        ..Eip712Domain::default()
    }
}

// ── micro-unit decimal parsing ────────────────────────────────────────────────

/// Parse a non-negative decimal string (≤ 6 fractional digits) into integer
/// micro-units. `"0.56"` → `560_000`. Rejects empty, negative, malformed, and
/// over-precise input.
pub fn parse_micro(s: &str) -> Result<u64> {
    let s = s.trim();
    let bad = |m: &str| PolymarketError::invalid(format!("bad decimal '{s}': {m}"));
    if s.is_empty() {
        return Err(bad("empty"));
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int_part.starts_with('-') {
        return Err(bad("negative"));
    }
    if frac_part.len() > 6 {
        return Err(bad("more than 6 decimal places"));
    }
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
        || (int_part.is_empty() && frac_part.is_empty())
    {
        return Err(bad("not a decimal number"));
    }
    let int_v: u64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().map_err(|_| bad("integer overflow"))?
    };
    let mut frac_v: u64 = 0;
    if !frac_part.is_empty() {
        frac_v = frac_part.parse().map_err(|_| bad("fraction overflow"))?;
        frac_v *= 10u64.pow(6 - frac_part.len() as u32);
    }
    int_v
        .checked_mul(MICRO)
        .and_then(|v| v.checked_add(frac_v))
        .ok_or_else(|| bad("overflow"))
}

/// Render micro-units as a decimal string (trailing zeros trimmed).
pub fn format_micro(v: u64) -> String {
    let int = v / MICRO;
    let frac = v % MICRO;
    if frac == 0 {
        return int.to_string();
    }
    let s = format!("{int}.{frac:06}");
    s.trim_end_matches('0').to_string()
}

/// Number of decimal places a tick size allows (`0.01` → 2). Ticks must be a
/// power of ten between `0.0001` and `0.1`, matching the CLOB's `TickSize`.
fn tick_decimals(tick_micro: u64) -> Result<u32> {
    match tick_micro {
        100_000 => Ok(1),
        10_000 => Ok(2),
        1_000 => Ok(3),
        100 => Ok(4),
        other => Err(PolymarketError::invalid(format!(
            "unsupported tick size {} (micro={other})",
            format_micro(other)
        ))),
    }
}

/// Quantize a buyer's price down to the tick grid (never pays more than asked)
/// or a seller's price up (never receives less than asked).
pub fn quantize_price(price_micro: u64, tick_micro: u64, side: Side) -> u64 {
    let rem = price_micro % tick_micro;
    match side {
        Side::Buy => price_micro - rem,
        Side::Sell => {
            if rem == 0 {
                price_micro
            } else {
                price_micro - rem + tick_micro
            }
        }
    }
}

/// Quantize a book-derived marketable limit without crossing away from the
/// book. BUY follows the best ask downward; SELL follows the best bid downward
/// too, so a FAK sell limit never ends up above the bid and silently fails to
/// fill.
pub fn quantize_marketable_limit(price_micro: u64, tick_micro: u64, _side: Side) -> u64 {
    price_micro - (price_micro % tick_micro)
}

fn validate_price(price_micro: u64, tick_micro: u64) -> Result<()> {
    tick_decimals(tick_micro)?;
    if !price_micro.is_multiple_of(tick_micro) {
        return Err(PolymarketError::invalid(format!(
            "price {} is not a multiple of tick size {}",
            format_micro(price_micro),
            format_micro(tick_micro)
        )));
    }
    if price_micro < tick_micro || price_micro > MICRO - tick_micro {
        return Err(PolymarketError::invalid(format!(
            "price {} outside [{}, {}] for tick size {}",
            format_micro(price_micro),
            format_micro(tick_micro),
            format_micro(MICRO - tick_micro),
            format_micro(tick_micro)
        )));
    }
    Ok(())
}

// ── order quantities ──────────────────────────────────────────────────────────

/// Integer quantities for one V2 limit order. All micro-units (6 dp).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitQuote {
    pub side: Side,
    /// Limit price, on the tick grid.
    pub price_micro: u64,
    /// Share size, a multiple of `0.01` shares.
    pub size_micro: u64,
    /// What the maker gives: USD for buys, shares for sells.
    pub maker_micro: u64,
    /// What the maker demands: shares for buys, USD for sells.
    pub taker_micro: u64,
}

/// `trunc(size * price, tick_decimals + LOT_SIZE_SCALE)` — the SDK's USD-leg
/// rounding for limit orders, in integer micro math.
fn usd_leg(size_micro: u64, price_micro: u64, tick_micro: u64) -> Result<u64> {
    let decimals = tick_decimals(tick_micro)?;
    // size*price is exact in u128; /MICRO returns to 6-dp scale.
    let raw = (size_micro as u128 * price_micro as u128) / MICRO as u128;
    let keep = 10u128.pow(6 - (decimals + LOT_SIZE_SCALE).min(6));
    u64::try_from(raw - raw % keep).map_err(|_| PolymarketError::invalid("order amount overflow"))
}

impl LimitQuote {
    /// Build a BUY quote from a USD spend budget and a limit price: shares are
    /// `spend / price` rounded **down** to the 0.01-share grid, and the USD leg
    /// is recomputed as `trunc(size * price)` so the implied price never
    /// exceeds the limit. The actual spend can be slightly below `spend_micro`.
    pub fn buy_from_spend(spend_micro: u64, price_micro: u64, tick_micro: u64) -> Result<Self> {
        validate_price(price_micro, tick_micro)?;
        if spend_micro == 0 {
            return Err(PolymarketError::invalid("spend amount must be > 0"));
        }
        let size = (spend_micro as u128 * MICRO as u128) / price_micro as u128;
        let size_micro = u64::try_from(size - size % LOT_UNIT as u128)
            .map_err(|_| PolymarketError::invalid("share size overflow"))?;
        if size_micro == 0 {
            return Err(PolymarketError::invalid(format!(
                "spend {} buys less than 0.01 shares at price {}",
                format_micro(spend_micro),
                format_micro(price_micro)
            )));
        }
        let maker_micro = usd_leg(size_micro, price_micro, tick_micro)?;
        Ok(Self {
            side: Side::Buy,
            price_micro,
            size_micro,
            maker_micro,
            taker_micro: size_micro,
        })
    }

    /// Build a **market** BUY quote (FAK/FOK) from a USD spend budget: the
    /// CLOB requires market-buy `makerAmount` at ≤ 2 decimals (dollars) and
    /// `takerAmount` at ≤ 4 decimals (shares) — different rules from limit
    /// orders. Matching the SDK's market-order builder: maker = spend
    /// truncated to cents; shares = `spend / price` truncated to
    /// `tick_decimals + 2` places. The implied price can exceed the limit by
    /// sub-tick dust (the official client's own market-order semantics); the
    /// user's `--max-price` bound still applies to the chosen book price.
    pub fn market_buy_from_spend(
        spend_micro: u64,
        price_micro: u64,
        tick_micro: u64,
    ) -> Result<Self> {
        validate_price(price_micro, tick_micro)?;
        if spend_micro == 0 {
            return Err(PolymarketError::invalid("spend amount must be > 0"));
        }
        // makerAmount: dollars at 2 dp (cents grid).
        let maker_micro = spend_micro - spend_micro % 10_000;
        if maker_micro == 0 {
            return Err(PolymarketError::invalid("spend rounds to $0.00"));
        }
        // takerAmount: shares at tick_decimals + 2 dp.
        let decimals = tick_decimals(tick_micro)?;
        let share_unit = 10u128.pow(6 - (decimals + LOT_SIZE_SCALE).min(6));
        let raw = (maker_micro as u128 * MICRO as u128) / price_micro as u128;
        let taker_micro = u64::try_from(raw - raw % share_unit)
            .map_err(|_| PolymarketError::invalid("share size overflow"))?;
        if taker_micro == 0 {
            return Err(PolymarketError::invalid(format!(
                "spend {} buys zero shares at price {}",
                format_micro(maker_micro),
                format_micro(price_micro)
            )));
        }
        Ok(Self {
            side: Side::Buy,
            price_micro,
            size_micro: taker_micro,
            maker_micro,
            taker_micro,
        })
    }

    /// Build a SELL quote from a share size and a limit price. Size must be on
    /// the 0.01-share grid. The USD leg is `trunc(size * price)` exactly as the
    /// SDK computes it.
    pub fn sell_from_shares(size_micro: u64, price_micro: u64, tick_micro: u64) -> Result<Self> {
        validate_price(price_micro, tick_micro)?;
        if size_micro == 0 {
            return Err(PolymarketError::invalid("share size must be > 0"));
        }
        if !size_micro.is_multiple_of(LOT_UNIT) {
            return Err(PolymarketError::invalid(format!(
                "share size {} has more than {LOT_SIZE_SCALE} decimal places",
                format_micro(size_micro)
            )));
        }
        let taker_micro = usd_leg(size_micro, price_micro, tick_micro)?;
        Ok(Self {
            side: Side::Sell,
            price_micro,
            size_micro,
            maker_micro: size_micro,
            taker_micro,
        })
    }
}

// ── building and signing ─────────────────────────────────────────────────────

/// Signature type the CLOB accepts for V2 deposit-wallet orders: POLY_1271
/// (signatureType 3, the only path Bloom trades).
pub const SIG_TYPE_POLY_1271: u8 = 3;

/// Everything needed to build a signable V2 order.
///
/// For signatureType 3 (POLY_1271): `maker` = the **deposit wallet** — both
/// the struct's `maker` and `signer` fields carry it; the owner EOA only
/// produces the wrapped ERC-7739 signature that the wallet validates via
/// ERC-1271.
#[derive(Debug, Clone)]
pub struct OrderParams {
    pub token_id: U256,
    /// Funder address: the deposit wallet.
    pub maker: Address,
    pub quote: LimitQuote,
    /// Builder attribution code. **Must stay zero unless the user explicitly
    /// opted in** — builder codes are fee-bearing attribution, a separate
    /// concept from builder API keys (relayer auth).
    pub builder_code: Option<B256>,
    /// Always `SIG_TYPE_POLY_1271`.
    pub signature_type: u8,
}

/// Build a V2 order: random JS-safe salt, millisecond timestamp.
pub fn build_order(p: &OrderParams) -> Order {
    let salt = rand::random::<u64>() & JS_SAFE_INTEGER_MAX;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Order {
        salt: U256::from(salt),
        maker: p.maker,
        signer: p.maker,
        tokenId: p.token_id,
        makerAmount: U256::from(p.quote.maker_micro),
        takerAmount: U256::from(p.quote.taker_micro),
        side: p.quote.side as u8,
        signatureType: p.signature_type,
        timestamp: U256::from(timestamp_ms),
        metadata: B256::ZERO,
        builder: p.builder_code.unwrap_or(B256::ZERO),
    }
}

/// EIP-712 signing hash for `order` against the V2 exchange domain.
pub fn signing_hash(order: &Order, chain_id: u64, neg_risk: bool) -> B256 {
    order.eip712_signing_hash(&ctf_exchange_domain(chain_id, neg_risk))
}

/// EIP-712 struct-only hash of `order` (the inner typed-data contents hash,
/// used by the POLY_1271 wrapped encoding). Exposed so the pure builder in
/// `crate::signing` can wrap a host-supplied raw signature without touching
/// the keystore.
pub fn signing_hash_contents(order: &Order) -> B256 {
    order.eip712_hash_struct()
}

/// Verbatim `Order` EIP-712 type string used for the ERC-7739 wrap. Public for
/// the same reason as [`signing_hash_contents`].
pub fn order_type_string() -> &'static str {
    ORDER_TYPE_STRING
}

// ── POLY_1271 (deposit wallet, signatureType 3) ──────────────────────────────

/// ERC-7739 `TypedDataSign` type string, verbatim from the official SDK
/// (`rs-clob-client-v2 src/clob/client.rs`). The nested `Order` text must be
/// byte-identical to our struct's root type — asserted in tests.
const SOLADY_TYPE_STRING: &str = concat!(
    "TypedDataSign(Order contents,string name,string version,uint256 chainId,",
    "address verifyingContract,bytes32 salt)",
    "Order(uint256 salt,address maker,address signer,uint256 tokenId,",
    "uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,",
    "uint256 timestamp,bytes32 metadata,bytes32 builder)"
);
const ORDER_TYPE_STRING: &str = concat!(
    "Order(uint256 salt,address maker,address signer,uint256 tokenId,",
    "uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,",
    "uint256 timestamp,bytes32 metadata,bytes32 builder)"
);
const DEPOSIT_WALLET_NAME: &str = "DepositWallet";
const DEPOSIT_WALLET_VERSION: &str = "1";

/// The ERC-7739 digest the owner EOA signs for a deposit-wallet order:
/// `keccak(0x1901 ‖ APP_DOMAIN_SEPARATOR ‖ TypedDataSign struct hash)` where
/// the app domain is the CTF Exchange V2 domain and the nested fields carry
/// the DepositWallet domain with `verifyingContract = order.signer` (the
/// deposit wallet) and zero salt. Verbatim port of the SDK's
/// `sign_poly1271_order`.
pub fn poly1271_digest(order: &Order, chain_id: u64, neg_risk: bool) -> B256 {
    use alloy::primitives::keccak256;
    use alloy::sol_types::SolValue;

    let contents_hash = order.eip712_hash_struct();
    let app_domain_separator = ctf_exchange_domain(chain_id, neg_risk).hash_struct();

    let typed_data_sign_struct_hash = keccak256(
        (
            keccak256(SOLADY_TYPE_STRING.as_bytes()),
            contents_hash,
            keccak256(DEPOSIT_WALLET_NAME.as_bytes()),
            keccak256(DEPOSIT_WALLET_VERSION.as_bytes()),
            U256::from(chain_id),
            order.signer,
            B256::ZERO,
        )
            .abi_encode(),
    );

    let mut digest_input = [0u8; 66];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(app_domain_separator.as_slice());
    digest_input[34..66].copy_from_slice(typed_data_sign_struct_hash.as_slice());
    keccak256(digest_input)
}

/// Sign a deposit-wallet order (signatureType 3) and return the **wrapped**
/// ERC-7739 signature hex the CLOB expects:
/// `0x ‖ inner(65) ‖ APP_DOMAIN_SEPARATOR(32) ‖ contentsHash(32) ‖
/// contentsType ‖ len(contentsType) as u16 BE` — layout verbatim from the
/// official SDK.
pub async fn sign_order_poly1271(
    order: &Order,
    signer: &KeystoreSigner,
    chain_id: u64,
    neg_risk: bool,
) -> Result<String> {
    if order.signatureType != SIG_TYPE_POLY_1271 {
        return Err(PolymarketError::invalid(format!(
            "sign_order_poly1271 called on signatureType {}",
            order.signatureType
        )));
    }
    let contents_hash = order.eip712_hash_struct();
    let app_domain_separator = ctf_exchange_domain(chain_id, neg_risk).hash_struct();
    let digest = poly1271_digest(order, chain_id, neg_risk);
    let inner = signer.sign_eip712_hash(&digest).await?;

    let type_len =
        u16::try_from(ORDER_TYPE_STRING.len()).expect("order type string length fits in u16");
    let mut wrapped = String::with_capacity(2 + 130 + 64 + 64 + ORDER_TYPE_STRING.len() * 2 + 4);
    wrapped.push_str("0x");
    wrapped.push_str(&hex::encode(inner.as_bytes()));
    wrapped.push_str(&hex::encode(app_domain_separator.as_slice()));
    wrapped.push_str(&hex::encode(contents_hash.as_slice()));
    wrapped.push_str(&hex::encode(ORDER_TYPE_STRING.as_bytes()));
    wrapped.push_str(&hex::encode(type_len.to_be_bytes()));
    Ok(wrapped)
}

/// Dispatch on the order's signature type.
pub async fn sign_order_for_type(
    order: &Order,
    signer: &KeystoreSigner,
    chain_id: u64,
    neg_risk: bool,
) -> Result<String> {
    match order.signatureType {
        SIG_TYPE_POLY_1271 => sign_order_poly1271(order, signer, chain_id, neg_risk).await,
        other => Err(PolymarketError::invalid(format!(
            "unsupported signature type {other}"
        ))),
    }
}

// ── wire encoding ────────────────────────────────────────────────────────────

/// The `order` object inside `POST /order`, mirroring the SDK's
/// `OrderV2WithSignature` field-for-field: salt is a JSON number; U256 fields
/// are decimal strings; side is `"BUY"`/`"SELL"`; `expiration` is wire-only.
#[derive(Debug, Clone, Serialize)]
pub struct WireOrder {
    pub salt: u64,
    pub maker: Address,
    pub signer: Address,
    #[serde(rename = "tokenId")]
    pub token_id: String,
    #[serde(rename = "makerAmount")]
    pub maker_amount: String,
    #[serde(rename = "takerAmount")]
    pub taker_amount: String,
    pub side: Side,
    /// `"0"` for everything except GTD.
    pub expiration: String,
    #[serde(rename = "signatureType")]
    pub signature_type: u8,
    pub timestamp: String,
    pub metadata: B256,
    pub builder: B256,
    pub signature: String,
}

/// Full `POST /order` body. `owner` is the CLOB API key.
#[derive(Debug, Clone, Serialize)]
pub struct OrderBody {
    pub order: WireOrder,
    #[serde(rename = "orderType")]
    pub order_type: OrderType,
    pub owner: String,
    #[serde(rename = "postOnly")]
    pub post_only: bool,
}

impl OrderBody {
    /// Assemble the wire body from a signed order. `api_key` is the CLOB
    /// credential key (`Credentials::key`) — the API's "owner".
    pub fn from_signed(
        order: &Order,
        signature: &str,
        api_key: &str,
        order_type: OrderType,
    ) -> Result<Self> {
        let side = match order.side {
            0 => Side::Buy,
            1 => Side::Sell,
            other => {
                return Err(PolymarketError::invalid(format!(
                    "invalid side {other} in signed order"
                )));
            }
        };
        if order_type == OrderType::GTD {
            return Err(PolymarketError::invalid(
                "GTD orders need an expiration; not supported by this builder",
            ));
        }
        let salt: u64 = order
            .salt
            .try_into()
            .map_err(|_| PolymarketError::invalid("salt does not fit in u64"))?;
        Ok(Self {
            order: WireOrder {
                salt,
                maker: order.maker,
                signer: order.signer,
                token_id: order.tokenId.to_string(),
                maker_amount: order.makerAmount.to_string(),
                taker_amount: order.takerAmount.to_string(),
                side,
                expiration: "0".to_string(),
                signature_type: order.signatureType,
                timestamp: order.timestamp.to_string(),
                metadata: order.metadata,
                builder: order.builder,
                signature: signature.to_string(),
            },
            order_type,
            owner: api_key.to_string(),
            post_only: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    const TICK_TENTH: u64 = 100_000;
    const TICK_HUNDREDTH: u64 = 10_000;

    #[test]
    fn parse_micro_basics() {
        assert_eq!(parse_micro("0.56").unwrap(), 560_000);
        assert_eq!(parse_micro("10").unwrap(), 10_000_000);
        assert_eq!(parse_micro("21.04").unwrap(), 21_040_000);
        assert_eq!(parse_micro("0.000001").unwrap(), 1);
        assert!(parse_micro("-1").is_err());
        assert!(parse_micro("0.0000001").is_err());
        assert!(parse_micro("abc").is_err());
        assert!(parse_micro("").is_err());
    }

    /// Market-buy vectors: the SDK's market test (amount 100 @ 0.5 → maker
    /// 100_000_000 / taker 200_000_000) plus the live CLOB precision rule
    /// (maker ≤ 2 dp, taker ≤ 4 dp) that rejected maker 3.598 on 2026-06-11.
    #[test]
    fn sdk_market_buy_vectors_and_precision() {
        let q = LimitQuote::market_buy_from_spend(100_000_000, 500_000, TICK_TENTH).unwrap();
        assert_eq!((q.maker_micro, q.taker_micro), (100_000_000, 200_000_000));

        // $3.60 at 0.70 (tick 0.01): maker exactly 3.60 (2 dp), shares
        // 5.1428 (4 dp) — the combination the CLOB rejected as 3.598/5.14.
        let q = LimitQuote::market_buy_from_spend(3_600_000, 700_000, TICK_HUNDREDTH).unwrap();
        assert_eq!(q.maker_micro, 3_600_000);
        assert_eq!(q.taker_micro, 5_142_800);
        assert_eq!(q.maker_micro % 10_000, 0, "maker must be on the cents grid");
        assert_eq!(q.taker_micro % 100, 0, "taker must be ≤ 4 dp for tick 0.01");

        // Sub-cent spend is refused, not silently zeroed.
        assert!(LimitQuote::market_buy_from_spend(9_999, 700_000, TICK_HUNDREDTH).is_err());
    }

    /// Amount vectors from the official SDK's `tests/order.rs` (limit orders):
    /// the integer math must reproduce `rust_decimal` results exactly.
    #[test]
    fn sdk_limit_amount_vectors() {
        // Buy 21.04 shares @ 0.5, tick 0.1 → maker 10_520_000, taker 21_040_000.
        let q = LimitQuote::sell_from_shares(21_040_000, 500_000, TICK_TENTH).unwrap();
        assert_eq!((q.maker_micro, q.taker_micro), (21_040_000, 10_520_000));
        // Same numbers as a buy: spend 10.52 @ 0.5 buys exactly 21.04 shares.
        let q = LimitQuote::buy_from_spend(10_520_000, 500_000, TICK_TENTH).unwrap();
        assert_eq!((q.maker_micro, q.taker_micro), (10_520_000, 21_040_000));
        // Buy @ 0.56, tick 0.01, size 21.04 → maker 11_782_400.
        let q = LimitQuote::buy_from_spend(11_782_400, 560_000, TICK_HUNDREDTH).unwrap();
        assert_eq!((q.maker_micro, q.taker_micro), (11_782_400, 21_040_000));
    }

    #[test]
    fn buy_never_exceeds_limit_price() {
        // Spend $10 at 0.695 (tick 0.001): shares floor to 0.01 grid and the
        // USD leg is recomputed, so implied price == limit exactly.
        let q = LimitQuote::buy_from_spend(10_000_000, 695_000, 1_000).unwrap();
        assert_eq!(q.size_micro % LOT_UNIT, 0);
        assert!(q.maker_micro <= 10_000_000);
        // implied price = maker/taker ≤ limit
        let implied_num = q.maker_micro as u128 * MICRO as u128;
        assert!(implied_num <= q.taker_micro as u128 * q.price_micro as u128);
    }

    #[test]
    fn price_validation() {
        // off-tick
        assert!(LimitQuote::buy_from_spend(MICRO, 555_000, TICK_HUNDREDTH).is_err());
        // out of range
        assert!(LimitQuote::buy_from_spend(MICRO, 5_000, TICK_HUNDREDTH).is_err());
        assert!(LimitQuote::buy_from_spend(MICRO, 995_000, TICK_HUNDREDTH).is_err());
        // in range bounds are accepted
        assert!(LimitQuote::buy_from_spend(MICRO, 10_000, TICK_HUNDREDTH).is_ok());
        assert!(LimitQuote::buy_from_spend(MICRO, 990_000, TICK_HUNDREDTH).is_ok());
    }

    #[test]
    fn quantize_directions() {
        assert_eq!(quantize_price(695_500, 1_000, Side::Buy), 695_000);
        assert_eq!(quantize_price(695_500, 1_000, Side::Sell), 696_000);
        assert_eq!(quantize_price(690_000, 10_000, Side::Buy), 690_000);
    }

    #[test]
    fn marketable_limits_never_cross_away_from_book() {
        assert_eq!(
            quantize_marketable_limit(695_500, 10_000, Side::Buy),
            690_000
        );
        assert_eq!(
            quantize_marketable_limit(695_500, 10_000, Side::Sell),
            690_000
        );
    }

    #[test]
    fn salt_is_js_safe_and_random() {
        let p = OrderParams {
            token_id: U256::from(1u64),
            maker: address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            quote: LimitQuote::buy_from_spend(MICRO, 500_000, TICK_HUNDREDTH).unwrap(),
            builder_code: None,
            signature_type: SIG_TYPE_POLY_1271,
        };
        let a = build_order(&p);
        let b = build_order(&p);
        assert!(a.salt <= U256::from(JS_SAFE_INTEGER_MAX));
        assert_ne!(a.salt, b.salt, "salts must not collide");
        assert_eq!(a.signatureType, 3);
    }

    #[test]
    fn neg_risk_changes_signing_hash_but_not_domain_name() {
        let p = OrderParams {
            token_id: U256::from(7u64),
            maker: address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            quote: LimitQuote::buy_from_spend(MICRO, 500_000, TICK_HUNDREDTH).unwrap(),
            builder_code: None,
            signature_type: SIG_TYPE_POLY_1271,
        };
        let o = build_order(&p);
        let normal = signing_hash(&o, crate::POLYGON, false);
        let neg = signing_hash(&o, crate::POLYGON, true);
        assert_ne!(normal, neg, "verifying contract must separate the domains");
        let d = ctf_exchange_domain(crate::POLYGON, true);
        assert_eq!(d.name.as_deref(), Some("Polymarket CTF Exchange"));
        assert_eq!(d.version.as_deref(), Some("2"));
    }

    /// Known-answer test for V2 order signing.
    ///
    /// Provenance: struct layout, domain (name "Polymarket CTF Exchange",
    /// version "2"), and exchange addresses are verbatim from the official
    /// `Polymarket/rs-clob-client-v2` SDK source. The expected hashes and
    /// signatures were generated with an independent EIP-712 implementation
    /// (python `eth_account` 0.13.7) over the same typed data, using anvil
    /// account 0 — the key the SDK's own auth vectors use. ECDSA here is
    /// RFC 6979 deterministic, so signature bytes must match exactly.
    #[tokio::test]
    async fn known_answer_v2_order_signing() {
        use alloy::primitives::{b256, keccak256};
        use alloy::signers::local::PrivateKeySigner;
        use std::str::FromStr;

        // The EIP-712 type string is what the on-chain exchanges hash; any
        // drift in our sol! struct (names, order, types) changes this.
        const TYPE_PREIMAGE: &str = "Order(uint256 salt,address maker,address signer,\
            uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint8 side,\
            uint8 signatureType,uint256 timestamp,bytes32 metadata,bytes32 builder)";
        assert_eq!(
            Order::eip712_root_type().to_string(),
            TYPE_PREIMAGE,
            "sol! struct drifted from the official V2 Order type"
        );
        assert_eq!(
            keccak256(TYPE_PREIMAGE.as_bytes()),
            b256!("bb86318a2138f5fa8ae32fbe8e659f8fcf13cc6ae4014a707893055433818589"),
        );

        let pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer =
            KeystoreSigner::new(std::sync::Arc::new(PrivateKeySigner::from_str(pk).unwrap()));
        let maker = signer.address();
        assert_eq!(maker, address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),);

        let order = Order {
            salt: U256::from(479_249_096_354u64),
            maker,
            signer: maker,
            tokenId: U256::from_str(
                "7496871387824498705150337097986995704782987980926026827618928384721521953608",
            )
            .unwrap(),
            makerAmount: U256::from(11_782_400u64),
            takerAmount: U256::from(21_040_000u64),
            side: 0,
            signatureType: 0,
            timestamp: U256::from(1_765_432_100_000u64),
            metadata: B256::ZERO,
            builder: B256::ZERO,
        };

        // Normal CTF Exchange V2 domain.
        let hash = signing_hash(&order, crate::POLYGON, false);
        assert_eq!(
            hash,
            b256!("e517dd3eb96dd4bb53991b43d62e69f7c5d10ee4b510e5e87e93bbb0535358ba"),
        );
        let sig = format!(
            "0x{}",
            hex::encode(signer.sign_eip712_hash(&hash).await.unwrap().as_bytes())
        );
        assert_eq!(
            sig,
            "0xe3e3249f25b889d58241dfc4947bcf1a6ff43570cef4ff0782f2fffa8ddb833c\
             0bfe9b84db6302fb667ab63a3d536984946cd82c4b22e6c0c1951d1a3ec249fa1c",
        );

        // Neg-risk exchange: same name/version, different verifying contract.
        let hash = signing_hash(&order, crate::POLYGON, true);
        assert_eq!(
            hash,
            b256!("5fd553ee8185fd4d9ab80f4bfbe4508e8e1168fed2b436928848c2d4d175c3a4"),
        );
        let sig = format!(
            "0x{}",
            hex::encode(signer.sign_eip712_hash(&hash).await.unwrap().as_bytes())
        );
        assert_eq!(
            sig,
            "0xdf7cfbd9a049d10596abdaed0f3be866a18f3a641a261b76edc756e9385d72dd\
             0bf6e2121138b5bc6c6b3057034a0e297575ca137899738f81b9d1375de9fbfe1b",
        );
    }

    /// POLY_1271 (signatureType 3) known-answer test.
    ///
    /// Provenance: TypedDataSign/Order type strings, DepositWallet domain
    /// fields, and the wrapped-signature layout are verbatim from
    /// `rs-clob-client-v2 src/clob/client.rs::sign_poly1271_order`. Expected
    /// digests and full wrapped signatures were generated with an independent
    /// implementation (python eth_account/eth_abi/eth_utils), anvil key 0 as
    /// the owner, deposit wallet = the eip712 derivation regression vector.
    #[tokio::test]
    async fn known_answer_poly1271_order_signing() {
        use alloy::primitives::b256;
        use alloy::signers::local::PrivateKeySigner;
        use std::str::FromStr;

        // The nested Order text inside SOLADY_TYPE_STRING must equal our
        // struct's real root type — drift breaks ERC-1271 validation.
        assert_eq!(Order::eip712_root_type().to_string(), ORDER_TYPE_STRING);
        assert!(SOLADY_TYPE_STRING.ends_with(ORDER_TYPE_STRING));

        let pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer =
            KeystoreSigner::new(std::sync::Arc::new(PrivateKeySigner::from_str(pk).unwrap()));
        let dw = address!("6c625c75652cf2cdf2bfe94ad59cb6f79b899a18");

        let order = Order {
            salt: U256::from(479_249_096_354u64),
            maker: dw,
            signer: dw,
            tokenId: U256::from_str(
                "7496871387824498705150337097986995704782987980926026827618928384721521953608",
            )
            .unwrap(),
            makerAmount: U256::from(11_782_400u64),
            takerAmount: U256::from(21_040_000u64),
            side: 0,
            signatureType: SIG_TYPE_POLY_1271,
            timestamp: U256::from(1_765_432_100_000u64),
            metadata: B256::ZERO,
            builder: B256::ZERO,
        };

        assert_eq!(
            order.eip712_hash_struct(),
            b256!("7dd531d9dd2f514b6cacf11d1ab1dc143297015de23ffea8d9cdb0616d5cf7cf"),
        );
        assert_eq!(
            poly1271_digest(&order, crate::POLYGON, false),
            b256!("ef5ec6a9a480c3a4f7bdf0b8a5dbf06c9fa11d7ad6a7b3273901528378fc0c36"),
        );
        assert_eq!(
            poly1271_digest(&order, crate::POLYGON, true),
            b256!("3f23a9ec3d94ca14672fa676310a174d8c1e2d43828754173c9c992d8ae3593e"),
        );

        const EXPECTED_NORMAL: &str = "0xa0e112ede36cedabec052439dd784df883fef0600a4c8c4a3133225fa2d7f44c66dd24dda1ba13ac69e1f567d482fd37f05458c30c3576b19550bfb41350e0e61c3264e159346253e26a64e00b69032db0e7d32f94628de3e6eecb50304d7af3d27dd531d9dd2f514b6cacf11d1ab1dc143297015de23ffea8d9cdb0616d5cf7cf4f726465722875696e743235362073616c742c61646472657373206d616b65722c61646472657373207369676e65722c75696e7432353620746f6b656e49642c75696e74323536206d616b6572416d6f756e742c75696e743235362074616b6572416d6f756e742c75696e743820736964652c75696e7438207369676e6174757265547970652c75696e743235362074696d657374616d702c62797465733332206d657461646174612c62797465733332206275696c6465722900ba";
        const EXPECTED_NEG_RISK: &str = "0x660b58b44156c18d48f061979bec4f2500915dbd157adc483debe59634494a6b7dfe15e28101097f8e6f3dd271e394349eca19035a265eab3683b6b3847683e71c9b858f53327b0bd13af8ec14cfb35234fb9eb7b0504d1a4e61f433840d30e81a7dd531d9dd2f514b6cacf11d1ab1dc143297015de23ffea8d9cdb0616d5cf7cf4f726465722875696e743235362073616c742c61646472657373206d616b65722c61646472657373207369676e65722c75696e7432353620746f6b656e49642c75696e74323536206d616b6572416d6f756e742c75696e743235362074616b6572416d6f756e742c75696e743820736964652c75696e7438207369676e6174757265547970652c75696e743235362074696d657374616d702c62797465733332206d657461646174612c62797465733332206275696c6465722900ba";

        let wrapped = sign_order_poly1271(&order, &signer, crate::POLYGON, false)
            .await
            .unwrap();
        assert_eq!(wrapped, EXPECTED_NORMAL);
        let wrapped = sign_order_poly1271(&order, &signer, crate::POLYGON, true)
            .await
            .unwrap();
        assert_eq!(wrapped, EXPECTED_NEG_RISK);

        // Wrapped is much longer than a 65-byte ECDSA sig and ends with the
        // big-endian u16 length of the Order type string (0x00ba = 186).
        assert_eq!(
            wrapped.len(),
            2 + 130 + 64 + 64 + ORDER_TYPE_STRING.len() * 2 + 4
        );
        assert!(wrapped.ends_with("00ba"));

        // Dispatch guard: a non-POLY_1271 (sigtype-0) order refuses the wrapped path.
        let mut wrong = order.clone();
        wrong.signatureType = 0;
        assert!(
            sign_order_poly1271(&wrong, &signer, crate::POLYGON, false)
                .await
                .is_err()
        );
    }

    #[test]
    fn wire_body_shape_matches_official_client() {
        let o = Order {
            salt: U256::from(1u64),
            maker: address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            signer: address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            tokenId: U256::from(123u64),
            makerAmount: U256::from(11_782_400u64),
            takerAmount: U256::from(21_040_000u64),
            side: 0,
            signatureType: 0,
            timestamp: U256::from(1_713_398_400_000u64),
            metadata: B256::ZERO,
            builder: B256::ZERO,
        };
        let body = OrderBody::from_signed(&o, "0xsig", "api-key-uuid", OrderType::FAK).unwrap();
        let v: serde_json::Value = serde_json::to_value(&body).unwrap();

        // Exhaustive top-level keys (serde_json sorts map keys; the wire is
        // key-order-insensitive, so we assert the exact key *set*).
        let mut top: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        top.sort_unstable();
        assert_eq!(top, vec!["order", "orderType", "owner", "postOnly"]);
        assert_eq!(v["orderType"], "FAK");
        assert_eq!(v["owner"], "api-key-uuid");
        assert_eq!(v["postOnly"], false);

        // Exhaustive order keys, matching the SDK's `OrderV2WithSignature`.
        let order = v["order"].as_object().unwrap();
        let mut keys: Vec<&str> = order.keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        let mut expected = vec![
            "salt",
            "maker",
            "signer",
            "tokenId",
            "makerAmount",
            "takerAmount",
            "side",
            "expiration",
            "signatureType",
            "timestamp",
            "metadata",
            "builder",
            "signature",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);
        assert!(order["salt"].is_u64(), "salt must be a JSON number");
        assert_eq!(order["side"], "BUY");
        assert_eq!(order["expiration"], "0");
        assert_eq!(order["signatureType"], 0);
        assert_eq!(order["timestamp"], "1713398400000");
        assert_eq!(order["makerAmount"], "11782400");
        assert_eq!(order["takerAmount"], "21040000");
        assert_eq!(
            order["metadata"],
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
