//! Domain types / DTOs for the Polymarket APIs.
//!
//! Gamma encodes several array fields (`clobTokenIds`, `outcomes`,
//! `outcomePrices`) as **JSON-encoded strings** — a JSON string whose contents
//! are themselves a JSON array. [`json_string_array`] decodes either form.

use serde::{Deserialize, Deserializer, Serialize};

/// Order side. Serializes to the uppercase form the CLOB expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Side {
    Buy,
    Sell,
}

/// A Gamma market. Only the fields we use are typed; unknown fields are
/// ignored by serde, and most are `#[serde(default)]` so partial payloads and
/// beta drift don't hard-fail a read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Market {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub question: String,
    #[serde(rename = "conditionId", default)]
    pub condition_id: String,
    /// The YES/NO CLOB token ids (index 0 = YES, 1 = NO).
    #[serde(
        rename = "clobTokenIds",
        default,
        deserialize_with = "json_string_array"
    )]
    pub clob_token_ids: Vec<String>,
    #[serde(default, deserialize_with = "json_string_array")]
    pub outcomes: Vec<String>,
    #[serde(
        rename = "outcomePrices",
        default,
        deserialize_with = "json_string_array"
    )]
    pub outcome_prices: Vec<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub closed: bool,
    #[serde(rename = "enableOrderBook", default)]
    pub enable_order_book: bool,
    #[serde(rename = "orderPriceMinTickSize", default)]
    pub order_price_min_tick_size: Option<f64>,
    #[serde(rename = "orderMinSize", default)]
    pub order_min_size: Option<f64>,
    #[serde(rename = "negRisk", default)]
    pub neg_risk: bool,
}

impl Market {
    /// The YES token id, if present.
    pub fn yes_token_id(&self) -> Option<&str> {
        self.clob_token_ids.first().map(String::as_str)
    }
    /// The NO token id, if present.
    pub fn no_token_id(&self) -> Option<&str> {
        self.clob_token_ids.get(1).map(String::as_str)
    }

    /// Whether this is a true binary YES/NO market: exactly two CLOB token ids
    /// and, when Gamma provides outcome labels, exactly the two case-insensitive
    /// `{yes, no}` labels. `yes_token_id`/`no_token_id` index by position, so a
    /// multi-outcome market would otherwise be silently traded as if binary —
    /// and `redeem`'s `indexSets = [1, 2]` is only correct for binary. Callers
    /// must refuse non-binary markets before signing.
    pub fn is_binary(&self) -> bool {
        if self.clob_token_ids.len() != 2 {
            return false;
        }
        // Empty outcomes (older/partial payloads) fall back to the token-id
        // arity check; when present, the labels must be exactly YES/NO.
        if self.outcomes.is_empty() {
            return true;
        }
        if self.outcomes.len() != 2 {
            return false;
        }
        let labels: Vec<String> = self
            .outcomes
            .iter()
            .map(|o| o.trim().to_ascii_lowercase())
            .collect();
        labels.contains(&"yes".to_string()) && labels.contains(&"no".to_string())
    }
}

/// One price level in an order book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookLevel {
    /// Decimal string, e.g. `"0.52"`.
    pub price: String,
    /// Decimal string (share size).
    pub size: String,
}

/// CLOB order book for a single token (`GET /book`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBook {
    /// Condition id (the CLOB calls this `market`).
    #[serde(default)]
    pub market: String,
    /// The token id this book is for.
    #[serde(default)]
    pub asset_id: String,
    #[serde(default)]
    pub tick_size: String,
    #[serde(default)]
    pub min_order_size: String,
    #[serde(default)]
    pub neg_risk: bool,
    #[serde(default)]
    pub last_trade_price: String,
    /// Bids, price-descending.
    #[serde(default)]
    pub bids: Vec<BookLevel>,
    /// Asks, price-ascending.
    #[serde(default)]
    pub asks: Vec<BookLevel>,
}

/// Token → market resolution (`GET /markets-by-token/{token_id}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMarket {
    pub condition_id: String,
    /// The YES token id.
    #[serde(default)]
    pub primary_token_id: String,
    /// The NO token id.
    #[serde(default)]
    pub secondary_token_id: String,
}

/// A user position (Data API `/positions`). Permissive: unknown fields ignored,
/// known fields optional, so beta drift doesn't break a read.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Position {
    #[serde(default)]
    pub proxy_wallet: String,
    #[serde(default)]
    pub asset: String,
    #[serde(default)]
    pub condition_id: String,
    #[serde(default)]
    pub size: Option<f64>,
    #[serde(default)]
    pub avg_price: Option<f64>,
    #[serde(default)]
    pub cur_price: Option<f64>,
    /// Data API flag: position can be redeemed after resolution.
    #[serde(default)]
    pub redeemable: bool,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub outcome: String,
}

/// A trade (Data API `/trades`). Permissive, as with [`Position`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trade {
    #[serde(default)]
    pub proxy_wallet: String,
    #[serde(default)]
    pub asset: String,
    #[serde(default)]
    pub condition_id: String,
    #[serde(default)]
    pub side: String,
    #[serde(default)]
    pub size: Option<f64>,
    #[serde(default)]
    pub price: Option<f64>,
    #[serde(default)]
    pub timestamp: Option<i64>,
}

/// CLOB API L2 credentials minted via L1 auth. **Secrets are redacted in
/// `Debug`** so they never land in logs or error chains.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// The API key (`apiKey`), not secret.
    #[serde(rename = "apiKey", alias = "key")]
    pub key: String,
    /// HMAC secret (base64url). Sensitive.
    pub secret: String,
    /// Passphrase. Sensitive.
    pub passphrase: String,
    /// The L1 nonce these creds were derived under (save it to re-derive).
    #[serde(default)]
    pub nonce: u32,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("key", &self.key)
            .field("secret", &"<redacted>")
            .field("passphrase", &"<redacted>")
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// Deserialize a field that is either a JSON-encoded string holding an array,
/// or a real JSON array, into `Vec<String>`. Null → empty.
pub fn json_string_array<'de, D>(d: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::String(s) => {
            if s.is_empty() {
                return Ok(Vec::new());
            }
            serde_json::from_str(&s).map_err(D::Error::custom)
        }
        serde_json::Value::Array(_) => serde_json::from_value(v).map_err(D::Error::custom),
        other => Err(D::Error::custom(format!(
            "expected JSON string or array, got: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_string_encoded_arrays() {
        // The exact double-encoding Gamma returns (proven live by the probe).
        let raw = r#"{
            "conditionId": "0xabc",
            "clobTokenIds": "[\"69324\", \"51797\"]",
            "outcomes": "[\"Yes\", \"No\"]",
            "negRisk": false,
            "enableOrderBook": true
        }"#;
        let m: Market = serde_json::from_str(raw).unwrap();
        assert_eq!(m.clob_token_ids, vec!["69324", "51797"]);
        assert_eq!(m.outcomes, vec!["Yes", "No"]);
        assert_eq!(m.yes_token_id(), Some("69324"));
        assert_eq!(m.no_token_id(), Some("51797"));
        assert!(m.enable_order_book);
    }

    #[test]
    fn parses_real_array_form_too() {
        // Defensive: accept a plain array if the API ever stops double-encoding.
        let raw = r#"{ "clobTokenIds": ["1", "2"] }"#;
        let m: Market = serde_json::from_str(raw).unwrap();
        assert_eq!(m.clob_token_ids, vec!["1", "2"]);
    }

    #[test]
    fn missing_arrays_default_empty() {
        let m: Market = serde_json::from_str(r#"{ "id": "1" }"#).unwrap();
        assert!(m.clob_token_ids.is_empty());
        assert!(m.outcome_prices.is_empty());
    }

    #[test]
    fn credentials_debug_redacts_secrets() {
        let c = Credentials {
            key: "11111111-2222-3333-4444-555555555555".into(),
            secret: "super-secret-value".into(),
            passphrase: "super-secret-passphrase".into(),
            nonce: 0,
        };
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("super-secret-value"), "secret leaked: {dbg}");
        assert!(
            !dbg.contains("super-secret-passphrase"),
            "passphrase leaked: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
        // The non-sensitive key may appear.
        assert!(dbg.contains("11111111"));
    }

    #[test]
    fn side_serializes_uppercase() {
        assert_eq!(serde_json::to_string(&Side::Buy).unwrap(), "\"BUY\"");
        assert_eq!(serde_json::to_string(&Side::Sell).unwrap(), "\"SELL\"");
    }

    fn market_with(token_ids: &[&str], outcomes: &[&str]) -> Market {
        Market {
            id: String::new(),
            slug: String::new(),
            question: String::new(),
            condition_id: String::new(),
            clob_token_ids: token_ids.iter().map(|s| s.to_string()).collect(),
            outcomes: outcomes.iter().map(|s| s.to_string()).collect(),
            outcome_prices: Vec::new(),
            active: true,
            closed: false,
            enable_order_book: true,
            order_price_min_tick_size: None,
            order_min_size: None,
            neg_risk: false,
        }
    }

    #[test]
    fn is_binary_accepts_yes_no_and_rejects_multi_outcome() {
        // Canonical binary market.
        assert!(market_with(&["1", "2"], &["Yes", "No"]).is_binary());
        // Case-insensitive, order-insensitive labels.
        assert!(market_with(&["1", "2"], &["no", "yes"]).is_binary());
        // Two token ids, no labels → arity-only fallback passes.
        assert!(market_with(&["1", "2"], &[]).is_binary());

        // Three token ids (categorical market) → not binary even though
        // yes_token_id()/no_token_id() would happily return [0]/[1].
        assert!(!market_with(&["1", "2", "3"], &["A", "B", "C"]).is_binary());
        // Two token ids but non-binary labels.
        assert!(!market_with(&["1", "2"], &["Trump", "Biden"]).is_binary());
        // Wrong arity.
        assert!(!market_with(&["1"], &["Yes"]).is_binary());
        assert!(!market_with(&[], &[]).is_binary());
    }
}
