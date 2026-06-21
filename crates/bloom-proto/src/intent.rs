//! Intent representations.
//!
//! Three input forms accepted:
//! 1. JSON  — structured tx (`to`, `value`, `data`, `chain`, …)
//! 2. TOML  — same fields in toml syntax
//! 3. Shell — single line: `send 1 ETH to 0xabc on ethereum`
//!
//! The `intent` module parses all three into a [`RawIntent`]; the
//! [`tx_engine`](crate::plan) downstream converts that into a concrete
//! [`crate::plan::StagedTx`].

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum ValueOrToken {
    /// e.g. "0.5 eth", "100 gwei", "10 usdc"
    String(String),
    #[default]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GasStrategy {
    #[default]
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "fast")]
    Fast,
    #[serde(rename = "standard")]
    Standard,
    #[serde(rename = "slow")]
    Slow,
}

/// Raw intent, with all fields optional except those that distinguish the
/// kind. The tx engine fills defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RawIntentBody {
    /// Plain native or token transfer.
    Send {
        to: String,
        #[serde(default)]
        value: String,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        data: Option<String>,
    },
    /// Contract method call.
    Call {
        contract: String,
        method: String,
        #[serde(default)]
        args: Vec<serde_json::Value>,
        #[serde(default)]
        value: String,
    },
    /// Pre-encoded raw transaction.
    Raw {
        to: String,
        #[serde(default)]
        value: String,
        data: String,
    },
    /// ERC-20 approval. `amount` accepts a decimal integer or `"max"`
    /// (shorthand for 2^256 - 1 — the conventional infinite-allowance
    /// value). The tx engine encodes `approve(address,uint256)`; the
    /// approval is to `spender` against the token contract `token`.
    Approve {
        token: String,
        spender: String,
        amount: String,
    },
    /// ERC-721 / ERC-1155 transfer. Encodes `safeTransferFrom(...)` when
    /// `safe = true` (default), `transferFrom(...)` for ERC-721 when
    /// `safe = false`. `standard` is auto-detected via ERC-165 when
    /// `None`. `amount` and `data` apply only to ERC-1155.
    NftTransfer {
        contract: String,
        to: String,
        token_id: String,
        #[serde(default)]
        standard: Option<String>,
        #[serde(default)]
        amount: Option<String>,
        #[serde(default = "default_true")]
        safe: bool,
        #[serde(default)]
        data: Option<String>,
    },
    /// ERC-721 single-token approval — `approve(address,uint256)`.
    /// Pass the zero address as `operator` to revoke. Errors against
    /// ERC-1155 (no per-token approval).
    NftApprove {
        contract: String,
        operator: String,
        token_id: String,
    },
    /// `setApprovalForAll(address,bool)` — operator-wide approval.
    /// Same selector for ERC-721 and ERC-1155.
    NftApproveAll {
        contract: String,
        operator: String,
        approved: bool,
    },
    /// Enso DeFi intent.
    Enso { intent: String },
}

fn default_true() -> bool {
    true
}

/// What the user wrote (after normalising format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawIntent {
    pub body: RawIntentBody,
    /// Filesystem chain name, e.g. "ethereum" or "anvil".
    pub chain: Option<String>,
    /// Gas strategy hint.
    #[serde(default)]
    pub gas: GasStrategy,
    /// Optional explicit nonce override (rarely useful).
    #[serde(default)]
    pub nonce: Option<u64>,
    /// Gas limit hint from an external estimator (e.g. Enso). Used as
    /// the fallback when `eth_estimateGas` fails at stage time.
    #[serde(default)]
    pub gas_limit_hint: Option<u64>,
    /// USD value hint supplied by a higher-level intent planner. This is
    /// intentionally advisory metadata for wallet policy checks; the concrete
    /// transaction is still fully represented by `body`.
    #[serde(default)]
    pub usd_value_hint: Option<String>,
}

/// A normalised concrete tx-intent (post-resolution): addresses parsed,
/// values resolved to wei.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIntent {
    pub from: String,
    pub to: String,
    pub value_wei: String,
    pub data_hex: String,
    pub chain_id: u64,
    pub chain: String,
    pub gas_limit: Option<u64>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub nonce: Option<u64>,
}

/// Shell-style intent. Parsed manually with a tiny grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellIntent {
    pub verb: String,   // "send"
    pub amount: String, // "0.5"
    pub unit: String,   // "eth" / "usdc"
    pub to: String,     // address or alias
    pub chain: Option<String>,
    pub priority: Option<String>,
}

impl ShellIntent {
    /// Parse `send <amount> <unit> to <addr> [on <chain>] [--priority <p>]`
    pub fn parse(line: &str) -> Result<Self, String> {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.len() < 5 {
            return Err(format!("too short: '{}'", line));
        }
        if toks[0] != "send" {
            return Err(format!("only 'send' supported, got '{}'", toks[0]));
        }
        let amount = toks[1].to_string();
        let unit = toks[2].to_string();
        if toks[3] != "to" {
            return Err("expected 'to' after amount".into());
        }
        let to = toks[4].to_string();
        let mut i = 5;
        let mut chain = None;
        let mut priority = None;
        while i < toks.len() {
            match toks[i] {
                "on" if i + 1 < toks.len() => {
                    chain = Some(toks[i + 1].to_string());
                    i += 2;
                }
                "--priority" if i + 1 < toks.len() => {
                    priority = Some(toks[i + 1].to_string());
                    i += 2;
                }
                other => return Err(format!("unexpected token '{}'", other)),
            }
        }
        Ok(ShellIntent {
            verb: "send".into(),
            amount,
            unit,
            to,
            chain,
            priority,
        })
    }
}

/// Enso intent body (placeholder; full client lives in `bloom-defi`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsoIntent {
    pub intent: String,
    pub chain: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_intent_basic() {
        let i = ShellIntent::parse("send 0.5 eth to 0xabc on ethereum").unwrap();
        assert_eq!(i.amount, "0.5");
        assert_eq!(i.unit, "eth");
        assert_eq!(i.to, "0xabc");
        assert_eq!(i.chain.as_deref(), Some("ethereum"));
        assert!(i.priority.is_none());
    }

    #[test]
    fn shell_intent_with_priority() {
        let i = ShellIntent::parse("send 10 usdc to vitalik.eth --priority fast").unwrap();
        assert_eq!(i.unit, "usdc");
        assert_eq!(i.priority.as_deref(), Some("fast"));
        assert!(i.chain.is_none());
    }

    #[test]
    fn json_send_round_trip() {
        let s = r#"{"kind":"send","to":"0xabc","value":"0.1 eth"}"#;
        let body: RawIntentBody = serde_json::from_str(s).unwrap();
        match body {
            RawIntentBody::Send { to, value, .. } => {
                assert_eq!(to, "0xabc");
                assert_eq!(value, "0.1 eth");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn json_nft_transfer_round_trip() {
        let s = r#"{"kind":"nft_transfer","contract":"0xnft","to":"0xbob","token_id":"42"}"#;
        let body: RawIntentBody = serde_json::from_str(s).unwrap();
        match &body {
            RawIntentBody::NftTransfer {
                contract,
                to,
                token_id,
                standard,
                amount,
                safe,
                data,
            } => {
                assert_eq!(contract, "0xnft");
                assert_eq!(to, "0xbob");
                assert_eq!(token_id, "42");
                assert!(standard.is_none());
                assert!(amount.is_none());
                assert!(*safe, "safe defaults to true");
                assert!(data.is_none());
            }
            _ => panic!("wrong variant"),
        }
        // Round-trip back through serde_json.
        let back = serde_json::to_string(&body).unwrap();
        let parsed: RawIntentBody = serde_json::from_str(&back).unwrap();
        assert_eq!(parsed, body);
    }

    #[test]
    fn json_nft_transfer_erc1155_amount() {
        let s = r#"{"kind":"nft_transfer","contract":"0xnft","to":"0xbob","token_id":"7","standard":"erc1155","amount":"3"}"#;
        let body: RawIntentBody = serde_json::from_str(s).unwrap();
        match body {
            RawIntentBody::NftTransfer {
                standard, amount, ..
            } => {
                assert_eq!(standard.as_deref(), Some("erc1155"));
                assert_eq!(amount.as_deref(), Some("3"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn toml_nft_approve_round_trip() {
        let s = r#"
kind = "nft_approve"
contract = "0xnft"
operator = "0xspender"
token_id = "1"
"#;
        let body: RawIntentBody = toml::from_str(s).unwrap();
        match &body {
            RawIntentBody::NftApprove {
                contract,
                operator,
                token_id,
            } => {
                assert_eq!(contract, "0xnft");
                assert_eq!(operator, "0xspender");
                assert_eq!(token_id, "1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn json_nft_approve_all_round_trip() {
        let s =
            r#"{"kind":"nft_approve_all","contract":"0xnft","operator":"0xop","approved":true}"#;
        let body: RawIntentBody = serde_json::from_str(s).unwrap();
        match &body {
            RawIntentBody::NftApproveAll {
                contract,
                operator,
                approved,
            } => {
                assert_eq!(contract, "0xnft");
                assert_eq!(operator, "0xop");
                assert!(*approved);
            }
            _ => panic!("wrong variant"),
        }
        let back = serde_json::to_string(&body).unwrap();
        let parsed: RawIntentBody = serde_json::from_str(&back).unwrap();
        assert_eq!(parsed, body);
    }
}
