//! Parse JSON / TOML / shell-style intents into a normalised
//! [`bloom_proto::RawIntent`].
//!
//! Heuristic: if input starts with `{`, it's JSON; if it parses as TOML
//! and has at least one of {`to`, `kind`}, it's TOML; otherwise it's
//! treated as a shell-style line.

use bloom_proto::{RawIntent, RawIntentBody, ShellIntent};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("empty input")]
    Empty,
    #[error("json parse: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml parse: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("shell parse: {0}")]
    Shell(String),
    #[error("ambiguous intent")]
    Ambiguous,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct LooseIntent {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    contract: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    args: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    spender: Option<String>,
    #[serde(default)]
    amount: Option<String>,
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    chain: Option<String>,
    #[serde(default)]
    gas: Option<String>,
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    priority: Option<String>,
    // NFT-specific fields.
    #[serde(default)]
    operator: Option<String>,
    #[serde(default)]
    token_id: Option<String>,
    #[serde(default)]
    standard: Option<String>,
    #[serde(default)]
    safe: Option<bool>,
    #[serde(default)]
    approved: Option<bool>,
}

impl LooseIntent {
    fn into_raw(self) -> Result<RawIntent, ParseError> {
        let kind = self
            .kind
            .clone()
            .or_else(|| {
                if self.token.is_some() && self.spender.is_some() {
                    Some("approve".into())
                } else if self.contract.is_some() && self.method.is_some() {
                    Some("call".into())
                } else if self.intent.is_some() {
                    Some("enso".into())
                } else if self.to.is_some() {
                    if self
                        .data
                        .as_deref()
                        .filter(|d| !d.is_empty() && *d != "0x")
                        .is_some()
                    {
                        Some("raw".into())
                    } else {
                        Some("send".into())
                    }
                } else {
                    None
                }
            })
            .ok_or(ParseError::Ambiguous)?;
        let body = match kind.as_str() {
            "send" => RawIntentBody::Send {
                to: self.to.ok_or(ParseError::Ambiguous)?,
                value: self.value.unwrap_or_default(),
                token: self.token,
                data: self.data,
            },
            "call" => RawIntentBody::Call {
                contract: self.contract.ok_or(ParseError::Ambiguous)?,
                method: self.method.ok_or(ParseError::Ambiguous)?,
                args: self.args.unwrap_or_default(),
                value: self.value.unwrap_or_default(),
            },
            "raw" => RawIntentBody::Raw {
                to: self.to.ok_or(ParseError::Ambiguous)?,
                value: self.value.unwrap_or_default(),
                data: self.data.ok_or(ParseError::Ambiguous)?,
            },
            "enso" => RawIntentBody::Enso {
                intent: self.intent.ok_or(ParseError::Ambiguous)?,
            },
            "approve" => RawIntentBody::Approve {
                token: self.token.ok_or(ParseError::Ambiguous)?,
                spender: self.spender.ok_or(ParseError::Ambiguous)?,
                amount: self.amount.unwrap_or_else(|| "max".into()),
            },
            "nft_transfer" => RawIntentBody::NftTransfer {
                contract: self.contract.ok_or(ParseError::Ambiguous)?,
                to: self.to.ok_or(ParseError::Ambiguous)?,
                token_id: self.token_id.ok_or(ParseError::Ambiguous)?,
                standard: self.standard,
                amount: self.amount,
                safe: self.safe.unwrap_or(true),
                data: self.data,
            },
            "nft_approve" => RawIntentBody::NftApprove {
                contract: self.contract.ok_or(ParseError::Ambiguous)?,
                operator: self.operator.ok_or(ParseError::Ambiguous)?,
                token_id: self.token_id.ok_or(ParseError::Ambiguous)?,
            },
            "nft_approve_all" => RawIntentBody::NftApproveAll {
                contract: self.contract.ok_or(ParseError::Ambiguous)?,
                operator: self.operator.ok_or(ParseError::Ambiguous)?,
                approved: self.approved.ok_or(ParseError::Ambiguous)?,
            },
            _ => return Err(ParseError::Ambiguous),
        };
        let gas = match self.gas.or(self.priority).as_deref() {
            Some("auto") | None => bloom_proto::GasStrategy::Auto,
            Some("fast") => bloom_proto::GasStrategy::Fast,
            Some("standard") => bloom_proto::GasStrategy::Standard,
            Some("slow") => bloom_proto::GasStrategy::Slow,
            Some(other) => {
                return Err(ParseError::Shell(format!(
                    "unknown gas strategy '{}'",
                    other
                )));
            }
        };
        Ok(RawIntent {
            body,
            chain: self.chain,
            gas,
            nonce: self.nonce,
            gas_limit_hint: None,
        })
    }
}

/// Parse a textual intent in any of the accepted forms.
pub fn parse(input: &str) -> Result<RawIntent, ParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseError::Empty);
    }
    if s.starts_with('{') {
        let loose: LooseIntent = serde_json::from_str(s)?;
        return loose.into_raw();
    }
    if s.starts_with("send ") {
        let shell = ShellIntent::parse(s).map_err(ParseError::Shell)?;
        return Ok(RawIntent {
            body: RawIntentBody::Send {
                to: shell.to,
                value: format!("{} {}", shell.amount, shell.unit),
                token: if shell.unit.eq_ignore_ascii_case("eth")
                    || shell.unit.eq_ignore_ascii_case("ether")
                    || shell.unit.eq_ignore_ascii_case("wei")
                    || shell.unit.eq_ignore_ascii_case("gwei")
                {
                    None
                } else {
                    Some(shell.unit.clone())
                },
                data: None,
            },
            chain: shell.chain,
            gas: match shell.priority.as_deref() {
                Some("fast") => bloom_proto::GasStrategy::Fast,
                Some("standard") => bloom_proto::GasStrategy::Standard,
                Some("slow") => bloom_proto::GasStrategy::Slow,
                _ => bloom_proto::GasStrategy::Auto,
            },
            nonce: None,
            gas_limit_hint: None,
        });
    }
    if s.starts_with("nft ") {
        return parse_nft_shell(s);
    }
    // Try TOML.
    let loose: LooseIntent = toml::from_str(s)?;
    loose.into_raw()
}

/// Parse the shell-style NFT intents:
///   `nft transfer <contract> <token_id> [amount <n>] to <addr> [on <chain>]`
///   `nft approve <contract> <token_id> to <operator> [on <chain>]`
///   `nft set_approval_for_all <contract> <operator> {true|false} [on <chain>]`
fn parse_nft_shell(line: &str) -> Result<RawIntent, ParseError> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    if toks.len() < 3 || toks[0] != "nft" {
        return Err(ParseError::Shell(format!("not an nft intent: '{line}'")));
    }
    // Pull out a trailing `on <chain>` if present.
    let (head, chain) = match toks.iter().position(|t| *t == "on") {
        Some(i) if i + 1 < toks.len() => (&toks[..i], Some(toks[i + 1].to_string())),
        Some(_) => return Err(ParseError::Shell("dangling 'on' with no chain".into())),
        None => (&toks[..], None),
    };
    let body = match head[1] {
        "transfer" => {
            // forms:
            //   nft transfer <contract> <token_id> to <addr>
            //   nft transfer <contract> <token_id> amount <n> to <addr>
            if head.len() < 6 {
                return Err(ParseError::Shell(format!(
                    "nft transfer too short: '{line}'"
                )));
            }
            let contract = head[2].to_string();
            let token_id = head[3].to_string();
            let (amount, to_idx) = if head[4] == "amount" {
                if head.len() < 8 {
                    return Err(ParseError::Shell(
                        "nft transfer amount form needs 'amount <n> to <addr>'".into(),
                    ));
                }
                (Some(head[5].to_string()), 6)
            } else {
                (None, 4)
            };
            if head[to_idx] != "to" {
                return Err(ParseError::Shell(format!(
                    "expected 'to' at position {}, got '{}'",
                    to_idx, head[to_idx]
                )));
            }
            let to = head
                .get(to_idx + 1)
                .ok_or_else(|| ParseError::Shell("missing recipient after 'to'".into()))?
                .to_string();
            // ERC-1155 is implied when amount is set; standard left None
            // otherwise lets the engine auto-detect.
            let standard = if amount.is_some() {
                Some("erc1155".to_string())
            } else {
                None
            };
            RawIntentBody::NftTransfer {
                contract,
                to,
                token_id,
                standard,
                amount,
                safe: true,
                data: None,
            }
        }
        "approve" => {
            // nft approve <contract> <token_id> to <operator>
            if head.len() < 6 || head[4] != "to" {
                return Err(ParseError::Shell(
                    "expected: nft approve <contract> <token_id> to <operator>".into(),
                ));
            }
            RawIntentBody::NftApprove {
                contract: head[2].to_string(),
                token_id: head[3].to_string(),
                operator: head[5].to_string(),
            }
        }
        "set_approval_for_all" => {
            // nft set_approval_for_all <contract> <operator> {true|false}
            if head.len() < 5 {
                return Err(ParseError::Shell(
                    "expected: nft set_approval_for_all <contract> <operator> {true|false}".into(),
                ));
            }
            let approved = match head[4] {
                "true" => true,
                "false" => false,
                other => {
                    return Err(ParseError::Shell(format!(
                        "expected 'true' or 'false', got '{other}'"
                    )));
                }
            };
            RawIntentBody::NftApproveAll {
                contract: head[2].to_string(),
                operator: head[3].to_string(),
                approved,
            }
        }
        other => {
            return Err(ParseError::Shell(format!(
                "unknown nft verb '{other}'; expected transfer | approve | set_approval_for_all"
            )));
        }
    };
    Ok(RawIntent {
        body,
        chain,
        gas: bloom_proto::GasStrategy::Auto,
        nonce: None,
        gas_limit_hint: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::RawIntentBody;

    #[test]
    fn json_send() {
        let r = parse(r#"{"to":"0xabc","value":"0.1 eth"}"#).unwrap();
        assert!(matches!(r.body, RawIntentBody::Send { .. }));
    }

    #[test]
    fn toml_send_with_chain() {
        let r = parse(
            r#"
to = "0xabc"
value = "10 usdc"
chain = "ethereum"
"#,
        )
        .unwrap();
        assert_eq!(r.chain.as_deref(), Some("ethereum"));
        if let RawIntentBody::Send { value, token, .. } = r.body {
            assert_eq!(value, "10 usdc");
            assert!(token.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn shell_send() {
        let r = parse("send 0.5 eth to 0xabc on anvil").unwrap();
        assert_eq!(r.chain.as_deref(), Some("anvil"));
    }

    #[test]
    fn shell_token_send_sets_token() {
        let r = parse("send 10 usdc to vitalik.eth").unwrap();
        if let RawIntentBody::Send { token, .. } = r.body {
            assert_eq!(token.as_deref(), Some("usdc"));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn json_call() {
        let r = parse(
            r#"{"contract":"0xabc","method":"transfer(address,uint256)","args":["0xdef","1"]}"#,
        )
        .unwrap();
        assert!(matches!(r.body, RawIntentBody::Call { .. }));
    }

    #[test]
    fn json_enso() {
        let r = parse(r#"{"kind":"enso","intent":"swap 1 ETH to USDC"}"#).unwrap();
        assert!(matches!(r.body, RawIntentBody::Enso { .. }));
    }

    #[test]
    fn empty_input_errors() {
        assert!(matches!(parse(""), Err(ParseError::Empty)));
    }

    #[test]
    fn json_approve_explicit_kind() {
        let r = parse(r#"{"kind":"approve","token":"0xUSDC","spender":"0xRouter","amount":"123"}"#)
            .unwrap();
        match r.body {
            RawIntentBody::Approve {
                token,
                spender,
                amount,
            } => {
                assert_eq!(token, "0xUSDC");
                assert_eq!(spender, "0xRouter");
                assert_eq!(amount, "123");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn json_approve_inferred_from_fields() {
        // No kind; presence of token+spender disambiguates.
        let r = parse(r#"{"token":"0xUSDC","spender":"0xRouter"}"#).unwrap();
        match r.body {
            RawIntentBody::Approve { amount, .. } => assert_eq!(amount, "max"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn shell_nft_transfer_erc721() {
        let r = parse("nft transfer 0xnft 42 to 0xbob on anvil").unwrap();
        assert_eq!(r.chain.as_deref(), Some("anvil"));
        match r.body {
            RawIntentBody::NftTransfer {
                contract,
                token_id,
                to,
                amount,
                standard,
                safe,
                ..
            } => {
                assert_eq!(contract, "0xnft");
                assert_eq!(token_id, "42");
                assert_eq!(to, "0xbob");
                assert!(amount.is_none());
                assert!(standard.is_none()); // auto-detect
                assert!(safe);
            }
            _ => panic!("wrong variant: {:?}", r.body),
        }
    }

    #[test]
    fn shell_nft_transfer_erc1155_amount() {
        let r = parse("nft transfer 0xnft 7 amount 3 to 0xbob").unwrap();
        match r.body {
            RawIntentBody::NftTransfer {
                amount, standard, ..
            } => {
                assert_eq!(amount.as_deref(), Some("3"));
                assert_eq!(standard.as_deref(), Some("erc1155"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn shell_nft_approve() {
        let r = parse("nft approve 0xnft 1 to 0xspender").unwrap();
        match r.body {
            RawIntentBody::NftApprove {
                contract,
                token_id,
                operator,
            } => {
                assert_eq!(contract, "0xnft");
                assert_eq!(token_id, "1");
                assert_eq!(operator, "0xspender");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn shell_nft_set_approval_for_all() {
        let r = parse("nft set_approval_for_all 0xnft 0xop true on ethereum").unwrap();
        assert_eq!(r.chain.as_deref(), Some("ethereum"));
        match r.body {
            RawIntentBody::NftApproveAll {
                contract,
                operator,
                approved,
            } => {
                assert_eq!(contract, "0xnft");
                assert_eq!(operator, "0xop");
                assert!(approved);
            }
            _ => panic!("wrong variant"),
        }

        let r2 = parse("nft set_approval_for_all 0xnft 0xop false").unwrap();
        match r2.body {
            RawIntentBody::NftApproveAll { approved, .. } => assert!(!approved),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn shell_nft_invalid_verb_errors() {
        let r = parse("nft yeet 0xnft 1 to 0xb");
        assert!(matches!(r, Err(ParseError::Shell(_))));
    }

    #[test]
    fn json_nft_transfer_explicit_kind() {
        let r = parse(r#"{"kind":"nft_transfer","contract":"0xnft","to":"0xbob","token_id":"42"}"#)
            .unwrap();
        assert!(matches!(r.body, RawIntentBody::NftTransfer { .. }));
    }

    #[test]
    fn json_nft_approve_all_explicit_kind() {
        let r = parse(
            r#"{"kind":"nft_approve_all","contract":"0xnft","operator":"0xop","approved":false}"#,
        )
        .unwrap();
        match r.body {
            RawIntentBody::NftApproveAll { approved, .. } => assert!(!approved),
            _ => panic!("wrong variant"),
        }
    }
}
