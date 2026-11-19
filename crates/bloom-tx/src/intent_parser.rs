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
    #[error("invalid intent: {0}")]
    Invalid(String),
    #[error("ambiguous intent: expected {SHAPES}")]
    Ambiguous,
}

/// Every intent shape, named in errors so an agent can correct its write.
const SHAPES: &str = "kind send (to, value | to, token, amount), approve (token, spender, amount), raw (to, data[, value]) for any contract call with calldata, call (contract, method, args), deploy (data), nft_transfer, nft_approve or nft_approve_all; fields go at the top level";

#[derive(serde::Deserialize, Debug, Clone)]
struct LooseIntent {
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, serde_json::Value>,
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
    #[serde(default)]
    usd_value_hint: Option<String>,
}

impl LooseIntent {
    fn into_raw(self) -> Result<RawIntent, ParseError> {
        // Fields nested under "intent" are only a mistake when the top level
        // does not already hold a complete intent.
        let nested = self.extra.get("intent").is_some_and(|v| v.is_object()).then(|| {
            format!(
                "put the intent's fields at the top level, not under \"intent\"; expected {SHAPES}"
            )
        });
        let kind = self
            .kind
            .clone()
            .or_else(|| {
                if self.token.is_some() && self.spender.is_some() {
                    Some("approve".into())
                } else if self.contract.is_some() && self.method.is_some() {
                    Some("call".into())
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
            .ok_or_else(|| match &nested {
                Some(nested) => ParseError::Invalid(nested.clone()),
                None => ParseError::Ambiguous,
            })?;
        // Calldata that is not hex is refused here, before anything stages.
        if let Some(data) = &self.data {
            let digits = data.trim().strip_prefix("0x").unwrap_or(data.trim());
            hex::decode(digits).map_err(|e| {
                ParseError::Invalid(format!(
                    "data is not calldata: {e} ({} hex digits); give it as 0x-prefixed hex, two digits per byte",
                    digits.len()
                ))
            })?;
        }
        // A known kind with a field missing says which one.
        let needs = |field: &str| {
            ParseError::Invalid(
                nested
                    .clone()
                    .unwrap_or_else(|| format!("{kind} needs {field}")),
            )
        };
        let body = match kind.as_str() {
            "send" => {
                let token = self.token;
                let value = self.value.unwrap_or_default();
                let amount = self.amount.unwrap_or_default();
                if token.is_some() {
                    if amount.trim().is_empty() {
                        return Err(ParseError::Invalid(
                            "token sends require amount; value is only for native sends".into(),
                        ));
                    }
                    if !is_empty_or_zero_value(&value) {
                        return Err(ParseError::Invalid(
                            "token sends must use amount; value is reserved for native sends"
                                .into(),
                        ));
                    }
                    RawIntentBody::Send {
                        to: self.to.ok_or_else(|| needs("to"))?,
                        value: String::new(),
                        token,
                        amount,
                        data: self.data,
                    }
                } else {
                    if !amount.trim().is_empty() {
                        return Err(ParseError::Invalid(
                            "native sends must use value; amount is only for token sends".into(),
                        ));
                    }
                    RawIntentBody::Send {
                        to: self.to.ok_or_else(|| needs("to"))?,
                        value,
                        token: None,
                        amount: String::new(),
                        data: self.data,
                    }
                }
            }
            "call" => RawIntentBody::Call {
                contract: self.contract.ok_or_else(|| needs("contract"))?,
                method: self.method.ok_or_else(|| needs("method"))?,
                args: self.args.unwrap_or_default(),
                value: self.value.unwrap_or_default(),
            },
            "raw" => RawIntentBody::Raw {
                to: self.to.ok_or_else(|| needs("to"))?,
                value: self.value.unwrap_or_default(),
                data: self.data.ok_or_else(|| needs("data"))?,
            },
            "deploy" => {
                if self.to.is_some()
                    || self.contract.is_some()
                    || self.token.is_some()
                    || self.method.is_some()
                    || self.args.is_some()
                    || self.amount.is_some()
                    || self.spender.is_some()
                    || self.operator.is_some()
                    || self.token_id.is_some()
                    || self.standard.is_some()
                    || self.safe.is_some()
                    || self.approved.is_some()
                {
                    return Err(ParseError::Invalid(
                        "deploy accepts complete initcode in data and an optional native value; call, token, and NFT fields are not supported".into(),
                    ));
                }
                let data = self.data.ok_or_else(|| needs("data"))?;
                let bytes = hex::decode(data.strip_prefix("0x").unwrap_or(&data))
                    .map_err(|_| ParseError::Invalid("deploy requires hex initcode".into()))?;
                if bytes.is_empty() {
                    return Err(ParseError::Invalid(
                        "deploy requires nonempty initcode".into(),
                    ));
                }
                RawIntentBody::Deploy {
                    data,
                    value: self.value.unwrap_or_default(),
                }
            }
            "approve" => {
                if !self.extra.is_empty()
                    || self.to.is_some()
                    || self.value.is_some()
                    || self.data.is_some()
                    || self.contract.is_some()
                    || self.method.is_some()
                    || self.args.is_some()
                    || self.operator.is_some()
                    || self.token_id.is_some()
                    || self.standard.is_some()
                    || self.safe.is_some()
                    || self.approved.is_some()
                {
                    return Err(ParseError::Invalid("approve accepts token, spender and amount plus transaction options; remove unknown or incompatible fields".into()));
                }
                let amount = self.amount.filter(|v| !v.trim().is_empty()).ok_or_else(||
                    ParseError::Invalid("approve requires amount in raw token units; use 0 to revoke or explicit max for unlimited".into()))?;
                RawIntentBody::Approve {
                    token: self.token.ok_or_else(|| needs("token"))?,
                    spender: self.spender.ok_or_else(|| needs("spender"))?,
                    amount,
                }
            }
            "nft_transfer" => RawIntentBody::NftTransfer {
                contract: self.contract.ok_or_else(|| needs("contract"))?,
                to: self.to.ok_or_else(|| needs("to"))?,
                token_id: self.token_id.ok_or_else(|| needs("token_id"))?,
                standard: self.standard,
                amount: self.amount,
                safe: self.safe.unwrap_or(true),
                data: self.data,
            },
            "nft_approve" => RawIntentBody::NftApprove {
                contract: self.contract.ok_or_else(|| needs("contract"))?,
                operator: self.operator.ok_or_else(|| needs("operator"))?,
                token_id: self.token_id.ok_or_else(|| needs("token_id"))?,
            },
            "nft_approve_all" => RawIntentBody::NftApproveAll {
                contract: self.contract.ok_or_else(|| needs("contract"))?,
                operator: self.operator.ok_or_else(|| needs("operator"))?,
                approved: self.approved.ok_or_else(|| needs("approved"))?,
            },
            other => {
                return Err(ParseError::Invalid(format!(
                    "unknown kind {other:?}; expected {SHAPES}"
                )));
            }
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
            usd_value_hint: self.usd_value_hint,
        })
    }
}

fn is_empty_or_zero_value(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed == "0"
}

/// The bodies one write holds: one per line when more than one line opens a
/// body (a `send` line or a single-line JSON object), each object when the
/// input is several JSON objects (pretty-printed, say), else the whole input.
pub fn bodies(input: &str) -> Vec<&str> {
    let lines: Vec<&str> = input
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let opens = |line: &&str| line.starts_with("send ") || line.starts_with('{');
    if lines.len() > 1 && lines.iter().all(opens) {
        return lines;
    }
    let mut objects = Vec::new();
    let mut stream = serde_json::Deserializer::from_str(input).into_iter::<serde::de::IgnoredAny>();
    let mut start = 0;
    while let Some(Ok(_)) = stream.next() {
        let end = stream.byte_offset();
        objects.push(input[start..end].trim());
        start = end;
    }
    if objects.len() > 1 && input[start..].trim().is_empty() {
        objects
    } else {
        vec![input]
    }
}

/// Parse a textual intent in any of the accepted forms.
pub fn parse(input: &str) -> Result<RawIntent, ParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseError::Empty);
    }
    // One write stages one transaction. Two forms in one body (a `send` line
    // and a JSON object, or two JSON objects) would otherwise fail deep in a
    // parser with an error that does not say so.
    let bodies = bodies(s).len();
    if bodies > 1 {
        return Err(ParseError::Invalid(format!(
            "this write holds {bodies} bodies; `send.tx` takes several, one per line, under one approval"
        )));
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
                value: if shell.unit.eq_ignore_ascii_case("eth")
                    || shell.unit.eq_ignore_ascii_case("ether")
                    || shell.unit.eq_ignore_ascii_case("wei")
                    || shell.unit.eq_ignore_ascii_case("gwei")
                {
                    format!("{} {}", shell.amount, shell.unit)
                } else {
                    String::new()
                },
                token: if shell.unit.eq_ignore_ascii_case("eth")
                    || shell.unit.eq_ignore_ascii_case("ether")
                    || shell.unit.eq_ignore_ascii_case("wei")
                    || shell.unit.eq_ignore_ascii_case("gwei")
                {
                    None
                } else {
                    Some(shell.unit.clone())
                },
                amount: if shell.unit.eq_ignore_ascii_case("eth")
                    || shell.unit.eq_ignore_ascii_case("ether")
                    || shell.unit.eq_ignore_ascii_case("wei")
                    || shell.unit.eq_ignore_ascii_case("gwei")
                {
                    String::new()
                } else {
                    shell.amount.clone()
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
            usd_value_hint: None,
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
        usd_value_hint: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::RawIntentBody;

    #[test]
    fn two_bodies_in_one_write_are_refused_plainly() {
        let both = "send 0.25 ETH to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8\n{\"kind\":\"send\",\"to\":\"0x70997970C51812dc3A010C7d01b50e0d17dc79C8\",\"value\":\"0.25 eth\"}";
        let error = parse(both).unwrap_err().to_string();
        assert!(error.contains("2 bodies"), "{error}");
        assert_eq!(bodies(both).len(), 2);
        // A pretty-printed JSON body is still one body.
        let pretty = "{\n  \"kind\": \"send\",\n  \"to\": \"0x70997970C51812dc3A010C7d01b50e0d17dc79C8\",\n  \"value\": \"0.25 eth\"\n}";
        assert!(parse(pretty).is_ok());
        assert_eq!(bodies(pretty), vec![pretty]);
        // A space after the brace, as `jq -c`-style tools may write it.
        let spaced = "{ \"kind\": \"send\", \"to\": \"0x70997970C51812dc3A010C7d01b50e0d17dc79C8\", \"value\": \"1 eth\" }";
        assert_eq!(bodies(&format!("{spaced}\n{spaced}")).len(), 2);
        // Two pretty-printed bodies are two bodies, not a parse error.
        let two = format!("{pretty}\n{pretty}\n");
        assert_eq!(bodies(&two), vec![pretty, pretty]);
    }

    #[test]
    fn errors_name_the_accepted_shapes() {
        // Writes an agent made in a 2026-11-04 bench trial (bloom#447).
        let to = "0xE592427A0AEce92De3Edee1F18E0157C05861564";
        for (input, start) in [
            (
                format!(r#"{{"intent":{{"chain":"ethereum","to":"{to}","data":"0x01"}}}}"#),
                "invalid intent: put the intent's fields at the top level",
            ),
            (
                format!(r#"{{"kind":"contract_call","to":"{to}","data":"0x01"}}"#),
                "invalid intent: unknown kind \"contract_call\"",
            ),
            (
                r#"{"chain":"ethereum"}"#.into(),
                "ambiguous intent: expected",
            ),
        ] {
            let err = super::parse(&input).unwrap_err().to_string();
            assert!(err.starts_with(start), "{err}");
            assert!(err.contains("raw (to, data[, value])"), "{err}");
        }
        // A known kind says which field is missing, and a complete top
        // level is not refused for also carrying an "intent" object.
        let err = super::parse(&format!(
            r#"{{"kind":"approve","token":"{to}","amount":"1"}}"#
        ))
        .unwrap_err()
        .to_string();
        assert_eq!(err, "invalid intent: approve needs spender");
        super::parse(&format!(
            r#"{{"kind":"send","to":"{to}","value":"1 eth","intent":{{"note":"x"}}}}"#
        ))
        .unwrap();
        // The shapes docs/examples.md lists.
        for input in [
            format!("send 0.25 ETH to {to}"),
            format!(r#"{{"kind":"send","to":"{to}","value":"0.25 eth"}}"#),
            format!(r#"{{"kind":"send","to":"{to}","token":"USDC","amount":"10"}}"#),
            format!(r#"{{"kind":"approve","token":"{to}","spender":"{to}","amount":"1000000"}}"#),
            format!(r#"{{"kind":"raw","to":"{to}","data":"0x01","value":"0"}}"#),
            format!(
                r#"{{"kind":"call","contract":"{to}","method":"transfer(address,uint256)","args":["{to}","1"]}}"#
            ),
            r#"{"kind":"deploy","data":"0x60006000f3","value":"0"}"#.into(),
            // A stray string field named "intent" is ignored like any other extra field.
            format!(r#"{{"kind":"send","to":"{to}","value":"1 eth","intent":"note"}}"#),
        ] {
            super::parse(&input).unwrap();
        }
    }

    #[test]
    fn parse_explicit_deployment_and_reject_ambiguous_fields() {
        for input in [
            r#"{"kind":"deploy","data":"0x60006000f3","value":"123 wei"}"#,
            r#"kind = "deploy"
data = "0x60006000f3"
value = "123 wei""#,
        ] {
            let parsed = super::parse(input).unwrap();
            assert!(
                matches!(parsed.body, bloom_proto::RawIntentBody::Deploy { value, .. } if value == "123 wei")
            );
        }
        for input in [
            r#"{"kind":"deploy","data":"0x"}"#,
            r#"{"kind":"deploy","data":"0xz0"}"#,
            r#"{"kind":"deploy","data":"0x00","to":"0x0000000000000000000000000000000000000000"}"#,
            r#"{"kind":"deploy","data":"0x00","args":[1]}"#,
            r#"{"kind":"raw","data":"0x00"}"#,
            r#"{"data":"0x00"}"#,
        ] {
            assert!(super::parse(input).is_err(), "accepted {input}");
        }
    }

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
token = "USDC"
amount = "10"
chain = "ethereum"
"#,
        )
        .unwrap();
        assert_eq!(r.chain.as_deref(), Some("ethereum"));
        if let RawIntentBody::Send {
            value,
            token,
            amount,
            ..
        } = r.body
        {
            assert_eq!(value, "");
            assert_eq!(token.as_deref(), Some("USDC"));
            assert_eq!(amount, "10");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn token_send_rejects_value_without_amount() {
        let err = parse(
            r#"
to = "0xabc"
token = "USDC"
value = "10"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::Invalid(_)), "{err}");
    }

    #[test]
    fn native_send_rejects_amount() {
        let err = parse(
            r#"
to = "0xabc"
amount = "10"
"#,
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::Invalid(_)), "{err}");
    }

    #[test]
    fn token_send_allows_explicit_zero_native_value() {
        let r = parse(
            r#"
to = "0xabc"
token = "USDC"
amount = "10"
value = "0"
"#,
        )
        .unwrap();
        match r.body {
            RawIntentBody::Send {
                value,
                token,
                amount,
                ..
            } => {
                assert_eq!(value, "");
                assert_eq!(token.as_deref(), Some("USDC"));
                assert_eq!(amount, "10");
            }
            _ => panic!("wrong variant"),
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
        if let RawIntentBody::Send { token, amount, .. } = r.body {
            assert_eq!(token.as_deref(), Some("usdc"));
            assert_eq!(amount, "10");
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
    fn approval_requires_explicit_unambiguous_amount() {
        for amount in ["0", "123", "max"] {
            let input = serde_json::json!({"kind":"approve", "token":"USDC", "spender":"router", "amount":amount});
            assert!(parse(&input.to_string()).is_ok());
        }
        for extra in [
            serde_json::json!({}),
            serde_json::json!({"amount":""}),
            serde_json::json!({"amount":" "}),
            serde_json::json!({"ammount":"max"}),
            serde_json::json!({"amount":"0", "value":"0"}),
            serde_json::json!({"amount":"0", "unknown":true}),
        ] {
            let mut input =
                serde_json::json!({"kind":"approve", "token":"USDC", "spender":"router"});
            input
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(parse(&input.to_string()).is_err(), "{input}");
        }
        assert!(parse("kind = 'approve'\ntoken = 'USDC'\nspender = 'router'").is_err());
    }

    #[test]
    fn json_approve_inferred_from_fields() {
        // No kind; presence of token+spender disambiguates.
        let r = parse(r#"{"token":"0xUSDC","spender":"0xRouter","amount":"max"}"#).unwrap();
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

    #[test]
    fn json_intent_preserves_usd_value_hint() {
        let r = parse(r#"{"to":"0xabc","usd_value_hint":"5.0","chain":"base"}"#).unwrap();
        assert_eq!(r.usd_value_hint.as_deref(), Some("5.0"));
    }

    #[test]
    fn toml_intent_preserves_usd_value_hint() {
        let r = parse(
            r#"to = "0xabc"
chain = "base"
usd_value_hint = "42.5""#,
        )
        .unwrap();
        assert_eq!(r.usd_value_hint.as_deref(), Some("42.5"));
    }

    #[test]
    fn shell_send_has_no_usd_value_hint() {
        let r = parse("send 1 eth to 0xabc on base").unwrap();
        assert!(r.usd_value_hint.is_none());
    }
}
