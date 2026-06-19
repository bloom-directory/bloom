//! Shared paid HTTP request lifecycle, challenge normalization, and policy helpers.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bloom_proto::Policy;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

pub trait PaidHttpChainRpcResolver: Send + Sync {
    fn http_rpc_urls_for_chain_id(&self, chain_id: u64) -> Vec<String>;

    fn http_rpc_url_for_chain_id(&self, chain_id: u64) -> Option<String> {
        self.http_rpc_urls_for_chain_id(chain_id).into_iter().next()
    }

    fn http_rpc_urls_for_chain_id_opt(&self, chain_id: Option<u64>) -> Vec<String> {
        chain_id
            .map(|chain_id| self.http_rpc_urls_for_chain_id(chain_id))
            .unwrap_or_default()
    }
}

pub struct EmptyPaidHttpChainRpcResolver;

impl PaidHttpChainRpcResolver for EmptyPaidHttpChainRpcResolver {
    fn http_rpc_urls_for_chain_id(&self, _chain_id: u64) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    pub url: Url,
    pub wallet: Option<String>,
    pub max_amount_usd: Option<f64>,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlRequest {
    method: Option<String>,
    url: String,
    wallet: Option<String>,
    max_amount_usd: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    body: Option<TomlBody>,
}

#[derive(Debug, Deserialize)]
struct TomlBody {
    inline: Option<String>,
}

pub fn parse_request(input: &str) -> Result<ParsedRequest, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty request".to_string());
    }
    if trimmed.contains("url")
        && trimmed.contains('=')
        && let Ok(t) = toml::from_str::<TomlRequest>(trimmed)
    {
        return Ok(ParsedRequest {
            method: t
                .method
                .unwrap_or_else(|| "GET".into())
                .to_ascii_uppercase(),
            url: Url::parse(&t.url).map_err(|e| format!("url: {e}"))?,
            wallet: t.wallet,
            max_amount_usd: t.max_amount_usd.as_deref().and_then(|v| v.parse().ok()),
            headers: t.headers,
            body: t.body.and_then(|b| b.inline),
        });
    }
    let mut lines = trimmed.lines();
    let first = lines.next().unwrap().trim();
    let mut parts = first.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_ascii_uppercase();
    let url = parts.next().ok_or_else(|| "missing URL".to_string())?;
    let mut wallet = None;
    let mut max_amount_usd = None;
    for attr in parts {
        if let Some(v) = attr.strip_prefix("wallet=") {
            wallet = Some(v.trim_matches('"').to_string());
        }
        if let Some(v) = attr.strip_prefix("max_amount_usd=") {
            max_amount_usd = v.trim_matches('"').parse().ok();
        }
    }
    let mut headers = BTreeMap::new();
    let mut body_lines = Vec::new();
    let mut in_body = false;
    for line in lines {
        if line.trim().is_empty() {
            in_body = true;
            continue;
        }
        if !in_body {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            } else {
                in_body = true;
                body_lines.push(line);
            }
        } else {
            body_lines.push(line);
        }
    }
    Ok(ParsedRequest {
        method,
        url: Url::parse(url).map_err(|e| format!("url: {e}"))?,
        wallet,
        max_amount_usd,
        headers,
        body: if body_lines.is_empty() {
            None
        } else {
            Some(body_lines.join("\n"))
        },
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedChallenge {
    pub protocol: String,
    pub intent: String,
    pub merchant: String,
    pub realm: Option<String>,
    pub network: Option<String>,
    pub asset: Option<String>,
    pub amount: Option<String>,
    pub amount_usd: Option<f64>,
    pub charge_id: Option<String>,
    pub session_id: Option<String>,
    pub deposit_amount: Option<String>,
    pub deposit_usd: Option<f64>,
    pub chain_id: Option<u64>,
    pub unit_type: Option<String>,
    pub channel_id: Option<String>,
    pub challenge_id: Option<String>,
    pub request: Option<serde_json::Value>,
    pub headers: BTreeMap<String, String>,
    pub accepts: Vec<PaymentRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequirement {
    pub scheme: Option<String>,
    pub network: Option<String>,
    pub asset: Option<String>,
    pub amount: Option<String>,
    pub pay_to: Option<String>,
    pub resource: Option<String>,
    pub raw: serde_json::Value,
}

impl NormalizedChallenge {
    pub fn payment_method(&self) -> serde_json::Value {
        json!({
            "protocol": self.protocol,
            "intent": self.intent,
            "network": self.network,
            "asset": self.asset,
            "merchant": self.merchant,
            "charge_id": self.charge_id,
            "session_id": self.session_id,
            "channel_id": self.channel_id,
            "deposit_amount": self.deposit_amount,
            "deposit_usd": self.deposit_usd,
            "chain_id": self.chain_id,
            "unit_type": self.unit_type,
        })
    }
}

pub fn normalize_challenge(headers: &HeaderMap, body: &[u8], url: &Url) -> NormalizedChallenge {
    let header_map = headers_to_string_map(headers);
    let www_values = headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>();
    if let Some((challenge, value)) = mpp::parse_www_authenticate_all(www_values)
        .into_iter()
        .filter_map(Result::ok)
        .find(|c| c.method.as_str() == "tempo")
        .and_then(|challenge| {
            challenge
                .request
                .decode::<serde_json::Value>()
                .ok()
                .map(|value| (challenge, value))
        })
    {
        let method_details = value
            .get("methodDetails")
            .unwrap_or(&serde_json::Value::Null);
        let amount = json_string(&value, &["amount"]);
        let asset = json_string(&value, &["currency"]);
        let deposit_amount = json_string(&value, &["suggestedDeposit"]);
        let channel_id = json_string(method_details, &["channelId"])
            .or_else(|| json_string(&value, &["sessionId"]));
        return NormalizedChallenge {
            protocol: "mpp".into(),
            intent: challenge.intent.as_str().to_string(),
            merchant: challenge.realm.clone(),
            realm: Some(challenge.realm),
            network: Some("tempo".into()),
            asset: asset.clone(),
            amount_usd: parse_payment_amount_usd(asset.as_deref(), amount.as_deref()),
            amount,
            charge_id: json_string(&value, &["externalId"]),
            session_id: channel_id.clone(),
            deposit_usd: parse_payment_amount_usd(asset.as_deref(), deposit_amount.as_deref()),
            deposit_amount,
            chain_id: method_details.get("chainId").and_then(|v| v.as_u64()),
            unit_type: json_string(&value, &["unitType"]),
            channel_id,
            challenge_id: Some(challenge.id),
            request: Some(value),
            headers: header_map,
            accepts: Vec::new(),
        };
    }
    let www = header_map
        .get("www-authenticate")
        .cloned()
        .unwrap_or_default();
    let lower_www = www.to_ascii_lowercase();
    let body_json: serde_json::Value = header_map
        .get("payment-required")
        .and_then(|value| B64.decode(value).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .or_else(|| serde_json::from_slice(body).ok())
        .unwrap_or_else(|| json!({}));
    let lower_body_protocol = json_string(&body_json, &["protocol", "paymentProtocol", "scheme"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let body_type = json_string(&body_json, &["type", "kind", "challengeType"])
        .unwrap_or_default()
        .to_ascii_lowercase();

    let protocol = if header_map.keys().any(|k| k.starts_with("x-payment"))
        || body_json.get("x402Version").is_some()
        || body_json.get("accepts").is_some()
    {
        "x402"
    } else if lower_www.contains("tempo")
        || lower_www.contains("mpp")
        || lower_www.contains("payment")
        || lower_body_protocol.contains("tempo")
        || lower_body_protocol.contains("mpp")
        || body_json.get("charge").is_some()
        || body_json.get("session").is_some()
    {
        "mpp"
    } else {
        "unknown"
    };
    let intent = if protocol == "x402" {
        "one_time"
    } else if lower_www.contains("session")
        || body_json.get("session").is_some()
        || body_type == "session"
    {
        "session"
    } else {
        "charge"
    };
    let accepts = parse_payment_requirements(&body_json);
    let session = body_json.get("session").unwrap_or(&serde_json::Value::Null);
    let charge = body_json.get("charge").unwrap_or(&serde_json::Value::Null);
    let network = json_string(&body_json, &["network"])
        .or_else(|| json_string(session, &["network"]))
        .or_else(|| json_string(charge, &["network"]))
        .or_else(|| {
            body_json
                .pointer("/accepts/0/network")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    let asset = json_string(&body_json, &["asset", "currency"])
        .or_else(|| json_string(session, &["asset", "currency"]))
        .or_else(|| json_string(charge, &["asset", "currency"]))
        .or_else(|| {
            body_json
                .pointer("/accepts/0/asset")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    let amount = if intent == "session" {
        json_string(session, &["voucherAmount", "amount", "price", "cost"])
            .or_else(|| json_string(&body_json, &["voucherAmount", "amount", "price", "cost"]))
    } else {
        json_string(charge, &["amount", "price", "cost"])
            .or_else(|| json_string(&body_json, &["amount", "price", "cost"]))
            .or_else(|| {
                body_json
                    .pointer("/accepts/0/maxAmountRequired")
                    .or_else(|| body_json.pointer("/accepts/0/amount"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
    };
    let amount_usd = if intent == "session" {
        json_f64(session, &["voucherAmountUsd", "amountUsd", "usd"])
            .or_else(|| json_f64(&body_json, &["voucherAmountUsd", "amountUsd", "usd"]))
            .or_else(|| parse_payment_amount_usd(asset.as_deref(), amount.as_deref()))
    } else {
        json_f64(charge, &["amountUsd", "usd"])
            .or_else(|| json_f64(&body_json, &["amountUsd", "usd"]))
            .or_else(|| {
                body_json
                    .pointer("/accepts/0/amountUsd")
                    .and_then(json_number)
            })
            .or_else(|| {
                body_json
                    .pointer("/accepts/0/amount_usd")
                    .and_then(json_number)
            })
            .or_else(|| parse_payment_amount_usd(asset.as_deref(), amount.as_deref()))
    };
    let deposit_amount = json_string(session, &["depositAmount", "deposit", "topUpAmount"])
        .or_else(|| json_string(&body_json, &["depositAmount", "deposit", "topUpAmount"]));
    let deposit_usd = json_f64(
        session,
        &["depositAmountUsd", "depositUsd", "topUpAmountUsd"],
    )
    .or_else(|| {
        json_f64(
            &body_json,
            &["depositAmountUsd", "depositUsd", "topUpAmountUsd"],
        )
    })
    .or_else(|| parse_payment_amount_usd(asset.as_deref(), deposit_amount.as_deref()));
    let merchant = json_string(charge, &["merchant", "merchantId"])
        .or_else(|| json_string(session, &["merchant", "merchantId"]))
        .or_else(|| json_string(&body_json, &["merchant", "merchantId"]))
        .unwrap_or_else(|| url.host_str().unwrap_or("unknown").into());

    NormalizedChallenge {
        protocol: protocol.into(),
        intent: intent.into(),
        merchant,
        realm: extract_realm(&www),
        network,
        asset,
        amount,
        amount_usd,
        charge_id: json_string(charge, &["id", "chargeId"])
            .or_else(|| json_string(&body_json, &["chargeId"])),
        session_id: json_string(session, &["id", "sessionId"])
            .or_else(|| json_string(&body_json, &["sessionId"])),
        deposit_amount,
        deposit_usd,
        chain_id: None,
        unit_type: None,
        channel_id: None,
        challenge_id: None,
        request: None,
        headers: header_map,
        accepts,
    }
}

pub fn parse_payment_requirements(body_json: &serde_json::Value) -> Vec<PaymentRequirement> {
    let accepts = body_json
        .get("accepts")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_else(|| vec![body_json.clone()]);
    accepts
        .into_iter()
        .filter(|v| v.is_object())
        .map(|v| PaymentRequirement {
            scheme: v.get("scheme").and_then(|x| x.as_str()).map(str::to_string),
            network: v
                .get("network")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            asset: v.get("asset").and_then(|x| x.as_str()).map(str::to_string),
            amount: v
                .get("maxAmountRequired")
                .or_else(|| v.get("amount"))
                .and_then(|x| x.as_str())
                .map(str::to_string),
            pay_to: v.get("payTo").and_then(|x| x.as_str()).map(str::to_string),
            resource: v
                .get("resource")
                .and_then(|x| x.as_str())
                .map(str::to_string),
            raw: v,
        })
        .collect()
}

pub fn json_string(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| {
        v.get(*k).and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.as_f64().map(trim_money))
        })
    })
}

pub fn json_f64(v: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|k| {
        v.get(*k)
            .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(parse_money)))
    })
}

pub fn parse_money(raw: &str) -> Option<f64> {
    raw.trim().trim_start_matches('$').parse().ok()
}

pub fn parse_payment_amount_usd(asset: Option<&str>, amount: Option<&str>) -> Option<f64> {
    let raw = amount?.trim();
    if raw.contains('.') || raw.starts_with('$') {
        return parse_money(raw);
    }
    if asset.is_some_and(is_known_six_decimal_usd_asset) {
        return raw.parse::<f64>().ok().map(|v| v / 1_000_000.0);
    }
    parse_money(raw)
}

fn is_known_six_decimal_usd_asset(asset: &str) -> bool {
    matches!(
        asset.to_ascii_lowercase().as_str(),
        // USDC on Base.
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
            // USDC on Tempo, as advertised by Nansen's MPP challenges.
            | "0x20c000000000000000000000b9537d11c60e8b50"
            // USD0 on Tempo.
            | "0x779ded0c9e1022225f8e0630b35a9b54be713736"
    )
}

pub fn trim_money(v: f64) -> String {
    let s = format!("{v:.6}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

pub fn paid_http_intent_label(intent: &str) -> &str {
    match intent {
        "charge" => "one_time",
        other => other,
    }
}

pub fn extract_realm(s: &str) -> Option<String> {
    s.split(',').find_map(|part| {
        part.trim()
            .strip_prefix("realm=")
            .map(|v| v.trim_matches('"').to_string())
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub rule: String,
    pub result: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy)]
pub struct PolicyEvalInput<'a> {
    pub host: &'a str,
    pub asset: Option<&'a str>,
    pub network: Option<&'a str>,
    pub intent: &'a str,
    pub amount_usd: Option<f64>,
    pub request_max_amount_usd: Option<f64>,
    pub spent_24h_usd: f64,
}

pub fn evaluate_payment_policy(policy: &Policy, input: PolicyEvalInput<'_>) -> Vec<PolicyCheck> {
    let mut out = Vec::new();
    let payments = &policy.payments;
    let host = input.host.to_ascii_lowercase();
    let asset = input.asset;
    let network = input.network;
    let amount_usd = input.amount_usd;
    push_check(
        &mut out,
        "payments.enabled",
        payments.enabled,
        if payments.enabled {
            "paid HTTP enabled".into()
        } else {
            "wallet policy has not enabled paid HTTP".into()
        },
        false,
    );
    push_check(
        &mut out,
        "payments.require_plan",
        payments.require_plan,
        if payments.require_plan {
            "staged plan is required before confirmation".into()
        } else {
            "paid HTTP requires a staged plan before confirmation".into()
        },
        false,
    );

    if contains_ci(&payments.http.deny_hosts, &host) {
        out.push(deny("payments.http.deny_hosts", format!("{host} denied")));
    }
    if !payments.http.allow_hosts.is_empty() && !contains_ci(&payments.http.allow_hosts, &host) {
        out.push(deny(
            "payments.http.allow_hosts",
            format!("{host} not allowed"),
        ));
    } else if !payments.http.allow_hosts.is_empty() {
        out.push(pass("payments.http.allow_hosts", format!("{host} allowed")));
    }

    if let Some(asset) = asset {
        if contains_ci(&payments.assets.deny, asset) {
            out.push(deny("payments.assets.deny", format!("{asset} denied")));
        }
        if !payments.assets.allow.is_empty() && !contains_ci(&payments.assets.allow, asset) {
            out.push(deny(
                "payments.assets.allow",
                format!("{asset} not allowed"),
            ));
        } else if !payments.assets.allow.is_empty() {
            out.push(pass("payments.assets.allow", format!("{asset} allowed")));
        }
    }
    if let Some(network) = network {
        if contains_ci(&payments.networks.deny, network) {
            out.push(deny("payments.networks.deny", format!("{network} denied")));
        }
        if !payments.networks.allow.is_empty() && !contains_ci(&payments.networks.allow, network) {
            out.push(deny(
                "payments.networks.allow",
                format!("{network} not allowed"),
            ));
        } else if !payments.networks.allow.is_empty() {
            out.push(pass(
                "payments.networks.allow",
                format!("{network} allowed"),
            ));
        }
    }

    if let Some(usd) = amount_usd {
        if let Some(cap) = min_cap([policy.caps.per_tx_usd, payments.http.per_request_usd]) {
            if usd > cap {
                out.push(deny(
                    "payments.http.per_request_usd",
                    format_usd_cmp(usd, ">", cap),
                ));
            } else {
                out.push(pass(
                    "payments.http.per_request_usd",
                    format_usd_cmp(usd, "<=", cap),
                ));
            }
        }
        if let Some(cap) = input.request_max_amount_usd {
            if usd > cap {
                out.push(deny(
                    "request.max_amount_usd",
                    format_usd_cmp(usd, ">", cap),
                ));
            } else {
                out.push(pass(
                    "request.max_amount_usd",
                    format_usd_cmp(usd, "<=", cap),
                ));
            }
        }
        if let Some(cap) = min_cap([policy.caps.per_day_usd, payments.http.per_day_usd]) {
            let total = input.spent_24h_usd + usd;
            if total > cap {
                out.push(deny(
                    "payments.http.per_day_usd",
                    format!("{} spent+request > {} cap", usd_fmt(total), usd_fmt(cap)),
                ));
            } else {
                out.push(pass(
                    "payments.http.per_day_usd",
                    format!("{} spent+request <= {} cap", usd_fmt(total), usd_fmt(cap)),
                ));
            }
        }
        if let Some(warn) = policy.caps.require_confirm_above_usd {
            if usd > warn {
                out.push(warn_check(
                    "caps.require_confirm_above_usd",
                    format_usd_cmp(usd, ">", warn),
                ));
            } else {
                out.push(pass(
                    "caps.require_confirm_above_usd",
                    format_usd_cmp(usd, "<=", warn),
                ));
            }
        }
        if input.intent == "session" {
            if !payments.sessions.enabled {
                out.push(deny(
                    "payments.sessions.enabled",
                    "session payments are disabled",
                ));
            } else {
                out.push(pass(
                    "payments.sessions.enabled",
                    "session payments enabled",
                ));
            }
            if let Some(cap) = payments.sessions.max_deposit_usd {
                if usd > cap {
                    out.push(deny(
                        "payments.sessions.max_deposit_usd",
                        format_usd_cmp(usd, ">", cap),
                    ));
                } else {
                    out.push(pass(
                        "payments.sessions.max_deposit_usd",
                        format_usd_cmp(usd, "<=", cap),
                    ));
                }
            }
            if let Some(cap) = payments.sessions.max_session_spend_usd {
                if usd > cap {
                    out.push(deny(
                        "payments.sessions.max_session_spend_usd",
                        format_usd_cmp(usd, ">", cap),
                    ));
                } else {
                    out.push(pass(
                        "payments.sessions.max_session_spend_usd",
                        format_usd_cmp(usd, "<=", cap),
                    ));
                }
            }
        }
    } else {
        out.push(warn_check(
            "payments.amount_usd",
            "paid HTTP challenge did not expose a USD-denominated amount; review before confirming",
        ));
    }

    out
}

fn push_check(out: &mut Vec<PolicyCheck>, rule: &str, pass_ok: bool, detail: String, warn: bool) {
    out.push(PolicyCheck {
        rule: rule.into(),
        result: if pass_ok {
            "pass"
        } else if warn {
            "warn"
        } else {
            "deny"
        }
        .into(),
        detail,
    });
}

fn pass(rule: &str, detail: impl Into<String>) -> PolicyCheck {
    PolicyCheck {
        rule: rule.into(),
        result: "pass".into(),
        detail: detail.into(),
    }
}
fn warn_check(rule: &str, detail: impl Into<String>) -> PolicyCheck {
    PolicyCheck {
        rule: rule.into(),
        result: "warn".into(),
        detail: detail.into(),
    }
}
fn deny(rule: &str, detail: impl Into<String>) -> PolicyCheck {
    PolicyCheck {
        rule: rule.into(),
        result: "deny".into(),
        detail: detail.into(),
    }
}
fn contains_ci(set: &std::collections::BTreeSet<String>, needle: &str) -> bool {
    set.iter().any(|v| v.eq_ignore_ascii_case(needle))
}
fn min_cap<const N: usize>(values: [Option<f64>; N]) -> Option<f64> {
    values.into_iter().flatten().reduce(f64::min)
}
fn format_usd_cmp(a: f64, op: &str, b: f64) -> String {
    format!("{} {op} {}", usd_fmt(a), usd_fmt(b))
}
fn usd_fmt(v: f64) -> String {
    format!("${v:.6}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}
pub fn json_number(v: &serde_json::Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str()?.parse().ok())
}

pub fn select_payment_requirement(
    challenge: &NormalizedChallenge,
    policy: &Policy,
    host: &str,
) -> Option<PaymentRequirement> {
    let candidates = if challenge.accepts.is_empty() {
        vec![PaymentRequirement {
            scheme: None,
            network: challenge.network.clone(),
            asset: challenge.asset.clone(),
            amount: challenge.amount.clone(),
            pay_to: None,
            resource: None,
            raw: json!({}),
        }]
    } else {
        challenge.accepts.clone()
    };
    candidates.into_iter().find(|req| {
        !evaluate_payment_policy(
            policy,
            PolicyEvalInput {
                host,
                asset: req.asset.as_deref(),
                network: req.network.as_deref(),
                intent: &challenge.intent,
                amount_usd: challenge.amount_usd,
                request_max_amount_usd: None,
                spent_24h_usd: 0.0,
            },
        )
        .iter()
        .any(|c| c.result == "deny")
    })
}

pub fn evaluate_session_policy(
    policy: &Policy,
    challenge: &NormalizedChallenge,
    already_spent_usd: f64,
) -> Vec<PolicyCheck> {
    let mut out = Vec::new();
    if challenge.intent != "session" {
        return out;
    }
    let sessions = &policy.payments.sessions;
    if !sessions.enabled {
        out.push(PolicyCheck {
            rule: "payments.sessions.enabled".into(),
            result: "deny".into(),
            detail: "wallet policy has not enabled payment sessions".into(),
        });
    } else {
        out.push(PolicyCheck {
            rule: "payments.sessions.enabled".into(),
            result: "pass".into(),
            detail: "payment sessions enabled".into(),
        });
    }
    if let (Some(deposit), Some(cap)) = (challenge.deposit_usd, sessions.max_deposit_usd) {
        out.push(PolicyCheck {
            rule: "payments.sessions.max_deposit_usd".into(),
            result: if deposit > cap { "deny" } else { "pass" }.into(),
            detail: format!(
                "{} {} {}",
                trim_money(deposit),
                if deposit > cap { ">" } else { "<=" },
                trim_money(cap)
            ),
        });
    }
    if let (Some(amount), Some(cap)) = (challenge.amount_usd, sessions.max_session_spend_usd) {
        let projected = already_spent_usd + amount;
        out.push(PolicyCheck {
            rule: "payments.sessions.max_session_spend_usd".into(),
            result: if projected > cap { "deny" } else { "pass" }.into(),
            detail: format!(
                "projected cumulative {} {} {}",
                trim_money(projected),
                if projected > cap { ">" } else { "<=" },
                trim_money(cap)
            ),
        });
    }
    out
}

pub fn headers_to_string_map(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{normalize_challenge, parse_payment_amount_usd};
    use reqwest::header::{HeaderMap, HeaderValue};
    use url::Url;

    #[test]
    fn parses_known_payment_stablecoin_base_units_as_usd() {
        assert_eq!(
            parse_payment_amount_usd(
                Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
                Some("10000")
            ),
            Some(0.01)
        );
        assert_eq!(
            parse_payment_amount_usd(
                Some("0x20C000000000000000000000b9537d11c60E8b50"),
                Some("50000")
            ),
            Some(0.05)
        );
    }

    #[test]
    fn normalizes_nansen_x402_v2_payment_required_header_amount() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "payment-required",
            HeaderValue::from_static(
                "eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQYXltZW50IHJlcXVpcmVkIiwicmVzb3VyY2UiOnsidXJsIjoiaHR0cHM6Ly9hcGkubmFuc2VuLmFpL2FwaS92MS90b2tlbi1zY3JlZW5lciIsImRlc2NyaXB0aW9uIjoiUmV0cmlldmUgdG9rZW4gc2NyZWVuZXIgZGF0YSIsIm1pbWVUeXBlIjoiIn0sImFjY2VwdHMiOlt7InNjaGVtZSI6ImV4YWN0IiwibmV0d29yayI6ImVpcDE1NTo4NDUzIiwiYXNzZXQiOiIweDgzMzU4OWZDRDZlRGI2RTA4ZjRjN0MzMkQ0ZjcxYjU0YmRBMDI5MTMiLCJhbW91bnQiOiIxMDAwMCIsInBheVRvIjoiMHg5MzA1M2YxZTdBNWVGRURhNTMyRmU2OUNiYkU0M2NCRWMzQTBGMTNmIiwibWF4VGltZW91dFNlY29uZHMiOjMwMCwiZXh0cmEiOnsibmFtZSI6IlVTRCBDb2luIiwidmVyc2lvbiI6IjIifX1dfQ==",
            ),
        );
        let challenge = normalize_challenge(
            &headers,
            b"{}",
            &Url::parse("https://api.nansen.ai/api/v1/token-screener").unwrap(),
        );
        assert_eq!(challenge.protocol, "x402");
        assert_eq!(challenge.amount.as_deref(), Some("10000"));
        assert_eq!(challenge.amount_usd, Some(0.01));
    }
}
