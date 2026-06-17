//! Protocol-neutral paid HTTP request surface.
//!
//! This handler owns the `/requests` VFS tree. Reads only expose durable
//! artefacts; payment/signing boundaries are writable control files.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bloom_keystore::Keystore;
use bloom_proto::Policy;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

#[derive(Clone)]
pub struct RequestsHandler {
    root: PathBuf,
    keystore: Keystore,
    default_wallet: Option<String>,
    client: reqwest::Client,
}

impl RequestsHandler {
    pub fn new(
        root: impl Into<PathBuf>,
        keystore: Keystore,
        default_wallet: Option<String>,
    ) -> Self {
        Self {
            root: root.into(),
            keystore,
            default_wallet,
            client: reqwest::Client::new(),
        }
    }

    fn requests_root(&self) -> PathBuf {
        self.root.join("requests")
    }

    fn ensure_layout(&self) -> Result<(), HandlerError> {
        for dir in ["pending", "sent", "failed", "sessions"] {
            fs::create_dir_all(self.requests_root().join(dir))?;
        }
        Ok(())
    }

    fn latest_path(&self) -> PathBuf {
        self.requests_root().join("latest")
    }

    fn write_latest(&self, state: &str, id: &str) -> Result<(), HandlerError> {
        fs::write(self.latest_path(), format!("{state}/{id}\n"))?;
        Ok(())
    }

    fn read_latest(&self) -> Result<(String, String), HandlerError> {
        let raw = fs::read_to_string(self.latest_path())
            .map_err(|_| HandlerError::NotFound("/requests/latest".into()))?;
        let trimmed = raw.trim();
        let (state, id) = trimmed
            .split_once('/')
            .ok_or_else(|| HandlerError::backend("corrupt requests/latest"))?;
        Ok((state.to_string(), id.to_string()))
    }

    fn resolve_ref(&self, raw: &str) -> Result<(String, String), HandlerError> {
        if raw == "latest" {
            return self.read_latest();
        }
        for state in ["pending", "sent", "failed"] {
            let path = self.requests_root().join(state).join(raw);
            if path.exists() {
                return Ok((state.to_string(), raw.to_string()));
            }
        }
        Err(HandlerError::NotFound(raw.into()))
    }

    fn req_dir(&self, state: &str, id: &str) -> PathBuf {
        self.requests_root().join(state).join(id)
    }

    async fn create_request(&self, input: &[u8], dry_run: bool) -> Result<String, HandlerError> {
        self.ensure_layout()?;
        let text = std::str::from_utf8(input)
            .map_err(|_| HandlerError::invalid("request input must be UTF-8"))?;
        let request = parse_request(text)?;
        let wallet = self.select_wallet(request.wallet.as_deref())?;
        let id = new_request_id();
        let host = request.url.host_str().unwrap_or("unknown").to_string();

        let mut req = self.client.request(
            request.method.parse().unwrap_or(reqwest::Method::GET),
            request.url.clone(),
        );
        for (k, v) in &request.headers {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| HandlerError::invalid(format!("invalid header {k}: {e}")))?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| HandlerError::invalid(format!("invalid header {k}: {e}")))?;
            req = req.header(name, val);
        }
        if let Some(body) = &request.body {
            req = req.body(body.clone());
        }
        let response = req
            .send()
            .await
            .map_err(|e| HandlerError::backend(format!("unpaid HTTP probe failed: {e}")))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .map_err(|e| HandlerError::backend(format!("read HTTP response: {e}")))?
            .to_vec();

        if status == 402 {
            let challenge = normalize_challenge(&headers, &body, &request.url);
            let policy = self.wallet_policy(&wallet)?;
            let spent_24h_usd = self.sum_paid_usd_last_24h(&wallet)?;
            let checks = evaluate_payment_policy(
                &policy,
                PolicyEvalInput {
                    host: &host,
                    asset: challenge.asset.as_deref(),
                    network: challenge.network.as_deref(),
                    intent: &challenge.intent,
                    amount_usd: challenge.amount_usd,
                    request_max_amount_usd: request.max_amount_usd,
                    spent_24h_usd,
                },
            );
            let dir = self.req_dir("pending", &id);
            fs::create_dir_all(dir.join("response"))?;
            write_request_artifacts(&dir, &request, &wallet, "pending")?;
            fs::write(dir.join("status"), b"pending\n")?;
            fs::write(dir.join("challenge.raw"), &body)?;
            write_json(dir.join("challenge.json"), &challenge)?;
            write_json(dir.join("payment_method.json"), &challenge.payment_method())?;
            write_json(dir.join("policy_check.json"), &checks)?;
            fs::write(
                dir.join("plan.md"),
                render_plan(&request, &wallet, &host, Some(&challenge), &checks, dry_run),
            )?;
            write_json(
                dir.join("credential.json"),
                &json!({"redacted": true, "status": "not_confirmed"}),
            )?;
            write_json(
                dir.join("audit.json"),
                &json!({"request_id": id, "event": "staged", "reads_spent": false}),
            )?;
            self.write_latest("pending", &id)?;
            Ok(id)
        } else {
            let dir = self.req_dir("sent", &id);
            fs::create_dir_all(dir.join("response"))?;
            write_request_artifacts(&dir, &request, &wallet, "sent")?;
            fs::write(dir.join("status"), b"sent\n")?;
            fs::write(
                dir.join("plan.md"),
                render_plan(&request, &wallet, &host, None, &[], dry_run),
            )?;
            fs::write(dir.join("response/status"), format!("{status}\n"))?;
            write_json(
                dir.join("response/headers.json"),
                &headers_to_json(&headers),
            )?;
            fs::write(dir.join("response/body"), &body)?;
            let sha = bloom_tools::sha256_hex(&body);
            fs::write(dir.join("response/body.sha256"), format!("{sha}\n"))?;
            write_json(
                dir.join("receipt.json"),
                &json!({
                    "request_id": id,
                    "wallet": wallet,
                    "merchant": host,
                    "amount": "0",
                    "currency": null,
                    "network": null,
                    "protocol": "free",
                    "intent": "none",
                    "tx_hash": null,
                    "session_id": null,
                    "response_sha256": sha,
                    "raw": {}
                }),
            )?;
            write_json(
                dir.join("audit.json"),
                &json!({"request_id": id, "event": "sent_free", "reads_spent": false}),
            )?;
            self.write_latest("sent", &id)?;
            Ok(id)
        }
    }

    fn select_wallet(&self, explicit: Option<&str>) -> Result<String, HandlerError> {
        if let Some(w) = explicit.filter(|s| !s.trim().is_empty()) {
            self.keystore
                .info(w)
                .map_err(|e| HandlerError::invalid(e.to_string()))?;
            return Ok(w.to_string());
        }
        if let Some(w) = self
            .default_wallet
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            self.keystore.info(w).map_err(|e| {
                HandlerError::invalid(format!(
                    "configured default_wallet '{w}' is not usable: {e}"
                ))
            })?;
            return Ok(w.to_string());
        }
        let wallets = self
            .keystore
            .list()
            .map_err(|e| HandlerError::backend(e.to_string()))?;
        match wallets.as_slice() {
            [only] => Ok(only.name.clone()),
            [] => Err(HandlerError::invalid(
                "No wallet specified and no wallets are available. Create a wallet or set wallet = \"<name>\" in the request.",
            )),
            many => Err(HandlerError::invalid(format!(
                "No wallet specified and multiple wallets are available. Set wallet = \"<name>\" in the request or configure default_wallet. Available wallets: {}",
                many.iter()
                    .map(|w| w.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    fn wallet_policy(&self, wallet: &str) -> Result<Policy, HandlerError> {
        self.keystore
            .info(wallet)
            .map(|i| i.policy)
            .map_err(|e| HandlerError::backend(e.to_string()))
    }

    fn sum_paid_usd_last_24h(&self, wallet: &str) -> Result<f64, HandlerError> {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(24 * 60 * 60);
        let mut total = 0.0;
        let sent_root = self.requests_root().join("sent");
        if !sent_root.exists() {
            return Ok(total);
        }
        for entry in fs::read_dir(sent_root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let dir = entry.path();
            let modified = entry
                .metadata()?
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if modified < since {
                continue;
            }
            let Ok(receipt) = read_json::<serde_json::Value>(dir.join("receipt.json")) else {
                continue;
            };
            if receipt.get("wallet").and_then(|v| v.as_str()) != Some(wallet) {
                continue;
            }
            let protocol = receipt
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("free");
            if protocol == "free" {
                continue;
            }
            total += receipt
                .get("amount_usd")
                .and_then(json_number)
                .or_else(|| receipt.get("amount").and_then(json_number))
                .unwrap_or(0.0);
        }
        Ok(total)
    }

    fn confirm(&self, id: &str, data: &[u8]) -> Result<(), HandlerError> {
        let value = String::from_utf8_lossy(data).trim().to_ascii_lowercase();
        let pending = self.req_dir("pending", id);
        if !pending.exists() {
            return Err(HandlerError::NotFound(format!("/requests/pending/{id}")));
        }
        let payment: serde_json::Value = read_json(pending.join("payment_method.json"))?;
        let checks: Vec<PolicyCheck> = read_json(pending.join("policy_check.json"))?;
        let request_meta: serde_json::Value = read_json(pending.join("request.toml"))?;
        let wallet = request_meta
            .get("wallet")
            .and_then(|v| v.as_str())
            .ok_or_else(|| HandlerError::backend("request metadata missing wallet"))?;
        let policy = self.wallet_policy(wallet)?;
        let sentinel = policy.override_sentinel().to_ascii_lowercase();
        if !matches!(value.as_str(), "y" | "yes" | "confirm") && value != sentinel {
            return Err(HandlerError::invalid(format!(
                "confirm accepts y, yes, confirm, or policy override sentinel '{sentinel}'"
            )));
        }
        if checks.iter().any(|c| c.result == "deny") {
            return Err(HandlerError::invalid(
                "hard payment policy denial blocks confirmation",
            ));
        }
        if checks.iter().any(|c| c.result == "warn") && value != sentinel {
            return Err(HandlerError::invalid(format!(
                "payment policy warning requires override sentinel '{sentinel}'"
            )));
        }
        write_json(
            pending.join("credential.json"),
            &json!({
                "redacted": true,
                "protocol": payment.get("protocol"),
                "intent": payment.get("intent"),
                "material": "not_stored",
                "secret_material_in_vfs": false
            }),
        )?;
        fs::write(pending.join("status"), b"failed\n")?;
        fs::write(pending.join("error.txt"), b"payment execution adapter is staged but no signer/settlement backend is configured; no credential or secret was stored in the VFS\n")?;
        let failed = self.req_dir("failed", id);
        if failed.exists() {
            fs::remove_dir_all(&failed)?;
        }
        fs::rename(&pending, &failed)?;
        self.write_latest("failed", id)?;
        Ok(())
    }
}

#[async_trait]
impl Handler for RequestsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        match segs {
            [] => Ok(Entry::dir("requests")),
            [one] if one == "new" => Ok(Entry::writable_file("new")),
            [one] if one == "latest" => Ok(Entry::symlink(
                "latest",
                &self
                    .read_latest()
                    .map(|(s, i)| format!("{s}/{i}"))
                    .unwrap_or_else(|_| "pending".into()),
            )),
            [one] if matches!(one.as_str(), "pending" | "sent" | "failed" | "sessions") => {
                Ok(Entry::dir(one))
            }
            [state, id] if matches!(state.as_str(), "pending" | "sent" | "failed" | "sessions") => {
                Ok(Entry::dir(id))
            }
            [state, _id, name] if matches!(state.as_str(), "pending" | "sent" | "failed") => {
                if matches!(name.as_str(), "confirm" | "cancel") {
                    Ok(Entry::writable_file(name))
                } else {
                    Ok(Entry::file(name))
                }
            }
            [state, _id, response, name]
                if matches!(state.as_str(), "pending" | "sent" | "failed")
                    && response == "response" =>
            {
                Ok(Entry::file(name))
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        self.ensure_layout()?;
        let segs = path.segments();
        match segs {
            [] => Ok(vec![
                Entry::writable_file("new"),
                Entry::symlink("latest", "pending/latest"),
                Entry::dir("pending"),
                Entry::dir("sent"),
                Entry::dir("failed"),
                Entry::dir("sessions"),
            ]),
            [state] if matches!(state.as_str(), "pending" | "sent" | "failed" | "sessions") => {
                list_dirs(self.requests_root().join(state))
            }
            [state, id] if matches!(state.as_str(), "pending" | "sent" | "failed") => {
                list_entries(self.req_dir(state, id))
            }
            [state, id, response]
                if matches!(state.as_str(), "pending" | "sent" | "failed")
                    && response == "response" =>
            {
                list_entries(self.req_dir(state, id).join("response"))
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        match segs {
            [one] if one == "latest" => {
                let (state, id) = self.read_latest()?;
                Ok(format!("{state}/{id}\n").into_bytes())
            }
            [reference, name] if reference == "latest" => {
                let (state, id) = self.read_latest()?;
                fs::read(self.req_dir(&state, &id).join(name)).map_err(Into::into)
            }
            [reference, response, name] if reference == "latest" && response == "response" => {
                let (state, id) = self.read_latest()?;
                fs::read(self.req_dir(&state, &id).join("response").join(name)).map_err(Into::into)
            }
            [state, id, name] if matches!(state.as_str(), "pending" | "sent" | "failed") => {
                fs::read(self.req_dir(state, id).join(name)).map_err(Into::into)
            }
            [state, id, response, name]
                if matches!(state.as_str(), "pending" | "sent" | "failed")
                    && response == "response" =>
            {
                fs::read(self.req_dir(state, id).join("response").join(name)).map_err(Into::into)
            }
            [state, id, name] if state == "sessions" => {
                fs::read(self.requests_root().join("sessions").join(id).join(name))
                    .map_err(Into::into)
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        match segs {
            [one] if one == "new" => {
                self.create_request(data, false).await?;
                Ok(())
            }
            [reference, action] if action == "confirm" => {
                let (state, id) = self.resolve_ref(reference)?;
                if state != "pending" {
                    return Err(HandlerError::invalid(
                        "only pending requests can be confirmed",
                    ));
                }
                self.confirm(&id, data)
            }
            [state, id, action] if state == "pending" && action == "confirm" => {
                self.confirm(id, data)
            }
            [state, id, action] if state == "pending" && action == "cancel" => {
                let pending = self.req_dir(state, id);
                let failed = self.req_dir("failed", id);
                fs::write(pending.join("status"), b"cancelled\n")?;
                fs::write(pending.join("error.txt"), b"cancelled by user\n")?;
                if failed.exists() {
                    fs::remove_dir_all(&failed)?;
                }
                fs::rename(pending, failed)?;
                self.write_latest("failed", id)
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedRequest {
    method: String,
    url: Url,
    wallet: Option<String>,
    max_amount_usd: Option<f64>,
    headers: BTreeMap<String, String>,
    body: Option<String>,
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

fn parse_request(input: &str) -> Result<ParsedRequest, HandlerError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(HandlerError::invalid("empty request"));
    }
    if trimmed.contains("url") && trimmed.contains('=') {
        if let Ok(t) = toml::from_str::<TomlRequest>(trimmed) {
            return Ok(ParsedRequest {
                method: t
                    .method
                    .unwrap_or_else(|| "GET".into())
                    .to_ascii_uppercase(),
                url: Url::parse(&t.url).map_err(|e| HandlerError::invalid(format!("url: {e}")))?,
                wallet: t.wallet,
                max_amount_usd: t.max_amount_usd.as_deref().and_then(|v| v.parse().ok()),
                headers: t.headers,
                body: t.body.and_then(|b| b.inline),
            });
        }
    }
    let mut lines = trimmed.lines();
    let first = lines.next().unwrap().trim();
    let mut parts = first.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HandlerError::invalid("missing method"))?
        .to_ascii_uppercase();
    let url = parts
        .next()
        .ok_or_else(|| HandlerError::invalid("missing URL"))?;
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
        url: Url::parse(url).map_err(|e| HandlerError::invalid(format!("url: {e}")))?,
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
struct NormalizedChallenge {
    protocol: String,
    intent: String,
    merchant: String,
    realm: Option<String>,
    network: Option<String>,
    asset: Option<String>,
    amount: Option<String>,
    amount_usd: Option<f64>,
    headers: BTreeMap<String, String>,
}

impl NormalizedChallenge {
    fn payment_method(&self) -> serde_json::Value {
        json!({"protocol": self.protocol, "intent": self.intent, "network": self.network, "asset": self.asset, "merchant": self.merchant})
    }
}

fn normalize_challenge(headers: &HeaderMap, body: &[u8], url: &Url) -> NormalizedChallenge {
    let header_map = headers_to_string_map(headers);
    let www = header_map
        .get("www-authenticate")
        .cloned()
        .unwrap_or_default();
    let lower = www.to_ascii_lowercase();
    let body_json: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let protocol = if header_map.keys().any(|k| k.starts_with("x-payment"))
        || body_json.get("x402Version").is_some()
        || body_json.get("accepts").is_some()
    {
        "x402"
    } else if lower.contains("payment") || lower.contains("mpp") {
        "mpp"
    } else {
        "unknown"
    };
    let intent = if lower.contains("session") || body_json.get("session").is_some() {
        "session"
    } else {
        "one_time"
    };
    let network = body_json
        .pointer("/network")
        .and_then(|v| v.as_str())
        .or_else(|| {
            body_json
                .pointer("/accepts/0/network")
                .and_then(|v| v.as_str())
        })
        .map(str::to_string);
    let asset = body_json
        .pointer("/asset")
        .and_then(|v| v.as_str())
        .or_else(|| {
            body_json
                .pointer("/accepts/0/asset")
                .and_then(|v| v.as_str())
        })
        .map(str::to_string);
    let amount = body_json
        .pointer("/amount")
        .and_then(|v| v.as_str())
        .or_else(|| {
            body_json
                .pointer("/accepts/0/maxAmountRequired")
                .and_then(|v| v.as_str())
        })
        .map(str::to_string);
    let amount_usd = body_json
        .pointer("/amountUsd")
        .and_then(json_number)
        .or_else(|| body_json.pointer("/amount_usd").and_then(json_number))
        .or_else(|| {
            body_json
                .pointer("/accepts/0/amountUsd")
                .and_then(json_number)
        })
        .or_else(|| {
            body_json
                .pointer("/accepts/0/amount_usd")
                .and_then(json_number)
        });
    NormalizedChallenge {
        protocol: protocol.into(),
        intent: intent.into(),
        merchant: url.host_str().unwrap_or("unknown").into(),
        realm: extract_realm(&www),
        network,
        asset,
        amount,
        amount_usd,
        headers: header_map,
    }
}

fn extract_realm(s: &str) -> Option<String> {
    s.split(',').find_map(|part| {
        part.trim()
            .strip_prefix("realm=")
            .map(|v| v.trim_matches('"').to_string())
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyCheck {
    rule: String,
    result: String,
    detail: String,
}

#[derive(Debug, Clone, Copy)]
struct PolicyEvalInput<'a> {
    host: &'a str,
    asset: Option<&'a str>,
    network: Option<&'a str>,
    intent: &'a str,
    amount_usd: Option<f64>,
    request_max_amount_usd: Option<f64>,
    spent_24h_usd: f64,
}

fn evaluate_payment_policy(policy: &Policy, input: PolicyEvalInput<'_>) -> Vec<PolicyCheck> {
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
fn json_number(v: &serde_json::Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str()?.parse().ok())
}

fn render_plan(
    req: &ParsedRequest,
    wallet: &str,
    host: &str,
    challenge: Option<&NormalizedChallenge>,
    checks: &[PolicyCheck],
    dry_run: bool,
) -> String {
    if let Some(ch) = challenge {
        format!(
            "# Payment plan\n\nRequest: {} {}\nWallet: {}\nMerchant: {}\nPayment method: paid_http:{}/{}\nNetwork: {}\nAsset: {}\nCost now: {}\nPolicy: {}\n{}\nOn confirm: prepare a redacted {} credential and retry only when a signer/settlement backend is configured. No secret credential material will be written to the VFS.\nDry run: {}\n",
            req.method,
            req.url,
            wallet,
            host,
            ch.protocol,
            ch.intent,
            ch.network.as_deref().unwrap_or("unknown"),
            ch.asset.as_deref().unwrap_or("unknown"),
            ch.amount.as_deref().unwrap_or("unknown"),
            if checks.iter().any(|c| c.result == "deny") {
                "denied"
            } else if checks.iter().any(|c| c.result == "warn") {
                "warning_requires_override"
            } else {
                "allowed"
            },
            checks
                .iter()
                .map(|c| format!("- {}: {} ({})", c.rule, c.result, c.detail))
                .collect::<Vec<_>>()
                .join("\n"),
            ch.protocol,
            dry_run
        )
    } else {
        format!(
            "# HTTP request plan\n\nRequest: {} {}\nWallet: {}\nMerchant: {}\nPayment method: free\nPolicy: no spend required\nOn confirm: no confirmation required; the unpaid response has already been stored.\nDry run: {}\n",
            req.method, req.url, wallet, host, dry_run
        )
    }
}

fn write_request_artifacts(
    dir: &Path,
    req: &ParsedRequest,
    wallet: &str,
    state: &str,
) -> Result<(), HandlerError> {
    write_json(
        dir.join("request.toml"),
        &json!({"method": req.method, "url": req.url.as_str(), "wallet": wallet, "max_amount_usd": req.max_amount_usd, "headers": req.headers, "state": state}),
    )?;
    fs::write(
        dir.join("request.http"),
        format!("{} {}\n", req.method, req.url),
    )?;
    Ok(())
}

fn headers_to_string_map(headers: &HeaderMap) -> BTreeMap<String, String> {
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
fn headers_to_json(headers: &HeaderMap) -> serde_json::Value {
    json!(headers_to_string_map(headers))
}
fn write_json(path: impl AsRef<Path>, v: &impl Serialize) -> Result<(), HandlerError> {
    fs::write(
        path,
        serde_json::to_vec_pretty(v).map_err(|e| HandlerError::backend(e.to_string()))?,
    )?;
    Ok(())
}
fn read_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> Result<T, HandlerError> {
    let b = fs::read(path)?;
    serde_json::from_slice(&b).map_err(|e| HandlerError::backend(e.to_string()))
}
fn list_dirs(path: PathBuf) -> Result<Vec<Entry>, HandlerError> {
    let mut out = Vec::new();
    if path.exists() {
        for e in fs::read_dir(path)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                out.push(Entry::dir(&e.file_name().to_string_lossy()));
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
fn list_entries(path: PathBuf) -> Result<Vec<Entry>, HandlerError> {
    let mut out = Vec::new();
    for e in fs::read_dir(path)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        let ty = e.file_type()?;
        out.push(if ty.is_dir() {
            Entry::dir(&name)
        } else if matches!(name.as_str(), "confirm" | "cancel" | "topup" | "close") {
            Entry::writable_file(&name)
        } else {
            Entry::file(&name)
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
fn new_request_id() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("req_{ms}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_line_with_attrs() {
        let req =
            parse_request("GET https://example.com/a wallet=research max_amount_usd=0.05").unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.wallet.as_deref(), Some("research"));
        assert_eq!(req.max_amount_usd, Some(0.05));
    }

    #[test]
    fn detects_x402_and_mpp_challenges() {
        let mut h = HeaderMap::new();
        h.insert("x-payment-required", HeaderValue::from_static("1"));
        let c = normalize_challenge(
            &h,
            b"{\"accepts\":[{\"network\":\"base\",\"asset\":\"USDC\",\"amountUsd\":\"0.04\"}]}",
            &Url::parse("https://merchant.test/").unwrap(),
        );
        assert_eq!(c.protocol, "x402");
        assert_eq!(c.asset.as_deref(), Some("USDC"));
        assert_eq!(c.amount_usd, Some(0.04));
        let mut h = HeaderMap::new();
        h.insert(
            "www-authenticate",
            HeaderValue::from_static("Payment realm=\"tempo\", session"),
        );
        let c = normalize_challenge(&h, b"{}", &Url::parse("https://mpp.test/").unwrap());
        assert_eq!(c.protocol, "mpp");
        assert_eq!(c.intent, "session");
    }

    #[test]
    fn payment_policy_uses_most_restrictive_http_and_global_caps() {
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.http.per_request_usd = Some(1.00);
        policy.caps.per_tx_usd = Some(0.04);
        let req = ParsedRequest {
            method: "GET".into(),
            url: Url::parse("https://merchant.test/data").unwrap(),
            wallet: Some("alice".into()),
            max_amount_usd: Some(0.04),
            headers: BTreeMap::new(),
            body: None,
        };
        let checks = evaluate_payment_policy(
            &policy,
            PolicyEvalInput {
                host: "merchant.test",
                asset: Some("USDC"),
                network: Some("base"),
                intent: "one_time",
                amount_usd: Some(0.045),
                request_max_amount_usd: req.max_amount_usd,
                spent_24h_usd: 0.0,
            },
        );
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "payments.http.per_request_usd" && c.result == "deny")
        );
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "request.max_amount_usd" && c.result == "deny")
        );
    }

    #[test]
    fn payment_policy_enforces_denies_allowlists_daily_warnings_and_sessions() {
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.caps.per_day_usd = Some(10.0);
        policy.caps.require_confirm_above_usd = Some(0.25);
        policy.payments.http.per_day_usd = Some(1.0);
        policy
            .payments
            .http
            .allow_hosts
            .insert("merchant.test".into());
        policy
            .payments
            .http
            .deny_hosts
            .insert("blocked.test".into());
        policy.payments.assets.allow.insert("USDC".into());
        policy.payments.assets.deny.insert("SCAM".into());
        policy.payments.networks.allow.insert("base".into());
        policy.payments.networks.deny.insert("mainnet".into());
        policy.payments.sessions.max_deposit_usd = Some(0.50);
        policy.payments.sessions.max_session_spend_usd = Some(0.75);

        let checks = evaluate_payment_policy(
            &policy,
            PolicyEvalInput {
                host: "blocked.test",
                asset: Some("SCAM"),
                network: Some("mainnet"),
                intent: "session",
                amount_usd: Some(0.80),
                request_max_amount_usd: None,
                spent_24h_usd: 0.30,
            },
        );
        for rule in [
            "payments.http.deny_hosts",
            "payments.http.allow_hosts",
            "payments.assets.deny",
            "payments.assets.allow",
            "payments.networks.deny",
            "payments.networks.allow",
            "payments.http.per_day_usd",
            "payments.sessions.enabled",
            "payments.sessions.max_deposit_usd",
            "payments.sessions.max_session_spend_usd",
        ] {
            assert!(
                checks.iter().any(|c| c.rule == rule && c.result == "deny"),
                "missing deny for {rule}: {checks:?}"
            );
        }
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "caps.require_confirm_above_usd" && c.result == "warn")
        );
    }
}
