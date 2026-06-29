//! Protocol-neutral paid HTTP request surface.
//!
//! This handler owns the `/requests` VFS tree. Reads only expose durable
//! artefacts; payment/signing boundaries are writable control files.

use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bloom_keystore::Keystore;
use bloom_paid_http::{
    EmptyPaidHttpChainRpcResolver, NormalizedChallenge, PaidHttpChainRpcResolver, ParsedRequest,
    PaymentRequirement, PolicyCheck, PolicyEvalInput, evaluate_payment_policy,
    evaluate_session_policy, headers_to_string_map, json_number, normalize_challenge,
    paid_http_intent_label, parse_money, parse_request, select_payment_requirement, trim_money,
};
use bloom_paid_mpp::{PaymentBackend, RealMppBackend};
use bloom_paid_x402::{KeystoreX402PaymentSigner, X402PaymentSigner, X402SignContext};
use bloom_proto::Policy;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const CONFIRM_APPROVAL_FILE: &str = ".confirm_approved.json";

#[derive(Clone)]
pub struct RequestsHandler {
    root: PathBuf,
    keystore: Keystore,
    default_wallet: Option<String>,
    client: reqwest::Client,
    x402_signer: Arc<dyn X402PaymentSigner>,
    paid_http_rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
}

impl RequestsHandler {
    pub fn new(
        root: impl Into<PathBuf>,
        keystore: Keystore,
        default_wallet: Option<String>,
    ) -> Self {
        Self {
            root: root.into(),
            keystore: keystore.clone(),
            default_wallet,
            client: reqwest::Client::new(),
            x402_signer: Arc::new(KeystoreX402PaymentSigner::new(keystore)),
            paid_http_rpc_resolver: Arc::new(EmptyPaidHttpChainRpcResolver),
        }
    }

    pub fn with_x402_signer(mut self, signer: Arc<dyn X402PaymentSigner>) -> Self {
        self.x402_signer = signer;
        self
    }

    pub fn with_paid_http_rpc_resolver(
        mut self,
        resolver: Arc<dyn PaidHttpChainRpcResolver>,
    ) -> Self {
        self.paid_http_rpc_resolver = resolver;
        self
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

    fn latest_target(&self) -> String {
        self.read_latest()
            .map(|(s, i)| format!("{s}/{i}"))
            .unwrap_or_else(|_| "pending".into())
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
        let request = parse_request(text).map_err(HandlerError::invalid)?;
        let id = new_request_id();
        let wallet = match self.select_wallet(request.wallet.as_deref()) {
            Ok(wallet) => wallet,
            Err(err) => {
                self.write_failed_request(&id, &request, "", &err.to_string())?;
                return Ok(id);
            }
        };
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
            let mut checks = evaluate_payment_policy(
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
            let already_spent = challenge
                .session_id
                .as_deref()
                .and_then(|sid| {
                    fs::read_to_string(
                        self.requests_root()
                            .join("sessions")
                            .join(sid)
                            .join("spent"),
                    )
                    .ok()
                    .and_then(|s| parse_money(&s))
                })
                .unwrap_or(0.0);
            checks.extend(evaluate_session_policy(&policy, &challenge, already_spent));
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

    fn write_failed_request(
        &self,
        id: &str,
        request: &ParsedRequest,
        wallet: &str,
        error: &str,
    ) -> Result<(), HandlerError> {
        let dir = self.req_dir("failed", id);
        fs::create_dir_all(dir.join("response"))?;
        write_request_artifacts(&dir, request, wallet, "failed")?;
        fs::write(dir.join("status"), b"failed\n")?;
        fs::write(dir.join("error.txt"), format!("{error}\n"))?;
        write_json(
            dir.join("audit.json"),
            &json!({"request_id": id, "event": "failed", "error": error, "reads_spent": false}),
        )?;
        self.write_latest("failed", id)?;
        Ok(())
    }

    async fn confirm(&self, id: &str, data: &[u8]) -> Result<(), HandlerError> {
        let value = String::from_utf8_lossy(data).trim().to_ascii_lowercase();
        let pending = self.req_dir("pending", id);
        if !pending.exists() {
            return Err(HandlerError::NotFound(format!("/requests/pending/{id}")));
        }
        let request_json: serde_json::Value = read_json(pending.join("request.toml"))?;
        let request = ParsedRequest {
            method: request_json
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .to_string(),
            url: Url::parse(
                request_json
                    .get("url")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| HandlerError::backend("request.toml missing url"))?,
            )
            .map_err(|e| HandlerError::backend(format!("stored request url: {e}")))?,
            wallet: request_json
                .get("wallet")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            max_amount_usd: request_json.get("max_amount_usd").and_then(|v| v.as_f64()),
            headers: serde_json::from_value(
                request_json
                    .get("headers")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            )
            .map_err(|e| HandlerError::backend(format!("stored request headers: {e}")))?,
            body: request_json
                .get("body")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };
        let wallet = request
            .wallet
            .as_deref()
            .ok_or_else(|| HandlerError::backend("request.toml missing wallet"))?
            .to_string();
        consume_request_confirm_approved(&pending, &wallet, &value)?;
        let host = request.url.host_str().unwrap_or("unknown").to_string();
        let mut challenge: NormalizedChallenge = read_json(pending.join("challenge.json"))?;
        let policy = self.wallet_policy(&wallet)?;
        let sentinel = policy.override_sentinel().to_ascii_lowercase();
        if !matches!(value.as_str(), "y" | "yes" | "confirm") && value != sentinel.as_str() {
            return Err(HandlerError::invalid(format!(
                "confirm accepts y, yes, confirm, or policy override sentinel '{sentinel}'"
            )));
        }
        if challenge.protocol == "mpp" && challenge.network.as_deref() == Some("tempo") {
            let already_spent = challenge
                .session_id
                .as_deref()
                .and_then(|sid| session_dir_name(sid).ok())
                .and_then(|sid| {
                    fs::read_to_string(
                        self.requests_root()
                            .join("sessions")
                            .join(sid)
                            .join("spent"),
                    )
                    .ok()
                    .and_then(|s| parse_money(&s))
                })
                .unwrap_or(0.0);
            let mut checks = evaluate_payment_policy(
                &policy,
                PolicyEvalInput {
                    host: &host,
                    asset: challenge.asset.as_deref(),
                    network: challenge.network.as_deref(),
                    intent: &challenge.intent,
                    amount_usd: challenge.amount_usd,
                    request_max_amount_usd: request.max_amount_usd,
                    spent_24h_usd: self.sum_paid_usd_last_24h(&wallet)?,
                },
            );
            checks.extend(evaluate_session_policy(&policy, &challenge, already_spent));
            let backend = RealMppBackend {
                keystore: self.keystore.clone(),
                client: self.client.clone(),
                rpc_resolver: Arc::clone(&self.paid_http_rpc_resolver),
            };
            let result = confirm_with_backend(
                &self.root,
                id,
                data,
                &backend,
                Some(&policy),
                Some(checks),
                Some(&sentinel),
            )
            .await?;
            if !matches!(result.final_state.as_str(), "sent" | "failed") {
                return Err(HandlerError::backend(format!(
                    "unexpected paid request final state: {}",
                    result.final_state
                )));
            }
            return Ok(());
        }
        let requirement = select_payment_requirement(&challenge, &policy, &host)
            .or_else(|| challenge.accepts.first().cloned())
            .unwrap_or_else(|| PaymentRequirement {
                scheme: None,
                network: challenge.network.clone(),
                asset: challenge.asset.clone(),
                amount: challenge.amount.clone(),
                pay_to: None,
                resource: None,
                raw: json!({}),
            });
        challenge.network = requirement.network.clone();
        challenge.asset = requirement.asset.clone();
        challenge.amount = requirement.amount.clone();
        let checks = evaluate_payment_policy(
            &policy,
            PolicyEvalInput {
                host: &host,
                asset: challenge.asset.as_deref(),
                network: challenge.network.as_deref(),
                intent: &challenge.intent,
                amount_usd: challenge.amount_usd,
                request_max_amount_usd: request.max_amount_usd,
                spent_24h_usd: self.sum_paid_usd_last_24h(&wallet)?,
            },
        );
        if checks.iter().any(|c| c.result == "deny") {
            return Err(HandlerError::invalid(
                "hard payment policy denial blocks confirmation",
            ));
        }
        if checks.iter().any(|c| c.result == "warn") && value != sentinel.as_str() {
            return Err(HandlerError::invalid(format!(
                "payment policy warning requires override sentinel '{sentinel}'"
            )));
        }
        let credential = self
            .x402_signer
            .sign_x402_payment(&X402SignContext {
                wallet: &wallet,
                request_id: id,
                request: &request,
                challenge: &challenge,
                requirement: &requirement,
                rpc_resolver: self.paid_http_rpc_resolver.as_ref(),
            })
            .await
            .map_err(HandlerError::backend)?;

        let mut retry = self.client.request(
            request.method.parse().unwrap_or(reqwest::Method::GET),
            request.url.clone(),
        );
        for (k, v) in &request.headers {
            if is_sensitive_request_header(k) {
                continue;
            }
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| HandlerError::invalid(format!("invalid header {k}: {e}")))?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| HandlerError::invalid(format!("invalid header {k}: {e}")))?;
            retry = retry.header(name, val);
        }
        retry = retry.header(credential.header_name, credential.header_value.clone());
        if let Some(body) = &request.body {
            retry = retry.body(body.clone());
        }
        let response = retry
            .send()
            .await
            .map_err(|e| HandlerError::backend(format!("paid HTTP retry failed: {e}")))?;
        let status = response.status().as_u16();
        let response_headers = response.headers().clone();
        let response_body = response
            .bytes()
            .await
            .map_err(|e| HandlerError::backend(format!("read paid HTTP response: {e}")))?
            .to_vec();
        let sha = bloom_tools::sha256_hex(&response_body);
        write_json(
            pending.join("credential.json"),
            &json!({
                "redacted": true,
                "protocol": challenge.protocol,
                "intent": challenge.intent,
                "scheme": requirement.scheme,
                "network": requirement.network,
                "asset": requirement.asset,
                "pay_to": requirement.pay_to,
                "charge_id": challenge.charge_id,
                "session_id": challenge.session_id,
                "material": "not_stored",
                "header_name": credential.header_name,
                "secret_material_in_vfs": false,
                "public": credential.public_metadata,
            }),
        )?;
        fs::write(pending.join("response/status"), format!("{status}\n"))?;
        write_json(
            pending.join("response/headers.json"),
            &headers_to_json(&response_headers),
        )?;
        fs::write(pending.join("response/body"), &response_body)?;
        fs::write(pending.join("response/body.sha256"), format!("{sha}\n"))?;
        write_json(
            pending.join("receipt.json"),
            &json!({
                "request_id": id,
                "wallet": wallet,
                "merchant": host,
                "amount": requirement.amount,
                "currency": requirement.asset,
                "network": requirement.network,
                "protocol": challenge.protocol,
                "intent": challenge.intent,
                "scheme": requirement.scheme,
                "charge_id": challenge.charge_id,
                "session_id": challenge.session_id,
                "amount_usd": challenge.amount_usd,
                "response_status": status,
                "credential_redacted": true,
            }),
        )?;
        write_json(
            pending.join("audit.json"),
            &json!({"request_id": id, "event": "confirmed_and_retried", "reads_spent": false, "credential_redacted": true}),
        )?;
        let target_state = if status < 400 { "sent" } else { "failed" };
        if target_state == "sent" && challenge.intent == "session" {
            update_session_state(&self.requests_root(), &challenge, id, &wallet)?;
        }
        fs::write(pending.join("status"), format!("{target_state}\n"))?;
        let target = self.req_dir(target_state, id);
        if target.exists() {
            fs::remove_dir_all(&target)?;
        }
        fs::rename(&pending, &target)?;
        self.write_latest(target_state, id)?;
        Ok(())
    }
}

pub fn persist_request_confirm_approved(
    root: &Path,
    id: &str,
    wallet: &str,
    confirm_value: &str,
) -> Result<(), HandlerError> {
    let dir = root.join("requests").join("pending").join(id);
    fs::write(
        dir.join(CONFIRM_APPROVAL_FILE),
        serde_json::to_vec_pretty(&json!({
            "schema": "bloom.requests.confirm_approved.v1",
            "wallet": wallet,
            "confirm_value": confirm_value,
        }))
        .map_err(|e| HandlerError::backend(e.to_string()))?,
    )?;
    Ok(())
}

fn consume_request_confirm_approved(
    pending: &Path,
    wallet: &str,
    confirm_value: &str,
) -> Result<(), HandlerError> {
    let path = pending.join(CONFIRM_APPROVAL_FILE);
    let approval: serde_json::Value = read_json(&path).map_err(|e| match e {
        HandlerError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            HandlerError::invalid("request confirm requires write_unlocked approval")
        }
        other => other,
    })?;
    let ok = approval.get("schema").and_then(|v| v.as_str())
        == Some("bloom.requests.confirm_approved.v1")
        && approval.get("wallet").and_then(|v| v.as_str()) == Some(wallet)
        && approval.get("confirm_value").and_then(|v| v.as_str()) == Some(confirm_value);
    if !ok {
        return Err(HandlerError::invalid(
            "request confirm approval does not match wallet or confirmation text",
        ));
    }
    fs::remove_file(path)?;
    Ok(())
}

#[async_trait]
impl Handler for RequestsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        match segs {
            [] => Ok(Entry::dir("requests")),
            [one] if one == "new" || one == "new.dry-run" => Ok(Entry::writable_file(one)),
            [one] if one == "latest" => Ok(Entry::symlink("latest", &self.latest_target())),
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
            [state, id, name] if state == "sessions" => {
                let file = self.requests_root().join("sessions").join(id).join(name);
                if matches!(name.as_str(), "topup" | "close") {
                    if file.exists() {
                        Ok(Entry::writable_file(name))
                    } else {
                        Err(HandlerError::NotFound(format!(
                            "/requests/sessions/{id}/{name}: control unavailable until a fresh Tempo MPP session challenge is staged"
                        )))
                    }
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
                Entry::writable_file("new.dry-run"),
                Entry::symlink("latest", &self.latest_target()),
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
            [state, id] if state == "sessions" => {
                list_entries(self.requests_root().join("sessions").join(id))
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
            [reference, name] => {
                let (state, id) = self.resolve_ref(reference)?;
                fs::read(self.req_dir(&state, &id).join(name)).map_err(Into::into)
            }
            [state, id, response, name]
                if matches!(state.as_str(), "pending" | "sent" | "failed")
                    && response == "response" =>
            {
                fs::read(self.req_dir(state, id).join("response").join(name)).map_err(Into::into)
            }
            [reference, response, name] if response == "response" => {
                let (state, id) = self.resolve_ref(reference)?;
                fs::read(self.req_dir(&state, &id).join("response").join(name)).map_err(Into::into)
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
            [one] if one == "new" || one == "new.dry-run" => {
                self.create_request(data, one == "new.dry-run").await?;
                Ok(())
            }
            [reference, action] if action == "confirm" => {
                let (state, id) = self.resolve_ref(reference)?;
                if state != "pending" {
                    return Err(HandlerError::invalid(
                        "only pending requests can be confirmed",
                    ));
                }
                self.confirm(&id, data).await
            }
            [state, id, action] if state == "pending" && action == "confirm" => {
                self.confirm(id, data).await
            }
            [state, id, action] if state == "sessions" && action == "topup" => {
                let dir = self.requests_root().join("sessions").join(id);
                if !dir.exists() {
                    return Err(HandlerError::NotFound(format!("/requests/sessions/{id}")));
                }
                Err(HandlerError::invalid(
                    "session top-up is unavailable from redacted session metadata; stage and confirm a fresh Tempo MPP session challenge that authorizes top-up before writing this control",
                ))
            }
            [state, id, action] if state == "sessions" && action == "close" => {
                let dir = self.requests_root().join("sessions").join(id);
                if !dir.exists() {
                    return Err(HandlerError::NotFound(format!("/requests/sessions/{id}")));
                }
                Err(HandlerError::invalid(
                    "session close is unavailable from redacted session metadata; stage and confirm a fresh Tempo MPP session challenge that authorizes close before writing this control",
                ))
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

#[derive(Debug)]
struct ConfirmResult {
    final_state: String,
}

async fn confirm_with_backend(
    root: &Path,
    id: &str,
    data: &[u8],
    backend: &dyn PaymentBackend,
    policy_override: Option<&Policy>,
    checks_override: Option<Vec<PolicyCheck>>,
    sentinel_override: Option<&str>,
) -> Result<ConfirmResult, HandlerError> {
    let value = String::from_utf8_lossy(data).trim().to_ascii_lowercase();
    let sentinel = sentinel_override.unwrap_or("override").to_ascii_lowercase();
    if !matches!(value.as_str(), "y" | "yes" | "confirm") && value != sentinel.as_str() {
        return Err(HandlerError::invalid(format!(
            "confirm accepts y, yes, confirm, or policy override sentinel '{sentinel}'"
        )));
    }
    let requests_root = root.join("requests");
    let pending = requests_root.join("pending").join(id);
    if !pending.exists() {
        return Err(HandlerError::NotFound(format!("/requests/pending/{id}")));
    }
    let checks: Vec<PolicyCheck> = match checks_override {
        Some(checks) => checks,
        None => read_json(pending.join("policy_check.json"))?,
    };
    if checks.iter().any(|c| c.result == "deny") {
        return Err(HandlerError::invalid(
            "hard payment policy denial blocks confirmation",
        ));
    }
    if checks.iter().any(|c| c.result == "warn") && value != sentinel.as_str() {
        return Err(HandlerError::invalid(format!(
            "payment policy warning requires override sentinel '{sentinel}'"
        )));
    }
    let challenge: NormalizedChallenge = read_json(pending.join("challenge.json"))?;
    let request_value: serde_json::Value = read_json(pending.join("request.toml"))?;
    let request = parsed_request_from_artifact(&request_value)?;
    let wallet = request_value
        .get("wallet")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::backend("request artifact missing wallet"))?
        .to_string();
    let fallback_policy;
    let policy = match policy_override {
        Some(policy) => policy,
        None => {
            fallback_policy = backend_policy_for_wallet(root, &wallet).unwrap_or_default();
            &fallback_policy
        }
    };
    let execution = backend
        .confirm(&challenge, &request, &wallet, policy, id)
        .await
        .map_err(HandlerError::backend)?;
    let succeeded = execution.response_status < 400;
    let final_state = if succeeded { "sent" } else { "failed" };
    fs::create_dir_all(pending.join("response"))?;
    write_json(
        pending.join("credential.json"),
        &execution.credential_metadata,
    )?;
    fs::write(
        pending.join("response/status"),
        format!("{}\n", execution.response_status),
    )?;
    fs::write(pending.join("response/body"), &execution.response_body)?;
    write_json(
        pending.join("response/headers.json"),
        &headers_to_json(&execution.response_headers),
    )?;
    let sha = bloom_tools::sha256_hex(&execution.response_body);
    fs::write(pending.join("response/body.sha256"), format!("{sha}\n"))?;
    write_json(
        pending.join("receipt.json"),
        &json!({
            "request_id": id,
            "wallet": request_json_field(&pending, "wallet"),
            "merchant": challenge.merchant,
            "amount": challenge.amount,
            "currency": challenge.asset,
            "network": challenge.network,
            "protocol": challenge.protocol,
            "intent": challenge.intent,
            "tx_hash": null,
            "session_id": challenge.session_id,
            "response_sha256": sha,
            "mock_backend": false,
            "raw": execution.receipt_raw
        }),
    )?;
    write_json(
        pending.join("audit.json"),
        &json!({
            "request_id": id,
            "event": "confirmed_and_retried",
            "backend": backend.name(),
            "response_status": execution.response_status,
            "paid_retry_succeeded": succeeded,
            "reads_spent": false,
            "secret_material_in_vfs": false
        }),
    )?;
    if succeeded && challenge.intent == "session" {
        let wallet = request_json_field(&pending, "wallet")
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        update_session_state(&requests_root, &challenge, id, &wallet)?;
    }
    fs::write(pending.join("status"), format!("{final_state}\n"))?;
    fs::create_dir_all(requests_root.join(final_state))?;
    let dest = requests_root.join(final_state).join(id);
    if dest.exists() {
        fs::remove_dir_all(&dest)?;
    }
    fs::rename(&pending, &dest)?;
    fs::write(
        requests_root.join("latest"),
        format!("{final_state}/{id}\n"),
    )?;
    Ok(ConfirmResult {
        final_state: final_state.into(),
    })
}

fn parsed_request_from_artifact(v: &serde_json::Value) -> Result<ParsedRequest, HandlerError> {
    let method = v
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_string();
    let url = v
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::backend("request artifact missing url"))?;
    let headers = v
        .get("headers")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Ok(ParsedRequest {
        method,
        url: Url::parse(url).map_err(|e| HandlerError::backend(format!("stored url: {e}")))?,
        wallet: v.get("wallet").and_then(|v| v.as_str()).map(str::to_string),
        max_amount_usd: v.get("max_amount_usd").and_then(|v| v.as_f64()),
        headers,
        body: v.get("body").and_then(|v| v.as_str()).map(str::to_string),
    })
}

fn backend_policy_for_wallet(root: &Path, wallet: &str) -> Result<Policy, HandlerError> {
    let raw = fs::read_to_string(root.join("keystore").join(wallet).join("policy.toml"))?;
    toml::from_str(&raw).map_err(|e| HandlerError::backend(e.to_string()))
}

fn request_json_field(dir: &Path, field: &str) -> serde_json::Value {
    read_json::<serde_json::Value>(dir.join("request.toml"))
        .ok()
        .and_then(|v| v.get(field).cloned())
        .unwrap_or(serde_json::Value::Null)
}

/// Records a redacted, append-only voucher trail after a session-intent paid
/// retry settles. This is *not* a durable Tempo MPP channel: real channel
/// reuse, top-up, and close primitives from `mpp-rs` are not linked in this
/// crate, so the session is marked `settled_no_durable_channel` rather than
/// `open` to avoid overclaiming a reusable channel.
fn update_session_state(
    requests_root: &Path,
    challenge: &NormalizedChallenge,
    request_id: &str,
    wallet: &str,
) -> Result<(), HandlerError> {
    let session_id = challenge
        .session_id
        .clone()
        .unwrap_or_else(|| format!("session_{request_id}"));
    let session_id = session_dir_name(&session_id)?;
    let dir = requests_root.join("sessions").join(&session_id);
    fs::create_dir_all(&dir)?;
    let previous_spent = fs::read_to_string(dir.join("spent"))
        .ok()
        .and_then(|s| parse_money(&s))
        .unwrap_or(0.0);
    let amount = challenge.amount_usd.unwrap_or_else(|| {
        challenge
            .amount
            .as_deref()
            .and_then(parse_money)
            .unwrap_or(0.0)
    });
    let deposited = challenge.deposit_usd.unwrap_or_else(|| {
        fs::read_to_string(dir.join("deposited"))
            .ok()
            .and_then(|s| parse_money(&s))
            .unwrap_or(0.0)
    });
    let spent = previous_spent + amount;
    fs::write(dir.join("merchant"), format!("{}\n", challenge.merchant))?;
    fs::write(dir.join("wallet"), format!("{wallet}\n"))?;
    fs::write(
        dir.join("network"),
        format!("{}\n", challenge.network.as_deref().unwrap_or("unknown")),
    )?;
    fs::write(
        dir.join("asset"),
        format!("{}\n", challenge.asset.as_deref().unwrap_or("unknown")),
    )?;
    fs::write(
        dir.join("deposited"),
        format!("{}\n", trim_money(deposited)),
    )?;
    fs::write(dir.join("spent"), format!("{}\n", trim_money(spent)))?;
    fs::write(
        dir.join("remaining"),
        format!("{}\n", trim_money((deposited - spent).max(0.0))),
    )?;
    fs::write(dir.join("status"), b"settled_no_durable_channel\n")?;
    fs::write(
        dir.join("limitations.md"),
        b"Durable Tempo MPP channel reuse, top-up, and close are not implemented; \
this session records a redacted voucher trail only. The `topup` and `close` \
control files are limitation stubs pending a real mpp-rs Tempo provider.\n",
    )?;
    let voucher = json!({
        "request_id": request_id,
        "amount": challenge.amount,
        "amount_usd": challenge.amount_usd,
        "credential": "redacted",
        "secret_material_in_vfs": false
    });
    let mut line =
        serde_json::to_vec(&voucher).map_err(|e| HandlerError::backend(e.to_string()))?;
    line.push(b'\n');
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("vouchers.jsonl"))?;
    file.write_all(&line)?;
    Ok(())
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
            paid_http_intent_label(&ch.intent),
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
        &json!({
            "method": req.method,
            "url": req.url.as_str(),
            "wallet": wallet,
            "max_amount_usd": req.max_amount_usd,
            "headers": redacted_headers(&req.headers),
            "body": req.body,
            "state": state
        }),
    )?;
    let mut http = format!("{} {}\n", req.method, req.url);
    for (k, v) in &req.headers {
        let value = if is_sensitive_request_header(k) {
            "redacted"
        } else {
            v
        };
        http.push_str(&format!("{k}: {value}\n"));
    }
    if let Some(body) = &req.body {
        http.push('\n');
        http.push_str(body);
        http.push('\n');
    }
    fs::write(dir.join("request.http"), http)?;
    Ok(())
}

fn headers_to_json(headers: &HeaderMap) -> serde_json::Value {
    json!(headers_to_string_map(headers))
}

fn redacted_headers(headers: &std::collections::BTreeMap<String, String>) -> serde_json::Value {
    json!(
        headers
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    if is_sensitive_request_header(k) {
                        "redacted".to_string()
                    } else {
                        v.clone()
                    },
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    )
}

fn is_sensitive_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "x-payment"
            | "payment-signature"
            | "x-api-key"
            | "api-key"
            | "apikey"
    )
}

fn session_dir_name(raw: &str) -> Result<String, HandlerError> {
    let name = raw.trim();
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || Path::new(name).is_absolute()
    {
        return Err(HandlerError::invalid(format!(
            "invalid paid request session id '{raw}'"
        )));
    }
    Ok(name.to_string())
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
    use crate::path::VfsPath;
    use bloom_paid_mpp::PaymentExecution;
    use mpp::client::{PaymentProvider, TempoProvider};
    use std::collections::BTreeMap;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct Fixture {
        _tmp: tempfile::TempDir,
        handler: RequestsHandler,
    }

    fn fixture(default_wallet: Option<&str>) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(tmp.path().join("keystore")).unwrap();
        keystore.create_local("alice", "pw").unwrap();
        Fixture {
            handler: RequestsHandler::new(
                tmp.path().join("home"),
                keystore,
                default_wallet.map(str::to_string),
            ),
            _tmp: tmp,
        }
    }

    #[test]
    fn request_confirm_approval_is_matching_and_one_time() {
        let tmp = tempfile::tempdir().unwrap();
        let pending = tmp.path().join("requests").join("pending").join("req_1");
        std::fs::create_dir_all(&pending).unwrap();

        persist_request_confirm_approved(tmp.path(), "req_1", "alice", "confirm").unwrap();
        assert!(consume_request_confirm_approved(&pending, "alice", "y").is_err());
        assert!(consume_request_confirm_approved(&pending, "alice", "confirm").is_ok());
        assert!(consume_request_confirm_approved(&pending, "alice", "confirm").is_err());
    }

    async fn mock_server(
        status: u16,
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let count_for_task = count.clone();
        let header_lines = headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}\r\n"))
            .collect::<String>();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                count_for_task.fetch_add(1, Ordering::SeqCst);
                let header_lines = header_lines.clone();
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let reason = if status == 402 {
                        "Payment Required"
                    } else {
                        "OK"
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\n{header_lines}\r\n",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                    socket.write_all(body).await.unwrap();
                });
            }
        });
        (format!("http://{addr}/resource"), count)
    }

    #[test]
    fn parses_one_line_toml_and_http_message_forms() {
        let req =
            parse_request("GET https://example.com/a wallet=research max_amount_usd=0.05").unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.wallet.as_deref(), Some("research"));
        assert_eq!(req.max_amount_usd, Some(0.05));

        let req = parse_request(
            r#"method = "POST"
url = "https://api.example.com/inference"
wallet = "research"
max_amount_usd = "0.05"

[headers]
content-type = "application/json"

[body]
inline = '{"prompt":"hi"}'
"#,
        )
        .unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.wallet.as_deref(), Some("research"));
        assert_eq!(req.headers["content-type"], "application/json");
        assert_eq!(req.body.as_deref(), Some(r#"{"prompt":"hi"}"#));

        let req = parse_request(
            "POST https://api.example.com/inference\ncontent-type: application/json\n\n{\"prompt\":\"hi\"}",
        )
        .unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.headers["content-type"], "application/json");
        assert_eq!(req.body.as_deref(), Some(r#"{"prompt":"hi"}"#));
    }

    #[test]
    fn request_artifacts_preserve_body_for_paid_retry() {
        let dir = tempfile::tempdir().unwrap();
        let req = parse_request(
            r#"method = "POST"
url = "https://api.example.com/inference"
wallet = "research"
max_amount_usd = "0.05"

[headers]
content-type = "application/json"

[body]
inline = '{"prompt":"hi"}'
"#,
        )
        .unwrap();
        write_request_artifacts(dir.path(), &req, "research", "pending").unwrap();

        let stored: serde_json::Value = read_json(dir.path().join("request.toml")).unwrap();
        assert_eq!(stored["body"], r#"{"prompt":"hi"}"#);
        let reloaded = parsed_request_from_artifact(&stored).unwrap();
        assert_eq!(reloaded.body.as_deref(), Some(r#"{"prompt":"hi"}"#));

        let http = fs::read_to_string(dir.path().join("request.http")).unwrap();
        assert!(http.contains("content-type: application/json\n\n"));
        assert!(http.ends_with("{\"prompt\":\"hi\"}\n"));
    }

    #[test]
    fn request_artifacts_redact_sensitive_headers() {
        let dir = tempfile::tempdir().unwrap();
        let req = parse_request(
            "GET https://api.example.com/data\nauthorization: Bearer secret\nx-api-key: key-123\naccept: application/json",
        )
        .unwrap();
        write_request_artifacts(dir.path(), &req, "research", "pending").unwrap();

        let stored: serde_json::Value = read_json(dir.path().join("request.toml")).unwrap();
        assert_eq!(stored["headers"]["authorization"], "redacted");
        assert_eq!(stored["headers"]["x-api-key"], "redacted");
        assert_eq!(stored["headers"]["accept"], "application/json");
        let http = fs::read_to_string(dir.path().join("request.http")).unwrap();
        assert!(http.contains("authorization: redacted\n"), "{http}");
        assert!(http.contains("x-api-key: redacted\n"), "{http}");
        assert!(!http.contains("Bearer secret"), "{http}");
        assert!(!http.contains("key-123"), "{http}");
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
            HeaderValue::from_static(r#"Payment realm="tempo", session"#),
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
    fn parses_tempo_charge_challenge_metadata() {
        let c = normalize_challenge(
            &HeaderMap::new(),
            br#"{
                "protocol": "tempo-mpp",
                "type": "Charge",
                "network": "tempo",
                "asset": "pathUSD",
                "amount": "0.25",
                "amountUsd": 0.25,
                "charge": {"id": "ch_123", "merchant": "merchant-42"}
            }"#,
            &Url::parse("https://mpp.test/pay").unwrap(),
        );
        assert_eq!(c.protocol, "mpp");
        assert_eq!(c.intent, "charge");
        assert_eq!(c.network.as_deref(), Some("tempo"));
        assert_eq!(c.asset.as_deref(), Some("pathUSD"));
        assert_eq!(c.amount.as_deref(), Some("0.25"));
        assert_eq!(c.amount_usd, Some(0.25));
        assert_eq!(c.charge_id.as_deref(), Some("ch_123"));
        assert_eq!(c.merchant, "merchant-42");
    }

    #[tokio::test]
    async fn parses_real_mpp_payment_header_and_formats_real_tempo_charge_credential() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let request = mpp::protocol::core::Base64UrlJson::from_value(&json!({
            "amount": "0",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": { "chainId": 42431 }
        }))
        .unwrap();
        let challenge = mpp::PaymentChallenge::new(
            "challenge-123",
            "merchant.test",
            "tempo",
            "charge",
            request,
        );
        let header = mpp::format_www_authenticate(&challenge).unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&header).unwrap(),
        );

        let normalized =
            normalize_challenge(&h, b"", &Url::parse("https://merchant.test/pay").unwrap());
        assert_eq!(normalized.protocol, "mpp");
        assert_eq!(normalized.intent, "charge");
        assert_eq!(normalized.network.as_deref(), Some("tempo"));
        assert_eq!(
            normalized.asset.as_deref(),
            Some("0x20c0000000000000000000000000000000000000")
        );
        assert_eq!(normalized.amount.as_deref(), Some("0"));
        assert_eq!(normalized.chain_id, Some(42431));

        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com").unwrap();
        let credential = provider.pay(&challenge).await.unwrap();
        let auth = mpp::format_authorization(&credential).unwrap();
        assert!(auth.starts_with("Payment "));
        assert_eq!(
            credential.source,
            Some(mpp::PaymentCredential::evm_did(
                42431,
                &signer.address().to_string()
            ))
        );
    }

    #[test]
    fn parses_tempo_session_challenge_and_enforces_cumulative_cap() {
        let c = normalize_challenge(
            &HeaderMap::new(),
            br#"{
                "protocol": "tempo-mpp",
                "type": "Session",
                "network": "tempo",
                "asset": "pathUSD",
                "session": {
                    "id": "sess_abc",
                    "voucherAmount": "0.40",
                    "voucherAmountUsd": 0.40,
                    "depositAmount": "2.00",
                    "depositAmountUsd": 2.00
                }
            }"#,
            &Url::parse("https://mpp.test/data").unwrap(),
        );
        assert_eq!(c.protocol, "mpp");
        assert_eq!(c.intent, "session");
        assert_eq!(c.session_id.as_deref(), Some("sess_abc"));
        assert_eq!(c.amount_usd, Some(0.40));
        assert_eq!(c.deposit_usd, Some(2.00));

        let policy = Policy {
            payments: bloom_proto::policy::PaymentsPolicy {
                enabled: true,
                sessions: bloom_proto::policy::PaymentsSessionsPolicy {
                    enabled: true,
                    max_deposit_usd: Some(2.0),
                    max_session_spend_usd: Some(1.0),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let checks = evaluate_session_policy(&policy, &c, 0.70);
        assert!(
            checks
                .iter()
                .any(|c| c.rule == "payments.sessions.max_session_spend_usd" && c.result == "deny")
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

    #[tokio::test]
    async fn free_request_moves_to_sent_and_reads_body_receipt_without_http_side_effects() {
        let f = fixture(Some("alice"));
        let (url, hits) = mock_server(200, &[("content-type", "text/plain")], b"hello\n").await;
        let id = f
            .handler
            .create_request(format!("GET {url}").as_bytes(), false)
            .await
            .unwrap();

        assert_eq!(
            f.handler.read_latest().unwrap(),
            ("sent".into(), id.clone())
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            f.handler
                .read(&VfsPath::parse(&format!("/sent/{id}/response/body")).unwrap())
                .await
                .unwrap(),
            b"hello\n"
        );
        assert_eq!(
            f.handler
                .read(&VfsPath::parse(&format!("/{id}/response/body")).unwrap())
                .await
                .unwrap(),
            b"hello\n"
        );
        let receipt = String::from_utf8(
            f.handler
                .read(&VfsPath::parse(&format!("/{id}/receipt.json")).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(receipt.contains("\"protocol\": \"free\""));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "reads must not re-issue HTTP"
        );
    }

    #[tokio::test]
    async fn dry_run_paid_request_stages_pending_plan_and_cancel_moves_failed() {
        let f = fixture(Some("alice"));
        let body = br#"{"accepts":[{"network":"base","asset":"USDC","maxAmountRequired":"1000"}]}"#;
        let (url, _hits) = mock_server(402, &[("x-payment-required", "1")], body).await;
        f.handler
            .write(
                &VfsPath::parse("/new.dry-run").unwrap(),
                format!("GET {url}").as_bytes(),
            )
            .await
            .unwrap();
        let (state, id) = f.handler.read_latest().unwrap();
        assert_eq!(state, "pending");
        let plan = String::from_utf8(
            f.handler
                .read(&VfsPath::parse("/latest/plan.md").unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(plan.contains("Dry run: true"));
        assert!(plan.contains("Payment method: paid_http:x402/one_time"));
        f.handler
            .write(
                &VfsPath::parse(&format!("/pending/{id}/cancel")).unwrap(),
                b"y",
            )
            .await
            .unwrap();
        assert_eq!(
            f.handler.read_latest().unwrap(),
            ("failed".into(), id.clone())
        );
        let error = String::from_utf8(
            f.handler
                .read(&VfsPath::parse(&format!("/failed/{id}/error.txt")).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(error.contains("cancelled by user"));
    }

    #[tokio::test]
    async fn multiple_wallet_without_default_creates_failed_request_before_probe() {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(tmp.path().join("keystore")).unwrap();
        keystore.create_local("alice", "pw").unwrap();
        keystore.create_local("bob", "pw").unwrap();
        let handler = RequestsHandler::new(tmp.path().join("home"), keystore, None);
        let (url, hits) = mock_server(200, &[], b"should-not-be-fetched").await;

        let id = handler
            .create_request(format!("GET {url}").as_bytes(), false)
            .await
            .unwrap();
        assert_eq!(
            handler.read_latest().unwrap(),
            ("failed".into(), id.clone())
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        let error = String::from_utf8(
            handler
                .read(&VfsPath::parse(&format!("/failed/{id}/error.txt")).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(error.contains("multiple wallets are available"));
        assert!(error.contains("alice"));
        assert!(error.contains("bob"));
    }

    struct StaticMppTestBackend;

    #[async_trait]
    impl PaymentBackend for StaticMppTestBackend {
        fn name(&self) -> &'static str {
            "mpp_tempo_test_double"
        }

        async fn confirm(
            &self,
            challenge: &NormalizedChallenge,
            _request: &ParsedRequest,
            _wallet: &str,
            _policy: &Policy,
            _request_id: &str,
        ) -> Result<PaymentExecution, String> {
            Ok(PaymentExecution {
                credential_metadata: json!({
                    "redacted": true,
                    "backend": self.name(),
                    "protocol": challenge.protocol,
                    "intent": challenge.intent,
                    "secret_material_in_vfs": false,
                    "raw_authorization_stored": false,
                    "raw_signed_payload_stored": false
                }),
                receipt_raw: json!({"backend": self.name()}),
                response_status: 200,
                response_headers: HeaderMap::new(),
                response_body: b"paid response\n".to_vec(),
            })
        }
    }

    #[tokio::test]
    async fn mpp_confirm_redacts_credentials_and_updates_session_state() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("requests/pending/req_1");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Session","network":"tempo","asset":"pathUSD","session":{"id":"sess_1","voucherAmount":"0.10","voucherAmountUsd":0.10,"depositAmount":"1.00","depositAmountUsd":1.00}}"#,
            &Url::parse("https://mpp.test/data").unwrap(),
        );
        write_json(pending.join("challenge.json"), &challenge).unwrap();
        let payment = challenge.payment_method();
        write_json(pending.join("payment_method.json"), &payment).unwrap();
        let empty_checks: Vec<PolicyCheck> = vec![];
        write_json(pending.join("policy_check.json"), &empty_checks).unwrap();
        write_json(
            pending.join("request.toml"),
            &json!({"method":"GET","url":"https://mpp.test/data","wallet":"alice","headers":{}}),
        )
        .unwrap();
        fs::write(pending.join("request.http"), "GET https://mpp.test/data\n").unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();

        let result = confirm_with_backend(
            dir.path(),
            "req_1",
            b"confirm",
            &StaticMppTestBackend,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.final_state, "sent");
        let credential: serde_json::Value =
            read_json(dir.path().join("requests/sent/req_1/credential.json")).unwrap();
        assert_eq!(credential["secret_material_in_vfs"], false);
        assert!(credential.get("raw_voucher").is_none());
        let spent = fs::read_to_string(dir.path().join("requests/sessions/sess_1/spent")).unwrap();
        assert_eq!(spent.trim(), "0.1");
        let session_status =
            fs::read_to_string(dir.path().join("requests/sessions/sess_1/status")).unwrap();
        assert_eq!(session_status.trim(), "settled_no_durable_channel");
        let receipt: serde_json::Value =
            read_json(dir.path().join("requests/sent/req_1/receipt.json")).unwrap();
        assert_eq!(receipt["session_id"], "sess_1");
        assert_eq!(receipt["mock_backend"], false);
        let audit: serde_json::Value =
            read_json(dir.path().join("requests/sent/req_1/audit.json")).unwrap();
        assert_eq!(audit["paid_retry_succeeded"], true);
        assert_eq!(audit["response_status"], 200);
    }

    #[tokio::test]
    async fn mpp_confirm_rechecks_current_policy() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("requests/pending/req_policy");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Charge","network":"tempo","asset":"pathUSD","amount":"0.10","amountUsd":0.10}"#,
            &Url::parse("https://mpp.test/data").unwrap(),
        );
        write_json(pending.join("challenge.json"), &challenge).unwrap();
        let staged_checks: Vec<PolicyCheck> = vec![];
        write_json(pending.join("policy_check.json"), &staged_checks).unwrap();
        write_json(
            pending.join("request.toml"),
            &json!({"method":"GET","url":"https://mpp.test/data","wallet":"alice","headers":{}}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        let current_checks = vec![PolicyCheck {
            rule: "payments.enabled".into(),
            result: "deny".into(),
            detail: "wallet policy has not enabled paid HTTP".into(),
        }];

        let err = confirm_with_backend(
            dir.path(),
            "req_policy",
            b"confirm",
            &StaticMppTestBackend,
            Some(&Policy::default()),
            Some(current_checks),
            Some("approve-spend"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("hard payment policy denial"));
    }

    #[test]
    fn mpp_session_id_must_be_single_safe_segment() {
        let dir = tempfile::tempdir().unwrap();
        let requests_root = dir.path().join("requests");
        let mut challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Session","network":"tempo","asset":"pathUSD","session":{"id":"../escape","voucherAmount":"0.10","voucherAmountUsd":0.10}}"#,
            &Url::parse("https://mpp.test/data").unwrap(),
        );
        let err =
            update_session_state(&requests_root, &challenge, "req_escape", "alice").unwrap_err();
        assert!(err.to_string().contains("invalid paid request session id"));
        assert!(!dir.path().join("escape").exists());

        challenge.session_id = Some("sess_safe".into());
        update_session_state(&requests_root, &challenge, "req_safe", "alice").unwrap();
        assert!(requests_root.join("sessions").join("sess_safe").exists());
    }

    struct FailingMppTestBackend;

    #[async_trait]
    impl PaymentBackend for FailingMppTestBackend {
        fn name(&self) -> &'static str {
            "mpp_tempo_test_double_failing"
        }

        async fn confirm(
            &self,
            challenge: &NormalizedChallenge,
            _request: &ParsedRequest,
            _wallet: &str,
            _policy: &Policy,
            _request_id: &str,
        ) -> Result<PaymentExecution, String> {
            Ok(PaymentExecution {
                credential_metadata: json!({
                    "redacted": true,
                    "backend": self.name(),
                    "protocol": challenge.protocol,
                    "intent": challenge.intent,
                    "secret_material_in_vfs": false,
                    "raw_authorization_stored": false,
                    "raw_signed_payload_stored": false
                }),
                receipt_raw: json!({"backend": self.name()}),
                response_status: 500,
                response_headers: HeaderMap::new(),
                response_body: b"merchant error\n".to_vec(),
            })
        }
    }

    #[tokio::test]
    async fn mpp_confirm_failed_paid_retry_routes_to_failed_and_skips_session_state() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("requests/pending/req_fail");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Session","network":"tempo","asset":"pathUSD","session":{"id":"sess_fail","voucherAmount":"0.10","voucherAmountUsd":0.10,"depositAmount":"1.00","depositAmountUsd":1.00}}"#,
            &Url::parse("https://mpp.test/data").unwrap(),
        );
        write_json(pending.join("challenge.json"), &challenge).unwrap();
        write_json(
            pending.join("payment_method.json"),
            &challenge.payment_method(),
        )
        .unwrap();
        let empty_checks: Vec<PolicyCheck> = vec![];
        write_json(pending.join("policy_check.json"), &empty_checks).unwrap();
        write_json(
            pending.join("request.toml"),
            &json!({"method":"GET","url":"https://mpp.test/data","wallet":"alice","headers":{}}),
        )
        .unwrap();
        fs::write(pending.join("request.http"), "GET https://mpp.test/data\n").unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();

        let result = confirm_with_backend(
            dir.path(),
            "req_fail",
            b"confirm",
            &FailingMppTestBackend,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.final_state, "failed");

        let failed = dir.path().join("requests/failed/req_fail");
        let sent = dir.path().join("requests/sent/req_fail");
        let still_pending = dir.path().join("requests/pending/req_fail");
        assert!(failed.exists(), "failed/<id> should exist");
        assert!(!sent.exists(), "sent/<id> must not exist for failed retry");
        assert!(
            !still_pending.exists(),
            "pending/<id> must be moved out after confirm"
        );

        let status = fs::read_to_string(failed.join("status")).unwrap();
        assert_eq!(status.trim(), "failed");
        let response_status = fs::read_to_string(failed.join("response/status")).unwrap();
        assert_eq!(response_status.trim(), "500");
        let body = fs::read(failed.join("response/body")).unwrap();
        assert_eq!(body, b"merchant error\n");
        assert!(failed.join("response/headers.json").exists());
        assert!(failed.join("response/body.sha256").exists());

        let latest = fs::read_to_string(dir.path().join("requests/latest")).unwrap();
        assert_eq!(latest.trim(), "failed/req_fail");

        let receipt: serde_json::Value = read_json(failed.join("receipt.json")).unwrap();
        assert_eq!(receipt["session_id"], "sess_fail");
        assert_eq!(receipt["mock_backend"], false);
        let audit: serde_json::Value = read_json(failed.join("audit.json")).unwrap();
        assert_eq!(audit["paid_retry_succeeded"], false);
        assert_eq!(audit["response_status"], 500);
        assert_eq!(audit["secret_material_in_vfs"], false);
        let credential: serde_json::Value = read_json(failed.join("credential.json")).unwrap();
        assert_eq!(credential["secret_material_in_vfs"], false);
        assert!(credential.get("raw_voucher").is_none());

        let session_dir = dir.path().join("requests/sessions/sess_fail");
        assert!(
            !session_dir.exists(),
            "failed paid retry must not create/open/update the MPP session state"
        );
    }

    #[tokio::test]
    async fn locked_local_wallet_fails_before_tempo_signing_with_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(dir.path().join("keystore")).unwrap();
        keystore.create_local("alice", "secret").unwrap();
        let backend = RealMppBackend::without_rpc_resolver(keystore, reqwest::Client::new());
        let challenge = NormalizedChallenge {
            protocol: "mpp".into(),
            intent: "charge".into(),
            merchant: "merchant.test".into(),
            realm: Some("merchant.test".into()),
            network: Some("tempo".into()),
            asset: Some("pathUSD".into()),
            amount: Some("0".into()),
            amount_usd: Some(0.0),
            charge_id: Some("ch_locked".into()),
            session_id: None,
            deposit_amount: None,
            deposit_usd: None,
            chain_id: Some(42431),
            unit_type: None,
            channel_id: None,
            challenge_id: Some("challenge-locked".into()),
            request: None,
            headers: BTreeMap::new(),
            accepts: Vec::new(),
        };
        let request = parse_request("GET https://merchant.test/pay wallet=alice").unwrap();

        let msg = match backend
            .confirm(
                &challenge,
                &request,
                "alice",
                &Policy::default(),
                "req_locked",
            )
            .await
        {
            Ok(_) => panic!("locked wallet unexpectedly signed Tempo MPP credential"),
            Err(err) => err.to_string(),
        };
        assert!(msg.contains("wallet 'alice' is locked"), "{msg}");
        assert!(msg.contains("unlock"), "{msg}");
    }

    #[tokio::test]
    async fn locked_passkey_wallet_error_points_to_foreground_unlock_passkey_flow() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(dir.path().join("keystore")).unwrap();
        keystore.create_local("passkey_alice", "secret").unwrap();
        fs::write(dir.path().join("keystore/passkey_alice/kind"), b"passkey").unwrap();
        let backend = RealMppBackend::without_rpc_resolver(keystore, reqwest::Client::new());
        let challenge = NormalizedChallenge {
            protocol: "mpp".into(),
            intent: "charge".into(),
            merchant: "merchant.test".into(),
            realm: Some("merchant.test".into()),
            network: Some("tempo".into()),
            asset: Some("pathUSD".into()),
            amount: Some("0".into()),
            amount_usd: Some(0.0),
            charge_id: Some("ch_passkey_locked".into()),
            session_id: None,
            deposit_amount: None,
            deposit_usd: None,
            chain_id: Some(42431),
            unit_type: None,
            channel_id: None,
            challenge_id: Some("challenge-passkey-locked".into()),
            request: None,
            headers: BTreeMap::new(),
            accepts: Vec::new(),
        };
        let request = parse_request("GET https://merchant.test/pay wallet=passkey_alice").unwrap();

        let msg = match backend
            .confirm(
                &challenge,
                &request,
                "passkey_alice",
                &Policy::default(),
                "req_passkey_locked",
            )
            .await
        {
            Ok(_) => panic!("locked passkey wallet unexpectedly signed Tempo MPP credential"),
            Err(err) => err.to_string(),
        };
        assert!(msg.contains("passkey wallet"), "{msg}");
        assert!(msg.contains("unlock-passkey"), "{msg}");
        assert!(msg.contains("foreground"), "{msg}");
    }

    #[tokio::test]
    async fn session_topup_and_close_controls_are_not_advertised_without_fresh_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(dir.path().join("keystore")).unwrap();
        let handler = RequestsHandler::new(dir.path(), keystore, None);
        let session_dir = dir.path().join("requests/sessions/sess_controls");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("status"), "open\n").unwrap();
        fs::write(session_dir.join("spent"), "0.25\n").unwrap();

        let topup_lookup = handler
            .lookup(&VfsPath::parse("/sessions/sess_controls/topup").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(topup_lookup, HandlerError::NotFound(_)));
        let close_lookup = handler
            .lookup(&VfsPath::parse("/sessions/sess_controls/close").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(close_lookup, HandlerError::NotFound(_)));

        let topup_write = handler
            .write(
                &VfsPath::parse("/sessions/sess_controls/topup").unwrap(),
                b"100",
            )
            .await
            .unwrap_err();
        assert!(
            topup_write
                .to_string()
                .contains("fresh Tempo MPP session challenge")
        );
        let close_write = handler
            .write(
                &VfsPath::parse("/sessions/sess_controls/close").unwrap(),
                b"close",
            )
            .await
            .unwrap_err();
        assert!(
            close_write
                .to_string()
                .contains("fresh Tempo MPP session challenge")
        );
    }

    #[tokio::test]
    async fn session_reads_have_no_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = Keystore::new(dir.path().join("keystore")).unwrap();
        let handler = RequestsHandler::new(dir.path(), keystore, None);
        let session_dir = dir.path().join("requests/sessions/sess_read");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("spent"), "0.25\n").unwrap();
        fs::write(
            session_dir.join("vouchers.jsonl"),
            "{\"request_id\":\"req_a\"}\n",
        )
        .unwrap();

        let before = fs::read_to_string(session_dir.join("vouchers.jsonl")).unwrap();
        let first = handler
            .read(&VfsPath::parse("/sessions/sess_read/spent").unwrap())
            .await
            .unwrap();
        let second = handler
            .read(&VfsPath::parse("/sessions/sess_read/spent").unwrap())
            .await
            .unwrap();
        let after = fs::read_to_string(session_dir.join("vouchers.jsonl")).unwrap();

        assert_eq!(first, b"0.25\n");
        assert_eq!(second, b"0.25\n");
        assert_eq!(before, after);
    }
}
