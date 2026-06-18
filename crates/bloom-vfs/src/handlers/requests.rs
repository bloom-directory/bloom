//! Protocol-neutral paid HTTP request surface.
//!
//! This handler owns the `/requests` VFS tree. Reads only expose durable
//! artefacts; payment/signing boundaries are writable control files.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::dyn_abi::Eip712Domain;
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::signers::SignerSync;
use alloy::sol;
use alloy::sol_types::SolStruct;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bloom_keystore::{Keystore, KeystoreError, WalletKind};
use bloom_proto::Policy;
use mpp::client::{PaymentProvider, TempoProvider, TempoSessionProvider};
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
    x402_signer: Arc<dyn X402PaymentSigner>,
}

pub trait X402PaymentSigner: Send + Sync {
    fn sign_x402_payment(
        &self,
        ctx: &X402SignContext<'_>,
    ) -> Result<X402PaymentCredential, HandlerError>;
}

pub struct X402SignContext<'a> {
    pub wallet: &'a str,
    /// Stable id of the staged pending request. The nonce in
    /// `TransferWithAuthorization` is derived from this so it is bound to the
    /// request the user actually confirmed, not a fresh id generated at sign
    /// time.
    pub request_id: &'a str,
    pub request: &'a ParsedRequest,
    pub challenge: &'a NormalizedChallenge,
    pub requirement: &'a PaymentRequirement,
}

pub struct X402PaymentCredential {
    /// The secret-bearing value sent as the `X-PAYMENT` retry header. This is
    /// intentionally never persisted to credential.json.
    pub header_value: String,
    /// Redacted/public metadata safe to expose in the VFS.
    pub public_metadata: serde_json::Value,
}

sol! {
    #[allow(missing_docs)]
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

pub struct KeystoreX402PaymentSigner {
    keystore: Keystore,
}

impl KeystoreX402PaymentSigner {
    pub fn new(keystore: Keystore) -> Self {
        Self { keystore }
    }
}

impl X402PaymentSigner for KeystoreX402PaymentSigner {
    fn sign_x402_payment(
        &self,
        ctx: &X402SignContext<'_>,
    ) -> Result<X402PaymentCredential, HandlerError> {
        let signer = self.keystore.signer(ctx.wallet).map_err(|e| {
            HandlerError::backend(x402_keystore_signer_error(ctx.wallet, &self.keystore, e))
        })?;
        let info = self.keystore.info(ctx.wallet).map_err(|e| {
            HandlerError::backend(format!("x402 signer wallet metadata unavailable: {e}"))
        })?;
        let scheme = ctx.requirement.scheme.as_deref().unwrap_or("exact");
        if scheme != "exact" {
            return Err(HandlerError::backend(format!(
                "x402 keystore signer supports exact EVM requirements, got scheme '{scheme}'"
            )));
        }
        let network = ctx
            .requirement
            .network
            .as_deref()
            .ok_or_else(|| HandlerError::backend("x402 requirement missing network"))?;
        let chain_id = x402_evm_chain_id(network)?;
        let asset = parse_x402_address(ctx.requirement.asset.as_deref(), "asset")?;
        let pay_to = parse_x402_address(ctx.requirement.pay_to.as_deref(), "payTo")?;
        let now = unix_seconds();
        let valid_after = U256::from(now.saturating_sub(600));
        let valid_before = U256::from(now + x402_max_timeout_seconds(ctx.requirement));
        let nonce = x402_nonce(ctx, now);
        let value = U256::from_str_radix(ctx.requirement.amount.as_deref().unwrap_or("0"), 10)
            .map_err(|e| HandlerError::backend(format!("x402 amount is not uint256: {e}")))?;
        let authorization = json!({
            "from": info.address.to_string(),
            "to": pay_to.to_string(),
            "value": value.to_string(),
            "validAfter": valid_after.to_string(),
            "validBefore": valid_before.to_string(),
            "nonce": nonce.to_string(),
        });
        let auth = TransferWithAuthorization {
            from: info.address,
            to: pay_to,
            value,
            validAfter: valid_after,
            validBefore: valid_before,
            nonce,
        };
        let domain = Eip712Domain {
            name: x402_requirement_extra_str(ctx.requirement, "name").map(Cow::Owned),
            version: x402_requirement_extra_str(ctx.requirement, "version").map(Cow::Owned),
            chain_id: Some(U256::from(chain_id)),
            verifying_contract: Some(asset),
            ..Eip712Domain::default()
        };
        let digest = auth.eip712_signing_hash(&domain);
        let signature = signer
            .sign_hash_sync(&digest)
            .map_err(|e| HandlerError::backend(format!("x402 keystore signing failed: {e}")))?
            .to_string();
        let header = json!({
            "x402Version": 1,
            "scheme": scheme,
            "network": network,
            "payload": {
                "signature": signature,
                "authorization": authorization,
            },
        });
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|e| HandlerError::backend(format!("serialize x402 header: {e}")))?;
        Ok(X402PaymentCredential {
            header_value: STANDARD.encode(header_bytes),
            public_metadata: json!({
                "signer_backend": "bloom-keystore",
                "wallet": ctx.wallet,
                "wallet_kind": wallet_kind_label(info.kind),
                "address": info.address.to_string(),
                "scheme": scheme,
                "network": network,
                "asset": asset.to_string(),
                "pay_to": pay_to.to_string(),
                "resource": ctx.requirement.resource.as_deref().unwrap_or(ctx.request.url.as_str()),
                "authorization": authorization,
                "signature": "redacted",
            }),
        })
    }
}

fn parse_x402_address(value: Option<&str>, field: &str) -> Result<Address, HandlerError> {
    value
        .ok_or_else(|| HandlerError::backend(format!("x402 requirement missing {field}")))?
        .parse::<Address>()
        .map_err(|e| {
            HandlerError::backend(format!(
                "x402 requirement {field} is not an EVM address: {e}"
            ))
        })
}

fn x402_evm_chain_id(network: &str) -> Result<u64, HandlerError> {
    match network {
        "abstract" => Ok(2741),
        "abstract-testnet" => Ok(11124),
        "base-sepolia" => Ok(84532),
        "base" => Ok(8453),
        "avalanche-fuji" => Ok(43113),
        "avalanche" => Ok(43114),
        "iotex" => Ok(4689),
        "sei" => Ok(1329),
        "sei-testnet" => Ok(1328),
        "polygon" => Ok(137),
        "polygon-amoy" => Ok(80002),
        "peaq" => Ok(3338),
        "story" => Ok(1514),
        "educhain" => Ok(41923),
        "skale-base-sepolia" => Ok(324705682),
        other => Err(HandlerError::backend(format!(
            "x402 keystore signer supports EVM networks only; unsupported network '{other}'"
        ))),
    }
}

fn x402_requirement_extra_str(req: &PaymentRequirement, key: &str) -> Option<String> {
    req.raw
        .get("extra")
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn x402_max_timeout_seconds(req: &PaymentRequirement) -> u64 {
    req.raw
        .get("maxTimeoutSeconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(60)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn x402_nonce(ctx: &X402SignContext<'_>, now: u64) -> B256 {
    keccak256(
        format!(
            "{}:{}:{}:{now}",
            ctx.wallet, ctx.request.url, ctx.request_id
        )
        .as_bytes(),
    )
}

fn wallet_kind_label(kind: WalletKind) -> &'static str {
    match kind {
        WalletKind::Local => "local",
        WalletKind::Watch => "watch",
        WalletKind::PasskeyGated => "passkey",
    }
}

fn x402_keystore_signer_error(wallet: &str, keystore: &Keystore, err: KeystoreError) -> String {
    match err {
        KeystoreError::Locked(_) => match keystore.info(wallet).map(|i| i.kind) {
            Ok(WalletKind::PasskeyGated) => format!(
                "wallet '{wallet}' is locked; passkey wallets must be foreground-unlocked with unlock_passkey before confirming this paid request"
            ),
            _ => format!(
                "wallet '{wallet}' is locked; unlock the wallet before confirming this paid request"
            ),
        },
        other => format!("x402 keystore signer unavailable for wallet '{wallet}': {other}"),
    }
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
        }
    }

    pub fn with_x402_signer(mut self, signer: Arc<dyn X402PaymentSigner>) -> Self {
        self.x402_signer = signer;
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
        let request = parse_request(text)?;
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
        let host = request.url.host_str().unwrap_or("unknown").to_string();
        let mut challenge: NormalizedChallenge = read_json(pending.join("challenge.json"))?;
        if challenge.protocol == "mpp" && challenge.network.as_deref() == Some("tempo") {
            let backend = RealMppBackend {
                keystore: self.keystore.clone(),
                client: self.client.clone(),
                rpc_url: std::env::var("BLOOM_TEMPO_RPC_URL")
                    .unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string()),
            };
            let result = confirm_with_backend(&self.root, id, data, &backend).await?;
            if !matches!(result.final_state.as_str(), "sent" | "failed") {
                return Err(HandlerError::backend(format!(
                    "unexpected paid request final state: {}",
                    result.final_state
                )));
            }
            return Ok(());
        }
        let policy = self.wallet_policy(&wallet)?;
        let sentinel = policy.override_sentinel().to_ascii_lowercase();
        if !matches!(value.as_str(), "y" | "yes" | "confirm") && value != sentinel {
            return Err(HandlerError::invalid(format!(
                "confirm accepts y, yes, confirm, or policy override sentinel '{sentinel}'"
            )));
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
        if checks.iter().any(|c| c.result == "warn") && value != sentinel {
            return Err(HandlerError::invalid(format!(
                "payment policy warning requires override sentinel '{sentinel}'"
            )));
        }
        let credential = self.x402_signer.sign_x402_payment(&X402SignContext {
            wallet: &wallet,
            request_id: id,
            request: &request,
            challenge: &challenge,
            requirement: &requirement,
        })?;

        let mut retry = self.client.request(
            request.method.parse().unwrap_or(reqwest::Method::GET),
            request.url.clone(),
        );
        for (k, v) in &request.headers {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| HandlerError::invalid(format!("invalid header {k}: {e}")))?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| HandlerError::invalid(format!("invalid header {k}: {e}")))?;
            retry = retry.header(name, val);
        }
        retry = retry.header("X-PAYMENT", credential.header_value.clone());
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

#[derive(Debug, Clone)]
pub struct ParsedRequest {
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
    if trimmed.contains("url")
        && trimmed.contains('=')
        && let Ok(t) = toml::from_str::<TomlRequest>(trimmed)
    {
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
pub struct NormalizedChallenge {
    protocol: String,
    intent: String,
    merchant: String,
    realm: Option<String>,
    network: Option<String>,
    asset: Option<String>,
    amount: Option<String>,
    amount_usd: Option<f64>,
    charge_id: Option<String>,
    session_id: Option<String>,
    deposit_amount: Option<String>,
    deposit_usd: Option<f64>,
    chain_id: Option<u64>,
    unit_type: Option<String>,
    channel_id: Option<String>,
    challenge_id: Option<String>,
    request: Option<serde_json::Value>,
    headers: BTreeMap<String, String>,
    accepts: Vec<PaymentRequirement>,
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
    fn payment_method(&self) -> serde_json::Value {
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

fn normalize_challenge(headers: &HeaderMap, body: &[u8], url: &Url) -> NormalizedChallenge {
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
        let deposit_amount = json_string(&value, &["suggestedDeposit"]);
        let channel_id = json_string(method_details, &["channelId"])
            .or_else(|| json_string(&value, &["sessionId"]));
        return NormalizedChallenge {
            protocol: "mpp".into(),
            intent: challenge.intent.as_str().to_string(),
            merchant: challenge.realm.clone(),
            realm: Some(challenge.realm),
            network: Some("tempo".into()),
            asset: json_string(&value, &["currency"]),
            amount_usd: amount.as_deref().and_then(parse_money),
            amount,
            charge_id: json_string(&value, &["externalId"]),
            session_id: channel_id.clone(),
            deposit_usd: deposit_amount.as_deref().and_then(parse_money),
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
    let body_json: serde_json::Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
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
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
    };
    let amount_usd = if intent == "session" {
        json_f64(session, &["voucherAmountUsd", "amountUsd", "usd"])
            .or_else(|| json_f64(&body_json, &["voucherAmountUsd", "amountUsd", "usd"]))
            .or_else(|| amount.as_deref().and_then(parse_money))
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
            .or_else(|| amount.as_deref().and_then(parse_money))
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
    .or_else(|| deposit_amount.as_deref().and_then(parse_money));
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

fn parse_payment_requirements(body_json: &serde_json::Value) -> Vec<PaymentRequirement> {
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

fn json_string(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| {
        v.get(*k).and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.as_f64().map(trim_money))
        })
    })
}

fn json_f64(v: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|k| {
        v.get(*k)
            .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(parse_money)))
    })
}

fn parse_money(raw: &str) -> Option<f64> {
    raw.trim().trim_start_matches('$').parse().ok()
}

fn trim_money(v: f64) -> String {
    let s = format!("{v:.6}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn paid_http_intent_label(intent: &str) -> &str {
    match intent {
        "charge" => "one_time",
        other => other,
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

fn select_payment_requirement(
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

fn evaluate_session_policy(
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

#[async_trait]
trait PaymentBackend: Send + Sync {
    fn name(&self) -> &'static str;
    async fn confirm(
        &self,
        challenge: &NormalizedChallenge,
        request: &ParsedRequest,
        wallet: &str,
        policy: &Policy,
        request_id: &str,
    ) -> Result<PaymentExecution, HandlerError>;
}

struct RealMppBackend {
    keystore: Keystore,
    client: reqwest::Client,
    rpc_url: String,
}

impl RealMppBackend {
    fn signer_error(&self, wallet: &str, err: KeystoreError) -> HandlerError {
        match err {
            KeystoreError::Locked(_) => {
                let kind = self
                    .keystore
                    .raw_policy(wallet)
                    .ok()
                    .map(|(_, kind)| kind)
                    .or_else(|| self.keystore.info(wallet).ok().map(|info| info.kind));
                if kind == Some(WalletKind::PasskeyGated) {
                    HandlerError::invalid(format!(
                        "passkey wallet '{wallet}' is locked; run the foreground passkey unlock flow (`unlock-passkey` / Keystore::unlock_passkey) before confirming Tempo MPP payments"
                    ))
                } else {
                    HandlerError::invalid(format!(
                        "wallet '{wallet}' is locked; unlock it before confirming Tempo MPP payments"
                    ))
                }
            }
            other => HandlerError::invalid(format!(
                "wallet '{wallet}' cannot be used for Tempo MPP signing: {other}"
            )),
        }
    }
}

struct PaymentExecution {
    credential_metadata: serde_json::Value,
    receipt_raw: serde_json::Value,
    response_status: u16,
    response_headers: HeaderMap,
    response_body: Vec<u8>,
}

struct ConfirmResult {
    final_state: String,
}

#[async_trait]
impl PaymentBackend for RealMppBackend {
    fn name(&self) -> &'static str {
        "mpp_tempo"
    }

    async fn confirm(
        &self,
        challenge: &NormalizedChallenge,
        request: &ParsedRequest,
        wallet: &str,
        policy: &Policy,
        _request_id: &str,
    ) -> Result<PaymentExecution, HandlerError> {
        if challenge.protocol != "mpp" || challenge.network.as_deref() != Some("tempo") {
            return Err(HandlerError::invalid(
                "only Tempo MPP challenges can be confirmed by the real MPP backend",
            ));
        }
        let signer = self
            .keystore
            .signer(wallet)
            .map_err(|e| self.signer_error(wallet, e))?;
        let payment_challenge = parse_stored_mpp_challenge(challenge)?;
        let credential = match challenge.intent.as_str() {
            "charge" => {
                let provider = TempoProvider::new((*signer).clone(), &self.rpc_url)
                    .map_err(|e| HandlerError::backend(format!("TempoProvider: {e}")))?;
                provider.pay(&payment_challenge).await
            }
            "session" => {
                let mut provider = TempoSessionProvider::new((*signer).clone(), &self.rpc_url)
                    .map_err(|e| HandlerError::backend(format!("TempoSessionProvider: {e}")))?;
                if let Some(max) = policy
                    .payments
                    .sessions
                    .max_deposit_usd
                    .and_then(f64_to_u128_amount)
                {
                    provider = provider.with_max_deposit(max);
                }
                provider.pay(&payment_challenge).await
            }
            other => {
                return Err(HandlerError::invalid(format!(
                    "unsupported MPP intent '{other}'"
                )));
            }
        }
        .map_err(|e| HandlerError::backend(format!("Tempo MPP credential: {e}")))?;
        let authorization = mpp::format_authorization(&credential)
            .map_err(|e| HandlerError::backend(format!("format MPP Authorization: {e}")))?;
        let authorization_sha256 = bloom_tools::sha256_hex(authorization.as_bytes());
        let credential_value = serde_json::to_value(&credential).map_err(|e| {
            HandlerError::backend(format!("serialize MPP credential metadata: {e}"))
        })?;
        let retry = retry_paid_request(&self.client, request, &authorization).await?;
        let receipt_raw = retry
            .headers
            .get("payment-receipt")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| mpp::parse_receipt(h).ok())
            .and_then(|r| serde_json::to_value(r).ok())
            .unwrap_or_else(|| json!({}));
        Ok(PaymentExecution {
            credential_metadata: json!({
                "redacted": true,
                "protocol": challenge.protocol,
                "intent": challenge.intent,
                "backend": self.name(),
                "authorization_sha256": authorization_sha256,
                "source": credential_value.get("source").cloned(),
                "payload_type": credential_value.get("payload").and_then(|p| p.get("type")).cloned(),
                "charge_id": challenge.charge_id,
                "session_id": challenge.session_id,
                "channel_id": challenge.channel_id,
                "secret_material_in_vfs": false,
                "raw_authorization_stored": false,
                "raw_signed_payload_stored": false
            }),
            receipt_raw,
            response_status: retry.status,
            response_headers: retry.headers,
            response_body: retry.body,
        })
    }
}

async fn confirm_with_backend(
    root: &Path,
    id: &str,
    data: &[u8],
    backend: &dyn PaymentBackend,
) -> Result<ConfirmResult, HandlerError> {
    let value = String::from_utf8_lossy(data).trim().to_ascii_lowercase();
    if !matches!(value.as_str(), "y" | "yes" | "confirm" | "override") {
        return Err(HandlerError::invalid(
            "confirm accepts y, yes, confirm, or override",
        ));
    }
    let requests_root = root.join("requests");
    let pending = requests_root.join("pending").join(id);
    if !pending.exists() {
        return Err(HandlerError::NotFound(format!("/requests/pending/{id}")));
    }
    let checks: Vec<PolicyCheck> = read_json(pending.join("policy_check.json"))?;
    if checks.iter().any(|c| c.result == "deny") {
        return Err(HandlerError::invalid(
            "hard payment policy denial blocks confirmation",
        ));
    }
    if checks.iter().any(|c| c.result == "warn") && value != "override" {
        return Err(HandlerError::invalid(
            "payment policy warning requires override",
        ));
    }
    let challenge: NormalizedChallenge = read_json(pending.join("challenge.json"))?;
    let request_value: serde_json::Value = read_json(pending.join("request.toml"))?;
    let request = parsed_request_from_artifact(&request_value)?;
    let wallet = request_value
        .get("wallet")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::backend("request artifact missing wallet"))?
        .to_string();
    let policy = backend_policy_for_wallet(root, &wallet).unwrap_or_default();
    let execution = backend
        .confirm(&challenge, &request, &wallet, &policy, id)
        .await?;
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

fn parse_stored_mpp_challenge(
    challenge: &NormalizedChallenge,
) -> Result<mpp::PaymentChallenge, HandlerError> {
    challenge
        .headers
        .get("www-authenticate")
        .and_then(|h| {
            mpp::parse_www_authenticate_all([h.as_str()])
                .into_iter()
                .filter_map(Result::ok)
                .find(|c| c.method.as_str() == "tempo" && c.intent.as_str() == challenge.intent)
        })
        .ok_or_else(|| {
            HandlerError::backend(
                "stored challenge is missing a parseable Tempo MPP WWW-Authenticate header",
            )
        })
}

fn f64_to_u128_amount(v: f64) -> Option<u128> {
    if v.is_finite() && v >= 0.0 {
        Some(v.floor() as u128)
    } else {
        None
    }
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
        body: None,
    })
}

fn backend_policy_for_wallet(root: &Path, wallet: &str) -> Result<Policy, HandlerError> {
    let raw = fs::read_to_string(root.join("keystore").join(wallet).join("policy.toml"))?;
    toml::from_str(&raw).map_err(|e| HandlerError::backend(e.to_string()))
}

struct RetryResponse {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn retry_paid_request(
    client: &reqwest::Client,
    request: &ParsedRequest,
    authorization: &str,
) -> Result<RetryResponse, HandlerError> {
    let mut req = client.request(
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
    req = req.header(reqwest::header::AUTHORIZATION, authorization);
    if let Some(body) = &request.body {
        req = req.body(body.clone());
    }
    let response = req
        .send()
        .await
        .map_err(|e| HandlerError::backend(format!("paid HTTP retry failed: {e}")))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|e| HandlerError::backend(format!("read paid HTTP retry response: {e}")))?
        .to_vec();
    Ok(RetryResponse {
        status,
        headers,
        body,
    })
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
    use crate::path::VfsPath;
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
        ) -> Result<PaymentExecution, HandlerError> {
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

        let result = confirm_with_backend(dir.path(), "req_1", b"confirm", &StaticMppTestBackend)
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
        ) -> Result<PaymentExecution, HandlerError> {
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

        let result =
            confirm_with_backend(dir.path(), "req_fail", b"confirm", &FailingMppTestBackend)
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
        let backend = RealMppBackend {
            keystore,
            client: reqwest::Client::new(),
            rpc_url: "https://rpc.example.com".to_string(),
        };
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
        let backend = RealMppBackend {
            keystore,
            client: reqwest::Client::new(),
            rpc_url: "https://rpc.example.com".to_string(),
        };
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
