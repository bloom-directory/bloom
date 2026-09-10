//! Protocol-neutral paid HTTP request surface.
//!
//! This handler owns the `/requests` VFS tree. Reads only expose durable
//! artefacts; payment/signing boundaries are writable control files.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bloom_machine_client::WalletProjectionReader;
use bloom_paid_http::{
    EmptyPaidHttpChainRpcResolver, NormalizedChallenge, PaidHttpChainRpcResolver,
    PaidHttpHostSigner, PaidHttpSigningFacts, ParsedRequest, PaymentRequirement, PolicyCheck,
    PolicyEvalInput, evaluate_payment_policy, evaluate_session_policy,
    is_sensitive_paid_http_header, json_number, normalize_challenge, paid_http_intent_label,
    parse_money, parse_payment_amount_usd, parse_request, select_payment_requirement,
    selected_requirement_amount_usd, trim_money,
};
use bloom_paid_mpp::{PaymentBackend, RealMppBackend};
use bloom_paid_x402::{HostX402PaymentSigner, X402PaymentSigner, X402SignContext};
use bloom_proto::Policy;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

use crate::BrokerExactPayloadSigner;
use crate::ExactPayloadOutcome;
use crate::FileOperationIndex;
use crate::OperationIndex;
use crate::handler::{
    Entry, EntryKind, Handler, HandlerError, entry_for_fs_path, entry_from_fs_dir_entry,
    fs_path_modified,
};
use crate::path::VfsPath;

const APPROVAL_CHALLENGE_FILE: &str = "approval_challenge.json";
const PAID_HTTP_X402_SIGN_INTENT: &str = "x402.sign";
const PAID_HTTP_MPP_SIGN_INTENT: &str = "paid-http.mpp.sign";

/// Upper bound on a single paid-HTTP round trip — the merchant probe, the
/// payment backend's RPC, and the credentialed retry all use it.
///
/// These calls run inside the router's audited effect window, so an
/// unresponsive merchant would otherwise hold an unresolved effect open with
/// no ceiling.
const PAID_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The one place paid-HTTP clients are built, so every request this handler
/// makes is bounded by [`PAID_HTTP_REQUEST_TIMEOUT`].
fn paid_http_client() -> reqwest::Client {
    paid_http_client_with_timeout(PAID_HTTP_REQUEST_TIMEOUT)
}

fn paid_http_client_with_timeout(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("paid http client builder")
}

#[cfg(test)]
struct VenueLocalTestOperationIndex;

#[cfg(test)]
impl OperationIndex for VenueLocalTestOperationIndex {
    fn allocate(
        &self,
        _surface: &str,
        venue_local_id: &str,
        _wallet: &str,
        _created_ms: u64,
    ) -> Result<String, String> {
        Ok(venue_local_id.to_owned())
    }
}

#[derive(Clone)]
pub struct RequestsHandler {
    root: PathBuf,
    default_wallet: Option<String>,
    client: reqwest::Client,
    x402_signer: Arc<dyn X402PaymentSigner>,
    paid_http_rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
    operation_index: Arc<dyn OperationIndex>,
    wallet_projections: Option<Arc<dyn WalletProjectionReader>>,
    exact_signer: Option<BrokerExactPayloadSigner>,
}

impl RequestsHandler {
    pub fn new_projected(
        root: impl Into<PathBuf>,
        default_wallet: Option<String>,
        wallet_projections: Arc<dyn WalletProjectionReader>,
    ) -> Self {
        let root = root.into();
        Self {
            operation_index: Arc::new(FileOperationIndex::new(root.join("operations/index.json"))),
            root,
            default_wallet,
            client: paid_http_client(),
            x402_signer: Arc::new(HostX402PaymentSigner::new()),
            paid_http_rpc_resolver: Arc::new(EmptyPaidHttpChainRpcResolver),
            wallet_projections: Some(wallet_projections),
            exact_signer: None,
        }
    }

    pub fn with_operation_index(mut self, operation_index: Arc<dyn OperationIndex>) -> Self {
        self.operation_index = operation_index;
        self
    }

    pub fn with_exact_signer(mut self, signer: Option<BrokerExactPayloadSigner>) -> Self {
        self.exact_signer = signer;
        self
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
        let raw = safe_fs_component(raw, "request id")?;
        if raw == "latest" {
            return self.read_latest();
        }
        for state in ["pending", "sent", "failed"] {
            let path = self.requests_root().join(state).join(&raw);
            if path.exists() {
                return Ok((state.to_string(), raw));
            }
        }
        Err(HandlerError::NotFound(raw))
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
        let wallet = match self.select_wallet(request.wallet.as_deref()).await {
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
            if is_sensitive_request_header(k) && !is_mpp_probe_marker_header(k, v) {
                continue;
            }
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
            let policy = self.wallet_policy(&wallet).await?;
            let spent_24h_usd = self.sum_paid_usd_last_24h(&wallet)?;
            let policy_requirement = select_payment_requirement(&challenge, &policy, &host)
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
            let policy_amount_usd =
                selected_requirement_amount_usd(&challenge, &policy_requirement);
            let mut checks = evaluate_payment_policy(
                &policy,
                PolicyEvalInput {
                    host: &host,
                    asset: policy_requirement.asset.as_deref(),
                    network: policy_requirement.network.as_deref(),
                    intent: &challenge.intent,
                    amount_usd: policy_amount_usd,
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
            write_request_artifacts(&dir, &request, &wallet, "pending", dry_run)?;
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
                &json!({"request_id": id, "event": "staged", "reads_spent": false, "dry_run": dry_run}),
            )?;
            self.stage_auth_entry(PaidHttpAuthSubject {
                id: &id,
                request: &request,
                wallet: &wallet,
                host: &host,
                challenge: &challenge,
                requirement: &policy_requirement,
                checks: &checks,
                policy: &policy,
                dry_run,
            })
            .await?;
            self.write_latest("pending", &id)?;
            Ok(id)
        } else {
            let dir = self.req_dir("sent", &id);
            fs::create_dir_all(dir.join("response"))?;
            write_request_artifacts(&dir, &request, &wallet, "sent", dry_run)?;
            fs::write(dir.join("status"), b"sent\n")?;
            fs::write(
                dir.join("plan.md"),
                render_plan(&request, &wallet, &host, None, &[], dry_run),
            )?;
            fs::write(dir.join("response/status"), format!("{status}\n"))?;
            write_json(
                dir.join("response/headers.json"),
                &public_headers_to_json(&headers),
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

    async fn select_wallet(&self, explicit: Option<&str>) -> Result<String, HandlerError> {
        let projections = self.wallet_projections.as_ref().ok_or_else(|| {
            HandlerError::backend("SERVICE_UNAVAILABLE: wallet projections are not configured")
        })?;
        if let Some(wallet) = explicit.filter(|value| !value.trim().is_empty()).or(self
            .default_wallet
            .as_deref()
            .filter(|value| !value.trim().is_empty()))
        {
            let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())
                .map_err(|error| HandlerError::invalid(error.to_string()))?;
            projections
                .get_wallet(&wallet_id)
                .await
                .map_err(|error| HandlerError::backend(error.to_string()))?;
            return Ok(wallet.to_owned());
        }
        let wallets = projections
            .list_wallets()
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        match wallets.as_slice() {
            [only] => Ok(only.wallet.wallet_id.as_str().to_owned()),
            [] => Err(HandlerError::invalid(
                "No wallet specified and no projected wallets are available. Create a wallet or set wallet = \"<name>\" in the request.",
            )),
            many => Err(HandlerError::invalid(format!(
                "No wallet specified and multiple projected wallets are available. Set wallet = \"<name>\" in the request or configure default_wallet. Available wallets: {}",
                many.iter()
                    .map(|projection| projection.wallet.wallet_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    async fn wallet_policy(&self, wallet: &str) -> Result<Policy, HandlerError> {
        let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        let projection = self
            .wallet_projections
            .as_ref()
            .ok_or_else(|| {
                HandlerError::backend("SERVICE_UNAVAILABLE: wallet projections are not configured")
            })?
            .get_wallet(&wallet_id)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        crate::advisory_paid_http_policy(&projection).map_err(HandlerError::backend)
    }

    async fn wallet_address(
        &self,
        wallet: &str,
    ) -> Result<alloy::primitives::Address, HandlerError> {
        let wallet_id = bloom_broker_api::Token::new(wallet.to_owned())
            .map_err(|error| HandlerError::invalid(error.to_string()))?;
        self.wallet_projections
            .as_ref()
            .ok_or_else(|| {
                HandlerError::backend("SERVICE_UNAVAILABLE: wallet projections are not configured")
            })?
            .get_wallet(&wallet_id)
            .await
            .map_err(|error| HandlerError::backend(error.to_string()))?
            .primary_address()
            .map_err(|error| HandlerError::backend(error.to_string()))?
            .parse()
            .map_err(|error| HandlerError::invalid(format!("wallet address: {error}")))
    }

    fn sum_paid_usd_last_24h(&self, wallet: &str) -> Result<f64, HandlerError> {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(24 * 60 * 60);
        let mut total = 0.0;
        for state in ["sent", "failed"] {
            let root = self.requests_root().join(state);
            if !root.exists() {
                continue;
            }
            for entry in fs::read_dir(root)? {
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
                    .or_else(|| {
                        parse_payment_amount_usd(
                            receipt.get("currency").and_then(|v| v.as_str()),
                            receipt.get("amount").and_then(|v| v.as_str()),
                        )
                    })
                    .unwrap_or(0.0);
            }
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
        write_request_artifacts(&dir, request, wallet, "failed", false)?;
        fs::write(dir.join("status"), b"failed\n")?;
        fs::write(dir.join("error.txt"), format!("{error}\n"))?;
        write_json(
            dir.join("audit.json"),
            &json!({"request_id": id, "event": "failed", "error": error, "reads_spent": false}),
        )?;
        self.write_latest("failed", id)?;
        Ok(())
    }

    async fn stage_auth_entry(
        &self,
        subject: PaidHttpAuthSubject<'_>,
    ) -> Result<String, HandlerError> {
        let action_id = self
            .operation_index
            .allocate("requests", subject.id, subject.wallet, now_ms())
            .map_err(|e| HandlerError::backend(format!("allocate paid-http action id: {e}")))?;
        let subject_value = paid_http_sealed_subject(subject);
        let policy_bytes = serde_jcs::to_vec(subject.policy)
            .map_err(|error| HandlerError::backend(error.to_string()))?;
        let snapshot = MachinePaidHttpExecutionSnapshot {
            schema: "bloom.machine_paid_http_execution.v1".into(),
            action_id: action_id.clone(),
            wallet: subject.wallet.to_owned(),
            subject: subject_value,
            policy: subject.policy.clone(),
            policy_snapshot_digest: bloom_tools::sha256_hex(&policy_bytes),
        };
        write_json(
            self.req_dir("pending", subject.id)
                .join("private/execution.json"),
            &snapshot,
        )?;
        fs::write(
            self.req_dir("pending", subject.id).join("action_id"),
            format!("{action_id}\n"),
        )?;
        Ok(action_id)
    }

    async fn ensure_sealed_confirm_approval(
        &self,
        _pending: &Path,
        _id: &str,
    ) -> Result<(), HandlerError> {
        if self.exact_signer.is_none() {
            return Err(HandlerError::Unsupported(
                "request confirm requires Broker exact signing".into(),
            ));
        }
        Ok(())
    }

    async fn sealed_execution_inputs(
        &self,
        pending: &Path,
        request_id: &str,
    ) -> Result<PaidHttpExecutionInputs, HandlerError> {
        let snapshot: MachinePaidHttpExecutionSnapshot =
            read_json(pending.join("private/execution.json"))?;
        if snapshot.schema != "bloom.machine_paid_http_execution.v1"
            || snapshot.action_id != self.request_action_id(request_id).await?
        {
            return Err(HandlerError::invalid(
                "paid-http execution snapshot identity is invalid; re-stage the request",
            ));
        }
        snapshot
            .subject
            .validate_basic(request_id, &snapshot.wallet)?;
        validate_pending_projection_matches_subject(pending, &snapshot.subject)?;
        let mut request = snapshot.subject.to_request(&snapshot.wallet)?;
        if let Some(body_sha256) = snapshot.subject.body_sha256.as_deref() {
            let body = fs::read_to_string(pending.join("private/request_body"))?;
            if bloom_tools::sha256_hex(body.as_bytes()) != body_sha256 {
                return Err(HandlerError::invalid(
                    "private/request_body does not match the staged request body hash",
                ));
            }
            request.body = Some(body);
        }
        Ok(PaidHttpExecutionInputs {
            request,
            host: snapshot.subject.host,
            challenge: snapshot.subject.challenge,
            requirement: snapshot.subject.selected_requirement,
            checks: snapshot.subject.policy_checks,
            dry_run: snapshot.subject.dry_run,
            policy: snapshot.policy,
            policy_snapshot_digest: snapshot.policy_snapshot_digest,
        })
    }

    async fn request_action_id(&self, request_id: &str) -> Result<String, HandlerError> {
        let pending = self.req_dir("pending", request_id);
        let request = parsed_request_from_dir(&pending)?;
        let wallet = request
            .wallet
            .as_deref()
            .ok_or_else(|| HandlerError::backend("request.toml missing wallet"))?;
        self.operation_index
            .allocate("requests", request_id, wallet, now_ms())
            .map_err(|e| HandlerError::backend(format!("lookup paid-http action id: {e}")))
    }

    /// Build the payload-bearing paid-HTTP Broker signing seam.
    fn paid_http_host_signer(&self, wallet: &str, action_id: &str) -> Arc<dyn PaidHttpHostSigner> {
        match &self.exact_signer {
            Some(signer) => Arc::new(BrokerPaidHttpHostSigner {
                signer: signer.clone(),
                wallet: wallet.to_owned(),
                action_id: action_id.to_owned(),
                requests_root: self.requests_root(),
            }),
            None => Arc::new(UnwiredPaidHttpHostSigner),
        }
    }

    async fn confirm(&self, id: &str, data: &[u8]) -> Result<(), HandlerError> {
        let value = String::from_utf8_lossy(data).trim().to_ascii_lowercase();
        let pending = self.req_dir("pending", id);
        if !pending.exists() {
            return Err(HandlerError::NotFound(format!("/requests/pending/{id}")));
        }
        let sealed_inputs = self.sealed_execution_inputs(&pending, id).await?;
        if sealed_inputs.dry_run {
            return Err(HandlerError::invalid(
                "dry-run paid requests cannot be confirmed; stage a fresh request with /requests/new",
            ));
        }
        if pending.join("private/credential_minted.json").exists() {
            return Err(HandlerError::invalid(
                "this pending request already minted a payment credential; cancel and stage a fresh request instead of re-confirming",
            ));
        }
        let request = sealed_inputs.request;
        let wallet = request
            .wallet
            .as_deref()
            .ok_or_else(|| HandlerError::backend("sealed request missing wallet"))?
            .to_string();
        let host = sealed_inputs.host;
        let mut challenge = sealed_inputs.challenge;
        validate_session_state_target(&challenge, id)?;
        let live_policy = self.wallet_policy(&wallet).await?;
        let policy = sealed_inputs.policy;
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
            let mut checks = sealed_inputs.checks.clone();
            let mut live_checks = evaluate_payment_policy(
                &live_policy,
                PolicyEvalInput {
                    host: &host,
                    asset: challenge.asset.as_deref(),
                    network: challenge.network.as_deref(),
                    intent: &challenge.intent,
                    amount_usd: selected_requirement_amount_usd(
                        &challenge,
                        &sealed_inputs.requirement,
                    ),
                    request_max_amount_usd: request.max_amount_usd,
                    spent_24h_usd: self.sum_paid_usd_last_24h(&wallet)?,
                },
            );
            live_checks.extend(evaluate_session_policy(
                &live_policy,
                &challenge,
                already_spent,
            ));
            checks.extend(live_checks.into_iter().filter(|c| c.result == "deny"));
            self.ensure_sealed_confirm_approval(&pending, id).await?;
            let action_id = self.request_action_id(id).await?;
            let wallet_address = self.wallet_address(&wallet).await?;
            let policy_snapshot_digest = Some(sealed_inputs.policy_snapshot_digest.clone());
            let mut requirement = sealed_inputs.requirement.clone();
            if requirement.resource.is_none() {
                requirement.resource = Some(request.url.to_string());
            }
            let host_signer = self.paid_http_host_signer(&wallet, &action_id);
            let facts = paid_http_mpp_facts(
                id,
                &request,
                &host,
                &challenge,
                &requirement,
                policy_snapshot_digest,
            );
            let backend = RealMppBackend {
                client: self.client.clone(),
                rpc_resolver: Arc::clone(&self.paid_http_rpc_resolver),
                wallet_address,
                host_signer,
                facts,
                draft_path: Some(pending.join("private/mpp-unsigned-draft")),
            };
            let result = confirm_with_backend(
                &self.root,
                id,
                data,
                &backend,
                ConfirmBackendOptions {
                    policy: &policy,
                    checks_override: Some(checks),
                    sentinel_override: Some(&sentinel),
                    // Execute from the sealed request/challenge/requirement we
                    // validated above, not from the mutable pending projection.
                    sealed_execution: Some(ConfirmExecutionInputs {
                        request: &request,
                        challenge: &challenge,
                        requirement: &requirement,
                        wallet: &wallet,
                        dry_run: sealed_inputs.dry_run,
                    }),
                },
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
        let requirement = sealed_inputs.requirement;
        challenge.network = requirement.network.clone();
        challenge.asset = requirement.asset.clone();
        challenge.amount = requirement.amount.clone();
        let amount_usd = selected_requirement_amount_usd(&challenge, &requirement);
        let mut checks = sealed_inputs.checks;
        checks.extend(
            evaluate_payment_policy(
                &live_policy,
                PolicyEvalInput {
                    host: &host,
                    asset: challenge.asset.as_deref(),
                    network: challenge.network.as_deref(),
                    intent: &challenge.intent,
                    amount_usd,
                    request_max_amount_usd: request.max_amount_usd,
                    spent_24h_usd: self.sum_paid_usd_last_24h(&wallet)?,
                },
            )
            .into_iter()
            .filter(|c| c.result == "deny"),
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
        self.ensure_sealed_confirm_approval(&pending, id).await?;
        // Sign the x402 credential through the host signing seam. The grant's
        // one signature allowance is consumed atomically inside host signing;
        // there is no separate bookkeeping consume around a direct signature.
        let action_id = self.request_action_id(id).await?;
        let wallet_address = self.wallet_address(&wallet).await?;
        let policy_snapshot_digest = Some(sealed_inputs.policy_snapshot_digest);
        let host_signer = self.paid_http_host_signer(&wallet, &action_id);
        let facts = paid_http_x402_facts(
            id,
            &request,
            &host,
            &challenge,
            &requirement,
            policy_snapshot_digest,
        );
        let credential = self
            .x402_signer
            .sign_x402_payment(&X402SignContext {
                wallet: &wallet,
                request_id: id,
                request: &request,
                challenge: &challenge,
                requirement: &requirement,
                rpc_resolver: self.paid_http_rpc_resolver.as_ref(),
                wallet_address,
                host_signer: &host_signer,
                facts: &facts,
                draft_path: &pending.join("private/x402-unsigned-draft"),
            })
            .await
            .map_err(HandlerError::backend)?;

        let credential_metadata = json!({
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
        });
        write_minted_marker(&pending, id, &credential_metadata)?;
        let retry = retry_paid_request(
            &self.client,
            &request,
            credential.header_name,
            &credential.header_value,
        )
        .await;
        finalize_paid_retry(
            &self.requests_root(),
            &pending,
            id,
            &wallet,
            &host,
            &challenge,
            &requirement,
            amount_usd,
            credential_metadata,
            retry,
        )?;
        let final_state = if self.req_dir("sent", id).exists() {
            "sent"
        } else {
            "failed"
        };
        self.write_latest(final_state, id)?;
        Ok(())
    }
}

/// Stub used when no Broker signer is wired. It never signs.
struct UnwiredPaidHttpHostSigner;

#[async_trait]
impl PaidHttpHostSigner for UnwiredPaidHttpHostSigner {
    async fn sign_paid_http_payload(
        &self,
        _intent: &str,
        _signing_slot: &str,
        _preimage: &[u8],
        _signing_hash: [u8; 32],
        _facts: &PaidHttpSigningFacts,
    ) -> Result<[u8; 65], String> {
        Err("Broker exact paid-http signing is unavailable".to_string())
    }

    async fn sign_paid_http_hash(
        &self,
        _intent: &str,
        _signing_hash: [u8; 32],
        _facts: &PaidHttpSigningFacts,
    ) -> Result<[u8; 65], String> {
        Err(
            "UNSUPPORTED_VERSION: legacy hash-only paid-http signing is disabled; use the \
             payload-bearing Machine-to-Broker signing protocol"
                .to_string(),
        )
    }
}

struct BrokerPaidHttpHostSigner {
    signer: BrokerExactPayloadSigner,
    wallet: String,
    action_id: String,
    requests_root: PathBuf,
}

#[async_trait]
impl PaidHttpHostSigner for BrokerPaidHttpHostSigner {
    async fn sign_paid_http_payload(
        &self,
        intent: &str,
        signing_slot: &str,
        preimage: &[u8],
        signing_hash: [u8; 32],
        facts: &PaidHttpSigningFacts,
    ) -> Result<[u8; 65], String> {
        let operation_class = match intent {
            PAID_HTTP_X402_SIGN_INTENT => "paid-http.x402",
            PAID_HTTP_MPP_SIGN_INTENT => "paid-http.mpp",
            _ => return Err(format!("unsupported paid-http signing intent {intent}")),
        };
        let request_id = safe_fs_component(&facts.request_id, "paid-http request id")
            .map_err(|error| error.to_string())?;
        let request_dir = self.requests_root.join("pending").join(request_id);
        let signing_slot = safe_fs_component(signing_slot, "paid-http signing slot")
            .map_err(|error| error.to_string())?;
        let state_path = request_dir
            .join("private/exact-signing")
            .join(format!("{signing_slot}.json"));
        let signing_action_id = format!("{}-{signing_slot}", self.action_id);
        let facts_json = serde_json::to_value(facts).map_err(|error| error.to_string())?;
        match self
            .signer
            .sign_or_prepare(
                &state_path,
                &signing_action_id,
                &self.wallet,
                operation_class,
                preimage,
                bloom_broker_api::Digest32::from_bytes(signing_hash),
                &facts_json,
            )
            .await?
        {
            ExactPayloadOutcome::ApprovalRequired {
                approval_id,
                ceremony_url,
                ceremony_expires_at_ms,
            } => {
                let challenge = json!({
                    "schema": "bloom.broker_approval_challenge.v1",
                    "action_id": signing_action_id,
                    "wallet": self.wallet,
                    "approval_id": approval_id,
                    "ceremony_url": ceremony_url,
                    "expiry_ms": ceremony_expires_at_ms,
                });
                fs::write(
                    request_dir.join(APPROVAL_CHALLENGE_FILE),
                    serde_json::to_vec_pretty(&challenge).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                Err("paid-http Broker approval required".into())
            }
            ExactPayloadOutcome::Signed(raw) => {
                let signature = <[u8; 65]>::try_from(raw.as_slice()).map_err(|_| {
                    format!(
                        "Broker paid-http signature is {} bytes, expected 65",
                        raw.len()
                    )
                })?;
                let _ = fs::remove_file(request_dir.join(APPROVAL_CHALLENGE_FILE));
                Ok(signature)
            }
        }
    }

    async fn sign_paid_http_hash(
        &self,
        _intent: &str,
        _signing_hash: [u8; 32],
        _facts: &PaidHttpSigningFacts,
    ) -> Result<[u8; 65], String> {
        Err("legacy hash-only paid-http signing is disabled".into())
    }
}

fn paid_http_x402_facts(
    request_id: &str,
    request: &ParsedRequest,
    host: &str,
    challenge: &NormalizedChallenge,
    requirement: &PaymentRequirement,
    policy_snapshot_digest: Option<String>,
) -> PaidHttpSigningFacts {
    PaidHttpSigningFacts {
        request_id: request_id.to_string(),
        method: request.method.clone(),
        url: request.url.to_string(),
        host: host.to_string(),
        protocol: "x402".to_string(),
        network: requirement.network.clone(),
        chain_id: challenge.chain_id,
        asset: requirement.asset.clone(),
        amount: requirement.amount.clone(),
        pay_to: requirement.pay_to.clone(),
        resource: requirement
            .resource
            .clone()
            .or_else(|| Some(request.url.to_string())),
        scheme: requirement.scheme.clone(),
        charge_id: challenge.charge_id.clone(),
        session_id: challenge.session_id.clone(),
        channel_id: challenge.channel_id.clone(),
        policy_snapshot_digest,
        selected_requirement: Some(requirement.raw.clone()),
    }
}

/// Assemble the secret-free Tempo MPP signing facts from the staged request
/// and normalized challenge.
fn paid_http_mpp_facts(
    request_id: &str,
    request: &ParsedRequest,
    host: &str,
    challenge: &NormalizedChallenge,
    requirement: &PaymentRequirement,
    policy_snapshot_digest: Option<String>,
) -> PaidHttpSigningFacts {
    PaidHttpSigningFacts {
        request_id: request_id.to_string(),
        method: request.method.clone(),
        url: request.url.to_string(),
        host: host.to_string(),
        protocol: "mpp".to_string(),
        network: challenge.network.clone(),
        chain_id: challenge.chain_id,
        asset: challenge.asset.clone(),
        amount: challenge.amount.clone(),
        pay_to: requirement.pay_to.clone(),
        resource: Some(request.url.to_string()),
        scheme: requirement.scheme.clone(),
        charge_id: challenge.charge_id.clone(),
        session_id: challenge.session_id.clone(),
        channel_id: challenge.channel_id.clone(),
        policy_snapshot_digest,
        selected_requirement: Some(requirement.raw.clone()),
    }
}

#[cfg(test)]
pub fn persist_request_confirm_approved(
    root: &Path,
    id: &str,
    wallet: &str,
    confirm_value: &str,
) -> Result<(), HandlerError> {
    let id = safe_fs_component(id, "request id")?;
    let dir = root.join("requests").join("pending").join(&id);
    fs::write(
        dir.join(".confirm_approved.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "bloom.requests.confirm_approved.v1",
            "wallet": wallet,
            "confirm_value": confirm_value,
        }))
        .map_err(|e| HandlerError::backend(e.to_string()))?,
    )?;
    Ok(())
}

#[async_trait]
impl Handler for RequestsHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        validate_vfs_segments(path)?;
        let segs = path.segments();
        match segs {
            [] => Ok(Entry::dir("requests")),
            [one] if one == "new" || one == "new.dry-run" => Ok(Entry::writable_file(one)),
            [one] if one == "latest" => {
                let mut entry = Entry::symlink("latest", &self.latest_target());
                if let Some(modified) = fs_path_modified(self.latest_path())? {
                    entry = entry.with_modified(modified);
                }
                Ok(entry)
            }
            [one] if matches!(one.as_str(), "pending" | "sent" | "failed" | "sessions") => {
                self.ensure_layout()?;
                entry_for_fs_path(self.requests_root().join(one), one, EntryKind::Dir)
            }
            [state, id] if matches!(state.as_str(), "pending" | "sent" | "failed" | "sessions") => {
                self.ensure_layout()?;
                entry_for_fs_path(
                    self.requests_root().join(state).join(id),
                    id,
                    EntryKind::Dir,
                )
            }
            [state, _id, name]
                if matches!(state.as_str(), "pending" | "sent" | "failed")
                    && name == "response" =>
            {
                // `response` is a subdirectory (its files are handled by the
                // 4-segment arm below and listed by `list`). Without this the
                // generic file arm reports it as a 0-byte file, so a mounted
                // client caches it as a file and descending into it fails with
                // ENOTDIR.
                entry_for_fs_path(
                    self.req_dir(state, _id).join("response"),
                    "response",
                    EntryKind::Dir,
                )
            }
            [state, _id, name] if matches!(state.as_str(), "pending" | "sent" | "failed") => {
                if matches!(name.as_str(), "confirm" | "cancel") {
                    let mut entry = Entry::writable_file(name);
                    if let Some(modified) = fs_path_modified(self.req_dir(state, _id))? {
                        entry = entry.with_modified(modified);
                    }
                    Ok(entry)
                } else {
                    entry_for_fs_path(self.req_dir(state, _id).join(name), name, EntryKind::File)
                }
            }
            [state, id, name] if state == "sessions" => {
                let file = self.requests_root().join("sessions").join(id).join(name);
                if matches!(name.as_str(), "topup" | "close") {
                    if file.exists() {
                        entry_for_fs_path(file, name, EntryKind::File).map(|mut entry| {
                            entry.mode = 0o644;
                            entry
                        })
                    } else {
                        Err(HandlerError::NotFound(format!(
                            "/requests/sessions/{id}/{name}: control unavailable until a fresh Tempo MPP session challenge is staged"
                        )))
                    }
                } else {
                    entry_for_fs_path(file, name, EntryKind::File)
                }
            }
            [state, id, response, name]
                if matches!(state.as_str(), "pending" | "sent" | "failed")
                    && response == "response" =>
            {
                entry_for_fs_path(
                    self.req_dir(state, id).join("response").join(name),
                    name,
                    EntryKind::File,
                )
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        validate_vfs_segments(path)?;
        self.ensure_layout()?;
        let segs = path.segments();
        match segs {
            [] => Ok(vec![
                Entry::writable_file("new"),
                Entry::writable_file("new.dry-run"),
                entry_with_optional_fs_modified(
                    self.latest_path(),
                    Entry::symlink("latest", &self.latest_target()),
                )?,
                entry_with_optional_fs_modified(
                    self.requests_root().join("pending"),
                    Entry::dir("pending"),
                )?,
                entry_with_optional_fs_modified(
                    self.requests_root().join("sent"),
                    Entry::dir("sent"),
                )?,
                entry_with_optional_fs_modified(
                    self.requests_root().join("failed"),
                    Entry::dir("failed"),
                )?,
                entry_with_optional_fs_modified(
                    self.requests_root().join("sessions"),
                    Entry::dir("sessions"),
                )?,
            ]),
            [state] if matches!(state.as_str(), "pending" | "sent" | "failed" | "sessions") => {
                list_dirs(self.requests_root().join(state))
            }
            [state, id] if matches!(state.as_str(), "pending" | "sent" | "failed") => {
                let mut entries = list_entries(self.req_dir(state, id))?;
                // Always advertise the pending control files even before
                // they've been written, so agents can `printf y > confirm`
                // (mirrors the EVM ln pending listing in wallets.rs). These
                // are virtual write-only sinks that never exist on disk, so
                // without this they'd be invisible to `ls`.
                if state.as_str() == "pending" {
                    for ctrl in ["cancel", "confirm"] {
                        if !entries.iter().any(|e| e.name == ctrl) {
                            entries.push(Entry::writable_file(ctrl));
                        }
                    }
                    entries.sort_by(|a, b| a.name.cmp(&b.name));
                }
                Ok(entries)
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
        validate_vfs_segments(path)?;
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

    async fn prepare_write_open(&self, path: &VfsPath) -> Result<(), HandlerError> {
        validate_vfs_segments(path)?;
        match path.segments() {
            [reference, action] if action == "confirm" => {
                let (state, id) = self.resolve_ref(reference)?;
                if state != "pending" {
                    return Err(HandlerError::OperationNotPermitted);
                }
                let pending = self.req_dir("pending", &id);
                if !pending.exists() {
                    return Err(HandlerError::NotFound(format!("/requests/pending/{id}")));
                }
                self.ensure_sealed_confirm_approval(&pending, &id).await
            }
            [state, id, action] if state == "pending" && action == "confirm" => {
                let pending = self.req_dir("pending", id);
                if !pending.exists() {
                    return Err(HandlerError::NotFound(format!("/requests/pending/{id}")));
                }
                self.ensure_sealed_confirm_approval(&pending, id).await
            }
            _ => Ok(()),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        validate_vfs_segments(path)?;
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

struct ConfirmBackendOptions<'a> {
    /// Explicit key-free policy projection already selected by the caller.
    /// Confirmation must never recover authority inputs from legacy Machine
    /// state when this value is unavailable.
    policy: &'a Policy,
    checks_override: Option<Vec<PolicyCheck>>,
    sentinel_override: Option<&'a str>,
    /// Sealed execution inputs already validated by the caller. When present,
    /// `confirm_with_backend` uses these bytes instead of re-reading the
    /// mutable pending projection (`challenge.json`, `request.toml`), closing
    /// the TOCTOU between sealed validation and backend execution.
    sealed_execution: Option<ConfirmExecutionInputs<'a>>,
}

/// Sealed request/challenge/requirement values threaded into
/// `confirm_with_backend` so it executes from the sealed action bytes rather
/// than re-reading the mutable pending projection.
struct ConfirmExecutionInputs<'a> {
    request: &'a ParsedRequest,
    challenge: &'a NormalizedChallenge,
    requirement: &'a PaymentRequirement,
    wallet: &'a str,
    dry_run: bool,
}

async fn confirm_with_backend(
    root: &Path,
    id: &str,
    data: &[u8],
    backend: &dyn PaymentBackend,
    options: ConfirmBackendOptions<'_>,
) -> Result<ConfirmResult, HandlerError> {
    let value = String::from_utf8_lossy(data).trim().to_ascii_lowercase();
    let sentinel = options
        .sentinel_override
        .unwrap_or("override")
        .to_ascii_lowercase();
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
    let checks: Vec<PolicyCheck> = match options.checks_override {
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
    // Prefer the caller's sealed values over the mutable pending projection:
    // for the MPP path the caller has already validated the sealed action and
    // its request/challenge/requirement, so re-reading `challenge.json` /
    // `request.toml` here would reopen a TOCTOU against a tampered projection.
    let (challenge, request, wallet, requirement, dry_run) = match &options.sealed_execution {
        Some(sealed) => (
            sealed.challenge.clone(),
            sealed.request.clone(),
            sealed.wallet.to_string(),
            sealed.requirement.clone(),
            sealed.dry_run,
        ),
        None => {
            let challenge: NormalizedChallenge = read_json(pending.join("challenge.json"))?;
            let request_value: serde_json::Value = read_json(pending.join("request.toml"))?;
            let dry_run = request_value
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let request = parsed_request_from_dir(&pending)?;
            let wallet = request_value
                .get("wallet")
                .and_then(|v| v.as_str())
                .ok_or_else(|| HandlerError::backend("request artifact missing wallet"))?
                .to_string();
            let requirement = PaymentRequirement {
                scheme: None,
                network: challenge.network.clone(),
                asset: challenge.asset.clone(),
                amount: challenge.amount.clone(),
                pay_to: None,
                resource: None,
                raw: json!({}),
            };
            (challenge, request, wallet, requirement, dry_run)
        }
    };
    validate_session_state_target(&challenge, id)?;
    if dry_run {
        return Err(HandlerError::invalid(
            "dry-run paid requests cannot be confirmed; stage a fresh request with /requests/new",
        ));
    }
    if pending.join("private/credential_minted.json").exists() {
        return Err(HandlerError::invalid(
            "this pending request already minted a payment credential; cancel and stage a fresh request instead of re-confirming",
        ));
    }
    let execution = backend
        .prepare(&challenge, &request, &wallet, options.policy, id)
        .await
        .map_err(HandlerError::backend)?;
    write_minted_marker(&pending, id, &execution.credential_metadata)?;
    let retry = retry_paid_request(
        &paid_http_client(),
        &request,
        execution.header_name,
        &execution.header_value,
    )
    .await;
    let amount_usd = selected_requirement_amount_usd(&challenge, &requirement);
    let final_state = finalize_paid_retry(
        &requests_root,
        &pending,
        id,
        &wallet,
        &challenge.merchant,
        &challenge,
        &requirement,
        amount_usd,
        execution.credential_metadata,
        retry,
    )?;
    fs::write(
        requests_root.join("latest"),
        format!("{final_state}/{id}\n"),
    )?;
    Ok(ConfirmResult { final_state })
}

fn parsed_request_from_dir(dir: &Path) -> Result<ParsedRequest, HandlerError> {
    let mut request =
        parsed_request_from_artifact(&read_json::<serde_json::Value>(dir.join("request.toml"))?)?;
    let private_body = dir.join("private/request_body");
    if private_body.exists() {
        request.body = Some(fs::read_to_string(private_body)?);
    }
    Ok(request)
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

fn validate_pending_projection_matches_subject(
    pending: &Path,
    subject: &PaidHttpSealedSubject,
) -> Result<(), HandlerError> {
    let request_value: serde_json::Value = read_json(pending.join("request.toml"))?;
    let artifact = parsed_request_from_artifact(&request_value)?;
    if artifact.method != subject.method
        || artifact.url.as_str() != subject.url
        || artifact.max_amount_usd != subject.max_amount_usd
    {
        return Err(HandlerError::invalid(
            "request.toml projection differs from the sealed request subject",
        ));
    }
    let artifact_headers = request_value
        .get("headers")
        .and_then(|v| serde_json::from_value::<BTreeMap<String, String>>(v.clone()).ok())
        .unwrap_or_default();
    if serde_json::to_value(&artifact_headers).map_err(|e| HandlerError::backend(e.to_string()))?
        != redacted_headers(&subject.headers)
    {
        return Err(HandlerError::invalid(
            "request.toml header projection differs from the sealed request subject",
        ));
    }
    let artifact_body_hash = request_value
        .get("body_sha256")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if artifact_body_hash != subject.body_sha256 {
        return Err(HandlerError::invalid(
            "request.toml body hash differs from the sealed request subject",
        ));
    }
    let private_body = pending.join("private/request_body");
    match subject.body_sha256.as_deref() {
        Some(expected) => {
            let body = fs::read_to_string(&private_body)?;
            let actual = bloom_tools::sha256_hex(body.as_bytes());
            if actual != expected {
                return Err(HandlerError::invalid(
                    "private/request_body does not match the sealed request body hash",
                ));
            }
        }
        None if private_body.exists() => {
            return Err(HandlerError::invalid(
                "private/request_body exists but the sealed request subject has no body hash",
            ));
        }
        None => {}
    }
    let challenge: NormalizedChallenge = read_json(pending.join("challenge.json"))?;
    if serde_json::to_value(&challenge).map_err(|e| HandlerError::backend(e.to_string()))?
        != serde_json::to_value(&subject.challenge)
            .map_err(|e| HandlerError::backend(e.to_string()))?
    {
        return Err(HandlerError::invalid(
            "challenge.json projection differs from the sealed request subject",
        ));
    }
    Ok(())
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

fn validate_session_state_target(
    challenge: &NormalizedChallenge,
    request_id: &str,
) -> Result<(), HandlerError> {
    if challenge.intent == "session" {
        let session_id = challenge
            .session_id
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| format!("session_{request_id}"));
        session_dir_name(&session_id)?;
    }
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
    dry_run: bool,
) -> Result<(), HandlerError> {
    fs::create_dir_all(dir.join("private"))?;
    let (body_redacted, body_len, body_sha256) = if let Some(body) = &req.body {
        fs::write(dir.join("private/request_body"), body)?;
        (
            true,
            Some(body.len()),
            Some(bloom_tools::sha256_hex(body.as_bytes())),
        )
    } else {
        (false, None, None)
    };
    write_json(
        dir.join("request.toml"),
        &json!({
            "method": req.method,
            "url": req.url.as_str(),
            "wallet": wallet,
            "max_amount_usd": req.max_amount_usd,
            "headers": redacted_headers(&req.headers),
            "body": if body_redacted { serde_json::Value::String("redacted".into()) } else { serde_json::Value::Null },
            "body_redacted": body_redacted,
            "body_len": body_len,
            "body_sha256": body_sha256,
            "dry_run": dry_run,
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
    if req.body.is_some() {
        http.push('\n');
        http.push_str("[request body redacted; see body_sha256 in request.toml]");
        http.push('\n');
    }
    fs::write(dir.join("request.http"), http)?;
    Ok(())
}

#[derive(Debug)]
struct PaidRetryResponse {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn retry_paid_request(
    client: &reqwest::Client,
    request: &ParsedRequest,
    payment_header_name: &str,
    payment_header_value: &str,
) -> Result<PaidRetryResponse, HandlerError> {
    let mut retry = client.request(
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
    let name = HeaderName::from_bytes(payment_header_name.as_bytes()).map_err(|e| {
        HandlerError::backend(format!("invalid paid HTTP credential header name: {e}"))
    })?;
    let value = HeaderValue::from_str(payment_header_value).map_err(|e| {
        HandlerError::backend(format!("invalid paid HTTP credential header value: {e}"))
    })?;
    retry = retry.header(name, value);
    if let Some(body) = &request.body {
        retry = retry.body(body.clone());
    }
    let response = retry
        .send()
        .await
        .map_err(|e| HandlerError::backend(format!("paid HTTP retry failed: {e}")))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|e| HandlerError::backend(format!("read paid HTTP response: {e}")))?
        .to_vec();
    Ok(PaidRetryResponse {
        status,
        headers,
        body,
    })
}

fn write_minted_marker(
    pending: &Path,
    id: &str,
    credential_metadata: &serde_json::Value,
) -> Result<(), HandlerError> {
    fs::create_dir_all(pending.join("private"))?;
    write_json(pending.join("credential.json"), credential_metadata)?;
    write_json(
        pending.join("private/credential_minted.json"),
        &json!({
            "request_id": id,
            "credential_redacted": true,
            "secret_material_in_vfs": false
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn finalize_paid_retry(
    requests_root: &Path,
    pending: &Path,
    id: &str,
    wallet: &str,
    merchant: &str,
    challenge: &NormalizedChallenge,
    requirement: &PaymentRequirement,
    amount_usd: Option<f64>,
    credential_metadata: serde_json::Value,
    retry: Result<PaidRetryResponse, HandlerError>,
) -> Result<String, HandlerError> {
    fs::create_dir_all(pending.join("response"))?;
    write_json(pending.join("credential.json"), &credential_metadata)?;
    let (status, response_headers, response_body, retry_error) = match retry {
        Ok(response) => (response.status, response.headers, response.body, None),
        Err(err) => (
            599,
            HeaderMap::new(),
            format!("{err}\n").into_bytes(),
            Some(err.to_string()),
        ),
    };
    fs::write(pending.join("response/status"), format!("{status}\n"))?;
    write_json(
        pending.join("response/headers.json"),
        &public_headers_to_json(&response_headers),
    )?;
    fs::write(pending.join("response/body"), &response_body)?;
    let sha = bloom_tools::sha256_hex(&response_body);
    fs::write(pending.join("response/body.sha256"), format!("{sha}\n"))?;
    if let Some(error) = &retry_error {
        fs::write(pending.join("error.txt"), format!("{error}\n"))?;
    }
    let receipt_raw = response_headers
        .get("payment-receipt")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| mpp::parse_receipt(h).ok())
        .and_then(|r| serde_json::to_value(r).ok())
        .unwrap_or_else(|| json!({}));
    write_json(
        pending.join("receipt.json"),
        &json!({
            "request_id": id,
            "wallet": wallet,
            "merchant": merchant,
            "amount": requirement.amount,
            "currency": requirement.asset,
            "network": requirement.network,
            "protocol": challenge.protocol,
            "intent": challenge.intent,
            "scheme": requirement.scheme,
            "charge_id": challenge.charge_id,
            "session_id": challenge.session_id,
            "amount_usd": amount_usd,
            "response_status": status,
            "response_sha256": sha,
            "credential_redacted": true,
            "raw": receipt_raw,
        }),
    )?;
    let succeeded = status < 400 && retry_error.is_none();
    write_json(
        pending.join("audit.json"),
        &json!({
            "request_id": id,
            "event": "confirmed_and_retried",
            "response_status": status,
            "paid_retry_succeeded": succeeded,
            "retry_error": retry_error,
            "reads_spent": false,
            "credential_redacted": true,
            "secret_material_in_vfs": false
        }),
    )?;
    let final_state = if succeeded { "sent" } else { "failed" };
    if succeeded && challenge.intent == "session" {
        update_session_state(requests_root, challenge, id, wallet)?;
    }
    fs::write(pending.join("status"), format!("{final_state}\n"))?;
    fs::create_dir_all(requests_root.join(final_state))?;
    let dest = requests_root
        .join(final_state)
        .join(safe_fs_component(id, "request id")?);
    if dest.exists() {
        return Err(HandlerError::backend(format!(
            "request destination already exists for id {id}"
        )));
    }
    fs::rename(pending, &dest)?;
    Ok(final_state.into())
}

fn public_headers_to_json(headers: &HeaderMap) -> serde_json::Value {
    let mut map = std::collections::BTreeMap::new();
    for (name, value) in headers {
        let key = name.as_str().to_ascii_lowercase();
        let rendered = if is_sensitive_response_header(&key) {
            "redacted".to_string()
        } else {
            value.to_str().unwrap_or("<non-utf8>").to_string()
        };
        map.insert(key, rendered);
    }
    json!(map)
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
    is_sensitive_paid_http_header(name)
}

fn is_mpp_probe_marker_header(name: &str, value: &str) -> bool {
    name.eq_ignore_ascii_case("authorization") && value.trim().eq_ignore_ascii_case("Payment")
}

fn is_sensitive_response_header(name: &str) -> bool {
    is_sensitive_paid_http_header(name)
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "www-authenticate" | "payment-required"
        )
}

fn session_dir_name(raw: &str) -> Result<String, HandlerError> {
    safe_fs_component(raw, "paid request session id")
}

fn safe_fs_component(raw: &str, label: &str) -> Result<String, HandlerError> {
    let name = raw.trim();
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || Path::new(name).is_absolute()
    {
        return Err(HandlerError::invalid(format!("invalid {label} '{raw}'")));
    }
    Ok(name.to_string())
}

fn validate_vfs_segments(path: &VfsPath) -> Result<(), HandlerError> {
    for segment in path.segments() {
        safe_fs_component(segment, "VFS path segment")?;
    }
    Ok(())
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
                let name = e.file_name().to_string_lossy().to_string();
                out.push(entry_from_fs_dir_entry(&e, &name, EntryKind::Dir)?);
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
        if name == "private" {
            continue;
        }
        let ty = e.file_type()?;
        out.push(if ty.is_dir() {
            entry_from_fs_dir_entry(&e, &name, EntryKind::Dir)?
        } else if matches!(name.as_str(), "confirm" | "cancel" | "topup" | "close") {
            let mut entry = entry_from_fs_dir_entry(&e, &name, EntryKind::File)?;
            entry.mode = 0o644;
            entry
        } else {
            entry_from_fs_dir_entry(&e, &name, EntryKind::File)?
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn entry_with_optional_fs_modified(
    path: impl AsRef<Path>,
    entry: Entry,
) -> Result<Entry, HandlerError> {
    let Some(modified) = fs_path_modified(path.as_ref())? else {
        return Ok(entry);
    };
    Ok(entry.with_modified(modified))
}
fn new_request_id() -> String {
    static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let n = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("req_{ms}_{n}")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Debug)]
struct PaidHttpExecutionInputs {
    request: ParsedRequest,
    host: String,
    challenge: NormalizedChallenge,
    requirement: PaymentRequirement,
    checks: Vec<PolicyCheck>,
    dry_run: bool,
    policy: Policy,
    policy_snapshot_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MachinePaidHttpExecutionSnapshot {
    schema: String,
    action_id: String,
    wallet: String,
    subject: PaidHttpSealedSubject,
    policy: Policy,
    policy_snapshot_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PaidHttpSealedSubject {
    schema: String,
    request_id: String,
    method: String,
    url: String,
    host: String,
    #[serde(default)]
    max_amount_usd: Option<f64>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body_sha256: Option<String>,
    challenge: NormalizedChallenge,
    selected_requirement: PaymentRequirement,
    #[serde(default)]
    policy_checks: Vec<PolicyCheck>,
    #[serde(default)]
    dry_run: bool,
}

impl PaidHttpSealedSubject {
    fn validate_basic(&self, request_id: &str, wallet: &str) -> Result<(), HandlerError> {
        if self.schema != "bloom.paid_http_subject.v1" {
            return Err(HandlerError::invalid(
                "unsupported paid-http subject schema",
            ));
        }
        if self.request_id != request_id {
            return Err(HandlerError::invalid(
                "sealed subject request_id does not match pending request",
            ));
        }
        if wallet.trim().is_empty() {
            return Err(HandlerError::invalid("sealed subject wallet is empty"));
        }
        Url::parse(&self.url)
            .map_err(|e| HandlerError::invalid(format!("sealed subject URL is invalid: {e}")))?;
        Ok(())
    }

    fn to_request(&self, wallet: &str) -> Result<ParsedRequest, HandlerError> {
        Ok(ParsedRequest {
            method: self.method.clone(),
            url: Url::parse(&self.url).map_err(|e| {
                HandlerError::invalid(format!("sealed subject URL is invalid: {e}"))
            })?,
            wallet: Some(wallet.to_string()),
            max_amount_usd: self.max_amount_usd,
            headers: self.headers.clone(),
            body: None,
        })
    }
}

#[derive(Clone, Copy)]
struct PaidHttpAuthSubject<'a> {
    id: &'a str,
    request: &'a ParsedRequest,
    wallet: &'a str,
    host: &'a str,
    challenge: &'a NormalizedChallenge,
    requirement: &'a PaymentRequirement,
    checks: &'a [PolicyCheck],
    policy: &'a Policy,
    dry_run: bool,
}

fn paid_http_sealed_subject(input: PaidHttpAuthSubject<'_>) -> PaidHttpSealedSubject {
    PaidHttpSealedSubject {
        schema: "bloom.paid_http_subject.v1".into(),
        request_id: input.id.to_string(),
        method: input.request.method.clone(),
        url: input.request.url.as_str().to_string(),
        host: input.host.to_string(),
        max_amount_usd: input.request.max_amount_usd,
        headers: input.request.headers.clone(),
        body_sha256: input
            .request
            .body
            .as_ref()
            .map(|body| bloom_tools::sha256_hex(body.as_bytes())),
        challenge: input.challenge.clone(),
        selected_requirement: input.requirement.clone(),
        policy_checks: input.checks.to_vec(),
        dry_run: input.dry_run,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paid requests run inside the router's audited effect window, so an
    /// unresponsive merchant must be ended by the client, not waited on.
    #[tokio::test]
    async fn paid_http_client_is_bounded_by_its_timeout() {
        // Accept connections and never answer them; only a client-side
        // deadline can complete this request.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _silent_merchant = tokio::spawn(async move {
            let mut accepted = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                accepted.push(stream);
            }
        });

        let error = paid_http_client_with_timeout(Duration::from_millis(250))
            .get(format!("http://{addr}/paid"))
            .send()
            .await
            .expect_err("an unresponsive merchant must not hang the request");
        assert!(error.is_timeout(), "expected a timeout, got {error}");

        assert!(
            PAID_HTTP_REQUEST_TIMEOUT > Duration::ZERO
                && PAID_HTTP_REQUEST_TIMEOUT <= Duration::from_secs(60),
            "the production paid-HTTP bound must stay a real ceiling"
        );
    }

    fn handler() -> (tempfile::TempDir, RequestsHandler) {
        let tmp = tempfile::tempdir().unwrap();
        let handler = RequestsHandler::new_projected(
            tmp.path().join("home"),
            Some("alice".into()),
            crate::test_support::wallet_projection_reader(
                "alice",
                "0x0000000000000000000000000000000000000001",
            ),
        )
        .with_operation_index(Arc::new(VenueLocalTestOperationIndex));
        (tmp, handler)
    }

    fn staged_subject<'a>(
        request: &'a ParsedRequest,
        challenge: &'a NormalizedChallenge,
        requirement: &'a PaymentRequirement,
        checks: &'a [PolicyCheck],
        policy: &'a Policy,
    ) -> PaidHttpAuthSubject<'a> {
        PaidHttpAuthSubject {
            id: "req-machine-snapshot",
            request,
            wallet: "alice",
            host: "merchant.example",
            challenge,
            requirement,
            checks,
            policy,
            dry_run: false,
        }
    }

    #[tokio::test]
    async fn staging_writes_machine_execution_snapshot_without_legacy_auth_artifacts() {
        let (_tmp, handler) = handler();
        handler.ensure_layout().unwrap();
        let pending = handler.req_dir("pending", "req-machine-snapshot");
        fs::create_dir_all(pending.join("private")).unwrap();
        let request =
            parse_request("GET https://merchant.example/resource wallet=alice max_amount_usd=1")
                .unwrap();
        let challenge = normalize_challenge(&HeaderMap::new(), b"{}", &request.url);
        let requirement = PaymentRequirement {
            scheme: Some("exact".into()),
            network: Some("base".into()),
            asset: Some("USDC".into()),
            amount: Some("1".into()),
            pay_to: None,
            resource: None,
            raw: json!({}),
        };
        let checks = Vec::new();
        let policy = Policy::default();

        let action_id = handler
            .stage_auth_entry(staged_subject(
                &request,
                &challenge,
                &requirement,
                &checks,
                &policy,
            ))
            .await
            .unwrap();

        let snapshot: MachinePaidHttpExecutionSnapshot =
            read_json(pending.join("private/execution.json")).unwrap();
        assert_eq!(snapshot.action_id, action_id);
        assert_eq!(snapshot.wallet, "alice");
        assert!(!pending.join("intent_hash").exists());
        assert!(!pending.join("approval.json").exists());
    }

    #[tokio::test]
    async fn confirm_authorization_fails_promptly_without_broker_exact_signing() {
        let (_tmp, handler) = handler();
        let result = handler
            .ensure_sealed_confirm_approval(Path::new("unused"), "req")
            .await;
        assert!(matches!(
            result,
            Err(HandlerError::Unsupported(message))
                if message.contains("Broker exact signing")
        ));
    }

    #[tokio::test]
    async fn unwired_paid_http_signer_rejects_payload_and_hash_signing() {
        let (_tmp, handler) = handler();
        let signer = handler.paid_http_host_signer("alice", "req");
        let facts = PaidHttpSigningFacts::default();
        for intent in [PAID_HTTP_X402_SIGN_INTENT, PAID_HTTP_MPP_SIGN_INTENT] {
            assert!(
                signer
                    .sign_paid_http_payload(intent, "slot", b"payload", [0; 32], &facts)
                    .await
                    .unwrap_err()
                    .contains("Broker exact")
            );
            assert!(
                signer
                    .sign_paid_http_hash(intent, [0; 32], &facts)
                    .await
                    .unwrap_err()
                    .contains("legacy hash-only")
            );
        }
    }

    #[test]
    fn parses_supported_request_forms() {
        let request =
            parse_request("GET https://example.com/a wallet=research max_amount_usd=0.05").unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.wallet.as_deref(), Some("research"));
        assert_eq!(request.max_amount_usd, Some(0.05));

        let request = parse_request(
            "POST https://api.example.com/inference\ncontent-type: application/json\n\n{\"prompt\":\"hi\"}",
        )
        .unwrap();
        assert_eq!(request.headers["content-type"], "application/json");
        assert_eq!(request.body.as_deref(), Some(r#"{"prompt":"hi"}"#));
    }

    #[test]
    fn request_artifacts_preserve_private_body_and_redact_public_projection() {
        let directory = tempfile::tempdir().unwrap();
        let request = parse_request(
            "POST https://api.example.com/inference\ncontent-type: application/json\n\n{\"prompt\":\"hi\"}",
        )
        .unwrap();
        write_request_artifacts(directory.path(), &request, "research", "pending", false).unwrap();
        let stored: serde_json::Value = read_json(directory.path().join("request.toml")).unwrap();
        assert_eq!(stored["body"], "redacted");
        assert_eq!(stored["body_redacted"], true);
        assert_eq!(
            parsed_request_from_dir(directory.path()).unwrap().body,
            request.body
        );
        let public_http = fs::read_to_string(directory.path().join("request.http")).unwrap();
        assert!(!public_http.contains("{\"prompt\":\"hi\"}"));
    }

    #[test]
    fn request_artifacts_redact_sensitive_headers() {
        let directory = tempfile::tempdir().unwrap();
        let request = parse_request(
            "GET https://api.example.com/data\nauthorization: Bearer secret\nx-api-key: key-123\naccept: application/json",
        )
        .unwrap();
        write_request_artifacts(directory.path(), &request, "research", "pending", false).unwrap();
        let stored: serde_json::Value = read_json(directory.path().join("request.toml")).unwrap();
        assert_eq!(stored["headers"]["authorization"], "redacted");
        assert_eq!(stored["headers"]["x-api-key"], "redacted");
        assert_eq!(stored["headers"]["accept"], "application/json");
    }

    #[test]
    fn detects_x402_and_mpp_challenges() {
        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", HeaderValue::from_static("1"));
        let challenge = normalize_challenge(
            &headers,
            b"{\"accepts\":[{\"network\":\"base\",\"asset\":\"USDC\",\"amountUsd\":\"0.04\"}]}",
            &Url::parse("https://merchant.test/").unwrap(),
        );
        assert_eq!(challenge.protocol, "x402");
        let mut headers = HeaderMap::new();
        headers.insert(
            "www-authenticate",
            HeaderValue::from_static(r#"Payment realm="tempo", session"#),
        );
        let challenge =
            normalize_challenge(&headers, b"{}", &Url::parse("https://mpp.test/").unwrap());
        assert_eq!(challenge.protocol, "mpp");
        assert_eq!(challenge.intent, "session");
    }
}
