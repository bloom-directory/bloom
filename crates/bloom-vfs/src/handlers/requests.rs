//! Protocol-neutral paid HTTP request surface.
//!
//! This handler owns the `/requests` VFS tree. Reads only expose durable
//! artefacts; payment/signing boundaries are writable control files.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bloom_auth_api::{
    ApprovalChallenge, AssuranceLevel, CanonicalEnvelope, CanonicalIntentHeader, DaemonGrantTerms,
    ExecutorKind, PetalHost, PolicyCheckClass, PolicyCheckResult, SIGNING_ATTESTATION_SCHEMA_V1,
    SealedAction, SealedApprovalGrant, SignHashRequest, SignedApproval, SigningAttestation,
    petal_identity,
};
use bloom_keystore::Keystore;
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
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::auth::AuthServices;
use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const APPROVAL_FILE: &str = "approval.json";
const APPROVAL_CHALLENGE_FILE: &str = "approval_challenge.json";
const APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;
const PAID_HTTP_X402_SIGN_INTENT: &str = "x402.sign";
const PAID_HTTP_MPP_SIGN_INTENT: &str = "paid-http.mpp.sign";

#[derive(Clone)]
pub struct RequestsHandler {
    root: PathBuf,
    keystore: Keystore,
    default_wallet: Option<String>,
    client: reqwest::Client,
    x402_signer: Arc<dyn X402PaymentSigner>,
    paid_http_rpc_resolver: Arc<dyn PaidHttpChainRpcResolver>,
    auth_services: AuthServices,
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
            x402_signer: Arc::new(HostX402PaymentSigner::new()),
            paid_http_rpc_resolver: Arc::new(EmptyPaidHttpChainRpcResolver),
            auth_services: AuthServices::default(),
        }
    }

    pub fn with_auth_services(mut self, auth_services: AuthServices) -> Self {
        self.auth_services = auth_services;
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
            let policy = self.wallet_policy(&wallet)?;
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
        let Some(writer) = self.auth_services.writer() else {
            return Ok(subject.id.to_string());
        };
        let action_id = writer
            .allocate_action_id("requests", subject.id, subject.wallet, now_ms())
            .await
            .map_err(|e| HandlerError::backend(format!("allocate paid-http action id: {e}")))?;
        let envelope = paid_http_canonical_envelope(subject, &action_id)?;
        let action = paid_http_sealed_action(envelope, subject, now_ms())?;
        let staged = writer
            .stage_action(action, now_ms())
            .await
            .map_err(|e| HandlerError::backend(format!("stage paid-http sealed action: {e}")))?;
        fs::write(
            self.req_dir("pending", subject.id).join("intent_hash"),
            format!("{}\n", staged.intent_hash),
        )?;
        fs::write(
            self.req_dir("pending", subject.id).join("action_id"),
            format!("{action_id}\n"),
        )?;
        Ok(action_id)
    }

    async fn ensure_sealed_confirm_approval(
        &self,
        pending: &Path,
        id: &str,
    ) -> Result<(), HandlerError> {
        if !self.auth_services.is_wired() {
            return Err(HandlerError::Unsupported(
                "request confirm requires Sealed Approval; \
                 auth services are not wired (marker fallback removed)"
                    .into(),
            ));
        }
        if self.active_paid_http_grant(id).await?.is_some() {
            return Ok(());
        }
        if pending.join(APPROVAL_FILE).exists() {
            let approval: SignedApproval = read_json(pending.join(APPROVAL_FILE))?;
            self.auth_services
                .require_approval_verifier()?
                .verify_and_mint_grant(
                    approval,
                    self.auth_services.require_grant_store()?.as_ref(),
                    now_ms(),
                )
                .await
                .map_err(|e| HandlerError::invalid(format!("Sealed Approval rejected: {e}")))?;
            return Ok(());
        }

        let challenge = self.issue_sealed_confirm_challenge(id).await?;
        write_json(pending.join(APPROVAL_CHALLENGE_FILE), &challenge)?;
        Err(HandlerError::PermissionDenied)
    }

    async fn active_paid_http_grant(
        &self,
        request_id: &str,
    ) -> Result<Option<SealedApprovalGrant>, HandlerError> {
        let Some(store) = self.auth_services.grant_store() else {
            return Ok(None);
        };
        let pending = self.req_dir("pending", request_id);
        let request = parsed_request_from_dir(&pending)?;
        let wallet = request
            .wallet
            .as_deref()
            .ok_or_else(|| HandlerError::backend("request.toml missing wallet"))?;
        let action_id = self.request_action_id(request_id).await?;
        store
            .get_active(
                wallet,
                &action_id,
                petal_identity::PETAL_ID_PAID_HTTP,
                petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP,
                now_ms(),
            )
            .await
            .map_err(|e| HandlerError::backend(format!("lookup paid-http grant: {e}")))
    }

    async fn sealed_execution_inputs(
        &self,
        pending: &Path,
        request_id: &str,
    ) -> Result<PaidHttpExecutionInputs, HandlerError> {
        let Some(intent_hash) = fs::read_to_string(pending.join("intent_hash"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        else {
            return Err(HandlerError::invalid(
                "pending paid-http request is missing sealed intent_hash; re-stage the request",
            ));
        };
        let sealed = self
            .auth_services
            .require_store()?
            .sealed_intent(&intent_hash)
            .await
            .map_err(|e| HandlerError::backend(format!("read sealed paid-http action: {e}")))?;
        let action = sealed.action.ok_or_else(|| {
            HandlerError::invalid("sealed paid-http action is missing; re-stage the request")
        })?;
        action
            .validate()
            .map_err(|e| HandlerError::invalid(format!("invalid sealed paid-http action: {e}")))?;
        if action.surface() != "requests"
            || action.petal_id() != petal_identity::PETAL_ID_PAID_HTTP
            || action.petal_digest() != petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP
            || action.envelope.subject_kind != "paid_http"
            || action.envelope.subject_schema != "bloom.paid_http_subject.v1"
        {
            return Err(HandlerError::invalid(
                "sealed action is not a paid-http request confirmation",
            ));
        }
        let subject_bytes = B64_STD
            .decode(&action.envelope.subject_bytes_b64)
            .map_err(|e| HandlerError::invalid(format!("decode sealed paid-http subject: {e}")))?;
        let subject: PaidHttpSealedSubject = serde_json::from_slice(&subject_bytes)
            .map_err(|e| HandlerError::invalid(format!("decode sealed paid-http subject: {e}")))?;
        subject.validate_basic(request_id, action.wallet())?;
        validate_pending_projection_matches_subject(pending, &subject)?;
        let mut request = subject.to_request(action.wallet())?;
        if let Some(body_sha256) = subject.body_sha256.as_deref() {
            let body = fs::read_to_string(pending.join("private/request_body"))?;
            let actual = bloom_tools::sha256_hex(body.as_bytes());
            if actual != body_sha256 {
                return Err(HandlerError::invalid(
                    "private/request_body does not match the sealed request body hash",
                ));
            }
            request.body = Some(body);
        }
        let policy = policy_from_paid_http_snapshot(&action.petal_policy);
        Ok(PaidHttpExecutionInputs {
            request,
            host: subject.host,
            challenge: subject.challenge,
            requirement: subject.selected_requirement,
            checks: subject.policy_checks,
            dry_run: subject.dry_run,
            policy,
            policy_snapshot_digest: action.petal_policy_digest,
        })
    }

    async fn request_action_id(&self, request_id: &str) -> Result<String, HandlerError> {
        let Some(writer) = self.auth_services.writer() else {
            return Ok(request_id.to_string());
        };
        let pending = self.req_dir("pending", request_id);
        let request = parsed_request_from_dir(&pending)?;
        let wallet = request
            .wallet
            .as_deref()
            .ok_or_else(|| HandlerError::backend("request.toml missing wallet"))?;
        writer
            .allocate_action_id("requests", request_id, wallet, now_ms())
            .await
            .map_err(|e| HandlerError::backend(format!("lookup paid-http action id: {e}")))
    }

    async fn consume_paid_http_grant(
        &self,
        request_id: &str,
        wallet: &str,
        intent: &str,
    ) -> Result<SealedApprovalGrant, HandlerError> {
        let action_id = self.request_action_id(request_id).await?;
        let grant = self
            .auth_services
            .require_grant_store()?
            .get_active(
                wallet,
                &action_id,
                petal_identity::PETAL_ID_PAID_HTTP,
                petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP,
                now_ms(),
            )
            .await
            .map_err(|e| HandlerError::backend(format!("lookup paid-http grant: {e}")))?
            .ok_or_else(|| HandlerError::invalid("paid-http grant is not active"))?;
        self.auth_services
            .require_grant_store()?
            .consume_signature(&grant.grant_id, intent, now_ms())
            .await
            .map_err(|e| HandlerError::invalid(format!("consume paid-http grant: {e}")))
    }

    /// Build the paid-HTTP host signing seam for a wallet/action. When a
    /// [`PetalHost`] is wired, signatures flow through it (grant-gated,
    /// attestation-recorded, one allowance consumed atomically). When it is
    /// not wired, a stub is returned that errors if a signature is actually
    /// requested, so misconfiguration surfaces at signing time rather than
    /// silently signing outside a grant.
    fn paid_http_host_signer(&self, wallet: &str, action_id: &str) -> Arc<dyn PaidHttpHostSigner> {
        match self.auth_services.petal_host() {
            Some(host) => Arc::new(PaidHttpPetalHostSigner {
                petal_host: host.clone(),
                wallet: wallet.to_string(),
                action_id: action_id.to_string(),
            }),
            None => Arc::new(UnwiredPaidHttpHostSigner),
        }
    }

    async fn issue_sealed_confirm_challenge(
        &self,
        id: &str,
    ) -> Result<ApprovalChallenge, HandlerError> {
        let now = now_ms();
        let action_id = self.request_action_id(id).await?;
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        self.auth_services
            .require_writer()?
            .issue_challenge(
                "requests",
                &action_id,
                &nonce,
                now.saturating_add(APPROVAL_TTL_MS),
                now,
            )
            .await
            .map(|challenge| {
                // Project the stable local ceremony URL for mounted/Bloom-Machine
                // flows, matching the EVM outbox. The URL token is derived from
                // the (reused-while-unexpired) `server_nonce`, so repeated confirm
                // writes surface the same challenge and the same `ceremony_url`.
                challenge.with_local_ceremony_url()
            })
            .map_err(|e| HandlerError::backend(format!("issue paid-http approval challenge: {e}")))
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
        let live_policy = self.wallet_policy(&wallet)?;
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
            let wallet_address = self
                .keystore
                .info(&wallet)
                .map_err(|e| HandlerError::backend(format!("wallet address unavailable: {e}")))?
                .address;
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
            };
            let result = confirm_with_backend(
                &self.root,
                id,
                data,
                &backend,
                ConfirmBackendOptions {
                    policy_override: Some(&policy),
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
                    ..Default::default()
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
        let wallet_address = self
            .keystore
            .info(&wallet)
            .map_err(|e| HandlerError::backend(format!("wallet address unavailable: {e}")))?
            .address;
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

/// Concrete paid-HTTP host signer: wraps the daemon [`PetalHost`] and turns a
/// protocol adapter's signing request into a grant-gated, attestation-recorded
/// [`PetalHost::sign_hash`] call. Key custody and grant enforcement stay in the
/// runtime; the adapters only ever see the returned signature bytes.
struct PaidHttpPetalHostSigner {
    petal_host: Arc<dyn PetalHost>,
    wallet: String,
    action_id: String,
}

#[async_trait]
impl PaidHttpHostSigner for PaidHttpPetalHostSigner {
    async fn sign_paid_http_hash(
        &self,
        intent: &str,
        signing_hash: [u8; 32],
        facts: &PaidHttpSigningFacts,
    ) -> Result<[u8; 65], String> {
        let hash_hex = format!("0x{}", hex_lower(&signing_hash));
        let attestation =
            paid_http_signing_attestation(intent, &hash_hex, &self.wallet, &self.action_id, facts);
        let sealed = self
            .petal_host
            .sign_hash(
                SignHashRequest {
                    wallet: self.wallet.clone(),
                    action_id: self.action_id.clone(),
                    intent: intent.to_string(),
                    hash_hex,
                },
                &attestation,
                now_ms(),
            )
            .await
            .map_err(|e| format!("paid-http host signing denied: {e}"))?;
        let bytes = B64_STD
            .decode(&sealed.signature_b64)
            .map_err(|e| format!("decode host signature: {e}"))?;
        <[u8; 65]>::try_from(bytes.as_slice())
            .map_err(|_| format!("host signature is {} bytes, expected 65", bytes.len()))
    }
}

/// Stub used when no [`PetalHost`] is wired. It never signs; it fails loudly so
/// a missing host wiring cannot degrade into an unauthorized signing path.
struct UnwiredPaidHttpHostSigner;

#[async_trait]
impl PaidHttpHostSigner for UnwiredPaidHttpHostSigner {
    async fn sign_paid_http_hash(
        &self,
        _intent: &str,
        _signing_hash: [u8; 32],
        _facts: &PaidHttpSigningFacts,
    ) -> Result<[u8; 65], String> {
        Err(
            "paid-http host signing requires a wired PetalHost under a live Sealed Approval grant"
                .to_string(),
        )
    }
}

/// Lowercase hex for a 32-byte hash without pulling an extra dep.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Build the structured [`SigningAttestation`] recorded for every paid-HTTP
/// host signature. Carries only public request/payment facts and digests — no
/// credential material, PRF output, or raw signatures.
fn paid_http_signing_attestation(
    intent: &str,
    signing_hash_hex: &str,
    wallet: &str,
    action_id: &str,
    facts: &PaidHttpSigningFacts,
) -> SigningAttestation {
    let mut map = std::collections::BTreeMap::new();
    let mut put = |k: &str, v: serde_json::Value| {
        map.insert(k.to_string(), v);
    };
    put("facts_schema", json!("bloom.paid_http.signing_facts.v1"));
    put("action_id", json!(action_id));
    put("wallet", json!(wallet));
    put("request_id", json!(facts.request_id));
    put("method", json!(facts.method));
    put("url", json!(facts.url));
    put("host", json!(facts.host));
    put("protocol", json!(facts.protocol));
    put("network", json!(facts.network));
    put("chain_id", json!(facts.chain_id));
    put("asset", json!(facts.asset));
    put("amount", json!(facts.amount));
    put("pay_to", json!(facts.pay_to));
    put("resource", json!(facts.resource));
    put("scheme", json!(facts.scheme));
    put("charge_id", json!(facts.charge_id));
    put("session_id", json!(facts.session_id));
    put("channel_id", json!(facts.channel_id));
    put("signing_hash", json!(signing_hash_hex));
    put(
        "policy_snapshot_digest",
        json!(facts.policy_snapshot_digest),
    );
    put(
        "selected_requirement",
        facts
            .selected_requirement
            .clone()
            .unwrap_or(serde_json::Value::Null),
    );
    SigningAttestation {
        schema: SIGNING_ATTESTATION_SCHEMA_V1.to_string(),
        petal_id: petal_identity::PETAL_ID_PAID_HTTP.to_string(),
        petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.to_string(),
        intent: intent.to_string(),
        facts: map,
    }
}

/// Assemble the secret-free x402 signing facts from the staged request and the
/// selected payment requirement.
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
            [one] if one == "latest" => Ok(Entry::symlink("latest", &self.latest_target())),
            [one] if matches!(one.as_str(), "pending" | "sent" | "failed" | "sessions") => {
                Ok(Entry::dir(one))
            }
            [state, id] if matches!(state.as_str(), "pending" | "sent" | "failed" | "sessions") => {
                Ok(Entry::dir(id))
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
                Ok(Entry::dir("response"))
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
        validate_vfs_segments(path)?;
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

#[derive(Default)]
struct ConfirmBackendOptions<'a> {
    grant_consumer: Option<(&'a RequestsHandler, &'a str, &'a str)>,
    policy_override: Option<&'a Policy>,
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
    let fallback_policy;
    let policy = match options.policy_override {
        Some(policy) => policy,
        None => {
            fallback_policy = backend_policy_for_wallet(root, &wallet).unwrap_or_default();
            &fallback_policy
        }
    };
    let execution = backend
        .prepare(&challenge, &request, &wallet, policy, id)
        .await
        .map_err(HandlerError::backend)?;
    if let Some((handler, grant_wallet, sign_intent)) = options.grant_consumer {
        let _grant = handler
            .consume_paid_http_grant(id, grant_wallet, sign_intent)
            .await?;
    }
    write_minted_marker(&pending, id, &execution.credential_metadata)?;
    let retry = retry_paid_request(
        &reqwest::Client::new(),
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

fn policy_from_paid_http_snapshot(snapshot: &bloom_auth_api::PetalPolicySnapshot) -> Policy {
    let mut policy = Policy::default();
    policy.payments.enabled = true;
    policy.payments.require_plan = true;
    policy.caps.per_tx_usd = snapshot_f64(snapshot, "caps.per_tx_usd");
    policy.caps.per_day_usd = snapshot_f64(snapshot, "caps.per_day_usd");
    policy.caps.require_confirm_above_usd =
        snapshot_f64(snapshot, "caps.require_confirm_above_usd");
    policy.payments.http.per_request_usd = snapshot_f64(snapshot, "payments.http.per_request_usd");
    policy.payments.http.per_day_usd = snapshot_f64(snapshot, "payments.http.per_day_usd");
    policy.payments.sessions.enabled = snapshot
        .caps
        .get("payments.sessions.enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    policy.payments.sessions.max_deposit_usd =
        snapshot_f64(snapshot, "payments.sessions.max_deposit_usd");
    policy.payments.sessions.max_session_spend_usd =
        snapshot_f64(snapshot, "payments.sessions.max_session_spend_usd");
    policy
}

fn snapshot_f64(snapshot: &bloom_auth_api::PetalPolicySnapshot, key: &str) -> Option<f64> {
    snapshot.caps.get(key).and_then(json_number)
}

fn backend_policy_for_wallet(root: &Path, wallet: &str) -> Result<Policy, HandlerError> {
    let raw = fs::read_to_string(root.join("keystore").join(wallet).join("policy.toml"))?;
    toml::from_str(&raw).map_err(|e| HandlerError::backend(e.to_string()))
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
        if name == "private" {
            continue;
        }
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

fn paid_http_canonical_envelope(
    input: PaidHttpAuthSubject<'_>,
    action_id: &str,
) -> Result<CanonicalEnvelope, HandlerError> {
    let network = input
        .requirement
        .network
        .as_deref()
        .or(input.challenge.network.as_deref())
        .unwrap_or("unknown")
        .to_string();
    let subject = serde_json::to_vec(&PaidHttpSealedSubject {
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
    })
    .map_err(|e| HandlerError::backend(e.to_string()))?;
    Ok(CanonicalEnvelope::new(
        CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: input.wallet.to_string(),
            surface: "requests".into(),
            action_id: action_id.to_string(),
            petal_id: petal_identity::PETAL_ID_PAID_HTTP.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network,
            account: "default".into(),
            action_kind: "paid_http_confirm".into(),
            value_movement: true,
            authority_change: false,
            // Must stay deterministic if the same request is re-sealed.
            // TODO(ws-G): commit a real confirm expiry when paid-http staging
            // computes venue terms.
            expires_ms: 0,
        },
        "paid_http",
        "bloom.paid_http_subject.v1",
        subject,
    ))
}

fn paid_http_sealed_action(
    envelope: CanonicalEnvelope,
    input: PaidHttpAuthSubject<'_>,
    now: u64,
) -> Result<SealedAction, HandlerError> {
    let mut extra = std::collections::BTreeMap::new();
    extra.insert(
        "request_id".to_string(),
        serde_json::Value::String(input.id.to_string()),
    );
    extra.insert(
        "protocol".to_string(),
        serde_json::Value::String(input.challenge.protocol.clone()),
    );
    let intent = paid_http_sign_intent(input.challenge);
    let terms = DaemonGrantTerms {
        max_ttl_secs: APPROVAL_TTL_MS / 1_000,
        max_signatures: 1,
        allowed_sign_intents: vec![intent.to_string()],
        assurance: AssuranceLevel::Standard,
        extra,
    };
    let mut snapshot = bloom_auth_api::PetalPolicySnapshot::minimal(&envelope.header);
    snapshot.caps.insert(
        "request_max_amount_usd".to_string(),
        input
            .request
            .max_amount_usd
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    snapshot.caps.insert(
        "caps.per_tx_usd".to_string(),
        input
            .policy
            .caps
            .per_tx_usd
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    snapshot.caps.insert(
        "caps.per_day_usd".to_string(),
        input
            .policy
            .caps
            .per_day_usd
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    snapshot.caps.insert(
        "caps.require_confirm_above_usd".to_string(),
        input
            .policy
            .caps
            .require_confirm_above_usd
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    snapshot.caps.insert(
        "payments.http.per_request_usd".to_string(),
        input
            .policy
            .payments
            .http
            .per_request_usd
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    snapshot.caps.insert(
        "payments.http.per_day_usd".to_string(),
        input
            .policy
            .payments
            .http
            .per_day_usd
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    snapshot.caps.insert(
        "payments.sessions.enabled".to_string(),
        serde_json::Value::Bool(input.policy.payments.sessions.enabled),
    );
    snapshot.caps.insert(
        "payments.sessions.max_deposit_usd".to_string(),
        input
            .policy
            .payments
            .sessions
            .max_deposit_usd
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    snapshot.caps.insert(
        "payments.sessions.max_session_spend_usd".to_string(),
        input
            .policy
            .payments
            .sessions
            .max_session_spend_usd
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    snapshot.config.insert(
        "host".to_string(),
        serde_json::Value::String(input.host.to_string()),
    );
    snapshot.config.insert(
        "selected_requirement".to_string(),
        serde_json::to_value(input.requirement)
            .map_err(|e| HandlerError::backend(e.to_string()))?,
    );
    let checks = input
        .checks
        .iter()
        .map(|check| PolicyCheckResult {
            rule_id: check.rule.clone(),
            rule_class: match check.class {
                bloom_paid_http::PolicyRuleClass::Hard => PolicyCheckClass::Hard,
                bloom_paid_http::PolicyRuleClass::Soft => PolicyCheckClass::StepUp,
                bloom_paid_http::PolicyRuleClass::Informational => PolicyCheckClass::Informational,
            },
            outcome: check.result.clone(),
            message: check.detail.clone(),
            step_up_ceiling: None,
        })
        .collect::<Vec<_>>();
    SealedAction::new(
        envelope,
        render_plan(
            input.request,
            input.wallet,
            input.host,
            Some(input.challenge),
            input.checks,
            input.dry_run,
        ),
        checks,
        terms,
        snapshot,
        now,
    )
    .map_err(|e| HandlerError::backend(format!("seal paid-http action: {e}")))
}

fn paid_http_sign_intent(challenge: &NormalizedChallenge) -> &'static str {
    if challenge.protocol == "mpp" {
        PAID_HTTP_MPP_SIGN_INTENT
    } else {
        PAID_HTTP_X402_SIGN_INTENT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::VfsPath;
    use bloom_auth_api::{
        APPROVAL_CHALLENGE_SCHEMA_V1, APPROVAL_SCHEMA_V1, ApprovalVerifier, AuthApiError,
        AuthEntryRecord, AuthEntryState, AuthStoreView, AuthStoreWriter, GrantStore, NonceState,
        SealedIntentRecord, SignerTransport, WebAuthnAssertionRecord,
    };
    use bloom_paid_mpp::PaymentExecution;
    use bloom_paid_x402::X402PaymentCredential;
    use mpp::client::{PaymentProvider, TempoProvider};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
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

    struct StaticX402Signer {
        calls: Arc<AtomicUsize>,
    }

    struct FailingX402Signer {
        calls: Arc<AtomicUsize>,
    }

    struct ChallengeOnlyWriter;

    struct StaticSealedStore {
        records: Mutex<BTreeMap<String, SealedIntentRecord>>,
    }

    impl StaticSealedStore {
        fn new(record: SealedIntentRecord) -> Self {
            let mut records = BTreeMap::new();
            records.insert(record.intent_hash.clone(), record);
            Self {
                records: Mutex::new(records),
            }
        }
    }

    #[async_trait]
    impl AuthStoreView for StaticSealedStore {
        async fn sealed_intent(
            &self,
            intent_hash: &str,
        ) -> Result<SealedIntentRecord, AuthApiError> {
            self.records
                .lock()
                .map_err(|_| AuthApiError::Store("test sealed store mutex poisoned".into()))?
                .get(intent_hash)
                .cloned()
                .ok_or_else(|| AuthApiError::NotFound(format!("sealed intent {intent_hash}")))
        }
    }

    struct AcceptingVerifier {
        calls: Arc<AtomicUsize>,
    }

    fn request_auth_services(verifier_calls: Arc<AtomicUsize>) -> AuthServices {
        AuthServices::new(
            Some(Arc::new(AcceptingVerifier {
                calls: verifier_calls,
            })),
            None,
            Some(Arc::new(ChallengeOnlyWriter)),
        )
        .with_grant_store(Arc::new(
            bloom_auth::grant_store::InMemoryGrantStore::default(),
        ))
    }

    #[async_trait]
    impl ApprovalVerifier for AcceptingVerifier {
        async fn verify_and_consume(
            &self,
            approval: SignedApproval,
            _now_ms: u64,
        ) -> Result<(), AuthApiError> {
            if approval.surface != "requests" {
                return Err(AuthApiError::Denied("wrong surface".into()));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn verify_and_mint_grant(
            &self,
            approval: SignedApproval,
            grant_store: &dyn GrantStore,
            now_ms: u64,
        ) -> Result<SealedApprovalGrant, AuthApiError> {
            if approval.surface != "requests" {
                return Err(AuthApiError::Denied("wrong surface".into()));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            let envelope = CanonicalEnvelope::new(
                CanonicalIntentHeader {
                    schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
                    wallet: approval.wallet.clone(),
                    surface: approval.surface.clone(),
                    action_id: approval.action_id.clone(),
                    petal_id: approval.petal_id.clone(),
                    petal_digest: approval.petal_digest.clone(),
                    petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
                    executor_kind: ExecutorKind::FirstParty,
                    network: "base".into(),
                    account: "default".into(),
                    action_kind: "paid_http_confirm".into(),
                    value_movement: true,
                    authority_change: false,
                    expires_ms: approval.expiry_ms,
                },
                "paid_http",
                "bloom.paid_http_subject.v1",
                serde_json::to_vec(&json!({
                    "schema": "bloom.paid_http_subject.v1",
                    "test": true,
                }))
                .unwrap(),
            );
            let mut extra = BTreeMap::new();
            extra.insert("test".into(), json!(true));
            let action = SealedAction::new(
                envelope,
                "test paid-http approval".into(),
                Vec::new(),
                DaemonGrantTerms {
                    max_ttl_secs: APPROVAL_TTL_MS / 1_000,
                    max_signatures: 1,
                    allowed_sign_intents: vec![
                        PAID_HTTP_X402_SIGN_INTENT.into(),
                        PAID_HTTP_MPP_SIGN_INTENT.into(),
                    ],
                    assurance: approval.assurance,
                    extra,
                },
                bloom_auth_api::PetalPolicySnapshot {
                    policy_version: approval.policy_version,
                    wallet: approval.wallet.clone(),
                    petal_id: approval.petal_id.clone(),
                    petal_digest: approval.petal_digest.clone(),
                    caps: BTreeMap::new(),
                    hard_rules: Vec::new(),
                    step_up_rules: Vec::new(),
                    config: BTreeMap::new(),
                    budget_state: BTreeMap::new(),
                    session_scope: None,
                },
                now_ms,
            )?;
            grant_store.mint(&action, approval.expiry_ms, now_ms).await
        }
    }

    #[async_trait]
    impl AuthStoreWriter for ChallengeOnlyWriter {
        async fn allocate_action_id(
            &self,
            _surface: &str,
            venue_local_id: &str,
            _wallet: &str,
            _now_ms: u64,
        ) -> Result<String, AuthApiError> {
            Ok(venue_local_id.to_string())
        }

        async fn stage_entry(
            &self,
            envelope: CanonicalEnvelope,
            assurance: AssuranceLevel,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            let intent_hash = envelope.intent_hash()?;
            Ok(AuthEntryRecord {
                surface: envelope.header.surface.clone(),
                action_id: envelope.header.action_id.clone(),
                state: AuthEntryState::Staged,
                intent_hash,
                assurance,
                nonce: None,
                nonce_state: NonceState::Unused,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn stage_action(
            &self,
            action: SealedAction,
            now_ms: u64,
        ) -> Result<AuthEntryRecord, AuthApiError> {
            let intent_hash = action.intent_hash()?;
            Ok(AuthEntryRecord {
                surface: action.envelope.header.surface.clone(),
                action_id: action.envelope.header.action_id.clone(),
                state: AuthEntryState::Staged,
                intent_hash,
                assurance: action.daemon_terms.assurance,
                nonce: None,
                nonce_state: NonceState::Unused,
                reservation_id: None,
                updated_ms: now_ms,
            })
        }

        async fn issue_challenge(
            &self,
            surface: &str,
            action_id: &str,
            _server_nonce: &str,
            _expiry_ms: u64,
            _now_ms: u64,
        ) -> Result<ApprovalChallenge, AuthApiError> {
            // Model the real `AuthStore`, which reuses an existing unexpired
            // challenge's `server_nonce` and `expiry_ms` rather than the freshly
            // generated values the handler passes on each confirm. Stable nonce
            // + expiry are what make the challenge hash and the derived
            // `ceremony_url` identical across repeated confirm writes.
            Ok(ApprovalChallenge {
                schema: APPROVAL_CHALLENGE_SCHEMA_V1.to_string(),
                action_id: action_id.to_string(),
                wallet: "alice".to_string(),
                surface: surface.to_string(),
                petal_id: petal_identity::PETAL_ID_PAID_HTTP.to_string(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.to_string(),
                intent_hash: "abc123".to_string(),
                server_nonce: "reused-server-nonce".to_string(),
                assurance: AssuranceLevel::Standard,
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: 9_999_999_999_999,
                ceremony_url: None,
            })
        }

        async fn issue_review_session(
            &self,
            review_session_id: &str,
            surface: &str,
            action_id: &str,
            expires_ms: u64,
            now_ms: u64,
        ) -> Result<bloom_auth_api::ReviewSessionRecord, AuthApiError> {
            Ok(bloom_auth_api::ReviewSessionRecord {
                review_session_id: review_session_id.to_string(),
                surface: surface.to_string(),
                action_id: action_id.to_string(),
                intent_hash: "abc123".to_string(),
                assurance: AssuranceLevel::Standard,
                expires_ms,
                consumed_ms: None,
                created_ms: now_ms,
            })
        }
    }

    #[async_trait]
    impl X402PaymentSigner for StaticX402Signer {
        async fn sign_x402_payment(
            &self,
            _ctx: &X402SignContext<'_>,
        ) -> Result<X402PaymentCredential, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(X402PaymentCredential {
                header_name: "X-Payment",
                header_value: "signed-x402".into(),
                public_metadata: json!({"test": true}),
            })
        }
    }

    #[async_trait]
    impl X402PaymentSigner for FailingX402Signer {
        async fn sign_x402_payment(
            &self,
            _ctx: &X402SignContext<'_>,
        ) -> Result<X402PaymentCredential, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err("x402 signer unavailable".into())
        }
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
    fn paid_http_canonical_envelope_commits_to_selected_plan() {
        let request = parse_request("GET https://merchant.test/pay wallet=alice").unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"x402Version":1,"accepts":[{"network":"base","asset":"USDC","maxAmountRequired":"1000","payTo":"0x1234"}]}"#,
            &request.url,
        );
        let requirement = challenge.accepts[0].clone();
        let checks: Vec<PolicyCheck> = vec![];
        let policy = Policy::default();
        let env = paid_http_canonical_envelope(
            PaidHttpAuthSubject {
                id: "req_1",
                request: &request,
                wallet: "alice",
                host: "merchant.test",
                challenge: &challenge,
                requirement: &requirement,
                checks: &checks,
                policy: &policy,
                dry_run: false,
            },
            "requests-0001",
        )
        .unwrap();
        assert_eq!(env.header.surface, "requests");
        assert_eq!(env.header.action_id, "requests-0001");
        assert_eq!(env.header.petal_id, petal_identity::PETAL_ID_PAID_HTTP);
        assert_eq!(
            env.header.petal_digest,
            petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP
        );
        assert_eq!(env.header.network, "base");
        assert_eq!(env.subject_kind, "paid_http");
        let hash1 = env.intent_hash().unwrap();

        let mut other_req = requirement;
        other_req.network = Some("polygon".into());
        let other = paid_http_canonical_envelope(
            PaidHttpAuthSubject {
                id: "req_1",
                request: &request,
                wallet: "alice",
                host: "merchant.test",
                challenge: &challenge,
                requirement: &other_req,
                checks: &checks,
                policy: &policy,
                dry_run: false,
            },
            "requests-0001",
        )
        .unwrap();
        assert_ne!(hash1, other.intent_hash().unwrap());
    }

    fn sealed_request_fixture(
        handler: &RequestsHandler,
        id: &str,
        body: Option<&str>,
        sealed_policy: &Policy,
        dry_run: bool,
    ) -> (PathBuf, SealedAction, NormalizedChallenge) {
        let mut request = parse_request("POST https://merchant.test/pay wallet=alice").unwrap();
        request.max_amount_usd = Some(1.0);
        request.body = body.map(str::to_string);
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"x402Version":1,"accepts":[{"network":"base","asset":"USDC","maxAmountRequired":"1","payTo":"0x1234"}]}"#,
            &request.url,
        );
        let requirement = challenge.accepts[0].clone();
        let checks = evaluate_payment_policy(
            sealed_policy,
            PolicyEvalInput {
                host: "merchant.test",
                asset: requirement.asset.as_deref(),
                network: requirement.network.as_deref(),
                intent: &challenge.intent,
                amount_usd: selected_requirement_amount_usd(&challenge, &requirement),
                request_max_amount_usd: request.max_amount_usd,
                spent_24h_usd: 0.0,
            },
        );
        let pending = handler.requests_root().join("pending").join(id);
        fs::create_dir_all(&pending).unwrap();
        write_request_artifacts(&pending, &request, "alice", "pending", dry_run).unwrap();
        write_json(pending.join("challenge.json"), &challenge).unwrap();
        write_json(pending.join("policy_check.json"), &checks).unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        let subject = PaidHttpAuthSubject {
            id,
            request: &request,
            wallet: "alice",
            host: "merchant.test",
            challenge: &challenge,
            requirement: &requirement,
            checks: &checks,
            policy: sealed_policy,
            dry_run,
        };
        let envelope = paid_http_canonical_envelope(subject, id).unwrap();
        let action = paid_http_sealed_action(envelope, subject, now_ms()).unwrap();
        fs::write(
            pending.join("intent_hash"),
            format!("{}\n", action.intent_hash().unwrap()),
        )
        .unwrap();
        (pending, action, challenge)
    }

    fn seal_existing_pending_request(
        pending: &Path,
        id: &str,
        policy: &Policy,
    ) -> SealedIntentRecord {
        let request = parsed_request_from_dir(pending).unwrap();
        let wallet = request.wallet.as_deref().unwrap();
        let host = request.url.host_str().unwrap_or("unknown").to_string();
        let challenge: NormalizedChallenge = read_json(pending.join("challenge.json")).unwrap();
        let checks: Vec<PolicyCheck> = read_json(pending.join("policy_check.json")).unwrap();
        let requirement = select_payment_requirement(&challenge, policy, &host)
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
        let request_value: serde_json::Value = read_json(pending.join("request.toml")).unwrap();
        let dry_run = request_value
            .get("dry_run")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let subject = PaidHttpAuthSubject {
            id,
            request: &request,
            wallet,
            host: &host,
            challenge: &challenge,
            requirement: &requirement,
            checks: &checks,
            policy,
            dry_run,
        };
        let envelope = paid_http_canonical_envelope(subject, id).unwrap();
        let action = paid_http_sealed_action(envelope, subject, now_ms()).unwrap();
        let intent_hash = action.intent_hash().unwrap();
        fs::write(pending.join("intent_hash"), format!("{intent_hash}\n")).unwrap();
        SealedIntentRecord {
            intent_hash,
            envelope: action.envelope.clone(),
            sealed_at_ms: action.created_ms,
            action: Some(action),
        }
    }

    #[tokio::test]
    async fn sealed_request_execution_rejects_projection_drift_and_body_tamper() {
        let f = fixture(Some("alice"));
        let mut sealed_policy = Policy::default();
        sealed_policy.payments.enabled = true;
        sealed_policy.payments.require_plan = true;
        sealed_policy.payments.http.per_request_usd = Some(1.0);
        let (pending, action, challenge) = sealed_request_fixture(
            &f.handler,
            "req_sealed_projection",
            Some("original body"),
            &sealed_policy,
            false,
        );
        let record = SealedIntentRecord {
            intent_hash: action.intent_hash().unwrap(),
            envelope: action.envelope.clone(),
            sealed_at_ms: action.created_ms,
            action: Some(action),
        };
        let handler = f.handler.with_auth_services(
            AuthServices::default().with_store(Arc::new(StaticSealedStore::new(record))),
        );

        let inputs = handler
            .sealed_execution_inputs(&pending, "req_sealed_projection")
            .await
            .unwrap();
        assert_eq!(inputs.request.body.as_deref(), Some("original body"));

        let mut projected_challenge = challenge.clone();
        projected_challenge.amount = Some("1000".into());
        write_json(pending.join("challenge.json"), &projected_challenge).unwrap();
        let err = handler
            .sealed_execution_inputs(&pending, "req_sealed_projection")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("challenge.json projection differs"),
            "{err}"
        );

        write_json(pending.join("challenge.json"), &challenge).unwrap();
        fs::write(pending.join("private/request_body"), "tampered body").unwrap();
        let err = handler
            .sealed_execution_inputs(&pending, "req_sealed_projection")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("private/request_body"), "{err}");
    }

    #[tokio::test]
    async fn sealed_request_execution_requires_sealed_intent_hash() {
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        let (pending, _action, _challenge) =
            sealed_request_fixture(&f.handler, "req_missing_seal", None, &policy, false);
        fs::remove_file(pending.join("intent_hash")).unwrap();

        let err = f
            .handler
            .sealed_execution_inputs(&pending, "req_missing_seal")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing sealed intent_hash"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn sealed_request_execution_uses_sealed_policy_snapshot_when_live_policy_widens() {
        let f = fixture(Some("alice"));
        let mut sealed_policy = Policy::default();
        sealed_policy.payments.enabled = true;
        sealed_policy.payments.require_plan = true;
        sealed_policy.payments.http.per_request_usd = Some(1.0);
        let (pending, action, _challenge) =
            sealed_request_fixture(&f.handler, "req_sealed_policy", None, &sealed_policy, false);
        let mut live_policy = sealed_policy.clone();
        live_policy.payments.http.per_request_usd = Some(1_000.0);
        f.handler
            .keystore
            .write_policy(
                "alice",
                toml::to_string_pretty(&live_policy).unwrap().as_bytes(),
            )
            .unwrap();
        let record = SealedIntentRecord {
            intent_hash: action.intent_hash().unwrap(),
            envelope: action.envelope.clone(),
            sealed_at_ms: action.created_ms,
            action: Some(action),
        };
        let handler = f.handler.with_auth_services(
            AuthServices::default().with_store(Arc::new(StaticSealedStore::new(record))),
        );

        let inputs = handler
            .sealed_execution_inputs(&pending, "req_sealed_policy")
            .await
            .unwrap();
        assert_eq!(inputs.policy.payments.http.per_request_usd, Some(1.0));
        assert_eq!(
            handler
                .wallet_policy("alice")
                .unwrap()
                .payments
                .http
                .per_request_usd,
            Some(1_000.0)
        );
    }

    #[test]
    fn spent_usd_history_converts_mpp_base_units_like_x402() {
        let f = fixture(Some("alice"));
        let sent = f.handler.requests_root().join("sent/req_mpp_paid");
        fs::create_dir_all(&sent).unwrap();
        write_json(
            sent.join("receipt.json"),
            &json!({
                "request_id": "req_mpp_paid",
                "wallet": "alice",
                "merchant": "api.nansen.ai",
                "amount": "10000",
                "currency": "0x20C000000000000000000000b9537d11c60E8b50",
                "network": "tempo",
                "protocol": "mpp",
                "intent": "charge"
            }),
        )
        .unwrap();

        let spent = f.handler.sum_paid_usd_last_24h("alice").unwrap();
        assert!((spent - 0.01).abs() < f64::EPSILON, "{spent}");
    }

    #[test]
    fn spent_usd_history_counts_paid_failed_retries() {
        let f = fixture(Some("alice"));
        let failed = f.handler.requests_root().join("failed/req_paid_failed");
        fs::create_dir_all(&failed).unwrap();
        write_json(
            failed.join("receipt.json"),
            &json!({
                "request_id": "req_paid_failed",
                "wallet": "alice",
                "merchant": "api.example.test",
                "amount_usd": 0.25,
                "currency": "USDC",
                "network": "base",
                "protocol": "x402",
                "intent": "charge",
                "response_status": 500,
                "credential_redacted": true,
                "raw": {"status": "success"}
            }),
        )
        .unwrap();

        let spent = f.handler.sum_paid_usd_last_24h("alice").unwrap();
        assert!((spent - 0.25).abs() < f64::EPSILON, "{spent}");
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

    async fn capture_server(
        status: u16,
        body: &'static [u8],
    ) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let response = format!(
                "HTTP/1.1 {status} OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
        });
        (format!("http://{addr}/resource"), rx)
    }

    #[test]
    fn request_ids_include_collision_disambiguator() {
        let id = new_request_id();
        assert!(id.starts_with("req_"));
        assert!(id.rsplit_once('_').is_some(), "{id}");
    }

    #[tokio::test]
    async fn dry_run_paid_request_cannot_be_confirmed() {
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        let (pending, action, _challenge) =
            sealed_request_fixture(&f.handler, "req_dry_run", None, &policy, true);
        let record = SealedIntentRecord {
            intent_hash: action.intent_hash().unwrap(),
            envelope: action.envelope.clone(),
            sealed_at_ms: action.created_ms,
            action: Some(action),
        };
        let handler = f.handler.with_auth_services(
            AuthServices::default().with_store(Arc::new(StaticSealedStore::new(record))),
        );

        let err = handler
            .write(
                &VfsPath::parse("/pending/req_dry_run/confirm").unwrap(),
                b"confirm",
            )
            .await
            .unwrap_err();
        assert!(pending.exists());
        assert!(err.to_string().contains("dry-run"), "{err}");
    }

    #[tokio::test]
    async fn unpaid_probe_strips_sensitive_payment_headers() {
        let f = fixture(Some("alice"));
        let (url, raw_rx) = capture_server(200, b"ok").await;
        f.handler
            .create_request(
                format!(
                    "GET {url}\nauthorization: Payment\nproxy-authorization: Bearer secret\nx-payment: old\npayment-signature: old\nx-api-key: key\naccept: application/json"
                )
                .as_bytes(),
                false,
            )
            .await
            .unwrap();

        let raw = raw_rx.await.unwrap().to_ascii_lowercase();
        assert!(raw.contains("authorization: payment"), "{raw}");
        assert!(!raw.contains("proxy-authorization:"), "{raw}");
        assert!(!raw.contains("x-payment:"), "{raw}");
        assert!(!raw.contains("payment-signature:"), "{raw}");
        assert!(!raw.contains("x-api-key:"), "{raw}");
        assert!(raw.contains("accept: application/json"), "{raw}");
    }

    #[tokio::test]
    async fn public_response_headers_are_redacted() {
        let f = fixture(Some("alice"));
        let (url, _hits) = mock_server(
            200,
            &[
                ("set-cookie", "sid=secret"),
                ("payment-receipt", "secret-receipt"),
                ("content-type", "application/json"),
            ],
            b"{}",
        )
        .await;
        let id = f
            .handler
            .create_request(format!("GET {url}").as_bytes(), false)
            .await
            .unwrap();
        let headers: serde_json::Value = serde_json::from_slice(
            &f.handler
                .read(&VfsPath::parse(&format!("/sent/{id}/response/headers.json")).unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(headers["set-cookie"], "redacted");
        assert_eq!(headers["payment-receipt"], "redacted");
        assert_eq!(headers["content-type"], "application/json");
    }

    #[tokio::test]
    async fn response_resolves_as_a_directory_via_lookup() {
        let f = fixture(Some("alice"));
        let (url, _hits) = mock_server(200, &[("content-type", "application/json")], b"{}").await;
        let id = f
            .handler
            .create_request(format!("GET {url}").as_bytes(), false)
            .await
            .unwrap();
        // `response` must resolve as a directory, not a 0-byte file — otherwise a
        // mounted client caches it as a file and descending into it is ENOTDIR.
        let entry = f
            .handler
            .lookup(&VfsPath::parse(&format!("/sent/{id}/response")).unwrap())
            .await
            .unwrap();
        assert_eq!(entry.kind, crate::handler::EntryKind::Dir);
        // And a file inside it still resolves as a file.
        let body = f
            .handler
            .lookup(&VfsPath::parse(&format!("/sent/{id}/response/body")).unwrap())
            .await
            .unwrap();
        assert_eq!(body.kind, crate::handler::EntryKind::File);
    }

    #[tokio::test]
    async fn pending_request_listing_advertises_confirm_and_cancel() {
        let f = fixture(Some("alice"));
        let pending = f.handler.requests_root().join("pending/req_ctrl");
        fs::create_dir_all(&pending).unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        write_json(
            pending.join("request.toml"),
            &json!({"method":"GET","url":"http://127.0.0.1:9/pay","wallet":"alice","headers":{},"dry_run":false}),
        )
        .unwrap();

        let entries = f
            .handler
            .list(&VfsPath::parse("/pending/req_ctrl").unwrap())
            .await
            .unwrap();
        for ctrl in ["confirm", "cancel"] {
            let e = entries
                .iter()
                .find(|e| e.name == ctrl)
                .unwrap_or_else(|| panic!("pending listing must advertise {ctrl}"));
            // Control files are writable sinks, not read-only metadata.
            assert!(e.mode & 0o200 != 0, "{ctrl} must be writable");
        }

        // Non-pending states must NOT advertise control files (they can
        // no longer be confirmed or cancelled).
        let sent = f.handler.requests_root().join("sent/req_ctrl");
        fs::create_dir_all(&sent).unwrap();
        fs::write(sent.join("status"), "sent\n").unwrap();
        let sent_entries = f
            .handler
            .list(&VfsPath::parse("/sent/req_ctrl").unwrap())
            .await
            .unwrap();
        assert!(
            !sent_entries
                .iter()
                .any(|e| e.name == "confirm" || e.name == "cancel"),
            "sent request must not advertise control files: {:?}",
            sent_entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn decoded_unsafe_vfs_segments_are_rejected() {
        let f = fixture(Some("alice"));
        let path = VfsPath::root().join("pending").join("bad/seg");
        let err = f.handler.read(&path).await.unwrap_err();
        assert!(err.to_string().contains("invalid"), "{err}");
    }

    #[tokio::test]
    async fn x402_retry_failure_moves_failed_and_does_not_resign() {
        let calls = Arc::new(AtomicUsize::new(0));
        let verify_calls = Arc::new(AtomicUsize::new(0));
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        f.handler
            .keystore
            .write_policy("alice", toml::to_string_pretty(&policy).unwrap().as_bytes())
            .unwrap();
        let auth_services = request_auth_services(verify_calls.clone());
        let handler = f
            .handler
            .with_auth_services(auth_services)
            .with_x402_signer(Arc::new(StaticX402Signer {
                calls: calls.clone(),
            }));
        let pending = handler.requests_root().join("pending/req_retry_fail");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"x402Version":1,"accepts":[{"network":"base","asset":"USDC","maxAmountRequired":"1000"}]}"#,
            &Url::parse("http://127.0.0.1:9/pay").unwrap(),
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
            &json!({"method":"GET","url":"http://127.0.0.1:9/pay","wallet":"alice","headers":{},"dry_run":false}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        let record = seal_existing_pending_request(&pending, "req_retry_fail", &policy);
        let auth_services = handler
            .auth_services
            .clone()
            .with_store(Arc::new(StaticSealedStore::new(record)));
        let handler = handler.with_auth_services(auth_services);

        write_json(
            pending.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "requests".into(),
                action_id: "req_retry_fail".into(),
                intent_hash: "abc123".into(),
                petal_id: petal_identity::PETAL_ID_PAID_HTTP.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                assurance: AssuranceLevel::Standard,
                server_nonce: "nonce".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();
        handler.confirm("req_retry_fail", b"confirm").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            handler
                .requests_root()
                .join("failed/req_retry_fail")
                .exists()
        );
        let err = handler
            .confirm("req_retry_fail", b"confirm")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pending"), "{err}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wired_auth_confirm_ignores_legacy_marker_and_issues_challenge() {
        let calls = Arc::new(AtomicUsize::new(0));
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        f.handler
            .keystore
            .write_policy("alice", toml::to_string_pretty(&policy).unwrap().as_bytes())
            .unwrap();
        let auth_services = AuthServices::new(None, None, Some(Arc::new(ChallengeOnlyWriter)));
        let handler = f
            .handler
            .with_auth_services(auth_services)
            .with_x402_signer(Arc::new(StaticX402Signer {
                calls: calls.clone(),
            }));
        let pending = handler.requests_root().join("pending/req_sealed");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"x402Version":1,"accepts":[{"network":"base","asset":"USDC","maxAmountRequired":"1000"}]}"#,
            &Url::parse("http://127.0.0.1:9/pay").unwrap(),
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
            &json!({"method":"GET","url":"http://127.0.0.1:9/pay","wallet":"alice","headers":{},"dry_run":false}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        let record = seal_existing_pending_request(&pending, "req_sealed", &policy);
        let auth_services = handler
            .auth_services
            .clone()
            .with_store(Arc::new(StaticSealedStore::new(record)));
        let handler = handler.with_auth_services(auth_services);

        persist_request_confirm_approved(handler.root.as_path(), "req_sealed", "alice", "confirm")
            .unwrap();
        let err = handler.confirm("req_sealed", b"confirm").await.unwrap_err();
        assert!(matches!(err, HandlerError::PermissionDenied), "{err}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let challenge: ApprovalChallenge =
            read_json(pending.join(APPROVAL_CHALLENGE_FILE)).unwrap();
        assert_eq!(challenge.surface, "requests");
        assert_eq!(challenge.action_id, "req_sealed");
        assert_eq!(challenge.intent_hash, "abc123");
        // The mounted/Bloom-Machine projection must carry the stable local
        // ceremony URL derived from the challenge `server_nonce`.
        let url = challenge
            .ceremony_url
            .as_deref()
            .expect("approval_challenge.json must include ceremony_url");
        assert_eq!(url, challenge.local_ceremony_url());
        assert!(url.contains(&challenge.ceremony_token()));
        assert!(!url.is_empty());
    }

    #[tokio::test]
    async fn wired_auth_confirm_reuses_ceremony_url_across_retries() {
        let calls = Arc::new(AtomicUsize::new(0));
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        f.handler
            .keystore
            .write_policy("alice", toml::to_string_pretty(&policy).unwrap().as_bytes())
            .unwrap();
        let auth_services = AuthServices::new(None, None, Some(Arc::new(ChallengeOnlyWriter)));
        let handler = f
            .handler
            .with_auth_services(auth_services)
            .with_x402_signer(Arc::new(StaticX402Signer {
                calls: calls.clone(),
            }));
        let pending = handler.requests_root().join("pending/req_reuse");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"x402Version":1,"accepts":[{"network":"base","asset":"USDC","maxAmountRequired":"1000"}]}"#,
            &Url::parse("http://127.0.0.1:9/pay").unwrap(),
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
            &json!({"method":"GET","url":"http://127.0.0.1:9/pay","wallet":"alice","headers":{},"dry_run":false}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        let record = seal_existing_pending_request(&pending, "req_reuse", &policy);
        let auth_services = handler
            .auth_services
            .clone()
            .with_store(Arc::new(StaticSealedStore::new(record)));
        let handler = handler.with_auth_services(auth_services);

        // First confirm stages the challenge and denies.
        let err = handler.confirm("req_reuse", b"confirm").await.unwrap_err();
        assert!(matches!(err, HandlerError::PermissionDenied), "{err}");
        let first: ApprovalChallenge = read_json(pending.join(APPROVAL_CHALLENGE_FILE)).unwrap();

        // Second confirm before expiry must reuse the same nonce and URL.
        let err = handler.confirm("req_reuse", b"confirm").await.unwrap_err();
        assert!(matches!(err, HandlerError::PermissionDenied), "{err}");
        let second: ApprovalChallenge = read_json(pending.join(APPROVAL_CHALLENGE_FILE)).unwrap();

        assert_eq!(first.server_nonce, second.server_nonce);
        assert_eq!(
            first.challenge_hash_hex().unwrap(),
            second.challenge_hash_hex().unwrap()
        );
        assert_eq!(first.ceremony_url, second.ceremony_url);
        assert!(first.ceremony_url.is_some());
        // No signature was produced across the denied retries.
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wired_auth_confirm_accepts_approval_without_legacy_marker() {
        let signer_calls = Arc::new(AtomicUsize::new(0));
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        f.handler
            .keystore
            .write_policy("alice", toml::to_string_pretty(&policy).unwrap().as_bytes())
            .unwrap();
        let auth_services = request_auth_services(verifier_calls.clone());
        let handler = f
            .handler
            .with_auth_services(auth_services)
            .with_x402_signer(Arc::new(StaticX402Signer {
                calls: signer_calls.clone(),
            }));
        let pending = handler.requests_root().join("pending/req_sealed_ok");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"x402Version":1,"accepts":[{"network":"base","asset":"USDC","maxAmountRequired":"1000"}]}"#,
            &Url::parse("http://127.0.0.1:9/pay").unwrap(),
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
            &json!({"method":"GET","url":"http://127.0.0.1:9/pay","wallet":"alice","headers":{},"dry_run":false}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        let record = seal_existing_pending_request(&pending, "req_sealed_ok", &policy);
        let auth_services = handler
            .auth_services
            .clone()
            .with_store(Arc::new(StaticSealedStore::new(record)));
        let handler = handler.with_auth_services(auth_services);
        write_json(
            pending.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "requests".into(),
                action_id: "req_sealed_ok".into(),
                intent_hash: "abc123".into(),
                petal_id: petal_identity::PETAL_ID_PAID_HTTP.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                assurance: AssuranceLevel::Standard,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();

        handler.confirm("req_sealed_ok", b"confirm").await.unwrap();
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 1);
        assert_eq!(signer_calls.load(Ordering::SeqCst), 1);
        assert!(
            handler
                .requests_root()
                .join("failed/req_sealed_ok")
                .exists()
        );
    }

    #[tokio::test]
    async fn x402_signer_failure_does_not_consume_paid_http_grant() {
        let signer_calls = Arc::new(AtomicUsize::new(0));
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        f.handler
            .keystore
            .write_policy("alice", toml::to_string_pretty(&policy).unwrap().as_bytes())
            .unwrap();
        let auth_services = request_auth_services(verifier_calls.clone());
        let handler = f
            .handler
            .with_auth_services(auth_services)
            .with_x402_signer(Arc::new(FailingX402Signer {
                calls: signer_calls.clone(),
            }));
        let pending = handler.requests_root().join("pending/req_signer_fail");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"x402Version":1,"accepts":[{"network":"base","asset":"USDC","maxAmountRequired":"1000"}]}"#,
            &Url::parse("http://127.0.0.1:9/pay").unwrap(),
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
            &json!({"method":"GET","url":"http://127.0.0.1:9/pay","wallet":"alice","headers":{},"dry_run":false}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        let record = seal_existing_pending_request(&pending, "req_signer_fail", &policy);
        let auth_services = handler
            .auth_services
            .clone()
            .with_store(Arc::new(StaticSealedStore::new(record)));
        let handler = handler.with_auth_services(auth_services);
        write_json(
            pending.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "requests".into(),
                action_id: "req_signer_fail".into(),
                intent_hash: "abc123".into(),
                petal_id: petal_identity::PETAL_ID_PAID_HTTP.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                assurance: AssuranceLevel::Standard,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();

        let err = handler
            .confirm("req_signer_fail", b"confirm")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("x402 signer unavailable"), "{err}");
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 1);
        assert_eq!(signer_calls.load(Ordering::SeqCst), 1);
        assert!(
            handler
                .active_paid_http_grant("req_signer_fail")
                .await
                .unwrap()
                .is_some(),
            "failed credential preparation must not consume the grant"
        );
    }

    fn paid_http_test_sealed_action(
        wallet: &str,
        action_id: &str,
        allowed_sign_intents: &[&str],
        max_signatures: u32,
        issued_ms: u64,
    ) -> SealedAction {
        let header = CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: wallet.into(),
            surface: "requests".into(),
            action_id: action_id.into(),
            petal_id: petal_identity::PETAL_ID_PAID_HTTP.into(),
            petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.into(),
            petal_version: petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "base".into(),
            account: "default".into(),
            action_kind: "paid_http_confirm".into(),
            value_movement: true,
            authority_change: false,
            expires_ms: issued_ms.saturating_add(APPROVAL_TTL_MS),
        };
        let envelope = CanonicalEnvelope::new(
            header,
            "paid_http",
            "bloom.paid_http_subject.v1",
            serde_json::to_vec(&json!({"schema":"bloom.paid_http_subject.v1","test":true}))
                .unwrap(),
        );
        let terms = DaemonGrantTerms {
            max_ttl_secs: APPROVAL_TTL_MS / 1_000,
            max_signatures,
            allowed_sign_intents: allowed_sign_intents.iter().map(|s| s.to_string()).collect(),
            assurance: AssuranceLevel::Standard,
            extra: std::collections::BTreeMap::new(),
        };
        let mut snapshot = bloom_auth_api::PetalPolicySnapshot::minimal(&envelope.header);
        snapshot.caps.clear();
        snapshot.config.clear();
        snapshot.budget_state.clear();
        SealedAction::new(
            envelope,
            "plan".into(),
            Vec::new(),
            terms,
            snapshot,
            issued_ms,
        )
        .expect("sealed action")
    }

    /// Build a real `KeystorePetalHost` over a shared grant store so paid-HTTP
    /// host signing exercises the same gate the daemon enforces.
    fn wired_petal_host(
        ks_dir: &Path,
    ) -> (
        Arc<dyn PetalHost>,
        Arc<bloom_auth::grant_store::InMemoryGrantStore>,
        alloy::primitives::Address,
    ) {
        use bloom_auth_api::{DefaultAttestationRegistry, SigningAttestationSchemaRegistry};
        use bloom_keystore::petal_host::KeystorePetalHost;
        use bloom_proto::AuditLog;

        let keystore = Arc::new(Keystore::new(ks_dir.join("keystore")).unwrap());
        keystore.create_local("alice", "pw").unwrap();
        keystore.unlock("alice", "pw").unwrap();
        let address = keystore.info("alice").unwrap().address;
        let grant_store = Arc::new(bloom_auth::grant_store::InMemoryGrantStore::new());
        let registry = Arc::new(DefaultAttestationRegistry::new());
        let audit = Arc::new(AuditLog::open(ks_dir.join("audit.jsonl")).unwrap());
        let grant_dyn: Arc<dyn GrantStore> = grant_store.clone();
        let registry_dyn: Arc<dyn SigningAttestationSchemaRegistry> = registry.clone();
        let host: Arc<dyn PetalHost> = Arc::new(KeystorePetalHost::new(
            keystore,
            grant_dyn,
            registry_dyn,
            audit,
        ));
        (host, grant_store, address)
    }

    #[tokio::test]
    async fn x402_host_signing_is_grant_gated_and_consumes_one_allowance() {
        use bloom_auth_api::GrantStore as _;
        let dir = tempfile::tempdir().unwrap();
        let (petal_host, grant_store, _address) = wired_petal_host(dir.path());
        let signer = PaidHttpPetalHostSigner {
            petal_host,
            wallet: "alice".into(),
            action_id: "act-x402".into(),
        };
        let now = now_ms();
        let action = paid_http_test_sealed_action("alice", "act-x402", &["x402.sign"], 1, now);
        let facts = PaidHttpSigningFacts {
            protocol: "x402".into(),
            request_id: "req-x402".into(),
            method: "GET".into(),
            url: "https://merchant.test/pay".into(),
            host: "merchant.test".into(),
            policy_snapshot_digest: Some(action.petal_policy_digest.clone()),
            ..Default::default()
        };
        let hash = [7u8; 32];

        // (a) No live grant → host signing is denied.
        let err = signer
            .sign_paid_http_hash("x402.sign", hash, &facts)
            .await
            .unwrap_err();
        assert!(err.contains("no live grant"), "unexpected: {err}");

        // Mint a one-shot paid-http grant for this action allowing x402.sign.
        grant_store
            .mint(&action, now.saturating_add(120_000), now)
            .await
            .unwrap();

        // (b) First signature succeeds and returns a 65-byte secp256k1 sig.
        let sig = signer
            .sign_paid_http_hash("x402.sign", hash, &facts)
            .await
            .expect("host signs under a live grant");
        assert_eq!(sig.len(), 65);

        // (c) The one-shot allowance is consumed; replay denies.
        let err = signer
            .sign_paid_http_hash("x402.sign", hash, &facts)
            .await
            .unwrap_err();
        assert!(err.contains("no live grant"), "replay: {err}");
    }

    #[tokio::test]
    async fn x402_host_signing_denies_intent_outside_grant_terms() {
        use bloom_auth_api::GrantStore as _;
        let dir = tempfile::tempdir().unwrap();
        let (petal_host, grant_store, _address) = wired_petal_host(dir.path());
        // Grant allows only the MPP intent, not x402.
        let now = now_ms();
        let action = paid_http_test_sealed_action(
            "alice",
            "act-intent",
            &[PAID_HTTP_MPP_SIGN_INTENT],
            3,
            now,
        );
        grant_store
            .mint(&action, now.saturating_add(120_000), now)
            .await
            .unwrap();
        let signer = PaidHttpPetalHostSigner {
            petal_host,
            wallet: "alice".into(),
            action_id: "act-intent".into(),
        };
        let facts = PaidHttpSigningFacts {
            protocol: "x402".into(),
            request_id: "req-intent".into(),
            method: "GET".into(),
            url: "https://merchant.test/pay".into(),
            host: "merchant.test".into(),
            policy_snapshot_digest: Some(action.petal_policy_digest.clone()),
            ..Default::default()
        };
        let err = signer
            .sign_paid_http_hash("x402.sign", [1u8; 32], &facts)
            .await
            .unwrap_err();
        assert!(
            err.contains("allowed_sign_intents"),
            "intent not in grant terms should deny: {err}"
        );
    }

    #[tokio::test]
    async fn paid_http_host_signing_denies_mismatched_attestation_facts_without_consuming() {
        use bloom_auth_api::GrantStore as _;
        let dir = tempfile::tempdir().unwrap();
        let (petal_host, grant_store, _address) = wired_petal_host(dir.path());
        let now = now_ms();
        let action = paid_http_test_sealed_action("alice", "act-facts", &["x402.sign"], 3, now);
        let grant = grant_store
            .mint(&action, now.saturating_add(120_000), now)
            .await
            .unwrap();
        let facts = PaidHttpSigningFacts {
            protocol: "x402".into(),
            request_id: "req-facts".into(),
            method: "GET".into(),
            url: "https://merchant.test/pay".into(),
            host: "merchant.test".into(),
            policy_snapshot_digest: Some(action.petal_policy_digest.clone()),
            ..Default::default()
        };
        let request = SignHashRequest {
            wallet: "alice".into(),
            action_id: "act-facts".into(),
            intent: "x402.sign".into(),
            hash_hex: format!("0x{}", "1".repeat(64)),
        };

        for (label, mutate) in [
            (
                "wrong action_id",
                Box::new(|att: &mut SigningAttestation| {
                    att.facts.insert("action_id".into(), json!("other-action"));
                }) as Box<dyn Fn(&mut SigningAttestation)>,
            ),
            (
                "wrong signing_hash",
                Box::new(|att: &mut SigningAttestation| {
                    att.facts.insert(
                        "signing_hash".into(),
                        json!(format!("0x{}", "2".repeat(64))),
                    );
                }),
            ),
            (
                "wrong policy digest",
                Box::new(|att: &mut SigningAttestation| {
                    att.facts
                        .insert("policy_snapshot_digest".into(), json!("3".repeat(64)));
                }),
            ),
        ] {
            let mut att = paid_http_signing_attestation(
                "x402.sign",
                &request.hash_hex,
                "alice",
                "act-facts",
                &facts,
            );
            mutate(&mut att);
            let err = petal_host
                .sign_hash(request.clone(), &att, now + 1)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("attestation"), "{label}: {err}");
        }

        let active = grant_store
            .get_active(
                "alice",
                "act-facts",
                petal_identity::PETAL_ID_PAID_HTTP,
                petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP,
                now + 10,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.grant_id, grant.grant_id);
        assert_eq!(active.consumed_signature_count, 0);
    }

    #[tokio::test]
    async fn paid_http_host_signing_denies_wrong_petal_identity_without_consuming() {
        use bloom_auth_api::GrantStore as _;
        let dir = tempfile::tempdir().unwrap();
        let (petal_host, grant_store, _address) = wired_petal_host(dir.path());
        let now = now_ms();
        let action = paid_http_test_sealed_action("alice", "act-petal", &["x402.sign"], 2, now);
        grant_store
            .mint(&action, now.saturating_add(120_000), now)
            .await
            .unwrap();
        let facts = PaidHttpSigningFacts {
            protocol: "x402".into(),
            request_id: "req-petal".into(),
            method: "GET".into(),
            url: "https://merchant.test/pay".into(),
            host: "merchant.test".into(),
            policy_snapshot_digest: Some(action.petal_policy_digest.clone()),
            ..Default::default()
        };
        let request = SignHashRequest {
            wallet: "alice".into(),
            action_id: "act-petal".into(),
            intent: "x402.sign".into(),
            hash_hex: format!("0x{}", "1".repeat(64)),
        };
        let base = paid_http_signing_attestation(
            "x402.sign",
            &request.hash_hex,
            "alice",
            "act-petal",
            &facts,
        );
        let mut wrong_id = base.clone();
        wrong_id.petal_id = petal_identity::PETAL_ID_EVM_WALLET.into();
        let err = petal_host
            .sign_hash(request.clone(), &wrong_id, now + 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not allowed"), "{err}");

        let mut wrong_digest = base;
        wrong_digest.petal_digest = petal_identity::PLACEHOLDER_DIGEST_EVM_WALLET.into();
        let err = petal_host
            .sign_hash(request, &wrong_digest, now + 2)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no live grant"), "{err}");

        let active = grant_store
            .get_active(
                "alice",
                "act-petal",
                petal_identity::PETAL_ID_PAID_HTTP,
                petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP,
                now + 10,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.consumed_signature_count, 0);
    }

    #[tokio::test]
    async fn unwired_paid_http_host_signer_refuses_to_sign() {
        let signer = UnwiredPaidHttpHostSigner;
        let facts = PaidHttpSigningFacts::default();
        let err = signer
            .sign_paid_http_hash("x402.sign", [0u8; 32], &facts)
            .await
            .unwrap_err();
        assert!(err.contains("requires a wired PetalHost"), "{err}");
    }

    #[tokio::test]
    async fn invalid_confirm_text_does_not_consume_sealed_approval() {
        let signer_calls = Arc::new(AtomicUsize::new(0));
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        f.handler
            .keystore
            .write_policy("alice", toml::to_string_pretty(&policy).unwrap().as_bytes())
            .unwrap();
        let auth_services = request_auth_services(verifier_calls.clone());
        let handler = f
            .handler
            .with_auth_services(auth_services)
            .with_x402_signer(Arc::new(StaticX402Signer {
                calls: signer_calls.clone(),
            }));
        let pending = handler.requests_root().join("pending/req_bad_confirm");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"x402Version":1,"accepts":[{"network":"base","asset":"USDC"}]}"#,
            &Url::parse("http://127.0.0.1:9/pay").unwrap(),
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
            &json!({"method":"GET","url":"http://127.0.0.1:9/pay","wallet":"alice","headers":{},"dry_run":false}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        let record = seal_existing_pending_request(&pending, "req_bad_confirm", &policy);
        let auth_services = handler
            .auth_services
            .clone()
            .with_store(Arc::new(StaticSealedStore::new(record)));
        let handler = handler.with_auth_services(auth_services);
        write_json(
            pending.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "requests".into(),
                action_id: "req_bad_confirm".into(),
                intent_hash: "abc123".into(),
                petal_id: petal_identity::PETAL_ID_PAID_HTTP.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                assurance: AssuranceLevel::Standard,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();

        let err = handler
            .confirm("req_bad_confirm", b"not-confirm")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("confirm accepts"), "{err}");
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 0);
        assert_eq!(signer_calls.load(Ordering::SeqCst), 0);
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
        write_request_artifacts(dir.path(), &req, "research", "pending", false).unwrap();

        let stored: serde_json::Value = read_json(dir.path().join("request.toml")).unwrap();
        assert_eq!(stored["body"], "redacted");
        assert_eq!(stored["body_redacted"], true);
        let reloaded = parsed_request_from_dir(dir.path()).unwrap();
        assert_eq!(reloaded.body.as_deref(), Some(r#"{"prompt":"hi"}"#));

        let http = fs::read_to_string(dir.path().join("request.http")).unwrap();
        assert!(http.contains("content-type: application/json\n\n"));
        assert!(!http.contains("{\"prompt\":\"hi\"}"));
        assert!(http.contains("request body redacted"));
    }

    #[test]
    fn request_artifacts_redact_sensitive_headers() {
        let dir = tempfile::tempdir().unwrap();
        let req = parse_request(
            "GET https://api.example.com/data\nauthorization: Bearer secret\nx-api-key: key-123\naccept: application/json",
        )
        .unwrap();
        write_request_artifacts(dir.path(), &req, "research", "pending", false).unwrap();

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

        async fn prepare(
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
                header_name: "Authorization",
                header_value: "Payment test".into(),
            })
        }
    }

    #[tokio::test]
    async fn mpp_confirm_redacts_credentials_and_updates_session_state() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("requests/pending/req_1");
        fs::create_dir_all(&pending).unwrap();
        let (url, _hits) = mock_server(
            200,
            &[("payment-receipt", r#"{"status":"success"}"#)],
            b"paid response\n",
        )
        .await;
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Session","network":"tempo","asset":"pathUSD","session":{"id":"sess_1","voucherAmount":"0.10","voucherAmountUsd":0.10,"depositAmount":"1.00","depositAmountUsd":1.00}}"#,
            &Url::parse(&url).unwrap(),
        );
        write_json(pending.join("challenge.json"), &challenge).unwrap();
        let payment = challenge.payment_method();
        write_json(pending.join("payment_method.json"), &payment).unwrap();
        let empty_checks: Vec<PolicyCheck> = vec![];
        write_json(pending.join("policy_check.json"), &empty_checks).unwrap();
        write_json(
            pending.join("request.toml"),
            &json!({"method":"GET","url":url,"wallet":"alice","headers":{}}),
        )
        .unwrap();
        fs::write(pending.join("request.http"), "GET https://mpp.test/data\n").unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();

        let result = confirm_with_backend(
            dir.path(),
            "req_1",
            b"confirm",
            &StaticMppTestBackend,
            ConfirmBackendOptions::default(),
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
            class: bloom_paid_http::PolicyRuleClass::Hard,
            detail: "wallet policy has not enabled paid HTTP".into(),
        }];

        let err = confirm_with_backend(
            dir.path(),
            "req_policy",
            b"confirm",
            &StaticMppTestBackend,
            ConfirmBackendOptions {
                policy_override: Some(&Policy::default()),
                checks_override: Some(current_checks),
                sentinel_override: Some("approve-spend"),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("hard payment policy denial"));
    }

    #[tokio::test]
    async fn mpp_confirm_rejects_unsafe_session_id_before_minting() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("requests/pending/req_escape");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Session","network":"tempo","asset":"pathUSD","session":{"id":"../escape","voucherAmount":"0.10","voucherAmountUsd":0.10,"depositAmount":"1.00","depositAmountUsd":1.00}}"#,
            &Url::parse("https://mpp.test/data").unwrap(),
        );
        write_json(pending.join("challenge.json"), &challenge).unwrap();
        let empty_checks: Vec<PolicyCheck> = vec![];
        write_json(pending.join("policy_check.json"), &empty_checks).unwrap();
        write_json(
            pending.join("request.toml"),
            &json!({"method":"GET","url":"https://mpp.test/data","wallet":"alice","headers":{}}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();

        let err = confirm_with_backend(
            dir.path(),
            "req_escape",
            b"confirm",
            &StaticMppTestBackend,
            ConfirmBackendOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid paid request session id"));
        assert!(!pending.join("private/credential_minted.json").exists());
    }

    /// Backend double that records the request/challenge/wallet it is prepared
    /// with, so a test can prove which bytes reached execution.
    #[derive(Clone, Default)]
    struct CapturingMppBackend {
        seen: Arc<std::sync::Mutex<Option<(String, String, String)>>>,
    }

    #[async_trait]
    impl PaymentBackend for CapturingMppBackend {
        fn name(&self) -> &'static str {
            "capturing_mpp_test_double"
        }

        async fn prepare(
            &self,
            challenge: &NormalizedChallenge,
            request: &ParsedRequest,
            wallet: &str,
            _policy: &Policy,
            _request_id: &str,
        ) -> Result<PaymentExecution, String> {
            *self.seen.lock().unwrap() = Some((
                challenge.merchant.clone(),
                request.url.to_string(),
                wallet.to_string(),
            ));
            Ok(PaymentExecution {
                credential_metadata: json!({
                    "redacted": true,
                    "backend": self.name(),
                    "secret_material_in_vfs": false,
                    "raw_authorization_stored": false,
                    "raw_signed_payload_stored": false
                }),
                header_name: "Authorization",
                header_value: "Payment test".into(),
            })
        }
    }

    /// Regression: once the MPP path has validated its sealed action, the
    /// backend must execute against the sealed request/challenge/requirement,
    /// not a `challenge.json` / `request.toml` projection an attacker tampered
    /// with after sealing.
    #[tokio::test]
    async fn mpp_confirm_uses_sealed_execution_not_tampered_projection() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("requests/pending/req_sealed_exec");
        fs::create_dir_all(&pending).unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();

        // The sealed retry target the caller validated.
        let (sealed_url, sealed_hits) = mock_server(
            200,
            &[("payment-receipt", r#"{"status":"success"}"#)],
            b"sealed paid response\n",
        )
        .await;
        // A second server that must NEVER be contacted (the tampered target).
        let (tampered_url, tampered_hits) = mock_server(200, &[], b"tampered response\n").await;

        let sealed_challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Charge","network":"tempo","asset":"pathUSD","amount":"0.10","amountUsd":0.10}"#,
            &Url::parse(&sealed_url).unwrap(),
        );
        let sealed_request = ParsedRequest {
            method: "GET".into(),
            url: Url::parse(&sealed_url).unwrap(),
            wallet: Some("sealed-wallet".into()),
            max_amount_usd: None,
            headers: BTreeMap::new(),
            body: None,
        };
        let sealed_requirement = PaymentRequirement {
            scheme: Some("exact".into()),
            network: Some("tempo".into()),
            asset: Some("pathUSD".into()),
            amount: Some("0.10".into()),
            pay_to: None,
            resource: Some(sealed_url.clone()),
            raw: json!({"scheme": "exact"}),
        };

        // Tamper the mutable pending projection after sealing: a different
        // merchant/URL/wallet that would divert the payment if it were read.
        let tampered_challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Charge","network":"tempo","asset":"pathUSD","amount":"9.99","amountUsd":9.99}"#,
            &Url::parse(&tampered_url).unwrap(),
        );
        write_json(pending.join("challenge.json"), &tampered_challenge).unwrap();
        write_json(
            pending.join("request.toml"),
            &json!({"method":"GET","url":tampered_url,"wallet":"tamper-wallet","headers":{}}),
        )
        .unwrap();

        let backend = CapturingMppBackend::default();
        let result = confirm_with_backend(
            dir.path(),
            "req_sealed_exec",
            b"confirm",
            &backend,
            ConfirmBackendOptions {
                checks_override: Some(vec![]),
                sealed_execution: Some(ConfirmExecutionInputs {
                    request: &sealed_request,
                    challenge: &sealed_challenge,
                    requirement: &sealed_requirement,
                    wallet: "sealed-wallet",
                    dry_run: false,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(result.final_state, "sent");

        // The backend saw the sealed request/challenge/wallet, never the
        // tampered projection.
        let (merchant, url, wallet) = backend.seen.lock().unwrap().clone().unwrap();
        let sealed_host = Url::parse(&sealed_url)
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        assert_eq!(merchant, sealed_host);
        assert_eq!(url, sealed_url);
        assert_eq!(wallet, "sealed-wallet");

        // The sealed retry target was contacted; the tampered one was not.
        assert_eq!(sealed_hits.load(Ordering::SeqCst), 1);
        assert_eq!(tampered_hits.load(Ordering::SeqCst), 0);
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

        async fn prepare(
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
                header_name: "Authorization",
                header_value: "Payment test".into(),
            })
        }
    }

    struct PrepareFailingMppTestBackend;

    #[async_trait]
    impl PaymentBackend for PrepareFailingMppTestBackend {
        fn name(&self) -> &'static str {
            "mpp_tempo_test_double_prepare_failing"
        }

        async fn prepare(
            &self,
            _challenge: &NormalizedChallenge,
            _request: &ParsedRequest,
            _wallet: &str,
            _policy: &Policy,
            _request_id: &str,
        ) -> Result<PaymentExecution, String> {
            Err("MPP credential preparation unavailable".into())
        }
    }

    #[tokio::test]
    async fn mpp_prepare_failure_does_not_consume_paid_http_grant() {
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let f = fixture(Some("alice"));
        let mut policy = Policy::default();
        policy.payments.enabled = true;
        policy.payments.require_plan = true;
        f.handler
            .keystore
            .write_policy("alice", toml::to_string_pretty(&policy).unwrap().as_bytes())
            .unwrap();
        let handler = f
            .handler
            .with_auth_services(request_auth_services(verifier_calls.clone()));
        let pending = handler.requests_root().join("pending/req_mpp_prepare_fail");
        fs::create_dir_all(&pending).unwrap();
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Charge","network":"tempo","asset":"pathUSD","amount":"0.10","amountUsd":0.10}"#,
            &Url::parse("https://mpp.test/data").unwrap(),
        );
        write_json(pending.join("challenge.json"), &challenge).unwrap();
        let empty_checks: Vec<PolicyCheck> = vec![];
        write_json(pending.join("policy_check.json"), &empty_checks).unwrap();
        write_json(
            pending.join("request.toml"),
            &json!({"method":"GET","url":"https://mpp.test/data","wallet":"alice","headers":{}}),
        )
        .unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();
        write_json(
            pending.join(APPROVAL_FILE),
            &SignedApproval {
                schema: APPROVAL_SCHEMA_V1.into(),
                wallet: "alice".into(),
                surface: "requests".into(),
                action_id: "req_mpp_prepare_fail".into(),
                intent_hash: "abc123".into(),
                petal_id: petal_identity::PETAL_ID_PAID_HTTP.into(),
                petal_digest: petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                assurance: AssuranceLevel::Standard,
                server_nonce: "nonce-1".into(),
                daemon_terms_digest: "1".repeat(64),
                petal_policy_digest: "2".repeat(64),
                policy_version: 0,
                expiry_ms: now_ms() + 60_000,
                signer_transport: SignerTransport::BrowserWebauthn,
                credential_id: "cred-1".into(),
                review_session_id: None,
                webauthn_assertion: WebAuthnAssertionRecord {
                    credential_id: "cred-1".into(),
                    authenticator_data_b64: "AA".into(),
                    client_data_json_b64: "e30".into(),
                    signature_b64: "AA".into(),
                    user_handle_b64: None,
                },
            },
        )
        .unwrap();
        handler
            .ensure_sealed_confirm_approval(&pending, "req_mpp_prepare_fail")
            .await
            .unwrap();

        let err = confirm_with_backend(
            handler.root.as_path(),
            "req_mpp_prepare_fail",
            b"confirm",
            &PrepareFailingMppTestBackend,
            ConfirmBackendOptions {
                grant_consumer: Some((&handler, "alice", PAID_HTTP_MPP_SIGN_INTENT)),
                policy_override: Some(&policy),
                checks_override: Some(Vec::new()),
                sentinel_override: Some("override"),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("MPP credential preparation unavailable"),
            "{err}"
        );
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 1);
        assert!(
            handler
                .active_paid_http_grant("req_mpp_prepare_fail")
                .await
                .unwrap()
                .is_some(),
            "failed MPP credential preparation must not consume the grant"
        );
    }

    #[tokio::test]
    async fn mpp_confirm_failed_paid_retry_routes_to_failed_and_skips_session_state() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("requests/pending/req_fail");
        fs::create_dir_all(&pending).unwrap();
        let (url, _hits) = mock_server(500, &[], b"merchant error\n").await;
        let challenge = normalize_challenge(
            &HeaderMap::new(),
            br#"{"protocol":"tempo-mpp","type":"Session","network":"tempo","asset":"pathUSD","session":{"id":"sess_fail","voucherAmount":"0.10","voucherAmountUsd":0.10,"depositAmount":"1.00","depositAmountUsd":1.00}}"#,
            &Url::parse(&url).unwrap(),
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
            &json!({"method":"GET","url":url,"wallet":"alice","headers":{}}),
        )
        .unwrap();
        fs::write(pending.join("request.http"), "GET https://mpp.test/data\n").unwrap();
        fs::write(pending.join("status"), "pending\n").unwrap();

        let result = confirm_with_backend(
            dir.path(),
            "req_fail",
            b"confirm",
            &FailingMppTestBackend,
            ConfirmBackendOptions::default(),
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

    struct FixedTempoRpcResolver;

    impl PaidHttpChainRpcResolver for FixedTempoRpcResolver {
        fn http_rpc_urls_for_chain_id(&self, chain_id: u64) -> Vec<String> {
            if chain_id == 42431 {
                vec!["https://rpc.example.com".into()]
            } else {
                Vec::new()
            }
        }
    }

    fn zero_amount_tempo_charge_challenge() -> NormalizedChallenge {
        let request = mpp::Base64UrlJson::from_value(&json!({
            "amount": "0",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": { "chainId": 42431 }
        }))
        .unwrap();
        let challenge = mpp::PaymentChallenge::new(
            "challenge-mpp-host",
            "merchant.test",
            "tempo",
            "charge",
            request,
        );
        let header = mpp::format_www_authenticate(&challenge).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&header).unwrap(),
        );
        normalize_challenge(
            &headers,
            b"",
            &Url::parse("https://merchant.test/pay").unwrap(),
        )
    }

    #[tokio::test]
    async fn mpp_host_signing_is_grant_gated_and_consumes_one_allowance() {
        use bloom_auth_api::GrantStore as _;
        let dir = tempfile::tempdir().unwrap();
        let (petal_host, grant_store, address) = wired_petal_host(dir.path());
        let now = now_ms();
        let action =
            paid_http_test_sealed_action("alice", "act-mpp", &[PAID_HTTP_MPP_SIGN_INTENT], 1, now);
        let host_signer: Arc<dyn PaidHttpHostSigner> = Arc::new(PaidHttpPetalHostSigner {
            petal_host,
            wallet: "alice".into(),
            action_id: "act-mpp".into(),
        });
        let backend = RealMppBackend::new(
            reqwest::Client::new(),
            Arc::new(FixedTempoRpcResolver),
            address,
            host_signer,
            PaidHttpSigningFacts {
                protocol: "mpp".into(),
                request_id: "req_mpp_host".into(),
                method: "GET".into(),
                url: "https://merchant.test/pay".into(),
                host: "merchant.test".into(),
                policy_snapshot_digest: Some(action.petal_policy_digest.clone()),
                ..Default::default()
            },
        );
        let challenge = zero_amount_tempo_charge_challenge();
        let request = parse_request("GET https://merchant.test/pay wallet=alice").unwrap();

        let err = match backend
            .prepare(
                &challenge,
                &request,
                "alice",
                &Policy::default(),
                "req_mpp_host",
            )
            .await
        {
            Ok(_) => panic!("MPP host signing unexpectedly succeeded without a grant"),
            Err(err) => err,
        };
        assert!(err.contains("no live grant"), "no-grant error: {err}");

        grant_store
            .mint(&action, now.saturating_add(120_000), now)
            .await
            .unwrap();

        let execution = backend
            .prepare(
                &challenge,
                &request,
                "alice",
                &Policy::default(),
                "req_mpp_host",
            )
            .await
            .expect("MPP host signer should mint a proof credential under a live grant");
        assert_eq!(execution.header_name, "Authorization");
        assert!(execution.header_value.starts_with("Payment "));
        assert_eq!(
            execution.credential_metadata["secret_material_in_vfs"],
            false
        );

        let err = match backend
            .prepare(
                &challenge,
                &request,
                "alice",
                &Policy::default(),
                "req_mpp_host",
            )
            .await
        {
            Ok(_) => panic!("MPP host signing unexpectedly replayed a one-shot grant"),
            Err(err) => err,
        };
        assert!(err.contains("no live grant"), "replay error: {err}");
    }

    #[tokio::test]
    async fn mpp_host_signing_denies_intent_outside_grant_terms() {
        use bloom_auth_api::GrantStore as _;
        let dir = tempfile::tempdir().unwrap();
        let (petal_host, grant_store, address) = wired_petal_host(dir.path());
        let now = now_ms();
        let action = paid_http_test_sealed_action("alice", "act-mpp-wrong", &["x402.sign"], 1, now);
        grant_store
            .mint(&action, now.saturating_add(120_000), now)
            .await
            .unwrap();
        let host_signer: Arc<dyn PaidHttpHostSigner> = Arc::new(PaidHttpPetalHostSigner {
            petal_host,
            wallet: "alice".into(),
            action_id: "act-mpp-wrong".into(),
        });
        let backend = RealMppBackend::new(
            reqwest::Client::new(),
            Arc::new(FixedTempoRpcResolver),
            address,
            host_signer,
            PaidHttpSigningFacts {
                protocol: "mpp".into(),
                request_id: "req_mpp_wrong_intent".into(),
                method: "GET".into(),
                url: "https://merchant.test/pay".into(),
                host: "merchant.test".into(),
                policy_snapshot_digest: Some(action.petal_policy_digest.clone()),
                ..Default::default()
            },
        );
        let challenge = zero_amount_tempo_charge_challenge();
        let request = parse_request("GET https://merchant.test/pay wallet=alice").unwrap();

        let err = match backend
            .prepare(
                &challenge,
                &request,
                "alice",
                &Policy::default(),
                "req_mpp_wrong_intent",
            )
            .await
        {
            Ok(_) => panic!("MPP host signing unexpectedly used an x402-only grant"),
            Err(err) => err,
        };
        assert!(
            err.contains("allowed_sign_intents"),
            "wrong MPP intent should deny: {err}"
        );
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
