//! Daemon-owned Sealed Approval ceremony HTTP server (Interaction Mode 3).
//!
//! `bloom serve` binds this long-running loopback server on
//! `127.0.0.1:LOCAL_CEREMONY_PORT`. It serves the `ceremony_url` that
//! `approval_challenge.json` advertises for mounted-VFS approvals. Unlike the
//! foreground passkey ceremony (`bloom-keystore::passkey`), this server:
//!
//! - never opens a browser — a deliberate client opens the URL;
//! - is long-lived and multiplexes every pending challenge by URL token;
//! - resolves a token to a stored challenge by recomputing the derivation from
//!   `server_nonce` (see [`AuthStoreView::resolve_ceremony_token`]);
//! - renders the daemon-produced sealed-action plan (never a mutable VFS
//!   projection);
//! - receives the WebAuthn assertion **and** PRF output over the trusted local
//!   channel, keeps PRF output in daemon memory only, verifies the approval,
//!   mints the in-memory grant, caches the decrypted signer, and — per the
//!   user's `grant` vs `grant + execute` choice — optionally executes.
//!
//! This endpoint serves Sealed Approval challenges only. It exposes no
//! registration or generic wallet-unlock route; those remain foreground
//! keystore ceremonies. The two flows share lower-level WebAuthn/PRF helpers in
//! `bloom-keystore`, not this HTTP surface.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use bloom_auth_api::{
    ApprovalChallenge, AssuranceLevel, CeremonyTokenResolution, LOCAL_CEREMONY_PORT, SealedAction,
    SignerTransport, UnsignedApproval, WebAuthnAssertionRecord,
};
use serde::Deserialize;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::Daemon;

mod wallet_registration;

const CEREMONY_HTML: &str = include_str!("sealed_ceremony.html");

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Deterministic review-session id for a hardened challenge. Mirrors the
/// foreground CLI derivation so the same challenge maps to the same session.
fn sealed_review_session_id(challenge: &ApprovalChallenge) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.review_session.v1");
    hasher.update(challenge.surface.as_bytes());
    hasher.update(&[0]);
    hasher.update(challenge.action_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(challenge.intent_hash.as_bytes());
    hasher.update(&[0]);
    hasher.update(challenge.server_nonce.as_bytes());
    format!("review-{}", hasher.finalize().to_hex())
}

#[derive(Clone)]
struct CeremonyState {
    daemon: Daemon,
}

/// Handle to the running ceremony server; mirrors `BackgroundTasks`.
pub struct CeremonyServer {
    shutdown: Arc<Notify>,
    handle: Option<JoinHandle<()>>,
    registration: Option<Arc<dyn bloom_auth_api::WalletRegistrationCoordinator>>,
}

impl CeremonyServer {
    /// Signal graceful shutdown and wait for the server task to exit.
    pub async fn shutdown(mut self) {
        if let Some(coordinator) = self.registration.take() {
            coordinator.mark_listener_unbound();
        }
        self.shutdown.notify_waiters();
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
    }
}

impl Drop for CeremonyServer {
    fn drop(&mut self) {
        if let Some(coordinator) = self.registration.take() {
            coordinator.mark_listener_unbound();
        }
        self.shutdown.notify_waiters();
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

/// Bind and spawn the daemon ceremony server on `127.0.0.1:LOCAL_CEREMONY_PORT`.
pub async fn spawn(daemon: &Daemon) -> std::io::Result<CeremonyServer> {
    let shutdown = Arc::new(Notify::new());
    let state = CeremonyState {
        daemon: daemon.clone(),
    };
    let app = router(state);
    let addr = format!("127.0.0.1:{LOCAL_CEREMONY_PORT}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(addr = %addr, "ceremony.server.listening");
    // Arm the wallet-registration coordinator now that this process owns
    // the one loopback ceremony listener — `stage()` fails closed until
    // this is called, which is the fix for the historical port-18734
    // double-bind: no VFS/IPC registration path can reach a second bind.
    //
    // Restart reconciliation runs here, not in `Daemon::from_home_inner`:
    // the successful bind above is the actual proof that no other process
    // (a live `bloom serve`, or another command-scoped fallback ceremony)
    // currently owns registration state, so any persisted non-terminal
    // session really is orphaned. A one-shot CLI command that never reaches
    // this point never reconciles anything.
    let registration = daemon.auth_services.registration_coordinator().cloned();
    if let Some(coordinator) = &registration {
        if let Err(e) = coordinator
            .reconcile_after_restart(
                "daemon restarted before this registration finished",
                crate::registration::now_ms(),
            )
            .await
        {
            tracing::warn!(err = %e, "daemon.wallet_registration_restart_reconciliation_failed");
        }
        coordinator.mark_listener_bound(&format!("http://localhost:{LOCAL_CEREMONY_PORT}"));
    }
    let shutdown_signal = shutdown.clone();
    let task_registration = registration.clone();
    let handle = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown_signal.notified().await })
            .await
        {
            tracing::error!(%error, "ceremony.server.failed");
        }
        if let Some(coordinator) = task_registration {
            coordinator.mark_listener_unbound();
        }
    });
    Ok(CeremonyServer {
        shutdown,
        handle: Some(handle),
        registration,
    })
}

fn router(state: CeremonyState) -> Router {
    Router::new()
        .route("/ceremony/{token}", get(page))
        .route("/ceremony/{token}/plan.json", get(plan_json))
        .route("/ceremony/{token}/challenge", get(challenge_json))
        .route("/ceremony/{token}/complete", post(complete))
        .merge(wallet_registration::router())
        .layer(axum::middleware::from_fn(require_local_origin))
        .with_state(state)
}

/// Reject cross-site POSTs. Loopback GETs carry no Origin; POSTs from the
/// ceremony page carry `http://localhost:<port>` (or `127.0.0.1`).
async fn require_local_origin(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if req.method() == axum::http::Method::POST {
        let ok = req
            .headers()
            .get(axum::http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|o| {
                o.eq_ignore_ascii_case(&format!("http://localhost:{LOCAL_CEREMONY_PORT}"))
                    || o.eq_ignore_ascii_case(&format!("http://127.0.0.1:{LOCAL_CEREMONY_PORT}"))
            });
        if !ok {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    next.run(req).await
}

/// Resolve a URL token to a live challenge + sealed action, or an HTTP status.
///
/// Takes only [`AuthServices`] (not the whole [`Daemon`]) so it is unit
/// testable, and so this endpoint's reach is provably limited to resolvable
/// Sealed Approval challenges — it has no path to registration or generic
/// wallet unlock.
async fn resolve(
    services: &bloom_vfs::AuthServices,
    token: &str,
) -> Result<(ApprovalChallenge, SealedAction), StatusCode> {
    let store = services
        .require_store()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match store
        .resolve_ceremony_token(token, now_ms())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        CeremonyTokenResolution::Live { challenge, action } => Ok((*challenge, *action)),
        // Consumed (single-use) or expired.
        CeremonyTokenResolution::Gone => Err(StatusCode::GONE),
        CeremonyTokenResolution::Unknown => Err(StatusCode::NOT_FOUND),
    }
}

async fn page(State(state): State<CeremonyState>, Path(token): Path<String>) -> Response {
    match resolve(&state.daemon.auth_services, &token).await {
        Ok(_) => Html(CEREMONY_HTML).into_response(),
        Err(StatusCode::GONE) => (
            StatusCode::GONE,
            "This Sealed Approval URL has expired or was already used.",
        )
            .into_response(),
        Err(StatusCode::NOT_FOUND) => {
            (StatusCode::NOT_FOUND, "Unknown Sealed Approval URL.").into_response()
        }
        Err(status) => status.into_response(),
    }
}

async fn plan_json(State(state): State<CeremonyState>, Path(token): Path<String>) -> Response {
    let (challenge, action) = match resolve(&state.daemon.auth_services, &token).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    Json(serde_json::json!({
        "wallet": challenge.wallet,
        "surface": challenge.surface,
        "action_id": challenge.action_id,
        "intent_hash": challenge.intent_hash,
        "assurance": challenge.assurance.as_str(),
        "expiry_ms": challenge.expiry_ms,
        // Daemon-produced plan from the sealed action — never a VFS projection.
        "plan": action.plan,
    }))
    .into_response()
}

async fn challenge_json(State(state): State<CeremonyState>, Path(token): Path<String>) -> Response {
    let (challenge, _action) = match resolve(&state.daemon.auth_services, &token).await {
        Ok(v) => v,
        Err(status) => return status.into_response(),
    };
    let unsigned = unsigned_for(&challenge, None);
    match state
        .daemon
        .keystore
        .sealed_ceremony_challenge(&challenge.wallet, &unsigned)
        .await
    {
        Ok(prep) => match serde_json::from_str::<serde_json::Value>(&prep.challenge_json) {
            Ok(v) => Json(v).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        Err(e) => {
            tracing::warn!(err = %e, "ceremony.challenge.prepare_failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn unsigned_for(
    challenge: &ApprovalChallenge,
    review_session_id: Option<String>,
) -> UnsignedApproval {
    UnsignedApproval::for_challenge(
        challenge,
        SignerTransport::BrowserWebauthn,
        None,
        review_session_id,
    )
}

#[derive(Deserialize)]
struct BrowserCredentialResponse {
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    signature: String,
    #[serde(rename = "userHandle", default)]
    user_handle: Option<String>,
}

#[derive(Deserialize)]
struct BrowserCredential {
    id: String,
    response: BrowserCredentialResponse,
}

#[derive(Deserialize)]
struct CompleteBody {
    /// `"grant"` or `"grant_execute"`.
    mode: String,
    credential: BrowserCredential,
    prf_output_b64: String,
    /// The `clientDataJSON` the PRF output was produced under; must match the
    /// assertion so a racing local process cannot pair a stolen assertion with
    /// a forged PRF output.
    prf_client_data_json_b64: String,
}

fn err_json(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": msg.into() })),
    )
        .into_response()
}

async fn revoke_grant_and_drop_cache(
    daemon: &Daemon,
    grant_store: &dyn bloom_auth_api::GrantStore,
    grant_id: &str,
    now_ms: u64,
) {
    if let Err(e) = grant_store.revoke(grant_id, now_ms).await {
        tracing::warn!(
            err = %e,
            grant_id,
            "ceremony.approval.grant_revoke_failed"
        );
    }
    daemon.signer_cache.drop_on_completion(grant_id);
}

async fn complete(
    State(state): State<CeremonyState>,
    Path(token): Path<String>,
    Json(body): Json<CompleteBody>,
) -> Response {
    let daemon = &state.daemon;
    let now = now_ms();
    let execute = match body.mode.as_str() {
        "grant" => false,
        "grant_execute" => true,
        other => return err_json(StatusCode::BAD_REQUEST, format!("unknown mode '{other}'")),
    };

    let (challenge, action) = match resolve(&daemon.auth_services, &token).await {
        Ok(v) => v,
        Err(StatusCode::GONE) => {
            return err_json(StatusCode::GONE, "approval URL expired or already used");
        }
        Err(StatusCode::NOT_FOUND) => {
            return err_json(StatusCode::NOT_FOUND, "unknown approval URL");
        }
        Err(status) => return err_json(status, "could not resolve approval URL"),
    };
    if execute && action.surface() == "hyperliquid" {
        return err_json(
            StatusCode::BAD_REQUEST,
            "Hyperliquid approvals support grant mode only; approve the grant, then retry the Bloom VFS write to sign and submit",
        );
    }
    let wallet = challenge.wallet.clone();

    // Hardened challenges require a daemon-side review session, minted the same
    // way the foreground CLI mints it, so the consume step can bind to it.
    let review_session_id = if challenge.assurance == AssuranceLevel::Hardened {
        let id = sealed_review_session_id(&challenge);
        let writer = match daemon.auth_services.require_writer() {
            Ok(w) => w,
            Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        if let Err(e) = writer
            .issue_review_session(
                &id,
                &challenge.surface,
                &challenge.action_id,
                challenge.expiry_ms,
                now,
            )
            .await
        {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("issue review session: {e}"),
            );
        }
        Some(id)
    } else {
        None
    };

    let unsigned = unsigned_for(&challenge, review_session_id);

    // Build the assertion from the browser payload and bind it to the exact
    // approval challenge (clientDataJSON.challenge == approval hash).
    let assertion = WebAuthnAssertionRecord {
        credential_id: body.credential.id.clone(),
        authenticator_data_b64: body.credential.response.authenticator_data.clone(),
        client_data_json_b64: body.credential.response.client_data_json.clone(),
        signature_b64: body.credential.response.signature.clone(),
        user_handle_b64: body.credential.response.user_handle.clone(),
    };
    if let Err(e) = assertion.validate_challenge(&unsigned) {
        return err_json(
            StatusCode::BAD_REQUEST,
            format!("assertion challenge mismatch: {e}"),
        );
    }

    // Bind the PRF output to the same ceremony: its clientDataJSON challenge
    // must match the assertion's approval-challenge hash.
    let expected_challenge_b64 = match unsigned.challenge_hash() {
        Ok(h) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "hash approval challenge"),
    };
    let prf_challenge = bloom_keystore::client_data_challenge_b64(&body.prf_client_data_json_b64);
    if prf_challenge.as_deref() != Some(expected_challenge_b64.as_str()) {
        return err_json(
            StatusCode::FORBIDDEN,
            "PRF output was not produced for this approval challenge",
        );
    }

    // Decode PRF output and decrypt the signer (PRF stays in daemon memory).
    let prf_bytes =
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.prf_output_b64.trim()) {
            Ok(b) if b.len() == 32 => b,
            _ => {
                return err_json(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "prf_output must be 32 bytes",
                );
            }
        };
    let mut prf_arr = [0u8; 32];
    prf_arr.copy_from_slice(&prf_bytes);
    let signer = match daemon
        .keystore
        .sealed_ceremony_decrypt_signer(&wallet, prf_arr)
        .await
    {
        Ok(s) => s,
        Err(e) => return err_json(StatusCode::UNAUTHORIZED, format!("decrypt signer: {e}")),
    };

    // Verify the approval and mint the in-memory grant (burns the nonce).
    let signed = unsigned.into_signed(assertion);
    let verifier = match daemon.auth_services.require_approval_verifier() {
        Ok(v) => v,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let grant_store = match daemon.auth_services.require_grant_store() {
        Ok(g) => g,
        Err(e) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let grant = match verifier
        .verify_and_mint_grant(signed.clone(), grant_store.as_ref(), now)
        .await
    {
        Ok(g) => g,
        Err(e) => return err_json(StatusCode::UNAUTHORIZED, format!("verify approval: {e}")),
    };

    // Cache the decrypted signer under the grant so the sign_hash path can use
    // it without a fresh ceremony.
    daemon.signer_cache.insert(
        grant.grant_id.clone(),
        signer,
        wallet.clone(),
        grant.expiry_ms,
    );
    daemon.signer_cache.prune_expired(now);

    // Whether this sealed action broadcasts an EVM transaction. Only broadcast
    // actions have a chain, a per-wallet outbox entry, and a tx to execute.
    // Non-broadcast first-party actions (wallet-policy updates, policy-session
    // mints) have none of these — the minted grant is their authorization, and
    // they are installed by retrying their own mounted write. So we route the
    // outbox-only tx-engine persistence/execution below only for broadcasts;
    // calling into the tx engine for a non-tx action would be a layering error
    // (and previously failed with "missing chain_name", revoking the grant).
    let is_broadcast = action.chain_name().is_some();

    // Persist approval.json into the outbox projection — broadcast actions only.
    if is_broadcast
        && let Err(e) = daemon
            .tx_engine
            .persist_outbox_ceremony_approval(&action, &signed)
    {
        revoke_grant_and_drop_cache(daemon, grant_store.as_ref(), &grant.grant_id, now).await;
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persist approval artifact: {e}"),
        );
    }

    // grant + execute: broadcast immediately from sealed bytes.
    let mut executed = false;
    let mut tx_hash: Option<String> = None;
    // For a non-broadcast action, "approve + execute" is equivalent to "approve":
    // mint the grant and let the caller retry the write. Failing here would
    // revoke the valid grant.
    let broadcastable = execute && is_broadcast;
    if execute && !broadcastable {
        tracing::info!(
            wallet = %wallet,
            action_id = %action.action_id(),
            "ceremony.execute.non_broadcast_action: grant minted, install happens on write retry"
        );
    }
    if broadcastable {
        // The chain registry is keyed by the human chain name ("base"), not the
        // CAIP-2 `network` header ("eip155:8453"), so resolve it from the sealed
        // policy snapshot rather than the header.
        let chain_name = match action.chain_name() {
            Some(name) => name.to_string(),
            None => {
                revoke_grant_and_drop_cache(daemon, grant_store.as_ref(), &grant.grant_id, now)
                    .await;
                return err_json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "grant minted but sealed action is missing chain_name for execute".to_string(),
                );
            }
        };
        let client = match daemon.chains.get(&chain_name) {
            Some(c) => c,
            None => {
                let message =
                    format!("grant minted but chain '{chain_name}' is not configured for execute");
                revoke_grant_and_drop_cache(daemon, grant_store.as_ref(), &grant.grant_id, now)
                    .await;
                if let Err(project_err) = daemon.tx_engine.project_sealed_action_execute_failure(
                    &action,
                    &chain_name,
                    &message,
                ) {
                    tracing::warn!(err = %project_err, "ceremony.execute.failure_projection_failed");
                }
                return err_json(StatusCode::INTERNAL_SERVER_ERROR, message);
            }
        };
        let policy = match daemon.keystore.info(&wallet) {
            Ok(info) => info.policy,
            Err(e) => {
                let message = format!("grant minted but wallet policy unavailable: {e}");
                revoke_grant_and_drop_cache(daemon, grant_store.as_ref(), &grant.grant_id, now)
                    .await;
                if let Err(project_err) = daemon.tx_engine.project_sealed_action_execute_failure(
                    &action,
                    &chain_name,
                    &message,
                ) {
                    tracing::warn!(err = %project_err, "ceremony.execute.failure_projection_failed");
                }
                return err_json(StatusCode::INTERNAL_SERVER_ERROR, message);
            }
        };
        match daemon
            .tx_engine
            .execute_sealed_action(&action, &chain_name, &client, &policy)
            .await
        {
            Ok(exec) => {
                executed = true;
                tx_hash = Some(format!("{:#x}", exec.tx_hash));
            }
            Err(e) => {
                let message = format!("grant minted but execute failed: {e}");
                revoke_grant_and_drop_cache(daemon, grant_store.as_ref(), &grant.grant_id, now)
                    .await;
                if let Err(project_err) = daemon.tx_engine.project_sealed_action_execute_failure(
                    &action,
                    &chain_name,
                    &message,
                ) {
                    tracing::warn!(err = %project_err, "ceremony.execute.failure_projection_failed");
                }
                return err_json(StatusCode::BAD_GATEWAY, message);
            }
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "grant_id": grant.grant_id,
        "executed": executed,
        "tx_hash": tx_hash,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_auth::{AuthStore, RejectingApprovalSignatureVerifier, StoreApprovalVerifier};
    use bloom_auth_api::petal_identity::{
        FIRST_PARTY_PETAL_VERSION_V0, PETAL_ID_EVM_WALLET, PLACEHOLDER_DIGEST_EVM_WALLET,
    };
    use bloom_auth_api::{
        APPROVAL_CHALLENGE_SCHEMA_V1, ApprovalVerifier, AuthStoreView, AuthStoreWriter,
        CANONICAL_INTENT_HEADER_SCHEMA_V1, CanonicalEnvelope, CanonicalIntentHeader,
        DaemonGrantTerms, ExecutorKind, PetalPolicySnapshot,
    };
    use bloom_vfs::AuthServices;

    fn sealed_action(action_id: &str, plan: &str, expires_ms: u64) -> SealedAction {
        let header = CanonicalIntentHeader {
            schema: CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: "my-wallet".into(),
            surface: "outbox".into(),
            action_id: action_id.into(),
            petal_id: PETAL_ID_EVM_WALLET.into(),
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "ethereum".into(),
            account: "default".into(),
            action_kind: "confirm".into(),
            value_movement: true,
            authority_change: false,
            expires_ms,
        };
        let envelope = CanonicalEnvelope::new(
            header,
            "evm_wallet_tx",
            "bloom.evm.sealed_intent.v1",
            br#"{"to":"0x1"}"#.to_vec(),
        );
        let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Standard);
        terms.allowed_sign_intents = vec!["evm.tx.sign".into()];
        let snapshot = PetalPolicySnapshot::minimal(&envelope.header);
        SealedAction::new(envelope, plan.into(), Vec::new(), terms, snapshot, 1_000)
            .expect("sealed action")
    }

    /// Build an `AuthStore`-backed `AuthServices`, stage a sealed action, issue
    /// a challenge, and return the services plus the ceremony URL token.
    async fn services_with_challenge(
        action_id: &str,
        plan: &str,
        expiry_ms: u64,
    ) -> (AuthServices, String) {
        let store = AuthStore::open_in_memory_for_tests().unwrap();
        let verifier = Arc::new(StoreApprovalVerifier::new(
            store,
            RejectingApprovalSignatureVerifier,
        ));
        let av: Arc<dyn ApprovalVerifier> = verifier.clone();
        let sv: Arc<dyn AuthStoreView> = verifier.clone();
        let wv: Arc<dyn AuthStoreWriter> = verifier;
        let services = AuthServices::new(Some(av), Some(sv), Some(wv));

        let action = sealed_action(action_id, plan, expiry_ms);
        let writer = services.require_writer().unwrap();
        writer.stage_action(action, 1_000).await.unwrap();
        let challenge = writer
            .issue_challenge("outbox", action_id, "nonce-abc", expiry_ms, 1_001)
            .await
            .unwrap();
        (services, challenge.ceremony_token())
    }

    #[tokio::test]
    async fn resolve_live_serves_daemon_plan() {
        let (services, token) =
            services_with_challenge("act-1", "SEND 1 ETH to 0xabc", u64::MAX / 2).await;
        let (challenge, action) = resolve(&services, &token).await.expect("live");
        assert_eq!(challenge.action_id, "act-1");
        // The plan is the daemon-produced sealed-action plan, not a projection.
        assert_eq!(action.plan, "SEND 1 ETH to 0xabc");
        assert_eq!(action.wallet(), "my-wallet");
        // The resolved challenge re-exposes its own ceremony URL / token.
        assert_eq!(challenge.ceremony_token(), token);
    }

    #[tokio::test]
    async fn resolve_unknown_token_is_404() {
        let (services, _token) = services_with_challenge("act-1", "p", u64::MAX / 2).await;
        let err = resolve(&services, "totally-unknown-token")
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn resolve_expired_token_is_410() {
        // Challenge expires at 2ms; wall-clock now is far past it.
        let (services, token) = services_with_challenge("act-1", "p", 2).await;
        let err = resolve(&services, &token).await.unwrap_err();
        assert_eq!(err, StatusCode::GONE);
    }

    /// Endpoint separation: `/ceremony/{token}` serves only resolvable Sealed
    /// Approval challenges. It has no route or handler for registration or
    /// generic wallet unlock (those are foreground keystore ceremonies in a
    /// different crate), and a token that maps to no issued challenge — such as
    /// one derived from a nonce that was never issued — simply 404s.
    #[tokio::test]
    async fn resolve_only_serves_sealed_approval_challenges() {
        let (services, _token) = services_with_challenge("act-1", "p", u64::MAX / 2).await;
        let bogus = ApprovalChallenge {
            schema: APPROVAL_CHALLENGE_SCHEMA_V1.into(),
            action_id: "act-x".into(),
            wallet: "w".into(),
            surface: "outbox".into(),
            petal_id: "p".into(),
            petal_digest: "d".into(),
            intent_hash: "h".into(),
            server_nonce: "never-issued".into(),
            assurance: AssuranceLevel::Standard,
            daemon_terms_digest: "x".into(),
            petal_policy_digest: "y".into(),
            policy_version: 0,
            expiry_ms: 0,
            ceremony_url: None,
        };
        assert_eq!(
            resolve(&services, &bogus.ceremony_token())
                .await
                .unwrap_err(),
            StatusCode::NOT_FOUND
        );
    }
}
