//! Passkey-bound collection of Privacy Pools withdrawal destinations.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use bloom_auth_api::{
    AssuranceLevel, CANONICAL_INTENT_HEADER_SCHEMA_V1, CanonicalEnvelope, CanonicalIntentHeader,
    DaemonGrantTerms, ExecutorKind, PETAL_PETAL_ID_PREFIX, PetalPolicySnapshot, PolicyCheckClass,
    PolicyCheckResult, SealedAction, SignerTransport, UnsignedApproval, WebAuthnAssertionRecord,
};
use rand::RngCore;
use serde::Deserialize;

use super::{CeremonyState, err_json, now_ms};

const HTML: &str = include_str!("private_input_ceremony.html");
const SURFACE: &str = "petal-private-input";

pub(super) fn router() -> Router<CeremonyState> {
    Router::new()
        .route("/private-input/{token}", get(page))
        .route("/private-input/{token}/request.json", get(request_json))
        .route("/private-input/{token}/prepare", post(prepare))
        .route("/private-input/{token}/complete", post(complete))
        .layer(axum::middleware::from_fn(private_input_headers))
}

async fn private_input_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("cross-origin-opener-policy"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    response
}

fn private_error(error: bloom_petals::HostError) -> Response {
    match error {
        bloom_petals::HostError::NotFound(_) => err_json(StatusCode::NOT_FOUND, error.to_string()),
        bloom_petals::HostError::Denied(_) => err_json(StatusCode::GONE, error.to_string()),
        bloom_petals::HostError::Invalid(_) => err_json(StatusCode::BAD_REQUEST, error.to_string()),
        bloom_petals::HostError::Backend(_) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "private-input backend error",
        ),
    }
}

async fn page(State(state): State<CeremonyState>, Path(token): Path<String>) -> Response {
    match state.daemon.private_inputs.metadata(&token, now_ms()) {
        Ok(_) => Html(HTML).into_response(),
        Err(error) => private_error(error),
    }
}

async fn request_json(State(state): State<CeremonyState>, Path(token): Path<String>) -> Response {
    match state.daemon.private_inputs.metadata(&token, now_ms()) {
        Ok(metadata) => Json(serde_json::json!({
            "title": metadata.title,
            "prompt": metadata.prompt,
            "note_wallet": metadata.wallet,
            "approval_wallet": metadata.approval_wallet,
            "kind": match metadata.kind {
                bloom_petals::abi::PrivateInputKind::EvmAddress => "evm-address",
            },
            "expires_ms": metadata.expires_ms,
        }))
        .into_response(),
        Err(error) => private_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_petals::abi::{PetalRouteContext, PrivateInputKind};

    fn metadata() -> crate::private_input::PrivateInputMetadata {
        crate::private_input::PrivateInputMetadata {
            token: "opaque-token".into(),
            id: "privacy-pools/withdraw/dev/note-1".into(),
            wallet: "dev".into(),
            approval_wallet: "owner-passkey".into(),
            title: "Private withdrawal".into(),
            prompt: "Enter a destination".into(),
            kind: PrivateInputKind::EvmAddress,
            context: PetalRouteContext {
                petal_root: "privacy-pools".into(),
                package_hash: "ab".repeat(32),
                route_id: "withdraw-private".into(),
                op: "write".into(),
                path: "withdrawals/dev/note-1.json".into(),
                params: vec![],
                actor: None,
            },
            expires_ms: 600_001,
        }
    }

    #[test]
    fn sealed_action_contains_digest_but_not_private_value() {
        let private_value = "0x1111111111111111111111111111111111111111";
        let digest = blake3::hash(private_value.as_bytes()).to_hex().to_string();
        let action = private_input_action(&metadata(), &digest, 1).unwrap();
        let encoded = serde_json::to_string(&action).unwrap();
        assert!(encoded.contains(&digest));
        assert_eq!(action.wallet(), "owner-passkey");
        assert_eq!(action.envelope.header.account, "owner-passkey");
        let subject = base64::engine::general_purpose::STANDARD
            .decode(&action.envelope.subject_bytes_b64)
            .unwrap();
        let subject: serde_json::Value = serde_json::from_slice(&subject).unwrap();
        assert_eq!(subject["note_wallet"], "dev");
        assert_eq!(subject["approval_wallet"], "owner-passkey");
        assert!(!encoded.contains(private_value));
        assert!(!HTML.contains(private_value));
    }

    #[test]
    fn page_posts_value_only_to_local_private_input_endpoint() {
        assert!(HTML.contains("PATH+'/prepare'"));
        assert!(HTML.contains("PATH+'/complete'"));
        assert!(!HTML.contains("console.log"));
        assert!(!HTML.contains("localStorage"));
        assert!(HTML.contains("v.approval_wallet"));
        assert!(HTML.contains("v.note_wallet"));
        assert!(!HTML.contains("v.wallet"));
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareBody {
    value: String,
}

async fn prepare(
    State(state): State<CeremonyState>,
    Path(token): Path<String>,
    Json(body): Json<PrepareBody>,
) -> Response {
    let now = now_ms();
    let metadata = match state.daemon.private_inputs.metadata(&token, now) {
        Ok(metadata) => metadata,
        Err(error) => return private_error(error),
    };
    let value = match body.value.trim().parse::<alloy::primitives::Address>() {
        Ok(address) if !address.is_zero() => format!("{address:#x}"),
        _ => return err_json(StatusCode::BAD_REQUEST, "enter a non-zero Ethereum address"),
    };
    let value_digest = blake3::hash(value.as_bytes()).to_hex().to_string();
    let action = match private_input_action(&metadata, &value_digest, now) {
        Ok(action) => action,
        Err(message) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, message),
    };
    let writer = match state.daemon.auth_services.require_writer() {
        Ok(writer) => writer,
        Err(error) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    if let Err(error) = writer.stage_action(action.clone(), now).await {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("stage private-input approval: {error}"),
        );
    }
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = match writer
        .issue_challenge(
            SURFACE,
            action.action_id(),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
            metadata.expires_ms,
            now,
        )
        .await
    {
        Ok(challenge) => challenge,
        Err(error) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("issue private-input approval challenge: {error}"),
            );
        }
    };
    let unsigned =
        UnsignedApproval::for_challenge(&challenge, SignerTransport::BrowserWebauthn, None, None);
    let prepared = match state
        .daemon
        .keystore
        .sealed_ceremony_challenge(&metadata.approval_wallet, &unsigned)
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("prepare private-input passkey challenge: {error}"),
            );
        }
    };
    if let Err(error) = state
        .daemon
        .private_inputs
        .set_prepared(&token, value, challenge, now)
    {
        return private_error(error);
    }
    match serde_json::from_str::<serde_json::Value>(&prepared.challenge_json) {
        Ok(json) => Json(json).into_response(),
        Err(_) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid private-input passkey challenge",
        ),
    }
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
    credential: BrowserCredential,
}

async fn complete(
    State(state): State<CeremonyState>,
    Path(token): Path<String>,
    Json(body): Json<CompleteBody>,
) -> Response {
    let now = now_ms();
    let challenge = match state.daemon.private_inputs.prepared_challenge(&token, now) {
        Ok(challenge) => challenge,
        Err(error) => return private_error(error),
    };
    let unsigned =
        UnsignedApproval::for_challenge(&challenge, SignerTransport::BrowserWebauthn, None, None);
    let assertion = WebAuthnAssertionRecord {
        credential_id: body.credential.id,
        authenticator_data_b64: body.credential.response.authenticator_data,
        client_data_json_b64: body.credential.response.client_data_json,
        signature_b64: body.credential.response.signature,
        user_handle_b64: body.credential.response.user_handle,
    };
    if let Err(error) = assertion.validate_challenge(&unsigned) {
        return err_json(
            StatusCode::BAD_REQUEST,
            format!("assertion challenge mismatch: {error}"),
        );
    }
    let verifier = match state.daemon.auth_services.require_approval_verifier() {
        Ok(verifier) => verifier,
        Err(error) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    let grants = match state.daemon.auth_services.require_grant_store() {
        Ok(grants) => grants,
        Err(error) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    let signed = unsigned.into_signed(assertion);
    let grant = match verifier
        .verify_and_mint_grant(signed, grants.as_ref(), now)
        .await
    {
        Ok(grant) => grant,
        Err(error) => {
            return err_json(
                StatusCode::UNAUTHORIZED,
                format!("verify private-input approval: {error}"),
            );
        }
    };
    if let Err(error) = state
        .daemon
        .private_inputs
        .complete(&token, &challenge.action_id, now)
    {
        let _ = grants.revoke(&grant.grant_id, now).await;
        return private_error(error);
    }
    // The grant authorizes no later signing operation; consume its nonce and
    // revoke it immediately after promoting the private value.
    if let Err(error) = grants.revoke(&grant.grant_id, now).await {
        tracing::warn!(err = %error, "private_input.grant_revoke_failed");
    }
    Json(serde_json::json!({ "ok": true, "status": "ready" })).into_response()
}

fn private_input_action(
    metadata: &crate::private_input::PrivateInputMetadata,
    value_digest: &str,
    now_ms: u64,
) -> Result<SealedAction, String> {
    let mut action_hasher = blake3::Hasher::new();
    action_hasher.update(b"bloom.private_input.approval.v1");
    action_hasher.update(metadata.token.as_bytes());
    action_hasher.update(value_digest.as_bytes());
    action_hasher.update(&metadata.expires_ms.to_be_bytes());
    let action_id = format!("private-input-{}", action_hasher.finalize().to_hex());
    let petal_id = format!("{PETAL_PETAL_ID_PREFIX}{}", metadata.context.petal_root);
    let header = CanonicalIntentHeader {
        schema: CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
        wallet: metadata.approval_wallet.clone(),
        surface: SURFACE.into(),
        action_id,
        petal_id,
        petal_digest: metadata.context.package_hash.clone(),
        petal_version: "v1-package".into(),
        executor_kind: ExecutorKind::Wasm,
        network: "eip155:1".into(),
        account: metadata.approval_wallet.clone(),
        action_kind: "petal.private_input".into(),
        value_movement: true,
        authority_change: false,
        expires_ms: metadata.expires_ms,
    };
    let subject = serde_json::to_vec(&serde_json::json!({
        "schema": "bloom.private_input.subject.v1",
        "input_id": metadata.id,
        "note_wallet": metadata.wallet,
        "approval_wallet": metadata.approval_wallet,
        "input_kind": "evm_address",
        "value_digest": value_digest,
        "petal_root": metadata.context.petal_root,
        "package_hash": metadata.context.package_hash,
        "route_id": metadata.context.route_id,
        "path": metadata.context.path,
    }))
    .map_err(|error| format!("encode private-input approval: {error}"))?;
    let envelope = CanonicalEnvelope::new(
        header,
        "petal_private_input",
        "bloom.private_input.subject.v1",
        subject,
    );
    let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Standard);
    terms.max_ttl_secs = crate::private_input::PRIVATE_INPUT_TTL_MS / 1_000;
    terms.max_signatures = 1;
    terms.extra.insert(
        "required.private_input_digest".into(),
        serde_json::Value::String(value_digest.into()),
    );
    let mut snapshot = PetalPolicySnapshot::minimal(&envelope.header);
    snapshot.config.insert(
        "private_input_kind".into(),
        serde_json::Value::String("evm_address".into()),
    );
    let plan = format!(
        "# Approve private Privacy Pools destination\n\nPetal: `{}`\nRoute: `{}`\nNote wallet: `{}`\nApproval wallet: `{}`\nInput: `{}`\nValue digest: `{}`\n\nThe destination remains private to Bloom and the Privacy Pools helper. Verify the address shown in this browser before approving.",
        metadata.context.petal_root,
        metadata.context.route_id,
        metadata.wallet,
        metadata.approval_wallet,
        metadata.id,
        value_digest,
    );
    SealedAction::new(
        envelope,
        plan,
        vec![PolicyCheckResult {
            rule_id: "privacy-pools.private_destination".into(),
            rule_class: PolicyCheckClass::Informational,
            outcome: "pass".into(),
            message:
                "destination value is bound by digest and omitted from agent-visible projections"
                    .into(),
            step_up_ceiling: None,
        }],
        terms,
        snapshot,
        now_ms,
    )
    .map_err(|error| format!("seal private-input approval: {error}"))
}
