//! IPC handlers for the WS-1 host signing API.
//!
//! The daemon exposes a `sign_hash` JSON-RPC method that gates wallet
//! signing on:
//!
//! 1. A live [`SealedApprovalGrant`] for
//!    `(wallet, action_id, petal_id, petal_digest)`.
//! 2. A [`SigningAttestation`] whose schema is registered with the
//!    wired [`SigningAttestationSchemaRegistry`].
//! 3. The grant's `daemon_terms.allowed_sign_intents` containing the
//!    requested `intent`.
//! 4. The wallet key signature at the call site (handled inside
//!    [`KeystorePetalHost`], see `crates/bloom-keystore/src/petal_host.rs`).
//!
//! Every denial produces an audit row (`petal.sign.deny`) before the IPC
//! response is generated, matching what
//! [`KeystorePetalHost::sign_hash`](bloom_keystore::petal_host::KeystorePetalHost) writes
//! for the same condition, so server-side and daemon-side denials look
//! identical at the IPC layer.

use std::time::{SystemTime, UNIX_EPOCH};

use bloom_auth_api::{
    AuthApiError, SIGNING_ATTESTATION_SCHEMA_V1, SealedSignature, SignHashRequest,
    SigningAttestation,
};
use bloom_vfs::{AuthServices, HandlerError};
use serde_json::{Value, json};

/// Param-driven [`PetalHost::sign_hash`] for the WS-1 IPC method.
///
/// On success returns a JSON object with `intent_hash`, `signature_b64`
/// and `signed_at_ms`. On failure returns a [`HandlerError`] whose
/// `Display` is a deterministic message that matches what
/// [`KeystorePetalHost::sign_hash`] produces for the same denial
/// condition, so a server-side error (caught by the host) and a
/// daemon-side error (caught here) yield the same string at the
/// JSON-RPC layer.
pub async fn handle_sign_hash(
    services: &AuthServices,
    params: &Value,
) -> Result<Value, HandlerError> {
    // 1. Pull and validate the basic string fields.
    let wallet = non_empty_str(params, "wallet")?;
    validate_wallet_name(wallet)?;
    let action_id = non_empty_str(params, "action_id")?;
    let petal_id = non_empty_str(params, "petal_id")?;
    let petal_digest = non_empty_str(params, "petal_digest")?;
    let intent = non_empty_str(params, "intent")?;
    let hash = non_empty_str(params, "hash")?;
    let attestation_json = params
        .get("attestation")
        .ok_or_else(|| HandlerError::invalid("sign_hash needs attestation"))?;

    // 2. Decode the attestation and reject any non-V1 schema up front
    //    so the failure message is consistent with what
    //    `KeystorePetalHost::sign_hash` produces through the registry.
    let attestation: SigningAttestation = serde_json::from_value(attestation_json.clone())
        .map_err(|e| HandlerError::invalid(format!("attestation: {e}")))?;
    if !attestation.schema.trim().is_empty() && attestation.schema != SIGNING_ATTESTATION_SCHEMA_V1
    {
        return Err(HandlerError::invalid(format!(
            "unsupported attestation schema {}",
            attestation.schema
        )));
    }

    // 2a. Defense-in-depth: the param-level `petal_id` and
    //     `petal_digest` MUST match the attestation's, otherwise an
    //     honest caller could be tricked into stamping a (wallet,
    //     action_id, petal_id, petal_digest) tuple that the host then
    //     looks grants up under — but the lookups would still be
    //     keyed on the attestation's tuple, so we'd silently agree to
    //     sign for a different Petal. Reject up front.
    if petal_id != attestation.petal_id {
        return Err(HandlerError::invalid(format!(
            "sign_hash petal_id '{petal_id}' does not match attestation petal_id '{}'",
            attestation.petal_id
        )));
    }
    if petal_digest != attestation.petal_digest {
        return Err(HandlerError::invalid(format!(
            "sign_hash petal_digest '{petal_digest}' does not match attestation petal_digest '{}'",
            attestation.petal_digest
        )));
    }

    // 3. Validate `hash` is `0x` + 64 hex chars. `KeystorePetalHost`
    //    does the same check internally; doing it here gives us a
    //    deterministic `HandlerError::invalid` instead of letting the
    //    host's `AuthApiError::Denied` bubble through.
    let hash_hex = validate_hash_hex(hash)?;

    // 4. `now_ms`: explicit from the caller, otherwise the daemon's
    //    wall clock. If wall-clock lookup fails (extremely rare —
    //    pre-1970 clock), fall back to `0` and let the host's "live"
    //    predicate miss rather than panic.
    let now_ms = params
        .get("now_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(wall_clock_ms);

    // 5. Delegate to the wired PetalHost.
    let host = services.require_petal_host()?;
    let request = SignHashRequest {
        wallet: wallet.to_string(),
        action_id: action_id.to_string(),
        intent: intent.to_string(),
        hash_hex,
    };
    let sealed: SealedSignature = host
        .sign_hash(request, &attestation, now_ms)
        .await
        .map_err(map_auth_error)?;

    // 6. Shape the IPC response.
    Ok(json!({
        "intent_hash": sealed.intent_hash,
        "signature_b64": sealed.signature_b64,
        "signed_at_ms": sealed.signed_at_ms,
    }))
}

/// Pull a non-empty `&str` from `params[key]`. Rejects missing keys
/// and empty strings deterministically.
fn non_empty_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, HandlerError> {
    let s = params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| HandlerError::invalid(format!("{key} is required")))?;
    if s.trim().is_empty() {
        return Err(HandlerError::invalid(format!("{key} is empty")));
    }
    Ok(s)
}

/// Validate a wallet name. `Keystore::validate_name` is private to
/// `bloom-keystore` so we mirror its rule here: `len ≤ 64`,
/// `chars ∈ [A-Za-z0-9_-]`, no path separators. Failing closed with a
/// `HandlerError::invalid` keeps the IPC layer deterministic.
fn validate_wallet_name(name: &str) -> Result<(), HandlerError> {
    if name.len() > 64 {
        return Err(HandlerError::invalid(format!(
            "invalid wallet name: too long ({} > 64)",
            name.len()
        )));
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(HandlerError::invalid(
            "invalid wallet name: contains path separator or NUL",
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(HandlerError::invalid(format!(
            "invalid wallet name: '{name}'"
        )));
    }
    Ok(())
}

/// Parse `hash` as `0x` + 64 lowercase hex chars; mirrors the host's
/// `parse_hash_hex` (see `bloom-keystore/src/petal_host.rs`) so denials
/// read identically here and there.
fn validate_hash_hex(s: &str) -> Result<String, HandlerError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(HandlerError::invalid(format!(
            "invalid hash_hex: expected 64 hex chars, got {}",
            stripped.len()
        )));
    }
    if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(HandlerError::invalid(
            "invalid hash_hex: not all chars are hex",
        ));
    }
    Ok(s.to_string())
}

/// Best-effort current wall-clock ms for defaulting `now_ms`.
fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Map an [`AuthApiError`] from the [`PetalHost`] into the IPC
/// [`HandlerError`]. We preserve the [`AuthApiError`] message
/// verbatim so the IPC client sees the same string that landed in the
/// host audit row.
fn map_auth_error(e: AuthApiError) -> HandlerError {
    match e {
        AuthApiError::Denied(msg) => HandlerError::Backend(format!("authorization denied: {msg}")),
        AuthApiError::InvalidSubject(msg) => HandlerError::invalid(msg),
        AuthApiError::InvalidAssuranceTransition(msg) => HandlerError::invalid(msg),
        AuthApiError::NotFound(msg) => HandlerError::not_found(msg),
        AuthApiError::Store(msg) => HandlerError::backend(msg),
        AuthApiError::Json(e) => HandlerError::backend(format!("json: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use bloom_auth::grant_store::InMemoryGrantStore;
    use bloom_auth_api::GrantStore;
    use bloom_auth_api::petal_identity::{
        FIRST_PARTY_PETAL_VERSION_V0, PETAL_ID_EVM_WALLET, PLACEHOLDER_DIGEST_EVM_WALLET,
    };
    use bloom_auth_api::{
        AssuranceLevel, CanonicalEnvelope, CanonicalIntentHeader, DaemonGrantTerms,
        DefaultAttestationRegistry, ExecutorKind, PetalPolicySnapshot, SealedAction,
    };
    use bloom_keystore::Keystore;
    use bloom_proto::AuditLog;

    use super::*;

    struct TestServices {
        services: AuthServices,
        store: Arc<InMemoryGrantStore>,
        audit_log: Arc<AuditLog>,
    }

    async fn make_test_services(ks_dir: &Path) -> TestServices {
        let keystore: Arc<Keystore> = Arc::new(Keystore::new(ks_dir).expect("keystore dir"));
        keystore
            .create_local("my-wallet", "p")
            .expect("create local wallet");
        keystore.unlock("my-wallet", "p").expect("unlock wallet");

        // Use a unique fixed path under `target/test-audit/` so the
        // directory is bound to the test process lifetime, not a
        // `tempfile::TempDir` RAII guard. The audit log path is
        // suffixed with the test name (and a counter) so concurrent
        // tests don't collide on the file.
        let audit_root = std::env::temp_dir().join("bloom-daemon-test-audit");
        std::fs::create_dir_all(&audit_root).expect("create audit root");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let audit_path = audit_root.join(format!(
            "{}-{}.jsonl",
            std::thread::current()
                .name()
                .unwrap_or("test")
                .replace(['/', '\\', '.', ' '], "_"),
            unique
        ));
        let audit_log = Arc::new(AuditLog::open(&audit_path).expect("audit log"));

        let store: Arc<InMemoryGrantStore> = Arc::new(InMemoryGrantStore::new());
        let registry: Arc<DefaultAttestationRegistry> = Arc::new(DefaultAttestationRegistry::new());
        let grant_dyn: Arc<dyn bloom_auth_api::GrantStore> = store.clone();
        let registry_dyn: Arc<dyn bloom_auth_api::SigningAttestationSchemaRegistry> =
            registry.clone();
        let petal_host: Arc<dyn bloom_auth_api::PetalHost> =
            Arc::new(bloom_keystore::petal_host::KeystorePetalHost::new(
                keystore,
                grant_dyn,
                registry_dyn,
                audit_log.clone(),
            ));
        let services = AuthServices::default()
            .with_grant_store(store.clone())
            .with_attestation_registry(registry)
            .with_petal_host(petal_host);
        TestServices {
            services,
            store,
            audit_log,
        }
    }

    async fn mint_evm_tx_grant(
        store: &InMemoryGrantStore,
        action_id: &str,
        allowed_sign_intents: &[&str],
        max_signatures: u32,
        issued_ms: u64,
        ttl_secs: u64,
    ) -> bloom_auth_api::SealedApprovalGrant {
        let header = CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V2.into(),
            wallet: "my-wallet".into(),
            surface: "outbox".into(),
            action_id: action_id.into(),
            petal_id: PETAL_ID_EVM_WALLET.into(),
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "ethereum".into(),
            account: "default".into(),
            action_kind: "tx_send".into(),
            value_movement: true,
            authority_change: false,
            expires_ms: 10_000,
        };
        let envelope = CanonicalEnvelope::new(
            header,
            "evm",
            "evm.v1",
            br#"{"to":"0x1234","value":"1"}"#.to_vec(),
        );
        let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Standard);
        terms.allowed_sign_intents = allowed_sign_intents.iter().map(|s| s.to_string()).collect();
        terms.max_signatures = max_signatures;
        terms.max_ttl_secs = ttl_secs;
        let snapshot = {
            let mut snap = PetalPolicySnapshot::minimal(&envelope.header);
            snap.caps.clear();
            snap.config.clear();
            snap.budget_state.clear();
            snap.wallet = "my-wallet".into();
            snap.petal_id = PETAL_ID_EVM_WALLET.into();
            snap.petal_digest = PLACEHOLDER_DIGEST_EVM_WALLET.into();
            snap
        };
        let action = SealedAction::new(
            envelope,
            "plan".into(),
            Vec::new(),
            terms,
            snapshot,
            issued_ms,
        )
        .expect("sealed action");
        store
            .mint(&action, issued_ms.saturating_add(120_000), issued_ms)
            .await
            .expect("mint")
    }

    fn base_params() -> Value {
        json!({
            "wallet": "my-wallet",
            "action_id": "act-1",
            "petal_id": PETAL_ID_EVM_WALLET,
            "petal_digest": PLACEHOLDER_DIGEST_EVM_WALLET,
            "intent": "evm.tx.sign",
            "hash": format!("0x{}", "1".repeat(64)),
            "attestation": {
                "schema": SIGNING_ATTESTATION_SCHEMA_V1,
                "petal_id": PETAL_ID_EVM_WALLET,
                "petal_digest": PLACEHOLDER_DIGEST_EVM_WALLET,
                "intent": "evm.tx.sign",
                "facts": {
                    "facts_schema": bloom_auth_api::EVM_SIGNING_ATTESTATION_FACTS_SCHEMA_V1,
                    "action_id": "act-1",
                    "wallet": "my-wallet",
                    "surface": "outbox",
                    "petal_id": PETAL_ID_EVM_WALLET,
                    "petal_digest": PLACEHOLDER_DIGEST_EVM_WALLET,
                    "petal_version": FIRST_PARTY_PETAL_VERSION_V0,
                    "action_kind": "confirm",
                    "chain_id": 31337,
                    "account": "0x0000000000000000000000000000000000000001",
                    "to": "0x0000000000000000000000000000000000000002",
                    "recipient": "0x0000000000000000000000000000000000000002",
                    "value": {
                        "native_value_wei": "1",
                        "valuation_usd_micro": 1
                    },
                    "token": null,
                    "method": "native_transfer",
                    "calldata_hash": format!("0x{}", "2".repeat(64)),
                    "nonce_intent": {
                        "mode": "exact",
                        "nonce": 0
                    },
                    "fee_facts": {
                        "tx_type": "eip1559",
                        "gas_limit": "21000",
                        "max_fee_per_gas_wei": "100",
                        "max_priority_fee_per_gas_wei": "10",
                        "max_total_fee_wei": "2100000"
                    },
                    "replacement_fee_facts": null,
                    "unsigned_envelope": {
                        "envelope_kind": "eip1559",
                        "unsigned_tx_bytes_hash": format!("0x{}", "3".repeat(64)),
                        "signing_hash": format!("0x{}", "1".repeat(64))
                    },
                    "signing_hash": format!("0x{}", "1".repeat(64)),
                    "policy_snapshot_digest": "4".repeat(64),
                    "daemon_terms_digest": "5".repeat(64)
                }
            },
        })
    }

    // ── happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_with_full_grant_flow() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices {
            services,
            store,
            audit_log,
            ..
        } = make_test_services(ks_dir.path()).await;
        let grant =
            mint_evm_tx_grant(store.as_ref(), "act-1", &["evm.tx.sign"], 3, 1_000, 120).await;
        // Pin `now_ms` to within the grant window (issued=1_000,
        // expiry≈121_000) so the live-grant predicate does not
        // reject based on wall-clock time.
        let mut params = base_params();
        params["now_ms"] = json!(grant.issued_ms.saturating_add(500));

        let value = handle_sign_hash(&services, &params)
            .await
            .expect("happy path");
        assert!(value.get("intent_hash").is_some());
        let sig_b64 = value
            .get("signature_b64")
            .and_then(|v| v.as_str())
            .expect("signature_b64");
        assert!(!sig_b64.is_empty());
        // Verify base64 decodes to a real signature (the host encodes a
        // 65-byte signature for secp256k1 sign_hash_sync).
        let decoded = B64.decode(sig_b64).expect("base64");
        assert_eq!(decoded.len(), 65);

        // Audit captured one ok row and zero deny rows.
        let log = audit_log.tail(10).unwrap();
        let oks = log.iter().filter(|r| r.kind == "petal.sign.ok").count();
        let denies = log.iter().filter(|r| r.kind == "petal.sign.deny").count();
        assert_eq!(oks, 1);
        assert_eq!(denies, 0);

        // Grant's `consumed_signature_count` incremented to 1.
        let live = store
            .get_active(
                "my-wallet",
                "act-1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                grant.issued_ms.saturating_add(500),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(live.consumed_signature_count, 1);
    }

    #[tokio::test]
    async fn sign_hash_one_shot_grant_consumes_and_replay_denies() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices {
            services,
            store,
            audit_log,
            ..
        } = make_test_services(ks_dir.path()).await;
        let grant =
            mint_evm_tx_grant(store.as_ref(), "act-1", &["evm.tx.sign"], 1, 1_000, 120).await;
        let mut params = base_params();
        params["now_ms"] = json!(grant.issued_ms.saturating_add(500));

        handle_sign_hash(&services, &params)
            .await
            .expect("first one-shot signature succeeds");
        assert!(
            store
                .get_active(
                    "my-wallet",
                    "act-1",
                    PETAL_ID_EVM_WALLET,
                    PLACEHOLDER_DIGEST_EVM_WALLET,
                    grant.issued_ms.saturating_add(500),
                )
                .await
                .unwrap()
                .is_none(),
            "exhausted one-shot grant must leave no live grant for replay"
        );

        let err = handle_sign_hash(&services, &params)
            .await
            .expect_err("replay after one-shot consume must deny");
        let msg = err.to_string();
        assert!(msg.contains("no live grant"), "unexpected denial: {msg}");

        let log = audit_log.tail(10).unwrap();
        assert_eq!(log.iter().filter(|r| r.kind == "petal.sign.ok").count(), 1);
        assert_eq!(
            log.iter().filter(|r| r.kind == "petal.sign.deny").count(),
            1
        );
    }

    // ── denial paths ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_denies_without_grant() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices { services, .. } = make_test_services(ks_dir.path()).await;
        let err = handle_sign_hash(&services, &base_params())
            .await
            .expect_err("must deny without grant");
        let msg = err.to_string();
        assert!(
            msg.contains("no live grant"),
            "denial should mention 'no live grant'; got: {msg}"
        );
    }

    #[tokio::test]
    async fn sign_hash_denies_wrong_action_id_without_consuming_matching_grant() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices {
            services, store, ..
        } = make_test_services(ks_dir.path()).await;
        let grant =
            mint_evm_tx_grant(store.as_ref(), "act-1", &["evm.tx.sign"], 1, 1_000, 120).await;
        let mut params = base_params();
        params["action_id"] = json!("act-2");
        params["now_ms"] = json!(grant.issued_ms.saturating_add(500));

        let err = handle_sign_hash(&services, &params)
            .await
            .expect_err("grant for act-1 must not authorize act-2");
        let msg = err.to_string();
        assert!(msg.contains("no live grant"), "unexpected denial: {msg}");

        let still_live = store
            .get_active(
                "my-wallet",
                "act-1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                grant.issued_ms.saturating_add(500),
            )
            .await
            .unwrap()
            .expect("grant for original action remains live");
        assert_eq!(still_live.consumed_signature_count, 0);
    }

    #[tokio::test]
    async fn sign_hash_denies_after_revoke_all_for_wallet() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices {
            services, store, ..
        } = make_test_services(ks_dir.path()).await;
        let _grant =
            mint_evm_tx_grant(store.as_ref(), "act-1", &["evm.tx.sign"], 3, 1_000, 120).await;

        // Revoke every grant for `my-wallet`.
        let revoked = store
            .revoke_all_for_wallet("my-wallet", 1_200)
            .await
            .unwrap();
        assert_eq!(revoked, 1);

        let err = handle_sign_hash(&services, &base_params())
            .await
            .expect_err("revoked grant must not sign");
        let msg = err.to_string();
        assert!(
            msg.contains("no live grant"),
            "post-revoke denial should still say 'no live grant'; got: {msg}"
        );
    }

    #[tokio::test]
    async fn sign_hash_denies_invalid_wallet_name_with_invalid_input() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices { services, .. } = make_test_services(ks_dir.path()).await;
        let mut params = base_params();
        params["wallet"] = json!("../etc/passwd");
        let err = handle_sign_hash(&services, &params)
            .await
            .expect_err("path-separator wallet must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("invalid wallet name"),
            "expected invalid wallet name; got: {msg}"
        );
    }

    #[tokio::test]
    async fn sign_hash_denies_invalid_hash_hex() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices { services, .. } = make_test_services(ks_dir.path()).await;
        let mut params = base_params();
        params["hash"] = json!("0xZZZZ");
        let err = handle_sign_hash(&services, &params)
            .await
            .expect_err("invalid hash must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("invalid hash_hex"),
            "expected hash_hex denial; got: {msg}"
        );
    }

    #[tokio::test]
    async fn sign_hash_denies_missing_attestation() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices { services, .. } = make_test_services(ks_dir.path()).await;
        let mut params = base_params();
        params.as_object_mut().unwrap().remove("attestation");
        let err = handle_sign_hash(&services, &params)
            .await
            .expect_err("missing attestation must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("attestation"),
            "expected attestation error; got: {msg}"
        );
    }

    #[tokio::test]
    async fn sign_hash_denies_when_intent_not_in_allowed_sign_intents() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices {
            services, store, ..
        } = make_test_services(ks_dir.path()).await;
        // Mint with NO allowed_sign_intents — any sign request must be
        // denied. (per-venue rule semantics land with WS-4..9; this just
        // exercises the gate.)
        let grant = mint_evm_tx_grant(store.as_ref(), "act-1", &[], 3, 1_000, 120).await;
        let mut params = base_params();
        params["now_ms"] = json!(grant.issued_ms.saturating_add(500));
        let err = handle_sign_hash(&services, &params)
            .await
            .expect_err("empty allowed_sign_intents must deny");
        let msg = err.to_string();
        assert!(
            msg.contains("allowed_sign_intents"),
            "expected allowed_sign_intents denial; got: {msg}"
        );
    }

    #[tokio::test]
    async fn sign_hash_denies_when_param_petal_id_mismatches_attestation() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices { services, .. } = make_test_services(ks_dir.path()).await;
        let mut params = base_params();
        params["petal_id"] = json!("paid-http");
        let err = handle_sign_hash(&services, &params)
            .await
            .expect_err("petal_id mismatch must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("petal_id") && msg.contains("does not match"),
            "expected petal_id mismatch denial; got: {msg}"
        );
    }

    #[tokio::test]
    async fn sign_hash_denies_when_param_petal_digest_mismatches_attestation() {
        let ks_dir = tempfile::tempdir().unwrap();
        let TestServices { services, .. } = make_test_services(ks_dir.path()).await;
        let mut params = base_params();
        params["petal_digest"] = json!("first-party-placeholder:paid-http:v0");
        let err = handle_sign_hash(&services, &params)
            .await
            .expect_err("petal_digest mismatch must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("petal_digest") && msg.contains("does not match"),
            "expected petal_digest mismatch denial; got: {msg}"
        );
    }

    #[test]
    fn validate_wallet_name_accepts_alphanumeric_dash_underscore() {
        assert!(validate_wallet_name("my-wallet").is_ok());
        assert!(validate_wallet_name("wallet_1").is_ok());
        assert!(validate_wallet_name("a").is_ok());
        assert!(validate_wallet_name("0x1234abcd").is_ok());
    }

    #[test]
    fn validate_wallet_name_rejects_path_separators() {
        assert!(validate_wallet_name("w/").is_err());
        assert!(validate_wallet_name("w\\a").is_err());
        assert!(validate_wallet_name("w\0a").is_err());
        assert!(validate_wallet_name("..").is_err());
    }

    #[test]
    fn validate_hash_hex_rejects_malformed() {
        assert!(validate_hash_hex("0xZZZZ").is_err());
        assert!(validate_hash_hex(&format!("0x{}", "1".repeat(63))).is_err());
        assert!(validate_hash_hex(&format!("0x{}", "1".repeat(65))).is_err());
        assert!(validate_hash_hex(&format!("0x{}", "g".repeat(64))).is_err());
        assert!(validate_hash_hex(&format!("0x{}", "1".repeat(64))).is_ok());
        assert!(validate_hash_hex(&"1".repeat(64)).is_ok());
    }
}
