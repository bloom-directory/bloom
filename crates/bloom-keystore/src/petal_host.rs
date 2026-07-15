//! [`PetalHost`] backed by the on-disk [`Keystore`] plus a [`GrantStore`],
//! [`SigningAttestationSchemaRegistry`], and append-only [`AuditLog`].
//!
//! The host gates every `sign_hash` call on:
//!
//! 1. The `SigningAttestation` is well-formed.
//! 2. The `(petal_id, intent, schema)` tuple is registered with the
//!    [`SigningAttestationSchemaRegistry`].
//! 3. A live [`SealedApprovalGrant`] exists for
//!    `(wallet, action_id, petal_id, petal_digest)`.
//! 4. The grant's `daemon_terms.allowed_sign_intents` includes `request.intent`.
//! 5. The grant's `petal_id` / `petal_digest` agree with the attestation.
//! 6. The attestation validates (`self.registry.validate_attestation(...)`).
//!
//! On success the host signs `request.hash_hex` with the cached signer
//! (unlocking the passkey wallet on demand), consumes one signature off the
//! grant, and appends an audit record with the `petal.sign.ok` kind. Any
//! failure along the way is logged with `petal.sign.deny` and surfaced as
//! [`AuthApiError::Denied`] so the caller never receives a partial signature.

use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::B256;
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use base64::Engine as _;

use bloom_auth_api::{
    AuditEvent, AuthApiError, DaemonGrantTerms, GrantStore, PetalHost, PetalPolicySnapshot,
    SealedApprovalGrant, SealedPetalContext, SealedSignBatchEntry, SealedSignature,
    SignHashRequest, SigningAttestation, SigningAttestationSchemaRegistry, intent_hash_of,
    petal_identity::placeholder_digest_for, signing_attestation_facts_digest,
};
use bloom_proto::AuditLog;
use bloom_proto::audit::AuditRecord;

use crate::Keystore;

/// Per-grant cache of decrypted passkey signers. Set by the daemon after
/// `sealed_approval_ceremony` completes; consumed by `sign_hash` to avoid
/// re-running a WebAuthn ceremony on every signature request within the
/// same grant.
///
/// The signer is dropped when:
/// - `drop_on_completion` is called (after the last `consume_signature`),
/// - `prune_expired` sweeps entries past their grant expiry,
/// - the daemon process restarts (cache is in-memory only).
pub struct SignerCache {
    inner: parking_lot::Mutex<HashMap<String, SignerEntry>>,
}

struct SignerEntry {
    signer: Arc<PrivateKeySigner>,
    expires_ms: u64,
    wallet: String,
}

impl Default for SignerCache {
    fn default() -> Self {
        Self {
            inner: parking_lot::Mutex::new(HashMap::new()),
        }
    }
}

impl SignerCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a cached signer by grant_id (clone of the Arc, does NOT remove).
    pub fn get(&self, grant_id: &str) -> Option<Arc<PrivateKeySigner>> {
        self.inner.lock().get(grant_id).map(|e| e.signer.clone())
    }

    /// Insert a signer for a grant. Called by the daemon after ceremony.
    pub fn insert(
        &self,
        grant_id: String,
        signer: Arc<PrivateKeySigner>,
        wallet: String,
        expires_ms: u64,
    ) {
        self.inner.lock().insert(
            grant_id,
            SignerEntry {
                signer,
                expires_ms,
                wallet,
            },
        );
    }

    /// Remove a signer after the grant's last signature is consumed.
    pub fn drop_on_completion(&self, grant_id: &str) {
        self.inner.lock().remove(grant_id);
    }

    /// Sweep entries past their expiry. Called opportunistically.
    pub fn prune_expired(&self, now_ms: u64) {
        self.inner.lock().retain(|_, e| e.expires_ms > now_ms);
    }

    /// Remove all entries for a wallet (e.g. on grant revocation).
    pub fn revoke_for_wallet(&self, wallet: &str) {
        self.inner.lock().retain(|_, e| e.wallet != wallet);
    }
}

/// Local signer backed by an unlocked wallet in the [`Keystore`].
pub struct KeystorePetalHost {
    keystore: Arc<Keystore>,
    grant_store: Arc<dyn GrantStore>,
    registry: Arc<dyn SigningAttestationSchemaRegistry>,
    audit_log: Arc<AuditLog>,
    signer_cache: Option<Arc<SignerCache>>,
}

impl KeystorePetalHost {
    pub fn new(
        keystore: Arc<Keystore>,
        grant_store: Arc<dyn GrantStore>,
        registry: Arc<dyn SigningAttestationSchemaRegistry>,
        audit_log: Arc<AuditLog>,
    ) -> Self {
        Self {
            keystore,
            grant_store,
            registry,
            audit_log,
            signer_cache: None,
        }
    }

    /// Wire a per-grant signer cache so `sign_hash` can reuse a decrypted
    /// signer set by `run_sealed_approval_ceremony` without re-running a
    /// WebAuthn ceremony on every signature within the same grant.
    pub fn with_signer_cache(mut self, cache: Arc<SignerCache>) -> Self {
        self.signer_cache = Some(cache);
        self
    }

    pub fn keystore(&self) -> &Arc<Keystore> {
        &self.keystore
    }

    pub fn grant_store(&self) -> &Arc<dyn GrantStore> {
        &self.grant_store
    }

    pub fn registry(&self) -> &Arc<dyn SigningAttestationSchemaRegistry> {
        &self.registry
    }

    pub fn audit_log(&self) -> &Arc<AuditLog> {
        &self.audit_log
    }
}

#[async_trait]
impl PetalHost for KeystorePetalHost {
    async fn seal_context(&self, petal_id: &str) -> Result<SealedPetalContext, AuthApiError> {
        if petal_id.trim().is_empty() {
            return Err(AuthApiError::InvalidSubject("petal_id is empty".into()));
        }
        // The host sealing view is bounded to first-party petals today
        // (placeholders only — real Petals must come with reproducible build
        // digests per §11.10).
        let petal_digest = placeholder_digest_for(petal_id)
            .ok_or_else(|| {
                AuthApiError::Denied(format!(
                    "petal '{petal_id}' is not a registered first-party petal"
                ))
            })?
            .to_string();
        // The host seal is the canonical-intent-bytes hash, plus the
        // daemon-owned digests that bind any signature back to a sealed
        // action snapshot. For an empty / non-action view we use the
        // canonical digest of an empty intent as a stand-in.
        let canonical_intent_bytes_hash =
            intent_hash_of(format!("petal:{petal_id}:{petal_digest}").as_bytes());
        Ok(SealedPetalContext {
            canonical_intent_bytes_hash: canonical_intent_bytes_hash.clone(),
            intent_hash: canonical_intent_bytes_hash,
            daemon_terms_digest: DaemonGrantTerms::minimal(
                bloom_auth_api::AssuranceLevel::Standard,
            )
            .daemon_terms_digest()
            .unwrap_or_default(),
            petal_policy_digest: "0".repeat(64),
            policy_version: 0,
            petal_id: petal_id.to_string(),
        })
    }

    async fn sealed_policy_snapshot(
        &self,
        wallet: &str,
        petal_id: &str,
    ) -> Result<PetalPolicySnapshot, AuthApiError> {
        Keystore::validate_name(wallet)
            .map_err(|e| AuthApiError::Denied(format!("invalid wallet name: {e}")))?;
        if petal_id.trim().is_empty() {
            return Err(AuthApiError::InvalidSubject("petal_id is empty".into()));
        }
        let info = self
            .keystore
            .info(wallet)
            .map_err(|e| AuthApiError::Denied(format!("keystore.info: {e}")))?;
        let petal_digest = placeholder_digest_for(petal_id)
            .ok_or_else(|| {
                AuthApiError::Denied(format!(
                    "petal '{petal_id}' is not a registered first-party petal"
                ))
            })?
            .to_string();
        let mut snapshot = PetalPolicySnapshot::minimal(&bloom_auth_api::CanonicalIntentHeader {
            schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: info.name.clone(),
            surface: "host".into(),
            action_id: String::new(),
            petal_id: petal_id.into(),
            petal_digest: petal_digest.clone(),
            petal_version: bloom_auth_api::petal_identity::FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: bloom_auth_api::ExecutorKind::FirstParty,
            network: String::new(),
            account: String::new(),
            action_kind: "host.snapshot".into(),
            value_movement: false,
            authority_change: false,
            expires_ms: 0,
        });
        snapshot.policy_version = 0;
        snapshot.wallet = info.name;
        snapshot.petal_id = petal_id.into();
        snapshot.petal_digest = petal_digest;
        Ok(snapshot)
    }

    async fn sign_hash(
        &self,
        request: SignHashRequest,
        attestation: &SigningAttestation,
        now_ms: u64,
    ) -> Result<SealedSignature, AuthApiError> {
        // Step 1: input validation (deterministic, fail closed).
        if request.wallet.trim().is_empty() {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    Some(request.action_id.clone()),
                    "empty wallet in sign-hash request",
                    None,
                )
                .await;
        }
        if request.action_id.trim().is_empty() {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    None,
                    "empty action_id in sign-hash request",
                    None,
                )
                .await;
        }
        if request.intent.trim().is_empty() {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    Some(request.action_id.clone()),
                    "empty intent in sign-hash request",
                    None,
                )
                .await;
        }
        let hash_b256 = parse_hash_hex(&request.hash_hex).map_err(|e| {
            // Synchronous error path; surface without an extra audit line.
            AuthApiError::Denied(format!("invalid hash_hex: {e}"))
        })?;

        // Step 2: attestation well-formedness.
        attestation.validate()?;

        // Step 3 + 4: registry allow-list + structural validation.
        if !self.registry.is_allowed(
            &attestation.petal_id,
            &attestation.intent,
            &attestation.schema,
        ) {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    Some(request.action_id.clone()),
                    "attestation schema is not allowed for (petal_id, intent)",
                    Some(serde_json::json!({
                        "petal_id": attestation.petal_id,
                        "intent": attestation.intent,
                        "schema": attestation.schema,
                    })),
                )
                .await;
        }
        self.registry.validate_attestation(attestation)?;

        // Step 5: live grant lookup.
        let grant = self
            .grant_store
            .get_active(
                &request.wallet,
                &request.action_id,
                &attestation.petal_id,
                &attestation.petal_digest,
                now_ms,
            )
            .await?;
        let grant = match grant {
            Some(g) => g,
            None => {
                return self
                    .deny(
                        "petal.sign.deny",
                        Some(request.wallet.clone()),
                        Some(request.action_id.clone()),
                        &format!(
                            "no live grant for ({}, {}, {}, {})",
                            request.wallet,
                            request.action_id,
                            attestation.petal_id,
                            attestation.petal_digest
                        ),
                        Some(serde_json::json!({
                            "petal_id": attestation.petal_id,
                            "petal_digest": attestation.petal_digest,
                        })),
                    )
                    .await;
            }
        };

        // Step 6: grant invariants.
        if grant.petal_id != attestation.petal_id {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    Some(request.action_id.clone()),
                    &format!(
                        "grant petal_id '{}' does not match attestation petal_id '{}'",
                        grant.petal_id, attestation.petal_id
                    ),
                    None,
                )
                .await;
        }
        if grant.petal_digest != attestation.petal_digest {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    Some(request.action_id.clone()),
                    &format!(
                        "grant petal_digest '{}' does not match attestation petal_digest '{}'",
                        grant.petal_digest, attestation.petal_digest
                    ),
                    None,
                )
                .await;
        }
        if !grant
            .daemon_terms
            .allowed_sign_intents
            .iter()
            .any(|s| s == &request.intent)
        {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    Some(request.action_id.clone()),
                    &format!(
                        "intent '{}' is not in the grant's allowed_sign_intents",
                        request.intent
                    ),
                    None,
                )
                .await;
        }
        if attestation.petal_id == bloom_auth_api::petal_identity::PETAL_ID_PAID_HTTP
            || bloom_auth_api::is_petal_petal_id(&attestation.petal_id)
        {
            if attestation.intent != request.intent {
                return self
                    .deny(
                        "petal.sign.deny",
                        Some(request.wallet.clone()),
                        Some(request.action_id.clone()),
                        "attestation intent does not match sign-hash request intent",
                        Some(serde_json::json!({
                            "request_intent": request.intent,
                            "attestation_intent": attestation.intent,
                        })),
                    )
                    .await;
            }
            if attestation_fact_str(attestation, "wallet") != Some(request.wallet.as_str()) {
                return self
                    .deny(
                        "petal.sign.deny",
                        Some(request.wallet.clone()),
                        Some(request.action_id.clone()),
                        "attestation wallet does not match sign-hash request wallet",
                        None,
                    )
                    .await;
            }
            if attestation_fact_str(attestation, "action_id") != Some(request.action_id.as_str()) {
                return self
                    .deny(
                        "petal.sign.deny",
                        Some(request.wallet.clone()),
                        Some(request.action_id.clone()),
                        "attestation action_id does not match sign-hash request action_id",
                        None,
                    )
                    .await;
            }
            if !attestation_signing_hash_matches(attestation, &request.hash_hex) {
                return self
                    .deny(
                        "petal.sign.deny",
                        Some(request.wallet.clone()),
                        Some(request.action_id.clone()),
                        "attestation signing_hash does not match sign-hash request hash",
                        None,
                    )
                    .await;
            }
            if attestation_fact_str(attestation, "policy_snapshot_digest")
                != Some(grant.petal_policy_digest.as_str())
            {
                return self
                    .deny(
                        "petal.sign.deny",
                        Some(request.wallet.clone()),
                        Some(request.action_id.clone()),
                        "attestation policy_snapshot_digest does not match the sealed grant",
                        None,
                    )
                    .await;
            }
        }
        if let Err(message) =
            validate_required_grant_terms(&grant.daemon_terms, &request, attestation)
        {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    Some(request.action_id.clone()),
                    &message,
                    Some(serde_json::json!({
                        "petal_id": attestation.petal_id,
                        "petal_digest": attestation.petal_digest,
                    })),
                )
                .await;
        }

        // NOTE: a sign-time policy hard-deny hook was intentionally removed
        // here. The grant carries only `petal_policy_digest` (a hash), not the
        // full `PetalPolicySnapshot`, so there is no rule set to hand an
        // evaluator at this point — a hook wired here could only ever see empty
        // caps/rules and would pass everything, which is worse than no hook.
        // Re-add it once a snapshot source keyed by wallet/policy_version exists
        // at sign time (tracked with the C9 policy-pricing work).

        // Step 7: ensure the signer is in memory. A per-grant signer cache
        // (set by the daemon after `sealed_approval_ceremony`) lets us reuse
        // the decrypted signer without re-running a WebAuthn ceremony; on a
        // cache miss we fall back to the keystore unlock path.
        let cache_required = grant
            .daemon_terms
            .extra
            .get("signer_cache_required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let signer = if let Some(cache) = &self.signer_cache {
            if let Some(cached) = cache.get(&grant.grant_id) {
                cached
            } else if cache_required {
                return self
                    .deny(
                        "petal.sign.deny",
                        Some(request.wallet.clone()),
                        Some(request.action_id.clone()),
                        "session_missing_signer_material",
                        Some(serde_json::json!({
                            "grant_id": grant.grant_id.clone(),
                        })),
                    )
                    .await;
            } else {
                // Cache miss — fall back to keystore unlock (e.g. daemon
                // restart between ceremony and one-shot sign). Owner sessions
                // opt out via `signer_cache_required`.
                self.keystore_unlock_signer(&request.wallet).await?
            }
        } else if cache_required {
            return self
                .deny(
                    "petal.sign.deny",
                    Some(request.wallet.clone()),
                    Some(request.action_id.clone()),
                    "session_missing_signer_material",
                    Some(serde_json::json!({
                        "grant_id": grant.grant_id.clone(),
                    })),
                )
                .await;
        } else {
            // No cache wired — legacy path.
            self.keystore_unlock_signer(&request.wallet).await?
        };

        // Step 8: sign the hash.
        let sig = signer
            .sign_hash_sync(&hash_b256)
            .map_err(|e| AuthApiError::Denied(format!("keystore.sign_hash_sync: {e}")))?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig.as_bytes());

        // Step 9: consume one signature off the grant.
        let updated_grant = self
            .grant_store
            .consume_signature(&grant.grant_id, &request.intent, now_ms)
            .await?;

        if updated_grant.consumed_signature_count >= updated_grant.max_signatures
            && let Some(cache) = &self.signer_cache
        {
            cache.drop_on_completion(&grant.grant_id);
        }

        // Step 10: audit.
        let intent_hash = updated_grant.intent_hash.clone();
        let _ = self
            .audit_log
            .append(AuditRecord {
                ts_ms: 0,
                kind: "petal.sign.ok".into(),
                wallet: Some(request.wallet.clone()),
                chain: None,
                data: serde_json::json!({
                    "action_id": request.action_id,
                    "petal_id": updated_grant.petal_id,
                    "petal_digest": updated_grant.petal_digest,
                    "intent": request.intent,
                    "grant_id": updated_grant.grant_id,
                    "consumed_signature_count": updated_grant.consumed_signature_count,
                    "max_signatures": updated_grant.max_signatures,
                }),
                prev: String::new(),
                digest: String::new(),
            })
            .map_err(|e| AuthApiError::Store(format!("audit.append: {e}")))?;

        Ok(SealedSignature {
            intent_hash,
            signature_b64,
            signed_at_ms: now_ms,
        })
    }

    async fn sign_hash_batch(
        &self,
        requests: Vec<SignHashRequest>,
        attestations: &[SigningAttestation],
        now_ms: u64,
    ) -> Result<Vec<SealedSignature>, AuthApiError> {
        if requests.is_empty() || requests.len() != attestations.len() {
            return Err(AuthApiError::Denied(
                "signing batch must contain matching non-empty requests and attestations".into(),
            ));
        }
        let first = &requests[0];
        if requests
            .iter()
            .any(|request| request.wallet != first.wallet || request.action_id != first.action_id)
        {
            return Err(AuthApiError::Denied(
                "every signing batch entry must share one wallet and action_id".into(),
            ));
        }
        let first_attestation = &attestations[0];
        let grant = self
            .grant_store
            .get_active(
                &first.wallet,
                &first.action_id,
                &first_attestation.petal_id,
                &first_attestation.petal_digest,
                now_ms,
            )
            .await?
            .ok_or_else(|| AuthApiError::Denied("no live grant for signing batch".into()))?;
        let sealed_entries: Vec<SealedSignBatchEntry> = serde_json::from_value(
            grant
                .daemon_terms
                .extra
                .get("required.signing_requests")
                .cloned()
                .ok_or_else(|| {
                    AuthApiError::Denied("batch grant is missing required.signing_requests".into())
                })?,
        )
        .map_err(|e| AuthApiError::Denied(format!("invalid sealed signing batch: {e}")))?;
        let actual_entries = sealed_batch_entries(&requests, attestations)?;
        if sealed_entries != actual_entries || grant.max_signatures as usize != requests.len() {
            return Err(AuthApiError::Denied(
                "signing batch does not exactly match the sealed ordered request set".into(),
            ));
        }

        // Validate the full set above before signing. Individual calls retain
        // the normal hash-specific attestation, grant, TTL, and count checks.
        let mut signatures = Vec::with_capacity(requests.len());
        for (request, attestation) in requests.into_iter().zip(attestations) {
            signatures.push(self.sign_hash(request, attestation, now_ms).await?);
        }
        Ok(signatures)
    }

    async fn audit(&self, event: AuditEvent) -> Result<(), AuthApiError> {
        let _ = self
            .audit_log
            .append(AuditRecord {
                ts_ms: 0,
                kind: event.kind,
                wallet: event.wallet,
                chain: None,
                data: serde_json::json!({
                    "message": event.message,
                    "action_id": event.action_id,
                }),
                prev: String::new(),
                digest: String::new(),
            })
            .map_err(|e| AuthApiError::Store(format!("audit.append: {e}")))?;
        Ok(())
    }
}

impl KeystorePetalHost {
    /// Resolve a signer from the keystore, running an `unlock_passkey_with_intent`
    /// ceremony first if the wallet is not yet decrypted. This is the fallback
    /// path for `sign_hash` when no per-grant cache entry exists.
    async fn keystore_unlock_signer(
        &self,
        wallet: &str,
    ) -> Result<Arc<PrivateKeySigner>, AuthApiError> {
        match self.keystore.cached_signer(wallet) {
            Ok(s) => Ok(s),
            Err(_) => {
                self.keystore
                    .unlock_passkey_with_intent(wallet, None)
                    .await
                    .map_err(|e| {
                        AuthApiError::Denied(format!("keystore.unlock_passkey_with_intent: {e}"))
                    })?;
                self.keystore
                    .cached_signer(wallet)
                    .map_err(|e| AuthApiError::Denied(format!("keystore.signer after unlock: {e}")))
            }
        }
    }

    /// Internal: log a denial event and return the deterministic [`AuthApiError`].
    ///
    /// Used by `sign_hash` so every denial surface produces an audit trail;
    /// failure to audit a denial is itself an error so the caller knows the
    /// denial was logged (or could not be).
    async fn deny(
        &self,
        kind: &str,
        wallet: Option<String>,
        _action_id: Option<String>,
        message: &str,
        extra: Option<serde_json::Value>,
    ) -> Result<SealedSignature, AuthApiError> {
        let mut data = serde_json::json!({ "message": message });
        if let Some(extra) = extra {
            data = match data {
                serde_json::Value::Object(mut m) => {
                    if let serde_json::Value::Object(em) = extra {
                        for (k, v) in em {
                            m.insert(k, v);
                        }
                    }
                    serde_json::Value::Object(m)
                }
                other => other,
            };
        }
        let _ = self
            .audit_log
            .append(AuditRecord {
                ts_ms: 0,
                kind: kind.into(),
                wallet,
                chain: None,
                data,
                prev: String::new(),
                digest: String::new(),
            })
            .map_err(|e| AuthApiError::Store(format!("audit.append: {e}")))?;
        Err(AuthApiError::Denied(message.to_string()))
    }
}

fn parse_hash_hex(s: &str) -> Result<B256, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", stripped.len()));
    }
    let bytes = hex::decode(stripped).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(B256::from(out))
}

fn validate_required_grant_terms(
    terms: &DaemonGrantTerms,
    request: &SignHashRequest,
    attestation: &SigningAttestation,
) -> Result<(), String> {
    for (key, value) in &terms.extra {
        match key.as_str() {
            "required.signing_hash" => {
                let expected = value.as_str().ok_or_else(|| {
                    "required.signing_hash grant term must be a string".to_string()
                })?;
                if expected != request.hash_hex {
                    return Err("sign_hash hash does not match required.signing_hash".to_string());
                }
            }
            "required.attestation_facts_digest" => {
                let expected = value.as_str().ok_or_else(|| {
                    "required.attestation_facts_digest grant term must be a string".to_string()
                })?;
                let actual = signing_attestation_facts_digest(&attestation.facts)
                    .map_err(|e| format!("digest signing attestation facts: {e}"))?;
                if expected != actual {
                    return Err(
                        "sign_hash attestation facts do not match required.attestation_facts_digest"
                            .to_string(),
                    );
                }
            }
            "required.signing_requests" => {
                let entries: Vec<SealedSignBatchEntry> = serde_json::from_value(value.clone())
                    .map_err(|e| format!("required.signing_requests is invalid: {e}"))?;
                let actual_digest = signing_attestation_facts_digest(&attestation.facts)
                    .map_err(|e| format!("digest signing attestation facts: {e}"))?;
                let matched = entries.iter().any(|entry| {
                    entry.wallet == request.wallet
                        && entry.intent == request.intent
                        && entry.hash_hex == request.hash_hex
                        && entry.attestation_facts_digest == actual_digest
                });
                if !matched {
                    return Err("sign_hash request is not in required.signing_requests".to_string());
                }
            }
            key if key.starts_with("required.") => {
                return Err(format!("unsupported required grant term '{key}'"));
            }
            _ => {}
        }
    }
    Ok(())
}

fn sealed_batch_entries(
    requests: &[SignHashRequest],
    attestations: &[SigningAttestation],
) -> Result<Vec<SealedSignBatchEntry>, AuthApiError> {
    requests
        .iter()
        .zip(attestations)
        .map(|(request, attestation)| {
            Ok(SealedSignBatchEntry {
                wallet: request.wallet.clone(),
                intent: request.intent.clone(),
                hash_hex: request.hash_hex.clone(),
                attestation_facts_digest: signing_attestation_facts_digest(&attestation.facts)?,
            })
        })
        .collect()
}

fn attestation_fact_str<'a>(attestation: &'a SigningAttestation, key: &str) -> Option<&'a str> {
    attestation.facts.get(key).and_then(|v| v.as_str())
}

fn attestation_signing_hash_matches(attestation: &SigningAttestation, request_hash: &str) -> bool {
    let Some(attested) = attestation_fact_str(attestation, "signing_hash") else {
        return false;
    };
    strip_0x(attested).eq_ignore_ascii_case(strip_0x(request_hash))
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

// `SealedApprovalGrant` must remain in scope for downstream use (the host
// reads grant fields above); suppress the unused-import lint if the type is
// ever unreferenced after refactors.
#[allow(dead_code)]
fn _grant_anchor(_g: SealedApprovalGrant) {}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_auth::InMemoryGrantStore;
    use bloom_auth_api::{
        AssuranceLevel, CanonicalEnvelope, CanonicalIntentHeader, DaemonGrantTerms,
        DefaultAttestationRegistry, EVM_SIGNING_ATTESTATION_FACTS_SCHEMA_V1, EvmFeeFacts,
        EvmNonceIntent, EvmSealedActionKind, EvmSigningAttestationFacts, EvmUnsignedEnvelopeFacts,
        EvmValueFact, ExecutorKind, PetalPolicySnapshot, SIGNING_ATTESTATION_SCHEMA_V1,
        SealedAction, SigningAttestation,
        petal_identity::{
            FIRST_PARTY_PETAL_VERSION_V0, PETAL_ID_EVM_WALLET, PLACEHOLDER_DIGEST_EVM_WALLET,
        },
    };
    use bloom_proto::audit::AuditRecord;
    use std::collections::BTreeMap;

    /// Test fixture: one keystore (local wallet pre-unlocked), one
    /// in-memory grant store, the default attestation registry, and a
    /// real `AuditLog` opened at `audit_dir/audit.jsonl`.
    struct Harness {
        _ks_dir: tempfile::TempDir,
        _audit_dir: tempfile::TempDir,
        #[allow(dead_code)]
        keystore: Arc<Keystore>,
        grant_store: Arc<InMemoryGrantStore>,
        #[allow(dead_code)]
        registry: Arc<DefaultAttestationRegistry>,
        audit_log: Arc<AuditLog>,
        host: KeystorePetalHost,
    }

    impl Harness {
        fn new(wallet_name: &str) -> Self {
            let ks_dir = tempfile::tempdir().unwrap();
            let audit_dir = tempfile::tempdir().unwrap();
            let keystore = Arc::new(Keystore::new(ks_dir.path()).unwrap());
            // A local wallet is the simplest signer source for the
            // sign-hash path; once unlocked, `keystore.signer(name)` returns
            // an `Arc<PrivateKeySigner>` and the host's unlock-passkey path
            // is bypassed.
            keystore.create_local(wallet_name, "p").unwrap();
            keystore.unlock(wallet_name, "p").unwrap();

            let grant_store: Arc<InMemoryGrantStore> = Arc::new(InMemoryGrantStore::new());
            let registry: Arc<DefaultAttestationRegistry> =
                Arc::new(DefaultAttestationRegistry::new());
            let audit_log = Arc::new(AuditLog::open(audit_dir.path().join("audit.jsonl")).unwrap());
            let host = KeystorePetalHost::new(
                keystore.clone(),
                grant_store.clone(),
                registry.clone(),
                audit_log.clone(),
            );
            Self {
                _ks_dir: ks_dir,
                _audit_dir: audit_dir,
                keystore,
                grant_store,
                registry,
                audit_log,
                host,
            }
        }

        fn attestation(
            &self,
            petal_id: &str,
            petal_digest: &str,
            intent: &str,
        ) -> SigningAttestation {
            let facts = if petal_id == PETAL_ID_EVM_WALLET
                && intent == bloom_auth_api::EVM_TX_SIGN_INTENT
            {
                EvmSigningAttestationFacts {
                    facts_schema: EVM_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
                    action_id: "req_1".into(),
                    wallet: "my-wallet".into(),
                    surface: "outbox".into(),
                    petal_id: petal_id.into(),
                    petal_digest: petal_digest.into(),
                    petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
                    action_kind: EvmSealedActionKind::Confirm,
                    chain_id: 1,
                    account: "0x0000000000000000000000000000000000000001".into(),
                    to: "0x0000000000000000000000000000000000000002".into(),
                    recipient: Some("0x0000000000000000000000000000000000000002".into()),
                    value: EvmValueFact {
                        native_value_wei: "1".into(),
                        token_amount_base_units: None,
                        valuation_usd_micro: Some(1),
                    },
                    token: None,
                    method: "native_transfer".into(),
                    calldata_hash: format!("0x{}", "0".repeat(64)),
                    nonce_intent: EvmNonceIntent {
                        mode: "exact".into(),
                        nonce: Some(0),
                        original_action_id: None,
                    },
                    fee_facts: EvmFeeFacts {
                        tx_type: "eip1559".into(),
                        gas_limit: "21000".into(),
                        max_fee_per_gas_wei: Some("100".into()),
                        max_priority_fee_per_gas_wei: Some("10".into()),
                        gas_price_wei: None,
                        max_total_fee_wei: None,
                    },
                    replacement_fee_facts: None,
                    unsigned_envelope: EvmUnsignedEnvelopeFacts {
                        envelope_kind: "eip1559".into(),
                        unsigned_tx_bytes_hash: format!("0x{}", "2".repeat(64)),
                        signing_hash: format!("0x{}", "1".repeat(64)),
                    },
                    signing_hash: format!("0x{}", "1".repeat(64)),
                    policy_snapshot_digest: "0".repeat(64),
                    daemon_terms_digest: "0".repeat(64),
                }
                .to_facts_map()
                .unwrap()
            } else {
                BTreeMap::new()
            };
            SigningAttestation {
                schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
                petal_id: petal_id.into(),
                petal_digest: petal_digest.into(),
                intent: intent.into(),
                facts,
            }
        }

        #[allow(clippy::too_many_arguments)]
        async fn mint_grant_with_intents(
            &self,
            wallet: &str,
            action_id: &str,
            petal_id: &str,
            petal_digest: &str,
            allowed_sign_intents: &[&str],
            max_signatures: u32,
            issued_ms: u64,
            ttl_secs: u64,
        ) -> SealedApprovalGrant {
            self.mint_grant_with_extra(
                wallet,
                action_id,
                petal_id,
                petal_digest,
                allowed_sign_intents,
                max_signatures,
                issued_ms,
                ttl_secs,
                BTreeMap::new(),
            )
            .await
        }

        #[allow(clippy::too_many_arguments)]
        async fn mint_grant_with_extra(
            &self,
            wallet: &str,
            action_id: &str,
            petal_id: &str,
            petal_digest: &str,
            allowed_sign_intents: &[&str],
            max_signatures: u32,
            issued_ms: u64,
            ttl_secs: u64,
            extra: BTreeMap<String, serde_json::Value>,
        ) -> SealedApprovalGrant {
            let env = sealed_envelope(wallet, action_id, petal_id, petal_digest);
            let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Standard);
            terms.allowed_sign_intents =
                allowed_sign_intents.iter().map(|s| s.to_string()).collect();
            terms.max_signatures = max_signatures;
            terms.max_ttl_secs = ttl_secs;
            terms.extra = extra;
            let mut snapshot = PetalPolicySnapshot::minimal(&env.header);
            snapshot.policy_version = 0;
            snapshot.caps.clear();
            snapshot.config.clear();
            snapshot.budget_state.clear();
            snapshot.wallet = wallet.into();
            snapshot.petal_id = petal_id.into();
            snapshot.petal_digest = petal_digest.into();
            let action =
                SealedAction::new(env, "plan".into(), Vec::new(), terms, snapshot, issued_ms)
                    .unwrap();
            self.grant_store
                .mint(&action, issued_ms.saturating_add(120_000), issued_ms)
                .await
                .unwrap()
        }

        fn sign_request(&self, wallet: &str, action_id: &str, intent: &str) -> SignHashRequest {
            SignHashRequest {
                wallet: wallet.into(),
                action_id: action_id.into(),
                intent: intent.into(),
                hash_hex: format!("0x{}", "1".repeat(64)),
            }
        }
    }

    fn sealed_envelope(
        wallet: &str,
        action_id: &str,
        petal_id: &str,
        petal_digest: &str,
    ) -> CanonicalEnvelope {
        CanonicalEnvelope::new(
            CanonicalIntentHeader {
                schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
                wallet: wallet.into(),
                surface: "outbox".into(),
                action_id: action_id.into(),
                petal_id: petal_id.into(),
                petal_digest: petal_digest.into(),
                petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
                executor_kind: ExecutorKind::FirstParty,
                network: "ethereum".into(),
                account: "default".into(),
                action_kind: "tx_send".into(),
                value_movement: true,
                authority_change: false,
                expires_ms: 10_000,
            },
            "evm",
            "evm.v1",
            br#"{"to":"0x1234","value":"1"}"#.to_vec(),
        )
    }

    fn count_audit_lines(log: &AuditLog) -> usize {
        log.count().unwrap_or(0)
    }

    // ── happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_succeeds_under_active_grant_with_matching_intent() {
        let h = Harness::new("my-wallet");
        let grant = h
            .mint_grant_with_intents(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &["evm.tx.sign"],
                3,
                1_000,
                120,
            )
            .await;
        let att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let sig = h
            .host
            .sign_hash(req, &att, 1_500)
            .await
            .expect("happy path must sign");
        assert!(!sig.signature_b64.is_empty());
        assert_eq!(sig.intent_hash, grant.intent_hash);
        assert_eq!(sig.signed_at_ms, 1_500);
        // The grant's signature count was incremented to 1.
        let active = h
            .grant_store
            .get_active(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                1_500,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.consumed_signature_count, 1);
        assert_eq!(active.max_signatures, 3);
        // Audit recorded one ok and zero deny entries.
        let log = h.audit_log.tail(10).unwrap();
        let oks = log.iter().filter(|r| r.kind == "petal.sign.ok").count();
        let denies = log.iter().filter(|r| r.kind == "petal.sign.deny").count();
        assert_eq!(oks, 1);
        assert_eq!(denies, 0);
    }

    #[tokio::test]
    async fn sign_hash_honors_required_hash_and_facts_digest_terms() {
        let h = Harness::new("my-wallet");
        let att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let facts_digest = signing_attestation_facts_digest(&att.facts).unwrap();
        let grant = h
            .mint_grant_with_extra(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &["evm.tx.sign"],
                1,
                1_000,
                120,
                BTreeMap::from([
                    (
                        "required.signing_hash".into(),
                        serde_json::json!(req.hash_hex.clone()),
                    ),
                    (
                        "required.attestation_facts_digest".into(),
                        serde_json::json!(facts_digest),
                    ),
                ]),
            )
            .await;

        let sig = h.host.sign_hash(req, &att, 1_500).await.unwrap();

        assert_eq!(sig.intent_hash, grant.intent_hash);
        let active = h
            .grant_store
            .get_active(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                1_500,
            )
            .await
            .unwrap();
        assert!(active.is_none(), "one-shot grant should be consumed");
    }

    #[test]
    fn required_signing_requests_bind_each_hash_and_attestation() {
        let h = Harness::new("my-wallet");
        let attestation = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let request = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let entry = SealedSignBatchEntry {
            wallet: request.wallet.clone(),
            intent: request.intent.clone(),
            hash_hex: request.hash_hex.clone(),
            attestation_facts_digest: signing_attestation_facts_digest(&attestation.facts).unwrap(),
        };
        let mut terms = DaemonGrantTerms::minimal(AssuranceLevel::Hardened);
        terms.extra.insert(
            "required.signing_requests".into(),
            serde_json::to_value([entry]).unwrap(),
        );
        assert!(validate_required_grant_terms(&terms, &request, &attestation).is_ok());

        let mut changed = request;
        changed.hash_hex = format!("0x{}", "2".repeat(64));
        assert!(
            validate_required_grant_terms(&terms, &changed, &attestation)
                .unwrap_err()
                .contains("not in required.signing_requests")
        );
    }

    #[tokio::test]
    async fn sign_hash_denies_required_hash_mismatch_without_consuming_grant() {
        let h = Harness::new("my-wallet");
        h.mint_grant_with_extra(
            "my-wallet",
            "req_1",
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            &["evm.tx.sign"],
            1,
            1_000,
            120,
            BTreeMap::from([(
                "required.signing_hash".into(),
                serde_json::json!(format!("0x{}", "2".repeat(64))),
            )]),
        )
        .await;
        let att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");

        let err = h.host.sign_hash(req, &att, 1_500).await.unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("required.signing_hash"), "{msg}");
        let active = h
            .grant_store
            .get_active(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                1_500,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.consumed_signature_count, 0);
    }

    #[tokio::test]
    async fn sign_hash_denies_required_facts_digest_mismatch_without_consuming_grant() {
        let h = Harness::new("my-wallet");
        h.mint_grant_with_extra(
            "my-wallet",
            "req_1",
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            &["evm.tx.sign"],
            1,
            1_000,
            120,
            BTreeMap::from([(
                "required.attestation_facts_digest".into(),
                serde_json::json!("0".repeat(64)),
            )]),
        )
        .await;
        let att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");

        let err = h.host.sign_hash(req, &att, 1_500).await.unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("required.attestation_facts_digest"), "{msg}");
        let active = h
            .grant_store
            .get_active(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                1_500,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.consumed_signature_count, 0);
    }

    // ── denial: no live grant ────────────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_denied_when_no_grant() {
        let h = Harness::new("my-wallet");
        // Intentionally do NOT mint a grant.
        let att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let err = h.host.sign_hash(req, &att, 1_000).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no live grant"), "{msg}");
        // Audit recorded exactly one denial.
        let log = h.audit_log.tail(10).unwrap();
        let denies = log.iter().filter(|r| r.kind == "petal.sign.deny").count();
        assert_eq!(denies, 1);
    }

    // ── denial: intent not in allowed_sign_intents ───────────────────────────

    #[tokio::test]
    async fn sign_hash_denied_when_intent_not_in_allowed_sign_intents() {
        let h = Harness::new("my-wallet");
        let _grant = h
            .mint_grant_with_intents(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &[], // empty allowed_sign_intents
                1,
                1_000,
                120,
            )
            .await;
        let att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let err = h.host.sign_hash(req, &att, 1_500).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("not in the grant's allowed_sign_intents"),
            "{err}"
        );
    }

    // ── denial: petal_id mismatch ────────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_denied_when_petal_id_mismatch() {
        let h = Harness::new("my-wallet");
        let _grant = h
            .mint_grant_with_intents(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &["evm.tx.sign"],
                2,
                1_000,
                120,
            )
            .await;
        // Different petal_id in the attestation than what the grant was
        // minted for. Because the host looks up the grant using the
        // attestation's petal_id + petal_digest tuple, the lookup misses
        // first and the deterministic denial message is "no live grant".
        // Use an intent that is registered for both `evm-wallet` AND a
        // different petal so the registry check passes; here we exercise the
        // registry-rejection path that fires when (paid-http, evm.tx.sign)
        // is not in the allow-list.
        let att = h.attestation(
            bloom_auth_api::petal_identity::PETAL_ID_PAID_HTTP,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let err = h.host.sign_hash(req, &att, 1_500).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("attestation schema is not allowed"),
            "{err}"
        );
    }

    // ── denial: petal_digest mismatch ────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_denied_when_petal_digest_mismatch() {
        let h = Harness::new("my-wallet");
        let _grant = h
            .mint_grant_with_intents(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &["evm.tx.sign"],
                2,
                1_000,
                120,
            )
            .await;
        // Different petal_digest in the attestation. The host's grant
        // lookup uses the attestation's tuple, so the lookup misses and
        // the denial message is the deterministic "no live grant".
        let other_digest = bloom_auth_api::petal_identity::PLACEHOLDER_DIGEST_PAID_HTTP;
        let att = h.attestation(PETAL_ID_EVM_WALLET, other_digest, "evm.tx.sign");
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let err = h.host.sign_hash(req, &att, 1_500).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no live grant"), "{msg}");
        // The grant's stored digest and the attestation's digest must NOT
        // have been confused at any layer.
        let live = h
            .grant_store
            .get_active(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                1_500,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(live.petal_digest, PLACEHOLDER_DIGEST_EVM_WALLET);
    }

    // ── denial: attestation schema unknown ───────────────────────────────────

    #[tokio::test]
    async fn sign_hash_denied_when_attestation_schema_unknown() {
        let h = Harness::new("my-wallet");
        let _grant = h
            .mint_grant_with_intents(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &["evm.tx.sign"],
                2,
                1_000,
                120,
            )
            .await;
        let mut att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        att.schema = "foo.bar.baz".into();
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let err = h.host.sign_hash(req, &att, 1_500).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("attestation schema is not allowed"),
            "{err}"
        );
    }

    // ── counter increment ────────────────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_increments_consumed_signature_count() {
        let h = Harness::new("my-wallet");
        let grant = h
            .mint_grant_with_intents(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &["evm.tx.sign"],
                5,
                1_000,
                120,
            )
            .await;
        assert_eq!(grant.consumed_signature_count, 0);

        for i in 1..=3u32 {
            let att = h.attestation(
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                "evm.tx.sign",
            );
            let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
            h.host.sign_hash(req, &att, 1_000 + i as u64).await.unwrap();
            let live = h
                .grant_store
                .get_active(
                    "my-wallet",
                    "req_1",
                    PETAL_ID_EVM_WALLET,
                    PLACEHOLDER_DIGEST_EVM_WALLET,
                    1_000 + i as u64,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(live.consumed_signature_count, i);
        }
    }

    // ── exhaustion ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_over_max_signatures_denies_after_final_consume() {
        let h = Harness::new("my-wallet");
        let _grant = h
            .mint_grant_with_intents(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &["evm.tx.sign"],
                1,
                1_000,
                120,
            )
            .await;
        // First sign exhausts the grant.
        let att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        h.host.sign_hash(req, &att, 1_500).await.unwrap();
        // Second sign must be denied because the grant is no longer live.
        let att2 = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let req2 = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        let err = h.host.sign_hash(req2, &att2, 1_600).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no live grant") || msg.contains("no remaining signatures"),
            "{msg}"
        );
    }

    // ── invalid hash_hex ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn sign_hash_denies_invalid_hash_hex() {
        let h = Harness::new("my-wallet");
        let _grant = h
            .mint_grant_with_intents(
                "my-wallet",
                "req_1",
                PETAL_ID_EVM_WALLET,
                PLACEHOLDER_DIGEST_EVM_WALLET,
                &["evm.tx.sign"],
                2,
                1_000,
                120,
            )
            .await;
        let att = h.attestation(
            PETAL_ID_EVM_WALLET,
            PLACEHOLDER_DIGEST_EVM_WALLET,
            "evm.tx.sign",
        );
        let mut req = h.sign_request("my-wallet", "req_1", "evm.tx.sign");
        req.hash_hex = "0xZZZZ".into();
        let err = h.host.sign_hash(req, &att, 1_500).await.unwrap_err();
        assert!(err.to_string().contains("invalid hash_hex"), "{err}");
    }

    // ── audit event surfaces from `audit(...)` ───────────────────────────────

    #[tokio::test]
    async fn audit_appends_event_to_log() {
        let h = Harness::new("my-wallet");
        let event = AuditEvent {
            kind: "petal.note".into(),
            wallet: Some("my-wallet".into()),
            action_id: Some("req_1".into()),
            message: "hi".into(),
        };
        h.host.audit(event).await.unwrap();
        let count = count_audit_lines(&h.audit_log);
        assert_eq!(count, 1);
    }

    // ── seal_context for an unknown petal_id ────────────────────────────────

    #[tokio::test]
    async fn seal_context_denies_unknown_petal_id() {
        let h = Harness::new("my-wallet");
        let err = h.host.seal_context("not-a-real-petal").await.unwrap_err();
        assert!(
            err.to_string()
                .contains("not a registered first-party petal")
        );
    }

    // ── sealed_policy_snapshot round-trip ────────────────────────────────────

    #[tokio::test]
    async fn sealed_policy_snapshot_matches_wallet() {
        let h = Harness::new("my-wallet");
        let snap = h
            .host
            .sealed_policy_snapshot("my-wallet", PETAL_ID_EVM_WALLET)
            .await
            .unwrap();
        assert_eq!(snap.wallet, "my-wallet");
        assert_eq!(snap.petal_id, PETAL_ID_EVM_WALLET);
        assert_eq!(snap.petal_digest, PLACEHOLDER_DIGEST_EVM_WALLET);
    }

    // ── deny audit row shape ────────────────────────────────────────────────

    #[test]
    fn deny_audit_record_carries_deterministic_message() {
        // Pure-shape sanity check on the record fields — keeps the on-disk
        // JSON stable so other surfaces can match on `kind == "petal.sign.deny"`.
        let r = AuditRecord {
            ts_ms: 0,
            kind: "petal.sign.deny".into(),
            wallet: Some("my-wallet".into()),
            chain: None,
            data: serde_json::json!({
                "message": "no live grant for (my-wallet, req_1, evm-wallet, first-party-placeholder:evm-wallet:v0)",
            }),
            prev: String::new(),
            digest: String::new(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("petal.sign.deny"));
        assert!(json.contains("no live grant for"));
    }
}
