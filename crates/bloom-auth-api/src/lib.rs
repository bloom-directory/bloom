//! Shared authorization API for Bloom Sealed Approval.
//!
//! This crate intentionally contains only stable data types and traits. The
//! concrete store, verifier, and signer integrations live outside the VFS-facing
//! crates so NFS/petal surfaces do not pull in the whole authorization TCB.
//!
//! The data model follows `docs/specs/2026-07-02-sealed-approval.md`:
//!
//! - [`CanonicalEnvelope`] is the immutable intent-hash preimage (§5.2);
//! - [`SealedAction`] wraps the envelope with plan, policy checks,
//!   [`DaemonGrantTerms`], and a [`PetalPolicySnapshot`] (§6.1);
//! - [`ApprovalChallenge`] is the daemon-issued WebAuthn challenge preimage
//!   (§5.7, §6.2);
//! - [`SignedApproval`] is the `approval.json` record (§6.3);
//! - [`SealedApprovalGrant`] is the in-memory, never-persisted grant (§6.4);
//! - [`SigningAttestation`] is the structured Petal signing claim (§8).

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema tag for [`SignedApproval`] (`approval.json`).
pub const APPROVAL_SCHEMA_V1: &str = "bloom.approval.v1";
/// Schema tag for [`ApprovalChallenge`] (`challenge.json` / the signed preimage).
pub const APPROVAL_CHALLENGE_SCHEMA_V1: &str = "bloom.approval_challenge.v1";
/// Schema tag for [`SealedAction`] records in daemon-controlled storage.
pub const SEALED_ACTION_SCHEMA_V1: &str = "bloom.sealed_action.v1";
/// Schema tag for [`SigningAttestation`] envelopes.
pub const SIGNING_ATTESTATION_SCHEMA_V1: &str = "bloom.signing_attestation.v1";
/// Schema tag for [`CanonicalEnvelope`].
///
/// v2: the canonical header gained Petal identity (`petal_id`, `petal_digest`,
/// `petal_version`, `executor_kind`) and `expires_ms`, replacing `executor_id`.
pub const CANONICAL_ENVELOPE_SCHEMA_V2: &str = "bloom.canonical_envelope.v2";
/// Schema tag callers should place in [`CanonicalIntentHeader::schema`].
pub const CANONICAL_INTENT_HEADER_SCHEMA_V2: &str = "bloom.intent_header.v2";

/// Domain tag for [`intent_hash_of`].
///
/// Spec §5.2: this tag MUST be bumped whenever the canonical schema changes.
/// v2 corresponds to [`CANONICAL_ENVELOPE_SCHEMA_V2`] (Petal identity +
/// `expires_ms` on the header). Hashes produced under `bloom.intent.v1` refer
/// to the retired v1 envelope schema and can no longer be recomputed.
pub const INTENT_HASH_DOMAIN: &[u8] = b"bloom.intent.v2";
/// Domain tag for the WebAuthn approval challenge hash (§5.7).
pub const APPROVAL_CHALLENGE_DOMAIN: &[u8] = b"bloom.approval.v1";
/// Domain tag for [`DaemonGrantTerms::daemon_terms_digest`].
pub const DAEMON_TERMS_DIGEST_DOMAIN: &[u8] = b"bloom.daemon_terms.v1";
/// Domain tag for [`PetalPolicySnapshot::petal_policy_digest`].
pub const PETAL_POLICY_DIGEST_DOMAIN: &[u8] = b"bloom.petal_policy.v1";

/// Hard ceiling on Sealed Approval Grant lifetime (§6.4 recommended default).
pub const GRANT_MAX_TTL_MS: u64 = 120_000;

/// First-party Petal identity constants and placeholder digests (spec §11.10).
pub mod petal_identity {
    /// `petal_id` for the EVM wallet tx first-party Petal (surface `wallets`/`outbox`).
    pub const PETAL_ID_EVM_WALLET: &str = "evm-wallet";
    /// `petal_id` for the paid HTTP (x402/MPP) first-party Petal (surface `requests`).
    pub const PETAL_ID_PAID_HTTP: &str = "paid-http";
    /// `petal_id` for the Polymarket first-party Petal.
    pub const PETAL_ID_POLYMARKET: &str = "polymarket";
    /// `petal_id` for the Hyperliquid first-party Petal.
    pub const PETAL_ID_HYPERLIQUID: &str = "hyperliquid";
    /// `petal_id` for the DeFi first-party Petal.
    pub const PETAL_ID_DEFI: &str = "defi";
    /// `petal_id` for the wallet-policy first-party Petal (policy edits,
    /// re-key/passkey management).
    pub const PETAL_ID_WALLET_POLICY: &str = "wallet-policy";

    /// `petal_version` recorded for first-party placeholder identities.
    pub const FIRST_PARTY_PETAL_VERSION_V0: &str = "v0";

    /// Prefix shared by every first-party placeholder digest.
    pub const PLACEHOLDER_DIGEST_PREFIX: &str = "first-party-placeholder:";

    // TODO(petal-digest-provenance): every placeholder digest below is
    // temporary and is NOT a real tamper-evidence boundary. It must be
    // replaced by reproducible build/source digests before untrusted or
    // dynamically loaded Petals can receive signing grants. Audit/status
    // output must label these as placeholders via [`is_placeholder_digest`].

    /// Placeholder `petal_digest` for the `evm-wallet` first-party Petal.
    ///
    /// TODO(petal-digest-provenance): temporary, not a real tamper-evidence
    /// boundary; must be replaced by reproducible build/source digests before
    /// untrusted or dynamically loaded Petals can receive signing grants.
    pub const PLACEHOLDER_DIGEST_EVM_WALLET: &str = "first-party-placeholder:evm-wallet:v0";
    /// Placeholder `petal_digest` for the `paid-http` first-party Petal.
    ///
    /// TODO(petal-digest-provenance): temporary, not a real tamper-evidence
    /// boundary; must be replaced by reproducible build/source digests before
    /// untrusted or dynamically loaded Petals can receive signing grants.
    pub const PLACEHOLDER_DIGEST_PAID_HTTP: &str = "first-party-placeholder:paid-http:v0";
    /// Placeholder `petal_digest` for the `polymarket` first-party Petal.
    ///
    /// TODO(petal-digest-provenance): temporary, not a real tamper-evidence
    /// boundary; must be replaced by reproducible build/source digests before
    /// untrusted or dynamically loaded Petals can receive signing grants.
    pub const PLACEHOLDER_DIGEST_POLYMARKET: &str = "first-party-placeholder:polymarket:v0";
    /// Placeholder `petal_digest` for the `hyperliquid` first-party Petal.
    ///
    /// TODO(petal-digest-provenance): temporary, not a real tamper-evidence
    /// boundary; must be replaced by reproducible build/source digests before
    /// untrusted or dynamically loaded Petals can receive signing grants.
    pub const PLACEHOLDER_DIGEST_HYPERLIQUID: &str = "first-party-placeholder:hyperliquid:v0";
    /// Placeholder `petal_digest` for the `defi` first-party Petal.
    ///
    /// TODO(petal-digest-provenance): temporary, not a real tamper-evidence
    /// boundary; must be replaced by reproducible build/source digests before
    /// untrusted or dynamically loaded Petals can receive signing grants.
    pub const PLACEHOLDER_DIGEST_DEFI: &str = "first-party-placeholder:defi:v0";
    /// Placeholder `petal_digest` for the `wallet-policy` first-party Petal.
    ///
    /// TODO(petal-digest-provenance): temporary, not a real tamper-evidence
    /// boundary; must be replaced by reproducible build/source digests before
    /// untrusted or dynamically loaded Petals can receive signing grants.
    pub const PLACEHOLDER_DIGEST_WALLET_POLICY: &str = "first-party-placeholder:wallet-policy:v0";

    /// True when `digest` is a first-party placeholder rather than a real
    /// build/source digest. Audit and status output must use this to label
    /// placeholder digests so operators do not mistake them for code
    /// attestation (spec §11.10).
    pub fn is_placeholder_digest(digest: &str) -> bool {
        digest.starts_with(PLACEHOLDER_DIGEST_PREFIX)
    }

    /// Placeholder digest for a known first-party `petal_id`, if any.
    pub fn placeholder_digest_for(petal_id: &str) -> Option<&'static str> {
        match petal_id {
            PETAL_ID_EVM_WALLET => Some(PLACEHOLDER_DIGEST_EVM_WALLET),
            PETAL_ID_PAID_HTTP => Some(PLACEHOLDER_DIGEST_PAID_HTTP),
            PETAL_ID_POLYMARKET => Some(PLACEHOLDER_DIGEST_POLYMARKET),
            PETAL_ID_HYPERLIQUID => Some(PLACEHOLDER_DIGEST_HYPERLIQUID),
            PETAL_ID_DEFI => Some(PLACEHOLDER_DIGEST_DEFI),
            PETAL_ID_WALLET_POLICY => Some(PLACEHOLDER_DIGEST_WALLET_POLICY),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    #[default]
    Standard,
    Hardened,
}

impl AssuranceLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Hardened => "hardened",
        }
    }
}

/// How the WebAuthn assertion of a [`SignedApproval`] was collected (§6.3).
///
/// This is transport/audit metadata, not an authority level: assurance is
/// enforced from authenticator flags (user presence / user verification), not
/// from the transport that carried the assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerTransport {
    /// The existing local browser ceremony (`navigator.credentials.get`).
    #[serde(rename = "browser_webauthn")]
    BrowserWebauthn,
    /// Reserved for a future direct CTAP2/FIDO2 device flow without a browser.
    #[serde(rename = "native_ctap2")]
    NativeCtap2,
}

impl SignerTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BrowserWebauthn => "browser_webauthn",
            Self::NativeCtap2 => "native_ctap2",
        }
    }
}

/// Legacy signer taxonomy used by [`ApprovalCredentialRecord`] and the
/// credential store.
///
/// Approvals themselves record a [`SignerTransport`] instead. `Password`
/// survives only so existing credential rows keep parsing; it satisfies no
/// assurance level.
// TODO(ws-L): delete `SignerKind::Password` (and the local/passphrase wallet
// lane) once legacy wallets are removed; see spec §3.1 and §10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    Password,
    PasskeyBrowser,
    PasskeyCtap,
    Test,
}

impl SignerKind {
    /// Whether this signer kind can satisfy `assurance` for a fresh approval.
    ///
    /// Passphrase/password proof never satisfies any assurance level:
    /// assurance is a WebAuthn authenticator property (presence/UV), and the
    /// passphrase lane is being deleted (TODO(ws-L)).
    pub fn satisfies(self, assurance: AssuranceLevel) -> bool {
        match assurance {
            AssuranceLevel::Standard | AssuranceLevel::Hardened => {
                matches!(self, SignerKind::PasskeyBrowser | SignerKind::PasskeyCtap)
            }
        }
    }
}

/// Executor provenance for a Petal (§6.1 `executor_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorKind {
    /// Rust component compiled into the daemon (placeholder digests allowed).
    FirstParty,
    /// Dynamically loaded WASM Petal (requires real digest provenance).
    Wasm,
}

impl ExecutorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstParty => "first_party",
            Self::Wasm => "wasm",
        }
    }
}

/// Header of the canonical intent envelope (intent-hash preimage, §5.2/§6.1).
///
/// `expires_ms` is the latest time the sealed action may be approved or
/// executed; `0` means the staging path did not compute an action expiry yet
/// (transitional; venue conversions must populate a real expiry). Challenge
/// expiry is enforced independently at consume time; sealed-action expiry
/// enforcement lands with the atomic verify-at-use path.
// TODO(ws-A): enforce `expires_ms` (when non-zero) inside the per-action
// verify-at-use lock in addition to the challenge expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalIntentHeader {
    pub schema: String,
    pub wallet: String,
    pub surface: String,
    pub action_id: String,
    pub petal_id: String,
    pub petal_digest: String,
    pub petal_version: String,
    pub executor_kind: ExecutorKind,
    pub network: String,
    pub account: String,
    pub action_kind: String,
    pub value_movement: bool,
    pub authority_change: bool,
    pub expires_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalEnvelope {
    pub schema: String,
    pub header: CanonicalIntentHeader,
    pub subject_kind: String,
    pub subject_schema: String,
    pub subject_bytes_b64: String,
}

impl CanonicalEnvelope {
    pub fn new(
        header: CanonicalIntentHeader,
        subject_kind: impl Into<String>,
        subject_schema: impl Into<String>,
        subject_bytes: Vec<u8>,
    ) -> Self {
        Self {
            schema: CANONICAL_ENVELOPE_SCHEMA_V2.to_string(),
            header,
            subject_kind: subject_kind.into(),
            subject_schema: subject_schema.into(),
            subject_bytes_b64: base64::engine::general_purpose::STANDARD.encode(subject_bytes),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthApiError> {
        serde_json::to_vec(self).map_err(AuthApiError::Json)
    }

    pub fn intent_hash(&self) -> Result<String, AuthApiError> {
        Ok(intent_hash_of(&self.canonical_bytes()?))
    }
}

/// Compute the domain-separated `intent_hash` over raw canonical bytes.
///
/// Uses BLAKE3 with the `bloom.intent.v2` domain tag, encoded as lowercase,
/// full-length, untruncated hex. This is the single hash function that must
/// be used anywhere an `intent_hash` is produced — in
/// [`CanonicalEnvelope::intent_hash`], in central outbox projections, and in
/// sealed-action challenge preimages.
pub fn intent_hash_of(canonical_bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INTENT_HASH_DOMAIN);
    hasher.update(canonical_bytes);
    hasher.finalize().to_hex().to_string()
}

pub trait CanonicalSubject {
    fn subject_kind(&self) -> &'static str;
    fn subject_schema(&self) -> &'static str;
    fn validate(&self) -> Result<(), AuthApiError>;
    fn canonical_subject_bytes(&self) -> Result<Vec<u8>, AuthApiError>;
}

/// Host-enforced signer boundaries for one sealed action (§9).
///
/// Copied verbatim into any [`SealedApprovalGrant`] minted for the action and
/// committed into the approval challenge via [`Self::daemon_terms_digest`].
///
/// There is deliberately no `require_attestation` field: a structured
/// [`SigningAttestation`] is mandatory for every `sign-hash` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonGrantTerms {
    /// Maximum grant lifetime, in seconds, the daemon may mint for this action.
    pub max_ttl_secs: u64,
    /// Maximum wallet signatures allowed across the whole action.
    pub max_signatures: u32,
    /// Exact `intent` strings the Petal may pass to `sign-hash`
    /// (e.g. `evm.tx.sign`, `polymarket.order.v2`, `wallet_policy.sign`).
    pub allowed_sign_intents: Vec<String>,
    /// Required approval strength, copied into the challenge.
    pub assurance: AssuranceLevel,
    /// Daemon-owned extension map for Petal-specific host terms that are not
    /// yet first-class fields.
    ///
    /// Fail-closed contract: if an enforcement point encounters an `extra`
    /// key it recognizes as REQUIRED but does not understand (or any key
    /// namespaced `required.*`), it must deny signing rather than ignore it.
    /// Unknown optional keys are audit-only. Enforcement lands with the grant
    /// service (TODO(ws-A)).
    #[serde(default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl DaemonGrantTerms {
    /// Restrictive default terms for staging paths that have not yet been
    /// converted to compute venue-specific terms: one signature, no allowed
    /// sign intents (so no `sign-hash` call can succeed), 120s TTL ceiling.
    // TODO(ws-F..ws-K): venue staging must replace these with real
    // venue-computed terms (allowed_sign_intents, max_signatures, ...).
    pub fn minimal(assurance: AssuranceLevel) -> Self {
        Self {
            max_ttl_secs: GRANT_MAX_TTL_MS / 1_000,
            max_signatures: 1,
            allowed_sign_intents: Vec::new(),
            assurance,
            extra: BTreeMap::new(),
        }
    }

    /// Canonical bytes for digesting. Deterministic: struct fields serialize
    /// in declaration order and `extra` is an ordered map.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthApiError> {
        serde_json::to_vec(self).map_err(AuthApiError::Json)
    }

    /// Collision-resistant, domain-tagged digest of the canonical terms
    /// (BLAKE3, lowercase full-length hex).
    pub fn daemon_terms_digest(&self) -> Result<String, AuthApiError> {
        Ok(digest_hex(
            DAEMON_TERMS_DIGEST_DOMAIN,
            &self.canonical_bytes()?,
        ))
    }
}

/// Rule classification for plan/challenge rendering and enforcement (§5.6, §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCheckClass {
    /// Never escalatable, even with a passkey.
    Hard,
    /// May be exceeded only by Sealed Approval, up to an explicit ceiling.
    StepUp,
    /// Plan/audit only.
    Informational,
}

/// One daemon-computed rule result shown in the plan and recorded in audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckResult {
    pub rule_id: String,
    pub rule_class: PolicyCheckClass,
    /// Normalized outcome, e.g. `pass`, `fail`, `step_up_required`.
    pub outcome: String,
    pub message: String,
    /// Ceiling for `step_up` rules, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_ceiling: Option<serde_json::Value>,
}

/// A rule entry inside a [`PetalPolicySnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetalPolicyRule {
    pub rule_id: String,
    #[serde(default)]
    pub message: String,
    /// Rule parameters (thresholds, lists, ...), as a typed-value map so venue
    /// crates can project their existing rule types into it.
    #[serde(default)]
    pub params: BTreeMap<String, serde_json::Value>,
    /// Ceiling for step-up rules, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_up_ceiling: Option<serde_json::Value>,
}

/// Daemon-cut, sealed projection of wallet policy and daemon-owned
/// configuration for one Petal (§2, §9).
///
/// Committed into the sealed action and injected into the Petal at execution
/// time via `get-policy()`. Petals do not read live `policy.toml` for an
/// already-sealed action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetalPolicySnapshot {
    /// Monotonic wallet-policy/config version observed when the snapshot was cut.
    pub policy_version: u64,
    /// Wallet name the snapshot applies to.
    pub wallet: String,
    /// Petal this snapshot was produced for.
    pub petal_id: String,
    /// Exact Petal digest expected to use the snapshot.
    pub petal_digest: String,
    /// Petal-specific limits (e.g. EVM `PolicyCaps`, Polymarket
    /// `max_order_usd`, Hyperliquid `max_notional_usd`), projected as a
    /// typed-value map by the owning venue crate.
    #[serde(default)]
    pub caps: BTreeMap<String, serde_json::Value>,
    /// Non-overridable daemon or wallet rules (geoblock, denylist, ...).
    #[serde(default)]
    pub hard_rules: Vec<PetalPolicyRule>,
    /// Rules exceedable only by Sealed Approval, up to explicit ceilings.
    #[serde(default)]
    pub step_up_rules: Vec<PetalPolicyRule>,
    /// Daemon-owned Petal configuration needed at runtime (endpoints, chain
    /// ids, protocol constants), as a typed-value map.
    #[serde(default)]
    pub config: BTreeMap<String, serde_json::Value>,
    /// Frozen spend/exposure/session counters used to check caps at execution.
    #[serde(default)]
    pub budget_state: BTreeMap<String, serde_json::Value>,
    /// Frozen standing-authority scope when the action mints or uses a venue
    /// session credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_scope: Option<BTreeMap<String, serde_json::Value>>,
}

impl PetalPolicySnapshot {
    /// Empty snapshot for staging paths that have not been converted to
    /// project real venue policy yet.
    // TODO(ws-F..ws-K): venue staging must replace this with a real projection
    // of the venue policy type (caps, hard/step-up rules, config, budget).
    pub fn minimal(header: &CanonicalIntentHeader) -> Self {
        Self {
            policy_version: 0,
            wallet: header.wallet.clone(),
            petal_id: header.petal_id.clone(),
            petal_digest: header.petal_digest.clone(),
            caps: BTreeMap::new(),
            hard_rules: Vec::new(),
            step_up_rules: Vec::new(),
            config: BTreeMap::new(),
            budget_state: BTreeMap::new(),
            session_scope: None,
        }
    }

    /// Canonical bytes for digesting and Petal injection. Deterministic:
    /// struct fields serialize in declaration order and all maps are ordered.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthApiError> {
        serde_json::to_vec(self).map_err(AuthApiError::Json)
    }

    /// Collision-resistant, domain-tagged digest of the canonical snapshot
    /// (BLAKE3, lowercase full-length hex).
    pub fn petal_policy_digest(&self) -> Result<String, AuthApiError> {
        Ok(digest_hex(
            PETAL_POLICY_DIGEST_DOMAIN,
            &self.canonical_bytes()?,
        ))
    }
}

/// The sealed action record persisted in daemon-controlled storage (§6.1).
///
/// The wrapped [`CanonicalEnvelope`] remains the sole intent-hash preimage
/// (`intent_hash = BLAKE3("bloom.intent.v2" || envelope canonical bytes)`);
/// the sealed action adds daemon-produced review and enforcement context.
/// Once sealed it is immutable — re-stage instead of mutating (§5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedAction {
    /// [`SEALED_ACTION_SCHEMA_V1`].
    pub schema: String,
    /// Immutable canonical intent (identity, subject bytes, `expires_ms`).
    pub envelope: CanonicalEnvelope,
    /// Daemon-rendered human review text derived from the canonical subject.
    pub plan: String,
    /// Daemon-computed rule results shown in the plan and audit.
    pub policy_checks: Vec<PolicyCheckResult>,
    /// Signer limits copied into any grant minted for the action.
    pub daemon_terms: DaemonGrantTerms,
    /// Sealed Petal policy snapshot injected at execution time.
    pub petal_policy: PetalPolicySnapshot,
    /// Digest of `petal_policy`, also bound into the approval challenge.
    pub petal_policy_digest: String,
    /// Monotonic wallet-policy/config version observed at sealing.
    pub policy_version: u64,
    /// Daemon sealing time.
    pub created_ms: u64,
    /// Latest time the sealed action may be approved or executed
    /// (mirrors `envelope.header.expires_ms`; `0` = not yet computed).
    pub expires_ms: u64,
}

impl SealedAction {
    /// Seal an envelope with explicit daemon-produced context. Digest and
    /// version fields are derived from `petal_policy`; `expires_ms` is taken
    /// from the envelope header so the expiry is part of the signed intent.
    pub fn new(
        envelope: CanonicalEnvelope,
        plan: String,
        policy_checks: Vec<PolicyCheckResult>,
        daemon_terms: DaemonGrantTerms,
        petal_policy: PetalPolicySnapshot,
        created_ms: u64,
    ) -> Result<Self, AuthApiError> {
        let petal_policy_digest = petal_policy.petal_policy_digest()?;
        let policy_version = petal_policy.policy_version;
        let expires_ms = envelope.header.expires_ms;
        let action = Self {
            schema: SEALED_ACTION_SCHEMA_V1.to_string(),
            envelope,
            plan,
            policy_checks,
            daemon_terms,
            petal_policy,
            petal_policy_digest,
            policy_version,
            created_ms,
            expires_ms,
        };
        action.validate()?;
        Ok(action)
    }

    /// Seal an envelope with restrictive default terms and an empty policy
    /// snapshot. Used by staging paths that predate venue-specific
    /// terms/snapshot projection.
    // TODO(ws-F..ws-K): converted venues must call [`SealedAction::new`] with
    // real plan, policy checks, terms, and snapshot instead.
    pub fn seal_with_default_terms(
        envelope: CanonicalEnvelope,
        assurance: AssuranceLevel,
        created_ms: u64,
    ) -> Result<Self, AuthApiError> {
        let terms = DaemonGrantTerms::minimal(assurance);
        let snapshot = PetalPolicySnapshot::minimal(&envelope.header);
        Self::new(
            envelope,
            String::new(),
            Vec::new(),
            terms,
            snapshot,
            created_ms,
        )
    }

    /// Internal consistency checks: schema tags, Petal identity agreement
    /// between the envelope header and the snapshot, digest/version
    /// derivation, and expiry mirroring.
    pub fn validate(&self) -> Result<(), AuthApiError> {
        if self.schema != SEALED_ACTION_SCHEMA_V1 {
            return Err(AuthApiError::InvalidSubject(format!(
                "unsupported sealed action schema {}",
                self.schema
            )));
        }
        if self.envelope.schema != CANONICAL_ENVELOPE_SCHEMA_V2 {
            return Err(AuthApiError::InvalidSubject(format!(
                "unsupported canonical envelope schema {}",
                self.envelope.schema
            )));
        }
        let header = &self.envelope.header;
        if header.schema != CANONICAL_INTENT_HEADER_SCHEMA_V2 {
            return Err(AuthApiError::InvalidSubject(format!(
                "unsupported canonical intent header schema {}",
                header.schema
            )));
        }
        if header.petal_id.trim().is_empty() || header.petal_digest.trim().is_empty() {
            return Err(AuthApiError::InvalidSubject(
                "sealed action is missing petal identity".into(),
            ));
        }
        if self.petal_policy.wallet != header.wallet
            || self.petal_policy.petal_id != header.petal_id
            || self.petal_policy.petal_digest != header.petal_digest
        {
            return Err(AuthApiError::InvalidSubject(
                "petal policy snapshot does not match the sealed action identity".into(),
            ));
        }
        if self.petal_policy_digest != self.petal_policy.petal_policy_digest()? {
            return Err(AuthApiError::InvalidSubject(
                "petal_policy_digest does not match petal_policy".into(),
            ));
        }
        if self.policy_version != self.petal_policy.policy_version {
            return Err(AuthApiError::InvalidSubject(
                "policy_version does not match petal_policy".into(),
            ));
        }
        if self.expires_ms != header.expires_ms {
            return Err(AuthApiError::InvalidSubject(
                "sealed action expires_ms does not match envelope header".into(),
            ));
        }
        if self.daemon_terms.max_signatures == 0 {
            return Err(AuthApiError::InvalidSubject(
                "daemon terms must allow at least one signature".into(),
            ));
        }
        Ok(())
    }

    pub fn intent_hash(&self) -> Result<String, AuthApiError> {
        self.envelope.intent_hash()
    }

    pub fn daemon_terms_digest(&self) -> Result<String, AuthApiError> {
        self.daemon_terms.daemon_terms_digest()
    }

    pub fn wallet(&self) -> &str {
        &self.envelope.header.wallet
    }

    pub fn surface(&self) -> &str {
        &self.envelope.header.surface
    }

    pub fn action_id(&self) -> &str {
        &self.envelope.header.action_id
    }

    pub fn petal_id(&self) -> &str {
        &self.envelope.header.petal_id
    }

    pub fn petal_digest(&self) -> &str {
        &self.envelope.header.petal_digest
    }
}

/// The daemon-issued approval challenge preimage (§5.7, §6.2).
///
/// The WebAuthn `challenge` MUST equal
/// `BLAKE3("bloom.approval.v1", canonical(ApprovalChallenge))` — see
/// [`Self::challenge_hash`]. Every field is daemon-issued; a client may echo
/// them in `approval.json`, but any mismatch from the issued challenge is
/// rejected at consume time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    /// [`APPROVAL_CHALLENGE_SCHEMA_V1`].
    pub schema: String,
    /// Concrete outbox action id (never `latest`).
    pub action_id: String,
    /// Bloom wallet name owning the authority being used.
    pub wallet: String,
    /// Staging/projection origin (informational, but signed).
    pub surface: String,
    pub petal_id: String,
    pub petal_digest: String,
    /// Lowercase, full-length, untruncated hex.
    pub intent_hash: String,
    /// Single-use daemon nonce; consumption must survive restart.
    pub server_nonce: String,
    /// Required proof level for this action; clients cannot lower it.
    pub assurance: AssuranceLevel,
    /// Digest of canonical `SealedAction.daemon_terms`.
    pub daemon_terms_digest: String,
    /// Digest of canonical `SealedAction.petal_policy`.
    pub petal_policy_digest: String,
    /// Wallet-policy/config version observed at sealing.
    pub policy_version: u64,
    /// Daemon-issued challenge expiry.
    pub expiry_ms: u64,
}

impl ApprovalChallenge {
    /// Canonical preimage bytes. Deterministic: fields serialize in
    /// declaration order.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthApiError> {
        serde_json::to_vec(self).map_err(AuthApiError::Json)
    }

    /// The 32-byte WebAuthn challenge:
    /// `BLAKE3("bloom.approval.v1", canonical(ApprovalChallenge))`.
    pub fn challenge_hash(&self) -> Result<[u8; 32], AuthApiError> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(APPROVAL_CHALLENGE_DOMAIN);
        hasher.update(&self.canonical_bytes()?);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn challenge_hash_hex(&self) -> Result<String, AuthApiError> {
        Ok(hex_lower(&self.challenge_hash()?))
    }
}

/// The `approval.json` record (§6.3): proof that a passkey ceremony approved
/// the exact sealed action challenge. Contains no secret key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedApproval {
    /// [`APPROVAL_SCHEMA_V1`].
    pub schema: String,
    pub action_id: String,
    pub wallet: String,
    pub surface: String,
    pub petal_id: String,
    pub petal_digest: String,
    pub intent_hash: String,
    pub server_nonce: String,
    pub assurance: AssuranceLevel,
    /// Must byte-equal the daemon-issued challenge value (§5.7 step 10).
    pub daemon_terms_digest: String,
    /// Must byte-equal the daemon-issued challenge value (§5.7 step 10).
    pub petal_policy_digest: String,
    /// Must equal the daemon-issued challenge value (§5.7 step 10).
    pub policy_version: u64,
    /// Must equal the daemon-issued challenge expiry (§5.7 step 9).
    pub expiry_ms: u64,
    /// Transport/audit metadata; not an authority level.
    pub signer_transport: SignerTransport,
    pub credential_id: String,
    /// Transitional hardened review-session binding (daemon-side record).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_session_id: Option<String>,
    pub webauthn_assertion: WebAuthnAssertionRecord,
}

/// [`SignedApproval`] without its signature: the payload a ceremony signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedApproval {
    pub schema: String,
    pub action_id: String,
    pub wallet: String,
    pub surface: String,
    pub petal_id: String,
    pub petal_digest: String,
    pub intent_hash: String,
    pub server_nonce: String,
    pub assurance: AssuranceLevel,
    pub daemon_terms_digest: String,
    pub petal_policy_digest: String,
    pub policy_version: u64,
    pub expiry_ms: u64,
    pub signer_transport: SignerTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_session_id: Option<String>,
}

impl UnsignedApproval {
    /// Build the unsigned approval a client should sign for a daemon-issued
    /// challenge.
    pub fn for_challenge(
        challenge: &ApprovalChallenge,
        signer_transport: SignerTransport,
        credential_id: Option<String>,
        review_session_id: Option<String>,
    ) -> Self {
        Self {
            schema: APPROVAL_SCHEMA_V1.into(),
            action_id: challenge.action_id.clone(),
            wallet: challenge.wallet.clone(),
            surface: challenge.surface.clone(),
            petal_id: challenge.petal_id.clone(),
            petal_digest: challenge.petal_digest.clone(),
            intent_hash: challenge.intent_hash.clone(),
            server_nonce: challenge.server_nonce.clone(),
            assurance: challenge.assurance,
            daemon_terms_digest: challenge.daemon_terms_digest.clone(),
            petal_policy_digest: challenge.petal_policy_digest.clone(),
            policy_version: challenge.policy_version,
            expiry_ms: challenge.expiry_ms,
            signer_transport,
            credential_id,
            review_session_id,
        }
    }

    /// Reconstruct the §5.7 challenge preimage from the approval fields.
    ///
    /// This equals the daemon-issued [`ApprovalChallenge`] iff the client
    /// echoed every daemon-issued field faithfully; verification compares
    /// against the *stored* issued challenge, never trusting this echo alone.
    pub fn approval_challenge(&self) -> ApprovalChallenge {
        ApprovalChallenge {
            schema: APPROVAL_CHALLENGE_SCHEMA_V1.into(),
            action_id: self.action_id.clone(),
            wallet: self.wallet.clone(),
            surface: self.surface.clone(),
            petal_id: self.petal_id.clone(),
            petal_digest: self.petal_digest.clone(),
            intent_hash: self.intent_hash.clone(),
            server_nonce: self.server_nonce.clone(),
            assurance: self.assurance,
            daemon_terms_digest: self.daemon_terms_digest.clone(),
            petal_policy_digest: self.petal_policy_digest.clone(),
            policy_version: self.policy_version,
            expiry_ms: self.expiry_ms,
        }
    }

    /// The WebAuthn challenge bytes for this approval: the hash of the full
    /// §5.7 [`ApprovalChallenge`] preimage (transport metadata such as
    /// `signer_transport`, `credential_id`, and `review_session_id` is *not*
    /// part of the signed challenge).
    pub fn challenge_hash(&self) -> Result<[u8; 32], AuthApiError> {
        self.approval_challenge().challenge_hash()
    }

    pub fn challenge_hash_hex(&self) -> Result<String, AuthApiError> {
        Ok(hex_lower(&self.challenge_hash()?))
    }

    pub fn into_signed(self, webauthn_assertion: WebAuthnAssertionRecord) -> SignedApproval {
        let credential_id = self
            .credential_id
            .unwrap_or_else(|| webauthn_assertion.credential_id.clone());
        SignedApproval {
            schema: self.schema,
            action_id: self.action_id,
            wallet: self.wallet,
            surface: self.surface,
            petal_id: self.petal_id,
            petal_digest: self.petal_digest,
            intent_hash: self.intent_hash,
            server_nonce: self.server_nonce,
            assurance: self.assurance,
            daemon_terms_digest: self.daemon_terms_digest,
            petal_policy_digest: self.petal_policy_digest,
            policy_version: self.policy_version,
            expiry_ms: self.expiry_ms,
            signer_transport: self.signer_transport,
            credential_id,
            review_session_id: self.review_session_id,
            webauthn_assertion,
        }
    }
}

impl SignedApproval {
    pub fn unsigned_payload(&self) -> UnsignedApproval {
        UnsignedApproval {
            schema: self.schema.clone(),
            action_id: self.action_id.clone(),
            wallet: self.wallet.clone(),
            surface: self.surface.clone(),
            petal_id: self.petal_id.clone(),
            petal_digest: self.petal_digest.clone(),
            intent_hash: self.intent_hash.clone(),
            server_nonce: self.server_nonce.clone(),
            assurance: self.assurance,
            daemon_terms_digest: self.daemon_terms_digest.clone(),
            petal_policy_digest: self.petal_policy_digest.clone(),
            policy_version: self.policy_version,
            expiry_ms: self.expiry_ms,
            signer_transport: self.signer_transport,
            credential_id: Some(self.credential_id.clone()),
            review_session_id: self.review_session_id.clone(),
        }
    }

    /// Daemon-side approval validation (§5.7 steps 3–4 and 9–10).
    ///
    /// Requires the approval to byte-equal the *daemon-issued* challenge on
    /// every daemon-issued field (identity, nonce, digests, policy version,
    /// expiry) and to bind the sealed action's identity. Cryptographic
    /// assertion verification (steps 5–8) is performed separately by an
    /// [`ApprovalSignatureVerifier`]; nonce burn (step 11) happens in the
    /// store transaction.
    pub fn validate_against_sealed(
        &self,
        sealed: &SealedIntentRecord,
        issued: &ApprovalChallenge,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        if self.schema != APPROVAL_SCHEMA_V1 {
            return Err(AuthApiError::Denied(format!(
                "unsupported approval schema {}",
                self.schema
            )));
        }
        if issued.schema != APPROVAL_CHALLENGE_SCHEMA_V1 {
            return Err(AuthApiError::Denied(format!(
                "unsupported challenge schema {}",
                issued.schema
            )));
        }
        if now_ms >= self.expiry_ms {
            return Err(AuthApiError::Denied("approval expired".into()));
        }
        if self.credential_id.trim().is_empty() {
            return Err(AuthApiError::Denied(
                "approval credential_id is empty".into(),
            ));
        }
        if self.credential_id != self.webauthn_assertion.credential_id {
            return Err(AuthApiError::Denied(
                "approval credential_id does not match WebAuthn assertion".into(),
            ));
        }
        // §5.7 steps 9–10: every daemon-issued value must be echoed exactly.
        let echoed = self.unsigned_payload().approval_challenge();
        let checks = [
            ("action_id", &echoed.action_id, &issued.action_id),
            ("wallet", &echoed.wallet, &issued.wallet),
            ("surface", &echoed.surface, &issued.surface),
            ("petal_id", &echoed.petal_id, &issued.petal_id),
            ("petal_digest", &echoed.petal_digest, &issued.petal_digest),
            ("intent_hash", &echoed.intent_hash, &issued.intent_hash),
            ("server_nonce", &echoed.server_nonce, &issued.server_nonce),
            (
                "daemon_terms_digest",
                &echoed.daemon_terms_digest,
                &issued.daemon_terms_digest,
            ),
            (
                "petal_policy_digest",
                &echoed.petal_policy_digest,
                &issued.petal_policy_digest,
            ),
        ];
        for (field, approval, challenge) in checks {
            if approval != challenge {
                return Err(AuthApiError::Denied(format!(
                    "{field} does not match issued challenge"
                )));
            }
        }
        if echoed.assurance != issued.assurance {
            return Err(AuthApiError::Denied(
                "assurance does not match issued challenge".into(),
            ));
        }
        if echoed.policy_version != issued.policy_version {
            return Err(AuthApiError::Denied(
                "policy_version does not match issued challenge".into(),
            ));
        }
        if echoed.expiry_ms != issued.expiry_ms {
            return Err(AuthApiError::Denied(
                "approval expiry does not match issued challenge".into(),
            ));
        }
        // Bind the sealed action: the issued challenge must refer to it, and
        // its header identity must agree with the challenge/approval.
        if issued.intent_hash != sealed.intent_hash {
            return Err(AuthApiError::Denied(
                "issued challenge does not match sealed intent_hash".into(),
            ));
        }
        let action = sealed.action.as_ref().ok_or_else(|| {
            AuthApiError::Denied("sealed action record is missing; re-stage the action".into())
        })?;
        action.validate()?;
        if action.intent_hash()? != sealed.intent_hash {
            return Err(AuthApiError::Denied(
                "sealed action intent_hash does not match stored key".into(),
            ));
        }
        let action_daemon_terms_digest = action.daemon_terms_digest()?;
        let action_checks = [
            ("wallet", issued.wallet.as_str(), action.wallet()),
            ("surface", issued.surface.as_str(), action.surface()),
            ("action_id", issued.action_id.as_str(), action.action_id()),
            ("petal_id", issued.petal_id.as_str(), action.petal_id()),
            (
                "petal_digest",
                issued.petal_digest.as_str(),
                action.petal_digest(),
            ),
            (
                "daemon_terms_digest",
                issued.daemon_terms_digest.as_str(),
                action_daemon_terms_digest.as_str(),
            ),
            (
                "petal_policy_digest",
                issued.petal_policy_digest.as_str(),
                action.petal_policy_digest.as_str(),
            ),
        ];
        for (field, challenge, sealed_value) in action_checks {
            if challenge != sealed_value {
                return Err(AuthApiError::Denied(format!(
                    "sealed action {field} mismatch"
                )));
            }
        }
        if issued.policy_version != action.policy_version {
            return Err(AuthApiError::Denied(
                "sealed action policy_version mismatch".into(),
            ));
        }
        let header = &sealed.envelope.header;
        let sealed_checks = [
            ("wallet", issued.wallet.as_str(), header.wallet.as_str()),
            ("surface", issued.surface.as_str(), header.surface.as_str()),
            (
                "action_id",
                issued.action_id.as_str(),
                header.action_id.as_str(),
            ),
            (
                "petal_id",
                issued.petal_id.as_str(),
                header.petal_id.as_str(),
            ),
            (
                "petal_digest",
                issued.petal_digest.as_str(),
                header.petal_digest.as_str(),
            ),
        ];
        for (field, challenge, sealed_value) in sealed_checks {
            if challenge != sealed_value {
                return Err(AuthApiError::Denied(format!(
                    "sealed action {field} mismatch"
                )));
            }
        }
        // Challenge binding: the WebAuthn assertion must commit to this exact
        // preimage.
        self.webauthn_assertion
            .validate_challenge(&self.unsigned_payload())?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnAssertionRecord {
    pub credential_id: String,
    pub authenticator_data_b64: String,
    pub client_data_json_b64: String,
    pub signature_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle_b64: Option<String>,
}

impl WebAuthnAssertionRecord {
    pub fn client_data_json(&self) -> Result<serde_json::Value, AuthApiError> {
        let bytes = decode_b64_any(&self.client_data_json_b64)?;
        serde_json::from_slice(&bytes).map_err(AuthApiError::Json)
    }

    pub fn client_challenge(&self) -> Result<String, AuthApiError> {
        self.client_data_json()?
            .get("challenge")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| AuthApiError::Denied("WebAuthn clientDataJSON missing challenge".into()))
    }

    pub fn validate_challenge(&self, unsigned: &UnsignedApproval) -> Result<(), AuthApiError> {
        let expected =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(unsigned.challenge_hash()?);
        let got = self.client_challenge()?;
        if got != expected {
            return Err(AuthApiError::Denied(
                "WebAuthn assertion challenge does not match approval payload".into(),
            ));
        }
        Ok(())
    }
}

/// The in-memory Sealed Approval Grant (§6.4).
///
/// Minted by the daemon after verifying `approval.json` and deriving the
/// wallet key from the ceremony PRF output. Bound to one sealed action and
/// one exact Petal identity.
///
/// Persistence is forbidden, not configurable: this type deliberately
/// implements neither `Serialize` nor `Deserialize`, so it cannot cross a
/// serialization boundary (VFS, sqlite JSON columns, logs) without a
/// compile error. On restart a new challenge and ceremony are required.
///
/// ```compile_fail,E0277
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<bloom_auth_api::SealedApprovalGrant>();
/// ```
///
/// ```compile_fail,E0277
/// fn assert_deserialize<T: serde::de::DeserializeOwned>() {}
/// assert_deserialize::<bloom_auth_api::SealedApprovalGrant>();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedApprovalGrant {
    /// Daemon-local unique id for audit and revocation.
    pub grant_id: String,
    /// Wallet name whose key may be used.
    pub wallet: String,
    /// Sealed outbox action this grant belongs to.
    pub action_id: String,
    /// Immutable action hash the grant is bound to.
    pub intent_hash: String,
    /// Exact Petal identity allowed to consume the grant.
    pub petal_id: String,
    pub petal_digest: String,
    pub petal_version: String,
    /// Signer limits copied from the sealed action.
    pub daemon_terms: DaemonGrantTerms,
    /// Digest of the sealed policy snapshot signing attestations must satisfy.
    pub petal_policy_digest: String,
    /// Wallet-policy/config version used when sealing.
    pub policy_version: u64,
    /// Grant mint time.
    pub issued_ms: u64,
    /// Grant expiry; never later than the signed approval expiry and never
    /// more than [`GRANT_MAX_TTL_MS`] past `issued_ms`.
    pub expiry_ms: u64,
    /// Total wallet signatures allowed under this grant.
    pub max_signatures: u32,
    /// Signatures already produced.
    pub consumed_signature_count: u32,
    /// In-memory kill switch set by failure, expiry handling, explicit
    /// revoke, or daemon shutdown.
    pub revoked: bool,
}

impl SealedApprovalGrant {
    /// Mint a grant for a verified sealed action.
    ///
    /// Enforces `expiry_ms = min(issued_ms + 120_000, approval_expiry_ms)`,
    /// additionally clamped by the sealed `daemon_terms.max_ttl_secs`.
    pub fn mint(
        grant_id: impl Into<String>,
        sealed: &SealedAction,
        approval_expiry_ms: u64,
        issued_ms: u64,
    ) -> Result<Self, AuthApiError> {
        sealed.validate()?;
        let terms_ttl_ms = sealed.daemon_terms.max_ttl_secs.saturating_mul(1_000);
        let ttl_ms = GRANT_MAX_TTL_MS.min(terms_ttl_ms);
        let expiry_ms = issued_ms.saturating_add(ttl_ms).min(approval_expiry_ms);
        if expiry_ms <= issued_ms {
            return Err(AuthApiError::Denied(
                "grant would be expired at mint time".into(),
            ));
        }
        Ok(Self {
            grant_id: grant_id.into(),
            wallet: sealed.wallet().to_string(),
            action_id: sealed.action_id().to_string(),
            intent_hash: sealed.intent_hash()?,
            petal_id: sealed.petal_id().to_string(),
            petal_digest: sealed.petal_digest().to_string(),
            petal_version: sealed.envelope.header.petal_version.clone(),
            daemon_terms: sealed.daemon_terms.clone(),
            petal_policy_digest: sealed.petal_policy_digest.clone(),
            policy_version: sealed.policy_version,
            issued_ms,
            expiry_ms,
            max_signatures: sealed.daemon_terms.max_signatures,
            consumed_signature_count: 0,
            revoked: false,
        })
    }

    pub fn is_active_at(&self, now_ms: u64) -> bool {
        !self.revoked
            && now_ms < self.expiry_ms
            && self.consumed_signature_count < self.max_signatures
    }
}

/// In-memory store for [`SealedApprovalGrant`]s.
///
/// Invariants the implementation must uphold (the concrete
/// `InMemoryGrantStore` lands with the grant service, TODO(ws-A)):
///
/// - grants are never persisted (the grant type is `!Serialize`);
/// - at most one live grant per `(wallet, action_id, petal_id, petal_digest)`
///   — [`GrantStore::mint`] must fail closed if a live grant already exists
///   for that tuple;
/// - any decrypted key material held behind a grant is zeroized on consume of
///   the final signature, expiry, revoke, failure, and daemon shutdown.
#[async_trait]
pub trait GrantStore: Send + Sync {
    /// Mint a grant for a verified sealed action, bounded by the approval
    /// expiry. Must fail if a live grant already exists for the same
    /// `(wallet, action_id, petal_id, petal_digest)`.
    async fn mint(
        &self,
        sealed: &SealedAction,
        approval_expiry_ms: u64,
        now_ms: u64,
    ) -> Result<SealedApprovalGrant, AuthApiError>;

    /// Atomically consume one signature under the grant, enforcing expiry,
    /// revocation, count, and `intent ∈ allowed_sign_intents`. Returns the
    /// updated grant snapshot.
    async fn consume_signature(
        &self,
        grant_id: &str,
        intent: &str,
        now_ms: u64,
    ) -> Result<SealedApprovalGrant, AuthApiError>;

    /// Revoke a single grant (idempotent).
    async fn revoke(&self, grant_id: &str, now_ms: u64) -> Result<(), AuthApiError>;

    /// Revoke every live grant for a wallet; returns how many were revoked.
    async fn revoke_all_for_wallet(&self, wallet: &str, now_ms: u64)
    -> Result<usize, AuthApiError>;

    /// The live grant for `(wallet, action_id, petal_id, petal_digest)`,
    /// if any.
    async fn get_active(
        &self,
        wallet: &str,
        action_id: &str,
        petal_id: &str,
        petal_digest: &str,
        now_ms: u64,
    ) -> Result<Option<SealedApprovalGrant>, AuthApiError>;
}

/// Structured Petal claim describing what a `sign-hash` request means (§8).
///
/// Mandatory for every `sign-hash` call. The daemon validates the attested
/// facts against the sealed [`PetalPolicySnapshot`] before signing; for the
/// MVP it trusts the approved Petal that the attestation honestly describes
/// `hash32`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningAttestation {
    /// Attestation schema id; selected by `(petal_id, intent)` — e.g.
    /// [`SIGNING_ATTESTATION_SCHEMA_V1`] or a venue-specific tag.
    pub schema: String,
    pub petal_id: String,
    /// The `sign-hash` intent string this attestation accompanies.
    pub intent: String,
    /// Policy-relevant facts (amount, asset, destination, network,
    /// action kind, fees, ...), as a typed-value map.
    #[serde(default)]
    pub facts: BTreeMap<String, serde_json::Value>,
}

impl SigningAttestation {
    pub fn validate(&self) -> Result<(), AuthApiError> {
        if self.schema.trim().is_empty() {
            return Err(AuthApiError::InvalidSubject(
                "attestation schema is empty".into(),
            ));
        }
        if self.petal_id.trim().is_empty() {
            return Err(AuthApiError::InvalidSubject(
                "attestation petal_id is empty".into(),
            ));
        }
        if self.intent.trim().is_empty() {
            return Err(AuthApiError::InvalidSubject(
                "attestation intent is empty".into(),
            ));
        }
        Ok(())
    }
}

/// Registry hook for per-`(petal_id, intent)` attestation schema validation.
///
/// The daemon consults this before signing: the attestation's `schema` must
/// be allowed for the `(petal_id, intent)` pair and its `facts` must conform
/// to that schema. Concrete registry + validation logic land with the grant
/// service (TODO(ws-A)); this trait freezes the contract shape.
pub trait SigningAttestationSchemaRegistry: Send + Sync {
    /// Whether `schema` is a registered attestation schema for
    /// `(petal_id, intent)`.
    fn is_allowed(&self, petal_id: &str, intent: &str, schema: &str) -> bool;

    /// Validate the attestation's schema registration and fact shape.
    /// Must fail closed for unknown `(petal_id, intent, schema)` tuples.
    fn validate_attestation(&self, attestation: &SigningAttestation) -> Result<(), AuthApiError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalCredentialRecord {
    pub wallet: String,
    pub credential_id: String,
    pub signer_kind: SignerKind,
    pub assurance: AssuranceLevel,
    pub public_key_json: serde_json::Value,
    pub registered_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_ms: Option<u64>,
}

impl ApprovalCredentialRecord {
    pub fn validate(&self) -> Result<(), AuthApiError> {
        if self.wallet.trim().is_empty() {
            return Err(AuthApiError::Denied("credential wallet is empty".into()));
        }
        if self.credential_id.trim().is_empty() {
            return Err(AuthApiError::Denied("credential_id is empty".into()));
        }
        if !self.signer_kind.satisfies(self.assurance) {
            return Err(AuthApiError::Denied(format!(
                "credential signer {:?} does not satisfy {:?} assurance",
                self.signer_kind, self.assurance
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValuationQuote {
    pub asset_id: String,
    pub amount_base_units: String,
    pub usd_micro: i128,
    pub source: String,
    pub quote_timestamp_ms: u64,
    pub fetched_at_ms: u64,
    pub max_age_ms: u64,
    pub confidence_ppm: Option<u32>,
    pub stablecoin_assumption: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEntryState {
    Staged,
    Challenged,
    Approved,
    Submitting,
    Submitted,
    Settled,
    Failed,
    Unknown,
}

impl AuthEntryState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Challenged => "challenged",
            Self::Approved => "approved",
            Self::Submitting => "submitting",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonceState {
    Unused,
    Consumed,
}

impl NonceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unused => "unused",
            Self::Consumed => "consumed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthEntryRecord {
    pub surface: String,
    pub action_id: String,
    pub state: AuthEntryState,
    pub intent_hash: String,
    pub assurance: AssuranceLevel,
    pub nonce: Option<String>,
    pub nonce_state: NonceState,
    pub reservation_id: Option<String>,
    pub updated_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionRecord {
    pub review_session_id: String,
    pub surface: String,
    pub action_id: String,
    pub intent_hash: String,
    pub assurance: AssuranceLevel,
    pub expires_ms: u64,
    pub consumed_ms: Option<u64>,
    pub created_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Active,
    Committed,
    Released,
    Failed,
    Unknown,
}

impl ReservationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Committed => "committed",
            Self::Released => "released",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationRecord {
    pub reservation_id: String,
    pub wallet: String,
    pub venue: String,
    pub amount_micro_usd: i128,
    pub state: ReservationState,
    pub created_ms: u64,
    pub updated_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValuationPolicy {
    pub volatile_max_age_ms: u64,
    pub stablecoin_max_age_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence_ppm: Option<u32>,
    #[serde(default)]
    pub stablecoin_asset_allowlist: Vec<String>,
}

impl Default for ValuationPolicy {
    fn default() -> Self {
        Self {
            volatile_max_age_ms: 30_000,
            stablecoin_max_age_ms: 120_000,
            min_confidence_ppm: None,
            stablecoin_asset_allowlist: Vec::new(),
        }
    }
}

impl ValuationPolicy {
    pub fn max_age_for(&self, quote: &ValuationQuote) -> u64 {
        let policy_age = if quote.stablecoin_assumption {
            self.stablecoin_max_age_ms
        } else {
            self.volatile_max_age_ms
        };
        quote.max_age_ms.min(policy_age)
    }

    pub fn stablecoin_allowed(&self, asset_id: &str) -> bool {
        self.stablecoin_asset_allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(asset_id))
    }
}

impl ValuationQuote {
    pub fn is_fresh_at(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.fetched_at_ms) <= self.max_age_ms
    }

    pub fn validate_for_authorization(
        &self,
        policy: &ValuationPolicy,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        if self.asset_id.trim().is_empty() {
            return Err(AuthApiError::Denied("valuation asset_id is empty".into()));
        }
        if self.amount_base_units.trim().is_empty() {
            return Err(AuthApiError::Denied(
                "valuation amount_base_units is empty".into(),
            ));
        }
        if self.source.trim().is_empty() {
            return Err(AuthApiError::Denied("valuation source is empty".into()));
        }
        if self.usd_micro < 0 {
            return Err(AuthApiError::Denied("valuation is negative".into()));
        }
        if self.quote_timestamp_ms == 0 {
            return Err(AuthApiError::Denied(
                "valuation quote timestamp is missing".into(),
            ));
        }
        if self.fetched_at_ms == 0 {
            return Err(AuthApiError::Denied(
                "valuation fetched timestamp is missing".into(),
            ));
        }
        let max_age_ms = policy.max_age_for(self);
        if now_ms.saturating_sub(self.fetched_at_ms) > max_age_ms {
            return Err(AuthApiError::Denied(format!(
                "valuation quote is stale: age_ms={} max_age_ms={}",
                now_ms.saturating_sub(self.fetched_at_ms),
                max_age_ms
            )));
        }
        if let Some(min_confidence) = policy.min_confidence_ppm {
            match self.confidence_ppm {
                Some(confidence) if confidence >= min_confidence => {}
                Some(confidence) => {
                    return Err(AuthApiError::Denied(format!(
                        "valuation confidence {confidence}ppm below required {min_confidence}ppm"
                    )));
                }
                None => {
                    return Err(AuthApiError::Denied(
                        "valuation confidence is missing".into(),
                    ));
                }
            }
        }
        if self.stablecoin_assumption && !policy.stablecoin_allowed(&self.asset_id) {
            return Err(AuthApiError::Denied(format!(
                "stablecoin shortcut is not allowed for {}",
                self.asset_id
            )));
        }
        Ok(())
    }
}

#[async_trait]
pub trait PriceOracle: Send + Sync {
    async fn quote_usd(
        &self,
        asset_id: &str,
        amount_base_units: &str,
        now_ms: u64,
    ) -> Result<ValuationQuote, AuthApiError>;
}

/// Sealed intent as stored in daemon-controlled storage.
///
/// `action` is `None` only for rows sealed before the
/// `bloom.sealed_action.v1` schema; such rows fail closed at challenge
/// issuance and must be re-staged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedIntentRecord {
    pub intent_hash: String,
    pub envelope: CanonicalEnvelope,
    pub sealed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<SealedAction>,
}

#[async_trait]
pub trait AuthStoreView: Send + Sync {
    async fn sealed_intent(&self, intent_hash: &str) -> Result<SealedIntentRecord, AuthApiError>;
}

#[async_trait]
pub trait AuthStoreWriter: Send + Sync {
    /// Stage an envelope with restrictive default daemon terms and an empty
    /// Petal policy snapshot ([`SealedAction::seal_with_default_terms`]).
    // TODO(ws-F..ws-K): converted venues should stage via `stage_action` with
    // real terms/snapshot instead.
    async fn stage_entry(
        &self,
        envelope: CanonicalEnvelope,
        assurance: AssuranceLevel,
        now_ms: u64,
    ) -> Result<AuthEntryRecord, AuthApiError>;

    /// Stage a fully-populated sealed action (plan, policy checks, daemon
    /// terms, Petal policy snapshot).
    ///
    /// The default implementation fails closed for store writers that predate
    /// sealed-action staging (test doubles); the production store overrides it.
    async fn stage_action(
        &self,
        action: SealedAction,
        now_ms: u64,
    ) -> Result<AuthEntryRecord, AuthApiError> {
        let _ = (action, now_ms);
        Err(AuthApiError::Store(
            "stage_action is not supported by this auth store writer".into(),
        ))
    }

    async fn issue_challenge(
        &self,
        surface: &str,
        action_id: &str,
        server_nonce: &str,
        expiry_ms: u64,
        now_ms: u64,
    ) -> Result<ApprovalChallenge, AuthApiError>;

    async fn issue_review_session(
        &self,
        review_session_id: &str,
        surface: &str,
        action_id: &str,
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<ReviewSessionRecord, AuthApiError>;
}

#[async_trait]
pub trait ApprovalSignatureVerifier: Send + Sync {
    async fn verify_signature(
        &self,
        unsigned: &UnsignedApproval,
        webauthn_assertion: &WebAuthnAssertionRecord,
        now_ms: u64,
    ) -> Result<(), AuthApiError>;
}

#[async_trait]
pub trait ApprovalVerifier: Send + Sync {
    async fn verify_and_consume(
        &self,
        approval: SignedApproval,
        now_ms: u64,
    ) -> Result<(), AuthApiError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AuthApiError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid canonical subject: {0}")]
    InvalidSubject(String),
    #[error("invalid assurance transition: {0}")]
    InvalidAssuranceTransition(String),
    #[error("authorization denied: {0}")]
    Denied(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("store: {0}")]
    Store(String),
}

fn digest_hex(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_b64_any(value: &str) -> Result<Vec<u8>, AuthApiError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .map_err(|e| AuthApiError::Denied(format!("invalid base64 field: {e}")))
}

#[cfg(test)]
mod tests {
    use super::petal_identity::*;
    use super::*;

    fn header() -> CanonicalIntentHeader {
        CanonicalIntentHeader {
            schema: CANONICAL_INTENT_HEADER_SCHEMA_V2.into(),
            wallet: "my-wallet".into(),
            surface: "requests".into(),
            action_id: "req_1".into(),
            petal_id: PETAL_ID_PAID_HTTP.into(),
            petal_digest: PLACEHOLDER_DIGEST_PAID_HTTP.into(),
            petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
            executor_kind: ExecutorKind::FirstParty,
            network: "base".into(),
            account: "default".into(),
            action_kind: "x402_payment".into(),
            value_movement: true,
            authority_change: false,
            expires_ms: 10_000,
        }
    }

    #[test]
    fn intent_hash_is_full_256_bit_hex_and_changes_with_subject_kind() {
        let a = CanonicalEnvelope::new(
            header(),
            "paid_http",
            "paid_http.v1",
            br#"{"a":1}"#.to_vec(),
        );
        let b = CanonicalEnvelope::new(header(), "defi", "paid_http.v1", br#"{"a":1}"#.to_vec());
        let ah = a.intent_hash().unwrap();
        let bh = b.intent_hash().unwrap();
        assert_eq!(ah.len(), 64);
        assert_ne!(ah, bh);
    }

    #[test]
    fn intent_hash_of_matches_envelope_method() {
        let env = CanonicalEnvelope::new(
            header(),
            "paid_http",
            "paid_http.v1",
            br#"{"a":1}"#.to_vec(),
        );
        let via_method = env.intent_hash().unwrap();
        let via_fn = intent_hash_of(&env.canonical_bytes().unwrap());
        assert_eq!(via_method, via_fn);
    }

    #[test]
    fn intent_hash_of_uses_v2_domain_tag() {
        let bytes = br#"{"x":42}"#;
        let with_domain = intent_hash_of(bytes);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bloom.intent.v2");
        hasher.update(bytes);
        let manual = hasher.finalize().to_hex().to_string();

        assert_eq!(with_domain, manual);

        // Not the retired v1 domain, and not the untagged hash.
        let mut v1 = blake3::Hasher::new();
        v1.update(b"bloom.intent.v1");
        v1.update(bytes);
        assert_ne!(with_domain, v1.finalize().to_hex().to_string());

        let mut no_domain = blake3::Hasher::new();
        no_domain.update(bytes);
        assert_ne!(with_domain, no_domain.finalize().to_hex().to_string());
    }

    #[test]
    fn envelope_schema_is_v2() {
        let env = CanonicalEnvelope::new(header(), "paid_http", "paid_http.v1", b"{}".to_vec());
        assert_eq!(env.schema, "bloom.canonical_envelope.v2");
    }

    // ------------------------------------------------------------------
    // Field-binding tests: mutating every header / envelope field must
    // produce a different intent_hash.
    // ------------------------------------------------------------------

    /// Build a baseline envelope for mutation tests.
    fn baseline_envelope() -> CanonicalEnvelope {
        CanonicalEnvelope::new(
            header(),
            "paid_http",
            "paid_http.v1",
            br#"{"a":1}"#.to_vec(),
        )
    }

    /// Assert that mutating exactly one header field changes the hash.
    fn assert_hash_changes<F: FnOnce(&mut CanonicalIntentHeader)>(mutate: F) {
        let original = baseline_envelope();
        let mut h = header();
        mutate(&mut h);
        let modified =
            CanonicalEnvelope::new(h, "paid_http", "paid_http.v1", br#"{"a":1}"#.to_vec());
        assert_ne!(
            original.intent_hash().unwrap(),
            modified.intent_hash().unwrap(),
        );
    }

    #[test]
    fn intent_hash_binds_wallet() {
        assert_hash_changes(|h| h.wallet = "other-wallet".into());
    }

    #[test]
    fn intent_hash_binds_surface() {
        assert_hash_changes(|h| h.surface = "outbox".into());
    }

    #[test]
    fn intent_hash_binds_action_id() {
        assert_hash_changes(|h| h.action_id = "req_2".into());
    }

    #[test]
    fn intent_hash_binds_petal_id() {
        assert_hash_changes(|h| h.petal_id = PETAL_ID_EVM_WALLET.into());
    }

    #[test]
    fn intent_hash_binds_petal_digest() {
        assert_hash_changes(|h| h.petal_digest = PLACEHOLDER_DIGEST_EVM_WALLET.into());
    }

    #[test]
    fn intent_hash_binds_petal_version() {
        assert_hash_changes(|h| h.petal_version = "v1".into());
    }

    #[test]
    fn intent_hash_binds_executor_kind() {
        assert_hash_changes(|h| h.executor_kind = ExecutorKind::Wasm);
    }

    #[test]
    fn intent_hash_binds_expires_ms() {
        assert_hash_changes(|h| h.expires_ms = 10_001);
    }

    #[test]
    fn intent_hash_binds_network() {
        assert_hash_changes(|h| h.network = "ethereum".into());
    }

    #[test]
    fn intent_hash_binds_account() {
        assert_hash_changes(|h| h.account = "trading".into());
    }

    #[test]
    fn intent_hash_binds_action_kind() {
        assert_hash_changes(|h| h.action_kind = "erc20_transfer".into());
    }

    #[test]
    fn intent_hash_binds_value_movement() {
        assert_hash_changes(|h| h.value_movement = false);
    }

    #[test]
    fn intent_hash_binds_authority_change() {
        assert_hash_changes(|h| h.authority_change = true);
    }

    #[test]
    fn intent_hash_binds_subject_bytes() {
        let original = baseline_envelope();
        let modified = CanonicalEnvelope::new(
            header(),
            "paid_http",
            "paid_http.v1",
            br#"{"a":2}"#.to_vec(),
        );
        assert_ne!(
            original.intent_hash().unwrap(),
            modified.intent_hash().unwrap(),
        );
    }

    #[test]
    fn intent_hash_binds_subject_schema() {
        let original = baseline_envelope();
        let modified = CanonicalEnvelope::new(
            header(),
            "paid_http",
            "paid_http.v2",
            br#"{"a":1}"#.to_vec(),
        );
        assert_ne!(
            original.intent_hash().unwrap(),
            modified.intent_hash().unwrap(),
        );
    }

    // ------------------------------------------------------------------
    // Petal identity placeholders (§11.10)
    // ------------------------------------------------------------------

    #[test]
    fn placeholder_digests_are_labeled_and_resolvable() {
        for (petal_id, digest) in [
            (PETAL_ID_EVM_WALLET, PLACEHOLDER_DIGEST_EVM_WALLET),
            (PETAL_ID_PAID_HTTP, PLACEHOLDER_DIGEST_PAID_HTTP),
            (PETAL_ID_POLYMARKET, PLACEHOLDER_DIGEST_POLYMARKET),
            (PETAL_ID_HYPERLIQUID, PLACEHOLDER_DIGEST_HYPERLIQUID),
            (PETAL_ID_DEFI, PLACEHOLDER_DIGEST_DEFI),
            (PETAL_ID_WALLET_POLICY, PLACEHOLDER_DIGEST_WALLET_POLICY),
        ] {
            assert_eq!(digest, format!("first-party-placeholder:{petal_id}:v0"));
            assert!(is_placeholder_digest(digest), "{digest}");
            assert_eq!(placeholder_digest_for(petal_id), Some(digest));
        }
        assert!(!is_placeholder_digest("blake3:abcdef"));
        assert!(!is_placeholder_digest(""));
        assert_eq!(placeholder_digest_for("unknown-petal"), None);
    }

    // ------------------------------------------------------------------
    // DaemonGrantTerms / PetalPolicySnapshot digests
    // ------------------------------------------------------------------

    fn terms() -> DaemonGrantTerms {
        DaemonGrantTerms {
            max_ttl_secs: 120,
            max_signatures: 2,
            allowed_sign_intents: vec!["evm.tx.sign".into()],
            assurance: AssuranceLevel::Standard,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn daemon_terms_digest_is_domain_tagged_full_hex() {
        let t = terms();
        let digest = t.daemon_terms_digest().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, digest.to_lowercase());

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bloom.daemon_terms.v1");
        hasher.update(&t.canonical_bytes().unwrap());
        assert_eq!(digest, hasher.finalize().to_hex().to_string());
    }

    #[test]
    fn daemon_terms_digest_binds_every_field() {
        let base = terms().daemon_terms_digest().unwrap();
        let mut t = terms();
        t.max_ttl_secs = 60;
        assert_ne!(t.daemon_terms_digest().unwrap(), base);
        let mut t = terms();
        t.max_signatures = 1;
        assert_ne!(t.daemon_terms_digest().unwrap(), base);
        let mut t = terms();
        t.allowed_sign_intents = vec!["evm.tx.sign".into(), "wallet_policy.sign".into()];
        assert_ne!(t.daemon_terms_digest().unwrap(), base);
        let mut t = terms();
        t.assurance = AssuranceLevel::Hardened;
        assert_ne!(t.daemon_terms_digest().unwrap(), base);
        let mut t = terms();
        t.extra
            .insert("required.session".into(), serde_json::json!("s-1"));
        assert_ne!(t.daemon_terms_digest().unwrap(), base);
    }

    fn snapshot() -> PetalPolicySnapshot {
        let mut s = PetalPolicySnapshot::minimal(&header());
        s.policy_version = 3;
        s.caps
            .insert("max_tx_usd_micro".into(), serde_json::json!(1_000_000));
        s
    }

    #[test]
    fn petal_policy_digest_is_domain_tagged_and_binds_fields() {
        let s = snapshot();
        let digest = s.petal_policy_digest().unwrap();
        assert_eq!(digest.len(), 64);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bloom.petal_policy.v1");
        hasher.update(&s.canonical_bytes().unwrap());
        assert_eq!(digest, hasher.finalize().to_hex().to_string());

        let mut m = snapshot();
        m.policy_version = 4;
        assert_ne!(m.petal_policy_digest().unwrap(), digest);
        let mut m = snapshot();
        m.caps
            .insert("max_tx_usd_micro".into(), serde_json::json!(2_000_000));
        assert_ne!(m.petal_policy_digest().unwrap(), digest);
        let mut m = snapshot();
        m.hard_rules.push(PetalPolicyRule {
            rule_id: "geoblock".into(),
            message: "geoblocked".into(),
            params: BTreeMap::new(),
            step_up_ceiling: None,
        });
        assert_ne!(m.petal_policy_digest().unwrap(), digest);
        let mut m = snapshot();
        m.config
            .insert("endpoint".into(), serde_json::json!("https://x"));
        assert_ne!(m.petal_policy_digest().unwrap(), digest);
        let mut m = snapshot();
        m.budget_state
            .insert("spent_micro_usd".into(), serde_json::json!(1));
        assert_ne!(m.petal_policy_digest().unwrap(), digest);
        let mut m = snapshot();
        m.session_scope = Some(BTreeMap::new());
        assert_ne!(m.petal_policy_digest().unwrap(), digest);
    }

    // ------------------------------------------------------------------
    // SealedAction
    // ------------------------------------------------------------------

    fn sealed_action() -> SealedAction {
        let mut snapshot = PetalPolicySnapshot::minimal(&header());
        snapshot.policy_version = 3;
        SealedAction::new(
            baseline_envelope(),
            "plan".into(),
            vec![PolicyCheckResult {
                rule_id: "limits.max_tx_usd".into(),
                rule_class: PolicyCheckClass::StepUp,
                outcome: "pass".into(),
                message: "within limits".into(),
                step_up_ceiling: None,
            }],
            terms(),
            snapshot,
            5,
        )
        .unwrap()
    }

    #[test]
    fn sealed_action_derives_digest_version_and_expiry() {
        let action = sealed_action();
        assert_eq!(action.schema, "bloom.sealed_action.v1");
        assert_eq!(action.policy_version, 3);
        assert_eq!(action.expires_ms, action.envelope.header.expires_ms);
        assert_eq!(
            action.petal_policy_digest,
            action.petal_policy.petal_policy_digest().unwrap()
        );
        action.validate().unwrap();
    }

    #[test]
    fn sealed_action_rejects_identity_mismatch_with_snapshot() {
        let mut action = sealed_action();
        action.petal_policy.petal_id = PETAL_ID_EVM_WALLET.into();
        // Digest must be recomputed or validation fails on identity first.
        let err = action.validate().unwrap_err();
        assert!(err.to_string().contains("identity"), "{err}");
    }

    #[test]
    fn sealed_action_rejects_tampered_digest_and_version() {
        let mut action = sealed_action();
        action.petal_policy_digest = "0".repeat(64);
        let err = action.validate().unwrap_err();
        assert!(err.to_string().contains("petal_policy_digest"), "{err}");

        let mut action = sealed_action();
        action.policy_version = 99;
        let err = action.validate().unwrap_err();
        assert!(err.to_string().contains("policy_version"), "{err}");

        let mut action = sealed_action();
        action.expires_ms = 1;
        let err = action.validate().unwrap_err();
        assert!(err.to_string().contains("expires_ms"), "{err}");
    }

    #[test]
    fn sealed_action_rejects_wrong_header_schema() {
        let mut action = sealed_action();
        action.envelope.header.schema = "bloom.intent_header.v1".into();
        let err = action.validate().unwrap_err();
        assert!(err.to_string().contains("intent header schema"), "{err}");
    }

    #[test]
    fn seal_with_default_terms_is_restrictive() {
        let action =
            SealedAction::seal_with_default_terms(baseline_envelope(), AssuranceLevel::Hardened, 7)
                .unwrap();
        assert_eq!(action.daemon_terms.max_signatures, 1);
        assert!(action.daemon_terms.allowed_sign_intents.is_empty());
        assert_eq!(action.daemon_terms.assurance, AssuranceLevel::Hardened);
        assert_eq!(action.policy_version, 0);
        assert_eq!(action.created_ms, 7);
    }

    // ------------------------------------------------------------------
    // ApprovalChallenge binding (§5.7 / §12 item 18)
    // ------------------------------------------------------------------

    fn challenge() -> ApprovalChallenge {
        ApprovalChallenge {
            schema: APPROVAL_CHALLENGE_SCHEMA_V1.into(),
            action_id: "req_1".into(),
            wallet: "my-wallet".into(),
            surface: "requests".into(),
            petal_id: PETAL_ID_PAID_HTTP.into(),
            petal_digest: PLACEHOLDER_DIGEST_PAID_HTTP.into(),
            intent_hash: "0".repeat(64),
            server_nonce: "nonce-1".into(),
            assurance: AssuranceLevel::Standard,
            daemon_terms_digest: "1".repeat(64),
            petal_policy_digest: "2".repeat(64),
            policy_version: 3,
            expiry_ms: 10_000,
        }
    }

    fn assert_challenge_changes<F: FnOnce(&mut ApprovalChallenge)>(mutate: F) {
        let base = challenge().challenge_hash_hex().unwrap();
        let mut c = challenge();
        mutate(&mut c);
        assert_ne!(c.challenge_hash_hex().unwrap(), base);
    }

    #[test]
    fn challenge_hash_uses_approval_domain_tag() {
        let c = challenge();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bloom.approval.v1");
        hasher.update(&c.canonical_bytes().unwrap());
        assert_eq!(c.challenge_hash().unwrap(), *hasher.finalize().as_bytes());
    }

    #[test]
    fn challenge_binds_schema() {
        assert_challenge_changes(|c| c.schema = "bloom.approval_challenge.v2".into());
    }

    #[test]
    fn challenge_binds_action_id() {
        assert_challenge_changes(|c| c.action_id = "req_2".into());
    }

    #[test]
    fn challenge_binds_wallet() {
        assert_challenge_changes(|c| c.wallet = "other".into());
    }

    #[test]
    fn challenge_binds_surface() {
        assert_challenge_changes(|c| c.surface = "outbox".into());
    }

    #[test]
    fn challenge_binds_petal_id() {
        assert_challenge_changes(|c| c.petal_id = PETAL_ID_EVM_WALLET.into());
    }

    #[test]
    fn challenge_binds_petal_digest() {
        assert_challenge_changes(|c| c.petal_digest = PLACEHOLDER_DIGEST_EVM_WALLET.into());
    }

    #[test]
    fn challenge_binds_intent_hash() {
        assert_challenge_changes(|c| c.intent_hash = "f".repeat(64));
    }

    #[test]
    fn challenge_binds_server_nonce() {
        assert_challenge_changes(|c| c.server_nonce = "nonce-2".into());
    }

    #[test]
    fn challenge_binds_assurance() {
        assert_challenge_changes(|c| c.assurance = AssuranceLevel::Hardened);
    }

    #[test]
    fn challenge_binds_daemon_terms_digest() {
        assert_challenge_changes(|c| c.daemon_terms_digest = "9".repeat(64));
    }

    #[test]
    fn challenge_binds_petal_policy_digest() {
        assert_challenge_changes(|c| c.petal_policy_digest = "9".repeat(64));
    }

    #[test]
    fn challenge_binds_policy_version() {
        assert_challenge_changes(|c| c.policy_version = 4);
    }

    #[test]
    fn challenge_binds_expiry_ms() {
        assert_challenge_changes(|c| c.expiry_ms = 10_001);
    }

    #[test]
    fn unsigned_approval_challenge_hash_matches_issued_challenge() {
        let c = challenge();
        let unsigned =
            UnsignedApproval::for_challenge(&c, SignerTransport::BrowserWebauthn, None, None);
        assert_eq!(
            unsigned.challenge_hash().unwrap(),
            c.challenge_hash().unwrap()
        );
        // Transport metadata is not part of the signed preimage.
        let mut with_cred = unsigned.clone();
        with_cred.credential_id = Some("cred-1".into());
        with_cred.review_session_id = Some("review-1".into());
        with_cred.signer_transport = SignerTransport::NativeCtap2;
        assert_eq!(
            with_cred.challenge_hash().unwrap(),
            c.challenge_hash().unwrap()
        );
    }

    fn webauthn_assertion_for(unsigned: &UnsignedApproval) -> WebAuthnAssertionRecord {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(unsigned.challenge_hash().unwrap());
        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": "http://localhost:18734",
        });
        WebAuthnAssertionRecord {
            credential_id: "cred-1".into(),
            authenticator_data_b64: "AA".into(),
            client_data_json_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&client_data_json).unwrap()),
            signature_b64: "AA".into(),
            user_handle_b64: None,
        }
    }

    #[test]
    fn webauthn_assertion_challenge_binds_to_approval_preimage() {
        let unsigned = UnsignedApproval::for_challenge(
            &challenge(),
            SignerTransport::BrowserWebauthn,
            Some("cred-1".into()),
            None,
        );
        webauthn_assertion_for(&unsigned)
            .validate_challenge(&unsigned)
            .unwrap();

        let mut substituted = unsigned.clone();
        substituted.action_id = "other".into();
        let err = webauthn_assertion_for(&unsigned)
            .validate_challenge(&substituted)
            .unwrap_err();
        assert!(
            err.to_string().contains("challenge does not match"),
            "{err}"
        );
    }

    // ------------------------------------------------------------------
    // SignedApproval verification against sealed action + issued challenge
    // ------------------------------------------------------------------

    fn sealed_record_and_challenge() -> (SealedIntentRecord, ApprovalChallenge) {
        let action = sealed_action();
        let intent_hash = action.intent_hash().unwrap();
        let issued = ApprovalChallenge {
            schema: APPROVAL_CHALLENGE_SCHEMA_V1.into(),
            action_id: action.action_id().into(),
            wallet: action.wallet().into(),
            surface: action.surface().into(),
            petal_id: action.petal_id().into(),
            petal_digest: action.petal_digest().into(),
            intent_hash: intent_hash.clone(),
            server_nonce: "nonce-1".into(),
            assurance: AssuranceLevel::Standard,
            daemon_terms_digest: action.daemon_terms_digest().unwrap(),
            petal_policy_digest: action.petal_policy_digest.clone(),
            policy_version: action.policy_version,
            expiry_ms: 10_000,
        };
        let sealed = SealedIntentRecord {
            intent_hash,
            envelope: action.envelope.clone(),
            sealed_at_ms: 1,
            action: Some(action),
        };
        (sealed, issued)
    }

    fn approval_for(issued: &ApprovalChallenge) -> SignedApproval {
        let unsigned = UnsignedApproval::for_challenge(
            issued,
            SignerTransport::BrowserWebauthn,
            Some("cred-1".into()),
            None,
        );
        let assertion = webauthn_assertion_for(&unsigned);
        unsigned.into_signed(assertion)
    }

    #[test]
    fn approval_validation_accepts_faithful_echo() {
        let (sealed, issued) = sealed_record_and_challenge();
        approval_for(&issued)
            .validate_against_sealed(&sealed, &issued, 100)
            .unwrap();
    }

    #[test]
    fn approval_validation_rejects_expired_approval() {
        let (sealed, issued) = sealed_record_and_challenge();
        let err = approval_for(&issued)
            .validate_against_sealed(&sealed, &issued, 10_000)
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn approval_validation_rejects_any_daemon_issued_field_drift() {
        let (sealed, issued) = sealed_record_and_challenge();
        type DriftCase = (&'static str, Box<dyn FnOnce(&mut SignedApproval)>);
        let cases: Vec<DriftCase> = vec![
            ("action_id", Box::new(|a| a.action_id = "other".into())),
            ("wallet", Box::new(|a| a.wallet = "other".into())),
            ("surface", Box::new(|a| a.surface = "outbox".into())),
            (
                "petal_id",
                Box::new(|a| a.petal_id = PETAL_ID_EVM_WALLET.into()),
            ),
            (
                "petal_digest",
                Box::new(|a| a.petal_digest = PLACEHOLDER_DIGEST_EVM_WALLET.into()),
            ),
            ("intent_hash", Box::new(|a| a.intent_hash = "f".repeat(64))),
            (
                "server_nonce",
                Box::new(|a| a.server_nonce = "nonce-2".into()),
            ),
            (
                "daemon_terms_digest",
                Box::new(|a| a.daemon_terms_digest = "9".repeat(64)),
            ),
            (
                "petal_policy_digest",
                Box::new(|a| a.petal_policy_digest = "9".repeat(64)),
            ),
            (
                "assurance",
                Box::new(|a| a.assurance = AssuranceLevel::Hardened),
            ),
            ("policy_version", Box::new(|a| a.policy_version = 99)),
            ("expiry_ms", Box::new(|a| a.expiry_ms = 9_999)),
        ];
        for (field, mutate) in cases {
            let mut approval = approval_for(&issued);
            mutate(&mut approval);
            let err = approval
                .validate_against_sealed(&sealed, &issued, 100)
                .unwrap_err();
            assert!(err.to_string().contains("does not match"), "{field}: {err}");
        }
    }

    #[test]
    fn approval_validation_rejects_challenge_not_matching_sealed_action() {
        let (sealed, mut issued) = sealed_record_and_challenge();
        issued.intent_hash = "f".repeat(64);
        let err = approval_for(&issued)
            .validate_against_sealed(&sealed, &issued, 100)
            .unwrap_err();
        assert!(err.to_string().contains("sealed"), "{err}");
    }

    #[test]
    fn approval_validation_requires_stored_sealed_action() {
        let (mut sealed, issued) = sealed_record_and_challenge();
        sealed.action = None;
        let err = approval_for(&issued)
            .validate_against_sealed(&sealed, &issued, 100)
            .unwrap_err();
        assert!(err.to_string().contains("sealed action record"), "{err}");
    }

    #[test]
    fn signed_approval_serializes_as_spec_webauthn_record() {
        let (_sealed, issued) = sealed_record_and_challenge();
        let approval = approval_for(&issued);
        let value = serde_json::to_value(&approval).unwrap();
        assert_eq!(value["credential_id"], "cred-1");
        assert!(value.get("webauthn_assertion").is_some());
        assert!(value.get("signature").is_none());
    }

    // ------------------------------------------------------------------
    // SealedApprovalGrant
    // ------------------------------------------------------------------

    #[test]
    fn grant_expiry_is_min_of_ttl_and_approval_expiry() {
        let action = sealed_action();
        // Approval expiry far away: grant capped at issued + 120s.
        let grant = SealedApprovalGrant::mint("g-1", &action, 1_000_000, 1_000).unwrap();
        assert_eq!(grant.expiry_ms, 1_000 + GRANT_MAX_TTL_MS);
        // Approval expiry sooner: grant capped at approval expiry.
        let grant = SealedApprovalGrant::mint("g-2", &action, 50_000, 1_000).unwrap();
        assert_eq!(grant.expiry_ms, 50_000);
        assert_eq!(grant.max_signatures, action.daemon_terms.max_signatures);
        assert_eq!(grant.consumed_signature_count, 0);
        assert!(!grant.revoked);
        assert_eq!(grant.petal_id, action.petal_id());
        assert_eq!(grant.petal_digest, action.petal_digest());
        assert_eq!(grant.intent_hash, action.intent_hash().unwrap());
        assert_eq!(
            grant.petal_policy_digest,
            action.petal_policy_digest.clone()
        );
    }

    #[test]
    fn grant_respects_tighter_daemon_terms_ttl() {
        let mut snapshot = PetalPolicySnapshot::minimal(&header());
        snapshot.policy_version = 3;
        let mut t = terms();
        t.max_ttl_secs = 30;
        let action = SealedAction::new(
            baseline_envelope(),
            String::new(),
            Vec::new(),
            t,
            snapshot,
            5,
        )
        .unwrap();
        let grant = SealedApprovalGrant::mint("g-3", &action, 1_000_000, 1_000).unwrap();
        assert_eq!(grant.expiry_ms, 1_000 + 30_000);
    }

    #[test]
    fn grant_mint_fails_when_already_expired() {
        let action = sealed_action();
        let err = SealedApprovalGrant::mint("g-4", &action, 500, 1_000).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn grant_activity_tracks_expiry_count_and_revocation() {
        let action = sealed_action();
        let mut grant = SealedApprovalGrant::mint("g-5", &action, 1_000_000, 1_000).unwrap();
        assert!(grant.is_active_at(1_001));
        assert!(!grant.is_active_at(grant.expiry_ms));
        grant.consumed_signature_count = grant.max_signatures;
        assert!(!grant.is_active_at(1_001));
        grant.consumed_signature_count = 0;
        grant.revoked = true;
        assert!(!grant.is_active_at(1_001));
    }

    // ------------------------------------------------------------------
    // SignerKind / SignerTransport
    // ------------------------------------------------------------------

    #[test]
    fn password_never_satisfies_any_assurance() {
        assert!(!SignerKind::Password.satisfies(AssuranceLevel::Standard));
        assert!(!SignerKind::Password.satisfies(AssuranceLevel::Hardened));
        assert!(!SignerKind::Test.satisfies(AssuranceLevel::Standard));
        assert!(!SignerKind::Test.satisfies(AssuranceLevel::Hardened));
        assert!(SignerKind::PasskeyBrowser.satisfies(AssuranceLevel::Standard));
        assert!(SignerKind::PasskeyBrowser.satisfies(AssuranceLevel::Hardened));
        assert!(SignerKind::PasskeyCtap.satisfies(AssuranceLevel::Hardened));
    }

    #[test]
    fn signer_transport_serializes_to_spec_strings() {
        assert_eq!(
            serde_json::to_string(&SignerTransport::BrowserWebauthn).unwrap(),
            "\"browser_webauthn\""
        );
        assert_eq!(
            serde_json::to_string(&SignerTransport::NativeCtap2).unwrap(),
            "\"native_ctap2\""
        );
        assert_eq!(
            SignerTransport::BrowserWebauthn.as_str(),
            "browser_webauthn"
        );
        assert_eq!(SignerTransport::NativeCtap2.as_str(), "native_ctap2");
    }

    #[test]
    fn executor_kind_serializes_to_spec_strings() {
        assert_eq!(
            serde_json::to_string(&ExecutorKind::FirstParty).unwrap(),
            "\"first_party\""
        );
        assert_eq!(
            serde_json::to_string(&ExecutorKind::Wasm).unwrap(),
            "\"wasm\""
        );
    }

    #[test]
    fn approval_credential_record_rejects_non_passkey_signers() {
        let mut record = ApprovalCredentialRecord {
            wallet: "my-wallet".into(),
            credential_id: "cred-1".into(),
            signer_kind: SignerKind::PasskeyBrowser,
            assurance: AssuranceLevel::Hardened,
            public_key_json: serde_json::json!({"kty":"placeholder"}),
            registered_ms: 100,
            revoked_ms: None,
        };
        record.validate().unwrap();

        record.assurance = AssuranceLevel::Standard;
        record.signer_kind = SignerKind::Password;
        let err = record.validate().unwrap_err();
        assert!(err.to_string().contains("does not satisfy"), "{err}");

        record.signer_kind = SignerKind::Test;
        let err = record.validate().unwrap_err();
        assert!(err.to_string().contains("does not satisfy"), "{err}");
    }

    // ------------------------------------------------------------------
    // SigningAttestation
    // ------------------------------------------------------------------

    #[test]
    fn signing_attestation_requires_identity_fields() {
        let mut att = SigningAttestation {
            schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
            petal_id: PETAL_ID_EVM_WALLET.into(),
            intent: "evm.tx.sign".into(),
            facts: BTreeMap::new(),
        };
        att.validate().unwrap();
        att.schema = " ".into();
        assert!(att.validate().is_err());
        att.schema = SIGNING_ATTESTATION_SCHEMA_V1.into();
        att.intent = String::new();
        assert!(att.validate().is_err());
    }

    // ------------------------------------------------------------------
    // Valuation (unchanged behavior)
    // ------------------------------------------------------------------

    fn valuation_quote() -> ValuationQuote {
        ValuationQuote {
            asset_id: "ethereum:0x0000000000000000000000000000000000000001".into(),
            amount_base_units: "1000000000000000000".into(),
            usd_micro: 1_000_000,
            source: "test-oracle".into(),
            quote_timestamp_ms: 1_000,
            fetched_at_ms: 1_000,
            max_age_ms: 30_000,
            confidence_ppm: Some(990_000),
            stablecoin_assumption: false,
        }
    }

    #[test]
    fn valuation_validation_fails_closed_for_stale_or_low_confidence_quotes() {
        let policy = ValuationPolicy {
            min_confidence_ppm: Some(950_000),
            ..ValuationPolicy::default()
        };
        assert!(
            valuation_quote()
                .validate_for_authorization(&policy, 20_000)
                .is_ok()
        );

        let stale = valuation_quote();
        let err = stale
            .validate_for_authorization(&policy, 40_001)
            .unwrap_err();
        assert!(err.to_string().contains("stale"), "{err}");

        let mut low_confidence = valuation_quote();
        low_confidence.confidence_ppm = Some(900_000);
        let err = low_confidence
            .validate_for_authorization(&policy, 20_000)
            .unwrap_err();
        assert!(err.to_string().contains("below required"), "{err}");

        let mut missing_confidence = valuation_quote();
        missing_confidence.confidence_ppm = None;
        let err = missing_confidence
            .validate_for_authorization(&policy, 20_000)
            .unwrap_err();
        assert!(err.to_string().contains("missing"), "{err}");
    }

    #[test]
    fn stablecoin_shortcut_requires_explicit_asset_allowlist() {
        let mut quote = valuation_quote();
        quote.asset_id = "base:0x1234".into();
        quote.stablecoin_assumption = true;
        quote.max_age_ms = 120_000;
        let policy = ValuationPolicy {
            stablecoin_asset_allowlist: vec!["base:0xabcd".into()],
            ..ValuationPolicy::default()
        };
        let err = quote
            .validate_for_authorization(&policy, 60_000)
            .unwrap_err();
        assert!(err.to_string().contains("stablecoin shortcut"), "{err}");

        let policy = ValuationPolicy {
            stablecoin_asset_allowlist: vec!["base:0x1234".into()],
            ..ValuationPolicy::default()
        };
        assert!(quote.validate_for_authorization(&policy, 60_000).is_ok());
    }
}
