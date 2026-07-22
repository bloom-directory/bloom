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

mod wallet_registration;
pub use wallet_registration::*;

/// Schema tag for [`SignedApproval`] (`approval.json`).
pub const APPROVAL_SCHEMA_V1: &str = "bloom.approval.v1";
/// Schema tag for [`ApprovalChallenge`] (`challenge.json` / the signed preimage).
pub const APPROVAL_CHALLENGE_SCHEMA_V1: &str = "bloom.approval_challenge.v1";
/// Schema tag for [`SealedAction`] records in daemon-controlled storage.
pub const SEALED_ACTION_SCHEMA_V1: &str = "bloom.sealed_action.v1";
/// Schema tag for [`SigningAttestation`] envelopes.
pub const SIGNING_ATTESTATION_SCHEMA_V1: &str = "bloom.signing_attestation.v1";
/// Typed facts schema embedded in [`SigningAttestation::facts`] for dynamically loaded
/// Petal package signing.
pub const PETAL_SIGNING_ATTESTATION_FACTS_SCHEMA_V1: &str = "bloom.petal.signing_facts.v1";
/// Petal id prefix for dynamically loaded dynamically loaded Petals.
pub const PETAL_PETAL_ID_PREFIX: &str = "petal:";
/// Canonical subject schema for EVM wallet sealed actions.
pub const EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1: &str = "bloom.evm.sealed_intent.v1";
/// Canonical subject kind for EVM wallet sealed actions.
pub const EVM_SEALED_INTENT_SUBJECT_KIND: &str = "evm_wallet_tx";
/// Typed facts schema embedded in [`SigningAttestation::facts`] for
/// `(petal_id=evm-wallet, intent=evm.tx.sign)`.
pub const EVM_SIGNING_ATTESTATION_FACTS_SCHEMA_V1: &str = "bloom.evm.signing_facts.v1";
/// EVM wallet signing intent.
pub const EVM_TX_SIGN_INTENT: &str = "evm.tx.sign";
/// Hyperliquid owner approval intent for authorizing an API-wallet agent.
pub const HYPERLIQUID_APPROVE_AGENT_SIGN_INTENT: &str = "hyperliquid.approve_agent";
/// Hyperliquid owner transfer intent for `usdSend`.
pub const HYPERLIQUID_USD_SEND_SIGN_INTENT: &str = "hyperliquid.usd_send";
/// Typed facts schema embedded in [`SigningAttestation::facts`] for the
/// paid-HTTP (`paid-http`) signing intents (`x402.sign`, `paid-http.mpp.sign`).
pub const PAID_HTTP_SIGNING_ATTESTATION_FACTS_SCHEMA_V1: &str = "bloom.paid_http.signing_facts.v1";
/// Paid-HTTP x402 signing intent.
pub const PAID_HTTP_X402_SIGN_INTENT: &str = "x402.sign";
/// Paid-HTTP Tempo MPP signing intent.
pub const PAID_HTTP_MPP_SIGN_INTENT: &str = "paid-http.mpp.sign";

/// Schema tag for [`CanonicalEnvelope`].
pub const CANONICAL_ENVELOPE_SCHEMA_V1: &str = "bloom.canonical_envelope.v1";
/// Schema tag callers should place in [`CanonicalIntentHeader::schema`].
pub const CANONICAL_INTENT_HEADER_SCHEMA_V1: &str = "bloom.intent_header.v1";

/// Domain tag for [`intent_hash_of`].
///
/// Spec §5.2: this tag MUST be bumped whenever the canonical schema changes.
/// The initial schema binds Petal identity and header expiry.
pub const INTENT_HASH_DOMAIN: &[u8] = b"bloom.intent.v1";
/// Domain tag for the WebAuthn approval challenge hash (§5.7).
pub const APPROVAL_CHALLENGE_DOMAIN: &[u8] = b"bloom.approval.v1";
/// Domain tag for [`DaemonGrantTerms::daemon_terms_digest`].
pub const DAEMON_TERMS_DIGEST_DOMAIN: &[u8] = b"bloom.daemon_terms.v1";
/// Domain tag for [`PetalPolicySnapshot::petal_policy_digest`].
pub const PETAL_POLICY_DIGEST_DOMAIN: &[u8] = b"bloom.petal_policy.v1";
/// Domain tag for binding structured signing facts into daemon grant terms.
pub const SIGNING_ATTESTATION_FACTS_DIGEST_DOMAIN: &[u8] = b"bloom.signing_attestation.facts.v1";

/// Hard ceiling on Sealed Approval Grant lifetime (§6.4 recommended default).
pub const GRANT_MAX_TTL_MS: u64 = 120_000;

/// Loopback port the daemon-owned Sealed Approval ceremony server binds for
/// Interaction Mode 3 (mounted VFS). The `ceremony_url` written into
/// `approval_challenge.json` points here, and `bloom serve` binds the same
/// port; keeping it a single constant guarantees the URL the daemon projects
/// is the URL the daemon serves.
pub const LOCAL_CEREMONY_PORT: u16 = 18734;

/// Domain tag for the deterministic ceremony URL token derivation.
pub const CEREMONY_URL_TOKEN_DOMAIN: &[u8] = b"bloom.ceremony_url.v1";

/// Standing-session kind for bounded EVM owner-signing sessions.
pub const EVM_OWNER_SIGNING_SESSION_KIND: &str = "evm_owner_signing.v1";
/// Sealed action kind for minting an EVM owner-signing session.
pub const EVM_OWNER_SESSION_MINT_ACTION_KIND: &str = "evm_owner_session_mint";
/// Sealed action kind for using an EVM owner-signing session.
pub const EVM_OWNER_SESSION_USE_ACTION_KIND: &str = "evm_owner_session_use";
/// MVP session method: ERC-20 `transfer(address,uint256)`.
pub const EVM_ERC20_TRANSFER_METHOD: &str = "erc20_transfer";
/// ERC-20 `transfer(address,uint256)` selector.
pub const EVM_ERC20_TRANSFER_SELECTOR: &str = "0xa9059cbb";

/// First-party Petal identity constants and placeholder digests (spec §11.10).
pub mod petal_identity {
    /// `petal_id` for the EVM wallet tx first-party Petal (surface `wallets`/`outbox`).
    pub const PETAL_ID_EVM_WALLET: &str = "evm-wallet";
    /// `petal_id` for the paid HTTP (x402/MPP) first-party Petal (surface `requests`).
    pub const PETAL_ID_PAID_HTTP: &str = "paid-http";
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
            PETAL_ID_HYPERLIQUID => Some(PLACEHOLDER_DIGEST_HYPERLIQUID),
            PETAL_ID_DEFI => Some(PLACEHOLDER_DIGEST_DEFI),
            PETAL_ID_WALLET_POLICY => Some(PLACEHOLDER_DIGEST_WALLET_POLICY),
            _ => None,
        }
    }

    /// Diagnostic label for a `petal_digest` value: either a first-party
    /// placeholder or, eventually, a reproducible build/source digest.
    /// Spec §11.10 requires audit and status output to label placeholder
    /// digests so operators do not mistake them for code attestation.
    ///
    /// Today every first-party digest is a placeholder, so this returns
    /// `"placeholder"`; once reproducible build/source digests land, those
    /// non-placeholder digests will surface as `"build"`.
    pub fn label_petal_digest(digest: &str) -> &'static str {
        if is_placeholder_digest(digest) {
            "placeholder"
        } else {
            "build"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn placeholder_digest_returns_placeholder() {
            assert_eq!(
                label_petal_digest(PLACEHOLDER_DIGEST_EVM_WALLET),
                "placeholder"
            );
            assert_eq!(
                label_petal_digest(PLACEHOLDER_DIGEST_PAID_HTTP),
                "placeholder"
            );
            assert_eq!(
                label_petal_digest(PLACEHOLDER_DIGEST_HYPERLIQUID),
                "placeholder"
            );
            assert_eq!(label_petal_digest(PLACEHOLDER_DIGEST_DEFI), "placeholder");
            assert_eq!(
                label_petal_digest(PLACEHOLDER_DIGEST_WALLET_POLICY),
                "placeholder"
            );
            // The prefix is sufficient — any string starting with the
            // placeholder prefix is labelled as such.
            assert_eq!(
                label_petal_digest("first-party-placeholder:custom-petal:v1"),
                "placeholder"
            );
            // Empty digest is not a placeholder (it fails closed elsewhere).
            assert_eq!(label_petal_digest(""), "build");
        }

        #[test]
        fn build_digest_returns_build() {
            // Anything that doesn't start with the placeholder prefix is
            // labelled "build" — even malformed values, because the audit
            // and status layers are responsible for surfacing the kind so
            // operators do not mistake it for code attestation.
            assert_eq!(label_petal_digest("sha256:abcdef0123456789"), "build");
            assert_eq!(
                label_petal_digest("blake3:00112233445566778899aabbccddeeff"),
                "build"
            );
            assert_eq!(label_petal_digest("a"), "build");
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
            schema: CANONICAL_ENVELOPE_SCHEMA_V1.to_string(),
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
/// Uses BLAKE3 with the `bloom.intent.v1` domain tag, encoded as lowercase,
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
    /// (e.g. `evm.tx.sign`, `polymarket.order.v1`, `wallet_policy.sign`).
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
    /// Petal-specific limits (e.g. EVM `PolicyCaps` or Hyperliquid
    /// `max_notional_usd`), projected as a
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

/// Result of evaluating policy checks against a sealed snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// A Hard rule was violated — non-escalatable, always deny.
    pub hard_violation: bool,
    /// A Soft/StepUp rule was violated — step-up ceremony required to proceed.
    pub step_up_required: bool,
    /// A step-up rule's ceiling was exceeded — non-escalatable. Contains a
    /// deterministic denial string: `"rule {rule_id} exceeds ceiling"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exceeded_ceiling: Option<String>,
}

impl PolicyDecision {
    pub fn pass_through() -> Self {
        Self {
            hard_violation: false,
            step_up_required: false,
            exceeded_ceiling: None,
        }
    }
    pub fn is_denied(&self) -> bool {
        self.hard_violation || self.exceeded_ceiling.is_some()
    }
}

/// Evaluates policy checks against a sealed snapshot to produce a decision.
#[async_trait]
pub trait PolicyEvaluator: Send + Sync {
    async fn evaluate(
        &self,
        snapshot: &PetalPolicySnapshot,
        checks: &[PolicyCheckResult],
        now_ms: u64,
    ) -> Result<PolicyDecision, AuthApiError>;
}

/// The sealed action record persisted in daemon-controlled storage (§6.1).
///
/// The wrapped [`CanonicalEnvelope`] remains the sole intent-hash preimage
/// (`intent_hash = BLAKE3("bloom.intent.v1" || envelope canonical bytes)`);
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
        if self.envelope.schema != CANONICAL_ENVELOPE_SCHEMA_V1 {
            return Err(AuthApiError::InvalidSubject(format!(
                "unsupported canonical envelope schema {}",
                self.envelope.schema
            )));
        }
        let header = &self.envelope.header;
        if header.schema != CANONICAL_INTENT_HEADER_SCHEMA_V1 {
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

    /// The human-readable chain name (e.g. `"base"`) this action targets, as
    /// carried in the sealed Petal policy snapshot at seal time.
    ///
    /// Prefer this over [`PetalPolicySnapshot`]'s `network` header, which is the
    /// CAIP-2 form (`"eip155:<chain_id>"`): the outbox directory layout and the
    /// daemon `ChainRegistry` are both keyed by this human name, so lookups that
    /// use the CAIP-2 header silently miss.
    pub fn chain_name(&self) -> Option<&str> {
        self.petal_policy
            .config
            .get("chain_name")
            .and_then(|v| v.as_str())
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
    /// Browser ceremony URL for mounted/daemon flows. Projection metadata only:
    /// it is intentionally excluded from the WebAuthn challenge hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony_url: Option<String>,
}

impl ApprovalChallenge {
    /// Deterministic single-use ceremony URL token derived from `server_nonce`.
    ///
    /// `token = base64url(BLAKE3("bloom.ceremony_url.v1" || server_nonce))`.
    /// Because it is a pure function of the (single-use) nonce, it is stable
    /// across repeated confirm writes that reuse an unexpired challenge, and
    /// the daemon can resolve it back to a pending challenge by recomputing the
    /// same derivation for each stored nonce (BLAKE3 is one-way, so lookup is a
    /// scan-and-match rather than an inversion). The token is not part of the
    /// signed challenge preimage.
    pub fn ceremony_token(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CEREMONY_URL_TOKEN_DOMAIN);
        hasher.update(self.server_nonce.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize().as_bytes())
    }

    /// Deterministic local ceremony URL for mounted daemon flows.
    ///
    /// The token is derived from `server_nonce` and therefore remains stable
    /// for an unexpired reused challenge. Full internet relay exposure can
    /// swap the base URL without changing the signed challenge preimage.
    pub fn local_ceremony_url(&self) -> String {
        format!(
            "http://localhost:{}/ceremony/{}",
            LOCAL_CEREMONY_PORT,
            self.ceremony_token()
        )
    }

    pub fn with_local_ceremony_url(mut self) -> Self {
        self.ceremony_url = Some(self.local_ceremony_url());
        self
    }

    /// Canonical preimage bytes. Deterministic: fields serialize in declaration
    /// order. Projection metadata such as `ceremony_url` is deliberately not
    /// part of this preimage.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthApiError> {
        #[derive(Serialize)]
        struct ApprovalChallengeHashPreimage<'a> {
            schema: &'a str,
            action_id: &'a str,
            wallet: &'a str,
            surface: &'a str,
            petal_id: &'a str,
            petal_digest: &'a str,
            intent_hash: &'a str,
            server_nonce: &'a str,
            assurance: AssuranceLevel,
            daemon_terms_digest: &'a str,
            petal_policy_digest: &'a str,
            policy_version: u64,
            expiry_ms: u64,
        }

        serde_json::to_vec(&ApprovalChallengeHashPreimage {
            schema: &self.schema,
            action_id: &self.action_id,
            wallet: &self.wallet,
            surface: &self.surface,
            petal_id: &self.petal_id,
            petal_digest: &self.petal_digest,
            intent_hash: &self.intent_hash,
            server_nonce: &self.server_nonce,
            assurance: self.assurance,
            daemon_terms_digest: &self.daemon_terms_digest,
            petal_policy_digest: &self.petal_policy_digest,
            policy_version: self.policy_version,
            expiry_ms: self.expiry_ms,
        })
        .map_err(AuthApiError::Json)
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
            ceremony_url: None,
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
    /// Exact Petal build/source digest this attestation claims to come from.
    /// Bound into every host-side grant lookup so a Petal cannot borrow a
    /// grant minted for a different build.
    pub petal_digest: String,
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
        if self.petal_digest.trim().is_empty() {
            return Err(AuthApiError::InvalidSubject(
                "attestation petal_digest is empty".into(),
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

/// Facts attested by the daemon-owned Petal signing bridge.
///
/// A component receives only `(wallet, hash32, intent)` through the WIT
/// interface. The runner supplies the remaining provenance from the resolved
/// package and route, so an app cannot select another app identity or route
/// when requesting a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PetalSigningAttestationFacts {
    pub facts_schema: String,
    pub action_id: String,
    pub wallet: String,
    pub surface: String,
    pub petal_id: String,
    pub petal_digest: String,
    pub petal_version: String,
    pub petal_root: String,
    pub package_hash: String,
    pub route_id: String,
    pub op: String,
    pub path: String,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    pub intent: String,
    pub signing_hash: String,
    pub policy_snapshot_digest: String,
}

/// Whether `petal_id` names a dynamically loaded dynamically loaded application.
pub fn is_petal_petal_id(petal_id: &str) -> bool {
    petal_id
        .strip_prefix(PETAL_PETAL_ID_PREFIX)
        .is_some_and(|petal_root| !petal_root.trim().is_empty())
}

impl PetalSigningAttestationFacts {
    pub fn to_facts_map(&self) -> Result<BTreeMap<String, serde_json::Value>, AuthApiError> {
        match serde_json::to_value(self).map_err(AuthApiError::Json)? {
            serde_json::Value::Object(map) => Ok(map.into_iter().collect()),
            _ => Err(AuthApiError::InvalidSubject(
                "petal attestation facts did not serialize as an object".into(),
            )),
        }
    }

    pub fn from_facts_map(
        facts: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, AuthApiError> {
        let map: serde_json::Map<String, serde_json::Value> = facts.clone().into_iter().collect();
        serde_json::from_value(serde_json::Value::Object(map)).map_err(AuthApiError::Json)
    }

    pub fn signing_attestation(&self) -> Result<SigningAttestation, AuthApiError> {
        self.validate()?;
        Ok(SigningAttestation {
            schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
            petal_id: self.petal_id.clone(),
            petal_digest: self.petal_digest.clone(),
            intent: self.intent.clone(),
            facts: self.to_facts_map()?,
        })
    }

    pub fn from_attestation(attestation: &SigningAttestation) -> Result<Self, AuthApiError> {
        if attestation.schema != SIGNING_ATTESTATION_SCHEMA_V1 {
            return Err(AuthApiError::Denied(format!(
                "unsupported attestation schema {}",
                attestation.schema
            )));
        }
        if !is_petal_petal_id(&attestation.petal_id) {
            return Err(AuthApiError::Denied(
                "petal attestation petal_id mismatch".into(),
            ));
        }
        let typed = Self::from_facts_map(&attestation.facts)?;
        typed.validate()?;
        if typed.petal_id != attestation.petal_id
            || typed.petal_digest != attestation.petal_digest
            || typed.intent != attestation.intent
        {
            return Err(AuthApiError::Denied(
                "petal attestation envelope does not match typed facts".into(),
            ));
        }
        Ok(typed)
    }

    pub fn validate(&self) -> Result<(), AuthApiError> {
        if self.facts_schema != PETAL_SIGNING_ATTESTATION_FACTS_SCHEMA_V1 {
            return Err(AuthApiError::Denied(format!(
                "unsupported petal attestation facts schema {}",
                self.facts_schema
            )));
        }
        for (name, value) in [
            ("action_id", &self.action_id),
            ("wallet", &self.wallet),
            ("petal_id", &self.petal_id),
            ("petal_digest", &self.petal_digest),
            ("petal_version", &self.petal_version),
            ("petal_root", &self.petal_root),
            ("package_hash", &self.package_hash),
            ("route_id", &self.route_id),
            ("op", &self.op),
            ("intent", &self.intent),
            ("signing_hash", &self.signing_hash),
            ("policy_snapshot_digest", &self.policy_snapshot_digest),
        ] {
            validate_required(name, value).map_err(denied_from_invalid)?;
        }
        if self.surface != "petals" {
            return Err(AuthApiError::Denied(
                "petal attestation surface must be apps".into(),
            ));
        }
        if !is_petal_petal_id(&self.petal_id) {
            return Err(AuthApiError::Denied(
                "petal attestation petal_id must use petal: prefix".into(),
            ));
        }
        if self.petal_id != format!("{PETAL_PETAL_ID_PREFIX}{}", self.petal_root)
            || self.petal_digest != self.package_hash
        {
            return Err(AuthApiError::Denied(
                "petal attestation identity does not match package provenance".into(),
            ));
        }
        if self.package_hash.len() != 64
            || !self
                .package_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthApiError::Denied(
                "petal attestation package_hash must be a lowercase BLAKE3 digest".into(),
            ));
        }
        if !matches!(self.op.as_str(), "lookup" | "list" | "read" | "write") {
            return Err(AuthApiError::Denied(
                "petal attestation operation is unsupported".into(),
            ));
        }
        let hash = self
            .signing_hash
            .strip_prefix("0x")
            .unwrap_or(&self.signing_hash);
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AuthApiError::Denied(
                "petal attestation signing_hash must be a 32-byte hex value".into(),
            ));
        }
        Ok(())
    }
}

/// Collision-resistant, domain-tagged digest of a signing attestation facts
/// map. The map is ordered so serde JSON output is deterministic.
pub fn signing_attestation_facts_digest(
    facts: &BTreeMap<String, serde_json::Value>,
) -> Result<String, AuthApiError> {
    let bytes = serde_json::to_vec(facts).map_err(AuthApiError::Json)?;
    Ok(digest_hex(SIGNING_ATTESTATION_FACTS_DIGEST_DOMAIN, &bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvmSealedActionKind {
    Confirm,
    Replace,
    Cancel,
    OwnerSessionUse,
}

impl EvmSealedActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirm => "confirm",
            Self::Replace => "replace",
            Self::Cancel => "cancel",
            Self::OwnerSessionUse => "owner_session_use",
        }
    }

    fn is_one_shot(self) -> bool {
        matches!(self, Self::Confirm | Self::Replace | Self::Cancel)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmTokenFact {
    pub chain_id: u64,
    pub token_address: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmValueFact {
    /// Native ETH value in wei as a decimal string.
    pub native_value_wei: String,
    /// Token amount in base units as a decimal string, if this action moves a
    /// token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_amount_base_units: Option<String>,
    /// Frozen valuation used by policy/budget checks, if computed at seal
    /// time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valuation_usd_micro: Option<i128>,
    /// Structured quote bound to the sealed action when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valuation: Option<ValuationQuote>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmCallFact {
    /// Transaction target (`to`) or contract target.
    pub to: String,
    /// End-recipient when the target is a token/contract method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Calldata bytes as `0x`-prefixed lowercase hex. Empty calldata is `0x`.
    pub calldata_hex: String,
    /// `0x` + lowercase 32-byte hash of `calldata_hex`.
    pub calldata_hash: String,
    /// Human/action method label, e.g. `native_transfer`, `erc20.transfer`.
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmNonceIntent {
    /// Deterministic nonce mode, e.g. `exact`, `next`, or `same_as_original`.
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_action_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmFeeFacts {
    /// EVM transaction type, e.g. `eip1559` or `legacy`.
    pub tx_type: String,
    pub gas_limit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas_wei: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas_wei: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_price_wei: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_fee_wei: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmUnsignedEnvelopeFacts {
    /// Raw unsigned transaction/envelope kind, e.g. `eip1559_rlp`.
    pub envelope_kind: String,
    /// `0x` + lowercase 32-byte hash of the raw unsigned transaction bytes.
    pub unsigned_tx_bytes_hash: String,
    /// `0x` + lowercase 32-byte EVM signing hash recomputed from the sealed
    /// unsigned envelope.
    pub signing_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmOriginalTxFact {
    pub original_action_id: String,
    pub original_tx_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_nonce: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmOwnerSessionUseFact {
    pub session_id: String,
    pub reservation_id: String,
    pub token_address: String,
    pub recipient: String,
    pub daily_cap_base_units: String,
    pub expires_ms: u64,
    pub max_signature_count: u32,
}

/// Deterministic EVM sealed subject used as the canonical intent subject for
/// confirm, replace, cancel, and bounded owner-session-use actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmSealedIntentSubject {
    pub schema: String,
    pub action_id: String,
    pub wallet: String,
    pub surface: String,
    pub petal_id: String,
    pub petal_digest: String,
    pub petal_version: String,
    pub action_kind: EvmSealedActionKind,
    pub chain_id: u64,
    pub account: String,
    pub call: EvmCallFact,
    pub value: EvmValueFact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<EvmTokenFact>,
    pub nonce_intent: EvmNonceIntent,
    pub fee_facts: EvmFeeFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_fee_facts: Option<EvmFeeFacts>,
    pub unsigned_envelope: EvmUnsignedEnvelopeFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_tx: Option<EvmOriginalTxFact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_session_use: Option<EvmOwnerSessionUseFact>,
    pub policy_snapshot_digest: String,
    pub policy_snapshot: PetalPolicySnapshot,
    pub daemon_terms: DaemonGrantTerms,
    pub daemon_terms_digest: String,
    #[serde(default)]
    pub authority_change: bool,
}

impl EvmSealedIntentSubject {
    pub fn validate_evm(&self) -> Result<(), AuthApiError> {
        if self.schema != EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1 {
            return Err(AuthApiError::InvalidSubject(format!(
                "unsupported EVM sealed intent schema {}",
                self.schema
            )));
        }
        validate_required("action_id", &self.action_id)?;
        validate_required("wallet", &self.wallet)?;
        validate_required("surface", &self.surface)?;
        validate_required("account", &self.account)?;
        if self.petal_id != petal_identity::PETAL_ID_EVM_WALLET
            && !is_petal_petal_id(&self.petal_id)
        {
            return Err(AuthApiError::InvalidSubject(
                "EVM sealed intent petal_id must be evm-wallet or a Petal".into(),
            ));
        }
        if self.petal_digest.trim().is_empty() || self.petal_version.trim().is_empty() {
            return Err(AuthApiError::InvalidSubject(
                "EVM sealed intent is missing Petal identity".into(),
            ));
        }
        if self.chain_id == 0 {
            return Err(AuthApiError::InvalidSubject(
                "EVM sealed intent chain_id is zero".into(),
            ));
        }
        self.call.validate()?;
        self.value.validate()?;
        if let Some(token) = &self.token {
            token.validate(self.chain_id)?;
        }
        self.nonce_intent.validate()?;
        self.fee_facts.validate("fee_facts")?;
        if let Some(fee) = &self.replacement_fee_facts {
            fee.validate("replacement_fee_facts")?;
        }
        self.unsigned_envelope.validate()?;
        if let Some(original) = &self.original_tx {
            original.validate()?;
        }
        if let Some(session_use) = &self.owner_session_use {
            session_use.validate()?;
        }
        let computed_policy_digest = self.policy_snapshot.petal_policy_digest()?;
        if self.policy_snapshot_digest != computed_policy_digest {
            return Err(AuthApiError::InvalidSubject(
                "EVM policy_snapshot_digest does not match policy_snapshot".into(),
            ));
        }
        if self.policy_snapshot.wallet != self.wallet
            || self.policy_snapshot.petal_id != self.petal_id
            || self.policy_snapshot.petal_digest != self.petal_digest
        {
            return Err(AuthApiError::InvalidSubject(
                "EVM policy snapshot identity mismatch".into(),
            ));
        }
        if !self
            .daemon_terms
            .allowed_sign_intents
            .iter()
            .any(|intent| intent == EVM_TX_SIGN_INTENT)
        {
            return Err(AuthApiError::InvalidSubject(
                "EVM daemon terms must allow evm.tx.sign".into(),
            ));
        }
        if self.action_kind.is_one_shot() && self.daemon_terms.max_signatures != 1 {
            return Err(AuthApiError::InvalidSubject(
                "EVM one-shot actions must allow exactly one signature".into(),
            ));
        }
        if self.daemon_terms_digest != self.daemon_terms.daemon_terms_digest()? {
            return Err(AuthApiError::InvalidSubject(
                "EVM daemon_terms_digest does not match daemon_terms".into(),
            ));
        }
        Ok(())
    }

    pub fn canonical_header(&self, expires_ms: u64) -> CanonicalIntentHeader {
        CanonicalIntentHeader {
            schema: CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
            wallet: self.wallet.clone(),
            surface: self.surface.clone(),
            action_id: self.action_id.clone(),
            petal_id: self.petal_id.clone(),
            petal_digest: self.petal_digest.clone(),
            petal_version: self.petal_version.clone(),
            executor_kind: ExecutorKind::FirstParty,
            network: format!("eip155:{}", self.chain_id),
            account: self.account.clone(),
            action_kind: self.action_kind.as_str().into(),
            value_movement: self.value.has_value_movement(),
            authority_change: self.authority_change,
            expires_ms,
        }
    }

    pub fn canonical_envelope(&self, expires_ms: u64) -> Result<CanonicalEnvelope, AuthApiError> {
        Ok(CanonicalEnvelope::new(
            self.canonical_header(expires_ms),
            self.subject_kind(),
            self.subject_schema(),
            self.canonical_subject_bytes()?,
        ))
    }

    pub fn signing_attestation_facts(&self) -> EvmSigningAttestationFacts {
        EvmSigningAttestationFacts {
            facts_schema: EVM_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
            action_id: self.action_id.clone(),
            wallet: self.wallet.clone(),
            surface: self.surface.clone(),
            petal_id: self.petal_id.clone(),
            petal_digest: self.petal_digest.clone(),
            petal_version: self.petal_version.clone(),
            action_kind: self.action_kind,
            chain_id: self.chain_id,
            account: self.account.clone(),
            to: self.call.to.clone(),
            recipient: self.call.recipient.clone(),
            value: self.value.clone(),
            token: self.token.clone(),
            method: self.call.method.clone(),
            calldata_hash: self.call.calldata_hash.clone(),
            nonce_intent: self.nonce_intent.clone(),
            fee_facts: self.fee_facts.clone(),
            replacement_fee_facts: self.replacement_fee_facts.clone(),
            unsigned_envelope: self.unsigned_envelope.clone(),
            signing_hash: self.unsigned_envelope.signing_hash.clone(),
            policy_snapshot_digest: self.policy_snapshot_digest.clone(),
            daemon_terms_digest: self.daemon_terms_digest.clone(),
        }
    }
}

impl CanonicalSubject for EvmSealedIntentSubject {
    fn subject_kind(&self) -> &'static str {
        EVM_SEALED_INTENT_SUBJECT_KIND
    }

    fn subject_schema(&self) -> &'static str {
        EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1
    }

    fn validate(&self) -> Result<(), AuthApiError> {
        self.validate_evm()
    }

    fn canonical_subject_bytes(&self) -> Result<Vec<u8>, AuthApiError> {
        self.validate_evm()?;
        serde_json::to_vec(self).map_err(AuthApiError::Json)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmSigningAttestationFacts {
    pub facts_schema: String,
    pub action_id: String,
    pub wallet: String,
    pub surface: String,
    pub petal_id: String,
    pub petal_digest: String,
    pub petal_version: String,
    pub action_kind: EvmSealedActionKind,
    pub chain_id: u64,
    pub account: String,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub value: EvmValueFact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<EvmTokenFact>,
    pub method: String,
    pub calldata_hash: String,
    pub nonce_intent: EvmNonceIntent,
    pub fee_facts: EvmFeeFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_fee_facts: Option<EvmFeeFacts>,
    pub unsigned_envelope: EvmUnsignedEnvelopeFacts,
    pub signing_hash: String,
    pub policy_snapshot_digest: String,
    pub daemon_terms_digest: String,
}

impl EvmSigningAttestationFacts {
    pub fn to_facts_map(&self) -> Result<BTreeMap<String, serde_json::Value>, AuthApiError> {
        match serde_json::to_value(self).map_err(AuthApiError::Json)? {
            serde_json::Value::Object(map) => Ok(map.into_iter().collect()),
            _ => Err(AuthApiError::InvalidSubject(
                "EVM attestation facts did not serialize as an object".into(),
            )),
        }
    }

    pub fn from_facts_map(
        facts: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Self, AuthApiError> {
        let map: serde_json::Map<String, serde_json::Value> = facts.clone().into_iter().collect();
        serde_json::from_value(serde_json::Value::Object(map)).map_err(AuthApiError::Json)
    }

    pub fn signing_attestation(&self) -> Result<SigningAttestation, AuthApiError> {
        self.validate()?;
        Ok(SigningAttestation {
            schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
            petal_id: self.petal_id.clone(),
            petal_digest: self.petal_digest.clone(),
            intent: EVM_TX_SIGN_INTENT.into(),
            facts: self.to_facts_map()?,
        })
    }

    pub fn from_attestation(attestation: &SigningAttestation) -> Result<Self, AuthApiError> {
        if attestation.schema != SIGNING_ATTESTATION_SCHEMA_V1 {
            return Err(AuthApiError::Denied(format!(
                "unsupported attestation schema {}",
                attestation.schema
            )));
        }
        if attestation.intent != EVM_TX_SIGN_INTENT {
            return Err(AuthApiError::Denied(
                "EVM attestation intent mismatch".into(),
            ));
        }
        if attestation.petal_id != petal_identity::PETAL_ID_EVM_WALLET
            && !is_petal_petal_id(&attestation.petal_id)
        {
            return Err(AuthApiError::Denied(
                "EVM attestation petal_id must be evm-wallet or a Petal".into(),
            ));
        }
        let typed = Self::from_facts_map(&attestation.facts)?;
        typed.validate()?;
        if typed.petal_id != attestation.petal_id {
            return Err(AuthApiError::Denied(
                "EVM attestation fact petal_id mismatch".into(),
            ));
        }
        if typed.petal_digest != attestation.petal_digest {
            return Err(AuthApiError::Denied(
                "EVM attestation fact petal_digest mismatch".into(),
            ));
        }
        Ok(typed)
    }

    pub fn validate(&self) -> Result<(), AuthApiError> {
        if self.facts_schema != EVM_SIGNING_ATTESTATION_FACTS_SCHEMA_V1 {
            return Err(AuthApiError::Denied(format!(
                "unsupported EVM attestation facts schema {}",
                self.facts_schema
            )));
        }
        validate_required("action_id", &self.action_id).map_err(denied_from_invalid)?;
        validate_required("wallet", &self.wallet).map_err(denied_from_invalid)?;
        validate_required("surface", &self.surface).map_err(denied_from_invalid)?;
        validate_required("account", &self.account).map_err(denied_from_invalid)?;
        validate_required("to", &self.to).map_err(denied_from_invalid)?;
        validate_required("method", &self.method).map_err(denied_from_invalid)?;
        if self.petal_id != petal_identity::PETAL_ID_EVM_WALLET
            && !is_petal_petal_id(&self.petal_id)
        {
            return Err(AuthApiError::Denied(
                "EVM attestation petal_id must be evm-wallet or a Petal".into(),
            ));
        }
        validate_required("petal_digest", &self.petal_digest).map_err(denied_from_invalid)?;
        validate_required("petal_version", &self.petal_version).map_err(denied_from_invalid)?;
        if self.chain_id == 0 {
            return Err(AuthApiError::Denied(
                "EVM attestation chain_id is zero".into(),
            ));
        }
        self.value.validate().map_err(denied_from_invalid)?;
        if let Some(token) = &self.token {
            token.validate(self.chain_id).map_err(denied_from_invalid)?;
        }
        self.nonce_intent.validate().map_err(denied_from_invalid)?;
        self.fee_facts
            .validate("fee_facts")
            .map_err(denied_from_invalid)?;
        if let Some(fee) = &self.replacement_fee_facts {
            fee.validate("replacement_fee_facts")
                .map_err(denied_from_invalid)?;
        }
        self.unsigned_envelope
            .validate()
            .map_err(denied_from_invalid)?;
        validate_hash32_hex("calldata_hash", &self.calldata_hash).map_err(denied_from_invalid)?;
        validate_hash32_hex("signing_hash", &self.signing_hash).map_err(denied_from_invalid)?;
        validate_digest_hex("policy_snapshot_digest", &self.policy_snapshot_digest)
            .map_err(denied_from_invalid)?;
        validate_digest_hex("daemon_terms_digest", &self.daemon_terms_digest)
            .map_err(denied_from_invalid)?;
        if self.signing_hash != self.unsigned_envelope.signing_hash {
            return Err(AuthApiError::Denied(
                "EVM attestation signing_hash mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_against_subject(
        &self,
        subject: &EvmSealedIntentSubject,
    ) -> Result<(), AuthApiError> {
        self.validate()?;
        subject.validate_evm()?;
        let expected = subject.signing_attestation_facts();
        if self != &expected {
            return Err(AuthApiError::Denied(
                "EVM attestation facts do not match sealed intent".into(),
            ));
        }
        Ok(())
    }
}

impl EvmTokenFact {
    fn validate(&self, chain_id: u64) -> Result<(), AuthApiError> {
        if self.chain_id != chain_id {
            return Err(AuthApiError::InvalidSubject(
                "EVM token chain_id mismatch".into(),
            ));
        }
        validate_required("token_address", &self.token_address)?;
        validate_required("token_symbol", &self.symbol)?;
        Ok(())
    }
}

impl EvmValueFact {
    fn validate(&self) -> Result<(), AuthApiError> {
        validate_decimal_string("native_value_wei", &self.native_value_wei)?;
        if let Some(amount) = &self.token_amount_base_units {
            validate_decimal_string("token_amount_base_units", amount)?;
        }
        Ok(())
    }

    fn has_value_movement(&self) -> bool {
        self.native_value_wei != "0"
            || self
                .token_amount_base_units
                .as_ref()
                .is_some_and(|amount| amount != "0")
    }
}

impl EvmCallFact {
    fn validate(&self) -> Result<(), AuthApiError> {
        validate_required("to", &self.to)?;
        validate_required("calldata_hex", &self.calldata_hex)?;
        validate_required("method", &self.method)?;
        if !self.calldata_hex.starts_with("0x") {
            return Err(AuthApiError::InvalidSubject(
                "calldata_hex must be 0x-prefixed".into(),
            ));
        }
        validate_hash32_hex("calldata_hash", &self.calldata_hash)?;
        Ok(())
    }
}

impl EvmNonceIntent {
    fn validate(&self) -> Result<(), AuthApiError> {
        validate_required("nonce_mode", &self.mode)?;
        if self.mode == "same_as_original" && self.original_action_id.is_none() {
            return Err(AuthApiError::InvalidSubject(
                "same_as_original nonce intent requires original_action_id".into(),
            ));
        }
        Ok(())
    }
}

impl EvmFeeFacts {
    fn validate(&self, field: &str) -> Result<(), AuthApiError> {
        validate_required("fee tx_type", &self.tx_type)?;
        validate_decimal_string("gas_limit", &self.gas_limit)?;
        match self.tx_type.as_str() {
            "eip1559" => {
                let max_fee = self.max_fee_per_gas_wei.as_ref().ok_or_else(|| {
                    AuthApiError::InvalidSubject(format!("{field} missing max_fee_per_gas_wei"))
                })?;
                let priority = self.max_priority_fee_per_gas_wei.as_ref().ok_or_else(|| {
                    AuthApiError::InvalidSubject(format!(
                        "{field} missing max_priority_fee_per_gas_wei"
                    ))
                })?;
                validate_decimal_string("max_fee_per_gas_wei", max_fee)?;
                validate_decimal_string("max_priority_fee_per_gas_wei", priority)?;
            }
            "legacy" => {
                let gas_price = self.gas_price_wei.as_ref().ok_or_else(|| {
                    AuthApiError::InvalidSubject(format!("{field} missing gas_price_wei"))
                })?;
                validate_decimal_string("gas_price_wei", gas_price)?;
            }
            other => {
                return Err(AuthApiError::InvalidSubject(format!(
                    "{field} has unsupported tx_type {other}"
                )));
            }
        }
        if let Some(total) = &self.max_total_fee_wei {
            validate_decimal_string("max_total_fee_wei", total)?;
        }
        Ok(())
    }
}

impl EvmUnsignedEnvelopeFacts {
    fn validate(&self) -> Result<(), AuthApiError> {
        validate_required("envelope_kind", &self.envelope_kind)?;
        validate_hash32_hex("unsigned_tx_bytes_hash", &self.unsigned_tx_bytes_hash)?;
        validate_hash32_hex("signing_hash", &self.signing_hash)?;
        Ok(())
    }
}

impl EvmOriginalTxFact {
    fn validate(&self) -> Result<(), AuthApiError> {
        validate_required("original_action_id", &self.original_action_id)?;
        validate_hash32_hex("original_tx_hash", &self.original_tx_hash)?;
        Ok(())
    }
}

impl EvmOwnerSessionUseFact {
    fn validate(&self) -> Result<(), AuthApiError> {
        validate_required("session_id", &self.session_id)?;
        validate_required("reservation_id", &self.reservation_id)?;
        validate_required("token_address", &self.token_address)?;
        validate_required("recipient", &self.recipient)?;
        validate_decimal_string("daily_cap_base_units", &self.daily_cap_base_units)?;
        if self.expires_ms == 0 {
            return Err(AuthApiError::InvalidSubject(
                "owner session expires_ms is zero".into(),
            ));
        }
        if self.max_signature_count == 0 {
            return Err(AuthApiError::InvalidSubject(
                "owner session max_signature_count is zero".into(),
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

/// Default allow-list implementation of [`SigningAttestationSchemaRegistry`].
///
/// Covers the first-party `(petal_id, intent)` pairs already named as
/// constants in [`petal_identity`]. Each pair accepts
/// [`SIGNING_ATTESTATION_SCHEMA_V1`]; per-venue rule semantics land in WS-4..9
/// so the per-(petal_id, intent) `facts` shape validation is intentionally
/// minimal in this wave.
#[derive(Debug, Default, Clone)]
pub struct DefaultAttestationRegistry;

impl DefaultAttestationRegistry {
    pub fn new() -> Self {
        Self
    }

    fn allowed_pair(petal_id: &str, intent: &str) -> bool {
        use petal_identity::{
            PETAL_ID_DEFI, PETAL_ID_EVM_WALLET, PETAL_ID_HYPERLIQUID, PETAL_ID_PAID_HTTP,
            PETAL_ID_WALLET_POLICY,
        };
        matches!(
            (petal_id, intent),
            (PETAL_ID_EVM_WALLET, EVM_TX_SIGN_INTENT)
                | (PETAL_ID_PAID_HTTP, "x402.sign")
                | (PETAL_ID_PAID_HTTP, "paid-http.mpp.sign")
                | (PETAL_ID_HYPERLIQUID, HYPERLIQUID_APPROVE_AGENT_SIGN_INTENT)
                | (PETAL_ID_HYPERLIQUID, HYPERLIQUID_USD_SEND_SIGN_INTENT)
                | (PETAL_ID_HYPERLIQUID, "hyperliquid.order")
                | (PETAL_ID_HYPERLIQUID, "hyperliquid.cancel")
                | (PETAL_ID_WALLET_POLICY, "wallet_policy.sign")
                | (PETAL_ID_DEFI, "defi.route.sign")
        )
    }
}

impl SigningAttestationSchemaRegistry for DefaultAttestationRegistry {
    fn is_allowed(&self, petal_id: &str, intent: &str, schema: &str) -> bool {
        if schema != SIGNING_ATTESTATION_SCHEMA_V1 {
            return false;
        }
        is_petal_petal_id(petal_id) || Self::allowed_pair(petal_id, intent)
    }

    fn validate_attestation(&self, attestation: &SigningAttestation) -> Result<(), AuthApiError> {
        attestation.validate()?;
        if attestation.schema != SIGNING_ATTESTATION_SCHEMA_V1 {
            return Err(AuthApiError::Denied(format!(
                "unsupported attestation schema {}",
                attestation.schema
            )));
        }
        if !is_petal_petal_id(&attestation.petal_id)
            && !Self::allowed_pair(&attestation.petal_id, &attestation.intent)
        {
            return Err(AuthApiError::Denied(format!(
                "unsupported attestation schema for ({}, {})",
                attestation.petal_id, attestation.intent
            )));
        }
        if attestation.intent == EVM_TX_SIGN_INTENT
            && (attestation.petal_id == petal_identity::PETAL_ID_EVM_WALLET
                || is_petal_petal_id(&attestation.petal_id))
        {
            EvmSigningAttestationFacts::from_attestation(attestation)?;
        } else if is_petal_petal_id(&attestation.petal_id) {
            PetalSigningAttestationFacts::from_attestation(attestation)?;
        }
        if attestation.petal_id == petal_identity::PETAL_ID_PAID_HTTP
            && matches!(
                attestation.intent.as_str(),
                PAID_HTTP_X402_SIGN_INTENT | PAID_HTTP_MPP_SIGN_INTENT
            )
        {
            validate_paid_http_signing_facts(&attestation.intent, &attestation.facts)?;
        }
        Ok(())
    }
}

/// Fetch a required, non-empty string fact for a paid-HTTP attestation.
fn paid_http_required_str<'a>(
    facts: &'a BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, AuthApiError> {
    match facts.get(key) {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Ok(s.as_str()),
        _ => Err(AuthApiError::Denied(format!(
            "paid-http attestation facts must include non-empty string {key}"
        ))),
    }
}

/// Assert an optional paid-HTTP string fact is either absent, null, or a string.
fn paid_http_optional_str(
    facts: &BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Result<(), AuthApiError> {
    match facts.get(key) {
        None | Some(serde_json::Value::Null) | Some(serde_json::Value::String(_)) => Ok(()),
        Some(_) => Err(AuthApiError::Denied(format!(
            "paid-http attestation fact {key} must be a string when present"
        ))),
    }
}

/// Shape validation for `(paid-http, x402.sign|paid-http.mpp.sign)` attestation
/// `facts` (spec §8). This is a trust-boundary shape check only: it asserts the
/// fact map projected by `RequestsHandler` is well formed and internally
/// consistent (protocol matches the intent, hashes/digests are well formed). It
/// does NOT reconstruct the sealed subject or protocol signing digest — that
/// trust boundary stays with the handler.
fn validate_paid_http_signing_facts(
    intent: &str,
    facts: &BTreeMap<String, serde_json::Value>,
) -> Result<(), AuthApiError> {
    let schema = paid_http_required_str(facts, "facts_schema")?;
    if schema != PAID_HTTP_SIGNING_ATTESTATION_FACTS_SCHEMA_V1 {
        return Err(AuthApiError::Denied(format!(
            "unsupported paid-http attestation facts schema {schema}"
        )));
    }
    for key in ["action_id", "wallet", "request_id", "method", "url", "host"] {
        paid_http_required_str(facts, key)?;
    }
    let signing_hash = paid_http_required_str(facts, "signing_hash")?;
    validate_hash32_hex("signing_hash", signing_hash).map_err(denied_from_invalid)?;

    // `protocol` must be present and must match the signing intent.
    let protocol = paid_http_required_str(facts, "protocol")?;
    let expected_protocol = match intent {
        PAID_HTTP_X402_SIGN_INTENT => "x402",
        PAID_HTTP_MPP_SIGN_INTENT => "mpp",
        other => {
            return Err(AuthApiError::Denied(format!(
                "unsupported paid-http signing intent {other}"
            )));
        }
    };
    if protocol != expected_protocol {
        return Err(AuthApiError::Denied(format!(
            "paid-http attestation protocol {protocol} does not match intent {intent}"
        )));
    }

    // Sealed `/requests` always projects the policy snapshot digest, so require
    // it as a well-formed digest string.
    let digest = paid_http_required_str(facts, "policy_snapshot_digest")?;
    validate_digest_hex("policy_snapshot_digest", digest).map_err(denied_from_invalid)?;

    for key in [
        "network",
        "asset",
        "amount",
        "pay_to",
        "resource",
        "scheme",
        "charge_id",
        "session_id",
        "channel_id",
    ] {
        paid_http_optional_str(facts, key)?;
    }

    match facts.get("chain_id") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Number(n)) if n.as_u64().is_some_and(|v| v > 0) => {}
        Some(_) => {
            return Err(AuthApiError::Denied(
                "paid-http attestation chain_id must be a positive integer when present".into(),
            ));
        }
    }

    // The selected payment requirement is bound for legibility; accept the
    // staged requirement JSON (object) or an explicit null, but reject an
    // obviously invalid scalar echo.
    match facts.get("selected_requirement") {
        Some(serde_json::Value::Object(_)) | Some(serde_json::Value::Null) => {}
        None => {
            return Err(AuthApiError::Denied(
                "paid-http attestation is missing selected_requirement".into(),
            ));
        }
        Some(_) => {
            return Err(AuthApiError::Denied(
                "paid-http attestation selected_requirement must be an object or null".into(),
            ));
        }
    }
    Ok(())
}

// ── PetalHost (WS-1 host signing API) ────────────────────────────────────────

/// The daemon-cut, host-side view of a Petal context: the canonical bytes the
/// Petal commits to, plus the daemon-owned policy/terms digests that bind
/// any signature back to a specific sealed action snapshot.
///
/// Produced by [`PetalHost::seal_context`] and shown to the user as part of
/// the plan / ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPetalContext {
    /// Lowercase, full-length, untruncated hex BLAKE3 of the canonical intent
    /// envelope bytes (the same bytes that produce `intent_hash`).
    pub canonical_intent_bytes_hash: String,
    /// Same as the canonical hash, but explicitly tagged with the
    /// `bloom.intent.v1` domain (== `intent_hash_of(canonical_bytes)`).
    pub intent_hash: String,
    pub daemon_terms_digest: String,
    pub petal_policy_digest: String,
    pub policy_version: u64,
    pub petal_id: String,
}

/// `sign-hash` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignHashRequest {
    pub wallet: String,
    pub action_id: String,
    pub intent: String,
    /// `0x` + 64 lowercase hex chars — the 32-byte hash the wallet key signs.
    pub hash_hex: String,
}

/// One entry in a daemon-sealed ordered signing batch. The optional facts
/// digest binds the hash-specific attestation used for this exact entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSignBatchEntry {
    pub wallet: String,
    pub intent: String,
    pub hash_hex: String,
    pub attestation_facts_digest: String,
}

/// Sealed signature returned by [`PetalHost::sign_hash`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSignature {
    pub intent_hash: String,
    pub signature_b64: String,
    pub signed_at_ms: u64,
}

/// Structured event the host appends to its audit log via [`PetalHost::audit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    pub message: String,
}

/// Host signing API for first-party Petals (WS-1, §7).
///
/// `PetalHost` is the seam through which a Petal obtains a wallet signature
/// for an arbitrary 32-byte hash. Every call is gated on a live
/// [`SealedApprovalGrant`] for `(wallet, action_id, petal_id, petal_digest)`
/// and on a [`SigningAttestation`] whose schema is registered for
/// `(petal_id, intent)` by the wired [`SigningAttestationSchemaRegistry`].
#[async_trait]
pub trait PetalHost: Send + Sync {
    /// Build the sealed Petal context for a given Petal id (audit/plan view).
    async fn seal_context(&self, petal_id: &str) -> Result<SealedPetalContext, AuthApiError>;

    /// Daemon-cut snapshot of the wallet's policy for a Petal (the same
    /// snapshot that gets bound into a sealed action and the approval
    /// challenge). Returned verbatim so a Petal can render its policy view.
    async fn sealed_policy_snapshot(
        &self,
        wallet: &str,
        petal_id: &str,
    ) -> Result<PetalPolicySnapshot, AuthApiError>;

    /// Sign a 32-byte hash with the wallet key under an active grant.
    ///
    /// The grant is consumed atomically; the signature is returned alongside
    /// the `intent_hash` of the sealed action the grant was minted for, so a
    /// caller can correlate the signature back to the originating sealed
    /// action in audit.
    async fn sign_hash(
        &self,
        request: SignHashRequest,
        attestation: &SigningAttestation,
        now_ms: u64,
    ) -> Result<SealedSignature, AuthApiError>;

    /// Sign a daemon-sealed ordered batch. The default is deliberately
    /// fail-closed; hosts opting in must validate every entry before exposing
    /// any signature to the caller. Signature production is not transactional:
    /// an unexpected signer or audit failure may consume a prefix internally,
    /// but that prefix is never returned and the caller must obtain a fresh
    /// approval rather than append or resume the sealed request set.
    async fn sign_hash_batch(
        &self,
        _requests: Vec<SignHashRequest>,
        _attestations: &[SigningAttestation],
        _now_ms: u64,
    ) -> Result<Vec<SealedSignature>, AuthApiError> {
        Err(AuthApiError::Denied(
            "batch signing is not supported by this host".into(),
        ))
    }

    /// Append a structured audit event to the host audit log.
    async fn audit(&self, event: AuditEvent) -> Result<(), AuthApiError>;
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

/// Cross-Bloom standing session metadata (spec §6.4).
///
/// This record holds only non-secret session bookkeeping — wallet, scope,
/// frozen caps/counters, and audit trail. Owner key material stays in-memory
/// only and is never persisted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingSessionRecord {
    pub session_id: String,
    pub wallet: String,
    pub petal_id: String,
    pub session_kind: String,
    pub scope: serde_json::Value,
    pub counters: serde_json::Value,
    pub frozen_policy_version: u64,
    pub frozen_petal_policy_digest: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub revoked_ms: Option<u64>,
    pub orphan: bool,
    pub created_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EvmFeePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas_wei: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas_wei: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_fee_wei: Option<String>,
}

/// Non-secret scope sealed into an EVM owner-signing standing session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmOwnerSigningSessionScope {
    pub wallet: String,
    pub chain_id: u64,
    pub token_contract: String,
    pub recipient: String,
    pub method: String,
    pub daily_cap_base_units: String,
    pub ttl_ms: u64,
    pub fee_policy: EvmFeePolicy,
    pub max_signature_count: u32,
    pub autonomy_classification: String,
    pub policy_snapshot_digest: String,
    pub petal_id: String,
    pub petal_digest: String,
    pub petal_version: String,
    pub reason: String,
    #[serde(default)]
    pub native_transfers_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmOwnerSigningSessionCounters {
    pub daily_window_start_ms: u64,
    pub spent_base_units: String,
    pub reserved_base_units: String,
    pub signature_count: u32,
    #[serde(default)]
    pub pending_reservations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmOwnerSigningSessionUse {
    pub wallet: String,
    pub chain_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    pub token_contract: String,
    pub recipient: String,
    pub method: String,
    pub calldata_hex: String,
    pub amount_base_units: String,
    #[serde(default = "default_zero_wei")]
    pub value_wei: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas_wei: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas_wei: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_fee_wei: Option<String>,
}

fn default_zero_wei() -> String {
    "0".to_string()
}

/// Deterministic, machine-comparable reasons for denying a standing-session
/// request. The stable string form ([`Self::as_deterministic_str`]) is what
/// callers compare on; never reorder or reword without a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDenialReason {
    Orphan,
    BudgetExhausted,
    ScopeMismatch,
    Expired,
    Revoked,
    WrongWallet,
    WrongToken,
    WrongRecipient,
    WrongChain,
    WrongMethod,
    WrongCalldata,
    WrongAmount,
    FeePolicy,
    NativeTransfer,
    SignatureCount,
    MissingSignerMaterial,
    Halted,
}

impl SessionDenialReason {
    pub fn as_deterministic_str(self) -> &'static str {
        match self {
            Self::Orphan => "session_orphaned_requires_reapproval",
            Self::BudgetExhausted => "session_budget_exhausted",
            Self::ScopeMismatch => "session_scope_mismatch",
            Self::Expired => "session_expired",
            Self::Revoked => "session_revoked",
            Self::WrongWallet => "session_wrong_wallet",
            Self::WrongToken => "session_wrong_token",
            Self::WrongRecipient => "session_wrong_recipient",
            Self::WrongChain => "session_wrong_chain",
            Self::WrongMethod => "session_wrong_method",
            Self::WrongCalldata => "session_wrong_calldata",
            Self::WrongAmount => "session_wrong_amount",
            Self::FeePolicy => "session_fee_policy_mismatch",
            Self::NativeTransfer => "session_native_transfer_not_scoped",
            Self::SignatureCount => "session_signature_count_exhausted",
            Self::MissingSignerMaterial => "session_missing_signer_material",
            Self::Halted => "session_halted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValuationPolicy {
    pub volatile_max_age_ms: u64,
    pub stablecoin_max_age_ms: u64,
    /// Maximum acceptable age of the upstream market observation. This is
    /// deliberately separate from the local cache/fetch age.
    #[serde(default = "default_observation_max_age_ms")]
    pub observation_max_age_ms: u64,
    /// Small allowance for provider/local clock skew.
    #[serde(default = "default_future_tolerance_ms")]
    pub future_tolerance_ms: u64,
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
            observation_max_age_ms: default_observation_max_age_ms(),
            future_tolerance_ms: default_future_tolerance_ms(),
            min_confidence_ppm: None,
            stablecoin_asset_allowlist: Vec::new(),
        }
    }
}

const fn default_observation_max_age_ms() -> u64 {
    5 * 60 * 1_000
}

const fn default_future_tolerance_ms() -> u64 {
    60 * 1_000
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
        if self.quote_timestamp_ms > now_ms.saturating_add(policy.future_tolerance_ms) {
            return Err(AuthApiError::Denied(
                "valuation quote timestamp is in the future".into(),
            ));
        }
        let observation_age_ms = now_ms.saturating_sub(self.quote_timestamp_ms);
        if observation_age_ms > policy.observation_max_age_ms {
            return Err(AuthApiError::Denied(format!(
                "valuation market observation is stale: age_ms={observation_age_ms} max_age_ms={}",
                policy.observation_max_age_ms
            )));
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
        asset_decimals: u8,
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

/// Outcome of resolving a mounted-ceremony URL token to a stored challenge
/// (Interaction Mode 3). Distinguishes the three HTTP responses the ceremony
/// server owes a client: serve the page, `410 Gone`, or `404 Not Found`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyTokenResolution {
    /// The token maps to a live, unexpired, unconsumed challenge. Carries the
    /// daemon-issued challenge and the sealed action so the ceremony page can
    /// render the daemon-produced plan without reading mutable VFS projections.
    Live {
        challenge: Box<ApprovalChallenge>,
        action: Box<SealedAction>,
    },
    /// The token maps to a known challenge that is expired or already consumed
    /// (single-use): the ceremony server must return a 410-style response.
    Gone,
    /// The token does not match any stored challenge: 404-style response.
    Unknown,
}

#[async_trait]
pub trait AuthStoreView: Send + Sync {
    async fn sealed_intent(&self, intent_hash: &str) -> Result<SealedIntentRecord, AuthApiError>;

    /// Resolve a deterministic ceremony URL token (see
    /// [`ApprovalChallenge::ceremony_token`]) to a stored challenge for the
    /// daemon-owned Mode 3 ceremony server. The default fails closed as
    /// `Unknown`; the production store overrides it with a scan-and-match over
    /// challenged entries.
    async fn resolve_ceremony_token(
        &self,
        token: &str,
        now_ms: u64,
    ) -> Result<CeremonyTokenResolution, AuthApiError> {
        let _ = (token, now_ms);
        Ok(CeremonyTokenResolution::Unknown)
    }

    async fn standing_session(
        &self,
        session_id: &str,
    ) -> Result<Option<StandingSessionRecord>, AuthApiError> {
        let _ = session_id;
        Err(AuthApiError::Store(
            "standing_session is not supported by this auth store view".into(),
        ))
    }

    async fn active_standing_sessions(
        &self,
        wallet: &str,
        session_kind: Option<&str>,
        now_ms: u64,
    ) -> Result<Vec<StandingSessionRecord>, AuthApiError> {
        let _ = (wallet, session_kind, now_ms);
        Err(AuthApiError::Store(
            "active_standing_sessions is not supported by this auth store view".into(),
        ))
    }
}

#[async_trait]
pub trait AuthStoreWriter: Send + Sync {
    /// Allocate or retrieve the durable central action id for a venue-local id.
    ///
    /// Converted venue handlers use this before sealing so the central action id
    /// is the value bound into the canonical envelope, approval challenge, and
    /// grant tuple.
    async fn allocate_action_id(
        &self,
        surface: &str,
        venue_local_id: &str,
        wallet: &str,
        now_ms: u64,
    ) -> Result<String, AuthApiError> {
        let _ = (surface, venue_local_id, wallet, now_ms);
        Err(AuthApiError::Store(
            "allocate_action_id is not supported by this auth store writer".into(),
        ))
    }

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

    #[allow(clippy::too_many_arguments)]
    async fn create_standing_session(
        &self,
        session_id: &str,
        wallet: &str,
        petal_id: &str,
        session_kind: &str,
        scope: serde_json::Value,
        counters: serde_json::Value,
        frozen_policy_version: u64,
        frozen_petal_policy_digest: &str,
        issued_ms: u64,
        expires_ms: u64,
        now_ms: u64,
    ) -> Result<StandingSessionRecord, AuthApiError> {
        let _ = (
            session_id,
            wallet,
            petal_id,
            session_kind,
            scope,
            counters,
            frozen_policy_version,
            frozen_petal_policy_digest,
            issued_ms,
            expires_ms,
            now_ms,
        );
        Err(AuthApiError::Store(
            "create_standing_session is not supported by this auth store writer".into(),
        ))
    }

    async fn revoke_standing_session(
        &self,
        session_id: &str,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        let _ = (session_id, now_ms);
        Err(AuthApiError::Store(
            "revoke_standing_session is not supported by this auth store writer".into(),
        ))
    }

    async fn reserve_evm_owner_session_use(
        &self,
        session_id: &str,
        reservation_id: &str,
        request: EvmOwnerSigningSessionUse,
        signer_material_available: bool,
        now_ms: u64,
    ) -> Result<StandingSessionRecord, AuthApiError> {
        let _ = (
            session_id,
            reservation_id,
            request,
            signer_material_available,
            now_ms,
        );
        Err(AuthApiError::Store(
            "reserve_evm_owner_session_use is not supported by this auth store writer".into(),
        ))
    }

    async fn commit_evm_owner_session_use(
        &self,
        session_id: &str,
        reservation_id: &str,
        now_ms: u64,
    ) -> Result<StandingSessionRecord, AuthApiError> {
        let _ = (session_id, reservation_id, now_ms);
        Err(AuthApiError::Store(
            "commit_evm_owner_session_use is not supported by this auth store writer".into(),
        ))
    }

    async fn release_evm_owner_session_use(
        &self,
        session_id: &str,
        reservation_id: &str,
        now_ms: u64,
    ) -> Result<StandingSessionRecord, AuthApiError> {
        let _ = (session_id, reservation_id, now_ms);
        Err(AuthApiError::Store(
            "release_evm_owner_session_use is not supported by this auth store writer".into(),
        ))
    }
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

    /// Verify a signed approval, burn its nonce, and mint a
    /// [`SealedApprovalGrant`] for the same sealed action.
    ///
    /// The default implementation fails closed so existing implementations
    /// keep compiling; production verifiers (e.g. the store-backed
    /// implementation in `bloom-auth`) override it to hold both the verifier
    /// store mutex and the [`GrantStore`] mutex end-to-end, ensuring the
    /// nonce burn and the grant mint happen atomically.
    async fn verify_and_mint_grant(
        &self,
        _approval: SignedApproval,
        _grant_store: &dyn GrantStore,
        _now_ms: u64,
    ) -> Result<SealedApprovalGrant, AuthApiError> {
        Err(AuthApiError::Store(
            "verify_and_mint_grant not implemented".into(),
        ))
    }
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

fn denied_from_invalid(err: AuthApiError) -> AuthApiError {
    match err {
        AuthApiError::InvalidSubject(message) => AuthApiError::Denied(message),
        other => other,
    }
}

fn validate_required(field: &str, value: &str) -> Result<(), AuthApiError> {
    if value.trim().is_empty() {
        return Err(AuthApiError::InvalidSubject(format!("{field} is empty")));
    }
    Ok(())
}

fn validate_decimal_string(field: &str, value: &str) -> Result<(), AuthApiError> {
    validate_required(field, value)?;
    if value.len() > 1 && value.starts_with('0') {
        return Err(AuthApiError::InvalidSubject(format!(
            "{field} must use canonical decimal form"
        )));
    }
    if !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(AuthApiError::InvalidSubject(format!(
            "{field} must be a decimal string"
        )));
    }
    Ok(())
}

fn validate_digest_hex(field: &str, value: &str) -> Result<(), AuthApiError> {
    if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(AuthApiError::InvalidSubject(format!(
            "{field} must be 64 lowercase hex chars"
        )));
    }
    if value != value.to_lowercase() {
        return Err(AuthApiError::InvalidSubject(format!(
            "{field} must be lowercase"
        )));
    }
    Ok(())
}

fn validate_hash32_hex(field: &str, value: &str) -> Result<(), AuthApiError> {
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| AuthApiError::InvalidSubject(format!("{field} must be 0x-prefixed")))?;
    validate_digest_hex(field, hex)
}

#[cfg(test)]
mod tests {
    use super::petal_identity::*;
    use super::*;

    fn header() -> CanonicalIntentHeader {
        CanonicalIntentHeader {
            schema: CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
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
    fn intent_hash_of_uses_v1_domain_tag() {
        let bytes = br#"{"x":42}"#;
        let with_domain = intent_hash_of(bytes);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bloom.intent.v1");
        hasher.update(bytes);
        let manual = hasher.finalize().to_hex().to_string();

        assert_eq!(with_domain, manual);

        // Domain separation must differ from an untagged hash.
        let mut no_domain = blake3::Hasher::new();
        no_domain.update(bytes);
        assert_ne!(with_domain, no_domain.finalize().to_hex().to_string());
    }

    #[test]
    fn envelope_schema_is_v1() {
        let env = CanonicalEnvelope::new(header(), "paid_http", "paid_http.v1", b"{}".to_vec());
        assert_eq!(env.schema, "bloom.canonical_envelope.v1");
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
            "paid_http.unsupported",
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
    fn chain_name_reads_human_name_not_caip2_header() {
        // Absent from the policy snapshot → None (callers must not silently fall
        // back to the CAIP-2 `network` header, which the outbox/registry can't key).
        let bare = sealed_action();
        assert_eq!(bare.chain_name(), None);

        // Present → the human chain name the outbox and ChainRegistry key on.
        let mut snapshot = PetalPolicySnapshot::minimal(&header());
        snapshot.policy_version = 3;
        snapshot
            .config
            .insert("chain_name".into(), serde_json::json!("base"));
        let action = SealedAction::new(
            baseline_envelope(),
            "plan".into(),
            vec![],
            terms(),
            snapshot,
            5,
        )
        .unwrap();
        assert_eq!(action.chain_name(), Some("base"));
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
        action.envelope.header.schema = "bloom.intent_header.unsupported".into();
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
            ceremony_url: None,
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
    fn ceremony_token_is_stable_and_url_uses_shared_port() {
        let c = challenge();
        // Deterministic function of the (single-use) nonce.
        assert_eq!(c.ceremony_token(), c.ceremony_token());
        // Independently recompute the derivation.
        let mut hasher = blake3::Hasher::new();
        hasher.update(CEREMONY_URL_TOKEN_DOMAIN);
        hasher.update(c.server_nonce.as_bytes());
        let expected =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize().as_bytes());
        assert_eq!(c.ceremony_token(), expected);
        // The URL uses the shared daemon port and embeds the token.
        let url = c.local_ceremony_url();
        assert!(url.contains(&format!(":{LOCAL_CEREMONY_PORT}/ceremony/")));
        assert!(url.ends_with(&c.ceremony_token()));
        // A different nonce yields a different token; the token/URL are not part
        // of the signed challenge preimage.
        let mut other = challenge();
        other.server_nonce = "nonce-2".into();
        assert_ne!(other.ceremony_token(), c.ceremony_token());
        assert_eq!(
            c.challenge_hash_hex().unwrap(),
            c.clone()
                .with_local_ceremony_url()
                .challenge_hash_hex()
                .unwrap(),
        );
    }

    #[test]
    fn signed_approval_json_carries_assertion_not_prf() {
        let unsigned = UnsignedApproval::for_challenge(
            &challenge(),
            SignerTransport::BrowserWebauthn,
            Some("cred-1".into()),
            None,
        );
        let assertion = webauthn_assertion_for(&unsigned);
        let signed = unsigned.into_signed(assertion);
        let value = serde_json::to_value(&signed).unwrap();
        let obj = value.as_object().unwrap();
        // The audit artifact carries the WebAuthn assertion...
        assert!(obj.contains_key("webauthn_assertion"));
        // ...and nothing resembling PRF output, decrypted keys, or a grant.
        let json = serde_json::to_string(&signed).unwrap();
        for forbidden in ["prf", "grant", "private", "secret", "wrap_key"] {
            assert!(
                !json.to_lowercase().contains(forbidden),
                "approval.json must not contain '{forbidden}': {json}"
            );
        }
    }

    #[test]
    fn challenge_binds_schema() {
        assert_challenge_changes(|c| c.schema = "bloom.approval_challenge.unsupported".into());
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
    fn ceremony_url_is_projected_but_not_signed() {
        let base = challenge();
        let mut with_url = base.clone().with_local_ceremony_url();
        assert!(with_url.ceremony_url.is_some());
        assert_eq!(
            base.challenge_hash().unwrap(),
            with_url.challenge_hash().unwrap()
        );
        with_url.ceremony_url = Some("https://relay.example/ceremony/changed".into());
        assert_eq!(
            base.challenge_hash().unwrap(),
            with_url.challenge_hash().unwrap()
        );
    }

    #[test]
    fn local_ceremony_url_is_stable_for_nonce() {
        let first = challenge().with_local_ceremony_url();
        let second = challenge().with_local_ceremony_url();
        assert_eq!(first.ceremony_url, second.ceremony_url);
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
            ceremony_url: None,
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
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            intent: "evm.tx.sign".into(),
            facts: BTreeMap::new(),
        };
        att.validate().unwrap();
        att.schema = " ".into();
        assert!(att.validate().is_err());
        att.schema = SIGNING_ATTESTATION_SCHEMA_V1.into();
        att.intent = String::new();
        assert!(att.validate().is_err());
        att.intent = "evm.tx.sign".into();
        att.petal_digest = String::new();
        assert!(att.validate().is_err());
    }

    fn evm_signing_attestation() -> SigningAttestation {
        let mut facts = BTreeMap::new();
        facts.insert("action_id".into(), serde_json::json!("31337:0001-send"));
        facts.insert("wallet".into(), serde_json::json!("my-wallet"));
        facts.insert("chain_id".into(), serde_json::json!(31337));
        facts.insert(
            "account".into(),
            serde_json::json!("0x0000000000000000000000000000000000000001"),
        );
        facts.insert(
            "to".into(),
            serde_json::json!("0x0000000000000000000000000000000000000002"),
        );
        facts.insert("value_wei".into(), serde_json::json!("0"));
        facts.insert(
            "token".into(),
            serde_json::json!({
                "address": "0x0000000000000000000000000000000000000003",
                "symbol": "USDC",
                "amount": "1000000",
                "decimals": 6,
            }),
        );
        facts.insert("method".into(), serde_json::json!("erc20.transfer"));
        facts.insert("action_kind".into(), serde_json::json!("evm_confirm"));
        facts.insert("calldata_hash".into(), serde_json::json!("a".repeat(64)));
        facts.insert("signing_hash".into(), serde_json::json!("b".repeat(64)));
        facts.insert(
            "fee_facts".into(),
            serde_json::json!({
                "gas_limit": 21000,
                "max_fee_per_gas": "100",
                "max_priority_fee_per_gas": "10",
            }),
        );
        facts.insert(
            "policy_snapshot_digest".into(),
            serde_json::json!("c".repeat(64)),
        );
        SigningAttestation {
            schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
            petal_id: PETAL_ID_EVM_WALLET.into(),
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            intent: "evm.tx.sign".into(),
            facts,
        }
    }

    #[test]
    fn evm_signing_attestation_serializes_deterministically() {
        let att = evm_signing_attestation();
        att.validate().unwrap();
        let first = serde_json::to_vec(&att).unwrap();

        let mut facts_reinserted = BTreeMap::new();
        for key in att.facts.keys().rev() {
            facts_reinserted.insert(key.clone(), att.facts[key].clone());
        }
        let reordered = SigningAttestation {
            facts: facts_reinserted,
            ..att.clone()
        };
        let second = serde_json::to_vec(&reordered).unwrap();
        assert_eq!(first, second);

        let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(value["petal_id"], PETAL_ID_EVM_WALLET);
        assert_eq!(value["petal_digest"], PLACEHOLDER_DIGEST_EVM_WALLET);
        assert_eq!(value["intent"], "evm.tx.sign");
        assert_eq!(value["facts"]["action_id"], "31337:0001-send");
        assert_eq!(value["facts"]["chain_id"], 31337);
        assert_eq!(value["facts"]["method"], "erc20.transfer");
        assert_eq!(value["facts"]["policy_snapshot_digest"], "c".repeat(64));
    }

    #[test]
    fn evm_signing_attestation_binds_ws4_critical_facts() {
        let base = serde_json::to_vec(&evm_signing_attestation()).unwrap();
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("action_id", serde_json::json!("31337:0002-replace")),
            ("wallet", serde_json::json!("other-wallet")),
            ("chain_id", serde_json::json!(8453)),
            (
                "account",
                serde_json::json!("0x0000000000000000000000000000000000000004"),
            ),
            (
                "to",
                serde_json::json!("0x0000000000000000000000000000000000000005"),
            ),
            ("value_wei", serde_json::json!("1")),
            (
                "token",
                serde_json::json!({
                    "address": "0x0000000000000000000000000000000000000006",
                    "symbol": "USDC",
                    "amount": "1000000",
                    "decimals": 6,
                }),
            ),
            ("method", serde_json::json!("native.transfer")),
            ("action_kind", serde_json::json!("evm_cancel")),
            ("calldata_hash", serde_json::json!("d".repeat(64))),
            ("signing_hash", serde_json::json!("e".repeat(64))),
            (
                "fee_facts",
                serde_json::json!({
                    "gas_limit": 21000,
                    "max_fee_per_gas": "200",
                    "max_priority_fee_per_gas": "20",
                }),
            ),
            ("policy_snapshot_digest", serde_json::json!("f".repeat(64))),
        ];

        for (field, replacement) in cases {
            let mut changed = evm_signing_attestation();
            changed.facts.insert(field.into(), replacement);
            assert_ne!(
                serde_json::to_vec(&changed).unwrap(),
                base,
                "mutating EVM attestation fact {field} must change serialized preimage"
            );
        }
    }

    #[test]
    fn evm_owner_session_record_is_metadata_only_and_exact_scope() {
        let scope = serde_json::json!({
            "wallet": "my-wallet",
            "chain_id": 31337,
            "token_contract": "0x0000000000000000000000000000000000000003",
            "recipient": "0x0000000000000000000000000000000000000002",
            "method": "erc20.transfer",
            "daily_cap_micro_usd": 100_000_000,
            "ttl_ms": 3_600_000,
            "fee_policy": {"max_fee_per_gas": "200", "max_priority_fee_per_gas": "20"},
            "max_signature_count": 10,
            "autonomy_classification": "bounded_owner_signing"
        });
        let counters = serde_json::json!({
            "spent_micro_usd": 0,
            "signature_count": 0,
            "window_started_ms": 1_000
        });
        let record = StandingSessionRecord {
            session_id: "evm-session-1".into(),
            wallet: "my-wallet".into(),
            petal_id: PETAL_ID_EVM_WALLET.into(),
            session_kind: "evm_owner_signing".into(),
            scope: scope.clone(),
            counters,
            frozen_policy_version: 7,
            frozen_petal_policy_digest: "c".repeat(64),
            issued_ms: 1_000,
            expires_ms: 3_601_000,
            revoked_ms: None,
            orphan: false,
            created_ms: 1_000,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"session_kind\":\"evm_owner_signing\""));
        assert!(json.contains("\"method\":\"erc20.transfer\""));
        assert!(json.contains("\"daily_cap_micro_usd\":100000000"));
        assert!(!json.contains("private_key"));
        assert!(!json.contains("passphrase"));
        assert!(!json.contains("mnemonic"));
        assert!(!json.contains("recovery_phrase"));

        let roundtrip: StandingSessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.scope, scope);
        assert_eq!(roundtrip.petal_id, PETAL_ID_EVM_WALLET);
        assert_eq!(roundtrip.frozen_policy_version, 7);
        assert!(!roundtrip.orphan);
    }

    fn evm_typed_subject() -> EvmSealedIntentSubject {
        let wallet = "my-wallet".to_string();
        let petal_id = PETAL_ID_EVM_WALLET.to_string();
        let petal_digest = PLACEHOLDER_DIGEST_EVM_WALLET.to_string();
        let policy_snapshot = PetalPolicySnapshot {
            policy_version: 7,
            wallet: wallet.clone(),
            petal_id: petal_id.clone(),
            petal_digest: petal_digest.clone(),
            caps: BTreeMap::from([(
                "daily_usdc_cap_base_units".into(),
                serde_json::json!("100000000"),
            )]),
            hard_rules: Vec::new(),
            step_up_rules: Vec::new(),
            config: BTreeMap::from([("chain_id".into(), serde_json::json!(8453_u64))]),
            budget_state: BTreeMap::from([(
                "spent_today_base_units".into(),
                serde_json::json!("0"),
            )]),
            session_scope: None,
        };
        let daemon_terms = DaemonGrantTerms {
            max_ttl_secs: 120,
            max_signatures: 1,
            allowed_sign_intents: vec![EVM_TX_SIGN_INTENT.into()],
            assurance: AssuranceLevel::Hardened,
            extra: BTreeMap::from([(
                "required.intent".into(),
                serde_json::json!(EVM_TX_SIGN_INTENT),
            )]),
        };
        EvmSealedIntentSubject {
            schema: EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1.into(),
            action_id: "act_evm_1".into(),
            wallet,
            surface: "outbox".into(),
            petal_id,
            petal_digest,
            petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
            action_kind: EvmSealedActionKind::Confirm,
            chain_id: 8453,
            account: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            call: EvmCallFact {
                to: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                recipient: Some("0xcccccccccccccccccccccccccccccccccccccccc".into()),
                calldata_hex: "0xa9059cbb".into(),
                calldata_hash: format!("0x{}", "1".repeat(64)),
                method: "erc20.transfer".into(),
            },
            value: EvmValueFact {
                native_value_wei: "0".into(),
                token_amount_base_units: Some("1000000".into()),
                valuation_usd_micro: Some(1_000_000),
                valuation: None,
            },
            token: Some(EvmTokenFact {
                chain_id: 8453,
                token_address: "0xdddddddddddddddddddddddddddddddddddddddd".into(),
                symbol: "USDC".into(),
                decimals: 6,
            }),
            nonce_intent: EvmNonceIntent {
                mode: "exact".into(),
                nonce: Some(12),
                original_action_id: None,
            },
            fee_facts: EvmFeeFacts {
                tx_type: "eip1559".into(),
                gas_limit: "21000".into(),
                max_fee_per_gas_wei: Some("1000000000".into()),
                max_priority_fee_per_gas_wei: Some("1000000".into()),
                gas_price_wei: None,
                max_total_fee_wei: Some("21000000000000".into()),
            },
            replacement_fee_facts: None,
            unsigned_envelope: EvmUnsignedEnvelopeFacts {
                envelope_kind: "eip1559_rlp".into(),
                unsigned_tx_bytes_hash: format!("0x{}", "2".repeat(64)),
                signing_hash: format!("0x{}", "3".repeat(64)),
            },
            original_tx: None,
            owner_session_use: None,
            policy_snapshot_digest: policy_snapshot.petal_policy_digest().unwrap(),
            policy_snapshot,
            daemon_terms_digest: daemon_terms.daemon_terms_digest().unwrap(),
            daemon_terms,
            authority_change: false,
        }
    }

    fn assert_evm_typed_subject_hash_changes<F: FnOnce(&mut EvmSealedIntentSubject)>(mutate: F) {
        let original = evm_typed_subject()
            .canonical_envelope(20_000)
            .unwrap()
            .intent_hash()
            .unwrap();
        let mut modified = evm_typed_subject();
        mutate(&mut modified);
        let modified_hash = modified
            .canonical_envelope(20_000)
            .unwrap()
            .intent_hash()
            .unwrap();
        assert_ne!(original, modified_hash);
    }

    #[test]
    fn evm_typed_subject_serialization_is_deterministic() {
        let subject = evm_typed_subject();
        let first = subject.canonical_subject_bytes().unwrap();
        let second = subject.canonical_subject_bytes().unwrap();
        assert_eq!(first, second);

        let envelope = subject.canonical_envelope(20_000).unwrap();
        assert_eq!(envelope.subject_kind, EVM_SEALED_INTENT_SUBJECT_KIND);
        assert_eq!(envelope.subject_schema, EVM_SEALED_INTENT_SUBJECT_SCHEMA_V1);
        assert_eq!(envelope.header.petal_id, PETAL_ID_EVM_WALLET);
        assert_eq!(envelope.header.action_kind, "confirm");
        assert_eq!(envelope.header.network, "eip155:8453");
    }

    #[test]
    fn evm_typed_subject_hash_binds_critical_fields() {
        assert_evm_typed_subject_hash_changes(|s| s.action_id = "act_evm_2".into());
        assert_evm_typed_subject_hash_changes(|s| {
            s.wallet = "other-wallet".into();
            s.policy_snapshot.wallet = s.wallet.clone();
            s.policy_snapshot_digest = s.policy_snapshot.petal_policy_digest().unwrap();
        });
        assert_evm_typed_subject_hash_changes(|s| s.surface = "wallets".into());
        assert_evm_typed_subject_hash_changes(|s| {
            s.petal_digest = "first-party-placeholder:evm-wallet:v1".into();
            s.policy_snapshot.petal_digest = s.petal_digest.clone();
            s.policy_snapshot_digest = s.policy_snapshot.petal_policy_digest().unwrap();
        });
        assert_evm_typed_subject_hash_changes(|s| s.action_kind = EvmSealedActionKind::Cancel);
        assert_evm_typed_subject_hash_changes(|s| {
            s.chain_id = 1;
            s.token.as_mut().unwrap().chain_id = 1;
        });
        assert_evm_typed_subject_hash_changes(|s| {
            s.account = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into()
        });
        assert_evm_typed_subject_hash_changes(|s| {
            s.call.to = "0xffffffffffffffffffffffffffffffffffffffff".into()
        });
        assert_evm_typed_subject_hash_changes(|s| s.call.recipient = None);
        assert_evm_typed_subject_hash_changes(|s| {
            s.value.token_amount_base_units = Some("2000000".into())
        });
        assert_evm_typed_subject_hash_changes(|s| {
            s.token.as_mut().unwrap().token_address =
                "0x1111111111111111111111111111111111111111".into()
        });
        assert_evm_typed_subject_hash_changes(|s| {
            s.call.calldata_hash = format!("0x{}", "4".repeat(64))
        });
        assert_evm_typed_subject_hash_changes(|s| s.nonce_intent.nonce = Some(13));
        assert_evm_typed_subject_hash_changes(|s| {
            s.fee_facts.max_fee_per_gas_wei = Some("2000000000".into())
        });
        assert_evm_typed_subject_hash_changes(|s| {
            s.unsigned_envelope.signing_hash = format!("0x{}", "5".repeat(64))
        });
        assert_evm_typed_subject_hash_changes(|s| {
            s.policy_snapshot
                .budget_state
                .insert("spent_today_base_units".into(), serde_json::json!("1"));
            s.policy_snapshot_digest = s.policy_snapshot.petal_policy_digest().unwrap();
        });
        assert_evm_typed_subject_hash_changes(|s| {
            s.daemon_terms.max_ttl_secs = 60;
            s.daemon_terms_digest = s.daemon_terms.daemon_terms_digest().unwrap();
        });
    }

    #[test]
    fn evm_typed_subject_validation_requires_terms_and_policy_binding() {
        evm_typed_subject().validate_evm().unwrap();

        let mut subject = evm_typed_subject();
        subject.daemon_terms.allowed_sign_intents.clear();
        let err = subject.validate_evm().unwrap_err();
        assert!(err.to_string().contains("evm.tx.sign"), "{err}");

        let mut subject = evm_typed_subject();
        subject.policy_snapshot_digest = "0".repeat(64);
        let err = subject.validate_evm().unwrap_err();
        assert!(err.to_string().contains("policy_snapshot_digest"), "{err}");

        let mut subject = evm_typed_subject();
        subject.daemon_terms.max_signatures = 2;
        subject.daemon_terms_digest = subject.daemon_terms.daemon_terms_digest().unwrap();
        let err = subject.validate_evm().unwrap_err();
        assert!(err.to_string().contains("one-shot"), "{err}");
    }

    #[test]
    fn evm_typed_subject_and_attestation_allow_petal_provenance() {
        let mut subject = evm_typed_subject();
        subject.petal_id = "petal:polymarket".into();
        subject.petal_digest = "a".repeat(64);
        subject.petal_version = "v1-package".into();
        subject.policy_snapshot.petal_id = subject.petal_id.clone();
        subject.policy_snapshot.petal_digest = subject.petal_digest.clone();
        subject.policy_snapshot_digest = subject.policy_snapshot.petal_policy_digest().unwrap();

        subject.validate_evm().unwrap();
        let attestation = subject
            .signing_attestation_facts()
            .signing_attestation()
            .unwrap();
        EvmSigningAttestationFacts::from_attestation(&attestation).unwrap();
        DefaultAttestationRegistry::new()
            .validate_attestation(&attestation)
            .unwrap();
    }

    #[test]
    fn evm_typed_attestation_round_trips_and_registry_accepts() {
        let subject = evm_typed_subject();
        let facts = subject.signing_attestation_facts();
        let attestation = facts.signing_attestation().unwrap();
        let parsed = EvmSigningAttestationFacts::from_attestation(&attestation).unwrap();
        assert_eq!(parsed, facts);
        parsed.validate_against_subject(&subject).unwrap();

        DefaultAttestationRegistry::new()
            .validate_attestation(&attestation)
            .unwrap();
    }

    #[test]
    fn petal_attestation_is_bound_to_package_and_route_provenance() {
        let facts = PetalSigningAttestationFacts {
            facts_schema: PETAL_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
            action_id: "appsign-test".into(),
            wallet: "alice".into(),
            surface: "petals".into(),
            petal_id: "petal:portfolio".into(),
            petal_digest: "a".repeat(64),
            petal_version: "v1-package".into(),
            petal_root: "portfolio".into(),
            package_hash: "a".repeat(64),
            route_id: "r000001".into(),
            op: "read".into(),
            path: "/positions".into(),
            params: BTreeMap::from([("account".into(), "main".into())]),
            actor: Some("agent-1".into()),
            intent: "portfolio.position.sign".into(),
            signing_hash: format!("0x{}", "b".repeat(64)),
            policy_snapshot_digest: "c".repeat(64),
        };
        let attestation = facts.signing_attestation().unwrap();
        DefaultAttestationRegistry::new()
            .validate_attestation(&attestation)
            .unwrap();

        let mut mismatched = facts;
        mismatched.package_hash = "e".repeat(64);
        let err = mismatched.validate().unwrap_err();
        assert!(err.to_string().contains("package provenance"), "{err}");
    }

    #[test]
    fn evm_typed_attestation_rejects_missing_or_mismatched_facts() {
        let subject = evm_typed_subject();
        let valid = subject
            .signing_attestation_facts()
            .signing_attestation()
            .unwrap();

        let mut missing = valid.clone();
        missing.facts.remove("signing_hash");
        let err = DefaultAttestationRegistry::new()
            .validate_attestation(&missing)
            .unwrap_err();
        assert!(
            err.to_string().contains("missing field") || err.to_string().contains("signing_hash"),
            "{err}"
        );

        let mut digest_mismatch = valid.clone();
        digest_mismatch.petal_digest = "first-party-placeholder:evm-wallet:other".into();
        let err = DefaultAttestationRegistry::new()
            .validate_attestation(&digest_mismatch)
            .unwrap_err();
        assert!(err.to_string().contains("petal_digest mismatch"), "{err}");

        let mut signing_hash_mismatch = subject.signing_attestation_facts();
        signing_hash_mismatch.signing_hash = format!("0x{}", "6".repeat(64));
        let err = signing_hash_mismatch.validate().unwrap_err();
        assert!(err.to_string().contains("signing_hash mismatch"), "{err}");

        let mut field_mismatch = subject.signing_attestation_facts();
        field_mismatch.wallet = "other-wallet".into();
        let err = field_mismatch
            .validate_against_subject(&subject)
            .unwrap_err();
        assert!(err.to_string().contains("sealed intent"), "{err}");
    }

    #[test]
    fn evm_owner_session_subject_carries_exact_scope_without_secret_material() {
        let mut subject = evm_typed_subject();
        subject.action_kind = EvmSealedActionKind::OwnerSessionUse;
        subject.owner_session_use = Some(EvmOwnerSessionUseFact {
            session_id: "evm-session-1".into(),
            reservation_id: "evm-reservation-1".into(),
            token_address: "0xdddddddddddddddddddddddddddddddddddddddd".into(),
            recipient: "0xcccccccccccccccccccccccccccccccccccccccc".into(),
            daily_cap_base_units: "100000000".into(),
            expires_ms: 3_601_000,
            max_signature_count: 10,
        });
        subject.daemon_terms.max_signatures = 10;
        subject.daemon_terms_digest = subject.daemon_terms.daemon_terms_digest().unwrap();

        let json = String::from_utf8(subject.canonical_subject_bytes().unwrap()).unwrap();
        assert!(json.contains("\"action_kind\":\"owner_session_use\""));
        assert!(json.contains("\"daily_cap_base_units\":\"100000000\""));
        assert!(!json.contains("private_key"));
        assert!(!json.contains("passphrase"));
        assert!(!json.contains("mnemonic"));
        assert!(!json.contains("recovery_phrase"));
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
    fn valuation_validation_checks_market_observation_age_and_future_skew() {
        let policy = ValuationPolicy::default();
        let now = 1_000_000;

        let mut old = valuation_quote();
        old.fetched_at_ms = now;
        old.quote_timestamp_ms = now - policy.observation_max_age_ms - 1;
        let err = old.validate_for_authorization(&policy, now).unwrap_err();
        assert!(err.to_string().contains("market observation is stale"));

        let mut future = valuation_quote();
        future.fetched_at_ms = now;
        future.quote_timestamp_ms = now + policy.future_tolerance_ms + 1;
        let err = future.validate_for_authorization(&policy, now).unwrap_err();
        assert!(err.to_string().contains("in the future"));

        let mut normal_provider_lag = valuation_quote();
        normal_provider_lag.fetched_at_ms = now;
        normal_provider_lag.quote_timestamp_ms = now - 45_000;
        assert!(
            normal_provider_lag
                .validate_for_authorization(&policy, now)
                .is_ok()
        );
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

    // ------------------------------------------------------------------
    // DefaultAttestationRegistry + SealedPetalContext / SignHashRequest /
    // SealedSignature / AuditEvent / PetalHost (WS-1 host signing API)
    // ------------------------------------------------------------------

    fn typed_evm_attestation_for_registry() -> SigningAttestation {
        EvmSigningAttestationFacts {
            facts_schema: EVM_SIGNING_ATTESTATION_FACTS_SCHEMA_V1.into(),
            action_id: "31337:0001-send".into(),
            wallet: "my-wallet".into(),
            surface: "outbox".into(),
            petal_id: PETAL_ID_EVM_WALLET.into(),
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
            action_kind: EvmSealedActionKind::Confirm,
            chain_id: 31337,
            account: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            recipient: Some("0x0000000000000000000000000000000000000002".into()),
            value: EvmValueFact {
                native_value_wei: "0".into(),
                token_amount_base_units: Some("1000000".into()),
                valuation_usd_micro: Some(1_000_000),
                valuation: None,
            },
            token: Some(EvmTokenFact {
                chain_id: 31337,
                token_address: "0x0000000000000000000000000000000000000003".into(),
                symbol: "USDC".into(),
                decimals: 6,
            }),
            method: EVM_ERC20_TRANSFER_METHOD.into(),
            calldata_hash: format!("0x{}", "a".repeat(64)),
            nonce_intent: EvmNonceIntent {
                mode: "exact".into(),
                nonce: Some(7),
                original_action_id: None,
            },
            fee_facts: EvmFeeFacts {
                tx_type: "eip1559".into(),
                gas_limit: "21000".into(),
                max_fee_per_gas_wei: Some("100".into()),
                max_priority_fee_per_gas_wei: Some("10".into()),
                gas_price_wei: None,
                max_total_fee_wei: Some("2100000".into()),
            },
            replacement_fee_facts: None,
            unsigned_envelope: EvmUnsignedEnvelopeFacts {
                envelope_kind: "eip1559_rlp".into(),
                unsigned_tx_bytes_hash: format!("0x{}", "b".repeat(64)),
                signing_hash: format!("0x{}", "c".repeat(64)),
            },
            signing_hash: format!("0x{}", "c".repeat(64)),
            policy_snapshot_digest: "d".repeat(64),
            daemon_terms_digest: "e".repeat(64),
        }
        .signing_attestation()
        .unwrap()
    }

    #[test]
    fn default_registry_accepts_first_party_pairs() {
        let r = DefaultAttestationRegistry::new();
        for (petal_id, intent) in [
            (PETAL_ID_EVM_WALLET, "evm.tx.sign"),
            (PETAL_ID_PAID_HTTP, "x402.sign"),
            (PETAL_ID_PAID_HTTP, "paid-http.mpp.sign"),
            (PETAL_ID_HYPERLIQUID, "hyperliquid.approve_agent"),
            (PETAL_ID_HYPERLIQUID, "hyperliquid.usd_send"),
            (PETAL_ID_HYPERLIQUID, "hyperliquid.order"),
            (PETAL_ID_HYPERLIQUID, "hyperliquid.cancel"),
            (PETAL_ID_WALLET_POLICY, "wallet_policy.sign"),
            (PETAL_ID_DEFI, "defi.route.sign"),
        ] {
            assert!(
                r.is_allowed(petal_id, intent, SIGNING_ATTESTATION_SCHEMA_V1),
                "({petal_id}, {intent}) must be allowed"
            );
            let att = if petal_id == PETAL_ID_EVM_WALLET && intent == EVM_TX_SIGN_INTENT {
                typed_evm_attestation_for_registry()
            } else if petal_id == PETAL_ID_PAID_HTTP {
                SigningAttestation {
                    schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
                    petal_id: petal_id.into(),
                    petal_digest: PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                    intent: intent.into(),
                    facts: paid_http_facts_for_intent(intent),
                }
            } else {
                SigningAttestation {
                    schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
                    petal_id: petal_id.into(),
                    petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
                    intent: intent.into(),
                    facts: BTreeMap::new(),
                }
            };
            r.validate_attestation(&att).unwrap();
        }
    }

    #[test]
    fn default_registry_denies_unknown_pair_or_unknown_schema() {
        let r = DefaultAttestationRegistry::new();
        // Unknown pair.
        assert!(!r.is_allowed(
            PETAL_ID_EVM_WALLET,
            "x402.sign",
            SIGNING_ATTESTATION_SCHEMA_V1
        ));
        // Known pair, unknown schema.
        assert!(!r.is_allowed(PETAL_ID_EVM_WALLET, "evm.tx.sign", "bloom.foo.bar"));
        // validate_attestation errors with a deterministic message.
        let att = SigningAttestation {
            schema: "bloom.foo.bar".into(),
            petal_id: PETAL_ID_EVM_WALLET.into(),
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            intent: "evm.tx.sign".into(),
            facts: BTreeMap::new(),
        };
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(
            err.to_string().contains("unsupported attestation schema"),
            "{err}"
        );
        let att = SigningAttestation {
            schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
            petal_id: PETAL_ID_EVM_WALLET.into(),
            petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET.into(),
            intent: "x402.sign".into(),
            facts: BTreeMap::new(),
        };
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported attestation schema for"),
            "{err}"
        );
    }

    /// A structurally valid paid-HTTP facts map for the given signing intent,
    /// mirroring what `RequestsHandler` projects.
    fn paid_http_facts_for_intent(intent: &str) -> BTreeMap<String, serde_json::Value> {
        let protocol = if intent == PAID_HTTP_MPP_SIGN_INTENT {
            "mpp"
        } else {
            "x402"
        };
        let mut facts = BTreeMap::new();
        facts.insert(
            "facts_schema".into(),
            serde_json::json!(PAID_HTTP_SIGNING_ATTESTATION_FACTS_SCHEMA_V1),
        );
        facts.insert("action_id".into(), serde_json::json!("req_1"));
        facts.insert("wallet".into(), serde_json::json!("my-wallet"));
        facts.insert("request_id".into(), serde_json::json!("req_1"));
        facts.insert("method".into(), serde_json::json!("GET"));
        facts.insert(
            "url".into(),
            serde_json::json!("https://api.example.com/paid"),
        );
        facts.insert("host".into(), serde_json::json!("api.example.com"));
        facts.insert("protocol".into(), serde_json::json!(protocol));
        facts.insert("network".into(), serde_json::json!("base"));
        facts.insert("chain_id".into(), serde_json::json!(8453));
        facts.insert("asset".into(), serde_json::json!("USDC"));
        facts.insert("amount".into(), serde_json::json!("1000000"));
        facts.insert(
            "pay_to".into(),
            serde_json::json!("0x0000000000000000000000000000000000000009"),
        );
        facts.insert(
            "resource".into(),
            serde_json::json!("https://api.example.com/paid"),
        );
        facts.insert("scheme".into(), serde_json::json!("exact"));
        facts.insert("charge_id".into(), serde_json::Value::Null);
        facts.insert("session_id".into(), serde_json::Value::Null);
        facts.insert("channel_id".into(), serde_json::Value::Null);
        facts.insert(
            "signing_hash".into(),
            serde_json::json!(format!("0x{}", "a".repeat(64))),
        );
        facts.insert(
            "policy_snapshot_digest".into(),
            serde_json::json!("d".repeat(64)),
        );
        facts.insert(
            "selected_requirement".into(),
            serde_json::json!({"scheme": "exact", "network": protocol}),
        );
        facts
    }

    fn paid_http_attestation_for_intent(intent: &str) -> SigningAttestation {
        SigningAttestation {
            schema: SIGNING_ATTESTATION_SCHEMA_V1.into(),
            petal_id: PETAL_ID_PAID_HTTP.into(),
            petal_digest: PLACEHOLDER_DIGEST_PAID_HTTP.into(),
            intent: intent.into(),
            facts: paid_http_facts_for_intent(intent),
        }
    }

    #[test]
    fn paid_http_registry_accepts_valid_x402_and_mpp_facts() {
        let r = DefaultAttestationRegistry::new();
        r.validate_attestation(&paid_http_attestation_for_intent(
            PAID_HTTP_X402_SIGN_INTENT,
        ))
        .unwrap();
        r.validate_attestation(&paid_http_attestation_for_intent(PAID_HTTP_MPP_SIGN_INTENT))
            .unwrap();
    }

    #[test]
    fn paid_http_registry_rejects_malformed_facts() {
        let r = DefaultAttestationRegistry::new();

        // Missing required string.
        let mut att = paid_http_attestation_for_intent(PAID_HTTP_X402_SIGN_INTENT);
        att.facts.remove("url");
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(err.to_string().contains("url"), "{err}");

        // Wrong facts schema.
        let mut att = paid_http_attestation_for_intent(PAID_HTTP_X402_SIGN_INTENT);
        att.facts
            .insert("facts_schema".into(), serde_json::json!("bloom.wrong.v1"));
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(err.to_string().contains("facts schema"), "{err}");

        // Protocol does not match the signing intent (x402 facts under the MPP
        // intent).
        let mut att = paid_http_attestation_for_intent(PAID_HTTP_MPP_SIGN_INTENT);
        att.facts
            .insert("protocol".into(), serde_json::json!("x402"));
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(err.to_string().contains("does not match intent"), "{err}");

        // signing_hash is not a 32-byte hex hash.
        let mut att = paid_http_attestation_for_intent(PAID_HTTP_X402_SIGN_INTENT);
        att.facts
            .insert("signing_hash".into(), serde_json::json!("0xdeadbeef"));
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(err.to_string().contains("signing_hash"), "{err}");

        // Optional string field present as a non-string.
        let mut att = paid_http_attestation_for_intent(PAID_HTTP_X402_SIGN_INTENT);
        att.facts.insert("asset".into(), serde_json::json!(42));
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(err.to_string().contains("asset"), "{err}");

        // chain_id present but not a positive integer.
        let mut att = paid_http_attestation_for_intent(PAID_HTTP_X402_SIGN_INTENT);
        att.facts.insert("chain_id".into(), serde_json::json!(0));
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(err.to_string().contains("chain_id"), "{err}");

        // selected_requirement echoed as a scalar.
        let mut att = paid_http_attestation_for_intent(PAID_HTTP_X402_SIGN_INTENT);
        att.facts
            .insert("selected_requirement".into(), serde_json::json!("nope"));
        let err = r.validate_attestation(&att).unwrap_err();
        assert!(err.to_string().contains("selected_requirement"), "{err}");
    }

    #[test]
    fn host_signing_data_types_round_trip_through_serde() {
        let ctx = SealedPetalContext {
            canonical_intent_bytes_hash: "a".repeat(64),
            intent_hash: "b".repeat(64),
            daemon_terms_digest: "c".repeat(64),
            petal_policy_digest: "d".repeat(64),
            policy_version: 3,
            petal_id: PETAL_ID_EVM_WALLET.into(),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: SealedPetalContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, back);

        let req = SignHashRequest {
            wallet: "my-wallet".into(),
            action_id: "req_1".into(),
            intent: "evm.tx.sign".into(),
            hash_hex: format!("0x{}", "0".repeat(64)),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SignHashRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let sig = SealedSignature {
            intent_hash: "1".repeat(64),
            signature_b64: "AAAA".into(),
            signed_at_ms: 100,
        };
        let json = serde_json::to_string(&sig).unwrap();
        let back: SealedSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);

        let ev = AuditEvent {
            kind: "petal.sign.ok".into(),
            wallet: Some("my-wallet".into()),
            action_id: Some("req_1".into()),
            message: "signed".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
        // The default-less fields are skipped in serialization (spec §4.1).
        let ev_bare = AuditEvent {
            kind: "host.note".into(),
            wallet: None,
            action_id: None,
            message: "msg".into(),
        };
        let json = serde_json::to_string(&ev_bare).unwrap();
        assert!(!json.contains("wallet"));
        assert!(!json.contains("action_id"));
    }

    #[test]
    fn session_denial_reason_strings_are_stable() {
        assert_eq!(
            SessionDenialReason::Orphan.as_deterministic_str(),
            "session_orphaned_requires_reapproval"
        );
        assert_eq!(
            SessionDenialReason::BudgetExhausted.as_deterministic_str(),
            "session_budget_exhausted"
        );
        assert_eq!(
            SessionDenialReason::ScopeMismatch.as_deterministic_str(),
            "session_scope_mismatch"
        );
        assert_eq!(
            SessionDenialReason::Expired.as_deterministic_str(),
            "session_expired"
        );
        assert_eq!(
            SessionDenialReason::Revoked.as_deterministic_str(),
            "session_revoked"
        );
        assert_eq!(
            SessionDenialReason::WrongToken.as_deterministic_str(),
            "session_wrong_token"
        );
        assert_eq!(
            SessionDenialReason::WrongRecipient.as_deterministic_str(),
            "session_wrong_recipient"
        );
        assert_eq!(
            SessionDenialReason::WrongChain.as_deterministic_str(),
            "session_wrong_chain"
        );
        assert_eq!(
            SessionDenialReason::WrongMethod.as_deterministic_str(),
            "session_wrong_method"
        );
        assert_eq!(
            SessionDenialReason::Halted.as_deterministic_str(),
            "session_halted"
        );
    }
}
