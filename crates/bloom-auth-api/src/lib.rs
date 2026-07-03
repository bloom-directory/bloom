//! Shared authorization API for Bloom Sealed Approval.
//!
//! This crate intentionally contains only stable data types and traits. The
//! concrete store, verifier, and signer integrations live outside the VFS-facing
//! crates so NFS/petal surfaces do not pull in the whole authorization TCB.

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const APPROVAL_SCHEMA_V1: &str = "bloom.approval.v1";
pub const CANONICAL_ENVELOPE_SCHEMA_V1: &str = "bloom.canonical_envelope.v1";
pub const INTENT_HASH_DOMAIN: &[u8] = b"bloom.intent.v1";
pub const APPROVAL_CHALLENGE_DOMAIN: &[u8] = b"bloom.approval.v1";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    Password,
    PasskeyBrowser,
    PasskeyCtap,
    Test,
}

impl SignerKind {
    pub fn satisfies(self, assurance: AssuranceLevel) -> bool {
        match assurance {
            AssuranceLevel::Standard => {
                matches!(
                    self,
                    SignerKind::Password | SignerKind::PasskeyBrowser | SignerKind::PasskeyCtap
                )
            }
            AssuranceLevel::Hardened => {
                matches!(self, SignerKind::PasskeyBrowser | SignerKind::PasskeyCtap)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalIntentHeader {
    pub schema: String,
    pub wallet: String,
    pub surface: String,
    pub action_id: String,
    pub executor_id: String,
    pub network: String,
    pub account: String,
    pub action_kind: String,
    pub value_movement: bool,
    pub authority_change: bool,
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
/// Uses BLAKE3 with the `bloom.intent.v1` domain tag.  This is the single
/// hash function that must be used anywhere an `intent_hash` is produced —
/// in [`CanonicalEnvelope::intent_hash`], in central outbox projections, and
/// in future sealed-action challenge preimages.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub schema: String,
    pub wallet: String,
    pub surface: String,
    pub action_id: String,
    pub intent_hash: String,
    pub executor_id: String,
    pub network: String,
    pub assurance: AssuranceLevel,
    pub server_nonce: String,
    pub caps: ApprovalCaps,
    pub expiry_ms: u64,
    pub signer_kind: SignerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_session_id: Option<String>,
    pub signature: ApprovalSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedApproval {
    pub schema: String,
    pub wallet: String,
    pub surface: String,
    pub action_id: String,
    pub intent_hash: String,
    pub executor_id: String,
    pub network: String,
    pub assurance: AssuranceLevel,
    pub server_nonce: String,
    pub caps: ApprovalCaps,
    pub expiry_ms: u64,
    pub signer_kind: SignerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_session_id: Option<String>,
}

impl Approval {
    pub fn unsigned_payload(&self) -> UnsignedApproval {
        UnsignedApproval {
            schema: self.schema.clone(),
            wallet: self.wallet.clone(),
            surface: self.surface.clone(),
            action_id: self.action_id.clone(),
            intent_hash: self.intent_hash.clone(),
            executor_id: self.executor_id.clone(),
            network: self.network.clone(),
            assurance: self.assurance,
            server_nonce: self.server_nonce.clone(),
            caps: self.caps.clone(),
            expiry_ms: self.expiry_ms,
            signer_kind: self.signer_kind,
            credential_id: self.credential_id.clone(),
            review_session_id: self.review_session_id.clone(),
        }
    }

    pub fn validate_against_sealed(
        &self,
        sealed: &SealedIntentRecord,
        now_ms: u64,
    ) -> Result<(), AuthApiError> {
        if self.schema != APPROVAL_SCHEMA_V1 {
            return Err(AuthApiError::Denied(format!(
                "unsupported approval schema {}",
                self.schema
            )));
        }
        if now_ms >= self.expiry_ms {
            return Err(AuthApiError::Denied("approval expired".into()));
        }
        if !self.signer_kind.satisfies(self.assurance) {
            return Err(AuthApiError::Denied(format!(
                "signer {:?} does not satisfy {:?} assurance",
                self.signer_kind, self.assurance
            )));
        }
        self.signature
            .validate_for_unsigned(&self.unsigned_payload())?;
        if self.intent_hash != sealed.intent_hash {
            return Err(AuthApiError::Denied("intent_hash mismatch".into()));
        }
        let header = &sealed.envelope.header;
        let checks = [
            ("wallet", self.wallet.as_str(), header.wallet.as_str()),
            ("surface", self.surface.as_str(), header.surface.as_str()),
            (
                "action_id",
                self.action_id.as_str(),
                header.action_id.as_str(),
            ),
            (
                "executor_id",
                self.executor_id.as_str(),
                header.executor_id.as_str(),
            ),
            ("network", self.network.as_str(), header.network.as_str()),
        ];
        for (field, approval, sealed) in checks {
            if approval != sealed {
                return Err(AuthApiError::Denied(format!("{field} mismatch")));
            }
        }
        Ok(())
    }
}

impl UnsignedApproval {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthApiError> {
        serde_json::to_vec(self).map_err(AuthApiError::Json)
    }

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ApprovalCaps {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_usd_micro: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_secs: Option<u64>,
    #[serde(default)]
    pub destinations: Vec<String>,
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalSignature {
    PasswordMac { mac_hex: String },
    WebAuthnAssertion(WebAuthnAssertionRecord),
    Test { sig_hex: String },
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

impl ApprovalSignature {
    pub fn validate_for_unsigned(&self, unsigned: &UnsignedApproval) -> Result<(), AuthApiError> {
        match self {
            ApprovalSignature::WebAuthnAssertion(assertion) => {
                assertion.validate_challenge(unsigned)
            }
            ApprovalSignature::PasswordMac { .. } | ApprovalSignature::Test { .. } => Ok(()),
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingAuthorityGrant {
    pub grant_id: String,
    pub wallet: String,
    pub assurance: AssuranceLevel,
    pub signer_kind: SignerKind,
    pub policy_digest: String,
    pub caps: ApprovalCaps,
    pub issued_ms: u64,
    pub expiry_ms: u64,
    pub revoked_ms: Option<u64>,
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
        if matches!(self.assurance, AssuranceLevel::Hardened)
            && !matches!(
                self.signer_kind,
                SignerKind::PasskeyBrowser | SignerKind::PasskeyCtap
            )
        {
            return Err(AuthApiError::Denied(
                "hardened credentials require WebAuthn/FIDO2 signer kind".into(),
            ));
        }
        Ok(())
    }
}

impl StandingAuthorityGrant {
    pub fn is_active_at(&self, now_ms: u64) -> bool {
        self.revoked_ms.is_none() && now_ms < self.expiry_ms
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
pub struct ChallengeRecord {
    pub surface: String,
    pub action_id: String,
    pub intent_hash: String,
    pub server_nonce: String,
    pub assurance: AssuranceLevel,
    pub expiry_ms: u64,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedIntentRecord {
    pub intent_hash: String,
    pub envelope: CanonicalEnvelope,
    pub sealed_at_ms: u64,
}

#[async_trait]
pub trait AuthStoreView: Send + Sync {
    async fn sealed_intent(&self, intent_hash: &str) -> Result<SealedIntentRecord, AuthApiError>;
}

#[async_trait]
pub trait AuthStoreWriter: Send + Sync {
    async fn stage_entry(
        &self,
        envelope: CanonicalEnvelope,
        assurance: AssuranceLevel,
        now_ms: u64,
    ) -> Result<AuthEntryRecord, AuthApiError>;

    async fn issue_challenge(
        &self,
        surface: &str,
        action_id: &str,
        server_nonce: &str,
        expiry_ms: u64,
        now_ms: u64,
    ) -> Result<ChallengeRecord, AuthApiError>;

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
        signature: &ApprovalSignature,
        now_ms: u64,
    ) -> Result<(), AuthApiError>;
}

#[async_trait]
pub trait ApprovalVerifier: Send + Sync {
    async fn verify_and_consume(&self, approval: Approval, now_ms: u64)
    -> Result<(), AuthApiError>;
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
    use super::*;

    fn header() -> CanonicalIntentHeader {
        CanonicalIntentHeader {
            schema: "bloom.intent_header.v1".into(),
            wallet: "my-wallet".into(),
            surface: "requests".into(),
            action_id: "req_1".into(),
            executor_id: "paid-http".into(),
            network: "base".into(),
            account: "default".into(),
            action_kind: "x402_payment".into(),
            value_movement: true,
            authority_change: false,
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
    fn intent_hash_of_uses_domain_tag() {
        let bytes = br#"{"x":42}"#;
        let with_domain = intent_hash_of(bytes);

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"bloom.intent.v1");
        hasher.update(bytes);
        let manual = hasher.finalize().to_hex().to_string();

        assert_eq!(with_domain, manual);

        let mut no_domain = blake3::Hasher::new();
        no_domain.update(bytes);
        assert_ne!(with_domain, no_domain.finalize().to_hex().to_string());
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
    fn intent_hash_binds_executor_id() {
        assert_hash_changes(|h| h.executor_id = "evm".into());
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

    #[test]
    fn approval_challenge_commits_to_assurance() {
        let mut a = UnsignedApproval {
            schema: APPROVAL_SCHEMA_V1.into(),
            wallet: "my-wallet".into(),
            surface: "outbox".into(),
            action_id: "abc".into(),
            intent_hash: "0".repeat(64),
            executor_id: "evm".into(),
            network: "base".into(),
            assurance: AssuranceLevel::Standard,
            server_nonce: "nonce".into(),
            caps: ApprovalCaps::default(),
            expiry_ms: 42,
            signer_kind: SignerKind::Password,
            credential_id: None,
            review_session_id: None,
        };
        let c1 = a.challenge_hash_hex().unwrap();
        a.assurance = AssuranceLevel::Hardened;
        a.signer_kind = SignerKind::PasskeyCtap;
        let c2 = a.challenge_hash_hex().unwrap();
        assert_ne!(c1, c2);
    }

    fn unsigned_approval() -> UnsignedApproval {
        UnsignedApproval {
            schema: APPROVAL_SCHEMA_V1.into(),
            wallet: "my-wallet".into(),
            surface: "outbox".into(),
            action_id: "abc".into(),
            intent_hash: "0".repeat(64),
            executor_id: "evm".into(),
            network: "base".into(),
            assurance: AssuranceLevel::Hardened,
            server_nonce: "nonce".into(),
            caps: ApprovalCaps::default(),
            expiry_ms: 42,
            signer_kind: SignerKind::PasskeyBrowser,
            credential_id: Some("cred-1".into()),
            review_session_id: Some("review-1".into()),
        }
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
    fn webauthn_assertion_challenge_binds_to_unsigned_approval_payload() {
        let unsigned = unsigned_approval();
        ApprovalSignature::WebAuthnAssertion(webauthn_assertion_for(&unsigned))
            .validate_for_unsigned(&unsigned)
            .unwrap();

        let mut substituted = unsigned.clone();
        substituted.action_id = "other".into();
        let err = ApprovalSignature::WebAuthnAssertion(webauthn_assertion_for(&unsigned))
            .validate_for_unsigned(&substituted)
            .unwrap_err();
        assert!(
            err.to_string().contains("challenge does not match"),
            "{err}"
        );
    }

    fn approval_for(
        sealed: &SealedIntentRecord,
        assurance: AssuranceLevel,
        signer_kind: SignerKind,
    ) -> Approval {
        Approval {
            schema: APPROVAL_SCHEMA_V1.into(),
            wallet: sealed.envelope.header.wallet.clone(),
            surface: sealed.envelope.header.surface.clone(),
            action_id: sealed.envelope.header.action_id.clone(),
            intent_hash: sealed.intent_hash.clone(),
            executor_id: sealed.envelope.header.executor_id.clone(),
            network: sealed.envelope.header.network.clone(),
            assurance,
            server_nonce: "nonce".into(),
            caps: ApprovalCaps::default(),
            expiry_ms: 200,
            signer_kind,
            credential_id: None,
            review_session_id: None,
            signature: ApprovalSignature::Test {
                sig_hex: "00".into(),
            },
        }
    }

    #[test]
    fn approval_validation_binds_to_sealed_header_and_assurance() {
        let env = CanonicalEnvelope::new(header(), "paid_http", "paid_http.v1", b"{}".to_vec());
        let sealed = SealedIntentRecord {
            intent_hash: env.intent_hash().unwrap(),
            envelope: env,
            sealed_at_ms: 1,
        };
        approval_for(&sealed, AssuranceLevel::Standard, SignerKind::Password)
            .validate_against_sealed(&sealed, 100)
            .unwrap();

        let err = approval_for(&sealed, AssuranceLevel::Hardened, SignerKind::Password)
            .validate_against_sealed(&sealed, 100)
            .unwrap_err();
        assert!(err.to_string().contains("does not satisfy"), "{err}");

        let mut wrong = approval_for(&sealed, AssuranceLevel::Standard, SignerKind::Password);
        wrong.network = "wrong".into();
        let err = wrong.validate_against_sealed(&sealed, 100).unwrap_err();
        assert!(err.to_string().contains("network mismatch"), "{err}");
    }

    #[test]
    fn approval_validation_rejects_expired_approval() {
        let env = CanonicalEnvelope::new(header(), "paid_http", "paid_http.v1", b"{}".to_vec());
        let sealed = SealedIntentRecord {
            intent_hash: env.intent_hash().unwrap(),
            envelope: env,
            sealed_at_ms: 1,
        };
        let err = approval_for(&sealed, AssuranceLevel::Standard, SignerKind::Password)
            .validate_against_sealed(&sealed, 200)
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn signer_kind_enforces_assurance_levels() {
        assert!(SignerKind::Password.satisfies(AssuranceLevel::Standard));
        assert!(!SignerKind::Password.satisfies(AssuranceLevel::Hardened));
        assert!(SignerKind::PasskeyBrowser.satisfies(AssuranceLevel::Hardened));
        assert!(!SignerKind::Test.satisfies(AssuranceLevel::Standard));
    }

    #[test]
    fn approval_credential_record_rejects_hardened_software_signers() {
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

        record.signer_kind = SignerKind::Password;
        let err = record.validate().unwrap_err();
        assert!(err.to_string().contains("does not satisfy"), "{err}");

        record.signer_kind = SignerKind::Test;
        let err = record.validate().unwrap_err();
        assert!(err.to_string().contains("does not satisfy"), "{err}");
    }

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
