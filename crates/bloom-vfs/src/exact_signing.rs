//! Durable Machine orchestration for the existing exact Broker signing flow.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bloom_broker_api::{
    ApprovalLifecycleState, AssetId, CryptoSuite, DecimalU64, DecimalU256, DeclaredFee, Digest32,
    DurableEffect, OperationId, OperationState, PetalUseClaim, ProtocolErrorCode,
    ProvenanceCatalog, ProvenanceSubject, RequestNonce, Token, ValueLimit,
};
use bloom_machine_client::{
    ExactPayloadBatchSignRequest, ExactPayloadSignOutcome, ExactPayloadSignRequest,
    MachineBrokerClient,
};
use fs2::FileExt as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const STATE_SCHEMA: &str = "bloom.machine_exact_signing.v1";
const REUSABLE_ATTEMPT_SCHEMA: &str = "bloom.machine_reusable_signing_attempt.v1";
const REUSABLE_ATTEMPT_DOMAIN: &[u8] = b"bloom.machine.reusable-signing-attempt/v1\0";
const APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// Old daemon facts already committed to the exact action bytes. Backfill only
// that authenticated local identity, never invent a new approval or sign ID.
fn migrate_review_digest(
    saved: &mut Option<Digest32>,
    current: &Option<Digest32>,
    saved_facts: &Digest32,
    current_facts: &Digest32,
    facts: &serde_json::Value,
) {
    if saved.is_none()
        && saved_facts == current_facts
        && let Some(digest) = current
        && facts
            .get("action_digest")
            .and_then(serde_json::Value::as_str)
            == Some(digest.as_str())
    {
        *saved = Some(digest.clone());
    }
}

fn exact_claim_value_limits(claim: &PetalUseClaim) -> Result<Vec<ValueLimit>, String> {
    let mut totals = BTreeMap::<(String, String), alloy::primitives::U256>::new();
    let mut add = |chain: &Token, asset: &str, amount: &DecimalU256| -> Result<(), String> {
        let value = amount
            .as_str()
            .parse::<alloy::primitives::U256>()
            .map_err(|error| format!("parse exact claim value: {error}"))?;
        let total = totals
            .entry((chain.as_str().to_owned(), asset.to_owned()))
            .or_default();
        *total = total
            .checked_add(value)
            .ok_or_else(|| "exact claim value total exceeds uint256".to_owned())?;
        Ok(())
    };
    for debit in &claim.declared_debits {
        add(&debit.asset.chain, &debit.asset.asset, &debit.amount)?;
    }
    if let DeclaredFee::Fee {
        chain,
        asset,
        amount,
    } = &claim.declared_fee
    {
        add(chain, asset, amount)?;
    }
    totals
        .into_iter()
        .map(|((chain, asset), lifetime)| {
            Ok(ValueLimit {
                asset: AssetId {
                    chain: Token::new(chain).map_err(|error| error.to_string())?,
                    asset,
                },
                lifetime: DecimalU256::parse(lifetime.to_string())
                    .map_err(|error| error.to_string())?,
                rolling_windows: Vec::new(),
            })
        })
        .collect()
}

#[derive(Clone)]
pub struct BrokerExactPayloadSigner {
    broker: MachineBrokerClient,
    provenance_catalog: ProvenanceCatalog,
    account_key_ref: Option<bloom_broker_api::KeyRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactPayloadOutcome {
    ApprovalRequired {
        approval_id: Digest32,
        ceremony_url: String,
        ceremony_expires_at_ms: u64,
    },
    Signed(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactPayloadBatchOutcome {
    ApprovalRequired {
        approval_id: Digest32,
        ceremony_url: String,
        ceremony_expires_at_ms: u64,
    },
    Signed(Vec<Vec<u8>>),
}

/// Why exact signing returned no outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactSigningError {
    /// Nothing was signed: a local check, an approval prepare, or a signing
    /// refusal Broker marks final.
    Refused(String),
    /// A signing request may already have produced a signature.
    OutcomeUnknown(String),
}

impl From<String> for ExactSigningError {
    fn from(message: String) -> Self {
        Self::Refused(message)
    }
}

impl From<&str> for ExactSigningError {
    fn from(message: &str) -> Self {
        Self::Refused(message.to_owned())
    }
}

impl std::fmt::Display for ExactSigningError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(message) | Self::OutcomeUnknown(message) => formatter.write_str(message),
        }
    }
}

impl ExactSigningError {
    /// Classify a Broker failure. A request that could have signed
    /// (`signing`) is a refusal only when Broker's error contract says it
    /// left nothing behind; otherwise a signature may already exist.
    pub fn from_broker(error: bloom_broker_api::ProtocolError, signing: bool) -> Self {
        if signing && !leaves_nothing_signed(&error) {
            Self::OutcomeUnknown(error.to_string())
        } else {
            Self::Refused(error.to_string())
        }
    }
}

fn leaves_nothing_signed(error: &bloom_broker_api::ProtocolError) -> bool {
    matches!(
        error.durable_effect,
        DurableEffect::None | DurableEffect::ReservationReleased
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactSigningState {
    schema: String,
    action_id: String,
    wallet_id: Token,
    #[serde(default)]
    account_key_ref: Option<bloom_broker_api::KeyRef>,
    operation_class: Token,
    crypto_suite: CryptoSuite,
    payload_digest: Digest32,
    claimed_hash: Digest32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    review_payload_digest: Option<Digest32>,
    provenance_digest: Digest32,
    approval_operation_id: OperationId,
    signing_operation_id: OperationId,
    request_nonce: RequestNonce,
    issued_at_ms: DecimalU64,
    expires_at_ms: DecimalU64,
    canonical_plan_facts_digest: Digest32,
    approval_id: Option<Digest32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactBatchSigningState {
    schema: String,
    action_id: String,
    wallet_id: Token,
    #[serde(default)]
    account_key_ref: Option<bloom_broker_api::KeyRef>,
    operation_class: Token,
    crypto_suite: CryptoSuite,
    payload_digests: Vec<Digest32>,
    claimed_hashes: Vec<Digest32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    review_payload_digest: Option<Digest32>,
    provenance_digest: Digest32,
    approval_operation_id: OperationId,
    signing_operation_id: OperationId,
    request_nonce: RequestNonce,
    issued_at_ms: DecimalU64,
    expires_at_ms: DecimalU64,
    canonical_plan_facts_digest: Digest32,
    approval_id: Option<Digest32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReusablePetalBatchSigningState {
    schema: String,
    action_id: String,
    wallet_id: Token,
    #[serde(default)]
    account_key_ref: Option<bloom_broker_api::KeyRef>,
    operation_class: Token,
    crypto_suite: CryptoSuite,
    signature_count: u64,
    provenance_digest: Digest32,
    approval_operation_id: OperationId,
    signing_operation_id: OperationId,
    request_nonce: RequestNonce,
    issued_at_ms: DecimalU64,
    expires_at_ms: DecimalU64,
    canonical_plan_facts_digest: Digest32,
    approval_id: Option<Digest32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReusablePetalBatchSigningAttempt {
    schema: String,
    signing_operation_id: OperationId,
    request_digest: Digest32,
    /// The signing call for this attempt returned an outcome that leaves
    /// nothing in flight: a signature, or a refusal with no lasting effect.
    /// Absent until then, including in attempts recorded before this field.
    #[serde(default)]
    settled: bool,
}

#[derive(Serialize)]
struct ReusablePetalBatchSigningAttemptIdentity<'a> {
    ordered_payload_digests: &'a [Digest32],
    ordered_hashes: &'a [Digest32],
    petal_use_claim: &'a PetalUseClaim,
    claim_assurance_evidence_digest: Option<Digest32>,
}

impl BrokerExactPayloadSigner {
    pub fn new(broker: MachineBrokerClient, provenance_catalog: ProvenanceCatalog) -> Self {
        Self {
            broker,
            provenance_catalog,
            account_key_ref: None,
        }
    }

    pub fn with_account_key(mut self, key: Option<bloom_broker_api::KeyRef>) -> Self {
        self.account_key_ref = key;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sign_or_prepare(
        &self,
        state_path: &Path,
        action_id: &str,
        wallet: &str,
        operation_class: &str,
        preimage: &[u8],
        claimed_hash: Digest32,
        canonical_plan_facts: &serde_json::Value,
    ) -> Result<ExactPayloadOutcome, String> {
        let parent = state_path
            .parent()
            .ok_or_else(|| "exact signing state path has no parent".to_owned())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create exact signing state directory: {error}"))?;
        let lock_path = state_path.with_extension("lock");
        let lock = tokio::task::spawn_blocking(move || {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)
                .map_err(|error| format!("open exact signing lock: {error}"))?;
            file.lock_exclusive()
                .map_err(|error| format!("lock exact signing state: {error}"))?;
            Ok::<_, String>(file)
        })
        .await
        .map_err(|error| format!("join exact signing lock task: {error}"))??;

        let result = self
            .sign_or_prepare_locked(
                state_path,
                action_id,
                wallet,
                operation_class,
                preimage,
                claimed_hash,
                CryptoSuite::Secp256k1Keccak256Recoverable,
                canonical_plan_facts,
                None,
                None,
                None,
            )
            .await;
        let _ = lock.unlock();
        result.map_err(|error| error.to_string())
    }

    /// Exact Petal payload signing uses installer-authenticated package and
    /// route provenance supplied by Machine, never provenance chosen by guest
    /// code. The durable state and retry rules are otherwise identical to CLI
    /// and system exact signing.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_or_prepare_petal(
        &self,
        state_path: &Path,
        action_id: &str,
        wallet: &str,
        operation_class: &str,
        preimage: &[u8],
        claimed_hash: Digest32,
        crypto_suite: CryptoSuite,
        canonical_plan_facts: &serde_json::Value,
        trusted_subject: &ProvenanceSubject,
        claim: &PetalUseClaim,
        claim_assurance_evidence: Option<&[u8]>,
        petal_review_payload: Option<&[u8]>,
    ) -> Result<ExactPayloadOutcome, ExactSigningError> {
        let parent = state_path
            .parent()
            .ok_or_else(|| "exact signing state path has no parent".to_owned())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create exact signing state directory: {error}"))?;
        let lock_path = state_path.with_extension("lock");
        let lock = tokio::task::spawn_blocking(move || {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)
                .map_err(|error| format!("open exact signing lock: {error}"))?;
            file.lock_exclusive()
                .map_err(|error| format!("lock exact signing state: {error}"))?;
            Ok::<_, String>(file)
        })
        .await
        .map_err(|error| format!("join exact signing lock task: {error}"))??;
        let result = self
            .sign_or_prepare_locked(
                state_path,
                action_id,
                wallet,
                operation_class,
                preimage,
                claimed_hash,
                crypto_suite,
                canonical_plan_facts,
                Some(trusted_subject),
                Some((claim, claim_assurance_evidence)),
                petal_review_payload,
            )
            .await;
        let _ = lock.unlock();
        result
    }

    /// The owner ceremony a stored approval still waits on. Signing with it
    /// now would fail CLAIM_INVALID, which reads as a final refusal, so a
    /// retry returns the same pending approval instead. A status Broker cannot
    /// confirm is outcome-unknown: never sign, never drop the approval. A
    /// Broker without the status method predates the check; let signing report.
    async fn awaiting_owner(
        &self,
        approval_id: Option<&Digest32>,
    ) -> Result<Option<(Digest32, String, u64)>, ExactSigningError> {
        let Some(approval_id) = approval_id else {
            return Ok(None);
        };
        let unconfirmed = || {
            ExactSigningError::OutcomeUnknown(
                "the stored approval's ceremony is unconfirmed; retry without rebuilding".into(),
            )
        };
        let status = match self.broker.approval_status(approval_id.clone()).await {
            Ok(status) => status,
            Err(error)
                if matches!(
                    error.code,
                    ProtocolErrorCode::UnknownMethod | ProtocolErrorCode::UnknownField
                ) =>
            {
                return Ok(None);
            }
            Err(_) => return Err(unconfirmed()),
        };
        if !matches!(
            status.state,
            ApprovalLifecycleState::Prepared | ApprovalLifecycleState::AwaitingCeremony
        ) {
            return Ok(None);
        }
        match (status.ceremony_url, status.ceremony_expires_at_ms) {
            (Some(url), Some(expires)) => Ok(Some((approval_id.clone(), url, expires.get()))),
            // Pending, but with no ceremony to await: the lookup may have
            // missed a live one, and signing now would refuse and drop it.
            _ => Err(unconfirmed()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_or_prepare_locked(
        &self,
        state_path: &Path,
        action_id: &str,
        wallet: &str,
        operation_class: &str,
        preimage: &[u8],
        claimed_hash: Digest32,
        crypto_suite: CryptoSuite,
        canonical_plan_facts: &serde_json::Value,
        trusted_subject: Option<&ProvenanceSubject>,
        petal_claim: Option<(&PetalUseClaim, Option<&[u8]>)>,
        petal_review_payload: Option<&[u8]>,
    ) -> Result<ExactPayloadOutcome, ExactSigningError> {
        let operation_class_token = Token::new(operation_class.to_owned())
            .map_err(|error| format!("operation class: {error}"))?;
        let provenance = self
            .provenance_catalog
            .records
            .iter()
            .find(|record| {
                trusted_subject.map_or_else(
                    || provenance_operation_class(&record.subject) == Some(operation_class),
                    |subject| &record.subject == subject,
                ) && record
                    .operation_classes
                    .iter()
                    .any(|entry| entry.operation_class == operation_class_token)
            })
            .ok_or_else(|| format!("installer provenance does not authorize {operation_class}"))?;
        let provenance_digest = provenance
            .digest()
            .map_err(|error| format!("digest installer provenance: {error}"))?;
        let payload_digest = Digest32::from_bytes(Sha256::digest(preimage).into());
        let review_payload_digest =
            petal_review_payload.map(|bytes| Digest32::from_bytes(Sha256::digest(bytes).into()));
        let plan_bytes = serde_jcs::to_vec(canonical_plan_facts)
            .map_err(|error| format!("canonicalize exact signing facts: {error}"))?;
        let canonical_plan_facts_digest = Digest32::from_bytes(Sha256::digest(plan_bytes).into());
        let wallet_id = Token::new(wallet.to_owned()).map_err(|error| error.to_string())?;

        let mut state = match fs::read(state_path) {
            Ok(bytes) => serde_json::from_slice::<ExactSigningState>(&bytes)
                .map_err(|error| format!("read exact signing state: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let now = now_ms()?;
                ExactSigningState {
                    schema: STATE_SCHEMA.into(),
                    action_id: action_id.to_owned(),
                    wallet_id: wallet_id.clone(),
                    account_key_ref: self.account_key_ref.clone(),
                    operation_class: operation_class_token.clone(),
                    crypto_suite,
                    payload_digest: payload_digest.clone(),
                    claimed_hash: claimed_hash.clone(),
                    review_payload_digest: review_payload_digest.clone(),
                    provenance_digest: provenance_digest.clone(),
                    approval_operation_id: random_operation_id(),
                    signing_operation_id: random_operation_id(),
                    request_nonce: random_request_nonce(),
                    issued_at_ms: DecimalU64::new(now),
                    expires_at_ms: DecimalU64::new(now.saturating_add(APPROVAL_TTL_MS)),
                    canonical_plan_facts_digest: canonical_plan_facts_digest.clone(),
                    approval_id: None,
                }
            }
            Err(error) => return Err(format!("read exact signing state: {error}").into()),
        };
        migrate_review_digest(
            &mut state.review_payload_digest,
            &review_payload_digest,
            &state.canonical_plan_facts_digest,
            &canonical_plan_facts_digest,
            canonical_plan_facts,
        );
        if state.schema != STATE_SCHEMA
            || state.action_id != action_id
            || state.wallet_id != wallet_id
            || state.account_key_ref != self.account_key_ref
            || state.operation_class != operation_class_token
            || state.crypto_suite != crypto_suite
            || state.payload_digest != payload_digest
            || state.claimed_hash != claimed_hash
            || state.review_payload_digest != review_payload_digest
            || state.provenance_digest != provenance_digest
            || state.canonical_plan_facts_digest != canonical_plan_facts_digest
        {
            return Err("exact signing retry differs from its persisted operation identity".into());
        }
        let now = now_ms()?;
        // A local TTL cannot retire an approval or a signing operation. Once
        // prepared, replay the same identity so Broker can recover its result
        // or report its authoritative expiry. In particular, do not replace
        // a ceremony that the owner is still completing.
        if state.expires_at_ms.get() <= now && state.approval_id.is_none() {
            state.approval_operation_id = random_operation_id();
            state.signing_operation_id = random_operation_id();
            state.request_nonce = random_request_nonce();
            state.issued_at_ms = DecimalU64::new(now);
            state.expires_at_ms = DecimalU64::new(now.saturating_add(APPROVAL_TTL_MS));
            state.approval_id = None;
        }
        write_state(state_path, &state)?;
        let approval_value_limits = petal_claim
            .map(|(claim, _)| exact_claim_value_limits(claim))
            .transpose()?
            .unwrap_or_default();
        let request = ExactPayloadSignRequest {
            evm_reported_token: None,
            wallet_id,
            preimage: preimage.to_vec(),
            claimed_hash,
            crypto_suite,
            provenance: provenance.subject.clone(),
            provenance_digest,
            activation_mode: None,
            approval_operation_id: state.approval_operation_id.clone(),
            signing_operation_id: state.signing_operation_id.clone(),
            request_nonce: state.request_nonce.clone(),
            issued_at_ms: state.issued_at_ms.clone(),
            expires_at_ms: state.expires_at_ms.clone(),
            canonical_plan_facts_digest,
            approval_id: state.approval_id.clone(),
            account_key_ref: self.account_key_ref.clone(),
            petal_use_claim: petal_claim.map(|(claim, _)| claim.clone()),
            system_use_claim: None,
            claim_assurance_evidence: petal_claim
                .and_then(|(_, evidence)| evidence.map(<[u8]>::to_vec)),
            safe_review_payload: petal_review_payload
                .filter(|_| operation_class == bloom_broker_api::SAFE_CONFIRM_OPERATION_CLASS)
                .map(<[u8]>::to_vec),
            message_review_payload: petal_review_payload
                .filter(|_| operation_class != bloom_broker_api::SAFE_CONFIRM_OPERATION_CLASS)
                .map(<[u8]>::to_vec),
            approval_value_limits,
        };
        if let Some((approval_id, ceremony_url, ceremony_expires_at_ms)) =
            self.awaiting_owner(state.approval_id.as_ref()).await?
        {
            return Ok(ExactPayloadOutcome::ApprovalRequired {
                approval_id,
                ceremony_url,
                ceremony_expires_at_ms,
            });
        }
        match self.broker.sign_exact_payload_recovering(request).await {
            Ok(ExactPayloadSignOutcome::ApprovalRequired(prepared)) => {
                state.approval_id = Some(prepared.approval_id.clone());
                write_state(state_path, &state)?;
                Ok(ExactPayloadOutcome::ApprovalRequired {
                    approval_id: prepared.approval_id,
                    ceremony_url: prepared.ceremony_url,
                    ceremony_expires_at_ms: prepared.ceremony_expires_at_ms.get(),
                })
            }
            Ok(ExactPayloadSignOutcome::Signed(result)) => {
                if result.signatures.len() != 1 {
                    return Err(ExactSigningError::OutcomeUnknown(
                        "Broker returned an unexpected exact signature count".into(),
                    ));
                }
                Ok(ExactPayloadOutcome::Signed(
                    result.signatures[0].bytes.decode(),
                ))
            }
            Err(error) => {
                tracing::error!(code = ?error.code, message = %error.message, action_id, "petal exact signing failed");
                Err(ExactSigningError::from_broker(
                    error,
                    state.approval_id.is_some(),
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sign_or_prepare_petal_batch(
        &self,
        state_path: &Path,
        action_id: &str,
        wallet: &str,
        operation_class: &str,
        preimages: &[Vec<u8>],
        claimed_hashes: &[Digest32],
        crypto_suite: CryptoSuite,
        canonical_plan_facts: &serde_json::Value,
        trusted_subject: &ProvenanceSubject,
        claim: &PetalUseClaim,
        claim_assurance_evidence: Option<&[u8]>,
        message_review_payload: Option<&[u8]>,
    ) -> Result<ExactPayloadBatchOutcome, ExactSigningError> {
        let parent = state_path
            .parent()
            .ok_or_else(|| "exact batch signing state path has no parent".to_owned())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create exact batch signing state directory: {error}"))?;
        let lock_path = state_path.with_extension("lock");
        let lock = tokio::task::spawn_blocking(move || {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)
                .map_err(|error| format!("open exact batch signing lock: {error}"))?;
            file.lock_exclusive()
                .map_err(|error| format!("lock exact batch signing state: {error}"))?;
            Ok::<_, String>(file)
        })
        .await
        .map_err(|error| format!("join exact batch signing lock task: {error}"))??;
        let result = self
            .sign_or_prepare_petal_batch_locked(
                state_path,
                action_id,
                wallet,
                operation_class,
                preimages,
                claimed_hashes,
                crypto_suite,
                canonical_plan_facts,
                trusted_subject,
                claim,
                claim_assurance_evidence,
                message_review_payload,
            )
            .await;
        let _ = lock.unlock();
        result
    }

    /// Single-use Petal-scoped batch approval for payloads containing short-
    /// lived venue fields. Durable identity intentionally excludes payload
    /// bytes while retaining package, route, operation class, wallet, suite,
    /// assurance, operation count and signature count in Broker terms.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_or_prepare_reusable_petal_batch(
        &self,
        state_path: &Path,
        action_id: &str,
        wallet: &str,
        operation_class: &str,
        preimages: &[Vec<u8>],
        claimed_hashes: &[Digest32],
        crypto_suite: CryptoSuite,
        canonical_plan_facts: &serde_json::Value,
        trusted_subject: &ProvenanceSubject,
        claim: &PetalUseClaim,
        claim_assurance_evidence: Option<&[u8]>,
    ) -> Result<ExactPayloadBatchOutcome, ExactSigningError> {
        let parent = state_path
            .parent()
            .ok_or_else(|| "reusable batch signing state path has no parent".to_owned())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create reusable batch signing state directory: {error}"))?;
        let lock_path = state_path.with_extension("lock");
        let lock = tokio::task::spawn_blocking(move || {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)
                .map_err(|error| format!("open reusable batch signing lock: {error}"))?;
            file.lock_exclusive()
                .map_err(|error| format!("lock reusable batch signing state: {error}"))?;
            Ok::<_, String>(file)
        })
        .await
        .map_err(|error| format!("join reusable batch signing lock task: {error}"))??;
        let result = self
            .sign_or_prepare_reusable_petal_batch_locked(
                state_path,
                action_id,
                wallet,
                operation_class,
                preimages,
                claimed_hashes,
                crypto_suite,
                canonical_plan_facts,
                trusted_subject,
                claim,
                claim_assurance_evidence,
            )
            .await;
        let _ = lock.unlock();
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_or_prepare_reusable_petal_batch_locked(
        &self,
        state_path: &Path,
        action_id: &str,
        wallet: &str,
        operation_class: &str,
        preimages: &[Vec<u8>],
        claimed_hashes: &[Digest32],
        crypto_suite: CryptoSuite,
        canonical_plan_facts: &serde_json::Value,
        trusted_subject: &ProvenanceSubject,
        claim: &PetalUseClaim,
        claim_assurance_evidence: Option<&[u8]>,
    ) -> Result<ExactPayloadBatchOutcome, ExactSigningError> {
        let operation_class_token = Token::new(operation_class.to_owned())
            .map_err(|error| format!("operation class: {error}"))?;
        let provenance = self
            .provenance_catalog
            .records
            .iter()
            .find(|record| {
                &record.subject == trusted_subject
                    && record
                        .operation_classes
                        .iter()
                        .any(|entry| entry.operation_class == operation_class_token)
            })
            .ok_or_else(|| format!("installer provenance does not authorize {operation_class}"))?;
        let provenance_digest = provenance
            .digest()
            .map_err(|error| format!("digest installer provenance: {error}"))?;
        let plan_bytes = serde_jcs::to_vec(canonical_plan_facts)
            .map_err(|error| format!("canonicalize reusable batch signing facts: {error}"))?;
        let canonical_plan_facts_digest = Digest32::from_bytes(Sha256::digest(plan_bytes).into());
        let wallet_id = Token::new(wallet.to_owned()).map_err(|error| error.to_string())?;
        let signature_count = u64::try_from(preimages.len())
            .map_err(|_| "reusable batch signature count overflow".to_owned())?;

        let mut state = match fs::read(state_path) {
            Ok(bytes) => serde_json::from_slice::<ReusablePetalBatchSigningState>(&bytes)
                .map_err(|error| format!("read reusable batch signing state: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let now = now_ms()?;
                ReusablePetalBatchSigningState {
                    schema: STATE_SCHEMA.into(),
                    action_id: action_id.to_owned(),
                    wallet_id: wallet_id.clone(),
                    account_key_ref: self.account_key_ref.clone(),
                    operation_class: operation_class_token.clone(),
                    crypto_suite,
                    signature_count,
                    provenance_digest: provenance_digest.clone(),
                    approval_operation_id: random_operation_id(),
                    signing_operation_id: random_operation_id(),
                    request_nonce: random_request_nonce(),
                    issued_at_ms: DecimalU64::new(now),
                    expires_at_ms: DecimalU64::new(now.saturating_add(APPROVAL_TTL_MS)),
                    canonical_plan_facts_digest: canonical_plan_facts_digest.clone(),
                    approval_id: None,
                }
            }
            Err(error) => return Err(format!("read reusable batch signing state: {error}").into()),
        };
        if state.schema != STATE_SCHEMA
            || state.action_id != action_id
            || state.wallet_id != wallet_id
            || state.account_key_ref != self.account_key_ref
            || state.operation_class != operation_class_token
            || state.crypto_suite != crypto_suite
            || state.signature_count != signature_count
            || state.provenance_digest != provenance_digest
            || state.canonical_plan_facts_digest != canonical_plan_facts_digest
        {
            return Err(
                "reusable batch retry differs from its persisted authorization scope".into(),
            );
        }
        let payload_digests = preimages
            .iter()
            .map(|payload| Digest32::from_bytes(Sha256::digest(payload).into()))
            .collect::<Vec<_>>();
        let attempt_identity = ReusablePetalBatchSigningAttemptIdentity {
            ordered_payload_digests: &payload_digests,
            ordered_hashes: claimed_hashes,
            petal_use_claim: claim,
            claim_assurance_evidence_digest: claim_assurance_evidence
                .map(|evidence| Digest32::from_bytes(Sha256::digest(evidence).into())),
        };
        let attempt_bytes = serde_jcs::to_vec(&attempt_identity)
            .map_err(|error| format!("canonicalize reusable signing attempt: {error}"))?;
        let mut attempt_hasher = Sha256::new();
        attempt_hasher.update(REUSABLE_ATTEMPT_DOMAIN);
        attempt_hasher.update(attempt_bytes);
        let request_digest = Digest32::from_bytes(attempt_hasher.finalize().into());
        let attempt_path = state_path.with_extension("attempt.json");
        let previous_attempt = match fs::read(&attempt_path) {
            Ok(bytes) => Some(
                serde_json::from_slice::<ReusablePetalBatchSigningAttempt>(&bytes)
                    .map_err(|error| format!("read reusable signing attempt: {error}"))?,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(format!("read reusable signing attempt: {error}").into()),
        };
        if previous_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.schema != REUSABLE_ATTEMPT_SCHEMA)
        {
            return Err("reusable signing attempt schema is unsupported".into());
        }
        let now = now_ms()?;
        let expired = state.expires_at_ms.get() <= now && state.approval_id.is_none();
        let different_request = previous_attempt.as_ref().filter(|attempt| {
            attempt.signing_operation_id == state.signing_operation_id
                && attempt.request_digest != request_digest
        });
        if let Some(attempt) = previous_attempt.as_ref().filter(|attempt| {
            attempt.signing_operation_id == state.signing_operation_id
                && (different_request.is_some() || expired)
        }) && !attempt.settled
        {
            // New bytes replace the attempt's identity, and with it the
            // approval. Do that only once the earlier operation is final:
            // while it may still sign, a fresh approval would put a second
            // operation beside it. Approval expiry does not prove that an
            // operation accepted before expiry has finished signing.
            self.require_attempt_final(&attempt.signing_operation_id)
                .await?;
        }
        if different_request.is_some() || expired {
            state.approval_operation_id = random_operation_id();
            state.signing_operation_id = random_operation_id();
            state.request_nonce = random_request_nonce();
            state.issued_at_ms = DecimalU64::new(now);
            state.expires_at_ms = DecimalU64::new(now.saturating_add(APPROVAL_TTL_MS));
            state.approval_id = None;
        }
        write_state(state_path, &state)?;
        // A write made while the owner's ceremony is still open cannot sign.
        // Recording an attempt for its bytes would make the rebuild after the
        // ceremony look like a different request and set the approval aside,
        // so the owner would have to approve again. Report the open ceremony
        // instead, and record nothing.
        if let Some((approval_id, ceremony_url, ceremony_expires_at_ms)) =
            self.awaiting_owner(state.approval_id.as_ref()).await?
        {
            return Ok(ExactPayloadBatchOutcome::ApprovalRequired {
                approval_id,
                ceremony_url,
                ceremony_expires_at_ms,
            });
        }
        let attempt = state
            .approval_id
            .is_some()
            .then(|| ReusablePetalBatchSigningAttempt {
                schema: REUSABLE_ATTEMPT_SCHEMA.into(),
                signing_operation_id: state.signing_operation_id.clone(),
                request_digest,
                settled: false,
            });
        if let Some(attempt) = &attempt {
            write_state(&attempt_path, attempt)?;
        }
        let request = ExactPayloadBatchSignRequest {
            message_review_payload: None,
            wallet_id,
            preimages: preimages.to_vec(),
            claimed_hashes: claimed_hashes.to_vec(),
            crypto_suite,
            provenance: provenance.subject.clone(),
            provenance_digest,
            activation_mode: None,
            approval_operation_id: state.approval_operation_id.clone(),
            signing_operation_id: state.signing_operation_id.clone(),
            request_nonce: state.request_nonce.clone(),
            issued_at_ms: state.issued_at_ms.clone(),
            expires_at_ms: state.expires_at_ms.clone(),
            canonical_plan_facts_digest,
            approval_id: state.approval_id.clone(),
            account_key_ref: self.account_key_ref.clone(),
            petal_use_claim: Some(claim.clone()),
            claim_assurance_evidence: claim_assurance_evidence.map(<[u8]>::to_vec),
        };
        let response = self.broker.sign_reusable_petal_payload_batch(request).await;
        if let Some(mut attempt) = attempt
            && response.as_ref().err().is_none_or(leaves_nothing_signed)
        {
            attempt.settled = true;
            // A signature may exist; a failed write must not read as a refusal.
            write_state(&attempt_path, &attempt).map_err(ExactSigningError::OutcomeUnknown)?;
        }
        match response {
            Ok(ExactPayloadSignOutcome::ApprovalRequired(prepared)) => {
                state.approval_id = Some(prepared.approval_id.clone());
                write_state(state_path, &state)?;
                Ok(ExactPayloadBatchOutcome::ApprovalRequired {
                    approval_id: prepared.approval_id,
                    ceremony_url: prepared.ceremony_url,
                    ceremony_expires_at_ms: prepared.ceremony_expires_at_ms.get(),
                })
            }
            Ok(ExactPayloadSignOutcome::Signed(result)) => {
                if result.signatures.len() != preimages.len() {
                    return Err(ExactSigningError::OutcomeUnknown(
                        "Broker returned an unexpected reusable batch signature count".into(),
                    ));
                }
                Ok(ExactPayloadBatchOutcome::Signed(
                    result
                        .signatures
                        .iter()
                        .map(|signature| signature.bytes.decode())
                        .collect(),
                ))
            }
            Err(error) => Err(ExactSigningError::from_broker(
                error,
                state.approval_id.is_some(),
            )),
        }
    }

    /// Succeed only when Broker reports the signing operation in a final
    /// state. A response that never arrived, an operation still moving, a
    /// quarantined one, or a status Broker cannot give all leave it open.
    async fn require_attempt_final(
        &self,
        operation_id: &OperationId,
    ) -> Result<(), ExactSigningError> {
        let unsettled = "the previous reusable signing attempt has not settled";
        match self.broker.operation_status(operation_id.clone()).await {
            Ok(status)
                if status.operation_id == *operation_id
                    && matches!(
                        status.state,
                        OperationState::Succeeded
                            | OperationState::Denied
                            | OperationState::Cancelled
                            | OperationState::Failed
                    ) =>
            {
                Ok(())
            }
            Ok(status) => Err(ExactSigningError::OutcomeUnknown(format!(
                "{unsettled} (Broker reports {:?}); retry the same request or wait for it to finish",
                status.state
            ))),
            Err(error) => Err(ExactSigningError::OutcomeUnknown(format!(
                "{unsettled} and its outcome is unknown ({error}); retry the same request or wait for it to resolve"
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_or_prepare_petal_batch_locked(
        &self,
        state_path: &Path,
        action_id: &str,
        wallet: &str,
        operation_class: &str,
        preimages: &[Vec<u8>],
        claimed_hashes: &[Digest32],
        crypto_suite: CryptoSuite,
        canonical_plan_facts: &serde_json::Value,
        trusted_subject: &ProvenanceSubject,
        claim: &PetalUseClaim,
        claim_assurance_evidence: Option<&[u8]>,
        message_review_payload: Option<&[u8]>,
    ) -> Result<ExactPayloadBatchOutcome, ExactSigningError> {
        let operation_class_token = Token::new(operation_class.to_owned())
            .map_err(|error| format!("operation class: {error}"))?;
        let provenance = self
            .provenance_catalog
            .records
            .iter()
            .find(|record| {
                &record.subject == trusted_subject
                    && record
                        .operation_classes
                        .iter()
                        .any(|entry| entry.operation_class == operation_class_token)
            })
            .ok_or_else(|| format!("installer provenance does not authorize {operation_class}"))?;
        let provenance_digest = provenance
            .digest()
            .map_err(|error| format!("digest installer provenance: {error}"))?;
        let payload_digests = preimages
            .iter()
            .map(|payload| Digest32::from_bytes(Sha256::digest(payload).into()))
            .collect::<Vec<_>>();
        let review_payload_digest =
            message_review_payload.map(|bytes| Digest32::from_bytes(Sha256::digest(bytes).into()));
        let plan_bytes = serde_jcs::to_vec(canonical_plan_facts)
            .map_err(|error| format!("canonicalize exact batch signing facts: {error}"))?;
        let canonical_plan_facts_digest = Digest32::from_bytes(Sha256::digest(plan_bytes).into());
        let wallet_id = Token::new(wallet.to_owned()).map_err(|error| error.to_string())?;

        let mut state = match fs::read(state_path) {
            Ok(bytes) => serde_json::from_slice::<ExactBatchSigningState>(&bytes)
                .map_err(|error| format!("read exact batch signing state: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let now = now_ms()?;
                ExactBatchSigningState {
                    schema: STATE_SCHEMA.into(),
                    action_id: action_id.to_owned(),
                    wallet_id: wallet_id.clone(),
                    account_key_ref: self.account_key_ref.clone(),
                    operation_class: operation_class_token.clone(),
                    crypto_suite,
                    payload_digests: payload_digests.clone(),
                    claimed_hashes: claimed_hashes.to_vec(),
                    review_payload_digest: review_payload_digest.clone(),
                    provenance_digest: provenance_digest.clone(),
                    approval_operation_id: random_operation_id(),
                    signing_operation_id: random_operation_id(),
                    request_nonce: random_request_nonce(),
                    issued_at_ms: DecimalU64::new(now),
                    expires_at_ms: DecimalU64::new(now.saturating_add(APPROVAL_TTL_MS)),
                    canonical_plan_facts_digest: canonical_plan_facts_digest.clone(),
                    approval_id: None,
                }
            }
            Err(error) => return Err(format!("read exact batch signing state: {error}").into()),
        };
        migrate_review_digest(
            &mut state.review_payload_digest,
            &review_payload_digest,
            &state.canonical_plan_facts_digest,
            &canonical_plan_facts_digest,
            canonical_plan_facts,
        );
        if state.schema != STATE_SCHEMA
            || state.action_id != action_id
            || state.wallet_id != wallet_id
            || state.account_key_ref != self.account_key_ref
            || state.operation_class != operation_class_token
            || state.crypto_suite != crypto_suite
            || state.payload_digests != payload_digests
            || state.claimed_hashes != claimed_hashes
            || state.review_payload_digest != review_payload_digest
            || state.provenance_digest != provenance_digest
            || state.canonical_plan_facts_digest != canonical_plan_facts_digest
        {
            return Err(
                "exact batch signing retry differs from its persisted operation identity".into(),
            );
        }
        let now = now_ms()?;
        // Preserve the operation across local expiry, including lost replies
        // and open ceremonies. Broker owns approval expiry and replay.
        if state.expires_at_ms.get() <= now && state.approval_id.is_none() {
            state.approval_operation_id = random_operation_id();
            state.signing_operation_id = random_operation_id();
            state.request_nonce = random_request_nonce();
            state.issued_at_ms = DecimalU64::new(now);
            state.expires_at_ms = DecimalU64::new(now.saturating_add(APPROVAL_TTL_MS));
            state.approval_id = None;
        }
        write_state(state_path, &state)?;
        let request = ExactPayloadBatchSignRequest {
            message_review_payload: message_review_payload.map(<[u8]>::to_vec),
            wallet_id,
            preimages: preimages.to_vec(),
            claimed_hashes: claimed_hashes.to_vec(),
            crypto_suite,
            provenance: provenance.subject.clone(),
            provenance_digest,
            activation_mode: None,
            approval_operation_id: state.approval_operation_id.clone(),
            signing_operation_id: state.signing_operation_id.clone(),
            request_nonce: state.request_nonce.clone(),
            issued_at_ms: state.issued_at_ms.clone(),
            expires_at_ms: state.expires_at_ms.clone(),
            canonical_plan_facts_digest,
            approval_id: state.approval_id.clone(),
            account_key_ref: self.account_key_ref.clone(),
            petal_use_claim: Some(claim.clone()),
            claim_assurance_evidence: claim_assurance_evidence.map(<[u8]>::to_vec),
        };
        if let Some((approval_id, ceremony_url, ceremony_expires_at_ms)) =
            self.awaiting_owner(state.approval_id.as_ref()).await?
        {
            return Ok(ExactPayloadBatchOutcome::ApprovalRequired {
                approval_id,
                ceremony_url,
                ceremony_expires_at_ms,
            });
        }
        match self
            .broker
            .sign_exact_payload_batch_recovering(request)
            .await
        {
            Ok(ExactPayloadSignOutcome::ApprovalRequired(prepared)) => {
                state.approval_id = Some(prepared.approval_id.clone());
                write_state(state_path, &state)?;
                Ok(ExactPayloadBatchOutcome::ApprovalRequired {
                    approval_id: prepared.approval_id,
                    ceremony_url: prepared.ceremony_url,
                    ceremony_expires_at_ms: prepared.ceremony_expires_at_ms.get(),
                })
            }
            Ok(ExactPayloadSignOutcome::Signed(result)) => {
                if result.signatures.len() != preimages.len() {
                    return Err(ExactSigningError::OutcomeUnknown(
                        "Broker returned an unexpected exact batch signature count".into(),
                    ));
                }
                Ok(ExactPayloadBatchOutcome::Signed(
                    result
                        .signatures
                        .iter()
                        .map(|signature| signature.bytes.decode())
                        .collect(),
                ))
            }
            Err(error) => {
                tracing::error!(code = ?error.code, message = %error.message, action_id, "petal exact batch signing failed");
                Err(ExactSigningError::from_broker(
                    error,
                    state.approval_id.is_some(),
                ))
            }
        }
    }
}

fn provenance_operation_class(subject: &ProvenanceSubject) -> Option<&str> {
    match subject {
        ProvenanceSubject::Cli { command_class, .. } => Some(command_class.as_str()),
        ProvenanceSubject::System {
            operation_class, ..
        } => Some(operation_class.as_str()),
        ProvenanceSubject::Petal { .. } => None,
    }
}

fn random_operation_id() -> OperationId {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    OperationId::from_bytes(bytes)
}

fn random_request_nonce() -> RequestNonce {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    RequestNonce::from_bytes(bytes)
}

fn now_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch".to_owned())?;
    u64::try_from(duration.as_millis()).map_err(|_| "system time overflow".to_owned())
}

fn write_state<T: Serialize>(path: &Path, state: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "exact signing state path has no parent".to_owned())?;
    let temporary = parent.join(format!(
        ".exact-signing.{}.{}.{}.tmp",
        std::process::id(),
        now_ms()?,
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let bytes = serde_json::to_vec(state)
        .map_err(|error| format!("encode exact signing state: {error}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create exact signing state update: {error}"))?;
    let result = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| format!("commit exact signing state: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use bloom_broker_api::{
        ApprovalPrepareState, ApprovalPublicStatus, Base64UrlBytes, KeyPublic, KeyRef, KeyRole,
        KeySpec, MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService,
        NormalizedSignature, OperationPublicStatus, OperationState, PROVENANCE_CATALOG_SCHEMA,
        ProtocolError, ProtocolErrorCode, ProvenanceOperationClass, ProvenanceRecord,
        SealedApprovalPrepareResponse, ServiceFuture, SigningResult, WalletPublic,
    };

    #[derive(Default)]
    struct MockBroker {
        requests: Mutex<Vec<MachineBrokerRequest>>,
        lose_sign_response_once: AtomicBool,
        /// Simulates the pre-#265 derivation defect for the negative twin: the
        /// approval presents no `value_limits` even though the claim declares
        /// value, so the accounting mirror must refuse it.
        drop_value_limits: bool,
        /// The fee asset the provenance catalog marks for the operation class
        /// under test, mirroring `account_declared_values`' fee matching.
        class_fee_asset: Option<bloom_broker_api::ProvenanceFeeAsset>,
        /// Signings so far, as (approval, operation, operation digest, suite).
        /// Like the Broker, one approval admits one signing operation, and a
        /// signing operation id is bound to its digest.
        signings: Mutex<Vec<(Digest32, OperationId, Digest32, CryptoSuite)>>,
        /// While set, every prepared approval is still awaiting the owner's
        /// ceremony: it reports so, and the Broker refuses to sign under it.
        ceremony_open: AtomicBool,
        /// While set, operation status cannot be read.
        operation_status_unavailable: AtomicBool,
        /// Reported in place of a retained operation's final state.
        operation_state: Mutex<Option<OperationState>>,
        /// Errors the next signing requests return, in order.
        sign_errors: Mutex<Vec<ProtocolError>>,
        /// Errors the next approval status queries return, in order.
        status_errors: Mutex<Vec<ProtocolError>>,
    }

    impl MockBroker {
        /// Broker's signing admission: no signing under an open ceremony, one
        /// operation per approval, and an operation id bound to its digest.
        fn record_signing(
            &self,
            request: &bloom_broker_api::MachineSignRequest,
        ) -> Result<(), ProtocolError> {
            if self.ceremony_open.load(Ordering::SeqCst) {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::ClaimInvalid,
                    "approval is not active",
                ));
            }
            let mut signings = self.signings.lock().unwrap();
            for (approval, operation, operation_digest, _) in signings.iter() {
                if *operation == request.operation_id {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::OperationIdConflict,
                        if *operation_digest == request.operation_digest {
                            "signing operation already finalized"
                        } else {
                            "signing operation id reused for a different request"
                        },
                    ));
                }
                if *approval == request.approval_id {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::LimitExceededOperations,
                        "approval already used by another signing operation",
                    ));
                }
            }
            signings.push((
                request.approval_id.clone(),
                request.operation_id.clone(),
                request.operation_digest.clone(),
                request.crypto_suite,
            ));
            if self.lose_sign_response_once.swap(false, Ordering::SeqCst) {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    "simulated lost response after signing committed",
                ));
            }
            Ok(())
        }

        /// Mirrors `account_declared_values` in bloom-broker's `authority.rs`
        /// (the accounting a real Broker runs whenever a claim declares
        /// value): the claim's declared debits plus its declared fee must
        /// each name an asset covered by the approval's `value_limits`, and
        /// each covered total must fit the limit's lifetime. A declared fee
        /// is only legal when the provenance class is fee-bearing with the
        /// same asset.
        fn assert_accounting_accepts(
            &self,
            claim: &bloom_broker_api::PetalUseClaim,
            limits: &[bloom_broker_api::ValueLimit],
        ) -> Result<(), ProtocolError> {
            let missing =
                |why: &str| ProtocolError::new(ProtocolErrorCode::ClaimInvalid, why.to_string());
            let mut declared: Vec<((String, String), u128)> = Vec::new();
            {
                let mut add =
                    |chain: &str, asset: &str, amount: &str| -> Result<(), ProtocolError> {
                        let amount: u128 = amount
                            .parse()
                            .map_err(|_| missing("declared value is not a decimal amount"))?;
                        let key = (chain.to_string(), asset.to_string());
                        if let Some((_, total)) = declared.iter_mut().find(|(name, _)| *name == key)
                        {
                            *total = total.checked_add(amount).ok_or_else(|| {
                                missing("declared value exceeds approval accounting arithmetic")
                            })?;
                        } else {
                            declared.push((key, amount));
                        }
                        Ok(())
                    };
                for debit in &claim.declared_debits {
                    add(
                        debit.asset.chain.as_str(),
                        &debit.asset.asset,
                        debit.amount.as_str(),
                    )?;
                }
                match (&self.class_fee_asset, &claim.declared_fee) {
                    (None, bloom_broker_api::DeclaredFee::None) => {}
                    (
                        Some(expected),
                        bloom_broker_api::DeclaredFee::Fee {
                            chain,
                            asset,
                            amount,
                        },
                    ) if expected.chain == *chain && expected.asset == *asset => {
                        add(chain.as_str(), asset.as_str(), amount.as_str())?;
                    }
                    (Some(_), bloom_broker_api::DeclaredFee::None) => {
                        return Err(missing(
                            "FEE_REQUIRED: fee-bearing operation class must declare its native fee",
                        ));
                    }
                    (None, bloom_broker_api::DeclaredFee::Fee { .. }) => {
                        return Err(missing(
                            "FEE_NOT_ALLOWED: non-fee operation class must declare fee none",
                        ));
                    }
                    _ => {
                        return Err(missing(
                            "FEE_ASSET_MISMATCH: declared fee does not match provenance fee asset",
                        ));
                    }
                }
            }
            let limits = if self.drop_value_limits {
                &[][..]
            } else {
                limits
            };
            for ((chain, asset), total) in &declared {
                let Some(limit) = limits.iter().find(|limit| {
                    limit.asset.chain.as_str() == chain && limit.asset.asset.as_str() == asset
                }) else {
                    return Err(missing(
                        "VALUE_ASSET_NOT_ALLOWED: declared debit or fee asset is absent from approval limits",
                    ));
                };
                let lifetime: u128 = limit
                    .lifetime
                    .as_str()
                    .parse()
                    .map_err(|_| missing("approval lifetime is not a decimal amount"))?;
                if lifetime < *total {
                    return Err(missing(
                        "LimitExceededValue: declared value exceeds the approval's lifetime limit",
                    ));
                }
            }
            Ok(())
        }
    }

    impl MachineBrokerService for MockBroker {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                self.requests.lock().unwrap().push(request.clone());
                match request {
                    MachineBrokerRequest::WalletGetPublic(_) => {
                        Ok(MachineBrokerResponse::WalletGetPublic(WalletPublic {
                            wallet_id: token("wallet"),
                            wallet_kind: token("local"),
                            root_key_ref: Some(test_key_ref()),
                            key_refs: vec![test_key_ref()],
                            policy_version: DecimalU64::new(1),
                            policy_digest: digest(4),
                            wallet_revocation_epoch: DecimalU64::new(1),
                        }))
                    }
                    MachineBrokerRequest::KeyGetPublic(request) => {
                        assert_eq!(request.key_ref, test_key_ref());
                        Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                            key_ref: test_key_ref(),
                            role: KeyRole::WalletRoot,
                            canonical_public_key: Base64UrlBytes::from_bytes(&[2; 33]),
                            addresses: vec!["0x0000000000000000000000000000000000000001".into()],
                            supported_crypto_suites: vec![
                                CryptoSuite::Secp256k1Keccak256Recoverable,
                                CryptoSuite::Secp256k1Sha256Recoverable,
                            ],
                        }))
                    }
                    MachineBrokerRequest::SealedApprovalPrepare(request) => {
                        Ok(MachineBrokerResponse::SealedApprovalPrepare(
                            SealedApprovalPrepareResponse {
                                approval_id: request.terms.approval_id()?,
                                state: ApprovalPrepareState::AwaitingCeremony,
                                ceremony_url: "http://localhost:18734/ceremony/test".into(),
                                ceremony_expires_at_ms: request.terms.expires_at_ms,
                                review_manifest_digest: digest(8),
                            },
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalStatus(request) => {
                        let scripted = {
                            let mut errors = self.status_errors.lock().unwrap();
                            (!errors.is_empty()).then(|| errors.remove(0))
                        };
                        if let Some(error) = scripted {
                            return Err(error);
                        }
                        let waiting = self.ceremony_open.load(Ordering::SeqCst);
                        Ok(MachineBrokerResponse::SealedApprovalStatus(
                            ApprovalPublicStatus {
                                approval_id: request.id,
                                wallet_id: token("wallet"),
                                state: if waiting {
                                    ApprovalLifecycleState::AwaitingCeremony
                                } else {
                                    ApprovalLifecycleState::Active
                                },
                                effective_claim_assurance: None,
                                ceremony_url: waiting
                                    .then(|| "http://localhost:18734/ceremony/test".into()),
                                ceremony_expires_at_ms: waiting
                                    .then(|| DecimalU64::new(u64::MAX / 2)),
                            },
                        ))
                    }
                    MachineBrokerRequest::SigningSign(ref request) => {
                        // The real Broker re-runs accounting at sign time
                        // against the sealed approval terms, not the request.
                        if let Some(claim) = request.petal_use_claim.as_ref() {
                            let recorded = self.requests.lock().unwrap();
                            let sealed = recorded.iter().find_map(|record| match record {
                                MachineBrokerRequest::SealedApprovalPrepare(prepared)
                                    if prepared.terms.approval_id().ok().as_ref()
                                        == Some(&request.approval_id) =>
                                {
                                    Some(&prepared.terms.limits.value_limits)
                                }
                                _ => None,
                            });
                            let limits = sealed.ok_or_else(|| {
                                ProtocolError::new(
                                    ProtocolErrorCode::ClaimInvalid,
                                    "signing request names no prepared approval".to_string(),
                                )
                            })?;
                            self.assert_accounting_accepts(claim, limits)?;
                        }
                        let scripted = {
                            let mut errors = self.sign_errors.lock().unwrap();
                            (!errors.is_empty()).then(|| errors.remove(0))
                        };
                        if let Some(error) = scripted {
                            return Err(error);
                        }
                        self.record_signing(request)?;
                        Ok(MachineBrokerResponse::SigningSign(SigningResult {
                            operation_id: request.operation_id.clone(),
                            operation_digest: request.operation_digest.clone(),
                            signatures: vec![NormalizedSignature {
                                crypto_suite: request.crypto_suite,
                                bytes: Base64UrlBytes::from_bytes(&[7_u8; 65]),
                            }],
                            signer_receipt_digest: digest(9),
                            broker_receipt_digest: digest(10),
                        }))
                    }
                    MachineBrokerRequest::SigningSignBatch(request) => {
                        self.record_signing(&request)?;
                        Ok(MachineBrokerResponse::SigningSignBatch(SigningResult {
                            operation_id: request.operation_id,
                            operation_digest: request.operation_digest,
                            signatures: vec![NormalizedSignature {
                                crypto_suite: request.crypto_suite,
                                bytes: Base64UrlBytes::from_bytes(&[7_u8; 65]),
                            }],
                            signer_receipt_digest: digest(9),
                            broker_receipt_digest: digest(10),
                        }))
                    }
                    MachineBrokerRequest::OperationStatus(request) => {
                        if self.operation_status_unavailable.load(Ordering::SeqCst) {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::ServiceUnavailable,
                                "simulated unavailable operation status",
                            ));
                        }
                        let signings = self.signings.lock().unwrap();
                        // Broker's own answer for an operation it never journaled.
                        let (_, operation_id, operation_digest, crypto_suite) = signings
                            .iter()
                            .find(|(_, operation, ..)| *operation == request.operation_id)
                            .ok_or_else(|| {
                                ProtocolError::new(
                                    ProtocolErrorCode::ApprovalNotFound,
                                    "operation not found",
                                )
                            })?;
                        let state = self
                            .operation_state
                            .lock()
                            .unwrap()
                            .unwrap_or(OperationState::Succeeded);
                        let result = SigningResult {
                            operation_id: operation_id.clone(),
                            operation_digest: operation_digest.clone(),
                            signatures: vec![NormalizedSignature {
                                crypto_suite: *crypto_suite,
                                bytes: Base64UrlBytes::from_bytes(&[7_u8; 65]),
                            }],
                            signer_receipt_digest: digest(9),
                            broker_receipt_digest: digest(10),
                        };
                        Ok(MachineBrokerResponse::OperationStatus(
                            OperationPublicStatus {
                                operation_id: operation_id.clone(),
                                operation_digest: operation_digest.clone(),
                                state,
                                result: (state == OperationState::Succeeded).then_some(result),
                                error: None,
                            },
                        ))
                    }
                    _ => Err(ProtocolError::new(
                        ProtocolErrorCode::UnknownMethod,
                        "unexpected request",
                    )),
                }
            })
        }
    }

    fn test_key_ref() -> KeyRef {
        KeyRef {
            backend: token("local"),
            backend_instance: token("primary"),
            locator: "wallet/root".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: digest(3),
            derivation: None,
        }
    }

    #[tokio::test]
    async fn persists_identity_reuses_approval_and_rejects_payload_drift() {
        let broker = Arc::new(MockBroker {
            requests: Mutex::new(Vec::new()),
            ..MockBroker::default()
        });
        let signer = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![ProvenanceRecord {
                    subject: ProvenanceSubject::System {
                        component_id: token("bloom-machine"),
                        operation_class: token("transaction.confirm"),
                    },
                    publisher: token("bloom-installer"),
                    petal_lineage: None,
                    operation_classes: vec![ProvenanceOperationClass {
                        operation_class: token("transaction.confirm"),
                        fee_asset: None,
                    }],
                    installer_key_id: token("test-key"),
                    installer_signature: Base64UrlBytes::from_bytes(&[]),
                }],
            },
        );
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("exact.json");
        let payload = b"exact transaction bytes";
        let hash = Digest32::from_bytes(alloy::primitives::keccak256(payload).into());
        let first = signer
            .sign_or_prepare(
                &state,
                "action-1",
                "wallet",
                "transaction.confirm",
                payload,
                hash.clone(),
                &serde_json::json!({"amount": "1"}),
            )
            .await
            .unwrap();
        assert!(matches!(
            first,
            ExactPayloadOutcome::ApprovalRequired { .. }
        ));
        // The signing commits but its response is lost; that attempt and a
        // later retry, which Broker refuses as a replay, both recover the
        // retained result instead of signing again.
        broker.lose_sign_response_once.store(true, Ordering::SeqCst);
        for _ in 0..2 {
            let retry = signer
                .sign_or_prepare(
                    &state,
                    "action-1",
                    "wallet",
                    "transaction.confirm",
                    payload,
                    hash.clone(),
                    &serde_json::json!({"amount": "1"}),
                )
                .await
                .unwrap();
            assert_eq!(retry, ExactPayloadOutcome::Signed(vec![7_u8; 65]));
        }
        assert_eq!(broker.signings.lock().unwrap().len(), 1);
        let signing_operation_ids = broker
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter_map(|request| match request {
                MachineBrokerRequest::SigningSign(request) => Some(request.operation_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(signing_operation_ids.len(), 2);
        assert_eq!(signing_operation_ids[0], signing_operation_ids[1]);
        let persisted: ExactSigningState =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert_eq!(persisted.signing_operation_id, signing_operation_ids[0]);
        let requests_after_sign = broker.requests.lock().unwrap().len();
        let error = signer
            .sign_or_prepare(
                &state,
                "action-1",
                "wallet",
                "transaction.confirm",
                b"altered",
                Digest32::from_bytes(alloy::primitives::keccak256(b"altered").into()),
                &serde_json::json!({"amount": "1"}),
            )
            .await
            .unwrap_err();
        assert!(error.contains("differs from its persisted operation identity"));
        assert_eq!(broker.requests.lock().unwrap().len(), requests_after_sign);
    }

    /// A retry while the owner has not finished the ceremony returns the same
    /// pending approval and never asks Broker to sign with it.
    #[tokio::test]
    async fn a_retry_before_the_owner_approves_stays_pending() {
        let broker = Arc::new(MockBroker::default());
        let signer = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![ProvenanceRecord {
                    subject: ProvenanceSubject::System {
                        component_id: token("bloom-machine"),
                        operation_class: token("transaction.confirm"),
                    },
                    publisher: token("bloom-installer"),
                    petal_lineage: None,
                    operation_classes: vec![ProvenanceOperationClass {
                        operation_class: token("transaction.confirm"),
                        fee_asset: None,
                    }],
                    installer_key_id: token("test-key"),
                    installer_signature: Base64UrlBytes::from_bytes(&[]),
                }],
            },
        );
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("exact.json");
        let payload = b"exact transaction bytes";
        let hash = Digest32::from_bytes(alloy::primitives::keccak256(payload).into());
        let facts = serde_json::json!({"amount": "1"});
        let attempt = || {
            signer.sign_or_prepare(
                &state,
                "action-1",
                "wallet",
                "transaction.confirm",
                payload,
                hash.clone(),
                &facts,
            )
        };
        let signs = || {
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| matches!(request, MachineBrokerRequest::SigningSign(_)))
                .count()
        };
        let ExactPayloadOutcome::ApprovalRequired { approval_id, .. } = attempt().await.unwrap()
        else {
            panic!("first attempt must prepare an approval")
        };
        broker.ceremony_open.store(true, Ordering::SeqCst);
        let ExactPayloadOutcome::ApprovalRequired {
            approval_id: retried,
            ceremony_url,
            ..
        } = attempt().await.unwrap()
        else {
            panic!("a retry before approval must stay pending")
        };
        assert_eq!(retried, approval_id);
        assert_eq!(ceremony_url, "http://localhost:18734/ceremony/test");
        assert_eq!(signs(), 0, "a waiting approval is never signed with");
        broker.ceremony_open.store(false, Ordering::SeqCst);
        assert_eq!(
            attempt().await.unwrap(),
            ExactPayloadOutcome::Signed(vec![7_u8; 65])
        );
        assert_eq!(signs(), 1);
    }

    /// A retry that cannot confirm the stored approval's ceremony waits
    /// instead of signing into a refusal that would drop a live approval.
    #[tokio::test]
    async fn an_unconfirmed_approval_ceremony_is_unknown_not_a_refusal() {
        let broker = Arc::new(MockBroker::default());
        let signer = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![ProvenanceRecord {
                    subject: ProvenanceSubject::System {
                        component_id: token("bloom-machine"),
                        operation_class: token("transaction.confirm"),
                    },
                    publisher: token("bloom-installer"),
                    petal_lineage: None,
                    operation_classes: vec![ProvenanceOperationClass {
                        operation_class: token("transaction.confirm"),
                        fee_asset: None,
                    }],
                    installer_key_id: token("test-key"),
                    installer_signature: Base64UrlBytes::from_bytes(&[]),
                }],
            },
        );
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("exact.json");
        let payload = b"exact transaction bytes";
        let hash = Digest32::from_bytes(alloy::primitives::keccak256(payload).into());
        let facts = serde_json::json!({"amount": "1"});
        let attempt = || {
            signer.sign_or_prepare_locked(
                &state,
                "action-1",
                "wallet",
                "transaction.confirm",
                payload,
                hash.clone(),
                CryptoSuite::Secp256k1Keccak256Recoverable,
                &facts,
                None,
                None,
                None,
            )
        };
        let signs = || {
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| matches!(request, MachineBrokerRequest::SigningSign(_)))
                .count()
        };
        let ExactPayloadOutcome::ApprovalRequired { approval_id, .. } = attempt().await.unwrap()
        else {
            panic!("first attempt must prepare an approval")
        };
        *broker.status_errors.lock().unwrap() = vec![ProtocolError::new(
            ProtocolErrorCode::ServiceUnavailable,
            "approval status query lost",
        )];
        let error = attempt().await.unwrap_err();
        assert!(
            matches!(error, ExactSigningError::OutcomeUnknown(_)),
            "an unconfirmed ceremony must wait, not refuse: {error}"
        );
        assert_eq!(signs(), 0, "an unconfirmed approval is never signed with");
        // Nothing was dropped: once status answers, the retry pends again.
        broker.ceremony_open.store(true, Ordering::SeqCst);
        let ExactPayloadOutcome::ApprovalRequired {
            approval_id: retried,
            ..
        } = attempt().await.unwrap()
        else {
            panic!("the stored approval must survive an unconfirmed retry")
        };
        assert_eq!(retried, approval_id);
    }

    /// A reusable batch retry while the owner has not finished the ceremony
    /// returns the same pending approval and never asks Broker to sign.
    #[tokio::test]
    async fn a_reusable_batch_retry_before_the_owner_approves_stays_pending() {
        let broker = Arc::new(MockBroker::default());
        let package_hash = digest(20);
        let subject = ProvenanceSubject::Petal {
            package_hash: package_hash.clone(),
            route: "orders/place".into(),
        };
        let signer = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![ProvenanceRecord {
                    subject: subject.clone(),
                    publisher: token("bloom-installer"),
                    petal_lineage: None,
                    operation_classes: vec![ProvenanceOperationClass {
                        operation_class: token("order.place"),
                        fee_asset: None,
                    }],
                    installer_key_id: token("test-key"),
                    installer_signature: Base64UrlBytes::from_bytes(&[]),
                }],
            },
        );
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("reusable-batch.json");
        let payload = b"reusable batch payload";
        let ordered_hash = Digest32::from_bytes(Sha256::digest(payload).into());
        let claim = PetalUseClaim {
            package_hash,
            route: "orders/place".into(),
            operation_class: token("order.place"),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            payload_digest: {
                let mut digest = Sha256::new();
                digest.update(b"bloom.petal.payload-batch.v1\0");
                digest.update(1_u64.to_be_bytes());
                digest.update((payload.len() as u64).to_be_bytes());
                digest.update(payload);
                Digest32::from_bytes(digest.finalize().into())
            },
            ordered_hashes: vec![ordered_hash.clone()],
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee: bloom_broker_api::DeclaredFee::None,
            nonce: RequestNonce::from_bytes([22; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        };
        let payloads = vec![payload.to_vec()];
        let claimed_hashes = vec![ordered_hash.clone()];
        let facts = serde_json::json!({"asset": "BTC"});
        let attempt = || {
            signer.sign_or_prepare_reusable_petal_batch(
                &state,
                "batch-action",
                "wallet",
                "order.place",
                &payloads,
                &claimed_hashes,
                CryptoSuite::Secp256k1Sha256Recoverable,
                &facts,
                &subject,
                &claim,
                Some(b"assurance"),
            )
        };
        let signs = || {
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| matches!(request, MachineBrokerRequest::SigningSignBatch(_)))
                .count()
        };
        let ExactPayloadBatchOutcome::ApprovalRequired { approval_id, .. } =
            attempt().await.unwrap()
        else {
            panic!("first attempt must prepare an approval")
        };
        broker.ceremony_open.store(true, Ordering::SeqCst);
        let ExactPayloadBatchOutcome::ApprovalRequired {
            approval_id: retried,
            ceremony_url,
            ..
        } = attempt().await.unwrap()
        else {
            panic!("a retry before approval must stay pending")
        };
        assert_eq!(retried, approval_id);
        assert_eq!(ceremony_url, "http://localhost:18734/ceremony/test");
        assert_eq!(signs(), 0, "a waiting approval is never signed with");
    }

    /// A signing failure is a refusal only when Broker marks it final with no
    /// lasting effect. A lost response, or a retry after a finalized attempt,
    /// may already have produced a signature.
    #[tokio::test]
    async fn signing_failures_are_refusals_only_under_brokers_contract() {
        let cases = [
            (
                vec![ProtocolError::new(
                    ProtocolErrorCode::ServiceUnavailable,
                    "read local frame prefix: early eof",
                )],
                false,
            ),
            (
                vec![ProtocolError::new(
                    ProtocolErrorCode::ClaimInvalid,
                    "approval is not active",
                )],
                true,
            ),
            (
                vec![ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "finalized",
                )],
                false,
            ),
        ];
        for (errors, refused) in cases {
            let broker = Arc::new(MockBroker::default());
            let signer = BrokerExactPayloadSigner::new(
                MachineBrokerClient::new(broker.clone()),
                ProvenanceCatalog {
                    schema: PROVENANCE_CATALOG_SCHEMA.into(),
                    records: vec![ProvenanceRecord {
                        subject: ProvenanceSubject::System {
                            component_id: token("bloom-machine"),
                            operation_class: token("transaction.confirm"),
                        },
                        publisher: token("bloom-installer"),
                        petal_lineage: None,
                        operation_classes: vec![ProvenanceOperationClass {
                            operation_class: token("transaction.confirm"),
                            fee_asset: None,
                        }],
                        installer_key_id: token("test-key"),
                        installer_signature: Base64UrlBytes::from_bytes(&[]),
                    }],
                },
            );
            let temporary = tempfile::tempdir().unwrap();
            let state = temporary.path().join("exact.json");
            let payload = b"exact transaction bytes";
            let hash = Digest32::from_bytes(alloy::primitives::keccak256(payload).into());
            let facts = serde_json::json!({"amount": "1"});
            let attempt = || {
                signer.sign_or_prepare_locked(
                    &state,
                    "action-1",
                    "wallet",
                    "transaction.confirm",
                    payload,
                    hash.clone(),
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    &facts,
                    None,
                    None,
                    None,
                )
            };
            attempt().await.unwrap();
            *broker.sign_errors.lock().unwrap() = errors;
            let error = attempt().await.unwrap_err();
            assert_eq!(
                matches!(error, ExactSigningError::Refused(_)),
                refused,
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn petal_retry_preserves_the_requested_crypto_suite_through_prepare_and_sign() {
        let broker = Arc::new(MockBroker {
            requests: Mutex::new(Vec::new()),
            ..MockBroker::default()
        });
        let package_hash = digest(20);
        let subject = ProvenanceSubject::Petal {
            package_hash: package_hash.clone(),
            route: "orders/place".into(),
        };
        let signer = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![ProvenanceRecord {
                    subject: subject.clone(),
                    publisher: token("bloom-installer"),
                    petal_lineage: None,
                    operation_classes: vec![ProvenanceOperationClass {
                        operation_class: token("order.place"),
                        fee_asset: None,
                    }],
                    installer_key_id: token("test-key"),
                    installer_signature: Base64UrlBytes::from_bytes(&[]),
                }],
            },
        );
        let temporary = tempfile::tempdir().unwrap();
        let state = temporary.path().join("petal-exact.json");
        let payload = b"exact venue payload";
        let ordered_hash = Digest32::from_bytes(Sha256::digest(payload).into());
        let claim_payload_digest = {
            let mut digest = Sha256::new();
            digest.update(b"bloom.petal.payload-batch.v1\0");
            digest.update(1_u64.to_be_bytes());
            digest.update((payload.len() as u64).to_be_bytes());
            digest.update(payload);
            Digest32::from_bytes(digest.finalize().into())
        };
        let claim = PetalUseClaim {
            package_hash,
            route: "orders/place".into(),
            operation_class: token("order.place"),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            payload_digest: claim_payload_digest,
            ordered_hashes: vec![ordered_hash.clone()],
            declared_debits: vec![
                bloom_broker_api::DeclaredDebit {
                    asset: AssetId {
                        chain: token("hyperliquid"),
                        asset: "usdc".into(),
                    },
                    amount: DecimalU256::parse("7").unwrap(),
                },
                bloom_broker_api::DeclaredDebit {
                    asset: AssetId {
                        chain: token("hyperliquid"),
                        asset: "usdc".into(),
                    },
                    amount: DecimalU256::parse("5").unwrap(),
                },
            ],
            declared_destinations: Vec::new(),
            declared_fee: bloom_broker_api::DeclaredFee::None,
            nonce: RequestNonce::from_bytes([21; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        };

        let first = signer
            .sign_or_prepare_petal(
                &state,
                "petal-action",
                "wallet",
                "order.place",
                payload,
                ordered_hash.clone(),
                CryptoSuite::Secp256k1Sha256Recoverable,
                &serde_json::json!({"asset": "BTC"}),
                &subject,
                &claim,
                Some(b"assurance"),
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            first,
            ExactPayloadOutcome::ApprovalRequired { .. }
        ));
        let second = signer
            .sign_or_prepare_petal(
                &state,
                "petal-action",
                "wallet",
                "order.place",
                payload,
                ordered_hash,
                CryptoSuite::Secp256k1Sha256Recoverable,
                &serde_json::json!({"asset": "BTC"}),
                &subject,
                &claim,
                Some(b"assurance"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(second, ExactPayloadOutcome::Signed(vec![7; 65]));

        let mut other_key = test_key_ref();
        // Even the same fingerprint with a different locator is a different
        // selected key: persist and compare the entire KeyRef.
        other_key.locator = "wallet/account/1".into();
        let other_signer = signer.clone().with_account_key(Some(other_key));
        let before = broker.requests.lock().unwrap().len();
        let error = other_signer
            .sign_or_prepare_petal(
                &state,
                "petal-action",
                "wallet",
                "order.place",
                payload,
                claim.ordered_hashes[0].clone(),
                CryptoSuite::Secp256k1Sha256Recoverable,
                &serde_json::json!({"asset": "BTC"}),
                &subject,
                &claim,
                Some(b"assurance"),
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("persisted"), "{error}");
        assert_eq!(broker.requests.lock().unwrap().len(), before);

        for reusable in [false, true] {
            let batch_state = temporary.path().join(format!("batch-{reusable}.json"));
            let payloads = vec![payload.to_vec()];
            let facts = serde_json::json!({"asset": "BTC"});
            for (selected, should_reject) in
                [(&signer, false), (&other_signer, true), (&signer, false)]
            {
                let before = broker.requests.lock().unwrap().len();
                let outcome = if reusable {
                    selected
                        .sign_or_prepare_reusable_petal_batch(
                            &batch_state,
                            "batch",
                            "wallet",
                            "order.place",
                            &payloads,
                            &claim.ordered_hashes,
                            claim.crypto_suite,
                            &facts,
                            &subject,
                            &claim,
                            Some(b"assurance"),
                        )
                        .await
                } else {
                    selected
                        .sign_or_prepare_petal_batch(
                            &batch_state,
                            "batch",
                            "wallet",
                            "order.place",
                            &payloads,
                            &claim.ordered_hashes,
                            claim.crypto_suite,
                            &facts,
                            &subject,
                            &claim,
                            Some(b"assurance"),
                            None,
                        )
                        .await
                };
                if should_reject {
                    assert!(outcome.unwrap_err().to_string().contains("persisted"));
                    assert_eq!(broker.requests.lock().unwrap().len(), before);
                } else {
                    outcome.unwrap();
                }
            }
        }

        let requests = broker.requests.lock().unwrap();
        let MachineBrokerRequest::SealedApprovalPrepare(prepared) = &requests[2] else {
            panic!("first exact attempt must prepare approval");
        };
        assert_eq!(
            prepared.terms.allowed_crypto_suites,
            [CryptoSuite::Secp256k1Sha256Recoverable]
        );
        assert_eq!(prepared.terms.limits.value_limits.len(), 1);
        assert_eq!(
            prepared.terms.limits.value_limits[0].asset,
            AssetId {
                chain: token("hyperliquid"),
                asset: "usdc".into(),
            }
        );
        assert_eq!(
            prepared.terms.limits.value_limits[0].lifetime.as_str(),
            "12"
        );
        let Some(signed) = requests.iter().find_map(|request| match request {
            MachineBrokerRequest::SigningSign(signed) => Some(signed),
            _ => None,
        }) else {
            panic!("approved retry must sign");
        };
        assert_eq!(signed.crypto_suite, CryptoSuite::Secp256k1Sha256Recoverable);
    }

    #[tokio::test]
    async fn safe_confirmation_forwards_its_review_envelope_to_approval_preparation() {
        review_envelope_forwarding(
            bloom_broker_api::SAFE_CONFIRM_OPERATION_CLASS,
            "bloom.safe.review.v1",
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn message_signatures_forward_their_review_envelopes_and_refuse_omission() {
        for class in bloom_broker_api::MESSAGE_REVIEW_OPERATION_CLASSES {
            review_envelope_forwarding(class, "bloom.message.review.v1", false).await;
        }
        for class in bloom_broker_api::POLYMARKET_REVIEW_OPERATION_CLASSES {
            review_envelope_forwarding(class, "prepared", true).await;
        }
    }

    async fn review_envelope_forwarding(class: &str, schema: &str, batch: bool) {
        let broker = Arc::new(MockBroker::default());
        let package_hash = digest(30);
        let subject = ProvenanceSubject::Petal {
            package_hash: package_hash.clone(),
            route: "transactions/confirm".into(),
        };
        let signer = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![ProvenanceRecord {
                    subject: subject.clone(),
                    publisher: token("bloom-installer"),
                    petal_lineage: None,
                    operation_classes: vec![ProvenanceOperationClass {
                        operation_class: token(class),
                        fee_asset: None,
                    }],
                    installer_key_id: token("test-key"),
                    installer_signature: Base64UrlBytes::from_bytes(&[]),
                }],
            },
        );
        let temporary = tempfile::tempdir().unwrap();
        let payload = b"\x19\x01safe preimage";
        let ordered_hash = Digest32::from_bytes(alloy::primitives::keccak256(payload).into());
        let claim = PetalUseClaim {
            package_hash,
            route: "transactions/confirm".into(),
            operation_class: token(class),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: {
                let mut digest = Sha256::new();
                digest.update(b"bloom.petal.payload-batch.v1\0");
                digest.update(1_u64.to_be_bytes());
                digest.update((payload.len() as u64).to_be_bytes());
                digest.update(payload);
                Digest32::from_bytes(digest.finalize().into())
            },
            ordered_hashes: vec![ordered_hash.clone()],
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee: bloom_broker_api::DeclaredFee::None,
            nonce: RequestNonce::from_bytes([31; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        };
        let envelope = serde_json::to_vec(&serde_json::json!({"schema":schema})).unwrap();
        let facts = serde_json::json!({"action_digest": hex::encode(Sha256::digest(&envelope))});
        let prepared_envelopes = || {
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter_map(|request| match request {
                    MachineBrokerRequest::SealedApprovalPrepare(prepared) => {
                        Some(if class == bloom_broker_api::SAFE_CONFIRM_OPERATION_CLASS {
                            assert!(prepared.message_review_payloads.is_empty());
                            prepared.safe_review_payloads.clone()
                        } else {
                            assert!(prepared.safe_review_payloads.is_empty());
                            prepared.message_review_payloads.clone()
                        })
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };

        // Without the envelope the class must not reach approval preparation.
        let missing = if batch {
            signer
                .sign_or_prepare_petal_batch(
                    &temporary.path().join("missing.json"),
                    "confirm",
                    "wallet",
                    class,
                    &[payload.to_vec()],
                    std::slice::from_ref(&ordered_hash),
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    &facts,
                    &subject,
                    &claim,
                    None,
                    None,
                )
                .await
                .map(|_| ())
        } else {
            signer
                .sign_or_prepare_petal(
                    &temporary.path().join("missing.json"),
                    "confirm",
                    "wallet",
                    class,
                    payload,
                    ordered_hash.clone(),
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    &facts,
                    &subject,
                    &claim,
                    None,
                    None,
                )
                .await
                .map(|_| ())
        };
        let error = missing.unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("review"),
            "{error}"
        );
        assert!(prepared_envelopes().is_empty());

        let prepared = if batch {
            let outcome = signer
                .sign_or_prepare_petal_batch(
                    &temporary.path().join("confirm.json"),
                    "confirm",
                    "wallet",
                    class,
                    &[payload.to_vec()],
                    std::slice::from_ref(&ordered_hash),
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    &facts,
                    &subject,
                    &claim,
                    None,
                    Some(&envelope),
                )
                .await
                .unwrap();
            matches!(outcome, ExactPayloadBatchOutcome::ApprovalRequired { .. })
        } else {
            let outcome = signer
                .sign_or_prepare_petal(
                    &temporary.path().join("confirm.json"),
                    "confirm",
                    "wallet",
                    class,
                    payload,
                    ordered_hash.clone(),
                    CryptoSuite::Secp256k1Keccak256Recoverable,
                    &facts,
                    &subject,
                    &claim,
                    None,
                    Some(&envelope),
                )
                .await
                .unwrap();
            matches!(outcome, ExactPayloadOutcome::ApprovalRequired { .. })
        };
        assert!(prepared);
        assert_eq!(
            prepared_envelopes(),
            vec![vec![Base64UrlBytes::from_bytes(&envelope)]]
        );
        // The signer binds the witness itself, even when its caller supplies
        // unchanged plan facts. Neither replacing nor dropping it may reuse
        // the saved approval, and rejection must leave that approval intact.
        let changed = br#"{"schema":"changed"}"#;
        let state_path = temporary.path().join("confirm.json");
        let saved = fs::read(&state_path).unwrap();
        let calls = broker.requests.lock().unwrap().len();
        for (migrate, witness) in [
            (false, Some(changed.as_slice())),
            (false, None),
            (true, Some(envelope.as_slice())),
        ] {
            if migrate {
                let mut legacy: serde_json::Value = serde_json::from_slice(&saved).unwrap();
                legacy
                    .as_object_mut()
                    .unwrap()
                    .remove("review_payload_digest");
                fs::write(&state_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
            }
            let result = if batch {
                signer
                    .sign_or_prepare_petal_batch(
                        &state_path,
                        "confirm",
                        "wallet",
                        class,
                        &[payload.to_vec()],
                        std::slice::from_ref(&ordered_hash),
                        CryptoSuite::Secp256k1Keccak256Recoverable,
                        &facts,
                        &subject,
                        &claim,
                        None,
                        witness,
                    )
                    .await
                    .map(|_| ())
            } else {
                signer
                    .sign_or_prepare_petal(
                        &state_path,
                        "confirm",
                        "wallet",
                        class,
                        payload,
                        ordered_hash.clone(),
                        CryptoSuite::Secp256k1Keccak256Recoverable,
                        &facts,
                        &subject,
                        &claim,
                        None,
                        witness,
                    )
                    .await
                    .map(|_| ())
            };
            if migrate {
                result.unwrap();
                let migrated: serde_json::Value =
                    serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
                let original: serde_json::Value = serde_json::from_slice(&saved).unwrap();
                for field in [
                    "approval_id",
                    "approval_operation_id",
                    "signing_operation_id",
                    "review_payload_digest",
                ] {
                    assert_eq!(migrated[field], original[field], "{field}");
                }
            } else {
                let error = result.unwrap_err();
                assert!(
                    error.to_string().contains("persisted operation identity"),
                    "{error}"
                );
                assert_eq!(fs::read(&state_path).unwrap(), saved);
                assert_eq!(broker.requests.lock().unwrap().len(), calls);
            }
        }
    }

    /// Builds the shared fixture: a petal exact signer whose provenance
    /// catalog marks one class with the scenario's fee asset.
    /// Its arbitrary SHA-256 payload and multiple assets exercise generic
    /// accounting, not Hyperliquid's single-message protocol contract.
    fn debiting_claim_fixture(
        broker: &Arc<MockBroker>,
        class_fee_asset: Option<bloom_broker_api::ProvenanceFeeAsset>,
    ) -> (
        BrokerExactPayloadSigner,
        tempfile::TempDir,
        PetalUseClaim,
        Digest32,
    ) {
        let package_hash = digest(30);
        let subject = ProvenanceSubject::Petal {
            package_hash: package_hash.clone(),
            route: "withdraw/request".into(),
        };
        let signer = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            ProvenanceCatalog {
                schema: PROVENANCE_CATALOG_SCHEMA.into(),
                records: vec![ProvenanceRecord {
                    subject,
                    publisher: token("bloom-installer"),
                    petal_lineage: None,
                    operation_classes: vec![ProvenanceOperationClass {
                        operation_class: token("fixture.withdraw"),
                        fee_asset: class_fee_asset,
                    }],
                    installer_key_id: token("test-key"),
                    installer_signature: Base64UrlBytes::from_bytes(&[]),
                }],
            },
        );
        let home = tempfile::tempdir().unwrap();
        let payload = b"exact withdraw payload";
        let ordered_hash = Digest32::from_bytes(Sha256::digest(payload).into());
        let claim = PetalUseClaim {
            package_hash,
            route: "withdraw/request".into(),
            operation_class: token("fixture.withdraw"),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            payload_digest: {
                let mut digest = Sha256::new();
                digest.update(b"bloom.petal.payload-batch.v1\0");
                digest.update(1_u64.to_be_bytes());
                digest.update((payload.len() as u64).to_be_bytes());
                digest.update(payload);
                Digest32::from_bytes(digest.finalize().into())
            },
            ordered_hashes: vec![Digest32::from_bytes(Sha256::digest(payload).into())],
            declared_debits: vec![
                bloom_broker_api::DeclaredDebit {
                    asset: bloom_broker_api::AssetId {
                        chain: token("hyperliquid"),
                        asset: "usdc".into(),
                    },
                    amount: bloom_broker_api::DecimalU256::parse("5000000").unwrap(),
                },
                bloom_broker_api::DeclaredDebit {
                    asset: bloom_broker_api::AssetId {
                        chain: token("arbitrum"),
                        asset: "usdc".into(),
                    },
                    amount: bloom_broker_api::DecimalU256::parse("2500000").unwrap(),
                },
            ],
            declared_destinations: Vec::new(),
            declared_fee: bloom_broker_api::DeclaredFee::None,
            nonce: RequestNonce::from_bytes([31; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        };
        (signer, home, claim, ordered_hash)
    }

    async fn flow_once(
        signer: &BrokerExactPayloadSigner,
        home: &tempfile::TempDir,
        claim: &PetalUseClaim,
        hash: &Digest32,
    ) -> Result<ExactPayloadOutcome, ExactSigningError> {
        let package_hash = claim.package_hash.clone();
        signer
            .sign_or_prepare_petal(
                &home.path().join("petal-exact.json"),
                "withdraw-action",
                "wallet",
                "fixture.withdraw",
                b"exact withdraw payload",
                hash.clone(),
                CryptoSuite::Secp256k1Sha256Recoverable,
                &serde_json::json!({"asset": "USDC"}),
                &ProvenanceSubject::Petal {
                    package_hash,
                    route: "withdraw/request".into(),
                },
                claim,
                Some(b"assurance"),
                None,
            )
            .await
    }

    #[tokio::test]
    async fn a_claim_declaring_value_is_accounted_end_to_end_against_its_derived_limits() {
        for (name, class_fee_asset, declared_fee, expected_fee_total) in [
            ("debit only", None, None, 0),
            (
                "debit plus fee",
                Some(bloom_broker_api::ProvenanceFeeAsset {
                    chain: token("hyperliquid"),
                    asset: "usdc".into(),
                }),
                Some(bloom_broker_api::DeclaredFee::Fee {
                    chain: token("hyperliquid"),
                    asset: "usdc".into(),
                    amount: bloom_broker_api::DecimalU256::parse("1000000").unwrap(),
                }),
                1_000_000,
            ),
        ] {
            let broker = Arc::new(MockBroker {
                requests: Mutex::new(Vec::new()),
                class_fee_asset: class_fee_asset.clone(),
                ..MockBroker::default()
            });
            let (signer, home, mut claim, hash) = debiting_claim_fixture(&broker, class_fee_asset);
            claim.declared_fee = declared_fee.unwrap_or(bloom_broker_api::DeclaredFee::None);

            // Prepare: the fixture Broker accounts the claim and accepts the
            // derived limits instead of refusing VALUE_ASSET_NOT_ALLOWED.
            let first = flow_once(&signer, &home, &claim, &hash).await.unwrap();
            assert!(
                matches!(first, ExactPayloadOutcome::ApprovalRequired { .. }),
                "{name}"
            );

            // Sign: the retry re-runs accounting against the sealed terms and
            // completes the flow with a signature.
            let second = flow_once(&signer, &home, &claim, &hash).await.unwrap();
            assert_eq!(
                second,
                ExactPayloadOutcome::Signed(vec![7_u8; 65]),
                "{name}"
            );

            // The sealed approval carries exactly the claim's declared
            // debits plus the declared fee, summed per asset.
            let requests = broker.requests.lock().unwrap();
            let MachineBrokerRequest::SealedApprovalPrepare(prepared) = &requests[2] else {
                panic!("{name}: first attempt must prepare an approval");
            };
            let expected = |chain: &str, total: u128| bloom_broker_api::ValueLimit {
                asset: bloom_broker_api::AssetId {
                    chain: token(chain),
                    asset: "usdc".into(),
                },
                lifetime: bloom_broker_api::DecimalU256::parse(total.to_string()).unwrap(),
                rolling_windows: Vec::new(),
            };
            assert_eq!(
                prepared.terms.limits.value_limits,
                vec![
                    expected("hyperliquid", 5_000_000 + expected_fee_total),
                    expected("arbitrum", 2_500_000),
                ],
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn an_approval_whose_limits_are_empty_again_refuses_the_declaring_claim() {
        // Negative twin: drop_value_limits simulates the pre-#265 derivation
        // defect (approvals prepared with empty value_limits). The accounting
        // mirror must refuse the claim at prepare with the
        // VALUE_ASSET_NOT_ALLOWED denial, and nothing may sign.
        let broker = Arc::new(MockBroker {
            requests: Mutex::new(Vec::new()),
            drop_value_limits: true,
            ..MockBroker::default()
        });
        let (signer, home, claim, hash) = debiting_claim_fixture(&broker, None);
        // The ceremony still completes — with empty limits the defect only
        // surfaces when signing re-runs accounting against the sealed terms.
        let prepared = flow_once(&signer, &home, &claim, &hash).await.unwrap();
        assert!(matches!(
            prepared,
            ExactPayloadOutcome::ApprovalRequired { .. }
        ));
        let error = flow_once(&signer, &home, &claim, &hash).await.unwrap_err();
        assert!(
            format!("{error:?}").contains("VALUE_ASSET_NOT_ALLOWED"),
            "{error:?}"
        );
        // The refusal fired at the signing gate: the sign was dispatched and
        // refused before any signature existed (proven by the error above).
        assert!(
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|record| matches!(record, MachineBrokerRequest::SigningSign(_))),
            "the refusal must happen at signing, not before it"
        );
    }

    /// Released v0.4.0 Machine reads this same schema with
    /// `deny_unknown_fields`; state without a review digest must not carry
    /// the key, or a rollback cannot read it.
    #[test]
    fn digestless_state_omits_review_payload_digest() {
        let single = ExactSigningState {
            schema: STATE_SCHEMA.into(),
            action_id: "confirm".into(),
            wallet_id: token("wallet"),
            account_key_ref: None,
            operation_class: token("class"),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: digest(1),
            claimed_hash: digest(2),
            review_payload_digest: None,
            provenance_digest: digest(3),
            approval_operation_id: random_operation_id(),
            signing_operation_id: random_operation_id(),
            request_nonce: random_request_nonce(),
            issued_at_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(2),
            canonical_plan_facts_digest: digest(4),
            approval_id: None,
        };
        let batch = ExactBatchSigningState {
            schema: single.schema.clone(),
            action_id: single.action_id.clone(),
            wallet_id: single.wallet_id.clone(),
            account_key_ref: None,
            operation_class: single.operation_class.clone(),
            crypto_suite: single.crypto_suite,
            payload_digests: vec![digest(1)],
            claimed_hashes: vec![digest(2)],
            review_payload_digest: None,
            provenance_digest: digest(3),
            approval_operation_id: random_operation_id(),
            signing_operation_id: random_operation_id(),
            request_nonce: random_request_nonce(),
            issued_at_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(2),
            canonical_plan_facts_digest: digest(4),
            approval_id: None,
        };
        for value in [
            serde_json::to_value(&single).unwrap(),
            serde_json::to_value(&batch).unwrap(),
        ] {
            assert!(value.get("review_payload_digest").is_none(), "{value}");
        }
        let mut with_digest = single;
        with_digest.review_payload_digest = Some(digest(5));
        assert!(serde_json::to_value(&with_digest).unwrap()["review_payload_digest"].is_string());

        // The v0.4.x single-payload reader rejects a populated digest, so
        // compatibility-v1.toml declares Machine state 3 with downgrade floor 3.
        #[allow(dead_code)]
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ReleasedExactSigningState {
            schema: IgnoredAny,
            action_id: IgnoredAny,
            wallet_id: IgnoredAny,
            #[serde(default)]
            account_key_ref: Option<IgnoredAny>,
            operation_class: IgnoredAny,
            crypto_suite: IgnoredAny,
            payload_digest: IgnoredAny,
            claimed_hash: IgnoredAny,
            provenance_digest: IgnoredAny,
            approval_operation_id: IgnoredAny,
            signing_operation_id: IgnoredAny,
            request_nonce: IgnoredAny,
            issued_at_ms: IgnoredAny,
            expires_at_ms: IgnoredAny,
            canonical_plan_facts_digest: IgnoredAny,
            approval_id: IgnoredAny,
        }
        use serde::de::IgnoredAny;
        let mut digestless = with_digest.clone();
        digestless.review_payload_digest = None;
        serde_json::from_slice::<ReleasedExactSigningState>(
            &serde_json::to_vec(&digestless).unwrap(),
        )
        .unwrap();
        let error = serde_json::from_slice::<ReleasedExactSigningState>(
            &serde_json::to_vec(&with_digest).unwrap(),
        )
        .err()
        .unwrap();
        assert!(
            error.to_string().contains("review_payload_digest"),
            "{error}"
        );
    }

    async fn reusable_once(
        signer: &BrokerExactPayloadSigner,
        home: &tempfile::TempDir,
        base: &PetalUseClaim,
        payload: &[u8],
    ) -> Result<ExactPayloadBatchOutcome, ExactSigningError> {
        let hash = Digest32::from_bytes(Sha256::digest(payload).into());
        let claim = PetalUseClaim {
            payload_digest: {
                let mut digest = Sha256::new();
                digest.update(b"bloom.petal.payload-batch.v1\0");
                digest.update(1_u64.to_be_bytes());
                digest.update((payload.len() as u64).to_be_bytes());
                digest.update(payload);
                Digest32::from_bytes(digest.finalize().into())
            },
            ordered_hashes: vec![hash.clone()],
            ..base.clone()
        };
        signer
            .sign_or_prepare_reusable_petal_batch(
                &home.path().join("petal-reusable.json"),
                "reusable-action",
                "wallet",
                "fixture.withdraw",
                &[payload.to_vec()],
                &[hash],
                CryptoSuite::Secp256k1Sha256Recoverable,
                &serde_json::json!({"max_operations": 1}),
                &ProvenanceSubject::Petal {
                    package_hash: base.package_hash.clone(),
                    route: "withdraw/request".into(),
                },
                &claim,
                None,
            )
            .await
    }

    fn approval_of(outcome: &ExactPayloadBatchOutcome) -> Digest32 {
        match outcome {
            ExactPayloadBatchOutcome::ApprovalRequired { approval_id, .. } => approval_id.clone(),
            other => panic!("expected an approval, got {other:?}"),
        }
    }

    /// A reusable approval covers one operation. Once it has signed, the next
    /// payload prepares its own approval at once rather than failing against
    /// the spent one until its TTL runs out.
    #[tokio::test]
    async fn a_spent_reusable_approval_lets_the_next_payload_prepare_a_fresh_one() {
        let broker = Arc::new(MockBroker::default());
        let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);

        let first = approval_of(
            &reusable_once(&signer, &home, &claim, b"first")
                .await
                .unwrap(),
        );
        assert_eq!(
            reusable_once(&signer, &home, &claim, b"first")
                .await
                .unwrap(),
            ExactPayloadBatchOutcome::Signed(vec![vec![7_u8; 65]])
        );
        let next = approval_of(
            &reusable_once(&signer, &home, &claim, b"second")
                .await
                .unwrap(),
        );
        assert_ne!(first, next, "the next payload asks for its own approval");
        assert_eq!(
            reusable_once(&signer, &home, &claim, b"second")
                .await
                .unwrap(),
            ExactPayloadBatchOutcome::Signed(vec![vec![7_u8; 65]])
        );
    }

    /// A Petal that writes again while the owner's ceremony is still open,
    /// each time with rebuilt bytes, is told the approval is pending and
    /// nothing is recorded; the rebuild after the ceremony signs under the
    /// approval the owner completed instead of asking for another.
    #[tokio::test]
    async fn writes_during_an_open_ceremony_keep_the_approval_for_the_rebuild() {
        let broker = Arc::new(MockBroker {
            ceremony_open: AtomicBool::new(true),
            ..MockBroker::default()
        });
        let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);

        let approval = approval_of(
            &reusable_once(&signer, &home, &claim, b"build-1")
                .await
                .unwrap(),
        );
        for rebuild in [&b"build-2"[..], b"build-3"] {
            assert_eq!(
                approval_of(
                    &reusable_once(&signer, &home, &claim, rebuild)
                        .await
                        .unwrap()
                ),
                approval,
                "a write during the ceremony reports the same pending approval"
            );
        }
        broker.ceremony_open.store(false, Ordering::SeqCst);
        assert_eq!(
            reusable_once(&signer, &home, &claim, b"build-4")
                .await
                .unwrap(),
            ExactPayloadBatchOutcome::Signed(vec![vec![7_u8; 65]])
        );
        let requests = broker.requests.lock().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| matches!(r, MachineBrokerRequest::SealedApprovalPrepare(_)))
                .count(),
            1,
            "the owner approves once"
        );
        assert!(
            !requests
                .iter()
                .any(|r| matches!(r, MachineBrokerRequest::SigningSignBatch(req) if req.approval_id != approval)),
        );
    }

    /// A retry of the exact signing attempt recovers the Broker's retained
    /// result for the same operation. It never prepares a second approval.
    #[tokio::test]
    async fn a_retry_of_the_signed_attempt_recovers_its_result() {
        let broker = Arc::new(MockBroker::default());
        let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);

        reusable_once(&signer, &home, &claim, b"only")
            .await
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                reusable_once(&signer, &home, &claim, b"only")
                    .await
                    .unwrap(),
                ExactPayloadBatchOutcome::Signed(vec![vec![7_u8; 65]])
            );
        }
        let requests = broker.requests.lock().unwrap();
        let prepares = requests
            .iter()
            .filter(|r| matches!(r, MachineBrokerRequest::SealedApprovalPrepare(_)))
            .count();
        assert_eq!(prepares, 1);
        let signings = broker.signings.lock().unwrap();
        assert_eq!(signings.len(), 1, "Broker signs the operation only once");
        assert!(
            requests
                .iter()
                .any(|request| { matches!(request, MachineBrokerRequest::OperationStatus(_)) })
        );
    }

    #[tokio::test]
    async fn the_same_payload_with_a_different_claim_gets_a_fresh_approval() {
        let broker = Arc::new(MockBroker::default());
        let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);

        let first = approval_of(
            &reusable_once(&signer, &home, &claim, b"same")
                .await
                .unwrap(),
        );
        reusable_once(&signer, &home, &claim, b"same")
            .await
            .unwrap();

        let mut changed_claim = claim;
        changed_claim.nonce = RequestNonce::from_bytes([99; 16]);
        let next = approval_of(
            &reusable_once(&signer, &home, &changed_claim, b"same")
                .await
                .unwrap(),
        );
        assert_ne!(first, next);
        assert_eq!(broker.signings.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_lost_signing_response_is_recovered_without_reusing_it_for_new_bytes() {
        let broker = Arc::new(MockBroker {
            lose_sign_response_once: AtomicBool::new(true),
            ..MockBroker::default()
        });
        let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);

        reusable_once(&signer, &home, &claim, b"first")
            .await
            .unwrap();
        assert_eq!(
            reusable_once(&signer, &home, &claim, b"first")
                .await
                .unwrap(),
            ExactPayloadBatchOutcome::Signed(vec![vec![7_u8; 65]])
        );

        let main_state: serde_json::Value =
            serde_json::from_slice(&fs::read(home.path().join("petal-reusable.json")).unwrap())
                .unwrap();
        assert!(main_state.get("signed_payload_digests").is_none());
        assert!(home.path().join("petal-reusable.attempt.json").is_file());
        assert!(
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .any(|request| { matches!(request, MachineBrokerRequest::OperationStatus(_)) })
        );

        assert_eq!(
            reusable_once(&signer, &home, &claim, b"first")
                .await
                .unwrap(),
            ExactPayloadBatchOutcome::Signed(vec![vec![7_u8; 65]])
        );
        assert!(matches!(
            reusable_once(&signer, &home, &claim, b"second")
                .await
                .unwrap(),
            ExactPayloadBatchOutcome::ApprovalRequired { .. }
        ));
        assert_eq!(broker.signings.lock().unwrap().len(), 1);
    }

    fn prepares(broker: &MockBroker) -> usize {
        broker
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| matches!(r, MachineBrokerRequest::SealedApprovalPrepare(_)))
            .count()
    }

    fn reusable_state(home: &tempfile::TempDir) -> ReusablePetalBatchSigningState {
        serde_json::from_slice(&fs::read(home.path().join("petal-reusable.json")).unwrap()).unwrap()
    }

    /// The response to a signing call is lost and Broker cannot yet say what
    /// became of the operation. New bytes arriving now must not replace the
    /// attempt and ask the owner for a second approval beside an operation
    /// that may have signed; once Broker reports it final, they may.
    #[tokio::test]
    async fn new_bytes_wait_while_the_earlier_attempt_is_unresolved() {
        let broker = Arc::new(MockBroker {
            lose_sign_response_once: AtomicBool::new(true),
            operation_status_unavailable: AtomicBool::new(true),
            ..MockBroker::default()
        });
        let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);

        approval_of(
            &reusable_once(&signer, &home, &claim, b"first")
                .await
                .unwrap(),
        );
        reusable_once(&signer, &home, &claim, b"first")
            .await
            .unwrap_err();
        let before = reusable_state(&home);

        for _ in 0..2 {
            let error = reusable_once(&signer, &home, &claim, b"second")
                .await
                .unwrap_err();
            assert!(
                matches!(&error, ExactSigningError::OutcomeUnknown(m) if m.contains("has not settled")),
                "{error}"
            );
        }
        let after = reusable_state(&home);
        assert_eq!(after.signing_operation_id, before.signing_operation_id);
        assert_eq!(after.approval_id, before.approval_id);
        assert_eq!(prepares(&broker), 1, "the owner is not asked again");
        assert_eq!(broker.signings.lock().unwrap().len(), 1);

        // Broker can answer again: the earlier operation is final, so the new
        // bytes get their own approval.
        broker
            .operation_status_unavailable
            .store(false, Ordering::SeqCst);
        let next = approval_of(
            &reusable_once(&signer, &home, &claim, b"second")
                .await
                .unwrap(),
        );
        assert_ne!(Some(next), before.approval_id);
        assert_ne!(
            reusable_state(&home).signing_operation_id,
            before.signing_operation_id
        );
    }

    /// An operation Broker still reports in progress or quarantined is not
    /// final, and one it never journaled may yet arrive.
    #[tokio::test]
    async fn new_bytes_wait_for_an_operation_broker_has_not_finished() {
        for (state, journaled) in [
            (Some(OperationState::Dispatched), true),
            (Some(OperationState::Quarantined), true),
            (None, false),
        ] {
            let broker = Arc::new(MockBroker {
                lose_sign_response_once: AtomicBool::new(true),
                operation_status_unavailable: AtomicBool::new(true),
                ..MockBroker::default()
            });
            let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);
            approval_of(
                &reusable_once(&signer, &home, &claim, b"first")
                    .await
                    .unwrap(),
            );
            reusable_once(&signer, &home, &claim, b"first")
                .await
                .unwrap_err();
            if !journaled {
                broker.signings.lock().unwrap().clear();
            }
            *broker.operation_state.lock().unwrap() = state;
            broker
                .operation_status_unavailable
                .store(false, Ordering::SeqCst);

            let error = reusable_once(&signer, &home, &claim, b"second")
                .await
                .unwrap_err();
            assert!(
                matches!(&error, ExactSigningError::OutcomeUnknown(m) if m.contains("has not settled")),
                "{state:?}: {error}"
            );
            assert_eq!(prepares(&broker), 1, "{state:?}");
        }
    }

    #[tokio::test]
    async fn approval_expiry_does_not_replace_an_unresolved_attempt() {
        let broker = Arc::new(MockBroker {
            lose_sign_response_once: AtomicBool::new(true),
            operation_status_unavailable: AtomicBool::new(true),
            ..MockBroker::default()
        });
        let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);
        approval_of(
            &reusable_once(&signer, &home, &claim, b"first")
                .await
                .unwrap(),
        );
        reusable_once(&signer, &home, &claim, b"first")
            .await
            .unwrap_err();
        let mut before = reusable_state(&home);
        before.issued_at_ms = DecimalU64::new(0);
        before.expires_at_ms = DecimalU64::new(1);
        write_state(&home.path().join("petal-reusable.json"), &before).unwrap();

        for bytes in [b"first".as_slice(), b"second".as_slice()] {
            let error = reusable_once(&signer, &home, &claim, bytes)
                .await
                .unwrap_err();
            assert!(
                matches!(&error, ExactSigningError::OutcomeUnknown(_)),
                "{error}"
            );
            let after = reusable_state(&home);
            assert_eq!(after.signing_operation_id, before.signing_operation_id);
            assert_eq!(after.approval_id, before.approval_id);
        }
        assert_eq!(prepares(&broker), 1);
        assert_eq!(broker.signings.lock().unwrap().len(), 1);
    }

    // Exercise both exact entrypoints with an expired local timestamp. The
    // owner's ceremony and a committed-but-unacknowledged signature must each
    // retain their identity; TTL expiry is not evidence of a final refusal.
    #[tokio::test]
    async fn exact_expiry_preserves_ceremony_and_recovers_the_original_signature() {
        for batch in [false, true] {
            let broker = Arc::new(MockBroker::default());
            let (signer, home, claim, hash) = debiting_claim_fixture(&broker, None);
            let path = home.path().join("petal-exact.json");
            let attempt = || async {
                if batch {
                    signer
                        .sign_or_prepare_petal_batch(
                            &path,
                            "withdraw-action",
                            "wallet",
                            "fixture.withdraw",
                            &[b"exact withdraw payload".to_vec()],
                            std::slice::from_ref(&hash),
                            CryptoSuite::Secp256k1Sha256Recoverable,
                            &serde_json::json!({"asset": "USDC"}),
                            &ProvenanceSubject::Petal {
                                package_hash: claim.package_hash.clone(),
                                route: "withdraw/request".into(),
                            },
                            &claim,
                            Some(b"assurance"),
                            None,
                        )
                        .await
                        .map(|outcome| matches!(outcome, ExactPayloadBatchOutcome::Signed(_)))
                } else {
                    flow_once(&signer, &home, &claim, &hash)
                        .await
                        .map(|outcome| matches!(outcome, ExactPayloadOutcome::Signed(_)))
                }
            };
            assert!(!attempt().await.unwrap());
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            state["issued_at_ms"] = serde_json::json!("0");
            state["expires_at_ms"] = serde_json::json!("1");
            write_state(&path, &state).unwrap();
            broker.ceremony_open.store(true, Ordering::SeqCst);
            assert!(!attempt().await.unwrap());
            assert_eq!(prepares(&broker), 1);
            broker.ceremony_open.store(false, Ordering::SeqCst);
            broker.lose_sign_response_once.store(true, Ordering::SeqCst);
            broker
                .operation_status_unavailable
                .store(true, Ordering::SeqCst);
            assert!(matches!(
                attempt().await,
                Err(ExactSigningError::OutcomeUnknown(_))
            ));
            assert!(matches!(
                attempt().await,
                Err(ExactSigningError::OutcomeUnknown(_))
            ));
            assert_eq!(prepares(&broker), 1);
            assert_eq!(broker.signings.lock().unwrap().len(), 1);
            let after: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(after, state);
            broker
                .operation_status_unavailable
                .store(false, Ordering::SeqCst);
            assert!(attempt().await.unwrap());
            assert_eq!(broker.signings.lock().unwrap().len(), 1);
        }
    }

    /// A refusal with no lasting effect settles the attempt where it
    /// happens, so new bytes move on without asking Broker about it.
    #[tokio::test]
    async fn a_refused_attempt_lets_new_bytes_move_on() {
        let broker = Arc::new(MockBroker::default());
        let (signer, home, claim, _) = debiting_claim_fixture(&broker, None);
        approval_of(
            &reusable_once(&signer, &home, &claim, b"first")
                .await
                .unwrap(),
        );
        // Another operation already spent the approval, so Broker refuses
        // this one with its reservation released.
        let attempt_path = home.path().join("petal-reusable.attempt.json");
        broker.signings.lock().unwrap().push((
            reusable_state(&home).approval_id.unwrap(),
            random_operation_id(),
            digest(1),
            CryptoSuite::Secp256k1Sha256Recoverable,
        ));
        let refusal = reusable_once(&signer, &home, &claim, b"first")
            .await
            .unwrap_err();
        assert!(
            matches!(&refusal, ExactSigningError::Refused(m) if m.contains("already used")),
            "{refusal}"
        );
        let attempt: ReusablePetalBatchSigningAttempt =
            serde_json::from_slice(&fs::read(&attempt_path).unwrap()).unwrap();
        assert!(attempt.settled);

        broker
            .operation_status_unavailable
            .store(true, Ordering::SeqCst);
        approval_of(
            &reusable_once(&signer, &home, &claim, b"second")
                .await
                .unwrap(),
        );
        assert_eq!(prepares(&broker), 2);
    }

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }
}
