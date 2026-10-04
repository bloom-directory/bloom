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
            )
            .await;
        let _ = lock.unlock();
        result
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
                crypto_suite,
                canonical_plan_facts,
                Some(trusted_subject),
                Some((claim, claim_assurance_evidence)),
            )
            .await;
        let _ = lock.unlock();
        result
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
    ) -> Result<ExactPayloadOutcome, String> {
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
            Err(error) => return Err(format!("read exact signing state: {error}")),
        };
        if state.schema != STATE_SCHEMA
            || state.action_id != action_id
            || state.wallet_id != wallet_id
            || state.account_key_ref != self.account_key_ref
            || state.operation_class != operation_class_token
            || state.crypto_suite != crypto_suite
            || state.payload_digest != payload_digest
            || state.claimed_hash != claimed_hash
            || state.provenance_digest != provenance_digest
            || state.canonical_plan_facts_digest != canonical_plan_facts_digest
        {
            return Err("exact signing retry differs from its persisted operation identity".into());
        }
        let now = now_ms()?;
        if state.expires_at_ms.get() <= now {
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
        let mut request = ExactPayloadSignRequest {
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
            approval_value_limits,
        };
        let mut response = self.broker.sign_exact_payload(request.clone()).await;
        if response
            .as_ref()
            .is_err_and(|error| error.code == ProtocolErrorCode::OperationIdConflict)
            && state.approval_id.is_some()
        {
            // A prior attempt may have committed at Broker before its response
            // reached Machine. Keep the activated approval and immutable payload,
            // but never retry a signing reservation that Broker finalized.
            state.signing_operation_id = random_operation_id();
            request.signing_operation_id = state.signing_operation_id.clone();
            write_state(state_path, &state)?;
            response = self.broker.sign_exact_payload(request).await;
        }
        match response {
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
                let signature = result
                    .signatures
                    .first()
                    .ok_or_else(|| "Broker returned no exact signature".to_owned())?;
                if result.signatures.len() != 1 {
                    return Err("Broker returned an unexpected exact signature count".into());
                }
                Ok(ExactPayloadOutcome::Signed(signature.bytes.decode()))
            }
            Err(error) => {
                tracing::error!(code = ?error.code, message = %error.message, action_id, "petal exact signing failed");
                Err(error.to_string())
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
    ) -> Result<ExactPayloadBatchOutcome, String> {
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
    ) -> Result<ExactPayloadBatchOutcome, String> {
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
    ) -> Result<ExactPayloadBatchOutcome, String> {
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
            Err(error) => return Err(format!("read reusable batch signing state: {error}")),
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
            Err(error) => return Err(format!("read reusable signing attempt: {error}")),
        };
        if previous_attempt
            .as_ref()
            .is_some_and(|attempt| attempt.schema != REUSABLE_ATTEMPT_SCHEMA)
        {
            return Err("reusable signing attempt schema is unsupported".into());
        }
        let now = now_ms()?;
        let expired = state.expires_at_ms.get() <= now;
        let different_request = previous_attempt.as_ref().filter(|attempt| {
            attempt.signing_operation_id == state.signing_operation_id
                && attempt.request_digest != request_digest
        });
        if let Some(attempt) = different_request
            && !attempt.settled
            && !expired
        {
            // New bytes replace the attempt's identity, and with it the
            // approval. Do that only once the earlier operation is final:
            // while it may still sign, a fresh approval would put a second
            // operation beside it.
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
        if let Some(approval_id) = state.approval_id.clone()
            && let Ok(status) = self.broker.approval_status(approval_id.clone()).await
            && status.state == ApprovalLifecycleState::AwaitingCeremony
            && let (Some(ceremony_url), Some(expires)) =
                (status.ceremony_url, status.ceremony_expires_at_ms)
        {
            return Ok(ExactPayloadBatchOutcome::ApprovalRequired {
                approval_id,
                ceremony_url,
                ceremony_expires_at_ms: expires.get(),
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
        let settled = match &response {
            Ok(_) => true,
            Err(error) => matches!(
                error.durable_effect,
                DurableEffect::None | DurableEffect::ReservationReleased
            ),
        };
        if let Some(mut attempt) = attempt
            && settled
        {
            attempt.settled = true;
            write_state(&attempt_path, &attempt)?;
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
                    return Err(
                        "Broker returned an unexpected reusable batch signature count".into(),
                    );
                }
                Ok(ExactPayloadBatchOutcome::Signed(
                    result
                        .signatures
                        .iter()
                        .map(|signature| signature.bytes.decode())
                        .collect(),
                ))
            }
            Err(error) => Err(error.to_string()),
        }
    }

    /// Succeed only when Broker reports the signing operation in a final
    /// state. A response that never arrived, an operation still moving, a
    /// quarantined one, or a status Broker cannot give all leave it open.
    async fn require_attempt_final(&self, operation_id: &OperationId) -> Result<(), String> {
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
            Ok(status) => Err(format!(
                "{unsettled} (Broker reports {:?}); retry the same request or wait for it to finish",
                status.state
            )),
            Err(error) => Err(format!(
                "{unsettled} and its outcome is unknown ({error}); retry the same request or wait for it to resolve"
            )),
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
    ) -> Result<ExactPayloadBatchOutcome, String> {
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
            Err(error) => return Err(format!("read exact batch signing state: {error}")),
        };
        if state.schema != STATE_SCHEMA
            || state.action_id != action_id
            || state.wallet_id != wallet_id
            || state.account_key_ref != self.account_key_ref
            || state.operation_class != operation_class_token
            || state.crypto_suite != crypto_suite
            || state.payload_digests != payload_digests
            || state.claimed_hashes != claimed_hashes
            || state.provenance_digest != provenance_digest
            || state.canonical_plan_facts_digest != canonical_plan_facts_digest
        {
            return Err(
                "exact batch signing retry differs from its persisted operation identity".into(),
            );
        }
        let now = now_ms()?;
        if state.expires_at_ms.get() <= now {
            state.approval_operation_id = random_operation_id();
            state.signing_operation_id = random_operation_id();
            state.request_nonce = random_request_nonce();
            state.issued_at_ms = DecimalU64::new(now);
            state.expires_at_ms = DecimalU64::new(now.saturating_add(APPROVAL_TTL_MS));
            state.approval_id = None;
        }
        write_state(state_path, &state)?;
        let mut request = ExactPayloadBatchSignRequest {
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
        let mut response = self.broker.sign_exact_payload_batch(request.clone()).await;
        if response
            .as_ref()
            .is_err_and(|error| error.code == ProtocolErrorCode::OperationIdConflict)
            && state.approval_id.is_some()
        {
            // A prior sign attempt may have durably finalized its reservation
            // before returning a retryable error. Preserve the completed
            // approval and exact payload identity, but never reuse that
            // finalized signing operation ID.
            state.signing_operation_id = random_operation_id();
            request.signing_operation_id = state.signing_operation_id.clone();
            write_state(state_path, &state)?;
            response = self.broker.sign_exact_payload_batch(request).await;
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
                    return Err("Broker returned an unexpected exact batch signature count".into());
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
                Err(error.to_string())
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
        conflict_sign_once: AtomicBool,
        lose_batch_response_once: AtomicBool,
        /// Simulates the pre-#265 derivation defect for the negative twin: the
        /// approval presents no `value_limits` even though the claim declares
        /// value, so the accounting mirror must refuse it.
        drop_value_limits: bool,
        /// The fee asset the provenance catalog marks for the operation class
        /// under test, mirroring `account_declared_values`' fee matching.
        class_fee_asset: Option<bloom_broker_api::ProvenanceFeeAsset>,
        /// Batch signings so far, as (approval, operation, operation digest).
        /// Like the Broker, one approval admits one signing operation, and a
        /// signing operation id is bound to its digest.
        batch_signings: Mutex<Vec<(Digest32, OperationId, Digest32)>>,
        /// While set, every prepared approval is still awaiting the owner's
        /// ceremony: it reports so, and the Broker refuses to sign under it.
        ceremony_open: AtomicBool,
        /// While set, operation status cannot be read.
        operation_status_unavailable: AtomicBool,
        /// Reported in place of a retained operation's final state.
        operation_state: Mutex<Option<OperationState>>,
    }

    impl MockBroker {
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
                        if self.conflict_sign_once.swap(false, Ordering::SeqCst) {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::OperationIdConflict,
                                "simulated finalized signing reservation",
                            ));
                        }
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
                    MachineBrokerRequest::SealedApprovalStatus(request) => Ok(
                        MachineBrokerResponse::SealedApprovalStatus(ApprovalPublicStatus {
                            approval_id: request.id,
                            wallet_id: token("wallet"),
                            state: if self.ceremony_open.load(Ordering::SeqCst) {
                                ApprovalLifecycleState::AwaitingCeremony
                            } else {
                                ApprovalLifecycleState::Active
                            },
                            effective_claim_assurance: None,
                            ceremony_url: Some("http://localhost:18734/ceremony/test".into()),
                            ceremony_expires_at_ms: Some(DecimalU64::new(u64::MAX / 2)),
                        }),
                    ),
                    MachineBrokerRequest::SigningSignBatch(request) => {
                        if self.ceremony_open.load(Ordering::SeqCst) {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::ClaimInvalid,
                                "approval is not active",
                            ));
                        }
                        let mut signings = self.batch_signings.lock().unwrap();
                        for (approval, operation, operation_digest) in signings.iter() {
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
                            if *approval == request.approval_id
                                && *operation != request.operation_id
                            {
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
                        ));
                        if self.lose_batch_response_once.swap(false, Ordering::SeqCst) {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::ServiceUnavailable,
                                "simulated lost response after signing committed",
                            ));
                        }
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
                        let signings = self.batch_signings.lock().unwrap();
                        // Broker's own answer for an operation it never journaled.
                        let (_, operation_id, operation_digest) = signings
                            .iter()
                            .find(|(_, operation, _)| *operation == request.operation_id)
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
                                crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
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
            conflict_sign_once: AtomicBool::new(false),
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
        broker.conflict_sign_once.store(true, Ordering::SeqCst);
        let second = signer
            .sign_or_prepare(
                &state,
                "action-1",
                "wallet",
                "transaction.confirm",
                payload,
                hash,
                &serde_json::json!({"amount": "1"}),
            )
            .await
            .unwrap();
        assert_eq!(second, ExactPayloadOutcome::Signed(vec![7_u8; 65]));
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
        assert_ne!(signing_operation_ids[0], signing_operation_ids[1]);
        let persisted: ExactSigningState =
            serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
        assert_eq!(persisted.signing_operation_id, signing_operation_ids[1]);
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

    #[tokio::test]
    async fn petal_retry_preserves_the_requested_crypto_suite_through_prepare_and_sign() {
        let broker = Arc::new(MockBroker {
            requests: Mutex::new(Vec::new()),
            conflict_sign_once: AtomicBool::new(false),
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
            )
            .await
            .unwrap_err();
        assert!(error.contains("persisted"), "{error}");
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
                        )
                        .await
                };
                if should_reject {
                    assert!(outcome.unwrap_err().contains("persisted"));
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
        let MachineBrokerRequest::SigningSign(signed) = &requests[5] else {
            panic!("approved retry must sign");
        };
        assert_eq!(signed.crypto_suite, CryptoSuite::Secp256k1Sha256Recoverable);
    }

    /// Builds the shared fixture: a petal exact signer whose provenance
    /// catalog marks one class with the scenario's fee asset.
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
                        operation_class: token("hyperliquid.withdraw"),
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
            operation_class: token("hyperliquid.withdraw"),
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
    ) -> Result<ExactPayloadOutcome, String> {
        let package_hash = claim.package_hash.clone();
        signer
            .sign_or_prepare_petal(
                &home.path().join("petal-exact.json"),
                "withdraw-action",
                "wallet",
                "hyperliquid.withdraw",
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
                conflict_sign_once: AtomicBool::new(false),
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
            conflict_sign_once: AtomicBool::new(false),
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
        assert!(error.contains("VALUE_ASSET_NOT_ALLOWED"), "{error}");
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

    async fn reusable_once(
        signer: &BrokerExactPayloadSigner,
        home: &tempfile::TempDir,
        base: &PetalUseClaim,
        payload: &[u8],
    ) -> Result<ExactPayloadBatchOutcome, String> {
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
                "hyperliquid.withdraw",
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
        let signings = broker.batch_signings.lock().unwrap();
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
        assert_eq!(broker.batch_signings.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_lost_signing_response_is_recovered_without_reusing_it_for_new_bytes() {
        let broker = Arc::new(MockBroker {
            lose_batch_response_once: AtomicBool::new(true),
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
        assert_eq!(broker.batch_signings.lock().unwrap().len(), 1);
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
            lose_batch_response_once: AtomicBool::new(true),
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
            assert!(error.contains("has not settled"), "{error}");
        }
        let after = reusable_state(&home);
        assert_eq!(after.signing_operation_id, before.signing_operation_id);
        assert_eq!(after.approval_id, before.approval_id);
        assert_eq!(prepares(&broker), 1, "the owner is not asked again");
        assert_eq!(broker.batch_signings.lock().unwrap().len(), 1);

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
                lose_batch_response_once: AtomicBool::new(true),
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
                broker.batch_signings.lock().unwrap().clear();
            }
            *broker.operation_state.lock().unwrap() = state;
            broker
                .operation_status_unavailable
                .store(false, Ordering::SeqCst);

            let error = reusable_once(&signer, &home, &claim, b"second")
                .await
                .unwrap_err();
            assert!(error.contains("has not settled"), "{state:?}: {error}");
            assert_eq!(prepares(&broker), 1, "{state:?}");
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
        broker.batch_signings.lock().unwrap().push((
            reusable_state(&home).approval_id.unwrap(),
            random_operation_id(),
            digest(1),
        ));
        let refusal = reusable_once(&signer, &home, &claim, b"first")
            .await
            .unwrap_err();
        assert!(refusal.contains("already used"), "{refusal}");
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
