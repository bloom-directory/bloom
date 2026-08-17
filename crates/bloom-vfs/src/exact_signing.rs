//! Durable Machine orchestration for the existing exact Broker signing flow.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bloom_broker_api::{
    CryptoSuite, DecimalU64, Digest32, OperationId, PetalUseClaim, ProtocolErrorCode,
    ProvenanceCatalog, ProvenanceSubject, RequestNonce, Token,
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
const APPROVAL_TTL_MS: u64 = 5 * 60 * 1000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct BrokerExactPayloadSigner {
    broker: MachineBrokerClient,
    provenance_catalog: ProvenanceCatalog,
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

impl BrokerExactPayloadSigner {
    pub fn new(broker: MachineBrokerClient, provenance_catalog: ProvenanceCatalog) -> Self {
        Self {
            broker,
            provenance_catalog,
        }
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
            petal_use_claim: petal_claim.map(|(claim, _)| claim.clone()),
            claim_assurance_evidence: petal_claim
                .and_then(|(_, evidence)| evidence.map(<[u8]>::to_vec)),
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
            petal_use_claim: Some(claim.clone()),
            claim_assurance_evidence: claim_assurance_evidence.map(<[u8]>::to_vec),
        };
        match self.broker.sign_reusable_petal_payload_batch(request).await {
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
        ApprovalPrepareState, Base64UrlBytes, KeyPublic, KeyRef, KeyRole, KeySpec,
        MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, NormalizedSignature,
        PROVENANCE_CATALOG_SCHEMA, ProtocolError, ProtocolErrorCode, ProvenanceOperationClass,
        ProvenanceRecord, SealedApprovalPrepareResponse, ServiceFuture, SigningResult,
        WalletPublic,
    };

    struct MockBroker {
        requests: Mutex<Vec<MachineBrokerRequest>>,
        conflict_sign_once: AtomicBool,
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
                            root_key_ref: test_key_ref(),
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
                    MachineBrokerRequest::SigningSign(request) => {
                        if self.conflict_sign_once.swap(false, Ordering::SeqCst) {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::OperationIdConflict,
                                "simulated finalized signing reservation",
                            ));
                        }
                        Ok(MachineBrokerResponse::SigningSign(SigningResult {
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
            declared_debits: Vec::new(),
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

        let requests = broker.requests.lock().unwrap();
        let MachineBrokerRequest::SealedApprovalPrepare(prepared) = &requests[2] else {
            panic!("first exact attempt must prepare approval");
        };
        assert_eq!(
            prepared.terms.allowed_crypto_suites,
            [CryptoSuite::Secp256k1Sha256Recoverable]
        );
        let MachineBrokerRequest::SigningSign(signed) = &requests[5] else {
            panic!("approved retry must sign");
        };
        assert_eq!(signed.crypto_suite, CryptoSuite::Secp256k1Sha256Recoverable);
    }

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }
}
