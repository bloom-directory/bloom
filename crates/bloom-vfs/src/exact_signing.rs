//! Durable Machine orchestration for the existing exact Broker signing flow.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bloom_broker_api::{
    AssetId, CryptoSuite, DecimalU64, DecimalU256, DeclaredFee, Digest32, OperationId,
    PetalUseClaim, ProtocolErrorCode, ProvenanceCatalog, ProvenanceSubject, RequestNonce, Token,
    ValueLimit,
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
    /// The scope this request is made in: package, route, wallet, operation
    /// class and account key, as Machine derived them.
    scope: Option<String>,
    /// The request id of an earlier attempt the caller says it has given up.
    supersedes: Option<String>,
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

/// The failure of a request that named an approval, classified by Broker's
/// own error contract: only a final refusal with no lasting effect proves no
/// signature exists. `prior_attempt_stands` marks a retry after an earlier
/// attempt Broker reported as finalized.
fn signing_error(
    error: bloom_broker_api::ProtocolError,
    signing: bool,
    prior_attempt_stands: bool,
) -> ExactSigningError {
    let refused = error.retry == bloom_broker_api::RetryClass::Never
        && matches!(
            error.durable_effect,
            bloom_broker_api::DurableEffect::None
                | bloom_broker_api::DurableEffect::ReservationReleased
        );
    if signing && (prior_attempt_stands || !refused) {
        ExactSigningError::OutcomeUnknown(error.to_string())
    } else {
        ExactSigningError::Refused(error.to_string())
    }
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

/// What Machine knows about one exact request beyond the operation state it
/// already kept: the scope the request was made in, which logical operation it
/// belongs to, whether a signing call that could have produced a signature was
/// ever issued for it, and whether it has been safely given up.
///
/// A separate record, not new fields on [`ExactSigningState`], because that
/// state shipped in v0.2.0 and v0.2.1 with `deny_unknown_fields`: a binary from
/// either release must still be able to read back a state file this one wrote.
/// It ignores a file it does not know about.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactOperationRecord {
    schema: String,
    /// Package, route, wallet, operation class and account key. Machine will
    /// only let a request give up an attempt made in its own scope.
    scope: String,
    /// The request id of the first attempt in this logical operation. Every
    /// rebuild inherits it, so the operation survives a change of bytes.
    operation_root: String,
    /// Set before any signing call that carries an approval id, and never
    /// cleared. While false, no signature can exist for this attempt.
    #[serde(default)]
    signing_may_have_started: bool,
    /// Every signing operation id this attempt has used, recorded before the
    /// call that uses it and never removed. The operation state rotates its id
    /// — when its own lifetime expires, and when Broker reports it has already
    /// finalized a reservation — and the rotated-away id is the only handle
    /// Broker has on whatever that call did. Asking about the current id alone
    /// would read "Broker has never heard of this" as "nothing signed".
    #[serde(default)]
    signing_operations: Vec<OperationId>,
    /// When this attempt was proven safe to abandon. Kept so a retry of the
    /// same replacement is idempotent without deleting the evidence needed to
    /// reconcile it.
    #[serde(default)]
    released_at_ms: Option<DecimalU64>,
}

const OPERATION_SCHEMA: &str = "bloom.machine_exact_operation.v1";

/// What Machine established about the attempt a request asks to replace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Supersession {
    /// Proven to have produced no signature, and it can no longer produce one.
    Released,
    /// Already proven, by an earlier attempt at the same replacement.
    AlreadyReleased,
    /// It may already have signed, or may still sign. The replacement must not
    /// proceed, and the operation's outcome is unresolved.
    PriorMaySign(String),
    /// Machine could not establish either, so it must not authorize anything.
    Unknown(String),
    /// The request may not replace this attempt at all. Nothing was changed.
    Invalid(String),
}

/// What a stored approval's ceremony check found before signing with it.
enum StoredApprovalCeremony {
    /// Still waiting on its owner: return the same pending approval.
    AwaitingOwner {
        ceremony_url: String,
        ceremony_expires_at_ms: u64,
    },
    /// Past pending (active, expired, revoked, ...): proceed to sign
    /// and let Broker report the approval's fate.
    NoLongerPending,
    /// The check itself could not confirm the ceremony: signing now
    /// would risk reporting a refusal for a live approval and dropping
    /// it. Wait for a retry instead of signing.
    Unconfirmed,
}

impl BrokerExactPayloadSigner {
    pub fn new(broker: MachineBrokerClient, provenance_catalog: ProvenanceCatalog) -> Self {
        Self {
            broker,
            provenance_catalog,
            account_key_ref: None,
            scope: None,
            supersedes: None,
        }
    }

    pub fn with_account_key(mut self, key: Option<bloom_broker_api::KeyRef>) -> Self {
        self.account_key_ref = key;
        self
    }

    /// The scope Machine derived for this request, and the earlier attempt in
    /// it — if any — that the caller says it has given up. Both come from
    /// Machine: `supersedes` is the caller's assertion, but which requests it
    /// can name is not.
    pub fn in_scope(mut self, scope: String, supersedes: Option<String>) -> Self {
        self.scope = Some(scope);
        self.supersedes = supersedes;
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
        let released = match self.supersedes.clone() {
            None => Ok(()),
            Some(superseded) if superseded == action_id => Err(ExactSigningError::Refused(
                "an exact request cannot supersede itself".into(),
            )),
            Some(superseded) => match self.release_superseded(parent, &superseded).await {
                Supersession::Released | Supersession::AlreadyReleased => Ok(()),
                // The replacement must not become eligible to sign while the
                // attempt it replaces is unresolved. Both of these are outcomes
                // the caller retries, and neither rebuilds.
                Supersession::PriorMaySign(reason) | Supersession::Unknown(reason) => {
                    Err(ExactSigningError::OutcomeUnknown(format!(
                        "the attempt this replaces is unresolved: {reason}"
                    )))
                }
                // The reason stays host-side. A guest that could tell "no such
                // request" from "a request in another scope" would have a way
                // to probe for other Petals' artifacts, and the two are one
                // refusal as far as the caller is concerned.
                Supersession::Invalid(reason) => {
                    tracing::warn!(superseded, reason, "exact supersession refused");
                    Err(ExactSigningError::Refused(
                        "approval artifact does not match the exact Petal operation".into(),
                    ))
                }
            },
        };
        if let Err(error) = released {
            let _ = lock.unlock();
            return Err(error);
        }
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

    /// The ceremony of a stored approval. A retry in the awaiting state
    /// returns the same pending approval: signing would fail with
    /// CLAIM_INVALID, which callers treat as a final refusal. A Broker
    /// without the status method predates the pending check; keep its
    /// legacy path and let signing report.
    async fn stored_approval_ceremony(&self, approval_id: &Digest32) -> StoredApprovalCeremony {
        let status = match self.broker.approval_status(approval_id.clone()).await {
            Ok(status) => status,
            Err(error)
                if matches!(
                    error.code,
                    ProtocolErrorCode::UnknownMethod | ProtocolErrorCode::UnknownField
                ) =>
            {
                return StoredApprovalCeremony::NoLongerPending;
            }
            Err(_) => return StoredApprovalCeremony::Unconfirmed,
        };
        if !matches!(
            status.state,
            bloom_broker_api::ApprovalLifecycleState::Prepared
                | bloom_broker_api::ApprovalLifecycleState::AwaitingCeremony
        ) {
            return StoredApprovalCeremony::NoLongerPending;
        }
        match (status.ceremony_url, status.ceremony_expires_at_ms) {
            (Some(ceremony_url), Some(ceremony_expires_at_ms)) => {
                StoredApprovalCeremony::AwaitingOwner {
                    ceremony_url,
                    ceremony_expires_at_ms: ceremony_expires_at_ms.get(),
                }
            }
            // Broker reports the approval pending but offers no ceremony to
            // await: the lookup may have missed a live ceremony, and signing
            // now would report a refusal for it. Wait instead of dropping it.
            _ => StoredApprovalCeremony::Unconfirmed,
        }
    }

    /// Give up the approval a caller has superseded, so the wallet is free for
    /// the one it is about to ask for — but only once Machine has established
    /// that doing so cannot strand or duplicate a signature.
    ///
    /// A caller that rebuilds a transaction — a Solana trade whose blockhash
    /// expired before the owner answered — asks to sign different bytes under
    /// a different request id. Nothing about that abandonment reaches Broker on
    /// its own, so the old approval's ceremony stays live for its full TTL, and
    /// a wallet holds one live ceremony: the rebuilt transaction cannot even be
    /// offered until it expires.
    ///
    /// The order matters. Revoking first is what makes the answer stable: after
    /// it, the approval can never sign, so whatever Broker then says about the
    /// attempt's signing operation is final. Asking before revoking would only
    /// describe a moment that the owner can still move past — they may complete
    /// the ceremony between the two calls, which is why an earlier `Prepared`
    /// or `AwaitingCeremony` reading is never on its own taken as proof that
    /// nothing signed.
    async fn release_superseded(&self, state_dir: &Path, superseded: &str) -> Supersession {
        let Some(scope) = self.scope.as_deref() else {
            return Supersession::Invalid("this request has no derived scope".into());
        };
        let record_path = state_dir.join(format!("{superseded}.op.json"));
        let record = match fs::read(&record_path) {
            Ok(bytes) => match serde_json::from_slice::<ExactOperationRecord>(&bytes) {
                Ok(record) if record.schema == OPERATION_SCHEMA => record,
                _ => {
                    return Supersession::Unknown(
                        "the superseded request's record is unreadable".into(),
                    );
                }
            },
            // Machine never removes this record, so its absence does not mean
            // the attempt was released. It means Machine has no attempt by that
            // name, and cannot say what became of one.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Supersession::Unknown(
                    "no exact request by that id was prepared here".into(),
                );
            }
            Err(error) => {
                return Supersession::Unknown(format!(
                    "the superseded request's record could not be read: {error}"
                ));
            }
        };
        if record.scope != scope {
            return Supersession::Invalid(
                "the superseded request belongs to another package, route, wallet, operation class or key"
                    .into(),
            );
        }
        if record.released_at_ms.is_some() {
            return Supersession::AlreadyReleased;
        }
        let state = match fs::read(state_dir.join(format!("{superseded}.json"))) {
            Ok(bytes) => match serde_json::from_slice::<ExactSigningState>(&bytes) {
                Ok(state) => state,
                Err(error) => {
                    return Supersession::Unknown(format!(
                        "the superseded request's state is malformed: {error}"
                    ));
                }
            },
            Err(error) => {
                return Supersession::Unknown(format!(
                    "the superseded request's state could not be read: {error}"
                ));
            }
        };

        // Whether the attempt could have signed comes first, and revoking comes
        // only after. An attempt whose outcome is open is left exactly as it
        // is: revoking it would take away the one recovery its caller has —
        // retrying the same bytes under the same approval, which can only
        // reproduce the same signature — and would buy nothing, because a
        // signature that already exists is not undone by revoking anything.
        //
        // Nothing can sign in the meantime. Machine is the only caller that
        // signs with these approvals and it is serialized, so the owner
        // completing a ceremony in this window activates an approval without
        // producing a signature, and the revoke below then ends it for good.
        if record.signing_may_have_started {
            // Every id the attempt ever used, not just the one its state
            // happens to hold now. An attempt whose signing call was recorded
            // but whose id was not kept cannot be answered for at all.
            if record.signing_operations.is_empty() {
                return Supersession::PriorMaySign(
                    "the superseded attempt issued a signing call under an id that was not kept"
                        .into(),
                );
            }
            for operation_id in &record.signing_operations {
                match self.broker.operation_status(operation_id.clone()).await {
                    // Broker never received a signing request under this id.
                    Err(error) if error.code == ProtocolErrorCode::ApprovalNotFound => {}
                    Ok(status)
                        if matches!(
                            status.state,
                            bloom_broker_api::OperationState::Cancelled
                                | bloom_broker_api::OperationState::Denied
                        ) => {}
                    Ok(status) => {
                        return Supersession::PriorMaySign(format!(
                            "a signing operation of the superseded attempt is {:?}",
                            status.state
                        ));
                    }
                    Err(error) => {
                        return Supersession::Unknown(format!(
                            "a signing operation of the superseded attempt could not be read: {:?}",
                            error.code
                        ));
                    }
                }
            }
        }

        // Nothing signed, and nothing can. If no approval was ever prepared
        // there is also nothing at Broker to end.
        let Some(approval_id) = state.approval_id.clone() else {
            return self.mark_released(&record_path, record);
        };
        if let Err(error) = self
            .broker
            .revoke_approval(bloom_broker_api::RevokeRequest {
                operation_id: random_operation_id(),
                approval_id,
                wallet_id: state.wallet_id.clone(),
                reason: "superseded: the caller rebuilt this operation".into(),
            })
            .await
        {
            tracing::warn!(
                code = ?error.code,
                message = %error.message,
                action_id = %state.action_id,
                "revoking a superseded exact approval failed"
            );
            return Supersession::Unknown(format!(
                "the superseded approval could not be revoked: {:?}",
                error.code
            ));
        }
        self.mark_released(&record_path, record)
    }

    /// Record that an attempt was proven safe to abandon. The record stays on
    /// disk: a later retry of the same replacement reads it instead of asking
    /// Broker again, and nothing needed to reconcile the attempt is removed.
    fn mark_released(&self, path: &Path, mut record: ExactOperationRecord) -> Supersession {
        record.released_at_ms = Some(DecimalU64::new(now_ms().unwrap_or(0)));
        match write_state(path, &record) {
            Ok(()) => Supersession::Released,
            // The approval is already revoked, so nothing can sign; but without
            // the record a retry cannot tell that, so report it as unresolved
            // rather than let a replacement through on an unrecorded release.
            Err(error) => Supersession::Unknown(format!(
                "the superseded request's release could not be recorded: {error}"
            )),
        }
    }

    /// Open or start this request's operation record. A request that supersedes
    /// an earlier attempt inherits that attempt's operation root, so the
    /// logical operation survives every change of bytes and every restart.
    ///
    /// `adopted` carries the signing operation id of a request that already had
    /// durable state when this Machine first saw it — one written before this
    /// record existed, or by another binary. Machine cannot know whether such a
    /// request issued a signing call, so it assumes it did, and takes the id
    /// from its state as the only handle Broker could have on it.
    fn operation_record(
        &self,
        state_dir: &Path,
        request_id: &str,
        adopted: Option<&OperationId>,
    ) -> Result<ExactOperationRecord, String> {
        let path = state_dir.join(format!("{request_id}.op.json"));
        let scope = self
            .scope
            .clone()
            .ok_or_else(|| "this request has no derived scope".to_owned())?;
        match fs::read(&path) {
            Ok(bytes) => {
                let record: ExactOperationRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("read exact operation record: {error}"))?;
                if record.schema != OPERATION_SCHEMA || record.scope != scope {
                    return Err("exact operation record does not match this request".into());
                }
                Ok(record)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let operation_root = match self.supersedes.as_deref() {
                    Some(superseded) => {
                        let previous = state_dir.join(format!("{superseded}.op.json"));
                        fs::read(&previous)
                            .ok()
                            .and_then(|bytes| {
                                serde_json::from_slice::<ExactOperationRecord>(&bytes).ok()
                            })
                            .map_or_else(|| request_id.to_owned(), |record| record.operation_root)
                    }
                    None => request_id.to_owned(),
                };
                let record = ExactOperationRecord {
                    schema: OPERATION_SCHEMA.into(),
                    scope,
                    operation_root,
                    signing_may_have_started: adopted.is_some(),
                    signing_operations: adopted.into_iter().cloned().collect(),
                    released_at_ms: None,
                };
                write_state(&path, &record)?;
                Ok(record)
            }
            Err(error) => Err(format!("read exact operation record: {error}")),
        }
    }

    /// Record that a call which could produce a signature is about to be made,
    /// and under which id. Both before the call, never after: a response that
    /// never arrives must still leave Broker's handle on it behind.
    fn record_signing_attempt(
        &self,
        state_path: &Path,
        request_id: &str,
        operation_id: &OperationId,
    ) -> Result<(), String> {
        let (Some(state_dir), true) = (state_path.parent(), self.scope.is_some()) else {
            return Ok(());
        };
        let mut record = self.operation_record(state_dir, request_id, None)?;
        if record.signing_may_have_started && record.signing_operations.contains(operation_id) {
            return Ok(());
        }
        record.signing_may_have_started = true;
        if !record.signing_operations.contains(operation_id) {
            record.signing_operations.push(operation_id.clone());
        }
        write_state(&state_dir.join(format!("{request_id}.op.json")), &record)
    }

    /// Whether this request has already been given up. A released request is
    /// finished: its approval was revoked and another request was allowed to
    /// take its place on the strength of that. Nothing may revive it — and the
    /// operation state's own lifetime expiring is exactly such a revival, since
    /// that path clears the approval id and prepares a fresh one.
    fn released(&self, state_path: &Path, request_id: &str) -> bool {
        let Some(state_dir) = state_path.parent() else {
            return false;
        };
        fs::read(state_dir.join(format!("{request_id}.op.json")))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ExactOperationRecord>(&bytes).ok())
            .is_some_and(|record| record.released_at_ms.is_some())
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
        let plan_bytes = serde_jcs::to_vec(canonical_plan_facts)
            .map_err(|error| format!("canonicalize exact signing facts: {error}"))?;
        let canonical_plan_facts_digest = Digest32::from_bytes(Sha256::digest(plan_bytes).into());
        let wallet_id = Token::new(wallet.to_owned()).map_err(|error| error.to_string())?;

        // A request that was given up is finished. Checked before anything else
        // touches its state, because the lifetime-expiry path below would
        // otherwise clear its approval id and prepare a second one for bytes
        // another request has already replaced.
        if self.released(state_path, action_id) {
            return Err(ExactSigningError::Refused(
                "this exact request was given up and replaced; it cannot be prepared again".into(),
            ));
        }
        // Whether this request already had durable state before this call.
        // A request Machine is meeting for the first time with state on disk
        // was prepared by something else, and nothing here can say what it did.
        let adopting_existing_state = state_path.exists();
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
            Err(error) => return Err(format!("read exact signing state: {error}").into()),
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
        // Every exact Petal request opens its operation record before it asks
        // Broker for anything, so a later replacement always has something to
        // read, and it inherits the operation root of an attempt it supersedes,
        // which is what carries the logical operation across a change of bytes
        // and across a restart.
        //
        // From the state exactly as persisted, and before the expiry path below
        // rewrites any of it. For a request this Machine did not prepare, the
        // signing operation id that state carries is the only handle Broker has
        // on whatever its previous call did, and expiry replaces it in this
        // very call.
        if self.scope.is_some()
            && let Some(record_dir) = state_path.parent()
        {
            self.operation_record(
                record_dir,
                action_id,
                adopting_existing_state
                    .then(|| state.signing_operation_id.clone())
                    .as_ref(),
            )?;
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
        if let Some(approval_id) = state.approval_id.clone() {
            match self.stored_approval_ceremony(&approval_id).await {
                StoredApprovalCeremony::AwaitingOwner {
                    ceremony_url,
                    ceremony_expires_at_ms,
                } => {
                    return Ok(ExactPayloadOutcome::ApprovalRequired {
                        approval_id,
                        ceremony_url,
                        ceremony_expires_at_ms,
                    });
                }
                StoredApprovalCeremony::NoLongerPending => {}
                StoredApprovalCeremony::Unconfirmed => {
                    return Err(ExactSigningError::OutcomeUnknown(
                        "the stored approval's ceremony is unconfirmed; retry without rebuilding"
                            .into(),
                    ));
                }
            }
            // Past this point the call carries an approval id, so Broker may
            // sign rather than prepare. Recorded before the call and never
            // cleared: whatever the response is, or whether one arrives at
            // all, a later replacement must treat this attempt as one that may
            // have signed until Broker says otherwise, and must know which id
            // to ask about.
            self.record_signing_attempt(state_path, action_id, &state.signing_operation_id)?;
        }
        let mut response = self.broker.sign_exact_payload(request.clone()).await;
        let prior_attempt_stands = response
            .as_ref()
            .is_err_and(|error| error.code == ProtocolErrorCode::OperationIdConflict)
            && state.approval_id.is_some();
        if prior_attempt_stands {
            // A prior attempt may have committed at Broker before its response
            // reached Machine. Keep the activated approval and immutable payload,
            // but never retry a signing reservation that Broker finalized. The
            // reservation Broker kept stays in the record, so it is still the
            // id a later replacement asks about; the fresh one is added before
            // it is used.
            state.signing_operation_id = random_operation_id();
            request.signing_operation_id = state.signing_operation_id.clone();
            write_state(state_path, &state)?;
            self.record_signing_attempt(state_path, action_id, &state.signing_operation_id)?;
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
                Err(signing_error(
                    error,
                    state.approval_id.is_some(),
                    prior_attempt_stands,
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
            account_key_ref: self.account_key_ref.clone(),
            petal_use_claim: Some(claim.clone()),
            claim_assurance_evidence: claim_assurance_evidence.map(<[u8]>::to_vec),
        };
        // Like the exact paths: a retry while the owner has not finished
        // the ceremony returns the same pending approval instead of
        // signing into a refusal that would drop it.
        if let Some(approval_id) = state.approval_id.clone() {
            match self.stored_approval_ceremony(&approval_id).await {
                StoredApprovalCeremony::AwaitingOwner {
                    ceremony_url,
                    ceremony_expires_at_ms,
                } => {
                    return Ok(ExactPayloadBatchOutcome::ApprovalRequired {
                        approval_id,
                        ceremony_url,
                        ceremony_expires_at_ms,
                    });
                }
                StoredApprovalCeremony::NoLongerPending => {}
                StoredApprovalCeremony::Unconfirmed => {
                    return Err(ExactSigningError::OutcomeUnknown(
                        "the stored approval's ceremony is unconfirmed; retry without rebuilding"
                            .into(),
                    ));
                }
            }
        }
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
            Err(error) => Err(signing_error(error, state.approval_id.is_some(), false)),
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
            Err(error) => return Err(format!("read exact batch signing state: {error}").into()),
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
        if let Some(approval_id) = state.approval_id.clone() {
            match self.stored_approval_ceremony(&approval_id).await {
                StoredApprovalCeremony::AwaitingOwner {
                    ceremony_url,
                    ceremony_expires_at_ms,
                } => {
                    return Ok(ExactPayloadBatchOutcome::ApprovalRequired {
                        approval_id,
                        ceremony_url,
                        ceremony_expires_at_ms,
                    });
                }
                StoredApprovalCeremony::NoLongerPending => {}
                StoredApprovalCeremony::Unconfirmed => {
                    return Err(ExactSigningError::OutcomeUnknown(
                        "the stored approval's ceremony is unconfirmed; retry without rebuilding"
                            .into(),
                    ));
                }
            }
        }
        let mut response = self.broker.sign_exact_payload_batch(request.clone()).await;
        let prior_attempt_stands = response
            .as_ref()
            .is_err_and(|error| error.code == ProtocolErrorCode::OperationIdConflict)
            && state.approval_id.is_some();
        if prior_attempt_stands {
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
                Err(signing_error(
                    error,
                    state.approval_id.is_some(),
                    prior_attempt_stands,
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
        ApprovalPrepareState, Base64UrlBytes, KeyPublic, KeyRef, KeyRole, KeySpec,
        MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, NormalizedSignature,
        PROVENANCE_CATALOG_SCHEMA, ProtocolError, ProtocolErrorCode, ProvenanceOperationClass,
        ProvenanceRecord, SealedApprovalPrepareResponse, ServiceFuture, SigningResult,
        WalletPublic,
    };

    #[derive(Default)]
    struct MockBroker {
        requests: Mutex<Vec<MachineBrokerRequest>>,
        conflict_sign_once: AtomicBool,
        /// Simulates the pre-#265 derivation defect for the negative twin: the
        /// approval presents no `value_limits` even though the claim declares
        /// value, so the accounting mirror must refuse it.
        drop_value_limits: bool,
        /// The fee asset the provenance catalog marks for the operation class
        /// under test, mirroring `account_declared_values`' fee matching.
        class_fee_asset: Option<bloom_broker_api::ProvenanceFeeAsset>,
        /// Prepared approvals still wait on their owner's ceremony.
        awaiting_owner: AtomicBool,
        /// Errors the next signing requests return, in order.
        sign_errors: Mutex<Vec<ProtocolError>>,
        /// Errors the next approval status queries return, in order.
        status_errors: Mutex<Vec<ProtocolError>>,
        /// Errors the next revoke calls return, in order.
        revoke_errors: Mutex<Vec<ProtocolError>>,
        /// Signing operations Broker has a record of, and what it says about
        /// them. Anything else answers ApprovalNotFound, which is how Machine
        /// learns a signing call never reached Broker.
        signing_operations: Mutex<BTreeMap<String, bloom_broker_api::OperationState>>,
        /// Errors the next operation status queries return, in order.
        operation_status_errors: Mutex<Vec<ProtocolError>>,
        /// Run once, the first time an approval's status is read: the owner
        /// completing a ceremony between Machine's inspection and its revoke.
        /// Deterministic, and the point of the race test.
        on_status_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
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
                    MachineBrokerRequest::SealedApprovalStatus(request) => {
                        let scripted = {
                            let mut errors = self.status_errors.lock().unwrap();
                            (!errors.is_empty()).then(|| errors.remove(0))
                        };
                        if let Some(error) = scripted {
                            return Err(error);
                        }
                        let waiting = self.awaiting_owner.load(Ordering::SeqCst);
                        // The owner's ceremony lands here, between the read and
                        // whatever the caller does next.
                        if let Some(advance) = self.on_status_read.lock().unwrap().take() {
                            advance();
                        }
                        Ok(MachineBrokerResponse::SealedApprovalStatus(
                            bloom_broker_api::ApprovalPublicStatus {
                                approval_id: request.id,
                                wallet_id: token("wallet"),
                                state: if waiting {
                                    bloom_broker_api::ApprovalLifecycleState::AwaitingCeremony
                                } else {
                                    bloom_broker_api::ApprovalLifecycleState::Active
                                },
                                effective_claim_assurance: None,
                                ceremony_url: waiting
                                    .then(|| "http://localhost:18734/ceremony/test".into()),
                                ceremony_expires_at_ms: waiting.then(|| DecimalU64::new(u64::MAX)),
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
                    MachineBrokerRequest::SigningSignBatch(request) => {
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
                        let scripted = {
                            let mut errors = self.operation_status_errors.lock().unwrap();
                            (!errors.is_empty()).then(|| errors.remove(0))
                        };
                        if let Some(error) = scripted {
                            return Err(error);
                        }
                        // The owner's ceremony lands here too: this is the
                        // read that now precedes the revoke.
                        if let Some(advance) = self.on_status_read.lock().unwrap().take() {
                            advance();
                        }
                        let state = self
                            .signing_operations
                            .lock()
                            .unwrap()
                            .get(request.operation_id.as_str())
                            .copied();
                        let Some(state) = state else {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::ApprovalNotFound,
                                "operation not found",
                            ));
                        };
                        Ok(MachineBrokerResponse::OperationStatus(
                            bloom_broker_api::OperationPublicStatus {
                                operation_id: request.operation_id,
                                operation_digest: digest(11),
                                state,
                                result: None,
                                error: None,
                            },
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalRevoke(request) => {
                        let scripted = {
                            let mut errors = self.revoke_errors.lock().unwrap();
                            (!errors.is_empty()).then(|| errors.remove(0))
                        };
                        if let Some(error) = scripted {
                            return Err(error);
                        }
                        Ok(MachineBrokerResponse::SealedApprovalRevoke(
                            bloom_broker_api::ApprovalPublicStatus {
                                approval_id: request.approval_id,
                                wallet_id: request.wallet_id,
                                state: bloom_broker_api::ApprovalLifecycleState::Revoked,
                                effective_claim_assurance: None,
                                ceremony_url: None,
                                ceremony_expires_at_ms: None,
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
        broker.awaiting_owner.store(true, Ordering::SeqCst);
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
        broker.awaiting_owner.store(false, Ordering::SeqCst);
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
        broker.awaiting_owner.store(true, Ordering::SeqCst);
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
        broker.awaiting_owner.store(true, Ordering::SeqCst);
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
                vec![
                    ProtocolError::new(ProtocolErrorCode::OperationIdConflict, "finalized"),
                    ProtocolError::new(ProtocolErrorCode::LimitExceededOperations, "used"),
                ],
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

    /// One scope's worth of exact signing: a signer, its state directory, and
    /// the claim and hash every attempt in it shares. Attempts differ by their
    /// state path, which is what the daemon derives per payload.
    struct Scope {
        broker: Arc<MockBroker>,
        home: tempfile::TempDir,
        claim: PetalUseClaim,
        hash: Digest32,
        scope: String,
    }

    impl Scope {
        fn open(broker: &Arc<MockBroker>, scope: &str) -> Self {
            let (_, home, claim, hash) = debiting_claim_fixture(broker, None);
            Self {
                broker: broker.clone(),
                home,
                claim,
                hash,
                scope: scope.to_owned(),
            }
        }

        fn state_dir(&self) -> std::path::PathBuf {
            self.home.path().to_path_buf()
        }

        fn signer(&self, supersedes: Option<&str>) -> BrokerExactPayloadSigner {
            let (signer, _, _, _) = debiting_claim_fixture(&self.broker, None);
            signer.in_scope(self.scope.clone(), supersedes.map(str::to_owned))
        }

        /// One attempt, named the way the daemon names them: a 64-hex request
        /// id that is both the state file's stem and the action id.
        async fn attempt(
            &self,
            request_id: &str,
            supersedes: Option<&str>,
        ) -> Result<ExactPayloadOutcome, ExactSigningError> {
            self.signer(supersedes)
                .sign_or_prepare_petal(
                    &self.state_dir().join(format!("{request_id}.json")),
                    request_id,
                    "wallet",
                    "hyperliquid.withdraw",
                    b"exact withdraw payload",
                    self.hash.clone(),
                    CryptoSuite::Secp256k1Sha256Recoverable,
                    &serde_json::json!({"asset": "USDC"}),
                    &ProvenanceSubject::Petal {
                        package_hash: self.claim.package_hash.clone(),
                        route: "withdraw/request".into(),
                    },
                    &self.claim,
                    Some(b"assurance"),
                )
                .await
        }

        /// The signing operation id this attempt's state currently holds.
        fn signing_operation(&self, request_id: &str) -> OperationId {
            let bytes = fs::read(self.state_dir().join(format!("{request_id}.json")))
                .expect("signing state");
            serde_json::from_slice::<ExactSigningState>(&bytes)
                .expect("signing state parses")
                .signing_operation_id
        }

        /// Run the attempt's own lifetime out, the way waiting would.
        fn expire(&self, request_id: &str) {
            let path = self.state_dir().join(format!("{request_id}.json"));
            let mut state: ExactSigningState =
                serde_json::from_slice(&fs::read(&path).expect("signing state"))
                    .expect("signing state parses");
            state.expires_at_ms = DecimalU64::new(1);
            write_state(&path, &state).expect("state rewritten");
        }

        fn record(&self, request_id: &str) -> ExactOperationRecord {
            let bytes = fs::read(self.state_dir().join(format!("{request_id}.op.json")))
                .expect("operation record");
            serde_json::from_slice(&bytes).expect("operation record parses")
        }

        fn revocations(&self) -> Vec<Digest32> {
            self.broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter_map(|request| match request {
                    MachineBrokerRequest::SealedApprovalRevoke(revoke) => {
                        Some(revoke.approval_id.clone())
                    }
                    _ => None,
                })
                .collect()
        }
    }

    fn request_id(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn approval_of(outcome: &ExactPayloadOutcome) -> Digest32 {
        match outcome {
            ExactPayloadOutcome::ApprovalRequired { approval_id, .. } => approval_id.clone(),
            other => panic!("expected a prepared approval, got {other:?}"),
        }
    }

    /// Rebuilding one operation releases its own earlier attempt: the approval
    /// is revoked, which is what ends its ceremony, and the rebuild gets an
    /// approval of its own without waiting for the old ceremony's TTL. The
    /// logical operation survives the change of bytes — the rebuild inherits
    /// the first attempt's operation root — and the release is recorded rather
    /// than erased.
    #[tokio::test]
    async fn a_rebuilt_operation_releases_its_own_earlier_attempt() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));

        let waiting_on = approval_of(&scope.attempt(&first, None).await.unwrap());
        let rebuilt = approval_of(&scope.attempt(&second, Some(&first)).await.unwrap());

        assert_ne!(rebuilt, waiting_on, "the rebuild asks for its own approval");
        assert_eq!(scope.revocations(), vec![waiting_on]);
        assert_eq!(
            scope.record(&second).operation_root,
            first,
            "a rebuild is the same logical operation as the attempt it replaces"
        );
        assert!(
            scope.record(&first).released_at_ms.is_some(),
            "the release is recorded"
        );
        assert!(
            scope.state_dir().join(format!("{first}.json")).is_file(),
            "the superseded attempt's state is kept, not deleted"
        );
    }

    /// The boundary Machine enforces. Two operations that share a package,
    /// route, wallet, operation class and account key are in one scope, and a
    /// request in another scope may not touch them at all: naming one is
    /// refused outright, with nothing changed on either side.
    ///
    /// Within a scope, which attempt a supersession refers to is the caller's
    /// assertion, not Machine's: see the contract in the daemon. What Machine
    /// guarantees is narrower — a supersession can only ever end an approval
    /// that is still awaiting its owner, and never one that may have signed.
    #[tokio::test]
    async fn a_request_cannot_supersede_an_attempt_from_another_scope() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let mine = Scope::open(&broker, "scope-a");
        let (a, b) = (request_id('a'), request_id('b'));
        let waiting_on = approval_of(&mine.attempt(&a, None).await.unwrap());

        // A second package, route, wallet, class or key is a different scope.
        // It shares the state directory here, which is exactly the case the
        // scope check has to catch.
        let theirs = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            mine.signer(None).provenance_catalog.clone(),
        )
        .in_scope("scope-b".into(), Some(a.clone()));
        let theirs_again = BrokerExactPayloadSigner::new(
            MachineBrokerClient::new(broker.clone()),
            mine.signer(None).provenance_catalog.clone(),
        )
        .in_scope("scope-b".into(), Some(a.clone()));
        let refused = theirs
            .sign_or_prepare_petal(
                &mine.state_dir().join(format!("{b}.json")),
                &b,
                "wallet",
                "hyperliquid.withdraw",
                b"exact withdraw payload",
                mine.hash.clone(),
                CryptoSuite::Secp256k1Sha256Recoverable,
                &serde_json::json!({"asset": "USDC"}),
                &ProvenanceSubject::Petal {
                    package_hash: mine.claim.package_hash.clone(),
                    route: "withdraw/request".into(),
                },
                &mine.claim,
                Some(b"assurance"),
            )
            .await
            .unwrap_err();

        assert!(
            matches!(&refused, ExactSigningError::Refused(message)
                if message == "approval artifact does not match the exact Petal operation"),
            "a cross-scope supersession is one refusal, indistinguishable from an \
             unknown id, so a Petal cannot probe for another's artifacts: {refused:?}"
        );
        // The reason itself is Machine's, and is what the protocol reports.
        assert!(matches!(
            theirs_again
                .release_superseded(&mine.state_dir(), &a)
                .await,
            Supersession::Invalid(reason)
                if reason.contains("another package, route, wallet, operation class or key")
        ),);
        assert!(mine.revocations().is_empty(), "nothing was revoked");
        assert!(
            mine.record(&a).released_at_ms.is_none(),
            "the named attempt is untouched"
        );
        // And it is still the live approval its own operation is waiting on.
        assert_eq!(
            approval_of(&mine.attempt(&a, None).await.unwrap()),
            waiting_on
        );
    }

    /// The whole hint contract, one input per case.
    #[tokio::test]
    async fn a_supersession_names_a_known_attempt_or_is_refused() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let known = request_id('1');
        scope.attempt(&known, None).await.unwrap();

        // Unknown, and well formed: Machine never removes an operation record,
        // so an id it has none for was never a request here. Deterministic, and
        // a refusal rather than a silent no-op.
        let unknown = scope
            .attempt(&request_id('9'), Some(&request_id('7')))
            .await
            .unwrap_err();
        assert!(
            matches!(&unknown, ExactSigningError::OutcomeUnknown(message)
                if message.contains("no exact request by that id was prepared here")),
            "{unknown:?}"
        );

        // Superseding itself is not a replacement.
        let itself = scope
            .attempt(&known, Some(&known))
            .await
            .expect_err("a request cannot supersede itself");
        assert!(
            matches!(&itself, ExactSigningError::Refused(_)),
            "{itself:?}"
        );

        // Already released: the retry is idempotent and revokes nothing new.
        let second = request_id('2');
        scope.attempt(&second, Some(&known)).await.unwrap();
        assert_eq!(scope.revocations().len(), 1);
        scope.attempt(&second, Some(&known)).await.unwrap();
        assert_eq!(
            scope.revocations().len(),
            1,
            "replaying the same replacement revokes nothing again"
        );
    }

    /// The owner completes the ceremony in the window between Machine reading
    /// the superseded attempt's signing operation and revoking its approval.
    /// Activating an approval does not produce a signature — Machine is the
    /// only caller that signs with it, and it is serialized behind this very
    /// call — so the read stays true and the revoke then ends it for good.
    /// Nothing here concludes "nothing signed" from a pending reading.
    #[tokio::test]
    async fn an_owner_approving_mid_replacement_cannot_cause_a_second_signature() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        let waiting_on = approval_of(&scope.attempt(&first, None).await.unwrap());

        // Give the attempt a signing call Broker refused, so the replacement
        // has a status to read before it revokes anything.
        broker.awaiting_owner.store(false, Ordering::SeqCst);
        broker.sign_errors.lock().unwrap().push(ProtocolError::new(
            ProtocolErrorCode::ClaimInvalid,
            "refused",
        ));
        scope.attempt(&first, None).await.unwrap_err();
        broker.signing_operations.lock().unwrap().insert(
            scope.signing_operation(&first).as_str().to_owned(),
            bloom_broker_api::OperationState::Denied,
        );
        broker.awaiting_owner.store(true, Ordering::SeqCst);

        // The owner's ceremony completes the moment Machine reads that status.
        let advancing = broker.clone();
        *broker.on_status_read.lock().unwrap() = Some(Box::new(move || {
            advancing.awaiting_owner.store(false, Ordering::SeqCst);
        }));

        scope.attempt(&second, Some(&first)).await.unwrap();
        assert_eq!(
            scope.revocations(),
            vec![waiting_on],
            "the approval the owner just activated is revoked, so it can never sign"
        );
        assert!(scope.record(&first).released_at_ms.is_some());
    }

    /// Once a signing call that could have produced a signature has been
    /// issued, an earlier pending reading proves nothing. Machine asks Broker
    /// about that attempt's signing operation, and refuses to replace an
    /// attempt Broker has a record of.
    #[tokio::test]
    async fn an_attempt_that_may_have_signed_is_never_replaced() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        scope.attempt(&first, None).await.unwrap();

        // The owner approves, and a retry of the first attempt falls through to
        // a signing call. That is what makes its outcome Broker's to report.
        broker.awaiting_owner.store(false, Ordering::SeqCst);
        scope.attempt(&first, None).await.unwrap();
        assert!(
            scope.record(&first).signing_may_have_started,
            "a call that can sign is recorded before it is made"
        );
        let signing_operation = {
            let bytes = fs::read(scope.state_dir().join(format!("{first}.json"))).unwrap();
            serde_json::from_slice::<ExactSigningState>(&bytes)
                .unwrap()
                .signing_operation_id
        };
        broker.signing_operations.lock().unwrap().insert(
            signing_operation.as_str().to_owned(),
            bloom_broker_api::OperationState::Succeeded,
        );

        let refused = scope.attempt(&second, Some(&first)).await.unwrap_err();
        assert!(
            matches!(&refused, ExactSigningError::OutcomeUnknown(message)
                if message.contains("is Succeeded")),
            "{refused:?}"
        );
        assert!(
            scope.record(&first).released_at_ms.is_none(),
            "an attempt that may have signed is not recorded as released"
        );
        assert!(
            scope.revocations().is_empty(),
            "and its approval is left alone: revoking it would take away the one \
             recovery its caller has, and undo no signature"
        );
    }

    /// Broker reporting that it had already finalized a signing reservation
    /// rotates the operation state's id. The reservation Broker kept is still
    /// in the record, so the attempt is still answered for by asking about it —
    /// and Broker saying it finalized one refuses the replacement.
    #[tokio::test]
    async fn a_rotated_signing_id_does_not_hide_the_reservation_broker_kept() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        scope.attempt(&first, None).await.unwrap();
        let reserved = scope.signing_operation(&first);

        // The owner approves, and the signing call comes back saying Broker
        // already finalized a reservation under that operation id.
        broker.awaiting_owner.store(false, Ordering::SeqCst);
        broker.conflict_sign_once.store(true, Ordering::SeqCst);
        scope.attempt(&first, None).await.unwrap();
        let record = scope.record(&first);
        assert_ne!(
            scope.signing_operation(&first),
            reserved,
            "the conflict rotates the id the state holds"
        );
        assert!(
            record.signing_operations.contains(&reserved),
            "the rotated-away id is still on record"
        );

        // Broker's account of the reservation it kept is what decides.
        broker.signing_operations.lock().unwrap().insert(
            reserved.as_str().to_owned(),
            bloom_broker_api::OperationState::Succeeded,
        );
        let refused = scope.attempt(&second, Some(&first)).await.unwrap_err();
        assert!(
            matches!(&refused, ExactSigningError::OutcomeUnknown(message)
                if message.contains("is Succeeded")),
            "{refused:?}"
        );
        assert!(scope.record(&first).released_at_ms.is_none());
    }

    /// The operation state's own lifetime expiring rotates its signing id too.
    /// A call whose response was lost before that happened is still the reason
    /// the attempt's outcome is open, and asking only about the id the state
    /// holds afterwards would read "Broker has never heard of this" as
    /// "nothing signed".
    #[tokio::test]
    async fn a_lost_signing_response_survives_the_operation_lifetime_expiring() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        scope.attempt(&first, None).await.unwrap();

        // The owner approves and the signing call is made; its response never
        // arrives, so Broker has a record of it and Machine does not.
        broker.awaiting_owner.store(false, Ordering::SeqCst);
        broker.sign_errors.lock().unwrap().push(ProtocolError::new(
            ProtocolErrorCode::ServiceUnavailable,
            "connection closed after the request was accepted",
        ));
        scope.attempt(&first, None).await.unwrap_err();
        let lost = scope.signing_operation(&first);
        broker.signing_operations.lock().unwrap().insert(
            lost.as_str().to_owned(),
            bloom_broker_api::OperationState::Succeeded,
        );

        // The attempt's own lifetime runs out, which rotates every id in its
        // state and clears its approval.
        scope.expire(&first);
        scope.attempt(&first, None).await.unwrap();
        assert_ne!(
            scope.signing_operation(&first),
            lost,
            "expiry rotates the id the state holds"
        );

        let refused = scope.attempt(&second, Some(&first)).await.unwrap_err();
        assert!(
            matches!(&refused, ExactSigningError::OutcomeUnknown(message)
                if message.contains("is Succeeded")),
            "the lost call is still what decides: {refused:?}"
        );
        assert!(scope.record(&first).released_at_ms.is_none());
        assert!(scope.revocations().is_empty(), "nothing was given up");
    }

    /// A request from before this record existed, whose own lifetime had already
    /// run out by the time this Machine met it. Adopting it has to take the
    /// signing operation id from the state **as persisted**: the expiry path in
    /// the same call rotates that id, and the persisted one is the only handle
    /// Broker has on whatever the previous binary's signing call did.
    ///
    /// Broker says that call succeeded. The attempt is therefore unresolved,
    /// the replacement is blocked, and its approval is left alone.
    #[tokio::test]
    async fn an_expired_legacy_request_is_adopted_from_the_id_its_state_persisted() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        scope.attempt(&first, None).await.unwrap();

        // What the previous binary left behind: a state file whose signing call
        // Broker has a record of, no operation record, and a lifetime that has
        // already run out.
        let original = scope.signing_operation(&first);
        broker.signing_operations.lock().unwrap().insert(
            original.as_str().to_owned(),
            bloom_broker_api::OperationState::Succeeded,
        );
        fs::remove_file(scope.state_dir().join(format!("{first}.op.json"))).unwrap();
        scope.expire(&first);

        // The retry adopts it, and the expiry path rotates the state's id in
        // the same call.
        scope.attempt(&first, None).await.unwrap();
        assert_ne!(scope.signing_operation(&first), original);
        let record = scope.record(&first);
        assert!(record.signing_may_have_started);
        assert!(
            record.signing_operations.contains(&original),
            "adoption must keep the id the state persisted, not the one expiry \
             replaced it with: {:?}",
            record.signing_operations
        );

        let refused = scope.attempt(&second, Some(&first)).await.unwrap_err();
        assert!(
            matches!(&refused, ExactSigningError::OutcomeUnknown(message)
                if message.contains("is Succeeded")),
            "{refused:?}"
        );
        assert!(scope.record(&first).released_at_ms.is_none());
        assert!(
            scope.revocations().is_empty(),
            "an attempt that may have signed keeps its approval"
        );
    }

    /// A released request is finished. Its own lifetime expiring must not
    /// revive it: that path clears the approval id and would prepare a second
    /// one for bytes another request has already replaced.
    #[tokio::test]
    async fn a_released_request_stays_refused_after_its_lifetime_expires() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        scope.attempt(&first, None).await.unwrap();
        scope.attempt(&second, Some(&first)).await.unwrap();
        assert!(scope.record(&first).released_at_ms.is_some());

        let prepares = || {
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| matches!(request, MachineBrokerRequest::SealedApprovalPrepare(_)))
                .count()
        };
        let before = prepares();

        scope.expire(&first);
        for _ in 0..2 {
            let refused = scope.attempt(&first, None).await.unwrap_err();
            assert!(
                matches!(&refused, ExactSigningError::Refused(message)
                    if message.contains("given up and replaced")),
                "{refused:?}"
            );
        }
        assert_eq!(prepares(), before, "no approval was prepared for it again");
    }

    /// A signing call whose response was lost leaves Broker with a record of
    /// the operation. Retrying the replacement reconciles against that record
    /// rather than opening a second live attempt, and once Broker reports the
    /// operation was refused, the replacement proceeds.
    #[tokio::test]
    async fn a_lost_signing_response_is_reconciled_before_a_replacement() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        scope.attempt(&first, None).await.unwrap();
        broker.awaiting_owner.store(false, Ordering::SeqCst);
        scope.attempt(&first, None).await.unwrap();
        let signing_operation = {
            let bytes = fs::read(scope.state_dir().join(format!("{first}.json"))).unwrap();
            serde_json::from_slice::<ExactSigningState>(&bytes)
                .unwrap()
                .signing_operation_id
        };

        // Broker cannot be reached: unresolved, and no replacement.
        broker
            .operation_status_errors
            .lock()
            .unwrap()
            .push(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "broker unreachable",
            ));
        let unresolved = scope.attempt(&second, Some(&first)).await.unwrap_err();
        assert!(
            matches!(&unresolved, ExactSigningError::OutcomeUnknown(message)
                if message.contains("could not be read")),
            "{unresolved:?}"
        );
        assert!(scope.record(&first).released_at_ms.is_none());

        // Broker reports the signing operation was refused, so no signature
        // exists and the replacement is safe.
        broker.signing_operations.lock().unwrap().insert(
            signing_operation.as_str().to_owned(),
            bloom_broker_api::OperationState::Denied,
        );
        scope.attempt(&second, Some(&first)).await.unwrap();
        assert!(scope.record(&first).released_at_ms.is_some());
    }

    /// Failures that leave the outcome unknown never authorize a replacement:
    /// an unreadable operation record, and a revoke Broker refused.
    #[tokio::test]
    async fn an_unresolved_failure_never_authorizes_a_replacement() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        scope.attempt(&first, None).await.unwrap();

        // Broker cannot be reached to revoke.
        broker
            .revoke_errors
            .lock()
            .unwrap()
            .push(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "broker unreachable",
            ));
        let unreachable = scope.attempt(&second, Some(&first)).await.unwrap_err();
        assert!(
            matches!(&unreachable, ExactSigningError::OutcomeUnknown(message)
                if message.contains("could not be revoked")),
            "{unreachable:?}"
        );
        assert!(scope.record(&first).released_at_ms.is_none());

        // A corrupt operation record is not an absent one, and neither is proof
        // of anything.
        fs::write(
            scope.state_dir().join(format!("{first}.op.json")),
            b"{ not json",
        )
        .unwrap();
        let corrupt = scope.attempt(&second, Some(&first)).await.unwrap_err();
        assert!(
            matches!(&corrupt, ExactSigningError::OutcomeUnknown(message)
                if message.contains("unreadable")),
            "{corrupt:?}"
        );
    }

    /// The state layout is the one that shipped. A pending exact request
    /// written by v0.2.0 or v0.2.1 — flat `.state/<request>.json`, no
    /// operation record, no `account_key_ref` — is still found and resumed
    /// after the upgrade, and it keeps its approval rather than preparing a
    /// second one. Nothing about the replacement work moves it.
    ///
    /// The one thing such a request cannot do is take part in a supersession:
    /// it has no operation record, and Machine will not invent one for state
    /// it did not write, so naming it is unresolved rather than allowed.
    #[tokio::test]
    async fn a_pending_request_written_before_this_change_is_still_resumed() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        let waiting_on = approval_of(&scope.attempt(&first, None).await.unwrap());

        // Put the state back in the shipped shape: the record this change adds
        // is a separate file, so removing it is exactly what a state directory
        // written by the released binary looks like.
        let shipped = scope.state_dir().join(format!("{first}.op.json"));
        fs::remove_file(&shipped).unwrap();
        let state_path = scope.state_dir().join(format!("{first}.json"));
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        state.as_object_mut().unwrap().remove("account_key_ref");
        assert_eq!(state["schema"], "bloom.machine_exact_signing.v1");
        fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();

        // The upgraded Machine finds it, and it is the same approval.
        assert_eq!(
            approval_of(&scope.attempt(&first, None).await.unwrap()),
            waiting_on,
            "an upgrade must not hide a request the owner is still deciding"
        );
        let prepares = broker
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| matches!(request, MachineBrokerRequest::SealedApprovalPrepare(_)))
            .count();
        assert_eq!(prepares, 1, "no second approval was prepared for it");

        // Adopting it does not clear Machine's ignorance about it: it records
        // that the request may already have issued a signing call, because
        // nothing here can say that it did not.
        assert!(
            scope.record(&first).signing_may_have_started,
            "a request Machine did not prepare is assumed to have tried to sign"
        );
        // So superseding it is only allowed once Broker has answered for the
        // attempt's signing operation, by the same rule as everywhere else.
        scope.attempt(&second, Some(&first)).await.unwrap();
        assert_eq!(scope.revocations(), vec![waiting_on]);
        assert!(scope.record(&first).released_at_ms.is_some());
    }

    /// A revoke that Broker carried out but whose response never arrived. The
    /// replacement does not proceed on a call it cannot account for, and the
    /// retry reaches the same conclusion by revoking again — which is
    /// idempotent — rather than by assuming the first one landed. One live
    /// attempt throughout: the replacement only becomes signable once the
    /// prior one is resolved.
    #[tokio::test]
    async fn a_lost_revoke_response_is_reconciled_by_the_retry() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        let waiting_on = approval_of(&scope.attempt(&first, None).await.unwrap());

        // Broker revokes, and the answer is lost on the way back.
        broker
            .revoke_errors
            .lock()
            .unwrap()
            .push(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                "connection closed after the request was accepted",
            ));
        let lost = scope.attempt(&second, Some(&first)).await.unwrap_err();
        assert!(
            matches!(&lost, ExactSigningError::OutcomeUnknown(_)),
            "{lost:?}"
        );
        assert!(
            scope.record(&first).released_at_ms.is_none(),
            "an unaccounted-for revoke is not a recorded release"
        );
        let prepares = || {
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| matches!(request, MachineBrokerRequest::SealedApprovalPrepare(_)))
                .count()
        };
        assert_eq!(prepares(), 1, "no second approval was opened meanwhile");

        // The retry settles it, and only then does the replacement get one.
        scope.attempt(&second, Some(&first)).await.unwrap();
        assert_eq!(scope.revocations(), vec![waiting_on.clone(), waiting_on]);
        assert!(scope.record(&first).released_at_ms.is_some());
        assert_eq!(prepares(), 2);
    }

    /// Machine is interrupted after revoking the superseded approval and before
    /// recording the release. The retry reaches the same conclusion from
    /// Broker rather than assuming it, and the operation keeps its identity.
    #[tokio::test]
    async fn a_release_interrupted_before_it_is_recorded_recovers() {
        let broker = Arc::new(MockBroker::default());
        broker.awaiting_owner.store(true, Ordering::SeqCst);
        let scope = Scope::open(&broker, "scope-a");
        let (first, second) = (request_id('1'), request_id('2'));
        let waiting_on = approval_of(&scope.attempt(&first, None).await.unwrap());
        scope.attempt(&second, Some(&first)).await.unwrap();

        // Put the record back the way a crash between the revoke and the write
        // would have left it: revoked at Broker, unrecorded here.
        let mut record = scope.record(&first);
        record.released_at_ms = None;
        write_state(&scope.state_dir().join(format!("{first}.op.json")), &record).unwrap();

        let third = request_id('3');
        scope.attempt(&third, Some(&first)).await.unwrap();
        assert_eq!(
            scope.revocations(),
            vec![waiting_on.clone(), waiting_on],
            "the retry revokes again rather than assuming the first one landed"
        );
        assert!(scope.record(&first).released_at_ms.is_some());
        assert_eq!(
            scope.record(&third).operation_root,
            first,
            "the logical operation survives the interruption"
        );
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
            .map_err(|error| error.to_string())
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

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }
}
