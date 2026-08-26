//! Machine-owned, keyless client surface for the Broker.
//!
//! This crate intentionally knows only the public Machine↔Broker protocol. It
//! contains no private-key, WKEK, PRF, provider-credential, or custody
//! plaintext type.

#![forbid(unsafe_code)]

mod projection;

pub use projection::{
    CachedWalletProjectionReader, FileProjectionStore, ProjectionFreshness, ProjectionVerification,
    WalletProjection, WalletProjectionReader,
};

use std::{
    collections::BTreeSet,
    future::Future,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

const AUTHORITY_HEAD_EXCHANGE_CADENCE: Duration = Duration::from_secs(45);
const AUTHORITY_HEAD_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

async fn run_periodic_authority_head_exchange<F, Fut, T>(mut exchange: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = T>,
{
    let mut interval = tokio::time::interval(AUTHORITY_HEAD_EXCHANGE_CADENCE);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        let _ = tokio::time::timeout(AUTHORITY_HEAD_EXCHANGE_TIMEOUT, exchange()).await;
    }
}

pub use bloom_audit_checkpoint::AuthorityEdgeHistory;
use bloom_audit_checkpoint::{CheckpointSink, CheckpointStore, PinnedAuditKey};
use bloom_broker_api::{
    ActivationMode, ApprovalLifecycleState, ApprovalLimitState, ApprovalLimits,
    ApprovalPrepareRequest, ApprovalPublicStatus, ApprovalRenewRequest, ApprovalSelector,
    ApprovalSubject, BROKER_API_CURRENT, BROKER_API_RANGE, Base64UrlBytes, CeremonyPublicStatus,
    CeremonyState, CredentialPublic, CryptoSuite, CustodyPrepareRequest, CustodyPrepareResponse,
    CustodyResult, DecimalU64, DerivationRef, Digest32, IdRequest, KeyPublic, KeyRef, KeyRequest,
    KeyRole, MachineBrokerRequest, MachineBrokerResponse, MachineBrokerService, MachineSignRequest,
    OperationId, OperationPublicStatus, OperationRequest, PetalUseClaim, PolicyCommitReceipt,
    PolicyCommitUpdateRequest, PolicyUpdatePrepareResponse, PolicyUpdateRequest, ProtocolError,
    ProtocolErrorCode, ProvenanceCatalog, ProvenanceSubject, RequestNonce, RevocationState,
    RevokeRequest, SealedApprovalPrepareResponse, SealedApprovalTerms, SignedPolicySnapshot,
    SigningPayloads, SigningResult, Token, TypedRequestMethod, WalletAccountsPublic,
    WalletOperationRequest, WalletPublic, WalletRequest, is_read_only_method,
};
use bloom_triad_local_transport::{LocalIdentity, PeerAcl};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

const SIGN_OPERATION_DOMAIN: &[u8] = b"bloom-sign-operation/v1";

/// Machine-owned identity used to bind a logical north-edge signing operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignOperationIdentity {
    pub operation_id: OperationId,
    pub approval_id: Digest32,
    pub key_ref: KeyRef,
    pub crypto_suite: CryptoSuite,
    pub ordered_payload_digests: Vec<Digest32>,
    pub ordered_hashes: Vec<Digest32>,
    pub petal_use_claim_digest: Option<Digest32>,
    pub claim_assurance_digest: Option<Digest32>,
    pub policy_version: DecimalU64,
    pub policy_digest: Digest32,
}

impl SignOperationIdentity {
    pub fn digest(&self) -> Result<Digest32, ProtocolError> {
        let mut hasher = Sha256::new();
        hasher.update(SIGN_OPERATION_DOMAIN);
        hasher.update(serde_jcs::to_vec(self).map_err(|error| {
            ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                format!("operation identity JCS encoding failed: {error}"),
            )
        })?);
        Ok(Digest32::from_bytes(hasher.finalize().into()))
    }
}

/// Production Machine→Broker connector. It carries only the public typed
/// protocol over mutually authenticated, signed, bounded Unix socket frames.
#[derive(Clone)]
pub struct UnixMachineBrokerService {
    socket_path: PathBuf,
    identity: LocalIdentity,
    broker: PeerAcl,
    journals: Arc<RwLock<Option<AuthorityJournalState>>>,
}

/// Narrow provider seam implemented by the signed Machine journal owner. It
/// deliberately exposes no append or caller-supplied-head capability.
pub trait MachineJournalHeadProvider: Send + Sync {
    fn verified_head(&self) -> Result<(u64, Digest32), ProtocolError>;
    fn latch_mutations(&self, reason: String);
}

struct AuthorityJournalState {
    provider: Arc<dyn MachineJournalHeadProvider>,
    checkpoints: Arc<CheckpointStore>,
}

impl UnixMachineBrokerService {
    pub fn new(socket_path: impl Into<PathBuf>, identity: LocalIdentity, broker: PeerAcl) -> Self {
        Self {
            socket_path: socket_path.into(),
            identity,
            broker,
            journals: Arc::new(RwLock::new(None)),
        }
    }

    fn attach_journal(
        &self,
        provider: Arc<dyn MachineJournalHeadProvider>,
        checkpoint_root: impl AsRef<Path>,
        expected_uid: u32,
        history: AuthorityEdgeHistory,
    ) -> Result<(), ProtocolError> {
        let allowed_services = [&self.identity.service_id, &self.broker.service_id];
        let historical = history
            .historical_pins_for(&allowed_services)
            .map_err(|error| {
                service_unavailable(format!("load checkpoint key history: {error}"))
            })?;
        let handovers = history.handovers_for(&allowed_services);
        let checkpoints = CheckpointStore::open_with_history(
            checkpoint_root,
            expected_uid,
            self.identity.service_id.clone(),
            [
                PinnedAuditKey {
                    service_id: self.identity.service_id.clone(),
                    key_id: self.identity.application_key_id.clone(),
                    verifying_key: self.identity.signing_key.verifying_key(),
                },
                PinnedAuditKey {
                    service_id: self.broker.service_id.clone(),
                    key_id: self.broker.application_key_id.clone(),
                    verifying_key: ed25519_dalek::VerifyingKey::from_bytes(
                        &self.broker.application_public_key,
                    )
                    .map_err(|_| service_unavailable("invalid Broker checkpoint pin"))?,
                },
            ],
            historical,
            handovers,
        )
        .map_err(|error| service_unavailable(format!("open Machine checkpoint store: {error}")))?;
        let mut state = self
            .journals
            .write()
            .map_err(|_| service_unavailable("Machine journal provider lock poisoned"))?;
        if state.is_some() {
            return Err(service_unavailable(
                "Machine journal provider is already attached",
            ));
        }
        *state = Some(AuthorityJournalState {
            provider,
            checkpoints: Arc::new(checkpoints),
        });
        Ok(())
    }

    async fn dispatch_head_aware(
        &self,
        request: MachineBrokerRequest,
    ) -> Result<MachineBrokerResponse, ProtocolError> {
        let method = request.method()?;
        let (provider, checkpoints) = {
            let state = self
                .journals
                .read()
                .map_err(|_| service_unavailable("Machine journal provider lock poisoned"))?;
            let state = state.as_ref().ok_or_else(|| {
                service_unavailable("Machine authority-edge journal is not initialized")
            })?;
            (state.provider.clone(), state.checkpoints.clone())
        };
        let sender_head = match provider.verified_head() {
            Ok((sequence, head_hash)) => {
                let head = bloom_triad_local_transport::sign_journal_head(
                    &self.identity,
                    sequence,
                    head_hash,
                );
                if let Err(error) = checkpoints.append_peer_head(&head) {
                    provider.latch_mutations(format!(
                        "persist Machine authority-edge audit head: {error}"
                    ));
                    if !is_read_only_method(&method) {
                        return Err(service_unavailable(format!(
                            "persist Machine audit head before Broker dispatch: {error}"
                        )));
                    }
                }
                head
            }
            Err(_error) if is_read_only_method(&method) => checkpoints
                .latest(&self.identity.service_id)
                .map_err(|failure| {
                    service_unavailable(format!("load retained Machine audit head: {failure}"))
                })?
                .ok_or_else(|| {
                    service_unavailable("no independently retained Machine audit head is available")
                })?,
            Err(error) => return Err(error),
        };
        let mut stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .map_err(|error| service_unavailable(format!("connect Broker: {error}")))?;
        bloom_triad_local_transport::call_with_journal_head(
            &mut stream,
            &self.identity,
            &self.broker,
            BROKER_API_CURRENT,
            BROKER_API_RANGE,
            request,
            30_000,
            sender_head,
            move |peer_head| {
                if let Err(error) = checkpoints.append_peer_head(peer_head) {
                    provider.latch_mutations(format!(
                        "persist Broker authority-edge audit head: {error}"
                    ));
                    if !is_read_only_method(&method) {
                        return Err(service_unavailable(format!(
                            "persist Broker audit checkpoint before publishing mutation result: {error}"
                        )));
                    }
                }
                Ok(())
            },
        )
        .await
    }
}

impl MachineBrokerService for UnixMachineBrokerService {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> bloom_broker_api::ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move { self.dispatch_head_aware(request).await })
    }
}

#[derive(Clone)]
pub struct MachineBrokerClient {
    service: Arc<dyn MachineBrokerService>,
    local_identity: Option<LocalIdentity>,
    unix_service: Option<Arc<UnixMachineBrokerService>>,
}

impl MachineBrokerClient {
    pub fn new(service: Arc<dyn MachineBrokerService>) -> Self {
        Self {
            service,
            local_identity: None,
            unix_service: None,
        }
    }

    pub fn connect_unix(
        socket_path: impl Into<PathBuf>,
        identity: LocalIdentity,
        broker: PeerAcl,
    ) -> Self {
        let unix_service = Arc::new(UnixMachineBrokerService::new(
            socket_path,
            identity.clone(),
            broker,
        ));
        Self {
            service: unix_service.clone(),
            local_identity: Some(identity),
            unix_service: Some(unix_service),
        }
    }

    /// Completes production authority-edge construction. Until this succeeds,
    /// the Unix client rejects every request rather than emitting a headless
    /// envelope. It also starts the required idle readiness exchange.
    pub fn attach_authority_journal(
        &self,
        provider: Arc<dyn MachineJournalHeadProvider>,
        checkpoint_root: impl AsRef<Path>,
        expected_uid: u32,
    ) -> Result<(), ProtocolError> {
        self.attach_authority_journal_with_history(
            provider,
            checkpoint_root,
            expected_uid,
            AuthorityEdgeHistory::empty(),
        )
    }

    pub fn attach_authority_journal_with_history(
        &self,
        provider: Arc<dyn MachineJournalHeadProvider>,
        checkpoint_root: impl AsRef<Path>,
        expected_uid: u32,
        history: AuthorityEdgeHistory,
    ) -> Result<(), ProtocolError> {
        let unix = self.unix_service.as_ref().ok_or_else(|| {
            service_unavailable("in-process Machine Broker service has no authority-edge transport")
        })?;
        unix.attach_journal(provider, checkpoint_root, expected_uid, history)?;
        let periodic = unix.clone();
        tokio::runtime::Handle::try_current()
            .map_err(|_| {
                service_unavailable("start Machine-Broker readiness timer outside runtime")
            })?
            .spawn(async move {
                run_periodic_authority_head_exchange(|| {
                    let periodic = periodic.clone();
                    async move {
                        periodic
                            .dispatch_head_aware(MachineBrokerRequest::BrokerReadiness(
                                bloom_broker_api::Empty {},
                            ))
                            .await
                    }
                })
                .await;
            });
        Ok(())
    }

    /// Return the already-authenticated Machine application identity for
    /// signing Machine-owned service records. This is transport/audit
    /// identity only; it has no wallet authority.
    pub fn local_application_identity(&self) -> Option<LocalIdentity> {
        self.local_identity.clone()
    }

    /// Loads the Machine application identity and the root-owned edge manifest
    /// without permitting an unauthenticated transport fallback.
    pub fn connect_unix_from_files(
        socket_path: impl Into<PathBuf>,
        identity_path: impl AsRef<Path>,
        edge_manifest_path: impl AsRef<Path>,
    ) -> Result<Self, ProtocolError> {
        let identity_path = identity_path.as_ref();
        let manifest_path = edge_manifest_path.as_ref();
        let (identity, manifest) = bloom_triad_local_transport::load_identity_and_manifest(
            identity_path,
            manifest_path,
            "bloom-machine",
        )?;
        Self::connect_unix_from_loaded(socket_path, identity, manifest)
    }

    #[cfg(feature = "triad-dev-harness")]
    pub fn connect_unix_from_developer_files(
        developer_root: impl AsRef<Path>,
        socket_path: impl Into<PathBuf>,
        identity_path: impl AsRef<Path>,
        edge_manifest_path: impl AsRef<Path>,
    ) -> Result<Self, ProtocolError> {
        let (identity, manifest) =
            bloom_triad_local_transport::load_developer_identity_and_manifest(
                developer_root.as_ref(),
                identity_path.as_ref(),
                edge_manifest_path.as_ref(),
                "bloom-machine",
            )?;
        Self::connect_unix_from_loaded(socket_path, identity, manifest)
    }

    fn connect_unix_from_loaded(
        socket_path: impl Into<PathBuf>,
        identity: LocalIdentity,
        manifest: bloom_triad_local_transport::EdgeManifest,
    ) -> Result<Self, ProtocolError> {
        let machine = manifest.machine.into_acl()?;
        let broker = manifest.broker.into_acl()?;
        if machine.service_id != identity.service_id
            || machine.boot_epoch != identity.boot_epoch
            || machine.application_key_id != identity.application_key_id
            || machine.application_public_key != identity.signing_key.verifying_key().to_bytes()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "Machine identity does not match the pinned edge manifest",
            ));
        }
        if broker.service_id.as_str() != "bloom-broker" {
            return Err(ProtocolError::new(
                ProtocolErrorCode::UnauthenticatedPeer,
                "edge manifest Broker service ID is invalid",
            ));
        }
        Ok(Self::connect_unix(socket_path, identity, broker))
    }

    pub async fn request(
        &self,
        request: MachineBrokerRequest,
    ) -> Result<MachineBrokerResponse, ProtocolError> {
        self.service.dispatch(request).await
    }

    pub async fn sign(&self, request: MachineSignRequest) -> Result<SigningResult, ProtocolError> {
        let expected = ExpectedSigningResult::from_request(&request);
        match self
            .request(MachineBrokerRequest::SigningSign(request))
            .await?
        {
            MachineBrokerResponse::SigningSign(result) => expected.validate(result),
            _ => Err(response_mismatch("signing.sign")),
        }
    }

    pub async fn sign_batch(
        &self,
        request: MachineSignRequest,
    ) -> Result<SigningResult, ProtocolError> {
        let expected = ExpectedSigningResult::from_request(&request);
        match self
            .request(MachineBrokerRequest::SigningSignBatch(request))
            .await?
        {
            MachineBrokerResponse::SigningSignBatch(result) => expected.validate(result),
            _ => Err(response_mismatch("signing.sign_batch")),
        }
    }

    /// Validate and translate a payload-bearing Petal request. Provenance is
    /// supplied independently by the trusted runner, never copied from guest
    /// fields without comparison.
    pub async fn sign_petal_payload(
        &self,
        request: TrustedPetalSignRequest,
    ) -> Result<SigningResult, ProtocolError> {
        self.sign_petal_payload_for_key(request, None).await
    }

    /// Sign a validated payload-bearing Petal request with an explicitly
    /// selected Signer-owned delegated key over the existing `signing.sign`
    /// method. The public key projection is fetched from Broker so Machine
    /// never infers delegated-key suite support locally.
    pub async fn sign_petal_payload_with_key(
        &self,
        request: TrustedPetalSignRequest,
        key_ref: KeyRef,
    ) -> Result<SigningResult, ProtocolError> {
        self.sign_petal_payload_for_key(request, Some(key_ref))
            .await
    }

    async fn sign_petal_payload_for_key(
        &self,
        request: TrustedPetalSignRequest,
        selected_key_ref: Option<KeyRef>,
    ) -> Result<SigningResult, ProtocolError> {
        request.validate()?;
        if request.selector == bloom_broker_api::PetalSignSelector::Exact
            && selected_key_ref.is_none()
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "exact Petal signing requires an explicit Signer-owned KeyRef",
            ));
        }
        let wallet = self.wallet(request.wallet_id.clone()).await?;
        let key_ref = match selected_key_ref {
            Some(key_ref) => {
                let key = self
                    .key(KeyRequest {
                        key_ref: key_ref.clone(),
                    })
                    .await?;
                if key.key_ref != key_ref {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::KeyrefMismatch,
                        "Broker returned public metadata for a different delegated key",
                    ));
                }
                if !key.supported_crypto_suites.contains(&request.crypto_suite) {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::SuiteNotAllowed,
                        "selected delegated key does not support the requested CryptoSuite",
                    ));
                }
                key_ref
            }
            None => unique_key_for_suite(&wallet.key_refs, request.crypto_suite)?,
        };
        let payload_digest = Digest32::from_bytes(Sha256::digest(&request.preimage).into());
        let claim_payload_digest =
            petal_batch_payload_digest(std::slice::from_ref(&request.preimage));
        let ordered_hash = suite_hash(request.crypto_suite, &request.preimage);
        let ProvenanceSubject::Petal {
            package_hash,
            route,
        } = &request.trusted_provenance
        else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ProvenanceMismatch,
                "Petal signing requires trusted Petal provenance",
            ));
        };
        if request.claimed_hash != ordered_hash
            || &request.claim.package_hash != package_hash
            || &request.claim.route != route
            || request.claim.operation_class != request.operation_class
            || request.claim.crypto_suite != request.crypto_suite
            || request.claim.payload_digest != claim_payload_digest
            || request.claim.ordered_hashes != [ordered_hash.clone()]
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ClaimInvalid,
                "payload, hash, operation class, or trusted Petal provenance differs from claim",
            ));
        }
        let approval_id = request.approval_id.clone().ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorCode::ApprovalNotFound,
                "payload signing requires an approval hint",
            )
        })?;
        let operation_id = request.operation_id()?;
        let (claim_digest, assurance_digest, petal_use_claim, claim_assurance_evidence) =
            match request.selector {
                bloom_broker_api::PetalSignSelector::Exact => (None, None, None, None),
                bloom_broker_api::PetalSignSelector::Reusable => (
                    Some(jcs_digest(&request.claim)?),
                    Some(jcs_digest(&request.claim.claim_assurance)?),
                    Some(request.claim),
                    request
                        .claim_assurance_evidence
                        .as_deref()
                        .map(Base64UrlBytes::from_bytes),
                ),
            };
        let operation_digest = SignOperationIdentity {
            operation_id: operation_id.clone(),
            approval_id: approval_id.clone(),
            key_ref: key_ref.clone(),
            crypto_suite: request.crypto_suite,
            ordered_payload_digests: vec![payload_digest],
            ordered_hashes: vec![ordered_hash],
            petal_use_claim_digest: claim_digest,
            claim_assurance_digest: assurance_digest,
            policy_version: wallet.policy_version,
            policy_digest: wallet.policy_digest,
        }
        .digest()?;
        self.sign(MachineSignRequest {
            operation_id,
            operation_digest,
            approval_id,
            key_ref,
            crypto_suite: request.crypto_suite,
            payloads: SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(&request.preimage),
            },
            petal_use_claim,
            claim_assurance_evidence,
            provenance: request.trusted_provenance,
        })
        .await
    }

    /// Prepare or execute one exact payload-bearing Machine/CLI operation.
    ///
    /// The caller persists the returned approval ID and reuses the exact
    /// immutable request identities after the ceremony. No hash-only fallback
    /// exists: both the payload bytes and the suite-derived hash are bound into
    /// the approval and sign operation.
    pub async fn sign_exact_payload(
        &self,
        request: ExactPayloadSignRequest,
    ) -> Result<ExactPayloadSignOutcome, ProtocolError> {
        request.validate()?;
        let wallet = self.wallet(request.wallet_id.clone()).await?;
        let payload_digest = Digest32::from_bytes(Sha256::digest(&request.preimage).into());
        let ordered_hash = suite_hash(request.crypto_suite, &request.preimage);
        if request.claimed_hash != ordered_hash {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "exact payload hash does not match the selected CryptoSuite",
            ));
        }
        let (petal_use_claim_digest, claim_assurance_digest) = match &request.petal_use_claim {
            Some(claim) => {
                let ProvenanceSubject::Petal {
                    package_hash,
                    route,
                } = &request.provenance
                else {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ProvenanceMismatch,
                        "PetalUseClaim requires trusted Petal provenance",
                    ));
                };
                if &claim.package_hash != package_hash
                    || &claim.route != route
                    || claim.crypto_suite != request.crypto_suite
                    || claim.payload_digest
                        != petal_batch_payload_digest(std::slice::from_ref(&request.preimage))
                    || claim.ordered_hashes.as_slice() != [ordered_hash.clone()]
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ProvenanceMismatch,
                        "exact Petal claim does not match trusted provenance or payload",
                    ));
                }
                (
                    Some(jcs_digest(claim)?),
                    Some(jcs_digest(&claim.claim_assurance)?),
                )
            }
            None => {
                if matches!(request.provenance, ProvenanceSubject::Petal { .. }) {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ProvenanceMismatch,
                        "trusted Petal exact signing requires a PetalUseClaim",
                    ));
                }
                if request.claim_assurance_evidence.is_some() {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::MalformedFrame,
                        "claim assurance evidence requires a PetalUseClaim",
                    ));
                }
                (None, None)
            }
        };
        let key_ref = self
            .verified_signing_key(
                &wallet,
                request.crypto_suite,
                request.account_key_ref.as_ref(),
            )
            .await?;
        let activation_mode = request
            .activation_mode
            .clone()
            .unwrap_or_else(|| default_activation_mode(&key_ref));

        if let Some(approval_id) = request.approval_id {
            let operation_digest = SignOperationIdentity {
                operation_id: request.signing_operation_id.clone(),
                approval_id: approval_id.clone(),
                key_ref: key_ref.clone(),
                crypto_suite: request.crypto_suite,
                ordered_payload_digests: vec![payload_digest],
                ordered_hashes: vec![ordered_hash],
                petal_use_claim_digest,
                claim_assurance_digest,
                policy_version: wallet.policy_version,
                policy_digest: wallet.policy_digest,
            }
            .digest()?;
            return self
                .sign(MachineSignRequest {
                    operation_id: request.signing_operation_id,
                    operation_digest,
                    approval_id,
                    key_ref,
                    crypto_suite: request.crypto_suite,
                    payloads: SigningPayloads::Single {
                        payload: Base64UrlBytes::from_bytes(&request.preimage),
                    },
                    petal_use_claim: request.petal_use_claim,
                    claim_assurance_evidence: request
                        .claim_assurance_evidence
                        .as_deref()
                        .map(Base64UrlBytes::from_bytes),
                    provenance: request.provenance,
                })
                .await
                .map(ExactPayloadSignOutcome::Signed);
        }

        let terms = SealedApprovalTerms {
            subject: approval_subject(&request.provenance),
            wallet_id: request.wallet_id,
            key_ref,
            allowed_crypto_suites: vec![request.crypto_suite],
            selector: ApprovalSelector::Exact {
                ordered_payload_digests: vec![payload_digest],
                ordered_hashes: vec![ordered_hash],
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(1),
                operation_rate_limits: Vec::new(),
                signature_rate_limits: Vec::new(),
                value_limits: Vec::new(),
            },
            activation_mode,
            wallet_revocation_epoch: wallet.wallet_revocation_epoch,
            policy_version: wallet.policy_version,
            policy_digest: wallet.policy_digest,
            provenance_digest: request.provenance_digest,
            request_nonce: request.request_nonce,
            issued_at_ms: request.issued_at_ms.clone(),
            not_before_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            renewal_of: None,
        };
        terms.validate()?;
        self.prepare_approval(ApprovalPrepareRequest {
            operation_id: request.approval_operation_id,
            terms,
            canonical_plan_facts_digest: request.canonical_plan_facts_digest,
        })
        .await
        .map(ExactPayloadSignOutcome::ApprovalRequired)
    }

    /// Prepare or execute one exact ordered payload batch using the existing
    /// `sealed_approval.prepare` and `signing.sign_batch` wire methods.
    ///
    /// The ordered payload bytes, suite-derived hashes, approval identity, and
    /// Broker operation identity are all frozen together. A caller may retry
    /// the same durable request after ceremony completion; it cannot replace,
    /// reorder, add, or remove a child without invalidating the selector and
    /// operation digest.
    pub async fn sign_exact_payload_batch(
        &self,
        request: ExactPayloadBatchSignRequest,
    ) -> Result<ExactPayloadSignOutcome, ProtocolError> {
        request.validate()?;
        let wallet = self.wallet(request.wallet_id.clone()).await?;
        let ordered_payload_digests = request
            .preimages
            .iter()
            .map(|payload| Digest32::from_bytes(Sha256::digest(payload).into()))
            .collect::<Vec<_>>();
        let ordered_hashes = request
            .preimages
            .iter()
            .map(|payload| suite_hash(request.crypto_suite, payload))
            .collect::<Vec<_>>();
        if request.claimed_hashes != ordered_hashes {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "exact batch payload hashes do not match the selected CryptoSuite",
            ));
        }
        let (petal_use_claim_digest, claim_assurance_digest) = match &request.petal_use_claim {
            Some(claim) => {
                let ProvenanceSubject::Petal {
                    package_hash,
                    route,
                } = &request.provenance
                else {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ProvenanceMismatch,
                        "PetalUseClaim requires trusted Petal provenance",
                    ));
                };
                if &claim.package_hash != package_hash
                    || &claim.route != route
                    || claim.crypto_suite != request.crypto_suite
                    || claim.payload_digest != petal_batch_payload_digest(&request.preimages)
                    || claim.ordered_hashes != ordered_hashes
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ProvenanceMismatch,
                        "exact Petal batch claim does not match trusted provenance or payloads",
                    ));
                }
                (
                    Some(jcs_digest(claim)?),
                    Some(jcs_digest(&claim.claim_assurance)?),
                )
            }
            None => {
                if matches!(request.provenance, ProvenanceSubject::Petal { .. }) {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::ProvenanceMismatch,
                        "trusted Petal exact batch signing requires a PetalUseClaim",
                    ));
                }
                if request.claim_assurance_evidence.is_some() {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::MalformedFrame,
                        "claim assurance evidence requires a PetalUseClaim",
                    ));
                }
                (None, None)
            }
        };
        let key_ref = self
            .verified_signing_key(
                &wallet,
                request.crypto_suite,
                request.account_key_ref.as_ref(),
            )
            .await?;
        let activation_mode = request
            .activation_mode
            .clone()
            .unwrap_or_else(|| default_activation_mode(&key_ref));

        if let Some(approval_id) = request.approval_id {
            let operation_digest = SignOperationIdentity {
                operation_id: request.signing_operation_id.clone(),
                approval_id: approval_id.clone(),
                key_ref: key_ref.clone(),
                crypto_suite: request.crypto_suite,
                ordered_payload_digests: ordered_payload_digests.clone(),
                ordered_hashes: ordered_hashes.clone(),
                petal_use_claim_digest,
                claim_assurance_digest,
                policy_version: wallet.policy_version,
                policy_digest: wallet.policy_digest,
            }
            .digest()?;
            return self
                .sign_batch(MachineSignRequest {
                    operation_id: request.signing_operation_id,
                    operation_digest,
                    approval_id,
                    key_ref,
                    crypto_suite: request.crypto_suite,
                    payloads: SigningPayloads::Batch {
                        children: request
                            .preimages
                            .iter()
                            .map(|payload| Base64UrlBytes::from_bytes(payload))
                            .collect(),
                    },
                    petal_use_claim: request.petal_use_claim,
                    claim_assurance_evidence: request
                        .claim_assurance_evidence
                        .as_deref()
                        .map(Base64UrlBytes::from_bytes),
                    provenance: request.provenance,
                })
                .await
                .map(ExactPayloadSignOutcome::Signed);
        }

        let signature_count = u64::try_from(request.preimages.len()).map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::LimitExceededSignatures,
                "exact batch signature count exceeds protocol limits",
            )
        })?;
        let terms = SealedApprovalTerms {
            subject: approval_subject(&request.provenance),
            wallet_id: request.wallet_id,
            key_ref,
            allowed_crypto_suites: vec![request.crypto_suite],
            selector: ApprovalSelector::Exact {
                ordered_payload_digests,
                ordered_hashes,
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(signature_count),
                operation_rate_limits: Vec::new(),
                signature_rate_limits: Vec::new(),
                value_limits: Vec::new(),
            },
            activation_mode,
            wallet_revocation_epoch: wallet.wallet_revocation_epoch,
            policy_version: wallet.policy_version,
            policy_digest: wallet.policy_digest,
            provenance_digest: request.provenance_digest,
            request_nonce: request.request_nonce,
            issued_at_ms: request.issued_at_ms.clone(),
            not_before_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            renewal_of: None,
        };
        terms.validate()?;
        self.prepare_approval(ApprovalPrepareRequest {
            operation_id: request.approval_operation_id,
            terms,
            canonical_plan_facts_digest: request.canonical_plan_facts_digest,
        })
        .await
        .map(ExactPayloadSignOutcome::ApprovalRequired)
    }

    /// Prepare or execute one Petal-scoped payload batch. Unlike the exact
    /// selector, the approval binds the installer-authenticated package,
    /// route, operation class, wallet and assurance level, so a short-lived
    /// venue timestamp may be refreshed after the owner completes ceremony.
    /// The one-operation/signature-count limits still make the approval
    /// single-use and bounded to this batch.
    pub async fn sign_reusable_petal_payload_batch(
        &self,
        request: ExactPayloadBatchSignRequest,
    ) -> Result<ExactPayloadSignOutcome, ProtocolError> {
        request.validate()?;
        let claim = request.petal_use_claim.as_ref().ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorCode::ClaimInvalid,
                "reusable Petal batch signing requires a PetalUseClaim",
            )
        })?;
        let ProvenanceSubject::Petal {
            package_hash,
            route,
        } = &request.provenance
        else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ProvenanceMismatch,
                "reusable Petal batch signing requires trusted Petal provenance",
            ));
        };
        let ordered_payload_digests = request
            .preimages
            .iter()
            .map(|payload| Digest32::from_bytes(Sha256::digest(payload).into()))
            .collect::<Vec<_>>();
        let ordered_hashes = request
            .preimages
            .iter()
            .map(|payload| suite_hash(request.crypto_suite, payload))
            .collect::<Vec<_>>();
        if request.claimed_hashes != ordered_hashes
            || &claim.package_hash != package_hash
            || &claim.route != route
            || claim.operation_class.as_str() == ""
            || claim.crypto_suite != request.crypto_suite
            || claim.payload_digest != petal_batch_payload_digest(&request.preimages)
            || claim.ordered_hashes != ordered_hashes
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ClaimInvalid,
                "reusable Petal batch claim does not match provenance or payloads",
            ));
        }
        let wallet = self.wallet(request.wallet_id.clone()).await?;
        let key_ref = self
            .verified_signing_key(
                &wallet,
                request.crypto_suite,
                request.account_key_ref.as_ref(),
            )
            .await?;
        let activation_mode = request
            .activation_mode
            .clone()
            .unwrap_or_else(|| default_activation_mode(&key_ref));
        let claim_digest = Some(jcs_digest(claim)?);
        let assurance_digest = Some(jcs_digest(&claim.claim_assurance)?);

        if let Some(approval_id) = request.approval_id {
            let operation_digest = SignOperationIdentity {
                operation_id: request.signing_operation_id.clone(),
                approval_id: approval_id.clone(),
                key_ref: key_ref.clone(),
                crypto_suite: request.crypto_suite,
                ordered_payload_digests,
                ordered_hashes,
                petal_use_claim_digest: claim_digest,
                claim_assurance_digest: assurance_digest,
                policy_version: wallet.policy_version,
                policy_digest: wallet.policy_digest,
            }
            .digest()?;
            return self
                .sign_batch(MachineSignRequest {
                    operation_id: request.signing_operation_id,
                    operation_digest,
                    approval_id,
                    key_ref,
                    crypto_suite: request.crypto_suite,
                    payloads: SigningPayloads::Batch {
                        children: request
                            .preimages
                            .iter()
                            .map(|payload| Base64UrlBytes::from_bytes(payload))
                            .collect(),
                    },
                    petal_use_claim: Some(claim.clone()),
                    claim_assurance_evidence: request
                        .claim_assurance_evidence
                        .as_deref()
                        .map(Base64UrlBytes::from_bytes),
                    provenance: request.provenance,
                })
                .await
                .map(ExactPayloadSignOutcome::Signed);
        }

        let signature_count = u64::try_from(request.preimages.len()).map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCode::LimitExceededSignatures,
                "reusable batch signature count exceeds protocol limits",
            )
        })?;
        let operation_class = claim.operation_class.clone();
        let terms = SealedApprovalTerms {
            subject: approval_subject(&request.provenance),
            wallet_id: request.wallet_id,
            key_ref,
            allowed_crypto_suites: vec![request.crypto_suite],
            selector: ApprovalSelector::Petal {
                package_hash: package_hash.clone(),
                route: route.clone(),
                allowed_operation_classes: vec![operation_class],
                route_grants: Vec::new(),
                required_claim_assurance: claim.claim_assurance.level(),
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(signature_count),
                operation_rate_limits: Vec::new(),
                signature_rate_limits: Vec::new(),
                value_limits: Vec::new(),
            },
            activation_mode,
            wallet_revocation_epoch: wallet.wallet_revocation_epoch,
            policy_version: wallet.policy_version,
            policy_digest: wallet.policy_digest,
            provenance_digest: request.provenance_digest,
            request_nonce: request.request_nonce,
            issued_at_ms: request.issued_at_ms.clone(),
            not_before_ms: request.issued_at_ms,
            expires_at_ms: request.expires_at_ms,
            renewal_of: None,
        };
        terms.validate()?;
        self.prepare_approval(ApprovalPrepareRequest {
            operation_id: request.approval_operation_id,
            terms,
            canonical_plan_facts_digest: request.canonical_plan_facts_digest,
        })
        .await
        .map(ExactPayloadSignOutcome::ApprovalRequired)
    }

    pub async fn prepare_approval(
        &self,
        request: ApprovalPrepareRequest,
    ) -> Result<SealedApprovalPrepareResponse, ProtocolError> {
        let expected_approval_id = request.terms.approval_id()?;
        match self
            .request(MachineBrokerRequest::SealedApprovalPrepare(request))
            .await?
        {
            MachineBrokerResponse::SealedApprovalPrepare(response)
                if response.approval_id == expected_approval_id =>
            {
                Ok(response)
            }
            MachineBrokerResponse::SealedApprovalPrepare(_) => {
                Err(response_identity_mismatch("sealed_approval.prepare"))
            }
            _ => Err(response_mismatch("sealed_approval.prepare")),
        }
    }

    pub async fn approval_status(
        &self,
        approval_id: Digest32,
    ) -> Result<ApprovalPublicStatus, ProtocolError> {
        match self
            .request(MachineBrokerRequest::SealedApprovalStatus(IdRequest {
                id: approval_id,
            }))
            .await?
        {
            MachineBrokerResponse::SealedApprovalStatus(status) => Ok(status),
            _ => Err(response_mismatch("sealed_approval.status")),
        }
    }

    pub async fn list_approvals(
        &self,
        wallet_id: Token,
    ) -> Result<Vec<ApprovalPublicStatus>, ProtocolError> {
        match self
            .request(MachineBrokerRequest::SealedApprovalList(WalletRequest {
                wallet_id,
            }))
            .await?
        {
            MachineBrokerResponse::SealedApprovalList(statuses) => Ok(statuses),
            _ => Err(response_mismatch("sealed_approval.list")),
        }
    }

    pub async fn approval_limit_state(
        &self,
        approval_id: Digest32,
    ) -> Result<ApprovalLimitState, ProtocolError> {
        match self
            .request(MachineBrokerRequest::SealedApprovalLimitState(IdRequest {
                id: approval_id,
            }))
            .await?
        {
            MachineBrokerResponse::SealedApprovalLimitState(state) => Ok(state),
            _ => Err(response_mismatch("sealed_approval.limit_state")),
        }
    }

    pub async fn renew_approval(
        &self,
        request: ApprovalRenewRequest,
    ) -> Result<SealedApprovalPrepareResponse, ProtocolError> {
        let expected_approval_id = request.replacement_terms.approval_id()?;
        match self
            .request(MachineBrokerRequest::SealedApprovalRenew(request))
            .await?
        {
            MachineBrokerResponse::SealedApprovalRenew(response)
                if response.approval_id == expected_approval_id =>
            {
                Ok(response)
            }
            MachineBrokerResponse::SealedApprovalRenew(_) => {
                Err(response_identity_mismatch("sealed_approval.renew"))
            }
            _ => Err(response_mismatch("sealed_approval.renew")),
        }
    }

    pub async fn revoke_approval(
        &self,
        request: RevokeRequest,
    ) -> Result<ApprovalPublicStatus, ProtocolError> {
        match self
            .request(MachineBrokerRequest::SealedApprovalRevoke(request))
            .await?
        {
            MachineBrokerResponse::SealedApprovalRevoke(status) => Ok(status),
            _ => Err(response_mismatch("sealed_approval.revoke")),
        }
    }

    pub async fn revoke_all_approvals(
        &self,
        request: WalletOperationRequest,
    ) -> Result<RevocationState, ProtocolError> {
        match self
            .request(MachineBrokerRequest::SealedApprovalRevokeAll(request))
            .await?
        {
            MachineBrokerResponse::SealedApprovalRevokeAll(state) => Ok(state),
            _ => Err(response_mismatch("sealed_approval.revoke_all")),
        }
    }

    pub async fn operation_status(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationPublicStatus, ProtocolError> {
        match self
            .request(MachineBrokerRequest::OperationStatus(OperationRequest {
                operation_id,
            }))
            .await?
        {
            MachineBrokerResponse::OperationStatus(status) => Ok(status),
            _ => Err(response_mismatch("operation.status")),
        }
    }

    /// Cancel a Broker operation only while Broker can prove it has not crossed
    /// the downstream-acceptance boundary. This is deliberately distinct from
    /// ceremony cancellation and never attempts backend or Signer cancellation.
    pub async fn cancel_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationPublicStatus, ProtocolError> {
        match self
            .request(MachineBrokerRequest::OperationCancel(OperationRequest {
                operation_id,
            }))
            .await?
        {
            MachineBrokerResponse::OperationCancel(status) => Ok(status),
            _ => Err(response_mismatch("operation.cancel")),
        }
    }

    pub async fn policy(&self, wallet_id: Token) -> Result<SignedPolicySnapshot, ProtocolError> {
        match self
            .request(MachineBrokerRequest::PolicyRead(WalletRequest {
                wallet_id,
            }))
            .await?
        {
            MachineBrokerResponse::PolicyRead(policy) => Ok(policy),
            _ => Err(response_mismatch("policy.read")),
        }
    }

    pub async fn validate_policy_update(
        &self,
        request: PolicyUpdateRequest,
    ) -> Result<PolicyUpdatePrepareResponse, ProtocolError> {
        let expected_operation_id = request.operation_id.clone();
        match self
            .request(MachineBrokerRequest::PolicyValidateUpdate(request))
            .await?
        {
            MachineBrokerResponse::PolicyValidateUpdate(response)
                if response.operation_id == expected_operation_id
                    && response.ceremony_kind == bloom_broker_api::CeremonyKind::PolicyUpdate =>
            {
                Ok(response)
            }
            MachineBrokerResponse::PolicyValidateUpdate(_) => {
                Err(response_identity_mismatch("policy.validate_update"))
            }
            _ => Err(response_mismatch("policy.validate_update")),
        }
    }

    pub async fn commit_policy_update(
        &self,
        request: PolicyCommitUpdateRequest,
    ) -> Result<PolicyCommitReceipt, ProtocolError> {
        match self
            .request(MachineBrokerRequest::PolicyCommitUpdate(request))
            .await?
        {
            MachineBrokerResponse::PolicyCommitUpdate(receipt) => Ok(receipt),
            _ => Err(response_mismatch("policy.commit_update")),
        }
    }

    pub async fn ceremony_status(
        &self,
        operation_id: OperationId,
    ) -> Result<CeremonyPublicStatus, ProtocolError> {
        let id = Digest32::new(operation_id.as_str().to_owned())?;
        match self
            .request(MachineBrokerRequest::CeremonyStatus(IdRequest { id }))
            .await?
        {
            MachineBrokerResponse::CeremonyStatus(status) => Ok(status),
            _ => Err(response_mismatch("ceremony.status")),
        }
    }

    pub async fn cancel_ceremony(
        &self,
        operation_id: OperationId,
    ) -> Result<CeremonyPublicStatus, ProtocolError> {
        let id = Digest32::new(operation_id.as_str().to_owned())?;
        match self
            .request(MachineBrokerRequest::CeremonyCancel(IdRequest { id }))
            .await?
        {
            MachineBrokerResponse::CeremonyCancel(status) => Ok(status),
            _ => Err(response_mismatch("ceremony.cancel")),
        }
    }

    pub async fn wallets(&self) -> Result<Vec<WalletPublic>, ProtocolError> {
        match self
            .request(MachineBrokerRequest::WalletListPublic(
                bloom_broker_api::Empty {},
            ))
            .await?
        {
            MachineBrokerResponse::WalletListPublic(wallets) => Ok(wallets),
            _ => Err(response_mismatch("wallet.list_public")),
        }
    }

    pub async fn wallet(&self, wallet_id: Token) -> Result<WalletPublic, ProtocolError> {
        match self
            .request(MachineBrokerRequest::WalletGetPublic(WalletRequest {
                wallet_id,
            }))
            .await?
        {
            MachineBrokerResponse::WalletGetPublic(wallet) => Ok(wallet),
            _ => Err(response_mismatch("wallet.get_public")),
        }
    }

    pub async fn keys(&self, wallet_id: Token) -> Result<Vec<KeyPublic>, ProtocolError> {
        match self
            .request(MachineBrokerRequest::KeyListPublic(WalletRequest {
                wallet_id,
            }))
            .await?
        {
            MachineBrokerResponse::KeyListPublic(keys) => Ok(keys),
            _ => Err(response_mismatch("key.list_public")),
        }
    }

    /// The wallet's derived-account projection (BIP-39 only). Imported-scalar
    /// and legacy wallets project an empty collection.
    pub async fn wallet_accounts(
        &self,
        wallet_id: Token,
    ) -> Result<WalletAccountsPublic, ProtocolError> {
        match self
            .request(MachineBrokerRequest::WalletAccounts(WalletRequest {
                wallet_id,
            }))
            .await?
        {
            MachineBrokerResponse::WalletAccounts(accounts) => Ok(accounts),
            _ => Err(response_mismatch("wallet.accounts")),
        }
    }

    /// Prepare an AccountAllocate custody ceremony bound to exact terms.
    pub async fn account_allocate(
        &self,
        request: CustodyPrepareRequest,
    ) -> Result<CustodyPrepareResponse, ProtocolError> {
        match self
            .request(MachineBrokerRequest::AccountAllocatePrepare(request))
            .await?
        {
            MachineBrokerResponse::AccountAllocatePrepare(prepared) => Ok(prepared),
            _ => Err(response_mismatch("account.allocate_prepare")),
        }
    }

    pub async fn key(&self, request: KeyRequest) -> Result<KeyPublic, ProtocolError> {
        match self
            .request(MachineBrokerRequest::KeyGetPublic(request))
            .await?
        {
            MachineBrokerResponse::KeyGetPublic(key) => Ok(key),
            _ => Err(response_mismatch("key.get_public")),
        }
    }

    /// The wallet's signable key for `suite`: the root for legacy/imported-scalar
    /// wallets, or a derived child for BIP-39 wallets (whose root is a
    /// non-signable seed).
    ///
    /// `selected` names one exact derived account. It is required whenever a
    /// BIP-39 wallet holds more than one child for `suite` — without it the
    /// choice is ambiguous, so selection fails closed rather than guessing.
    /// The key returned here is bound into `SealedApprovalTerms::key_ref` when
    /// an approval is prepared and into `SignOperationIdentity::key_ref` when
    /// one is spent, so an approval issued for one account can never authorise
    /// a signature from another.
    async fn verified_signing_key(
        &self,
        wallet: &WalletPublic,
        suite: CryptoSuite,
        selected: Option<&KeyRef>,
    ) -> Result<KeyRef, ProtocolError> {
        let (key_ref, expected_role) = match &wallet.root_key_ref {
            Some(root) => {
                if let Some(selected) = selected
                    && selected != root
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::KeyrefMismatch,
                        "wallet signs with its root key; no derived account may be selected",
                    ));
                }
                (root.clone(), KeyRole::WalletRoot)
            }
            None => {
                let matching: Vec<&KeyRef> = wallet
                    .key_refs
                    .iter()
                    .filter(|key| key.key_spec == suite.key_spec())
                    .collect();
                match selected {
                    Some(selected) => {
                        let chosen = matching
                            .iter()
                            .copied()
                            .find(|key| *key == selected)
                            .ok_or_else(|| {
                                ProtocolError::new(
                                    ProtocolErrorCode::KeyrefMismatch,
                                    format!(
                                        "selected account is not a derived child of this wallet \
                                         for the requested CryptoSuite; this wallet offers: {}",
                                        describe_candidates(&matching),
                                    ),
                                )
                            })?;
                        (chosen.clone(), KeyRole::Derived)
                    }
                    None => match matching.as_slice() {
                        [child] => ((*child).clone(), KeyRole::Derived),
                        [] => {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::KeyrefMismatch,
                                "BIP-39 wallet has no derived child for the requested CryptoSuite",
                            ));
                        }
                        // Never fall back to the first match. The candidates
                        // are named so the caller can pick one, because an
                        // error that only says "ambiguous" leaves no way
                        // forward.
                        candidates => {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::KeyrefMismatch,
                                format!(
                                    "BIP-39 wallet has {} derived children for the requested \
                                     CryptoSuite; select one by account fingerprint: {}",
                                    candidates.len(),
                                    describe_candidates(candidates),
                                ),
                            ));
                        }
                    },
                }
            }
        };
        if !wallet.key_refs.contains(&key_ref) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "wallet signing key is absent from the wallet key set",
            ));
        }
        if key_ref.key_spec != suite.key_spec() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SuiteNotAllowed,
                "wallet signing key is incompatible with the requested CryptoSuite",
            ));
        }
        let public = self
            .key(KeyRequest {
                key_ref: key_ref.clone(),
            })
            .await?;
        if public.key_ref != key_ref || public.role != expected_role {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "Broker did not confirm the selected wallet signing key",
            ));
        }
        if !public.supported_crypto_suites.contains(&suite) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SuiteNotAllowed,
                "wallet signing key does not support the requested CryptoSuite",
            ));
        }
        Ok(key_ref)
    }

    pub async fn credentials(
        &self,
        wallet_id: Token,
    ) -> Result<Vec<CredentialPublic>, ProtocolError> {
        match self
            .request(MachineBrokerRequest::CredentialListPublic(WalletRequest {
                wallet_id,
            }))
            .await?
        {
            MachineBrokerResponse::CredentialListPublic(credentials) => Ok(credentials),
            _ => Err(response_mismatch("credential.list_public")),
        }
    }

    pub async fn custody_result(
        &self,
        request: OperationRequest,
    ) -> Result<CustodyResult, ProtocolError> {
        match self
            .request(MachineBrokerRequest::CustodyResult(request))
            .await?
        {
            MachineBrokerResponse::CustodyResult(result) => Ok(result),
            _ => Err(response_mismatch("custody.result")),
        }
    }

    pub async fn prepare_custody(
        &self,
        method: CustodyPrepareMethod,
        request: CustodyPrepareRequest,
    ) -> Result<CustodyPrepareResponse, ProtocolError> {
        let expected_operation_id = request.custody_operation_id.clone();
        let expected_ceremony_kind = request.ceremony_kind;
        let request = match method {
            CustodyPrepareMethod::WalletRegistration => {
                MachineBrokerRequest::WalletRegistrationPrepare(request)
            }
            CustodyPrepareMethod::WalletUnlock => {
                MachineBrokerRequest::WalletUnlockPrepare(request)
            }
            CustodyPrepareMethod::WalletImport => {
                MachineBrokerRequest::WalletImportPrepare(request)
            }
            CustodyPrepareMethod::WalletExport => {
                MachineBrokerRequest::WalletExportPrepare(request)
            }
            CustodyPrepareMethod::WalletDelete => {
                MachineBrokerRequest::WalletDeletePrepare(request)
            }
            CustodyPrepareMethod::KeyDerive => MachineBrokerRequest::KeyDerivePrepare(request),
            CustodyPrepareMethod::KeyEnroll => MachineBrokerRequest::KeyEnrollPrepare(request),
            CustodyPrepareMethod::CredentialAdd => {
                MachineBrokerRequest::CredentialAddPrepare(request)
            }
            CustodyPrepareMethod::CredentialReplace => {
                MachineBrokerRequest::CredentialReplacePrepare(request)
            }
            CustodyPrepareMethod::CredentialRemove => {
                MachineBrokerRequest::CredentialRemovePrepare(request)
            }
            CustodyPrepareMethod::Recovery => MachineBrokerRequest::RecoveryPrepare(request),
        };
        let expected = method.wire_name();
        match (method, self.request(request).await?) {
            (
                CustodyPrepareMethod::WalletRegistration,
                MachineBrokerResponse::WalletRegistrationPrepare(response),
            )
            | (
                CustodyPrepareMethod::WalletUnlock,
                MachineBrokerResponse::WalletUnlockPrepare(response),
            )
            | (
                CustodyPrepareMethod::WalletImport,
                MachineBrokerResponse::WalletImportPrepare(response),
            )
            | (
                CustodyPrepareMethod::WalletExport,
                MachineBrokerResponse::WalletExportPrepare(response),
            )
            | (
                CustodyPrepareMethod::WalletDelete,
                MachineBrokerResponse::WalletDeletePrepare(response),
            )
            | (
                CustodyPrepareMethod::KeyDerive,
                MachineBrokerResponse::KeyDerivePrepare(response),
            )
            | (
                CustodyPrepareMethod::KeyEnroll,
                MachineBrokerResponse::KeyEnrollPrepare(response),
            )
            | (
                CustodyPrepareMethod::CredentialAdd,
                MachineBrokerResponse::CredentialAddPrepare(response),
            )
            | (
                CustodyPrepareMethod::CredentialReplace,
                MachineBrokerResponse::CredentialReplacePrepare(response),
            )
            | (
                CustodyPrepareMethod::CredentialRemove,
                MachineBrokerResponse::CredentialRemovePrepare(response),
            )
            | (CustodyPrepareMethod::Recovery, MachineBrokerResponse::RecoveryPrepare(response)) => {
                if response.custody_operation_id != expected_operation_id
                    || response.ceremony_kind != expected_ceremony_kind
                {
                    Err(response_identity_mismatch(expected))
                } else {
                    Ok(response)
                }
            }
            _ => Err(response_mismatch(expected)),
        }
    }
}

struct ExpectedSigningResult {
    operation_id: OperationId,
    operation_digest: Digest32,
    crypto_suite: CryptoSuite,
    signature_count: usize,
}

impl ExpectedSigningResult {
    fn from_request(request: &MachineSignRequest) -> Self {
        let signature_count = match &request.payloads {
            SigningPayloads::Single { .. } => 1,
            SigningPayloads::Batch { children } => children.len(),
        };
        Self {
            operation_id: request.operation_id.clone(),
            operation_digest: request.operation_digest.clone(),
            crypto_suite: request.crypto_suite,
            signature_count,
        }
    }

    fn validate(&self, result: SigningResult) -> Result<SigningResult, ProtocolError> {
        let expected_length = match self.crypto_suite.signature_encoding() {
            bloom_broker_api::SignatureEncoding::Secp256k1Recoverable65 => 65,
            bloom_broker_api::SignatureEncoding::Ed25519Raw64 => 64,
        };
        if result.operation_id != self.operation_id
            || result.operation_digest != self.operation_digest
            || result.signatures.len() != self.signature_count
            || result.signatures.iter().any(|signature| {
                signature.crypto_suite != self.crypto_suite
                    || signature.bytes.decode().len() != expected_length
            })
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "Broker signing response does not match operation, digest, count, suite, or encoding",
            ));
        }
        Ok(result)
    }
}

#[derive(Clone, Debug)]
pub struct TrustedPetalSignRequest {
    pub wallet_id: Token,
    pub preimage: Vec<u8>,
    pub claimed_hash: Digest32,
    pub crypto_suite: CryptoSuite,
    pub operation_class: Token,
    pub selector: bloom_broker_api::PetalSignSelector,
    pub claim: PetalUseClaim,
    pub claim_assurance_evidence: Option<Vec<u8>>,
    pub approval_id: Option<Digest32>,
    pub trusted_provenance: ProvenanceSubject,
    pub frozen_action: Option<Vec<u8>>,
    pub frozen_advisory: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ExactPayloadSignRequest {
    pub wallet_id: Token,
    pub preimage: Vec<u8>,
    pub claimed_hash: Digest32,
    pub crypto_suite: CryptoSuite,
    pub provenance: ProvenanceSubject,
    pub provenance_digest: Digest32,
    /// `None` selects the fail-closed v1 default: boot-bound for local keys and
    /// backend-managed for non-local enrolled backends.
    pub activation_mode: Option<ActivationMode>,
    pub approval_operation_id: OperationId,
    pub signing_operation_id: OperationId,
    pub request_nonce: RequestNonce,
    pub issued_at_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub canonical_plan_facts_digest: Digest32,
    pub approval_id: Option<Digest32>,
    pub petal_use_claim: Option<PetalUseClaim>,
    pub claim_assurance_evidence: Option<Vec<u8>>,
    /// The exact derived account to sign with. Required when the wallet is
    /// BIP-39 and holds more than one child for `crypto_suite`; `None` keeps
    /// the single-account and legacy-root behaviour.
    pub account_key_ref: Option<KeyRef>,
}

#[derive(Clone, Debug)]
pub struct ExactPayloadBatchSignRequest {
    pub wallet_id: Token,
    pub preimages: Vec<Vec<u8>>,
    pub claimed_hashes: Vec<Digest32>,
    pub crypto_suite: CryptoSuite,
    pub provenance: ProvenanceSubject,
    pub provenance_digest: Digest32,
    /// `None` selects the fail-closed v1 default: boot-bound for local keys and
    /// backend-managed for non-local enrolled backends.
    pub activation_mode: Option<ActivationMode>,
    pub approval_operation_id: OperationId,
    pub signing_operation_id: OperationId,
    pub request_nonce: RequestNonce,
    pub issued_at_ms: DecimalU64,
    pub expires_at_ms: DecimalU64,
    pub canonical_plan_facts_digest: Digest32,
    pub approval_id: Option<Digest32>,
    pub petal_use_claim: Option<PetalUseClaim>,
    pub claim_assurance_evidence: Option<Vec<u8>>,
    /// The exact derived account to sign with. Required when the wallet is
    /// BIP-39 and holds more than one child for `crypto_suite`; `None` keeps
    /// the single-account and legacy-root behaviour.
    pub account_key_ref: Option<KeyRef>,
}

impl ExactPayloadBatchSignRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.expires_at_ms.get() <= self.issued_at_ms.get() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "exact batch approval validity interval is invalid",
            ));
        }
        if self.preimages.len() != self.claimed_hashes.len() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "exact batch payload and claimed-hash counts differ",
            ));
        }
        SigningPayloads::Batch {
            children: self
                .preimages
                .iter()
                .map(|payload| Base64UrlBytes::from_bytes(payload))
                .collect(),
        }
        .validate()
    }
}

impl ExactPayloadSignRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.expires_at_ms.get() <= self.issued_at_ms.get() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "exact approval validity interval is invalid",
            ));
        }
        SigningPayloads::Single {
            payload: Base64UrlBytes::from_bytes(&self.preimage),
        }
        .validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactPayloadSignOutcome {
    ApprovalRequired(SealedApprovalPrepareResponse),
    Signed(SigningResult),
}

/// Durable Machine projection of a Broker-owned ceremony. Launch secrets are
/// retained only while Broker reports an actionable awaiting state.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyProjection {
    identity: Option<CeremonyProjectionIdentity>,
    ceremony_state: Option<CeremonyProjectionState>,
    ceremony_url: Option<String>,
    ceremony_expires_at_ms: Option<DecimalU64>,
    review_manifest_digest: Option<Digest32>,
    receipt_digest: Option<Digest32>,
    last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CeremonyProjectionIdentity {
    Approval {
        approval_id: Digest32,
    },
    Custody {
        operation_id: OperationId,
        ceremony_kind: bloom_broker_api::CeremonyKind,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "state", rename_all = "snake_case")]
pub enum CeremonyProjectionState {
    Approval(ApprovalLifecycleState),
    Custody(CeremonyState),
}

impl CeremonyProjection {
    pub fn from_approval_prepare(
        response: &SealedApprovalPrepareResponse,
        now_ms: u64,
    ) -> Result<Self, ProtocolError> {
        if response.state != bloom_broker_api::ApprovalPrepareState::AwaitingCeremony {
            return Err(projection_mismatch(
                "approval prepare is not awaiting ceremony",
            ));
        }
        Self::awaiting(
            CeremonyProjectionIdentity::Approval {
                approval_id: response.approval_id.clone(),
            },
            CeremonyProjectionState::Approval(ApprovalLifecycleState::AwaitingCeremony),
            response.ceremony_url.clone(),
            response.ceremony_expires_at_ms.clone(),
            Some(response.review_manifest_digest.clone()),
            now_ms,
        )
    }

    pub fn from_custody_prepare(
        response: &CustodyPrepareResponse,
        now_ms: u64,
    ) -> Result<Self, ProtocolError> {
        if response.state != bloom_broker_api::CustodyPrepareState::AwaitingUser {
            return Err(projection_mismatch("custody prepare is not awaiting user"));
        }
        Self::awaiting(
            CeremonyProjectionIdentity::Custody {
                operation_id: response.custody_operation_id.clone(),
                ceremony_kind: response.ceremony_kind,
            },
            CeremonyProjectionState::Custody(CeremonyState::AwaitingUser),
            response.ceremony_url.clone(),
            response.ceremony_expires_at_ms.clone(),
            None,
            now_ms,
        )
    }

    pub fn from_policy_prepare(
        response: &PolicyUpdatePrepareResponse,
        now_ms: u64,
    ) -> Result<Self, ProtocolError> {
        if response.ceremony_kind != bloom_broker_api::CeremonyKind::PolicyUpdate {
            return Err(projection_mismatch(
                "policy prepare did not return policy_update ceremony kind",
            ));
        }
        Self::awaiting(
            CeremonyProjectionIdentity::Custody {
                operation_id: response.operation_id.clone(),
                ceremony_kind: response.ceremony_kind,
            },
            CeremonyProjectionState::Custody(CeremonyState::AwaitingUser),
            response.ceremony_url.clone(),
            response.ceremony_expires_at_ms.clone(),
            Some(response.review_manifest_digest.clone()),
            now_ms,
        )
    }

    pub fn from_custody_status(
        status: &CeremonyPublicStatus,
        now_ms: u64,
    ) -> Result<Self, ProtocolError> {
        if status.state != CeremonyState::AwaitingUser {
            return Ok(Self {
                identity: Some(CeremonyProjectionIdentity::Custody {
                    operation_id: status.operation_id.clone(),
                    ceremony_kind: status.ceremony_kind,
                }),
                ceremony_state: Some(CeremonyProjectionState::Custody(status.state)),
                ceremony_url: None,
                ceremony_expires_at_ms: None,
                review_manifest_digest: None,
                receipt_digest: status.receipt_digest.clone(),
                last_error: None,
            });
        }
        let url = status.ceremony_url.clone().ok_or_else(|| {
            projection_mismatch("awaiting custody status is missing ceremony URL")
        })?;
        Self::awaiting(
            CeremonyProjectionIdentity::Custody {
                operation_id: status.operation_id.clone(),
                ceremony_kind: status.ceremony_kind,
            },
            CeremonyProjectionState::Custody(status.state),
            url,
            status.expires_at_ms.clone(),
            None,
            now_ms,
        )
    }

    pub fn from_custody_result(result: &CustodyResult) -> Self {
        Self {
            identity: Some(CeremonyProjectionIdentity::Custody {
                operation_id: result.custody_operation_id.clone(),
                ceremony_kind: result.ceremony_kind,
            }),
            ceremony_state: Some(CeremonyProjectionState::Custody(result.public_status)),
            ceremony_url: None,
            ceremony_expires_at_ms: None,
            receipt_digest: Some(result.receipt_digest.clone()),
            review_manifest_digest: None,
            last_error: None,
        }
    }

    pub fn reconcile_approval(
        &mut self,
        status: &ApprovalPublicStatus,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        if self.identity
            != Some(CeremonyProjectionIdentity::Approval {
                approval_id: status.approval_id.clone(),
            })
        {
            self.fail_closed("approval status does not match originating projection");
            return Err(projection_mismatch(
                "approval status does not match originating projection",
            ));
        }
        self.ceremony_state = Some(CeremonyProjectionState::Approval(status.state));
        if status.state == ApprovalLifecycleState::AwaitingCeremony {
            match (&status.ceremony_url, &status.ceremony_expires_at_ms) {
                (Some(url), Some(expiry))
                    if self.ceremony_url.as_ref() == Some(url)
                        && self.ceremony_expires_at_ms.as_ref() == Some(expiry)
                        && expiry.get() > now_ms =>
                {
                    self.last_error = None;
                }
                (Some(_), Some(_)) => {
                    self.fail_closed("approval ceremony URL or expiry changed");
                    return Err(projection_mismatch(
                        "approval ceremony URL or expiry changed",
                    ));
                }
                _ => self.clear_launch_secret(),
            }
        } else {
            self.clear_launch_secret();
        }
        Ok(())
    }

    pub fn reconcile_custody(
        &mut self,
        status: &CeremonyPublicStatus,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        if self.identity
            != Some(CeremonyProjectionIdentity::Custody {
                operation_id: status.operation_id.clone(),
                ceremony_kind: status.ceremony_kind,
            })
        {
            self.fail_closed("custody status does not match originating projection");
            return Err(projection_mismatch(
                "custody status does not match originating projection",
            ));
        }
        self.ceremony_state = Some(CeremonyProjectionState::Custody(status.state));
        self.receipt_digest = status.receipt_digest.clone();
        if status.state == CeremonyState::AwaitingUser
            && self.ceremony_url.is_some()
            && self.ceremony_expires_at_ms.as_ref() == Some(&status.expires_at_ms)
            && status.ceremony_url.as_deref() == self.ceremony_url.as_deref()
            && status.expires_at_ms.get() > now_ms
        {
            self.last_error = None;
            return Ok(());
        }
        self.clear_launch_secret();
        Ok(())
    }

    pub fn reconcile_custody_result(
        &mut self,
        result: &CustodyResult,
    ) -> Result<(), ProtocolError> {
        if self.identity
            != Some(CeremonyProjectionIdentity::Custody {
                operation_id: result.custody_operation_id.clone(),
                ceremony_kind: result.ceremony_kind,
            })
        {
            self.fail_closed("custody result does not match originating projection");
            return Err(projection_mismatch(
                "custody result does not match originating projection",
            ));
        }
        self.ceremony_state = Some(CeremonyProjectionState::Custody(result.public_status));
        self.receipt_digest = Some(result.receipt_digest.clone());
        self.clear_launch_secret();
        Ok(())
    }

    pub fn expire_launch_secret(&mut self, now_ms: u64) {
        if self
            .ceremony_expires_at_ms
            .as_ref()
            .is_some_and(|expiry| expiry.get() <= now_ms)
        {
            self.clear_launch_secret();
            self.last_error = Some("ceremony launch URL expired".into());
        }
    }

    pub fn ceremony_url(&self) -> Option<&str> {
        self.ceremony_url.as_deref()
    }

    pub fn expires_at_ms(&self) -> Option<u64> {
        self.ceremony_expires_at_ms.as_ref().map(DecimalU64::get)
    }

    pub fn operation_id(&self) -> Option<&OperationId> {
        match self.identity.as_ref() {
            Some(CeremonyProjectionIdentity::Custody { operation_id, .. }) => Some(operation_id),
            _ => None,
        }
    }

    pub fn approval_id(&self) -> Option<&Digest32> {
        match self.identity.as_ref() {
            Some(CeremonyProjectionIdentity::Approval { approval_id }) => Some(approval_id),
            _ => None,
        }
    }

    pub fn ceremony_kind(&self) -> Option<bloom_broker_api::CeremonyKind> {
        match self.identity.as_ref() {
            Some(CeremonyProjectionIdentity::Custody { ceremony_kind, .. }) => Some(*ceremony_kind),
            _ => None,
        }
    }

    pub fn state(&self) -> Option<CeremonyProjectionState> {
        self.ceremony_state
    }

    pub fn receipt_digest(&self) -> Option<&Digest32> {
        self.receipt_digest.as_ref()
    }

    pub fn review_manifest_digest(&self) -> Option<&Digest32> {
        self.review_manifest_digest.as_ref()
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    fn fail_closed(&mut self, message: &str) {
        self.clear_launch_secret();
        self.last_error = Some(message.into());
    }

    fn clear_launch_secret(&mut self) {
        self.ceremony_url = None;
        self.ceremony_expires_at_ms = None;
    }

    fn awaiting(
        identity: CeremonyProjectionIdentity,
        state: CeremonyProjectionState,
        url: String,
        expiry: DecimalU64,
        review_manifest_digest: Option<Digest32>,
        now_ms: u64,
    ) -> Result<Self, ProtocolError> {
        if url.is_empty() || expiry.get() <= now_ms {
            Err(projection_mismatch(
                "ceremony URL must be non-empty and unexpired",
            ))
        } else {
            Ok(Self {
                identity: Some(identity),
                ceremony_state: Some(state),
                ceremony_url: Some(url),
                ceremony_expires_at_ms: Some(expiry),
                review_manifest_digest,
                receipt_digest: None,
                last_error: None,
            })
        }
    }
}

fn projection_mismatch(message: &str) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::MalformedFrame, message)
}

fn approval_subject(provenance: &ProvenanceSubject) -> ApprovalSubject {
    match provenance {
        ProvenanceSubject::Petal {
            package_hash,
            route,
        } => ApprovalSubject::Petal {
            package_hash: package_hash.clone(),
            route: route.clone(),
            agent_id: None,
        },
        ProvenanceSubject::Cli {
            client_id,
            command_class,
        } => ApprovalSubject::Cli {
            client_id: client_id.clone(),
            command_class: command_class.clone(),
        },
        ProvenanceSubject::System {
            component_id,
            operation_class,
        } => ApprovalSubject::System {
            component_id: component_id.clone(),
            operation_class: operation_class.clone(),
        },
    }
}

fn default_activation_mode(key_ref: &KeyRef) -> ActivationMode {
    if key_ref.backend.as_str() == "local" {
        ActivationMode::BootBound
    } else {
        ActivationMode::BackendManaged
    }
}

/// Load the installer-owned public provenance catalog used to bind approval
/// terms. Broker independently verifies every record signature before use.
#[cfg(unix)]
pub fn load_provenance_catalog(path: impl AsRef<Path>) -> Result<ProvenanceCatalog, ProtocolError> {
    use std::os::unix::fs::MetadataExt as _;

    let path = path.as_ref();
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            format!("inspect {}: {error}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            "provenance catalog must be a root-owned, non-symlink regular file not writable by group or other",
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::UnauthenticatedPeer,
            format!("read {}: {error}", path.display()),
        )
    })?;
    decode_provenance_catalog(&bytes)
}

#[cfg(feature = "triad-dev-harness")]
pub fn load_developer_provenance_catalog(
    developer_root: impl AsRef<Path>,
    path: impl AsRef<Path>,
) -> Result<ProvenanceCatalog, ProtocolError> {
    bloom_triad_local_transport::validate_developer_security_file(
        developer_root.as_ref(),
        path.as_ref(),
        "provenance catalog",
    )?;
    let catalog: ProvenanceCatalog =
        serde_json::from_slice(&std::fs::read(path.as_ref()).map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::UnauthenticatedPeer, error.to_string())
        })?)
        .map_err(|error| {
            ProtocolError::new(ProtocolErrorCode::UnauthenticatedPeer, error.to_string())
        })?;
    catalog.validate_shape()?;
    Ok(catalog)
}

fn decode_provenance_catalog(bytes: &[u8]) -> Result<ProvenanceCatalog, ProtocolError> {
    if bytes.len() > 1024 * 1024 {
        return Err(ProtocolError::new(
            ProtocolErrorCode::LimitExceededFrame,
            "provenance catalog exceeds 1 MiB",
        ));
    }
    let catalog: ProvenanceCatalog = serde_json::from_slice(bytes).map_err(|error| {
        ProtocolError::new(
            ProtocolErrorCode::MalformedFrame,
            format!("parse provenance catalog: {error}"),
        )
    })?;
    catalog.validate_shape()?;
    Ok(catalog)
}

impl TrustedPetalSignRequest {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.preimage.is_empty()
            || !matches!(
                &self.trusted_provenance,
                ProvenanceSubject::Petal { route, .. } if !route.is_empty()
            )
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "payload and trusted route must be non-empty",
            ));
        }
        SigningPayloads::Single {
            payload: Base64UrlBytes::from_bytes(&self.preimage),
        }
        .validate()
    }

    fn operation_id(&self) -> Result<OperationId, ProtocolError> {
        #[derive(Serialize)]
        struct Identity<'a> {
            wallet_id: &'a Token,
            approval_id: &'a Option<Digest32>,
            payload_digest: Digest32,
            claimed_hash: &'a Digest32,
            crypto_suite: CryptoSuite,
            operation_class: &'a Token,
            selector: bloom_broker_api::PetalSignSelector,
            claim_digest: Digest32,
            trusted_provenance: &'a ProvenanceSubject,
            frozen_action_digest: Option<Digest32>,
            frozen_advisory_digest: Option<Digest32>,
        }
        let identity = Identity {
            wallet_id: &self.wallet_id,
            approval_id: &self.approval_id,
            payload_digest: Digest32::from_bytes(Sha256::digest(&self.preimage).into()),
            claimed_hash: &self.claimed_hash,
            crypto_suite: self.crypto_suite,
            operation_class: &self.operation_class,
            selector: self.selector,
            claim_digest: jcs_digest(&self.claim)?,
            trusted_provenance: &self.trusted_provenance,
            frozen_action_digest: self
                .frozen_action
                .as_ref()
                .map(|bytes| Digest32::from_bytes(Sha256::digest(bytes).into())),
            frozen_advisory_digest: self
                .frozen_advisory
                .as_ref()
                .map(|bytes| Digest32::from_bytes(Sha256::digest(bytes).into())),
        };
        let mut hasher = Sha256::new();
        hasher.update(b"bloom-machine-petal-operation/v1");
        hasher.update(serde_jcs::to_vec(&identity).map_err(canonical_error)?);
        Ok(OperationId::from_bytes(hasher.finalize().into()))
    }
}

fn unique_key_for_suite(keys: &[KeyRef], suite: CryptoSuite) -> Result<KeyRef, ProtocolError> {
    let mut matching = keys.iter().filter(|key| key.key_spec == suite.key_spec());
    let key = matching.next().cloned().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorCode::KeyrefMismatch,
            "wallet has no key compatible with requested CryptoSuite",
        )
    })?;
    if matching.next().is_some() {
        return Err(ProtocolError::new(
            ProtocolErrorCode::KeyrefMismatch,
            "wallet has multiple compatible keys; signing selection is ambiguous",
        ));
    }
    Ok(key)
}

fn suite_hash(suite: CryptoSuite, payload: &[u8]) -> Digest32 {
    match suite {
        CryptoSuite::Secp256k1Keccak256Recoverable => {
            Digest32::from_bytes(Keccak256::digest(payload).into())
        }
        CryptoSuite::Secp256k1Sha256Recoverable | CryptoSuite::Ed25519Message => {
            Digest32::from_bytes(Sha256::digest(payload).into())
        }
    }
}

fn petal_batch_payload_digest(payloads: &[Vec<u8>]) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(b"bloom.petal.payload-batch.v1\0");
    digest.update((payloads.len() as u64).to_be_bytes());
    for payload in payloads {
        digest.update((payload.len() as u64).to_be_bytes());
        digest.update(payload);
    }
    Digest32::from_bytes(digest.finalize().into())
}

fn jcs_digest<T: Serialize>(value: &T) -> Result<Digest32, ProtocolError> {
    Ok(Digest32::from_bytes(
        Sha256::digest(serde_jcs::to_vec(value).map_err(canonical_error)?).into(),
    ))
}

const CLAIMED_POLICY_AUTHORITY_DIFF_DOMAIN: &[u8] = b"bloom-policy-authority-diff/v1";

#[derive(Serialize)]
struct ClaimedPolicyAuthorityDiff {
    maximum_approval_lifetime_ms_before: DecimalU64,
    maximum_approval_lifetime_ms_after: DecimalU64,
    added_petal_packages: Vec<Digest32>,
    removed_petal_packages: Vec<Digest32>,
    added_destinations: Vec<ClaimedPolicyAuthorityDestination>,
    removed_destinations: Vec<ClaimedPolicyAuthorityDestination>,
    added_required_verifiers: Vec<ClaimedPolicyAuthorityVerifier>,
    removed_required_verifiers: Vec<ClaimedPolicyAuthorityVerifier>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ClaimedPolicyAuthorityDestination {
    chain: Token,
    destination: String,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ClaimedPolicyAuthorityVerifier {
    verifier_id: Token,
    verifier_digest: Digest32,
}

/// Computes Machine's claimed authority-diff digest for policy-update
/// preflight. Broker independently recomputes the canonical review delta and
/// rejects any mismatch; this helper confers no policy or review authority.
pub fn claimed_policy_authority_diff_digest(
    current: &bloom_broker_api::CanonicalWalletPolicy,
    proposed: &bloom_broker_api::CanonicalWalletPolicy,
) -> Result<Digest32, ProtocolError> {
    fn set_diff<T: Ord + Clone>(
        before: impl IntoIterator<Item = T>,
        after: impl IntoIterator<Item = T>,
    ) -> (Vec<T>, Vec<T>) {
        let before = before.into_iter().collect::<BTreeSet<_>>();
        let after = after.into_iter().collect::<BTreeSet<_>>();
        (
            after.difference(&before).cloned().collect(),
            before.difference(&after).cloned().collect(),
        )
    }

    let (added_petal_packages, removed_petal_packages) = set_diff(
        current.allowed_petal_packages.iter().cloned(),
        proposed.allowed_petal_packages.iter().cloned(),
    );
    let (added_destinations, removed_destinations) = set_diff(
        current
            .allowed_destinations
            .iter()
            .map(|value| ClaimedPolicyAuthorityDestination {
                chain: value.chain.clone(),
                destination: value.destination.clone(),
            }),
        proposed
            .allowed_destinations
            .iter()
            .map(|value| ClaimedPolicyAuthorityDestination {
                chain: value.chain.clone(),
                destination: value.destination.clone(),
            }),
    );
    let (added_required_verifiers, removed_required_verifiers) = set_diff(
        current
            .required_verifiers
            .iter()
            .map(|value| ClaimedPolicyAuthorityVerifier {
                verifier_id: value.verifier_id.clone(),
                verifier_digest: value.verifier_digest.clone(),
            }),
        proposed
            .required_verifiers
            .iter()
            .map(|value| ClaimedPolicyAuthorityVerifier {
                verifier_id: value.verifier_id.clone(),
                verifier_digest: value.verifier_digest.clone(),
            }),
    );
    let claimed = ClaimedPolicyAuthorityDiff {
        maximum_approval_lifetime_ms_before: DecimalU64::new(current.maximum_approval_lifetime_ms),
        maximum_approval_lifetime_ms_after: DecimalU64::new(proposed.maximum_approval_lifetime_ms),
        added_petal_packages,
        removed_petal_packages,
        added_destinations,
        removed_destinations,
        added_required_verifiers,
        removed_required_verifiers,
    };
    let mut hasher = Sha256::new();
    hasher.update(CLAIMED_POLICY_AUTHORITY_DIFF_DOMAIN);
    hasher.update(serde_jcs::to_vec(&claimed).map_err(canonical_error)?);
    Ok(Digest32::from_bytes(hasher.finalize().into()))
}

fn canonical_error(error: serde_json::Error) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        format!("canonical request encoding failed: {error}"),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyPrepareMethod {
    WalletRegistration,
    WalletUnlock,
    WalletImport,
    WalletExport,
    WalletDelete,
    KeyDerive,
    KeyEnroll,
    CredentialAdd,
    CredentialReplace,
    CredentialRemove,
    Recovery,
}

impl CustodyPrepareMethod {
    pub const ALL: [Self; 11] = [
        Self::WalletRegistration,
        Self::WalletUnlock,
        Self::WalletImport,
        Self::WalletExport,
        Self::WalletDelete,
        Self::KeyDerive,
        Self::KeyEnroll,
        Self::CredentialAdd,
        Self::CredentialReplace,
        Self::CredentialRemove,
        Self::Recovery,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::WalletRegistration => "wallet.registration_prepare",
            Self::WalletUnlock => "wallet.unlock_prepare",
            Self::WalletImport => "wallet.import_prepare",
            Self::WalletExport => "wallet.export_prepare",
            Self::WalletDelete => "wallet.delete_prepare",
            Self::KeyDerive => "key.derive_prepare",
            Self::KeyEnroll => "key.enroll_prepare",
            Self::CredentialAdd => "credential.add_prepare",
            Self::CredentialReplace => "credential.replace_prepare",
            Self::CredentialRemove => "credential.remove_prepare",
            Self::Recovery => "recovery.prepare",
        }
    }
}

/// Name each candidate child so an ambiguity error can be acted on: the public
/// key fingerprint that selects it, and the derivation path that identifies it
/// to a human. Ordering here is presentational only — it must never be used to
/// choose a key.
fn describe_candidates(candidates: &[&KeyRef]) -> String {
    candidates
        .iter()
        .map(|key| {
            let path = match &key.derivation {
                Some(DerivationRef::Bip39Multicurve { path, .. })
                | Some(DerivationRef::Bip32Secp256k1 { path, .. }) => path.as_str(),
                None => "<no derivation path>",
            };
            format!("{} ({path})", key.public_key_fingerprint.as_str())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn response_mismatch(method: &str) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::MalformedFrame,
        format!("Broker returned a mismatched response for {method}"),
    )
}

fn response_identity_mismatch(method: &str) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::OperationIdConflict,
        format!("Broker returned a response for different {method} terms"),
    )
}

fn service_unavailable(message: impl Into<String>) -> ProtocolError {
    ProtocolError::new(ProtocolErrorCode::ServiceUnavailable, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{MetadataExt, PermissionsExt},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use bloom_broker_api::{
        ApprovalPrepareState, CeremonyKind, CustodyPrepareState, DeclaredFee, KeySpec,
        NormalizedSignature, RequestNonce, ServiceFuture, SignatureEncoding,
    };
    use ed25519_dalek::SigningKey;

    #[derive(Deserialize)]
    struct MachineSignOperationVector {
        operation_identity: SignOperationIdentity,
        operation_canonical_jcs: String,
        operation_digest: Digest32,
    }

    #[test]
    fn machine_sign_operation_identity_matches_reviewed_artifact() {
        let vector: MachineSignOperationVector =
            serde_json::from_str(include_str!("../vectors/sign-operation-local-v1.json")).unwrap();
        assert_eq!(
            String::from_utf8(serde_jcs::to_vec(&vector.operation_identity).unwrap()).unwrap(),
            vector.operation_canonical_jcs
        );
        assert_eq!(
            vector.operation_identity.digest().unwrap(),
            vector.operation_digest
        );
    }

    #[test]
    fn claimed_policy_authority_diff_digest_matches_reviewed_v1_vector() {
        let current = bloom_broker_api::CanonicalWalletPolicy {
            wallet_id: Token::new("wallet").unwrap(),
            maximum_approval_lifetime_ms: 10,
            allowed_petal_packages: vec![
                Digest32::from_bytes([2; 32]),
                Digest32::from_bytes([1; 32]),
                Digest32::from_bytes([2; 32]),
            ],
            allowed_destinations: vec![bloom_broker_api::PolicyDestination {
                chain: Token::new("ethereum").unwrap(),
                destination: "old".into(),
            }],
            required_verifiers: vec![bloom_broker_api::RequiredVerifier {
                verifier_id: Token::new("human").unwrap(),
                verifier_digest: Digest32::from_bytes([3; 32]),
            }],
        };
        let proposed = bloom_broker_api::CanonicalWalletPolicy {
            wallet_id: Token::new("wallet").unwrap(),
            maximum_approval_lifetime_ms: 20,
            allowed_petal_packages: vec![
                Digest32::from_bytes([4; 32]),
                Digest32::from_bytes([2; 32]),
                Digest32::from_bytes([4; 32]),
            ],
            allowed_destinations: vec![bloom_broker_api::PolicyDestination {
                chain: Token::new("ethereum").unwrap(),
                destination: "new".into(),
            }],
            required_verifiers: Vec::new(),
        };
        assert_eq!(
            claimed_policy_authority_diff_digest(&current, &proposed)
                .unwrap()
                .as_str(),
            "3cb245d0d885a2802566aca5c7af7caed5a069d4d205ec484538a1e4f67b9e42"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_machine_broker_exchange_completes_with_margin_inside_sixty_seconds() {
        let completions = Arc::new(AtomicUsize::new(0));
        let observed = completions.clone();
        let task = tokio::spawn(run_periodic_authority_head_exchange(move || {
            let observed = observed.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
            }
        }));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(44)).await;
        tokio::task::yield_now().await;
        assert_eq!(completions.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(completions.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(45)).await;
        tokio::task::yield_now().await;
        assert_eq!(completions.load(Ordering::SeqCst), 2);
        task.abort();
    }

    struct TestJournalProvider;

    impl MachineJournalHeadProvider for TestJournalProvider {
        fn verified_head(&self) -> Result<(u64, Digest32), ProtocolError> {
            Ok((3, Digest32::from_bytes([3; 32])))
        }

        fn latch_mutations(&self, _reason: String) {}
    }

    struct MockBroker {
        wallet: WalletPublic,
        requests: Mutex<Vec<MachineBrokerRequest>>,
        corrupt_response: bool,
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
                        Ok(MachineBrokerResponse::WalletGetPublic(self.wallet.clone()))
                    }
                    MachineBrokerRequest::KeyGetPublic(request) => {
                        let mut returned_key_ref = request.key_ref;
                        let supported_crypto_suites =
                            if returned_key_ref.locator.contains("unsupported-suite") {
                                vec![]
                            } else {
                                vec![
                                    CryptoSuite::Secp256k1Keccak256Recoverable,
                                    CryptoSuite::Secp256k1Sha256Recoverable,
                                ]
                            };
                        if returned_key_ref.locator.contains("wrong-key") {
                            returned_key_ref.locator = "wallet/delegated/substituted".into();
                        }
                        Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                            role: if returned_key_ref.locator.contains("delegated")
                                || returned_key_ref.locator.contains("derived")
                            {
                                KeyRole::Derived
                            } else {
                                KeyRole::WalletRoot
                            },
                            key_ref: returned_key_ref,
                            canonical_public_key: Base64UrlBytes::from_bytes(&[2; 33]),
                            addresses: vec!["0x0000000000000000000000000000000000000001".into()],
                            supported_crypto_suites,
                        }))
                    }
                    MachineBrokerRequest::SigningSign(request) => {
                        Ok(MachineBrokerResponse::SigningSign(SigningResult {
                            operation_id: request.operation_id,
                            operation_digest: if self.corrupt_response {
                                digest(99)
                            } else {
                                request.operation_digest
                            },
                            signatures: vec![NormalizedSignature {
                                crypto_suite: request.crypto_suite,
                                bytes: Base64UrlBytes::from_bytes(&[7; 65]),
                            }],
                            signer_receipt_digest: digest(90),
                            broker_receipt_digest: digest(91),
                        }))
                    }
                    MachineBrokerRequest::SigningSignBatch(request) => {
                        let signature_count = match &request.payloads {
                            SigningPayloads::Batch { children } => children.len(),
                            SigningPayloads::Single { .. } => 1,
                        };
                        Ok(MachineBrokerResponse::SigningSignBatch(SigningResult {
                            operation_id: request.operation_id,
                            operation_digest: if self.corrupt_response {
                                digest(99)
                            } else {
                                request.operation_digest
                            },
                            signatures: (0..signature_count)
                                .map(|index| NormalizedSignature {
                                    crypto_suite: request.crypto_suite,
                                    bytes: Base64UrlBytes::from_bytes(&[index as u8 + 7; 65]),
                                })
                                .collect(),
                            signer_receipt_digest: digest(90),
                            broker_receipt_digest: digest(91),
                        }))
                    }
                    MachineBrokerRequest::SealedApprovalPrepare(request) => {
                        Ok(MachineBrokerResponse::SealedApprovalPrepare(
                            SealedApprovalPrepareResponse {
                                approval_id: if self.corrupt_response {
                                    digest(99)
                                } else {
                                    request.terms.approval_id()?
                                },
                                state: ApprovalPrepareState::AwaitingCeremony,
                                ceremony_url: "http://localhost:18734/ceremony/exact-owner-secret"
                                    .into(),
                                ceremony_expires_at_ms: request.terms.expires_at_ms,
                                review_manifest_digest: digest(92),
                            },
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalStatus(request) => Ok(
                        MachineBrokerResponse::SealedApprovalStatus(ApprovalPublicStatus {
                            approval_id: request.id,
                            wallet_id: token("wallet"),
                            state: ApprovalLifecycleState::Active,
                            effective_claim_assurance: None,
                            ceremony_url: None,
                            ceremony_expires_at_ms: None,
                        }),
                    ),
                    MachineBrokerRequest::SealedApprovalList(request) => {
                        Ok(MachineBrokerResponse::SealedApprovalList(vec![
                            ApprovalPublicStatus {
                                approval_id: digest(71),
                                wallet_id: request.wallet_id,
                                state: ApprovalLifecycleState::Active,
                                effective_claim_assurance: None,
                                ceremony_url: None,
                                ceremony_expires_at_ms: None,
                            },
                        ]))
                    }
                    MachineBrokerRequest::SealedApprovalLimitState(request) => Ok(
                        MachineBrokerResponse::SealedApprovalLimitState(ApprovalLimitState {
                            approval_id: request.id,
                            committed_operations: DecimalU64::new(1),
                            reserved_operations: DecimalU64::new(2),
                            quarantined_operations: DecimalU64::new(3),
                            committed_signatures: DecimalU64::new(4),
                            reserved_signatures: DecimalU64::new(5),
                            quarantined_signatures: DecimalU64::new(6),
                        }),
                    ),
                    MachineBrokerRequest::SealedApprovalRenew(request) => Ok(
                        MachineBrokerResponse::SealedApprovalRenew(SealedApprovalPrepareResponse {
                            approval_id: if self.corrupt_response {
                                digest(99)
                            } else {
                                request.replacement_terms.approval_id()?
                            },
                            state: ApprovalPrepareState::AwaitingCeremony,
                            ceremony_url: "http://localhost:18734/ceremony/renew".into(),
                            ceremony_expires_at_ms: request.replacement_terms.expires_at_ms,
                            review_manifest_digest: digest(72),
                        }),
                    ),
                    MachineBrokerRequest::PolicyValidateUpdate(request) => Ok(
                        MachineBrokerResponse::PolicyValidateUpdate(PolicyUpdatePrepareResponse {
                            operation_id: if self.corrupt_response {
                                OperationId::from_bytes([99; 32])
                            } else {
                                request.operation_id
                            },
                            ceremony_kind: if self.corrupt_response {
                                CeremonyKind::WalletDelete
                            } else {
                                CeremonyKind::PolicyUpdate
                            },
                            ceremony_url: "http://localhost:18734/ceremony/policy".into(),
                            ceremony_expires_at_ms: DecimalU64::new(9_000),
                            review_manifest_digest: digest(74),
                        }),
                    ),
                    MachineBrokerRequest::WalletImportPrepare(request) => Ok(
                        MachineBrokerResponse::WalletImportPrepare(CustodyPrepareResponse {
                            ceremony_kind: if self.corrupt_response {
                                CeremonyKind::WalletDelete
                            } else {
                                request.ceremony_kind
                            },
                            custody_operation_id: if self.corrupt_response {
                                OperationId::from_bytes([99; 32])
                            } else {
                                request.custody_operation_id
                            },
                            state: CustodyPrepareState::AwaitingUser,
                            ceremony_url: "http://localhost:18734/ceremony/import".into(),
                            ceremony_expires_at_ms: DecimalU64::new(9_000),
                            signer_contribution_digest: digest(75),
                        }),
                    ),
                    MachineBrokerRequest::SealedApprovalRevoke(request) => Ok(
                        MachineBrokerResponse::SealedApprovalRevoke(ApprovalPublicStatus {
                            approval_id: request.approval_id,
                            wallet_id: request.wallet_id,
                            state: ApprovalLifecycleState::Revoked,
                            effective_claim_assurance: None,
                            ceremony_url: None,
                            ceremony_expires_at_ms: None,
                        }),
                    ),
                    MachineBrokerRequest::SealedApprovalRevokeAll(request) => Ok(
                        MachineBrokerResponse::SealedApprovalRevokeAll(RevocationState {
                            wallet_id: request.wallet_id,
                            wallet_revocation_epoch: DecimalU64::new(9),
                            wallet_tombstone: None,
                            approval_tombstone_digest: digest(73),
                            approval_tombstone_count: DecimalU64::new(2),
                            observed_at_ms: DecimalU64::new(10),
                            issuer_service_id: token("bloom-broker"),
                            key_id: token("broker-key"),
                            signature: Base64UrlBytes::from_bytes(&[1, 2, 3]),
                        }),
                    ),
                    MachineBrokerRequest::CeremonyStatus(request) => {
                        let operation_id =
                            OperationId::new(request.id.as_str().to_owned()).unwrap();
                        Ok(MachineBrokerResponse::CeremonyStatus(
                            CeremonyPublicStatus {
                                ceremony_id: digest(81),
                                ceremony_kind: CeremonyKind::WalletImport,
                                operation_id,
                                state: CeremonyState::AwaitingUser,
                                expires_at_ms: DecimalU64::new(9_000),
                                ceremony_url: Some(
                                    "http://localhost:18734/ceremony/owner-secret".into(),
                                ),
                                receipt_digest: None,
                            },
                        ))
                    }
                    MachineBrokerRequest::CeremonyCancel(request) => {
                        let operation_id =
                            OperationId::new(request.id.as_str().to_owned()).unwrap();
                        Ok(MachineBrokerResponse::CeremonyCancel(
                            CeremonyPublicStatus {
                                ceremony_id: digest(81),
                                ceremony_kind: CeremonyKind::WalletImport,
                                operation_id,
                                state: CeremonyState::Cancelled,
                                expires_at_ms: DecimalU64::new(9_000),
                                ceremony_url: None,
                                receipt_digest: None,
                            },
                        ))
                    }
                    MachineBrokerRequest::OperationStatus(request) => Ok(
                        MachineBrokerResponse::OperationStatus(OperationPublicStatus {
                            operation_id: request.operation_id,
                            operation_digest: digest(83),
                            state: bloom_broker_api::OperationState::Validated,
                            result: None,
                            error: None,
                        }),
                    ),
                    MachineBrokerRequest::OperationCancel(request) => Ok(
                        MachineBrokerResponse::OperationCancel(OperationPublicStatus {
                            operation_id: request.operation_id,
                            operation_digest: digest(83),
                            state: bloom_broker_api::OperationState::Cancelled,
                            result: None,
                            error: None,
                        }),
                    ),
                    _ => Err(ProtocolError::new(
                        ProtocolErrorCode::UnknownMethod,
                        "unexpected mock request",
                    )),
                }
            })
        }
    }

    #[tokio::test]
    async fn payload_translation_binds_bytes_claim_and_trusted_provenance() {
        let key_ref = key_ref();
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref.clone()),
                key_refs: vec![key_ref.clone()],
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
                wallet_revocation_epoch: DecimalU64::new(2),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let client = MachineBrokerClient::new(broker.clone());
        let payload = b"exact final bytes".to_vec();
        let payload_digest = Digest32::from_bytes(Sha256::digest(&payload).into());
        let claim_payload_digest = petal_batch_payload_digest(std::slice::from_ref(&payload));
        let request = TrustedPetalSignRequest {
            wallet_id: token("wallet"),
            preimage: payload.clone(),
            claimed_hash: payload_digest.clone(),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            operation_class: token("order.place"),
            selector: bloom_broker_api::PetalSignSelector::Reusable,
            claim: PetalUseClaim {
                package_hash: digest(40),
                route: "orders/place".into(),
                operation_class: token("order.place"),
                crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
                payload_digest: claim_payload_digest,
                ordered_hashes: vec![payload_digest],
                declared_debits: vec![],
                declared_destinations: vec![],
                declared_fee: DeclaredFee::None,
                nonce: RequestNonce::from_bytes([5; 16]),
                claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
            },
            claim_assurance_evidence: Some(b"machine evidence".to_vec()),
            approval_id: Some(digest(50)),
            trusted_provenance: ProvenanceSubject::Petal {
                package_hash: digest(40),
                route: "orders/place".into(),
            },
            frozen_action: Some(b"place order".to_vec()),
            frozen_advisory: Some(b"price moved".to_vec()),
        };

        let result = client.sign_petal_payload(request).await.unwrap();
        assert_eq!(result.signatures[0].bytes.decode(), vec![7; 65]);
        assert_eq!(
            result.signatures[0].crypto_suite.signature_encoding(),
            SignatureEncoding::Secp256k1Recoverable65
        );
        let requests = broker.requests.lock().unwrap();
        let MachineBrokerRequest::SigningSign(signed) = &requests[1] else {
            panic!("second request must be signing.sign");
        };
        assert_eq!(signed.key_ref, key_ref);
        assert_eq!(
            signed.payloads,
            SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(&payload)
            }
        );
    }

    #[tokio::test]
    async fn petal_payload_can_use_an_explicit_broker_validated_delegated_key() {
        let root_key_ref = key_ref();
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(root_key_ref.clone()),
                key_refs: vec![root_key_ref],
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
                wallet_revocation_epoch: DecimalU64::new(2),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let client = MachineBrokerClient::new(broker.clone());
        let payload = b"delegated petal action".to_vec();
        let payload_digest = Digest32::from_bytes(Sha256::digest(&payload).into());
        let claim_payload_digest = petal_batch_payload_digest(std::slice::from_ref(&payload));
        let mut delegated_key_ref = key_ref();
        delegated_key_ref.locator = "wallet/delegated/1".into();
        let request = TrustedPetalSignRequest {
            wallet_id: token("wallet"),
            preimage: payload,
            claimed_hash: payload_digest.clone(),
            crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
            operation_class: token("order.cancel"),
            selector: bloom_broker_api::PetalSignSelector::Reusable,
            claim: PetalUseClaim {
                package_hash: digest(40),
                route: "orders/cancel".into(),
                operation_class: token("order.cancel"),
                crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
                payload_digest: claim_payload_digest,
                ordered_hashes: vec![payload_digest],
                declared_debits: vec![],
                declared_destinations: vec![],
                declared_fee: DeclaredFee::None,
                nonce: RequestNonce::from_bytes([5; 16]),
                claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
            },
            claim_assurance_evidence: Some(b"machine evidence".to_vec()),
            approval_id: Some(digest(50)),
            trusted_provenance: ProvenanceSubject::Petal {
                package_hash: digest(40),
                route: "orders/cancel".into(),
            },
            frozen_action: Some(b"cancel order".to_vec()),
            frozen_advisory: None,
        };

        client
            .sign_petal_payload_with_key(request.clone(), delegated_key_ref.clone())
            .await
            .unwrap();

        let reusable_operation_id = {
            let requests = broker.requests.lock().unwrap();
            assert!(matches!(
                &requests[0],
                MachineBrokerRequest::WalletGetPublic(_)
            ));
            let MachineBrokerRequest::KeyGetPublic(key_request) = &requests[1] else {
                panic!("explicit delegated signing must fetch its public key projection");
            };
            assert_eq!(key_request.key_ref, delegated_key_ref);
            let MachineBrokerRequest::SigningSign(sign_request) = &requests[2] else {
                panic!("explicit delegated signing must use signing.sign");
            };
            assert_eq!(sign_request.key_ref, delegated_key_ref);
            assert_eq!(sign_request.petal_use_claim.as_ref(), Some(&request.claim));
            assert_eq!(
                sign_request
                    .claim_assurance_evidence
                    .as_ref()
                    .map(Base64UrlBytes::decode),
                Some(b"machine evidence".to_vec())
            );
            sign_request.operation_id.clone()
        };

        broker.requests.lock().unwrap().clear();
        let mut exact_request = request.clone();
        exact_request.selector = bloom_broker_api::PetalSignSelector::Exact;
        client
            .sign_petal_payload_with_key(exact_request, delegated_key_ref.clone())
            .await
            .unwrap();
        {
            let requests = broker.requests.lock().unwrap();
            let MachineBrokerRequest::SigningSign(exact_sign_request) = &requests[2] else {
                panic!("exact explicit delegated signing must use signing.sign");
            };
            assert_eq!(exact_sign_request.key_ref, delegated_key_ref);
            assert!(exact_sign_request.petal_use_claim.is_none());
            assert!(exact_sign_request.claim_assurance_evidence.is_none());
            assert_ne!(exact_sign_request.operation_id, reusable_operation_id);
            let expected_exact_digest = SignOperationIdentity {
                operation_id: exact_sign_request.operation_id.clone(),
                approval_id: digest(50),
                key_ref: delegated_key_ref.clone(),
                crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
                ordered_payload_digests: vec![Digest32::from_bytes(
                    Sha256::digest(b"delegated petal action").into(),
                )],
                ordered_hashes: vec![Digest32::from_bytes(
                    Sha256::digest(b"delegated petal action").into(),
                )],
                petal_use_claim_digest: None,
                claim_assurance_digest: None,
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
            }
            .digest()
            .unwrap();
            assert_eq!(exact_sign_request.operation_digest, expected_exact_digest);
        }
        broker.requests.lock().unwrap().clear();

        let mut unsupported_key_ref = key_ref();
        unsupported_key_ref.locator = "wallet/delegated/unsupported-suite".into();
        let error = client
            .sign_petal_payload_with_key(request.clone(), unsupported_key_ref)
            .await
            .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::SuiteNotAllowed);
        assert_eq!(
            broker.requests.lock().unwrap().len(),
            2,
            "suite rejection must happen before signing.sign"
        );

        let mut substituted_key_ref = key_ref();
        substituted_key_ref.locator = "wallet/delegated/wrong-key".into();
        let error = client
            .sign_petal_payload_with_key(request, substituted_key_ref)
            .await
            .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::KeyrefMismatch);
        assert_eq!(
            broker.requests.lock().unwrap().len(),
            4,
            "substituted key metadata must be rejected before signing.sign"
        );
    }

    fn exact_request(payload: Vec<u8>, approval_id: Option<Digest32>) -> ExactPayloadSignRequest {
        ExactPayloadSignRequest {
            wallet_id: token("wallet"),
            claimed_hash: Digest32::from_bytes(Keccak256::digest(&payload).into()),
            preimage: payload,
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            provenance: ProvenanceSubject::Cli {
                client_id: token("bloom-cli"),
                command_class: token("transaction.confirm"),
            },
            provenance_digest: digest(60),
            activation_mode: Some(ActivationMode::BootBound),
            approval_operation_id: OperationId::from_bytes([61; 32]),
            signing_operation_id: OperationId::from_bytes([62; 32]),
            request_nonce: RequestNonce::from_bytes([63; 16]),
            issued_at_ms: DecimalU64::new(1_000),
            expires_at_ms: DecimalU64::new(601_000),
            canonical_plan_facts_digest: digest(64),
            approval_id,
            petal_use_claim: None,
            claim_assurance_evidence: None,
            account_key_ref: None,
        }
    }

    fn exact_batch_request(
        preimages: Vec<Vec<u8>>,
        approval_id: Option<Digest32>,
    ) -> ExactPayloadBatchSignRequest {
        let claimed_hashes = preimages
            .iter()
            .map(|payload| Digest32::from_bytes(Keccak256::digest(payload).into()))
            .collect();
        ExactPayloadBatchSignRequest {
            wallet_id: token("wallet"),
            preimages,
            claimed_hashes,
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            provenance: ProvenanceSubject::Cli {
                client_id: token("bloom-cli"),
                command_class: token("transaction.confirm_batch"),
            },
            provenance_digest: digest(60),
            activation_mode: Some(ActivationMode::BootBound),
            approval_operation_id: OperationId::from_bytes([65; 32]),
            signing_operation_id: OperationId::from_bytes([66; 32]),
            request_nonce: RequestNonce::from_bytes([67; 16]),
            issued_at_ms: DecimalU64::new(1_000),
            expires_at_ms: DecimalU64::new(601_000),
            canonical_plan_facts_digest: digest(68),
            approval_id,
            petal_use_claim: None,
            claim_assurance_evidence: None,
            account_key_ref: None,
        }
    }

    #[tokio::test]
    async fn bip39_multi_account_signing_requires_and_honours_an_account_selector() {
        // A BIP-39 wallet has no signable root; it holds one derived child per
        // account. Two accounts on the same suite is the case that previously
        // made every wallet-level signing call fail with KeyrefMismatch.
        let mut account_one = key_ref();
        account_one.locator = "wallet/derived/account-0".into();
        account_one.public_key_fingerprint = digest(11);
        let mut account_two = key_ref();
        account_two.locator = "wallet/derived/account-1".into();
        account_two.public_key_fingerprint = digest(12);

        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("bip39"),
                root_key_ref: None,
                key_refs: vec![account_one.clone(), account_two.clone()],
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
                wallet_revocation_epoch: DecimalU64::new(2),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let client = MachineBrokerClient::new(broker.clone());
        let payload = b"canonical unsigned EVM envelope".to_vec();

        // With two candidates and no selector the choice is ambiguous, so
        // selection fails closed rather than silently picking one.
        let error = client
            .sign_exact_payload(exact_request(payload.clone(), None))
            .await
            .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::KeyrefMismatch);

        // Each account signs under its own approval, bound to its own KeyRef.
        for account in [&account_one, &account_two] {
            broker.requests.lock().unwrap().clear();
            let mut request = exact_request(payload.clone(), None);
            request.account_key_ref = Some(account.clone());
            let prepared = client.sign_exact_payload(request).await.unwrap();
            let ExactPayloadSignOutcome::ApprovalRequired(_) = prepared else {
                panic!("first call must prepare an exact approval");
            };
            let requests = broker.requests.lock().unwrap();
            let MachineBrokerRequest::SealedApprovalPrepare(prepare) = &requests[2] else {
                panic!("third call must be sealed_approval.prepare");
            };
            assert_eq!(
                &prepare.terms.key_ref, account,
                "the approval must bind the selected account, never the other one"
            );
        }

        // A KeyRef that is not a child of this wallet is refused before any
        // approval is prepared.
        broker.requests.lock().unwrap().clear();
        let mut foreign = key_ref();
        foreign.locator = "wallet/derived/not-mine".into();
        let mut request = exact_request(payload, None);
        request.account_key_ref = Some(foreign);
        let error = client.sign_exact_payload(request).await.unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::KeyrefMismatch);
        assert_eq!(
            broker.requests.lock().unwrap().len(),
            1,
            "a foreign account must be rejected before Broker is asked for key metadata"
        );
    }

    #[tokio::test]
    async fn exact_payload_prepares_then_signs_without_a_hash_only_path() {
        let root_key_ref = key_ref();
        let mut derived_key_ref = key_ref();
        derived_key_ref.locator = "wallet/derived/same-suite".into();
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(root_key_ref.clone()),
                key_refs: vec![derived_key_ref, root_key_ref.clone()],
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
                wallet_revocation_epoch: DecimalU64::new(2),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let client = MachineBrokerClient::new(broker.clone());
        let payload = b"canonical unsigned EVM envelope".to_vec();
        let prepared = client
            .sign_exact_payload(exact_request(payload.clone(), None))
            .await
            .unwrap();
        let ExactPayloadSignOutcome::ApprovalRequired(prepared) = prepared else {
            panic!("first call must prepare an exact approval");
        };

        {
            let requests = broker.requests.lock().unwrap();
            let MachineBrokerRequest::SealedApprovalPrepare(request) = &requests[2] else {
                panic!("third call must be sealed_approval.prepare");
            };
            assert_eq!(
                request.terms.selector,
                ApprovalSelector::Exact {
                    ordered_payload_digests: vec![Digest32::from_bytes(
                        Sha256::digest(&payload).into()
                    )],
                    ordered_hashes: vec![Digest32::from_bytes(Keccak256::digest(&payload).into())],
                }
            );
            assert_eq!(request.terms.provenance_digest, digest(60));
            assert_eq!(request.terms.key_ref, root_key_ref);
            assert_eq!(request.terms.limits.max_operations.get(), 1);
            assert_eq!(request.terms.limits.max_signatures.get(), 1);
        }

        let signed = client
            .sign_exact_payload(exact_request(payload.clone(), Some(prepared.approval_id)))
            .await
            .unwrap();
        let ExactPayloadSignOutcome::Signed(signed) = signed else {
            panic!("approved retry must call signing.sign");
        };
        assert_eq!(signed.signatures[0].bytes.decode(), vec![7; 65]);
        let requests = broker.requests.lock().unwrap();
        let MachineBrokerRequest::SigningSign(request) = &requests[5] else {
            panic!("sixth call must be signing.sign");
        };
        assert_eq!(
            request.payloads,
            SigningPayloads::Single {
                payload: Base64UrlBytes::from_bytes(&payload)
            }
        );
        assert!(request.petal_use_claim.is_none());
        assert!(request.claim_assurance_evidence.is_none());
    }

    #[tokio::test]
    async fn exact_petal_payload_uses_the_canonical_batch_digest() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
                wallet_revocation_epoch: DecimalU64::new(2),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let client = MachineBrokerClient::new(broker);
        let payload = b"hyperliquid approve-agent payload".to_vec();
        let mut request = exact_request(payload.clone(), None);
        let package_hash = digest(80);
        let route = "r000021".to_owned();
        request.provenance = ProvenanceSubject::Petal {
            package_hash: package_hash.clone(),
            route: route.clone(),
        };
        request.activation_mode = None;
        request.petal_use_claim = Some(PetalUseClaim {
            package_hash,
            route,
            operation_class: token("hyperliquid.approve_agent"),
            crypto_suite: request.crypto_suite,
            payload_digest: petal_batch_payload_digest(std::slice::from_ref(&payload)),
            ordered_hashes: vec![request.claimed_hash.clone()],
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee: DeclaredFee::None,
            nonce: RequestNonce::from_bytes([81; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        });

        assert!(matches!(
            client.sign_exact_payload(request).await.unwrap(),
            ExactPayloadSignOutcome::ApprovalRequired(_)
        ));
    }

    #[tokio::test]
    async fn exact_payload_batch_prepares_then_uses_sign_batch_with_receipts() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
                wallet_revocation_epoch: DecimalU64::new(2),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let client = MachineBrokerClient::new(broker.clone());
        let payloads = vec![
            b"unsigned EVM child 1".to_vec(),
            b"unsigned EVM child 2".to_vec(),
        ];
        let prepared = client
            .sign_exact_payload_batch(exact_batch_request(payloads.clone(), None))
            .await
            .unwrap();
        let ExactPayloadSignOutcome::ApprovalRequired(prepared) = prepared else {
            panic!("first call must prepare one exact batch approval");
        };

        {
            let requests = broker.requests.lock().unwrap();
            let MachineBrokerRequest::SealedApprovalPrepare(request) = &requests[2] else {
                panic!("third call must be sealed_approval.prepare");
            };
            assert_eq!(request.terms.limits.max_operations.get(), 1);
            assert_eq!(request.terms.limits.max_signatures.get(), 2);
            assert_eq!(
                request.terms.selector,
                ApprovalSelector::Exact {
                    ordered_payload_digests: payloads
                        .iter()
                        .map(|payload| Digest32::from_bytes(Sha256::digest(payload).into()))
                        .collect(),
                    ordered_hashes: payloads
                        .iter()
                        .map(|payload| Digest32::from_bytes(Keccak256::digest(payload).into()))
                        .collect(),
                }
            );
        }

        let signed = client
            .sign_exact_payload_batch(exact_batch_request(
                payloads.clone(),
                Some(prepared.approval_id),
            ))
            .await
            .unwrap();
        let ExactPayloadSignOutcome::Signed(signed) = signed else {
            panic!("approved retry must call signing.sign_batch");
        };
        assert_eq!(signed.signatures.len(), 2);
        assert_eq!(signed.signer_receipt_digest, digest(90));
        assert_eq!(signed.broker_receipt_digest, digest(91));

        let requests = broker.requests.lock().unwrap();
        let MachineBrokerRequest::SigningSignBatch(request) = &requests[5] else {
            panic!("sixth call must be signing.sign_batch");
        };
        assert_eq!(
            request.payloads,
            SigningPayloads::Batch {
                children: payloads
                    .iter()
                    .map(|payload| Base64UrlBytes::from_bytes(payload))
                    .collect(),
            }
        );
        assert!(request.petal_use_claim.is_none());
        assert!(request.claim_assurance_evidence.is_none());
    }

    #[tokio::test]
    async fn exact_payload_batch_rejects_reorder_before_prepare_or_sign() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(1),
                policy_digest: digest(1),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let mut request = exact_batch_request(vec![b"one".to_vec(), b"two".to_vec()], None);
        request.preimages.swap(0, 1);
        let error = MachineBrokerClient::new(broker.clone())
            .sign_exact_payload_batch(request)
            .await
            .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);
        assert_eq!(broker.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn exact_payload_rejects_changed_hash_before_prepare_or_sign() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(1),
                policy_digest: digest(1),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let mut request = exact_request(b"payload".to_vec(), None);
        request.claimed_hash = digest(99);
        let error = MachineBrokerClient::new(broker.clone())
            .sign_exact_payload(request)
            .await
            .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::SelectorMismatch);
        assert_eq!(broker.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn guest_provenance_substitution_fails_before_signing() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(1),
                policy_digest: digest(1),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let payload = b"payload".to_vec();
        let hash = Digest32::from_bytes(Sha256::digest(&payload).into());
        let error = MachineBrokerClient::new(broker.clone())
            .sign_petal_payload(TrustedPetalSignRequest {
                wallet_id: token("wallet"),
                preimage: payload,
                claimed_hash: hash.clone(),
                crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
                operation_class: token("order.place"),
                selector: bloom_broker_api::PetalSignSelector::Reusable,
                claim: PetalUseClaim {
                    package_hash: digest(41),
                    route: "forged/route".into(),
                    operation_class: token("order.place"),
                    crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
                    payload_digest: hash.clone(),
                    ordered_hashes: vec![hash],
                    declared_debits: vec![],
                    declared_destinations: vec![],
                    declared_fee: DeclaredFee::None,
                    nonce: RequestNonce::from_bytes([8; 16]),
                    claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
                },
                claim_assurance_evidence: None,
                approval_id: Some(digest(52)),
                trusted_provenance: ProvenanceSubject::Petal {
                    package_hash: digest(40),
                    route: "orders/place".into(),
                },
                frozen_action: None,
                frozen_advisory: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::ClaimInvalid);
        assert!(
            broker
                .requests
                .lock()
                .unwrap()
                .iter()
                .all(|request| !matches!(request, MachineBrokerRequest::SigningSign(_)))
        );
    }

    #[test]
    fn broker_ceremony_projection_is_visible_only_while_awaiting() {
        let prepare = CustodyPrepareResponse {
            ceremony_kind: CeremonyKind::WalletImport,
            custody_operation_id: OperationId::from_bytes([4; 32]),
            state: CustodyPrepareState::AwaitingUser,
            ceremony_url: "http://127.0.0.1:18734/c/opaque".into(),
            ceremony_expires_at_ms: DecimalU64::new(2_000),
            signer_contribution_digest: digest(6),
        };
        let mut projection = CeremonyProjection::from_custody_prepare(&prepare, 1_000).unwrap();
        assert_eq!(
            projection.ceremony_url(),
            Some("http://127.0.0.1:18734/c/opaque")
        );
        projection
            .reconcile_custody(
                &CeremonyPublicStatus {
                    ceremony_id: digest(8),
                    ceremony_kind: CeremonyKind::WalletImport,
                    operation_id: OperationId::from_bytes([4; 32]),
                    state: CeremonyState::AwaitingUser,
                    expires_at_ms: DecimalU64::new(2_000),
                    ceremony_url: Some("http://127.0.0.1:18734/c/opaque".into()),
                    receipt_digest: None,
                },
                1_999,
            )
            .unwrap();
        assert!(projection.ceremony_url().is_some());
        projection
            .reconcile_custody(
                &CeremonyPublicStatus {
                    ceremony_id: digest(8),
                    ceremony_kind: CeremonyKind::WalletImport,
                    operation_id: OperationId::from_bytes([4; 32]),
                    state: CeremonyState::Succeeded,
                    expires_at_ms: DecimalU64::new(2_000),
                    ceremony_url: None,
                    receipt_digest: Some(digest(9)),
                },
                1_999,
            )
            .unwrap();
        assert_eq!(projection.ceremony_url(), None);
        assert_eq!(
            projection.operation_id(),
            Some(&OperationId::from_bytes([4; 32]))
        );
        assert_eq!(
            projection.state(),
            Some(CeremonyProjectionState::Custody(CeremonyState::Succeeded))
        );
        assert_eq!(projection.receipt_digest(), Some(&digest(9)));
        let encoded = serde_json::to_vec(&projection).unwrap();
        assert_eq!(
            serde_json::from_slice::<CeremonyProjection>(&encoded).unwrap(),
            projection
        );

        let approval = SealedApprovalPrepareResponse {
            approval_id: digest(10),
            state: ApprovalPrepareState::AwaitingCeremony,
            ceremony_url: "http://127.0.0.1:18734/c/approval".into(),
            ceremony_expires_at_ms: DecimalU64::new(3_000),
            review_manifest_digest: digest(11),
        };
        let mut projection = CeremonyProjection::from_approval_prepare(&approval, 2_000).unwrap();
        projection
            .reconcile_approval(
                &ApprovalPublicStatus {
                    approval_id: digest(10),
                    wallet_id: token("wallet"),
                    state: ApprovalLifecycleState::Expired,
                    effective_claim_assurance: None,
                    ceremony_url: Some("must-not-leak".into()),
                    ceremony_expires_at_ms: Some(DecimalU64::new(3_000)),
                },
                2_500,
            )
            .unwrap();
        assert_eq!(projection.ceremony_url(), None);
        assert_eq!(projection.approval_id(), Some(&digest(10)));
        assert_eq!(
            projection.state(),
            Some(CeremonyProjectionState::Approval(
                ApprovalLifecycleState::Expired
            ))
        );
    }

    #[tokio::test]
    async fn ceremony_status_and_cancel_use_shared_operation_surface() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(1),
                policy_digest: digest(1),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let operation_id = OperationId::from_bytes([82; 32]);
        let client = MachineBrokerClient::new(broker.clone());
        let status = client.ceremony_status(operation_id.clone()).await.unwrap();
        assert_eq!(status.operation_id, operation_id);
        assert!(status.ceremony_url.is_some());
        let rebuilt = CeremonyProjection::from_custody_status(&status, 8_000).unwrap();
        assert_eq!(rebuilt.ceremony_url(), status.ceremony_url.as_deref());

        let cancelled = client.cancel_ceremony(operation_id.clone()).await.unwrap();
        assert_eq!(cancelled.operation_id, operation_id);
        assert_eq!(cancelled.state, CeremonyState::Cancelled);
        assert!(cancelled.ceremony_url.is_none());

        let requests = broker.requests.lock().unwrap();
        assert!(matches!(
            &requests[0],
            MachineBrokerRequest::CeremonyStatus(_)
        ));
        assert!(matches!(
            &requests[1],
            MachineBrokerRequest::CeremonyCancel(_)
        ));
    }

    #[tokio::test]
    async fn operation_cancel_uses_broker_pre_acceptance_surface() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(1),
                policy_digest: digest(1),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let operation_id = OperationId::from_bytes([84; 32]);
        let client = MachineBrokerClient::new(broker.clone());
        let status = client.operation_status(operation_id.clone()).await.unwrap();
        assert_eq!(status.operation_id, operation_id);
        assert_eq!(status.state, bloom_broker_api::OperationState::Validated);
        let cancelled = client.cancel_operation(operation_id.clone()).await.unwrap();
        assert_eq!(cancelled.operation_id, operation_id);
        assert_eq!(cancelled.state, bloom_broker_api::OperationState::Cancelled);
        let requests = broker.requests.lock().unwrap();
        assert!(matches!(
            requests.as_slice(),
            [
                MachineBrokerRequest::OperationStatus(_),
                MachineBrokerRequest::OperationCancel(_)
            ]
        ));
    }

    #[tokio::test]
    async fn cross_operation_signing_response_fails_closed() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(1),
                policy_digest: digest(1),
                wallet_revocation_epoch: DecimalU64::new(0),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: true,
        });
        let payload = b"payload".to_vec();
        let hash = Digest32::from_bytes(Sha256::digest(&payload).into());
        let claim_payload_digest = petal_batch_payload_digest(std::slice::from_ref(&payload));
        let error = MachineBrokerClient::new(broker)
            .sign_petal_payload(TrustedPetalSignRequest {
                wallet_id: token("wallet"),
                preimage: payload,
                claimed_hash: hash.clone(),
                crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
                operation_class: token("order.place"),
                selector: bloom_broker_api::PetalSignSelector::Reusable,
                claim: PetalUseClaim {
                    package_hash: digest(40),
                    route: "orders/place".into(),
                    operation_class: token("order.place"),
                    crypto_suite: CryptoSuite::Secp256k1Sha256Recoverable,
                    payload_digest: claim_payload_digest,
                    ordered_hashes: vec![hash],
                    declared_debits: vec![],
                    declared_destinations: vec![],
                    declared_fee: DeclaredFee::None,
                    nonce: RequestNonce::from_bytes([9; 16]),
                    claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
                },
                claim_assurance_evidence: None,
                approval_id: Some(digest(52)),
                trusted_provenance: ProvenanceSubject::Petal {
                    package_hash: digest(40),
                    route: "orders/place".into(),
                },
                frozen_action: None,
                frozen_advisory: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::OperationIdConflict);
    }

    #[tokio::test]
    async fn prepare_wrappers_reject_crossed_operation_and_terms_responses() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(2),
                policy_digest: digest(82),
                wallet_revocation_epoch: DecimalU64::new(1),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: true,
        });
        let client = MachineBrokerClient::new(broker);

        let approval = ApprovalPrepareRequest {
            operation_id: OperationId::from_bytes([94; 32]),
            terms: approval_terms("wallet", None),
            canonical_plan_facts_digest: digest(95),
        };
        assert_eq!(
            client.prepare_approval(approval).await.unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );

        let old_approval_id = digest(70);
        let renewal = ApprovalRenewRequest {
            operation_id: OperationId::from_bytes([95; 32]),
            old_approval_id: old_approval_id.clone(),
            replacement_terms: approval_terms("wallet", Some(old_approval_id)),
        };
        assert_eq!(
            client.renew_approval(renewal).await.unwrap_err().code,
            ProtocolErrorCode::OperationIdConflict
        );

        let policy = PolicyUpdateRequest {
            operation_id: OperationId::from_bytes([96; 32]),
            wallet_id: token("wallet"),
            baseline_version: DecimalU64::new(2),
            baseline_digest: digest(82),
            proposed_canonical_policy: Base64UrlBytes::from_bytes(b"{}"),
            proposed_policy_digest: digest(83),
            authority_diff_digest: digest(84),
            assurance_level: token("passkey"),
        };
        assert_eq!(
            client
                .validate_policy_update(policy)
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );

        let custody = CustodyPrepareRequest {
            ceremony_kind: CeremonyKind::WalletImport,
            custody_operation_id: OperationId::from_bytes([97; 32]),
            wallet_id: None,
            key_ref: None,
            exact_terms_digest: digest(85),
            expected_input_class: token("raw-wallet-import"),
            browser_output_recipient_key: None,
            petal_key_scope: None,
            legacy_passkey_migration: None,
            wallet_seed_profile: None,
            derivation_request: None,
            account_terms: None,
        };
        assert_eq!(
            client
                .prepare_custody(CustodyPrepareMethod::WalletImport, custody)
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );
    }

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }

    fn approval_terms(wallet: &str, renewal_of: Option<Digest32>) -> SealedApprovalTerms {
        SealedApprovalTerms {
            subject: ApprovalSubject::Cli {
                client_id: token("bloom-cli"),
                command_class: token("test.approval"),
            },
            wallet_id: token(wallet),
            key_ref: key_ref(),
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: ApprovalSelector::Exact {
                ordered_payload_digests: vec![digest(80)],
                ordered_hashes: vec![digest(81)],
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(1),
                max_signatures: DecimalU64::new(1),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: vec![],
            },
            activation_mode: ActivationMode::BootBound,
            wallet_revocation_epoch: DecimalU64::new(1),
            policy_version: DecimalU64::new(2),
            policy_digest: digest(82),
            provenance_digest: digest(83),
            request_nonce: RequestNonce::from_bytes([84; 16]),
            issued_at_ms: DecimalU64::new(1_000),
            not_before_ms: DecimalU64::new(1_000),
            expires_at_ms: DecimalU64::new(61_000),
            renewal_of,
        }
    }

    #[tokio::test]
    async fn approval_management_wrappers_dispatch_existing_protocol_methods() {
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(key_ref()),
                key_refs: vec![key_ref()],
                policy_version: DecimalU64::new(2),
                policy_digest: digest(82),
                wallet_revocation_epoch: DecimalU64::new(1),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let client = MachineBrokerClient::new(broker.clone());
        let old_id = digest(70);

        assert_eq!(
            client.list_approvals(token("wallet")).await.unwrap().len(),
            1
        );
        assert_eq!(
            client
                .approval_limit_state(old_id.clone())
                .await
                .unwrap()
                .approval_id,
            old_id
        );
        let renewal = ApprovalRenewRequest {
            operation_id: OperationId::from_bytes([85; 32]),
            old_approval_id: old_id.clone(),
            replacement_terms: approval_terms("wallet", Some(old_id.clone())),
        };
        assert_eq!(
            client
                .renew_approval(renewal.clone())
                .await
                .unwrap()
                .ceremony_url,
            "http://localhost:18734/ceremony/renew"
        );
        let revoke = RevokeRequest {
            operation_id: OperationId::from_bytes([86; 32]),
            approval_id: old_id.clone(),
            wallet_id: token("wallet"),
            reason: "test".into(),
        };
        assert_eq!(
            client.revoke_approval(revoke.clone()).await.unwrap().state,
            ApprovalLifecycleState::Revoked
        );
        let revoke_all = WalletOperationRequest {
            operation_id: OperationId::from_bytes([87; 32]),
            wallet_id: token("wallet"),
        };
        assert_eq!(
            client
                .revoke_all_approvals(revoke_all.clone())
                .await
                .unwrap()
                .approval_tombstone_count,
            DecimalU64::new(2)
        );

        let requests = broker.requests.lock().unwrap();
        assert!(matches!(
            &requests[0],
            MachineBrokerRequest::SealedApprovalList(_)
        ));
        assert!(matches!(
            &requests[1],
            MachineBrokerRequest::SealedApprovalLimitState(_)
        ));
        assert_eq!(
            requests[2],
            MachineBrokerRequest::SealedApprovalRenew(renewal)
        );
        assert_eq!(
            requests[3],
            MachineBrokerRequest::SealedApprovalRevoke(revoke)
        );
        assert_eq!(
            requests[4],
            MachineBrokerRequest::SealedApprovalRevokeAll(revoke_all)
        );
    }

    struct MismatchedApprovalBroker;

    impl MachineBrokerService for MismatchedApprovalBroker {
        fn dispatch<'a>(
            &'a self,
            _request: MachineBrokerRequest,
        ) -> ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async { Ok(MachineBrokerResponse::WalletListPublic(vec![])) })
        }
    }

    #[tokio::test]
    async fn approval_management_wrappers_reject_mismatched_responses() {
        let client = MachineBrokerClient::new(Arc::new(MismatchedApprovalBroker));
        let old_id = digest(90);
        let renewal = ApprovalRenewRequest {
            operation_id: OperationId::from_bytes([91; 32]),
            old_approval_id: old_id.clone(),
            replacement_terms: approval_terms("wallet", Some(old_id.clone())),
        };
        let revoke = RevokeRequest {
            operation_id: OperationId::from_bytes([92; 32]),
            approval_id: old_id.clone(),
            wallet_id: token("wallet"),
            reason: "test".into(),
        };
        let revoke_all = WalletOperationRequest {
            operation_id: OperationId::from_bytes([93; 32]),
            wallet_id: token("wallet"),
        };
        assert_eq!(
            client
                .list_approvals(token("wallet"))
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );
        assert_eq!(
            client.approval_limit_state(old_id).await.unwrap_err().code,
            ProtocolErrorCode::MalformedFrame
        );
        assert_eq!(
            client.renew_approval(renewal).await.unwrap_err().code,
            ProtocolErrorCode::MalformedFrame
        );
        assert_eq!(
            client.revoke_approval(revoke).await.unwrap_err().code,
            ProtocolErrorCode::MalformedFrame
        );
        assert_eq!(
            client
                .revoke_all_approvals(revoke_all)
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::MalformedFrame
        );
    }

    #[tokio::test]
    async fn unix_service_transports_authenticated_signed_envelopes() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("broker.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let machine = local_identity("bloom-machine", "machine-key", 7);
        let broker = local_identity("bloom-broker", "broker-key", 8);
        let machine_acl = peer_acl(uid, &machine);
        let broker_acl = peer_acl(uid, &broker);
        let expected = digest(42);
        let server_expected = expected.clone();
        let server_identity = broker.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = bloom_triad_local_transport::receive_request::<MachineBrokerRequest>(
                &mut stream,
                &server_identity,
                &machine_acl,
                BROKER_API_CURRENT,
                BROKER_API_RANGE,
                bloom_broker_api::JournalHeadPolicy::Required,
            )
            .await
            .unwrap();
            assert_eq!(
                request.unsigned.body,
                MachineBrokerRequest::ActionValidate(server_expected.clone())
            );
            let response: Result<MachineBrokerResponse, ProtocolError> =
                Ok(MachineBrokerResponse::ActionValidate(server_expected));
            bloom_triad_local_transport::send_response_with_journal_head(
                &mut stream,
                &server_identity,
                &request,
                response,
                bloom_triad_local_transport::sign_journal_head(
                    &server_identity,
                    4,
                    Digest32::from_bytes([4; 32]),
                ),
            )
            .await
            .unwrap();
        });

        let checkpoint_root = directory.path().join("checkpoints");
        std::fs::create_dir(&checkpoint_root).unwrap();
        std::fs::set_permissions(&checkpoint_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let client = MachineBrokerClient::connect_unix(socket, machine, broker_acl);
        client
            .attach_authority_journal(Arc::new(TestJournalProvider), &checkpoint_root, uid)
            .unwrap();
        let response = client
            .request(MachineBrokerRequest::ActionValidate(expected.clone()))
            .await
            .unwrap();
        assert_eq!(response, MachineBrokerResponse::ActionValidate(expected));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unix_service_never_emits_a_headless_authority_request() {
        let directory = tempfile::tempdir().unwrap();
        let machine = local_identity("bloom-machine", "machine-key", 7);
        let broker = local_identity("bloom-broker", "broker-key", 8);
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let client = MachineBrokerClient::connect_unix(
            directory.path().join("missing.sock"),
            machine,
            peer_acl(uid, &broker),
        );
        let error = client
            .request(MachineBrokerRequest::ActionValidate(digest(1)))
            .await
            .unwrap_err();
        assert_eq!(error.code, ProtocolErrorCode::ServiceUnavailable);
        assert!(error.message.contains("journal is not initialized"));
    }

    #[test]
    fn security_files_fail_closed_on_writable_or_non_root_metadata() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let identity_path = directory.path().join("machine-identity.json");
        let manifest_path = directory.path().join("edge-manifest.json");
        std::fs::write(&identity_path, b"{}").unwrap();
        std::fs::write(&manifest_path, b"{}").unwrap();

        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error =
            MachineBrokerClient::connect_unix_from_files("unused", &identity_path, &manifest_path)
                .err()
                .expect("insecure identity metadata must fail");
        assert_eq!(error.code, ProtocolErrorCode::UnauthenticatedPeer);

        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error =
            MachineBrokerClient::connect_unix_from_files("unused", &identity_path, &manifest_path)
                .err()
                .expect("writable manifest metadata must fail");
        assert_eq!(error.code, ProtocolErrorCode::UnauthenticatedPeer);
    }

    fn local_identity(service: &str, key_id: &str, byte: u8) -> LocalIdentity {
        LocalIdentity {
            service_id: token(service),
            boot_epoch: bloom_broker_api::BootEpoch::from_bytes([byte; 16]),
            application_key_id: token(key_id),
            signing_key: Arc::new(SigningKey::from_bytes(&[byte; 32])),
        }
    }

    fn peer_acl(uid: u32, identity: &LocalIdentity) -> PeerAcl {
        PeerAcl {
            effective_uid: uid,
            service_id: identity.service_id.clone(),
            boot_epoch: identity.boot_epoch.clone(),
            application_key_id: identity.application_key_id.clone(),
            application_public_key: identity.signing_key.verifying_key().to_bytes(),
        }
    }

    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn key_ref() -> KeyRef {
        KeyRef {
            backend: token("local"),
            backend_instance: token("primary"),
            locator: "wallet/root".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: digest(3),
            derivation: None,
        }
    }

    // ------------------------------------------------------------------
    // Explicit derived-account selection (Finding R1).
    //
    // A BIP-39 wallet has no signable root, so `root_key_ref` is None and the
    // signable keys are its derived children. Two active children of the same
    // key spec are exactly the ambiguity these cover.
    // ------------------------------------------------------------------

    fn derived_child(account: u32, fingerprint: u8) -> KeyRef {
        KeyRef {
            backend: token("local"),
            backend_instance: token("primary"),
            locator: format!("wallet/derived/{account}"),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: digest(fingerprint),
            derivation: Some(DerivationRef::Bip39Multicurve {
                wallet_seed_ref: token("seed"),
                profile: bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1,
                path: format!("m/44'/60'/{account}'/0/0"),
            }),
        }
    }

    fn multi_account_broker(children: Vec<KeyRef>) -> Arc<MockBroker> {
        Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                // A BIP-39 seed root is not signable.
                root_key_ref: None,
                key_refs: children,
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
                wallet_revocation_epoch: DecimalU64::new(2),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        })
    }

    #[test]
    fn candidate_description_names_every_fingerprint_and_path() {
        let described = describe_candidates(&[&derived_child(0, 0xa1), &derived_child(1, 0xb2)]);
        assert!(described.contains(digest(0xa1).as_str()));
        assert!(described.contains(digest(0xb2).as_str()));
        assert!(described.contains("m/44'/60'/0'/0/0"));
        assert!(described.contains("m/44'/60'/1'/0/0"));

        // A key with no derivation metadata is still nameable by fingerprint.
        let rootish = describe_candidates(&[&key_ref()]);
        assert!(rootish.contains(digest(3).as_str()));
        assert!(rootish.contains("<no derivation path>"));
    }

    #[tokio::test]
    async fn omitted_selector_with_two_active_children_fails_and_names_both() {
        let broker = multi_account_broker(vec![derived_child(0, 0xa1), derived_child(1, 0xb2)]);
        let client = MachineBrokerClient::new(broker.clone());
        let error = client
            .sign_exact_payload(exact_request(b"exact bytes".to_vec(), None))
            .await
            .expect_err("two compatible active children must not resolve implicitly");

        assert_eq!(error.code, ProtocolErrorCode::KeyrefMismatch);
        // Actionable: the caller can pick one from the error itself.
        assert!(
            error.message.contains(digest(0xa1).as_str()),
            "{}",
            error.message
        );
        assert!(
            error.message.contains(digest(0xb2).as_str()),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("m/44'/60'/0'/0/0"),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("m/44'/60'/1'/0/0"),
            "{}",
            error.message
        );
    }

    #[tokio::test]
    async fn a_single_active_child_still_resolves_without_a_selector() {
        let broker = multi_account_broker(vec![derived_child(0, 0xa1)]);
        let client = MachineBrokerClient::new(broker.clone());
        client
            .sign_exact_payload(exact_request(b"exact bytes".to_vec(), None))
            .await
            .expect("one compatible child keeps the pre-selector behaviour");
    }

    #[tokio::test]
    async fn each_selected_child_binds_its_own_key_and_never_the_other() {
        for (account, fingerprint) in [(0_u32, 0xa1_u8), (1, 0xb2)] {
            let children = vec![derived_child(0, 0xa1), derived_child(1, 0xb2)];
            let selected = derived_child(account, fingerprint);
            let broker = multi_account_broker(children);
            let client = MachineBrokerClient::new(broker.clone());
            let mut request = exact_request(b"exact bytes".to_vec(), None);
            request.account_key_ref = Some(selected.clone());
            client
                .sign_exact_payload(request)
                .await
                .expect("an explicitly selected active child signs");

            // The approval must be bound to the selected child, not to
            // whichever child happened to be listed first.
            let requests = broker.requests.lock().unwrap();
            let bound: Vec<&KeyRef> = requests
                .iter()
                .filter_map(|request| match request {
                    MachineBrokerRequest::SealedApprovalPrepare(prepare) => {
                        Some(&prepare.terms.key_ref)
                    }
                    _ => None,
                })
                .collect();
            assert!(!bound.is_empty(), "the flow must prepare an approval");
            for key_ref in bound {
                assert_eq!(
                    key_ref, &selected,
                    "approval bound a key other than the selected account"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_foreign_selector_is_refused_and_names_the_real_children() {
        let broker = multi_account_broker(vec![derived_child(0, 0xa1), derived_child(1, 0xb2)]);
        let client = MachineBrokerClient::new(broker.clone());
        let mut request = exact_request(b"exact bytes".to_vec(), None);
        // Same shape, but not a child of this wallet.
        request.account_key_ref = Some(derived_child(9, 0xc3));
        let error = client
            .sign_exact_payload(request)
            .await
            .expect_err("a key outside the wallet must never be selectable");

        assert_eq!(error.code, ProtocolErrorCode::KeyrefMismatch);
        assert!(
            error.message.contains(digest(0xa1).as_str()),
            "{}",
            error.message
        );
        assert!(
            error.message.contains(digest(0xb2).as_str()),
            "{}",
            error.message
        );
    }

    #[tokio::test]
    async fn a_selector_is_refused_on_a_wallet_that_signs_with_its_root() {
        let root = key_ref();
        let broker = Arc::new(MockBroker {
            wallet: WalletPublic {
                wallet_id: token("wallet"),
                wallet_kind: token("local"),
                root_key_ref: Some(root.clone()),
                key_refs: vec![root],
                policy_version: DecimalU64::new(7),
                policy_digest: digest(7),
                wallet_revocation_epoch: DecimalU64::new(2),
            },
            requests: Mutex::new(Vec::new()),
            corrupt_response: false,
        });
        let client = MachineBrokerClient::new(broker);
        let mut request = exact_request(b"exact bytes".to_vec(), None);
        request.account_key_ref = Some(derived_child(0, 0xa1));
        let error = client
            .sign_exact_payload(request)
            .await
            .expect_err("a root-signing wallet has no derived account to select");
        assert_eq!(error.code, ProtocolErrorCode::KeyrefMismatch);
    }
}
