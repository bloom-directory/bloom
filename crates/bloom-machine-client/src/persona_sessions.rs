//! Public persona grant orchestration. Authority and all spending reservations
//! remain in Broker/Signer; these files contain public terms and retry identities.

use super::*;
use fs2::FileExt;
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

const SESSION_SCHEMA: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaSessionProposal {
    pub schema_version: u32,
    pub persona: String,
    pub account: u32,
    pub prepare_operation_id: OperationId,
    pub terms: SealedApprovalTerms,
    pub canonical_plan_facts_digest: Digest32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRecord {
    proposal: PersonaSessionProposal,
    /// A local stop is persisted before contacting Broker. Failure to revoke
    /// remotely must never advertise the grant as available for a new action.
    disabled: bool,
    #[serde(default)]
    revoke_request: Option<RevokeRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaSessionStatus {
    pub approval_id: Digest32,
    pub persona: String,
    pub account: u32,
    pub terms: SealedApprovalTerms,
    pub locally_disabled: bool,
    /// Frozen locally but Broker has not yet returned a status. This is never
    /// active authority and can be resumed by the identical prepare request.
    pub preparation_pending: bool,
    pub authority: ApprovalPublicStatus,
    pub usage: Option<ApprovalLimitState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningAttempt {
    approval_id: Digest32,
    source_digest: Digest32,
    operation_digest: Digest32,
}

fn io_error(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCode::ServiceUnavailable,
        format!("persona session state: {error}"),
    )
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<(), ProtocolError> {
    let parent = path
        .parent()
        .ok_or_else(|| io_error("missing state parent"))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    let bytes = serde_json::to_vec(value).map_err(io_error)?;
    // Callers hold the store's interprocess lock, so this temporary name cannot
    // race another writer. Atomic rename leaves either the old or complete file.
    let temporary = path.with_extension("pending");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(io_error)?;
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(&temporary, path).map_err(io_error)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, ProtocolError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(io_error),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn store_lock(root: &Path) -> Result<fs::File, ProtocolError> {
    fs::create_dir_all(root).map_err(io_error)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(root.join("session.lock"))
        .map_err(io_error)?;
    file.try_lock_exclusive().map_err(io_error)?;
    Ok(file)
}

fn grant_path(root: &Path, id: &Digest32) -> PathBuf {
    root.join("grants").join(format!("{}.json", id.as_str()))
}

fn attempt_path(root: &Path, id: &OperationId) -> PathBuf {
    root.join("attempts").join(format!("{}.json", id.as_str()))
}

fn owner_account_number(key: &KeyRef) -> Option<u32> {
    match &key.derivation {
        None => Some(0),
        Some(bloom_broker_api::DerivationRef::Bip39Multicurve { profile, path, .. }) => {
            match profile {
                bloom_broker_api::DerivationProfile::Bip44EvmSecp256k1V1 => {
                    path.rsplit('/').next()?.parse().ok()
                }
                bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1 => {
                    path.split('/').nth(3)?.strip_suffix("'")?.parse().ok()
                }
            }
        }
        _ => None,
    }
}

fn assurance_rank(level: bloom_broker_api::ClaimAssuranceLevel) -> u8 {
    match level {
        bloom_broker_api::ClaimAssuranceLevel::MachineAsserted => 0,
        bloom_broker_api::ClaimAssuranceLevel::ProofVerified => 1,
        bloom_broker_api::ClaimAssuranceLevel::InvariantAttested => 2,
    }
}

fn selector_matches(
    terms: &SealedApprovalTerms,
    provenance: &ProvenanceSubject,
    claim: Option<&PetalUseClaim>,
    provenance_digest: &Digest32,
    system_use: Option<&bloom_broker_api::SystemSessionUse>,
) -> bool {
    match (&terms.selector, provenance, claim) {
        (
            ApprovalSelector::Petal {
                package_hash,
                route,
                allowed_operation_classes,
                route_grants,
                required_claim_assurance,
            },
            ProvenanceSubject::Petal {
                package_hash: source_package,
                route: source_route,
            },
            Some(claim),
        ) => {
            if package_hash != source_package
                || &claim.package_hash != source_package
                || &claim.route != source_route
                || assurance_rank(claim.claim_assurance.level())
                    < assurance_rank(*required_claim_assurance)
            {
                return false;
            }
            let scope_matches = if route_grants.is_empty() {
                route == source_route
                    && allowed_operation_classes.contains(&claim.operation_class)
                    && &terms.provenance_digest == provenance_digest
            } else {
                route_grants.iter().any(|grant| {
                    &grant.route == source_route
                        && grant
                            .allowed_operation_classes
                            .contains(&claim.operation_class)
                        && &grant.provenance_digest == provenance_digest
                })
            };
            scope_matches
                && claim.declared_debits.iter().all(|debit| {
                    terms
                        .limits
                        .value_limits
                        .iter()
                        .any(|limit| limit.asset == debit.asset)
                })
                && match &claim.declared_fee {
                    bloom_broker_api::DeclaredFee::None => true,
                    bloom_broker_api::DeclaredFee::Fee { chain, asset, .. } => terms
                        .limits
                        .value_limits
                        .iter()
                        .any(|limit| &limit.asset.chain == chain && &limit.asset.asset == asset),
                }
        }
        (
            ApprovalSelector::SystemSession { scope },
            ProvenanceSubject::System { component_id, .. },
            None,
        ) => {
            let Some(action) = system_use else {
                return false;
            };
            &scope.component_id == component_id
                && &terms.provenance_digest == provenance_digest
                && scope.validate_use(action).is_ok()
        }
        _ => false,
    }
}

impl MachineBrokerClient {
    /// Read the source-pinned identity recorded before a session sign was sent.
    /// This lets native orchestrators reconcile instead of rotating their
    /// operation identity when a response or process was lost.
    pub fn persona_operation_digest(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<Digest32>, ProtocolError> {
        let Some(root) = &self.persona_session_root else {
            return Ok(None);
        };
        Ok(
            read_json::<SigningAttempt>(&attempt_path(root, operation_id))?
                .map(|attempt| attempt.operation_digest),
        )
    }

    pub(crate) fn persona_recovery_key(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<KeyRef>, ProtocolError> {
        let Some(root) = &self.persona_session_root else {
            return Ok(None);
        };
        let Some(attempt) = read_json::<SigningAttempt>(&attempt_path(root, operation_id))? else {
            return Ok(None);
        };
        let record = read_json::<SessionRecord>(&grant_path(root, &attempt.approval_id))?
            .ok_or_else(|| io_error("original persona grant record is missing"))?;
        if record.proposal.terms.approval_id()? != attempt.approval_id {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "persona recovery grant identity mismatch",
            ));
        }
        Ok(Some(record.proposal.terms.key_ref))
    }

    /// Configure public session discovery for this Machine home. Clones retain
    /// the same root and gate. Merely configuring the store grants no authority.
    pub fn with_persona_session_store(mut self, root: impl Into<PathBuf>) -> Self {
        self.persona_session_root = Some(Arc::new(root.into()));
        self
    }

    pub async fn prepare_persona_session(
        &self,
        proposal: PersonaSessionProposal,
    ) -> Result<PersonaSessionStatus, ProtocolError> {
        if proposal.schema_version != SESSION_SCHEMA
            || !matches!(proposal.persona.as_str(), "trader" | "degen")
            || proposal.terms.limits.max_operations.get() <= 1
            || matches!(proposal.terms.selector, ApprovalSelector::Exact { .. })
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::SelectorMismatch,
                "persona activation requires reviewed multi-operation scoped terms",
            ));
        }
        proposal.terms.validate()?;
        let wallet = self.wallet(proposal.terms.wallet_id.clone()).await?;
        if proposal.terms.policy_version != wallet.policy_version
            || proposal.terms.policy_digest != wallet.policy_digest
            || proposal.terms.wallet_revocation_epoch != wallet.wallet_revocation_epoch
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::PolicyBaselineStale,
                "persona activation does not match current wallet authority",
            ));
        }
        let selected = if wallet.root_key_ref.is_some() {
            None
        } else {
            Some(&proposal.terms.key_ref)
        };
        for suite in &proposal.terms.allowed_crypto_suites {
            if self.verified_signing_key(&wallet, *suite, selected).await? != proposal.terms.key_ref
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::KeyrefMismatch,
                    "persona proposal selected a different wallet key",
                ));
            }
        }
        if owner_account_number(&proposal.terms.key_ref) != Some(proposal.account) {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "persona proposal account does not match its selected owner key",
            ));
        }
        let root = self
            .persona_session_root
            .as_ref()
            .ok_or_else(|| io_error("session store is not configured"))?;
        let _gate = self.persona_session_gate.lock().await;
        let _lock = store_lock(root)?;
        let id = proposal.terms.approval_id()?;
        let path = grant_path(root, &id);
        let record = match read_json::<SessionRecord>(&path)? {
            Some(record) => {
                if serde_jcs::to_vec(&record.proposal).map_err(io_error)?
                    != serde_jcs::to_vec(&proposal).map_err(io_error)?
                {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::OperationIdConflict,
                        "persona proposal identity changed during activation",
                    ));
                }
                record
            }
            None => {
                let record = SessionRecord {
                    proposal,
                    disabled: false,
                    revoke_request: None,
                };
                atomic_json(&path, &record)?;
                record
            }
        };
        if record.disabled {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ApprovalRevoked,
                "stopped persona proposal cannot be activated again",
            ));
        }
        match self.approval_status(id.clone()).await {
            Ok(_) => {}
            Err(error) if error.code == ProtocolErrorCode::ApprovalNotFound => {
                self.prepare_approval(ApprovalPrepareRequest {
                    surface_selection: bloom_broker_api::CeremonySurfaceSelection::Default,
                    operation_id: record.proposal.prepare_operation_id.clone(),
                    terms: record.proposal.terms.clone(),
                    canonical_plan_facts_digest: record
                        .proposal
                        .canonical_plan_facts_digest
                        .clone(),
                    petal_use_claim: None,
                    system_use_claim: None,
                    requested_review_mode: None,
                    evm_review_payloads: Vec::new(),
                })
                .await?;
            }
            Err(error) => return Err(error),
        }
        self.persona_status_for(&record).await
    }

    async fn persona_status_for(
        &self,
        record: &SessionRecord,
    ) -> Result<PersonaSessionStatus, ProtocolError> {
        let id = record.proposal.terms.approval_id()?;
        let (authority, preparation_pending) = match self.approval_status(id.clone()).await {
            Ok(authority) => (authority, false),
            Err(error) if error.code == ProtocolErrorCode::ApprovalNotFound => (
                ApprovalPublicStatus {
                    approval_id: id.clone(),
                    wallet_id: record.proposal.terms.wallet_id.clone(),
                    state: ApprovalLifecycleState::Prepared,
                    effective_claim_assurance: None,
                    ceremony_url: None,
                    ceremony_expires_at_ms: None,
                },
                true,
            ),
            Err(error) => return Err(error),
        };
        if authority.approval_id != id || authority.wallet_id != record.proposal.terms.wallet_id {
            return Err(ProtocolError::new(
                ProtocolErrorCode::OperationIdConflict,
                "persona status identity mismatch",
            ));
        }
        let usage = if authority.state == ApprovalLifecycleState::Active {
            let usage = self.approval_limit_state(id.clone()).await?;
            if usage.approval_id != id {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "persona usage identity mismatch",
                ));
            }
            Some(usage)
        } else {
            None
        };
        Ok(PersonaSessionStatus {
            approval_id: id,
            persona: record.proposal.persona.clone(),
            account: record.proposal.account,
            terms: record.proposal.terms.clone(),
            locally_disabled: record.disabled,
            preparation_pending,
            authority,
            usage,
        })
    }

    pub async fn persona_sessions(
        &self,
        wallet: &Token,
    ) -> Result<Vec<PersonaSessionStatus>, ProtocolError> {
        let Some(root) = &self.persona_session_root else {
            return Ok(Vec::new());
        };
        let _gate = self.persona_session_gate.lock().await;
        let _lock = store_lock(root)?;
        let mut statuses = Vec::new();
        for record in records(root)? {
            if &record.proposal.terms.wallet_id == wallet {
                statuses.push(self.persona_status_for(&record).await?);
            }
        }
        Ok(statuses)
    }

    /// Downgrading to Custodian uses this method before changing local persona
    /// preferences. The persisted stop survives an unavailable Broker.
    pub async fn stop_persona_sessions(
        &self,
        wallet: &Token,
        reason: &str,
    ) -> Result<(), ProtocolError> {
        let Some(root) = &self.persona_session_root else {
            return Ok(());
        };
        let _gate = self.persona_session_gate.lock().await;
        let _lock = store_lock(root)?;
        let mut stopped = Vec::new();
        for mut record in records(root)? {
            if &record.proposal.terms.wallet_id != wallet {
                continue;
            }
            record.disabled = true;
            let id = record.proposal.terms.approval_id()?;
            if record.revoke_request.is_none() {
                let mut bytes = b"bloom.persona.revoke/v1\0".to_vec();
                bytes.extend_from_slice(id.as_str().as_bytes());
                record.revoke_request = Some(RevokeRequest {
                    operation_id: OperationId::from_bytes(Sha256::digest(bytes).into()),
                    approval_id: id.clone(),
                    wallet_id: record.proposal.terms.wallet_id.clone(),
                    reason: reason.to_owned(),
                });
            }
            atomic_json(&grant_path(root, &id), &record)?;
            stopped.push(record.revoke_request.expect("frozen above"));
        }
        let mut failures = Vec::new();
        for request in stopped {
            if let Err(error) = self.revoke_approval(request).await {
                failures.push(error.code.as_str());
            }
        }
        if !failures.is_empty() {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ServiceUnavailable,
                format!(
                    "persona stopped locally; {} remote revocations remain unresolved ({})",
                    failures.len(),
                    failures.join(", ")
                ),
            ));
        }
        Ok(())
    }

    /// Separate multi-operation path; existing one-operation helpers retain
    /// their limits. An uncovered request returns None for explicit exact
    /// step-up. Once an attempt is journaled, every retry stays on that grant.
    pub(crate) async fn try_persona_sign(
        &self,
        request: &ExactPayloadSignRequest,
        key_ref: &KeyRef,
    ) -> Result<Option<SigningResult>, ProtocolError> {
        if request
            .account_key_ref
            .as_ref()
            .is_some_and(|selected| selected != key_ref)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "persona retry changed its selected account",
            ));
        }
        self.try_persona_sign_payloads(
            &request.wallet_id,
            key_ref,
            request.crypto_suite,
            &request.provenance,
            &request.provenance_digest,
            request.petal_use_claim.as_ref(),
            request.system_use_claim.as_ref(),
            request.session_use.as_ref(),
            request.claim_assurance_evidence.as_deref(),
            &request.signing_operation_id,
            std::slice::from_ref(&request.preimage),
            false,
        )
        .await
    }

    pub(crate) async fn try_persona_sign_batch(
        &self,
        request: &ExactPayloadBatchSignRequest,
        key_ref: &KeyRef,
    ) -> Result<Option<SigningResult>, ProtocolError> {
        if request
            .account_key_ref
            .as_ref()
            .is_some_and(|selected| selected != key_ref)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::KeyrefMismatch,
                "persona retry changed its selected account",
            ));
        }
        self.try_persona_sign_payloads(
            &request.wallet_id,
            key_ref,
            request.crypto_suite,
            &request.provenance,
            &request.provenance_digest,
            request.petal_use_claim.as_ref(),
            None,
            None,
            request.claim_assurance_evidence.as_deref(),
            &request.signing_operation_id,
            &request.preimages,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_persona_sign_payloads(
        &self,
        wallet_id: &Token,
        key_ref: &KeyRef,
        suite: CryptoSuite,
        provenance: &ProvenanceSubject,
        provenance_digest: &Digest32,
        claim: Option<&PetalUseClaim>,
        system_claim: Option<&SystemUseClaim>,
        system_use: Option<&bloom_broker_api::SystemSessionUse>,
        evidence: Option<&[u8]>,
        operation_id: &OperationId,
        preimages: &[Vec<u8>],
        batch: bool,
    ) -> Result<Option<SigningResult>, ProtocolError> {
        let Some(root) = &self.persona_session_root else {
            return Ok(None);
        };
        let _gate = self.persona_session_gate.lock().await;
        let _lock = store_lock(root)?;
        let source_digest = jcs_digest(&(
            wallet_id,
            key_ref,
            suite,
            provenance,
            provenance_digest,
            claim,
            system_claim,
            system_use,
            evidence,
            preimages,
            batch,
        ))?;
        let path = attempt_path(root, operation_id);
        let old_attempt = read_json::<SigningAttempt>(&path)?;
        let (record, old_attempt) = if let Some(attempt) = old_attempt {
            if attempt.source_digest != source_digest {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "persona retry changed its payload or trusted context",
                ));
            }
            let record = read_json::<SessionRecord>(&grant_path(root, &attempt.approval_id))?
                .ok_or_else(|| io_error("original persona grant record is missing"))?;
            (record, Some(attempt))
        } else {
            let wallet = self.wallet(wallet_id.clone()).await?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io_error)?
                .as_millis();
            let mut matched = None;
            for record in records(root)? {
                let terms = &record.proposal.terms;
                if record.disabled
                    || &terms.wallet_id != wallet_id
                    || &terms.key_ref != key_ref
                    || !terms.allowed_crypto_suites.contains(&suite)
                    || terms.policy_version != wallet.policy_version
                    || terms.policy_digest != wallet.policy_digest
                    || terms.wallet_revocation_epoch != wallet.wallet_revocation_epoch
                    || now < u128::from(terms.not_before_ms.get())
                    || now >= u128::from(terms.expires_at_ms.get())
                    || !selector_matches(terms, provenance, claim, provenance_digest, system_use)
                {
                    continue;
                }
                if terms.session_budget.is_some()
                    && claim.is_some_and(|claim| {
                        !claim
                            .declared_debits
                            .iter()
                            .any(|debit| debit.amount.as_str() != "0")
                    })
                {
                    // Older monetary Petals omitted effects. They must take
                    // exact step-up without pinning a doomed session attempt.
                    continue;
                }
                let accounting = session_accounting(terms, claim, system_use)?;
                if let Some(budget) = &terms.session_budget
                    && budget.action_nominal_quantity(&accounting.values).is_err()
                {
                    continue;
                }
                let id = terms.approval_id()?;
                let status = self.approval_status(id.clone()).await?;
                if status.approval_id != id || &status.wallet_id != wallet_id {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::OperationIdConflict,
                        "persona discovery status identity mismatch",
                    ));
                }
                if status.state != ApprovalLifecycleState::Active {
                    continue;
                }
                if matched.is_some() {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::SelectorMismatch,
                        "multiple persona grants cover this action; explicitly stop or select one",
                    ));
                }
                matched = Some(record);
            }
            let Some(record) = matched else {
                return Ok(None);
            };
            (record, None)
        };
        let terms = &record.proposal.terms;
        let approval_id = terms.approval_id()?;
        let accounting = session_accounting(terms, claim, system_use)?;
        let operation_digest = SignOperationIdentity {
            session_accounting_digest: Some(accounting.digest()),
            operation_id: operation_id.clone(),
            approval_id: approval_id.clone(),
            key_ref: key_ref.clone(),
            crypto_suite: suite,
            ordered_payload_digests: preimages
                .iter()
                .map(|bytes| Digest32::from_bytes(Sha256::digest(bytes).into()))
                .collect(),
            ordered_hashes: preimages
                .iter()
                .map(|bytes| suite_hash(suite, bytes))
                .collect(),
            petal_use_claim_digest: match (claim, system_claim) {
                (Some(claim), _) => Some(jcs_digest(claim)?),
                (_, Some(claim)) => Some(jcs_digest(claim)?),
                _ => None,
            },
            claim_assurance_digest: match (claim, system_claim) {
                (Some(claim), _) => Some(jcs_digest(&claim.claim_assurance)?),
                (_, Some(claim)) => Some(jcs_digest(&claim.claim_assurance)?),
                _ => None,
            },
            policy_version: terms.policy_version.clone(),
            policy_digest: terms.policy_digest.clone(),
        }
        .digest()?;
        if let Some(attempt) = old_attempt {
            if attempt.operation_digest != operation_digest {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "persona retry operation identity mismatch",
                ));
            }
        } else {
            atomic_json(
                &path,
                &SigningAttempt {
                    approval_id: approval_id.clone(),
                    source_digest,
                    operation_digest: operation_digest.clone(),
                },
            )?;
        }
        let request = MachineSignRequest {
            session_use: system_use.cloned(),
            operation_id: operation_id.clone(),
            operation_digest,
            approval_id,
            key_ref: key_ref.clone(),
            crypto_suite: suite,
            payloads: if batch {
                SigningPayloads::Batch {
                    children: preimages
                        .iter()
                        .map(|bytes| Base64UrlBytes::from_bytes(bytes))
                        .collect(),
                }
            } else {
                SigningPayloads::Single {
                    payload: Base64UrlBytes::from_bytes(&preimages[0]),
                }
            },
            petal_use_claim: claim.cloned(),
            system_use_claim: system_claim.cloned(),
            claim_assurance_evidence: evidence.map(Base64UrlBytes::from_bytes),
            provenance: provenance.clone(),
        };
        let expected = ExpectedSigningResult::from_request(&request);
        // Recover a retained signature even after expiry/revocation. Returning
        // existing bytes does not authorize another signing operation.
        if let Ok(status) = self.operation_status(operation_id.clone()).await {
            if status.operation_id != expected.operation_id
                || status.operation_digest != expected.operation_digest
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "persona operation status identity mismatch",
                ));
            }
            if let Some(result) = status.result {
                return expected.validate(result).map(Some);
            }
        }
        if record.disabled {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ApprovalRevoked,
                "persona was stopped; an unresolved prior operation must be recovered by status, not dispatched again",
            ));
        }
        let result = if batch {
            self.sign_batch(request).await
        } else {
            self.sign(request).await
        };
        match result {
            Ok(result) => Ok(Some(result)),
            Err(mut error) => {
                if let Ok(status) = self.operation_status(operation_id.clone()).await
                    && status.operation_id == expected.operation_id
                    && status.operation_digest == expected.operation_digest
                    && let Some(result) = status.result
                {
                    return expected.validate(result).map(Some);
                }
                if matches!(
                    error.code,
                    ProtocolErrorCode::LimitExceededValue
                        | ProtocolErrorCode::LimitExceededOperations
                        | ProtocolErrorCode::LimitExceededSignatures
                        | ProtocolErrorCode::LimitExceededRate
                        | ProtocolErrorCode::SignerRateBackstopDenied
                ) {
                    error.message.push_str("; this operation remains bound to its original session. Wait for rolling capacity or separately request fresh owner-reviewed authority; retrying activation must not reset the budget.");
                }
                Err(error)
            }
        }
    }
}

fn session_accounting(
    terms: &SealedApprovalTerms,
    claim: Option<&PetalUseClaim>,
    system_use: Option<&bloom_broker_api::SystemSessionUse>,
) -> Result<bloom_broker_api::SessionAccounting, ProtocolError> {
    match (claim, system_use) {
        (Some(claim), None) => bloom_broker_api::SessionAccounting::from_petal_claim(
            claim,
            terms.session_budget.as_ref(),
        ),
        (None, Some(action)) => action.accounting(terms.session_budget.as_ref()),
        _ => Err(ProtocolError::new(
            ProtocolErrorCode::ClaimInvalid,
            "session action requires exactly one authenticated value projection",
        )),
    }
}

fn records(root: &Path) -> Result<Vec<SessionRecord>, ProtocolError> {
    let entries = match fs::read_dir(root.join("grants")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(error)),
    };
    let mut paths = entries
        .map(|entry| entry.map(|entry| entry.path()).map_err(io_error))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    let mut records = Vec::new();
    for path in paths {
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let record = read_json::<SessionRecord>(&path)?
                .ok_or_else(|| io_error("grant disappeared during discovery"))?;
            if path != grant_path(root, &record.proposal.terms.approval_id()?) {
                return Err(io_error("grant filename does not match signed terms"));
            }
            records.push(record);
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::{
        AssetId, DecimalU256, KeySpec, NormalizedSignature, OperationState, SessionValueCeiling,
        SystemSessionAction, SystemSessionChain, SystemSessionScope, SystemSessionUse,
    };
    use std::{collections::BTreeMap, sync::Mutex};

    fn token(value: &str) -> Token {
        Token::new(value).unwrap()
    }
    fn digest(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }
    fn key() -> KeyRef {
        KeyRef {
            backend: token("local"),
            backend_instance: token("primary"),
            locator: "wallet/root".into(),
            key_spec: KeySpec::Secp256k1,
            public_key_fingerprint: digest(3),
            derivation: None,
        }
    }
    fn wallet() -> WalletPublic {
        WalletPublic {
            wallet_id: token("wallet"),
            wallet_kind: token("local"),
            root_key_ref: Some(key()),
            key_refs: vec![key()],
            policy_version: DecimalU64::new(2),
            policy_digest: digest(82),
            wallet_revocation_epoch: DecimalU64::new(1),
        }
    }
    fn proposal() -> PersonaSessionProposal {
        let asset = AssetId {
            chain: token("evm-1"),
            asset: "native".into(),
        };
        let terms = SealedApprovalTerms {
            session_budget: None,
            subject: ApprovalSubject::System {
                component_id: token("bloom-machine"),
                operation_class: token("evm.tx.confirm"),
            },
            wallet_id: token("wallet"),
            key_ref: key(),
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: ApprovalSelector::SystemSession {
                scope: SystemSessionScope {
                    component_id: token("bloom-machine"),
                    actions: vec![SystemSessionAction::NativeTransfer],
                    chains: vec![SystemSessionChain::Evm {
                        chain: token("evm-1"),
                        chain_id: DecimalU64::new(1),
                    }],
                    destinations: vec![bloom_broker_api::PolicyDestination {
                        chain: token("evm-1"),
                        destination: "0x0000000000000000000000000000000000000002".into(),
                    }],
                    tokens: vec![],
                    per_action_value_limits: vec![SessionValueCeiling {
                        asset: asset.clone(),
                        maximum: DecimalU256::parse("100").unwrap(),
                    }],
                },
            },
            limits: ApprovalLimits {
                max_operations: DecimalU64::new(10),
                max_signatures: DecimalU64::new(10),
                operation_rate_limits: vec![],
                signature_rate_limits: vec![],
                value_limits: vec![ValueLimit {
                    asset,
                    lifetime: DecimalU256::parse("1000").unwrap(),
                    rolling_windows: vec![],
                }],
            },
            activation_mode: ActivationMode::BootBound,
            wallet_revocation_epoch: DecimalU64::new(1),
            policy_version: DecimalU64::new(2),
            policy_digest: digest(82),
            provenance_digest: digest(83),
            request_nonce: RequestNonce::from_bytes([84; 16]),
            issued_at_ms: DecimalU64::new(1),
            not_before_ms: DecimalU64::new(1),
            expires_at_ms: DecimalU64::new(u64::MAX),
            renewal_of: None,
        };
        PersonaSessionProposal {
            schema_version: 1,
            persona: "trader".into(),
            account: 0,
            prepare_operation_id: OperationId::from_bytes([8; 32]),
            terms,
            canonical_plan_facts_digest: digest(9),
        }
    }
    fn action(chain_id: u64) -> SystemSessionUse {
        SystemSessionUse {
            action: SystemSessionAction::NativeTransfer,
            chain: SystemSessionChain::Evm {
                chain: token("evm-1"),
                chain_id: DecimalU64::new(chain_id),
            },
            token: None,
            recipient: "0x0000000000000000000000000000000000000002".into(),
            amount: DecimalU256::parse("10").unwrap(),
            maximum_fee: DecimalU256::parse("1").unwrap(),
        }
    }
    struct State {
        wallet: WalletPublic,
        active: bool,
        signatures: usize,
        preparations: usize,
        lose_next_response: bool,
        fail_wallet_reads: bool,
        outcomes: BTreeMap<String, SigningResult>,
    }
    struct Broker(Mutex<State>);
    impl MachineBrokerService for Broker {
        fn dispatch<'a>(
            &'a self,
            request: MachineBrokerRequest,
        ) -> bloom_broker_api::ServiceFuture<'a, MachineBrokerResponse> {
            Box::pin(async move {
                let mut state = self.0.lock().unwrap();
                match request {
                    MachineBrokerRequest::WalletGetPublic(_) => {
                        if state.fail_wallet_reads {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::ServiceUnavailable,
                                "wallet projection unavailable",
                            ));
                        }
                        Ok(MachineBrokerResponse::WalletGetPublic(state.wallet.clone()))
                    }
                    MachineBrokerRequest::KeyGetPublic(_) => {
                        Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                            role: bloom_broker_api::KeyRole::WalletRoot,
                            key_ref: key(),
                            canonical_public_key: Base64UrlBytes::from_bytes(&[2; 33]),
                            addresses: vec!["0x0000000000000000000000000000000000000001".into()],
                            supported_crypto_suites: vec![
                                CryptoSuite::Secp256k1Keccak256Recoverable,
                            ],
                        }))
                    }
                    MachineBrokerRequest::SealedApprovalStatus(request) => Ok(
                        MachineBrokerResponse::SealedApprovalStatus(ApprovalPublicStatus {
                            approval_id: request.id,
                            wallet_id: token("wallet"),
                            state: if state.active {
                                ApprovalLifecycleState::Active
                            } else {
                                ApprovalLifecycleState::Revoked
                            },
                            effective_claim_assurance: None,
                            ceremony_url: None,
                            ceremony_expires_at_ms: None,
                        }),
                    ),
                    MachineBrokerRequest::OperationStatus(request) => {
                        let result = state
                            .outcomes
                            .get(request.operation_id.as_str())
                            .cloned()
                            .ok_or_else(|| {
                                ProtocolError::new(
                                    ProtocolErrorCode::ApprovalNotFound,
                                    "no retained operation",
                                )
                            })?;
                        Ok(MachineBrokerResponse::OperationStatus(
                            OperationPublicStatus {
                                operation_id: result.operation_id.clone(),
                                operation_digest: result.operation_digest.clone(),
                                state: OperationState::Succeeded,
                                result: Some(result),
                                error: None,
                            },
                        ))
                    }
                    MachineBrokerRequest::SigningSign(request) => {
                        if !state.active {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::ApprovalRevoked,
                                "revoked",
                            ));
                        }
                        state.signatures += 1;
                        let result = SigningResult {
                            operation_id: request.operation_id.clone(),
                            operation_digest: request.operation_digest,
                            signatures: vec![NormalizedSignature {
                                crypto_suite: request.crypto_suite,
                                bytes: Base64UrlBytes::from_bytes(&[7; 65]),
                            }],
                            signer_receipt_digest: digest(90),
                            broker_receipt_digest: digest(91),
                        };
                        state
                            .outcomes
                            .insert(request.operation_id.as_str().to_owned(), result.clone());
                        if state.lose_next_response {
                            state.lose_next_response = false;
                            Err(ProtocolError::new(
                                ProtocolErrorCode::ServiceUnavailable,
                                "response lost after signing",
                            ))
                        } else {
                            Ok(MachineBrokerResponse::SigningSign(result))
                        }
                    }
                    MachineBrokerRequest::SealedApprovalPrepare(_) => {
                        state.preparations += 1;
                        Err(ProtocolError::new(
                            ProtocolErrorCode::ClaimInvalid,
                            "unexpected per-action ceremony",
                        ))
                    }
                    MachineBrokerRequest::SealedApprovalRevoke(request) => {
                        state.active = false;
                        Ok(MachineBrokerResponse::SealedApprovalRevoke(
                            ApprovalPublicStatus {
                                approval_id: request.approval_id,
                                wallet_id: request.wallet_id,
                                state: ApprovalLifecycleState::Revoked,
                                effective_claim_assurance: None,
                                ceremony_url: None,
                                ceremony_expires_at_ms: None,
                            },
                        ))
                    }
                    _ => Err(ProtocolError::new(
                        ProtocolErrorCode::UnknownMethod,
                        "not implemented by boundary fixture",
                    )),
                }
            })
        }
    }
    fn fixture() -> (tempfile::TempDir, MachineBrokerClient, Arc<Broker>) {
        let directory = tempfile::tempdir().unwrap();
        let broker = Arc::new(Broker(Mutex::new(State {
            wallet: wallet(),
            active: true,
            signatures: 0,
            preparations: 0,
            lose_next_response: false,
            fail_wallet_reads: false,
            outcomes: BTreeMap::new(),
        })));
        let client =
            MachineBrokerClient::new(broker.clone()).with_persona_session_store(directory.path());
        let proposal = proposal();
        atomic_json(
            &grant_path(directory.path(), &proposal.terms.approval_id().unwrap()),
            &SessionRecord {
                proposal,
                disabled: false,
                revoke_request: None,
            },
        )
        .unwrap();
        (directory, client, broker)
    }
    async fn sign(
        client: &MachineBrokerClient,
        operation: u8,
        payload: &[u8],
        action: &SystemSessionUse,
    ) -> Result<Option<SigningResult>, ProtocolError> {
        client
            .try_persona_sign_payloads(
                &token("wallet"),
                &key(),
                CryptoSuite::Secp256k1Keccak256Recoverable,
                &ProvenanceSubject::System {
                    component_id: token("bloom-machine"),
                    operation_class: token("evm.tx.confirm"),
                },
                &digest(83),
                None,
                None,
                Some(action),
                None,
                &OperationId::from_bytes([operation; 32]),
                &[payload.to_vec()],
                false,
            )
            .await
    }
    #[tokio::test]
    async fn distinct_actions_reuse_one_grant_and_lost_responses_recover_without_another_sign() {
        let (_directory, client, broker) = fixture();
        assert!(
            sign(&client, 1, b"first transaction", &action(1))
                .await
                .unwrap()
                .is_some()
        );
        broker.0.lock().unwrap().lose_next_response = true;
        assert!(
            sign(&client, 2, b"second transaction", &action(1))
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            sign(&client, 2, b"second transaction", &action(1))
                .await
                .unwrap()
                .is_some()
        );
        let state = broker.0.lock().unwrap();
        assert_eq!(state.signatures, 2);
        assert_eq!(state.preparations, 0);
    }
    #[tokio::test]
    async fn wrong_chain_stale_policy_and_changed_retry_cannot_borrow_session_authority() {
        let (_directory, client, broker) = fixture();
        assert!(
            sign(&client, 1, b"wrong chain", &action(2))
                .await
                .unwrap()
                .is_none()
        );
        sign(&client, 2, b"original", &action(1)).await.unwrap();
        assert_eq!(
            sign(&client, 2, b"changed bytes", &action(1))
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );
        broker.0.lock().unwrap().wallet.policy_digest = digest(11);
        assert!(
            sign(&client, 3, b"policy changed", &action(1))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(broker.0.lock().unwrap().signatures, 1);
    }
    #[tokio::test]
    async fn stop_prevents_new_actions_but_retains_original_result_recovery() {
        let (_directory, client, broker) = fixture();
        sign(&client, 1, b"original", &action(1)).await.unwrap();
        client
            .stop_persona_sessions(&token("wallet"), "custodian downgrade")
            .await
            .unwrap();
        assert!(
            sign(&client, 2, b"new action", &action(1))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            sign(&client, 1, b"original", &action(1))
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(broker.0.lock().unwrap().signatures, 1);
    }

    #[tokio::test]
    async fn public_exact_adapter_recovers_source_result_without_resolving_current_wallet() {
        let (_directory, client, broker) = fixture();
        let payload = b"source-preserved native transaction".to_vec();
        let request = ExactPayloadSignRequest {
            session_use: Some(action(1)),
            wallet_id: token("wallet"),
            claimed_hash: suite_hash(CryptoSuite::Secp256k1Keccak256Recoverable, &payload),
            preimage: payload,
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            provenance: ProvenanceSubject::System {
                component_id: token("bloom-machine"),
                operation_class: token("evm.tx.confirm"),
            },
            provenance_digest: digest(83),
            activation_mode: None,
            approval_operation_id: OperationId::from_bytes([3; 32]),
            signing_operation_id: OperationId::from_bytes([4; 32]),
            request_nonce: RequestNonce::from_bytes([5; 16]),
            issued_at_ms: DecimalU64::new(1000),
            expires_at_ms: DecimalU64::new(2000),
            canonical_plan_facts_digest: digest(9),
            approval_id: None,
            petal_use_claim: None,
            system_use_claim: None,
            claim_assurance_evidence: None,
            approval_value_limits: vec![],
            account_key_ref: None,
            requested_review_mode: None,
        };
        assert!(matches!(
            client.sign_exact_payload(request.clone()).await.unwrap(),
            ExactPayloadSignOutcome::Signed(_)
        ));
        broker.0.lock().unwrap().fail_wallet_reads = true;
        broker.0.lock().unwrap().active = false;
        assert!(matches!(
            client.sign_exact_payload(request).await.unwrap(),
            ExactPayloadSignOutcome::Signed(_)
        ));
        assert_eq!(broker.0.lock().unwrap().signatures, 1);
    }

    #[tokio::test]
    async fn interrupted_prepare_remains_visible_and_retries_its_frozen_terms() {
        struct UnavailablePrepare(Mutex<Vec<ApprovalPrepareRequest>>);
        impl MachineBrokerService for UnavailablePrepare {
            fn dispatch<'a>(
                &'a self,
                request: MachineBrokerRequest,
            ) -> bloom_broker_api::ServiceFuture<'a, MachineBrokerResponse> {
                Box::pin(async move {
                    match request {
                        MachineBrokerRequest::WalletGetPublic(_) => {
                            Ok(MachineBrokerResponse::WalletGetPublic(wallet()))
                        }
                        MachineBrokerRequest::KeyGetPublic(_) => {
                            Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                                role: bloom_broker_api::KeyRole::WalletRoot,
                                key_ref: key(),
                                canonical_public_key: Base64UrlBytes::from_bytes(&[2; 33]),
                                addresses: vec![
                                    "0x0000000000000000000000000000000000000001".into(),
                                ],
                                supported_crypto_suites: vec![
                                    CryptoSuite::Secp256k1Keccak256Recoverable,
                                ],
                            }))
                        }
                        MachineBrokerRequest::SealedApprovalStatus(_) => Err(ProtocolError::new(
                            ProtocolErrorCode::ApprovalNotFound,
                            "not accepted",
                        )),
                        MachineBrokerRequest::SealedApprovalPrepare(request) => {
                            self.0.lock().unwrap().push(request);
                            Err(ProtocolError::new(
                                ProtocolErrorCode::ServiceUnavailable,
                                "prepare transport interrupted",
                            ))
                        }
                        _ => Err(ProtocolError::new(
                            ProtocolErrorCode::UnknownMethod,
                            "unexpected call",
                        )),
                    }
                })
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let broker = Arc::new(UnavailablePrepare(Mutex::new(Vec::new())));
        let client =
            MachineBrokerClient::new(broker.clone()).with_persona_session_store(directory.path());
        let proposal = proposal();
        assert!(
            client
                .prepare_persona_session(proposal.clone())
                .await
                .is_err()
        );
        let statuses = client.persona_sessions(&token("wallet")).await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert!(statuses[0].preparation_pending);
        assert_ne!(statuses[0].authority.state, ApprovalLifecycleState::Active);
        assert!(client.prepare_persona_session(proposal).await.is_err());
        let requests = broker.0.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            serde_jcs::to_vec(&requests[0]).unwrap(),
            serde_jcs::to_vec(&requests[1]).unwrap()
        );
    }
}
