//! Public persona grant orchestration. Authority and all spending reservations
//! remain in Broker; Signer enforces structural signing limits; these files contain public terms and retry identities.

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

/// Explicit capability selection. These are public suggestions, never authority.
/// Broker validates provenance, mappings and each exact key during preparation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaSessionSelection {
    /// Explicit raw-unit overrides, especially native gas and assets without a preset.
    #[serde(default)]
    pub token_allowances: Vec<PersonaTokenAllowance>,
    pub assets: Vec<bloom_broker_api::AssetId>,
    pub members: Vec<PersonaSessionMember>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaTokenAllowance {
    pub asset: bloom_broker_api::AssetId,
    pub per_action: bloom_broker_api::DecimalU256,
    pub per_window: bloom_broker_api::DecimalU256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaSessionMember {
    pub account: u32,
    pub key_ref: KeyRef,
    pub subject: ApprovalSubject,
    pub selector: ApprovalSelector,
    pub provenance_digest: Digest32,
    pub allowed_crypto_suites: Vec<CryptoSuite>,
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
    #[serde(default)]
    revoke_confirmed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_fallback_code: Option<ProtocolErrorCode>,
    #[serde(default)]
    rearm_operation_id: Option<OperationId>,
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
    /// Diagnostic only; live Broker status and usage remain authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_fallback_code: Option<ProtocolErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_error: Option<ProtocolErrorCode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningAttempt {
    approval_id: Digest32,
    source_digest: Digest32,
    operation_digest: Digest32,
    #[serde(default)]
    exact_fallback: bool,
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
                    path.split('/').nth(3)?.strip_suffix("'")?.parse().ok()
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
            let asset_allowed = |asset: &bloom_broker_api::AssetId| {
                terms
                    .session_budget
                    .as_ref()
                    .and_then(|budget| budget.token_policy.as_ref())
                    .map_or_else(
                        || {
                            terms
                                .limits
                                .value_limits
                                .iter()
                                .any(|limit| &limit.asset == asset)
                        },
                        |policy| policy.assets.iter().any(|entry| &entry.asset == asset),
                    )
            };
            scope_matches
                && claim
                    .declared_debits
                    .iter()
                    .all(|debit| asset_allowed(&debit.asset))
                && match &claim.declared_fee {
                    bloom_broker_api::DeclaredFee::None => true,
                    bloom_broker_api::DeclaredFee::Fee { chain, asset, .. } => {
                        asset_allowed(&bloom_broker_api::AssetId {
                            chain: chain.clone(),
                            asset: asset.clone(),
                        })
                    }
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
                .filter(|attempt| !attempt.exact_fallback)
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

    /// Freeze the entire pool before the first ceremony. Interrupted activation
    /// can then resume later members without a fresh nonce or shifted limits.
    pub async fn stage_persona_sessions(
        &self,
        proposals: &[PersonaSessionProposal],
    ) -> Result<(), ProtocolError> {
        let root = self
            .persona_session_root
            .as_ref()
            .ok_or_else(|| io_error("session store is not configured"))?;
        let _gate = self.persona_session_gate.lock().await;
        let _lock = store_lock(root)?;
        for proposal in proposals {
            proposal.terms.validate()?;
            let id = proposal.terms.approval_id()?;
            if let Some(record) = read_json::<SessionRecord>(&grant_path(root, &id))?
                && record.proposal != *proposal
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "staged session differs from frozen proposal",
                ));
            }
        }
        // A single manifest commits the full selection before per-member files.
        // A crash during staging can reconstruct the remaining frozen members.
        let manifest_id = jcs_digest(&proposals)?;
        atomic_json(
            &root
                .join("pools")
                .join(format!("{}.json", manifest_id.as_str())),
            &proposals,
        )?;
        for proposal in proposals {
            let id = proposal.terms.approval_id()?;
            let path = grant_path(root, &id);
            if let Some(record) = read_json::<SessionRecord>(&path)? {
                if record.proposal != *proposal {
                    return Err(ProtocolError::new(
                        ProtocolErrorCode::OperationIdConflict,
                        "staged session differs from frozen proposal",
                    ));
                }
            } else {
                atomic_json(
                    &path,
                    &SessionRecord {
                        proposal: proposal.clone(),
                        disabled: false,
                        revoke_request: None,
                        revoke_confirmed: false,
                        last_fallback_code: None,
                        rearm_operation_id: None,
                    },
                )?;
            }
        }
        Ok(())
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
                    revoke_confirmed: false,
                    last_fallback_code: None,
                    rearm_operation_id: None,
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
                    safe_review_payloads: vec![],
                    message_review_payloads: vec![],
                    evm_reported_token: None,
                    evm_review_payloads: Vec::new(),
                })
                .await?;
            }
            Err(error) => return Err(error),
        }
        self.persona_status_for(&record).await
    }

    /// Owner-requested unlock of unchanged standing terms. A rearm never
    /// creates a grant, rotates an economic budget or resets a counter.
    pub async fn rearm_persona_session(
        &self,
        wallet: &Token,
        approval: Option<&Digest32>,
        new_operation: OperationId,
    ) -> Result<PersonaSessionStatus, ProtocolError> {
        let root = self
            .persona_session_root
            .as_ref()
            .ok_or_else(|| io_error("session store is not configured"))?;
        let _gate = self.persona_session_gate.lock().await;
        let _lock = store_lock(root)?;
        let mut record = records(root)?
            .into_iter()
            .find(|r| {
                !r.disabled
                    && &r.proposal.terms.wallet_id == wallet
                    && approval.is_none_or(|id| r.proposal.terms.approval_id().as_ref() == Ok(id))
            })
            .ok_or_else(|| io_error("no matching standing persona permission"))?;
        let status = self.persona_status_for(&record).await?;
        if status.authority.state != ApprovalLifecycleState::Active
            || record.proposal.terms.expires_at_ms.get() != u64::MAX
            || !matches!(
                record.proposal.terms.activation_mode,
                bloom_broker_api::ActivationMode::DurableLocal { .. }
            )
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ApprovalRevoked,
                "only an active standing local permission can be rearmed",
            ));
        }
        if status.authority.ceremony_url.is_some() {
            return Ok(status);
        }
        let operation = if let Some(op) = record.rearm_operation_id.clone() {
            match self.ceremony_status(op.clone()).await {
                Ok(prior)
                    if matches!(
                        prior.state,
                        bloom_broker_api::CeremonyState::Succeeded
                            | bloom_broker_api::CeremonyState::Completed
                            | bloom_broker_api::CeremonyState::Cancelled
                            | bloom_broker_api::CeremonyState::Expired
                            | bloom_broker_api::CeremonyState::Failed
                            | bloom_broker_api::CeremonyState::AlreadyRegistered
                    ) =>
                {
                    new_operation
                }
                Ok(_) => op,
                Err(error) if error.code == ProtocolErrorCode::ApprovalNotFound => op,
                Err(error) => return Err(error),
            }
        } else {
            new_operation
        };
        record.rearm_operation_id = Some(operation.clone());
        atomic_json(&grant_path(root, &status.approval_id), &record)?;
        self.prepare_approval(ApprovalPrepareRequest {
            surface_selection: bloom_broker_api::CeremonySurfaceSelection::Default,
            operation_id: operation,
            terms: record.proposal.terms.clone(),
            canonical_plan_facts_digest: record.proposal.canonical_plan_facts_digest.clone(),
            petal_use_claim: None,
            system_use_claim: None,
            safe_review_payloads: vec![],
            message_review_payloads: vec![],
            evm_reported_token: None,
            evm_review_payloads: vec![],
        })
        .await?;
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
        let (usage, usage_error) = if matches!(
            authority.state,
            ApprovalLifecycleState::Active | ApprovalLifecycleState::Exhausted
        ) {
            match self.approval_limit_state(id.clone()).await {
                Ok(usage) => {
                    if usage.approval_id != id {
                        return Err(ProtocolError::new(
                            ProtocolErrorCode::OperationIdConflict,
                            "persona usage identity mismatch",
                        ));
                    }
                    (Some(usage), None)
                }
                Err(error)
                    if matches!(
                        error.code,
                        ProtocolErrorCode::ServiceUnavailable
                            | ProtocolErrorCode::ClockUntrusted
                            | ProtocolErrorCode::ClockRollback
                            | ProtocolErrorCode::QuotaExceeded
                            | ProtocolErrorCode::AssuranceUnavailable
                    ) =>
                {
                    (None, Some(error.code))
                }
                Err(error) => return Err(error),
            }
        } else {
            (None, None)
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
            last_fallback_code: record.last_fallback_code,
            usage_error,
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
        let mut pools = std::collections::BTreeMap::new();
        let retained = records(root)?;
        // One local marker disables the entire pool across a crash while its
        // individual stop records are being rewritten. Broker is still truth.
        for record in &retained {
            if &record.proposal.terms.wallet_id == wallet
                && let Some(budget) = &record.proposal.terms.session_budget
                && budget.token_policy.is_some()
            {
                let budget_id = budget.budget_id()?;
                let path = root
                    .join("stops")
                    .join(format!("{}.json", budget_id.as_str()));
                if read_json::<bloom_broker_api::SessionStopRequest>(&path)?.is_none() {
                    atomic_json(
                        &path,
                        &bloom_broker_api::SessionStopRequest {
                            operation_id: OperationId::from_bytes(
                                Sha256::digest(
                                    [
                                        b"bloom.persona.pool-stop/v2".as_slice(),
                                        budget_id.as_str().as_bytes(),
                                    ]
                                    .concat(),
                                )
                                .into(),
                            ),
                            budget_id,
                            reason: reason.to_owned(),
                        },
                    )?;
                }
            }
        }
        for mut record in retained {
            if &record.proposal.terms.wallet_id != wallet {
                continue;
            }
            record.disabled = true;
            if let Some(budget) = &record.proposal.terms.session_budget
                && budget.token_policy.is_some()
            {
                let id = budget.budget_id()?;
                pools.insert(id.as_str().to_owned(), id);
            }
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
            // A local receipt is only a cache hint: confirm the remote state
            // before skipping a revocation, even when a prior stop succeeded.
            let remotely_revoked = record.revoke_confirmed
                && self.approval_status(id.clone()).await.is_ok_and(|status| {
                    status.approval_id == id
                        && &status.wallet_id == wallet
                        && status.state == ApprovalLifecycleState::Revoked
                });
            if !remotely_revoked {
                stopped.push((id, record.revoke_request.expect("frozen above")));
            }
        }
        // Fence every shared pool in Broker before any member revocation.
        // Local records above are already disabled even if this RPC is lost.
        for (_, budget_id) in pools {
            let request: bloom_broker_api::SessionStopRequest = read_json(
                &root
                    .join("stops")
                    .join(format!("{}.json", budget_id.as_str())),
            )?
            .ok_or_else(|| io_error("frozen pool stop disappeared"))?;
            if request.budget_id != budget_id {
                return Err(ProtocolError::new(
                    ProtocolErrorCode::OperationIdConflict,
                    "frozen pool stop identity changed",
                ));
            }
            match self
                .request(MachineBrokerRequest::SessionStop(request))
                .await?
            {
                MachineBrokerResponse::SessionStop(response) if response.budget_id == budget_id => {
                }
                _ => return Err(response_mismatch("session.stop")),
            }
        }
        let mut failures = Vec::new();
        for (id, request) in stopped {
            let confirmed = match self.revoke_approval(request).await {
                Ok(_) => true,
                Err(error) => match self.approval_status(id.clone()).await {
                    Ok(status)
                        if status.approval_id == id
                            && &status.wallet_id == wallet
                            && status.state == ApprovalLifecycleState::Revoked =>
                    {
                        true
                    }
                    _ => {
                        failures.push(error.code.as_str());
                        false
                    }
                },
            };
            if confirmed {
                let path = grant_path(root, &id);
                let mut record: SessionRecord =
                    read_json(&path)?.ok_or_else(|| io_error("stopped grant disappeared"))?;
                record.revoke_confirmed = true;
                atomic_json(&path, &record)?;
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
            request
                .message_review_payload
                .as_deref()
                .or(request.claim_assurance_evidence.as_deref()),
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
        // Selection is structural. Broker owns profile-specific verification,
        // economic admission; unrelated Petals need no global
        // application-name gate or fabricated witness.
        if !matches!(
            (provenance, claim, system_use),
            (ProvenanceSubject::Petal { .. }, Some(_), None)
                | (ProvenanceSubject::System { .. }, None, Some(_))
        ) {
            return Ok(None);
        }
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
            if attempt.exact_fallback {
                return Ok(None);
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
                if terms
                    .session_budget
                    .as_ref()
                    .is_some_and(|b| b.token_policy.is_some())
                    && claim.is_some_and(|c| {
                        c.economic_effects.as_ref().is_none_or(|e| {
                            e.permission_effect != bloom_broker_api::SessionPermissionEffect::None
                        })
                    })
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
                // Do not convert quantities locally. An allowed token need not
                // have a nominal conversion; only Broker can admit its value.
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
        let operation_digest = SignOperationIdentity {
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
                _ => system_use
                    .map(bloom_broker_api::session_native_claim_digests)
                    .transpose()?
                    .map(|pair| pair.0),
            },
            claim_assurance_digest: match (claim, system_claim) {
                (Some(claim), _) => Some(jcs_digest(&claim.claim_assurance)?),
                (_, Some(claim)) => Some(jcs_digest(&claim.claim_assurance)?),
                _ => system_use
                    .map(bloom_broker_api::session_native_claim_digests)
                    .transpose()?
                    .map(|pair| pair.1),
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
                    exact_fallback: false,
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
                let recovery_status = self.operation_status(operation_id.clone()).await;
                if let Ok(status) = &recovery_status
                    && status.operation_id == expected.operation_id
                    && status.operation_digest == expected.operation_digest
                    && let Some(result) = &status.result
                {
                    return expected.validate(result.clone()).map(Some);
                }
                // Unsupported/degraded native verification may request exact
                // review. A negative authenticated status is mandatory before
                // changing authority; an existing or unreadable operation can
                // already hold a signature/reservation and stays pinned.
                let native_exact_stepup = system_use.is_some()
                    && matches!(provenance, ProvenanceSubject::System { .. })
                    && matches!(
                        error.code,
                        ProtocolErrorCode::SelectorMismatch | ProtocolErrorCode::EffectsUnsupported
                    )
                    && recovery_status
                        .as_ref()
                        .is_err_and(|status| status.code == ProtocolErrorCode::ApprovalNotFound);
                if native_exact_stepup {
                    // Native step-up additionally proves no retained operation exists.
                    // Retain source identity while making the fallback durable.
                    let mut attempt: SigningAttempt =
                        read_json(&path)?.ok_or_else(|| io_error("missing frozen attempt"))?;
                    attempt.exact_fallback = true;
                    atomic_json(&path, &attempt)?;
                    let mut record = record.clone();
                    record.last_fallback_code = Some(error.code);
                    atomic_json(&grant_path(root, &attempt.approval_id), &record)?;
                    return Ok(None);
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

fn records(root: &Path) -> Result<Vec<SessionRecord>, ProtocolError> {
    match fs::read_dir(root.join("pools")) {
        Ok(entries) => {
            for entry in entries {
                let path = entry.map_err(io_error)?.path();
                if path.extension().is_some_and(|e| e == "json") {
                    let proposals: Vec<PersonaSessionProposal> =
                        read_json(&path)?.ok_or_else(|| io_error("staged pool disappeared"))?;
                    if proposals.is_empty()
                        || proposals.len() > 128
                        || path.file_stem().and_then(|s| s.to_str())
                            != Some(jcs_digest(&proposals)?.as_str())
                    {
                        return Err(io_error("invalid frozen pool manifest"));
                    }
                    for proposal in proposals {
                        let path = grant_path(root, &proposal.terms.approval_id()?);
                        if read_json::<SessionRecord>(&path)?.is_none() {
                            atomic_json(
                                &path,
                                &SessionRecord {
                                    proposal,
                                    disabled: false,
                                    revoke_request: None,
                                    revoke_confirmed: false,
                                    last_fallback_code: None,
                                    rearm_operation_id: None,
                                },
                            )?;
                        }
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(e)),
    }
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
            let mut record = read_json::<SessionRecord>(&path)?
                .ok_or_else(|| io_error("grant disappeared during discovery"))?;
            if let Some(budget) = &record.proposal.terms.session_budget
                && budget.token_policy.is_some()
                && root
                    .join("stops")
                    .join(format!("{}.json", budget.budget_id()?.as_str()))
                    .exists()
            {
                record.disabled = true;
            }
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
        AssetId, DecimalU256, KeySpec, NormalizedSignature, OperationState, SystemSessionAction,
        SystemSessionChain, SystemSessionUse,
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
            chain: token("polygon"),
            asset: "pusd".into(),
        };
        let terms = SealedApprovalTerms {
            session_budget: None,
            subject: ApprovalSubject::Petal {
                package_hash: digest(4),
                route: "trade/wallet/0/new".into(),
                agent_id: None,
            },
            wallet_id: token("wallet"),
            key_ref: key(),
            allowed_crypto_suites: vec![CryptoSuite::Secp256k1Keccak256Recoverable],
            selector: ApprovalSelector::Petal {
                package_hash: digest(4),
                route: "trade/wallet/0/new".into(),
                allowed_operation_classes: vec![token("polymarket.order.poly1271")],
                route_grants: vec![],
                required_claim_assurance: bloom_broker_api::ClaimAssuranceLevel::MachineAsserted,
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
        reject_limit: bool,
        native_refusal: bool,
        retain_native_refusal: bool,
        status_unavailable: bool,
        pending: BTreeMap<String, Digest32>,
        pool_stop_requests: Vec<bloom_broker_api::SessionStopRequest>,
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
                    MachineBrokerRequest::WalletAccounts(request) => {
                        let accounts = state
                            .wallet
                            .key_refs
                            .iter()
                            .filter_map(|key| {
                                let Some(bloom_broker_api::DerivationRef::Bip39Multicurve {
                                    profile,
                                    path,
                                    ..
                                }) = &key.derivation
                                else {
                                    return None;
                                };
                                Some(bloom_broker_api::DerivedAccountPublic {
                                    key_ref: key.clone(),
                                    wallet_seed_profile:
                                        bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
                                    derivation_profile: *profile,
                                    path: path.clone(),
                                    canonical_public_key: Base64UrlBytes::from_bytes(&[2; 33]),
                                    public_key_encoding: if key.key_spec == KeySpec::Ed25519 {
                                        bloom_broker_api::PublicKeyEncoding::Ed25519SpkiDer
                                    } else {
                                        bloom_broker_api::PublicKeyEncoding::Secp256k1SpkiDer
                                    },
                                    public_key_fingerprint: key.public_key_fingerprint.clone(),
                                    supported_crypto_suites: vec![if key.key_spec
                                        == KeySpec::Ed25519
                                    {
                                        CryptoSuite::Ed25519Message
                                    } else {
                                        CryptoSuite::Secp256k1Keccak256Recoverable
                                    }],
                                    chain_projections: vec![],
                                    lifecycle: bloom_broker_api::AccountLifecycleState::Active,
                                })
                            })
                            .collect();
                        Ok(MachineBrokerResponse::WalletAccounts(
                            bloom_broker_api::WalletAccountsPublic {
                                wallet_id: request.wallet_id,
                                seed_profile:
                                    bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
                                accounts,
                            },
                        ))
                    }
                    MachineBrokerRequest::KeyGetPublic(request) => {
                        let suite = if request.key_ref.key_spec == KeySpec::Ed25519 {
                            CryptoSuite::Ed25519Message
                        } else {
                            CryptoSuite::Secp256k1Keccak256Recoverable
                        };
                        Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                            role: if state.wallet.root_key_ref.is_some() {
                                bloom_broker_api::KeyRole::WalletRoot
                            } else {
                                bloom_broker_api::KeyRole::Derived
                            },
                            key_ref: request.key_ref,
                            canonical_public_key: Base64UrlBytes::from_bytes(&[2; 33]),
                            addresses: vec!["0x0000000000000000000000000000000000000001".into()],
                            supported_crypto_suites: vec![suite],
                        }))
                    }
                    MachineBrokerRequest::SealedApprovalLimitState(_) => Err(ProtocolError::new(
                        ProtocolErrorCode::ClockUntrusted,
                        "usage unavailable while clock is untrusted",
                    )),
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
                        if state.status_unavailable {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::ServiceUnavailable,
                                "status unavailable",
                            ));
                        }
                        if let Some(digest) = state.pending.get(request.operation_id.as_str()) {
                            return Ok(MachineBrokerResponse::OperationStatus(
                                OperationPublicStatus {
                                    operation_id: request.operation_id,
                                    operation_digest: digest.clone(),
                                    state: OperationState::Reserved,
                                    result: None,
                                    error: None,
                                },
                            ));
                        }
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
                        if state.native_refusal {
                            if state.retain_native_refusal {
                                state.pending.insert(
                                    request.operation_id.as_str().to_owned(),
                                    request.operation_digest,
                                );
                            }
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::SelectorMismatch,
                                "native RPC context unavailable; exact approval required",
                            ));
                        }
                        if state.reject_limit {
                            return Err(ProtocolError::new(
                                ProtocolErrorCode::LimitExceededValue,
                                "token allowance exceeded; no reservation/signature",
                            ));
                        }
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
                                bytes: Base64UrlBytes::from_bytes(&vec![
                                    7;
                                    if request.crypto_suite == CryptoSuite::Ed25519Message {
                                        64
                                    } else {
                                        65
                                    }
                                ]),
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
                    MachineBrokerRequest::SessionStop(request) => {
                        state.pool_stop_requests.push(request.clone());
                        Ok(MachineBrokerResponse::SessionStop(
                            bloom_broker_api::SessionStopResponse {
                                budget_id: request.budget_id,
                                revoked: vec![],
                                pending: vec![],
                            },
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
            reject_limit: false,
            native_refusal: false,
            retain_native_refusal: false,
            status_unavailable: false,
            pending: BTreeMap::new(),
            pool_stop_requests: vec![],
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
                revoke_confirmed: false,
                last_fallback_code: None,
                rearm_operation_id: None,
            },
        )
        .unwrap();
        (directory, client, broker)
    }
    fn use_claim(payload: &[u8], chain: u64) -> PetalUseClaim {
        PetalUseClaim {
            economic_effects: None,
            package_hash: digest(4), route: "trade/wallet/0/new".into(), operation_class: token("polymarket.order.poly1271"),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: petal_batch_payload_digest(&[payload.to_vec()]),
            ordered_hashes: vec![suite_hash(CryptoSuite::Secp256k1Keccak256Recoverable,payload)],
            declared_debits: serde_json::from_value(serde_json::json!([{"asset":{"chain":if chain==1 {"polygon"} else {"ethereum"},"asset":"pusd"},"amount":"10"}])).unwrap(),
            declared_destinations:vec![], declared_fee:bloom_broker_api::DeclaredFee::None,
            nonce:RequestNonce::from_bytes([1;16]), claim_assurance:bloom_broker_api::ClaimAssurance::MachineAsserted,
        }
    }
    async fn sign(
        client: &MachineBrokerClient,
        operation: u8,
        payload: &[u8],
        action: &SystemSessionUse,
    ) -> Result<Option<SigningResult>, ProtocolError> {
        let chain = match &action.chain {
            SystemSessionChain::Evm { chain_id, .. } => chain_id.get(),
            _ => 0,
        };
        let claim = use_claim(payload, chain);
        client
            .try_persona_sign_payloads(
                &token("wallet"),
                &key(),
                CryptoSuite::Secp256k1Keccak256Recoverable,
                &ProvenanceSubject::Petal {
                    package_hash: digest(4),
                    route: "trade/wallet/0/new".into(),
                },
                &digest(83),
                Some(&claim),
                None,
                None,
                Some(b"retained prepared order witness"),
                &OperationId::from_bytes([operation; 32]),
                &[payload.to_vec()],
                false,
            )
            .await
    }
    fn install_native_fixture(directory: &Path) {
        use bloom_broker_api::*;
        let mut record = records(directory).unwrap().remove(0);
        let old = record.proposal.terms.approval_id().unwrap();
        let use_ = action(1);
        let asset = AssetId {
            chain: token("evm-1"),
            asset: "native".into(),
        };
        record.proposal.terms.subject = ApprovalSubject::System {
            component_id: token("bloom-machine"),
            operation_class: token("transaction.confirm"),
        };
        record.proposal.terms.selector = ApprovalSelector::SystemSession {
            scope: SystemSessionScope {
                any_erc20_recipient: false,
                component_id: token("bloom-machine"),
                actions: vec![SystemSessionAction::NativeTransfer],
                chains: vec![use_.chain],
                destinations: vec![PolicyDestination {
                    chain: token("evm-1"),
                    destination: use_.recipient,
                }],
                tokens: vec![],
                per_action_value_limits: vec![SessionValueCeiling {
                    asset: asset.clone(),
                    maximum: DecimalU256::parse("1000").unwrap(),
                }],
            },
        };
        record.proposal.terms.limits.value_limits = vec![ValueLimit {
            asset,
            lifetime: DecimalU256::parse("1000").unwrap(),
            rolling_windows: vec![],
        }];
        let template = record.proposal.terms.clone();
        let scope_digest = session_member_scope_digest(&template).unwrap();
        let asset = AssetId {
            chain: token("evm-1"),
            asset: "native".into(),
        };
        record.proposal.terms.session_budget = Some(SessionBudget {
            token_policy: Some(SessionTokenPolicy {
                schema_version: 3,
                budget_nonce: RequestNonce::from_bytes([63; 16]),
                member_scope_digests: vec![scope_digest.clone()],
                member_backstop_allocations: vec![SessionMemberAllocation {
                    scope_digest,
                    limits: template.limits.clone(),
                }],
                member_templates: vec![template.clone()],
                assets: vec![approved_session_asset(&asset).unwrap()],
            }),
            wallet_id: template.wallet_id.clone(),
            policy_version: template.policy_version.clone(),
            policy_digest: template.policy_digest.clone(),
            wallet_revocation_epoch: template.wallet_revocation_epoch.clone(),
            member_keys: vec![template.key_ref.clone()],
            limits: template.limits.clone(),
            per_action_value_limits: vec![SessionValueCeiling {
                asset,
                maximum: DecimalU256::parse("1000").unwrap(),
            }],
            not_before_ms: template.not_before_ms,
            expires_at_ms: template.expires_at_ms,
        });
        fs::remove_file(grant_path(directory, &old)).unwrap();
        atomic_json(
            &grant_path(directory, &record.proposal.terms.approval_id().unwrap()),
            &record,
        )
        .unwrap();
    }
    async fn native_sign(
        client: &MachineBrokerClient,
        operation: u8,
    ) -> Result<Option<SigningResult>, ProtocolError> {
        client
            .try_persona_sign_payloads(
                &token("wallet"),
                &key(),
                CryptoSuite::Secp256k1Keccak256Recoverable,
                &ProvenanceSubject::System {
                    component_id: token("bloom-machine"),
                    operation_class: token("transaction.confirm"),
                },
                &digest(83),
                None,
                None,
                Some(&action(1)),
                None,
                &OperationId::from_bytes([operation; 32]),
                &[b"native transfer bytes".to_vec()],
                false,
            )
            .await
    }
    #[tokio::test]
    async fn pool_stop_retries_freeze_the_original_reason_and_fence_identity() {
        let (directory, client, broker) = fixture();
        install_native_fixture(directory.path());
        client
            .stop_persona_sessions(&token("wallet"), "original stop")
            .await
            .unwrap();
        client
            .stop_persona_sessions(&token("wallet"), "different retry reason")
            .await
            .unwrap();
        let state = broker.0.lock().unwrap();
        assert_eq!(state.pool_stop_requests.len(), 2);
        assert_eq!(state.pool_stop_requests[0], state.pool_stop_requests[1]);
        assert_eq!(state.pool_stop_requests[0].reason, "original stop");
    }

    #[tokio::test]
    async fn native_degraded_context_steps_up_only_after_authoritative_absence() {
        for (retain, unavailable, expect_fallback) in [
            (false, false, true),
            (true, false, false),
            (false, true, false),
        ] {
            let (directory, client, broker) = fixture();
            install_native_fixture(directory.path());
            {
                let mut state = broker.0.lock().unwrap();
                state.native_refusal = true;
                state.retain_native_refusal = retain;
                state.status_unavailable = unavailable;
            }
            let result = native_sign(&client, 92).await;
            if expect_fallback {
                assert!(result.unwrap().is_none());
                broker.0.lock().unwrap().native_refusal = false;
                assert!(native_sign(&client, 92).await.unwrap().is_none());
                assert_eq!(
                    records(directory.path()).unwrap()[0].last_fallback_code,
                    Some(ProtocolErrorCode::SelectorMismatch)
                );
            } else {
                assert_eq!(
                    result.unwrap_err().code,
                    ProtocolErrorCode::SelectorMismatch
                );
            }
            assert_eq!(broker.0.lock().unwrap().signatures, 0);
            assert_eq!(
                read_json::<SigningAttempt>(&attempt_path(
                    directory.path(),
                    &OperationId::from_bytes([92; 32])
                ))
                .unwrap()
                .unwrap()
                .exact_fallback,
                expect_fallback
            );
        }
    }

    #[tokio::test]
    async fn degraded_usage_does_not_hide_live_authority_status() {
        let (_directory, client, _broker) = fixture();
        let statuses = client.persona_sessions(&token("wallet")).await.unwrap();
        assert_eq!(statuses[0].authority.state, ApprovalLifecycleState::Active);
        assert!(statuses[0].usage.is_none());
        assert_eq!(
            statuses[0].usage_error,
            Some(ProtocolErrorCode::ClockUntrusted)
        );
    }

    #[tokio::test]
    async fn unrelated_evm_and_svm_petals_use_one_pool_through_public_host_adapter() {
        use bloom_broker_api::*;
        let (directory, client, broker) = fixture();
        let original = proposal();
        fs::remove_file(grant_path(
            directory.path(),
            &original.terms.approval_id().unwrap(),
        ))
        .unwrap();
        let assets = [
            AssetId {
                chain: token("evm-137"),
                asset: "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb".into(),
            },
            AssetId {
                chain: token("solana-mainnet"),
                asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            },
        ];
        let mut proposals = Vec::new();
        for (i, profile, suite, path) in [
            (
                0,
                DerivationProfile::Bip44EvmSecp256k1V1,
                CryptoSuite::Secp256k1Keccak256Recoverable,
                "m/44'/60'/0'/0/0",
            ),
            (
                1,
                DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                CryptoSuite::Ed25519Message,
                "m/44'/501'/0'/0'",
            ),
        ] {
            let mut p = original.clone();
            p.terms.key_ref.key_spec = suite.key_spec();
            p.terms.key_ref.locator = format!("child-{i}");
            p.terms.key_ref.public_key_fingerprint = digest(30 + i as u8);
            p.terms.key_ref.derivation = Some(DerivationRef::Bip39Multicurve {
                wallet_seed_ref: token("seed"),
                profile,
                path: path.into(),
            });
            p.terms.allowed_crypto_suites = vec![suite];
            p.terms.subject = ApprovalSubject::Petal {
                package_hash: digest(40 + i as u8),
                route: format!("application-{i}/wallet/0/action"),
                agent_id: None,
            };
            p.terms.selector = ApprovalSelector::Petal {
                package_hash: digest(40 + i as u8),
                route: format!("application-{i}/wallet/0/action"),
                allowed_operation_classes: vec![token(&format!("example-{i}.swap"))],
                route_grants: vec![],
                required_claim_assurance: ClaimAssuranceLevel::MachineAsserted,
            };
            p.terms.limits.value_limits.clear();
            p.prepare_operation_id = OperationId::from_bytes([30 + i as u8; 32]);
            proposals.push(p);
        }
        let mut members = proposals
            .iter()
            .map(|p| p.terms.clone())
            .collect::<Vec<_>>();
        members.sort_by_key(|t| session_member_scope_digest(t).unwrap().as_str().to_owned());
        let mut limits = original.terms.limits.clone();
        limits.value_limits.clear();
        limits.max_operations = DecimalU64::new(limits.max_operations.get() * 2);
        limits.max_signatures = DecimalU64::new(limits.max_signatures.get() * 2);
        let mut budget = SessionBudget {
            token_policy: Some(SessionTokenPolicy {
                schema_version: 3,
                budget_nonce: RequestNonce::from_bytes([55; 16]),
                member_scope_digests: members
                    .iter()
                    .map(|t| session_member_scope_digest(t).unwrap())
                    .collect(),
                member_backstop_allocations: members
                    .iter()
                    .map(|t| SessionMemberAllocation {
                        scope_digest: session_member_scope_digest(t).unwrap(),
                        limits: t.limits.clone(),
                    })
                    .collect(),
                member_templates: members,
                assets: assets
                    .iter()
                    .map(|a| approved_session_asset(a).unwrap())
                    .collect(),
            }),
            wallet_id: token("wallet"),
            policy_version: original.terms.policy_version.clone(),
            policy_digest: original.terms.policy_digest.clone(),
            wallet_revocation_epoch: original.terms.wallet_revocation_epoch.clone(),
            member_keys: proposals.iter().map(|p| p.terms.key_ref.clone()).collect(),
            limits,
            per_action_value_limits: assets
                .iter()
                .map(|a| SessionValueCeiling {
                    asset: a.clone(),
                    maximum: DecimalU256::parse("100000000").unwrap(),
                })
                .collect(),
            not_before_ms: original.terms.not_before_ms,
            expires_at_ms: original.terms.expires_at_ms,
        };
        budget.limits.value_limits = assets
            .iter()
            .map(|asset| bloom_broker_api::ValueLimit {
                asset: asset.clone(),
                lifetime: DecimalU256::parse("10000000000000000000").unwrap(),
                rolling_windows: vec![],
            })
            .collect();
        budget.validate().unwrap();
        for p in &mut proposals {
            p.terms.session_budget = Some(budget.clone());
            p.terms.validate().unwrap();
        }
        {
            let mut state = broker.0.lock().unwrap();
            state.wallet.root_key_ref = None;
            state.wallet.key_refs = proposals.iter().map(|p| p.terms.key_ref.clone()).collect();
        }
        client.stage_persona_sessions(&proposals).await.unwrap();
        for (i, p) in proposals.iter().enumerate() {
            let suite = p.terms.allowed_crypto_suites[0];
            let payload = format!("trusted generic transaction {i}").into_bytes();
            let ApprovalSelector::Petal {
                package_hash,
                route,
                allowed_operation_classes,
                ..
            } = &p.terms.selector
            else {
                panic!()
            };
            let mut claim = use_claim(&payload, 1);
            claim.package_hash = package_hash.clone();
            claim.route = route.clone();
            claim.operation_class = allowed_operation_classes[0].clone();
            claim.crypto_suite = suite;
            claim.ordered_hashes = vec![suite_hash(suite, &payload)];
            claim.declared_debits[0].asset = assets[i].clone();
            claim.economic_effects = Some(EconomicEffectsV1 {
                schema_version: 1,
                payload_contexts: vec![SessionPayloadContext {
                    payload_index: 0,
                    network: assets[i].chain.clone(),
                    spending_accounts: vec![],
                }],
                permission_effect: SessionPermissionEffect::None,
            });
            let request = ExactPayloadSignRequest {
                session_use: None,
                evm_reported_token: None,
                wallet_id: token("wallet"),
                preimage: payload.clone(),
                claimed_hash: suite_hash(suite, &payload),
                crypto_suite: suite,
                provenance: ProvenanceSubject::Petal {
                    package_hash: package_hash.clone(),
                    route: route.clone(),
                },
                provenance_digest: p.terms.provenance_digest.clone(),
                activation_mode: None,
                approval_operation_id: OperationId::from_bytes([61 + i as u8; 32]),
                signing_operation_id: OperationId::from_bytes([71 + i as u8; 32]),
                request_nonce: RequestNonce::from_bytes([81 + i as u8; 16]),
                issued_at_ms: DecimalU64::new(10),
                expires_at_ms: DecimalU64::new(20),
                canonical_plan_facts_digest: digest(91),
                approval_id: None,
                petal_use_claim: Some(claim),
                system_use_claim: None,
                claim_assurance_evidence: None,
                approval_value_limits: vec![],
                account_key_ref: Some(p.terms.key_ref.clone()),
                safe_review_payload: None,
                message_review_payload: None,
            };
            assert!(matches!(
                client.sign_exact_payload(request).await.unwrap(),
                ExactPayloadSignOutcome::Signed(_)
            ));
        }
        assert_eq!(broker.0.lock().unwrap().signatures, 2);
        assert_eq!(broker.0.lock().unwrap().preparations, 0);
        assert_eq!(
            records(directory.path())
                .unwrap()
                .iter()
                .map(|r| r
                    .proposal
                    .terms
                    .session_budget
                    .as_ref()
                    .unwrap()
                    .budget_id()
                    .unwrap())
                .map(|d| d.as_str().to_owned())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn arbitrary_certified_petal_class_needs_no_polymarket_witness() {
        let (directory, client, broker) = fixture();
        let mut record = records(directory.path()).unwrap().remove(0);
        let old = record.proposal.terms.approval_id().unwrap();
        let ApprovalSelector::Petal {
            allowed_operation_classes,
            ..
        } = &mut record.proposal.terms.selector
        else {
            panic!()
        };
        *allowed_operation_classes = vec![token("example.swap.v1")];
        fs::remove_file(grant_path(directory.path(), &old)).unwrap();
        atomic_json(
            &grant_path(
                directory.path(),
                &record.proposal.terms.approval_id().unwrap(),
            ),
            &record,
        )
        .unwrap();
        let mut claim = use_claim(b"swap", 1);
        claim.operation_class = token("example.swap.v1");
        let result = client
            .try_persona_sign_payloads(
                &token("wallet"),
                &key(),
                claim.crypto_suite,
                &ProvenanceSubject::Petal {
                    package_hash: digest(4),
                    route: claim.route.clone(),
                },
                &digest(83),
                Some(&claim),
                None,
                None,
                None,
                &OperationId::from_bytes([22; 32]),
                &[b"swap".to_vec()],
                false,
            )
            .await
            .unwrap();
        assert!(result.is_some());
        assert_eq!(broker.0.lock().unwrap().signatures, 1);
    }

    #[tokio::test]
    async fn token_denial_does_not_rotate_authority_or_create_signatures() {
        let (directory, client, broker) = fixture();
        broker.0.lock().unwrap().reject_limit = true;
        assert_eq!(
            sign(&client, 21, b"limited", &action(1))
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::LimitExceededValue
        );
        let attempt = read_json::<SigningAttempt>(&attempt_path(
            directory.path(),
            &OperationId::from_bytes([21; 32]),
        ))
        .unwrap()
        .unwrap();
        assert!(!attempt.exact_fallback);
        assert_eq!(broker.0.lock().unwrap().signatures, 0);
        assert_eq!(
            sign(&client, 21, b"changed", &action(1))
                .await
                .unwrap_err()
                .code,
            ProtocolErrorCode::OperationIdConflict
        );
        broker.0.lock().unwrap().reject_limit = false;
        assert!(
            sign(&client, 21, b"limited", &action(1))
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(broker.0.lock().unwrap().signatures, 1);
    }

    #[tokio::test]
    async fn all_members_are_frozen_before_any_activation_rpc() {
        let (directory, client, broker) = fixture();
        let first = proposal();
        let mut second = first.clone();
        second.terms.request_nonce = RequestNonce::from_bytes([99; 16]);
        second.prepare_operation_id = OperationId::from_bytes([99; 32]);
        client
            .stage_persona_sessions(&[first, second])
            .await
            .unwrap();
        assert_eq!(records(directory.path()).unwrap().len(), 2);
        // Simulate a crash after writing the pool manifest and only one grant.
        let one = records(directory.path()).unwrap().remove(0);
        fs::remove_file(grant_path(
            directory.path(),
            &one.proposal.terms.approval_id().unwrap(),
        ))
        .unwrap();
        assert_eq!(records(directory.path()).unwrap().len(), 2);
        assert_eq!(broker.0.lock().unwrap().preparations, 0);
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
            session_use: None,
            evm_reported_token: None,
            wallet_id: token("wallet"),
            claimed_hash: suite_hash(CryptoSuite::Secp256k1Keccak256Recoverable, &payload),
            preimage: payload.clone(),
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            provenance: ProvenanceSubject::Petal {
                package_hash: digest(4),
                route: "trade/wallet/0/new".into(),
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
            petal_use_claim: Some(use_claim(&payload, 1)),
            system_use_claim: None,
            claim_assurance_evidence: Some(b"retained prepared order witness".to_vec()),
            approval_value_limits: vec![],
            account_key_ref: None,
            safe_review_payload: None,
            message_review_payload: Some(b"retained prepared order witness".to_vec()),
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
    async fn repeated_stop_skips_confirmed_remote_revocations() {
        let (directory, client, broker) = fixture();
        client
            .stop_persona_sessions(&token("wallet"), "pause")
            .await
            .unwrap();
        client
            .stop_persona_sessions(&token("wallet"), "pause again")
            .await
            .unwrap();
        assert!(!broker.0.lock().unwrap().active);
        assert!(records(directory.path()).unwrap()[0].revoke_confirmed);
    }

    #[tokio::test]
    async fn cached_stop_receipt_cannot_hide_a_live_remote_grant() {
        let (directory, client, broker) = fixture();
        let mut record = records(directory.path()).unwrap().remove(0);
        record.revoke_confirmed = true;
        atomic_json(
            &grant_path(
                directory.path(),
                &record.proposal.terms.approval_id().unwrap(),
            ),
            &record,
        )
        .unwrap();
        client
            .stop_persona_sessions(&token("wallet"), "pause")
            .await
            .unwrap();
        assert!(!broker.0.lock().unwrap().active);
    }

    #[tokio::test]
    async fn native_transfers_do_not_borrow_a_petal_session() {
        let (_, client, broker) = fixture();
        let result = client
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
                Some(&action(1)),
                None,
                &OperationId::from_bytes([7; 32]),
                &[b"native".to_vec()],
                false,
            )
            .await
            .unwrap();
        assert!(result.is_none());
        assert_eq!(broker.0.lock().unwrap().signatures, 0);
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
