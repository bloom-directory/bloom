//! Machine-owned binding and continuation of prepared Petal operations.
use super::*;
use bloom_petal_contract::prepared::{self, ErrorCode, SigningError, SigningOutcome};
use fs2::FileExt as _;
use sha2::{Digest as _, Sha256};
use std::io::Write as _;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    package_hash: String,
    route: String,
    wallet: String,
    key: bloom_broker_api::KeyRef,
    operation_key: String,
    action: prepared::PreparedAction,
    outcome: Option<SigningOutcome>,
}

fn error(code: ErrorCode, message: impl ToString) -> SigningError {
    SigningError {
        code,
        message: message.to_string(),
    }
}
fn host_error(e: HostError) -> SigningError {
    let code = match e {
        HostError::Invalid(_) => ErrorCode::Invalid,
        HostError::Denied(_) => ErrorCode::Denied,
        HostError::UnsupportedVersion(_) => ErrorCode::Unsupported,
        _ => ErrorCode::Backend,
    };
    error(code, e)
}
/// Preserve the prepared API's explicit reconciliation outcome across the
/// legacy single-message and batch signing transports.
fn prepared_signing_failure(e: HostError) -> Result<SigningOutcome, SigningError> {
    match e {
        HostError::Denied(message) if message.contains("APPROVAL_EXPIRED") => {
            Err(error(ErrorCode::Expired, message))
        }
        HostError::Denied(message)
            if message.contains("APPROVAL_REVOKED") || message.contains("CANCELLED") =>
        {
            Err(error(ErrorCode::Cancelled, message))
        }
        HostError::Denied(message)
            if message.contains("OperationIdConflict")
                || message.contains("OPERATION_ID_CONFLICT")
                || message.contains("RECOVERY_REQUIRED") =>
        {
            Ok(SigningOutcome::RecoveryRequired {
                status: "signing_outcome_ambiguous".into(),
            })
        }
        HostError::Backend(message) if message.contains("signing outcome unknown") => {
            Ok(SigningOutcome::RecoveryRequired {
                status: "signing_outcome_ambiguous".into(),
            })
        }
        other => Err(host_error(other)),
    }
}
fn suite(s: prepared::CryptoSuite) -> bloom_broker_api::CryptoSuite {
    match s {
        prepared::CryptoSuite::Keccak256 => {
            bloom_broker_api::CryptoSuite::Secp256k1Keccak256Recoverable
        }
        prepared::CryptoSuite::Sha256 => bloom_broker_api::CryptoSuite::Secp256k1Sha256Recoverable,
        prepared::CryptoSuite::Ed25519Message => bloom_broker_api::CryptoSuite::Ed25519Message,
    }
}
fn lock(root: &Path) -> Result<std::fs::File, SigningError> {
    std::fs::create_dir_all(root).map_err(|e| error(ErrorCode::Backend, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| error(ErrorCode::Backend, e))?;
    }
    let mut options = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(".lock"))
        .map_err(|e| error(ErrorCode::Backend, e))?;
    file.lock_exclusive()
        .map_err(|e| error(ErrorCode::Backend, e))?;
    Ok(file)
}
fn write_record(path: &Path, record: &Record) -> Result<(), SigningError> {
    let bytes = serde_json::to_vec(record).map_err(|e| error(ErrorCode::Backend, e))?;
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| error(ErrorCode::Backend, e))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| error(ErrorCode::Backend, e))?;
    std::fs::rename(&tmp, path).map_err(|e| error(ErrorCode::Backend, e))?;
    std::fs::File::open(path.parent().unwrap())
        .and_then(|f| f.sync_all())
        .map_err(|e| error(ErrorCode::Backend, e))
}
fn path(
    root: &Path,
    context: &PetalRouteContext,
    wallet: &str,
    key: &bloom_broker_api::KeyRef,
    operation_key: &str,
) -> Result<PathBuf, SigningError> {
    let identity = serde_jcs::to_vec(&(
        context.package_hash.as_str(),
        context.route_id.as_str(),
        wallet,
        key,
        operation_key,
    ))
    .map_err(|e| error(ErrorCode::Invalid, e))?;
    Ok(root.join(format!("{}.json", blake3::hash(&identity).to_hex())))
}
fn claim(
    context: &PetalRouteContext,
    action: &prepared::PreparedAction,
) -> Result<Vec<u8>, SigningError> {
    let mut h = Sha256::new();
    h.update(b"bloom.petal.payload-batch.v1\0");
    h.update(1u64.to_be_bytes());
    h.update((action.payload.preimage.len() as u64).to_be_bytes());
    h.update(&action.payload.preimage);
    let digest: [u8; 32] = h.finalize().into();
    let suite_name = match action.payload.suite {
        prepared::CryptoSuite::Keccak256 => "secp256k1-keccak256-recoverable",
        prepared::CryptoSuite::Sha256 => "secp256k1-sha256-recoverable",
        prepared::CryptoSuite::Ed25519Message => "ed25519-message",
    };
    let (debits, effects) = match &action.spend {
        prepared::Spend::Bounded { debits } => {
            let mut seen = std::collections::BTreeSet::new();
            let mut entries = Vec::with_capacity(debits.len());
            for d in debits {
                let asset = match &d.asset {
                    prepared::Asset::Erc20 { address } => address.clone(),
                    prepared::Asset::Erc1155 { address, token_id } => {
                        format!("erc1155:{address}:{token_id}")
                    }
                };
                if !seen.insert((d.network.clone(), asset.clone())) {
                    return Err(error(ErrorCode::Invalid, "duplicate debit asset"));
                }
                entries.push(serde_json::json!({"asset":{"chain":d.network,"asset":asset},"amount":d.amount}));
            }
            let effects = (debits.iter().all(|d| d.amount != "0") && debits.iter().all(|d| d.network == debits[0].network)).then(|| serde_json::json!({"schema_version":1,"spend":"bounded","permission_effect":"none","payload_contexts":[{"payload_index":0,"network":debits[0].network,"spending_accounts":[]}]}));
            (entries, effects)
        }
        prepared::Spend::None => {
            let review: serde_json::Value = serde_json::from_slice(&action.review.bytes)
                .map_err(|e| error(ErrorCode::Invalid, e))?;
            let chain_id = &review["typed_data"]["domain"]["chainId"];
            let chain = chain_id
                .as_u64()
                .map(|id| format!("evm-{id}"))
                .or_else(|| {
                    chain_id
                        .as_str()
                        .and_then(|id| id.parse::<u64>().ok())
                        .map(|id| format!("evm-{id}"))
                })
                .unwrap_or_else(|| "message".into());
            (
                Vec::new(),
                Some(
                    serde_json::json!({"schema_version":1,"spend":"none","permission_effect":"none","payload_contexts":[{"payload_index":0,"network":chain,"spending_accounts":[]}]}),
                ),
            )
        }
        prepared::Spend::Unspecified => (Vec::new(), None),
    };
    let nonce = Sha256::digest(
        [
            context.package_hash.as_bytes(),
            context.route_id.as_bytes(),
            action.operation_class.as_bytes(),
            digest.as_slice(),
        ]
        .concat(),
    );
    let value = serde_json::json!({"package_hash":context.package_hash,"route":context.route_id,"operation_class":action.operation_class,"crypto_suite":suite_name,"payload_digest":hex::encode(digest),"ordered_hashes":[hex::encode(action.payload.hash)],"declared_debits":debits,"declared_destinations":[],"declared_fee":{"kind":"none"},"economic_effects":effects,"nonce":hex::encode(&nonce[..16]),"claim_assurance":{"kind":"machine_asserted"}});
    let typed: bloom_broker_api::PetalUseClaim =
        serde_json::from_value(value).map_err(|e| error(ErrorCode::Invalid, e))?;
    serde_jcs::to_vec(&typed).map_err(|e| error(ErrorCode::Backend, e))
}

fn validate_message_review(action: &prepared::PreparedAction) -> Result<(), SigningError> {
    if action.review.format != "bloom.message.review" || action.review.version != 1 {
        return Err(error(
            ErrorCode::Unsupported,
            "review format is not supported",
        ));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&action.review.bytes).map_err(|e| error(ErrorCode::Invalid, e))?;
    if value["schema"] != "bloom.message.review.v1"
        || !matches!(value["kind"].as_str(), Some("eip712" | "personal"))
    {
        return Err(error(ErrorCode::Invalid, "invalid message review envelope"));
    }
    if action.payload.suite != prepared::CryptoSuite::Keccak256 {
        return Err(error(
            ErrorCode::Invalid,
            "message review requires recoverable Keccak signing",
        ));
    }
    let preimage = match value["kind"].as_str() {
        Some("eip712") => {
            let typed: alloy_dyn_abi::eip712::TypedData =
                serde_json::from_value(value["typed_data"].clone())
                    .map_err(|e| error(ErrorCode::Invalid, e))?;
            let mut preimage = vec![0x19, 0x01];
            preimage.extend_from_slice(typed.domain.separator().as_slice());
            if typed.primary_type != "EIP712Domain" {
                preimage.extend_from_slice(
                    typed
                        .hash_struct()
                        .map_err(|e| error(ErrorCode::Invalid, e))?
                        .as_slice(),
                );
            }
            preimage
        }
        Some("personal") => {
            let message = value["message"]
                .as_str()
                .ok_or_else(|| error(ErrorCode::Invalid, "personal review requires a message"))?;
            let mut preimage =
                format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
            preimage.extend_from_slice(message.as_bytes());
            preimage
        }
        _ => unreachable!(),
    };
    if action.payload.preimage != preimage
        || action.payload.hash != alloy::primitives::keccak256(&preimage).0
    {
        return Err(error(
            ErrorCode::Invalid,
            "message review differs from signing payload",
        ));
    }
    Ok(())
}

impl DaemonPetalHost {
    async fn prepared_key(
        &self,
        context: &PetalRouteContext,
        wallet: &str,
        crypto: prepared::CryptoSuite,
    ) -> Result<bloom_broker_api::KeyRef, SigningError> {
        if let Some(key) = self
            .account_owner(context, wallet, suite(crypto), None)
            .await
            .map_err(host_error)?
        {
            return Ok(key);
        }
        let broker = self
            .broker
            .as_ref()
            .ok_or_else(|| error(ErrorCode::Backend, "Broker unavailable"))?;
        let wallet = bloom_broker_api::Token::new(wallet.to_owned())
            .map_err(|e| error(ErrorCode::Invalid, e))?;
        broker
            .wallet(wallet)
            .await
            .map_err(|e| error(ErrorCode::Backend, e))?
            .root_key_ref
            .ok_or_else(|| error(ErrorCode::Denied, "missing exact root key"))
    }

    async fn prepared_verify(
        &self,
        key: &bloom_broker_api::KeyRef,
        action: &prepared::PreparedAction,
        signature: &[u8],
    ) -> Result<(), SigningError> {
        let broker = self
            .broker
            .as_ref()
            .ok_or_else(|| error(ErrorCode::Backend, "Broker unavailable"))?;
        let public = broker
            .key(bloom_broker_api::KeyRequest {
                key_ref: key.clone(),
            })
            .await
            .map_err(|e| error(ErrorCode::Backend, e))?;
        if public.key_ref != *key
            || !public
                .supported_crypto_suites
                .contains(&suite(action.payload.suite))
        {
            return Err(error(ErrorCode::Denied, "selected public key differs"));
        }
        let bytes = public.canonical_public_key.decode();
        if hex::encode(Sha256::digest(&bytes)) != key.public_key_fingerprint.as_str() {
            return Err(error(ErrorCode::Backend, "public key fingerprint differs"));
        }
        match action.payload.suite {
            prepared::CryptoSuite::Keccak256 | prepared::CryptoSuite::Sha256 => {
                let sig = alloy::primitives::Signature::from_raw(signature)
                    .map_err(|e| error(ErrorCode::Backend, e))?;
                let recovered = sig
                    .recover_from_prehash(&action.payload.hash.into())
                    .map_err(|e| error(ErrorCode::Backend, e))?;
                use k256::elliptic_curve::sec1::ToEncodedPoint as _;
                use k256::pkcs8::DecodePublicKey as _;
                let public = k256::PublicKey::from_public_key_der(&bytes)
                    .map_err(|e| error(ErrorCode::Backend, e))?;
                if recovered.to_encoded_point(true).as_bytes()
                    != public.to_encoded_point(true).as_bytes()
                {
                    return Err(error(
                        ErrorCode::Backend,
                        "signature does not match selected key",
                    ));
                }
            }
            prepared::CryptoSuite::Ed25519Message => {
                use ed25519_dalek::Verifier as _;
                use ed25519_dalek::pkcs8::DecodePublicKey as _;
                let key = ed25519_dalek::VerifyingKey::from_public_key_der(&bytes)
                    .map_err(|e| error(ErrorCode::Backend, e))?;
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|e| error(ErrorCode::Backend, e))?;
                key.verify(&action.payload.preimage, &sig)
                    .map_err(|e| error(ErrorCode::Backend, e))?;
            }
        }
        Ok(())
    }

    async fn prepared_ceremony_terminal(
        &self,
        root: &Path,
        outcome: &Option<SigningOutcome>,
    ) -> Result<Option<SigningError>, SigningError> {
        let Some(SigningOutcome::ApprovalPending { action_id, .. }) = outcome else {
            return Ok(None);
        };
        if !bloom_petals::store::is_valid_hex_hash(action_id) {
            return Ok(None);
        }
        let path = root
            .parent()
            .ok_or_else(|| error(ErrorCode::Backend, "invalid state root"))?
            .join(".state")
            .join(format!("{action_id}.json"));
        #[derive(serde::Deserialize)]
        struct ApprovalOperation {
            approval_operation_id: bloom_broker_api::OperationId,
        }
        let operation = match std::fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice::<ApprovalOperation>(&bytes)
                    .map_err(|e| error(ErrorCode::Backend, e))?
                    .approval_operation_id
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(error(ErrorCode::Backend, e)),
        };
        let Some(broker) = &self.broker else {
            return Err(error(ErrorCode::Backend, "Broker unavailable"));
        };
        let status = match broker.ceremony_status(operation.clone()).await {
            Ok(status) => status,
            Err(_) => return Ok(None),
        };
        if status.operation_id != operation {
            return Err(error(
                ErrorCode::Conflict,
                "ceremony status identity mismatch",
            ));
        }
        Ok(match status.state {
            bloom_broker_api::CeremonyState::Cancelled => {
                Some(error(ErrorCode::Cancelled, "approval ceremony cancelled"))
            }
            bloom_broker_api::CeremonyState::Expired => {
                Some(error(ErrorCode::Expired, "approval ceremony expired"))
            }
            _ => None,
        })
    }

    pub(super) async fn run_prepared(
        &self,
        request: prepared::Request,
        context: PetalRouteContext,
    ) -> Result<SigningOutcome, SigningError> {
        request.validate()?;
        if context
            .trusted_account()
            .is_none_or(|a| a.wallet != request.wallet)
        {
            return Err(error(ErrorCode::Denied, "trusted wallet required"));
        }
        if request.action.payload.preimage.is_empty() {
            return Err(error(ErrorCode::Invalid, "empty preimage"));
        }
        validate_message_review(&request.action)?;
        let key = self
            .prepared_key(&context, &request.wallet, request.action.payload.suite)
            .await?;
        let root = self
            .petal_signing_state_root
            .as_ref()
            .ok_or_else(|| error(ErrorCode::Backend, "prepared signing state unavailable"))?
            .join(".prepared");
        let lock_root = root.clone();
        let _lock = tokio::task::spawn_blocking(move || lock(&lock_root))
            .await
            .map_err(|e| error(ErrorCode::Backend, e))??;
        let state_path = path(
            &root,
            &context,
            &request.wallet,
            &key,
            &request.operation_key,
        )?;
        let mut state = match std::fs::read(&state_path) {
            Ok(bytes) => serde_json::from_slice::<Record>(&bytes)
                .map_err(|e| error(ErrorCode::Backend, e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Record {
                version: 1,
                package_hash: context.package_hash.clone(),
                route: context.route_id.clone(),
                wallet: request.wallet.clone(),
                key: key.clone(),
                operation_key: request.operation_key.clone(),
                action: request.action.clone(),
                outcome: None,
            },
            Err(e) => return Err(error(ErrorCode::Backend, e)),
        };
        if state.version != 1
            || state.package_hash != context.package_hash
            || state.route != context.route_id
            || state.wallet != request.wallet
            || state.key != key
            || state.operation_key != request.operation_key
        {
            return Err(error(
                ErrorCode::Conflict,
                "operation key is bound to different action",
            ));
        }
        state.action.validate()?;
        if state.action != request.action {
            return Err(error(
                ErrorCode::Conflict,
                "operation key is bound to different action",
            ));
        }
        if let Some(SigningOutcome::Signed { signature }) = &state.outcome {
            self.prepared_verify(&key, &state.action, signature).await?;
            return Ok(state.outcome.unwrap());
        }
        if let Some(terminal) = self
            .prepared_ceremony_terminal(&root, &state.outcome)
            .await?
        {
            return Err(terminal);
        }
        write_record(&state_path, &state)?;
        let action = &request.action;
        let algorithm = match action.payload.suite {
            prepared::CryptoSuite::Keccak256 => "secp256k1-keccak256-recoverable",
            prepared::CryptoSuite::Sha256 => "secp256k1-sha256-recoverable",
            prepared::CryptoSuite::Ed25519Message => "ed25519-message",
        };
        let mut context = context;
        context.params.push((
            "bloom.internal.prepared-operation".into(),
            request.operation_key.clone(),
        ));
        context
            .params
            .push(("bloom.internal.prepared-persona".into(), "true".into()));
        context.params.push((
            "bloom.internal.prepared-key".into(),
            serde_json::to_string(&key).map_err(|e| error(ErrorCode::Backend, e))?,
        ));
        {
            let single = bloom_petals::PayloadSignRequest {
                wallet: request.wallet,
                preimage: action.payload.preimage.clone(),
                claimed_hash: action.payload.hash,
                signature_algorithm: algorithm.into(),
                operation_class: action.operation_class.clone(),
                petal_use_claim_jcs: claim(&context, action)?,
                claim_assurance_evidence: None,
                approval_hint: None,
                action: Some(action.review.bytes.clone()),
                advisory: None,
                selector: bloom_broker_api::PetalSignSelector::Exact,
                key_ref: None,
                context: Some(context),
            };
            let result = match self.sign_payload_outcome(single).await {
                Ok(result) => result,
                Err(err) => return prepared_signing_failure(err),
            };
            let outcome = match result {
                SignOutcome::Signature(signature) => {
                    self.prepared_verify(&key, action, &signature).await?;
                    SigningOutcome::Signed { signature }
                }
                SignOutcome::ApprovalPending(pending) => SigningOutcome::ApprovalPending {
                    action_id: pending.action_id,
                    expires_ms: pending.expires_ms,
                },
                SignOutcome::ApprovalRequired(_) => {
                    return Err(error(
                        ErrorCode::Backend,
                        "unexpected legacy approval response",
                    ));
                }
            };
            state.outcome = Some(outcome.clone());
            write_record(&state_path, &state)?;
            Ok(outcome)
        }
    }

    pub(super) async fn status_prepared(
        &self,
        request: prepared::StatusRequest,
        context: PetalRouteContext,
    ) -> Result<SigningOutcome, SigningError> {
        request.validate()?;
        if context
            .trusted_account()
            .is_none_or(|a| a.wallet != request.wallet)
        {
            return Err(error(ErrorCode::Denied, "trusted wallet required"));
        }
        let root = self
            .petal_signing_state_root
            .as_ref()
            .ok_or_else(|| error(ErrorCode::Backend, "prepared signing state unavailable"))?
            .join(".prepared");
        let lock_root = root.clone();
        let _lock = tokio::task::spawn_blocking(move || lock(&lock_root))
            .await
            .map_err(|e| error(ErrorCode::Backend, e))??;
        let mut found = None;
        for (index, entry) in std::fs::read_dir(&root)
            .map_err(|e| error(ErrorCode::Backend, e))?
            .take(4097)
            .enumerate()
        {
            if index == 4096 {
                return Err(error(
                    ErrorCode::Backend,
                    "too many prepared signing records",
                ));
            }
            let path = entry.map_err(|e| error(ErrorCode::Backend, e))?.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let state: Record = serde_json::from_slice(
                &std::fs::read(path).map_err(|e| error(ErrorCode::Backend, e))?,
            )
            .map_err(|e| error(ErrorCode::Backend, e))?;
            if state.package_hash != context.package_hash
                || state.wallet != request.wallet
                || state.operation_key != request.operation_key
            {
                continue;
            }
            if self
                .prepared_key(&context, &request.wallet, state.action.payload.suite)
                .await?
                != state.key
            {
                continue;
            }
            if found.is_some() {
                return Err(error(ErrorCode::Conflict, "ambiguous operation key"));
            }
            found = Some(state);
        }
        let state = found.ok_or_else(|| error(ErrorCode::Invalid, "operation not found"))?;
        state.action.validate()?;
        if let Some(terminal) = self
            .prepared_ceremony_terminal(&root, &state.outcome)
            .await?
        {
            return Err(terminal);
        }
        match state.outcome {
            Some(SigningOutcome::Signed { signature }) => {
                self.prepared_verify(&state.key, &state.action, &signature)
                    .await?;
                Ok(SigningOutcome::Signed { signature })
            }
            Some(SigningOutcome::ApprovalPending {
                action_id,
                expires_ms,
            }) => {
                if !bloom_petals::store::is_valid_hex_hash(&action_id) {
                    return Ok(SigningOutcome::RecoveryRequired {
                        status: "authorization_status_unavailable".into(),
                    });
                }
                let projection_path = root
                    .parent()
                    .ok_or_else(|| error(ErrorCode::Backend, "invalid state root"))?
                    .join(format!("{action_id}.json"));
                let projection = match std::fs::read(projection_path) {
                    Ok(bytes) => serde_json::from_slice::<PetalSigningRequestProjection>(&bytes)
                        .map_err(|e| error(ErrorCode::Backend, e))?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let operation = bloom_broker_api::OperationId::new(action_id.clone())
                            .map_err(|e| error(ErrorCode::Backend, e))?;
                        let status = self
                            .broker
                            .as_ref()
                            .ok_or_else(|| error(ErrorCode::Backend, "Broker unavailable"))?
                            .operation_status(operation)
                            .await
                            .map_err(|e| error(ErrorCode::Backend, e))?;
                        use bloom_broker_api::OperationState as O;
                        return match status.state {
                            O::Received
                            | O::Validated
                            | O::Reserved
                            | O::Dispatched
                            | O::DownstreamAccepted
                            | O::Committed => Ok(SigningOutcome::ApprovalPending {
                                action_id,
                                expires_ms,
                            }),
                            O::Succeeded => Ok(SigningOutcome::RecoveryRequired {
                                status: "eligibility_approved_retry".into(),
                            }),
                            O::Cancelled => {
                                Err(error(ErrorCode::Cancelled, "eligibility cancelled"))
                            }
                            O::Denied | O::Failed => {
                                Err(error(ErrorCode::Denied, "eligibility denied"))
                            }
                            O::Quarantined => Ok(SigningOutcome::RecoveryRequired {
                                status: "eligibility_requires_reconciliation".into(),
                            }),
                        };
                    }
                    Err(e) => return Err(error(ErrorCode::Backend, e)),
                };
                if projection.wallet != request.wallet
                    || projection.package_hash != context.package_hash
                    || projection.route_id != state.route
                {
                    return Err(error(
                        ErrorCode::Conflict,
                        "status projection differs from operation",
                    ));
                }
                let Some(id) = projection.approval_id else {
                    return Ok(SigningOutcome::RecoveryRequired {
                        status: "authorization_status_unavailable".into(),
                    });
                };
                let approval = self
                    .broker
                    .as_ref()
                    .ok_or_else(|| error(ErrorCode::Backend, "Broker unavailable"))?
                    .approval_status(
                        bloom_broker_api::Digest32::new(id)
                            .map_err(|e| error(ErrorCode::Backend, e))?,
                    )
                    .await
                    .map_err(|e| error(ErrorCode::Backend, e))?;
                use bloom_broker_api::ApprovalLifecycleState as S;
                match approval.state {
                    S::Prepared | S::AwaitingCeremony => Ok(SigningOutcome::ApprovalPending {
                        action_id,
                        expires_ms,
                    }),
                    S::Active => Ok(SigningOutcome::RecoveryRequired {
                        status: "approved_retry".into(),
                    }),
                    S::Expired => Err(error(ErrorCode::Expired, "approval expired")),
                    S::Cancelled | S::Revoked => {
                        Err(error(ErrorCode::Cancelled, "approval cancelled or revoked"))
                    }
                    S::Orphaned | S::Exhausted | S::Failed => {
                        Ok(SigningOutcome::RecoveryRequired {
                            status: "authorization_requires_reconciliation".into(),
                        })
                    }
                }
            }
            Some(outcome) => Ok(outcome),
            None => Ok(SigningOutcome::RecoveryRequired {
                status: "operation_in_progress".into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_signing_outcomes_require_recovery_while_refusals_remain_errors() {
        // Both prepared signing transports receive the same sanitized host
        // error from exact signing; it must not look safe to rebuild or retry.
        let unknown = super::super::exact_signing_host_error(
            bloom_vfs::ExactSigningError::OutcomeUnknown("lost response".into()),
        );
        assert!(matches!(
            prepared_signing_failure(unknown),
            Ok(SigningOutcome::RecoveryRequired { .. })
        ));
        let refused = super::super::exact_signing_host_error(
            bloom_vfs::ExactSigningError::Refused("policy denied".into()),
        );
        assert_eq!(
            prepared_signing_failure(refused).unwrap_err().code,
            ErrorCode::Denied
        );
        assert_eq!(
            prepared_signing_failure(HostError::Backend("Broker unavailable".into()))
                .unwrap_err()
                .code,
            ErrorCode::Backend,
        );
    }

    fn context() -> PetalRouteContext {
        PetalRouteContext {
            petal_root: "example".into(),
            package_hash: "11".repeat(32),
            route_id: "r1".into(),
            op: "write".into(),
            path: "/example".into(),
            params: vec![],
            actor: None,
        }
    }
    fn action(spend: prepared::Spend) -> prepared::PreparedAction {
        prepared::PreparedAction::new(
            "example.order",
            prepared::SigningPayload::keccak256(vec![1, 2, 3]).unwrap(),
            prepared::ReviewArtifact::new("bloom.message.review", 1, b"{}".to_vec()).unwrap(),
        )
        .unwrap()
        .with_spend(spend)
    }
    #[test]
    fn debit_claim_binds_exact_chain_asset_and_payload() {
        let spend = prepared::Spend::erc20(
            "evm-137",
            "0x1111111111111111111111111111111111111111",
            "123",
        )
        .unwrap();
        let action = action(spend);
        let bytes = claim(&context(), &action).unwrap();
        let claim: bloom_broker_api::PetalUseClaim = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(claim.route, "r1");
        assert_eq!(
            claim.ordered_hashes[0].as_str(),
            hex::encode(action.payload.hash)
        );
        assert_eq!(claim.declared_debits[0].amount.as_str(), "123");
        assert!(claim.economic_effects.is_some());
        assert_eq!(bytes, serde_jcs::to_vec(&claim).unwrap());
    }
    #[test]
    fn unspecified_remains_exact_and_zero_or_empty_bounded_is_malformed() {
        let claim: bloom_broker_api::PetalUseClaim = serde_json::from_slice(
            &claim(&context(), &action(prepared::Spend::Unspecified)).unwrap(),
        )
        .unwrap();
        assert!(claim.economic_effects.is_none());
        assert!(
            prepared::Spend::erc20("evm-137", "0x1111111111111111111111111111111111111111", "0")
                .is_err()
        );
        assert!(
            prepared::Spend::Bounded { debits: vec![] }
                .validate()
                .is_err()
        );
    }
    #[test]
    fn explicit_none_is_distinct_from_unspecified_and_binds_a_payload_context() {
        let declaration: bloom_broker_api::PetalUseClaim =
            serde_json::from_slice(&claim(&context(), &action(prepared::Spend::None)).unwrap())
                .unwrap();
        assert!(declaration.declared_debits.is_empty());
        let effects = declaration.economic_effects.unwrap();
        assert_eq!(effects.spend, bloom_broker_api::DeclaredSpendKind::None);
        assert_eq!(effects.payload_contexts[0].network.as_str(), "message");
    }

    #[test]
    fn generic_review_binds_the_exact_payload_independently_of_class_and_debit() {
        let text = "An ordinary login";
        let mut preimage = format!("\x19Ethereum Signed Message:\n{}", text.len()).into_bytes();
        preimage.extend_from_slice(text.as_bytes());
        let mut action=prepared::PreparedAction::new("unrelated.login",prepared::SigningPayload::keccak256(preimage).unwrap(),prepared::ReviewArtifact::new("bloom.message.review",1,serde_json::to_vec(&serde_json::json!({"schema":"bloom.message.review.v1","kind":"personal","message":text})).unwrap()).unwrap()).unwrap().with_spend(prepared::Spend::None);
        validate_message_review(&action).unwrap();
        action.review.bytes=serde_json::to_vec(&serde_json::json!({"schema":"bloom.message.review.v1","kind":"personal","message":"different"})).unwrap();
        assert_eq!(
            validate_message_review(&action).unwrap_err().code,
            ErrorCode::Invalid
        );
        action.review.format = "unsupported.review".into();
        assert_eq!(
            validate_message_review(&action).unwrap_err().code,
            ErrorCode::Unsupported
        );
    }

    #[test]
    fn duplicate_debit_assets_fail_closed() {
        let prepared::Spend::Bounded { debits } =
            prepared::Spend::erc20("evm-137", "0x1111111111111111111111111111111111111111", "1")
                .unwrap()
        else {
            unreachable!()
        };
        let duplicated = prepared::Spend::Bounded {
            debits: vec![debits[0].clone(), debits[0].clone()],
        };
        assert_eq!(
            claim(&context(), &action(duplicated)).unwrap_err().code,
            ErrorCode::Invalid
        );
    }
}
