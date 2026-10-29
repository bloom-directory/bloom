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
            let effects = (debits.iter().all(|d| d.amount != "0") && debits.iter().all(|d| d.network == debits[0].network)).then(|| serde_json::json!({"schema_version":1,"permission_effect":"none","payload_contexts":[{"payload_index":0,"network":debits[0].network,"spending_accounts":[]}]}));
            (entries, effects)
        }
        _ => (Vec::new(), None),
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClobReview {
    operation: String,
    intent: String,
    owner: String,
    signing_hash: String,
    signing_preimage_hex: String,
    preimage: ClobFields,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClobFields {
    timestamp: u64,
    nonce: u64,
    chain_id: u64,
    review_intent_hash: String,
}

fn clob_validate(
    action: &prepared::PreparedAction,
    owner: alloy::primitives::Address,
) -> Result<(), SigningError> {
    use alloy::primitives::{U256, keccak256};
    if action.operation_class != bloom_broker_api::POLYMARKET_CLOB_AUTH_CLASS
        || action.payload.suite != prepared::CryptoSuite::Keccak256
        || action.review.format != "polymarket.prepared-record"
        || action.review.version != 1
        || !matches!(
            action.spend,
            prepared::Spend::Unspecified | prepared::Spend::None
        )
    {
        return Err(error(ErrorCode::Invalid, "invalid ClobAuth profile"));
    }
    let records: Vec<ClobReview> =
        serde_json::from_slice(&action.review.bytes).map_err(|e| error(ErrorCode::Invalid, e))?;
    let [record] = records.as_slice() else {
        return Err(error(
            ErrorCode::Invalid,
            "ClobAuth requires one review record",
        ));
    };
    let parsed_owner: alloy::primitives::Address = record
        .owner
        .parse()
        .map_err(|e| error(ErrorCode::Invalid, e))?;
    if record.operation != "clob_auth"
        || record.intent != action.operation_class
        || parsed_owner != owner
        || record.preimage.chain_id != 137
        || record.preimage.nonce != 0
        || record.signing_hash != format!("0x{}", hex::encode(action.payload.hash))
        || record.signing_preimage_hex != hex::encode(&action.payload.preimage)
    {
        return Err(error(
            ErrorCode::Invalid,
            "ClobAuth review differs from selected owner or payload",
        ));
    }
    let mut domain = Vec::new();
    domain.extend_from_slice(
        keccak256("EIP712Domain(string name,string version,uint256 chainId)").as_slice(),
    );
    domain.extend_from_slice(keccak256("ClobAuthDomain").as_slice());
    domain.extend_from_slice(keccak256("1").as_slice());
    domain.extend_from_slice(&U256::from(137).to_be_bytes::<32>());
    let mut message = Vec::new();
    message.extend_from_slice(
        keccak256("ClobAuth(address address,string timestamp,uint256 nonce,string message)")
            .as_slice(),
    );
    message.extend_from_slice(&[0; 12]);
    message.extend_from_slice(owner.as_slice());
    message.extend_from_slice(keccak256(record.preimage.timestamp.to_string()).as_slice());
    message.extend_from_slice(&[0; 32]);
    message.extend_from_slice(
        keccak256("This message attests that I control the given wallet").as_slice(),
    );
    let mut expected = vec![0x19, 0x01];
    expected.extend_from_slice(keccak256(domain).as_slice());
    expected.extend_from_slice(keccak256(message).as_slice());
    if action.payload.preimage != expected {
        return Err(error(
            ErrorCode::Invalid,
            "ClobAuth payload does not match its owner and timestamp",
        ));
    }
    let intent = serde_json::json!({"operation":"clob_auth","owner":record.owner,"chain_id":137,"timestamp":record.preimage.timestamp,"nonce":0,"message":"This message attests that I control the given wallet","signing_hash":record.signing_hash});
    // The guest serializes a sorted JSON map; Machine's serde_json build may
    // enable preserve_order through other crates, so canonicalize explicitly.
    let encoded = serde_jcs::to_vec(&intent).map_err(|e| error(ErrorCode::Invalid, e))?;
    if record.preimage.review_intent_hash != blake3::hash(&encoded).to_hex().to_string() {
        return Err(error(ErrorCode::Invalid, "ClobAuth review intent differs"));
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

    async fn prepared_evm_owner(
        &self,
        key: &bloom_broker_api::KeyRef,
    ) -> Result<alloy::primitives::Address, SigningError> {
        use k256::pkcs8::DecodePublicKey as _;
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
        if public.key_ref != *key {
            return Err(error(ErrorCode::Denied, "selected public key differs"));
        }
        let public_bytes = public.canonical_public_key.decode();
        if hex::encode(Sha256::digest(&public_bytes)) != key.public_key_fingerprint.as_str() {
            return Err(error(ErrorCode::Backend, "public key fingerprint differs"));
        }
        let key = k256::PublicKey::from_public_key_der(&public_bytes)
            .map_err(|e| error(ErrorCode::Backend, e))?;
        let verifying_key = k256::ecdsa::VerifyingKey::from(key);
        Ok(alloy::primitives::Address::from_public_key(&verifying_key))
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
        if !matches!(
            request.action.review.format.as_str(),
            "polymarket.prepared-record" | "bloom.message.review"
        ) || request.action.review.version != 1
        {
            return Err(error(
                ErrorCode::Unsupported,
                "review format is not supported",
            ));
        }
        if request.action.review.format == "bloom.message.review"
            && serde_json::from_slice::<serde_json::Value>(&request.action.review.bytes)
                .ok()
                .is_none_or(|value| value["schema"] != "bloom.message.review.v1")
        {
            return Err(error(ErrorCode::Invalid, "invalid message review envelope"));
        }
        if request.action.review.format == "polymarket.prepared-record"
            && !bloom_broker_api::POLYMARKET_REVIEW_OPERATION_CLASSES
                .contains(&request.action.operation_class.as_str())
            && request.action.operation_class != bloom_broker_api::POLYMARKET_CLOB_AUTH_CLASS
        {
            return Err(error(
                ErrorCode::Unsupported,
                "review format does not match operation class",
            ));
        }
        let is_clob =
            request.action.operation_class == bloom_broker_api::POLYMARKET_CLOB_AUTH_CLASS;
        let key = self
            .prepared_key(&context, &request.wallet, request.action.payload.suite)
            .await?;
        let clob_owner = if is_clob {
            let owner = self.prepared_evm_owner(&key).await?;
            clob_validate(&request.action, owner)?;
            Some(owner)
        } else {
            None
        };
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
            if let Some(owner) = clob_owner {
                clob_validate(&state.action, owner)?;
                if matches!(state.outcome, Some(SigningOutcome::Signed { .. })) {
                    return Ok(SigningOutcome::RecoveryRequired {
                        status: "signed_payload_differs".into(),
                    });
                }
                state.action = request.action.clone();
            } else {
                return Err(error(
                    ErrorCode::Conflict,
                    "operation key is bound to different action",
                ));
            }
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
        let allow_persona = matches!(&action.spend, prepared::Spend::Bounded { debits } if debits.iter().all(|d| d.amount != "0") && debits.iter().all(|d| d.network == debits[0].network));
        context.params.push((
            "bloom.internal.prepared-persona".into(),
            allow_persona.to_string(),
        ));
        context.params.push((
            "bloom.internal.prepared-key".into(),
            serde_json::to_string(&key).map_err(|e| error(ErrorCode::Backend, e))?,
        ));
        if action.review.format == "bloom.message.review" {
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
                Err(HostError::Denied(message)) if message.contains("APPROVAL_EXPIRED") => {
                    return Err(error(ErrorCode::Expired, message));
                }
                Err(HostError::Denied(message))
                    if message.contains("APPROVAL_REVOKED") || message.contains("CANCELLED") =>
                {
                    return Err(error(ErrorCode::Cancelled, message));
                }
                Err(HostError::Denied(message))
                    if message.contains("OPERATION_ID_CONFLICT")
                        || message.contains("RECOVERY_REQUIRED") =>
                {
                    return Ok(SigningOutcome::RecoveryRequired {
                        status: "signing_outcome_ambiguous".into(),
                    });
                }
                Err(err) => return Err(host_error(err)),
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
            return Ok(outcome);
        }
        let old_request = PayloadBatchSignRequest {
            wallet: request.wallet,
            payloads: vec![bloom_petals::PayloadSignItem {
                preimage: action.payload.preimage.clone(),
                claimed_hash: action.payload.hash,
            }],
            signature_algorithm: algorithm.into(),
            operation_class: action.operation_class.clone(),
            petal_use_claim_jcs: claim(&context, action)?,
            claim_assurance_evidence: None,
            approval_hint: None,
            action: Some(action.review.bytes.clone()),
            advisory: None,
            selector: if is_clob {
                bloom_broker_api::PetalSignSelector::Reusable
            } else {
                bloom_broker_api::PetalSignSelector::Exact
            },
            key_ref: None,
            context: Some(context),
        };
        let result = match self.sign_payload_batch_outcome(old_request).await {
            Ok(result) => result,
            Err(HostError::Denied(message)) if message.contains("APPROVAL_EXPIRED") => {
                return Err(error(ErrorCode::Expired, message));
            }
            Err(HostError::Denied(message))
                if message.contains("APPROVAL_REVOKED") || message.contains("CANCELLED") =>
            {
                return Err(error(ErrorCode::Cancelled, message));
            }
            Err(HostError::Denied(message))
                if message.contains("OperationIdConflict")
                    || message.contains("OPERATION_ID_CONFLICT")
                    || message.contains("RECOVERY_REQUIRED") =>
            {
                return Ok(SigningOutcome::RecoveryRequired {
                    status: "signing_outcome_ambiguous".into(),
                });
            }
            Err(error) => return Err(host_error(error)),
        };
        let outcome = match result {
            PayloadBatchSignOutcome::ApprovalPending(pending) => SigningOutcome::ApprovalPending {
                action_id: pending.action_id,
                expires_ms: pending.expires_ms,
            },
            PayloadBatchSignOutcome::Signatures(signatures) => {
                let [signature] = signatures.as_slice() else {
                    return Err(error(ErrorCode::Backend, "invalid signature count"));
                };
                self.prepared_verify(&key, action, signature).await?;
                SigningOutcome::Signed {
                    signature: signature.clone(),
                }
            }
        };
        state.outcome = Some(outcome.clone());
        write_record(&state_path, &state)?;
        Ok(outcome)
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
    fn zero_and_unspecified_declarations_cannot_create_reusable_effects() {
        for spend in [
            prepared::Spend::Unspecified,
            prepared::Spend::None,
            prepared::Spend::erc20("evm-137", "0x1111111111111111111111111111111111111111", "0")
                .unwrap(),
        ] {
            let claim: bloom_broker_api::PetalUseClaim =
                serde_json::from_slice(&claim(&context(), &action(spend)).unwrap()).unwrap();
            assert!(claim.economic_effects.is_none());
        }
    }
    #[test]
    fn clob_profile_accepts_only_authoritative_owner_and_exact_payload() {
        let owner: alloy::primitives::Address = "0x0000000000000000000000000000000000000007"
            .parse()
            .unwrap();
        let preimage = hex::decode("1901cfc66be2a3b30464cb3b588324101f660c9a205fa76e8e5f83ee16a528e1c4cb50968619823f5177bd507b288d899a2d0d517f0dd56d62217210884afcd70217").unwrap();
        let hash = "0x46cf12b7c0c5f516befb1439a288dc3f247bc23b80e48ca26e3fdebd5ad00f95";
        let owner_text = format!("{owner:#x}");
        let intent = serde_json::json!({"operation":"clob_auth", "owner":owner_text, "chain_id":137, "timestamp":1800000000u64, "nonce":0, "message":"This message attests that I control the given wallet", "signing_hash":hash});
        let intent_hash = blake3::hash(&serde_jcs::to_vec(&intent).unwrap())
            .to_hex()
            .to_string();
        let record = serde_json::json!([{"operation":"clob_auth", "intent":bloom_broker_api::POLYMARKET_CLOB_AUTH_CLASS, "owner":owner_text, "signing_hash":hash, "signing_preimage_hex":hex::encode(&preimage), "preimage":{"timestamp":1800000000u64,"nonce":0,"chain_id":137,"review_intent_hash":intent_hash}}]);
        let action = prepared::PreparedAction::new(
            bloom_broker_api::POLYMARKET_CLOB_AUTH_CLASS,
            prepared::SigningPayload::keccak256(preimage).unwrap(),
            prepared::ReviewArtifact::new(
                "polymarket.prepared-record",
                1,
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(clob_validate(&action, owner).is_ok());
        assert!(clob_validate(&action, alloy::primitives::Address::with_last_byte(8)).is_err());
        let mut changed = action;
        changed.payload.preimage[40] ^= 1;
        assert!(clob_validate(&changed, owner).is_err());
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
