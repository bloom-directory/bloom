//! Claims for the fixed host outbox workflow, derived from final signing inputs.
use super::*;
use bloom_broker_api::{
    AssetId, ClaimAssurance, DecimalU256, DeclaredDebit, DeclaredDestination, DeclaredFee,
    PetalUseClaim,
};

fn unsupported(message: impl Into<String>) -> TxEngineError {
    TxEngineError::ApprovalDenied(message.into())
}

pub(super) fn subject(staged: &StagedTx) -> Result<Option<ProvenanceSubject>, TxEngineError> {
    let Some(origin) = &staged.execution_origin else {
        return Ok(None);
    };
    if origin == &ExecutionOrigin::default() {
        return Ok(None);
    }
    let route = origin.route_id.as_ref().filter(|route| !route.is_empty()).ok_or_else(||
        unsupported("Petal transaction has no persisted producing route; restage it under the installed Petal"))?;
    let package_hash = Digest32::new(origin.petal_digest.clone()).map_err(|_| {
        unsupported(
            "Petal transaction has an invalid package hash; restage it under the installed Petal",
        )
    })?;
    Ok(Some(ProvenanceSubject::Petal {
        package_hash,
        route: route.clone(),
    }))
}

fn decimal(value: U256) -> Result<DecimalU256, TxEngineError> {
    DecimalU256::parse(value.to_string()).map_err(|error| protocol_signing_error(error.into()))
}

fn raw_amount(value: &str) -> Result<U256, TxEngineError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(unsupported(
            "outbox accounting requires an unsigned decimal base-unit amount",
        ));
    }
    value
        .parse()
        .map_err(|_| unsupported("outbox amount exceeds U256"))
}

fn local_anvil(spec: &ChainSpec) -> bool {
    let urls: Vec<_> = if spec.rpc_endpoints.is_empty() {
        spec.rpc_urls.iter().map(String::as_str).collect()
    } else {
        spec.rpc_endpoints
            .iter()
            .map(|endpoint| endpoint.url.as_str())
            .collect()
    };
    spec.name == "anvil"
        && !urls.is_empty()
        && urls.iter().all(|url| {
            let Some((scheme, rest)) = url.split_once("://") else {
                return false;
            };
            if !matches!(scheme, "http" | "https" | "ws" | "wss") {
                return false;
            }
            let authority = rest.split('/').next().unwrap_or_default();
            ["localhost", "127.0.0.1", "[::1]"].iter().any(|host| {
                authority == *host
                    || authority
                        .strip_prefix(host)
                        .and_then(|port| port.strip_prefix(':'))
                        .is_some_and(|port| {
                            !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
                        })
            })
        })
}

pub(super) fn build(
    staged: &StagedTx,
    spec: &ChainSpec,
    unsigned: &UnsignedEvmTx,
    action: EvmOutboxActionKind,
    preimage: &[u8],
    hash: B256,
) -> Result<Option<PetalUseClaim>, TxEngineError> {
    let Some(ProvenanceSubject::Petal {
        package_hash,
        route,
    }) = subject(staged)?
    else {
        return Ok(None);
    };
    if spec.op_stack
        || matches!(spec.chain_id, 10 | 8453 | 11155420 | 84532)
        || !matches!(spec.chain_id, 1 | 137) && !(spec.chain_id == 31337 && local_anvil(spec))
    {
        return Err(unsupported(
            "Petal outbox fee accounting supports Ethereum, Polygon PoS, and local Anvil only; this network has no supported total fee bound",
        ));
    }
    let (chain_id, nonce, gas, fee_cap, to, value, data) = match unsigned {
        UnsignedEvmTx::Legacy(tx) => (
            tx.chain_id,
            tx.nonce,
            tx.gas_limit,
            tx.gas_price,
            tx.to,
            tx.value,
            &tx.input,
        ),
        UnsignedEvmTx::Eip1559(tx) => {
            if tx.max_priority_fee_per_gas > tx.max_fee_per_gas {
                return Err(unsupported("priority fee exceeds final maximum fee"));
            }
            (
                Some(tx.chain_id),
                tx.nonce,
                tx.gas_limit,
                tx.max_fee_per_gas,
                tx.to,
                tx.value,
                &tx.input,
            )
        }
    };
    if chain_id != Some(spec.chain_id)
        || staged.chain != spec.name
        || staged.chain_id != spec.chain_id
        || nonce != staged.nonce
        || TxEngine::unsigned_signing_preimage(unsigned) != preimage
        || TxEngine::unsigned_signing_hash(unsigned) != hash
    {
        return Err(unsupported(
            "outbox chain, nonce, or final signing payload is inconsistent",
        ));
    }
    let TxKind::Call(to) = to else {
        return Err(unsupported(
            "Petal outbox contract creation accounting is unsupported",
        ));
    };
    if raw_amount(&staged.value_wei)? != value {
        return Err(unsupported(
            "staged native amount differs from final transaction",
        ));
    }
    for field in [
        &staged.gas_price,
        &staged.max_fee_per_gas,
        &staged.max_priority_fee_per_gas,
    ]
    .into_iter()
    .flatten()
    {
        if field.is_empty()
            || !field.bytes().all(|byte| byte.is_ascii_digit())
            || field.parse::<u128>().is_err()
        {
            return Err(unsupported(
                "staged fee is not a valid unsigned decimal amount",
            ));
        }
    }
    if staged.action_kind == TxActionKind::NativeTransfer && !data.is_empty() {
        return Err(unsupported(
            "native transfer classification disagrees with final calldata",
        ));
    }
    let chain =
        Token::new(spec.name.clone()).map_err(|error| protocol_signing_error(error.into()))?;
    let fee = U256::from(gas)
        .checked_mul(U256::from(fee_cap))
        .ok_or_else(|| unsupported("outbox fee exceeds U256"))?;
    let mut debits = Vec::new();
    let mut destinations = vec![DeclaredDestination {
        chain: chain.clone(),
        destination: bloom_proto::checksum_address(&to),
    }];
    if value != U256::ZERO {
        debits.push(DeclaredDebit {
            asset: AssetId {
                chain: chain.clone(),
                asset: "native".into(),
            },
            amount: decimal(value)?,
        });
    }
    if action != EvmOutboxActionKind::Cancel
        && (staged.action_kind == TxActionKind::Erc20Transfer || staged.token.is_some())
    {
        let token = staged.token.as_ref().ok_or_else(|| {
            unsupported("typed token transfer is missing exact token facts; restage it")
        })?;
        if staged.action_kind != TxActionKind::Erc20Transfer {
            return Err(unsupported(
                "token metadata disagrees with the staged action",
            ));
        }
        let token_address: Address = token
            .address
            .parse()
            .map_err(|_| unsupported("invalid token address"))?;
        let recipient: Address = token
            .recipient
            .parse()
            .map_err(|_| unsupported("invalid token recipient"))?;
        let amount =
            raw_amount(token.amount_base_units.as_deref().ok_or_else(|| {
                unsupported("token transfer has no exact raw amount; restage it")
            })?)?;
        let transfer = IERC20::transferCall::abi_decode(data)
            .map_err(|_| unsupported("typed token transfer calldata is invalid"))?;
        if to != token_address
            || transfer.to != recipient
            || transfer.amount != amount
            || transfer.abi_encode().as_slice() != data.as_ref()
        {
            return Err(unsupported(
                "typed token transfer facts differ from the final calldata",
            ));
        }
        if amount != U256::ZERO {
            debits.push(DeclaredDebit {
                asset: AssetId {
                    chain: chain.clone(),
                    asset: bloom_proto::checksum_address(&token_address),
                },
                amount: decimal(amount)?,
            });
        }
        destinations.push(DeclaredDestination {
            chain: chain.clone(),
            destination: bloom_proto::checksum_address(&recipient),
        });
    }
    if action == EvmOutboxActionKind::Cancel && (value != U256::ZERO || !data.is_empty()) {
        return Err(unsupported(
            "cancellation must use its final zero-value empty-data payload",
        ));
    }
    if let Some(recipient) = decode_nft_recipient(data) {
        destinations.push(DeclaredDestination {
            chain: chain.clone(),
            destination: bloom_proto::checksum_address(&recipient),
        });
    }
    if let Ok(approval) = INftWrite721::setApprovalForAllCall::abi_decode(data) {
        destinations.push(DeclaredDestination {
            chain: chain.clone(),
            destination: bloom_proto::checksum_address(&approval.operator),
        });
    }
    if let Some(spender) = decode_approve_spender(data) {
        destinations.push(DeclaredDestination {
            chain: chain.clone(),
            destination: bloom_proto::checksum_address(&spender),
        });
    }
    Ok(Some(PetalUseClaim {
        package_hash,
        route,
        operation_class: Token::new(triad_operation_class(action))
            .map_err(|error| protocol_signing_error(error.into()))?,
        crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
        payload_digest: payload_digest(&[preimage.to_vec()]),
        ordered_hashes: vec![Digest32::from_bytes(hash.0)],
        declared_debits: debits,
        declared_destinations: destinations,
        declared_fee: DeclaredFee::Fee {
            chain,
            asset: "native".into(),
            amount: decimal(fee)?,
        },
        nonce: RequestNonce::from_bytes([0; 16]),
        claim_assurance: ClaimAssurance::MachineAsserted,
    }))
}

pub(super) fn payload_digest(preimages: &[Vec<u8>]) -> Digest32 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"bloom.petal.payload-batch.v1\0");
    hasher.update((preimages.len() as u64).to_be_bytes());
    for preimage in preimages {
        hasher.update((preimage.len() as u64).to_be_bytes());
        hasher.update(preimage);
    }
    Digest32::from_bytes(hasher.finalize().into())
}

pub(super) fn aggregate(
    claims: Vec<Option<PetalUseClaim>>,
    preimages: &[Vec<u8>],
) -> Result<Option<PetalUseClaim>, TxEngineError> {
    let mut iter = claims.into_iter();
    let first = iter
        .next()
        .ok_or_else(|| unsupported("empty outbox batch"))?;
    let Some(mut first) = first else {
        if iter.any(|claim| claim.is_some()) {
            return Err(unsupported(
                "cannot mix native and Petal origins in an outbox batch",
            ));
        }
        return Ok(None);
    };
    for claim in iter {
        let claim = claim
            .ok_or_else(|| unsupported("cannot mix native and Petal origins in an outbox batch"))?;
        if claim.package_hash != first.package_hash
            || claim.route != first.route
            || claim.operation_class != first.operation_class
        {
            return Err(unsupported(
                "outbox batch requires one exact producing Petal route",
            ));
        }
        match (&mut first.declared_fee, claim.declared_fee) {
            (
                DeclaredFee::Fee {
                    chain,
                    asset,
                    amount,
                },
                DeclaredFee::Fee {
                    chain: other_chain,
                    asset: other_asset,
                    amount: other_amount,
                },
            ) if *chain == other_chain && *asset == other_asset => {
                *amount = decimal(
                    raw_amount(amount.as_str())?
                        .checked_add(raw_amount(other_amount.as_str())?)
                        .ok_or_else(|| unsupported("batch fee exceeds U256"))?,
                )?;
            }
            _ => {
                return Err(unsupported(
                    "Petal outbox batch requires one fee chain and asset",
                ));
            }
        }
        first.declared_debits.extend(claim.declared_debits);
        first
            .declared_destinations
            .extend(claim.declared_destinations);
        first.ordered_hashes.extend(claim.ordered_hashes);
    }
    first.payload_digest = payload_digest(preimages);
    Ok(Some(first))
}

pub(super) fn with_nonce(
    claim: &Option<PetalUseClaim>,
    nonce: &RequestNonce,
) -> Option<PetalUseClaim> {
    claim.clone().map(|mut claim| {
        claim.nonce = nonce.clone();
        claim
    })
}

pub(super) fn digest(value: &impl serde::Serialize) -> Result<Digest32, TxEngineError> {
    Ok(Digest32::from_bytes(
        sha2::Sha256::digest(
            serde_jcs::to_vec(value)
                .map_err(|error| TxEngineError::ApprovalConstruction(error.to_string()))?,
        )
        .into(),
    ))
}

pub(super) async fn resolve(
    service: &TriadSigningService,
    staged: &StagedTx,
    class: &str,
) -> Result<bloom_broker_api::ResolvedProvenance, TxEngineError> {
    if let Some(subject) = subject(staged)? {
        let resolved = service
            .broker
            .resolve_provenance(&subject, &service.provenance_catalog)
            .await
            .map_err(|error| protocol_signing_error(error.into()))?;
        let route = resolved.owner_route().map_err(|_| unsupported("Petal outbox signing requires a committed owner registration for the producing route"))?;
        if !route
            .capabilities
            .iter()
            .any(|cap| cap == "bloom:tx.outbox")
            || !bloom_broker_api::PETAL_OUTBOX_OPERATION_CLASSES.contains(&class)
        {
            return Err(unsupported(
                "producing Petal route is not registered for this outbox operation",
            ));
        }
        return Ok(resolved);
    }
    service
        .provenance_catalog
        .records
        .iter()
        .find(|record| provenance_action_class(&record.subject) == Some(class))
        .cloned()
        .map(bloom_broker_api::ResolvedProvenance::Installer)
        .ok_or_else(|| unsupported(format!("installer provenance does not authorize {class}")))
}
