//! Real-authority native transfer coverage using a grant created by onboarding.
use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    primitives::{Address, TxKind, U256, keccak256},
};
use bloom_broker_api::*;
use bloom_machine_client::{
    ExactPayloadSignOutcome, ExactPayloadSignRequest, MachineBrokerClient, PersonaSessionStatus,
};

pub(super) async fn assert_compiler_native_transfer(
    client: &MachineBrokerClient,
    wallet: &Token,
    key: &KeyRef,
    grant: &PersonaSessionStatus,
) -> serde_json::Value {
    let ApprovalSelector::NativeSession { scope } = &grant.terms.selector else {
        panic!("acceptance requires a compiler-created native grant");
    };
    assert_eq!(grant.persona, "degen");
    assert_eq!(&grant.terms.key_ref, key);
    assert!(scope.any_erc20_recipient);
    let asset = scope
        .tokens
        .iter()
        .find(|asset| asset.chain.as_str() == "evm-137")
        .expect("Degen compiler must include Polygon tokens")
        .clone();
    let contract: Address = asset.asset.parse().unwrap();
    let recipient = Address::repeat_byte(0x72);
    let before = client
        .approval_limit_state(grant.approval_id.clone())
        .await
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let public = client
        .key(KeyRequest {
            key_ref: key.clone(),
        })
        .await
        .unwrap();
    assert_eq!(&public.key_ref, key);
    let der = public.canonical_public_key.decode();
    use sha2::Digest as _;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(&der)),
        key.public_key_fingerprint.as_str()
    );
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;
    use k256::pkcs8::DecodePublicKey as _;
    let expected = k256::PublicKey::from_public_key_der(&der).unwrap();
    let mut results = Vec::new();
    for index in 0..2u8 {
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(recipient.as_slice());
        data.extend_from_slice(&U256::from(1).to_be_bytes::<32>());
        let tx = TxEip1559 {
            chain_id: 137,
            nonce: u64::from(index),
            gas_limit: 50_000,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(contract),
            input: data.into(),
            ..Default::default()
        };
        let preimage = tx.encoded_for_signing();
        let request = ExactPayloadSignRequest {
            session_use: Some(SystemSessionUse {
                action: SystemSessionAction::Erc20Transfer,
                chain: SystemSessionChain::Evm {
                    chain: asset.chain.clone(),
                    chain_id: DecimalU64::new(137),
                },
                token: Some(asset.clone()),
                recipient: format!("{recipient:#x}"),
                amount: DecimalU256::parse("1").unwrap(),
                maximum_fee: DecimalU256::parse("100000").unwrap(),
            }),
            wallet_id: wallet.clone(),
            claimed_hash: Digest32::from_bytes(keccak256(&preimage).into()),
            preimage,
            crypto_suite: CryptoSuite::Secp256k1Keccak256Recoverable,
            provenance: ProvenanceSubject::System {
                component_id: scope.component_id.clone(),
                operation_class: Token::new("transaction.confirm").unwrap(),
            },
            provenance_digest: grant.terms.provenance_digest.clone(),
            activation_mode: None,
            approval_operation_id: OperationId::from_bytes([160 + index; 32]),
            signing_operation_id: OperationId::from_bytes([170 + index; 32]),
            request_nonce: RequestNonce::from_bytes([180 + index; 16]),
            issued_at_ms: DecimalU64::new(now),
            expires_at_ms: DecimalU64::new(now + 300_000),
            canonical_plan_facts_digest: Digest32::from_bytes([190 + index; 32]),
            approval_id: None,
            petal_use_claim: None,
            system_use_claim: None,
            claim_assurance_evidence: None,
            safe_review_payload: None,
            message_review_payload: None,
            evm_reported_token: None,
            approval_value_limits: vec![],
            account_key_ref: Some(key.clone()),
            expected_key_ref: Some(key.clone()),
            allow_persona: true,
        };
        let outcome = client
            .sign_exact_payload_recovering(request.clone())
            .await
            .unwrap();
        let ExactPayloadSignOutcome::Signed(result) = &outcome else {
            panic!("covered ERC20 transfer unexpectedly requested a ceremony: {outcome:?}");
        };
        assert_eq!(result.signatures.len(), 1);
        assert_eq!(result.signatures[0].bytes.decode().len(), 65);
        let signature =
            alloy::primitives::Signature::from_raw(&result.signatures[0].bytes.decode()).unwrap();
        let recovered = signature
            .recover_from_prehash(&alloy::primitives::B256::from(
                request.claimed_hash.to_bytes(),
            ))
            .unwrap();
        assert_eq!(
            recovered.to_encoded_point(true).as_bytes(),
            expected.to_encoded_point(true).as_bytes()
        );

        assert_eq!(
            client.sign_exact_payload_recovering(request).await.unwrap(),
            outcome
        );
        results.push(result.clone());
    }
    assert_ne!(results[0].signatures, results[1].signatures);
    let after = client
        .approval_limit_state(grant.approval_id.clone())
        .await
        .unwrap();
    assert_eq!(
        after.committed_operations.get(),
        before.committed_operations.get() + 2
    );
    assert_eq!(
        after.committed_signatures.get(),
        before.committed_signatures.get() + 2
    );
    assert_eq!(after.reserved_operations.get(), 0);
    assert_eq!(after.quarantined_operations.get(), 0);
    let used = |state: &ApprovalLimitState, asset: &AssetId| -> U256 {
        state
            .session_budget_state
            .as_ref()
            .unwrap()
            .asset_usage
            .iter()
            .find(|entry| &entry.asset == asset)
            .map(|entry| entry.amount.as_str().parse().unwrap())
            .unwrap_or(U256::ZERO)
    };
    assert_eq!(used(&after, &asset) - used(&before, &asset), U256::from(2));
    let native = AssetId {
        chain: asset.chain.clone(),
        asset: "native".into(),
    };
    assert_eq!(
        used(&after, &native) - used(&before, &native),
        U256::from(200_000)
    );
    serde_json::json!({
        "approval_id": grant.approval_id,
        "token": asset,
        "new_signatures": 2,
        "extra_ceremonies": 0,
        "token_charge_raw": "2",
        "maximum_fee_charge_raw": "200000",
        "retries_double_charged": false
    })
}
