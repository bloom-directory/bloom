//! End-to-end signing test: a BIP-39 wallet's derived Solana child signs the
//! golden-shaped transfer through the real `SolanaTransferSigner` → Broker
//! seam, and the signature verifies over the raw message bytes.

use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalPrepareState, Base64UrlBytes, CryptoSuite, DecimalU64,
    Digest32, KeyPublic, KeyRef, KeyRequest, KeyRole, KeySpec, MachineBrokerRequest,
    MachineBrokerResponse, MachineBrokerService, MachineSignRequest, NormalizedSignature,
    ProtocolError, ProtocolErrorCode, ProvenanceCatalog, ProvenanceOperationClass,
    ProvenanceRecord, ProvenanceSubject, SealedApprovalPrepareResponse, ServiceFuture,
    SigningPayloads, SigningResult, Token, WalletPublic, WalletRequest,
};
use bloom_machine_client::MachineBrokerClient;
use bloom_solana_tx::message::{build_transfer_message, verify_signature};
use bloom_solana_tx::signing::{SolanaSignOutcome, SolanaTransferSigner};
use sha2::{Digest as _, Sha256};

/// A Broker fixture that signs with a real Ed25519 derived child.
struct SolanaBrokerFixture {
    child_signing_key: ed25519_dalek::SigningKey,
    child_key_ref: KeyRef,
    prepared_claim: std::sync::Mutex<Option<bloom_broker_api::SystemUseClaim>>,
}

fn token(s: &str) -> Token {
    Token::new(s).unwrap()
}

fn digest(byte: u8) -> Digest32 {
    Digest32::from_bytes([byte; 32])
}

impl SolanaBrokerFixture {
    fn new() -> Self {
        // The derived Solana child (BIP-44 m/44'/501'/0'/0'): a real Ed25519
        // key with a deterministic seed for the fixture.
        let seed: [u8; 32] = [0xaa; 32];
        let child_signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey = child_signing_key.verifying_key().to_bytes();
        let child_key_ref = KeyRef {
            backend: token("local"),
            backend_instance: token("primary"),
            locator: "wallet/derived/solana-0".into(),
            key_spec: KeySpec::Ed25519,
            public_key_fingerprint: Digest32::from_bytes(Sha256::digest(pubkey).into()),
            derivation: None,
        };
        Self {
            child_signing_key,
            child_key_ref,
            prepared_claim: std::sync::Mutex::new(None),
        }
    }

    fn child_pubkey(&self) -> [u8; 32] {
        self.child_signing_key.verifying_key().to_bytes()
    }

    fn wallet(&self) -> WalletPublic {
        WalletPublic {
            wallet_id: token("wallet"),
            wallet_kind: token("local"),
            root_key_ref: None, // BIP-39 seed wallet: no signable root
            key_refs: vec![self.child_key_ref.clone()],
            policy_version: DecimalU64::new(1),
            policy_digest: digest(1),
            wallet_revocation_epoch: DecimalU64::new(1),
        }
    }

    fn sign_payload(
        &self,
        request: &MachineSignRequest,
    ) -> Result<NormalizedSignature, ProtocolError> {
        let SigningPayloads::Single { payload } = &request.payloads else {
            return Err(ProtocolError::new(
                ProtocolErrorCode::MalformedFrame,
                "expected single payload",
            ));
        };
        let claim = request.system_use_claim.as_ref().ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorCode::ClaimInvalid,
                "native Solana signing omitted its system claim",
            )
        })?;
        let evidence = request.claim_assurance_evidence.as_ref().ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorCode::ClaimInvalid,
                "native Solana signing omitted semantic verifier evidence",
            )
        })?;
        if evidence.decode() != payload.decode()
            || claim.payload_digest != Digest32::from_bytes(Sha256::digest(payload.decode()).into())
            || claim.action_class.as_str() != "solana.transfer.confirm"
            || claim.operation_class.as_str() != "solana.native-transfer"
        {
            return Err(ProtocolError::new(
                ProtocolErrorCode::ClaimInvalid,
                "native Solana claim does not bind its exact evidence",
            ));
        }
        use ed25519_dalek::Signer as _;
        let signature = self.child_signing_key.sign(payload.decode().as_slice());
        Ok(NormalizedSignature {
            crypto_suite: CryptoSuite::Ed25519Message,
            bytes: Base64UrlBytes::from_bytes(&signature.to_bytes()),
        })
    }
}

impl MachineBrokerService for SolanaBrokerFixture {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move {
            match request {
                MachineBrokerRequest::WalletGetPublic(WalletRequest { wallet_id }) => {
                    let mut wallet = self.wallet();
                    wallet.wallet_id = wallet_id;
                    Ok(MachineBrokerResponse::WalletGetPublic(wallet))
                }
                MachineBrokerRequest::KeyGetPublic(KeyRequest { key_ref }) => {
                    let mut returned = key_ref;
                    let role = if returned.locator.contains("derived") {
                        KeyRole::Derived
                    } else {
                        KeyRole::WalletRoot
                    };
                    returned.key_spec = KeySpec::Ed25519;
                    Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                        role,
                        key_ref: returned,
                        canonical_public_key: Base64UrlBytes::from_bytes(&self.child_pubkey()),
                        addresses: vec![],
                        supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
                    }))
                }
                MachineBrokerRequest::SigningSign(sign_request) => {
                    if let Some(prepared) = self.prepared_claim.lock().unwrap().as_ref()
                        && sign_request.system_use_claim.as_ref() != Some(prepared)
                    {
                        return Err(ProtocolError::new(
                            ProtocolErrorCode::ClaimInvalid,
                            "ceremony retry changed the reviewed Solana claim",
                        ));
                    }
                    let signature = self.sign_payload(&sign_request)?;
                    Ok(MachineBrokerResponse::SigningSign(SigningResult {
                        operation_id: sign_request.operation_id,
                        operation_digest: sign_request.operation_digest,
                        signatures: vec![signature],
                        signer_receipt_digest: digest(90),
                        broker_receipt_digest: digest(91),
                    }))
                }
                MachineBrokerRequest::SealedApprovalPrepare(ApprovalPrepareRequest {
                    terms,
                    system_use_claim,
                    ..
                }) => {
                    assert_eq!(terms.limits.value_limits.len(), 1);
                    assert_eq!(terms.limits.value_limits[0].asset.chain.as_str(), "solana");
                    assert_eq!(terms.limits.value_limits[0].asset.asset, "native");
                    *self.prepared_claim.lock().unwrap() = system_use_claim;
                    Ok(MachineBrokerResponse::SealedApprovalPrepare(
                        SealedApprovalPrepareResponse {
                            approval_id: terms.approval_id().unwrap_or_else(|_| digest(7)),
                            state: ApprovalPrepareState::AwaitingCeremony,
                            ceremony_url: "http://localhost:18734/ceremony".into(),
                            ceremony_expires_at_ms: terms.expires_at_ms,
                            review_manifest_digest: digest(92),
                        },
                    ))
                }
                other => Err(ProtocolError::new(
                    ProtocolErrorCode::UnknownMethod,
                    format!("unhandled {other:?}"),
                )),
            }
        })
    }
}

fn catalog() -> ProvenanceCatalog {
    ProvenanceCatalog {
        schema: bloom_broker_api::PROVENANCE_CATALOG_SCHEMA.into(),
        records: vec![ProvenanceRecord {
            subject: ProvenanceSubject::System {
                component_id: token("bloom-machine"),
                operation_class: token("solana.transfer.confirm"),
            },
            publisher: token("bloom-installer"),
            petal_lineage: None,
            operation_classes: vec![ProvenanceOperationClass {
                operation_class: token("solana.native-transfer"),
                fee_asset: Some(bloom_broker_api::ProvenanceFeeAsset {
                    chain: token("solana"),
                    asset: "native".into(),
                }),
            }],
            installer_key_id: token("installer-key"),
            installer_signature: Base64UrlBytes::from_bytes(&[11; 64]),
        }],
    }
}

fn plan_facts_digest() -> Digest32 {
    digest(3)
}

#[tokio::test]
async fn derived_child_signs_transfer_and_signature_verifies() {
    let fixture = std::sync::Arc::new(SolanaBrokerFixture::new());
    let broker = MachineBrokerClient::new(fixture.clone());
    let signer = SolanaTransferSigner::from_catalog(broker, &catalog()).unwrap();

    let fee_payer = fixture.child_pubkey();
    let destination = {
        // A fixed destination distinct from the fee payer.
        let seed: [u8; 32] = [0xbb; 32];
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
    };
    let message = build_transfer_message(&fee_payer, &destination, 1_000_000, &[0x42; 32]).unwrap();

    let now = 1_000u64;
    let outcome = signer
        .sign_transfer(
            "wallet",
            &fee_payer,
            None,
            &message,
            &bs58::encode(destination).into_string(),
            1_000_000,
            5_000,
            "test-genesis",
            &bs58::encode([0x42; 32]).into_string(),
            100,
            Some(digest(7)), // already-approved: sign directly
            now,
            now + 60_000,
            plan_facts_digest(),
        )
        .await
        .unwrap();

    let SolanaSignOutcome::Signed { signature } = outcome else {
        panic!("expected Signed, got {outcome:?}");
    };
    assert!(verify_signature(&fee_payer, &message, &signature));

    // The signature also passes the Anza reference transaction verification.
    use solana_message::{Address, Hash, Message};
    use solana_system_interface::instruction::transfer;
    use solana_transaction::{Signature, Transaction};
    let from = Address::from(fee_payer);
    let to = Address::from(destination);
    let ix = transfer(&from, &to, 1_000_000);
    let message =
        Message::new_with_blockhash(&[ix], Some(&from), &Hash::new_from_array([0x42; 32]));
    let tx = Transaction {
        signatures: vec![Signature::from(signature)],
        message,
    };
    tx.verify().expect("signature must verify");
}

#[tokio::test]
async fn first_attempt_returns_approval_required() {
    let fixture = std::sync::Arc::new(SolanaBrokerFixture::new());
    let broker = MachineBrokerClient::new(fixture.clone());
    let signer = SolanaTransferSigner::from_catalog(broker, &catalog()).unwrap();

    let fee_payer = fixture.child_pubkey();
    let destination = [0xcc; 32];
    let message = build_transfer_message(&fee_payer, &destination, 1, &[0x42; 32]).unwrap();

    let outcome = signer
        .sign_transfer(
            "wallet",
            &fee_payer,
            None,
            &message,
            &bs58::encode(destination).into_string(),
            1,
            5_000,
            "test-genesis",
            &bs58::encode([0x42; 32]).into_string(),
            100,
            None, // no approval yet: prepare the ceremony
            1,
            60_000,
            plan_facts_digest(),
        )
        .await
        .unwrap();

    assert!(matches!(
        outcome,
        SolanaSignOutcome::ApprovalRequired { .. }
    ));
}

#[tokio::test]
async fn ceremony_retry_preserves_claim_and_authority_identity() {
    let fixture = std::sync::Arc::new(SolanaBrokerFixture::new());
    let broker = MachineBrokerClient::new(fixture.clone());
    let signer = SolanaTransferSigner::from_catalog(broker, &catalog()).unwrap();
    let fee_payer = fixture.child_pubkey();
    let destination = [0xdd; 32];
    let message = build_transfer_message(&fee_payer, &destination, 50, &[0x43; 32]).unwrap();

    let first = signer
        .sign_transfer(
            "wallet",
            &fee_payer,
            None,
            &message,
            &bs58::encode(destination).into_string(),
            50,
            5_000,
            "test-genesis",
            &bs58::encode([0x43; 32]).into_string(),
            100,
            None,
            1,
            60_000,
            plan_facts_digest(),
        )
        .await
        .unwrap();
    let SolanaSignOutcome::ApprovalRequired { approval_id, .. } = first else {
        panic!("expected approval preparation");
    };
    let second = signer
        .sign_transfer(
            "wallet",
            &fee_payer,
            None,
            &message,
            &bs58::encode(destination).into_string(),
            50,
            5_000,
            "test-genesis",
            &bs58::encode([0x43; 32]).into_string(),
            100,
            Some(approval_id),
            1,
            60_000,
            plan_facts_digest(),
        )
        .await
        .unwrap();
    assert!(matches!(second, SolanaSignOutcome::Signed { .. }));
}

#[tokio::test]
async fn rejects_missing_catalog_authorization() {
    let fixture = std::sync::Arc::new(SolanaBrokerFixture::new());
    let broker = MachineBrokerClient::new(fixture.clone());
    let mut empty_catalog = catalog();
    empty_catalog.records.clear();
    assert!(SolanaTransferSigner::from_catalog(broker, &empty_catalog).is_err());
}
