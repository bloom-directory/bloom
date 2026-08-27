//! Local-validator lifecycle E2E: stage → sign → broadcast → reconcile against
//! a real Agave validator. `#[ignore]`d — driven by
//! `.github/workflows/solana-validator.yml`, which installs the validator,
//! starts it, and runs this with `SOLANA_VALIDATOR_HTTP`.

use std::sync::Arc;

use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalPrepareState, Base64UrlBytes, CryptoSuite, DecimalU64,
    Digest32, KeyPublic, KeyRef, KeyRequest, KeyRole, KeySpec, MachineBrokerRequest,
    MachineBrokerResponse, MachineBrokerService, NormalizedSignature, ProtocolError,
    ProtocolErrorCode, ProvenanceCatalog, ProvenanceOperationClass, ProvenanceRecord,
    ProvenanceSubject, SealedApprovalPrepareResponse, ServiceFuture, SigningPayloads,
    SigningResult, Token, WalletPublic, WalletRequest,
};
use bloom_machine_client::MachineBrokerClient;
use bloom_solana::{EndpointSpec, SolanaChainRegistry, SolanaClient, SolanaSpec};
use bloom_solana_tx::engine::SolanaTransferEngine;
use bloom_solana_tx::outbox::SolanaOutbox;
use bloom_solana_tx::reconcile::SolanaReconciler;
use bloom_solana_tx::signing::{SolanaSignOutcome, SolanaTransferSigner};
use sha2::{Digest as _, Sha256};

fn token(s: &str) -> Token {
    Token::new(s).unwrap()
}
fn digest(byte: u8) -> Digest32 {
    Digest32::from_bytes([byte; 32])
}

struct BrokerFixture {
    child_signing_key: ed25519_dalek::SigningKey,
    child_key_ref: KeyRef,
}

impl BrokerFixture {
    fn new() -> Self {
        let child_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xaa; 32]);
        let pubkey = child_signing_key.verifying_key().to_bytes();
        Self {
            child_signing_key,
            child_key_ref: KeyRef {
                backend: token("local"),
                backend_instance: token("primary"),
                locator: "wallet/derived/solana-0".into(),
                key_spec: KeySpec::Ed25519,
                public_key_fingerprint: Digest32::from_bytes(Sha256::digest(pubkey).into()),
                derivation: None,
            },
        }
    }
    fn child_pubkey(&self) -> [u8; 32] {
        self.child_signing_key.verifying_key().to_bytes()
    }
}

impl MachineBrokerService for BrokerFixture {
    fn dispatch<'a>(
        &'a self,
        request: MachineBrokerRequest,
    ) -> ServiceFuture<'a, MachineBrokerResponse> {
        Box::pin(async move {
            match request {
                MachineBrokerRequest::WalletGetPublic(WalletRequest { wallet_id }) => {
                    Ok(MachineBrokerResponse::WalletGetPublic(WalletPublic {
                        wallet_id,
                        wallet_kind: token("local"),
                        root_key_ref: None,
                        key_refs: vec![self.child_key_ref.clone()],
                        policy_version: DecimalU64::new(1),
                        policy_digest: digest(1),
                        wallet_revocation_epoch: DecimalU64::new(1),
                    }))
                }
                MachineBrokerRequest::KeyGetPublic(KeyRequest { key_ref }) => {
                    Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                        role: KeyRole::Derived,
                        key_ref,
                        canonical_public_key: Base64UrlBytes::from_bytes(&self.child_pubkey()),
                        addresses: vec![],
                        supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
                    }))
                }
                MachineBrokerRequest::SigningSign(sign_request) => {
                    let SigningPayloads::Single { payload } = &sign_request.payloads else {
                        return Err(ProtocolError::new(
                            ProtocolErrorCode::MalformedFrame,
                            "expected single payload",
                        ));
                    };
                    use ed25519_dalek::Signer as _;
                    let signature = self.child_signing_key.sign(payload.decode().as_slice());
                    Ok(MachineBrokerResponse::SigningSign(SigningResult {
                        operation_id: sign_request.operation_id,
                        operation_digest: sign_request.operation_digest,
                        signatures: vec![NormalizedSignature {
                            crypto_suite: CryptoSuite::Ed25519Message,
                            bytes: Base64UrlBytes::from_bytes(&signature.to_bytes()),
                        }],
                        signer_receipt_digest: digest(90),
                        broker_receipt_digest: digest(91),
                    }))
                }
                MachineBrokerRequest::SealedApprovalPrepare(ApprovalPrepareRequest {
                    terms,
                    ..
                }) => Ok(MachineBrokerResponse::SealedApprovalPrepare(
                    SealedApprovalPrepareResponse {
                        approval_id: terms.approval_id().unwrap_or_else(|_| digest(7)),
                        state: ApprovalPrepareState::AwaitingCeremony,
                        ceremony_url: "http://localhost:18734/ceremony".into(),
                        ceremony_expires_at_ms: terms.expires_at_ms,
                        review_manifest_digest: digest(92),
                    },
                )),
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

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[tokio::test]
#[ignore]
async fn local_validator_lifecycle_stage_sign_broadcast_reconcile() {
    let endpoint =
        std::env::var("SOLANA_VALIDATOR_HTTP").unwrap_or_else(|_| "http://127.0.0.1:8899".into());
    let endpoint_spec = EndpointSpec {
        url: endpoint,
        weight: 100,
        cu_per_sec: None,
        max_rps: None,
        http_only: false,
    };
    let discovery_client = SolanaClient::build(&SolanaSpec {
        name: "solana-local-discovery".into(),
        endpoints: vec![endpoint_spec.clone()],
        expected_genesis_hex: None,
        allow_broadcast: false,
    })
    .unwrap();
    let genesis = discovery_client
        .verify_genesis()
        .await
        .expect("discover local validator genesis");
    let client = SolanaClient::build(&SolanaSpec {
        name: "solana-local".into(),
        endpoints: vec![endpoint_spec],
        expected_genesis_hex: Some(genesis),
        allow_broadcast: true,
    })
    .unwrap();
    client.get_health().await.expect("validator is healthy");

    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let engine = SolanaTransferEngine::new(outbox.clone(), client.clone(), signer, "solana-local");

    let fee_payer = broker.child_pubkey();
    let fee_payer_b58 = bs58::encode(fee_payer).into_string();
    println!("fee_payer={fee_payer_b58}");
    let airdrop_lamports = std::env::var("SOLANA_AIRDROP_LAMPORTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000_000_000);
    let transfer_lamports = std::env::var("SOLANA_TRANSFER_LAMPORTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000_000);
    assert!(transfer_lamports > 0);
    assert!(airdrop_lamports > transfer_lamports + 5_000);

    // Fund the derived child and wait for the balance to land.
    let mut airdrop_result = None;
    for attempt in 0..3 {
        match client
            .request_airdrop(&fee_payer_b58, airdrop_lamports)
            .await
        {
            Ok(signature) => {
                airdrop_result = Some(signature);
                break;
            }
            Err(error) if attempt < 2 => {
                eprintln!("airdrop attempt {} failed: {error}", attempt + 1);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(error) => panic!("airdrop to the derived child: {error}"),
        }
    }
    assert!(airdrop_result.is_some());
    for _ in 0..30 {
        if client.get_balance(&fee_payer_b58).await.unwrap_or(0) >= airdrop_lamports {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert!(
        client.get_balance(&fee_payer_b58).await.unwrap_or(0) >= airdrop_lamports,
        "airdrop must fund the derived child"
    );

    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();

    let staged = engine
        .stage(
            "wallet",
            &fee_payer,
            None,
            None,
            &destination,
            transfer_lamports,
            now_ms(),
        )
        .await
        .expect("stage against the local validator");

    let first = engine
        .sign("wallet", &staged.id, &fee_payer, None, None, now_ms())
        .await
        .expect("prepare the signing ceremony");
    let approval_id = match first {
        SolanaSignOutcome::ApprovalRequired { approval_id, .. } => approval_id,
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    let signed = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval_id),
            now_ms(),
        )
        .await
        .expect("sign");
    assert!(matches!(signed, SolanaSignOutcome::Signed { .. }));

    let signature = engine
        .broadcast("wallet", &staged.id, now_ms())
        .await
        .expect("broadcast against the local validator");

    // Reconcile: the sent entry must reach a confirmed receipt.
    let registry = SolanaChainRegistry::new();
    registry.add(client);
    let reconciler = SolanaReconciler::new(outbox.clone(), registry);
    for _ in 0..30 {
        if reconciler.tick().await > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let receipt = outbox
        .read_receipt("wallet", "solana-local", &staged.id)
        .unwrap()
        .expect("reconciler writes a receipt");
    assert_eq!(receipt.signature, signature);
    assert_eq!(receipt.outcome, "success");
    println!(
        "confirmed_signature={} destination={} lamports={transfer_lamports}",
        receipt.signature,
        bs58::encode(destination).into_string()
    );
}
