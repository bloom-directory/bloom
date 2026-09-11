//! End-to-end transfer lifecycle: stage → sign → broadcast, driven by a stub
//! Solana RPC node and a real-Ed25519 Broker fixture.

use std::sync::{Arc, Mutex};

use bloom_broker_api::{
    ApprovalPrepareRequest, ApprovalPrepareState, Base64UrlBytes, CryptoSuite, DecimalU64,
    Digest32, KeyPublic, KeyRef, KeyRequest, KeyRole, KeySpec, MachineBrokerRequest,
    MachineBrokerResponse, MachineBrokerService, NormalizedSignature, ProtocolError,
    ProtocolErrorCode, ProvenanceCatalog, ProvenanceOperationClass, ProvenanceRecord,
    ProvenanceSubject, SealedApprovalPrepareResponse, ServiceFuture, SigningPayloads,
    SigningResult, Token, WalletPublic, WalletRequest,
};
use bloom_machine_client::MachineBrokerClient;
use bloom_solana::{EndpointSpec, SolanaClient, SolanaSpec};
use bloom_solana_tx::engine::SolanaTransferEngine;
use bloom_solana_tx::outbox::{SolanaOutbox, SolanaOutboxState};
use bloom_solana_tx::signing::SolanaTransferSigner;
use bloom_solana_tx::types::SolanaTxStatus;
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
    prepared_expiries: Mutex<Vec<u64>>,
    /// Operation id to the exact terms it was first prepared with, mirroring
    /// the Broker's own `stable_approval_response`: a second prepare carrying
    /// the same id with different terms is refused, permanently.
    prepared_terms: Mutex<std::collections::BTreeMap<String, String>>,
    prepared_ids: Mutex<Vec<Digest32>>,
    conflicts: Mutex<u32>,
    /// When set, the next signing request is answered with this error.
    next_sign_error: Mutex<Option<(ProtocolErrorCode, String)>>,
    /// When set, a signing request announces itself on `sign_reached` and
    /// then waits for a permit, holding the signature in flight.
    sign_gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    sign_reached: tokio::sync::Notify,
    sign_calls: Mutex<u32>,
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
            prepared_expiries: Mutex::new(Vec::new()),
            prepared_terms: Mutex::new(std::collections::BTreeMap::new()),
            prepared_ids: Mutex::new(Vec::new()),
            conflicts: Mutex::new(0),
            next_sign_error: Mutex::new(None),
            sign_gate: Mutex::new(None),
            sign_reached: tokio::sync::Notify::new(),
            sign_calls: Mutex::new(0),
        }
    }
    fn child_pubkey(&self) -> [u8; 32] {
        self.child_signing_key.verifying_key().to_bytes()
    }

    fn last_prepared_expiry(&self) -> u64 {
        *self.prepared_expiries.lock().unwrap().last().unwrap()
    }

    /// How many prepares were refused as reusing an operation id with
    /// different terms.
    fn conflicts(&self) -> u32 {
        *self.conflicts.lock().unwrap()
    }

    fn prepared_ids(&self) -> Vec<Digest32> {
        self.prepared_ids.lock().unwrap().clone()
    }

    fn fail_next_signature(&self, code: ProtocolErrorCode, message: &str) {
        *self.next_sign_error.lock().unwrap() = Some((code, message.to_owned()));
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
                // Selection resolves candidates from the fresh account
                // projection; serve the fixture's single active child.
                MachineBrokerRequest::WalletAccounts(WalletRequest { wallet_id }) => Ok(
                    MachineBrokerResponse::WalletAccounts(bloom_broker_api::WalletAccountsPublic {
                        wallet_id,
                        seed_profile: bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
                        accounts: vec![bloom_broker_api::DerivedAccountPublic {
                            key_ref: self.child_key_ref.clone(),
                            wallet_seed_profile:
                                bloom_broker_api::WalletSeedProfile::Bip39MulticurveV1,
                            derivation_profile:
                                bloom_broker_api::DerivationProfile::Bip44SolanaSlip10Ed25519V1,
                            path: "m/44'/501'/0'/0'".into(),
                            canonical_public_key: Base64UrlBytes::from_bytes(&self.child_pubkey()),
                            public_key_encoding:
                                bloom_broker_api::PublicKeyEncoding::Ed25519SpkiDer,
                            public_key_fingerprint: self
                                .child_key_ref
                                .public_key_fingerprint
                                .clone(),
                            supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
                            chain_projections: vec![],
                            lifecycle: bloom_broker_api::AccountLifecycleState::Active,
                        }],
                    }),
                ),
                MachineBrokerRequest::KeyGetPublic(KeyRequest { key_ref }) => {
                    Ok(MachineBrokerResponse::KeyGetPublic(KeyPublic {
                        role: KeyRole::Derived,
                        key_ref,
                        canonical_public_key: Base64UrlBytes::from_bytes(&self.child_pubkey()),
                        addresses: vec![],
                        supported_crypto_suites: vec![CryptoSuite::Ed25519Message],
                        petal_scope_expires_at_ms: None,
                    }))
                }
                MachineBrokerRequest::SigningSign(sign_request) => {
                    *self.sign_calls.lock().unwrap() += 1;
                    if let Some((code, message)) = self.next_sign_error.lock().unwrap().take() {
                        return Err(ProtocolError::new(code, message));
                    }
                    let gate = self.sign_gate.lock().unwrap().clone();
                    if let Some(gate) = gate {
                        self.sign_reached.notify_one();
                        gate.acquire().await.unwrap().forget();
                    }
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
                    operation_id,
                    terms,
                    ..
                }) => {
                    // The Broker keys a prepared ceremony by operation id and
                    // compares the whole request against what it stored. Model
                    // that here: same id, different terms, permanent refusal.
                    let fingerprint = serde_json::to_string(&terms).unwrap();
                    {
                        let mut prepared = self.prepared_terms.lock().unwrap();
                        match prepared.get(operation_id.as_str()) {
                            Some(existing) if existing != &fingerprint => {
                                *self.conflicts.lock().unwrap() += 1;
                                return Err(ProtocolError::new(
                                    ProtocolErrorCode::OperationIdConflict,
                                    "ceremony operation ID was reused with different stable input",
                                ));
                            }
                            _ => {
                                prepared.insert(operation_id.as_str().to_owned(), fingerprint);
                            }
                        }
                    }
                    self.prepared_expiries
                        .lock()
                        .unwrap()
                        .push(terms.expires_at_ms.get());
                    let approval_id = terms.approval_id().unwrap_or_else(|_| digest(7));
                    self.prepared_ids.lock().unwrap().push(approval_id.clone());
                    Ok(MachineBrokerResponse::SealedApprovalPrepare(
                        SealedApprovalPrepareResponse {
                            approval_id,
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

fn submitted_transaction_signature(request: &serde_json::Value) -> String {
    let tx_b64 = request["params"][0]
        .as_str()
        .expect("transaction parameter");
    let tx = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tx_b64)
        .expect("base64 transaction");
    assert_eq!(tx.first(), Some(&1), "expected one transaction signature");
    bs58::encode(&tx[1..65]).into_string()
}

/// A stub Solana JSON-RPC node answering blockhash + sendTransaction.
async fn spawn_node() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
                let request_json = serde_json::from_str::<serde_json::Value>(body)
                    .unwrap_or(serde_json::Value::Null);
                let method = request_json
                    .get("method")
                    .and_then(|m| m.as_str())
                    .map(String::from)
                    .unwrap_or_default();
                let result = match method.as_str() {
                    "getGenesisHash" => r#""test-genesis""#.to_string(),
                    "getLatestBlockhash" => {
                        let blockhash = bs58::encode([0x42u8; 32]).into_string();
                        format!(
                            r#"{{"context":{{"slot":1}},"value":{{"blockhash":"{blockhash}","lastValidBlockHeight":100}}}}"#
                        )
                    }
                    "getBlockHeight" => "1".to_string(),
                    "getFeeForMessage" => r#"{"context":{"slot":1},"value":5000}"#.to_string(),
                    "simulateTransaction" => r#"{"context":{"slot":1},"value":{"err":null,"logs":["Program 11111111111111111111111111111111 success"],"unitsConsumed":150}}"#.to_string(),
                    "sendTransaction" => serde_json::to_string(
                        &submitted_transaction_signature(&request_json),
                    )
                    .unwrap(),
                    _ => r#"{"code":-32601,"message":"method not found"}"#.to_string(),
                };
                let payload = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

/// A stub node answering `getLatestBlockhash` (with a configurable
/// `lastValidBlockHeight`) and `getBlockHeight` (with a configurable
/// current height), for the `stage()` expiry tests below (Fix D,
/// PLAN-SOLANA-PR-FIXES.md).
async fn spawn_node_with_heights(
    current_block_height: u64,
    last_valid_block_height: u64,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
                let request_json = serde_json::from_str::<serde_json::Value>(body)
                    .unwrap_or(serde_json::Value::Null);
                let method = request_json
                    .get("method")
                    .and_then(|m| m.as_str())
                    .map(String::from)
                    .unwrap_or_default();
                let result = match method.as_str() {
                    "getGenesisHash" => r#""test-genesis""#.to_string(),
                    "getLatestBlockhash" => {
                        let blockhash = bs58::encode([0x42u8; 32]).into_string();
                        format!(
                            r#"{{"context":{{"slot":{current_block_height}}},"value":{{"blockhash":"{blockhash}","lastValidBlockHeight":{last_valid_block_height}}}}}"#
                        )
                    }
                    "getBlockHeight" => current_block_height.to_string(),
                    "getFeeForMessage" => {
                        format!(r#"{{"context":{{"slot":{current_block_height}}},"value":5000}}"#)
                    }
                    _ => r#"{"code":-32601,"message":"method not found"}"#.to_string(),
                };
                let payload = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

// Fix D (PLAN-SOLANA-PR-FIXES.md): stage() hardcoded expires_ms: 0, which
// sweep_expired's `!= 0` guard treats as "never expires". A staged transfer
// whose blockhash has already gone (or is about to go) stale must get a
// real, reapable expiry instead.
#[tokio::test]
async fn stage_refuses_an_already_stale_latest_blockhash() {
    // The blockhash's last-valid height is already behind the current
    // height: it's stale the moment it's staged.
    let endpoint = spawn_node_with_heights(/* current */ 500, /* last_valid */ 350).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");

    let fee_payer = broker.child_pubkey();
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();
    let now_ms = 1_000_000u128;
    let error = engine
        .stage(
            "wallet",
            &fee_payer,
            Default::default(),
            &destination,
            1_000_000,
            now_ms,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("staged blockhash expired"));
    assert!(
        outbox
            .list("wallet", "solana-devnet", SolanaOutboxState::Pending)
            .unwrap()
            .is_empty(),
        "an RPC's stale latest blockhash must never reach durable state"
    );
}

#[tokio::test]
async fn stage_with_a_fresh_blockhash_is_not_reaped_immediately() {
    // Plenty of blocks remain before the blockhash goes stale.
    let endpoint = spawn_node_with_heights(/* current */ 500, /* last_valid */ 650).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");

    let fee_payer = broker.child_pubkey();
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();
    let now_ms = 1_000_000u128;
    let staged = engine
        .stage(
            "wallet",
            &fee_payer,
            Default::default(),
            &destination,
            1_000_000,
            now_ms,
        )
        .await
        .unwrap();
    assert!(
        staged.expires_ms > now_ms,
        "a fresh blockhash must expire well after now, got expires_ms={} for now_ms={now_ms}",
        staged.expires_ms
    );

    let swept = outbox
        .sweep_expired(
            now_ms,
            &std::collections::HashMap::from([("solana-devnet".to_string(), 500_u64)]),
        )
        .unwrap();
    assert_eq!(swept, 0, "a not-yet-stale stage must survive a sweep pass");
}

fn client(endpoint: &str) -> SolanaClient {
    SolanaClient::build(&SolanaSpec {
        name: "solana-devnet".into(),
        endpoints: vec![EndpointSpec {
            url: endpoint.to_string(),
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        }],
        expected_genesis_base58: Some("test-genesis".into()),
        allow_broadcast: true,
    })
    .unwrap()
}

#[tokio::test]
async fn full_transfer_lifecycle_stage_sign_broadcast() {
    let endpoint = spawn_node().await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");

    let fee_payer = broker.child_pubkey();
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();

    // Stage.
    let staged = engine
        .stage(
            "wallet",
            &fee_payer,
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap();
    assert_eq!(staged.status, SolanaTxStatus::Pending);
    assert_eq!(staged.lamports, 1_000_000);
    assert_eq!(staged.blockhash, bs58::encode([0x42u8; 32]).into_string());

    // First sign attempt prepares the ceremony (no approval id yet).
    let first = engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
        .await
        .unwrap();
    let approval_id = match first {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    assert_eq!(broker.last_prepared_expiry(), 3_601_100);
    // Still pending: no signature recorded yet.
    assert!(
        outbox
            .read_in_state(
                "wallet",
                "solana-devnet",
                &staged.id,
                SolanaOutboxState::Pending
            )
            .is_ok()
    );

    // Retry with the approval id: signs, but stays pending — the entry only
    // moves to `sent` once `broadcast` actually succeeds (Fix C,
    // PLAN-SOLANA-PR-FIXES.md: signing alone must never strand an entry in
    // `sent` for a broadcast that hasn't happened yet).
    let signed = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval_id),
            1_200,
        )
        .await
        .unwrap();
    assert!(matches!(
        signed,
        bloom_solana_tx::signing::SolanaSignOutcome::Signed { .. }
    ));
    let still_pending = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Pending,
        )
        .unwrap();
    let expected_signature = outbox
        .recorded_signature(&still_pending)
        .unwrap()
        .expect("signed entry");

    // Broadcast: durably records the exact attempt and claims the entry for
    // reconciliation before submitting the assembled transaction.
    let signature = engine.broadcast("wallet", &staged.id, 1_300).await.unwrap();
    assert_eq!(signature, expected_signature);
    let sent = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Sent,
        )
        .unwrap();
    // The broadcast attempt marker is recorded next to the sent entry.
    assert!(
        sent.dir
            .join(bloom_solana_tx::outbox::BROADCAST_ATTEMPT_FILE)
            .exists()
    );
    // `intent.json`'s persisted status must agree with the directory it now
    // lives in — broadcast() derives the transition target from
    // `SolanaOutboxState::from_status(&staged.status)` (the previously
    // dead-code mapping the plan asked to wire in) and rewrites
    // `intent.json` accordingly, rather than leaving it stale at Pending.
    assert_eq!(sent.staged.status, SolanaTxStatus::Sent);
    let simulation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(sent.dir.join("simulation.json")).unwrap()).unwrap();
    assert_eq!(simulation["success"], true);
    assert_eq!(simulation["units_consumed"], 150);
    assert!(simulation.get("signature").is_none());
    assert_eq!(
        bloom_solana_tx::outbox::SolanaOutboxState::from_status(&sent.staged.status),
        SolanaOutboxState::Sent
    );
}

// ------------------------------------------------------------------
// Staging idempotency: one message is one chain transaction.
// ------------------------------------------------------------------

#[tokio::test]
async fn staging_an_identical_active_transfer_is_idempotent() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height, false, false, requests).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();

    // The stub serves one fixed recent blockhash, so two stagings of the
    // same economic intent serialize to the same message — and therefore
    // the same deterministic Solana signature.
    let first = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap();
    let second = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            2_000,
        )
        .await
        .unwrap();
    assert_eq!(first.id, second.id, "the existing entry must be returned");
    assert_eq!(first.message_b64, second.message_b64);
    assert_eq!(
        outbox
            .list("wallet", "solana-devnet", SolanaOutboxState::Pending)
            .unwrap()
            .len(),
        1,
        "no second receipt-eligible identity for one on-chain transfer"
    );

    // A different amount is a genuinely different transfer and still stages.
    let distinct = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            2_000_000,
            3_000,
        )
        .await
        .unwrap();
    assert_ne!(distinct.id, first.id);
    assert_ne!(distinct.message_b64, first.message_b64);
}

#[tokio::test]
async fn an_identical_transfer_cannot_be_staged_again_after_dispatch() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height, false, false, requests).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();

    let staged = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap();
    let first = engine
        .sign(
            "wallet",
            &staged.id,
            &broker.child_pubkey(),
            None,
            None,
            1_100,
        )
        .await
        .unwrap();
    let approval_id = match first {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    engine
        .sign(
            "wallet",
            &staged.id,
            &broker.child_pubkey(),
            None,
            Some(approval_id),
            1_200,
        )
        .await
        .unwrap();
    engine.broadcast("wallet", &staged.id, 1_300).await.unwrap();

    // The same message was already dispatched: its single deterministic
    // signature names one on-chain transaction, so a second outbox identity
    // could only ever produce a second success receipt for that one payment.
    let error = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            2_000,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("already dispatched"), "{error}");
    assert!(
        outbox
            .list("wallet", "solana-devnet", SolanaOutboxState::Pending)
            .unwrap()
            .is_empty(),
        "the refused duplicate must not leave durable state behind"
    );
}

/// A stub node whose `sendTransaction` answers with a non-retryable
/// JSON-RPC error `fail_times` times before succeeding, and otherwise
/// behaves like [`spawn_node`]. Used to exercise the "broadcast RPC call
/// fails after a successful `sign()`" window (Fix C,
/// PLAN-SOLANA-PR-FIXES.md).
async fn spawn_node_with_flaky_broadcast(fail_times: Arc<std::sync::atomic::AtomicU64>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let fail_times = fail_times.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
                let request_json = serde_json::from_str::<serde_json::Value>(body)
                    .unwrap_or(serde_json::Value::Null);
                let method = request_json
                    .get("method")
                    .and_then(|m| m.as_str())
                    .map(String::from)
                    .unwrap_or_default();
                let payload = match method.as_str() {
                    "getGenesisHash" => {
                        r#"{"jsonrpc":"2.0","id":1,"result":"test-genesis"}"#.to_string()
                    }
                    "getLatestBlockhash" => {
                        let blockhash = bs58::encode([0x42u8; 32]).into_string();
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"blockhash":"{blockhash}","lastValidBlockHeight":100}}}}}}"#
                        )
                    }
                    "getBlockHeight" => {
                        r#"{"jsonrpc":"2.0","id":1,"result":1}"#.to_string()
                    }
                    "getFeeForMessage" => {
                        r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":5000}}"#.to_string()
                    }
                    "simulateTransaction" => {
                        r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"err":null,"logs":[],"unitsConsumed":150}}}"#.to_string()
                    }
                    "sendTransaction" => {
                        let remaining = fail_times.fetch_update(
                            std::sync::atomic::Ordering::SeqCst,
                            std::sync::atomic::Ordering::SeqCst,
                            |n| n.checked_sub(1),
                        );
                        if remaining.is_ok_and(|n| n > 0) {
                            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"simulated broadcast failure"}}"#.to_string()
                        } else {
                            format!(
                                r#"{{"jsonrpc":"2.0","id":1,"result":{}}}"#,
                                serde_json::to_string(&submitted_transaction_signature(&request_json)).unwrap()
                            )
                        }
                    }
                    _ => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#.to_string(),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

async fn spawn_node_with_controls(
    block_height: Arc<std::sync::atomic::AtomicU64>,
    simulation_fails: bool,
    mismatched_signature: bool,
    requests: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let block_height = block_height.clone();
            let requests = requests.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
                let request_json = serde_json::from_str::<serde_json::Value>(body)
                    .unwrap_or(serde_json::Value::Null);
                requests.lock().unwrap().push(request_json.clone());
                let method = request_json["method"].as_str().unwrap_or_default();
                let result = match method {
                    "getGenesisHash" => serde_json::json!("test-genesis"),
                    "getLatestBlockhash" => {
                        let height = block_height.load(std::sync::atomic::Ordering::SeqCst);
                        serde_json::json!({
                            "context": { "slot": height },
                            "value": {
                                "blockhash": bs58::encode([((height % 250) + 1) as u8; 32]).into_string(),
                                "lastValidBlockHeight": height + 100
                            }
                        })
                    }
                    "getBlockHeight" => {
                        serde_json::json!(block_height.load(std::sync::atomic::Ordering::SeqCst))
                    }
                    "getFeeForMessage" => serde_json::json!({
                        "context": { "slot": 1 }, "value": 5_000
                    }),
                    "simulateTransaction" => serde_json::json!({
                        "context": { "slot": 1 },
                        "value": {
                            "err": simulation_fails.then(|| serde_json::json!({
                                "InstructionError": [0, "InsufficientFunds"]
                            })),
                            "logs": ["Program log: preflight"],
                            "unitsConsumed": 321
                        }
                    }),
                    "sendTransaction" => {
                        if mismatched_signature {
                            serde_json::json!(bs58::encode([9u8; 64]).into_string())
                        } else {
                            serde_json::json!(submitted_transaction_signature(&request_json))
                        }
                    }
                    _ => serde_json::Value::Null,
                };
                let payload = serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "result": result
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

/// Stage + sign (through the two-step approval ceremony) a transfer and
/// return once it's signed and pending, ready for `broadcast`.
async fn stage_and_sign(
    engine: &SolanaTransferEngine,
    broker: &BrokerFixture,
) -> bloom_solana_tx::types::StagedSolanaTransfer {
    let fee_payer = broker.child_pubkey();
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();
    let staged = engine
        .stage(
            "wallet",
            &fee_payer,
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap();
    let first = engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
        .await
        .unwrap();
    let approval_id = match first {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    let signed = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval_id),
            1_200,
        )
        .await
        .unwrap();
    assert!(matches!(
        signed,
        bloom_solana_tx::signing::SolanaSignOutcome::Signed { .. }
    ));
    staged
}

#[tokio::test]
async fn ambiguous_broadcast_failure_is_durable_and_not_retried() {
    let fail_times = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let endpoint = spawn_node_with_flaky_broadcast(fail_times).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");

    let staged = stage_and_sign(&engine, &broker).await;
    let expected_signature = outbox
        .recorded_signature(
            &outbox
                .read_in_state(
                    "wallet",
                    "solana-devnet",
                    &staged.id,
                    SolanaOutboxState::Pending,
                )
                .unwrap(),
        )
        .unwrap()
        .unwrap();

    // A node error is ambiguous: the endpoint may have accepted the exact
    // transaction before its response was lost. The entry must therefore be
    // durable and non-cancellable before the request begins.
    let first_attempt = engine.broadcast("wallet", &staged.id, 1_300).await;
    assert!(
        first_attempt.is_err(),
        "expected the first broadcast to fail"
    );
    let entry = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Sent,
        )
        .expect("an ambiguous attempt must be owned by reconciliation");
    assert!(
        entry
            .dir
            .join(bloom_solana_tx::outbox::BROADCAST_ATTEMPT_FILE)
            .exists()
    );
    assert_eq!(
        outbox.walk_all_sent().unwrap()[0].signature,
        expected_signature
    );

    // Neither retry nor cancellation may create a second economic effect.
    assert!(engine.broadcast("wallet", &staged.id, 1_400).await.is_err());
    assert!(engine.cancel("wallet", &staged.id).await.is_err());
}

#[tokio::test]
async fn a_durable_broadcast_attempt_is_not_cancellable() {
    // Never recovers: every `sendTransaction` call fails.
    let fail_times = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
    let endpoint = spawn_node_with_flaky_broadcast(fail_times).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");

    let staged = stage_and_sign(&engine, &broker).await;
    assert!(engine.broadcast("wallet", &staged.id, 1_300).await.is_err());

    engine
        .cancel("wallet", &staged.id)
        .await
        .expect_err("a possibly-submitted transfer cannot be reported cancelled");
    let attempted = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Sent,
        )
        .unwrap();
    assert_eq!(attempted.staged.status, SolanaTxStatus::Sent);
}

#[tokio::test]
async fn signing_and_broadcast_both_refuse_an_expired_blockhash() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height.clone(), false, false, requests.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();

    let unsigned = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap();
    height.store(102, std::sync::atomic::Ordering::SeqCst);
    let sign_error = engine
        .sign(
            "wallet",
            &unsigned.id,
            &broker.child_pubkey(),
            None,
            None,
            1_100,
        )
        .await
        .unwrap_err();
    assert!(sign_error.to_string().contains("restage the transfer"));

    height.store(1, std::sync::atomic::Ordering::SeqCst);
    let signed = stage_and_sign(&engine, &broker).await;
    height.store(102, std::sync::atomic::Ordering::SeqCst);
    let broadcast_error = engine
        .broadcast("wallet", &signed.id, 1_300)
        .await
        .unwrap_err();
    assert!(broadcast_error.to_string().contains("restage the transfer"));
    let expired = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &signed.id,
            SolanaOutboxState::Pending,
        )
        .expect("expired signed transfer remains pending for explicit restaging");
    assert!(!requests.lock().unwrap().iter().any(|r| matches!(
        r["method"].as_str(),
        Some("simulateTransaction" | "sendTransaction")
    )));
    assert!(
        !expired
            .dir
            .join(bloom_solana_tx::outbox::BROADCAST_ATTEMPT_FILE)
            .exists(),
        "a refused broadcast must not look like one that may have been sent"
    );

    // The last valid height itself is still inside the window.
    height.store(
        signed.last_valid_block_height,
        std::sync::atomic::Ordering::SeqCst,
    );
    engine
        .broadcast("wallet", &signed.id, 1_400)
        .await
        .expect("the blockhash is valid through its last valid height");
}

/// An approval now lives for an hour, far longer than a blockhash. A live
/// approval must still not sign a message whose blockhash has passed: the
/// refusal comes before the Broker is asked, and leaves the approval intact
/// for the restage that follows.
#[tokio::test]
async fn a_live_approval_cannot_sign_past_the_blockhash_height() {
    let (height, _dir, outbox, broker, engine) = restage_fixture().await;
    let (staged, approval) = stage_awaiting_approval(&engine, &outbox, &broker).await;
    let fee_payer = broker.child_pubkey();
    let attempt_before = outbox
        .approval_attempt(&pending(&outbox, &staged.id))
        .unwrap()
        .unwrap();

    height.store(
        staged.last_valid_block_height + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    // Half an hour after approval: well inside its window.
    let error = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval.clone()),
            1_800_100,
        )
        .await
        .expect_err("a passed blockhash cannot be signed");
    assert!(
        error.to_string().contains("restage the transfer"),
        "{error}"
    );
    assert_eq!(*broker.sign_calls.lock().unwrap(), 0);
    let entry = pending(&outbox, &staged.id);
    assert!(outbox.recorded_signature(&entry).unwrap().is_none());
    let attempt = outbox.approval_attempt(&entry).unwrap().unwrap();
    assert_eq!(
        (attempt.attempt, attempt.issued_at_ms, attempt.expires_at_ms),
        (
            attempt_before.attempt,
            attempt_before.issued_at_ms,
            attempt_before.expires_at_ms
        ),
        "the refusal must not touch the approval"
    );
    assert_eq!(challenge_of(&entry)["approval_id"], approval.as_str());

    height.store(
        staged.last_valid_block_height,
        std::sync::atomic::Ordering::SeqCst,
    );
    let signed = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval),
            1_800_200,
        )
        .await
        .unwrap();
    assert!(matches!(
        signed,
        bloom_solana_tx::signing::SolanaSignOutcome::Signed { .. }
    ));
    assert_eq!(*broker.sign_calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn expired_transfer_restages_with_fresh_facts_and_no_reused_authority() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height.clone(), false, false, requests).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();
    let original = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap();

    let too_early = engine
        .restage_expired("wallet", &original.id, &broker.child_pubkey(), 1_250)
        .await
        .unwrap_err();
    assert!(too_early.to_string().contains("remains valid"));

    assert_eq!(
        outbox
            .sweep_expired(
                u128::MAX,
                &std::collections::HashMap::from([("solana-devnet".to_string(), 1_000_000_u64)]),
            )
            .unwrap(),
        1
    );
    outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &original.id,
            SolanaOutboxState::Failed,
        )
        .expect("the sweeper moves stale entries to failed before users can restage them");

    height.store(102, std::sync::atomic::Ordering::SeqCst);
    let replacement = engine
        .restage_expired("wallet", &original.id, &broker.child_pubkey(), 1_300)
        .await
        .unwrap();
    assert_ne!(replacement.id, original.id);
    assert_ne!(replacement.blockhash, original.blockhash);
    assert_eq!(replacement.destination, original.destination);
    assert_eq!(replacement.lamports, original.lamports);
    assert_eq!(replacement.status, SolanaTxStatus::Pending);

    let expired = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &original.id,
            SolanaOutboxState::Failed,
        )
        .unwrap();
    assert_eq!(expired.staged.status, SolanaTxStatus::Expired);
    assert!(!expired.dir.join(".signature").exists());
    let advice: serde_json::Value =
        serde_json::from_slice(&std::fs::read(expired.dir.join("restage_advice.json")).unwrap())
            .unwrap();
    assert_eq!(advice["replacement_id"], replacement.id);

    let pending = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &replacement.id,
            SolanaOutboxState::Pending,
        )
        .unwrap();
    assert!(outbox.recorded_signature(&pending).unwrap().is_none());
    assert!(!pending.dir.join("approval.json").exists());

    height.store(103, std::sync::atomic::Ordering::SeqCst);
    let retried = engine
        .restage_expired("wallet", &original.id, &broker.child_pubkey(), 1_400)
        .await
        .unwrap();
    assert_eq!(retried.id, replacement.id);
    assert_eq!(retried.message_b64, replacement.message_b64);
}

#[tokio::test]
async fn failed_signature_verifying_simulation_is_persisted_and_blocks_broadcast() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height, true, false, requests.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let staged = stage_and_sign(&engine, &broker).await;

    let error = engine
        .broadcast("wallet", &staged.id, 1_300)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("simulation failed"));
    let pending = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Pending,
        )
        .unwrap();
    let artifact: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pending.dir.join("simulation.json")).unwrap())
            .unwrap();
    assert_eq!(artifact["success"], false);
    assert_eq!(artifact["units_consumed"], 321);
    assert!(artifact.get("signature").is_none());

    let requests = requests.lock().unwrap();
    let simulation = requests
        .iter()
        .find(|request| request["method"] == "simulateTransaction")
        .expect("simulation request");
    assert_eq!(simulation["params"][1]["sigVerify"], true);
    assert_eq!(simulation["params"][1]["replaceRecentBlockhash"], false);
    assert!(
        !requests
            .iter()
            .any(|request| request["method"] == "sendTransaction")
    );
}

#[tokio::test]
async fn mismatched_rpc_signature_remains_a_reconcilable_sent_attempt() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height, false, true, requests).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let staged = stage_and_sign(&engine, &broker).await;

    let error = engine
        .broadcast("wallet", &staged.id, 1_300)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("RPC returned transaction signature")
    );
    let sent = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Sent,
        )
        .expect("a dispatched request must remain reconcilable despite an untrusted response");
    let recorded = outbox
        .recorded_signature(&sent)
        .expect("read local signature")
        .expect("local deterministic signature");
    assert_eq!(bs58::decode(recorded).into_vec().unwrap().len(), 64);
}

#[tokio::test]
async fn tampered_private_signature_is_reverified_before_rpc_submission() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height, false, false, requests.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let staged = stage_and_sign(&engine, &broker).await;
    outbox
        .record_signature(
            "wallet",
            "solana-devnet",
            &staged.id,
            &bs58::encode([9u8; 64]).into_string(),
        )
        .unwrap();

    let error = engine
        .broadcast("wallet", &staged.id, 1_300)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not verify"));
    assert!(!requests.lock().unwrap().iter().any(|request| {
        matches!(
            request["method"].as_str(),
            Some("simulateTransaction" | "sendTransaction")
        )
    }));
}

#[tokio::test]
async fn broadcast_refuses_when_operator_disables_it() {
    let endpoint = spawn_node().await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let mut spec = SolanaSpec {
        name: "solana-devnet".into(),
        endpoints: vec![EndpointSpec {
            url: endpoint,
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        }],
        expected_genesis_base58: None,
        allow_broadcast: false,
    };
    spec.allow_broadcast = false;
    let client = SolanaClient::build(&spec).unwrap();
    let engine = SolanaTransferEngine::new(outbox, client, signer, "solana-devnet");

    // The broadcast gate is the operator's release posture: it fires before
    // any outbox lookup, so even a valid path is refused.
    let err = engine
        .broadcast("wallet", "0001-00001", 1_000)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            bloom_solana_tx::engine::EngineError::BroadcastDisabled(_)
        ),
        "{err}"
    );
}

/// Refreshing an approved transfer when the cluster has no newer blockhash is
/// not a failure. `stage_with_id` deduplicates an identical message, so the
/// "replacement" is the entry itself; the transfer must stay pending, keep its
/// id, and remain signable under the approval the owner already granted.
/// Against a local validator, or whenever a confirm follows staging closely,
/// this is the ordinary case.
#[tokio::test]
async fn approved_restage_without_a_newer_blockhash_keeps_the_staged_transfer() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height.clone(), false, false, requests).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xcc; 32])
        .verifying_key()
        .to_bytes();
    let original = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap();

    // The stub node keeps returning the same blockhash, so the refresh finds
    // nothing newer to stage.
    let refreshed = engine
        .restage_approved("wallet", &original.id, &broker.child_pubkey(), 1_100)
        .await
        .expect("an unchanged blockhash must not fail an approved refresh");

    assert_eq!(refreshed.id, original.id);
    assert_eq!(refreshed.blockhash, original.blockhash);
    outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &original.id,
            bloom_solana_tx::outbox::SolanaOutboxState::Pending,
        )
        .expect("the transfer stays pending under its existing approval");
}

/// The approval must reach the successor before the entry holding it is
/// retired. Retiring an entry deletes its `approval_challenge.json`, which
/// carries the only durable approval id, so migrating afterwards leaves a
/// window where a crash strips the lineage of its approval and every later
/// confirm re-prepares an operation the Broker refuses permanently.
#[tokio::test]
async fn restage_migrates_the_approval_before_retiring_its_predecessor() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let endpoint = spawn_node_with_controls(height.clone(), false, false, requests).await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xdd; 32])
        .verifying_key()
        .to_bytes();
    let original = engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap();

    let entry = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &original.id,
            bloom_solana_tx::outbox::SolanaOutboxState::Pending,
        )
        .unwrap();
    let challenge =
        SolanaOutbox::approval_challenge(&original, "beef", "http://localhost/ceremony", 5_000)
            .unwrap();
    outbox.write_approval_challenge(&entry, &challenge).unwrap();

    // Advance past the staged window so the restage produces a real successor.
    height.store(
        original.last_valid_block_height + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    let replacement = engine
        .restage_expired("wallet", &original.id, &broker.child_pubkey(), 10_000)
        .await
        .unwrap();
    assert_ne!(replacement.id, original.id);

    let successor = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &replacement.id,
            bloom_solana_tx::outbox::SolanaOutboxState::Pending,
        )
        .unwrap();
    let migrated = std::fs::read(
        successor
            .dir
            .join(bloom_solana_tx::outbox::APPROVAL_CHALLENGE_FILE),
    )
    .expect("the successor must carry the approval the owner already granted");
    let migrated: serde_json::Value = serde_json::from_slice(&migrated).unwrap();
    assert_eq!(migrated["approval_id"], "beef");
    assert_eq!(migrated["ceremony_url"], "http://localhost/ceremony");
    assert_eq!(migrated["expiry_ms"], 5_000);
    // The copy is rebuilt for the entry it now sits in. A verbatim copy names
    // the retired id and a retry path that no longer exists, and fails the
    // `action_id` check owners run before opening the ceremony.
    assert_eq!(migrated["action_id"], replacement.id.as_str());
    assert!(
        migrated["retry_path"]
            .as_str()
            .unwrap()
            .contains(&format!("/pending/{}/", replacement.id))
    );
}

/// A node whose blockhash follows `height`, an outbox, a Broker, and an engine
/// wired to all three, for the restage tests below.
async fn restage_fixture() -> (
    Arc<std::sync::atomic::AtomicU64>,
    tempfile::TempDir,
    SolanaOutbox,
    Arc<BrokerFixture>,
    Arc<SolanaTransferEngine>,
) {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let endpoint = spawn_node_with_controls(
        height.clone(),
        false,
        false,
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine = Arc::new(SolanaTransferEngine::new(
        outbox.clone(),
        client(&endpoint),
        signer,
        "solana-devnet",
    ));
    (height, dir, outbox, broker, engine)
}

/// Stage a transfer and take it to an approval the owner has been asked for,
/// with the challenge published the way the confirm path publishes it.
async fn stage_awaiting_approval(
    engine: &SolanaTransferEngine,
    outbox: &SolanaOutbox,
    broker: &BrokerFixture,
) -> (bloom_solana_tx::types::StagedSolanaTransfer, Digest32) {
    let staged = stage_for_retry(engine, broker).await;
    let approval = approval_required(
        engine
            .sign(
                "wallet",
                &staged.id,
                &broker.child_pubkey(),
                None,
                None,
                1_100,
            )
            .await
            .unwrap(),
    );
    let challenge = SolanaOutbox::approval_challenge(
        &staged,
        approval.as_str(),
        "http://localhost/ceremony",
        900_000,
    )
    .unwrap();
    outbox
        .write_approval_challenge(&pending(outbox, &staged.id), &challenge)
        .unwrap();
    (staged, approval)
}

fn challenge_of(entry: &bloom_solana_tx::outbox::SolanaOutboxEntry) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(
            entry
                .dir
                .join(bloom_solana_tx::outbox::APPROVAL_CHALLENGE_FILE),
        )
        .unwrap(),
    )
    .unwrap()
}

/// The confirm path refreshes an approved transfer onto the newest blockhash
/// before signing. When the cluster has moved on, the transfer changes id: the
/// successor must carry the approval and its attempt, the predecessor must be
/// retired with advice saying why, and the approval must sign the successor.
#[tokio::test]
async fn an_approved_refresh_hands_the_approval_to_its_successor() {
    let (height, _dir, outbox, broker, engine) = restage_fixture().await;
    let (staged, approval) = stage_awaiting_approval(&engine, &outbox, &broker).await;
    let fee_payer = broker.child_pubkey();

    // A newer blockhash, while the staged one is still valid.
    height.store(2, std::sync::atomic::Ordering::SeqCst);
    assert!(2 <= staged.last_valid_block_height);
    let successor = engine
        .restage_approved("wallet", &staged.id, &fee_payer, 1_300)
        .await
        .unwrap();
    assert_ne!(successor.id, staged.id);

    let retired = outbox.read("wallet", "solana-devnet", &staged.id).unwrap();
    assert_eq!(retired.state, SolanaOutboxState::Failed);
    assert_eq!(retired.staged.status, SolanaTxStatus::Expired);
    let advice: serde_json::Value =
        serde_json::from_slice(&std::fs::read(retired.dir.join("restage_advice.json")).unwrap())
            .unwrap();
    assert_eq!(advice["reason"], "approval_refresh");
    assert_eq!(advice["replacement_id"], successor.id.as_str());

    let live = pending(&outbox, &successor.id);
    let challenge = challenge_of(&live);
    assert_eq!(challenge["approval_id"], approval.as_str());
    assert_eq!(challenge["action_id"], successor.id.as_str());
    let attempt = outbox
        .approval_attempt(&live)
        .unwrap()
        .expect("the attempt travels with the approval");
    assert_eq!((attempt.attempt, attempt.issued_at_ms), (0, 1_100));

    let signed = engine
        .sign(
            "wallet",
            &successor.id,
            &fee_payer,
            None,
            Some(approval),
            1_400,
        )
        .await
        .unwrap();
    assert!(matches!(
        signed,
        bloom_solana_tx::signing::SolanaSignOutcome::Signed { .. }
    ));
    assert_eq!(broker.conflicts(), 0);
}

/// Two confirms of one transfer: the first is signing when the second
/// refreshes it. The refresh must wait for the signature and then leave the
/// signed entry alone. Retiring it mid-sign, or after, deletes the one
/// signature the approval allows and strands the transfer.
#[tokio::test]
async fn an_approved_refresh_waits_for_an_in_flight_signature() {
    let (height, _dir, outbox, broker, engine) = restage_fixture().await;
    let (staged, approval) = stage_awaiting_approval(&engine, &outbox, &broker).await;
    let fee_payer = broker.child_pubkey();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *broker.sign_gate.lock().unwrap() = Some(gate.clone());

    let signing = tokio::spawn({
        let engine = engine.clone();
        let id = staged.id.clone();
        async move {
            engine
                .sign("wallet", &id, &fee_payer, None, Some(approval), 1_200)
                .await
        }
    });
    broker.sign_reached.notified().await;

    height.store(2, std::sync::atomic::Ordering::SeqCst);
    let mut refresh = tokio::spawn({
        let engine = engine.clone();
        let id = staged.id.clone();
        async move {
            engine
                .restage_approved("wallet", &id, &fee_payer, 1_300)
                .await
        }
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), &mut refresh)
            .await
            .is_err(),
        "a refresh must not run while the transfer is being signed"
    );

    gate.add_permits(1);
    assert!(matches!(
        signing.await.unwrap().unwrap(),
        bloom_solana_tx::signing::SolanaSignOutcome::Signed { .. }
    ));
    let refreshed = refresh.await.unwrap().unwrap();
    assert_eq!(refreshed.id, staged.id, "a signed transfer is not replaced");
    assert!(
        outbox
            .recorded_signature(&pending(&outbox, &staged.id))
            .unwrap()
            .is_some(),
        "the signature stays with the entry that will broadcast it"
    );
}

/// A second confirm that read the transfer before the first retired it goes on
/// to restage the retired id. It must find the same successor and leave that
/// successor's newer approval state as it is.
#[tokio::test]
async fn restaging_a_retired_id_again_leaves_its_successor_alone() {
    let (height, _dir, outbox, broker, engine) = restage_fixture().await;
    let (staged, _) = stage_awaiting_approval(&engine, &outbox, &broker).await;
    let fee_payer = broker.child_pubkey();
    height.store(2, std::sync::atomic::Ordering::SeqCst);
    let successor = engine
        .restage_approved("wallet", &staged.id, &fee_payer, 1_300)
        .await
        .unwrap();

    // The successor moves on under its own lineage.
    let live = pending(&outbox, &successor.id);
    outbox
        .write_approval_attempt(
            &live,
            &bloom_solana_tx::outbox::ApprovalAttempt {
                attempt: 3,
                issued_at_ms: 1_350,
                expires_at_ms: 900_000,
            },
        )
        .unwrap();
    let newer = SolanaOutbox::approval_challenge(&successor, "newer", "http://x", 1).unwrap();
    outbox.write_approval_challenge(&live, &newer).unwrap();

    let again = engine
        .restage_approved("wallet", &staged.id, &fee_payer, 1_400)
        .await
        .unwrap();
    assert_eq!(again.id, successor.id);
    let live = pending(&outbox, &successor.id);
    assert_eq!(outbox.approval_attempt(&live).unwrap().unwrap().attempt, 3);
    assert_eq!(challenge_of(&live)["approval_id"], "newer");
}

/// Fixtures for the approval-retry tests: a node, an outbox, a Broker that
/// enforces operation-id stability, and an engine wired to all three.
async fn retry_fixture() -> (
    tempfile::TempDir,
    SolanaOutbox,
    Arc<BrokerFixture>,
    SolanaTransferEngine,
) {
    let endpoint = spawn_node().await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    (dir, outbox, broker, engine)
}

async fn stage_for_retry(
    engine: &SolanaTransferEngine,
    broker: &BrokerFixture,
) -> bloom_solana_tx::types::StagedSolanaTransfer {
    let destination = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32])
        .verifying_key()
        .to_bytes();
    engine
        .stage(
            "wallet",
            &broker.child_pubkey(),
            Default::default(),
            &destination,
            1_000_000,
            1_000,
        )
        .await
        .unwrap()
}

fn pending(outbox: &SolanaOutbox, id: &str) -> bloom_solana_tx::outbox::SolanaOutboxEntry {
    outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            id,
            bloom_solana_tx::outbox::SolanaOutboxState::Pending,
        )
        .unwrap()
}

fn approval_required(outcome: bloom_solana_tx::signing::SolanaSignOutcome) -> Digest32 {
    match outcome {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    }
}

/// bloom#236: the operation id is derived from the transfer's stable facts,
/// but the terms hashed alongside it carried a freshly computed expiry. A
/// second confirm of the same transfer therefore presented the same id with
/// different terms and was refused permanently.
#[tokio::test]
async fn confirming_the_same_transfer_twice_reaches_the_same_ceremony() {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();

    let first = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
            .await
            .unwrap(),
    );
    // Time moves between the two confirms; that must not change the terms.
    let second = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 900_000)
            .await
            .unwrap(),
    );

    assert_eq!(
        broker.conflicts(),
        0,
        "a retry of one attempt must not look like a different action"
    );
    assert_eq!(
        first, second,
        "both confirms must reach the one ceremony the owner is being asked about"
    );
    let attempt = outbox
        .approval_attempt(&pending(&outbox, &staged.id))
        .unwrap()
        .expect("the attempt is durable");
    assert_eq!(attempt.attempt, 0, "this is still the first attempt");
    assert_eq!(attempt.issued_at_ms, 1_100);
}

/// bloom#237: a definite refusal used to leave the dead approval in place, so
/// every later confirm replayed an id the Broker would never accept again.
#[tokio::test]
async fn a_definitely_dead_approval_is_retired_and_the_next_confirm_starts_over() {
    a_dead_approval_is_retired(ProtocolErrorCode::ApprovalExpired).await;
}

/// A budget refusal is as final as an expired approval: the Broker released
/// the reservation before anything was signed, and the approval can never
/// sign this intent. Keeping it replays the refusal on every confirm.
#[tokio::test]
async fn a_budget_refusal_retires_the_approval_and_the_next_confirm_starts_over() {
    a_dead_approval_is_retired(ProtocolErrorCode::LimitExceededSignatures).await;
}

async fn a_dead_approval_is_retired(code: ProtocolErrorCode) {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();

    let approval = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
            .await
            .unwrap(),
    );
    let entry = pending(&outbox, &staged.id);
    outbox
        .write_approval_challenge(&entry, br#"{"approval_id":"stale"}"#)
        .unwrap();

    broker.fail_next_signature(code, "refused");
    let error = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval.clone()),
            1_200,
        )
        .await
        .expect_err("a dead approval cannot sign");
    assert!(error.to_string().contains(code.as_str()), "{error}");

    let entry = pending(&outbox, &staged.id);
    assert_eq!(
        outbox
            .approval_attempt(&entry)
            .unwrap()
            .expect("the attempt is remembered so its successor gets a new identity")
            .expires_at_ms,
        0,
        "a dead approval must not be resumed"
    );
    assert!(
        !entry
            .dir
            .join(bloom_solana_tx::outbox::APPROVAL_CHALLENGE_FILE)
            .exists(),
        "a dead ceremony must stop being advertised"
    );

    // The next confirm is a genuinely new attempt: it must reach a ceremony,
    // not collide with the operation id the dead approval used.
    let replacement = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_300)
            .await
            .unwrap(),
    );
    assert_eq!(
        broker.conflicts(),
        0,
        "a new lineage must not reuse the dead operation id"
    );
    assert_ne!(
        replacement, approval,
        "the replacement must be a different approval"
    );
    assert_eq!(
        outbox
            .approval_attempt(&pending(&outbox, &staged.id))
            .unwrap()
            .expect("a new attempt is recorded")
            .attempt,
        1
    );
    assert_eq!(broker.prepared_ids().len(), 2);
}

/// An outcome that may have produced a signature must keep its approval, so
/// reconciliation still has one identity to resolve against.
#[tokio::test]
async fn an_ambiguous_signing_outcome_keeps_the_approval() {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();

    let approval = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
            .await
            .unwrap(),
    );
    let entry = pending(&outbox, &staged.id);
    outbox
        .write_approval_challenge(&entry, br#"{"approval_id":"live"}"#)
        .unwrap();

    broker.fail_next_signature(
        ProtocolErrorCode::AmbiguousProviderEffect,
        "provider outcome is unknown",
    );
    let error = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval),
            1_200,
        )
        .await
        .expect_err("an unknown outcome is not a signature");
    assert!(
        error.to_string().contains("AMBIGUOUS_PROVIDER_EFFECT"),
        "{error}"
    );

    let entry = pending(&outbox, &staged.id);
    assert!(
        outbox.approval_attempt(&entry).unwrap().is_some(),
        "an unknown outcome must not discard the authority it may already have used"
    );
    assert!(
        entry
            .dir
            .join(bloom_solana_tx::outbox::APPROVAL_CHALLENGE_FILE)
            .exists()
    );
}

/// A transient fault is not a decision either: the approval survives it and
/// the retry reaches the same ceremony.
#[tokio::test]
async fn a_transient_broker_fault_keeps_the_approval_and_the_retry_succeeds() {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();

    let approval = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
            .await
            .unwrap(),
    );
    broker.fail_next_signature(ProtocolErrorCode::ServiceUnavailable, "Broker restarting");
    engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval.clone()),
            1_200,
        )
        .await
        .expect_err("a restarting Broker did not sign");
    assert!(
        outbox
            .approval_attempt(&pending(&outbox, &staged.id))
            .unwrap()
            .is_some()
    );

    let signed = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval),
            1_300,
        )
        .await
        .unwrap();
    assert!(matches!(
        signed,
        bloom_solana_tx::signing::SolanaSignOutcome::Signed { .. }
    ));
    assert_eq!(broker.conflicts(), 0);
    assert!(
        outbox
            .approval_attempt(&pending(&outbox, &staged.id))
            .unwrap()
            .is_none(),
        "a completed signature ends the attempt"
    );
}

/// A dead approval followed by a restage: the successor carries the same
/// economic intent, so it rebuilds the same approval operation id. Losing the
/// attempt counter on the way across makes that id collide with the approval
/// that just died.
#[tokio::test]
async fn a_dead_approval_survives_a_restage_and_the_successor_recovers() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let endpoint = spawn_node_with_controls(
        height.clone(),
        false,
        false,
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();

    let approval = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
            .await
            .unwrap(),
    );
    outbox
        .write_approval_challenge(&pending(&outbox, &staged.id), br#"{"approval_id":"stale"}"#)
        .unwrap();
    broker.fail_next_signature(ProtocolErrorCode::ApprovalExpired, "expired");
    engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval),
            1_200,
        )
        .await
        .expect_err("an expired approval cannot sign");

    height.store(
        staged.last_valid_block_height + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    let successor = engine
        .restage_expired("wallet", &staged.id, &fee_payer, 1_300)
        .await
        .unwrap();
    assert_ne!(successor.id, staged.id);

    let result = engine
        .sign("wallet", &successor.id, &fee_payer, None, None, 1_400)
        .await;
    assert!(
        result.is_ok(),
        "a dead approval followed by a restage must still recover: {result:?}"
    );
    assert_eq!(
        broker.conflicts(),
        0,
        "the successor must not rebuild the dead approval's operation id"
    );
    assert_eq!(
        outbox
            .approval_attempt(&pending(&outbox, &successor.id))
            .unwrap()
            .expect("the successor carries the lineage")
            .attempt,
        1
    );
}

/// The same, with the predecessor swept into `failed` before it is restaged.
/// Retiring an entry must not take its identity lineage with it.
#[tokio::test]
async fn a_swept_expired_transfer_keeps_its_approval_lineage() {
    let height = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let endpoint = spawn_node_with_controls(
        height.clone(),
        false,
        false,
        Arc::new(Mutex::new(Vec::new())),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let broker = Arc::new(BrokerFixture::new());
    let signer =
        SolanaTransferSigner::from_catalog(MachineBrokerClient::new(broker.clone()), &catalog())
            .unwrap();
    let engine =
        SolanaTransferEngine::new(outbox.clone(), client(&endpoint), signer, "solana-devnet");
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();

    let approval = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
            .await
            .unwrap(),
    );
    broker.fail_next_signature(ProtocolErrorCode::ApprovalRevoked, "revoked");
    engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval),
            1_200,
        )
        .await
        .expect_err("a revoked approval cannot sign");

    // The sweep retires the stale entry into `failed` before anyone restages.
    height.store(
        staged.last_valid_block_height + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    let mut heights = std::collections::HashMap::new();
    heights.insert(
        "solana-devnet".to_string(),
        staged.last_valid_block_height + 1,
    );
    outbox.sweep_expired(2_000, &heights).unwrap();

    let successor = engine
        .restage_expired("wallet", &staged.id, &fee_payer, 2_100)
        .await
        .unwrap();
    let result = engine
        .sign("wallet", &successor.id, &fee_payer, None, None, 2_200)
        .await;
    assert!(
        result.is_ok(),
        "a swept transfer must not lose the identity of its dead approval: {result:?}"
    );
    assert_eq!(broker.conflicts(), 0);
}
