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
    prepare_calls: std::sync::atomic::AtomicUsize,
    block_prepares: std::sync::atomic::AtomicBool,
    prepare_release: tokio::sync::Semaphore,
    /// Whether the owner has completed the ceremony. A normalized confirm
    /// refuses to finalize until the Broker says the approval is ACTIVE, so
    /// tests drive that explicitly instead of inferring it from holding an id.
    approval_is_active: std::sync::atomic::AtomicBool,
    sign_calls: std::sync::atomic::AtomicUsize,
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
            prepare_calls: std::sync::atomic::AtomicUsize::new(0),
            block_prepares: std::sync::atomic::AtomicBool::new(false),
            approval_is_active: std::sync::atomic::AtomicBool::new(true),
            sign_calls: std::sync::atomic::AtomicUsize::new(0),
            prepare_release: tokio::sync::Semaphore::new(0),
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
    /// Whether the fixture reports the owner's approval as ACTIVE.
    fn set_approval_active(&self, active: bool) {
        self.approval_is_active
            .store(active, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many ceremonies were prepared.
    fn prepare_calls(&self) -> usize {
        self.prepare_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many signing requests actually reached the Broker.
    fn sign_calls(&self) -> usize {
        self.sign_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn conflicts(&self) -> u32 {
        *self.conflicts.lock().unwrap()
    }

    fn prepared_ids(&self) -> Vec<Digest32> {
        self.prepared_ids.lock().unwrap().clone()
    }

    fn fail_next_signature(&self, code: ProtocolErrorCode, message: &str) {
        *self.next_sign_error.lock().unwrap() = Some((code, message.to_owned()));
    }

    fn block_approval_prepares(&self) {
        self.block_prepares
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn release_approval_prepares(&self) {
        self.block_prepares
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.prepare_release.add_permits(1);
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
                    }))
                }
                MachineBrokerRequest::SigningSign(sign_request) => {
                    self.sign_calls
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if let Some((code, message)) = self.next_sign_error.lock().unwrap().take() {
                        return Err(ProtocolError::new(code, message));
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
                    self.prepare_calls
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if self
                        .block_prepares
                        .load(std::sync::atomic::Ordering::SeqCst)
                    {
                        self.prepare_release
                            .acquire()
                            .await
                            .expect("test semaphore remains open")
                            .forget();
                    }
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
                // A blockhash-normalized confirm asks what state the approval
                // is really in before it finalizes anything. The fixture
                // answers ACTIVE once the test has said the owner approved,
                // and AWAITING_CEREMONY until then.
                MachineBrokerRequest::SealedApprovalStatus(request) => {
                    let active = self
                        .approval_is_active
                        .load(std::sync::atomic::Ordering::SeqCst);
                    Ok(MachineBrokerResponse::SealedApprovalStatus(
                        bloom_broker_api::ApprovalPublicStatus {
                            approval_id: request.id,
                            wallet_id: Token::new("wallet").unwrap(),
                            state: if active {
                                bloom_broker_api::ApprovalLifecycleState::Active
                            } else {
                                bloom_broker_api::ApprovalLifecycleState::AwaitingCeremony
                            },
                            effective_claim_assurance: None,
                            ceremony_url: Some("http://localhost:18734/ceremony".into()),
                            ceremony_expires_at_ms: None,
                        },
                    ))
                }
                MachineBrokerRequest::OperationStatus(request) => {
                    Ok(MachineBrokerResponse::OperationStatus(
                        bloom_broker_api::OperationPublicStatus {
                            operation_id: request.operation_id,
                            operation_digest: digest(93),
                            state: bloom_broker_api::OperationState::Reserved,
                            result: None,
                            error: None,
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
    // Five minutes, not one blockhash: a newly staged native transfer is
    // blockhash-normalized, so its approval outlives the staged blockhash.
    assert_eq!(broker.last_prepared_expiry(), 301_100);
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
    // A blockhash-normalized entry is exactly the case that must NOT refuse
    // here: the staged blockhash going stale is the situation the mode exists
    // for, and the approval still stands. It proceeds to the ceremony.
    let past_expiry = engine
        .sign(
            "wallet",
            &unsigned.id,
            &broker.child_pubkey(),
            None,
            None,
            1_100,
        )
        .await
        .unwrap();
    assert!(matches!(
        past_expiry,
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { .. }
    ));

    // A legacy unmarked entry keeps the old contract: its message can never be
    // replaced, so a stale blockhash is terminal and it must be restaged.
    let mut legacy = unsigned.clone();
    legacy.id = "sol-00000000000000000000000000000001".into();
    legacy.message_normalization = None;
    outbox
        .write_pending(&legacy, "legacy unmarked entry\n")
        .unwrap();
    let sign_error = engine
        .sign(
            "wallet",
            &legacy.id,
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
    outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &signed.id,
            SolanaOutboxState::Pending,
        )
        .expect("expired signed transfer remains pending for explicit restaging");
    assert!(
        !requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| { r["method"] == "sendTransaction" })
    );
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
    // This case covers the pre-existing unmarked contract.
    let original = demote_to_legacy(&outbox, &original);

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
/// An Exact approval cannot authorize the replacement message, but the
/// attempt counter must survive so the successor does not reuse the dead
/// predecessor's approval identity.
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

/// Rewrite a staged entry as a legacy unmarked one.
///
/// `stage` now marks new native transfers as blockhash-normalized, which
/// deliberately changes expiry, sweep and dead-approval behaviour. The
/// pre-existing contract still governs every entry staged before this feature,
/// so the tests that cover it demote their entry first and keep asserting it.
fn demote_to_legacy(
    outbox: &SolanaOutbox,
    staged: &bloom_solana_tx::types::StagedSolanaTransfer,
) -> bloom_solana_tx::types::StagedSolanaTransfer {
    let entry = pending(outbox, &staged.id);
    let mut legacy = entry.staged.clone();
    legacy.message_normalization = None;
    outbox
        .rewrite_intent(&bloom_solana_tx::outbox::SolanaOutboxEntry {
            state: entry.state,
            staged: legacy.clone(),
            dir: entry.dir,
        })
        .unwrap();
    legacy
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
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
    let fee_payer = broker.child_pubkey();

    let first = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
            .await
            .unwrap(),
    );
    // Time moves between the two confirms while the attempt's window is
    // still live; that must not change the terms. (A lapsed window is a
    // different situation: it cannot be resumed, so the next confirm is a
    // new attempt with a new identity — covered by the dead-approval tests.)
    let second = approval_required(
        engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 30_000)
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

#[tokio::test]
async fn overlapping_confirms_are_serialized_through_approval_preparation() {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
    let engine = Arc::new(engine);
    let fee_payer = broker.child_pubkey();
    broker.block_approval_prepares();

    let first_engine = engine.clone();
    let first_id = staged.id.clone();
    let first = tokio::spawn(async move {
        first_engine
            .sign("wallet", &first_id, &fee_payer, None, None, 1_100)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while broker
            .prepare_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first confirm must reach approval preparation");

    let second_engine = engine.clone();
    let second_id = staged.id.clone();
    let second = tokio::spawn(async move {
        second_engine
            .sign("wallet", &second_id, &fee_payer, None, None, 2_100)
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while broker
                .prepare_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                < 2
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_err(),
        "a second confirm must not enter Broker while the first owns the transfer lock"
    );

    broker.release_approval_prepares();
    let first = approval_required(first.await.unwrap().unwrap());
    let second = approval_required(second.await.unwrap().unwrap());
    assert_eq!(first, second);
    assert_eq!(broker.conflicts(), 0);
}

/// bloom#237: a definite refusal used to leave the dead approval in place, so
/// every later confirm replayed an id the Broker would never accept again.
#[tokio::test]
async fn a_definitely_dead_approval_is_retired_and_the_next_confirm_starts_over() {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
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

    broker.fail_next_signature(
        ProtocolErrorCode::ApprovalExpired,
        "sealed approval is past its expiry",
    );
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
        .expect_err("an expired approval cannot sign");
    assert!(error.to_string().contains("APPROVAL_EXPIRED"), "{error}");

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
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
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
            Some(approval.clone()),
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
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
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
            Some(approval.clone()),
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

/// A dead approval followed by a restage: the Exact approval identity hashes
/// the full replacement message, so the successor's identity is distinct
/// without carrying the predecessor's attempt counter across messages.
#[tokio::test]
async fn a_dead_approval_survives_a_restage_with_a_fresh_identity() {
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
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
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
            Some(approval.clone()),
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
    let fresh = approval_required(result.unwrap());
    assert_ne!(
        fresh, approval,
        "the successor must reach a fresh approval, not the dead one"
    );
    assert_eq!(
        outbox
            .approval_attempt(&pending(&outbox, &successor.id))
            .unwrap()
            .expect("the successor records its own first attempt")
            .attempt,
        0,
        "no attempt counter crosses messages"
    );
}

/// A swept transfer actually retires (one sweep, Failed/Expired state) and
/// restages onto a fresh Exact approval.
#[tokio::test]
async fn a_swept_transfer_fails_over_and_restages_onto_a_fresh_approval() {
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
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
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
            Some(approval.clone()),
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
    assert_eq!(
        outbox.sweep_expired(staged.expires_ms, &heights).unwrap(),
        1,
        "exactly the stale entry must be swept at its own deadline"
    );
    let retired = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Failed,
        )
        .expect("the sweeper must have retired the stale entry");
    assert_eq!(retired.staged.status, SolanaTxStatus::Expired);

    let successor = engine
        .restage_expired("wallet", &staged.id, &fee_payer, 2_100)
        .await
        .unwrap();
    let fresh = approval_required(
        engine
            .sign("wallet", &successor.id, &fee_payer, None, None, 2_200)
            .await
            .unwrap(),
    );
    assert_ne!(
        fresh, approval,
        "the successor must reach a fresh approval, not the swept one's"
    );
    assert_eq!(broker.conflicts(), 0);
}

/// Repeated restage of the same predecessor must never disturb a successor
/// that has already prepared its own live attempt, and must keep returning
/// that same successor (the reservation is idempotent) even after the
/// successor's attempt ends at dispatch.
#[tokio::test]
async fn repeated_restage_cannot_clobber_the_successor() {
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
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
    let fee_payer = broker.child_pubkey();

    height.store(
        staged.last_valid_block_height + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    let successor = engine
        .restage_expired("wallet", &staged.id, &fee_payer, 1_300)
        .await
        .unwrap();

    // The successor prepares its own live attempt.
    let approval = approval_required(
        engine
            .sign("wallet", &successor.id, &fee_payer, None, None, 1_400)
            .await
            .unwrap(),
    );
    let recorded = outbox
        .approval_attempt(&pending(&outbox, &successor.id))
        .unwrap()
        .expect("the successor has a live attempt");

    // A repeated restage of the predecessor returns the same successor and
    // must not overwrite the successor's live attempt terms.
    let again = engine
        .restage_expired("wallet", &staged.id, &fee_payer, 1_500)
        .await
        .unwrap();
    assert_eq!(again.id, successor.id);
    assert_eq!(
        outbox
            .approval_attempt(&pending(&outbox, &successor.id))
            .unwrap()
            .expect("the live attempt must survive a repeated restage"),
        recorded,
        "a repeated restage must not rewrite the successor's attempt terms"
    );

    // Complete the signature: the attempt ends. A further restage still
    // returns the same successor and does not resurrect any attempt state.
    engine
        .sign(
            "wallet",
            &successor.id,
            &fee_payer,
            None,
            Some(approval.clone()),
            1_600,
        )
        .await
        .unwrap();
    let third = engine
        .restage_expired("wallet", &staged.id, &fee_payer, 1_700)
        .await
        .unwrap();
    assert_eq!(third.id, successor.id);
    assert!(
        outbox
            .approval_attempt(&pending(&outbox, &successor.id))
            .is_err()
            || outbox
                .approval_attempt(&pending(&outbox, &successor.id))
                .unwrap()
                .is_none(),
        "no attempt state may reappear after the successor completed"
    );
    assert_eq!(broker.conflicts(), 0);
}

/// Corrupt persisted approval-attempt state must fail closed: no Broker
/// preparation may run on top of terms the host cannot read.
#[tokio::test]
async fn corrupt_approval_attempt_state_fails_closed() {
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
    // This case covers the pre-existing unmarked contract, which `stage` no
    // longer produces for native transfers.
    let staged = demote_to_legacy(&outbox, &staged);
    let fee_payer = broker.child_pubkey();

    let entry = pending(&outbox, &staged.id);
    std::fs::write(entry.dir.join(".approval_attempt"), b"{not json").unwrap();

    let error = engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 1_100)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("corrupt"),
        "corrupt attempt state must be reported, got: {error}"
    );
    assert!(
        broker.prepared_ids().is_empty(),
        "no Broker preparation may run against unreadable terms"
    );
}

// ---------------------------------------------------------------------------
// Blockhash-normalized native transfers
//
// A newly staged native transfer commits its approval to the message with the
// 32 recent-blockhash bytes zeroed, so the owner's ceremony may finish after
// the staged blockhash has died. These cases cover what that changes on the
// Machine side: the approval outlives the template, the blockhash is replaced
// exactly once immediately before signing, the committed attempt is durable,
// and nothing may quietly produce a second message for one intent.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_newly_staged_native_transfer_is_normalized_and_legacy_entries_are_not() {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    assert_eq!(
        staged.message_normalization,
        Some(bloom_broker_api::ExactMessageNormalization::SolanaNativeTransferBlockhashV1),
        "a new native transfer is staged blockhash-normalized"
    );
    // The marker is persisted, so a restart still knows how this entry's
    // approval matches.
    assert_eq!(
        pending(&outbox, &staged.id).staged.message_normalization,
        staged.message_normalization
    );
    // An entry staged before the feature has no marker and must not acquire
    // one: its standing approval pinned raw bytes.
    let legacy = demote_to_legacy(&outbox, &staged);
    assert_eq!(legacy.message_normalization, None);
    assert_eq!(
        pending(&outbox, &staged.id).staged.message_normalization,
        None
    );
}

#[tokio::test]
async fn a_normalized_approval_lasts_five_minutes_and_a_retry_reuses_its_window() {
    let (_dir, _outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();

    engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 1_000)
        .await
        .unwrap();
    assert_eq!(
        broker.last_prepared_expiry(),
        301_000,
        "five minutes, not one blockhash"
    );

    // Polling must not extend the window. A second confirm inside it presents
    // the Broker the same terms and so reaches the same standing ceremony.
    engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 120_000)
        .await
        .unwrap();
    assert_eq!(broker.last_prepared_expiry(), 301_000);
    assert_eq!(broker.conflicts(), 0);
}

#[tokio::test]
async fn an_unapproved_ceremony_cannot_be_signed_by_presenting_its_id() {
    let (_dir, _outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();
    let approval = match engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 1_000)
        .await
        .unwrap()
    {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };

    // The owner has not completed the ceremony. Holding the id is not consent:
    // the Broker still reports AWAITING_CEREMONY and nothing may be submitted.
    broker.set_approval_active(false);
    let outcome = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval.clone()),
            2_000,
        )
        .await
        .unwrap();
    assert!(
        matches!(
            outcome,
            bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { .. }
        ),
        "an unapproved ceremony must be handed back, not signed"
    );
    assert_eq!(broker.sign_calls(), 0, "nothing was submitted for signing");
}

/// A stub node whose recent blockhash and fee quote can be moved between
/// calls, so a confirm can be driven across a genuine blockhash rotation.
async fn spawn_rotating_node(
    blockhash: Arc<std::sync::Mutex<[u8; 32]>>,
    fee: Arc<std::sync::atomic::AtomicU64>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let blockhash = blockhash.clone();
            let fee = fee.clone();
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
                        let current = bs58::encode(*blockhash.lock().unwrap()).into_string();
                        format!(
                            r#"{{"context":{{"slot":1}},"value":{{"blockhash":"{current}","lastValidBlockHeight":100}}}}"#
                        )
                    }
                    "getBlockHeight" => "1".to_string(),
                    "getFeeForMessage" => format!(
                        r#"{{"context":{{"slot":1}},"value":{}}}"#,
                        fee.load(std::sync::atomic::Ordering::SeqCst)
                    ),
                    "simulateTransaction" => r#"{"context":{"slot":1},"value":{"err":null,"logs":[],"unitsConsumed":150}}"#.to_string(),
                    "sendTransaction" => {
                        serde_json::to_string(&submitted_transaction_signature(&request_json))
                            .unwrap()
                    }
                    _ => "null".to_string(),
                };
                let payload = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

async fn rotating_fixture(
    blockhash: Arc<std::sync::Mutex<[u8; 32]>>,
    fee: Arc<std::sync::atomic::AtomicU64>,
) -> (
    tempfile::TempDir,
    SolanaOutbox,
    Arc<BrokerFixture>,
    SolanaTransferEngine,
) {
    let endpoint = spawn_rotating_node(blockhash, fee).await;
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

/// The behaviour the whole feature exists for, on the Machine side: the staged
/// blockhash is replaced once, immediately before signing, under the same
/// entry and the same approval — and the snapshot records exactly what was
/// sent.
#[tokio::test]
async fn a_confirm_replaces_the_blockhash_once_and_records_what_it_sent() {
    let blockhash = Arc::new(std::sync::Mutex::new([0x42u8; 32]));
    let fee = Arc::new(std::sync::atomic::AtomicU64::new(5_000));
    let (_dir, outbox, broker, engine) = rotating_fixture(blockhash.clone(), fee).await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();

    let approval = match engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 1_000)
        .await
        .unwrap()
    {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };

    // The cluster moves on while the owner is still at the passkey prompt.
    *blockhash.lock().unwrap() = [0x5au8; 32];

    let signed = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval.clone()),
            200_000,
        )
        .await
        .unwrap();
    assert!(matches!(
        signed,
        bloom_solana_tx::signing::SolanaSignOutcome::Signed { .. }
    ));

    // Same entry, one approval, one prepare.
    assert_eq!(broker.prepare_calls(), 1);
    assert_eq!(broker.sign_calls(), 1);

    let entry = pending(&outbox, &staged.id);
    let snapshot = outbox
        .signing_attempt(&entry)
        .unwrap()
        .expect("the confirm committed to a message");
    assert_eq!(
        snapshot.finalized_staged.blockhash,
        bs58::encode([0x5au8; 32]).into_string(),
        "the signed message carries the refreshed blockhash"
    );
    assert_ne!(snapshot.finalized_staged.message_b64, staged.message_b64);
    // The projection was restored to what was actually signed.
    assert_eq!(
        entry.staged.message_b64,
        snapshot.finalized_staged.message_b64
    );
    // And the request in the snapshot signs exactly those bytes.
    let bloom_broker_api::SigningPayloads::Single { payload } = &snapshot.request.payloads else {
        panic!("a native transfer is never a batch");
    };
    assert_eq!(
        {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(payload.decode())
        },
        snapshot.finalized_staged.message_b64
    );
}

/// A committed attempt is replayed, never rebuilt. Rebuilding could pick a
/// newer blockhash and buy a second signature under one approval.
#[tokio::test]
async fn a_lost_response_replays_the_persisted_request_rather_than_refreshing() {
    let blockhash = Arc::new(std::sync::Mutex::new([0x42u8; 32]));
    let fee = Arc::new(std::sync::atomic::AtomicU64::new(5_000));
    let (_dir, outbox, broker, engine) = rotating_fixture(blockhash.clone(), fee).await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();
    let approval = match engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 1_000)
        .await
        .unwrap()
    {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    *blockhash.lock().unwrap() = [0x5au8; 32];

    // The Broker's response is lost after it has been dispatched.
    broker.fail_next_signature(
        bloom_broker_api::ProtocolErrorCode::ServiceUnavailable,
        "transport closed before the response arrived",
    );
    let error = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval.clone()),
            200_000,
        )
        .await
        .expect_err("a lost response is not a success");
    assert!(error.to_string().contains("transport closed"), "{error}");

    let committed = outbox
        .signing_attempt(&pending(&outbox, &staged.id))
        .unwrap()
        .expect("the attempt was persisted before it was sent");

    // The cluster moves again. The retry must ignore it entirely.
    *blockhash.lock().unwrap() = [0x77u8; 32];
    let signed = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval),
            260_000,
        )
        .await
        .unwrap();
    assert!(matches!(
        signed,
        bloom_solana_tx::signing::SolanaSignOutcome::Signed { .. }
    ));
    let after = outbox
        .signing_attempt(&pending(&outbox, &staged.id))
        .unwrap()
        .unwrap();
    assert_eq!(
        after.finalized_staged.message_b64, committed.finalized_staged.message_b64,
        "the replay signed the persisted message, not a freshly refreshed one"
    );
    assert_eq!(
        after.request.operation_id.as_str(),
        committed.request.operation_id.as_str(),
        "and under the same operation"
    );
    // One approval, one ceremony, throughout.
    assert_eq!(broker.prepare_calls(), 1);
}

/// A changed fee is a changed reviewed fact. Refuse before signing; never
/// silently approve a new quote.
#[tokio::test]
async fn a_requoted_fee_refuses_before_anything_is_committed() {
    let blockhash = Arc::new(std::sync::Mutex::new([0x42u8; 32]));
    let fee = Arc::new(std::sync::atomic::AtomicU64::new(5_000));
    let (_dir, outbox, broker, engine) = rotating_fixture(blockhash.clone(), fee.clone()).await;
    let staged = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();
    let approval = match engine
        .sign("wallet", &staged.id, &fee_payer, None, None, 1_000)
        .await
        .unwrap()
    {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    *blockhash.lock().unwrap() = [0x5au8; 32];
    fee.store(6_000, std::sync::atomic::Ordering::SeqCst);

    let error = engine
        .sign(
            "wallet",
            &staged.id,
            &fee_payer,
            None,
            Some(approval),
            200_000,
        )
        .await
        .expect_err("a re-quoted fee must refuse");
    assert!(error.to_string().contains("6000"), "{error}");
    assert_eq!(broker.sign_calls(), 0, "nothing was submitted");
    assert!(
        outbox
            .signing_attempt(&pending(&outbox, &staged.id))
            .unwrap()
            .is_none(),
        "and nothing was committed"
    );
}

/// Sweep and cancel must not discard an approval the owner has granted, nor an
/// attempt that may be in flight.
#[tokio::test]
async fn sweep_and_cancel_respect_a_normalized_entry() {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let marked = stage_for_retry(&engine, &broker).await;

    // Its template is long past its window, which is exactly the situation
    // this mode exists to survive.
    let mut heights = std::collections::HashMap::new();
    heights.insert(
        "solana-devnet".to_string(),
        marked.last_valid_block_height + 1,
    );
    assert_eq!(
        outbox
            .sweep_expired(marked.expires_ms + 1, &heights)
            .unwrap(),
        0,
        "a normalized entry's expired template must not retire its approval"
    );
    assert!(pending(&outbox, &marked.id).staged.lamports > 0);

    // Before anything is committed the owner may still cancel explicitly.
    outbox
        .cancel("wallet", "solana-devnet", &marked.id)
        .unwrap();

    // Once an attempt is committed, cancellation is refused: its outcome has
    // to be resolved first.
    let second = stage_for_retry(&engine, &broker).await;
    let fee_payer = broker.child_pubkey();
    let approval = match engine
        .sign("wallet", &second.id, &fee_payer, None, None, 1_000)
        .await
        .unwrap()
    {
        bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired { approval_id, .. } => {
            approval_id
        }
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    broker.fail_next_signature(
        bloom_broker_api::ProtocolErrorCode::ServiceUnavailable,
        "response lost",
    );
    let _ = engine
        .sign(
            "wallet",
            &second.id,
            &fee_payer,
            None,
            Some(approval),
            200_000,
        )
        .await;
    let cancel_error = outbox
        .cancel("wallet", "solana-devnet", &second.id)
        .expect_err("an unresolved signing attempt cannot be cancelled away");
    assert!(
        cancel_error.to_string().contains("committed to signing"),
        "{cancel_error}"
    );
    assert_eq!(
        outbox
            .sweep_expired(second.expires_ms + 1, &heights)
            .unwrap(),
        0,
        "nor swept"
    );
}

/// A snapshot that does not describe one coherent request is not "no attempt".
#[tokio::test]
async fn a_corrupt_signing_snapshot_fails_closed() {
    let (_dir, outbox, broker, engine) = retry_fixture().await;
    let staged = stage_for_retry(&engine, &broker).await;
    let entry = pending(&outbox, &staged.id);
    std::fs::write(entry.dir.join(".signing_attempt"), b"{\"schema\":\"nope\"}").unwrap();

    let error = outbox
        .signing_attempt(&entry)
        .expect_err("a corrupt snapshot is an error, never None");
    assert!(error.to_string().contains("signing snapshot"), "{error}");
    // And it still blocks the destructive paths.
    assert!(
        outbox
            .cancel("wallet", "solana-devnet", &staged.id)
            .is_err()
    );
    let confirm_error = engine
        .sign(
            "wallet",
            &staged.id,
            &broker.child_pubkey(),
            None,
            None,
            2_000,
        )
        .await
        .expect_err("a corrupt snapshot must not be confirmed past");
    assert!(
        confirm_error.to_string().contains("signing snapshot"),
        "{confirm_error}"
    );
}

/// Two intents with identical economics can refresh onto the same blockhash
/// and become the same bytes — and the same bytes are the same Ed25519
/// signature and the same transaction. One payment where the owner approved
/// two. Distinct off-chain intent ids do not change that, so the second
/// finalization must wait rather than commit.
#[tokio::test]
async fn two_intents_that_refresh_onto_one_message_do_not_both_commit() {
    let blockhash = Arc::new(std::sync::Mutex::new([0x42u8; 32]));
    let fee = Arc::new(std::sync::atomic::AtomicU64::new(5_000));
    let (_dir, outbox, broker, engine) = rotating_fixture(blockhash.clone(), fee).await;
    let fee_payer = broker.child_pubkey();

    // Different initial blockhashes, so stage's duplicate-message guard lets
    // both exist: two deliberate payments of the same amount.
    let first = stage_for_retry(&engine, &broker).await;
    *blockhash.lock().unwrap() = [0x43u8; 32];
    let second = stage_for_retry(&engine, &broker).await;
    assert_ne!(first.id, second.id);
    assert_ne!(first.message_b64, second.message_b64);

    let mut approvals = Vec::new();
    for staged in [&first, &second] {
        match engine
            .sign("wallet", &staged.id, &fee_payer, None, None, 1_000)
            .await
            .unwrap()
        {
            bloom_solana_tx::signing::SolanaSignOutcome::ApprovalRequired {
                approval_id, ..
            } => approvals.push(approval_id),
            other => panic!("expected ApprovalRequired, got {other:?}"),
        }
    }
    assert_ne!(approvals[0], approvals[1], "two intents, two approvals");

    // Both now refresh onto the same blockhash.
    *blockhash.lock().unwrap() = [0x5au8; 32];
    engine
        .sign(
            "wallet",
            &first.id,
            &fee_payer,
            None,
            Some(approvals[0].clone()),
            200_000,
        )
        .await
        .expect("the first intent owns these bytes");

    let clash = engine
        .sign(
            "wallet",
            &second.id,
            &fee_payer,
            None,
            Some(approvals[1].clone()),
            200_000,
        )
        .await
        .expect_err("the second must not sign the same message");
    assert!(
        clash.to_string().contains("already owns these exact bytes"),
        "{clash}"
    );
    assert!(
        outbox
            .signing_attempt(&pending(&outbox, &second.id))
            .unwrap()
            .is_none(),
        "and must not have committed to anything"
    );

    // Once the cluster moves again the second intent settles on its own bytes,
    // so two approvals still buy two distinct transfers.
    *blockhash.lock().unwrap() = [0x6bu8; 32];
    engine
        .sign(
            "wallet",
            &second.id,
            &fee_payer,
            None,
            Some(approvals[1].clone()),
            260_000,
        )
        .await
        .expect("a fresh blockhash lets the second intent through");
    let first_bytes = outbox
        .signing_attempt(&pending(&outbox, &first.id))
        .unwrap()
        .unwrap()
        .finalized_staged
        .message_b64;
    let second_bytes = outbox
        .signing_attempt(&pending(&outbox, &second.id))
        .unwrap()
        .unwrap()
        .finalized_staged
        .message_b64;
    assert_ne!(
        first_bytes, second_bytes,
        "two distinct messages, so two distinct signatures and two transfers"
    );
}
