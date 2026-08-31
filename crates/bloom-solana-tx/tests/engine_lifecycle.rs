//! End-to-end transfer lifecycle: stage → sign → broadcast, driven by a stub
//! Solana RPC node and a real-Ed25519 Broker fixture.

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

    let swept = outbox.sweep_expired(now_ms).unwrap();
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

    // Broadcast: submits the assembled transaction, *then* transitions to
    // sent and records the attempt.
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

// Fix C (PLAN-SOLANA-PR-FIXES.md): a broadcast RPC failure after a
// successful `sign()` must never permanently strand the entry — it must
// stay `pending`, exactly as retryable and cancellable as before signing.
#[tokio::test]
async fn broadcast_failure_leaves_entry_pending_and_retry_succeeds() {
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

    // First broadcast attempt: the node returns a hard RPC error. The entry
    // must not have moved to `sent` for a broadcast that never happened.
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
            SolanaOutboxState::Pending,
        )
        .expect("entry must remain pending after a failed broadcast, not stuck in sent");
    assert!(
        outbox.recorded_signature(&entry).unwrap().is_some(),
        "the recorded signature from sign() survives the failed broadcast attempt"
    );

    // Retry: the node now accepts the same call. No re-signing needed —
    // broadcast reads the already-recorded signature straight from the
    // still-pending entry.
    let signature = engine
        .broadcast("wallet", &staged.id, 1_400)
        .await
        .expect("retried broadcast must succeed");
    assert_eq!(signature, expected_signature);
    outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Sent,
        )
        .expect("entry moves to sent once the retried broadcast actually succeeds");
}

#[tokio::test]
async fn broadcast_failure_leaves_entry_cancellable() {
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

    // The VFS write handler only permits `pending/<id>/cancel` on a Pending
    // entry (see `bloom-vfs`'s wallets handler) — this is exactly the path
    // that was unreachable before the fix, since the entry was already
    // stuck in `sent`.
    outbox
        .cancel("wallet", "solana-devnet", &staged.id)
        .expect("a signed-but-not-broadcast entry must still be cancellable");
    let cancelled = outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Failed,
        )
        .unwrap();
    assert_eq!(cancelled.staged.status, SolanaTxStatus::Cancelled);
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

    let too_early = engine
        .restage_expired("wallet", &original.id, &broker.child_pubkey(), 1_250)
        .await
        .unwrap_err();
    assert!(too_early.to_string().contains("remains valid"));

    assert_eq!(outbox.sweep_expired(u128::MAX).unwrap(), 1);
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
async fn mismatched_rpc_signature_never_marks_the_entry_sent() {
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
    outbox
        .read_in_state(
            "wallet",
            "solana-devnet",
            &staged.id,
            SolanaOutboxState::Pending,
        )
        .expect("an untrusted RPC response cannot advance durable state");
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
