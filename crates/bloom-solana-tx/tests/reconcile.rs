//! Reconciliation test: a staged+sent transfer is reconciled to a receipt
//! via a stubbed `getSignatureStatuses` node.

use std::sync::Arc;

use bloom_proto::AuditLog;
use bloom_solana::{EndpointSpec, SolanaChainRegistry, SolanaClient, SolanaSpec};
use bloom_solana_tx::outbox::{SolanaOutbox, SolanaOutboxState};
use bloom_solana_tx::reconcile::SolanaReconciler;
use bloom_solana_tx::types::{SolanaTxStatus, StagedSolanaTransfer};
use serde_json::json;
use tempfile::TempDir;

fn audit(dir: &TempDir) -> Arc<AuditLog> {
    Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap())
}

async fn spawn_status_stub(
    confirmations: Option<u64>,
    err: bool,
    finalized: bool,
    block_height: u64,
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
                let mut buf = Vec::new();
                loop {
                    let mut chunk = [0_u8; 4096];
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let Some(header_end) = buf.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&buf[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if buf.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&buf).to_string();
                let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
                let method = serde_json::from_str::<serde_json::Value>(body)
                    .ok()
                    .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(String::from))
                    .unwrap_or_default();
                let result = match method.as_str() {
                    "getSignatureStatuses" => {
                        let status = if let Some(c) = confirmations {
                            json!({
                                "slot": 42,
                                "confirmations": c,
                                "err": if err { json!({"InstructionError": [0, "Custom"]}) } else { serde_json::Value::Null },
                                "confirmation_status": if c == 0 {
                                    serde_json::Value::Null
                                } else if finalized {
                                    json!("finalized")
                                } else {
                                    json!("processed")
                                },
                            })
                        } else {
                            serde_json::Value::Null
                        };
                        json!({ "context": {"slot": 42}, "value": [status] }).to_string()
                    }
                    "getBlockHeight" => block_height.to_string(),
                    _ => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#
                        .to_string(),
                };
                let payload =
                    if matches!(method.as_str(), "getSignatureStatuses" | "getBlockHeight") {
                        format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result}}}"#)
                    } else {
                        result
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

fn sent_entry(id: &str) -> StagedSolanaTransfer {
    StagedSolanaTransfer {
        id: id.into(),
        wallet: "alice".into(),
        chain: "solana-devnet".into(),
        fee_payer: "FEEPAYER111111111111111111111111111111111".into(),
        account_fingerprint: None,
        account_derivation_path: None,
        destination: "DEST111111111111111111111111111111111111111".into(),
        lamports: 1,
        fee_lamports: 5_000,
        genesis_hash: "GENESIS111111111111111111111111111111111111".into(),
        blockhash: "BLOCKHASH111111111111111111111111111111111111".into(),
        last_valid_block_height: 1,
        message_b64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"m"),
        payload_digest_hex: "ab".repeat(32),
        signature: Some("SIG1111111111111111111111111111111111111111111111111111111111111".into()),
        created_ms: 1,
        expires_ms: 0,
        status: SolanaTxStatus::Sent,
        action_id: None,
    }
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
        expected_genesis_base58: None,
        allow_broadcast: false,
    })
    .unwrap()
}

#[tokio::test]
async fn reconciles_success_to_receipt() {
    let endpoint = spawn_status_stub(Some(1), false, true, 1).await;
    let dir = TempDir::new().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let s = sent_entry("0001-00001");
    outbox.write_pending(&s, "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .write_broadcast_attempt(&entry, s.signature.as_deref().unwrap(), b"raw", 1)
        .unwrap();
    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();

    let registry = SolanaChainRegistry::new();
    registry.add(client(&endpoint));
    let reconciler = SolanaReconciler::new(outbox.clone(), registry, audit(&dir));
    let updated = reconciler.tick().await;
    assert_eq!(updated, 1);

    let receipt = outbox
        .read_receipt("alice", "solana-devnet", "0001-00001")
        .unwrap()
        .expect("receipt written");
    assert_eq!(receipt.outcome, "success");
    assert_eq!(receipt.slot, Some(42));
    // A second tick is a no-op: the entry is already mined.
    assert_eq!(reconciler.tick().await, 0);
}

#[tokio::test]
async fn reconciles_failure_to_receipt() {
    let endpoint = spawn_status_stub(Some(1), true, true, 1).await;
    let dir = TempDir::new().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let s = sent_entry("0001-00001");
    outbox.write_pending(&s, "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .write_broadcast_attempt(&entry, s.signature.as_deref().unwrap(), b"raw", 1)
        .unwrap();
    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();

    let registry = SolanaChainRegistry::new();
    registry.add(client(&endpoint));
    let reconciler = SolanaReconciler::new(outbox.clone(), registry, audit(&dir));
    assert_eq!(reconciler.tick().await, 1);

    let receipt = outbox
        .read_receipt("alice", "solana-devnet", "0001-00001")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.outcome, "failed");
    assert!(receipt.err.is_some());
}

#[tokio::test]
async fn unseen_signature_stays_unreconciled() {
    // The node returns a null entry: signature not observed yet.
    let endpoint = spawn_status_stub(None, false, true, 1).await;
    let dir = TempDir::new().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let s = sent_entry("0001-00001");
    outbox.write_pending(&s, "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .write_broadcast_attempt(&entry, s.signature.as_deref().unwrap(), b"raw", 1)
        .unwrap();
    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();

    let registry = SolanaChainRegistry::new();
    registry.add(client(&endpoint));
    let reconciler = SolanaReconciler::new(outbox.clone(), registry, audit(&dir));
    assert_eq!(reconciler.tick().await, 0);
    assert!(
        outbox
            .read_receipt("alice", "solana-devnet", "0001-00001")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn processed_signature_stays_unreconciled() {
    let endpoint = spawn_status_stub(Some(1), false, false, 2).await;
    let dir = TempDir::new().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let s = sent_entry("0001-00001");
    outbox.write_pending(&s, "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .write_broadcast_attempt(&entry, s.signature.as_deref().unwrap(), b"raw", 1)
        .unwrap();
    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();

    let registry = SolanaChainRegistry::new();
    registry.add(client(&endpoint));
    let reconciler = SolanaReconciler::new(outbox.clone(), registry, audit(&dir));
    assert_eq!(reconciler.tick().await, 0);
    assert!(
        outbox
            .read_receipt("alice", "solana-devnet", "0001-00001")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn unseen_signature_becomes_terminal_after_blockhash_expiry() {
    let endpoint = spawn_status_stub(None, false, true, 2).await;
    let dir = TempDir::new().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let s = sent_entry("0001-00001");
    outbox.write_pending(&s, "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .write_broadcast_attempt(&entry, s.signature.as_deref().unwrap(), b"raw", 1)
        .unwrap();
    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();

    let registry = SolanaChainRegistry::new();
    registry.add(client(&endpoint));
    let reconciler = SolanaReconciler::new(outbox.clone(), registry, audit(&dir));
    assert_eq!(reconciler.tick().await, 1);
    let receipt = outbox
        .read_receipt("alice", "solana-devnet", "0001-00001")
        .unwrap()
        .unwrap();
    assert_eq!(receipt.outcome, "failed");
    assert_eq!(receipt.slot, None);
    assert_eq!(receipt.err.unwrap()["kind"], "blockhash_expired_unseen");
}

#[tokio::test]
async fn audit_prewrite_failure_prevents_receipt_projection() {
    let endpoint = spawn_status_stub(Some(1), false, true, 1).await;
    let dir = TempDir::new().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let staged = sent_entry("0001-00001");
    outbox.write_pending(&staged, "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .write_broadcast_attempt(&entry, staged.signature.as_deref().unwrap(), b"raw", 1)
        .unwrap();
    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();

    let registry = SolanaChainRegistry::new();
    registry.add(client(&endpoint));
    let audit = audit(&dir);
    audit.fail_next_write_for_test();
    let reconciler = SolanaReconciler::new(outbox.clone(), registry, audit.clone());
    assert_eq!(reconciler.tick().await, 0);
    assert!(
        outbox
            .read_receipt("alice", "solana-devnet", "0001-00001")
            .unwrap()
            .is_none()
    );
    assert!(audit.mutation_degradation().is_some());
}

#[tokio::test]
async fn receipt_projection_result_loss_latches_on_restart() {
    let endpoint = spawn_status_stub(Some(1), false, true, 1).await;
    let dir = TempDir::new().unwrap();
    let outbox = SolanaOutbox::new(dir.path().join("outbox")).unwrap();
    let staged = sent_entry("0001-00001");
    outbox.write_pending(&staged, "plan").unwrap();
    let entry = outbox.read("alice", "solana-devnet", "0001-00001").unwrap();
    outbox
        .write_broadcast_attempt(&entry, staged.signature.as_deref().unwrap(), b"raw", 1)
        .unwrap();
    outbox.transition(&entry, SolanaOutboxState::Sent).unwrap();

    let registry = SolanaChainRegistry::new();
    registry.add(client(&endpoint));
    let audit_path = dir.path().join("audit.jsonl");
    let audit = audit(&dir);
    audit.fail_after_writes_for_test(1);
    let reconciler = SolanaReconciler::new(outbox.clone(), registry, audit.clone());
    assert_eq!(reconciler.tick().await, 0);
    assert!(
        outbox
            .read_receipt("alice", "solana-devnet", "0001-00001")
            .unwrap()
            .is_some()
    );
    drop(reconciler);
    drop(audit);
    let restarted = AuditLog::open(audit_path).unwrap();
    assert!(restarted.mutation_degradation().is_some());
    assert_eq!(restarted.pending_effect_correlations().unwrap().len(), 1);
}
