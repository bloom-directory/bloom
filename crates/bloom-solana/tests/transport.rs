//! Transport tests against a real loopback HTTP stub standing in for a
//! Solana RPC node: retry, failover, genesis binding, and the typed read
//! surface, exercised without any external network access.

use bloom_proto::EndpointSpec;
use bloom_solana::{SolanaClient, SolanaRpcError, SolanaSpec};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A stub JSON-RPC server that answers a fixed set of methods.
async fn spawn_stub() -> String {
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
                let body = request
                    .split("\r\n\r\n")
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let method = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(String::from))
                    .unwrap_or_default();
                let body = match method.as_str() {
                    "getHealth" => r#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#.to_string(),
                    "getGenesisHash" => {
                        format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{}"}}"#, "G".repeat(32))
                    }
                    "getSlot" => r#"{"jsonrpc":"2.0","id":1,"result":12345}"#.to_string(),
                    "getBalance" => r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":999}}"#
                        .to_string(),
                    _ => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#
                        .to_string(),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

async fn spawn_write_stub(genesis: String, send_status: u16, send_calls: Arc<AtomicU64>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let genesis = genesis.clone();
            let send_calls = send_calls.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let body = String::from_utf8_lossy(&buf[..n])
                    .split("\r\n\r\n")
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let request = serde_json::from_str::<serde_json::Value>(&body).unwrap_or_default();
                let method = request
                    .get("method")
                    .and_then(|method| method.as_str())
                    .map(str::to_owned)
                    .unwrap_or_default();
                if method == "sendTransaction" {
                    send_calls.fetch_add(1, Ordering::SeqCst);
                }
                let send_config_matches_blockhash =
                    request.get("params").and_then(|params| params.get(1))
                        == Some(&serde_json::json!({
                            "encoding": "base64",
                            "preflightCommitment": "processed"
                        }));
                let payload = match method.as_str() {
                    "getGenesisHash" => {
                        format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{genesis}"}}"#)
                    }
                    "sendTransaction" if send_status == 200 && send_config_matches_blockhash => {
                        r#"{"jsonrpc":"2.0","id":1,"result":"signature"}"#.to_string()
                    }
                    "sendTransaction" if send_status == 200 => r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"preflight commitment mismatch"}}"#.to_string(),
                    _ => String::new(),
                };
                let response = if send_status != 200 && method == "sendTransaction" {
                    format!(
                        "HTTP/1.1 {send_status} Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                    )
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    )
                };
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

/// Accepts a fee quote only when it uses the same `processed` commitment as
/// the blockhash fetch. A newly produced blockhash need not be visible at the
/// RPC default commitment yet, in which case Agave returns a null fee.
async fn spawn_fee_stub() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 8192];
        let n = socket.read(&mut buf).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);
        let value = request
            .split("\r\n\r\n")
            .nth(1)
            .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
            .unwrap_or_default();
        let expected = serde_json::json!(["serialized-message", { "commitment": "processed" }]);
        let body = if value.get("method").and_then(|v| v.as_str()) == Some("getFeeForMessage")
            && value.get("params") == Some(&expected)
        {
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":5000}}"#
        } else {
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"commitment mismatch"}}"#
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = socket.write_all(response.as_bytes()).await;
    });
    format!("http://{addr}/")
}

fn spec(endpoint: &str) -> SolanaSpec {
    SolanaSpec {
        name: "solana-test".into(),
        endpoints: vec![EndpointSpec {
            url: endpoint.to_string(),
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        }],
        expected_genesis_base58: Some("G".repeat(32)),
        allow_broadcast: false,
    }
}

#[tokio::test]
async fn typed_read_methods_roundtrip() {
    let endpoint = spawn_stub().await;
    let client = SolanaClient::build(&spec(&endpoint)).unwrap();

    client.get_health().await.unwrap();
    assert_eq!(client.get_genesis_hash().await.unwrap(), "G".repeat(32));
    assert_eq!(client.get_slot().await.unwrap(), 12345);
    assert_eq!(client.get_balance("irrelevant").await.unwrap(), 999);
}

#[tokio::test]
async fn fee_quote_matches_the_blockhash_commitment() {
    let endpoint = spawn_fee_stub().await;
    let client = SolanaClient::build(&spec(&endpoint)).unwrap();

    assert_eq!(
        client
            .get_fee_for_message("serialized-message")
            .await
            .unwrap(),
        Some(5_000)
    );
}

#[tokio::test]
async fn genesis_mismatch_is_refused() {
    let endpoint = spawn_stub().await;
    let mut spec = spec(&endpoint);
    spec.expected_genesis_base58 = Some("X".repeat(32));
    let client = SolanaClient::build(&spec).unwrap();

    let err = client.verify_genesis().await.unwrap_err();
    assert!(
        matches!(err, SolanaRpcError::GenesisMismatch { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn pinned_mainnet_uses_the_standard_broadcast_path() {
    let send_calls = Arc::new(AtomicU64::new(0));
    let genesis = bloom_proto::SOLANA_MAINNET_BETA_GENESIS_HASH;
    let endpoint = spawn_write_stub(genesis.into(), 200, send_calls.clone()).await;
    let mut spec = spec(&endpoint);
    spec.name = "solana-mainnet".into();
    spec.expected_genesis_base58 = Some(genesis.into());
    spec.allow_broadcast = true;

    let client = SolanaClient::build(&spec).unwrap();
    assert_eq!(client.verify_genesis().await.unwrap(), genesis);
    assert_eq!(
        client.send_transaction("signed-transaction").await.unwrap(),
        "signature"
    );
    assert_eq!(send_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mixed_genesis_endpoints_are_refused_before_any_send() {
    let primary_sends = Arc::new(AtomicU64::new(0));
    let backup_sends = Arc::new(AtomicU64::new(0));
    let primary = spawn_write_stub("G".repeat(32), 200, primary_sends.clone()).await;
    let backup = spawn_write_stub("X".repeat(32), 200, backup_sends.clone()).await;
    let mut spec = spec(&primary);
    spec.allow_broadcast = true;
    spec.endpoints.push(bloom_proto::EndpointSpec {
        url: backup,
        weight: 50,
        cu_per_sec: None,
        max_rps: None,
        http_only: false,
    });
    let client = SolanaClient::build(&spec).unwrap();

    let error = client
        .send_transaction("signed-transaction")
        .await
        .expect_err("every configured endpoint must prove the pinned genesis");
    assert!(matches!(error, SolanaRpcError::GenesisMismatch { .. }));
    assert_eq!(primary_sends.load(Ordering::SeqCst), 0);
    assert_eq!(backup_sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ambiguous_send_is_attempted_once_without_failover() {
    let primary_sends = Arc::new(AtomicU64::new(0));
    let backup_sends = Arc::new(AtomicU64::new(0));
    let primary = spawn_write_stub("G".repeat(32), 503, primary_sends.clone()).await;
    let backup = spawn_write_stub("G".repeat(32), 200, backup_sends.clone()).await;
    let mut spec = spec(&primary);
    spec.allow_broadcast = true;
    spec.endpoints.push(bloom_proto::EndpointSpec {
        url: backup,
        weight: 50,
        cu_per_sec: None,
        max_rps: None,
        http_only: false,
    });
    let client = SolanaClient::build(&spec).unwrap();

    client
        .send_transaction("signed-transaction")
        .await
        .expect_err("an ambiguous write must not retry or fail over");
    assert_eq!(primary_sends.load(Ordering::SeqCst), 1);
    assert_eq!(backup_sends.load(Ordering::SeqCst), 0);
}

/// A stub that fails the first N requests with 503, then succeeds, to prove
/// the retry layer recovers a transient outage.
#[tokio::test]
async fn retries_transient_http_failures() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let failures = Arc::new(AtomicU64::new(2));
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let failures = failures.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap_or(0);
                let remaining =
                    failures.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
                let body = if remaining.is_ok() && remaining.unwrap() > 0 {
                    "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
                } else {
                    let body = r#"{"jsonrpc":"2.0","id":1,"result":777}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                let _ = socket.write_all(body.as_bytes()).await;
            });
        }
    });
    let client = SolanaClient::build(&spec(&format!("http://{addr}/"))).unwrap();
    // The first two calls fail with 503; the third attempt (after retries)
    // succeeds and decodes the slot.
    let slot: u64 = client.get_slot().await.unwrap();
    assert_eq!(slot, 777);
}

#[tokio::test]
async fn fails_over_across_endpoints() {
    // First endpoint is a dead port (connection refused), second answers.
    let good = spawn_stub().await;
    let mut spec = spec("http://127.0.0.1:1");
    spec.endpoints.push(EndpointSpec {
        url: good,
        weight: 50,
        cu_per_sec: None,
        max_rps: None,
        http_only: false,
    });
    let client = SolanaClient::build(&spec).unwrap();
    assert_eq!(client.get_slot().await.unwrap(), 12345);
}

/// A stub that always answers a specific method with a non-retryable
/// JSON-RPC error (`-32601`, method-not-found — per `should_retry`, never
/// retryable).
async fn spawn_non_retryable_stub(method_name: &'static str) -> String {
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
                let _ = socket.read(&mut buf).await.unwrap_or(0);
                let body = format!(
                    r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32601,"message":"the method {method_name} does not exist/is not available"}}}}"#
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

// Fix E (PLAN-SOLANA-PR-FIXES.md): `call_raw` used to return immediately on
// a non-retryable error from the first endpoint, without trying any
// configured backup — despite this module's own doc comment claiming
// EVM-equivalent failover behaviour.
#[tokio::test]
async fn fails_over_to_backup_after_a_non_retryable_error_on_the_primary() {
    let primary = spawn_non_retryable_stub("getSlot").await;
    let backup = spawn_stub().await;
    let mut spec = spec(&primary);
    spec.endpoints[0].weight = 100; // primary preferred
    spec.endpoints.push(EndpointSpec {
        url: backup,
        weight: 50,
        cu_per_sec: None,
        max_rps: None,
        http_only: false,
    });
    let client = SolanaClient::build(&spec).unwrap();
    // The primary's -32601 is deterministic and non-retryable — the call
    // must still succeed by falling through to the healthy backup, not
    // fail on the primary's answer alone.
    assert_eq!(client.get_slot().await.unwrap(), 12345);
}

#[test]
fn empty_endpoint_list_is_refused() {
    let spec = SolanaSpec {
        name: "solana-test".into(),
        endpoints: vec![],
        expected_genesis_base58: None,
        allow_broadcast: false,
    };
    assert!(matches!(
        SolanaClient::build(&spec),
        Err(SolanaRpcError::NoEndpoints(_))
    ));
}

#[test]
fn broadcast_requires_an_expected_genesis_hash() {
    let mut spec = spec("http://127.0.0.1:1");
    spec.expected_genesis_base58 = None;
    spec.allow_broadcast = true;
    let error = SolanaClient::build(&spec).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("without an expected genesis hash"),
        "{error}"
    );
}
