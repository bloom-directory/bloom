//! The authoritative "is this actually Solana mainnet" check.
//!
//! Solana has no chain-id analogue baked into transactions (a message
//! carries a recent blockhash, not a chain identifier), so the only thing
//! that reliably identifies a cluster is its genesis hash — a value fixed
//! at network genesis and returned by every conforming node via
//! `getGenesisHash`. A config key's *name* (`"mainnet"`, `"solana-prod"`,
//! `"sol-live"`, a typo) is operator-chosen and proves nothing about the
//! cluster an endpoint actually talks to.
//!
//! [`MAINNET_BETA_GENESIS_HASH`] is the known genesis hash for Solana
//! mainnet-beta, confirmed against four independent sources before being
//! hardcoded here (2026-08-19): a live `getGenesisHash` call against
//! `api.mainnet-beta.solana.com` (the official public endpoint), the same
//! call against `solana-rpc.publicnode.com` (an unrelated, independently
//! operated endpoint), Anza's official cluster reference
//! (<https://docs.anza.xyz/clusters/available>, the `--expected-genesis-hash`
//! value documented for `agave-validator`), and the reference validator
//! client's own source
//! (`solana-labs/solana:sdk/src/genesis_config.rs`,
//! `ClusterType::MainnetBeta => get_genesis_hash()`). All four agreed.
//!
//! [`is_mainnet_beta_blocking`] is deliberately **blocking**: it exists to
//! be called from `bloom-daemon`'s synchronous `from_home_inner` chain
//! construction, which runs before (or entirely without) a `tokio` runtime.
//! It uses `reqwest::blocking`, which runs its I/O on a dedicated internal
//! thread rather than entering the calling thread's tokio context, so it is
//! safe to call whether or not the caller happens to already be on a tokio
//! worker thread.

use serde_json::Value;

use crate::SolanaSpec;
use crate::error::SolanaRpcError;

/// The known genesis hash for Solana mainnet-beta. See the module docs for
/// how this value was verified. Do not hand-edit without re-verifying
/// against a live node and the reference client source — this constant is
/// the sole gate standing between a misconfigured chain and a real mainnet
/// broadcast.
pub const MAINNET_BETA_GENESIS_HASH: &str = bloom_proto::SOLANA_MAINNET_BETA_GENESIS_HASH;

/// Whether the cluster reachable at `spec`'s endpoints is confirmed to be
/// Solana mainnet-beta, checked via a live, blocking `getGenesisHash` call.
///
/// Tries each configured HTTP(S) endpoint in turn (skipping `ws://`/`wss://`
/// entries, matching [`crate::transport::SolanaRpcClient`]'s read-client
/// scope) and returns as soon as one answers.
///
/// Returns:
/// - `Ok(true)` — confirmed mainnet-beta. The caller must refuse to
///   construct/broadcast.
/// - `Ok(false)` — confirmed to be a different cluster (genesis hash
///   observed and it does not match).
/// - `Err(_)` — no configured endpoint could be reached to determine the
///   cluster's identity at all. Boot callers may keep the read-only engine
///   available for degraded readiness, but stage/broadcast must still fail
///   closed until a live identity check succeeds.
pub fn is_mainnet_beta_blocking(spec: &SolanaSpec) -> Result<bool, SolanaRpcError> {
    let observed = observed_genesis_hash_blocking(spec)?;
    Ok(observed == MAINNET_BETA_GENESIS_HASH)
}

/// Runs the blocking check on a plain OS thread that never enters any
/// `tokio` context. `reqwest::blocking` builds (and, on drop, tears down)
/// its own internal runtime; doing that on a thread that is itself already
/// inside an async task panics ("Cannot drop a runtime in a context where
/// blocking is not allowed"). Spawning a fresh, tokio-naive thread and
/// joining it sidesteps that regardless of the caller's context — this
/// function is called both from `bloom-daemon`'s synchronous boot path and,
/// in tests, from inside `#[tokio::test]`.
fn observed_genesis_hash_blocking(spec: &SolanaSpec) -> Result<String, SolanaRpcError> {
    let spec = spec.clone();
    std::thread::spawn(move || observed_genesis_hash_blocking_on_this_thread(&spec))
        .join()
        .unwrap_or_else(|_| {
            Err(SolanaRpcError::Transport(
                "genesis check thread panicked".into(),
            ))
        })
}

fn observed_genesis_hash_blocking_on_this_thread(
    spec: &SolanaSpec,
) -> Result<String, SolanaRpcError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| SolanaRpcError::Transport(e.to_string()))?;

    let mut last_error: Option<SolanaRpcError> = None;
    let mut tried_any = false;
    for endpoint in &spec.endpoints {
        if endpoint.url.starts_with("ws://") || endpoint.url.starts_with("wss://") {
            continue;
        }
        tried_any = true;
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getGenesisHash",
            "params": []
        });
        let attempt = client
            .post(&endpoint.url)
            .json(&body)
            .send()
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| SolanaRpcError::Transport(e.to_string()))
            .and_then(|resp| {
                resp.json::<Value>()
                    .map_err(|e| SolanaRpcError::Decode(e.to_string()))
            })
            .and_then(|payload| {
                if let Some(error) = payload.get("error") {
                    let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                    let message = error
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or_default()
                        .to_string();
                    return Err(SolanaRpcError::Rpc { code, message });
                }
                payload
                    .get("result")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| SolanaRpcError::Decode(format!("getGenesisHash: {payload}")))
            });
        match attempt {
            Ok(hash) => return Ok(hash),
            Err(e) => last_error = Some(e),
        }
    }
    if !tried_any {
        return Err(SolanaRpcError::NoEndpoints(spec.name.clone()));
    }
    Err(last_error.unwrap_or_else(|| SolanaRpcError::NoEndpoints(spec.name.clone())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::EndpointSpec;

    fn spec_with_endpoint(url: &str) -> SolanaSpec {
        SolanaSpec {
            name: "test".to_string(),
            endpoints: vec![EndpointSpec {
                url: url.to_string(),
                weight: 100,
                cu_per_sec: None,
                max_rps: None,
                http_only: false,
            }],
            expected_genesis_hex: None,
            allow_broadcast: false,
        }
    }

    #[test]
    fn refuses_when_no_endpoints_reachable() {
        // Port 0/unroutable: connection must fail, and the gate must fail
        // closed (Err), not silently report "not mainnet".
        let spec = spec_with_endpoint("http://127.0.0.1:1");
        let result = is_mainnet_beta_blocking(&spec);
        assert!(result.is_err(), "unreachable endpoint must fail closed");
    }

    #[test]
    fn refuses_when_no_http_endpoints_configured() {
        let mut spec = spec_with_endpoint("wss://example.invalid");
        spec.endpoints[0].url = "ws://example.invalid".to_string();
        let result = is_mainnet_beta_blocking(&spec);
        assert!(matches!(result, Err(SolanaRpcError::NoEndpoints(_))));
    }

    /// A loopback JSON-RPC stub answering `getGenesisHash` with a fixed
    /// value, for the async, network-exercising checks below.
    async fn spawn_genesis_stub(hash: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let hash = hash.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let _ = socket.read(&mut buf).await.unwrap_or(0);
                    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{hash}"}}"#);
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

    // `flavor = "multi_thread"`: `is_mainnet_beta_blocking` blocks its
    // calling worker thread by design (see its doc comment). Under the
    // default single-threaded test runtime that worker *is* the only
    // thread driving the stub server's `tokio::spawn`ed accept loop, so
    // blocking it would starve the stub instead of exercising the real
    // (multi-threaded, production-shaped) scenario.
    #[tokio::test(flavor = "multi_thread")]
    async fn confirms_mainnet_when_genesis_matches() {
        let endpoint = spawn_genesis_stub(MAINNET_BETA_GENESIS_HASH.to_string()).await;
        let spec = spec_with_endpoint(&endpoint);
        // Blocking call from inside a tokio runtime: must not panic or
        // deadlock (this is exactly the context `bloom-daemon` calls it
        // from — its own boot path is synchronous but may run under an
        // already-active tokio runtime in production).
        assert!(is_mainnet_beta_blocking(&spec).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn does_not_confirm_mainnet_for_a_different_genesis() {
        let endpoint = spawn_genesis_stub("D".repeat(32)).await;
        let spec = spec_with_endpoint(&endpoint);
        assert!(!is_mainnet_beta_blocking(&spec).unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn broadcast_client_refuses_mainnet_even_after_boot_admission() {
        let endpoint = spawn_genesis_stub(MAINNET_BETA_GENESIS_HASH.to_string()).await;
        let mut spec = spec_with_endpoint(&endpoint);
        spec.expected_genesis_hex = Some(MAINNET_BETA_GENESIS_HASH.to_string());
        spec.allow_broadcast = true;
        let client = crate::SolanaClient::build(&spec).unwrap();
        let error = client.verify_genesis().await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("broadcast to Solana mainnet-beta is disabled")
        );

        let error = client
            .send_transaction("signed-transaction")
            .await
            .expect_err("the write method itself must retain the mainnet guard");
        assert!(
            error
                .to_string()
                .contains("broadcast to Solana mainnet-beta is disabled")
        );
    }

    #[test]
    fn known_hash_constant_is_well_formed_base58() {
        // Sanity guard against a corrupted constant: Solana hashes are
        // 32-byte base58 (roughly 32-44 chars, no 0/O/I/l).
        assert!(bs58::decode(MAINNET_BETA_GENESIS_HASH).into_vec().is_ok());
        assert_eq!(
            bs58::decode(MAINNET_BETA_GENESIS_HASH)
                .into_vec()
                .unwrap()
                .len(),
            32
        );
    }
}
