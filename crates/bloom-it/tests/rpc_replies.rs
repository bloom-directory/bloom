//! Category: integration
//!
//! How the EVM endpoint pool reports what nodes, gateways and providers
//! answer: reverts, rate limits, refusals and gateway failures, against
//! `anvil` and local HTTP stand-ins.
//!
//! Requires `anvil` from Foundry on `$PATH`.

use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes, U64};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use anyhow::{Context, Result, anyhow, bail};
use bloom_evm::ChainClient;
use bloom_it::{pick_free_port, spawn_anvil};
use bloom_proto::ChainSpec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Runtime code that reverts with `Error(reason)`.
fn reverts_with(reason: &str) -> String {
    let mut payload = String::from("08c379a0");
    payload.push_str(&format!("{:064x}", 32));
    payload.push_str(&format!("{:064x}", reason.len()));
    let mut data = hex::encode(reason.as_bytes());
    let padded = reason.len().div_ceil(32) * 64;
    while data.len() < padded {
        data.push('0');
    }
    payload.push_str(&data);
    let n = payload.len() / 2;
    // PUSH1 n PUSH1 12 PUSH1 0 CODECOPY PUSH1 n PUSH1 0 REVERT, then payload.
    format!("0x60{n:02x}600c60003960{n:02x}6000fd{payload}")
}

/// Runtime code that reverts without data: `PUSH1 0 PUSH1 0 REVERT`.
const ALWAYS_REVERTS: &str = "0x60006000fd";

async fn install(anvil_url: &str, at: Address, code: &str) -> Result<()> {
    let single = client_over(vec![anvil_url.to_string()])?;
    let _: serde_json::Value = single
        .provider()
        .raw_request("anvil_setCode".into(), (at, code))
        .await
        .context("anvil_setCode")?;
    Ok(())
}

fn client_over(urls: Vec<String>) -> Result<ChainClient> {
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = urls;
    spec.rpc_endpoints.clear();
    ChainClient::new(spec).map_err(|e| anyhow!("build chain client: {e}"))
}

fn dead_endpoint() -> Result<String> {
    Ok(format!("http://127.0.0.1:{}", pick_free_port()?))
}

/// A local endpoint answering every request with `status` and `body` after
/// `delay`. `"__ID__"` in `body` becomes the request's id.
async fn endpoint(status: &'static str, body: &'static str, delay: Duration) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Read the whole request first, so the client sees the
                // answer rather than a reset connection.
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                let head = loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                    let Some(head) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let length = String::from_utf8_lossy(&request[..head])
                        .to_ascii_lowercase()
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:")?.trim().parse().ok())
                        .unwrap_or(0usize);
                    if request.len() >= head + 4 + length {
                        break head;
                    }
                };
                let id = serde_json::from_slice::<serde_json::Value>(&request[head + 4..])
                    .ok()
                    .and_then(|v| v.get("id").cloned())
                    .unwrap_or(serde_json::Value::from(0));
                let body = body.replace("\"__ID__\"", &id.to_string());
                tokio::time::sleep(delay).await;
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    url
}

/// An endpoint that accepts connections and never answers.
async fn silent_endpoint() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    url
}

/// A revert reason is the contract's, so one that mentions "capacity" is
/// not a rate limit. Retried, it would come back as "max retries
/// exceeded", a transport error that the pre-broadcast simulation reads
/// as "unavailable", letting the transaction through to signing.
#[tokio::test(flavor = "multi_thread")]
async fn a_revert_whose_reason_reads_like_a_rate_limit_is_a_revert() -> Result<()> {
    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let vault = Address::repeat_byte(0xca);
    install(
        &anvil.rpc_url(),
        vault,
        &reverts_with("Vault capacity exceeded"),
    )
    .await?;
    let client = client_over(vec![anvil.rpc_url()])?;
    let outcome = client
        .eth_call_capture_revert(TransactionRequest::default().to(vault), None)
        .await;
    match outcome {
        Ok(Err(_revert)) => Ok(()),
        other => bail!("expected the revert, got {other:?}"),
    }
}

/// Nor can a revert reason choose the retry delay, as "try again in 3s"
/// would if it were read as a rate limit.
#[tokio::test(flavor = "multi_thread")]
async fn a_revert_reason_cannot_choose_the_retry_delay() -> Result<()> {
    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let target = Address::repeat_byte(0xcb);
    install(
        &anvil.rpc_url(),
        target,
        &reverts_with("rate limited, try again in 3s"),
    )
    .await?;
    let client = client_over(vec![anvil.rpc_url()])?;
    let started = Instant::now();
    let outcome = client
        .eth_call_capture_revert(TransactionRequest::default().to(target), None)
        .await;
    let elapsed = started.elapsed();
    if elapsed > Duration::from_secs(2) {
        bail!("the revert reason held the call for {elapsed:?}");
    }
    match outcome {
        Ok(Err(_revert)) => Ok(()),
        other => bail!("expected the revert, got {other:?}"),
    }
}

/// A read takes the first answer: a revert does not wait for the other
/// endpoint in its race, here one that never answers and so would hold
/// every revert for the full request timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_revert_is_not_held_up_by_a_silent_peer() -> Result<()> {
    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let reverter = Address::repeat_byte(0xde);
    install(&anvil.rpc_url(), reverter, ALWAYS_REVERTS).await?;
    let client = client_over(vec![anvil.rpc_url(), silent_endpoint().await])?;
    client.block_number().await.map_err(|e| anyhow!("{e}"))?;

    for i in 0..2 {
        let started = Instant::now();
        let outcome = timeout(
            Duration::from_secs(45),
            client.eth_call_capture_revert(TransactionRequest::default().to(reverter), None),
        )
        .await
        .map_err(|_| anyhow!("call {i} still waiting"))?;
        let elapsed = started.elapsed();
        if !matches!(outcome, Ok(Err(_))) {
            bail!("call {i}: expected the revert, got {outcome:?}");
        }
        if elapsed > Duration::from_secs(5) {
            bail!("call {i}: the revert waited {elapsed:?} for the silent endpoint");
        }
    }
    Ok(())
}

/// A lagging node's later success does not override the revert an
/// up-to-date node reported first, which would let the simulation pass.
#[tokio::test(flavor = "multi_thread")]
async fn a_read_takes_the_revert_that_comes_first() -> Result<()> {
    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let pool = Address::repeat_byte(0xab);
    install(&anvil.rpc_url(), pool, &reverts_with("Too little received")).await?;
    let stale = endpoint(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"__ID__","result":"0x"}"#,
        Duration::from_millis(500),
    )
    .await;
    let client = client_over(vec![anvil.rpc_url(), stale])?;
    let outcome = client
        .eth_call_capture_revert(TransactionRequest::default().to(pool), None)
        .await;
    match outcome {
        Ok(Err(_revert)) => Ok(()),
        other => bail!("expected the revert, got {other:?}"),
    }
}

/// A gateway that answers a broadcast with a 5xx may have forwarded the
/// transaction before it failed, whatever JSON-RPC error its body carries.
/// The send's outcome is unknown, so another endpoint's refusal must not
/// be reported, since fee repair sets a refused attempt aside.
#[tokio::test(flavor = "multi_thread")]
async fn a_gateway_failure_keeps_a_send_unknown() -> Result<()> {
    let gateway = endpoint(
        "504 Gateway Timeout",
        r#"{"jsonrpc":"2.0","id":"__ID__","error":{"code":-32603,"message":"upstream request timeout"}}"#,
        Duration::from_millis(300),
    )
    .await;
    let refuses = endpoint(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"__ID__","error":{"code":-32000,"message":"transaction underpriced: tip needed 30000000000, tip permitted 1000000000"}}"#,
        Duration::ZERO,
    )
    .await;
    let client = client_over(vec![gateway, refuses])?;
    let err = client
        .send_raw(Bytes::from_static(&[0x02, 0x01]))
        .await
        .expect_err("no hash comes back");
    let text = err.to_string();
    if text.to_ascii_lowercase().contains("underpriced") {
        bail!("an unknown outcome was reported as a refusal: {text}");
    }
    Ok(())
}

/// A 503 is the endpoint failing even when its body is a JSON-RPC error:
/// it is retried, counted against the endpoint, and the read moves on to
/// a live endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn a_gateway_failure_does_not_block_reads() -> Result<()> {
    let gateway = endpoint(
        "503 Service Unavailable",
        r#"{"jsonrpc":"2.0","id":"__ID__","error":{"code":-32603,"message":"no healthy upstream"}}"#,
        Duration::ZERO,
    )
    .await;
    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let client = client_over(vec![gateway, dead_endpoint()?, anvil.rpc_url()])?;
    for i in 0..5 {
        client
            .block_number()
            .await
            .map_err(|e| anyhow!("read {i}: {e}"))?;
    }
    Ok(())
}

/// A provider's requested backoff (Infura's `data.rate.backoff_seconds`)
/// is honoured only briefly, so a rate-limited endpoint does not keep a
/// read from the live endpoint after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_requested_backoff_does_not_stall_failover() -> Result<()> {
    let limited = endpoint(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"__ID__","error":{"code":-32005,"message":"daily request count exceeded, request rate limited","data":{"rate":{"backoff_seconds":30}}}}"#,
        Duration::ZERO,
    )
    .await;
    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let client = client_over(vec![limited, dead_endpoint()?, anvil.rpc_url()])?;
    let started = Instant::now();
    client.block_number().await.map_err(|e| anyhow!("{e}"))?;
    let elapsed = started.elapsed();
    if elapsed > Duration::from_secs(5) {
        bail!("the read waited {elapsed:?} on the requested backoff");
    }
    Ok(())
}

/// "already known" proves the node has the transaction, so it reports a
/// resubmission even when the other endpoint is down. The resubmit path
/// settles the attempt on it.
#[tokio::test(flavor = "multi_thread")]
async fn already_known_reports_a_send_over_a_dead_peer() -> Result<()> {
    let knows = endpoint(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"__ID__","error":{"code":-32000,"message":"already known"}}"#,
        Duration::from_millis(100),
    )
    .await;
    let client = client_over(vec![knows, dead_endpoint()?])?;
    let err = client
        .send_raw(Bytes::from_static(&[0x02, 0x01]))
        .await
        .expect_err("no hash comes back");
    let text = err.to_string();
    if !text.to_ascii_lowercase().contains("already known") {
        bail!("\"already known\" lost to the dead endpoint: {text}");
    }
    Ok(())
}

/// A batch keeps each request's own response: one reverting call does not
/// fail the others.
#[tokio::test(flavor = "multi_thread")]
async fn batch_members_get_their_own_responses() -> Result<()> {
    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let reverter = Address::repeat_byte(0xdf);
    install(&anvil.rpc_url(), reverter, ALWAYS_REVERTS).await?;
    let client = client_over(vec![anvil.rpc_url()])?;
    let provider = client.provider();
    let mut batch = alloy::rpc::client::BatchRequest::new(provider.client());
    let block = batch
        .add_call::<_, U64>("eth_blockNumber", &())
        .map_err(|e| anyhow!("{e}"))?;
    let call = batch
        .add_call::<_, Bytes>(
            "eth_call",
            &(TransactionRequest::default().to(reverter), "latest"),
        )
        .map_err(|e| anyhow!("{e}"))?;
    batch.send().await.map_err(|e| anyhow!("send batch: {e}"))?;
    block
        .await
        .map_err(|e| anyhow!("eth_blockNumber failed with its sibling: {e}"))?;
    if call.await.is_ok() {
        bail!("the reverting call succeeded");
    }
    Ok(())
}
