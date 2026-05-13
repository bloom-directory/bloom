//! Integration test for the WebSocket subscription fast path
//! introduced in WP-4 of the RPC robustness overhaul.
//!
//! Spawns an `anvil` instance, builds a `ChainClient` whose
//! `EndpointSpec` list contains the `ws://` URL, opens
//! `subscribe_blocks()` against the lazily-constructed WS provider,
//! mines three blocks via `evm_mine`, and asserts three headers
//! arrive within the budget.
//!
//! Gated `#[ignore]` to match the rest of `bloom-it`. Run with:
//!
//! ```text
//! cargo test -p bloom-it -- --ignored rpc_ws_subscriptions
//! ```
//!
//! Skips if `anvil` is not on `$PATH` (the spawn helper times out and
//! the test fails — same convention as the other bloom-it tests).
//! See `docs/specs/rpc-robustness.md` §C.4 / §F.2 for the WS
//! lifecycle decisions this exercises.

use std::time::Duration;

use alloy::providers::Provider;
use anyhow::{Context, Result, anyhow};
use bloom_chain::ChainClient;
use bloom_it::spawn_anvil;
use bloom_proto::{ChainSpec, EndpointSpec};
use futures::StreamExt;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn ws_subscribe_blocks_against_anvil() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,bloom_rpc=debug,bloom_watch=debug")
            }),
        )
        .with_test_writer()
        .try_init();

    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let http_url = anvil.rpc_url();
    let ws_url = anvil.ws_url();

    // Two endpoints: HTTP for fallback / one-shot calls, WS for
    // subscriptions. Use the rich `rpc_endpoints` form so the engine
    // sees both schemes.
    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls.clear();
    spec.rpc_endpoints = vec![
        EndpointSpec {
            url: http_url.clone(),
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: true,
        },
        EndpointSpec {
            url: ws_url.clone(),
            weight: 100,
            cu_per_sec: None,
            max_rps: None,
            http_only: false,
        },
    ];

    let client = ChainClient::new(spec).map_err(|e| anyhow!("build chain client: {e}"))?;
    assert!(
        client.supports_subscriptions(),
        "expected supports_subscriptions == true with a ws endpoint"
    );

    let ws_provider = client
        .ws_provider()
        .await
        .ok_or_else(|| anyhow!("ws_provider returned None"))?;

    let sub = ws_provider
        .subscribe_blocks()
        .await
        .context("open subscribe_blocks")?;
    let mut stream = sub.into_stream().take(3);

    // Mine three blocks via the HTTP endpoint. We use the generic raw
    // request path so the test doesn't need the anvil-typed helpers.
    let http_provider = client.provider();
    for _ in 0..3 {
        let _: serde_json::Value = http_provider
            .client()
            .request("evm_mine", ())
            .await
            .context("evm_mine via http provider")?;
    }

    let mut received = 0usize;
    timeout(Duration::from_secs(5), async {
        while let Some(_header) = stream.next().await {
            received += 1;
        }
    })
    .await
    .map_err(|_| anyhow!("only received {received}/3 headers within 5 s"))?;

    assert_eq!(received, 3, "expected 3 headers, got {received}");
    drop(anvil);
    Ok(())
}
