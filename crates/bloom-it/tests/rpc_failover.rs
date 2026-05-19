//! Category: integration
//!
//! Integration test for the multi-endpoint failover path introduced in
//! WP-2 of the RPC robustness overhaul.
//!
//! Spawns two `anvil` instances on separate ports, builds a
//! `ChainClient` with both URLs, runs a sequence of `block_number()`
//! calls, kills the first anvil mid-loop, and asserts subsequent calls
//! still succeed via the second endpoint within < 1 s.
//!
//! Like the rest of `bloom-it`, the test is gated `#[ignore]` so CI
//! runs that lack a foundry install (or just don't want to spawn
//! processes) skip cleanly. Invoke with:
//!
//! ```text
//! cargo test -p bloom-it -- --ignored rpc_failover
//! ```

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bloom_chain::ChainClient;
use bloom_it::spawn_anvil;
use bloom_proto::ChainSpec;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn block_number_failover_when_first_anvil_dies() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_rpc=debug")),
        )
        .with_test_writer()
        .try_init();

    // Two independent anvils, each on its own port.
    let mut anvil_a = spawn_anvil().await.context("spawn anvil A")?;
    let anvil_b = spawn_anvil().await.context("spawn anvil B")?;

    let url_a = anvil_a.rpc_url();
    let url_b = anvil_b.rpc_url();

    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![url_a.clone(), url_b.clone()];
    let client = ChainClient::new(spec).map_err(|e| anyhow!("build chain client: {e}"))?;

    // Warm-up: confirm the client can reach the first anvil.
    let _ = client
        .block_number()
        .await
        .context("initial block_number sanity call")?;

    // Run 25 calls before the kill, then kill anvil A and run 25 more.
    // The fallback layer queries the top two transports in parallel,
    // so even before the kill both anvils see traffic.
    for _ in 0..25 {
        client
            .block_number()
            .await
            .context("pre-kill block_number")?;
    }

    // Kill anvil A. Drop the guard so any background readers stop.
    if let Some(mut child) = anvil_a.take_child() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    // First post-kill call must still succeed via anvil B within 1 s.
    let started = Instant::now();
    let res = timeout(Duration::from_secs(1), client.block_number()).await;
    let elapsed = started.elapsed();
    res.map_err(|_| anyhow!("post-kill block_number timed out after {elapsed:?}"))?
        .map_err(|e| anyhow!("post-kill block_number failed: {e}"))?;

    // 24 more calls — every one must succeed.
    for i in 0..24 {
        client
            .block_number()
            .await
            .with_context(|| format!("post-kill block_number iteration {i}"))?;
    }

    drop(anvil_b);
    Ok(())
}
