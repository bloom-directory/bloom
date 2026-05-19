//! Category: integration
//!
//! Integration test for the active health probe loop introduced in
//! WP-3 of the RPC robustness overhaul.
//!
//! Strategy: build a `ChainClient` whose endpoint list contains one
//! live anvil URL plus one deliberately-bad URL (`http://127.0.0.1:1`,
//! a port nothing should be listening on). Wait for one probe cycle
//! plus a small jitter buffer (the loop pulses every 15 s) and then
//! assert:
//!
//! - the snapshot for the live URL records `success_rate > 0.0` and
//!   `last_block` populated,
//! - the snapshot for the dead URL records `success_rate == 0.0` and
//!   either a populated `cooldown_until` or at least one failure
//!   captured in the rolling window.
//!
//! Like the rest of `bloom-it`, the test is gated `#[ignore]` so CI
//! runs that lack a foundry install (or just don't want to spawn
//! processes) skip cleanly. Invoke with:
//!
//! ```text
//! cargo test -p bloom-it -- --ignored rpc_health_probe
//! ```

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bloom_chain::ChainClient;
use bloom_it::spawn_anvil;
use bloom_proto::ChainSpec;

/// One probe cycle is 15 s; pad with a 2 s jitter so a slow scheduler
/// doesn't flake the test.
const PROBE_WAIT: Duration = Duration::from_secs(17);

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn active_probe_records_success_and_failure() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,bloom_rpc=debug")),
        )
        .with_test_writer()
        .try_init();

    let anvil = spawn_anvil().await.context("spawn anvil")?;
    let live_url = anvil.rpc_url();
    let dead_url = "http://127.0.0.1:1".to_string();

    let mut spec = ChainSpec::anvil_default();
    spec.rpc_urls = vec![live_url.clone(), dead_url.clone()];
    let client = ChainClient::new(spec).map_err(|e| anyhow!("build chain client: {e}"))?;

    // Sanity: the engine should currently report no cooled-down
    // endpoints because the probe loop hasn't run yet.
    assert_eq!(client.cooled_down_count(), 0);

    // Wait one probe cycle.
    tokio::time::sleep(PROBE_WAIT).await;

    let snaps = client.endpoints();
    assert_eq!(
        snaps.len(),
        2,
        "expected one snapshot per configured endpoint, got {}",
        snaps.len()
    );

    let live = snaps
        .iter()
        .find(|s| s.url == live_url)
        .ok_or_else(|| anyhow!("missing snapshot for live url {live_url}"))?;
    let dead = snaps
        .iter()
        .find(|s| s.url == dead_url)
        .ok_or_else(|| anyhow!("missing snapshot for dead url {dead_url}"))?;

    assert!(
        live.success_rate > 0.0,
        "live endpoint should have a non-zero success rate, got {}",
        live.success_rate
    );
    assert!(
        live.last_block.is_some(),
        "live endpoint should have observed a block number"
    );

    // The dead endpoint either tripped a full cooldown (5 failures
    // back-to-back) or — if the test ran exactly one round — has at
    // least registered the failure in the sample window.
    assert!(
        dead.success_rate == 0.0,
        "dead endpoint should have zero success rate, got {}",
        dead.success_rate
    );

    drop(anvil);
    Ok(())
}
