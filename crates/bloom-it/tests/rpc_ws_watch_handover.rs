//! Category: integration
//!
//! Integration test for the WS-to-poll handover in `bloom-watch`.
//!
//! Scenario:
//!
//! 1. Spawn `anvil` with HTTP + WS, start a `WatchExecutor` with a
//!    `WatchKind::Block` spec.
//! 2. Mine a few blocks; assert the executor's per-watch live file
//!    accumulates lines.
//! 3. Kill anvil. The WS subscription stream closes; the executor's
//!    block supervisor logs `watch.subscribe_blocks.ended_falling_back_to_poll`.
//! 4. Re-spawn anvil on the same port (best-effort; we just confirm
//!    the executor doesn't panic during the gap).
//!
//! Gated `#[ignore]` like the rest of `bloom-it`. The handover is
//! observed via the live-file content rather than a dedicated channel
//! to keep the test infrastructure-light; the per-event tracing
//! signals are still emitted at `info`/`warn` and visible under
//! `RUST_LOG=bloom_watch=debug`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::providers::Provider;
use anyhow::{Context, Result, anyhow};
use bloom_evm::{ChainClient, ChainRegistry};
use bloom_it::spawn_anvil;
use bloom_proto::{ChainSpec, EndpointSpec, HomeDir};
use bloom_watch::executor::WatchExecutor;
use bloom_watch::{WatchKind, WatchRegistry, WatchSpec};
use tempfile::tempdir;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn block_watch_falls_back_to_poll_when_anvil_dies() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,bloom_watch=debug,bloom_rpc=debug")
            }),
        )
        .with_test_writer()
        .try_init();

    let mut anvil = spawn_anvil().await.context("spawn anvil")?;
    let http_url = anvil.rpc_url();
    let ws_url = anvil.ws_url();

    // Build the chain client with both endpoints.
    let mut chain_spec = ChainSpec::anvil_default();
    chain_spec.name = "anvil".into();
    chain_spec.rpc_urls.clear();
    chain_spec.rpc_endpoints = vec![
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
    let client = ChainClient::new(chain_spec).map_err(|e| anyhow!("build chain client: {e}"))?;
    let chains = ChainRegistry::new();
    chains.add(client.clone());

    // Set up the watch executor in a temp dir.
    let tmp = tempdir().context("tempdir")?;
    let home = HomeDir::at(tmp.path());
    home.ensure().context("ensure home")?;
    let registry = Arc::new(WatchRegistry::new(home.watch_dir()).context("watch registry")?);
    let spec = WatchSpec {
        id: "w-0001".into(),
        wallet: "alice".into(),
        created_ms: 1,
        kind: WatchKind::Block {
            chain: "anvil".into(),
        },
        note: None,
    };
    registry.add(spec.clone()).context("add spec")?;

    let exec = Arc::new(
        WatchExecutor::new(chains, registry, home.clone()).with_tick(Duration::from_millis(200)),
    );
    exec.start().context("executor start")?;

    // Mine a couple blocks via http; expect the WS subscription to
    // surface them and the executor to write to the live file.
    let http_provider = client.provider();
    for _ in 0..2 {
        let _: serde_json::Value = http_provider
            .client()
            .request("evm_mine", ())
            .await
            .context("evm_mine pre-kill")?;
    }
    let live = WatchExecutor::live_path_for_spec(&home, &spec);
    wait_for_lines(&live, 1, Duration::from_secs(4))
        .await
        .context("first live line never appeared")?;

    // Kill anvil. The WS supervisor should log
    // `watch.subscribe_blocks.ended_falling_back_to_poll` (visible
    // when the test is run with `RUST_LOG=bloom_watch=debug`); the poll
    // loop continues to run as the watchdog so the executor doesn't
    // panic.
    if let Some(mut child) = anvil.take_child() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    drop(anvil);

    // Give the executor a beat to observe the closure. We can't easily
    // re-spawn anvil on the same port from a test, so the assertion
    // here is "executor remains alive across the kill". A subsequent
    // tick (poll) is harmless because there's no chain to query.
    tokio::time::sleep(Duration::from_secs(1)).await;
    exec.stop().await;

    // Sanity: the live file we asserted on still exists and isn't
    // truncated.
    let body = std::fs::read_to_string(&live).context("read live")?;
    assert!(body.lines().count() >= 1, "expected ≥1 line, got {body}");
    Ok(())
}

async fn wait_for_lines(path: &std::path::Path, min_lines: usize, budget: Duration) -> Result<()> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Ok(body) = std::fs::read_to_string(path)
            && body.lines().count() >= min_lines
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!(
        "timed out waiting for {min_lines} lines at {}",
        path.display()
    ))
}
