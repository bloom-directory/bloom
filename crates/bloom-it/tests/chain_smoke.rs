//! Category: smoke
//!
//! `chain_smoke.rs` — 4-validator local network smoke test (spec §15 minus DEX).
//!
//! Acceptance: spawn four validator nodes via `bloom chain run-validator`,
//! wait for block height ≥ 5 on every node, assert all four agree on the
//! state_root for height 5.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde_json::json;
use tempfile::tempdir;
use tokio::time::{sleep, timeout};

use bloom_chain_node::RpcClient;
use bloom_it::chain_harness;

const TARGET_HEIGHT: u64 = 5;
const BOOT_TIMEOUT: Duration = Duration::from_secs(20);
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(45);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "spawns 4 long-running validator processes; run with `--ignored` or in CI"]
async fn four_validator_state_root_convergence() -> Result<()> {
    ensure_bloom_built()?;

    let dir = tempdir()?;
    let parent: PathBuf = dir.path().to_path_buf();

    // 1. Provision 4 validators (genesis + per-node config + keystores).
    let cfgs = chain_harness::provision_network(&parent, 4).context("provision_network(4)")?;
    assert_eq!(cfgs.len(), 4);

    // 2. Spawn each validator.  Hold the guards for the whole test so the
    //    children get killed on drop.
    let mut guards = Vec::with_capacity(cfgs.len());
    for cfg in cfgs {
        let g = chain_harness::spawn_validator(cfg, BOOT_TIMEOUT)
            .await
            .context("spawn_validator")?;
        guards.push(g);
    }

    // 3. Poll each node's RPC until all four report a committed block at
    //    `TARGET_HEIGHT`.  Collect the state_roots and assert agreement.
    let roots = timeout(
        CONVERGE_TIMEOUT,
        wait_for_convergence(&guards, TARGET_HEIGHT),
    )
    .await
    .map_err(|_| anyhow!("timeout waiting for height {TARGET_HEIGHT} on all nodes"))??;

    let first = &roots[0];
    for (i, r) in roots.iter().enumerate().skip(1) {
        if r != first {
            return Err(anyhow!(
                "state_root divergence at height {TARGET_HEIGHT}: node[0]={first} node[{i}]={r}"
            ));
        }
    }

    Ok(())
}

async fn wait_for_convergence(
    guards: &[chain_harness::ChainNodeGuard],
    target_height: u64,
) -> Result<Vec<String>> {
    loop {
        let mut roots = Vec::with_capacity(guards.len());
        let mut all_at_height = true;

        for (i, g) in guards.iter().enumerate() {
            let client = RpcClient::new(g.rpc_sock());
            match client
                .call("chain_query_block", json!({ "height": target_height }))
                .await
            {
                Ok(v) => {
                    if v.is_null() {
                        all_at_height = false;
                        break;
                    }
                    let root = v
                        .get("state_root")
                        .and_then(|x| x.as_str())
                        .ok_or_else(|| anyhow!("node[{i}] returned block without state_root"))?
                        .to_string();
                    roots.push(root);
                }
                Err(_) => {
                    all_at_height = false;
                    break;
                }
            }
        }

        if all_at_height && roots.len() == guards.len() {
            return Ok(roots);
        }

        sleep(Duration::from_millis(250)).await;
    }
}

fn ensure_bloom_built() -> Result<()> {
    let bin = chain_harness::bloom_bin();
    if bin.exists() {
        return Ok(());
    }
    // Force a build if the binary isn't there yet.
    let status = std::process::Command::new("cargo")
        .args(["build", "-p", "bloom", "--bin", "bloom"])
        .status()
        .context("invoke `cargo build -p bloom`")?;
    if !status.success() {
        return Err(anyhow!("`cargo build -p bloom` failed"));
    }
    Ok(())
}
