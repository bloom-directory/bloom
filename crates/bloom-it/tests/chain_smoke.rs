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
use futures::future::try_join_all;
use serde_json::json;
use tempfile::tempdir;
use tokio::time::{Instant, sleep};

use bloom_chain_node::RpcClient;
use bloom_it::chain_harness;

const TARGET_HEIGHT: u64 = 5;
const BOOT_TIMEOUT: Duration = Duration::from_secs(20);
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(120);

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
    let guards = try_join_all(cfgs.into_iter().map(|cfg| async move {
        chain_harness::spawn_validator(cfg, BOOT_TIMEOUT)
            .await
            .context("spawn_validator")
    }))
    .await?;

    // 3. Poll each node's RPC until all four report a committed block at
    //    `TARGET_HEIGHT`.  Collect the state_roots and assert agreement.
    let roots = wait_for_convergence(&guards, TARGET_HEIGHT, CONVERGE_TIMEOUT).await?;

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
    converge_timeout: Duration,
) -> Result<Vec<String>> {
    let deadline = Instant::now() + converge_timeout;
    loop {
        let mut roots = Vec::with_capacity(guards.len());
        let mut all_at_height = true;
        let mut observation = Vec::with_capacity(guards.len());

        for (i, g) in guards.iter().enumerate() {
            let client = RpcClient::new(g.rpc_sock());
            let tip = client
                .call("chain_tip", json!({}))
                .await
                .ok()
                .and_then(|v| v.get("height").and_then(serde_json::Value::as_u64));
            match client
                .call("chain_query_block", json!({ "height": target_height }))
                .await
            {
                Ok(v) => {
                    if v.is_null() {
                        observation.push(format!("node[{i}] tip={tip:?} block=null"));
                        all_at_height = false;
                        break;
                    }
                    let root = v
                        .get("state_root")
                        .and_then(|x| x.as_str())
                        .ok_or_else(|| anyhow!("node[{i}] returned block without state_root"))?
                        .to_string();
                    observation.push(format!("node[{i}] tip={tip:?} root={root}"));
                    roots.push(root);
                }
                Err(e) => {
                    observation.push(format!("node[{i}] tip={tip:?} err={e}"));
                    all_at_height = false;
                    break;
                }
            }
        }
        let observation = observation.join("; ");

        if all_at_height && roots.len() == guards.len() {
            return Ok(roots);
        }
        if Instant::now() >= deadline {
            let log_tails = validator_log_tails(guards);
            return Err(anyhow!(
                "timeout waiting for height {target_height} on all nodes; last observation: {observation}; log tails:\n{log_tails}"
            ));
        }

        sleep(Duration::from_millis(250)).await;
    }
}

fn validator_log_tails(guards: &[chain_harness::ChainNodeGuard]) -> String {
    guards
        .iter()
        .enumerate()
        .map(|(i, g)| {
            let stderr = g.home().join("validator.stderr.log");
            format!("node[{i}] stderr tail:\n{}", tail_file(&stderr, 40))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn tail_file(path: &std::path::Path, max_lines: usize) -> String {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let lines = contents.lines().collect::<Vec<_>>();
            let start = lines.len().saturating_sub(max_lines);
            lines[start..].join("\n")
        }
        Err(e) => format!("failed to read {}: {e}", path.display()),
    }
}

fn ensure_bloom_built() -> Result<()> {
    let status = std::process::Command::new("cargo")
        .args(["build", "-p", "bloom", "--bin", "bloom"])
        .status()
        .context("invoke `cargo build -p bloom`")?;
    if !status.success() {
        return Err(anyhow!("`cargo build -p bloom` failed"));
    }
    Ok(())
}
