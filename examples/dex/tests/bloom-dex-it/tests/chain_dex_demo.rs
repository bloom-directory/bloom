//! Category: acceptance
//!
//! `chain_dex_demo.rs` — full DEX v0 acceptance test (chain spec §15 + DEX spec §15).
//!
//! Drives the local 4-validator network through the complete DEX flow.
//! Validator 0 acts as the active wallet (it holds the genesis allocation).
//!
//! Flow:
//!   1. provision 4-validator network via `bloom chain testnet`
//!   2. spawn all 4; wait for height ≥ 2
//!   3. `bloom dex deploy-suite` → wloom + factory + router
//!   4. `bloom dex deploy-token TKA` and `bloom dex deploy-token TKB`
//!   5. `bloom dex create-pair TKA TKB`
//!   6. `bloom dex add-liquidity ...` → assert reserves and LP supply
//!   7. `bloom dex swap` → assert `r0*r1 ≥ k_before`
//!   8. `bloom dex remove-liquidity` → assert tokens returned
//!   9. LOOM conservation check: sum-of-all-balances grew by exactly
//!      `committed_blocks * BLOCK_EMISSION`.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tempfile::tempdir;
use tokio::time::timeout;

use bloom_chain_node::rpc::RpcClient;
use bloom_dex_it::{
    bloom_dex_bin, current_height, derive_pair_addr, json_hex, last_json_object, locate_wasm_dir,
    mul_u256, query_account_loom, query_erc20_balance, query_pair_reserves, run_bloom_dex,
    wait_for_height, wallet_addr_for_home,
};
use bloom_it::chain_harness;

const BOOT_TIMEOUT: Duration = Duration::from_secs(20);
const CONVERGE_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCK_EMISSION: u128 = 10_000_000_000_000_000_000u128;
const GENESIS_ALLOCATION: u128 = 1_000_000_000_000_000_000_000_000u128; // 10^24

const ERC20_SUPPLY: &str = "1000000000000000000000000"; // 1M * 10^18
const ADD_LIQ_AMOUNT: &str = "100000000000000000000000"; // 100k * 10^18
const SWAP_IN: &str = "1000000000000000000000"; // 1k * 10^18

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "long-running 4-validator DEX e2e; run with `--ignored` or in CI"]
async fn dex_v0_acceptance_end_to_end() -> Result<()> {
    ensure_bloom_built()?;
    let wasm_dir = locate_wasm_dir()?;

    let dir = tempdir()?;
    let parent: PathBuf = dir.path().to_path_buf();

    // ── 1. Provision + spawn 4 validators ────────────────────────────────
    let cfgs = chain_harness::provision_network(&parent, 4)?;
    assert_eq!(cfgs.len(), 4);
    let home_0 = cfgs[0].home.clone();

    let mut guards = Vec::with_capacity(cfgs.len());
    for cfg in cfgs {
        guards.push(chain_harness::spawn_validator(cfg, BOOT_TIMEOUT).await?);
    }

    // ── 2. Wait for height ≥ 2 on validator 0 ─────────────────────────────
    let client0 = RpcClient::new(guards[0].rpc_sock());
    timeout(CONVERGE_TIMEOUT, wait_for_height(&client0, 2))
        .await
        .map_err(|_| anyhow!("validators failed to reach height 2"))??;

    // ── 3. deploy-suite (4 deploys: pair-bootstrap, wloom, factory, router) ──
    let suite_out = run_bloom_dex(
        &home_0,
        &["deploy-suite", "--wasm-dir", wasm_dir.to_str().unwrap()],
        None,
    )?;
    let suite = last_json_object(&suite_out)?;
    let factory_addr = json_hex(&suite, "factory_addr")?;
    let _router_addr = json_hex(&suite, "router_addr")?;
    let pair_petal_hash = json_hex(&suite, "pair_petal_hash")?;

    // ── 4. deploy two ERC-20 tokens ──────────────────────────────────────
    let erc20_wasm = wasm_dir.join("bloom_dex_erc20.wasm");
    let erc20_wasm_s = erc20_wasm.to_str().unwrap();
    let tka_out = run_bloom_dex(
        &home_0,
        &[
            "deploy-token",
            "--wasm",
            erc20_wasm_s,
            "--name",
            "TKA",
            "--symbol",
            "TKA",
            "--supply",
            ERC20_SUPPLY,
            "--salt",
            "00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa",
        ],
        None,
    )?;
    let tka = json_hex(&last_json_object(&tka_out)?, "token_address")?;

    let tkb_out = run_bloom_dex(
        &home_0,
        &[
            "deploy-token",
            "--wasm",
            erc20_wasm_s,
            "--name",
            "TKB",
            "--symbol",
            "TKB",
            "--supply",
            ERC20_SUPPLY,
            "--salt",
            "00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb",
        ],
        None,
    )?;
    let tkb = json_hex(&last_json_object(&tkb_out)?, "token_address")?;

    // ── 5. create-pair ────────────────────────────────────────────────────
    run_bloom_dex(
        &home_0,
        &[
            "create-pair",
            "--factory",
            &hex::encode(factory_addr),
            &hex::encode(tka),
            &hex::encode(tkb),
        ],
        None,
    )?;

    // Compute the pair address client-side using the same derivation factory does.
    let pair_addr = derive_pair_addr(&factory_addr, &tka, &tkb, &pair_petal_hash);

    // Validator 0's address — derive from its keystore.
    let wallet_addr = wallet_addr_for_home(&home_0)?;

    // ── 6. add-liquidity ─────────────────────────────────────────────────
    run_bloom_dex(
        &home_0,
        &[
            "add-liquidity",
            "--amount-a",
            ADD_LIQ_AMOUNT,
            "--amount-b",
            ADD_LIQ_AMOUNT,
            &hex::encode(tka),
            &hex::encode(tkb),
        ],
        None,
    )?;

    let (r0_after_mint, r1_after_mint) = query_pair_reserves(&client0, &pair_addr).await?;
    if r0_after_mint == 0 || r1_after_mint == 0 {
        dump_validator_logs(&guards);
        bail!("reserves zero after add-liquidity: r0={r0_after_mint} r1={r1_after_mint}");
    }
    let k_after_mint: (u128, u128) = mul_u256(r0_after_mint, r1_after_mint);

    let wallet_lp = query_erc20_balance(&client0, &pair_addr, &wallet_addr).await?;
    if wallet_lp == 0 {
        bail!("wallet LP balance is zero after add-liquidity");
    }

    // ── 7. swap ──────────────────────────────────────────────────────────
    run_bloom_dex(
        &home_0,
        &[
            "swap",
            "--amount-in",
            SWAP_IN,
            "--min-out",
            "0",
            "--path",
            &format!("{},{}", hex::encode(tka), hex::encode(tkb)),
        ],
        None,
    )?;

    let (r0_after_swap, r1_after_swap) = query_pair_reserves(&client0, &pair_addr).await?;
    let k_after_swap: (u128, u128) = mul_u256(r0_after_swap, r1_after_swap);
    if k_after_swap < k_after_mint {
        bail!(
            "x*y=k invariant violated: k_after_mint={k_after_mint:?} k_after_swap={k_after_swap:?}"
        );
    }

    // ── 8. remove-liquidity (half of LP) ─────────────────────────────────
    let half_lp = wallet_lp / 2;
    run_bloom_dex(
        &home_0,
        &[
            "remove-liquidity",
            "--liquidity",
            &half_lp.to_string(),
            &hex::encode(tka),
            &hex::encode(tkb),
        ],
        None,
    )?;

    let (r0_after_burn, r1_after_burn) = query_pair_reserves(&client0, &pair_addr).await?;
    if r0_after_burn >= r0_after_swap || r1_after_burn >= r1_after_swap {
        dump_validator_logs(&guards);
        bail!(
            "reserves did not decrease after burn: \
             before=({r0_after_swap},{r1_after_swap}) after=({r0_after_burn},{r1_after_burn})"
        );
    }

    // ── 9. LOOM conservation check ───────────────────────────────────────
    // Sum balances of all 4 validators + wallet (wallet == validator 0).
    // Total system LOOM == 4 * GENESIS_ALLOCATION + committed_blocks * BLOCK_EMISSION.
    let height = current_height(&client0).await?;
    let mut sum_loom: u128 = 0;
    for g in &guards {
        let addr = wallet_addr_for_home(g.home())?;
        let c = RpcClient::new(g.rpc_sock());
        let bal = query_account_loom(&c, &addr).await?;
        sum_loom = sum_loom
            .checked_add(bal)
            .ok_or_else(|| anyhow!("sum_loom overflow"))?;
    }
    let expected = (4u128 * GENESIS_ALLOCATION) + (height as u128) * BLOCK_EMISSION;
    if sum_loom != expected {
        bail!(
            "LOOM accounting mismatch at height {height}: sum={sum_loom} expected={expected}"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// In-process-test-only helpers
// ---------------------------------------------------------------------------

fn ensure_bloom_built() -> Result<()> {
    let bloom = chain_harness::bloom_bin();
    let bloom_dex = bloom_dex_bin();
    if bloom.exists() && bloom_dex.exists() {
        return Ok(());
    }
    let status = Command::new("cargo")
        .args(["build", "-p", "bloom", "-p", "bloom-dex-cli"])
        .status()
        .context("invoke `cargo build -p bloom -p bloom-dex-cli`")?;
    if !status.success() {
        bail!("`cargo build -p bloom -p bloom-dex-cli` failed");
    }
    Ok(())
}

/// Dump validator stderr logs to test output on failure. Each validator's
/// log file lives at `<home>/validator.stderr.log` (see chain_harness::spawn_validator).
fn dump_validator_logs(guards: &[chain_harness::ChainNodeGuard]) {
    for (i, g) in guards.iter().enumerate() {
        let log = g.home().join("validator.stderr.log");
        eprintln!("=================================================================");
        eprintln!("validator {} log: {}", i, log.display());
        eprintln!("=================================================================");
        match std::fs::read_to_string(&log) {
            Ok(contents) => {
                let needles = [
                    "deploy committed",
                    "deploy trapped",
                    "call reverted",
                    "call trapped",
                    "execute_tx",
                    "apply_block",
                    "ERROR",
                    "WARN",
                ];
                for line in contents.lines() {
                    if needles.iter().any(|n| line.contains(n)) {
                        eprintln!("{}", line);
                    }
                }
            }
            Err(e) => {
                eprintln!("(failed to read log: {e})");
            }
        }
    }
}
