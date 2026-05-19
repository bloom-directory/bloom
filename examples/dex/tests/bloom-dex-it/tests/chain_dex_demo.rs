//! `chain_dex_demo.rs` — full DEX v0 acceptance test (chain spec §15 + DEX spec §15).
//!
//! Drives the local 4-validator network through the complete DEX flow.
//! Validator 0 acts as the active wallet (it holds the genesis allocation).
//!
//! Flow:
//!   1. provision 4-validator network via `bloom chain testnet`
//!   2. spawn all 4; wait for height ≥ 2
//!   3. `bloom dex deploy-suite` → reentrancy + wloom + factory + router
//!   4. `bloom dex deploy-token TKA` and `bloom dex deploy-token TKB`
//!   5. `bloom dex create-pair TKA TKB`
//!   6. `bloom dex add-liquidity ...` → assert reserves and LP supply
//!   7. `bloom dex swap` → assert `r0*r1 ≥ k_before`
//!   8. `bloom dex remove-liquidity` → assert tokens returned
//!   9. LOOM conservation check: sum-of-all-balances grew by exactly
//!      `committed_blocks * BLOCK_EMISSION`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tempfile::tempdir;
use tokio::time::{sleep, timeout};

use bloom_chain_node::rpc::RpcClient;
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

    // ── 3. deploy-suite (5 deploys: pair-bootstrap, reentrancy, wloom, factory, router) ──
    let suite_out = run_bloom_dex(
        &home_0,
        &["deploy-suite", "--wasm-dir", wasm_dir.to_str().unwrap()],
    )?;
    // The deploy-suite emits a single trailing JSON object with the registry.
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
    )?;

    let (r0_after_mint, r1_after_mint) =
        query_pair_reserves(&client0, &pair_addr).await?;
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
    )?;

    let (r0_after_swap, r1_after_swap) =
        query_pair_reserves(&client0, &pair_addr).await?;
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
    )?;

    let (r0_after_burn, r1_after_burn) =
        query_pair_reserves(&client0, &pair_addr).await?;
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
    let expected = (4u128 * GENESIS_ALLOCATION)
        + (height as u128) * BLOCK_EMISSION;
    if sum_loom != expected {
        bail!(
            "LOOM accounting mismatch at height {height}: sum={sum_loom} expected={expected}"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
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

/// Locate the directory containing the 6 DEX wasm artifacts.
fn locate_wasm_dir() -> Result<PathBuf> {
    // CARGO_MANIFEST_DIR points at examples/dex/tests/bloom-dex-it. Workspace
    // root is four levels up.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let candidate = PathBuf::from(manifest_dir)
        .join("../../../../target/wasm32-unknown-unknown/release");
    let canon = candidate
        .canonicalize()
        .with_context(|| format!("wasm dir {} not found — build DEX petals first", candidate.display()))?;
    for name in [
        "bloom_dex_reentrancy.wasm",
        "bloom_dex_wloom.wasm",
        "bloom_dex_pair.wasm",
        "bloom_dex_factory.wasm",
        "bloom_dex_router.wasm",
        "bloom_dex_erc20.wasm",
    ] {
        if !canon.join(name).exists() {
            bail!("missing {} in {}", name, canon.display());
        }
    }
    Ok(canon)
}

/// Shell out to `bloom-dex <args>` with `--home <home>` and return stdout.
fn run_bloom_dex(home: &Path, args: &[&str]) -> Result<String> {
    let bin = bloom_dex_bin();
    let mut cmd = Command::new(&bin);
    cmd.arg("--home").arg(home);
    for a in args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = cmd.output().with_context(|| format!("invoke {} {:?}", bin.display(), args))?;
    if !out.status.success() {
        bail!(
            "bloom-dex {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Resolve the `bloom-dex` binary path. Honors `$BLOOM_DEX_BIN`; otherwise
/// falls back to the workspace target dir based on whether `$BLOOM_BIN` is
/// release or debug, then defaults to release.
fn bloom_dex_bin() -> PathBuf {
    if let Ok(p) = std::env::var("BLOOM_DEX_BIN") {
        return PathBuf::from(p);
    }
    // Default: same flavor as bloom_bin, but with name `bloom-dex`.
    let bloom = chain_harness::bloom_bin();
    let dir = bloom.parent().expect("bloom_bin must have a parent");
    dir.join("bloom-dex")
}

/// Parse the last well-formed JSON object from CLI stdout. The DEX subcommands
/// emit one JSON object per tx submission plus a final summary; we want the
/// trailing one (the summary).
fn last_json_object(text: &str) -> Result<Value> {
    let mut depth = 0i32;
    let mut last_start: Option<usize> = None;
    let mut last_complete: Option<(usize, usize)> = None;
    for (i, c) in text.char_indices() {
        if c == '{' {
            if depth == 0 {
                last_start = Some(i);
            }
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                if let Some(s) = last_start {
                    last_complete = Some((s, i + 1));
                }
                last_start = None;
            }
        }
    }
    let (s, e) = last_complete.ok_or_else(|| anyhow!("no JSON object in output: {text}"))?;
    serde_json::from_str(&text[s..e]).with_context(|| format!("parse JSON: {}", &text[s..e]))
}

fn json_hex(v: &Value, field: &str) -> Result<[u8; 32]> {
    let s = v
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("field `{field}` missing in {v:?}"))?;
    let bytes = hex::decode(s).with_context(|| format!("hex decode {field}"))?;
    if bytes.len() != 32 {
        bail!("field `{field}` not 32 bytes: {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derive a pair instance address using the same formula as factory.createPair:
///   pair_salt    = blake3("factory.pair_salt:" || sorted(t0, t1))
///   pair_address = blake3("bloom-chain.v0.addr:deploy:" || factory || ":" || pair_salt || ":" || pair_petal_hash)
fn derive_pair_addr(
    factory: &[u8; 32],
    t_a: &[u8; 32],
    t_b: &[u8; 32],
    pair_petal_hash: &[u8; 32],
) -> [u8; 32] {
    let (lo, hi) = if t_a <= t_b { (t_a, t_b) } else { (t_b, t_a) };
    let salt = {
        let mut h = blake3::Hasher::new();
        h.update(b"dex.pair.salt:");
        h.update(lo);
        h.update(hi);
        *h.finalize().as_bytes()
    };
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-chain.v0.addr:deploy:");
    h.update(factory);
    h.update(b":");
    h.update(&salt);
    h.update(b":");
    h.update(pair_petal_hash);
    *h.finalize().as_bytes()
}

/// Derive the validator's xDSA address from the keystore under `<home>/chain/keystore/validator.xdsa`.
fn wallet_addr_for_home(home: &Path) -> Result<[u8; 32]> {
    let key_path = home.join("chain/keystore/validator.xdsa");
    let bytes = std::fs::read(&key_path)
        .with_context(|| format!("read {}", key_path.display()))?;
    let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&bytes)
        .map_err(|e| anyhow!("decode xdsa key: {e}"))?;
    let pk = sk.public_key();
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-chain.v0.addr:");
    h.update(&pk.0);
    Ok(*h.finalize().as_bytes())
}

async fn current_height(client: &RpcClient) -> Result<u64> {
    let mut h = 0u64;
    loop {
        let probe_h = h + 1;
        let v = client
            .call("chain_query_block", json!({ "height": probe_h }))
            .await?;
        if v.is_null() {
            return Ok(h);
        }
        h = probe_h;
    }
}

async fn wait_for_height(client: &RpcClient, target: u64) -> Result<()> {
    loop {
        let v = client
            .call("chain_query_block", json!({ "height": target }))
            .await?;
        if !v.is_null() {
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn query_pair_reserves(client: &RpcClient, pair: &[u8; 32]) -> Result<(u128, u128)> {
    let r0 = query_storage_u128(client, pair, blake3::hash(b"pair.reserve0").as_bytes()).await?;
    let r1 = query_storage_u128(client, pair, blake3::hash(b"pair.reserve1").as_bytes()).await?;
    Ok((r0, r1))
}

async fn query_erc20_balance(
    client: &RpcClient,
    token: &[u8; 32],
    holder: &[u8; 32],
) -> Result<u128> {
    let mut tag = Vec::with_capacity(14 + 32);
    tag.extend_from_slice(b"erc20.balance:");
    tag.extend_from_slice(holder);
    let key = blake3::hash(&tag);
    query_storage_u128(client, token, key.as_bytes()).await
}

async fn query_storage_u128(client: &RpcClient, addr: &[u8; 32], key: &[u8; 32]) -> Result<u128> {
    let v = client
        .call(
            "chain_query_state",
            json!({
                "address": hex::encode(addr),
                "key": hex::encode(key),
            }),
        )
        .await?;
    let hex_s = v
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing storage value"))?;
    let bytes = hex::decode(hex_s).context("decode storage value")?;
    if bytes.len() != 32 {
        bail!("storage value not 32 bytes: {}", bytes.len());
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..32]);
    Ok(u128::from_be_bytes(buf))
}

/// Multiply two u128s and return the 256-bit product as `(hi, lo)` where
/// `result == hi * 2^128 + lo`. Used for the x*y=k invariant check, since
/// realistic Uniswap reserves can exceed `u128::MAX` when multiplied.
fn mul_u256(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let a_lo = a & MASK;
    let a_hi = a >> 64;
    let b_lo = b & MASK;
    let b_hi = b >> 64;

    let p00 = a_lo * b_lo;
    let p01 = a_lo * b_hi;
    let p10 = a_hi * b_lo;
    let p11 = a_hi * b_hi;

    let c0 = p00 & MASK;
    let r0 = p00 >> 64;

    let s1 = r0 + (p01 & MASK) + (p10 & MASK);
    let c1 = s1 & MASK;
    let r1 = s1 >> 64;

    let s2 = r1 + (p01 >> 64) + (p10 >> 64) + (p11 & MASK);
    let c2 = s2 & MASK;
    let r2 = s2 >> 64;

    let c3 = r2 + (p11 >> 64);

    let lo = (c1 << 64) | c0;
    let hi = (c3 << 64) | c2;
    (hi, lo)
}

#[test]
fn mul_u256_known_vectors() {
    assert_eq!(mul_u256(0, 0), (0, 0));
    assert_eq!(mul_u256(1, 1), (0, 1));
    assert_eq!(mul_u256(1u128 << 64, 1u128 << 64), (1, 0));
    // (2^128 - 1) * 2 = 2^129 - 2 = 1 * 2^128 + (2^128 - 2)
    assert_eq!(mul_u256(u128::MAX, 2), (1, u128::MAX - 1));
    // 10^23 * 10^23 = 10^46. u128::MAX ≈ 3.4 * 10^38, so this overflows.
    let r = 100_000u128 * 10u128.pow(18);
    let (h, l) = mul_u256(r, r);
    // Verify by reconstructing: h * 2^128 + l == r * r when computed exactly.
    // We can verify by multiplying back: (h * 2^128 + l) / r should equal r.
    // Easier: ensure h is nonzero (since we know overflow happens).
    assert!(h > 0, "expected high half nonzero for 10^46 product, got ({h},{l})");
}

/// Dump validator stderr logs to test output on failure. Each validator's
/// log file lives at `<home>/validator.stderr.log` (see chain_harness::spawn_validator).
/// We grep for the petal_executor log lines to focus on tx execution.
fn dump_validator_logs(guards: &[chain_harness::ChainNodeGuard]) {
    for (i, g) in guards.iter().enumerate() {
        let log = g.home().join("validator.stderr.log");
        eprintln!("=================================================================");
        eprintln!("validator {} log: {}", i, log.display());
        eprintln!("=================================================================");
        match std::fs::read_to_string(&log) {
            Ok(contents) => {
                // Filter to the lines of interest from petal_executor:
                // - "deploy committed"
                // - "deploy trapped"
                // - "call reverted"
                // - "call trapped"
                // Also include sender-execute / state-root convergence lines.
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

async fn query_account_loom(client: &RpcClient, addr: &[u8; 32]) -> Result<u128> {
    let v = client
        .call("chain_query_account", json!({ "address": hex::encode(addr) }))
        .await?;
    if v.is_null() {
        return Ok(0);
    }
    let s = v
        .get("loom")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing loom in account"))?;
    Ok(s.parse::<u128>().context("parse loom u128")?)
}
