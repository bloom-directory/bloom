//! Category: docker-acceptance
//!
//! `docker_dex_multi_user.rs` — multi-user DEX acceptance test against a
//! docker-compose 4-validator network.
//!
//! Drives the v0 DEX through a realistic multi-user scenario:
//!   - Alice provides liquidity.
//!   - Bob and Carol each swap on the same pool in opposite directions.
//!   - Alice removes all liquidity and must come out ahead of her deposits
//!     (LP fees earned from Bob's and Carol's swaps).
//!   - LOOM conservation: sum across users + validators changes only by
//!     per-block emission.
//!
//! Driving model:
//!   - The compose stack runs 4 validators (val0..val3), each binding TCP
//!     JSON-RPC on container port 8545, exposed to host ports 18545..18548.
//!   - The script `scripts/test-docker-dex.sh` provisions homes on the host
//!     under `$BLOOM_DOCKER_TMPDIR/home<i>` and `docker compose up --wait`s
//!     the stack. We attach to that running stack here.
//!   - Each user has their own `BLOOM_HOME` directory on the host, containing
//!     a fresh xDSA keystore + a copy of the shared genesis.toml. Users sign
//!     locally; CLIs talk to validators via TCP (`BLOOM_RPC_TCP` env var).
//!
//! Set `BLOOM_DOCKER_TMPDIR` to the provisioner output dir. The script does
//! this automatically; for ad-hoc runs, point it at any host tmpdir that
//! contains the 4 validator homes.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::time::{sleep, timeout};

use bloom_chain_node::rpc::RpcClient;
use bloom_dex_it::{
    current_height, derive_pair_addr, json_hex, last_json_object, locate_wasm_dir, mul_u256,
    pro_rata, query_account_loom, query_erc20_balance, query_nonce, query_pair_reserves,
    query_storage_u128, reserves_by_token, run_bloom_dex, uniswap_get_amount_out, wait_for_height,
    wallet_addr_for_home,
};

// ---------------------------------------------------------------------------
// Constants — keep in sync with scripts/test-docker-dex.sh
// ---------------------------------------------------------------------------

const HOST_RPC_PORTS: [u16; 4] = [18545, 18546, 18547, 18548];
const BLOCK_EMISSION: u128 = 10_000_000_000_000_000_000u128; // 10 LOOM per block
const GENESIS_ALLOCATION: u128 = 1_000_000_000_000_000_000_000_000u128; // 10^24 = 1M LOOM
const N_VALIDATORS: usize = 4;

// Per-user funding (must cover gas + deployments + add-liquidity).
const USER_LOOM_FUND: u128 = 100_000_000_000_000_000_000_000u128; // 100k LOOM

// Token economics for the test pool.
const ERC20_SUPPLY: &str = "1000000000000000000000000"; // 1M * 10^18
const ALICE_LIQ_A: u128 = 100_000_000_000_000_000_000_000u128; // 100k * 10^18
const ALICE_LIQ_B: u128 = 100_000_000_000_000_000_000_000u128; // 100k * 10^18
const BOB_SWAP_IN: u128 = 1_000_000_000_000_000_000_000u128; // 1k * 10^18
const CAROL_SWAP_IN: u128 = 1_500_000_000_000_000_000_000u128; // 1.5k * 10^18

const READINESS_TIMEOUT: Duration = Duration::from_secs(60);
const TX_TIMEOUT: Duration = Duration::from_secs(45);

// ---------------------------------------------------------------------------
// User identity
// ---------------------------------------------------------------------------

/// A test user with their own keystore + RPC endpoint.
struct User {
    name: &'static str,
    home: PathBuf,
    addr: [u8; 32],
    rpc_tcp: String, // "127.0.0.1:18545"
}

// ---------------------------------------------------------------------------
// Top-level test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires docker-compose stack; run via scripts/test-docker-dex.sh"]
async fn docker_dex_multi_user_acceptance() -> Result<()> {
    let tmpdir = compose_tmpdir()?;
    let wasm_dir = locate_wasm_dir()?;
    let genesis_path = tmpdir.join("home0").join("chain").join("genesis.toml");
    if !genesis_path.exists() {
        bail!(
            "missing {} — did `bloom chain testnet` run? (provision homes first)",
            genesis_path.display()
        );
    }

    // ── 1. Wait for stack readiness (height >= 2 on every validator) ──────
    let validator_clients: Vec<RpcClient> = HOST_RPC_PORTS
        .iter()
        .map(|p| RpcClient::tcp(format!("127.0.0.1:{}", p)))
        .collect();
    for (i, c) in validator_clients.iter().enumerate() {
        timeout(READINESS_TIMEOUT, wait_for_height(c, 2))
            .await
            .map_err(|_| anyhow!("validator {} did not reach height 2 via TCP", i))??;
    }
    // Pick val0 as our query client (any validator works after gossip).
    let client0 = &validator_clients[0];

    // ── 2. Resolve treasury (validator 0) + create 3 user identities ──────
    let treasury_home = tmpdir.join("home0");
    let treasury_addr = wallet_addr_for_home(&treasury_home)?;
    let users_root = tmpdir.join("users");
    std::fs::create_dir_all(&users_root)?;

    let alice = create_user("alice", &users_root, &genesis_path, HOST_RPC_PORTS[0])?;
    let bob = create_user("bob", &users_root, &genesis_path, HOST_RPC_PORTS[1])?;
    let carol = create_user("carol", &users_root, &genesis_path, HOST_RPC_PORTS[2])?;

    // ── 3. Fund each user from the treasury (validator 0 holds genesis) ──
    let treasury_rpc = format!("127.0.0.1:{}", HOST_RPC_PORTS[0]);
    let mut treasury_nonce: u64 = query_nonce(client0, &treasury_addr).await?;
    for user in [&alice, &bob, &carol] {
        run_bloom_chain_transfer(
            &treasury_home,
            &treasury_rpc,
            &user.addr,
            USER_LOOM_FUND,
            treasury_nonce,
        )?;
        treasury_nonce += 1;
        // Wait for the funding to land *on every validator* — not just val0.
        // Bob's CLI talks to val1, Carol's to val2; if we only check val0 we
        // race against gossip and the user's tx gets admitted before that
        // validator has applied the block where their balance was credited,
        // leading to "insufficient balance: have 0" mempool rejections.
        for c in &validator_clients {
            wait_for_account_loom(c, &user.addr, USER_LOOM_FUND).await?;
        }
    }

    // Capture an *atomic* (height, sum) snapshot. The chain commits a block
    // every second, so sum_loom_all_accounts() may straddle a commit and read
    // some accounts pre-emission and others post-emission. Retry until the
    // height before and after the sum agree.
    let (start_height, start_total_loom) =
        atomic_height_and_loom_sum(client0, &treasury_addr, &[&alice, &bob, &carol]).await?;
    let expected_start = (N_VALIDATORS as u128 * GENESIS_ALLOCATION)
        + (start_height as u128) * BLOCK_EMISSION;
    if start_total_loom != expected_start {
        bail!(
            "loom conservation precheck failed: sum={} expected={} (height={})",
            start_total_loom,
            expected_start,
            start_height
        );
    }

    // ── 4. Alice deploys the DEX suite + two ERC-20s + creates a pool ────
    let suite_out = dex_as(&alice, &["deploy-suite", "--wasm-dir", wasm_dir.to_str().unwrap()])?;
    let suite = last_json_object(&suite_out)?;
    let factory_addr = json_hex(&suite, "factory_addr")?;
    let pair_petal_hash = json_hex(&suite, "pair_petal_hash")?;

    // `bloom-dex deploy-suite` writes a `dex.toml` registry in Alice's home
    // recording the factory/router/wloom/reentrancy addresses. Bob's and
    // Carol's CLIs need the same registry to resolve `--router` / `--factory`
    // defaults on `swap` etc. Share Alice's registry across all user homes.
    let alice_registry = alice.home.join("chain").join("dex.toml");
    for u in [&bob, &carol] {
        let dest_dir = u.home.join("chain");
        std::fs::create_dir_all(&dest_dir).with_context(|| format!("mkdir {}", dest_dir.display()))?;
        let dest = dest_dir.join("dex.toml");
        std::fs::copy(&alice_registry, &dest)
            .with_context(|| format!("copy dex.toml to {}", dest.display()))?;
    }

    let erc20_wasm = wasm_dir.join("bloom_dex_erc20.wasm");
    let erc20_wasm_s = erc20_wasm.to_str().unwrap();

    let tka_out = dex_as(
        &alice,
        &[
            "deploy-token",
            "--wasm", erc20_wasm_s,
            "--name", "TKA",
            "--symbol", "TKA",
            "--supply", ERC20_SUPPLY,
            "--salt", "00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa00aa",
        ],
    )?;
    let tka = json_hex(&last_json_object(&tka_out)?, "token_address")?;

    let tkb_out = dex_as(
        &alice,
        &[
            "deploy-token",
            "--wasm", erc20_wasm_s,
            "--name", "TKB",
            "--symbol", "TKB",
            "--supply", ERC20_SUPPLY,
            "--salt", "00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb00bb",
        ],
    )?;
    let tkb = json_hex(&last_json_object(&tkb_out)?, "token_address")?;

    dex_as(
        &alice,
        &[
            "create-pair",
            "--factory", &hex::encode(factory_addr),
            &hex::encode(tka), &hex::encode(tkb),
        ],
    )?;
    let pair_addr = derive_pair_addr(&factory_addr, &tka, &tkb, &pair_petal_hash);

    // ── 5. Alice seeds the pool with liquidity ────────────────────────────
    dex_as(
        &alice,
        &[
            "add-liquidity",
            "--amount-a", &ALICE_LIQ_A.to_string(),
            "--amount-b", &ALICE_LIQ_B.to_string(),
            &hex::encode(tka), &hex::encode(tkb),
        ],
    )?;
    let (r0_a, r1_a) = query_pair_reserves(client0, &pair_addr).await?;
    if r0_a == 0 || r1_a == 0 {
        bail!("reserves zero after alice add-liquidity: r0={r0_a} r1={r1_a}");
    }
    let k_init = mul_u256(r0_a, r1_a);
    let alice_lp = query_erc20_balance(client0, &pair_addr, &alice.addr).await?;
    if alice_lp == 0 {
        bail!("alice has zero LP after add-liquidity");
    }

    // Alice's TKA / TKB right after seeding the pool. NOTE: this is captured
    // *before* the seed transfers to Bob / Carol below — those flow out of
    // Alice's TKA / TKB balance — so the burn-time delta must add back
    // bob_seed_tka / carol_seed_tkb to recover what Alice actually got from
    // the pair on remove-liquidity.
    let alice_tka_pre_seed = query_erc20_balance(client0, &tka, &alice.addr).await?;
    let alice_tkb_pre_seed = query_erc20_balance(client0, &tkb, &alice.addr).await?;

    // ── 6. Bob needs TKA to swap; Carol needs TKB. Alice transfers some. ─
    // Alice is the genesis-supply holder for both tokens; gift each trader
    // enough to perform their swap. We use ERC-20 transfer via bloom-dex.
    let bob_seed_tka = BOB_SWAP_IN * 10; // headroom for fuel + slippage
    let carol_seed_tkb = CAROL_SWAP_IN * 10;
    erc20_transfer(&alice, &tka, &bob.addr, bob_seed_tka)?;
    // Wait on every validator — Bob's CLI submits via val1; if val1 hasn't
    // applied the seed-transfer block yet, Bob's swap is admitted with stale
    // token balance and the swap reverts inside the WASM router.
    for c in &validator_clients {
        wait_for_erc20_balance(c, &tka, &bob.addr, bob_seed_tka).await?;
    }
    erc20_transfer(&alice, &tkb, &carol.addr, carol_seed_tkb)?;
    for c in &validator_clients {
        wait_for_erc20_balance(c, &tkb, &carol.addr, carol_seed_tkb).await?;
    }

    // ── 7. Bob: swap TKA -> TKB ───────────────────────────────────────────
    let bob_tkb_before = query_erc20_balance(client0, &tkb, &bob.addr).await?;
    let bob_tka_before = query_erc20_balance(client0, &tka, &bob.addr).await?;
    let (r0_pre_bob, r1_pre_bob) = query_pair_reserves(client0, &pair_addr).await?;
    // Pair stores reserves in token0/token1 order, where token0 = min(addr_a, addr_b)
    // (Uniswap-v2 convention, mirrored by bloom-dex-pair). Resolve which reserve
    // is TKA's vs TKB's so amount-out math matches the on-chain swap regardless
    // of how the random token addresses sort.
    let (tka_res_pre_bob, tkb_res_pre_bob) = reserves_by_token(&tka, &tkb, r0_pre_bob, r1_pre_bob);

    let bob_nonce_before = query_nonce(&validator_clients[1], &bob.addr).await?;
    dex_as(
        &bob,
        &[
            "swap",
            "--amount-in", &BOB_SWAP_IN.to_string(),
            "--min-out", "0",
            "--path", &format!("{},{}", hex::encode(tka), hex::encode(tkb)),
        ],
    )?;
    // The swap CLI returns after val1 (Bob's RPC) has applied the swap.
    // Make val0 catch up before we read derived state — otherwise we'd see
    // pre-swap reserves / balances and the assertions would mis-fire.
    // NB: `swap` emits 2 txs (approve + swap_exact_tokens_for_tokens) so
    // val0's nonce must advance by 2; waiting on +1 would race past the
    // approve and read pre-swap balances ("bob TKA in mismatch: got 0").
    wait_for_nonce_at_least(client0, &bob.addr, bob_nonce_before + 2).await?;

    let (r0_post_bob, r1_post_bob) = query_pair_reserves(client0, &pair_addr).await?;
    let k_post_bob = mul_u256(r0_post_bob, r1_post_bob);
    if k_post_bob < k_init {
        bail!("x*y=k violated after Bob's swap: k_init={k_init:?} k_post_bob={k_post_bob:?}");
    }

    // Expected Bob TKB delta: Uniswap-v2 with 0.3% fee
    //   amount_in_with_fee = amount_in * 997
    //   numerator   = amount_in_with_fee * reserve_out
    //   denominator = reserve_in * 1000 + amount_in_with_fee
    let bob_tkb_after = query_erc20_balance(client0, &tkb, &bob.addr).await?;
    let bob_tka_after = query_erc20_balance(client0, &tka, &bob.addr).await?;
    let bob_tka_in = bob_tka_before - bob_tka_after;
    let bob_tkb_out = bob_tkb_after - bob_tkb_before;
    if bob_tka_in != BOB_SWAP_IN {
        bail!("bob TKA in mismatch: got {bob_tka_in} expected {BOB_SWAP_IN}");
    }
    // Bob: TKA → TKB, so reserve_in is the TKA-side reserve.
    let expected_bob_out =
        uniswap_get_amount_out(BOB_SWAP_IN, tka_res_pre_bob, tkb_res_pre_bob);
    if bob_tkb_out != expected_bob_out {
        bail!(
            "bob TKB out mismatch: got {bob_tkb_out} expected {expected_bob_out} (within 0% — exact match required)"
        );
    }

    // ── 8. Carol: swap TKB -> TKA ─────────────────────────────────────────
    let carol_tka_before = query_erc20_balance(client0, &tka, &carol.addr).await?;
    let carol_tkb_before = query_erc20_balance(client0, &tkb, &carol.addr).await?;
    let (r0_pre_carol, r1_pre_carol) = query_pair_reserves(client0, &pair_addr).await?;
    let (tka_res_pre_carol, tkb_res_pre_carol) =
        reserves_by_token(&tka, &tkb, r0_pre_carol, r1_pre_carol);

    let carol_nonce_before = query_nonce(&validator_clients[2], &carol.addr).await?;
    dex_as(
        &carol,
        &[
            "swap",
            "--amount-in", &CAROL_SWAP_IN.to_string(),
            "--min-out", "0",
            "--path", &format!("{},{}", hex::encode(tkb), hex::encode(tka)),
        ],
    )?;
    // Same +2 as Bob: `swap` is approve + swap_exact_tokens_for_tokens.
    wait_for_nonce_at_least(client0, &carol.addr, carol_nonce_before + 2).await?;

    let (r0_post_carol, r1_post_carol) = query_pair_reserves(client0, &pair_addr).await?;
    let k_post_carol = mul_u256(r0_post_carol, r1_post_carol);
    if k_post_carol < k_post_bob {
        bail!(
            "x*y=k violated after Carol's swap: k_post_bob={k_post_bob:?} k_post_carol={k_post_carol:?}"
        );
    }
    let carol_tka_after = query_erc20_balance(client0, &tka, &carol.addr).await?;
    let carol_tkb_after = query_erc20_balance(client0, &tkb, &carol.addr).await?;
    let carol_tkb_in = carol_tkb_before - carol_tkb_after;
    let carol_tka_out = carol_tka_after - carol_tka_before;
    if carol_tkb_in != CAROL_SWAP_IN {
        bail!("carol TKB in mismatch: got {carol_tkb_in} expected {CAROL_SWAP_IN}");
    }
    // Carol: TKB → TKA, so reserve_in is the TKB-side reserve.
    let expected_carol_out =
        uniswap_get_amount_out(CAROL_SWAP_IN, tkb_res_pre_carol, tka_res_pre_carol);
    if carol_tka_out != expected_carol_out {
        bail!(
            "carol TKA out mismatch: got {carol_tka_out} expected {expected_carol_out}"
        );
    }

    // ── 9. Alice removes all liquidity; must come out >= initial deposits ─
    let (r0_pre_burn, r1_pre_burn) = query_pair_reserves(client0, &pair_addr).await?;
    let (tka_res_pre_burn, tkb_res_pre_burn) =
        reserves_by_token(&tka, &tkb, r0_pre_burn, r1_pre_burn);
    let total_lp = query_storage_u128(client0, &pair_addr, blake3::hash(b"erc20.total_supply").as_bytes()).await?;
    // Pro-rata payout: alice_lp / total_lp of each token. Use U256 to avoid
    // overflow when alice_lp * reserve exceeds u128.
    let expected_a_out = pro_rata(alice_lp, tka_res_pre_burn, total_lp);
    let expected_b_out = pro_rata(alice_lp, tkb_res_pre_burn, total_lp);

    let alice_nonce_before = query_nonce(&validator_clients[0], &alice.addr).await?;
    dex_as(
        &alice,
        &[
            "remove-liquidity",
            "--liquidity", &alice_lp.to_string(),
            &hex::encode(tka), &hex::encode(tkb),
        ],
    )?;
    // remove-liquidity emits 2 txs (approve + burn) so nonce advances by 2.
    wait_for_nonce_at_least(client0, &alice.addr, alice_nonce_before + 2).await?;

    let alice_tka_final = query_erc20_balance(client0, &tka, &alice.addr).await?;
    let alice_tkb_final = query_erc20_balance(client0, &tkb, &alice.addr).await?;
    // What the pair actually paid Alice on burn = balance delta + the amount
    // she had previously given away as seed transfers (those flow out of the
    // same balance the burn pays back into).
    let burn_amount0_tka = alice_tka_final + bob_seed_tka - alice_tka_pre_seed;
    let burn_amount1_tkb = alice_tkb_final + carol_seed_tkb - alice_tkb_pre_seed;

    // Alice should reclaim ~r0_pre_burn (since she owns all LP minus locked MIN).
    if burn_amount0_tka < expected_a_out * 99 / 100 || burn_amount1_tkb < expected_b_out * 99 / 100 {
        bail!(
            "alice burn output below 99% of pro-rata expectation: \
             got A={burn_amount0_tka} B={burn_amount1_tkb} expected ~A={expected_a_out} B={expected_b_out}"
        );
    }

    // LP fee accrual: the pair paid Alice more than she originally seeded the
    // pool with, because Bob and Carol left 0.3% fee residue on each swap.
    let total_paid_to_alice = burn_amount0_tka + burn_amount1_tkb;
    let total_seeded = ALICE_LIQ_A + ALICE_LIQ_B;
    if total_paid_to_alice <= total_seeded {
        bail!(
            "alice LP fee accrual failed: pair paid={total_paid_to_alice} seeded={total_seeded} \
             (expected paid > seeded after Bob+Carol swaps)"
        );
    }

    // ── 10. LOOM conservation across all accounts ─────────────────────────
    let (end_height, end_total_loom) =
        atomic_height_and_loom_sum(client0, &treasury_addr, &[&alice, &bob, &carol]).await?;
    let blocks_committed = end_height - start_height;
    let expected_end = start_total_loom + (blocks_committed as u128) * BLOCK_EMISSION;
    if end_total_loom != expected_end {
        bail!(
            "LOOM conservation violated: end_sum={end_total_loom} expected={expected_end} \
             (start={start_total_loom} blocks={blocks_committed} emission={BLOCK_EMISSION})"
        );
    }

    eprintln!(
        "docker_dex_multi_user_acceptance: OK \
         (blocks committed during test = {blocks_committed}, k_init={k_init:?}, k_final={k_post_carol:?})"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Docker-test-only helpers
// ---------------------------------------------------------------------------

fn compose_tmpdir() -> Result<PathBuf> {
    let s = std::env::var("BLOOM_DOCKER_TMPDIR")
        .context("BLOOM_DOCKER_TMPDIR not set; run via scripts/test-docker-dex.sh")?;
    let p = PathBuf::from(s);
    if !p.is_dir() {
        bail!("BLOOM_DOCKER_TMPDIR={} is not a directory", p.display());
    }
    Ok(p)
}

fn bloom_bin() -> PathBuf {
    if let Ok(p) = std::env::var("BLOOM_BIN") {
        return PathBuf::from(p);
    }
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("../../../../target/release/bloom")
}

/// Create a fresh user identity:
///   1. Make `<users_root>/<name>/chain/keystore/`
///   2. Run `bloom chain init` to generate an xDSA keypair in that home
///   3. Copy the shared genesis.toml into the user's chain dir
///   4. Return `User` with the rpc_tcp endpoint pointing at one validator
fn create_user(
    name: &'static str,
    users_root: &Path,
    shared_genesis: &Path,
    host_rpc_port: u16,
) -> Result<User> {
    let home = users_root.join(name);
    let chain_dir = home.join("chain");
    std::fs::create_dir_all(chain_dir.join("keystore"))?;

    let status = Command::new(bloom_bin())
        .args([
            "--home", home.to_str().unwrap(),
            "chain", "init",
            "--genesis", shared_genesis.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .context("invoke bloom chain init")?;
    if !status.success() {
        bail!("bloom chain init failed for {name}");
    }

    let user_genesis = chain_dir.join("genesis.toml");
    std::fs::copy(shared_genesis, &user_genesis)
        .with_context(|| format!("copy genesis to {}", user_genesis.display()))?;

    let addr = wallet_addr_for_home(&home)?;
    Ok(User {
        name,
        home,
        addr,
        rpc_tcp: format!("127.0.0.1:{}", host_rpc_port),
    })
}

/// Run `bloom chain transfer` from `from_home` to `to_addr` for `amount`.
fn run_bloom_chain_transfer(
    from_home: &Path,
    rpc_tcp: &str,
    to_addr: &[u8; 32],
    amount: u128,
    _nonce_hint: u64,
) -> Result<()> {
    let mut cmd = Command::new(bloom_bin());
    cmd.env("BLOOM_RPC_TCP", rpc_tcp)
        .arg("--home").arg(from_home)
        .arg("chain").arg("transfer")
        .arg("--to").arg(hex::encode(to_addr))
        .arg("--amount").arg(amount.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().context("invoke bloom chain transfer")?;
    if !out.status.success() {
        bail!(
            "bloom chain transfer failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Thin convenience wrapper: run `bloom-dex` as a particular `User`, setting
/// `BLOOM_RPC_TCP` so the CLI dials that user's validator over TCP.
fn dex_as(user: &User, args: &[&str]) -> Result<String> {
    let out = run_bloom_dex(&user.home, args, Some(&user.rpc_tcp))
        .with_context(|| format!("bloom-dex as {} {:?}", user.name, args))?;
    Ok(out)
}

/// Send ERC-20 tokens by calling token.transfer(to, amount) via `bloom chain call`.
fn erc20_transfer(from: &User, token: &[u8; 32], to: &[u8; 32], amount: u128) -> Result<()> {
    // ERC-20 transfer calldata: 4-byte selector + 32-byte `to` + 32-byte u256 amount.
    // The canonical method string for the erc20.transfer selector is
    // "erc20.transfer(address,u256)" — NOT the Solidity-style
    // "transfer(address,uint256)". The contract's dispatcher
    // (bloom-dex-erc20::lib.rs `call`) traps with "erc20: unknown selector"
    // if these don't match.
    let sig_full = *blake3::hash(b"erc20.transfer(address,u256)").as_bytes();
    let selector = &sig_full[..4];

    let mut calldata = Vec::with_capacity(4 + 32 + 32);
    calldata.extend_from_slice(selector);
    calldata.extend_from_slice(to);
    let mut amt = [0u8; 32];
    amt[16..].copy_from_slice(&amount.to_be_bytes());
    calldata.extend_from_slice(&amt);

    let mut cmd = Command::new(bloom_bin());
    cmd.env("BLOOM_RPC_TCP", &from.rpc_tcp)
        .arg("--home").arg(&from.home)
        .arg("chain").arg("call")
        .arg(hex::encode(token))
        .arg(hex::encode(&calldata))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd.output().context("invoke bloom chain call (erc20 transfer)")?;
    if !out.status.success() {
        bail!(
            "erc20 transfer failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Convergence waiters (docker-test-only — depend on TX_TIMEOUT)
// ---------------------------------------------------------------------------

async fn wait_for_account_loom(client: &RpcClient, addr: &[u8; 32], min: u128) -> Result<()> {
    let deadline = std::time::Instant::now() + TX_TIMEOUT;
    loop {
        let bal = query_account_loom(client, addr).await.unwrap_or(0);
        if bal >= min {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for account {} to reach loom>={} (got {})",
                hex::encode(addr),
                min,
                bal
            );
        }
        sleep(Duration::from_millis(250)).await;
    }
}

/// Wait until `client`'s view of `addr`'s nonce reaches at least `target`.
async fn wait_for_nonce_at_least(client: &RpcClient, addr: &[u8; 32], target: u64) -> Result<()> {
    let deadline = std::time::Instant::now() + TX_TIMEOUT;
    loop {
        let n = query_nonce(client, addr).await.unwrap_or(0);
        if n >= target {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for nonce of {} to reach {} (still at {})",
                hex::encode(addr),
                target,
                n
            );
        }
        sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_erc20_balance(client: &RpcClient, token: &[u8; 32], holder: &[u8; 32], min: u128) -> Result<()> {
    let deadline = std::time::Instant::now() + TX_TIMEOUT;
    loop {
        let bal = query_erc20_balance(client, token, holder).await.unwrap_or(0);
        if bal >= min {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for erc20 {} balance of {} to reach {} (got {})",
                hex::encode(token),
                hex::encode(holder),
                min,
                bal
            );
        }
        sleep(Duration::from_millis(250)).await;
    }
}

/// Read `(height, sum_of_loom)` such that the height before and after the
/// per-account sum agree. Without this guard, the sum can straddle a 1-second
/// block commit and double-count or under-count the proposer's emission for
/// that block.
async fn atomic_height_and_loom_sum(
    client: &RpcClient,
    treasury: &[u8; 32],
    users: &[&User],
) -> Result<(u64, u128)> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let h_pre = current_height(client).await?;
        let sum = sum_loom_all_accounts(client, treasury, users).await?;
        let h_post = current_height(client).await?;
        if h_pre == h_post {
            return Ok((h_pre, sum));
        }
        if std::time::Instant::now() >= deadline {
            bail!("could not get atomic (height, loom-sum) snapshot in 20s");
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn sum_loom_all_accounts(
    client: &RpcClient,
    treasury: &[u8; 32],
    users: &[&User],
) -> Result<u128> {
    // Validators: their addresses come from the home dirs in BLOOM_DOCKER_TMPDIR/homeN.
    let tmpdir = compose_tmpdir()?;
    let mut sum: u128 = 0;
    for i in 0..N_VALIDATORS {
        let home = tmpdir.join(format!("home{}", i));
        let addr = wallet_addr_for_home(&home)?;
        // val0 == treasury; don't double-count. But if treasury is val0
        // we count it as a validator only.
        if i == 0 && addr == *treasury {
            // count once
        }
        sum = sum
            .checked_add(query_account_loom(client, &addr).await?)
            .ok_or_else(|| anyhow!("loom sum overflow"))?;
    }
    for u in users {
        sum = sum
            .checked_add(query_account_loom(client, &u.addr).await?)
            .ok_or_else(|| anyhow!("loom sum overflow"))?;
    }
    Ok(sum)
}
