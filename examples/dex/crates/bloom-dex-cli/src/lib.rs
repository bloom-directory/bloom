#![allow(clippy::too_many_arguments)]
#![deprecated(
    since = "0.2.0",
    note = "use bloom-resource framework — see docs/specs/2026-05-20-bloom-native-contracts-design.md"
)]
#![allow(deprecated)]
//! `bloom dex ...` — DEX subcommand tree (v0 acceptance demo driver).
//!
//! High-level glue around `bloom chain deploy` + `bloom chain call`. These
//! subcommands build the calldata for the five DEX petals (erc20, pair,
//! factory, router, wloom) and submit Deploy/Call txs through the running
//! node's UDS JSON-RPC.
//!
//! v0 acceptance flow (per DEX spec §15):
//!   1. `bloom dex deploy-suite`        — bootstraps pair wasm, deploys wloom + factory + router; writes `dex.toml`.
//!   2. `bloom dex deploy-token`        — deploys a fresh ERC-20 petal.
//!   3. `bloom dex create-pair`         — creates a pair via factory.
//!   4. `bloom dex add-liquidity`       — approves + addLiquidity.
//!   5. `bloom dex swap`                — swapExactTokensForTokens.
//!   6. `bloom dex remove-liquidity`    — approves LP + removeLiquidity.
//!
//! Calldata encoding uses `bloom_chain_abi::Encoder` and selectors derived
//! from canonical DEX v0 signature strings via `bloom_chain_abi::selector`.
//!
//! The dispatcher writes a `dex.toml` registry under `<bloom_home>/chain/`
//! that subsequent subcommands read for the factory / router / wloom /
//! pair-petal-hash bindings, so the user doesn't have to thread addresses
//! through every command.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use bloom_chain_abi::Encoder;
use bloom_chain_node::rpc::RpcClient;
use bloom_chain_types::ssz::Encode;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_dex_erc20::Erc20;
use bloom_dex_factory::Factory;
use bloom_dex_router::Router;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ---------------------------------------------------------------------------
// `bloom dex` subcommand tree
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum DexCmd {
    /// Deploy wloom + factory + router; bootstrap pair wasm; write `dex.toml`.
    DeploySuite {
        /// Path to a directory containing the five DEX wasm artifacts.
        ///
        /// Expected filenames:
        ///   bloom_dex_wloom.wasm,  bloom_dex_pair.wasm,
        ///   bloom_dex_factory.wasm, bloom_dex_router.wasm,
        ///   bloom_dex_erc20.wasm
        #[arg(long, value_name = "DIR")]
        wasm_dir: PathBuf,
        /// Address that will be set as factory `fee_to_setter`.
        ///
        /// Defaults to the active xDSA wallet.
        #[arg(long, value_name = "ADDR")]
        fee_to_setter: Option<String>,
    },
    /// Deploy a fresh ERC-20 token petal with the given metadata.
    DeployToken {
        /// Path to `bloom_dex_erc20.wasm` (default: `<bloom_home>/chain/dex/erc20.wasm`).
        #[arg(long, value_name = "FILE")]
        wasm: Option<PathBuf>,
        /// Token name (UTF-8, ≤ 32 bytes).
        #[arg(long)]
        name: String,
        /// Token symbol (UTF-8, ≤ 32 bytes).
        #[arg(long)]
        symbol: String,
        /// Decimals (default 18).
        #[arg(long, default_value_t = 18u8)]
        decimals: u8,
        /// Initial supply (raw u256 in decimal).
        #[arg(long)]
        supply: String,
        /// Initial holder address. Defaults to active wallet.
        #[arg(long)]
        holder: Option<String>,
        /// 32-byte hex salt; defaults to a randomized salt-of-the-day so
        /// repeated invocations don't collide on `(deployer, salt,
        /// petal_hash)`.
        #[arg(long, value_name = "HEX")]
        salt: Option<String>,
    },
    /// Create a pair via factory.
    CreatePair {
        /// Factory address (defaults to the one in `dex.toml`).
        #[arg(long)]
        factory: Option<String>,
        /// Token A address.
        token_a: String,
        /// Token B address.
        token_b: String,
    },
    /// Add liquidity via router (calls approve on both tokens first).
    AddLiquidity {
        /// Router address (defaults to the one in `dex.toml`).
        #[arg(long)]
        router: Option<String>,
        /// Token A address.
        token_a: String,
        /// Token B address.
        token_b: String,
        /// Desired amount of A (u256 decimal).
        #[arg(long)]
        amount_a: String,
        /// Desired amount of B (u256 decimal).
        #[arg(long)]
        amount_b: String,
        /// Minimum A (default amount_a * 99 / 100).
        #[arg(long)]
        min_a: Option<String>,
        /// Minimum B (default amount_b * 99 / 100).
        #[arg(long)]
        min_b: Option<String>,
        /// LP recipient (default active wallet).
        #[arg(long)]
        to: Option<String>,
        /// Deadline in seconds-from-now (default 600).
        #[arg(long, default_value_t = 600u64)]
        deadline_secs: u64,
    },
    /// Swap exact tokens for tokens via router.
    Swap {
        /// Router address (defaults to the one in `dex.toml`).
        #[arg(long)]
        router: Option<String>,
        /// Exact input amount (u256 decimal).
        #[arg(long)]
        amount_in: String,
        /// Minimum output (u256 decimal).
        #[arg(long)]
        min_out: String,
        /// Token path (comma-separated addresses, e.g. `tokenA,tokenB`).
        #[arg(long)]
        path: String,
        /// Output recipient (default active wallet).
        #[arg(long)]
        to: Option<String>,
        /// Deadline in seconds-from-now (default 600).
        #[arg(long, default_value_t = 600u64)]
        deadline_secs: u64,
    },
    /// Remove liquidity via router (approves LP first).
    RemoveLiquidity {
        /// Router address (defaults to the one in `dex.toml`).
        #[arg(long)]
        router: Option<String>,
        /// Token A address.
        token_a: String,
        /// Token B address.
        token_b: String,
        /// LP amount to burn (u256 decimal).
        #[arg(long)]
        liquidity: String,
        /// Min A out (default 0).
        #[arg(long)]
        min_a: Option<String>,
        /// Min B out (default 0).
        #[arg(long)]
        min_b: Option<String>,
        /// Recipient (default active wallet).
        #[arg(long)]
        to: Option<String>,
        /// Deadline in seconds-from-now (default 600).
        #[arg(long, default_value_t = 600u64)]
        deadline_secs: u64,
    },
}

// ---------------------------------------------------------------------------
// dex.toml registry (per-home)
// ---------------------------------------------------------------------------

/// Persistent index of the deployed DEX suite addresses + the pair petal_hash.
///
/// Stored as TOML at `<bloom_home>/chain/dex.toml`. The deploy-suite
/// subcommand writes it; subsequent subcommands read it for defaults.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct DexRegistry {
    /// Hex (no prefix) — 32 bytes, BLAKE3 of pair wasm.
    pair_petal_hash: Option<String>,
    /// Bootstrap pair instance address (the throwaway from §5 bootstrap).
    pair_bootstrap_addr: Option<String>,
    wloom_addr: Option<String>,
    factory_addr: Option<String>,
    router_addr: Option<String>,
}

fn registry_path(home: &bloom_proto::HomeDir) -> PathBuf {
    home.root().join("chain/dex.toml")
}

fn load_registry(home: &bloom_proto::HomeDir) -> Result<DexRegistry> {
    let p = registry_path(home);
    if !p.exists() {
        return Ok(DexRegistry::default());
    }
    let text = std::fs::read_to_string(&p)
        .with_context(|| format!("read dex registry {}", p.display()))?;
    Ok(toml::from_str(&text)?)
}

fn save_registry(home: &bloom_proto::HomeDir, reg: &DexRegistry) -> Result<()> {
    let p = registry_path(home);
    let text = toml::to_string_pretty(reg).context("serialize dex.toml")?;
    std::fs::write(&p, text).with_context(|| format!("write {}", p.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

pub async fn run_dex(home: &bloom_proto::HomeDir, cmd: DexCmd) -> Result<()> {
    let chain_dir = home.root().join("chain");
    let rpc_sock = chain_dir.join("rpc.sock");
    // Honor `BLOOM_RPC_TCP=host:port` to switch the RpcClient from UDS to TCP.
    // This is the same env-var convention used by `bloom chain ...`.
    let client = match std::env::var("BLOOM_RPC_TCP") {
        Ok(addr) if !addr.is_empty() => RpcClient::tcp(addr),
        _ => RpcClient::new(&rpc_sock),
    };

    match cmd {
        DexCmd::DeploySuite {
            wasm_dir,
            fee_to_setter,
        } => deploy_suite(home, &chain_dir, &client, wasm_dir, fee_to_setter).await,
        DexCmd::DeployToken {
            wasm,
            name,
            symbol,
            decimals,
            supply,
            holder,
            salt,
        } => {
            deploy_token(
                home, &chain_dir, &client, wasm, name, symbol, decimals, supply, holder, salt,
            )
            .await
        }
        DexCmd::CreatePair {
            factory,
            token_a,
            token_b,
        } => create_pair(home, &chain_dir, &client, factory, token_a, token_b).await,
        DexCmd::AddLiquidity {
            router,
            token_a,
            token_b,
            amount_a,
            amount_b,
            min_a,
            min_b,
            to,
            deadline_secs,
        } => {
            add_liquidity(
                home,
                &chain_dir,
                &client,
                router,
                token_a,
                token_b,
                amount_a,
                amount_b,
                min_a,
                min_b,
                to,
                deadline_secs,
            )
            .await
        }
        DexCmd::Swap {
            router,
            amount_in,
            min_out,
            path,
            to,
            deadline_secs,
        } => {
            swap_exact_tokens(
                home,
                &chain_dir,
                &client,
                router,
                amount_in,
                min_out,
                path,
                to,
                deadline_secs,
            )
            .await
        }
        DexCmd::RemoveLiquidity {
            router,
            token_a,
            token_b,
            liquidity,
            min_a,
            min_b,
            to,
            deadline_secs,
        } => {
            remove_liquidity(
                home,
                &chain_dir,
                &client,
                router,
                token_a,
                token_b,
                liquidity,
                min_a,
                min_b,
                to,
                deadline_secs,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// deploy-suite
// ---------------------------------------------------------------------------

async fn deploy_suite(
    home: &bloom_proto::HomeDir,
    chain_dir: &Path,
    client: &RpcClient,
    wasm_dir: PathBuf,
    fee_to_setter: Option<String>,
) -> Result<()> {
    let (sk, pk, sender) = load_wallet_key(chain_dir)?;
    let chain_id = load_chain_id(chain_dir)?;
    let fee_to_setter = match fee_to_setter {
        Some(s) => parse_addr(&s)?,
        None => sender,
    };

    // ── 1. Bootstrap pair wasm via dummy Deploy ──────────────────────────
    //
    // Per DEX spec §5, the pair wasm must be registered in `code_root`
    // before factory.createPair can `host.deploy` instances of it. Phase B
    // shrank the pair init to 96B (drop `reentrancy_addr` — guard moved into
    // `#[nonreentrant]`), so we bootstrap with a 96B zero-init that's a
    // valid pair but never used. The bootstrap instance lives at a
    // predictable dead address; v1 may add TxKind::UploadCode to skip this
    // dead state (Task #16).
    let pair_wasm = read_wasm(&wasm_dir.join("bloom_dex_pair.wasm"))?;
    let pair_petal_hash = petal_hash_of(&pair_wasm);
    let pair_bootstrap_salt = [0u8; 32];
    let pair_bootstrap_init = vec![0u8; 96];
    let pair_bootstrap_addr = deploy_addr(&sender, &pair_bootstrap_salt, &pair_petal_hash);
    submit_deploy(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        &pair_wasm,
        pair_bootstrap_salt,
        pair_bootstrap_init,
    )
    .await
    .context("bootstrap pair wasm")?;

    // ── 2. Deploy wLOOM ──────────────────────────────────────────────────
    let wloom_wasm = read_wasm(&wasm_dir.join("bloom_dex_wloom.wasm"))?;
    let wloom_hash = petal_hash_of(&wloom_wasm);
    let wloom_salt = [2u8; 32];
    let wloom_addr = deploy_addr(&sender, &wloom_salt, &wloom_hash);
    submit_deploy(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        &wloom_wasm,
        wloom_salt,
        Vec::new(),
    )
    .await
    .context("deploy wLOOM")?;

    // ── 3. Deploy factory ────────────────────────────────────────────────
    //
    // Init payload (Phase D, post-migration):
    //   pair_petal_hash (32) || fee_to_setter (32) || factory_self_addr (32)
    // for a total of 96 bytes. The reentrancy guard moved into the
    // `#[nonreentrant]` attribute on the pair, so the factory no longer
    // tracks a reentrancy petal address.
    let factory_wasm = read_wasm(&wasm_dir.join("bloom_dex_factory.wasm"))?;
    let factory_hash = petal_hash_of(&factory_wasm);
    let factory_salt = [3u8; 32];
    let factory_addr_arr = deploy_addr(&sender, &factory_salt, &factory_hash);
    let mut factory_init = Vec::with_capacity(96);
    factory_init.extend_from_slice(&pair_petal_hash);
    factory_init.extend_from_slice(&fee_to_setter.0);
    factory_init.extend_from_slice(&factory_addr_arr.0);
    submit_deploy(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        &factory_wasm,
        factory_salt,
        factory_init,
    )
    .await
    .context("deploy factory")?;

    // ── 4. Deploy router ─────────────────────────────────────────────────
    //
    // init = factory_addr (32) || wloom_addr (32) || router_self_addr (32) — 96 bytes.
    let router_wasm = read_wasm(&wasm_dir.join("bloom_dex_router.wasm"))?;
    let router_hash = petal_hash_of(&router_wasm);
    let router_salt = [4u8; 32];
    let router_addr_arr = deploy_addr(&sender, &router_salt, &router_hash);
    let mut router_init = Vec::with_capacity(96);
    router_init.extend_from_slice(&factory_addr_arr.0);
    router_init.extend_from_slice(&wloom_addr.0);
    router_init.extend_from_slice(&router_addr_arr.0);
    submit_deploy(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        &router_wasm,
        router_salt,
        router_init,
    )
    .await
    .context("deploy router")?;

    // ── 5. Persist registry ──────────────────────────────────────────────
    let reg = DexRegistry {
        pair_petal_hash: Some(hex::encode(pair_petal_hash)),
        pair_bootstrap_addr: Some(hex::encode(pair_bootstrap_addr.0)),
        wloom_addr: Some(hex::encode(wloom_addr.0)),
        factory_addr: Some(hex::encode(factory_addr_arr.0)),
        router_addr: Some(hex::encode(router_addr_arr.0)),
    };
    save_registry(home, &reg)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "pair_petal_hash":    hex::encode(pair_petal_hash),
            "pair_bootstrap_addr": hex::encode(pair_bootstrap_addr.0),
            "wloom_addr":         hex::encode(wloom_addr.0),
            "factory_addr":       hex::encode(factory_addr_arr.0),
            "router_addr":        hex::encode(router_addr_arr.0),
        }))?
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// deploy-token
// ---------------------------------------------------------------------------

async fn deploy_token(
    _home: &bloom_proto::HomeDir,
    chain_dir: &Path,
    client: &RpcClient,
    wasm: Option<PathBuf>,
    name: String,
    symbol: String,
    decimals: u8,
    supply: String,
    holder: Option<String>,
    salt: Option<String>,
) -> Result<()> {
    let wasm_path = wasm.unwrap_or_else(|| chain_dir.join("dex/erc20.wasm"));
    let wasm_bytes = read_wasm(&wasm_path)?;
    let (sk, pk, sender) = load_wallet_key(chain_dir)?;
    let chain_id = load_chain_id(chain_dir)?;
    let holder = match holder {
        Some(s) => parse_addr(&s)?,
        None => sender,
    };
    let supply_u256 = parse_u256_decimal(&supply)?;
    let salt_bytes = parse_salt_or_random(salt.as_deref())?;

    // ERC-20 init payload — encoded via the bloom-contract ABI through the
    // canonical helper in bloom-dex-erc20 so the wire layout has exactly one
    // source of truth.
    let init = bloom_dex_erc20::encode_init_payload(
        &name,
        &symbol,
        decimals,
        bloom_chain_abi::U256(supply_u256),
        holder.0,
    )
    .map_err(|e| anyhow::anyhow!("encode erc20 init: {e:?}"))?;

    let petal_hash = petal_hash_of(&wasm_bytes);
    let token_addr = deploy_addr(&sender, &salt_bytes, &petal_hash);

    submit_deploy(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        &wasm_bytes,
        salt_bytes,
        init,
    )
    .await?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "token_address": hex::encode(token_addr.0),
            "petal_hash":    hex::encode(petal_hash),
            "name": name,
            "symbol": symbol,
            "decimals": decimals,
            "supply": supply,
        }))?
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// create-pair
// ---------------------------------------------------------------------------

async fn create_pair(
    home: &bloom_proto::HomeDir,
    chain_dir: &Path,
    client: &RpcClient,
    factory: Option<String>,
    token_a: String,
    token_b: String,
) -> Result<()> {
    let factory_addr = resolve_addr(factory, home, |r| r.factory_addr.clone(), "factory")?;
    let (sk, pk, sender) = load_wallet_key(chain_dir)?;
    let chain_id = load_chain_id(chain_dir)?;
    let a = parse_addr(&token_a)?;
    let b = parse_addr(&token_b)?;

    let mut e = Encoder::with_selector(Factory::SEL_CREATE_PAIR);
    e.push_address(&a.0);
    e.push_address(&b.0);
    let calldata = e.finish();

    submit_call(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        factory_addr,
        calldata,
        0,
        5_000_000,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// add-liquidity
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn add_liquidity(
    home: &bloom_proto::HomeDir,
    chain_dir: &Path,
    client: &RpcClient,
    router: Option<String>,
    token_a: String,
    token_b: String,
    amount_a: String,
    amount_b: String,
    min_a: Option<String>,
    min_b: Option<String>,
    to: Option<String>,
    deadline_secs: u64,
) -> Result<()> {
    let router_addr = resolve_addr(router, home, |r| r.router_addr.clone(), "router")?;
    let (sk, pk, sender) = load_wallet_key(chain_dir)?;
    let chain_id = load_chain_id(chain_dir)?;
    let a = parse_addr(&token_a)?;
    let b = parse_addr(&token_b)?;
    let amt_a = parse_u256_decimal(&amount_a)?;
    let amt_b = parse_u256_decimal(&amount_b)?;
    let min_a = match min_a {
        Some(s) => parse_u256_decimal(&s)?,
        None => mul_99_div_100(&amt_a),
    };
    let min_b = match min_b {
        Some(s) => parse_u256_decimal(&s)?,
        None => mul_99_div_100(&amt_b),
    };
    let to = match to {
        Some(s) => parse_addr(&s)?,
        None => sender,
    };
    let deadline = now_secs() + deadline_secs;

    // 1. approve(router, amount_a) on token A
    submit_erc20_approve(client, &sk, &pk, sender, &chain_id, a, router_addr, &amt_a).await?;
    // 2. approve(router, amount_b) on token B
    submit_erc20_approve(client, &sk, &pk, sender, &chain_id, b, router_addr, &amt_b).await?;

    // 3. router.add_liquidity(a, b, amt_a, amt_b, min_a, min_b, to, deadline)
    let mut e = Encoder::with_selector(Router::SEL_ADD_LIQUIDITY);
    e.push_address(&a.0)
        .push_address(&b.0)
        .push_u256_bytes(&amt_a)
        .push_u256_bytes(&amt_b)
        .push_u256_bytes(&min_a)
        .push_u256_bytes(&min_b)
        .push_address(&to.0)
        .push_u64(deadline);
    let calldata = e.finish();
    submit_call(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        router_addr,
        calldata,
        0,
        8_000_000,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// swap
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn swap_exact_tokens(
    home: &bloom_proto::HomeDir,
    chain_dir: &Path,
    client: &RpcClient,
    router: Option<String>,
    amount_in: String,
    min_out: String,
    path: String,
    to: Option<String>,
    deadline_secs: u64,
) -> Result<()> {
    let router_addr = resolve_addr(router, home, |r| r.router_addr.clone(), "router")?;
    let (sk, pk, sender) = load_wallet_key(chain_dir)?;
    let chain_id = load_chain_id(chain_dir)?;
    let in_amt = parse_u256_decimal(&amount_in)?;
    let min_out_v = parse_u256_decimal(&min_out)?;
    let path_addrs: Vec<[u8; 32]> = path
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| parse_addr(s).map(|a| a.0))
        .collect::<Result<_>>()?;
    if path_addrs.len() < 2 {
        bail!("--path must list at least 2 addresses");
    }
    let to = match to {
        Some(s) => parse_addr(&s)?,
        None => sender,
    };
    let deadline = now_secs() + deadline_secs;

    // 1. approve(router, amount_in) on path[0]
    submit_erc20_approve(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        Address(path_addrs[0]),
        router_addr,
        &in_amt,
    )
    .await?;

    // 2. router.swap_exact_tokens_for_tokens(amount_in, min_out, path, to, deadline)
    let mut e = Encoder::with_selector(Router::SEL_SWAP_EXACT_TOKENS_FOR_TOKENS);
    e.push_u256_bytes(&in_amt).push_u256_bytes(&min_out_v);
    e.push_address_vec(&path_addrs)
        .map_err(|err| anyhow!("encode swap path: {err}"))?;
    e.push_address(&to.0).push_u64(deadline);
    let calldata = e.finish();
    submit_call(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        router_addr,
        calldata,
        0,
        8_000_000,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// remove-liquidity
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn remove_liquidity(
    home: &bloom_proto::HomeDir,
    chain_dir: &Path,
    client: &RpcClient,
    router: Option<String>,
    token_a: String,
    token_b: String,
    liquidity: String,
    min_a: Option<String>,
    min_b: Option<String>,
    to: Option<String>,
    deadline_secs: u64,
) -> Result<()> {
    let router_addr = resolve_addr(router, home, |r| r.router_addr.clone(), "router")?;
    let (sk, pk, sender) = load_wallet_key(chain_dir)?;
    let chain_id = load_chain_id(chain_dir)?;
    let a = parse_addr(&token_a)?;
    let b = parse_addr(&token_b)?;
    let liq = parse_u256_decimal(&liquidity)?;
    let min_a = min_a
        .as_deref()
        .map(parse_u256_decimal)
        .transpose()?
        .unwrap_or([0u8; 32]);
    let min_b = min_b
        .as_deref()
        .map(parse_u256_decimal)
        .transpose()?
        .unwrap_or([0u8; 32]);
    let to = match to {
        Some(s) => parse_addr(&s)?,
        None => sender,
    };
    let deadline = now_secs() + deadline_secs;

    // Compute pair address client-side so we know which LP token to approve.
    let reg = load_registry(home)?;
    let factory_hex = reg
        .factory_addr
        .as_ref()
        .ok_or_else(|| anyhow!("factory address not in dex.toml; run `bloom dex deploy-suite`"))?;
    let pair_hash_hex = reg
        .pair_petal_hash
        .as_ref()
        .ok_or_else(|| anyhow!("pair_petal_hash not in dex.toml"))?;
    let factory_addr = parse_addr(factory_hex)?;
    let pair_hash = hex_to_32(pair_hash_hex)?;
    let salt = pair_salt(&a, &b);
    let pair_addr = deploy_addr(&factory_addr, &salt, &pair_hash);

    // 1. approve(router, liquidity) on the pair LP token (pair is itself the LP token)
    submit_erc20_approve(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        pair_addr,
        router_addr,
        &liq,
    )
    .await?;

    // 2. router.remove_liquidity(a, b, liquidity, min_a, min_b, to, deadline)
    let mut e = Encoder::with_selector(Router::SEL_REMOVE_LIQUIDITY);
    e.push_address(&a.0)
        .push_address(&b.0)
        .push_u256_bytes(&liq)
        .push_u256_bytes(&min_a)
        .push_u256_bytes(&min_b)
        .push_address(&to.0)
        .push_u64(deadline);
    let calldata = e.finish();
    submit_call(
        client,
        &sk,
        &pk,
        sender,
        &chain_id,
        router_addr,
        calldata,
        0,
        8_000_000,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_wasm(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("read wasm {}", path.display()))
}

fn petal_hash_of(wasm: &[u8]) -> [u8; 32] {
    // Must match `bloom_chain_types::digest::blake3_tagged(tags::PETAL, wasm)`,
    // which is what the chain uses to identify deployed code (and feeds into
    // the CREATE2 address derivation).
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-chain.v0.petal:");
    h.update(wasm);
    *h.finalize().as_bytes()
}

/// Compute the deploy address per chain spec §7.7:
/// `blake3("bloom-chain.v0.addr:deploy:" || deployer || ":" || salt || ":" || petal_hash)`.
fn deploy_addr(deployer: &Address, salt: &[u8; 32], petal_hash: &[u8; 32]) -> Address {
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-chain.v0.addr:deploy:");
    h.update(&deployer.0);
    h.update(b":");
    h.update(salt);
    h.update(b":");
    h.update(petal_hash);
    Address(*h.finalize().as_bytes())
}

/// Factory's pair salt: `blake3("dex.pair.salt:" || sorted(t0, t1))`.
/// Must match `bloom_dex_factory::pair_salt` (DEX spec §5.1).
fn pair_salt(t_a: &Address, t_b: &Address) -> [u8; 32] {
    let (a, b) = if t_a.0 <= t_b.0 {
        (t_a, t_b)
    } else {
        (t_b, t_a)
    };
    let mut h = blake3::Hasher::new();
    h.update(b"dex.pair.salt:");
    h.update(&a.0);
    h.update(&b.0);
    *h.finalize().as_bytes()
}

fn parse_addr(s: &str) -> Result<Address> {
    bloom_chain_node::genesis::parse_b1_address(s).with_context(|| format!("parse address {s:?}"))
}

fn parse_u256_decimal(s: &str) -> Result<[u8; 32]> {
    // u128 covers up to ~3.4e38, large enough for v0 DEX amounts; reject anything bigger.
    let v: u128 = s
        .parse()
        .with_context(|| format!("parse u256 (decimal up to u128) {s:?}"))?;
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    Ok(out)
}

fn hex_to_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("decode hex")?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_salt_or_random(s: Option<&str>) -> Result<[u8; 32]> {
    if let Some(h) = s {
        return hex_to_32(h);
    }
    // Use the current ms as a salt-of-the-day so repeat invocations don't collide.
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-cli.dex.salt:");
    h.update(&ms.to_be_bytes());
    Ok(*h.finalize().as_bytes())
}

fn mul_99_div_100(v: &[u8; 32]) -> [u8; 32] {
    // u256 stored in v with the value in the low 16 bytes (we accept up to u128 above).
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&v[16..]);
    let n = u128::from_be_bytes(buf);
    let m = n.saturating_mul(99) / 100;
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&m.to_be_bytes());
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn resolve_addr<F: Fn(&DexRegistry) -> Option<String>>(
    explicit: Option<String>,
    home: &bloom_proto::HomeDir,
    field: F,
    name: &str,
) -> Result<Address> {
    if let Some(s) = explicit {
        return parse_addr(&s);
    }
    let reg = load_registry(home)?;
    let hex_s = field(&reg)
        .ok_or_else(|| anyhow!("{name} not in dex.toml; pass --{name} or run deploy-suite"))?;
    parse_addr(&hex_s)
}

fn load_wallet_key(
    chain_dir: &Path,
) -> Result<(
    bloom_keystore::xdsa::XdsaSecretKey,
    bloom_keystore::xdsa::XdsaPublicKey,
    Address,
)> {
    let key_path = chain_dir.join("keystore").join("validator.xdsa");
    let key_bytes =
        std::fs::read(&key_path).with_context(|| format!("read key {}", key_path.display()))?;
    let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow!("decode validator key: {e}"))?;
    let pk = sk.public_key();
    let addr = Address::from_pubkey_bytes(&pk.0);
    Ok((sk, pk, addr))
}

/// Fetch the current nonce of `addr` via RPC. Falls back to 0 on a missing
/// account so freshly funded wallets start at nonce 1.
async fn fetch_nonce(client: &RpcClient, addr: &Address) -> Result<u64> {
    let res = client
        .call(
            "chain_query_account",
            json!({ "address": hex::encode(addr.0) }),
        )
        .await
        .context("rpc chain_query_account")?;
    Ok(res.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Poll `chain_query_account` until the on-chain nonce reaches `expected`.
/// Used after `chain_submit_tx` to ensure the next tx's nonce is correct.
async fn wait_for_nonce(
    client: &RpcClient,
    addr: &Address,
    expected: u64,
    timeout_secs: u64,
) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let cur = fetch_nonce(client, addr).await?;
        if cur >= expected {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for nonce {expected} on {} (still at {cur})",
                hex::encode(addr.0)
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Poll `chain_query_tx` for the receipt of `tx_hash` and surface the
/// execution outcome. The consensus driver bumps the sender's nonce *before*
/// executing the petal, so a tx that reverted still advances the nonce —
/// without checking the receipt, a silent revert looks identical to success.
///
/// Returns Ok on `success=true`, Err with the petal-side revert reason on
/// `success=false`, Err on timeout. The poll deadline is reached only if the
/// block containing the tx never lands.
async fn wait_for_tx_receipt(
    client: &RpcClient,
    tx_hash: &Hash32,
    timeout_secs: u64,
) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let res = client
            .call(
                "chain_query_tx",
                json!({ "tx_hash": hex::encode(tx_hash.0) }),
            )
            .await
            .context("rpc chain_query_tx")?;
        if !res.is_null() {
            let success = res
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if success {
                return Ok(());
            }
            let reason = res
                .get("return_text")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    res.get("return_data")
                        .and_then(|v| v.as_str())
                        .map(|s| format!("return_data=0x{s}"))
                        .unwrap_or_else(|| "(no revert reason)".to_string())
                });
            bail!(
                "tx {} reverted on-chain: {}",
                hex::encode(tx_hash.0),
                reason
            );
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for receipt of tx {}",
                hex::encode(tx_hash.0)
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }
}

fn build_and_sign(
    sk: &bloom_keystore::xdsa::XdsaSecretKey,
    pk: &bloom_keystore::xdsa::XdsaPublicKey,
    sender: Address,
    chain_id: &str,
    nonce: u64,
    max_fuel: u64,
    fee_per_unit: u64,
    kind: TxKind,
) -> Tx {
    let mut tx = Tx {
        chain_id: chain_id.to_string(),
        sender,
        nonce,
        max_fuel,
        fee_per_unit,
        kind,
        pubkey: PubKeyBytes(pk.to_bytes()),
        sig: SigBytes(vec![]),
    };
    let digest = tx.signing_digest();
    let sig = sk.sign(&digest.0);
    tx.sig = SigBytes(sig.to_bytes());
    tx
}

/// Read the chain_id field from `<chain_dir>/genesis.toml`.
fn load_chain_id(chain_dir: &Path) -> Result<String> {
    let path = chain_dir.join("genesis.toml");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("read genesis {}", path.display()))?;
    let parsed: bloom_chain_node::genesis::GenesisFile =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(parsed.chain_id)
}

async fn submit_deploy(
    client: &RpcClient,
    sk: &bloom_keystore::xdsa::XdsaSecretKey,
    pk: &bloom_keystore::xdsa::XdsaPublicKey,
    sender: Address,
    chain_id: &str,
    wasm: &[u8],
    salt: [u8; 32],
    init_args: Vec<u8>,
) -> Result<()> {
    let nonce = fetch_nonce(client, &sender).await? + 1;
    let tx = build_and_sign(
        sk,
        pk,
        sender,
        chain_id,
        nonce,
        10_000_000,
        1,
        TxKind::Deploy {
            wasm: wasm.to_vec(),
            salt,
            init_args,
            manifest_hash: None,
        },
    );
    let tx_hash = tx.tx_hash();
    let res = client
        .call(
            "chain_submit_tx",
            json!({ "tx_hex": hex::encode(tx.as_ssz_bytes()) }),
        )
        .await?;
    println!("{}", serde_json::to_string_pretty(&res)?);
    wait_for_nonce(client, &sender, nonce, 30).await?;
    wait_for_tx_receipt(client, &tx_hash, 30).await?;
    Ok(())
}

async fn submit_call(
    client: &RpcClient,
    sk: &bloom_keystore::xdsa::XdsaSecretKey,
    pk: &bloom_keystore::xdsa::XdsaPublicKey,
    sender: Address,
    chain_id: &str,
    to: Address,
    calldata: Vec<u8>,
    value_loom: u128,
    max_fuel: u64,
) -> Result<()> {
    let nonce = fetch_nonce(client, &sender).await? + 1;
    let tx = build_and_sign(
        sk,
        pk,
        sender,
        chain_id,
        nonce,
        max_fuel,
        1,
        TxKind::Call {
            to,
            calldata,
            value_loom,
        },
    );
    let tx_hash = tx.tx_hash();
    let res = client
        .call(
            "chain_submit_tx",
            json!({ "tx_hex": hex::encode(tx.as_ssz_bytes()) }),
        )
        .await?;
    println!("{}", serde_json::to_string_pretty(&res)?);
    wait_for_nonce(client, &sender, nonce, 30).await?;
    wait_for_tx_receipt(client, &tx_hash, 30).await?;
    Ok(())
}

async fn submit_erc20_approve(
    client: &RpcClient,
    sk: &bloom_keystore::xdsa::XdsaSecretKey,
    pk: &bloom_keystore::xdsa::XdsaPublicKey,
    sender: Address,
    chain_id: &str,
    token: Address,
    spender: Address,
    amount: &[u8; 32],
) -> Result<()> {
    let mut e = Encoder::with_selector(Erc20::SEL_APPROVE);
    e.push_address(&spender.0).push_u256_bytes(amount);
    submit_call(
        client,
        sk,
        pk,
        sender,
        chain_id,
        token,
        e.finish(),
        0,
        2_000_000,
    )
    .await
}
