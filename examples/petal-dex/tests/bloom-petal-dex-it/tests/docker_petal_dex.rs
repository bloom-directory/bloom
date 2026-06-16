//! Category: docker-acceptance
//!
//! `docker_petal_dex.rs` — LIVE 4-validator docker acceptance test for the
//! petal-based DEX (`/bloom/petals/dex/{pool,wallet,faucet}`).
//!
//! This proves the faucet→create_pool and faucet→swap→wallet.receive flows
//! execute on a live multi-validator network over RPC with REAL signing and
//! on-chain object assertions — the on-chain analog of the in-process
//! `faucet_provision.rs` tests (which are GREEN through the production chain
//! VM). The PTB shapes here mirror those tests exactly.
//!
//! Driving model (mirrors `bloom-dex-it`'s `docker_dex_multi_user.rs`):
//!   - `scripts/test-docker-petal-dex.sh` builds the docker image, provisions
//!     a 4-validator testnet under `$BLOOM_DOCKER_TMPDIR/home{0..3}`, APPENDS
//!     an xDSA gas allocation (keyed to the inner-PTB signer pubkey) to
//!     all four byte-identical genesis.toml files, `docker compose up -d`s
//!     the stack, and runs this test.
//!   - This driver attaches to the running stack over TCP (host ports
//!     18545..18548), deploys the three petal wasms via `bloom chain deploy`,
//!     then submits two xDSA-signed inner PTBs via `bloom chain submit-ptb`.
//!
//! Two address spaces (see brief):
//!   - INNER PTB auth: a deterministic xDSA key (`ptb_signer_*` in
//!     `dex_harness`). Its genesis-allocated `Coin<LOOM>` is the inner
//!     gas-payer; every Address-owned input must be owned by it.
//!   - OUTER Tx envelope: `bloom chain submit-ptb` signs it with the home0
//!     xDSA keystore wallet.
//!
//! `#[ignore]`-gated. Run via `scripts/test-docker-petal-dex.sh`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{io::Write, net::TcpStream};

use anyhow::{Context, Result, anyhow, bail};
use bloom_chain_consensus::validator_set::ValidatorSet;
use bloom_chain_types::block::{Block, BlockHeader};
use bloom_chain_types::digest::blake3_tagged;
use bloom_chain_types::frame::{MsgType, encode_wire_frame};
use bloom_chain_types::ssz::Encode;
use bloom_chain_types::types::{Address, Hash32, SigBytes};
use bloom_chain_types::vote::{Commit, Proposal, Vote, VoteKind};
use serde_json::Value;
use tokio::time::{sleep, timeout};

use bloom_chain_node::rpc::RpcClient;
use bloom_objects::{AbilitySet, AccessMode, Owner, TypeTag};
use bloom_petal_manifest::types::{ArgDecl, ArgKind, FunctionDecl, PetalManifest, SCHEMA_VERSION};
use bloom_resource::BloomType;
use bloom_script::{
    Arg, CORE_FUNGIBLE_PATH, Command as PtbCommand, ExpectedVersion, MoveCmd, PetalRef, PtbTx,
    UseRef, loom_coin_type_tag,
};

use bloom_petal_dex_it::dex_harness::{
    append_manifest_section, build_faucet_wasm, build_pool_wasm, build_router_wasm,
    build_wallet_wasm, erased_type_tag, petal_hash_of, ptb_decode_coin_value, ptb_signer_pubkey,
    ptb_signer_pubkey_hex, ptb_signer_xdsa_pubkey, sign_and_encode_ptb, wat_to_wasm,
};

// ---------------------------------------------------------------------------
// Constants — keep in sync with scripts/test-docker-petal-dex.sh
// ---------------------------------------------------------------------------

const HOST_RPC_PORTS: [u16; 4] = [18545, 18546, 18547, 18548];
const HOST_P2P_PORTS: [u16; 4] = [18656, 18657, 18658, 18659];
const PETAL_VFS_PROBE_PATH: &str = "/bloom/petals/dex/view-probe";

/// Settlement recipient for the swap output. A distinct, deterministic 32-byte
/// address (not the inner-PTB signer) so the receive assertion is unambiguous.
const CAROL: [u8; 32] = [0xC0u8; 32];

/// Pool fee parameter (30 bps), big-endian u16 — mirrors `faucet_provision.rs`.
const POOL_FEE_BPS: u16 = 30;

/// Far-future expiry so the live, ever-advancing chain never rejects the PTB
/// as expired (validator rejects when `current_block > expiry_block`).
const PTB_EXPIRY_BLOCK: u64 = 1_000_000_000;

const PTB_GAS_BUDGET: u64 = 2_000_000;

const ADVERSARY_PATH: &str = "/bloom/petals/dex/adversary";
const LOOM_PROBE_PATH: &str = "/bloom/petals/dex/loom-probe";

const READINESS_TIMEOUT: Duration = Duration::from_secs(90);
const TX_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Top-level test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires docker-compose stack; run via scripts/test-docker-petal-dex.sh"]
async fn docker_petal_dex_acceptance() -> Result<()> {
    if !require_docker_harness("docker_petal_dex_acceptance") {
        return Ok(());
    }
    Box::pin(docker_petal_dex_acceptance_inner(false)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires docker-compose stack; run via scripts/test-docker-petal-vfs.sh"]
async fn docker_petal_vfs_acceptance() -> Result<()> {
    if !require_docker_harness("docker_petal_vfs_acceptance") {
        return Ok(());
    }
    Box::pin(docker_petal_dex_acceptance_inner(true)).await
}

#[test]
fn prints_ptb_signer_registry_entry_for_docker_script() {
    use base64::Engine as _;

    println!("PTB_SIGNER_PK_HEX={}", ptb_signer_pubkey_hex());
    println!(
        "PTB_SIGNER_PUBKEY_B64={}",
        base64::engine::general_purpose::STANDARD.encode(ptb_signer_xdsa_pubkey().0)
    );
}

fn require_docker_harness(test_name: &str) -> bool {
    if std::env::var_os("BLOOM_DOCKER_TMPDIR").is_none() {
        eprintln!("skipping {test_name}: run via scripts/test-docker-petal-dex.sh");
        return false;
    }
    true
}

async fn docker_petal_dex_acceptance_inner(vfs_only: bool) -> Result<()> {
    let tmpdir = compose_tmpdir()?;
    let home0 = tmpdir.join("home0");
    let genesis_path = home0.join("chain").join("genesis.toml");
    if !genesis_path.exists() {
        bail!(
            "missing {} — did `bloom chain testnet` run? (provision homes first)",
            genesis_path.display()
        );
    }

    // ── 1. Wait for stack readiness (height >= 2 on every validator) ──────
    let clients: Vec<RpcClient> = HOST_RPC_PORTS
        .iter()
        .map(|p| RpcClient::tcp(format!("127.0.0.1:{}", p)))
        .collect();
    for (i, c) in clients.iter().enumerate() {
        timeout(READINESS_TIMEOUT, wait_for_height(c, 2))
            .await
            .map_err(|_| anyhow!("validator {} did not reach height 2 via TCP", i))??;
    }
    let client0 = &clients[0];

    eprintln!("================================================================");
    eprintln!("  bloom PETAL-DEX acceptance  —  4-validator docker stack");
    eprintln!("================================================================");
    eprintln!("[stack] all 4 validators ready at height >= 2");
    eprintln!(
        "        endpoints: val0=127.0.0.1:{} val1=127.0.0.1:{} val2=127.0.0.1:{} val3=127.0.0.1:{}",
        HOST_RPC_PORTS[0], HOST_RPC_PORTS[1], HOST_RPC_PORTS[2], HOST_RPC_PORTS[3]
    );
    eprintln!(
        "[xDSA] inner-PTB signer pubkey = {}  (genesis gas-payer)",
        ptb_signer_pubkey_hex()
    );

    Box::pin(exercise_live_malformed_transport(client0, &tmpdir)).await?;

    // ── 2. Build the petal wasms + deploy each via the bloom CLI ──────────
    eprintln!();
    eprintln!("[build] resolving pool/wallet/faucet/router wasm artifacts");
    let pool_wasm_path = docker_petal_wasm_path("bloom_petal_dex_pool", build_pool_wasm)?;
    let wallet_wasm_path = docker_petal_wasm_path("bloom_petal_dex_wallet", build_wallet_wasm)?;
    let faucet_wasm_path = docker_petal_wasm_path("bloom_petal_dex_faucet", build_faucet_wasm)?;
    let router_wasm_path = docker_petal_wasm_path("bloom_petal_dex_router", build_router_wasm)?;
    let view_probe_wasm_path = tmpdir.join("petal-vfs-view-probe.wasm");
    std::fs::write(&view_probe_wasm_path, view_probe_wasm()).context("write view probe wasm")?;

    let pool_wasm = std::fs::read(&pool_wasm_path).context("read pool wasm")?;
    let wallet_wasm = std::fs::read(&wallet_wasm_path).context("read wallet wasm")?;
    let faucet_wasm = std::fs::read(&faucet_wasm_path).context("read faucet wasm")?;
    let router_wasm = std::fs::read(&router_wasm_path).context("read router wasm")?;
    let view_probe_wasm = std::fs::read(&view_probe_wasm_path).context("read view probe wasm")?;

    // Host-side petal hashes (= blake3_tagged(PETAL, wasm)) — what deploy
    // inserts, and what each PetalRef pins.
    let pool_hash = petal_hash_of(&pool_wasm);
    let wallet_hash = petal_hash_of(&wallet_wasm);
    let faucet_hash = petal_hash_of(&faucet_wasm);
    let router_hash = petal_hash_of(&router_wasm);
    let view_probe_hash = petal_hash_of(&view_probe_wasm);

    eprintln!();
    eprintln!("[deploy] deploying petals from home0 (outer xDSA envelope):");
    deploy_petal(&home0, HOST_RPC_PORTS[0], &pool_wasm_path)?;
    assert_resolves(client0, "/bloom/petals/dex/pool", pool_hash).await?;
    eprintln!(
        "         /bloom/petals/dex/pool   hash={}",
        hex::encode(pool_hash.0)
    );
    deploy_petal(&home0, HOST_RPC_PORTS[0], &wallet_wasm_path)?;
    assert_resolves(client0, "/bloom/petals/dex/wallet", wallet_hash).await?;
    eprintln!(
        "         /bloom/petals/dex/wallet hash={}",
        hex::encode(wallet_hash.0)
    );
    deploy_petal(&home0, HOST_RPC_PORTS[0], &faucet_wasm_path)?;
    assert_resolves(client0, "/bloom/petals/dex/faucet", faucet_hash).await?;
    eprintln!(
        "         /bloom/petals/dex/faucet hash={}",
        hex::encode(faucet_hash.0)
    );
    deploy_petal(&home0, HOST_RPC_PORTS[0], &router_wasm_path)?;
    assert_resolves(client0, "/bloom/petals/dex/router", router_hash).await?;
    eprintln!(
        "         /bloom/petals/dex/router hash={}",
        hex::encode(router_hash.0)
    );
    deploy_petal(&home0, HOST_RPC_PORTS[0], &view_probe_wasm_path)?;
    assert_resolves(client0, PETAL_VFS_PROBE_PATH, view_probe_hash).await?;
    eprintln!(
        "         {PETAL_VFS_PROBE_PATH} hash={}",
        hex::encode(view_probe_hash.0)
    );

    // Deploy receipts are waited on by the CLI. Let every validator catch up
    // before submitting PTBs that may be admitted by any validator after gossip.
    let mut latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest + 2).await?;

    // ── 3. Discover the xDSA-owned gas Coin<LOOM> ──────────────────────
    let signer_hex = ptb_signer_pubkey_hex();
    let signer_genesis_coins = timeout(TX_TIMEOUT, wait_for_owned_coins(client0, &signer_hex, 4))
        .await
        .map_err(|_| anyhow!("timed out discovering xDSA genesis Coin<LOOM> set"))??;
    let gas_coin = signer_genesis_coins[0].clone();
    let gas_payer = obj_id_from_hex(&gas_coin)?;
    let merge_a = signer_genesis_coins[1].clone();
    let merge_b = signer_genesis_coins[2].clone();
    let split_src = signer_genesis_coins[3].clone();
    let merge_a_id = obj_id_from_hex(&merge_a)?;
    let merge_b_id = obj_id_from_hex(&merge_b)?;
    let split_src_id = obj_id_from_hex(&split_src)?;
    eprintln!();
    eprintln!(
        "[gas]   xDSA gas Coin<LOOM> = {}  (genesis allocation)",
        json_str(&gas_coin, "id")?
    );
    eprintln!(
        "[gas]   custody probes use merge=({}, {}) split={}",
        json_str(&merge_a, "id")?,
        json_str(&merge_b, "id")?,
        json_str(&split_src, "id")?
    );

    exercise_live_petal_vfs_mount(&clients, &tmpdir, &home0, gas_payer, view_probe_hash).await?;
    if vfs_only {
        return Ok(());
    }

    let fungible_hash = resolve_petal_hash(client0, CORE_FUNGIBLE_PATH).await?;
    eprintln!("[fungible] creating canonical MintCap<Erased> and Supply<Erased>");
    let fungible_setup = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            create_currency_cmd(fungible_hash),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
            create_supply_cmd(fungible_hash),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 2,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let fungible_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], fungible_setup)?;
    if !fungible_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("fungible setup reverted: {fungible_receipt}");
    }
    let mint_cap = timeout(
        TX_TIMEOUT,
        wait_for_owned_object_type(client0, &signer_hex, fungible_hash, "MintCap"),
    )
    .await
    .map_err(|_| anyhow!("timed out discovering MintCap<Erased>"))??;
    let supply = timeout(
        TX_TIMEOUT,
        wait_for_owned_object_type(client0, &signer_hex, fungible_hash, "Supply"),
    )
    .await
    .map_err(|_| anyhow!("timed out discovering Supply<Erased>"))??;
    let mint_cap_id = obj_id_from_hex(&mint_cap)?;
    let mint_cap_version = object_version(&mint_cap)?;
    let supply_id = obj_id_from_hex(&supply)?;
    let mut supply_version = object_version(&supply)?;
    eprintln!(
        "[fungible] MintCap = {}  Supply = {}",
        json_str(&mint_cap, "id")?,
        json_str(&supply, "id")?
    );

    let loom_probe_wasm = loom_probe_wasm(merge_a_id, merge_b_id, split_src_id, fungible_hash);
    let loom_probe_hash = petal_hash_of(&loom_probe_wasm);
    let loom_probe_path = std::env::temp_dir().join(format!(
        "bloom-loom-probe-{}.wasm",
        hex::encode(loom_probe_hash.0)
    ));
    std::fs::write(&loom_probe_path, &loom_probe_wasm).context("write loom probe wasm")?;
    deploy_petal(&home0, HOST_RPC_PORTS[0], &loom_probe_path)?;
    let _ = std::fs::remove_file(&loom_probe_path);
    assert_resolves(client0, LOOM_PROBE_PATH, loom_probe_hash).await?;
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;

    Box::pin(exercise_live_gas_alias_split_merge_and_trap(
        LiveGasAliasEnv {
            client: client0,
            clients: &clients,
            home0: &home0,
            tmpdir: &tmpdir,
            probe_hash: loom_probe_hash,
        },
        LiveGasAliasCoins {
            gas_coin: &gas_coin,
            merge_a: &merge_a,
            merge_b: &merge_b,
            split_src: &split_src,
        },
    ))
    .await?;

    let bad_sig_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    assert_submit_rejected(
        submit_ptb_with_bad_inner_signature(&home0, HOST_RPC_PORTS[0], bad_sig_ptb),
        "bad inner PTB signature",
        "signature verification failed for signer index 0",
    )?;

    // ── 4. canonical fungible mint ×2 → create_pool ───────────────────────
    eprintln!();
    eprintln!("[ptb-1] fungible.mint(10000)×2 -> create_pool(30bps) -> share Pool + LP to signer");
    let pool_coin_a = mint_owned_coin(MintOwnedCoin {
        client: client0,
        clients: &clients,
        home: &home0,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version: &mut supply_version,
        gas_payer,
        value: 10_000,
    })
    .await?;
    let pool_coin_b = mint_owned_coin(MintOwnedCoin {
        client: client0,
        clients: &clients,
        home: &home0,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version: &mut supply_version,
        gas_payer,
        value: 10_000,
    })
    .await?;
    let create_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()], // overwritten by sign_and_encode_ptb
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "create_pool".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: obj_id_from_hex(&pool_coin_a)?,
                        expected_version: ExpectedVersion(object_version(&pool_coin_a)?),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: obj_id_from_hex(&pool_coin_b)?,
                        expected_version: ExpectedVersion(object_version(&pool_coin_b)?),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Const(vector_u8_const(&POOL_FEE_BPS.to_be_bytes())),
                ],
            }),
            // Share the Pool (slot 0) so anyone can swap.
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Shared,
            },
            // Give the LpPosition (slot 1) to the signer.
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], create_ptb)?;
    let ok = receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !ok {
        bail!(
            "create_pool PTB reverted: return_text={:?} return_data={:?}",
            receipt.get("return_text"),
            receipt.get("return_data")
        );
    }
    eprintln!(
        "        receipt: success=true fuel_used={}",
        receipt
            .get("fuel_used")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );

    // Make every validator catch up so discovery is not racing the apply.
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;

    // ── 5. Discover the shared Pool + assert reserves (10000, 10000) ────────
    let pool_obj = timeout(TX_TIMEOUT, wait_for_pool(client0))
        .await
        .map_err(|_| anyhow!("timed out discovering shared Pool"))??;
    let pool_id_hex = json_str(&pool_obj, "id")?;
    let pool_obj_id = obj_id_from_hex(&pool_obj)?;
    if json_str(&pool_obj, "owner_kind")? != "shared" {
        bail!("Pool is not shared: {:?}", pool_obj.get("owner_kind"));
    }
    let (ra, rb) = decode_pool_reserves(&pool_obj)?;
    if ra != 10_000 || rb != 10_000 {
        bail!("pool reserves after create_pool: got ({ra}, {rb}) expected (10000, 10000)");
    }
    let mut pool_version = pool_obj
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing pool version"))?;
    eprintln!(
        "[pool]  shared Pool = {}  reserves=({ra}, {rb})  version={pool_version}",
        pool_id_hex
    );
    assert_object_converged(&clients, pool_id_hex).await?;

    // An LpPosition must exist (transferred to the signer).
    let lps = ls_objects_by_type(client0, "LpPosition").await?;
    if lps.is_empty() {
        bail!("no LpPosition object exists after create_pool");
    }
    eprintln!("[lp]    LpPosition objects found: {}", lps.len());
    let lp_a = lps
        .iter()
        .find(|lp| decode_lp_pool_id(lp).ok().as_ref() == Some(&pool_obj_id))
        .ok_or_else(|| anyhow!("no LpPosition points at primary pool"))?
        .clone();
    let lp_a_id = obj_id_from_hex(&lp_a)?;
    let lp_a_version = lp_a
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing LP version"))?;

    // Create a second pool, then try to burn pool-A LP against pool-B. This
    // must revert without mutating either pool or the LP.
    let pool_b_coin_a = mint_owned_coin(MintOwnedCoin {
        client: client0,
        clients: &clients,
        home: &home0,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version: &mut supply_version,
        gas_payer,
        value: 10_000,
    })
    .await?;
    let pool_b_coin_b = mint_owned_coin(MintOwnedCoin {
        client: client0,
        clients: &clients,
        home: &home0,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version: &mut supply_version,
        gas_payer,
        value: 10_000,
    })
    .await?;
    let create_pool_b = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "create_pool".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: obj_id_from_hex(&pool_b_coin_a)?,
                        expected_version: ExpectedVersion(object_version(&pool_b_coin_a)?),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: obj_id_from_hex(&pool_b_coin_b)?,
                        expected_version: ExpectedVersion(object_version(&pool_b_coin_b)?),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Const(vector_u8_const(&(POOL_FEE_BPS + 1).to_be_bytes())),
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Shared,
            },
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let pool_b_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], create_pool_b)?;
    if !pool_b_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("second pool create reverted: {pool_b_receipt}");
    }
    supply_version = refresh_object_version(client0, supply_id, "Supply<Erased>").await?;
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;
    let pools = ls_objects_by_type(client0, "Pool").await?;
    let pool_b = pools
        .into_iter()
        .find(|p| obj_id_from_hex(p).ok().as_ref() != Some(&pool_obj_id))
        .ok_or_else(|| anyhow!("second shared pool not found"))?;
    let pool_b_id = obj_id_from_hex(&pool_b)?;
    if pool_b_id == pool_obj_id {
        bail!("second pool selection returned primary pool");
    }
    let mut pool_b_version = pool_b
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing pool B version"))?;
    let pool_a_before_cross = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool A missing before cross-pool check"))?;
    let router_quote = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![PtbCommand::Move(MoveCmd {
            petal: PetalRef {
                path: "/bloom/petals/dex/router".to_string(),
                hash: Some(router_hash),
            },
            function: "quote_2hop".to_string(),
            type_args: erased_triplet_type_args(),
            args: vec![
                Arg::Object {
                    id: pool_obj_id,
                    expected_version: ExpectedVersion(pool_version),
                    access_mode: AccessMode::ReadOnly,
                },
                Arg::Object {
                    id: pool_b_id,
                    expected_version: ExpectedVersion(pool_b_version),
                    access_mode: AccessMode::ReadOnly,
                },
                Arg::Const(100u128.to_be_bytes().to_vec()),
            ],
        })],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let router_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], router_quote)?;
    if !router_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("router quote_2hop reverted: {router_receipt}");
    }
    let pool_a_after_router = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool A missing after router quote"))?;
    let pool_b_after_router = query_object(client0, json_str(&pool_b, "id")?)
        .await?
        .ok_or_else(|| anyhow!("pool B missing after router quote"))?;
    assert_same_object_fields(&pool_a_after_router, &pool_a_before_cross, "router pool A")?;
    assert_same_object_fields(&pool_b_after_router, &pool_b, "router pool B")?;
    eprintln!("            router quote_2hop on live pools executed without mutation");

    let lp_a_before_cross = query_object(client0, json_str(&lp_a, "id")?)
        .await?
        .ok_or_else(|| anyhow!("LP A missing before cross-pool check"))?;
    let cross_pool_remove = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![PtbCommand::Move(MoveCmd {
            petal: pool_ref(pool_hash),
            function: "remove_liquidity".to_string(),
            type_args: erased_pair_type_args(),
            args: vec![
                Arg::Object {
                    id: pool_b_id,
                    expected_version: ExpectedVersion(pool_b_version),
                    access_mode: AccessMode::Mutable,
                },
                Arg::Object {
                    id: lp_a_id,
                    expected_version: ExpectedVersion(lp_a_version),
                    access_mode: AccessMode::Consume,
                },
            ],
        })],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let cross_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], cross_pool_remove)?;
    assert_reverted(&cross_receipt, "cross-pool LP withdrawal")?;
    let pool_a_after_cross = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool A missing after cross-pool check"))?;
    let pool_b_after_cross = query_object(client0, json_str(&pool_b, "id")?)
        .await?
        .ok_or_else(|| anyhow!("pool B missing after cross-pool check"))?;
    let lp_a_after_cross = query_object(client0, json_str(&lp_a, "id")?)
        .await?
        .ok_or_else(|| anyhow!("LP A missing after cross-pool check"))?;
    assert_same_object_fields(
        &pool_a_after_cross,
        &pool_a_before_cross,
        "cross-pool pool A",
    )?;
    assert_same_object_fields(&pool_b_after_cross, &pool_b, "cross-pool pool B")?;
    assert_same_object_fields(&lp_a_after_cross, &lp_a_before_cross, "cross-pool LP A")?;

    let add_lp_coin_a = mint_owned_coin(MintOwnedCoin {
        client: client0,
        clients: &clients,
        home: &home0,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version: &mut supply_version,
        gas_payer,
        value: 500,
    })
    .await?;
    let add_lp_coin_b = mint_owned_coin(MintOwnedCoin {
        client: client0,
        clients: &clients,
        home: &home0,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version: &mut supply_version,
        gas_payer,
        value: 500,
    })
    .await?;
    let add_lp_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "add_liquidity".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_obj_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: obj_id_from_hex(&add_lp_coin_a)?,
                        expected_version: ExpectedVersion(object_version(&add_lp_coin_a)?),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: obj_id_from_hex(&add_lp_coin_b)?,
                        expected_version: ExpectedVersion(object_version(&add_lp_coin_b)?),
                        access_mode: AccessMode::Consume,
                    },
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let add_lp_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], add_lp_ptb)?;
    if !add_lp_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("add_liquidity reverted: {add_lp_receipt}");
    }
    supply_version = refresh_object_version(client0, supply_id, "Supply<Erased>").await?;
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;
    let pool_after_add = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after add_liquidity"))?;
    let (ra_add, rb_add) = decode_pool_reserves(&pool_after_add)?;
    if (ra_add, rb_add) != (10_500, 10_500) {
        bail!(
            "pool reserves after add_liquidity: got ({ra_add}, {rb_add}) expected (10500, 10500)"
        );
    }
    pool_version = pool_after_add
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing pool version after add_liquidity"))?;
    let added_lp = ls_objects_by_type(client0, "LpPosition")
        .await?
        .into_iter()
        .find(|lp| {
            json_str(lp, "id").ok() != Some(json_str(&lp_a, "id").unwrap_or_default())
                && decode_lp_pool_id(lp).ok().as_ref() == Some(&pool_obj_id)
        })
        .ok_or_else(|| anyhow!("add_liquidity did not mint a new primary-pool LP"))?;
    let added_lp_id = obj_id_from_hex(&added_lp)?;
    let added_lp_payload_id = decode_lp_self_id(&added_lp)?;
    if added_lp_payload_id != added_lp_id {
        bail!(
            "add_liquidity LP payload self-id mismatch: payload={} object={}",
            hex::encode(added_lp_payload_id.0),
            hex::encode(added_lp_id.0)
        );
    }
    let added_lp_version = added_lp
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing added LP version"))?;

    let remove_lp_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "remove_liquidity".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_obj_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: added_lp_id,
                        expected_version: ExpectedVersion(added_lp_version),
                        access_mode: AccessMode::Consume,
                    },
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let remove_lp_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], remove_lp_ptb)?;
    if !remove_lp_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("remove_liquidity reverted: {remove_lp_receipt}");
    }
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;
    let pool_after_remove = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after remove_liquidity"))?;
    let (ra_remove, rb_remove) = decode_pool_reserves(&pool_after_remove)?;
    if (ra_remove, rb_remove) != (10_000, 10_000) {
        bail!(
            "pool reserves after remove_liquidity: got ({ra_remove}, {rb_remove}) expected (10000, 10000)"
        );
    }
    pool_version = pool_after_remove
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing pool version after remove_liquidity"))?;
    if query_object(client0, json_str(&added_lp, "id")?)
        .await?
        .is_some()
    {
        bail!("remove_liquidity left burned LP object live");
    }
    eprintln!("            add_liquidity/remove_liquidity round-trip preserved primary pool");

    pool_version = exercise_live_dex_partial_consume(LiveDexPartialConsume {
        client: client0,
        clients: &clients,
        home0: &home0,
        pool_hash,
        wallet_hash,
        pool_id: pool_obj_id,
        pool_id_hex,
        pool_version,
        pool_b_id,
        pool_b_id_hex: json_str(&pool_b, "id")?,
        pool_b_version: &mut pool_b_version,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version: &mut supply_version,
        gas_payer,
    })
    .await?;

    let exact_out_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            fungible_mint_cmd(
                fungible_hash,
                mint_cap_id,
                mint_cap_version,
                supply_id,
                supply_version,
                250,
            ),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_out".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_b_id,
                        expected_version: ExpectedVersion(pool_b_version),
                        access_mode: AccessMode::Mutable,
                    },
                    use_ret(0, 0),
                    Arg::Const(90u128.to_be_bytes().to_vec()),
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 1,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
            PtbCommand::Move(MoveCmd {
                petal: wallet_ref(wallet_hash),
                function: "receive_optional".to_string(),
                type_args: vec![],
                args: vec![use_ret(1, 1), Arg::Const(ptb_signer_pubkey().to_vec())],
            }),
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let exact_out_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], exact_out_ptb)?;
    if !exact_out_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("swap_exact_out reverted: {exact_out_receipt}");
    }
    supply_version = refresh_object_version(client0, supply_id, "Supply<Erased>").await?;
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;
    let pool_b_after_exact_out = query_object(client0, json_str(&pool_b, "id")?)
        .await?
        .ok_or_else(|| anyhow!("pool B disappeared after swap_exact_out"))?;
    assert_object_converged(&clients, json_str(&pool_b, "id")?).await?;
    if json_str(&pool_b_after_exact_out, "payload")? == json_str(&pool_b, "payload")? {
        bail!("swap_exact_out succeeded without mutating pool B");
    }
    eprintln!("            swap_exact_out on second pool executed and converged");

    // ── 6. fungible.mint → swap_exact_in → wallet.receive (one atomic PTB) ─
    eprintln!();
    eprintln!("[ptb-2] fungible.mint(100) -> swap_exact_in(min_out=90) -> wallet.receive(carol)");
    let min_out: u128 = 90;
    let swap_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            fungible_mint_cmd(
                fungible_hash,
                mint_cap_id,
                mint_cap_version,
                supply_id,
                supply_version,
                100,
            ),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    use_ret(0, 0),
                    Arg::Object {
                        id: pool_obj_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(min_out.to_be_bytes().to_vec()),
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 1,
                    ret_idx: 0,
                }],
                owner: Owner::Address(CAROL),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], swap_ptb)?;
    let ok = receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !ok {
        bail!(
            "swap→receive PTB reverted: return_text={:?} return_data={:?}",
            receipt.get("return_text"),
            receipt.get("return_data")
        );
    }
    eprintln!(
        "        receipt: success=true fuel_used={}",
        receipt
            .get("fuel_used")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    );
    if receipt
        .get("fuel_used")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        bail!("nonzero-gas swap success reported zero fuel_used");
    }
    supply_version = refresh_object_version(client0, supply_id, "Supply<Erased>").await?;

    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;

    // ── 7. Assert carol received a Coin worth 98 ──────────────────────────
    let carol_hex = hex::encode(CAROL);
    let carol_coin = timeout(TX_TIMEOUT, wait_for_owned_coin(client0, &carol_hex))
        .await
        .map_err(|_| anyhow!("timed out waiting for carol's output Coin"))??;
    let carol_value = decode_coin_value(&carol_coin)?;
    if carol_value != 98 {
        bail!("carol's output Coin value: got {carol_value} expected 98");
    }
    eprintln!();
    eprintln!(
        "[recv]  carol Coin = {}  value={carol_value}",
        json_str(&carol_coin, "id")?
    );

    // ── 8. Assert pool reserves moved to (10100, 9902) ────────────────────
    let pool_after = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after swap"))?;
    let (ra2, rb2) = decode_pool_reserves(&pool_after)?;
    if ra2 != 10_100 || rb2 != 9_902 {
        bail!("pool reserves after swap: got ({ra2}, {rb2}) expected (10100, 9902)");
    }
    eprintln!("[pool]  reserves after swap = ({ra2}, {rb2})  (was (10000, 10000))");
    assert_object_converged(&clients, pool_id_hex).await?;

    let pool_after_version = pool_after
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing pool version after swap"))?;

    let bad_sig_real_swap = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            fungible_mint_cmd(
                fungible_hash,
                mint_cap_id,
                mint_cap_version,
                supply_id,
                supply_version,
                1,
            ),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    use_ret(0, 0),
                    Arg::Object {
                        id: pool_obj_id,
                        expected_version: ExpectedVersion(pool_after_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(0u128.to_be_bytes().to_vec()),
                ],
            }),
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    assert_submit_rejected(
        submit_ptb_with_bad_inner_signature(&home0, HOST_RPC_PORTS[0], bad_sig_real_swap),
        "bad inner PTB signature on stateful swap",
        "signature verification failed for signer index 0",
    )?;
    let pool_after_bad_sig = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after bad-signature swap"))?;
    assert_same_object_fields(
        &pool_after_bad_sig,
        &pool_after,
        "bad-signature swap revert",
    )?;

    let stale_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            fungible_mint_cmd(
                fungible_hash,
                mint_cap_id,
                mint_cap_version,
                supply_id,
                supply_version,
                1,
            ),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    use_ret(0, 0),
                    Arg::Object {
                        id: pool_obj_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(0u128.to_be_bytes().to_vec()),
                ],
            }),
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    assert_submit_rejected(
        submit_ptb(&home0, HOST_RPC_PORTS[0], stale_ptb),
        "stale shared Pool version",
        "version mismatch",
    )?;
    let pool_after_stale = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after stale-version attempt"))?;
    assert_same_object_fields(&pool_after_stale, &pool_after, "stale-version revert")?;

    let slippage_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            fungible_mint_cmd(
                fungible_hash,
                mint_cap_id,
                mint_cap_version,
                supply_id,
                supply_version,
                100,
            ),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    use_ret(0, 0),
                    Arg::Object {
                        id: pool_obj_id,
                        expected_version: ExpectedVersion(pool_after_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(999u128.to_be_bytes().to_vec()),
                ],
            }),
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let slippage_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], slippage_ptb)?;
    assert_reverted(&slippage_receipt, "sandwich/order slippage guard")?;
    if slippage_receipt
        .get("fuel_used")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        bail!("nonzero-gas slippage revert reported zero fuel_used");
    }
    let pool_after_slippage = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after slippage attempt"))?;
    assert_same_object_fields(&pool_after_slippage, &pool_after, "slippage revert")?;

    let low_gas_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            fungible_mint_cmd(
                fungible_hash,
                mint_cap_id,
                mint_cap_version,
                supply_id,
                supply_version,
                1,
            ),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    use_ret(0, 0),
                    Arg::Object {
                        id: pool_obj_id,
                        expected_version: ExpectedVersion(pool_after_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(0u128.to_be_bytes().to_vec()),
                ],
            }),
        ],
        gas_payer,
        gas_budget: 1,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let low_gas_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], low_gas_ptb)?;
    assert_reverted(&low_gas_receipt, "insufficient DeX gas budget")?;
    let pool_after_low_gas = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after low-gas attempt"))?;
    assert_same_object_fields(&pool_after_low_gas, &pool_after, "low-gas revert")?;

    // ── 9. Adversarial petal must not mutate or steal the shared Pool ─────
    let adversary_wasm = adversary_wasm(pool_hash, pool_obj_id);
    let adversary_hash = petal_hash_of(&adversary_wasm);
    let adversary_path = std::env::temp_dir().join(format!(
        "bloom-petal-adversary-{}.wasm",
        hex::encode(adversary_hash.0)
    ));
    std::fs::write(&adversary_path, &adversary_wasm).context("write adversary wasm")?;
    deploy_petal(&home0, HOST_RPC_PORTS[0], &adversary_path)?;
    let _ = std::fs::remove_file(&adversary_path);
    assert_resolves(client0, ADVERSARY_PATH, adversary_hash).await?;
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;

    eprintln!();
    eprintln!(
        "[adversary] deployed malicious petal hash={}",
        hex::encode(adversary_hash.0)
    );

    let corrupt_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![PtbCommand::Move(MoveCmd {
            petal: adversary_ref(adversary_hash),
            function: "corrupt_pool".to_string(),
            type_args: vec![],
            args: vec![Arg::Object {
                id: pool_obj_id,
                expected_version: ExpectedVersion(pool_after_version),
                access_mode: AccessMode::Mutable,
            }],
        })],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let corrupt_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], corrupt_ptb)?;
    assert_reverted(&corrupt_receipt, "non-defining mutate of shared Pool")?;

    let steal_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![PtbCommand::Move(MoveCmd {
            petal: adversary_ref(adversary_hash),
            function: "steal_pool".to_string(),
            type_args: vec![],
            args: vec![Arg::Object {
                id: pool_obj_id,
                expected_version: ExpectedVersion(pool_after_version),
                access_mode: AccessMode::Consume,
            }],
        })],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    assert_submit_rejected(
        submit_ptb(&home0, HOST_RPC_PORTS[0], steal_ptb),
        "Consume access to shared Pool",
        "shared objects cannot be consumed",
    )?;

    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest).await?;
    let pool_after_attack = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after adversarial attempts"))?;
    if json_str(&pool_after_attack, "owner_kind")? != "shared" {
        bail!("adversary changed Pool owner: {:?}", pool_after_attack);
    }
    let (ra3, rb3) = decode_pool_reserves(&pool_after_attack)?;
    if (ra3, rb3) != (ra2, rb2) {
        bail!("adversary mutated Pool reserves: got ({ra3}, {rb3}) expected ({ra2}, {rb2})");
    }
    eprintln!(
        "[adversary] mutate and consume/steal attempts reverted; Pool unchanged at ({ra3}, {rb3})"
    );
    assert_object_converged(&clients, pool_id_hex).await?;

    // ── 10. Restart one validator and prove snapshot/replay catch-up converges ─
    restart_validator_and_assert_catches_up(&clients, &tmpdir, 3, pool_id_hex).await?;

    eprintln!();
    eprintln!("================================================================");
    eprintln!("  PASS  docker_petal_dex_acceptance");
    eprintln!("        create_pool : shared Pool reserves (10000, 10000) + LpPosition");
    eprintln!("        swap+receive: carol Coin worth 98; pool reserves (10100, 9902)");
    eprintln!(
        "        adversary   : bad sig, stale version, slippage, low gas, non-defining mutate rejected"
    );
    eprintln!("        restart     : validator 3 restarted and caught up with pool state");
    eprintln!("================================================================");
    Ok(())
}

// ---------------------------------------------------------------------------
// PTB construction helpers
// ---------------------------------------------------------------------------

fn create_currency_cmd(fungible_hash: bloom_chain_types::types::Hash32) -> PtbCommand {
    PtbCommand::Move(MoveCmd {
        petal: fungible_ref(fungible_hash),
        function: "create_currency".to_string(),
        type_args: vec![erased_type_tag()],
        args: vec![Arg::Signer(0)],
    })
}

fn create_supply_cmd(fungible_hash: bloom_chain_types::types::Hash32) -> PtbCommand {
    PtbCommand::Move(MoveCmd {
        petal: fungible_ref(fungible_hash),
        function: "create_supply".to_string(),
        type_args: vec![erased_type_tag()],
        args: vec![Arg::Signer(0)],
    })
}

fn fungible_mint_cmd(
    fungible_hash: bloom_chain_types::types::Hash32,
    mint_cap_id: bloom_objects::ObjectId,
    mint_cap_version: u64,
    supply_id: bloom_objects::ObjectId,
    supply_version: u64,
    value: u128,
) -> PtbCommand {
    PtbCommand::Move(MoveCmd {
        petal: fungible_ref(fungible_hash),
        function: "mint".to_string(),
        type_args: vec![erased_type_tag()],
        args: vec![
            Arg::Object {
                id: mint_cap_id,
                expected_version: ExpectedVersion(mint_cap_version),
                access_mode: AccessMode::ReadOnly,
            },
            Arg::Object {
                id: supply_id,
                expected_version: ExpectedVersion(supply_version),
                access_mode: AccessMode::Mutable,
            },
            Arg::Const(value.to_be_bytes().to_vec()),
        ],
    })
}

fn vector_u8_const(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec().canonical_encode()
}

fn fungible_ref(fungible_hash: bloom_chain_types::types::Hash32) -> PetalRef {
    PetalRef {
        path: CORE_FUNGIBLE_PATH.to_string(),
        hash: Some(fungible_hash),
    }
}

fn pool_ref(pool_hash: bloom_chain_types::types::Hash32) -> PetalRef {
    PetalRef {
        path: "/bloom/petals/dex/pool".to_string(),
        hash: Some(pool_hash),
    }
}

fn wallet_ref(wallet_hash: bloom_chain_types::types::Hash32) -> PetalRef {
    PetalRef {
        path: "/bloom/petals/dex/wallet".to_string(),
        hash: Some(wallet_hash),
    }
}

fn erased_pair_type_args() -> Vec<TypeTag> {
    vec![erased_type_tag(), erased_type_tag()]
}

fn erased_triplet_type_args() -> Vec<TypeTag> {
    vec![erased_type_tag(), erased_type_tag(), erased_type_tag()]
}

fn adversary_ref(adversary_hash: bloom_chain_types::types::Hash32) -> PetalRef {
    PetalRef {
        path: ADVERSARY_PATH.to_string(),
        hash: Some(adversary_hash),
    }
}

fn loom_probe_ref(probe_hash: bloom_chain_types::types::Hash32) -> PetalRef {
    PetalRef {
        path: LOOM_PROBE_PATH.to_string(),
        hash: Some(probe_hash),
    }
}

fn use_ret(cmd_idx: u16, ret_idx: u16) -> Arg {
    Arg::Use { cmd_idx, ret_idx }
}

fn assert_reverted(receipt: &Value, label: &str) -> Result<()> {
    if receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("{label} unexpectedly succeeded: {receipt}");
    }
    eprintln!(
        "            rejected {label}: return_text={:?}",
        receipt.get("return_text")
    );
    Ok(())
}

fn assert_submit_rejected(result: Result<Value>, label: &str, expected: &str) -> Result<()> {
    match result {
        Ok(receipt) => bail!("{label} unexpectedly submitted: {receipt}"),
        Err(err) => {
            let msg = format!("{err:#}");
            if !msg.contains(expected) {
                bail!("{label} rejected for the wrong reason: {msg}");
            }
            eprintln!("            rejected {label}: {msg}");
        }
    }
    Ok(())
}

struct LiveGasAliasEnv<'a> {
    client: &'a RpcClient,
    clients: &'a [RpcClient],
    home0: &'a std::path::Path,
    tmpdir: &'a std::path::Path,
    probe_hash: bloom_chain_types::types::Hash32,
}

struct LiveGasAliasCoins<'a> {
    gas_coin: &'a Value,
    merge_a: &'a Value,
    merge_b: &'a Value,
    split_src: &'a Value,
}

async fn exercise_live_gas_alias_split_merge_and_trap(
    env: LiveGasAliasEnv<'_>,
    coins: LiveGasAliasCoins<'_>,
) -> Result<()> {
    let LiveGasAliasEnv {
        client,
        clients,
        home0,
        tmpdir,
        probe_hash,
    } = env;
    let LiveGasAliasCoins {
        gas_coin,
        merge_a,
        merge_b,
        split_src,
    } = coins;
    let gas_payer = obj_id_from_hex(gas_coin)?;
    let gas_version = query_object(client, json_str(gas_coin, "id")?)
        .await?
        .ok_or_else(|| anyhow!("gas coin missing before alias attempt"))
        .and_then(|obj| object_version(&obj))?;
    let gas_alias_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![PtbCommand::Move(MoveCmd {
            petal: loom_probe_ref(probe_hash),
            function: "load_split".to_string(),
            type_args: vec![],
            args: vec![Arg::Object {
                id: gas_payer,
                expected_version: ExpectedVersion(gas_version),
                access_mode: AccessMode::Mutable,
            }],
        })],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let gas_alias_receipt = submit_ptb(home0, HOST_RPC_PORTS[0], gas_alias_ptb)?;
    if !gas_alias_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("gas-payer alias as PTB object input reverted: {gas_alias_receipt}");
    }
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;

    let merge_a_id = obj_id_from_hex(merge_a)?;
    let merge_b_id = obj_id_from_hex(merge_b)?;
    let merge_a_before = decode_coin_value(merge_a)?;
    let merge_b_before = decode_coin_value(merge_b)?;
    let merge_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: loom_probe_ref(probe_hash),
                function: "load_merge".to_string(),
                type_args: vec![],
                args: vec![
                    Arg::Object {
                        id: merge_a_id,
                        expected_version: ExpectedVersion(object_version(merge_a)?),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: merge_b_id,
                        expected_version: ExpectedVersion(object_version(merge_b)?),
                        access_mode: AccessMode::Consume,
                    },
                ],
            }),
            PtbCommand::MergeCoins(vec![
                UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                },
            ]),
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let merge_receipt = submit_ptb(home0, HOST_RPC_PORTS[0], merge_ptb)?;
    if !merge_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("persistent MergeCoins reverted: {merge_receipt}");
    }
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;
    let merged = query_object(client, json_str(merge_a, "id")?)
        .await?
        .ok_or_else(|| anyhow!("merged persistent coin missing"))?;
    if decode_coin_value(&merged)? != merge_a_before + merge_b_before {
        bail!(
            "persistent MergeCoins value mismatch: got {} expected {}",
            decode_coin_value(&merged)?,
            merge_a_before + merge_b_before
        );
    }
    if query_object(client, json_str(merge_b, "id")?)
        .await?
        .is_some()
    {
        bail!("persistent MergeCoins left the consumed second coin live");
    }

    let split_src_id = obj_id_from_hex(split_src)?;
    let split_before = decode_coin_value(split_src)?;
    let owner_before_split = ls_objects_by_owner(client, &ptb_signer_pubkey_hex()).await?;
    let before_ids: std::collections::HashSet<String> = owner_before_split
        .iter()
        .filter_map(|o| json_str(o, "id").ok().map(str::to_string))
        .collect();
    let split_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: loom_probe_ref(probe_hash),
                function: "load_split".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: split_src_id,
                    expected_version: ExpectedVersion(object_version(split_src)?),
                    access_mode: AccessMode::Mutable,
                }],
            }),
            PtbCommand::SplitCoins {
                src: UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                amounts: vec![111, 222],
            },
            PtbCommand::TransferObjects {
                uses: vec![
                    UseRef {
                        cmd_idx: 1,
                        ret_idx: 0,
                    },
                    UseRef {
                        cmd_idx: 1,
                        ret_idx: 1,
                    },
                ],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let split_receipt = submit_ptb(home0, HOST_RPC_PORTS[0], split_ptb)?;
    if !split_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("persistent SplitCoins reverted: {split_receipt}");
    }
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;
    let split_after = query_object(client, json_str(split_src, "id")?)
        .await?
        .ok_or_else(|| anyhow!("split source coin missing"))?;
    if decode_coin_value(&split_after)? != split_before - 333 {
        bail!(
            "persistent SplitCoins source value mismatch: got {} expected {}",
            decode_coin_value(&split_after)?,
            split_before - 333
        );
    }
    let mut new_split_values = ls_objects_by_owner(client, &ptb_signer_pubkey_hex())
        .await?
        .into_iter()
        .filter(|o| o.get("type_name").and_then(Value::as_str) == Some("Coin"))
        .filter(|o| {
            json_str(o, "id")
                .map(|id| !before_ids.contains(id))
                .unwrap_or(false)
        })
        .map(|o| decode_coin_value(&o))
        .collect::<Result<Vec<_>>>()?;
    new_split_values.sort_unstable();
    if new_split_values != vec![111, 222] {
        bail!("persistent SplitCoins minted values {new_split_values:?}, expected [111, 222]");
    }

    let gas_before_trap = query_object(client, json_str(gas_coin, "id")?)
        .await?
        .ok_or_else(|| anyhow!("gas coin missing before trap"))?;
    let validator_balances_before = validator_coin_balances(client, tmpdir).await?;
    let height_before = current_height(client).await?;
    let trap_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![PtbCommand::Move(MoveCmd {
            petal: loom_probe_ref(probe_hash),
            function: "trap_after_work".to_string(),
            type_args: vec![],
            args: vec![],
        })],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let trap_receipt = submit_ptb(home0, HOST_RPC_PORTS[0], trap_ptb)?;
    assert_reverted(&trap_receipt, "non-OOF wasm trap after fuel burn")?;
    let trap_fuel = trap_receipt
        .get("fuel_used")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if trap_fuel == 0 {
        bail!("non-OOF wasm trap reported zero fuel_used");
    }
    let trap_tx_hash = json_str(&trap_receipt, "tx_hash")?;
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;
    let trap_block = find_block_containing_tx(client, height_before, latest + 1, trap_tx_hash)
        .await?
        .ok_or_else(|| anyhow!("could not find trap tx {trap_tx_hash} in recent blocks"))?;
    if trap_block
        .get("fuel_used")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        < trap_fuel
    {
        bail!("trap block fuel_used is lower than trap receipt fuel_used");
    }
    let gas_after_trap = query_object(client, json_str(gas_coin, "id")?)
        .await?
        .ok_or_else(|| anyhow!("gas coin missing after trap"))?;
    let gas_before_value = decode_coin_value(&gas_before_trap)?;
    let gas_after_value = decode_coin_value(&gas_after_trap)?;
    if gas_after_value != gas_before_value - PTB_GAS_BUDGET as u128 {
        bail!(
            "non-OOF trap gas burn mismatch: gas coin got {gas_after_value}, expected {}",
            gas_before_value - PTB_GAS_BUDGET as u128
        );
    }
    let proposer = json_str(&trap_block, "proposer")?;
    let proposer_after = query_owned_coin_balance(client, proposer).await?;
    let proposer_before = validator_balances_before
        .get(proposer)
        .copied()
        .unwrap_or_default();
    if proposer_after < proposer_before + PTB_GAS_BUDGET as u128 {
        bail!(
            "non-OOF trap proposer credit too small: before={proposer_before} after={proposer_after}"
        );
    }

    eprintln!(
        "[ptb]   live gas alias rejected; persistent split/merge conserved custody; non-OOF trap fuel={} charged",
        trap_fuel
    );
    Ok(())
}

struct LiveDexPartialConsume<'a> {
    client: &'a RpcClient,
    clients: &'a [RpcClient],
    home0: &'a std::path::Path,
    pool_hash: bloom_chain_types::types::Hash32,
    wallet_hash: bloom_chain_types::types::Hash32,
    pool_id: bloom_objects::ObjectId,
    pool_id_hex: &'a str,
    pool_version: u64,
    pool_b_id: bloom_objects::ObjectId,
    pool_b_id_hex: &'a str,
    pool_b_version: &'a mut u64,
    fungible_hash: bloom_chain_types::types::Hash32,
    mint_cap_id: bloom_objects::ObjectId,
    mint_cap_version: u64,
    supply_id: bloom_objects::ObjectId,
    supply_version: &'a mut u64,
    gas_payer: bloom_objects::ObjectId,
}

async fn exercise_live_dex_partial_consume(input: LiveDexPartialConsume<'_>) -> Result<u64> {
    let LiveDexPartialConsume {
        client,
        clients,
        home0,
        pool_hash,
        wallet_hash,
        pool_id,
        pool_id_hex,
        pool_version,
        pool_b_id,
        pool_b_id_hex,
        pool_b_version,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version,
        gas_payer,
    } = input;
    let mut pool_version = pool_version;
    let signer_hex = ptb_signer_pubkey_hex();

    let add_a = mint_owned_coin(MintOwnedCoin {
        client,
        clients,
        home: home0,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version,
        gas_payer,
        value: 500,
    })
    .await?;
    let add_b = mint_owned_coin(MintOwnedCoin {
        client,
        clients,
        home: home0,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version,
        gas_payer,
        value: 500,
    })
    .await?;
    let add_a_id = obj_id_from_hex(&add_a)?;
    let add_b_id = obj_id_from_hex(&add_b)?;

    let lps_before = ls_objects_by_type(client, "LpPosition")
        .await?
        .into_iter()
        .filter_map(|lp| json_str(&lp, "id").ok().map(str::to_string))
        .collect::<std::collections::HashSet<_>>();
    let partial_add_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "add_liquidity".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: add_a_id,
                        expected_version: ExpectedVersion(object_version(&add_a)?),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: add_b_id,
                        expected_version: ExpectedVersion(object_version(&add_b)?),
                        access_mode: AccessMode::Consume,
                    },
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let partial_add_receipt = submit_ptb(home0, HOST_RPC_PORTS[0], partial_add_ptb)?;
    if !partial_add_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("persistent partial add_liquidity reverted: {partial_add_receipt}");
    }
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;
    if query_object(client, json_str(&add_a, "id")?)
        .await?
        .is_some()
        || query_object(client, json_str(&add_b, "id")?)
            .await?
            .is_some()
    {
        bail!("partial add_liquidity left a consumed persistent input live");
    }
    let pool_after_partial_add = query_object(client, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool missing after partial add_liquidity"))?;
    let (ra_add, rb_add) = decode_pool_reserves(&pool_after_partial_add)?;
    if (ra_add, rb_add) != (10_500, 10_500) {
        bail!("partial add_liquidity reserves got ({ra_add}, {rb_add}), expected (10500, 10500)");
    }
    pool_version = object_version(&pool_after_partial_add)?;
    let added_lp = ls_objects_by_type(client, "LpPosition")
        .await?
        .into_iter()
        .find(|lp| {
            json_str(lp, "id")
                .map(|id| !lps_before.contains(id))
                .unwrap_or(false)
                && decode_lp_pool_id(lp).ok().as_ref() == Some(&pool_id)
        })
        .ok_or_else(|| anyhow!("partial add_liquidity did not mint a primary-pool LP"))?;
    let added_lp_id = obj_id_from_hex(&added_lp)?;
    if decode_lp_self_id(&added_lp)? != added_lp_id {
        bail!("partial add_liquidity LP payload self-id mismatch");
    }

    let remove_partial_lp = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "remove_liquidity".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: added_lp_id,
                        expected_version: ExpectedVersion(object_version(&added_lp)?),
                        access_mode: AccessMode::Consume,
                    },
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let remove_partial_receipt = submit_ptb(home0, HOST_RPC_PORTS[0], remove_partial_lp)?;
    if !remove_partial_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("remove partial add_liquidity LP reverted: {remove_partial_receipt}");
    }
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;
    let pool_after_remove = query_object(client, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool missing after partial LP removal"))?;
    let (ra_remove, rb_remove) = decode_pool_reserves(&pool_after_remove)?;
    if (ra_remove, rb_remove) != (10_000, 10_000) {
        bail!(
            "partial add_liquidity cleanup reserves got ({ra_remove}, {rb_remove}), expected (10000, 10000)"
        );
    }
    pool_version = object_version(&pool_after_remove)?;

    let before_exact_seed = owned_coin_ids(client, &signer_hex).await?;
    let seed_exact_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            fungible_mint_cmd(
                fungible_hash,
                mint_cap_id,
                mint_cap_version,
                supply_id,
                *supply_version,
                120,
            ),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let seed_exact_receipt = submit_ptb(home0, HOST_RPC_PORTS[0], seed_exact_ptb)?;
    if !seed_exact_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("partial exact_out seed mint reverted: {seed_exact_receipt}");
    }
    *supply_version = refresh_object_version(client, supply_id, "Supply<Erased>").await?;
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;
    let max_in_coin =
        wait_for_new_owned_coins_with_values(client, &signer_hex, &before_exact_seed, &[120])
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("missing persistent exact-out max_in coin"))?;
    let before_exact = owned_coin_ids(client, &signer_hex).await?;
    let partial_exact_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_out".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_b_id,
                        expected_version: ExpectedVersion(*pool_b_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: obj_id_from_hex(&max_in_coin)?,
                        expected_version: ExpectedVersion(object_version(&max_in_coin)?),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Const(90u128.to_be_bytes().to_vec()),
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
            PtbCommand::Move(MoveCmd {
                petal: wallet_ref(wallet_hash),
                function: "receive_optional".to_string(),
                type_args: vec![],
                args: vec![use_ret(0, 1), Arg::Const(ptb_signer_pubkey().to_vec())],
            }),
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let partial_exact_receipt = submit_ptb(home0, HOST_RPC_PORTS[0], partial_exact_ptb)?;
    if !partial_exact_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("persistent partial swap_exact_out reverted: {partial_exact_receipt}");
    }
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;
    if query_object(client, json_str(&max_in_coin, "id")?)
        .await?
        .is_some()
    {
        bail!("partial swap_exact_out left max_in persistent input live");
    }
    let exact_outputs =
        wait_for_new_owned_coins_with_values(client, &signer_hex, &before_exact, &[28, 90]).await?;
    let mut exact_values = exact_outputs
        .iter()
        .map(decode_coin_value)
        .collect::<Result<Vec<_>>>()?;
    exact_values.sort_unstable();
    if exact_values != vec![28, 90] {
        bail!("partial swap_exact_out returned values {exact_values:?}, expected [28, 90]");
    }
    let pool_b_after = query_object(client, pool_b_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool B missing after partial exact_out"))?;
    *pool_b_version = object_version(&pool_b_after)?;

    eprintln!(
        "            persistent DeX partial-consume add_liquidity and swap_exact_out conserved custody"
    );
    Ok(pool_version)
}

async fn exercise_live_malformed_transport(
    client: &RpcClient,
    tmpdir: &std::path::Path,
) -> Result<()> {
    let before = current_height(client).await?;

    // Malformed proposal: valid frame digest, invalid SSZ payload.
    let bad_proposal = encode_wire_frame(MsgType::Proposal, b"not-a-proposal")
        .context("encode malformed proposal frame")?;
    send_raw_p2p_frame(HOST_P2P_PORTS[0], &bad_proposal).context("send malformed proposal")?;

    // Malformed sync block: BlockResponse message with undecodable block bytes.
    let bad_block = encode_wire_frame(MsgType::BlockResponse, b"not-a-block")
        .context("encode malformed block response frame")?;
    send_raw_p2p_frame(HOST_P2P_PORTS[0], &bad_block).context("send malformed block response")?;

    // Oversized frame: the node must close/reject without affecting consensus.
    let oversized_len = (bloom_chain_types::frame::MAX_PAYLOAD_LEN + 1 + 33) as u32;
    let mut oversized = oversized_len.to_be_bytes().to_vec();
    oversized.extend(std::iter::repeat_n(0u8, 64));
    let _ = send_raw_p2p_frame(HOST_P2P_PORTS[0], &oversized);

    let _ = send_oversized_rpc_line(HOST_RPC_PORTS[0]);

    let bad_height = current_height(client).await?.saturating_add(1);
    let parent_hash = query_block(client, bad_height.saturating_sub(1))
        .await?
        .and_then(|b| {
            json_str(&b, "hash")
                .ok()
                .and_then(|h| hash32_from_hex(h).ok())
        })
        .ok_or_else(|| anyhow!("missing parent block hash for height {}", bad_height - 1))?;
    let (bad_proposal_block, bad_proposal) =
        signed_tampered_empty_block(tmpdir, bad_height, parent_hash, false)
            .context("build signed tampered proposal block")?;
    send_frame(
        HOST_P2P_PORTS[0],
        MsgType::BlockResponse,
        &bad_proposal_block.as_ssz_bytes(),
    )
    .context("send tampered proposal body")?;
    send_frame(
        HOST_P2P_PORTS[0],
        MsgType::Proposal,
        &bad_proposal.as_ssz_bytes(),
    )
    .context("send signed tampered proposal")?;

    let (bad_sync_block, _) = signed_tampered_empty_block(tmpdir, bad_height, parent_hash, true)
        .context("build signed tampered sync block")?;
    let bad_sync_hash = bad_sync_block.header.block_hash();
    send_frame(
        HOST_P2P_PORTS[0],
        MsgType::BlockResponse,
        &bad_sync_block.as_ssz_bytes(),
    )
    .context("send signed tampered sync block")?;

    let snapshot_height = current_height(client).await?.saturating_add(20);
    let snapshot_parent_hash = query_block(client, snapshot_height.saturating_sub(20))
        .await?
        .and_then(|b| {
            json_str(&b, "hash")
                .ok()
                .and_then(|h| hash32_from_hex(h).ok())
        })
        .unwrap_or(parent_hash);
    let (snapshot_block, _) =
        signed_tampered_empty_block(tmpdir, snapshot_height, snapshot_parent_hash, true)
            .context("build signed snapshot block")?;
    let malformed_blob = malformed_snapshot_blob(
        snapshot_block.header.height,
        snapshot_block.header.state_root,
        snapshot_block.header.parent_hash,
    );
    let malformed_blob_hash = bloom_chain_state::State::blob_hash(&malformed_blob);
    send_snapshot_response_frame(
        HOST_P2P_PORTS[0],
        &snapshot_block,
        snapshot_block.header.state_root,
        malformed_blob_hash,
        &malformed_blob,
    )
    .context("send malformed state snapshot response")?;

    let target = before.saturating_add(2);
    timeout(Duration::from_secs(30), wait_for_height(client, target))
        .await
        .map_err(|_| anyhow!("validator stopped after malformed p2p frames"))??;
    let canonical = query_block(client, bad_height).await?;
    if let Some(block) = canonical
        && json_str(&block, "hash")? == hex::encode(bad_sync_hash.0)
    {
        bail!("validator accepted tampered execution-commitment block at height {bad_height}");
    }
    eprintln!(
        "[net]   malformed and signed-tampered proposal/sync/snapshot blocks, oversized p2p, and bounded RPC inputs rejected; chain still advances"
    );
    Ok(())
}

fn malformed_snapshot_blob(height: u64, state_root: Hash32, parent_hash: Hash32) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"BLMSTATE");
    blob.push(1);
    blob.extend_from_slice(&height.to_le_bytes());
    blob.extend_from_slice(&state_root.0);
    blob.extend_from_slice(&parent_hash.0);
    blob.extend_from_slice(&0u32.to_le_bytes()); // accounts
    blob.extend_from_slice(&0u32.to_le_bytes()); // storage
    blob.extend_from_slice(&0u32.to_le_bytes()); // code
    blob.extend_from_slice(&0u32.to_le_bytes()); // objects
    blob.extend_from_slice(&1u32.to_le_bytes()); // ownership rows
    blob.push(0); // address owner kind
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&1_000_001u32.to_le_bytes()); // exceeds ownership id cap
    blob
}

fn signed_tampered_empty_block(
    tmpdir: &std::path::Path,
    height: u64,
    parent_hash: Hash32,
    with_commit: bool,
) -> Result<(Block, Proposal)> {
    let genesis = bloom_chain_node::genesis::Genesis::from_file(
        &tmpdir.join("home0").join("chain").join("genesis.toml"),
    )
    .map_err(|e| anyhow!("load docker genesis: {e}"))?;
    let keys = load_validator_keys(tmpdir)?;
    let proposer = genesis.validator_set.proposer_for(height, 0).address;
    let header = BlockHeader {
        chain_id: genesis.chain_id.clone(),
        height,
        parent_hash,
        timestamp_ms: genesis.genesis_time_ms.saturating_add(height * 1_000),
        proposer,
        txs_root: empty_txs_root(),
        state_root: Hash32([0xA5; 32]),
        receipts_root: Hash32([0x5A; 32]),
        validator_set_hash: genesis.validator_set.validator_set_hash(),
        fuel_used: 1,
        fuel_limit: 30_000_000,
    };
    let block_hash = header.block_hash();
    let commit = if with_commit {
        signed_commit(height, block_hash, &genesis.validator_set, &keys)?
    } else {
        Commit {
            height: 0,
            round: 0,
            block_hash: Hash32([0; 32]),
            votes: vec![],
        }
    };
    let block = Block {
        header,
        txs: vec![],
        commit,
    };
    let proposer_key = keys
        .iter()
        .find(|(addr, _)| *addr == proposer)
        .ok_or_else(|| anyhow!("missing proposer key {}", hex::encode(proposer.0)))?;
    let mut proposal = Proposal {
        height,
        round: 0,
        block_hash,
        pol_round: -1,
        proposer,
        sig: SigBytes(vec![]),
    };
    let digest = proposal.signing_digest();
    proposal.sig = SigBytes(proposer_key.1.sign(&digest.0).to_bytes());
    Ok((block, proposal))
}

fn signed_commit(
    height: u64,
    block_hash: Hash32,
    validator_set: &ValidatorSet,
    keys: &[(Address, bloom_keystore::xdsa::XdsaSecretKey)],
) -> Result<Commit> {
    let mut votes = Vec::new();
    for validator in validator_set.validators().iter().take(3) {
        let (_, sk) = keys
            .iter()
            .find(|(addr, _)| *addr == validator.address)
            .ok_or_else(|| anyhow!("missing validator key {}", hex::encode(validator.address.0)))?;
        let mut vote = Vote {
            height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            validator: validator.address,
            sig: SigBytes(vec![]),
        };
        let digest = vote.signing_digest();
        vote.sig = SigBytes(sk.sign(&digest.0).to_bytes());
        votes.push(vote);
    }
    Ok(Commit {
        height,
        round: 0,
        block_hash,
        votes,
    })
}

fn load_validator_keys(
    tmpdir: &std::path::Path,
) -> Result<Vec<(Address, bloom_keystore::xdsa::XdsaSecretKey)>> {
    let mut out = Vec::new();
    for i in 0..4 {
        let bytes = std::fs::read(
            tmpdir
                .join(format!("home{i}"))
                .join("chain")
                .join("keystore")
                .join("validator.xdsa"),
        )
        .with_context(|| format!("read validator key home{i}"))?;
        let sk = bloom_keystore::xdsa::XdsaSecretKey::from_bytes(&bytes)
            .map_err(|e| anyhow!("decode validator key home{i}: {e}"))?;
        let pk = sk.public_key();
        out.push((Address::from_pubkey_bytes(&pk.0), sk));
    }
    Ok(out)
}

fn empty_txs_root() -> Hash32 {
    blake3_tagged("bloom-chain.v0.txs_root:", &[])
}

fn send_frame(port: u16, msg_type: MsgType, payload: &[u8]) -> Result<()> {
    let frame = encode_wire_frame(msg_type, payload).context("encode p2p frame")?;
    send_raw_p2p_frame(port, &frame)
}

fn send_snapshot_response_frame(
    port: u16,
    block: &Block,
    state_root: Hash32,
    blob_hash: Hash32,
    blob: &[u8],
) -> Result<()> {
    let block_bytes = block.as_ssz_bytes();
    let mut payload = Vec::with_capacity(4 + block_bytes.len() + 64 + blob.len());
    payload.extend_from_slice(&(block_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&block_bytes);
    payload.extend_from_slice(&state_root.0);
    payload.extend_from_slice(&blob_hash.0);
    payload.extend_from_slice(blob);
    send_frame(port, MsgType::StateSnapshotResponse, &payload)
}

fn send_raw_p2p_frame(port: u16, bytes: &[u8]) -> Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("connect p2p port {port}"))?;
    stream
        .write_all(bytes)
        .with_context(|| format!("write p2p frame to port {port}"))?;
    Ok(())
}

fn send_oversized_rpc_line(port: u16) -> Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("connect RPC port {port}"))?;
    let mut line = br#"{"jsonrpc":"2.0","id":1,"method":"chain_tip","params":{"pad":""#.to_vec();
    line.extend(std::iter::repeat_n(b'a', 3 * 1024 * 1024));
    line.extend_from_slice(br#""}}"#);
    line.push(b'\n');
    let _ = stream.write_all(&line);
    Ok(())
}

fn pool_type_tag(pool_hash: bloom_chain_types::types::Hash32) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: pool_hash.0,
        type_name: "Pool".to_string(),
        type_args: vec![],
    }
}

fn u128_type_tag() -> TypeTag {
    TypeTag::Concrete {
        petal_hash: bloom_objects::BUILTIN_TYPE_HASH,
        type_name: "u128".to_string(),
        type_args: vec![],
    }
}

fn counter_type_tag(petal_hash: Hash32) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: petal_hash.0,
        type_name: "Counter".to_string(),
        type_args: vec![],
    }
}

fn view_probe_manifest() -> Vec<u8> {
    let self_counter = counter_type_tag(Hash32([0u8; 32]));
    let manifest = PetalManifest {
        schema_version: SCHEMA_VERSION,
        module_path: PETAL_VFS_PROBE_PATH.to_string(),
        functions: vec![
            FunctionDecl {
                name: "answer".to_string(),
                view: true,
                returns: vec![u128_type_tag()],
                ..Default::default()
            },
            FunctionDecl {
                name: "init_counter".to_string(),
                returns: vec![self_counter.clone()],
                ..Default::default()
            },
            FunctionDecl {
                name: "set_counter".to_string(),
                args: vec![ArgDecl {
                    name: "counter".to_string(),
                    kind: ArgKind::Object {
                        ty: self_counter.clone(),
                        mode: AccessMode::Mutable,
                    },
                }],
                ..Default::default()
            },
            FunctionDecl {
                name: "set_counter_99_ret".to_string(),
                args: vec![ArgDecl {
                    name: "counter".to_string(),
                    kind: ArgKind::Object {
                        ty: self_counter.clone(),
                        mode: AccessMode::Mutable,
                    },
                }],
                returns: vec![self_counter.clone()],
                ..Default::default()
            },
            FunctionDecl {
                name: "set_counter_123_ret".to_string(),
                args: vec![ArgDecl {
                    name: "counter".to_string(),
                    kind: ArgKind::Object {
                        ty: self_counter.clone(),
                        mode: AccessMode::Mutable,
                    },
                }],
                returns: vec![self_counter.clone()],
                ..Default::default()
            },
            FunctionDecl {
                name: "sink_counter".to_string(),
                args: vec![ArgDecl {
                    name: "counter".to_string(),
                    kind: ArgKind::Object {
                        ty: self_counter.clone(),
                        mode: AccessMode::ReadOnly,
                    },
                }],
                ..Default::default()
            },
            FunctionDecl {
                name: "fail_after_counter".to_string(),
                args: vec![ArgDecl {
                    name: "counter".to_string(),
                    kind: ArgKind::Object {
                        ty: self_counter.clone(),
                        mode: AccessMode::ReadOnly,
                    },
                }],
                ..Default::default()
            },
            FunctionDecl {
                name: "fail_counter".to_string(),
                ..Default::default()
            },
            FunctionDecl {
                name: "counter_value".to_string(),
                view: true,
                args: vec![ArgDecl {
                    name: "counter".to_string(),
                    kind: ArgKind::Object {
                        ty: self_counter,
                        mode: AccessMode::ReadOnly,
                    },
                }],
                returns: vec![u128_type_tag()],
                ..Default::default()
            },
        ],
        object_types: vec![bloom_petal_manifest::types::ObjectTypeDecl {
            name: "Counter".to_string(),
            abilities: AbilitySet::key_store(),
            fields: vec![bloom_petal_manifest::types::FieldDecl {
                name: "value".to_string(),
                ty: u128_type_tag(),
                offset: Some(0),
                width: Some(16),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    bloom_petal_manifest::encode(&manifest).expect("view probe manifest encodes")
}

fn view_probe_wasm() -> Vec<u8> {
    let counter_tag = counter_type_tag(Hash32([0u8; 32]))
        .encode_canonical()
        .expect("counter type tag encodes");
    let counter_tag_wat = wat_bytes(&counter_tag);
    let counter_tag_len = counter_tag.len();
    let wat = format!(
        r#"
(module
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (import "chain" "petal.revert" (func $revert (param i32 i32)))
  (import "chain" "msg.calldata.read" (func $cdread (param i32 i32 i32) (result i32)))
  (import "object" "borrow" (func $borrow (param i32 i32) (result i32)))
  (import "object" "create" (func $create (param i32 i32 i32 i32) (result i32)))
  (import "object" "id" (func $id (param i32 i32) (result i32)))
  (import "object" "mutate" (func $mutate (param i32 i32 i32) (result i32)))
  (import "object" "read" (func $read (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; count=1, len=16, u128=42
  (data (i32.const 0) "\00\00\00\01\10\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\2a")
  (data (i32.const 64) "{counter_tag_wat}")
  ;; Counter payloads: initial 42, then mutated values.
  (data (i32.const 160) "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\2a")
  (data (i32.const 192) "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\4d")
  (data (i32.const 208) "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\63")
  (data (i32.const 224) "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\7b")
  (data (i32.const 240) "forced revert")
  ;; one object-id return slot: count=1, len=32
  (data (i32.const 512) "\00\00\00\01\20")
  ;; one u128 return slot: count=1, len=16
  (data (i32.const 640) "\00\00\00\01\10")
  (func (export "__petal_answer") (param i32 i32) (result i32)
    (call $ret (i32.const 0) (i32.const 21))
    i32.const 0)
  (func (export "__petal_init_counter") (param i32 i32) (result i32)
    (local $h i32)
    (local.set $h
      (call $create (i32.const 64) (i32.const {counter_tag_len}) (i32.const 160) (i32.const 16)))
    (drop (call $id (local.get $h) (i32.const 517)))
    (call $ret (i32.const 512) (i32.const 37))
    i32.const 0)
  (func (export "__petal_set_counter") (param i32 i32) (result i32)
    (local $h i32)
    ;; Arg 0 is an object: count(4), tag(1), id(32).
    (drop (call $cdread (i32.const 256) (i32.const 5) (i32.const 32)))
    (local.set $h (call $borrow (i32.const 256) (i32.const 1)))
    (drop (call $mutate (local.get $h) (i32.const 192) (i32.const 16)))
    i32.const 0)
  (func (export "__petal_set_counter_99_ret") (param i32 i32) (result i32)
    (local $h i32)
    ;; Arg 0 is an object: count(4), tag(1), id(32).
    (drop (call $cdread (i32.const 256) (i32.const 5) (i32.const 32)))
    (local.set $h (call $borrow (i32.const 256) (i32.const 1)))
    (drop (call $mutate (local.get $h) (i32.const 208) (i32.const 16)))
    (drop (call $id (local.get $h) (i32.const 517)))
    (call $ret (i32.const 512) (i32.const 37))
    i32.const 0)
  (func (export "__petal_set_counter_123_ret") (param i32 i32) (result i32)
    (local $h i32)
    ;; Arg 0 is an object: count(4), tag(1), id(32).
    (drop (call $cdread (i32.const 256) (i32.const 5) (i32.const 32)))
    (local.set $h (call $borrow (i32.const 256) (i32.const 1)))
    (drop (call $mutate (local.get $h) (i32.const 224) (i32.const 16)))
    (drop (call $id (local.get $h) (i32.const 517)))
    (call $ret (i32.const 512) (i32.const 37))
    i32.const 0)
  (func (export "__petal_sink_counter") (param i32 i32) (result i32)
    (local $h i32)
    ;; Arg 0 is an object: count(4), tag(1), id(32).
    (drop (call $cdread (i32.const 256) (i32.const 5) (i32.const 32)))
    (local.set $h (call $borrow (i32.const 256) (i32.const 0)))
    i32.const 0)
  (func (export "__petal_fail_after_counter") (param i32 i32) (result i32)
    (local $h i32)
    ;; Arg 0 is an object: count(4), tag(1), id(32).
    (drop (call $cdread (i32.const 256) (i32.const 5) (i32.const 32)))
    (local.set $h (call $borrow (i32.const 256) (i32.const 0)))
    (call $revert (i32.const 240) (i32.const 13))
    i32.const 0)
  (func (export "__petal_fail_counter") (param i32 i32) (result i32)
    (call $revert (i32.const 240) (i32.const 13))
    i32.const 0)
  (func (export "__petal_counter_value") (param i32 i32) (result i32)
    (local $h i32)
    ;; Arg 0 is an object: count(4), tag(1), id(32).
    (drop (call $cdread (i32.const 256) (i32.const 5) (i32.const 32)))
    (local.set $h (call $borrow (i32.const 256) (i32.const 0)))
    (drop (call $read (local.get $h) (i32.const 645) (i32.const 16)))
    (call $ret (i32.const 640) (i32.const 21))
    i32.const 0)
)
"#,
        counter_tag_wat = counter_tag_wat,
        counter_tag_len = counter_tag_len,
    );
    append_manifest_section(wat_to_wasm(&wat), &view_probe_manifest())
}

fn adversary_manifest(pool_hash: bloom_chain_types::types::Hash32) -> Vec<u8> {
    let pool_ty = pool_type_tag(pool_hash);
    let manifest = PetalManifest {
        schema_version: SCHEMA_VERSION,
        module_path: ADVERSARY_PATH.to_string(),
        functions: vec![
            FunctionDecl {
                name: "corrupt_pool".to_string(),
                args: vec![ArgDecl {
                    name: "pool".to_string(),
                    kind: ArgKind::Object {
                        ty: pool_ty.clone(),
                        mode: AccessMode::Mutable,
                    },
                }],
                ..Default::default()
            },
            FunctionDecl {
                name: "steal_pool".to_string(),
                args: vec![ArgDecl {
                    name: "pool".to_string(),
                    kind: ArgKind::Object {
                        ty: pool_ty,
                        mode: AccessMode::Consume,
                    },
                }],
                ..Default::default()
            },
        ],
        object_types: vec![bloom_petal_manifest::types::ObjectTypeDecl {
            name: "AdversaryMarker".to_string(),
            abilities: AbilitySet::key_store(),
            ..Default::default()
        }],
        ..Default::default()
    };
    bloom_petal_manifest::encode(&manifest).expect("adversary manifest encodes")
}

fn adversary_wasm(
    pool_hash: bloom_chain_types::types::Hash32,
    pool_id: bloom_objects::ObjectId,
) -> Vec<u8> {
    let pool_id_wat = wat_bytes(&pool_id.0);
    let attacker = wat_bytes(&ptb_signer_pubkey());
    let erased = erased_type_tag();
    let poisoned_payload = wat_bytes(&bloom_petal_dex_pool::payload::pool_payload(
        &pool_id,
        1,
        1,
        1,
        1,
        &POOL_FEE_BPS.to_be_bytes(),
        &erased,
        &erased,
    ));
    let payload_len = bloom_petal_dex_pool::payload::pool_payload(
        &pool_id,
        1,
        1,
        1,
        1,
        &POOL_FEE_BPS.to_be_bytes(),
        &erased,
        &erased,
    )
    .len();
    let wat = format!(
        r#"
(module
  (import "chain" "petal.revert" (func $revert (param i32 i32)))
  (import "object" "borrow" (func $borrow (param i32 i32) (result i32)))
  (import "object" "mutate" (func $mutate (param i32 i32 i32) (result i32)))
  (import "object" "transfer" (func $transfer (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{pool_id_wat}")
  (data (i32.const 64) "{poisoned_payload}")
  (data (i32.const 256) "{attacker}")
  (data (i32.const 320) "attack blocked")
  (func (export "__petal_corrupt_pool") (param i32 i32) (result i32)
    (local $h i32)
    (local $r i32)
    (local.set $h (call $borrow (i32.const 0) (i32.const 1)))
    (local.set $r (call $mutate (local.get $h) (i32.const 64) (i32.const {payload_len})))
    (if (i32.ne (local.get $r) (i32.const 0))
      (then (call $revert (i32.const 320) (i32.const 14))))
    i32.const 0)
  (func (export "__petal_steal_pool") (param i32 i32) (result i32)
    (local $h i32)
    (local $r i32)
    (local.set $h (call $borrow (i32.const 0) (i32.const 2)))
    (local.set $r (call $transfer (local.get $h) (i32.const 0) (i32.const 256) (i32.const 32)))
    (if (i32.ne (local.get $r) (i32.const 0))
      (then (call $revert (i32.const 320) (i32.const 14))))
    i32.const 0)
)
"#
    );
    append_manifest_section(wat_to_wasm(&wat), &adversary_manifest(pool_hash))
}

fn loom_probe_manifest(fungible_hash: Hash32) -> Vec<u8> {
    let coin_ty = loom_coin_type_tag(fungible_hash);
    let manifest = PetalManifest {
        schema_version: SCHEMA_VERSION,
        module_path: LOOM_PROBE_PATH.to_string(),
        functions: vec![
            FunctionDecl {
                name: "load_merge".to_string(),
                args: vec![
                    ArgDecl {
                        name: "a".to_string(),
                        kind: ArgKind::Object {
                            ty: coin_ty.clone(),
                            mode: AccessMode::Mutable,
                        },
                    },
                    ArgDecl {
                        name: "b".to_string(),
                        kind: ArgKind::Object {
                            ty: coin_ty.clone(),
                            mode: AccessMode::Consume,
                        },
                    },
                ],
                returns: vec![coin_ty.clone(), coin_ty.clone()],
                ..Default::default()
            },
            FunctionDecl {
                name: "load_split".to_string(),
                args: vec![ArgDecl {
                    name: "coin".to_string(),
                    kind: ArgKind::Object {
                        ty: coin_ty.clone(),
                        mode: AccessMode::Mutable,
                    },
                }],
                returns: vec![coin_ty],
                ..Default::default()
            },
            FunctionDecl {
                name: "trap_after_work".to_string(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    bloom_petal_manifest::encode(&manifest).expect("loom probe manifest encodes")
}

fn loom_probe_wasm(
    merge_a: bloom_objects::ObjectId,
    merge_b: bloom_objects::ObjectId,
    split_src: bloom_objects::ObjectId,
    fungible_hash: Hash32,
) -> Vec<u8> {
    let merge_a_wat = wat_bytes(&merge_a.0);
    let merge_b_wat = wat_bytes(&merge_b.0);
    let split_wat = wat_bytes(&split_src.0);
    let wat = format!(
        r#"
(module
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; count=2 | len=32 | merge_a | len=32 | merge_b
  (data (i32.const 0) "\00\00\00\02\20{merge_a_wat}\20{merge_b_wat}")
  ;; count=1 | len=32 | split_src
  (data (i32.const 128) "\00\00\00\01\20{split_wat}")
  (func (export "__petal_load_merge") (param i32 i32) (result i32)
    (call $ret (i32.const 0) (i32.const 70))
    i32.const 0)
  (func (export "__petal_load_split") (param i32 i32) (result i32)
    (call $ret (i32.const 128) (i32.const 37))
    i32.const 0)
  (func (export "__petal_trap_after_work") (param i32 i32) (result i32)
    (local $i i32)
    (loop $again
      (if (i32.lt_u (local.get $i) (i32.const 1000))
        (then
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $again))))
    unreachable)
)
"#
    );
    append_manifest_section(wat_to_wasm(&wat), &loom_probe_manifest(fungible_hash))
}

fn wat_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// CLI shellouts (host-side `bloom` binary)
// ---------------------------------------------------------------------------

fn compose_tmpdir() -> Result<PathBuf> {
    let s = std::env::var("BLOOM_DOCKER_TMPDIR")
        .context("BLOOM_DOCKER_TMPDIR not set; run via scripts/test-docker-petal-dex.sh")?;
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

fn docker_petal_wasm_path(stem: &str, build: fn() -> PathBuf) -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("BLOOM_DOCKER_PREBUILT_WASM_DIR") {
        let path = PathBuf::from(dir).join(format!("{stem}.wasm"));
        if path.exists() {
            return Ok(path);
        }
        bail!(
            "BLOOM_DOCKER_PREBUILT_WASM_DIR was set, but {} is missing",
            path.display()
        );
    }
    Ok(build())
}

/// `bloom chain deploy <wasm> --wait` from `home`, dialing the validator at
/// `127.0.0.1:<port>` via `BLOOM_RPC_TCP`.
fn deploy_petal(home: &std::path::Path, port: u16, wasm: &std::path::Path) -> Result<()> {
    let rpc = format!("127.0.0.1:{}", port);
    let out = Command::new(bloom_bin())
        .env("BLOOM_RPC_TCP", &rpc)
        .arg("--home")
        .arg(home)
        .arg("chain")
        .arg("deploy")
        .arg(wasm)
        .arg("--wait")
        .arg("--wait-timeout-secs")
        .arg("60")
        .output()
        .context("invoke bloom chain deploy")?;
    if !out.status.success() {
        bail!(
            "bloom chain deploy {} failed:\n  stdout={}\n  stderr={}",
            wasm.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let receipt = parse_success_receipt(&stdout)
        .with_context(|| format!("parse deploy receipt for {}", wasm.display()))?;
    if !receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!(
            "bloom chain deploy {} reverted: receipt={receipt}",
            wasm.display()
        );
    }
    Ok(())
}

async fn exercise_live_petal_vfs_mount(
    clients: &[RpcClient],
    tmpdir: &Path,
    home: &Path,
    gas_payer: bloom_objects::ObjectId,
    probe_hash: Hash32,
) -> Result<()> {
    let mount_dir = tmpdir.join("petal-vfs-mount");
    if mount_dir.exists() {
        std::fs::remove_dir_all(&mount_dir)
            .with_context(|| format!("remove old mount dir {}", mount_dir.display()))?;
    }
    std::fs::create_dir_all(&mount_dir)
        .with_context(|| format!("create mount dir {}", mount_dir.display()))?;

    let bloom = bloom_bin();
    let bloom_dir = bloom
        .parent()
        .ok_or_else(|| anyhow!("BLOOM_BIN has no parent: {}", bloom.display()))?;
    let path_env = match std::env::var_os("PATH") {
        Some(path) => {
            let mut paths = std::env::split_paths(&path).collect::<Vec<_>>();
            paths.insert(0, bloom_dir.to_path_buf());
            std::env::join_paths(paths).context("build PATH for petal VFS shim")?
        }
        None => std::env::join_paths([bloom_dir]).context("build PATH for petal VFS shim")?,
    };

    let rpc = format!("127.0.0.1:{}", HOST_RPC_PORTS[0]);
    let serve_home = tmpdir.join("petal-vfs-serve-home");
    if serve_home.exists() {
        std::fs::remove_dir_all(&serve_home)
            .with_context(|| format!("remove old serve home {}", serve_home.display()))?;
    }
    std::fs::create_dir_all(&serve_home)
        .with_context(|| format!("create serve home {}", serve_home.display()))?;
    let short_home = short_home_symlink(&serve_home)?;
    let serve_stdout_path = tmpdir.join("petal-vfs-serve.stdout.log");
    let serve_stderr_path = tmpdir.join("petal-vfs-serve.stderr.log");
    let serve_stdout = std::fs::File::create(&serve_stdout_path)
        .with_context(|| format!("create {}", serve_stdout_path.display()))?;
    let serve_stderr = std::fs::File::create(&serve_stderr_path)
        .with_context(|| format!("create {}", serve_stderr_path.display()))?;
    let mut child = Command::new(&bloom)
        .env("BLOOM_HOME", &short_home)
        .env("BLOOM_RPC_TCP", &rpc)
        .env("PATH", &path_env)
        .arg("serve")
        .arg("--mount")
        .arg(&mount_dir)
        .stdout(Stdio::from(serve_stdout))
        .stderr(Stdio::from(serve_stderr))
        .spawn()
        .with_context(|| format!("spawn bloom serve --mount {}", mount_dir.display()))?;

    let answer_endpoint = mount_dir.join("petals/dex/view-probe/answer");
    let counter_endpoint = mount_dir.join("petals/dex/view-probe/counter_value");
    let set_counter_endpoint = mount_dir.join("petals/dex/view-probe/set_counter");
    let fail_counter_endpoint = mount_dir.join("petals/dex/view-probe/fail_counter");
    let pipe_endpoint = mount_dir.join("petals/.pipe");
    let wait_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().context("poll bloom serve --mount")? {
            let _ = std::fs::remove_file(&short_home);
            bail!(
                "bloom serve --mount exited early ({status}):\nstdout={}\nstderr={}",
                read_log_lossy(&serve_stdout_path),
                read_log_lossy(&serve_stderr_path)
            );
        }
        if answer_endpoint.exists()
            && counter_endpoint.exists()
            && set_counter_endpoint.exists()
            && fail_counter_endpoint.exists()
            && pipe_endpoint.exists()
        {
            break;
        }
        if Instant::now() >= wait_deadline {
            stop_child(&mut child);
            let _ = std::fs::remove_file(&short_home);
            bail!(
                "timed out waiting for mounted endpoint {}",
                counter_endpoint.display()
            );
        }
        sleep(Duration::from_millis(250)).await;
    }

    let direct = direct_petal_vfs_answer(home)?;
    let argv = run_mounted_petal_endpoint(&answer_endpoint, home, &rpc, &path_env, None)?;
    let stdin = run_mounted_petal_endpoint(
        &answer_endpoint,
        home,
        &rpc,
        &path_env,
        Some(serde_json::json!({
            "args": [],
            "fuel_limit": 1_000_000u64,
        })),
    )?;

    if view_returns(&argv) != view_returns(&direct) {
        bail!(
            "mounted argv view result differed from direct chain_view_call: argv={argv} direct={direct}"
        );
    }
    if view_returns(&stdin) != view_returns(&direct) {
        bail!(
            "mounted stdin view result differed from direct chain_view_call: stdin={stdin} direct={direct}"
        );
    }
    eprintln!("[petals-vfs] mounted answer view argv/stdin returns matched direct chain_view_call");

    let before_counters = ls_objects_by_type(&clients[0], "Counter").await?;
    let create_counter = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            PtbCommand::Move(MoveCmd {
                petal: PetalRef {
                    path: PETAL_VFS_PROBE_PATH.to_string(),
                    hash: Some(probe_hash),
                },
                function: "init_counter".to_string(),
                type_args: vec![],
                args: vec![],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Shared,
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let create_receipt = submit_ptb(home, HOST_RPC_PORTS[0], create_counter)?;
    if !create_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("VFS counter create PTB reverted: {create_receipt}");
    }
    let latest = current_height(&clients[0]).await?;
    wait_all_reach_height(clients, latest).await?;

    let counter = ls_objects_by_type(&clients[0], "Counter")
        .await?
        .into_iter()
        .find(|obj| {
            let Ok(id) = json_str(obj, "id") else {
                return false;
            };
            !before_counters
                .iter()
                .any(|before| json_str(before, "id").ok() == Some(id))
        })
        .ok_or_else(|| anyhow!("VFS counter create did not produce a new Counter object"))?;
    let counter_id = json_str(&counter, "id")?.to_string();
    let counter_version = object_version(&counter)?;
    if json_str(&counter, "owner_kind")? != "shared" {
        bail!("VFS counter was not shared after create: {counter}");
    }

    let direct_before = direct_petal_vfs_counter_value(home, &counter_id)?;
    eprintln!("[petals-vfs] reading mounted counter before mutation");
    let mounted_before = run_mounted_petal_endpoint(
        &counter_endpoint,
        home,
        &rpc,
        &path_env,
        Some(serde_json::json!({
            "args": [{ "kind": "object", "id": counter_id }],
            "fuel_limit": 1_000_000u64,
        })),
    )?;
    let before_value = first_view_u128_return(&mounted_before)?;
    if before_value != 42 || view_returns(&mounted_before) != view_returns(&direct_before) {
        bail!(
            "mounted counter view before mutation differed: mounted={mounted_before} direct={direct_before}"
        );
    }

    let counter_arg = serde_json::json!({
        "kind": "object",
        "id": counter_id,
        "version": counter_version,
    })
    .to_string();
    let set_receipt = run_mounted_petal_endpoint_with_args(
        &set_counter_endpoint,
        home,
        &rpc,
        &path_env,
        &["--arg".to_string(), counter_arg],
        Some(serde_json::json!({
            "gas_budget": PTB_GAS_BUDGET,
            "fuel_limit": 10_000_000u64,
        })),
    )?;
    if !set_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("mounted VFS counter mutation endpoint reverted: {set_receipt}");
    }
    let latest = current_height(&clients[0]).await?;
    wait_all_reach_height(clients, latest).await?;

    let direct_after = direct_petal_vfs_counter_value(home, &counter_id)?;
    eprintln!("[petals-vfs] reading mounted counter after mutation");
    let mounted_after = run_mounted_petal_endpoint(
        &counter_endpoint,
        home,
        &rpc,
        &path_env,
        Some(serde_json::json!({
            "args": [{ "kind": "object", "id": counter_id }],
            "fuel_limit": 1_000_000u64,
        })),
    )?;
    let after_value = first_view_u128_return(&mounted_after)?;
    if after_value != 77 || view_returns(&mounted_after) != view_returns(&direct_after) {
        bail!(
            "mounted counter view after mutation differed: mounted={mounted_after} direct={direct_after}"
        );
    }

    let counter_after_set = ls_objects_by_type(&clients[0], "Counter")
        .await?
        .into_iter()
        .find(|obj| json_str(obj, "id").ok() == Some(counter_id.as_str()))
        .ok_or_else(|| anyhow!("counter disappeared before pipe composition"))?;
    let counter_version_after_set = object_version(&counter_after_set)?;
    let pipe_success_expr = format!(
        "{PETAL_VFS_PROBE_PATH}/set_counter_99_ret obj:{counter_id}@{counter_version_after_set} \
         | {PETAL_VFS_PROBE_PATH}/sink_counter"
    );
    let pipe_success = run_mounted_petal_endpoint_raw_stdin(
        &pipe_endpoint,
        home,
        &rpc,
        &path_env,
        &[
            "--gas-budget".to_string(),
            PTB_GAS_BUDGET.to_string(),
            "--fuel-limit".to_string(),
            "10000000".to_string(),
        ],
        Some(&pipe_success_expr),
    )?;
    if !pipe_success.status.success() {
        bail!(
            "mounted pipe composition unexpectedly failed:\nexpr={pipe_success_expr}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&pipe_success.stdout),
            String::from_utf8_lossy(&pipe_success.stderr)
        );
    }
    assert_pipe_ndjson("mounted pipe success", &pipe_success.stdout, 2, true)?;
    let latest = current_height(&clients[0]).await?;
    wait_all_reach_height(clients, latest).await?;

    let mounted_after_pipe = run_mounted_petal_endpoint(
        &counter_endpoint,
        home,
        &rpc,
        &path_env,
        Some(serde_json::json!({
            "args": [{ "kind": "object", "id": counter_id }],
            "fuel_limit": 1_000_000u64,
        })),
    )?;
    let after_pipe_value = first_view_u128_return(&mounted_after_pipe)?;
    if after_pipe_value != 99 {
        bail!("mounted pipe composition did not mutate counter to 99: {mounted_after_pipe}");
    }
    let state_value_path = mount_dir.join(format!(
        "petals/dex/view-probe/.state/Counter/{counter_id}/value"
    ));
    let state_value_text = std::fs::read_to_string(&state_value_path)
        .with_context(|| format!("read state projection field {}", state_value_path.display()))?;
    let state_value: Value = serde_json::from_str(&state_value_text).with_context(|| {
        format!(
            "parse state projection field {}: {state_value_text}",
            state_value_path.display()
        )
    })?;
    if state_value != serde_json::json!(after_pipe_value.to_string()) {
        bail!(
            "mounted state projection value differed from view result: state={state_value} view={mounted_after_pipe}"
        );
    }
    let state_object_path = mount_dir.join(format!(
        "petals/dex/view-probe/.state/Counter/{counter_id}/_object.json"
    ));
    let state_object_text = std::fs::read_to_string(&state_object_path).with_context(|| {
        format!(
            "read state projection object {}",
            state_object_path.display()
        )
    })?;
    let state_object: Value = serde_json::from_str(&state_object_text).with_context(|| {
        format!(
            "parse state projection object {}: {state_object_text}",
            state_object_path.display()
        )
    })?;
    if state_object.get("id").and_then(Value::as_str) != Some(counter_id.as_str())
        || state_object.pointer("/fields/value") != Some(&state_value)
    {
        bail!(
            "mounted state projection _object.json did not match field read: object={state_object} field={state_value}"
        );
    }

    let counter_after_pipe = ls_objects_by_type(&clients[0], "Counter")
        .await?
        .into_iter()
        .find(|obj| json_str(obj, "id").ok() == Some(counter_id.as_str()))
        .ok_or_else(|| anyhow!("counter disappeared before reverting pipe composition"))?;
    let counter_version_after_pipe = object_version(&counter_after_pipe)?;
    let pipe_revert_expr = format!(
        "{PETAL_VFS_PROBE_PATH}/set_counter_123_ret obj:{counter_id}@{counter_version_after_pipe} \
         | {PETAL_VFS_PROBE_PATH}/fail_after_counter"
    );
    let pipe_revert = run_mounted_petal_endpoint_raw_stdin(
        &pipe_endpoint,
        home,
        &rpc,
        &path_env,
        &[
            "--gas-budget".to_string(),
            PTB_GAS_BUDGET.to_string(),
            "--fuel-limit".to_string(),
            "10000000".to_string(),
        ],
        Some(&pipe_revert_expr),
    )?;
    if pipe_revert.status.success() {
        bail!(
            "mounted reverting pipe composition unexpectedly succeeded:\nexpr={pipe_revert_expr}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&pipe_revert.stdout),
            String::from_utf8_lossy(&pipe_revert.stderr)
        );
    }
    assert_pipe_ndjson("mounted pipe revert", &pipe_revert.stdout, 2, false)?;
    let latest = current_height(&clients[0]).await?;
    wait_all_reach_height(clients, latest).await?;
    let mounted_after_revert_pipe = run_mounted_petal_endpoint(
        &counter_endpoint,
        home,
        &rpc,
        &path_env,
        Some(serde_json::json!({
            "args": [{ "kind": "object", "id": counter_id }],
            "fuel_limit": 1_000_000u64,
        })),
    )?;
    let after_revert_pipe_value = first_view_u128_return(&mounted_after_revert_pipe)?;
    if after_revert_pipe_value != 99 {
        bail!(
            "mounted reverting pipe composition partially mutated state: {mounted_after_revert_pipe}"
        );
    }

    eprintln!(
        "[petals-vfs] mounted counter endpoint and pipe composition mutated atomically: {before_value} -> {after_value} -> {after_pipe_value}"
    );
    stop_child(&mut child);
    let _ = std::fs::remove_file(&short_home);
    Ok(())
}

fn short_home_symlink(home: &Path) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let link = PathBuf::from(format!(
        "/tmp/bloom-vfs-home-{}-{nanos}",
        std::process::id()
    ));
    std::os::unix::fs::symlink(home, &link)
        .with_context(|| format!("symlink {} -> {}", link.display(), home.display()))?;
    Ok(link)
}

fn view_returns(value: &Value) -> Option<&Value> {
    value
        .get("commands")
        .and_then(Value::as_array)
        .and_then(|commands| commands.first())
        .and_then(|command| command.get("returns"))
}

fn first_view_u128_return(value: &Value) -> Result<u128> {
    view_returns(value)
        .and_then(Value::as_array)
        .and_then(|returns| returns.first())
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("view result missing first u128 return: {value}"))?
        .parse::<u128>()
        .with_context(|| format!("parse first u128 return from {value}"))
}

fn direct_petal_vfs_answer(home: &Path) -> Result<Value> {
    let out = Command::new(bloom_bin())
        .env("BLOOM_RPC_TCP", format!("127.0.0.1:{}", HOST_RPC_PORTS[0]))
        .arg("--home")
        .arg(home)
        .arg("chain")
        .arg("view-call")
        .arg("--path")
        .arg(PETAL_VFS_PROBE_PATH)
        .arg("--function")
        .arg("answer")
        .output()
        .context("invoke direct bloom chain view-call")?;
    parse_json_command_output("direct bloom chain view-call", out)
}

fn direct_petal_vfs_counter_value(home: &Path, counter_id: &str) -> Result<Value> {
    let arg = serde_json::json!({ "kind": "object", "id": counter_id }).to_string();
    let out = Command::new(bloom_bin())
        .env("BLOOM_RPC_TCP", format!("127.0.0.1:{}", HOST_RPC_PORTS[0]))
        .arg("--home")
        .arg(home)
        .arg("chain")
        .arg("view-call")
        .arg("--path")
        .arg(PETAL_VFS_PROBE_PATH)
        .arg("--function")
        .arg("counter_value")
        .arg("--arg")
        .arg(arg)
        .output()
        .context("invoke direct bloom chain view-call counter_value")?;
    parse_json_command_output("direct bloom chain view-call counter_value", out)
}

fn run_mounted_petal_endpoint(
    endpoint: &Path,
    home: &Path,
    rpc: &str,
    path_env: &std::ffi::OsStr,
    stdin_json: Option<Value>,
) -> Result<Value> {
    run_mounted_petal_endpoint_with_args(endpoint, home, rpc, path_env, &[], stdin_json)
}

fn run_mounted_petal_endpoint_with_args(
    endpoint: &Path,
    home: &Path,
    rpc: &str,
    path_env: &std::ffi::OsStr,
    argv: &[String],
    stdin_json: Option<Value>,
) -> Result<Value> {
    let out = run_mounted_petal_endpoint_raw(endpoint, home, rpc, path_env, argv, stdin_json)?;
    parse_json_command_output(
        &format!("mounted petal endpoint {}", endpoint.display()),
        out,
    )
}

fn run_mounted_petal_endpoint_raw(
    endpoint: &Path,
    home: &Path,
    rpc: &str,
    path_env: &std::ffi::OsStr,
    argv: &[String],
    stdin_json: Option<Value>,
) -> Result<std::process::Output> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(endpoint);
        cmd.env("BLOOM_HOME", home)
            .env("BLOOM_RPC_TCP", rpc)
            .env("PATH", path_env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.args(argv);
        if stdin_json.is_some() {
            cmd.stdin(Stdio::piped());
        }

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "spawn mounted petal endpoint {} (exists={})",
                        endpoint.display(),
                        endpoint.exists()
                    )
                });
            }
        };
        if let Some(stdin_json) = stdin_json.clone() {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("mounted endpoint stdin was not piped"))?;
            stdin
                .write_all(serde_json::to_string(&stdin_json)?.as_bytes())
                .context("write mounted endpoint stdin JSON")?;
        }
        let out = child
            .wait_with_output()
            .context("wait for mounted petal endpoint")?;
        if is_transient_mounted_endpoint_enoent(endpoint, &out) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        return Ok(out);
    }
}

fn is_transient_mounted_endpoint_enoent(endpoint: &Path, out: &std::process::Output) -> bool {
    if out.status.success() {
        return false;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    stderr.contains(&endpoint.display().to_string()) && stderr.contains("No such file or directory")
}

fn run_mounted_petal_endpoint_raw_stdin(
    endpoint: &Path,
    home: &Path,
    rpc: &str,
    path_env: &std::ffi::OsStr,
    argv: &[String],
    stdin_text: Option<&str>,
) -> Result<std::process::Output> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(endpoint);
        cmd.env("BLOOM_HOME", home)
            .env("BLOOM_RPC_TCP", rpc)
            .env("PATH", path_env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd.args(argv);
        if stdin_text.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "spawn mounted petal endpoint {} (exists={})",
                        endpoint.display(),
                        endpoint.exists()
                    )
                });
            }
        };
        if let Some(stdin_text) = stdin_text {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("mounted endpoint stdin was not piped"))?;
            stdin
                .write_all(stdin_text.as_bytes())
                .context("write mounted endpoint stdin text")?;
        }
        let out = child
            .wait_with_output()
            .context("wait for mounted petal endpoint")?;
        if is_transient_mounted_endpoint_enoent(endpoint, &out) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        return Ok(out);
    }
}

fn read_log_lossy(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|err| format!("<failed to read: {err}>"))
}

fn assert_pipe_ndjson(
    label: &str,
    stdout: &[u8],
    expected_commands: u64,
    expected_success: bool,
) -> Result<()> {
    let text = std::str::from_utf8(stdout).with_context(|| format!("{label} stdout utf8"))?;
    let lines = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()
        .with_context(|| format!("{label} parse NDJSON stdout: {text}"))?;
    let expected_lines = expected_commands as usize + 3;
    if lines.len() != expected_lines {
        bail!(
            "{label} expected {expected_lines} NDJSON lines, got {}: {lines:?}",
            lines.len()
        );
    }
    let header_line = lines
        .first()
        .ok_or_else(|| anyhow!("{label} missing PTB header line"))?;
    if header_line.get("kind").and_then(Value::as_str) != Some("ptb")
        || header_line.get("commands").and_then(Value::as_u64) != Some(expected_commands)
    {
        bail!("{label} unexpected PTB header: {header_line}");
    }
    let command_lines = &lines[1..=expected_commands as usize];
    if command_lines.len() != expected_commands as usize
        || command_lines
            .iter()
            .any(|line| line.get("kind").and_then(Value::as_str) != Some("command"))
    {
        bail!("{label} unexpected command lines: {command_lines:?}");
    }
    let submit = &lines[expected_commands as usize + 1];
    if submit.get("kind").and_then(Value::as_str) != Some("submit") {
        bail!("{label} missing submit line: {submit}");
    }
    let submit_tx_hash = submit
        .get("tx_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{label} submit line missing tx_hash: {submit}"))?;
    if !submit_tx_hash.starts_with("0x") {
        bail!("{label} submit tx_hash must be 0x-prefixed: {submit_tx_hash}");
    }
    let receipt_line = &lines[expected_commands as usize + 2];
    if receipt_line.get("kind").and_then(Value::as_str) != Some("receipt")
        || receipt_line.get("tx_hash").and_then(Value::as_str) != Some(submit_tx_hash)
    {
        bail!("{label} unexpected receipt line: {receipt_line}");
    }
    let receipt = receipt_line
        .get("receipt")
        .ok_or_else(|| anyhow!("{label} receipt line missing receipt object: {receipt_line}"))?;
    if receipt.get("success").and_then(Value::as_bool) != Some(expected_success) {
        bail!("{label} unexpected receipt success: {receipt}");
    }
    Ok(())
}

#[test]
fn pipe_ndjson_assertion_accepts_submitted_receipts() {
    let out = concat!(
        r#"{"kind":"ptb","commands":2}"#,
        "\n",
        r#"{"kind":"command","cmd_idx":0}"#,
        "\n",
        r#"{"kind":"command","cmd_idx":1}"#,
        "\n",
        r#"{"kind":"submit","tx_hash":"0xabc"}"#,
        "\n",
        r#"{"kind":"receipt","tx_hash":"0xabc","receipt":{"success":true}}"#,
        "\n",
    );
    assert_pipe_ndjson("test pipe", out.as_bytes(), 2, true).unwrap();
}

fn parse_json_command_output(label: &str, out: std::process::Output) -> Result<Value> {
    if !out.status.success() {
        bail!(
            "{label} failed (status={}):\nstdout={}\nstderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    serde_json::from_slice(&out.stdout).with_context(|| {
        format!(
            "parse {label} JSON stdout: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

fn stop_child(child: &mut Child) {
    if let Ok(None) = child.try_wait() {
        let _ = Command::new("kill")
            .arg("-INT")
            .arg(child.id().to_string())
            .status();
        for _ in 0..20 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// xDSA-sign + encode `ptb`, write the bytes to a temp file, and run
/// `bloom chain submit-ptb --ptb-file <f> --wait` from `home`. Returns the
/// parsed receipt JSON (the pretty block printed before the final `tx_hash`
/// line).
fn submit_ptb(home: &std::path::Path, port: u16, ptb: PtbTx) -> Result<Value> {
    let bytes = sign_and_encode_ptb(ptb);
    submit_ptb_bytes(home, port, &bytes)
}

fn submit_ptb_with_bad_inner_signature(
    home: &std::path::Path,
    port: u16,
    ptb: PtbTx,
) -> Result<Value> {
    let mut bytes = sign_and_encode_ptb(ptb);
    let last = bytes
        .last_mut()
        .ok_or_else(|| anyhow!("encoded PTB unexpectedly empty"))?;
    *last ^= 0x01;
    submit_ptb_bytes(home, port, &bytes)
}

fn submit_ptb_bytes(home: &std::path::Path, port: u16, bytes: &[u8]) -> Result<Value> {
    let tmp = std::env::temp_dir().join(format!(
        "bloom-petal-ptb-{}-{}.bin",
        std::process::id(),
        blake3::hash(bytes).to_hex()
    ));
    std::fs::write(&tmp, bytes).context("write ptb file")?;

    let rpc = format!("127.0.0.1:{}", port);
    let out = Command::new(bloom_bin())
        .env("BLOOM_RPC_TCP", &rpc)
        .arg("--home")
        .arg(home)
        .arg("chain")
        .arg("submit-ptb")
        .arg("--ptb-file")
        .arg(&tmp)
        .arg("--wait")
        .arg("--wait-timeout-secs")
        .arg("60")
        .output()
        .context("invoke bloom chain submit-ptb")?;
    let _ = std::fs::remove_file(&tmp);

    if !out.status.success() {
        bail!(
            "bloom chain submit-ptb failed:\n  stdout={}\n  stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_receipt_from_submit_ptb(&stdout)
}

/// `bloom chain submit-ptb --wait` prints the pretty receipt JSON, then a
/// final `{"tx_hash":"..."}` line. Parse the first `{...}` block that carries a
/// `success` field as the receipt.
fn parse_receipt_from_submit_ptb(stdout: &str) -> Result<Value> {
    let mut receipt = parse_success_receipt(stdout).with_context(|| {
        format!("could not parse receipt JSON from submit-ptb stdout:\n{stdout}")
    })?;
    if receipt.get("tx_hash").is_none()
        && let Some(tx_hash) = parse_tx_hash(stdout)
        && let Some(obj) = receipt.as_object_mut()
    {
        obj.insert("tx_hash".to_string(), Value::String(tx_hash));
    }
    Ok(receipt)
}

fn parse_tx_hash(stdout: &str) -> Option<String> {
    stdout.lines().rev().find_map(|line| {
        serde_json::from_str::<Value>(line)
            .ok()
            .and_then(|v| v.get("tx_hash").and_then(Value::as_str).map(str::to_string))
    })
}

fn parse_success_receipt(stdout: &str) -> Result<Value> {
    // The receipt is a multi-line pretty JSON object. Concatenate everything
    // up to (but excluding) the trailing single-line tx_hash object and parse.
    // Simplest robust approach: try each balanced-brace candidate.
    let mut depth = 0i32;
    let mut start = None;
    let bytes = stdout.as_bytes();
    let mut candidates: Vec<&str> = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0
                    && let Some(s) = start.take()
                {
                    candidates.push(&stdout[s..=i]);
                }
            }
            _ => {}
        }
    }
    for c in &candidates {
        if let Ok(v) = serde_json::from_str::<Value>(c)
            && v.get("success").is_some()
        {
            return Ok(v);
        }
    }
    bail!("no JSON receipt with success field found")
}

// ---------------------------------------------------------------------------
// RPC query helpers
// ---------------------------------------------------------------------------

async fn current_height(client: &RpcClient) -> Result<u64> {
    let v = client.call("chain_tip", serde_json::json!({})).await?;
    Ok(v.get("height").and_then(Value::as_u64).unwrap_or(0))
}

async fn query_block(client: &RpcClient, height: u64) -> Result<Option<Value>> {
    let v = client
        .call("chain_query_block", serde_json::json!({ "height": height }))
        .await?;
    if v.is_null() { Ok(None) } else { Ok(Some(v)) }
}

async fn assert_resolves(
    client: &RpcClient,
    path: &str,
    expected: bloom_chain_types::types::Hash32,
) -> Result<()> {
    let got_hash = resolve_petal_hash(client, path).await?;
    let got = hex::encode(got_hash.0);
    let expected_hex = hex::encode(expected.0);
    if got != expected_hex {
        bail!("petal path {path} resolved to {got}, expected {expected_hex}");
    }
    Ok(())
}

async fn resolve_petal_hash(client: &RpcClient, path: &str) -> Result<Hash32> {
    let resolved = client
        .call("chain_resolve_path", serde_json::json!({ "path": path }))
        .await
        .with_context(|| format!("resolve petal path {path}"))?;
    let got = resolved
        .get("hash")
        .and_then(Value::as_str)
        .with_context(|| format!("petal path {path} is not bound"))?;
    let bytes = hex::decode(got).with_context(|| format!("petal path {path} hash is not hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("petal path {path} hash is not 32 bytes"))?;
    Ok(Hash32(arr))
}

/// Block until the node reports a tip at or beyond `target`.
async fn wait_for_height(client: &RpcClient, target: u64) -> Result<()> {
    loop {
        if let Ok(height) = current_height(client).await
            && height >= target
        {
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

/// Wait for every validator to reach `target` height (so gossip has applied
/// the latest blocks everywhere before discovery).
async fn wait_all_reach_height(clients: &[RpcClient], target: u64) -> Result<()> {
    for (i, c) in clients.iter().enumerate() {
        timeout(TX_TIMEOUT, wait_for_height(c, target))
            .await
            .map_err(|_| anyhow!("validator {} did not reach height {}", i, target))??;
    }
    Ok(())
}

async fn restart_validator_and_assert_catches_up(
    clients: &[RpcClient],
    tmpdir: &std::path::Path,
    validator_idx: usize,
    object_id_hex: &str,
) -> Result<()> {
    let prune_probe = 1u64;
    let prune_target = prune_probe + 10;
    wait_all_reach_height(clients, prune_target).await?;
    let block_probe = tmpdir
        .join(format!("home{validator_idx}"))
        .join("chain")
        .join("blocks")
        .join(prune_probe.to_string());
    if block_probe.exists() {
        bail!(
            "docker prune-window probe failed: {} still exists",
            block_probe.display()
        );
    }
    let blob_count = std::fs::read_dir(
        tmpdir
            .join(format!("home{validator_idx}"))
            .join("chain")
            .join("state_blobs"),
    )
    .with_context(|| format!("read val{validator_idx} state_blobs"))?
    .filter_map(std::result::Result::ok)
    .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
    .count();
    if blob_count == 0 || blob_count > 4 {
        bail!("docker state-blob retention probe expected 1..=4 blobs, got {blob_count}");
    }

    let before = current_height(&clients[0]).await?;
    eprintln!(
        "[restart] restarting bloom-val{validator_idx} at network height {before} after prune-window snapshot probe; waiting for catch-up"
    );

    let out = Command::new("docker")
        .arg("restart")
        .arg(format!("bloom-val{validator_idx}"))
        .output()
        .context("invoke docker restart")?;
    if !out.status.success() {
        bail!(
            "docker restart bloom-val{validator_idx} failed:\n  stdout={}\n  stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    wait_docker_container_healthy(&format!("bloom-val{validator_idx}")).await?;

    let after_restart = current_height(&clients[0]).await?;
    let committed_target = after_restart.saturating_add(2);
    let target_tip = committed_target.saturating_add(1);
    timeout(
        Duration::from_secs(120),
        wait_for_height(&clients[0], target_tip),
    )
    .await
    .map_err(|_| anyhow!("network did not advance to height {target_tip} after restart"))??;
    timeout(
        Duration::from_secs(120),
        wait_for_height(&clients[validator_idx], target_tip),
    )
    .await
    .map_err(|_| anyhow!("validator {validator_idx} did not catch up to height {target_tip}"))??;

    assert_chain_converged(clients, committed_target).await?;
    assert_object_converged(clients, object_id_hex).await?;
    eprintln!(
        "[restart] bloom-val{validator_idx} caught up to tip {target_tip}; committed block {committed_target}, roots, and object state converged"
    );
    Ok(())
}

async fn wait_docker_container_healthy(name: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let out = Command::new("docker")
            .args(["inspect", "--format={{.State.Health.Status}}", name])
            .output()
            .with_context(|| format!("inspect {name} health"))?;
        let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && status == "healthy" {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "{name} did not become healthy after restart; last status={status:?}, stderr={}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        sleep(Duration::from_millis(500)).await;
    }
}

async fn query_object(client: &RpcClient, id_hex: &str) -> Result<Option<Value>> {
    let v = client
        .call("chain_query_object", serde_json::json!({ "id": id_hex }))
        .await?;
    Ok(if v.is_null() { None } else { Some(v) })
}

async fn query_owned_coin_balance(client: &RpcClient, owner_hex: &str) -> Result<u128> {
    ls_objects_by_owner(client, owner_hex)
        .await?
        .into_iter()
        .filter(|o| o.get("type_name").and_then(Value::as_str) == Some("Coin"))
        .try_fold(0u128, |acc, obj| {
            let value = decode_coin_value(&obj)?;
            acc.checked_add(value)
                .ok_or_else(|| anyhow!("Coin balance overflow for owner {owner_hex}"))
        })
}

async fn validator_coin_balances(
    client: &RpcClient,
    tmpdir: &std::path::Path,
) -> Result<std::collections::HashMap<String, u128>> {
    let mut out = std::collections::HashMap::new();
    for (addr, _) in load_validator_keys(tmpdir)? {
        let addr_hex = hex::encode(addr.0);
        out.insert(
            addr_hex.clone(),
            query_owned_coin_balance(client, &addr_hex).await?,
        );
    }
    Ok(out)
}

async fn find_block_containing_tx(
    client: &RpcClient,
    from_height: u64,
    to_height: u64,
    tx_hash: &str,
) -> Result<Option<Value>> {
    for height in from_height..=to_height {
        let Some(block) = query_block(client, height).await? else {
            continue;
        };
        let contains = block
            .get("tx_hashes")
            .and_then(Value::as_array)
            .map(|hashes| hashes.iter().any(|h| h.as_str() == Some(tx_hash)))
            .unwrap_or(false);
        if contains {
            return Ok(Some(block));
        }
    }
    Ok(None)
}

async fn assert_object_converged(clients: &[RpcClient], id_hex: &str) -> Result<()> {
    let expected = query_object(&clients[0], id_hex)
        .await?
        .ok_or_else(|| anyhow!("object {id_hex} missing on validator 0"))?;
    for (i, client) in clients.iter().enumerate().skip(1) {
        let got = query_object(client, id_hex)
            .await?
            .ok_or_else(|| anyhow!("object {id_hex} missing on validator {i}"))?;
        assert_same_object_fields(&got, &expected, &format!("validator {i} convergence"))?;
    }
    Ok(())
}

async fn assert_chain_converged(clients: &[RpcClient], height: u64) -> Result<()> {
    let expected_block = clients[0]
        .call("chain_query_block", serde_json::json!({ "height": height }))
        .await?;
    for (i, client) in clients.iter().enumerate().skip(1) {
        let block = client
            .call("chain_query_block", serde_json::json!({ "height": height }))
            .await?;
        for field in [
            "hash",
            "parent_hash",
            "state_root",
            "txs_root",
            "receipts_root",
        ] {
            if block.get(field) != expected_block.get(field) {
                bail!(
                    "validator {i} block field {field} mismatch at height {height}: got {:?}, expected {:?}",
                    block.get(field),
                    expected_block.get(field)
                );
            }
        }
    }
    assert_latest_health_converges(clients).await
}

async fn assert_latest_health_converges(clients: &[RpcClient]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last: Option<Vec<Value>> = None;
    while Instant::now() < deadline {
        let mut health = Vec::with_capacity(clients.len());
        for client in clients {
            health.push(client.call("chain_health", serde_json::json!({})).await?);
        }
        let Some(expected_height) = health.first().and_then(|h| h.get("height")).cloned() else {
            bail!("chain_health response missing height");
        };
        let same_height = health
            .iter()
            .all(|h| h.get("height") == Some(&expected_height));
        let roots_match = same_height
            && ["state_root", "object_root", "ownership_root", "vfs_root"]
                .iter()
                .all(|field| {
                    health
                        .iter()
                        .all(|h| h.get(*field) == health[0].get(*field))
                });
        if roots_match {
            return Ok(());
        }
        last = Some(health);
        sleep(Duration::from_millis(250)).await;
    }
    bail!(
        "latest chain_health roots did not converge at a common height; last sample={:?}",
        last
    )
}

fn assert_same_object_fields(got: &Value, expected: &Value, label: &str) -> Result<()> {
    for field in [
        "id",
        "owner_kind",
        "owner",
        "version",
        "type_name",
        "payload",
    ] {
        if got.get(field) != expected.get(field) {
            bail!(
                "{label}: object field {field} mismatch: got {:?}, expected {:?}",
                got.get(field),
                expected.get(field)
            );
        }
    }
    Ok(())
}

async fn ls_objects_by_owner(client: &RpcClient, owner_hex: &str) -> Result<Vec<Value>> {
    let v = client
        .call(
            "chain_ls_objects",
            serde_json::json!({ "owner_addr": owner_hex }),
        )
        .await?;
    Ok(v.as_array().cloned().unwrap_or_default())
}

async fn ls_objects_by_type(client: &RpcClient, type_name: &str) -> Result<Vec<Value>> {
    let v = client
        .call(
            "chain_ls_objects",
            serde_json::json!({ "type_name": type_name }),
        )
        .await?;
    Ok(v.as_array().cloned().unwrap_or_default())
}

async fn owned_coin_ids(
    client: &RpcClient,
    owner_hex: &str,
) -> Result<std::collections::HashSet<String>> {
    Ok(ls_objects_by_owner(client, owner_hex)
        .await?
        .into_iter()
        .filter(|o| o.get("type_name").and_then(Value::as_str) == Some("Coin"))
        .filter_map(|o| json_str(&o, "id").ok().map(str::to_string))
        .collect())
}

struct MintOwnedCoin<'a> {
    client: &'a RpcClient,
    clients: &'a [RpcClient],
    home: &'a Path,
    fungible_hash: Hash32,
    mint_cap_id: bloom_objects::ObjectId,
    mint_cap_version: u64,
    supply_id: bloom_objects::ObjectId,
    supply_version: &'a mut u64,
    gas_payer: bloom_objects::ObjectId,
    value: u128,
}

async fn mint_owned_coin(input: MintOwnedCoin<'_>) -> Result<Value> {
    let MintOwnedCoin {
        client,
        clients,
        home,
        fungible_hash,
        mint_cap_id,
        mint_cap_version,
        supply_id,
        supply_version,
        gas_payer,
        value,
    } = input;
    let owner_hex = ptb_signer_pubkey_hex();
    let before_ids = owned_coin_ids(client, &owner_hex).await?;
    let ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            fungible_mint_cmd(
                fungible_hash,
                mint_cap_id,
                mint_cap_version,
                supply_id,
                *supply_version,
                value,
            ),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 1,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let receipt = submit_ptb(home, HOST_RPC_PORTS[0], ptb)?;
    if !receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("canonical fungible mint({value}) reverted: {receipt}");
    }
    *supply_version = refresh_object_version(client, supply_id, "Supply<Erased>").await?;
    let latest = current_height(client).await?;
    wait_all_reach_height(clients, latest).await?;
    let mut coins =
        wait_for_new_owned_coins_with_values(client, &owner_hex, &before_ids, &[value]).await?;
    coins
        .pop()
        .ok_or_else(|| anyhow!("canonical fungible mint({value}) produced no owned coin"))
}

async fn wait_for_new_owned_coins_with_values(
    client: &RpcClient,
    owner_hex: &str,
    before_ids: &std::collections::HashSet<String>,
    expected_values: &[u128],
) -> Result<Vec<Value>> {
    let mut expected = expected_values.to_vec();
    expected.sort_unstable();
    let deadline = Instant::now() + TX_TIMEOUT;
    loop {
        let mut candidates = ls_objects_by_owner(client, owner_hex)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|o| o.get("type_name").and_then(Value::as_str) == Some("Coin"))
            .filter(|o| {
                json_str(o, "id")
                    .map(|id| !before_ids.contains(id))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|a, b| {
            json_str(a, "id")
                .unwrap_or_default()
                .cmp(json_str(b, "id").unwrap_or_default())
        });

        let mut selected = Vec::new();
        let mut remaining = expected.clone();
        for candidate in &candidates {
            let value = decode_coin_value(candidate)?;
            if let Some(pos) = remaining.iter().position(|v| *v == value) {
                remaining.remove(pos);
                selected.push(candidate.clone());
            }
            if remaining.is_empty() {
                return Ok(selected);
            }
        }
        if Instant::now() >= deadline {
            let mut seen = candidates
                .iter()
                .map(decode_coin_value)
                .collect::<Result<Vec<_>>>()?;
            seen.sort_unstable();
            bail!(
                "timed out waiting for new owned coin values {expected:?}; saw new values {seen:?}"
            );
        }
        sleep(Duration::from_millis(250)).await;
    }
}

/// Poll until `owner_hex` owns at least one object whose `type_name == "Coin"`,
/// returning that object's JSON.
async fn wait_for_owned_coin(client: &RpcClient, owner_hex: &str) -> Result<Value> {
    loop {
        let objs = ls_objects_by_owner(client, owner_hex)
            .await
            .unwrap_or_default();
        if let Some(coin) = objs
            .into_iter()
            .find(|o| o.get("type_name").and_then(Value::as_str) == Some("Coin"))
        {
            return Ok(coin);
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_owned_object_type(
    client: &RpcClient,
    owner_hex: &str,
    petal_hash: bloom_chain_types::types::Hash32,
    type_name: &str,
) -> Result<Value> {
    let petal_hash_hex = hex::encode(petal_hash.0);
    loop {
        let objs = ls_objects_by_owner(client, owner_hex)
            .await
            .unwrap_or_default();
        if let Some(obj) = objs.into_iter().find(|o| {
            o.get("type_name").and_then(Value::as_str) == Some(type_name)
                && o.get("petal_hash").and_then(Value::as_str) == Some(petal_hash_hex.as_str())
        }) {
            return Ok(obj);
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn refresh_object_version(
    client: &RpcClient,
    id: bloom_objects::ObjectId,
    label: &str,
) -> Result<u64> {
    let id_hex = hex::encode(id.0);
    let obj = query_object(client, &id_hex)
        .await?
        .ok_or_else(|| anyhow!("{label} missing: {id_hex}"))?;
    object_version(&obj)
}

async fn wait_for_owned_coins(
    client: &RpcClient,
    owner_hex: &str,
    count: usize,
) -> Result<Vec<Value>> {
    loop {
        let mut coins = ls_objects_by_owner(client, owner_hex)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|o| o.get("type_name").and_then(Value::as_str) == Some("Coin"))
            .collect::<Vec<_>>();
        coins.sort_by(|a, b| {
            json_str(a, "id")
                .unwrap_or_default()
                .cmp(json_str(b, "id").unwrap_or_default())
        });
        if coins.len() >= count {
            coins.truncate(count);
            return Ok(coins);
        }
        sleep(Duration::from_millis(250)).await;
    }
}

/// Poll until a shared `Pool` object exists, returning its JSON.
async fn wait_for_pool(client: &RpcClient) -> Result<Value> {
    loop {
        let pools = ls_objects_by_type(client, "Pool").await.unwrap_or_default();
        if let Some(p) = pools
            .into_iter()
            .find(|o| o.get("owner_kind").and_then(Value::as_str) == Some("shared"))
        {
            return Ok(p);
        }
        sleep(Duration::from_millis(250)).await;
    }
}

// ---------------------------------------------------------------------------
// JSON / payload decode helpers
// ---------------------------------------------------------------------------

fn json_str<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field '{field}' in {v}"))
}

fn obj_id_from_hex(obj: &Value) -> Result<bloom_objects::ObjectId> {
    let id_hex = json_str(obj, "id")?;
    let b = hex::decode(id_hex).context("decode object id hex")?;
    if b.len() != 32 {
        bail!("object id not 32 bytes: {id_hex}");
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(bloom_objects::ObjectId(a))
}

fn hash32_from_hex(hexs: &str) -> Result<Hash32> {
    let b = hex::decode(hexs).context("decode hash hex")?;
    if b.len() != 32 {
        bail!("hash not 32 bytes: {hexs}");
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(Hash32(a))
}

fn object_version(obj: &Value) -> Result<u64> {
    obj.get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("object missing version: {obj}"))
}

fn payload_bytes(obj: &Value) -> Result<Vec<u8>> {
    let hexs = json_str(obj, "payload")?;
    hex::decode(hexs).context("decode object payload hex")
}

fn decode_coin_value(obj: &Value) -> Result<u128> {
    Ok(ptb_decode_coin_value(&payload_bytes(obj)?))
}

fn decode_pool_reserves(obj: &Value) -> Result<(u128, u128)> {
    let payload = payload_bytes(obj)?;
    let (ra, rb, _lp, _k, _price, _coin_a_tag, _coin_b_tag) =
        bloom_petal_dex_pool::payload::decode_pool(&payload)
            .ok_or_else(|| anyhow!("decode_pool failed for payload {} bytes", payload.len()))?;
    Ok((ra, rb))
}

fn decode_lp_pool_id(obj: &Value) -> Result<bloom_objects::ObjectId> {
    let payload = payload_bytes(obj)?;
    let (pool_id, _shares) = bloom_petal_dex_pool::payload::decode_lp(&payload)
        .ok_or_else(|| anyhow!("decode_lp failed for payload {} bytes", payload.len()))?;
    Ok(pool_id)
}

fn decode_lp_self_id(obj: &Value) -> Result<bloom_objects::ObjectId> {
    let payload = payload_bytes(obj)?;
    if payload.len() < 32 {
        bail!(
            "decode_lp self id failed for payload {} bytes",
            payload.len()
        );
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&payload[..32]);
    Ok(bloom_objects::ObjectId(id))
}
