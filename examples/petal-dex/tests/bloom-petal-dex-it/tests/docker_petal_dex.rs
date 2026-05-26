//! Category: docker-acceptance
//!
//! `docker_petal_dex.rs` — LIVE 4-validator docker acceptance test for the
//! petal-based DEX (`/bloom/dex/{pool,wallet,faucet}`).
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
//!     an Ed25519 gas allocation (keyed to the inner-PTB signer pubkey) to
//!     all four byte-identical genesis.toml files, `docker compose up -d`s
//!     the stack, and runs this test.
//!   - This driver attaches to the running stack over TCP (host ports
//!     18545..18548), deploys the three petal wasms via `bloom chain deploy`,
//!     then submits two Ed25519-signed inner PTBs via `bloom chain submit-ptb`.
//!
//! Two address spaces (see brief):
//!   - INNER PTB auth: a deterministic Ed25519 key (`ptb_signer_*` in
//!     `dex_harness`). Its genesis-allocated `Coin<LOOM>` is the inner
//!     gas-payer; every Address-owned input must be owned by it.
//!   - OUTER Tx envelope: `bloom chain submit-ptb` signs it with the home0
//!     xDSA keystore wallet.
//!
//! `#[ignore]`-gated. Run via `scripts/test-docker-petal-dex.sh`.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use std::{io::Write, net::TcpStream};

use anyhow::{Context, Result, anyhow, bail};
use bloom_chain_consensus::validator_set::ValidatorSet;
use bloom_chain_types::block::{Block, BlockHeader};
use bloom_chain_types::digest::blake3_tagged;
use bloom_chain_types::frame::{MsgType, encode_wire_frame};
use bloom_chain_types::ssz::{Decode, Encode};
use bloom_chain_types::types::{Address, Hash32, SigBytes};
use bloom_chain_types::vote::{Commit, Proposal, Vote, VoteKind};
use serde_json::Value;
use tokio::time::{sleep, timeout};

use bloom_chain_node::rpc::RpcClient;
use bloom_objects::{AbilitySet, AccessMode, Owner, TypeTag};
use bloom_petal_manifest::types::{
    ArgDecl, ArgKind, FunctionDecl, PetalManifestV0, SCHEMA_VERSION,
};
use bloom_script::{Arg, Command as PtbCommand, ExpectedVersion, MoveCmd, PetalRef, PtbTx, UseRef};

use bloom_petal_dex_it::dex_harness::{
    append_manifest_section, build_faucet_wasm, build_pool_wasm, build_wallet_wasm, petal_hash_of,
    ptb_decode_coin_value, ptb_signer_pubkey, ptb_signer_pubkey_hex, real_router_manifest_bytes,
    sign_and_encode_ptb, wat_to_wasm,
};

// ---------------------------------------------------------------------------
// Constants — keep in sync with scripts/test-docker-petal-dex.sh
// ---------------------------------------------------------------------------

const HOST_RPC_PORTS: [u16; 4] = [18545, 18546, 18547, 18548];
const HOST_P2P_PORTS: [u16; 4] = [18656, 18657, 18658, 18659];

/// Settlement recipient for the swap output. A distinct, deterministic 32-byte
/// address (not the inner-PTB signer) so the receive assertion is unambiguous.
const CAROL: [u8; 32] = [0xC0u8; 32];

/// Pool fee parameter (30 bps), big-endian u16 — mirrors `faucet_provision.rs`.
const POOL_FEE_BPS: u16 = 30;

/// Far-future expiry so the live, ever-advancing chain never rejects the PTB
/// as expired (validator rejects when `current_block > expiry_block`).
const PTB_EXPIRY_BLOCK: u64 = 1_000_000_000;

const PTB_GAS_BUDGET: u64 = 2_000_000;

const ADVERSARY_PATH: &str = "/bloom/dex/adversary";

const READINESS_TIMEOUT: Duration = Duration::from_secs(90);
const TX_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Top-level test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires docker-compose stack; run via scripts/test-docker-petal-dex.sh"]
async fn docker_petal_dex_acceptance() -> Result<()> {
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
        "[ed25519] inner-PTB signer pubkey = {}  (genesis gas-payer)",
        ptb_signer_pubkey_hex()
    );

    exercise_live_malformed_transport(client0, &tmpdir).await?;

    // ── 2. Build the petal wasms + deploy each via the bloom CLI ──────────
    eprintln!();
    eprintln!("[build] compiling pool/wallet/faucet to wasm32-unknown-unknown");
    let pool_wasm_path = build_pool_wasm();
    let wallet_wasm_path = build_wallet_wasm();
    let faucet_wasm_path = build_faucet_wasm();

    let pool_wasm = std::fs::read(&pool_wasm_path).context("read pool wasm")?;
    let wallet_wasm = std::fs::read(&wallet_wasm_path).context("read wallet wasm")?;
    let faucet_wasm = std::fs::read(&faucet_wasm_path).context("read faucet wasm")?;
    let router_wasm = router_probe_wasm();
    let router_deploy_path = std::env::temp_dir().join(format!(
        "bloom-petal-dex-router-{}-{}.wasm",
        std::process::id(),
        blake3::hash(&router_wasm).to_hex()
    ));
    std::fs::write(&router_deploy_path, &router_wasm)
        .context("write manifest-wrapped router wasm")?;

    // Host-side petal hashes (= blake3_tagged(PETAL, wasm)) — what deploy
    // inserts, and what each PetalRef pins.
    let pool_hash = petal_hash_of(&pool_wasm);
    let wallet_hash = petal_hash_of(&wallet_wasm);
    let faucet_hash = petal_hash_of(&faucet_wasm);
    let router_hash = petal_hash_of(&router_wasm);

    eprintln!();
    eprintln!("[deploy] deploying petals from home0 (outer xDSA envelope):");
    deploy_petal(&home0, HOST_RPC_PORTS[0], &pool_wasm_path)?;
    assert_resolves(client0, "/bloom/dex/pool", pool_hash).await?;
    eprintln!(
        "         /bloom/dex/pool   hash={}",
        hex::encode(pool_hash.0)
    );
    deploy_petal(&home0, HOST_RPC_PORTS[0], &wallet_wasm_path)?;
    assert_resolves(client0, "/bloom/dex/wallet", wallet_hash).await?;
    eprintln!(
        "         /bloom/dex/wallet hash={}",
        hex::encode(wallet_hash.0)
    );
    deploy_petal(&home0, HOST_RPC_PORTS[0], &faucet_wasm_path)?;
    assert_resolves(client0, "/bloom/dex/faucet", faucet_hash).await?;
    eprintln!(
        "         /bloom/dex/faucet hash={}",
        hex::encode(faucet_hash.0)
    );
    deploy_petal(&home0, HOST_RPC_PORTS[0], &router_deploy_path)?;
    let _ = std::fs::remove_file(&router_deploy_path);
    assert_resolves(client0, "/bloom/dex/router", router_hash).await?;
    eprintln!(
        "         /bloom/dex/router hash={}",
        hex::encode(router_hash.0)
    );

    // Deploy receipts are waited on by the CLI. Let every validator catch up
    // before submitting PTBs that may be admitted by any validator after gossip.
    let mut latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest + 2).await?;

    // ── 3. Discover the ed25519-owned gas Coin<LOOM> ──────────────────────
    let signer_hex = ptb_signer_pubkey_hex();
    let gas_coin = timeout(TX_TIMEOUT, wait_for_owned_coin(client0, &signer_hex))
        .await
        .map_err(|_| anyhow!("timed out discovering ed25519 gas Coin<LOOM>"))??;
    let gas_payer = obj_id_from_hex(&gas_coin)?;
    eprintln!();
    eprintln!(
        "[gas]   ed25519 gas Coin<LOOM> = {}  (genesis allocation)",
        json_str(&gas_coin, "id")?
    );

    let bad_sig_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 0,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let bad_sig_receipt =
        submit_ptb_with_bad_inner_signature(&home0, HOST_RPC_PORTS[0], bad_sig_ptb)?;
    assert_reverted(&bad_sig_receipt, "bad inner PTB signature")?;

    // ── 4. faucet.mint ×2 → create_pool (one atomic PTB) ──────────────────
    eprintln!();
    eprintln!("[ptb-1] faucet.mint(1000)×2 -> create_pool(30bps) -> share Pool + LP to signer");
    let create_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()], // overwritten by sign_and_encode_ptb
        commands: vec![
            mint_cmd(faucet_hash, 1000),
            mint_cmd(faucet_hash, 1000),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "create_pool".to_string(),
                type_args: vec![],
                args: vec![
                    use_ret(0, 0),
                    use_ret(1, 0),
                    Arg::Const(POOL_FEE_BPS.to_be_bytes().to_vec()),
                ],
            }),
            // Share the Pool (slot 0) so anyone can swap.
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 2,
                    ret_idx: 0,
                }],
                owner: Owner::Shared,
            },
            // Give the LpPosition (slot 1) to the signer.
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 2,
                    ret_idx: 1,
                }],
                owner: Owner::Address(ptb_signer_pubkey()),
            },
        ],
        gas_payer,
        gas_budget: PTB_GAS_BUDGET,
        gas_price: 0,
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
    wait_all_reach_height(&clients, latest + 1).await?;

    // ── 5. Discover the shared Pool + assert reserves (1000, 1000) ────────
    let pool_obj = timeout(TX_TIMEOUT, wait_for_pool(client0))
        .await
        .map_err(|_| anyhow!("timed out discovering shared Pool"))??;
    let pool_id_hex = json_str(&pool_obj, "id")?;
    let pool_obj_id = obj_id_from_hex(&pool_obj)?;
    if json_str(&pool_obj, "owner_kind")? != "shared" {
        bail!("Pool is not shared: {:?}", pool_obj.get("owner_kind"));
    }
    let (ra, rb) = decode_pool_reserves(&pool_obj)?;
    if ra != 1000 || rb != 1000 {
        bail!("pool reserves after create_pool: got ({ra}, {rb}) expected (1000, 1000)");
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
    let create_pool_b = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            mint_cmd(faucet_hash, 700),
            mint_cmd(faucet_hash, 700),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "create_pool".to_string(),
                type_args: vec![],
                args: vec![
                    use_ret(0, 0),
                    use_ret(1, 0),
                    Arg::Const((POOL_FEE_BPS + 1).to_be_bytes().to_vec()),
                ],
            }),
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 2,
                    ret_idx: 0,
                }],
                owner: Owner::Shared,
            },
            PtbCommand::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 2,
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
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest + 1).await?;
    let pools = ls_objects_by_type(client0, "Pool").await?;
    let pool_b = pools
        .into_iter()
        .find(|p| json_str(p, "id").ok() != Some(pool_id_hex))
        .ok_or_else(|| anyhow!("second shared pool not found"))?;
    let pool_b_id = obj_id_from_hex(&pool_b)?;
    let pool_b_version = pool_b
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
                path: "/bloom/dex/router".to_string(),
                hash: Some(router_hash),
            },
            function: "quote_2hop".to_string(),
            type_args: vec![],
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
            type_args: vec![],
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

    let add_lp_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            mint_cmd(faucet_hash, 500),
            mint_cmd(faucet_hash, 500),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "add_liquidity".to_string(),
                type_args: vec![],
                args: vec![
                    Arg::Object {
                        id: pool_obj_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    use_ret(0, 0),
                    use_ret(1, 0),
                ],
            }),
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
    let add_lp_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], add_lp_ptb)?;
    if !add_lp_receipt
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        bail!("add_liquidity reverted: {add_lp_receipt}");
    }
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest + 1).await?;
    let pool_after_add = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after add_liquidity"))?;
    let (ra_add, rb_add) = decode_pool_reserves(&pool_after_add)?;
    if (ra_add, rb_add) != (1500, 1500) {
        bail!("pool reserves after add_liquidity: got ({ra_add}, {rb_add}) expected (1500, 1500)");
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
                type_args: vec![],
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
    wait_all_reach_height(&clients, latest + 1).await?;
    let pool_after_remove = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after remove_liquidity"))?;
    let (ra_remove, rb_remove) = decode_pool_reserves(&pool_after_remove)?;
    if (ra_remove, rb_remove) != (1000, 1000) {
        bail!(
            "pool reserves after remove_liquidity: got ({ra_remove}, {rb_remove}) expected (1000, 1000)"
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

    let exact_out_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            mint_cmd(faucet_hash, 105),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_out".to_string(),
                type_args: vec![],
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
    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest + 1).await?;
    let pool_b_after_exact_out = query_object(client0, json_str(&pool_b, "id")?)
        .await?
        .ok_or_else(|| anyhow!("pool B disappeared after swap_exact_out"))?;
    assert_object_converged(&clients, json_str(&pool_b, "id")?).await?;
    if json_str(&pool_b_after_exact_out, "payload")? == json_str(&pool_b, "payload")? {
        bail!("swap_exact_out succeeded without mutating pool B");
    }
    eprintln!("            swap_exact_out on second pool executed and converged");

    // ── 6. faucet.mint → swap_exact_in → wallet.receive (one atomic PTB) ──
    eprintln!();
    eprintln!("[ptb-2] faucet.mint(100) -> swap_exact_in(min_out=90) -> wallet.receive(carol)");
    let min_out: u128 = 90;
    let swap_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            mint_cmd(faucet_hash, 100),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: vec![],
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
            PtbCommand::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/wallet".to_string(),
                    hash: Some(wallet_hash),
                },
                function: "receive".to_string(),
                type_args: vec![],
                args: vec![use_ret(1, 0), Arg::Const(CAROL.to_vec())],
            }),
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

    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest + 1).await?;

    // ── 7. Assert carol received a Coin worth 90 ──────────────────────────
    let carol_hex = hex::encode(CAROL);
    let carol_coin = timeout(TX_TIMEOUT, wait_for_owned_coin(client0, &carol_hex))
        .await
        .map_err(|_| anyhow!("timed out waiting for carol's output Coin"))??;
    let carol_value = decode_coin_value(&carol_coin)?;
    if carol_value != 90 {
        bail!("carol's output Coin value: got {carol_value} expected 90");
    }
    eprintln!();
    eprintln!(
        "[recv]  carol Coin = {}  value={carol_value}",
        json_str(&carol_coin, "id")?
    );

    // ── 8. Assert pool reserves moved to (1100, 910) ──────────────────────
    let pool_after = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after swap"))?;
    let (ra2, rb2) = decode_pool_reserves(&pool_after)?;
    if ra2 != 1100 || rb2 != 910 {
        bail!("pool reserves after swap: got ({ra2}, {rb2}) expected (1100, 910)");
    }
    eprintln!("[pool]  reserves after swap = ({ra2}, {rb2})  (was (1000, 1000))");
    assert_object_converged(&clients, pool_id_hex).await?;

    let pool_after_version = pool_after
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing pool version after swap"))?;

    let bad_sig_real_swap = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            mint_cmd(faucet_hash, 1),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: vec![],
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
    let bad_sig_real_receipt =
        submit_ptb_with_bad_inner_signature(&home0, HOST_RPC_PORTS[0], bad_sig_real_swap)?;
    assert_reverted(
        &bad_sig_real_receipt,
        "bad inner PTB signature on stateful swap",
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
            mint_cmd(faucet_hash, 1),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: vec![],
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
    let stale_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], stale_ptb)?;
    assert_reverted(&stale_receipt, "stale shared Pool version")?;
    let pool_after_stale = query_object(client0, pool_id_hex)
        .await?
        .ok_or_else(|| anyhow!("pool object disappeared after stale-version attempt"))?;
    assert_same_object_fields(&pool_after_stale, &pool_after, "stale-version revert")?;

    let slippage_ptb = PtbTx {
        signers: vec![ptb_signer_pubkey()],
        commands: vec![
            mint_cmd(faucet_hash, 100),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: vec![],
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
            mint_cmd(faucet_hash, 1),
            PtbCommand::Move(MoveCmd {
                petal: pool_ref(pool_hash),
                function: "swap_exact_in".to_string(),
                type_args: vec![],
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
    wait_all_reach_height(&clients, latest + 1).await?;

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
        gas_price: 0,
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
        gas_price: 0,
        expiry_block: PTB_EXPIRY_BLOCK,
        signatures: vec![],
    };
    let steal_receipt = submit_ptb(&home0, HOST_RPC_PORTS[0], steal_ptb)?;
    assert_reverted(&steal_receipt, "Consume access to shared Pool")?;

    latest = current_height(client0).await?;
    wait_all_reach_height(&clients, latest + 1).await?;
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
    eprintln!("        create_pool : shared Pool reserves (1000, 1000) + LpPosition");
    eprintln!("        swap+receive: carol Coin worth 90; pool reserves (1100, 910)");
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

/// A faucet `mint(value)` Move command (pure mint — no object args).
fn mint_cmd(faucet_hash: bloom_chain_types::types::Hash32, value: u128) -> PtbCommand {
    PtbCommand::Move(MoveCmd {
        petal: PetalRef {
            path: "/bloom/dex/faucet".to_string(),
            hash: Some(faucet_hash),
        },
        function: "mint".to_string(),
        type_args: vec![],
        args: vec![Arg::Const(value.to_be_bytes().to_vec())],
    })
}

fn pool_ref(pool_hash: bloom_chain_types::types::Hash32) -> PetalRef {
    PetalRef {
        path: "/bloom/dex/pool".to_string(),
        hash: Some(pool_hash),
    }
}

fn adversary_ref(adversary_hash: bloom_chain_types::types::Hash32) -> PetalRef {
    PetalRef {
        path: ADVERSARY_PATH.to_string(),
        hash: Some(adversary_hash),
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
    let (bad_proposal_block, bad_proposal) = signed_tampered_empty_block(tmpdir, bad_height, false)
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

    let (bad_sync_block, _) = signed_tampered_empty_block(tmpdir, bad_height, true)
        .context("build signed tampered sync block")?;
    let bad_sync_hash = bad_sync_block.header.block_hash();
    send_frame(
        HOST_P2P_PORTS[0],
        MsgType::BlockResponse,
        &bad_sync_block.as_ssz_bytes(),
    )
    .context("send signed tampered sync block")?;

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
        "[net]   malformed and signed-tampered proposal/sync blocks, oversized p2p, and bounded RPC inputs rejected; chain still advances"
    );
    Ok(())
}

fn signed_tampered_empty_block(
    tmpdir: &std::path::Path,
    height: u64,
    with_commit: bool,
) -> Result<(Block, Proposal)> {
    let genesis = bloom_chain_node::genesis::Genesis::from_file(
        &tmpdir.join("home0").join("chain").join("genesis.toml"),
    )
    .map_err(|e| anyhow!("load docker genesis: {e}"))?;
    let latest = read_block_from_home(tmpdir, 0, height.saturating_sub(1))?
        .ok_or_else(|| anyhow!("missing parent block {}", height.saturating_sub(1)))?;
    let keys = load_validator_keys(tmpdir)?;
    let proposer = genesis.validator_set.proposer_for(height, 0).address;
    let header = BlockHeader {
        chain_id: genesis.chain_id.clone(),
        height,
        parent_hash: latest.header.block_hash(),
        timestamp_ms: latest.header.timestamp_ms.saturating_add(1_000),
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

fn read_block_from_home(
    tmpdir: &std::path::Path,
    home_idx: usize,
    height: u64,
) -> Result<Option<Block>> {
    let path = tmpdir
        .join(format!("home{home_idx}"))
        .join("chain")
        .join("blocks")
        .join(height.to_string());
    match std::fs::read(&path) {
        Ok(bytes) => Block::from_ssz_bytes(&bytes)
            .map(Some)
            .map_err(|e| anyhow!("decode block {}: {:?}", path.display(), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read block {}", path.display())),
    }
}

fn empty_txs_root() -> Hash32 {
    blake3_tagged("bloom-chain.v0.txs_root:", &[])
}

fn send_frame(port: u16, msg_type: MsgType, payload: &[u8]) -> Result<()> {
    let frame = encode_wire_frame(msg_type, payload).context("encode p2p frame")?;
    send_raw_p2p_frame(port, &frame)
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

fn adversary_manifest(pool_hash: bloom_chain_types::types::Hash32) -> Vec<u8> {
    let pool_ty = pool_type_tag(pool_hash);
    let manifest = PetalManifestV0 {
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
    let poisoned_payload = wat_bytes(&bloom_petal_dex_pool::payload::pool_payload(
        &pool_id,
        1,
        1,
        1,
        1,
        &POOL_FEE_BPS.to_be_bytes(),
    ));
    let payload_len = bloom_petal_dex_pool::payload::pool_payload(
        &pool_id,
        1,
        1,
        1,
        1,
        &POOL_FEE_BPS.to_be_bytes(),
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

fn router_probe_wasm() -> Vec<u8> {
    let wat = r#"
(module
  (import "chain" "msg.calldata.read" (func $calldata (param i32 i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (import "chain" "petal.revert" (func $revert (param i32 i32)))
  (import "object" "borrow" (func $borrow (param i32 i32) (result i32)))
  (import "object" "read" (func $read (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; Return envelope: count=1, len=16, payload=42u128.
  (data (i32.const 0) "\00\00\00\01\00\00\00\10\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\2a")
  (data (i32.const 64) "router probe failed")
  (func $fail
    (call $revert (i32.const 64) (i32.const 19)))
  (func (export "__petal_quote_2hop") (param i32 i32) (result i32)
    (local $n i32)
    (local $h1 i32)
    (local $h2 i32)
    (local.set $n (call $calldata (i32.const 128) (i32.const 0) (i32.const 75)))
    (if (i32.lt_s (local.get $n) (i32.const 75)) (then (call $fail)))
    ;; Arg0 is tag=2 followed by object id at calldata offset 5.
    (local.set $h1 (call $borrow (i32.const 133) (i32.const 0)))
    ;; Arg1 is tag=2 followed by object id at calldata offset 38.
    (local.set $h2 (call $borrow (i32.const 166) (i32.const 0)))
    (if (i32.le_s (local.get $h1) (i32.const 0)) (then (call $fail)))
    (if (i32.le_s (local.get $h2) (i32.const 0)) (then (call $fail)))
    (local.set $n (call $read (local.get $h1) (i32.const 256) (i32.const 256)))
    (if (i32.le_s (local.get $n) (i32.const 0)) (then (call $fail)))
    (local.set $n (call $read (local.get $h2) (i32.const 512) (i32.const 256)))
    (if (i32.le_s (local.get $n) (i32.const 0)) (then (call $fail)))
    (call $ret (i32.const 0) (i32.const 24))
    i32.const 0)
)
"#;
    append_manifest_section(wat_to_wasm(wat), real_router_manifest_bytes())
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

/// Ed25519-sign + encode `ptb`, write the bytes to a temp file, and run
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
    parse_success_receipt(stdout)
        .with_context(|| format!("could not parse receipt JSON from submit-ptb stdout:\n{stdout}"))
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
    let resolved = client
        .call("chain_resolve_path", serde_json::json!({ "path": path }))
        .await
        .with_context(|| format!("resolve petal path {path}"))?;
    let got = resolved
        .get("hash")
        .and_then(Value::as_str)
        .with_context(|| format!("petal path {path} is not bound"))?;
    let expected_hex = hex::encode(expected.0);
    if got != expected_hex {
        bail!("petal path {path} resolved to {got}, expected {expected_hex}");
    }
    Ok(())
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

fn payload_bytes(obj: &Value) -> Result<Vec<u8>> {
    let hexs = json_str(obj, "payload")?;
    hex::decode(hexs).context("decode object payload hex")
}

fn decode_coin_value(obj: &Value) -> Result<u128> {
    Ok(ptb_decode_coin_value(&payload_bytes(obj)?))
}

fn decode_pool_reserves(obj: &Value) -> Result<(u128, u128)> {
    let payload = payload_bytes(obj)?;
    let (ra, rb, _lp, _k, _price) = bloom_petal_dex_pool::payload::decode_pool(&payload)
        .ok_or_else(|| anyhow!("decode_pool failed for payload {} bytes", payload.len()))?;
    Ok((ra, rb))
}

fn decode_lp_pool_id(obj: &Value) -> Result<bloom_objects::ObjectId> {
    let payload = payload_bytes(obj)?;
    let (pool_id, _shares) = bloom_petal_dex_pool::payload::decode_lp(&payload)
        .ok_or_else(|| anyhow!("decode_lp failed for payload {} bytes", payload.len()))?;
    Ok(pool_id)
}
