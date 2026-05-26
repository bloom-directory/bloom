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
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use tokio::time::{sleep, timeout};

use bloom_chain_node::rpc::RpcClient;
use bloom_objects::{AccessMode, Owner};
use bloom_script::{Arg, Command as PtbCommand, ExpectedVersion, MoveCmd, PetalRef, PtbTx, UseRef};

use bloom_petal_dex_it::dex_harness::{
    build_faucet_wasm, build_pool_wasm, build_wallet_wasm, petal_hash_of, ptb_decode_coin_value,
    ptb_signer_pubkey, ptb_signer_pubkey_hex, sign_and_encode_ptb,
};

// ---------------------------------------------------------------------------
// Constants — keep in sync with scripts/test-docker-petal-dex.sh
// ---------------------------------------------------------------------------

const HOST_RPC_PORTS: [u16; 4] = [18545, 18546, 18547, 18548];

/// Settlement recipient for the swap output. A distinct, deterministic 32-byte
/// address (not the inner-PTB signer) so the receive assertion is unambiguous.
const CAROL: [u8; 32] = [0xC0u8; 32];

/// Pool fee parameter (30 bps), big-endian u16 — mirrors `faucet_provision.rs`.
const POOL_FEE_BPS: u16 = 30;

/// Far-future expiry so the live, ever-advancing chain never rejects the PTB
/// as expired (validator rejects when `current_block > expiry_block`).
const PTB_EXPIRY_BLOCK: u64 = 1_000_000_000;

const PTB_GAS_BUDGET: u64 = 2_000_000;

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

    // ── 2. Build the three petal wasms + deploy each via the bloom CLI ────
    eprintln!();
    eprintln!("[build] compiling pool/wallet/faucet to wasm32-unknown-unknown");
    let pool_wasm_path = build_pool_wasm();
    let wallet_wasm_path = build_wallet_wasm();
    let faucet_wasm_path = build_faucet_wasm();

    let pool_wasm = std::fs::read(&pool_wasm_path).context("read pool wasm")?;
    let wallet_wasm = std::fs::read(&wallet_wasm_path).context("read wallet wasm")?;
    let faucet_wasm = std::fs::read(&faucet_wasm_path).context("read faucet wasm")?;

    // Host-side petal hashes (= blake3_tagged(PETAL, wasm)) — what deploy
    // inserts, and what each PetalRef pins.
    let pool_hash = petal_hash_of(&pool_wasm);
    let wallet_hash = petal_hash_of(&wallet_wasm);
    let faucet_hash = petal_hash_of(&faucet_wasm);

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
    if json_str(&pool_obj, "owner_kind")? != "shared" {
        bail!("Pool is not shared: {:?}", pool_obj.get("owner_kind"));
    }
    let (ra, rb) = decode_pool_reserves(&pool_obj)?;
    if ra != 1000 || rb != 1000 {
        bail!("pool reserves after create_pool: got ({ra}, {rb}) expected (1000, 1000)");
    }
    let pool_version = pool_obj
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing pool version"))?;
    eprintln!(
        "[pool]  shared Pool = {}  reserves=({ra}, {rb})  version={pool_version}",
        pool_id_hex
    );

    // An LpPosition must exist (transferred to the signer).
    let lps = ls_objects_by_type(client0, "LpPosition").await?;
    if lps.is_empty() {
        bail!("no LpPosition object exists after create_pool");
    }
    eprintln!("[lp]    LpPosition objects found: {}", lps.len());

    // ── 6. faucet.mint → swap_exact_in → wallet.receive (one atomic PTB) ──
    eprintln!();
    eprintln!("[ptb-2] faucet.mint(100) -> swap_exact_in(min_out=90) -> wallet.receive(carol)");
    let pool_obj_id = obj_id_from_hex(&pool_obj)?;
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
        gas_price: 0,
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

    eprintln!();
    eprintln!("================================================================");
    eprintln!("  PASS  docker_petal_dex_acceptance");
    eprintln!("        create_pool : shared Pool reserves (1000, 1000) + LpPosition");
    eprintln!("        swap+receive: carol Coin worth 90; pool reserves (1100, 910)");
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

fn use_ret(cmd_idx: u16, ret_idx: u16) -> Arg {
    Arg::Use { cmd_idx, ret_idx }
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
    Ok(())
}

/// Ed25519-sign + encode `ptb`, write the bytes to a temp file, and run
/// `bloom chain submit-ptb --ptb-file <f> --wait` from `home`. Returns the
/// parsed receipt JSON (the pretty block printed before the final `tx_hash`
/// line).
fn submit_ptb(home: &std::path::Path, port: u16, ptb: PtbTx) -> Result<Value> {
    let bytes = sign_and_encode_ptb(ptb);
    let tmp = std::env::temp_dir().join(format!(
        "bloom-petal-ptb-{}-{}.bin",
        std::process::id(),
        blake3::hash(&bytes).to_hex()
    ));
    std::fs::write(&tmp, &bytes).context("write ptb file")?;

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
    bail!("could not parse receipt JSON from submit-ptb stdout:\n{stdout}")
}

// ---------------------------------------------------------------------------
// RPC query helpers
// ---------------------------------------------------------------------------

async fn current_height(client: &RpcClient) -> Result<u64> {
    let v = client.call("chain_tip", serde_json::json!({})).await?;
    Ok(v.get("height").and_then(Value::as_u64).unwrap_or(0))
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

/// Block until `chain_query_block(target)` returns a non-null block.
async fn wait_for_height(client: &RpcClient, target: u64) -> Result<()> {
    loop {
        match client
            .call("chain_query_block", serde_json::json!({ "height": target }))
            .await
        {
            Ok(v) if !v.is_null() => return Ok(()),
            _ => sleep(Duration::from_millis(250)).await,
        }
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

async fn query_object(client: &RpcClient, id_hex: &str) -> Result<Option<Value>> {
    let v = client
        .call("chain_query_object", serde_json::json!({ "id": id_hex }))
        .await?;
    Ok(if v.is_null() { None } else { Some(v) })
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
