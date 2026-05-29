//! **Phase F DeFi litmus** (spec §6, litmus 5.1 + 5.2): the swap pipelines
//! end-to-end through **both** front doors —
//!
//! 1. the **CLI pipe** path (`bloom_ptb_builder::lower_pipe_expr` →
//!    `PtbSession`), reproducing `bloom pipe '<expr>'`, and
//! 2. the **tx-session VFS** path (`bloom_vfs::tx_handler::TxHandler`,
//!    NFS read/write staging),
//!
//! with the **real** pool + wallet wasm executed through the production
//! chain VM. Each litmus builds the `PtbTx` via both doors, asserts the two
//! are byte-identical (`signing_digest()` equality), then executes each
//! against its own fresh-but-identical chain state and checks the on-chain
//! outcome (coins consumed, recipient credited, pool reserves moved,
//! atomic revert on slippage).
//!
//! Built on the proven `real_wasm_pool.rs` de-risk: `litmus_5_1` reproduces
//! `real_pool_swap_then_wallet_receive_threads_coin`'s semantics, but built
//! from a pipe expression rather than a hand-assembled `PtbTx`.
//!
//! `#[ignore]`-gated because it shells out to `cargo build --target
//! wasm32-unknown-unknown` (wasm32 is not in CI). Run with:
//!
//! ```text
//! cargo test -p bloom-petal-dex-it --test pipe_litmus -- --ignored --nocapture
//! ```

use std::sync::Arc;

use bloom_chain_node::ptb_chain_iface::PtbChainAdapter;
use bloom_chain_state::State;
use bloom_chain_types::Hash32;
use bloom_objects::{Object, ObjectId, Owner, TypeTag};
use bloom_ptb_builder::{PtbSession, lower_pipe_expr};
use bloom_script::{ChainStateIface, PetalManifestStub, PqSignature, PtbTx};
use bloom_vfs::{Handler, TxHandler, VfsPath};

use bloom_dex_math::{ConstantProduct, ConstantProductParams, SwapStrategy};
use bloom_petal_dex_it::dex_harness::{
    addr, build_pool_wasm, build_state, build_wallet_wasm, coin_erased_tag, create_shared_pool,
    erased_coin_id, erased_type_tag, genesis_coin_id, owner_has_coin_worth,
    real_pool_manifest_bytes, real_wallet_manifest_bytes, seed_erased_coin, submit_ptb_chain_auth,
    wrap_with_real_manifest,
};

// ---------------------------------------------------------------------------
// Owned `ChainStateIface` adapter for the VFS `TxHandler`.
//
// `PtbChainAdapter<'a>` borrows `&'a State`, so it can't be the
// `Arc<dyn ChainStateIface + Send + Sync>` the handler stores. `State` is
// `Clone + Send + Sync + 'static`, so we keep an owned `Arc<State>` and
// delegate each accessor to a fresh borrowing `PtbChainAdapter` per call.
// ---------------------------------------------------------------------------

struct OwnedAdapter {
    state: Arc<State>,
    block: u64,
}

impl ChainStateIface for OwnedAdapter {
    fn load_object(&self, id: &ObjectId) -> Option<Object> {
        PtbChainAdapter::new(&self.state, self.block).load_object(id)
    }
    fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>> {
        PtbChainAdapter::new(&self.state, self.block).load_petal(hash)
    }
    fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
        PtbChainAdapter::new(&self.state, self.block).load_manifest(hash)
    }
    fn resolve_path(&self, path: &str) -> Option<Hash32> {
        PtbChainAdapter::new(&self.state, self.block).resolve_path(path)
    }
    fn current_block(&self) -> u64 {
        self.block
    }
}

const BLOCK: u64 = 100;

/// Standard pool fee for the single-hop litmus (5.1).
const FEE_BPS: u16 = 30;
/// Litmus 5.2 builds two pools in one chain state. The chain VM derives a
/// created object's `ObjectId` from `petal_hash + per-PTB-counter + tag +
/// payload` with no tx-digest mix-in (`derive_create_id`), so two pools with
/// identical reserves *and* fee would collide on the same id. Distinct fees
/// give distinct payloads → distinct ids; each hop's math uses its own fee.
const HOP1_FEE_BPS: u16 = 30;
const HOP2_FEE_BPS: u16 = 25;
const SHARED_POOL_INITIAL_RESERVE: u128 = 10_000;
const BOB_SWAP_IN: u128 = 100;

/// Standard fixture: a fresh state with the real pool + wallet wasm
/// deployed/bound. Returns `(state, pool_petal_hash, wallet_petal_hash)`.
/// `allocations` pre-funds the listed accounts (genesis `Coin<LOOM>`).
fn deploy(allocations: &[(bloom_chain_types::Address, u128)]) -> (State, Hash32, Hash32) {
    let mut state = build_state(allocations);
    let pool_wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_hash = state.insert_code(&pool_wasm);
    state.set_vfs_binding("/bloom/petals/dex/pool".to_string(), pool_hash);
    let wallet_wasm = std::fs::read(build_wallet_wasm()).expect("read wallet wasm");
    let wallet_hash = state.insert_code(&wallet_wasm);
    state.set_vfs_binding("/bloom/petals/dex/wallet".to_string(), wallet_hash);
    (state, pool_hash, wallet_hash)
}

const FAST_POOL_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_create_pool") (param i32 i32) (result i32) i32.const 0)
  (func (export "__petal_swap_exact_in") (param i32 i32) (result i32) i32.const 0)
  (func (export "__petal_reserves") (param i32 i32) (result i32) i32.const 0)
)
"#;

const FAST_WALLET_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_receive") (param i32 i32) (result i32) i32.const 0)
)
"#;

fn pool_object_tag(petal_hash: [u8; 32]) -> TypeTag {
    TypeTag::Concrete {
        petal_hash,
        type_name: "Pool".to_string(),
        type_args: vec![],
    }
}

fn is_coin_erased(tag: &TypeTag) -> bool {
    let erased = erased_type_tag();
    matches!(
        tag,
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } if type_name == "Coin" && type_args.len() == 1 && type_args[0] == erased
    )
}

fn install_fast_manifest_fixture() -> (State, ObjectId) {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000)]);

    let pool_wasm = wrap_with_real_manifest(FAST_POOL_WAT, real_pool_manifest_bytes());
    let pool_hash = state.insert_code(&pool_wasm);
    state.set_vfs_binding("/bloom/petals/dex/pool".to_string(), pool_hash);

    let wallet_wasm = wrap_with_real_manifest(FAST_WALLET_WAT, real_wallet_manifest_bytes());
    let wallet_hash = state.insert_code(&wallet_wasm);
    state.set_vfs_binding("/bloom/petals/dex/wallet".to_string(), wallet_hash);

    let pool_id = erased_coin_id(b"fast-manifest-pool-id");
    state.set_object(Object {
        id: pool_id,
        type_tag: pool_object_tag(pool_hash.0),
        owner: Owner::Shared,
        version: 0,
        payload: bloom_petal_dex_pool::payload::pool_payload(
            &pool_id,
            1000,
            1000,
            1000,
            1_000_000,
            &FEE_BPS.to_be_bytes(),
            &coin_erased_tag(),
            &coin_erased_tag(),
        ),
    });

    let bob_coin = erased_coin_id(b"fast-manifest-bob-coin");
    seed_erased_coin(&mut state, bob_coin, Owner::Address(bob.0), 100);

    (state, pool_id)
}

fn derive_object_create_id_for_test(
    petal_hash: Hash32,
    create_idx: u64,
    type_tag: &TypeTag,
    payload: &[u8],
) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.object.create.v1\0");
    hasher.update(&petal_hash.0);
    hasher.update(&create_idx.to_be_bytes());
    hasher.update(
        &type_tag
            .encode_canonical()
            .expect("test type tag must encode"),
    );
    hasher.update(payload);
    ObjectId(*hasher.finalize().as_bytes())
}

/// Hex (no `0x`) of a 32-byte id, for splicing into pipe-expr `obj:` tokens.
fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn reject_duplicate_linear_uses(lines: &[String]) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for line in lines {
        for token in line.split_whitespace() {
            let Some(rest) = token.strip_prefix('@') else {
                continue;
            };
            let Some((cmd, ret)) = rest.split_once('.') else {
                continue;
            };
            if cmd.parse::<u16>().is_ok() && ret.parse::<u16>().is_ok() {
                let key = format!("@{cmd}.{ret}");
                if !seen.insert(key.clone()) {
                    return Err(format!(
                        "duplicate linear Use {key}: a PTB return object may be consumed once"
                    ));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Front-door drivers
// ---------------------------------------------------------------------------

/// Build the `PtbTx` for `expr` via the **CLI pipe** front door
/// (`lower_pipe_expr` + `PtbSession`) against a snapshot of `state`.
fn build_via_cli(
    state: &State,
    expr: &str,
    signer: [u8; 32],
    gas_payer: ObjectId,
) -> Result<PtbTx, String> {
    let lines = lower_pipe_expr(expr).map_err(|e| format!("lower_pipe_expr: {e}"))?;
    build_via_cli_lines(state, &lines, signer, gas_payer)
}

/// CLI front door from already-lowered command lines (shared seam:
/// `PtbSession::append_command`). Used directly by the double-spend litmus,
/// whose double-use plan the linear pipe grammar cannot express.
fn build_via_cli_lines(
    state: &State,
    lines: &[String],
    signer: [u8; 32],
    gas_payer: ObjectId,
) -> Result<PtbTx, String> {
    reject_duplicate_linear_uses(lines)?;
    let adapter = PtbChainAdapter::new(state, BLOCK);
    let mut s = PtbSession::new(&adapter);
    for line in lines {
        s.append_command(line)
            .map_err(|e| format!("append_command({line:?}): {e}"))?;
    }
    s.set_signers(vec![signer]);
    s.set_gas_payer(gas_payer);
    // NOTE: deliberately do NOT call set_expiry_block — the VFS `TxHandler`
    // has no expiry seam, so its `build_tx` leaves the `PtbSession` default
    // (`u64::MAX`). Matching that here keeps the two front doors'
    // `signing_digest()` byte-identical (the Phase D gate this litmus
    // asserts). The submit harness uses block 100, well under u64::MAX.
    s.build_unsigned()
        .map_err(|e| format!("build_unsigned: {e}"))
}

/// Build the `PtbTx` for `expr` via the **tx-session VFS** front door
/// (`TxHandler` NFS staging) against a snapshot of `state`.
async fn build_via_vfs(
    state: &State,
    expr: &str,
    signer: [u8; 32],
    gas_payer: ObjectId,
) -> Result<PtbTx, String> {
    let lines = lower_pipe_expr(expr).map_err(|e| format!("lower_pipe_expr: {e}"))?;
    build_via_vfs_lines(state, &lines, signer, gas_payer).await
}

/// VFS front door from already-lowered command lines (shared seam:
/// `write <id>/cmd`). See [`build_via_cli_lines`].
async fn build_via_vfs_lines(
    state: &State,
    lines: &[String],
    signer: [u8; 32],
    gas_payer: ObjectId,
) -> Result<PtbTx, String> {
    reject_duplicate_linear_uses(lines)?;
    let chain = Arc::new(OwnedAdapter {
        state: Arc::new(state.clone()),
        block: BLOCK,
    });
    let handler = TxHandler::new(chain);

    // `cat new` → session id.
    let new_bytes = handler
        .read(&vpath("new"))
        .await
        .map_err(|e| format!("read new: {e:?}"))?;
    let id_str = String::from_utf8(new_bytes).unwrap();
    let id_num: u64 = id_str.trim().parse().unwrap();
    let id = bloom_ptb_builder::SessionId(id_num);

    // Each command line becomes one `write <id>/cmd` write.
    for line in lines {
        handler
            .write(&vpath(&format!("{id_num}/cmd")), line.as_bytes())
            .await
            .map_err(|e| format!("write cmd {line:?}: {e:?}"))?;
    }

    // Header injection seam: signer + gas payer.
    handler
        .write(
            &vpath(&format!("{id_num}/signer")),
            format!("0x{}", hex32(&signer)).as_bytes(),
        )
        .await
        .map_err(|e| format!("write signer: {e:?}"))?;
    handler
        .write(
            &vpath(&format!("{id_num}/gas-payer")),
            format!("0x{}", hex32(&gas_payer.0)).as_bytes(),
        )
        .await
        .map_err(|e| format!("write gas-payer: {e:?}"))?;

    handler.build_tx(id).map_err(|e| format!("build_tx: {e:?}"))
}

fn vpath(p: &str) -> VfsPath {
    VfsPath::parse(p).unwrap()
}

/// Drive the async VFS builder on a single-thread runtime (the
/// `TxHandler` future is `Send`, but a `current_thread` runtime is plenty).
fn build_via_vfs_blocking(
    state: &State,
    expr: &str,
    signer: [u8; 32],
    gas_payer: ObjectId,
) -> Result<PtbTx, String> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(build_via_vfs(state, expr, signer, gas_payer))
}

/// Blocking VFS builder from already-lowered command lines.
fn build_via_vfs_lines_blocking(
    state: &State,
    lines: &[String],
    signer: [u8; 32],
    gas_payer: ObjectId,
) -> Result<PtbTx, String> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(build_via_vfs_lines(state, lines, signer, gas_payer))
}

/// Set a placeholder signature and submit a built `PtbTx` through the
/// chain VM as `sender` (chain-auth is by sender; `build_unsigned` leaves
/// `signatures` empty, so we stamp a placeholder to match the de-risk
/// tests' shape).
fn submit(state: &mut State, sender: bloom_chain_types::Address, mut tx: PtbTx) -> bool {
    if tx.signatures.is_empty() {
        tx.signatures = vec![PqSignature(vec![0u8; 64])];
    }
    let out = submit_ptb_chain_auth(state, sender, tx);
    if !out.success {
        eprintln!(
            "submit reverted: {}",
            String::from_utf8_lossy(&out.return_data)
        );
    }
    out.success
}

// ===========================================================================
// Litmus 5.1 — one-hop swap → receive, through BOTH front doors.
// ===========================================================================

/// Build the 5.1 pipe expr for bob's input coin, the pool, min_out, and the
/// carol recipient. `pool_id`/`pool_ver` are spliced as an `obj:` token.
fn expr_5_1(
    bob_coin: &ObjectId,
    pool_id: &ObjectId,
    pool_ver: u64,
    min_out: u128,
    carol: &[u8; 32],
) -> String {
    format!(
        "/bloom/petals/dex/pool/swap_exact_in type:Erased type:Erased obj:{bob}@0 obj:{pool}@{pool_ver} {min_out} | /bloom/petals/dex/wallet/receive 0x{carol}",
        bob = hex32(&bob_coin.0),
        pool = hex32(&pool_id.0),
        carol = hex32(carol),
    )
}

#[test]
fn fast_pipe_front_doors_match_for_single_hop_plan() {
    let bob = addr(0xB0);
    let carol = addr(0xC0);
    let (state, pool_id) = install_fast_manifest_fixture();

    let bob_coin = erased_coin_id(b"fast-manifest-bob-coin");
    let gas_payer = genesis_coin_id(bob, 1);
    let expr = expr_5_1(&bob_coin, &pool_id, 0, 90, &carol.0);

    let tx_cli = build_via_cli(&state, &expr, bob.0, gas_payer).expect("CLI build");
    let tx_vfs = build_via_vfs_blocking(&state, &expr, bob.0, gas_payer).expect("VFS build");

    assert_eq!(
        tx_cli.signing_digest(),
        tx_vfs.signing_digest(),
        "fast manifest fixture: CLI and VFS must commit the same single-hop plan"
    );
}

#[test]
fn fast_double_spend_lines_rejected_before_execution() {
    let bob = addr(0xB0);
    let carol = addr(0xC0);
    let dave = addr(0xD0);
    let (state, pool_id) = install_fast_manifest_fixture();

    let bob_coin = erased_coin_id(b"fast-manifest-bob-coin");
    let gas_payer = genesis_coin_id(bob, 1);
    let lines = vec![
        format!(
            "/bloom/petals/dex/pool/swap_exact_in type:Erased type:Erased obj:{bob}@0 obj:{pool}@0 1",
            bob = hex32(&bob_coin.0),
            pool = hex32(&pool_id.0),
        ),
        format!(
            "/bloom/petals/dex/wallet/receive @0.0 0x{}",
            hex32(&carol.0)
        ),
        format!("/bloom/petals/dex/wallet/receive @0.0 0x{}", hex32(&dave.0)),
    ];

    let cli_err = build_via_cli_lines(&state, &lines, bob.0, gas_payer)
        .expect_err("CLI must reject duplicate consumption of @0.0");
    let vfs_err = build_via_vfs_lines_blocking(&state, &lines, bob.0, gas_payer)
        .expect_err("VFS must reject duplicate consumption of @0.0");

    assert!(
        cli_err.contains("duplicate linear Use @0.0"),
        "CLI error should name the duplicate linear Use, got: {cli_err}"
    );
    assert_eq!(
        cli_err, vfs_err,
        "both front doors should report the same duplicate-use rejection"
    );
}

#[test]
fn pool_create_id_collision_is_documented_by_payload_discriminator() {
    let pool_hash = Hash32([0x42; 32]);
    let pool_tag = pool_object_tag([0u8; 32]);
    let payload_fee_30 = bloom_petal_dex_pool::payload::pool_payload(
        &ObjectId([0u8; 32]),
        1000,
        1000,
        1000,
        1_000_000,
        &30u16.to_be_bytes(),
        &coin_erased_tag(),
        &coin_erased_tag(),
    );
    let payload_fee_25 = bloom_petal_dex_pool::payload::pool_payload(
        &ObjectId([0u8; 32]),
        1000,
        1000,
        1000,
        1_000_000,
        &25u16.to_be_bytes(),
        &coin_erased_tag(),
        &coin_erased_tag(),
    );

    let id_a = derive_object_create_id_for_test(pool_hash, 0, &pool_tag, &payload_fee_30);
    let id_b = derive_object_create_id_for_test(pool_hash, 0, &pool_tag, &payload_fee_30);
    let id_discriminated =
        derive_object_create_id_for_test(pool_hash, 0, &pool_tag, &payload_fee_25);

    assert_eq!(
        id_a, id_b,
        "two separate single-create PTBs with identical pool payloads collide today"
    );
    assert_ne!(
        id_a, id_discriminated,
        "the current two-hop fixture uses distinct fee params as a payload discriminator"
    );
}

#[test]
#[ignore = "compiles pool+wallet to wasm32; run with `-- --ignored`"]
fn litmus_5_1_one_hop_both_front_doors() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let carol = addr(0xC0); // recipient, distinct from the swapper

    // Two fresh-but-identical states: one per front door (so each executes
    // against its own chain; the digests must match before either runs).
    let (mut state_cli, pool_hash, _wallet_hash) = deploy(&[(alice, 1_000_000), (bob, 1_000_000)]);

    // Alice stands up a shared pool in BOTH states identically.
    let pool_id = create_shared_pool(&mut state_cli, alice, pool_hash, b"p1", FEE_BPS);
    let pool_ver = state_cli.get_object(&pool_id).unwrap().version;
    // Bob seeds his Coin<Erased>(100) input.
    let bob_coin = erased_coin_id(b"bob-5.1");
    seed_erased_coin(&mut state_cli, bob_coin, Owner::Address(bob.0), BOB_SWAP_IN);

    // Clone the prepared state so the VFS run starts from byte-identical
    // chain state (pool created, bob coin seeded).
    let mut state_vfs = state_cli.clone();

    let gas_payer = genesis_coin_id(bob, 1);
    let (_expected_ra, _expected_rb, expected_out) = ConstantProduct::apply_swap(
        SHARED_POOL_INITIAL_RESERVE,
        SHARED_POOL_INITIAL_RESERVE,
        BOB_SWAP_IN,
        &ConstantProductParams { fee_bps: FEE_BPS },
    )
    .expect("swap quote");
    let min_out = expected_out - 1;
    let expr = expr_5_1(&bob_coin, &pool_id, pool_ver, min_out, &carol.0);

    let tx_cli = build_via_cli(&state_cli, &expr, bob.0, gas_payer).expect("CLI build");
    let tx_vfs = build_via_vfs_blocking(&state_vfs, &expr, bob.0, gas_payer).expect("VFS build");

    // The two front doors must produce a byte-identical plan (Phase D gate).
    assert_eq!(
        tx_cli.signing_digest(),
        tx_vfs.signing_digest(),
        "CLI and VFS front doors must commit an identical PtbTx"
    );

    // Execute each against its own state and assert identical on-chain
    // outcomes.
    for (label, state, tx) in [
        ("cli", &mut state_cli, tx_cli),
        ("vfs", &mut state_vfs, tx_vfs),
    ] {
        assert!(
            submit(state, bob, tx),
            "[{label}] swap→receive must succeed"
        );

        // Bob's input coin consumed by the swap.
        assert!(
            state.get_object(&bob_coin).is_none(),
            "[{label}] bob's input coin must be consumed by swap_exact_in"
        );
        // CAROL — not bob — owns the swapped output coin.
        assert!(
            owner_has_coin_worth(state, carol, expected_out),
            "[{label}] carol must receive the swapped output coin (worth {expected_out})"
        );
        assert!(
            !owner_has_coin_worth(state, bob, expected_out),
            "[{label}] the output coin must settle to carol, not bob"
        );
        // Pool reserves moved by the quoted swap.
        let (ra, rb, ..) = bloom_petal_dex_pool::payload::decode_pool(
            &state.get_object(&pool_id).unwrap().payload,
        )
        .unwrap();
        assert_eq!(ra, _expected_ra, "[{label}] reserve_a after swap");
        assert_eq!(rb, _expected_rb, "[{label}] reserve_b after swap");
    }
}

#[test]
#[ignore = "compiles pool+wallet to wasm32; run with `-- --ignored`"]
fn litmus_5_1_slippage_reverts_whole_plan() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let carol = addr(0xC0);

    let (mut state, pool_hash, _wallet_hash) = deploy(&[(alice, 1_000_000), (bob, 1_000_000)]);
    let pool_id = create_shared_pool(&mut state, alice, pool_hash, b"p1", FEE_BPS);
    let pool_ver = state.get_object(&pool_id).unwrap().version;
    let bob_coin = erased_coin_id(b"bob-5.1-slip");
    seed_erased_coin(&mut state, bob_coin, Owner::Address(bob.0), BOB_SWAP_IN);

    let gas_payer = genesis_coin_id(bob, 1);
    let (_, _, expected_out) = ConstantProduct::apply_swap(
        SHARED_POOL_INITIAL_RESERVE,
        SHARED_POOL_INITIAL_RESERVE,
        BOB_SWAP_IN,
        &ConstantProductParams { fee_bps: FEE_BPS },
    )
    .expect("swap quote");
    // min_out above the real output → SlippageExceeded → whole-plan revert.
    let min_out: u128 = 200;
    let expr = expr_5_1(&bob_coin, &pool_id, pool_ver, min_out, &carol.0);

    // Build via both doors (must still agree) then execute the CLI one (the
    // revert is a chain-VM outcome, identical regardless of which door
    // assembled the byte-identical tx).
    let tx_cli = build_via_cli(&state, &expr, bob.0, gas_payer).expect("CLI build");
    let tx_vfs = build_via_vfs_blocking(&state, &expr, bob.0, gas_payer).expect("VFS build");
    assert_eq!(tx_cli.signing_digest(), tx_vfs.signing_digest());

    assert!(
        !submit(&mut state, bob, tx_cli),
        "swap with min_out=200 must revert on slippage"
    );

    // Whole plan reverted: bob's input survives untouched...
    let surviving = state
        .get_object(&bob_coin)
        .expect("bob's input coin must survive a reverted swap");
    assert_eq!(
        bloom_petal_fungible::ops::decode_coin_value(&surviving.payload).ok(),
        Some(BOB_SWAP_IN),
        "bob's input coin value must be unchanged after revert"
    );
    // ...pool reserves stay at their initial values...
    let (ra, rb, ..) =
        bloom_petal_dex_pool::payload::decode_pool(&state.get_object(&pool_id).unwrap().payload)
            .unwrap();
    assert_eq!(
        ra, SHARED_POOL_INITIAL_RESERVE,
        "reserve_a unchanged after revert"
    );
    assert_eq!(
        rb, SHARED_POOL_INITIAL_RESERVE,
        "reserve_b unchanged after revert"
    );
    // ...and carol was credited nothing.
    assert!(
        !owner_has_coin_worth(&state, carol, expected_out),
        "carol must be credited nothing on a reverted swap"
    );
}

#[test]
#[ignore = "compiles pool+wallet to wasm32; run with `-- --ignored`"]
fn litmus_5_1_output_not_double_spendable() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let carol = addr(0xC0);

    let dave = addr(0xD0);

    let (mut state, pool_hash, _wallet_hash) = deploy(&[(alice, 1_000_000), (bob, 1_000_000)]);
    let pool_id = create_shared_pool(&mut state, alice, pool_hash, b"p1", FEE_BPS);
    let pool_ver = state.get_object(&pool_id).unwrap().version;
    let bob_coin = erased_coin_id(b"bob-5.1-double");
    seed_erased_coin(&mut state, bob_coin, Owner::Address(bob.0), BOB_SWAP_IN);

    let gas_payer = genesis_coin_id(bob, 1);

    // The swap's expected output (derived, no magic number): the single coin
    // packet `@0.0` is worth this much.
    let (_ra, _rb, out) = ConstantProduct::apply_swap(
        SHARED_POOL_INITIAL_RESERVE,
        SHARED_POOL_INITIAL_RESERVE,
        BOB_SWAP_IN,
        &ConstantProductParams { fee_bps: FEE_BPS },
    )
    .expect("swap quote");

    // A plan that swaps ONCE (producing the single linear coin packet `@0.0`)
    // then references that SAME `@0.0` output as the input to TWO downstream
    // `receive` commands — a double-spend of one packet to two recipients. The
    // "not double-spendable" guarantee is value-conservation: the packet is a
    // single object, so it cannot be credited to BOTH carol and dave. At most
    // one recipient may end up with the coin (whether the VM rejects the second
    // consume outright or applies last-writer-wins, no value is duplicated).
    //
    // We assemble the lines explicitly rather than via a `|` pipe: the linear
    // grammar auto-binds each stage's primary input to the *prior* stage's
    // output, so it cannot express "two sinks consuming the same source
    // `@0.0`". The explicit lines feed the SAME shared seams both front doors
    // use — `PtbSession::append_command` / `write <id>/cmd` — so both doors are
    // still exercised, just below the pipe-lowering layer.
    let lines = vec![
        // 0: bob's 100-coin → pool → output coin @0.0.
        format!(
            "/bloom/petals/dex/pool/swap_exact_in type:Erased type:Erased obj:{bob}@0 obj:{pool}@{ver} 1",
            bob = hex32(&bob_coin.0),
            pool = hex32(&pool_id.0),
            ver = pool_ver,
        ),
        // 1: settle @0.0 to carol.
        format!(
            "/bloom/petals/dex/wallet/receive @0.0 0x{}",
            hex32(&carol.0)
        ),
        // 2: settle the SAME @0.0 to dave — the double-spend.
        format!("/bloom/petals/dex/wallet/receive @0.0 0x{}", hex32(&dave.0)),
    ];

    // Both doors must treat the double-use identically: either both reject it at
    // build time, or both build the byte-identical plan and the chain VM must
    // reject/revert it deterministically. A permissive "last receive wins"
    // execution is not acceptable for this litmus.
    eprintln!("double-spend plan lines: {lines:#?}");
    match build_via_cli_lines(&state, &lines, bob.0, gas_payer) {
        Err(build_err) => {
            // Rejected at build time. The VFS door must reject identically.
            let vfs_err = build_via_vfs_lines_blocking(&state, &lines, bob.0, gas_payer)
                .expect_err("VFS door must also reject the double-use plan");
            assert_eq!(
                build_err, vfs_err,
                "CLI and VFS should report the same double-use rejection"
            );
            eprintln!("double-use rejected at build: CLI={build_err} VFS={vfs_err}");
        }
        Ok(tx_cli) => {
            // Built — both doors must agree on the byte-identical plan.
            let tx_vfs = build_via_vfs_lines_blocking(&state, &lines, bob.0, gas_payer)
                .expect("VFS door must build the same plan the CLI door did");
            assert_eq!(
                tx_cli.signing_digest(),
                tx_vfs.signing_digest(),
                "both doors must commit the identical double-use plan"
            );
            assert!(
                !submit(&mut state, bob, tx_cli),
                "a double-use plan that builds must revert; last-writer execution is forbidden"
            );

            let surviving = state
                .get_object(&bob_coin)
                .expect("bob's input coin must survive a reverted double-spend");
            assert_eq!(
                bloom_petal_fungible::ops::decode_coin_value(&surviving.payload).ok(),
                Some(BOB_SWAP_IN),
                "bob's input coin value must be unchanged after double-spend revert"
            );
            let (ra, rb, ..) = bloom_petal_dex_pool::payload::decode_pool(
                &state.get_object(&pool_id).unwrap().payload,
            )
            .unwrap();
            assert_eq!(
                ra, SHARED_POOL_INITIAL_RESERVE,
                "pool reserve_a unchanged after double-spend revert"
            );
            assert_eq!(
                rb, SHARED_POOL_INITIAL_RESERVE,
                "pool reserve_b unchanged after double-spend revert"
            );
        }
    }

    // THE INVARIANT (deterministic rejection/revert): neither recipient may get
    // the output coin from a rejected double-spend attempt.
    let carol_has = owner_has_coin_worth(&state, carol, out);
    let dave_has = owner_has_coin_worth(&state, dave, out);
    assert!(
        !carol_has && !dave_has,
        "double-spend must reject/revert, not credit either recipient \
         (carol_has={carol_has}, dave_has={dave_has})"
    );
    let out_coins = state
        .iter_objects()
        .filter(|(_, o)| {
            matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "Coin")
                && bloom_petal_fungible::ops::decode_coin_value(&o.payload).ok() == Some(out)
        })
        .count();
    assert_eq!(
        out_coins, 0,
        "double-spend reject/revert must not commit an output coin worth {out}"
    );
    eprintln!(
        "double-spend reject/revert invariant held: carol_has={carol_has} \
         dave_has={dave_has} out_coins={out_coins}"
    );
}

// ===========================================================================
// Litmus 5.2 — two-hop atomic swap (swap → swap → receive), both doors.
// ===========================================================================

/// Expected per-hop outputs for a fixed-input two-hop through two fresh shared pools
/// charging `HOP1_FEE_BPS` / `HOP2_FEE_BPS` respectively, derived from
/// `bloom_dex_math` (no magic numbers). The two fees differ only so the pools
/// get distinct content-addressed ids (see `HOP*_FEE_BPS`); the swap semantics
/// are otherwise identical to the spec's "two identical pools" framing.
fn two_hop_expected() -> (u128, u128) {
    // Hop 1: input against a fresh pool at HOP1's fee → out1.
    let p1 = ConstantProductParams {
        fee_bps: HOP1_FEE_BPS,
    };
    let (_ra1, _rb1, out1) = ConstantProduct::apply_swap(
        SHARED_POOL_INITIAL_RESERVE,
        SHARED_POOL_INITIAL_RESERVE,
        BOB_SWAP_IN,
        &p1,
    )
    .expect("hop1");
    // Hop 2: out1 in against a fresh pool at HOP2's fee → out2.
    let p2 = ConstantProductParams {
        fee_bps: HOP2_FEE_BPS,
    };
    let (_ra2, _rb2, out2) = ConstantProduct::apply_swap(
        SHARED_POOL_INITIAL_RESERVE,
        SHARED_POOL_INITIAL_RESERVE,
        out1,
        &p2,
    )
    .expect("hop2");
    (out1, out2)
}

/// One swap hop in a 5.2 pipe: the pool to swap against, its expected version,
/// and the slippage floor for that hop.
struct Hop {
    pool: ObjectId,
    version: u64,
    min_out: u128,
}

fn expr_5_2(bob_coin: &ObjectId, hop1: &Hop, hop2: &Hop, carol: &[u8; 32]) -> String {
    format!(
        "/bloom/petals/dex/pool/swap_exact_in type:Erased type:Erased obj:{bob}@0 obj:{p1}@{v1} {min1} \
         | /bloom/petals/dex/pool/swap_exact_in type:Erased type:Erased obj:{p2}@{v2} {min2} \
         | /bloom/petals/dex/wallet/receive 0x{carol}",
        bob = hex32(&bob_coin.0),
        p1 = hex32(&hop1.pool.0),
        v1 = hop1.version,
        min1 = hop1.min_out,
        p2 = hex32(&hop2.pool.0),
        v2 = hop2.version,
        min2 = hop2.min_out,
        carol = hex32(carol),
    )
}

#[test]
#[ignore = "compiles pool+wallet to wasm32; run with `-- --ignored`"]
fn litmus_5_2_two_hop_atomic() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let carol = addr(0xC0);

    let (mut state_cli, pool_hash, _wallet_hash) = deploy(&[(alice, 1_000_000), (bob, 1_000_000)]);

    // Two distinct shared pools.
    let pool1 = create_shared_pool(&mut state_cli, alice, pool_hash, b"hop1", HOP1_FEE_BPS);
    let pool2 = create_shared_pool(&mut state_cli, alice, pool_hash, b"hop2", HOP2_FEE_BPS);
    assert_ne!(pool1, pool2, "the two hops must be distinct pools");
    let v1 = state_cli.get_object(&pool1).unwrap().version;
    let v2 = state_cli.get_object(&pool2).unwrap().version;

    let bob_coin = erased_coin_id(b"bob-5.2");
    seed_erased_coin(&mut state_cli, bob_coin, Owner::Address(bob.0), BOB_SWAP_IN);

    let mut state_vfs = state_cli.clone();

    let (out1, out2) = two_hop_expected();
    // Slippage guards set strictly below the derived outputs.
    let hop1 = Hop {
        pool: pool1,
        version: v1,
        min_out: out1 - 1,
    };
    let hop2 = Hop {
        pool: pool2,
        version: v2,
        min_out: out2 - 1,
    };
    let gas_payer = genesis_coin_id(bob, 1);
    let expr = expr_5_2(&bob_coin, &hop1, &hop2, &carol.0);

    let tx_cli = build_via_cli(&state_cli, &expr, bob.0, gas_payer).expect("CLI build");
    let tx_vfs = build_via_vfs_blocking(&state_vfs, &expr, bob.0, gas_payer).expect("VFS build");
    assert_eq!(
        tx_cli.signing_digest(),
        tx_vfs.signing_digest(),
        "CLI and VFS front doors must commit an identical two-hop PtbTx"
    );

    for (label, state, tx) in [
        ("cli", &mut state_cli, tx_cli),
        ("vfs", &mut state_vfs, tx_vfs),
    ] {
        // Snapshot the set of DEX Coin<Erased> ids before exec so we can
        // assert no orphan intermediate ("B") coin is committed. Successful
        // PTB gas settlement may also mint Coin<LOOM> for the proposer; that
        // accounting coin is not part of this DEX-output invariant.
        let coins_before: std::collections::HashSet<ObjectId> = state
            .iter_objects()
            .filter(|(_, o)| is_coin_erased(&o.type_tag))
            .map(|(id, _)| *id)
            .collect();

        assert!(
            submit(state, bob, tx),
            "[{label}] two-hop swap→swap→receive must succeed"
        );

        // Bob's input consumed.
        assert!(
            state.get_object(&bob_coin).is_none(),
            "[{label}] bob's input coin must be consumed by hop 1"
        );
        // Carol owns the final (computed two-hop) output coin.
        assert!(
            owner_has_coin_worth(state, carol, out2),
            "[{label}] carol must receive the two-hop output coin (worth {out2})"
        );
        // Both pools' reserves updated atomically.
        let (ra1, rb1, ..) =
            bloom_petal_dex_pool::payload::decode_pool(&state.get_object(&pool1).unwrap().payload)
                .unwrap();
        assert_eq!(
            ra1,
            SHARED_POOL_INITIAL_RESERVE + BOB_SWAP_IN,
            "[{label}] pool1 reserve_a after hop1"
        );
        assert_eq!(
            rb1,
            SHARED_POOL_INITIAL_RESERVE - out1,
            "[{label}] pool1 reserve_b after hop1"
        );
        let (ra2, rb2, ..) =
            bloom_petal_dex_pool::payload::decode_pool(&state.get_object(&pool2).unwrap().payload)
                .unwrap();
        assert_eq!(
            ra2,
            SHARED_POOL_INITIAL_RESERVE + out1,
            "[{label}] pool2 reserve_a after hop2"
        );
        assert_eq!(
            rb2,
            SHARED_POOL_INITIAL_RESERVE - out2,
            "[{label}] pool2 reserve_b after hop2"
        );

        // The intermediate coin (hop0's output, consumed by hop1) must NOT
        // be a committed standalone object owned by anyone (no orphan
        // "B-coin"). The only NEW committed Coin is carol's final output.
        let new_coins: Vec<(ObjectId, u128, Owner)> = state
            .iter_objects()
            .filter(|(id, o)| is_coin_erased(&o.type_tag) && !coins_before.contains(id))
            .map(|(id, o)| {
                (
                    *id,
                    bloom_petal_fungible::ops::decode_coin_value(&o.payload).unwrap_or(0),
                    o.owner.clone(),
                )
            })
            .collect();
        assert_eq!(
            new_coins.len(),
            1,
            "[{label}] exactly one new Coin must be committed (carol's output); \
             no orphan intermediate B-coin. got: {new_coins:?}"
        );
        assert_eq!(
            new_coins[0].1, out2,
            "[{label}] the lone new coin is the final output"
        );
        assert_eq!(
            new_coins[0].2,
            Owner::Address(carol.0),
            "[{label}] the lone new coin is owned by carol"
        );
    }
}

#[test]
#[ignore = "compiles pool+wallet to wasm32; run with `-- --ignored`"]
fn litmus_5_2_failure_reverts_whole_plan() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let carol = addr(0xC0);

    let (mut state, pool_hash, _wallet_hash) = deploy(&[(alice, 1_000_000), (bob, 1_000_000)]);
    let pool1 = create_shared_pool(&mut state, alice, pool_hash, b"hop1", HOP1_FEE_BPS);
    let pool2 = create_shared_pool(&mut state, alice, pool_hash, b"hop2", HOP2_FEE_BPS);
    let v1 = state.get_object(&pool1).unwrap().version;
    let v2 = state.get_object(&pool2).unwrap().version;
    let bob_coin = erased_coin_id(b"bob-5.2-fail");
    seed_erased_coin(&mut state, bob_coin, Owner::Address(bob.0), BOB_SWAP_IN);

    let (out1, out2) = two_hop_expected();
    let hop1 = Hop {
        pool: pool1,
        version: v1,
        min_out: out1 - 1, // hop 1 ok
    };
    let hop2 = Hop {
        pool: pool2,
        version: v2,
        min_out: out2 + 1, // hop 2 slippage → SlippageExceeded → whole revert
    };
    let gas_payer = genesis_coin_id(bob, 1);
    let expr = expr_5_2(&bob_coin, &hop1, &hop2, &carol.0);

    let tx_cli = build_via_cli(&state, &expr, bob.0, gas_payer).expect("CLI build");
    let tx_vfs = build_via_vfs_blocking(&state, &expr, bob.0, gas_payer).expect("VFS build");
    assert_eq!(tx_cli.signing_digest(), tx_vfs.signing_digest());

    assert!(
        !submit(&mut state, bob, tx_cli),
        "two-hop with min2 above the second-hop output must revert"
    );

    // Whole plan reverted: bob's input intact...
    let surviving = state
        .get_object(&bob_coin)
        .expect("bob's input coin must survive the reverted two-hop");
    assert_eq!(
        bloom_petal_fungible::ops::decode_coin_value(&surviving.payload).ok(),
        Some(BOB_SWAP_IN),
        "bob's input value unchanged after revert"
    );
    // ...BOTH pools unchanged at their initial values...
    for (label, pool) in [("pool1", &pool1), ("pool2", &pool2)] {
        let (ra, rb, ..) =
            bloom_petal_dex_pool::payload::decode_pool(&state.get_object(pool).unwrap().payload)
                .unwrap();
        assert_eq!(
            ra, SHARED_POOL_INITIAL_RESERVE,
            "{label} reserve_a unchanged after revert"
        );
        assert_eq!(
            rb, SHARED_POOL_INITIAL_RESERVE,
            "{label} reserve_b unchanged after revert"
        );
    }
    // ...and carol credited nothing.
    assert!(
        !owner_has_coin_worth(&state, carol, out1) && !owner_has_coin_worth(&state, carol, out2),
        "carol credited nothing on a reverted two-hop"
    );
}
