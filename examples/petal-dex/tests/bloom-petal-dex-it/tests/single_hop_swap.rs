//! Integration tests for single-hop DEX swap scenarios.
//!
//! # Test strategy
//!
//! Test 1: Math-only — assert `ConstantProduct::apply_swap` matches hand-calculated values.
//! Test 2: PTB smoke — inline WAT "router-like" petal emits SplitCoins + MergeCoins
//!   commands simulating a swap; verify the PTB executes and coin amounts are correct.
//!
//! No wasm32 build required; all petals are inline WAT fixtures.

use std::collections::HashMap;

use bloom_chain_types::types::Hash32;
use bloom_dex_math::{ConstantProduct, ConstantProductParams, SwapStrategy};
use bloom_objects::{AccessMode, OWNER_KIND_ADDRESS, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::type_tag_coin_loom;
use bloom_script::{
    Arg, ArgDeclStub, Command, ExpectedVersion, FunctionDeclStub, MoveCmd, PetalManifestStub,
    PetalRef, PqSignature, PtbTx, UseRef,
};

use bloom_petal_dex_it::dex_harness::{
    addr, build_state, genesis_coin_id, ptb_decode_coin_value, seed_coin, single_manifest,
    submit_ptb, wat_to_wasm,
};

fn params(fee_bps: u16) -> ConstantProductParams {
    ConstantProductParams { fee_bps }
}

// ---------------------------------------------------------------------------
// Test 1: math-only — apply_swap hand-calculated value.
//
// Pool: reserve_in=1000, reserve_out=1000, amount_in=100, fee=30bps
// amount_in_with_fee = 100 * 9970 / 10000 = 99  (integer div)
// amount_out = 1000 * 99 / (1000 + 99) = 99000 / 1099 = 90
// new_reserve_in  = 1000 + 100 = 1100
// new_reserve_out = 1000 - 90  = 910
// ---------------------------------------------------------------------------

#[test]
fn apply_swap_matches_hand_calc() {
    let (new_ri, new_ro, amount_out) =
        ConstantProduct::apply_swap(1000, 1000, 100, &params(30)).unwrap();

    assert_eq!(amount_out, 90, "amount_out must be 90 (hand calc)");
    assert_eq!(new_ri, 1100, "new_reserve_in must be 1100");
    assert_eq!(new_ro, 910, "new_reserve_out must be 910");
}

// ---------------------------------------------------------------------------
// Test 2: PTB smoke — inline WAT "router" petal does Move → SplitCoins →
// TransferObjects, simulating a swap that sends `amount_out` to the user.
//
// The WAT petal acts like a router: it loads alice's coin (returning its id
// in slot 0), then the PTB splits 90 tokens (the expected swap output) and
// transfers them to bob. This verifies the PTB-level command shape works
// end-to-end with the in-process executor.
// ---------------------------------------------------------------------------

#[test]
fn ptb_single_hop_swap_shape() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let mut state = build_state(&[(alice, 1000)]);
    let alice_coin_id = genesis_coin_id(alice, 0);
    let gas_coin_id = genesis_coin_id(alice, 1);
    seed_coin(&mut state, gas_coin_id, alice, 1);

    // WAT petal: takes alice's coin as Arg::Object, returns its id (37-byte envelope)
    // simulating a "router load coin" operation.
    let id_bytes = alice_coin_id.0;
    let id_hex: String = id_bytes.iter().map(|b| format!("\\{b:02x}")).collect();
    let loader_wat = format!(
        r#"
(module
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; 37-byte return envelope: count=1 (4 bytes BE) | len=32 (ULEB128) | id (32 bytes)
  (data (i32.const 0) "\00\00\00\01\20{id_hex}")
  (func (export "__petal_load_coin") (param i32 i32) (result i32)
    (call $ret (i32.const 0) (i32.const 37))
    i32.const 0)
)
"#
    );
    let wasm = wat_to_wasm(&loader_wat);
    let petal_hash = state.insert_code(&wasm);

    let mut manifests: HashMap<Hash32, PetalManifestStub> = HashMap::new();
    manifests.insert(
        petal_hash,
        PetalManifestStub {
            module_path: "/dex/router-proxy".to_string(),
            functions: vec![FunctionDeclStub {
                view: false,
                name: "load_coin".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Object {
                    ty: type_tag_coin_loom(),
                    mode: AccessMode::Mutable,
                }],
                returns: vec![type_tag_coin_loom()],
                required_signers: 0,
                required_capabilities: vec![],
                attached_invariants: vec![],
            }],
            ..Default::default()
        },
    );

    // PTB: Move(load_coin) → SplitCoins(90) → TransferObjects([split], bob)
    // Simulates a swap where alice pays 90 tokens "received" from the pool.
    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            // cmd 0: load alice's coin into borrow table; returns coin id in slot 0
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: String::new(),
                    hash: Some(petal_hash),
                },
                function: "load_coin".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: alice_coin_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::Mutable,
                }],
            }),
            // cmd 1: SplitCoins(alice_coin_ref, [90]) — simulates swap output
            Command::SplitCoins {
                src: UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                amounts: vec![90],
            },
            // cmd 2: TransferObjects([split_result], bob) — deliver to recipient
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 1,
                    ret_idx: 0,
                }],
                owner: Owner::Address(bob.0),
            },
        ],
        gas_payer: gas_coin_id,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb(&mut state, alice, ptb, manifests);
    assert!(
        out.success,
        "PTB must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    // Alice's coin debited by 90 (the simulated swap amount).
    let alice_coin = state
        .get_object(&alice_coin_id)
        .expect("alice coin must exist");
    let alice_val = ptb_decode_coin_value(&alice_coin.payload);
    assert_eq!(alice_val, 910, "alice must have Coin<LOOM>(910) after swap");

    // Bob receives the 90-token split.
    let bob_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: bob.0,
    };
    let bob_owned = state
        .get_ownership(&bob_okey)
        .expect("bob ownership must exist");
    assert_eq!(bob_owned.len(), 1, "bob must own exactly one coin");
    let bob_coin = state
        .get_object(&bob_owned[0])
        .expect("bob coin must exist");
    let bob_val = ptb_decode_coin_value(&bob_coin.payload);
    assert_eq!(bob_val, 90, "bob must have Coin<LOOM>(90)");
    assert_eq!(bob_coin.owner, Owner::Address(bob.0));
}

// ---------------------------------------------------------------------------
// Test 3: zero-fee swap math correctness.
//
// With fee=0, the CPMM formula is pure xy=k.
// reserve_in=500, reserve_out=2000, amount_in=50, fee=0
// amount_out = 2000 * 50 / (500 + 50) = 100000 / 550 = 181
// ---------------------------------------------------------------------------

#[test]
fn apply_swap_zero_fee_correctness() {
    let (new_ri, new_ro, amount_out) =
        ConstantProduct::apply_swap(500, 2000, 50, &params(0)).unwrap();

    // 2000 * 50 / 550 = 181 (integer div)
    assert_eq!(amount_out, 181);
    assert_eq!(new_ri, 550);
    assert_eq!(new_ro, 2000 - 181);

    // k invariant: k_after >= k_before
    let k_before = 500u128 * 2000;
    let k_after = new_ri * new_ro;
    assert!(
        k_after >= k_before,
        "k must not decrease: before={k_before} after={k_after}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: real DEX cpmm manifest end-to-end via chain-authoritative path.
//
// Previously `#[ignore]`d pending a pre-built `bloom_petal_dex_router.wasm`
// (wasm32-unknown-unknown is not in CI). With `wrap_with_real_manifest`
// we pair a tiny WAT body with the **real** macro-emitted canonical
// manifest bytes for `/bloom/petals/dex/strategy/cpmm`, install it in `state`,
// and invoke the nullary `version()` function. The validator decodes
// the manifest from the wasm custom section via `PtbChainAdapter`
// (layer 2, the production path) — identical to what the chain node
// does for any deployed petal.
//
// This proves end-to-end:
//   1. The cpmm petal's macro-emitted manifest is canonical-decodable.
//   2. `PtbChainAdapter::load_manifest` finds it via the custom section.
//   3. Validator typechecks a real petal function call against it.
//   4. The PTB executes (WAT noop body) without revert.
// ---------------------------------------------------------------------------

use bloom_petal_dex_it::dex_harness::{
    real_cpmm_manifest_bytes, submit_ptb_chain_auth, wrap_with_real_manifest,
};

#[test]
fn cpmm_version_call_uses_real_manifest_via_wasm_section() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);
    let gas_payer = genesis_coin_id(alice, 0);

    // WAT body exporting `__petal_version` and returning one ABI slot.
    // The real manifest declares `version()` with no args and one `u32`
    // return, so the synthetic body must satisfy the executor's manifest
    // return-arity check.
    let wat = r#"
(module
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; output buffer: count=1, len=4, payload=1
  (data (i32.const 0) "\00\00\00\01\04\00\00\00\01")
  (func (export "__petal_version") (param i32 i32) (result i32)
    (call $ret (i32.const 0) (i32.const 9))
    i32.const 0)
)
"#;
    let wasm = wrap_with_real_manifest(wat, real_cpmm_manifest_bytes());
    let petal_hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/petals/dex/strategy/cpmm".to_string(), petal_hash);

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: String::new(),
                hash: Some(petal_hash),
            },
            function: "version".to_string(),
            type_args: vec![],
            args: vec![],
        })],
        gas_payer,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, alice, ptb);
    assert!(
        out.success,
        "cpmm.version() against real manifest must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
}

// ---------------------------------------------------------------------------
// Test 5: PTB smoke — log.emit confirms full dispatch path is live in this crate.
// ---------------------------------------------------------------------------

const EMIT_LOG_WAT: &str = r#"
(module
  (import "log" "emit" (func $log (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0)  "\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB")
  (data (i32.const 32) "dex-it-ok")
  (func (export "__petal_emit") (param i32 i32) (result i32)
    (drop (call $log (i32.const 0) (i32.const 32) (i32.const 32) (i32.const 9)))
    i32.const 0)
)
"#;

#[test]
fn smoke_ptb_log_emit_succeeds() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000_000)]);
    let gas_payer = genesis_coin_id(alice, 0);

    let wasm = wat_to_wasm(EMIT_LOG_WAT);
    let petal_hash = state.insert_code(&wasm);
    let manifests = single_manifest(petal_hash, "emit");

    use bloom_script::{MoveCmd, PetalRef, PtbTx};
    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: String::new(),
                hash: Some(petal_hash),
            },
            function: "emit".to_string(),
            type_args: vec![],
            args: vec![],
        })],
        gas_payer,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb(&mut state, alice, ptb, manifests);
    assert!(out.success, "smoke PTB must succeed");
    assert_eq!(out.logs.len(), 1, "expected exactly one log entry");
    assert_eq!(out.logs[0].data, b"dex-it-ok", "log data must round-trip");
}
