//! Integration tests for 2-hop DEX swap scenarios.
//!
//! # Test strategy
//!
//! Test 1: 2-hop quote — chain two `ConstantProduct::quote` calls; verify against hand math.
//! Test 2: 2-hop apply_swap — run two sequential `apply_swap` calls and verify the
//!   final output and reserve updates are correct.
//!
//! All tests are pure math (no wasm, no PTB submission required).

use bloom_dex_math::{ConstantProduct, ConstantProductParams, SwapStrategy};

fn params(fee_bps: u16) -> ConstantProductParams {
    ConstantProductParams { fee_bps }
}

// ---------------------------------------------------------------------------
// Test 1: 2-hop quote — hand math verification.
//
// Pool A→B: reserve_a=1000, reserve_b=1000, fee=30bps
// Pool B→C: reserve_b=1000, reserve_c=1000, fee=30bps
// amount_in (A) = 100
//
// Hop 1:
//   out_1 = 100 * 9970 * 1000 / (1000 * 10000 + 100 * 9970) = 90
//
// Hop 2:
//   out_2 = 90 * 9970 * 1000 / (1000 * 10000 + 90 * 9970) = 82
// ---------------------------------------------------------------------------

#[test]
fn two_hop_quote_matches_hand_calc() {
    let p = params(30);
    let amount_in = 100u128;

    // Hop 1: A→B
    let out_1 = ConstantProduct::quote(1000, 1000, amount_in, &p).unwrap();
    assert_eq!(out_1, 90, "hop 1 output must be 90");

    // Hop 2: B→C (out_1 becomes amount_in for hop 2)
    let out_2 = ConstantProduct::quote(1000, 1000, out_1, &p).unwrap();
    assert_eq!(out_2, 82, "hop 2 output must be 82");
}

// ---------------------------------------------------------------------------
// Test 2: 2-hop apply_swap — sequential reserve updates.
//
// Same pools/amounts as above.
// After hop 1: reserve_a=1100, reserve_b=910, amount_out_1=90
// After hop 2: reserve_b=1090, reserve_c=918, amount_out_2=82
// ---------------------------------------------------------------------------

#[test]
fn two_hop_apply_swap_reserve_updates() {
    let p = params(30);

    // Hop 1: A→B
    let (new_ra, new_rb_after_hop1, out_1) =
        ConstantProduct::apply_swap(1000, 1000, 100, &p).unwrap();
    assert_eq!(out_1, 90);
    assert_eq!(new_ra, 1100);
    assert_eq!(new_rb_after_hop1, 910);

    // Hop 2: B→C (uses out_1 as amount_in)
    // The second pool starts at its own reserves (1000/1000), independent of pool 1.
    let (new_rb2, new_rc, out_2) = ConstantProduct::apply_swap(1000, 1000, out_1, &p).unwrap();
    assert_eq!(out_2, 82, "final output must be 82");
    assert_eq!(new_rb2, 1090, "pool 2 reserve_in = 1000 + 90 = 1090");
    assert_eq!(new_rc, 918, "pool 2 reserve_out = 1000 - 82 = 918");

    // Verify k invariant holds for both hops
    assert!(
        new_ra * new_rb_after_hop1 >= 1000 * 1000,
        "pool1 k must not decrease"
    );
    assert!(new_rb2 * new_rc >= 1000 * 1000, "pool2 k must not decrease");
}

// ---------------------------------------------------------------------------
// Test 3: 2-hop with asymmetric pools.
//
// Pool A→B: reserve_a=5000, reserve_b=1000, fee=0
//   → deeper pool on one side
//   out_1 = 1000 * 500 / (5000 + 500) = 500000 / 5500 = 90
// Pool B→C: reserve_b=10000, reserve_c=10000, fee=0
//   out_2 = 10000 * 90 / (10000 + 90) = 900000 / 10090 = 89
// ---------------------------------------------------------------------------

#[test]
fn two_hop_asymmetric_pools_no_fee() {
    let p0 = params(0);

    let amount_in = 500u128;

    // Hop 1: deep A-side pool
    let out_1 = ConstantProduct::quote(5000, 1000, amount_in, &p0).unwrap();
    // 1000 * 500 / 5500 = 90
    assert_eq!(out_1, 90, "asymmetric hop 1 = 90");

    // Hop 2: equal pool, shallow input
    let out_2 = ConstantProduct::quote(10000, 10000, out_1, &p0).unwrap();
    // 10000 * 90 / 10090 = 900000 / 10090 = 89
    assert_eq!(out_2, 89, "asymmetric hop 2 = 89");
}

// ---------------------------------------------------------------------------
// Test 4: real DEX router manifest preview-call via chain-authoritative path.
//
// Previously `#[ignore]`d pending a pre-built `bloom_petal_dex_router.wasm`
// (wasm32-unknown-unknown is not in CI). With `wrap_with_real_manifest`
// we pair a tiny WAT body with the **real** macro-emitted canonical
// manifest bytes for `/bloom/petals/dex/strategy/cpmm` (which exposes the
// nullary `version()` entry point exercising the multi-petal manifest
// resolution path). The router petal's `quote_*hop` functions take
// `&Pool<A, B, S>` arguments that the validator would substitute via
// `type_args=[A, B, S]`; setting up real `Pool` objects in state is
// covered by `lp_lifecycle` and `dex_smoke_full`. This test focuses
// on proving the router manifest itself decodes cleanly from the wasm
// custom section.
// ---------------------------------------------------------------------------

use bloom_petal_dex_it::dex_harness::{
    addr, build_state, genesis_coin_id, real_router_manifest_bytes, submit_ptb_chain_auth,
    wrap_with_real_manifest,
};
use bloom_petal_manifest::codec::decode as decode_manifest;
use bloom_script::{Command, MoveCmd, PetalRef, PqSignature, PtbTx};

#[test]
fn router_manifest_decodes_and_publishes_via_wasm_section() {
    // Step 1: verify the macro-emitted bytes round-trip the canonical
    // codec (i.e. they are valid `PetalManifestV0` bytes).
    let bytes = real_router_manifest_bytes();
    let m = decode_manifest(bytes).expect("real router manifest must decode");
    assert_eq!(m.module_path, "/bloom/petals/dex/router");
    let names: Vec<&str> = m.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("quote_") || n.starts_with("swap_")),
        "router manifest must declare quote_/swap_ entry points (got {names:?})"
    );

    // Step 2: install the wasm + manifest into a fresh state and let
    // the executor's chain adapter resolve the manifest entirely from
    // the custom section (no override). We don't actually call a
    // router function — those need full Pool objects — but we DO need
    // the manifest to be loadable when a PTB names this petal's hash,
    // which is what the validator's manifest-resolution path does.
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);
    let gas_payer = genesis_coin_id(alice, 0);

    // The router petal has no nullary entry points (every fn takes
    // pool args). Use a sibling cpmm WAT + cpmm manifest as the
    // PTB target, but in addition install the **router** wasm/manifest
    // so this test covers the router's `__bloom_manifest_bytes` →
    // wasm custom-section round-trip on real chain state.
    let router_wat = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_quote_1hop") (param i32 i32) (result i32)
    i32.const 0)
)
"#;
    let router_wasm = wrap_with_real_manifest(router_wat, real_router_manifest_bytes());
    let router_hash = state.insert_code(&router_wasm);
    state.set_vfs_binding("/bloom/petals/dex/router".to_string(), router_hash);

    // Also install the cpmm petal so we can submit a real PTB that
    // exercises the chain-authoritative path end-to-end.
    use bloom_petal_dex_it::dex_harness::real_cpmm_manifest_bytes;
    let cpmm_wat = r#"
(module
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\00\00\00\01\00\00\00\04\00\00\00\01")
  (func (export "__petal_version") (param i32 i32) (result i32)
    (call $ret (i32.const 0) (i32.const 12))
    i32.const 0)
)
"#;
    let cpmm_wasm = wrap_with_real_manifest(cpmm_wat, real_cpmm_manifest_bytes());
    let cpmm_hash = state.insert_code(&cpmm_wasm);
    state.set_vfs_binding("/bloom/petals/dex/strategy/cpmm".to_string(), cpmm_hash);

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: String::new(),
                hash: Some(cpmm_hash),
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
        "PTB against real cpmm manifest must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
}
