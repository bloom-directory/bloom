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
//   amount_in_with_fee = 100 * 9970 / 10000 = 99
//   out_1 = 1000 * 99 / (1000 + 99) = 99000 / 1099 = 90
//
// Hop 2:
//   amount_in_with_fee = 90 * 9970 / 10000 = 89 (integer div: 89730/10000=89)
//   out_2 = 1000 * 89 / (1000 + 89) = 89000 / 1089 = 81
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
    assert_eq!(out_2, 81, "hop 2 output must be 81");
}

// ---------------------------------------------------------------------------
// Test 2: 2-hop apply_swap — sequential reserve updates.
//
// Same pools/amounts as above.
// After hop 1: reserve_a=1100, reserve_b=910, amount_out_1=90
// After hop 2: reserve_b=1090, reserve_c=919, amount_out_2=81
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
    let (new_rb2, new_rc, out_2) =
        ConstantProduct::apply_swap(1000, 1000, out_1, &p).unwrap();
    assert_eq!(out_2, 81, "final output must be 81");
    assert_eq!(new_rb2, 1090, "pool 2 reserve_in = 1000 + 90 = 1090");
    assert_eq!(new_rc, 919, "pool 2 reserve_out = 1000 - 81 = 919");

    // Verify k invariant holds for both hops
    assert!(new_ra * new_rb_after_hop1 >= 1000 * 1000, "pool1 k must not decrease");
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
// Test 4 (ignored): 2-hop PTB using real wasm router petal.
//
// PREREQUISITE: cargo build -p bloom-petal-dex-router --target wasm32-unknown-unknown --release
// TODO: follow-up task to wire real wasm artifacts.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires pre-built bloom_petal_dex_router.wasm; TODO: follow-up task for real wasm integration"]
fn full_wasm_two_hop_swap() {
    let wasm_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-unknown-unknown/release/bloom_petal_dex_router.wasm");
    assert!(wasm_path.exists(), "wasm not found; build first");
}
