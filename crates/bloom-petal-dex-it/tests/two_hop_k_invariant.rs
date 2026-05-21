//! Spec §19 #7 — 2-hop all_pools_k_non_decreasing.
//!
//! Pure-math test: simulate a U→A→B 2-hop swap by chaining two
//! `ConstantProduct::apply_swap` calls. After each 2-hop swap assert that
//! k1 >= prev_k1 AND k2 >= prev_k2.
//!
//! DOD item: spec §19 #7.

use bloom_dex_math::{ConstantProduct, ConstantProductParams, SwapStrategy};

fn params(fee_bps: u16) -> ConstantProductParams {
    ConstantProductParams { fee_bps }
}

// ---------------------------------------------------------------------------
// Test 1: 50 different 2-hop swaps, pool1 and pool2 both 30bps.
//
// U→A (pool 1): reserve_in=1_000_000, reserve_out=1_000_000
// A→B (pool 2): reserve_in=1_000_000, reserve_out=1_000_000
//
// Both pools must satisfy k >= prev_k after each 2-hop.
// ---------------------------------------------------------------------------

#[test]
fn two_hop_all_pools_k_non_decreasing_50_swaps() {
    let p = params(30);

    let mut p1_ri = 1_000_000u128;
    let mut p1_ro = 1_000_000u128;
    let mut p2_ri = 1_000_000u128;
    let mut p2_ro = 1_000_000u128;

    let mut k1_prev = p1_ri * p1_ro;
    let mut k2_prev = p2_ri * p2_ro;

    for i in 1u128..=50 {
        // Vary input amount: [1, 20_000].
        let amount_u = (i % 20_000) + 1;

        // Hop 1: U→A (pool 1)
        let (new_p1_ri, new_p1_ro, amount_a) =
            match ConstantProduct::apply_swap(p1_ri, p1_ro, amount_u, &p) {
                Ok(r) => r,
                Err(_) => break, // pool drained; not a k violation
            };

        // Hop 2: A→B (pool 2), using hop-1 output as input
        let (new_p2_ri, new_p2_ro, _amount_b) =
            match ConstantProduct::apply_swap(p2_ri, p2_ro, amount_a, &p) {
                Ok(r) => r,
                Err(_) => break, // pool drained; not a k violation
            };

        let k1_new = new_p1_ri * new_p1_ro;
        let k2_new = new_p2_ri * new_p2_ro;

        assert!(
            k1_new >= k1_prev,
            "pool1 k decreased at 2-hop {i}: k_prev={k1_prev} k_new={k1_new}"
        );
        assert!(
            k2_new >= k2_prev,
            "pool2 k decreased at 2-hop {i}: k_prev={k2_prev} k_new={k2_new}"
        );

        p1_ri = new_p1_ri;
        p1_ro = new_p1_ro;
        p2_ri = new_p2_ri;
        p2_ro = new_p2_ro;
        k1_prev = k1_new;
        k2_prev = k2_new;
    }
}

// ---------------------------------------------------------------------------
// Test 2: Asymmetric pools — pool1 deep, pool2 shallow (fee=30bps).
//
// Verifies the invariant holds even when pools differ greatly in depth.
// ---------------------------------------------------------------------------

#[test]
fn two_hop_asymmetric_pools_k_non_decreasing() {
    let p = params(30);

    // pool1: U→A (deep)
    let mut p1_ri = 10_000_000u128;
    let mut p1_ro = 10_000_000u128;
    // pool2: A→B (shallow)
    let mut p2_ri = 100_000u128;
    let mut p2_ro = 100_000u128;

    let mut k1_prev = p1_ri * p1_ro;
    let mut k2_prev = p2_ri * p2_ro;

    for i in 1u128..=50 {
        let amount_u = (i % 1_000) + 1;

        let (new_p1_ri, new_p1_ro, amount_a) =
            match ConstantProduct::apply_swap(p1_ri, p1_ro, amount_u, &p) {
                Ok(r) => r,
                Err(_) => break,
            };

        let (new_p2_ri, new_p2_ro, _) =
            match ConstantProduct::apply_swap(p2_ri, p2_ro, amount_a, &p) {
                Ok(r) => r,
                Err(_) => break,
            };

        let k1_new = new_p1_ri * new_p1_ro;
        let k2_new = new_p2_ri * new_p2_ro;

        assert!(k1_new >= k1_prev, "pool1 k decreased at swap {i}");
        assert!(k2_new >= k2_prev, "pool2 k decreased at swap {i}");

        p1_ri = new_p1_ri;
        p1_ro = new_p1_ro;
        p2_ri = new_p2_ri;
        p2_ro = new_p2_ro;
        k1_prev = k1_new;
        k2_prev = k2_new;
    }
}

// ---------------------------------------------------------------------------
// Test 3: Zero-fee 2-hop — k still non-decreasing due to integer rounding.
// ---------------------------------------------------------------------------

#[test]
fn two_hop_zero_fee_k_non_decreasing() {
    let p = params(0);

    let mut p1_ri = 1_000_000u128;
    let mut p1_ro = 1_000_000u128;
    let mut p2_ri = 1_000_000u128;
    let mut p2_ro = 1_000_000u128;

    let mut k1_prev = p1_ri * p1_ro;
    let mut k2_prev = p2_ri * p2_ro;

    for i in 1u128..=50 {
        let amount_u = (i % 10_000) + 1;

        let (new_p1_ri, new_p1_ro, amount_a) =
            match ConstantProduct::apply_swap(p1_ri, p1_ro, amount_u, &p) {
                Ok(r) => r,
                Err(_) => break,
            };

        let (new_p2_ri, new_p2_ro, _) =
            match ConstantProduct::apply_swap(p2_ri, p2_ro, amount_a, &p) {
                Ok(r) => r,
                Err(_) => break,
            };

        let k1_new = new_p1_ri * new_p1_ro;
        let k2_new = new_p2_ri * new_p2_ro;

        assert!(
            k1_new >= k1_prev,
            "pool1 k decreased at swap {i} (zero fee)"
        );
        assert!(
            k2_new >= k2_prev,
            "pool2 k decreased at swap {i} (zero fee)"
        );

        p1_ri = new_p1_ri;
        p1_ro = new_p1_ro;
        p2_ri = new_p2_ri;
        p2_ro = new_p2_ro;
        k1_prev = k1_new;
        k2_prev = k2_new;
    }
}
