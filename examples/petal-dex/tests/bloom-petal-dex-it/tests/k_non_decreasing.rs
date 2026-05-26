//! Spec §19 #6 — k non-decreasing across many CPMM swaps.
//!
//! Pure-math test using `bloom_dex_math::ConstantProduct::apply_swap`.
//! No chain state or PTB execution required.
//!
//! # Amount selection
//!
//! With fee_bps=30, small amounts (< ~34) cause `amount_in_with_fee` to
//! round to zero via integer division, which makes `quote` return
//! `InsufficientLiquidity` before any pool drain occurs. We therefore use
//! amounts in the range [1_000, 51_000] where the fee rounding is
//! negligible. Where the 200-swap stress or zero-fee tests use smaller
//! amounts, they tolerate early termination via `break`.
//!
//! DOD item: spec §19 #6.

use bloom_dex_math::{ConstantProduct, ConstantProductParams, SwapStrategy};

fn params(fee_bps: u16) -> ConstantProductParams {
    ConstantProductParams { fee_bps }
}

// ---------------------------------------------------------------------------
// Test 1: 100 swaps with fee=30bps — k must be non-decreasing each step.
//
// With fee > 0, the fee retained in the pool strictly increases k on every
// swap. k = new_reserve_in * new_reserve_out.
// ---------------------------------------------------------------------------

#[test]
fn k_non_decreasing_100_swaps_with_fee() {
    let p = params(30);

    let mut reserve_in = 1_000_000u128;
    let mut reserve_out = 1_000_000u128;
    let mut k_prev = reserve_in * reserve_out;

    // Use amounts in [1_000, 50_999] — large enough that the 30bps fee
    // does not round amount_in_with_fee to zero.
    for i in 1u128..=100 {
        let amount_in = (i % 50_000) + 1_000;

        // Stop early if pool drains below the swap amount.
        if reserve_out <= amount_in {
            break;
        }

        let (new_ri, new_ro, _) =
            ConstantProduct::apply_swap(reserve_in, reserve_out, amount_in, &p)
                .expect("swap must succeed: reserves >> amount_in");

        let k_new = new_ri * new_ro;
        assert!(
            k_new >= k_prev,
            "k decreased at swap {i}: k_prev={k_prev} k_new={k_new} \
             (ri={reserve_in}, ro={reserve_out}, ai={amount_in})"
        );

        reserve_in = new_ri;
        reserve_out = new_ro;
        k_prev = k_new;
    }
}

// ---------------------------------------------------------------------------
// Test 2: 200-swap stress version (fee=30bps).
// ---------------------------------------------------------------------------

#[test]
fn k_non_decreasing_200_swaps_stress() {
    let p = params(30);

    let mut reserve_in = 1_000_000u128;
    let mut reserve_out = 1_000_000u128;
    let mut k_prev = reserve_in * reserve_out;

    for i in 1u128..=200 {
        let amount_in = (i % 50_000) + 1_000;

        // Stop early if pool drains below a useful level.
        if reserve_out <= amount_in {
            break;
        }

        match ConstantProduct::apply_swap(reserve_in, reserve_out, amount_in, &p) {
            Ok((new_ri, new_ro, _)) => {
                let k_new = new_ri * new_ro;
                assert!(
                    k_new >= k_prev,
                    "k decreased at swap {i}: k_prev={k_prev} k_new={k_new}"
                );
                reserve_in = new_ri;
                reserve_out = new_ro;
                k_prev = k_new;
            }
            // InsufficientLiquidity / MaxOutExceeded can occur near pool drain —
            // not a k violation, just end the run.
            Err(e) => {
                let _ = e; // expected near drain
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 3: 100 swaps with fee=0 — k must be non-decreasing (only goes up due
// to integer division rounding; exact conservation not required by spec).
// ---------------------------------------------------------------------------

#[test]
fn k_non_decreasing_100_swaps_zero_fee() {
    let p = params(0);

    let mut reserve_in = 1_000_000u128;
    let mut reserve_out = 1_000_000u128;
    let mut k_prev = reserve_in * reserve_out;

    for i in 1u128..=100 {
        let amount_in = (i % 50_000) + 1_000;

        if reserve_out <= amount_in {
            break;
        }

        match ConstantProduct::apply_swap(reserve_in, reserve_out, amount_in, &p) {
            Ok((new_ri, new_ro, _)) => {
                let k_new = new_ri * new_ro;
                assert!(
                    k_new >= k_prev,
                    "k decreased at swap {i} (zero fee): k_prev={k_prev} k_new={k_new}"
                );
                reserve_in = new_ri;
                reserve_out = new_ro;
                k_prev = k_new;
            }
            Err(_) => break,
        }
    }
}
