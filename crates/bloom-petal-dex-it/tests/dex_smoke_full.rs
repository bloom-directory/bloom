//! Full DEX smoke test: create_pool → add_liquidity → swap → remove_liquidity.
//!
//! This test exercises the complete LP lifecycle mathematically, then verifies
//! the expected coin balance invariants hold after each operation.
//!
//! # Test strategy
//!
//! Math-only verification (no wasm required). The full PTB-level wasm flow
//! is marked `#[ignore]` pending real wasm artifact integration.

use bloom_dex_math::{ConstantProduct, ConstantProductParams, SwapStrategy};

fn params(fee_bps: u16) -> ConstantProductParams {
    ConstantProductParams { fee_bps }
}

// ---------------------------------------------------------------------------
// Test 1: Full flow math — create_pool → add_liquidity → swap → remove.
//
// Scenario: 3 users — alice creates pool, bob adds liquidity, charlie swaps,
// then bob removes liquidity.
//
// Step 1 (alice creates pool): amount_a=1000, amount_b=1000, lp_supply=0
//   → lp_minted = sqrt(1000*1000) = 1000
//
// Step 2 (bob adds liquidity): reserve=1000/1000, lp=1000, deposit=500/500
//   → lp_minted = 500, taken_a=500, taken_b=500
//   → pool: reserve_a=1500, reserve_b=1500, lp_supply=1500
//
// Step 3 (charlie swaps): amount_in=100 A→B, fee=30bps
//   → out_1 = 1500 * 99 / (1500 + 99) = 148500 / 1599 = 92
//   → pool: reserve_a=1600, reserve_b=1408
//
// Step 4 (bob removes half his LP): lp_burned=250 (half of 500)
//   → reserve_a=1600, reserve_b=1408, lp_supply=1500
//   → a_out = 1600 * 250 / 1500 = 266
//   → b_out = 1408 * 250 / 1500 = 234
// ---------------------------------------------------------------------------

#[test]
fn full_dex_flow_math() {
    // Step 1: alice creates pool
    let (taken_a_alice, taken_b_alice, alice_lp) =
        ConstantProduct::add_liquidity(0, 0, 1000, 1000, 0).unwrap();
    assert_eq!(alice_lp, 1000, "alice initial lp = sqrt(1M) = 1000");
    assert_eq!(taken_a_alice, 1000);
    assert_eq!(taken_b_alice, 1000);

    let mut reserve_a = 1000u128;
    let mut reserve_b = 1000u128;
    let mut lp_supply = alice_lp;

    // Step 2: bob adds liquidity (deposit 500/500 into 1000/1000 pool)
    let (taken_a_bob, taken_b_bob, bob_lp) =
        ConstantProduct::add_liquidity(reserve_a, reserve_b, 500, 500, lp_supply).unwrap();
    assert_eq!(bob_lp, 500, "bob lp proportional = 500");
    assert_eq!(taken_a_bob, 500);
    assert_eq!(taken_b_bob, 500);

    reserve_a += taken_a_bob;
    reserve_b += taken_b_bob;
    lp_supply += bob_lp;
    assert_eq!(reserve_a, 1500);
    assert_eq!(reserve_b, 1500);
    assert_eq!(lp_supply, 1500);

    // Step 3: charlie swaps 100 A→B (fee=30bps)
    let (new_ra, new_rb, amount_out_charlie) =
        ConstantProduct::apply_swap(reserve_a, reserve_b, 100, &params(30)).unwrap();

    // Hand calc: amount_in_with_fee = 100 * 9970 / 10000 = 99
    // amount_out = 1500 * 99 / (1500 + 99) = 148500 / 1599 = 92
    assert_eq!(amount_out_charlie, 92, "charlie gets 92 B tokens");
    assert_eq!(new_ra, 1600, "pool reserve_a = 1600");
    assert_eq!(new_rb, 1408, "pool reserve_b = 1500 - 92 = 1408");

    reserve_a = new_ra;
    reserve_b = new_rb;

    // Verify k invariant (with fee, k should be >= original)
    assert!(reserve_a * reserve_b >= 1500 * 1500, "k must not decrease after swap");

    // Step 4: bob removes half his LP
    let bob_lp_to_burn = bob_lp / 2; // 250
    let (a_out_bob, b_out_bob) =
        ConstantProduct::remove_liquidity(reserve_a, reserve_b, lp_supply, bob_lp_to_burn).unwrap();

    // Hand calc: a_out = 1600 * 250 / 1500 = 266, b_out = 1408 * 250 / 1500 = 234
    assert_eq!(a_out_bob, 266, "bob gets 266 A tokens back");
    assert_eq!(b_out_bob, 234, "bob gets 234 B tokens back");

    // Bob gets back more value than he put in on A-side (due to charlie's swap adding A)
    let bob_a_in = taken_a_bob / 2; // he's only burning half
    let bob_b_in = taken_b_bob / 2;
    assert!(a_out_bob > bob_a_in, "bob gains A due to charlie's swap (IL in reverse)");
    assert!(b_out_bob < bob_b_in, "bob gets back less B due to B being bought by charlie");
}

// ---------------------------------------------------------------------------
// Test 2: Multi-token scenario — verify math with different token scales.
//
// Simulates USDC/LOOM pool where USDC has 6 decimals, LOOM has 18.
// Uses small scale factors to stay in integer range.
//
// Pool: reserve_usdc=1_000_000 (1 USDC), reserve_loom=1_000 (1e-15 LOOM), fee=30bps
// Swap: amount_in_usdc=100_000 (0.1 USDC)
// ---------------------------------------------------------------------------

#[test]
fn multi_token_scale_swap() {
    let reserve_usdc = 1_000_000u128; // 1 USDC (6 dec)
    let reserve_loom = 1_000u128;     // scaled
    let amount_in    = 100_000u128;   // 0.1 USDC

    let out = ConstantProduct::quote(reserve_usdc, reserve_loom, amount_in, &params(30)).unwrap();

    // amount_in_with_fee = 100_000 * 9970 / 10000 = 99700
    // amount_out = 1000 * 99700 / (1_000_000 + 99700) = 99_700_000 / 1_099_700 = 90
    assert_eq!(out, 90, "multi-token quote = 90");
}

// ---------------------------------------------------------------------------
// Test 3 (ignored): Full PTB flow with 3 users, real wasm petals.
//
// Build allocations for 3 users with Coin<USDC>, Coin<LOOM>, Coin<DAI>.
// Submit PTBs: create_pool → add_liquidity → swap_exact_in → remove_liquidity.
// Assert end-of-flow Coin balances.
//
// TODO: follow-up task to wire real wasm artifacts once build.rs integration is set up.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires pre-built DEX petal wasms; TODO: follow-up task for real wasm PTB integration"]
fn full_ptb_three_user_dex_flow() {
    // This test will exercise the complete on-chain DEX flow once real wasm petals
    // are available. The math validation above (full_dex_flow_math) covers the
    // computation correctness; this test would cover the PTB encoding/dispatch path.
    todo!("wire real wasm petals from build artifacts")
}
