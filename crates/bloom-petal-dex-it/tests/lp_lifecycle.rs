//! LP lifecycle tests: create_pool (initial mint), add_liquidity, remove_liquidity.
//!
//! All tests are pure math through `bloom_dex_math` — no wasm, no PTB.
//!
//! # Hand-math reference
//!
//! - create_pool initial mint uses `sqrt(amount_a * amount_b)` (spec §15.3)
//! - add_liquidity proportional: `lp = min(a*lp_supply/reserve_a, b*lp_supply/reserve_b)`
//! - remove_liquidity: `a_out = reserve_a * lp_burned / lp_supply`

use bloom_dex_math::{ConstantProduct, SwapStrategy, integer_sqrt};

// ---------------------------------------------------------------------------
// Test 1: create_pool initial mint uses sqrt.
//
// amount_a=400, amount_b=900, lp_supply=0
// lp_minted = sqrt(400 * 900) = sqrt(360_000) = 600
// ---------------------------------------------------------------------------

#[test]
fn create_pool_initial_mint_uses_sqrt() {
    let (taken_a, taken_b, lp_minted) =
        ConstantProduct::add_liquidity(0, 0, 400, 900, 0).unwrap();

    assert_eq!(taken_a, 400, "all amount_a deposited on initial mint");
    assert_eq!(taken_b, 900, "all amount_b deposited on initial mint");
    assert_eq!(lp_minted, 600, "lp_minted = sqrt(400 * 900) = 600");

    // Verify via integer_sqrt directly
    let product = 400u128 * 900u128;
    assert_eq!(integer_sqrt(product), 600);
}

// ---------------------------------------------------------------------------
// Test 2: add_liquidity proportional mint.
//
// Existing pool: reserve_a=1000, reserve_b=2000, lp_supply=1000
// Deposit amount_a=100, amount_b=300
// mint_a = 100 * 1000 / 1000 = 100
// mint_b = 300 * 1000 / 2000 = 150
// lp_minted = min(100, 150) = 100
// taken_a = 100 * 1000 / 1000 = 100
// taken_b = 100 * 2000 / 1000 = 200
// ---------------------------------------------------------------------------

#[test]
fn add_liquidity_proportional_mint() {
    let (taken_a, taken_b, lp_minted) =
        ConstantProduct::add_liquidity(1000, 2000, 100, 300, 1000).unwrap();

    assert_eq!(lp_minted, 100, "lp_minted = 100 (A is limiting side)");
    assert_eq!(taken_a, 100, "taken_a = 100");
    assert_eq!(taken_b, 200, "taken_b = 200 (proportional to A side)");
}

// ---------------------------------------------------------------------------
// Test 3: remove_liquidity round-trip.
//
// After initial deposit: reserve_a=400, reserve_b=900, lp_supply=600
// Remove all LP: lp_burned=600
// amount_a = 400 * 600 / 600 = 400
// amount_b = 900 * 600 / 600 = 900
// ---------------------------------------------------------------------------

#[test]
fn remove_liquidity_full_round_trip() {
    // Initial state after create_pool (400, 900)
    let lp_supply = 600u128; // sqrt(400*900)

    let (a_out, b_out) = ConstantProduct::remove_liquidity(400, 900, lp_supply, lp_supply).unwrap();

    assert_eq!(a_out, 400, "full burn returns all reserve_a");
    assert_eq!(b_out, 900, "full burn returns all reserve_b");
}

// ---------------------------------------------------------------------------
// Test 4: remove_liquidity partial burn.
//
// reserve_a=1000, reserve_b=2000, lp_supply=500, lp_burned=100
// amount_a = 1000 * 100 / 500 = 200
// amount_b = 2000 * 100 / 500 = 400
// ---------------------------------------------------------------------------

#[test]
fn remove_liquidity_partial_burn() {
    let (a_out, b_out) = ConstantProduct::remove_liquidity(1000, 2000, 500, 100).unwrap();
    assert_eq!(a_out, 200, "partial burn: a_out = 200");
    assert_eq!(b_out, 400, "partial burn: b_out = 400");
}

// ---------------------------------------------------------------------------
// Test 5: error paths.
// ---------------------------------------------------------------------------

#[test]
fn add_liquidity_zero_deposit_rejected() {
    use bloom_dex_math::MathError;
    // lp_supply=0 and amount_a=0 → product=0 → sqrt=0 → InsufficientLiquidity
    let result = ConstantProduct::add_liquidity(0, 0, 0, 0, 0);
    assert_eq!(result, Err(MathError::InsufficientLiquidity));
}

#[test]
fn remove_liquidity_zero_supply_rejected() {
    use bloom_dex_math::MathError;
    let result = ConstantProduct::remove_liquidity(1000, 1000, 0, 100);
    assert_eq!(result, Err(MathError::ZeroLpSupply));
}

#[test]
fn remove_liquidity_burn_exceeds_supply_rejected() {
    use bloom_dex_math::MathError;
    let result = ConstantProduct::remove_liquidity(1000, 1000, 100, 200);
    assert_eq!(result, Err(MathError::InsufficientLiquidity));
}

// ---------------------------------------------------------------------------
// Test 6: sequential add_liquidity (create + subsequent) consistency.
//
// Create pool with (100, 100) → lp = sqrt(10000) = 100
// Add (50, 50) → proportional on equal pool
//   mint_a = 50 * 100 / 100 = 50
//   mint_b = 50 * 100 / 100 = 50
//   lp_minted = 50
// ---------------------------------------------------------------------------

#[test]
fn add_liquidity_create_then_subsequent() {
    // Step 1: create
    let (_a1, _b1, lp1) = ConstantProduct::add_liquidity(0, 0, 100, 100, 0).unwrap();
    assert_eq!(lp1, 100, "initial lp = sqrt(100*100) = 100");

    // Step 2: subsequent deposit (pool now has reserve_a=100, reserve_b=100, lp=100)
    let (taken_a, taken_b, lp2) =
        ConstantProduct::add_liquidity(100, 100, 50, 50, lp1).unwrap();
    assert_eq!(lp2, 50, "subsequent lp proportional = 50");
    assert_eq!(taken_a, 50);
    assert_eq!(taken_b, 50);
}

// ---------------------------------------------------------------------------
// Test 7 (ignored): full wasm LP lifecycle using real pool petal.
//
// TODO: follow-up task to wire real wasm artifacts.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires pre-built bloom_petal_dex_pool.wasm; TODO: follow-up task for real wasm integration"]
fn full_wasm_lp_lifecycle() {
    let wasm_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-unknown-unknown/release/bloom_petal_dex_pool.wasm");
    assert!(wasm_path.exists(), "wasm not found; build first");
}
