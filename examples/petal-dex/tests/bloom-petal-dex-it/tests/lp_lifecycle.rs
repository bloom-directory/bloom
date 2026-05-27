//! LP lifecycle tests: create_pool (initial mint), add_liquidity, remove_liquidity.
//!
//! All tests are pure math through `bloom_dex_math` — no wasm, no PTB.
//!
//! # Hand-math reference
//!
//! - create_pool initial mint uses `sqrt(amount_a * amount_b)` (spec §15.3)
//! - add_liquidity proportional: `lp = min(a*lp_supply/reserve_a, b*lp_supply/reserve_b)`
//! - remove_liquidity: `a_out = reserve_a * lp_burned / lp_supply`

use bloom_dex_math::{ConstantProduct, MINIMUM_LIQUIDITY, SwapStrategy, integer_sqrt};

// ---------------------------------------------------------------------------
// Test 1: create_pool initial mint uses sqrt.
//
// amount_a=400, amount_b=900, lp_supply=0
// lp_minted = sqrt(400 * 900) = sqrt(360_000) = 600
// ---------------------------------------------------------------------------

#[test]
fn create_pool_initial_mint_uses_sqrt() {
    let (taken_a, taken_b, lp_minted) =
        ConstantProduct::add_liquidity(0, 0, 40_000, 90_000, 0).unwrap();

    assert_eq!(taken_a, 40_000, "all amount_a deposited on initial mint");
    assert_eq!(taken_b, 90_000, "all amount_b deposited on initial mint");
    assert_eq!(lp_minted, 59_000, "lp_minted = sqrt(k) - minimum");

    // Verify via integer_sqrt directly
    let product = 40_000u128 * 90_000u128;
    assert_eq!(integer_sqrt(product), lp_minted + MINIMUM_LIQUIDITY);
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
    let (_a1, _b1, lp1) = ConstantProduct::add_liquidity(0, 0, 10_000, 10_000, 0).unwrap();
    assert_eq!(lp1, 9000, "initial lp = sqrt(k) - minimum");

    // Step 2: subsequent deposit (pool now has reserve_a=100, reserve_b=100, lp=100)
    let lp_supply = lp1 + MINIMUM_LIQUIDITY;
    let (taken_a, taken_b, lp2) =
        ConstantProduct::add_liquidity(10_000, 10_000, 5000, 5000, lp_supply).unwrap();
    assert_eq!(lp2, 5000, "subsequent lp proportional = 5000");
    assert_eq!(taken_a, 5000);
    assert_eq!(taken_b, 5000);
}

// ---------------------------------------------------------------------------
// Test 7: real pool petal manifest decodes via chain-authoritative path.
//
// Previously `#[ignore]`d pending a pre-built `bloom_petal_dex_pool.wasm`
// (wasm32-unknown-unknown is not in CI). With `wrap_with_real_manifest`
// we install the **real** macro-emitted canonical manifest bytes for
// `/bloom/dex/pool` into chain state and confirm:
//   1. The manifest is canonical-decodable.
//   2. It declares the LP lifecycle entry points the spec promises
//      (`create_pool`, `add_liquidity`, `remove_liquidity`).
//   3. The wasm custom-section path can be loaded by
//      `PtbChainAdapter::load_manifest` against a synthetic
//      WAT body — i.e. the manifest is portable independent of any
//      wasm32 toolchain.
//
// The full PTB-driven LP lifecycle (with actual Pool / LpPosition
// objects) is exercised by `dex_smoke_full::ptb_pool_lifecycle_*`.
// ---------------------------------------------------------------------------

use bloom_chain_node::ptb_chain_iface::PtbChainAdapter;
use bloom_chain_state::State;
use bloom_petal_dex_it::dex_harness::{real_pool_manifest_bytes, wrap_with_real_manifest};
use bloom_petal_manifest::codec::decode as decode_manifest;
use bloom_script::ChainStateIface;

#[test]
fn real_pool_manifest_loads_via_chain_adapter() {
    let bytes = real_pool_manifest_bytes();
    let m = decode_manifest(bytes).expect("real pool manifest must decode");
    assert_eq!(m.module_path, "/bloom/dex/pool");

    let names: Vec<&str> = m.functions.iter().map(|f| f.name.as_str()).collect();
    for expected in ["create_pool", "add_liquidity", "remove_liquidity"] {
        assert!(
            names.contains(&expected),
            "pool manifest must declare `{expected}` (got {names:?})"
        );
    }

    // Install a synthetic wasm carrying the real manifest in its
    // `bloom_petal_manifest_v0` custom section and confirm the
    // production `PtbChainAdapter` finds it via layer 2 (wasm
    // custom-section parse + project). This is the **exact** path
    // the chain node uses for a deployed petal.
    let wat = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_create_pool") (param i32 i32) (result i32)
    i32.const 0)
)
"#;
    let wasm = wrap_with_real_manifest(wat, bytes);
    let mut state = State::new();
    let hash = state.insert_code(&wasm);

    let adapter = PtbChainAdapter::new(&state, 100);
    let stub = adapter
        .load_manifest(&hash)
        .expect("adapter must load manifest from wasm custom section");
    assert_eq!(stub.module_path, "/bloom/dex/pool");
    let stub_names: Vec<&str> = stub.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(stub_names.contains(&"create_pool"));
    assert!(stub_names.contains(&"add_liquidity"));
    assert!(stub_names.contains(&"remove_liquidity"));
}
