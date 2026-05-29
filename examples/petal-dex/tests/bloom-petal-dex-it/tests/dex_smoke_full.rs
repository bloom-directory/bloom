//! Full DEX smoke test: create_pool → add_liquidity → swap → remove_liquidity.
//!
//! This test exercises the complete LP lifecycle mathematically, then verifies
//! the expected coin balance invariants hold after each operation.
//!
//! # Test strategy
//!
//! Math-only verification (no wasm required). The full PTB-level wasm flow
//! is marked `#[ignore]` pending real wasm artifact integration.

use bloom_dex_math::{ConstantProduct, ConstantProductParams, MINIMUM_LIQUIDITY, SwapStrategy};

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
        ConstantProduct::add_liquidity(0, 0, 10_000, 10_000, 0).unwrap();
    assert_eq!(
        alice_lp, 9000,
        "alice initial lp = sqrt(100M) - MINIMUM_LIQUIDITY"
    );
    assert_eq!(taken_a_alice, 10_000);
    assert_eq!(taken_b_alice, 10_000);

    let mut reserve_a = 10_000u128;
    let mut reserve_b = 10_000u128;
    let mut lp_supply = alice_lp + MINIMUM_LIQUIDITY;

    // Step 2: bob adds liquidity (deposit 500/500 into 1000/1000 pool)
    let (taken_a_bob, taken_b_bob, bob_lp) =
        ConstantProduct::add_liquidity(reserve_a, reserve_b, 5000, 5000, lp_supply).unwrap();
    assert_eq!(bob_lp, 5000, "bob lp proportional = 5000");
    assert_eq!(taken_a_bob, 5000);
    assert_eq!(taken_b_bob, 5000);

    reserve_a += taken_a_bob;
    reserve_b += taken_b_bob;
    lp_supply += bob_lp;
    assert_eq!(reserve_a, 15_000);
    assert_eq!(reserve_b, 15_000);
    assert_eq!(lp_supply, 15_000);

    // Step 3: charlie swaps 100 A→B (fee=30bps)
    let (new_ra, new_rb, amount_out_charlie) =
        ConstantProduct::apply_swap(reserve_a, reserve_b, 1000, &params(30)).unwrap();

    assert_eq!(amount_out_charlie, 934, "charlie gets 934 B tokens");
    assert_eq!(new_ra, 16_000, "pool reserve_a = 16000");
    assert_eq!(new_rb, 14_066, "pool reserve_b = 15000 - 934 = 14066");

    reserve_a = new_ra;
    reserve_b = new_rb;

    // Verify k invariant (with fee, k should be >= original)
    assert!(
        reserve_a * reserve_b >= 15_000 * 15_000,
        "k must not decrease after swap"
    );

    // Step 4: bob removes half his LP
    let bob_lp_to_burn = bob_lp / 2; // 2500
    let (a_out_bob, b_out_bob) =
        ConstantProduct::remove_liquidity(reserve_a, reserve_b, lp_supply, bob_lp_to_burn).unwrap();

    assert_eq!(a_out_bob, 2666, "bob gets 2666 A tokens back");
    assert_eq!(b_out_bob, 2344, "bob gets 2344 B tokens back");

    // Bob gets back more value than he put in on A-side (due to charlie's swap adding A)
    let bob_a_in = taken_a_bob / 2; // he's only burning half
    let bob_b_in = taken_b_bob / 2;
    assert!(
        a_out_bob > bob_a_in,
        "bob gains A due to charlie's swap (IL in reverse)"
    );
    assert!(
        b_out_bob < bob_b_in,
        "bob gets back less B due to B being bought by charlie"
    );
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
    let reserve_loom = 1_000u128; // scaled
    let amount_in = 100_000u128; // 0.1 USDC

    let out = ConstantProduct::quote(reserve_usdc, reserve_loom, amount_in, &params(30)).unwrap();

    // amount_in_with_fee = 100_000 * 9970 / 10000 = 99700
    // amount_out = 1000 * 99700 / (1_000_000 + 99700) = 99_700_000 / 1_099_700 = 90
    assert_eq!(out, 90, "multi-token quote = 90");
}

// ---------------------------------------------------------------------------
// Test 3: real DEX petal manifests are all loadable side-by-side.
//
// Previously `#[ignore]`d pending pre-built DEX petal wasms (the
// wasm32-unknown-unknown toolchain is not in CI). With
// `wrap_with_real_manifest` we install **all three** real DEX petal
// manifests (`/bloom/petals/dex/pool`, `/bloom/petals/dex/strategy/cpmm`,
// `/bloom/petals/dex/router`) into a single `State`, then drive a PTB that
// invokes the nullary `cpmm.version()` entry against the chain
// adapter's wasm custom-section path. Asserting that the executor
// resolves the right manifest by hash (and not by VFS path collision
// or override) gives end-to-end coverage of the multi-petal
// manifest-resolution shape that the production node sees in a real
// DEX deployment.
//
// Per-petal lifecycle math is covered in `dex_smoke_full::full_dex_flow_math`
// (test 1 above) and `lp_lifecycle.rs`. Full PTB-driven create_pool /
// swap flows depend on cross-petal `Use(cmd, ret)` typed-slot tracking
// for `Pool<A, B, S>` returns; that's the next follow-up.
// ---------------------------------------------------------------------------

use bloom_petal_dex_it::dex_harness::{
    addr, build_state, genesis_coin_id, real_cpmm_manifest_bytes, real_pool_manifest_bytes,
    real_router_manifest_bytes, submit_ptb_chain_auth, wrap_with_real_manifest,
};
use bloom_script::{Command, MoveCmd, PetalRef, PqSignature, PtbTx};

#[test]
fn three_dex_petal_manifests_coexist_via_chain_adapter() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000_000)]);
    let gas_payer = genesis_coin_id(alice, 0);

    // Install pool, cpmm, router all carrying their real manifests.
    let pool_wat = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_create_pool") (param i32 i32) (result i32)
    i32.const 0)
)
"#;
    let pool_wasm = wrap_with_real_manifest(pool_wat, real_pool_manifest_bytes());
    let pool_hash = state.insert_code(&pool_wasm);
    state.set_vfs_binding("/bloom/petals/dex/pool".to_string(), pool_hash);

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

    assert_ne!(
        pool_hash, cpmm_hash,
        "different wasms must hash differently"
    );
    assert_ne!(
        cpmm_hash, router_hash,
        "different wasms must hash differently"
    );
    assert_ne!(
        pool_hash, router_hash,
        "different wasms must hash differently"
    );

    // PTB calls cpmm.version() — pinning by hash forces the adapter
    // to resolve the cpmm manifest from its specific wasm custom
    // section (not from pool or router).
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
        "cpmm.version() must succeed when pool/cpmm/router manifests coexist; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
}
