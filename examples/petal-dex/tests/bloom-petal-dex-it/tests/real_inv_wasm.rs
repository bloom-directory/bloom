//! **Real-wasm** verdict + gas test for the `pool_k_non_decreasing`
//! invariant. Drives the *actual compiled* `__inv_0` export of the
//! `/bloom/dex/pool` petal through the chain VM with hand-built scope
//! buffers — closing the gap left by `pool_k_invariant.rs` (which checks
//! the macro-generated evaluator on the host) and `real_wasm_pool.rs`
//! (which only exercises the satisfied path via a full swap).
//!
//! Verifies, on real bytecode:
//! - a k-non-decreasing scope returns `1` (satisfied),
//! - a k-decreasing scope returns `0` (violated),
//! - invariant fuel is non-zero, bounded, and deterministic (gate 9.6).
//!
//! `#[ignore]`-gated because it compiles the pool crate to
//! `wasm32-unknown-unknown` (not in CI). Run with:
//!
//! ```text
//! cargo test -p bloom-petal-dex-it --test real_inv_wasm -- --ignored --nocapture
//! ```

use bloom_chain_state::State;
use bloom_chain_types::Address;
use bloom_chain_types::types::Hash32;
use bloom_petals::PetalVm;
use bloom_petals::chain_vm::{BlockCtx, ChainCallInput, ChainEntry};
use bloom_script::invariant_scope::{SCOPE_KIND_OBJECT_TYPE, build_invariant_scope};

use bloom_petal_dex_it::dex_harness::build_pool_wasm;

/// Generous per-invariant fuel ceiling; the predicate is a handful of
/// loads + one 256-bit multiply + a compare, so real usage is tiny.
const FUEL_BUDGET: u64 = 5_000_000;

/// Build a scope holding every field the *corrected* `pool_k_non_decreasing`
/// predicate references — including `before/after.lp_supply`. The real
/// on-chain scope (`build_object_scope`) always populates every addressable
/// field of the Pool layout; omitting `lp_supply` here would make the
/// `Not(FieldEq(lp_supply))` disjunct fail-open in the guest (missing field
/// → 0 → `1 - 0 = 1`), masking a true violation. Callers set `lp_before ==
/// lp_after` to exercise the k-comparison (pure-swap path).
fn scope(ra: u128, rb: u128, k_before: u128, lp_before: u128, lp_after: u128) -> Vec<u8> {
    build_invariant_scope(
        SCOPE_KIND_OBJECT_TYPE,
        "Pool",
        0,
        &[
            ("after.reserve_a".into(), ra),
            ("after.reserve_b".into(), rb),
            ("before.k_last".into(), k_before),
            ("before.lp_supply".into(), lp_before),
            ("after.lp_supply".into(), lp_after),
        ],
    )
    .unwrap()
}

/// Invoke the compiled `__inv_0` export over `scope`; return
/// `(verdict_byte, fuel_used)`.
fn run_inv(wasm: &[u8], scope: &[u8]) -> (u8, u64) {
    let input = ChainCallInput {
        wasm: wasm.to_vec(),
        external_manifests: Vec::new(),
        entry: ChainEntry::Function("__inv_0".to_string()),
        contract_address: Address([0x01; 32]),
        msg_sender: Address([0x02; 32]),
        msg_value: 0,
        calldata: scope.to_vec(),
        block: BlockCtx {
            number: 1,
            timestamp_ms: 0,
            prevhash: Hash32([0; 32]),
        },
        fuel: FUEL_BUDGET,
        snapshot: State::new().snapshot(),
        ptb_ctx: None,
    };
    let out = PetalVm::run_chain_call(input).expect("__inv_0 runs");
    let verdict = out
        .return_data
        .expect("invariant returns a verdict via petal.return");
    assert_eq!(verdict.len(), 1, "verdict is a single byte");
    (verdict[0], out.fuel_used)
}

#[test]
#[ignore = "compiles pool to wasm32; run with `-- --ignored`"]
fn real_inv0_verdicts_and_gas() {
    let wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");

    // Pure swap (lp unchanged), k grew: 1100 * 910 = 1_001_000 >= 1_000_000.
    let (v_ok, fuel_ok) = run_inv(&wasm, &scope(1100, 910, 1_000_000, 5, 5));
    assert_eq!(v_ok, 1, "non-decreasing k must satisfy the invariant");

    // Pure swap (lp unchanged), k dropped: 900 * 900 = 810_000 < 1_000_000.
    // Both disjuncts false → violated.
    let (v_bad, fuel_bad) = run_inv(&wasm, &scope(900, 900, 1_000_000, 5, 5));
    assert_eq!(v_bad, 0, "decreasing k with unchanged lp must violate");

    // Liquidity event: k dropped but lp_supply changed → the `|| lp changed`
    // disjunct exempts it (remove_liquidity path). Must satisfy.
    let (v_liq, fuel_liq) = run_inv(&wasm, &scope(900, 900, 1_000_000, 5, 3));
    assert_eq!(v_liq, 1, "liquidity event (lp changed) must be exempt");

    // Extreme operands: u128::MAX * u128::MAX is a 256-bit product that
    // must not overflow or be mis-decided — it dwarfs any u128 k_last.
    let (v_max, fuel_max) = run_inv(&wasm, &scope(u128::MAX, u128::MAX, u128::MAX, 5, 5));
    assert_eq!(
        v_max, 1,
        "256-bit product must compare correctly at the extreme"
    );

    // Gas: bounded and non-zero on every path (gate 9.6).
    for fuel in [fuel_ok, fuel_bad, fuel_liq, fuel_max] {
        assert!(fuel > 0, "invariant evaluation must consume fuel");
        assert!(
            fuel < FUEL_BUDGET,
            "invariant fuel {fuel} must stay under the budget {FUEL_BUDGET}"
        );
    }

    // Determinism: identical scope ⇒ identical fuel across runs.
    let (_, fuel_ok2) = run_inv(&wasm, &scope(1100, 910, 1_000_000, 5, 5));
    assert_eq!(fuel_ok, fuel_ok2, "invariant fuel must be deterministic");
}
