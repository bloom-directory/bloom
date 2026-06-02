//! `pool_k_non_decreasing` invariant — wiring + differential tests.
//!
//! These run entirely on the host (no wasm32 build):
//! 1. The real `/bloom/dex/pool` manifest carries the invariant with the
//!    expected `Or(ArithCmp, Not(FieldEq))` AST and `Pool` field layout.
//! 2. The macro-generated guest evaluator (`__bloom_inv_0_eval`, exposed
//!    `pub` for host testing) agrees, over a fuzz corpus of scopes, with
//!    the independent trusted interpreter `interpret_predicate`
//!    (plan §9.3 differential gate).

use bloom_petal_dex_it::dex_harness::real_pool_manifest_bytes;
use bloom_petal_manifest::interpret::{EvalOutcome, interpret_predicate};
use bloom_petal_manifest::types::{
    ArithExpr, BoundedArithOp, CmpOp, InvariantTarget, PredicateAst,
};
use bloom_script::invariant_scope::{SCOPE_KIND_OBJECT_TYPE, build_invariant_scope};

fn pool_predicate() -> PredicateAst {
    let manifest =
        bloom_petal_manifest::decode(real_pool_manifest_bytes()).expect("pool manifest decodes");
    let inv = manifest
        .invariants
        .iter()
        .find(|i| i.name == "pool_k_non_decreasing")
        .expect("pool_k_non_decreasing invariant present in real manifest");
    assert!(
        matches!(&inv.target, InvariantTarget::ObjectType { name } if name == "Pool"),
        "invariant must target ObjectType(Pool), got {:?}",
        inv.target
    );
    inv.predicate.clone()
}

#[test]
fn real_pool_manifest_carries_boolean_k_invariant() {
    // after.reserve_a * after.reserve_b >= before.k_last
    //   || !(after.lp_supply == before.lp_supply)
    let PredicateAst::Or(left, right) = pool_predicate() else {
        panic!("expected Or(...) predicate");
    };
    match *left {
        PredicateAst::ArithCmp {
            op: CmpOp::Ge,
            lhs:
                ArithExpr::Bounded {
                    op: BoundedArithOp::Mul,
                    lhs,
                    rhs,
                    ..
                },
            rhs: kfield,
        } => {
            assert_eq!(*lhs, ArithExpr::Field("after.reserve_a".into()));
            assert_eq!(*rhs, ArithExpr::Field("after.reserve_b".into()));
            assert_eq!(kfield, ArithExpr::Field("before.k_last".into()));
        }
        other => panic!("unexpected left disjunct: {other:?}"),
    }
    match *right {
        PredicateAst::Not(inner) => assert_eq!(
            *inner,
            PredicateAst::FieldEq {
                lhs: "after.lp_supply".into(),
                rhs: "before.lp_supply".into(),
            }
        ),
        other => panic!("unexpected right disjunct: {other:?}"),
    }
}

#[test]
fn real_pool_field_layout_locates_reserves_and_k() {
    let manifest =
        bloom_petal_manifest::decode(real_pool_manifest_bytes()).expect("pool manifest decodes");
    let stub = bloom_petal_manifest::to_petal_manifest_stub(&manifest);
    let pool = stub.object_type("Pool").expect("Pool object type");
    let offset_of = |name: &str| {
        pool.field_layout
            .iter()
            .find(|f| f.name == name)
            .map(|f| (f.offset, f.width))
    };
    // id(32) | reserve_a(16) | reserve_b(16) | lp_supply(16) | k_last(16)
    assert_eq!(offset_of("reserve_a"), Some((32, 16)));
    assert_eq!(offset_of("reserve_b"), Some((48, 16)));
    assert_eq!(offset_of("k_last"), Some((80, 16)));
}

/// Build a scope holding every field the predicate references. Includes
/// `before/after.lp_supply` (the host always populates them for a real Pool
/// row); omitting them would make the interpreter return Indeterminate on the
/// `Not(FieldEq)` disjunct while the guest fail-closes, a spurious mismatch.
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

/// Assert the macro-generated guest evaluator and the trusted interpreter
/// agree for one scope. Indeterminate cannot occur (all referenced fields
/// present, 256-bit product never overflows), so it is a hard failure.
fn assert_agrees(
    pred: &PredicateAst,
    ra: u128,
    rb: u128,
    k: u128,
    lp_before: u128,
    lp_after: u128,
) {
    let s = scope(ra, rb, k, lp_before, lp_after);
    let generated = bloom_petal_dex_pool::pool::__bloom_inv_0_eval(&s);
    let reference = match interpret_predicate(pred, &s) {
        EvalOutcome::Satisfied => 1,
        EvalOutcome::Violated => 0,
        EvalOutcome::Indeterminate => {
            panic!("unexpected indeterminate for {ra},{rb},{k},{lp_before},{lp_after}")
        }
    };
    assert_eq!(
        generated, reference,
        "guest vs interpreter mismatch at reserves=({ra},{rb}) k={k} lp=({lp_before}->{lp_after})"
    );
}

#[test]
fn generated_evaluator_matches_trusted_interpreter() {
    let pred = pool_predicate();
    // (reserve_a, reserve_b, k_last, lp_before, lp_after).
    let corpus: &[(u128, u128, u128, u128, u128)] = &[
        (1100, 910, 1_000_000, 5, 5),            // swap, k grew -> satisfied
        (1000, 1000, 1_000_000, 5, 5),           // swap, k equal -> satisfied
        (900, 900, 1_000_000, 5, 5),             // swap, k dropped -> violated
        (900, 900, 1_000_000, 5, 3), // remove_liquidity: k down, lp changed -> satisfied
        (1200, 1200, 1_000_000, 5, 9), // add_liquidity: lp changed -> satisfied
        (0, 0, 0, 0, 0),             // degenerate
        (u128::MAX, u128::MAX, u128::MAX, 1, 1), // 256-bit product, no overflow
        (u128::MAX, 1, 5, 7, 7),
        (7, 11, 77, 2, 2),
        (7, 11, 78, 2, 2),
    ];
    for &(ra, rb, k, lpb, lpa) in corpus {
        assert_agrees(&pred, ra, rb, k, lpb, lpa);
    }
}

/// splitmix64 — a tiny deterministic PRNG so the sweep is reproducible
/// and needs no dependency.
struct SplitMix64(u64);
impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A `u128` masked to a random bit-width so magnitudes span the whole
    /// range (tiny values, mid, and near `u128::MAX`).
    fn next_u128_varwidth(&mut self) -> u128 {
        let raw = ((self.next_u64() as u128) << 64) | self.next_u64() as u128;
        let bits = (self.next_u64() % 129) as u32; // 0..=128
        if bits >= 128 {
            raw
        } else {
            raw & ((1u128 << bits) - 1)
        }
    }
}

#[test]
fn generated_evaluator_matches_interpreter_randomized() {
    let pred = pool_predicate();
    let mut rng = SplitMix64(0x5EED_1234_C0FF_EE99);
    for _ in 0..2000 {
        let ra = rng.next_u128_varwidth();
        let rb = rng.next_u128_varwidth();
        // Bias k toward the comparison boundary half the time so the sweep
        // hits both satisfied and violated, not just one side. Only straddle
        // when the product fits in u128 — otherwise the true 256-bit product
        // dwarfs any u128 k and the case can't bracket the real boundary
        // (it would just pin k at u128::MAX and always satisfy).
        let k = match (rng.next_u64() & 1 == 0, ra.checked_mul(rb)) {
            (true, _) | (false, None) => rng.next_u128_varwidth(),
            (false, Some(product)) => {
                let delta = (rng.next_u64() % 5) as u128; // straddle by a few units
                if rng.next_u64() & 1 == 0 {
                    product.saturating_sub(delta)
                } else {
                    product.saturating_add(delta)
                }
            }
        };
        // Exercise both disjuncts: ~half the time lp_supply changes
        // (liquidity event), otherwise it's unchanged (pure swap).
        let lp_before = rng.next_u128_varwidth();
        let lp_after = if rng.next_u64() & 1 == 0 {
            lp_before
        } else {
            rng.next_u128_varwidth()
        };
        assert_agrees(&pred, ra, rb, k, lp_before, lp_after);
    }
}
