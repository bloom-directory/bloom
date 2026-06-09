//! `cap_revoked_is_monotone` invariant — proves the invariant framework
//! generalizes to a non-DEX petal (`/bloom/core/cap`) and exercises boolean
//! composition (`&&` over field and literal-bounded comparisons).
//!
//! Host-only (no wasm32): decode the petal's embedded manifest, assert the
//! invariant's shape, then check the macro-generated host evaluator
//! (`cap::__bloom_inv_0_eval`) agrees with the trusted interpreter over a few
//! Cap before/after scopes.

use bloom_petal_cap::cap;
use bloom_petal_manifest::interpret::{EvalOutcome, interpret_predicate};
use bloom_petal_manifest::types::{ArithExpr, CmpOp, InvariantTarget, PredicateAst};
use bloom_script::invariant_scope::{SCOPE_KIND_OBJECT_TYPE, build_invariant_scope};

fn cap_predicate() -> PredicateAst {
    let manifest =
        bloom_petal_manifest::decode(cap::__bloom_manifest_bytes()).expect("cap manifest decodes");
    let inv = manifest
        .invariants
        .iter()
        .find(|i| i.name == "cap_revoked_is_monotone")
        .expect("cap_revoked_is_monotone present in manifest");
    assert!(
        matches!(&inv.target, InvariantTarget::ObjectType { name } if name == "Cap"),
        "must target ObjectType(Cap), got {:?}",
        inv.target
    );
    inv.predicate.clone()
}

fn assert_field_le_literal(pred: PredicateAst, field: &str, literal: u128) {
    match pred {
        PredicateAst::ArithCmp {
            op: CmpOp::Le,
            lhs,
            rhs,
        } => {
            assert_eq!(lhs, ArithExpr::Field(field.into()));
            assert_eq!(rhs, ArithExpr::Literal(literal));
        }
        other => panic!("unexpected conjunct: {other:?}"),
    }
}

#[test]
fn manifest_carries_cap_invariant() {
    // after.revoked >= before.revoked && after.revoked <= 1 && after.inner_kind <= 2
    let PredicateAst::And(left, right) = cap_predicate() else {
        panic!("expected And(...) predicate");
    };
    let PredicateAst::And(monotone, flag_range) = *left else {
        panic!("expected left And(...) predicate");
    };
    assert_eq!(
        *monotone,
        PredicateAst::FieldGe {
            lhs: "after.revoked".into(),
            rhs: "before.revoked".into(),
        }
    );
    assert_field_le_literal(*flag_range, "after.revoked", 1);
    assert_field_le_literal(*right, "after.inner_kind", 2);
}

fn scope(rev_before: u128, rev_after: u128, kind_after: u128) -> Vec<u8> {
    build_invariant_scope(
        SCOPE_KIND_OBJECT_TYPE,
        "Cap",
        0,
        &[
            ("before.revoked".into(), rev_before),
            ("after.revoked".into(), rev_after),
            ("after.inner_kind".into(), kind_after),
        ],
    )
    .unwrap()
}

#[test]
fn generated_evaluator_matches_interpreter() {
    let pred = cap_predicate();
    // (before.revoked, after.revoked, after.inner_kind, expected)
    let cases = [
        (0, 1, 0u128, EvalOutcome::Satisfied), // revoke: 0 -> 1, kind Open
        (0, 0, 1, EvalOutcome::Satisfied),     // lock: revoked preserved, kind Locked
        (1, 1, 2, EvalOutcome::Satisfied),     // already revoked, ExpireAt kind
        (1, 0, 0, EvalOutcome::Violated),      // illegal un-revoke (1 -> 0)
        (1, 2, 0, EvalOutcome::Violated),      // invalid revoked flag
        (0, 0, 3, EvalOutcome::Violated),      // out-of-range inner_kind
    ];
    for (rb, ra, kind, expected) in cases {
        let s = scope(rb, ra, kind);
        assert_eq!(
            interpret_predicate(&pred, &s),
            expected,
            "interpreter at revoked {rb}->{ra}, kind {kind}"
        );
        let generated = cap::__bloom_inv_0_eval(&s);
        let want = if expected == EvalOutcome::Satisfied {
            1
        } else {
            0
        };
        assert_eq!(
            generated, want,
            "guest evaluator at revoked {rb}->{ra}, kind {kind}"
        );
    }
}
