use bloom_petal_manifest::{
    codec,
    types::{FunctionDecl, MANIFEST_CUSTOM_SECTION, PetalManifestV0},
};
use bloom_petals::chain_vm::validate_chain_wasm;

fn wasm_with_manifest(wat_src: &str, functions: Vec<FunctionDecl>) -> Vec<u8> {
    let mut wasm = wat::parse_str(wat_src).expect("wat parses");
    let manifest = PetalManifestV0 {
        module_path: "/bloom/test/view".to_string(),
        functions,
        ..Default::default()
    };
    append_custom_section(
        &mut wasm,
        MANIFEST_CUSTOM_SECTION,
        &codec::encode(&manifest).expect("manifest encodes"),
    );
    wasm
}

fn append_custom_section(wasm: &mut Vec<u8>, name: &str, data: &[u8]) {
    wasm.push(0);
    let mut body = Vec::new();
    leb128(&mut body, name.len() as u64);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(data);
    leb128(wasm, body.len() as u64);
    wasm.extend_from_slice(&body);
}

fn leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            return;
        }
    }
}

fn func(name: &str, view: bool) -> FunctionDecl {
    FunctionDecl {
        name: name.to_string(),
        view,
        ..Default::default()
    }
}

#[test]
fn view_reaching_direct_mutating_import_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "create" (func $create))
            (func $__petal_quote (call $create))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("view function 'quote'"));
    assert!(err.contains("object.create"));
}

#[test]
fn view_reaching_transitive_mutating_import_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "delete" (func $delete))
            (func $helper (call $delete))
            (func $__petal_quote (call $helper))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("view function 'quote'"));
    assert!(err.contains("object.delete"));
}

#[test]
fn reachable_call_indirect_in_view_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (type $t (func))
            (table 1 funcref)
            (func $helper)
            (elem (i32.const 0) $helper)
            (func $__petal_quote
              (i32.const 0)
              (call_indirect (type $t)))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("call_indirect"));
}

#[test]
fn reachable_return_call_to_mutating_import_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "mutate" (func $mutate))
            (func $__petal_quote
              (return_call $mutate))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("return_call"));
}

#[test]
fn reachable_return_call_indirect_in_view_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (type $t (func))
            (table 1 funcref)
            (func $helper)
            (elem (i32.const 0) $helper)
            (func $__petal_quote
              (i32.const 0)
              (return_call_indirect (type $t)))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("return_call_indirect"));
}

#[test]
fn tail_call_in_non_view_export_is_rejected() {
    let wasm = wasm_with_manifest(
        r#"(module
            (func $helper)
            (func $__petal_update
              (return_call $helper))
            (export "__petal_update" (func $__petal_update))
        )"#,
        vec![func("update", false)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("return_call"));
}

#[test]
fn start_section_is_rejected_before_view_purity_claims() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "mutate" (func $mutate))
            (func $start (call $mutate))
            (start $start)
            (func $__petal_quote)
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", true)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(err.contains("start function"));
    assert!(err.contains("not allowed"));
}

#[test]
fn pure_view_passes_and_mixed_mutating_non_view_deploys() {
    let wasm = wasm_with_manifest(
        r#"(module
            (import "object" "mutate" (func $mutate))
            (func $__petal_quote)
            (func $__petal_update (call $mutate))
            (export "__petal_quote" (func $__petal_quote))
            (export "__petal_update" (func $__petal_update))
        )"#,
        vec![func("quote", true), func("update", false)],
    );

    validate_chain_wasm(&wasm).expect("pure view plus mutating non-view should pass");
}

#[test]
fn float_opcode_in_chain_petal_is_rejected() {
    // A function that multiplies two f64s — the canonical non-deterministic
    // float op (ADR-004). Deploy-time validation must reject it.
    let wasm = wasm_with_manifest(
        r#"(module
            (func $__petal_quote (result f64)
              (f64.mul (f64.const 1.5) (f64.const 2.0)))
            (export "__petal_quote" (func $__petal_quote))
        )"#,
        vec![func("quote", false)],
    );

    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("floating-point"),
        "expected float rejection, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed: invariants whose predicate the on-chain evaluator cannot
// enforce must be rejected at deploy time (rather than silently passing).
// ---------------------------------------------------------------------------

fn wasm_with_invariant(predicate: bloom_petal_manifest::types::PredicateAst) -> Vec<u8> {
    use bloom_objects::{AbilitySet, TypeTag};
    use bloom_petal_manifest::types::{FieldDecl, InvariantDecl, InvariantTarget, ObjectTypeDecl};
    let mut wasm = wat::parse_str("(module)").expect("wat parses");
    // A numeric (16-byte) field addressable by `before.`/`after.` predicates.
    let num_field = |name: &str, offset: u32| FieldDecl {
        name: name.to_string(),
        ty: TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "u128".to_string(),
            type_args: vec![],
        },
        offset: Some(offset),
        width: Some(16),
    };
    let id_field = FieldDecl {
        name: "id".to_string(),
        ty: TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "UID".to_string(),
            type_args: vec![],
        },
        offset: Some(0),
        width: Some(32),
    };
    let manifest = PetalManifestV0 {
        module_path: "/bloom/test/inv".to_string(),
        functions: vec![FunctionDecl {
            name: "touch".to_string(),
            attached_invariants: vec![0],
            ..Default::default()
        }],
        object_types: vec![ObjectTypeDecl {
            name: "Pool".to_string(),
            abilities: AbilitySet::default(),
            type_params: vec![],
            fields: vec![
                id_field,
                num_field("reserve_a", 32),
                num_field("reserve_b", 48),
                num_field("k_last", 64),
            ],
        }],
        invariants: vec![InvariantDecl {
            name: "guard".to_string(),
            target: InvariantTarget::ObjectType {
                name: "Pool".to_string(),
            },
            predicate,
            wasm_export: "__inv_0".to_string(),
            human_text: String::new(),
        }],
        ..Default::default()
    };
    append_custom_section(
        &mut wasm,
        MANIFEST_CUSTOM_SECTION,
        &codec::encode(&manifest).expect("manifest encodes"),
    );
    wasm
}

#[test]
fn unenforceable_invariant_predicate_is_rejected() {
    use bloom_petal_manifest::types::PredicateAst;
    // These shapes lower to a constant in the guest — no real check.
    for predicate in [
        PredicateAst::AllPoolsKNonDecreasing,
        PredicateAst::Opaque,
        PredicateAst::StrategyKNonDecreasing {
            strategy_param: "S".into(),
            pool_field: "k_last".into(),
        },
    ] {
        let wasm = wasm_with_invariant(predicate.clone());
        let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
        assert!(
            err.contains("unenforceable predicate"),
            "expected rejection for {predicate:?}, got: {err}"
        );
    }
}

#[test]
fn enforceable_invariant_predicate_is_accepted() {
    use bloom_petal_manifest::types::{
        ArithExpr, BoundedArithOp, CmpOp, OverflowPolicy, PredicateAst, Widening,
    };
    // The real pool_k shape: after.reserve_a * after.reserve_b >= before.k_last.
    let predicate = PredicateAst::ArithCmp {
        op: CmpOp::Ge,
        lhs: ArithExpr::Bounded {
            op: BoundedArithOp::Mul,
            lhs: Box::new(ArithExpr::Field("after.reserve_a".into())),
            rhs: Box::new(ArithExpr::Field("after.reserve_b".into())),
            widening: Widening::U256,
            on_overflow: OverflowPolicy::Indeterminate,
        },
        rhs: ArithExpr::Field("before.k_last".into()),
    };
    let wasm = wasm_with_invariant(predicate);
    validate_chain_wasm(&wasm).expect("enforceable ArithCmp invariant must validate");
}

#[test]
fn subtraction_invariant_predicate_is_rejected_at_deploy() {
    use bloom_petal_manifest::types::{
        ArithExpr, BoundedArithOp, CmpOp, OverflowPolicy, PredicateAst, Widening,
    };
    // `after.reserve_a - before.k_last >= after.reserve_b`: the guest fails
    // closed to Violated on underflow while the interpreter says
    // Indeterminate. Until that divergence is reconciled + fuzzed, deploy
    // must reject any `Sub`-using predicate (S1).
    let predicate = PredicateAst::ArithCmp {
        op: CmpOp::Ge,
        lhs: ArithExpr::Bounded {
            op: BoundedArithOp::Sub,
            lhs: Box::new(ArithExpr::Field("after.reserve_a".into())),
            rhs: Box::new(ArithExpr::Field("before.k_last".into())),
            widening: Widening::U256,
            on_overflow: OverflowPolicy::Indeterminate,
        },
        rhs: ArithExpr::Field("after.reserve_b".into()),
    };
    let wasm = wasm_with_invariant(predicate);
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("subtraction"),
        "expected subtraction rejection, got: {err}"
    );
}

#[test]
fn invariant_referencing_unknown_field_is_rejected() {
    use bloom_petal_manifest::types::PredicateAst;
    // `after.not_a_field` is not in the Pool layout. In the guest it lowers
    // to `0`; wrapped in `Not` it would flip to a false `Satisfied`. Deploy
    // must reject it rather than let it silently fail-open (B2).
    let predicate = PredicateAst::Not(Box::new(PredicateAst::FieldEq {
        lhs: "after.not_a_field".into(),
        rhs: "before.not_a_field".into(),
    }));
    let wasm = wasm_with_invariant(predicate);
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("not_a_field") && err.contains("addressable"),
        "expected unknown-field rejection, got: {err}"
    );
}

#[test]
fn function_exit_invariant_referencing_fields_is_rejected() {
    use bloom_petal_manifest::types::{InvariantDecl, InvariantTarget, PredicateAst};
    // A function-exit invariant gets an empty field table in v1, so any
    // field reference can't be enforced — reject at deploy (B2).
    let mut wasm = wat::parse_str("(module)").expect("wat parses");
    let manifest = PetalManifestV0 {
        module_path: "/bloom/test/inv".to_string(),
        functions: vec![FunctionDecl {
            name: "swap".to_string(),
            attached_invariants: vec![0],
            ..Default::default()
        }],
        invariants: vec![InvariantDecl {
            name: "guard".to_string(),
            target: InvariantTarget::FunctionExit {
                name: "swap".to_string(),
            },
            predicate: PredicateAst::FieldGe {
                lhs: "after.x".into(),
                rhs: "before.x".into(),
            },
            wasm_export: "__inv_0".to_string(),
            human_text: String::new(),
        }],
        ..Default::default()
    };
    append_custom_section(
        &mut wasm,
        MANIFEST_CUSTOM_SECTION,
        &codec::encode(&manifest).expect("manifest encodes"),
    );
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("function-exit") && err.contains("after.x"),
        "expected function-exit field rejection, got: {err}"
    );
}

#[test]
fn overly_expensive_invariant_predicate_is_rejected() {
    use bloom_petal_manifest::types::PredicateAst;
    // Deeply nested boolean composition over a valid field, exceeding the
    // deploy fuel-headroom ceiling (B1 / RT-006 headroom gate). Each leaf is
    // a real field comparison so it's otherwise enforceable.
    let leaf = || PredicateAst::FieldGe {
        lhs: "after.reserve_a".into(),
        rhs: "before.k_last".into(),
    };
    // ~60 leaves * ~110k worst-case fuel each comfortably exceeds the 5M
    // deploy ceiling while staying well under the decoder's depth limit.
    let mut pred = leaf();
    for _ in 0..60 {
        pred = PredicateAst::And(Box::new(pred), Box::new(leaf()));
    }
    let wasm = wasm_with_invariant(pred);
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("too expensive"),
        "expected headroom rejection, got: {err}"
    );
}

#[test]
fn vacuous_invariant_predicate_is_rejected() {
    use bloom_petal_manifest::types::PredicateAst;
    // `after.reserve_a >= after.reserve_a` references a real Pool field (so it
    // clears the enforceability / field-name / headroom gates) but is always
    // true — it enforces nothing and must be rejected (ADR-003).
    let pred = PredicateAst::FieldGe {
        lhs: "after.reserve_a".into(),
        rhs: "after.reserve_a".into(),
    };
    let wasm = wasm_with_invariant(pred);
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("vacuous"),
        "expected vacuity rejection, got: {err}"
    );
}

#[test]
fn tautology_via_or_is_rejected() {
    use bloom_petal_manifest::types::PredicateAst;
    let p = PredicateAst::FieldGe {
        lhs: "after.reserve_a".into(),
        rhs: "before.reserve_a".into(),
    };
    let pred = PredicateAst::Or(
        Box::new(p.clone()),
        Box::new(PredicateAst::Not(Box::new(p))),
    );
    let wasm = wasm_with_invariant(pred);
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("vacuous"),
        "P || !P must be rejected, got: {err}"
    );
}

#[test]
fn contradiction_via_and_is_rejected() {
    use bloom_petal_manifest::types::PredicateAst;
    let p = PredicateAst::FieldGe {
        lhs: "after.reserve_a".into(),
        rhs: "before.reserve_a".into(),
    };
    let pred = PredicateAst::And(
        Box::new(p.clone()),
        Box::new(PredicateAst::Not(Box::new(p))),
    );
    let wasm = wasm_with_invariant(pred);
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("vacuous"),
        "P && !P must be rejected, got: {err}"
    );
}

#[test]
fn constant_contradiction_is_rejected() {
    use bloom_petal_manifest::types::{ArithExpr, CmpOp, PredicateAst};
    let pred = PredicateAst::ArithCmp {
        op: CmpOp::Le,
        lhs: ArithExpr::Literal(2),
        rhs: ArithExpr::Literal(1),
    };
    let wasm = wasm_with_invariant(pred);
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("vacuous"),
        "constant contradiction 2 <= 1 must be rejected, got: {err}"
    );
}

#[test]
fn semantically_vacuous_predicate_rejected_at_deploy() {
    use bloom_petal_manifest::types::{ArithExpr, CmpOp, PredicateAst};
    // `after.reserve_a >= 0` on a u128 field — structurally non-trivial
    // (gate 4 passes), but semantically always true because every u128 >= 0.
    // The boundary gate (gate 5) must catch it (ADR-003 Tier 1a).
    let pred = PredicateAst::ArithCmp {
        op: CmpOp::Ge,
        lhs: ArithExpr::Field("after.reserve_a".into()),
        rhs: ArithExpr::Literal(0),
    };
    let wasm = wasm_with_invariant(pred);
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("semantically vacuous"),
        "semantic vacuity must be rejected, got: {err}"
    );
}

#[test]
fn semantically_always_false_predicate_rejected_at_deploy() {
    use bloom_objects::{AbilitySet, TypeTag};
    use bloom_petal_manifest::{
        codec,
        types::{
            ArithExpr, CmpOp, FieldDecl, InvariantDecl, InvariantTarget, MANIFEST_CUSTOM_SECTION,
            ObjectTypeDecl, PetalManifestV0, PredicateAst,
        },
    };
    // `after.x >= 256` on a u8 field (width=1, domain 0..255) — always
    // false because the maximum value of u8 is 255.
    let pred = PredicateAst::ArithCmp {
        op: CmpOp::Ge,
        lhs: ArithExpr::Field("after.x".into()),
        rhs: ArithExpr::Literal(256),
    };
    let mut wasm = wat::parse_str("(module)").expect("wat parses");
    let manifest = PetalManifestV0 {
        module_path: "/bloom/test/inv".to_string(),
        functions: vec![FunctionDecl {
            name: "touch".to_string(),
            attached_invariants: vec![0],
            ..Default::default()
        }],
        object_types: vec![ObjectTypeDecl {
            name: "T".to_string(),
            abilities: AbilitySet::default(),
            type_params: vec![],
            fields: vec![FieldDecl {
                name: "x".to_string(),
                ty: TypeTag::Concrete {
                    petal_hash: [0u8; 32],
                    type_name: "u8".to_string(),
                    type_args: vec![],
                },
                offset: Some(0),
                width: Some(1),
            }],
        }],
        invariants: vec![InvariantDecl {
            name: "guard".to_string(),
            target: InvariantTarget::ObjectType {
                name: "T".to_string(),
            },
            predicate: pred,
            wasm_export: "__inv_0".to_string(),
            human_text: String::new(),
        }],
        ..Default::default()
    };
    append_custom_section(
        &mut wasm,
        MANIFEST_CUSTOM_SECTION,
        &codec::encode(&manifest).expect("manifest encodes"),
    );
    let err = validate_chain_wasm(&wasm).unwrap_err().to_string();
    assert!(
        err.contains("semantically vacuous"),
        "semantic always-false must be rejected, got: {err}"
    );
}
