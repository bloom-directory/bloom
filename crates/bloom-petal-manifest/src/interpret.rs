//! Trusted host-side interpreter for [`PredicateAst`] over a flat
//! field-table scope buffer (`bloom_script::invariant_scope`).
//!
//! This is the reference implementation the compiled `__inv_<idx>` wasm
//! export is checked against (plan §9.3 differential gate). It is written
//! independently of the macro-generated guest evaluator: any divergence
//! between the two indicates a codegen, scope-encoding, or memory bug.

use bloom_script::invariant_scope::lookup_field;

use crate::types::{ArithExpr, BoundedArithOp, CmpOp, OverflowPolicy, PredicateAst};

/// Tri-state result of evaluating a predicate (ADR-002).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalOutcome {
    /// Predicate holds.
    Satisfied,
    /// Predicate is violated.
    Violated,
    /// Could not be decided (missing field, overflow with
    /// `OverflowPolicy::Indeterminate`, or an unsupported AST shape).
    Indeterminate,
}

/// An arithmetic value that may exceed `u128` while remaining finite.
/// `TooBig` lets comparisons against a `u128` field resolve without a
/// wider integer type (a value above `u128::MAX` is `>=` any `u128`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AVal {
    Num(u128),
    TooBig,
}

/// Whether the on-chain (`__inv_<idx>`) evaluator can actually enforce a
/// predicate of this shape. Shapes outside this set lower to a constant in
/// the guest (no real check), so a petal must not be allowed to deploy one
/// — deploy-time validation rejects them (fail-closed). Kept here as the
/// single source of truth shared by the validator.
pub fn predicate_is_enforceable(p: &PredicateAst) -> bool {
    match p {
        PredicateAst::ArithCmp { .. }
        | PredicateAst::FieldGe { .. }
        | PredicateAst::FieldLe { .. }
        | PredicateAst::FieldEq { .. } => true,
        // A boolean composition is enforceable iff all its children are.
        PredicateAst::And(a, b) | PredicateAst::Or(a, b) => {
            predicate_is_enforceable(a) && predicate_is_enforceable(b)
        }
        PredicateAst::Not(inner) => predicate_is_enforceable(inner),
        PredicateAst::StrategyKNonDecreasing { .. }
        | PredicateAst::AllPoolsKNonDecreasing
        | PredicateAst::Opaque => false,
    }
}

/// Deploy-time ceiling on a predicate's worst-case evaluation cost
/// ([`predicate_max_fuel`]). A petal whose invariant exceeds this is
/// rejected at deploy (`validate_chain_wasm`). The on-chain runtime grants
/// each evaluation a strictly larger *fixed* budget
/// (`bloom_script::executor::INV_FUEL_PER_EVAL`, currently 10M), so any
/// predicate that passes this gate provably completes within its runtime
/// budget and can never be pushed out-of-fuel by adversarial inputs
/// (red-team RT-006, option b). Keep this comfortably below that budget.
pub const MAX_INVARIANT_PREDICATE_FUEL: u64 = 5_000_000;

// Per-node worst-case fuel weights. These are deliberate *over*-estimates
// of the wasm fuel each lowered AST node can consume (codegen.rs:
// `emit_predicate_eval` / `emit_arith`), so the static sum is a true upper
// bound — erring toward rejecting a predicate too early, never too late.
const FUEL_FIELD_LOOKUP: u64 = 50_000; // worst-case linear scan of the scope table
const FUEL_ARITH_OP: u64 = 5_000; // one 256-bit add/sub/mul
const FUEL_COMPARE: u64 = 5_000; // one 256-bit comparison
const FUEL_BOOL_NODE: u64 = 5_000; // one And/Or/Not combinator
const FUEL_LITERAL: u64 = 1_000; // widening a constant

/// Conservative upper bound on the wasm fuel one evaluation of `p` can
/// consume, computed structurally from the AST (no execution). Used by the
/// deploy-time headroom gate; see [`MAX_INVARIANT_PREDICATE_FUEL`].
pub fn predicate_max_fuel(p: &PredicateAst) -> u64 {
    match p {
        PredicateAst::ArithCmp { lhs, rhs, .. } => FUEL_COMPARE
            .saturating_add(arith_max_fuel(lhs))
            .saturating_add(arith_max_fuel(rhs)),
        PredicateAst::FieldGe { .. }
        | PredicateAst::FieldLe { .. }
        | PredicateAst::FieldEq { .. } => {
            // Two scope lookups + one comparison.
            FUEL_COMPARE.saturating_add(FUEL_FIELD_LOOKUP.saturating_mul(2))
        }
        PredicateAst::And(a, b) | PredicateAst::Or(a, b) => FUEL_BOOL_NODE
            .saturating_add(predicate_max_fuel(a))
            .saturating_add(predicate_max_fuel(b)),
        PredicateAst::Not(inner) => FUEL_BOOL_NODE.saturating_add(predicate_max_fuel(inner)),
        // Unenforceable shapes lower to a constant (and are rejected by
        // `predicate_is_enforceable` first); cost is negligible.
        PredicateAst::StrategyKNonDecreasing { .. }
        | PredicateAst::AllPoolsKNonDecreasing
        | PredicateAst::Opaque => FUEL_BOOL_NODE,
    }
}

fn arith_max_fuel(e: &ArithExpr) -> u64 {
    match e {
        ArithExpr::Field(_) => FUEL_FIELD_LOOKUP,
        ArithExpr::Literal(_) => FUEL_LITERAL,
        ArithExpr::Bounded { lhs, rhs, .. } => FUEL_ARITH_OP
            .saturating_add(arith_max_fuel(lhs))
            .saturating_add(arith_max_fuel(rhs)),
    }
}

/// Collect every scope-field name a predicate references (e.g.
/// `"after.reserve_a"`), in evaluation order, including duplicates.
/// Used by the deploy-time field-name gate so a predicate referencing a
/// field absent from its target's layout is rejected rather than silently
/// fail-open: in the guest a missing field lowers to `0`, and a `Not` over
/// it flips to a false `Satisfied` (the codegen has no tri-state).
pub fn collect_field_refs(p: &PredicateAst) -> Vec<&str> {
    let mut out = Vec::new();
    collect_pred_refs(p, &mut out);
    out
}

fn collect_pred_refs<'a>(p: &'a PredicateAst, out: &mut Vec<&'a str>) {
    match p {
        PredicateAst::ArithCmp { lhs, rhs, .. } => {
            collect_arith_refs(lhs, out);
            collect_arith_refs(rhs, out);
        }
        PredicateAst::FieldGe { lhs, rhs }
        | PredicateAst::FieldLe { lhs, rhs }
        | PredicateAst::FieldEq { lhs, rhs } => {
            out.push(lhs);
            out.push(rhs);
        }
        PredicateAst::And(a, b) | PredicateAst::Or(a, b) => {
            collect_pred_refs(a, out);
            collect_pred_refs(b, out);
        }
        PredicateAst::Not(inner) => collect_pred_refs(inner, out),
        PredicateAst::StrategyKNonDecreasing { .. }
        | PredicateAst::AllPoolsKNonDecreasing
        | PredicateAst::Opaque => {}
    }
}

fn collect_arith_refs<'a>(e: &'a ArithExpr, out: &mut Vec<&'a str>) {
    match e {
        ArithExpr::Field(name) => out.push(name),
        ArithExpr::Literal(_) => {}
        ArithExpr::Bounded { lhs, rhs, .. } => {
            collect_arith_refs(lhs, out);
            collect_arith_refs(rhs, out);
        }
    }
}

/// `true` iff `p` contains a `BoundedArithOp::Sub` anywhere in its arithmetic.
///
/// Subtraction is the one arithmetic node where the on-chain guest and this
/// trusted interpreter **disagree**: on underflow the guest's
/// [`BoundedArithOp::Sub`] lowering returns `None`, which the `ArithCmp`
/// codegen maps to `0` = **Violated** (fail-closed, it has no tri-state),
/// while this interpreter honours the macro's `OverflowPolicy::Indeterminate`
/// and returns [`EvalOutcome::Indeterminate`] = **no revert**. `Add`/`Mul`
/// never produce this split (overflow widens to `TooBig`, which both sides
/// resolve identically), and the field-name gate removes the analogous
/// missing-field divergence — but `Sub` underflow is value-dependent and
/// cannot be ruled out statically.
///
/// The differential gate (`pool_k_invariant`) only exercises `Mul`, so the
/// `Sub` divergence is unverified. Until the differential covers underflowing
/// `Sub` (and the two implementations are reconciled), deploy validation
/// rejects any predicate that uses it — see `validate_chain_wasm`.
pub fn predicate_uses_subtraction(p: &PredicateAst) -> bool {
    match p {
        PredicateAst::ArithCmp { lhs, rhs, .. } => arith_uses_sub(lhs) || arith_uses_sub(rhs),
        PredicateAst::And(a, b) | PredicateAst::Or(a, b) => {
            predicate_uses_subtraction(a) || predicate_uses_subtraction(b)
        }
        PredicateAst::Not(inner) => predicate_uses_subtraction(inner),
        PredicateAst::FieldGe { .. }
        | PredicateAst::FieldLe { .. }
        | PredicateAst::FieldEq { .. }
        | PredicateAst::StrategyKNonDecreasing { .. }
        | PredicateAst::AllPoolsKNonDecreasing
        | PredicateAst::Opaque => false,
    }
}

fn arith_uses_sub(e: &ArithExpr) -> bool {
    match e {
        ArithExpr::Field(_) | ArithExpr::Literal(_) => false,
        ArithExpr::Bounded { op, lhs, rhs, .. } => {
            matches!(op, BoundedArithOp::Sub) || arith_uses_sub(lhs) || arith_uses_sub(rhs)
        }
    }
}

/// Returns true for arithmetic shapes whose guest and reference semantics are
/// not part of the v1 equivalence contract.
///
/// The generated runtime can evaluate one non-nested bounded arithmetic node
/// over `u128` operands and compare it against a field/literal. That covers the
/// current pool invariant shape (`after.reserve_a * after.reserve_b >=
/// before.k_last`). Nested arithmetic and arithmetic on both sides can involve
/// two exact overflowing `U256` values; the current reference interpreter's
/// coarse overflow model is not equivalent for those cases, so deployment must
/// reject them until the interpreter is upgraded to exact `U256`.
pub fn predicate_uses_unsupported_arithmetic_shape(p: &PredicateAst) -> bool {
    match p {
        PredicateAst::ArithCmp { lhs, rhs, .. } => {
            arith_has_nested_bounded(lhs)
                || arith_has_nested_bounded(rhs)
                || (arith_has_bounded(lhs) && arith_has_bounded(rhs))
        }
        PredicateAst::And(a, b) | PredicateAst::Or(a, b) => {
            predicate_uses_unsupported_arithmetic_shape(a)
                || predicate_uses_unsupported_arithmetic_shape(b)
        }
        PredicateAst::Not(inner) => predicate_uses_unsupported_arithmetic_shape(inner),
        PredicateAst::FieldGe { .. }
        | PredicateAst::FieldLe { .. }
        | PredicateAst::FieldEq { .. }
        | PredicateAst::StrategyKNonDecreasing { .. }
        | PredicateAst::AllPoolsKNonDecreasing
        | PredicateAst::Opaque => false,
    }
}

fn arith_has_bounded(e: &ArithExpr) -> bool {
    match e {
        ArithExpr::Field(_) | ArithExpr::Literal(_) => false,
        ArithExpr::Bounded { .. } => true,
    }
}

fn arith_has_nested_bounded(e: &ArithExpr) -> bool {
    match e {
        ArithExpr::Field(_) | ArithExpr::Literal(_) => false,
        ArithExpr::Bounded { lhs, rhs, .. } => {
            arith_has_bounded(lhs)
                || arith_has_bounded(rhs)
                || arith_has_nested_bounded(lhs)
                || arith_has_nested_bounded(rhs)
        }
    }
}

// ---------------------------------------------------------------------------
// AST → English (ADR-001/003): a canonical, deterministic rendering of a
// predicate, so the machine predicate and its `human_text` claim can be
// compared by a human/tool. Pure; no consumer beyond tooling/arbitration.
// ---------------------------------------------------------------------------

/// Render `p` to a canonical English-ish string (e.g.
/// `"after.reserve_a × after.reserve_b ≥ before.k_last or not (after.lp_supply = before.lp_supply)"`).
pub fn render_predicate_english(p: &PredicateAst) -> String {
    match p {
        PredicateAst::ArithCmp { op, lhs, rhs } => {
            format!(
                "{} {} {}",
                render_arith(lhs),
                cmp_symbol(*op),
                render_arith(rhs)
            )
        }
        PredicateAst::FieldGe { lhs, rhs } => format!("{lhs} ≥ {rhs}"),
        PredicateAst::FieldLe { lhs, rhs } => format!("{lhs} ≤ {rhs}"),
        PredicateAst::FieldEq { lhs, rhs } => format!("{lhs} = {rhs}"),
        PredicateAst::And(a, b) => {
            format!(
                "({}) and ({})",
                render_predicate_english(a),
                render_predicate_english(b)
            )
        }
        PredicateAst::Or(a, b) => {
            format!(
                "({}) or ({})",
                render_predicate_english(a),
                render_predicate_english(b)
            )
        }
        PredicateAst::Not(inner) => format!("not ({})", render_predicate_english(inner)),
        PredicateAst::StrategyKNonDecreasing {
            strategy_param,
            pool_field,
        } => {
            format!("<unsupported: {strategy_param}::k(pool) ≥ {pool_field}>")
        }
        PredicateAst::AllPoolsKNonDecreasing => "<unsupported: all pools' k non-decreasing>".into(),
        PredicateAst::Opaque => "<unsupported: opaque predicate>".into(),
    }
}

fn render_arith(e: &ArithExpr) -> String {
    match e {
        ArithExpr::Field(name) => name.clone(),
        ArithExpr::Literal(v) => v.to_string(),
        ArithExpr::Bounded { op, lhs, rhs, .. } => {
            format!(
                "({} {} {})",
                render_arith(lhs),
                arith_symbol(*op),
                render_arith(rhs)
            )
        }
    }
}

fn cmp_symbol(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Ge => "≥",
        CmpOp::Le => "≤",
        CmpOp::Eq => "=",
    }
}

fn arith_symbol(op: BoundedArithOp) -> &'static str {
    match op {
        BoundedArithOp::Add => "+",
        BoundedArithOp::Sub => "−",
        BoundedArithOp::Mul => "×",
    }
}

// ---------------------------------------------------------------------------
// Vacuity / tautology detection (ADR-003 intent-conformance, the
// fully-automatable slice). A predicate that is statically always-true or
// always-false enforces nothing — it cannot match any real human intent — so
// it is rejected at deploy. Conservative: only structurally-decidable cases;
// anything uncertain returns `None`.
// ---------------------------------------------------------------------------

/// A predicate that holds (or fails) regardless of input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Triviality {
    /// Always satisfied (e.g. `x >= x`, `P || !P`).
    AlwaysTrue,
    /// Always violated (e.g. `P && !P`, `2 <= 1`).
    AlwaysFalse,
}

/// Statically decide whether `p` is vacuous. `None` = not provably trivial.
pub fn predicate_triviality(p: &PredicateAst) -> Option<Triviality> {
    use Triviality::*;
    match p {
        // Self-comparison: `x ≥ x` / `x ≤ x` / `x = x` always hold.
        PredicateAst::FieldGe { lhs, rhs }
        | PredicateAst::FieldLe { lhs, rhs }
        | PredicateAst::FieldEq { lhs, rhs }
            if lhs == rhs =>
        {
            Some(AlwaysTrue)
        }
        PredicateAst::ArithCmp { op, lhs, rhs } => {
            if lhs == rhs {
                // `e ≥ e` / `e ≤ e` / `e = e` (assuming `e` is decidable, which
                // the field-name + enforceability gates already require).
                return Some(AlwaysTrue);
            }
            // Constant-folded comparison of two literals.
            if let (ArithExpr::Literal(a), ArithExpr::Literal(b)) = (lhs, rhs) {
                let holds = match op {
                    CmpOp::Ge => a >= b,
                    CmpOp::Le => a <= b,
                    CmpOp::Eq => a == b,
                };
                return Some(if holds { AlwaysTrue } else { AlwaysFalse });
            }
            None
        }
        PredicateAst::And(a, b) => {
            if is_negation(a, b) {
                return Some(AlwaysFalse); // P && !P
            }
            match (predicate_triviality(a), predicate_triviality(b)) {
                (Some(AlwaysFalse), _) | (_, Some(AlwaysFalse)) => Some(AlwaysFalse),
                (Some(AlwaysTrue), Some(AlwaysTrue)) => Some(AlwaysTrue),
                _ => None,
            }
        }
        PredicateAst::Or(a, b) => {
            if is_negation(a, b) {
                return Some(AlwaysTrue); // P || !P
            }
            match (predicate_triviality(a), predicate_triviality(b)) {
                (Some(AlwaysTrue), _) | (_, Some(AlwaysTrue)) => Some(AlwaysTrue),
                (Some(AlwaysFalse), Some(AlwaysFalse)) => Some(AlwaysFalse),
                _ => None,
            }
        }
        PredicateAst::Not(inner) => predicate_triviality(inner).map(|t| match t {
            AlwaysTrue => AlwaysFalse,
            AlwaysFalse => AlwaysTrue,
        }),
        _ => None,
    }
}

/// `true` iff one of `p`/`q` is the boolean negation of the other.
///
/// Conservative: detects direct `P`/`Not(P)` pairs and one level of
/// inversion (`Not(Not(P))` / `Not(P)`) via the `inner == q` structural
/// equality check. Deeper nesting (e.g. `Not(Not(Not(P)))` / `Not(P)`) is
/// not detected; that is safe conservatism — `predicate_triviality` only
/// needs *decidable* cases; uncertain cases return `None`.
fn is_negation(p: &PredicateAst, q: &PredicateAst) -> bool {
    matches!(p, PredicateAst::Not(inner) if inner.as_ref() == q)
        || matches!(q, PredicateAst::Not(inner) if inner.as_ref() == p)
}

/// Evaluate `p` against the encoded `scope`.
pub fn interpret_predicate(p: &PredicateAst, scope: &[u8]) -> EvalOutcome {
    match p {
        PredicateAst::ArithCmp { op, lhs, rhs } => {
            match (eval_arith(lhs, scope), eval_arith(rhs, scope)) {
                (Some(l), Some(r)) => bool_outcome(compare(*op, l, r)),
                _ => EvalOutcome::Indeterminate,
            }
        }
        PredicateAst::FieldGe { lhs, rhs } => field_cmp(CmpOp::Ge, lhs, rhs, scope),
        PredicateAst::FieldLe { lhs, rhs } => field_cmp(CmpOp::Le, lhs, rhs, scope),
        PredicateAst::FieldEq { lhs, rhs } => field_cmp(CmpOp::Eq, lhs, rhs, scope),
        // Boolean composition over the three-valued outcome (Kleene logic):
        // `&&` is Violated if either side is; `||` is Satisfied if either is;
        // an undecided operand only matters when it could change the result.
        PredicateAst::And(a, b) => {
            and_outcome(interpret_predicate(a, scope), interpret_predicate(b, scope))
        }
        PredicateAst::Or(a, b) => {
            or_outcome(interpret_predicate(a, scope), interpret_predicate(b, scope))
        }
        PredicateAst::Not(inner) => not_outcome(interpret_predicate(inner, scope)),
        // Shapes the flat field-table interpreter does not model in v1.
        PredicateAst::StrategyKNonDecreasing { .. }
        | PredicateAst::AllPoolsKNonDecreasing
        | PredicateAst::Opaque => EvalOutcome::Indeterminate,
    }
}

fn and_outcome(a: EvalOutcome, b: EvalOutcome) -> EvalOutcome {
    use EvalOutcome::*;
    match (a, b) {
        (Violated, _) | (_, Violated) => Violated,
        (Satisfied, Satisfied) => Satisfied,
        _ => Indeterminate,
    }
}

fn or_outcome(a: EvalOutcome, b: EvalOutcome) -> EvalOutcome {
    use EvalOutcome::*;
    match (a, b) {
        (Satisfied, _) | (_, Satisfied) => Satisfied,
        (Violated, Violated) => Violated,
        _ => Indeterminate,
    }
}

fn not_outcome(a: EvalOutcome) -> EvalOutcome {
    match a {
        EvalOutcome::Satisfied => EvalOutcome::Violated,
        EvalOutcome::Violated => EvalOutcome::Satisfied,
        EvalOutcome::Indeterminate => EvalOutcome::Indeterminate,
    }
}

fn field_cmp(op: CmpOp, lhs: &str, rhs: &str, scope: &[u8]) -> EvalOutcome {
    match (lookup_field(scope, lhs), lookup_field(scope, rhs)) {
        (Some(l), Some(r)) => bool_outcome(compare(op, AVal::Num(l), AVal::Num(r))),
        _ => EvalOutcome::Indeterminate,
    }
}

fn bool_outcome(b: bool) -> EvalOutcome {
    if b {
        EvalOutcome::Satisfied
    } else {
        EvalOutcome::Violated
    }
}

fn compare(op: CmpOp, l: AVal, r: AVal) -> bool {
    use AVal::*;
    match (l, r) {
        (Num(a), Num(b)) => match op {
            CmpOp::Ge => a >= b,
            CmpOp::Le => a <= b,
            CmpOp::Eq => a == b,
        },
        // A finite value above u128::MAX vs a u128.
        (TooBig, Num(_)) => matches!(op, CmpOp::Ge),
        (Num(_), TooBig) => matches!(op, CmpOp::Le),
        (TooBig, TooBig) => matches!(op, CmpOp::Ge | CmpOp::Le),
    }
}

/// Evaluate an arithmetic expression; `None` ⇒ indeterminate.
fn eval_arith(e: &ArithExpr, scope: &[u8]) -> Option<AVal> {
    match e {
        ArithExpr::Field(name) => lookup_field(scope, name).map(AVal::Num),
        ArithExpr::Literal(v) => Some(AVal::Num(*v)),
        ArithExpr::Bounded {
            op,
            lhs,
            rhs,
            on_overflow,
            ..
        } => {
            let l = eval_arith(lhs, scope)?;
            let r = eval_arith(rhs, scope)?;
            combine(*op, l, r, *on_overflow)
        }
    }
}

fn combine(op: BoundedArithOp, l: AVal, r: AVal, on_overflow: OverflowPolicy) -> Option<AVal> {
    use AVal::*;
    // `on_overflow` only governs a step that exceeds its domain. Add/Mul
    // that exceed `u128` map to `TooBig` (a finite value above any `u128`),
    // verdict-equivalent to saturating-to-max for the comparisons we model
    // and never indeterminate; only `Sub` underflow consults the policy.
    //
    // NOTE: the `#[invariant]` macro currently always lowers to
    // `OverflowPolicy::Indeterminate` (see `arith_expr_of` in
    // `bloom-resource-macros`), so the `Saturate` arms below are not
    // reachable in practice; they are kept correct (saturating `Sub`
    // underflow floors to 0, not `TooBig`) so the interpreter stays a sound
    // oracle if `Saturate` is ever wired through codegen.
    //
    // The `Sub`-underflow `Indeterminate` result here diverges from the
    // two-valued guest (which fails closed to Violated); that divergence is
    // unverified by the differential gate, so `Sub` predicates are rejected
    // at deploy (`predicate_uses_subtraction` → `validate_chain_wasm`).
    match (op, l, r) {
        (BoundedArithOp::Add, Num(a), Num(b)) => Some(a.checked_add(b).map_or(TooBig, Num)),
        (BoundedArithOp::Mul, Num(a), Num(b)) => Some(a.checked_mul(b).map_or(TooBig, Num)),
        (BoundedArithOp::Sub, Num(a), Num(b)) => match a.checked_sub(b) {
            Some(v) => Some(Num(v)),
            // Underflow: Indeterminate can't decide; Saturate floors to 0.
            None => match on_overflow {
                OverflowPolicy::Indeterminate => None,
                OverflowPolicy::Saturate => Some(Num(0)),
            },
        },
        // Any TooBig operand: addition/multiplication stays TooBig;
        // subtraction can't be resolved without a wider type.
        (BoundedArithOp::Add | BoundedArithOp::Mul, TooBig, _)
        | (BoundedArithOp::Add | BoundedArithOp::Mul, _, TooBig) => Some(TooBig),
        (BoundedArithOp::Sub, _, _) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Widening;
    use bloom_script::invariant_scope::{SCOPE_KIND_OBJECT_TYPE, build_invariant_scope};

    fn pool_k_predicate() -> PredicateAst {
        PredicateAst::ArithCmp {
            op: CmpOp::Ge,
            lhs: ArithExpr::Bounded {
                op: BoundedArithOp::Mul,
                lhs: Box::new(ArithExpr::Field("after.reserve_a".into())),
                rhs: Box::new(ArithExpr::Field("after.reserve_b".into())),
                widening: Widening::U256,
                on_overflow: OverflowPolicy::Indeterminate,
            },
            rhs: ArithExpr::Field("before.k_last".into()),
        }
    }

    fn scope(ra: u128, rb: u128, k_before: u128) -> Vec<u8> {
        build_invariant_scope(
            SCOPE_KIND_OBJECT_TYPE,
            "Pool",
            0,
            &[
                ("after.reserve_a".into(), ra),
                ("after.reserve_b".into(), rb),
                ("before.k_last".into(), k_before),
            ],
        )
        .unwrap()
    }

    #[test]
    fn pool_k_satisfied_when_product_holds() {
        let p = pool_k_predicate();
        // 1100 * 910 = 1_001_000 >= 1_000_000 (k grew via fee).
        assert_eq!(
            interpret_predicate(&p, &scope(1100, 910, 1_000_000)),
            EvalOutcome::Satisfied
        );
    }

    #[test]
    fn pool_k_violated_when_product_drops() {
        let p = pool_k_predicate();
        // 900 * 900 = 810_000 < 1_000_000.
        assert_eq!(
            interpret_predicate(&p, &scope(900, 900, 1_000_000)),
            EvalOutcome::Violated
        );
    }

    #[test]
    fn pool_k_holds_without_overflow_at_extremes() {
        let p = pool_k_predicate();
        // u128::MAX * u128::MAX is a 256-bit product; must not overflow or
        // be mis-decided. It dwarfs any u128 k_last.
        assert_eq!(
            interpret_predicate(&p, &scope(u128::MAX, u128::MAX, u128::MAX)),
            EvalOutcome::Satisfied
        );
    }

    #[test]
    fn field_ge_resolves_only_with_qualified_before_after_names() {
        // Qualified names match the scope keys → decidable.
        let q = PredicateAst::FieldGe {
            lhs: "after.reserve_a".into(),
            rhs: "before.k_last".into(),
        };
        assert_eq!(
            interpret_predicate(&q, &scope(1500, 1, 1000)),
            EvalOutcome::Satisfied
        );
        assert_eq!(
            interpret_predicate(&q, &scope(10, 1, 1000)),
            EvalOutcome::Violated
        );
        // Unqualified names (the old footgun) never resolve → fail closed.
        let unq = PredicateAst::FieldGe {
            lhs: "reserve_a".into(),
            rhs: "k_last".into(),
        };
        assert_eq!(
            interpret_predicate(&unq, &scope(1500, 1, 1000)),
            EvalOutcome::Indeterminate
        );
    }

    #[test]
    fn boolean_composition_evaluates_and_is_enforceable() {
        // pool_k corrected form: k non-decreasing OR (lp_supply changed).
        let k_ge = PredicateAst::ArithCmp {
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
        let lp_changed = PredicateAst::Not(Box::new(PredicateAst::FieldEq {
            lhs: "after.lp_supply".into(),
            rhs: "before.lp_supply".into(),
        }));
        let pred = PredicateAst::Or(Box::new(k_ge), Box::new(lp_changed));

        let scope = |ra: u128, rb: u128, k: u128, lp_before: u128, lp_after: u128| {
            build_invariant_scope(
                SCOPE_KIND_OBJECT_TYPE,
                "Pool",
                0,
                &[
                    ("after.reserve_a".into(), ra),
                    ("after.reserve_b".into(), rb),
                    ("before.k_last".into(), k),
                    ("before.lp_supply".into(), lp_before),
                    ("after.lp_supply".into(), lp_after),
                ],
            )
            .unwrap()
        };
        // Valid swap: k grew, lp unchanged -> Satisfied (left disjunct).
        assert_eq!(
            interpret_predicate(&pred, &scope(1100, 910, 1_000_000, 5, 5)),
            EvalOutcome::Satisfied
        );
        // remove_liquidity: k dropped, lp changed -> Satisfied (right disjunct).
        assert_eq!(
            interpret_predicate(&pred, &scope(900, 900, 1_000_000, 5, 3)),
            EvalOutcome::Satisfied
        );
        // Malicious swap: k dropped, lp unchanged -> Violated (both false).
        assert_eq!(
            interpret_predicate(&pred, &scope(900, 900, 1_000_000, 5, 5)),
            EvalOutcome::Violated
        );

        // Enforceability is recursive: all leaves enforceable -> composite is.
        assert!(predicate_is_enforceable(&pred));
        // A composite containing a no-op leaf is rejected.
        assert!(!predicate_is_enforceable(&PredicateAst::And(
            Box::new(PredicateAst::AllPoolsKNonDecreasing),
            Box::new(PredicateAst::Opaque),
        )));
    }

    #[test]
    fn detects_subtraction_anywhere_in_predicate() {
        // Mul-only predicate (real pool_k) uses no subtraction.
        assert!(!predicate_uses_subtraction(&pool_k_predicate()));
        // A Sub nested inside an Or / Not / Bounded is detected.
        let sub = PredicateAst::ArithCmp {
            op: CmpOp::Ge,
            lhs: ArithExpr::Bounded {
                op: BoundedArithOp::Sub,
                lhs: Box::new(ArithExpr::Field("after.x".into())),
                rhs: Box::new(ArithExpr::Field("before.x".into())),
                widening: Widening::U256,
                on_overflow: OverflowPolicy::Indeterminate,
            },
            rhs: ArithExpr::Literal(0),
        };
        assert!(predicate_uses_subtraction(&sub));
        assert!(predicate_uses_subtraction(&PredicateAst::Or(
            Box::new(pool_k_predicate()),
            Box::new(PredicateAst::Not(Box::new(sub))),
        )));
    }

    #[test]
    fn detects_unsupported_arithmetic_shapes() {
        let product = ArithExpr::Bounded {
            op: BoundedArithOp::Mul,
            lhs: Box::new(ArithExpr::Field("after.a".into())),
            rhs: Box::new(ArithExpr::Field("after.b".into())),
            widening: Widening::U256,
            on_overflow: OverflowPolicy::Indeterminate,
        };
        let supported = PredicateAst::ArithCmp {
            op: CmpOp::Ge,
            lhs: product.clone(),
            rhs: ArithExpr::Field("before.k".into()),
        };
        assert!(!predicate_uses_unsupported_arithmetic_shape(&supported));

        let product_vs_product = PredicateAst::ArithCmp {
            op: CmpOp::Le,
            lhs: product.clone(),
            rhs: product.clone(),
        };
        assert!(predicate_uses_unsupported_arithmetic_shape(
            &product_vs_product
        ));

        let nested = PredicateAst::ArithCmp {
            op: CmpOp::Ge,
            lhs: ArithExpr::Bounded {
                op: BoundedArithOp::Mul,
                lhs: Box::new(product),
                rhs: Box::new(ArithExpr::Field("after.c".into())),
                widening: Widening::U256,
                on_overflow: OverflowPolicy::Indeterminate,
            },
            rhs: ArithExpr::Literal(0),
        };
        assert!(predicate_uses_unsupported_arithmetic_shape(&nested));
    }

    #[test]
    fn missing_field_is_indeterminate() {
        let p = pool_k_predicate();
        let s = build_invariant_scope(SCOPE_KIND_OBJECT_TYPE, "Pool", 0, &[]).unwrap();
        assert_eq!(interpret_predicate(&p, &s), EvalOutcome::Indeterminate);
    }

    #[test]
    fn renders_pool_k_predicate_to_english() {
        // The real pool_k shape, with the boolean liquidity-event exemption.
        let pred = PredicateAst::Or(
            Box::new(pool_k_predicate()),
            Box::new(PredicateAst::Not(Box::new(PredicateAst::FieldEq {
                lhs: "after.lp_supply".into(),
                rhs: "before.lp_supply".into(),
            }))),
        );
        assert_eq!(
            render_predicate_english(&pred),
            "((after.reserve_a × after.reserve_b) ≥ before.k_last) \
             or (not (after.lp_supply = before.lp_supply))"
        );
        // Cap shape: `after.revoked >= before.revoked && after.inner_kind <= 2`.
        let cap = PredicateAst::And(
            Box::new(PredicateAst::FieldGe {
                lhs: "after.revoked".into(),
                rhs: "before.revoked".into(),
            }),
            Box::new(PredicateAst::ArithCmp {
                op: CmpOp::Le,
                lhs: ArithExpr::Field("after.inner_kind".into()),
                rhs: ArithExpr::Literal(2),
            }),
        );
        assert_eq!(
            render_predicate_english(&cap),
            "(after.revoked ≥ before.revoked) and (after.inner_kind ≤ 2)"
        );
    }

    #[test]
    fn vacuity_detector_flags_trivial_predicates() {
        use Triviality::*;
        // Self-comparisons.
        assert_eq!(
            predicate_triviality(&PredicateAst::FieldGe {
                lhs: "after.x".into(),
                rhs: "after.x".into(),
            }),
            Some(AlwaysTrue)
        );
        // P || !P  and  P && !P.
        let p = PredicateAst::FieldGe {
            lhs: "after.x".into(),
            rhs: "before.x".into(),
        };
        assert_eq!(
            predicate_triviality(&PredicateAst::Or(
                Box::new(p.clone()),
                Box::new(PredicateAst::Not(Box::new(p.clone())))
            )),
            Some(AlwaysTrue)
        );
        assert_eq!(
            predicate_triviality(&PredicateAst::And(
                Box::new(p.clone()),
                Box::new(PredicateAst::Not(Box::new(p.clone())))
            )),
            Some(AlwaysFalse)
        );
        // Constant contradiction `2 <= 1`.
        assert_eq!(
            predicate_triviality(&PredicateAst::ArithCmp {
                op: CmpOp::Le,
                lhs: ArithExpr::Literal(2),
                rhs: ArithExpr::Literal(1),
            }),
            Some(AlwaysFalse)
        );
        // The real pool_k predicate is NOT trivial.
        assert_eq!(predicate_triviality(&pool_k_predicate()), None);
    }
}
