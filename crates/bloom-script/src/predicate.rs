//! Runtime predicate AST and trusted host-side interpreter for invariant
//! enforcement.
//!
//! The manifest's `__inv_*` wasm exports are developer/tooling artifacts. A
//! hand-written or tampered petal can make those exports return any byte, so
//! the executor must enforce the manifest predicate itself over the canonical
//! invariant scope buffer.

use crate::invariant_scope::lookup_field;

/// Tri-state result of evaluating a manifest predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredicateEvalOutcome {
    /// Predicate holds.
    Satisfied,
    /// Predicate is violated.
    Violated,
    /// Predicate could not be decided from the supplied scope.
    Indeterminate,
}

/// Runtime copy of the manifest predicate AST.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PredicateAstStub {
    /// `lhs >= rhs` comparison over named fields.
    FieldGe {
        /// Left-hand field name.
        lhs: String,
        /// Right-hand field name.
        rhs: String,
    },
    /// `lhs <= rhs` comparison over named fields.
    FieldLe {
        /// Left-hand field name.
        lhs: String,
        /// Right-hand field name.
        rhs: String,
    },
    /// `lhs == rhs` comparison over named fields.
    FieldEq {
        /// Left-hand field name.
        lhs: String,
        /// Right-hand field name.
        rhs: String,
    },
    /// Pool-style strategy predicate unsupported by the v1 flat interpreter.
    StrategyKNonDecreasing {
        /// Generic strategy parameter name.
        strategy_param: String,
        /// Pool field that stores the prior `k` value.
        pool_field: String,
    },
    /// Router-style aggregate predicate unsupported by the v1 flat interpreter.
    AllPoolsKNonDecreasing,
    /// Bounded-arithmetic comparison over scope fields and literals.
    ArithCmp {
        /// Comparison operator.
        op: CmpOpStub,
        /// Left-hand arithmetic expression.
        lhs: ArithExprStub,
        /// Right-hand arithmetic expression.
        rhs: ArithExprStub,
    },
    /// Boolean conjunction.
    And(Box<PredicateAstStub>, Box<PredicateAstStub>),
    /// Boolean disjunction.
    Or(Box<PredicateAstStub>, Box<PredicateAstStub>),
    /// Boolean negation.
    Not(Box<PredicateAstStub>),
    /// Unsupported or absent predicate.
    #[default]
    Opaque,
}

/// Comparison operator for [`PredicateAstStub::ArithCmp`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOpStub {
    /// `>=`
    Ge,
    /// `<=`
    Le,
    /// `==`
    Eq,
}

/// Checked arithmetic operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedArithOpStub {
    /// Checked addition.
    Add,
    /// Checked subtraction.
    Sub,
    /// Checked multiplication.
    Mul,
}

/// Intermediate widening domain for bounded arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WideningStub {
    /// Stay in `u128`.
    None,
    /// Widen intermediates to 256 bits.
    U256,
    /// Widen intermediates to 512 bits.
    U512,
}

/// Overflow behavior for bounded arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverflowPolicyStub {
    /// Overflow makes the predicate indeterminate.
    Indeterminate,
    /// Overflow saturates at the domain maximum.
    Saturate,
}

/// Arithmetic expression over scope fields and literals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArithExprStub {
    /// Reference to a named scope field.
    Field(String),
    /// Literal `u128`.
    Literal(u128),
    /// Bounded binary arithmetic expression.
    Bounded {
        /// Arithmetic operation.
        op: BoundedArithOpStub,
        /// Left operand.
        lhs: Box<ArithExprStub>,
        /// Right operand.
        rhs: Box<ArithExprStub>,
        /// Intermediate widening domain.
        widening: WideningStub,
        /// Overflow behavior.
        on_overflow: OverflowPolicyStub,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AVal {
    Num(u128),
    TooBig,
}

/// Interpret a predicate over a canonical invariant scope buffer.
pub fn interpret_predicate(p: &PredicateAstStub, scope: &[u8]) -> PredicateEvalOutcome {
    match p {
        PredicateAstStub::ArithCmp { op, lhs, rhs } => {
            match (eval_arith(lhs, scope), eval_arith(rhs, scope)) {
                (Some(l), Some(r)) => bool_outcome(compare(*op, l, r)),
                _ => PredicateEvalOutcome::Indeterminate,
            }
        }
        PredicateAstStub::FieldGe { lhs, rhs } => field_cmp(CmpOpStub::Ge, lhs, rhs, scope),
        PredicateAstStub::FieldLe { lhs, rhs } => field_cmp(CmpOpStub::Le, lhs, rhs, scope),
        PredicateAstStub::FieldEq { lhs, rhs } => field_cmp(CmpOpStub::Eq, lhs, rhs, scope),
        PredicateAstStub::And(a, b) => {
            and_outcome(interpret_predicate(a, scope), interpret_predicate(b, scope))
        }
        PredicateAstStub::Or(a, b) => {
            or_outcome(interpret_predicate(a, scope), interpret_predicate(b, scope))
        }
        PredicateAstStub::Not(inner) => not_outcome(interpret_predicate(inner, scope)),
        PredicateAstStub::StrategyKNonDecreasing { .. }
        | PredicateAstStub::AllPoolsKNonDecreasing
        | PredicateAstStub::Opaque => PredicateEvalOutcome::Indeterminate,
    }
}

fn and_outcome(a: PredicateEvalOutcome, b: PredicateEvalOutcome) -> PredicateEvalOutcome {
    use PredicateEvalOutcome::*;
    match (a, b) {
        (Violated, _) | (_, Violated) => Violated,
        (Satisfied, Satisfied) => Satisfied,
        _ => Indeterminate,
    }
}

fn or_outcome(a: PredicateEvalOutcome, b: PredicateEvalOutcome) -> PredicateEvalOutcome {
    use PredicateEvalOutcome::*;
    match (a, b) {
        (Satisfied, _) | (_, Satisfied) => Satisfied,
        (Violated, Violated) => Violated,
        _ => Indeterminate,
    }
}

fn not_outcome(a: PredicateEvalOutcome) -> PredicateEvalOutcome {
    match a {
        PredicateEvalOutcome::Satisfied => PredicateEvalOutcome::Violated,
        PredicateEvalOutcome::Violated => PredicateEvalOutcome::Satisfied,
        PredicateEvalOutcome::Indeterminate => PredicateEvalOutcome::Indeterminate,
    }
}

fn field_cmp(op: CmpOpStub, lhs: &str, rhs: &str, scope: &[u8]) -> PredicateEvalOutcome {
    match (lookup_field(scope, lhs), lookup_field(scope, rhs)) {
        (Some(l), Some(r)) => bool_outcome(compare(op, AVal::Num(l), AVal::Num(r))),
        _ => PredicateEvalOutcome::Indeterminate,
    }
}

fn bool_outcome(b: bool) -> PredicateEvalOutcome {
    if b {
        PredicateEvalOutcome::Satisfied
    } else {
        PredicateEvalOutcome::Violated
    }
}

fn compare(op: CmpOpStub, l: AVal, r: AVal) -> bool {
    use AVal::*;
    match (l, r) {
        (Num(a), Num(b)) => match op {
            CmpOpStub::Ge => a >= b,
            CmpOpStub::Le => a <= b,
            CmpOpStub::Eq => a == b,
        },
        (TooBig, Num(_)) => matches!(op, CmpOpStub::Ge),
        (Num(_), TooBig) => matches!(op, CmpOpStub::Le),
        (TooBig, TooBig) => matches!(op, CmpOpStub::Ge | CmpOpStub::Le),
    }
}

fn eval_arith(e: &ArithExprStub, scope: &[u8]) -> Option<AVal> {
    match e {
        ArithExprStub::Field(name) => lookup_field(scope, name).map(AVal::Num),
        ArithExprStub::Literal(v) => Some(AVal::Num(*v)),
        ArithExprStub::Bounded {
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

fn combine(
    op: BoundedArithOpStub,
    l: AVal,
    r: AVal,
    on_overflow: OverflowPolicyStub,
) -> Option<AVal> {
    use AVal::*;
    match (op, l, r) {
        (BoundedArithOpStub::Add, Num(a), Num(b)) => Some(a.checked_add(b).map_or(TooBig, Num)),
        (BoundedArithOpStub::Mul, Num(a), Num(b)) => Some(a.checked_mul(b).map_or(TooBig, Num)),
        (BoundedArithOpStub::Sub, Num(a), Num(b)) => match a.checked_sub(b) {
            Some(v) => Some(Num(v)),
            None => match on_overflow {
                OverflowPolicyStub::Indeterminate => None,
                OverflowPolicyStub::Saturate => Some(Num(0)),
            },
        },
        (BoundedArithOpStub::Add | BoundedArithOpStub::Mul, TooBig, _)
        | (BoundedArithOpStub::Add | BoundedArithOpStub::Mul, _, TooBig) => Some(TooBig),
        (BoundedArithOpStub::Sub, _, _) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariant_scope::{SCOPE_KIND_OBJECT_TYPE, build_invariant_scope};

    fn scope(fields: &[(&str, u128)]) -> Vec<u8> {
        build_invariant_scope(
            SCOPE_KIND_OBJECT_TYPE,
            "Coin",
            0,
            &fields
                .iter()
                .map(|(name, value)| (name.to_string(), *value))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn field_comparisons_are_interpreted() {
        let p = PredicateAstStub::FieldGe {
            lhs: "after.value".to_string(),
            rhs: "before.value".to_string(),
        };
        assert_eq!(
            interpret_predicate(&p, &scope(&[("before.value", 10), ("after.value", 12)])),
            PredicateEvalOutcome::Satisfied
        );
        assert_eq!(
            interpret_predicate(&p, &scope(&[("before.value", 10), ("after.value", 7)])),
            PredicateEvalOutcome::Violated
        );
    }
}
