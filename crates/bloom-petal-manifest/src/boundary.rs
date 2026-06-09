//! Boundary test generation for ADR-003 Tier 1a spec↔intent conformance.
//!
//! Generates a deterministic corpus of scope inputs (boundary values +
//! randomized sweep) and evaluates the predicate against each. A predicate
//! that returns the same outcome across the entire corpus is **semantically
//! vacuous** — it enforces nothing independent of field domains — and is
//! rejected.
//!
//! This extends the structural triviality check (`predicate_triviality`,
//! gate E) which catches non-domain-aware cases like `x >= x` and `P && !P`.
//! The boundary gate catches cases like `after.x >= 0` on a `u128` field —
//! structurally non-trivial but always true because every `u128` is ≥ 0.

use std::collections::{HashMap, HashSet};

use bloom_script::invariant_scope::{SCOPE_KIND_OBJECT_TYPE, build_invariant_scope};

use crate::interpret::{EvalOutcome, collect_field_refs, interpret_predicate};
use crate::types::PredicateAst;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Tuning knobs for the boundary check.
pub struct BoundaryConfig {
    /// Number of randomized test cases (default: 2000).
    pub random_cases: u32,
    /// PRNG seed for reproducibility across validators.
    pub seed: u64,
}

impl Default for BoundaryConfig {
    fn default() -> Self {
        Self {
            random_cases: 2000,
            seed: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// Outcome summary from a successful [`boundary_check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryReport {
    /// Total test cases evaluated.
    pub total_cases: u32,
    /// Predicate held.
    pub satisfied: u32,
    /// Predicate was violated.
    pub violated: u32,
    /// Could not be decided (missing field / overflow etc.).
    pub indeterminate: u32,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Reasons a boundary check may fail (fail-closed).
#[derive(Debug)]
pub enum BoundaryError {
    /// Predicate returned the same outcome for every test case — it enforces
    /// nothing across the field domains.
    SemanticallyVacuous {
        /// Invariant name.
        inv_name: String,
        /// `true` for always-satisfied, `false` for always-violated.
        always_true: bool,
        /// How many cases were tested.
        total_cases: u32,
    },
    /// Predicate could not be decided for *any* test case. An indeterminate
    /// verdict never reverts at runtime (ADR-002), so a predicate that is
    /// indeterminate across its whole domain enforces nothing — reject it
    /// rather than deploy a check that can never fire.
    AlwaysIndeterminate {
        /// Invariant name.
        inv_name: String,
        /// How many cases were tested.
        total_cases: u32,
    },
    /// A field referenced in the predicate is not in the supplied field-domain
    /// map (caller bug).
    MissingFieldDomain {
        /// Unresolvable field.
        field: String,
    },
}

impl std::fmt::Display for BoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundaryError::SemanticallyVacuous {
                inv_name,
                always_true,
                total_cases,
            } => {
                let outcome = if *always_true {
                    "satisfied"
                } else {
                    "violated"
                };
                write!(
                    f,
                    "invariant '{inv_name}' is semantically vacuous — it is always {outcome} \
                     across {total_cases} boundary + randomized test cases; \
                     rewrite the predicate so it depends on at least one field's value"
                )
            }
            BoundaryError::AlwaysIndeterminate {
                inv_name,
                total_cases,
            } => {
                write!(
                    f,
                    "invariant '{inv_name}' is indeterminate across all {total_cases} boundary + \
                     randomized test cases — it can never produce a verdict (and so never \
                     reverts); rewrite the predicate so it decides over its field domains"
                )
            }
            BoundaryError::MissingFieldDomain { field } => {
                write!(
                    f,
                    "field '{field}' referenced in predicate but not in field-width map"
                )
            }
        }
    }
}

impl std::error::Error for BoundaryError {}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the boundary gate for one predicate.
///
/// `field_widths` maps a **bare** field name (e.g. `"reserve_a"`) to its
/// bit-width (e.g. `128` for a `u128` field; `8` for a `u8`). These are
/// usually derived from an [`ObjectTypeDecl`](crate::types::ObjectTypeDecl).
pub fn boundary_check(
    predicate: &PredicateAst,
    inv_name: &str,
    target_name: &str,
    field_widths: &HashMap<String, u8>,
    config: &BoundaryConfig,
) -> Result<BoundaryReport, BoundaryError> {
    let refs = unique_field_refs(predicate);
    if refs.is_empty() {
        return Ok(BoundaryReport {
            total_cases: 0,
            satisfied: 0,
            violated: 0,
            indeterminate: 0,
        });
    }

    for r in &refs {
        let bare = strip_prefix(r);
        if !field_widths.contains_key(bare) {
            return Err(BoundaryError::MissingFieldDomain {
                field: bare.to_string(),
            });
        }
    }

    let mut report = BoundaryReport {
        total_cases: 0,
        satisfied: 0,
        violated: 0,
        indeterminate: 0,
    };
    let mut rng = SplitMix64(config.seed);

    // ── boundary sweep ──────────────────────────────────────────────
    boundary_cases(&refs, target_name, field_widths, predicate, &mut report);

    // ── randomized sweep ────────────────────────────────────────────
    for _ in 0..config.random_cases {
        let assignments: Vec<(String, u128)> = refs
            .iter()
            .map(|r| {
                let bare = strip_prefix(r);
                let bits = field_widths[bare];
                let max = domain_max(bits);
                let val = rng.next_u128_varwidth().min(max);
                (r.clone(), val)
            })
            .collect();
        evaluate_one(&assignments, target_name, predicate, &mut report);
    }

    // ── gate ────────────────────────────────────────────────────────
    if report.satisfied > 0 && report.violated == 0 {
        return Err(BoundaryError::SemanticallyVacuous {
            inv_name: inv_name.to_string(),
            always_true: true,
            total_cases: report.total_cases,
        });
    }
    if report.satisfied == 0 && report.violated > 0 {
        return Err(BoundaryError::SemanticallyVacuous {
            inv_name: inv_name.to_string(),
            always_true: false,
            total_cases: report.total_cases,
        });
    }
    // Never decided either way: indeterminate does not revert, so this check
    // can never fire. Fail closed (the field-ref + enforceability gates make
    // this hard to reach, but a `Sub`-underflowing predicate could).
    if report.satisfied == 0 && report.violated == 0 {
        return Err(BoundaryError::AlwaysIndeterminate {
            inv_name: inv_name.to_string(),
            total_cases: report.total_cases,
        });
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unique_field_refs(p: &PredicateAst) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for r in collect_field_refs(p) {
        if seen.insert(r.to_string()) {
            out.push(r.to_string());
        }
    }
    out
}

fn strip_prefix(field_ref: &str) -> &str {
    if let Some(s) = field_ref.strip_prefix("after.") {
        s
    } else if let Some(s) = field_ref.strip_prefix("before.") {
        s
    } else {
        field_ref
    }
}

fn domain_max(bits: u8) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else if bits == 0 {
        0
    } else {
        (1u128 << bits) - 1
    }
}

fn boundary_cases(
    refs: &[String],
    target_name: &str,
    field_widths: &HashMap<String, u8>,
    predicate: &PredicateAst,
    report: &mut BoundaryReport,
) {
    // Per-field boundary: cycle through [0, 1, max/2, max-1, max],
    // holding other fields at 0.
    for field in refs {
        let bare = strip_prefix(field);
        let bits = field_widths[bare];
        let max = domain_max(bits);
        for &val in &[0u128, 1, max >> 1, max.saturating_sub(1), max] {
            let assignments: Vec<(String, u128)> = refs
                .iter()
                .map(|r| {
                    if r == field {
                        (r.clone(), val.min(max))
                    } else {
                        (r.clone(), 0)
                    }
                })
                .collect();
            evaluate_one(&assignments, target_name, predicate, report);
        }
    }

    // Extreme points.
    for assignments in [
        refs.iter().map(|r| (r.clone(), 0u128)).collect::<Vec<_>>(),
        refs.iter()
            .map(|r| {
                let bare = strip_prefix(r);
                let bits = field_widths[bare];
                (r.clone(), domain_max(bits))
            })
            .collect::<Vec<_>>(),
    ] {
        evaluate_one(&assignments, target_name, predicate, report);
    }
}

fn evaluate_one(
    assignments: &[(String, u128)],
    target_name: &str,
    predicate: &PredicateAst,
    report: &mut BoundaryReport,
) {
    let scope = build_invariant_scope(SCOPE_KIND_OBJECT_TYPE, target_name, 0, assignments)
        .expect("scope buffer build should never fail for valid field names");
    report.total_cases += 1;
    match interpret_predicate(predicate, &scope) {
        EvalOutcome::Satisfied => report.satisfied += 1,
        EvalOutcome::Violated => report.violated += 1,
        EvalOutcome::Indeterminate => report.indeterminate += 1,
    }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG
// ---------------------------------------------------------------------------

/// splitmix64 — tiny, deterministic, no dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u128_varwidth(&mut self) -> u128 {
        let raw = ((self.next_u64() as u128) << 64) | self.next_u64() as u128;
        let bits = (self.next_u64() % 129) as u32;
        if bits >= 128 {
            raw
        } else {
            raw & ((1u128 << bits) - 1)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ArithExpr, CmpOp};

    fn widths(map: &[(&str, u8)]) -> HashMap<String, u8> {
        map.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn semantically_always_true_on_unsigned_domain_is_rejected() {
        // `after.x >= 0` on a u8 field — structurally non-trivial,
        // semantically always true (every u8 is >= 0).
        let pred = PredicateAst::ArithCmp {
            op: CmpOp::Ge,
            lhs: ArithExpr::Field("after.x".into()),
            rhs: ArithExpr::Literal(0),
        };
        let err = boundary_check(
            &pred,
            "test",
            "TestObj",
            &widths(&[("x", 8)]),
            &BoundaryConfig::default(),
        )
        .unwrap_err();
        match err {
            BoundaryError::SemanticallyVacuous {
                always_true: true, ..
            } => {}
            other => panic!("expected always-true vacuity, got {other:?}"),
        }
    }

    #[test]
    fn semantically_always_false_on_unsigned_domain_is_rejected() {
        // `after.x >= 256` on a u8 field — max value is 255, so always false.
        let pred = PredicateAst::ArithCmp {
            op: CmpOp::Ge,
            lhs: ArithExpr::Field("after.x".into()),
            rhs: ArithExpr::Literal(256),
        };
        let err = boundary_check(
            &pred,
            "test",
            "TestObj",
            &widths(&[("x", 8)]),
            &BoundaryConfig::default(),
        )
        .unwrap_err();
        match err {
            BoundaryError::SemanticallyVacuous {
                always_true: false, ..
            } => {}
            other => panic!("expected always-false vacuity, got {other:?}"),
        }
    }

    #[test]
    fn non_vacuous_predicate_passes() {
        // `after.x > before.x` — can be both true and false.
        let pred = PredicateAst::FieldGe {
            lhs: "after.x".into(),
            rhs: "before.x".into(),
        };
        let report = boundary_check(
            &pred,
            "test",
            "TestObj",
            &widths(&[("x", 128)]),
            &BoundaryConfig::default(),
        )
        .unwrap();
        assert!(report.satisfied > 0);
        assert!(report.violated > 0);
    }

    #[test]
    fn always_indeterminate_predicate_is_rejected() {
        use crate::types::{BoundedArithOp, OverflowPolicy, Widening};
        // `(after.x - 1000) >= 0` on a u8 field (max 255): every subtraction
        // underflows with the default Indeterminate policy, so the predicate
        // is indeterminate for every case and can never revert.
        let pred = PredicateAst::ArithCmp {
            op: CmpOp::Ge,
            lhs: ArithExpr::Bounded {
                op: BoundedArithOp::Sub,
                lhs: Box::new(ArithExpr::Field("after.x".into())),
                rhs: Box::new(ArithExpr::Literal(1000)),
                widening: Widening::U256,
                on_overflow: OverflowPolicy::Indeterminate,
            },
            rhs: ArithExpr::Literal(0),
        };
        let err = boundary_check(
            &pred,
            "test",
            "TestObj",
            &widths(&[("x", 8)]),
            &BoundaryConfig::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, BoundaryError::AlwaysIndeterminate { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn empty_field_refs_is_noop() {
        let pred = PredicateAst::Opaque;
        let report = boundary_check(
            &pred,
            "test",
            "TestObj",
            &widths(&[("x", 8)]),
            &BoundaryConfig::default(),
        )
        .unwrap();
        assert_eq!(report.total_cases, 0);
    }

    #[test]
    fn missing_field_domain_is_error() {
        let pred = PredicateAst::FieldGe {
            lhs: "after.missing".into(),
            rhs: "before.missing".into(),
        };
        let err = boundary_check(
            &pred,
            "test",
            "TestObj",
            &widths(&[("other", 8)]),
            &BoundaryConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(err, BoundaryError::MissingFieldDomain { .. }));
    }

    #[test]
    fn boundary_seed_is_deterministic() {
        let pred = PredicateAst::FieldGe {
            lhs: "after.x".into(),
            rhs: "before.x".into(),
        };
        let cfg = BoundaryConfig {
            random_cases: 100,
            seed: 42,
        };
        let a = boundary_check(&pred, "test", "T", &widths(&[("x", 64)]), &cfg).unwrap();
        let b = boundary_check(&pred, "test", "T", &widths(&[("x", 64)]), &cfg).unwrap();
        assert_eq!(a.total_cases, b.total_cases);
        assert_eq!(a.satisfied, b.satisfied);
        assert_eq!(a.violated, b.violated);
    }
}
