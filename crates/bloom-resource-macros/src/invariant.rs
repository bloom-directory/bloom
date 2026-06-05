//! `#[invariant]` function attribute (spec §12).
//!
//! ```ignore
//! #[invariant(
//!     name   = "pool_k_non_decreasing",
//!     target = "Pool",   // base object-type name; fires on each Pool mutation
//!     pred   = |before, after| after.reserve_a * after.reserve_b >= before.k_last
//!     text   = "the pool constant-product k never decreases across a swap", // optional
//! )]
//! pub fn swap_exact_in<A, B>(...) -> Coin<B> { ... }
//! ```
//!
//! The `pred` closure compares an object's `before`/`after` state; reference
//! fields as `before.<field>` / `after.<field>`. The macro lowers it to a
//! [`PredicateAst`] and the petal-level macro compiles a real `__inv_<idx>`
//! evaluator from it (see [`crate::codegen::emit_invariant_shim`]).
//!
//! **Supported predicate shapes:** comparisons (`>=`, `<=`, `==`) between field
//! or bounded-arithmetic (`*`, `+`, `u128` literals) expressions, composed
//! with boolean `&&`/`||`/`!` (ADR-015) — lowered to
//! [`PredicateAst::FieldGe`]/`FieldLe`/`FieldEq`, [`PredicateAst::ArithCmp`],
//! and [`PredicateAst::And`]/`Or`/`Not`. Only fixed-prefix unsigned-integer
//! fields (`u8`..`u128`) are addressable as numeric invariant fields; `bool`
//! is intentionally excluded rather than modeled as `u8` (ADR-011).
//! Subtraction (`-`) lowers but is **rejected at deploy** for now: the guest
//! fails closed to Violated on underflow while the trusted interpreter returns
//! Indeterminate, and the differential gate does not yet cover that split.
//! Nested bounded arithmetic and bounded arithmetic on both sides of a
//! comparison are also rejected at deploy until the trusted interpreter uses
//! exact `U256` semantics throughout — use a single `+`/`*` expression on one
//! side of the comparison for now.
//!
//! **Unsupported shapes are rejected at deploy** (fail-closed, ADR-014):
//! `S::k(p)`-style calls and any closure that doesn't lower to a supported
//! shape ([`PredicateAst::Opaque`]) are refused by `validate_chain_wasm`, not
//! silently accepted — the generated `__inv_<idx>` evaluator returns `0`
//! (Violated) for these arms rather than running any original closure.
//! Predicates that are statically vacuous (always-true / always-false) are
//! likewise rejected (ADR-003 intent-conformance).
//!
//! See `docs/guides/authoring-invariants.md` for the full author guide and
//! `docs/research/formal-verification/08-implementation-status.md` for status.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Attribute, BinOp, Expr, ExprBinary, ExprClosure, ExprField, ExprPath, ExprUnary, ItemFn, Meta,
    UnOp,
};

use crate::ast::{attr_is_named, parse_str_value};
use crate::error::err_spanned;
use bloom_petal_manifest::types::{
    ArithExpr, BoundedArithOp, CmpOp, InvariantDecl, InvariantTarget, OverflowPolicy, PredicateAst,
    Widening,
};

/// Parsed `#[invariant(...)]` attribute.
#[derive(Debug, Clone)]
pub(crate) struct InvariantAttr {
    /// User-provided invariant name.
    pub name: String,
    /// Target object-type or function (string form, e.g. `"Pool<A, B>"`
    /// or `"swap_a_for_b"`).
    pub target: Option<String>,
    /// Predicate closure expr (parsed for AST shape).
    pub pred: Option<Expr>,
    /// Optional natural-language claim paired with the predicate (ADR-003,
    /// spec↔intent). Stored in the manifest's `InvariantDecl.human_text`.
    pub text: Option<String>,
}

impl InvariantAttr {
    /// Parse the bare attribute tokens (everything inside the `(...)`).
    pub fn parse(attr: TokenStream) -> syn::Result<Self> {
        if attr.is_empty() {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "`#[invariant(...)]` requires at least `name = \"...\"`",
            ));
        }
        let attr_text = format!("#[invariant({})]", attr);
        let attrs: Vec<Attribute> =
            syn::parse::Parser::parse_str(Attribute::parse_outer, &attr_text)?;
        let outer = attrs.into_iter().next().ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                "expected `#[invariant(...)]`",
            )
        })?;

        let mut name: Option<String> = None;
        let mut target: Option<String> = None;
        let mut pred: Option<Expr> = None;
        let mut text: Option<String> = None;

        if let Meta::List(list) = &outer.meta {
            let nested = list.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )?;
            for meta in nested {
                match &meta {
                    Meta::NameValue(nv) if nv.path.is_ident("name") => {
                        name = Some(parse_str_value(nv)?);
                    }
                    Meta::NameValue(nv) if nv.path.is_ident("target") => {
                        target = Some(parse_str_value(nv)?);
                    }
                    Meta::NameValue(nv) if nv.path.is_ident("pred") => {
                        pred = Some(nv.value.clone());
                    }
                    Meta::NameValue(nv) if nv.path.is_ident("text") => {
                        text = Some(parse_str_value(nv)?);
                    }
                    other => {
                        return Err(err_spanned(
                            other,
                            "unknown #[invariant] argument; expected `name`, `target`, `pred`, or `text`",
                        ));
                    }
                }
            }
        }

        Ok(Self {
            name: name.ok_or_else(|| {
                syn::Error::new(
                    proc_macro2::Span::call_site(),
                    "#[invariant] requires `name = \"...\"`",
                )
            })?,
            target,
            pred,
            text,
        })
    }
}

/// Build the manifest [`InvariantDecl`] from the attribute + the
/// host function. `idx` is the invariant's slot in the petal's
/// invariant table (used to derive the `__inv_<idx>` export name).
pub(crate) fn build_decl(attr: &InvariantAttr, host_fn: &ItemFn, idx: u16) -> InvariantDecl {
    let target = match &attr.target {
        Some(t) => InvariantTarget::ObjectType { name: t.clone() },
        None => InvariantTarget::FunctionExit {
            name: host_fn.sig.ident.to_string(),
        },
    };
    let predicate = attr
        .pred
        .as_ref()
        .map(predicate_ast_of)
        .unwrap_or(PredicateAst::Opaque);
    InvariantDecl {
        name: attr.name.clone(),
        target,
        predicate,
        wasm_export: format!("__inv_{}", idx),
        human_text: attr.text.clone().unwrap_or_default(),
    }
}

/// Lower a Rust `Expr` into a best-effort [`PredicateAst`]. Unknown
/// shapes round-trip as [`PredicateAst::Opaque`], which the generated
/// `__inv_<idx>` evaluator lowers to `0` (Violated — fail-closed) and
/// `validate_chain_wasm` rejects at deploy; there is no fallback to running
/// the original closure on-chain.
pub(crate) fn predicate_ast_of(expr: &Expr) -> PredicateAst {
    // Strip the closure wrapper, then lower the body recursively.
    let body = match expr {
        Expr::Closure(ExprClosure { body, .. }) => body.as_ref(),
        other => other,
    };
    lower_predicate(body)
}

/// Recursively lower a predicate expression. Handles boolean composition
/// (`&&`, `||`, `!`) by recursion; leaves are field / bounded-arithmetic
/// comparisons. Unknown shapes round-trip as [`PredicateAst::Opaque`].
fn lower_predicate(expr: &Expr) -> PredicateAst {
    let body = match expr {
        Expr::Paren(p) => return lower_predicate(p.expr.as_ref()),
        other => other,
    };

    // Boolean negation: `!inner`.
    if let Expr::Unary(ExprUnary {
        op: UnOp::Not(_),
        expr,
        ..
    }) = body
    {
        return PredicateAst::Not(Box::new(lower_predicate(expr)));
    }

    // Bin-op: boolean composition `&&` / `||`, else a `lhs <cmp> rhs` leaf.
    if let Expr::Binary(ExprBinary {
        left, op, right, ..
    }) = body
    {
        match op {
            BinOp::And(_) => {
                return PredicateAst::And(
                    Box::new(lower_predicate(left)),
                    Box::new(lower_predicate(right)),
                );
            }
            BinOp::Or(_) => {
                return PredicateAst::Or(
                    Box::new(lower_predicate(left)),
                    Box::new(lower_predicate(right)),
                );
            }
            _ => {}
        }
        // Simple field comparison. Use *qualified* names (`after.reserve_a`,
        // not `reserve_a`) so the leaf matches the flat field-table scope
        // keys the host builds (`before.<f>` / `after.<f>`); an unqualified
        // name would never resolve and the predicate would fail closed.
        let (lhs_name, rhs_name) = (
            qualified_field_name_of(left),
            qualified_field_name_of(right),
        );
        if let (Some(l), Some(r)) = (lhs_name, rhs_name) {
            return match op {
                BinOp::Ge(_) => PredicateAst::FieldGe { lhs: l, rhs: r },
                BinOp::Le(_) => PredicateAst::FieldLe { lhs: l, rhs: r },
                BinOp::Eq(_) => PredicateAst::FieldEq { lhs: l, rhs: r },
                _ => PredicateAst::Opaque,
            };
        }

        // Bounded-arithmetic comparison, e.g.
        // `after.reserve_a * after.reserve_b >= before.k_last` (plan §7).
        if let Some(cmp) = cmp_op_of(op) {
            if let (Some(l), Some(r)) = (arith_expr_of(left), arith_expr_of(right)) {
                return PredicateAst::ArithCmp {
                    op: cmp,
                    lhs: l,
                    rhs: r,
                };
            }
        }

        // `S::k(p) >= p.k_last` — pool-style invariant (spec §12.1).
        if matches!(op, BinOp::Ge(_)) {
            if let (Some(strategy), Some(field)) = (strategy_call_param(left), field_name_of(right))
            {
                return PredicateAst::StrategyKNonDecreasing {
                    strategy_param: strategy,
                    pool_field: field,
                };
            }
        }
    }

    PredicateAst::Opaque
}

/// Map a comparison `BinOp` to a [`CmpOp`].
fn cmp_op_of(op: &BinOp) -> Option<CmpOp> {
    match op {
        BinOp::Ge(_) => Some(CmpOp::Ge),
        BinOp::Le(_) => Some(CmpOp::Le),
        BinOp::Eq(_) => Some(CmpOp::Eq),
        _ => None,
    }
}

/// Lower an arithmetic sub-expression over scope fields into an
/// [`ArithExpr`]. Recognizes qualified field accesses (`after.reserve_a`),
/// `u128` literals, and `*`/`+`/`-` of such. Returns `None` for shapes
/// outside the v1 vocabulary (the predicate then falls back to `Opaque`).
fn arith_expr_of(e: &Expr) -> Option<ArithExpr> {
    match e {
        Expr::Paren(p) => arith_expr_of(&p.expr),
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(i),
            ..
        }) => i.base10_parse::<u128>().ok().map(ArithExpr::Literal),
        Expr::Binary(ExprBinary {
            left, op, right, ..
        }) => {
            let arith_op = match op {
                BinOp::Mul(_) => BoundedArithOp::Mul,
                BinOp::Add(_) => BoundedArithOp::Add,
                BinOp::Sub(_) => BoundedArithOp::Sub,
                _ => return None,
            };
            Some(ArithExpr::Bounded {
                op: arith_op,
                lhs: Box::new(arith_expr_of(left)?),
                rhs: Box::new(arith_expr_of(right)?),
                // 256-bit intermediates hold any product of two u128s, so
                // the comparison never overflows; overflow elsewhere is
                // surfaced as indeterminate (ADR-009).
                widening: Widening::U256,
                on_overflow: OverflowPolicy::Indeterminate,
            })
        }
        _ => qualified_field_name_of(e).map(ArithExpr::Field),
    }
}

/// Extract a qualified field name from a `<base>.<field>` access, e.g.
/// `after.reserve_a` → `"after.reserve_a"`. A bare single-segment path
/// (`reserve_a`) returns itself.
fn qualified_field_name_of(e: &Expr) -> Option<String> {
    match e {
        Expr::Field(ExprField {
            base,
            member: syn::Member::Named(field),
            ..
        }) => {
            let base = qualified_field_name_of(base)?;
            Some(format!("{base}.{field}"))
        }
        Expr::Path(ExprPath { path, .. }) if path.segments.len() == 1 => {
            Some(path.segments[0].ident.to_string())
        }
        _ => None,
    }
}

/// Extract a bare field name from a `<receiver>.<field>` access expr.
fn field_name_of(e: &Expr) -> Option<String> {
    match e {
        Expr::Field(ExprField {
            member: syn::Member::Named(i),
            ..
        }) => Some(i.to_string()),
        Expr::Path(ExprPath { path, .. }) if path.segments.len() == 1 => {
            Some(path.segments[0].ident.to_string())
        }
        _ => None,
    }
}

/// Extract `S` from `S::k(p)` — the strategy generic name.
fn strategy_call_param(e: &Expr) -> Option<String> {
    let Expr::Call(call) = e else {
        return None;
    };
    let Expr::Path(ExprPath { path, .. }) = call.func.as_ref() else {
        return None;
    };
    // `S::k` — two segments.
    if path.segments.len() != 2 {
        return None;
    }
    Some(path.segments[0].ident.to_string())
}

/// Macro entry: parse attr + fn, re-emit the fn unchanged plus a
/// marker constant the petal-level macro can read.
pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let parsed: ItemFn = syn::parse2(item)?;
    let attr = InvariantAttr::parse(attr)?;
    // We don't know the petal-level idx yet; the petal macro will
    // reassign. For solo use, idx=0 is fine.
    let _decl = build_decl(&attr, &parsed, 0);

    let mut output = parsed.clone();
    output.attrs.retain(|a| !attr_is_named(a, "invariant"));

    // Embed the user-provided name as a string constant for later
    // collection by `#[bloom::petal]`.
    let fn_ident = &parsed.sig.ident;
    let name_const = syn::Ident::new(&format!("__BLOOM_INV_{}__NAME", fn_ident), fn_ident.span());
    let name_str = attr.name.clone();

    Ok(quote! {
        #output

        /// Invariant name recorded by `#[invariant]`. Auto-generated.
        #[allow(non_upper_case_globals, dead_code)]
        pub(crate) const #name_const: &str = #name_str;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn parse_minimal_attr() {
        let a = InvariantAttr::parse(quote! { name = "x" }).unwrap();
        assert_eq!(a.name, "x");
        assert!(a.target.is_none());
        assert!(a.pred.is_none());
    }

    #[test]
    fn parse_requires_name() {
        assert!(InvariantAttr::parse(quote! { target = "Pool" }).is_err());
    }

    #[test]
    fn parse_full_attr() {
        let a = InvariantAttr::parse(quote! {
            name = "x", target = "Pool", pred = |p: &Pool| p.a >= p.b
        })
        .unwrap();
        assert_eq!(a.name, "x");
        assert_eq!(a.target.as_deref(), Some("Pool"));
        assert!(a.pred.is_some());
    }

    #[test]
    fn parse_text_attr() {
        let a = InvariantAttr::parse(quote! { name = "x", text = "a never decreases" }).unwrap();
        assert_eq!(a.name, "x");
        assert_eq!(a.text.as_deref(), Some("a never decreases"));
        assert!(a.target.is_none());
        assert!(a.pred.is_none());
    }

    #[test]
    fn parse_full_attr_with_text() {
        let a = InvariantAttr::parse(quote! {
            name = "x", target = "Pool", pred = |before, after| after.a >= before.a,
            text = "a never decreases across any mutation"
        })
        .unwrap();
        assert_eq!(a.name, "x");
        assert_eq!(a.target.as_deref(), Some("Pool"));
        assert!(a.pred.is_some());
        assert_eq!(
            a.text.as_deref(),
            Some("a never decreases across any mutation")
        );
    }

    #[test]
    fn predicate_field_ge_recognized() {
        let e: Expr = syn::parse2(quote! { |p: &Pool| p.a >= p.b }).unwrap();
        match predicate_ast_of(&e) {
            PredicateAst::FieldGe { lhs, rhs } => {
                assert_eq!(lhs, "p.a");
                assert_eq!(rhs, "p.b");
            }
            other => panic!("expected FieldGe, got {:?}", other),
        }
    }

    #[test]
    fn predicate_field_ge_qualifies_before_after_names() {
        // A simple before/after comparison must produce the *qualified*
        // names that match the runtime scope keys — otherwise the leaf
        // would never resolve and the invariant would fail closed.
        let e: Expr =
            syn::parse2(quote! { |before, after| after.reserve_a >= before.k_last }).unwrap();
        match predicate_ast_of(&e) {
            PredicateAst::FieldGe { lhs, rhs } => {
                assert_eq!(lhs, "after.reserve_a");
                assert_eq!(rhs, "before.k_last");
            }
            other => panic!("expected FieldGe, got {:?}", other),
        }
    }

    #[test]
    fn predicate_field_le_recognized() {
        let e: Expr = syn::parse2(quote! { |p: &Pool| p.a <= p.b }).unwrap();
        assert!(matches!(predicate_ast_of(&e), PredicateAst::FieldLe { .. }));
    }

    #[test]
    fn predicate_field_eq_recognized() {
        let e: Expr = syn::parse2(quote! { |p: &Pool| p.a == p.b }).unwrap();
        assert!(matches!(predicate_ast_of(&e), PredicateAst::FieldEq { .. }));
    }

    #[test]
    fn predicate_boolean_composition_lowers() {
        // The corrected pool_k form: k non-decreasing OR a liquidity event.
        let e: Expr = syn::parse2(quote! {
            |before, after| after.reserve_a * after.reserve_b >= before.k_last
                || !(after.lp_supply == before.lp_supply)
        })
        .unwrap();
        match predicate_ast_of(&e) {
            PredicateAst::Or(l, r) => {
                assert!(matches!(*l, PredicateAst::ArithCmp { .. }));
                match *r {
                    PredicateAst::Not(inner) => {
                        assert!(matches!(*inner, PredicateAst::FieldEq { .. }))
                    }
                    other => panic!("expected Not(FieldEq), got {other:?}"),
                }
            }
            other => panic!("expected Or, got {other:?}"),
        }
    }

    #[test]
    fn predicate_and_lowers() {
        let e: Expr =
            syn::parse2(quote! { |before, after| after.a >= before.a && after.a <= after.cap })
                .unwrap();
        assert!(matches!(predicate_ast_of(&e), PredicateAst::And(_, _)));
    }

    #[test]
    fn predicate_unknown_is_opaque() {
        let e: Expr = syn::parse2(quote! { |p: &Pool| p.a + p.b > 0 }).unwrap();
        assert_eq!(predicate_ast_of(&e), PredicateAst::Opaque);
    }

    #[test]
    fn build_decl_function_exit_default() {
        let f: ItemFn = syn::parse2(quote! { pub fn swap() {} }).unwrap();
        let a = InvariantAttr::parse(quote! { name = "x" }).unwrap();
        let d = build_decl(&a, &f, 0);
        assert_eq!(d.wasm_export, "__inv_0");
        assert!(matches!(d.target, InvariantTarget::FunctionExit { .. }));
    }

    #[test]
    fn build_decl_object_target() {
        let f: ItemFn = syn::parse2(quote! { pub fn swap() {} }).unwrap();
        let a = InvariantAttr::parse(quote! { name = "x", target = "Pool<A>" }).unwrap();
        let d = build_decl(&a, &f, 3);
        assert_eq!(d.wasm_export, "__inv_3");
        match d.target {
            InvariantTarget::ObjectType { name } => assert_eq!(name, "Pool<A>"),
            _ => panic!("expected ObjectType target"),
        }
    }

    #[test]
    fn build_decl_with_text_passes_human_text_through() {
        let f: ItemFn = syn::parse2(quote! { pub fn swap() {} }).unwrap();
        let a = InvariantAttr::parse(quote! { name = "x", text = "a never decreases" }).unwrap();
        let d = build_decl(&a, &f, 0);
        assert_eq!(d.human_text, "a never decreases");
    }

    #[test]
    fn build_decl_without_text_has_empty_human_text() {
        let f: ItemFn = syn::parse2(quote! { pub fn swap() {} }).unwrap();
        let a = InvariantAttr::parse(quote! { name = "x" }).unwrap();
        let d = build_decl(&a, &f, 0);
        assert_eq!(d.human_text, "");
    }

    #[test]
    fn expand_emits_name_constant() {
        let toks = expand(quote! { name = "x" }, quote! { pub fn swap() {} }).unwrap();
        let s = toks.to_string();
        assert!(s.contains("__BLOOM_INV_swap__NAME"));
        assert!(s.contains("\"x\""));
    }
}
