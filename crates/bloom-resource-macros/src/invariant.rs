//! `#[invariant]` function attribute (spec §12).
//!
//! ```ignore
//! #[invariant(
//!     name = "reserve_product_non_decreasing",
//!     target = "Pool<A, B, S>",
//!     pred  = |p: &Pool<A, B, S>| S::k(p) >= p.k_last
//! )]
//! pub fn swap_a_for_b<A, B, S>(...) -> Coin<B> { ... }
//! ```
//!
//! In phase 1 the macro records the invariant decl (name, target,
//! predicate AST best-effort, wasm export name) onto the function as a
//! tagged attribute that the petal-level macro later collects. The
//! emitted `__inv_<idx>` body is a stub (see [`crate::codegen::emit_invariant_shim`]).
//!
//! `pred` is parsed best-effort into [`PredicateAst`]; unrecognized
//! shapes round-trip as [`PredicateAst::Opaque`].

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Attribute, BinOp, Expr, ExprBinary, ExprClosure, ExprField, ExprPath, ItemFn, Meta};

use crate::ast::{attr_is_named, parse_str_value};
use crate::error::err_spanned;
use bloom_petal_manifest::types::{InvariantDecl, InvariantTarget, PredicateAst};

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
                    other => {
                        return Err(err_spanned(
                            other,
                            "unknown #[invariant] argument; expected `name`, `target`, or `pred`",
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
    }
}

/// Lower a Rust `Expr` into a best-effort [`PredicateAst`]. Unknown
/// shapes round-trip as [`PredicateAst::Opaque`] — the body of the
/// generated `__inv_<idx>` export still runs the original closure
/// (spec §12.3: machine-readability is best-effort).
pub(crate) fn predicate_ast_of(expr: &Expr) -> PredicateAst {
    // Strip leading parens and (the common case) a closure to get to
    // the body.
    let body = match expr {
        Expr::Closure(ExprClosure { body, .. }) => body.as_ref(),
        Expr::Paren(p) => p.expr.as_ref(),
        other => other,
    };

    // Bin-op: `lhs <cmp> rhs`.
    if let Expr::Binary(ExprBinary {
        left, op, right, ..
    }) = body
    {
        let (lhs_name, rhs_name) = (field_name_of(left), field_name_of(right));
        if let (Some(l), Some(r)) = (lhs_name, rhs_name) {
            return match op {
                BinOp::Ge(_) => PredicateAst::FieldGe { lhs: l, rhs: r },
                BinOp::Le(_) => PredicateAst::FieldLe { lhs: l, rhs: r },
                BinOp::Eq(_) => PredicateAst::FieldEq { lhs: l, rhs: r },
                _ => PredicateAst::Opaque,
            };
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
    fn predicate_field_ge_recognized() {
        let e: Expr = syn::parse2(quote! { |p: &Pool| p.a >= p.b }).unwrap();
        match predicate_ast_of(&e) {
            PredicateAst::FieldGe { lhs, rhs } => {
                assert_eq!(lhs, "a");
                assert_eq!(rhs, "b");
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
    fn expand_emits_name_constant() {
        let toks = expand(quote! { name = "x" }, quote! { pub fn swap() {} }).unwrap();
        let s = toks.to_string();
        assert!(s.contains("__BLOOM_INV_swap__NAME"));
        assert!(s.contains("\"x\""));
    }
}
