//! Shared `syn` helpers used by every macro module.
//!
//! These helpers do not depend on `bloom_objects` types so they can be
//! exercised in unit tests without dragging the whole runtime crate in.

use std::collections::HashSet;

use proc_macro2::Span;
use syn::{
    Attribute, Expr, ExprLit, FnArg, GenericParam, Generics, Ident, ItemFn, ItemStruct, Lit, Meta,
    MetaNameValue, PatType, Type, TypePath, TypeReference,
};

use crate::error::err_spanned;

/// Drain attributes off a `Vec<Attribute>` that satisfy `pred`, returning
/// the survivors and the removed set.
pub(crate) fn partition_attrs<F>(attrs: Vec<Attribute>, pred: F) -> (Vec<Attribute>, Vec<Attribute>)
where
    F: Fn(&Attribute) -> bool,
{
    let mut kept = Vec::with_capacity(attrs.len());
    let mut removed = Vec::new();
    for a in attrs {
        if pred(&a) {
            removed.push(a);
        } else {
            kept.push(a);
        }
    }
    (kept, removed)
}

/// Test if `attr` is `#[name]` or `#[name(...)]`, accepting either a
/// single-segment path (`#[object]`) or any qualified path whose final
/// segment matches (`#[bloom::object]`, `#[some::prefix::object]`).
pub(crate) fn attr_is_named(attr: &Attribute, name: &str) -> bool {
    let path = attr.path();
    if path.is_ident(name) {
        return true;
    }
    path.segments
        .last()
        .map(|seg| seg.ident == name)
        .unwrap_or(false)
}

/// Parse a `key = "value"` form on an attribute's `Meta`.
pub(crate) fn parse_str_value(meta: &MetaNameValue) -> syn::Result<String> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(s), ..
    }) = &meta.value
    {
        Ok(s.value())
    } else {
        Err(err_spanned(&meta.value, "expected string literal"))
    }
}

/// Parse an integer `key = N` form on an attribute's `Meta`.
pub(crate) fn parse_u64_value(meta: &MetaNameValue) -> syn::Result<u64> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Int(i), ..
    }) = &meta.value
    {
        i.base10_parse::<u64>()
    } else {
        Err(err_spanned(&meta.value, "expected integer literal"))
    }
}

/// Parse `#[attr(key = "...", key = "...", ...)]` into a vector of
/// `MetaNameValue`s, preserving source order.
pub(crate) fn parse_kv_attr(attr: &Attribute) -> syn::Result<Vec<MetaNameValue>> {
    match &attr.meta {
        Meta::List(list) => list
            .parse_args_with(
                syn::punctuated::Punctuated::<MetaNameValue, syn::Token![,]>::parse_terminated,
            )
            .map(|p| p.into_iter().collect()),
        Meta::Path(_) => Ok(Vec::new()),
        Meta::NameValue(_) => Err(err_spanned(attr, "expected attribute list `(...)`")),
    }
}

/// Parse a comma-separated identifier list out of a string literal —
/// used for `phantom = "T, U"` and `abilities = "key, store"`.
pub(crate) fn parse_ident_list(raw: &str, span: Span) -> syn::Result<Vec<String>> {
    let mut out = Vec::new();
    for token in raw.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        // Validate it's a syntactic identifier.
        if !is_valid_ident(t) {
            return Err(syn::Error::new(
                span,
                format!("`{}` is not a valid identifier", t),
            ));
        }
        out.push(t.to_string());
    }
    Ok(out)
}

/// True iff `s` is a syntactically valid Rust identifier (ASCII).
pub(crate) fn is_valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Collect every type-parameter name on `generics` into a `HashSet`.
pub(crate) fn type_param_names(generics: &Generics) -> HashSet<String> {
    generics
        .params
        .iter()
        .filter_map(|p| match p {
            GenericParam::Type(t) => Some(t.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// Extract the leading identifier of a path-type, or `None` if the type
/// is something other than a path (`&T`, tuple, etc.).
pub(crate) fn first_path_ident(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(TypePath { path, .. }) => path.segments.first().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// Determine whether `ty` is `&T` (returning `(is_mut, inner)`) or not.
pub(crate) fn as_reference(ty: &Type) -> Option<(bool, &Type)> {
    match ty {
        Type::Reference(TypeReference {
            mutability, elem, ..
        }) => Some((mutability.is_some(), elem.as_ref())),
        _ => None,
    }
}

/// Extract `Signer`-ness from a function argument. Returns `Some(ty)` if
/// the argument is `_: &Signer` / `_: Signer` regardless of name.
pub(crate) fn signer_arg(arg: &FnArg) -> Option<&Type> {
    let FnArg::Typed(PatType { ty, .. }) = arg else {
        return None;
    };
    let inner: &Type = match as_reference(ty) {
        Some((_, inner)) => inner,
        None => ty.as_ref(),
    };
    match first_path_ident(inner).as_deref() {
        Some("Signer") => Some(inner),
        _ => None,
    }
}

/// Returns the name (`String`) of the function as a `&str`.
pub(crate) fn fn_name(f: &ItemFn) -> String {
    f.sig.ident.to_string()
}

/// Returns the struct name as `String`.
pub(crate) fn struct_name(s: &ItemStruct) -> String {
    s.ident.to_string()
}

/// Build a `proc_macro2::Ident` from a `&str`, panicking only if the
/// identifier is invalid (which we validate at call-site).
pub(crate) fn ident(name: &str, span: Span) -> Ident {
    Ident::new(name, span)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn is_valid_ident_basics() {
        assert!(is_valid_ident("Foo"));
        assert!(is_valid_ident("_x"));
        assert!(is_valid_ident("a1"));
        assert!(!is_valid_ident(""));
        assert!(!is_valid_ident("1x"));
        assert!(!is_valid_ident("a-b"));
        assert!(!is_valid_ident("a b"));
    }

    #[test]
    fn parse_ident_list_handles_spaces() {
        let list = parse_ident_list("T, U , V", Span::call_site()).unwrap();
        assert_eq!(list, vec!["T", "U", "V"]);
    }

    #[test]
    fn parse_ident_list_handles_empty() {
        let list = parse_ident_list("", Span::call_site()).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn parse_ident_list_rejects_invalid() {
        let res = parse_ident_list("T, 1x", Span::call_site());
        assert!(res.is_err());
    }

    #[test]
    fn first_path_ident_basic() {
        let ty: Type = syn::parse2(quote! { Foo<Bar> }).unwrap();
        assert_eq!(first_path_ident(&ty).as_deref(), Some("Foo"));
        let ty: Type = syn::parse2(quote! { (u8, u8) }).unwrap();
        assert_eq!(first_path_ident(&ty), None);
    }

    #[test]
    fn as_reference_distinguishes_mut() {
        let ty: Type = syn::parse2(quote! { &Foo }).unwrap();
        assert!(!as_reference(&ty).unwrap().0);
        let ty: Type = syn::parse2(quote! { &mut Foo }).unwrap();
        assert!(as_reference(&ty).unwrap().0);
        let ty: Type = syn::parse2(quote! { Foo }).unwrap();
        assert!(as_reference(&ty).is_none());
    }

    #[test]
    fn signer_arg_recognizes_ref() {
        let arg: FnArg = syn::parse2(quote! { signer: &Signer }).unwrap();
        assert!(signer_arg(&arg).is_some());
        let arg: FnArg = syn::parse2(quote! { signer: Signer }).unwrap();
        assert!(signer_arg(&arg).is_some());
        let arg: FnArg = syn::parse2(quote! { x: u32 }).unwrap();
        assert!(signer_arg(&arg).is_none());
    }

    #[test]
    fn type_param_names_collected() {
        let g: Generics = syn::parse2(quote! { <A, B, const N: usize> }).unwrap();
        let names = type_param_names(&g);
        assert!(names.contains("A"));
        assert!(names.contains("B"));
        assert!(!names.contains("N"));
    }

    #[test]
    fn parse_str_and_int_values() {
        let mv: MetaNameValue = syn::parse2(quote! { foo = "bar" }).unwrap();
        assert_eq!(parse_str_value(&mv).unwrap(), "bar");
        let mv: MetaNameValue = syn::parse2(quote! { foo = 42 }).unwrap();
        assert_eq!(parse_u64_value(&mv).unwrap(), 42);
        let mv: MetaNameValue = syn::parse2(quote! { foo = "bar" }).unwrap();
        assert!(parse_u64_value(&mv).is_err());
    }
}
