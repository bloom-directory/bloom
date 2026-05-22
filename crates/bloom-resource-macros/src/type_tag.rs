//! `syn::Type` → `bloom_objects::TypeTag` lowering used by every macro
//! to record field / argument / return shapes in the manifest.
//!
//! All `Concrete` TypeTags use `[0u8; 32]` as the `petal_hash`: the
//! macro cannot know its own crate's wasm hash at expansion time. The
//! chain layer replaces these placeholders with the actual hash on
//! publish (spec §8.3, §8.2 paragraph about self-references).

use std::collections::HashMap;

use bloom_objects::TypeTag;
use syn::{GenericArgument, PathArguments, Type, TypePath};

use crate::error::err_spanned;

/// Builder for type-tag emission inside a single petal scope.
///
/// `generic_idx` maps a generic-param name (`"A"`) to its declaration
/// index. `phantom_params` is the set of generic params declared with
/// `phantom = "..."` — these may appear bare in `TypeTag` positions but
/// are rejected as field/arg payloads (handled separately in
/// [`reject_plain_generic_in_payload`]).
#[derive(Debug, Default, Clone)]
pub(crate) struct TypeTagCtx {
    /// `name -> idx` mapping for generic params on the enclosing
    /// struct/function. `0`-indexed by source declaration order.
    pub generic_idx: HashMap<String, u16>,
}

impl TypeTagCtx {
    /// Build a `TypeTagCtx` from an ordered list of generic-param names.
    pub fn from_generic_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let generic_idx = names
            .into_iter()
            .enumerate()
            .map(|(i, n)| (n.into(), i as u16))
            .collect();
        Self { generic_idx }
    }

    /// Lower a `syn::Type` to a `bloom_objects::TypeTag`.
    ///
    /// Rules (spec §8.2 / §11.2):
    /// - `T` (a generic name in scope) → `TypeTag::Generic { idx }`.
    /// - `SomeName<A, B>` (concrete path) → `TypeTag::Concrete { petal_hash:
    ///   [0; 32] (self), type_name, type_args }`.
    /// - References, slices, tuples, fn pointers, etc. are rejected.
    pub fn lower(&self, ty: &Type) -> syn::Result<TypeTag> {
        // Strip a single layer of `&` / `&mut` so callers can pass the
        // raw arg type and we apply consistent rules.
        let inner = match ty {
            Type::Reference(r) => r.elem.as_ref(),
            other => other,
        };

        let path = match inner {
            Type::Path(TypePath { path, qself: None }) => path,
            _ => {
                return Err(err_spanned(
                    ty,
                    "only path types are supported in object fields / function args",
                ));
            }
        };

        // We always look at the last path segment for the type name.
        // We *also* reject anything that isn't a single-segment path
        // (no `::` qualification) because the macro emits the bare type
        // name into the manifest and the chain resolves it within the
        // same petal scope.
        if path.segments.len() != 1 {
            return Err(err_spanned(
                ty,
                "qualified paths are not supported; use the unqualified type name",
            ));
        }

        let seg = path.segments.first().expect("checked len == 1");
        let name = seg.ident.to_string();

        // Bare generic reference: `T`, where `T` is in scope.
        if matches!(seg.arguments, PathArguments::None) {
            if let Some(idx) = self.generic_idx.get(&name) {
                return Ok(TypeTag::Generic { idx: *idx });
            }
            return Ok(TypeTag::Concrete {
                petal_hash: [0u8; 32],
                type_name: name,
                type_args: Vec::new(),
            });
        }

        // Otherwise: `Foo<A, B, ...>`.
        let mut type_args = Vec::new();
        if let PathArguments::AngleBracketed(args) = &seg.arguments {
            for arg in &args.args {
                match arg {
                    GenericArgument::Type(t) => {
                        type_args.push(self.lower(t)?);
                    }
                    GenericArgument::Lifetime(_) => {
                        // Lifetimes don't show up in `TypeTag`; ignore.
                    }
                    other => {
                        return Err(err_spanned(
                            other,
                            "only type arguments are supported in `TypeTag` positions",
                        ));
                    }
                }
            }
        }

        Ok(TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name,
            type_args,
        })
    }
}

/// Reject plain generic types in payload positions (spec §11.2: `T` is
/// only allowed in TypeTag-bearing positions; payload usage must go
/// through `Resource<T>`).
///
/// Returns `Ok(())` if `ty` is not a plain generic reference, or if it
/// *is* but does not appear in `non_phantom`. Returns `Err` if `ty` is
/// a plain non-phantom generic that the caller therefore needs to wrap.
pub(crate) fn reject_plain_generic_in_payload(
    ty: &Type,
    non_phantom: &[String],
) -> syn::Result<()> {
    // Walk through one reference layer (`&T`).
    let inner = match ty {
        Type::Reference(r) => r.elem.as_ref(),
        other => other,
    };
    let Type::Path(TypePath { path, qself: None }) = inner else {
        return Ok(());
    };
    if path.segments.len() != 1 {
        return Ok(());
    }
    let seg = path.segments.first().expect("checked len == 1");
    if !matches!(seg.arguments, PathArguments::None) {
        return Ok(());
    }
    let name = seg.ident.to_string();
    if non_phantom.iter().any(|n| n == &name) {
        return Err(err_spanned(
            ty,
            format!(
                "plain generic `{}` is not allowed in field/arg position; \
                 wrap with `Resource<{}>` (spec §11.2)",
                name, name
            ),
        ));
    }
    Ok(())
}

/// If `ty` (after stripping one `&`/`&mut` layer) is `Resource<Inner>`,
/// return `Inner`; otherwise return `ty` unchanged.
///
/// `Resource<T>` is the petal-side *handle wrapper* around an on-chain `T`
/// object — it never appears in the on-chain type system. So the declared
/// type recorded in the manifest for a `Resource<T>` arg / return must be
/// `T`'s tag, not `Resource<T>` (spec §11.2). The codegen shim still
/// materializes the full `Resource<T>` for the user fn; only the manifest
/// type is unwrapped.
pub(crate) fn strip_resource_wrapper(ty: &Type) -> &Type {
    let inner = match ty {
        Type::Reference(r) => r.elem.as_ref(),
        other => other,
    };
    let Type::Path(TypePath { path, qself: None }) = inner else {
        return ty;
    };
    let Some(seg) = path.segments.last() else {
        return ty;
    };
    if seg.ident != "Resource" {
        return ty;
    }
    if let PathArguments::AngleBracketed(args) = &seg.arguments {
        for a in &args.args {
            if let GenericArgument::Type(t) = a {
                return t;
            }
        }
    }
    ty
}

/// True iff `ty` is `Resource<...>` (single-segment).
pub(crate) fn is_resource_wrapper(ty: &Type) -> bool {
    let inner = match ty {
        Type::Reference(r) => r.elem.as_ref(),
        other => other,
    };
    let Type::Path(TypePath { path, qself: None }) = inner else {
        return false;
    };
    path.segments
        .last()
        .map(|s| s.ident == "Resource")
        .unwrap_or(false)
}

/// True iff `ty` is `Coin<...>` or `Balance<...>` (the linear value
/// wrappers from `bloom-resource`).
pub(crate) fn is_value_wrapper(ty: &Type) -> bool {
    let inner = match ty {
        Type::Reference(r) => r.elem.as_ref(),
        other => other,
    };
    let Type::Path(TypePath { path, qself: None }) = inner else {
        return false;
    };
    let Some(last) = path.segments.last() else {
        return false;
    };
    last.ident == "Coin" || last.ident == "Balance"
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn lower(ty: proc_macro2::TokenStream, generics: &[&str]) -> TypeTag {
        let parsed: Type = syn::parse2(ty).unwrap();
        let ctx = TypeTagCtx::from_generic_names(generics.iter().map(|s| s.to_string()));
        ctx.lower(&parsed).unwrap()
    }

    #[test]
    fn concrete_no_args() {
        let t = lower(quote! { Pool }, &[]);
        match t {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, [0; 32]);
                assert_eq!(type_name, "Pool");
                assert!(type_args.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn concrete_with_args() {
        let t = lower(quote! { Pool<A, B> }, &["A", "B"]);
        match t {
            TypeTag::Concrete {
                type_name,
                type_args,
                ..
            } => {
                assert_eq!(type_name, "Pool");
                assert_eq!(type_args.len(), 2);
                assert_eq!(type_args[0], TypeTag::Generic { idx: 0 });
                assert_eq!(type_args[1], TypeTag::Generic { idx: 1 });
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn bare_generic_becomes_generic_idx() {
        let t = lower(quote! { A }, &["A"]);
        assert_eq!(t, TypeTag::Generic { idx: 0 });
        let t = lower(quote! { B }, &["A", "B"]);
        assert_eq!(t, TypeTag::Generic { idx: 1 });
    }

    #[test]
    fn nested_concrete_with_generic_args() {
        let t = lower(quote! { Coin<USDC> }, &[]);
        match t {
            TypeTag::Concrete {
                type_name,
                type_args,
                ..
            } => {
                assert_eq!(type_name, "Coin");
                assert_eq!(type_args.len(), 1);
                assert!(matches!(
                    &type_args[0],
                    TypeTag::Concrete { type_name, .. } if type_name == "USDC"
                ));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn reference_stripped() {
        let t = lower(quote! { &Pool }, &[]);
        match t {
            TypeTag::Concrete { type_name, .. } => assert_eq!(type_name, "Pool"),
            _ => panic!("wrong variant"),
        }
        let t = lower(quote! { &mut Pool }, &[]);
        match t {
            TypeTag::Concrete { type_name, .. } => assert_eq!(type_name, "Pool"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn qualified_path_rejected() {
        let ty: Type = syn::parse2(quote! { foo::Bar }).unwrap();
        let ctx = TypeTagCtx::default();
        assert!(ctx.lower(&ty).is_err());
    }

    #[test]
    fn tuple_rejected() {
        let ty: Type = syn::parse2(quote! { (u8, u8) }).unwrap();
        let ctx = TypeTagCtx::default();
        assert!(ctx.lower(&ty).is_err());
    }

    #[test]
    fn reject_plain_generic_in_payload_flags_t() {
        let ty: Type = syn::parse2(quote! { T }).unwrap();
        assert!(reject_plain_generic_in_payload(&ty, &["T".to_string()]).is_err());
    }

    #[test]
    fn reject_plain_generic_in_payload_allows_concrete() {
        let ty: Type = syn::parse2(quote! { u128 }).unwrap();
        assert!(reject_plain_generic_in_payload(&ty, &["T".to_string()]).is_ok());
    }

    #[test]
    fn reject_plain_generic_in_payload_allows_resource_wrap() {
        let ty: Type = syn::parse2(quote! { Resource<T> }).unwrap();
        assert!(reject_plain_generic_in_payload(&ty, &["T".to_string()]).is_ok());
    }

    #[test]
    fn is_resource_wrapper_recognizes() {
        let ty: Type = syn::parse2(quote! { Resource<T> }).unwrap();
        assert!(is_resource_wrapper(&ty));
        let ty: Type = syn::parse2(quote! { Pool<A> }).unwrap();
        assert!(!is_resource_wrapper(&ty));
    }

    #[test]
    fn is_value_wrapper_recognizes() {
        let ty: Type = syn::parse2(quote! { Coin<USDC> }).unwrap();
        assert!(is_value_wrapper(&ty));
        let ty: Type = syn::parse2(quote! { Balance<USDC> }).unwrap();
        assert!(is_value_wrapper(&ty));
        let ty: Type = syn::parse2(quote! { Pool<A> }).unwrap();
        assert!(!is_value_wrapper(&ty));
    }
}
