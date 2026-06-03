//! `syn::Type` → `bloom_objects::TypeTag` lowering used by every macro
//! to record field / argument / return shapes in the manifest.
//!
//! Petal-defined `Concrete` TypeTags use `[0u8; 32]` as the `petal_hash`:
//! the macro cannot know its own crate's wasm hash at expansion time. Built-in
//! primitives/containers use `BUILTIN_TYPE_HASH`.

use std::collections::HashMap;

use bloom_objects::{BUILTIN_TYPE_HASH, TypeTag};
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
    /// - `SomeName<A, B>` (concrete path) → `TypeTag::Concrete`.
    /// - Built-ins are stamped with `BUILTIN_TYPE_HASH`; petal-defined types use
    ///   `[0; 32]` until publish-time self-reference stamping.
    /// - References are stripped; unsupported Rust type forms are rejected.
    pub fn lower(&self, ty: &Type) -> syn::Result<TypeTag> {
        // Strip a single layer of `&` / `&mut` so callers can pass the
        // raw arg type and we apply consistent rules.
        let inner = match ty {
            Type::Reference(r) => r.elem.as_ref(),
            other => other,
        };

        if let Type::Tuple(tuple) = inner {
            let type_args = tuple
                .elems
                .iter()
                .map(|elem| self.lower(elem))
                .collect::<syn::Result<Vec<_>>>()?;
            return Ok(TypeTag::Concrete {
                petal_hash: BUILTIN_TYPE_HASH,
                type_name: "tuple".to_string(),
                type_args,
            });
        }

        let path = match inner {
            Type::Path(TypePath { path, qself: None }) => path,
            _ => {
                return Err(err_spanned(
                    ty,
                    "only path and tuple types are supported in object fields / function args",
                ));
            }
        };

        // We always look at the last path segment for the type name.
        // Arbitrary qualified petal-local types remain rejected because
        // the manifest records the bare in-petal name. Qualified
        // framework wrappers are allowed so signatures can disambiguate
        // a handle wrapper from an object schema with the same logical
        // name, e.g. `bloom_resource::Coin<T>` inside the fungible petal
        // that declares the `Coin<T>` object.
        if path.segments.len() != 1 && !is_qualified_framework_wrapper(path) {
            return Err(err_spanned(
                ty,
                "qualified paths are not supported; use the unqualified type name",
            ));
        }

        let seg = path.segments.last().expect("path has at least one segment");
        let name = seg.ident.to_string();

        // Bare generic reference: `T`, where `T` is in scope.
        if matches!(seg.arguments, PathArguments::None) {
            if let Some(idx) = self.generic_idx.get(&name) {
                return Ok(TypeTag::Generic { idx: *idx });
            }
            let (petal_hash, type_name) = builtin_type_name(&name)
                .map(|builtin| (BUILTIN_TYPE_HASH, builtin.to_string()))
                .unwrap_or(([0u8; 32], name));
            return Ok(TypeTag::Concrete {
                petal_hash,
                type_name,
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

        let (petal_hash, type_name) = builtin_type_name(&name)
            .map(|builtin| (BUILTIN_TYPE_HASH, builtin.to_string()))
            .unwrap_or(([0u8; 32], name));
        Ok(TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args,
        })
    }
}

fn builtin_type_name(name: &str) -> Option<&'static str> {
    match name {
        "bool" => Some("bool"),
        "u8" => Some("u8"),
        "u16" => Some("u16"),
        "u32" => Some("u32"),
        "u64" => Some("u64"),
        "u128" => Some("u128"),
        "Address" => Some("Address"),
        "address" => Some("address"),
        "ObjectId" => Some("ObjectId"),
        "Hash32" => Some("Hash32"),
        "UID" => Some("UID"),
        "TypeTag" => Some("TypeTag"),
        "String" => Some("String"),
        "Bytes" | "bytes" => Some("bytes"),
        "Option" => Some("Option"),
        "Result" => Some("Result"),
        "Vec" | "vector" => Some("vector"),
        "BTreeMap" | "HashMap" | "map" => Some("map"),
        "BTreeSet" | "HashSet" | "set" => Some("set"),
        _ => None,
    }
}

fn is_qualified_framework_wrapper(path: &syn::Path) -> bool {
    let Some(first) = path.segments.first() else {
        return false;
    };
    let Some(last) = path.segments.last() else {
        return false;
    };
    first.ident == "bloom_resource"
        && matches!(
            last.ident.to_string().as_str(),
            "Coin" | "Balance" | "Capability" | "Resource" | "Bytes"
        )
}

/// Reject generic types in payload positions (spec §11.2: `T` is only
/// allowed in TypeTag-bearing positions; payload usage must go through
/// `Resource<T>`).
///
/// Returns `Ok(())` if `ty` contains no non-phantom generic payload use.
/// Returns `Err` if the generic appears directly or nested inside another
/// payload type. Bloom wrappers such as `Resource<T>` and `Capability<T>`
/// are allowed because they carry the type parameter in the type tag rather
/// than encoding a generic `T` payload field.
pub(crate) fn reject_plain_generic_in_payload(
    ty: &Type,
    non_phantom: &[String],
) -> syn::Result<()> {
    reject_generic_payload_inner(ty, non_phantom)
}

fn reject_generic_payload_inner(ty: &Type, non_phantom: &[String]) -> syn::Result<()> {
    match ty {
        Type::Reference(r) => reject_generic_payload_inner(&r.elem, non_phantom),
        Type::Tuple(tuple) => tuple
            .elems
            .iter()
            .try_for_each(|elem| reject_generic_payload_inner(elem, non_phantom)),
        Type::Paren(paren) => reject_generic_payload_inner(&paren.elem, non_phantom),
        Type::Group(group) => reject_generic_payload_inner(&group.elem, non_phantom),
        Type::Path(TypePath { path, qself: None }) if is_generic_payload_wrapper_path(path) => {
            Ok(())
        }
        Type::Path(TypePath { path, qself: None }) => {
            if path.segments.len() == 1 {
                let seg = path.segments.first().expect("checked len == 1");
                if matches!(seg.arguments, PathArguments::None) {
                    let name = seg.ident.to_string();
                    if non_phantom.iter().any(|n| n == &name) {
                        return generic_payload_err(ty, &name);
                    }
                }
            }
            for segment in &path.segments {
                match &segment.arguments {
                    PathArguments::None => {}
                    PathArguments::AngleBracketed(args) => {
                        for arg in &args.args {
                            if let GenericArgument::Type(inner) = arg {
                                reject_generic_payload_inner(inner, non_phantom)?;
                            }
                        }
                    }
                    PathArguments::Parenthesized(args) => {
                        for input in &args.inputs {
                            reject_generic_payload_inner(input, non_phantom)?;
                        }
                        if let syn::ReturnType::Type(_, output) = &args.output {
                            reject_generic_payload_inner(output, non_phantom)?;
                        }
                    }
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn generic_payload_err(ty: &Type, name: &str) -> syn::Result<()> {
    Err(err_spanned(
        ty,
        format!(
            "plain generic `{}` is not allowed in field/arg position; \
             wrap with `Resource<{}>` (spec §11.2)",
            name, name
        ),
    ))
}

fn is_generic_payload_wrapper_path(path: &syn::Path) -> bool {
    let Some(seg) = path.segments.last() else {
        return false;
    };
    if !matches!(
        seg.ident.to_string().as_str(),
        "Resource" | "Capability" | "Coin" | "Balance"
    ) {
        return false;
    }
    if path.segments.len() > 1 && !is_qualified_framework_wrapper(path) {
        return false;
    }
    matches!(seg.arguments, PathArguments::AngleBracketed(_))
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
    fn qualified_framework_coin_lowers_by_last_segment() {
        let ty: Type = syn::parse2(quote! { bloom_resource::Coin<T> }).unwrap();
        let ctx = TypeTagCtx::from_generic_names(["T"]);
        match ctx.lower(&ty).unwrap() {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, [0u8; 32]);
                assert_eq!(type_name, "Coin");
                assert_eq!(type_args, vec![TypeTag::Generic { idx: 0 }]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn tuple_lowers_to_builtin_tuple() {
        let ty: Type = syn::parse2(quote! { (u8, u8) }).unwrap();
        let ctx = TypeTagCtx::default();
        match ctx.lower(&ty).unwrap() {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, BUILTIN_TYPE_HASH);
                assert_eq!(type_name, "tuple");
                assert_eq!(type_args.len(), 2);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn primitive_lowers_to_builtin_hash() {
        match lower(quote! { u64 }, &[]) {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, BUILTIN_TYPE_HASH);
                assert_eq!(type_name, "u64");
                assert!(type_args.is_empty());
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn vec_lowers_to_builtin_vector() {
        match lower(quote! { Vec<String> }, &[]) {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, BUILTIN_TYPE_HASH);
                assert_eq!(type_name, "vector");
                assert_eq!(type_args.len(), 1);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn bytes_lowers_to_builtin_bytes() {
        match lower(quote! { Bytes }, &[]) {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, BUILTIN_TYPE_HASH);
                assert_eq!(type_name, "bytes");
                assert!(type_args.is_empty());
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn qualified_bytes_lowers_to_builtin_bytes() {
        match lower(quote! { bloom_resource::Bytes }, &[]) {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, BUILTIN_TYPE_HASH);
                assert_eq!(type_name, "bytes");
                assert!(type_args.is_empty());
            }
            other => panic!("wrong variant: {other:?}"),
        }
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
    fn reject_plain_generic_in_payload_flags_nested_generic_payloads() {
        for src in [
            "Option<T>",
            "Vec<T>",
            "(u64, T)",
            "BTreeMap<T, u64>",
            "Foo<T>",
        ] {
            let ty: Type = syn::parse_str(src).unwrap();
            assert!(
                reject_plain_generic_in_payload(&ty, &["T".to_string()]).is_err(),
                "expected nested generic payload to be rejected: {src}"
            );
        }
    }

    #[test]
    fn reject_plain_generic_in_payload_allows_nested_resource_wrap() {
        let ty: Type = syn::parse2(quote! { Option<Resource<T>> }).unwrap();
        assert!(reject_plain_generic_in_payload(&ty, &["T".to_string()]).is_ok());
        let ty: Type = syn::parse2(quote! { Capability<MintCap<T>> }).unwrap();
        assert!(reject_plain_generic_in_payload(&ty, &["T".to_string()]).is_ok());
        let ty: Type = syn::parse2(quote! { bloom_resource::Coin<T> }).unwrap();
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
