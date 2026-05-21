//! `#[capability]` struct attribute (spec §5).
//!
//! Capabilities are sugar for `#[object(abilities = "key, store, copy")]`
//! plus a `CapabilityMarker` impl. Holders can mint clones via `copy`
//! but cannot drop them silently — they must be `delete()`d via the
//! `cap.revoke` host import.
//!
//! The macro accepts an optional `phantom = "T, U"` like `#[object]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Attribute, GenericParam, ItemStruct, Meta};

use crate::ast::{attr_is_named, ident, parse_ident_list, parse_str_value, struct_name};
use crate::error::err_spanned;
use bloom_petal_manifest::types::{CapabilityDecl, TypeParamDecl, TypeParamKind};
use syn::spanned::Spanned;

/// Parsed `#[capability(...)]` attribute.
#[derive(Debug, Default, Clone)]
pub(crate) struct CapabilityAttr {
    /// Phantom generic-param names.
    pub phantom: Vec<String>,
}

impl CapabilityAttr {
    /// Parse `(phantom = "T, U")` style attribute args.
    pub fn parse(attr: TokenStream) -> syn::Result<Self> {
        if attr.is_empty() {
            return Ok(Self::default());
        }
        let attr_text = format!("#[capability({})]", attr);
        let attrs: Vec<Attribute> =
            syn::parse::Parser::parse_str(Attribute::parse_outer, &attr_text)?;
        let outer = attrs.into_iter().next().ok_or_else(|| {
            syn::Error::new(
                proc_macro2::Span::call_site(),
                "expected `#[capability(...)]`",
            )
        })?;
        let mut out = Self::default();
        if let Meta::List(list) = &outer.meta {
            let nested = list.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            )?;
            for meta in nested {
                match &meta {
                    Meta::NameValue(nv) if nv.path.is_ident("phantom") => {
                        let raw = parse_str_value(nv)?;
                        out.phantom = parse_ident_list(&raw, nv.value.span())?;
                    }
                    other => {
                        return Err(err_spanned(
                            other,
                            "unknown #[capability] argument; expected `phantom = \"...\"`",
                        ));
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Build the manifest [`CapabilityDecl`] from the user struct.
pub(crate) fn build_decl(item: &ItemStruct, attr: &CapabilityAttr) -> syn::Result<CapabilityDecl> {
    let name = struct_name(item);
    let mut type_params = Vec::new();
    let mut generic_names = Vec::new();
    for p in &item.generics.params {
        if let GenericParam::Type(t) = p {
            let n = t.ident.to_string();
            let kind = if attr.phantom.iter().any(|p| p == &n) {
                TypeParamKind::Phantom
            } else {
                TypeParamKind::Resource
            };
            type_params.push(TypeParamDecl {
                name: n.clone(),
                kind,
                bounds: Vec::new(),
            });
            generic_names.push(n);
        }
    }
    for declared in &attr.phantom {
        if !generic_names.iter().any(|n| n == declared) {
            return Err(syn::Error::new(
                item.ident.span(),
                format!(
                    "phantom parameter `{}` is not a generic of capability `{}`",
                    declared, name
                ),
            ));
        }
    }
    Ok(CapabilityDecl { name, type_params })
}

/// Macro entry: re-emit the user struct plus a `CapabilityMarker` impl.
pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let parsed: ItemStruct = syn::parse2(item)?;
    let attr = CapabilityAttr::parse(attr)?;
    let _decl = build_decl(&parsed, &attr)?;

    let mut output = parsed.clone();
    output.attrs.retain(|a| !attr_is_named(a, "capability"));

    let name = &parsed.ident;
    let (impl_gen, ty_gen, where_clause) = parsed.generics.split_for_impl();

    let abilities_marker = ident(
        &format!("__BLOOM_CAPABILITY_{}__ABILITIES", parsed.ident),
        proc_macro2::Span::call_site(),
    );

    // key | store | copy = 0b0111 = 7
    let abilities_byte: u8 = 0b0111;

    Ok(quote! {
        #output

        impl #impl_gen ::bloom_resource::CapabilityMarker for #name #ty_gen #where_clause {}

        /// Ability bits implied by `#[capability]` (`key | store | copy`).
        /// Auto-generated; read by the petal-level macro.
        #[allow(non_upper_case_globals, dead_code)]
        pub(crate) const #abilities_marker: u8 = #abilities_byte;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn parse_empty_attr() {
        let a = CapabilityAttr::parse(TokenStream::new()).unwrap();
        assert!(a.phantom.is_empty());
    }

    #[test]
    fn parse_phantom_list() {
        let a = CapabilityAttr::parse(quote! { phantom = "T" }).unwrap();
        assert_eq!(a.phantom, vec!["T"]);
    }

    #[test]
    fn parse_rejects_unknown_arg() {
        let r = CapabilityAttr::parse(quote! { abilities = "key" });
        assert!(r.is_err());
    }

    #[test]
    fn build_decl_collects_generics() {
        let s: ItemStruct = syn::parse2(quote! {
            pub struct AdminCap<T> { id: UID }
        })
        .unwrap();
        let a = CapabilityAttr::parse(quote! { phantom = "T" }).unwrap();
        let d = build_decl(&s, &a).unwrap();
        assert_eq!(d.name, "AdminCap");
        assert_eq!(d.type_params.len(), 1);
        assert!(matches!(d.type_params[0].kind, TypeParamKind::Phantom));
    }

    #[test]
    fn build_decl_rejects_phantom_not_in_generics() {
        let s: ItemStruct = syn::parse2(quote! {
            pub struct AdminCap { id: UID }
        })
        .unwrap();
        let a = CapabilityAttr::parse(quote! { phantom = "T" }).unwrap();
        assert!(build_decl(&s, &a).is_err());
    }

    #[test]
    fn expand_emits_capability_marker_impl() {
        let toks = expand(
            TokenStream::new(),
            quote! { pub struct AdminCap { id: UID } },
        )
        .unwrap();
        let s = toks.to_string();
        assert!(s.contains("CapabilityMarker"));
        assert!(s.contains("AdminCap"));
        assert!(s.contains("__BLOOM_CAPABILITY_AdminCap__ABILITIES"));
    }
}
