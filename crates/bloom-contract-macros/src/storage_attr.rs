//! `#[storage]` attribute macro — placed on a contract's `State` struct.
//!
//! The macro keeps the user's struct definition unchanged and generates:
//!
//! - `impl State { pub fn load(_ctx: &Context) -> Result<Self> { ... } }` —
//!   constructs each typed handle with its derived slot or prefix.
//! - `impl State { pub const SCHEMA: &'static [StorageEntry] = &[ ... ]; }` —
//!   a manifest-ready descriptor for every field, picked up by the build
//!   crate.
//!
//! # Syntax
//!
//! ```ignore
//! #[storage(domain = "erc20")]
//! pub struct State {
//!     pub total_supply: StorageValue<U256>,
//!     #[storage(compat_tag = "erc20.balance:")]
//!     pub balances: Map<Address, U256>,
//!     pub all_pairs: VecStore<Address>,
//! }
//! ```
//!
//! `domain` defaults to the snake_case of the struct name when omitted; it's
//! the leading segment of every new-rule slot key derived for this struct.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    AngleBracketedGenericArguments, Attribute, Data, DeriveInput, Field, Fields, GenericArgument,
    Ident, LitStr, PathArguments, Type, TypePath, parse_macro_input,
};

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let struct_name = input.ident.clone();

    // Parse `#[storage]` or `#[storage(domain = "...")]`.
    let mut domain_override: Option<String> = None;
    let attr_parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("domain") {
            let v: LitStr = meta.value()?.parse()?;
            domain_override = Some(v.value());
            Ok(())
        } else {
            Err(meta.error("expected `domain = \"...\"`"))
        }
    });
    if let Err(e) = syn::parse::Parser::parse(attr_parser, attr) {
        return e.to_compile_error().into();
    }
    let domain = domain_override.unwrap_or_else(|| pascal_to_snake(&struct_name.to_string()));

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => &n.named,
            _ => {
                return syn::Error::new_spanned(
                    &input.ident,
                    "#[storage] only supports structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                &input.ident,
                "#[storage] only supports structs",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut load_inits: Vec<TokenStream2> = Vec::new();
    let mut schema_entries: Vec<TokenStream2> = Vec::new();

    for field in fields {
        match build_field(&domain, field) {
            Ok((init, entry)) => {
                load_inits.push(init);
                schema_entries.push(entry);
            }
            Err(e) => return e.to_compile_error().into(),
        }
    }

    // Strip our per-field `#[storage(...)]` attributes from the emitted struct
    // so the compiler doesn't see an unknown attribute on a plain struct field.
    let mut sanitized = input.clone();
    if let Data::Struct(s) = &mut sanitized.data
        && let Fields::Named(n) = &mut s.fields {
            for f in n.named.iter_mut() {
                f.attrs.retain(|a| !a.path().is_ident("storage"));
            }
        }

    let domain_lit = LitStr::new(&domain, proc_macro2::Span::call_site());

    quote! {
        #sanitized

        impl #struct_name {
            /// Storage domain — first segment of every new-rule slot key.
            pub const STORAGE_DOMAIN: &'static str = #domain_lit;

            /// Layout descriptor consumed by the manifest emitter.
            pub const SCHEMA: &'static [::bloom_contract::storage::StorageEntry] = &[
                #(#schema_entries,)*
            ];

            /// Construct typed storage handles. Returns `Ok` unconditionally
            /// today; the `Result` shape future-proofs the API against
            /// upcoming runtime-checked migrations.
            pub fn load(
                _ctx: &::bloom_contract::context::Context,
            ) -> ::bloom_contract::error::Result<Self> {
                ::core::result::Result::Ok(Self {
                    #(#load_inits,)*
                })
            }
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

/// Per-field `#[storage(compat_tag = "...")]`.
fn parse_compat_tag(attrs: &[Attribute]) -> syn::Result<Option<String>> {
    for a in attrs {
        if !a.path().is_ident("storage") {
            continue;
        }
        let mut tag: Option<String> = None;
        // Both `#[storage(compat_tag = "...")]` and bare `#[storage]` (no-op)
        // are accepted on fields.
        if let syn::Meta::List(list) = &a.meta {
            list.parse_nested_meta(|nested| {
                if nested.path.is_ident("compat_tag") {
                    let v: LitStr = nested.value()?.parse()?;
                    tag = Some(v.value());
                    Ok(())
                } else {
                    Err(nested.error("expected `compat_tag = \"...\"`"))
                }
            })?;
        }
        return Ok(tag);
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Field expansion
// ---------------------------------------------------------------------------

enum FieldShape<'a> {
    Scalar(&'a Type),
    Map(&'a Type, &'a Type),
    Vec(&'a Type),
}

fn build_field(domain: &str, field: &Field) -> syn::Result<(TokenStream2, TokenStream2)> {
    let ident = field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new_spanned(field, "expected named field"))?;
    let name = ident.to_string();
    let compat = parse_compat_tag(&field.attrs)?;

    let shape = classify(&field.ty).ok_or_else(|| {
        syn::Error::new_spanned(
            &field.ty,
            "field type must be StorageValue<T>, Map<K, V>, or VecStore<T>",
        )
    })?;

    let name_lit = LitStr::new(&name, proc_macro2::Span::call_site());
    let domain_lit = LitStr::new(domain, proc_macro2::Span::call_site());

    Ok(match shape {
        FieldShape::Scalar(inner) => scalar_field(ident, &name_lit, &domain_lit, inner, compat),
        FieldShape::Map(k, v) => map_field(ident, &name_lit, &domain_lit, k, v, compat),
        FieldShape::Vec(inner) => vec_field(ident, &name_lit, &domain_lit, inner, compat),
    })
}

fn scalar_field(
    ident: &Ident,
    name_lit: &LitStr,
    domain_lit: &LitStr,
    inner: &Type,
    compat: Option<String>,
) -> (TokenStream2, TokenStream2) {
    let slot_expr = match &compat {
        Some(tag) => {
            // Legacy rule for scalars: slot = blake3(compat_tag).
            // The tag is hashed at runtime in const-friendly fashion via
            // the public `slot_for_compat_tag` helper.
            let tag_lit = LitStr::new(tag, proc_macro2::Span::call_site());
            quote! {
                ::bloom_contract::storage::slot_for_compat_tag(#tag_lit)
            }
        }
        None => quote! {
            ::bloom_contract::storage::slot_for_field(#domain_lit, #name_lit)
        },
    };

    let compat_tok = match compat {
        Some(tag) => {
            let l = LitStr::new(&tag, proc_macro2::Span::call_site());
            quote! { ::core::option::Option::Some(#l) }
        }
        None => quote! { ::core::option::Option::None },
    };

    let init = quote! {
        #ident: ::bloom_contract::storage::StorageValue::<#inner>::new(#slot_expr)
    };

    let entry = quote! {
        ::bloom_contract::storage::StorageEntry {
            name: #name_lit,
            kind: ::bloom_contract::storage::StorageKind::Scalar {
                ty: <#inner as ::bloom_contract::abi::AbiType>::ABI_TYPE,
            },
            compat_tag: #compat_tok,
            prefix: &[],
        }
    };

    (init, entry)
}

fn map_field(
    ident: &Ident,
    name_lit: &LitStr,
    domain_lit: &LitStr,
    k: &Type,
    v: &Type,
    compat: Option<String>,
) -> (TokenStream2, TokenStream2) {
    let (prefix_expr, compat_tok) = match &compat {
        Some(tag) => {
            let tag_lit = LitStr::new(tag, proc_macro2::Span::call_site());
            (
                // Legacy mapping rule: prefix = the tag bytes verbatim.
                quote! { #tag_lit.as_bytes() },
                {
                    let l = LitStr::new(tag, proc_macro2::Span::call_site());
                    quote! { ::core::option::Option::Some(#l) }
                },
            )
        }
        None => (
            quote! {
                ::core::concat!("storage:", #domain_lit, ":", #name_lit, ":").as_bytes()
            },
            quote! { ::core::option::Option::None },
        ),
    };

    let init = quote! {
        #ident: ::bloom_contract::storage::Map::<#k, #v>::new(#prefix_expr)
    };

    let entry = quote! {
        ::bloom_contract::storage::StorageEntry {
            name: #name_lit,
            kind: ::bloom_contract::storage::StorageKind::Map {
                key_ty: <#k as ::bloom_contract::abi::AbiType>::ABI_TYPE,
                value_ty: <#v as ::bloom_contract::abi::AbiType>::ABI_TYPE,
            },
            compat_tag: #compat_tok,
            prefix: #prefix_expr,
        }
    };

    (init, entry)
}

fn vec_field(
    ident: &Ident,
    name_lit: &LitStr,
    domain_lit: &LitStr,
    inner: &Type,
    compat: Option<String>,
) -> (TokenStream2, TokenStream2) {
    let slot_expr = match &compat {
        Some(tag) => {
            let tag_lit = LitStr::new(tag, proc_macro2::Span::call_site());
            quote! { ::bloom_contract::storage::slot_for_compat_tag(#tag_lit) }
        }
        None => quote! {
            ::bloom_contract::storage::slot_for_field(#domain_lit, #name_lit)
        },
    };

    let compat_tok = match compat {
        Some(tag) => {
            let l = LitStr::new(&tag, proc_macro2::Span::call_site());
            quote! { ::core::option::Option::Some(#l) }
        }
        None => quote! { ::core::option::Option::None },
    };

    let init = quote! {
        #ident: ::bloom_contract::storage::VecStore::<#inner>::new(#slot_expr)
    };

    let entry = quote! {
        ::bloom_contract::storage::StorageEntry {
            name: #name_lit,
            kind: ::bloom_contract::storage::StorageKind::Vec {
                ty: <#inner as ::bloom_contract::abi::AbiType>::ABI_TYPE,
            },
            compat_tag: #compat_tok,
            prefix: &[],
        }
    };

    (init, entry)
}

// ---------------------------------------------------------------------------
// Type classification — matches on the last path segment so it works whether
// the user wrote `Map<A, B>` (prelude import) or `bloom_contract::storage::Map<A, B>`.
// ---------------------------------------------------------------------------

fn classify(ty: &Type) -> Option<FieldShape<'_>> {
    let p = match ty {
        Type::Path(TypePath { qself: None, path }) => path,
        _ => return None,
    };
    let seg = p.segments.last()?;
    match seg.ident.to_string().as_str() {
        "StorageValue" => first_generic(&seg.arguments).map(FieldShape::Scalar),
        "VecStore" => first_generic(&seg.arguments).map(FieldShape::Vec),
        "Map" => {
            let (k, v) = two_generics(&seg.arguments)?;
            Some(FieldShape::Map(k, v))
        }
        _ => None,
    }
}

fn first_generic(args: &PathArguments) -> Option<&Type> {
    let AngleBracketedGenericArguments { args, .. } = match args {
        PathArguments::AngleBracketed(a) => a,
        _ => return None,
    };
    args.iter().find_map(|a| match a {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    })
}

fn two_generics(args: &PathArguments) -> Option<(&Type, &Type)> {
    let AngleBracketedGenericArguments { args, .. } = match args {
        PathArguments::AngleBracketed(a) => a,
        _ => return None,
    };
    let mut tys = args.iter().filter_map(|a| match a {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    });
    let k = tys.next()?;
    let v = tys.next()?;
    Some((k, v))
}

// ---------------------------------------------------------------------------
// Naming
// ---------------------------------------------------------------------------

fn pascal_to_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

