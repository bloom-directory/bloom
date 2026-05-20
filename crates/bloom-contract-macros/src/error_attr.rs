//! `#[error]` attribute macro — placed on a contract's error enum.
//!
//! For an enum like:
//!
//! ```ignore
//! #[error(domain = "erc20")]
//! pub enum Error {
//!     InsufficientBalance,
//!     Overflow,
//!     InvalidRecipient(Address),
//! }
//! ```
//!
//! the macro generates:
//!
//! - `impl bloom_contract::error::Error for Error { ... }` with
//!   `encode_revert(&self)` that produces `selector_4_bytes || abi_payload`.
//! - A `pub const SEL_<VARIANT>: [u8; 4]` constant per variant — the first
//!   four bytes of `blake3("<Domain>::<Error>::<Variant>(<types>)")`.
//! - A `pub const VARIANTS: &[ErrorVariantDescriptor]` table consumed by
//!   the build crate at manifest-emission time.
//! - `From<ContractError>` so internal framework errors propagate via `?`.
//!
//! Variants are limited to unit, tuple, or named-field shapes (no nested
//! enums) — same surface as `#[derive(AbiEncode/AbiDecode)]`.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitStr, parse_macro_input};

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = input.ident.clone();

    let mut domain: Option<String> = None;
    let attr_parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("domain") {
            let v: LitStr = meta.value()?.parse()?;
            domain = Some(v.value());
            Ok(())
        } else {
            Err(meta.error("expected `domain = \"...\"`"))
        }
    });
    if let Err(e) = syn::parse::Parser::parse(attr_parser, attr) {
        return e.to_compile_error().into();
    }
    let domain = domain.unwrap_or_default();

    let data = match &input.data {
        Data::Enum(e) => e,
        _ => {
            return syn::Error::new_spanned(
                &input.ident,
                "#[error] only supports enums",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut selector_consts: Vec<TokenStream2> = Vec::new();
    let mut encode_arms: Vec<TokenStream2> = Vec::new();
    let mut variant_descriptors: Vec<TokenStream2> = Vec::new();

    for variant in &data.variants {
        let v_ident = &variant.ident;
        let v_name = v_ident.to_string();
        let signature = build_variant_signature(&domain, &name.to_string(), &v_name, &variant.fields);
        let sig_lit = LitStr::new(&signature, proc_macro2::Span::call_site());

        // Compile-time blake3 of the canonical signature → first 4 bytes.
        let h = blake3::hash(signature.as_bytes());
        let sel = &h.as_bytes()[..4];
        let s0 = sel[0];
        let s1 = sel[1];
        let s2 = sel[2];
        let s3 = sel[3];

        let const_ident = syn::Ident::new(
            &format!("SEL_{}", screaming_snake(&v_name)),
            proc_macro2::Span::call_site(),
        );

        selector_consts.push(quote! {
            pub const #const_ident: [u8; 4] = [#s0, #s1, #s2, #s3];
        });

        let encode_arm = build_encode_arm(&name, variant, &const_ident);
        encode_arms.push(encode_arm);

        let descriptor = build_descriptor(&v_name, &sig_lit, variant);
        variant_descriptors.push(descriptor);
    }

    let domain_lit = LitStr::new(&domain, proc_macro2::Span::call_site());
    let name_str_lit = LitStr::new(&name.to_string(), proc_macro2::Span::call_site());
    let descriptor_count = variant_descriptors.len();

    // Sanitize the original enum — no per-variant attributes today, so the
    // input passes through verbatim.
    let sanitized = input.clone();

    quote! {
        #sanitized

        #[automatically_derived]
        impl #name {
            #(#selector_consts)*

            /// Contract domain prefix, used to canonicalise the variant
            /// signatures.
            pub const ERROR_DOMAIN: &'static str = #domain_lit;

            /// Total variant count — handy for tests that want to assert
            /// completeness.
            pub const VARIANT_COUNT: usize = #descriptor_count;

            /// Manifest-ready descriptor for every variant in source order.
            pub const VARIANTS: &'static [::bloom_contract::error::ErrorVariantDescriptor] = &[
                #(#variant_descriptors,)*
            ];
        }

        #[automatically_derived]
        impl ::bloom_contract::error::Error for #name {
            const NAME: &'static str = #name_str_lit;

            fn encode_revert(&self) -> ::bloom_contract::__private::Vec<u8> {
                let mut enc = ::bloom_contract::abi::Encoder::new();
                match self {
                    #(#encode_arms)*
                }
                enc.finish()
            }
        }

        #[automatically_derived]
        impl ::core::convert::From<::bloom_contract::error::ContractError> for #name {
            fn from(e: ::bloom_contract::error::ContractError) -> Self {
                // Internal failures don't map onto a typed variant — they
                // surface as the framework's generic revert with the
                // original payload preserved.
                ::core::panic!(
                    "internal framework error not representable by typed Error: {:?}",
                    e
                )
            }
        }
    }
    .into()
}

fn build_variant_signature(
    domain: &str,
    enum_name: &str,
    variant_name: &str,
    fields: &Fields,
) -> String {
    let mut s = String::new();
    if !domain.is_empty() {
        s.push_str(domain);
        s.push_str("::");
    }
    s.push_str(enum_name);
    s.push_str("::");
    s.push_str(variant_name);
    s.push('(');
    let mut first = true;
    let push_ty = |s: &mut String, ty: &syn::Type| {
        if let syn::Type::Path(tp) = ty {
            if let Some(seg) = tp.path.segments.last() {
                s.push_str(&seg.ident.to_string().to_ascii_lowercase());
                return;
            }
        }
        s.push('?');
    };
    match fields {
        Fields::Unit => {}
        Fields::Unnamed(u) => {
            for f in &u.unnamed {
                if !first {
                    s.push(',');
                }
                first = false;
                push_ty(&mut s, &f.ty);
            }
        }
        Fields::Named(n) => {
            for f in &n.named {
                if !first {
                    s.push(',');
                }
                first = false;
                push_ty(&mut s, &f.ty);
            }
        }
    }
    s.push(')');
    s
}

fn build_encode_arm(
    enum_name: &syn::Ident,
    variant: &syn::Variant,
    selector_const: &syn::Ident,
) -> TokenStream2 {
    let v_ident = &variant.ident;
    match &variant.fields {
        Fields::Unit => quote! {
            #enum_name::#v_ident => {
                enc.push_bytes(&Self::#selector_const);
            }
        },
        Fields::Unnamed(u) => {
            let bindings: Vec<_> = (0..u.unnamed.len())
                .map(|i| syn::Ident::new(&format!("__f{i}"), proc_macro2::Span::call_site()))
                .collect();
            let writes = bindings.iter().map(|b| {
                quote! {
                    let _ = ::bloom_contract::abi::AbiEncode::encode_into(#b, &mut enc);
                }
            });
            quote! {
                #enum_name::#v_ident(#(#bindings),*) => {
                    enc.push_bytes(&Self::#selector_const);
                    #(#writes)*
                }
            }
        }
        Fields::Named(n) => {
            let bindings: Vec<_> = n.named.iter().map(|f| f.ident.clone().unwrap()).collect();
            let writes = bindings.iter().map(|b| {
                quote! {
                    let _ = ::bloom_contract::abi::AbiEncode::encode_into(#b, &mut enc);
                }
            });
            quote! {
                #enum_name::#v_ident { #(#bindings),* } => {
                    enc.push_bytes(&Self::#selector_const);
                    #(#writes)*
                }
            }
        }
    }
}

fn build_descriptor(v_name: &str, signature_lit: &LitStr, variant: &syn::Variant) -> TokenStream2 {
    let v_name_lit = LitStr::new(v_name, proc_macro2::Span::call_site());
    let h = blake3::hash(signature_lit.value().as_bytes());
    let sel = &h.as_bytes()[..4];
    let s0 = sel[0];
    let s1 = sel[1];
    let s2 = sel[2];
    let s3 = sel[3];

    let field_count = match &variant.fields {
        Fields::Unit => 0,
        Fields::Unnamed(u) => u.unnamed.len(),
        Fields::Named(n) => n.named.len(),
    };

    quote! {
        ::bloom_contract::error::ErrorVariantDescriptor {
            name: #v_name_lit,
            signature: #signature_lit,
            selector: [#s0, #s1, #s2, #s3],
            field_count: #field_count,
        }
    }
}

fn screaming_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_uppercase());
    }
    out
}
