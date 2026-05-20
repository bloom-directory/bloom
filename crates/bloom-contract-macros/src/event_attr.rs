//! `#[event]` attribute macro — placed on a struct that represents a log
//! event. The macro:
//!
//! - Derives [`AbiEncode`] / [`AbiDecode`] / [`AbiType`] for the struct so
//!   handlers can encode the payload bytes.
//! - Generates a `TOPIC0: [u8; 32]` constant — `blake3("event:<Domain>::<Name>(<types>)")`.
//! - Generates `pub fn emit(&self, ctx: &mut Context)` that builds the
//!   topic list (indexed fields → extra topics) plus the ABI-encoded data
//!   payload and forwards to `ctx.emit_raw`.
//!
//! Indexed fields are marked with `#[indexed]` inside the struct body.
//!
//! ## Example
//!
//! ```ignore
//! #[event(domain = "erc20")]
//! pub struct Transfer {
//!     #[indexed]
//!     pub from: Address,
//!     #[indexed]
//!     pub to: Address,
//!     pub value: U256,
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Field, Fields, LitStr, parse_macro_input};

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let struct_name = input.ident.clone();

    // Parse `#[event]` or `#[event(domain = "...")]`.
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

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => &n.named,
            _ => {
                return syn::Error::new_spanned(
                    &input.ident,
                    "#[event] only supports structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                &input.ident,
                "#[event] only supports structs",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut sanitized = input.clone();
    if let Data::Struct(s) = &mut sanitized.data {
        if let Fields::Named(n) = &mut s.fields {
            for f in n.named.iter_mut() {
                f.attrs.retain(|a| !a.path().is_ident("indexed"));
            }
        }
    }

    let indexed: Vec<&Field> = fields.iter().filter(|f| has_indexed(f)).collect();
    let non_indexed: Vec<&Field> = fields.iter().filter(|f| !has_indexed(f)).collect();

    let signature = build_signature(&domain, &struct_name.to_string(), fields);
    let signature_lit = LitStr::new(&signature, proc_macro2::Span::call_site());

    // Topic-0 is `blake3(signature)`. Compute it at macro expansion so the
    // emitted struct holds a literal `[u8; 32]` and avoids runtime hashing
    // on the hot emit path.
    let topic0_bytes = blake3::hash(signature.as_bytes());
    let topic0_arr = topic0_bytes.as_bytes();
    let topic0_lits = topic0_arr.iter().map(|b| quote! { #b });

    let topic_pushes = indexed.iter().map(|f| {
        let ident = f.ident.as_ref().unwrap();
        quote! {
            topics.push(::bloom_contract::events::topic_from_value(&self.#ident));
        }
    });

    let data_pushes = non_indexed.iter().map(|f| {
        let ident = f.ident.as_ref().unwrap();
        quote! {
            ::bloom_contract::abi::AbiEncode::encode_into(&self.#ident, &mut enc)?;
        }
    });

    let name_lit = LitStr::new(&struct_name.to_string(), proc_macro2::Span::call_site());

    quote! {
        #sanitized

        #[automatically_derived]
        impl #struct_name {
            /// Canonical event name (the struct identifier).
            pub const EVENT_NAME: &'static str = #name_lit;

            /// Canonical signature `Domain::Name(types)` hashed into `TOPIC0`.
            pub const EVENT_SIGNATURE: &'static str = #signature_lit;

            /// 32-byte topic-0: `blake3(EVENT_SIGNATURE)`, computed at
            /// macro expansion time so the constant is a literal byte array
            /// (no runtime hashing on the emit path).
            pub const TOPIC0: [u8; 32] = [#(#topic0_lits),*];

            /// Build the topic list (TOPIC0 + each `#[indexed]` field's
            /// 32-byte topic) and the ABI-encoded data payload, then forward
            /// to `ctx.emit_raw`.
            pub fn emit(
                &self,
                ctx: &mut ::bloom_contract::context::Context,
            ) -> ::bloom_contract::error::Result<()> {
                let mut topics: ::bloom_contract::__private::Vec<[u8; 32]> =
                    ::bloom_contract::__private::Vec::new();
                topics.push(Self::TOPIC0);
                #(#topic_pushes)*

                let mut enc = ::bloom_contract::abi::Encoder::new();
                #(#data_pushes)*
                let data = enc.finish();

                ctx.emit_raw(&topics, &data);
                ::core::result::Result::Ok(())
            }
        }
    }
    .into()
}

fn has_indexed(f: &Field) -> bool {
    f.attrs.iter().any(|a| a.path().is_ident("indexed"))
}

fn build_signature(domain: &str, name: &str, fields: &syn::punctuated::Punctuated<Field, syn::Token![,]>) -> String {
    // `Domain::Name(t1,t2,t3)`. Empty domain elides the `Domain::` prefix.
    let mut s = String::new();
    if !domain.is_empty() {
        s.push_str(domain);
        s.push_str("::");
    }
    s.push_str(name);
    s.push('(');
    let mut first = true;
    for f in fields {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&type_canonical_name(&f.ty));
    }
    s.push(')');
    s
}

fn type_canonical_name(ty: &syn::Type) -> String {
    // Reuse the path's last segment ident — matches `AbiType::ABI_TYPE`
    // conventions ("u256", "address", ...). For composite types this is
    // best-effort; full canonicalization happens at host time via the
    // type's `AbiType::schema()`.
    if let syn::Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return seg.ident.to_string().to_ascii_lowercase();
        }
    }
    "?".to_string()
}
