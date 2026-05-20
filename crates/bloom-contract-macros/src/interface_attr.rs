//! `#[bloom::interface]` attribute macro — placed on a trait declaration to
//! describe a cross-contract ABI surface (typically ERC-20-style standards).
//!
//! Input shape:
//!
//! ```ignore
//! #[bloom::interface(domain = "erc20")]
//! pub trait Erc20 {
//!     fn balance_of(owner: Address) -> Result<U256>;
//!     fn transfer(to: Address, amount: U256) -> Result<bool>;
//! }
//! ```
//!
//! Because `ContractRef<I>` takes a *type* (not a trait) as its parameter,
//! the macro replaces the `pub trait Erc20 { ... }` declaration with a
//! zero-variant marker `pub enum Erc20 {}`. The original method list is
//! kept only as the source of selector + descriptor data — users call into
//! the contract through the typed `ContractRef<Erc20>` inherent impl, not
//! through the trait dispatcher.
//!
//! The macro generates:
//!
//! - A zero-variant marker type with the trait's identifier (`pub enum Erc20 {}`).
//! - `impl bloom_contract::interface::ContractInterface for Erc20` with the
//!   canonical `ABI_DOMAIN` and a `METHODS` descriptor slice.
//! - `pub const SEL_<METHOD>: [u8; 4]` constants on the marker (via an
//!   inherent impl block).
//! - A companion `pub trait Erc20Calls` with one method per interface entry,
//!   implemented for `ContractRef<Erc20>`. We use an extension trait rather
//!   than an inherent impl because Rust's orphan rules forbid an inherent
//!   `impl ContractRef<UserType>` outside the crate where `ContractRef` is
//!   defined. Users import `Erc20Calls` to bring the methods into scope.
//!
//! Method signatures must end in `Result<T>` or `Result<T, E>` (the
//! framework's `bloom_contract::error::Result` alias is in scope through the
//! prelude); the macro decodes `T` from the call's return data and rewraps
//! the result so the caller sees the same typed surface they'd get from a
//! direct handler call.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    AngleBracketedGenericArguments, FnArg, GenericArgument, Ident, ItemTrait, LitStr, Pat,
    PathArguments, ReturnType, TraitItem, TraitItemFn, Type, parse_macro_input,
};

use crate::sig::build_method_signature;

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let trait_decl = parse_macro_input!(item as ItemTrait);
    let trait_ident = trait_decl.ident.clone();
    let trait_vis = trait_decl.vis.clone();
    let trait_attrs = trait_decl.attrs.clone();

    // -- Attribute args -----------------------------------------------------
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
    let domain = match domain {
        Some(d) => d,
        None => {
            return syn::Error::new_spanned(
                &trait_decl.ident,
                "#[bloom::interface] requires a `domain = \"...\"` argument",
            )
            .to_compile_error()
            .into();
        }
    };

    // -- Walk trait methods --------------------------------------------------
    let mut methods: Vec<MethodSpec> = Vec::new();
    for it in &trait_decl.items {
        if let TraitItem::Fn(f) = it {
            match MethodSpec::from_trait_fn(f, &domain) {
                Ok(m) => methods.push(m),
                Err(e) => return e.to_compile_error().into(),
            }
        }
    }

    let domain_lit = LitStr::new(&domain, proc_macro2::Span::call_site());
    let selector_consts = methods.iter().map(|m| m.selector_const());
    let descriptors = methods.iter().map(|m| m.descriptor());
    let calls_trait_ident = format_ident!("{}Calls", trait_ident);
    let trait_method_sigs = methods.iter().map(|m| m.trait_method_signature());
    let trait_method_impls = methods.iter().map(|m| m.trait_method_impl(&trait_ident));

    // Emit a `bloom_interfaces` custom-section record so the build crate
    // can resolve declared interface names to full method descriptors at
    // build time. Wire form: `<u16-le len><JSON bytes>` per record; the
    // linker concatenates one section per interface in the final wasm.
    let interface_record_static = build_interface_record_static(&trait_ident, &domain, &methods);

    quote! {
        // Marker type — the original `pub trait Erc20 { ... }` is replaced
        // by a zero-variant enum because `ContractRef<I>` and the
        // `ContractInterface` impl below both need `I` to be a type, not a
        // trait. The original method list survives as `METHODS`, the
        // selector consts, and the `<Trait>Calls` extension trait.
        #(#trait_attrs)*
        #trait_vis enum #trait_ident {}

        #[automatically_derived]
        impl ::bloom_contract::interface::ContractInterface for #trait_ident {
            const ABI_DOMAIN: &'static str = #domain_lit;
            const METHODS: &'static [::bloom_contract::interface::InterfaceMethod] = &[
                #(#descriptors,)*
            ];
        }

        #[automatically_derived]
        impl #trait_ident {
            #(#selector_consts)*
        }

        /// Typed cross-contract call surface for the matching interface.
        /// Implemented for `ContractRef<Trait>` so users get the
        /// `r.method(ctx, ...)` ergonomic after importing this trait.
        #trait_vis trait #calls_trait_ident {
            #(#trait_method_sigs)*
        }

        #[automatically_derived]
        impl #calls_trait_ident
            for ::bloom_contract::interface::ContractRef<#trait_ident>
        {
            #(#trait_method_impls)*
        }

        #interface_record_static
    }
    .into()
}

/// Emit the `#[link_section = "bloom_interfaces"]` byte array carrying
/// the JSON `InterfaceManifest` record for this trait. The record is
/// length-prefixed (`<u16-le><JSON>`) so the build crate can decode a
/// concatenated stream of records from multiple interfaces.
fn build_interface_record_static(
    trait_ident: &Ident,
    domain: &str,
    methods: &[MethodSpec],
) -> TokenStream2 {
    use serde_json::json;

    let method_records: Vec<serde_json::Value> = methods
        .iter()
        .map(|m| {
            let sel_hex: String = m
                .selector
                .iter()
                .flat_map(|b| {
                    let hi = HEX[(b >> 4) as usize] as char;
                    let lo = HEX[(b & 0x0f) as usize] as char;
                    [hi, lo]
                })
                .collect();
            json!({
                "name": m.name,
                "signature": m.signature,
                "selector": sel_hex,
            })
        })
        .collect();
    let record = json!({
        "name": trait_ident.to_string(),
        "domain": domain,
        "methods": method_records,
    });
    let json_bytes = serde_json::to_vec(&record).expect("interface record serializes");

    let len = json_bytes.len();
    if len > u16::MAX as usize {
        return syn::Error::new_spanned(
            trait_ident,
            "interface record exceeds 64 KiB — too many methods for the manifest custom section",
        )
        .to_compile_error();
    }

    // Wire form: <u16-le len><JSON bytes>.
    let len_lo = (len & 0xff) as u8;
    let len_hi = ((len >> 8) & 0xff) as u8;
    let mut blob: Vec<u8> = Vec::with_capacity(2 + len);
    blob.push(len_lo);
    blob.push(len_hi);
    blob.extend_from_slice(&json_bytes);

    let total_len = blob.len();
    let bytes_lits = blob.iter().map(|b| quote::quote! { #b });
    let static_ident = format_ident!("__BLOOM_INTERFACE_{}", trait_ident);

    quote! {
        #[cfg(target_arch = "wasm32")]
        #[doc(hidden)]
        #[unsafe(link_section = "bloom_interfaces")]
        #[used]
        static #static_ident: [u8; #total_len] = [#(#bytes_lits),*];
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

// ===========================================================================
// Method specs
// ===========================================================================

struct MethodSpec {
    name: String,
    fn_ident: Ident,
    selector: [u8; 4],
    signature: String,
    arg_idents: Vec<Ident>,
    arg_types: Vec<Type>,
    /// The `T` inside the trait method's `Result<T>` / `Result<T, _>`. The
    /// macro decodes this from the call's return data.
    ok_type: Type,
}

impl MethodSpec {
    fn from_trait_fn(f: &TraitItemFn, domain: &str) -> syn::Result<Self> {
        let name = f.sig.ident.to_string();
        let mut arg_idents = Vec::new();
        let mut arg_types = Vec::new();

        for arg in &f.sig.inputs {
            match arg {
                FnArg::Receiver(_) => {
                    return Err(syn::Error::new_spanned(
                        arg,
                        "#[bloom::interface] methods must be free fns (no `self`)",
                    ));
                }
                FnArg::Typed(pt) => {
                    let ident = match &*pt.pat {
                        Pat::Ident(pi) => pi.ident.clone(),
                        _ => format_ident!("__arg{}", arg_idents.len()),
                    };
                    arg_idents.push(ident);
                    arg_types.push((*pt.ty).clone());
                }
            }
        }

        let return_ty = match &f.sig.output {
            ReturnType::Default => {
                return Err(syn::Error::new_spanned(
                    &f.sig,
                    "#[bloom::interface] methods must return `Result<T>` or `Result<T, E>`",
                ));
            }
            ReturnType::Type(_, t) => (**t).clone(),
        };
        let ok_type = extract_ok_type(&return_ty)?;

        let signature = build_method_signature(domain, &name, &arg_types);
        let h = blake3::hash(signature.as_bytes());
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&h.as_bytes()[..4]);

        Ok(Self {
            name,
            fn_ident: f.sig.ident.clone(),
            selector,
            signature,
            arg_idents,
            arg_types,
            ok_type,
        })
    }

    fn selector_const(&self) -> TokenStream2 {
        let const_ident = format_ident!("SEL_{}", screaming_snake(&self.name));
        let [a, b, c, d] = self.selector;
        quote! {
            pub const #const_ident: [u8; 4] = [#a, #b, #c, #d];
        }
    }

    fn descriptor(&self) -> TokenStream2 {
        let name_lit = LitStr::new(&self.name, proc_macro2::Span::call_site());
        let sig_lit = LitStr::new(&self.signature, proc_macro2::Span::call_site());
        let [a, b, c, d] = self.selector;
        quote! {
            ::bloom_contract::interface::InterfaceMethod {
                name: #name_lit,
                signature: #sig_lit,
                selector: [#a, #b, #c, #d],
            }
        }
    }

    /// Trait method signature inside the `<Trait>Calls` companion trait —
    /// no body, since the impl on `ContractRef<Trait>` carries it.
    fn trait_method_signature(&self) -> TokenStream2 {
        let fn_ident = &self.fn_ident;
        let arg_idents = &self.arg_idents;
        let arg_types = &self.arg_types;
        let ok_type = &self.ok_type;
        quote! {
            fn #fn_ident(
                &self,
                ctx: &mut ::bloom_contract::context::Context,
                #(#arg_idents: #arg_types),*
            ) -> ::bloom_contract::error::Result<#ok_type>;
        }
    }

    /// Impl body for `<Trait>Calls::method` on `ContractRef<Trait>` —
    /// encode selector + args, forward through `ctx.raw_call`, decode the
    /// return value.
    fn trait_method_impl(&self, trait_ident: &Ident) -> TokenStream2 {
        let fn_ident = &self.fn_ident;
        let arg_idents = &self.arg_idents;
        let arg_types = &self.arg_types;
        let ok_type = &self.ok_type;
        let sel_const = format_ident!("SEL_{}", screaming_snake(&self.name));

        let encode_args = arg_idents.iter().map(|id| {
            quote! {
                if let ::core::result::Result::Err(__e) =
                    ::bloom_contract::abi::AbiEncode::encode_into(&#id, &mut __enc)
                {
                    return ::core::result::Result::Err(
                        ::bloom_contract::error::ContractError::from(__e),
                    );
                }
            }
        });

        quote! {
            fn #fn_ident(
                &self,
                ctx: &mut ::bloom_contract::context::Context,
                #(#arg_idents: #arg_types),*
            ) -> ::bloom_contract::error::Result<#ok_type> {
                let mut __enc = ::bloom_contract::abi::Encoder::new();
                __enc.push_bytes(&#trait_ident::#sel_const);
                #(#encode_args)*
                let __cd: ::bloom_contract::__private::Vec<u8> = __enc.finish();
                let __ret = ctx.__call_raw(
                    &self.address,
                    &__cd,
                    self.value,
                )?;
                let mut __buf = ::bloom_contract::abi::Buf::new(&__ret);
                let __value =
                    <#ok_type as ::bloom_contract::abi::AbiDecode>::decode(&mut __buf)
                        .map_err(::bloom_contract::error::ContractError::from)?;
                ::core::result::Result::Ok(__value)
            }
        }
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

fn extract_ok_type(ty: &Type) -> syn::Result<Type> {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            if seg.ident == "Result" {
                if let PathArguments::AngleBracketed(AngleBracketedGenericArguments {
                    args,
                    ..
                }) = &seg.arguments
                {
                    if let Some(GenericArgument::Type(t)) = args.first() {
                        return Ok(t.clone());
                    }
                }
            }
        }
    }
    Err(syn::Error::new_spanned(
        ty,
        "interface method return type must be `Result<T>` or `Result<T, E>`",
    ))
}

fn screaming_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    let mut prev_lower = false;
    for ch in s.chars() {
        if ch == '_' {
            out.push('_');
            prev_lower = false;
            continue;
        }
        if ch.is_ascii_uppercase() && prev_lower {
            out.push('_');
        }
        out.push(ch.to_ascii_uppercase());
        prev_lower = ch.is_ascii_lowercase();
    }
    out
}
