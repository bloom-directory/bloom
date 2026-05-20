//! `#[bloom::contract]` — top-level attribute placed on the `mod` that
//! contains a contract's storage struct, init function, event types, error
//! enum, and handler methods.
//!
//! The macro scans the module body and emits:
//!
//! - A `pub extern "C" fn init()` wasm export that decodes the init payload
//!   (any `AbiDecode`), calls the `#[init]` fn, and forwards `Ok(())` /
//!   `Err(_)` to `petal.return` / `petal.revert`.
//! - A `pub extern "C" fn call()` wasm export with a 4-byte-selector
//!   dispatch table over every `pub fn` (excluding `#[internal]`) in the
//!   module body. Each branch decodes the args via `AbiDecode`, invokes
//!   the handler, then encodes the return value.
//! - A `pub const SELECTORS: &[SelectorEntry]` table consumed by the
//!   manifest emitter at build time.
//! - A `pub const DOMAIN: &str` constant.
//!
//! ## Attribute arguments
//!
//! ```ignore
//! #[bloom::contract(domain = "erc20", interfaces(Erc20, Burnable))]
//! mod erc20 { ... }
//! ```
//!
//! `domain` defaults to the mod ident if omitted. The `interfaces(...)`
//! list folds in the Phase 5 `#[interface]` traits — for Phase 4 it parses
//! but generates no additional dispatch entries.
//!
//! ## Method attributes
//!
//! - `#[init]` — declared once; produces the `init` wasm export.
//! - `#[view]` — handler takes `&Context` (no mutation).
//! - `#[payable]` — handler accepts non-zero `ctx.value()`. Non-payable
//!   methods revert when `value() > 0`.
//! - `#[nonreentrant]` — acquires the framework reentrancy lock on entry,
//!   releases on every exit path (Ok and Err).
//! - `#[internal]` — handler is omitted from the public dispatch table; it
//!   can still be called from inside the contract module.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    AngleBracketedGenericArguments, Attribute, FnArg, GenericArgument, Ident, Item, ItemFn,
    ItemMod, LitByteStr, LitStr, Pat, PathArguments, ReturnType, Type, Visibility,
    parse_macro_input,
};

use crate::manifest::{self, ManifestMethod, Mutability as ManifestMutability};

pub fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut module = parse_macro_input!(item as ItemMod);
    let module_ident = module.ident.clone();

    // -- Parse attribute args ------------------------------------------------
    let mut domain: Option<String> = None;
    let mut interfaces: Vec<Ident> = Vec::new();
    let attr_parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("domain") {
            let v: LitStr = meta.value()?.parse()?;
            domain = Some(v.value());
            Ok(())
        } else if meta.path.is_ident("interfaces") {
            meta.parse_nested_meta(|nested| {
                if let Some(ident) = nested.path.get_ident() {
                    interfaces.push(ident.clone());
                    Ok(())
                } else {
                    Err(nested.error("expected interface identifier"))
                }
            })
        } else {
            Err(meta.error("expected `domain = \"...\"` or `interfaces(...)`"))
        }
    });
    if let Err(e) = syn::parse::Parser::parse(attr_parser, attr) {
        return e.to_compile_error().into();
    }
    let domain = domain.unwrap_or_else(|| module_ident.to_string());

    // -- Locate items inside the module body --------------------------------
    let content = match module.content.as_mut() {
        Some((_, items)) => items,
        None => {
            return syn::Error::new_spanned(
                &module.ident,
                "#[bloom::contract] requires an inline `mod` body",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut init_idx: Option<usize> = None;
    let mut handlers: Vec<HandlerSpec> = Vec::new();

    for (idx, item) in content.iter_mut().enumerate() {
        if let Item::Fn(f) = item {
            if has_marker(&f.attrs, "init") {
                if init_idx.is_some() {
                    return syn::Error::new_spanned(
                        &f.sig.ident,
                        "#[bloom::contract] only supports a single `#[init]` function",
                    )
                    .to_compile_error()
                    .into();
                }
                strip_marker(&mut f.attrs, "init");
                init_idx = Some(idx);
                continue;
            }
            if matches!(f.vis, Visibility::Public(_)) && !has_marker(&f.attrs, "internal") {
                if let Some(spec) = HandlerSpec::from_fn(f, &domain) {
                    handlers.push(spec);
                }
            }
            // Strip method-level marker attributes regardless of branch so
            // the emitted module compiles.
            for marker in ["view", "payable", "nonreentrant", "internal"] {
                strip_marker(&mut f.attrs, marker);
            }
        }
    }

    let init_call = match init_idx {
        Some(idx) => match &content[idx] {
            Item::Fn(f) => build_init_call(f),
            _ => unreachable!("init_idx must point at an ItemFn"),
        },
        None => {
            return syn::Error::new_spanned(
                &module.ident,
                "#[bloom::contract] module must contain exactly one `#[init]` function",
            )
            .to_compile_error()
            .into();
        }
    };

    // -- Build the dispatch table -------------------------------------------
    let selector_consts = handlers.iter().map(|h| h.selector_const());
    let invoke_fns = handlers.iter().map(|h| h.invoke_fn());
    let primary_arms = handlers.iter().map(|h| h.primary_arm());
    let name_arms = handlers.iter().map(|h| h.name_match_arm());
    let selector_descriptors = handlers.iter().map(|h| h.descriptor());
    let handler_count = handlers.len();

    let domain_lit = LitStr::new(&domain, proc_macro2::Span::call_site());
    let module_str_lit = LitStr::new(&module_ident.to_string(), proc_macro2::Span::call_site());
    let interfaces_lit_strs: Vec<LitStr> = interfaces
        .iter()
        .map(|i| LitStr::new(&i.to_string(), proc_macro2::Span::call_site()))
        .collect();
    let interface_idents = &interfaces;

    // -- Generated runtime items appended to the module body ---------------
    let dispatcher_module: TokenStream2 = quote! {
        /// Auto-generated framework runtime support. Do not depend on
        /// these symbols directly — they're an implementation detail of
        /// `#[bloom::contract]` and can change between versions.
        pub mod __bloom {
            use super::*;
            #[allow(unused_imports)]
            use ::bloom_contract::__private::Vec as __Vec;
            #[allow(unused_imports)]
            use ::bloom_contract::interface::ContractInterface as __ContractInterface;

            /// Contract domain — prefix for selectors, storage slots, and
            /// event signatures.
            pub const DOMAIN: &str = #domain_lit;

            /// Source-level module identifier.
            pub const MODULE_NAME: &str = #module_str_lit;

            /// Interfaces this contract claims to implement. The dispatcher
            /// folds every interface's selectors into the routing table so
            /// callers can reach handlers through either the contract's own
            /// domain or any declared interface domain.
            pub const INTERFACES: &[&str] = &[#(#interfaces_lit_strs),*];

            /// `ContractInterface::METHODS` slices for every declared
            /// interface, in declaration order. Empty when no interfaces
            /// were listed.
            pub const INTERFACE_METHODS: &[
                &[::bloom_contract::interface::InterfaceMethod]
            ] = &[
                #(
                    <#interface_idents as ::bloom_contract::interface::ContractInterface>::METHODS,
                )*
            ];

            #(#selector_consts)*

            /// Selector → method descriptor table consumed by the manifest
            /// emitter and surfaced to tooling.
            pub const SELECTORS: &[::bloom_contract::dispatch::SelectorEntry] = &[
                #(#selector_descriptors,)*
            ];

            pub const SELECTOR_COUNT: usize = #handler_count;

            // -- Per-handler invoke functions ---------------------------------
            #(#invoke_fns)*

            /// Decode the init payload, invoke `#[init]`, and forward the
            /// result to `petal.return`/`petal.revert`.
            #[doc(hidden)]
            pub fn __dispatch_init() {
                let calldata = ::bloom_petal_sdk::msg::calldata();
                #init_call
            }

            /// Read calldata, peel the 4-byte selector, route through the
            /// primary selector table, then fall back to interface-aliased
            /// dispatch before reverting.
            #[doc(hidden)]
            pub fn __dispatch_call() {
                let calldata = ::bloom_petal_sdk::msg::calldata();
                if calldata.len() < 4 {
                    ::bloom_petal_sdk::petal::revert("calldata too short");
                }
                let mut sel = [0u8; 4];
                sel.copy_from_slice(&calldata[..4]);
                let args = &calldata[4..];
                match sel {
                    #(#primary_arms)*
                    _ => {}
                }
                // Interface fallthrough — a method declared on a listed
                // interface routes to the local handler of the same name,
                // letting the contract surface its own domain plus every
                // ERC-20-style interface it implements without hand-rolled
                // dispatch.
                for __table in INTERFACE_METHODS {
                    for __m in *__table {
                        if __m.selector == sel {
                            match __m.name {
                                #(#name_arms)*
                                _ => {}
                            }
                        }
                    }
                }
                ::bloom_petal_sdk::petal::revert("unknown selector");
            }
        }
    };

    // Push dispatcher into the module body so generated names are siblings
    // of user-defined items (and the user's `use super::*;` can resolve
    // them when needed).
    content.push(Item::Verbatim(dispatcher_module));

    // Top-level wasm exports outside the module so they hit the wasm
    // `start` table at module scope.
    let init_export = format_ident!("__bloom_init_{}", module_ident);
    let call_export = format_ident!("__bloom_call_{}", module_ident);

    // The wasm `init` / `call` exports are entry points for the chain's
    // VM. On host targets they collide with each other when more than one
    // `#[bloom::contract]` lives in the same binary (every contract would
    // claim the same symbol). Gate them on `wasm32` so host-side tests can
    // declare several contract modules side-by-side and the framework
    // itself stays exercise-able without per-contract build scripts.
    let exports: TokenStream2 = quote! {
        #[cfg(target_arch = "wasm32")]
        #[doc(hidden)]
        #[unsafe(export_name = "init")]
        pub extern "C" fn #init_export() {
            #module_ident::__bloom::__dispatch_init();
        }

        #[cfg(target_arch = "wasm32")]
        #[doc(hidden)]
        #[unsafe(export_name = "call")]
        pub extern "C" fn #call_export() {
            #module_ident::__bloom::__dispatch_call();
        }

        // Off-wasm: keep a non-exported alias of each shim so host-side
        // tests can take a function pointer (`__bloom_init_<mod>`) to verify
        // the dispatcher generated correctly without instantiating a wasm
        // engine.
        #[cfg(not(target_arch = "wasm32"))]
        #[doc(hidden)]
        pub extern "C" fn #init_export() {
            #module_ident::__bloom::__dispatch_init();
        }

        #[cfg(not(target_arch = "wasm32"))]
        #[doc(hidden)]
        pub extern "C" fn #call_export() {
            #module_ident::__bloom::__dispatch_call();
        }
    };

    // Build the partial manifest (everything that can be derived
    // statically — methods, storage layout, events, errors, interfaces)
    // and embed its JSON bytes in a `bloom_manifest` custom wasm section.
    // The `bloom contract build` tool reads the section back, fills in
    // `wasm_hash` / `source_hash` / `imports`, and emits the on-disk
    // `<name>.manifest.json`.
    let manifest_methods: Vec<ManifestMethod> =
        handlers.iter().map(|h| h.to_manifest_method()).collect();
    let manifest_json = manifest::build_skeleton_json(&module, &domain, &manifest_methods, &interfaces);
    let manifest_bytes = LitByteStr::new(manifest_json.as_bytes(), proc_macro2::Span::call_site());
    let manifest_len = manifest_json.len();
    let manifest_static_ident = format_ident!("__BLOOM_MANIFEST_{}", module_ident);

    let manifest_section: TokenStream2 = quote! {
        // The link-section attribute is honoured by the wasm32 backend
        // (it produces a custom section with the given name). On host
        // targets we omit the section to avoid object-format quirks; the
        // manifest is wasm-only metadata anyway.
        #[cfg(target_arch = "wasm32")]
        #[doc(hidden)]
        #[used]
        #[unsafe(link_section = "bloom_manifest")]
        pub static #manifest_static_ident: [u8; #manifest_len] = *#manifest_bytes;
    };

    quote! {
        #module
        #exports
        #manifest_section
    }
    .into()
}

// ===========================================================================
// Handler specs
// ===========================================================================

struct HandlerSpec {
    name: String,
    fn_ident: Ident,
    selector: [u8; 4],
    signature: String,
    arg_idents: Vec<Ident>,
    arg_types: Vec<Type>,
    /// The `T` inside the handler's `Result<T, E>` return type, if it can be
    /// extracted. The manifest's `outputs` field uses this.
    ok_type: Option<Type>,
    takes_mut_ctx: bool,
    view: bool,
    payable: bool,
    nonreentrant: bool,
}

impl HandlerSpec {
    fn from_fn(f: &ItemFn, domain: &str) -> Option<Self> {
        let name = f.sig.ident.to_string();
        let mut arg_idents = Vec::new();
        let mut arg_types = Vec::new();
        let mut takes_mut_ctx = false;
        let mut first = true;

        for arg in &f.sig.inputs {
            match arg {
                FnArg::Receiver(_) => return None, // contract handlers are free fns
                FnArg::Typed(pt) => {
                    if first {
                        first = false;
                        if let Type::Reference(r) = &*pt.ty {
                            takes_mut_ctx = r.mutability.is_some();
                            continue; // Context is implicit — not part of calldata.
                        }
                    }
                    let ident = match &*pt.pat {
                        Pat::Ident(pi) => pi.ident.clone(),
                        _ => format_ident!("__arg{}", arg_idents.len()),
                    };
                    arg_idents.push(ident);
                    arg_types.push((*pt.ty).clone());
                }
            }
        }

        let signature = build_method_signature(domain, &name, &arg_types);
        let h = blake3::hash(signature.as_bytes());
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&h.as_bytes()[..4]);

        let ok_type = match &f.sig.output {
            ReturnType::Default => None,
            ReturnType::Type(_, t) => extract_result_ok(t),
        };

        Some(Self {
            name,
            fn_ident: f.sig.ident.clone(),
            selector,
            signature,
            arg_idents,
            arg_types,
            ok_type,
            takes_mut_ctx,
            view: has_marker(&f.attrs, "view"),
            payable: has_marker(&f.attrs, "payable"),
            nonreentrant: has_marker(&f.attrs, "nonreentrant"),
        })
    }

    fn to_manifest_method(&self) -> ManifestMethod {
        ManifestMethod {
            name: self.name.clone(),
            signature: self.signature.clone(),
            selector: self.selector,
            mutability: if self.view {
                ManifestMutability::View
            } else if self.payable {
                ManifestMutability::Payable
            } else {
                ManifestMutability::Mutating
            },
            arg_idents: self.arg_idents.iter().map(|i| i.to_string()).collect(),
            arg_types: self.arg_types.clone(),
            return_type: self.ok_type.clone(),
        }
    }

    fn selector_const(&self) -> TokenStream2 {
        let const_ident = format_ident!("SEL_{}", screaming_snake(&self.name));
        let [a, b, c, d] = self.selector;
        quote! {
            pub const #const_ident: [u8; 4] = [#a, #b, #c, #d];
        }
    }

    fn const_ident(&self) -> Ident {
        format_ident!("SEL_{}", screaming_snake(&self.name))
    }

    fn invoke_ident(&self) -> Ident {
        format_ident!("__invoke_{}", self.name)
    }

    /// Build a free fn `fn __invoke_<name>(args: &[u8]) -> !` containing the
    /// per-handler dispatch body (payability check, arg decode, optional
    /// reentrancy guard, handler call, return/revert encoding). Both the
    /// main selector match and the interface-fallthrough loop call into this
    /// fn so the body lives in exactly one place.
    fn invoke_fn(&self) -> TokenStream2 {
        let fn_ident = &self.fn_ident;
        let invoke_ident = self.invoke_ident();
        let arg_idents = &self.arg_idents;
        let arg_types = &self.arg_types;

        let decode_args = arg_idents.iter().zip(arg_types.iter()).map(|(id, ty)| {
            quote! {
                let #id: #ty = match <#ty as ::bloom_contract::abi::AbiDecode>::decode(&mut buf) {
                    ::core::result::Result::Ok(v) => v,
                    ::core::result::Result::Err(_) => {
                        ::bloom_petal_sdk::petal::revert("calldata decode failed");
                    }
                };
            }
        });

        let ctx_arg = if self.takes_mut_ctx {
            quote! { &mut __ctx }
        } else {
            quote! { &__ctx }
        };

        let payability_check = if self.payable {
            quote! {}
        } else {
            quote! {
                if !::bloom_petal_sdk::msg::value().is_zero() {
                    ::bloom_petal_sdk::petal::revert("non-payable method received value");
                }
            }
        };

        let (acquire_guard, release_guard) = if self.nonreentrant {
            (
                quote! {
                    let __reentrancy_guard =
                        ::bloom_contract::reentrancy::Guard::acquire();
                },
                quote! { __reentrancy_guard.release(); },
            )
        } else {
            (quote! {}, quote! {})
        };

        quote! {
            #[doc(hidden)]
            fn #invoke_ident(args: &[u8]) -> ! {
                #payability_check
                let mut buf = ::bloom_contract::abi::Buf::new(args);
                #(#decode_args)*
                let mut __ctx = ::bloom_contract::context::Context::new();
                #acquire_guard
                let __result = super::#fn_ident(#ctx_arg, #(#arg_idents),*);
                match __result {
                    ::core::result::Result::Ok(__v) => {
                        let mut __enc = ::bloom_contract::abi::Encoder::new();
                        if ::bloom_contract::abi::AbiEncode::encode_into(&__v, &mut __enc).is_err() {
                            ::bloom_petal_sdk::petal::revert("return encode failed");
                        }
                        let __bytes: __Vec<u8> = __enc.finish();
                        #release_guard
                        ::bloom_petal_sdk::petal::return_data(&__bytes);
                    }
                    ::core::result::Result::Err(__e) => {
                        let __bytes: __Vec<u8> =
                            ::bloom_contract::error::Error::encode_revert(&__e);
                        ::bloom_contract::dispatch::revert_with_bytes(&__bytes);
                    }
                }
            }
        }
    }

    fn primary_arm(&self) -> TokenStream2 {
        let const_ident = self.const_ident();
        let invoke_ident = self.invoke_ident();
        quote! { #const_ident => #invoke_ident(args), }
    }

    fn name_match_arm(&self) -> TokenStream2 {
        let name_lit = LitStr::new(&self.name, proc_macro2::Span::call_site());
        let invoke_ident = self.invoke_ident();
        quote! { #name_lit => #invoke_ident(args), }
    }

    fn descriptor(&self) -> TokenStream2 {
        let name_lit = LitStr::new(&self.name, proc_macro2::Span::call_site());
        let sig_lit = LitStr::new(&self.signature, proc_macro2::Span::call_site());
        let [a, b, c, d] = self.selector;
        let nonreentrant = self.nonreentrant;
        let mutability = if self.view {
            quote! { ::bloom_contract::dispatch::Mutability::View }
        } else if self.payable {
            quote! { ::bloom_contract::dispatch::Mutability::Payable }
        } else {
            quote! { ::bloom_contract::dispatch::Mutability::Mutating }
        };
        quote! {
            ::bloom_contract::dispatch::SelectorEntry {
                name: #name_lit,
                signature: #sig_lit,
                selector: [#a, #b, #c, #d],
                mutability: #mutability,
                nonreentrant: #nonreentrant,
            }
        }
    }
}

fn build_init_call(f: &ItemFn) -> TokenStream2 {
    let fn_ident = &f.sig.ident;
    // Identify init's arg shape: skip the leading &mut Context, decode the
    // single payload arg via AbiDecode.
    let mut payload_type: Option<Type> = None;
    let mut first = true;
    for arg in &f.sig.inputs {
        if let FnArg::Typed(pt) = arg {
            if first {
                first = false;
                if let Type::Reference(_) = &*pt.ty {
                    continue;
                }
            }
            payload_type = Some((*pt.ty).clone());
            break;
        }
    }

    let decode_and_call = match payload_type {
        Some(ty) => quote! {
            let mut buf = ::bloom_contract::abi::Buf::new(&calldata);
            let __cfg: #ty = match <#ty as ::bloom_contract::abi::AbiDecode>::decode(&mut buf) {
                ::core::result::Result::Ok(v) => v,
                ::core::result::Result::Err(_) => {
                    ::bloom_petal_sdk::petal::revert("init calldata decode failed");
                }
            };
            let mut __ctx = ::bloom_contract::context::Context::new();
            let __result = #fn_ident(&mut __ctx, __cfg);
        },
        None => quote! {
            // Init takes no payload — bytes after &mut Context are unused.
            let _ = calldata;
            let mut __ctx = ::bloom_contract::context::Context::new();
            let __result = #fn_ident(&mut __ctx);
        },
    };

    quote! {
        #decode_and_call
        match __result {
            ::core::result::Result::Ok(()) => {
                ::bloom_petal_sdk::petal::return_data(&[]);
            }
            ::core::result::Result::Err(__e) => {
                let __bytes = ::bloom_contract::error::Error::encode_revert(&__e);
                ::bloom_contract::dispatch::revert_with_bytes(&__bytes);
            }
        }
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

fn has_marker(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

fn strip_marker(attrs: &mut Vec<Attribute>, name: &str) {
    attrs.retain(|a| !a.path().is_ident(name));
}

/// Extract `T` from `Result<T>` or `Result<T, E>`. Returns `None` for
/// other return shapes — the manifest then records an empty `outputs` list.
fn extract_result_ok(ty: &Type) -> Option<Type> {
    let tp = match ty {
        Type::Path(t) => t,
        _ => return None,
    };
    let seg = tp.path.segments.last()?;
    if seg.ident != "Result" {
        return None;
    }
    let ab = match &seg.arguments {
        PathArguments::AngleBracketed(AngleBracketedGenericArguments { args, .. }) => args,
        _ => return None,
    };
    let first = ab.first()?;
    if let GenericArgument::Type(t) = first {
        Some(t.clone())
    } else {
        None
    }
}

fn build_method_signature(domain: &str, method: &str, args: &[Type]) -> String {
    let mut s = String::new();
    s.push_str(domain);
    s.push('.');
    s.push_str(method);
    s.push('(');
    let mut first = true;
    for ty in args {
        if !first {
            s.push(',');
        }
        first = false;
        if let Type::Path(tp) = ty {
            if let Some(seg) = tp.path.segments.last() {
                s.push_str(&seg.ident.to_string().to_ascii_lowercase());
                continue;
            }
        }
        s.push('?');
    }
    s.push(')');
    s
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
