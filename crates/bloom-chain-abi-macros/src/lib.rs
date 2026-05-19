//! Proc-macros for bloom-chain-abi.
//!
//! `contract!` generates client-side call builders, a guest-side `Handler`
//! trait, a strict-decoding dispatcher, and (optionally) an init-calldata
//! codec from a small DSL:
//!
//! ```text
//! bloom_chain_abi::contract! {
//!     contract Factory {
//!         init(creator: Address);                       // optional
//!         fn create_pair(token_a: Address, token_b: Address) -> Address;
//!         #[internal]
//!         fn _bump(index: u64);                         // gated on reentrancy_addr
//!     }
//! }
//! ```

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{Attribute, Ident, Result, Token, braced, parenthesized, parse_macro_input};

/// ABI primitive types accepted in `contract!` declarations.
#[derive(Clone, PartialEq, Eq)]
enum AbiType {
    Address,
    Bytes32,
    U256,
    U128,
    U64,
    Bool,
    AddressVec,
    /// Variable-length "rest of calldata" bytes. Only valid as the LAST
    /// argument of a method, and never as a return type. Consumes every byte
    /// remaining in the buffer; no length prefix.
    Bytes,
}

impl AbiType {
    /// Canonical type string used inside method/event signatures for hashing.
    fn sig(&self) -> &'static str {
        match self {
            AbiType::Address => "address",
            AbiType::Bytes32 => "bytes32",
            AbiType::U256 => "u256",
            AbiType::U128 => "u128",
            AbiType::U64 => "u64",
            AbiType::Bool => "bool",
            AbiType::AddressVec => "Vec<Address>",
            AbiType::Bytes => "bytes",
        }
    }

    /// Rust handler-side type (what the user impl receives / returns).
    fn handler_ty(&self) -> TokenStream2 {
        match self {
            AbiType::Address => quote! { [u8; 32] },
            AbiType::Bytes32 => quote! { [u8; 32] },
            AbiType::U256 => quote! { ::bloom_chain_abi::U256 },
            AbiType::U128 => quote! { u128 },
            AbiType::U64 => quote! { u64 },
            AbiType::Bool => quote! { bool },
            AbiType::AddressVec => quote! { ::bloom_chain_abi::__private::Vec<[u8; 32]> },
            AbiType::Bytes => quote! { ::bloom_chain_abi::__private::Vec<u8> },
        }
    }

    /// Rust client-side parameter type for call builders (by-reference where
    /// the encoder prefers it).
    fn client_param_ty(&self) -> TokenStream2 {
        match self {
            AbiType::Address => quote! { &[u8; 32] },
            AbiType::Bytes32 => quote! { &[u8; 32] },
            AbiType::U256 => quote! { ::bloom_chain_abi::U256 },
            AbiType::U128 => quote! { u128 },
            AbiType::U64 => quote! { u64 },
            AbiType::Bool => quote! { bool },
            AbiType::AddressVec => quote! { &[[u8; 32]] },
            AbiType::Bytes => quote! { &[u8] },
        }
    }

    /// Emit `buf.read_<ty>()` for decoder use.
    fn decode_expr(&self, buf: &Ident) -> TokenStream2 {
        match self {
            AbiType::Address => quote! { #buf.read_address() },
            AbiType::Bytes32 => quote! { #buf.read_bytes32() },
            AbiType::U256 => quote! { #buf.read_u256() },
            AbiType::U128 => quote! { #buf.read_u128() },
            AbiType::U64 => quote! { #buf.read_u64() },
            AbiType::Bool => quote! { #buf.read_bool() },
            AbiType::AddressVec => quote! { #buf.read_address_vec() },
            AbiType::Bytes => quote! { #buf.read_rest() },
        }
    }

    /// Emit `enc.push_<ty>(<value>)` for encoder use.
    /// `value` should be a name; the encoder takes care of borrowing.
    fn encode_call(&self, enc: &Ident, value: TokenStream2) -> TokenStream2 {
        match self {
            AbiType::Address => quote! { #enc.push_address(#value); },
            AbiType::Bytes32 => quote! { #enc.push_bytes32(#value); },
            AbiType::U256 => quote! { #enc.push_u256(#value); },
            AbiType::U128 => quote! { #enc.push_u128(#value); },
            AbiType::U64 => quote! { #enc.push_u64(#value); },
            AbiType::Bool => quote! { #enc.push_bool(#value); },
            AbiType::AddressVec => quote! {
                #enc.push_address_vec(#value)
                    .expect("address vec length must fit in u16");
            },
            AbiType::Bytes => quote! { #enc.push_bytes(#value); },
        }
    }
}

impl Parse for AbiType {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(Ident) {
            let ident: Ident = input.parse()?;
            let name = ident.to_string();
            match name.as_str() {
                "Address" => Ok(AbiType::Address),
                "Hash32" | "Bytes32" => Ok(AbiType::Bytes32),
                "U256" | "u256" => Ok(AbiType::U256),
                "u128" => Ok(AbiType::U128),
                "u64" => Ok(AbiType::U64),
                "bool" => Ok(AbiType::Bool),
                "bytes" | "Bytes" => Ok(AbiType::Bytes),
                "Vec" => {
                    // Parse `<Address>`
                    let _lt: Token![<] = input.parse()?;
                    let inner: Ident = input.parse()?;
                    let _gt: Token![>] = input.parse()?;
                    if inner == "Address" {
                        Ok(AbiType::AddressVec)
                    } else {
                        Err(syn::Error::new(
                            inner.span(),
                            "only Vec<Address> is supported",
                        ))
                    }
                }
                other => Err(syn::Error::new(
                    ident.span(),
                    format!(
                        "unsupported ABI type `{other}` (expected one of: Address, Hash32, U256, u128, u64, bool, Vec<Address>, bytes)",
                    ),
                )),
            }
        } else {
            Err(lookahead.error())
        }
    }
}

struct Arg {
    name: Ident,
    ty: AbiType,
}

impl Parse for Arg {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        let _colon: Token![:] = input.parse()?;
        let ty: AbiType = input.parse()?;
        Ok(Arg { name, ty })
    }
}

struct MethodDecl {
    internal: bool,
    name: Ident,
    args: Vec<Arg>,
    ret: Option<AbiType>,
}

struct InitDecl {
    args: Vec<Arg>,
}

enum Item {
    Method(MethodDecl),
    Init(InitDecl),
}

impl Parse for Item {
    fn parse(input: ParseStream) -> Result<Self> {
        let attrs: Vec<Attribute> = input.call(Attribute::parse_outer)?;
        let mut internal = false;
        for a in &attrs {
            if a.path().is_ident("internal") {
                internal = true;
            } else {
                return Err(syn::Error::new_spanned(
                    a,
                    "only #[internal] is supported on contract methods",
                ));
            }
        }

        let lookahead = input.lookahead1();
        if lookahead.peek(Token![fn]) {
            let _fn: Token![fn] = input.parse()?;
            let name: Ident = input.parse()?;

            let content;
            parenthesized!(content in input);
            let mut args = Vec::new();
            while !content.is_empty() {
                args.push(content.parse::<Arg>()?);
                if !content.is_empty() {
                    let _comma: Token![,] = content.parse()?;
                }
            }

            let ret = if input.peek(Token![->]) {
                let _arrow: Token![->] = input.parse()?;
                Some(input.parse::<AbiType>()?)
            } else {
                None
            };
            let _semi: Token![;] = input.parse()?;

            Ok(Item::Method(MethodDecl {
                internal,
                name,
                args,
                ret,
            }))
        } else if lookahead.peek(Ident) {
            // Could be `init(...)`. Peek without consuming.
            let fork = input.fork();
            let ident: Ident = fork.parse()?;
            if ident == "init" {
                if internal {
                    return Err(syn::Error::new(
                        ident.span(),
                        "#[internal] is not valid on init",
                    ));
                }
                let _ident: Ident = input.parse()?;
                let content;
                parenthesized!(content in input);
                let mut args = Vec::new();
                while !content.is_empty() {
                    args.push(content.parse::<Arg>()?);
                    if !content.is_empty() {
                        let _comma: Token![,] = content.parse()?;
                    }
                }
                let _semi: Token![;] = input.parse()?;
                Ok(Item::Init(InitDecl { args }))
            } else {
                Err(syn::Error::new(
                    ident.span(),
                    format!("expected `fn` or `init`, got `{ident}`"),
                ))
            }
        } else {
            Err(lookahead.error())
        }
    }
}

struct ContractInput {
    name: Ident,
    init: Option<InitDecl>,
    methods: Vec<MethodDecl>,
}

impl Parse for ContractInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let kw: Ident = input.parse()?;
        if kw != "contract" {
            return Err(syn::Error::new(
                kw.span(),
                format!("expected `contract`, got `{kw}`"),
            ));
        }
        let name: Ident = input.parse()?;
        let body;
        braced!(body in input);

        let mut init = None;
        let mut methods = Vec::new();
        while !body.is_empty() {
            match body.parse::<Item>()? {
                Item::Method(m) => methods.push(m),
                Item::Init(i) => {
                    if init.is_some() {
                        return Err(syn::Error::new(
                            name.span(),
                            "duplicate `init` declaration in contract",
                        ));
                    }
                    init = Some(i);
                }
            }
        }

        Ok(ContractInput {
            name,
            init,
            methods,
        })
    }
}

/// Compute the 4-byte BLAKE3-prefix selector from a canonical signature.
fn selector_bytes(sig: &str) -> [u8; 4] {
    let h = blake3::hash(sig.as_bytes());
    let b = h.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

/// Convert "FooBar" → "foo_bar" for use as a module name.
fn to_snake_case(camel: &str) -> String {
    let mut out = String::new();
    for (i, c) in camel.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Build the canonical method signature string: `"<domain>.<method>(<types>)"`.
fn method_sig(domain: &str, method: &str, args: &[Arg]) -> String {
    let mut s = String::new();
    s.push_str(domain);
    s.push('.');
    s.push_str(method);
    s.push('(');
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(a.ty.sig());
    }
    s.push(')');
    s
}

#[proc_macro]
pub fn contract(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as ContractInput);
    match emit_contract(parsed) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn emit_contract(c: ContractInput) -> Result<TokenStream2> {
    let contract_name_str = c.name.to_string();
    let domain = to_snake_case(&contract_name_str);
    let mod_ident = format_ident!("{}", domain);

    // Validate Bytes positioning: only ever the LAST argument; never a return.
    for m in &c.methods {
        if let Some(ret) = &m.ret {
            if matches!(ret, AbiType::Bytes) {
                return Err(syn::Error::new(
                    m.name.span(),
                    "`bytes` is not a valid return type (raw return payloads bypass the ABI)",
                ));
            }
        }
        for (i, a) in m.args.iter().enumerate() {
            if matches!(a.ty, AbiType::Bytes) && i + 1 != m.args.len() {
                return Err(syn::Error::new(
                    a.name.span(),
                    "`bytes` is only valid as the LAST argument (it consumes the rest of calldata)",
                ));
            }
        }
    }
    if let Some(init) = &c.init {
        for (i, a) in init.args.iter().enumerate() {
            if matches!(a.ty, AbiType::Bytes) && i + 1 != init.args.len() {
                return Err(syn::Error::new(
                    a.name.span(),
                    "`bytes` in init is only valid as the LAST argument",
                ));
            }
        }
    }

    // ---- Selector constants & sig strings ----
    let mut sel_consts = Vec::new();
    let mut sig_consts = Vec::new();
    for m in &c.methods {
        let sig = method_sig(&domain, &m.name.to_string(), &m.args);
        let sel = selector_bytes(&sig);
        let sel_ident = format_ident!("SEL_{}", m.name.to_string().to_uppercase());
        let sig_ident = format_ident!("SIG_{}", m.name.to_string().to_uppercase());
        let s0 = sel[0];
        let s1 = sel[1];
        let s2 = sel[2];
        let s3 = sel[3];
        let sig_lit = sig.clone();
        sel_consts.push(quote! {
            #[allow(non_upper_case_globals)]
            pub const #sel_ident: [u8; 4] = [#s0, #s1, #s2, #s3];
        });
        sig_consts.push(quote! {
            #[allow(non_upper_case_globals)]
            pub const #sig_ident: &str = #sig_lit;
        });
    }

    // ---- Client-side call builders ----
    let mut call_fns = Vec::new();
    for m in &c.methods {
        let fn_name = m.name.clone();
        let sel_ident = format_ident!("SEL_{}", m.name.to_string().to_uppercase());
        let mut params = Vec::new();
        let mut push_stmts = Vec::new();
        for a in &m.args {
            let name = a.name.clone();
            let pty = a.ty.client_param_ty();
            params.push(quote! { #name: #pty });
            let enc_ident = format_ident!("enc");
            let value: TokenStream2 = match a.ty {
                AbiType::Address | AbiType::Bytes32 => quote! { #name },
                AbiType::U256 | AbiType::U128 | AbiType::U64 | AbiType::Bool => quote! { #name },
                AbiType::AddressVec => quote! { #name },
                AbiType::Bytes => quote! { #name },
            };
            push_stmts.push(a.ty.encode_call(&enc_ident, value));
        }
        call_fns.push(quote! {
            pub fn #fn_name(#(#params),*) -> ::bloom_chain_abi::__private::Vec<u8> {
                let mut enc = ::bloom_chain_abi::Encoder::with_selector(#sel_ident);
                #(#push_stmts)*
                enc.finish()
            }
        });
    }

    // ---- Handler trait ----
    let mut trait_methods = Vec::new();
    for m in &c.methods {
        let fn_name = m.name.clone();
        let mut params = Vec::new();
        for a in &m.args {
            let name = a.name.clone();
            let hty = a.ty.handler_ty();
            params.push(quote! { #name: #hty });
        }
        let ret_ty = match &m.ret {
            None => quote! { () },
            Some(t) => t.handler_ty(),
        };
        trait_methods.push(quote! {
            fn #fn_name(&mut self #(, #params)*) -> ::core::result::Result<#ret_ty, &'static str>;
        });
    }

    let has_internal = c.methods.iter().any(|m| m.internal);
    let internal_trait_method = if has_internal {
        quote! {
            /// Address allowed to invoke `#[internal]` selectors.
            ///
            /// Internal methods reject calls where the caller is not this
            /// address. Used by the pair lock / reentrancy pattern.
            fn reentrancy_addr(&self) -> [u8; 32];
        }
    } else {
        quote! {}
    };

    // ---- Dispatcher arms ----
    let mut arms = Vec::new();
    for m in &c.methods {
        let sel_ident = format_ident!("SEL_{}", m.name.to_string().to_uppercase());
        let fn_name = m.name.clone();
        let mut arg_lets = Vec::new();
        let mut handler_args = Vec::new();
        for a in &m.args {
            let name = a.name.clone();
            let buf_ident = format_ident!("buf");
            let read = a.ty.decode_expr(&buf_ident);
            arg_lets.push(quote! {
                let #name = #read.map_err(::bloom_chain_abi::DispatchError::Decode)?;
            });
            handler_args.push(quote! { #name });
        }
        let internal_guard = if m.internal {
            quote! {
                if caller != &handler.reentrancy_addr() {
                    return ::core::result::Result::Err(
                        ::bloom_chain_abi::DispatchError::Unauthorized
                    );
                }
            }
        } else {
            quote! {}
        };
        let ret_encode: TokenStream2 = match &m.ret {
            None => quote! { ::bloom_chain_abi::__private::Vec::new() },
            Some(t) => {
                let enc_ident = format_ident!("enc");
                let push_call = match t {
                    AbiType::Address | AbiType::Bytes32 => {
                        t.encode_call(&enc_ident, quote! { &ret })
                    }
                    _ => t.encode_call(&enc_ident, quote! { ret }),
                };
                quote! {
                    {
                        let mut enc = ::bloom_chain_abi::Encoder::new();
                        #push_call
                        enc.finish()
                    }
                }
            }
        };
        arms.push(quote! {
            #sel_ident => {
                #internal_guard
                #(#arg_lets)*
                buf.expect_eof().map_err(::bloom_chain_abi::DispatchError::Decode)?;
                let ret = handler.#fn_name(#(#handler_args),*)
                    .map_err(::bloom_chain_abi::DispatchError::Handler)?;
                ::core::result::Result::Ok(#ret_encode)
            }
        });
    }

    // The dispatcher always takes `caller` (32-byte address); methods without
    // #[internal] simply don't use it.
    let dispatch_caller_use = if has_internal {
        quote! { let _ = caller; }
    } else {
        quote! { let _ = caller; }
    };

    let dispatcher = quote! {
        pub fn dispatch<H: Handler>(
            handler: &mut H,
            caller: &[u8; 32],
            calldata: &[u8],
        ) -> ::core::result::Result<::bloom_chain_abi::__private::Vec<u8>, ::bloom_chain_abi::DispatchError> {
            #dispatch_caller_use
            if calldata.len() < 4 {
                return ::core::result::Result::Err(
                    ::bloom_chain_abi::DispatchError::ShortCalldata
                );
            }
            let sel = [calldata[0], calldata[1], calldata[2], calldata[3]];
            let args = &calldata[4..];
            #[allow(unused_mut)]
            let mut buf = ::bloom_chain_abi::Buf::new(args);
            match sel {
                #(#arms),*
                other => ::core::result::Result::Err(
                    ::bloom_chain_abi::DispatchError::UnknownSelector(other),
                ),
            }
        }
    };

    // ---- Init codec ----
    let init_block = if let Some(init) = &c.init {
        let mut client_params = Vec::new();
        let mut push_stmts = Vec::new();
        let mut struct_fields = Vec::new();
        let mut decode_stmts = Vec::new();
        let mut struct_inits = Vec::new();
        for a in &init.args {
            let name = a.name.clone();
            let pty = a.ty.client_param_ty();
            client_params.push(quote! { #name: #pty });
            let enc_ident = format_ident!("enc");
            let value = quote! { #name };
            push_stmts.push(a.ty.encode_call(&enc_ident, value));

            let hty = a.ty.handler_ty();
            struct_fields.push(quote! { pub #name: #hty });
            let buf_ident = format_ident!("buf");
            let read = a.ty.decode_expr(&buf_ident);
            decode_stmts.push(quote! {
                let #name = #read?;
            });
            struct_inits.push(quote! { #name });
        }
        quote! {
            pub fn init_calldata(#(#client_params),*) -> ::bloom_chain_abi::__private::Vec<u8> {
                let mut enc = ::bloom_chain_abi::Encoder::new();
                #(#push_stmts)*
                enc.finish()
            }

            #[derive(Clone, Debug)]
            pub struct InitArgs {
                #(#struct_fields),*
            }

            pub fn parse_init(
                calldata: &[u8],
            ) -> ::core::result::Result<InitArgs, ::bloom_chain_abi::AbiError> {
                #[allow(unused_mut)]
                let mut buf = ::bloom_chain_abi::Buf::new(calldata);
                #(#decode_stmts)*
                buf.expect_eof()?;
                ::core::result::Result::Ok(InitArgs { #(#struct_inits),* })
            }
        }
    } else {
        quote! {}
    };

    let out = quote! {
        #[allow(non_snake_case)]
        pub mod #mod_ident {
            #(#sel_consts)*
            #(#sig_consts)*

            pub mod calls {
                use super::*;
                #(#call_fns)*
            }

            pub trait Handler {
                #(#trait_methods)*
                #internal_trait_method
            }

            #dispatcher

            #init_block
        }
    };

    Ok(out)
}
