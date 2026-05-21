//! Proc-macros for bloom-chain-abi.
//!
//! `contract!` generates client-side call builders, a guest-side `Handler`
//! trait, a strict-decoding dispatcher, init-calldata codecs, storage
//! accessors, event emitters, and an optional reentrancy guard from a small
//! DSL:
//!
//! ```text
//! bloom_chain_abi::contract! {
//!     contract Pair {
//!         storage {
//!             token0:       Address;
//!             reserve0:     u128;
//!             balances:     Mapping<Address, U256> @ "erc20.balance:";
//!             total_supply: U256 @ "erc20.total_supply";
//!         }
//!
//!         event Transfer(#[indexed] from: Address, #[indexed] to: Address, value: U256);
//!         event Sync(reserve0: u128, reserve1: u128);
//!
//!         init(token0: Address);
//!         fn token0() -> Address;
//!
//!         #[nonreentrant]
//!         fn mint(to: Address);
//!
//!         #[internal]
//!         fn _helper();
//!     }
//! }
//! ```
//!
//! Phase A emits both the legacy root-level `<contract>::calls` module (for
//! existing call sites) AND the new `<contract>::abi` tree
//! (`abi::call`, `abi::events`, `abi::storage`). Once consumers migrate onto
//! the new tree, the legacy emission will be removed.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{Attribute, Ident, LitStr, Result, Token, braced, parenthesized, parse_macro_input};

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

    /// Reference-form parameter type used for event-emitter arguments and
    /// storage setters. Scalars (u64/u128/bool) cross the boundary by value;
    /// addresses, bytes32, and U256 are passed by reference.
    fn ref_param_ty(&self) -> TokenStream2 {
        match self {
            AbiType::Address | AbiType::Bytes32 => quote! { &[u8; 32] },
            AbiType::U256 => quote! { &::bloom_chain_abi::U256 },
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

/// Mapping key types accepted in `Mapping<K, V>` storage declarations.
#[derive(Clone, PartialEq, Eq)]
enum KeyType {
    Address,
    U256,
    AddressAddress,
    AddressU256,
}

impl KeyType {
    /// Tokens for the reference-form parameter type of a `get`/`set` key.
    fn param_ty(&self) -> TokenStream2 {
        match self {
            KeyType::Address => quote! { &[u8; 32] },
            KeyType::U256 => quote! { &::bloom_chain_abi::U256 },
            KeyType::AddressAddress => quote! { (&[u8; 32], &[u8; 32]) },
            KeyType::AddressU256 => quote! { (&[u8; 32], &::bloom_chain_abi::U256) },
        }
    }

    /// Expression that turns the parameter `k` into a byte slice usable by
    /// `slot_mapping`. Emits a `let __kb = ...` binding the caller can refer
    /// to as `&__kb[..]`.
    fn encode_to_bytes(&self, k_ident: &Ident, kb_ident: &Ident) -> TokenStream2 {
        match self {
            KeyType::Address => quote! {
                let #kb_ident: [u8; 32] = ::bloom_chain_abi::storage::encode_key_address(#k_ident);
            },
            KeyType::U256 => quote! {
                let #kb_ident: [u8; 32] = ::bloom_chain_abi::storage::encode_key_u256(#k_ident);
            },
            KeyType::AddressAddress => quote! {
                let #kb_ident: [u8; 64] = ::bloom_chain_abi::storage::encode_key_address_address(
                    #k_ident.0, #k_ident.1,
                );
            },
            KeyType::AddressU256 => quote! {
                let #kb_ident: [u8; 64] = ::bloom_chain_abi::storage::encode_key_address_u256(
                    #k_ident.0, #k_ident.1,
                );
            },
        }
    }
}

/// Storage value types accepted in scalar slots / mapping values.
#[derive(Clone, PartialEq, Eq)]
enum StorageValueType {
    Address,
    Bytes32,
    U256,
    U128,
    U64,
    Bool,
}

impl StorageValueType {
    fn from_abi(t: &AbiType, span: Span) -> Result<Self> {
        match t {
            AbiType::Address => Ok(StorageValueType::Address),
            AbiType::Bytes32 => Ok(StorageValueType::Bytes32),
            AbiType::U256 => Ok(StorageValueType::U256),
            AbiType::U128 => Ok(StorageValueType::U128),
            AbiType::U64 => Ok(StorageValueType::U64),
            AbiType::Bool => Ok(StorageValueType::Bool),
            AbiType::Bytes => Err(syn::Error::new(
                span,
                "`bytes` storage fields are deferred to v1",
            )),
            AbiType::AddressVec => Err(syn::Error::new(
                span,
                "`Vec<Address>` is not a valid storage value type",
            )),
        }
    }

    fn owned_ty(&self) -> TokenStream2 {
        match self {
            StorageValueType::Address | StorageValueType::Bytes32 => quote! { [u8; 32] },
            StorageValueType::U256 => quote! { ::bloom_chain_abi::U256 },
            StorageValueType::U128 => quote! { u128 },
            StorageValueType::U64 => quote! { u64 },
            StorageValueType::Bool => quote! { bool },
        }
    }

    fn set_param_ty(&self) -> TokenStream2 {
        match self {
            StorageValueType::Address | StorageValueType::Bytes32 => quote! { &[u8; 32] },
            StorageValueType::U256 => quote! { &::bloom_chain_abi::U256 },
            StorageValueType::U128 => quote! { u128 },
            StorageValueType::U64 => quote! { u64 },
            StorageValueType::Bool => quote! { bool },
        }
    }

    /// Generate `let <out> = <decode 32B slot>` reading from `<slot>` named
    /// by `slot_ident`. Produces the owned-type value or its zero default
    /// when the slot is unwritten.
    fn read_expr(&self, slot_ident: &Ident) -> TokenStream2 {
        match self {
            StorageValueType::Address | StorageValueType::Bytes32 => quote! {
                match ::bloom_petal_sdk::state::read(&#slot_ident) {
                    ::core::option::Option::Some(v) => v,
                    ::core::option::Option::None => [0u8; 32],
                }
            },
            StorageValueType::U256 => quote! {
                match ::bloom_petal_sdk::state::read(&#slot_ident) {
                    ::core::option::Option::Some(v) => ::bloom_chain_abi::U256(v),
                    ::core::option::Option::None => ::bloom_chain_abi::U256::ZERO,
                }
            },
            StorageValueType::U128 => quote! {
                match ::bloom_petal_sdk::state::read(&#slot_ident) {
                    ::core::option::Option::Some(v) => {
                        let mut buf = [0u8; 16];
                        buf.copy_from_slice(&v[16..32]);
                        u128::from_be_bytes(buf)
                    }
                    ::core::option::Option::None => 0u128,
                }
            },
            StorageValueType::U64 => quote! {
                match ::bloom_petal_sdk::state::read(&#slot_ident) {
                    ::core::option::Option::Some(v) => {
                        let mut buf = [0u8; 8];
                        buf.copy_from_slice(&v[24..32]);
                        u64::from_be_bytes(buf)
                    }
                    ::core::option::Option::None => 0u64,
                }
            },
            StorageValueType::Bool => quote! {
                match ::bloom_petal_sdk::state::read(&#slot_ident) {
                    ::core::option::Option::Some(v) => v[31] != 0,
                    ::core::option::Option::None => false,
                }
            },
        }
    }

    /// Generate the encode + `state::write` call for the setter. `v_ident`
    /// names the incoming value (already in setter-parameter form).
    fn write_expr(&self, slot_ident: &Ident, v_ident: &Ident) -> TokenStream2 {
        match self {
            StorageValueType::Address | StorageValueType::Bytes32 => quote! {
                ::bloom_petal_sdk::state::write(&#slot_ident, #v_ident);
            },
            StorageValueType::U256 => quote! {
                ::bloom_petal_sdk::state::write(&#slot_ident, &#v_ident.0);
            },
            // Inner buffer is named `__buf` (NOT `__slot`) to avoid shadowing
            // the caller-supplied slot-key binding when both happen to be
            // called `__slot` at the call site (which is the macro's own
            // default in `storage_fns`). Shadowing previously caused all
            // u128/u64/bool storage writes to land at the all-zeros slot.
            StorageValueType::U128 => quote! {
                {
                    let mut __buf = [0u8; 32];
                    __buf[16..32].copy_from_slice(&#v_ident.to_be_bytes());
                    ::bloom_petal_sdk::state::write(&#slot_ident, &__buf);
                }
            },
            StorageValueType::U64 => quote! {
                {
                    let mut __buf = [0u8; 32];
                    __buf[24..32].copy_from_slice(&#v_ident.to_be_bytes());
                    ::bloom_petal_sdk::state::write(&#slot_ident, &__buf);
                }
            },
            StorageValueType::Bool => quote! {
                {
                    let mut __buf = [0u8; 32];
                    __buf[31] = #v_ident as u8;
                    ::bloom_petal_sdk::state::write(&#slot_ident, &__buf);
                }
            },
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
    nonreentrant: bool,
    name: Ident,
    args: Vec<Arg>,
    ret: Option<AbiType>,
}

struct InitDecl {
    args: Vec<Arg>,
}

/// One field of a `storage { ... }` block.
enum StorageField {
    Scalar {
        name: Ident,
        ty: StorageValueType,
        tag: String,
    },
    Mapping {
        name: Ident,
        key: KeyType,
        val: StorageValueType,
        tag: String,
    },
}

impl StorageField {
    fn name(&self) -> &Ident {
        match self {
            StorageField::Scalar { name, .. } | StorageField::Mapping { name, .. } => name,
        }
    }
}

/// One field of an `event Name(...)` declaration.
struct EventField {
    name: Ident,
    ty: AbiType,
    indexed: bool,
}

struct EventDecl {
    name: Ident,
    fields: Vec<EventField>,
}

/// A whole `storage { ... }` block (zero or one per contract).
struct StorageBlock {
    fields: Vec<StorageField>,
}

enum Item {
    Method(MethodDecl),
    Init(InitDecl),
    Event(EventDecl),
    Storage(StorageBlock),
}

/// Parse a storage-field declaration:
///
/// ```text
/// <ident> ":" <ty>                                 ["@" <lit>] ";"
/// <ident> ":" "Mapping" "<" <key> "," <val> ">"    ["@" <lit>] ";"
/// ```
fn parse_storage_field(input: ParseStream, domain: &str) -> Result<StorageField> {
    let name: Ident = input.parse()?;
    let _colon: Token![:] = input.parse()?;

    // Peek to see if this is `Mapping<...>` or a plain type.
    let lookahead = input.fork();
    let probe: Ident = lookahead.parse()?;
    let is_mapping = probe == "Mapping" && lookahead.peek(Token![<]);

    let field = if is_mapping {
        let _mapping: Ident = input.parse()?; // consume "Mapping"
        let _lt: Token![<] = input.parse()?;
        // Key type can be Address, U256, or (Address, Address) / (Address, U256).
        let key = parse_mapping_key(input)?;
        let _comma: Token![,] = input.parse()?;
        let val_ty: AbiType = input.parse()?;
        let val_span = name.span();
        let val = StorageValueType::from_abi(&val_ty, val_span)?;
        let _gt: Token![>] = input.parse()?;

        let tag = parse_storage_tag(input, domain, &name, /* mapping = */ true)?;
        StorageField::Mapping {
            name,
            key,
            val,
            tag,
        }
    } else {
        let val_ty: AbiType = input.parse()?;
        let val_span = name.span();
        let ty = StorageValueType::from_abi(&val_ty, val_span)?;
        let tag = parse_storage_tag(input, domain, &name, /* mapping = */ false)?;
        StorageField::Scalar { name, ty, tag }
    };

    let _semi: Token![;] = input.parse()?;
    Ok(field)
}

fn parse_mapping_key(input: ParseStream) -> Result<KeyType> {
    if input.peek(syn::token::Paren) {
        let inner;
        parenthesized!(inner in input);
        let a: Ident = inner.parse()?;
        let _comma: Token![,] = inner.parse()?;
        let b: Ident = inner.parse()?;
        let pair = (a.to_string(), b.to_string());
        match (pair.0.as_str(), pair.1.as_str()) {
            ("Address", "Address") => Ok(KeyType::AddressAddress),
            ("Address", "U256" | "u256") => Ok(KeyType::AddressU256),
            (x, y) => Err(syn::Error::new(
                a.span(),
                format!(
                    "unsupported mapping key tuple `({x}, {y})` (expected `(Address, Address)` or `(Address, U256)`)",
                ),
            )),
        }
    } else {
        let ident: Ident = input.parse()?;
        match ident.to_string().as_str() {
            "Address" => Ok(KeyType::Address),
            "U256" | "u256" => Ok(KeyType::U256),
            other => Err(syn::Error::new(
                ident.span(),
                format!(
                    "unsupported mapping key type `{other}` (expected Address, U256, (Address, Address), or (Address, U256))",
                ),
            )),
        }
    }
}

fn parse_storage_tag(
    input: ParseStream,
    domain: &str,
    name: &Ident,
    is_mapping: bool,
) -> Result<String> {
    if input.peek(Token![@]) {
        let _at: Token![@] = input.parse()?;
        let lit: LitStr = input.parse()?;
        let value = lit.value();
        if value.starts_with("__macro.") {
            return Err(syn::Error::new(
                lit.span(),
                "storage tag prefix `__macro.` is reserved for macro-managed slots",
            ));
        }
        Ok(value)
    } else {
        let base = format!("{}.{}", domain, name);
        if is_mapping {
            Ok(format!("{base}:"))
        } else {
            Ok(base)
        }
    }
}

/// Parse one event-field, optionally tagged `#[indexed]`.
fn parse_event_field(input: ParseStream) -> Result<EventField> {
    let attrs: Vec<Attribute> = input.call(Attribute::parse_outer)?;
    let mut indexed = false;
    for a in &attrs {
        if a.path().is_ident("indexed") {
            indexed = true;
        } else {
            return Err(syn::Error::new_spanned(
                a,
                "only #[indexed] is supported on event fields",
            ));
        }
    }
    let name: Ident = input.parse()?;
    let _colon: Token![:] = input.parse()?;
    let ty: AbiType = input.parse()?;
    if indexed && matches!(ty, AbiType::Bytes) {
        return Err(syn::Error::new(
            name.span(),
            "`#[indexed]` cannot be applied to `bytes` (indexed fields must have a fixed 32-byte encoding)",
        ));
    }
    if matches!(ty, AbiType::Bytes) {
        return Err(syn::Error::new(
            name.span(),
            "`bytes` event fields are deferred to v1",
        ));
    }
    Ok(EventField { name, ty, indexed })
}

impl Item {
    fn parse(input: ParseStream, domain: &str) -> Result<Self> {
        let attrs: Vec<Attribute> = input.call(Attribute::parse_outer)?;
        let mut internal = false;
        let mut internal_span: Option<Span> = None;
        let mut nonreentrant = false;
        let mut nonreentrant_span: Option<Span> = None;
        for a in &attrs {
            if a.path().is_ident("internal") {
                if internal {
                    return Err(syn::Error::new_spanned(
                        a,
                        "duplicate #[internal] attribute",
                    ));
                }
                internal = true;
                internal_span = Some(a.path().span());
            } else if a.path().is_ident("nonreentrant") {
                if nonreentrant {
                    return Err(syn::Error::new_spanned(
                        a,
                        "duplicate #[nonreentrant] attribute",
                    ));
                }
                nonreentrant = true;
                nonreentrant_span = Some(a.path().span());
            } else {
                return Err(syn::Error::new_spanned(
                    a,
                    "only #[internal] and #[nonreentrant] are supported on contract methods",
                ));
            }
        }

        if internal && nonreentrant {
            // Report the conflict on the second-applied attribute. We don't
            // know which one came second from the attribute list order alone
            // (syn preserves source order), so attach to nonreentrant by
            // convention — the spec describes that case explicitly.
            let span = nonreentrant_span
                .or(internal_span)
                .unwrap_or(Span::call_site());
            return Err(syn::Error::new(
                span,
                "combining #[internal] and #[nonreentrant] on the same fn is not allowed",
            ));
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
                nonreentrant,
                name,
                args,
                ret,
            }))
        } else if lookahead.peek(Ident) {
            // Either `init(...)`, `event Name(...)`, or `storage { ... }`.
            let fork = input.fork();
            let ident: Ident = fork.parse()?;
            let kw = ident.to_string();
            if kw == "init" {
                if internal {
                    return Err(syn::Error::new(
                        ident.span(),
                        "#[internal] is not valid on init",
                    ));
                }
                if nonreentrant {
                    return Err(syn::Error::new(
                        ident.span(),
                        "#[nonreentrant] is not valid on init",
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
            } else if kw == "event" {
                if !attrs.is_empty() {
                    return Err(syn::Error::new(
                        ident.span(),
                        "attributes are not valid on `event` declarations",
                    ));
                }
                let _ident: Ident = input.parse()?;
                let name: Ident = input.parse()?;
                let content;
                parenthesized!(content in input);
                let mut fields = Vec::new();
                while !content.is_empty() {
                    fields.push(parse_event_field(&content)?);
                    if !content.is_empty() {
                        let _comma: Token![,] = content.parse()?;
                    }
                }
                let _semi: Token![;] = input.parse()?;
                Ok(Item::Event(EventDecl { name, fields }))
            } else if kw == "storage" {
                if !attrs.is_empty() {
                    return Err(syn::Error::new(
                        ident.span(),
                        "attributes are not valid on `storage` blocks",
                    ));
                }
                let _ident: Ident = input.parse()?;
                let body;
                braced!(body in input);
                let mut fields = Vec::new();
                while !body.is_empty() {
                    fields.push(parse_storage_field(&body, domain)?);
                }
                Ok(Item::Storage(StorageBlock { fields }))
            } else {
                Err(syn::Error::new(
                    ident.span(),
                    format!("expected `fn`, `init`, `event`, or `storage`, got `{kw}`"),
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
    events: Vec<EventDecl>,
    storage: Vec<StorageField>,
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
        let domain = to_snake_case(&name.to_string());
        let body;
        braced!(body in input);

        let mut init = None;
        let mut methods = Vec::new();
        let mut events = Vec::new();
        let mut storage = Vec::new();
        let mut storage_seen = false;
        while !body.is_empty() {
            match Item::parse(&body, &domain)? {
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
                Item::Event(e) => events.push(e),
                Item::Storage(s) => {
                    if storage_seen {
                        return Err(syn::Error::new(
                            name.span(),
                            "duplicate `storage` block in contract",
                        ));
                    }
                    storage_seen = true;
                    storage = s.fields;
                }
            }
        }

        Ok(ContractInput {
            name,
            init,
            methods,
            events,
            storage,
        })
    }
}

trait SpanExt {
    fn span(&self) -> Span;
}

impl SpanExt for syn::Path {
    fn span(&self) -> Span {
        syn::spanned::Spanned::span(self)
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

/// Build the canonical event signature string: `"<Name>(<types>)"`.
fn event_sig(name: &str, fields: &[EventField]) -> String {
    let mut s = String::new();
    s.push_str(name);
    s.push('(');
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(f.ty.sig());
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
        if let Some(ret) = &m.ret
            && matches!(ret, AbiType::Bytes)
        {
            return Err(syn::Error::new(
                m.name.span(),
                "`bytes` is not a valid return type (raw return payloads bypass the ABI)",
            ));
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

    // Reject duplicate storage field names.
    {
        let mut seen = std::collections::HashSet::new();
        for f in &c.storage {
            let n = f.name();
            if !seen.insert(n.to_string()) {
                return Err(syn::Error::new(
                    n.span(),
                    format!("duplicate storage field `{n}`"),
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

    // ---- Reentrancy lock slot (only generated if any fn is nonreentrant) ----
    let has_nonreentrant = c.methods.iter().any(|m| m.nonreentrant);
    let lock_tag = format!("__macro.nonreentrant.{}", domain);
    let revert_msg = format!("{}: reentrant call", domain);
    let (lock_slot_const, lock_clear_fn) = if has_nonreentrant {
        let lock_bytes = blake3::hash(lock_tag.as_bytes());
        let b: &[u8; 32] = lock_bytes.as_bytes();
        let byte_literals = b.iter().map(|x| quote! { #x }).collect::<Vec<_>>();
        let byte_literals2 = b.iter().map(|x| quote! { #x }).collect::<Vec<_>>();
        (
            quote! {
                #[allow(non_upper_case_globals)]
                const __NONREENTRANT_LOCK_SLOT: [u8; 32] = [ #(#byte_literals),* ];
            },
            quote! {
                /// Clear the macro-managed reentrancy lock for this contract.
                ///
                /// Must be called by user code in any `#[nonreentrant]` handler
                /// before invoking a divergent terminator (e.g.
                /// `petal::return_data`) that prevents the dispatcher's
                /// post-handler clear from running. After tx-level success the
                /// lock is reset to zero; on revert tx-level atomicity rolls
                /// back the lock write.
                pub fn nonreentrant_lock_clear() {
                    const __LOCK_SLOT: [u8; 32] = [ #(#byte_literals2),* ];
                    ::bloom_petal_sdk::state::write(&__LOCK_SLOT, &[0u8; 32]);
                }
            },
        )
    } else {
        (quote! {}, quote! {})
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

        // Reentrancy guard wraps the handler call (check+set lock before,
        // clear on success). The lock is NOT cleared on revert; tx-level
        // atomicity rolls back the lock write.
        let revert_msg_lit = revert_msg.clone();
        let (lock_pre, lock_post) = if m.nonreentrant {
            (
                quote! {
                    {
                        let __cur = ::bloom_petal_sdk::state::read(&__NONREENTRANT_LOCK_SLOT);
                        let __locked = match __cur {
                            ::core::option::Option::Some(v) => v[31] == 1,
                            ::core::option::Option::None => false,
                        };
                        if __locked {
                            return ::core::result::Result::Err(
                                ::bloom_chain_abi::DispatchError::Handler(#revert_msg_lit),
                            );
                        }
                        let mut __slot = [0u8; 32];
                        __slot[31] = 1;
                        ::bloom_petal_sdk::state::write(&__NONREENTRANT_LOCK_SLOT, &__slot);
                    }
                },
                quote! {
                    {
                        let __slot = [0u8; 32];
                        ::bloom_petal_sdk::state::write(&__NONREENTRANT_LOCK_SLOT, &__slot);
                    }
                },
            )
        } else {
            (quote! {}, quote! {})
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
                #lock_pre
                let ret = handler.#fn_name(#(#handler_args),*)
                    .map_err(::bloom_chain_abi::DispatchError::Handler)?;
                #lock_post
                ::core::result::Result::Ok(#ret_encode)
            }
        });
    }

    // The dispatcher always takes `caller` (32-byte address); methods without
    // #[internal] simply don't use it.
    let dispatch_caller_use = quote! { let _ = caller; };

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

    // ---- Event emitters ----
    let event_topic_consts = c
        .events
        .iter()
        .map(|e| {
            let topic_ident = format_ident!(
                "{}_TOPIC",
                to_snake_case(&e.name.to_string()).to_uppercase()
            );
            let sig = event_sig(&e.name.to_string(), &e.fields);
            let sel = selector_bytes(&sig);
            let s0 = sel[0];
            let s1 = sel[1];
            let s2 = sel[2];
            let s3 = sel[3];
            let sig_ident =
                format_ident!("{}_SIG", to_snake_case(&e.name.to_string()).to_uppercase());
            let sig_lit = sig.clone();
            quote! {
                #[allow(non_upper_case_globals)]
                pub const #topic_ident: [u8; 4] = [#s0, #s1, #s2, #s3];
                #[allow(non_upper_case_globals)]
                pub const #sig_ident: &str = #sig_lit;
            }
        })
        .collect::<Vec<_>>();

    let event_emit_fns = c
        .events
        .iter()
        .map(|e| {
            let topic_ident = format_ident!(
                "{}_TOPIC",
                to_snake_case(&e.name.to_string()).to_uppercase()
            );
            let fn_ident = format_ident!("emit_{}", to_snake_case(&e.name.to_string()));
            let mut params = Vec::new();
            let mut indexed_push = Vec::new();
            let mut data_push = Vec::new();
            for f in &e.fields {
                let n = f.name.clone();
                let pty = f.ty.ref_param_ty();
                params.push(quote! { #n: #pty });
                let enc_ident = format_ident!("enc");
                if f.indexed {
                    // Indexed fields are encoded into a 32-byte topic each. Per
                    // the v0 chain log host import (4-byte topics only), we
                    // pre-pend them to the data blob. The first topic remains
                    // the 4-byte event-signature prefix; downstream consumers
                    // read the 32-byte indexed fields by position.
                    match f.ty {
                        AbiType::Address | AbiType::Bytes32 => {
                            indexed_push.push(quote! {
                                #enc_ident.push_address(#n);
                            });
                        }
                        AbiType::U256 => {
                            indexed_push.push(quote! {
                                #enc_ident.push_u256(*#n);
                            });
                        }
                        AbiType::U128 => {
                            indexed_push.push(quote! {
                            {
                                let __k: [u8; 32] = ::bloom_chain_abi::storage::encode_key_u128(#n);
                                #enc_ident.push_bytes(&__k);
                            }
                        });
                        }
                        AbiType::U64 => {
                            indexed_push.push(quote! {
                            {
                                let __k: [u8; 32] = ::bloom_chain_abi::storage::encode_key_u64(#n);
                                #enc_ident.push_bytes(&__k);
                            }
                        });
                        }
                        AbiType::Bool => {
                            indexed_push.push(quote! {
                            {
                                let __k: [u8; 32] = ::bloom_chain_abi::storage::encode_key_bool(#n);
                                #enc_ident.push_bytes(&__k);
                            }
                        });
                        }
                        AbiType::AddressVec | AbiType::Bytes => unreachable!(),
                    }
                } else {
                    match f.ty {
                        AbiType::Address | AbiType::Bytes32 => {
                            data_push.push(quote! { #enc_ident.push_address(#n); });
                        }
                        AbiType::U256 => {
                            data_push.push(quote! { #enc_ident.push_u256(*#n); });
                        }
                        AbiType::U128 => {
                            data_push.push(quote! { #enc_ident.push_u128(#n); });
                        }
                        AbiType::U64 => {
                            data_push.push(quote! { #enc_ident.push_u64(#n); });
                        }
                        AbiType::Bool => {
                            data_push.push(quote! { #enc_ident.push_bool(#n); });
                        }
                        AbiType::AddressVec => {
                            data_push.push(quote! {
                                #enc_ident.push_address_vec(#n)
                                    .expect("address vec length must fit in u16");
                            });
                        }
                        AbiType::Bytes => unreachable!(),
                    }
                }
            }
            quote! {
                pub fn #fn_ident(#(#params),*) {
                    let mut enc = ::bloom_chain_abi::Encoder::new();
                    #(#indexed_push)*
                    #(#data_push)*
                    let data = enc.finish();
                    ::bloom_petal_sdk::log::emit(&[#topic_ident], &data);
                }
            }
        })
        .collect::<Vec<_>>();

    // ---- Storage accessors ----
    let storage_fns = c.storage.iter().map(|f| {
        match f {
            StorageField::Scalar { name, ty, tag } => {
                let getter = name.clone();
                let setter = format_ident!("set_{}", name);
                let owned = ty.owned_ty();
                let set_param = ty.set_param_ty();
                let slot_ident = format_ident!("__slot");
                let read = ty.read_expr(&slot_ident);
                let v_ident = format_ident!("v");
                let write = ty.write_expr(&slot_ident, &v_ident);
                let tag_lit = tag.clone();
                quote! {
                    pub fn #getter() -> #owned {
                        let #slot_ident: [u8; 32] = ::bloom_chain_abi::storage::slot_scalar(#tag_lit);
                        #read
                    }
                    pub fn #setter(#v_ident: #set_param) {
                        let #slot_ident: [u8; 32] = ::bloom_chain_abi::storage::slot_scalar(#tag_lit);
                        #write
                    }
                }
            }
            StorageField::Mapping {
                name,
                key,
                val,
                tag,
            } => {
                let mod_name = name.clone();
                let key_ty = key.param_ty();
                let val_owned = val.owned_ty();
                let val_set = val.set_param_ty();
                let k_ident = format_ident!("k");
                let kb_ident = format_ident!("__kb");
                let key_encode = key.encode_to_bytes(&k_ident, &kb_ident);
                let slot_ident = format_ident!("__slot");
                let read = val.read_expr(&slot_ident);
                let v_ident = format_ident!("v");
                let write = val.write_expr(&slot_ident, &v_ident);
                let tag_lit = tag.clone();
                quote! {
                    pub mod #mod_name {
                        #[allow(unused_imports)]
                        use super::*;
                        pub fn get(#k_ident: #key_ty) -> #val_owned {
                            #key_encode
                            let #slot_ident: [u8; 32] = ::bloom_chain_abi::storage::slot_mapping(
                                #tag_lit, &#kb_ident,
                            );
                            #read
                        }
                        pub fn set(#k_ident: #key_ty, #v_ident: #val_set) {
                            #key_encode
                            let #slot_ident: [u8; 32] = ::bloom_chain_abi::storage::slot_mapping(
                                #tag_lit, &#kb_ident,
                            );
                            #write
                        }
                    }
                }
            }
        }
    }).collect::<Vec<_>>();

    // Both surfaces share the same `call_fns`. We emit them under
    // `<contract>::calls` (legacy) AND under `<contract>::abi::call` (new).
    // Phase D will delete the legacy emission once consumers have migrated.
    let out = quote! {
        #[allow(non_snake_case)]
        pub mod #mod_ident {
            #(#sel_consts)*
            #(#sig_consts)*

            #lock_slot_const

            // Legacy emission — kept for Phase A compatibility with existing
            // call sites that import `<contract>::calls::*`. Phase D will
            // delete this in favour of the `abi::call` tree below.
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

            /// New canonical entry point per spec §"Generated surface".
            ///
            /// Mirrors the legacy `calls` / event-pack / storage-key
            /// emissions but under a single `abi` namespace. Phase A emits
            /// both; later phases will collapse onto this tree.
            pub mod abi {
                #[allow(unused_imports)]
                use super::*;

                #lock_clear_fn

                pub mod call {
                    #[allow(unused_imports)]
                    use super::*;
                    #(#call_fns)*
                }

                pub mod events {
                    #[allow(unused_imports)]
                    use super::*;
                    #(#event_topic_consts)*
                    #(#event_emit_fns)*
                }

                pub mod storage {
                    #[allow(unused_imports)]
                    use super::*;
                    #(#storage_fns)*
                }
            }
        }
    };

    Ok(out)
}
