//! Proc-macro entry points for the `bloom-contract` framework.
//!
//! Phase 1 ships stubs that accept the attribute syntax and pass the input
//! through unchanged. Each follow-up phase implements the real expansion:
//!
//! - Phase 2 — derives ([`AbiEncode`], [`AbiDecode`], [`AbiType`]).
//! - Phase 3 — `#[storage]`.
//! - Phase 4 — `#[bloom::contract]`, `#[event]`, `#[error]`, `#[init]`.
//! - Phase 5 — `#[bloom::interface]`.

use proc_macro::TokenStream;

mod derives;
mod storage_attr;

/// `#[derive(AbiEncode)]` — sequential field encoding for structs;
/// discriminant-prefixed encoding for enums.
#[proc_macro_derive(AbiEncode, attributes(abi))]
pub fn derive_abi_encode(input: TokenStream) -> TokenStream {
    derives::derive_abi_encode(input)
}

/// `#[derive(AbiDecode)]` — symmetric counterpart to `AbiEncode`.
#[proc_macro_derive(AbiDecode, attributes(abi))]
pub fn derive_abi_decode(input: TokenStream) -> TokenStream {
    derives::derive_abi_decode(input)
}

/// `#[derive(AbiType)]` — generates `ABI_TYPE` string + structured schema for
/// manifest emission.
#[proc_macro_derive(AbiType, attributes(abi))]
pub fn derive_abi_type(input: TokenStream) -> TokenStream {
    derives::derive_abi_type(input)
}

/// `#[bloom::contract]` — top-level attribute placed on a `mod` containing
/// the contract's storage struct, init fn, event types, error enum, and
/// handler methods. Phase 1 stub: passes the input through unchanged.
#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// `#[storage]` — placed on the contract's state struct. Generates the
/// `load(ctx) -> Result<Self>` constructor and a `SCHEMA` constant used by
/// the build crate at manifest-emission time.
#[proc_macro_attribute]
pub fn storage(attr: TokenStream, item: TokenStream) -> TokenStream {
    storage_attr::expand(attr, item)
}

/// `#[event]` — placed on an event struct. Phase 1 stub.
#[proc_macro_attribute]
pub fn event(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// `#[error]` — placed on the contract's error enum. Phase 1 stub.
#[proc_macro_attribute]
pub fn error(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// `#[init]` — placed on the contract's initialiser. Phase 1 stub.
#[proc_macro_attribute]
pub fn init(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// `#[bloom::interface]` — placed on a trait declaration to expose an ABI
/// domain. Phase 1 stub.
#[proc_macro_attribute]
pub fn interface(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
