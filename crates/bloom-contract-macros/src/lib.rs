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

mod contract;
mod derives;
mod error_attr;
mod event_attr;
mod interface_attr;
mod manifest;
mod sig;
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
/// handler methods. Scans the module body and emits `init` / `call` wasm
/// exports plus a `__bloom` submodule with the selector table.
#[proc_macro_attribute]
pub fn contract(attr: TokenStream, item: TokenStream) -> TokenStream {
    contract::expand(attr, item)
}

/// `#[storage]` — placed on the contract's state struct. Generates the
/// `load(ctx) -> Result<Self>` constructor and a `SCHEMA` constant used by
/// the build crate at manifest-emission time.
#[proc_macro_attribute]
pub fn storage(attr: TokenStream, item: TokenStream) -> TokenStream {
    storage_attr::expand(attr, item)
}

/// `#[event]` — placed on an event struct. Derives `AbiEncode`/`AbiDecode`/
/// `AbiType`, emits the `TOPIC0` constant (compile-time blake3 of the event
/// signature), and generates `emit(&self, ctx)` for the hot path.
#[proc_macro_attribute]
pub fn event(attr: TokenStream, item: TokenStream) -> TokenStream {
    event_attr::expand(attr, item)
}

/// `#[error]` — placed on the contract's error enum. Implements
/// `bloom_contract::error::Error`, derives per-variant 4-byte selectors
/// (compile-time blake3), and exposes a `VARIANTS` const for manifest
/// emission.
#[proc_macro_attribute]
pub fn error(attr: TokenStream, item: TokenStream) -> TokenStream {
    error_attr::expand(attr, item)
}

/// `#[init]` — placed on the contract's initialiser. Phase 1 stub.
#[proc_macro_attribute]
pub fn init(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// `#[bloom::interface]` — placed on a trait declaration to describe a
/// cross-contract ABI surface. Emits selector constants, an
/// `InterfaceMethod` descriptor table, and a typed
/// `ContractRef<Trait>` inherent impl for cross-contract calls.
#[proc_macro_attribute]
pub fn interface(attr: TokenStream, item: TokenStream) -> TokenStream {
    interface_attr::expand(attr, item)
}
