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

/// `#[bloom::contract]` — top-level attribute placed on a `mod` containing
/// the contract's storage struct, init fn, event types, error enum, and
/// handler methods. Phase 1 stub: passes the input through unchanged.
#[proc_macro_attribute]
pub fn contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// `#[storage]` — placed on the contract's state struct. Phase 1 stub.
#[proc_macro_attribute]
pub fn storage(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
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
