//! Proc-macros for the Bloom-native contracts framework
//! (spec §11 / §12).
//!
//! Public surface:
//!
//! - `#[bloom::petal]` — module-level attribute that emits the wasm
//!   custom-section manifest plus a runtime registry of the module's
//!   `pub fn` entry points (spec §11.1).
//! - `#[object]` — struct-level attribute marking a linear,
//!   id-bearing on-chain object (spec §4 / §11.3).
//! - `#[capability]` — struct-level attribute marking a `key,
//!   store, copy` cap-token (spec §5).
//! - `#[invariant]` — function-level attribute that records a
//!   predicate + target into the manifest and re-emits the function
//!   as `__inv_<idx>(scope_ptr, scope_len) -> i32` (spec §12).
//!
//! All the heavy lifting (parsing, code emission, manifest
//! construction, canonical encoding) lives in private modules that
//! cannot be re-exported because of Rust's `proc-macro = true` crate
//! restriction.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::too_many_lines)]
// The crate's internal manifest codec / AST helpers are exercised
// primarily by tests + by the macro-expansion paths. Production lib
// builds therefore see lots of "dead code" — that's by design.
#![allow(dead_code)]

extern crate proc_macro;

use proc_macro::TokenStream;

mod ast;
mod bloom_type;
mod capability;
mod codegen;
mod error;
mod invariant;
mod object;
mod petal;
mod type_tag;

/// Attribute applied to a `mod` declaration to mark it as a Bloom
/// petal entry-point. Emits the `__petal_<fn>` wasm exports and the
/// `bloom_petal_manifest_v0` custom section (spec §8 / §11.1).
#[proc_macro_attribute]
pub fn petal(attr: TokenStream, item: TokenStream) -> TokenStream {
    petal::expand(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Attribute applied to a struct declaration to mark it as an
/// on-chain object (`key` + optional `store`/`copy`/`drop` abilities).
/// See spec §4.
#[proc_macro_attribute]
pub fn object(attr: TokenStream, item: TokenStream) -> TokenStream {
    object::expand(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Attribute applied to a struct declaration to mark it as a
/// capability token. Sugar for `#[object(abilities = "key, store, copy")]`
/// plus a `CapabilityMarker` impl (spec §5).
#[proc_macro_attribute]
pub fn capability(attr: TokenStream, item: TokenStream) -> TokenStream {
    capability::expand(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Attribute applied to a function declaration to register a
/// PTB-time invariant. Emits a `__inv_<idx>` wasm export and pushes
/// an [`InvariantDecl`](bloom_petal_manifest::types::InvariantDecl) into the manifest (spec §12).
#[proc_macro_attribute]
pub fn invariant(attr: TokenStream, item: TokenStream) -> TokenStream {
    invariant::expand(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Derive canonical `BloomType` encoding/decoding for plain value
/// structs and enums.
#[proc_macro_derive(BloomType)]
pub fn derive_bloom_type(item: TokenStream) -> TokenStream {
    bloom_type::expand(item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
