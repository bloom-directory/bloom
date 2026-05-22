//! Wasm-side runtime library for Bloom-native petals.
//!
//! This crate is the **runtime layer** for the contracts redesign: it
//! provides the safe Rust API that `#[bloom::petal]` macro output
//! compiles against and that hand-written petals link to directly.
//! Its surface area is the contract that `bloom-resource-macros` and
//! every petal share.
//!
//! Scope:
//! - [`host`] — safe wrappers around the chain VM host imports (spec
//!   §16.2). On `wasm32` these call the real `extern "C"` symbols;
//!   off-wasm they route through a thread-local mock so host-side
//!   unit tests can exercise wrapper logic without a wasm engine.
//! - [`abi`] — canonical args/ret buffer codec for the
//!   `__petal_<fn>(args_ptr, args_len, ret_ptr, ret_cap) -> i32`
//!   wasm-export protocol (spec §11.1).
//! - [`handle`] — `RuntimeHandle` newtype for opaque borrow-table
//!   indices.
//! - [`coin`] — `Coin<T>` and `Balance<T>` typed wrappers.
//! - [`capability`] — `Capability<T>` typed wrapper + `CapabilityMarker`
//!   marker trait.
//! - [`signer`] — `Signer` reference into the PTB's signer vector
//!   (spec §6).
//! - [`uid`] — `UID` newtype for the `id: UID` field of every
//!   `#[object]` struct (spec §4.1).
//! - [`resource`] — `Resource<T>` + `BloomType` trait for non-phantom
//!   generic state (spec §11.2).
//! - [`type_args`] — per-call type-argument context that lets generic
//!   petal fns resolve a phantom `T`'s concrete `TypeTag` at runtime
//!   (spec §5 generic dispatch).
//! - [`error`] — `PetalError` typed error code returned by host
//!   wrappers and (via `as_i32()`) by `__petal_<fn>` wasm exports.
//! - [`linearity`] — client-side `PetalScope` guardrail for
//!   transient-row leakage (spec §4.4).
//!
//! ## Targets
//!
//! - `cargo build`: compiles host-side; the `host` module's mock impl
//!   is active. Useful for unit tests, doctests, and tooling.
//! - `cargo build --target wasm32-unknown-unknown`: compiles for the
//!   chain VM target; the `host` module's `extern "C"` block is active.
//!   The chain VM provides the `object` / `cap` / `signer` / `ptb` /
//!   `log` import modules per spec §16.2.
//!
//! ## Spec
//!
//! `docs/specs/2026-05-20-bloom-native-contracts-design.md` —
//! especially §4 (object model), §5 (capabilities), §6 (authorization),
//! §11 (macros / developer surface), §12 (invariants), §16.2 (host
//! imports).

#![deny(missing_docs)]

pub mod abi;
pub mod capability;
pub mod coin;
pub mod error;
pub mod handle;
pub mod host;
pub mod linearity;
pub mod resource;
pub mod signer;
pub mod type_args;
pub mod uid;

pub use abi::{AbiError, ArgReader, RetWriter};
pub use capability::{Capability, CapabilityMarker};
pub use coin::{Balance, Coin};
pub use error::{CUSTOM_BIT, PetalError};
pub use handle::RuntimeHandle;
pub use linearity::{PetalScope, ScopeGuard};
pub use resource::{BloomType, PRIMITIVE_PETAL_HASH, Resource};
pub use signer::Signer;
pub use type_args::{Erased, TypeArgs, TypeArgsGuard, current_type_arg, current_type_arg_count};
pub use uid::UID;
