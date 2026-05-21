//! `Context` — the runtime handle threaded through every contract method.
//!
//! `Context` is the *only* way handlers reach the chain. Free functions in
//! `bloom_petal_sdk` are still callable directly but contract code should go
//! through `Context` so handlers can be reviewed in isolation from their host
//! environment and the `#[view]` / `#[payable]` / `#[nonreentrant]`
//! attributes can statically gate access to mutating effects.
//!
//! ## Effect typing
//!
//! - `&Context` — read-only host queries (sender, value, block number,
//!   block timestamp). `#[view]` handlers take this form.
//! - `&mut Context` — adds storage writes, event emission, nested calls, and
//!   deploys. Everything else takes this form.
//!
//! The struct is zero-sized; the `&` / `&mut` distinction exists purely to
//! drive Rust's borrow checker into refusing mutating calls inside a
//! `#[view]` body.

use core::marker::PhantomData;

use alloc::vec::Vec;

pub use bloom_petal_sdk::value::LoomValue;
use bloom_petal_sdk::{block, host, msg, petal};

use crate::error::{ContractError, Result};
use crate::interface::{ContractInterface, ContractRef};
use crate::types::Address;

/// Per-invocation runtime context.
///
/// All accessors are thin wrappers around `bloom_petal_sdk` host imports; on
/// `wasm32-unknown-unknown` they compile to direct host calls, on the host
/// they panic. `#[bloom::contract]` modules are designed to run inside
/// `bloom-petals` (wasmtime) rather than natively.
#[derive(Default)]
pub struct Context {
    _private: PhantomData<()>,
}

impl Context {
    /// Construct a fresh context handle. Cheap (zero-sized).
    #[inline]
    pub const fn new() -> Self {
        Self {
            _private: PhantomData,
        }
    }

    /// 32-byte address of the immediate caller of the current method.
    #[inline]
    pub fn sender(&self) -> Address {
        Address::from(msg::sender())
    }

    /// Native LOOM attached to the current call. Always zero for `#[view]`
    /// or non-`#[payable]` methods (the dispatcher reverts before reaching
    /// the handler if a caller sends value to a non-payable method).
    #[inline]
    pub fn value(&self) -> LoomValue {
        msg::value()
    }

    /// Current block height.
    #[inline]
    pub fn block_number(&self) -> u64 {
        block::number()
    }

    /// Current block timestamp in milliseconds since the Unix epoch.
    #[inline]
    pub fn block_timestamp(&self) -> u64 {
        block::timestamp()
    }

    /// Raw calldata for the current invocation, post-dispatcher (the
    /// 4-byte selector has already been consumed). Useful when a handler
    /// wants to inspect the bytes itself.
    pub fn calldata(&self) -> Vec<u8> {
        msg::calldata()
    }

    // -----------------------------------------------------------------
    // Typed cross-contract gateway
    // -----------------------------------------------------------------

    /// Construct a typed [`ContractRef<I>`] for a deployed contract at
    /// `address`. The returned ref exposes the interface's `<I>Calls`
    /// extension trait methods — each one takes `&mut Context`, so
    /// nested calls are spelled as `factory.create_pair(ctx, ...)`
    /// rather than `ctx.raw_call(&factory, &cd, ...)`.
    ///
    /// This is the spec-level entry point users should reach for. The
    /// raw byte-level call helper is intentionally `#[doc(hidden)]` —
    /// it exists so the interface macro can implement `<I>Calls`
    /// without going through `Context` itself, but contract authors
    /// shouldn't touch it.
    #[inline]
    pub fn call<I: ContractInterface>(&mut self, address: Address) -> ContractRef<I> {
        let _ = self; // future-proof: keeps the `&mut` binding in scope
        ContractRef::<I>::new(address)
    }

    /// Deploy a fresh contract instance from a petal hash, returning a
    /// typed [`ContractRef<I>`] for the resulting address.
    ///
    /// - `petal_hash` is the chain-known hash of the petal blob (the
    ///   `wasm_hash` recorded on `Account.code_hash`).
    /// - `salt` is the caller-supplied 32-byte tag baked into the
    ///   deterministic address derivation (see spec §7.7).
    /// - `init` is the ABI-encoded init payload — typically built with
    ///   `AbiEncode` then handed to the contract's `#[init]` handler.
    ///
    /// Errors propagate the host's error code as a `ContractError` so
    /// `?` works in handler bodies without ad-hoc decoders.
    pub fn deploy<I: ContractInterface>(
        &mut self,
        petal_hash: &[u8; 32],
        salt: &[u8; 32],
        init: &[u8],
    ) -> Result<ContractRef<I>> {
        let _ = self;
        match host::deploy(petal_hash, salt, init) {
            Ok(addr) => Ok(ContractRef::<I>::new(Address::from(addr))),
            Err(code) => {
                let mut data = Vec::with_capacity(16);
                data.extend_from_slice(b"deploy_failed:");
                data.extend_from_slice(&code.to_be_bytes());
                Err(ContractError::new(data))
            }
        }
    }

    // -----------------------------------------------------------------
    // Internal byte-level primitives
    // -----------------------------------------------------------------
    //
    // Renamed to `__call_raw` / `__emit_raw` and marked `#[doc(hidden)]`
    // so they don't appear in user-facing API docs. The interface
    // macro's generated `<I>Calls` impls reach for these by name, and
    // the event macro's `emit()` body does the same — they're plumbing
    // that the framework itself owns. Contract authors should call
    // `ctx.call::<I>(addr).method(ctx, ...)` instead of `ctx.raw_call`,
    // and `MyEvent { ... }.emit(ctx)` instead of `ctx.emit_raw`.

    /// Internal: perform a raw, untyped petal call.
    ///
    /// Used by `#[bloom::interface]` to implement typed call methods;
    /// new contracts should reach the chain through
    /// [`Context::call`] + the interface's extension trait, not this.
    #[doc(hidden)]
    pub fn __call_raw(
        &mut self,
        to: &Address,
        calldata: &[u8],
        value: LoomValue,
    ) -> Result<Vec<u8>> {
        let target = to.as_bytes();
        match petal::call(target, calldata, value) {
            Ok(retdata) => Ok(retdata),
            Err(code) => {
                let mut data = Vec::with_capacity(16);
                data.extend_from_slice(b"call_failed:");
                data.extend_from_slice(&code.to_be_bytes());
                Err(ContractError::new(data))
            }
        }
    }

    /// Internal: emit a log entry under raw topic bytes.
    ///
    /// Called by the `#[event]` macro's `emit()` body. Contract authors
    /// should construct the event struct and call `event.emit(ctx)`
    /// instead of touching this directly.
    #[doc(hidden)]
    pub fn __emit_raw(&mut self, topics: &[[u8; 32]], data: &[u8]) {
        bloom_petal_sdk::log::emit_topics32(topics, data);
    }
}
