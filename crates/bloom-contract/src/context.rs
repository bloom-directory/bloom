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

use bloom_petal_sdk::{block, msg, petal};
pub use bloom_petal_sdk::value::LoomValue;

use crate::error::{ContractError, Result};
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
        Self { _private: PhantomData }
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

    /// Perform a typed cross-contract call. `&mut` because the callee can
    /// mutate state; the dispatcher rolls back the callee on revert via
    /// snapshot semantics, so this is safe for nested calls.
    pub fn raw_call(
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

    /// Emit a log entry under `topics` with `data` as the payload.
    ///
    /// Topics are 32 bytes apiece. The `#[event]` macro builds the topic
    /// list and ABI-encoded data; user code rarely calls this directly.
    pub fn emit_raw(&mut self, topics: &[[u8; 32]], data: &[u8]) {
        bloom_petal_sdk::log::emit_topics32(topics, data);
    }
}
