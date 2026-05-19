//! `Context` — the runtime handle threaded through every contract method.
//!
//! Phase 1 ships only the shape. Wired methods (sender/value/block, event
//! emission, typed calls) land alongside the `#[bloom::contract]` attribute
//! macro in Phase 4.

use core::marker::PhantomData;

/// Per-invocation runtime context.
///
/// `Context` is zero-sized on wasm32: every accessor is a thin wrapper around
/// a chain.* host import. On host targets it panics — `#[bloom::contract]`
/// modules are designed to run inside `bloom-petals` (wasmtime) rather than
/// natively on the host.
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
}
