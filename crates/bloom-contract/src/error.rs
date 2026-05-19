//! Typed contract errors.
//!
//! Phase 1 ships only the [`Error`] trait. The `#[bloom::error]` attribute
//! macro (Phase 4) derives selector bytes and `encode_revert` for any
//! `enum`-shaped error type.

use alloc::vec::Vec;

/// Every error type used in a `#[bloom::contract]` method must implement
/// `Error`. The macro emits this impl automatically for `#[error] pub enum
/// Foo { ... }`; users rarely implement it by hand.
pub trait Error {
    /// Canonical name of this error (used inside the manifest).
    const NAME: &'static str;

    /// Encode the error as revert bytes:
    /// `blake3("<domain>::<Error>::<Variant>(<types>)")[..4] || abi-payload`.
    fn encode_revert(&self) -> Vec<u8>;
}

/// A fallback error type that wraps a raw revert payload. Useful for FFI
/// boundaries where the caller doesn't know the contract's error enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractError {
    pub data: Vec<u8>,
}

impl ContractError {
    #[inline]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// Convenience alias used by every `#[bloom::contract]` handler signature.
///
/// Users write `pub fn transfer(...) -> Result<bool, MyError>` and the macro
/// re-exports this alias inside the contract module so they don't need to
/// import `core::result::Result` explicitly.
pub type Result<T, E = ContractError> = core::result::Result<T, E>;
