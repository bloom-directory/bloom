//! Typed contract errors.
//!
//! Every error type that crosses a `#[bloom::contract]` handler boundary
//! implements [`Error`]: it carries a stable 4-byte selector (derived from
//! the canonical signature `Domain::Error::Variant(<types>)`) plus an
//! `encode_revert(&self) -> Vec<u8>` that the dispatcher passes straight to
//! `petal.revert`.
//!
//! `#[error]` derives [`Error`] for user enums automatically; [`ContractError`]
//! is the framework's catch-all for internal failures (encode, decode,
//! storage) and is what `?` produces when a handler propagates a generic
//! error type.

use alloc::vec::Vec;

use crate::abi::{AbiEncodeError, AbiError};

/// Stable selector + revert-payload encoding for every error a handler can
/// return.
pub trait Error {
    /// Canonical name of this error (used inside the manifest and for
    /// debugging output). For enums, this is the type name *without* the
    /// variant suffix.
    const NAME: &'static str;

    /// Encode the error as revert bytes:
    /// `blake3("<domain>::<Error>::<Variant>(<types>)")[..4] || abi_payload`.
    /// The dispatcher feeds the result to `petal.revert` verbatim.
    fn encode_revert(&self) -> Vec<u8>;
}

/// Catch-all error: a raw revert payload with no schema.
///
/// Used by the framework for non-user errors (ABI encode/decode failures,
/// host imports returning negative codes, etc.) and by handlers that don't
/// declare a typed error enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractError {
    pub data: Vec<u8>,
}

impl ContractError {
    #[inline]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Wrap a static reason string. Encoded as `b"reason:" || msg.as_bytes()`
    /// so an indexer can distinguish from typed errors.
    pub fn from_str(msg: &str) -> Self {
        let mut data = Vec::with_capacity(7 + msg.len());
        data.extend_from_slice(b"reason:");
        data.extend_from_slice(msg.as_bytes());
        Self { data }
    }
}

impl Error for ContractError {
    const NAME: &'static str = "ContractError";

    fn encode_revert(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl From<AbiEncodeError> for ContractError {
    fn from(e: AbiEncodeError) -> Self {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(b"encode:");
        match e {
            AbiEncodeError::TooManyAddresses(n) | AbiEncodeError::TooLong(n) => {
                data.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        Self::new(data)
    }
}

impl From<AbiError> for ContractError {
    fn from(e: AbiError) -> Self {
        let tag: &[u8] = match e {
            AbiError::UnexpectedEof { .. } => b"decode:eof",
            AbiError::InvalidBool(_) => b"decode:bool",
            AbiError::VecOverflow { .. } => b"decode:vec_overflow",
            AbiError::Overflow => b"decode:overflow",
            AbiError::TrailingBytes { .. } => b"decode:trailing",
            AbiError::InvalidUtf8 => b"decode:utf8",
            AbiError::InvalidDiscriminant(_) => b"decode:discriminant",
        };
        Self::new(tag.to_vec())
    }
}

/// Descriptor for one variant of a `#[error]` enum. The build crate reads
/// the const slice to populate the manifest's `errors` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorVariantDescriptor {
    /// Variant identifier (e.g. `"InsufficientBalance"`).
    pub name: &'static str,
    /// Canonical signature `Domain::Enum::Variant(types)` used to derive
    /// the selector. Stored verbatim so the manifest emitter doesn't have
    /// to reconstruct it.
    pub signature: &'static str,
    /// First four bytes of `blake3(signature)`.
    pub selector: [u8; 4],
    /// Number of payload fields the variant carries.
    pub field_count: usize,
}

/// Convenience alias used by every `#[bloom::contract]` handler signature.
///
/// Users write `pub fn transfer(...) -> Result<bool, MyError>` and the macro
/// re-exports this alias inside the contract module so they don't need to
/// import `core::result::Result` explicitly.
pub type Result<T, E = ContractError> = core::result::Result<T, E>;
