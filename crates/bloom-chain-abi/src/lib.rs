//! Chain-owned canonical ABI.
//!
//! This crate is the single source of truth for how data crosses the
//! bloom-chain calldata / return / event boundary. Petals (guest contracts)
//! and chain hosts share the encoding rules defined here.
//!
//! Layout per type (fixed-width, no padding, no length encoding except where
//! noted):
//!
//! - `address` / `bytes32` — 32 bytes
//! - `u256` — 32 bytes, big-endian
//! - `u128` — 16 bytes, big-endian
//! - `u64`  — 8 bytes, big-endian
//! - `bool` — 1 byte (0 or 1)
//! - `Vec<Address>` — 2-byte big-endian length prefix + length * 32 bytes
//!
//! Method selectors are the first 4 bytes of `blake3(method_string)`. Event
//! topic prefixes use the same rule on the event signature.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod decode;
pub mod dispatch;
pub mod dyn_codec;
pub mod encode;
pub mod event;
pub mod selector;
pub mod storage;
pub mod u256;

pub use decode::{AbiError, Buf};
pub use dispatch::DispatchError;
pub use dyn_codec::MAX_DYN_LEN;
pub use encode::{AbiEncodeError, Encoder};
pub use event::{event_signature_topic, event_topic};
pub use selector::selector;
pub use u256::U256;

// Re-export the proc-macro under the chain-abi namespace so consumers write
// `bloom_chain_abi::contract! { ... }`.
pub use bloom_chain_abi_macros::contract;

#[doc(hidden)]
pub mod __private {
    pub use alloc::vec::Vec;
}
