//! bloom-contract — Solana/Anchor-style Rust framework for Bloom petals.
//!
//! This crate is the public runtime surface that `#[bloom::contract]` modules
//! depend on. It re-exports the canonical types ([`Address`], [`Hash32`],
//! [`U256`]) and the user-facing primitives (storage handles, ABI traits,
//! [`Context`], [`Error`]) so contracts only need a single import:
//!
//! ```ignore
//! use bloom_contract::prelude::*;
//! ```
//!
//! All `#[bloom::contract]` attribute macros live in the sibling
//! `bloom-contract-macros` crate and are re-exported through [`prelude`] for
//! ergonomic single-import usage.
//!
//! The crate is `no_std`-friendly: on `wasm32-unknown-unknown` (the target for
//! deployed petals) it compiles without `std`; on host targets the `std`
//! feature unlocks formatting/debug helpers.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod types;
pub mod abi;
pub mod storage;
pub mod context;
pub mod events;
pub mod interface;
pub mod error;
pub mod dispatch;
pub mod reentrancy;
pub mod panic;
pub mod prelude;

// Re-export attribute macros from the sibling proc-macro crate so users can
// write `#[bloom_contract::contract]` directly. The recommended usage path is
// `use bloom_contract::prelude::*;` followed by the bare `#[contract]`.
pub use bloom_contract_macros::{
    AbiDecode, AbiEncode, AbiType, contract, error, event, init, interface, storage,
};

#[doc(hidden)]
pub mod __private {
    pub use alloc::boxed::Box;
    pub use alloc::vec::Vec;
    pub use core::result::Result;
    pub use bloom_chain_abi as chain_abi;
}
