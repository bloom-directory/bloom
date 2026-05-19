//! Re-export of `bloom-chain-abi::encode`.
//!
//! The chain owns calldata encoding. This module preserves the historical
//! `bloom_dex_abi::encode::{Encoder, AbiEncodeError}` path during migration.

pub use bloom_chain_abi::encode::{AbiEncodeError, Encoder};
