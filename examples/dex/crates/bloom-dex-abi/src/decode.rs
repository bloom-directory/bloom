//! Re-export of `bloom-chain-abi::decode`.
//!
//! The chain owns calldata decoding (including the strict `expect_eof`
//! terminator). This module preserves the historical
//! `bloom_dex_abi::decode::{Buf, AbiError}` path during migration.

pub use bloom_chain_abi::decode::{AbiError, Buf};
