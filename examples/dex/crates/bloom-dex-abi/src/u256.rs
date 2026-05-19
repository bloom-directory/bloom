//! Re-export of `bloom-chain-abi::u256`.
//!
//! The chain owns the U256 primitive. This module keeps the historical path
//! `bloom_dex_abi::u256::U256` working while callers migrate.

pub use bloom_chain_abi::u256::U256;
