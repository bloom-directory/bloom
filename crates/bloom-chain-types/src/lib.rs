//! Wire types for bloom-chain v0 — pure types + SSZ encoding, no I/O.
//!
//! All on-wire types use SSZ (Simple Serialize) for canonical encoding.
//! Every hash uses BLAKE3 with domain separation (see [`digest`]).
//!
//! # Modules
//! - [`types`] — core newtypes: `Address`, `Hash32`, `PubKeyBytes`, `SigBytes`, `Loom`.
//! - [`digest`] — domain-separated BLAKE3 helpers.
//! - [`tx`] — transaction types.
//! - [`block`] — block header and block types.
//! - [`vote`] — consensus message types (votes, proposals, commits).
//! - [`receipt`] — transaction receipts and logs.
//! - [`frame`] — length-prefixed TCP wire framing.

#![forbid(unsafe_code)]

pub mod block;
pub mod digest;
pub mod frame;
pub mod receipt;
pub mod tx;
pub mod types;
pub mod vote;

// Re-export ssz (the ethereum_ssz crate — its lib name is `ssz`) for downstream convenience.
pub use ssz;

// Commonly used re-exports.
pub use types::{Address, Hash32, Loom, PubKeyBytes, SigBytes};
