//! `tokens/known.json` payload types for the VFS token surface.
//!
//! The well-known token *table* itself now lives in `bloom_proto::tokens`
//! (the single source of truth shared by the send path, the route path, and
//! this VFS surface). `KnownToken`/`for_chain` are re-exported here so the
//! `addresses/<a>/tokens/` handler keeps its existing import path.
//!
//! Addresses are stored lowercase and re-checksummed at serialization time,
//! so casing can never be wrong.

use serde::Serialize;

pub use bloom_proto::tokens::for_chain;

/// One curated token in `known.json`.
#[derive(Serialize)]
pub struct KnownEntry {
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
    pub source: &'static str,
}

/// One history-discovered token in `known.json`.
#[derive(Serialize)]
pub struct DiscoveredEntry {
    pub address: String,
    pub symbol: String,
    pub source: &'static str,
}

/// The full `tokens/known.json` payload.
#[derive(Serialize)]
pub struct KnownJson {
    pub chain: String,
    /// One of: `etherscan` (discovery ran), `unsupported` (etherscan
    /// configured but history unavailable on this chain / no creds),
    /// `rpc`, `indexer` (backend has no history-discovery).
    pub discovery_backend: String,
    pub note: String,
    pub known: Vec<KnownEntry>,
    pub discovered: Vec<DiscoveredEntry>,
}
