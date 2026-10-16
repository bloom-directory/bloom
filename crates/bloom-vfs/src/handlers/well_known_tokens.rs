//! `tokens/known.json` payload types for the VFS token surface.
//!
//! The token list itself is `bloom_broker_api::known_tokens`, the one list
//! Broker and Machine both compile in.
//!
//! Addresses are stored lowercase and re-checksummed at serialization time,
//! so casing can never be wrong.

use serde::Serialize;

pub use bloom_broker_api::tokens_on as for_chain;

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
