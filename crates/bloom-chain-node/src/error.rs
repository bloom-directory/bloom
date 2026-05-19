//! `NodeError` — top-level error enum for bloom-chain-node.

use thiserror::Error;

/// All errors that can arise during node operation.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("genesis error: {0}")]
    Genesis(String),

    #[error("state error: {0}")]
    State(#[from] bloom_chain_state::StateError),

    #[error("consensus error: {0}")]
    Consensus(#[from] bloom_chain_consensus::ConsensusError),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("SSZ decode error: {0}")]
    Ssz(String),

    #[error("BLAKE3 digest mismatch — frame dropped")]
    DigestMismatch,

    #[error("unknown msg_type byte: {0}")]
    UnknownMsgType(u8),

    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(usize),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("block not found at height {0}")]
    BlockNotFound(u64),

    #[error("wasmtime version mismatch: expected {expected:?}, got {actual:?}")]
    WasmtimeVersionMismatch { expected: String, actual: String },

    #[error("keystore error: {0}")]
    Keystore(String),

    #[error("anyhow: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml error: {0}")]
    Toml(String),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
}

impl From<toml::de::Error> for NodeError {
    fn from(e: toml::de::Error) -> Self {
        NodeError::Toml(e.to_string())
    }
}
