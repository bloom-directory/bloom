//! Error types for bloom-chain-state.

/// Errors produced by the state layer.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("SSZ encode/decode error: {0}")]
    Ssz(String),

    #[error("state-blob decode error: {0}")]
    BlobDecode(String),

    #[error("state root mismatch: expected {expected}, got {actual}")]
    RootMismatch { expected: String, actual: String },

    #[error("blob store error: {0}")]
    BlobStore(String),

    #[error("blob not found: {0}")]
    BlobNotFound(String),

    #[error(
        "generation conflict: snapshot is stale (state has been mutated since snapshot was taken)"
    )]
    StaleSnapshot,
}
