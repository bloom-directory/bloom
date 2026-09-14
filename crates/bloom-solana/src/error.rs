//! Error surface for the Solana read client.

use thiserror::Error;

/// Errors surfaced by the Solana JSON-RPC transport and typed read methods.
#[derive(Debug, Error)]
pub enum SolanaRpcError {
    /// A chain spec named no usable endpoints.
    #[error("chain '{0}' has no usable HTTP endpoints")]
    NoEndpoints(String),

    /// Transport-level failure (connection, timeout, malformed HTTP) that
    /// could not be recovered by retry/failover.
    #[error("rpc transport: {0}")]
    Transport(String),

    /// The node returned a structured JSON-RPC error.
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },

    /// A successful response whose body did not decode into the expected type.
    #[error("rpc decode: {0}")]
    Decode(String),

    /// The configured expected genesis hash did not match the node's.
    #[error("genesis mismatch for '{chain}': expected {expected}, observed {observed}")]
    GenesisMismatch {
        chain: String,
        expected: String,
        observed: String,
    },

    /// A caller-supplied value (address, signature, encoding) was invalid.
    #[error("invalid value: {0}")]
    Invalid(String),
}
