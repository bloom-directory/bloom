//! Errors raised by the RPC engine.

use alloy::transports::TransportError;
use thiserror::Error;

/// Top-level error variant returned by `bloom-rpc` constructors and the
/// (still-stub) session API. Callers in `bloom-evm` translate this into
/// their own `ChainError` so we don't leak this enum across crate
/// boundaries unnecessarily.
#[derive(Debug, Error)]
pub enum BloomRpcError {
    /// One of the configured endpoints had an unparsable URL.
    #[error("invalid endpoint url '{url}': {source}")]
    InvalidUrl {
        /// The URL string that failed to parse.
        url: String,
        /// The underlying parser error.
        #[source]
        source: url::ParseError,
    },

    /// A `ChainSpec` resolved to zero usable endpoints.
    #[error("no rpc endpoints configured for chain '{0}'")]
    NoEndpoints(String),

    /// Wraps an alloy transport-level error from the layered stack.
    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    /// Every configured endpoint returned a non-retryable error and the
    /// fallback layer ran out of healthy candidates.
    #[error("all endpoints failed for chain '{chain}': {last_error}")]
    AllEndpointsFailed {
        /// Human-readable chain name for log/UX context.
        chain: String,
        /// The last error surfaced by the fallback layer.
        last_error: String,
    },
}
