//! Dispatcher error type for `contract!`-generated method routers.
//!
//! Variants carry enough context for hosts to translate into chain-level
//! errors (e.g. revert with reason) without losing the cause.

use crate::decode::AbiError;

/// Failure modes for the macro-generated dispatcher.
#[derive(Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// Calldata is shorter than the 4-byte selector.
    ShortCalldata,
    /// Selector did not match any declared method on this contract.
    UnknownSelector([u8; 4]),
    /// Argument decoding (or strict-EOF check) failed.
    Decode(AbiError),
    /// Caller is not authorized to invoke this `#[internal]` method.
    Unauthorized,
    /// Handler returned an explicit error string.
    Handler(&'static str),
}

#[cfg(feature = "std")]
impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::ShortCalldata => write!(f, "calldata shorter than 4-byte selector"),
            DispatchError::UnknownSelector(s) => write!(
                f,
                "unknown selector: {:02x}{:02x}{:02x}{:02x}",
                s[0], s[1], s[2], s[3]
            ),
            DispatchError::Decode(e) => write!(f, "decode error: {e}"),
            DispatchError::Unauthorized => write!(f, "caller is not the reentrancy_addr"),
            DispatchError::Handler(s) => write!(f, "handler error: {s}"),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DispatchError")
    }
}
