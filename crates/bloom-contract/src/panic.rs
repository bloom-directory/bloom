//! Panic handler glue.
//!
//! The petal SDK already installs a wasm32 `#[panic_handler]` that routes to
//! `petal.revert("panic")`. This module exists so the `#[bloom::contract]`
//! macro can opt into richer revert payloads in a future phase without
//! redefining the global handler.

/// Marker function used by `#[bloom::contract]`-generated code to signal a
/// revert. Lives here so callers don't depend directly on
/// `bloom_petal_sdk::petal::revert`.
#[inline]
pub fn revert_with(reason: &str) -> ! {
    bloom_petal_sdk::petal::revert(reason)
}
