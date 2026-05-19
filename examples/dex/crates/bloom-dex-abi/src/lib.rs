//! bloom-dex-abi — host-side and guest-side ABI types for the bloom-chain DEX.
//!
//! Pure Rust, `no_std`-compatible (with `alloc` when `std` feature is off).
//!
//! ## Feature flags
//! - `std` (default): link against the standard library for tests and host tools.
//!   Disable with `default-features = false` when compiling for `wasm32` guests.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod selectors;
pub mod events;
pub mod u256;
pub mod encode;
pub mod decode;

/// Assert that each `selector => method_string` pair matches the v0 canonical
/// rule that selectors are `blake3(method_string)[..4]`.
///
/// Each DEX petal mirrors a slice of the canonical selector table in its own
/// `selectors` module and used to inline the same 5-line `crate_sel` helper +
/// long `assert_eq!` runs in its tests. This macro centralises both.
///
/// The macro hashes via `blake3::hash`, which the caller must have in scope —
/// every DEX petal already depends on `blake3` directly for its own state-key
/// hashing, so this is a no-op import-wise.
#[macro_export]
macro_rules! assert_selector_parity {
    ( $( $sel:expr => $method:expr ),+ $(,)? ) => {{
        fn _expected(method: &[u8]) -> [u8; 4] {
            let h = ::blake3::hash(method);
            let b = h.as_bytes();
            [b[0], b[1], b[2], b[3]]
        }
        $(
            assert_eq!(
                $sel,
                _expected($method),
                "selector parity violated for `{}`",
                core::str::from_utf8($method).unwrap_or("<non-utf8>"),
            );
        )+
    }};
}
