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
