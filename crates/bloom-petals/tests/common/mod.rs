//! Shared helpers for `bloom-petals` integration tests.
//!
//! Centralises the small set of builders / assertions that were previously
//! duplicated across `chain_imports.rs`, `chain_hardening.rs`, and
//! `chain_revert_fuel.rs`.

#![allow(dead_code)]

use bloom_chain_types::{Address, Hash32};
use bloom_petals::BlockCtx;

pub fn make_address(b: u8) -> Address {
    Address([b; 32])
}

pub fn make_hash32(b: u8) -> Hash32 {
    Hash32([b; 32])
}

pub fn wat(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

/// Block context with the conventional `0xAB`-filled `prevhash`. Pass any
/// `number` the test needs; the timestamp is fixed at a real-world value
/// (~2023-11-14) so anything reading `timestamp_ms` sees something sensible.
pub fn block_at(number: u64) -> BlockCtx {
    block_with(number, 0xAB)
}

/// As `block_at`, but lets the caller pick the `prevhash` byte. Used by
/// `chain_revert_fuel.rs`, which deliberately uses a distinct `prevhash`
/// to make any cross-test bleed obvious in failures.
pub fn block_with(number: u64, prevhash_byte: u8) -> BlockCtx {
    BlockCtx {
        number,
        timestamp_ms: 1_700_000_000_000,
        prevhash: Hash32([prevhash_byte; 32]),
    }
}

/// Assert that `actual` is within `tolerance_pct` of `expected` (symmetric).
/// `tolerance_pct` is a percentage, e.g. `25` means ±25%.
pub fn assert_fuel_close(actual: u64, expected: u64, tolerance_pct: u64) {
    let slack = expected.saturating_mul(tolerance_pct) / 100;
    let lo = expected.saturating_sub(slack);
    let hi = expected.saturating_add(slack);
    assert!(
        actual >= lo && actual <= hi,
        "fuel {actual} not within ±{tolerance_pct}% of {expected} (window [{lo}, {hi}])"
    );
}
