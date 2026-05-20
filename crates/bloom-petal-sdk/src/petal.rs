//! Safe wrappers around `petal.call`, `petal.return`, `petal.revert`.

use alloc::vec::Vec;

use crate::imports;
use crate::value::LoomValue;

/// Maximum return-data buffer size for `call` (64 KiB).
const MAX_RETDATA: usize = 65536;

/// Perform a synchronous call to another petal.
///
/// - `callee` — 32-byte instance address of the target petal.
/// - `calldata` — encoded calldata (selector + ABI-encoded args).
/// - `value_loom` — native LOOM to attach as a [`LoomValue`] (u128-wide).
///   Use [`LoomValue::ZERO`] for zero-value calls.
///
/// Returns `Ok(retdata)` on success (up to 64 KiB of return data).
/// Returns `Err(code)` if the callee reverted or trapped (negative code).
///
/// The value width matches the native LOOM type on the chain
/// (`bloom_chain_types::Loom` is a `u128`). The previous surface accepted a
/// 32-byte big-endian u256 and silently truncated the upper 16 bytes; that
/// foot-gun has been removed — callers holding a u256 representation MUST
/// convert via [`LoomValue::try_from_be_u256_bytes`] and handle the
/// `Overflow` case explicitly.
pub fn call(
    callee: &[u8; 32],
    calldata: &[u8],
    value_loom: LoomValue,
) -> Result<Vec<u8>, i32> {
    // Split the u128 into two i64 halves for the host import.
    let v = value_loom.to_u128();
    let lo = i64::from_ne_bytes((v as u64).to_ne_bytes());
    let hi = i64::from_ne_bytes(((v >> 64) as u64).to_ne_bytes());

    let mut retbuf = Vec::with_capacity(MAX_RETDATA);
    retbuf.resize(MAX_RETDATA, 0u8);

    let result = unsafe {
        imports::petal_call(
            callee.as_ptr() as i32,
            32,
            calldata.as_ptr() as i32,
            calldata.len() as i32,
            lo,
            hi,
            retbuf.as_mut_ptr() as i32,
            MAX_RETDATA as i32,
        )
    };

    if result < 0 {
        return Err(result as i32);
    }

    let len = result as usize;
    retbuf.truncate(len);
    Ok(retbuf)
}

/// Return `data` as the output of the current call and exit successfully.
/// This function does not return.
pub fn return_data(data: &[u8]) -> ! {
    unsafe {
        imports::petal_return(data.as_ptr() as i32, data.len() as i32);
    }
}

/// Revert the current call with a UTF-8 reason message.
/// Discards all writes since the call began. Does not return.
pub fn revert(msg: &str) -> ! {
    unsafe {
        imports::petal_revert(msg.as_ptr() as i32, msg.len() as i32);
    }
}

/// Revert with an arbitrary-bytes payload (not necessarily UTF-8).
///
/// The chain-mode host import `petal.revert` stores `revert_data` verbatim;
/// the `revert(&str)` wrapper above is only a typed convenience. Typed
/// contract errors (selector + ABI payload) flow through this entry point so
/// indexers can decode them by selector.
pub fn revert_bytes(data: &[u8]) -> ! {
    unsafe {
        imports::petal_revert(data.as_ptr() as i32, data.len() as i32);
    }
}

#[cfg(test)]
mod tests {
    //! These tests live alongside the SDK call surface and verify the
    //! `LoomValue`-typed signature. They cannot exercise the host import
    //! (which panics on non-wasm32) but they confirm the value path is
    //! lossless at the type boundary and that overflow on the u256
    //! conversion is surfaced rather than silently truncated.
    use super::*;
    use crate::value::{LoomValue, LoomValueError};

    #[test]
    fn call_signature_takes_loom_value() {
        // Compile-time confirmation that the new signature compiles with
        // a `LoomValue` argument (not `&[u8; 32]`).
        let _f: fn(&[u8; 32], &[u8], LoomValue) -> Result<alloc::vec::Vec<u8>, i32> = call;
    }

    #[test]
    fn u128_max_is_representable_at_api_boundary() {
        // u128::MAX is representable as a LoomValue — the type encodes the
        // full natural width of LOOM. This means it can be passed to
        // `petal::call` without any narrowing.
        let v = LoomValue::from_u128(u128::MAX);
        assert_eq!(v.to_u128(), u128::MAX);
    }

    #[test]
    fn u128_max_plus_one_rejected_not_truncated() {
        // A 32-byte u256 with a single bit set in the high half cannot be
        // converted to a LoomValue — it MUST error, never silently truncate.
        let mut bytes = [0u8; 32];
        bytes[15] = 1; // 2^128
        assert_eq!(
            LoomValue::try_from_be_u256_bytes(&bytes),
            Err(LoomValueError::Overflow),
        );
    }

    #[test]
    fn one_loom_round_trips_through_call_boundary() {
        // 1 LOOM = 10^18 bloomweis — round-trips losslessly.
        let one_loom = 1_000_000_000_000_000_000u128;
        let v = LoomValue::from_u128(one_loom);
        let bytes = v.to_be_u256_bytes();
        let v2 = LoomValue::try_from_be_u256_bytes(&bytes).expect("1 LOOM fits");
        assert_eq!(v, v2);
        assert_eq!(v2.to_u128(), one_loom);
    }

    #[test]
    fn zero_round_trips_through_call_boundary() {
        let z = LoomValue::ZERO;
        let bytes = z.to_be_u256_bytes();
        let z2 = LoomValue::try_from_be_u256_bytes(&bytes).expect("zero fits");
        assert_eq!(z, z2);
        assert!(z2.is_zero());
    }
}
