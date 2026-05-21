//! Safe wrappers around the `chain.code.*` host imports.
//!
//! These read code-related metadata from on-chain accounts. Today this is
//! only the optional manifest anchor introduced in bloom-rust-contracts
//! Phase 8; future imports (e.g. `code.hash_of(addr)`) belong here too.

use crate::imports;

/// Read the optional manifest anchor for `addr`.
///
/// Returns `Some(hash)` if the deployer of `addr` committed to a manifest
/// at deploy time, `None` otherwise (including for EOAs and for any
/// account that was deployed before the Phase 8 anchor field existed).
///
/// `Err(code)` on host-side failure (negative wasm error code).
pub fn manifest_hash(addr: &[u8; 32]) -> Result<Option<[u8; 32]>, i32> {
    let mut out = [0u8; 33];
    let result =
        unsafe { imports::code_manifest_hash(addr.as_ptr() as i32, out.as_mut_ptr() as i32) };
    if result < 0 {
        return Err(result);
    }
    match out[0] {
        0 => Ok(None),
        1 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&out[1..33]);
            Ok(Some(hash))
        }
        // The host writes only 0 or 1; an unexpected value indicates host
        // / SDK skew. Surface it as an error code distinct from negatives.
        _ => Err(-1),
    }
}
