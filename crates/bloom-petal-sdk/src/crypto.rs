//! Safe wrapper around `crypto.blake3`.

use crate::imports;

/// Compute BLAKE3(`data`) via the chain host import.
///
/// Returns 32 bytes. This is an untagged BLAKE3 hash — the chain's domain-
/// tagged hashes (for addresses, tx hashes, etc.) are handled by the chain
/// internals. Use this for guest-side storage key derivation, salt generation,
/// and any other hashing the petal needs to do itself.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let result = unsafe {
        imports::crypto_blake3(
            data.as_ptr() as i32,
            data.len() as i32,
            out.as_mut_ptr() as i32,
        )
    };
    if result < 0 {
        crate::petal::revert("crypto_blake3 failed");
    }
    out
}
