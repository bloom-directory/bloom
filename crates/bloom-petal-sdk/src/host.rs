//! Safe wrapper around `host.deploy`.

use crate::imports;

/// Deploy a petal as a sub-call from within the current petal.
///
/// The deployer-of-record is the **calling petal's address** (chain spec §7.7).
/// The deployed instance address is deterministic:
///
/// ```text
/// blake3("addr:" || "deploy:" || caller || ":" || salt || ":" || petal_hash)
/// ```
///
/// # Parameters
/// - `petal_hash` — 32-byte BLAKE3 hash of the wasm bytes; must already exist
///   in the chain's `code_root` (uploaded via a prior `Deploy` tx).
/// - `salt` — 32-byte CREATE2-style salt.
/// - `init` — calldata passed to the deployed petal's `init` entry point.
///
/// # Returns
/// `Ok([u8; 32])` — the deployed instance address, on success.
/// `Err(code)` — negative host error code on failure.
pub fn deploy(petal_hash: &[u8; 32], salt: &[u8; 32], init: &[u8]) -> Result<[u8; 32], i32> {
    let mut out_addr = [0u8; 32];
    let result = unsafe {
        imports::host_deploy(
            petal_hash.as_ptr() as i32,
            32,
            salt.as_ptr() as i32,
            32,
            init.as_ptr() as i32,
            init.len() as i32,
            out_addr.as_mut_ptr() as i32,
        )
    };
    if result < 0 {
        return Err(result as i32);
    }
    Ok(out_addr)
}
