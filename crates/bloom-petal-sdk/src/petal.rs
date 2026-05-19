//! Safe wrappers around `petal.call`, `petal.return`, `petal.revert`.

use alloc::vec::Vec;

use crate::imports;

/// Maximum return-data buffer size for `call` (64 KiB).
const MAX_RETDATA: usize = 65536;

/// Perform a synchronous call to another petal.
///
/// - `callee` — 32-byte instance address of the target petal.
/// - `calldata` — encoded calldata (selector + ABI-encoded args).
/// - `value_loom` — 32-byte big-endian u256 LOOM to attach; use `&[0u8;32]`
///   for zero-value calls.
///
/// Returns `Ok(retdata)` on success (up to 64 KiB of return data).
/// Returns `Err(code)` if the callee reverted or trapped (negative code).
pub fn call(callee: &[u8; 32], calldata: &[u8], value_loom: &[u8; 32]) -> Result<Vec<u8>, i32> {
    // Decode the u128 LOOM value from the 32-byte big-endian representation.
    // The chain spec stores LOOM as u128; the upper 16 bytes of the 32-byte
    // field must be zero in practice. We pass lo/hi as i64 to the host.
    let mut lo_bytes = [0u8; 8];
    let mut hi_bytes = [0u8; 8];
    lo_bytes.copy_from_slice(&value_loom[24..32]);
    hi_bytes.copy_from_slice(&value_loom[16..24]);
    // Note: value_loom[0..16] should be zero for valid u128 LOOM values.
    let lo = i64::from_be_bytes(lo_bytes);
    let hi = i64::from_be_bytes(hi_bytes);

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
