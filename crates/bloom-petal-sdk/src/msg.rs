//! Safe wrappers around `msg.sender`, `msg.value`, `msg.calldata.*`.

use alloc::vec::Vec;

use crate::imports;

/// 32-byte address of the message sender (caller of the current petal).
pub fn sender() -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { imports::msg_sender(out.as_mut_ptr() as i32) }
    out
}

/// Native LOOM attached to the current call, as a 32-byte big-endian u256.
///
/// The chain runtime writes the value as a 16-byte little-endian u128 into a
/// caller-supplied buffer. We then re-encode it into a 32-byte big-endian slot
/// with the upper 16 bytes zeroed (since LOOM is u128 at the chain level).
pub fn value() -> [u8; 32] {
    let mut le = [0u8; 16];
    unsafe { imports::msg_value(le.as_mut_ptr() as i32) }
    let v = u128::from_le_bytes(le);
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// Read all calldata for the current call into a `Vec<u8>`.
pub fn calldata() -> Vec<u8> {
    let len = unsafe { imports::msg_calldata_len() };
    if len <= 0 {
        return Vec::new();
    }
    let mut buf = Vec::with_capacity(len as usize);
    buf.resize(len as usize, 0u8);
    let copied = unsafe {
        imports::msg_calldata_read(buf.as_mut_ptr() as i32, 0, len)
    };
    buf.truncate(copied.max(0) as usize);
    buf
}
