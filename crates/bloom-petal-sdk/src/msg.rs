//! Safe wrappers around `msg.sender`, `msg.value`, `msg.calldata.*`.

use alloc::vec::Vec;

use crate::imports;
use crate::value::LoomValue;

/// 32-byte address of the message sender (caller of the current petal).
pub fn sender() -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { imports::msg_sender(out.as_mut_ptr() as i32) }
    out
}

/// Native LOOM attached to the current call.
///
/// The chain runtime stores LOOM as `u128` and writes it as 16 little-endian
/// bytes via the host import; we decode and return a [`LoomValue`] directly.
/// Previously this returned a 32-byte big-endian `[u8; 32]` representation,
/// which paired with a u256-shaped `petal::call` value parameter that
/// silently truncated the upper 16 bytes. Both surfaces have been migrated
/// to `LoomValue` to remove the foot-gun. Callers needing the 32-byte u256
/// form can call [`LoomValue::to_be_u256_bytes`].
pub fn value() -> LoomValue {
    let mut le = [0u8; 16];
    unsafe { imports::msg_value(le.as_mut_ptr() as i32) }
    LoomValue::from_u128(u128::from_le_bytes(le))
}

/// Read all calldata for the current call into a `Vec<u8>`.
pub fn calldata() -> Vec<u8> {
    let len = unsafe { imports::msg_calldata_len() };
    if len <= 0 {
        return Vec::new();
    }
    let mut buf = vec![0; len as usize];
    let copied = unsafe { imports::msg_calldata_read(buf.as_mut_ptr() as i32, 0, len) };
    buf.truncate(copied.max(0) as usize);
    buf
}
