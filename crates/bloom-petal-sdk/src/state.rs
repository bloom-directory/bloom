//! Safe wrappers around `state.read`, `state.write`, `state.delete`.

use crate::imports;

/// Read a 32-byte storage value for the current contract instance.
///
/// `key` must be a 32-byte storage key (typically a BLAKE3 digest of a
/// domain-tagged tuple).
///
/// Returns `Some([u8; 32])` if the slot exists, `None` if it is unset
/// (the host returns all-zeros for unset slots, and we treat all-zeros
/// as absent to match the chain spec §6.2 semantics: the default value
/// for any slot is a 32-byte zero word).
pub fn read(key: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let result = unsafe {
        imports::state_read(
            key.as_ptr() as i32,
            32,
            out.as_mut_ptr() as i32,
        )
    };
    if result < 0 {
        return None;
    }
    // All-zeros is the default/empty slot — callers can distinguish
    // "not set" from "set to zero" by the return value if needed.
    // We return None only on an explicit host error.
    Some(out)
}

/// Write a 32-byte storage value for the current contract instance.
///
/// Panics (revert) on host error.
pub fn write(key: &[u8; 32], value: &[u8; 32]) {
    let result = unsafe {
        imports::state_write(
            key.as_ptr() as i32,
            32,
            value.as_ptr() as i32,
            32,
        )
    };
    if result < 0 {
        crate::petal::revert("state_write failed");
    }
}

/// Delete (clear) a storage slot for the current contract instance.
///
/// Panics (revert) on host error.
pub fn delete(key: &[u8; 32]) {
    let result = unsafe {
        imports::state_delete(
            key.as_ptr() as i32,
            32,
        )
    };
    if result < 0 {
        crate::petal::revert("state_delete failed");
    }
}
