//! Safe wrappers around `block.number`, `block.timestamp`, `block.prevhash`.

use crate::imports;

/// Current block number.
pub fn number() -> u64 {
    unsafe { imports::block_number() as u64 }
}

/// Current block timestamp in milliseconds since UNIX epoch.
pub fn timestamp() -> u64 {
    unsafe { imports::block_timestamp() as u64 }
}

/// 32-byte hash of the previous block.
pub fn prevhash() -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { imports::block_prevhash(out.as_mut_ptr() as i32) }
    out
}
