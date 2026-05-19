//! Safe wrapper around `log.emit`.

use crate::imports;

/// Emit a log entry attached to the current tx's receipt.
///
/// `topics` — slice of 4-byte topic selectors (each `[u8; 4]`, typically a
///   BLAKE3-4 prefix of the event signature). The host stores
///   `topic_count * 32` bytes; we zero-pad each 4-byte topic to 32 bytes
///   before passing to the host.
/// `data` — unstructured log payload.
///
/// Panics (revert) on host error.
pub fn emit(topics: &[[u8; 4]], data: &[u8]) {
    // The host log.emit expects topic_count * 32 bytes of topic data.
    // Each topic is a 4-byte selector (typically BLAKE3-4 of the event
    // signature); zero-pad to 32 bytes as Solidity-style events expect.
    let mut topic_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(topics.len() * 32);
    for t in topics {
        topic_buf.extend_from_slice(t);
        topic_buf.extend_from_slice(&[0u8; 28]); // pad to 32 bytes
    }

    let result = unsafe {
        imports::log_emit(
            topic_buf.as_ptr() as i32,
            topics.len() as i32,
            data.as_ptr() as i32,
            data.len() as i32,
        )
    };
    if result < 0 {
        crate::petal::revert("log_emit failed");
    }
}
