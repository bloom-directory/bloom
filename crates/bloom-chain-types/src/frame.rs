//! Length-prefixed TCP wire framing (spec §10.2, prior-art §3).
//!
//! Frame layout:
//! ```text
//! +----------+----------+----------------+
//! | 4 bytes  | 1 byte   | <len> bytes    |
//! | len (BE) | msg_type | payload (SSZ)  |
//! +----------+----------+----------------+
//! ```
//!
//! The full frame is `u32_be(payload_len + 1) || msg_type || payload`.
//! Maximum payload size is 16 MiB (enforced on both encode and decode).
//!
//! Note: The chain spec §10.2 also includes a 32-byte frame digest:
//! `blake3("bloom-chain.v0.frame:" || msg_type || payload)`.  The digest is
//! appended after the length field in the full network format.  This module
//! provides helpers for both the simple variant (no digest) and the full
//! framing variant used on the wire.

use thiserror::Error;

/// Maximum allowed payload length: 16 MiB.
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Errors from frame encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FrameError {
    /// The payload exceeds the 16 MiB maximum.
    #[error("payload is {len} bytes, exceeds maximum of {max} bytes", max = MAX_PAYLOAD_LEN)]
    PayloadTooLarge { len: usize },
    /// The frame buffer is too short to contain a complete frame.
    #[error("incomplete frame: need at least {needed} bytes, have {have}")]
    Incomplete { needed: usize, have: usize },
    /// The frame header declares a length that exceeds the maximum.
    #[error("frame declares length {len}, exceeds maximum of {max} bytes", max = MAX_PAYLOAD_LEN)]
    FrameLengthTooLarge { len: usize },
}

/// `msg_type` byte values (spec §10.2).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    Proposal = 0,
    Vote = 1,
    Tx = 2,
    BlockRequest = 3,
    BlockResponse = 4,
    StateBlobRequest = 5,
    StateBlobResponse = 6,
    Ping = 7,
    Pong = 8,
    StateSnapshotRequest = 9,
    StateSnapshotResponse = 10,
}

impl MsgType {
    /// Parse a `msg_type` byte into a [`MsgType`], or `None` if unknown.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(MsgType::Proposal),
            1 => Some(MsgType::Vote),
            2 => Some(MsgType::Tx),
            3 => Some(MsgType::BlockRequest),
            4 => Some(MsgType::BlockResponse),
            5 => Some(MsgType::StateBlobRequest),
            6 => Some(MsgType::StateBlobResponse),
            7 => Some(MsgType::Ping),
            8 => Some(MsgType::Pong),
            9 => Some(MsgType::StateSnapshotRequest),
            10 => Some(MsgType::StateSnapshotResponse),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Simple framing (no digest — for internal use / testing)
// ---------------------------------------------------------------------------

/// Encode a payload into a length-prefixed frame.
///
/// Frame layout: `u32_be(payload.len()) || payload`.
///
/// Returns `Err` if `payload.len()` exceeds [`MAX_PAYLOAD_LEN`].
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLarge { len: payload.len() });
    }
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode the first complete frame from `buf`.
///
/// Returns `(bytes_consumed, payload_slice)` on success, where
/// `bytes_consumed = 4 + payload_len`.
///
/// Returns [`FrameError::Incomplete`] if `buf` does not yet contain a
/// complete frame, and [`FrameError::FrameLengthTooLarge`] if the declared
/// length exceeds [`MAX_PAYLOAD_LEN`].
pub fn decode_frame(buf: &[u8]) -> Result<(usize, &[u8]), FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::Incomplete {
            needed: 4,
            have: buf.len(),
        });
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_PAYLOAD_LEN {
        return Err(FrameError::FrameLengthTooLarge { len });
    }
    let total = 4 + len;
    if buf.len() < total {
        return Err(FrameError::Incomplete {
            needed: total,
            have: buf.len(),
        });
    }
    Ok((total, &buf[4..total]))
}

// ---------------------------------------------------------------------------
// Full wire framing (with msg_type + BLAKE3 digest, spec §10.2)
// ---------------------------------------------------------------------------

/// Encode a full wire frame:
/// `u32_be(1 + 32 + payload.len()) || msg_type || digest || payload`
///
/// `digest = blake3("bloom-chain.v0.frame:" || [msg_type] || payload)`
pub fn encode_wire_frame(msg_type: MsgType, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(FrameError::PayloadTooLarge { len: payload.len() });
    }
    let digest = crate::digest::blake3_tagged(
        crate::digest::tags::FRAME,
        &[&[msg_type as u8], payload].concat(),
    );
    let frame_body_len = 1 + 32 + payload.len();
    let mut out = Vec::with_capacity(4 + frame_body_len);
    out.extend_from_slice(&(frame_body_len as u32).to_be_bytes());
    out.push(msg_type as u8);
    out.extend_from_slice(&digest.0);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode a full wire frame.
///
/// Returns `(bytes_consumed, msg_type_byte, payload_slice)`.
/// Does **not** verify the digest (verification is the caller's responsibility
/// to keep this function allocation-free).
pub fn decode_wire_frame(buf: &[u8]) -> Result<(usize, u8, &[u8]), FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::Incomplete {
            needed: 4,
            have: buf.len(),
        });
    }
    let frame_body_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if frame_body_len > MAX_PAYLOAD_LEN + 1 + 32 {
        return Err(FrameError::FrameLengthTooLarge {
            len: frame_body_len,
        });
    }
    let total = 4 + frame_body_len;
    if buf.len() < total {
        return Err(FrameError::Incomplete {
            needed: total,
            have: buf.len(),
        });
    }
    if frame_body_len < 1 + 32 {
        return Err(FrameError::Incomplete {
            needed: 4 + 1 + 32,
            have: buf.len(),
        });
    }
    let msg_type = buf[4];
    let payload = &buf[4 + 1 + 32..total];
    Ok((total, msg_type, payload))
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"hello bloom-chain";
        let framed = encode_frame(payload).unwrap();
        assert_eq!(framed.len(), 4 + payload.len());
        let (consumed, decoded) = decode_frame(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(decoded, payload);
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        let big = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(
            encode_frame(&big),
            Err(FrameError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn decode_rejects_oversized_frame() {
        // Craft a frame header claiming MAX+1 bytes.
        let too_big = (MAX_PAYLOAD_LEN as u32 + 1).to_be_bytes();
        let buf: Vec<u8> = too_big
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0u8, MAX_PAYLOAD_LEN + 1))
            .collect();
        assert!(matches!(
            decode_frame(&buf),
            Err(FrameError::FrameLengthTooLarge { .. })
        ));
    }

    #[test]
    fn decode_incomplete_header() {
        assert!(matches!(
            decode_frame(&[0, 0, 0]),
            Err(FrameError::Incomplete { needed: 4, .. })
        ));
    }

    #[test]
    fn decode_incomplete_body() {
        // Header says 10 bytes but we only provide 5.
        let mut buf = vec![0u8, 0, 0, 10];
        buf.extend_from_slice(&[1u8; 5]);
        assert!(matches!(
            decode_frame(&buf),
            Err(FrameError::Incomplete { .. })
        ));
    }

    #[test]
    fn decode_empty_payload() {
        let framed = encode_frame(b"").unwrap();
        let (consumed, decoded) = decode_frame(&framed).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(decoded, b"");
    }

    #[test]
    fn wire_frame_encode_decode() {
        let payload = b"vote data";
        let framed = encode_wire_frame(MsgType::Vote, payload).unwrap();
        let (consumed, msg_type, decoded_payload) = decode_wire_frame(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(msg_type, MsgType::Vote as u8);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn msg_type_from_byte() {
        assert_eq!(MsgType::from_byte(0), Some(MsgType::Proposal));
        assert_eq!(MsgType::from_byte(8), Some(MsgType::Pong));
        assert_eq!(MsgType::from_byte(99), None);
    }

    #[test]
    fn wire_frame_rejects_oversized() {
        let big = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(
            encode_wire_frame(MsgType::Tx, &big),
            Err(FrameError::PayloadTooLarge { .. })
        ));
    }
}
