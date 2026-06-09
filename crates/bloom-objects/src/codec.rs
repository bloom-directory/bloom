//! Codec helpers that extend `bloom-chain-abi` with the variable-length
//! primitives (`Vec<u8>`, `String`, recursive `TypeTag`) used by the
//! Bloom-native object model.
//!
//! These helpers are intentionally narrow: every length prefix is a
//! big-endian unsigned integer of the smallest width the spec calls for
//! (u16 for strings and `TypeTag::Concrete` type-arg counts; u32 for
//! object payload bytes). The existing fixed-width `Encoder` / `Buf`
//! types in `bloom-chain-abi` cover scalar fields; these helpers cover
//! only what that codec does not.
//!
//! All readers operate on a `&mut &[u8]` cursor so multiple helpers can
//! be chained without allocating an explicit cursor type.

use thiserror::Error;

/// Errors returned by the canonical codec helpers in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CodecError {
    /// Buffer ran out before the requested number of bytes could be read.
    #[error("unexpected eof: need {needed} bytes, have {available}")]
    UnexpectedEof {
        /// Number of bytes the caller tried to read.
        needed: usize,
        /// Number of bytes that were actually available.
        available: usize,
    },
    /// Bytes remained in the buffer after the final declared field was read.
    #[error("trailing bytes after decode: {remaining}")]
    TrailingBytes {
        /// Number of bytes left over.
        remaining: usize,
    },
    /// An enum / variant discriminant byte was outside the valid set.
    #[error("invalid discriminant byte: {0}")]
    InvalidDiscriminant(u8),
    /// A `String` field contained invalid UTF-8.
    #[error("invalid utf-8 in string field")]
    InvalidUtf8,
    /// A length prefix declared more bytes than the buffer contains, or a
    /// length exceeded the helper's declared width.
    #[error("length prefix overflows buffer or width: {0}")]
    LengthOverflow(u64),
    /// A length value was outside the helper's declared bounds.
    #[error("invalid length: {0}")]
    InvalidLength(u64),
    /// A recursively-decoded structure (e.g. a predicate AST) nested
    /// deeper than the decoder's bound. Guards against a malicious blob
    /// stack-overflowing the decoder.
    #[error("recursion limit exceeded while decoding")]
    RecursionLimit,
}

/// Read `N` bytes from `rdr`, advancing the cursor.
fn read_array<const N: usize>(rdr: &mut &[u8]) -> Result<[u8; N], CodecError> {
    if rdr.len() < N {
        return Err(CodecError::UnexpectedEof {
            needed: N,
            available: rdr.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&rdr[..N]);
    *rdr = &rdr[N..];
    Ok(out)
}

/// Read `n` bytes from `rdr`, advancing the cursor.
pub fn read_slice<'a>(rdr: &mut &'a [u8], n: usize) -> Result<&'a [u8], CodecError> {
    if rdr.len() < n {
        return Err(CodecError::UnexpectedEof {
            needed: n,
            available: rdr.len(),
        });
    }
    let (head, tail) = rdr.split_at(n);
    *rdr = tail;
    Ok(head)
}

/// Append a `u8` discriminant byte.
pub fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

/// Read a `u8` discriminant byte.
pub fn read_u8(rdr: &mut &[u8]) -> Result<u8, CodecError> {
    let a = read_array::<1>(rdr)?;
    Ok(a[0])
}

/// Append a big-endian `u16` length prefix or field.
pub fn write_u16_be(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Read a big-endian `u16` length prefix or field.
pub fn read_u16_be(rdr: &mut &[u8]) -> Result<u16, CodecError> {
    let a = read_array::<2>(rdr)?;
    Ok(u16::from_be_bytes(a))
}

/// Append a big-endian `u32`.
pub fn write_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Read a big-endian `u32`.
pub fn read_u32_be(rdr: &mut &[u8]) -> Result<u32, CodecError> {
    let a = read_array::<4>(rdr)?;
    Ok(u32::from_be_bytes(a))
}

/// Append a big-endian `u64`.
pub fn write_u64_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Read a big-endian `u64`.
pub fn read_u64_be(rdr: &mut &[u8]) -> Result<u64, CodecError> {
    let a = read_array::<8>(rdr)?;
    Ok(u64::from_be_bytes(a))
}

/// Append a fixed-length 32-byte field (id, address, hash, ...).
pub fn write_bytes32(buf: &mut Vec<u8>, v: &[u8; 32]) {
    buf.extend_from_slice(v);
}

/// Read a fixed-length 32-byte field.
pub fn read_bytes32(rdr: &mut &[u8]) -> Result<[u8; 32], CodecError> {
    read_array::<32>(rdr)
}

/// Append a variable-length byte vector with a 4-byte BE length prefix.
pub fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len: u32 = bytes
        .len()
        .try_into()
        .expect("bytes length fits in u32 for canonical encoding");
    write_u32_be(buf, len);
    buf.extend_from_slice(bytes);
}

/// Read a variable-length byte vector with a 4-byte BE length prefix.
pub fn read_bytes(rdr: &mut &[u8]) -> Result<Vec<u8>, CodecError> {
    let len = read_u32_be(rdr)? as usize;
    let slice = read_slice(rdr, len)?;
    Ok(slice.to_vec())
}

/// Append a UTF-8 string with a 2-byte BE length prefix.
///
/// Strings longer than `u16::MAX` bytes cannot be encoded; this helper
/// returns an error rather than truncating.
pub fn write_string(buf: &mut Vec<u8>, s: &str) -> Result<(), CodecError> {
    let bytes = s.as_bytes();
    let len: u16 = bytes
        .len()
        .try_into()
        .map_err(|_| CodecError::LengthOverflow(bytes.len() as u64))?;
    write_u16_be(buf, len);
    buf.extend_from_slice(bytes);
    Ok(())
}

/// Read a UTF-8 string with a 2-byte BE length prefix.
pub fn read_string(rdr: &mut &[u8]) -> Result<String, CodecError> {
    let len = read_u16_be(rdr)? as usize;
    let slice = read_slice(rdr, len)?;
    core::str::from_utf8(slice)
        .map(|s| s.to_owned())
        .map_err(|_| CodecError::InvalidUtf8)
}

/// Assert that all bytes in `rdr` have been consumed.
pub fn expect_eof(rdr: &[u8]) -> Result<(), CodecError> {
    if rdr.is_empty() {
        Ok(())
    } else {
        Err(CodecError::TrailingBytes {
            remaining: rdr.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u16_roundtrip() {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, 0xBEEF);
        let mut rdr = buf.as_slice();
        assert_eq!(read_u16_be(&mut rdr).unwrap(), 0xBEEF);
        expect_eof(rdr).unwrap();
    }

    #[test]
    fn u32_roundtrip() {
        let mut buf = Vec::new();
        write_u32_be(&mut buf, 0xDEAD_BEEF);
        let mut rdr = buf.as_slice();
        assert_eq!(read_u32_be(&mut rdr).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn u64_roundtrip() {
        let mut buf = Vec::new();
        write_u64_be(&mut buf, 0x0102_0304_0506_0708);
        let mut rdr = buf.as_slice();
        assert_eq!(read_u64_be(&mut rdr).unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn bytes_roundtrip() {
        let v = b"abcdefg";
        let mut buf = Vec::new();
        write_bytes(&mut buf, v);
        let mut rdr = buf.as_slice();
        assert_eq!(read_bytes(&mut rdr).unwrap(), v);
        expect_eof(rdr).unwrap();
    }

    #[test]
    fn bytes_empty_roundtrip() {
        let mut buf = Vec::new();
        write_bytes(&mut buf, &[]);
        let mut rdr = buf.as_slice();
        assert_eq!(read_bytes(&mut rdr).unwrap(), Vec::<u8>::new());
        expect_eof(rdr).unwrap();
    }

    #[test]
    fn string_roundtrip() {
        let mut buf = Vec::new();
        write_string(&mut buf, "Coin").unwrap();
        let mut rdr = buf.as_slice();
        assert_eq!(read_string(&mut rdr).unwrap(), "Coin");
        expect_eof(rdr).unwrap();
    }

    #[test]
    fn string_invalid_utf8() {
        // 2-byte BE length prefix of 2, then two raw bytes that aren't valid UTF-8.
        let buf = [0u8, 2, 0xFF, 0xFE];
        let mut rdr = buf.as_slice();
        assert_eq!(read_string(&mut rdr), Err(CodecError::InvalidUtf8));
    }

    #[test]
    fn eof_detection() {
        let mut rdr: &[u8] = &[0u8];
        assert!(matches!(
            read_u32_be(&mut rdr),
            Err(CodecError::UnexpectedEof {
                needed: 4,
                available: 1
            })
        ));
    }

    #[test]
    fn trailing_bytes_detection() {
        let rdr: &[u8] = &[0u8, 1, 2];
        assert_eq!(
            expect_eof(rdr),
            Err(CodecError::TrailingBytes { remaining: 3 })
        );
    }

    #[test]
    fn bytes_eof_when_short() {
        // 4-byte BE length prefix says 10 bytes, only 3 follow.
        let buf = [0u8, 0, 0, 10, 1, 2, 3];
        let mut rdr = buf.as_slice();
        assert!(matches!(
            read_bytes(&mut rdr),
            Err(CodecError::UnexpectedEof { .. })
        ));
    }
}
