//! Dynamic codec helpers — length-prefixed strings, byte arrays, and
//! variable-length vectors.
//!
//! These helpers extend the fixed-width [`Encoder`](crate::Encoder) /
//! [`Buf`](crate::Buf) codec with `u16-BE` length prefixes for unbounded ABI
//! types.
//!
//! Layout:
//!
//! - `string` — `u16-BE length || UTF-8 bytes` (length ≤ `u16::MAX`)
//! - `bytes`  — `u16-BE length || raw bytes`   (length ≤ `u16::MAX`)
//! - `vec<T>` — `u16-BE length || N * T-encoding`

use alloc::string::String;
use alloc::vec::Vec;

use crate::decode::{AbiError, Buf};
use crate::encode::{AbiEncodeError, Encoder};

/// Maximum length a single dynamic field may encode (constrained by the
/// `u16` length prefix).
pub const MAX_DYN_LEN: usize = u16::MAX as usize;

impl Encoder {
    /// Encode a UTF-8 string as `u16-BE length || bytes`.
    pub fn push_string(&mut self, s: &str) -> Result<&mut Self, AbiEncodeError> {
        let bytes = s.as_bytes();
        let len = bytes.len();
        if len > MAX_DYN_LEN {
            return Err(AbiEncodeError::TooLong(len));
        }
        self.push_bytes(&(len as u16).to_be_bytes());
        self.push_bytes(bytes);
        Ok(self)
    }

    /// Encode a variable-length byte array as `u16-BE length || bytes`.
    pub fn push_bytes_var(&mut self, b: &[u8]) -> Result<&mut Self, AbiEncodeError> {
        let len = b.len();
        if len > MAX_DYN_LEN {
            return Err(AbiEncodeError::TooLong(len));
        }
        self.push_bytes(&(len as u16).to_be_bytes());
        self.push_bytes(b);
        Ok(self)
    }

    /// Encode a `u16-BE` length prefix on its own. Callers that want full
    /// control over how individual elements get encoded use this + their own
    /// per-element `push_*` calls.
    pub fn push_u16_len(&mut self, len: usize) -> Result<&mut Self, AbiEncodeError> {
        if len > MAX_DYN_LEN {
            return Err(AbiEncodeError::TooLong(len));
        }
        self.push_bytes(&(len as u16).to_be_bytes());
        Ok(self)
    }
}

impl<'a> Buf<'a> {
    /// Read a `u16-BE`-prefixed UTF-8 string.
    pub fn read_string(&mut self) -> Result<String, AbiError> {
        let bytes = self.read_bytes_var()?;
        match core::str::from_utf8(&bytes) {
            Ok(_) => Ok(String::from_utf8(bytes).expect("validated above")),
            Err(_) => Err(AbiError::InvalidUtf8),
        }
    }

    /// Read a `u16-BE`-prefixed byte array as an owned `Vec<u8>`.
    pub fn read_bytes_var(&mut self) -> Result<Vec<u8>, AbiError> {
        let len = self.read_u16_len()?;
        if len > self.remaining() {
            return Err(AbiError::UnexpectedEof {
                needed: len,
                available: self.remaining(),
            });
        }
        let start = self.position();
        // Use the public read primitive to advance the cursor.
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&self.data()[start..start + len]);
        self.advance(len);
        Ok(out)
    }

    /// Read a `u16-BE` length prefix and return its value as `usize`.
    pub fn read_u16_len(&mut self) -> Result<usize, AbiError> {
        let b = self.read_u16_bytes()?;
        Ok(u16::from_be_bytes(b) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn string_roundtrip() {
        let mut e = Encoder::new();
        e.push_string("hello").unwrap();
        let out = e.finish();
        assert_eq!(&out[..2], &[0, 5]);
        let mut b = Buf::new(&out);
        assert_eq!(b.read_string().unwrap(), "hello");
        assert_eq!(b.expect_eof(), Ok(()));
    }

    #[test]
    fn string_empty() {
        let mut e = Encoder::new();
        e.push_string("").unwrap();
        let out = e.finish();
        assert_eq!(out, vec![0, 0]);
        let mut b = Buf::new(&out);
        assert_eq!(b.read_string().unwrap(), "");
    }

    #[test]
    fn bytes_var_roundtrip() {
        let mut e = Encoder::new();
        e.push_bytes_var(&[1, 2, 3, 4]).unwrap();
        let out = e.finish();
        assert_eq!(&out[..2], &[0, 4]);
        let mut b = Buf::new(&out);
        assert_eq!(b.read_bytes_var().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn invalid_utf8_rejected() {
        let mut buf = vec![0, 2];
        buf.extend_from_slice(&[0xFF, 0xFE]);
        let mut b = Buf::new(&buf);
        assert_eq!(b.read_string(), Err(AbiError::InvalidUtf8));
    }

    #[test]
    fn overflow_length_rejected() {
        let mut buf = vec![0xFF, 0x10]; // 65296 bytes promised
        buf.extend_from_slice(&[0u8; 4]);
        let mut b = Buf::new(&buf);
        match b.read_bytes_var() {
            Err(AbiError::UnexpectedEof {
                needed: 65296,
                available: 4,
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn too_long_string_rejected() {
        let s: String = "x".repeat(MAX_DYN_LEN + 1);
        let mut e = Encoder::new();
        let res = e.push_string(&s);
        assert!(matches!(res, Err(AbiEncodeError::TooLong(_))));
    }
}
