//! Fixed-width calldata decoder (DEX spec §4).
//!
//! Provides a cursor-based `Buf` reader that returns `Result<_, AbiError>`
//! on short reads or decoding failures.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::u256::U256;

/// Error type for decoding failures.
#[derive(Debug, PartialEq, Eq)]
pub enum AbiError {
    /// Buffer does not contain enough bytes for the requested read.
    UnexpectedEof { needed: usize, available: usize },
    /// A `bool` byte was neither 0 nor 1.
    InvalidBool(u8),
    /// A `Vec<Address>` length prefix encodes a count that would exceed
    /// the available buffer.
    VecOverflow { count: usize, available: usize },
    /// A `u128` slot had non-zero high bytes when narrowing from a `u256`
    /// (only used in checked narrowing helpers).
    Overflow,
}

#[cfg(feature = "std")]
impl std::fmt::Display for AbiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbiError::UnexpectedEof { needed, available } => {
                write!(f, "unexpected eof: need {needed}, have {available}")
            }
            AbiError::InvalidBool(b) => write!(f, "invalid bool byte: {b}"),
            AbiError::VecOverflow { count, available } => {
                write!(f, "vec overflow: {count} items but {available} bytes left")
            }
            AbiError::Overflow => write!(f, "arithmetic overflow in narrowing conversion"),
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for AbiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AbiError")
    }
}

/// Cursor-based reader over a byte slice.
pub struct Buf<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Buf<'a> {
    /// Create a new `Buf` starting at offset 0.
    pub fn new(data: &'a [u8]) -> Self {
        Buf { data, pos: 0 }
    }

    /// Remaining bytes.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Current read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read exactly `N` bytes.
    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], AbiError> {
        let avail = self.remaining();
        if avail < N {
            return Err(AbiError::UnexpectedEof {
                needed: N,
                available: avail,
            });
        }
        let mut buf = [0u8; N];
        buf.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(buf)
    }

    /// Read a 32-byte address.
    pub fn read_address(&mut self) -> Result<[u8; 32], AbiError> {
        self.read_exact::<32>()
    }

    /// Read a 32-byte `bytes32`.
    pub fn read_bytes32(&mut self) -> Result<[u8; 32], AbiError> {
        self.read_exact::<32>()
    }

    /// Read a `U256` (32 bytes, big-endian).
    pub fn read_u256(&mut self) -> Result<U256, AbiError> {
        let b = self.read_exact::<32>()?;
        Ok(U256(b))
    }

    /// Read a `u128` (16 bytes, big-endian).
    pub fn read_u128(&mut self) -> Result<u128, AbiError> {
        let b = self.read_exact::<16>()?;
        Ok(u128::from_be_bytes(b))
    }

    /// Read a `u64` (8 bytes, big-endian).
    pub fn read_u64(&mut self) -> Result<u64, AbiError> {
        let b = self.read_exact::<8>()?;
        Ok(u64::from_be_bytes(b))
    }

    /// Read a `bool` (1 byte, must be 0 or 1).
    pub fn read_bool(&mut self) -> Result<bool, AbiError> {
        let b = self.read_exact::<1>()?;
        match b[0] {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(AbiError::InvalidBool(other)),
        }
    }

    /// Read a `Vec<Address>` (`u16-BE` length prefix + `length * 32` bytes).
    pub fn read_address_vec(&mut self) -> Result<Vec<[u8; 32]>, AbiError> {
        let len_b = self.read_exact::<2>()?;
        let count = u16::from_be_bytes(len_b) as usize;
        let needed = count * 32;
        if needed > self.remaining() {
            return Err(AbiError::VecOverflow {
                count,
                available: self.remaining(),
            });
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.read_address()?);
        }
        Ok(out)
    }

    /// Assert all bytes have been consumed.
    pub fn expect_eof(&self) -> Result<(), AbiError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(AbiError::UnexpectedEof {
                needed: 0,
                available: self.remaining(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::Encoder;

    fn roundtrip_u256(v: U256) {
        let mut e = Encoder::new();
        e.push_u256(v);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        let decoded = buf.read_u256().unwrap();
        assert_eq!(decoded, v);
    }

    #[test]
    fn u256_roundtrip() {
        roundtrip_u256(U256::ZERO);
        roundtrip_u256(U256::from_u64(u64::MAX));
        roundtrip_u256(U256::from_u128(u128::MAX));
    }

    #[test]
    fn u128_roundtrip() {
        let v: u128 = 0xDEAD_BEEF_CAFE_0000_0000_0000_0001_0001;
        let mut e = Encoder::new();
        e.push_u128(v);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        assert_eq!(buf.read_u128().unwrap(), v);
    }

    #[test]
    fn u64_roundtrip() {
        let v: u64 = 0x0102_0304_0506_0708;
        let mut e = Encoder::new();
        e.push_u64(v);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        assert_eq!(buf.read_u64().unwrap(), v);
    }

    #[test]
    fn bool_roundtrip() {
        let mut e = Encoder::new();
        e.push_bool(true);
        e.push_bool(false);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        assert_eq!(buf.read_bool().unwrap(), true);
        assert_eq!(buf.read_bool().unwrap(), false);
    }

    #[test]
    fn bool_invalid() {
        let data = [2u8];
        let mut buf = Buf::new(&data);
        assert_eq!(buf.read_bool(), Err(AbiError::InvalidBool(2)));
    }

    #[test]
    fn address_roundtrip() {
        let addr = [42u8; 32];
        let mut e = Encoder::new();
        e.push_address(&addr);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        assert_eq!(buf.read_address().unwrap(), addr);
    }

    #[test]
    fn address_vec_roundtrip() {
        let addrs: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut e = Encoder::new();
        e.push_address_vec(&addrs).unwrap();
        let out = e.finish();
        let mut buf = Buf::new(&out);
        let decoded = buf.read_address_vec().unwrap();
        assert_eq!(decoded, addrs);
    }

    #[test]
    fn short_read_error() {
        let data = [0u8; 4]; // Only 4 bytes, need 32 for a U256.
        let mut buf = Buf::new(&data);
        assert!(buf.read_u256().is_err());
    }

    #[test]
    fn bytes32_roundtrip() {
        let b = [0xABu8; 32];
        let mut e = Encoder::new();
        e.push_bytes32(&b);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        assert_eq!(buf.read_bytes32().unwrap(), b);
    }
}
