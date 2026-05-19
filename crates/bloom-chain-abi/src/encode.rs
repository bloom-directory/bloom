//! Fixed-width calldata encoder.
//!
//! Layout rules are documented on the crate root. This module owns the
//! `Encoder` cursor and its `push_*` helpers; consumers (clients, dispatch
//! macros, return packers, event packers) all share this surface.

use alloc::vec::Vec;

use crate::u256::U256;

/// A minimal write buffer that wraps a `Vec<u8>`.
pub struct Encoder(Vec<u8>);

impl Encoder {
    /// Create an empty encoder.
    pub fn new() -> Self {
        Encoder(Vec::new())
    }

    /// Create an empty encoder with a capacity hint.
    pub fn with_capacity(cap: usize) -> Self {
        Encoder(Vec::with_capacity(cap))
    }

    /// Create an encoder pre-filled with the 4-byte method selector.
    pub fn with_selector(sel: [u8; 4]) -> Self {
        let mut e = Encoder::new();
        e.push_bytes(&sel);
        e
    }

    /// Append raw bytes.
    pub fn push_bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }

    /// Encode a 32-byte address.
    pub fn push_address(&mut self, addr: &[u8; 32]) -> &mut Self {
        self.push_bytes(addr)
    }

    /// Encode a `U256` (32 bytes, big-endian).
    pub fn push_u256(&mut self, v: U256) -> &mut Self {
        self.push_bytes(&v.0)
    }

    /// Encode a `u256` from raw bytes (big-endian, 32 bytes).
    pub fn push_u256_bytes(&mut self, b: &[u8; 32]) -> &mut Self {
        self.push_bytes(b)
    }

    /// Encode a `u128` (16 bytes, big-endian).
    pub fn push_u128(&mut self, v: u128) -> &mut Self {
        self.push_bytes(&v.to_be_bytes())
    }

    /// Encode a `u64` (8 bytes, big-endian).
    pub fn push_u64(&mut self, v: u64) -> &mut Self {
        self.push_bytes(&v.to_be_bytes())
    }

    /// Encode a `bool` (1 byte: 0 or 1).
    pub fn push_bool(&mut self, v: bool) -> &mut Self {
        self.0.push(if v { 1 } else { 0 });
        self
    }

    /// Encode a `bytes32` (32 bytes, verbatim).
    pub fn push_bytes32(&mut self, b: &[u8; 32]) -> &mut Self {
        self.push_bytes(b)
    }

    /// Encode a `Vec<Address>` (path arg): `u16-BE length || length * 32 bytes`.
    ///
    /// Returns `Err` if the number of addresses exceeds `u16::MAX`.
    pub fn push_address_vec(&mut self, addrs: &[[u8; 32]]) -> Result<&mut Self, AbiEncodeError> {
        let len = addrs.len();
        if len > u16::MAX as usize {
            return Err(AbiEncodeError::TooManyAddresses(len));
        }
        self.push_bytes(&(len as u16).to_be_bytes());
        for a in addrs {
            self.push_bytes(a);
        }
        Ok(self)
    }

    /// Consume the encoder and return the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.0
    }

    /// Borrow the current buffer.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Current encoded length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when nothing has been pushed.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for encoding failures.
#[derive(Debug, PartialEq, Eq)]
pub enum AbiEncodeError {
    /// `Vec<Address>` path exceeds the `u16` length prefix maximum.
    TooManyAddresses(usize),
    /// A dynamic field (string / bytes / vec) exceeds the `u16` length prefix
    /// maximum (`u16::MAX` bytes / items).
    TooLong(usize),
}

#[cfg(feature = "std")]
impl std::fmt::Display for AbiEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbiEncodeError::TooManyAddresses(n) => {
                write!(f, "too many addresses: {n} (max {})", u16::MAX)
            }
            AbiEncodeError::TooLong(n) => {
                write!(f, "dynamic field too long: {n} (max {})", u16::MAX)
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for AbiEncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AbiEncodeError::TooManyAddresses(n) => {
                write!(f, "too many addresses: {n}")
            }
            AbiEncodeError::TooLong(n) => {
                write!(f, "dynamic field too long: {n}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn encode_bool() {
        let mut e = Encoder::new();
        e.push_bool(true);
        e.push_bool(false);
        assert_eq!(e.finish(), vec![1, 0]);
    }

    #[test]
    fn encode_u64() {
        let mut e = Encoder::new();
        e.push_u64(0x0102030405060708);
        assert_eq!(e.finish(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn encode_u128() {
        let v: u128 = 1 << 64;
        let mut e = Encoder::new();
        e.push_u128(v);
        let out = e.finish();
        assert_eq!(out.len(), 16);
        let expected = v.to_be_bytes();
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn encode_address_vec_empty() {
        let mut e = Encoder::new();
        e.push_address_vec(&[]).unwrap();
        assert_eq!(e.finish(), vec![0, 0]);
    }

    #[test]
    fn encode_address_vec_two() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let mut e = Encoder::new();
        e.push_address_vec(&[a, b]).unwrap();
        let out = e.finish();
        assert_eq!(out.len(), 2 + 32 + 32);
        assert_eq!(&out[..2], &[0, 2]);
        assert_eq!(&out[2..34], &[1u8; 32]);
        assert_eq!(&out[34..66], &[2u8; 32]);
    }

    #[test]
    fn with_selector_prefixes() {
        let e = Encoder::with_selector([0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(e.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }
}
