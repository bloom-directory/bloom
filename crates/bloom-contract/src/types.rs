//! Canonical primitive types shared by all `#[bloom::contract]` modules.
//!
//! These newtypes wrap the raw 32-byte byte arrays used by the wasm host
//! imports. Wrapping (rather than re-using `bloom-chain-types`) keeps the
//! crate `no_std` and free of `serde`/`ssz` dependencies that the wasm guest
//! cannot link.

use core::fmt;

pub use bloom_chain_abi::U256;

/// A 32-byte bloom-chain address. Layout-compatible with `[u8; 32]`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Address(pub [u8; 32]);

impl Address {
    pub const ZERO: Self = Self([0u8; 32]);

    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Address {
    #[inline]
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<Address> for [u8; 32] {
    #[inline]
    fn from(a: Address) -> Self {
        a.0
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Address(0x")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A 32-byte BLAKE3 hash. Layout-compatible with `[u8; 32]`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub const ZERO: Self = Self([0u8; 32]);

    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Hash32 {
    #[inline]
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<Hash32> for [u8; 32] {
    #[inline]
    fn from(h: Hash32) -> Self {
        h.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hash32(0x")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrips_bytes() {
        let bytes = [7u8; 32];
        let a = Address::from(bytes);
        assert_eq!(a.as_bytes(), &bytes);
        assert_eq!(<[u8; 32]>::from(a), bytes);
    }

    #[test]
    fn hash32_zero_is_all_zero() {
        assert_eq!(Hash32::ZERO.as_bytes(), &[0u8; 32]);
    }
}
