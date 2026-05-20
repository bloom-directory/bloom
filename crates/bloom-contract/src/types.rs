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

/// A fixed-size 32-byte slot holding an ASCII/UTF-8 string.
///
/// Used for on-chain metadata that fits in one slot (e.g. ERC-20 `name` /
/// `symbol`). Encodes as `bytes32` on the wire — indistinguishable from a
/// `Hash32` slot — but carries a string-typed API: `pad_right` / `pad_left`
/// const constructors and an `as_str()` view.
///
/// Two padding conventions are supported and must be chosen at construction
/// time: `pad_right` (text first, zeros trailing — the legacy DEX-pair
/// convention) and `pad_left` (zeros first, text trailing — the legacy
/// wLOOM convention). Both are `const fn` so the value can be baked into a
/// `const` slot at compile time.
///
/// # Panics
///
/// In `const` context, construction panics (a compile error) if the input
/// exceeds 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Bytes32String(pub [u8; 32]);

impl Bytes32String {
    /// All-zeros slot.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Construct from raw 32 bytes (no padding applied).
    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Right-pad: text fills the leading bytes, trailing bytes are zero.
    /// (e.g. `b"BDPL" -> [B, D, P, L, 0, 0, ..., 0]`.)
    ///
    /// Panics at compile time if `s.len() > 32`.
    pub const fn pad_right(s: &str) -> Self {
        let bytes = s.as_bytes();
        if bytes.len() > 32 {
            panic!("Bytes32String::pad_right: input exceeds 32 bytes");
        }
        let mut slot = [0u8; 32];
        let mut i = 0;
        while i < bytes.len() {
            slot[i] = bytes[i];
            i += 1;
        }
        Self(slot)
    }

    /// Left-pad: leading bytes are zero, text fills the trailing bytes.
    /// (e.g. `b"wLOOM" -> [0, 0, ..., 0, w, L, O, O, M]`.)
    ///
    /// Panics at compile time if `s.len() > 32`.
    pub const fn pad_left(s: &str) -> Self {
        let bytes = s.as_bytes();
        if bytes.len() > 32 {
            panic!("Bytes32String::pad_left: input exceeds 32 bytes");
        }
        let mut slot = [0u8; 32];
        let offset = 32 - bytes.len();
        let mut i = 0;
        while i < bytes.len() {
            slot[offset + i] = bytes[i];
            i += 1;
        }
        Self(slot)
    }

    /// Raw byte view of the slot.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume self and return the raw 32-byte slot.
    #[inline]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Return the longest UTF-8 prefix of the slot before the first zero
    /// byte. Returns `None` if the bytes are not valid UTF-8.
    ///
    /// Note: this assumes right-padded layout. Left-padded strings
    /// (e.g. wLOOM convention) should use `as_str_trim_left` instead.
    pub fn as_str(&self) -> Option<&str> {
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.0[..end]).ok()
    }

    /// Return the trailing non-zero UTF-8 suffix of the slot — the
    /// counterpart to `as_str` for left-padded layouts.
    pub fn as_str_trim_left(&self) -> Option<&str> {
        let start = self.0.iter().position(|&b| b != 0).unwrap_or(32);
        core::str::from_utf8(&self.0[start..]).ok()
    }
}

impl From<Bytes32String> for Hash32 {
    #[inline]
    fn from(s: Bytes32String) -> Self {
        Hash32(s.0)
    }
}

impl From<Hash32> for Bytes32String {
    #[inline]
    fn from(h: Hash32) -> Self {
        Bytes32String(h.0)
    }
}

impl From<[u8; 32]> for Bytes32String {
    #[inline]
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl From<Bytes32String> for [u8; 32] {
    #[inline]
    fn from(s: Bytes32String) -> Self {
        s.0
    }
}

impl fmt::Debug for Bytes32String {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) if !s.is_empty() => write!(f, "Bytes32String({s:?})"),
            _ => {
                f.write_str("Bytes32String(0x")?;
                for b in &self.0 {
                    write!(f, "{b:02x}")?;
                }
                f.write_str(")")
            }
        }
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

    #[test]
    fn bytes32_pad_right_lays_text_at_start() {
        let s = Bytes32String::pad_right("BDPL");
        assert_eq!(&s.as_bytes()[..4], b"BDPL");
        assert!(s.as_bytes()[4..].iter().all(|&b| b == 0));
        assert_eq!(s.as_str(), Some("BDPL"));
    }

    #[test]
    fn bytes32_pad_left_lays_text_at_end() {
        let s = Bytes32String::pad_left("wLOOM");
        assert!(s.as_bytes()[..27].iter().all(|&b| b == 0));
        assert_eq!(&s.as_bytes()[27..], b"wLOOM");
        assert_eq!(s.as_str_trim_left(), Some("wLOOM"));
    }

    #[test]
    fn bytes32_const_construction() {
        const SLOT: Bytes32String = Bytes32String::pad_right("BloomDexPair LP");
        assert_eq!(&SLOT.as_bytes()[..15], b"BloomDexPair LP");
        assert!(SLOT.as_bytes()[15..].iter().all(|&b| b == 0));
    }

    #[test]
    fn bytes32_full_32_bytes_fits() {
        let s = Bytes32String::pad_right("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(s.as_bytes(), &[b'A'; 32]);
    }

    #[test]
    fn bytes32_roundtrips_hash32() {
        let s = Bytes32String::pad_right("hello");
        let h: Hash32 = s.into();
        let s2: Bytes32String = h.into();
        assert_eq!(s, s2);
    }
}
