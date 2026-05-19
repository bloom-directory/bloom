//! Storage-slot derivation helpers used by `contract!`-generated code.
//!
//! The `contract!` proc-macro emits storage accessors that delegate to the
//! free functions in this module to derive 32-byte storage keys and to encode
//! mapping keys. The encoder rules mirror the calldata encoder in
//! `crate::encode` so a single source defines on-wire layout for both
//! calldata and storage-key derivation.
//!
//! Slot layout rules (matching the current hand-rolled patterns in the DEX):
//!
//! - **Scalar slot**: `blake3("<tag>")[..32]`
//! - **Mapping slot**: `blake3("<tag>" || encode_key(k))[..32]`
//!
//! Where `encode_key` is the per-type 32-byte encoding:
//! - `Address` / `bytes32` — 32 bytes verbatim.
//! - `U256` — 32 bytes, big-endian.
//! - `u128` — 16 bytes BE, left-padded to 32 bytes.
//! - `u64`  — 8 bytes BE, left-padded to 32 bytes.
//! - `bool` — 32 bytes, last byte 0/1.
//! - `(Address, Address)` / `(Address, U256)` — concat of per-element 32B
//!   encodings.

use core::marker::PhantomData;

use crate::u256::U256;

/// Phantom-typed wrapper for storage mappings.
///
/// The macro emits per-mapping accessor modules with concrete `get` / `set`
/// functions; this struct is here purely as a type-level documentation aid
/// so that user-facing DSL declarations like `Mapping<Address, U256>` parse
/// cleanly without needing runtime encoder traits.
pub struct Mapping<K, V> {
    _phantom: PhantomData<(K, V)>,
}

impl<K, V> Mapping<K, V> {
    /// Construct a phantom mapping reference. Never actually used at runtime —
    /// the macro emits free functions instead.
    pub const fn new() -> Self {
        Mapping {
            _phantom: PhantomData,
        }
    }
}

impl<K, V> Default for Mapping<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a scalar-slot key from a domain tag.
///
/// `slot_scalar(tag) == blake3(tag)[..32]`. Returned bytes are the storage
/// key passed to `state::read` / `state::write`.
pub fn slot_scalar(tag: &str) -> [u8; 32] {
    let h = blake3::hash(tag.as_bytes());
    *h.as_bytes()
}

/// Derive a mapping-slot key from a domain tag plus pre-encoded key bytes.
///
/// `slot_mapping(tag, kb) == blake3(tag.as_bytes() || kb)[..32]`. The caller
/// is responsible for encoding the mapping key via one of the
/// `encode_key_*` helpers before invoking this.
pub fn slot_mapping(tag: &str, key_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(tag.as_bytes());
    h.update(key_bytes);
    *h.finalize().as_bytes()
}

// ---- Per-type 32-byte key encodings ----------------------------------------

/// Encode an address key (32 bytes verbatim).
pub fn encode_key_address(addr: &[u8; 32]) -> [u8; 32] {
    *addr
}

/// Encode a `U256` key (32 bytes, big-endian).
pub fn encode_key_u256(v: &U256) -> [u8; 32] {
    v.0
}

/// Encode a `u128` key (16 bytes BE, left-padded to 32 bytes).
pub fn encode_key_u128(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// Encode a `u64` key (8 bytes BE, left-padded to 32 bytes).
pub fn encode_key_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

/// Encode a `bool` key (32 bytes, last byte 0/1).
pub fn encode_key_bool(v: bool) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = if v { 1 } else { 0 };
    out
}

/// Encode a `(Address, Address)` tuple key (concatenated, 64 bytes).
pub fn encode_key_address_address(a: &[u8; 32], b: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(a);
    out[32..].copy_from_slice(b);
    out
}

/// Encode an `(Address, U256)` tuple key (concatenated, 64 bytes).
pub fn encode_key_address_u256(a: &[u8; 32], b: &U256) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(a);
    out[32..].copy_from_slice(&b.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn slot_scalar_matches_blake3_prefix() {
        let s = slot_scalar("pair.token0");
        let h = blake3::hash(b"pair.token0");
        assert_eq!(&s[..], &h.as_bytes()[..]);
    }

    #[test]
    fn slot_mapping_matches_blake3_concat() {
        let addr = [0x42u8; 32];
        let s = slot_mapping("erc20.balance:", &addr);
        let mut buf = Vec::<u8>::new();
        buf.extend_from_slice(b"erc20.balance:");
        buf.extend_from_slice(&addr);
        let h = blake3::hash(&buf);
        assert_eq!(&s[..], &h.as_bytes()[..]);
    }

    #[test]
    fn encode_u128_left_pads() {
        let k = encode_key_u128(0x0102_0304_0506_0708);
        // High 16 bytes are zero, low 16 bytes are u128 big-endian:
        //   0x0000_0000_0000_0000_0102_0304_0506_0708
        assert_eq!(&k[..24], &[0u8; 24]);
        assert_eq!(&k[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn encode_u64_left_pads() {
        let k = encode_key_u64(0x0102_0304_0506_0708);
        assert_eq!(&k[..24], &[0u8; 24]);
        assert_eq!(&k[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn encode_bool_last_byte() {
        let t = encode_key_bool(true);
        let f = encode_key_bool(false);
        assert_eq!(t[31], 1);
        assert_eq!(f[31], 0);
        assert_eq!(&t[..31], &[0u8; 31]);
        assert_eq!(&f[..31], &[0u8; 31]);
    }

    #[test]
    fn encode_address_address_tuple() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let k = encode_key_address_address(&a, &b);
        assert_eq!(&k[..32], &a[..]);
        assert_eq!(&k[32..], &b[..]);
    }

    #[test]
    fn encode_address_u256_tuple() {
        let a = [0x11u8; 32];
        let v = U256::from_u64(0x42);
        let k = encode_key_address_u256(&a, &v);
        assert_eq!(&k[..32], &a[..]);
        assert_eq!(&k[32..], &v.0[..]);
    }

    #[test]
    fn slot_derivation_deterministic() {
        let a = slot_scalar("pair.token0");
        let b = slot_scalar("pair.token0");
        assert_eq!(a, b);

        let addr = [0x42u8; 32];
        let a = slot_mapping("erc20.balance:", &addr);
        let b = slot_mapping("erc20.balance:", &addr);
        assert_eq!(a, b);
    }

    #[test]
    fn mapping_struct_is_zero_sized() {
        assert_eq!(core::mem::size_of::<Mapping<[u8; 32], U256>>(), 0);
    }
}
