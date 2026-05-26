//! Core newtypes: `Address`, `Hash32`, `PubKeyBytes`, `SigBytes`, `Loom`.
//!
//! - `Address` — 32-byte BLAKE3-derived account address.  Display uses z-base-32
//!   with a `b1` prefix (matching the `../bloom` prior-art fingerprint style).
//! - `Hash32` — generic 32-byte BLAKE3 hash.
//! - `PubKeyBytes` — opaque, length-tagged xDSA public key (variable len, ≤ 2048 B).
//! - `SigBytes` — opaque, length-tagged xDSA signature (variable len, ≤ 4096 B).
//! - `Loom` — native LOOM amount in bloomweis (1 LOOM = 10^18 bloomweis).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode};

/// A 32-byte bloom-chain address derived from a composite xDSA public key via BLAKE3.
///
/// # Wire format
/// SSZ-encodes as a fixed 32-byte array.
///
/// # Display / parsing
/// Displayed as `b1<z-base-32(bytes)>` (58 chars total).
/// Parsed via [`FromStr`]; rejects malformed strings.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Spec §4.3 address derivation:
    /// `address = BLAKE3("bloom-chain.v0.addr:" || pk_composite)`.
    ///
    /// This is the single canonical derivation. All chain-side and wallet-side
    /// callers must use this — any inline duplicate of the domain tag is a
    /// drift hazard.
    pub fn from_pubkey_bytes(pk_bytes: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(crate::digest::tags::ADDR.as_bytes());
        h.update(pk_bytes);
        Address(*h.finalize().as_bytes())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = zbase32::encode_full_bytes(&self.0);
        write!(f, "b1{encoded}")
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("b1")
            .ok_or(AddressParseError::MissingPrefix)?;
        let bytes =
            zbase32::decode_full_bytes_str(rest).map_err(|_| AddressParseError::InvalidEncoding)?;
        if bytes.len() != 32 {
            return Err(AddressParseError::WrongLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Address(arr))
    }
}

/// Errors returned when parsing an [`Address`] from a string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressParseError {
    #[error("address must start with 'b1'")]
    MissingPrefix,
    #[error("invalid z-base-32 encoding")]
    InvalidEncoding,
    #[error("decoded address is {0} bytes, expected 32")]
    WrongLength(usize),
}

// --- SSZ Encode / Decode for Address (fixed 32-byte array) ---

impl Encode for Address {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn ssz_bytes_len(&self) -> usize {
        32
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for Address {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != 32 {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 32,
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Address(arr))
    }
}

// ---------------------------------------------------------------------------

/// A 32-byte BLAKE3 hash (generic, domain-tagged at the call site).
///
/// # Wire format
/// SSZ-encodes as a fixed 32-byte array.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Hash32(pub [u8; 32]);

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Hash32 {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            // hex::FromHexError doesn't have a "wrong length" variant, so use InvalidStringLength
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash32(arr))
    }
}

// --- SSZ Encode / Decode for Hash32 (fixed 32-byte array) ---

impl Encode for Hash32 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn ssz_bytes_len(&self) -> usize {
        32
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for Hash32 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != 32 {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 32,
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Hash32(arr))
    }
}

// ---------------------------------------------------------------------------

/// An opaque xDSA public key blob (composite ML-DSA-65 + Ed25519, nominally 1984 bytes).
///
/// Stored as a variable-length byte vec for forward-compatibility.
///
/// # Wire format
/// SSZ-encodes as `Vec<u8>` (variable-length list of bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Debug)]
pub struct PubKeyBytes(pub Vec<u8>);

impl Encode for PubKeyBytes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for PubKeyBytes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(PubKeyBytes(bytes.to_vec()))
    }
}

// ---------------------------------------------------------------------------

/// An opaque xDSA signature blob (composite ML-DSA-65 + Ed25519, nominally 3373 bytes).
///
/// Stored as a variable-length byte vec for forward-compatibility.
///
/// # Wire format
/// SSZ-encodes as `Vec<u8>` (variable-length list of bytes).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default, Debug)]
pub struct SigBytes(pub Vec<u8>);

impl Encode for SigBytes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for SigBytes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(SigBytes(bytes.to_vec()))
    }
}

// ---------------------------------------------------------------------------

/// Native LOOM amount in bloomweis (1 LOOM = 10^18 bloomweis).
///
/// # Wire format
/// SSZ-encodes as a fixed 16-byte little-endian `u128`.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default, Debug,
)]
pub struct Loom(pub u128);

impl Loom {
    /// 1 LOOM expressed in bloomweis.
    pub const ONE_LOOM: u128 = 1_000_000_000_000_000_000;

    /// Per-block emission: 10 LOOM in bloomweis.
    pub const BLOCK_EMISSION: u128 = 10 * Self::ONE_LOOM;
}

impl fmt::Display for Loom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bloomweis", self.0)
    }
}

// Loom delegates to u128's SSZ implementation.
impl Encode for Loom {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        16
    }

    fn ssz_bytes_len(&self) -> usize {
        16
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf);
    }
}

impl Decode for Loom {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        16
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        u128::from_ssz_bytes(bytes).map(Loom)
    }
}

// ---------------------------------------------------------------------------
// SSZ helpers for String (UTF-8 bytes, encoded as Vec<u8>)
// ---------------------------------------------------------------------------

/// Encode a `String` into SSZ bytes (UTF-8 byte sequence, variable-length).
pub(crate) fn encode_string(s: &str, buf: &mut Vec<u8>) {
    buf.extend_from_slice(s.as_bytes());
}

/// Decode SSZ bytes as a UTF-8 `String`.
pub(crate) fn decode_string(bytes: &[u8]) -> Result<String, DecodeError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::BytesInvalid("invalid UTF-8".into()))
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

    #[test]
    fn address_display_parse_roundtrip() {
        let addr = Address([42u8; 32]);
        let s = addr.to_string();
        assert!(s.starts_with("b1"), "expected b1 prefix, got {s}");
        let parsed: Address = s.parse().expect("should parse");
        assert_eq!(addr, parsed);
    }

    #[test]
    fn address_parse_rejects_missing_prefix() {
        let err = "deadbeef".parse::<Address>().unwrap_err();
        assert!(matches!(err, AddressParseError::MissingPrefix));
    }

    #[test]
    fn address_parse_rejects_wrong_length() {
        // Build a b1-prefixed z-base-32 of wrong data length.
        let short = zbase32::encode_full_bytes(&[1u8; 4]);
        let s = format!("b1{short}");
        let err = s.parse::<Address>().unwrap_err();
        assert!(matches!(err, AddressParseError::WrongLength(_)));
    }

    #[test]
    fn address_ssz_roundtrip() {
        let addr = Address([0xAB; 32]);
        let bytes = addr.as_ssz_bytes();
        assert_eq!(bytes.len(), 32);
        let decoded = Address::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn hash32_ssz_roundtrip() {
        let h = Hash32([0xCD; 32]);
        let bytes = h.as_ssz_bytes();
        assert_eq!(bytes.len(), 32);
        let decoded = Hash32::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn pubkey_bytes_ssz_roundtrip() {
        let pk = PubKeyBytes(vec![1, 2, 3, 4, 5]);
        let bytes = pk.as_ssz_bytes();
        let decoded = PubKeyBytes::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(pk, decoded);
    }

    #[test]
    fn sig_bytes_ssz_roundtrip() {
        let sig = SigBytes(vec![9, 8, 7]);
        let bytes = sig.as_ssz_bytes();
        let decoded = SigBytes::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn loom_ssz_roundtrip() {
        let loom = Loom(1_000_000_000_000_000_000u128);
        let bytes = loom.as_ssz_bytes();
        assert_eq!(bytes.len(), 16);
        let decoded = Loom::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(loom, decoded);
    }

    #[test]
    fn loom_constants() {
        assert_eq!(Loom::ONE_LOOM, 1_000_000_000_000_000_000u128);
        assert_eq!(Loom::BLOCK_EMISSION, 10 * Loom::ONE_LOOM);
    }

    #[test]
    fn hash32_display_and_parse() {
        let h = Hash32([0u8; 32]);
        let s = h.to_string();
        assert_eq!(s.len(), 64);
        let parsed: Hash32 = s.parse().unwrap();
        assert_eq!(h, parsed);
    }
}
