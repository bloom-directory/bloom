//! `LoomValue` — native LOOM value type for the bloom-petal-sdk call surface.
//!
//! Native LOOM amounts on bloom-chain are stored as `u128` (16-byte
//! little-endian on the wire — see `bloom-chain-types::Loom` and
//! `bloom-chain-state::account::Account::loom`). The host-side `petal.call`
//! import accepts the value as `(value_lo: i64, value_hi: i64)` — a split
//! `u128`. The previous SDK surface accepted a `[u8; 32]` big-endian "u256"
//! and silently discarded the upper 16 bytes; that quietly destroyed value
//! whenever a caller passed anything beyond `u128::MAX`.
//!
//! `LoomValue` makes the natural width explicit at the API boundary and
//! provides a fallible constructor for converting from caller-side 32-byte
//! u256 representations (e.g. dex `U256`). Conversions that don't fit in
//! `u128` are surfaced as `LoomValueError::Overflow` — never silently
//! narrowed.

/// Error returned when a value cannot be represented as a `LoomValue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoomValueError {
    /// The 32-byte big-endian u256 had non-zero bytes in the upper 16 bytes
    /// (i.e. the value exceeded `u128::MAX`).
    Overflow,
}

impl core::fmt::Display for LoomValueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoomValueError::Overflow => f.write_str("LoomValue overflow: value exceeds u128::MAX"),
        }
    }
}

/// A native LOOM value, exactly `u128` wide (no silent narrowing).
///
/// LOOM is denominated in bloomweis (1 LOOM = 10^18 bloomweis), matching
/// `bloom_chain_types::Loom`. Use `from_u128` for direct construction or
/// `try_from_be_u256_bytes` to convert from a caller-side 32-byte u256
/// representation; the latter returns `LoomValueError::Overflow` if the
/// value does not fit in `u128`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
pub struct LoomValue(u128);

impl LoomValue {
    /// Zero LOOM.
    pub const ZERO: LoomValue = LoomValue(0);

    /// Maximum representable LOOM value (`u128::MAX` bloomweis).
    pub const MAX: LoomValue = LoomValue(u128::MAX);

    /// Construct from a raw `u128`.
    #[inline]
    pub const fn from_u128(v: u128) -> Self {
        LoomValue(v)
    }

    /// Return the value as a `u128`.
    #[inline]
    pub const fn to_u128(self) -> u128 {
        self.0
    }

    /// Return `true` iff this value is zero.
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Try to construct a `LoomValue` from a 32-byte big-endian u256.
    ///
    /// Returns `Err(LoomValueError::Overflow)` if the upper 16 bytes are
    /// non-zero. NEVER silently truncates.
    pub fn try_from_be_u256_bytes(bytes: &[u8; 32]) -> Result<Self, LoomValueError> {
        // Upper 16 bytes (high half) must be zero for a u128-representable value.
        for &b in &bytes[..16] {
            if b != 0 {
                return Err(LoomValueError::Overflow);
            }
        }
        let mut lo = [0u8; 16];
        lo.copy_from_slice(&bytes[16..32]);
        Ok(LoomValue(u128::from_be_bytes(lo)))
    }

    /// Encode as a 32-byte big-endian u256 (upper 16 bytes are zero).
    pub fn to_be_u256_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&self.0.to_be_bytes());
        out
    }
}

impl From<u128> for LoomValue {
    fn from(v: u128) -> Self {
        LoomValue(v)
    }
}

impl From<u64> for LoomValue {
    fn from(v: u64) -> Self {
        LoomValue(v as u128)
    }
}

impl From<LoomValue> for u128 {
    fn from(v: LoomValue) -> u128 {
        v.0
    }
}

// `LoomValue` ↔ `U256` bridge.
//
// LoomValue is `u128`-wide; the ABI surface uses `U256`. Widening is
// infallible; narrowing is fallible because a `U256` above `u128::MAX`
// has no native LOOM representation.

impl From<LoomValue> for bloom_chain_abi::U256 {
    #[inline]
    fn from(v: LoomValue) -> Self {
        bloom_chain_abi::U256::from_u128(v.0)
    }
}

impl core::convert::TryFrom<bloom_chain_abi::U256> for LoomValue {
    type Error = LoomValueError;

    #[inline]
    fn try_from(v: bloom_chain_abi::U256) -> core::result::Result<Self, Self::Error> {
        LoomValue::try_from_be_u256_bytes(&v.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_round_trips_via_u128() {
        let z = LoomValue::ZERO;
        assert_eq!(z.to_u128(), 0u128);
        assert!(z.is_zero());
        assert_eq!(LoomValue::from_u128(0), z);
    }

    #[test]
    fn zero_round_trips_via_be_bytes() {
        let z = LoomValue::ZERO;
        let bytes = z.to_be_u256_bytes();
        assert_eq!(bytes, [0u8; 32]);
        assert_eq!(LoomValue::try_from_be_u256_bytes(&bytes), Ok(z));
    }

    #[test]
    fn u128_max_round_trips_unchanged() {
        // u128::MAX must pass through cleanly — this is the upper bound of the
        // SDK value surface and previously was silently corruptible.
        let v = LoomValue::from_u128(u128::MAX);
        assert_eq!(v.to_u128(), u128::MAX);

        let bytes = v.to_be_u256_bytes();
        // Upper 16 bytes are zero, lower 16 bytes are 0xff.
        assert_eq!(&bytes[..16], &[0u8; 16]);
        assert_eq!(&bytes[16..], &[0xffu8; 16]);

        let round_tripped = LoomValue::try_from_be_u256_bytes(&bytes).expect("u128::MAX fits");
        assert_eq!(round_tripped, v);
        assert_eq!(round_tripped.to_u128(), u128::MAX);
    }

    #[test]
    fn one_loom_round_trips() {
        // 1 LOOM = 10^18 bloomweis — the canonical mid-range value.
        let one_loom: u128 = 1_000_000_000_000_000_000;
        let v = LoomValue::from_u128(one_loom);
        assert_eq!(v.to_u128(), one_loom);

        let bytes = v.to_be_u256_bytes();
        let round_tripped = LoomValue::try_from_be_u256_bytes(&bytes).expect("1 LOOM fits in u128");
        assert_eq!(round_tripped, v);
    }

    #[test]
    fn u128_max_plus_one_overflows_not_truncates() {
        // u128::MAX + 1 cannot be constructed via from_u128 (the type is u128),
        // so we hand-craft the 32-byte u256 representation: a single bit set
        // in the high half (bit 0 of byte 15 from the top means byte index 15).
        let mut bytes = [0u8; 32];
        bytes[15] = 1; // First byte of the high half — value 2^128.

        let result = LoomValue::try_from_be_u256_bytes(&bytes);
        // Must NOT silently truncate to LoomValue(0); must surface overflow.
        assert_eq!(result, Err(LoomValueError::Overflow));
    }

    #[test]
    fn any_high_byte_nonzero_overflows() {
        // Exhaustively confirm each of the 16 high bytes triggers overflow.
        for byte_idx in 0..16 {
            let mut bytes = [0u8; 32];
            bytes[byte_idx] = 0x01;
            assert_eq!(
                LoomValue::try_from_be_u256_bytes(&bytes),
                Err(LoomValueError::Overflow),
                "high byte {byte_idx} should overflow",
            );
        }
    }

    #[test]
    fn full_u256_max_overflows_not_truncates() {
        // 0xffff...ff (256 bits set) must error, not truncate to u128::MAX.
        let bytes = [0xffu8; 32];
        assert_eq!(
            LoomValue::try_from_be_u256_bytes(&bytes),
            Err(LoomValueError::Overflow),
        );
    }

    #[test]
    fn from_u64_widens() {
        let v: LoomValue = 42u64.into();
        assert_eq!(v.to_u128(), 42u128);
    }
}
