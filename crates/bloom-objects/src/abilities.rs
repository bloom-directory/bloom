//! `AbilitySet` and `AccessMode` — the Move-style ability bitfield and
//! the PTB borrow-table access mode (spec §4.2, §4.4).

use thiserror::Error;

use crate::codec::CodecError;

/// Object-type ability bitfield (spec §4.2).
///
/// Bits:
/// - `KEY   = 0b0001` — has an `id`, can be a top-level object.
/// - `STORE = 0b0010` — can be nested inside another object by-id.
/// - `COPY  = 0b0100` — can be cloned (rare; capability shapes only).
/// - `DROP  = 0b1000` — can be silently dropped (hot-potato patterns).
#[derive(Default, Clone, Copy, Eq, PartialEq, Debug)]
pub struct AbilitySet(pub u8);

impl AbilitySet {
    /// `key` ability bit.
    pub const KEY: u8 = 0b0001;
    /// `store` ability bit.
    pub const STORE: u8 = 0b0010;
    /// `copy` ability bit.
    pub const COPY: u8 = 0b0100;
    /// `drop` ability bit.
    pub const DROP: u8 = 0b1000;

    /// Construct from a raw bit mask.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Raw bit mask.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// `true` iff the `key` bit is set.
    pub const fn has_key(self) -> bool {
        self.0 & Self::KEY != 0
    }
    /// `true` iff the `store` bit is set.
    pub const fn has_store(self) -> bool {
        self.0 & Self::STORE != 0
    }
    /// `true` iff the `copy` bit is set.
    pub const fn has_copy(self) -> bool {
        self.0 & Self::COPY != 0
    }
    /// `true` iff the `drop` bit is set.
    pub const fn has_drop(self) -> bool {
        self.0 & Self::DROP != 0
    }

    /// `{ key, store }` — the default for coins, pools, LP positions, etc.
    pub const fn key_store() -> Self {
        Self(Self::KEY | Self::STORE)
    }

    /// `{ key, store, copy }` — the default for duplicable capabilities.
    pub const fn key_store_copy() -> Self {
        Self(Self::KEY | Self::STORE | Self::COPY)
    }

    /// `{ key, store, drop }` — used by ephemeral receipt-style objects.
    pub const fn key_store_drop() -> Self {
        Self(Self::KEY | Self::STORE | Self::DROP)
    }

    /// Parse a comma-separated ability list like `"key, store"`.
    ///
    /// Whitespace around each token is ignored; case-insensitive.
    /// Empty input yields the empty ability set.
    pub fn from_str_list(s: &str) -> Result<Self, AbilityParseError> {
        let mut bits: u8 = 0;
        for token in s.split(',') {
            let t = token.trim();
            if t.is_empty() {
                continue;
            }
            let bit = match t.to_ascii_lowercase().as_str() {
                "key" => Self::KEY,
                "store" => Self::STORE,
                "copy" => Self::COPY,
                "drop" => Self::DROP,
                _ => return Err(AbilityParseError::UnknownAbility(t.to_string())),
            };
            if bits & bit != 0 {
                return Err(AbilityParseError::Duplicate(t.to_string()));
            }
            bits |= bit;
        }
        Ok(Self(bits))
    }
}

/// Errors returned by [`AbilitySet::from_str_list`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AbilityParseError {
    /// A token in the list did not match `key`/`store`/`copy`/`drop`.
    #[error("unknown ability: {0}")]
    UnknownAbility(String),
    /// An ability was listed more than once.
    #[error("duplicate ability: {0}")]
    Duplicate(String),
}

/// PTB borrow-table access mode (spec §4.4 / §7.1).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
pub enum AccessMode {
    /// `&T` borrow — no mutation allowed.
    ReadOnly = 0,
    /// `&mut T` borrow — mutation allowed; bumps version on commit.
    Mutable = 1,
    /// `T` (value) — object is consumed by the command; row dropped at end.
    Consume = 2,
}

impl AccessMode {
    /// Serialise as the 1-byte wire encoding.
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Deserialise from the 1-byte wire encoding.
    pub fn from_byte(b: u8) -> Result<Self, CodecError> {
        match b {
            0 => Ok(AccessMode::ReadOnly),
            1 => Ok(AccessMode::Mutable),
            2 => Ok(AccessMode::Consume),
            other => Err(CodecError::InvalidDiscriminant(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_basics() {
        let s = AbilitySet::key_store();
        assert!(s.has_key());
        assert!(s.has_store());
        assert!(!s.has_copy());
        assert!(!s.has_drop());
        assert_eq!(s.bits(), AbilitySet::KEY | AbilitySet::STORE);
    }

    #[test]
    fn parse_key_store() {
        let s = AbilitySet::from_str_list("key, store").unwrap();
        assert_eq!(s, AbilitySet::key_store());
    }

    #[test]
    fn parse_handles_whitespace_and_case() {
        let s = AbilitySet::from_str_list("  KEY ,Store,COPY  ").unwrap();
        assert!(s.has_key() && s.has_store() && s.has_copy() && !s.has_drop());
    }

    #[test]
    fn parse_empty_string_is_no_abilities() {
        let s = AbilitySet::from_str_list("").unwrap();
        assert_eq!(s.bits(), 0);
    }

    #[test]
    fn parse_rejects_unknown() {
        let err = AbilitySet::from_str_list("key, magic").unwrap_err();
        assert!(matches!(err, AbilityParseError::UnknownAbility(s) if s == "magic"));
    }

    #[test]
    fn parse_rejects_duplicate() {
        let err = AbilitySet::from_str_list("key, key").unwrap_err();
        assert!(matches!(err, AbilityParseError::Duplicate(s) if s == "key"));
    }

    #[test]
    fn access_mode_roundtrip() {
        for m in [
            AccessMode::ReadOnly,
            AccessMode::Mutable,
            AccessMode::Consume,
        ] {
            assert_eq!(AccessMode::from_byte(m.as_byte()).unwrap(), m);
        }
    }

    #[test]
    fn access_mode_rejects_unknown() {
        assert!(matches!(
            AccessMode::from_byte(7),
            Err(CodecError::InvalidDiscriminant(7))
        ));
    }
}
