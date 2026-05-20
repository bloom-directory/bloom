//! `PetalError` — the typed error code returned by host wrappers and
//! ultimately by `__petal_<fn>` wasm exports (spec §11.1).
//!
//! Encoding: success is wasm i32 `0`. Errors are positive i32 codes;
//! the high bit (`0x8000_0000`) marks user-defined custom errors so
//! petal authors can return their own discriminants without colliding
//! with the runtime-reserved codes.

use core::fmt;

/// Bit set on `Custom(code)` discriminants. The remaining 31 bits carry
/// the petal-defined sub-code. Reserved-runtime codes are required to
/// stay below this bit.
pub const CUSTOM_BIT: i32 = 0x40_00_00_00;

/// Runtime-defined error codes for host-import wrappers and the wasm
/// entry shim.
///
/// Discriminant assignment (kept in sync with §11.1 / §16.2 wording):
/// - `Aborted` — generic abort, used as fallback by macros.
/// - `NotImplemented` — wrapper present but the host returned `-1` for
///   an import the v0 chain has not yet enabled.
/// - `InvalidArgs` — args buffer for the wasm entry shim is malformed.
/// - `HostImportFailed` — a host import returned an unspecified failure.
/// - `InvalidHandle` — runtime handle index is `< 0` or otherwise out
///   of bounds.
/// - `OwnershipDenied` — borrow / transfer denied by the executor.
/// - `LinearityViolation` — the per-tx linearity check was about to be
///   tripped (raised client-side by `linearity::PetalScope`).
/// - `InvariantViolation` — an attached invariant returned `0`.
/// - `TypeMismatch` — a `Resource<T>` decode or `cap.check` rejected
///   the actual vs. expected type tag.
/// - `InsufficientBalance` — surface returned by `Coin<T>` math when a
///   split / withdraw underflows.
/// - `Custom(code)` — petal-defined sub-code, marked by `CUSTOM_BIT`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PetalError {
    /// Discriminant `0`. Strictly speaking unused as an *error*; kept
    /// so round-tripping through `from_i32(0)` yields a typed value.
    Ok,
    /// Generic abort. Equivalent to a `panic!` at the wasm boundary.
    Aborted,
    /// Wrapper present but the host import is not enabled in this
    /// build of the chain VM.
    NotImplemented,
    /// The wasm entry shim could not decode the args buffer.
    InvalidArgs,
    /// A host import returned an unspecified failure (typically
    /// negative `i32` not otherwise mapped).
    HostImportFailed,
    /// Runtime handle is invalid (e.g. negative or not in the borrow
    /// table).
    InvalidHandle,
    /// Borrow / transfer was denied by the executor's ownership rules.
    OwnershipDenied,
    /// Client-side linearity tracker about to revert (e.g. transient
    /// row left dangling at scope-exit).
    LinearityViolation,
    /// An attached invariant returned `0` (violated).
    InvariantViolation,
    /// Type tag for a `Resource<T>` or capability did not match.
    TypeMismatch,
    /// A coin / vault math operation underflowed.
    InsufficientBalance,
    /// Petal-defined error sub-code. `code` carries the low 31 bits.
    Custom(i32),
}

impl PetalError {
    /// Encode this error as the `i32` returned by a wasm export.
    ///
    /// `Ok` encodes as `0` (the "no error" wire value); every other
    /// variant maps to a positive integer.
    pub fn as_i32(&self) -> i32 {
        match self {
            PetalError::Ok => 0,
            PetalError::Aborted => 1,
            PetalError::NotImplemented => 2,
            PetalError::InvalidArgs => 3,
            PetalError::HostImportFailed => 4,
            PetalError::InvalidHandle => 5,
            PetalError::OwnershipDenied => 6,
            PetalError::LinearityViolation => 7,
            PetalError::InvariantViolation => 8,
            PetalError::TypeMismatch => 9,
            PetalError::InsufficientBalance => 10,
            PetalError::Custom(code) => CUSTOM_BIT | (code & (CUSTOM_BIT - 1)),
        }
    }

    /// Decode a wire `i32` back into a typed error.
    ///
    /// Unknown reserved-range codes round-trip through
    /// `PetalError::Aborted` — the spec deliberately does not promise
    /// a stable mapping for codes outside the enumerated set, and the
    /// macros only ever emit values from this enum.
    pub fn from_i32(code: i32) -> Self {
        if code & CUSTOM_BIT != 0 {
            return PetalError::Custom(code & (CUSTOM_BIT - 1));
        }
        match code {
            0 => PetalError::Ok,
            1 => PetalError::Aborted,
            2 => PetalError::NotImplemented,
            3 => PetalError::InvalidArgs,
            4 => PetalError::HostImportFailed,
            5 => PetalError::InvalidHandle,
            6 => PetalError::OwnershipDenied,
            7 => PetalError::LinearityViolation,
            8 => PetalError::InvariantViolation,
            9 => PetalError::TypeMismatch,
            10 => PetalError::InsufficientBalance,
            _ => PetalError::Aborted,
        }
    }
}

impl fmt::Display for PetalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PetalError::Ok => write!(f, "ok"),
            PetalError::Aborted => write!(f, "aborted"),
            PetalError::NotImplemented => write!(f, "not implemented"),
            PetalError::InvalidArgs => write!(f, "invalid args buffer"),
            PetalError::HostImportFailed => write!(f, "host import failed"),
            PetalError::InvalidHandle => write!(f, "invalid runtime handle"),
            PetalError::OwnershipDenied => write!(f, "ownership denied"),
            PetalError::LinearityViolation => write!(f, "linearity violation"),
            PetalError::InvariantViolation => write!(f, "invariant violation"),
            PetalError::TypeMismatch => write!(f, "type mismatch"),
            PetalError::InsufficientBalance => write!(f, "insufficient balance"),
            PetalError::Custom(code) => write!(f, "custom petal error: {code}"),
        }
    }
}

impl std::error::Error for PetalError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_round_trips() {
        assert_eq!(PetalError::Ok.as_i32(), 0);
        assert_eq!(PetalError::from_i32(0), PetalError::Ok);
    }

    #[test]
    fn reserved_codes_round_trip() {
        for e in [
            PetalError::Aborted,
            PetalError::NotImplemented,
            PetalError::InvalidArgs,
            PetalError::HostImportFailed,
            PetalError::InvalidHandle,
            PetalError::OwnershipDenied,
            PetalError::LinearityViolation,
            PetalError::InvariantViolation,
            PetalError::TypeMismatch,
            PetalError::InsufficientBalance,
        ] {
            let code = e.as_i32();
            assert!(code > 0 && code < CUSTOM_BIT, "code in reserved range");
            assert_eq!(PetalError::from_i32(code), e);
        }
    }

    #[test]
    fn custom_round_trips() {
        let e = PetalError::Custom(0x123_4567);
        let code = e.as_i32();
        assert!(code & CUSTOM_BIT != 0);
        assert_eq!(PetalError::from_i32(code), e);
    }

    #[test]
    fn custom_zero_distinct_from_ok() {
        let e = PetalError::Custom(0);
        assert_ne!(e.as_i32(), 0);
        assert_eq!(PetalError::from_i32(e.as_i32()), e);
    }

    #[test]
    fn unknown_reserved_decodes_as_aborted() {
        // 99 is inside the reserved range but unassigned.
        assert_eq!(PetalError::from_i32(99), PetalError::Aborted);
    }

    #[test]
    fn display_includes_code_for_custom() {
        let s = format!("{}", PetalError::Custom(42));
        assert!(s.contains("42"));
    }
}
