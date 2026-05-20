//! `RuntimeHandle` — an opaque `i32` index into the PTB executor's
//! borrow table (spec §16.2).
//!
//! Petals must treat handle values as opaque. They are minted by
//! `object.borrow` / `object.create` and consumed by the other host
//! imports; the executor reuses indices across tx boundaries, so a
//! handle from one PTB is meaningless in another.

/// Opaque borrow-table handle. `-1` (and any other negative value) is
/// the sentinel for "invalid"; positive values are runtime-internal.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, Ord, PartialOrd)]
pub struct RuntimeHandle(pub i32);

impl RuntimeHandle {
    /// Canonical invalid handle returned by host imports that fail with
    /// "no such object" / "not yet enabled".
    pub const INVALID: Self = Self(-1);

    /// Build a handle from a raw i32. Prefer the named constructor over
    /// inline `RuntimeHandle(x)` so reviewers see the intent.
    pub const fn from_raw(raw: i32) -> Self {
        Self(raw)
    }

    /// Raw i32 representation; what crosses the wasm ABI.
    pub const fn as_raw(self) -> i32 {
        self.0
    }

    /// `true` iff this handle was not the sentinel `-1`.
    pub const fn is_valid(self) -> bool {
        self.0 >= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_sentinel() {
        assert_eq!(RuntimeHandle::INVALID.as_raw(), -1);
        assert!(!RuntimeHandle::INVALID.is_valid());
    }

    #[test]
    fn valid_positive() {
        assert!(RuntimeHandle::from_raw(0).is_valid());
        assert!(RuntimeHandle::from_raw(42).is_valid());
    }

    #[test]
    fn invalid_negative() {
        assert!(!RuntimeHandle::from_raw(-7).is_valid());
    }

    #[test]
    fn raw_round_trip() {
        let h = RuntimeHandle::from_raw(123);
        assert_eq!(h.as_raw(), 123);
    }

    #[test]
    fn equality_and_hash_by_raw() {
        let a = RuntimeHandle::from_raw(7);
        let b = RuntimeHandle::from_raw(7);
        let c = RuntimeHandle::from_raw(8);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
