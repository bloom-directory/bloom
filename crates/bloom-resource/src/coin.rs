//! `Coin<T>` — typed handle wrapper for `Coin` objects in the
//! executor's borrow table (spec §5, §14).
//!
//! This crate does **not** implement Coin semantics (split, merge,
//! value, etc.); that lives in the `/bloom/core/fungible` petal. This
//! type is a wrapper so the macros and petals have a stable type to
//! refer to in function signatures.

use core::marker::PhantomData;

use bloom_objects::TypeTag;

use crate::handle::RuntimeHandle;
use crate::type_args;

/// Typed handle to a borrowed `Coin<T>` row.
pub struct Coin<T> {
    pub(crate) handle: RuntimeHandle,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T> core::fmt::Debug for Coin<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Coin")
            .field("handle", &self.handle)
            .finish()
    }
}

impl<T> Coin<T> {
    /// Wrap a runtime handle as a typed coin. The macro-emitted entry
    /// shim is the primary caller; user code rarely constructs `Coin`s
    /// directly.
    pub fn from_handle(h: RuntimeHandle) -> Self {
        Self {
            handle: h,
            _phantom: PhantomData,
        }
    }

    /// Underlying borrow-table handle.
    pub fn handle(&self) -> RuntimeHandle {
        self.handle
    }

    /// Consume self and yield the inner handle (used by the macros
    /// when threading a `Coin` into a downstream host call).
    pub fn into_handle(self) -> RuntimeHandle {
        self.handle
    }

    /// Resolve the **runtime** `TypeTag` of the inner coin type `T` for
    /// the currently executing generic petal call (spec §5 generic
    /// dispatch).
    ///
    /// `T` is a compile-time phantom and carries no runtime identity, so
    /// the petal body supplies `idx` — the position of `T` among the
    /// fn's generic parameters (`identity<T>` → `idx = 0`;
    /// `swap<A, B>(coin_in: Coin<A>) -> Coin<B>` → `Coin<A>` resolves
    /// `idx = 0`, the output `Coin<B>` resolves `idx = 1`). The tag is
    /// read from the per-call [`type_args`] context the shim bound from
    /// the calldata's `Arg::TypeArg` slots.
    ///
    /// Returns `None` outside a generic dispatch or when `idx` is out of
    /// range (fewer type-args were supplied than the fn declares).
    pub fn type_tag(idx: u16) -> Option<TypeTag> {
        type_args::current_type_arg(idx)
    }
}

impl<T> Copy for Coin<T> {}
impl<T> Clone for Coin<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for Coin<T> {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl<T> Eq for Coin<T> {}

/// Marker for the "value field" of a coin (a `u128` in v0). The
/// concrete `Balance<T>` is provided as a thin newtype so petals can
/// type-erase amount arithmetic if they want to (e.g. saturating math
/// guards). Today it's just transparent.
pub struct Balance<T> {
    value: u128,
    _phantom: PhantomData<T>,
}

impl<T> Copy for Balance<T> {}
impl<T> Clone for Balance<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Default for Balance<T> {
    fn default() -> Self {
        Self::from_u128(0)
    }
}
impl<T> PartialEq for Balance<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl<T> Eq for Balance<T> {}
impl<T> Ord for Balance<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}
impl<T> PartialOrd for Balance<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> core::hash::Hash for Balance<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}
impl<T> core::fmt::Debug for Balance<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Balance")
            .field("value", &self.value)
            .finish()
    }
}

impl<T> Balance<T> {
    /// Build a balance from a raw `u128`.
    pub const fn from_u128(value: u128) -> Self {
        Self {
            value,
            _phantom: PhantomData,
        }
    }

    /// Raw `u128` amount.
    pub const fn as_u128(&self) -> u128 {
        self.value
    }

    /// Saturating add; returns the new balance.
    pub const fn saturating_add(self, other: Self) -> Self {
        Self::from_u128(self.value.saturating_add(other.value))
    }

    /// Checked subtraction. `None` on underflow.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.value.checked_sub(other.value).map(Self::from_u128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::upper_case_acronyms)]
    struct USDC;

    #[test]
    fn coin_round_trip() {
        let c: Coin<USDC> = Coin::from_handle(RuntimeHandle::from_raw(3));
        assert_eq!(c.handle(), RuntimeHandle::from_raw(3));
        assert_eq!(c.into_handle(), RuntimeHandle::from_raw(3));
    }

    #[test]
    fn coin_copy_clone_equal() {
        let c1: Coin<USDC> = Coin::from_handle(RuntimeHandle::from_raw(1));
        let c2 = c1;
        #[allow(clippy::clone_on_copy)]
        let c3 = c1.clone();
        assert_eq!(c1, c2);
        assert_eq!(c1, c3);
    }

    #[test]
    fn coin_ineq_by_handle() {
        let c1: Coin<USDC> = Coin::from_handle(RuntimeHandle::from_raw(1));
        let c2: Coin<USDC> = Coin::from_handle(RuntimeHandle::from_raw(2));
        assert_ne!(c1, c2);
    }

    #[test]
    fn balance_basics() {
        let a: Balance<USDC> = Balance::from_u128(100);
        let b: Balance<USDC> = Balance::from_u128(50);
        assert_eq!(a.as_u128(), 100);
        assert_eq!(a.saturating_add(b).as_u128(), 150);
        assert_eq!(a.checked_sub(b).unwrap().as_u128(), 50);
        assert_eq!(b.checked_sub(a), None);
    }

    #[test]
    fn balance_saturating_at_max() {
        let big: Balance<USDC> = Balance::from_u128(u128::MAX);
        let one: Balance<USDC> = Balance::from_u128(1);
        assert_eq!(big.saturating_add(one).as_u128(), u128::MAX);
    }

    #[test]
    fn type_tag_resolves_from_bound_context() {
        use crate::type_args::TypeArgs;
        let usdc = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "USDC".to_string(),
            type_args: Vec::new(),
        };
        let loom = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "LOOM".to_string(),
            type_args: Vec::new(),
        };
        let _g = TypeArgs::bind(vec![usdc.clone(), loom.clone()]);
        // `Coin<A>` at generic index 0, `Coin<B>` at index 1.
        assert_eq!(Coin::<USDC>::type_tag(0), Some(usdc));
        assert_eq!(Coin::<USDC>::type_tag(1), Some(loom));
        assert_eq!(Coin::<USDC>::type_tag(2), None);
    }

    #[test]
    fn type_tag_is_none_without_binding() {
        assert_eq!(Coin::<USDC>::type_tag(0), None);
    }
}
