//! Explicit-loading storage handles ([`Map`], [`VecStore`], [`StorageValue`]).
//!
//! Phase 1 ships only the type definitions and the slot-derivation helper.
//! The wiring to `chain.state.read/write` host imports lands in Phase 3.

use core::marker::PhantomData;

pub use bloom_chain_abi::storage::{slot_mapping, slot_scalar};

/// A 32-byte storage slot — the chain's keyspace unit.
pub type Slot = [u8; 32];

/// Derive a slot for a *new-rule* storage field:
/// `blake3("storage:" || domain || ":" || field)`.
///
/// Legacy fields use the v1 derivation rule (`blake3(tag)` / `blake3(tag||key)`).
/// To opt a field into the legacy rule for byte-for-byte parity, pass the
/// `compat_tag` to the `#[storage]` macro — the macro forwards to
/// [`slot_scalar`] / [`slot_mapping`] instead of this helper.
#[inline]
pub fn slot_for_field(domain: &str, field: &str) -> Slot {
    let mut h = blake3::Hasher::new();
    h.update(b"storage:");
    h.update(domain.as_bytes());
    h.update(b":");
    h.update(field.as_bytes());
    *h.finalize().as_bytes()
}

/// Phantom handle for a `Map<K, V>` storage field. Stub in Phase 1; methods
/// (`get`, `set`, `remove`) land in Phase 3 once `AbiEncode`/`AbiDecode` are
/// in place.
#[derive(Clone, Copy)]
pub struct Map<K, V> {
    pub slot: Slot,
    _marker: PhantomData<(K, V)>,
}

impl<K, V> Map<K, V> {
    #[inline]
    pub const fn new(slot: Slot) -> Self {
        Self { slot, _marker: PhantomData }
    }
}

/// Phantom handle for a typed scalar slot. Stub in Phase 1.
#[derive(Clone, Copy)]
pub struct StorageValue<T> {
    pub slot: Slot,
    _marker: PhantomData<T>,
}

impl<T> StorageValue<T> {
    #[inline]
    pub const fn new(slot: Slot) -> Self {
        Self { slot, _marker: PhantomData }
    }
}

/// Phantom handle for a growable vector of `T`. Stub in Phase 1.
#[derive(Clone, Copy)]
pub struct VecStore<T> {
    pub slot: Slot,
    _marker: PhantomData<T>,
}

impl<T> VecStore<T> {
    #[inline]
    pub const fn new(slot: Slot) -> Self {
        Self { slot, _marker: PhantomData }
    }
}
