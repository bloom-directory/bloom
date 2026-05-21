//! Explicit-loading storage handles for `#[bloom::contract]` modules.
//!
//! Every contract declares one `#[storage] pub struct State { ... }` and reads
//! / writes through it inside method bodies:
//!
//! ```ignore
//! #[storage]
//! pub struct State {
//!     pub total_supply: StorageValue<U256>,
//!     pub balances:     Map<Address, U256>,
//!     pub allowances:   Map<(Address, Address), U256>,
//! }
//!
//! pub fn transfer(ctx: &mut Context, to: Address, amount: U256) -> Result<bool, Error> {
//!     let mut state = State::load(ctx)?;
//!     let bal = state.balances.get(ctx, &ctx.sender())?;
//!     // ...
//! }
//! ```
//!
//! Each handle (`StorageValue<T>`, `Map<K, V>`, `VecStore<T>`) is zero-sized
//! at runtime — it carries only the byte prefix used for slot derivation and
//! is laid out in the parent `State` struct at compile time. The actual
//! storage I/O routes through `bloom_petal_sdk::state::read/write/delete`.
//!
//! ## Slot derivation
//!
//! Two derivation rules coexist for byte-for-byte compatibility with the
//! legacy `contract!` macro:
//!
//! - **New-rule scalar:** `blake3("storage:" || domain || ":" || field)`.
//! - **New-rule mapping:** `blake3("storage:" || domain || ":" || field || ":" || encoded_key)`.
//! - **Legacy scalar:** `blake3(compat_tag)` — used when `#[storage(compat_tag = "..." )]`.
//! - **Legacy mapping:** `blake3(compat_tag || encoded_key)` — same attribute.
//!
//! Storage values are written into a single 32-byte slot. The on-disk byte
//! layout per primitive matches the legacy `contract!` macro exactly so a
//! migration with the `compat_tag` attribute is a no-op on the wire:
//!
//! | Type      | Bytes                                                  |
//! |-----------|--------------------------------------------------------|
//! | `U256`    | full 32 bytes big-endian                               |
//! | `u128`    | high half zero, value big-endian in `slot[16..32]`     |
//! | `u64`     | leading 24 zeros, value big-endian in `slot[24..32]`   |
//! | `u32`     | leading 28 zeros, value big-endian in `slot[28..32]`   |
//! | `u16`     | leading 30 zeros, value big-endian in `slot[30..32]`   |
//! | `u8`      | leading 31 zeros, value byte in `slot[31]`             |
//! | `bool`    | leading 31 zeros, `0`/`1` in `slot[31]`                |
//! | `Address` | full 32 bytes verbatim                                 |
//! | `Hash32`  | full 32 bytes verbatim                                 |

use core::marker::PhantomData;

use alloc::vec::Vec;
use blake3::Hasher;
use bloom_petal_sdk::state;

pub use bloom_chain_abi::storage::{slot_mapping, slot_scalar};

use crate::abi::{AbiEncode, AbiEncodeError, AbiError, Encoder};
use crate::context::Context;
use crate::error::{ContractError, Result};
use crate::types::{Address, Hash32, U256};

/// A 32-byte storage slot.
pub type Slot = [u8; 32];

// ---------------------------------------------------------------------------
// Storage schema descriptors — `#[storage]` macro emits one of these per field
// so the build crate can pull the layout out at manifest-emission time without
// re-parsing the source.
// ---------------------------------------------------------------------------

/// Discriminator inside a [`StorageEntry`]: scalar / map / vec.
///
/// Each variant carries the `AbiType::ABI_TYPE` strings of its component types
/// so the manifest emitter can render them without re-parsing source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageKind {
    Scalar {
        ty: &'static str,
    },
    Map {
        key_ty: &'static str,
        value_ty: &'static str,
    },
    Vec {
        ty: &'static str,
    },
}

/// One entry in a contract's `Self::SCHEMA`.
///
/// Slot bytes are not stored here (they'd need a non-const blake3 call). The
/// build crate derives them at host time via [`StorageEntry::derived_slot`]
/// using the contract's `STORAGE_DOMAIN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageEntry {
    /// Source-level field name.
    pub name: &'static str,
    /// Field shape + type names.
    pub kind: StorageKind,
    /// `Some("erc20.balance:")` if `#[storage(compat_tag = "..." )]` is set,
    /// `None` for new-rule fields.
    pub compat_tag: Option<&'static str>,
    /// For maps: the static prefix bytes used in `blake3(prefix || key)`.
    /// Empty for scalar/vec entries.
    pub prefix: &'static [u8],
}

impl StorageEntry {
    /// Derive the entry's storage slot under `domain`.
    ///
    /// For maps, slots are per-key — this returns the all-zero placeholder.
    /// For scalar/vec with a `compat_tag`, the legacy `blake3(tag)` rule
    /// applies. Otherwise the new-rule `blake3("storage:" || domain || ":" || name)`.
    pub fn derived_slot(&self, domain: &str) -> Slot {
        match (self.kind, self.compat_tag) {
            (StorageKind::Map { .. }, _) => [0u8; 32],
            (_, Some(tag)) => slot_for_compat_tag(tag),
            (_, None) => slot_for_field(domain, self.name),
        }
    }
}

/// Derive a slot from a legacy `compat_tag`. Used by `#[storage(compat_tag = "..." )]`
/// scalars and vecs to mirror pre-migration byte layout exactly.
#[inline]
pub fn slot_for_compat_tag(tag: &str) -> Slot {
    let mut h = Hasher::new();
    h.update(tag.as_bytes());
    *h.finalize().as_bytes()
}

/// Derive a slot key for a new-rule storage field:
/// `blake3("storage:" || domain || ":" || field)`.
#[inline]
pub fn slot_for_field(domain: &str, field: &str) -> Slot {
    let mut h = Hasher::new();
    h.update(b"storage:");
    h.update(domain.as_bytes());
    h.update(b":");
    h.update(field.as_bytes());
    *h.finalize().as_bytes()
}

/// Derive a slot key for a new-rule mapping entry:
/// `blake3("storage:" || domain || ":" || field || ":" || key_bytes)`.
pub fn slot_for_map_key(domain: &str, field: &str, key_bytes: &[u8]) -> Slot {
    let mut h = Hasher::new();
    h.update(b"storage:");
    h.update(domain.as_bytes());
    h.update(b":");
    h.update(field.as_bytes());
    h.update(b":");
    h.update(key_bytes);
    *h.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// SlotEncode — value <-> [u8; 32] mapping for primitives
// ---------------------------------------------------------------------------

/// Bidirectional codec between a typed scalar and its 32-byte storage layout.
///
/// Mirrors the legacy `contract!` macro's storage encoding rules exactly so
/// `#[storage(compat_tag = "..." )]` fields are byte-for-byte parity with
/// pre-migration writes. Unset slots decode to the type's natural zero.
pub trait SlotEncode: Sized {
    fn to_slot(&self) -> Slot;
    fn from_slot(slot: Slot) -> Self;
}

impl SlotEncode for U256 {
    fn to_slot(&self) -> Slot {
        self.0
    }
    fn from_slot(slot: Slot) -> Self {
        U256(slot)
    }
}

impl SlotEncode for u128 {
    fn to_slot(&self) -> Slot {
        let mut s = [0u8; 32];
        s[16..32].copy_from_slice(&self.to_be_bytes());
        s
    }
    fn from_slot(slot: Slot) -> Self {
        let mut b = [0u8; 16];
        b.copy_from_slice(&slot[16..32]);
        u128::from_be_bytes(b)
    }
}

impl SlotEncode for u64 {
    fn to_slot(&self) -> Slot {
        let mut s = [0u8; 32];
        s[24..32].copy_from_slice(&self.to_be_bytes());
        s
    }
    fn from_slot(slot: Slot) -> Self {
        let mut b = [0u8; 8];
        b.copy_from_slice(&slot[24..32]);
        u64::from_be_bytes(b)
    }
}

impl SlotEncode for u32 {
    fn to_slot(&self) -> Slot {
        let mut s = [0u8; 32];
        s[28..32].copy_from_slice(&self.to_be_bytes());
        s
    }
    fn from_slot(slot: Slot) -> Self {
        let mut b = [0u8; 4];
        b.copy_from_slice(&slot[28..32]);
        u32::from_be_bytes(b)
    }
}

impl SlotEncode for u16 {
    fn to_slot(&self) -> Slot {
        let mut s = [0u8; 32];
        s[30..32].copy_from_slice(&self.to_be_bytes());
        s
    }
    fn from_slot(slot: Slot) -> Self {
        let mut b = [0u8; 2];
        b.copy_from_slice(&slot[30..32]);
        u16::from_be_bytes(b)
    }
}

impl SlotEncode for u8 {
    fn to_slot(&self) -> Slot {
        let mut s = [0u8; 32];
        s[31] = *self;
        s
    }
    fn from_slot(slot: Slot) -> Self {
        slot[31]
    }
}

impl SlotEncode for bool {
    fn to_slot(&self) -> Slot {
        let mut s = [0u8; 32];
        s[31] = if *self { 1 } else { 0 };
        s
    }
    fn from_slot(slot: Slot) -> Self {
        slot[31] != 0
    }
}

impl SlotEncode for Address {
    fn to_slot(&self) -> Slot {
        self.0
    }
    fn from_slot(slot: Slot) -> Self {
        Address(slot)
    }
}

impl SlotEncode for Hash32 {
    fn to_slot(&self) -> Slot {
        self.0
    }
    fn from_slot(slot: Slot) -> Self {
        Hash32(slot)
    }
}

impl SlotEncode for crate::types::Bytes32String {
    fn to_slot(&self) -> Slot {
        self.0
    }
    fn from_slot(slot: Slot) -> Self {
        crate::types::Bytes32String(slot)
    }
}

impl SlotEncode for Slot {
    fn to_slot(&self) -> Slot {
        *self
    }
    fn from_slot(slot: Slot) -> Self {
        slot
    }
}

// ---------------------------------------------------------------------------
// StorageValue<T> — typed scalar slot
// ---------------------------------------------------------------------------

/// A typed handle to a single 32-byte storage slot.
///
/// Constructed by the `#[storage]` macro; users do not build these by hand.
/// `load()` reads, `store()` writes, `clear()` zeroes the slot.
#[derive(Clone, Copy)]
pub struct StorageValue<T> {
    pub slot: Slot,
    _marker: PhantomData<T>,
}

impl<T> StorageValue<T> {
    #[inline]
    pub const fn new(slot: Slot) -> Self {
        Self {
            slot,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub const fn slot(&self) -> &Slot {
        &self.slot
    }
}

impl<T: SlotEncode> StorageValue<T> {
    /// Read the stored value (zero/default for unset slots).
    ///
    /// Takes `&Context` so a `#[view]` handler — which holds the
    /// context immutably — can still read storage, but the borrow
    /// checker rejects any storage write from the same body.
    pub fn load(&self, ctx: &Context) -> T {
        let _ = ctx;
        match state::read(&self.slot) {
            Some(bytes) => T::from_slot(bytes),
            None => T::from_slot([0u8; 32]),
        }
    }

    /// Overwrite the stored value.
    ///
    /// Takes `&mut Context`, which a `#[view]` handler cannot supply
    /// — so attempting to mutate storage from a view body is a
    /// compile error, not a runtime check.
    pub fn store(&self, ctx: &mut Context, v: &T) {
        let _ = ctx;
        state::write(&self.slot, &v.to_slot());
    }

    /// Reset the slot to the default zero state. Requires
    /// `&mut Context` for the same reason as `store`.
    pub fn clear(&self, ctx: &mut Context) {
        let _ = ctx;
        state::delete(&self.slot);
    }
}

// ---------------------------------------------------------------------------
// Map<K, V> — keyed storage
// ---------------------------------------------------------------------------

/// A typed handle to a mapping `K -> V` stored at slot
/// `blake3(prefix || encoded_key)`.
///
/// The `prefix` is set by the `#[storage]` macro: either the new-rule
/// `b"storage:<domain>:<field>:"` or, when `#[storage(compat_tag = "..." )]`
/// is set, the literal legacy tag bytes (e.g. `b"erc20.balance:"`).
#[derive(Clone, Copy)]
pub struct Map<K, V> {
    pub prefix: &'static [u8],
    _marker: PhantomData<(K, V)>,
}

impl<K, V> Map<K, V> {
    #[inline]
    pub const fn new(prefix: &'static [u8]) -> Self {
        Self {
            prefix,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub const fn prefix(&self) -> &[u8] {
        self.prefix
    }
}

impl<K: AbiEncode, V: SlotEncode> Map<K, V> {
    /// Derive the storage slot for a given key:
    /// `blake3(prefix || abi_encode(key))`.
    pub fn slot(&self, key: &K) -> core::result::Result<Slot, AbiEncodeError> {
        let mut enc = Encoder::new();
        key.encode_into(&mut enc)?;
        let key_bytes = enc.finish();
        let mut h = Hasher::new();
        h.update(self.prefix);
        h.update(&key_bytes);
        Ok(*h.finalize().as_bytes())
    }

    /// Read the stored value for `key`. Returns the type's zero for unset
    /// slots (mirroring chain semantics §6.2). `&Context` borrow gates
    /// reads through the context handle.
    pub fn get(&self, ctx: &Context, key: &K) -> Result<V> {
        let _ = ctx;
        let slot = self.slot(key).map_err(map_encode_err)?;
        let bytes = state::read(&slot).unwrap_or([0u8; 32]);
        Ok(V::from_slot(bytes))
    }

    /// Overwrite the value at `key`. `&mut Context` enforces that
    /// `#[view]` handlers can't reach this method.
    pub fn set(&self, ctx: &mut Context, key: &K, value: &V) -> Result<()> {
        let _ = ctx;
        let slot = self.slot(key).map_err(map_encode_err)?;
        state::write(&slot, &value.to_slot());
        Ok(())
    }

    /// Delete the slot for `key`. `&mut Context` for the same reason.
    pub fn remove(&self, ctx: &mut Context, key: &K) -> Result<()> {
        let _ = ctx;
        let slot = self.slot(key).map_err(map_encode_err)?;
        state::delete(&slot);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VecStore<T> — growable list
// ---------------------------------------------------------------------------

/// A typed handle to a growable list. Length lives at `prefix_slot`; items at
/// `blake3(prefix_slot || u64_be(index))`.
#[derive(Clone, Copy)]
pub struct VecStore<T> {
    /// 32-byte slot holding the length (encoded as u64 — same layout as
    /// `StorageValue<u64>`).
    pub len_slot: Slot,
    _marker: PhantomData<T>,
}

impl<T> VecStore<T> {
    #[inline]
    pub const fn new(len_slot: Slot) -> Self {
        Self {
            len_slot,
            _marker: PhantomData,
        }
    }

    /// Derive the slot for the element at `index`.
    pub fn element_slot(&self, index: u64) -> Slot {
        let mut h = Hasher::new();
        h.update(&self.len_slot);
        h.update(&index.to_be_bytes());
        *h.finalize().as_bytes()
    }
}

impl<T: SlotEncode> VecStore<T> {
    /// Number of elements currently stored. Reads the length slot.
    pub fn len(&self, ctx: &Context) -> u64 {
        let _ = ctx;
        let slot = state::read(&self.len_slot).unwrap_or([0u8; 32]);
        u64::from_slot(slot)
    }

    pub fn is_empty(&self, ctx: &Context) -> bool {
        self.len(ctx) == 0
    }

    /// Read the value at `index`. Returns `None` if `index >= len`.
    pub fn get(&self, ctx: &Context, index: u64) -> Option<T> {
        if index >= self.len(ctx) {
            return None;
        }
        let slot = self.element_slot(index);
        let bytes = state::read(&slot).unwrap_or([0u8; 32]);
        Some(T::from_slot(bytes))
    }

    /// Append `value` at the next index and bump the length slot.
    /// `&mut Context` keeps view handlers out.
    pub fn push(&self, ctx: &mut Context, value: &T) {
        let len = self.len(ctx);
        let slot = self.element_slot(len);
        state::write(&slot, &value.to_slot());
        state::write(&self.len_slot, &(len + 1).to_slot());
    }

    /// Overwrite the element at `index`. `&mut Context` required.
    pub fn set(&self, ctx: &mut Context, index: u64, value: &T) -> Result<()> {
        if index >= self.len(ctx) {
            return Err(out_of_bounds());
        }
        let slot = self.element_slot(index);
        state::write(&slot, &value.to_slot());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn map_encode_err(e: AbiEncodeError) -> ContractError {
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(b"encode:");
    match e {
        AbiEncodeError::TooManyAddresses(n) => data.extend_from_slice(&(n as u64).to_be_bytes()),
        AbiEncodeError::TooLong(n) => data.extend_from_slice(&(n as u64).to_be_bytes()),
    }
    ContractError::new(data)
}

fn out_of_bounds() -> ContractError {
    ContractError::new(b"vec:out_of_bounds".to_vec())
}

// `AbiError` -> `ContractError` is required when storage uses dynamic decode
// paths (Phase 4+). Mapping kept here so the abi/storage modules don't depend
// on each other beyond the trait bounds.
#[allow(dead_code)]
fn map_decode_err(e: AbiError) -> ContractError {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(b"decode:");
    // Cheap discriminator (rather than a full encode) — error messages are
    // diagnostic, not part of the wire ABI.
    data.extend_from_slice(format_abi_error(&e).as_bytes());
    ContractError::new(data)
}

#[allow(dead_code)]
fn format_abi_error(e: &AbiError) -> &'static str {
    match e {
        AbiError::UnexpectedEof { .. } => "eof",
        AbiError::InvalidBool(_) => "bool",
        AbiError::VecOverflow { .. } => "vec_overflow",
        AbiError::Overflow => "overflow",
        AbiError::TrailingBytes { .. } => "trailing",
        AbiError::InvalidUtf8 => "utf8",
        AbiError::InvalidDiscriminant(_) => "discriminant",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_for_field_matches_blake3_spec() {
        let s = slot_for_field("erc20", "balances");
        let expected = blake3::hash(b"storage:erc20:balances");
        assert_eq!(&s, expected.as_bytes());
    }

    #[test]
    fn slot_for_map_key_matches_blake3_spec() {
        let s = slot_for_map_key("erc20", "balances", &[1, 2, 3]);
        let mut h = blake3::Hasher::new();
        h.update(b"storage:erc20:balances:");
        h.update(&[1, 2, 3]);
        assert_eq!(&s, h.finalize().as_bytes());
    }

    #[test]
    fn slot_encode_u256_full_width() {
        let v = U256::from_u128(0xDEAD_BEEF);
        let s = v.to_slot();
        assert_eq!(<U256 as SlotEncode>::from_slot(s), v);
    }

    #[test]
    fn slot_encode_u64_right_aligned() {
        let v: u64 = 0x0102_0304_0506_0708;
        let s = SlotEncode::to_slot(&v);
        assert_eq!(&s[..24], &[0u8; 24]);
        assert_eq!(&s[24..], &v.to_be_bytes());
        assert_eq!(u64::from_slot(s), v);
    }

    #[test]
    fn slot_encode_u128_right_aligned() {
        let v: u128 = (1u128 << 100) | 0xCAFE;
        let s = SlotEncode::to_slot(&v);
        assert_eq!(&s[..16], &[0u8; 16]);
        assert_eq!(u128::from_slot(s), v);
    }

    #[test]
    fn slot_encode_bool_single_byte() {
        let s_t = SlotEncode::to_slot(&true);
        let s_f = SlotEncode::to_slot(&false);
        assert_eq!(s_t[31], 1);
        assert_eq!(s_f[31], 0);
        assert!(<bool as SlotEncode>::from_slot(s_t));
        assert!(!<bool as SlotEncode>::from_slot(s_f));
    }

    #[test]
    fn map_slot_derivation_legacy_compat() {
        // Legacy rule: blake3("erc20.balance:" || addr_bytes).
        let m: Map<Address, U256> = Map::new(b"erc20.balance:");
        let addr = Address::from([7u8; 32]);
        let derived = m.slot(&addr).unwrap();
        let mut h = blake3::Hasher::new();
        h.update(b"erc20.balance:");
        h.update(&[7u8; 32]);
        let expected = *h.finalize().as_bytes();
        assert_eq!(derived, expected);
    }

    #[test]
    fn map_slot_derivation_tuple_key() {
        // (Address, Address) — encoded as two 32-byte words concatenated.
        let m: Map<(Address, Address), U256> = Map::new(b"erc20.allowance:");
        let key = (Address::from([1u8; 32]), Address::from([2u8; 32]));
        let derived = m.slot(&key).unwrap();
        let mut h = blake3::Hasher::new();
        h.update(b"erc20.allowance:");
        h.update(&[1u8; 32]);
        h.update(&[2u8; 32]);
        assert_eq!(&derived, h.finalize().as_bytes());
    }

    #[test]
    fn map_slot_u64_key() {
        // Factory uses u64 keys (e.g. all_pairs_at). Legacy rule serialises
        // u64 as 8 BE bytes — matches `AbiEncode for u64`.
        let m: Map<u64, Address> = Map::new(b"factory.all_pairs:");
        let derived = m.slot(&5u64).unwrap();
        let mut h = blake3::Hasher::new();
        h.update(b"factory.all_pairs:");
        h.update(&5u64.to_be_bytes());
        assert_eq!(&derived, h.finalize().as_bytes());
    }
}
