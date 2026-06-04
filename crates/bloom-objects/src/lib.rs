//! Shared object-model types for Bloom-native contracts.
//!
//! This is the **leaf crate** for the contracts redesign: it owns the
//! pure data types every other new crate (`bloom-resource`,
//! `bloom-script`, `bloom-resource-macros`, the new petals) depends
//! on. It deliberately has zero references to wasmtime, the chain
//! state, or the PTB executor — those live in higher-level crates that
//! will depend on this one.
//!
//! Scope:
//! - [`id`] — `ObjectId` derivation.
//! - [`object`] — `Owner` + `Object` records and canonical codec.
//! - [`packet`] — `Packet` pipe-edge envelope (`TypeTag` + in-plan/object ref).
//! - [`type_tag`] — recursive `TypeTag` (concrete / generic / external).
//! - [`abilities`] — `AbilitySet` bitfield + `AccessMode` enum.
//! - [`codec`] — variable-length codec extensions over `bloom-chain-abi`.
//! - [`host_imports`] — host-import name + signature declarations (data only).
//! - [`primitive`] — canonical-bytes validator for primitive `TypeTag`
//!   payloads, used by the PTB validator's strict typecheck pass.
//! - [`store`] — key/value types for the two new chain-state tries.
//!
//! Spec: `docs/specs/2026-05-20-bloom-native-contracts-design.md`
//! (§4, §7.1, §8, §16).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod abilities;
pub mod codec;
pub mod host_imports;
pub mod id;
pub mod object;
pub mod packet;
pub mod primitive;
pub mod store;
pub mod type_tag;

pub use abilities::{AbilityParseError, AbilitySet, AccessMode};
pub use codec::CodecError;
pub use host_imports::{HostImport, NEW_HOST_IMPORTS, WasmValType};
pub use id::{OBJECT_ID_TAG, ObjectId};
pub use object::{
    OWNER_KIND_ADDRESS, OWNER_KIND_IMMUTABLE, OWNER_KIND_OBJECT, OWNER_KIND_SHARED, Object, Owner,
};
pub use packet::{PACKET_REF_OBJECT, PACKET_REF_USE, Packet, PacketRef};
pub use primitive::{ValidationOutcome, validate_canonical_bytes};
pub use store::{
    OBJECT_LEAF_TAG, OBJECT_ROOT_TAG, OWNERSHIP_LEAF_TAG, OWNERSHIP_ROOT_TAG, ObjectTrieKey,
    ObjectTrieValue, OwnershipIndexKey, OwnershipIndexValue,
};
pub use type_tag::{BUILTIN_TYPE_HASH, TypeTag};
