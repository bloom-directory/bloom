#![allow(dead_code)]
#![allow(deprecated)]
//! Integration tests for the `#[storage]` attribute macro.
//!
//! The macro generates `load(ctx) -> Result<Self>` and a `SCHEMA` const that
//! the build crate consumes. These tests cover:
//!
//! - field-name → slot derivation for new-rule scalars
//! - byte-for-byte parity with the legacy `erc20.balance:` /
//!   `erc20.allowance:` / `factory.all_pairs:` mapping prefixes via
//!   `#[storage(compat_tag = "..." )]`
//! - the `SCHEMA` descriptor surface
//!
//! Storage I/O itself is exercised in the wasm-VM integration tests (Phase
//! 7+); on the host `state::read/write` panic, so we stay clear of them here.

use bloom_contract::prelude::*;
use bloom_contract::storage::{
    StorageEntry, StorageKind, slot_for_compat_tag, slot_for_field,
};

#[storage(domain = "erc20")]
pub struct Erc20State {
    pub name: StorageValue<U256>,
    pub total_supply: StorageValue<U256>,
    #[storage(compat_tag = "erc20.balance:")]
    pub balances: Map<Address, U256>,
    #[storage(compat_tag = "erc20.allowance:")]
    pub allowances: Map<(Address, Address), U256>,
}

#[test]
fn storage_domain_is_attribute_value() {
    assert_eq!(Erc20State::STORAGE_DOMAIN, "erc20");
}

#[test]
fn schema_has_entry_per_field_in_source_order() {
    let entries = Erc20State::SCHEMA;
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].name, "name");
    assert_eq!(entries[1].name, "total_supply");
    assert_eq!(entries[2].name, "balances");
    assert_eq!(entries[3].name, "allowances");
}

#[test]
fn schema_scalar_kind_carries_ty() {
    match Erc20State::SCHEMA[1].kind {
        StorageKind::Scalar { ty } => assert_eq!(ty, "u256"),
        other => panic!("expected scalar, got {other:?}"),
    }
}

#[test]
fn schema_map_kind_carries_key_and_value_ty() {
    match Erc20State::SCHEMA[2].kind {
        StorageKind::Map { key_ty, value_ty } => {
            assert_eq!(key_ty, "address");
            assert_eq!(value_ty, "u256");
        }
        other => panic!("expected map, got {other:?}"),
    }
}

#[test]
fn schema_compat_tag_is_preserved() {
    assert_eq!(Erc20State::SCHEMA[2].compat_tag, Some("erc20.balance:"));
    assert_eq!(Erc20State::SCHEMA[3].compat_tag, Some("erc20.allowance:"));
    assert_eq!(Erc20State::SCHEMA[0].compat_tag, None);
}

#[test]
fn schema_map_prefix_matches_compat_tag_bytes() {
    assert_eq!(Erc20State::SCHEMA[2].prefix, b"erc20.balance:");
    assert_eq!(Erc20State::SCHEMA[3].prefix, b"erc20.allowance:");
}

#[test]
fn scalar_slot_matches_new_rule() {
    let derived = Erc20State::SCHEMA[1].derived_slot(Erc20State::STORAGE_DOMAIN);
    let expected = slot_for_field("erc20", "total_supply");
    assert_eq!(derived, expected);
}

#[test]
fn scalar_with_compat_tag_takes_legacy_slot() {
    // Define a separate struct to avoid coupling the assertion to the layout
    // above; this is also the migration-time invariant the spec calls out.
    #[storage(domain = "router")]
    pub struct RouterState {
        #[storage(compat_tag = "router.factory")]
        pub factory: StorageValue<Address>,
    }

    let derived = RouterState::SCHEMA[0].derived_slot(RouterState::STORAGE_DOMAIN);
    let expected = slot_for_compat_tag("router.factory");
    assert_eq!(derived, expected);
}

#[test]
fn map_slot_matches_legacy_blake3_format() {
    // erc20.balance: + addr_bytes is the exact pre-migration encoding.
    let cfg = Context::default();
    let state = Erc20State::load(&cfg).unwrap();
    let addr = Address::from([7u8; 32]);
    let derived = state.balances.slot(&addr).unwrap();

    let mut h = blake3::Hasher::new();
    h.update(b"erc20.balance:");
    h.update(&[7u8; 32]);
    assert_eq!(&derived, h.finalize().as_bytes());
}

#[test]
fn map_slot_matches_legacy_tuple_key_format() {
    let cfg = Context::default();
    let state = Erc20State::load(&cfg).unwrap();
    let key = (Address::from([1u8; 32]), Address::from([2u8; 32]));
    let derived = state.allowances.slot(&key).unwrap();

    let mut h = blake3::Hasher::new();
    h.update(b"erc20.allowance:");
    h.update(&[1u8; 32]);
    h.update(&[2u8; 32]);
    assert_eq!(&derived, h.finalize().as_bytes());
}

#[test]
fn map_slot_with_u64_key_matches_factory_layout() {
    #[storage(domain = "factory")]
    pub struct Factory {
        #[storage(compat_tag = "factory.all_pairs:")]
        pub all_pairs_at: Map<u64, Address>,
    }

    let cfg = Context::default();
    let f = Factory::load(&cfg).unwrap();
    let derived = f.all_pairs_at.slot(&7u64).unwrap();

    let mut h = blake3::Hasher::new();
    h.update(b"factory.all_pairs:");
    h.update(&7u64.to_be_bytes());
    assert_eq!(&derived, h.finalize().as_bytes());
}

#[test]
fn vecstore_uses_new_rule_slot_for_len() {
    #[storage(domain = "factory")]
    pub struct Factory {
        pub all_pairs: VecStore<Address>,
    }

    let entry: &StorageEntry = &Factory::SCHEMA[0];
    match entry.kind {
        StorageKind::Vec { ty } => assert_eq!(ty, "address"),
        other => panic!("expected vec, got {other:?}"),
    }
    let slot = entry.derived_slot("factory");
    let expected = slot_for_field("factory", "all_pairs");
    assert_eq!(slot, expected);
}

#[test]
fn default_domain_uses_struct_name_in_snake_case() {
    // No explicit `domain = ...` — should fall back to "router_v2".
    #[storage]
    pub struct RouterV2 {
        pub admin: StorageValue<Address>,
    }
    assert_eq!(RouterV2::STORAGE_DOMAIN, "router_v2");
}
