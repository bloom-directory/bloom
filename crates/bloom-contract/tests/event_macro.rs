#![allow(dead_code)]
//! Integration tests for the `#[event]` attribute macro.
//!
//! `Context::emit_raw` panics on the host (its host import is unavailable),
//! so we can't exercise the full `emit` path here — what we *can* verify is:
//!
//! - `TOPIC0` matches `blake3(EVENT_SIGNATURE)` byte-for-byte
//! - `EVENT_SIGNATURE` follows the canonical `Domain::Name(types)` form
//! - The macro pass-through preserves the struct itself (debug, equality)
//!
//! Full topic-list construction and host-side emit verification land in the
//! wasm integration tests once the wasmtime test harness can run the
//! framework end-to-end.

use bloom_contract::prelude::*;

#[event(domain = "erc20")]
#[derive(Debug, PartialEq, Eq)]
pub struct Transfer {
    #[indexed]
    pub from: Address,
    #[indexed]
    pub to: Address,
    pub value: U256,
}

#[event(domain = "erc20")]
#[derive(Debug, PartialEq, Eq)]
pub struct Approval {
    #[indexed]
    pub owner: Address,
    #[indexed]
    pub spender: Address,
    pub value: U256,
}

#[test]
fn event_signature_uses_domain_prefix() {
    assert_eq!(Transfer::EVENT_SIGNATURE, "erc20::Transfer(address,address,u256)");
    assert_eq!(Approval::EVENT_SIGNATURE, "erc20::Approval(address,address,u256)");
}

#[test]
fn topic0_matches_blake3_of_signature() {
    let expected = blake3::hash(Transfer::EVENT_SIGNATURE.as_bytes());
    assert_eq!(&Transfer::TOPIC0, expected.as_bytes());
}

#[test]
fn distinct_events_have_distinct_topic0() {
    assert_ne!(Transfer::TOPIC0, Approval::TOPIC0);
}

#[test]
fn event_name_is_struct_ident() {
    assert_eq!(Transfer::EVENT_NAME, "Transfer");
}

#[test]
fn struct_is_still_constructible_after_macro_expansion() {
    let t = Transfer {
        from: Address::from([1u8; 32]),
        to: Address::from([2u8; 32]),
        value: U256::from_u128(100),
    };
    assert_eq!(t.from, Address::from([1u8; 32]));
    assert_eq!(t.value, U256::from_u128(100));
}
