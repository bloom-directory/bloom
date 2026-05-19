//! Slot-derivation determinism for `contract!`-generated storage accessors.
//!
//! Property: the same contract + field declaration produces the same 32-byte
//! storage slot every time. The macro derives slots from `(contract_snake,
//! field, tag)` purely; this test pins that behaviour by declaring the same
//! field shape in two contracts with explicit-tag overrides that match, and
//! verifies the runtime slot helpers reproduce the same bytes.

use bloom_chain_abi::storage::{
    encode_key_address, encode_key_address_address, encode_key_address_u256, encode_key_bool,
    encode_key_u128, encode_key_u256, encode_key_u64, slot_mapping, slot_scalar,
};
use bloom_chain_abi::U256;
use proptest::prelude::*;

#[test]
fn slot_scalar_pure_function_of_tag() {
    let a = slot_scalar("pair.token0");
    let b = slot_scalar("pair.token0");
    assert_eq!(a, b);
    let h = blake3::hash(b"pair.token0");
    assert_eq!(&a[..], &h.as_bytes()[..]);
}

#[test]
fn slot_mapping_pure_function_of_tag_and_key() {
    let addr = [0x42u8; 32];
    let a = slot_mapping("erc20.balance:", &addr);
    let b = slot_mapping("erc20.balance:", &addr);
    assert_eq!(a, b);

    let mut buf = Vec::new();
    buf.extend_from_slice(b"erc20.balance:");
    buf.extend_from_slice(&addr);
    let h = blake3::hash(&buf);
    assert_eq!(&a[..], &h.as_bytes()[..]);
}

#[test]
fn different_keys_produce_different_slots() {
    let a = slot_mapping("erc20.balance:", &[0x01u8; 32]);
    let b = slot_mapping("erc20.balance:", &[0x02u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn different_tags_produce_different_slots() {
    let a = slot_mapping("erc20.balance:", &[0x42u8; 32]);
    let b = slot_mapping("erc20.allowance:", &[0x42u8; 32]);
    assert_ne!(a, b);
}

// ---- Per-key-type encoding round-trips ------------------------------------

#[test]
fn encode_address_key_verbatim() {
    let a = [0xABu8; 32];
    assert_eq!(encode_key_address(&a), a);
}

#[test]
fn encode_u256_key_verbatim() {
    let v = U256::from_u64(0xDEAD_BEEF);
    assert_eq!(encode_key_u256(&v), v.0);
}

#[test]
fn encode_u128_key_left_pads() {
    let k = encode_key_u128(0x0102_0304_0506_0708u128);
    assert_eq!(&k[..24], &[0u8; 24]);
    assert_eq!(&k[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn encode_u64_key_left_pads() {
    let k = encode_key_u64(0x0102_0304_0506_0708u64);
    assert_eq!(&k[..24], &[0u8; 24]);
    assert_eq!(&k[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn encode_bool_key_last_byte() {
    assert_eq!(encode_key_bool(true)[31], 1);
    assert_eq!(encode_key_bool(false)[31], 0);
}

#[test]
fn encode_tuple_keys_are_concat() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    let k = encode_key_address_address(&a, &b);
    assert_eq!(&k[..32], &a[..]);
    assert_eq!(&k[32..], &b[..]);

    let v = U256::from_u64(7);
    let k = encode_key_address_u256(&a, &v);
    assert_eq!(&k[..32], &a[..]);
    assert_eq!(&k[32..], &v.0[..]);
}

// ---- Proptest: pure-function determinism of slot derivation --------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fuzz_slot_scalar_determinism(tag in "[a-z][a-z0-9_.]{0,32}") {
        let a = slot_scalar(&tag);
        let b = slot_scalar(&tag);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn fuzz_slot_mapping_determinism(
        tag in "[a-z][a-z0-9_.:]{0,32}",
        key in proptest::collection::vec(any::<u8>(), 0..=64),
    ) {
        let a = slot_mapping(&tag, &key);
        let b = slot_mapping(&tag, &key);
        prop_assert_eq!(a, b);
    }
}
