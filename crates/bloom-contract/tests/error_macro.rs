#![allow(dead_code)]
//! Integration tests for the `#[error]` attribute macro.

use bloom_contract::error::{Error as ErrorTrait, ErrorVariantDescriptor};
use bloom_contract::prelude::*;

#[error(domain = "erc20")]
#[derive(Debug, PartialEq, Eq)]
pub enum Erc20Error {
    InsufficientBalance,
    InsufficientAllowance,
    Overflow,
    Frozen(u64),
    BadRecipient { recipient: Address, reason: u8 },
}

#[test]
fn variant_count_matches_source() {
    assert_eq!(Erc20Error::VARIANT_COUNT, 5);
    assert_eq!(Erc20Error::VARIANTS.len(), 5);
}

#[test]
fn unit_variant_selector_is_first_four_blake3_bytes() {
    let sig = "erc20::Erc20Error::InsufficientBalance()";
    let h = blake3::hash(sig.as_bytes());
    let expected: [u8; 4] = h.as_bytes()[..4].try_into().unwrap();
    assert_eq!(Erc20Error::SEL_INSUFFICIENT_BALANCE, expected);
}

#[test]
fn tuple_variant_selector_includes_payload_types() {
    let sig = "erc20::Erc20Error::Frozen(u64)";
    let h = blake3::hash(sig.as_bytes());
    let expected: [u8; 4] = h.as_bytes()[..4].try_into().unwrap();
    assert_eq!(Erc20Error::SEL_FROZEN, expected);
}

#[test]
fn named_variant_selector_uses_field_types_in_order() {
    let sig = "erc20::Erc20Error::BadRecipient(address,u8)";
    let h = blake3::hash(sig.as_bytes());
    let expected: [u8; 4] = h.as_bytes()[..4].try_into().unwrap();
    assert_eq!(Erc20Error::SEL_BAD_RECIPIENT, expected);
}

#[test]
fn encode_revert_unit_variant_is_just_selector() {
    let bytes = Erc20Error::Overflow.encode_revert();
    assert_eq!(bytes.len(), 4);
    assert_eq!(&bytes[..], &Erc20Error::SEL_OVERFLOW);
}

#[test]
fn encode_revert_tuple_variant_is_selector_plus_payload() {
    let bytes = Erc20Error::Frozen(0xCAFE).encode_revert();
    // 4-byte selector + 8-byte u64 BE payload.
    assert_eq!(bytes.len(), 4 + 8);
    assert_eq!(&bytes[..4], &Erc20Error::SEL_FROZEN);
    assert_eq!(&bytes[4..], &0xCAFE_u64.to_be_bytes());
}

#[test]
fn encode_revert_named_variant_packs_fields_in_order() {
    let err = Erc20Error::BadRecipient {
        recipient: Address::from([9u8; 32]),
        reason: 3,
    };
    let bytes = err.encode_revert();
    // selector(4) + address(32) + u8(1) = 37 bytes.
    assert_eq!(bytes.len(), 37);
    assert_eq!(&bytes[..4], &Erc20Error::SEL_BAD_RECIPIENT);
    assert_eq!(&bytes[4..36], &[9u8; 32]);
    assert_eq!(bytes[36], 3);
}

#[test]
fn descriptors_carry_signatures_in_source_order() {
    let v: &[ErrorVariantDescriptor] = Erc20Error::VARIANTS;
    assert_eq!(v[0].name, "InsufficientBalance");
    assert_eq!(v[0].signature, "erc20::Erc20Error::InsufficientBalance()");
    assert_eq!(v[0].field_count, 0);
    assert_eq!(v[3].name, "Frozen");
    assert_eq!(v[3].field_count, 1);
    assert_eq!(v[4].name, "BadRecipient");
    assert_eq!(v[4].field_count, 2);
}

#[test]
fn error_trait_name_matches_enum_ident() {
    assert_eq!(<Erc20Error as ErrorTrait>::NAME, "Erc20Error");
}

#[test]
fn all_selectors_are_distinct() {
    let s = [
        Erc20Error::SEL_INSUFFICIENT_BALANCE,
        Erc20Error::SEL_INSUFFICIENT_ALLOWANCE,
        Erc20Error::SEL_OVERFLOW,
        Erc20Error::SEL_FROZEN,
        Erc20Error::SEL_BAD_RECIPIENT,
    ];
    for i in 0..s.len() {
        for j in (i + 1)..s.len() {
            assert_ne!(s[i], s[j], "selectors collide at {i}/{j}");
        }
    }
}
