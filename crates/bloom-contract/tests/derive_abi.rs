//! Integration tests for the `#[derive(AbiEncode, AbiDecode, AbiType)]`
//! proc-macros. Lives outside `src/` so the derives can resolve
//! `::bloom_contract::*` paths via the public crate name.

#![allow(deprecated)]

use bloom_contract::prelude::*;

#[derive(Debug, PartialEq, Eq, AbiEncode, AbiDecode, AbiType)]
struct InitConfig {
    name: String,
    symbol: String,
    decimals: u8,
    initial_supply: U256,
    initial_holder: Address,
}

#[test]
fn struct_roundtrip() {
    let cfg = InitConfig {
        name: "Loom".into(),
        symbol: "LOOM".into(),
        decimals: 18,
        initial_supply: U256::from_u128(1_000_000_000),
        initial_holder: Address::from([7u8; 32]),
    };
    let bytes = cfg.encode().unwrap();
    let back = InitConfig::decode_from(&bytes).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn struct_schema_is_named() {
    match <InitConfig as AbiType>::schema() {
        TypeSchema::Struct { name, fields } => {
            assert_eq!(name, "InitConfig");
            assert_eq!(fields.len(), 5);
            assert_eq!(fields[0].0, "name");
            assert!(matches!(fields[0].1, TypeSchema::String { max: None }));
            assert_eq!(fields[3].0, "initial_supply");
            assert!(matches!(fields[3].1, TypeSchema::U256));
        }
        other => panic!("expected struct schema, got {other:?}"),
    }
}

#[derive(Debug, PartialEq, Eq, AbiEncode, AbiDecode, AbiType)]
enum Error {
    Overflow,
    InsufficientBalance { available: U256, required: U256 },
    Frozen(u64),
}

#[test]
fn enum_roundtrip_unit_variant() {
    let v = Error::Overflow;
    let bytes = v.encode().unwrap();
    assert_eq!(bytes, vec![0u8]);
    let back = Error::decode_from(&bytes).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enum_roundtrip_named_variant() {
    let v = Error::InsufficientBalance {
        available: U256::from_u128(10),
        required: U256::from_u128(50),
    };
    let bytes = v.encode().unwrap();
    // discriminant byte (= 1) + 32 bytes available + 32 bytes required
    assert_eq!(bytes.len(), 1 + 32 + 32);
    assert_eq!(bytes[0], 1);
    let back = Error::decode_from(&bytes).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enum_roundtrip_tuple_variant() {
    let v = Error::Frozen(0xDEADBEEF);
    let bytes = v.encode().unwrap();
    assert_eq!(bytes[0], 2);
    let back = Error::decode_from(&bytes).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enum_rejects_unknown_discriminant() {
    let bytes = vec![9u8];
    let res = Error::decode_from(&bytes);
    assert!(matches!(res, Err(AbiError::InvalidDiscriminant(9))));
}

#[derive(Debug, PartialEq, Eq, AbiEncode, AbiDecode, AbiType)]
#[abi(transparent)]
struct Balance(U256);

#[test]
fn transparent_newtype_matches_inner() {
    let b = Balance(U256::from_u128(42));
    let bytes = b.encode().unwrap();
    assert_eq!(bytes.len(), 32);
    let back = Balance::decode_from(&bytes).unwrap();
    assert_eq!(back, b);
    // Schema mirrors the inner type.
    assert!(matches!(<Balance as AbiType>::schema(), TypeSchema::U256));
}

#[derive(Debug, PartialEq, Eq, AbiEncode, AbiDecode, AbiType)]
struct Pair(u64, u64);

#[test]
fn tuple_struct_roundtrip() {
    let p = Pair(1, 2);
    let bytes = p.encode().unwrap();
    let back = Pair::decode_from(&bytes).unwrap();
    assert_eq!(back, p);
}
