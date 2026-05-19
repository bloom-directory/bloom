//! Integration tests for bloom-dex-abi.
//!
//! Covers:
//! - Round-trip encode→decode for every ABI type.
//! - U256 sqrt of perfect squares.
//! - U256 overflow rejection.
//! - Selector uniqueness across all method strings.

use bloom_dex_abi::{
    decode::{AbiError, Buf},
    encode::Encoder,
    selectors,
    u256::U256,
};

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_address() {
    let addr = [0xABu8; 32];
    let mut e = Encoder::new();
    e.push_address(&addr);
    let out = e.finish();
    let mut buf = Buf::new(&out);
    assert_eq!(buf.read_address().unwrap(), addr);
}

#[test]
fn roundtrip_bytes32() {
    let b = [0x5Cu8; 32];
    let mut e = Encoder::new();
    e.push_bytes32(&b);
    let out = e.finish();
    let mut buf = Buf::new(&out);
    assert_eq!(buf.read_bytes32().unwrap(), b);
}

#[test]
fn roundtrip_u256_zero() {
    let v = U256::ZERO;
    let mut e = Encoder::new();
    e.push_u256(v);
    let out = e.finish();
    let mut buf = Buf::new(&out);
    assert_eq!(buf.read_u256().unwrap(), v);
}

#[test]
fn roundtrip_u256_max() {
    let v = U256([0xff; 32]);
    let mut e = Encoder::new();
    e.push_u256(v);
    let out = e.finish();
    let mut buf = Buf::new(&out);
    assert_eq!(buf.read_u256().unwrap(), v);
}

#[test]
fn roundtrip_u256_mid() {
    let v = U256::from_u128(u128::MAX / 2);
    let mut e = Encoder::new();
    e.push_u256(v);
    let out = e.finish();
    let mut buf = Buf::new(&out);
    assert_eq!(buf.read_u256().unwrap(), v);
}

#[test]
fn roundtrip_u128() {
    let vals: &[u128] = &[0, 1, u64::MAX as u128, u128::MAX];
    for &v in vals {
        let mut e = Encoder::new();
        e.push_u128(v);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        assert_eq!(buf.read_u128().unwrap(), v, "u128 roundtrip failed for {v}");
    }
}

#[test]
fn roundtrip_u64() {
    let vals: &[u64] = &[0, 1, 0xDEAD_BEEF, u64::MAX];
    for &v in vals {
        let mut e = Encoder::new();
        e.push_u64(v);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        assert_eq!(buf.read_u64().unwrap(), v, "u64 roundtrip failed for {v}");
    }
}

#[test]
fn roundtrip_bool() {
    for &v in &[true, false] {
        let mut e = Encoder::new();
        e.push_bool(v);
        let out = e.finish();
        let mut buf = Buf::new(&out);
        assert_eq!(buf.read_bool().unwrap(), v);
    }
}

#[test]
fn roundtrip_address_vec_empty() {
    let mut e = Encoder::new();
    e.push_address_vec(&[]).unwrap();
    let out = e.finish();
    let mut buf = Buf::new(&out);
    let decoded = buf.read_address_vec().unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn roundtrip_address_vec_several() {
    let addrs: &[[u8; 32]] = &[[1u8; 32], [2u8; 32], [255u8; 32]];
    let mut e = Encoder::new();
    e.push_address_vec(addrs).unwrap();
    let out = e.finish();
    let mut buf = Buf::new(&out);
    let decoded = buf.read_address_vec().unwrap();
    assert_eq!(decoded.as_slice(), addrs);
}

// ---------------------------------------------------------------------------
// U256 sqrt tests
// ---------------------------------------------------------------------------

#[test]
fn sqrt_perfect_squares() {
    let cases: &[(u64, u64)] = &[
        (0, 0),
        (1, 1),
        (4, 2),
        (9, 3),
        (16, 4),
        (25, 5),
        (100, 10),
        (10_000, 100),
        (1_000_000, 1_000),
        (u32::MAX as u64 * u32::MAX as u64, u32::MAX as u64),
    ];
    for &(sq, expected_root) in cases {
        let input = U256::from_u64(sq);
        let root = input.sqrt();
        assert_eq!(
            root,
            U256::from_u64(expected_root),
            "sqrt({sq}) should be {expected_root}"
        );
    }
}

#[test]
fn sqrt_large_perfect_square() {
    // (2^64)^2 = 2^128; sqrt should be 2^64.
    let two_pow_128 = {
        let mut b = [0u8; 32];
        b[15] = 1; // byte 15 from left = 2^((32-16)*8) = 2^128
        U256(b)
    };
    let two_pow_64 = {
        let mut b = [0u8; 32];
        b[23] = 1; // 2^64
        U256(b)
    };
    assert_eq!(two_pow_128.sqrt(), two_pow_64);
}

// ---------------------------------------------------------------------------
// U256 overflow rejection
// ---------------------------------------------------------------------------

#[test]
fn add_overflow_rejected() {
    let max = U256([0xff; 32]);
    assert!(max.checked_add(U256::from_u64(1)).is_none());
}

#[test]
fn sub_underflow_rejected() {
    assert!(U256::ZERO.checked_sub(U256::from_u64(1)).is_none());
}

#[test]
fn mul_overflow_rejected() {
    // 2^128 * 2^128 = 2^256 overflows.
    let hi128 = {
        let mut b = [0u8; 32];
        b[15] = 1;
        U256(b)
    };
    assert!(hi128.checked_mul(hi128).is_none());
}

#[test]
fn div_zero_rejected() {
    assert!(U256::from_u64(42).checked_div(U256::ZERO).is_none());
}

// ---------------------------------------------------------------------------
// Selector uniqueness
// ---------------------------------------------------------------------------

#[test]
fn selectors_are_unique() {
    // All selectors from §4.1
    let sels: &[(&str, [u8; 4])] = &[
        ("ERC20_TOTAL_SUPPLY",        selectors::ERC20_TOTAL_SUPPLY),
        ("ERC20_BALANCE_OF",          selectors::ERC20_BALANCE_OF),
        ("ERC20_ALLOWANCE",           selectors::ERC20_ALLOWANCE),
        ("ERC20_TRANSFER",            selectors::ERC20_TRANSFER),
        ("ERC20_TRANSFER_FROM",       selectors::ERC20_TRANSFER_FROM),
        ("ERC20_APPROVE",             selectors::ERC20_APPROVE),
        ("ERC20_NAME",                selectors::ERC20_NAME),
        ("ERC20_SYMBOL",              selectors::ERC20_SYMBOL),
        ("ERC20_DECIMALS",            selectors::ERC20_DECIMALS),
        ("PAIR_TOKEN0",               selectors::PAIR_TOKEN0),
        ("PAIR_TOKEN1",               selectors::PAIR_TOKEN1),
        ("PAIR_GET_RESERVES",         selectors::PAIR_GET_RESERVES),
        ("PAIR_MINT",                 selectors::PAIR_MINT),
        ("PAIR_BURN",                 selectors::PAIR_BURN),
        ("PAIR_SWAP",                 selectors::PAIR_SWAP),
        ("PAIR_SKIM",                 selectors::PAIR_SKIM),
        ("PAIR_SYNC",                 selectors::PAIR_SYNC),
        ("FACTORY_CREATE_PAIR",       selectors::FACTORY_CREATE_PAIR),
        ("FACTORY_GET_PAIR",          selectors::FACTORY_GET_PAIR),
        ("FACTORY_ALL_PAIRS",         selectors::FACTORY_ALL_PAIRS),
        ("FACTORY_ALL_PAIRS_LENGTH",  selectors::FACTORY_ALL_PAIRS_LENGTH),
        ("ROUTER_ADD_LIQUIDITY",      selectors::ROUTER_ADD_LIQUIDITY),
        ("ROUTER_REMOVE_LIQUIDITY",   selectors::ROUTER_REMOVE_LIQUIDITY),
        ("ROUTER_SWAP_EXACT_TOKENS_FOR_TOKENS", selectors::ROUTER_SWAP_EXACT_TOKENS_FOR_TOKENS),
        ("ROUTER_SWAP_TOKENS_FOR_EXACT_TOKENS", selectors::ROUTER_SWAP_TOKENS_FOR_EXACT_TOKENS),
        ("WLOOM_DEPOSIT",             selectors::WLOOM_DEPOSIT),
        ("WLOOM_WITHDRAW",            selectors::WLOOM_WITHDRAW),
        ("REENTRANCY_ENTER",          selectors::REENTRANCY_ENTER),
        // Pair internal selectors (callable only by reentrancy petal)
        ("PAIR_LOCK_CHECK_AND_SET",   selectors::PAIR_LOCK_CHECK_AND_SET),
        ("PAIR_LOCK_CLEAR",           selectors::PAIR_LOCK_CLEAR),
        ("PAIR_MINT_INNER",           selectors::PAIR_MINT_INNER),
        ("PAIR_BURN_INNER",           selectors::PAIR_BURN_INNER),
        ("PAIR_SWAP_INNER",           selectors::PAIR_SWAP_INNER),
    ];

    let mut seen: std::collections::HashSet<[u8; 4]> = std::collections::HashSet::new();
    for &(name, sel) in sels {
        assert!(
            seen.insert(sel),
            "Selector collision: {name} has selector {sel:02x?} which is already used"
        );
    }
    // Verify we checked all selectors.
    assert_eq!(seen.len(), sels.len());
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn bool_invalid_byte() {
    let data = [42u8];
    let mut buf = Buf::new(&data);
    assert_eq!(buf.read_bool(), Err(AbiError::InvalidBool(42)));
}

#[test]
fn short_read_u256() {
    let data = [0u8; 10];
    let mut buf = Buf::new(&data);
    assert!(buf.read_u256().is_err());
}

#[test]
fn address_vec_truncated() {
    // Length prefix says 3 addresses (96 bytes) but only 1 address (32 bytes) follows.
    let mut e = Encoder::new();
    e.push_bytes(&[0u8, 3u8]); // length = 3
    e.push_address(&[0u8; 32]); // only 1 address
    let out = e.finish();
    let mut buf = Buf::new(&out);
    assert!(buf.read_address_vec().is_err());
}
