//! Unit tests for `bloom-petal-dex-pool`.
//!
//! This is a wasm-cdylib petal, so the entry points in `mod pool` drive
//! host imports that are not available in a plain `cargo test` run. We
//! therefore test only the two layers that are host-independent:
//!
//! 1. **Payload helpers** (`payload::pool_payload` / `payload::decode_pool`,
//!    `payload::lp_payload` / `payload::decode_lp`) — pure encode/decode
//!    round-trips, no host I/O.
//! 2. **`ParamCodec`** for `ConstantProductParams` — encode/decode
//!    round-trip.
//! 3. **Create-pool math** — verify that the initial LP mint computed by
//!    `ConstantProduct::add_liquidity(0, 0, a, b, 0)` matches
//!    `bloom_dex_math::integer_sqrt(a * b)`, which is the formula the
//!    petal's `create_pool` delegates to.
//!
//! Full PTB-level integration tests (which exercise the host imports via
//! the mock) will live in `bloom-petal-dex-it` (Task #44).

use bloom_dex_math::{ConstantProduct, ConstantProductParams, SwapStrategy, integer_sqrt};
use bloom_objects::{ObjectId, TypeTag};
use bloom_petal_dex_pool::ParamCodec;
use bloom_petal_dex_pool::payload;
use bloom_petal_dex_pool::pool;
use bloom_value::{CodecLimits, validate_value_bytes};

fn test_tag(name: &str) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: name.to_string(),
        type_args: vec![],
    }
}

// ─── 1. Pool payload round-trips ─────────────────────────────────────────────

#[test]
fn pool_payload_round_trip_basic() {
    let id = ObjectId([0x11u8; 32]);
    let reserve_a = 1_000_000u128;
    let reserve_b = 2_000_000u128;
    let lp_supply = 1_414u128;
    let k_last = reserve_a * reserve_b;
    let params_bytes = ConstantProductParams { fee_bps: 30 }.encode();
    let coin_a_tag = test_tag("A");
    let coin_b_tag = test_tag("B");

    let encoded = payload::pool_payload(
        &id,
        reserve_a,
        reserve_b,
        lp_supply,
        k_last,
        &params_bytes,
        &coin_a_tag,
        &coin_b_tag,
    );

    let (ra, rb, lps, kl, pb, got_a_tag, got_b_tag) =
        payload::decode_pool(&encoded).expect("decode_pool should succeed");

    assert_eq!(ra, reserve_a);
    assert_eq!(rb, reserve_b);
    assert_eq!(lps, lp_supply);
    assert_eq!(kl, k_last);
    assert_eq!(pb, params_bytes);
    assert_eq!(got_a_tag, coin_a_tag);
    assert_eq!(got_b_tag, coin_b_tag);
}

#[test]
fn pool_payload_round_trip_zero_reserves() {
    let id = ObjectId([0u8; 32]);
    let params_bytes = ConstantProductParams { fee_bps: 0 }.encode();
    let encoded = payload::pool_payload(
        &id,
        0,
        0,
        0,
        0,
        &params_bytes,
        &test_tag("A"),
        &test_tag("B"),
    );

    let (ra, rb, lps, kl, _pb, _coin_a, _coin_b) =
        payload::decode_pool(&encoded).expect("decode_pool with zeros");

    assert_eq!(ra, 0);
    assert_eq!(rb, 0);
    assert_eq!(lps, 0);
    assert_eq!(kl, 0);
}

#[test]
fn pool_payload_round_trip_large_values() {
    let id = ObjectId([0xFFu8; 32]);
    let reserve_a = u128::MAX / 2;
    let reserve_b = u128::MAX / 3;
    let lp_supply = u128::MAX / 4;
    let k_last = 999_999_999_999_999u128;
    let params_bytes = ConstantProductParams { fee_bps: 9999 }.encode();
    let coin_a_tag = test_tag("LargeA");
    let coin_b_tag = test_tag("LargeB");

    let encoded = payload::pool_payload(
        &id,
        reserve_a,
        reserve_b,
        lp_supply,
        k_last,
        &params_bytes,
        &coin_a_tag,
        &coin_b_tag,
    );

    let (ra, rb, lps, kl, pb, got_a_tag, got_b_tag) =
        payload::decode_pool(&encoded).expect("decode_pool large values");

    assert_eq!(ra, reserve_a);
    assert_eq!(rb, reserve_b);
    assert_eq!(lps, lp_supply);
    assert_eq!(kl, k_last);
    assert_eq!(pb, params_bytes);
    assert_eq!(got_a_tag, coin_a_tag);
    assert_eq!(got_b_tag, coin_b_tag);
}

#[test]
fn decode_pool_rejects_short_buffer() {
    let short = vec![0u8; 10];
    assert!(
        payload::decode_pool(&short).is_none(),
        "short buffer should fail"
    );
}

#[test]
fn payload_helpers_match_declared_manifest_layouts() {
    let manifest = bloom_petal_manifest::codec::decode(pool::__bloom_manifest_bytes()).unwrap();
    let resolver = bloom_petal_manifest::ManifestResolver::new(&manifest);
    let limits = CodecLimits::default();
    let pool_tag = TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "Pool".to_string(),
        type_args: vec![],
    };
    let lp_tag = TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "LpPosition".to_string(),
        type_args: vec![],
    };

    let id = ObjectId([0x11u8; 32]);
    let pool_id = ObjectId([0x22u8; 32]);
    let params_bytes = ConstantProductParams { fee_bps: 30 }.encode();
    let coin_a_tag = test_tag("A");
    let coin_b_tag = test_tag("B");
    let encoded = payload::pool_payload(&id, 1, 2, 3, 4, &params_bytes, &coin_a_tag, &coin_b_tag);
    validate_value_bytes(&resolver, &pool_tag, &encoded, &limits).unwrap();

    let mut old_four_byte_params_len = Vec::new();
    old_four_byte_params_len.extend_from_slice(&id.0);
    old_four_byte_params_len.extend_from_slice(&1u128.to_be_bytes());
    old_four_byte_params_len.extend_from_slice(&2u128.to_be_bytes());
    old_four_byte_params_len.extend_from_slice(&3u128.to_be_bytes());
    old_four_byte_params_len.extend_from_slice(&4u128.to_be_bytes());
    old_four_byte_params_len.extend_from_slice(&(params_bytes.len() as u32).to_be_bytes());
    old_four_byte_params_len.extend_from_slice(&params_bytes);
    coin_a_tag
        .encode_into(&mut old_four_byte_params_len)
        .unwrap();
    coin_b_tag
        .encode_into(&mut old_four_byte_params_len)
        .unwrap();
    assert!(
        validate_value_bytes(&resolver, &pool_tag, &old_four_byte_params_len, &limits).is_err(),
        "old 4-byte params_bytes length prefix must not validate"
    );

    let lp_payload = payload::lp_payload(&id, &pool_id, 99);
    validate_value_bytes(&resolver, &lp_tag, &lp_payload, &limits).unwrap();
}

// ─── 2. LpPosition payload round-trips ───────────────────────────────────────

#[test]
fn lp_payload_round_trip_basic() {
    let id = ObjectId([0x22u8; 32]);
    let pool_id = ObjectId([0x33u8; 32]);
    let shares = 600u128;

    let encoded = payload::lp_payload(&id, &pool_id, shares);
    let (got_pool_id, got_shares) = payload::decode_lp(&encoded).expect("decode_lp should succeed");

    assert_eq!(got_pool_id, pool_id);
    assert_eq!(got_shares, shares);
}

#[test]
fn lp_payload_round_trip_max_shares() {
    let id = ObjectId([0u8; 32]);
    let pool_id = ObjectId([0xABu8; 32]);
    let shares = u128::MAX;

    let encoded = payload::lp_payload(&id, &pool_id, shares);
    let (got_pool_id, got_shares) = payload::decode_lp(&encoded).expect("decode_lp max shares");

    assert_eq!(got_pool_id, pool_id);
    assert_eq!(got_shares, shares);
}

#[test]
fn lp_payload_encoded_length_is_80_bytes() {
    let id = ObjectId([0u8; 32]);
    let pool_id = ObjectId([0u8; 32]);
    let encoded = payload::lp_payload(&id, &pool_id, 0);
    // 32 (id) + 32 (pool_id) + 16 (shares u128) = 80
    assert_eq!(
        encoded.len(),
        80,
        "LpPosition payload must be exactly 80 bytes"
    );
}

#[test]
fn decode_lp_rejects_short_buffer() {
    let short = vec![0u8; 40];
    assert!(
        payload::decode_lp(&short).is_none(),
        "short buffer should fail"
    );
}

// ─── 3. ParamCodec for ConstantProductParams ──────────────────────────────────

#[test]
fn constant_product_params_encode_decode_round_trip() {
    let params = ConstantProductParams { fee_bps: 30 };
    let encoded = params.encode();
    let decoded = ConstantProductParams::decode(&encoded).expect("decode should succeed");
    assert_eq!(decoded, params);
}

#[test]
fn constant_product_params_encode_is_2_bytes() {
    let params = ConstantProductParams { fee_bps: 100 };
    let encoded = params.encode();
    assert_eq!(encoded.len(), 2, "ConstantProductParams encodes to 2 bytes");
    // Big-endian: fee_bps 100 = 0x0064
    assert_eq!(encoded, vec![0x00, 0x64]);
}

#[test]
fn constant_product_params_decode_zero() {
    let params = ConstantProductParams { fee_bps: 0 };
    let encoded = params.encode();
    let decoded = ConstantProductParams::decode(&encoded).expect("decode zero fee_bps");
    assert_eq!(decoded.fee_bps, 0);
}

#[test]
fn constant_product_params_decode_rejects_short() {
    let short = vec![0xABu8];
    assert!(
        ConstantProductParams::decode(&short).is_none(),
        "single byte must fail"
    );
}

#[test]
fn constant_product_params_decode_rejects_empty() {
    assert!(
        ConstantProductParams::decode(&[]).is_none(),
        "empty slice must fail"
    );
}

// ─── 4. Create-pool math matches SwapStrategy directly ───────────────────────

/// The petal's `create_pool` delegates the initial user LP amount to
/// `S::add_liquidity(0, 0, value_a, value_b, 0)`. Verify that the result
/// matches `floor(sqrt(value_a * value_b)) - MINIMUM_LIQUIDITY`.
#[test]
fn create_pool_initial_lp_matches_sqrt() {
    let cases: &[(u128, u128)] = &[
        (4_000_000, 9_000_000), // sqrt(36e12) = 6_000_000
        (10_000, 20_000),       // sqrt(200_000_000) = 14_142
        (1_000_000, 1_000_000), // sqrt(1e12) = 1_000_000
        (12_340, 56_780),       // arbitrary
    ];

    for &(a, b) in cases {
        let (taken_a, taken_b, lp_minted) =
            ConstantProduct::add_liquidity(0, 0, a, b, 0).expect("add_liquidity should succeed");
        assert_eq!(
            taken_a, a,
            "all of coin_a should be taken on initial deposit"
        );
        assert_eq!(
            taken_b, b,
            "all of coin_b should be taken on initial deposit"
        );
        let expected_lp = integer_sqrt(a.checked_mul(b).expect("no overflow in test"))
            - bloom_dex_math::MINIMUM_LIQUIDITY;
        assert_eq!(
            lp_minted, expected_lp,
            "initial LP minted {lp_minted} != sqrt({a}*{b})={expected_lp}"
        );
    }
}

#[test]
fn create_pool_zero_input_returns_insufficient_liquidity() {
    // sqrt(0 * anything) = 0 → InsufficientLiquidity
    let err = ConstantProduct::add_liquidity(0, 0, 0, 1000, 0).unwrap_err();
    assert_eq!(err, bloom_dex_math::MathError::InsufficientLiquidity);
}

// ─── 5. PoolError display ─────────────────────────────────────────────────────

#[test]
fn pool_error_display_variants() {
    use bloom_petal_dex_pool::PoolError;

    assert_eq!(PoolError::SlippageExceeded.to_string(), "slippage exceeded");
    assert_eq!(
        PoolError::InsufficientLiquidity.to_string(),
        "insufficient liquidity"
    );
    assert_eq!(PoolError::WrongPool.to_string(), "wrong pool");
    assert!(
        PoolError::MathFailed(bloom_dex_math::MathError::Overflow)
            .to_string()
            .contains("overflow")
    );
}

// ─── 6. PoolError From<MathError> ────────────────────────────────────────────

#[test]
fn pool_error_from_math_error() {
    use bloom_petal_dex_pool::PoolError;

    let e: PoolError = bloom_dex_math::MathError::ZeroReserves.into();
    assert!(matches!(
        e,
        PoolError::MathFailed(bloom_dex_math::MathError::ZeroReserves)
    ));
}

#[test]
fn constant_product_params_decode_bounds_fee_bps() {
    use bloom_dex_math::ConstantProductParams;

    assert_eq!(
        ConstantProductParams::decode(&9999u16.to_be_bytes()),
        Some(ConstantProductParams { fee_bps: 9999 })
    );
    assert_eq!(ConstantProductParams::decode(&10000u16.to_be_bytes()), None);
    assert_eq!(ConstantProductParams::decode(&10001u16.to_be_bytes()), None);
    assert_eq!(ConstantProductParams::decode(&[0x00]), None);
    assert_eq!(ConstantProductParams::decode(&[0x00, 0x1e, 0x00]), None);
}
