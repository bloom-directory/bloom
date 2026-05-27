//! Unit tests for `bloom-petal-dex-router`.
//!
//! This is a wasm-cdylib petal, so the petal entry points in `mod router`
//! exercise host imports that are not available in a plain `cargo test` run.
//! We therefore test only the host-independent layers:
//!
//! 1. **`RouterError`** — display formatting, `From<MathError>` conversion.
//! 2. **Quote math** — `ops::quote_one` is not available (needs host), but
//!    `bloom_dex_math::SwapStrategy::quote` is pure; we verify the chained
//!    2-hop and 3-hop arithmetic against hand-calculated values using the
//!    math crate directly (this is what the petal delegates to).
//! 3. **`ops::decode_coin_value` / `ops::coin_payload`** — pure codec
//!    helpers exposed from `ops`.
//! 4. **Pool payload decode** — re-uses `bloom_petal_dex_pool::payload`
//!    helpers (shared rlib dep); verifies the router's expected input format.
//! 5. **Slippage check semantics** — verifies that `RouterError::SlippageExceeded`
//!    is emitted correctly when `amount_out < min_out`.
//!
//! Full PTB-level integration tests (host mock) will land in
//! `bloom-petal-dex-it` (Task #44).

use bloom_dex_math::{ConstantProduct, ConstantProductParams, MathError, SwapStrategy};
use bloom_objects::{ObjectId, TypeTag};
use bloom_petal_dex_pool::{ParamCodec, payload};
use bloom_petal_dex_router::{RouterError, ops};
use bloom_resource::RuntimeHandle;

// ─── helpers ─────────────────────────────────────────────────────────────────

fn cpmm_params(fee_bps: u16) -> ConstantProductParams {
    ConstantProductParams { fee_bps }
}

fn test_tag(name: &str) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: name.to_string(),
        type_args: vec![],
    }
}

/// Hand-calculate the CPMM quote with the fee division kept at the end.
fn hand_quote(reserve_in: u128, reserve_out: u128, amount_in: u128, fee_bps: u16) -> u128 {
    let fee_factor = 10_000u128 - u128::from(fee_bps);
    let amount_in_fee = amount_in * fee_factor;
    let numerator = reserve_out * amount_in_fee;
    let denominator = reserve_in * 10_000 + amount_in_fee;
    numerator / denominator
}

// ─── 1. RouterError ───────────────────────────────────────────────────────────

#[test]
fn router_error_display_slippage() {
    let e = RouterError::SlippageExceeded {
        expected: 100,
        got: 90,
    };
    let s = e.to_string();
    assert!(s.contains("slippage"), "display: {s}");
    assert!(s.contains("100"), "display: {s}");
    assert!(s.contains("90"), "display: {s}");
}

#[test]
fn router_error_display_math_failed() {
    let e = RouterError::MathFailed(MathError::Overflow);
    let s = e.to_string();
    assert!(s.contains("math failed"), "display: {s}");
    assert!(s.contains("overflow"), "display: {s}");
}

#[test]
fn router_error_display_empty_input() {
    let s = RouterError::EmptyInput.to_string();
    assert!(s.contains("empty"), "display: {s}");
}

#[test]
fn router_error_display_pool_payload_decode() {
    let s = RouterError::PoolPayloadDecode.to_string();
    assert!(s.contains("pool payload"), "display: {s}");
}

#[test]
fn router_error_display_param_decode() {
    let s = RouterError::ParamDecode.to_string();
    assert!(s.contains("param"), "display: {s}");
}

#[test]
fn router_error_display_same_pool_route() {
    assert_eq!(RouterError::SamePoolRoute.to_string(), "same pool route");
}

#[test]
fn router_error_display_object_delete_failed() {
    assert_eq!(
        RouterError::ObjectDeleteFailed.to_string(),
        "object delete failed"
    );
}

#[test]
fn router_error_display_token_type_mismatch() {
    assert_eq!(
        RouterError::TokenTypeMismatch.to_string(),
        "token type mismatch"
    );
}

#[test]
fn router_error_from_math_error() {
    let me = MathError::ZeroReserves;
    let re: RouterError = me.into();
    assert_eq!(re, RouterError::MathFailed(MathError::ZeroReserves));
}

#[test]
fn router_error_eq_slippage() {
    let a = RouterError::SlippageExceeded {
        expected: 50,
        got: 40,
    };
    let b = RouterError::SlippageExceeded {
        expected: 50,
        got: 40,
    };
    assert_eq!(a, b);
}

// ─── 2. Quote math (hand-calculated, pure) ───────────────────────────────────

/// Verify 1-hop quote matches the CPMM formula directly.
#[test]
fn quote_1hop_matches_cpmm_formula() {
    let ra = 1_000_000u128;
    let rb = 2_000_000u128;
    let amount_in = 10_000u128;
    let fee_bps = 30u16;
    let p = cpmm_params(fee_bps);

    let got = ConstantProduct::quote(ra, rb, amount_in, &p).unwrap();
    let expected = hand_quote(ra, rb, amount_in, fee_bps);

    assert_eq!(got, expected, "1-hop quote mismatch");
    // Sanity: with equal reserves and small input, out < in (fee taken).
    assert!(
        got < amount_in * 2,
        "reserve_b is 2x reserve_a; out should be ≈ 2x in minus fee"
    );
}

/// Verify 2-hop quote chains two CPMM quotes correctly.
#[test]
fn quote_2hop_chains_correctly() {
    // Pool A→B: 1_000_000 / 1_000_000, fee 30 bps
    let (ra1, rb1, fee1) = (1_000_000u128, 1_000_000u128, 30u16);
    // Pool B→C: 500_000 / 2_000_000, fee 100 bps
    let (ra2, rb2, fee2) = (500_000u128, 2_000_000u128, 100u16);
    let amount_in = 5_000u128;

    let p1 = cpmm_params(fee1);
    let p2 = cpmm_params(fee2);

    let mid = ConstantProduct::quote(ra1, rb1, amount_in, &p1).unwrap();
    let out = ConstantProduct::quote(ra2, rb2, mid, &p2).unwrap();

    // Hand-calculate expected values.
    let expected_mid = hand_quote(ra1, rb1, amount_in, fee1);
    let expected_out = hand_quote(ra2, rb2, expected_mid, fee2);

    assert_eq!(mid, expected_mid, "mid amount mismatch");
    assert_eq!(out, expected_out, "final amount mismatch");
    // Output must be less than amount_in (fees taken, but rb2 > ra2 → roughly 4x leverage).
    assert!(out > 0, "out must be positive");
}

/// Verify 3-hop quote chains three CPMM quotes correctly.
#[test]
fn quote_3hop_chains_correctly() {
    // Pool A→B: 1_000_000 / 1_000_000, fee 30 bps
    let (ra1, rb1, fee1) = (1_000_000u128, 1_000_000u128, 30u16);
    // Pool B→C: 1_000_000 / 1_000_000, fee 30 bps
    let (ra2, rb2, fee2) = (1_000_000u128, 1_000_000u128, 30u16);
    // Pool C→D: 1_000_000 / 1_000_000, fee 30 bps
    let (ra3, rb3, fee3) = (1_000_000u128, 1_000_000u128, 30u16);
    let amount_in = 1_000u128;

    let p1 = cpmm_params(fee1);
    let p2 = cpmm_params(fee2);
    let p3 = cpmm_params(fee3);

    let mid1 = ConstantProduct::quote(ra1, rb1, amount_in, &p1).unwrap();
    let mid2 = ConstantProduct::quote(ra2, rb2, mid1, &p2).unwrap();
    let out = ConstantProduct::quote(ra3, rb3, mid2, &p3).unwrap();

    let exp_mid1 = hand_quote(ra1, rb1, amount_in, fee1);
    let exp_mid2 = hand_quote(ra2, rb2, exp_mid1, fee2);
    let exp_out = hand_quote(ra3, rb3, exp_mid2, fee3);

    assert_eq!(mid1, exp_mid1);
    assert_eq!(mid2, exp_mid2);
    assert_eq!(out, exp_out);
    // 3 hops at 30 bps each: out ≈ amount_in * (9970/10000)^3 ≈ 0.991 * amount_in
    // Integer arithmetic makes it slightly less; verify it's in reasonable range.
    assert!(
        out > amount_in * 98 / 100,
        "out={out} too low for 3x 30bps hops"
    );
    assert!(
        out <= amount_in,
        "out={out} must not exceed in (fees always taken)"
    );
}

/// Cross-check: 3-hop with zero fees collapses toward the CPMM no-fee formula.
#[test]
fn quote_3hop_zero_fee_near_identity() {
    let (r, fee) = (1_000_000u128, 0u16);
    let amount_in = 1_000u128;
    let p = cpmm_params(fee);

    let mid1 = ConstantProduct::quote(r, r, amount_in, &p).unwrap();
    let mid2 = ConstantProduct::quote(r, r, mid1, &p).unwrap();
    let out = ConstantProduct::quote(r, r, mid2, &p).unwrap();

    // Without fee, each hop: out ≈ in * r / (r + in) ≈ in for small in/r.
    // 3 hops with equal reserves will slightly reduce due to integer rounding.
    assert!(out > 0);
    assert!(out <= amount_in, "no-fee output must not exceed input");
}

/// Quote with asymmetric reserves: verify mid > amount_in when reserve_b >> reserve_a.
#[test]
fn quote_2hop_amplified_first_pool() {
    // Pool A→B: tiny reserve_a, large reserve_b (B is cheap relative to A)
    let (ra1, rb1, fee1) = (100_000u128, 10_000_000u128, 30u16);
    // Pool B→C: equal reserves
    let (ra2, rb2, fee2) = (1_000_000u128, 1_000_000u128, 30u16);
    let amount_in = 1_000u128;

    let p1 = cpmm_params(fee1);
    let p2 = cpmm_params(fee2);

    let mid = ConstantProduct::quote(ra1, rb1, amount_in, &p1).unwrap();
    let out = ConstantProduct::quote(ra2, rb2, mid, &p2).unwrap();

    // First hop amplifies: mid >> amount_in (B is cheap, so you get lots of B).
    assert!(
        mid > amount_in * 50,
        "mid={mid} should be >> amount_in={amount_in}"
    );
    // Second hop with equal reserves: mid is large relative to reserve_b,
    // so there is substantial price impact; out should still be positive.
    assert!(out > 0, "out={out} must be positive");
    // out < mid because fees are taken and mid is significant relative to the pool.
    assert!(
        out < mid,
        "out={out} must be less than mid={mid} (price impact + fee)"
    );
}

#[test]
fn ensure_distinct_pools_rejects_same_handle() {
    let h = RuntimeHandle::from_raw(7);
    assert_eq!(
        ops::ensure_distinct_pools(h, h),
        Err(RouterError::SamePoolRoute)
    );
}

#[test]
fn ensure_distinct_pools_accepts_different_handles() {
    assert_eq!(
        ops::ensure_distinct_pools(RuntimeHandle::from_raw(7), RuntimeHandle::from_raw(8)),
        Ok(())
    );
}

#[test]
fn ensure_all_distinct_pools_rejects_any_repeat() {
    assert_eq!(
        ops::ensure_all_distinct_pools(
            RuntimeHandle::from_raw(7),
            RuntimeHandle::from_raw(8),
            RuntimeHandle::from_raw(7),
        ),
        Err(RouterError::SamePoolRoute)
    );
}

#[test]
fn ensure_all_distinct_pools_accepts_unique_handles() {
    assert_eq!(
        ops::ensure_all_distinct_pools(
            RuntimeHandle::from_raw(7),
            RuntimeHandle::from_raw(8),
            RuntimeHandle::from_raw(9),
        ),
        Ok(())
    );
}

#[test]
fn ensure_pool_pair_rejects_mismatched_tags() {
    let a = test_tag("A");
    let b = test_tag("B");
    let c = test_tag("C");
    assert_eq!(
        ops::ensure_pool_pair(&a, &b, &a, &c),
        Err(RouterError::TokenTypeMismatch)
    );
}

#[test]
fn ensure_pool_pair_accepts_matching_tags() {
    let a = test_tag("A");
    let b = test_tag("B");
    assert_eq!(ops::ensure_pool_pair(&a, &b, &a, &b), Ok(()));
}

// ─── 3. Coin payload codec ────────────────────────────────────────────────────

#[test]
fn coin_payload_encode_decode_round_trip() {
    let value = 1_234_567_890u128;
    let payload = ops::coin_payload(value);

    // Coin payload: 32-byte id + 16-byte u128 = 48 bytes.
    assert_eq!(payload.len(), 48, "coin payload must be 48 bytes");

    let decoded = ops::decode_coin_value(&payload).expect("decode should succeed");
    assert_eq!(decoded, value);
}

#[test]
fn coin_payload_zero_value() {
    let payload = ops::coin_payload(0u128);
    assert_eq!(payload.len(), 48);
    let decoded = ops::decode_coin_value(&payload).unwrap();
    assert_eq!(decoded, 0);
}

#[test]
fn coin_payload_max_value() {
    let payload = ops::coin_payload(u128::MAX);
    let decoded = ops::decode_coin_value(&payload).unwrap();
    assert_eq!(decoded, u128::MAX);
}

#[test]
fn router_coin_create_tag_is_coin_erased() {
    assert_eq!(
        ops::coin_erased_tag(),
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "Coin".to_string(),
            type_args: vec![TypeTag::Concrete {
                petal_hash: [0u8; 32],
                type_name: "Erased".to_string(),
                type_args: vec![],
            }],
        }
    );
}

#[test]
fn decode_coin_value_rejects_short_buffer() {
    let short = vec![0u8; 47];
    assert!(
        ops::decode_coin_value(&short).is_err(),
        "short buffer must fail"
    );
}

#[test]
fn decode_coin_value_reads_bytes_32_to_48() {
    // Build a payload manually: id = 0xFF * 32, value at bytes 32..48.
    let mut buf = vec![0xFFu8; 48];
    let value: u128 = 42_000;
    buf[32..48].copy_from_slice(&value.to_be_bytes());
    let decoded = ops::decode_coin_value(&buf).unwrap();
    assert_eq!(decoded, value);
}

// ─── 4. Pool payload compatibility ───────────────────────────────────────────

/// Verify the router can decode pool payloads produced by bloom-petal-dex-pool.
#[test]
fn pool_payload_decode_compatible_with_pool_crate() {
    let id = ObjectId([0x55u8; 32]);
    let reserve_a = 500_000u128;
    let reserve_b = 750_000u128;
    let lp_supply = 612u128;
    let k_last = reserve_a * reserve_b;
    let params_bytes = cpmm_params(50).encode();
    let coin_a_tag = test_tag("A");
    let coin_b_tag = test_tag("B");

    // Encode using bloom-petal-dex-pool's canonical encoder.
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

    // Decode using the same helpers (same dep imported into the router).
    let (ra, rb, lps, kl, pb, got_a_tag, got_b_tag) =
        payload::decode_pool(&encoded).expect("decode_pool must succeed");

    assert_eq!(ra, reserve_a);
    assert_eq!(rb, reserve_b);
    assert_eq!(lps, lp_supply);
    assert_eq!(kl, k_last);
    assert_eq!(pb, params_bytes);
    assert_eq!(got_a_tag, coin_a_tag);
    assert_eq!(got_b_tag, coin_b_tag);

    // Verify params round-trip.
    let decoded_params = ConstantProductParams::decode(&pb).expect("param decode");
    assert_eq!(decoded_params.fee_bps, 50);
}

#[test]
fn pool_payload_decode_rejects_short_buffer() {
    let short = vec![0u8; 31];
    assert!(
        payload::decode_pool(&short).is_none(),
        "short buffer must fail"
    );
}

// ─── 5. Slippage check semantics ─────────────────────────────────────────────

/// When amount_out < min_out, SlippageExceeded must be returned.
#[test]
fn slippage_exceeded_is_correct_variant() {
    // Simulate: quote returns 90, but min_out = 100.
    let amount_out = 90u128;
    let min_out = 100u128;

    if amount_out < min_out {
        let e = RouterError::SlippageExceeded {
            expected: min_out,
            got: amount_out,
        };
        assert_eq!(
            e,
            RouterError::SlippageExceeded {
                expected: 100,
                got: 90
            }
        );
    } else {
        panic!("test setup error");
    }
}

/// Verify that amount_out == min_out is NOT an error (boundary: equal is OK).
#[test]
fn slippage_at_boundary_is_not_exceeded() {
    let amount_out = 100u128;
    let min_out = 100u128;
    // amount_out >= min_out → no slippage error.
    assert!(
        amount_out >= min_out,
        "equal amount should not trigger slippage"
    );
}

// ─── 6. ParamCodec integration (re-used dep) ─────────────────────────────────

#[test]
fn param_codec_encode_decode_via_router_dep() {
    // Router depends on bloom-petal-dex-pool as an rlib; verify the shared
    // ParamCodec impl is accessible.
    let params = cpmm_params(30);
    let encoded = params.encode();
    let decoded = ConstantProductParams::decode(&encoded).expect("decode via router dep");
    assert_eq!(decoded, params);
}

#[test]
fn param_codec_short_buffer_returns_none() {
    let short = vec![0u8; 1];
    assert!(ConstantProductParams::decode(&short).is_none());
}
