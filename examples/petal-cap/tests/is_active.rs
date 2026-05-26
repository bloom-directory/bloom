//! Predicate tests for `Cap<T>::is_active`.
//!
//! Spec §18: a cap is active when not revoked AND its inner kind reports
//! "currently honouring" at the given block. We test the pure-logic
//! helper (`is_active_logic`) rather than the petal-wrapped fn so we
//! avoid needing to construct a `Cap<T>` from outside the petal (its
//! fields are intentionally private to the petal body).

use bloom_petal_cap::{INNER_KIND_EXPIRE_AT, INNER_KIND_LOCKED, INNER_KIND_OPEN, is_active_logic};

#[test]
fn is_active_open() {
    assert!(is_active_logic(INNER_KIND_OPEN, 0, false, 0));
    assert!(is_active_logic(INNER_KIND_OPEN, 0, false, u64::MAX));
}

#[test]
fn is_active_locked_always_false() {
    assert!(!is_active_logic(INNER_KIND_LOCKED, 0, false, 0));
    assert!(!is_active_logic(INNER_KIND_LOCKED, 0, false, u64::MAX));
    // Even a non-zero `expires_at_block` doesn't unlock a locked cap.
    assert!(!is_active_logic(INNER_KIND_LOCKED, 9_999, false, 5));
}

#[test]
fn is_active_expire_at_before_expiry() {
    assert!(is_active_logic(INNER_KIND_EXPIRE_AT, 100, false, 0));
    assert!(is_active_logic(INNER_KIND_EXPIRE_AT, 100, false, 99));
}

#[test]
fn is_active_expire_at_after_expiry() {
    assert!(!is_active_logic(INNER_KIND_EXPIRE_AT, 100, false, 100));
    assert!(!is_active_logic(
        INNER_KIND_EXPIRE_AT,
        100,
        false,
        1_000_000
    ));
}

#[test]
fn is_active_revoked_short_circuits() {
    // A revoked cap is inactive regardless of kind / block.
    assert!(!is_active_logic(INNER_KIND_OPEN, 0, true, 0));
    assert!(!is_active_logic(INNER_KIND_LOCKED, 0, true, 0));
    assert!(!is_active_logic(INNER_KIND_EXPIRE_AT, u64::MAX, true, 0));
}

#[test]
fn is_active_unknown_kind_is_inactive() {
    // Any unrecognized inner_kind is treated as inactive (fail-safe).
    for kind in [3u8, 7, 42, 255] {
        assert!(!is_active_logic(kind, 0, false, 0));
    }
}
