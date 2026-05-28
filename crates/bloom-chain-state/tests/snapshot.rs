//! Category: integration
//!
//! Tests for the snapshot / commit / revert pattern.

use bloom_chain_state::{Account, State, StateError};
use bloom_chain_types::{Address, Hash32};

fn addr(b: u8) -> Address {
    Address([b; 32])
}

fn acct(nonce: u64) -> Account {
    Account {
        nonce,
        code_hash: None,
        storage_root: Hash32([0u8; 32]),
        manifest_hash: None,
    }
}

// ---------------------------------------------------------------------------
// Snapshot → write → commit applies
// ---------------------------------------------------------------------------

#[test]
fn commit_applies_writes() {
    let mut state = State::new();

    let mut snap = state.snapshot();
    snap.set_account(addr(1), acct(100));
    snap.storage_write(addr(2), [5u8; 32], [7u8; 32]);

    state.apply(snap.commit()).expect("apply should succeed");

    assert_eq!(state.get_account(&addr(1)).unwrap().nonce, 100);
    assert_eq!(state.storage_read(&addr(2), &[5u8; 32]), [7u8; 32]);
    assert_eq!(state.generation(), 1);
}

// ---------------------------------------------------------------------------
// Revert discards writes
// ---------------------------------------------------------------------------

#[test]
fn revert_discards_writes() {
    let mut state = State::new();
    state.set_account(addr(1), acct(50));

    let mut snap = state.snapshot();
    snap.set_account(addr(1), acct(9999));
    snap.revert();

    // Live state is unchanged
    assert_eq!(state.get_account(&addr(1)).unwrap().nonce, 50);
    assert_eq!(state.generation(), 0);
}

// ---------------------------------------------------------------------------
// Two parallel snapshots do not interfere; second's commit fails after first
// ---------------------------------------------------------------------------

#[test]
fn parallel_snapshots_do_not_interfere() {
    let mut state = State::new();
    state.set_account(addr(1), acct(10));

    let mut snap_a = state.snapshot();
    let mut snap_b = state.snapshot();

    snap_a.set_account(addr(1), acct(100));
    snap_b.set_account(addr(1), acct(200));

    // Apply snap_a first — generation 0 → 1
    state.apply(snap_a.commit()).expect("snap_a should apply");
    assert_eq!(state.get_account(&addr(1)).unwrap().nonce, 100);

    // snap_b was taken at generation 0; now state is at 1 — should fail
    let result = state.apply(snap_b.commit());
    assert!(
        matches!(result, Err(StateError::StaleSnapshot)),
        "snap_b should be rejected as stale"
    );

    // State is unchanged after rejection
    assert_eq!(state.get_account(&addr(1)).unwrap().nonce, 100);
    assert_eq!(state.generation(), 1);
}

// ---------------------------------------------------------------------------
// Snapshot reads through to base state
// ---------------------------------------------------------------------------

#[test]
fn snapshot_reads_through_base() {
    let mut state = State::new();
    state.set_account(addr(1), acct(77));

    let snap = state.snapshot();
    assert_eq!(snap.get_account(&addr(1)).unwrap().nonce, 77);
}

// ---------------------------------------------------------------------------
// Snapshot staged reads shadow base
// ---------------------------------------------------------------------------

#[test]
fn snapshot_staged_read_shadows_base() {
    let mut state = State::new();
    state.set_account(addr(1), acct(10));

    let mut snap = state.snapshot();
    snap.set_account(addr(1), acct(99));

    // Snap should return staged value, not base
    assert_eq!(snap.get_account(&addr(1)).unwrap().nonce, 99);
    // Base state is unchanged
    assert_eq!(state.get_account(&addr(1)).unwrap().nonce, 10);
}

// ---------------------------------------------------------------------------
// Storage snapshot round-trip
// ---------------------------------------------------------------------------

#[test]
fn storage_snapshot_roundtrip() {
    let mut state = State::new();
    state.storage_write(addr(3), [1u8; 32], [0xAB; 32]);

    let mut snap = state.snapshot();
    // Read through
    assert_eq!(snap.storage_read(&addr(3), &[1u8; 32]), [0xAB; 32]);

    // Stage a change
    snap.storage_write(addr(3), [1u8; 32], [0xCD; 32]);
    assert_eq!(snap.storage_read(&addr(3), &[1u8; 32]), [0xCD; 32]);

    state.apply(snap.commit()).unwrap();
    assert_eq!(state.storage_read(&addr(3), &[1u8; 32]), [0xCD; 32]);
}

// ---------------------------------------------------------------------------
// Empty-account writes in snapshot auto-remove
// ---------------------------------------------------------------------------

#[test]
fn snapshot_empty_account_removes_entry() {
    let mut state = State::new();
    state.set_account(addr(1), acct(500));

    let mut snap = state.snapshot();
    snap.set_account(addr(1), Account::empty());

    state.apply(snap.commit()).unwrap();
    assert_eq!(state.get_account(&addr(1)), None);
}

// ---------------------------------------------------------------------------
// Staged code is visible via get_code within the same snapshot (review #14).
//
// Regression test for the "same-tx deploy-then-call" bug: code inserted with
// `StateSnapshot::insert_code` must be retrievable by `StateSnapshot::get_code`
// *before* the write set has been committed to the base state, so that a tx
// can deploy a petal and then immediately invoke a method on it (or have its
// init self-call) within the same execution frame.
// ---------------------------------------------------------------------------

#[test]
fn snapshot_get_code_sees_staged_insert() {
    let state = State::new();
    let mut snap = state.snapshot();

    let wasm = b"fake wasm bytes for staged-code test".to_vec();
    let hash = snap.insert_code(wasm.clone());

    // Before commit: staged code must be readable via the snapshot.
    let fetched = snap
        .get_code(&hash)
        .expect("staged code must be visible via snapshot");
    assert_eq!(
        fetched,
        wasm.as_slice(),
        "staged code bytes must round-trip"
    );
}

#[test]
fn snapshot_staged_code_does_not_leak_to_base() {
    // A snapshot that stages new code must NOT mutate the underlying base
    // state until the write set is applied — staged deploys are tx-scoped.
    let state = State::new();
    let mut snap = state.snapshot();
    let wasm = b"another fake wasm".to_vec();
    let hash = snap.insert_code(wasm);

    // The base state has no record of this code.
    assert!(
        state.get_code(&hash).is_none(),
        "staged code must not leak into base state"
    );
}

#[test]
fn parallel_snapshots_do_not_share_staged_code() {
    // Two independent snapshots taken at the same height must not see each
    // other's staged code — preserving the snapshot invariant that future-tx
    // pending deploys never bleed into a concurrent snapshot.
    let state = State::new();
    let mut snap_a = state.snapshot();
    let snap_b = state.snapshot();

    let wasm_a = b"snap-a wasm".to_vec();
    let hash_a = snap_a.insert_code(wasm_a);

    // snap_b must NOT see snap_a's staged code.
    assert!(
        snap_b.get_code(&hash_a).is_none(),
        "staged code in snap_a must not be visible to snap_b"
    );
}

#[test]
fn committed_code_is_visible_to_new_snapshots() {
    // After commit, the staged code lives in the base store and any newly
    // taken snapshot sees it.
    let mut state = State::new();
    let mut snap = state.snapshot();
    let wasm = b"persisted wasm".to_vec();
    let hash = snap.insert_code(wasm.clone());
    state.apply(snap.commit()).unwrap();

    let snap2 = state.snapshot();
    assert_eq!(snap2.get_code(&hash), Some(wasm.as_slice()));
}
