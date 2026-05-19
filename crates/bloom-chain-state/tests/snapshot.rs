//! Tests for the snapshot / commit / revert pattern.

use bloom_chain_state::{Account, State, StateError};
use bloom_chain_types::{Address, Hash32};

fn addr(b: u8) -> Address {
    Address([b; 32])
}

fn acct(loom: u128) -> Account {
    Account {
        nonce: 1,
        loom,
        code_hash: None,
        storage_root: Hash32([0u8; 32]),
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

    assert_eq!(state.get_account(&addr(1)).unwrap().loom, 100);
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
    assert_eq!(state.get_account(&addr(1)).unwrap().loom, 50);
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
    assert_eq!(state.get_account(&addr(1)).unwrap().loom, 100);

    // snap_b was taken at generation 0; now state is at 1 — should fail
    let result = state.apply(snap_b.commit());
    assert!(
        matches!(result, Err(StateError::StaleSnapshot)),
        "snap_b should be rejected as stale"
    );

    // State is unchanged after rejection
    assert_eq!(state.get_account(&addr(1)).unwrap().loom, 100);
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
    assert_eq!(snap.get_account(&addr(1)).unwrap().loom, 77);
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
    assert_eq!(snap.get_account(&addr(1)).unwrap().loom, 99);
    // Base state is unchanged
    assert_eq!(state.get_account(&addr(1)).unwrap().loom, 10);
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
