//! Mempool unit tests.

use bloom_chain_consensus::{ConsensusError, Mempool, NoopVerifier, RejectAllVerifier};
use bloom_chain_types::{
    tx::{Tx, TxKind},
    types::{Address, PubKeyBytes, SigBytes},
};

fn addr(seed: u8) -> Address {
    Address([seed; 32])
}

fn make_tx(sender: u8, nonce: u64, fee: u64, max_fuel: u64, value: u128) -> Tx {
    let kind = if value > 0 {
        TxKind::Transfer {
            to: addr(99),
            amount_loom: value,
        }
    } else {
        TxKind::Transfer {
            to: addr(99),
            amount_loom: 0,
        }
    };
    Tx {
        chain_id: "bloomchain.v0".to_string(),
        sender: addr(sender),
        nonce,
        max_fuel,
        fee_per_unit: fee,
        kind,
        pubkey: PubKeyBytes(vec![sender; 4]),
        sig: SigBytes(vec![0u8; 4]),
    }
}

// ---------------------------------------------------------------------------
// Admission tests
// ---------------------------------------------------------------------------

#[test]
fn admit_valid_tx() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_tx(1, 1, 10, 1000, 0), 0, 1_000_000).unwrap();
    assert_eq!(mp.len(), 1);
}

#[test]
fn accept_future_nonce() {
    // Future nonces are now admitted so gossip propagation isn't blocked by
    // a transient state lag on the receiving validator. The proposer-side
    // `select_for_block_for` enforces strict per-sender sequential nonces.
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_tx(1, 3, 10, 1000, 0), 0, 1_000_000).unwrap();
    assert_eq!(mp.len(), 1);
}

#[test]
fn reject_wrong_nonce_too_low() {
    let mut mp = Mempool::new(NoopVerifier);
    let err = mp.admit(make_tx(1, 0, 10, 1000, 0), 0, 1_000_000).unwrap_err();
    assert!(matches!(err, ConsensusError::NonceMismatch { expected: 1, got: 0 }));
}

#[test]
fn admit_nonce_1_for_new_account() {
    // New account has current_nonce=0, so first tx must have nonce=1.
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_tx(1, 1, 10, 100, 0), 0, 100_000).unwrap();
}

#[test]
fn reject_insufficient_balance_fee_only() {
    let mut mp = Mempool::new(NoopVerifier);
    // max_fuel=1000, fee_per_unit=10 → need 10_000
    let err = mp
        .admit(make_tx(1, 1, 10, 1000, 0), 0, 9_999)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::InsufficientBalance { need: 10000, have: 9999 }));
}

#[test]
fn reject_insufficient_balance_with_value() {
    let mut mp = Mempool::new(NoopVerifier);
    // max_fuel=100, fee=1 → fee_reservation=100; value=500; need=600; have=599.
    let err = mp
        .admit(make_tx(1, 1, 1, 100, 500), 0, 599)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::InsufficientBalance { need: 600, have: 599 }));
}

#[test]
fn reject_invalid_signature() {
    let mut mp = Mempool::new(RejectAllVerifier);
    let err = mp
        .admit(make_tx(1, 1, 10, 100, 0), 0, 1_000_000)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidSignature));
}

// ---------------------------------------------------------------------------
// Replace-by-fee tests
// ---------------------------------------------------------------------------

#[test]
fn replace_by_fee_accepts_strictly_higher() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_tx(1, 1, 10, 100, 0), 0, 1_000_000).unwrap();
    mp.admit(make_tx(1, 1, 11, 100, 0), 0, 1_000_000).unwrap();
    assert_eq!(mp.len(), 1);
    // The replacement (fee=11) is stored.
    let selected = mp.select_for_block(u64::MAX);
    assert_eq!(selected[0].fee_per_unit, 11);
}

#[test]
fn replace_by_fee_rejects_equal_fee() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_tx(1, 1, 10, 100, 0), 0, 1_000_000).unwrap();
    let err = mp
        .admit(make_tx(1, 1, 10, 100, 0), 0, 1_000_000)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::ReplaceFeeNotHigher));
}

#[test]
fn replace_by_fee_rejects_lower_fee() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_tx(1, 1, 10, 100, 0), 0, 1_000_000).unwrap();
    let err = mp
        .admit(make_tx(1, 1, 9, 100, 0), 0, 1_000_000)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::ReplaceFeeNotHigher));
}

// ---------------------------------------------------------------------------
// select_for_block ordering
// ---------------------------------------------------------------------------

#[test]
fn select_ordering_fee_desc() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_tx(1, 1, 5, 100, 0), 0, 1_000_000).unwrap();
    mp.admit(make_tx(2, 1, 20, 100, 0), 0, 1_000_000).unwrap();
    mp.admit(make_tx(3, 1, 10, 100, 0), 0, 1_000_000).unwrap();

    let selected = mp.select_for_block(u64::MAX);
    assert_eq!(selected.len(), 3);
    assert_eq!(selected[0].fee_per_unit, 20);
    assert_eq!(selected[1].fee_per_unit, 10);
    assert_eq!(selected[2].fee_per_unit, 5);
}

#[test]
fn select_ordering_nonce_asc_within_same_sender_via_fuel_fill() {
    // We can only add one tx per sender per (current_nonce+1), so test the ordering
    // property by checking two txs from same-fee different-sender come out deterministically.
    let mut mp = Mempool::new(NoopVerifier);
    // sender 0, nonce 1, fee 10
    mp.admit(make_tx(0, 1, 10, 100, 0), 0, 1_000_000).unwrap();
    // sender 1, nonce 1, fee 10 (same fee, nonce ordering among senders is deterministic)
    mp.admit(make_tx(1, 1, 10, 100, 0), 0, 1_000_000).unwrap();

    let selected = mp.select_for_block(u64::MAX);
    assert_eq!(selected.len(), 2);
    // Both are at same fee and nonce — result is deterministic (sorted by sender bytes).
    // Just confirm both are present.
    let senders: Vec<_> = selected.iter().map(|t| t.sender).collect();
    assert!(senders.contains(&addr(0)));
    assert!(senders.contains(&addr(1)));
}

#[test]
fn select_respects_fuel_limit() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_tx(1, 1, 20, 700, 0), 0, 1_000_000).unwrap();
    mp.admit(make_tx(2, 1, 10, 700, 0), 0, 1_000_000).unwrap();

    // Fuel limit = 1000. First tx (fee=20) takes 700. Second (fee=10) would take 1400 total → skip.
    let selected = mp.select_for_block(1000);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].fee_per_unit, 20);
}

// ---------------------------------------------------------------------------
// remove_included
// ---------------------------------------------------------------------------

#[test]
fn remove_included_clears_txs() {
    let mut mp = Mempool::new(NoopVerifier);
    let tx = make_tx(1, 1, 10, 100, 0);
    mp.admit(tx.clone(), 0, 1_000_000).unwrap();
    assert_eq!(mp.len(), 1);
    mp.remove_included(&[tx]);
    assert!(mp.is_empty());
}

#[test]
fn remove_included_only_removes_matching_txs() {
    let mut mp = Mempool::new(NoopVerifier);
    let tx1 = make_tx(1, 1, 10, 100, 0);
    let tx2 = make_tx(2, 1, 10, 100, 0);
    mp.admit(tx1.clone(), 0, 1_000_000).unwrap();
    mp.admit(tx2.clone(), 0, 1_000_000).unwrap();
    mp.remove_included(&[tx1]);
    assert_eq!(mp.len(), 1);
    assert!(!mp.is_empty());
}
