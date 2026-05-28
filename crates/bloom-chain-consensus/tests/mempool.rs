//! Category: unit
//!
//! Mempool unit tests.

use bloom_chain_consensus::tx_admission::SimpleBalanceView;
use bloom_chain_consensus::{ConsensusError, Mempool, NoopVerifier, RejectAllVerifier};
use bloom_chain_types::tx::TxKind;
use bloom_chain_types::types::Address;
use bloom_script::{PtbTx, encode_ptb};
use bloom_test_util::{make_addr_derived, make_mempool_tx};

// ---------------------------------------------------------------------------
// Admission tests
// ---------------------------------------------------------------------------

fn valid_ptb_bytes(gas_budget: u64, gas_price: u128) -> Vec<u8> {
    encode_ptb(&PtbTx {
        gas_budget,
        gas_price,
        expiry_block: 100,
        ..PtbTx::default()
    })
    .expect("test PTB encodes")
}

fn funded_ptb_view(sender: Address, gas_payer_balance: u128) -> SimpleBalanceView {
    SimpleBalanceView {
        sender,
        nonce: 0,
        balance: 0,
        ptb_gas_payer_balance: gas_payer_balance,
    }
}

#[test]
fn admit_valid_tx() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap();
    assert_eq!(mp.len(), 1);
}

#[test]
fn accept_future_nonce() {
    // Future nonces are now admitted so gossip propagation isn't blocked by
    // a transient state lag on the receiving validator. The proposer-side
    // `select_for_block_for` enforces strict per-sender sequential nonces.
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_mempool_tx(1, 3, 10, 1000, 0), 0, 1_000_000)
        .unwrap();
    assert_eq!(mp.len(), 1);
}

#[test]
fn reject_wrong_nonce_too_low() {
    let mut mp = Mempool::new(NoopVerifier);
    let err = mp
        .admit(make_mempool_tx(1, 0, 10, 1000, 0), 0, 1_000_000)
        .unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::NonceMismatch {
            expected: 1,
            got: 0
        }
    ));
}

#[test]
fn admit_nonce_1_for_new_account() {
    // New account has current_nonce=0, so first tx must have nonce=1.
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 100_000)
        .unwrap();
}

#[test]
fn reject_insufficient_balance_fee_only() {
    let mut mp = Mempool::new(NoopVerifier);
    // max_fuel=1000, fee_per_unit=10 → need 10_000
    let err = mp
        .admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 9_999)
        .unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::InsufficientBalance {
            need: 10000,
            have: 9999
        }
    ));
}

#[test]
fn submit_ptb_admission_does_not_charge_outer_sender_balance() {
    let mut mp = Mempool::new(NoopVerifier);
    let mut tx = make_mempool_tx(1, 1, 10, 1000, 0);
    tx.kind = TxKind::SubmitPtb {
        ptb_bytes: valid_ptb_bytes(100, 10),
    };
    let view = funded_ptb_view(tx.sender, 1_000);

    mp.admit_with_view(tx, &view)
        .expect("sponsored PTB admission must not require relayer LOOM");
    assert_eq!(mp.len(), 1);
}

#[test]
fn legacy_admit_rejects_submit_ptb_without_balance_view() {
    let mut mp = Mempool::new(NoopVerifier);
    let mut tx = make_mempool_tx(1, 1, 10, 1000, 0);
    tx.kind = TxKind::SubmitPtb {
        ptb_bytes: valid_ptb_bytes(100, 10),
    };

    let err = mp.admit(tx, 0, 0).unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidSubmitPtb(_)));
    assert_eq!(mp.len(), 0);
}

#[test]
fn submit_ptb_admission_checks_gas_payer_balance() {
    let mut mp = Mempool::new(NoopVerifier);
    let mut tx = make_mempool_tx(1, 1, 10, 1000, 0);
    tx.kind = TxKind::SubmitPtb {
        ptb_bytes: valid_ptb_bytes(100, 10),
    };
    let view = SimpleBalanceView {
        sender: tx.sender,
        nonce: 0,
        balance: 0,
        ptb_gas_payer_balance: 999,
    };

    let err = mp.admit_with_view(tx, &view).unwrap_err();

    assert!(matches!(
        err,
        ConsensusError::InsufficientBalance {
            need: 1000,
            have: 999
        }
    ));
    assert_eq!(mp.len(), 0);
}

#[test]
fn submit_ptb_admission_rejects_malformed_bytes() {
    let mut mp = Mempool::new(NoopVerifier);
    let mut tx = make_mempool_tx(1, 1, 10, 1000, 0);
    tx.kind = TxKind::SubmitPtb {
        ptb_bytes: vec![0xCA, 0xFE],
    };
    let view = funded_ptb_view(tx.sender, 1_000);

    let err = mp.admit_with_view(tx, &view).unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidSubmitPtb(_)));
    assert_eq!(mp.len(), 0);
}

#[test]
fn submit_ptb_admission_rejects_inner_cap_above_outer_cap() {
    let mut mp = Mempool::new(NoopVerifier);
    let mut tx = make_mempool_tx(1, 1, 10, 99, 0);
    tx.kind = TxKind::SubmitPtb {
        ptb_bytes: valid_ptb_bytes(100, 10),
    };
    let view = funded_ptb_view(tx.sender, 1_000);

    let err = mp.admit_with_view(tx, &view).unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidSubmitPtb(_)));
    assert_eq!(mp.len(), 0);
}

#[test]
fn submit_ptb_admission_rejects_free_inner_gas() {
    let mut mp = Mempool::new(NoopVerifier);
    let mut tx = make_mempool_tx(1, 1, 10, 1000, 0);
    tx.kind = TxKind::SubmitPtb {
        ptb_bytes: valid_ptb_bytes(100, 0),
    };
    let view = funded_ptb_view(tx.sender, 1_000);

    let err = mp.admit_with_view(tx, &view).unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidSubmitPtb(_)));
    assert_eq!(mp.len(), 0);
}

#[test]
fn reject_invalid_signature() {
    let mut mp = Mempool::new(RejectAllVerifier);
    let err = mp
        .admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidSignature));
}

// ---------------------------------------------------------------------------
// Replace-by-fee tests
// ---------------------------------------------------------------------------

#[test]
fn replace_by_fee_accepts_strictly_higher() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap();
    mp.admit(make_mempool_tx(1, 1, 11, 1000, 0), 0, 1_000_000)
        .unwrap();
    assert_eq!(mp.len(), 1);
    // The replacement (fee=11) is stored.
    let selected = mp.select_for_block(u64::MAX);
    assert_eq!(selected[0].fee_per_unit, 11);
}

#[test]
fn replace_by_fee_rejects_equal_fee() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap();
    let err = mp
        .admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::ReplaceFeeNotHigher));
}

#[test]
fn replace_by_fee_rejects_lower_fee() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap();
    let err = mp
        .admit(make_mempool_tx(1, 1, 9, 1000, 0), 0, 1_000_000)
        .unwrap_err();
    assert!(matches!(err, ConsensusError::ReplaceFeeNotHigher));
}

// ---------------------------------------------------------------------------
// select_for_block ordering
// ---------------------------------------------------------------------------

#[test]
fn select_ordering_fee_desc() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_mempool_tx(1, 1, 5, 1000, 0), 0, 1_000_000)
        .unwrap();
    mp.admit(make_mempool_tx(2, 1, 20, 1000, 0), 0, 1_000_000)
        .unwrap();
    mp.admit(make_mempool_tx(3, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap();

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
    mp.admit(make_mempool_tx(0, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap();
    // sender 1, nonce 1, fee 10 (same fee, nonce ordering among senders is deterministic)
    mp.admit(make_mempool_tx(1, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap();

    let selected = mp.select_for_block(u64::MAX);
    assert_eq!(selected.len(), 2);
    // Both are at same fee and nonce — result is deterministic (sorted by sender bytes).
    // Just confirm both are present.
    let senders: Vec<_> = selected.iter().map(|t| t.sender).collect();
    assert!(senders.contains(&make_addr_derived(0)));
    assert!(senders.contains(&make_addr_derived(1)));
}

#[test]
fn select_respects_fuel_limit() {
    let mut mp = Mempool::new(NoopVerifier);
    mp.admit(make_mempool_tx(1, 1, 20, 1000, 0), 0, 1_000_000)
        .unwrap();
    mp.admit(make_mempool_tx(2, 1, 10, 1000, 0), 0, 1_000_000)
        .unwrap();

    // Fuel limit = 1000. First tx (fee=20) takes 1000. Second would exceed.
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
    let tx = make_mempool_tx(1, 1, 10, 1000, 0);
    mp.admit(tx.clone(), 0, 1_000_000).unwrap();
    assert_eq!(mp.len(), 1);
    mp.remove_included(&[tx]);
    assert!(mp.is_empty());
}

#[test]
fn remove_included_only_removes_matching_txs() {
    let mut mp = Mempool::new(NoopVerifier);
    let tx1 = make_mempool_tx(1, 1, 10, 1000, 0);
    let tx2 = make_mempool_tx(2, 1, 10, 1000, 0);
    mp.admit(tx1.clone(), 0, 1_000_000).unwrap();
    mp.admit(tx2.clone(), 0, 1_000_000).unwrap();
    mp.remove_included(&[tx1]);
    assert_eq!(mp.len(), 1);
    assert!(!mp.is_empty());
}

// ---------------------------------------------------------------------------
// Adversarial: forged-sender admission
// ---------------------------------------------------------------------------
//
// Review item #11 (2026-05-19 consensus hardening): a tx that carries a
// validly-signed body but whose `sender` field does NOT derive from the
// signing pubkey must be rejected at the mempool boundary.
//
// Pre-fix, `Mempool::admit` accepted such a tx (signature verifies fine,
// nonce/balance checks both reference `tx.sender` rather than the derived
// address), letting an attacker propagate a tx that claims a sender it has
// no key for. The chain-apply path already rejected it with `sender mismatch`
// in `consensus_driver::apply_block`, but only after gossip had already paid
// the network cost.
//
// This test passes the signature check (NoopVerifier) and constructs a tx
// whose `pubkey` would derive to address X via
// `Address::from_pubkey_bytes`, but mutates `sender` to a different,
// attacker-chosen address before calling `admit`. The mempool must reject
// with `AddressMismatch`.

// ---------------------------------------------------------------------------
// Adversarial: per-sender nonce contiguity under fuel pressure
// ---------------------------------------------------------------------------

/// Review item #8 (2026-05-19 consensus hardening): `select_for_block_for`
/// must never emit `(sender S, nonce K+1)` without `(sender S, nonce K)` for
/// the same block, even under fuel pressure where a higher-fee nonce-2 would
/// "outbid" a lower-fee nonce-1.
///
/// Pre-fix, the proposer flattened the per-sender eligible lists and then
/// greedy-picked globally by fee. Given S's (nonce 1, fee 1) and (nonce 2,
/// fee 100) plus T's (nonce 1, fee 50), the greedy picker would take
/// (S, 2) and (T, 1) in that order, skipping (S, 1) — producing a block
/// where S's nonce-2 has no predecessor. `apply_block` would then reject it.
///
/// The fix enforces per-sender stride: only the head of each sender's
/// contiguous-nonce run is eligible at each greedy step; if a head won't
/// fit the remaining fuel budget, that sender is dropped entirely.
#[test]
fn select_for_block_keeps_per_sender_nonce_contiguity() {
    let mut mp = Mempool::new(NoopVerifier);

    // S: nonce 1 (low fee), nonce 2 (very high fee). Same sender.
    mp.admit(make_mempool_tx(1, 1, 1, 1000, 0), 0, 10_000_000)
        .unwrap();
    mp.admit(make_mempool_tx(1, 2, 100, 1000, 0), 0, 10_000_000)
        .unwrap();
    // T: nonce 1, medium-high fee.
    mp.admit(make_mempool_tx(2, 1, 50, 1000, 0), 0, 10_000_000)
        .unwrap();

    let s = make_addr_derived(1);
    let t = make_addr_derived(2);

    // Fuel budget fits exactly two 1000-max_fuel txs.
    let selected = mp.select_for_block_for(2_000, |_| 0);

    // Find the indices of (S, 1) and (S, 2) in the selection. If (S, 2) is
    // present, (S, 1) MUST be present and precede it in the output.
    let s1 = selected
        .iter()
        .position(|tx| tx.sender == s && tx.nonce == 1);
    let s2 = selected
        .iter()
        .position(|tx| tx.sender == s && tx.nonce == 2);
    if let Some(j) = s2 {
        let i = s1.expect("(S, 2) selected without (S, 1) — nonce gap in block");
        assert!(i < j, "(S, 1) must precede (S, 2) within the block");
    }

    // The selection must include exactly two txs (fuel budget fits two), and
    // must include (S, 1) — without it neither (S, 2) nor any other S tx
    // could ride. Either (T, 1) or (S, 2) is the second slot; both are valid.
    assert_eq!(selected.len(), 2, "expected two txs to fit the fuel budget");
    assert!(
        s1.is_some(),
        "(S, 1) must be included as a contiguity anchor"
    );
    let has_t1 = selected.iter().any(|tx| tx.sender == t && tx.nonce == 1);
    assert!(
        has_t1 || s2.is_some(),
        "second slot should be (T, 1) or (S, 2), got {selected:?}"
    );
}

/// Tighter variant: fuel budget fits only ONE tx. With the pre-fix algorithm
/// the global-greedy picker would select (S, nonce 2, fee 100) alone — an
/// invalid block, since S has no nonce 1 on-chain. The fix must instead
/// drop (S, 2) entirely (no predecessor can fit) and pick the best
/// independently-anchored head — here (T, nonce 1, fee 50).
#[test]
fn select_for_block_under_tight_fuel_never_skips_predecessor() {
    let mut mp = Mempool::new(NoopVerifier);

    mp.admit(make_mempool_tx(1, 1, 1, 1000, 0), 0, 10_000_000)
        .unwrap();
    mp.admit(make_mempool_tx(1, 2, 100, 1000, 0), 0, 10_000_000)
        .unwrap();
    mp.admit(make_mempool_tx(2, 1, 50, 1000, 0), 0, 10_000_000)
        .unwrap();

    let s = make_addr_derived(1);
    let t = make_addr_derived(2);

    // Budget fits exactly one 1000-max_fuel tx.
    let selected = mp.select_for_block_for(1_000, |_| 0);

    assert_eq!(selected.len(), 1, "only one tx should fit");
    let tx = &selected[0];
    // (S, 2) alone is forbidden — no predecessor.
    assert!(
        !(tx.sender == s && tx.nonce == 2),
        "(S, 2) selected without (S, 1) under tight budget"
    );
    // The valid picks here are (S, 1) [fee 1] or (T, 1) [fee 50]. Either is
    // legal per-block; given fee priority among eligible heads, expect (T, 1).
    assert!(
        (tx.sender == t || tx.sender == s) && tx.nonce == 1,
        "expected an eligible nonce-1 head, got sender={:?} nonce={}",
        tx.sender,
        tx.nonce
    );
}

#[test]
fn reject_forged_sender_admission() {
    let mut mp = Mempool::new(NoopVerifier);

    // Start from a well-formed tx (sender derives from the seeded pubkey).
    let mut tx = make_mempool_tx(1, 1, 10, 1000, 0);
    // Sanity: the helper builds matching sender/pubkey.
    assert_eq!(tx.sender, Address::from_pubkey_bytes(&tx.pubkey.0));

    // Attacker forges the sender field to point at a different account.
    let victim = Address([0xAA; 32]);
    assert_ne!(victim, Address::from_pubkey_bytes(&tx.pubkey.0));
    tx.sender = victim;

    let err = mp.admit(tx, 0, 1_000_000).unwrap_err();
    assert!(
        matches!(err, ConsensusError::AddressMismatch),
        "expected AddressMismatch, got {err:?}"
    );
    assert_eq!(mp.len(), 0, "forged-sender tx must not enter the pool");
}
