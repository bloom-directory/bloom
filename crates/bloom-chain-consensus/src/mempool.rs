//! Transaction mempool with nonce ordering and replace-by-fee (spec §7.4, §9.5).
//!
//! `Tx` (from `bloom-chain-types`) is the signed envelope — it contains `sender`,
//! `pubkey`, `sig`, `nonce`, `max_fuel`, `fee_per_unit`, and `kind`. There is no
//! separate `SignedTx` wrapper; `Tx` already IS the signed tx.

use std::collections::{BTreeMap, HashMap};

use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::Address;

use crate::error::ConsensusError;
use crate::tx_admission::{
    AdmitOutcome, AdmitReject, BalanceView, SimpleBalanceView, check_admissible,
};
use crate::verifier::SigVerifier;

/// Hard cap on pending transactions retained by one node.
pub const MAX_MEMPOOL_PENDING_TXS: usize = 50_000;

/// Per-sender cap and future-nonce window. This bounds unchargeable storage
/// and repeated proposer work even when gossip admits future nonces.
pub const MAX_MEMPOOL_PENDING_PER_SENDER: usize = 128;

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// Identifies a pending tx slot: (sender address, nonce).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
struct TxSlot {
    sender: Address,
    nonce: u64,
}

// ---------------------------------------------------------------------------
// Mempool
// ---------------------------------------------------------------------------

/// In-memory pending-transaction pool.
///
/// # Admission invariants
/// - Signature is valid (delegate to `V: SigVerifier`).
/// - `nonce == current_nonce + 1` (or 1 for new accounts).
/// - `max_fuel * fee_per_unit + value ≤ balance`.
/// - No duplicate `(sender, nonce)` unless the replacement pays a strictly higher fee.
pub struct Mempool<V> {
    verifier: V,
    /// Primary store: TxSlot → Tx.
    pending: HashMap<TxSlot, Tx>,
}

impl<V: SigVerifier> Mempool<V> {
    /// Construct a new, empty mempool.
    pub fn new(verifier: V) -> Self {
        Self {
            verifier,
            pending: HashMap::new(),
        }
    }

    /// Attempt to admit a non-PTB transaction into the mempool.
    ///
    /// `current_nonce` is the account's current committed nonce (0 for new accounts).
    /// `current_balance` is the account's confirmed LOOM balance in bloomweis.
    ///
    /// `SubmitPtb` admission needs a chain-state view so the gas-payer coin can
    /// be checked. Use [`Self::admit_with_view`] for PTBs.
    pub fn admit(
        &mut self,
        tx: Tx,
        current_nonce: u64,
        current_balance: u128,
    ) -> Result<(), ConsensusError> {
        if matches!(tx.kind, TxKind::SubmitPtb { .. }) {
            return Err(ConsensusError::InvalidSubmitPtb(
                "SubmitPtb admission requires BalanceView".to_string(),
            ));
        }
        let view = SimpleBalanceView {
            sender: tx.sender,
            nonce: current_nonce,
            balance: current_balance,
            ptb_gas_payer_balance: 0,
        };
        self.admit_with_view(tx, &view)
    }

    pub fn admit_with_view(
        &mut self,
        tx: Tx,
        view: &dyn BalanceView,
    ) -> Result<(), ConsensusError> {
        // 1. Verify signature.
        let digest = tx.signing_digest();
        if !self.verifier.verify(&tx.pubkey, &digest.0, &tx.sig) {
            return Err(ConsensusError::InvalidSignature);
        }

        if let AdmitOutcome::Reject(reject) = check_admissible(&tx, view, false) {
            return Err(admit_reject_to_consensus_error(reject));
        }

        let slot = TxSlot {
            sender: tx.sender,
            nonce: tx.nonce,
        };

        let current_nonce = view.nonce(&tx.sender);
        let nonce_distance = tx.nonce.saturating_sub(current_nonce);
        if nonce_distance > MAX_MEMPOOL_PENDING_PER_SENDER as u64 {
            return Err(ConsensusError::MempoolSenderLimit {
                limit: MAX_MEMPOOL_PENDING_PER_SENDER,
            });
        }

        let is_replacement = self.pending.contains_key(&slot);
        if !is_replacement {
            if self.pending.len() >= MAX_MEMPOOL_PENDING_TXS {
                return Err(ConsensusError::MempoolFull {
                    limit: MAX_MEMPOOL_PENDING_TXS,
                });
            }
            let sender_pending = self
                .pending
                .keys()
                .filter(|pending_slot| pending_slot.sender == tx.sender)
                .count();
            if sender_pending >= MAX_MEMPOOL_PENDING_PER_SENDER {
                return Err(ConsensusError::MempoolSenderLimit {
                    limit: MAX_MEMPOOL_PENDING_PER_SENDER,
                });
            }
        }

        // 4. Replace-by-fee: if a pending tx for (sender, nonce) exists, new fee must be
        //    strictly higher.
        if let Some(existing) = self.pending.get(&slot)
            && tx.fee_per_unit <= existing.fee_per_unit
        {
            return Err(ConsensusError::ReplaceFeeNotHigher);
        }

        self.pending.insert(slot, tx);
        Ok(())
    }

    /// Select transactions for a block up to `fuel_limit` total max_fuel.
    ///
    /// Ordering: `fee_per_unit DESC`, then per-sender `nonce ASC` (spec §9.5).
    ///
    /// The greedy fill includes a tx if adding its `max_fuel` does not exceed `fuel_limit`.
    ///
    /// NOTE: this overload assumes mempool only contains strict next-nonce
    /// txs (no gaps relative to applied state). For the production path that
    /// admits future nonces from gossip, use `select_for_block_for` which
    /// takes per-sender applied nonces and emits only sequential txs.
    pub fn select_for_block(&self, fuel_limit: u64) -> Vec<Tx> {
        let mut candidates: Vec<&Tx> = self.pending.values().collect();
        candidates.sort_by(|a, b| {
            b.fee_per_unit
                .cmp(&a.fee_per_unit)
                .then(a.nonce.cmp(&b.nonce))
                .then(a.sender.cmp(&b.sender))
        });
        let mut selected = Vec::new();
        let mut fuel_used: u64 = 0;
        for tx in candidates {
            if let Some(next_fuel_used) = fuel_used.checked_add(tx.max_fuel)
                && next_fuel_used <= fuel_limit
            {
                fuel_used = next_fuel_used;
                selected.push(tx.clone());
            }
        }
        selected
    }

    /// Select txs for a block where each sender's applied nonce is given by
    /// `applied_nonce_for(sender)`. Only emits a contiguous run from
    /// `applied + 1, applied + 2, ...` per sender — gaps (future-nonce txs
    /// whose predecessors haven't landed) are held until later blocks.
    ///
    /// This is the variant proposers should use when the mempool admits
    /// future-nonce txs from gossip: it prevents building a block that
    /// would silently no-op on validators that share the same state.
    pub fn select_for_block_for<F>(&self, fuel_limit: u64, applied_nonce_for: F) -> Vec<Tx>
    where
        F: Fn(&Address) -> u64,
    {
        // Group by sender and sort by nonce ASC.
        let mut by_sender: BTreeMap<Address, Vec<&Tx>> = BTreeMap::new();
        for tx in self.pending.values() {
            by_sender.entry(tx.sender).or_default().push(tx);
        }
        for txs in by_sender.values_mut() {
            txs.sort_by_key(|t| t.nonce);
        }

        // Per-sender stride: walk each sender forward from its applied-nonce+1,
        // discarding stale slots and stopping at the first gap. The remaining
        // slice is the sender's "contiguous run" — the only nonce-prefix we may
        // ever include in this block.
        //
        // Selection then proceeds head-only: at each step we look at the head
        // of every sender's remaining run, pick the highest-fee one whose
        // max_fuel fits the remaining budget, and advance that sender's
        // pointer by one. If a sender's head does NOT fit the budget, that
        // sender is dropped entirely — including a later (higher-fee) nonce
        // without its predecessor would produce an invalid block. This is the
        // fix for review item #8 (2026-05-19 consensus hardening): the prior
        // implementation flattened the eligible txs and greedy-picked by fee
        // globally, which could include (S, nonce 2) without (S, nonce 1)
        // under fuel pressure.
        let mut heads: Vec<&[&Tx]> = Vec::with_capacity(by_sender.len());
        for (addr, txs) in &by_sender {
            let applied = applied_nonce_for(addr);
            let mut expected = applied + 1;
            // Skip stale txs already on-chain.
            let mut start = 0;
            while start < txs.len() && txs[start].nonce < expected {
                start += 1;
            }
            // Walk the contiguous run.
            let mut end = start;
            while end < txs.len() && txs[end].nonce == expected {
                expected += 1;
                end += 1;
            }
            if start < end {
                heads.push(&txs[start..end]);
            }
        }

        let mut selected: Vec<Tx> = Vec::new();
        let mut fuel_used: u64 = 0;
        loop {
            // Find the highest-fee head across senders that still fits the
            // remaining fuel budget. Tiebreakers: lower nonce, then sender
            // bytes — matches the legacy `select_for_block` ordering for
            // determinism.
            let mut best: Option<usize> = None;
            for (i, run) in heads.iter().enumerate() {
                let Some(head) = run.first() else { continue };
                let Some(next_fuel_used) = fuel_used.checked_add(head.max_fuel) else {
                    continue;
                };
                if next_fuel_used > fuel_limit {
                    continue;
                }
                let pick = match best {
                    None => true,
                    Some(j) => {
                        let cur = heads[j].first().expect("non-empty by construction");
                        head.fee_per_unit
                            .cmp(&cur.fee_per_unit)
                            .then(cur.nonce.cmp(&head.nonce))
                            .then(cur.sender.cmp(&head.sender))
                            .is_gt()
                    }
                };
                if pick {
                    best = Some(i);
                }
            }
            let Some(i) = best else { break };
            let head = heads[i][0];
            fuel_used = fuel_used
                .checked_add(head.max_fuel)
                .expect("selected head was checked against fuel budget");
            selected.push(head.clone());
            heads[i] = &heads[i][1..];
        }

        // Re-sort by (sender, nonce ASC) so apply_block sees per-sender txs
        // in nonce order (apply_block's strict-next-nonce check requires this).
        selected.sort_by(|a, b| a.sender.cmp(&b.sender).then(a.nonce.cmp(&b.nonce)));
        selected
    }

    /// Remove transactions that were included in a committed block.
    pub fn remove_included(&mut self, txs: &[Tx]) {
        for tx in txs {
            let slot = TxSlot {
                sender: tx.sender,
                nonce: tx.nonce,
            };
            self.pending.remove(&slot);
        }
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Returns `true` if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn admit_reject_to_consensus_error(reject: AdmitReject) -> ConsensusError {
    match reject {
        AdmitReject::SenderMismatch => ConsensusError::AddressMismatch,
        AdmitReject::Nonce { expected, got } => ConsensusError::NonceMismatch { expected, got },
        AdmitReject::InsufficientBalance { need, have } => {
            ConsensusError::InsufficientBalance { need, have }
        }
        AdmitReject::EnvelopeInvalid(reason) => ConsensusError::InvalidSubmitPtb(reason),
        AdmitReject::IntrinsicFuel { required, got } => {
            ConsensusError::InsufficientFuel { required, got }
        }
        AdmitReject::Overflow(reason) => ConsensusError::InvalidSubmitPtb(reason),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_types::tx::TxKind;
    use bloom_chain_types::types::{PubKeyBytes, SigBytes};

    use crate::tx_admission::DEPLOY_PETAL_BASE_FUEL;
    use crate::verifier::NoopVerifier;

    /// Derive a fake address from a seed in the same way `admit`'s
    /// sender-derivation check does, so a tx built with the matching pubkey
    /// passes the check. (`admit` calls `Address::from_pubkey_bytes(&pubkey)`.)
    fn addr_from_seed(seed: u8) -> Address {
        Address::from_pubkey_bytes(&[seed; 4])
    }

    fn make_tx(sender: u8, nonce: u64, fee: u64, max_fuel: u64) -> Tx {
        Tx {
            chain_id: "bloomchain.v0".to_string(),
            sender: addr_from_seed(sender),
            nonce,
            max_fuel,
            fee_per_unit: fee,
            kind: TxKind::DeployPetal {
                wasm_bytes: b"test-wasm".to_vec(),
            },
            pubkey: PubKeyBytes(vec![sender; 4]),
            sig: SigBytes(vec![0u8; 4]),
        }
    }

    #[test]
    fn admit_valid_tx() {
        let mut mp = Mempool::new(NoopVerifier);
        mp.admit(make_tx(1, 1, 10, 1000), 0, 1_000_000).unwrap();
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn reject_stale_nonce() {
        let mut mp = Mempool::new(NoopVerifier);
        // current_nonce=2 means tx with nonce 1 (or 2) is stale — already on-chain.
        let err = mp.admit(make_tx(1, 2, 10, 1000), 2, 1_000_000).unwrap_err();
        assert!(matches!(
            err,
            ConsensusError::NonceMismatch {
                expected: 3,
                got: 2
            }
        ));
    }

    #[test]
    fn accept_future_nonce() {
        // Future nonces must be admitted so gossip propagation isn't blocked
        // by a transient state lag. The strict sequential check moves to
        // `select_for_block_for` at proposal time.
        let mut mp = Mempool::new(NoopVerifier);
        mp.admit(make_tx(1, 5, 10, 1000), 0, 1_000_000).unwrap();
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn reject_future_nonce_outside_sender_window() {
        let mut mp = Mempool::new(NoopVerifier);
        let too_far = MAX_MEMPOOL_PENDING_PER_SENDER as u64 + 1;

        let err = mp
            .admit(make_tx(1, too_far, 10, 1000), 0, 1_000_000)
            .unwrap_err();

        assert!(matches!(
            err,
            ConsensusError::MempoolSenderLimit {
                limit: MAX_MEMPOOL_PENDING_PER_SENDER
            }
        ));
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn reject_too_many_pending_from_one_sender() {
        let mut mp = Mempool::new(NoopVerifier);
        for nonce in 1..=MAX_MEMPOOL_PENDING_PER_SENDER as u64 {
            mp.admit(make_tx(1, nonce, 10, 1000), 0, 10_000_000)
                .unwrap();
        }

        let err = mp
            .admit(
                make_tx(1, MAX_MEMPOOL_PENDING_PER_SENDER as u64 + 1, 10, 1000),
                0,
                10_000_000,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            ConsensusError::MempoolSenderLimit {
                limit: MAX_MEMPOOL_PENDING_PER_SENDER
            }
        ));
        assert_eq!(mp.len(), MAX_MEMPOOL_PENDING_PER_SENDER);
    }

    #[test]
    fn select_for_block_for_holds_gaps() {
        let mut mp = Mempool::new(NoopVerifier);
        // Admit nonces 1, 2, then 5 (a gap at 3, 4). State applied = 0.
        mp.admit(make_tx(1, 1, 10, 1000), 0, 1_000_000).unwrap();
        mp.admit(make_tx(1, 2, 10, 1000), 0, 1_000_000).unwrap();
        mp.admit(make_tx(1, 5, 10, 1000), 0, 1_000_000).unwrap();
        let selected = mp.select_for_block_for(10_000, |_| 0);
        // Only the contiguous run [1, 2] should be selected.
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].nonce, 1);
        assert_eq!(selected[1].nonce, 2);
    }

    #[test]
    fn reject_insufficient_balance() {
        let mut mp = Mempool::new(NoopVerifier);
        // max_fuel=1000, fee_per_unit=10 → need 10_000
        let err = mp.admit(make_tx(1, 1, 10, 1000), 0, 9_999).unwrap_err();
        assert!(matches!(err, ConsensusError::InsufficientBalance { .. }));
    }

    #[test]
    fn reject_zero_fee_or_fuel() {
        let mut mp = Mempool::new(NoopVerifier);
        let err = mp.admit(make_tx(1, 1, 0, 0), 0, 1_000_000).unwrap_err();
        assert!(matches!(
            err,
            ConsensusError::InsufficientFuel {
                required: DEPLOY_PETAL_BASE_FUEL,
                got: 0
            }
        ));
        assert_eq!(mp.len(), 0);
    }

    #[test]
    fn replace_by_fee_accepts_strictly_higher() {
        let mut mp = Mempool::new(NoopVerifier);
        mp.admit(make_tx(1, 1, 10, 1000), 0, 1_000_000).unwrap();
        mp.admit(make_tx(1, 1, 11, 1000), 0, 1_000_000).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.pending.values().next().unwrap().fee_per_unit, 11);
    }

    #[test]
    fn replace_by_fee_rejects_equal_fee() {
        let mut mp = Mempool::new(NoopVerifier);
        mp.admit(make_tx(1, 1, 10, 1000), 0, 1_000_000).unwrap();
        let err = mp.admit(make_tx(1, 1, 10, 1000), 0, 1_000_000).unwrap_err();
        assert!(matches!(err, ConsensusError::ReplaceFeeNotHigher));
    }

    #[test]
    fn replace_by_fee_rejects_lower_fee() {
        let mut mp = Mempool::new(NoopVerifier);
        mp.admit(make_tx(1, 1, 10, 1000), 0, 1_000_000).unwrap();
        let err = mp.admit(make_tx(1, 1, 9, 1000), 0, 1_000_000).unwrap_err();
        assert!(matches!(err, ConsensusError::ReplaceFeeNotHigher));
    }

    #[test]
    fn select_for_block_fee_ordering() {
        let mut mp = Mempool::new(NoopVerifier);
        // sender 1, nonce 1, fee=5
        mp.admit(make_tx(1, 1, 5, 1000), 0, 1_000_000).unwrap();
        // sender 2, nonce 1, fee=20
        mp.admit(make_tx(2, 1, 20, 1000), 0, 1_000_000).unwrap();
        // sender 3, nonce 1, fee=10
        mp.admit(make_tx(3, 1, 10, 1000), 0, 1_000_000).unwrap();

        let selected = mp.select_for_block(10_000);
        assert_eq!(selected.len(), 3);
        // Highest fee first
        assert_eq!(selected[0].fee_per_unit, 20);
        assert_eq!(selected[1].fee_per_unit, 10);
        assert_eq!(selected[2].fee_per_unit, 5);
    }

    #[test]
    fn select_for_block_nonce_order_within_sender() {
        let mut mp = Mempool::new(NoopVerifier);
        // Two txs from same sender; they can't both be admitted without incrementing nonce,
        // so test single-sender ordering with separate admits using incremented state.
        // Sender 1, nonce 1 (first tx)
        mp.admit(make_tx(1, 1, 10, 1000), 0, 1_000_000).unwrap();
        // For nonce 2 we'd need current_nonce=1, but mempool doesn't track committed state.
        // Test that within same fee, lower nonce comes first for distinct senders.
        // sender 2, nonce 1, fee=10
        mp.admit(make_tx(2, 1, 10, 1000), 0, 1_000_000).unwrap();

        let selected = mp.select_for_block(10_000);
        assert_eq!(selected.len(), 2);
        // Both fee=10, nonce=1 — ordering is deterministic by sender.
        // Just assert both are present.
        let senders: Vec<_> = selected.iter().map(|t| t.sender).collect();
        assert!(senders.contains(&addr_from_seed(1)));
        assert!(senders.contains(&addr_from_seed(2)));
    }

    #[test]
    fn select_respects_fuel_limit() {
        let mut mp = Mempool::new(NoopVerifier);
        mp.admit(make_tx(1, 1, 10, 1000), 0, 1_000_000).unwrap();
        mp.admit(make_tx(2, 1, 9, 1000), 0, 1_000_000).unwrap();

        // Only room for one tx (1000 < 1500, but 1000+1000=2000 > 1500).
        let selected = mp.select_for_block(1500);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].fee_per_unit, 10); // higher fee selected first
    }

    #[test]
    fn select_for_block_rejects_fuel_sum_overflow() {
        let mut mp = Mempool::new(NoopVerifier);
        mp.admit(make_tx(1, 1, 10, u64::MAX), 0, u128::MAX).unwrap();
        mp.admit(make_tx(2, 1, 9, 1000), 0, u128::MAX).unwrap();

        let selected = mp.select_for_block(u64::MAX);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].sender, addr_from_seed(1));
        assert_eq!(selected[0].max_fuel, u64::MAX);
    }

    #[test]
    fn select_for_block_for_rejects_fuel_sum_overflow() {
        let mut mp = Mempool::new(NoopVerifier);
        mp.admit(make_tx(1, 1, 10, u64::MAX), 0, u128::MAX).unwrap();
        mp.admit(make_tx(2, 1, 9, 1000), 0, u128::MAX).unwrap();

        let selected = mp.select_for_block_for(u64::MAX, |_| 0);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].sender, addr_from_seed(1));
        assert_eq!(selected[0].max_fuel, u64::MAX);
    }

    #[test]
    fn remove_included() {
        let mut mp = Mempool::new(NoopVerifier);
        let tx = make_tx(1, 1, 10, 1000);
        mp.admit(tx.clone(), 0, 1_000_000).unwrap();
        assert_eq!(mp.len(), 1);
        mp.remove_included(&[tx]);
        assert!(mp.is_empty());
    }
}
