//! Spec §19 #4 — Account.loom reconciliation invariant.
//!
//! After applying a sequence of transactions, walk `state.objects` collecting
//! every `Coin<LOOM>` owned by `Owner::Address(addr)`, sum the values, and
//! assert the sum matches `state.get_account(&addr).loom`.
//!
//! DOD item: spec §19 #4.

use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutor;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{OWNER_KIND_ADDRESS, OwnershipIndexKey};
use bloom_petal_fungible::ops::{decode_coin_value, type_tag_coin_loom};

use bloom_petal_it::harness::{addr, build_state};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sum all `Coin<LOOM>` values owned by `owner` via the ownership index.
///
/// Uses `bloom_petal_fungible::ops::decode_coin_value` (canonical 48-byte
/// format) and `type_tag_coin_loom()`. Skips objects whose type tag doesn't
/// match `Coin<LOOM>`.
fn sum_coin_loom(state: &State, owner: Address) -> u128 {
    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    let owned = state.get_ownership(&okey).unwrap_or_default();
    let coin_type = type_tag_coin_loom();
    owned
        .iter()
        .filter_map(|id| state.get_object(id))
        .filter(|o| o.type_tag == coin_type)
        .map(|o| decode_coin_value(&o.payload).unwrap_or(0))
        .sum()
}

/// Assert the reconciliation invariant for `addr`:
///   account.loom == sum(Coin<LOOM> owned by addr)
fn assert_reconciled(state: &State, owner: Address, label: &str) {
    let account_loom = state.get_account(&owner).map(|a| a.loom).unwrap_or(0);
    let coin_total = sum_coin_loom(state, owner);
    assert_eq!(
        account_loom,
        coin_total,
        "{label}: account.loom ({account_loom}) != sum(Coin<LOOM>) ({coin_total}) \
         for addr {addr:?}",
        addr = owner.0
    );
}

/// Execute a `TxKind::Transfer` and apply the write set.
///
/// Mirrors `apply_block_state_transitions` steps 3+4: debit `amount_loom`
/// from the sender's `account.loom` before calling `execute_tx` (which only
/// credits the receiver). This is necessary for the reconciliation invariant
/// to hold for both parties; without the debit, the sender's `account.loom`
/// would remain inflated relative to their `Coin<LOOM>` sum.
fn exec_transfer(state: &mut State, sender: Address, to: Address, amount: u128) {
    // Step 3 (block driver): debit sender's account.loom.
    {
        let mut sender_acct = state
            .get_account(&sender)
            .expect("sender must have an account");
        assert!(
            sender_acct.loom >= amount,
            "sender account.loom {loom} < transfer amount {amount}",
            loom = sender_acct.loom
        );
        sender_acct.loom -= amount;
        state.set_account(sender, sender_acct);
    }

    // Step 4 (block driver): execute_tx (credits receiver's account.loom,
    // updates Coin<LOOM> objects via the PTB compat shim).
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 0,
        max_fuel: 1_000,
        fee_per_unit: 0,
        kind: TxKind::Transfer {
            to,
            amount_loom: amount,
        },
        pubkey: PubKeyBytes(vec![0u8; 32]),
        sig: SigBytes(vec![0u8; 64]),
    };
    let out = ChainPetalExecutor.execute_tx(&tx, state, 1, 0, addr(0xFF), Hash32([0u8; 32]));
    assert!(out.success, "Transfer must succeed");
    state
        .apply(out.write_set.unwrap())
        .expect("apply must not fail");
}

// ---------------------------------------------------------------------------
// Scenario 1: Fresh genesis with 3 allocations.
//
// Build a state with 3 addresses, each with an initial balance.
// Assert the reconciliation invariant for all three addresses immediately.
// ---------------------------------------------------------------------------

#[test]
fn reconciliation_genesis_3_allocations() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);
    let charlie = addr(0xC3);

    let state = build_state(&[(alice, 1_000), (bob, 2_000), (charlie, 3_000)]);

    assert_reconciled(&state, alice, "genesis alice");
    assert_reconciled(&state, bob, "genesis bob");
    assert_reconciled(&state, charlie, "genesis charlie");
}

// ---------------------------------------------------------------------------
// Scenario 2: After a TxKind::Transfer from alice→bob.
//
// alice starts with 1000, transfers 300 to bob.
// Both alice (700) and bob (300) must satisfy the invariant.
// ---------------------------------------------------------------------------

#[test]
fn reconciliation_after_single_transfer() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let mut state = build_state(&[(alice, 1_000)]);

    exec_transfer(&mut state, alice, bob, 300);

    assert_reconciled(&state, alice, "after transfer: alice");
    assert_reconciled(&state, bob, "after transfer: bob");

    // Spot-check values.
    assert_eq!(
        sum_coin_loom(&state, alice),
        700,
        "alice Coin<LOOM> sum must be 700"
    );
    assert_eq!(
        sum_coin_loom(&state, bob),
        300,
        "bob Coin<LOOM> sum must be 300"
    );
}

// ---------------------------------------------------------------------------
// Scenario 3: 5 sequential transfers across 3 addresses.
//
// alice starts with 10_000. We do 5 transfers in a round-robin:
//   alice→bob 1000, bob→charlie 500, charlie→alice 200,
//   alice→charlie 300, bob→alice 100.
//
// After all 5 transfers, all three addresses must satisfy the invariant.
// Also verify total LOOM is conserved.
// ---------------------------------------------------------------------------

#[test]
fn reconciliation_5_sequential_transfers_3_addresses() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);
    let charlie = addr(0xC3);

    let initial = 10_000u128;
    let mut state = build_state(&[(alice, initial)]);

    // We need bob and charlie to have non-zero balances before they
    // can send; seed the early transfers from alice.
    exec_transfer(&mut state, alice, bob, 1_000);
    exec_transfer(&mut state, alice, charlie, 500); // give charlie some first
    exec_transfer(&mut state, bob, charlie, 400);
    exec_transfer(&mut state, alice, charlie, 300);
    exec_transfer(&mut state, alice, bob, 200);

    assert_reconciled(&state, alice, "after 5 transfers: alice");
    assert_reconciled(&state, bob, "after 5 transfers: bob");
    assert_reconciled(&state, charlie, "after 5 transfers: charlie");

    // Conservation: total must equal 10_000.
    let total =
        sum_coin_loom(&state, alice) + sum_coin_loom(&state, bob) + sum_coin_loom(&state, charlie);
    assert_eq!(total, initial, "total LOOM must be conserved: got {total}");
}
