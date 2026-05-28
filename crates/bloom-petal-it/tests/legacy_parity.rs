//! Integration tests for legacy TxKind::Transfer / PTB parity.
//!
//! # Test strategy
//!
//! These tests verify that the legacy `TxKind::Transfer` compat shim
//! (introduced in commit fd57f2d, spec §9.2) produces consistent
//! `Coin<LOOM>` state.
//!
//! Coins are seeded with the 48-byte fungible-petal payload format
//! (32-byte ObjectId placeholder + 16-byte u128 value) because
//! `select_coin_loom` uses `bloom_petal_fungible::ops::decode_coin_value`
//! which reads bytes[32..48].
//!
//! Assertions follow spec §9.2:
//!   - `Coin<LOOM>` split remainder = sender balance - amount.
//!   - Bob receives a new `Coin<LOOM>` of the transferred value.
//!   - Total conserved (no LOOM created or destroyed).

use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutor;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::{coin_payload, decode_coin_value, type_tag_coin_loom};
use bloom_script::{CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH};

use bloom_petal_it::harness::addr;

// ---------------------------------------------------------------------------
// Legacy-parity helpers: seed coins with 48-byte fungible-petal payload.
// ---------------------------------------------------------------------------

/// Seed a `Coin<LOOM>` with the 48-byte fungible-petal payload format
/// (32-byte ObjectId placeholder + 16-byte u128 value).
/// This matches what `select_coin_loom` + `decode_coin_value` expect.
fn seed_fungible_coin(state: &mut State, id: ObjectId, owner: Address, value: u128) {
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
    let obj = Object {
        id,
        type_tag: type_tag_coin_loom(),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: coin_payload(value), // 48-byte format
    };
    state.set_object(obj);

    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    let mut owned = state.get_ownership(&okey).unwrap_or_default();
    let pos = owned.partition_point(|oid| oid.0 < id.0);
    owned.insert(pos, id);
    state.set_ownership(okey, owned);
}

/// Build a deterministic coin id for legacy-parity tests.
fn legacy_coin_id(seed: u8) -> ObjectId {
    ObjectId([seed; 32])
}

fn transfer_tx_with_nonce(sender: Address, to: Address, amount: u128, nonce: u64) -> Tx {
    Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce,
        max_fuel: 1_000,
        fee_per_unit: 0,
        kind: TxKind::Transfer {
            to,
            amount_loom: amount,
        },
        pubkey: PubKeyBytes(vec![0u8; 32]),
        sig: SigBytes(vec![0u8; 64]),
    }
}

fn transfer_tx(sender: Address, to: Address, amount: u128) -> Tx {
    transfer_tx_with_nonce(sender, to, amount, 1)
}

fn exec_transfer(state: &mut State, sender: Address, to: Address, amount: u128) {
    let tx = transfer_tx(sender, to, amount);
    exec_transfer_tx(state, &tx);
}

fn exec_transfer_tx(state: &mut State, tx: &Tx) {
    let out = ChainPetalExecutor.execute_tx(tx, state, 1, 0, addr(0xFF), Hash32([0u8; 32]));
    assert!(out.success, "Transfer must succeed");
    state
        .apply(out.write_set.unwrap())
        .expect("apply must not fail");
}

fn bind_bootstrap_fungible(state: &mut State) {
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
}

/// Sum all `Coin<LOOM>` values owned by `owner` (uses 48-byte fungible decode).
fn total_coin_loom(state: &State, owner: Address) -> u128 {
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

// ---------------------------------------------------------------------------
// Test 1: legacy Transfer produces correct Coin<LOOM> values.
// ---------------------------------------------------------------------------

#[test]
fn legacy_transfer_produces_correct_coin_values() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let mut state = State::new();
    state.set_account(
        alice,
        bloom_chain_state::Account {
            nonce: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    seed_fungible_coin(&mut state, legacy_coin_id(0xAA), alice, 1000);

    exec_transfer(&mut state, alice, bob, 300);

    // Alice's coins total 700.
    assert_eq!(
        total_coin_loom(&state, alice),
        700,
        "alice total Coin<LOOM> must be 700"
    );

    // Bob has exactly one coin of value 300.
    let bob_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: bob.0,
    };
    let bob_owned = state
        .get_ownership(&bob_okey)
        .expect("bob must have an ownership entry");
    assert_eq!(bob_owned.len(), 1, "bob must own exactly one Coin<LOOM>");
    let bob_coin = state
        .get_object(&bob_owned[0])
        .expect("bob's coin must exist");
    assert_eq!(
        decode_coin_value(&bob_coin.payload).unwrap(),
        300,
        "bob's coin must be 300"
    );
    assert_eq!(
        bob_coin.type_tag,
        type_tag_coin_loom(),
        "bob's coin must be Coin<LOOM>"
    );
    assert_eq!(
        bob_coin.owner,
        Owner::Address(bob.0),
        "bob must own the coin"
    );
}

// ---------------------------------------------------------------------------
// Test 2: exact-match transfer deletes the sender's coin.
// ---------------------------------------------------------------------------

#[test]
fn legacy_transfer_exact_deletes_sender_coin() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let mut state = State::new();
    state.set_account(
        alice,
        bloom_chain_state::Account {
            nonce: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    let alice_coin_id = legacy_coin_id(0xAA);
    seed_fungible_coin(&mut state, alice_coin_id, alice, 300);

    exec_transfer(&mut state, alice, bob, 300);

    // Alice's coin should be deleted (fully consumed).
    assert!(
        state.get_object(&alice_coin_id).is_none(),
        "alice's coin must be deleted after exact-match transfer"
    );
    assert_eq!(
        total_coin_loom(&state, alice),
        0,
        "alice must have no remaining Coin<LOOM>"
    );

    // Bob received 300.
    assert_eq!(
        total_coin_loom(&state, bob),
        300,
        "bob must have Coin<LOOM>(300)"
    );
}

// ---------------------------------------------------------------------------
// Test 3: five sequential Transfers maintain Coin<LOOM> totals.
// ---------------------------------------------------------------------------

#[test]
fn five_sequential_transfers_maintain_totals() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);
    let total = 10_000u128;

    let mut state = State::new();
    state.set_account(
        alice,
        bloom_chain_state::Account {
            nonce: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    seed_fungible_coin(&mut state, legacy_coin_id(0xAA), alice, total);

    for nonce in 1..=5 {
        let tx = transfer_tx_with_nonce(alice, bob, 1000, nonce);
        exec_transfer_tx(&mut state, &tx);
    }

    let alice_total = total_coin_loom(&state, alice);
    let bob_total = total_coin_loom(&state, bob);

    assert_eq!(
        alice_total, 5_000,
        "alice must have 5000 total Coin<LOOM> after 5 transfers"
    );
    assert_eq!(
        bob_total, 5_000,
        "bob must have 5000 total Coin<LOOM> after 5 transfers"
    );

    // Conservation: total must not change.
    assert_eq!(
        alice_total + bob_total,
        total,
        "total Coin<LOOM> must be conserved: {alice_total} + {bob_total} != {total}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: diverged state (no Coin<LOOM>) — legacy Transfer fails closed.
// ---------------------------------------------------------------------------

#[test]
fn legacy_transfer_diverged_no_coin_loom_fails_closed() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    // Alice has no Coin<LOOM> object.
    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    state.set_account(
        alice,
        bloom_chain_state::Account {
            nonce: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );

    let tx = transfer_tx(alice, bob, 300);
    let out = ChainPetalExecutor.execute_tx(&tx, &mut state, 1, 0, addr(0xFF), Hash32([0u8; 32]));
    assert!(!out.success, "diverged transfer must fail closed");
    assert!(out.write_set.is_none(), "failed transfer must not write");
    assert!(
        state.get_account(&bob).is_none(),
        "bob must not be credited"
    );

    // Bob has no Coin<LOOM> either.
    let bob_coin_total = total_coin_loom(&state, bob);
    assert_eq!(
        bob_coin_total, 0,
        "bob must have no Coin<LOOM> when shim diverged"
    );
}

// ---------------------------------------------------------------------------
// Test 5: value conservation across two independent states.
// ---------------------------------------------------------------------------

#[test]
fn value_conservation_across_two_paths() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let mut state_a = State::new();
    state_a.set_account(
        alice,
        bloom_chain_state::Account {
            nonce: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    seed_fungible_coin(&mut state_a, legacy_coin_id(0xAA), alice, 1000);
    exec_transfer(&mut state_a, alice, bob, 300);

    let mut state_b = State::new();
    state_b.set_account(
        alice,
        bloom_chain_state::Account {
            nonce: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    seed_fungible_coin(&mut state_b, legacy_coin_id(0xAA), alice, 1000);
    exec_transfer(&mut state_b, alice, bob, 300);

    for (label, state) in [("A", &state_a), ("B", &state_b)] {
        let alice_coins = total_coin_loom(state, alice);
        let bob_coins = total_coin_loom(state, bob);
        assert_eq!(alice_coins, 700, "state {label}: alice must have 700");
        assert_eq!(bob_coins, 300, "state {label}: bob must have 300");
        assert_eq!(
            alice_coins + bob_coins,
            1000,
            "state {label}: total must be conserved"
        );
    }
}
