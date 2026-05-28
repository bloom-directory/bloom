//! Category: feature
//!
//! Integration tests for the legacy `TxKind::Transfer` PTB compat shim
//! (Task #33).
//!
//! Verifies that after a legacy `Transfer` tx:
//! - The sender's `Coin<LOOM>` object is updated (split remainder) or
//!   deleted (fully consumed).
//! - The receiver gains a new `Coin<LOOM>` object with the transferred value.
//! - The `OwnershipIndex` for both addresses is kept consistent.

use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutor;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::{coin_payload, decode_coin_value, type_tag_coin_loom};
use bloom_script::{CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn addr(b: u8) -> Address {
    Address([b; 32])
}

/// Build a minimal legacy `TxKind::Transfer` transaction.
fn transfer_tx(sender: Address, to: Address, amount: u128) -> Tx {
    Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 1,
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

fn bind_bootstrap_fungible(state: &mut State) {
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
}

/// Seed `state` with a single `Coin<LOOM>` for `owner` with the given value.
/// Returns the `ObjectId` of the seeded coin.
fn seed_single_coin(state: &mut State, owner: Address, value: u128) -> ObjectId {
    let id_bytes: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        h.update(b"test.seed");
        h.update(&owner.0);
        h.update(&value.to_be_bytes());
        *h.finalize().as_bytes()
    };
    let coin_id = ObjectId(id_bytes);
    let obj = Object {
        id: coin_id,
        type_tag: type_tag_coin_loom(),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: coin_payload(value),
    };
    state.set_object(obj);
    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    let mut owned = state.get_ownership(&okey).unwrap_or_default();
    if !owned.contains(&coin_id) {
        owned.push(coin_id);
        owned.sort();
        state.set_ownership(okey, owned);
    }
    coin_id
}

fn total_coin_loom(state: &State, owner: Address) -> u128 {
    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    state
        .get_ownership(&okey)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|id| state.get_object(&id))
        .map(|obj| decode_coin_value(&obj.payload).expect("coin payload decodes"))
        .sum()
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Core shim test: alice owns 1 Coin<LOOM>(1000), transfers 300 to bob.
///
/// Expected post-state:
/// - alice's coin value = 700 (split remainder).
/// - bob has a new coin of value 300.
/// - OwnershipIndex for alice still contains alice's coin.
/// - OwnershipIndex for bob contains the new coin.
#[test]
fn transfer_splits_sender_coin_and_mints_receiver_coin() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);

    let alice_acct = bloom_chain_state::Account {
        nonce: 0,
        code_hash: None,
        storage_root: Hash32([0u8; 32]),
        manifest_hash: None,
    };
    state.set_account(alice, alice_acct.clone());

    // Seed the Coin<LOOM> for alice.
    let alice_coin_id = seed_single_coin(&mut state, alice, 1000);

    // Execute the Transfer tx directly.
    let tx = transfer_tx(alice, bob, 300);
    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 1,
        /* timestamp_ms */ 0,
        /* proposer */ addr(0xFF),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(out.success, "Transfer must succeed");
    let ws = out.write_set.expect("Transfer must produce a write set");
    state.apply(ws).expect("apply write_set must not fail");

    // ── Coin<LOOM> checks ───────────────────────────────────────────────────
    // Alice's original coin should now have value 700 (1000 - 300).
    let alice_coin = state
        .get_object(&alice_coin_id)
        .expect("alice's coin must still exist (split remainder)");
    let alice_coin_value =
        decode_coin_value(&alice_coin.payload).expect("alice coin payload must decode");
    assert_eq!(
        alice_coin_value, 700,
        "alice's coin value should be 700 (split remainder)"
    );

    // Bob should have exactly one Coin<LOOM> object.
    let bob_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: bob.0,
    };
    let bob_owned = state
        .get_ownership(&bob_okey)
        .expect("bob should have an ownership entry");
    assert_eq!(bob_owned.len(), 1, "bob should own exactly one coin");

    let bob_coin_id = bob_owned[0];
    let bob_coin = state
        .get_object(&bob_coin_id)
        .expect("bob's coin must exist");
    let bob_coin_value =
        decode_coin_value(&bob_coin.payload).expect("bob coin payload must decode");
    assert_eq!(bob_coin_value, 300, "bob's coin should have value 300");

    // Coin types must be Coin<LOOM>.
    let coin_type = type_tag_coin_loom();
    assert_eq!(
        alice_coin.type_tag, coin_type,
        "alice's coin must be Coin<LOOM>"
    );
    assert_eq!(
        bob_coin.type_tag, coin_type,
        "bob's coin must be Coin<LOOM>"
    );

    // Bob's coin must be owned by bob.
    assert_eq!(
        bob_coin.owner,
        Owner::Address(bob.0),
        "bob's coin owner must be bob"
    );

    // Alice's ownership index must still contain her (split) coin.
    let alice_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: alice.0,
    };
    let alice_owned = state
        .get_ownership(&alice_okey)
        .expect("alice's ownership entry must exist");
    assert!(
        alice_owned.contains(&alice_coin_id),
        "alice's ownership index must still contain her coin"
    );
}

/// Edge case: exact-match transfer consumes alice's coin entirely.
/// Alice's coin of exactly 300 transferred to bob → coin deleted.
#[test]
fn transfer_exact_match_deletes_sender_coin() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

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
    let alice_coin_id = seed_single_coin(&mut state, alice, 300);

    let tx = transfer_tx(alice, bob, 300);
    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(&tx, &mut state, 1, 0, addr(0xFF), Hash32([0u8; 32]));
    assert!(out.success);
    state.apply(out.write_set.unwrap()).unwrap();

    // Alice's coin should be deleted.
    assert!(
        state.get_object(&alice_coin_id).is_none(),
        "alice's coin should be deleted"
    );

    // Alice's ownership index should be empty (no coins remain).
    let alice_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: alice.0,
    };
    let alice_owned = state.get_ownership(&alice_okey).unwrap_or_default();
    assert!(
        !alice_owned.contains(&alice_coin_id),
        "alice's deleted coin must not appear in ownership"
    );

    // Bob has a coin of value 300.
    let bob_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: bob.0,
    };
    let bob_owned = state
        .get_ownership(&bob_okey)
        .expect("bob should have an ownership entry");
    assert_eq!(bob_owned.len(), 1);
    let bob_coin_val =
        decode_coin_value(&state.get_object(&bob_owned[0]).unwrap().payload).unwrap();
    assert_eq!(bob_coin_val, 300);
}

/// Divergence case: if sender has no Coin<LOOM>, the Transfer fails closed
/// without changing the object world.
#[test]
fn transfer_without_coin_loom_fails_closed() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    // Alice has NO Coin<LOOM> object.
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
    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(&tx, &mut state, 1, 0, addr(0xFF), Hash32([0u8; 32]));

    // Missing Coin<LOOM> must fail closed.
    assert!(!out.success, "Transfer must fail with missing Coin<LOOM>");
    assert!(
        out.write_set.is_none(),
        "failed transfer must not produce writes"
    );

    // Bob gets no account materialization.
    assert!(state.get_account(&bob).is_none());

    // Bob has no Coin<LOOM> either.
    let bob_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: bob.0,
    };
    let bob_owned = state.get_ownership(&bob_okey).unwrap_or_default();
    assert!(
        bob_owned.is_empty(),
        "bob must have no Coin<LOOM> objects when shim diverged"
    );
}

#[test]
fn transfer_without_fungible_vfs_binding_fails_closed() {
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
    seed_single_coin(&mut state, alice, 1000);

    let tx = transfer_tx(alice, bob, 300);
    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(&tx, &mut state, 1, 0, addr(0xFF), Hash32([0u8; 32]));

    assert!(
        !out.success,
        "Transfer must fail when /bloom/core/fungible is unbound"
    );
    assert!(
        String::from_utf8_lossy(&out.return_data).contains("missing required VFS binding"),
        "unexpected return_data: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert!(out.write_set.is_none());
    assert!(state.get_account(&bob).is_none());
}

#[test]
fn transfer_recipient_coin_aggregate_overflow_fails_closed() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    seed_single_coin(&mut state, alice, 10);
    seed_single_coin(&mut state, bob, u128::MAX);

    let tx = transfer_tx(alice, bob, 1);
    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(&tx, &mut state, 1, 0, addr(0xFF), Hash32([0u8; 32]));

    assert!(!out.success, "transfer must fail on recipient overflow");
    assert!(
        String::from_utf8_lossy(&out.return_data).contains("balance overflow"),
        "unexpected return_data: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert!(out.write_set.is_none());
    assert_eq!(total_coin_loom(&state, alice), 10);
    assert_eq!(total_coin_loom(&state, bob), u128::MAX);
}

#[test]
fn transfer_to_self_at_max_balance_does_not_false_overflow() {
    let alice = addr(0xA1);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    seed_single_coin(&mut state, alice, u128::MAX);

    let tx = transfer_tx(alice, alice, 1);
    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(&tx, &mut state, 1, 0, addr(0xFF), Hash32([0u8; 32]));

    assert!(
        out.success,
        "self-transfer should preserve aggregate balance"
    );
    state.apply(out.write_set.expect("write set")).unwrap();
    assert_eq!(total_coin_loom(&state, alice), u128::MAX);
}
