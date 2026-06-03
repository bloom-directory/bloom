//! Category: adversarial
//!
//! Regression coverage for the 2026-05-19 review #5 — `apply_block`
//! settlement ordering.
//!
//! On master, `apply_block_state_transitions` credited the proposer fee
//! and refunded the sender BEFORE applying the tx output's `write_set`.
//! Because `WriteSet` carries absolute post-execution account values
//! (see `bloom_chain_state::state::AccountDelta::Set`), any tx whose
//! write set touched the sender or proposer account would silently
//! overwrite the fee/refund settlement — meaning fee revenue
//! disappeared whenever the transfer recipient was the proposer, and
//! sender balance reconciliation broke on transfer-to-self.
//!
//! Post-fix, the write_set is applied first and settlement runs on top
//! of the post-write_set balances, so transfer-to-self, recipient-is-
//! proposer, and sender-is-proposer all reconcile to the spec numbers.

use bloom_chain_node::consensus_driver::{
    ExecOutput, PetalExecutor, apply_block_state_transitions, coin_loom_balance,
    resolve_loom_coin_type, try_apply_block_state_transitions,
};
use bloom_chain_state::{Account, State};
use bloom_chain_types::{
    block::Block,
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::coin_payload;
use bloom_script::{CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, loom_coin_type_tag};
use bloom_test_util::{BlockBuilder, make_addr};

// Block emission is intentionally zero in these tests so the proposer
// balance after the block is purely the result of fee/refund settlement
// and write-set application; the spec emission credit is tested
// elsewhere.
const ZERO_EMISSION: u128 = 0;

fn make_deploy_tx(
    sender: Address,
    sender_pubkey_bytes: Vec<u8>,
    nonce: u64,
    max_fuel: u64,
    fee_per_unit: u64,
) -> Tx {
    Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce,
        max_fuel,
        fee_per_unit,
        kind: TxKind::DeployPetal {
            wasm_bytes: b"test-wasm".to_vec(),
        },
        pubkey: PubKeyBytes(sender_pubkey_bytes),
        sig: SigBytes(vec![0u8; 64]),
    }
}

fn make_block(height: u64, proposer: Address, txs: Vec<Tx>) -> Block {
    BlockBuilder::at(height).proposer(proposer).txs(txs).build()
}

fn fund(state: &mut State, addr: Address, loom: u128) {
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
    state.set_account(
        addr,
        Account {
            nonce: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    if loom > 0 {
        let mut h = blake3::Hasher::new();
        h.update(b"apply_block_settlement_ordering.fund");
        h.update(&addr.0);
        h.update(&loom.to_be_bytes());
        let coin_id = ObjectId(*h.finalize().as_bytes());
        state.set_object(Object {
            id: coin_id,
            type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
            owner: Owner::Address(addr.0),
            version: 0,
            payload: coin_payload(loom),
        });
        state.set_ownership(
            OwnershipIndexKey {
                owner_kind: OWNER_KIND_ADDRESS,
                owner_id: addr.0,
            },
            vec![coin_id],
        );
    }
}

fn balance_of(state: &State, addr: &Address) -> u128 {
    resolve_loom_coin_type(state)
        .and_then(|coin_type| coin_loom_balance(state, *addr, &coin_type).ok())
        .unwrap_or(0)
}

/// `NoopExecutor` always reports `fuel_used = 100` for a `Transfer`, so
/// fee accounting is `100 * fee_per_unit`. With `max_fuel` larger than
/// 100, the refund is `(max_fuel - 100) * fee_per_unit`.
const NOOP_FUEL_USED: u64 = 100;

struct CoinTransferExecutor {
    to: Address,
    amount: u128,
}

fn deterministic_coin_id(owner: Address, salt: &[u8]) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"apply_block_settlement_ordering.executor_coin");
    h.update(&owner.0);
    h.update(salt);
    ObjectId(*h.finalize().as_bytes())
}

fn set_single_coin_balance(
    snap: &mut bloom_chain_state::StateSnapshot,
    owner: Address,
    amount: u128,
) {
    let key = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    for id in snap.get_ownership(&key).unwrap_or_default() {
        snap.delete_object(id);
    }
    if amount == 0 {
        snap.set_ownership(key, vec![]);
        return;
    }

    let coin_id = deterministic_coin_id(owner, &amount.to_be_bytes());
    snap.insert_object(Object {
        id: coin_id,
        type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: coin_payload(amount),
    });
    snap.set_ownership(key, vec![coin_id]);
}

impl PetalExecutor for CoinTransferExecutor {
    fn execute_tx(
        &self,
        tx: &Tx,
        state: &mut State,
        _block_number: u64,
        _timestamp_ms: u64,
        _proposer: Address,
        _parent_hash: Hash32,
    ) -> ExecOutput {
        let sender_before = balance_of(state, &tx.sender);
        let recipient_before = balance_of(state, &self.to);
        let mut snap = state.snapshot();
        if tx.sender == self.to {
            set_single_coin_balance(&mut snap, tx.sender, sender_before);
        } else {
            set_single_coin_balance(&mut snap, tx.sender, sender_before - self.amount);
            set_single_coin_balance(&mut snap, self.to, recipient_before + self.amount);
        }
        ExecOutput {
            success: true,
            fuel_used: NOOP_FUEL_USED,
            return_data: vec![],
            logs: vec![],
            write_set: Some(snap.commit()),
        }
    }
}

struct StaleWriteSetExecutor;

impl PetalExecutor for StaleWriteSetExecutor {
    fn execute_tx(
        &self,
        _tx: &Tx,
        state: &mut State,
        _block_number: u64,
        _timestamp_ms: u64,
        _proposer: Address,
        _parent_hash: Hash32,
    ) -> ExecOutput {
        let stale = state.snapshot().commit();
        let bump = state.snapshot().commit();
        state.apply(bump).expect("generation bump must apply");
        ExecOutput {
            success: true,
            fuel_used: NOOP_FUEL_USED,
            return_data: vec![],
            logs: vec![],
            write_set: Some(stale),
        }
    }
}

struct DrainsSenderExecutor;

impl PetalExecutor for DrainsSenderExecutor {
    fn execute_tx(
        &self,
        tx: &Tx,
        state: &mut State,
        _block_number: u64,
        _timestamp_ms: u64,
        _proposer: Address,
        _parent_hash: Hash32,
    ) -> ExecOutput {
        let mut snap = state.snapshot();
        let key = OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: tx.sender.0,
        };
        for id in snap.get_ownership(&key).unwrap_or_default() {
            snap.delete_object(id);
        }
        snap.set_ownership(key, vec![]);
        ExecOutput {
            success: true,
            fuel_used: NOOP_FUEL_USED,
            return_data: vec![],
            logs: vec![],
            write_set: Some(snap.commit()),
        }
    }
}

#[test]
fn transfer_to_self_preserves_fee_debit() {
    // tx where sender == recipient with a non-zero amount.
    // After fee settlement, balance should be `initial - fee_earned`,
    // NOT `initial` (which is what a clobbering write_set would
    // produce, because the snapshot reads sender post-max-fee-debit,
    // adds `amount`, and rewrites sender back).

    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let proposer = make_addr(0x77);

    let initial: u128 = 1_000_000_000_000_000_000_000u128;
    let amount: u128 = 12_345;
    let fee_per_unit: u64 = 7;
    let max_fuel: u64 = 1_000;
    let fee_earned: u128 = NOOP_FUEL_USED as u128 * fee_per_unit as u128;

    let mut state = State::new();
    fund(&mut state, sender, initial);

    let tx = make_deploy_tx(sender, pk.0.clone(), 1, max_fuel, fee_per_unit);
    let block = make_block(1, proposer, vec![tx]);
    let executor = CoinTransferExecutor { to: sender, amount };
    let (_fuel, receipts) =
        apply_block_state_transitions(&mut state, &executor, &block, ZERO_EMISSION);
    assert_eq!(receipts.len(), 1, "one receipt expected");
    assert!(receipts[0].success, "transfer-to-self must succeed");

    assert_eq!(
        balance_of(&state, &sender),
        initial - fee_earned,
        "sender balance must be initial - fee_earned (write_set must not erase the fee debit)",
    );
    assert_eq!(
        balance_of(&state, &proposer),
        fee_earned,
        "proposer must receive the fee even when sender == recipient",
    );
}

#[test]
fn recipient_is_proposer_fee_credit_survives_write_set() {
    // tx where transfer recipient is the block proposer.
    // After: sender == initial_sender - fee_earned - amount,
    //        proposer == initial_proposer + fee_earned + amount.
    // On master, the write_set (which sets proposer = initial_proposer
    // + amount) was applied LAST and overwrote the fee_earned credit,
    // so proposer would only see + amount.

    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let proposer = make_addr(0x55);

    let initial_sender: u128 = 1_000_000_000_000_000_000_000u128;
    let initial_proposer: u128 = 5_000;
    let amount: u128 = 9_999;
    let fee_per_unit: u64 = 11;
    let max_fuel: u64 = 2_000;
    let fee_earned: u128 = NOOP_FUEL_USED as u128 * fee_per_unit as u128;

    let mut state = State::new();
    fund(&mut state, sender, initial_sender);
    fund(&mut state, proposer, initial_proposer);

    let tx = make_deploy_tx(sender, pk.0.clone(), 1, max_fuel, fee_per_unit);
    let block = make_block(1, proposer, vec![tx]);
    let executor = CoinTransferExecutor {
        to: proposer,
        amount,
    };
    let (_fuel, receipts) =
        apply_block_state_transitions(&mut state, &executor, &block, ZERO_EMISSION);
    assert!(receipts[0].success, "tx must succeed");

    assert_eq!(
        balance_of(&state, &sender),
        initial_sender - fee_earned - amount,
        "sender debited fee + amount",
    );
    assert_eq!(
        balance_of(&state, &proposer),
        initial_proposer + fee_earned + amount,
        "proposer must receive BOTH the amount (via write_set) AND the fee (via settlement); \
         a clobbering write_set order would erase the fee",
    );
}

#[test]
fn sender_is_proposer_pays_amount_only() {
    // tx where sender IS the block proposer, transferring to a third
    // party. After: sender balance == initial - amount (the fee was
    // charged to sender and then credited back to the same account).
    // On master the fee_earned credit was applied BEFORE the write_set,
    // and the write_set never touched the sender/proposer, so this
    // case actually balanced — but only by accident. We still pin it
    // down so future re-orderings can't break it.

    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender_and_proposer = Address::from_pubkey_bytes(&pk.0);
    let recipient = make_addr(0x22);

    let initial: u128 = 1_000_000_000_000_000_000_000u128;
    let amount: u128 = 4_242;
    let fee_per_unit: u64 = 5;
    let max_fuel: u64 = 1_500;

    let mut state = State::new();
    fund(&mut state, sender_and_proposer, initial);

    let tx = make_deploy_tx(sender_and_proposer, pk.0.clone(), 1, max_fuel, fee_per_unit);
    let block = make_block(1, sender_and_proposer, vec![tx]);
    let executor = CoinTransferExecutor {
        to: recipient,
        amount,
    };
    let (_fuel, receipts) =
        apply_block_state_transitions(&mut state, &executor, &block, ZERO_EMISSION);
    assert!(receipts[0].success, "tx must succeed");

    assert_eq!(
        balance_of(&state, &sender_and_proposer),
        initial - amount,
        "sender-is-proposer ends down by only `amount` — the fee circled back",
    );
    assert_eq!(
        balance_of(&state, &recipient),
        amount,
        "recipient gets the full amount",
    );
}

#[test]
fn state_apply_failure_rejects_transition() {
    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let proposer = make_addr(0x44);
    let initial = 1_000_000u128;

    let mut state = State::new();
    fund(&mut state, sender, initial);
    let before_root = state.state_root();

    let tx = make_deploy_tx(sender, pk.0.clone(), 1, 1_000, 1);
    let block = make_block(1, proposer, vec![tx]);
    let err = try_apply_block_state_transitions(
        &mut state,
        &StaleWriteSetExecutor,
        &block,
        ZERO_EMISSION,
    )
    .expect_err("stale executor write_set must reject the transition");

    assert!(err.contains("apply write_set failed"), "got: {err}");
    assert_eq!(
        state.state_root(),
        before_root,
        "state must remain unchanged"
    );
    assert_eq!(balance_of(&state, &sender), initial);
}

#[test]
fn non_ptb_effects_are_not_published_when_fee_settlement_fails() {
    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let proposer = make_addr(0x45);
    let max_fuel = 1_000;
    let fee_per_unit = 1;
    let initial = max_fuel as u128 * fee_per_unit as u128 + 1;

    let mut state = State::new();
    fund(&mut state, sender, initial);
    let before_root = state.state_root();

    let tx = make_deploy_tx(sender, pk.0.clone(), 1, max_fuel, fee_per_unit);
    let block = make_block(1, proposer, vec![tx]);
    let err =
        try_apply_block_state_transitions(&mut state, &DrainsSenderExecutor, &block, ZERO_EMISSION)
            .expect_err("fee settlement must reject after executor spends the fee payer coins");

    assert!(err.contains("non-PTB fee settlement failed"), "got: {err}");
    assert_eq!(
        state.state_root(),
        before_root,
        "executor effects must not publish"
    );
    assert_eq!(balance_of(&state, &sender), initial);
    assert_eq!(balance_of(&state, &proposer), 0);
}
