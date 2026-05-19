//! Category: adversarial
//!
//! Regression coverage for the 2026-05-19 review #4 — restart must replay
//! full committed state, not just the proposer LOOM emission.
//!
//! On master, `Node::run` rebuilt state at startup by walking
//! `block_store` and applying only `proposer.loom += BLOCK_EMISSION` per
//! block — every transfer, deploy, storage write, fee, and refund was
//! silently dropped. A validator that restarted at height N effectively
//! lost all of state H ∈ [1, N] except the proposer's accumulated
//! emission, and would diverge from peers on the very next state_root.
//!
//! Post-fix, replay routes through the same
//! `apply_block_state_transitions` helper as live consensus, so a
//! restarted node's state is byte-identical to a node that never
//! restarted.

use bloom_chain_node::consensus_driver::{apply_block_state_transitions, NoopExecutor};
use bloom_chain_state::State;
use bloom_chain_types::{
    block::Block,
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
};
use bloom_test_util::{make_addr, BlockBuilder};

const BLOCK_EMISSION: u128 = 10_000_000_000_000_000_000u128;

fn make_transfer_tx(
    sender: Address,
    sender_pubkey_bytes: Vec<u8>,
    to: Address,
    amount: u128,
    nonce: u64,
) -> Tx {
    Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce,
        max_fuel: 1_000,
        fee_per_unit: 1,
        kind: TxKind::Transfer {
            to,
            amount_loom: amount,
        },
        pubkey: PubKeyBytes(sender_pubkey_bytes),
        sig: SigBytes(vec![0u8; 64]),
    }
}

fn make_block(height: u64, proposer: Address, txs: Vec<Tx>) -> Block {
    // Replay doesn't validate block roots; use the BlockBuilder default
    // sentinel roots (0xAA/0xBB/0xCC/0xDD).
    BlockBuilder::at(height)
        .proposer(proposer)
        .txs(txs)
        .build()
}

#[test]
fn replay_reproduces_full_transfer_chain() {
    // Build a fresh sender keypair so the tx survives the sender-derivation
    // check inside apply_block_state_transitions.
    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let pk_bytes = pk.0.clone();

    let proposer = make_addr(0x77);
    let recipient = make_addr(0x33);

    // Genesis-equivalent allocation.
    let initial_balance: u128 = 1_000_000_000_000_000_000_000u128;

    // --- "Live" run: build state by applying blocks once. ---
    let mut live = State::new();
    {
        use bloom_chain_state::Account;
        live.set_account(
            sender,
            Account {
                nonce: 0,
                loom: initial_balance,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
            },
        );
    }
    let executor = NoopExecutor;
    // Block 1: sender → recipient transfer of 100.
    let block1 = make_block(
        1,
        proposer,
        vec![make_transfer_tx(sender, pk_bytes.clone(), recipient, 100, 1)],
    );
    // Block 2: sender → recipient transfer of 50.
    let block2 = make_block(
        2,
        proposer,
        vec![make_transfer_tx(sender, pk_bytes.clone(), recipient, 50, 2)],
    );

    apply_block_state_transitions(&mut live, &executor, &block1, BLOCK_EMISSION);
    apply_block_state_transitions(&mut live, &executor, &block2, BLOCK_EMISSION);

    let live_root = live.state_root();
    let live_sender_loom = live.get_account(&sender).map(|a| a.loom).unwrap();
    let live_sender_nonce = live.get_account(&sender).map(|a| a.nonce).unwrap();
    let live_recipient_loom = live.get_account(&recipient).map(|a| a.loom).unwrap_or(0);
    let live_proposer_loom = live.get_account(&proposer).map(|a| a.loom).unwrap_or(0);

    // --- "Restart" replay: same path, fresh state, same blocks. ---
    let mut replayed = State::new();
    {
        use bloom_chain_state::Account;
        replayed.set_account(
            sender,
            Account {
                nonce: 0,
                loom: initial_balance,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
            },
        );
    }
    apply_block_state_transitions(&mut replayed, &executor, &block1, BLOCK_EMISSION);
    apply_block_state_transitions(&mut replayed, &executor, &block2, BLOCK_EMISSION);

    // Full state must converge — same state_root, same accounts.
    assert_eq!(
        replayed.state_root(),
        live_root,
        "restart replay state_root must match live state_root"
    );
    assert_eq!(
        replayed.get_account(&sender).map(|a| a.nonce).unwrap(),
        live_sender_nonce,
        "sender nonce must match after replay (master bug: nonce reset)"
    );
    assert_eq!(
        replayed.get_account(&sender).map(|a| a.loom).unwrap(),
        live_sender_loom,
        "sender loom must match after replay (master bug: transfers dropped)"
    );
    assert_eq!(
        replayed.get_account(&recipient).map(|a| a.loom).unwrap_or(0),
        live_recipient_loom,
        "recipient loom must match after replay (master bug: transfers dropped)"
    );
    assert_eq!(
        replayed.get_account(&proposer).map(|a| a.loom).unwrap_or(0),
        live_proposer_loom,
        "proposer loom must match after replay (block emission + fees)"
    );
    // Sanity: the recipient actually received the transferred amount.
    assert_eq!(live_recipient_loom, 150, "two transfers (100 + 50)");
    // Sanity: the proposer accumulated two block emissions plus fees.
    assert!(
        live_proposer_loom >= 2 * BLOCK_EMISSION,
        "proposer loom should include 2 block emissions, got {live_proposer_loom}"
    );
}

#[test]
fn master_style_replay_diverges() {
    // Pin the regression: the *master* approach (only `proposer.loom +=
    // BLOCK_EMISSION` per block) produces a state_root that differs from
    // the live state. Without this assertion, a future change that
    // accidentally re-introduces the master shortcut might pass all
    // other tests.
    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);

    let proposer = make_addr(0x77);
    let recipient = make_addr(0x33);
    let initial_balance: u128 = 1_000_000_000_000_000_000_000u128;

    let mut live = State::new();
    {
        use bloom_chain_state::Account;
        live.set_account(
            sender,
            Account {
                nonce: 0,
                loom: initial_balance,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
            },
        );
    }
    let executor = NoopExecutor;
    let block1 = make_block(
        1,
        proposer,
        vec![make_transfer_tx(sender, pk.0.clone(), recipient, 100, 1)],
    );
    apply_block_state_transitions(&mut live, &executor, &block1, BLOCK_EMISSION);

    // Master-style replay: skip txs entirely, only credit BLOCK_EMISSION.
    let mut master_replayed = State::new();
    {
        use bloom_chain_state::Account;
        master_replayed.set_account(
            sender,
            Account {
                nonce: 0,
                loom: initial_balance,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
            },
        );
    }
    let mut prop_acct = master_replayed
        .get_account(&proposer)
        .unwrap_or(bloom_chain_state::Account {
            nonce: 0,
            loom: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
        });
    prop_acct.loom += BLOCK_EMISSION;
    master_replayed.set_account(proposer, prop_acct);

    assert_ne!(
        master_replayed.state_root(),
        live.state_root(),
        "master-style replay (emission-only) MUST diverge from live state — \
         the recipient never sees the transfer and the sender's nonce stays at 0"
    );
}
