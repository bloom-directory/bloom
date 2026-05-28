//! Category: adversarial
//!
//! Regression coverage for the 2026-05-19 review #4 — restart must replay
//! full committed state, not just the proposer LOOM emission.
//!
//! On master, `Node::run` rebuilt state at startup by walking
//! `block_store` and applying only proposer block emission per
//! block — every transfer, deploy, storage write, fee, and refund was
//! silently dropped. A validator that restarted at height N effectively
//! lost all of state H ∈ [1, N] except the proposer's accumulated
//! emission, and would diverge from peers on the very next state_root.
//!
//! Post-fix, replay routes through the same
//! `apply_block_state_transitions` helper as live consensus, so a
//! restarted node's state is byte-identical to a node that never
//! restarted.

use bloom_chain_consensus::{ValidatorSet, validator_set::Validator};
use bloom_chain_node::consensus_driver::{
    ExecOutput, NoopExecutor, PetalExecutor, apply_block_state_transitions, coin_loom_balance,
    resolve_loom_coin_type,
};
use bloom_chain_node::{
    block_store::BlockStore, genesis::Genesis, node::restore_state_from_storage,
    state_blob::StateBlobStore, state_index::StateIndex,
};
use bloom_chain_state::Account;
use bloom_chain_state::State;
use bloom_chain_types::{
    block::Block,
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::coin_payload;
use bloom_script::{CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, loom_coin_type_tag};
use bloom_test_util::{BlockBuilder, make_addr};

const BLOCK_EMISSION: u128 = 10_000_000_000_000_000_000u128;

struct FuelOnlyNonPtbExecutor;

impl PetalExecutor for FuelOnlyNonPtbExecutor {
    fn execute_tx(
        &self,
        _tx: &Tx,
        state: &mut State,
        _block_number: u64,
        _timestamp_ms: u64,
        _proposer: Address,
        _parent_hash: Hash32,
    ) -> ExecOutput {
        ExecOutput {
            success: true,
            fuel_used: 100,
            return_data: vec![],
            logs: vec![],
            write_set: Some(state.snapshot().commit()),
        }
    }
}

fn make_deploy_tx(sender: Address, sender_pubkey_bytes: Vec<u8>, nonce: u64) -> Tx {
    Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce,
        max_fuel: 1_000,
        fee_per_unit: 1,
        kind: TxKind::DeployPetal {
            wasm_bytes: b"test-wasm".to_vec(),
        },
        pubkey: PubKeyBytes(sender_pubkey_bytes),
        sig: SigBytes(vec![0u8; 64]),
    }
}

fn make_block(height: u64, proposer: Address, txs: Vec<Tx>) -> Block {
    // Replay doesn't validate block roots; use the BlockBuilder default
    // sentinel roots (0xAA/0xBB/0xCC/0xDD).
    BlockBuilder::at(height).proposer(proposer).txs(txs).build()
}

fn make_genesis() -> Genesis {
    let pk = PubKeyBytes(vec![0u8; 1984]);
    let validator = Validator {
        address: make_addr(0xAA),
        pubkey: pk.clone(),
        voting_power: 1,
    };
    Genesis {
        chain_id: "bloom-chain.v0".to_string(),
        genesis_time_ms: 0,
        validator_set: ValidatorSet::new(vec![validator]).unwrap(),
        peer_addrs: vec![],
        allocations: vec![],
        petals: vec![],
        key_registry: vec![(make_addr(0xAA), pk)],
        genesis_hash: Hash32([0x42; 32]),
    }
}

fn bind_bootstrap_fungible(state: &mut State) {
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
}

fn coin_balance(state: &State, addr: Address) -> u128 {
    resolve_loom_coin_type(state)
        .map(|coin_type| coin_loom_balance(state, addr, &coin_type))
        .unwrap_or(0)
}

fn seed_coin(state: &mut State, owner: Address, value: u128) {
    let mut h = blake3::Hasher::new();
    h.update(b"restart_replay.seed");
    h.update(&owner.0);
    h.update(&value.to_be_bytes());
    let id = ObjectId(*h.finalize().as_bytes());
    state.set_object(Object {
        id,
        type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: coin_payload(value),
    });
    state.set_ownership(
        OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: owner.0,
        },
        vec![id],
    );
}

fn persist_checkpoint(
    state: &State,
    height: u64,
    blob_store: &StateBlobStore,
    state_index: &StateIndex,
) {
    let root = state.state_root();
    let (blob, expected_hash) = state.to_blob(height, Hash32([height as u8; 32]));
    let stored_hash = blob_store.put(&blob).unwrap();
    assert_eq!(stored_hash, expected_hash);
    state_index.put(height, &root, &stored_hash).unwrap();
}

#[test]
fn replay_reproduces_full_non_ptb_chain() {
    // Build a fresh sender keypair so the tx survives the sender-derivation
    // check inside apply_block_state_transitions.
    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let pk_bytes = pk.0.clone();

    let proposer = make_addr(0x77);
    // Genesis-equivalent allocation.
    let initial_balance: u128 = 1_000_000_000_000_000_000_000u128;

    // --- "Live" run: build state by applying blocks once. ---
    let mut live = State::new();
    bind_bootstrap_fungible(&mut live);
    seed_coin(&mut live, sender, initial_balance);
    {
        use bloom_chain_state::Account;
        live.set_account(
            sender,
            Account {
                nonce: 0,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            },
        );
    }
    let executor = FuelOnlyNonPtbExecutor;
    // Block 1: first non-PTB tx.
    let block1 = make_block(
        1,
        proposer,
        vec![make_deploy_tx(sender, pk_bytes.clone(), 1)],
    );
    // Block 2: second non-PTB tx.
    let block2 = make_block(
        2,
        proposer,
        vec![make_deploy_tx(sender, pk_bytes.clone(), 2)],
    );

    apply_block_state_transitions(&mut live, &executor, &block1, BLOCK_EMISSION);
    apply_block_state_transitions(&mut live, &executor, &block2, BLOCK_EMISSION);

    let live_root = live.state_root();
    let live_sender_loom = coin_balance(&live, sender);
    let live_sender_nonce = live.get_account(&sender).map(|a| a.nonce).unwrap();
    let live_proposer_loom = coin_balance(&live, proposer);

    // --- "Restart" replay: same path, fresh state, same blocks. ---
    let mut replayed = State::new();
    bind_bootstrap_fungible(&mut replayed);
    seed_coin(&mut replayed, sender, initial_balance);
    {
        use bloom_chain_state::Account;
        replayed.set_account(
            sender,
            Account {
                nonce: 0,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
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
        coin_balance(&replayed, sender),
        live_sender_loom,
        "sender loom must match after replay (master bug: transfers dropped)"
    );
    assert_eq!(
        coin_balance(&replayed, proposer),
        live_proposer_loom,
        "proposer loom must match after replay (block emission + fees)"
    );
    // Sanity: the proposer accumulated two block emissions plus fees.
    assert!(
        live_proposer_loom >= 2 * BLOCK_EMISSION,
        "proposer loom should include 2 block emissions, got {live_proposer_loom}"
    );
}

#[test]
fn master_style_replay_diverges() {
    // Pin the regression: the *master* approach (only proposer block
    // emission per block) produces a state_root that differs from
    // the live state. Without this assertion, a future change that
    // accidentally re-introduces the master shortcut might pass all
    // other tests.
    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);

    let proposer = make_addr(0x77);
    let initial_balance: u128 = 1_000_000_000_000_000_000_000u128;

    let mut live = State::new();
    bind_bootstrap_fungible(&mut live);
    seed_coin(&mut live, sender, initial_balance);
    {
        use bloom_chain_state::Account;
        live.set_account(
            sender,
            Account {
                nonce: 0,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            },
        );
    }
    let executor = FuelOnlyNonPtbExecutor;
    let block1 = make_block(1, proposer, vec![make_deploy_tx(sender, pk.0.clone(), 1)]);
    apply_block_state_transitions(&mut live, &executor, &block1, BLOCK_EMISSION);

    // Master-style replay: skip txs entirely, only credit BLOCK_EMISSION.
    let mut master_replayed = State::new();
    bind_bootstrap_fungible(&mut master_replayed);
    seed_coin(&mut master_replayed, sender, initial_balance);
    {
        use bloom_chain_state::Account;
        master_replayed.set_account(
            sender,
            Account {
                nonce: 0,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            },
        );
    }
    assert_ne!(
        master_replayed.state_root(),
        live.state_root(),
        "master-style replay (emission-only) MUST diverge from live state — \
         the sender's nonce stays at 0"
    );
}

#[test]
fn restore_uses_latest_checkpoint_and_replays_suffix_after_pruning() {
    let temp = tempfile::tempdir().unwrap();
    let blocks = BlockStore::open(&temp.path().join("blocks")).unwrap();
    let blobs = StateBlobStore::open(&temp.path().join("state_blobs")).unwrap();
    let index = StateIndex::open(&temp.path().join("state_index.sqlite")).unwrap();

    let proposer = make_addr(0x77);
    let executor = NoopExecutor;
    let mut live = State::new();
    bind_bootstrap_fungible(&mut live);
    live.set_account(
        make_addr(0x10),
        Account {
            nonce: 1,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );

    let checkpoint_height = 260;
    let latest_height = 520;
    for h in 1..=latest_height {
        let mut block = make_block(h, proposer, vec![]);
        apply_block_state_transitions(&mut live, &executor, &block, BLOCK_EMISSION);
        block.header.state_root = live.state_root();
        blocks.put(h, &block).unwrap();
        if h == checkpoint_height {
            persist_checkpoint(&live, h, &blobs, &index);
        }
    }
    blocks.prune(latest_height).unwrap();
    assert!(
        blocks.get(1).unwrap().is_none(),
        "old pre-checkpoint blocks should be pruned"
    );

    let (restored, restored_height) = restore_state_from_storage(
        &make_genesis(),
        &blocks,
        &blobs,
        &index,
        &executor,
        BLOCK_EMISSION,
    )
    .unwrap();

    assert_eq!(restored_height, latest_height);
    assert_eq!(restored.state_root(), live.state_root());
    assert_eq!(
        coin_balance(&restored, proposer),
        coin_balance(&live, proposer)
    );
}

#[test]
fn restore_fails_when_required_suffix_block_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    let blocks = BlockStore::open(&temp.path().join("blocks")).unwrap();
    let blobs = StateBlobStore::open(&temp.path().join("state_blobs")).unwrap();
    let index = StateIndex::open(&temp.path().join("state_index.sqlite")).unwrap();

    let proposer = make_addr(0x77);
    let executor = NoopExecutor;
    let mut checkpoint_state = State::new();
    bind_bootstrap_fungible(&mut checkpoint_state);
    let mut block1 = make_block(1, proposer, vec![]);
    apply_block_state_transitions(&mut checkpoint_state, &executor, &block1, BLOCK_EMISSION);
    block1.header.state_root = checkpoint_state.state_root();
    blocks.put(1, &block1).unwrap();
    persist_checkpoint(&checkpoint_state, 1, &blobs, &index);

    // Height 3 exists, so latest_height is 3, but height 2 is required and
    // missing. Restore must fail instead of silently skipping it.
    blocks.put(3, &make_block(3, proposer, vec![])).unwrap();

    let err = restore_state_from_storage(
        &make_genesis(),
        &blocks,
        &blobs,
        &index,
        &executor,
        BLOCK_EMISSION,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("required replay block missing"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn restore_falls_back_when_latest_checkpoint_block_is_missing() {
    let temp = tempfile::tempdir().unwrap();
    let blocks = BlockStore::open(&temp.path().join("blocks")).unwrap();
    let blobs = StateBlobStore::open(&temp.path().join("state_blobs")).unwrap();
    let index = StateIndex::open(&temp.path().join("state_index.sqlite")).unwrap();

    let proposer = make_addr(0x77);
    let executor = NoopExecutor;
    let mut live = State::new();
    bind_bootstrap_fungible(&mut live);

    let mut block1 = make_block(1, proposer, vec![]);
    apply_block_state_transitions(&mut live, &executor, &block1, BLOCK_EMISSION);
    block1.header.state_root = live.state_root();
    blocks.put(1, &block1).unwrap();
    persist_checkpoint(&live, 1, &blobs, &index);

    let mut block2 = make_block(2, proposer, vec![]);
    apply_block_state_transitions(&mut live, &executor, &block2, BLOCK_EMISSION);
    block2.header.state_root = live.state_root();
    blocks.put(2, &block2).unwrap();

    let mut indexed_but_missing_block_state = live.clone();
    let block3 = make_block(3, proposer, vec![]);
    apply_block_state_transitions(
        &mut indexed_but_missing_block_state,
        &executor,
        &block3,
        BLOCK_EMISSION,
    );
    persist_checkpoint(&indexed_but_missing_block_state, 3, &blobs, &index);

    let (restored, restored_height) = restore_state_from_storage(
        &make_genesis(),
        &blocks,
        &blobs,
        &index,
        &executor,
        BLOCK_EMISSION,
    )
    .unwrap();

    assert_eq!(restored_height, 2);
    assert_eq!(restored.state_root(), live.state_root());
}
