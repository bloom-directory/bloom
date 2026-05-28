//! Category: adversarial
//!
//! The block header must commit to the actual deterministic execution result:
//! post-state root, receipts root, and total fuel. A malicious proposer or sync
//! peer must not be able to finalize one body while advertising another result.

use bloom_chain_node::consensus_driver::{
    BLOCK_EMISSION, NoopExecutor, apply_block_state_transitions, validate_block_execution,
};
use bloom_chain_state::{Account, State};
use bloom_chain_types::{receipt::receipts_root, types::Hash32};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::coin_payload;
use bloom_script::{CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, loom_coin_type_tag};
use bloom_test_util::{BlockBuilder, make_addr, make_signed_transfer_tx};

fn fund(state: &mut State, addr: bloom_chain_types::Address, loom: u128) {
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
    let mut h = blake3::Hasher::new();
    h.update(b"execution_commitment_validation.fund");
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

fn executable_transfer_block() -> (State, bloom_chain_types::block::Block) {
    let (sk, _pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let tx = make_signed_transfer_tx(&sk, "bloom-chain.v0", make_addr(0x77), 12_345, 1, 1_000, 3);

    let mut state = State::new();
    fund(&mut state, tx.sender, 1_000_000_000_000_000_000_000);

    let mut block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(1_000)
        .build();

    let mut scratch = state.clone();
    let (fuel_used, receipts) =
        apply_block_state_transitions(&mut scratch, &NoopExecutor, &block, BLOCK_EMISSION);
    block.header.state_root = scratch.state_root();
    block.header.receipts_root = receipts_root(&receipts);
    block.header.fuel_used = fuel_used;

    (state, block)
}

#[test]
fn valid_execution_commitment_is_accepted() {
    let (state, block) = executable_transfer_block();

    let validated =
        validate_block_execution(&state, &NoopExecutor, &block, BLOCK_EMISSION).unwrap();

    assert_eq!(validated.state_root, block.header.state_root);
    assert_eq!(validated.receipts_root, block.header.receipts_root);
    assert_eq!(validated.fuel_used, block.header.fuel_used);
}

#[test]
fn tampered_state_root_is_rejected() {
    let (state, mut block) = executable_transfer_block();
    block.header.state_root = Hash32([0xAA; 32]);

    let err = validate_block_execution(&state, &NoopExecutor, &block, BLOCK_EMISSION)
        .expect_err("tampered state_root must reject");

    assert!(err.contains("state_root mismatch"), "got: {err}");
}

#[test]
fn tampered_receipts_root_is_rejected() {
    let (state, mut block) = executable_transfer_block();
    block.header.receipts_root = Hash32([0xBB; 32]);

    let err = validate_block_execution(&state, &NoopExecutor, &block, BLOCK_EMISSION)
        .expect_err("tampered receipts_root must reject");

    assert!(err.contains("receipts_root mismatch"), "got: {err}");
}

#[test]
fn tampered_fuel_used_is_rejected() {
    let (state, mut block) = executable_transfer_block();
    block.header.fuel_used = block.header.fuel_used.saturating_add(1);

    let err = validate_block_execution(&state, &NoopExecutor, &block, BLOCK_EMISSION)
        .expect_err("tampered fuel_used must reject");

    assert!(err.contains("fuel_used mismatch"), "got: {err}");
}

#[test]
fn tx_max_fuel_sum_above_block_limit_is_rejected_before_execution() {
    let (state, mut block) = executable_transfer_block();
    block.header.fuel_limit = block.txs[0].max_fuel - 1;

    let err = validate_block_execution(&state, &NoopExecutor, &block, BLOCK_EMISSION)
        .expect_err("block over fuel limit must reject");

    assert!(err.contains("exceeds header.fuel_limit"), "got: {err}");
}
