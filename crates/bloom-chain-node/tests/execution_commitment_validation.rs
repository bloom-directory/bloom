//! Category: adversarial
//!
//! The block header must commit to the actual deterministic execution result:
//! post-state root, receipts root, and total fuel. A malicious proposer or sync
//! peer must not be able to finalize one body while advertising another result.

use bloom_chain_node::consensus_driver::{
    BLOCK_EMISSION, ExecOutput, NoopExecutor, PetalExecutor, apply_block_state_transitions,
    validate_block_execution,
};
use bloom_chain_node::petal_executor::ChainPetalExecutor;
use bloom_chain_state::{Account, State};
use bloom_chain_types::{
    Address,
    receipt::receipts_root,
    tx::{Tx, TxKind},
    types::{Hash32, PubKeyBytes, SigBytes},
};
use bloom_keystore::xdsa::XdsaSecretKey;
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::coin_payload;
use bloom_script::{
    CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, PtbTx, encode_ptb, loom_coin_type_tag,
    types::PqSignature,
};
use bloom_test_util::{BlockBuilder, make_addr, make_signed_deploy_tx};

struct FreeFailedPtbExecutor;

impl PetalExecutor for FreeFailedPtbExecutor {
    fn execute_tx(
        &self,
        _tx: &Tx,
        _state: &mut State,
        _block_number: u64,
        _timestamp_ms: u64,
        _proposer: Address,
        _parent_hash: Hash32,
    ) -> ExecOutput {
        ExecOutput {
            success: false,
            fuel_used: 0,
            return_data: b"ptb validation error: synthetic".to_vec(),
            logs: vec![],
            invariant_outcomes: Vec::new(),
            write_set: None,
        }
    }
}

struct FuelOnlyFailedPtbExecutor;

impl PetalExecutor for FuelOnlyFailedPtbExecutor {
    fn execute_tx(
        &self,
        _tx: &Tx,
        _state: &mut State,
        _block_number: u64,
        _timestamp_ms: u64,
        _proposer: Address,
        _parent_hash: Hash32,
    ) -> ExecOutput {
        ExecOutput {
            success: false,
            fuel_used: 1,
            return_data: b"ptb settlement missing: synthetic".to_vec(),
            logs: vec![],
            invariant_outcomes: Vec::new(),
            write_set: None,
        }
    }
}

struct OverFuelPtbExecutor;

impl PetalExecutor for OverFuelPtbExecutor {
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
            fuel_used: 8,
            return_data: vec![],
            logs: vec![],
            invariant_outcomes: Vec::new(),
            write_set: Some(state.snapshot().commit()),
        }
    }
}

struct OverFuelNonPtbExecutor;

impl PetalExecutor for OverFuelNonPtbExecutor {
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
            fuel_used: 1_001,
            return_data: vec![],
            logs: vec![],
            invariant_outcomes: Vec::new(),
            write_set: Some(state.snapshot().commit()),
        }
    }
}

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
            invariant_outcomes: Vec::new(),
            write_set: Some(state.snapshot().commit()),
        }
    }
}

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

fn admissible_submit_ptb(pubkey: PubKeyBytes, nonce: u64) -> (State, Tx) {
    let (signer_sk, signer_pk) = XdsaSecretKey::generate();
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let signer = bloom_chain_types::types::Address::from_pubkey_bytes(&signer_pk.0);
    let gas_payer = ObjectId([0xA5; 32]);
    let mut ptb = PtbTx {
        signers: vec![signer.0],
        commands: vec![],
        gas_payer,
        gas_budget: 7,
        gas_price: 3,
        expiry_block: 99,
        signatures: vec![PqSignature(vec![])],
    };
    let digest = ptb.signing_digest();
    ptb.signatures = vec![PqSignature(signer_sk.sign(&digest).to_bytes())];
    let ptb_bytes = encode_ptb(&ptb).expect("PTB encodes");
    let mut state = State::new();
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
    state.register_pubkey(signer, PubKeyBytes(signer_pk.to_bytes()));
    state.set_object(Object {
        id: gas_payer,
        type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
        owner: Owner::Address(signer.0),
        version: 1,
        payload: coin_payload(1_000_000),
    });
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce,
        max_fuel: 7,
        fee_per_unit: 3,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey,
        sig: SigBytes(vec![0u8; 64]),
    };
    (state, tx)
}

fn executable_non_ptb_block() -> (State, bloom_chain_types::block::Block) {
    let (sk, _pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let tx = make_signed_deploy_tx(&sk, "bloom-chain.v0", b"test-wasm".to_vec(), 1, 1_000, 3);

    let mut state = State::new();
    fund(&mut state, tx.sender, 1_000_000_000_000_000_000_000);

    let mut block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(1_000)
        .build();

    let mut scratch = state.clone();
    let (fuel_used, receipts) = apply_block_state_transitions(
        &mut scratch,
        &FuelOnlyNonPtbExecutor,
        &block,
        BLOCK_EMISSION,
    );
    block.header.state_root = scratch.state_root();
    block.header.receipts_root = receipts_root(&receipts);
    block.header.fuel_used = fuel_used;

    (state, block)
}

#[test]
fn valid_execution_commitment_is_accepted() {
    let (state, block) = executable_non_ptb_block();

    let validated =
        validate_block_execution(&state, &FuelOnlyNonPtbExecutor, &block, BLOCK_EMISSION).unwrap();

    assert_eq!(validated.state_root, block.header.state_root);
    assert_eq!(validated.receipts_root, block.header.receipts_root);
    assert_eq!(validated.fuel_used, block.header.fuel_used);
}

#[test]
fn tampered_state_root_is_rejected() {
    let (state, mut block) = executable_non_ptb_block();
    block.header.state_root = Hash32([0xAA; 32]);

    let err = validate_block_execution(&state, &FuelOnlyNonPtbExecutor, &block, BLOCK_EMISSION)
        .expect_err("tampered state_root must reject");

    assert!(err.contains("state_root mismatch"), "got: {err}");
}

#[test]
fn tampered_receipts_root_is_rejected() {
    let (state, mut block) = executable_non_ptb_block();
    block.header.receipts_root = Hash32([0xBB; 32]);

    let err = validate_block_execution(&state, &FuelOnlyNonPtbExecutor, &block, BLOCK_EMISSION)
        .expect_err("tampered receipts_root must reject");

    assert!(err.contains("receipts_root mismatch"), "got: {err}");
}

#[test]
fn tampered_fuel_used_is_rejected() {
    let (state, mut block) = executable_non_ptb_block();
    block.header.fuel_used = block.header.fuel_used.saturating_add(1);

    let err = validate_block_execution(&state, &FuelOnlyNonPtbExecutor, &block, BLOCK_EMISSION)
        .expect_err("tampered fuel_used must reject");

    assert!(err.contains("fuel_used mismatch"), "got: {err}");
}

#[test]
fn tx_max_fuel_sum_above_block_limit_is_rejected_before_execution() {
    let (state, mut block) = executable_non_ptb_block();
    block.header.fuel_limit = block.txs[0].max_fuel - 1;

    let err = validate_block_execution(&state, &FuelOnlyNonPtbExecutor, &block, BLOCK_EMISSION)
        .expect_err("block over fuel limit must reject");

    assert!(err.contains("exceeds header.fuel_limit"), "got: {err}");
}

#[test]
fn zero_fuel_malformed_submit_ptb_is_rejected_before_nonce_bump() {
    let pubkey = PubKeyBytes(vec![0xAB; 32]);
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 1,
        max_fuel: 0,
        fee_per_unit: 1,
        kind: TxKind::SubmitPtb {
            ptb_bytes: vec![0xCA, 0xFE],
        },
        pubkey,
        sig: SigBytes(vec![0u8; 64]),
    };
    let state = State::new();
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(0)
        .build();

    let err = validate_block_execution(&state, &NoopExecutor, &block, 0)
        .expect_err("malformed zero-fuel SubmitPtb must invalidate block execution");

    assert!(err.contains("state_root mismatch"), "got: {err}");
    assert!(
        state.get_account(&sender).is_none(),
        "validation must not bump sender nonce on malformed zero-fuel PTB"
    );
}

#[test]
fn zero_gas_submit_ptb_is_rejected_before_nonce_bump() {
    let pubkey = PubKeyBytes(vec![0xCD; 32]);
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let ptb_bytes = encode_ptb(&PtbTx::default()).expect("default PTB encodes");
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 1,
        max_fuel: 0,
        fee_per_unit: 1,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey,
        sig: SigBytes(vec![0u8; 64]),
    };
    let state = State::new();
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(0)
        .build();

    let err = validate_block_execution(&state, &NoopExecutor, &block, 0)
        .expect_err("zero-gas SubmitPtb must invalidate block execution");

    assert!(err.contains("state_root mismatch"), "got: {err}");
    assert!(
        state.get_account(&sender).is_none(),
        "validation must not bump sender nonce on zero-gas PTB"
    );
}

#[test]
fn bad_inner_signature_submit_ptb_is_rejected_without_nonce_bump() {
    let (signer_sk, signer_pk) = XdsaSecretKey::generate();
    let signer = bloom_chain_types::types::Address::from_pubkey_bytes(&signer_pk.0);
    let outer_pubkey = PubKeyBytes(vec![0xD0; 32]);
    let outer_sender = bloom_chain_types::types::Address::from_pubkey_bytes(&outer_pubkey.0);
    let gas_payer = ObjectId([0x91; 32]);

    let mut ptb = PtbTx {
        signers: vec![signer.0],
        commands: vec![],
        gas_payer,
        gas_budget: 7,
        gas_price: 3,
        expiry_block: 99,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };
    let digest = ptb.signing_digest();
    let mut sig = signer_sk.sign(&digest).to_bytes();
    sig[0] ^= 0x01;
    ptb.signatures = vec![PqSignature(sig)];
    let ptb_bytes = encode_ptb(&ptb).expect("PTB encodes");
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender: outer_sender,
        nonce: 1,
        max_fuel: 7,
        fee_per_unit: 3,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: outer_pubkey,
        sig: SigBytes(vec![0u8; 64]),
    };

    let mut state = State::new();
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
    state.register_pubkey(signer, PubKeyBytes(signer_pk.to_bytes()));
    state.set_object(Object {
        id: gas_payer,
        type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
        owner: Owner::Address(signer.0),
        version: 1,
        payload: coin_payload(1_000_000),
    });
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(7)
        .build();

    let err = validate_block_execution(&state, &ChainPetalExecutor, &block, 0)
        .expect_err("bad inner signature SubmitPtb must invalidate block execution");

    assert!(err.contains("state_root mismatch"), "got: {err}");
    assert!(
        state.get_account(&outer_sender).is_none(),
        "validation must not bump outer sender nonce for bad inner signature"
    );
}

#[test]
fn failed_submit_ptb_cannot_advance_nonce_without_fuel_or_settlement() {
    let pubkey = PubKeyBytes(vec![0xEF; 32]);
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let (state, tx) = admissible_submit_ptb(pubkey, 1);
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(7)
        .build();

    let err = validate_block_execution(&state, &FreeFailedPtbExecutor, &block, 0)
        .expect_err("free failed SubmitPtb must invalidate block execution");

    assert!(
        err.contains("prechecked PTB must charge positive fuel"),
        "got: {err}"
    );
    assert!(
        state.get_account(&sender).is_none(),
        "validation must not bump sender nonce for a free failed PTB"
    );
}

#[test]
fn failed_submit_ptb_cannot_report_fuel_without_gas_settlement() {
    let pubkey = PubKeyBytes(vec![0xF0; 32]);
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let (state, tx) = admissible_submit_ptb(pubkey, 1);
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(7)
        .build();

    let err = validate_block_execution(&state, &FuelOnlyFailedPtbExecutor, &block, 0)
        .expect_err("failed SubmitPtb with no gas settlement must invalidate block execution");

    assert!(
        err.contains("prechecked PTB must charge positive fuel"),
        "got: {err}"
    );
    assert!(
        state.get_account(&sender).is_none(),
        "validation must not bump sender nonce without gas settlement"
    );
}

#[test]
fn successful_submit_ptb_cannot_advance_nonce_with_zero_fuel() {
    struct ZeroFuelSuccessPtbExecutor;

    impl PetalExecutor for ZeroFuelSuccessPtbExecutor {
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
                fuel_used: 0,
                return_data: vec![],
                logs: vec![],
                invariant_outcomes: Vec::new(),
                write_set: Some(state.snapshot().commit()),
            }
        }
    }

    let pubkey = PubKeyBytes(vec![0xF1; 32]);
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let (state, tx) = admissible_submit_ptb(pubkey, 1);
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(7)
        .build();

    let err = validate_block_execution(&state, &ZeroFuelSuccessPtbExecutor, &block, 0)
        .expect_err("successful zero-fuel SubmitPtb must invalidate block execution");

    assert!(
        err.contains("prechecked PTB must charge positive fuel"),
        "got: {err}"
    );
    assert!(
        state.get_account(&sender).is_none(),
        "validation must not bump sender nonce for successful zero-fuel PTB"
    );
}

#[test]
fn submit_ptb_cannot_charge_more_than_outer_max_fuel() {
    let pubkey = PubKeyBytes(vec![0xF3; 32]);
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let (state, tx) = admissible_submit_ptb(pubkey, 1);
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(8)
        .build();

    let err = validate_block_execution(&state, &OverFuelPtbExecutor, &block, 0)
        .expect_err("over-fuel SubmitPtb must invalidate block execution");

    assert!(err.contains("exceeds max_fuel"), "got: {err}");
    assert!(
        state.get_account(&sender).is_none(),
        "validation must not bump sender nonce for over-fuel SubmitPtb"
    );
}

#[test]
fn non_ptb_zero_fee_envelope_is_rejected_before_nonce_bump() {
    let (sk, _pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let tx = make_signed_deploy_tx(&sk, "bloom-chain.v0", b"test-wasm".to_vec(), 1, 1_000, 0);
    let mut state = State::new();
    fund(&mut state, tx.sender, 1_000_000);
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx.clone()])
        .fuel_limit(1_000)
        .build();

    let err = validate_block_execution(&state, &NoopExecutor, &block, 0)
        .expect_err("zero-fee non-PTB tx must invalidate block execution");

    assert!(err.contains("state_root mismatch"), "got: {err}");
    assert!(
        state
            .get_account(&tx.sender)
            .map(|acct| acct.nonce == 0)
            .unwrap_or(true),
        "validation must not bump sender nonce for zero-fee non-PTB tx"
    );
}

#[test]
fn successful_non_ptb_cannot_advance_nonce_with_zero_fuel() {
    let pubkey = PubKeyBytes(vec![0xF2; 32]);
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 1,
        max_fuel: 1_000,
        fee_per_unit: 1,
        kind: TxKind::DeployPetal {
            wasm_bytes: vec![0x00, 0x61, 0x73, 0x6d],
        },
        pubkey,
        sig: SigBytes(vec![0u8; 64]),
    };
    let mut state = State::new();
    fund(&mut state, sender, 1_000_000);
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(1_000)
        .build();

    let err = validate_block_execution(&state, &NoopExecutor, &block, 0)
        .expect_err("successful zero-fuel non-PTB tx must invalidate block execution");

    assert!(
        err.contains("successful tx must charge positive fuel"),
        "got: {err}"
    );
    assert!(
        state
            .get_account(&sender)
            .map(|acct| acct.nonce == 0)
            .unwrap_or(true),
        "validation must not bump sender nonce for successful zero-fuel non-PTB tx"
    );
}

#[test]
fn successful_non_ptb_cannot_charge_more_than_max_fuel() {
    let pubkey = PubKeyBytes(vec![0xF4; 32]);
    let sender = bloom_chain_types::types::Address::from_pubkey_bytes(&pubkey.0);
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 1,
        max_fuel: 1_000,
        fee_per_unit: 1,
        kind: TxKind::DeployPetal {
            wasm_bytes: vec![0x00, 0x61, 0x73, 0x6d],
        },
        pubkey,
        sig: SigBytes(vec![0u8; 64]),
    };
    let mut state = State::new();
    fund(&mut state, sender, 1_000_000);
    let block = BlockBuilder::at(1)
        .chain_id("bloom-chain.v0")
        .proposer(make_addr(0x11))
        .txs(vec![tx])
        .fuel_limit(1_001)
        .build();

    let err = validate_block_execution(&state, &OverFuelNonPtbExecutor, &block, 0)
        .expect_err("over-fuel non-PTB tx must invalidate block execution");

    assert!(err.contains("exceeds max_fuel"), "got: {err}");
    assert!(
        state
            .get_account(&sender)
            .map(|acct| acct.nonce == 0)
            .unwrap_or(true),
        "validation must not bump sender nonce for over-fuel non-PTB tx"
    );
}
