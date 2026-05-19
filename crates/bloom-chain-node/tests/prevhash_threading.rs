//! Regression coverage for review 2026-05-19 #13 — `block.prevhash`
//! threading into `PetalExecutor`.
//!
//! On master, `ChainPetalExecutor::execute_tx` constructed the
//! `PetalBlockCtx` with a hard-coded zero `prevhash`, so any chain-mode
//! petal that read `chain::block.prevhash` got all-zero bytes regardless
//! of the actual parent block hash.
//!
//! Post-fix, `apply_block_state_transitions` extracts
//! `block.header.parent_hash` and threads it into `execute_tx`, which
//! forwards it as `PetalBlockCtx.prevhash`. The petal then reads the
//! correct 32 bytes via `chain::block.prevhash`.
//!
//! Strategy: deploy a tiny petal (via direct `state.insert_code` so we
//! don't need to mint xDSA signatures), then submit a `Call` tx against
//! it inside a block whose `header.parent_hash` is a known
//! non-zero value. The petal reads `chain::block.prevhash` into return
//! data via `petal.return`; we assert the returned bytes equal the block
//! header's `parent_hash`.

use bloom_chain_node::{
    consensus_driver::apply_block_state_transitions,
    petal_executor::ChainPetalExecutor,
};
use bloom_chain_state::{Account, State};
use bloom_chain_types::{
    block::{Block, BlockHeader},
    digest::{blake3_tagged, tags},
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
    vote::Commit,
};

const ZERO_EMISSION: u128 = 0;

const PREVHASH_RETURN_PETAL: &str = r#"
(module
  (import "chain" "block.prevhash" (func $ph  (param i32)))
  (import "chain" "petal.return"   (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "init") (param i32 i32) (result i32) i32.const 0)
  (func (export "call") (param i32 i32) (result i32)
    (call $ph (i32.const 0))
    (call $ret (i32.const 0) (i32.const 32))
    i32.const 0)
)
"#;

fn wat(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

#[test]
fn prevhash_visible_to_petal() {
    // The non-zero parent_hash we want the petal to observe.
    let known_parent_hash = Hash32([0xC0; 32]);

    // ── 1. Mint a sender keypair so the tx passes sender-derivation. ─────
    let (sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let proposer = Address([0x77; 32]);

    // ── 2. Pre-deploy the petal directly into state (no Deploy tx
    //       needed for this test). ───────────────────────────────────────
    let wasm = wat(PREVHASH_RETURN_PETAL);
    let mut state = State::new();
    let petal_hash = state.insert_code(&wasm);
    let contract_addr = Address([0xAB; 32]);
    state.set_account(
        contract_addr,
        Account {
            nonce: 0,
            loom: 0,
            code_hash: Some(petal_hash),
            storage_root: Hash32([0u8; 32]),
        },
    );

    // ── 3. Fund the sender. ──────────────────────────────────────────────
    let initial: u128 = 1_000_000_000_000_000_000u128;
    state.set_account(
        sender,
        Account {
            nonce: 0,
            loom: initial,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
        },
    );

    // ── 4. Build a Call tx and sign it. ──────────────────────────────────
    let max_fuel: u64 = 1_000_000;
    let fee_per_unit: u64 = 1;
    let tx_unsigned = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 1,
        max_fuel,
        fee_per_unit,
        kind: TxKind::Call {
            to: contract_addr,
            calldata: Vec::new(),
            value_loom: 0,
        },
        pubkey: PubKeyBytes(pk.0.clone()),
        sig: SigBytes(vec![0u8; 64]),
    };
    let _ = sk; // Tx signatures aren't checked in
                // apply_block_state_transitions — sender derivation +
                // nonce + balance are. Keep `sk` referenced so the test
                // documents the production lifecycle even though we
                // don't sign here.

    // ── 5. Build a block whose header carries the known parent_hash.
    //       (apply_block_state_transitions reads block.header.parent_hash
    //       and threads it into the executor.) ─────────────────────────────
    let block = Block {
        header: BlockHeader {
            chain_id: "bloom-chain.v0".to_string(),
            height: 2,
            parent_hash: known_parent_hash,
            timestamp_ms: 1_747_526_400_000,
            proposer,
            txs_root: Hash32([0u8; 32]),
            state_root: Hash32([0u8; 32]),
            receipts_root: Hash32([0u8; 32]),
            validator_set_hash: Hash32([0u8; 32]),
            fuel_used: 0,
            fuel_limit: 30_000_000,
        },
        txs: vec![tx_unsigned],
        commit: Commit {
            height: 0,
            round: 0,
            block_hash: Hash32([0u8; 32]),
            votes: vec![],
        },
    };

    let (_fuel, receipts) = apply_block_state_transitions(
        &mut state,
        &ChainPetalExecutor,
        &block,
        ZERO_EMISSION,
    );
    assert_eq!(receipts.len(), 1, "exactly one tx receipt");
    let r = &receipts[0];
    assert!(
        r.success,
        "tx must succeed; got return_data={:?}",
        String::from_utf8_lossy(&r.return_data)
    );

    // The petal returned 32 bytes from `chain::block.prevhash`. They
    // must equal the block header's `parent_hash`.
    assert_eq!(
        r.return_data.len(),
        32,
        "petal must return 32 bytes from chain::block.prevhash"
    );
    assert_eq!(
        r.return_data, known_parent_hash.0,
        "block.prevhash bytes must match block.header.parent_hash; \
         on master this would be all-zero regardless of the actual parent"
    );

    // Sanity: keep blake3_tagged import alive so removing it later is a
    // conscious change.
    let _ = blake3_tagged(tags::PETAL, &[]);
}
