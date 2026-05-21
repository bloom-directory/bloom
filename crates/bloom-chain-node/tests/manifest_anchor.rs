//! Category: integration
//!
//! Phase 8 — on-chain manifest anchor.
//!
//! When a `TxKind::Deploy { manifest_hash: Some(h), .. }` is applied through
//! `apply_block_state_transitions`, the deployed account must have
//! `account.manifest_hash == Some(h)`. The anchor is consensus-relevant
//! state; this test wires the full block path so that any regression in
//! the executor, snapshot commit, or SSZ encoding surfaces here.

use bloom_chain_node::{
    consensus_driver::apply_block_state_transitions, petal_executor::ChainPetalExecutor,
};
use bloom_chain_state::{Account, State};
use bloom_chain_types::{
    digest::{blake3_tagged, tags},
    tx::{Tx, TxKind},
    types::{Address, Hash32, PubKeyBytes, SigBytes},
};
use bloom_test_util::{BlockBuilder, make_addr};

const ZERO_EMISSION: u128 = 0;

/// Smallest valid chain-mode petal: an `init` that immediately returns and
/// a `call` that does nothing. The wasm bytes themselves don't matter for
/// this test — we only care that the account at the derived deploy address
/// has the right `manifest_hash` after the block is applied.
const NOOP_PETAL: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "init") (param i32 i32) (result i32) i32.const 0)
  (func (export "call") (param i32 i32) (result i32) i32.const 0)
)
"#;

fn wat(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

#[test]
fn deploy_persists_manifest_hash_on_account() {
    let manifest = Hash32([0xEF; 32]);

    // Sender keypair (its derived address is the deployer in §7.7).
    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let proposer = make_addr(0x77);

    // Fund the sender so the deploy tx can pay max_fuel * fee_per_unit.
    let mut state = State::new();
    state.set_account(
        sender,
        Account {
            nonce: 0,
            loom: 1_000_000_000_000_000_000u128,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );

    let wasm = wat(NOOP_PETAL);
    let salt = [0x33u8; 32];
    let petal_hash = blake3_tagged(tags::PETAL, &wasm);

    // Compute the deploy address per §7.7 so we can read it back.
    let deployed_addr = {
        let mut payload = b"deploy:".to_vec();
        payload.extend_from_slice(&sender.0);
        payload.push(b':');
        payload.extend_from_slice(&salt);
        payload.push(b':');
        payload.extend_from_slice(&petal_hash.0);
        Address(blake3_tagged(tags::ADDR, &payload).0)
    };

    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 1,
        max_fuel: 5_000_000,
        fee_per_unit: 1,
        kind: TxKind::Deploy {
            wasm,
            salt,
            init_args: Vec::new(),
            manifest_hash: Some(manifest),
        },
        pubkey: PubKeyBytes(pk.0.clone()),
        sig: SigBytes(vec![0u8; 64]),
    };

    let block = BlockBuilder::at(1)
        .parent_hash(Hash32([0u8; 32]))
        .proposer(proposer)
        .txs(vec![tx])
        .build();

    let (_fuel, receipts) =
        apply_block_state_transitions(&mut state, &ChainPetalExecutor, &block, ZERO_EMISSION);
    assert_eq!(receipts.len(), 1);
    assert!(
        receipts[0].success,
        "deploy must succeed; return_data={:?}",
        String::from_utf8_lossy(&receipts[0].return_data)
    );

    let acct = state
        .get_account(&deployed_addr)
        .expect("deployed account must exist");
    assert_eq!(acct.code_hash, Some(petal_hash), "code_hash should match");
    assert_eq!(
        acct.manifest_hash,
        Some(manifest),
        "manifest_hash anchor must be persisted on the deployed account"
    );
}

#[test]
fn deploy_without_manifest_hash_leaves_anchor_none() {
    // Same flow but with `manifest_hash: None` — the deployed account must
    // come back with `manifest_hash == None`, not Some(zeros) or a stale
    // value from elsewhere.
    let (_sk, pk) = bloom_keystore::xdsa::XdsaSecretKey::generate();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let proposer = make_addr(0x77);

    let mut state = State::new();
    state.set_account(
        sender,
        Account {
            nonce: 0,
            loom: 1_000_000_000_000_000_000u128,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );

    let wasm = wat(NOOP_PETAL);
    let salt = [0x44u8; 32];
    let petal_hash = blake3_tagged(tags::PETAL, &wasm);
    let deployed_addr = {
        let mut payload = b"deploy:".to_vec();
        payload.extend_from_slice(&sender.0);
        payload.push(b':');
        payload.extend_from_slice(&salt);
        payload.push(b':');
        payload.extend_from_slice(&petal_hash.0);
        Address(blake3_tagged(tags::ADDR, &payload).0)
    };

    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 1,
        max_fuel: 5_000_000,
        fee_per_unit: 1,
        kind: TxKind::Deploy {
            wasm,
            salt,
            init_args: Vec::new(),
            manifest_hash: None,
        },
        pubkey: PubKeyBytes(pk.0.clone()),
        sig: SigBytes(vec![0u8; 64]),
    };

    let block = BlockBuilder::at(1)
        .parent_hash(Hash32([0u8; 32]))
        .proposer(proposer)
        .txs(vec![tx])
        .build();

    let (_fuel, receipts) =
        apply_block_state_transitions(&mut state, &ChainPetalExecutor, &block, ZERO_EMISSION);
    assert!(receipts[0].success);

    let acct = state.get_account(&deployed_addr).unwrap();
    assert_eq!(acct.manifest_hash, None);
}
