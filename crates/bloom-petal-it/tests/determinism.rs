//! Spec §19 #16 — Determinism.
//!
//! Build two independent fresh States from the same genesis config.
//! Apply the SAME sequence of transactions to each. After all txs commit,
//! compute state roots and assert they are equal.
//!
//! ObjectIds are deterministic — they are derived from tx hash + seed +
//! counter, so the same transaction on the same initial state produces the
//! same ObjectIds on both runs.
//!
//! If a non-determinism bug exists (e.g., HashMap iteration order leaking into
//! the root), this test will detect it and produce an explicit failure with
//! the differing roots. We do NOT paper over any such failure.
//!
//! DOD item: spec §19 #16.

use std::collections::HashMap;

use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutorWithManifests;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::AccessMode;
use bloom_script::{
    Arg, ArgDeclStub, Command, ExpectedVersion, FunctionDeclStub, MoveCmd, PetalManifestStub,
    PetalRef, PqSignature, PtbTx, UseRef, encode_ptb,
};

use bloom_petal_it::harness::{addr, build_state, genesis_coin_id, seed_coin, wat_to_wasm};

/// WAT petal: takes a coin as Arg::Object (Mutable), returns its id.
fn coin_loader_wat(coin_id: bloom_objects::ObjectId) -> String {
    let id_hex: String = coin_id.0.iter().map(|b| format!("\\{b:02x}")).collect();
    format!(
        r#"
(module
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; 40-byte return envelope: count=1 (4 BE) | len=32 (4 BE) | coin_id (32 bytes)
  (data (i32.const 0) "\00\00\00\01\00\00\00\20{id_hex}")
  (func (export "__petal_load_coin") (param i32 i32) (result i32)
    (call $ret (i32.const 0) (i32.const 40))
    i32.const 0)
)
"#
    )
}

/// Apply a PTB that splits `amount` from alice's coin and transfers it to bob.
fn apply_ptb_split_transfer(
    state: &mut State,
    alice: Address,
    bob: Address,
    amount: u128,
    alice_coin_id: bloom_objects::ObjectId,
    petal_hash: Hash32,
) {
    // Read the current version of alice's coin from state so the PTB
    // validator's version-check (spec §7.2 step 5) passes regardless of
    // how many prior txs have mutated the coin.
    let alice_coin_version = state
        .get_object(&alice_coin_id)
        .map(|o| o.version)
        .unwrap_or(0);
    let gas_coin_id = genesis_coin_id(alice, 99);
    if state.get_object(&gas_coin_id).is_none() {
        seed_coin(state, gas_coin_id, alice, 1);
    }

    let mut manifests: HashMap<Hash32, PetalManifestStub> = HashMap::new();
    manifests.insert(
        petal_hash,
        PetalManifestStub {
            module_path: "/test/loader".to_string(),
            functions: vec![FunctionDeclStub {
                name: "load_coin".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Object {
                    ty: bloom_petal_fungible::ops::type_tag_coin_loom(),
                    mode: AccessMode::Mutable,
                }],
                returns: vec![bloom_petal_fungible::ops::type_tag_coin_loom()],
                attached_invariants: vec![],
            }],
            ..Default::default()
        },
    );

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            // cmd 0: load alice's coin → slot 0 = alice_coin_id
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: String::new(),
                    hash: Some(petal_hash),
                },
                function: "load_coin".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: alice_coin_id,
                    expected_version: ExpectedVersion(alice_coin_version),
                    access_mode: AccessMode::Mutable,
                }],
            }),
            // cmd 1: SplitCoins(alice_coin, [amount])
            Command::SplitCoins {
                src: UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                amounts: vec![amount],
            },
            // cmd 2: TransferObjects([split], bob)
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 1,
                    ret_idx: 0,
                }],
                owner: bloom_objects::Owner::Address(bob.0),
            },
        ],
        gas_payer: gas_coin_id,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let ptb_bytes = encode_ptb(&ptb).expect("PTB encode must not fail");
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender: alice,
        nonce: 0,
        max_fuel: 1_000_000,
        fee_per_unit: 0,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: PubKeyBytes(vec![0u8; 32]),
        sig: SigBytes(vec![0u8; 64]),
    };

    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let out = exec.execute_tx(
        &tx,
        state,
        100,
        1_700_000_000_000,
        addr(0xAA),
        Hash32([0u8; 32]),
    );
    assert!(
        out.success,
        "PTB must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    state
        .apply(out.write_set.unwrap())
        .expect("apply must not fail");
}

// ---------------------------------------------------------------------------
// Test 1: Identical tx sequence on two independent states yields equal roots.
//
// Sequence:
//   tx 1: PTB SplitCoins+TransferObjects alice→bob 300
//   tx 2: PTB SplitCoins+TransferObjects alice→bob 200
//   tx 3: PTB SplitCoins+TransferObjects alice→bob 100
//
// Genesis: alice=1000, bob=0.
//
// After all 3 txs, state roots of both runs must be equal.
// ---------------------------------------------------------------------------

#[test]
fn determinism_same_tx_sequence_same_state_root() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    // We need to insert the WAT petal into each state independently.
    // The petal hash is content-addressed, so the same WAT bytes produce
    // the same hash in both states.
    let alice_coin_id = genesis_coin_id(alice, 0);
    let loader_wasm = wat_to_wasm(&coin_loader_wat(alice_coin_id));

    // Run 1
    let root_1 = {
        let mut state = build_state(&[(alice, 1_000)]);

        let petal_hash = state.insert_code(&loader_wasm);
        // Tx 1: PTB SplitCoins+TransferObjects(300)
        apply_ptb_split_transfer(&mut state, alice, bob, 300, alice_coin_id, petal_hash);

        // Tx 2: PTB SplitCoins+TransferObjects(200)
        apply_ptb_split_transfer(&mut state, alice, bob, 200, alice_coin_id, petal_hash);

        // Tx 3: PTB SplitCoins+TransferObjects(100)
        apply_ptb_split_transfer(&mut state, alice, bob, 100, alice_coin_id, petal_hash);

        state.state_root()
    };

    // Run 2 — independent state, same sequence
    let root_2 = {
        let mut state = build_state(&[(alice, 1_000)]);

        let petal_hash = state.insert_code(&loader_wasm);
        apply_ptb_split_transfer(&mut state, alice, bob, 300, alice_coin_id, petal_hash);
        apply_ptb_split_transfer(&mut state, alice, bob, 200, alice_coin_id, petal_hash);
        apply_ptb_split_transfer(&mut state, alice, bob, 100, alice_coin_id, petal_hash);

        state.state_root()
    };

    assert_eq!(
        root_1, root_2,
        "state roots must be equal across two independent runs of the same tx sequence: \
         run1={:?} run2={:?}",
        root_1.0, root_2.0
    );
}

// ---------------------------------------------------------------------------
// Test 2: Determinism across 5 PTB coin transfers.
//
// Applies 5 PTB transfers of varying amounts from alice to bob and verifies
// both runs produce the same state root.
// ---------------------------------------------------------------------------

#[test]
fn determinism_5_ptb_transfers_same_state_root() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);

    let amounts = [100u128, 50, 200, 75, 25];

    let apply_sequence = || {
        let mut state = build_state(&[(alice, 1_000)]);
        let alice_coin_id = genesis_coin_id(alice, 0);
        let loader_wasm = wat_to_wasm(&coin_loader_wat(alice_coin_id));
        let petal_hash = state.insert_code(&loader_wasm);
        for &amt in &amounts {
            apply_ptb_split_transfer(&mut state, alice, bob, amt, alice_coin_id, petal_hash);
        }
        state.state_root()
    };

    let root_1 = apply_sequence();
    let root_2 = apply_sequence();

    assert_eq!(
        root_1, root_2,
        "state roots must be equal across two independent 5-PTB-transfer runs"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Determinism with 3 addresses.
//
// More complex: alice, bob, and charlie exchange LOOM in a defined sequence.
// Both runs must agree on the final state root.
// ---------------------------------------------------------------------------

#[test]
fn determinism_3_address_exchange_same_state_root() {
    let alice = addr(0xA1);
    let bob = addr(0xB2);
    let charlie = addr(0xC3);

    let apply_sequence = || {
        let mut state = build_state(&[(alice, 5_000), (bob, 3_000), (charlie, 2_000)]);
        let alice_coin_id = genesis_coin_id(alice, 0);
        let bob_coin_id = genesis_coin_id(bob, 1);
        let charlie_coin_id = genesis_coin_id(charlie, 2);
        let alice_loader = state.insert_code(&wat_to_wasm(&coin_loader_wat(alice_coin_id)));
        let bob_loader = state.insert_code(&wat_to_wasm(&coin_loader_wat(bob_coin_id)));
        let charlie_loader = state.insert_code(&wat_to_wasm(&coin_loader_wat(charlie_coin_id)));

        apply_ptb_split_transfer(&mut state, alice, bob, 500, alice_coin_id, alice_loader);
        apply_ptb_split_transfer(&mut state, bob, charlie, 200, bob_coin_id, bob_loader);
        apply_ptb_split_transfer(
            &mut state,
            charlie,
            alice,
            100,
            charlie_coin_id,
            charlie_loader,
        );
        apply_ptb_split_transfer(&mut state, alice, charlie, 300, alice_coin_id, alice_loader);
        state.state_root()
    };

    let root_1 = apply_sequence();
    let root_2 = apply_sequence();

    assert_eq!(
        root_1, root_2,
        "state roots must be equal across two independent 3-address runs"
    );
}
