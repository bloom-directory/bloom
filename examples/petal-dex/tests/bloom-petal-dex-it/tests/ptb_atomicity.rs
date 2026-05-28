//! Spec §19 #11 — PTB atomicity: second command failure rolls back first.
//!
//! A PTB with two commands where the first succeeds but the second deliberately
//! fails must roll back the entire PTB: success=false, write_set=None, and
//! all state is unchanged.
//!
//! # Failure strategy
//!
//! We use a linearity violation as the "deliberate second failure":
//!   cmd 0: SplitCoins(alice_coin, [100]) — succeeds, creates transient Coin
//!   cmd 1: SplitCoins(alice_coin, [100]) — fails because alice_coin was
//!          already mutably borrowed in cmd 0 (the borrow table will reject a
//!          second mutable borrow of the same object id in the same PTB).
//!          Alternatively, if the second SplitCoins proceeds, the two
//!          resulting transient coins are orphaned and the linearity check at
//!          tx-end reverts the whole PTB.
//!
//! The simpler + more reliable path: emit a deliberate abort from a WAT petal
//! using the `chain.revert` host import (or non-zero return code), then verify
//! that the write set is None and alice's coin is unchanged.
//!
//! We use a WAT petal that intentionally returns non-zero (petal-side abort)
//! as command 1. The executor must roll back the SplitCoins of command 0.
//!
//! DOD item: spec §19 #11.

use std::collections::HashMap;

use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutorWithManifests;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{AccessMode, OWNER_KIND_ADDRESS, OwnershipIndexKey};
use bloom_petal_fungible::ops::{decode_coin_value, type_tag_coin_loom};
use bloom_script::{
    Arg, ArgDeclStub, Command, ExpectedVersion, FunctionDeclStub, MoveCmd, PetalManifestStub,
    PetalRef, PqSignature, PtbTx, UseRef, encode_ptb,
};

use bloom_petal_dex_it::dex_harness::{
    addr, build_state, genesis_coin_id, ptb_decode_coin_value, single_manifest, wat_to_wasm,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sum all `Coin<LOOM>` values owned by `owner`.
fn sum_coin_loom(state: &State, owner: Address) -> u128 {
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

/// Submit a PTB without applying the write set. Returns `ExecOutput`.
fn submit_raw(
    state: &mut State,
    sender: Address,
    ptb: PtbTx,
    manifests: HashMap<Hash32, PetalManifestStub>,
) -> bloom_chain_node::consensus_driver::ExecOutput {
    let ptb_bytes = encode_ptb(&ptb).expect("PTB encode must not fail");
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 0,
        max_fuel: 1_000_000,
        fee_per_unit: 0,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: PubKeyBytes(vec![0u8; 32]),
        sig: SigBytes(vec![0u8; 64]),
    };
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    exec.execute_tx(
        &tx,
        state,
        100,
        1_700_000_000_000,
        addr(0xAA),
        Hash32([0u8; 32]),
    )
}

/// WAT petal that deliberately aborts (returns non-zero exit code).
const ABORT_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_deliberate_abort") (param i32 i32) (result i32)
    ;; return non-zero = petal-side abort
    i32.const 1)
)
"#;

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

// ---------------------------------------------------------------------------
// Test 1: cmd0 succeeds (SplitCoins), cmd1 deliberately aborts.
//
// PTB:
//   cmd 0: Move(load_coin, Arg::Object(alice_coin, Mutable)) → returns coin id
//   cmd 1: SplitCoins(Use(0,0), [100]) → transient Coin<LOOM>(100) created
//   cmd 2: Move(deliberate_abort) → returns non-zero (petal-side abort)
//
// Expected:
//   - success == false
//   - write_set == None
//   - alice's coin unchanged (still 1000)
//   - alice's ownership index unchanged
// ---------------------------------------------------------------------------

#[test]
fn ptb_second_command_abort_rolls_back_first() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000)]);
    let alice_coin_id = genesis_coin_id(alice, 0);

    // Record pre-tx state.
    let root_before = state.state_root();

    // Insert petals.
    let loader_wasm = wat_to_wasm(&coin_loader_wat(alice_coin_id));
    let loader_hash = state.insert_code(&loader_wasm);

    let abort_wasm = wat_to_wasm(ABORT_WAT);
    let abort_hash = state.insert_code(&abort_wasm);

    // Note: state_root changes when we insert code (code_root updates).
    // We snapshot alice's object state separately.

    let mut manifests: HashMap<Hash32, PetalManifestStub> = HashMap::new();
    manifests.insert(
        loader_hash,
        PetalManifestStub {
            module_path: "/test/loader".to_string(),
            functions: vec![FunctionDeclStub {
                name: "load_coin".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Object {
                    ty: type_tag_coin_loom(),
                    mode: AccessMode::Mutable,
                }],
                returns: vec![type_tag_coin_loom()],
                attached_invariants: vec![],
            }],
            ..Default::default()
        },
    );
    manifests.insert(
        abort_hash,
        single_manifest(abort_hash, "deliberate_abort")[&abort_hash].clone(),
    );

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            // cmd 0: Move(load_coin) → returns alice_coin_id in slot 0
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: String::new(),
                    hash: Some(loader_hash),
                },
                function: "load_coin".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: alice_coin_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::Mutable,
                }],
            }),
            // cmd 1: SplitCoins(alice_coin, [100]) — produces transient coin
            Command::SplitCoins {
                src: UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                amounts: vec![100],
            },
            // cmd 2: Move(deliberate_abort) — aborts, rolling back the whole PTB
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: String::new(),
                    hash: Some(abort_hash),
                },
                function: "deliberate_abort".to_string(),
                type_args: vec![],
                args: vec![],
            }),
        ],
        gas_payer: alice_coin_id,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_raw(&mut state, alice, ptb, manifests);

    // ── Core atomicity assertions ─────────────────────────────────────────────
    assert!(!out.success, "PTB with deliberate abort must fail");
    assert!(
        out.write_set.is_none(),
        "failed PTB must produce no write set"
    );
    assert!(out.logs.is_empty(), "failed PTB must produce no logs");

    // ── State unchanged ────────────────────────────────────────────────────────
    // alice's coin must be unchanged.
    let alice_coin = state
        .get_object(&alice_coin_id)
        .expect("alice's coin must still exist after revert");
    let alice_val = ptb_decode_coin_value(&alice_coin.payload);
    assert_eq!(
        alice_val, 1_000,
        "alice's coin value must be 1000 after revert"
    );

    // alice's total Coin<LOOM> sum must be unchanged.
    assert_eq!(
        sum_coin_loom(&state, alice),
        1_000,
        "alice's total Coin<LOOM> must still be 1000"
    );

    // Ownership index must be unchanged: alice still owns exactly her genesis coin.
    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: alice.0,
    };
    let owned = state.get_ownership(&okey).unwrap_or_default();
    assert!(
        owned.contains(&alice_coin_id),
        "alice's ownership index must still contain her genesis coin"
    );

    // The state root (excluding code_root which changed on petal insert)
    // is verified indirectly via the object + ownership assertions above.
    // We cannot compare root_before == root_after because insert_code mutates
    // code_root. Instead we assert the object_root portion is unchanged by
    // verifying alice's objects are in their pre-tx state.
    let _ = root_before; // acknowledged: code insertions change code_root
}

// ---------------------------------------------------------------------------
// Test 2: Linearity violation — SplitCoins without TransferObjects.
//
// cmd 0: Move(load_coin) → returns alice_coin_id
// cmd 1: SplitCoins(Use(0,0), [200]) → transient Coin<LOOM>(200)
// (no TransferObjects → linearity check fails at tx-end)
//
// Expected: success=false, write_set=None, alice's coin unchanged.
// ---------------------------------------------------------------------------

#[test]
fn ptb_orphaned_split_coin_rolls_back() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000)]);
    let alice_coin_id = genesis_coin_id(alice, 0);

    let loader_wasm = wat_to_wasm(&coin_loader_wat(alice_coin_id));
    let loader_hash = state.insert_code(&loader_wasm);

    let mut manifests: HashMap<Hash32, PetalManifestStub> = HashMap::new();
    manifests.insert(
        loader_hash,
        PetalManifestStub {
            module_path: "/dex/loader".to_string(),
            functions: vec![FunctionDeclStub {
                name: "load_coin".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Object {
                    ty: type_tag_coin_loom(),
                    mode: AccessMode::Mutable,
                }],
                returns: vec![type_tag_coin_loom()],
                attached_invariants: vec![],
            }],
            ..Default::default()
        },
    );

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            // cmd 0: load alice's coin
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: String::new(),
                    hash: Some(loader_hash),
                },
                function: "load_coin".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: alice_coin_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::Mutable,
                }],
            }),
            // cmd 1: SplitCoins — produces orphaned transient coin
            Command::SplitCoins {
                src: UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
                amounts: vec![200],
            },
            // NO TransferObjects → linearity violation at tx-end.
        ],
        gas_payer: alice_coin_id,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_raw(&mut state, alice, ptb, manifests);

    assert!(!out.success, "linearity violation must fail");
    assert!(out.write_set.is_none(), "revert must produce no write set");

    // Alice's coin unchanged.
    let alice_coin = state
        .get_object(&alice_coin_id)
        .expect("alice's coin must exist");
    let alice_val = ptb_decode_coin_value(&alice_coin.payload);
    assert_eq!(
        alice_val, 1_000,
        "alice's coin must be 1000 after linearity revert"
    );

    // alice total unchanged.
    assert_eq!(
        sum_coin_loom(&state, alice),
        1_000,
        "alice total Coin<LOOM> must be 1000"
    );
}
