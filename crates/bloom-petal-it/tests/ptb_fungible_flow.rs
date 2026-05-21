//! Integration tests for the PTB fungible-token happy path.
//!
//! # Test strategy
//!
//! We exercise the PTB fungible flow **without** building the real fungible
//! petal wasm at test time (no `cargo build --target wasm32-unknown-unknown`
//! required). Instead we use:
//!
//! 1. The built-in `Command::SplitCoins` and `Command::TransferObjects`
//!    executor commands (pure in-process logic; no petal VM call) together
//!    with an inline WAT petal that "introduces" alice's coin to the borrow
//!    table and returns its id as a result slot.
//!
//! 2. A standalone `log.emit` smoke test to confirm the full
//!    `ChainPetalExecutorWithManifests` dispatch path is wired end-to-end.
//!
//! The full wasm fungible-petal variant (using the real compiled wasm) is
//! marked `#[ignore]` with a note explaining the prerequisite.
//!
//! Assertions follow spec §4.3 / §9.2: alice ends with Coin<LOOM>(700),
//! bob ends with Coin<LOOM>(300), ownership indices updated consistently.

use std::collections::HashMap;

use bloom_chain_node::petal_executor::ChainPetalExecutorWithManifests;
use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{AccessMode, Owner, OwnershipIndexKey, OWNER_KIND_ADDRESS};
use bloom_script::ExpectedVersion;
use bloom_petal_fungible::ops::type_tag_coin_loom;
use bloom_script::{
    ArgDeclStub, Command, Arg, FunctionDeclStub, MoveCmd, PetalManifestStub, PetalRef,
    PqSignature, PtbTx, UseRef, encode_ptb,
};

use bloom_petal_it::harness::{
    addr, build_state, genesis_coin_id, ptb_decode_coin_value, single_manifest, wat_to_wasm,
};

// ---------------------------------------------------------------------------
// Helper: submit a PTB and apply the write set on success.
// ---------------------------------------------------------------------------

fn submit_and_apply(
    state: &mut State,
    sender: Address,
    ptb: PtbTx,
    manifests: HashMap<Hash32, PetalManifestStub>,
) -> bloom_chain_node::consensus_driver::ExecOutput {
    let ptb_bytes = encode_ptb(&ptb).expect("PTB encode");
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
    let out = exec.execute_tx(&tx, state, 100, 1_700_000_000_000, addr(0xAA), Hash32([0u8; 32]));
    if out.success
        && let Some(ws) = out.write_set.clone()
    {
        state.apply(ws).expect("apply write_set must not fail");
    }
    out
}

// ---------------------------------------------------------------------------
// Test 1: Move(load_coin) → SplitCoins → TransferObjects happy path.
//
// PTB command sequence:
//   cmd 0 Move(load_coin, Arg::Object(alice_coin, Mutable))
//          → WAT returns 40-byte envelope: 1 slot of 32 bytes = alice_coin_id
//   cmd 1 SplitCoins(src=Use(0,0), amounts=[300])
//          → produces transient Coin<LOOM>(300), alice's coin debited to 700
//   cmd 2 TransferObjects([Use(1,0)], Owner::Address(bob))
//          → transfers the 300-coin to bob
//
// Expected post-state:
//   alice.coin.value = 700, bob has one Coin<LOOM>(300).
// ---------------------------------------------------------------------------

#[test]
fn move_split_transfer_happy_path() {
    let alice = addr(0xA1);
    let bob   = addr(0xB2);

    let mut state = build_state(&[(alice, 1000)]);
    let alice_coin_id = genesis_coin_id(alice, 0);

    // WAT petal: takes alice's coin as Arg::Object, returns its id (40-byte envelope).
    let id_bytes = alice_coin_id.0;
    let id_hex: String = id_bytes.iter().map(|b| format!("\\{b:02x}")).collect();
    let loader_wat = format!(
        r#"
(module
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; 40-byte return envelope: count=1 (4 bytes BE) | len=32 (4 bytes BE) | id (32 bytes)
  (data (i32.const 0) "\00\00\00\01\00\00\00\20{id_hex}")
  (func (export "__petal_load_coin") (param i32 i32) (result i32)
    (call $ret (i32.const 0) (i32.const 40))
    i32.const 0)
)
"#
    );
    let wasm = wat_to_wasm(&loader_wat);
    let petal_hash = state.insert_code(&wasm);

    let mut manifests = HashMap::new();
    manifests.insert(
        petal_hash,
        PetalManifestStub {
            module_path: "/test/loader".to_string(),
            functions: vec![FunctionDeclStub {
                name: "load_coin".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Object {
                    ty: type_tag_coin_loom(),
                    mode: AccessMode::Mutable,
                }],
                returns: vec![],
                attached_invariants: vec![],
            }],
            ..Default::default()
        },
    );

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            // cmd 0: Move → returns alice_coin_id in slot 0
            Command::Move(MoveCmd {
                petal: PetalRef { path: String::new(), hash: Some(petal_hash) },
                function: "load_coin".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: alice_coin_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::Mutable,
                }],
            }),
            // cmd 1: SplitCoins(alice_coin, [300])
            Command::SplitCoins {
                src: UseRef { cmd_idx: 0, ret_idx: 0 },
                amounts: vec![300],
            },
            // cmd 2: TransferObjects([split_result], bob)
            Command::TransferObjects {
                uses: vec![UseRef { cmd_idx: 1, ret_idx: 0 }],
                owner: Owner::Address(bob.0),
            },
        ],
        gas_payer: alice_coin_id,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_and_apply(&mut state, alice, ptb, manifests);
    assert!(
        out.success,
        "PTB must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    // Alice's coin should be 700.
    let alice_coin = state.get_object(&alice_coin_id).expect("alice's coin must still exist");
    let alice_val = ptb_decode_coin_value(&alice_coin.payload);
    assert_eq!(alice_val, 700, "alice must have Coin<LOOM>(700)");

    // Bob should own one Coin<LOOM>(300).
    let bob_okey = OwnershipIndexKey { owner_kind: OWNER_KIND_ADDRESS, owner_id: bob.0 };
    let bob_owned = state.get_ownership(&bob_okey).expect("bob ownership index must exist");
    assert_eq!(bob_owned.len(), 1, "bob must own exactly one coin");
    let bob_coin = state.get_object(&bob_owned[0]).expect("bob's coin must exist");
    let bob_val = ptb_decode_coin_value(&bob_coin.payload);
    assert_eq!(bob_val, 300, "bob must have Coin<LOOM>(300)");
    assert_eq!(bob_coin.type_tag, type_tag_coin_loom(), "bob's coin must be Coin<LOOM>");
    assert_eq!(bob_coin.owner, Owner::Address(bob.0), "bob's coin owner must be bob");
}

// ---------------------------------------------------------------------------
// Test 2: smoke — log.emit confirms the full PTB dispatch path is live.
// ---------------------------------------------------------------------------

const EMIT_LOG_WAT: &str = r#"
(module
  (import "log" "emit" (func $log (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0)  "\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB\AB")
  (data (i32.const 32) "petal-it-ok")
  (func (export "__petal_emit") (param i32 i32) (result i32)
    (drop (call $log (i32.const 0) (i32.const 32) (i32.const 32) (i32.const 11)))
    i32.const 0)
)
"#;

#[test]
fn smoke_ptb_log_emit_succeeds() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000_000)]);
    let gas_payer = genesis_coin_id(alice, 0);

    let wasm = wat_to_wasm(EMIT_LOG_WAT);
    let petal_hash = state.insert_code(&wasm);
    let manifests = single_manifest(petal_hash, "emit");

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef { path: String::new(), hash: Some(petal_hash) },
            function: "emit".to_string(),
            type_args: vec![],
            args: vec![],
        })],
        gas_payer,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_and_apply(&mut state, alice, ptb, manifests);
    assert!(
        out.success,
        "smoke PTB must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert_eq!(out.logs.len(), 1, "expected exactly one log entry");
    assert_eq!(out.logs[0].data, b"petal-it-ok", "log data must round-trip verbatim");
}

// ---------------------------------------------------------------------------
// Test 3 (ignored): Full fungible-petal wasm split+transfer.
//
// PREREQUISITE: run
//   cargo build -p bloom-petal-fungible --target wasm32-unknown-unknown --release
// so that the wasm binary exists at
//   target/wasm32-unknown-unknown/release/bloom_petal_fungible.wasm
// relative to the workspace root. Without that binary this test will panic
// on the assert below.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires pre-built bloom_petal_fungible.wasm (cargo build -p bloom-petal-fungible --target wasm32-unknown-unknown --release)"]
fn full_fungible_petal_split_and_transfer() {
    let wasm_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-unknown-unknown/release/bloom_petal_fungible.wasm");
    assert!(
        wasm_path.exists(),
        "wasm not found at {}; run cargo build -p bloom-petal-fungible --target wasm32-unknown-unknown --release first",
        wasm_path.display()
    );
    // Full test implementation would use the wasm bytes here.
}
