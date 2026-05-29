//! Category: feature (regression — P1-2, spec §16.3).
//!
//! `OwnershipIndex` rebuild must be **owner-symmetric**: when a PTB
//! transfers an object from `A` to `B`, the chain-node's commit step
//! must rebuild the index row for *both* `A` (drop the id) and `B`
//! (gain the id). When a PTB deletes an object, the index row for
//! its prior owner must be rebuilt to drop the id. Earlier
//! revisions only rebuilt the new-owner row on transfer and didn't
//! rebuild any row on delete, leaving stale ids in the trie.
//!
//! This test drives the production `ChainPetalExecutorWithManifests`
//! end-to-end against a freshly built `State`:
//!
//!   1. Seed an object `id` with `Owner::Address(A)`; seed `A`'s
//!      ownership row to `[id]`.
//!   2. Submit a PTB that calls a type-defining petal's `xfer`
//!      export. The petal does `object.borrow(id) → handle`,
//!      `object.transfer(handle, Address(B))` via §16.2 host
//!      imports.
//!   3. Apply the resulting `WriteSet` and assert:
//!      - `A`'s ownership row is absent (the only id transferred
//!        away — set_ownership evicts empty rows),
//!      - `B`'s ownership row is `[id]`.
//!   4. Submit a second PTB calling the same petal's `del` export,
//!      which `object.delete`s the object (only the type-defining
//!      petal can call delete).
//!   5. Apply the resulting `WriteSet` and assert `B`'s ownership
//!      row is absent.

use std::collections::HashMap;

use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::ChainPetalExecutorWithManifests;
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{
    AccessMode, OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey, TypeTag,
};
use bloom_script::{
    CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH,
    chain_iface::{ArgDeclStub, FunctionDeclStub, PetalManifestStub},
    encode_ptb, loom_coin_type_tag,
    types::{Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, PtbTx},
};

/// Address slots used throughout the test.
const ADDR_A: [u8; 32] = [0xAA; 32];
const ADDR_B: [u8; 32] = [0xBB; 32];

/// The deterministic id of the object the PTB hands around.
const OBJ_ID_BYTE: u8 = 0x77;

/// Sender field for both PTB envelopes — not load-bearing; the
/// executor doesn't look this up before dispatching to the PTB
/// branch.
fn ptb_sender() -> Address {
    Address([0x11; 32])
}

/// Build the smallest possible `TxKind::SubmitPtb` transaction.
fn submit_ptb_tx(sender: Address, ptb_bytes: Vec<u8>) -> Tx {
    Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce: 0,
        max_fuel: 1_000_000,
        fee_per_unit: 0,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: PubKeyBytes(vec![0u8; 32]),
        sig: SigBytes(vec![0u8; 64]),
    }
}

/// Build the canonical `Coin<LOOM>` payload for a balance.
fn coin_payload(value: u128) -> Vec<u8> {
    let mut p = vec![0u8; 32];
    p.extend_from_slice(&value.to_be_bytes());
    p
}

/// Mint a `Coin<LOOM>` object owned by `owner` for fee coverage.
fn make_loom_coin(id: ObjectId, owner: [u8; 32], value: u128) -> Object {
    Object {
        id,
        type_tag: loom_coin_type_tag(Hash32([0u8; 32])),
        owner: Owner::Address(owner),
        version: 1,
        payload: coin_payload(value),
    }
}

/// Parse a WAT source string into wasm bytes.
fn wat(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

// ---------------------------------------------------------------------------
// Type-defining petal: exports `__petal_xfer` and `__petal_del`.
//
// Layout of `Arg::Object` on the marshalled calldata stream:
//   offset 0..4   = u32 BE count
//   offset 4..5   = u8 tag = 2 (Arg::Object)
//   offset 5..37  = 32 id bytes
//
// `__petal_xfer`:
//   - reads 37 calldata bytes into mem[0..37];
//   - calls `object.borrow(id_ptr=5, mode=Mutable=1)` -> handle;
//   - calls `object.transfer(handle, kind=Address(0),
//     recipient_ptr=64, recipient_len=32)` where mem[64..96] holds
//     ADDR_B (pre-seeded via `(data ...)`).
//
// `__petal_del`:
//   - reads 37 calldata bytes into mem[0..37];
//   - calls `object.borrow(id_ptr=5, mode=Consume=2)` -> handle;
//   - calls `object.delete(handle)`.
// ---------------------------------------------------------------------------

const TRANSFER_AND_DELETE_PETAL: &str = r#"
(module
  (import "chain"  "msg.calldata.read"
    (func $cdread (param i32 i32 i32) (result i32)))
  (import "object" "borrow"   (func $borrow (param i32 i32) (result i32)))
  (import "object" "transfer" (func $xfer (param i32 i32 i32 i32) (result i32)))
  (import "object" "delete"   (func $del  (param i32) (result i32)))
  (memory (export "memory") 1)

  ;; Pre-seed ADDR_B (32 bytes of 0xBB) at offset 64 — recipient for
  ;; the transfer call.
  (data (i32.const 64) "\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb")

  (func (export "__petal_xfer") (param i32 i32) (result i32)
    ;; Pull the 37-byte Arg::Object calldata envelope into mem[0..37].
    (drop (call $cdread (i32.const 0) (i32.const 0) (i32.const 37)))
    ;; object.borrow(id_ptr=5, mode=Mutable=1) -> handle.
    ;; object.transfer(handle, kind=Address(0), recipient_ptr=64, 32).
    (drop (call $xfer
            (call $borrow (i32.const 5) (i32.const 1))
            (i32.const 0)
            (i32.const 64)
            (i32.const 32)))
    i32.const 0)

  (func (export "__petal_del") (param i32 i32) (result i32)
    (drop (call $cdread (i32.const 0) (i32.const 0) (i32.const 37)))
    ;; object.borrow(id_ptr=5, mode=Consume=2) -> handle.
    (drop (call $del (call $borrow (i32.const 5) (i32.const 2))))
    i32.const 0)
)
"#;

/// Build a manifest stub declaring `xfer` and `del` — each takes one
/// `Object` arg.
fn manifest_for(obj_type: TypeTag) -> PetalManifestStub {
    PetalManifestStub {
        module_path: "/test/p1-2".to_string(),
        functions: vec![
            FunctionDeclStub {
                view: false,
                name: "xfer".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Object {
                    ty: obj_type.clone(),
                    mode: AccessMode::Mutable,
                }],
                returns: vec![],
                attached_invariants: vec![],
            },
            FunctionDeclStub {
                view: false,
                name: "del".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Object {
                    ty: obj_type,
                    mode: AccessMode::Consume,
                }],
                returns: vec![],
                attached_invariants: vec![],
            },
        ],
        ..Default::default()
    }
}

/// Build a `PtbTx` with a single `Command::Move` calling `fn_name`
/// against `petal_hash`, signed (sham PQ sig) by `signer`, with one
/// `Arg::Object` referencing `obj_id` at `expected_version` and the
/// requested access mode.
#[allow(clippy::too_many_arguments)]
fn single_move_with_object(
    signer: [u8; 32],
    petal_hash: Hash32,
    fn_name: &str,
    gas_payer: ObjectId,
    obj_id: ObjectId,
    expected_version: u64,
    mode: AccessMode,
    expiry_block: u64,
) -> PtbTx {
    PtbTx {
        signers: vec![signer],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: String::new(),
                hash: Some(petal_hash),
            },
            function: fn_name.to_string(),
            type_args: vec![],
            args: vec![Arg::Object {
                id: obj_id,
                expected_version: ExpectedVersion(expected_version),
                access_mode: mode,
            }],
        })],
        gas_payer,
        gas_budget: 200_000,
        gas_price: 1,
        expiry_block,
        signatures: vec![PqSignature(vec![0u8; 64])],
    }
}

/// P1-2 (spec §16.3): owner-symmetric ownership-index rebuild.
///
/// Drives the same petal through transfer then delete, asserting
/// the index converges to the expected shape at each step.
#[test]
fn ownership_index_rebuilds_for_old_and_new_owners_on_transfer_then_delete() {
    // ---- Seed ----------------------------------------------------------
    let mut state = State::new();
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
    let wasm = wat(TRANSFER_AND_DELETE_PETAL);
    let petal_hash = state.insert_code(&wasm);

    // Object's TypeTag uses this petal as its defining petal so
    // `object.delete` from inside this petal is permitted.
    let obj_type = TypeTag::Concrete {
        petal_hash: petal_hash.0,
        type_name: "Widget".to_string(),
        type_args: vec![],
    };

    // Single object owned by A, version 0.
    let obj_id = ObjectId([OBJ_ID_BYTE; 32]);
    state.set_object(Object {
        id: obj_id,
        type_tag: obj_type.clone(),
        owner: Owner::Address(ADDR_A),
        version: 0,
        payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
    });
    // Seed A's ownership-index row with the object's id so we can
    // detect the rebuild's eviction step.
    let a_key = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: ADDR_A,
    };
    let b_key = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: ADDR_B,
    };
    state.set_ownership(a_key, vec![obj_id]);
    assert_eq!(
        state.get_ownership(&a_key),
        Some(vec![obj_id]),
        "seed: A's index must start with [id]"
    );
    assert!(
        state.get_ownership(&b_key).is_none(),
        "seed: B's index must start empty"
    );

    // Gas payers for the two PTBs (each PTB consumes its own gas
    // coin — once a coin is referenced in a PTB the validator marks
    // it as "expected version" and the executor bumps its version
    // implicitly through the borrow-table commit step). Using two
    // distinct gas coins sidesteps that bookkeeping.
    let gas_payer_xfer = ObjectId([0xC1; 32]);
    let gas_payer_del = ObjectId([0xC2; 32]);
    state.set_object(make_loom_coin(gas_payer_xfer, ADDR_A, 1_000_000_000));
    state.set_object(make_loom_coin(gas_payer_del, ADDR_B, 1_000_000_000));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_for(obj_type.clone()));

    // ---- Step 1: transfer A -> B --------------------------------------
    let xfer_ptb = single_move_with_object(
        ADDR_A,
        petal_hash,
        "xfer",
        gas_payer_xfer,
        obj_id,
        0,
        AccessMode::Mutable,
        100,
    );
    let xfer_bytes = encode_ptb(&xfer_ptb).expect("encode xfer PTB");
    let tx = submit_ptb_tx(ptb_sender(), xfer_bytes);

    let exec = ChainPetalExecutorWithManifests::new(manifests.clone());
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAB; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );
    assert!(
        out.success,
        "xfer PTB must commit: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    let ws = out.write_set.expect("xfer PTB must emit write set");
    state.apply(ws).expect("apply xfer write set");

    // Post-transfer assertions ------------------------------------------
    // The object moves to B.
    let after_xfer = state
        .get_object(&obj_id)
        .expect("object must still exist after xfer");
    assert_eq!(after_xfer.owner, Owner::Address(ADDR_B), "owner must be B");

    // A's ownership row must be evicted (only id transferred away).
    assert!(
        state.get_ownership(&a_key).is_none(),
        "A's index row must be empty/evicted after xfer; got: {:?}",
        state.get_ownership(&a_key)
    );
    // B's ownership row must contain the id.
    let b_row = state
        .get_ownership(&b_key)
        .expect("B's index row must exist after xfer");
    assert_eq!(
        b_row,
        vec![obj_id],
        "B's index row must contain [obj_id] exactly"
    );

    // ---- Step 2: delete (called by the type-defining petal) ----------
    // The post-xfer object version is whatever the executor bumped to.
    let post_xfer_version = after_xfer.version;
    let del_ptb = single_move_with_object(
        ADDR_B,
        petal_hash,
        "del",
        gas_payer_del,
        obj_id,
        post_xfer_version,
        AccessMode::Consume,
        200,
    );
    let del_bytes = encode_ptb(&del_ptb).expect("encode del PTB");
    let tx2 = submit_ptb_tx(ptb_sender(), del_bytes);

    let exec2 = ChainPetalExecutorWithManifests::new(manifests);
    let out2 = exec2.execute_tx(
        &tx2,
        &mut state,
        /* block_number */ 101,
        /* timestamp_ms */ 1_700_000_001_000,
        /* proposer    */ Address([0xAB; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );
    assert!(
        out2.success,
        "del PTB must commit: {}",
        String::from_utf8_lossy(&out2.return_data)
    );
    let ws2 = out2.write_set.expect("del PTB must emit write set");
    state.apply(ws2).expect("apply del write set");

    // Post-delete assertions --------------------------------------------
    assert!(
        state.get_object(&obj_id).is_none(),
        "object must be gone after delete"
    );
    // B's row must now be evicted.
    assert!(
        state.get_ownership(&b_key).is_none(),
        "B's index row must be empty/evicted after delete; got: {:?}",
        state.get_ownership(&b_key)
    );
    // A's row remains absent (never re-populated).
    assert!(
        state.get_ownership(&a_key).is_none(),
        "A's index row must remain empty after delete"
    );
}
