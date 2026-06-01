//! Category: feature
//!
//! Integration tests for `TxKind::SubmitPtb` activation (Task #31 + #38).
//!
//! Each test wires `ChainPetalExecutor::execute_tx` (or its manifest-
//! aware sibling `ChainPetalExecutorWithManifests`) directly against a
//! freshly built `State`, mirroring what `apply_block_state_transitions`
//! does, and asserts on the resulting `ExecOutput`.
//!
//! Test plan (spec §16.2):
//!   1. Undecodable PTB bytes → revert with decode-error reason; no
//!      write set.
//!   2. Validator-rejected PTB (zero signers) → revert atomically; no
//!      write set, no logs.
//!   3. `signer.address(0)` host import returns the PTB's first-signer
//!      pubkey bytes in the receipt's return slot.
//!   4. `log.emit` host import round-trips topic + data into the
//!      receipt's `logs` vector.
//!   5. Out-of-fuel during a petal call surfaces as PTB revert with no
//!      state diff, no logs, and `fuel_used` close to the budget.
//!
//! Per the original Task #31 brief (`/goal` 2026-05-20), each test
//! drives the production `ChainPetalExecutor` end-to-end; no
//! production code paths are mocked.

use std::collections::HashMap;

use bloom_chain_node::consensus_driver::PetalExecutor;
use bloom_chain_node::petal_executor::{ChainPetalExecutor, ChainPetalExecutorWithManifests};
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey, TypeTag};
use bloom_script::{
    CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH,
    chain_iface::{ArgDeclStub, FunctionDeclStub, PetalManifestStub},
    encode_ptb, loom_coin_type_tag,
    types::{Arg, Command, MoveCmd, PetalRef, PqSignature, PtbTx},
};

/// Build the smallest possible `TxKind::SubmitPtb` transaction with
/// the given PTB bytes. Fuel/fees are zero — the executor does not
/// debit them itself (that's `apply_block`'s job).
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

/// Sender used across these tests; not load-bearing — the executor
/// does not look the account up before dispatching to the PTB path.
fn test_sender() -> Address {
    Address([0x11u8; 32])
}

/// Test 1: PTB bytes that do not decode (empty payload) MUST revert
/// with `success = false`, `write_set = None`, and a revert reason
/// that mentions decode failure — not the legacy
/// `NotYetActivated: SubmitPtb (Phase 1)` placeholder.
#[test]
fn undecodable_ptb_bytes_revert_atomically() {
    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    let sender = test_sender();

    // Empty bytes are not a valid canonical PTB encoding.
    let tx = submit_ptb_tx(sender, Vec::new());

    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAAu8; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(!out.success, "undecodable PTB must revert");
    assert!(out.write_set.is_none(), "revert must drop write set");
    assert!(out.logs.is_empty(), "revert must drop logs");

    let reason = String::from_utf8_lossy(&out.return_data);
    assert!(
        !reason.contains("NotYetActivated"),
        "SubmitPtb dispatcher is still the Phase-1 placeholder: {reason}"
    );
    assert!(
        reason.to_lowercase().contains("decode") || reason.to_lowercase().contains("invalid"),
        "expected decode/invalid revert reason, got: {reason}"
    );
}

/// Test 2: A structurally-decodable PTB that the validator rejects
/// (here: zero signers) MUST revert atomically. No write set, no logs,
/// and a reason that surfaces the validator error — not the decoder.
#[test]
fn validator_rejected_ptb_reverts_atomically() {
    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    let sender = test_sender();

    // Empty PtbTx decodes fine but fails validation immediately at the
    // signer-count check (`PtbError::NoSigners`).
    let ptb = PtbTx::default();
    let bytes = encode_ptb(&ptb).expect("encode empty PTB");
    let tx = submit_ptb_tx(sender, bytes);

    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAAu8; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(!out.success, "validator-rejected PTB must revert");
    assert!(
        out.write_set.is_none(),
        "validator rejection must drop write set"
    );
    assert!(out.logs.is_empty(), "validator rejection must drop logs");

    let reason = String::from_utf8_lossy(&out.return_data);
    assert!(
        reason.to_lowercase().contains("signer")
            || reason.to_lowercase().contains("validation")
            || reason.to_lowercase().contains("nosigners")
            || reason.to_lowercase().contains("validator"),
        "expected validator error reason, got: {reason}"
    );
}

#[test]
fn missing_fungible_binding_rejects_submit_ptb_before_zero_hash_fallback() {
    let mut state = State::new();
    let sender = test_sender();

    let ptb = PtbTx::default();
    let bytes = encode_ptb(&ptb).expect("encode empty PTB");
    let tx = submit_ptb_tx(sender, bytes);

    let exec = ChainPetalExecutor;
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAAu8; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(!out.success, "missing fungible binding must fail closed");
    assert!(out.write_set.is_none(), "failure must not mutate state");
    let reason = String::from_utf8_lossy(&out.return_data);
    assert!(
        reason.contains("missing required VFS binding"),
        "expected missing binding error, got: {reason}"
    );
}

// ---------------------------------------------------------------------------
// Subtask D — §16.2 host-import end-to-end fixtures (Task #38)
//
// These tests exercise the *full* SubmitPtb path:
//   PTB decode → validator → executor.execute → ChainPetalRunner →
//   PetalVm::run_chain_call (with the real wasmtime engine) → §16.2
//   host imports → drained PtbHostCtx → folded into the chain WriteSet.
//
// They deliberately use inline WAT fixtures rather than building real
// bloom-resource-macros petals because we want the e2e wiring to be the
// only thing under test; the macro crate has its own integration suite.
// The wasm here imports only the §16.2 host-import surface
// (`signer.*`, `log.*`) and the legacy `chain.petal.return` (used to
// shuttle bytes from wasm memory into `ChainCallOutput.return_data` and
// thence into `PetalCallResult.ret_buf`).
//
// Wiring sketch shared by all three tests:
//   1. Mint a deterministic signer pubkey + matching gas-payer
//      `Coin<LOOM>` object owned by `Owner::Address(signer)`.
//   2. Pre-deploy the petal wasm via `state.insert_code` so the
//      validator's `load_petal` lookup succeeds without going through a
//      `Deploy` tx (those need real xDSA signatures we don't want to
//      mint here).
//   3. Build a `PtbTx` with a single `Command::Move` targeting a
//      `__petal_<fn>` export the WAT module declares.
//   4. Build a `ChainPetalExecutorWithManifests` carrying a stub manifest
//      whose `FunctionDeclStub` matches the Move call's arity (zero
//      args, zero returns).
//   5. Dispatch through `execute_tx` and assert on the resulting
//      `ExecOutput`.
// ---------------------------------------------------------------------------

/// Parse a WAT source string into wasm bytes. Panics on malformed WAT
/// because every fixture in this file is statically valid.
fn wat(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

/// Build the canonical `Coin<LOOM>` payload for a balance.
///
/// Canonical on-chain format: [ObjectId placeholder (32 bytes)] || [value BE (16 bytes)].
fn coin_payload(value: u128) -> Vec<u8> {
    let mut p = vec![0u8; 32];
    p.extend_from_slice(&value.to_be_bytes());
    p
}

/// Mint a `Coin<LOOM>` object at `id` owned by `owner`, holding
/// `value` bloomwei. Tests bind the bootstrap fungible VFS path to the
/// sentinel hash explicitly, matching pre-pin genesis behavior.
fn make_loom_coin(id: ObjectId, owner: [u8; 32], value: u128) -> Object {
    Object {
        id,
        type_tag: loom_coin_type_tag(DEFAULT_FUNGIBLE_PETAL_HASH),
        owner: Owner::Address(owner),
        version: 1,
        payload: coin_payload(value),
    }
}

fn bind_bootstrap_fungible(state: &mut State) {
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
}

/// Build a manifest stub declaring a single zero-arg, zero-return
/// `__petal_<fn>` function — the surface the validator's typecheck
/// (step 4) needs.
fn manifest_with_nullary_fn(fn_name: &str) -> PetalManifestStub {
    manifest_with_nullary_fn_returns(fn_name, vec![])
}

fn manifest_with_nullary_fn_returns(fn_name: &str, returns: Vec<TypeTag>) -> PetalManifestStub {
    PetalManifestStub {
        module_path: "/test/e2e".to_string(),
        functions: vec![FunctionDeclStub {
            view: false,
            name: fn_name.to_string(),
            type_params: vec![],
            args: vec![],
            returns,
            required_signers: 0,
            required_capabilities: vec![],
            attached_invariants: vec![],
        }],
        ..Default::default()
    }
}

/// Build a `PtbTx` with a single `Command::Move` calling `fn_name`
/// against the petal at `petal_hash`, signed (sham PQ sig) by
/// `signer`, and paying gas out of `gas_payer`.
fn nullary_move_ptb(
    signer: [u8; 32],
    petal_hash: Hash32,
    fn_name: &str,
    gas_payer: ObjectId,
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
            args: vec![],
        })],
        gas_payer,
        gas_budget: 200_000,
        gas_price: 1,
        expiry_block,
        // `AlwaysOkVerifier` (the chain-node default until the PQ-key
        // registry lands) accepts any byte buffer; we just need one
        // entry per signer to satisfy the count check.
        signatures: vec![PqSignature(vec![0u8; 64])],
    }
}

// ---------------------------------------------------------------------------
// Test 3 — `signer.address(0)` resolves to the first PTB signer.
//
// The petal calls `signer.address(0, 0)` to write the first signer's
// 32-byte pubkey into wasm memory, then `petal.return`s those bytes so
// they land in `ExecOutput.return_data` via the runner's
// `PetalCallResult.ret_buf`.
//
// We expect:
// - `success = true` (no revert),
// - `return_data` begins with the signer pubkey bytes (the executor's
//   `unmarshal_outputs` may wrap them — we accept either a verbatim
//   prefix or a count-prefixed envelope).
// ---------------------------------------------------------------------------

// The PTB executor parses `petal.return`'d bytes as a length-prefixed
// envelope: `count u32 BE | for each: (len u32 BE | bytes)`. To return
// one 32-byte slot we therefore lay out 40 bytes:
//
//   offset 0..4   = 0x00000001  (count = 1 slot)
//   offset 4..8   = 0x00000020  (len   = 32 bytes)
//   offset 8..40  = 32 bytes the host writes via `signer.address(0, 8)`
//
// Then `petal.return(0, 40)` ships the whole envelope back.
const SIGNER_FETCH_PETAL: &str = r#"
(module
  (import "signer" "address"     (func $sa  (param i32 i32) (result i32)))
  (import "chain"  "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; Pre-seed the length-prefixed envelope header: count=1, len=32 (BE).
  (data (i32.const 0) "\00\00\00\01\00\00\00\20")
  (func (export "__petal_get_signer") (param i32 i32) (result i32)
    ;; signer.address(0, 8) — writes 32 signer bytes after the header.
    (drop (call $sa (i32.const 0) (i32.const 8)))
    ;; Ship the full 40-byte envelope back to the executor.
    (call $ret (i32.const 0) (i32.const 40))
    i32.const 0)
)
"#;

#[test]
fn signer_address_zero_resolves_to_first_signer() {
    let signer = [0x7Au8; 32];
    let gas_payer_id = ObjectId([0xCC; 32]);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    let wasm = wat(SIGNER_FETCH_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, 1_000_000_000));

    let mut manifests = HashMap::new();
    manifests.insert(
        petal_hash,
        manifest_with_nullary_fn_returns("get_signer", vec![TypeTag::External { ref_idx: 0 }]),
    );

    let ptb = nullary_move_ptb(signer, petal_hash, "get_signer", gas_payer_id, 100);
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let tx = submit_ptb_tx(test_sender(), bytes);

    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAA; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(
        out.success,
        "expected PTB success, got revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert!(
        out.write_set.is_some(),
        "successful PTB must emit a write set"
    );

    // The petal returned the 32 raw signer bytes via `petal.return`.
    // The runner stores that buffer in `PetalCallResult.ret_buf` and the
    // executor's `unmarshal_outputs` parses it as the marshalled
    // return-slot envelope. Either way the signer bytes must appear
    // somewhere in the byte stream so an indexer can recover them.
    let signer_window = out.return_data.windows(32).any(|w| w == signer);
    assert!(
        signer_window,
        "expected signer bytes 0x7A..7A somewhere in return_data, got {} bytes: {:?}",
        out.return_data.len(),
        out.return_data
    );
}

// ---------------------------------------------------------------------------
// Test 4 — `log.emit` round-trips topic + data into the receipt logs.
//
// The petal pre-loads a fixed 32-byte topic + 12-byte data payload into
// linear memory via `(data ...)`, then calls `log.emit(0, 32, 32, 12)`.
// We then assert the executor folded the PtbHostCtx log into a single
// `Log` entry on the `ExecOutput`.
// ---------------------------------------------------------------------------

const LOG_EMIT_PETAL: &str = r#"
(module
  (import "log" "emit" (func $log (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; 32 bytes of topic at offset 0 (all 0xCD bytes), 12 bytes of data
  ;; "hello-bloom!" (offset 32). WAT requires single-line strings.
  (data (i32.const 0)  "\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd\cd")
  (data (i32.const 32) "hello-bloom!")
  (func (export "__petal_log_thing") (param i32 i32) (result i32)
    ;; log.emit(topic_ptr=0, topic_len=32, data_ptr=32, data_len=12)
    (drop (call $log (i32.const 0) (i32.const 32) (i32.const 32) (i32.const 12)))
    i32.const 0)
)
"#;

#[test]
fn log_emit_round_trips_topics_and_data() {
    let signer = [0x55u8; 32];
    let gas_payer_id = ObjectId([0xDD; 32]);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    let wasm = wat(LOG_EMIT_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, 1_000_000_000));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("log_thing"));

    let ptb = nullary_move_ptb(signer, petal_hash, "log_thing", gas_payer_id, 100);
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let tx = submit_ptb_tx(test_sender(), bytes);

    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAA; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(
        out.success,
        "expected PTB success, got revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert_eq!(
        out.logs.len(),
        1,
        "expected exactly one log; got {} entries: {:?}",
        out.logs.len(),
        out.logs
    );
    let log = &out.logs[0];

    // `ptb_log_to_receipt_log` (the executor's mapping helper) sets the
    // log's address to the emitting petal's content hash and preserves
    // a 32-byte topic verbatim as a single `Hash32` entry.
    assert_eq!(
        log.address.0, petal_hash.0,
        "log.address must be the emitting petal's hash",
    );
    assert_eq!(
        log.topics.len(),
        1,
        "expected one topic, got {:?}",
        log.topics
    );
    assert_eq!(
        log.topics[0].0, [0xCDu8; 32],
        "topic bytes must round-trip verbatim",
    );
    assert_eq!(
        log.data, b"hello-bloom!",
        "data bytes must round-trip verbatim",
    );
}

// ---------------------------------------------------------------------------
// Test 5 — out-of-fuel during a petal call reverts atomically.
//
// The petal enters an infinite `(loop (br 0))` that the wasm engine
// must trap as "out of fuel" before reaching `petal.return`. The
// ChainPetalRunner's dispatcher translates that trap into
// `PtbError::OutOfFuel`, which the PTB executor records as a
// `revert_with` and bubbles up as `ExecOutput.success = false`.
//
// We expect:
//   - `success = false` (revert),
//   - no logs / no write set (atomic),
//   - revert reason mentions fuel/out-of/oof so explorers can surface
//     the cause distinctly from a regular `petal.revert`.
//
// We intentionally do NOT assert `fuel_used > 0` here: the PTB
// executor's `ExecutionReport.fuel_used` aggregation is wired in
// Phase 2 (today the executor still keeps fuel accounting in the
// thread-local `fuel_remaining` and does not surface it on revert —
// see TODO #36 in `bloom-script/src/executor.rs`).
// ---------------------------------------------------------------------------

const FUEL_BURNER_PETAL: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_burn_fuel") (param i32 i32) (result i32)
    (loop (br 0))
    i32.const 0)
)
"#;

#[test]
fn out_of_fuel_reverts_atomically() {
    let signer = [0x33u8; 32];
    let gas_payer_id = ObjectId([0xEE; 32]);

    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    let wasm = wat(FUEL_BURNER_PETAL);
    let petal_hash = state.insert_code(&wasm);
    // Generous coin so the validator's gas-reservation check succeeds
    // — the OOF trap must be the cause of failure, not insufficient gas.
    state.set_object(make_loom_coin(gas_payer_id, signer, 1_000_000_000));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("burn_fuel"));

    let ptb = nullary_move_ptb(signer, petal_hash, "burn_fuel", gas_payer_id, 100);
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let tx = submit_ptb_tx(test_sender(), bytes);

    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAA; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    assert!(!out.success, "out-of-fuel must revert");
    // P0-5: the revert path now emits a write set carrying the
    // gas-payer Coin<LOOM> debit + proposer credit. PTB-side state
    // mutations are still dropped — only the gas accounting is kept.
    assert!(
        out.write_set.is_some(),
        "revert must still settle gas via a write set (P0-5)"
    );
    assert!(out.logs.is_empty(), "revert must drop logs");

    let reason = String::from_utf8_lossy(&out.return_data);
    let r = reason.to_lowercase();
    assert!(
        r.contains("fuel") || r.contains("out of") || r.contains("oof"),
        "expected out-of-fuel-flavoured revert reason, got: {reason}"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — `object.create` + `object.transfer` round-trip through the
// unified PtbHostCtx (P0-2 + P1-1 conformance fix).
//
// This test is the end-to-end guard for the borrow-table unification:
// the wasm petal mints a brand-new object via `object.create` and then
// hands it off to a fresh owner via `object.transfer`. Both host
// imports operate on the PtbHostCtx's borrow table; before the fix
// they wrote into a ctx the PTB executor never read, so the new
// object would have vanished at commit time.
//
// After the fix, the executor's end-of-execute drain folds the
// host-attributed borrow rows + ownership changes into
// `ExecutionReport.object_writes` and `.ownership_changes`. Those land
// in the `ExecOutput.write_set`, which we then `State::apply` to drive
// the visible-state assertions:
//
//   1. `out.success == true` (no revert),
//   2. After applying the write set, the new object lives at the
//      derived `ObjectId` with `Owner::Address(recipient)`,
//   3. The OwnershipIndex contains the new object under the recipient,
//   4. The OwnershipIndex does NOT keep the new object under the petal
//      contract address (the default-owner the host assigns at create
//      time — the transfer overrides it before the command ends).
// ---------------------------------------------------------------------------

/// WAT petal that:
///   1. Reads a 90-byte `Const` blob from calldata starting at byte 9
///      (the marshalled layout is `[u32 count=1][u8 tag=1][u32 len=90]
///      [90 bytes]`).
///   2. The 90-byte blob holds: `[u16 BE type_tag_len=38][38 type_tag
///      bytes][u16 BE payload_len=16][16 payload bytes][32 recipient
///      bytes]`. We pass the type tag dynamically because it embeds
///      the petal's content hash, which is only known after the petal
///      is published.
///   3. Calls `object.create(type_tag_ptr=2, type_tag_len=38,
///      payload_ptr=42, payload_len=16)` → handle.
///   4. Calls `object.transfer(handle, OWNER_KIND_ADDRESS=0,
///      recipient_ptr=58, 32)`.
const CREATE_AND_TRANSFER_PETAL: &str = r#"
(module
  (import "chain"  "msg.calldata.read"
    (func $cdread (param i32 i32 i32) (result i32)))
  (import "object" "create"
    (func $ocreate (param i32 i32 i32 i32) (result i32)))
  (import "object" "transfer"
    (func $otransfer (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)

  (func (export "__petal_create_and_transfer") (param i32 i32) (result i32)
    ;; Pull the 90-byte Const payload out of calldata into memory[0..90].
    ;; Const payload starts at calldata offset 9
    ;; (4-byte count u32 BE | 1-byte tag=1 | 4-byte len u32 BE).
    (drop (call $cdread
            (i32.const 0)   ;; dst_ptr
            (i32.const 9)   ;; offset
            (i32.const 90))) ;; len

    ;; object.create(type_tag_ptr=2, type_tag_len=38,
    ;;               payload_ptr=42, payload_len=16) -> handle
    ;; (mem layout: [u16 BE tag_len][38 tag][u16 BE pay_len][16 pay][32 recip])
    ;;                 0..2          2..40    40..42         42..58   58..90
    (drop (call $otransfer
            (call $ocreate
                  (i32.const 2)
                  (i32.const 38)
                  (i32.const 42)
                  (i32.const 16))
            (i32.const 0)   ;; OWNER_KIND_ADDRESS
            (i32.const 58)  ;; recipient_ptr
            (i32.const 32))) ;; recipient_len

    i32.const 0)
)
"#;

/// Compute the deterministic ObjectId the host's `derive_create_id`
/// will produce for `(ptb_digest, petal_hash, type_tag_bytes,
/// payload_bytes, created_objects_so_far=0)`. Mirrors `bloom-petals`
/// exactly.
fn derive_create_id_test(
    ptb_digest: [u8; 32],
    petal_hash: [u8; 32],
    tag_bytes: &[u8],
    payload: &[u8],
) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.object.create.v1\0");
    hasher.update(&ptb_digest);
    hasher.update(&petal_hash);
    hasher.update(&0u64.to_be_bytes()); // first object created in this PTB
    hasher.update(tag_bytes);
    hasher.update(payload);
    let h = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(h.as_bytes());
    ObjectId(arr)
}

#[test]
fn object_create_then_transfer_round_trips_through_unified_ctx() {
    // Test inputs ------------------------------------------------------
    let signer = [0x91u8; 32];
    let gas_payer_id = ObjectId([0xBB; 32]);
    let recipient: [u8; 32] = [0xAB; 32];
    let new_obj_payload: [u8; 16] = [0x42; 16]; // 16 arbitrary bytes
    let new_obj_type_name = "T";

    // Build state + register the petal --------------------------------
    let mut state = State::new();
    bind_bootstrap_fungible(&mut state);
    let wasm = wat(CREATE_AND_TRANSFER_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, 1_000_000_000));

    // Encode the TypeTag for the new object. The defining-petal hash
    // is the petal we just registered (object.create enforces this).
    let new_obj_type = TypeTag::Concrete {
        petal_hash: petal_hash.0,
        type_name: new_obj_type_name.to_string(),
        type_args: vec![],
    };
    let tag_bytes = new_obj_type.encode_canonical().expect("encode type tag");
    assert_eq!(
        tag_bytes.len(),
        38,
        "type tag size assumption for 1-char name + 0 type args",
    );

    // Assemble the 90-byte calldata blob -------------------------------
    //   [u16 BE tag_len=38][38 tag][u16 BE pay_len=16][16 pay][32 recip]
    let mut blob = Vec::with_capacity(90);
    blob.extend_from_slice(&(tag_bytes.len() as u16).to_be_bytes());
    blob.extend_from_slice(&tag_bytes);
    blob.extend_from_slice(&(new_obj_payload.len() as u16).to_be_bytes());
    blob.extend_from_slice(&new_obj_payload);
    blob.extend_from_slice(&recipient);
    assert_eq!(blob.len(), 90);

    // Build a manifest declaring one `Const` arg of arbitrary type --
    // the validator only checks variant-shape, not the inner TypeTag.
    let mut manifests = HashMap::new();
    manifests.insert(
        petal_hash,
        PetalManifestStub {
            module_path: "/test/e2e".to_string(),
            functions: vec![FunctionDeclStub {
                view: false,
                name: "create_and_transfer".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Const(new_obj_type.clone())],
                returns: vec![],
                required_signers: 0,
                required_capabilities: vec![],
                attached_invariants: vec![],
            }],
            ..Default::default()
        },
    );

    // Build the PTB ---------------------------------------------------
    let ptb = PtbTx {
        signers: vec![signer],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: String::new(),
                hash: Some(petal_hash),
            },
            function: "create_and_transfer".to_string(),
            type_args: vec![],
            args: vec![Arg::Const(blob)],
        })],
        gas_payer: gas_payer_id,
        gas_budget: 500_000,
        gas_price: 1,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let tx = submit_ptb_tx(test_sender(), bytes);

    // Run -------------------------------------------------------------
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let out = exec.execute_tx(
        &tx,
        &mut state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAA; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    // Assert 1 — no revert.
    assert!(
        out.success,
        "expected PTB success, got revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    let ws = out.write_set.expect("successful PTB must emit a write set");

    // Apply the WriteSet so we can query the resulting State.
    state.apply(ws).expect("apply write set");

    // Compute the deterministic ObjectId the host produced.
    let new_id = derive_create_id_test(
        ptb.signing_digest(),
        petal_hash.0,
        &tag_bytes,
        &new_obj_payload,
    );

    // Assert 2 — the new object lives at the derived id with the right
    // owner. Before the P0-2 fix this lookup returned `None` because
    // the host-import borrow row never made it into the executor's
    // drain step.
    let stored = state.get_object(&new_id).unwrap_or_else(|| {
        panic!(
            "host-created object missing from State; \
                 ids present: {:?}",
            state.iter_objects().map(|(id, _)| *id).collect::<Vec<_>>()
        )
    });
    assert_eq!(
        stored.owner,
        Owner::Address(recipient),
        "host transfer must rewrite owner before commit",
    );
    assert_eq!(stored.payload, new_obj_payload, "payload must round-trip");
    assert_eq!(
        stored.type_tag, new_obj_type,
        "type tag must round-trip via canonical encoding",
    );

    // Assert 3 — OwnershipIndex contains the new object under the
    // recipient. Before the P0-2 fix the host's ownership_changes
    // entry was dropped on the floor.
    let recipient_key = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: recipient,
    };
    let row = state
        .get_ownership(&recipient_key)
        .expect("ownership row for recipient must exist");
    assert!(
        row.contains(&new_id),
        "recipient row missing new object id; row = {row:?}",
    );

    // Assert 4 — OwnershipIndex must NOT keep the new object under
    // the petal contract address (the default owner at create time).
    // `rebuild_ownership_rows` only writes the new-owner row in Phase
    // 1, so we just check that the petal-address row, if present,
    // doesn't list the new id.
    let petal_address_key = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: petal_hash.0,
    };
    if let Some(row) = state.get_ownership(&petal_address_key) {
        assert!(
            !row.contains(&new_id),
            "petal-address row must not retain the transferred object",
        );
    }
}
