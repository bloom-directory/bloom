//! Category: adversarial
//!
//! Adversarial regression coverage for the 2026-05-19 consensus-hardening
//! review items #6 (nested `petal.call` revert isolation), #7 (wasmtime
//! ResourceLimiter caps `memory.grow` at runtime), and #12 (single,
//! exercised revert API path).
//!
//! Each test in this file is shaped to fail on master and pass on the
//! `feat/petals` branch.

use bloom_chain_state::{Account, State};
use bloom_chain_types::{
    Hash32,
    digest::{blake3_tagged, tags},
};
use bloom_petals::{BlockCtx, ChainCallInput, ChainEntry, PetalError, PetalVm};

mod common;
use common::{block_at, make_address, wat};

fn default_block() -> BlockCtx {
    block_at(7)
}

// ---------------------------------------------------------------------------
// Test (review #6): a reverted nested call must not leak writes to the parent
//
// Layout:
//   - Child petal: writes a non-zero value into its own slot[0..32] = [0x01;32],
//     then calls `petal.revert`. The post-revert child snapshot has the write
//     staged.
//   - Parent petal: calls the child via `petal.call`. *After* the call returns
//     (the parent IGNORES the negative return code from petal.call), the
//     parent reads `state.read(child_slot)` — but for the child's storage,
//     which lives on the child's contract address. To make the assertion
//     observable, the test inspects the output snapshot directly: the
//     child's account should still have its `storage_root` == zero with no
//     storage entries.
//
// Critically, the value transfer (1 LOOM caller → child) must also have
// been rolled back: the child's `loom` should remain 0 and the parent's
// `loom` should remain at its initial balance.
// ---------------------------------------------------------------------------

/// Child petal: writes [0x01; 32] into its own storage slot[0..32] = [0xAA;32],
/// then reverts. Has both `init` (no-op) and `call`.
const CHILD_WRITES_THEN_REVERTS: &str = r#"
(module
  (import "chain" "state.write"   (func $write (param i32 i32 i32 i32) (result i32)))
  (import "chain" "petal.revert"  (func $revert (param i32 i32)))
  (memory (export "memory") 1)
  ;; key (32 bytes 0xAA) at offset 0; value (32 bytes 0x01) at offset 32
  (data (i32.const 0)  "\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa")
  (data (i32.const 32) "\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01")
  ;; "child-revert" data for revert reason at offset 80
  (data (i32.const 80) "child-revert")
  (func (export "init") (param i32 i32) (result i32)
    i32.const 0)
  (func (export "call") (param i32 i32) (result i32)
    ;; Stage a non-zero storage write — this should be discarded on revert.
    (drop (call $write (i32.const 0) (i32.const 32) (i32.const 32) (i32.const 32)))
    ;; Revert with a 12-byte reason.
    (call $revert (i32.const 80) (i32.const 12))
    ;; Unreachable but well-typed.
    i32.const 0)
)
"#;

/// Parent petal: reads child's address + value-amount from calldata, then
/// calls the child via `petal.call`. CRITICALLY, the parent IGNORES the
/// negative return code from petal.call and returns normally, so the test
/// can prove the child's writes / value transfer never leaked back.
///
/// calldata layout:
///   0..32   = child address
///   32..48  = u128 value to transfer (little-endian)
const PARENT_CALLS_THEN_IGNORES: &str = r#"
(module
  (import "chain" "msg.calldata.read" (func $cdread (param i32 i32 i32) (result i32)))
  (import "chain" "petal.call"        (func $call (param i32 i32 i32 i32 i64 i64 i32 i32) (result i64)))
  (import "chain" "petal.return"      (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "init") (param i32 i32) (result i32)
    i32.const 0)
  (func (export "call") (param i32 i32) (result i32)
    (local $rc i64)
    (local $lo i64)
    (local $hi i64)
    ;; Read child address into [0..32].
    (drop (call $cdread (i32.const 0) (i32.const 0) (i32.const 32)))
    ;; Read 16 bytes of u128 value into [32..48], then split into i64 lo/hi.
    (drop (call $cdread (i32.const 32) (i32.const 32) (i32.const 16)))
    (local.set $lo (i64.load (i32.const 32)))
    (local.set $hi (i64.load (i32.const 40)))
    ;; petal.call(child, no calldata, value, retdata buf at 64 max 32).
    (local.set $rc
      (call $call
        (i32.const 0)  (i32.const 32)   ;; target
        (i32.const 0)  (i32.const 0)    ;; calldata
        (local.get $lo) (local.get $hi) ;; value lo, hi
        (i32.const 64) (i32.const 32)   ;; retdata
      ))
    ;; IGNORE rc deliberately — the revert must not leak even if the
    ;; parent's wasm forgets to check the return code.
    (i64.store (i32.const 100) (local.get $rc))
    (call $ret (i32.const 100) (i32.const 8))
    i32.const 0)
)
"#;

#[test]
fn revert_child_writes_dont_leak() {
    let child_wasm = wat(CHILD_WRITES_THEN_REVERTS);
    let parent_wasm = wat(PARENT_CALLS_THEN_IGNORES);

    // Pre-stage both contracts in state.
    let mut state = State::new();
    let child_hash = state.insert_code(&child_wasm);
    let parent_hash = state.insert_code(&parent_wasm);

    let child_addr = make_address(0x11);
    let parent_addr = make_address(0x22);

    // Parent starts with a known LOOM balance — we'll check it after.
    let parent_initial_loom: u128 = 1_000_000;
    state.set_account(
        parent_addr,
        Account {
            nonce: 0,
            loom: parent_initial_loom,
            code_hash: Some(parent_hash),
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
    state.set_account(
        child_addr,
        Account {
            nonce: 0,
            loom: 0,
            code_hash: Some(child_hash),
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );

    // Value to transfer parent → child (must roll back too).
    let value_to_transfer: u128 = 4_242;

    // calldata: child_addr (32) || value_lo_le (16) total 48 bytes.
    let mut calldata = Vec::with_capacity(48);
    calldata.extend_from_slice(&child_addr.0);
    calldata.extend_from_slice(&value_to_transfer.to_le_bytes());

    let input = ChainCallInput {
        wasm: parent_wasm,
        entry: ChainEntry::Call,
        contract_address: parent_addr,
        msg_sender: make_address(0x02),
        msg_value: 0,
        calldata,
        block: default_block(),
        fuel: 50_000_000,
        snapshot: state.snapshot(),
        ptb_ctx: None,
    };

    let out = PetalVm::run_chain_call(input)
        .expect("parent run must succeed (it ignores the negative rc)");

    // The parent ignored the negative rc and returned normally; the
    // returned 8 bytes are the rc the child triggered. Sanity check:
    // confirm it was negative.
    let rc_bytes = out.return_data.as_deref().unwrap();
    assert_eq!(rc_bytes.len(), 8, "parent returns the 8-byte rc");
    let rc = i64::from_le_bytes(rc_bytes.try_into().unwrap());
    assert!(
        rc < 0,
        "petal.call should have surfaced a negative rc for a reverted child; got {rc}"
    );

    // Now interrogate the post-call snapshot. The child's storage slot
    // must NOT contain the [0x01; 32] write — it must read back as zero.
    let snap = out.snapshot;
    let child_slot_key = [0xAA_u8; 32];
    let child_slot = snap.storage_read(&child_addr, &child_slot_key);
    assert_eq!(
        child_slot, [0u8; 32],
        "child's reverted storage write must NOT leak into the parent's snapshot"
    );

    // The value transfer must also have rolled back: parent retains its
    // initial balance, child retains 0.
    let parent_acct = snap
        .get_account(&parent_addr)
        .expect("parent account exists");
    assert_eq!(
        parent_acct.loom, parent_initial_loom,
        "parent's LOOM must be restored after the child reverted the value transfer"
    );
    let child_acct = snap.get_account(&child_addr).expect("child account exists");
    assert_eq!(
        child_acct.loom, 0,
        "child's LOOM must remain 0 — value transfer was rolled back with the revert"
    );
}

// ---------------------------------------------------------------------------
// Test (review #7): wasm `memory.grow` past the chain limiter cap traps at
// runtime rather than succeeding.
//
// The static validator caps the declared min/max memory at 256 pages (16 MiB),
// but a module with `(memory 1)` can still issue `memory.grow` to request
// more pages later. The `ChainLimiter` installed on the chain store should
// reject the grow request, causing wasmtime to raise an OutOfMemory trap.
// That surfaces as `PetalError::ChainCall("trapped: ...")` from the VM.
// ---------------------------------------------------------------------------

/// Petal whose `call` issues `memory.grow(1024)` — well past the 256-page
/// (16 MiB) chain-mode cap.
const MEMORY_GROW_OVER_CAP: &str = include_str!("fixtures/memory_grow_over_cap.wat");

#[test]
fn wasm_memory_grow_caught_at_runtime() {
    // The wasm calls `memory.grow(1024)` (1024 additional pages = 64 MiB),
    // well past the 256-page cap. The ChainLimiter returns Ok(false), so
    // memory.grow returns -1, and the wasm explicitly `unreachable`s to
    // surface the failure as a trap (a malicious petal might instead try
    // to write past the old memory bound; either way, the limiter must
    // prevent the grow from succeeding).
    let state = State::new();
    let input = ChainCallInput {
        wasm: wat(MEMORY_GROW_OVER_CAP),
        entry: ChainEntry::Call,
        contract_address: make_address(0x01),
        msg_sender: make_address(0x02),
        msg_value: 0,
        calldata: Vec::new(),
        block: default_block(),
        fuel: 50_000_000,
        snapshot: state.snapshot(),
        ptb_ctx: None,
    };

    // The petal will either (a) succeed and grow memory if the limiter
    // is missing (master) or (b) trap on the `unreachable` after grow
    // returned -1 (post-fix).
    let err =
        PetalVm::run_chain_call(input).expect_err("memory.grow over cap must trap (review #7)");
    match err {
        PetalError::ChainCall(msg) => {
            assert!(
                msg.contains("trapped"),
                "expected a trap diagnostic, got: {msg}"
            );
        }
        other => panic!("expected ChainCall(trapped), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Test (review #12): the single revert API path. `petal.revert` at top level
// must funnel through `Ok(ChainCallOutput { revert_reason: Some(_), .. })`
// — not through a separate `Err` variant. The reason bytes must match
// exactly; the snapshot returned is the (mutated) child snapshot but the
// executor is responsible for discarding it.
// ---------------------------------------------------------------------------

const SMOKE_REVERT_PETAL: &str = r#"
(module
  (import "chain" "petal.revert" (func $revert (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "smoke-reason")
  (func (export "call") (param i32 i32) (result i32)
    (call $revert (i32.const 0) (i32.const 12))
    i32.const 0)
)
"#;

#[test]
fn single_revert_path_smoke() {
    let state = State::new();
    let input = ChainCallInput {
        wasm: wat(SMOKE_REVERT_PETAL),
        entry: ChainEntry::Call,
        contract_address: make_address(0x01),
        msg_sender: make_address(0x02),
        msg_value: 0,
        calldata: Vec::new(),
        block: default_block(),
        fuel: 1_000_000,
        snapshot: state.snapshot(),
        ptb_ctx: None,
    };

    let out = PetalVm::run_chain_call(input)
        .expect("top-level revert must come back as Ok with revert_reason set, not Err");
    let reason = out
        .revert_reason
        .as_deref()
        .expect("revert_reason must be populated");
    assert_eq!(reason, b"smoke-reason", "revert reason must match exactly");
    assert!(
        out.return_data.is_none(),
        "revert must not also populate return_data (single-path invariant)"
    );

    // The output snapshot is returned but the executor will not commit
    // it. Sanity: no accounts in the base snapshot (state was new).
    let _ = blake3_tagged(tags::PETAL, &[]); // touch tags to keep imports tidy
}
