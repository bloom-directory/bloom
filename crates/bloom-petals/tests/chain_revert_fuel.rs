//! Category: adversarial
//!
//! Regression coverage for the 2026-05-19 DoS-hardening review item:
//! a chain-mode petal that burns fuel and then reverts must bill the
//! caller for the work it actually performed. If revert paths zero out
//! `fuel_used`, an adversary can repeatedly call a burn-then-revert
//! contract for free, costing validators real CPU without paying.
//!
//! These tests fail on the unfixed code (revert paths drop `fuel_used`
//! to 0 in `run_chain_call`, and sub-call hosts skip `consume_fuel` on
//! the revert branch) and pass on the fixed code.

use bloom_chain_state::{Account, State};
use bloom_chain_types::{Address, Hash32};
use bloom_petals::{BlockCtx, ChainCallInput, ChainEntry, PetalVm};

mod common;
use common::{block_with, make_address, wat};

fn default_block() -> BlockCtx {
    block_with(1, 0xCD)
}

// ---------------------------------------------------------------------------
// BURNER fixture: runs a counted loop (burns ~ N fuel), then either reverts
// or calls petal.return depending on calldata byte[0].
//
//   calldata[0] == 0x01 → revert with reason "burned-and-reverted"
//   calldata[0] == 0x00 → return ok (1 byte: 0xAA)
//
// The loop is `local i = 0; while (i < 50_000) { i += 1; }` — 50_000
// iterations of a 3-instruction inner body burns hundreds of thousands of
// fuel units against wasmtime's default 1-unit-per-instruction metering.
// ---------------------------------------------------------------------------
const BURN_THEN_REVERT_OR_RETURN: &str = include_str!("fixtures/burn_then_revert_or_return.wat");

fn run_burner(calldata: Vec<u8>) -> bloom_petals::ChainCallOutput {
    let state = State::new();
    let input = ChainCallInput {
        wasm: wat(BURN_THEN_REVERT_OR_RETURN),
        entry: ChainEntry::Call,
        contract_address: make_address(0x01),
        msg_sender: make_address(0x02),
        msg_value: 0,
        calldata,
        block: default_block(),
        fuel: 10_000_000,
        snapshot: state.snapshot(),
    };
    PetalVm::run_chain_call(input).expect("top-level revert is Ok with revert_reason set")
}

#[test]
fn top_level_revert_bills_real_fuel_used() {
    // Sibling baseline: same wasm, success branch. fuel_used here is the
    // ground-truth cost of running the loop + epilogue.
    let ok_out = run_burner(vec![0x00]);
    assert!(ok_out.revert_reason.is_none(), "success branch must not revert");
    assert_eq!(ok_out.return_data.as_deref(), Some(&[0xAA_u8][..]));
    let ok_fuel = ok_out.fuel_used;
    assert!(
        ok_fuel >= 50_000,
        "loop should burn at least 50_000 fuel; got {ok_fuel}"
    );

    // Revert branch: same loop, then petal.revert. Per the DoS-hardening
    // contract, fuel_used must be NEARLY identical to the success path —
    // and crucially, MUST NOT be zero.
    let rev_out = run_burner(vec![0x01]);
    assert_eq!(
        rev_out.revert_reason.as_deref(),
        Some(&b"burned-and-reverted"[..]),
        "revert branch must surface the reason bytes"
    );
    assert!(
        rev_out.return_data.is_none(),
        "revert must not also populate return_data"
    );

    // The core DoS-hardening assertion. On the unfixed code this is 0.
    assert!(
        rev_out.fuel_used > 0,
        "revert path MUST bill the caller for fuel actually burned; got 0 — \
         this is the DoS bug: burn-then-revert looks free"
    );

    // And the revert branch should bill close to the success branch
    // (the loop work is identical; only the epilogue differs).
    // We allow ample slack (50%) — the exact figure depends on wasmtime
    // internals — but the two MUST be the same order of magnitude.
    let lo = ok_fuel / 2;
    let hi = ok_fuel.saturating_mul(2);
    assert!(
        rev_out.fuel_used >= lo && rev_out.fuel_used <= hi,
        "revert fuel ({}) should be in the same ballpark as success fuel ({}); \
         range [{lo}, {hi}]",
        rev_out.fuel_used, ok_fuel,
    );
}

// ---------------------------------------------------------------------------
// Sub-call DoS scenario: parent invokes child via `petal.call`. Whether the
// child reverts or returns, the parent's fuel meter must reflect the work
// the child actually performed.
//
// We compare two runs of the same parent:
//   (a) parent calls child with calldata[0]=0x00 → child runs loop & returns
//   (b) parent calls child with calldata[0]=0x01 → child runs loop & reverts
//
// `out.fuel_used` (i.e. the fuel the *parent* burned, transitively
// including the child) must be approximately equal in (a) and (b). If the
// sub-call host skips `consume_fuel(out.fuel_used)` on the revert path,
// (b)'s fuel_used will be dramatically smaller than (a)'s — that's the
// DoS vector.
// ---------------------------------------------------------------------------

const PARENT_FORWARDS_CALLDATA: &str = r#"
(module
  (import "chain" "msg.calldata.read" (func $cdread (param i32 i32 i32) (result i32)))
  (import "chain" "petal.call"        (func $call (param i32 i32 i32 i32 i64 i64 i32 i32) (result i64)))
  (import "chain" "petal.return"      (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "init") (param i32 i32) (result i32)
    i32.const 0)
  (func (export "call") (param i32 i32) (result i32)
    (local $rc i64)
    ;; calldata layout: [0..32] = child address, [32..33] = mode byte.
    (drop (call $cdread (i32.const 0) (i32.const 0) (i32.const 33)))
    ;; petal.call(child, calldata=[32..33] 1 byte, value=0, retdata buf at 64 max 32)
    (local.set $rc
      (call $call
        (i32.const 0)  (i32.const 32)   ;; target ptr/len (32)
        (i32.const 32) (i32.const 1)    ;; calldata ptr/len (1 byte mode)
        (i64.const 0) (i64.const 0)     ;; value lo/hi = 0
        (i32.const 64) (i32.const 32)   ;; retdata buf
      ))
    ;; Stash rc at [96..104] and return it so the test can see it.
    (i64.store (i32.const 96) (local.get $rc))
    (call $ret (i32.const 96) (i32.const 8))
    i32.const 0)
)
"#;

fn run_parent(child_mode_byte: u8) -> bloom_petals::ChainCallOutput {
    let child_wasm = wat(BURN_THEN_REVERT_OR_RETURN);
    let parent_wasm = wat(PARENT_FORWARDS_CALLDATA);

    let mut state = State::new();
    let child_hash = state.insert_code(&child_wasm);
    let parent_hash = state.insert_code(&parent_wasm);

    let child_addr = make_address(0x33);
    let parent_addr = make_address(0x44);

    state.set_account(
        parent_addr,
        Account {
            nonce: 0,
            loom: 1_000_000,
            code_hash: Some(parent_hash),
            storage_root: Hash32([0u8; 32]),
        },
    );
    state.set_account(
        child_addr,
        Account {
            nonce: 0,
            loom: 0,
            code_hash: Some(child_hash),
            storage_root: Hash32([0u8; 32]),
        },
    );

    // calldata: child_addr (32) || mode (1) = 33 bytes
    let mut cd = Vec::with_capacity(33);
    cd.extend_from_slice(&child_addr.0);
    cd.push(child_mode_byte);

    let input = ChainCallInput {
        wasm: parent_wasm,
        entry: ChainEntry::Call,
        contract_address: parent_addr,
        msg_sender: make_address(0x05),
        msg_value: 0,
        calldata: cd,
        block: default_block(),
        fuel: 50_000_000,
        snapshot: state.snapshot(),
    };

    PetalVm::run_chain_call(input).expect("parent must return normally")
}

#[test]
fn sub_call_revert_bills_parent_for_child_fuel() {
    let ok_parent = run_parent(0x00);
    assert!(ok_parent.revert_reason.is_none(), "success-child case must not revert at parent");
    let ok_fuel = ok_parent.fuel_used;
    assert!(ok_fuel >= 50_000, "loop in child must burn measurable fuel; got {ok_fuel}");

    let rev_parent = run_parent(0x01);
    assert!(
        rev_parent.revert_reason.is_none(),
        "parent returns normally even when child reverts (it ignores the negative rc)",
    );
    let rev_fuel = rev_parent.fuel_used;

    // Core DoS assertion: parent's fuel after a reverted child should be
    // approximately the same as after a successful child. If the sub-call
    // host skips `consume_fuel(out.fuel_used)` on the revert branch,
    // rev_fuel will be MUCH smaller than ok_fuel — that's the bug.
    //
    // Allow a 50% band; in practice they differ only by epilogue cost.
    let lo = ok_fuel / 2;
    let hi = ok_fuel.saturating_mul(2);
    assert!(
        rev_fuel >= lo && rev_fuel <= hi,
        "parent fuel after child-revert ({}) must be in the same ballpark as \
         parent fuel after child-success ({}); range [{lo}, {hi}]. \
         Significantly smaller means the sub-call host did NOT bill the \
         parent for the reverted child's burn — the DoS bug.",
        rev_fuel, ok_fuel,
    );
}
