//! Category: conformance
//!
//! P0-5: PTB gas-payer reservation + refund + outer/inner accounting
//! reconciliation.
//!
//! Spec references:
//!   - §7.2 PTB validation/dispatch
//!   - §9.4 gas-payer Coin<LOOM>
//!
//! Inner PTB gas accounting:
//!   - Before execution: debit `gas_budget * gas_price` from the
//!     gas-payer `Coin<LOOM>` (snapshot mutation; version increments).
//!   - After execution (success):
//!     - Refund `(gas_budget - fuel_used) * gas_price` to the
//!       (possibly mutated) gas-payer Coin<LOOM>.
//!     - Credit the proposer `fuel_used * gas_price` via
//!       `apply_loom_delta`.
//!   - After execution (revert):
//!     - Burn the full `gas_budget * gas_price` from the gas-payer
//!       Coin<LOOM>.
//!     - Credit the proposer the full burnt amount.
//!
//! Outer envelope reconciliation (in `apply_block_state_transitions`):
//!   - For `TxKind::SubmitPtb`, the outer `max_fuel`/`fee_per_unit`
//!     caps must dominate the inner `gas_budget`/`gas_price`.
//!   - Sender's `Account.loom` is NEVER touched by a SubmitPtb (the
//!     gas comes out of the gas-payer Coin<LOOM> object only).

use std::collections::HashMap;

use bloom_chain_node::consensus_driver::apply_block_state_transitions;
use bloom_chain_node::petal_executor::{ChainPetalExecutor, ChainPetalExecutorWithManifests};
use bloom_chain_state::{Account, State};
use bloom_chain_types::block::Block;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{Object, ObjectId, Owner};
use bloom_petal_fungible::ops::decode_coin_value;
use bloom_script::{
    chain_iface::{FunctionDeclStub, PetalManifestStub},
    encode_ptb, loom_coin_type_tag,
    types::{Command, MoveCmd, PetalRef, PqSignature, PtbTx},
};
use bloom_test_util::BlockBuilder;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const ZERO_EMISSION: u128 = 0;

/// Build a SubmitPtb Tx with explicit outer caps. The tx `sender` is
/// derived from the supplied envelope-level pubkey so
/// `apply_block_state_transitions`' sender-derivation check passes.
fn submit_ptb_tx_with_caps_and_pubkey(
    pubkey: Vec<u8>,
    ptb_bytes: Vec<u8>,
    nonce: u64,
    max_fuel: u64,
    fee_per_unit: u64,
) -> (Address, Tx) {
    let sender = Address::from_pubkey_bytes(&pubkey);
    let tx = Tx {
        chain_id: "bloom-chain.v0".to_string(),
        sender,
        nonce,
        max_fuel,
        fee_per_unit,
        kind: TxKind::SubmitPtb { ptb_bytes },
        pubkey: PubKeyBytes(pubkey),
        sig: SigBytes(vec![0u8; 64]),
    };
    (sender, tx)
}

/// Convenience: use a fixed envelope pubkey for tests that don't care
/// about which sender derivation matches.
fn submit_ptb_tx_with_caps(
    ptb_bytes: Vec<u8>,
    nonce: u64,
    max_fuel: u64,
    fee_per_unit: u64,
) -> (Address, Tx) {
    submit_ptb_tx_with_caps_and_pubkey(vec![0u8; 32], ptb_bytes, nonce, max_fuel, fee_per_unit)
}

fn make_loom_coin(id: ObjectId, owner: [u8; 32], value: u128) -> Object {
    let mut payload = vec![0u8; 32];
    payload.extend_from_slice(&value.to_be_bytes());
    Object {
        id,
        type_tag: loom_coin_type_tag(Hash32([0u8; 32])),
        owner: Owner::Address(owner),
        version: 1,
        payload,
    }
}

fn coin_value(state: &State, id: &ObjectId) -> Option<u128> {
    let obj = state.get_object(id)?;
    decode_coin_value(&obj.payload).ok()
}

fn coin_version(state: &State, id: &ObjectId) -> Option<u64> {
    state.get_object(id).map(|o| o.version)
}

fn balance(state: &State, addr: &Address) -> u128 {
    state.get_account(addr).map(|a| a.loom).unwrap_or(0)
}

fn fund(state: &mut State, addr: Address, loom: u128) {
    state.set_account(
        addr,
        Account {
            nonce: 0,
            loom,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        },
    );
}

fn manifest_with_nullary_fn(fn_name: &str) -> PetalManifestStub {
    PetalManifestStub {
        module_path: "/test/p0-5".to_string(),
        functions: vec![FunctionDeclStub {
            name: fn_name.to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![],
            attached_invariants: vec![],
        }],
        ..Default::default()
    }
}

/// Build a single-Move PTB with the given outer gas knobs.
fn nullary_move_ptb_full(
    signer: [u8; 32],
    petal_hash: Hash32,
    fn_name: &str,
    gas_payer: ObjectId,
    gas_budget: u64,
    gas_price: u128,
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
        gas_budget,
        gas_price,
        expiry_block,
        signatures: vec![PqSignature(vec![0u8; 64])],
    }
}

/// Wrap one Tx into a block at the given height with the given proposer.
fn make_block(height: u64, proposer: Address, txs: Vec<Tx>) -> Block {
    BlockBuilder::at(height).proposer(proposer).txs(txs).build()
}

fn wat(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

/// Trivial petal that does nothing — exits immediately. Burns minimal
/// fuel so the refund path is exercised.
const NOOP_PETAL: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_noop") (param i32 i32) (result i32)
    i32.const 0)
)
"#;

/// Petal that infinite-loops — used to exercise the OOF / revert path.
const FUEL_BURNER_PETAL: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_burn_fuel") (param i32 i32) (result i32)
    (loop (br 0))
    i32.const 0)
)
"#;

const NON_OOF_TRAP_PETAL: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_trap_after_work") (param i32 i32) (result i32)
    (local $i i32)
    (loop $again
      (if (i32.lt_u (local.get $i) (i32.const 1000))
        (then
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $again))))
    unreachable)
)
"#;

// ---------------------------------------------------------------------------
// Outer/inner cap reconciliation
// ---------------------------------------------------------------------------

/// `tx.max_fuel < ptb.gas_budget` must be rejected at the outer
/// consensus envelope. No execution, no sender debit, no coin
/// mutation; only nonce advances (so a re-submission can progress).
#[test]
fn outer_max_fuel_lower_than_inner_budget_rejected_at_envelope() {
    let signer = [0x11u8; 32];
    let gas_payer_id = ObjectId([0xAA; 32]);
    let proposer = Address([0xBB; 32]);

    let mut state = State::new();
    let wasm = wat(NOOP_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, 1_000_000_000));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("noop"));

    // Inner budget = 1_000_000, outer cap = 500_000 → mismatch.
    let ptb = nullary_move_ptb_full(
        signer,
        petal_hash,
        "noop",
        gas_payer_id,
        /* gas_budget */ 1_000_000,
        /* gas_price  */ 1,
        100,
    );
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let (sender, tx) = submit_ptb_tx_with_caps(bytes, 1, 500_000, 1);
    fund(&mut state, sender, 5_000_000); // sender Account.loom seed

    let coin_before = coin_value(&state, &gas_payer_id).unwrap();
    let sender_before = balance(&state, &sender);

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let (_fuel, receipts) = apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert_eq!(receipts.len(), 1);
    assert!(!receipts[0].success, "outer/inner cap mismatch must reject");
    assert_eq!(receipts[0].fuel_used, 0, "no fuel consumed");
    let reason = String::from_utf8_lossy(&receipts[0].return_data);
    assert!(
        reason.to_lowercase().contains("outer") || reason.contains("max_fuel"),
        "expected reconciliation revert reason, got: {reason}"
    );

    // Coin and sender balance must be untouched. Nonce bumped.
    assert_eq!(coin_value(&state, &gas_payer_id).unwrap(), coin_before);
    assert_eq!(balance(&state, &sender), sender_before);
    assert_eq!(state.get_account(&sender).unwrap().nonce, 1);
}

/// `tx.fee_per_unit < ptb.gas_price` must be rejected at the outer
/// envelope (same shape as the max-fuel check).
#[test]
fn outer_fee_per_unit_lower_than_inner_price_rejected_at_envelope() {
    let signer = [0x22u8; 32];
    let gas_payer_id = ObjectId([0xCC; 32]);
    let proposer = Address([0xDD; 32]);

    let mut state = State::new();
    let wasm = wat(NOOP_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, 1_000_000_000));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("noop"));

    // Inner gas_price = 10, outer fee_per_unit = 1 → mismatch.
    let ptb = nullary_move_ptb_full(
        signer,
        petal_hash,
        "noop",
        gas_payer_id,
        /* gas_budget */ 100_000,
        /* gas_price  */ 10,
        100,
    );
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let (sender, tx) = submit_ptb_tx_with_caps(bytes, 1, 1_000_000, 1);
    fund(&mut state, sender, 5_000_000);

    let coin_before = coin_value(&state, &gas_payer_id).unwrap();
    let sender_before = balance(&state, &sender);

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let (_fuel, receipts) = apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert_eq!(receipts.len(), 1);
    assert!(
        !receipts[0].success,
        "outer/inner price mismatch must reject"
    );
    assert_eq!(receipts[0].fuel_used, 0, "no fuel consumed");

    // Coin and sender balance must be untouched. Nonce bumped.
    assert_eq!(coin_value(&state, &gas_payer_id).unwrap(), coin_before);
    assert_eq!(balance(&state, &sender), sender_before);
    assert_eq!(state.get_account(&sender).unwrap().nonce, 1);
}

// ---------------------------------------------------------------------------
// Successful PTB → partial gas refund + proposer credit
// ---------------------------------------------------------------------------

/// A successful PTB that burns N < gas_budget fuel:
///   - gas-payer Coin<LOOM> ends up at `initial - N * gas_price`.
///   - proposer Account.loom gains `N * gas_price`.
///   - sender Account.loom is unchanged.
///   - coin version is incremented on every mutation (pre-debit, refund).
#[test]
fn successful_ptb_refunds_unused_gas_and_credits_proposer() {
    let signer = [0x33u8; 32];
    let gas_payer_id = ObjectId([0xEE; 32]);
    let proposer = Address([0xFF; 32]);
    let initial_coin: u128 = 1_000_000_000;

    let mut state = State::new();
    let wasm = wat(NOOP_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, initial_coin));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("noop"));

    let gas_budget: u64 = 200_000;
    let gas_price: u128 = 5;

    let ptb = nullary_move_ptb_full(
        signer,
        petal_hash,
        "noop",
        gas_payer_id,
        gas_budget,
        gas_price,
        100,
    );
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let (sender, tx) = submit_ptb_tx_with_caps(
        bytes,
        1,
        /* max_fuel    */ gas_budget,
        /* fee_per_unit*/ gas_price as u64,
    );
    fund(&mut state, sender, 7_777);

    let sender_before = balance(&state, &sender);
    let coin_version_before = coin_version(&state, &gas_payer_id).unwrap();

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let (_fuel, receipts) = apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert_eq!(receipts.len(), 1, "exactly one receipt");
    assert!(
        receipts[0].success,
        "expected PTB success, got: {}",
        String::from_utf8_lossy(&receipts[0].return_data)
    );
    let fuel_used = receipts[0].fuel_used;
    // The executor's fuel-aggregation tail is wired phase-by-phase
    // (TODO #36 in bloom-script/src/executor.rs): a successful trivial
    // petal can report `fuel_used == 0`. The accounting algebra still
    // has to balance — coin and proposer both move by the same
    // `fuel_used * gas_price`.
    assert!(
        fuel_used <= gas_budget,
        "fuel_used must never exceed gas_budget (got {fuel_used} > {gas_budget})"
    );

    let burnt = (fuel_used as u128) * gas_price;
    // Coin value: initial - burnt (the unused refund cancels half of the
    // pre-debit reservation).
    assert_eq!(
        coin_value(&state, &gas_payer_id).unwrap(),
        initial_coin - burnt,
        "gas-payer coin must reflect a net burn of fuel_used * gas_price"
    );
    // Version must have been bumped on the pre-debit. If there's a
    // refund (fuel_used < gas_budget), the success path bumps a second
    // time on the refund write.
    let expected_bumps = if fuel_used < gas_budget { 2 } else { 1 };
    assert!(
        coin_version(&state, &gas_payer_id).unwrap() >= coin_version_before + expected_bumps,
        "coin version must increment on every mutation \
         (before={coin_version_before}, after={}, expected ≥ +{expected_bumps})",
        coin_version(&state, &gas_payer_id).unwrap(),
    );

    // Proposer Account.loom: gained exactly the burnt portion.
    assert_eq!(
        balance(&state, &proposer),
        burnt,
        "proposer must be credited the burnt gas"
    );

    // Sender Account.loom: untouched (Option A: PTB gas does NOT flow
    // through the sender's account).
    assert_eq!(
        balance(&state, &sender),
        sender_before,
        "sender Account.loom must be untouched by a SubmitPtb"
    );
}

// ---------------------------------------------------------------------------
// Reverted PTB → full burn, no refund
// ---------------------------------------------------------------------------

/// An out-of-fuel revert: the entire `gas_budget * gas_price` is
/// burnt — no refund, even though `report.fuel_used` may technically
/// equal `gas_budget`.
///
/// Assertions:
///   - gas-payer Coin<LOOM> loses exactly `gas_budget * gas_price`,
///   - proposer Account.loom gains exactly the same,
///   - sender Account.loom is unchanged.
#[test]
fn reverted_ptb_burns_full_reservation_and_credits_proposer() {
    let signer = [0x44u8; 32];
    let gas_payer_id = ObjectId([0xAB; 32]);
    let proposer = Address([0xBA; 32]);
    let initial_coin: u128 = 1_000_000_000;

    let mut state = State::new();
    let wasm = wat(FUEL_BURNER_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, initial_coin));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("burn_fuel"));

    let gas_budget: u64 = 100_000;
    let gas_price: u128 = 7;
    let ptb = nullary_move_ptb_full(
        signer,
        petal_hash,
        "burn_fuel",
        gas_payer_id,
        gas_budget,
        gas_price,
        100,
    );
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let (sender, tx) = submit_ptb_tx_with_caps(
        bytes,
        1,
        /* max_fuel    */ gas_budget,
        /* fee_per_unit*/ gas_price as u64,
    );
    fund(&mut state, sender, 31_415);

    let sender_before = balance(&state, &sender);

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let (_fuel, receipts) = apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert_eq!(receipts.len(), 1);
    assert!(!receipts[0].success, "out-of-fuel must revert");

    let reservation = (gas_budget as u128) * gas_price;
    assert_eq!(
        coin_value(&state, &gas_payer_id).unwrap(),
        initial_coin - reservation,
        "gas-payer coin must lose the entire reservation on revert"
    );
    assert_eq!(
        balance(&state, &proposer),
        reservation,
        "proposer must be credited the entire reservation on revert"
    );
    assert_eq!(
        balance(&state, &sender),
        sender_before,
        "sender Account.loom must be untouched even on PTB revert"
    );
}

#[test]
fn non_oof_wasm_trap_charges_consumed_fuel_and_full_revert_burn() {
    let signer = [0x4Au8; 32];
    let gas_payer_id = ObjectId([0x4B; 32]);
    let proposer = Address([0x4C; 32]);
    let initial_coin: u128 = 1_000_000_000;

    let mut state = State::new();
    let wasm = wat(NON_OOF_TRAP_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, initial_coin));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("trap_after_work"));

    let gas_budget: u64 = 100_000;
    let gas_price: u128 = 11;
    let ptb = nullary_move_ptb_full(
        signer,
        petal_hash,
        "trap_after_work",
        gas_payer_id,
        gas_budget,
        gas_price,
        100,
    );
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let (sender, tx) = submit_ptb_tx_with_caps(bytes, 1, gas_budget, gas_price as u64);
    fund(&mut state, sender, 123_456);

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let (block_fuel, receipts) =
        apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert_eq!(receipts.len(), 1);
    assert!(!receipts[0].success, "non-OOF trap must revert");
    assert!(
        receipts[0].fuel_used > 0,
        "non-OOF trap must preserve consumed wasm fuel in the receipt"
    );
    assert_eq!(
        block_fuel, receipts[0].fuel_used,
        "block fuel must include the non-OOF trap's consumed fuel"
    );

    let reservation = (gas_budget as u128) * gas_price;
    assert_eq!(
        coin_value(&state, &gas_payer_id).unwrap(),
        initial_coin - reservation,
        "gas-payer coin must lose the full reservation on trap revert"
    );
    assert_eq!(
        balance(&state, &proposer),
        reservation,
        "proposer must receive the full burn on trap revert"
    );
}

// ---------------------------------------------------------------------------
// Free-VM-work regression guard: a tiny outer cap can't cover a huge
// inner budget. Without P0-5 this PTB would have executed and the
// proposer would have only earned `max_fuel * fee_per_unit` (peanuts)
// for a huge VM run.
// ---------------------------------------------------------------------------

#[test]
fn free_vm_work_attempt_is_rejected_before_execution() {
    let signer = [0x55u8; 32];
    let gas_payer_id = ObjectId([0xCD; 32]);
    let proposer = Address([0xDC; 32]);

    let mut state = State::new();
    let wasm = wat(FUEL_BURNER_PETAL);
    let petal_hash = state.insert_code(&wasm);
    // Give the coin enough to cover the inner budget so the validator
    // doesn't reject on InsufficientGas — we want to specifically
    // exercise the outer/inner cap mismatch path.
    state.set_object(make_loom_coin(gas_payer_id, signer, u128::MAX / 2));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("burn_fuel"));

    // Tiny outer max_fuel (1) vs huge inner gas_budget (50_000_000).
    let ptb = nullary_move_ptb_full(
        signer,
        petal_hash,
        "burn_fuel",
        gas_payer_id,
        /* gas_budget */ 50_000_000,
        /* gas_price  */ 1,
        100,
    );
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let (sender, tx) =
        submit_ptb_tx_with_caps(bytes, 1, /* max_fuel    */ 1, /* fee_per_unit*/ 1);
    fund(&mut state, sender, 100);

    let coin_before = coin_value(&state, &gas_payer_id).unwrap();
    let proposer_before = balance(&state, &proposer);
    let sender_before = balance(&state, &sender);

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let (fuel, receipts) = apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert_eq!(fuel, 0, "no fuel may be consumed on outer reject");
    assert_eq!(receipts.len(), 1);
    assert!(!receipts[0].success);
    assert_eq!(receipts[0].fuel_used, 0);

    // Nothing moved — sender, coin, proposer all unchanged.
    assert_eq!(coin_value(&state, &gas_payer_id).unwrap(), coin_before);
    assert_eq!(balance(&state, &proposer), proposer_before);
    assert_eq!(balance(&state, &sender), sender_before);
}

// ---------------------------------------------------------------------------
// Sender Account.loom strict invariant.
//
// This is the explicit "no double-billing" guard: even on the success
// path with a non-zero outer fee_per_unit and non-zero max_fuel, the
// sender's Account.loom moves by zero. Gas comes from the gas-payer
// Coin<LOOM> object and lands in the proposer's account — never the
// sender's account.
// ---------------------------------------------------------------------------

#[test]
fn sender_account_loom_never_moves_across_submit_ptb() {
    let signer = [0x66u8; 32];
    let gas_payer_id = ObjectId([0xEF; 32]);
    let proposer = Address([0xFE; 32]);
    let sender_seed: u128 = 12_345_678_901_234;

    let mut state = State::new();
    let wasm = wat(NOOP_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, 1_000_000_000));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("noop"));

    let ptb = nullary_move_ptb_full(
        signer,
        petal_hash,
        "noop",
        gas_payer_id,
        /* gas_budget */ 200_000,
        /* gas_price  */ 3,
        100,
    );
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let (sender, tx) = submit_ptb_tx_with_caps(
        bytes, 1, /* max_fuel    */ 200_000, /* fee_per_unit*/ 3,
    );
    fund(&mut state, sender, sender_seed);

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let (_fuel, receipts) = apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert!(
        receipts[0].success,
        "PTB must succeed: {}",
        String::from_utf8_lossy(&receipts[0].return_data)
    );
    assert_eq!(
        balance(&state, &sender),
        sender_seed,
        "sender Account.loom must be byte-equal across the SubmitPtb"
    );
    // Nonce did advance.
    assert_eq!(state.get_account(&sender).unwrap().nonce, 1);
}

// ---------------------------------------------------------------------------
// Decode-error path: undecodable PTB bytes should fail at the outer
// envelope with a clean nonce bump and no other state change. Verifies
// the consensus_driver decode-error branch (not the executor's branch).
// ---------------------------------------------------------------------------

#[test]
fn undecodable_ptb_rejected_at_envelope_with_nonce_bump() {
    let proposer = Address([0x88u8; 32]);
    let sender_seed: u128 = 42;

    let mut state = State::new();

    // Empty bytes do not decode.
    let (sender, tx) = submit_ptb_tx_with_caps(vec![], 1, 10_000_000, 1);
    fund(&mut state, sender, sender_seed);

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutor;
    let (_fuel, receipts) = apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert_eq!(receipts.len(), 1);
    assert!(!receipts[0].success);
    assert_eq!(receipts[0].fuel_used, 0);
    assert_eq!(
        balance(&state, &sender),
        sender_seed,
        "sender Account.loom must be untouched on outer-envelope decode reject"
    );
    assert_eq!(state.get_account(&sender).unwrap().nonce, 1);
    assert_eq!(
        balance(&state, &proposer),
        0,
        "proposer must not be credited"
    );
}

// ---------------------------------------------------------------------------
// `fuel_used == gas_budget` corner-case: zero refund, full burn,
// no spurious snapshot mutations.
// ---------------------------------------------------------------------------

#[test]
fn full_budget_consumed_zero_refund_full_burn() {
    // We can't easily make the noop petal burn EXACTLY gas_budget
    // fuel, but we can exercise the "fuel_used == gas_budget" code
    // path via the FUEL_BURNER_PETAL (which reports fuel_used capped
    // to the budget on OOF) and then assert the same shape as the
    // reverted-PTB test. The semantic guarantee we want here is that
    // `(gas_budget - gas_budget) * gas_price == 0` refund is a no-op
    // (no underflow, no spurious coin mutation beyond the pre-debit).
    let signer = [0x99u8; 32];
    let gas_payer_id = ObjectId([0x10; 32]);
    let proposer = Address([0x20; 32]);
    let initial_coin: u128 = 1_000_000;

    let mut state = State::new();
    let wasm = wat(FUEL_BURNER_PETAL);
    let petal_hash = state.insert_code(&wasm);
    state.set_object(make_loom_coin(gas_payer_id, signer, initial_coin));

    let mut manifests = HashMap::new();
    manifests.insert(petal_hash, manifest_with_nullary_fn("burn_fuel"));

    let gas_budget: u64 = 50_000;
    let gas_price: u128 = 2;
    let ptb = nullary_move_ptb_full(
        signer,
        petal_hash,
        "burn_fuel",
        gas_payer_id,
        gas_budget,
        gas_price,
        100,
    );
    let bytes = encode_ptb(&ptb).expect("encode PTB");
    let (sender, tx) = submit_ptb_tx_with_caps(bytes, 1, gas_budget, gas_price as u64);
    fund(&mut state, sender, 1);

    let block = make_block(1, proposer, vec![tx]);
    let exec = ChainPetalExecutorWithManifests::new(manifests);
    let (_fuel, receipts) = apply_block_state_transitions(&mut state, &exec, &block, ZERO_EMISSION);

    assert!(!receipts[0].success);
    let burn = (gas_budget as u128) * gas_price;
    assert_eq!(
        coin_value(&state, &gas_payer_id).unwrap(),
        initial_coin - burn,
    );
    assert_eq!(balance(&state, &proposer), burn);
}
