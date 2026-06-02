//! Real `&Capability<EpochZero>` required-capability check.
//!
//! Audit finding: previous cap-revert coverage exercised gas-payer /
//! access-control failures rather than the real `&MintCap<T>` /
//! `&Capability<...>` typecheck that the validator enforces against a
//! chain-authoritative manifest. This file keeps that coverage end to end:
//!
//! 1. Load the **real** macro-emitted manifest bytes from
//!    `bloom_petal_fungible::fungible::__bloom_manifest_bytes()` and
//!    install them on a synthetic WAT wasm via the
//!    `bloom_petal_manifest_v0` custom section — i.e. the exact same
//!    manifest the production node decodes via `PtbChainAdapter::new`
//!    from each petal's wasm.
//!
//! 2. Build a PTB that calls `mint_genesis(epoch, amount, recipient)`
//!    from that manifest and assert validation rejects a wrongly typed
//!    capability object.
//!
//! 3. Assert a properly typed `EpochZero` capability object satisfies
//!    the manifest-level required capability.
//!
//! Why `mint_genesis` and not `mint`? `mint` is generic on `T` so its
//! cap arg is declared as `Capability<MintCap<T>>` with a `Generic{idx:0}`
//! inner type that requires the caller to thread `type_args=[T]`. The
//! validator's substitution then checks the seeded cap against
//! `MintCap<LOOM>`. `mint_genesis` is non-generic and uses
//! `EpochZero` directly, so the typecheck is independent
//! of `type_args` substitution and the assertion is simpler. The
//! validator pathway exercised is identical — both go through
//! `typecheck_move_cmd` → `type_tags_match` on `ArgDeclStub::Object`.

use bloom_chain_state::State;
use bloom_objects::{AccessMode, Object, ObjectId, Owner, TypeTag};
use bloom_script::ExpectedVersion;
use bloom_script::{Arg, Command, MoveCmd, PetalRef, PqSignature, PtbTx};

use bloom_petal_fungible::ops::cap_payload;
use bloom_petal_it::harness::{
    addr, build_state, genesis_coin_id, real_fungible_manifest_bytes, submit_ptb_chain_auth,
    wrap_with_real_manifest,
};

// ---------------------------------------------------------------------------
// Helpers: build the canonical TypeTag for `EpochZero` and
// seed such an object into state for the positive-control test.
// ---------------------------------------------------------------------------

fn type_tag_epoch_zero() -> TypeTag {
    // Macro emits `petal_hash: [0u8; 32]` ("self" sentinel) for any
    // type declared inside the petal — the validator treats this as
    // a wildcard match against on-chain hashes.
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: "EpochZero".to_string(),
        type_args: vec![],
    }
}

fn seed_epoch_zero_cap(state: &mut State, id: ObjectId, owner: bloom_chain_types::types::Address) {
    let obj = Object {
        id,
        type_tag: type_tag_epoch_zero(),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: cap_payload(),
    };
    state.set_object(obj);
}

/// Tiny WAT petal exporting `__petal_mint_genesis` as a noop. The
/// `bloom_petal_manifest_v0` custom section appended by
/// `wrap_with_real_manifest` carries the real macro-emitted manifest
/// for `/bloom/petals/core/fungible`, so the validator sees the exact
/// declared arg types for `mint_genesis`.
fn noop_mint_genesis_wat() -> &'static str {
    r#"
(module
  (memory (export "memory") 1)
  (func (export "__petal_mint_genesis") (param i32 i32) (result i32)
    i32.const 0)
)
"#
}

// ---------------------------------------------------------------------------
// Negative: missing required capability fails closed.
// ---------------------------------------------------------------------------

#[test]
fn mint_genesis_required_capability_rejects_wrong_typed_cap() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);
    let alice_coin_id = genesis_coin_id(alice, 0);

    // Install the real fungible manifest on a synthetic WAT body.
    let wasm = wrap_with_real_manifest(noop_mint_genesis_wat(), real_fungible_manifest_bytes());
    let petal_hash = state.insert_code(&wasm);
    // The PTB pins by hash, so the manifest is loaded from the inserted
    // wasm. The harness keeps `/bloom/petals/core/fungible` bound to the
    // bootstrap sentinel so the seeded gas coin remains Coin<LOOM>.

    // Build `mint_genesis(epoch=alice_coin /* WRONG TYPE */,
    //                    amount=u128 BE 1000,
    //                    recipient=alice address)`.
    // `mint_genesis` declares arg[0] as Object{EpochZero, ReadOnly};
    // we pass alice's Coin<LOOM> in ReadOnly mode (ReadOnly never trips
    // ownership) so the typecheck error is the type-tag mismatch, not
    // an access-mode/ownership error.
    let mut amount_bytes = Vec::with_capacity(16);
    amount_bytes.extend_from_slice(&1000u128.to_be_bytes());

    let recipient_bytes = alice.0.to_vec(); // canonical Address = 32 raw bytes

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: String::new(),
                hash: Some(petal_hash),
            },
            function: "mint_genesis".to_string(),
            type_args: vec![],
            args: vec![
                // arg[0]: WRONG-TYPED OBJECT — Coin<LOOM>, not EpochZero.
                Arg::Object {
                    id: alice_coin_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::ReadOnly,
                },
                // arg[1]: amount as canonical u128 BE.
                Arg::Const(amount_bytes),
                // arg[2]: recipient as canonical Address (32 bytes).
                Arg::Const(recipient_bytes),
            ],
        })],
        gas_payer: alice_coin_id,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, alice, ptb);

    assert!(
        !out.success,
        "passing Coin<LOOM> where EpochZero is expected MUST revert"
    );
    assert!(out.write_set.is_none(), "revert must drop write set");
    assert!(out.logs.is_empty(), "revert must drop logs");

    let reason = String::from_utf8_lossy(&out.return_data);
    let reason_lc = reason.to_lowercase();
    assert!(
        reason_lc.contains("arg type mismatch")
            && reason_lc.contains("coin<loom>")
            && reason_lc.contains("epochzero"),
        "revert reason must cite the canonical capability arg type mismatch; got: {reason}"
    );
}

// ---------------------------------------------------------------------------
// A properly-typed EpochZero capability object satisfies the manifest
// required capability.
// ---------------------------------------------------------------------------

#[test]
fn mint_genesis_required_capability_accepts_real_epoch_zero_cap() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);
    let alice_coin_id = genesis_coin_id(alice, 0);

    let wasm = wrap_with_real_manifest(noop_mint_genesis_wat(), real_fungible_manifest_bytes());
    let petal_hash = state.insert_code(&wasm);

    // Seed a real EpochZero capability object owned by alice.
    let epoch_id = ObjectId([0xE0; 32]);
    seed_epoch_zero_cap(&mut state, epoch_id, alice);

    let mut amount_bytes = Vec::with_capacity(16);
    amount_bytes.extend_from_slice(&1000u128.to_be_bytes());
    let recipient_bytes = alice.0.to_vec();

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![Command::Move(MoveCmd {
            petal: PetalRef {
                path: String::new(),
                hash: Some(petal_hash),
            },
            function: "mint_genesis".to_string(),
            type_args: vec![],
            args: vec![
                Arg::Object {
                    id: epoch_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::ReadOnly,
                },
                Arg::Const(amount_bytes),
                Arg::Const(recipient_bytes),
            ],
        })],
        gas_payer: alice_coin_id,
        gas_budget: 200_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, alice, ptb);

    assert!(
        out.success,
        "properly typed EpochZero object must satisfy required_capabilities; got: {}",
        String::from_utf8_lossy(&out.return_data)
    );
}
