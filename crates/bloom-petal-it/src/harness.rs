//! Shared test harness for `bloom-petal-it` integration tests.
//!
//! Provides:
//! - [`build_state`] — produce a fresh `State` with N pre-funded accounts,
//!   each owning a `Coin<LOOM>(initial_balance)`, mirroring what
//!   `Genesis::apply_to_state` does but without needing a full `GenesisFile`.
//! - [`submit_ptb`] — wrap a `PtbTx` as a `TxKind::SubmitPtb` and drive it
//!   through `ChainPetalExecutorWithManifests::execute_tx`, applying the
//!   write set on success and returning the raw `ExecOutput`.
//! - [`make_loom_coin`] / [`seed_coin`] — lower-level helpers for seeding
//!   objects directly into a `State` without genesis machinery.
//! - [`wat_to_wasm`] — convert a WAT source string to wasm bytes (panics on
//!   malformed WAT; every fixture in this crate is statically valid).

use std::collections::HashMap;

use bloom_chain_node::{
    consensus_driver::{ExecOutput, PetalExecutor},
    petal_executor::ChainPetalExecutorWithManifests,
};
use bloom_chain_state::State;
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::{
    coin_payload, decode_coin_value as fungible_decode_coin_value, type_tag_coin_loom,
};
use bloom_script::{
    CORE_FUNGIBLE_PATH, DEFAULT_FUNGIBLE_PETAL_HASH, FunctionDeclStub, PetalManifestStub,
    encode_ptb, types::PtbTx,
};

// ---------------------------------------------------------------------------
// Coin payload format
// ---------------------------------------------------------------------------

/// Canonical coin payload: 48-byte `[ObjectId placeholder (32 bytes)] ||
/// [value BE (16 bytes)]`. Delegates to `bloom_petal_fungible::ops::coin_payload`.
///
/// Both the PTB executor and the on-chain fungible petal now use the same
/// 48-byte layout, so this is the only helper needed.
pub fn ptb_coin_payload(value: u128) -> Vec<u8> {
    coin_payload(value)
}

/// Decode the value from a canonical 48-byte coin payload.
/// Returns 0 on malformed input (test-harness convenience).
pub fn ptb_decode_coin_value(payload: &[u8]) -> u128 {
    fungible_decode_coin_value(payload).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// State seeding
// ---------------------------------------------------------------------------

/// Build a fresh `State` with each `(address, balance)` allocation:
/// 1. A `Coin<LOOM>` object with a deterministic id owned by the address.
/// 2. The `OwnershipIndex` updated to list the coin.
///
/// This replicates what `Genesis::apply_to_state` does without requiring a
/// full `GenesisFile` or TOML parsing.
pub fn build_state(allocations: &[(Address, u128)]) -> State {
    let mut state = State::new();
    state.set_vfs_binding(CORE_FUNGIBLE_PATH.to_string(), DEFAULT_FUNGIBLE_PETAL_HASH);
    let coin_type = type_tag_coin_loom();

    for (idx, (addr, balance)) in allocations.iter().enumerate() {
        // Deterministic Coin<LOOM> id.
        let coin_id = genesis_coin_id(*addr, idx);

        let obj = Object {
            id: coin_id,
            type_tag: coin_type.clone(),
            owner: Owner::Address(addr.0),
            version: 0,
            // Canonical 48-byte payload: [ObjectId placeholder (32)] || [value BE (16)].
            payload: coin_payload(*balance),
        };
        state.set_object(obj.clone());

        // Ownership index.
        let okey = OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: addr.0,
        };
        let mut owned = state.get_ownership(&okey).unwrap_or_default();
        let pos = owned.partition_point(|id| id.0 < coin_id.0);
        owned.insert(pos, coin_id);
        state.set_ownership(okey, owned);
    }

    state
}

/// Derive a deterministic `ObjectId` for genesis-seeded `Coin<LOOM>` objects.
///
/// `blake3("bloom-petal-it.genesis" || addr || idx_le32)`
pub fn genesis_coin_id(addr: Address, idx: usize) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-petal-it.genesis");
    h.update(&addr.0);
    h.update(&(idx as u32).to_le_bytes());
    ObjectId(*h.finalize().as_bytes())
}

/// Insert a `Coin<LOOM>` object directly into `state` with a custom id.
/// Uses the canonical 48-byte payload format: [id placeholder (32)] || [value BE (16)].
pub fn seed_coin(state: &mut State, id: ObjectId, owner: Address, value: u128) {
    let obj = Object {
        id,
        type_tag: type_tag_coin_loom(),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: coin_payload(value),
    };
    state.set_object(obj.clone());

    let okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: owner.0,
    };
    let mut owned = state.get_ownership(&okey).unwrap_or_default();
    let pos = owned.partition_point(|id| id.0 < obj.id.0);
    owned.insert(pos, obj.id);
    state.set_ownership(okey, owned);
}

// ---------------------------------------------------------------------------
// PTB submission
// ---------------------------------------------------------------------------

/// Wrap `ptb` as a `TxKind::SubmitPtb` transaction, drive it through
/// the `ChainPetalExecutorWithManifests` executor with an **empty**
/// override map, apply the write set on success, and return the
/// `ExecOutput`.
///
/// "Chain-authoritative" here means the manifest is decoded entirely
/// from the `bloom_petal_manifest_v0` custom section of each petal's
/// on-chain wasm bytes (layer 2 of `PtbChainAdapter::load_manifest`),
/// exactly like the production node — the empty override map
/// short-circuits layer 1. This pairs well with
/// [`wrap_with_real_manifest`], which compiles a WAT body and
/// appends the real macro-emitted canonical manifest bytes.
///
/// Note: this still uses the test-only `AlwaysOkVerifier` for PTB
/// signatures (the production verifier requires registered xDSA keys and
/// composite signatures; constructing those in every fixture is out of scope
/// for these integration tests, and signature verification has its own coverage in
/// `crates/bloom-chain-node/tests/ptb_signature_rejection.rs`).
///
/// `state` is mutated in-place when the tx succeeds. On revert the
/// state is unchanged (atomic).
pub fn submit_ptb_chain_auth(state: &mut State, sender: Address, ptb: PtbTx) -> ExecOutput {
    // Empty override map → PtbChainAdapter falls through to the
    // wasm custom-section path for every petal hash. The executor's
    // signature verifier is the test-only `AlwaysOkVerifier`, which
    // matches the manifest-only flavour of other tests in this crate.
    submit_ptb(state, sender, ptb, HashMap::new())
}

/// Wrap `ptb` as a `TxKind::SubmitPtb` transaction, drive it through
/// `ChainPetalExecutorWithManifests` (using `manifests` for Move-command
/// typechecks), **apply the write set on success**, and return the
/// `ExecOutput`.
///
/// `state` is mutated in-place when the tx succeeds. On revert the state is
/// unchanged (atomic).
pub fn submit_ptb(
    state: &mut State,
    sender: Address,
    ptb: PtbTx,
    manifests: HashMap<Hash32, PetalManifestStub>,
) -> ExecOutput {
    let ptb_bytes = encode_ptb(&ptb).expect("PTB encode must not fail in harness");
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
    let out = exec.execute_tx(
        &tx,
        state,
        /* block_number */ 100,
        /* timestamp_ms */ 1_700_000_000_000,
        /* proposer    */ Address([0xAAu8; 32]),
        /* parent_hash */ Hash32([0u8; 32]),
    );

    if out.success
        && let Some(ws) = out.write_set.clone()
    {
        state
            .apply(ws)
            .expect("apply write_set must not fail in harness");
    }

    out
}

// ---------------------------------------------------------------------------
// WAT helpers
// ---------------------------------------------------------------------------

/// Parse a WAT source string into wasm bytes. Panics on malformed WAT —
/// every fixture in this crate is statically valid.
pub fn wat_to_wasm(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

/// Append a `bloom_petal_manifest_v0` custom section carrying
/// `manifest_bytes` to `wasm`. The caller is expected to pass canonical
/// manifest bytes — typically the output of one of the real petals'
/// macro-emitted `__bloom_manifest_bytes()` accessors.
///
/// This gives integration tests a "best of both worlds" fixture: a
/// chain-authoritative manifest (decoded by `PtbChainAdapter::new` via
/// the wasm custom-section path, identical to production), paired with
/// a hand-written WAT body that emulates the wasm-side `__petal_<fn>`
/// exports without needing a `wasm32-unknown-unknown` toolchain at test
/// time.
///
/// The append is byte-level (matches the `wasm_with_custom` helper used
/// in `bloom-chain-node`'s adapter tests); we don't re-parse the wasm.
pub fn append_manifest_section(mut wasm: Vec<u8>, manifest_bytes: &[u8]) -> Vec<u8> {
    let name = "bloom_petal_manifest_v0";
    // Body = name_len (LEB128) | name | payload.
    let mut body = Vec::new();
    leb128(&mut body, name.len() as u64);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(manifest_bytes);
    // Section: id 0 (custom) | LEB128 body_len | body.
    wasm.push(0x00);
    leb128(&mut wasm, body.len() as u64);
    wasm.extend_from_slice(&body);
    wasm
}

/// Convenience: compile `wat_src` and append the
/// `bloom_petal_manifest_v0` custom section in one call.
pub fn wrap_with_real_manifest(wat_src: &str, manifest_bytes: &[u8]) -> Vec<u8> {
    let base = wat_to_wasm(wat_src);
    append_manifest_section(base, manifest_bytes)
}

fn leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        } else {
            out.push(b | 0x80);
        }
    }
}

/// The canonical-encoded `PetalManifestV0` bytes embedded in the real
/// `/bloom/core/fungible` petal — i.e. the exact same blob the macro
/// emits into the wasm `bloom_petal_manifest_v0` custom section. Use
/// with [`wrap_with_real_manifest`] to build a chain-authoritative
/// fixture for the fungible petal.
pub fn real_fungible_manifest_bytes() -> &'static [u8] {
    bloom_petal_fungible::fungible::__bloom_manifest_bytes()
}

// ---------------------------------------------------------------------------
// Manifest helpers
// ---------------------------------------------------------------------------

/// Build a `PetalManifestStub` declaring a single zero-arg, zero-return
/// `__petal_<fn_name>` function — exactly what the PTB validator's
/// typecheck (§7.2 step 4) needs for a nullary `Command::Move`.
pub fn manifest_nullary(fn_name: &str) -> PetalManifestStub {
    PetalManifestStub {
        module_path: "/test/petal-it".to_string(),
        functions: vec![FunctionDeclStub {
            view: false,
            name: fn_name.to_string(),
            type_params: vec![],
            args: vec![],
            returns: vec![],
            attached_invariants: vec![],
        }],
        ..Default::default()
    }
}

/// Build a one-entry manifest registry for a single petal.
pub fn single_manifest(hash: Hash32, fn_name: &str) -> HashMap<Hash32, PetalManifestStub> {
    let mut m = HashMap::new();
    m.insert(hash, manifest_nullary(fn_name));
    m
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

/// Build a deterministic `Address` from a single seed byte.
pub fn addr(b: u8) -> Address {
    Address([b; 32])
}
