//! Shared test harness for `bloom-petal-dex-it` integration tests.
//!
//! Adapted from `bloom-petal-it/src/harness.rs` and specialised for the DEX
//! scenario (pool / cpmm / router petals).
//!
//! Provides:
//! - [`build_state`] — produce a fresh `State` with N pre-funded accounts.
//! - [`submit_ptb`] — drive a `PtbTx` through `ChainPetalExecutorWithManifests`
//!   and apply the write set on success.
//! - [`seed_coin`] / [`genesis_coin_id`] — lower-level object seeding helpers.
//! - [`wat_to_wasm`] — convert WAT source to wasm bytes.
//! - [`manifest_nullary`] / [`single_manifest`] — manifest builder helpers.
//! - [`addr`] — deterministic `Address` from a seed byte.

use std::collections::HashMap;

use bloom_chain_node::{
    consensus_driver::{ExecOutput, PetalExecutor},
    petal_executor::ChainPetalExecutorWithManifests,
};
use bloom_chain_state::{Account, State};
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::{
    coin_payload, decode_coin_value as fungible_decode_coin_value, type_tag_coin_loom,
};
use bloom_script::{FunctionDeclStub, PetalManifestStub, encode_ptb, types::PtbTx};

// ---------------------------------------------------------------------------
// Coin payload helpers
// ---------------------------------------------------------------------------

/// Canonical 48-byte coin payload: `[ObjectId placeholder (32)] || [value BE (16)]`.
/// Delegates to `bloom_petal_fungible::ops::coin_payload`.
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
/// 1. `Account.loom = balance` (derived cache, spec §9.2).
/// 2. A `Coin<LOOM>` object with a deterministic id owned by the address.
/// 3. The `OwnershipIndex` updated to list the coin.
pub fn build_state(allocations: &[(Address, u128)]) -> State {
    let mut state = State::new();
    let coin_type = type_tag_coin_loom();

    for (idx, (addr, balance)) in allocations.iter().enumerate() {
        state.set_account(
            *addr,
            Account {
                nonce: 0,
                loom: *balance,
                code_hash: None,
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            },
        );

        let coin_id = genesis_coin_id(*addr, idx);

        let obj = Object {
            id: coin_id,
            type_tag: coin_type.clone(),
            owner: Owner::Address(addr.0),
            version: 0,
            payload: coin_payload(*balance),
        };
        state.set_object(obj.clone());

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
/// `blake3("bloom-petal-dex-it.genesis" || addr || idx_le32)`
pub fn genesis_coin_id(addr: Address, idx: usize) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"bloom-petal-dex-it.genesis");
    h.update(&addr.0);
    h.update(&(idx as u32).to_le_bytes());
    ObjectId(*h.finalize().as_bytes())
}

/// Insert a `Coin<LOOM>` object directly into `state` with a custom id.
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
/// override map (so `PtbChainAdapter::load_manifest` falls through to
/// the wasm custom-section path — the production manifest source —
/// for every petal hash), apply the write set on success, and return
/// the `ExecOutput`.
///
/// See `bloom-petal-it`'s `submit_ptb_chain_auth` doc-comment for
/// rationale; this is a verbatim DEX-side mirror.
pub fn submit_ptb_chain_auth(state: &mut State, sender: Address, ptb: PtbTx) -> ExecOutput {
    submit_ptb(state, sender, ptb, HashMap::new())
}

/// Wrap `ptb` as a `TxKind::SubmitPtb` transaction, drive it through
/// `ChainPetalExecutorWithManifests`, **apply the write set on success**,
/// and return the `ExecOutput`.
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

/// Parse a WAT source string into wasm bytes. Panics on malformed WAT.
pub fn wat_to_wasm(src: &str) -> Vec<u8> {
    wat::parse_str(src).expect("valid WAT")
}

/// Append a `bloom_petal_manifest_v0` custom section carrying
/// `manifest_bytes` to `wasm`. See [`crate::dex_harness`] / the
/// `bloom-petal-it` mirror for the rationale: this pairs a real,
/// chain-authoritative manifest (as the macro emits into the wasm
/// custom section) with a hand-written WAT body so tests don't need
/// `wasm32-unknown-unknown` at compile time.
pub fn append_manifest_section(mut wasm: Vec<u8>, manifest_bytes: &[u8]) -> Vec<u8> {
    let name = "bloom_petal_manifest_v0";
    let mut body = Vec::new();
    leb128(&mut body, name.len() as u64);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(manifest_bytes);
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
/// `/bloom/core/fungible` petal.
pub fn real_fungible_manifest_bytes() -> &'static [u8] {
    bloom_petal_fungible::fungible::__bloom_manifest_bytes()
}

/// Canonical `PetalManifestV0` bytes embedded in the real
/// `/bloom/dex/pool` petal.
pub fn real_pool_manifest_bytes() -> &'static [u8] {
    bloom_petal_dex_pool::pool::__bloom_manifest_bytes()
}

/// Canonical `PetalManifestV0` bytes embedded in the real
/// `/bloom/dex/strategy/cpmm` petal.
pub fn real_cpmm_manifest_bytes() -> &'static [u8] {
    bloom_petal_dex_cpmm::cpmm::__bloom_manifest_bytes()
}

/// Canonical `PetalManifestV0` bytes embedded in the real
/// `/bloom/dex/router` petal.
pub fn real_router_manifest_bytes() -> &'static [u8] {
    bloom_petal_dex_router::router::__bloom_manifest_bytes()
}

// ---------------------------------------------------------------------------
// Manifest helpers
// ---------------------------------------------------------------------------

/// Build a `PetalManifestStub` declaring a single zero-arg, zero-return
/// `__petal_<fn_name>` function.
pub fn manifest_nullary(fn_name: &str) -> PetalManifestStub {
    PetalManifestStub {
        module_path: "/dex/petal-it".to_string(),
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
