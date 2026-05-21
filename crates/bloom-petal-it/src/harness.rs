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
use bloom_chain_state::{Account, State};
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_objects::{Object, ObjectId, Owner, OwnershipIndexKey, OWNER_KIND_ADDRESS};
use bloom_petal_fungible::ops::type_tag_coin_loom;
use bloom_script::{FunctionDeclStub, PetalManifestStub, encode_ptb, types::PtbTx};

// ---------------------------------------------------------------------------
// Coin payload format (PTB path)
// ---------------------------------------------------------------------------

/// Canonical coin payload for the **PTB executor path**: just the 16-byte
/// big-endian u128 value.
///
/// The PTB validator's `decode_coin_value` (in `bloom-script`) reads
/// `payload[0..16]` as the value. This differs from the 48-byte format
/// produced by `bloom_petal_fungible::ops::coin_payload` (32-byte ObjectId
/// placeholder + 16-byte value), which is used by the legacy-transfer shim
/// and the fungible petal's on-chain encoding.
///
/// This crate uses the 16-byte format for all coins seeded for PTB-path
/// tests so that both gas-payer validation and `SplitCoins` work correctly.
pub fn ptb_coin_payload(value: u128) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

/// Decode the value from a 16-byte PTB-path coin payload.
pub fn ptb_decode_coin_value(payload: &[u8]) -> u128 {
    if payload.len() < 16 {
        return 0;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&payload[..16]);
    u128::from_be_bytes(a)
}

// ---------------------------------------------------------------------------
// State seeding
// ---------------------------------------------------------------------------

/// Build a fresh `State` with each `(address, balance)` allocation:
/// 1. `Account.loom = balance` (derived cache, spec §9.2).
/// 2. A `Coin<LOOM>` object with a deterministic id owned by the address.
/// 3. The `OwnershipIndex` updated to list the coin.
///
/// This replicates what `Genesis::apply_to_state` does without requiring a
/// full `GenesisFile` or TOML parsing.
pub fn build_state(allocations: &[(Address, u128)]) -> State {
    let mut state = State::new();
    let coin_type = type_tag_coin_loom();

    for (idx, (addr, balance)) in allocations.iter().enumerate() {
        // Account.loom cache.
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

        // Deterministic Coin<LOOM> id.
        let coin_id = genesis_coin_id(*addr, idx);

        let obj = Object {
            id: coin_id,
            type_tag: coin_type.clone(),
            owner: Owner::Address(addr.0),
            version: 0,
            // Use the 16-byte PTB-path payload: the PTB validator's
            // decode_coin_value reads payload[0..16] as the u128 value.
            payload: ptb_coin_payload(*balance),
        };
        state.set_object(obj.clone());

        // Ownership index.
        let okey = OwnershipIndexKey { owner_kind: OWNER_KIND_ADDRESS, owner_id: addr.0 };
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
/// Uses the 16-byte PTB-path payload format (value at bytes[0..16]).
pub fn seed_coin(state: &mut State, id: ObjectId, owner: Address, value: u128) {
    let obj = Object {
        id,
        type_tag: type_tag_coin_loom(),
        owner: Owner::Address(owner.0),
        version: 0,
        payload: ptb_coin_payload(value),
    };
    state.set_object(obj.clone());

    let okey = OwnershipIndexKey { owner_kind: OWNER_KIND_ADDRESS, owner_id: owner.0 };
    let mut owned = state.get_ownership(&okey).unwrap_or_default();
    let pos = owned.partition_point(|id| id.0 < obj.id.0);
    owned.insert(pos, obj.id);
    state.set_ownership(okey, owned);
}

// ---------------------------------------------------------------------------
// PTB submission
// ---------------------------------------------------------------------------

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
        state.apply(ws).expect("apply write_set must not fail in harness");
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
pub fn single_manifest(
    hash: Hash32,
    fn_name: &str,
) -> HashMap<Hash32, PetalManifestStub> {
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
