//! Real chain-mode petal executor.
//!
//! Bridges `consensus_driver::PetalExecutor` to `bloom_petals::PetalVm::run_chain_call`.
//!
//! Handles the three tx kinds:
//! - `Transfer`: pure LOOM move (no VM invocation).
//! - `Deploy`: validate wasm → check address collision → stage code + account →
//!   invoke `init` via the chain VM → on success, commit snapshot writes and
//!   return the deploy address; on revert, drop writes.
//! - `Call`: load wasm by `code_hash` → forward value → invoke `call` via the
//!   chain VM → on success commit writes, on revert drop them.
//!
//! Snapshot semantics:
//! - `consensus_driver::apply_block` debits `max_fuel * fee_per_unit + value`
//!   from the sender at the `State` level *before* calling `execute_tx`. The
//!   snapshot we take here therefore already reflects that debit.
//! - The VM returns the (mutated) snapshot; we `.commit()` it into a `WriteSet`
//!   on success, or drop it on revert.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bloom_chain_state::{Account, State};
use bloom_chain_types::{
    digest::{blake3_tagged, tags},
    receipt::Log,
    tx::{Tx, TxKind},
    types::{Address, Hash32},
};
use bloom_objects::{OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey};
use bloom_petal_fungible::ops::{
    coin_payload, decode_coin_value, rewrite_value, type_tag_coin_loom,
};
use bloom_petals::{BlockCtx as PetalBlockCtx, ChainCallInput, ChainEntry, PetalVm};
use bloom_script::{
    AlwaysOkVerifier, PetalManifestStub, SignatureVerifier, ValidationContext,
    executor::{LogEntry as PtbLogEntry, PtbExecutor},
    host_ctx::PtbHostCtx,
    loom_coin_type_tag, validate_ptb,
};
use tracing::warn;

use crate::chain_petal_runner::ChainPetalRunner;
use crate::coin_select::select_coin_loom;
use crate::consensus_driver::{ExecOutput, PetalExecutor, empty_account};
use crate::ptb_chain_iface::PtbChainAdapter;
use crate::sig_verifier::Ed25519PtbVerifier;

/// Production chain-mode executor.
///
/// `ChainPetalExecutor` is a unit struct so all existing call sites
/// (e.g. `Arc::new(ChainPetalExecutor)` in `node.rs`,
/// `&ChainPetalExecutor` in test fixtures) remain source-compatible.
///
/// PTB-mode `Command::Move` dispatch is **chain-authoritative**: the
/// validator's typecheck pulls each referenced petal's manifest by
/// decoding the `bloom_petal_manifest_v0` wasm custom section (spec
/// §8.1, §11.1) on demand via [`PtbChainAdapter::new`]. No external
/// manifest registry is required.
pub struct ChainPetalExecutor;

/// **Test-only** wrapper around [`ChainPetalExecutor`] that injects a
/// per-petal manifest override map into the SubmitPtb dispatch path.
///
/// Production code uses [`ChainPetalExecutor`] directly, which derives
/// manifests from each petal's wasm custom section. This wrapper
/// exists for tests that need to validate PTBs against petals which
/// either:
/// - aren't real wasm (e.g. validator unit tests with mock manifests), or
/// - need a synthetic manifest that diverges from the petal's embedded
///   section (e.g. negative-path tests).
///
/// The override map is consulted **before** the wasm custom-section
/// path inside [`PtbChainAdapter::with_overrides`].
pub struct ChainPetalExecutorWithManifests {
    /// Per-petal manifest override map consulted by the PTB validator
    /// in lieu of (or in addition to) the wasm custom section.
    pub manifests: HashMap<Hash32, PetalManifestStub>,
}

impl ChainPetalExecutorWithManifests {
    /// Construct with an explicit manifest registry.
    pub fn new(manifests: HashMap<Hash32, PetalManifestStub>) -> Self {
        Self { manifests }
    }
}

/// Domain-separated derivation of a contract instance address (spec §7.7).
///
///   instance_address = blake3(
///       "bloom-chain.v0.addr:" ||
///       "deploy:" || deployer || ":" || salt || ":" || petal_hash)
fn deploy_address(deployer: &Address, salt: &[u8; 32], petal_hash: &Hash32) -> Address {
    let mut h = blake3::Hasher::new();
    h.update(tags::ADDR.as_bytes());
    h.update(b"deploy:");
    h.update(&deployer.0);
    h.update(b":");
    h.update(salt);
    h.update(b":");
    h.update(&petal_hash.0);
    Address(*h.finalize().as_bytes())
}

fn petal_log_to_receipt_log(l: bloom_petals::LogEntry) -> Log {
    Log {
        address: l.address,
        topics: l.topics,
        data: l.data,
    }
}

/// Serialise an `ExecutionReport::command_outputs` matrix into the
/// receipt's `return_data` byte buffer.
///
/// Wire shape (all integers big-endian):
///   `u32 num_commands` |
///   for each command: `u32 num_slots` | for each slot: `u32 len` | bytes
///
/// This mirrors the per-call envelope produced by
/// `bloom_script::executor::marshal_args` / `unmarshal_outputs`, just
/// wrapped one level deeper so an RPC consumer can recover every
/// command's return slots in order. A PTB with no Move commands (e.g.
/// pure `TransferObjects`) serialises to `\x00\x00\x00\x00`.
fn encode_command_outputs(outputs: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(outputs.len() as u32).to_be_bytes());
    for cmd in outputs {
        buf.extend_from_slice(&(cmd.len() as u32).to_be_bytes());
        for slot in cmd {
            buf.extend_from_slice(&(slot.len() as u32).to_be_bytes());
            buf.extend_from_slice(slot);
        }
    }
    buf
}

/// Map a PTB-host-context [`PtbLogEntry`] into the chain receipt
/// [`Log`] shape.
///
/// - `address` ← the emitting petal's content hash (32 bytes,
///   reinterpreted as an `Address`). This is the same convention used
///   by §16.2's `log.emit` host import.
/// - `topics` ← if the topic is exactly 32 bytes, surface it
///   verbatim; otherwise hash it down to a single 32-byte topic so
///   indexers see a stable key. Empty topic ⇒ empty topic list.
/// - `data` ← bytes verbatim.
fn ptb_log_to_receipt_log(l: PtbLogEntry) -> Log {
    let topics = if l.topic.is_empty() {
        Vec::new()
    } else if l.topic.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&l.topic);
        vec![Hash32(arr)]
    } else {
        vec![Hash32(*blake3::hash(&l.topic).as_bytes())]
    };
    Log {
        address: Address(l.petal.0),
        topics,
        data: l.data,
    }
}

/// For each unique owner referenced — *both* old and new sides of
/// every transfer, plus the prior owner of every delete — rebuild
/// the corresponding `OwnershipIndex` trie row from the snapshot's
/// current object table (spec §16.3).
///
/// **Symmetry contract (P1-2):** when an object is transferred from
/// `A` to `B`, the index must drop the id from `A`'s row and add it
/// to `B`'s. When an object is deleted, the id must drop from its
/// owner's row. Earlier revisions only rebuilt the *new* owner's
/// row, leaving stale ids behind in the old owner's row (and
/// rebuilding nothing for deletes). This implementation collects
/// every affected owner key from both sides.
///
/// Phase 1 walks the in-memory object map per affected owner; Phase 2
/// will keep an incremental index inside the trie itself. The Phase 1
/// implementation is O(unique_owners * candidate_ids) — acceptable
/// for the tens-to-low-hundreds of objects per PTB the v0 chain
/// expects.
///
/// The membership of each rebuilt row is determined by reading each
/// candidate object's current record from the snapshot (which
/// already reflects the executor's `object_writes` / `object_deletes`),
/// so deleted ids and re-homed ids naturally fall out of the old
/// owner's row.
fn rebuild_ownership_rows(
    snapshot: &mut bloom_chain_state::StateSnapshot,
    transfers: &[(
        bloom_objects::ObjectId,
        bloom_objects::Owner,
        bloom_objects::Owner,
    )],
    deletes: &[(bloom_objects::ObjectId, bloom_objects::Owner)],
) {
    use bloom_objects::OWNER_KIND_OBJECT;

    // Helper: extract the (kind, owner_id) pair if this owner has an
    // ownership-index row. `Shared` / `Immutable` owners are not
    // indexed.
    fn owner_key(owner: &Owner) -> Option<(u8, [u8; 32])> {
        match owner {
            Owner::Address(a) => Some((OWNER_KIND_ADDRESS, *a)),
            Owner::Object(id) => Some((OWNER_KIND_OBJECT, id.0)),
            Owner::Shared | Owner::Immutable => None,
        }
    }

    // Collect unique (kind, owner_id) keys we need to rebuild.
    // Symmetric: both old and new owners for transfers, prior owner
    // for deletes.
    let mut keys: std::collections::BTreeSet<(u8, [u8; 32])> = std::collections::BTreeSet::new();
    for (_, old_owner, new_owner) in transfers {
        if let Some(k) = owner_key(old_owner) {
            keys.insert(k);
        }
        if let Some(k) = owner_key(new_owner) {
            keys.insert(k);
        }
    }
    for (_, old_owner) in deletes {
        if let Some(k) = owner_key(old_owner) {
            keys.insert(k);
        }
    }

    // Candidate id pool spans every transfer / delete (the executor's
    // touch-list). For each affected owner key we also fold in the
    // owner's existing index row so previously-resident ids whose
    // owner didn't change get carried through.
    let all_touched_ids: std::collections::BTreeSet<bloom_objects::ObjectId> = transfers
        .iter()
        .map(|(id, _, _)| *id)
        .chain(deletes.iter().map(|(id, _)| *id))
        .collect();

    for (kind, owner_id) in keys {
        let mut candidate_ids: std::collections::BTreeSet<bloom_objects::ObjectId> =
            all_touched_ids.clone();
        if let Some(existing) = snapshot.get_ownership(&OwnershipIndexKey {
            owner_kind: kind,
            owner_id,
        }) {
            candidate_ids.extend(existing);
        }
        let mut owned: Vec<bloom_objects::ObjectId> = Vec::new();
        for cid in candidate_ids {
            // Deleted objects vanish from `get_object`, so they fall
            // out of every owner's row naturally.
            if let Some(obj) = snapshot.get_object(&cid) {
                let matches = match (&obj.owner, kind) {
                    (Owner::Address(a), OWNER_KIND_ADDRESS) => *a == owner_id,
                    (Owner::Object(o), OWNER_KIND_OBJECT) => o.0 == owner_id,
                    _ => false,
                };
                if matches {
                    owned.push(cid);
                }
            }
        }
        owned.sort();
        // Empty `owned` is set via `set_ownership` which evicts the
        // row to keep the trie sparse.
        snapshot.set_ownership(
            OwnershipIndexKey {
                owner_kind: kind,
                owner_id,
            },
            owned,
        );
    }
}

impl PetalExecutor for ChainPetalExecutor {
    fn execute_tx(
        &self,
        tx: &Tx,
        state: &mut State,
        block_number: u64,
        timestamp_ms: u64,
        proposer: Address,
        parent_hash: Hash32,
    ) -> ExecOutput {
        // Production path: manifests resolve from each petal's wasm
        // custom section. `None` overrides ⇒ wasm-only resolution.
        // PTB signer signatures are checked with the production
        // Ed25519 verifier (P0-3 fix, spec §7.2 step 1).
        let verifier = Ed25519PtbVerifier::new();
        execute_tx_impl(
            tx,
            state,
            block_number,
            timestamp_ms,
            proposer,
            parent_hash,
            None,
            &verifier,
        )
    }
}

impl PetalExecutor for ChainPetalExecutorWithManifests {
    fn execute_tx(
        &self,
        tx: &Tx,
        state: &mut State,
        block_number: u64,
        timestamp_ms: u64,
        proposer: Address,
        parent_hash: Hash32,
    ) -> ExecOutput {
        // `ChainPetalExecutorWithManifests` is a **test-only** wrapper
        // (see struct docs). Its existing fixtures across the workspace
        // construct PTBs with stub signer / signature placeholders and
        // exercise downstream pipeline steps (host imports, ownership
        // index, gas refund, …), not signature cryptography. Keeping
        // the always-ok verifier here preserves that contract while the
        // production `ChainPetalExecutor` path uses
        // [`Ed25519PtbVerifier`]. Tests that *do* want to exercise real
        // signature verification go through `ChainPetalExecutor`
        // directly (see `tests/ptb_signature_rejection.rs`).
        let verifier = AlwaysOkVerifier;
        execute_tx_impl(
            tx,
            state,
            block_number,
            timestamp_ms,
            proposer,
            parent_hash,
            Some(&self.manifests),
            &verifier,
        )
    }
}

/// Shared `PetalExecutor::execute_tx` body. The trailing `manifests`
/// parameter is an optional per-petal manifest **override** map the
/// PTB validator consults *before* the wasm custom-section path
/// during `Command::Move` typechecks. Production passes `None`.
///
/// `verifier` plugs the signature-check policy: production uses
/// [`Ed25519PtbVerifier`]; the test-only `ChainPetalExecutorWithManifests`
/// uses `AlwaysOkVerifier` for backwards compatibility with existing
/// stub-signature fixtures.
#[allow(clippy::too_many_arguments)]
fn execute_tx_impl(
    tx: &Tx,
    state: &mut State,
    block_number: u64,
    timestamp_ms: u64,
    proposer: Address,
    parent_hash: Hash32,
    manifests: Option<&HashMap<Hash32, PetalManifestStub>>,
    verifier: &dyn SignatureVerifier,
) -> ExecOutput {
    // `parent_hash` is the committing block's parent block hash —
    // surfaced to chain-mode petals as `chain::block.prevhash`
    // (review 2026-05-19 #13). Threaded in by
    // `apply_block_state_transitions` from `block.header.parent_hash`.
    let block_ctx = PetalBlockCtx {
        number: block_number,
        timestamp_ms,
        prevhash: parent_hash,
    };

    match &tx.kind {
        TxKind::Transfer { to, amount_loom } => {
            // Pure LOOM move — no VM invocation required.
            let mut snap = state.snapshot();
            let mut to_acct = snap.get_account(to).unwrap_or_else(empty_account);
            to_acct.loom += amount_loom;
            snap.set_account(*to, to_acct);

            // ── PTB compat shim ─────────────────────────────────────────
            // Keep Coin<LOOM> objects in sync with the Account.loom update.
            // If select_coin_loom returns Insufficient we warn and continue
            // (legacy Account.loom is the authoritative source of truth in
            // Phase 2/3; Phase 4 removal will tighten this).
            //
            // TODO(phase4): make Coin<LOOM> insufficient a hard revert once
            // the legacy Account.loom path is removed.
            if *amount_loom > 0 {
                apply_coin_loom_transfer(&mut snap, tx.sender, *to, *amount_loom, &tx.tx_hash());
            }

            let ws = snap.commit();
            ExecOutput {
                success: true,
                fuel_used: 100,
                return_data: vec![],
                logs: vec![],
                write_set: Some(ws),
            }
        }

        TxKind::Deploy {
            wasm,
            salt,
            init_args,
            manifest_hash,
        } => {
            if let Err(e) = PetalVm::validate_for_chain(wasm) {
                return ExecOutput {
                    success: false,
                    fuel_used: 0,
                    return_data: format!("invalid wasm: {e}").into_bytes(),
                    logs: vec![],
                    write_set: None,
                };
            }

            let petal_hash = blake3_tagged(tags::PETAL, wasm);
            let addr = deploy_address(&tx.sender, salt, &petal_hash);

            // Collision: address already deployed (§7.7).
            if let Some(a) = state.get_account(&addr)
                && a.code_hash.is_some()
            {
                return ExecOutput {
                    success: false,
                    fuel_used: 0,
                    return_data: b"deploy address already in use".to_vec(),
                    logs: vec![],
                    write_set: None,
                };
            }

            // Stage account + code in the snapshot; invoke init. The
            // deployer's manifest anchor (if present) lands in the
            // account here, before `init` runs, so a contract can read
            // its own anchor inside `init` via the chain.code import.
            let mut snap = state.snapshot();
            snap.insert_code(wasm.clone());
            let mut acct = snap.get_account(&addr).unwrap_or_else(empty_account);
            acct.code_hash = Some(petal_hash);
            acct.manifest_hash = *manifest_hash;
            snap.set_account(addr, acct);

            let input = ChainCallInput {
                wasm: wasm.clone(),
                entry: ChainEntry::Init,
                contract_address: addr,
                msg_sender: tx.sender,
                msg_value: 0,
                calldata: init_args.clone(),
                block: block_ctx,
                fuel: tx.max_fuel,
                snapshot: snap,
                ptb_ctx: None,
            };

            // Decode the petal's manifest custom section (if
            // present) so we can bind `module_path → petal_hash` in
            // the VFS index. New-framework petals always carry one;
            // legacy framework petals don't, in which case we leave
            // the VFS index untouched (the petal is reachable only
            // by pure-hash refs).
            let vfs_binding: Option<(String, Hash32)> =
                bloom_petal_manifest::extract_petal_manifest_v0(wasm)
                    .filter(|m| !m.module_path.is_empty())
                    .map(|m| (m.module_path, petal_hash));

            match PetalVm::run_chain_call(input) {
                Ok(out) => {
                    if let Some(reason) = out.revert_reason {
                        // Snapshot writes discarded.
                        ExecOutput {
                            success: false,
                            fuel_used: out.fuel_used,
                            return_data: reason,
                            logs: out.logs.into_iter().map(petal_log_to_receipt_log).collect(),
                            write_set: None,
                        }
                    } else {
                        let ws = out.snapshot.commit();
                        // VFS binding survives the deploy only if
                        // init succeeded. We apply it directly to
                        // `state` after the write-set commits (the
                        // VFS is a derived index, not part of the
                        // committed state root).
                        if let Some((path, hash)) = vfs_binding {
                            state.set_vfs_binding(path, hash);
                        }
                        tracing::info!(
                            addr = %hex::encode(addr.0),
                            fuel_used = out.fuel_used,
                            "deploy committed"
                        );
                        ExecOutput {
                            success: true,
                            fuel_used: out.fuel_used,
                            return_data: addr.0.to_vec(),
                            logs: out.logs.into_iter().map(petal_log_to_receipt_log).collect(),
                            write_set: Some(ws),
                        }
                    }
                }
                Err(e) => {
                    warn!(err = %e, "deploy trapped");
                    ExecOutput {
                        success: false,
                        fuel_used: tx.max_fuel,
                        return_data: e.to_string().into_bytes(),
                        logs: vec![],
                        write_set: None,
                    }
                }
            }
        }

        TxKind::Call {
            to,
            calldata,
            value_loom,
        } => {
            // Resolve callee: contract → load wasm; non-contract → value-transfer only.
            let callee = state.get_account(to);
            let code_hash = callee.as_ref().and_then(|a| a.code_hash);

            let wasm: Vec<u8> = match code_hash {
                Some(ref h) => match state.get_code(h) {
                    Some(b) => b.to_vec(),
                    None => {
                        return ExecOutput {
                            success: false,
                            fuel_used: 0,
                            return_data: b"code missing for code_hash".to_vec(),
                            logs: vec![],
                            write_set: None,
                        };
                    }
                },
                None => {
                    // Pure value transfer (callee is an EOA).
                    let mut snap = state.snapshot();
                    if *value_loom > 0 {
                        let mut to_acct = snap.get_account(to).unwrap_or_else(empty_account);
                        to_acct.loom += value_loom;
                        snap.set_account(*to, to_acct);

                        // PTB compat shim: keep Coin<LOOM> objects in sync.
                        apply_coin_loom_transfer(
                            &mut snap,
                            tx.sender,
                            *to,
                            *value_loom,
                            &tx.tx_hash(),
                        );
                    }
                    return ExecOutput {
                        success: true,
                        fuel_used: 100,
                        return_data: vec![],
                        logs: vec![],
                        write_set: Some(snap.commit()),
                    };
                }
            };

            // Pre-credit value to callee inside the snapshot.
            let mut snap = state.snapshot();
            if *value_loom > 0 {
                let mut to_acct = snap.get_account(to).unwrap_or_else(empty_account);
                to_acct.loom += value_loom;
                snap.set_account(*to, to_acct);

                // PTB compat shim: keep Coin<LOOM> objects in sync.
                // This runs BEFORE the VM call so the Coin<LOOM> credit
                // and Account.loom credit land together in the writeset.
                apply_coin_loom_transfer(&mut snap, tx.sender, *to, *value_loom, &tx.tx_hash());
            }

            let input = ChainCallInput {
                wasm,
                entry: ChainEntry::Call,
                contract_address: *to,
                msg_sender: tx.sender,
                msg_value: *value_loom,
                calldata: calldata.clone(),
                block: block_ctx,
                fuel: tx.max_fuel,
                snapshot: snap,
                ptb_ctx: None,
            };

            match PetalVm::run_chain_call(input) {
                Ok(out) => {
                    if let Some(reason) = out.revert_reason {
                        warn!(
                            to = %hex::encode(to.0),
                            fuel_used = out.fuel_used,
                            reason = %String::from_utf8_lossy(&reason),
                            "call reverted"
                        );
                        ExecOutput {
                            success: false,
                            fuel_used: out.fuel_used,
                            return_data: reason,
                            logs: out.logs.into_iter().map(petal_log_to_receipt_log).collect(),
                            write_set: None,
                        }
                    } else {
                        let ws = out.snapshot.commit();
                        ExecOutput {
                            success: true,
                            fuel_used: out.fuel_used,
                            return_data: out.return_data.unwrap_or_default(),
                            logs: out.logs.into_iter().map(petal_log_to_receipt_log).collect(),
                            write_set: Some(ws),
                        }
                    }
                }
                Err(e) => {
                    warn!(to = %hex::encode(to.0), err = %e, "call trapped");
                    ExecOutput {
                        success: false,
                        fuel_used: tx.max_fuel,
                        return_data: e.to_string().into_bytes(),
                        logs: vec![],
                        write_set: None,
                    }
                }
            }
        }

        // PTB dispatch (spec §16.2). The PTB wire bytes are decoded
        // here; structural decode failures revert atomically with
        // no fuel consumed beyond the spec-mandated minimum (zero —
        // the PTB never reached execution). Downstream commits in
        // this branch wire validator + executor + host imports.
        TxKind::SubmitPtb { ptb_bytes } => {
            match bloom_script::decode_ptb(ptb_bytes) {
                Err(e) => {
                    warn!(
                        sender = %hex::encode(tx.sender.0),
                        err = %e,
                        "SubmitPtb decode failed"
                    );
                    ExecOutput {
                        success: false,
                        fuel_used: 0,
                        return_data: format!("ptb decode error: {e}").into_bytes(),
                        logs: vec![],
                        write_set: None,
                    }
                }
                Ok(ptb) => {
                    // Validator runs against current chain state.
                    // The signature verifier is now supplied by the
                    // caller (P0-3 fix, spec §7.2 step 1): the
                    // production `ChainPetalExecutor` hands in
                    // `Ed25519PtbVerifier`; the test-only
                    // `ChainPetalExecutorWithManifests` keeps
                    // `AlwaysOkVerifier` for legacy fixtures (see
                    // each impl's call to `execute_tx_impl`).
                    //
                    // TODO(task#32): replace the all-zero
                    // `loom_coin_type` and `fungible_petal_hash`
                    // below with the values pinned at genesis once
                    // the fungible petal lands.
                    let loom_coin_type = loom_coin_type_tag(Hash32([0u8; 32]));
                    let fungible_petal_hash = Hash32([0u8; 32]);

                    // Capture per-PTB scratch we need across the
                    // immutable borrow of `state` (validate) and
                    // the mutable borrow (commit) below.
                    let signers = ptb.signers.clone();

                    let validated = {
                        let adapter = match manifests {
                            Some(m) => PtbChainAdapter::with_overrides(state, block_number, m),
                            None => PtbChainAdapter::new(state, block_number),
                        };
                        let ctx = ValidationContext {
                            current_block: block_number,
                            chain: &adapter,
                            verifier,
                            loom_coin_type: loom_coin_type.clone(),
                        };
                        match validate_ptb(&ptb, &ctx) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!(
                                    sender = %hex::encode(tx.sender.0),
                                    err = %e,
                                    "SubmitPtb validation failed"
                                );
                                return ExecOutput {
                                    success: false,
                                    fuel_used: 0,
                                    return_data: format!("ptb validation error: {e}").into_bytes(),
                                    logs: vec![],
                                    write_set: None,
                                };
                            }
                        }
                    };

                    // Build the host-context + snapshot the runner
                    // and §16.2 imports share.
                    let host_ctx = {
                        let mut c = PtbHostCtx::new();
                        c.signers = signers;
                        Arc::new(Mutex::new(c))
                    };
                    let mut snapshot = state.snapshot();

                    // P0-5: pre-execution gas reservation (spec §7.2
                    // step 6 + §9.4). The validator already verified
                    // that the gas-payer `Coin<LOOM>` exists, is
                    // owned by the first signer, and holds at least
                    // `gas_budget * gas_price`. Debit the full
                    // reservation from the coin *before* the PTB
                    // sees the snapshot so the VM can't observe an
                    // un-reserved gas-payer balance. Stash the
                    // pre-execution object so the revert path can
                    // settle off the original — not whatever the
                    // PTB might have mutated mid-flight.
                    //
                    // When `gas_budget * gas_price == 0` (e.g.
                    // free-tier PTBs used in tests / micro-tx
                    // fixtures) we skip the gas plumbing entirely:
                    // no debit, no refund, no proposer credit. The
                    // gas-payer object is left untouched so the
                    // revert path matches the historical contract
                    // (write_set = None on revert).
                    let gas_payer_id = ptb.gas_payer;
                    let gas_budget = ptb.gas_budget;
                    let gas_price = ptb.gas_price;
                    let reservation = (gas_budget as u128).saturating_mul(gas_price);
                    let pre_exec_gas_payer = validated
                        .objects
                        .get(&gas_payer_id.0)
                        .cloned()
                        .expect("validator inserted gas_payer object");
                    if reservation > 0 {
                        // Apply pre-debit. `version` is monotonic on
                        // every mutation (spec §4.4).
                        let pre_value = decode_coin_value(&pre_exec_gas_payer.payload)
                            .expect("validator decoded coin value");
                        let debited = pre_value.saturating_sub(reservation);
                        let new_payload = rewrite_value(&pre_exec_gas_payer.payload, debited)
                            .expect("rewrite Coin<LOOM> payload");
                        let mut debited_obj = pre_exec_gas_payer.clone();
                        debited_obj.version = debited_obj.version.saturating_add(1);
                        debited_obj.payload = new_payload;
                        snapshot.insert_object(debited_obj);
                    }

                    let petals_owned = ChainPetalRunner::petals_from_validated(&validated.petals);
                    let runner = ChainPetalRunner::new(
                        petals_owned,
                        Arc::clone(&host_ctx),
                        snapshot,
                        block_ctx.clone(),
                        tx.sender,
                    );

                    // The ChainStateIface adapter the executor
                    // hands to its built-in commands needs a
                    // borrow of `state`; create it inside this
                    // scope so we drop it before reclaiming
                    // ownership of the snapshot.
                    //
                    // CRITICAL (P0-2): the executor MUST share the
                    // same `Arc<Mutex<PtbHostCtx>>` as the wasm
                    // host imports. Without this, `object.borrow`
                    // can't see pre-loaded objects, and
                    // `object.create` rows land in a ctx the
                    // executor never reads. We thread `host_ctx`
                    // via `with_ctx_arc(...)` so the executor's
                    // pre-load + diff-check + linearity-check
                    // operate on the *same* borrow table the host
                    // imports mutate.
                    let report = {
                        let adapter = match manifests {
                            Some(m) => PtbChainAdapter::with_overrides(state, block_number, m),
                            None => PtbChainAdapter::new(state, block_number),
                        };
                        let mut exec = PtbExecutor::with_ctx_arc(
                            &adapter,
                            &runner,
                            loom_coin_type,
                            fungible_petal_hash,
                            Arc::clone(&host_ctx),
                        );
                        exec.execute(validated)
                    };

                    // The executor drains the ctx itself at the
                    // end of `execute(...)` (success path) and
                    // folds host-attributed entries (created
                    // objects, host deletes, host ownership
                    // changes, loom deltas, logs) into the
                    // `ExecutionReport`. We don't need a separate
                    // drain step here — the host_ctx behind the
                    // Arc has already been std::mem::take'n.

                    // Reclaim the snapshot the runner threaded
                    // through the calls.
                    let mut snapshot = runner.into_snapshot();

                    // Clamp fuel actually charged to the inner
                    // budget — defence-in-depth in case the
                    // executor accidentally reports more than the
                    // cap. The reservation we pre-debited is
                    // `gas_budget * gas_price`, so charging more
                    // would underflow the refund.
                    let charged_fuel = report.fuel_used.min(gas_budget);

                    if !report.success {
                        // Revert: drop every PTB-side mutation —
                        // EXCEPT the gas accounting, which must
                        // still settle. The pre-execution snapshot
                        // already debited the gas-payer Coin<LOOM>
                        // by the full reservation; on revert we
                        // burn the entire `gas_budget * gas_price`
                        // to the proposer (no refund, even if
                        // `report.fuel_used < gas_budget`). Build a
                        // fresh snapshot off `state` so the
                        // intermediate writes the PTB made are
                        // discarded but the gas debit + proposer
                        // credit still land in the WriteSet.
                        //
                        // For zero-reservation PTBs the write_set
                        // stays `None` — matches the historical
                        // contract atomic-revert tests rely on.
                        let reason = report
                            .reverted_with
                            .as_ref()
                            .map(|e| e.to_string())
                            .unwrap_or_else(|| "ptb reverted".to_string());
                        warn!(
                            sender = %hex::encode(tx.sender.0),
                            reason = %reason,
                            "SubmitPtb reverted"
                        );
                        // Drop the in-flight snapshot.
                        drop(snapshot);
                        let ws_out = if reservation > 0 {
                            let mut gas_snap = state.snapshot();
                            let mut debited = pre_exec_gas_payer.clone();
                            let pre_value = decode_coin_value(&debited.payload)
                                .expect("decode pre-exec coin value");
                            let new_value = pre_value.saturating_sub(reservation);
                            debited.payload = rewrite_value(&debited.payload, new_value)
                                .expect("rewrite coin payload");
                            debited.version = debited.version.saturating_add(1);
                            gas_snap.insert_object(debited);
                            // Credit proposer the full burn.
                            // Saturating-cast to i128 for safety
                            // (reservation is bounded by the
                            // validator's coin-value check).
                            gas_snap.apply_loom_delta(
                                proposer,
                                reservation.min(i128::MAX as u128) as i128,
                            );
                            Some(gas_snap.commit())
                        } else {
                            None
                        };
                        return ExecOutput {
                            success: false,
                            fuel_used: charged_fuel,
                            return_data: reason.into_bytes(),
                            logs: vec![],
                            write_set: ws_out,
                        };
                    }

                    // Success: fold the unified ExecutionReport
                    // (which already includes both executor- and
                    // host-import-attributed state) into the
                    // snapshot.
                    for obj in &report.object_writes {
                        snapshot.insert_object(obj.clone());
                    }
                    for (id, _old_owner) in &report.object_deletes {
                        snapshot.delete_object(*id);
                    }
                    // Ownership-index rewrites: rebuild the row
                    // for every affected owner — both sides of
                    // each transfer plus the prior owner of each
                    // delete (P1-2: spec §16.3 owner-symmetric
                    // rebuild). The lists now include
                    // host-import-attributed changes (drained
                    // into the report by the executor's commit
                    // step).
                    rebuild_ownership_rows(
                        &mut snapshot,
                        &report.ownership_changes,
                        &report.object_deletes,
                    );

                    // Loom deltas: executor- and host-import-
                    // attributed (both flow through report).
                    for d in &report.loom_deltas {
                        snapshot.apply_loom_delta(Address(d.address), d.delta);
                    }

                    // P0-5: settle inner gas. The reservation was
                    // already debited from the gas-payer Coin<LOOM>
                    // pre-execution. Refund the unused portion to
                    // the (possibly mutated) gas-payer object, and
                    // credit the proposer with the burnt portion.
                    // If the PTB itself deleted the gas-payer
                    // object we keep the full burn (no refund) but
                    // still credit the proposer the burnt amount,
                    // matching the spec's settlement boundary.
                    let burnt = (charged_fuel as u128).saturating_mul(gas_price);
                    let refund = reservation.saturating_sub(burnt);
                    if refund > 0 {
                        if let Some(mut current) = snapshot.get_object(&gas_payer_id) {
                            match decode_coin_value(&current.payload) {
                                Ok(cur_value) => {
                                    let new_value = cur_value.saturating_add(refund);
                                    match rewrite_value(&current.payload, new_value) {
                                        Ok(new_payload) => {
                                            current.payload = new_payload;
                                            current.version = current.version.saturating_add(1);
                                            snapshot.insert_object(current);
                                        }
                                        Err(e) => warn!(
                                            err = ?e,
                                            gas_payer = %hex::encode(gas_payer_id.0),
                                            "PTB gas refund: rewrite_value failed; skipping refund"
                                        ),
                                    }
                                }
                                Err(e) => warn!(
                                    err = ?e,
                                    gas_payer = %hex::encode(gas_payer_id.0),
                                    "PTB gas refund: decode_coin_value failed; skipping refund"
                                ),
                            }
                        } else {
                            warn!(
                                gas_payer = %hex::encode(gas_payer_id.0),
                                "PTB gas refund: gas-payer object deleted by PTB; skipping refund"
                            );
                        }
                    }
                    // Proposer credit (always — burnt or full
                    // burn). saturating_cast i128 for safety.
                    if burnt > 0 {
                        snapshot.apply_loom_delta(proposer, burnt.min(i128::MAX as u128) as i128);
                    }

                    let ws = snapshot.commit();
                    let logs: Vec<Log> = report
                        .logs
                        .clone()
                        .into_iter()
                        .map(ptb_log_to_receipt_log)
                        .collect();

                    // Serialise per-command return slots into
                    // `return_data` so RPC consumers can recover
                    // every command's outputs deterministically.
                    let return_data = encode_command_outputs(&report.command_outputs);

                    ExecOutput {
                        success: true,
                        fuel_used: charged_fuel,
                        return_data,
                        logs,
                        write_set: Some(ws),
                    }
                }
            }
        }
    }
}

/// PTB compat shim: adjust Coin<LOOM> objects to match a legacy
/// `Account.loom` debit/credit pair.
///
/// Steps:
/// 1. Call `select_coin_loom` to pick sender coins.
/// 2. Delete consumed coins from the snapshot; shrink the split remainder.
/// 3. Mint a new `Coin<LOOM>` owned by `to` with value `amount`.
/// 4. Update ownership indices for both `sender` and `to`.
///
/// If `sender` lacks sufficient `Coin<LOOM>` (e.g. the coins are already
/// diverged from `Account.loom`), this logs a warning and returns
/// without modifying the object world. The `Account.loom` update in the
/// caller is the source of truth and proceeds regardless.
///
/// TODO(phase4): tighten to a hard revert once the legacy Account.loom
/// path is removed.
fn apply_coin_loom_transfer(
    snap: &mut bloom_chain_state::StateSnapshot,
    sender: Address,
    to: Address,
    amount: u128,
    tx_hash: &Hash32,
) {
    use crate::coin_select::CoinSelection;

    let coin_type = type_tag_coin_loom();

    // 1. Select sender coins.
    let selection: CoinSelection = match select_coin_loom(snap, sender, amount) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                sender = %hex::encode(sender.0),
                to = %hex::encode(to.0),
                amount = amount,
                err = %e,
                "legacy Transfer/Call Coin<LOOM> state diverged — \
                 Account.loom updated but Coin<LOOM> objects unchanged; \
                 TODO(phase4): remove legacy Account.loom path"
            );
            return;
        }
    };

    // 2a. Delete fully-consumed coins and remove from sender's ownership index.
    let sender_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: sender.0,
    };
    let mut sender_owned = snap.get_ownership(&sender_okey).unwrap_or_default();
    for id in &selection.consumed {
        snap.delete_object(*id);
        sender_owned.retain(|x| x != id);
    }

    // 2b. If last coin is split: update its payload to the remainder value.
    if let Some((id, new_value)) = selection.split_remainder
        && let Some(mut obj) = snap.get_object(&id)
    {
        obj.payload = coin_payload(new_value);
        obj.version += 1;
        snap.insert_object(obj);
        // The split coin stays in sender_owned — we keep it.
    }

    snap.set_ownership(sender_okey, sender_owned);

    // 3. Mint a new Coin<LOOM> owned by `to`.
    //
    // Deterministic ObjectId: blake3("bloom.legacy.transfer" || tx_hash)
    // Each Transfer tx is 1-to-1 with exactly one mint, so the tx hash
    // as the sole input is collision-free across distinct txs.
    let new_coin_id = {
        let mut h = blake3::Hasher::new();
        h.update(b"bloom.legacy.transfer");
        h.update(&tx_hash.0);
        ObjectId(*h.finalize().as_bytes())
    };

    let new_coin = Object {
        id: new_coin_id,
        type_tag: coin_type,
        owner: Owner::Address(to.0),
        version: 0,
        payload: coin_payload(amount),
    };
    snap.insert_object(new_coin);

    // 4. Update ownership index for `to`.
    let to_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: to.0,
    };
    let mut to_owned = snap.get_ownership(&to_okey).unwrap_or_default();
    let pos = to_owned.partition_point(|id| id.0 < new_coin_id.0);
    to_owned.insert(pos, new_coin_id);
    snap.set_ownership(to_okey, to_owned);
}

// suppress unused-import lints when Account isn't needed in some configs
#[allow(dead_code)]
fn _typecheck() -> Option<Account> {
    None
}
