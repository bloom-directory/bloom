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
use bloom_objects::OwnershipIndexKey;
use bloom_petals::{BlockCtx as PetalBlockCtx, ChainCallInput, ChainEntry, PetalVm};
use bloom_script::{
    executor::{LogEntry as PtbLogEntry, PtbExecutor},
    host_ctx::PtbHostCtx,
    AlwaysOkVerifier, PetalManifestStub, ValidationContext, loom_coin_type_tag,
    validate_ptb,
};
use tracing::warn;

use crate::chain_petal_runner::ChainPetalRunner;
use crate::consensus_driver::{ExecOutput, PetalExecutor, empty_account};
use crate::ptb_chain_iface::PtbChainAdapter;

/// Production chain-mode executor.
///
/// `ChainPetalExecutor` is a unit struct so all existing call sites
/// (e.g. `Arc::new(ChainPetalExecutor)` in `node.rs`,
/// `&ChainPetalExecutor` in test fixtures) remain source-compatible.
///
/// PTB-mode `Command::Move` dispatch needs a per-petal manifest stub
/// for the validator's typecheck. Production currently has no
/// in-state manifest registry — TODO(task#36 / spec §16.5) — so the
/// default unit-struct flow ships with an empty registry, and any
/// `Move`-bearing PTB reverts at validation. Tests that need to
/// exercise §16.2 host imports thread a manifest map through
/// [`ChainPetalExecutorWithManifests`] (a thin wrapper that
/// `impl PetalExecutor`s by delegating into the same code path).
pub struct ChainPetalExecutor;

/// Test wrapper around [`ChainPetalExecutor`] that injects a
/// per-petal manifest registry into the SubmitPtb dispatch path.
///
/// Drives the same `execute_tx` body as the unit-struct flow with
/// the only difference being the manifest source consulted by the
/// PTB validator.
pub struct ChainPetalExecutorWithManifests {
    /// Per-petal manifest registry consulted by the PTB validator.
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
    Log { address: l.address, topics: l.topics, data: l.data }
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

/// For each unique owner referenced in `(id, new_owner)` updates,
/// rebuild the corresponding `OwnershipIndex` trie row from the
/// snapshot's current object table.
///
/// Phase 1 walks the in-memory object map per affected owner; Phase 2
/// will keep an incremental index inside the trie itself. The Phase 1
/// implementation is O(unique_owners * total_objects) — acceptable
/// for the tens-to-low-hundreds of objects per PTB the v0 chain
/// expects.
///
/// The owner of an object is determined by reading its current record
/// from the snapshot (which already reflects the executor's
/// `object_writes`), so we don't need to inspect the `(id, owner)`
/// tuples beyond their owner keys.
fn rebuild_ownership_rows(
    snapshot: &mut bloom_chain_state::StateSnapshot,
    changes: &[(bloom_objects::ObjectId, bloom_objects::Owner)],
) {
    use bloom_objects::{Owner, OWNER_KIND_ADDRESS, OWNER_KIND_OBJECT};

    // Collect unique (kind, id) owner keys we need to rebuild. Only
    // Address / Object owners are indexed; Shared / Immutable never
    // appear in the ownership trie.
    let mut keys: std::collections::BTreeSet<(u8, [u8; 32])> =
        std::collections::BTreeSet::new();
    for (_, owner) in changes {
        match owner {
            Owner::Address(a) => {
                keys.insert((OWNER_KIND_ADDRESS, *a));
            }
            Owner::Object(id) => {
                keys.insert((OWNER_KIND_OBJECT, id.0));
            }
            Owner::Shared | Owner::Immutable => {}
        }
    }

    // For each affected owner key, scan the snapshot's current
    // (post-write) object table and gather the sorted id list.
    // We pull every object via `get_object` — the snapshot returns
    // pending writes first, so freshly inserted / deleted objects
    // are visible.
    for (kind, owner_id) in keys {
        let mut owned: Vec<bloom_objects::ObjectId> = Vec::new();
        // We don't have a snapshot.iter_objects(); fall back to
        // collecting ids the executor told us about + any preexisting
        // owner row, then filter by current owner.
        let mut candidate_ids: std::collections::BTreeSet<bloom_objects::ObjectId> =
            std::collections::BTreeSet::new();
        for (id, _) in changes {
            candidate_ids.insert(*id);
        }
        if let Some(existing) =
            snapshot.get_ownership(&OwnershipIndexKey { owner_kind: kind, owner_id })
        {
            candidate_ids.extend(existing);
        }
        for cid in candidate_ids {
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
        snapshot.set_ownership(
            OwnershipIndexKey { owner_kind: kind, owner_id },
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
        // Unit-struct executor: no manifest registry, so any
        // `Move`-bearing PTB reverts at validation.
        execute_tx_impl(
            tx,
            state,
            block_number,
            timestamp_ms,
            proposer,
            parent_hash,
            &HashMap::new(),
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
        execute_tx_impl(
            tx,
            state,
            block_number,
            timestamp_ms,
            proposer,
            parent_hash,
            &self.manifests,
        )
    }
}

/// Shared `PetalExecutor::execute_tx` body. The trailing
/// `manifests` parameter is the per-petal manifest registry the PTB
/// validator consults during `Command::Move` typechecks.
fn execute_tx_impl(
    tx: &Tx,
    state: &mut State,
    block_number: u64,
    timestamp_ms: u64,
    _proposer: Address,
    parent_hash: Hash32,
    manifests: &HashMap<Hash32, PetalManifestStub>,
) -> ExecOutput {
        // `parent_hash` is the committing block's parent block hash —
        // surfaced to chain-mode petals as `chain::block.prevhash`
        // (review 2026-05-19 #13). Threaded in by
        // `apply_block_state_transitions` from `block.header.parent_hash`.
        let block_ctx = PetalBlockCtx { number: block_number, timestamp_ms, prevhash: parent_hash };

        match &tx.kind {
            TxKind::Transfer { to, amount_loom } => {
                // Pure LOOM move — no VM invocation required.
                let mut snap = state.snapshot();
                let mut to_acct = snap.get_account(to).unwrap_or_else(empty_account);
                to_acct.loom += amount_loom;
                snap.set_account(*to, to_acct);
                let ws = snap.commit();
                ExecOutput {
                    success: true,
                    fuel_used: 100,
                    return_data: vec![],
                    logs: vec![],
                    write_set: Some(ws),
                }
            }

            TxKind::Deploy { wasm, salt, init_args, manifest_hash } => {
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

            TxKind::Call { to, calldata, value_loom } => {
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
                        // Phase 1 wiring: validate against current
                        // chain state. The verifier is `AlwaysOk` until
                        // the PQ-key registry lands (the 32-byte
                        // `PqPubkey` is a key *identifier*, not the
                        // full key; the real verifier resolves it
                        // through an on-chain map).
                        //
                        // TODO(task#32): replace the all-zero
                        // `loom_coin_type` and `fungible_petal_hash`
                        // below with the values pinned at genesis once
                        // the fungible petal lands.
                        let loom_coin_type =
                            loom_coin_type_tag(Hash32([0u8; 32]));
                        let fungible_petal_hash = Hash32([0u8; 32]);

                        // Capture per-PTB scratch we need across the
                        // immutable borrow of `state` (validate) and
                        // the mutable borrow (commit) below.
                        let signers = ptb.signers.clone();

                        let validated = {
                            let adapter = PtbChainAdapter::with_manifests(
                                state,
                                block_number,
                                manifests,
                            );
                            let verifier = AlwaysOkVerifier;
                            let ctx = ValidationContext {
                                current_block: block_number,
                                chain: &adapter,
                                verifier: &verifier,
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
                                        return_data:
                                            format!("ptb validation error: {e}")
                                                .into_bytes(),
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
                        let snapshot = state.snapshot();
                        let petals_owned = ChainPetalRunner::petals_from_validated(
                            &validated.petals,
                        );
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
                        let report = {
                            let adapter =
                                PtbChainAdapter::with_manifests(
                                    state,
                                    block_number,
                                    manifests,
                                );
                            let mut exec = PtbExecutor::new(
                                &adapter,
                                &runner,
                                loom_coin_type,
                                fungible_petal_hash,
                            );
                            exec.execute(validated)
                        };

                        // Drain shared host-context state before we
                        // consume the runner (which holds an Arc).
                        let drained = {
                            let mut c =
                                host_ctx.lock().expect("PtbHostCtx mutex poisoned");
                            std::mem::take(&mut *c)
                        };

                        // Reclaim the snapshot the runner threaded
                        // through the calls.
                        let mut snapshot = runner.into_snapshot();

                        if !report.success {
                            // Revert: drop everything.
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
                            return ExecOutput {
                                success: false,
                                fuel_used: report.fuel_used,
                                return_data: reason.into_bytes(),
                                logs: vec![],
                                write_set: None,
                            };
                        }

                        // Success: fold ExecutionReport diffs + any
                        // host-import-emitted state into the snapshot.
                        for obj in &report.object_writes {
                            snapshot.insert_object(obj.clone());
                        }
                        for id in &report.object_deletes {
                            snapshot.delete_object(*id);
                        }
                        for id in &drained.object_deletes {
                            snapshot.delete_object(*id);
                        }
                        // Ownership-index rewrites: rebuild the row
                        // for each owner referenced by either the
                        // executor or the host imports.
                        // Phase 1: a single ownership-row replace per
                        // unique owner. The host_ctx.ownership_changes
                        // and report.ownership_changes are both
                        // "(id, new_owner)" lists; we collect the
                        // affected (owner_kind, owner_id) keys and
                        // rebuild each from the post-write object
                        // table (Phase 2 will do this incrementally).
                        let mut combined_ownership: Vec<
                            (bloom_objects::ObjectId, bloom_objects::Owner),
                        > = Vec::new();
                        combined_ownership
                            .extend(report.ownership_changes.iter().cloned());
                        combined_ownership
                            .extend(drained.ownership_changes.iter().cloned());
                        rebuild_ownership_rows(&mut snapshot, &combined_ownership);

                        // Loom deltas: both executor- and host-import-
                        // attributed.
                        for d in &report.loom_deltas {
                            snapshot
                                .apply_loom_delta(Address(d.address), d.delta);
                        }
                        for d in &drained.loom_deltas {
                            snapshot
                                .apply_loom_delta(Address(d.address), d.delta);
                        }

                        let ws = snapshot.commit();
                        let logs: Vec<Log> = drained
                            .logs
                            .into_iter()
                            .map(ptb_log_to_receipt_log)
                            .collect();

                        // Serialise per-command return slots into
                        // `return_data` so RPC consumers can recover
                        // every command's outputs deterministically.
                        let return_data =
                            encode_command_outputs(&report.command_outputs);

                        ExecOutput {
                            success: true,
                            fuel_used: report.fuel_used,
                            return_data,
                            logs,
                            write_set: Some(ws),
                        }
                    }
                }
            }
        }
}

// suppress unused-import lints when Account isn't needed in some configs
#[allow(dead_code)]
fn _typecheck() -> Option<Account> { None }

