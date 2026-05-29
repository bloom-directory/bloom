//! In-memory PTB executor (spec §7.2 steps 7–10).
//!
//! The executor dispatches each command sequentially:
//!
//! - `Move(...)` — load the petal's manifest, marshal args, call into
//!   the wasm via [`PetalRunner`], decode return values into command
//!   output buffers, then run any attached invariants.
//! - Built-ins (`TransferObjects`, `MergeCoins`, `SplitCoins`,
//!   `MakeMoveVec`, `Publish`, `UpgradePetal`) — handled directly,
//!   without dropping into wasm.
//!
//! After each command we run [`BorrowTable::diff_check`]. After the
//! whole PTB we run [`BorrowTable::linearity_check`]. Any failure
//! reverts the entire PTB (callers should discard the
//! [`ExecutionReport`]'s state diffs in that case — `success ==
//! false`).
//!
//! # Shared host context
//!
//! Per spec §16.2 + §16.3, the chain VM's `object.*` / `ptb.*` host
//! imports operate on the same per-PTB borrow table and
//! command-output matrix as the executor. To enforce this single
//! source of truth, [`PtbExecutor`] is constructed with an
//! `Arc<Mutex<PtbHostCtx>>` (see [`PtbExecutor::with_ctx_arc`]); the
//! chain-node layer threads the same handle into the wasm linker so
//! every `object.borrow`, `object.create`, `object.mutate`,
//! `object.transfer`, etc. mutates the executor's view directly.
//!
//! Tests that don't need the chain-VM linkage can use
//! [`PtbExecutor::new`], which internally allocates a fresh
//! `Arc<Mutex<PtbHostCtx>>`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use bloom_chain_types::{
    Hash32,
    digest::{blake3_tagged, tags},
};
use bloom_objects::{
    AbilitySet, AccessMode, Object, ObjectId, Owner, TypeTag, ValidationOutcome,
    validate_canonical_bytes,
};

use crate::borrow_table::BorrowRow;
use crate::chain_iface::{ArgDeclStub, ChainStateIface, InvariantDeclStub, PetalManifestStub};
use crate::error::PtbError;
use crate::host_ctx::PtbHostCtx;
use crate::types::{Arg, Command, MoveCmd, PublishCmd, UpgradeCmd, UseRef};
use crate::validator::{ValidatedPtb, decode_coin_value};

const MAX_PETAL_RETURN_SLOTS: usize = 32;
const MAX_PETAL_RETURN_BYTES: usize = 2 << 20;
const PUBLISH_BASE_FUEL: u64 = 1_000;
const PUBLISH_BYTES_PER_FUEL: u64 = 64;

// ---------------------------------------------------------------------------
// Petal runner trait
// ---------------------------------------------------------------------------

/// Output of a single petal call.
#[derive(Debug, Clone, Default)]
pub struct PetalCallResult {
    /// Canonical-encoded return-buffer bytes (length-prefixed return
    /// values; the executor splits into per-return-slot byte vectors).
    pub ret_buf: Vec<u8>,
    /// Fuel consumed by the call.
    pub fuel_used: u64,
}

/// Output of a single invariant call.
#[derive(Debug, Clone, Default)]
pub struct InvariantResult {
    /// `true` iff the invariant returned `1`.
    pub ok: bool,
    /// Fuel consumed by the invariant.
    pub fuel_used: u64,
}

/// Trait the executor delegates to for wasm dispatch.
///
/// Real implementation lives in `bloom-chain-state` / `bloom-chain-node`
/// in Phase 2 (wasmtime instance + linker per-petal). Tests use a
/// hand-rolled [`tests::MockPetalRunner`] that returns canned bytes.
pub trait PetalRunner {
    /// Call a function `function` in the petal identified by
    /// `petal_hash`, passing canonical-encoded `args_buf`. Returns
    /// the return buffer + fuel consumed.
    fn call(
        &self,
        petal_hash: &Hash32,
        function: &str,
        type_args: &[TypeTag],
        args_buf: &[u8],
        fuel_budget: u64,
    ) -> Result<PetalCallResult, PtbError>;

    /// Run an invariant export (`__inv_<n>`) over the supplied scope
    /// buffer.
    fn call_invariant(
        &self,
        petal_hash: &Hash32,
        export_name: &str,
        scope_buf: &[u8],
        fuel_budget: u64,
    ) -> Result<InvariantResult, PtbError>;
}

// ---------------------------------------------------------------------------
// Report shapes
// ---------------------------------------------------------------------------

/// A single petal-emitted log record (forwarded by the executor to the
/// chain receipt). Phase 1 is a minimal struct so the executor's API
/// is stable.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LogEntry {
    /// Petal that emitted the log.
    pub petal: Hash32,
    /// Optional topic bytes.
    pub topic: Vec<u8>,
    /// Opaque data payload.
    pub data: Vec<u8>,
}

/// Petal publish/upgrade event (Phase 1 stub).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PetalPublishEvent {
    /// VFS path that was published / upgraded.
    pub module_path: String,
    /// Content hash (`blake3` of the wasm).
    pub wasm_hash: Hash32,
    /// Wasm bytes to install if the enclosing PTB commits.
    pub wasm_bytes: Vec<u8>,
    /// `true` if a fresh `OwnerCap<Path>` was minted.
    pub minted_owner_cap: bool,
}

/// Top-level execution outcome.
#[derive(Clone, Debug, Default)]
pub struct ExecutionReport {
    /// Whether the PTB committed atomically. Failures revert.
    pub success: bool,
    /// If `success == false`, the typed error that caused the revert.
    pub reverted_with: Option<PtbError>,
    /// Total fuel consumed by petal calls (excludes built-ins for now).
    pub fuel_used: u64,
    /// Per-command return slot bytes: `outputs[cmd][ret]`. Empty on revert.
    pub command_outputs: Vec<Vec<Vec<u8>>>,
    /// Object trie writes (insert or update) to apply on commit.
    pub object_writes: Vec<Object>,
    /// Objects to delete from the trie. Each entry is `(id, old_owner)`:
    /// the chain-node layer reads the old owner so it can rebuild the
    /// prior owner's ownership-index row (spec §16.3 — symmetric
    /// owner-rebuild on delete).
    pub object_deletes: Vec<(ObjectId, Owner)>,
    /// Ownership re-keys: `(id, old_owner, new_owner)`. The chain-node
    /// layer rebuilds the OwnershipIndex row for *both* sides per
    /// spec §16.3 (the old owner must drop the id; the new owner must
    /// gain it). Single-owner tuples would leak stale ids in the old
    /// owner's row.
    pub ownership_changes: Vec<(ObjectId, Owner, Owner)>,
    /// Publish / upgrade events for explorer indexers.
    pub publish_events: Vec<PetalPublishEvent>,
    /// Log records emitted by petals.
    pub logs: Vec<LogEntry>,
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// PTB executor.
pub struct PtbExecutor<'c> {
    #[allow(dead_code)]
    chain: &'c dyn ChainStateIface,
    petal_runner: &'c dyn PetalRunner,
    /// `Coin<LOOM>` type tag the executor uses to recognise gas-relevant coins.
    #[allow(dead_code)]
    loom_coin_type: TypeTag,
    /// Hash of the fungible petal — used when minting new `Coin<LOOM>`
    /// objects during built-in commands (gas refund, SplitCoins).
    #[allow(dead_code)]
    fungible_petal_hash: Hash32,
    /// Per-PTB host context shared with the chain VM's §16.2 host
    /// imports. The executor mutates `ctx.borrow_table` and
    /// `ctx.command_outputs` directly; the host imports do the same
    /// under the same lock. Holding this lock across `petal_runner.call`
    /// would deadlock (the host imports re-acquire it), so dispatch
    /// methods take short critical sections via [`Self::with_ctx`].
    ctx: Arc<Mutex<PtbHostCtx>>,
    /// Internal counter that drives unique transient `ObjectId`s.
    transient_counter: u64,
    /// PTB hash used as seed for transient id derivation; keeps ids
    /// reproducible across replays of the same tx.
    seed: [u8; 32],
    /// Persistent object ids that were explicitly loaded with consume access.
    ///
    /// TransferObjects uses this as the authority record instead of the
    /// borrow row's mutable `access_mode`, which is scoped to the latest Move
    /// command that mentioned the row.
    consume_authority: HashSet<ObjectId>,
}

impl<'c> PtbExecutor<'c> {
    /// Construct a new executor with a private host context.
    ///
    /// Suitable for tests / library callers that don't need to share
    /// the borrow table with chain-VM host imports. The chain-node
    /// layer uses [`Self::with_ctx_arc`] to thread the same
    /// `Arc<Mutex<PtbHostCtx>>` into the wasm linker.
    pub fn new(
        chain: &'c dyn ChainStateIface,
        petal_runner: &'c dyn PetalRunner,
        loom_coin_type: TypeTag,
        fungible_petal_hash: Hash32,
    ) -> Self {
        Self::with_ctx_arc(
            chain,
            petal_runner,
            loom_coin_type,
            fungible_petal_hash,
            Arc::new(Mutex::new(PtbHostCtx::new())),
        )
    }

    /// Construct an executor that shares `ctx` with the chain VM's
    /// §16.2 host imports.
    pub fn with_ctx_arc(
        chain: &'c dyn ChainStateIface,
        petal_runner: &'c dyn PetalRunner,
        loom_coin_type: TypeTag,
        fungible_petal_hash: Hash32,
        ctx: Arc<Mutex<PtbHostCtx>>,
    ) -> Self {
        Self {
            chain,
            petal_runner,
            loom_coin_type,
            fungible_petal_hash,
            ctx,
            transient_counter: 0,
            seed: [0u8; 32],
            consume_authority: HashSet::new(),
        }
    }

    /// Run a closure with mutable access to the per-PTB host context.
    ///
    /// CRITICAL: callers MUST NOT call into `self.petal_runner` while
    /// holding the lock — the runner's `call(...)` triggers wasm host
    /// imports that re-acquire the same `Arc<Mutex<PtbHostCtx>>`,
    /// which would deadlock. Each `with_ctx` call should perform one
    /// short critical section: read what you need, drop the guard,
    /// then call out.
    fn with_ctx<R>(&self, f: impl FnOnce(&mut PtbHostCtx) -> R) -> R {
        let mut g = self
            .ctx
            .lock()
            .expect("PtbHostCtx mutex poisoned during executor dispatch");
        f(&mut g)
    }

    /// Execute a validated PTB. Returns a complete
    /// [`ExecutionReport`]. On error, `success = false` and all state
    /// diff fields are cleared.
    pub fn execute(&mut self, vtx: ValidatedPtb) -> ExecutionReport {
        let mut report = ExecutionReport::default();
        self.seed = vtx.tx.signing_digest();
        self.consume_authority.clear();
        self.with_ctx(|ctx| {
            ctx.ptb_digest = self.seed;
            ctx.signers = vtx.tx.signers.clone();
        });

        // Track ownership changes for Loom-bearing objects. The
        // executor consults the per-object type tag to know whether to
        // record a Loom delta. These accumulators are local because
        // they're only touched by the executor's built-ins;
        // host-import-attributed entries flow through
        // `ctx.ownership_changes` and are folded in at the end.
        let mut planned_writes: Vec<Object> = Vec::new();
        let mut planned_deletes: Vec<(ObjectId, Owner)> = Vec::new();
        let mut ownership_changes: Vec<(ObjectId, Owner, Owner)> = Vec::new();
        let mut consumed_use_refs: HashSet<UseRef> = HashSet::new();

        // Tx-scope fuel: Phase 1 charges only inside petal calls.
        // We treat `gas_budget` as the upper bound for the *whole* PTB.
        let mut fuel_remaining = vtx.tx.gas_budget;

        for (cmd_idx, cmd) in vtx.tx.commands.iter().enumerate() {
            // Tell the host imports which command they're inside; the
            // `current_command_idx` is read by `object.create` and any
            // other §16.2 import that attributes work to a command.
            self.with_ctx(|ctx| {
                ctx.current_command_idx = cmd_idx as u16;
            });

            if let Err(e) = reject_duplicate_linear_use_refs(
                cmd,
                cmd_idx as u16,
                &vtx.manifests,
                &mut consumed_use_refs,
            ) {
                return self.revert_report(report, e);
            }

            let cmd_outputs = match self.dispatch_command(
                cmd,
                cmd_idx as u16,
                &vtx,
                &mut ownership_changes,
                &mut fuel_remaining,
                &mut report,
            ) {
                Ok(o) => o,
                Err(e) => return self.revert_report(report, e),
            };

            // Push this command's outputs into the shared ctx so later
            // commands (and the chain VM's `ptb.command_output` host
            // import inside subsequent Move calls) can read them.
            self.with_ctx(|ctx| {
                ctx.command_outputs.push(cmd_outputs);
            });

            if let Err(e) = self.with_ctx(|ctx| ctx.borrow_table.diff_check(cmd_idx as u16)) {
                return self.revert_report(report, e);
            }
        }

        // Tx-end linearity check.
        let orphans = self.with_ctx(|ctx| ctx.borrow_table.linearity_check());
        if !orphans.is_empty() {
            return self.revert_report(
                report,
                PtbError::LinearityViolation {
                    orphans: orphans.len(),
                    ids: orphans,
                },
            );
        }

        // Commit: drain the shared host context.
        //
        // - `borrow_table.iter()` produces persistent (touched) + transient
        //   (surviving) rows. Host-created objects entered the borrow
        //   table via `object.create` and are picked up here.
        // - `ctx.object_deletes` carries host-`object.delete` ids.
        // - `ctx.ownership_changes` carries host-`object.transfer/share/freeze` rekeys.
        // - `ctx.logs` flow through verbatim.
        let drained = self.with_ctx(std::mem::take);
        let command_outputs = drained.command_outputs;

        for (_id, row) in drained.borrow_table.iter() {
            // Skip persistent rows that weren't touched.
            if row.origin_command_idx.is_none() {
                // Persistent: only write if the version changed (i.e.
                // diff_check bumped the version) or the owner changed.
                if let Some(original) = vtx.objects.get(&row.object_id.0)
                    && original.version == row.version
                    && original.owner == row.owner
                    && original.payload == row.payload_bytes
                {
                    continue;
                }
                planned_writes.push(row.to_object());
            } else {
                // Transient: write the row to the trie (this is the
                // "promote to persistent" step).
                planned_writes.push(row.to_object());
            }
        }

        // Fold host-import-attributed deltas in.
        planned_deletes.extend(drained.object_deletes);
        ownership_changes.extend(drained.ownership_changes);

        report.success = true;
        report.command_outputs = command_outputs;
        report.object_writes = planned_writes;
        report.object_deletes = planned_deletes;
        report.ownership_changes = ownership_changes;
        report.logs = drained.logs;
        report
    }

    fn revert_report(&self, report: ExecutionReport, err: PtbError) -> ExecutionReport {
        self.with_ctx(|ctx| {
            *ctx = PtbHostCtx::new();
        });
        revert(report, err)
    }

    // -----------------------------------------------------------------
    // Per-command dispatch
    // -----------------------------------------------------------------

    fn dispatch_command(
        &mut self,
        cmd: &Command,
        cmd_idx: u16,
        vtx: &ValidatedPtb,
        ownership_changes: &mut Vec<(ObjectId, Owner, Owner)>,
        fuel_remaining: &mut u64,
        report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        // `object_writes` and `object_deletes` aren't accumulated here;
        // executor- and host-attributed rows all land in
        // `ctx.borrow_table` / `ctx.object_deletes` and are drained at
        // the end of `execute(...)`. Only `ownership_changes` is still
        // pushed here (by `exec_transfer`), since the TransferObjects
        // builtin operates outside the host context.
        match cmd {
            Command::Move(m) => self.exec_move(m, cmd_idx, vtx, fuel_remaining, report),
            Command::TransferObjects { uses, owner } => {
                self.exec_transfer(uses, owner.clone(), cmd_idx, ownership_changes)
            }
            Command::SplitCoins { src, amounts } => self.exec_split_coins(src, amounts, cmd_idx),
            Command::MergeCoins(uses) => self.exec_merge_coins(uses, cmd_idx),
            Command::MakeMoveVec { ty, uses } => self.exec_make_vec_inner(ty, uses, cmd_idx),
            Command::Publish(p) => self.exec_publish(p, cmd_idx, fuel_remaining, report),
            Command::UpgradePetal(u) => self.exec_upgrade(u, cmd_idx, fuel_remaining, report),
        }
    }

    fn exec_move(
        &mut self,
        m: &MoveCmd,
        cmd_idx: u16,
        vtx: &ValidatedPtb,
        fuel_remaining: &mut u64,
        report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        // Load every Arg::Object into the borrow table (already type-
        // checked by the validator). This is the executor's contract
        // with the host imports: by the time we call into wasm, every
        // PTB-declared Object arg must be visible in `ctx.borrow_table`
        // so `object.borrow` can mint a handle without doing chain I/O.
        for arg in &m.args {
            if let Arg::Object {
                id, access_mode, ..
            } = arg
            {
                if *access_mode == AccessMode::Consume {
                    self.consume_authority.insert(*id);
                }
                let loaded = self.with_ctx(|ctx| {
                    if let Some(row) = ctx.borrow_table.get_mut(id) {
                        row.access_mode = *access_mode;
                        true
                    } else {
                        false
                    }
                });
                if !loaded {
                    let obj = vtx
                        .objects
                        .get(&id.0)
                        .cloned()
                        .ok_or(PtbError::ObjectNotFound { id: *id })?;
                    self.with_ctx(|ctx| ctx.borrow_table.load_persistent(&obj, *access_mode));
                }
            }
        }

        // Marshal args: a length-prefixed concatenation of per-arg
        // canonical bytes. The bloom-resource runtime on the guest
        // side decodes this prefix-length-blob format.
        //
        // We marshal *outside* the ctx lock — `marshal_args` needs to
        // read prior command outputs, which we snapshot first.
        let outputs_snapshot = self.with_ctx(|ctx| ctx.command_outputs.clone());
        let args_buf = marshal_args(&m.args, &outputs_snapshot)?;

        let hash = m.petal.hash.ok_or_else(|| PtbError::PetalNotPinned {
            path: m.petal.path.clone(),
        })?;
        let manifest = vtx
            .manifests
            .get(&hash.0)
            .ok_or(PtbError::PetalNotFound { hash })?;
        let f = manifest
            .function(&m.function)
            .ok_or_else(|| PtbError::UnknownFunction {
                function: m.function.clone(),
                petal_hash: hash,
            })?;
        let expected_returns = f.returns.len();

        // Petal call: DO NOT hold the ctx lock here. The wasm host
        // imports (chain_vm.rs) reach back into `ctx` via the same
        // Arc<Mutex>; deadlock if we held it.
        let result = match self.petal_runner.call(
            &hash,
            &m.function,
            &m.type_args,
            &args_buf,
            *fuel_remaining,
        ) {
            Ok(result) => result,
            Err(PtbError::OutOfFuel { used, .. }) => {
                let limit = *fuel_remaining;
                let charged = used.min(*fuel_remaining);
                report.fuel_used = report.fuel_used.saturating_add(charged);
                *fuel_remaining = fuel_remaining.saturating_sub(charged);
                return Err(PtbError::OutOfFuel {
                    cmd_idx,
                    limit,
                    used,
                });
            }
            Err(PtbError::PetalAbort {
                code, fuel_used, ..
            }) => {
                let charged = fuel_used.min(*fuel_remaining);
                report.fuel_used = report.fuel_used.saturating_add(charged);
                *fuel_remaining = fuel_remaining.saturating_sub(charged);
                return Err(PtbError::PetalAbort {
                    cmd_idx,
                    code,
                    fuel_used,
                });
            }
            Err(e) => return Err(e),
        };
        if result.fuel_used > *fuel_remaining {
            report.fuel_used = report.fuel_used.saturating_add(*fuel_remaining);
            return Err(PtbError::OutOfFuel {
                cmd_idx,
                limit: *fuel_remaining,
                used: result.fuel_used,
            });
        }
        report.fuel_used = report.fuel_used.saturating_add(result.fuel_used);
        *fuel_remaining = fuel_remaining.saturating_sub(result.fuel_used);

        // Decode the return buffer: same length-prefixed-blobs format
        // as the args, and exactly matching the manifest return arity.
        let outputs = unmarshal_outputs(&result.ret_buf, expected_returns, cmd_idx)?;
        for (ret_idx, (output, declared)) in outputs.iter().zip(f.returns.iter()).enumerate() {
            let expected = substitute_type_args(declared, &m.type_args);
            match validate_canonical_bytes(&expected, output) {
                ValidationOutcome::Ok | ValidationOutcome::Unknown => {}
                ValidationOutcome::Invalid(reason) => {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx,
                        reason: format!(
                            "Move return slot {ret_idx} does not match declared type {}: {reason}",
                            type_tag_label(&expected),
                        ),
                    });
                }
            }
        }

        // Run attached invariants.
        if let Some(f) = manifest.function(&m.function) {
            for inv in &f.attached_invariants {
                let before_invariant = *fuel_remaining;
                let used = match run_invariant(
                    self.petal_runner,
                    &hash,
                    inv,
                    &m.args,
                    &outputs,
                    cmd_idx,
                    *fuel_remaining,
                    fuel_remaining,
                ) {
                    Ok(used) => used,
                    Err(e) => {
                        let charged = before_invariant.saturating_sub(*fuel_remaining);
                        report.fuel_used = report.fuel_used.saturating_add(charged);
                        return Err(e);
                    }
                };
                report.fuel_used = report.fuel_used.saturating_add(used);
            }
        }

        Ok(outputs)
    }

    fn exec_transfer(
        &mut self,
        uses: &[UseRef],
        owner: Owner,
        cmd_idx: u16,
        ownership_changes: &mut Vec<(ObjectId, Owner, Owner)>,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        // Each Use must resolve to a transient object id; we decode
        // the upstream output bytes as `ObjectId` (32 bytes).
        let outputs_snapshot = self.with_ctx(|ctx| ctx.command_outputs.clone());
        for u in uses {
            let bytes = lookup_use(&outputs_snapshot, *u, cmd_idx)?;
            if bytes.len() != 32 {
                return Err(PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: format!(
                        "TransferObjects: expected 32-byte object id, got {} bytes",
                        bytes.len()
                    ),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let id = ObjectId(arr);
            // Capture the row's *prior* owner before we overwrite it.
            // The chain-node layer needs both keys to rebuild a
            // symmetric `OwnershipIndex` (spec §16.3): the old
            // owner's row must drop `id`; the new owner's row must
            // gain it. Without the old key, the prior row retains a
            // stale entry.
            let old_owner = self.with_ctx(|ctx| -> Result<Owner, PtbError> {
                let row = ctx
                    .borrow_table
                    .get_mut(&id)
                    .ok_or(PtbError::ObjectNotFound { id })?;
                if row.origin_command_idx.is_none() && !self.consume_authority.contains(&id) {
                    return Err(PtbError::AccessDenied {
                        id,
                        mode: AccessMode::Consume,
                        reason: "TransferObjects requires consume access for persistent objects"
                            .to_string(),
                    });
                }
                let old = row.owner.clone();
                row.owner = owner.clone();
                ctx.borrow_table.mark_consumed(&id);
                ctx.retire_handles_for(&id);
                Ok(old)
            })?;
            ownership_changes.push((id, old_owner, owner.clone()));
        }
        Ok(vec![])
    }

    fn exec_split_coins(
        &mut self,
        src: &UseRef,
        amounts: &[u128],
        cmd_idx: u16,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        let outputs_snapshot = self.with_ctx(|ctx| ctx.command_outputs.clone());
        let bytes = lookup_use(&outputs_snapshot, *src, cmd_idx)?;
        if bytes.len() != 32 {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: format!("SplitCoins src: expected 32-byte id, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let src_id = ObjectId(arr);

        // Pull what we need from the source row in one short critical
        // section.
        let (mut value, coin_type, owner, src_id_prefix) = self.with_ctx(|ctx| {
            let src_row = ctx
                .borrow_table
                .get(&src_id)
                .ok_or(PtbError::ObjectNotFound { id: src_id })?;
            if !self.is_fungible_coin_type(&src_row.type_tag) {
                return Err(PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: "SplitCoins source is not a Coin<T>".to_string(),
                });
            }
            let v =
                decode_coin_value(&src_row.payload_bytes).map_err(|_| PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: "SplitCoins src has invalid Coin payload".to_string(),
                })?;
            let prefix: [u8; 32] = src_row.payload_bytes[..32].try_into().unwrap();
            Ok::<_, PtbError>((v, src_row.type_tag.clone(), src_row.owner.clone(), prefix))
        })?;

        let total_out: u128 = amounts.iter().try_fold(0u128, |acc, a| {
            acc.checked_add(*a).ok_or_else(|| PtbError::BuiltinFailed {
                cmd_idx,
                reason: "SplitCoins amount overflow".to_string(),
            })
        })?;
        if total_out > value {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: format!("SplitCoins: total {total_out} exceeds source value {value}"),
            });
        }
        value -= total_out;

        // Write the source's new value back using canonical 48-byte
        // format, preserving its id prefix; mark dirty so diff_check
        // bumps the version.
        let mut new_payload = src_id_prefix.to_vec();
        new_payload.extend_from_slice(&value.to_be_bytes());
        self.with_ctx(|ctx| ctx.borrow_table.mark_dirty(&src_id, new_payload))?;

        // Emit one transient Coin per requested amount, each with a
        // canonical 48-byte payload: [transient id (32 bytes)] ||
        // [amount BE (16 bytes)].
        let mut outs: Vec<Vec<u8>> = Vec::with_capacity(amounts.len());
        for amt in amounts {
            let id = self.mint_transient_id(b"split-coin");
            let mut payload = id.0.to_vec();
            payload.extend_from_slice(&amt.to_be_bytes());
            let row = BorrowRow {
                object_id: id,
                type_tag: coin_type.clone(),
                owner: owner.clone(),
                version: 0,
                payload_bytes: payload.clone(),
                access_mode: AccessMode::Mutable,
                origin_command_idx: Some(cmd_idx),
                dirty: false,
                baseline_payload: payload,
            };
            self.with_ctx(|ctx| ctx.borrow_table.insert_transient(row));
            outs.push(id.0.to_vec());
        }

        Ok(outs)
    }

    fn exec_merge_coins(
        &mut self,
        uses: &[UseRef],
        cmd_idx: u16,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        if uses.is_empty() {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: "MergeCoins requires at least one Use".to_string(),
            });
        }
        let outputs_snapshot = self.with_ctx(|ctx| ctx.command_outputs.clone());
        let mut accum: u128 = 0;
        let mut first_id: Option<ObjectId> = None;
        let mut first_type: Option<TypeTag> = None;
        let mut first_owner: Option<Owner> = None;
        for u in uses {
            let bytes = lookup_use(&outputs_snapshot, *u, cmd_idx)?;
            if bytes.len() != 32 {
                return Err(PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: format!("MergeCoins: expected 32-byte id, got {}", bytes.len()),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let id = ObjectId(arr);
            let (v, ty, ow, is_first, was_persistent, access_mode) = self.with_ctx(
                |ctx| -> Result<(u128, TypeTag, Owner, bool, bool, AccessMode), PtbError> {
                    let row = ctx
                        .borrow_table
                        .get(&id)
                        .ok_or(PtbError::ObjectNotFound { id })?;
                    if !self.is_fungible_coin_type(&row.type_tag) {
                        return Err(PtbError::BuiltinFailed {
                            cmd_idx,
                            reason: "MergeCoins input is not a Coin<T>".to_string(),
                        });
                    }
                    let v = decode_coin_value(&row.payload_bytes).map_err(|_| {
                        PtbError::BuiltinFailed {
                            cmd_idx,
                            reason: "MergeCoins: invalid Coin payload".to_string(),
                        }
                    })?;
                    let ty = row.type_tag.clone();
                    let ow = row.owner.clone();
                    let was_persistent = row.origin_command_idx.is_none();
                    let access_mode = row.access_mode;
                    let is_first = first_id.is_none();
                    Ok((v, ty, ow, is_first, was_persistent, access_mode))
                },
            )?;
            accum = accum
                .checked_add(v)
                .ok_or_else(|| PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: "MergeCoins: total overflow".to_string(),
                })?;
            if is_first {
                first_id = Some(id);
                first_type = Some(ty);
                first_owner = Some(ow);
            } else {
                if ty != *first_type.as_ref().unwrap() {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx,
                        reason: "MergeCoins: heterogeneous coin types".to_string(),
                    });
                }
                if ow != *first_owner.as_ref().unwrap() {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx,
                        reason: "MergeCoins: heterogeneous owners".to_string(),
                    });
                }
                if was_persistent && access_mode != AccessMode::Consume {
                    return Err(PtbError::AccessDenied {
                        id,
                        mode: access_mode,
                        reason:
                            "MergeCoins requires consume access for persistent non-target coins"
                                .to_string(),
                    });
                }
                self.with_ctx(|ctx| ctx.borrow_table.drop_row(&id));
                if was_persistent {
                    self.with_ctx(|ctx| ctx.object_deletes.push((id, ow.clone())));
                }
            }
        }
        let id = first_id.unwrap();
        // Write merged total in canonical 48-byte format: [id (32)] || [total BE (16)].
        let mut merged_payload = id.0.to_vec();
        merged_payload.extend_from_slice(&accum.to_be_bytes());
        self.with_ctx(|ctx| ctx.borrow_table.mark_dirty(&id, merged_payload))?;
        Ok(vec![id.0.to_vec()])
    }

    fn is_fungible_coin_type(&self, ty: &TypeTag) -> bool {
        match ty {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                *petal_hash == self.fungible_petal_hash.0
                    && type_name == "Coin"
                    && type_args.len() == 1
            }
            _ => false,
        }
    }

    fn exec_publish(
        &mut self,
        p: &PublishCmd,
        cmd_idx: u16,
        fuel_remaining: &mut u64,
        report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        charge_builtin_fuel(p.wasm_bytes.len(), cmd_idx, fuel_remaining, report)?;
        if p.publisher_cap.is_some() {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: "publish with OwnerCap is disabled until owner-cap authority is enforced"
                    .to_string(),
            });
        }
        let wasm_hash = blake3_tagged(tags::PETAL, &p.wasm_bytes);
        let minted_owner_cap = true;
        report.publish_events.push(PetalPublishEvent {
            module_path: p.module_path.clone(),
            wasm_hash,
            wasm_bytes: p.wasm_bytes.clone(),
            minted_owner_cap,
        });
        // Output slot 0: 32-byte content hash; slot 1: 32-byte
        // OwnerCap object id (if minted, else empty).
        let mut outs = vec![wasm_hash.0.to_vec()];
        if minted_owner_cap {
            // Mint a stub OwnerCap object id; full materialisation
            // (with a real Object record + ownership) lands in Phase 2
            // when the cap petal is published.
            let id = self.mint_transient_id(b"owner-cap");
            outs.push(id.0.to_vec());
        } else {
            outs.push(vec![]);
        }
        Ok(outs)
    }

    fn exec_upgrade(
        &mut self,
        u: &UpgradeCmd,
        cmd_idx: u16,
        fuel_remaining: &mut u64,
        report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        charge_builtin_fuel(u.wasm_bytes.len(), cmd_idx, fuel_remaining, report)?;
        let _ = &u.publisher_cap;
        Err(PtbError::BuiltinFailed {
            cmd_idx,
            reason: "UpgradePetal is disabled until owner-cap authority is enforced".to_string(),
        })
    }

    fn exec_make_vec_inner(
        &mut self,
        _ty: &TypeTag,
        uses: &[UseRef],
        cmd_idx: u16,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        let outputs_snapshot = self.with_ctx(|ctx| ctx.command_outputs.clone());
        let mut out = Vec::with_capacity(uses.len() * 32);
        for u in uses {
            let bytes = lookup_use(&outputs_snapshot, *u, cmd_idx)?;
            if bytes.len() != 32 {
                return Err(PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: format!("MakeMoveVec entry must be 32-byte id, got {}", bytes.len()),
                });
            }
            out.extend_from_slice(&bytes);
        }
        Ok(vec![out])
    }

    /// Derive a fresh transient `ObjectId` deterministic per-tx.
    fn mint_transient_id(&mut self, tag: &[u8]) -> ObjectId {
        self.transient_counter = self.transient_counter.saturating_add(1);
        let mut h = blake3::Hasher::new();
        h.update(b"bloom-script.v0.transient_id:");
        h.update(&self.seed);
        h.update(tag);
        h.update(&self.transient_counter.to_le_bytes());
        ObjectId(*h.finalize().as_bytes())
    }
}

// We didn't end up needing the AbilitySet import; tag it so clippy
// doesn't flag it.
#[allow(dead_code)]
fn _abilities_compile_assert(_: AbilitySet) {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn revert(mut report: ExecutionReport, err: PtbError) -> ExecutionReport {
    report.success = false;
    report.reverted_with = Some(err);
    report.object_writes.clear();
    report.object_deletes.clear();
    report.ownership_changes.clear();
    report.publish_events.clear();
    report.logs.clear();
    report.command_outputs.clear();
    report
}

fn substitute_type_args(t: &TypeTag, type_args: &[TypeTag]) -> TypeTag {
    match t {
        TypeTag::Generic { idx } => type_args
            .get(*idx as usize)
            .cloned()
            .unwrap_or_else(|| t.clone()),
        TypeTag::Concrete {
            petal_hash,
            type_name,
            type_args: inner,
        } => TypeTag::Concrete {
            petal_hash: *petal_hash,
            type_name: type_name.clone(),
            type_args: inner
                .iter()
                .map(|x| substitute_type_args(x, type_args))
                .collect(),
        },
        TypeTag::External { .. } => t.clone(),
    }
}

fn type_tag_label(t: &TypeTag) -> String {
    match t {
        TypeTag::Concrete {
            type_name,
            type_args,
            ..
        } => {
            if type_args.is_empty() {
                type_name.clone()
            } else {
                let inner = type_args
                    .iter()
                    .map(type_tag_label)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{type_name}<{inner}>")
            }
        }
        TypeTag::Generic { idx } => format!("T{idx}"),
        TypeTag::External { ref_idx } => format!("$external_{ref_idx}"),
    }
}

fn marshal_args(args: &[Arg], command_outputs: &[Vec<Vec<u8>>]) -> Result<Vec<u8>, PtbError> {
    // Format: count (u32 BE) then for each arg: tag (u8) + length-prefixed payload.
    let mut buf = Vec::new();
    let count: u32 = args.len().try_into().map_err(|_| PtbError::BuiltinFailed {
        cmd_idx: 0,
        reason: "too many args".to_string(),
    })?;
    buf.extend_from_slice(&count.to_be_bytes());
    for arg in args {
        match arg {
            Arg::Signer(idx) => {
                buf.push(0);
                buf.extend_from_slice(&idx.to_be_bytes());
            }
            Arg::Const(bytes) => {
                buf.push(1);
                let len: u32 = bytes
                    .len()
                    .try_into()
                    .map_err(|_| PtbError::BuiltinFailed {
                        cmd_idx: 0,
                        reason: "Const too large".to_string(),
                    })?;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(bytes);
            }
            Arg::Object { id, .. } => {
                buf.push(2);
                buf.extend_from_slice(&id.0);
            }
            Arg::Use { cmd_idx, ret_idx } => {
                let bytes = lookup_use(
                    command_outputs,
                    UseRef {
                        cmd_idx: *cmd_idx,
                        ret_idx: *ret_idx,
                    },
                    *cmd_idx,
                )?;
                buf.push(3);
                let len: u32 = bytes
                    .len()
                    .try_into()
                    .map_err(|_| PtbError::BuiltinFailed {
                        cmd_idx: *cmd_idx,
                        reason: "Use payload too large".to_string(),
                    })?;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&bytes);
            }
            Arg::TypeArg(t) => {
                buf.push(4);
                let enc = t.encode_canonical().map_err(PtbError::Codec)?;
                let len: u32 = enc.len().try_into().map_err(|_| PtbError::BuiltinFailed {
                    cmd_idx: 0,
                    reason: "TypeArg encoding too large".to_string(),
                })?;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&enc);
            }
        }
    }
    Ok(buf)
}

fn unmarshal_outputs(
    buf: &[u8],
    expected_count: usize,
    cmd_idx: u16,
) -> Result<Vec<Vec<u8>>, PtbError> {
    // Format: count (u32 BE) then for each return: length-prefixed bytes.
    if buf.len() < 4 {
        if expected_count == 0 {
            return Ok(vec![]);
        }
        return Err(PtbError::BuiltinFailed {
            cmd_idx,
            reason: format!("petal returned 0 slots, manifest declares {expected_count}"),
        });
    }
    let mut rdr = buf;
    let count = read_u32(&mut rdr)? as usize;
    if count > MAX_PETAL_RETURN_SLOTS {
        return Err(PtbError::BuiltinFailed {
            cmd_idx,
            reason: format!("petal returned too many slots: {count} > {MAX_PETAL_RETURN_SLOTS}"),
        });
    }
    if count != expected_count {
        return Err(PtbError::BuiltinFailed {
            cmd_idx,
            reason: format!("petal returned {count} slots, manifest declares {expected_count}"),
        });
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(&mut rdr)? as usize;
        if len > MAX_PETAL_RETURN_BYTES {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: format!("petal return slot too large: {len} > {MAX_PETAL_RETURN_BYTES}"),
            });
        }
        if rdr.len() < len {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: format!(
                    "petal return buffer truncated: need {len}, have {}",
                    rdr.len()
                ),
            });
        }
        out.push(rdr[..len].to_vec());
        rdr = &rdr[len..];
    }
    if !rdr.is_empty() {
        return Err(PtbError::BuiltinFailed {
            cmd_idx,
            reason: format!("petal return buffer has {} trailing bytes", rdr.len()),
        });
    }
    Ok(out)
}

fn read_u32(rdr: &mut &[u8]) -> Result<u32, PtbError> {
    if rdr.len() < 4 {
        return Err(PtbError::BuiltinFailed {
            cmd_idx: 0,
            reason: "buffer truncated".to_string(),
        });
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(&rdr[..4]);
    *rdr = &rdr[4..];
    Ok(u32::from_be_bytes(a))
}

fn lookup_use(
    command_outputs: &[Vec<Vec<u8>>],
    u: UseRef,
    referring_cmd: u16,
) -> Result<Vec<u8>, PtbError> {
    let cmd = command_outputs
        .get(u.cmd_idx as usize)
        .ok_or(PtbError::DanglingUse {
            cmd_idx: u.cmd_idx,
            ret_idx: u.ret_idx,
        })?;
    let _ = referring_cmd;
    cmd.get(u.ret_idx as usize)
        .cloned()
        .ok_or(PtbError::DanglingUse {
            cmd_idx: u.cmd_idx,
            ret_idx: u.ret_idx,
        })
}

fn reject_duplicate_linear_use_refs(
    cmd: &Command,
    cmd_idx: u16,
    manifests: &std::collections::HashMap<[u8; 32], PetalManifestStub>,
    consumed: &mut HashSet<UseRef>,
) -> Result<(), PtbError> {
    match cmd {
        Command::Move(m) => {
            let hash = m.petal.hash.ok_or_else(|| PtbError::PetalNotPinned {
                path: m.petal.path.clone(),
            })?;
            let manifest = manifests
                .get(&hash.0)
                .ok_or(PtbError::PetalNotFound { hash })?;
            let f = manifest
                .function(&m.function)
                .ok_or_else(|| PtbError::UnknownFunction {
                    function: m.function.clone(),
                    petal_hash: hash,
                })?;
            for (arg, decl) in m.args.iter().zip(f.args.iter()) {
                if matches!(decl, ArgDeclStub::Object { .. })
                    && let Arg::Use {
                        cmd_idx: use_cmd_idx,
                        ret_idx,
                    } = arg
                {
                    consume_linear_use_ref(
                        consumed,
                        UseRef {
                            cmd_idx: *use_cmd_idx,
                            ret_idx: *ret_idx,
                        },
                        cmd_idx,
                    )?;
                }
            }
        }
        Command::TransferObjects { uses, .. }
        | Command::MergeCoins(uses)
        | Command::MakeMoveVec { uses, .. } => {
            for u in uses {
                consume_linear_use_ref(consumed, *u, cmd_idx)?;
            }
        }
        Command::SplitCoins { src, .. } => {
            consume_linear_use_ref(consumed, *src, cmd_idx)?;
        }
        Command::Publish(_) | Command::UpgradePetal(_) => {}
    }
    Ok(())
}

fn consume_linear_use_ref(
    consumed: &mut HashSet<UseRef>,
    u: UseRef,
    referring_cmd: u16,
) -> Result<(), PtbError> {
    if consumed.insert(u) {
        Ok(())
    } else {
        Err(PtbError::BuiltinFailed {
            cmd_idx: referring_cmd,
            reason: format!(
                "duplicate linear Use({}, {}) consumption",
                u.cmd_idx, u.ret_idx
            ),
        })
    }
}

fn charge_builtin_fuel(
    byte_len: usize,
    cmd_idx: u16,
    fuel_remaining: &mut u64,
    report: &mut ExecutionReport,
) -> Result<(), PtbError> {
    let byte_fuel = (byte_len as u64).saturating_div(PUBLISH_BYTES_PER_FUEL);
    let cost = PUBLISH_BASE_FUEL.saturating_add(byte_fuel);
    if cost > *fuel_remaining {
        report.fuel_used = report.fuel_used.saturating_add(*fuel_remaining);
        *fuel_remaining = 0;
        return Err(PtbError::OutOfFuel {
            cmd_idx,
            limit: cost,
            used: cost,
        });
    }
    *fuel_remaining -= cost;
    report.fuel_used = report.fuel_used.saturating_add(cost);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_invariant(
    runner: &dyn PetalRunner,
    petal: &Hash32,
    inv: &InvariantDeclStub,
    args: &[Arg],
    outputs: &[Vec<u8>],
    cmd_idx: u16,
    fuel_budget: u64,
    fuel_remaining: &mut u64,
) -> Result<u64, PtbError> {
    // Build the scope buffer from argspec indices: indices < args.len()
    // select args, indices >= args.len() select outputs[idx - args.len()].
    let mut scope = Vec::new();
    for idx in &inv.argspec {
        let i = *idx as usize;
        if i < args.len() {
            // Re-encode the arg as a length-prefixed blob.
            let bytes = encode_arg_for_scope(&args[i])?;
            let len: u32 = bytes
                .len()
                .try_into()
                .map_err(|_| PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: "invariant scope arg too large".to_string(),
                })?;
            scope.extend_from_slice(&len.to_be_bytes());
            scope.extend_from_slice(&bytes);
        } else {
            let j = i - args.len();
            let bytes = outputs.get(j).ok_or(PtbError::InvariantFailed {
                cmd_idx,
                name: inv.name.clone(),
            })?;
            let len: u32 = bytes
                .len()
                .try_into()
                .map_err(|_| PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: "invariant scope output too large".to_string(),
                })?;
            scope.extend_from_slice(&len.to_be_bytes());
            scope.extend_from_slice(bytes);
        }
    }
    let res = runner.call_invariant(petal, &inv.wasm_export, &scope, fuel_budget)?;
    if res.fuel_used > *fuel_remaining {
        let limit = *fuel_remaining;
        *fuel_remaining = 0;
        return Err(PtbError::OutOfFuel {
            cmd_idx,
            limit,
            used: res.fuel_used,
        });
    }
    *fuel_remaining = fuel_remaining.saturating_sub(res.fuel_used);
    if !res.ok {
        return Err(PtbError::InvariantFailed {
            cmd_idx,
            name: inv.name.clone(),
        });
    }
    Ok(res.fuel_used)
}

fn encode_arg_for_scope(arg: &Arg) -> Result<Vec<u8>, PtbError> {
    let mut buf = Vec::new();
    crate::encode::encode_arg(&mut buf, arg).map_err(PtbError::Codec)?;
    Ok(buf)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_iface::{ArgDeclStub, FunctionDeclStub, PetalManifestStub, TypeParamDeclStub};
    use crate::host_ctx::HandleEntry;
    use crate::types::{
        Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, PtbTx, PublishCmd, UseRef,
        loom_coin_type_tag,
    };
    use crate::validator::{AlwaysOkVerifier, ValidationContext, ValidationMode, validate_ptb};
    use bloom_chain_types::Hash32;
    use bloom_objects::{Object, Owner};
    use std::cell::RefCell;
    use std::collections::HashMap;

    // ---- Mock chain ----

    #[derive(Default)]
    struct MockChain {
        objects: RefCell<HashMap<[u8; 32], Object>>,
        petals: RefCell<HashMap<[u8; 32], Vec<u8>>>,
        manifests: RefCell<HashMap<[u8; 32], PetalManifestStub>>,
        paths: RefCell<HashMap<String, Hash32>>,
        block: u64,
    }

    impl MockChain {
        fn new() -> Self {
            Self {
                block: 1,
                ..Default::default()
            }
        }
        fn put_object(&self, obj: Object) {
            self.objects.borrow_mut().insert(obj.id.0, obj);
        }
        fn put_petal(&self, hash: Hash32, wasm: Vec<u8>, manifest: PetalManifestStub) {
            self.petals.borrow_mut().insert(hash.0, wasm);
            self.manifests.borrow_mut().insert(hash.0, manifest);
        }
        fn put_path(&self, path: &str, hash: Hash32) {
            self.paths.borrow_mut().insert(path.to_string(), hash);
        }
    }

    impl ChainStateIface for MockChain {
        fn load_object(&self, id: &ObjectId) -> Option<Object> {
            self.objects.borrow().get(&id.0).cloned()
        }
        fn load_petal(&self, hash: &Hash32) -> Option<Vec<u8>> {
            self.petals.borrow().get(&hash.0).cloned()
        }
        fn load_manifest(&self, hash: &Hash32) -> Option<PetalManifestStub> {
            self.manifests.borrow().get(&hash.0).cloned()
        }
        fn resolve_path(&self, path: &str) -> Option<Hash32> {
            self.paths.borrow().get(path).copied()
        }
        fn current_block(&self) -> u64 {
            self.block
        }
    }

    // ---- Mock petal runner ----

    struct MockPetalRunner {
        // (petal, function) -> canned return buffer + fuel
        canned: HashMap<(Hash32, String), (Vec<u8>, u64)>,
        // (petal, export) -> (ok, fuel)
        inv: HashMap<(Hash32, String), (bool, u64)>,
        calls: RefCell<Vec<MockCall>>,
    }

    #[derive(Debug, Clone)]
    struct MockCall {
        petal_hash: Hash32,
        function: String,
        type_args: Vec<TypeTag>,
        args_buf: Vec<u8>,
    }

    impl MockPetalRunner {
        fn new() -> Self {
            Self {
                canned: HashMap::new(),
                inv: HashMap::new(),
                calls: RefCell::new(Vec::new()),
            }
        }
        fn set(&mut self, petal: Hash32, func: &str, ret_buf: Vec<u8>, fuel: u64) {
            self.canned
                .insert((petal, func.to_string()), (ret_buf, fuel));
        }
    }

    impl PetalRunner for MockPetalRunner {
        fn call(
            &self,
            petal_hash: &Hash32,
            function: &str,
            type_args: &[TypeTag],
            args_buf: &[u8],
            _fuel_budget: u64,
        ) -> Result<PetalCallResult, PtbError> {
            self.calls.borrow_mut().push(MockCall {
                petal_hash: *petal_hash,
                function: function.to_string(),
                type_args: type_args.to_vec(),
                args_buf: args_buf.to_vec(),
            });
            match self.canned.get(&(*petal_hash, function.to_string())) {
                Some((buf, fuel)) => Ok(PetalCallResult {
                    ret_buf: buf.clone(),
                    fuel_used: *fuel,
                }),
                None => Err(PtbError::PetalAbort {
                    cmd_idx: 0,
                    code: -1,
                    fuel_used: 0,
                }),
            }
        }
        fn call_invariant(
            &self,
            petal_hash: &Hash32,
            export_name: &str,
            _scope_buf: &[u8],
            _fuel_budget: u64,
        ) -> Result<InvariantResult, PtbError> {
            match self.inv.get(&(*petal_hash, export_name.to_string())) {
                Some((ok, fuel)) => Ok(InvariantResult {
                    ok: *ok,
                    fuel_used: *fuel,
                }),
                None => Ok(InvariantResult {
                    ok: true,
                    fuel_used: 0,
                }),
            }
        }
    }

    // ---- helpers ----

    fn loom_tt() -> TypeTag {
        loom_coin_type_tag(Hash32([0; 32]))
    }

    fn make_coin(id_byte: u8, owner: [u8; 32], value: u128, version: u64) -> Object {
        // 48-byte canonical payload: [ObjectId placeholder (32 bytes)] || [value BE (16 bytes)]
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&value.to_be_bytes());
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: loom_tt(),
            owner: Owner::Address(owner),
            version,
            payload,
        }
    }

    fn non_coin_tt() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0x99; 32],
            type_name: "Vault".to_string(),
            type_args: vec![],
        }
    }

    fn make_non_coin_resource(id_byte: u8, owner: [u8; 32], value: u128, version: u64) -> Object {
        let mut payload = vec![0u8; 32];
        payload.extend_from_slice(&value.to_be_bytes());
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: non_coin_tt(),
            owner: Owner::Address(owner),
            version,
            payload,
        }
    }

    fn build_pkg(chain: &MockChain) -> (Hash32, [u8; 32], ObjectId) {
        let signer = [0x11; 32];
        let gas_id = ObjectId([0xFE; 32]);
        chain.put_object(make_coin(0xFE, signer, 10_000_000, 0));
        let petal = Hash32([0xAB; 32]);
        chain.put_path("/p", petal);
        (petal, signer, gas_id)
    }

    fn build_outputs(items: &[&[u8]]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(items.len() as u32).to_be_bytes());
        for it in items {
            buf.extend_from_slice(&(it.len() as u32).to_be_bytes());
            buf.extend_from_slice(it);
        }
        buf
    }

    fn run(chain: &MockChain, runner: &MockPetalRunner, tx: PtbTx) -> ExecutionReport {
        let verifier = AlwaysOkVerifier;
        let ctx = ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain,
            verifier: &verifier,
            loom_coin_type: loom_tt(),
        };
        let validated = validate_ptb(&tx, &ctx).unwrap();
        let mut exec = PtbExecutor::new(chain, runner, loom_tt(), Hash32([0; 32]));
        exec.execute(validated)
    }

    fn sample_signed_ptb(signer: [u8; 32], gas_id: ObjectId, commands: Vec<Command>) -> PtbTx {
        PtbTx {
            signers: vec![signer],
            commands,
            gas_payer: gas_id,
            gas_budget: 1_000_000,
            gas_price: 1,
            expiry_block: 1000,
            signatures: vec![PqSignature(vec![0; 8])],
        }
    }

    // ---- Tests ----

    #[test]
    fn executes_single_move_command() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "f".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![loom_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "f", build_outputs(&[b"hello"]), 100);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![],
            })],
        );
        let report = run(&chain, &runner, tx);
        assert!(report.success, "report: {report:?}");
        assert_eq!(report.command_outputs.len(), 1);
        assert_eq!(report.command_outputs[0], vec![b"hello".to_vec()]);
    }

    #[test]
    fn executor_rejects_duplicate_linear_use_ref_consumption() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let manifest = PetalManifestStub {
            module_path: "/p".to_string(),
            functions: vec![FunctionDeclStub {
                view: false,
                name: "mint".to_string(),
                type_params: vec![],
                args: vec![],
                returns: vec![loom_tt()],
                attached_invariants: vec![],
            }],
            object_types: vec![],
            external_type_refs: vec![],
        };
        chain.put_petal(petal, vec![1, 2, 3], manifest.clone());
        let minted_id = ObjectId([0x44; 32]);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "mint".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::TransferObjects {
                    uses: vec![
                        UseRef {
                            cmd_idx: 0,
                            ret_idx: 0,
                        },
                        UseRef {
                            cmd_idx: 0,
                            ret_idx: 0,
                        },
                    ],
                    owner: Owner::Address([0x22; 32]),
                },
            ],
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "mint", build_outputs(&[&minted_id.0]), 1);
        let mut manifests = HashMap::new();
        manifests.insert(petal.0, manifest);
        let mut petals = HashMap::new();
        petals.insert(petal.0, vec![1, 2, 3]);
        let mut objects = HashMap::new();
        objects.insert(gas_id.0, chain.load_object(&gas_id).unwrap());
        let validated = ValidatedPtb {
            tx,
            objects,
            petals,
            manifests,
            first_signer_addr: signer,
        };

        let mut exec = PtbExecutor::new(&chain, &runner, loom_tt(), Hash32([0; 32]));
        let report = exec.execute(validated);

        assert!(!report.success);
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::BuiltinFailed { ref reason, .. })
                if reason.contains("duplicate linear Use(0, 0)")
        ));
    }

    #[test]
    fn move_return_count_must_match_manifest() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "f".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "f", build_outputs(&[b"unexpected"]), 7);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![],
            })],
        );
        let report = run(&chain, &runner, tx);
        assert!(!report.success);
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::BuiltinFailed { ref reason, .. }) if reason.contains("manifest declares 0")
        ));
    }

    #[test]
    fn move_return_bytes_must_match_declared_primitive_type() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "f".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![TypeTag::Concrete {
                        petal_hash: [0u8; 32],
                        type_name: "u64".to_string(),
                        type_args: vec![],
                    }],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "f", build_outputs(&[[0u8; 32].as_slice()]), 7);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![],
            })],
        );
        let report = run(&chain, &runner, tx);
        assert!(!report.success);
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::BuiltinFailed { ref reason, .. })
                if reason.contains("declared type u64")
        ));
    }

    #[test]
    fn huge_return_count_reverts_without_allocation() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "f".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "f", u32::MAX.to_be_bytes().to_vec(), 7);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![],
            })],
        );
        let report = run(&chain, &runner, tx);
        assert!(!report.success);
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::BuiltinFailed { ref reason, .. }) if reason.contains("too many slots")
        ));
    }

    #[test]
    fn successful_move_fuel_accumulates_across_commands() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "f".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "f", build_outputs(&[]), 11);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "f".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "f".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
            ],
        );
        let report = run(&chain, &runner, tx);
        assert!(report.success, "report: {report:?}");
        assert_eq!(report.fuel_used, 22);
    }

    #[test]
    fn move_command_forwards_generic_type_args_to_runner() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let usdc = TypeTag::Concrete {
            petal_hash: [0x22; 32],
            type_name: "USDC".to_string(),
            type_args: vec![],
        };
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "generic".to_string(),
                    type_params: vec![TypeParamDeclStub {
                        name: "T".to_string(),
                        phantom: true,
                    }],
                    args: vec![ArgDeclStub::Const(TypeTag::Generic { idx: 0 })],
                    returns: vec![],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "generic", build_outputs(&[]), 100);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "generic".to_string(),
                type_args: vec![usdc.clone()],
                args: vec![Arg::Const(42u128.to_be_bytes().to_vec())],
            })],
        );

        let report = run(&chain, &runner, tx);
        assert!(report.success, "report: {report:?}");
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].petal_hash, petal);
        assert_eq!(calls[0].function, "generic");
        assert_eq!(calls[0].type_args, vec![usdc]);
        assert_eq!(
            u32::from_be_bytes(calls[0].args_buf[..4].try_into().unwrap()),
            1
        );
        assert_eq!(calls[0].args_buf[4], 1);
    }

    #[test]
    fn split_coins_produces_transient_coins() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "load".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        // Source coin (separate from gas payer).
        let src_id = ObjectId([0xCC; 32]);
        chain.put_object(make_coin(0xCC, signer, 1_000, 0));

        // Command 0: "load" returns 32-byte id of the source coin so
        // SplitCoins can refer to it via Use(0,0). In a real PTB this
        // would be a `Move` call to `fungible::borrow_coin` etc.
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "load", build_outputs(&[&src_id.0]), 10);

        // But we also need the source coin to be in the borrow table
        // when SplitCoins runs. Easiest: declare it as an Object arg
        // (Consume) on the `load` MoveCmd; the executor loads it.
        let mut manifest_with_arg = PetalManifestStub {
            module_path: "/p".to_string(),
            functions: vec![FunctionDeclStub {
                view: false,
                name: "load".to_string(),
                type_params: vec![],
                args: vec![ArgDeclStub::Object {
                    ty: loom_tt(),
                    mode: AccessMode::Mutable,
                }],
                returns: vec![loom_tt()],
                attached_invariants: vec![],
            }],
            object_types: vec![],
            external_type_refs: vec![],
        };
        chain.put_petal(petal, vec![], manifest_with_arg.clone());

        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "load".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Object {
                        id: src_id,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Mutable,
                    }],
                }),
                Command::SplitCoins {
                    src: UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    amounts: vec![400, 300],
                },
                // Transfer the two new coins to keep linearity happy.
                Command::TransferObjects {
                    uses: vec![
                        UseRef {
                            cmd_idx: 1,
                            ret_idx: 0,
                        },
                        UseRef {
                            cmd_idx: 1,
                            ret_idx: 1,
                        },
                    ],
                    owner: Owner::Address(signer),
                },
            ],
        );
        // Quiet the unused-var warning.
        let _ = &mut manifest_with_arg;
        let report = run(&chain, &runner, tx);
        assert!(report.success, "report: {report:?}");
        assert_eq!(report.command_outputs[1].len(), 2);
        // Source coin should have a write with value 300 (1000 - 700).
        let updated = report
            .object_writes
            .iter()
            .find(|o| o.id == src_id)
            .expect("source coin must be in writes");
        assert_eq!(decode_coin_value(&updated.payload).unwrap(), 300);
    }

    #[test]
    fn split_coins_rejects_non_coin_shape() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let src_id = ObjectId([0xD1; 32]);
        chain.put_object(make_non_coin_resource(0xD1, signer, 1_000, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "load".to_string(),
                    type_params: vec![],
                    args: vec![ArgDeclStub::Object {
                        ty: non_coin_tt(),
                        mode: AccessMode::Consume,
                    }],
                    returns: vec![non_coin_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "load".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Object {
                        id: src_id,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    }],
                }),
                Command::SplitCoins {
                    src: UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    amounts: vec![100],
                },
            ],
        );

        let verifier = AlwaysOkVerifier;
        let vctx = ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain: &chain,
            verifier: &verifier,
            loom_coin_type: loom_tt(),
        };
        let err = validate_ptb(&tx, &vctx).unwrap_err();
        assert!(matches!(
            err,
            PtbError::BuiltinFailed { reason, .. } if reason.contains("not a Coin")
        ));
    }

    #[test]
    fn transfer_objects_records_ownership_change() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let coin_id = ObjectId([0xCD; 32]);
        chain.put_object(make_coin(0xCD, signer, 100, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "load".to_string(),
                    type_params: vec![],
                    args: vec![ArgDeclStub::Object {
                        ty: loom_tt(),
                        mode: AccessMode::Consume,
                    }],
                    returns: vec![loom_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "load", build_outputs(&[&coin_id.0]), 10);

        let other = [0x22; 32];

        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "load".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Object {
                        id: coin_id,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    }],
                }),
                Command::TransferObjects {
                    uses: vec![UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                    owner: Owner::Address(other),
                },
            ],
        );
        let report = run(&chain, &runner, tx);
        assert!(report.success);
        assert!(
            report
                .ownership_changes
                .iter()
                .any(|(id, old, new)| *id == coin_id
                    && *old == Owner::Address(signer)
                    && *new == Owner::Address(other)),
            "ownership_changes: {:?}",
            report.ownership_changes
        );
    }

    #[test]
    fn transfer_objects_rejects_persistent_read_only_row() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let coin_id = ObjectId([0xD1; 32]);
        chain.put_object(make_coin(0xD1, signer, 100, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "load".to_string(),
                    type_params: vec![],
                    args: vec![ArgDeclStub::Object {
                        ty: loom_tt(),
                        mode: AccessMode::ReadOnly,
                    }],
                    returns: vec![loom_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "load", build_outputs(&[&coin_id.0]), 10);

        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "load".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Object {
                        id: coin_id,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::ReadOnly,
                    }],
                }),
                Command::TransferObjects {
                    uses: vec![UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                    owner: Owner::Address([0x22; 32]),
                },
            ],
        );

        let report = run(&chain, &runner, tx);
        assert!(!report.success, "report: {report:?}");
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::AccessDenied { ref reason, .. })
                if reason.contains("TransferObjects requires consume")
        ));
    }

    #[test]
    fn linearity_violation_reverts() {
        // We construct a SplitCoins whose results are NOT consumed.
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let coin_id = ObjectId([0xCD; 32]);
        chain.put_object(make_coin(0xCD, signer, 100, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "load".to_string(),
                    type_params: vec![],
                    args: vec![ArgDeclStub::Object {
                        ty: loom_tt(),
                        mode: AccessMode::Mutable,
                    }],
                    returns: vec![loom_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "load", build_outputs(&[&coin_id.0]), 10);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "load".to_string(),
                    type_args: vec![],
                    args: vec![Arg::Object {
                        id: coin_id,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Mutable,
                    }],
                }),
                Command::SplitCoins {
                    src: UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    amounts: vec![10],
                },
            ],
        );
        let report = run(&chain, &runner, tx);
        assert!(!report.success);
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::LinearityViolation { .. })
        ));
    }

    #[test]
    fn publish_emits_publish_event() {
        let chain = MockChain::new();
        let (_petal, signer, gas_id) = build_pkg(&chain);
        let runner = MockPetalRunner::new();
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Publish(PublishCmd {
                wasm_bytes: vec![0xDEu8; 32],
                module_path: "/bloom/new/petal".to_string(),
                publisher_cap: None,
            })],
        );
        let report = run(&chain, &runner, tx);
        assert!(report.success);
        assert_eq!(report.publish_events.len(), 1);
        assert_eq!(report.publish_events[0].module_path, "/bloom/new/petal");
        assert!(report.publish_events[0].minted_owner_cap);
        // Output 0 = wasm hash, output 1 = stub owner-cap id.
        assert_eq!(report.command_outputs[0][0].len(), 32);
        assert_eq!(report.command_outputs[0][1].len(), 32);
    }

    #[test]
    fn second_command_revert_discards_first_writes() {
        // Command 0 returns a typed coin id that is absent from the borrow
        // table; command 1 typechecks but fails at execution and must revert.
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "noop".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![loom_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "noop", build_outputs(&[&[0xEE; 32]]), 1);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "noop".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                Command::SplitCoins {
                    src: UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    amounts: vec![1],
                },
            ],
        );
        let report = run(&chain, &runner, tx);
        assert!(!report.success);
        assert!(
            report.object_writes.is_empty(),
            "writes must be discarded on revert"
        );
    }

    #[test]
    fn merge_coins_combines_values() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let a = ObjectId([0x21; 32]);
        let b = ObjectId([0x22; 32]);
        chain.put_object(make_coin(0x21, signer, 50, 0));
        chain.put_object(make_coin(0x22, signer, 70, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "load_two".to_string(),
                    type_params: vec![],
                    args: vec![
                        ArgDeclStub::Object {
                            ty: loom_tt(),
                            mode: AccessMode::Mutable,
                        },
                        ArgDeclStub::Object {
                            ty: loom_tt(),
                            mode: AccessMode::Consume,
                        },
                    ],
                    returns: vec![loom_tt(), loom_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "load_two", build_outputs(&[&a.0, &b.0]), 10);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "load_two".to_string(),
                    type_args: vec![],
                    args: vec![
                        Arg::Object {
                            id: a,
                            expected_version: ExpectedVersion(0),
                            access_mode: AccessMode::Mutable,
                        },
                        Arg::Object {
                            id: b,
                            expected_version: ExpectedVersion(0),
                            access_mode: AccessMode::Consume,
                        },
                    ],
                }),
                Command::MergeCoins(vec![
                    UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    UseRef {
                        cmd_idx: 0,
                        ret_idx: 1,
                    },
                ]),
            ],
        );
        let report = run(&chain, &runner, tx);
        assert!(report.success);
        let merged = report
            .object_writes
            .iter()
            .find(|o| o.id == a)
            .expect("merged coin a");
        assert_eq!(decode_coin_value(&merged.payload).unwrap(), 120);
        // b should be deleted from the borrow table and from persistent state.
        assert!(!report.object_writes.iter().any(|o| o.id == b));
        assert_eq!(
            report.object_deletes,
            vec![(b, Owner::Address(signer))],
            "persistent non-first merge input must be deleted"
        );
    }

    #[test]
    fn merge_coins_rejects_read_only_persistent_non_target() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let a = ObjectId([0x25; 32]);
        let b = ObjectId([0x26; 32]);
        chain.put_object(make_coin(0x25, signer, 50, 0));
        chain.put_object(make_coin(0x26, signer, 70, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "load_two".to_string(),
                    type_params: vec![],
                    args: vec![
                        ArgDeclStub::Object {
                            ty: loom_tt(),
                            mode: AccessMode::Mutable,
                        },
                        ArgDeclStub::Object {
                            ty: loom_tt(),
                            mode: AccessMode::ReadOnly,
                        },
                    ],
                    returns: vec![loom_tt(), loom_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "load_two", build_outputs(&[&a.0, &b.0]), 10);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "load_two".to_string(),
                    type_args: vec![],
                    args: vec![
                        Arg::Object {
                            id: a,
                            expected_version: ExpectedVersion(0),
                            access_mode: AccessMode::Mutable,
                        },
                        Arg::Object {
                            id: b,
                            expected_version: ExpectedVersion(0),
                            access_mode: AccessMode::ReadOnly,
                        },
                    ],
                }),
                Command::MergeCoins(vec![
                    UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    UseRef {
                        cmd_idx: 0,
                        ret_idx: 1,
                    },
                ]),
            ],
        );
        let report = run(&chain, &runner, tx);
        assert!(!report.success, "report: {report:?}");
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::AccessDenied { ref reason, .. })
                if reason.contains("MergeCoins requires consume")
        ));
        assert!(
            !report.object_deletes.iter().any(|(id, _)| *id == b),
            "read-only coin must not be deleted on failed merge"
        );
    }

    #[test]
    fn merge_coins_rejects_non_coin_shape() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let a = ObjectId([0x31; 32]);
        let b = ObjectId([0x32; 32]);
        chain.put_object(make_non_coin_resource(0x31, signer, 50, 0));
        chain.put_object(make_non_coin_resource(0x32, signer, 70, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "load_two".to_string(),
                    type_params: vec![],
                    args: vec![
                        ArgDeclStub::Object {
                            ty: non_coin_tt(),
                            mode: AccessMode::Mutable,
                        },
                        ArgDeclStub::Object {
                            ty: non_coin_tt(),
                            mode: AccessMode::Mutable,
                        },
                    ],
                    returns: vec![non_coin_tt(), non_coin_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "load_two", build_outputs(&[&a.0, &b.0]), 10);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "load_two".to_string(),
                    type_args: vec![],
                    args: vec![
                        Arg::Object {
                            id: a,
                            expected_version: ExpectedVersion(0),
                            access_mode: AccessMode::Mutable,
                        },
                        Arg::Object {
                            id: b,
                            expected_version: ExpectedVersion(0),
                            access_mode: AccessMode::Mutable,
                        },
                    ],
                }),
                Command::MergeCoins(vec![
                    UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    UseRef {
                        cmd_idx: 0,
                        ret_idx: 1,
                    },
                ]),
            ],
        );

        let verifier = AlwaysOkVerifier;
        let vctx = ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain: &chain,
            verifier: &verifier,
            loom_coin_type: loom_tt(),
        };
        let err = validate_ptb(&tx, &vctx).unwrap_err();
        assert!(matches!(
            err,
            PtbError::BuiltinFailed { reason, .. } if reason.contains("not a Coin")
        ));
    }

    #[test]
    fn invariant_failure_reverts() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let mut manifest = PetalManifestStub {
            module_path: "/p".to_string(),
            functions: vec![FunctionDeclStub {
                view: false,
                name: "f".to_string(),
                type_params: vec![],
                args: vec![],
                returns: vec![],
                attached_invariants: vec![InvariantDeclStub {
                    name: "always_fail".to_string(),
                    wasm_export: "__inv_0".to_string(),
                    argspec: vec![],
                }],
            }],
            object_types: vec![],
            external_type_refs: vec![],
        };
        chain.put_petal(petal, vec![], manifest.clone());
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "f", build_outputs(&[]), 1);
        runner
            .inv
            .insert((petal, "__inv_0".to_string()), (false, 1));
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![],
            })],
        );
        let report = run(&chain, &runner, tx);
        let _ = &mut manifest;
        assert!(!report.success);
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::InvariantFailed { .. })
        ));
    }

    #[test]
    fn invariant_out_of_fuel_charges_remaining_fuel() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "f".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![],
                    attached_invariants: vec![InvariantDeclStub {
                        name: "oof".to_string(),
                        wasm_export: "__inv_oof".to_string(),
                        argspec: vec![],
                    }],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let mut runner = MockPetalRunner::new();
        runner.set(petal, "f", build_outputs(&[]), 1);
        runner
            .inv
            .insert((petal, "__inv_oof".to_string()), (true, 2_000_000));
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![],
            })],
        );
        let report = run(&chain, &runner, tx);
        assert!(!report.success);
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::OutOfFuel { .. })
        ));
        assert_eq!(report.fuel_used, 1_000_000);
    }

    #[test]
    fn upgrade_is_disabled_until_owner_cap_authority_exists() {
        let chain = MockChain::new();
        let (_petal, signer, gas_id) = build_pkg(&chain);
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::UpgradePetal(UpgradeCmd {
                wasm_bytes: vec![0xCAu8; 16],
                module_path: "/bloom/dex/strategy/cpmm".to_string(),
                publisher_cap: UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                },
            })],
        );
        let verifier = AlwaysOkVerifier;
        let ctx = ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain: &chain,
            verifier: &verifier,
            loom_coin_type: loom_tt(),
        };
        let err = validate_ptb(&tx, &ctx).expect_err("upgrade must be rejected before execution");
        assert!(matches!(
            err,
            PtbError::BuiltinFailed { ref reason, .. }
                if reason.contains("UpgradePetal is disabled")
        ));
    }

    // ------------------------------------------------------------------
    // P0-2 / P1-1 conformance tests (shared borrow table)
    // ------------------------------------------------------------------

    /// Petal runner that asserts the shared ctx holds the preloaded
    /// object row when its `call(...)` body runs, then optionally
    /// inserts a host-created object into the borrow table to simulate
    /// the `object.create` host import.
    type HostMutations = HashMap<String, Vec<(ObjectId, Vec<u8>)>>;

    struct AssertingRunner<'a> {
        ctx: Arc<Mutex<PtbHostCtx>>,
        expect_preloaded: Vec<ObjectId>,
        /// (function, return buffer, fuel).
        canned: HashMap<String, (Vec<u8>, u64)>,
        /// On a call to this function name, simulate `object.create`
        /// by inserting these objects into both `borrow_table` and
        /// `created_objects`. We thread the cell so the runner can
        /// pop a Vec per call without taking &mut self.
        host_creates: std::cell::RefCell<HashMap<String, Vec<Object>>>,
        /// On a call to this function name, simulate `object.mutate` on
        /// preloaded rows.
        host_mutates: std::cell::RefCell<HostMutations>,
        /// Verifies that calling the runner does NOT find a held lock
        /// in the ctx mutex (i.e. the executor released it).
        try_lock_must_succeed: std::cell::Cell<bool>,
        _life: std::marker::PhantomData<&'a ()>,
    }

    impl<'a> AssertingRunner<'a> {
        fn new(ctx: Arc<Mutex<PtbHostCtx>>) -> Self {
            Self {
                ctx,
                expect_preloaded: Vec::new(),
                canned: HashMap::new(),
                host_creates: std::cell::RefCell::new(HashMap::new()),
                host_mutates: std::cell::RefCell::new(HashMap::new()),
                try_lock_must_succeed: std::cell::Cell::new(false),
                _life: std::marker::PhantomData,
            }
        }
        fn set(&mut self, func: &str, ret_buf: Vec<u8>, fuel: u64) {
            self.canned.insert(func.to_string(), (ret_buf, fuel));
        }
    }

    impl<'a> PetalRunner for AssertingRunner<'a> {
        fn call(
            &self,
            _petal_hash: &Hash32,
            function: &str,
            _type_args: &[TypeTag],
            _args_buf: &[u8],
            _fuel_budget: u64,
        ) -> Result<PetalCallResult, PtbError> {
            // Test #3: the executor must have released the lock before
            // calling us. If `try_lock_must_succeed` is set we assert
            // the lock acquires cleanly here (would deadlock if the
            // executor held it across the call).
            if self.try_lock_must_succeed.get() {
                let g = self.ctx.try_lock();
                assert!(g.is_ok(), "executor held ctx lock across petal call");
                drop(g);
            }
            // Test #1: preloaded objects must be visible in the borrow
            // table.
            {
                let g = self.ctx.lock().unwrap();
                for id in &self.expect_preloaded {
                    assert!(
                        g.borrow_table.get(id).is_some(),
                        "preloaded object {id:?} not visible to host import"
                    );
                }
            }
            // Simulate `object.mutate` host import.
            if let Some(mutations) = self.host_mutates.borrow_mut().remove(function) {
                let mut g = self.ctx.lock().unwrap();
                for (id, payload) in mutations {
                    g.borrow_table.mark_dirty(&id, payload)?;
                }
            }
            // Test #2: simulate `object.create` host import.
            if let Some(creates) = self.host_creates.borrow_mut().remove(function) {
                let mut g = self.ctx.lock().unwrap();
                for obj in creates {
                    let row = BorrowRow {
                        object_id: obj.id,
                        type_tag: obj.type_tag.clone(),
                        owner: obj.owner.clone(),
                        version: 0,
                        payload_bytes: obj.payload.clone(),
                        access_mode: AccessMode::Mutable,
                        origin_command_idx: Some(g.current_command_idx),
                        dirty: false,
                        baseline_payload: obj.payload.clone(),
                    };
                    g.borrow_table.insert_transient(row);
                    let _ = g.alloc_handle(HandleEntry {
                        object_id: obj.id,
                        created: true,
                    });
                    g.created_objects.push(obj);
                }
            }
            let (buf, fuel) = self
                .canned
                .get(function)
                .cloned()
                .ok_or(PtbError::PetalAbort {
                    cmd_idx: 0,
                    code: -1,
                    fuel_used: 0,
                })?;
            Ok(PetalCallResult {
                ret_buf: buf,
                fuel_used: fuel,
            })
        }

        fn call_invariant(
            &self,
            _petal_hash: &Hash32,
            _export_name: &str,
            _scope_buf: &[u8],
            _fuel_budget: u64,
        ) -> Result<InvariantResult, PtbError> {
            Ok(InvariantResult {
                ok: true,
                fuel_used: 0,
            })
        }
    }

    /// P0-2 conformance: a PTB with `Arg::Object{id, Mutable}` must
    /// preload the row into the *shared* `ctx.borrow_table` before
    /// dispatching the wasm call, so `object.borrow` host import sees
    /// it. We assert from inside the runner's `call(...)`.
    #[test]
    fn preloaded_object_visible_to_host_import() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let coin_id = ObjectId([0xCD; 32]);
        chain.put_object(make_coin(0xCD, signer, 100, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "f".to_string(),
                    type_params: vec![],
                    args: vec![ArgDeclStub::Object {
                        ty: loom_tt(),
                        mode: AccessMode::Mutable,
                    }],
                    returns: vec![],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );

        let ctx = Arc::new(Mutex::new(PtbHostCtx::new()));
        let mut runner = AssertingRunner::new(Arc::clone(&ctx));
        runner.expect_preloaded.push(coin_id);
        runner.try_lock_must_succeed.set(true);
        runner.set("f", build_outputs(&[]), 5);

        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![Arg::Object {
                    id: coin_id,
                    expected_version: ExpectedVersion(0),
                    access_mode: AccessMode::Mutable,
                }],
            })],
        );

        let verifier = AlwaysOkVerifier;
        let vctx = ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain: &chain,
            verifier: &verifier,
            loom_coin_type: loom_tt(),
        };
        let validated = validate_ptb(&tx, &vctx).unwrap();
        let mut exec = PtbExecutor::with_ctx_arc(
            &chain,
            &runner,
            loom_tt(),
            Hash32([0; 32]),
            Arc::clone(&ctx),
        );
        let report = exec.execute(validated);
        assert!(report.success, "report: {report:?}");
    }

    #[test]
    fn repeated_move_object_arg_uses_current_command_access_mode() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let obj_id = ObjectId([0xA7; 32]);
        chain.put_object(make_non_coin_resource(0xA7, signer, 1, 0));
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![
                    FunctionDeclStub {
                        view: false,
                        name: "mut".to_string(),
                        type_params: vec![],
                        args: vec![ArgDeclStub::Object {
                            ty: non_coin_tt(),
                            mode: AccessMode::Mutable,
                        }],
                        returns: vec![],
                        attached_invariants: vec![],
                    },
                    FunctionDeclStub {
                        view: false,
                        name: "ro".to_string(),
                        type_params: vec![],
                        args: vec![ArgDeclStub::Object {
                            ty: non_coin_tt(),
                            mode: AccessMode::ReadOnly,
                        }],
                        returns: vec![],
                        attached_invariants: vec![],
                    },
                ],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );

        let ctx = Arc::new(Mutex::new(PtbHostCtx::new()));
        let mut runner = AssertingRunner::new(Arc::clone(&ctx));
        runner.set("mut", build_outputs(&[]), 5);
        runner.set("ro", build_outputs(&[]), 5);
        runner
            .host_mutates
            .borrow_mut()
            .insert("ro".to_string(), vec![(obj_id, vec![0xFF; 48])]);

        let obj_arg = |access_mode| Arg::Object {
            id: obj_id,
            expected_version: ExpectedVersion(0),
            access_mode,
        };
        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "mut".to_string(),
                    type_args: vec![],
                    args: vec![obj_arg(AccessMode::Mutable)],
                }),
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "ro".to_string(),
                    type_args: vec![],
                    args: vec![obj_arg(AccessMode::ReadOnly)],
                }),
            ],
        );

        let verifier = AlwaysOkVerifier;
        let vctx = ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain: &chain,
            verifier: &verifier,
            loom_coin_type: loom_tt(),
        };
        let validated = validate_ptb(&tx, &vctx).unwrap();
        let mut exec = PtbExecutor::with_ctx_arc(&chain, &runner, loom_tt(), Hash32([0; 32]), ctx);
        let report = exec.execute(validated);
        assert!(!report.success, "report: {report:?}");
        assert!(matches!(
            report.reverted_with,
            Some(PtbError::IllegalMutation { id, .. }) if id == obj_id
        ));
    }

    /// P1-1 conformance: an object created by a host import inside a
    /// Move call must end up in `report.object_writes`. We simulate
    /// `object.create` by directly inserting into the shared ctx from
    /// our mock runner.
    #[test]
    fn host_created_object_survives_to_report() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "mint".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![loom_tt()],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );

        let new_id = ObjectId([0x77; 32]);
        // 48-byte payload: [id (32)] || [value BE (16)].
        let mut payload = new_id.0.to_vec();
        payload.extend_from_slice(&123u128.to_be_bytes());
        let host_obj = Object {
            id: new_id,
            type_tag: loom_tt(),
            // Defaults the host import gives newly-created objects:
            // the petal's contract address. We use the same signer
            // for simplicity — the test only cares the object ends up
            // in writes; transfer is exercised in the e2e test.
            owner: Owner::Address(signer),
            version: 0,
            payload,
        };

        let ctx = Arc::new(Mutex::new(PtbHostCtx::new()));
        let mut runner = AssertingRunner::new(Arc::clone(&ctx));
        runner.set("mint", build_outputs(&[&new_id.0]), 10);
        runner
            .host_creates
            .borrow_mut()
            .insert("mint".to_string(), vec![host_obj]);

        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![
                Command::Move(MoveCmd {
                    petal: PetalRef {
                        path: "/p".to_string(),
                        hash: Some(petal),
                    },
                    function: "mint".to_string(),
                    type_args: vec![],
                    args: vec![],
                }),
                // Transfer the new object to the signer to satisfy
                // tx-end linearity. The Use(0,0) is the 32-byte id
                // the mock runner emitted.
                Command::TransferObjects {
                    uses: vec![UseRef {
                        cmd_idx: 0,
                        ret_idx: 0,
                    }],
                    owner: Owner::Address(signer),
                },
            ],
        );

        let verifier = AlwaysOkVerifier;
        let vctx = ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain: &chain,
            verifier: &verifier,
            loom_coin_type: loom_tt(),
        };
        let validated = validate_ptb(&tx, &vctx).unwrap();
        let mut exec = PtbExecutor::with_ctx_arc(
            &chain,
            &runner,
            loom_tt(),
            Hash32([0; 32]),
            Arc::clone(&ctx),
        );
        let report = exec.execute(validated);
        assert!(report.success, "report: {report:?}");
        assert!(
            report.object_writes.iter().any(|o| o.id == new_id),
            "host-created object missing from report.object_writes: {:?}",
            report
                .object_writes
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>()
        );
    }

    /// P0-2 / no-deadlock: prove the executor does not hold the ctx
    /// lock across the `petal_runner.call(...)` boundary. The runner
    /// invokes `try_lock()` on the ctx; a `Poisoned` or `WouldBlock`
    /// would fail the test.
    #[test]
    fn executor_releases_lock_across_petal_call() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    view: false,
                    name: "f".to_string(),
                    type_params: vec![],
                    args: vec![],
                    returns: vec![],
                    attached_invariants: vec![],
                }],
                object_types: vec![],
                external_type_refs: vec![],
            },
        );
        let ctx = Arc::new(Mutex::new(PtbHostCtx::new()));
        let mut runner = AssertingRunner::new(Arc::clone(&ctx));
        runner.try_lock_must_succeed.set(true);
        runner.set("f", build_outputs(&[]), 5);

        let tx = sample_signed_ptb(
            signer,
            gas_id,
            vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/p".to_string(),
                    hash: Some(petal),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![],
            })],
        );

        let verifier = AlwaysOkVerifier;
        let vctx = ValidationContext {
            mode: ValidationMode::Commit,
            current_block: chain.block,
            chain: &chain,
            verifier: &verifier,
            loom_coin_type: loom_tt(),
        };
        let validated = validate_ptb(&tx, &vctx).unwrap();
        let mut exec = PtbExecutor::with_ctx_arc(
            &chain,
            &runner,
            loom_tt(),
            Hash32([0; 32]),
            Arc::clone(&ctx),
        );
        let report = exec.execute(validated);
        assert!(report.success);
    }
}
