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
//! Phase 1 caveat: the executor is library-only. Chain-side wiring
//! into `TxKind::SubmitPtb` lands in Phase 2.

use bloom_chain_types::Hash32;
use bloom_objects::{AbilitySet, AccessMode, Object, ObjectId, Owner, TypeTag};

use crate::borrow_table::{BorrowRow, BorrowTable};
use crate::chain_iface::{ChainStateIface, InvariantDeclStub};
use crate::error::PtbError;
use crate::types::{Arg, Command, MoveCmd, PublishCmd, UpgradeCmd, UseRef};
use crate::validator::{ValidatedPtb, decode_coin_value};

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

/// Loom delta to apply to an account after the executor has run.
///
/// Phase 1: we accumulate these as a list of `(address, delta_loom)`
/// pairs. The chain-side commit step (Phase 2) walks the list and
/// updates `accounts[address].loom`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoomDelta {
    /// 32-byte address whose Loom balance changes.
    pub address: [u8; 32],
    /// Signed bloomwei delta. Positive = credit; negative = debit.
    pub delta: i128,
}

/// Petal publish/upgrade event (Phase 1 stub).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PetalPublishEvent {
    /// VFS path that was published / upgraded.
    pub module_path: String,
    /// Content hash (`blake3` of the wasm).
    pub wasm_hash: Hash32,
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
    /// Objects to delete from the trie.
    pub object_deletes: Vec<ObjectId>,
    /// Ownership re-keys: `(id, new_owner)`. Phase-2 chain code re-
    /// keys the `OwnershipIndex` trie from this list.
    pub ownership_changes: Vec<(ObjectId, Owner)>,
    /// Account-level Loom deltas to reconcile post-commit (spec §9.2).
    pub loom_deltas: Vec<LoomDelta>,
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
    /// Internal counter that drives unique transient `ObjectId`s.
    transient_counter: u64,
    /// PTB hash used as seed for transient id derivation; keeps ids
    /// reproducible across replays of the same tx.
    seed: [u8; 32],
}

impl<'c> PtbExecutor<'c> {
    /// Construct a new executor.
    pub fn new(
        chain: &'c dyn ChainStateIface,
        petal_runner: &'c dyn PetalRunner,
        loom_coin_type: TypeTag,
        fungible_petal_hash: Hash32,
    ) -> Self {
        Self {
            chain,
            petal_runner,
            loom_coin_type,
            fungible_petal_hash,
            transient_counter: 0,
            seed: [0u8; 32],
        }
    }

    /// Execute a validated PTB. Returns a complete
    /// [`ExecutionReport`]. On error, `success = false` and all state
    /// diff fields are cleared.
    pub fn execute(&mut self, vtx: ValidatedPtb) -> ExecutionReport {
        let mut report = ExecutionReport::default();
        self.seed = vtx.tx.signing_digest();
        let mut borrow_table = BorrowTable::new();
        let mut command_outputs: Vec<Vec<Vec<u8>>> = Vec::with_capacity(vtx.tx.commands.len());

        // Track ownership changes for Loom-bearing objects. The
        // executor consults the per-object type tag to know whether to
        // record a Loom delta.
        let mut planned_writes: Vec<Object> = Vec::new();
        let mut planned_deletes: Vec<ObjectId> = Vec::new();
        let mut ownership_changes: Vec<(ObjectId, Owner)> = Vec::new();

        // Tx-scope fuel: Phase 1 charges only inside petal calls.
        // We treat `gas_budget` as the upper bound for the *whole* PTB.
        let mut fuel_remaining = vtx.tx.gas_budget;

        for (cmd_idx, cmd) in vtx.tx.commands.iter().enumerate() {
            let cmd_outputs = match self.dispatch_command(
                cmd,
                cmd_idx as u16,
                &vtx,
                &mut borrow_table,
                &mut command_outputs,
                &mut planned_writes,
                &mut planned_deletes,
                &mut ownership_changes,
                &mut fuel_remaining,
                &mut report,
            ) {
                Ok(o) => o,
                Err(e) => return revert(report, e),
            };
            command_outputs.push(cmd_outputs);

            if let Err(e) = borrow_table.diff_check(cmd_idx as u16) {
                return revert(report, e);
            }
        }

        // Tx-end linearity check.
        let orphans = borrow_table.linearity_check();
        if !orphans.is_empty() {
            return revert(
                report,
                PtbError::LinearityViolation {
                    orphans: orphans.len(),
                    ids: orphans,
                },
            );
        }

        // Commit: persistent rows whose payload changed go onto the
        // write list. Transient rows that survived the linearity
        // check (because they were transferred / shared / frozen via
        // a built-in command) likewise get written.
        for (_id, row) in borrow_table.iter() {
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

        report.success = true;
        report.command_outputs = command_outputs;
        report.object_writes = planned_writes;
        report.object_deletes = planned_deletes;
        report.ownership_changes = ownership_changes;
        report
    }

    // -----------------------------------------------------------------
    // Per-command dispatch
    // -----------------------------------------------------------------

    #[allow(clippy::too_many_arguments, clippy::ptr_arg)]
    fn dispatch_command(
        &mut self,
        cmd: &Command,
        cmd_idx: u16,
        vtx: &ValidatedPtb,
        borrow_table: &mut BorrowTable,
        command_outputs: &mut Vec<Vec<Vec<u8>>>,
        planned_writes: &mut Vec<Object>,
        planned_deletes: &mut Vec<ObjectId>,
        ownership_changes: &mut Vec<(ObjectId, Owner)>,
        fuel_remaining: &mut u64,
        report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        self.dispatch_command_inner(
            cmd,
            cmd_idx,
            vtx,
            borrow_table,
            command_outputs,
            planned_writes,
            planned_deletes,
            ownership_changes,
            fuel_remaining,
            report,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_move(
        &mut self,
        m: &MoveCmd,
        cmd_idx: u16,
        vtx: &ValidatedPtb,
        borrow_table: &mut BorrowTable,
        command_outputs: &[Vec<Vec<u8>>],
        fuel_remaining: &mut u64,
        _report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        // Load every Arg::Object into the borrow table (already type-
        // checked by the validator).
        for arg in &m.args {
            if let Arg::Object {
                id, access_mode, ..
            } = arg
            {
                if borrow_table.get(id).is_none() {
                    let obj = vtx
                        .objects
                        .get(&id.0)
                        .cloned()
                        .ok_or(PtbError::ObjectNotFound { id: *id })?;
                    borrow_table.load_persistent(&obj, *access_mode);
                }
            }
        }

        // Marshal args: a length-prefixed concatenation of per-arg
        // canonical bytes. The bloom-resource runtime on the guest
        // side decodes this prefix-length-blob format.
        let args_buf = marshal_args(&m.args, command_outputs)?;

        let hash = m
            .petal
            .hash
            .ok_or_else(|| PtbError::PetalNotPinned {
                path: m.petal.path.clone(),
            })?;

        let result = self
            .petal_runner
            .call(&hash, &m.function, &m.type_args, &args_buf, *fuel_remaining)?;
        *fuel_remaining = fuel_remaining.saturating_sub(result.fuel_used);

        // Decode the return buffer: same length-prefixed-blobs format
        // as the args.
        let outputs = unmarshal_outputs(&result.ret_buf)?;

        // Run attached invariants.
        let manifest = vtx
            .manifests
            .get(&hash.0)
            .ok_or(PtbError::PetalNotFound { hash })?;
        if let Some(f) = manifest.function(&m.function) {
            for inv in &f.attached_invariants {
                run_invariant(
                    self.petal_runner,
                    &hash,
                    inv,
                    &m.args,
                    &outputs,
                    cmd_idx,
                    *fuel_remaining,
                    fuel_remaining,
                )?;
            }
        }

        Ok(outputs)
    }

    fn exec_transfer(
        &mut self,
        uses: &[UseRef],
        owner: Owner,
        cmd_idx: u16,
        command_outputs: &[Vec<Vec<u8>>],
        borrow_table: &mut BorrowTable,
        ownership_changes: &mut Vec<(ObjectId, Owner)>,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        // Each Use must resolve to a transient object id; we decode
        // the upstream output bytes as `ObjectId` (32 bytes).
        for u in uses {
            let bytes = lookup_use(command_outputs, *u, cmd_idx)?;
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
            let row = borrow_table
                .get_mut(&id)
                .ok_or(PtbError::ObjectNotFound { id })?;
            row.owner = owner.clone();
            ownership_changes.push((id, owner.clone()));
            borrow_table.mark_consumed(&id);
        }
        Ok(vec![])
    }

    fn exec_split_coins(
        &mut self,
        src: &UseRef,
        amounts: &[u128],
        cmd_idx: u16,
        command_outputs: &[Vec<Vec<u8>>],
        borrow_table: &mut BorrowTable,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        let bytes = lookup_use(command_outputs, *src, cmd_idx)?;
        if bytes.len() != 32 {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: format!("SplitCoins src: expected 32-byte id, got {}", bytes.len()),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let src_id = ObjectId(arr);
        let src_row = borrow_table
            .get_mut(&src_id)
            .ok_or(PtbError::ObjectNotFound { id: src_id })?;
        // Decode value.
        let mut value = decode_coin_value(&src_row.payload_bytes).map_err(|_| {
            PtbError::BuiltinFailed {
                cmd_idx,
                reason: "SplitCoins src has invalid Coin payload".to_string(),
            }
        })?;
        let coin_type = src_row.type_tag.clone();
        let owner = src_row.owner.clone();

        let total_out: u128 = amounts.iter().try_fold(0u128, |acc, a| {
            acc.checked_add(*a)
                .ok_or_else(|| PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: "SplitCoins amount overflow".to_string(),
                })
        })?;
        if total_out > value {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: format!(
                    "SplitCoins: total {total_out} exceeds source value {value}"
                ),
            });
        }
        value -= total_out;

        // Write the source's new value back; mark dirty so diff_check
        // bumps the version.
        let new_payload = value.to_be_bytes().to_vec();
        borrow_table.mark_dirty(&src_id, new_payload)?;

        // Emit one transient Coin per requested amount.
        let mut outs: Vec<Vec<u8>> = Vec::with_capacity(amounts.len());
        for amt in amounts {
            let id = self.mint_transient_id(b"split-coin");
            let payload = amt.to_be_bytes().to_vec();
            borrow_table.insert_transient(BorrowRow {
                object_id: id,
                type_tag: coin_type.clone(),
                owner: owner.clone(),
                version: 0,
                payload_bytes: payload.clone(),
                access_mode: AccessMode::Mutable,
                origin_command_idx: Some(cmd_idx),
                dirty: false,
                baseline_payload: payload,
            });
            outs.push(id.0.to_vec());
        }

        Ok(outs)
    }

    fn exec_merge_coins(
        &mut self,
        uses: &[UseRef],
        cmd_idx: u16,
        command_outputs: &[Vec<Vec<u8>>],
        borrow_table: &mut BorrowTable,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        if uses.is_empty() {
            return Err(PtbError::BuiltinFailed {
                cmd_idx,
                reason: "MergeCoins requires at least one Use".to_string(),
            });
        }
        let mut accum: u128 = 0;
        let mut first_id: Option<ObjectId> = None;
        let mut first_type: Option<TypeTag> = None;
        let mut first_owner: Option<Owner> = None;
        for u in uses {
            let bytes = lookup_use(command_outputs, *u, cmd_idx)?;
            if bytes.len() != 32 {
                return Err(PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: format!("MergeCoins: expected 32-byte id, got {}", bytes.len()),
                });
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let id = ObjectId(arr);
            let row = borrow_table
                .get(&id)
                .ok_or(PtbError::ObjectNotFound { id })?;
            let v = decode_coin_value(&row.payload_bytes).map_err(|_| PtbError::BuiltinFailed {
                cmd_idx,
                reason: "MergeCoins: invalid Coin payload".to_string(),
            })?;
            accum = accum
                .checked_add(v)
                .ok_or_else(|| PtbError::BuiltinFailed {
                    cmd_idx,
                    reason: "MergeCoins: total overflow".to_string(),
                })?;
            if first_id.is_none() {
                first_id = Some(id);
                first_type = Some(row.type_tag.clone());
                first_owner = Some(row.owner.clone());
            } else {
                // Type + owner must agree.
                if row.type_tag != *first_type.as_ref().unwrap() {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx,
                        reason: "MergeCoins: heterogeneous coin types".to_string(),
                    });
                }
                if row.owner != *first_owner.as_ref().unwrap() {
                    return Err(PtbError::BuiltinFailed {
                        cmd_idx,
                        reason: "MergeCoins: heterogeneous owners".to_string(),
                    });
                }
                borrow_table.drop_row(&id);
            }
        }
        let id = first_id.unwrap();
        borrow_table.mark_dirty(&id, accum.to_be_bytes().to_vec())?;
        Ok(vec![id.0.to_vec()])
    }

    fn exec_publish(
        &mut self,
        p: &PublishCmd,
        _cmd_idx: u16,
        report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        let wasm_hash = Hash32(*blake3::hash(&p.wasm_bytes).as_bytes());
        let minted_owner_cap = p.publisher_cap.is_none();
        report.publish_events.push(PetalPublishEvent {
            module_path: p.module_path.clone(),
            wasm_hash,
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
        _cmd_idx: u16,
        report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        let wasm_hash = Hash32(*blake3::hash(&u.wasm_bytes).as_bytes());
        report.publish_events.push(PetalPublishEvent {
            module_path: u.module_path.clone(),
            wasm_hash,
            minted_owner_cap: false,
        });
        Ok(vec![wasm_hash.0.to_vec()])
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

// Re-implementation: `dispatch_command` above used `unreachable!()` as
// a placeholder; rewrite the function below as a clean single-match
// returning the per-command outputs and replace the call site.
impl<'c> PtbExecutor<'c> {
    #[allow(clippy::too_many_arguments, clippy::ptr_arg)]
    fn dispatch_command_inner(
        &mut self,
        cmd: &Command,
        cmd_idx: u16,
        vtx: &ValidatedPtb,
        borrow_table: &mut BorrowTable,
        command_outputs: &mut Vec<Vec<Vec<u8>>>,
        _planned_writes: &mut Vec<Object>,
        _planned_deletes: &mut Vec<ObjectId>,
        ownership_changes: &mut Vec<(ObjectId, Owner)>,
        fuel_remaining: &mut u64,
        report: &mut ExecutionReport,
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        match cmd {
            Command::Move(m) => self.exec_move(
                m,
                cmd_idx,
                vtx,
                borrow_table,
                command_outputs,
                fuel_remaining,
                report,
            ),
            Command::TransferObjects { uses, owner } => self.exec_transfer(
                uses,
                owner.clone(),
                cmd_idx,
                command_outputs,
                borrow_table,
                ownership_changes,
            ),
            Command::SplitCoins { src, amounts } => self.exec_split_coins(
                src,
                amounts,
                cmd_idx,
                command_outputs,
                borrow_table,
            ),
            Command::MergeCoins(uses) => {
                self.exec_merge_coins(uses, cmd_idx, command_outputs, borrow_table)
            }
            Command::MakeMoveVec { ty, uses } => self.exec_make_vec_inner(ty, uses, cmd_idx, command_outputs),
            Command::Publish(p) => self.exec_publish(p, cmd_idx, report),
            Command::UpgradePetal(u) => self.exec_upgrade(u, cmd_idx, report),
        }
    }

    fn exec_make_vec_inner(
        &mut self,
        _ty: &TypeTag,
        uses: &[UseRef],
        cmd_idx: u16,
        command_outputs: &[Vec<Vec<u8>>],
    ) -> Result<Vec<Vec<u8>>, PtbError> {
        let mut out = Vec::with_capacity(uses.len() * 32);
        for u in uses {
            let bytes = lookup_use(command_outputs, *u, cmd_idx)?;
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
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn revert(mut report: ExecutionReport, err: PtbError) -> ExecutionReport {
    report.success = false;
    report.reverted_with = Some(err);
    report.object_writes.clear();
    report.object_deletes.clear();
    report.ownership_changes.clear();
    report.loom_deltas.clear();
    report
}

fn marshal_args(args: &[Arg], command_outputs: &[Vec<Vec<u8>>]) -> Result<Vec<u8>, PtbError> {
    // Format: count (u32 BE) then for each arg: tag (u8) + length-prefixed payload.
    let mut buf = Vec::new();
    let count: u32 = args
        .len()
        .try_into()
        .map_err(|_| PtbError::BuiltinFailed {
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
                let len: u32 = enc
                    .len()
                    .try_into()
                    .map_err(|_| PtbError::BuiltinFailed {
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

fn unmarshal_outputs(buf: &[u8]) -> Result<Vec<Vec<u8>>, PtbError> {
    // Format: count (u32 BE) then for each return: length-prefixed bytes.
    if buf.len() < 4 {
        return Ok(vec![]);
    }
    let mut rdr = buf;
    let count = read_u32(&mut rdr)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(&mut rdr)? as usize;
        if rdr.len() < len {
            return Err(PtbError::BuiltinFailed {
                cmd_idx: 0,
                reason: format!(
                    "petal return buffer truncated: need {len}, have {}",
                    rdr.len()
                ),
            });
        }
        out.push(rdr[..len].to_vec());
        rdr = &rdr[len..];
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
) -> Result<(), PtbError> {
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
    *fuel_remaining = fuel_remaining.saturating_sub(res.fuel_used);
    if !res.ok {
        return Err(PtbError::InvariantFailed {
            cmd_idx,
            name: inv.name.clone(),
        });
    }
    Ok(())
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
    use crate::chain_iface::{ArgDeclStub, FunctionDeclStub, PetalManifestStub};
    use crate::types::{
        Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, PtbTx, PublishCmd, UseRef,
        loom_coin_type_tag,
    };
    use crate::validator::{AlwaysOkVerifier, ValidationContext, validate_ptb};
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
    }

    impl MockPetalRunner {
        fn new() -> Self {
            Self {
                canned: HashMap::new(),
                inv: HashMap::new(),
            }
        }
        fn set(&mut self, petal: Hash32, func: &str, ret_buf: Vec<u8>, fuel: u64) {
            self.canned.insert((petal, func.to_string()), (ret_buf, fuel));
        }
    }

    impl PetalRunner for MockPetalRunner {
        fn call(
            &self,
            petal_hash: &Hash32,
            function: &str,
            _type_args: &[TypeTag],
            _args_buf: &[u8],
            _fuel_budget: u64,
        ) -> Result<PetalCallResult, PtbError> {
            match self.canned.get(&(*petal_hash, function.to_string())) {
                Some((buf, fuel)) => Ok(PetalCallResult {
                    ret_buf: buf.clone(),
                    fuel_used: *fuel,
                }),
                None => Err(PtbError::PetalAbort {
                    cmd_idx: 0,
                    code: -1,
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
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: loom_tt(),
            owner: Owner::Address(owner),
            version,
            payload: value.to_be_bytes().to_vec(),
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

    fn run(
        chain: &MockChain,
        runner: &MockPetalRunner,
        tx: PtbTx,
    ) -> ExecutionReport {
        let verifier = AlwaysOkVerifier;
        let ctx = ValidationContext {
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
    fn split_coins_produces_transient_coins() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
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
                name: "load".to_string(),
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
                    name: "load".to_string(),
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
                        access_mode: AccessMode::Mutable,
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
                .any(|(id, o)| *id == coin_id && *o == Owner::Address(other)),
            "ownership_changes: {:?}",
            report.ownership_changes
        );
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
                    name: "load".to_string(),
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
        // Command 0 mutates a Coin via a wasm call (returns garbage so
        // the executor's Move handler succeeds); command 1 tries to
        // SplitCoins from a non-existent transient → revert.
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        chain.put_petal(
            petal,
            vec![],
            PetalManifestStub {
                module_path: "/p".to_string(),
                functions: vec![FunctionDeclStub {
                    name: "noop".to_string(),
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
        runner.set(petal, "noop", build_outputs(&[]), 1);
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
                // Bad split: refers to ret_idx 99 of cmd 0, which has no returns.
                Command::SplitCoins {
                    src: UseRef {
                        cmd_idx: 0,
                        ret_idx: 99,
                    },
                    amounts: vec![1],
                },
            ],
        );
        let report = run(&chain, &runner, tx);
        assert!(!report.success);
        assert!(report.object_writes.is_empty(), "writes must be discarded on revert");
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
                    name: "load_two".to_string(),
                    type_params: vec![],
                    args: vec![
                        ArgDeclStub::Object {
                            ty: loom_tt(),
                            mode: AccessMode::Mutable,
                        },
                        ArgDeclStub::Object {
                            ty: loom_tt(),
                            mode: AccessMode::Mutable,
                        },
                    ],
                    returns: vec![],
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
        let report = run(&chain, &runner, tx);
        assert!(report.success);
        let merged = report
            .object_writes
            .iter()
            .find(|o| o.id == a)
            .expect("merged coin a");
        assert_eq!(decode_coin_value(&merged.payload).unwrap(), 120);
        // b should be deleted from the borrow table (not written).
        assert!(!report.object_writes.iter().any(|o| o.id == b));
    }

    #[test]
    fn invariant_failure_reverts() {
        let chain = MockChain::new();
        let (petal, signer, gas_id) = build_pkg(&chain);
        let mut manifest = PetalManifestStub {
            module_path: "/p".to_string(),
            functions: vec![FunctionDeclStub {
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
        runner.inv.insert((petal, "__inv_0".to_string()), (false, 1));
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
    fn upgrade_emits_event_no_owner_cap() {
        let chain = MockChain::new();
        let (_petal, signer, gas_id) = build_pkg(&chain);
        let runner = MockPetalRunner::new();
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
        let report = run(&chain, &runner, tx);
        assert!(report.success);
        assert_eq!(report.publish_events.len(), 1);
        assert!(!report.publish_events[0].minted_owner_cap);
    }
}
