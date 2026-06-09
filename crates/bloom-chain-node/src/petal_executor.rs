//! Real chain-mode petal executor.
//!
//! Bridges `consensus_driver::PetalExecutor` to Bloom-native PTB/object
//! execution through the deterministic chain VM.
//!
//! Snapshot semantics:
//! - LOOM value lives in `Coin<LOOM>` objects. The executor mutates those
//!   objects directly and never mirrors value into `Account`.
//! - The VM returns the (mutated) snapshot; we `.commit()` it into a `WriteSet`
//!   on success, or drop it on revert.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bloom_chain_consensus::tx_admission::{MAX_CHAIN_WASM_BYTES, deploy_petal_fuel_for_bytes};
use bloom_chain_state::{State, StateSnapshot};
use bloom_chain_types::{
    receipt::{InvariantRecord, Log},
    tx::{Tx, TxKind},
    types::{Address, Hash32},
};
use bloom_objects::{
    NEW_HOST_IMPORTS, OWNER_KIND_ADDRESS, Object, ObjectId, Owner, OwnershipIndexKey, TypeTag,
    WasmValType,
};
use bloom_petal_fungible::ops::{coin_payload, decode_coin_value, rewrite_value};
use bloom_petal_manifest::extract_petal_manifest_v0;
use bloom_petals::{BlockCtx as PetalBlockCtx, PetalVm};
use bloom_script::{
    AlwaysOkVerifier, CORE_FUNGIBLE_PATH, PetalManifestStub, PtbError, SignatureVerifier,
    ValidatedPtb, ValidationContext, ValidationMode,
    executor::{LogEntry as PtbLogEntry, PtbExecutor},
    host_ctx::PtbHostCtx,
    loom_coin_type_tag, validate_ptb,
};
use tracing::warn;

use crate::chain_petal_runner::ChainPetalRunner;
use crate::coin_select::select_coin_loom;
use crate::consensus_driver::{ExecOutput, PetalExecutor};
use crate::ptb_chain_iface::PtbChainAdapter;
use crate::sig_verifier::XdsaPtbVerifier;

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

/// Map an executor-side invariant verdict into the receipt-level record
/// (ADR-002). Verdict encoding: 0 = satisfied, 1 = violated, 2 =
/// indeterminate.
fn inv_outcome_to_record(o: &bloom_script::InvariantOutcome) -> InvariantRecord {
    use bloom_script::InvariantVerdict;
    InvariantRecord {
        cmd_idx: o.cmd_idx,
        verdict: match o.verdict {
            InvariantVerdict::Satisfied => 0,
            InvariantVerdict::Violated => 1,
            InvariantVerdict::Indeterminate => 2,
        },
        name: o.name.clone().into_bytes(),
    }
}

fn invariant_records(report: &bloom_script::ExecutionReport) -> Vec<InvariantRecord> {
    report
        .invariant_outcomes
        .iter()
        .map(inv_outcome_to_record)
        .collect()
}

fn next_object_version(id: ObjectId, version: u64) -> Result<u64, PtbError> {
    version
        .checked_add(1)
        .ok_or(PtbError::ObjectVersionOverflow { id, version })
}

fn version_overflow_output(error: PtbError, fuel_used: u64) -> ExecOutput {
    ExecOutput {
        success: false,
        fuel_used,
        return_data: format!("ptb execution error: {error}").into_bytes(),
        logs: vec![],
        invariant_outcomes: Vec::new(),
        write_set: None,
    }
}

pub(crate) fn validate_chain_petal_admission(
    wasm_bytes: &[u8],
    module_path: &str,
) -> Result<(), String> {
    if wasm_bytes.len() > MAX_CHAIN_WASM_BYTES {
        return Err(format!(
            "wasm size {} exceeds limit {}",
            wasm_bytes.len(),
            MAX_CHAIN_WASM_BYTES
        ));
    }
    validate_chain_petal_module_path(module_path)?;
    let manifest = extract_petal_manifest_v0(wasm_bytes)
        .ok_or_else(|| "missing bloom_petal_manifest_v0".to_string())?;
    if manifest.module_path != module_path {
        return Err(format!(
            "manifest module_path '{}' does not match command path '{}'",
            manifest.module_path, module_path
        ));
    }
    validate_manifest_wasm_abi(wasm_bytes, &manifest)?;
    PetalVm::validate_for_chain(wasm_bytes).map_err(|e| e.to_string())?;
    Ok(())
}

fn validate_chain_petal_module_path(module_path: &str) -> Result<(), String> {
    let Some(suffix) = module_path.strip_prefix("/bloom/petals/") else {
        return Err(format!(
            "module_path '{module_path}' must start with /bloom/petals/"
        ));
    };
    if suffix.is_empty() {
        return Err(format!(
            "module_path '{module_path}' must include a petal path after /bloom/petals/"
        ));
    }
    for segment in suffix.split('/') {
        validate_chain_petal_vfs_segment(module_path, segment)?;
    }
    Ok(())
}

fn validate_chain_petal_vfs_segment(module_path: &str, segment: &str) -> Result<(), String> {
    if segment.is_empty()
        || segment == "."
        || segment == ".."
        || segment.contains('\\')
        || segment.contains('\0')
        || segment.chars().any(char::is_whitespace)
    {
        return Err(format!(
            "module_path '{module_path}' contains VFS-invalid path segment"
        ));
    }
    if segment.starts_with('.') {
        return Err(format!(
            "module_path '{module_path}' reserves dot-prefixed VFS control segments"
        ));
    }
    if segment == "page" {
        return Err(format!(
            "module_path '{module_path}' reserves 'page' for VFS pagination"
        ));
    }
    Ok(())
}

fn validate_chain_petal_function_segment(function: &str) -> Result<(), String> {
    if function.is_empty()
        || function == "."
        || function == ".."
        || function == "page"
        || function.starts_with('.')
        || function.contains('/')
        || function.contains('\\')
        || function.contains('\0')
        || function.chars().any(char::is_whitespace)
    {
        return Err(format!(
            "petal function '{function}' is not addressable as a VFS path segment"
        ));
    }
    Ok(())
}

fn validate_chain_petal_vfs_collisions(
    state: &State,
    manifest: &bloom_petal_manifest::types::PetalManifestV0,
) -> Result<(), String> {
    let new_rel = petal_path_segments(&manifest.module_path)?;
    for (existing_path, existing_hash) in state.iter_vfs() {
        if existing_path == &manifest.module_path {
            continue;
        }
        let Ok(existing_rel) = petal_path_segments(existing_path) else {
            continue;
        };
        if existing_rel.len() < new_rel.len()
            && new_rel.starts_with(&existing_rel)
            && let Some(child_segment) = new_rel.get(existing_rel.len())
            && let Some(existing_manifest) = state
                .get_code(existing_hash)
                .and_then(extract_petal_manifest_v0)
            && existing_manifest
                .functions
                .iter()
                .any(|f| f.name == *child_segment)
        {
            return Err(format!(
                "module_path '{}' collides with function '{}' on ancestor petal '{}'",
                manifest.module_path, child_segment, existing_path
            ));
        }
        if new_rel.len() < existing_rel.len()
            && existing_rel.starts_with(&new_rel)
            && let Some(child_segment) = existing_rel.get(new_rel.len())
            && manifest.functions.iter().any(|f| f.name == *child_segment)
        {
            return Err(format!(
                "function '{}' collides with descendant petal path '{}'",
                child_segment, existing_path
            ));
        }
    }
    validate_chain_petal_vfs_collisions_with_pending(&new_rel, manifest, &[])
}

pub(crate) fn validate_chain_petal_vfs_collisions_with_pending(
    new_rel: &[String],
    manifest: &bloom_petal_manifest::types::PetalManifestV0,
    pending: &[(String, bloom_petal_manifest::types::PetalManifestV0)],
) -> Result<(), String> {
    for (existing_path, existing_manifest) in pending {
        if existing_path == &manifest.module_path {
            return Err(format!(
                "module_path '{}' collides with another publish in the same transaction",
                manifest.module_path
            ));
        }
        let existing_rel = petal_path_segments(existing_path)?;
        if existing_rel.len() < new_rel.len()
            && new_rel.starts_with(&existing_rel)
            && let Some(child_segment) = new_rel.get(existing_rel.len())
            && existing_manifest
                .functions
                .iter()
                .any(|f| f.name == *child_segment)
        {
            return Err(format!(
                "module_path '{}' collides with function '{}' on pending ancestor petal '{}'",
                manifest.module_path, child_segment, existing_path
            ));
        }
        if new_rel.len() < existing_rel.len()
            && existing_rel.starts_with(new_rel)
            && let Some(child_segment) = existing_rel.get(new_rel.len())
            && manifest.functions.iter().any(|f| f.name == *child_segment)
        {
            return Err(format!(
                "function '{}' collides with pending descendant petal path '{}'",
                child_segment, existing_path
            ));
        }
    }
    Ok(())
}

pub(crate) fn petal_path_segments(path: &str) -> Result<Vec<String>, String> {
    let Some(suffix) = path.strip_prefix("/bloom/petals/") else {
        return Err(format!(
            "module_path '{path}' must start with /bloom/petals/"
        ));
    };
    Ok(suffix.split('/').map(str::to_string).collect())
}

fn validate_manifest_wasm_abi(
    wasm_bytes: &[u8],
    manifest: &bloom_petal_manifest::types::PetalManifestV0,
) -> Result<(), String> {
    use std::collections::HashMap;
    use wasmparser::{ExternalKind, Parser, Payload, TypeRef, ValType};

    let mut types = Vec::new();
    let mut imported_func_types = Vec::new();
    let mut defined_func_types = Vec::new();
    let mut exports: HashMap<String, u32> = HashMap::new();

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        let payload = payload.map_err(|e| format!("wasm parse: {e}"))?;
        match payload {
            Payload::TypeSection(reader) => {
                for ty in reader.into_iter_err_on_gc_types() {
                    let ty = ty.map_err(|e| format!("wasm type section: {e}"))?;
                    types.push((ty.params().to_vec(), ty.results().to_vec()));
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| format!("wasm import section: {e}"))?;
                    let TypeRef::Func(type_idx) = import.ty else {
                        return Err(format!(
                            "chain petal import '{}.{}' must be a function import",
                            import.module, import.name
                        ));
                    };
                    let (params, results) = types.get(type_idx as usize).ok_or_else(|| {
                        format!(
                            "import {}.{} references missing type {type_idx}",
                            import.module, import.name
                        )
                    })?;
                    let Some(expected) = NEW_HOST_IMPORTS
                        .iter()
                        .find(|decl| decl.module == import.module && decl.name == import.name)
                    else {
                        return Err(format!(
                            "chain petal imports unknown host function '{}.{}'",
                            import.module, import.name
                        ));
                    };
                    if !wasm_sig_matches(params, expected.params)
                        || !wasm_sig_matches(results, expected.results)
                    {
                        return Err(format!(
                            "chain petal import '{}.{}' has wrong signature",
                            import.module, import.name
                        ));
                    }
                    imported_func_types.push(type_idx);
                }
            }
            Payload::FunctionSection(reader) => {
                for type_idx in reader {
                    defined_func_types
                        .push(type_idx.map_err(|e| format!("wasm function section: {e}"))?);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| format!("wasm export section: {e}"))?;
                    if export.kind == ExternalKind::Func {
                        exports.insert(export.name.to_string(), export.index);
                    }
                }
            }
            _ => {}
        }
    }

    for f in &manifest.functions {
        validate_chain_petal_function_segment(&f.name)?;
        validate_export_abi(
            &format!("__petal_{}", f.name),
            &exports,
            &imported_func_types,
            &defined_func_types,
            &types,
        )?;
    }
    for inv in &manifest.invariants {
        validate_export_abi(
            &inv.wasm_export,
            &exports,
            &imported_func_types,
            &defined_func_types,
            &types,
        )?;
    }

    fn wasm_sig_matches(actual: &[ValType], expected: &[WasmValType]) -> bool {
        actual.len() == expected.len()
            && actual.iter().zip(expected).all(|(actual, expected)| {
                matches!(
                    (actual, expected),
                    (ValType::I32, WasmValType::I32) | (ValType::I64, WasmValType::I64)
                )
            })
    }

    fn validate_export_abi(
        export_name: &str,
        exports: &HashMap<String, u32>,
        imported_func_types: &[u32],
        defined_func_types: &[u32],
        types: &[(Vec<ValType>, Vec<ValType>)],
    ) -> Result<(), String> {
        let func_idx = *exports
            .get(export_name)
            .ok_or_else(|| format!("manifest export '{export_name}' missing from wasm"))?;
        let type_idx = if (func_idx as usize) < imported_func_types.len() {
            imported_func_types[func_idx as usize]
        } else {
            let defined_idx = func_idx as usize - imported_func_types.len();
            *defined_func_types
                .get(defined_idx)
                .ok_or_else(|| format!("export '{export_name}' references missing function"))?
        };
        let (params, results) = types
            .get(type_idx as usize)
            .ok_or_else(|| format!("export '{export_name}' references missing type"))?;
        if !matches!(
            (params.as_slice(), results.as_slice()),
            ([ValType::I32, ValType::I32], [ValType::I32])
        ) {
            return Err(format!(
                "manifest export '{export_name}' has wrong signature; expected (i32, i32) -> i32"
            ));
        }
        Ok(())
    }

    Ok(())
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
        // Production path: manifests resolve from each petal's wasm custom
        // section. PTB signatures are verified as full xDSA signatures by
        // resolving 32-byte signer addresses through chain state's key registry.
        execute_tx_impl(
            tx,
            state,
            block_number,
            timestamp_ms,
            proposer,
            parent_hash,
            None,
            PtbSignaturePolicy::ProductionXdsa,
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
        // production `ChainPetalExecutor` path uses full xDSA via the
        // state key registry. Tests that *do* want to exercise real signature
        // verification go through `ChainPetalExecutor` directly (see
        // `tests/ptb_signature_rejection.rs`).
        execute_tx_impl(
            tx,
            state,
            block_number,
            timestamp_ms,
            proposer,
            parent_hash,
            Some(&self.manifests),
            PtbSignaturePolicy::AlwaysOk,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PtbSignaturePolicy {
    ProductionXdsa,
    AlwaysOk,
}

fn resolve_fungible_petal_hash_from_state(state: &State) -> Result<Hash32, String> {
    state.vfs_lookup(CORE_FUNGIBLE_PATH).ok_or_else(|| {
        format!(
            "missing required VFS binding for {CORE_FUNGIBLE_PATH}; \
             bootstrap states must bind the sentinel explicitly"
        )
    })
}

/// Result of running a PTB through the shared validate + execute core.
pub(crate) struct RunPtbOutput {
    /// Complete PTB execution report.
    pub report: bloom_script::ExecutionReport,
    /// Snapshot after execution. Callers decide whether and how to commit it.
    pub snapshot: StateSnapshot,
}

/// Shared PTB execution core for commit and read-only paths.
///
/// Snapshot selection is deliberately outside this helper: callers pass the
/// exact [`State`] they want evaluated, and the helper has no height selector
/// or historical-read concept.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_ptb(
    state: &State,
    block_number: u64,
    block_ctx: PetalBlockCtx,
    sender: Address,
    ptb: &bloom_script::PtbTx,
    loom_coin_type: TypeTag,
    fungible_petal_hash: Hash32,
    verifier: &dyn SignatureVerifier,
    manifests: Option<&HashMap<Hash32, PetalManifestStub>>,
    mode: ValidationMode,
    prepare_snapshot: impl FnOnce(&ValidatedPtb, StateSnapshot) -> Result<StateSnapshot, PtbError>,
) -> Result<RunPtbOutput, PtbError> {
    let validated = {
        let adapter = match manifests {
            Some(m) => PtbChainAdapter::with_overrides(state, block_number, m),
            None => PtbChainAdapter::new(state, block_number),
        };
        let ctx = ValidationContext {
            mode,
            current_block: block_number,
            chain: &adapter,
            verifier,
            loom_coin_type: loom_coin_type.clone(),
        };
        validate_ptb(ptb, &ctx)?
    };

    let host_ctx = {
        let mut c = PtbHostCtx::new();
        c.signers = validated.tx.signers.clone();
        Arc::new(Mutex::new(c))
    };
    let snapshot = prepare_snapshot(&validated, state.snapshot())?;
    let petals_owned = ChainPetalRunner::petals_from_validated(&validated.petals);
    let runner = ChainPetalRunner::new(
        petals_owned,
        Arc::clone(&host_ctx),
        snapshot,
        block_ctx,
        sender,
    );

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

    Ok(RunPtbOutput {
        report,
        snapshot: runner.into_snapshot(),
    })
}

/// Shared `PetalExecutor::execute_tx` body. The trailing `manifests`
/// parameter is an optional per-petal manifest **override** map the
/// PTB validator consults *before* the wasm custom-section path
/// during `Command::Move` typechecks. Production passes `None`.
///
/// `signature_policy` plugs the signature-check policy: production uses full
/// xDSA via the state key registry; the test-only
/// `ChainPetalExecutorWithManifests` uses `AlwaysOkVerifier` for backwards
/// compatibility with existing stub-signature fixtures.
#[allow(clippy::too_many_arguments)]
fn execute_tx_impl(
    tx: &Tx,
    state: &mut State,
    block_number: u64,
    timestamp_ms: u64,
    proposer: Address,
    parent_hash: Hash32,
    manifests: Option<&HashMap<Hash32, PetalManifestStub>>,
    signature_policy: PtbSignaturePolicy,
) -> ExecOutput {
    // `parent_hash` is the committing block's parent block hash, threaded in
    // by `apply_block_state_transitions` from `block.header.parent_hash`.
    let block_ctx = PetalBlockCtx {
        number: block_number,
        timestamp_ms,
        prevhash: parent_hash,
    };

    match &tx.kind {
        TxKind::DeployPetal { wasm_bytes } => {
            let required_fuel = deploy_petal_fuel_for_bytes(wasm_bytes.len());
            let fuel_used = required_fuel.min(tx.max_fuel);
            if required_fuel > tx.max_fuel {
                return ExecOutput {
                    success: false,
                    fuel_used,
                    return_data: b"deploy petal failed: insufficient max_fuel for wasm storage"
                        .to_vec(),
                    logs: vec![],
                    invariant_outcomes: Vec::new(),
                    write_set: None,
                };
            }
            let manifest = match extract_petal_manifest_v0(wasm_bytes) {
                Some(m) => m,
                None => {
                    return ExecOutput {
                        success: false,
                        fuel_used,
                        return_data: b"deploy petal failed: missing bloom_petal_manifest_v0"
                            .to_vec(),
                        logs: vec![],
                        invariant_outcomes: Vec::new(),
                        write_set: None,
                    };
                }
            };
            if let Err(e) = validate_chain_petal_admission(wasm_bytes, &manifest.module_path) {
                return ExecOutput {
                    success: false,
                    fuel_used,
                    return_data: format!("deploy petal failed: {e}").into_bytes(),
                    logs: vec![],
                    invariant_outcomes: Vec::new(),
                    write_set: None,
                };
            }
            if state.vfs_lookup(&manifest.module_path).is_some() {
                return ExecOutput {
                    success: false,
                    fuel_used,
                    return_data: format!(
                        "deploy petal failed: path '{}' already bound",
                        manifest.module_path
                    )
                    .into_bytes(),
                    logs: vec![],
                    invariant_outcomes: Vec::new(),
                    write_set: None,
                };
            }
            if let Err(e) = validate_chain_petal_vfs_collisions(state, &manifest) {
                return ExecOutput {
                    success: false,
                    fuel_used,
                    return_data: format!("deploy petal failed: {e}").into_bytes(),
                    logs: vec![],
                    invariant_outcomes: Vec::new(),
                    write_set: None,
                };
            }
            let mut snap = state.snapshot();
            let hash = snap.insert_code(wasm_bytes.clone());
            snap.set_vfs_binding(manifest.module_path.clone(), hash);
            ExecOutput {
                success: true,
                fuel_used,
                return_data: hash.0.to_vec(),
                logs: vec![],
                invariant_outcomes: Vec::new(),
                write_set: Some(snap.commit()),
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
                        invariant_outcomes: Vec::new(),
                        write_set: None,
                    }
                }
                Ok(ptb) => {
                    // Validator runs against current chain state. Production
                    // resolves each PTB signer address through the state key
                    // registry and verifies a full xDSA signature. The
                    // manifest-override harness intentionally keeps the
                    // always-ok verifier for legacy in-process fixtures.
                    //
                    let fungible_petal_hash = match resolve_fungible_petal_hash_from_state(state) {
                        Ok(hash) => hash,
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
                                invariant_outcomes: Vec::new(),
                                write_set: None,
                            };
                        }
                    };
                    let loom_coin_type = loom_coin_type_tag(fungible_petal_hash);

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
                    let reservation = match ptb.checked_gas_reservation() {
                        Some(reservation) => reservation,
                        None => {
                            return ExecOutput {
                                success: false,
                                fuel_used: 0,
                                return_data: b"ptb validation error: gas reservation overflow"
                                    .to_vec(),
                                logs: vec![],
                                invariant_outcomes: Vec::new(),
                                write_set: None,
                            };
                        }
                    };
                    let production_verifier;
                    let always_ok_verifier;
                    let verifier: &dyn SignatureVerifier = match signature_policy {
                        PtbSignaturePolicy::ProductionXdsa => {
                            production_verifier = XdsaPtbVerifier::new(state);
                            &production_verifier
                        }
                        PtbSignaturePolicy::AlwaysOk => {
                            always_ok_verifier = AlwaysOkVerifier;
                            &always_ok_verifier
                        }
                    };
                    let mut pre_exec_gas_payer = None;
                    let run = match run_ptb(
                        state,
                        block_number,
                        block_ctx.clone(),
                        tx.sender,
                        &ptb,
                        loom_coin_type.clone(),
                        fungible_petal_hash,
                        verifier,
                        manifests,
                        ValidationMode::Commit,
                        |validated, mut snapshot| {
                            let gas_obj = validated
                                .objects
                                .get(&gas_payer_id.0)
                                .cloned()
                                .expect("validator inserted gas_payer object");
                            if reservation > 0 {
                                // Apply pre-debit. `version` is monotonic on
                                // every mutation (spec §4.4).
                                let pre_value = decode_coin_value(&gas_obj.payload)
                                    .expect("validator decoded coin value");
                                let debited = pre_value
                                    .checked_sub(reservation)
                                    .expect("reservation bounds debit");
                                let new_payload = rewrite_value(&gas_obj.payload, debited)
                                    .expect("rewrite Coin<LOOM> payload");
                                let mut debited_obj = gas_obj.clone();
                                debited_obj.version =
                                    next_object_version(debited_obj.id, debited_obj.version)?;
                                debited_obj.payload = new_payload;
                                snapshot.insert_object(debited_obj);
                            }
                            pre_exec_gas_payer = Some(gas_obj);
                            Ok(snapshot)
                        },
                    ) {
                        Ok(run) => run,
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
                                invariant_outcomes: Vec::new(),
                                write_set: None,
                            };
                        }
                    };
                    let pre_exec_gas_payer =
                        pre_exec_gas_payer.expect("run_ptb prepared commit gas snapshot");
                    let report = run.report;
                    let mut snapshot = run.snapshot;

                    // Clamp fuel actually charged to the inner
                    // budget — defence-in-depth in case the
                    // executor accidentally reports more than the
                    // cap. The reservation we pre-debited is
                    // `gas_budget * gas_price`, so charging more
                    // would underflow the refund.
                    let charged_fuel = report.fuel_used.min(gas_budget);
                    let revert_charged_fuel = if reservation > 0 {
                        gas_budget
                    } else {
                        charged_fuel
                    };

                    if !report.success {
                        // Revert: drop every PTB-side mutation —
                        // EXCEPT the gas accounting, which must
                        // still settle. The pre-execution snapshot
                        // already debited the gas-payer Coin<LOOM>
                        // by the full reservation; on revert we burn
                        // the entire `gas_budget * gas_price` to the
                        // proposer and report `fuel_used = gas_budget`
                        // so receipts/block accounting match the gas
                        // delta. Build a
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
                            let new_value = pre_value
                                .checked_sub(reservation)
                                .expect("reservation bounds debit");
                            debited.payload = rewrite_value(&debited.payload, new_value)
                                .expect("rewrite coin payload");
                            debited.version = match next_object_version(debited.id, debited.version)
                            {
                                Ok(version) => version,
                                Err(e) => {
                                    return version_overflow_output(e, revert_charged_fuel);
                                }
                            };
                            gas_snap.insert_object(debited);
                            if let Err(e) = mint_coin_loom_to(
                                &mut gas_snap,
                                proposer,
                                reservation,
                                b"bloom.ptb.gas.revert",
                                &tx.tx_hash(),
                                loom_coin_type.clone(),
                            ) {
                                warn!(err = %e, "PTB gas proposer credit failed");
                            }
                            Some(gas_snap.commit())
                        } else {
                            None
                        };
                        return ExecOutput {
                            success: false,
                            fuel_used: revert_charged_fuel,
                            return_data: reason.into_bytes(),
                            logs: vec![],
                            // Surface the recorded verdicts on a reverted
                            // PTB too — e.g. the violating invariant when
                            // the revert reason is InvariantFailed (ADR-002).
                            invariant_outcomes: invariant_records(&report),
                            write_set: ws_out,
                        };
                    }

                    // Success: fold the unified ExecutionReport
                    // (which already includes both executor- and
                    // host-import-attributed state) into the
                    // snapshot.
                    let gas_payer_written_by_ptb = report
                        .object_writes
                        .iter()
                        .any(|obj| obj.id == gas_payer_id);
                    let gas_payer_deleted_by_ptb = report
                        .object_deletes
                        .iter()
                        .any(|(id, _)| *id == gas_payer_id);

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

                    let mut pending_publish_manifests = Vec::new();
                    for event in &report.publish_events {
                        let existing_binding = state.vfs_lookup(&event.module_path);
                        if event.minted_owner_cap && existing_binding.is_some() {
                            drop(snapshot);
                            let ws_out = if reservation > 0 {
                                let mut gas_snap = state.snapshot();
                                let mut debited = pre_exec_gas_payer.clone();
                                let pre_value = decode_coin_value(&debited.payload)
                                    .expect("decode pre-exec coin value");
                                let new_value = pre_value
                                    .checked_sub(reservation)
                                    .expect("reservation bounds debit");
                                debited.payload = rewrite_value(&debited.payload, new_value)
                                    .expect("rewrite coin payload");
                                debited.version =
                                    match next_object_version(debited.id, debited.version) {
                                        Ok(version) => version,
                                        Err(e) => {
                                            return version_overflow_output(e, revert_charged_fuel);
                                        }
                                    };
                                gas_snap.insert_object(debited);
                                if let Err(e) = mint_coin_loom_to(
                                    &mut gas_snap,
                                    proposer,
                                    reservation,
                                    b"bloom.ptb.gas.publish.path",
                                    &tx.tx_hash(),
                                    loom_coin_type.clone(),
                                ) {
                                    warn!(err = %e, "PTB gas proposer credit failed");
                                }
                                Some(gas_snap.commit())
                            } else {
                                None
                            };
                            return ExecOutput {
                                success: false,
                                fuel_used: revert_charged_fuel,
                                return_data: format!(
                                    "ptb publish admission error: path '{}' already bound",
                                    event.module_path
                                )
                                .into_bytes(),
                                logs: vec![],
                                invariant_outcomes: invariant_records(&report),
                                write_set: ws_out,
                            };
                        }
                        if !event.minted_owner_cap && existing_binding.is_none() {
                            drop(snapshot);
                            let ws_out = if reservation > 0 {
                                let mut gas_snap = state.snapshot();
                                let mut debited = pre_exec_gas_payer.clone();
                                let pre_value = decode_coin_value(&debited.payload)
                                    .expect("decode pre-exec coin value");
                                let new_value = pre_value
                                    .checked_sub(reservation)
                                    .expect("reservation bounds debit");
                                debited.payload = rewrite_value(&debited.payload, new_value)
                                    .expect("rewrite coin payload");
                                debited.version =
                                    match next_object_version(debited.id, debited.version) {
                                        Ok(version) => version,
                                        Err(e) => {
                                            return version_overflow_output(e, revert_charged_fuel);
                                        }
                                    };
                                gas_snap.insert_object(debited);
                                if let Err(e) = mint_coin_loom_to(
                                    &mut gas_snap,
                                    proposer,
                                    reservation,
                                    b"bloom.ptb.gas.upgrade.path",
                                    &tx.tx_hash(),
                                    loom_coin_type.clone(),
                                ) {
                                    warn!(err = %e, "PTB gas proposer credit failed");
                                }
                                Some(gas_snap.commit())
                            } else {
                                None
                            };
                            return ExecOutput {
                                success: false,
                                fuel_used: revert_charged_fuel,
                                return_data: format!(
                                    "ptb upgrade admission error: path '{}' is not bound",
                                    event.module_path
                                )
                                .into_bytes(),
                                logs: vec![],
                                invariant_outcomes: invariant_records(&report),
                                write_set: ws_out,
                            };
                        }
                        let admission =
                            validate_chain_petal_admission(&event.wasm_bytes, &event.module_path);
                        if let Err(e) = admission {
                            drop(snapshot);
                            let ws_out = if reservation > 0 {
                                let mut gas_snap = state.snapshot();
                                let mut debited = pre_exec_gas_payer.clone();
                                let pre_value = decode_coin_value(&debited.payload)
                                    .expect("decode pre-exec coin value");
                                let new_value = pre_value
                                    .checked_sub(reservation)
                                    .expect("reservation bounds debit");
                                debited.payload = rewrite_value(&debited.payload, new_value)
                                    .expect("rewrite coin payload");
                                debited.version =
                                    match next_object_version(debited.id, debited.version) {
                                        Ok(version) => version,
                                        Err(e) => {
                                            return version_overflow_output(e, revert_charged_fuel);
                                        }
                                    };
                                gas_snap.insert_object(debited);
                                if let Err(e) = mint_coin_loom_to(
                                    &mut gas_snap,
                                    proposer,
                                    reservation,
                                    b"bloom.ptb.gas.admission",
                                    &tx.tx_hash(),
                                    loom_coin_type.clone(),
                                ) {
                                    warn!(err = %e, "PTB gas proposer credit failed");
                                }
                                Some(gas_snap.commit())
                            } else {
                                None
                            };
                            return ExecOutput {
                                success: false,
                                fuel_used: revert_charged_fuel,
                                return_data: format!("ptb publish admission error: {e}")
                                    .into_bytes(),
                                logs: vec![],
                                invariant_outcomes: invariant_records(&report),
                                write_set: ws_out,
                            };
                        }
                        let event_manifest = match extract_petal_manifest_v0(&event.wasm_bytes) {
                            Some(manifest) => manifest,
                            None => {
                                drop(snapshot);
                                let ws_out = if reservation > 0 {
                                    let mut gas_snap = state.snapshot();
                                    let mut debited = pre_exec_gas_payer.clone();
                                    let pre_value = decode_coin_value(&debited.payload)
                                        .expect("decode pre-exec coin value");
                                    let new_value = pre_value
                                        .checked_sub(reservation)
                                        .expect("reservation bounds debit");
                                    debited.payload = rewrite_value(&debited.payload, new_value)
                                        .expect("rewrite coin payload");
                                    debited.version =
                                        match next_object_version(debited.id, debited.version) {
                                            Ok(version) => version,
                                            Err(e) => {
                                                return version_overflow_output(
                                                    e,
                                                    revert_charged_fuel,
                                                );
                                            }
                                        };
                                    gas_snap.insert_object(debited);
                                    if let Err(e) = mint_coin_loom_to(
                                        &mut gas_snap,
                                        proposer,
                                        reservation,
                                        b"bloom.ptb.gas.admission",
                                        &tx.tx_hash(),
                                        loom_coin_type.clone(),
                                    ) {
                                        warn!(err = %e, "PTB gas proposer credit failed");
                                    }
                                    Some(gas_snap.commit())
                                } else {
                                    None
                                };
                                return ExecOutput {
                                    success: false,
                                    fuel_used: revert_charged_fuel,
                                    return_data: b"ptb publish admission error: missing bloom_petal_manifest_v0"
                                        .to_vec(),
                                    logs: vec![],
                                    invariant_outcomes: invariant_records(&report),
                                    write_set: ws_out,
                                };
                            }
                        };
                        if let Err(e) = validate_chain_petal_vfs_collisions(state, &event_manifest)
                        {
                            drop(snapshot);
                            let ws_out = if reservation > 0 {
                                let mut gas_snap = state.snapshot();
                                let mut debited = pre_exec_gas_payer.clone();
                                let pre_value = decode_coin_value(&debited.payload)
                                    .expect("decode pre-exec coin value");
                                let new_value = pre_value
                                    .checked_sub(reservation)
                                    .expect("reservation bounds debit");
                                debited.payload = rewrite_value(&debited.payload, new_value)
                                    .expect("rewrite coin payload");
                                debited.version =
                                    match next_object_version(debited.id, debited.version) {
                                        Ok(version) => version,
                                        Err(e) => {
                                            return version_overflow_output(e, revert_charged_fuel);
                                        }
                                    };
                                gas_snap.insert_object(debited);
                                if let Err(e) = mint_coin_loom_to(
                                    &mut gas_snap,
                                    proposer,
                                    reservation,
                                    b"bloom.ptb.gas.admission",
                                    &tx.tx_hash(),
                                    loom_coin_type.clone(),
                                ) {
                                    warn!(err = %e, "PTB gas proposer credit failed");
                                }
                                Some(gas_snap.commit())
                            } else {
                                None
                            };
                            return ExecOutput {
                                success: false,
                                fuel_used: revert_charged_fuel,
                                return_data: format!("ptb publish admission error: {e}")
                                    .into_bytes(),
                                logs: vec![],
                                invariant_outcomes: invariant_records(&report),
                                write_set: ws_out,
                            };
                        }
                        let event_rel = match petal_path_segments(&event_manifest.module_path) {
                            Ok(rel) => rel,
                            Err(e) => {
                                drop(snapshot);
                                let ws_out = if reservation > 0 {
                                    let mut gas_snap = state.snapshot();
                                    let mut debited = pre_exec_gas_payer.clone();
                                    let pre_value = decode_coin_value(&debited.payload)
                                        .expect("decode pre-exec coin value");
                                    let new_value = pre_value
                                        .checked_sub(reservation)
                                        .expect("reservation bounds debit");
                                    debited.payload = rewrite_value(&debited.payload, new_value)
                                        .expect("rewrite coin payload");
                                    debited.version =
                                        match next_object_version(debited.id, debited.version) {
                                            Ok(version) => version,
                                            Err(e) => {
                                                return version_overflow_output(
                                                    e,
                                                    revert_charged_fuel,
                                                );
                                            }
                                        };
                                    gas_snap.insert_object(debited);
                                    if let Err(e) = mint_coin_loom_to(
                                        &mut gas_snap,
                                        proposer,
                                        reservation,
                                        b"bloom.ptb.gas.admission",
                                        &tx.tx_hash(),
                                        loom_coin_type.clone(),
                                    ) {
                                        warn!(err = %e, "PTB gas proposer credit failed");
                                    }
                                    Some(gas_snap.commit())
                                } else {
                                    None
                                };
                                return ExecOutput {
                                    success: false,
                                    fuel_used: revert_charged_fuel,
                                    return_data: format!("ptb publish admission error: {e}")
                                        .into_bytes(),
                                    logs: vec![],
                                    invariant_outcomes: invariant_records(&report),
                                    write_set: ws_out,
                                };
                            }
                        };
                        if let Err(e) = validate_chain_petal_vfs_collisions_with_pending(
                            &event_rel,
                            &event_manifest,
                            &pending_publish_manifests,
                        ) {
                            drop(snapshot);
                            let ws_out = if reservation > 0 {
                                let mut gas_snap = state.snapshot();
                                let mut debited = pre_exec_gas_payer.clone();
                                let pre_value = decode_coin_value(&debited.payload)
                                    .expect("decode pre-exec coin value");
                                let new_value = pre_value
                                    .checked_sub(reservation)
                                    .expect("reservation bounds debit");
                                debited.payload = rewrite_value(&debited.payload, new_value)
                                    .expect("rewrite coin payload");
                                debited.version =
                                    match next_object_version(debited.id, debited.version) {
                                        Ok(version) => version,
                                        Err(e) => {
                                            return version_overflow_output(e, revert_charged_fuel);
                                        }
                                    };
                                gas_snap.insert_object(debited);
                                if let Err(e) = mint_coin_loom_to(
                                    &mut gas_snap,
                                    proposer,
                                    reservation,
                                    b"bloom.ptb.gas.admission",
                                    &tx.tx_hash(),
                                    loom_coin_type.clone(),
                                ) {
                                    warn!(err = %e, "PTB gas proposer credit failed");
                                }
                                Some(gas_snap.commit())
                            } else {
                                None
                            };
                            return ExecOutput {
                                success: false,
                                fuel_used: revert_charged_fuel,
                                return_data: format!("ptb publish admission error: {e}")
                                    .into_bytes(),
                                logs: vec![],
                                invariant_outcomes: invariant_records(&report),
                                write_set: ws_out,
                            };
                        }
                        let hash = snapshot.insert_code(event.wasm_bytes.clone());
                        snapshot.set_vfs_binding(event.module_path.clone(), hash);
                        pending_publish_manifests
                            .push((event.module_path.clone(), event_manifest.clone()));
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
                    let burnt = (charged_fuel as u128)
                        .checked_mul(gas_price)
                        .expect("charged fuel is bounded by checked reservation");
                    let refund = reservation
                        .checked_sub(burnt)
                        .expect("charged fuel is bounded by gas budget");
                    if !gas_payer_deleted_by_ptb
                        && ((gas_payer_written_by_ptb && burnt > 0) || refund > 0)
                    {
                        if let Some(mut current) = snapshot.get_object(&gas_payer_id) {
                            match decode_coin_value(&current.payload) {
                                Ok(cur_value) => {
                                    let new_value = if gas_payer_written_by_ptb {
                                        match cur_value.checked_sub(burnt) {
                                            Some(value) => value,
                                            None => {
                                                return ExecOutput {
                                                    success: false,
                                                    fuel_used: charged_fuel,
                                                    return_data:
                                                        b"ptb gas settlement error: gas burn exceeds mutated gas-payer balance"
                                                            .to_vec(),
                                                    logs: vec![],
                                                    invariant_outcomes: invariant_records(&report),
                                                    write_set: None,
                                                };
                                            }
                                        }
                                    } else {
                                        match cur_value.checked_add(refund) {
                                            Some(value) => value,
                                            None => {
                                                return ExecOutput {
                                                    success: false,
                                                    fuel_used: charged_fuel,
                                                    return_data:
                                                        b"ptb gas settlement error: refund overflow"
                                                            .to_vec(),
                                                    logs: vec![],
                                                    invariant_outcomes: invariant_records(&report),
                                                    write_set: None,
                                                };
                                            }
                                        }
                                    };
                                    match rewrite_value(&current.payload, new_value) {
                                        Ok(new_payload) => {
                                            current.payload = new_payload;
                                            current.version = match next_object_version(
                                                current.id,
                                                current.version,
                                            ) {
                                                Ok(version) => version,
                                                Err(e) => {
                                                    return version_overflow_output(
                                                        e,
                                                        charged_fuel,
                                                    );
                                                }
                                            };
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
                    // Proposer credit (always — burnt or full burn).
                    if burnt > 0
                        && let Err(e) = mint_coin_loom_to(
                            &mut snapshot,
                            proposer,
                            burnt,
                            b"bloom.ptb.gas.success",
                            &tx.tx_hash(),
                            loom_coin_type.clone(),
                        )
                    {
                        return ExecOutput {
                            success: false,
                            fuel_used: charged_fuel,
                            return_data: format!("ptb gas settlement error: {e}").into_bytes(),
                            logs: vec![],
                            invariant_outcomes: invariant_records(&report),
                            write_set: None,
                        };
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

                    let invariant_outcomes = report
                        .invariant_outcomes
                        .iter()
                        .map(inv_outcome_to_record)
                        .collect();

                    ExecOutput {
                        success: true,
                        fuel_used: charged_fuel,
                        return_data,
                        logs,
                        invariant_outcomes,
                        write_set: Some(ws),
                    }
                }
            }
        }
    }
}

/// Move Coin<LOOM> value between address owners.
///
/// Fee settlement and PTB helper paths use this to debit selected sender
/// coins, mint a recipient coin with a deterministic id, and refresh ownership
/// indices for both sides.
pub(crate) fn apply_coin_loom_transfer_with_domain(
    snap: &mut bloom_chain_state::StateSnapshot,
    sender: Address,
    to: Address,
    amount: u128,
    tx_hash: &Hash32,
    coin_type: TypeTag,
    mint_domain: &[u8],
) -> Result<(), String> {
    use crate::coin_select::CoinSelection;

    // 1. Select sender coins.
    let selection: CoinSelection = select_coin_loom(snap, sender, amount, &coin_type)
        .map_err(|e| format!("Coin<LOOM> selection failed: {e}"))?;

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
        obj.version = next_object_version(obj.id, obj.version).map_err(|e| e.to_string())?;
        snap.insert_object(obj);
        // The split coin stays in sender_owned — we keep it.
    }

    snap.set_ownership(sender_okey, sender_owned);

    ensure_coin_loom_credit_fits(snap, to, amount, &coin_type)?;

    mint_coin_loom_to(snap, to, amount, mint_domain, tx_hash, coin_type)
}

fn ensure_coin_loom_credit_fits(
    snap: &bloom_chain_state::StateSnapshot,
    to: Address,
    amount: u128,
    coin_type: &TypeTag,
) -> Result<(), String> {
    let to_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: to.0,
    };
    let current = snap
        .get_ownership(&to_okey)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|id| {
            let obj = snap.get_object(&id)?;
            if obj.type_tag != *coin_type {
                return None;
            }
            match obj.owner {
                Owner::Address(addr) if addr == to.0 => Some(decode_coin_value(&obj.payload)),
                _ => None,
            }
        })
        .try_fold(0u128, |acc, value| {
            let value = value.map_err(|e| format!("Coin<LOOM> decode failed: {e}"))?;
            acc.checked_add(value)
                .ok_or_else(|| "recipient Coin<LOOM> balance overflow".to_string())
        })?;
    current
        .checked_add(amount)
        .map(|_| ())
        .ok_or_else(|| "recipient Coin<LOOM> balance overflow".to_string())
}

pub(crate) fn mint_coin_loom_to(
    snap: &mut bloom_chain_state::StateSnapshot,
    to: Address,
    amount: u128,
    domain: &[u8],
    seed_hash: &Hash32,
    coin_type: TypeTag,
) -> Result<(), String> {
    if amount == 0 {
        return Ok(());
    }
    let payload = coin_payload(amount);
    let creation_seed = loom_mint_creation_seed(domain, seed_hash, to, amount);
    let new_coin_id = ObjectId::derive_for_type_tag(&creation_seed, 0, &coin_type, &payload);

    if snap.get_object(&new_coin_id).is_some() {
        return Err(format!(
            "Coin<LOOM> mint id collision: {}",
            hex::encode(new_coin_id.0)
        ));
    }

    let new_coin = Object {
        id: new_coin_id,
        type_tag: coin_type,
        owner: Owner::Address(to.0),
        version: 0,
        payload,
    };
    snap.insert_object(new_coin);

    let to_okey = OwnershipIndexKey {
        owner_kind: OWNER_KIND_ADDRESS,
        owner_id: to.0,
    };
    let mut to_owned = snap.get_ownership(&to_okey).unwrap_or_default();
    let pos = to_owned.partition_point(|id| id.0 < new_coin_id.0);
    to_owned.insert(pos, new_coin_id);
    snap.set_ownership(to_okey, to_owned);
    Ok(())
}

fn loom_mint_creation_seed(domain: &[u8], seed_hash: &Hash32, to: Address, amount: u128) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(b"bloom.loom.mint.seed");
    h.update(&(domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update(&seed_hash.0);
    h.update(&to.0);
    h.update(&amount.to_be_bytes());
    Hash32(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_chain_consensus::tx_admission::{
        DEPLOY_PETAL_BASE_FUEL, DEPLOY_PETAL_BYTES_PER_FUEL,
    };

    #[test]
    fn inv_outcome_to_record_maps_verdicts() {
        use bloom_script::{InvariantOutcome, InvariantVerdict};
        let mk = |verdict| InvariantOutcome {
            name: "pool_k".to_string(),
            cmd_idx: 4,
            verdict,
        };
        assert_eq!(
            inv_outcome_to_record(&mk(InvariantVerdict::Satisfied)).verdict,
            0
        );
        assert_eq!(
            inv_outcome_to_record(&mk(InvariantVerdict::Violated)).verdict,
            1
        );
        let rec = inv_outcome_to_record(&mk(InvariantVerdict::Indeterminate));
        assert_eq!(rec.verdict, 2);
        assert_eq!(rec.cmd_idx, 4);
        assert_eq!(rec.name, b"pool_k");
    }

    #[test]
    fn deploy_fuel_for_bytes_uses_saturating_add() {
        let per_byte = (usize::MAX as u64) / DEPLOY_PETAL_BYTES_PER_FUEL;
        let expected = DEPLOY_PETAL_BASE_FUEL.saturating_add(per_byte);

        assert_eq!(deploy_petal_fuel_for_bytes(usize::MAX), expected);
    }

    #[test]
    fn chain_petal_module_path_rejects_non_canonical_segments() {
        validate_chain_petal_module_path("/bloom/petals/dex/pool").unwrap();

        for path in [
            "/bloom/dex/pool",
            "/bloom/petals/",
            "/bloom/petals/.pipe",
            "/bloom/petals/.pipe/child",
            "/bloom/petals/dex/.state",
            "/bloom/petals/dex/.foo",
            "/bloom/petals/page",
            "/bloom/petals/dex/page",
            "/bloom/petals/dex\\pool",
            "/bloom/petals/dex/\0pool",
            "/bloom/petals/my app/pool",
            "/bloom/petals/dex/\tpool",
            "/bloom/petals/dex/pool/",
            "/bloom/petals/dex//pool",
            "/bloom/petals/dex/./pool",
            "/bloom/petals/dex/../pool",
        ] {
            assert!(
                validate_chain_petal_module_path(path).is_err(),
                "{path} should be rejected"
            );
        }
    }

    #[test]
    fn chain_petal_function_names_must_be_vfs_segments() {
        validate_chain_petal_function_segment("swap_exact_in").unwrap();

        for function in [
            "",
            ".",
            "..",
            "page",
            ".state",
            ".pipe",
            "foo/bar",
            "foo\\bar",
            "foo\0bar",
            "set counter",
            "set\tcounter",
        ] {
            assert!(
                validate_chain_petal_function_segment(function).is_err(),
                "{function:?} should be rejected"
            );
        }
    }

    #[test]
    fn pending_petal_publishes_reject_path_function_collisions() {
        let parent = bloom_petal_manifest::types::PetalManifestV0 {
            module_path: "/bloom/petals/dex".to_string(),
            functions: vec![bloom_petal_manifest::types::FunctionDecl {
                name: "pool".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let child = bloom_petal_manifest::types::PetalManifestV0 {
            module_path: "/bloom/petals/dex/pool".to_string(),
            ..Default::default()
        };
        let child_rel = petal_path_segments(&child.module_path).unwrap();
        assert!(
            validate_chain_petal_vfs_collisions_with_pending(
                &child_rel,
                &child,
                &[(parent.module_path.clone(), parent)]
            )
            .is_err()
        );
    }

    #[test]
    fn pending_petal_publishes_reject_duplicate_paths() {
        let first = bloom_petal_manifest::types::PetalManifestV0 {
            module_path: "/bloom/petals/dex/pool".to_string(),
            ..Default::default()
        };
        let second = bloom_petal_manifest::types::PetalManifestV0 {
            module_path: "/bloom/petals/dex/pool".to_string(),
            ..Default::default()
        };
        let second_rel = petal_path_segments(&second.module_path).unwrap();
        assert!(
            validate_chain_petal_vfs_collisions_with_pending(
                &second_rel,
                &second,
                &[(first.module_path.clone(), first)]
            )
            .is_err()
        );
    }
}
