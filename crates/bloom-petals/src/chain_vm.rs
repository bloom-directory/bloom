//! Chain-mode petal VM — deterministic smart-contract execution for bloom-chain v0.
//!
//! # Wasmtime configuration (spec §7.5)
//!
//! The chain engine uses a **separate** `wasmtime::Engine` from the
//! local engine so the config cannot bleed across modes.
//!
//! | Setting | Value | Reason |
//! |---------|-------|--------|
//! | `consume_fuel` | `true` | Required for fuel metering and gas pricing (§7.9). |
//! | `cranelift_nan_canonicalization` | `true` | Makes float ops bit-identical across CPUs (determinism). |
//! | `wasm_relaxed_simd` | `false` | Relaxed SIMD is not deterministic across microarchitectures; disabled for chain mode. |
//! | `wasm_simd` | `true` | Standard deterministic SIMD is allowed. |
//! | `wasm_multi_memory` | `false` | Multiple memories are non-deterministic in ordering; banned per spec. |
//! | `wasm_bulk_memory` | `true` | Bulk-memory is deterministic and useful; allowed. |
//! | `wasm_tail_call` | `false` | Tail calls add alternate control-flow opcodes; chain mode rejects them. |
//! | `wasm_threads` | `false` | Shared-memory threads break determinism; banned. |
//! | `async_support` | `false` | Chain calls are fully synchronous (§7.6). |
//! | `cranelift_opt_level` | `Speed` | Same as the existing engine; deterministic across runs. |
//!
//! # Early-exit mechanism for `petal.return` / `petal.revert`
//!
//! wasmtime has no "clean early exit" hook other than traps. We implement
//! early exit by having the `petal.return` / `petal.revert` host imports:
//! 1. Store their data in `ChainCtx` (`return_data` / `revert_reason`).
//! 2. Return `Err(anyhow!("petal.return"))` from the `func_wrap` closure,
//!    which wasmtime propagates as a wasm trap — this reliably interrupts
//!    wasm execution at the callsite, in both sync and async modes.
//!
//! The dispatch loop (`dispatch_chain_call_sync`) then inspects the
//! `ChainStoreData` fields to distinguish "intended exit" from "genuine
//! trap/out-of-fuel":
//! - `revert_reason.is_some()` → reverted (writes discarded).
//! - `return_data.is_some()` → successful return.
//! - Both `None` → genuine trap or out-of-fuel.
//!
//! This is sound because:
//! 1. `return_data` / `revert_reason` are only set by their respective imports.
//! 2. Any other trap leaves both `None`, so the dispatch can distinguish them.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
};

use wasmtime::{Caller, Config, Engine, Linker, Module, OptLevel, Store};

use bloom_chain_state::StateSnapshot;
use bloom_chain_types::{
    Address, Hash32,
    digest::{blake3_tagged, tags},
};
use bloom_objects::{
    AccessMode, OWNER_KIND_ADDRESS, OWNER_KIND_IMMUTABLE, OWNER_KIND_OBJECT, OWNER_KIND_SHARED,
    Object, ObjectId, Owner, TypeTag,
};
use bloom_petal_manifest::{extract_petal_manifest_v0, types::PetalManifestV0};
use bloom_script::{
    BorrowRow, CORE_FUNGIBLE_PATH,
    executor::LogEntry as PtbLogEntry,
    host_ctx::{HandleEntry, PtbHostCtx},
};

use crate::error::PetalError;
use crate::host::HostError;
use crate::vm::PetalVm;

// ---------------------------------------------------------------------------
// Chain-mode context structs
// ---------------------------------------------------------------------------

/// Block-level context values exposed via `block.*` imports.
#[derive(Clone, Debug)]
pub struct BlockCtx {
    pub number: u64,
    pub timestamp_ms: u64,
    pub prevhash: Hash32,
}

/// A single emitted log entry.
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub address: Address,
    pub topics: Vec<Hash32>,
    pub data: Vec<u8>,
}

/// All chain-mode state threaded through `Store<ChainStoreData>`.
pub struct ChainCtx {
    pub snapshot: StateSnapshot,
    pub contract_address: Address,
    pub msg_sender: Address,
    pub msg_value: u128,
    pub calldata: Vec<u8>,
    pub block: BlockCtx,
    pub return_data: Option<Vec<u8>>,
    pub revert_reason: Option<Vec<u8>>,
    pub logs: Vec<LogEntry>,
    pub call_depth: u32,
}

/// Store data for chain-mode execution (no WASI, no bloom VFS).
pub struct ChainStoreData {
    pub chain_ctx: ChainCtx,
    pub petal_hash: Hash32,
    /// Per-PTB host context (spec §16.2 borrow table, signers, logs,
    /// host-created object state, ...) shared between the wasm host imports
    /// installed by `link_new_host_imports` and the surrounding `PtbExecutor`.
    ///
    /// `None` is only used by low-level tests that exercise the linker without a
    /// surrounding PTB executor.
    pub ptb_ctx: Option<Arc<Mutex<PtbHostCtx>>>,
}

// ---------------------------------------------------------------------------
// Public entry-point types
// ---------------------------------------------------------------------------

/// Which exported function the chain VM should invoke.
pub enum ChainEntry {
    /// Invoke the Bloom-native PTB export with the given name.
    Function(String),
}

pub struct ChainCallInput {
    pub wasm: Vec<u8>,
    pub entry: ChainEntry,
    pub contract_address: Address,
    pub msg_sender: Address,
    pub msg_value: u128,
    pub calldata: Vec<u8>,
    pub block: BlockCtx,
    pub fuel: u64,
    pub snapshot: StateSnapshot,
    /// Optional per-PTB host context (spec §16.2).
    ///
    /// Production dispatch always supplies `Some(...)`. Tests may pass `None` to
    /// verify host-import error handling.
    pub ptb_ctx: Option<Arc<Mutex<PtbHostCtx>>>,
}

pub struct ChainCallOutput {
    pub return_data: Option<Vec<u8>>,
    pub revert_reason: Option<Vec<u8>>,
    pub fuel_used: u64,
    pub logs: Vec<LogEntry>,
    /// The snapshot, with any writes accumulated during this call.
    /// Note: `StateSnapshot` does not implement `Debug`, so `ChainCallOutput`
    /// provides a manual `Debug` impl that elides the snapshot.
    pub snapshot: StateSnapshot,
}

impl std::fmt::Debug for ChainCallOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainCallOutput")
            .field("return_data", &self.return_data)
            .field("revert_reason", &self.revert_reason)
            .field("fuel_used", &self.fuel_used)
            .field("logs", &format!("{} entries", self.logs.len()))
            .field("snapshot", &"<StateSnapshot>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Chain-mode engine (singleton within a process, shared across calls)
// ---------------------------------------------------------------------------

static CHAIN_ENGINE: OnceLock<Result<Engine, String>> = OnceLock::new();

fn chain_engine() -> Result<&'static Engine, PetalError> {
    let result = CHAIN_ENGINE.get_or_init(|| {
        let mut config = Config::new();
        // Synchronous — chain calls have no async I/O.
        config.async_support(false);
        // Fuel metering required for gas pricing (spec §7.9).
        config.consume_fuel(true);
        // Determinism: NaN canonicalization (same as local engine).
        config.cranelift_nan_canonicalization(true);
        // Relaxed SIMD is non-deterministic across microarchitectures; disabled.
        config.wasm_relaxed_simd(false);
        // Standard SIMD is deterministic and allowed.
        config.wasm_simd(true);
        // Multiple memories create ordering ambiguity; banned.
        config.wasm_multi_memory(false);
        // Bulk-memory (memory.copy, memory.fill) is deterministic; allowed.
        config.wasm_bulk_memory(true);
        // Tail-call opcodes are disabled in chain mode; the deploy-time verifier
        // rejects them globally so admission matches this engine config.
        config.wasm_tail_call(false);
        config.cranelift_opt_level(OptLevel::Speed);
        Engine::new(&config).map_err(|e| e.to_string())
    });
    result.as_ref().map_err(|e| PetalError::vm(e.clone()))
}

// ---------------------------------------------------------------------------
// Wasm validation
// ---------------------------------------------------------------------------

/// Allow-list of import modules a chain-mode petal may declare.
///
/// `"chain"` is retained only for the PTB calldata/return/revert shim used by
/// the resource runtime. The other modules are the Bloom-native PTB surface.
const CHAIN_ALLOWED_IMPORT_MODULES: &[&str] = &["chain", "object", "cap", "signer", "ptb", "log"];

const VIEW_MUTATING_OBJECT_IMPORTS: &[&str] =
    &["create", "transfer", "share", "freeze", "delete", "mutate"];

/// Validate a wasm binary for chain-mode admission.
///
/// Rejects:
/// - Any import whose module is not in `CHAIN_ALLOWED_IMPORT_MODULES`.
/// - Any function export whose name does not match the PTB petal export naming convention
///   (`__petal_*`, `__inv_*`, `__alloc`, `__dealloc`,
///   `__bloom_manifest_*`).
/// - A `memory` export with min pages > 256 or max pages > 256 (16 MiB cap).
///
/// LLVM/Rust wasm32 builds routinely emit non-function exports such as
/// `__heap_base`, `__data_end`, and `__indirect_function_table`. Those are
/// inert globals/tables — they're not callable host entry points — so we
/// only enforce the entry-point allow-list on Function exports.
///
/// PTB-mode petals (spec §16.2) emit one `__petal_<fn>` export per
/// public function and `__inv_<n>` exports for attached invariants;
/// both naming patterns are permitted.
/// Whether `name` matches one of the PTB-mode petal export naming
/// conventions emitted by `bloom-resource-macros` (spec §16.2).
fn is_ptb_petal_export(name: &str) -> bool {
    name.starts_with("__petal_")
        || name.starts_with("__inv_")
        || matches!(name, "__alloc" | "__dealloc")
        || name.starts_with("__bloom_manifest_")
}

pub fn validate_chain_wasm(bytes: &[u8]) -> Result<(), PetalError> {
    use wasmparser::{ExternalKind, Operator, Parser, Payload};

    let parser = Parser::new(0);
    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
                    if !CHAIN_ALLOWED_IMPORT_MODULES.contains(&import.module) {
                        return Err(PetalError::InvalidWasm(format!(
                            "chain petal imports from disallowed module '{}' (function '{}')",
                            import.module, import.name
                        )));
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
                    match (export.kind, export.name) {
                        (ExternalKind::Func, other) if !is_ptb_petal_export(other) => {
                            return Err(PetalError::InvalidWasm(format!(
                                "chain petal exports disallowed function '{other}'"
                            )));
                        }
                        // Non-function exports (globals, tables, memory) and
                        // function exports allowed by `is_ptb_petal_export`
                        // are harmless: they aren't callable host entry points.
                        _ => {}
                    }
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem = mem.map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
                    if mem.initial > 256 {
                        return Err(PetalError::InvalidWasm(format!(
                            "chain petal memory min pages {} exceeds 256 (16 MiB cap)",
                            mem.initial
                        )));
                    }
                    if mem.maximum.is_some_and(|max| max > 256) {
                        return Err(PetalError::InvalidWasm(format!(
                            "chain petal memory max pages {} exceeds 256 (16 MiB cap)",
                            mem.maximum.unwrap()
                        )));
                    }
                }
            }
            Payload::StartSection { func, .. } => {
                return Err(PetalError::InvalidWasm(format!(
                    "chain petal declares start function {func}; start sections are not allowed"
                )));
            }
            Payload::CodeSectionEntry(body) => {
                let operators = body
                    .get_operators_reader()
                    .map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
                for op in operators {
                    match op.map_err(|e| PetalError::InvalidWasm(e.to_string()))? {
                        Operator::ReturnCall { .. } => {
                            return Err(PetalError::InvalidWasm(
                                "chain petal uses disabled tail-call opcode return_call".into(),
                            ));
                        }
                        Operator::ReturnCallIndirect { .. } => {
                            return Err(PetalError::InvalidWasm(
                                "chain petal uses disabled tail-call opcode return_call_indirect"
                                    .into(),
                            ));
                        }
                        Operator::ReturnCallRef { .. } => {
                            return Err(PetalError::InvalidWasm(
                                "chain petal uses disabled tail-call opcode return_call_ref".into(),
                            ));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(manifest) = extract_petal_manifest_v0(bytes) {
        validate_view_functions_are_pure(bytes, &manifest)?;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct StaticCallGraph {
    exports: HashMap<String, u32>,
    import_targets: HashMap<u32, (String, String)>,
    calls: HashMap<u32, Vec<u32>>,
    functions_with_indirect_calls: HashMap<u32, &'static str>,
}

fn validate_view_functions_are_pure(
    bytes: &[u8],
    manifest: &PetalManifestV0,
) -> Result<(), PetalError> {
    let graph = parse_static_call_graph(bytes)?;
    for f in manifest.functions.iter().filter(|f| f.view) {
        let export_name = format!("__petal_{}", f.name);
        let start = graph.exports.get(&export_name).copied().ok_or_else(|| {
            PetalError::InvalidWasm(format!(
                "view function '{}' export '{export_name}' missing from wasm",
                f.name
            ))
        })?;
        reject_view_reachable_mutation(&graph, &f.name, start)?;
    }
    Ok(())
}

fn parse_static_call_graph(bytes: &[u8]) -> Result<StaticCallGraph, PetalError> {
    use wasmparser::{ExternalKind, Operator, Parser, Payload, TypeRef};

    let mut graph = StaticCallGraph::default();
    let mut next_func_index = 0u32;
    let mut defined_func_indices = Vec::<u32>::new();
    let mut code_index = 0usize;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
        match payload {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
                    if matches!(import.ty, TypeRef::Func(_)) {
                        graph.import_targets.insert(
                            next_func_index,
                            (import.module.to_string(), import.name.to_string()),
                        );
                        next_func_index = next_func_index.checked_add(1).ok_or_else(|| {
                            PetalError::InvalidWasm("function index overflow".into())
                        })?;
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    ty.map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
                    defined_func_indices.push(next_func_index);
                    next_func_index = next_func_index
                        .checked_add(1)
                        .ok_or_else(|| PetalError::InvalidWasm("function index overflow".into()))?;
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
                    if export.kind == ExternalKind::Func {
                        graph.exports.insert(export.name.to_string(), export.index);
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let func_idx = *defined_func_indices.get(code_index).ok_or_else(|| {
                    PetalError::InvalidWasm("code section has more bodies than functions".into())
                })?;
                code_index += 1;

                let mut calls = Vec::new();
                let operators = body
                    .get_operators_reader()
                    .map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
                for op in operators {
                    match op.map_err(|e| PetalError::InvalidWasm(e.to_string()))? {
                        Operator::Call { function_index } => calls.push(function_index),
                        Operator::ReturnCall { function_index } => calls.push(function_index),
                        Operator::CallIndirect { .. } => {
                            graph
                                .functions_with_indirect_calls
                                .entry(func_idx)
                                .or_insert("call_indirect");
                        }
                        Operator::ReturnCallIndirect { .. } => {
                            graph
                                .functions_with_indirect_calls
                                .entry(func_idx)
                                .or_insert("return_call_indirect");
                        }
                        Operator::CallRef { .. } => {
                            graph
                                .functions_with_indirect_calls
                                .entry(func_idx)
                                .or_insert("call_ref");
                        }
                        Operator::ReturnCallRef { .. } => {
                            graph
                                .functions_with_indirect_calls
                                .entry(func_idx)
                                .or_insert("return_call_ref");
                        }
                        _ => {}
                    }
                }
                if !calls.is_empty() {
                    graph.calls.insert(func_idx, calls);
                }
            }
            _ => {}
        }
    }

    if code_index != defined_func_indices.len() {
        return Err(PetalError::InvalidWasm(format!(
            "code section body count {} does not match function count {}",
            code_index,
            defined_func_indices.len()
        )));
    }

    Ok(graph)
}

fn reject_view_reachable_mutation(
    graph: &StaticCallGraph,
    view_name: &str,
    start: u32,
) -> Result<(), PetalError> {
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(func_idx) = stack.pop() {
        if !seen.insert(func_idx) {
            continue;
        }

        if let Some(op) = graph.functions_with_indirect_calls.get(&func_idx) {
            return Err(PetalError::InvalidWasm(format!(
                "view function '{view_name}' reaches {op} in function index {func_idx}"
            )));
        }

        if let Some((module, name)) = graph.import_targets.get(&func_idx) {
            if module == "object" && VIEW_MUTATING_OBJECT_IMPORTS.contains(&name.as_str()) {
                return Err(PetalError::InvalidWasm(format!(
                    "view function '{view_name}' reaches mutating host import object.{name}"
                )));
            }
            continue;
        }

        if let Some(calls) = graph.calls.get(&func_idx) {
            stack.extend(calls.iter().copied());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Memory helpers (for ChainStoreData)
// ---------------------------------------------------------------------------

fn get_chain_memory(caller: &mut Caller<'_, ChainStoreData>) -> Option<wasmtime::Memory> {
    caller.get_export("memory").and_then(|e| e.into_memory())
}

fn read_chain_bytes(
    mem: &wasmtime::Memory,
    caller: &mut Caller<'_, ChainStoreData>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, i32> {
    if ptr < 0 || len < 0 {
        return Err(HostError::Invalid("negative ptr/len".into()).as_wasm_code());
    }
    let data = mem.data(caller);
    let start = ptr as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or(HostError::Invalid("ptr+len overflow".into()).as_wasm_code())?;
    let slice = data
        .get(start..end)
        .ok_or(HostError::Invalid("oob read".into()).as_wasm_code())?;
    Ok(slice.to_vec())
}

fn write_chain_bytes(
    mem: &wasmtime::Memory,
    caller: &mut Caller<'_, ChainStoreData>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), i32> {
    if ptr < 0 {
        return Err(HostError::Invalid("negative ptr".into()).as_wasm_code());
    }
    let data = mem.data_mut(caller);
    let start = ptr as usize;
    let end = start
        .checked_add(bytes.len())
        .ok_or(HostError::Invalid("ptr+len overflow".into()).as_wasm_code())?;
    let slot = data
        .get_mut(start..end)
        .ok_or(HostError::Invalid("oob write".into()).as_wasm_code())?;
    slot.copy_from_slice(bytes);
    Ok(())
}

/// Consume fuel for a host-import surcharge. Returns a wasm error code on failure.
///
/// `Caller` exposes `get_fuel` / `set_fuel` but not `consume_fuel`. We subtract
/// manually, saturating at 0 to prevent underflow and allowing the next wasm
/// instruction's fuel check to fire the OutOfFuel trap.
fn consume_fuel(caller: &mut Caller<'_, ChainStoreData>, amount: u64) -> Result<(), i32> {
    let current = caller
        .get_fuel()
        .map_err(|_| HostError::Backend("fuel error".into()).as_wasm_code())?;
    if current < amount {
        // Drain to 0 — next wasm instruction will fire OutOfFuel.
        let _ = caller.set_fuel(0);
        return Err(HostError::Backend("out of fuel".into()).as_wasm_code());
    }
    caller
        .set_fuel(current - amount)
        .map_err(|_| HostError::Backend("fuel set error".into()).as_wasm_code())
}

// ---------------------------------------------------------------------------
// Host imports
// ---------------------------------------------------------------------------

pub fn link_chain_imports(linker: &mut Linker<ChainStoreData>) -> anyhow::Result<()> {
    linker.func_wrap(
        "chain",
        "petal.return",
        |mut caller: Caller<'_, ChainStoreData>,
         data_ptr: i32,
         data_len: i32|
         -> anyhow::Result<()> {
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => {
                    caller.data_mut().chain_ctx.return_data = Some(Vec::new());
                    anyhow::bail!("petal.return");
                }
            };
            let data = read_chain_bytes(&mem, &mut caller, data_ptr, data_len).unwrap_or_default();
            caller.data_mut().chain_ctx.return_data = Some(data);
            anyhow::bail!("petal.return")
        },
    )?;

    linker.func_wrap(
        "chain",
        "petal.revert",
        |mut caller: Caller<'_, ChainStoreData>,
         reason_ptr: i32,
         reason_len: i32|
         -> anyhow::Result<()> {
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => {
                    caller.data_mut().chain_ctx.revert_reason = Some(Vec::new());
                    anyhow::bail!("petal.revert");
                }
            };
            let reason =
                read_chain_bytes(&mem, &mut caller, reason_ptr, reason_len).unwrap_or_default();
            caller.data_mut().chain_ctx.revert_reason = Some(reason);
            anyhow::bail!("petal.revert")
        },
    )?;

    linker.func_wrap(
        "chain",
        "msg.calldata.read",
        |mut caller: Caller<'_, ChainStoreData>, dst_ptr: i32, offset: i32, len: i32| -> i32 {
            if offset < 0 || len < 0 {
                return HostError::Invalid("negative offset/len".into()).as_wasm_code();
            }
            let calldata = caller.data().chain_ctx.calldata.clone();
            let start = offset as usize;
            let end = start.saturating_add(len as usize).min(calldata.len());
            if start > calldata.len() {
                return 0;
            }
            let slice = &calldata[start..end];
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            match write_chain_bytes(&mem, &mut caller, dst_ptr, slice) {
                Ok(()) => slice.len() as i32,
                Err(c) => c,
            }
        },
    )?;

    link_new_host_imports(linker)?;

    Ok(())
}

/// Legacy stub code, retained for documentation: was returned by every
/// §16.2 import while the body was a `NotYetActivated` placeholder.
///
/// All 13 imports now have real bodies (see [`link_new_host_imports`]).
/// We keep the constant so PTBs run against an older binary that still
/// surfaces this code can be diagnosed and any external test harness
/// can keep its assertion.
pub const NOT_YET_ACTIVATED_CODE: i32 = -100;

/// Run a closure with mutable access to the per-PTB host context. If the
/// store has no PTB context attached, the closure is *not* invoked and we
/// return [`HostError::Backend`]'s wasm code so the petal aborts cleanly.
///
/// Returned `i32` is the host import's wasm-side return value — never
/// poisoned-panic, never silent success.
fn with_ptb_ctx<F>(caller: &Caller<'_, ChainStoreData>, f: F) -> i32
where
    F: FnOnce(&mut PtbHostCtx) -> i32,
{
    match caller.data().ptb_ctx.clone() {
        Some(arc) => match arc.lock() {
            Ok(mut ctx) => f(&mut ctx),
            Err(_) => HostError::Backend("ptb ctx poisoned".into()).as_wasm_code(),
        },
        None => HostError::Backend("no ptb ctx".into()).as_wasm_code(),
    }
}

fn row_defining_petal(row: &BorrowRow) -> Result<[u8; 32], i32> {
    match &row.type_tag {
        TypeTag::Concrete { petal_hash, .. } => Ok(*petal_hash),
        _ => Err(HostError::Invalid("object op requires Concrete type_tag".into()).as_wasm_code()),
    }
}

fn can_move_or_reown(row: &BorrowRow, caller_petal: Hash32) -> Result<bool, i32> {
    let defines = row_defining_petal(row)? == caller_petal.0;
    let consumed = row.access_mode == AccessMode::Consume;
    Ok(defines || consumed)
}

const COIN_MINTER_PATHS: &[&str] = &[
    CORE_FUNGIBLE_PATH,
    "/bloom/dex/faucet",
    "/bloom/dex/pool",
    "/bloom/dex/router",
];

fn is_authorized_coin_minter(caller: &Caller<'_, ChainStoreData>, caller_petal: [u8; 32]) -> bool {
    COIN_MINTER_PATHS.iter().any(|path| {
        caller
            .data()
            .chain_ctx
            .snapshot
            .vfs_lookup(path)
            .is_some_and(|hash| hash.0 == caller_petal)
    })
}

/// Install the spec §16.2 host imports onto `linker`.
///
/// Every import:
/// 1. Charges the per-import fuel cost listed in spec §16.4.
/// 2. Reads / writes the petal's linear memory as needed.
/// 3. Mutates / inspects the per-PTB [`PtbHostCtx`] via the
///    [`with_ptb_ctx`] helper.
/// 4. Returns one of the negative [`HostError::as_wasm_code`] values
///    on failure or a non-negative result on success (handle id,
///    written length, 0/1 cap-check, etc.).
fn link_new_host_imports(linker: &mut Linker<ChainStoreData>) -> anyhow::Result<()> {
    // -----------------------------------------------------------------------
    // object.borrow(id_ptr i32, mode i32) -> handle i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "borrow",
        |mut caller: Caller<'_, ChainStoreData>, id_ptr: i32, mode: i32| -> i32 {
            if consume_fuel(&mut caller, 200).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            let id_bytes = match read_chain_bytes(&mem, &mut caller, id_ptr, 32) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let mut id_arr = [0u8; 32];
            id_arr.copy_from_slice(&id_bytes);
            let id = ObjectId(id_arr);

            // Validate the access mode early so the petal sees the
            // proper error code even if no row is preloaded. The actual
            // diff/access enforcement happens in BorrowTable::diff_check
            // at command-end and in `object.mutate` per-call.
            let requested_mode = match AccessMode::from_byte(mode as u8) {
                Ok(m) => m,
                Err(_) => return HostError::Invalid("bad access mode".into()).as_wasm_code(),
            };

            with_ptb_ctx(&caller, |ctx| {
                // Linear-move promotion: a `Consume` borrow of a
                // *transient* row (an object created earlier in this same
                // PTB and threaded here via `Arg::Use`) is an explicit
                // hand-off. The PTB author wired a freshly-minted value
                // into a by-value (Consume) arg slot — so the borrowing
                // petal may delete it even though it does not define the
                // type, exactly as a `Coin<Erased>` faucet-mint feeds a
                // pool's `create_pool` / `swap_exact_in`. Transient rows
                // are born `Mutable` (see `object.create`); promote so
                // `object.delete`'s `defines || Consume` gate admits them.
                //
                // We deliberately do NOT promote *persistent* rows: those
                // carry the PTB-declared access mode the validator already
                // authorized against on-chain ownership, and silently
                // escalating a `Mutable` loan to `Consume` would let a
                // petal delete an object it was only lent.
                if requested_mode == AccessMode::Consume
                    && let Some(row) = ctx.borrow_table.get_mut(&id)
                    && row.origin_command_idx.is_some()
                {
                    row.access_mode = AccessMode::Consume;
                }

                // Coalesce repeat borrows of the same object. (The
                // linear-move promotion above already ran against the
                // row, so reusing a prior command's handle is safe.)
                if ctx.is_handle_retired(&id) {
                    return HostError::Invalid("handle retired".into()).as_wasm_code();
                }
                if let Some(existing) = ctx.handle_for(&id) {
                    return existing;
                }
                // If the row exists but no handle was minted yet (e.g.
                // the executor pre-loaded the row before the petal
                // asked), mint a fresh handle.
                if ctx.borrow_table.get(&id).is_some() {
                    return ctx.alloc_handle(HandleEntry {
                        object_id: id,
                        created: false,
                    });
                }
                // Row not pre-loaded: surface a stable NotFound code so
                // the petal can revert. (The validator + executor are
                // expected to pre-load every object referenced by an
                // `Arg::Object`.)
                HostError::NotFound("object not in borrow table".into()).as_wasm_code()
            })
        },
    )?;

    // -----------------------------------------------------------------------
    // object.read(handle i32, dst_ptr i32, dst_cap i32) -> len i32
    //
    // Returns the number of bytes written (>= 0). If the row's payload is
    // larger than `dst_cap`, returns the **negative** total length so the
    // petal can resize and retry.
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "read",
        |mut caller: Caller<'_, ChainStoreData>, handle: i32, dst_ptr: i32, dst_cap: i32| -> i32 {
            // Pull the bytes out of the ctx first so we can size the
            // fuel charge and the memory write.
            let id = match with_ptb_ctx_lookup_id(&caller, handle) {
                Ok(id) => id,
                Err(code) => return code,
            };
            let payload = match with_ptb_ctx_payload(&caller, &id) {
                Ok(p) => p,
                Err(code) => return code,
            };

            let base_fuel = 100u64.saturating_add(4u64.saturating_mul(payload.len() as u64));
            if consume_fuel(&mut caller, base_fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }

            if dst_cap < 0 {
                return HostError::Invalid("negative dst_cap".into()).as_wasm_code();
            }
            if (payload.len() as i64) > (dst_cap as i64) {
                // Buffer too small — return the negative required length so
                // the petal can resize and retry. We use the i32::MIN bound
                // to avoid wrap-around; if the payload doesn't fit in i32
                // the petal cannot consume it anyway.
                if payload.len() > i32::MAX as usize {
                    return HostError::Invalid("payload exceeds i32::MAX".into()).as_wasm_code();
                }
                return -(payload.len() as i32);
            }

            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            if let Err(c) = write_chain_bytes(&mem, &mut caller, dst_ptr, &payload) {
                return c;
            }
            payload.len() as i32
        },
    )?;

    // -----------------------------------------------------------------------
    // object.mutate(handle i32, src_ptr i32, src_len i32) -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "mutate",
        |mut caller: Caller<'_, ChainStoreData>, handle: i32, src_ptr: i32, src_len: i32| -> i32 {
            if src_len < 0 {
                return HostError::Invalid("negative src_len".into()).as_wasm_code();
            }
            let base_fuel = 1500u64.saturating_add(4u64.saturating_mul(src_len as u64));
            if consume_fuel(&mut caller, base_fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            let bytes = match read_chain_bytes(&mem, &mut caller, src_ptr, src_len) {
                Ok(b) => b,
                Err(c) => return c,
            };

            let id = match with_ptb_ctx_lookup_id(&caller, handle) {
                Ok(id) => id,
                Err(code) => return code,
            };

            let caller_petal = caller.data().petal_hash;
            with_ptb_ctx(&caller, |ctx| {
                let row = match ctx.borrow_table.get(&id) {
                    Some(row) => row,
                    None => {
                        return HostError::NotFound("row vanished".into()).as_wasm_code();
                    }
                };
                if matches!(row.access_mode, AccessMode::ReadOnly) {
                    return HostError::Denied("mutate on ReadOnly".into()).as_wasm_code();
                }
                let defining = match row_defining_petal(row) {
                    Ok(p) => p,
                    Err(code) => return code,
                };
                if defining != caller_petal.0 {
                    return HostError::Denied("object.mutate from non-defining petal".into())
                        .as_wasm_code();
                }
                match ctx.borrow_table.mark_dirty(&id, bytes) {
                    Ok(()) => 0,
                    Err(_) => HostError::Backend("mark_dirty failed".into()).as_wasm_code(),
                }
            })
        },
    )?;

    // -----------------------------------------------------------------------
    // object.create(type_tag_ptr i32, type_tag_len i32,
    //               payload_ptr i32, payload_len i32) -> handle i32
    //
    // Type-defining-petal rule (spec §16.2): the caller petal must
    // be the petal whose hash is in the `TypeTag::Concrete.petal_hash`.
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "create",
        |mut caller: Caller<'_, ChainStoreData>,
         type_tag_ptr: i32,
         type_tag_len: i32,
         payload_ptr: i32,
         payload_len: i32|
         -> i32 {
            if type_tag_len < 0 || payload_len < 0 {
                return HostError::Invalid("negative len".into()).as_wasm_code();
            }
            let base_fuel = 5000u64.saturating_add(4u64.saturating_mul(payload_len as u64));
            if consume_fuel(&mut caller, base_fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            let tag_bytes = match read_chain_bytes(&mem, &mut caller, type_tag_ptr, type_tag_len) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let payload = match read_chain_bytes(&mem, &mut caller, payload_ptr, payload_len) {
                Ok(b) => b,
                Err(c) => return c,
            };

            let type_tag = match TypeTag::decode_canonical(&tag_bytes) {
                Ok(t) => t,
                Err(_) => return HostError::Invalid("bad type_tag".into()).as_wasm_code(),
            };

            // Enforce the type-defining-petal rule (spec §16.2).
            //
            // A petal cannot name its own code hash at compile time, so
            // the `#[bloom::object]` macro emits the `petal_hash =
            // [0u8; 32]` sentinel for every type the petal defines. We
            // treat that sentinel as "self": it is stamped with the
            // caller's real petal hash on creation, giving the on-chain
            // object a concrete defining-petal identity (the validator's
            // `type_tags_match` already treats a `[0u8; 32]` *declared*
            // hash as a wildcard, so downstream type checks line up). A
            // *non-zero* hash that does not match the caller is a forgery
            // attempt — a petal trying to mint another petal's type — and
            // is denied.
            let caller_petal = caller.data().petal_hash.0;
            let stamped_tag = match type_tag {
                TypeTag::Concrete {
                    petal_hash,
                    type_name,
                    type_args,
                } => {
                    if petal_hash != [0u8; 32] && petal_hash != caller_petal {
                        return HostError::Denied("object.create from non-defining petal".into())
                            .as_wasm_code();
                    }
                    if type_name == "Coin" && !is_authorized_coin_minter(&caller, caller_petal) {
                        return HostError::Denied(
                            "object.create Coin from unauthorized petal".into(),
                        )
                        .as_wasm_code();
                    }
                    TypeTag::Concrete {
                        petal_hash: caller_petal,
                        type_name,
                        type_args,
                    }
                }
                _ => {
                    return HostError::Invalid("create requires Concrete type_tag".into())
                        .as_wasm_code();
                }
            };

            // Derive a deterministic transient ObjectId.
            let id = derive_create_id(&caller, &tag_bytes, &payload);
            let object = Object {
                id,
                type_tag: stamped_tag,
                // Default owner: the petal contract address. The petal
                // is expected to call `object.transfer` (or share /
                // freeze) before the command ends. The borrow row is
                // marked `Mutable` so mutate is permitted.
                owner: Owner::Address(caller.data().chain_ctx.contract_address.0),
                version: 0,
                payload: payload.clone(),
            };

            with_ptb_ctx(&caller, |ctx| {
                let row = BorrowRow {
                    object_id: id,
                    type_tag: object.type_tag.clone(),
                    owner: object.owner.clone(),
                    version: 0,
                    payload_bytes: payload.clone(),
                    access_mode: AccessMode::Mutable,
                    origin_command_idx: Some(ctx.current_command_idx),
                    dirty: false,
                    baseline_payload: payload.clone(),
                };
                ctx.borrow_table.insert_transient(row);
                ctx.created_objects.push(object.clone());
                ctx.alloc_handle(HandleEntry {
                    object_id: id,
                    created: true,
                })
            })
        },
    )?;

    // -----------------------------------------------------------------------
    // object.transfer(handle i32, owner_kind i32,
    //                 owner_payload_ptr i32, owner_payload_len i32) -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "transfer",
        |mut caller: Caller<'_, ChainStoreData>,
         handle: i32,
         owner_kind: i32,
         owner_payload_ptr: i32,
         owner_payload_len: i32|
         -> i32 {
            if consume_fuel(&mut caller, 500).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            if owner_payload_len < 0 {
                return HostError::Invalid("negative owner_payload_len".into()).as_wasm_code();
            }
            let new_owner = match owner_kind as u8 {
                OWNER_KIND_ADDRESS | OWNER_KIND_OBJECT => {
                    if owner_payload_len != 32 {
                        return HostError::Invalid("Address/Object owner needs 32 bytes".into())
                            .as_wasm_code();
                    }
                    let mem = match get_chain_memory(&mut caller) {
                        Some(m) => m,
                        None => {
                            return HostError::Invalid("no memory".into()).as_wasm_code();
                        }
                    };
                    let bytes = match read_chain_bytes(
                        &mem,
                        &mut caller,
                        owner_payload_ptr,
                        owner_payload_len,
                    ) {
                        Ok(b) => b,
                        Err(c) => return c,
                    };
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    if owner_kind as u8 == OWNER_KIND_ADDRESS {
                        Owner::Address(arr)
                    } else {
                        Owner::Object(ObjectId(arr))
                    }
                }
                OWNER_KIND_SHARED => Owner::Shared,
                OWNER_KIND_IMMUTABLE => Owner::Immutable,
                other => {
                    return HostError::Invalid(format!("bad owner_kind {other}")).as_wasm_code();
                }
            };

            let id = match with_ptb_ctx_lookup_id(&caller, handle) {
                Ok(id) => id,
                Err(code) => return code,
            };
            let caller_petal = caller.data().petal_hash;

            with_ptb_ctx(&caller, |ctx| {
                match ctx.borrow_table.get_mut(&id) {
                    Some(row) => {
                        match can_move_or_reown(row, caller_petal) {
                            Ok(true) => {}
                            Ok(false) => {
                                return HostError::Denied(
                                    "object.transfer without defining or consume authority".into(),
                                )
                                .as_wasm_code();
                            }
                            Err(code) => return code,
                        }
                        // Capture prior owner before overwrite: the
                        // chain-node's `rebuild_ownership_rows` needs
                        // both keys to keep the OwnershipIndex
                        // symmetric (spec §16.3).
                        let old_owner = row.owner.clone();
                        row.owner = new_owner.clone();
                        ctx.ownership_changes.push((id, old_owner, new_owner));
                        ctx.borrow_table.mark_consumed(&id);
                        ctx.retire_handles_for(&id);
                        0
                    }
                    None => HostError::NotFound("row vanished".into()).as_wasm_code(),
                }
            })
        },
    )?;

    // -----------------------------------------------------------------------
    // object.share(handle i32) -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "share",
        |mut caller: Caller<'_, ChainStoreData>, handle: i32| -> i32 {
            if consume_fuel(&mut caller, 500).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let id = match with_ptb_ctx_lookup_id(&caller, handle) {
                Ok(id) => id,
                Err(code) => return code,
            };
            let caller_petal = caller.data().petal_hash;
            with_ptb_ctx(&caller, |ctx| match ctx.borrow_table.get_mut(&id) {
                Some(row) => {
                    match can_move_or_reown(row, caller_petal) {
                        Ok(true) => {}
                        Ok(false) => {
                            return HostError::Denied(
                                "object.share without defining or consume authority".into(),
                            )
                            .as_wasm_code();
                        }
                        Err(code) => return code,
                    }
                    let old_owner = row.owner.clone();
                    row.owner = Owner::Shared;
                    ctx.ownership_changes.push((id, old_owner, Owner::Shared));
                    ctx.borrow_table.mark_consumed(&id);
                    ctx.retire_handles_for(&id);
                    0
                }
                None => HostError::NotFound("row vanished".into()).as_wasm_code(),
            })
        },
    )?;

    // -----------------------------------------------------------------------
    // object.freeze(handle i32) -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "freeze",
        |mut caller: Caller<'_, ChainStoreData>, handle: i32| -> i32 {
            if consume_fuel(&mut caller, 500).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let id = match with_ptb_ctx_lookup_id(&caller, handle) {
                Ok(id) => id,
                Err(code) => return code,
            };
            let caller_petal = caller.data().petal_hash;
            with_ptb_ctx(&caller, |ctx| match ctx.borrow_table.get_mut(&id) {
                Some(row) => {
                    match can_move_or_reown(row, caller_petal) {
                        Ok(true) => {}
                        Ok(false) => {
                            return HostError::Denied(
                                "object.freeze without defining or consume authority".into(),
                            )
                            .as_wasm_code();
                        }
                        Err(code) => return code,
                    }
                    let old_owner = row.owner.clone();
                    row.owner = Owner::Immutable;
                    ctx.ownership_changes
                        .push((id, old_owner, Owner::Immutable));
                    ctx.borrow_table.mark_consumed(&id);
                    ctx.retire_handles_for(&id);
                    0
                }
                None => HostError::NotFound("row vanished".into()).as_wasm_code(),
            })
        },
    )?;

    // -----------------------------------------------------------------------
    // object.delete(handle i32) -> i32
    //
    // Spec §16.2: "only the type-defining petal can call".
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "delete",
        |mut caller: Caller<'_, ChainStoreData>, handle: i32| -> i32 {
            if consume_fuel(&mut caller, 500).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let id = match with_ptb_ctx_lookup_id(&caller, handle) {
                Ok(id) => id,
                Err(code) => return code,
            };
            let caller_petal = caller.data().petal_hash;
            with_ptb_ctx(&caller, |ctx| {
                // Capture both the defining-petal hash (for the
                // §16.2 access-control check) and the row's prior
                // owner (so the chain-node's
                // `rebuild_ownership_rows` can drop `id` from the
                // old owner's row — spec §16.3 symmetric rebuild).
                let (defining_hash, old_owner, row_mode) = match ctx.borrow_table.get(&id) {
                    Some(row) => {
                        let defining = match &row.type_tag {
                            TypeTag::Concrete { petal_hash, .. } => *petal_hash,
                            _ => {
                                return HostError::Invalid(
                                    "delete requires Concrete type_tag".into(),
                                )
                                .as_wasm_code();
                            }
                        };
                        (defining, row.owner.clone(), row.access_mode)
                    }
                    None => {
                        return HostError::NotFound("row vanished".into()).as_wasm_code();
                    }
                };
                // Authorization to delete (spec §16.2, refined for linear
                // moves): the type-defining petal may always delete its
                // own objects. In addition, an object handed to this petal
                // as a `Consume`-mode argument carries an explicit linear
                // "move" authorization from the PTB — the validator
                // (`check_access_mode`) already proved the first signer
                // owns it (or it is `Shared`), so the PTB author chose to
                // surrender it. This is what lets the erased-coin DEX
                // consume `Coin<Erased>` deposits minted by the fungible
                // petal. A petal still cannot delete an object it merely
                // borrowed `Mutable`/`ReadOnly` unless it defines the type.
                let defines = defining_hash == caller_petal.0;
                let consumed = row_mode == AccessMode::Consume;
                if !defines && !consumed {
                    return HostError::Denied("object.delete from non-defining petal".into())
                        .as_wasm_code();
                }
                ctx.object_deletes.push((id, old_owner));
                ctx.borrow_table.drop_row(&id);
                ctx.retire_handles_for(&id);
                0
            })
        },
    )?;

    // -----------------------------------------------------------------------
    // object.id(handle i32, out_ptr i32) -> i32
    //
    // Resolve a borrow handle back to the stable 32-byte `ObjectId` it
    // points at, writing the id into guest memory at `out_ptr`. Returns
    // `0` on success (the petal knows the width is always 32) or a
    // negative `HostError` code. The return path uses this so a
    // Coin/Capability output crosses a command boundary as its on-chain
    // id (which `exec_transfer` / `exec_split_coins` decode from a
    // `Use(...)` slot) rather than the ephemeral borrow handle.
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "object",
        "id",
        |mut caller: Caller<'_, ChainStoreData>, handle: i32, out_ptr: i32| -> i32 {
            if consume_fuel(&mut caller, 100).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let id = match with_ptb_ctx_lookup_id(&caller, handle) {
                Ok(id) => id,
                Err(code) => return code,
            };
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            if let Err(c) = write_chain_bytes(&mem, &mut caller, out_ptr, &id.0) {
                return c;
            }
            0
        },
    )?;

    // -----------------------------------------------------------------------
    // cap.check(cap_handle i32, type_tag_ptr i32, type_tag_len i32) -> i32
    //
    // Returns 1 iff the borrowed object's type tag matches the supplied
    // tag bytes verbatim; 0 otherwise. Abilities are checked at type
    // declaration time, not here (the cap marker abilities live on the
    // type itself); see spec §5.
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "cap",
        "check",
        |mut caller: Caller<'_, ChainStoreData>,
         cap_handle: i32,
         type_tag_ptr: i32,
         type_tag_len: i32|
         -> i32 {
            if consume_fuel(&mut caller, 100).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            if type_tag_len < 0 {
                return HostError::Invalid("negative type_tag_len".into()).as_wasm_code();
            }
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            let want_bytes = match read_chain_bytes(&mem, &mut caller, type_tag_ptr, type_tag_len) {
                Ok(b) => b,
                Err(c) => return c,
            };

            let id = match with_ptb_ctx_lookup_id(&caller, cap_handle) {
                Ok(id) => id,
                Err(code) => return code,
            };

            with_ptb_ctx(&caller, |ctx| match ctx.borrow_table.get(&id) {
                Some(row) => match row.type_tag.encode_canonical() {
                    Ok(have) => {
                        if have == want_bytes {
                            1
                        } else {
                            0
                        }
                    }
                    Err(_) => HostError::Backend("encode type_tag".into()).as_wasm_code(),
                },
                None => HostError::NotFound("cap row vanished".into()).as_wasm_code(),
            })
        },
    )?;

    // -----------------------------------------------------------------------
    // signer.index() -> i32
    //
    // Returns the 0-based index of the current command's primary signer
    // (today: the first signer in `PtbHostCtx::signers`), or -1 if none.
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "signer",
        "index",
        |mut caller: Caller<'_, ChainStoreData>| -> i32 {
            if consume_fuel(&mut caller, 50).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            with_ptb_ctx(&caller, |ctx| if ctx.signers.is_empty() { -1 } else { 0 })
        },
    )?;

    // -----------------------------------------------------------------------
    // signer.address(idx i32, out_ptr i32) -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "signer",
        "address",
        |mut caller: Caller<'_, ChainStoreData>, idx: i32, out_ptr: i32| -> i32 {
            if consume_fuel(&mut caller, 50).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            if idx < 0 {
                return HostError::Invalid("negative signer idx".into()).as_wasm_code();
            }
            let addr = match caller.data().ptb_ctx.clone() {
                Some(arc) => match arc.lock() {
                    Ok(ctx) => match ctx.signers.get(idx as usize) {
                        Some(a) => *a,
                        None => {
                            return HostError::NotFound("signer idx oob".into()).as_wasm_code();
                        }
                    },
                    Err(_) => {
                        return HostError::Backend("ptb ctx poisoned".into()).as_wasm_code();
                    }
                },
                None => {
                    return HostError::Backend("no ptb ctx".into()).as_wasm_code();
                }
            };
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            if let Err(c) = write_chain_bytes(&mem, &mut caller, out_ptr, &addr) {
                return c;
            }
            0
        },
    )?;

    // -----------------------------------------------------------------------
    // ptb.command_output(cmd_idx i32, ret_idx i32,
    //                    out_ptr i32, out_cap i32) -> len i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "ptb",
        "command_output",
        |mut caller: Caller<'_, ChainStoreData>,
         cmd_idx: i32,
         ret_idx: i32,
         out_ptr: i32,
         out_cap: i32|
         -> i32 {
            if cmd_idx < 0 || ret_idx < 0 || out_cap < 0 {
                return HostError::Invalid("negative index/cap".into()).as_wasm_code();
            }

            let bytes = match caller.data().ptb_ctx.clone() {
                Some(arc) => match arc.lock() {
                    Ok(ctx) => match ctx
                        .command_outputs
                        .get(cmd_idx as usize)
                        .and_then(|cmd| cmd.get(ret_idx as usize))
                    {
                        Some(b) => b.clone(),
                        None => {
                            return HostError::NotFound("no such command output".into())
                                .as_wasm_code();
                        }
                    },
                    Err(_) => {
                        return HostError::Backend("ptb ctx poisoned".into()).as_wasm_code();
                    }
                },
                None => return HostError::Backend("no ptb ctx".into()).as_wasm_code(),
            };

            let base_fuel = 100u64.saturating_add(4u64.saturating_mul(bytes.len() as u64));
            if consume_fuel(&mut caller, base_fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }

            if (bytes.len() as i64) > (out_cap as i64) {
                if bytes.len() > i32::MAX as usize {
                    return HostError::Invalid("output exceeds i32::MAX".into()).as_wasm_code();
                }
                return -(bytes.len() as i32);
            }
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            if let Err(c) = write_chain_bytes(&mem, &mut caller, out_ptr, &bytes) {
                return c;
            }
            bytes.len() as i32
        },
    )?;

    // -----------------------------------------------------------------------
    // log.emit(topic_ptr i32, topic_len i32, data_ptr i32, data_len i32) -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "log",
        "emit",
        |mut caller: Caller<'_, ChainStoreData>,
         topic_ptr: i32,
         topic_len: i32,
         data_ptr: i32,
         data_len: i32|
         -> i32 {
            if topic_len < 0 || data_len < 0 {
                return HostError::Invalid("negative len".into()).as_wasm_code();
            }
            let base_fuel = 200u64.saturating_add(
                4u64.saturating_mul((topic_len as u64).saturating_add(data_len as u64)),
            );
            if consume_fuel(&mut caller, base_fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            let topic = match read_chain_bytes(&mem, &mut caller, topic_ptr, topic_len) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let data = match read_chain_bytes(&mem, &mut caller, data_ptr, data_len) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let petal = caller.data().petal_hash;
            with_ptb_ctx(&caller, |ctx| {
                ctx.logs.push(PtbLogEntry { petal, topic, data });
                0
            })
        },
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers for the §16.2 import bodies
// ---------------------------------------------------------------------------

/// Resolve a wasm-side handle to its `ObjectId` via the per-PTB ctx.
/// Returns either the id or the negative wasm error code the import
/// should propagate.
fn with_ptb_ctx_lookup_id(
    caller: &Caller<'_, ChainStoreData>,
    handle: i32,
) -> Result<ObjectId, i32> {
    match caller.data().ptb_ctx.clone() {
        Some(arc) => match arc.lock() {
            Ok(ctx) => ctx
                .id_for_handle(handle)
                .ok_or_else(|| HostError::Invalid("bad handle".into()).as_wasm_code()),
            Err(_) => Err(HostError::Backend("ptb ctx poisoned".into()).as_wasm_code()),
        },
        None => Err(HostError::Backend("no ptb ctx".into()).as_wasm_code()),
    }
}

/// Pull the current payload bytes for `id` out of the borrow table.
fn with_ptb_ctx_payload(
    caller: &Caller<'_, ChainStoreData>,
    id: &ObjectId,
) -> Result<Vec<u8>, i32> {
    match caller.data().ptb_ctx.clone() {
        Some(arc) => match arc.lock() {
            Ok(ctx) => match ctx.borrow_table.get(id) {
                Some(row) => Ok(row.payload_bytes.clone()),
                None => Err(HostError::NotFound("object not borrowed".into()).as_wasm_code()),
            },
            Err(_) => Err(HostError::Backend("ptb ctx poisoned".into()).as_wasm_code()),
        },
        None => Err(HostError::Backend("no ptb ctx".into()).as_wasm_code()),
    }
}

/// Derive a deterministic transient `ObjectId` for an `object.create`
/// call. The recipe (BLAKE3 of PTB digest + caller petal hash +
/// ptb-scope counter + type-tag bytes + payload bytes) makes the id
/// reproducible across validator replays of the same PTB while avoiding
/// collisions between different PTBs that create identical objects.
fn derive_create_id(
    caller: &Caller<'_, ChainStoreData>,
    type_tag_bytes: &[u8],
    payload: &[u8],
) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.object.create.v1\0");
    let (ptb_digest, n) = caller
        .data()
        .ptb_ctx
        .as_ref()
        .and_then(|arc| {
            arc.lock()
                .ok()
                .map(|c| (c.ptb_digest, c.created_objects.len() as u64))
        })
        .unwrap_or(([0u8; 32], 0));
    hasher.update(&ptb_digest);
    hasher.update(&caller.data().petal_hash.0);
    // Mix in the PTB ctx's "created so far" length for per-call
    // uniqueness within a single PTB.
    hasher.update(&n.to_be_bytes());
    hasher.update(type_tag_bytes);
    hasher.update(payload);
    let h = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(h.as_bytes());
    ObjectId(arr)
}

// ---------------------------------------------------------------------------
// Sub-call error type (carries snapshot back on failure for revert semantics)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
enum SubCallError {
    Reverted {
        snapshot: Box<StateSnapshot>,
        reason: Option<Vec<u8>>,
        fuel_used: u64,
    },
    Trapped {
        snapshot: Box<StateSnapshot>,
        error: Option<String>,
        fuel_used: u64,
    },
}

// ---------------------------------------------------------------------------
// Resource limiter (review 2026-05-19 #7)
// ---------------------------------------------------------------------------

/// Per-instance cap on linear-memory growth for chain-mode petals.
///
/// Static validation in `validate_chain_wasm` rejects modules whose declared
/// memory min/max pages exceed 256 (16 MiB). But a module can pass static
/// validation with `(memory 1)` and then issue `memory.grow` at runtime to
/// blow past that cap. The `ResourceLimiter` enforces the same 256-page
/// (16 MiB) bound at runtime, returning `Ok(false)` from `memory_growing`
/// when the requested size would exceed it. wasmtime then raises an
/// "OutOfMemory" trap, which propagates up as a `SubCallError::Trapped`
/// and triggers the parent's revert-on-error path (see review #6).
const CHAIN_MAX_MEMORY_PAGES: usize = 256;

/// Per-instance cap on indirect-call table growth for chain-mode petals.
///
/// Tables aren't currently a major attack vector (modules can't reflectively
/// inject entries), but bounding growth keeps memory use predictable.
const CHAIN_MAX_TABLE_ELEMENTS: usize = 10_000;

/// Per-instance cap on instance/memory/table counts. The chain-mode dispatcher
/// creates exactly one instance and one memory per `dispatch_chain_call_sync`
/// call, so these limits are tight.
const CHAIN_MAX_INSTANCES: usize = 1;
const CHAIN_MAX_TABLES: usize = 16;
const CHAIN_MAX_MEMORIES: usize = 1;

struct ChainLimiter;

impl wasmtime::ResourceLimiter for ChainLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // `desired` is in bytes; convert to pages.
        let desired_pages = desired.div_ceil(64 * 1024);
        Ok(desired_pages <= CHAIN_MAX_MEMORY_PAGES)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= CHAIN_MAX_TABLE_ELEMENTS)
    }

    fn instances(&self) -> usize {
        CHAIN_MAX_INSTANCES
    }
    fn tables(&self) -> usize {
        CHAIN_MAX_TABLES
    }
    fn memories(&self) -> usize {
        CHAIN_MAX_MEMORIES
    }
}

// ---------------------------------------------------------------------------
// Synchronous chain call dispatch
// ---------------------------------------------------------------------------

/// Synchronously execute a chain petal call (or init). Returns `ChainCallOutput`
/// on success (explicit `petal.return` or normal function return), or
/// `SubCallError` on revert / trap.
fn dispatch_chain_call_sync(
    engine: &Engine,
    input: ChainCallInput,
    call_depth: u32,
) -> Result<ChainCallOutput, SubCallError> {
    let module = Module::new(engine, &input.wasm).map_err(|e| SubCallError::Trapped {
        snapshot: Box::new(bloom_chain_state::State::new().snapshot()),
        error: Some(format!("module load: {e}")),
        fuel_used: 0,
    })?;

    let petal_hash = blake3_tagged(tags::PETAL, &input.wasm);

    let chain_ctx = ChainCtx {
        snapshot: input.snapshot,
        contract_address: input.contract_address,
        msg_sender: input.msg_sender,
        msg_value: input.msg_value,
        calldata: input.calldata,
        block: input.block,
        return_data: None,
        revert_reason: None,
        logs: Vec::new(),
        call_depth,
    };

    let store_data = ChainStoreData {
        chain_ctx,
        petal_hash,
        ptb_ctx: input.ptb_ctx,
    };

    let mut store = Store::new(engine, store_data);
    store
        .set_fuel(input.fuel)
        .map_err(|e| SubCallError::Trapped {
            snapshot: Box::new(bloom_chain_state::State::new().snapshot()),
            error: Some(format!("set_fuel: {e}")),
            fuel_used: 0,
        })?;
    // Install the runtime ResourceLimiter so `memory.grow` past the static
    // validation cap (256 pages / 16 MiB) traps instead of succeeding
    // (review 2026-05-19 #7). Chain-mode only — host-mode petals use
    // `MemLimiter` in `vm.rs`.
    store.limiter(|_| {
        // Box-leak a small zero-sized limiter for this store. Same pattern
        // as the host-mode limiter; there is no per-store state to maintain.
        Box::leak(Box::new(ChainLimiter))
    });

    let mut linker = Linker::<ChainStoreData>::new(engine);
    link_chain_imports(&mut linker).map_err(|e| SubCallError::Trapped {
        snapshot: Box::new(bloom_chain_state::State::new().snapshot()),
        error: Some(format!("link imports: {e}")),
        fuel_used: 0,
    })?;

    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            let err_msg = format!("instantiate: {e}");
            // Instantiation may execute `start`/global-init code that burns
            // fuel, so capture the real `fuel_used` for the caller's meter.
            let fuel_used = input.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
            let snap = std::mem::replace(
                &mut store.data_mut().chain_ctx.snapshot,
                bloom_chain_state::State::new().snapshot(),
            );
            return Err(SubCallError::Trapped {
                snapshot: Box::new(snap),
                error: Some(err_msg),
                fuel_used,
            });
        }
    };

    let ChainEntry::Function(entry_name) = &input.entry;
    let entry_name: &str = entry_name;

    let func = match instance.get_typed_func::<(i32, i32), i32>(&mut store, entry_name) {
        Ok(f) => f,
        Err(e) => {
            let err_msg = format!("get_typed_func('{entry_name}'): {e}");
            let fuel_used = input.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
            let snap = std::mem::replace(
                &mut store.data_mut().chain_ctx.snapshot,
                bloom_chain_state::State::new().snapshot(),
            );
            return Err(SubCallError::Trapped {
                snapshot: Box::new(snap),
                error: Some(err_msg),
                fuel_used,
            });
        }
    };

    let calldata_len = store.data().chain_ctx.calldata.len() as i32;
    // Calldata is passed by length here; the petal reads it via msg.calldata.read.
    let call_result = func.call(&mut store, (0i32, calldata_len));

    let fuel_used = input.fuel.saturating_sub(store.get_fuel().unwrap_or(0));

    let return_data_opt = store.data().chain_ctx.return_data.clone();
    let revert_reason_opt = store.data().chain_ctx.revert_reason.clone();
    let logs = store.data().chain_ctx.logs.clone();

    // Extract snapshot.
    let snapshot = std::mem::replace(
        &mut store.data_mut().chain_ctx.snapshot,
        bloom_chain_state::State::new().snapshot(),
    );

    match call_result {
        Ok(_ret) => {
            // Normal return (no trap). Treat as success.
            Ok(ChainCallOutput {
                return_data: return_data_opt,
                revert_reason: None,
                fuel_used,
                logs,
                snapshot,
            })
        }
        Err(e) => {
            // Trap. Check if it was triggered by petal.return or petal.revert.
            //
            // `fuel_used` is carried back on EVERY revert / trap variant
            // (DoS-hardening 2026-05-19): the caller must be billed the
            // real work the child performed, identical to the success
            // path. Otherwise an adversary can repeatedly call a contract
            // that burns fuel and reverts, costing validators real work
            // without paying for it.
            if revert_reason_opt.is_some() {
                return Err(SubCallError::Reverted {
                    snapshot: Box::new(snapshot),
                    reason: revert_reason_opt,
                    fuel_used,
                });
            }
            if return_data_opt.is_some() {
                // petal.return raised a trap — treat as clean successful exit.
                return Ok(ChainCallOutput {
                    return_data: return_data_opt,
                    revert_reason: None,
                    fuel_used,
                    logs,
                    snapshot,
                });
            }
            // Genuine trap or out-of-fuel. Preserve the wasmtime trap detail
            // (e.g. "out of fuel", "unreachable", "memory access out of bounds",
            // or a specific host-import error) so the caller can diagnose.
            Err(SubCallError::Trapped {
                snapshot: Box::new(snapshot),
                error: Some(format!("{e:?}")),
                fuel_used,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point on PetalVm
// ---------------------------------------------------------------------------

impl PetalVm {
    /// Validate wasm bytes for deploy-time admission as a chain-mode petal.
    pub fn validate_for_chain(bytes: &[u8]) -> Result<(), PetalError> {
        validate_chain_wasm(bytes)
    }

    /// Run a petal in chain-mode (synchronous, deterministic).
    ///
    /// Revert / trap reconciliation (review 2026-05-19 #12):
    /// - Success → `Ok(ChainCallOutput { revert_reason: None, .. })`.
    /// - `petal.revert` (or any sub-call surfacing a revert at top-level) →
    ///   `Ok(ChainCallOutput { revert_reason: Some(bytes), .. })`. The
    ///   embedded `snapshot` carries the mutated writes — the executor is
    ///   responsible for *discarding* it (the natural revert: just drop
    ///   the snapshot instead of `commit()`-ing it).
    /// - Genuine wasm trap / out-of-fuel / engine error →
    ///   `Err(PetalError::ChainCall(detail))`.
    ///
    /// This funnels both `petal_executor.rs` revert paths into one
    /// authoritative code path: the executor only needs to check
    /// `out.revert_reason.is_some()` for the revert case; the trap case
    /// is the `Err` arm.
    pub fn run_chain_call(input: ChainCallInput) -> Result<ChainCallOutput, PetalError> {
        let engine = chain_engine()?;
        match dispatch_chain_call_sync(engine, input, 0) {
            Ok(out) => Ok(out),
            Err(SubCallError::Reverted {
                snapshot,
                reason,
                fuel_used,
            }) => {
                // Surface revert as a successful `ChainCallOutput` carrying
                // the reason. The snapshot it travels with is the mutated
                // child snapshot — the executor will not commit it.
                //
                // CRITICAL (DoS-hardening 2026-05-19): `fuel_used` is the
                // real fuel the child burned before reverting — NOT zero.
                // A reverting contract must not look "free" to the caller;
                // otherwise an adversary can call a fuel-burning + reverting
                // contract repeatedly, costing validators real work without
                // paying for it.
                Ok(ChainCallOutput {
                    return_data: None,
                    revert_reason: Some(reason.unwrap_or_default()),
                    fuel_used,
                    logs: Vec::new(),
                    snapshot: *snapshot,
                })
            }
            Err(SubCallError::Trapped {
                error, fuel_used, ..
            }) => Err(PetalError::ChainCallTrap {
                detail: error
                    .map(|s| format!("trapped: {s}"))
                    .unwrap_or_else(|| "trapped".into()),
                fuel_used,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: §16.2 host imports
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ptb_host_import_tests {
    //! Integration-level tests for the spec §16.2 host imports.
    //!
    //! Each test builds a tiny WAT module that imports one §16.2 symbol,
    //! wires a `ChainCallInput` with `Some(Arc<Mutex<PtbHostCtx>>)`, and
    //! asserts both the wasm-visible return value and the resulting
    //! mutations to the shared `PtbHostCtx`.

    use super::*;
    use bloom_chain_state::State;
    use bloom_chain_types::Address;
    use bloom_objects::{AccessMode, Object, ObjectId, Owner, TypeTag};
    use bloom_script::host_ctx::PtbHostCtx;
    use std::sync::{Arc, Mutex};

    fn parse(src: &str) -> Vec<u8> {
        wat::parse_str(src).expect("valid WAT")
    }

    fn run_with(wasm: Vec<u8>, ctx: Arc<Mutex<PtbHostCtx>>, petal_hash: Hash32) -> ChainCallOutput {
        run_with_state(wasm, ctx, petal_hash, State::new())
    }

    fn run_with_state(
        wasm: Vec<u8>,
        ctx: Arc<Mutex<PtbHostCtx>>,
        petal_hash: Hash32,
        state: State,
    ) -> ChainCallOutput {
        let input = ChainCallInput {
            wasm,
            entry: ChainEntry::Function("call".into()),
            contract_address: Address([0x01; 32]),
            msg_sender: Address([0x02; 32]),
            msg_value: 0,
            calldata: Vec::new(),
            block: BlockCtx {
                number: 1,
                timestamp_ms: 0,
                prevhash: Hash32([0; 32]),
            },
            fuel: 10_000_000,
            snapshot: state.snapshot(),
            ptb_ctx: Some(ctx),
        };
        // Manually override the inferred petal_hash because the test
        // closures need to set `current_petal_hash` to control the
        // type-defining-petal check inside `object.create`.
        let _ = petal_hash; // documented; passed in for symmetry
        PetalVm::run_chain_call(input).expect("ok")
    }

    fn make_object(id_byte: u8, payload: Vec<u8>, owner: Owner, petal_hash: [u8; 32]) -> Object {
        Object {
            id: ObjectId([id_byte; 32]),
            type_tag: TypeTag::Concrete {
                petal_hash,
                type_name: "T".into(),
                type_args: vec![],
            },
            owner,
            version: 0,
            payload,
        }
    }

    // -----------------------------------------------------------------------
    // signer.address(0, out_ptr) writes the first signer pubkey.
    // -----------------------------------------------------------------------

    const SIGNER_ADDRESS_FETCH: &str = r#"
(module
  (import "signer" "address" (func $sa (param i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "call") (param i32 i32) (result i32)
    ;; signer.address(0, 0) — writes 32 bytes starting at offset 0.
    (drop (call $sa (i32.const 0) (i32.const 0)))
    (call $ret (i32.const 0) (i32.const 32))
    i32.const 0)
)
"#;

    #[test]
    fn signer_address_writes_first_signer() {
        let mut ctx = PtbHostCtx::new();
        ctx.signers.push([0x7Au8; 32]);
        ctx.signers.push([0x99u8; 32]);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(parse(SIGNER_ADDRESS_FETCH), arc.clone(), Hash32([0; 32]));
        assert_eq!(out.return_data, Some(vec![0x7Au8; 32]));
    }

    // -----------------------------------------------------------------------
    // signer.index returns 0 when at least one signer is present, -1 otherwise.
    // -----------------------------------------------------------------------

    const SIGNER_INDEX: &str = r#"
(module
  (import "signer" "index" (func $si (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "call") (param i32 i32) (result i32)
    (i32.store (i32.const 0) (call $si))
    (call $ret (i32.const 0) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn signer_index_returns_zero_when_signer_present() {
        let mut ctx = PtbHostCtx::new();
        ctx.signers.push([0u8; 32]);
        let out = run_with(
            parse(SIGNER_INDEX),
            Arc::new(Mutex::new(ctx)),
            Hash32([0; 32]),
        );
        let bytes = out.return_data.unwrap();
        assert_eq!(i32::from_le_bytes(bytes.try_into().unwrap()), 0);
    }

    #[test]
    fn signer_index_returns_minus_one_when_empty() {
        let ctx = PtbHostCtx::new();
        let out = run_with(
            parse(SIGNER_INDEX),
            Arc::new(Mutex::new(ctx)),
            Hash32([0; 32]),
        );
        let bytes = out.return_data.unwrap();
        assert_eq!(i32::from_le_bytes(bytes.try_into().unwrap()), -1);
    }

    // -----------------------------------------------------------------------
    // log.emit appends a LogEntry to PtbHostCtx::logs.
    // -----------------------------------------------------------------------

    const LOG_EMIT: &str = r#"
(module
  (import "log" "emit" (func $emit (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; topic at offset 0 (4 bytes), data at offset 4 (8 bytes)
  (data (i32.const 0) "\11\22\33\44\aa\bb\cc\dd\ee\ff\00\01")
  (func (export "call") (param i32 i32) (result i32)
    (drop (call $emit (i32.const 0) (i32.const 4) (i32.const 4) (i32.const 8)))
    i32.const 0)
)
"#;

    #[test]
    fn log_emit_records_entry() {
        let arc = Arc::new(Mutex::new(PtbHostCtx::new()));
        let _ = run_with(parse(LOG_EMIT), arc.clone(), Hash32([0; 32]));
        let logs = &arc.lock().unwrap().logs;
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].topic, vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(
            logs[0].data,
            vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01]
        );
    }

    // -----------------------------------------------------------------------
    // object.borrow: handle is minted when a row is pre-loaded; coalesces
    // on second call.
    // -----------------------------------------------------------------------

    const OBJECT_BORROW_TWICE: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; 32-byte id at offset 0
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (func (export "call") (param i32 i32) (result i32)
    (local $h1 i32) (local $h2 i32)
    (local.set $h1 (call $bo (i32.const 0) (i32.const 1)))
    (local.set $h2 (call $bo (i32.const 0) (i32.const 1)))
    (i32.store (i32.const 64) (local.get $h1))
    (i32.store (i32.const 68) (local.get $h2))
    (call $ret (i32.const 64) (i32.const 8))
    i32.const 0)
)
"#;

    #[test]
    fn object_borrow_coalesces_repeat_calls() {
        let petal = Hash32([0xAA; 32]);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1, 2, 3], Owner::Address([0; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));

        let out = run_with(parse(OBJECT_BORROW_TWICE), arc.clone(), petal);
        let bytes = out.return_data.unwrap();
        assert_eq!(bytes.len(), 8);
        let h1 = i32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let h2 = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert!(h1 > 0, "handle 1 must be positive");
        assert_eq!(h1, h2, "repeat borrow of same id must return same handle");
    }

    // -----------------------------------------------------------------------
    // object.read returns payload bytes into the supplied buffer.
    // -----------------------------------------------------------------------

    const OBJECT_BORROW_READ: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "object" "read"   (func $rd (param i32 i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $n i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    ;; read into offset 64, cap 64
    (local.set $n (call $rd (local.get $h) (i32.const 64) (i32.const 64)))
    (call $ret (i32.const 64) (local.get $n))
    i32.const 0)
)
"#;

    #[test]
    fn object_read_returns_payload_bytes() {
        let petal = Hash32([0xCD; 32]);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(
            0x07,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            Owner::Address([0; 32]),
            petal.0,
        );
        ctx.borrow_table.load_persistent(&obj, AccessMode::ReadOnly);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(parse(OBJECT_BORROW_READ), arc.clone(), petal);
        assert_eq!(out.return_data, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    // -----------------------------------------------------------------------
    // object.mutate flips the row's payload + marks dirty.
    // -----------------------------------------------------------------------

    const OBJECT_BORROW_MUTATE: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "object" "mutate" (func $mu (param i32 i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (data (i32.const 64) "\f0\f1\f2")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (local.set $r (call $mu (local.get $h) (i32.const 64) (i32.const 3)))
    (i32.store (i32.const 96) (local.get $r))
    (call $ret (i32.const 96) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn object_mutate_replaces_payload() {
        let wasm = parse(OBJECT_BORROW_MUTATE);
        let petal = blake3_tagged(tags::PETAL, &wasm);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![0; 3], Owner::Address([0; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(wasm, arc.clone(), petal);
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, 0, "object.mutate must succeed");
        let guard = arc.lock().unwrap();
        let row = guard.borrow_table.get(&ObjectId([0x07; 32])).unwrap();
        assert_eq!(row.payload_bytes, vec![0xf0, 0xf1, 0xf2]);
        assert!(row.dirty);
    }

    // -----------------------------------------------------------------------
    // object.mutate on a ReadOnly row is denied.
    // -----------------------------------------------------------------------

    #[test]
    fn object_mutate_on_readonly_is_denied() {
        let petal = Hash32([0x22; 32]);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![0; 3], Owner::Address([0; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::ReadOnly);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(parse(OBJECT_BORROW_MUTATE), arc.clone(), petal);
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, -2, "Denied wasm error");
    }

    // -----------------------------------------------------------------------
    // object.transfer changes owner and records ownership_changes.
    // -----------------------------------------------------------------------

    const OBJECT_TRANSFER: &str = r#"
(module
  (import "object" "borrow"   (func $bo (param i32 i32) (result i32)))
  (import "object" "transfer" (func $tr (param i32 i32 i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  ;; object id at offset 0
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  ;; new owner address at offset 32 (Address kind = 0, 32 bytes)
  (data (i32.const 32) "\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    ;; transfer(h, kind=Address(0), payload_ptr=32, payload_len=32)
    (local.set $r (call $tr (local.get $h) (i32.const 0) (i32.const 32) (i32.const 32)))
    (i32.store (i32.const 96) (local.get $r))
    (call $ret (i32.const 96) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn object_transfer_records_ownership_change() {
        let wasm = parse(OBJECT_TRANSFER);
        let petal = blake3_tagged(tags::PETAL, &wasm);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(wasm, arc.clone(), petal);
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, 0);
        let guard = arc.lock().unwrap();
        assert_eq!(guard.ownership_changes.len(), 1);
        let (id, old, new) = &guard.ownership_changes[0];
        assert_eq!(*id, ObjectId([0x07; 32]));
        assert_eq!(*old, Owner::Address([0xaa; 32]));
        assert_eq!(*new, Owner::Address([0xbb; 32]));
    }

    fn run_reuse_after_terminal_op(wat: &str, access_mode: AccessMode) -> i32 {
        let wasm = parse(wat);
        let petal = blake3_tagged(tags::PETAL, &wasm);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, access_mode);
        let out = run_with(wasm, Arc::new(Mutex::new(ctx)), petal);
        i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap())
    }

    const OBJECT_TRANSFER_THEN_ID: &str = r#"
(module
  (import "object" "borrow"   (func $bo (param i32 i32) (result i32)))
  (import "object" "transfer" (func $tr (param i32 i32 i32 i32) (result i32)))
  (import "object" "id"       (func $id (param i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (data (i32.const 32) "\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb\bb")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (drop (call $tr (local.get $h) (i32.const 0) (i32.const 32) (i32.const 32)))
    (local.set $r (call $id (local.get $h) (i32.const 96)))
    (i32.store (i32.const 160) (local.get $r))
    (call $ret (i32.const 160) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn transferred_handle_cannot_be_reused() {
        assert_eq!(
            run_reuse_after_terminal_op(OBJECT_TRANSFER_THEN_ID, AccessMode::Mutable),
            -3
        );
    }

    // -----------------------------------------------------------------------
    // object.share switches owner to Owner::Shared.
    // -----------------------------------------------------------------------

    const OBJECT_SHARE: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "object" "share"  (func $sh (param i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (local.set $r (call $sh (local.get $h)))
    (i32.store (i32.const 64) (local.get $r))
    (call $ret (i32.const 64) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn object_share_sets_shared_owner() {
        let wasm = parse(OBJECT_SHARE);
        let petal = blake3_tagged(tags::PETAL, &wasm);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let _ = run_with(wasm, arc.clone(), petal);
        let guard = arc.lock().unwrap();
        assert_eq!(
            guard.ownership_changes.last().map(|c| c.2.clone()),
            Some(Owner::Shared)
        );
        assert_eq!(
            guard.ownership_changes.last().map(|c| c.1.clone()),
            Some(Owner::Address([0xaa; 32]))
        );
    }

    const OBJECT_SHARE_THEN_ID: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "object" "share"  (func $sh (param i32) (result i32)))
  (import "object" "id"     (func $id (param i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (drop (call $sh (local.get $h)))
    (local.set $r (call $id (local.get $h) (i32.const 64)))
    (i32.store (i32.const 128) (local.get $r))
    (call $ret (i32.const 128) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn shared_handle_cannot_be_reused() {
        assert_eq!(
            run_reuse_after_terminal_op(OBJECT_SHARE_THEN_ID, AccessMode::Mutable),
            -3
        );
    }

    // -----------------------------------------------------------------------
    // object.freeze switches owner to Owner::Immutable.
    // -----------------------------------------------------------------------

    const OBJECT_FREEZE: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "object" "freeze" (func $fz (param i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (local.set $r (call $fz (local.get $h)))
    (i32.store (i32.const 64) (local.get $r))
    (call $ret (i32.const 64) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn object_freeze_sets_immutable_owner() {
        let wasm = parse(OBJECT_FREEZE);
        let petal = blake3_tagged(tags::PETAL, &wasm);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let _ = run_with(wasm, arc.clone(), petal);
        let guard = arc.lock().unwrap();
        assert_eq!(
            guard.ownership_changes.last().map(|c| c.2.clone()),
            Some(Owner::Immutable)
        );
        assert_eq!(
            guard.ownership_changes.last().map(|c| c.1.clone()),
            Some(Owner::Address([0xaa; 32]))
        );
    }

    const OBJECT_FREEZE_THEN_ID: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "object" "freeze" (func $fz (param i32) (result i32)))
  (import "object" "id"     (func $id (param i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (drop (call $fz (local.get $h)))
    (local.set $r (call $id (local.get $h) (i32.const 64)))
    (i32.store (i32.const 128) (local.get $r))
    (call $ret (i32.const 128) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn frozen_handle_cannot_be_reused() {
        assert_eq!(
            run_reuse_after_terminal_op(OBJECT_FREEZE_THEN_ID, AccessMode::Mutable),
            -3
        );
    }

    // -----------------------------------------------------------------------
    // object.delete by the defining petal removes the row.
    // -----------------------------------------------------------------------

    const OBJECT_DELETE: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "object" "delete" (func $dl (param i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (local.set $r (call $dl (local.get $h)))
    (i32.store (i32.const 64) (local.get $r))
    (call $ret (i32.const 64) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn object_delete_by_defining_petal_succeeds() {
        // The petal_hash of the executing wasm matches the type's
        // defining petal hash, so delete is permitted.
        let mut ctx = PtbHostCtx::new();
        // The wasm's content-addressed petal_hash is computed from the
        // bytes inside `dispatch_chain_call_sync`; we can't predict it
        // here, but we can stage the row with that same hash by reading
        // it back from `blake3_tagged(tags::PETAL, &wasm)`.
        let wasm = parse(OBJECT_DELETE);
        let computed = blake3_tagged(tags::PETAL, &wasm);
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), computed.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(wasm, arc.clone(), computed);
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, 0);
        let guard = arc.lock().unwrap();
        assert!(guard.borrow_table.get(&ObjectId([0x07; 32])).is_none());
        assert_eq!(
            guard.object_deletes,
            vec![(ObjectId([0x07; 32]), Owner::Address([0xaa; 32]))]
        );
    }

    #[test]
    fn object_delete_by_non_defining_petal_is_denied() {
        // Type's defining petal is a different hash → delete returns
        // `HostError::Denied` (-2).
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), [0xFF; 32]);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let wasm = parse(OBJECT_DELETE);
        let out = run_with(wasm, arc.clone(), Hash32([0; 32]));
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, -2);
    }

    const OBJECT_DELETE_THEN_ID: &str = r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "object" "delete" (func $dl (param i32) (result i32)))
  (import "object" "id"     (func $id (param i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (drop (call $dl (local.get $h)))
    (local.set $r (call $id (local.get $h) (i32.const 64)))
    (i32.store (i32.const 128) (local.get $r))
    (call $ret (i32.const 128) (i32.const 4))
    i32.const 0)
)
"#;

    #[test]
    fn deleted_handle_cannot_be_reused() {
        assert_eq!(
            run_reuse_after_terminal_op(OBJECT_DELETE_THEN_ID, AccessMode::Mutable),
            -3
        );
    }

    // -----------------------------------------------------------------------
    // cap.check returns 1 when the type tag matches.
    // -----------------------------------------------------------------------

    fn cap_check_wat(tag_bytes: &[u8]) -> String {
        // Build a WAT module that places the tag bytes at offset 32, then
        // calls cap.check(handle, 32, tag_len) and returns the result.
        // Object id at offset 0 (0x07 * 32).
        let mut tag_lit = String::new();
        for b in tag_bytes {
            tag_lit.push_str(&format!("\\{:02x}", b));
        }
        format!(
            r#"
(module
  (import "object" "borrow" (func $bo (param i32 i32) (result i32)))
  (import "cap" "check"     (func $cc (param i32 i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07\07")
  (data (i32.const 32) "{tag_lit}")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32) (local $r i32)
    (local.set $h (call $bo (i32.const 0) (i32.const 1)))
    (local.set $r (call $cc (local.get $h) (i32.const 32) (i32.const {len})))
    (i32.store (i32.const 200) (local.get $r))
    (call $ret (i32.const 200) (i32.const 4))
    i32.const 0)
)
"#,
            tag_lit = tag_lit,
            len = tag_bytes.len(),
        )
    }

    #[test]
    fn cap_check_returns_one_on_matching_type_tag() {
        let petal_hash = [0x99u8; 32];
        let type_tag = TypeTag::Concrete {
            petal_hash,
            type_name: "Cap".to_string(),
            type_args: vec![],
        };
        let want = type_tag.encode_canonical().unwrap();
        let obj = Object {
            id: ObjectId([0x07; 32]),
            type_tag: type_tag.clone(),
            owner: Owner::Address([0; 32]),
            version: 0,
            payload: vec![],
        };
        let mut ctx = PtbHostCtx::new();
        ctx.borrow_table.load_persistent(&obj, AccessMode::ReadOnly);
        let arc = Arc::new(Mutex::new(ctx));
        let wasm = parse(&cap_check_wat(&want));
        let out = run_with(wasm, arc.clone(), Hash32(petal_hash));
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, 1);
    }

    #[test]
    fn cap_check_returns_zero_on_mismatched_type_tag() {
        let petal_hash = [0x99u8; 32];
        let real_tag = TypeTag::Concrete {
            petal_hash,
            type_name: "Cap".into(),
            type_args: vec![],
        };
        let other_tag = TypeTag::Concrete {
            petal_hash,
            type_name: "Other".into(),
            type_args: vec![],
        };
        let want = other_tag.encode_canonical().unwrap();
        let obj = Object {
            id: ObjectId([0x07; 32]),
            type_tag: real_tag,
            owner: Owner::Address([0; 32]),
            version: 0,
            payload: vec![],
        };
        let mut ctx = PtbHostCtx::new();
        ctx.borrow_table.load_persistent(&obj, AccessMode::ReadOnly);
        let arc = Arc::new(Mutex::new(ctx));
        let wasm = parse(&cap_check_wat(&want));
        let out = run_with(wasm, arc.clone(), Hash32(petal_hash));
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, 0);
    }

    // -----------------------------------------------------------------------
    // ptb.command_output reads completed-command bytes back into wasm.
    // -----------------------------------------------------------------------

    const PTB_CMD_OUTPUT: &str = r#"
(module
  (import "ptb" "command_output"
    (func $co (param i32 i32 i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "call") (param i32 i32) (result i32)
    (local $n i32)
    (local.set $n (call $co (i32.const 0) (i32.const 0) (i32.const 64) (i32.const 64)))
    (call $ret (i32.const 64) (local.get $n))
    i32.const 0)
)
"#;

    #[test]
    fn ptb_command_output_reads_existing_slot() {
        let mut ctx = PtbHostCtx::new();
        ctx.command_outputs.push(vec![vec![0xCA, 0xFE, 0xBA, 0xBE]]);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(parse(PTB_CMD_OUTPUT), arc.clone(), Hash32([0; 32]));
        assert_eq!(out.return_data, Some(vec![0xCA, 0xFE, 0xBA, 0xBE]));
    }

    // -----------------------------------------------------------------------
    // object.create by the type-defining petal succeeds.
    // -----------------------------------------------------------------------

    fn object_create_wat(type_tag_bytes: &[u8]) -> String {
        let mut tag_lit = String::new();
        for b in type_tag_bytes {
            tag_lit.push_str(&format!("\\{:02x}", b));
        }
        format!(
            r#"
(module
  (import "object" "create" (func $cr (param i32 i32 i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{tag_lit}")
  (data (i32.const 256) "\de\ad\be\ef")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32)
    (local.set $h
      (call $cr (i32.const 0) (i32.const {tag_len}) (i32.const 256) (i32.const 4)))
    (i32.store (i32.const 512) (local.get $h))
    (call $ret (i32.const 512) (i32.const 4))
    i32.const 0)
)
"#,
            tag_lit = tag_lit,
            tag_len = type_tag_bytes.len(),
        )
    }

    fn object_create_return_id_wat(type_tag_bytes: &[u8]) -> String {
        let mut tag_lit = String::new();
        for b in type_tag_bytes {
            tag_lit.push_str(&format!("\\{:02x}", b));
        }
        format!(
            r#"
(module
  (import "object" "create" (func $cr (param i32 i32 i32 i32) (result i32)))
  (import "object" "id" (func $id (param i32 i32) (result i32)))
  (import "chain" "petal.return" (func $ret (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{tag_lit}")
  (data (i32.const 256) "\de\ad\be\ef")
  (func (export "call") (param i32 i32) (result i32)
    (local $h i32)
    (local.set $h
      (call $cr (i32.const 0) (i32.const {tag_len}) (i32.const 256) (i32.const 4)))
    (drop (call $id (local.get $h) (i32.const 512)))
    (call $ret (i32.const 512) (i32.const 32))
    i32.const 0)
)
"#,
            tag_lit = tag_lit,
            tag_len = type_tag_bytes.len(),
        )
    }

    #[test]
    fn object_create_with_sentinel_hash_stamps_self_and_mints_handle() {
        // The `[0u8; 32]` petal_hash is the compile-time "self" sentinel:
        // a petal cannot name its own code hash, so the `#[bloom::object]`
        // macro emits the zero hash for every type the petal defines.
        // `object.create` must accept the sentinel and stamp the caller's
        // real (computed) petal hash onto the created object — minting a
        // valid handle. (A *non-zero* mismatching hash is still denied;
        // see `object_create_by_non_defining_petal_is_denied`.)
        let sentinel_tag = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "X".into(),
            type_args: vec![],
        };
        let want = sentinel_tag.encode_canonical().unwrap();
        let wasm = parse(&object_create_wat(&want));
        let computed_petal = blake3_tagged(tags::PETAL, &wasm);

        let arc = Arc::new(Mutex::new(PtbHostCtx::new()));
        let out = run_with(wasm, arc.clone(), Hash32([0u8; 32]));
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        // Sentinel hash is accepted (self) → a non-negative handle.
        assert!(
            code >= 0,
            "sentinel-hash create must mint a handle, got {code}"
        );

        // The created object's type_tag must be stamped with the caller's
        // real computed petal hash, not the [0;32] sentinel.
        let guard = arc.lock().unwrap();
        assert_eq!(guard.created_objects.len(), 1, "one object created");
        match &guard.created_objects[0].type_tag {
            TypeTag::Concrete { petal_hash, .. } => {
                assert_eq!(
                    *petal_hash, computed_petal.0,
                    "the self sentinel must be stamped with the caller's hash"
                );
            }
            other => panic!("expected concrete tag, got {other:?}"),
        }
    }

    #[test]
    fn object_create_id_differs_across_ptb_digests() {
        let sentinel_tag = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "X".into(),
            type_args: vec![],
        };
        let want = sentinel_tag.encode_canonical().unwrap();
        let wasm = parse(&object_create_return_id_wat(&want));

        let mut ctx_a = PtbHostCtx::new();
        ctx_a.ptb_digest = [0xA1; 32];
        let out_a = run_with(wasm.clone(), Arc::new(Mutex::new(ctx_a)), Hash32([0u8; 32]));

        let mut ctx_b = PtbHostCtx::new();
        ctx_b.ptb_digest = [0xB2; 32];
        let out_b = run_with(wasm, Arc::new(Mutex::new(ctx_b)), Hash32([0u8; 32]));

        assert_ne!(out_a.return_data.unwrap(), out_b.return_data.unwrap());
    }

    #[test]
    fn object_create_by_non_defining_petal_is_denied() {
        // Type tag's petal_hash != caller wasm's petal_hash → Denied (-2).
        let bogus_tag = TypeTag::Concrete {
            petal_hash: [0xFF; 32],
            type_name: "Whatever".into(),
            type_args: vec![],
        };
        let bytes = bogus_tag.encode_canonical().unwrap();
        let wasm = parse(&object_create_wat(&bytes));
        let arc = Arc::new(Mutex::new(PtbHostCtx::new()));
        let out = run_with(wasm, arc.clone(), Hash32([0; 32]));
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, -2);
    }

    #[test]
    fn object_create_coin_from_unbound_petal_is_denied() {
        let coin_tag = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "Coin".into(),
            type_args: vec![TypeTag::Concrete {
                petal_hash: [0u8; 32],
                type_name: "Erased".into(),
                type_args: vec![],
            }],
        };
        let bytes = coin_tag.encode_canonical().unwrap();
        let wasm = parse(&object_create_wat(&bytes));
        let arc = Arc::new(Mutex::new(PtbHostCtx::new()));
        let out = run_with(wasm, arc.clone(), Hash32([0; 32]));
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, -2);
        assert!(
            arc.lock().unwrap().created_objects.is_empty(),
            "unauthorized Coin create must not stage an object"
        );
    }

    #[test]
    fn object_create_coin_from_vfs_bound_faucet_is_allowed() {
        let coin_tag = TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "Coin".into(),
            type_args: vec![TypeTag::Concrete {
                petal_hash: [0u8; 32],
                type_name: "Erased".into(),
                type_args: vec![],
            }],
        };
        let bytes = coin_tag.encode_canonical().unwrap();
        let wasm = parse(&object_create_wat(&bytes));
        let computed_petal = blake3_tagged(tags::PETAL, &wasm);
        let mut state = State::new();
        state.set_vfs_binding("/bloom/dex/faucet".to_string(), computed_petal);

        let arc = Arc::new(Mutex::new(PtbHostCtx::new()));
        let out = run_with_state(wasm, arc.clone(), Hash32([0; 32]), state);
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert!(code >= 0, "authorized faucet Coin create got {code}");
        assert_eq!(arc.lock().unwrap().created_objects.len(), 1);
    }
}
