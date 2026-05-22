//! Chain-mode petal VM — deterministic smart-contract execution for bloom-chain v0.
//!
//! # Wasmtime configuration (spec §7.5)
//!
//! The chain engine uses a **separate** `wasmtime::Engine` from the
//! local/onchain engine so the config cannot bleed across modes.
//!
//! | Setting | Value | Reason |
//! |---------|-------|--------|
//! | `consume_fuel` | `true` | Required for fuel metering and gas pricing (§7.9). |
//! | `cranelift_nan_canonicalization` | `true` | Makes float ops bit-identical across CPUs (determinism). |
//! | `wasm_relaxed_simd` | `false` | Relaxed SIMD is not deterministic across microarchitectures; disabled for chain mode. |
//! | `wasm_simd` | `true` | Standard deterministic SIMD is allowed. |
//! | `wasm_multi_memory` | `false` | Multiple memories are non-deterministic in ordering; banned per spec. |
//! | `wasm_bulk_memory` | `true` | Bulk-memory is deterministic and useful; allowed. |
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

use std::sync::{Arc, Mutex, OnceLock};

use wasmtime::{Caller, Config, Engine, Linker, Module, OptLevel, Store};

use bloom_chain_state::{Account, StateSnapshot};
use bloom_chain_types::{
    Address, Hash32,
    digest::{blake3_tagged, tags},
};
use bloom_objects::{
    AccessMode, OWNER_KIND_ADDRESS, OWNER_KIND_IMMUTABLE, OWNER_KIND_OBJECT, OWNER_KIND_SHARED,
    Object, ObjectId, Owner, TypeTag,
};
use bloom_script::{
    BorrowRow,
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
    /// loom deltas, …) shared between the wasm host imports installed by
    /// `link_new_host_imports` and the surrounding `PtbExecutor`.
    ///
    /// `None` for the legacy `TxKind::Transfer` / `TxKind::Call` paths
    /// — those code paths never call any of the §16.2 imports, so the
    /// imports will see `None` and respond with `HostError::Backend`.
    pub ptb_ctx: Option<Arc<Mutex<PtbHostCtx>>>,
}

// ---------------------------------------------------------------------------
// Public entry-point types
// ---------------------------------------------------------------------------

/// Which exported function the chain VM should invoke.
pub enum ChainEntry {
    /// Legacy v0 deploy-time `init` export.
    Init,
    /// Legacy v0 `call` export (used by the legacy
    /// `TxKind::Call` / `TxKind::Deploy` paths).
    Call,
    /// PTB-mode Move command: invoke the export with the given name.
    ///
    /// Bloom-native petals (spec §16.2) export one function per
    /// `#[bloom::petal]` function decl, named `__petal_<fn_name>`.
    /// PTB-mode dispatch routes `MoveCmd::function = "name"` into this
    /// variant after prefixing the export name.
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
    /// `Some` for PTB-mode dispatch (driven by `ChainPetalRunner` in
    /// `bloom-chain-node`). `None` for the legacy `TxKind::Transfer` /
    /// `TxKind::Call` paths — those construct `ChainStoreData` with
    /// `ptb_ctx: None` and the §16.2 imports return `HostError::Backend`
    /// when called.
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
        // Determinism: NaN canonicalization (same as local/onchain engine).
        config.cranelift_nan_canonicalization(true);
        // Relaxed SIMD is non-deterministic across microarchitectures; disabled.
        config.wasm_relaxed_simd(false);
        // Standard SIMD is deterministic and allowed.
        config.wasm_simd(true);
        // Multiple memories create ordering ambiguity; banned.
        config.wasm_multi_memory(false);
        // Bulk-memory (memory.copy, memory.fill) is deterministic; allowed.
        config.wasm_bulk_memory(true);
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
/// `"chain"` is the legacy v0 surface. The five new modules
/// (`object`, `cap`, `signer`, `ptb`, `log`) are the spec §16.2
/// Bloom-native surface — they are accepted at validate-time so that
/// Phase 2 petals load, but every imported symbol in those modules is
/// installed as a `NotYetActivated` trap stub in Phase 1.
const CHAIN_ALLOWED_IMPORT_MODULES: &[&str] = &["chain", "object", "cap", "signer", "ptb", "log"];

/// Validate a wasm binary for deploy-time admission as a chain-mode petal.
///
/// Rejects:
/// - Any import whose module is not in `CHAIN_ALLOWED_IMPORT_MODULES`.
/// - Any function export whose name is not in `{"init", "call"}` and
///   does not match the PTB petal export naming convention
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
/// both naming patterns are permitted to keep the legacy
/// `TxKind::Deploy` admission path forward-compatible with bloom-native
/// petals.
/// Whether `name` matches one of the PTB-mode petal export naming
/// conventions emitted by `bloom-resource-macros` (spec §16.2).
fn is_ptb_petal_export(name: &str) -> bool {
    name.starts_with("__petal_")
        || name.starts_with("__inv_")
        || matches!(name, "__alloc" | "__dealloc")
        || name.starts_with("__bloom_manifest_")
}

pub fn validate_chain_wasm(bytes: &[u8]) -> Result<(), PetalError> {
    use wasmparser::{ExternalKind, Parser, Payload};

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
                        (ExternalKind::Func, "init") | (ExternalKind::Func, "call") => {}
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
            _ => {}
        }
    }
    Ok(())
}

/// Whether `bytes` exports a *function* named `name`.
///
/// Used by the `TxKind::Deploy` apply path to decide whether to invoke the
/// deploy-time `init` entry point. PTB-mode petals emitted by
/// `bloom-resource-macros` (spec §16.2) have no `init`/`call` exports — only
/// `__petal_*` shims — and create all of their state lazily through PTB
/// `Move` commands, so deploying one is a pure code+VFS staging step with no
/// initializer to run. Without this check the deploy path would
/// unconditionally `get_typed_func("init")` and trap with
/// `failed to find function export 'init'`.
pub fn wasm_exports_function(bytes: &[u8], name: &str) -> bool {
    use wasmparser::{ExternalKind, Parser, Payload};

    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(Payload::ExportSection(reader)) = payload else {
            continue;
        };
        for export in reader.into_iter().flatten() {
            if export.kind == ExternalKind::Func && export.name == name {
                return true;
            }
        }
    }
    false
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
    // -----------------------------------------------------------------------
    // chain.state.read(key_ptr, key_len, out_ptr) -> i64
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "state.read",
        |mut caller: Caller<'_, ChainStoreData>, key_ptr: i32, key_len: i32, out_ptr: i32| -> i64 {
            if consume_fuel(&mut caller, 100).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code() as i64;
            }
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code() as i64,
            };
            let key_bytes = match read_chain_bytes(&mem, &mut caller, key_ptr, key_len) {
                Ok(b) => b,
                Err(c) => return c as i64,
            };
            if key_bytes.len() != 32 {
                return HostError::Invalid("key must be 32 bytes".into()).as_wasm_code() as i64;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let addr = caller.data().chain_ctx.contract_address;
            let value = caller.data().chain_ctx.snapshot.storage_read(&addr, &key);

            // Write 32 bytes to out_ptr (zeros if slot is missing).
            if let Err(c) = write_chain_bytes(&mem, &mut caller, out_ptr, &value) {
                return c as i64;
            }
            32
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.state.write(key_ptr, key_len, val_ptr, val_len) -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "state.write",
        |mut caller: Caller<'_, ChainStoreData>,
         key_ptr: i32,
         key_len: i32,
         val_ptr: i32,
         val_len: i32|
         -> i32 {
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            let key_bytes = match read_chain_bytes(&mem, &mut caller, key_ptr, key_len) {
                Ok(b) => b,
                Err(c) => return c,
            };
            if key_bytes.len() != 32 {
                return HostError::Invalid("key must be 32 bytes".into()).as_wasm_code();
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            if !(0..=32).contains(&val_len) {
                return HostError::Invalid("val_len must be 0..=32".into()).as_wasm_code();
            }
            let val_bytes = match read_chain_bytes(&mem, &mut caller, val_ptr, val_len) {
                Ok(b) => b,
                Err(c) => return c,
            };

            // Left-pad with zeros to 32 bytes.
            let mut value = [0u8; 32];
            let offset = 32 - val_bytes.len();
            value[offset..].copy_from_slice(&val_bytes);

            // Determine new vs. existing slot for fuel pricing.
            let addr = caller.data().chain_ctx.contract_address;
            let existing = caller.data().chain_ctx.snapshot.storage_read(&addr, &key);
            let is_new = existing == [0u8; 32];
            let fuel = if is_new { 5000 } else { 1500 };

            if consume_fuel(&mut caller, fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }

            caller
                .data_mut()
                .chain_ctx
                .snapshot
                .storage_write(addr, key, value);
            0
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.state.delete(key_ptr, key_len) -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "state.delete",
        |mut caller: Caller<'_, ChainStoreData>, key_ptr: i32, key_len: i32| -> i32 {
            if consume_fuel(&mut caller, 500).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            let key_bytes = match read_chain_bytes(&mem, &mut caller, key_ptr, key_len) {
                Ok(b) => b,
                Err(c) => return c,
            };
            if key_bytes.len() != 32 {
                return HostError::Invalid("key must be 32 bytes".into()).as_wasm_code();
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let addr = caller.data().chain_ctx.contract_address;
            caller
                .data_mut()
                .chain_ctx
                .snapshot
                .storage_delete(addr, key);
            0
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.petal.return(data_ptr, data_len)
    //
    // Stores return data then raises a wasmtime trap. The dispatch loop
    // detects `return_data.is_some()` in the `ChainStoreData` and treats
    // the trap as a clean successful exit, discarding the trap error.
    //
    // We raise the trap by returning `Err(...)` from the `func_wrap` closure
    // (wasmtime propagates this as a wasm trap). This is reliable in both
    // sync and async modes — unlike `set_fuel(0)` which only fires at
    // safepoints.
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // chain.petal.revert(reason_ptr, reason_len)
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // chain.petal.call(target_ptr, target_len, cd_ptr, cd_len,
    //                  value_lo, value_hi, retdata_ptr, retdata_max) -> i64
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "petal.call",
        |mut caller: Caller<'_, ChainStoreData>,
         target_ptr: i32,
         target_len: i32,
         cd_ptr: i32,
         cd_len: i32,
         value_lo: i64,
         value_hi: i64,
         retdata_ptr: i32,
         retdata_max: i32|
         -> i64 {
            // Depth check (spec §7.6: max 16 nested calls).
            if caller.data().chain_ctx.call_depth >= 16 {
                return HostError::Backend("call depth exceeded".into()).as_wasm_code() as i64;
            }

            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code() as i64,
            };

            let target_bytes = match read_chain_bytes(&mem, &mut caller, target_ptr, target_len) {
                Ok(b) => b,
                Err(c) => return c as i64,
            };
            if target_bytes.len() != 32 {
                return HostError::Invalid("target must be 32 bytes".into()).as_wasm_code() as i64;
            }
            let mut target_arr = [0u8; 32];
            target_arr.copy_from_slice(&target_bytes);
            let target = Address(target_arr);

            let calldata = match read_chain_bytes(&mem, &mut caller, cd_ptr, cd_len) {
                Ok(b) => b,
                Err(c) => return c as i64,
            };

            let value_loom =
                ((value_hi as u128) << 64) | (value_lo as u128 & 0xFFFF_FFFF_FFFF_FFFF);

            // Fuel pre-charge (5000 per call; callee fuel added after).
            if consume_fuel(&mut caller, 5000).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code() as i64;
            }

            // Get code for target contract.
            let code_hash = {
                match caller.data().chain_ctx.snapshot.get_account(&target) {
                    Some(acct) => match acct.code_hash {
                        Some(h) => h,
                        None => {
                            return HostError::NotFound("target has no code".into()).as_wasm_code()
                                as i64;
                        }
                    },
                    None => {
                        return HostError::NotFound("target account not found".into()).as_wasm_code()
                            as i64;
                    }
                }
            };

            // We need the wasm bytes — but snapshot.get_code only has a reference tied
            // to the snapshot borrow. We clone to avoid the borrow-check issue.
            let wasm_bytes: Vec<u8> = match caller.data().chain_ctx.snapshot.get_code(&code_hash) {
                Some(bytes) => bytes.to_vec(),
                None => return HostError::NotFound("code not found".into()).as_wasm_code() as i64,
            };

            // Checkpoint-then-restore for nested-call revert isolation
            // (review 2026-05-19 #6).
            //
            // We clone the parent's snapshot BEFORE the value transfer
            // so that on revert/trap we can restore exactly the parent's
            // pre-call view — including rolling back the value transfer.
            // The clone is taken here (and not after the value transfer)
            // because a reverted child must not retain the LOOM credit;
            // the parent must end up with its pre-call balance.
            //
            // StateSnapshot is `Clone`; the per-call WriteSet is small.
            let parent_snapshot_checkpoint = caller.data().chain_ctx.snapshot.clone();

            // LOOM transfer (caller → target) before executing.
            if value_loom > 0 {
                let caller_addr = caller.data().chain_ctx.contract_address;
                let caller_acct = caller.data().chain_ctx.snapshot.get_account(&caller_addr);
                let caller_loom = caller_acct.map(|a| a.loom).unwrap_or(0);
                if caller_loom < value_loom {
                    return HostError::Backend("insufficient balance".into()).as_wasm_code() as i64;
                }
                // Debit caller.
                let mut ca = caller
                    .data()
                    .chain_ctx
                    .snapshot
                    .get_account(&caller_addr)
                    .unwrap_or_else(Account::empty);
                ca.loom -= value_loom;
                caller
                    .data_mut()
                    .chain_ctx
                    .snapshot
                    .set_account(caller_addr, ca);
                // Credit target.
                let mut ta = caller
                    .data()
                    .chain_ctx
                    .snapshot
                    .get_account(&target)
                    .unwrap_or_else(Account::empty);
                ta.loom += value_loom;
                caller.data_mut().chain_ctx.snapshot.set_account(target, ta);
            }

            // Build sub-input. We must take a nested snapshot from the same state.
            // The caller's snapshot accumulates the writes; we pass it by moving it
            // into the callee via a sub-snapshot derived from its current state.
            //
            // Implementation: extract the snapshot from caller, pass it to a sync
            // recursive call, then restore it afterwards.
            let depth = caller.data().chain_ctx.call_depth;
            let block = caller.data().chain_ctx.block.clone();
            let msg_sender = caller.data().chain_ctx.contract_address;
            let fuel_remaining = caller.get_fuel().unwrap_or(0);

            // Take ownership of the snapshot to pass to the callee.
            // We swap it out with a dummy, run the callee, then swap back
            // with the (mutated) snapshot from the callee output on
            // success, or with the checkpoint on error.
            let snap = {
                let dummy = bloom_chain_state::State::new().snapshot();
                std::mem::replace(&mut caller.data_mut().chain_ctx.snapshot, dummy)
            };

            let sub_input = ChainCallInput {
                wasm: wasm_bytes,
                entry: ChainEntry::Call,
                contract_address: target,
                msg_sender,
                msg_value: value_loom,
                calldata,
                block,
                fuel: fuel_remaining,
                snapshot: snap,
                ptb_ctx: None,
            };

            let engine = match chain_engine() {
                Ok(e) => e,
                Err(_) => {
                    // Restore parent's pre-call view (value transfer reverts too).
                    caller.data_mut().chain_ctx.snapshot = parent_snapshot_checkpoint;
                    return HostError::Backend("engine error".into()).as_wasm_code() as i64;
                }
            };

            let sub_result = dispatch_chain_call_sync(engine, sub_input, depth + 1);

            match sub_result {
                Ok(out) => {
                    // Success: keep the callee's mutated snapshot — the
                    // callee's writes (and the pre-call value transfer)
                    // are now part of the parent's view.
                    caller.data_mut().chain_ctx.snapshot = out.snapshot;
                    // Append callee logs.
                    caller.data_mut().chain_ctx.logs.extend(out.logs);

                    // Charge callee's fuel usage.
                    let _ = consume_fuel(&mut caller, out.fuel_used);

                    // Write return data.
                    if let Some(retdata) = out.return_data {
                        let need = retdata.len();
                        if retdata_max < 0 || need > retdata_max as usize {
                            // Overflow: return data too large.
                            return -((need as i64).saturating_add(PetalVm::OVERFLOW_BIAS as i64));
                        }
                        if write_chain_bytes(
                            &get_chain_memory(&mut caller).unwrap(),
                            &mut caller,
                            retdata_ptr,
                            &retdata,
                        )
                        .is_err()
                        {
                            return HostError::Invalid("retdata write failed".into()).as_wasm_code()
                                as i64;
                        }
                        need as i64
                    } else {
                        0
                    }
                }
                Err(e) => {
                    // Sub-call failed — discard the callee's (mutated)
                    // snapshot and restore the parent's pre-call
                    // checkpoint. This rolls back ALL child writes,
                    // including the value transfer and any storage
                    // mutations the child performed before reverting.
                    // Critically, this holds even if the parent ignores
                    // the negative return code and continues executing.
                    caller.data_mut().chain_ctx.snapshot = parent_snapshot_checkpoint;
                    match e {
                        SubCallError::Reverted {
                            reason, fuel_used, ..
                        } => {
                            // DoS-hardening 2026-05-19: even though the
                            // child reverted (and its writes are rolled
                            // back), the parent's fuel meter MUST be
                            // debited by what the child actually burned.
                            // Otherwise burn-then-revert is free.
                            let _ = consume_fuel(&mut caller, fuel_used);
                            // Surface the sub-call's revert reason so
                            // callers can inspect it.
                            caller.data_mut().chain_ctx.return_data = reason;
                            HostError::Backend("callee reverted".into()).as_wasm_code() as i64
                        }
                        SubCallError::Trapped { fuel_used, .. } => {
                            // Same hardening for traps: a trapped child
                            // burned real work and the parent pays for it.
                            let _ = consume_fuel(&mut caller, fuel_used);
                            HostError::Backend("callee trapped".into()).as_wasm_code() as i64
                        }
                    }
                }
            }
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.block.number() -> i64
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "block.number",
        |caller: Caller<'_, ChainStoreData>| -> i64 { caller.data().chain_ctx.block.number as i64 },
    )?;

    // -----------------------------------------------------------------------
    // chain.block.timestamp() -> i64
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "block.timestamp",
        |caller: Caller<'_, ChainStoreData>| -> i64 {
            caller.data().chain_ctx.block.timestamp_ms as i64
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.block.prevhash(out_ptr: i32)
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "block.prevhash",
        |mut caller: Caller<'_, ChainStoreData>, out_ptr: i32| {
            let prevhash = caller.data().chain_ctx.block.prevhash.0;
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return,
            };
            let _ = write_chain_bytes(&mem, &mut caller, out_ptr, &prevhash);
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.msg.sender(out_ptr: i32)
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "msg.sender",
        |mut caller: Caller<'_, ChainStoreData>, out_ptr: i32| {
            let sender = caller.data().chain_ctx.msg_sender.0;
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return,
            };
            let _ = write_chain_bytes(&mem, &mut caller, out_ptr, &sender);
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.msg.value(out_ptr: i32) — writes the 16-byte little-endian u128 value.
    //
    // Multi-value wasm returns aren't part of the default C ABI on
    // wasm32-unknown-unknown, so we follow the same write-to-pointer convention
    // used by msg.sender / block.prevhash to stay compatible across compilers.
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "msg.value",
        |mut caller: Caller<'_, ChainStoreData>, out_ptr: i32| {
            let v = caller.data().chain_ctx.msg_value;
            let bytes = v.to_le_bytes();
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return,
            };
            let _ = write_chain_bytes(&mem, &mut caller, out_ptr, &bytes);
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.msg.calldata.len() -> i32
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "msg.calldata.len",
        |caller: Caller<'_, ChainStoreData>| -> i32 {
            caller.data().chain_ctx.calldata.len() as i32
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.msg.calldata.read(dst_ptr, offset, len) -> i32
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // chain.log.emit(topic_ptr, topic_count, data_ptr, data_len) -> i32
    // Fuel: 100 + 8*data_len + 100*topic_count
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "log.emit",
        |mut caller: Caller<'_, ChainStoreData>,
         topic_ptr: i32,
         topic_count: i32,
         data_ptr: i32,
         data_len: i32|
         -> i32 {
            if topic_count < 0 || data_len < 0 {
                return HostError::Invalid("negative topic_count or data_len".into())
                    .as_wasm_code();
            }
            let fuel = 100u64 + 8u64 * data_len as u64 + 100u64 * topic_count as u64;
            if consume_fuel(&mut caller, fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }

            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };

            // Read topics: topic_count * 32 bytes.
            let topics_len = (topic_count as usize) * 32;
            let topics_raw = match read_chain_bytes(&mem, &mut caller, topic_ptr, topics_len as i32)
            {
                Ok(b) => b,
                Err(c) => return c,
            };
            let topics: Vec<Hash32> = topics_raw
                .chunks_exact(32)
                .map(|chunk| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(chunk);
                    Hash32(arr)
                })
                .collect();

            let data = match read_chain_bytes(&mem, &mut caller, data_ptr, data_len) {
                Ok(b) => b,
                Err(c) => return c,
            };

            let address = caller.data().chain_ctx.contract_address;
            caller.data_mut().chain_ctx.logs.push(LogEntry {
                address,
                topics,
                data,
            });
            0
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.crypto.blake3(in_ptr, in_len, out_ptr) -> i32
    // Fuel: 50 + 4*in_len
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "crypto.blake3",
        |mut caller: Caller<'_, ChainStoreData>, in_ptr: i32, in_len: i32, out_ptr: i32| -> i32 {
            if in_len < 0 {
                return HostError::Invalid("negative in_len".into()).as_wasm_code();
            }
            let fuel = 50u64 + 4u64 * in_len as u64;
            if consume_fuel(&mut caller, fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }

            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };
            let input = match read_chain_bytes(&mem, &mut caller, in_ptr, in_len) {
                Ok(b) => b,
                Err(c) => return c,
            };

            // Raw (untagged) BLAKE3 for the crypto import — it is a general
            // hash utility. The spec §7.6 says "deterministic; no state" and
            // does not mandate a domain tag for this primitive.
            let hash = *blake3::hash(&input).as_bytes();
            match write_chain_bytes(&mem, &mut caller, out_ptr, &hash) {
                Ok(()) => 32,
                Err(c) => c,
            }
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.code.manifest_hash(addr_ptr, out_ptr) -> i32
    //
    // Writes a 33-byte answer at `out_ptr`:
    //   byte 0: 0 = no anchor, 1 = anchor present
    //   bytes 1..33: the 32-byte manifest hash (zeroed when byte 0 is 0)
    //
    // Returns 0 on success or a HostError code on failure. The query is
    // safe for non-existent addresses — those return present=0 with a
    // zero hash, matching the `Account::manifest_hash == None` view.
    // (bloom-rust-contracts Phase 8 — on-chain manifest anchor read.)
    // Fuel: 200
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "code.manifest_hash",
        |mut caller: Caller<'_, ChainStoreData>, addr_ptr: i32, out_ptr: i32| -> i32 {
            if consume_fuel(&mut caller, 200).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }

            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };

            let addr_bytes = match read_chain_bytes(&mem, &mut caller, addr_ptr, 32) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let mut addr_arr = [0u8; 32];
            addr_arr.copy_from_slice(&addr_bytes);
            let target = Address(addr_arr);

            let mut out = [0u8; 33];
            if let Some(acct) = caller.data().chain_ctx.snapshot.get_account(&target)
                && let Some(h) = acct.manifest_hash
            {
                out[0] = 1;
                out[1..33].copy_from_slice(&h.0);
            }

            match write_chain_bytes(&mem, &mut caller, out_ptr, &out) {
                Ok(()) => 0,
                Err(c) => c,
            }
        },
    )?;

    // -----------------------------------------------------------------------
    // chain.host.deploy(hash_ptr, hash_len, salt_ptr, salt_len,
    //                   init_ptr, init_len, out_addr_ptr) -> i64
    // Fuel: 10000 + init's used fuel
    // -----------------------------------------------------------------------
    linker.func_wrap(
        "chain",
        "host.deploy",
        |mut caller: Caller<'_, ChainStoreData>,
         hash_ptr: i32,
         hash_len: i32,
         salt_ptr: i32,
         salt_len: i32,
         init_ptr: i32,
         init_len: i32,
         out_addr_ptr: i32|
         -> i64 {
            if consume_fuel(&mut caller, 10000).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code() as i64;
            }

            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code() as i64,
            };

            let hash_bytes = match read_chain_bytes(&mem, &mut caller, hash_ptr, hash_len) {
                Ok(b) => b,
                Err(c) => return c as i64,
            };
            if hash_bytes.len() != 32 {
                return HostError::Invalid("petal_hash must be 32 bytes".into()).as_wasm_code()
                    as i64;
            }
            let mut petal_hash_arr = [0u8; 32];
            petal_hash_arr.copy_from_slice(&hash_bytes);
            let petal_hash = Hash32(petal_hash_arr);

            let salt_bytes = match read_chain_bytes(&mem, &mut caller, salt_ptr, salt_len) {
                Ok(b) => b,
                Err(c) => return c as i64,
            };
            if salt_bytes.len() != 32 {
                return HostError::Invalid("salt must be 32 bytes".into()).as_wasm_code() as i64;
            }

            let init_calldata = match read_chain_bytes(&mem, &mut caller, init_ptr, init_len) {
                Ok(b) => b,
                Err(c) => return c as i64,
            };

            // Verify petal_hash exists in code store.
            if caller
                .data()
                .chain_ctx
                .snapshot
                .get_code(&petal_hash)
                .is_none()
            {
                return HostError::NotFound("petal_hash not in code store".into()).as_wasm_code()
                    as i64;
            }

            // Compute deployed address per spec §7.7:
            // instance_address = blake3("bloom-chain.v0.addr:" || "deploy:" || deployer || ":" || salt || ":" || petal_hash)
            let deployer = caller.data().chain_ctx.contract_address;
            let deployed_address = {
                let mut payload = b"deploy:".to_vec();
                payload.extend_from_slice(&deployer.0);
                payload.push(b':');
                payload.extend_from_slice(&salt_bytes);
                payload.push(b':');
                payload.extend_from_slice(&petal_hash.0);
                let h = blake3_tagged(tags::ADDR, &payload);
                Address(h.0)
            };

            // Check for address collision.
            if caller
                .data()
                .chain_ctx
                .snapshot
                .get_account(&deployed_address)
                .is_some_and(|a| a.code_hash.is_some())
            {
                return HostError::Backend("address collision: already deployed".into())
                    .as_wasm_code() as i64;
            }

            // Checkpoint BEFORE the spawn so a failed init rolls back the
            // staged account too (review 2026-05-19 #6).
            let parent_snapshot_checkpoint = caller.data().chain_ctx.snapshot.clone();

            // Spawn the new account with code_hash set. Cross-contract
            // deploys via `chain.code.deploy` do not carry a manifest
            // anchor — only top-level `TxKind::Deploy` does.
            let new_account = Account {
                nonce: 0,
                loom: 0,
                code_hash: Some(petal_hash),
                storage_root: Hash32([0u8; 32]),
                manifest_hash: None,
            };
            caller
                .data_mut()
                .chain_ctx
                .snapshot
                .set_account(deployed_address, new_account);

            // Get the wasm bytes for the init call.
            let wasm_bytes: Vec<u8> = match caller.data().chain_ctx.snapshot.get_code(&petal_hash) {
                Some(b) => b.to_vec(),
                None => {
                    caller.data_mut().chain_ctx.snapshot = parent_snapshot_checkpoint;
                    return HostError::NotFound("code not found".into()).as_wasm_code() as i64;
                }
            };

            let depth = caller.data().chain_ctx.call_depth;
            let block = caller.data().chain_ctx.block.clone();
            let fuel_remaining = caller.get_fuel().unwrap_or(0);

            // Move snapshot into the init call.
            let snap = {
                let dummy = bloom_chain_state::State::new().snapshot();
                std::mem::replace(&mut caller.data_mut().chain_ctx.snapshot, dummy)
            };

            let sub_input = ChainCallInput {
                wasm: wasm_bytes,
                entry: ChainEntry::Init,
                contract_address: deployed_address,
                msg_sender: deployer,
                msg_value: 0,
                calldata: init_calldata,
                block,
                fuel: fuel_remaining,
                snapshot: snap,
                ptb_ctx: None,
            };

            let engine = match chain_engine() {
                Ok(e) => e,
                Err(_) => {
                    caller.data_mut().chain_ctx.snapshot = parent_snapshot_checkpoint;
                    return HostError::Backend("engine error".into()).as_wasm_code() as i64;
                }
            };

            match dispatch_chain_call_sync(engine, sub_input, depth + 1) {
                Ok(out) => {
                    // Charge init fuel.
                    let _ = consume_fuel(&mut caller, out.fuel_used);
                    // Keep the post-init mutated snapshot (account spawn + init writes).
                    caller.data_mut().chain_ctx.snapshot = out.snapshot;
                    caller.data_mut().chain_ctx.logs.extend(out.logs);

                    // Write deployed address to out_addr_ptr.
                    let mem2 = match get_chain_memory(&mut caller) {
                        Some(m) => m,
                        None => {
                            return HostError::Invalid("no memory".into()).as_wasm_code() as i64;
                        }
                    };
                    if let Err(c) =
                        write_chain_bytes(&mem2, &mut caller, out_addr_ptr, &deployed_address.0)
                    {
                        return c as i64;
                    }
                    0
                }
                Err(e) => {
                    // Failed init: restore parent's pre-deploy checkpoint —
                    // this rolls back BOTH the staged account and any init
                    // writes the child may have done before reverting.
                    caller.data_mut().chain_ctx.snapshot = parent_snapshot_checkpoint;
                    // DoS-hardening 2026-05-19: charge the parent for the
                    // fuel the failed init actually burned. Otherwise a
                    // deploy whose `init` runs a fuel-bomb and reverts is
                    // free to the caller.
                    let fuel_used = match &e {
                        SubCallError::Reverted { fuel_used, .. } => *fuel_used,
                        SubCallError::Trapped { fuel_used, .. } => *fuel_used,
                    };
                    let _ = consume_fuel(&mut caller, fuel_used);
                    HostError::Backend("init failed".into()).as_wasm_code() as i64
                }
            }
        },
    )?;

    // -----------------------------------------------------------------------
    // Bloom-native contracts (spec §16.2) — real bodies.
    //
    // Every import in `bloom_objects::host_imports::NEW_HOST_IMPORTS`
    // is installed with a real body that charges per-spec §16.4 fuel
    // and mutates the per-PTB `PtbHostCtx` stored on `ChainStoreData`.
    // Legacy `TxKind::Transfer` / `TxKind::Call` paths still link them
    // — but they construct `ChainStoreData { ptb_ctx: None, .. }` so a
    // legacy petal that mistakenly imports one of these symbols sees
    // `HostError::Backend` and aborts cleanly.
    // -----------------------------------------------------------------------
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
/// store has no PTB context attached (legacy `TxKind::Call` reached a
/// §16.2 import, which should not happen for validated petals), the
/// closure is *not* invoked and we return [`HostError::Backend`]'s wasm
/// code so the petal aborts cleanly.
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
        None => HostError::Backend("no ptb ctx (legacy path?)".into()).as_wasm_code(),
    }
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

            with_ptb_ctx(&caller, |ctx| {
                // Access-mode check: ReadOnly rows cannot be mutated.
                let access = match ctx.borrow_table.get(&id) {
                    Some(row) => row.access_mode,
                    None => {
                        return HostError::NotFound("row vanished".into()).as_wasm_code();
                    }
                };
                if matches!(access, AccessMode::ReadOnly) {
                    return HostError::Denied("mutate on ReadOnly".into()).as_wasm_code();
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

            with_ptb_ctx(&caller, |ctx| {
                match ctx.borrow_table.get_mut(&id) {
                    Some(row) => {
                        // Capture prior owner before overwrite: the
                        // chain-node's `rebuild_ownership_rows` needs
                        // both keys to keep the OwnershipIndex
                        // symmetric (spec §16.3).
                        let old_owner = row.owner.clone();
                        row.owner = new_owner.clone();
                        ctx.ownership_changes.push((id, old_owner, new_owner));
                        ctx.borrow_table.mark_consumed(&id);
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
            with_ptb_ctx(&caller, |ctx| match ctx.borrow_table.get_mut(&id) {
                Some(row) => {
                    let old_owner = row.owner.clone();
                    row.owner = Owner::Shared;
                    ctx.ownership_changes.push((id, old_owner, Owner::Shared));
                    ctx.borrow_table.mark_consumed(&id);
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
            with_ptb_ctx(&caller, |ctx| match ctx.borrow_table.get_mut(&id) {
                Some(row) => {
                    let old_owner = row.owner.clone();
                    row.owner = Owner::Immutable;
                    ctx.ownership_changes
                        .push((id, old_owner, Owner::Immutable));
                    ctx.borrow_table.mark_consumed(&id);
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
/// call. The recipe (BLAKE3 of caller petal hash + ptb-scope counter +
/// type-tag bytes + payload bytes) makes the id reproducible across
/// validator replays of the same PTB without depending on the engine's
/// internal bookkeeping.
fn derive_create_id(
    caller: &Caller<'_, ChainStoreData>,
    type_tag_bytes: &[u8],
    payload: &[u8],
) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.object.create.v1\0");
    hasher.update(&caller.data().petal_hash.0);
    // Mix in the PTB ctx's "created so far" length for per-call
    // uniqueness within a single PTB.
    let n = caller
        .data()
        .ptb_ctx
        .as_ref()
        .and_then(|arc| arc.lock().ok().map(|c| c.created_objects.len()))
        .unwrap_or(0) as u64;
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

/// Per-instance cap on instance/memory/table counts. The chain-mode
/// dispatcher creates exactly one instance per `dispatch_chain_call_sync`
/// call and one memory per instance, but nested `petal.call` may create
/// new stores; the limiter is scoped to a single store, so these are tight.
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
        // PTB-mode dispatch (`ChainPetalRunner`) supplies an
        // `Arc<Mutex<PtbHostCtx>>` here; legacy `TxKind::Transfer` /
        // `TxKind::Call` paths pass `None` and the §16.2 host imports
        // return `HostError::Backend` when called.
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

    let entry_name = match &input.entry {
        ChainEntry::Init => "init".to_string(),
        ChainEntry::Call => "call".to_string(),
        ChainEntry::Function(name) => name.clone(),
    };
    let entry_name: &str = &entry_name;

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
            Err(SubCallError::Trapped { error, .. }) => Err(PetalError::ChainCall(
                error
                    .map(|s| format!("trapped: {s}"))
                    .unwrap_or_else(|| "trapped".into()),
            )),
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
        let state = State::new();
        let input = ChainCallInput {
            wasm,
            entry: ChainEntry::Call,
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
        let petal = Hash32([0x11; 32]);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![0; 3], Owner::Address([0; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(parse(OBJECT_BORROW_MUTATE), arc.clone(), petal);
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
        let petal = Hash32([0x33; 32]);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let out = run_with(parse(OBJECT_TRANSFER), arc.clone(), petal);
        let code = i32::from_le_bytes(out.return_data.unwrap().try_into().unwrap());
        assert_eq!(code, 0);
        let guard = arc.lock().unwrap();
        assert_eq!(guard.ownership_changes.len(), 1);
        let (id, old, new) = &guard.ownership_changes[0];
        assert_eq!(*id, ObjectId([0x07; 32]));
        assert_eq!(*old, Owner::Address([0xaa; 32]));
        assert_eq!(*new, Owner::Address([0xbb; 32]));
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
        let petal = Hash32([0x44; 32]);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let _ = run_with(parse(OBJECT_SHARE), arc.clone(), petal);
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
        let petal = Hash32([0x55; 32]);
        let mut ctx = PtbHostCtx::new();
        let obj = make_object(0x07, vec![1], Owner::Address([0xaa; 32]), petal.0);
        ctx.borrow_table.load_persistent(&obj, AccessMode::Mutable);
        let arc = Arc::new(Mutex::new(ctx));
        let _ = run_with(parse(OBJECT_FREEZE), arc.clone(), petal);
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
}
