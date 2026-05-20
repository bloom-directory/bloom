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

use std::sync::OnceLock;

use wasmtime::{Caller, Config, Engine, Linker, Module, OptLevel, Store};

use bloom_chain_types::{
    Address, Hash32,
    digest::{blake3_tagged, tags},
};
use bloom_chain_state::{Account, StateSnapshot};

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
}

// ---------------------------------------------------------------------------
// Public entry-point types
// ---------------------------------------------------------------------------

pub enum ChainEntry {
    Init,
    Call,
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
const CHAIN_ALLOWED_IMPORT_MODULES: &[&str] = &[
    "chain", "object", "cap", "signer", "ptb", "log",
];

/// Validate a wasm binary for deploy-time admission as a chain-mode petal.
///
/// Rejects:
/// - Any import whose module is not in `CHAIN_ALLOWED_IMPORT_MODULES`.
/// - Any function export whose name is not in `{"init", "call"}`.
/// - A `memory` export with min pages > 256 or max pages > 256 (16 MiB cap).
///
/// LLVM/Rust wasm32 builds routinely emit non-function exports such as
/// `__heap_base`, `__data_end`, and `__indirect_function_table`. Those are
/// inert globals/tables — they're not callable host entry points — so we
/// only enforce the entry-point allow-list on Function exports.
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
                        (ExternalKind::Func, other) => {
                            return Err(PetalError::InvalidWasm(format!(
                                "chain petal exports disallowed function '{other}'"
                            )));
                        }
                        // Non-function exports (globals, tables, memory) are
                        // harmless: they aren't callable host entry points.
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
        |mut caller: Caller<'_, ChainStoreData>, data_ptr: i32, data_len: i32| -> anyhow::Result<()> {
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => {
                    caller.data_mut().chain_ctx.return_data = Some(Vec::new());
                    anyhow::bail!("petal.return");
                }
            };
            let data = read_chain_bytes(&mem, &mut caller, data_ptr, data_len)
                .unwrap_or_default();
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
        |mut caller: Caller<'_, ChainStoreData>, reason_ptr: i32, reason_len: i32| -> anyhow::Result<()> {
            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => {
                    caller.data_mut().chain_ctx.revert_reason = Some(Vec::new());
                    anyhow::bail!("petal.revert");
                }
            };
            let reason = read_chain_bytes(&mem, &mut caller, reason_ptr, reason_len)
                .unwrap_or_default();
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

            let value_loom = ((value_hi as u128) << 64) | (value_lo as u128 & 0xFFFF_FFFF_FFFF_FFFF);

            // Fuel pre-charge (5000 per call; callee fuel added after).
            if consume_fuel(&mut caller, 5000).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code() as i64;
            }

            // Get code for target contract.
            let code_hash = {
                match caller.data().chain_ctx.snapshot.get_account(&target) {
                    Some(acct) => match acct.code_hash {
                        Some(h) => h,
                        None => return HostError::NotFound("target has no code".into()).as_wasm_code() as i64,
                    },
                    None => return HostError::NotFound("target account not found".into()).as_wasm_code() as i64,
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
                let mut ca = caller.data().chain_ctx.snapshot.get_account(&caller_addr)
                    .unwrap_or_else(Account::empty);
                ca.loom -= value_loom;
                caller.data_mut().chain_ctx.snapshot.set_account(caller_addr, ca);
                // Credit target.
                let mut ta = caller.data().chain_ctx.snapshot.get_account(&target)
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
                            return HostError::Invalid("retdata write failed".into()).as_wasm_code() as i64;
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
                        SubCallError::Reverted { reason, fuel_used, .. } => {
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
    linker.func_wrap("chain", "block.number", |caller: Caller<'_, ChainStoreData>| -> i64 {
        caller.data().chain_ctx.block.number as i64
    })?;

    // -----------------------------------------------------------------------
    // chain.block.timestamp() -> i64
    // -----------------------------------------------------------------------
    linker.func_wrap("chain", "block.timestamp", |caller: Caller<'_, ChainStoreData>| -> i64 {
        caller.data().chain_ctx.block.timestamp_ms as i64
    })?;

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
                return HostError::Invalid("negative topic_count or data_len".into()).as_wasm_code();
            }
            let fuel = 100u64
                + 8u64 * data_len as u64
                + 100u64 * topic_count as u64;
            if consume_fuel(&mut caller, fuel).is_err() {
                return HostError::Backend("out of fuel".into()).as_wasm_code();
            }

            let mem = match get_chain_memory(&mut caller) {
                Some(m) => m,
                None => return HostError::Invalid("no memory".into()).as_wasm_code(),
            };

            // Read topics: topic_count * 32 bytes.
            let topics_len = (topic_count as usize) * 32;
            let topics_raw = match read_chain_bytes(&mem, &mut caller, topic_ptr, topics_len as i32) {
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
            caller.data_mut().chain_ctx.logs.push(LogEntry { address, topics, data });
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
                return HostError::Invalid("petal_hash must be 32 bytes".into()).as_wasm_code() as i64;
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
            if caller.data().chain_ctx.snapshot.get_code(&petal_hash).is_none() {
                return HostError::NotFound("petal_hash not in code store".into()).as_wasm_code() as i64;
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
                return HostError::Backend("address collision: already deployed".into()).as_wasm_code() as i64;
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
                        None => return HostError::Invalid("no memory".into()).as_wasm_code() as i64,
                    };
                    if let Err(c) = write_chain_bytes(&mem2, &mut caller, out_addr_ptr, &deployed_address.0) {
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
    // Bloom-native contracts (spec §16.2) — Phase 1 stubs.
    //
    // Every import in `bloom_objects::host_imports::NEW_HOST_IMPORTS`
    // is installed as a trap closure that consumes 1 unit of fuel
    // (cheap-to-skip, but non-zero so an infinite loop calling stubs
    // still exhausts fuel) and then returns `NOT_YET_ACTIVATED_CODE`
    // for an i32-result import, or signals a wasm trap for the
    // few imports that have wider-than-i32 conceptual results.
    //
    // The current §16.2 table is uniformly `i32`-result, so we use the
    // simple "return error code" path. If §16.2 ever grows imports
    // with `i64` or `(i32, i32)` results we add specialised stubs here.
    // -----------------------------------------------------------------------
    link_new_host_import_stubs(linker)?;

    Ok(())
}

/// Negative wasm error code returned by every Phase-1 stub for the new
/// Bloom-native host surface (spec §16.2).
///
/// `-100` is chosen to sit comfortably below the existing host-error
/// codes (`-1..-7`) and any code the petal-side macros use for their
/// own diagnostics (high-bit `0x4000_0000` per `bloom_resource::error`).
/// A petal that calls one of these imports during Phase 1 will read
/// this code and surface `PetalError::NotYetActivated` to the user.
pub const NOT_YET_ACTIVATED_CODE: i32 = -100;

/// Install Phase-1 stubs for every entry in
/// `bloom_objects::host_imports::NEW_HOST_IMPORTS`.
///
/// Each stub:
/// 1. Charges 1 unit of fuel (so an attacker can't busy-loop calling
///    stubs for free — the eventual `out of fuel` trap still fires).
/// 2. Returns the `NOT_YET_ACTIVATED_CODE` error code.
///
/// All §16.2 imports today have an `i32` result. The match below is
/// keyed on arity (0..=4) and closes over the import name only.
fn link_new_host_import_stubs(linker: &mut Linker<ChainStoreData>) -> anyhow::Result<()> {
    use bloom_objects::host_imports::NEW_HOST_IMPORTS;

    for h in NEW_HOST_IMPORTS {
        // Sanity-check: the §16.2 table is uniformly i32 → i32 today.
        debug_assert!(
            h.results.len() == 1,
            "host import {}.{} has non-singular result arity {}",
            h.module,
            h.name,
            h.results.len()
        );

        let module = h.module;
        let name = h.name;

        match h.params.len() {
            0 => {
                linker.func_wrap(
                    module,
                    name,
                    move |mut caller: Caller<'_, ChainStoreData>| -> i32 {
                        let _ = consume_fuel(&mut caller, 1);
                        NOT_YET_ACTIVATED_CODE
                    },
                )?;
            }
            1 => {
                linker.func_wrap(
                    module,
                    name,
                    move |mut caller: Caller<'_, ChainStoreData>, _a: i32| -> i32 {
                        let _ = consume_fuel(&mut caller, 1);
                        NOT_YET_ACTIVATED_CODE
                    },
                )?;
            }
            2 => {
                linker.func_wrap(
                    module,
                    name,
                    move |mut caller: Caller<'_, ChainStoreData>,
                          _a: i32,
                          _b: i32|
                          -> i32 {
                        let _ = consume_fuel(&mut caller, 1);
                        NOT_YET_ACTIVATED_CODE
                    },
                )?;
            }
            3 => {
                linker.func_wrap(
                    module,
                    name,
                    move |mut caller: Caller<'_, ChainStoreData>,
                          _a: i32,
                          _b: i32,
                          _c: i32|
                          -> i32 {
                        let _ = consume_fuel(&mut caller, 1);
                        NOT_YET_ACTIVATED_CODE
                    },
                )?;
            }
            4 => {
                linker.func_wrap(
                    module,
                    name,
                    move |mut caller: Caller<'_, ChainStoreData>,
                          _a: i32,
                          _b: i32,
                          _c: i32,
                          _d: i32|
                          -> i32 {
                        let _ = consume_fuel(&mut caller, 1);
                        NOT_YET_ACTIVATED_CODE
                    },
                )?;
            }
            n => {
                anyhow::bail!(
                    "unsupported arity {n} for Phase-1 stub of {module}.{name}; \
                     update link_new_host_import_stubs"
                );
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sub-call error type (carries snapshot back on failure for revert semantics)
// ---------------------------------------------------------------------------

enum SubCallError {
    Reverted { snapshot: Box<StateSnapshot>, reason: Option<Vec<u8>>, fuel_used: u64 },
    Trapped { snapshot: Box<StateSnapshot>, error: Option<String>, fuel_used: u64 },
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

    fn instances(&self) -> usize { CHAIN_MAX_INSTANCES }
    fn tables(&self) -> usize { CHAIN_MAX_TABLES }
    fn memories(&self) -> usize { CHAIN_MAX_MEMORIES }
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

    let store_data = ChainStoreData { chain_ctx, petal_hash };

    let mut store = Store::new(engine, store_data);
    store.set_fuel(input.fuel).map_err(|e| SubCallError::Trapped {
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

    let entry_name = match input.entry {
        ChainEntry::Init => "init",
        ChainEntry::Call => "call",
    };

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
            Err(SubCallError::Reverted { snapshot, reason, fuel_used }) => {
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
                error.map(|s| format!("trapped: {s}")).unwrap_or_else(|| "trapped".into()),
            )),
        }
    }
}
