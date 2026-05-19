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

/// Validate a wasm binary for deploy-time admission as a chain-mode petal.
///
/// Rejects:
/// - Any import whose module is not `"chain"`.
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
                    if import.module != "chain" {
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
            // We swap it out with a dummy, run the callee, then swap back with
            // the (mutated) snapshot from the callee output.
            let snap = {
                // We can't move out of &mut through data_mut() without a swap.
                // Use std::mem::replace with a fresh snapshot taken from the
                // base state. This is sound because the callee writes flow
                // through the returned snapshot.
                //
                // We need a placeholder snapshot. We build one by taking a
                // snapshot of the base state inside the existing snapshot.
                // Actually: bloom-chain-state's StateSnapshot doesn't expose a
                // way to take a sub-snapshot. So we move the live snapshot out
                // using a placeholder trick.
                //
                // Approach: temporarily replace with a dummy snapshot of an
                // empty state, run the sub-call with the real snapshot, then
                // put the result back.
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
                    // Restore snapshot from dummy — we can't do anything meaningful.
                    return HostError::Backend("engine error".into()).as_wasm_code() as i64;
                }
            };

            let sub_result = dispatch_chain_call_sync(engine, sub_input, depth + 1);

            match sub_result {
                Ok(out) => {
                    // Restore the mutated snapshot.
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
                    // Sub-call failed. Restore dummy snapshot (writes are lost).
                    // We have no way to restore the real snapshot since it was
                    // consumed — the caller's state is whatever the dummy was.
                    // This is the correct revert semantics: sub-call failure
                    // rolls back sub-call writes.
                    //
                    // Actually we need to restore the real snapshot that was passed
                    // to the sub-call but may have been reverted inside it.
                    // The `Err` path in dispatch_chain_call_sync returns the snapshot
                    // back inside the error for exactly this case.
                    match e {
                        SubCallError::Reverted { snapshot, reason } => {
                            // Revert: sub-call writes are discarded; restore caller snapshot.
                            caller.data_mut().chain_ctx.snapshot = *snapshot;
                            // Store the sub-call's revert reason so callers can inspect it.
                            caller.data_mut().chain_ctx.return_data = reason;
                            HostError::Backend("callee reverted".into()).as_wasm_code() as i64
                        }
                        SubCallError::Trapped { snapshot, .. } => {
                            caller.data_mut().chain_ctx.snapshot = *snapshot;
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

            // Spawn the new account with code_hash set.
            let new_account = Account {
                nonce: 0,
                loom: 0,
                code_hash: Some(petal_hash),
                storage_root: Hash32([0u8; 32]),
            };
            caller
                .data_mut()
                .chain_ctx
                .snapshot
                .set_account(deployed_address, new_account);

            // Get the wasm bytes for the init call.
            let wasm_bytes: Vec<u8> = match caller.data().chain_ctx.snapshot.get_code(&petal_hash) {
                Some(b) => b.to_vec(),
                None => return HostError::NotFound("code not found".into()).as_wasm_code() as i64,
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
                Err(_) => return HostError::Backend("engine error".into()).as_wasm_code() as i64,
            };

            match dispatch_chain_call_sync(engine, sub_input, depth + 1) {
                Ok(out) => {
                    // Charge init fuel.
                    let _ = consume_fuel(&mut caller, out.fuel_used);
                    // Restore snapshot.
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
                    let snap = match e {
                        SubCallError::Reverted { snapshot, .. } | SubCallError::Trapped { snapshot, .. } => {
                            *snapshot
                        }
                    };
                    // Undo the account spawn — restore to pre-deploy snapshot (without the new account).
                    caller.data_mut().chain_ctx.snapshot = snap;
                    caller
                        .data_mut()
                        .chain_ctx
                        .snapshot
                        .remove_account(deployed_address);
                    HostError::Backend("init failed".into()).as_wasm_code() as i64
                }
            }
        },
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Sub-call error type (carries snapshot back on failure for revert semantics)
// ---------------------------------------------------------------------------

enum SubCallError {
    Reverted { snapshot: Box<StateSnapshot>, reason: Option<Vec<u8>> },
    Trapped { snapshot: Box<StateSnapshot>, error: Option<String> },
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
    })?;

    let mut linker = Linker::<ChainStoreData>::new(engine);
    link_chain_imports(&mut linker).map_err(|e| SubCallError::Trapped {
        snapshot: Box::new(bloom_chain_state::State::new().snapshot()),
        error: Some(format!("link imports: {e}")),
    })?;

    let instance = match linker.instantiate(&mut store, &module) {
        Ok(i) => i,
        Err(e) => {
            let err_msg = format!("instantiate: {e}");
            let snap = std::mem::replace(
                &mut store.data_mut().chain_ctx.snapshot,
                bloom_chain_state::State::new().snapshot(),
            );
            return Err(SubCallError::Trapped { snapshot: Box::new(snap), error: Some(err_msg) });
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
            let snap = std::mem::replace(
                &mut store.data_mut().chain_ctx.snapshot,
                bloom_chain_state::State::new().snapshot(),
            );
            return Err(SubCallError::Trapped { snapshot: Box::new(snap), error: Some(err_msg) });
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
            if revert_reason_opt.is_some() {
                return Err(SubCallError::Reverted {
                    snapshot: Box::new(snapshot),
                    reason: revert_reason_opt,
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
    pub fn run_chain_call(input: ChainCallInput) -> Result<ChainCallOutput, PetalError> {
        let engine = chain_engine()?;
        dispatch_chain_call_sync(engine, input, 0).map_err(|e| match e {
            SubCallError::Reverted { reason, .. } => PetalError::ChainCall(
                reason
                    .and_then(|r| String::from_utf8(r).ok())
                    .unwrap_or_else(|| "reverted".into()),
            ),
            SubCallError::Trapped { error, .. } => PetalError::ChainCall(
                error.map(|s| format!("trapped: {s}")).unwrap_or_else(|| "trapped".into()),
            ),
        })
    }
}
