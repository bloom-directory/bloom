//! Wasmtime-backed petal VM.
//!
//! A petal is a WASI command-style wasm module (exports `_start`,
//! WASI preview 1 stdio). The VM runs it with:
//!
//! * **stdin** = caller-provided bytes (`Vec<u8>`),
//! * **stdout / stderr** = captured into in-memory pipes,
//! * a configurable fuel cap (out-of-fuel surfaces as a trap),
//! * a configurable linear-memory cap (16 MiB by default),
//! * **no filesystem preopens** and **no sockets** — petals reach the
//!   outside only through host imports we explicitly add.
//!
//! On top of WASI we expose the `bloom` host module:
//!
//! ```text
//! (import "bloom" "vfs_read"  (func (param i32 i32 i32 i32) (result i32)))
//! (import "bloom" "vfs_write" (func (param i32 i32 i32 i32) (result i32)))
//! ```
//!
//! `vfs_read(path_ptr, path_len, dst_ptr, dst_max) -> i32` returns the
//! number of bytes written to `dst_ptr` on success, or a negative
//! [`crate::host::HostError`] code. If the response would not fit, the
//! return value is `-1 * (needed_len + 0x10000)` so the petal can
//! detect "buffer too small" by checking whether the magnitude is at
//! least `0x10000` — see [`Self::OVERFLOW_BIAS`].
//!
//! `vfs_write(path_ptr, path_len, src_ptr, src_len) -> i32` returns
//! `0` on success or a negative error code.
//!
//! Both calls fail with [`HostError::Denied`] (`-2`) unless the petal's
//! metadata declared the corresponding capability.

use std::collections::BTreeSet;
use std::sync::Arc;

use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};

use crate::error::PetalError;
use crate::host::{HostError, PetalHost};
use crate::meta::Capability;

const DEFAULT_FUEL: u64 = 100_000_000;
const DEFAULT_MEMORY_PAGES: u32 = 256; // 16 MiB (64 KiB pages).
const STDOUT_CAP: usize = 1 << 20; // 1 MiB.

/// State threaded through `Store<StoreData>`. Owns the WASI context,
/// the host bridge, and the capability set for the petal in flight.
pub struct StoreData {
    wasi: WasiP1Ctx,
    host: Arc<dyn PetalHost>,
    caps: BTreeSet<Capability>,
    petal_hash: String,
    onchain_stdin: Vec<u8>,
    onchain_stdin_pos: usize,
    onchain_stdout: Vec<u8>,
    onchain_stderr: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub fuel: u64,
    pub memory_pages: u32,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL,
            memory_pages: DEFAULT_MEMORY_PAGES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Process exit code, mirroring WASI semantics. `0` means
    /// `_start` returned normally; non-zero means the petal trapped
    /// or called `proc_exit(N)`.
    pub exit_code: i32,
    /// Fuel consumed, when fuel metering is enabled (always, for us).
    pub fuel_consumed: u64,
}

/// One VM. Cheap to clone (shares the `Engine`), so callers can keep
/// a single instance and `run` many petals.
#[derive(Clone)]
pub struct PetalVm {
    engine: Engine,
}

impl PetalVm {
    /// Bias added to the magnitude of a negative return value to mean
    /// "buffer too small; you need this many bytes". A petal can
    /// distinguish a normal negative error code (e.g. `-1` =
    /// `NotFound`) from an overflow indicator by checking
    /// `ret <= -OVERFLOW_BIAS`.
    pub const OVERFLOW_BIAS: i32 = 0x10000;

    pub fn new() -> Result<Self, PetalError> {
        let mut config = Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        // Reasonable defaults for production. Cranelift compiles
        // modules just-in-time on the first instantiate.
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        // Cross-machine determinism cheap-knobs. NaN canonicalization
        // makes float ops bit-identical across CPUs that follow the
        // IEEE spec differently. `wasm_relaxed_simd(true)` is the
        // prerequisite that turns the feature on; `relaxed_simd_
        // deterministic(true)` then pins it to a single profile (so
        // enabling the feature does not widen what a petal can observe
        // across hosts). Engine-version determinism is NOT addressed
        // here.
        config.cranelift_nan_canonicalization(true);
        config.wasm_relaxed_simd(true);
        config.relaxed_simd_deterministic(true);
        let engine = Engine::new(&config).map_err(|e| PetalError::vm(e.to_string()))?;
        Ok(Self { engine })
    }

    /// Run a petal end-to-end: instantiate, call `_start`, collect
    /// captured stdout/stderr, return.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        wasm: &[u8],
        stdin: Vec<u8>,
        caps: BTreeSet<Capability>,
        host: Arc<dyn PetalHost>,
        petal_hash: &str,
        mode: crate::meta::PetalMode,
        opts: RunOptions,
    ) -> Result<RunOutput, PetalError> {
        let module =
            Module::new(&self.engine, wasm).map_err(|e| PetalError::InvalidWasm(e.to_string()))?;

        let stdout = MemoryOutputPipe::new(STDOUT_CAP);
        let stderr = MemoryOutputPipe::new(STDOUT_CAP);

        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder
            .stdin(MemoryInputPipe::new(stdin.clone()))
            .stdout(stdout.clone())
            .stderr(stderr.clone());
        let wasi_ctx = wasi_builder.build_p1();

        let mut store = Store::new(
            &self.engine,
            StoreData {
                wasi: wasi_ctx,
                host,
                caps,
                petal_hash: petal_hash.to_string(),
                onchain_stdin: stdin,
                onchain_stdin_pos: 0,
                onchain_stdout: Vec::new(),
                onchain_stderr: Vec::new(),
            },
        );
        store
            .set_fuel(opts.fuel)
            .map_err(|e| PetalError::vm(e.to_string()))?;
        store.limiter(move |_| {
            // Box-leak a per-store limiter. Simpler than threading a
            // separate field on StoreData; we only need the page cap.
            Box::leak(Box::new(MemLimiter::new(opts.memory_pages)))
        });

        let mut linker = Linker::<StoreData>::new(&self.engine);
        link_wasi_for_mode(&mut linker, mode).map_err(|e| PetalError::vm(e.to_string()))?;
        link_imports_for_mode(&mut linker, mode).map_err(|e| PetalError::vm(e.to_string()))?;

        let exit_code = run_command(&mut store, &linker, &module).await;
        let fuel_consumed = opts.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
        let (stdout_bytes, stderr_bytes) = match mode {
            crate::meta::PetalMode::Onchain => (
                store.data().onchain_stdout.clone(),
                store.data().onchain_stderr.clone(),
            ),
            _ => (stdout.contents().to_vec(), stderr.contents().to_vec()),
        };

        Ok(RunOutput {
            stdout: stdout_bytes,
            stderr: stderr_bytes,
            exit_code,
            fuel_consumed,
        })
    }
}

async fn run_command(
    store: &mut Store<StoreData>,
    linker: &Linker<StoreData>,
    module: &Module,
) -> i32 {
    let instance = match linker.instantiate_async(&mut *store, module).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(target: "bloom_petals::vm", error = %e, "instantiate failed");
            return 127;
        }
    };
    let start = match instance.get_typed_func::<(), ()>(&mut *store, "_start") {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(target: "bloom_petals::vm", error = %e, "petal missing _start");
            return 126;
        }
    };
    match start.call_async(store, ()).await {
        Ok(()) => 0,
        Err(trap) => {
            // WASI's `proc_exit(N)` surfaces as a trap that carries N
            // in the `I32Exit` downcast. Anything else is a real trap.
            if let Some(exit) = trap.root_cause().downcast_ref::<wasmtime_wasi::I32Exit>() {
                exit.0
            } else {
                tracing::info!(target: "bloom_petals::vm", error = %trap, "petal trapped");
                // 137 is the conventional exit code for "killed".
                137
            }
        }
    }
}

fn link_wasi_for_mode(
    linker: &mut Linker<StoreData>,
    mode: crate::meta::PetalMode,
) -> anyhow::Result<()> {
    match mode {
        crate::meta::PetalMode::Local => {
            preview1::add_to_linker_async(linker, |s: &mut StoreData| &mut s.wasi)?;
        }
        crate::meta::PetalMode::Onchain => link_minimal_onchain_wasi(linker)?,
        crate::meta::PetalMode::Chain => {}
    }
    Ok(())
}

fn link_minimal_onchain_wasi(linker: &mut Linker<StoreData>) -> anyhow::Result<()> {
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "proc_exit",
        |code: i32| -> anyhow::Result<()> { Err(anyhow::Error::new(wasmtime_wasi::I32Exit(code))) },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_write",
        |mut caller: Caller<'_, StoreData>,
         fd: i32,
         iovs_ptr: i32,
         iovs_len: i32,
         nwritten_ptr: i32|
         -> i32 {
            let mem = match get_memory(&mut caller) {
                Some(m) => m,
                None => return wasi_errno_inval(),
            };
            let bytes = match read_iovs(&mem, &mut caller, iovs_ptr, iovs_len) {
                Ok(b) => b,
                Err(c) => return c,
            };
            let target = match fd {
                1 => &mut caller.data_mut().onchain_stdout,
                2 => &mut caller.data_mut().onchain_stderr,
                _ => return wasi_errno_badf(),
            };
            if target.len().saturating_add(bytes.len()) > STDOUT_CAP {
                return wasi_errno_inval();
            }
            target.extend_from_slice(&bytes);
            write_u32(&mem, &mut caller, nwritten_ptr, bytes.len() as u32)
        },
    )?;
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_read",
        |mut caller: Caller<'_, StoreData>,
         fd: i32,
         iovs_ptr: i32,
         iovs_len: i32,
         nread_ptr: i32|
         -> i32 {
            if fd != 0 {
                return wasi_errno_badf();
            }
            let mem = match get_memory(&mut caller) {
                Some(m) => m,
                None => return wasi_errno_inval(),
            };
            let iovs = match read_iov_headers(&mem, &mut caller, iovs_ptr, iovs_len) {
                Ok(v) => v,
                Err(c) => return c,
            };
            let mut total = 0usize;
            for (dst, len) in iovs {
                let (chunk, new_pos) = {
                    let d = caller.data();
                    let available = d.onchain_stdin.len().saturating_sub(d.onchain_stdin_pos);
                    let take = available.min(len as usize);
                    (
                        d.onchain_stdin[d.onchain_stdin_pos..d.onchain_stdin_pos + take].to_vec(),
                        d.onchain_stdin_pos + take,
                    )
                };
                if chunk.is_empty() {
                    break;
                }
                if let Err(c) = write_bytes(&mem, &mut caller, dst, &chunk) {
                    return c;
                }
                caller.data_mut().onchain_stdin_pos = new_pos;
                total += chunk.len();
            }
            write_u32(&mem, &mut caller, nread_ptr, total as u32)
        },
    )?;
    Ok(())
}

fn link_imports_for_mode(
    linker: &mut Linker<StoreData>,
    mode: crate::meta::PetalMode,
) -> anyhow::Result<()> {
    use crate::meta::PetalMode;
    match mode {
        PetalMode::Local => link_local_imports(linker),
        PetalMode::Onchain => link_onchain_imports(linker),
        PetalMode::Chain => {
            // Chain mode uses its own engine/store type (ChainStoreData) and
            // is driven via PetalVm::run_chain_call, not via PetalVm::run.
            // If someone calls PetalVm::run with Chain mode, return an error
            // rather than silently running with no imports.
            Err(anyhow::anyhow!(
                "PetalMode::Chain is not supported via PetalVm::run; use PetalVm::run_chain_call"
            ))
        }
    }
}

fn link_local_imports(linker: &mut Linker<StoreData>) -> anyhow::Result<()> {
    linker.func_wrap_async(
        "bloom",
        "vfs_read",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (path_ptr, path_len, dst_ptr, dst_max) = params;
            Box::new(async move {
                let cap_ok = caller.data().caps.contains(&Capability::VfsRead);
                if !cap_ok {
                    log_denied(caller.data(), "vfs_read");
                    return HostError::Denied("vfs.read".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let path = match read_string(&mem, &mut caller, path_ptr, path_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let host = caller.data().host.clone();
                match host.vfs_read(&path).await {
                    Ok(bytes) => {
                        if dst_max < 0 {
                            return HostError::Invalid("dst_max < 0".into()).as_wasm_code();
                        }
                        let need = bytes.len();
                        if need > dst_max as usize {
                            return -((need as i32).saturating_add(PetalVm::OVERFLOW_BIAS));
                        }
                        if let Err(c) = write_bytes(&mem, &mut caller, dst_ptr, &bytes) {
                            return c;
                        }
                        need as i32
                    }
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom",
        "vfs_write",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (path_ptr, path_len, src_ptr, src_len) = params;
            Box::new(async move {
                let cap_ok = caller.data().caps.contains(&Capability::VfsWrite);
                if !cap_ok {
                    log_denied(caller.data(), "vfs_write");
                    return HostError::Denied("vfs.write".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let path = match read_string(&mem, &mut caller, path_ptr, path_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let bytes = match read_bytes(&mem, &mut caller, src_ptr, src_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let host = caller.data().host.clone();
                match host.vfs_write(&path, &bytes).await {
                    Ok(()) => 0,
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;
    Ok(())
}

fn link_onchain_imports(linker: &mut Linker<StoreData>) -> anyhow::Result<()> {
    linker.func_wrap_async(
        "bloom",
        "chain_read_at",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i64, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (chain_ptr, chain_len, block, dst_ptr, dst_max) = params;
            Box::new(async move {
                let cap_ok = caller.data().caps.contains(&Capability::ChainRead);
                if !cap_ok {
                    log_denied(caller.data(), "chain_read_at");
                    return HostError::Denied("chain.read".into()).as_wasm_code();
                }
                if block == 0 {
                    return HostError::BlockNotPinnable.as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                // Spec ABI: one utf-8 path buffer in the existing
                // `chains/<chain>/...` namespace. For compatibility with
                // early fixtures we also accept `<chain>\0<path>`.
                let raw = match read_bytes(&mem, &mut caller, chain_ptr, chain_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let raw = match String::from_utf8(raw) {
                    Ok(s) => s,
                    Err(_) => return HostError::Invalid("path not utf-8".into()).as_wasm_code(),
                };
                let (chain, path) = match raw.split_once('\0') {
                    Some((chain, path)) if !chain.is_empty() && !path.is_empty() => {
                        (chain.to_string(), path.to_string())
                    }
                    Some(_) => {
                        return HostError::Invalid("chain_read_at: empty chain/path".into())
                            .as_wasm_code();
                    }
                    None => match parse_chain_path(&raw) {
                        Some((chain, path)) => (chain, path),
                        None => {
                            return HostError::Invalid(
                                "chain_read_at: expected chains/<chain>/... path".into(),
                            )
                            .as_wasm_code();
                        }
                    },
                };
                let host = caller.data().host.clone();
                match host.chain_read_at(&chain, &path, block as u64).await {
                    Ok(bytes) => {
                        if dst_max < 0 {
                            return HostError::Invalid("dst_max < 0".into()).as_wasm_code();
                        }
                        let need = bytes.len();
                        if need > dst_max as usize {
                            return -((need as i32).saturating_add(PetalVm::OVERFLOW_BIAS));
                        }
                        if let Err(c) = write_bytes(&mem, &mut caller, dst_ptr, &bytes) {
                            return c;
                        }
                        need as i32
                    }
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;
    Ok(())
}

fn log_denied(d: &StoreData, op: &str) {
    tracing::info!(
        target: "bloom_petals::vm",
        petal = %d.petal_hash,
        op,
        "host capability denied"
    );
}

fn parse_chain_path(path: &str) -> Option<(String, String)> {
    let normalized = path.trim_start_matches('/');
    let rest = normalized.strip_prefix("chains/")?;
    let (chain, tail) = rest.split_once('/')?;
    if chain.is_empty() || tail.is_empty() {
        return None;
    }
    Some((chain.to_string(), normalized.to_string()))
}

fn get_memory(caller: &mut Caller<'_, StoreData>) -> Option<Memory> {
    caller.get_export("memory").and_then(|e| e.into_memory())
}

fn read_string(
    mem: &Memory,
    caller: &mut Caller<'_, StoreData>,
    ptr: i32,
    len: i32,
) -> Result<String, i32> {
    let bytes = read_bytes(mem, caller, ptr, len)?;
    String::from_utf8(bytes).map_err(|_| HostError::Invalid("path not utf-8".into()).as_wasm_code())
}

fn read_bytes(
    mem: &Memory,
    caller: &mut Caller<'_, StoreData>,
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

fn write_bytes(
    mem: &Memory,
    caller: &mut Caller<'_, StoreData>,
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

fn read_iov_headers(
    mem: &Memory,
    caller: &mut Caller<'_, StoreData>,
    iovs_ptr: i32,
    iovs_len: i32,
) -> Result<Vec<(i32, i32)>, i32> {
    if iovs_ptr < 0 || iovs_len < 0 {
        return Err(wasi_errno_inval());
    }
    let mut iovs = Vec::with_capacity(iovs_len as usize);
    let data = mem.data(caller);
    let base = iovs_ptr as usize;
    for idx in 0..iovs_len as usize {
        let off = base
            .checked_add(idx.saturating_mul(8))
            .ok_or_else(wasi_errno_inval)?;
        let end = off.checked_add(8).ok_or_else(wasi_errno_inval)?;
        let raw = data.get(off..end).ok_or_else(wasi_errno_inval)?;
        let ptr = i32::from_le_bytes(raw[0..4].try_into().expect("slice length"));
        let len = i32::from_le_bytes(raw[4..8].try_into().expect("slice length"));
        if ptr < 0 || len < 0 {
            return Err(wasi_errno_inval());
        }
        iovs.push((ptr, len));
    }
    Ok(iovs)
}

fn read_iovs(
    mem: &Memory,
    caller: &mut Caller<'_, StoreData>,
    iovs_ptr: i32,
    iovs_len: i32,
) -> Result<Vec<u8>, i32> {
    let iovs = read_iov_headers(mem, caller, iovs_ptr, iovs_len)?;
    let mut out = Vec::new();
    for (ptr, len) in iovs {
        out.extend(read_bytes(mem, caller, ptr, len)?);
    }
    Ok(out)
}

fn write_u32(mem: &Memory, caller: &mut Caller<'_, StoreData>, ptr: i32, value: u32) -> i32 {
    match write_bytes(mem, caller, ptr, &value.to_le_bytes()) {
        Ok(()) => 0,
        Err(_) => wasi_errno_inval(),
    }
}

fn wasi_errno_badf() -> i32 {
    8
}

fn wasi_errno_inval() -> i32 {
    28
}

/// Memory growth limiter. We only care about the page cap; everything
/// else uses wasmtime's defaults.
struct MemLimiter {
    max_pages: usize,
}

impl MemLimiter {
    fn new(pages: u32) -> Self {
        Self {
            max_pages: pages as usize,
        }
    }
}

impl wasmtime::ResourceLimiter for MemLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // `desired` is in bytes; convert to pages and compare.
        let pages = desired.div_ceil(64 * 1024);
        Ok(pages <= self.max_pages)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }
}

impl Default for PetalVm {
    fn default() -> Self {
        Self::new().expect("Engine::new with default Config never fails on a healthy system")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::DenyHost;
    use crate::meta::PetalMode;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    /// Compile a WAT snippet to wasm bytes.
    fn wat(src: &str) -> Vec<u8> {
        wat::parse_str(src).expect("valid WAT")
    }

    /// Smallest valid WASI command: imports `proc_exit(0)` and calls it.
    /// We can't easily test `_start` without WASI's full preview1
    /// import shape, so the tests below build modules that import
    /// only what they use.
    const NOOP_WASI: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            i32.const 0
            call $exit)
        )
    "#;

    #[tokio::test]
    async fn runs_noop_petal_and_returns_exit_code_zero() {
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(NOOP_WASI),
                Vec::new(),
                BTreeSet::new(),
                Arc::new(DenyHost),
                "deadbeef",
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.is_empty());
        assert!(out.fuel_consumed > 0);
    }

    /// Petal that writes to stdout via `fd_write`. We do this by
    /// composing a tiny WASI command that writes a fixed buffer.
    const HELLO_WASI: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          ;; "hi\n" at offset 0; iovec at offset 16 pointing at it.
          (data (i32.const 0) "hi\n")
          (data (i32.const 16) "\00\00\00\00\03\00\00\00") ;; ptr=0, len=3
          (func (export "_start")
            (call $fd_write
              (i32.const 1)   ;; stdout
              (i32.const 16)  ;; iovec ptr
              (i32.const 1)   ;; iovec count
              (i32.const 32)) ;; nwritten ptr
            drop
            (call $exit (i32.const 0)))
        )
    "#;

    #[tokio::test]
    async fn captures_stdout_from_wasi_fd_write() {
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(HELLO_WASI),
                Vec::new(),
                BTreeSet::new(),
                Arc::new(DenyHost),
                "deadbeef",
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, b"hi\n");
    }

    #[tokio::test]
    async fn onchain_mode_allows_stdio_but_not_full_wasi() {
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(HELLO_WASI),
                Vec::new(),
                BTreeSet::new(),
                Arc::new(DenyHost),
                "h",
                PetalMode::Onchain,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, b"hi\n");
    }

    /// Petal that calls `bloom.vfs_read("k")` and writes the resulting
    /// length (as a single byte) to stdout. Tests the host bridge +
    /// capability gating.
    const READ_PROBE: &str = r#"
        (module
          (import "bloom" "vfs_read"
            (func $vfs_read (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          ;; layout:
          ;;   [0..1)    "k"  (path)
          ;;   [16..272) destination buffer (256 bytes)
          ;;   [400..408) iovec: ptr=412, len=1
          ;;   [412..)   output byte
          (data (i32.const 0) "k")
          (data (i32.const 400) "\9c\01\00\00\01\00\00\00")
          (func (export "_start")
            (local $n i32)
            (local.set $n
              (call $vfs_read
                (i32.const 0)    ;; path_ptr
                (i32.const 1)    ;; path_len
                (i32.const 16)   ;; dst_ptr
                (i32.const 256))) ;; dst_max
            ;; Write low byte of $n to address 412.
            (i32.store8 (i32.const 412) (local.get $n))
            (call $fd_write
              (i32.const 1)
              (i32.const 400)
              (i32.const 1)
              (i32.const 420))
            drop
            (call $exit (i32.const 0)))
        )
    "#;

    #[derive(Default)]
    struct MockHost {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl PetalHost for MockHost {
        async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
            self.store
                .lock()
                .get(path)
                .cloned()
                .ok_or_else(|| HostError::NotFound(path.into()))
        }
        async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
            self.store.lock().insert(path.into(), bytes.to_vec());
            Ok(())
        }
        async fn chain_read_at(
            &self,
            chain: &str,
            path: &str,
            block: u64,
        ) -> Result<Vec<u8>, HostError> {
            let key = format!("@{block}:{chain}/{path}");
            self.store
                .lock()
                .get(&key)
                .cloned()
                .ok_or_else(|| HostError::NotFound(key))
        }
    }

    #[tokio::test]
    async fn vfs_read_denied_without_capability() {
        let vm = PetalVm::new().unwrap();
        let host = Arc::new(MockHost::default());
        host.store.lock().insert("k".into(), b"VALUE".to_vec());
        let out = vm
            .run(
                &wat(READ_PROBE),
                Vec::new(),
                BTreeSet::new(), // no caps
                host,
                "h",
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
        // -2 as a single byte = 254.
        assert_eq!(
            out.stdout,
            vec![(HostError::Denied("".into()).as_wasm_code() as i8) as u8]
        );
    }

    #[tokio::test]
    async fn vfs_read_returns_payload_length_when_allowed() {
        let vm = PetalVm::new().unwrap();
        let host = Arc::new(MockHost::default());
        host.store.lock().insert("k".into(), b"VALUE".to_vec());
        let mut caps = BTreeSet::new();
        caps.insert(Capability::VfsRead);
        let out = vm
            .run(
                &wat(READ_PROBE),
                Vec::new(),
                caps,
                host,
                "h",
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, vec![5u8]); // "VALUE".len()
    }

    const ONCHAIN_TRIES_VFS_READ: &str = r#"
        (module
          (import "bloom" "vfs_read"
            (func $vfs_read (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "_start") nop)
        )
    "#;

    #[tokio::test]
    async fn onchain_vm_refuses_to_link_vfs_imports() {
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(ONCHAIN_TRIES_VFS_READ),
                Vec::new(),
                BTreeSet::new(),
                Arc::new(DenyHost),
                "h",
                PetalMode::Onchain,
                RunOptions::default(),
            )
            .await
            .unwrap();
        // Instantiation should fail (linker has no bloom.vfs_read in onchain mode).
        assert_eq!(out.exit_code, 127);
    }

    const ONCHAIN_TRIES_RANDOM: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "random_get"
            (func $random_get (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            (drop (call $random_get (i32.const 0) (i32.const 8)))))
    "#;

    const ONCHAIN_TRIES_CLOCK: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "clock_time_get"
            (func $clock_time_get (param i32 i64 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            (drop (call $clock_time_get (i32.const 0) (i64.const 1) (i32.const 0)))))
    "#;

    #[tokio::test]
    async fn onchain_vm_refuses_to_link_random_and_clock() {
        let vm = PetalVm::new().unwrap();
        for wat_src in [ONCHAIN_TRIES_RANDOM, ONCHAIN_TRIES_CLOCK] {
            let out = vm
                .run(
                    &wat(wat_src),
                    Vec::new(),
                    BTreeSet::new(),
                    Arc::new(DenyHost),
                    "h",
                    PetalMode::Onchain,
                    RunOptions::default(),
                )
                .await
                .unwrap();
            assert_eq!(out.exit_code, 127);
        }
    }

    #[tokio::test]
    async fn local_run_takes_mode_parameter_and_keeps_working() {
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(NOOP_WASI),
                Vec::new(),
                BTreeSet::new(),
                Arc::new(DenyHost),
                "h",
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
    }

    const LOCAL_TRIES_CHAIN_READ: &str = r#"
        (module
          (import "bloom" "chain_read_at"
            (func $chain_read_at (param i32 i32 i64 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "_start") nop)
        )
    "#;

    #[tokio::test]
    async fn local_vm_refuses_to_link_chain_imports() {
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(LOCAL_TRIES_CHAIN_READ),
                Vec::new(),
                BTreeSet::new(),
                Arc::new(DenyHost),
                "h",
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
        // Instantiation should fail (linker has no bloom.chain_read_at in local mode).
        assert_eq!(out.exit_code, 127);
    }

    #[test]
    fn vm_construction_with_deterministic_knobs_succeeds() {
        let vm = PetalVm::new().unwrap();
        drop(vm);
    }
}
