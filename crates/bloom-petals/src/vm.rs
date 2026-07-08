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

        Ok(RunOutput {
            stdout: stdout.contents().to_vec(),
            stderr: stderr.contents().to_vec(),
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
    }
    Ok(())
}

fn link_imports_for_mode(
    linker: &mut Linker<StoreData>,
    mode: crate::meta::PetalMode,
) -> anyhow::Result<()> {
    use crate::meta::PetalMode;
    match mode {
        PetalMode::Local => link_local_imports(linker),
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

fn log_denied(d: &StoreData, op: &str) {
    tracing::info!(
        target: "bloom_petals::vm",
        petal = %d.petal_hash,
        op,
        "host capability denied"
    );
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

    #[test]
    fn vm_construction_with_deterministic_knobs_succeeds() {
        let vm = PetalVm::new().unwrap();
        drop(vm);
    }
}
