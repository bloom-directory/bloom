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
use std::path::PathBuf;
use std::sync::Arc;

use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};

use crate::abi::{
    DispatchRequest, DispatchResponse, decode_dispatch_response, decode_http_request,
    decode_sign_request, encode_dispatch_request, encode_http_response, encode_string_list,
};
use crate::error::PetalError;
use crate::host::{HostError, PetalHost};
use crate::meta::Capability;
use crate::policy::NetPolicy;
use crate::private_store::PrivateStore;

const DEFAULT_FUEL: u64 = 100_000_000;
const DEFAULT_MEMORY_PAGES: u32 = 256; // 16 MiB (64 KiB pages).
const STDOUT_CAP: usize = 1 << 20; // 1 MiB.
const DEFAULT_HTTP_RESPONSE_CAP: usize = 8 * 1024 * 1024;

/// State threaded through `Store<StoreData>`. Owns the WASI context,
/// the host bridge, and the capability set for the petal in flight.
pub struct StoreData {
    wasi: WasiP1Ctx,
    host: Arc<dyn PetalHost>,
    caps: BTreeSet<Capability>,
    petal_hash: String,
    net_policy: NetPolicy,
    http_response_cap: usize,
    private_store: Option<PrivateStore>,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub fuel: u64,
    pub memory_pages: u32,
    /// Optional runtime network mask. When running through [`PetalRunner`],
    /// this is intersected with the manifest-declared policy and can only
    /// narrow it. Direct VM callers that omit it get deny-all.
    pub net_policy: Option<NetPolicy>,
    pub http_response_cap: usize,
    pub private_store_root: Option<PathBuf>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL,
            memory_pages: DEFAULT_MEMORY_PAGES,
            net_policy: None,
            http_response_cap: DEFAULT_HTTP_RESPONSE_CAP,
            private_store_root: None,
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

#[derive(Debug, Clone)]
pub struct DispatchOutput {
    pub response: DispatchResponse,
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
                net_policy: opts.net_policy.clone().unwrap_or_else(NetPolicy::deny_all),
                http_response_cap: opts.http_response_cap,
                private_store: match opts.private_store_root.clone() {
                    Some(root) => Some(
                        PrivateStore::open(root)
                            .map_err(|e| PetalError::vm(format!("private store open: {e}")))?,
                    ),
                    None => None,
                },
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

    /// Dispatch one VFS operation into a local handler petal.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch(
        &self,
        wasm: &[u8],
        request: DispatchRequest,
        caps: BTreeSet<Capability>,
        host: Arc<dyn PetalHost>,
        petal_hash: &str,
        opts: RunOptions,
    ) -> Result<DispatchOutput, PetalError> {
        let module =
            Module::new(&self.engine, wasm).map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
        let stdout = MemoryOutputPipe::new(STDOUT_CAP);
        let stderr = MemoryOutputPipe::new(STDOUT_CAP);
        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder
            .stdin(MemoryInputPipe::new(Vec::new()))
            .stdout(stdout)
            .stderr(stderr);
        let wasi_ctx = wasi_builder.build_p1();

        let mut store = Store::new(
            &self.engine,
            StoreData {
                wasi: wasi_ctx,
                host,
                caps,
                petal_hash: petal_hash.to_string(),
                net_policy: opts.net_policy.clone().unwrap_or_else(NetPolicy::deny_all),
                http_response_cap: opts.http_response_cap,
                private_store: match opts.private_store_root.clone() {
                    Some(root) => Some(
                        PrivateStore::open(root)
                            .map_err(|e| PetalError::vm(format!("private store open: {e}")))?,
                    ),
                    None => None,
                },
            },
        );
        store
            .set_fuel(opts.fuel)
            .map_err(|e| PetalError::vm(e.to_string()))?;
        store.limiter(move |_| Box::leak(Box::new(MemLimiter::new(opts.memory_pages))));

        let mut linker = Linker::<StoreData>::new(&self.engine);
        link_wasi_for_mode(&mut linker, crate::meta::PetalMode::Local)
            .map_err(|e| PetalError::vm(e.to_string()))?;
        link_imports_for_mode(&mut linker, crate::meta::PetalMode::Local)
            .map_err(|e| PetalError::vm(e.to_string()))?;

        let response = dispatch_once(&mut store, &linker, &module, &request).await?;
        let fuel_consumed = opts.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
        Ok(DispatchOutput {
            response,
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

async fn dispatch_once(
    store: &mut Store<StoreData>,
    linker: &Linker<StoreData>,
    module: &Module,
    request: &DispatchRequest,
) -> Result<DispatchResponse, PetalError> {
    let instance = linker
        .instantiate_async(&mut *store, module)
        .await
        .map_err(|e| PetalError::vm(format!("dispatch instantiate: {e}")))?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&mut *store, "petal_alloc")
        .map_err(|e| PetalError::vm(format!("missing petal_alloc: {e}")))?;
    let dispatch = instance
        .get_typed_func::<(i32, i32), i64>(&mut *store, "petal_dispatch")
        .map_err(|e| PetalError::vm(format!("missing petal_dispatch: {e}")))?;
    let request_bytes = encode_dispatch_request(request);
    if request_bytes.len() > i32::MAX as usize {
        return Err(PetalError::vm("dispatch request too large"));
    }
    let req_ptr = alloc
        .call_async(&mut *store, request_bytes.len() as i32)
        .await
        .map_err(|e| PetalError::vm(format!("petal_alloc trapped: {e}")))?;
    let mem = instance
        .get_memory(&mut *store, "memory")
        .ok_or_else(|| PetalError::vm("dispatch petal did not export memory"))?;
    write_bytes_store(&mem, &mut *store, req_ptr, &request_bytes)
        .map_err(|code| PetalError::vm(format!("write dispatch request failed: {code}")))?;
    let packed = dispatch
        .call_async(&mut *store, (req_ptr, request_bytes.len() as i32))
        .await
        .map_err(|e| PetalError::vm(format!("petal_dispatch trapped: {e}")))?;
    let packed = packed as u64;
    let resp_ptr = (packed >> 32) as i32;
    let resp_len = (packed & 0xffff_ffff) as i32;
    let response_bytes = read_bytes_store(&mem, &mut *store, resp_ptr, resp_len)
        .map_err(|code| PetalError::vm(format!("read dispatch response failed: {code}")))?;
    decode_dispatch_response(&response_bytes).map_err(|e| PetalError::vm(e.to_string()))
}

fn link_wasi_for_mode(
    linker: &mut Linker<StoreData>,
    mode: crate::meta::PetalMode,
) -> anyhow::Result<()> {
    match mode {
        crate::meta::PetalMode::Local => {
            preview1::add_to_linker_async(linker, |s: &mut StoreData| &mut s.wasi)?;
        }
        crate::meta::PetalMode::Chain => {}
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
    link_vfs_imports(linker, "bloom")?;
    link_vfs_imports(linker, "bloom.v1")?;
    link_vfs_list_import(linker, "bloom.v1")?;
    link_bloom_v1_imports(linker)?;
    Ok(())
}

fn link_vfs_imports(linker: &mut Linker<StoreData>, module: &'static str) -> anyhow::Result<()> {
    linker.func_wrap_async(
        module,
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
        module,
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

fn link_vfs_list_import(
    linker: &mut Linker<StoreData>,
    module: &'static str,
) -> anyhow::Result<()> {
    linker.func_wrap_async(
        module,
        "vfs_list",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (path_ptr, path_len, dst_ptr, dst_max) = params;
            Box::new(async move {
                let cap_ok = caller.data().caps.contains(&Capability::VfsRead);
                if !cap_ok {
                    log_denied(caller.data(), "vfs_list");
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
                match host.vfs_list(&path).await {
                    Ok(names) => write_blob_response(
                        &mem,
                        &mut caller,
                        dst_ptr,
                        dst_max,
                        &encode_string_list(&names),
                    ),
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    Ok(())
}

fn link_bloom_v1_imports(linker: &mut Linker<StoreData>) -> anyhow::Result<()> {
    linker.func_wrap_async(
        "bloom.v1",
        "http_fetch",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (req_ptr, req_len, dst_ptr, dst_max) = params;
            Box::new(async move {
                if !caller.data().caps.contains(&Capability::NetFetch) {
                    log_denied(caller.data(), "http_fetch");
                    return HostError::Denied("net.fetch".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let req_bytes = match read_bytes(&mem, &mut caller, req_ptr, req_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let req = match decode_http_request(&req_bytes) {
                    Ok(req) => req,
                    Err(e) => return e.as_wasm_code(),
                };
                let audit = http_audit_target(&req.url);
                let effective_policy = caller.data().net_policy.clone();
                if let Err(e) = effective_policy.check(&req.method, &req.url) {
                    tracing::info!(
                        target: "bloom_petals::vm",
                        petal = %caller.data().petal_hash,
                        method = %req.method,
                        host = audit.host.as_deref().unwrap_or("<invalid>"),
                        path = audit.path.as_deref().unwrap_or("<invalid>"),
                        "http_fetch denied by net policy"
                    );
                    return e.as_wasm_code();
                }
                let host = caller.data().host.clone();
                let cap = caller.data().http_response_cap;
                let req_body_len = req.body.len();
                let method = req.method.clone();
                match host.http_fetch(req, effective_policy, cap).await {
                    Ok(resp) => {
                        let encoded = encode_http_response(&resp);
                        if resp.body.len() > cap || encoded.len() > cap {
                            return HostError::Backend("http response too large".into())
                                .as_wasm_code();
                        }
                        tracing::info!(
                            target: "bloom_petals::vm",
                            petal = %caller.data().petal_hash,
                            method = %method,
                            host = audit.host.as_deref().unwrap_or("<invalid>"),
                            path = audit.path.as_deref().unwrap_or("<invalid>"),
                            status = resp.status,
                            request_bytes = req_body_len,
                            response_bytes = resp.body.len(),
                            "http_fetch allowed"
                        );
                        write_blob_response(&mem, &mut caller, dst_ptr, dst_max, &encoded)
                    }
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom.v1",
        "sign_hash",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (req_ptr, req_len, dst_ptr, dst_max) = params;
            Box::new(async move {
                if !caller.data().caps.contains(&Capability::Sign) {
                    log_denied(caller.data(), "sign_hash");
                    return HostError::Denied("sign".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let req_bytes = match read_bytes(&mem, &mut caller, req_ptr, req_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let req = match decode_sign_request(&req_bytes) {
                    Ok(req) => req,
                    Err(e) => return e.as_wasm_code(),
                };
                let host = caller.data().host.clone();
                match host.sign_hash(req).await {
                    Ok(sig) if sig.len() == 65 => {
                        write_blob_response(&mem, &mut caller, dst_ptr, dst_max, &sig)
                    }
                    Ok(_) => HostError::Backend("sign_hash returned non-65-byte signature".into())
                        .as_wasm_code(),
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom.v1",
        "store_get",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (key_ptr, key_len, dst_ptr, dst_max) = params;
            Box::new(async move {
                if !caller.data().caps.contains(&Capability::Store) {
                    log_denied(caller.data(), "store_get");
                    return HostError::Denied("store".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let key = match read_string(&mem, &mut caller, key_ptr, key_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let Some(store) = caller.data().private_store.clone() else {
                    return HostError::Denied("store unavailable".into()).as_wasm_code();
                };
                let petal_hash = caller.data().petal_hash.clone();
                match store.get(&petal_hash, &key) {
                    Ok(bytes) => write_blob_response(&mem, &mut caller, dst_ptr, dst_max, &bytes),
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom.v1",
        "store_put",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (key_ptr, key_len, val_ptr, val_len, secret_flag) = params;
            Box::new(async move {
                if !caller.data().caps.contains(&Capability::Store) {
                    log_denied(caller.data(), "store_put");
                    return HostError::Denied("store".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let key = match read_string(&mem, &mut caller, key_ptr, key_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let value = match read_bytes(&mem, &mut caller, val_ptr, val_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let Some(store) = caller.data().private_store.clone() else {
                    return HostError::Denied("store unavailable".into()).as_wasm_code();
                };
                let petal_hash = caller.data().petal_hash.clone();
                match store.put(&petal_hash, &key, &value, secret_flag != 0) {
                    Ok(()) => 0,
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom.v1",
        "store_put_new",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (key_ptr, key_len, val_ptr, val_len, secret_flag) = params;
            Box::new(async move {
                if !caller.data().caps.contains(&Capability::Store) {
                    log_denied(caller.data(), "store_put_new");
                    return HostError::Denied("store".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let key = match read_string(&mem, &mut caller, key_ptr, key_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let value = match read_bytes(&mem, &mut caller, val_ptr, val_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let Some(store) = caller.data().private_store.clone() else {
                    return HostError::Denied("store unavailable".into()).as_wasm_code();
                };
                let petal_hash = caller.data().petal_hash.clone();
                match store.put_new(&petal_hash, &key, &value, secret_flag != 0) {
                    Ok(()) => 0,
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom.v1",
        "store_list",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (prefix_ptr, prefix_len, dst_ptr, dst_max) = params;
            Box::new(async move {
                if !caller.data().caps.contains(&Capability::Store) {
                    log_denied(caller.data(), "store_list");
                    return HostError::Denied("store".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let prefix = match read_string(&mem, &mut caller, prefix_ptr, prefix_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let Some(store) = caller.data().private_store.clone() else {
                    return HostError::Denied("store unavailable".into()).as_wasm_code();
                };
                let petal_hash = caller.data().petal_hash.clone();
                match store.list(&petal_hash, &prefix) {
                    Ok(keys) => write_blob_response(
                        &mem,
                        &mut caller,
                        dst_ptr,
                        dst_max,
                        &encode_string_list(&keys),
                    ),
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom.v1",
        "store_del",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (key_ptr, key_len) = params;
            Box::new(async move {
                if !caller.data().caps.contains(&Capability::Store) {
                    log_denied(caller.data(), "store_del");
                    return HostError::Denied("store".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let key = match read_string(&mem, &mut caller, key_ptr, key_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let Some(store) = caller.data().private_store.clone() else {
                    return HostError::Denied("store unavailable".into()).as_wasm_code();
                };
                let petal_hash = caller.data().petal_hash.clone();
                match store.del(&petal_hash, &key) {
                    Ok(()) => 0,
                    Err(e) => e.as_wasm_code(),
                }
            })
        },
    )?;

    linker.func_wrap_async(
        "bloom.v1",
        "store_del_if_value",
        |mut caller: Caller<'_, StoreData>,
         params: (i32, i32, i32, i32)|
         -> Box<dyn std::future::Future<Output = i32> + Send + '_> {
            let (key_ptr, key_len, expected_ptr, expected_len) = params;
            Box::new(async move {
                if !caller.data().caps.contains(&Capability::Store) {
                    log_denied(caller.data(), "store_del_if_value");
                    return HostError::Denied("store".into()).as_wasm_code();
                }
                let mem = match get_memory(&mut caller) {
                    Some(m) => m,
                    None => return HostError::Invalid("no exported memory".into()).as_wasm_code(),
                };
                let key = match read_string(&mem, &mut caller, key_ptr, key_len) {
                    Ok(s) => s,
                    Err(c) => return c,
                };
                let expected = match read_bytes(&mem, &mut caller, expected_ptr, expected_len) {
                    Ok(b) => b,
                    Err(c) => return c,
                };
                let Some(store) = caller.data().private_store.clone() else {
                    return HostError::Denied("store unavailable".into()).as_wasm_code();
                };
                let petal_hash = caller.data().petal_hash.clone();
                match store.del_if_value(&petal_hash, &key, &expected) {
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

fn write_blob_response(
    mem: &Memory,
    caller: &mut Caller<'_, StoreData>,
    dst_ptr: i32,
    dst_max: i32,
    bytes: &[u8],
) -> i32 {
    if dst_max < 0 {
        return HostError::Invalid("dst_max < 0".into()).as_wasm_code();
    }
    if bytes.len() > i32::MAX as usize {
        return HostError::Backend("response too large".into()).as_wasm_code();
    }
    if bytes.len() > dst_max as usize {
        return -((bytes.len() as i32).saturating_add(PetalVm::OVERFLOW_BIAS));
    }
    match write_bytes(mem, caller, dst_ptr, bytes) {
        Ok(()) => bytes.len() as i32,
        Err(c) => c,
    }
}

#[derive(Debug)]
struct HttpAuditTarget {
    host: Option<String>,
    path: Option<String>,
}

fn http_audit_target(url: &str) -> HttpAuditTarget {
    match url::Url::parse(url) {
        Ok(parsed) => HttpAuditTarget {
            host: parsed.host_str().map(|h| h.to_ascii_lowercase()),
            path: Some(parsed.path().to_string()),
        },
        Err(_) => HttpAuditTarget {
            host: None,
            path: None,
        },
    }
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

fn read_bytes_store(
    mem: &Memory,
    store: &mut Store<StoreData>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, i32> {
    if ptr < 0 || len < 0 {
        return Err(HostError::Invalid("negative ptr/len".into()).as_wasm_code());
    }
    let data = mem.data(&mut *store);
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

fn write_bytes_store(
    mem: &Memory,
    store: &mut Store<StoreData>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), i32> {
    if ptr < 0 {
        return Err(HostError::Invalid("negative ptr".into()).as_wasm_code());
    }
    let data = mem.data_mut(&mut *store);
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
    use crate::abi::{
        DispatchOp, DispatchRequest, DispatchResponse, HttpRequest, HttpResponse, SignRequest,
        encode_dispatch_response, encode_http_request, encode_sign_request,
    };
    use crate::host::DenyHost;
    use crate::meta::PetalMode;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use tempfile::TempDir;

    const VALID_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Compile a WAT snippet to wasm bytes.
    fn wat(src: &str) -> Vec<u8> {
        wat::parse_str(src).expect("valid WAT")
    }

    fn wat_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("\\{b:02x}")).collect()
    }

    fn denied_byte() -> u8 {
        (HostError::Denied("".into()).as_wasm_code() as i8) as u8
    }

    fn invalid_byte() -> u8 {
        (HostError::Invalid("".into()).as_wasm_code() as i8) as u8
    }

    fn http_probe(req: &[u8]) -> String {
        format!(
            r#"
        (module
          (import "bloom.v1" "http_fetch"
            (func $http_fetch (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{}")
          (data (i32.const 400) "\9c\01\00\00\01\00\00\00")
          (func (export "_start")
            (local $n i32)
            (local.set $n
              (call $http_fetch
                (i32.const 0)
                (i32.const {})
                (i32.const 1024)
                (i32.const 4096)))
            (i32.store8 (i32.const 412) (local.get $n))
            (call $fd_write (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 420))
            drop
            (call $exit (i32.const 0)))
        )
    "#,
            wat_bytes(req),
            req.len()
        )
    }

    fn sign_probe(req: &[u8]) -> String {
        format!(
            r#"
        (module
          (import "bloom.v1" "sign_hash"
            (func $sign_hash (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{}")
          (data (i32.const 400) "\9c\01\00\00\01\00\00\00")
          (func (export "_start")
            (local $n i32)
            (local.set $n
              (call $sign_hash
                (i32.const 0)
                (i32.const {})
                (i32.const 1024)
                (i32.const 128)))
            (i32.store8 (i32.const 412) (local.get $n))
            (call $fd_write (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 420))
            drop
            (call $exit (i32.const 0)))
        )
    "#,
            wat_bytes(req),
            req.len()
        )
    }

    fn store_put_get_probe(key: &str, value: &[u8]) -> String {
        format!(
            r#"
        (module
          (import "bloom.v1" "store_put"
            (func $store_put (param i32 i32 i32 i32 i32) (result i32)))
          (import "bloom.v1" "store_get"
            (func $store_get (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{}")
          (data (i32.const 128) "{}")
          (data (i32.const 400) "\9c\01\00\00\01\00\00\00")
          (func (export "_start")
            (local $n i32)
            (call $store_put
              (i32.const 0)
              (i32.const {})
              (i32.const 128)
              (i32.const {})
              (i32.const 1))
            drop
            (local.set $n
              (call $store_get
                (i32.const 0)
                (i32.const {})
                (i32.const 1024)
                (i32.const 256)))
            (i32.store8 (i32.const 412) (local.get $n))
            (call $fd_write (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 420))
            drop
            (call $exit (i32.const 0)))
        )
    "#,
            wat_bytes(key.as_bytes()),
            wat_bytes(value),
            key.len(),
            value.len(),
            key.len()
        )
    }

    fn store_put_new_probe(key: &str, first: &[u8], second: &[u8]) -> String {
        format!(
            r#"
        (module
          (import "bloom.v1" "store_put_new"
            (func $store_put_new (param i32 i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{}")
          (data (i32.const 128) "{}")
          (data (i32.const 256) "{}")
          (data (i32.const 400) "\9c\01\00\00\01\00\00\00")
          (func (export "_start")
            (local $n i32)
            (call $store_put_new
              (i32.const 0)
              (i32.const {})
              (i32.const 128)
              (i32.const {})
              (i32.const 0))
            drop
            (local.set $n
              (call $store_put_new
                (i32.const 0)
                (i32.const {})
                (i32.const 256)
                (i32.const {})
                (i32.const 0)))
            (i32.store8 (i32.const 412) (local.get $n))
            (call $fd_write (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 420))
            drop
            (call $exit (i32.const 0)))
        )
    "#,
            wat_bytes(key.as_bytes()),
            wat_bytes(first),
            wat_bytes(second),
            key.len(),
            first.len(),
            key.len(),
            second.len()
        )
    }

    fn store_del_if_value_probe(key: &str, value: &[u8], expected: &[u8]) -> String {
        format!(
            r#"
        (module
          (import "bloom.v1" "store_put"
            (func $store_put (param i32 i32 i32 i32 i32) (result i32)))
          (import "bloom.v1" "store_del_if_value"
            (func $store_del_if_value (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "{}")
          (data (i32.const 128) "{}")
          (data (i32.const 256) "{}")
          (data (i32.const 400) "\9c\01\00\00\01\00\00\00")
          (func (export "_start")
            (local $n i32)
            (call $store_put
              (i32.const 0)
              (i32.const {})
              (i32.const 128)
              (i32.const {})
              (i32.const 0))
            drop
            (local.set $n
              (call $store_del_if_value
                (i32.const 0)
                (i32.const {})
                (i32.const 256)
                (i32.const {})))
            (i32.store8 (i32.const 412) (local.get $n))
            (call $fd_write (i32.const 1) (i32.const 400) (i32.const 1) (i32.const 420))
            drop
            (call $exit (i32.const 0)))
        )
    "#,
            wat_bytes(key.as_bytes()),
            wat_bytes(value),
            wat_bytes(expected),
            key.len(),
            value.len(),
            key.len(),
            expected.len()
        )
    }

    fn dispatch_read_response_wat(response: &[u8]) -> String {
        let len = response.len();
        format!(
            r#"
        (module
          (memory (export "memory") 1)
          (data (i32.const 2048) "{}")
          (func (export "petal_alloc") (param $len i32) (result i32)
            (i32.const 1024))
          (func (export "petal_dispatch") (param $ptr i32) (param $len i32) (result i64)
            (i64.or
              (i64.shl (i64.const 2048) (i64.const 32))
              (i64.const {})))
        )
    "#,
            wat_bytes(response),
            len
        )
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
        lists: Mutex<HashMap<String, Vec<String>>>,
        http_calls: Mutex<Vec<HttpRequest>>,
        sign_calls: Mutex<Vec<SignRequest>>,
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
        async fn vfs_list(&self, path: &str) -> Result<Vec<String>, HostError> {
            self.lists
                .lock()
                .get(path)
                .cloned()
                .ok_or_else(|| HostError::NotFound(path.into()))
        }
        async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
            self.store.lock().insert(path.into(), bytes.to_vec());
            Ok(())
        }

        async fn http_fetch(
            &self,
            req: HttpRequest,
            policy: NetPolicy,
            max_response_bytes: usize,
        ) -> Result<HttpResponse, HostError> {
            policy.check(&req.method, &req.url)?;
            self.http_calls.lock().push(req);
            let resp = HttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: b"ok".to_vec(),
            };
            if resp.body.len() > max_response_bytes {
                return Err(HostError::Backend("too large".into()));
            }
            Ok(resp)
        }

        async fn sign_hash(&self, req: SignRequest) -> Result<Vec<u8>, HostError> {
            self.sign_calls.lock().push(req);
            Ok(vec![7u8; 65])
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
        assert_eq!(out.stdout, vec![denied_byte()]);
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
    async fn vfs_list_returns_encoded_payload_length_when_allowed() {
        let vm = PetalVm::new().unwrap();
        let host = Arc::new(MockHost::default());
        host.lists
            .lock()
            .insert("wallets".into(), vec!["alice".into(), "bob".into()]);
        let mut caps = BTreeSet::new();
        caps.insert(Capability::VfsRead);
        let wat = r#"
        (module
          (import "bloom.v1" "vfs_list"
            (func $vfs_list (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "wallets")
          ;; DispatchResponse::Read([0])
          (data (i32.const 300) "\02\01\00\00\00\00")
          (func (export "petal_alloc") (param $len i32) (result i32)
            (i32.const 1024))
          (func (export "petal_dispatch") (param $ptr i32) (param $len i32) (result i64)
            (i32.store8
              (i32.const 305)
              (call $vfs_list
                (i32.const 0)
                (i32.const 7)
                (i32.const 64)
                (i32.const 256)))
            (i64.or
              (i64.shl (i64.extend_i32_u (i32.const 300)) (i64.const 32))
              (i64.extend_i32_u (i32.const 6)))))
        "#;
        let out = vm
            .dispatch(
                &wat::parse_str(&wat).unwrap(),
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "summary.md".into(),
                    body: Vec::new(),
                    ctx: Vec::new(),
                },
                caps,
                host.clone(),
                "h",
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            out.response,
            DispatchResponse::Read(vec![
                encode_string_list(&vec!["alice".to_string(), "bob".to_string()]).len() as u8
            ])
        );

        let out = vm
            .dispatch(
                &wat::parse_str(wat).unwrap(),
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "summary.md".into(),
                    body: Vec::new(),
                    ctx: Vec::new(),
                },
                BTreeSet::new(),
                host,
                "h",
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.response, DispatchResponse::Read(vec![denied_byte()]));
    }

    #[tokio::test]
    async fn http_fetch_denied_without_capability_before_host_call() {
        let req = encode_http_request(&HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/markets".into(),
            headers: Vec::new(),
            body: Vec::new(),
        });
        let vm = PetalVm::new().unwrap();
        let host = Arc::new(MockHost::default());
        let out = vm
            .run(
                &wat(&http_probe(&req)),
                Vec::new(),
                BTreeSet::new(),
                host.clone(),
                VALID_HASH,
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, vec![denied_byte()]);
        assert!(host.http_calls.lock().is_empty());
    }

    #[tokio::test]
    async fn http_fetch_denied_by_net_policy_before_host_call() {
        let req = encode_http_request(&HttpRequest {
            method: "GET".into(),
            url: "https://evil.example.com/markets".into(),
            headers: Vec::new(),
            body: Vec::new(),
        });
        let mut caps = BTreeSet::new();
        caps.insert(Capability::NetFetch);
        let manifest = bloom_petal_manifest::local::parse_local_manifest_toml(
            br#"
schema = "bloom.petal.local.v1"
name = "netty"
[provides]
kind = "vfs"
mount = "netty"
caps = ["net.fetch"]
[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/markets*"]
"#,
        )
        .unwrap();
        let opts = RunOptions {
            net_policy: Some(NetPolicy::from_manifest(&manifest)),
            ..RunOptions::default()
        };
        let vm = PetalVm::new().unwrap();
        let host = Arc::new(MockHost::default());
        let out = vm
            .run(
                &wat(&http_probe(&req)),
                Vec::new(),
                caps,
                host.clone(),
                VALID_HASH,
                PetalMode::Local,
                opts,
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, vec![denied_byte()]);
        assert!(host.http_calls.lock().is_empty());
    }

    #[tokio::test]
    async fn http_fetch_allowed_by_cap_and_net_policy() {
        let req = encode_http_request(&HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/markets".into(),
            headers: Vec::new(),
            body: Vec::new(),
        });
        let mut caps = BTreeSet::new();
        caps.insert(Capability::NetFetch);
        let manifest = bloom_petal_manifest::local::parse_local_manifest_toml(
            br#"
schema = "bloom.petal.local.v1"
name = "netty"
[provides]
kind = "vfs"
mount = "netty"
caps = ["net.fetch"]
[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/markets*"]
"#,
        )
        .unwrap();
        let opts = RunOptions {
            net_policy: Some(NetPolicy::from_manifest(&manifest)),
            ..RunOptions::default()
        };
        let vm = PetalVm::new().unwrap();
        let host = Arc::new(MockHost::default());
        let out = vm
            .run(
                &wat(&http_probe(&req)),
                Vec::new(),
                caps,
                host.clone(),
                VALID_HASH,
                PetalMode::Local,
                opts,
            )
            .await
            .unwrap();
        assert_eq!(host.http_calls.lock().len(), 1);
        assert!(out.stdout[0] > 0);
    }

    #[tokio::test]
    async fn sign_hash_allowed_by_cap() {
        let req = encode_sign_request(&SignRequest {
            wallet: "0xabc".into(),
            hash32: [9u8; 32],
            purpose: "polymarket-order".into(),
        });
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Sign);
        let vm = PetalVm::new().unwrap();
        let host = Arc::new(MockHost::default());
        let out = vm
            .run(
                &wat(&sign_probe(&req)),
                Vec::new(),
                caps,
                host.clone(),
                VALID_HASH,
                PetalMode::Local,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, vec![65]);
        assert_eq!(host.sign_calls.lock().len(), 1);
    }

    #[tokio::test]
    async fn store_put_get_uses_private_petal_directory() {
        let tmp = TempDir::new().unwrap();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Store);
        let opts = RunOptions {
            private_store_root: Some(tmp.path().to_path_buf()),
            ..RunOptions::default()
        };
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(&store_put_get_probe("creds/api.json", b"secret")),
                Vec::new(),
                caps,
                Arc::new(MockHost::default()),
                VALID_HASH,
                PetalMode::Local,
                opts,
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, vec![6]);
        assert_eq!(
            std::fs::read(tmp.path().join(VALID_HASH).join("creds/api.json")).unwrap(),
            b"secret"
        );
    }

    #[tokio::test]
    async fn store_put_new_refuses_overwrite() {
        let tmp = TempDir::new().unwrap();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Store);
        let opts = RunOptions {
            private_store_root: Some(tmp.path().to_path_buf()),
            ..RunOptions::default()
        };
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(&store_put_new_probe("orders/.lock", b"first", b"second")),
                Vec::new(),
                caps,
                Arc::new(MockHost::default()),
                VALID_HASH,
                PetalMode::Local,
                opts,
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, vec![denied_byte()]);
        assert_eq!(
            std::fs::read(tmp.path().join(VALID_HASH).join("orders/.lock")).unwrap(),
            b"first"
        );
    }

    #[tokio::test]
    async fn store_del_if_value_refuses_changed_value() {
        let tmp = TempDir::new().unwrap();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Store);
        let opts = RunOptions {
            private_store_root: Some(tmp.path().to_path_buf()),
            ..RunOptions::default()
        };
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(&store_del_if_value_probe(
                    "orders/.lock",
                    b"first",
                    b"second",
                )),
                Vec::new(),
                caps,
                Arc::new(MockHost::default()),
                VALID_HASH,
                PetalMode::Local,
                opts,
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, vec![denied_byte()]);
        assert_eq!(
            std::fs::read(tmp.path().join(VALID_HASH).join("orders/.lock")).unwrap(),
            b"first"
        );
    }

    #[tokio::test]
    async fn store_rejects_traversal_key() {
        let tmp = TempDir::new().unwrap();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Store);
        let opts = RunOptions {
            private_store_root: Some(tmp.path().to_path_buf()),
            ..RunOptions::default()
        };
        let vm = PetalVm::new().unwrap();
        let out = vm
            .run(
                &wat(&store_put_get_probe("../creds", b"secret")),
                Vec::new(),
                caps,
                Arc::new(MockHost::default()),
                VALID_HASH,
                PetalMode::Local,
                opts,
            )
            .await
            .unwrap();
        assert_eq!(out.stdout, vec![invalid_byte()]);
        assert!(!tmp.path().join("creds").exists());
    }

    #[tokio::test]
    async fn dispatch_calls_petal_dispatch_and_decodes_response() {
        let vm = PetalVm::new().unwrap();
        let response = encode_dispatch_response(&DispatchResponse::Read(b"hello".to_vec()));
        let out = vm
            .dispatch(
                &wat(&dispatch_read_response_wat(&response)),
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "status.json".into(),
                    body: Vec::new(),
                    ctx: Vec::new(),
                },
                BTreeSet::new(),
                Arc::new(DenyHost),
                VALID_HASH,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.response, DispatchResponse::Read(b"hello".to_vec()));
        assert!(out.fuel_consumed > 0);
    }

    #[tokio::test]
    async fn dispatch_requires_alloc_and_dispatch_exports() {
        let vm = PetalVm::new().unwrap();
        let err = vm
            .dispatch(
                &wat("(module (memory (export \"memory\") 1))"),
                DispatchRequest {
                    op: DispatchOp::Lookup,
                    path: "".into(),
                    body: Vec::new(),
                    ctx: Vec::new(),
                },
                BTreeSet::new(),
                Arc::new(DenyHost),
                VALID_HASH,
                RunOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing petal_alloc"));
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
