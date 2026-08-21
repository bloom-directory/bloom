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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use wasmtime::component::{Component, Linker as ComponentLinker, Val as ComponentVal};
use wasmtime::{Caller, Config, Engine, Linker, Memory, Module, Store, StoreContextMut};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};

use crate::abi::{
    ChainRequest, ChainResponse, DispatchOp, DispatchRequest, DispatchResponse,
    EvmOutboxInspection, EvmOutboxOutcome, EvmTransactionRequest, PayloadBatchSignOutcome,
    PayloadBatchSignRequest, PayloadSignItem, PayloadSignRequest, PetalKeyGuestRequest,
    PetalKeyRequest, PetalRouteContext, SignOutcome,
};
use crate::error::PetalError;
use crate::host::{HostError, HostVfsEntry, HostVfsEntryKind, PetalHost};
use crate::meta::Capability;
use crate::policy::{NetPolicy, StoreNamespacePolicy};
use crate::private_store::PrivateStore;

const DEFAULT_FUEL: u64 = 100_000_000;
const DEFAULT_MEMORY_PAGES: u32 = 256; // 16 MiB (64 KiB pages).
const STDOUT_CAP: usize = 1 << 20; // 1 MiB.
const DEFAULT_HTTP_RESPONSE_CAP: usize = 8 * 1024 * 1024;
const DEFAULT_RANDOM_BYTES_CAP: u32 = 1024 * 1024;
const MAX_SIGN_BATCH_ITEMS: usize = 32;
const MAX_SIGN_BATCH_CHILD_BYTES: usize = 64 * 1024;
const MAX_SIGN_BATCH_PAYLOAD_BYTES: usize = 512 * 1024;
pub(crate) const COMPONENT_NOT_A_DIR_CODE: i32 = -101;
pub(crate) const COMPONENT_UNSUPPORTED_CODE: i32 = -102;

/// State threaded through `Store<StoreData>`. Owns the WASI context,
/// the host bridge, and the capability set for the petal in flight.
pub struct StoreData {
    wasi: WasiP1Ctx,
    host: Arc<dyn PetalHost>,
    caps: BTreeSet<Capability>,
    petal_hash: String,
    net_policy: NetPolicy,
    sign_context: Option<PetalRouteContext>,
    sign_intents: Option<BTreeSet<String>>,
    store_namespaces: Option<StoreNamespacePolicy>,
    http_response_cap: usize,
    private_store: Option<PrivateStore>,
    deterministic_env: bool,
    runtime_settings: BTreeMap<String, String>,
    limiter: MemLimiter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentRouteMetadata {
    pub kind: ComponentRouteEntryKind,
    pub mode: u32,
    pub cache_ttl_ms: Option<u64>,
    pub side_effecting_read: bool,
    pub write_async: bool,
    pub required_caps: Vec<String>,
    pub sign_intent: Option<String>,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentRouteEntryKind {
    Dir,
    File,
    Symlink,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub fuel: u64,
    pub memory_pages: u32,
    /// Optional runtime network mask. When running through [`PetalRunner`],
    /// this is intersected with the manifest-declared policy and can only
    /// narrow it. Direct VM callers that omit it get deny-all.
    pub net_policy: Option<NetPolicy>,
    /// Optional signing intent allow-list. `None` preserves legacy/direct VM
    /// behavior; Petal package dispatch sets this from `[sign].allowed_intents`.
    pub sign_intents: Option<BTreeSet<String>>,
    /// Optional private-store namespace policy. `None` preserves legacy/direct
    /// VM behavior; Petal package dispatch sets this from `[store]`.
    pub store_namespaces: Option<StoreNamespacePolicy>,
    pub http_response_cap: usize,
    pub private_store_root: Option<PathBuf>,
    /// Force mediated env helpers to deterministic values for install-time checks.
    pub deterministic_env: bool,
    /// Daemon-owned settings exposed read-only through `bloom:env`.
    pub runtime_settings: BTreeMap<String, String>,
    /// Daemon-owned HTTPS origins for manifest-declared endpoint bindings.
    pub endpoint_bindings: BTreeMap<String, String>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL,
            memory_pages: DEFAULT_MEMORY_PAGES,
            net_policy: None,
            sign_intents: None,
            store_namespaces: None,
            http_response_cap: DEFAULT_HTTP_RESPONSE_CAP,
            private_store_root: None,
            deterministic_env: false,
            runtime_settings: BTreeMap::new(),
            endpoint_bindings: BTreeMap::new(),
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
    components: Arc<Mutex<HashMap<[u8; 32], Component>>>,
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
        config.wasm_component_model(true);
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
        // Keep memory64 outside the Petal runtime profile. This is separate
        // from the `bloom:route@0.1.0` WIT ABI: changing that interface would
        // not make 64-bit linear memories safe or compatible with older
        // hosts. Wasmtime 36 enables the core proposal by default even though
        // its component-model integration is still incomplete (tracked by
        // upstream issue #4311). The `MemLimiter` cap applies to either
        // address width, so this is a compatibility/support boundary rather
        // than a memory-exhaustion fix. Enable it only with an explicit Petal
        // runtime-feature contract and component-level conformance coverage.
        // `accepted_petal_component_surface_is_pinned` below catches future
        // Wasmtime default changes.
        config.wasm_memory64(false);
        let engine = Engine::new(&config).map_err(|e| PetalError::vm(e.to_string()))?;
        Ok(Self {
            engine,
            components: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn component(&self, wasm: &[u8]) -> Result<Component, PetalError> {
        let key = *blake3::hash(wasm).as_bytes();
        if let Some(component) = self.components.lock().get(&key).cloned() {
            return Ok(component);
        }
        let component = Component::from_binary(&self.engine, wasm)
            .map_err(|e| PetalError::InvalidWasm(e.to_string()))?;
        self.components.lock().insert(key, component.clone());
        Ok(component)
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
                sign_context: None,
                sign_intents: opts.sign_intents.clone(),
                store_namespaces: opts.store_namespaces.clone(),
                http_response_cap: opts.http_response_cap,
                deterministic_env: opts.deterministic_env,
                runtime_settings: opts.runtime_settings.clone(),
                limiter: MemLimiter::new(opts.memory_pages),
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
        store.limiter(|data| &mut data.limiter);

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

    /// Dispatch one VFS operation into a `bloom:route@0.1.0` component.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_component_route(
        &self,
        wasm: &[u8],
        request: DispatchRequest,
        caps: BTreeSet<Capability>,
        host: Arc<dyn PetalHost>,
        petal_hash: &str,
        petal_root: &str,
        route_params: Vec<(String, String)>,
        opts: RunOptions,
    ) -> Result<DispatchOutput, PetalError> {
        let component = self.component(wasm)?;
        let wasi_ctx = WasiCtxBuilder::new().build_p1();
        let mut store = Store::new(
            &self.engine,
            StoreData {
                wasi: wasi_ctx,
                host,
                caps,
                petal_hash: petal_hash.to_string(),
                net_policy: opts.net_policy.clone().unwrap_or_else(NetPolicy::deny_all),
                sign_context: Some(PetalRouteContext {
                    petal_root: petal_root.to_string(),
                    package_hash: petal_hash.to_string(),
                    route_id: request
                        .ctx
                        .iter()
                        .find_map(|(name, value)| (name == "bloom.route_id").then(|| value.clone()))
                        .unwrap_or_default(),
                    op: route_component_export_name(request.op).to_string(),
                    path: request.path.clone(),
                    params: route_params.clone(),
                    actor: request
                        .ctx
                        .iter()
                        .find_map(|(name, value)| (name == "actor").then(|| value.clone())),
                }),
                sign_intents: opts.sign_intents.clone(),
                store_namespaces: opts.store_namespaces.clone(),
                http_response_cap: opts.http_response_cap,
                deterministic_env: opts.deterministic_env,
                runtime_settings: opts.runtime_settings.clone(),
                limiter: MemLimiter::new(opts.memory_pages),
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
        store.limiter(|data| &mut data.limiter);

        let mut linker = ComponentLinker::<StoreData>::new(&self.engine);
        linker
            .define_unknown_imports_as_traps(&component)
            .map_err(|e| PetalError::vm(e.to_string()))?;
        link_component_host_imports(&mut linker).map_err(|e| PetalError::vm(e.to_string()))?;

        let instance = linker
            .instantiate_async(&mut store, &component)
            .await
            .map_err(|e| PetalError::vm(format!("component instantiate: {e}")))?;
        let export = route_component_export_name(request.op);
        let func = instance.get_func(&mut store, export).ok_or_else(|| {
            PetalError::InvalidWasm(format!("component route missing {export:?} export"))
        })?;
        let params = route_component_params(&request, petal_root, petal_hash, route_params);
        let mut results = vec![ComponentVal::Bool(false)];
        func.call_async(&mut store, &params, &mut results)
            .await
            .map_err(|e| PetalError::vm(format!("component route {export}: {e}")))?;
        func.post_return_async(&mut store)
            .await
            .map_err(|e| PetalError::vm(format!("component route {export} post-return: {e}")))?;
        let response = route_component_response(request.op, results.remove(0))?;
        let fuel_consumed = opts.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
        Ok(DispatchOutput {
            response,
            fuel_consumed,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn component_route_metadata(
        &self,
        wasm: &[u8],
        caps: BTreeSet<Capability>,
        host: Arc<dyn PetalHost>,
        petal_hash: &str,
        petal_root: &str,
        path: &str,
        route_params: Vec<(String, String)>,
        opts: RunOptions,
    ) -> Result<ComponentRouteMetadata, PetalError> {
        let component = self.component(wasm)?;
        let wasi_ctx = WasiCtxBuilder::new().build_p1();
        let mut store = Store::new(
            &self.engine,
            StoreData {
                wasi: wasi_ctx,
                host,
                caps,
                petal_hash: petal_hash.to_string(),
                net_policy: opts.net_policy.clone().unwrap_or_else(NetPolicy::deny_all),
                sign_context: None,
                sign_intents: opts.sign_intents.clone(),
                store_namespaces: opts.store_namespaces.clone(),
                http_response_cap: opts.http_response_cap,
                deterministic_env: opts.deterministic_env,
                runtime_settings: opts.runtime_settings.clone(),
                limiter: MemLimiter::new(opts.memory_pages),
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
        store.limiter(|data| &mut data.limiter);

        let mut linker = ComponentLinker::<StoreData>::new(&self.engine);
        linker
            .define_unknown_imports_as_traps(&component)
            .map_err(|e| PetalError::vm(e.to_string()))?;
        link_component_host_imports(&mut linker).map_err(|e| PetalError::vm(e.to_string()))?;

        let instance = linker
            .instantiate_async(&mut store, &component)
            .await
            .map_err(|e| PetalError::vm(format!("component instantiate: {e}")))?;
        let func = instance.get_func(&mut store, "metadata").ok_or_else(|| {
            PetalError::InvalidWasm("component route missing \"metadata\" export".into())
        })?;
        let request = DispatchRequest {
            op: DispatchOp::Lookup,
            path: path.to_string(),
            body: Vec::new(),
            ctx: Vec::new(),
        };
        let params = route_component_params(&request, petal_root, petal_hash, route_params);
        let mut results = vec![ComponentVal::Bool(false)];
        func.call_async(&mut store, &params, &mut results)
            .await
            .map_err(|e| PetalError::vm(format!("component route metadata: {e}")))?;
        func.post_return_async(&mut store)
            .await
            .map_err(|e| PetalError::vm(format!("component route metadata post-return: {e}")))?;
        route_component_metadata_result(results.remove(0))
    }
}

fn route_component_export_name(op: DispatchOp) -> &'static str {
    match op {
        DispatchOp::Lookup => "lookup",
        DispatchOp::List => "list",
        DispatchOp::Read => "read",
        DispatchOp::Write => "write",
    }
}

fn route_component_params(
    request: &DispatchRequest,
    petal_root: &str,
    petal_hash: &str,
    route_params: Vec<(String, String)>,
) -> Vec<ComponentVal> {
    let mut params = Vec::new();
    let actor = request
        .ctx
        .iter()
        .find_map(|(name, value)| (name == "actor").then(|| value.clone()));
    let route_params = route_params
        .into_iter()
        .map(|(name, value)| {
            ComponentVal::Tuple(vec![
                ComponentVal::String(name),
                ComponentVal::String(value),
            ])
        })
        .collect::<Vec<_>>();
    params.push(ComponentVal::Record(vec![
        (
            "petal-root".into(),
            ComponentVal::String(petal_root.to_string()),
        ),
        (
            "package-hash".into(),
            ComponentVal::String(petal_hash.to_string()),
        ),
        ("path".into(), ComponentVal::String(request.path.clone())),
        ("params".into(), ComponentVal::List(route_params)),
        (
            "actor".into(),
            ComponentVal::Option(actor.map(|actor| Box::new(ComponentVal::String(actor)))),
        ),
    ]));
    if request.op == DispatchOp::Write {
        params.push(ComponentVal::List(
            request.body.iter().copied().map(ComponentVal::U8).collect(),
        ));
    }
    params
}

fn route_component_response(
    op: DispatchOp,
    val: ComponentVal,
) -> Result<DispatchResponse, PetalError> {
    let ok = match val {
        ComponentVal::Result(Ok(Some(ok))) => *ok,
        ComponentVal::Result(Ok(None)) if op == DispatchOp::Write => {
            return Ok(DispatchResponse::Write);
        }
        ComponentVal::Result(Err(Some(err))) => {
            let (code, message) = route_component_error(*err)?;
            return Ok(DispatchResponse::Error { code, message });
        }
        ComponentVal::Result(Err(None)) => {
            return Ok(DispatchResponse::Error {
                code: HostError::Backend("component route error".into()).as_wasm_code(),
                message: "component route returned an empty error".into(),
            });
        }
        other => {
            return Err(PetalError::vm(format!(
                "component route returned unexpected value {other:?}"
            )));
        }
    };
    match op {
        DispatchOp::Lookup => Ok(DispatchResponse::Lookup(route_component_entry(ok)?)),
        DispatchOp::List => {
            let ComponentVal::List(entries) = ok else {
                return Err(PetalError::vm("component list returned non-list"));
            };
            entries
                .into_iter()
                .map(route_component_entry)
                .collect::<Result<Vec<_>, _>>()
                .map(DispatchResponse::List)
        }
        DispatchOp::Read => {
            let ComponentVal::List(bytes) = ok else {
                return Err(PetalError::vm("component read returned non-list"));
            };
            bytes
                .into_iter()
                .map(|byte| match byte {
                    ComponentVal::U8(byte) => Ok(byte),
                    other => Err(PetalError::vm(format!(
                        "component read returned non-u8 byte {other:?}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(DispatchResponse::Read)
        }
        DispatchOp::Write => Err(PetalError::vm(
            "component write returned unexpected ok payload",
        )),
    }
}

fn route_component_error(err: ComponentVal) -> Result<(i32, String), PetalError> {
    let ComponentVal::Variant(name, payload) = err else {
        return Err(PetalError::vm("component route error is not a variant"));
    };
    let message = match payload.map(|payload| *payload) {
        Some(ComponentVal::String(message)) => message,
        Some(other) => {
            return Err(PetalError::vm(format!(
                "component route error payload is not a string: {other:?}"
            )));
        }
        None => String::new(),
    };
    let code = match name.as_str() {
        "not-found" => HostError::NotFound(message.clone()).as_wasm_code(),
        "denied" => HostError::Denied(message.clone()).as_wasm_code(),
        "invalid" => HostError::Invalid(message.clone()).as_wasm_code(),
        "backend" => HostError::Backend(message.clone()).as_wasm_code(),
        "not-a-dir" => COMPONENT_NOT_A_DIR_CODE,
        "unsupported" => COMPONENT_UNSUPPORTED_CODE,
        _ => HostError::Backend(format!("unknown component route error {name}")).as_wasm_code(),
    };
    Ok((code, message))
}

fn route_component_entry(val: ComponentVal) -> Result<crate::abi::DispatchEntry, PetalError> {
    let fields = component_record(val, "entry")?;
    let name = component_string_field(&fields, "name")?;
    let kind = match component_enum_field(&fields, "kind")?.as_str() {
        "dir" => crate::abi::DispatchEntryKind::Dir,
        "file" => crate::abi::DispatchEntryKind::File,
        "symlink" => crate::abi::DispatchEntryKind::Symlink,
        other => {
            return Err(PetalError::vm(format!(
                "component entry has unknown kind {other:?}"
            )));
        }
    };
    let mode = component_u32_field(&fields, "mode")?;
    let size = component_optional_u64_field(&fields, "size")?.unwrap_or(0);
    let link_target = component_optional_string_field(&fields, "link-target")?;
    Ok(crate::abi::DispatchEntry {
        name,
        kind,
        size,
        mode,
        ttl_hint_ms: None,
        link_target,
    })
}

fn route_component_metadata_result(
    val: ComponentVal,
) -> Result<ComponentRouteMetadata, PetalError> {
    let ok = match val {
        ComponentVal::Result(Ok(Some(ok))) => *ok,
        ComponentVal::Result(Err(Some(err))) => {
            let (code, message) = route_component_error(*err)?;
            return Err(PetalError::vm(format!(
                "component metadata returned error {code}: {message}"
            )));
        }
        ComponentVal::Result(Err(None)) => {
            return Err(PetalError::vm(
                "component metadata returned an empty error".to_string(),
            ));
        }
        other => {
            return Err(PetalError::vm(format!(
                "component metadata returned unexpected value {other:?}"
            )));
        }
    };
    route_component_metadata(ok)
}

fn route_component_metadata(val: ComponentVal) -> Result<ComponentRouteMetadata, PetalError> {
    let fields = component_record(val, "route-meta")?;
    let kind = match component_enum_field(&fields, "kind")?.as_str() {
        "dir" => ComponentRouteEntryKind::Dir,
        "file" => ComponentRouteEntryKind::File,
        "symlink" => ComponentRouteEntryKind::Symlink,
        other => {
            return Err(PetalError::vm(format!(
                "component route-meta has unknown kind {other:?}"
            )));
        }
    };
    Ok(ComponentRouteMetadata {
        kind,
        mode: component_u32_field(&fields, "mode")?,
        cache_ttl_ms: component_optional_u64_field(&fields, "cache-ttl-ms")?,
        side_effecting_read: component_bool_field(&fields, "side-effecting-read")?,
        write_async: component_bool_field(&fields, "write-async")?,
        required_caps: component_string_list_field(&fields, "required-caps")?,
        sign_intent: component_optional_string_field(&fields, "sign-intent")?,
        executable: component_bool_field(&fields, "executable")?,
    })
}

fn component_record(
    val: ComponentVal,
    label: &str,
) -> Result<Vec<(String, ComponentVal)>, PetalError> {
    match val {
        ComponentVal::Record(fields) => Ok(fields),
        other => Err(PetalError::vm(format!(
            "component {label} is not a record: {other:?}"
        ))),
    }
}

fn component_field<'a>(
    fields: &'a [(String, ComponentVal)],
    name: &str,
) -> Result<&'a ComponentVal, PetalError> {
    fields
        .iter()
        .find_map(|(field, value)| (field == name).then_some(value))
        .ok_or_else(|| PetalError::vm(format!("component record missing field {name:?}")))
}

fn component_bool_field(fields: &[(String, ComponentVal)], name: &str) -> Result<bool, PetalError> {
    match component_field(fields, name)? {
        ComponentVal::Bool(value) => Ok(*value),
        other => Err(PetalError::vm(format!(
            "component field {name:?} is not a bool: {other:?}"
        ))),
    }
}

fn component_string_field(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<String, PetalError> {
    match component_field(fields, name)? {
        ComponentVal::String(value) => Ok(value.clone()),
        other => Err(PetalError::vm(format!(
            "component field {name:?} is not a string: {other:?}"
        ))),
    }
}

fn component_string_list_field(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<Vec<String>, PetalError> {
    let ComponentVal::List(values) = component_field(fields, name)? else {
        return Err(PetalError::vm(format!(
            "component field {name:?} is not a list"
        )));
    };
    values
        .iter()
        .map(|value| match value {
            ComponentVal::String(value) => Ok(value.clone()),
            other => Err(PetalError::vm(format!(
                "component field {name:?} contains non-string value {other:?}"
            ))),
        })
        .collect()
}

fn component_enum_field(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<String, PetalError> {
    match component_field(fields, name)? {
        ComponentVal::Enum(value) => Ok(value.clone()),
        other => Err(PetalError::vm(format!(
            "component field {name:?} is not an enum: {other:?}"
        ))),
    }
}

fn component_u32_field(fields: &[(String, ComponentVal)], name: &str) -> Result<u32, PetalError> {
    match component_field(fields, name)? {
        ComponentVal::U32(value) => Ok(*value),
        other => Err(PetalError::vm(format!(
            "component field {name:?} is not a u32: {other:?}"
        ))),
    }
}

fn component_optional_u64_field(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<Option<u64>, PetalError> {
    match component_field(fields, name)? {
        ComponentVal::Option(None) => Ok(None),
        ComponentVal::Option(Some(value)) => match value.as_ref() {
            ComponentVal::U64(value) => Ok(Some(*value)),
            other => Err(PetalError::vm(format!(
                "component field {name:?} option is not a u64: {other:?}"
            ))),
        },
        other => Err(PetalError::vm(format!(
            "component field {name:?} is not an option: {other:?}"
        ))),
    }
}

fn component_optional_string_field(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<Option<String>, PetalError> {
    match component_field(fields, name)? {
        ComponentVal::Option(None) => Ok(None),
        ComponentVal::Option(Some(value)) => match value.as_ref() {
            ComponentVal::String(value) => Ok(Some(value.clone())),
            other => Err(PetalError::vm(format!(
                "component field {name:?} option is not a string: {other:?}"
            ))),
        },
        other => Err(PetalError::vm(format!(
            "component field {name:?} is not an option: {other:?}"
        ))),
    }
}

fn link_component_host_imports(linker: &mut ComponentLinker<StoreData>) -> anyhow::Result<()> {
    linker.allow_shadowing(true);

    {
        let mut http = linker.instance("bloom:http/fetch@0.1.0")?;
        http.func_new_async("fetch", |store, params, results| {
            Box::new(async move { component_http_fetch(store, params, results).await })
        })?;
    }
    {
        let mut store = linker.instance("bloom:store/kv@0.1.0")?;
        store.func_new_async("get", |store, params, results| {
            Box::new(async move { component_store_get(store, params, results).await })
        })?;
        store.func_new_async("put", |store, params, results| {
            Box::new(async move { component_store_put(store, params, results).await })
        })?;
        store.func_new_async("put-new", |store, params, results| {
            Box::new(async move { component_store_put_new(store, params, results).await })
        })?;
        store.func_new_async("list", |store, params, results| {
            Box::new(async move { component_store_list(store, params, results).await })
        })?;
        store.func_new_async("delete", |store, params, results| {
            Box::new(async move { component_store_delete(store, params, results).await })
        })?;
        store.func_new_async("delete-if-value", |store, params, results| {
            Box::new(async move { component_store_delete_if_value(store, params, results).await })
        })?;
    }
    {
        let mut sign = linker.instance("bloom:sign/signing@0.1.0")?;
        sign.func_new_async("sign-hash", |store, params, results| {
            Box::new(async move { component_sign_hash(store, params, results).await })
        })?;
        sign.func_new_async("sign-hashes", |store, params, results| {
            Box::new(async move { component_sign_hashes(store, params, results).await })
        })?;
    }
    {
        let mut sign = linker.instance("bloom:sign/signing@0.2.0")?;
        sign.func_new_async("sign-payload", |store, params, results| {
            Box::new(async move { component_sign_payload_current(store, params, results).await })
        })?;
        sign.func_new_async("sign-payload-batch", |store, params, results| {
            Box::new(async move { component_sign_payload_batch(store, params, results).await })
        })?;
    }
    {
        let mut key = linker.instance("bloom:key/derive@0.1.0")?;
        key.func_new_async("request", |store, params, results| {
            Box::new(async move { component_petal_key_request(store, params, results).await })
        })?;
    }
    {
        let mut tx = linker.instance("bloom:tx/outbox@0.1.0")?;
        tx.func_new_async("stage", |store, params, results| {
            Box::new(async move { component_evm_tx_stage(store, params, results).await })
        })?;
        tx.func_new_async("confirm", |store, params, results| {
            Box::new(async move { component_evm_tx_confirm(store, params, results).await })
        })?;
        tx.func_new_async("inspect", |store, params, results| {
            Box::new(async move { component_evm_tx_inspect(store, params, results).await })
        })?;
    }
    {
        let mut vfs = linker.instance("bloom:vfs/readwrite@0.1.0")?;
        vfs.func_new_async("lookup", |store, params, results| {
            Box::new(async move { component_vfs_lookup(store, params, results).await })
        })?;
        vfs.func_new_async("list", |store, params, results| {
            Box::new(async move { component_vfs_list(store, params, results).await })
        })?;
        vfs.func_new_async("read", |store, params, results| {
            Box::new(async move { component_vfs_read(store, params, results).await })
        })?;
        vfs.func_new_async("write", |store, params, results| {
            Box::new(async move { component_vfs_write(store, params, results).await })
        })?;
    }
    {
        let mut chain = linker.instance("bloom:chain/read@0.1.0")?;
        chain.func_new_async("call", |store, params, results| {
            Box::new(async move { component_chain_call(store, params, results).await })
        })?;
    }
    {
        let mut env = linker.instance("bloom:env/runtime@0.1.0")?;
        env.func_new_async("now-ms", |store, _params, results| {
            Box::new(async move { component_env_now_ms(store, results).await })
        })?;
        env.func_new_async("random-bytes", |store, params, results| {
            Box::new(async move { component_env_random_bytes(store, params, results).await })
        })?;
        env.func_new_async("setting", |store, params, results| {
            Box::new(async move { component_env_setting(store, params, results).await })
        })?;
    }
    Ok(())
}

async fn component_http_fetch(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    let req = match params {
        [ComponentVal::Record(fields)] => component_http_request(fields),
        _ => Err(HostError::Invalid("invalid bloom:http.fetch params".into())),
    };
    let req = match req {
        Ok(req) => req,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };

    if !store.data().caps.contains(&Capability::NetFetch) {
        log_denied(store.data(), "component_http_fetch");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("net.fetch".into())),
        );
    }
    let audit = http_audit_target(&req.url);
    let effective_policy = store.data().net_policy.clone();
    if let Err(e) = effective_policy.check(&req.method, &req.url) {
        tracing::info!(
            target: "bloom_petals::vm",
            petal = %store.data().petal_hash,
            method = %req.method,
            host = audit.host.as_deref().unwrap_or("<invalid>"),
            path = audit.path.as_deref().unwrap_or("<invalid>"),
            "component http.fetch denied by net policy"
        );
        return set_component_result(results, component_host_err(e));
    }
    let host = store.data().host.clone();
    let cap = store.data().http_response_cap;
    let petal_hash = store.data().petal_hash.clone();
    let req_body_len = req.body.len();
    let method = req.method.clone();
    match host.http_fetch(req, effective_policy, cap).await {
        Ok(resp) if resp.body.len() <= cap => {
            tracing::info!(
                target: "bloom_petals::vm",
                petal = %petal_hash,
                method = %method,
                host = audit.host.as_deref().unwrap_or("<invalid>"),
                path = audit.path.as_deref().unwrap_or("<invalid>"),
                status = resp.status,
                request_bytes = req_body_len,
                response_bytes = resp.body.len(),
                "component http.fetch allowed"
            );
            set_component_result(results, component_ok(Some(component_http_response(resp))))
        }
        Ok(_) => set_component_result(
            results,
            component_host_err(HostError::Backend("http response too large".into())),
        ),
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_store_get(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::Store) {
        log_denied(store.data(), "component_store_get");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store".into())),
        );
    }
    let (namespace, key) = match component_namespace_key(params) {
        Ok(v) => v,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    if let Err(e) = store_namespace_allowed(store.data(), &namespace) {
        return set_component_result(results, component_host_err(e));
    }
    let logical_key = key;
    let key = match namespaced_store_key(&namespace, &logical_key) {
        Ok(key) => key,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let Some(private_store) = store.data().private_store.clone() else {
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store unavailable".into())),
        );
    };
    let petal_hash = store.data().petal_hash.clone();
    let value = match private_store.get(&petal_hash, &key) {
        Err(HostError::NotFound(_))
            if namespace == "state"
                && (logical_key == "creds" || logical_key.starts_with("creds/")) =>
        {
            // SDK releases through 0.1.0 routed secret writes to `secrets`
            // but routed every read to `state`, despite documenting `creds/`
            // as key-routed. Preserve compatibility with already-built Petals
            // while the corrected SDK propagates through pinned packages.
            if let Err(e) = store_namespace_allowed(store.data(), "secrets") {
                return set_component_result(results, component_host_err(e));
            }
            let secret_key = match namespaced_store_key("secrets", &logical_key) {
                Ok(key) => key,
                Err(e) => return set_component_result(results, component_host_err(e)),
            };
            private_store.get(&petal_hash, &secret_key)
        }
        result => result,
    };
    match value {
        Ok(bytes) => set_component_result(
            results,
            component_ok(Some(ComponentVal::Option(Some(Box::new(component_bytes(
                bytes,
            )))))),
        ),
        Err(HostError::NotFound(_)) => {
            set_component_result(results, component_ok(Some(ComponentVal::Option(None))))
        }
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_store_put(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::Store) {
        log_denied(store.data(), "component_store_put");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store".into())),
        );
    }
    let [namespace, key, value, secret] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid("invalid bloom:store.put params".into())),
        );
    };
    let namespace = match component_string(namespace, "namespace") {
        Ok(namespace) => namespace,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let key = match component_string(key, "key") {
        Ok(key) => key,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let value = match component_byte_list(value, "value") {
        Ok(value) => value,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let secret = match component_bool(secret, "secret") {
        Ok(secret) => secret,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    if let Err(e) = store_namespace_put_allowed(store.data(), &namespace, secret) {
        return set_component_result(results, component_host_err(e));
    }
    let key = match namespaced_store_key(&namespace, &key) {
        Ok(key) => key,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let Some(private_store) = store.data().private_store.clone() else {
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store unavailable".into())),
        );
    };
    let petal_hash = store.data().petal_hash.clone();
    match private_store.put(&petal_hash, &key, &value, secret) {
        Ok(()) => set_component_result(results, component_ok(None)),
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_store_put_new(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::Store) {
        log_denied(store.data(), "component_store_put_new");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store".into())),
        );
    }
    let [namespace, key, value, secret] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:store.put-new params".into(),
            )),
        );
    };
    let namespace = match component_string(namespace, "namespace") {
        Ok(namespace) => namespace,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let key = match component_string(key, "key") {
        Ok(key) => key,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let value = match component_byte_list(value, "value") {
        Ok(value) => value,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let secret = match component_bool(secret, "secret") {
        Ok(secret) => secret,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    if let Err(e) = store_namespace_put_allowed(store.data(), &namespace, secret) {
        return set_component_result(results, component_host_err(e));
    }
    let key = match namespaced_store_key(&namespace, &key) {
        Ok(key) => key,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let Some(private_store) = store.data().private_store.clone() else {
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store unavailable".into())),
        );
    };
    let petal_hash = store.data().petal_hash.clone();
    match private_store.put_new(&petal_hash, &key, &value, secret) {
        Ok(()) => set_component_result(results, component_ok(None)),
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_store_list(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::Store) {
        log_denied(store.data(), "component_store_list");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store".into())),
        );
    }
    let (namespace, prefix) = match component_namespace_key(params) {
        Ok(v) => v,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    if let Err(e) = store_namespace_allowed(store.data(), &namespace) {
        return set_component_result(results, component_host_err(e));
    }
    let store_prefix = match namespaced_store_prefix(&namespace, &prefix) {
        Ok(prefix) => prefix,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let Some(private_store) = store.data().private_store.clone() else {
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store unavailable".into())),
        );
    };
    let petal_hash = store.data().petal_hash.clone();
    match private_store.list(&petal_hash, &store_prefix) {
        Ok(keys) => {
            let namespace_prefix = format!("{namespace}/");
            let keys = keys
                .into_iter()
                .filter_map(|key| key.strip_prefix(&namespace_prefix).map(str::to_string))
                .map(ComponentVal::String)
                .collect();
            set_component_result(results, component_ok(Some(ComponentVal::List(keys))))
        }
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_store_delete(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::Store) {
        log_denied(store.data(), "component_store_delete");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store".into())),
        );
    }
    let (namespace, key) = match component_namespace_key(params) {
        Ok(v) => v,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    if let Err(e) = store_namespace_allowed(store.data(), &namespace) {
        return set_component_result(results, component_host_err(e));
    }
    let key = match namespaced_store_key(&namespace, &key) {
        Ok(key) => key,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let Some(private_store) = store.data().private_store.clone() else {
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store unavailable".into())),
        );
    };
    let petal_hash = store.data().petal_hash.clone();
    match private_store.del(&petal_hash, &key) {
        Ok(()) => set_component_result(results, component_ok(None)),
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_store_delete_if_value(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::Store) {
        log_denied(store.data(), "component_store_delete_if_value");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store".into())),
        );
    }
    let [namespace, key, expected] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:store.delete-if-value params".into(),
            )),
        );
    };
    let namespace = match component_string(namespace, "namespace") {
        Ok(namespace) => namespace,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let key = match component_string(key, "key") {
        Ok(key) => key,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let expected = match component_byte_list(expected, "expected") {
        Ok(expected) => expected,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    if let Err(e) = store_namespace_allowed(store.data(), &namespace) {
        return set_component_result(results, component_host_err(e));
    }
    let key = match namespaced_store_key(&namespace, &key) {
        Ok(key) => key,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let Some(private_store) = store.data().private_store.clone() else {
        return set_component_result(
            results,
            component_host_err(HostError::Denied("store unavailable".into())),
        );
    };
    let petal_hash = store.data().petal_hash.clone();
    match private_store.del_if_value(&petal_hash, &key, &expected) {
        Ok(()) => set_component_result(results, component_ok(None)),
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_sign_hash(
    _store: StoreContextMut<'_, StoreData>,
    _params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    set_component_result(results, component_host_err(legacy_signing_unsupported()))
}

#[cfg(test)]
async fn component_sign_payload(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    component_sign_payload_versioned(store, params, results, false, false).await
}

#[cfg(test)]
async fn component_sign_payload_scoped(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    component_sign_payload_versioned(store, params, results, true, false).await
}

async fn component_sign_payload_current(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    component_sign_payload_versioned(store, params, results, true, true).await
}

async fn component_sign_payload_versioned(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
    allow_explicit_key: bool,
    safe_pending: bool,
) -> anyhow::Result<()> {
    let req = match component_payload_sign_request(
        store.data(),
        params,
        allow_explicit_key,
        safe_pending,
    ) {
        Ok(req) => req,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let expected_signature_len = payload_signature_len(&req.signature_algorithm);
    let host = store.data().host.clone();
    match host.sign_payload_outcome(req).await {
        Ok(SignOutcome::Signature(signature))
            if expected_signature_len.is_some_and(|length| signature.len() == length) =>
        {
            set_component_result(results, component_sign_signature(signature))
        }
        Ok(SignOutcome::Signature(_)) => set_component_result(
            results,
            component_host_err(HostError::Backend(
                "sign-payload returned a signature with the wrong normalized encoding".into(),
            )),
        ),
        Ok(SignOutcome::ApprovalPending(approval)) if safe_pending => set_component_result(
            results,
            component_sign_approval_pending(approval.action_id, approval.expires_ms),
        ),
        Ok(SignOutcome::ApprovalPending(approval)) => set_component_result(
            results,
            component_host_err(legacy_approval_pending_error(
                &approval.action_id,
                approval.expires_ms,
            )),
        ),
        Ok(SignOutcome::ApprovalRequired(approval)) if safe_pending => set_component_result(
            results,
            component_sign_approval_pending(approval.action_id, approval.expires_ms),
        ),
        Ok(SignOutcome::ApprovalRequired(approval)) => set_component_result(
            results,
            component_host_err(legacy_approval_pending_error(
                &approval.action_id,
                approval.expires_ms,
            )),
        ),
        Err(err) => set_component_result(results, component_host_err(err)),
    }
}

fn legacy_approval_pending_error(action_id: &str, expires_ms: u64) -> HostError {
    const MAX_ACTION_ID_CHARS: usize = 128;
    let bounded_action_id: String = action_id.chars().take(MAX_ACTION_ID_CHARS).collect();
    HostError::Backend(format!(
        "APPROVAL_PENDING action_id={bounded_action_id:?} expires_ms={expires_ms}; retry after owner approval"
    ))
}

async fn component_sign_payload_batch(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    let req = match component_payload_batch_sign_request(store.data(), params) {
        Ok(req) => req,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let expected_count = req.payloads.len();
    let expected_signature_len = payload_signature_len(&req.signature_algorithm);
    let host = store.data().host.clone();
    match host.sign_payload_batch_outcome(req).await {
        Ok(PayloadBatchSignOutcome::Signatures(signatures))
            if signatures.len() == expected_count
                && expected_signature_len.is_some_and(|length| {
                    signatures.iter().all(|signature| signature.len() == length)
                }) =>
        {
            set_component_result(results, component_sign_batch_signatures(signatures))
        }
        Ok(PayloadBatchSignOutcome::Signatures(_)) => set_component_result(
            results,
            component_host_err(HostError::Backend(
                "sign-payload-batch returned the wrong count or normalized encoding".into(),
            )),
        ),
        Ok(PayloadBatchSignOutcome::ApprovalPending(approval)) => set_component_result(
            results,
            component_sign_approval_pending(approval.action_id, approval.expires_ms),
        ),
        Err(err) => set_component_result(results, component_host_err(err)),
    }
}

async fn component_sign_hashes(
    _store: StoreContextMut<'_, StoreData>,
    _params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    set_component_result(results, component_host_err(legacy_signing_unsupported()))
}

async fn component_petal_key_request(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::KeyDerive) {
        log_denied(store.data(), "component_petal_key_request");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("key.derive".into())),
        );
    }
    let [ComponentVal::List(bytes)] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:key/derive@0.1.0 request payload".into(),
            )),
        );
    };
    let bytes = match bytes
        .iter()
        .map(|value| match value {
            ComponentVal::U8(byte) => Ok(*byte),
            _ => Err(HostError::Invalid(
                "Petal key request payload must be bytes".into(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(bytes) => bytes,
        Err(error) => return set_component_result(results, component_host_err(error)),
    };
    let guest: PetalKeyGuestRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(error) => {
            return set_component_result(
                results,
                component_host_err(HostError::Invalid(format!(
                    "decode Petal key request: {error}"
                ))),
            );
        }
    };
    let mut request = PetalKeyRequest::from(guest);
    request.context = store.data().sign_context.clone();
    let host = store.data().host.clone();
    match host.petal_key_request(request).await {
        Ok(outcome) => match serde_jcs::to_vec(&outcome) {
            Ok(bytes) => set_component_result(results, component_ok(Some(component_bytes(bytes)))),
            Err(error) => set_component_result(
                results,
                component_host_err(HostError::Backend(format!(
                    "encode Petal key result: {error}"
                ))),
            ),
        },
        Err(error) => {
            // The guest collapses a host error to its variant name, so the
            // reason reaches neither the Petal nor the mount. Record it
            // host-side, where it is not observable by an evaluated agent.
            log_host_error(store.data(), "component_petal_key_request", &error);
            set_component_result(results, component_host_err(error))
        }
    }
}

fn legacy_signing_unsupported() -> HostError {
    HostError::UnsupportedVersion(
        "bloom:sign/signing@0.1.0 hash-only signing is disabled; use @0.2.0".into(),
    )
}

fn component_payload_sign_request(
    data: &StoreData,
    params: &[ComponentVal],
    allow_explicit_key: bool,
    validate_claim_jcs: bool,
) -> Result<PayloadSignRequest, HostError> {
    if !data.caps.contains(&Capability::Sign) {
        log_denied(data, "component_sign_payload");
        return Err(HostError::Denied("sign".into()));
    }
    let [ComponentVal::Record(fields)] = params else {
        return Err(HostError::Invalid(
            "invalid bloom:sign.sign-payload params".into(),
        ));
    };
    component_payload_sign_record(data, fields, allow_explicit_key, validate_claim_jcs)
}

fn payload_signature_len(algorithm: &str) -> Option<usize> {
    match algorithm {
        "secp256k1-keccak256-recoverable" | "secp256k1-sha256-recoverable" => Some(65),
        "ed25519-message" => Some(64),
        _ => None,
    }
}

fn component_payload_sign_record(
    data: &StoreData,
    fields: &[(String, ComponentVal)],
    allow_explicit_key: bool,
    validate_claim_jcs: bool,
) -> Result<PayloadSignRequest, HostError> {
    let wallet = component_record_string(fields, "wallet")?;
    let preimage = component_record_bytes(fields, "preimage")?;
    let claimed_hash = component_record_bytes(fields, "claimed-hash")?;
    if claimed_hash.len() != 32 {
        return Err(HostError::Invalid(
            "sign-payload requires a 32-byte claimed-hash".into(),
        ));
    }
    let signature_algorithm = component_record_string(fields, "signature-algorithm")?;
    let operation_class = component_record_string(fields, "operation-class")?;
    let petal_use_claim_jcs = component_record_bytes(fields, "petal-use-claim-jcs")?;
    if wallet.trim().is_empty()
        || signature_algorithm.trim().is_empty()
        || operation_class.trim().is_empty()
        || petal_use_claim_jcs.is_empty()
    {
        return Err(HostError::Invalid(
            "payload signing identity and claim fields must be non-empty".into(),
        ));
    }
    if !sign_intent_allowed(data, &operation_class) {
        return Err(HostError::Denied(format!(
            "sign operation class {operation_class:?} is not allowed"
        )));
    }
    if validate_claim_jcs {
        validate_petal_use_claim_jcs(&petal_use_claim_jcs)?;
        if preimage.is_empty() {
            return Err(HostError::Invalid(
                "sign-payload requires a non-empty preimage".into(),
            ));
        }
        if payload_signature_len(&signature_algorithm).is_none() {
            return Err(HostError::Invalid(format!(
                "unsupported payload signature algorithm {signature_algorithm:?}"
            )));
        }
    }
    let mut hash32 = [0u8; 32];
    hash32.copy_from_slice(&claimed_hash);
    let key_ref = if allow_explicit_key {
        match component_record_optional_bytes(fields, "key-ref-jcs")? {
            None => None,
            Some(bytes) => {
                let key_ref: bloom_broker_api::KeyRef =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        HostError::Invalid(format!("decode explicit Petal KeyRef: {error}"))
                    })?;
                let canonical = serde_jcs::to_vec(&key_ref).map_err(|error| {
                    HostError::Invalid(format!("canonicalize explicit Petal KeyRef: {error}"))
                })?;
                if canonical != bytes {
                    return Err(HostError::Invalid(
                        "explicit Petal KeyRef must use exact RFC 8785 canonical JSON".into(),
                    ));
                }
                Some(key_ref)
            }
        }
    } else {
        None
    };
    let selector = if allow_explicit_key {
        match component_record_field(fields, "selector")? {
            ComponentVal::Enum(value) if value == "exact" => {
                bloom_broker_api::PetalSignSelector::Exact
            }
            ComponentVal::Enum(value) if value == "reusable" => {
                bloom_broker_api::PetalSignSelector::Reusable
            }
            ComponentVal::Enum(value) => {
                return Err(HostError::Invalid(format!(
                    "unknown bloom:sign/signing@0.2.0 selector {value:?}"
                )));
            }
            other => {
                return Err(HostError::Invalid(format!(
                    "component selector expected exact|reusable enum, got {other:?}"
                )));
            }
        }
    } else {
        bloom_broker_api::PetalSignSelector::Reusable
    };
    Ok(PayloadSignRequest {
        wallet,
        preimage,
        claimed_hash: hash32,
        signature_algorithm,
        operation_class,
        petal_use_claim_jcs,
        claim_assurance_evidence: component_record_optional_bytes(
            fields,
            "claim-assurance-evidence",
        )?,
        approval_hint: component_record_optional_string(fields, "approval-hint")?,
        action: component_record_optional_bytes(fields, "action")?,
        advisory: component_record_optional_bytes(fields, "advisory")?,
        selector,
        key_ref,
        context: data.sign_context.clone(),
    })
}

fn component_payload_batch_sign_request(
    data: &StoreData,
    params: &[ComponentVal],
) -> Result<PayloadBatchSignRequest, HostError> {
    if !data.caps.contains(&Capability::Sign) {
        log_denied(data, "component_sign_payload_batch");
        return Err(HostError::Denied("sign".into()));
    }
    let [ComponentVal::Record(fields)] = params else {
        return Err(HostError::Invalid(
            "invalid bloom:sign.sign-payload-batch params".into(),
        ));
    };
    let wallet = component_record_string(fields, "wallet")?;
    let signature_algorithm = component_record_string(fields, "signature-algorithm")?;
    let operation_class = component_record_string(fields, "operation-class")?;
    let petal_use_claim_jcs = component_record_bytes(fields, "petal-use-claim-jcs")?;
    if wallet.trim().is_empty() || operation_class.trim().is_empty() {
        return Err(HostError::Invalid(
            "payload batch identity fields must be non-empty".into(),
        ));
    }
    if payload_signature_len(&signature_algorithm).is_none() {
        return Err(HostError::Invalid(format!(
            "unsupported payload signature algorithm {signature_algorithm:?}"
        )));
    }
    if !sign_intent_allowed(data, &operation_class) {
        return Err(HostError::Denied(format!(
            "sign operation class {operation_class:?} is not allowed"
        )));
    }
    validate_petal_use_claim_jcs(&petal_use_claim_jcs)?;

    let ComponentVal::List(items) = component_record_field(fields, "payloads")? else {
        return Err(HostError::Invalid(
            "payloads must be a list of payload-sign-item records".into(),
        ));
    };
    if items.is_empty() || items.len() > MAX_SIGN_BATCH_ITEMS {
        return Err(HostError::Invalid(format!(
            "payload batch must contain 1..={MAX_SIGN_BATCH_ITEMS} items"
        )));
    }
    let mut total_bytes = 0usize;
    let mut payloads = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let ComponentVal::Record(item_fields) = item else {
            return Err(HostError::Invalid(format!(
                "payload item {index} must be a record"
            )));
        };
        let preimage = component_record_bytes(item_fields, "preimage")?;
        if preimage.is_empty() {
            return Err(HostError::Invalid(format!(
                "payload item {index} has an empty preimage"
            )));
        }
        if preimage.len() > MAX_SIGN_BATCH_CHILD_BYTES {
            return Err(HostError::Invalid(format!(
                "payload item {index} exceeds {MAX_SIGN_BATCH_CHILD_BYTES} bytes"
            )));
        }
        total_bytes = total_bytes
            .checked_add(preimage.len())
            .ok_or_else(|| HostError::Invalid("payload batch byte count overflowed".into()))?;
        if total_bytes > MAX_SIGN_BATCH_PAYLOAD_BYTES {
            return Err(HostError::Invalid(format!(
                "payload batch exceeds {MAX_SIGN_BATCH_PAYLOAD_BYTES} bytes"
            )));
        }
        let claimed_hash = component_record_bytes(item_fields, "claimed-hash")?;
        if claimed_hash.len() != 32 {
            return Err(HostError::Invalid(format!(
                "payload item {index} requires a 32-byte claimed-hash"
            )));
        }
        let mut hash32 = [0u8; 32];
        hash32.copy_from_slice(&claimed_hash);
        payloads.push(PayloadSignItem {
            preimage,
            claimed_hash: hash32,
        });
    }

    let selector = match component_record_field(fields, "selector")? {
        ComponentVal::Enum(value) if value == "exact" => bloom_broker_api::PetalSignSelector::Exact,
        ComponentVal::Enum(value) if value == "reusable" => {
            bloom_broker_api::PetalSignSelector::Reusable
        }
        other => {
            return Err(HostError::Invalid(format!(
                "component selector expected exact|reusable enum, got {other:?}"
            )));
        }
    };
    let key_ref = match component_record_optional_bytes(fields, "key-ref-jcs")? {
        None => None,
        Some(bytes) => {
            let key_ref: bloom_broker_api::KeyRef =
                serde_json::from_slice(&bytes).map_err(|error| {
                    HostError::Invalid(format!("decode explicit Petal KeyRef: {error}"))
                })?;
            let canonical = serde_jcs::to_vec(&key_ref).map_err(|error| {
                HostError::Invalid(format!("canonicalize explicit Petal KeyRef: {error}"))
            })?;
            if canonical != bytes {
                return Err(HostError::Invalid(
                    "explicit Petal KeyRef must use exact RFC 8785 canonical JSON".into(),
                ));
            }
            Some(key_ref)
        }
    };

    Ok(PayloadBatchSignRequest {
        wallet,
        payloads,
        signature_algorithm,
        operation_class,
        petal_use_claim_jcs,
        claim_assurance_evidence: component_record_optional_bytes(
            fields,
            "claim-assurance-evidence",
        )?,
        approval_hint: component_record_optional_string(fields, "approval-hint")?,
        action: component_record_optional_bytes(fields, "action")?,
        advisory: component_record_optional_bytes(fields, "advisory")?,
        selector,
        key_ref,
        context: data.sign_context.clone(),
    })
}

fn validate_petal_use_claim_jcs(bytes: &[u8]) -> Result<(), HostError> {
    let claim: bloom_broker_api::PetalUseClaim = serde_json::from_slice(bytes)
        .map_err(|error| HostError::Invalid(format!("decode PetalUseClaim: {error}")))?;
    let canonical = serde_jcs::to_vec(&claim)
        .map_err(|error| HostError::Invalid(format!("canonicalize PetalUseClaim: {error}")))?;
    if canonical != bytes {
        return Err(HostError::Invalid(
            "PetalUseClaim must use exact RFC 8785 canonical JSON".into(),
        ));
    }
    Ok(())
}

fn component_sign_signature(signature: Vec<u8>) -> ComponentVal {
    ComponentVal::Result(Ok(Some(Box::new(ComponentVal::Variant(
        "signature".into(),
        Some(Box::new(component_bytes(signature))),
    )))))
}

fn component_sign_approval_pending(action_id: String, expires_ms: u64) -> ComponentVal {
    ComponentVal::Result(Ok(Some(Box::new(ComponentVal::Variant(
        "approval-pending".into(),
        Some(Box::new(ComponentVal::Record(vec![
            ("action-id".into(), ComponentVal::String(action_id)),
            ("expires-ms".into(), ComponentVal::U64(expires_ms)),
        ]))),
    )))))
}

fn component_sign_batch_signatures(signatures: Vec<Vec<u8>>) -> ComponentVal {
    ComponentVal::Result(Ok(Some(Box::new(ComponentVal::Variant(
        "signatures".into(),
        Some(Box::new(ComponentVal::List(
            signatures.into_iter().map(component_bytes).collect(),
        ))),
    )))))
}

async fn component_evm_tx_stage(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::TxOutbox) {
        log_denied(store.data(), "component_evm_tx_stage");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("tx.outbox".into())),
        );
    }
    let [ComponentVal::Record(fields)] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:tx.outbox stage params".into(),
            )),
        );
    };
    let request = match component_evm_transaction_request(fields, store.data().sign_context.clone())
    {
        Ok(request) => request,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let host = store.data().host.clone();
    match host.evm_tx_stage(request).await {
        Ok(outcome) => set_component_result(results, component_evm_outbox_outcome(outcome)),
        Err(err) => set_component_result(results, component_host_err(err)),
    }
}

async fn component_evm_tx_confirm(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::TxOutbox) {
        log_denied(store.data(), "component_evm_tx_confirm");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("tx.outbox".into())),
        );
    }
    let [wallet, chain, outbox_id, acknowledge_warnings] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:tx.outbox confirm params".into(),
            )),
        );
    };
    let wallet = match component_string(wallet, "wallet") {
        Ok(value) => value,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let chain = match component_string(chain, "chain") {
        Ok(value) => value,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let outbox_id = match component_string(outbox_id, "outbox-id") {
        Ok(value) => value,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let ComponentVal::Bool(acknowledge_warnings) = acknowledge_warnings else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "acknowledge-warnings must be a bool".into(),
            )),
        );
    };
    let host = store.data().host.clone();
    match host
        .evm_tx_confirm(
            wallet,
            chain,
            outbox_id,
            *acknowledge_warnings,
            store.data().sign_context.clone(),
        )
        .await
    {
        Ok(outcome) => set_component_result(results, component_evm_outbox_outcome(outcome)),
        Err(err) => set_component_result(results, component_host_err(err)),
    }
}

async fn component_evm_tx_inspect(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::TxOutbox) {
        log_denied(store.data(), "component_evm_tx_inspect");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("tx.outbox".into())),
        );
    }
    let [wallet, chain, outbox_id] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:tx.outbox inspect params".into(),
            )),
        );
    };
    let wallet = match component_string(wallet, "wallet") {
        Ok(value) => value,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let chain = match component_string(chain, "chain") {
        Ok(value) => value,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let outbox_id = match component_string(outbox_id, "outbox-id") {
        Ok(value) => value,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let host = store.data().host.clone();
    match host
        .evm_tx_inspect(wallet, chain, outbox_id, store.data().sign_context.clone())
        .await
    {
        Ok(inspection) => {
            set_component_result(results, component_evm_outbox_inspection(inspection))
        }
        Err(err) => set_component_result(results, component_host_err(err)),
    }
}

fn component_evm_transaction_request(
    fields: &[(String, ComponentVal)],
    context: Option<PetalRouteContext>,
) -> Result<EvmTransactionRequest, HostError> {
    let string = |name| {
        component_string_field(fields, name).map_err(|err| HostError::Invalid(err.to_string()))
    };
    let optional_u64 = |name| {
        component_optional_u64_field(fields, name)
            .map_err(|err| HostError::Invalid(err.to_string()))
    };
    let optional_string = |name| {
        component_optional_string_field(fields, name)
            .map_err(|err| HostError::Invalid(err.to_string()))
    };
    Ok(EvmTransactionRequest {
        wallet: string("wallet")?,
        chain: string("chain")?,
        to: string("to")?,
        value_wei: string("value-wei")?,
        data_hex: string("data-hex")?,
        nonce: optional_u64("nonce")?,
        max_fee_per_gas: optional_string("max-fee-per-gas")?,
        max_priority_fee_per_gas: optional_string("max-priority-fee-per-gas")?,
        context,
    })
}

fn component_evm_outbox_outcome(outcome: EvmOutboxOutcome) -> ComponentVal {
    let approval = outcome.approval_required.map(|approval| {
        Box::new(ComponentVal::Record(vec![
            ("action-id".into(), ComponentVal::String(approval.action_id)),
            ("expires-ms".into(), ComponentVal::U64(approval.expires_ms)),
        ]))
    });
    component_ok(Some(ComponentVal::Record(vec![
        ("outbox-id".into(), ComponentVal::String(outcome.outbox_id)),
        ("plan-md".into(), ComponentVal::String(outcome.plan_md)),
        ("approval".into(), ComponentVal::Option(approval)),
    ])))
}

fn component_evm_outbox_inspection(inspection: EvmOutboxInspection) -> ComponentVal {
    component_ok(Some(ComponentVal::Record(vec![
        (
            "outbox-id".into(),
            ComponentVal::String(inspection.outbox_id),
        ),
        ("state".into(), ComponentVal::String(inspection.state)),
        (
            "tx-hash".into(),
            ComponentVal::Option(
                inspection
                    .tx_hash
                    .map(|value| Box::new(ComponentVal::String(value))),
            ),
        ),
        (
            "receipt-json".into(),
            ComponentVal::Option(
                inspection
                    .receipt_json
                    .map(|value| Box::new(ComponentVal::String(value))),
            ),
        ),
    ])))
}

async fn component_chain_call(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::Chain) {
        log_denied(store.data(), "component_chain_call");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("chain".into())),
        );
    }
    let req = match params {
        [ComponentVal::Record(fields)] => {
            component_chain_request(fields, store.data().sign_context.clone())
        }
        _ => Err(HostError::Invalid(
            "invalid bloom:chain.read call params".into(),
        )),
    };
    let req = match req {
        Ok(req) => req,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let host = store.data().host.clone();
    match host.chain_read(req).await {
        Ok(resp) => {
            set_component_result(results, component_ok(Some(component_chain_response(resp))))
        }
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_vfs_lookup(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::VfsRead) {
        log_denied(store.data(), "component_vfs_lookup");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("vfs.read".into())),
        );
    }
    let path = match component_single_string_param(params, "path") {
        Ok(path) => path,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let host = store.data().host.clone();
    match host.vfs_lookup(&path).await {
        Ok(entry) => set_component_result(results, component_ok(Some(component_vfs_entry(entry)))),
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_vfs_list(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::VfsRead) {
        log_denied(store.data(), "component_vfs_list");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("vfs.read".into())),
        );
    }
    let path = match component_single_string_param(params, "path") {
        Ok(path) => path,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let host = store.data().host.clone();
    match host.vfs_list(&path).await {
        Ok(names) => {
            let entries = names.into_iter().map(component_vfs_entry).collect();
            set_component_result(results, component_ok(Some(ComponentVal::List(entries))))
        }
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_vfs_read(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::VfsRead) {
        log_denied(store.data(), "component_vfs_read");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("vfs.read".into())),
        );
    }
    let path = match component_single_string_param(params, "path") {
        Ok(path) => path,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let host = store.data().host.clone();
    match host.vfs_read(&path).await {
        Ok(bytes) => set_component_result(results, component_ok(Some(component_bytes(bytes)))),
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_vfs_write(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    if !store.data().caps.contains(&Capability::VfsWrite) {
        log_denied(store.data(), "component_vfs_write");
        return set_component_result(
            results,
            component_host_err(HostError::Denied("vfs.write".into())),
        );
    }
    let [path, body] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid("invalid bloom:vfs.write params".into())),
        );
    };
    let path = match component_string(path, "path") {
        Ok(path) => path,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let body = match component_byte_list(body, "body") {
        Ok(body) => body,
        Err(e) => return set_component_result(results, component_host_err(e)),
    };
    let host = store.data().host.clone();
    match host.vfs_write(&path, &body).await {
        Ok(()) => set_component_result(results, component_ok(None)),
        Err(e) => set_component_result(results, component_host_err(e)),
    }
}

async fn component_env_now_ms(
    store: StoreContextMut<'_, StoreData>,
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    let now = if store.data().deterministic_env {
        0
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("system time before unix epoch: {e}"))?
            .as_millis();
        u64::try_from(now).map_err(|_| anyhow::anyhow!("system time overflow"))?
    };
    set_component_result(results, component_ok(Some(ComponentVal::U64(now))))
}

async fn component_env_random_bytes(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    let [len] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:env.random-bytes params".into(),
            )),
        );
    };
    let ComponentVal::U32(len) = len else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:env.random-bytes len".into(),
            )),
        );
    };
    if *len > DEFAULT_RANDOM_BYTES_CAP {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid("random-bytes length too large".into())),
        );
    }
    let mut bytes = vec![0u8; *len as usize];
    if !store.data().deterministic_env {
        getrandom::getrandom(&mut bytes)
            .map_err(|e| anyhow::anyhow!("random-bytes unavailable: {e}"))?;
    }
    set_component_result(results, component_ok(Some(component_bytes(bytes))))
}

async fn component_env_setting(
    store: StoreContextMut<'_, StoreData>,
    params: &[ComponentVal],
    results: &mut [ComponentVal],
) -> anyhow::Result<()> {
    let [key] = params else {
        return set_component_result(
            results,
            component_host_err(HostError::Invalid(
                "invalid bloom:env.setting params".into(),
            )),
        );
    };
    let key = match component_string(key, "key") {
        Ok(key) => key,
        Err(err) => return set_component_result(results, component_host_err(err)),
    };
    let value = store.data().runtime_settings.get(&key).cloned();
    set_component_result(
        results,
        component_ok(Some(ComponentVal::Option(
            value.map(|value| Box::new(ComponentVal::String(value))),
        ))),
    )
}

fn set_component_result(results: &mut [ComponentVal], val: ComponentVal) -> anyhow::Result<()> {
    let [result] = results else {
        anyhow::bail!("component host function expected one result slot");
    };
    *result = val;
    Ok(())
}

fn component_ok(value: Option<ComponentVal>) -> ComponentVal {
    ComponentVal::Result(Ok(value.map(Box::new)))
}

fn component_err(message: impl Into<String>) -> ComponentVal {
    ComponentVal::Result(Err(Some(Box::new(ComponentVal::String(message.into())))))
}

fn component_host_err(err: HostError) -> ComponentVal {
    component_err(err.to_string())
}

fn sign_intent_allowed(data: &StoreData, intent: &str) -> bool {
    data.sign_intents
        .as_ref()
        .map(|allowed| allowed.contains(intent))
        .unwrap_or(true)
}

fn store_namespace_allowed(data: &StoreData, namespace: &str) -> Result<(), HostError> {
    match &data.store_namespaces {
        Some(policy) => policy.check_namespace(namespace),
        None => Ok(()),
    }
}

fn store_namespace_put_allowed(
    data: &StoreData,
    namespace: &str,
    secret: bool,
) -> Result<(), HostError> {
    match &data.store_namespaces {
        Some(policy) => policy.check_put(namespace, secret),
        None => Ok(()),
    }
}

fn component_string(val: &ComponentVal, label: &str) -> Result<String, HostError> {
    match val {
        ComponentVal::String(value) => Ok(value.clone()),
        other => Err(HostError::Invalid(format!(
            "component {label} expected string, got {other:?}"
        ))),
    }
}

fn component_bool(val: &ComponentVal, label: &str) -> Result<bool, HostError> {
    match val {
        ComponentVal::Bool(value) => Ok(*value),
        other => Err(HostError::Invalid(format!(
            "component {label} expected bool, got {other:?}"
        ))),
    }
}

fn component_byte_list(val: &ComponentVal, label: &str) -> Result<Vec<u8>, HostError> {
    let ComponentVal::List(items) = val else {
        return Err(HostError::Invalid(format!(
            "component {label} expected list<u8>, got {val:?}"
        )));
    };
    items
        .iter()
        .map(|item| match item {
            ComponentVal::U8(byte) => Ok(*byte),
            other => Err(HostError::Invalid(format!(
                "component {label} expected u8 item, got {other:?}"
            ))),
        })
        .collect()
}

fn component_bytes(bytes: Vec<u8>) -> ComponentVal {
    ComponentVal::List(bytes.into_iter().map(ComponentVal::U8).collect())
}

fn component_single_string_param(
    params: &[ComponentVal],
    label: &str,
) -> Result<String, HostError> {
    let [value] = params else {
        return Err(HostError::Invalid(format!(
            "component expected single {label} param"
        )));
    };
    component_string(value, label)
}

fn component_namespace_key(params: &[ComponentVal]) -> Result<(String, String), HostError> {
    let [namespace, key] = params else {
        return Err(HostError::Invalid(
            "component store function expected namespace and key/prefix".into(),
        ));
    };
    Ok((
        component_string(namespace, "namespace")?,
        component_string(key, "key")?,
    ))
}

fn namespaced_store_key(namespace: &str, key: &str) -> Result<String, HostError> {
    if namespace.is_empty() {
        return Err(HostError::Invalid("store namespace is empty".into()));
    }
    Ok(format!("{namespace}/{key}"))
}

fn namespaced_store_prefix(namespace: &str, prefix: &str) -> Result<String, HostError> {
    if namespace.is_empty() {
        return Err(HostError::Invalid("store namespace is empty".into()));
    }
    if prefix.is_empty() {
        Ok(format!("{namespace}/"))
    } else {
        Ok(format!("{namespace}/{prefix}"))
    }
}

fn component_http_request(
    fields: &[(String, ComponentVal)],
) -> Result<crate::abi::HttpRequest, HostError> {
    Ok(crate::abi::HttpRequest {
        method: component_record_string(fields, "method")?,
        url: component_record_string(fields, "url")?,
        headers: component_record_headers(fields, "headers")?,
        body: component_record_bytes(fields, "body")?,
    })
}

fn component_http_response(resp: crate::abi::HttpResponse) -> ComponentVal {
    ComponentVal::Record(vec![
        ("status".into(), ComponentVal::U16(resp.status)),
        ("headers".into(), component_headers(resp.headers)),
        ("body".into(), component_bytes(resp.body)),
    ])
}

fn component_chain_request(
    fields: &[(String, ComponentVal)],
    context: Option<PetalRouteContext>,
) -> Result<ChainRequest, HostError> {
    Ok(ChainRequest {
        chain: component_record_string(fields, "chain")?,
        method: component_record_string(fields, "method")?,
        params_json: component_record_string(fields, "params-json")?,
        context,
    })
}

fn component_chain_response(resp: ChainResponse) -> ComponentVal {
    ComponentVal::Record(vec![(
        "result-json".into(),
        ComponentVal::String(resp.result_json),
    )])
}

fn component_record_string(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<String, HostError> {
    component_string(component_record_field(fields, name)?, name)
}

fn component_record_bytes(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<Vec<u8>, HostError> {
    component_byte_list(component_record_field(fields, name)?, name)
}

fn component_record_optional_bytes(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<Option<Vec<u8>>, HostError> {
    match component_record_field(fields, name)? {
        ComponentVal::Option(None) => Ok(None),
        ComponentVal::Option(Some(value)) => component_byte_list(value, name).map(Some),
        other => Err(HostError::Invalid(format!(
            "component {name} expected option<list<u8>>, got {other:?}"
        ))),
    }
}

fn component_record_optional_string(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<Option<String>, HostError> {
    match component_record_field(fields, name)? {
        ComponentVal::Option(None) => Ok(None),
        ComponentVal::Option(Some(value)) => component_string(value, name).map(Some),
        other => Err(HostError::Invalid(format!(
            "component {name} expected option<string>, got {other:?}"
        ))),
    }
}

fn component_record_headers(
    fields: &[(String, ComponentVal)],
    name: &str,
) -> Result<Vec<(String, String)>, HostError> {
    component_headers_from_val(component_record_field(fields, name)?, name)
}

fn component_record_field<'a>(
    fields: &'a [(String, ComponentVal)],
    name: &str,
) -> Result<&'a ComponentVal, HostError> {
    fields
        .iter()
        .find_map(|(field, value)| (field == name).then_some(value))
        .ok_or_else(|| HostError::Invalid(format!("component record missing field {name:?}")))
}

fn component_headers_from_val(
    val: &ComponentVal,
    label: &str,
) -> Result<Vec<(String, String)>, HostError> {
    let ComponentVal::List(items) = val else {
        return Err(HostError::Invalid(format!(
            "component {label} expected list<tuple<string,string>>, got {val:?}"
        )));
    };
    items
        .iter()
        .map(|item| {
            let ComponentVal::Tuple(parts) = item else {
                return Err(HostError::Invalid(format!(
                    "component {label} expected tuple item, got {item:?}"
                )));
            };
            let [key, value] = parts.as_slice() else {
                return Err(HostError::Invalid(format!(
                    "component {label} expected pair tuple"
                )));
            };
            Ok((
                component_string(key, "header-name")?,
                component_string(value, "header-value")?,
            ))
        })
        .collect()
}

fn component_headers(headers: Vec<(String, String)>) -> ComponentVal {
    ComponentVal::List(
        headers
            .into_iter()
            .map(|(key, value)| {
                ComponentVal::Tuple(vec![ComponentVal::String(key), ComponentVal::String(value)])
            })
            .collect(),
    )
}

fn component_vfs_entry(entry: HostVfsEntry) -> ComponentVal {
    let kind = match entry.kind {
        HostVfsEntryKind::Dir => "dir",
        HostVfsEntryKind::File => "file",
        HostVfsEntryKind::Symlink => "symlink",
    };
    ComponentVal::Record(vec![
        (
            "name".into(),
            ComponentVal::String(vfs_entry_name(&entry.name)),
        ),
        ("kind".into(), ComponentVal::Enum(kind.into())),
        ("mode".into(), ComponentVal::U32(entry.mode)),
        (
            "size".into(),
            ComponentVal::Option(entry.size.map(|size| Box::new(ComponentVal::U64(size)))),
        ),
        (
            "link-target".into(),
            ComponentVal::Option(
                entry
                    .link_target
                    .map(|target| Box::new(ComponentVal::String(target))),
            ),
        ),
    ])
}

fn vfs_entry_name(path_or_name: &str) -> String {
    path_or_name
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or(path_or_name)
        .to_string()
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
    link_vfs_imports(linker, "bloom")?;
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

fn log_host_error(d: &StoreData, op: &str, error: &HostError) {
    tracing::warn!(
        target: "bloom_petals::vm",
        petal = %d.petal_hash,
        op,
        error = %error,
        "host call failed"
    );
}

fn log_denied(d: &StoreData, op: &str) {
    tracing::info!(
        target: "bloom_petals::vm",
        petal = %d.petal_hash,
        op,
        "host capability denied"
    );
}

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

#[cfg(test)]
static DROPPED_MEM_LIMITERS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
impl Drop for MemLimiter {
    fn drop(&mut self) {
        DROPPED_MEM_LIMITERS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
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
        DispatchOp, DispatchRequest, DispatchResponse, HttpRequest, HttpResponse,
        PayloadBatchSignOutcome, PayloadBatchSignRequest, PayloadSignRequest,
    };
    use crate::host::DenyHost;
    use crate::meta::PetalMode;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use wasmtime::AsContextMut;

    const VALID_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn component_payload_request(wallet: &str, byte: u8, operation_class: &str) -> ComponentVal {
        ComponentVal::Record(vec![
            ("wallet".into(), ComponentVal::String(wallet.into())),
            ("preimage".into(), component_bytes(vec![byte; 48])),
            ("claimed-hash".into(), component_bytes(vec![byte; 32])),
            (
                "signature-algorithm".into(),
                ComponentVal::String("secp256k1-keccak256-recoverable".into()),
            ),
            (
                "operation-class".into(),
                ComponentVal::String(operation_class.into()),
            ),
            (
                "petal-use-claim-jcs".into(),
                component_bytes(br#"{"claim":"complete"}"#.to_vec()),
            ),
            (
                "claim-assurance-evidence".into(),
                ComponentVal::Option(None),
            ),
            ("approval-hint".into(), ComponentVal::Option(None)),
            ("action".into(), ComponentVal::Option(None)),
            ("advisory".into(), ComponentVal::Option(None)),
        ])
    }

    fn component_scoped_payload_request(
        wallet: &str,
        byte: u8,
        operation_class: &str,
        key_ref_jcs: Option<Vec<u8>>,
    ) -> ComponentVal {
        component_scoped_payload_request_with_selector(
            wallet,
            byte,
            operation_class,
            "reusable",
            key_ref_jcs,
        )
    }

    fn component_scoped_payload_request_with_selector(
        wallet: &str,
        byte: u8,
        operation_class: &str,
        selector: &str,
        key_ref_jcs: Option<Vec<u8>>,
    ) -> ComponentVal {
        let ComponentVal::Record(mut fields) =
            component_payload_request(wallet, byte, operation_class)
        else {
            unreachable!()
        };
        fields.push(("selector".into(), ComponentVal::Enum(selector.into())));
        fields.push((
            "key-ref-jcs".into(),
            ComponentVal::Option(key_ref_jcs.map(|bytes| Box::new(component_bytes(bytes)))),
        ));
        ComponentVal::Record(fields)
    }

    fn canonical_test_claim() -> Vec<u8> {
        let digest = bloom_broker_api::Digest32::from_bytes([3; 32]);
        serde_jcs::to_vec(&bloom_broker_api::PetalUseClaim {
            package_hash: bloom_broker_api::Digest32::from_bytes([4; 32]),
            route: "r000001".into(),
            operation_class: bloom_broker_api::Token::new("orders.place").unwrap(),
            crypto_suite: bloom_broker_api::CryptoSuite::Secp256k1Keccak256Recoverable,
            payload_digest: digest.clone(),
            ordered_hashes: vec![digest],
            declared_debits: Vec::new(),
            declared_destinations: Vec::new(),
            declared_fee: bloom_broker_api::DeclaredFee::None,
            nonce: bloom_broker_api::RequestNonce::from_bytes([5; 16]),
            claim_assurance: bloom_broker_api::ClaimAssurance::MachineAsserted,
        })
        .unwrap()
    }

    fn component_payload_batch_request(bytes: &[u8]) -> ComponentVal {
        let payloads = bytes
            .iter()
            .map(|byte| {
                ComponentVal::Record(vec![
                    ("preimage".into(), component_bytes(vec![*byte; 48])),
                    ("claimed-hash".into(), component_bytes(vec![*byte; 32])),
                ])
            })
            .collect();
        ComponentVal::Record(vec![
            ("wallet".into(), ComponentVal::String("primary".into())),
            ("payloads".into(), ComponentVal::List(payloads)),
            (
                "signature-algorithm".into(),
                ComponentVal::String("secp256k1-keccak256-recoverable".into()),
            ),
            (
                "operation-class".into(),
                ComponentVal::String("orders.place".into()),
            ),
            (
                "petal-use-claim-jcs".into(),
                component_bytes(canonical_test_claim()),
            ),
            (
                "claim-assurance-evidence".into(),
                ComponentVal::Option(None),
            ),
            ("approval-hint".into(), ComponentVal::Option(None)),
            ("action".into(), ComponentVal::Option(None)),
            ("advisory".into(), ComponentVal::Option(None)),
            ("selector".into(), ComponentVal::Enum("exact".into())),
            ("key-ref-jcs".into(), ComponentVal::Option(None)),
        ])
    }

    fn component_current_payload_request() -> ComponentVal {
        let mut request = component_scoped_payload_request("primary", 3, "orders.place", None);
        let ComponentVal::Record(fields) = &mut request else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(name, _)| name == "petal-use-claim-jcs")
            .unwrap()
            .1 = component_bytes(canonical_test_claim());
        request
    }

    /// Compile a WAT snippet to wasm bytes.
    fn wat(src: &str) -> Vec<u8> {
        wat::parse_str(src).expect("valid WAT")
    }

    fn denied_byte() -> u8 {
        (HostError::Denied("".into()).as_wasm_code() as i8) as u8
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

    #[test]
    fn store_data_owns_and_drops_its_memory_limiter() {
        let before = DROPPED_MEM_LIMITERS.load(std::sync::atomic::Ordering::SeqCst);
        let store = component_test_store(BTreeSet::new(), None, Arc::new(DenyHost));
        drop(store);
        let after = DROPPED_MEM_LIMITERS.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            after > before,
            "dropping a Wasmtime store must drop its owned memory limiter"
        );
    }

    /// The core-Wasm proposals accepted inside a Petal component form a host
    /// runtime profile, separate from the component's `bloom:route@0.1.0` WIT
    /// ABI. Most are inherited from moving Wasmtime defaults. Upgrading
    /// Wasmtime 26 -> 36 silently flipped `memory64` from rejected to accepted;
    /// this test makes the next such change an explicit compatibility choice.
    ///
    /// Adding a row here is fine. Flipping one changes the runtime profile.
    #[test]
    fn accepted_petal_component_surface_is_pinned() {
        let vm = PetalVm::new().expect("engine");
        // (proposal, core module body, accepted inside a component?)
        let cases: &[(&str, &str, bool)] = &[
            ("memory64", r#"(memory i64 1)"#, false),
            ("threads/shared-memory", r#"(memory 1 1 shared)"#, false),
            (
                "wide-arithmetic",
                r#"(func (result i64 i64)
                     (i64.const 1) (i64.const 2) (i64.mul_wide_s))"#,
                false,
            ),
            ("multi-memory", r#"(memory 1) (memory 1)"#, true),
            ("tail-call", r#"(func $a) (func $b (return_call $a))"#, true),
        ];
        for (name, module_body, want_accepted) in cases {
            // A proposal can be refused either by the text parser or by
            // component validation; for this profile both count as rejected.
            let component = format!("(component (core module {module_body}))");
            let accepted = wat::parse_str(&component)
                .ok()
                .is_some_and(|bytes| Component::from_binary(&vm.engine, &bytes).is_ok());
            assert_eq!(
                accepted, *want_accepted,
                "accepted Petal component surface changed for the {name} proposal: \
                 expected accepted={want_accepted}, got accepted={accepted}. \
                 If this is intended, update the runtime profile and its \
                 compatibility documentation."
            );
        }
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

    type TxConfirmCall = (String, String, String, bool, Option<PetalRouteContext>);
    type TxInspectCall = (String, String, String, Option<PetalRouteContext>);

    #[derive(Default)]
    struct MockHost {
        store: Mutex<HashMap<String, Vec<u8>>>,
        lists: Mutex<HashMap<String, Vec<HostVfsEntry>>>,
        vfs_reads: Mutex<Vec<String>>,
        http_calls: Mutex<Vec<HttpRequest>>,
        sign_calls: Mutex<Vec<PayloadSignRequest>>,
        sign_outcome: Mutex<Option<SignOutcome>>,
        payload_batch_calls: Mutex<Vec<PayloadBatchSignRequest>>,
        payload_batch_outcome: Mutex<Option<PayloadBatchSignOutcome>>,
        petal_key_calls: Mutex<Vec<PetalKeyRequest>>,
        petal_key_outcomes: Mutex<Vec<crate::abi::PetalKeyOutcome>>,
        authority_calls: Mutex<Vec<&'static str>>,
        tx_stage_calls: Mutex<Vec<EvmTransactionRequest>>,
        tx_confirm_calls: Mutex<Vec<TxConfirmCall>>,
        tx_inspect_calls: Mutex<Vec<TxInspectCall>>,
        tx_outcome: Mutex<Option<EvmOutboxOutcome>>,
        chain_calls: Mutex<Vec<ChainRequest>>,
    }

    #[async_trait]
    impl PetalHost for MockHost {
        async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
            if self.store.lock().contains_key(path) {
                return Ok(HostVfsEntry {
                    name: vfs_entry_name(path),
                    kind: HostVfsEntryKind::File,
                    mode: 0o644,
                    size: None,
                    link_target: None,
                });
            }
            if self.lists.lock().contains_key(path) {
                return Ok(HostVfsEntry {
                    name: vfs_entry_name(path),
                    kind: HostVfsEntryKind::Dir,
                    mode: 0o755,
                    size: None,
                    link_target: None,
                });
            }
            Err(HostError::NotFound(path.into()))
        }

        async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
            self.vfs_reads.lock().push(path.into());
            self.store
                .lock()
                .get(path)
                .cloned()
                .ok_or_else(|| HostError::NotFound(path.into()))
        }
        async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
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

        async fn sign_payload_outcome(
            &self,
            req: PayloadSignRequest,
        ) -> Result<SignOutcome, HostError> {
            self.authority_calls.lock().push("sign");
            self.sign_calls.lock().push(req);
            Ok(self
                .sign_outcome
                .lock()
                .clone()
                .unwrap_or_else(|| SignOutcome::Signature(vec![7u8; 65])))
        }

        async fn sign_payload_batch_outcome(
            &self,
            req: PayloadBatchSignRequest,
        ) -> Result<PayloadBatchSignOutcome, HostError> {
            let count = req.payloads.len();
            self.payload_batch_calls.lock().push(req);
            Ok(self
                .payload_batch_outcome
                .lock()
                .clone()
                .unwrap_or_else(|| PayloadBatchSignOutcome::Signatures(vec![vec![8; 65]; count])))
        }

        async fn petal_key_request(
            &self,
            req: PetalKeyRequest,
        ) -> Result<crate::abi::PetalKeyOutcome, HostError> {
            self.authority_calls.lock().push("derive");
            self.petal_key_calls.lock().push(req);
            let mut outcomes = self.petal_key_outcomes.lock();
            if !outcomes.is_empty() {
                return Ok(outcomes.remove(0));
            }
            Ok(crate::abi::PetalKeyOutcome::Pending {
                operation_id: "11".repeat(32),
                scope_digest: "22".repeat(32),
            })
        }

        async fn evm_tx_stage(
            &self,
            req: EvmTransactionRequest,
        ) -> Result<EvmOutboxOutcome, HostError> {
            self.tx_stage_calls.lock().push(req);
            Ok(self.tx_outcome.lock().clone().unwrap_or(EvmOutboxOutcome {
                outbox_id: "outbox-1".into(),
                plan_md: "# transaction\n".into(),
                approval_required: None,
            }))
        }

        async fn evm_tx_confirm(
            &self,
            wallet: String,
            chain: String,
            outbox_id: String,
            acknowledge_warnings: bool,
            context: Option<PetalRouteContext>,
        ) -> Result<EvmOutboxOutcome, HostError> {
            self.tx_confirm_calls.lock().push((
                wallet,
                chain,
                outbox_id,
                acknowledge_warnings,
                context,
            ));
            Ok(self.tx_outcome.lock().clone().unwrap_or(EvmOutboxOutcome {
                outbox_id: "outbox-1".into(),
                plan_md: "# transaction\n".into(),
                approval_required: None,
            }))
        }

        async fn evm_tx_inspect(
            &self,
            wallet: String,
            chain: String,
            outbox_id: String,
            context: Option<PetalRouteContext>,
        ) -> Result<EvmOutboxInspection, HostError> {
            self.tx_inspect_calls
                .lock()
                .push((wallet, chain, outbox_id.clone(), context));
            Ok(EvmOutboxInspection {
                outbox_id,
                state: "sent".into(),
                tx_hash: Some(format!("0x{}", "ab".repeat(32))),
                receipt_json: Some(r#"{"outcome":"success"}"#.into()),
            })
        }

        async fn chain_read(&self, req: ChainRequest) -> Result<ChainResponse, HostError> {
            self.chain_calls.lock().push(req);
            Ok(ChainResponse {
                result_json: r#"{"ok":true}"#.into(),
            })
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

    #[test]
    fn component_route_response_maps_read_lookup_and_errors() {
        let params = route_component_params(
            &DispatchRequest {
                op: DispatchOp::Read,
                path: "alice.txt".into(),
                body: Vec::new(),
                ctx: vec![
                    ("name".into(), "spoofed".into()),
                    ("actor".into(), "agent".into()),
                    ("bloom.route_id".into(), "r000001".into()),
                ],
            },
            "echo",
            VALID_HASH,
            vec![("name".into(), "alice".into())],
        );
        let ComponentVal::Record(ctx) = &params[0] else {
            panic!("ctx was not a record");
        };
        let ComponentVal::List(bound_params) = component_field(ctx, "params").unwrap() else {
            panic!("ctx.params was not a list");
        };
        assert_eq!(
            bound_params,
            &[ComponentVal::Tuple(vec![
                ComponentVal::String("name".into()),
                ComponentVal::String("alice".into())
            ])]
        );
        assert!(
            !bound_params.iter().any(|value| matches!(
                value,
                ComponentVal::Tuple(fields)
                    if fields.first() == Some(&ComponentVal::String("bloom.route_id".into()))
            )),
            "route identity must come from the trusted route match, not request.ctx"
        );

        let read = route_component_response(
            DispatchOp::Read,
            ComponentVal::Result(Ok(Some(Box::new(ComponentVal::List(vec![
                ComponentVal::U8(b'o'),
                ComponentVal::U8(b'k'),
            ]))))),
        )
        .unwrap();
        assert_eq!(read, DispatchResponse::Read(b"ok".to_vec()));

        let lookup = route_component_response(
            DispatchOp::Lookup,
            ComponentVal::Result(Ok(Some(Box::new(component_entry(
                "status.json",
                "file",
                Some(2),
            ))))),
        )
        .unwrap();
        assert_eq!(
            lookup,
            DispatchResponse::Lookup(crate::abi::DispatchEntry {
                name: "status.json".into(),
                kind: crate::abi::DispatchEntryKind::File,
                size: 2,
                mode: 0o644,
                ttl_hint_ms: None,
                link_target: None,
            })
        );

        let denied = route_component_response(
            DispatchOp::Read,
            ComponentVal::Result(Err(Some(Box::new(ComponentVal::Variant(
                "denied".into(),
                Some(Box::new(ComponentVal::String("no".into()))),
            ))))),
        )
        .unwrap();
        assert_eq!(
            denied,
            DispatchResponse::Error {
                code: HostError::Denied("no".into()).as_wasm_code(),
                message: "no".into(),
            }
        );

        let not_a_dir = route_component_response(
            DispatchOp::Lookup,
            ComponentVal::Result(Err(Some(Box::new(ComponentVal::Variant(
                "not-a-dir".into(),
                Some(Box::new(ComponentVal::String("plain-file".into()))),
            ))))),
        )
        .unwrap();
        assert_eq!(
            not_a_dir,
            DispatchResponse::Error {
                code: COMPONENT_NOT_A_DIR_CODE,
                message: "plain-file".into(),
            }
        );

        let unsupported = route_component_response(
            DispatchOp::Write,
            ComponentVal::Result(Err(Some(Box::new(ComponentVal::Variant(
                "unsupported".into(),
                Some(Box::new(ComponentVal::String("write".into()))),
            ))))),
        )
        .unwrap();
        assert_eq!(
            unsupported,
            DispatchResponse::Error {
                code: COMPONENT_UNSUPPORTED_CODE,
                message: "write".into(),
            }
        );
    }

    #[tokio::test]
    async fn component_store_adapter_enforces_caps_and_namespaces_keys() {
        let tmp = TempDir::new().unwrap();
        let mut store = component_test_store(
            BTreeSet::new(),
            Some(PrivateStore::open(tmp.path()).unwrap()),
            Arc::new(DenyHost),
        );

        let mut denied = vec![ComponentVal::Bool(false)];
        component_store_put(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("drafts/a.json".into()),
                component_bytes(b"one".to_vec()),
                ComponentVal::Bool(false),
            ],
            &mut denied,
        )
        .await
        .unwrap();
        assert_component_err_contains(&denied[0], "denied");

        let mut caps = BTreeSet::new();
        caps.insert(Capability::Store);
        let mut store = component_test_store(
            caps,
            Some(PrivateStore::open(tmp.path()).unwrap()),
            Arc::new(DenyHost),
        );
        store.data_mut().store_namespaces = Some(StoreNamespacePolicy::from_namespaces(
            ["orders".to_string()],
            ["credentials".to_string()],
        ));

        let mut wrong_namespace = vec![ComponentVal::Bool(false)];
        component_store_put(
            store.as_context_mut(),
            &[
                ComponentVal::String("sessions".into()),
                ComponentVal::String("drafts/a.json".into()),
                component_bytes(b"blocked".to_vec()),
                ComponentVal::Bool(false),
            ],
            &mut wrong_namespace,
        )
        .await
        .unwrap();
        assert_component_err_contains(&wrong_namespace[0], "not allowed");

        let mut secret_mismatch = vec![ComponentVal::Bool(false)];
        component_store_put(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("drafts/secret.json".into()),
                component_bytes(b"blocked".to_vec()),
                ComponentVal::Bool(true),
            ],
            &mut secret_mismatch,
        )
        .await
        .unwrap();
        assert_component_err_contains(&secret_mismatch[0], "not declared secret");

        let mut secret_without_flag = vec![ComponentVal::Bool(false)];
        component_store_put(
            store.as_context_mut(),
            &[
                ComponentVal::String("credentials".into()),
                ComponentVal::String("api-key".into()),
                component_bytes(b"blocked".to_vec()),
                ComponentVal::Bool(false),
            ],
            &mut secret_without_flag,
        )
        .await
        .unwrap();
        assert_component_err_contains(&secret_without_flag[0], "requires secret writes");

        let mut put = vec![ComponentVal::Bool(false)];
        component_store_put(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("drafts/a.json".into()),
                component_bytes(b"one".to_vec()),
                ComponentVal::Bool(false),
            ],
            &mut put,
        )
        .await
        .unwrap();
        assert_component_ok_none(&put[0]);

        let mut invalid = vec![ComponentVal::Bool(false)];
        component_store_put(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("../escape".into()),
                component_bytes(b"nope".to_vec()),
                ComponentVal::Bool(false),
            ],
            &mut invalid,
        )
        .await
        .unwrap();
        assert_component_err_contains(&invalid[0], "escapes namespace");

        assert_eq!(
            std::fs::read(tmp.path().join(VALID_HASH).join("orders/drafts/a.json")).unwrap(),
            b"one"
        );

        let mut put_new_existing = vec![ComponentVal::Bool(false)];
        component_store_put_new(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("drafts/a.json".into()),
                component_bytes(b"two".to_vec()),
                ComponentVal::Bool(false),
            ],
            &mut put_new_existing,
        )
        .await
        .unwrap();
        assert_component_err_contains(&put_new_existing[0], "already exists");

        let mut put_new = vec![ComponentVal::Bool(false)];
        component_store_put_new(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("locks/a.json".into()),
                component_bytes(b"lock".to_vec()),
                ComponentVal::Bool(false),
            ],
            &mut put_new,
        )
        .await
        .unwrap();
        assert_component_ok_none(&put_new[0]);

        let mut delete_wrong_value = vec![ComponentVal::Bool(false)];
        component_store_delete_if_value(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("locks/a.json".into()),
                component_bytes(b"other".to_vec()),
            ],
            &mut delete_wrong_value,
        )
        .await
        .unwrap();
        assert_component_err_contains(&delete_wrong_value[0], "value changed");

        let mut delete_if_value = vec![ComponentVal::Bool(false)];
        component_store_delete_if_value(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("locks/a.json".into()),
                component_bytes(b"lock".to_vec()),
            ],
            &mut delete_if_value,
        )
        .await
        .unwrap();
        assert_component_ok_none(&delete_if_value[0]);

        let mut get = vec![ComponentVal::Bool(false)];
        component_store_get(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("drafts/a.json".into()),
            ],
            &mut get,
        )
        .await
        .unwrap();
        assert_component_ok_optional_bytes(&get[0], Some(b"one"));

        let mut list = vec![ComponentVal::Bool(false)];
        component_store_list(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("drafts".into()),
            ],
            &mut list,
        )
        .await
        .unwrap();
        assert_component_ok_string_list(&list[0], &["drafts/a.json"]);

        let mut delete = vec![ComponentVal::Bool(false)];
        component_store_delete(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("drafts/a.json".into()),
            ],
            &mut delete,
        )
        .await
        .unwrap();
        assert_component_ok_none(&delete[0]);

        let mut missing = vec![ComponentVal::Bool(false)];
        component_store_get(
            store.as_context_mut(),
            &[
                ComponentVal::String("orders".into()),
                ComponentVal::String("drafts/a.json".into()),
            ],
            &mut missing,
        )
        .await
        .unwrap();
        assert_component_ok_optional_bytes(&missing[0], None);
    }

    #[tokio::test]
    async fn component_store_get_reads_legacy_sdk_credential_keys_from_secrets() {
        let tmp = TempDir::new().unwrap();
        let private_store = PrivateStore::open(tmp.path()).unwrap();
        private_store
            .put(
                VALID_HASH,
                "secrets/creds/wallet/clob.json",
                b"credential",
                true,
            )
            .unwrap();

        let mut caps = BTreeSet::new();
        caps.insert(Capability::Store);
        let mut store = component_test_store(caps, Some(private_store), Arc::new(DenyHost));
        store.data_mut().store_namespaces = Some(StoreNamespacePolicy::from_namespaces(
            ["state".to_string()],
            ["secrets".to_string()],
        ));

        let mut result = vec![ComponentVal::Bool(false)];
        component_store_get(
            store.as_context_mut(),
            &[
                ComponentVal::String("state".into()),
                ComponentVal::String("creds/wallet/clob.json".into()),
            ],
            &mut result,
        )
        .await
        .unwrap();
        assert_component_ok_optional_bytes(&result[0], Some(b"credential"));
    }

    #[tokio::test]
    async fn component_chain_adapter_enforces_caps_and_uses_mediated_host() {
        let host = Arc::new(MockHost::default());
        let mut store = component_test_store(BTreeSet::new(), None, host.clone());
        let req = ComponentVal::Record(vec![
            ("chain".into(), ComponentVal::String("polygon".into())),
            ("method".into(), ComponentVal::String("eth_call".into())),
            (
                "params-json".into(),
                ComponentVal::String(r#"{"to":"0x1"}"#.into()),
            ),
        ]);

        let mut denied = vec![ComponentVal::Bool(false)];
        component_chain_call(
            store.as_context_mut(),
            std::slice::from_ref(&req),
            &mut denied,
        )
        .await
        .unwrap();
        assert_component_err_contains(&denied[0], "denied");
        assert!(host.chain_calls.lock().is_empty());

        let mut caps = BTreeSet::new();
        caps.insert(Capability::Chain);
        let mut store = component_test_store(caps, None, host.clone());
        let context = PetalRouteContext {
            petal_root: "reader".into(),
            package_hash: "a".repeat(64),
            route_id: "r000001".into(),
            op: "read".into(),
            path: "/balance.json".into(),
            params: vec![],
            actor: None,
        };
        store.data_mut().sign_context = Some(context.clone());
        let mut allowed = vec![ComponentVal::Bool(false)];
        component_chain_call(store.as_context_mut(), &[req], &mut allowed)
            .await
            .unwrap();
        assert_component_ok_chain_result(&allowed[0], r#"{"ok":true}"#);

        let calls = host.chain_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].chain, "polygon");
        assert_eq!(calls[0].method, "eth_call");
        assert_eq!(calls[0].params_json, r#"{"to":"0x1"}"#);
        assert_eq!(calls[0].context, Some(context));
    }

    #[tokio::test]
    async fn component_http_sign_and_vfs_adapters_use_mediated_host() {
        let host = Arc::new(MockHost::default());
        host.store
            .lock()
            .insert("wallets/alice.txt".into(), b"alice".to_vec());
        host.lists.lock().insert(
            "wallets".into(),
            vec![HostVfsEntry {
                name: "alice.txt".into(),
                kind: HostVfsEntryKind::File,
                mode: 0o644,
                size: Some(5),
                link_target: None,
            }],
        );

        let mut caps = BTreeSet::new();
        caps.insert(Capability::NetFetch);
        caps.insert(Capability::Sign);
        caps.insert(Capability::VfsRead);
        caps.insert(Capability::VfsWrite);
        let policy = NetPolicy::from_manifest_toml(
            br#"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/status"]
"#,
        )
        .unwrap();
        let mut store = component_test_store_with_policy(caps, None, host.clone(), policy);

        let mut http = vec![ComponentVal::Bool(false)];
        component_http_fetch(
            store.as_context_mut(),
            &[ComponentVal::Record(vec![
                ("method".into(), ComponentVal::String("GET".into())),
                (
                    "url".into(),
                    ComponentVal::String("https://api.example.com/status".into()),
                ),
                ("headers".into(), ComponentVal::List(Vec::new())),
                ("body".into(), component_bytes(Vec::new())),
            ])],
            &mut http,
        )
        .await
        .unwrap();
        assert_component_ok_http_body(&http[0], b"ok");
        assert_eq!(host.http_calls.lock().len(), 1);

        let mut sign = vec![ComponentVal::Bool(false)];
        component_sign_hash(
            store.as_context_mut(),
            &[
                ComponentVal::String("alice".into()),
                component_bytes(vec![3u8; 32]),
                ComponentVal::String("test.intent".into()),
            ],
            &mut sign,
        )
        .await
        .unwrap();
        assert_component_err_contains(&sign[0], "UNSUPPORTED_VERSION");
        assert!(host.sign_calls.lock().is_empty());

        let mut payload_sign = vec![ComponentVal::Bool(false)];
        component_sign_payload(
            store.as_context_mut(),
            &[component_payload_request("alice", 3, "test.intent")],
            &mut payload_sign,
        )
        .await
        .unwrap();
        assert_component_ok_signature(&payload_sign[0], &[7u8; 65]);
        assert_eq!(host.sign_calls.lock().len(), 1);

        store.data_mut().sign_intents = Some(BTreeSet::from(["test.allowed".to_string()]));
        let mut denied_sign = vec![ComponentVal::Bool(false)];
        component_sign_payload(
            store.as_context_mut(),
            &[component_payload_request("alice", 3, "test.denied")],
            &mut denied_sign,
        )
        .await
        .unwrap();
        assert_component_err_contains(&denied_sign[0], "not allowed");
        assert_eq!(host.sign_calls.lock().len(), 1);

        let mut read = vec![ComponentVal::Bool(false)];
        component_vfs_read(
            store.as_context_mut(),
            &[ComponentVal::String("wallets/alice.txt".into())],
            &mut read,
        )
        .await
        .unwrap();
        assert_component_ok_bytes(&read[0], b"alice");

        let mut list = vec![ComponentVal::Bool(false)];
        component_vfs_list(
            store.as_context_mut(),
            &[ComponentVal::String("wallets".into())],
            &mut list,
        )
        .await
        .unwrap();
        assert_component_ok_entry_names(&list[0], &["alice.txt"]);

        host.vfs_reads.lock().clear();
        let mut lookup = vec![ComponentVal::Bool(false)];
        component_vfs_lookup(
            store.as_context_mut(),
            &[ComponentVal::String("wallets/alice.txt".into())],
            &mut lookup,
        )
        .await
        .unwrap();
        assert_component_ok_entry(&lookup[0], "alice.txt", "file", 0o644);
        assert!(
            host.vfs_reads.lock().is_empty(),
            "component vfs.lookup must not perform side-effecting reads"
        );

        let mut write = vec![ComponentVal::Bool(false)];
        component_vfs_write(
            store.as_context_mut(),
            &[
                ComponentVal::String("wallets/bob.txt".into()),
                component_bytes(b"bob".to_vec()),
            ],
            &mut write,
        )
        .await
        .unwrap();
        assert_component_ok_none(&write[0]);
        assert_eq!(
            host.store.lock().get("wallets/bob.txt").cloned().unwrap(),
            b"bob"
        );
    }

    #[tokio::test]
    async fn component_petal_key_request_injects_provenance_and_rejects_guest_override() {
        let host = Arc::new(MockHost::default());
        let mut store =
            component_test_store(BTreeSet::from([Capability::KeyDerive]), None, host.clone());
        let context = PetalRouteContext {
            petal_root: "exchange".into(),
            package_hash: VALID_HASH.into(),
            route_id: "r000007".into(),
            op: "write".into(),
            path: "orders/new".into(),
            params: Vec::new(),
            actor: None,
        };
        store.data_mut().sign_context = Some(context.clone());

        let attempted_override = serde_json::to_vec(&serde_json::json!({
            "request_id": "agent-a",
            "wallet_id": "primary",
            "purpose": "exchange-agent",
            "allowed_crypto_suites": ["secp256k1-keccak256-recoverable"],
            "maximum_lifetime_ms": 60_000,
            "package_hash": "ff".repeat(32),
            "context": {"package_hash": "ff".repeat(32), "route_id": "r999999"}
        }))
        .unwrap();
        let mut denied = vec![ComponentVal::Bool(false)];
        component_petal_key_request(
            store.as_context_mut(),
            &[component_bytes(attempted_override)],
            &mut denied,
        )
        .await
        .unwrap();
        assert_component_err_contains(&denied[0], "unknown field");
        assert!(host.petal_key_calls.lock().is_empty());

        let request = serde_json::to_vec(&serde_json::json!({
            "wallet_id": "primary",
            "key_slot": "desk-a",
            "allowed_routes": ["r000007"],
            "allowed_operation_classes": ["order.place"],
            "allowed_crypto_suites": ["secp256k1-keccak256-recoverable"],
            "maximum_lifetime_ms": 60_000
        }))
        .unwrap();
        let mut result = vec![ComponentVal::Bool(false)];
        component_petal_key_request(
            store.as_context_mut(),
            &[component_bytes(request)],
            &mut result,
        )
        .await
        .unwrap();
        let bytes = component_result_bytes(&result[0]);
        let outcome: crate::abi::PetalKeyOutcome = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(
            outcome,
            crate::abi::PetalKeyOutcome::Pending { .. }
        ));
        let calls = host.petal_key_calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].context, Some(context));
    }

    #[tokio::test]
    async fn executable_component_fixture_reconciles_ready_keyref_then_scoped_signs() {
        const FIXTURE: &str = r#"
            (component
              (type $key-interface
                (instance
                  (type $bytes (list u8))
                  (type $outcome (result $bytes (error string)))
                  (type $request-func
                    (func (param "request" $bytes) (result $outcome)))
                  (export "request" (func (type $request-func)))))
              (import "bloom:key/derive@0.1.0"
                (instance $key (type $key-interface)))

              (type $sign-interface
                (instance
                  (type $bytes (list u8))
                  (type $approval (record
                    (field "action-id" string)
                    (field "expires-ms" u64)))
                  (export "approval-pending" (type $approval-export (eq $approval)))
                  (type $sign-result (variant
                    (case "signature" $bytes)
                    (case "approval-pending" $approval-export)))
                  (export "sign-result" (type $sign-result-export (eq $sign-result)))
                  (type $maybe-bytes (option $bytes))
                  (type $maybe-string (option string))
                  (type $selector (enum "exact" "reusable"))
                  (export "selector" (type $selector-export (eq $selector)))
                  (type $payload (record
                    (field "wallet" string)
                    (field "preimage" $bytes)
                    (field "claimed-hash" $bytes)
                    (field "signature-algorithm" string)
                    (field "operation-class" string)
                    (field "petal-use-claim-jcs" $bytes)
                    (field "claim-assurance-evidence" $maybe-bytes)
                    (field "approval-hint" $maybe-string)
                    (field "action" $maybe-bytes)
                    (field "advisory" $maybe-bytes)
                    (field "selector" $selector-export)
                    (field "key-ref-jcs" $maybe-bytes)))
                  (export "payload-sign-request" (type $payload-export (eq $payload)))
                  (type $outcome (result $sign-result-export (error string)))
                  (type $sign-func
                    (func (param "request" $payload-export) (result $outcome)))
                  (export "sign-payload" (func (type $sign-func)))))
              (import "bloom:sign/signing@0.2.0"
                (instance $sign (type $sign-interface)))

              ;; Canonical ABI forwarding module: its exported functions execute
              ;; the two imported Bloom authority functions through a fixup table.
              (core module $main
                (type $derive-lowered (func (param i32 i32 i32)))
                (type $sign-lowered (func (param i32 i32)))
                (type $realloc-type (func (param i32 i32 i32 i32) (result i32)))
                (type $derive-export (func (param i32 i32) (result i32)))
                (type $sign-export (func (param i32) (result i32)))
                (import "key" "request" (func $derive (type $derive-lowered)))
                (import "sign" "sign-payload" (func $sign-payload (type $sign-lowered)))
                (memory (export "memory") 1)
                (global $heap (mut i32) (i32.const 4096))
                (func $realloc (export "realloc") (type $realloc-type)
                  (param i32 i32 i32 i32) (result i32)
                  global.get $heap
                  local.get 2
                  i32.add
                  i32.const 1
                  i32.sub
                  local.get 2
                  i32.const 1
                  i32.sub
                  i32.const -1
                  i32.xor
                  i32.and
                  local.tee 0
                  local.get 0
                  local.get 3
                  i32.add
                  global.set $heap)
                (func (export "derive") (type $derive-export) (param i32 i32) (result i32)
                  local.get 0 local.get 1 i32.const 1024 call $derive
                  i32.const 1024)
                (func (export "sign-payload") (type $sign-export) (param i32) (result i32)
                  local.get 0 i32.const 1088 call $sign-payload
                  i32.const 1088))
              (core module $shim
                (type $derive-lowered (func (param i32 i32 i32)))
                (type $sign-lowered (func (param i32 i32)))
                (table (export "$imports") 2 2 funcref)
                (func (export "derive") (type $derive-lowered) (param i32 i32 i32)
                  local.get 0 local.get 1 local.get 2 i32.const 0
                  call_indirect (type $derive-lowered))
                (func (export "sign-payload") (type $sign-lowered) (param i32 i32)
                  local.get 0 local.get 1 i32.const 1
                  call_indirect (type $sign-lowered)))
              (core module $fixup
                (type $derive-lowered (func (param i32 i32 i32)))
                (type $sign-lowered (func (param i32 i32)))
                (import "" "derive" (func $derive (type $derive-lowered)))
                (import "" "sign-payload" (func $sign-payload (type $sign-lowered)))
                (import "" "$imports" (table $imports 2 2 funcref))
                (elem (i32.const 0) func $derive $sign-payload))
              (core instance $shim-instance (instantiate $shim))
              (alias core export $shim-instance "derive" (core func $derive-shim))
              (alias core export $shim-instance "sign-payload" (core func $sign-shim))
              (core instance $key-lowered (export "request" (func $derive-shim)))
              (core instance $sign-lowered (export "sign-payload" (func $sign-shim)))
              (core instance $main-instance (instantiate $main
                (with "key" (instance $key-lowered))
                (with "sign" (instance $sign-lowered))))
              (alias core export $main-instance "memory" (core memory $memory))
              (alias core export $main-instance "realloc" (core func $realloc))
              (alias core export $shim-instance "$imports" (core table $imports))
              (alias export $key "request" (func $derive-host))
              (core func $derive-host-lowered
                (canon lower (func $derive-host) (memory $memory) (realloc $realloc)))
              (alias export $sign "sign-payload" (func $sign-host))
              (core func $sign-host-lowered
                (canon lower (func $sign-host) (memory $memory) (realloc $realloc)))
              (core instance $fixup-args
                (export "$imports" (table $imports))
                (export "derive" (func $derive-host-lowered))
                (export "sign-payload" (func $sign-host-lowered)))
              (core instance $fixed (instantiate $fixup
                (with "" (instance $fixup-args))))
              (alias core export $main-instance "derive" (core func $derive-core))
              (alias core export $main-instance "sign-payload" (core func $sign-core))
              (type $derive-bytes (list u8))
              (type $derive-result (result $derive-bytes (error string)))
              (type $derive-type
                (func (param "request" $derive-bytes) (result $derive-result)))
              (func $derive (type $derive-type)
                (canon lift (core func $derive-core) (memory $memory) (realloc $realloc)))
              (export "derive" (func $derive))
              (alias export $sign "payload-sign-request" (type $sign-payload))
              (import "fixture-payload-sign-request"
                (type $sign-payload-import (eq $sign-payload)))
              (alias export $sign "sign-result" (type $sign-result))
              (import "fixture-sign-result"
                (type $sign-result-import (eq $sign-result)))
              (type $sign-outcome-import (result $sign-result-import (error string)))
              (type $sign-type-import
                (func (param "request" $sign-payload-import) (result $sign-outcome-import)))
              (func $sign-forward (type $sign-type-import)
                (canon lift (core func $sign-core) (memory $memory) (realloc $realloc)))
              (export "sign-payload" (func $sign-forward)))
        "#;
        let vm = PetalVm::new().unwrap();
        let component = Component::from_binary(&vm.engine, &wat(FIXTURE)).unwrap();
        let host = Arc::new(MockHost::default());
        let key_ref = bloom_broker_api::KeyRef {
            backend: bloom_broker_api::Token::new("local").unwrap(),
            backend_instance: bloom_broker_api::Token::new("default").unwrap(),
            locator: "wallet/primary/petals/7".into(),
            key_spec: bloom_broker_api::KeySpec::Secp256k1,
            public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([7; 32]),
            derivation: Some(bloom_broker_api::DerivationRef::Bip32Secp256k1 {
                root_key_id: bloom_broker_api::Token::new("primary-root").unwrap(),
                path: "m/44'/60'/0'/18734/7".into(),
            }),
        };
        let canonical = serde_jcs::to_vec(&key_ref).unwrap();
        host.petal_key_outcomes.lock().extend([
            crate::abi::PetalKeyOutcome::Pending {
                operation_id: "11".repeat(32),
                scope_digest: "22".repeat(32),
            },
            crate::abi::PetalKeyOutcome::Ready {
                operation_id: "11".repeat(32),
                scope_digest: "22".repeat(32),
                key_ref_jcs: canonical.clone(),
                addresses: vec!["0x1234".into()],
            },
        ]);
        let mut store = component_test_store_for_engine(
            &vm.engine,
            BTreeSet::from([Capability::KeyDerive, Capability::Sign]),
            None,
            host.clone(),
        );
        store.set_fuel(DEFAULT_FUEL).unwrap();
        let mut linker = ComponentLinker::<StoreData>::new(&vm.engine);
        linker.define_unknown_imports_as_traps(&component).unwrap();
        link_component_host_imports(&mut linker).unwrap();
        let instance = linker
            .instantiate_async(&mut store, &component)
            .await
            .unwrap();

        let derive = instance.get_func(&mut store, "derive").unwrap();
        let request = serde_json::to_vec(&serde_json::json!({
            "wallet_id": "primary",
            "key_slot": "fixture",
            "allowed_routes": ["r000001"],
            "allowed_operation_classes": ["order.place"],
            "allowed_crypto_suites": ["secp256k1-keccak256-recoverable"],
            "maximum_lifetime_ms": 60_000
        }))
        .unwrap();
        let mut result = vec![ComponentVal::Bool(false)];
        derive
            .call_async(&mut store, &[component_bytes(request.clone())], &mut result)
            .await
            .unwrap();
        derive.post_return_async(&mut store).await.unwrap();
        assert!(matches!(
            serde_json::from_slice::<crate::abi::PetalKeyOutcome>(&component_result_bytes(
                &result[0]
            ))
            .unwrap(),
            crate::abi::PetalKeyOutcome::Pending { .. }
        ));

        derive
            .call_async(&mut store, &[component_bytes(request)], &mut result)
            .await
            .unwrap();
        derive.post_return_async(&mut store).await.unwrap();
        let ready = serde_json::from_slice::<crate::abi::PetalKeyOutcome>(&component_result_bytes(
            &result[0],
        ))
        .unwrap();
        let crate::abi::PetalKeyOutcome::Ready { key_ref_jcs, .. } = ready else {
            panic!("expected reconciled Ready Petal key");
        };
        assert_eq!(key_ref_jcs, canonical);

        let sign = instance.get_func(&mut store, "sign-payload").unwrap();
        let mut signed = vec![ComponentVal::Bool(false)];
        let mut sign_request =
            component_scoped_payload_request("primary", 7, "order.place", Some(key_ref_jcs));
        let ComponentVal::Record(fields) = &mut sign_request else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(name, _)| name == "petal-use-claim-jcs")
            .unwrap()
            .1 = component_bytes(canonical_test_claim());
        sign.call_async(&mut store, &[sign_request], &mut signed)
            .await
            .unwrap();
        sign.post_return_async(&mut store).await.unwrap();
        assert_component_ok_signature(&signed[0], &[7; 65]);
        assert_eq!(host.sign_calls.lock()[0].key_ref.as_ref(), Some(&key_ref));
        assert_eq!(
            host.sign_calls.lock()[0].selector,
            bloom_broker_api::PetalSignSelector::Reusable
        );
        assert_eq!(*host.authority_calls.lock(), ["derive", "derive", "sign"]);
    }

    #[tokio::test]
    async fn scoped_payload_signing_validates_canonical_keyref_and_preserves_v02_root_behavior() {
        let host = Arc::new(MockHost::default());
        let mut store =
            component_test_store(BTreeSet::from([Capability::Sign]), None, host.clone());
        let key_ref = bloom_broker_api::KeyRef {
            backend: bloom_broker_api::Token::new("local").unwrap(),
            backend_instance: bloom_broker_api::Token::new("default").unwrap(),
            locator: "wallet/primary/petals/7".into(),
            key_spec: bloom_broker_api::KeySpec::Secp256k1,
            public_key_fingerprint: bloom_broker_api::Digest32::from_bytes([7; 32]),
            derivation: Some(bloom_broker_api::DerivationRef::Bip32Secp256k1 {
                root_key_id: bloom_broker_api::Token::new("primary-root").unwrap(),
                path: "m/44'/60'/0'/18734/7".into(),
            }),
        };

        let mut legacy = vec![ComponentVal::Bool(false)];
        component_sign_payload(
            store.as_context_mut(),
            &[component_payload_request("primary", 7, "order.place")],
            &mut legacy,
        )
        .await
        .unwrap();
        assert_component_ok_signature(&legacy[0], &[7; 65]);
        assert!(host.sign_calls.lock()[0].key_ref.is_none());
        assert_eq!(
            host.sign_calls.lock()[0].selector,
            bloom_broker_api::PetalSignSelector::Reusable,
            "v0.2 retains reusable Petal-selector behavior"
        );

        let canonical = serde_jcs::to_vec(&key_ref).unwrap();
        let mut scoped = vec![ComponentVal::Bool(false)];
        component_sign_payload_scoped(
            store.as_context_mut(),
            &[component_scoped_payload_request(
                "primary",
                7,
                "order.place",
                Some(canonical.clone()),
            )],
            &mut scoped,
        )
        .await
        .unwrap();
        assert_component_ok_signature(&scoped[0], &[7; 65]);
        assert_eq!(host.sign_calls.lock()[1].key_ref.as_ref(), Some(&key_ref));
        assert_eq!(
            host.sign_calls.lock()[1].selector,
            bloom_broker_api::PetalSignSelector::Reusable
        );

        let before = host.sign_calls.lock().len();
        let mut unknown = vec![ComponentVal::Bool(false)];
        component_sign_payload_scoped(
            store.as_context_mut(),
            &[component_scoped_payload_request_with_selector(
                "primary",
                7,
                "order.place",
                "future-selector",
                Some(canonical.clone()),
            )],
            &mut unknown,
        )
        .await
        .unwrap();
        assert_component_err_contains(&unknown[0], "unknown");
        assert_eq!(host.sign_calls.lock().len(), before);

        for invalid in [b"not-json".to_vec(), [b" ".as_slice(), &canonical].concat()] {
            let before = host.sign_calls.lock().len();
            let mut denied = vec![ComponentVal::Bool(false)];
            component_sign_payload_scoped(
                store.as_context_mut(),
                &[component_scoped_payload_request(
                    "primary",
                    7,
                    "order.place",
                    Some(invalid),
                )],
                &mut denied,
            )
            .await
            .unwrap();
            assert_component_err_contains(&denied[0], "Petal KeyRef");
            assert_eq!(host.sign_calls.lock().len(), before);
        }
    }

    #[tokio::test]
    async fn legacy_component_pending_fails_closed_without_ceremony_url() {
        let host = Arc::new(MockHost::default());
        *host.sign_outcome.lock() = Some(SignOutcome::ApprovalRequired(
            crate::abi::ApprovalRequired {
                action_id: "action-123".into(),
                ceremony_url: "bloom://ceremony/action-123".into(),
                expires_ms: 123_456,
            },
        ));
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Sign);
        let mut store = component_test_store(caps, None, host.clone());
        let mut result = vec![ComponentVal::Bool(false)];

        component_sign_payload(
            store.as_context_mut(),
            &[component_payload_request("alice", 3, "orders.place")],
            &mut result,
        )
        .await
        .unwrap();

        assert_component_err_contains(&result[0], "APPROVAL_PENDING");
        assert!(!format!("{:?}", result[0]).contains("bloom://ceremony"));
        assert_eq!(host.sign_calls.lock().len(), 1);
    }

    #[tokio::test]
    async fn component_v2_pending_projection_never_exposes_ceremony_url() {
        let host = Arc::new(MockHost::default());
        *host.sign_outcome.lock() =
            Some(SignOutcome::ApprovalPending(crate::abi::ApprovalPending {
                action_id: "action-v2".into(),
                expires_ms: 444,
            }));
        let mut store = component_test_store(BTreeSet::from([Capability::Sign]), None, host);
        let mut result = vec![ComponentVal::Bool(false)];
        component_sign_payload_current(
            store.as_context_mut(),
            &[component_current_payload_request()],
            &mut result,
        )
        .await
        .unwrap();

        let ComponentVal::Result(Ok(Some(value))) = &result[0] else {
            panic!("expected successful pending result: {:?}", result[0]);
        };
        let ComponentVal::Variant(name, Some(record)) = value.as_ref() else {
            panic!("expected approval-pending variant: {value:?}");
        };
        assert_eq!(name, "approval-pending");
        let ComponentVal::Record(fields) = record.as_ref() else {
            panic!("expected approval-pending record: {record:?}");
        };
        assert_eq!(
            fields,
            &vec![
                ("action-id".into(), ComponentVal::String("action-v2".into())),
                ("expires-ms".into(), ComponentVal::U64(444)),
            ]
        );
    }

    #[tokio::test]
    async fn component_v2_batch_is_bounded_validated_and_preserves_order_and_context() {
        let host = Arc::new(MockHost::default());
        let mut store =
            component_test_store(BTreeSet::from([Capability::Sign]), None, host.clone());
        let context = PetalRouteContext {
            petal_root: "venue".into(),
            package_hash: VALID_HASH.into(),
            route_id: "r000001".into(),
            op: "write".into(),
            path: "orders/new".into(),
            params: Vec::new(),
            actor: None,
        };
        store.data_mut().sign_context = Some(context.clone());

        let mut result = vec![ComponentVal::Bool(false)];
        component_sign_payload_batch(
            store.as_context_mut(),
            &[component_payload_batch_request(&[1, 2, 3])],
            &mut result,
        )
        .await
        .unwrap();
        {
            let calls = host.payload_batch_calls.lock();
            assert_eq!(calls.len(), 1);
            assert_eq!(
                calls[0]
                    .payloads
                    .iter()
                    .map(|item| item.preimage[0])
                    .collect::<Vec<_>>(),
                vec![1, 2, 3]
            );
            assert_eq!(calls[0].context, Some(context));
        }

        let mut malformed_hash = component_payload_batch_request(&[9]);
        let ComponentVal::Record(fields) = &mut malformed_hash else {
            unreachable!();
        };
        let ComponentVal::List(payloads) = fields
            .iter_mut()
            .find(|(name, _)| name == "payloads")
            .unwrap()
            .1
            .clone()
        else {
            unreachable!();
        };
        let ComponentVal::Record(mut item) = payloads[0].clone() else {
            unreachable!();
        };
        item.iter_mut()
            .find(|(name, _)| name == "claimed-hash")
            .unwrap()
            .1 = component_bytes(vec![0; 31]);
        fields
            .iter_mut()
            .find(|(name, _)| name == "payloads")
            .unwrap()
            .1 = ComponentVal::List(vec![ComponentVal::Record(item)]);
        let mut denied = vec![ComponentVal::Bool(false)];
        component_sign_payload_batch(store.as_context_mut(), &[malformed_hash], &mut denied)
            .await
            .unwrap();
        assert_component_err_contains(&denied[0], "32-byte");
        assert_eq!(host.payload_batch_calls.lock().len(), 1);

        let mut noncanonical_claim = component_payload_batch_request(&[9]);
        let ComponentVal::Record(fields) = &mut noncanonical_claim else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(name, _)| name == "petal-use-claim-jcs")
            .unwrap()
            .1 = component_bytes([b" ".as_slice(), &canonical_test_claim()].concat());
        let mut denied = vec![ComponentVal::Bool(false)];
        component_sign_payload_batch(store.as_context_mut(), &[noncanonical_claim], &mut denied)
            .await
            .unwrap();
        assert_component_err_contains(&denied[0], "canonical JSON");
        assert_eq!(host.payload_batch_calls.lock().len(), 1);

        let mut malformed_key_ref = component_payload_batch_request(&[9]);
        let ComponentVal::Record(fields) = &mut malformed_key_ref else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(name, _)| name == "key-ref-jcs")
            .unwrap()
            .1 = ComponentVal::Option(Some(Box::new(component_bytes(b"not-json".to_vec()))));
        let mut denied = vec![ComponentVal::Bool(false)];
        component_sign_payload_batch(store.as_context_mut(), &[malformed_key_ref], &mut denied)
            .await
            .unwrap();
        assert_component_err_contains(&denied[0], "Petal KeyRef");
        assert_eq!(host.payload_batch_calls.lock().len(), 1);

        let mut empty_batch = component_payload_batch_request(&[9]);
        let ComponentVal::Record(fields) = &mut empty_batch else {
            unreachable!();
        };
        fields
            .iter_mut()
            .find(|(name, _)| name == "payloads")
            .unwrap()
            .1 = ComponentVal::List(Vec::new());
        let mut denied = vec![ComponentVal::Bool(false)];
        component_sign_payload_batch(store.as_context_mut(), &[empty_batch], &mut denied)
            .await
            .unwrap();
        assert_component_err_contains(&denied[0], "1..=");
        assert_eq!(host.payload_batch_calls.lock().len(), 1);

        let mut oversized_child = component_payload_batch_request(&[9]);
        let ComponentVal::Record(fields) = &mut oversized_child else {
            unreachable!();
        };
        let ComponentVal::List(payloads) = &mut fields
            .iter_mut()
            .find(|(name, _)| name == "payloads")
            .unwrap()
            .1
        else {
            unreachable!();
        };
        let ComponentVal::Record(item) = &mut payloads[0] else {
            unreachable!();
        };
        item.iter_mut()
            .find(|(name, _)| name == "preimage")
            .unwrap()
            .1 = component_bytes(vec![0; MAX_SIGN_BATCH_CHILD_BYTES + 1]);
        let mut denied = vec![ComponentVal::Bool(false)];
        component_sign_payload_batch(store.as_context_mut(), &[oversized_child], &mut denied)
            .await
            .unwrap();
        assert_component_err_contains(&denied[0], "exceeds");
        assert_eq!(host.payload_batch_calls.lock().len(), 1);

        let mut no_cap_store = component_test_store(BTreeSet::new(), None, host.clone());
        let mut denied = vec![ComponentVal::Bool(false)];
        component_sign_payload_batch(
            no_cap_store.as_context_mut(),
            &[component_payload_batch_request(&[9])],
            &mut denied,
        )
        .await
        .unwrap();
        assert_component_err_contains(&denied[0], "denied");
        assert_eq!(host.payload_batch_calls.lock().len(), 1);
    }

    #[tokio::test]
    async fn component_sign_preserves_signature_and_policy_checks() {
        let host = Arc::new(MockHost::default());
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Sign);
        let mut store = component_test_store(caps, None, host.clone());
        let params = [component_payload_request("alice", 3, "orders.place")];
        let mut result = vec![ComponentVal::Bool(false)];
        component_sign_payload(store.as_context_mut(), &params, &mut result)
            .await
            .unwrap();
        let ComponentVal::Result(Ok(Some(value))) = &result[0] else {
            panic!(
                "expected successful structured sign result: {:?}",
                result[0]
            );
        };
        let ComponentVal::Variant(name, Some(signature)) = value.as_ref() else {
            panic!("expected signature variant: {value:?}");
        };
        assert_eq!(name, "signature");
        assert_eq!(
            component_byte_list(signature, "signature").unwrap(),
            vec![7u8; 65]
        );

        store.data_mut().sign_intents = Some(BTreeSet::from(["orders.cancel".to_string()]));
        let mut denied = vec![ComponentVal::Bool(false)];
        component_sign_payload(store.as_context_mut(), &params, &mut denied)
            .await
            .unwrap();
        assert_component_err_contains(&denied[0], "not allowed");
        assert_eq!(host.sign_calls.lock().len(), 1);
    }

    #[tokio::test]
    async fn component_payload_sign_accepts_normalized_ed25519_signature() {
        let host = Arc::new(MockHost::default());
        *host.sign_outcome.lock() = Some(SignOutcome::Signature(vec![9; 64]));
        let mut caps = BTreeSet::new();
        caps.insert(Capability::Sign);
        let mut store = component_test_store(caps, None, host);
        let mut request = component_payload_request("alice", 3, "message.sign");
        let ComponentVal::Record(fields) = &mut request else {
            unreachable!();
        };
        let algorithm = fields
            .iter_mut()
            .find(|(name, _)| name == "signature-algorithm")
            .unwrap();
        algorithm.1 = ComponentVal::String("ed25519-message".into());
        let mut result = vec![ComponentVal::Bool(false)];
        component_sign_payload(store.as_context_mut(), &[request], &mut result)
            .await
            .unwrap();
        assert_component_ok_signature(&result[0], &[9; 64]);
    }

    #[tokio::test]
    async fn ac35_legacy_v0_1_component_routes_are_always_unsupported() {
        let host = Arc::new(MockHost::default());
        let request = |wallet: &str, byte: u8| {
            ComponentVal::Record(vec![
                ("wallet".into(), ComponentVal::String(wallet.into())),
                ("hash32".into(), component_bytes(vec![byte; 32])),
                ("intent".into(), ComponentVal::String("orders.place".into())),
            ])
        };
        for has_sign_capability in [false, true] {
            let mut caps = BTreeSet::new();
            if has_sign_capability {
                caps.insert(Capability::Sign);
            }
            let mut store = component_test_store(caps, None, host.clone());
            for params in [
                vec![],
                vec![ComponentVal::String("malformed".into())],
                vec![
                    ComponentVal::String("alice".into()),
                    component_bytes(vec![1; 32]),
                    ComponentVal::String("orders.place".into()),
                ],
            ] {
                let mut result = vec![ComponentVal::Bool(false)];
                component_sign_hash(store.as_context_mut(), &params, &mut result)
                    .await
                    .unwrap();
                assert_component_err_contains(&result[0], "UNSUPPORTED_VERSION");
            }

            for params in [
                vec![],
                vec![ComponentVal::String("malformed".into())],
                vec![ComponentVal::List(vec![
                    request("alice", 1),
                    request("bob", 2),
                ])],
            ] {
                let mut result = vec![ComponentVal::Bool(false)];
                component_sign_hashes(store.as_context_mut(), &params, &mut result)
                    .await
                    .unwrap();
                assert_component_err_contains(&result[0], "UNSUPPORTED_VERSION");
            }
        }
        assert!(host.sign_calls.lock().is_empty());
    }

    #[tokio::test]
    async fn component_evm_outbox_is_capability_gated_and_preserves_trusted_context() {
        let host = Arc::new(MockHost::default());
        let transaction = ComponentVal::Record(vec![
            ("wallet".into(), ComponentVal::String("alice".into())),
            ("chain".into(), ComponentVal::String("polygon".into())),
            (
                "to".into(),
                ComponentVal::String("0x0000000000000000000000000000000000000001".into()),
            ),
            ("value-wei".into(), ComponentVal::String("1".into())),
            ("data-hex".into(), ComponentVal::String("0x".into())),
            ("nonce".into(), ComponentVal::Option(None)),
            ("max-fee-per-gas".into(), ComponentVal::Option(None)),
            (
                "max-priority-fee-per-gas".into(),
                ComponentVal::Option(None),
            ),
        ]);
        let mut denied_store = component_test_store(BTreeSet::new(), None, host.clone());
        let mut denied = vec![ComponentVal::Bool(false)];
        component_evm_tx_stage(
            denied_store.as_context_mut(),
            std::slice::from_ref(&transaction),
            &mut denied,
        )
        .await
        .unwrap();
        assert_component_err_contains(&denied[0], "tx.outbox");
        assert!(host.tx_stage_calls.lock().is_empty());

        let context = PetalRouteContext {
            petal_root: "polymarket".into(),
            package_hash: "a".repeat(64),
            route_id: "r000001".into(),
            op: "write".into(),
            path: "/fund/alice/one/confirm".into(),
            params: vec![("id".into(), "one".into())],
            actor: Some("agent-1".into()),
        };
        *host.tx_outcome.lock() = Some(EvmOutboxOutcome {
            outbox_id: "outbox-1".into(),
            plan_md: "# transaction\n".into(),
            approval_required: Some(crate::abi::ApprovalRequired {
                action_id: "action-1".into(),
                ceremony_url: "bloom://ceremony/action-1".into(),
                expires_ms: 500,
            }),
        });
        let mut caps = BTreeSet::new();
        caps.insert(Capability::TxOutbox);
        let mut store = component_test_store(caps, None, host.clone());
        store.data_mut().sign_context = Some(context.clone());
        let mut staged = vec![ComponentVal::Bool(false)];
        component_evm_tx_stage(store.as_context_mut(), &[transaction], &mut staged)
            .await
            .unwrap();
        let ComponentVal::Result(Ok(Some(value))) = &staged[0] else {
            panic!("expected staged transaction: {:?}", staged[0]);
        };
        let ComponentVal::Record(fields) = value.as_ref() else {
            panic!("expected staged record: {value:?}");
        };
        assert_eq!(
            component_string(component_field(fields, "outbox-id").unwrap(), "outbox-id").unwrap(),
            "outbox-1"
        );
        let ComponentVal::Option(Some(approval)) = component_field(fields, "approval").unwrap()
        else {
            panic!("expected structured approval: {fields:?}");
        };
        let ComponentVal::Record(approval_fields) = approval.as_ref() else {
            panic!("expected approval record: {approval:?}");
        };
        assert_eq!(
            component_string(
                component_field(approval_fields, "action-id").unwrap(),
                "action-id"
            )
            .unwrap(),
            "action-1"
        );
        assert!(
            !approval_fields
                .iter()
                .any(|(field, _)| field == "ceremony-url"),
            "owner-only ceremony URLs must not reach Petal component code"
        );
        assert_eq!(
            component_field(approval_fields, "expires-ms").unwrap(),
            &ComponentVal::U64(500)
        );
        {
            let calls = host.tx_stage_calls.lock();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].context, Some(context.clone()));
            assert_eq!(calls[0].value_wei, "1");
        }

        let mut inspected = vec![ComponentVal::Bool(false)];
        component_evm_tx_inspect(
            store.as_context_mut(),
            &[
                ComponentVal::String("alice".into()),
                ComponentVal::String("polygon".into()),
                ComponentVal::String("outbox-1".into()),
            ],
            &mut inspected,
        )
        .await
        .unwrap();
        let ComponentVal::Result(Ok(Some(inspection))) = &inspected[0] else {
            panic!("expected inspection: {:?}", inspected[0]);
        };
        let ComponentVal::Record(inspection) = inspection.as_ref() else {
            panic!("expected inspection record");
        };
        assert_eq!(
            component_string(component_field(inspection, "state").unwrap(), "state").unwrap(),
            "sent"
        );
        assert_eq!(host.tx_inspect_calls.lock()[0].3, Some(context));
    }

    #[tokio::test]
    async fn component_dispatch_links_http_import_and_enforces_caps() {
        let wasm = wat::parse_str(include_str!(
            "../tests/fixtures/route_component_http_calls_fetch.wat"
        ))
        .unwrap();
        let policy = NetPolicy::from_manifest_toml(
            br#"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/status"]
"#,
        )
        .unwrap();
        let request = DispatchRequest {
            op: DispatchOp::Read,
            path: "message.txt".into(),
            body: Vec::new(),
            ctx: Vec::new(),
        };

        let vm = PetalVm::new().unwrap();
        let host = Arc::new(MockHost::default());
        let mut caps = BTreeSet::new();
        caps.insert(Capability::NetFetch);
        let err = vm
            .dispatch_component_route(
                &wasm,
                request.clone(),
                caps,
                host.clone(),
                VALID_HASH,
                "petals/echo",
                Vec::new(),
                RunOptions {
                    net_policy: Some(policy.clone()),
                    ..RunOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("component route read"),
            "unexpected component error: {err}"
        );
        {
            let calls = host.http_calls.lock();
            assert_eq!(calls.len(), 1, "component error before host call: {err}");
            assert_eq!(calls[0].method, "GET");
            assert_eq!(calls[0].url, "https://api.example.com/status");
        }

        let denied_host = Arc::new(MockHost::default());
        let err = vm
            .dispatch_component_route(
                &wasm,
                request,
                BTreeSet::new(),
                denied_host.clone(),
                VALID_HASH,
                "petals/echo",
                Vec::new(),
                RunOptions {
                    net_policy: Some(policy),
                    ..RunOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("component route read"));
        assert!(denied_host.http_calls.lock().is_empty());
    }

    fn component_test_store(
        caps: BTreeSet<Capability>,
        private_store: Option<PrivateStore>,
        host: Arc<dyn PetalHost>,
    ) -> Store<StoreData> {
        component_test_store_with_policy(caps, private_store, host, NetPolicy::deny_all())
    }

    fn component_test_store_with_policy(
        caps: BTreeSet<Capability>,
        private_store: Option<PrivateStore>,
        host: Arc<dyn PetalHost>,
        net_policy: NetPolicy,
    ) -> Store<StoreData> {
        let vm = PetalVm::new().unwrap();
        component_test_store_for_engine_with_policy(
            &vm.engine,
            caps,
            private_store,
            host,
            net_policy,
        )
    }

    fn component_test_store_for_engine(
        engine: &Engine,
        caps: BTreeSet<Capability>,
        private_store: Option<PrivateStore>,
        host: Arc<dyn PetalHost>,
    ) -> Store<StoreData> {
        component_test_store_for_engine_with_policy(
            engine,
            caps,
            private_store,
            host,
            NetPolicy::deny_all(),
        )
    }

    fn component_test_store_for_engine_with_policy(
        engine: &Engine,
        caps: BTreeSet<Capability>,
        private_store: Option<PrivateStore>,
        host: Arc<dyn PetalHost>,
        net_policy: NetPolicy,
    ) -> Store<StoreData> {
        Store::new(
            engine,
            StoreData {
                wasi: WasiCtxBuilder::new().build_p1(),
                host,
                caps,
                petal_hash: VALID_HASH.into(),
                net_policy,
                sign_context: None,
                sign_intents: None,
                store_namespaces: None,
                http_response_cap: DEFAULT_HTTP_RESPONSE_CAP,
                deterministic_env: false,
                runtime_settings: BTreeMap::new(),
                limiter: MemLimiter::new(DEFAULT_MEMORY_PAGES),
                private_store,
            },
        )
    }

    fn assert_component_ok_none(value: &ComponentVal) {
        assert!(matches!(value, ComponentVal::Result(Ok(None))));
    }

    fn assert_component_err_contains(value: &ComponentVal, needle: &str) {
        let ComponentVal::Result(Err(Some(payload))) = value else {
            panic!("expected component err result, got {value:?}");
        };
        let ComponentVal::String(message) = payload.as_ref() else {
            panic!("expected string error payload, got {payload:?}");
        };
        assert!(
            message.contains(needle),
            "expected {message:?} to contain {needle:?}"
        );
    }

    fn assert_component_ok_optional_bytes(value: &ComponentVal, expected: Option<&[u8]>) {
        let ComponentVal::Result(Ok(Some(payload))) = value else {
            panic!("expected component ok result, got {value:?}");
        };
        let ComponentVal::Option(option) = payload.as_ref() else {
            panic!("expected option payload, got {payload:?}");
        };
        match (option.as_ref().map(|v| v.as_ref()), expected) {
            (None, None) => {}
            (Some(ComponentVal::List(items)), Some(expected)) => {
                let bytes = items
                    .iter()
                    .map(|item| match item {
                        ComponentVal::U8(byte) => *byte,
                        other => panic!("expected u8 item, got {other:?}"),
                    })
                    .collect::<Vec<_>>();
                assert_eq!(bytes, expected);
            }
            other => panic!("unexpected optional bytes payload: {other:?}"),
        }
    }

    fn assert_component_ok_bytes(value: &ComponentVal, expected: &[u8]) {
        assert_eq!(component_result_bytes(value), expected);
    }

    fn component_result_bytes(value: &ComponentVal) -> Vec<u8> {
        let ComponentVal::Result(Ok(Some(payload))) = value else {
            panic!("expected component ok result, got {value:?}");
        };
        let ComponentVal::List(items) = payload.as_ref() else {
            panic!("expected byte list payload, got {payload:?}");
        };
        items
            .iter()
            .map(|item| match item {
                ComponentVal::U8(byte) => *byte,
                other => panic!("expected u8 item, got {other:?}"),
            })
            .collect::<Vec<_>>()
    }

    fn assert_component_ok_signature(value: &ComponentVal, expected: &[u8]) {
        let ComponentVal::Result(Ok(Some(payload))) = value else {
            panic!("expected component ok result, got {value:?}");
        };
        let ComponentVal::Variant(kind, Some(signature)) = payload.as_ref() else {
            panic!("expected signature result, got {payload:?}");
        };
        assert_eq!(kind, "signature");
        let ComponentVal::List(items) = signature.as_ref() else {
            panic!("expected signature bytes, got {signature:?}");
        };
        let bytes = items
            .iter()
            .map(|item| match item {
                ComponentVal::U8(byte) => *byte,
                other => panic!("expected u8 item, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(bytes, expected);
    }

    fn assert_component_ok_http_body(value: &ComponentVal, expected: &[u8]) {
        let ComponentVal::Result(Ok(Some(payload))) = value else {
            panic!("expected component ok result, got {value:?}");
        };
        let ComponentVal::Record(fields) = payload.as_ref() else {
            panic!("expected response record payload, got {payload:?}");
        };
        let body = component_record_field(fields, "body").unwrap();
        assert_eq!(component_byte_list(body, "body").unwrap(), expected);
    }

    fn assert_component_ok_chain_result(value: &ComponentVal, expected: &str) {
        let ComponentVal::Result(Ok(Some(payload))) = value else {
            panic!("expected component ok result, got {value:?}");
        };
        let ComponentVal::Record(fields) = payload.as_ref() else {
            panic!("expected response record payload, got {payload:?}");
        };
        assert_eq!(
            component_record_string(fields, "result-json").unwrap(),
            expected
        );
    }

    fn assert_component_ok_entry_names(value: &ComponentVal, expected: &[&str]) {
        let ComponentVal::Result(Ok(Some(payload))) = value else {
            panic!("expected component ok result, got {value:?}");
        };
        let ComponentVal::List(items) = payload.as_ref() else {
            panic!("expected entry list payload, got {payload:?}");
        };
        let names = items
            .iter()
            .map(|item| {
                let ComponentVal::Record(fields) = item else {
                    panic!("expected entry record, got {item:?}");
                };
                component_record_string(fields, "name").unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(names, expected);
    }

    fn assert_component_ok_entry(
        value: &ComponentVal,
        expected_name: &str,
        expected_kind: &str,
        expected_mode: u32,
    ) {
        let ComponentVal::Result(Ok(Some(payload))) = value else {
            panic!("expected component ok result, got {value:?}");
        };
        let ComponentVal::Record(fields) = payload.as_ref() else {
            panic!("expected entry record payload, got {payload:?}");
        };
        assert_eq!(
            component_record_string(fields, "name").unwrap(),
            expected_name
        );
        assert!(matches!(
            component_record_field(fields, "kind").unwrap(),
            ComponentVal::Enum(kind) if kind == expected_kind
        ));
        assert_eq!(
            component_record_field(fields, "mode").unwrap(),
            &ComponentVal::U32(expected_mode)
        );
    }

    fn assert_component_ok_string_list(value: &ComponentVal, expected: &[&str]) {
        let ComponentVal::Result(Ok(Some(payload))) = value else {
            panic!("expected component ok result, got {value:?}");
        };
        let ComponentVal::List(items) = payload.as_ref() else {
            panic!("expected list payload, got {payload:?}");
        };
        let values = items
            .iter()
            .map(|item| match item {
                ComponentVal::String(value) => value.as_str(),
                other => panic!("expected string item, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(values, expected);
    }

    fn component_entry(name: &str, kind: &str, size: Option<u64>) -> ComponentVal {
        ComponentVal::Record(vec![
            ("name".into(), ComponentVal::String(name.into())),
            ("kind".into(), ComponentVal::Enum(kind.into())),
            ("mode".into(), ComponentVal::U32(0o644)),
            (
                "size".into(),
                ComponentVal::Option(size.map(|size| Box::new(ComponentVal::U64(size)))),
            ),
            ("link-target".into(), ComponentVal::Option(None)),
        ])
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
