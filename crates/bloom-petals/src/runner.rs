//! High-level petal install / run, gluing the store, registry, and VM.
//!
//! The runner is the only place that bridges a [`PetalVm`] to a
//! surrounding [`bloom_vfs::Vfs`] — petals reach VFS paths via the
//! host imports we install on the runner's VM.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_petal_manifest::local::LocalPetalManifest;
use bloom_vfs::handler::HandlerError;
use bloom_vfs::path::VfsPath;
use bloom_vfs::{Handler, Vfs};
use parking_lot::RwLock;

use crate::error::PetalError;
use crate::host::{HostError, PetalHost};
use crate::meta::{Capability, PetalMeta};
use crate::policy::NetPolicy;
use crate::registry::NameRegistry;
use crate::store::{InstallResult, PetalStore};
use crate::v2::{RouteAbi, RouteEntryKind, RouteIndex, RouteIndexRecord, RouteOp};
use crate::vm::{DispatchOutput, PetalVm, RunOptions, RunOutput};
use crate::{DispatchOp, DispatchRequest};

/// Wraps an `Arc<Vfs>` so a petal's `bloom.vfs_read`/`vfs_write` calls
/// land on the live VFS (and therefore on the same daemon state the
/// rest of the bloom CLI sees).
pub struct VfsHost {
    vfs: Arc<Vfs>,
}

impl VfsHost {
    pub fn new(vfs: Arc<Vfs>) -> Self {
        Self { vfs }
    }
}

#[async_trait]
impl PetalHost for VfsHost {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        let path = VfsPath::parse(path).map_err(|e| HostError::Invalid(format!("path: {e}")))?;
        deny_apps_subtree(&path)?;
        self.vfs.read(&path).await.map_err(host_from_handler)
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<String>, HostError> {
        let path = VfsPath::parse(path).map_err(|e| HostError::Invalid(format!("path: {e}")))?;
        deny_apps_subtree(&path)?;
        self.vfs
            .list(&path)
            .await
            .map(|entries| entries.into_iter().map(|entry| entry.name).collect())
            .map_err(host_from_handler)
    }

    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        let path = VfsPath::parse(path).map_err(|e| HostError::Invalid(format!("path: {e}")))?;
        deny_apps_subtree(&path)?;
        self.vfs
            .write(&path, bytes)
            .await
            .map_err(host_from_handler)
    }
}

fn deny_apps_subtree(path: &VfsPath) -> Result<(), HostError> {
    if path.first() == Some("apps") {
        return Err(HostError::Denied(
            "petals may not call other apps through vfs imports".into(),
        ));
    }
    Ok(())
}

/// A VFS host whose router is set after the daemon finishes building the VFS.
///
/// `apps/` needs a [`PetalHost`] while the VFS builder is still being wired,
/// but the host itself should point at the final router. This tiny indirection
/// avoids disabling `vfs.read`/`vfs.write` for app petals.
#[derive(Default)]
pub struct LateVfsHost {
    vfs: RwLock<Option<Arc<Vfs>>>,
}

impl LateVfsHost {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, vfs: Arc<Vfs>) {
        *self.vfs.write() = Some(vfs);
    }

    fn current(&self) -> Result<Arc<Vfs>, HostError> {
        self.vfs
            .read()
            .as_ref()
            .cloned()
            .ok_or_else(|| HostError::Backend("VFS host not initialised".into()))
    }
}

#[async_trait]
impl PetalHost for LateVfsHost {
    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        let vfs = self.current()?;
        VfsHost::new(vfs).vfs_read(path).await
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<String>, HostError> {
        let vfs = self.current()?;
        VfsHost::new(vfs).vfs_list(path).await
    }

    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        let vfs = self.current()?;
        VfsHost::new(vfs).vfs_write(path, bytes).await
    }
}

fn host_from_handler(e: HandlerError) -> HostError {
    match e {
        HandlerError::NotFound(s) => HostError::NotFound(s),
        HandlerError::NotADir(s) | HandlerError::NotAFile(s) => HostError::Invalid(s),
        HandlerError::PermissionDenied => HostError::Denied("vfs".into()),
        HandlerError::Invalid(s) => HostError::Invalid(s),
        HandlerError::Unsupported(s) => HostError::Backend(format!("unsupported: {s}")),
        HandlerError::Backend(s) => HostError::Backend(s),
        HandlerError::Io(e) => HostError::Backend(format!("io: {e}")),
    }
}

/// Single source of truth for installing and running petals.
#[derive(Clone)]
pub struct PetalRunner {
    store: PetalStore,
    registry: Arc<NameRegistry>,
    vm: PetalVm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAppRouteMatch {
    pub hash: String,
    pub route: RouteIndexRecord,
    pub params: Vec<(String, String)>,
}

impl PetalRunner {
    pub fn new(store: PetalStore, registry: Arc<NameRegistry>, vm: PetalVm) -> Self {
        Self {
            store,
            registry,
            vm,
        }
    }

    pub fn store(&self) -> &PetalStore {
        &self.store
    }

    pub fn registry(&self) -> &Arc<NameRegistry> {
        &self.registry
    }

    /// Install a petal from raw bytes. Accepts either a wasm binary
    /// (starting with `\0asm`) or WAT source — WAT is compiled in
    /// memory before hashing, so the on-disk hash is always the
    /// canonical wasm.
    ///
    /// `(mode, caps)` is validated against [`validate_mode_caps`] before
    /// any bytes are parsed. Re-installing the same hash under a different
    /// mode is rejected with `ModeConflict` by the store.
    pub fn install(
        &self,
        bytes: &[u8],
        name: Option<&str>,
        caps: &BTreeSet<Capability>,
        mode: crate::meta::PetalMode,
    ) -> Result<(InstallResult, PetalMeta), PetalError> {
        crate::meta::validate_mode_caps(mode, caps)?;
        let wasm = if bytes.starts_with(b"\0asm") {
            bytes.to_vec()
        } else {
            // Try WAT.
            let s = std::str::from_utf8(bytes)
                .map_err(|_| PetalError::InvalidWasm("not wasm and not utf-8 WAT".into()))?;
            wat::parse_str(s).map_err(|e| PetalError::InvalidWasm(format!("wat: {e}")))?
        };
        let local_manifest = if mode == crate::meta::PetalMode::Local
            && bloom_petal_manifest::extract_petal_manifest_bytes(&wasm).is_some()
        {
            let occupied = self
                .store
                .list_hashes_by_mode(crate::meta::PetalMode::Local)?
                .into_iter()
                .filter_map(|hash| self.store.load_meta(&hash).ok())
                .filter_map(|meta| meta.local_manifest.map(|m| m.provides.mount))
                .collect::<Vec<_>>();
            Some(
                bloom_petal_manifest::extract_local_petal_manifest(
                    &wasm,
                    occupied.iter().map(String::as_str),
                )
                .map_err(|e| PetalError::InvalidWasm(format!("local manifest: {e}")))?,
            )
        } else {
            None
        };
        let effective_caps = local_manifest
            .as_ref()
            .map(|manifest| {
                manifest
                    .cap_set()
                    .into_iter()
                    .filter_map(|cap| Capability::parse(cap.as_str()))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_else(|| caps.clone());
        if local_manifest.is_none() && effective_caps.iter().any(requires_local_manifest) {
            return Err(PetalError::InvalidWasm(
                "net.fetch, sign, and store require an embedded local manifest".into(),
            ));
        }
        if local_manifest.is_some() && !caps.is_empty() && *caps != effective_caps {
            return Err(PetalError::CapMismatch);
        }
        let (result, mut meta) = self.store.install(&wasm, name, &effective_caps, mode)?;
        if meta.local_manifest != local_manifest {
            meta.local_manifest = local_manifest;
            self.store.write_meta(&meta)?;
        }
        if let Some(n) = name {
            self.registry.set(n, &result.hash)?;
        }
        Ok((result, meta))
    }

    /// Remove an installed petal and any petname pointing at it.
    /// Returns true if anything was removed.
    pub fn uninstall(&self, hash: &str) -> Result<bool, PetalError> {
        let to_unset: Vec<String> = self
            .registry
            .snapshot()
            .into_iter()
            .filter_map(|(n, h)| if h == hash { Some(n) } else { None })
            .collect();
        let removed = self.store.uninstall(hash)?;
        for n in to_unset {
            self.registry.unset(&n)?;
        }
        Ok(removed)
    }

    /// Resolve a `name_or_hash` to a content hash. Hashes win — if a
    /// caller passes a 64-char hex that happens to be a name, the
    /// hash interpretation is used.
    pub fn resolve(&self, name_or_hash: &str) -> Result<String, PetalError> {
        if crate::store::is_valid_hex_hash(name_or_hash) && self.store.contains(name_or_hash) {
            return Ok(name_or_hash.to_string());
        }
        self.registry
            .lookup(name_or_hash)
            .ok_or_else(|| PetalError::NotFound(name_or_hash.to_string()))
    }

    pub fn local_mounts(&self) -> Result<Vec<(String, String)>, PetalError> {
        let mut out = Vec::new();
        for hash in self
            .store
            .list_hashes_by_mode(crate::meta::PetalMode::Local)?
        {
            let meta = self.store.load_meta(&hash)?;
            if let Some(manifest) = meta.local_manifest {
                out.push((manifest.provides.mount, hash));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    pub fn local_app_mounts(&self) -> Result<Vec<(String, String)>, PetalError> {
        let mut out = Vec::new();
        for hash in self.store.list_package_hashes()? {
            let meta = self.store.load_meta(&hash)?;
            if let Some(app) = meta.local_app {
                out.push((app.name, hash));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    pub fn resolve_mount(&self, mount: &str) -> Result<String, PetalError> {
        self.local_mounts()?
            .into_iter()
            .find_map(|(candidate, hash)| (candidate == mount).then_some(hash))
            .ok_or_else(|| PetalError::NotFound(format!("apps/{mount}")))
    }

    pub fn resolve_app_mount(&self, mount: &str) -> Result<String, PetalError> {
        self.local_app_mounts()?
            .into_iter()
            .find_map(|(candidate, hash)| (candidate == mount).then_some(hash))
            .ok_or_else(|| PetalError::NotFound(format!("apps/{mount}")))
    }

    pub fn load_app_route_index(&self, mount: &str) -> Result<RouteIndex, PetalError> {
        let hash = self.resolve_app_mount(mount)?;
        self.store.load_route_index(&hash)
    }

    pub fn local_app_route(
        &self,
        mount: &str,
        op: DispatchOp,
        path: &str,
    ) -> Result<LocalAppRouteMatch, PetalError> {
        validate_runtime_route_path(path)?;
        let hash = self.resolve_app_mount(mount)?;
        let index = self.store.load_route_index(&hash)?;
        let Some(matched) = match_index_for_op(&index, op, path) else {
            return Err(PetalError::NotFound(app_path(mount, path)));
        };
        let required_op = route_op(op);
        if !matched.route.ops.contains(&required_op) {
            return Err(PetalError::ModeUnsupported(format!(
                "v2 route {} does not support {required_op:?}",
                matched.route.route_id
            )));
        }
        Ok(LocalAppRouteMatch {
            hash,
            route: matched.route.clone(),
            params: matched.params,
        })
    }

    pub fn local_app_has_descendant(&self, mount: &str, path: &str) -> Result<bool, PetalError> {
        validate_runtime_route_path(path)?;
        let index = self.load_app_route_index(mount)?;
        Ok(index
            .routes
            .iter()
            .any(|route| route_has_descendant(&route.pattern, path)))
    }

    pub fn local_app_static_list(
        &self,
        mount: &str,
        path: &str,
    ) -> Result<Vec<crate::DispatchEntry>, PetalError> {
        validate_runtime_route_path(path)?;
        let index = self.load_app_route_index(mount)?;
        Ok(static_list_entries(&index, path))
    }

    pub fn local_manifest_for_mount(&self, mount: &str) -> Result<LocalPetalManifest, PetalError> {
        let hash = self.resolve_mount(mount)?;
        self.store
            .load_meta(&hash)?
            .local_manifest
            .ok_or_else(|| PetalError::NotFound(format!("apps/{mount}")))
    }

    /// Run a petal by name or hash. The caps used at runtime are the
    /// petal's declared caps, intersected with `cap_mask` if provided
    /// (`None` means "use the petal's declared caps"). Callers that
    /// want to *further restrict* what a petal can do can pass a
    /// narrower mask; they cannot grant capabilities the petal didn't
    /// declare.
    pub async fn run(
        &self,
        name_or_hash: &str,
        stdin: Vec<u8>,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
    ) -> Result<RunOutput, PetalError> {
        let hash = self.resolve(name_or_hash)?;
        let wasm = self.store.read_wasm(&hash)?;
        let meta = self.store.load_meta(&hash)?;
        let mut caps: BTreeSet<Capability> = match cap_mask {
            Some(mask) => meta.caps.intersection(&mask).copied().collect(),
            None => meta.caps.clone(),
        };
        let mut opts = opts;
        if opts.private_store_root.is_none() {
            opts.private_store_root = Some(self.store.private_data_root());
        }
        if let Some(manifest) = &meta.local_manifest {
            let declared = NetPolicy::from_manifest(manifest);
            opts.net_policy = Some(match opts.net_policy {
                Some(mask) => declared.intersect(&mask),
                None => declared,
            });
        } else {
            caps.retain(|cap| !requires_local_manifest(cap));
            opts.net_policy = None;
        }
        self.vm
            .run(&wasm, stdin, caps, host, &hash, meta.mode, opts)
            .await
    }

    pub async fn dispatch_mount(
        &self,
        mount: &str,
        request: DispatchRequest,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
    ) -> Result<DispatchOutput, PetalError> {
        let hash = self.resolve_mount(mount)?;
        let wasm = self.store.read_wasm(&hash)?;
        let meta = self.store.load_meta(&hash)?;
        let Some(manifest) = &meta.local_manifest else {
            return Err(PetalError::NotFound(format!("apps/{mount}")));
        };
        let caps = match cap_mask {
            Some(mask) => meta.caps.intersection(&mask).copied().collect(),
            None => meta.caps.clone(),
        };
        let declared = NetPolicy::from_manifest(manifest);
        let mut opts = opts;
        opts.net_policy = Some(match opts.net_policy {
            Some(mask) => declared.intersect(&mask),
            None => declared,
        });
        if opts.private_store_root.is_none() {
            opts.private_store_root = Some(self.store.private_data_root());
        }
        self.vm
            .dispatch(&wasm, request, caps, host, &hash, opts)
            .await
    }

    pub async fn dispatch_app_route(
        &self,
        mount: &str,
        mut request: DispatchRequest,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
    ) -> Result<DispatchOutput, PetalError> {
        let matched = self.local_app_route(mount, request.op, &request.path)?;
        let route_params = matched.params.clone();
        request.ctx.extend(route_params.clone());
        request
            .ctx
            .push(("bloom.route_id".into(), matched.route.route_id.clone()));

        let mut caps = matched
            .route
            .install_metadata
            .required_caps
            .iter()
            .map(|cap| {
                v2_capability(cap).ok_or_else(|| {
                    PetalError::InvalidWasm(format!(
                        "v2 route {} has unknown required cap {cap:?}",
                        matched.route.route_id
                    ))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if let Some(mask) = cap_mask {
            caps = caps.intersection(&mask).copied().collect();
        }

        let wasm = self
            .store
            .read_route_artifact(&matched.hash, &matched.route.route_id)?;
        let mut opts = opts;
        if opts.private_store_root.is_none() {
            opts.private_store_root = Some(self.store.private_data_root());
        }
        let declared = self.v2_net_policy(&matched.hash)?;
        opts.net_policy = Some(match opts.net_policy {
            Some(mask) => declared.intersect(&mask),
            None => declared,
        });
        match matched.route.abi {
            RouteAbi::CompatPetalDispatchV1 => {
                self.vm
                    .dispatch(&wasm, request, caps, host, &matched.hash, opts)
                    .await
            }
            RouteAbi::ComponentBloomRoute010 => {
                self.vm
                    .dispatch_component_route(
                        &wasm,
                        request,
                        caps,
                        host,
                        &matched.hash,
                        mount,
                        route_params,
                        opts,
                    )
                    .await
            }
        }
    }

    fn v2_net_policy(&self, hash: &str) -> Result<NetPolicy, PetalError> {
        let manifest = std::fs::read(self.store.package_path(hash)?.join("source/petal.toml"))?;
        NetPolicy::from_v2_manifest_toml(&manifest)
    }
}

fn requires_local_manifest(cap: &Capability) -> bool {
    matches!(
        cap,
        Capability::NetFetch | Capability::Sign | Capability::Store
    )
}

fn route_op(op: DispatchOp) -> RouteOp {
    match op {
        DispatchOp::Lookup => RouteOp::Lookup,
        DispatchOp::List => RouteOp::List,
        DispatchOp::Read => RouteOp::Read,
        DispatchOp::Write => RouteOp::Write,
    }
}

fn match_index_for_op<'a>(
    index: &'a RouteIndex,
    op: DispatchOp,
    path: &str,
) -> Option<crate::v2::RouteIndexMatch<'a>> {
    match op {
        DispatchOp::Lookup => index
            .match_route(path)
            .or_else(|| match_special_route(index, path, "$lookup")),
        DispatchOp::List => match_special_route(index, path, "$list"),
        DispatchOp::Read | DispatchOp::Write => index.match_route(path),
    }
}

fn match_special_route<'a>(
    index: &'a RouteIndex,
    path: &str,
    special: &str,
) -> Option<crate::v2::RouteIndexMatch<'a>> {
    let candidate = special_route_path(path, special);
    let matched = index.match_route(&candidate)?;
    if route_segments(&matched.route.pattern).last().copied() == Some(special) {
        Some(matched)
    } else {
        None
    }
}

fn validate_runtime_route_path(path: &str) -> Result<(), PetalError> {
    if path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|b| b == 0)
        || (!path.is_empty()
            && path.split('/').any(|segment| {
                segment.is_empty() || segment == "." || segment == ".." || segment.starts_with('$')
            }))
    {
        return Err(PetalError::InvalidWasm(format!(
            "invalid v2 runtime route path {path:?}"
        )));
    }
    Ok(())
}

fn special_route_path(path: &str, special: &str) -> String {
    if path.is_empty() {
        special.to_string()
    } else {
        format!("{path}/{special}")
    }
}

fn v2_capability(cap: &str) -> Option<Capability> {
    match cap {
        "bloom:http" => Some(Capability::NetFetch),
        "bloom:store" => Some(Capability::Store),
        "bloom:sign" => Some(Capability::Sign),
        "bloom:vfs.read" => Some(Capability::VfsRead),
        "bloom:vfs.write" => Some(Capability::VfsWrite),
        _ => Capability::parse(cap),
    }
}

fn app_path(mount: &str, path: &str) -> String {
    if path.is_empty() {
        format!("apps/{mount}")
    } else {
        format!("apps/{mount}/{path}")
    }
}

fn route_has_descendant(pattern: &str, path: &str) -> bool {
    let pattern_segments = route_segments(pattern);
    let path_segments = route_segments(path);
    if path_segments.len() >= pattern_segments.len() {
        return false;
    }
    path_segments
        .iter()
        .zip(pattern_segments.iter())
        .all(|(value, pattern)| route_segment_matches(pattern, value))
}

fn static_list_entries(index: &RouteIndex, path: &str) -> Vec<crate::DispatchEntry> {
    use crate::{DispatchEntry, DispatchEntryKind};
    use std::collections::BTreeMap;

    let path_segments = route_segments(path);
    let mut entries = BTreeMap::<String, DispatchEntryKind>::new();
    for route in &index.routes {
        let pattern_segments = route_segments(&route.pattern);
        if path_segments.len() >= pattern_segments.len() {
            continue;
        }
        if !path_segments
            .iter()
            .zip(pattern_segments.iter())
            .all(|(value, pattern)| route_segment_matches(pattern, value))
        {
            continue;
        }
        let next = pattern_segments[path_segments.len()];
        if next.starts_with('$') || next.starts_with('[') {
            continue;
        }
        let kind = if path_segments.len() + 1 == pattern_segments.len()
            && route.kind == RouteEntryKind::File
        {
            DispatchEntryKind::File
        } else {
            DispatchEntryKind::Dir
        };
        entries
            .entry(next.to_string())
            .and_modify(|existing| {
                if kind == DispatchEntryKind::Dir {
                    *existing = DispatchEntryKind::Dir;
                }
            })
            .or_insert(kind);
    }
    entries
        .into_iter()
        .map(|(name, kind)| DispatchEntry {
            name,
            kind,
            size: 0,
            mode: 0,
            ttl_hint_ms: None,
            link_target: None,
        })
        .collect()
}

fn route_segments(path: &str) -> Vec<&str> {
    if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    }
}

fn route_segment_matches(pattern: &str, value: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let suffix = &rest[end + 1..];
        return value
            .strip_suffix(suffix)
            .is_some_and(|bound| !bound.is_empty());
    }
    pattern == value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{HttpRequest, HttpResponse, encode_http_request};
    use parking_lot::Mutex;
    use tempfile::TempDir;

    fn runner() -> (TempDir, PetalRunner) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let vm = PetalVm::new().unwrap();
        (dir, PetalRunner::new(store, reg, vm))
    }

    const HELLO_WAT: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "hi from petal\n")
          (data (i32.const 32) "\00\00\00\00\0e\00\00\00")
          (func (export "_start")
            (call $fd_write (i32.const 1) (i32.const 32) (i32.const 1) (i32.const 48))
            drop
            (call $exit (i32.const 0)))
        )
    "#;

    fn wat_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("\\{b:02x}")).collect()
    }

    fn http_probe_wat(req: &[u8]) -> String {
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

    fn embedded_net_petal() -> Vec<u8> {
        let req = encode_http_request(&HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/markets".into(),
            headers: Vec::new(),
            body: Vec::new(),
        });
        let wasm = wat::parse_str(http_probe_wat(&req)).unwrap();
        bloom_petal_manifest::embed_local_manifest_section(
            &wasm,
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
        .unwrap()
    }

    #[derive(Default)]
    struct HttpHost {
        calls: Mutex<Vec<HttpRequest>>,
    }

    #[async_trait]
    impl PetalHost for HttpHost {
        async fn vfs_read(&self, _path: &str) -> Result<Vec<u8>, HostError> {
            Err(HostError::Denied("vfs".into()))
        }

        async fn vfs_list(&self, _path: &str) -> Result<Vec<String>, HostError> {
            Err(HostError::Denied("vfs".into()))
        }

        async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
            Err(HostError::Denied("vfs".into()))
        }

        async fn http_fetch(
            &self,
            req: HttpRequest,
            policy: NetPolicy,
            max_response_bytes: usize,
        ) -> Result<HttpResponse, HostError> {
            policy.check(&req.method, &req.url)?;
            self.calls.lock().push(req);
            let body = b"ok".to_vec();
            assert!(body.len() <= max_response_bytes);
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body,
            })
        }
    }

    struct StaticHandler;

    #[async_trait::async_trait]
    impl Handler for StaticHandler {
        async fn lookup(&self, path: &VfsPath) -> Result<bloom_vfs::Entry, HandlerError> {
            if path.is_root() {
                Ok(bloom_vfs::Entry::dir(""))
            } else {
                Ok(bloom_vfs::Entry::read_only_file("x"))
            }
        }

        async fn read(&self, _path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            Ok(b"reachable".to_vec())
        }

        async fn write(&self, _path: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn install_from_wat_then_run_by_name() {
        let (_d, r) = runner();
        let (res, _meta) = r
            .install(
                HELLO_WAT.as_bytes(),
                Some("hello"),
                &BTreeSet::new(),
                crate::meta::PetalMode::Local,
            )
            .unwrap();
        // Registry now maps `hello` to the installed hash.
        assert_eq!(r.registry().lookup("hello"), Some(res.hash.clone()));
        let out = r
            .run(
                "hello",
                Vec::new(),
                Arc::new(crate::host::DenyHost),
                None,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, b"hi from petal\n");
    }

    #[tokio::test]
    async fn vfs_host_denies_apps_subtree_to_prevent_petal_recursion() {
        let vfs = Vfs::builder()
            .mount("apps", Arc::new(StaticHandler) as _)
            .build();
        let host = VfsHost::new(Arc::new(vfs));
        assert!(matches!(
            host.vfs_read("apps/demo/file").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_write("apps/demo/file", b"x").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_list("apps/demo").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_list("../wallets").await,
            Err(HostError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn component_app_routes_use_component_runner_and_surface_component_errors() {
        let (dir, r) = runner();
        let package = dir.path().join("component-app");
        write_package_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(&package, "README.md", b"# echo");
        write_package_file(&package, "AGENTS.md", b"# echo agents");
        write_package_file(
            &package,
            "app/echo/message.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        r.store().install_app_package_dir(&package).unwrap();

        let err = r
            .dispatch_app_route(
                "echo",
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "message.txt".into(),
                    body: Vec::new(),
                    ctx: Vec::new(),
                },
                Arc::new(crate::host::DenyHost),
                None,
                RunOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(!matches!(err, PetalError::ModeUnsupported(_)));
        assert!(err.to_string().contains("component route"));
    }

    #[tokio::test]
    async fn resolve_prefers_hash_then_name() {
        let (_d, r) = runner();
        let (res, _) = r
            .install(
                HELLO_WAT.as_bytes(),
                Some("aname"),
                &BTreeSet::new(),
                crate::meta::PetalMode::Local,
            )
            .unwrap();
        assert_eq!(r.resolve(&res.hash).unwrap(), res.hash);
        assert_eq!(r.resolve("aname").unwrap(), res.hash);
        assert!(matches!(
            r.resolve("nope").unwrap_err(),
            PetalError::NotFound(_)
        ));
    }

    fn write_package_file(root: &std::path::Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[tokio::test]
    async fn uninstall_removes_object_meta_and_petname() {
        let (_d, r) = runner();
        let (res, _) = r
            .install(
                HELLO_WAT.as_bytes(),
                Some("byename"),
                &BTreeSet::new(),
                crate::meta::PetalMode::Local,
            )
            .unwrap();
        assert!(r.store().contains(&res.hash));
        assert_eq!(r.registry().lookup("byename"), Some(res.hash.clone()));
        let removed = r.uninstall(&res.hash).unwrap();
        assert!(removed);
        assert!(!r.store().contains(&res.hash));
        assert!(r.registry().lookup("byename").is_none());
    }

    #[tokio::test]
    async fn embedded_manifest_net_policy_is_used_by_runner_and_can_be_narrowed() {
        let (_d, r) = runner();
        let (res, meta) = r
            .install(
                &embedded_net_petal(),
                Some("netty"),
                &BTreeSet::new(),
                crate::meta::PetalMode::Local,
            )
            .unwrap();
        assert!(meta.local_manifest.is_some());
        assert!(meta.caps.contains(&Capability::NetFetch));

        let host = Arc::new(HttpHost::default());
        let out = r
            .run(
                "netty",
                Vec::new(),
                host.clone(),
                None,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(host.calls.lock().len(), 1);
        assert!(out.stdout[0] > 0);

        let manifest = r
            .store()
            .load_meta(&res.hash)
            .unwrap()
            .local_manifest
            .unwrap();
        let mut mask = NetPolicy::from_manifest(&manifest);
        let deny_manifest = bloom_petal_manifest::local::parse_local_manifest_toml(
            br#"
schema = "bloom.petal.local.v1"
name = "nettymask"
[provides]
kind = "vfs"
mount = "nettymask"
caps = ["net.fetch"]
[[net.allow]]
host = "api.example.com"
methods = ["POST"]
paths = ["/markets*"]
"#,
        )
        .unwrap();
        mask = mask.intersect(&NetPolicy::from_manifest(&deny_manifest));
        let out = r
            .run(
                "netty",
                Vec::new(),
                host.clone(),
                None,
                RunOptions {
                    net_policy: Some(mask),
                    ..RunOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            out.stdout,
            vec![(HostError::Denied("".into()).as_wasm_code() as i8) as u8]
        );
        assert_eq!(host.calls.lock().len(), 1);
    }

    #[test]
    fn no_manifest_install_rejects_sensitive_caps() {
        let (_d, r) = runner();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::NetFetch);
        assert!(matches!(
            r.install(
                HELLO_WAT.as_bytes(),
                Some("legacy-net"),
                &caps,
                crate::meta::PetalMode::Local,
            ),
            Err(PetalError::InvalidWasm(_))
        ));
    }

    #[tokio::test]
    async fn no_manifest_metadata_cannot_use_runtime_net_policy_as_grant() {
        let (_d, r) = runner();
        let req = encode_http_request(&HttpRequest {
            method: "GET".into(),
            url: "https://api.example.com/markets".into(),
            headers: Vec::new(),
            body: Vec::new(),
        });
        let wasm = wat::parse_str(http_probe_wat(&req)).unwrap();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::NetFetch);
        let (res, _) = r
            .store()
            .install(&wasm, None, &caps, crate::meta::PetalMode::Local)
            .unwrap();
        r.registry().set("legacy-net", &res.hash).unwrap();
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
        let host = Arc::new(HttpHost::default());
        let out = r
            .run(
                "legacy-net",
                Vec::new(),
                host.clone(),
                None,
                RunOptions {
                    net_policy: Some(NetPolicy::from_manifest(&manifest)),
                    ..RunOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            out.stdout,
            vec![(HostError::Denied("".into()).as_wasm_code() as i8) as u8]
        );
        assert!(host.calls.lock().is_empty());
    }
}
