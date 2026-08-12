//! High-level petal install / run, gluing the store, registry, and VM.
//!
//! The runner is the only place that bridges a [`PetalVm`] to a
//! surrounding [`bloom_vfs::Vfs`] — petals reach VFS paths via the
//! host imports we install on the runner's VM.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_vfs::handler::HandlerError;
use bloom_vfs::path::VfsPath;
use bloom_vfs::{Handler, Vfs};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};

use crate::error::PetalError;
use crate::host::{DenyHost, HostError, HostVfsEntry, HostVfsEntryKind, PetalHost};
use crate::meta::Capability;
use crate::package::{
    InstallRouteMetadata, PetalDiscovery, RouteAbi, RouteEntryKind, RouteIndex, RouteIndexRecord,
    RouteOp, narrow_runtime_route_metadata, petal_discovery_from_manifest_toml,
    sign_intents_from_manifest_toml, store_policy_from_manifest_toml,
};
use crate::policy::NetPolicy;
use crate::registry::NameRegistry;
use crate::store::PetalStore;
use crate::vm::{DispatchOutput, PetalVm, RunOptions};
use crate::{DispatchOp, DispatchRequest};

/// Runtime route metadata is deterministic for an immutable package and a
/// fully-bound route path. Keep a bounded cache so synchronous VFS metadata
/// hooks can use the validated, narrowed result after an async route lookup.
const RUNTIME_METADATA_CACHE_CAPACITY: usize = 1024;

pub(crate) const PETAL_DOCUMENT_NAMES: [&str; 2] = ["README.md", "AGENTS.md"];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RuntimeMetadataCacheKey {
    package_hash: String,
    route_id: String,
    path: String,
}

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
    async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
        let path = VfsPath::parse(path).map_err(|e| HostError::Invalid(format!("path: {e}")))?;
        deny_apps_subtree(&path)?;
        self.vfs
            .lookup(&path)
            .await
            .map(host_entry_from_vfs)
            .map_err(host_from_handler)
    }

    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        let path = VfsPath::parse(path).map_err(|e| HostError::Invalid(format!("path: {e}")))?;
        deny_apps_subtree(&path)?;
        self.vfs.read(&path).await.map_err(host_from_handler)
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        let path = VfsPath::parse(path).map_err(|e| HostError::Invalid(format!("path: {e}")))?;
        deny_apps_subtree(&path)?;
        self.vfs
            .list(&path)
            .await
            .map(|entries| entries.into_iter().map(host_entry_from_vfs).collect())
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
    if path.first() == Some("petals") {
        return Err(HostError::Denied(
            "petals may not call other apps through vfs imports".into(),
        ));
    }
    Ok(())
}

/// A VFS host whose router is set after the daemon finishes building the VFS.
///
/// `petals/` needs a [`PetalHost`] while the VFS builder is still being wired,
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
    async fn vfs_lookup(&self, path: &str) -> Result<HostVfsEntry, HostError> {
        let vfs = self.current()?;
        VfsHost::new(vfs).vfs_lookup(path).await
    }

    async fn vfs_read(&self, path: &str) -> Result<Vec<u8>, HostError> {
        let vfs = self.current()?;
        VfsHost::new(vfs).vfs_read(path).await
    }

    async fn vfs_list(&self, path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
        let vfs = self.current()?;
        VfsHost::new(vfs).vfs_list(path).await
    }

    async fn vfs_write(&self, path: &str, bytes: &[u8]) -> Result<(), HostError> {
        let vfs = self.current()?;
        VfsHost::new(vfs).vfs_write(path, bytes).await
    }
}

fn host_entry_from_vfs(entry: bloom_vfs::handler::Entry) -> HostVfsEntry {
    let kind = match entry.kind {
        bloom_vfs::handler::EntryKind::Dir => HostVfsEntryKind::Dir,
        bloom_vfs::handler::EntryKind::File => HostVfsEntryKind::File,
        bloom_vfs::handler::EntryKind::Symlink => HostVfsEntryKind::Symlink,
    };
    HostVfsEntry {
        name: entry.name,
        kind,
        mode: entry.mode,
        size: Some(entry.size),
        link_target: entry.link_target,
    }
}

fn host_from_handler(e: HandlerError) -> HostError {
    match e {
        HandlerError::NotFound(s) => HostError::NotFound(s),
        HandlerError::NotADir(s) | HandlerError::NotAFile(s) => HostError::Invalid(s),
        HandlerError::PermissionDenied | HandlerError::OperationNotPermitted => {
            HostError::Denied("vfs".into())
        }
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
    runtime_metadata: Arc<Mutex<LruCache<RuntimeMetadataCacheKey, InstallRouteMetadata>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalRouteMatch {
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
            runtime_metadata: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(RUNTIME_METADATA_CACHE_CAPACITY)
                    .expect("runtime metadata cache capacity is non-zero"),
            ))),
        }
    }

    fn runtime_metadata_key(matched: &PetalRouteMatch, path: &str) -> RuntimeMetadataCacheKey {
        RuntimeMetadataCacheKey {
            package_hash: matched.hash.clone(),
            route_id: matched.route.route_id.clone(),
            path: path.to_string(),
        }
    }

    /// Return the best synchronously available metadata for a route.
    ///
    /// Parameterized routes start with a conservative install-time ceiling.
    /// Once an async lookup or dispatch has evaluated their component
    /// metadata, this returns that validated narrowing. Cache misses remain
    /// fail-closed by returning the install-time metadata.
    pub fn petal_route_effective_metadata(
        &self,
        mount: &str,
        op: DispatchOp,
        path: &str,
    ) -> Result<(PetalRouteMatch, InstallRouteMetadata), PetalError> {
        let matched = self.petal_route(mount, op, path)?;
        if matched.params.is_empty() {
            return Ok((matched.clone(), matched.route.install_metadata.clone()));
        }
        let key = Self::runtime_metadata_key(&matched, path);
        let metadata = self
            .runtime_metadata
            .lock()
            .get(&key)
            .cloned()
            .unwrap_or_else(|| matched.route.install_metadata.clone());
        Ok((matched, metadata))
    }

    pub fn store(&self) -> &PetalStore {
        &self.store
    }

    pub fn registry(&self) -> &Arc<NameRegistry> {
        &self.registry
    }

    /// Remove an installed petal and any petname pointing at it. The
    /// target may be a full content hash, a unique hash prefix of at
    /// least [`crate::store::HASH_PREFIX_LEN`] chars (the length
    /// `petal ls` prints), a Petal name, or a petname. Returns
    /// true if anything was removed.
    pub fn uninstall(&self, target: &str) -> Result<bool, PetalError> {
        let Some(hash) = self.resolve_uninstall_hash(target)? else {
            return Ok(false);
        };
        let to_unset: Vec<String> = self
            .registry
            .snapshot()
            .into_iter()
            .filter_map(|(n, h)| if h == hash { Some(n) } else { None })
            .collect();
        let removed = self.store.uninstall(&hash)?;
        for n in to_unset {
            self.registry.unset(&n)?;
        }
        Ok(removed)
    }

    /// Resolve an uninstall target to a full content hash. Hashes win
    /// (as in [`Self::resolve`]): a full 64-char hash is used as-is,
    /// then a hash prefix is tried against every installed hash, then
    /// a Petal name, then a petname. Returns `None` when nothing
    /// matches.
    fn resolve_uninstall_hash(&self, target: &str) -> Result<Option<String>, PetalError> {
        if crate::store::is_valid_hex_hash(target) {
            return Ok(Some(target.to_string()));
        }
        if crate::store::is_hex_hash_prefix(target) {
            let mut hashes: BTreeSet<String> = self.store.list_hashes()?.into_iter().collect();
            hashes.extend(self.store.list_package_hashes()?);
            if let Some(hash) = resolve_hash_prefix(target, hashes)? {
                return Ok(Some(hash));
            }
        }
        if let Some(hash) = self
            .local_petal_mounts()?
            .into_iter()
            .find_map(|(name, hash)| (name == target).then_some(hash))
        {
            return Ok(Some(hash));
        }
        Ok(self.registry.lookup(target))
    }

    /// Resolve a `name_or_hash` to a content hash. Hashes win — if a
    /// caller passes a 64-char hex that happens to be a name, the
    /// hash interpretation is used.
    pub fn resolve(&self, name_or_hash: &str) -> Result<String, PetalError> {
        if crate::store::is_valid_hex_hash(name_or_hash)
            && (self.store.contains(name_or_hash) || self.store.contains_package(name_or_hash))
        {
            return Ok(name_or_hash.to_string());
        }
        if let Some(hash) = self.store.resolve_petal_owner(name_or_hash)? {
            return Ok(hash);
        }
        self.registry
            .lookup(name_or_hash)
            .ok_or_else(|| PetalError::NotFound(name_or_hash.to_string()))
    }

    pub fn local_petal_mounts(&self) -> Result<Vec<(String, String)>, PetalError> {
        self.store.list_petal_owners()
    }

    /// Return installed Petals as agent-facing discovery records sourced from
    /// each immutable installed package's retained `petal.toml`.
    pub fn installed_petal_discovery(&self) -> Result<Vec<PetalDiscovery>, PetalError> {
        let mut installed = Vec::new();
        for (mount, hash) in self.store.list_petal_owners()? {
            let manifest =
                std::fs::read(self.store.package_path(&hash)?.join("source/petal.toml"))?;
            let discovery = petal_discovery_from_manifest_toml(&manifest)?;
            if discovery.name != mount {
                return Err(PetalError::InvalidWasm(format!(
                    "installed Petal mount {mount:?} does not match manifest name {:?}",
                    discovery.name
                )));
            }
            installed.push(discovery);
        }
        Ok(installed)
    }

    pub fn resolve_petal_mount(&self, mount: &str) -> Result<String, PetalError> {
        self.store
            .resolve_petal_owner(mount)?
            .ok_or_else(|| PetalError::NotFound(format!("petals/{mount}")))
    }

    /// Validate operator-configured endpoint origins against the bindings
    /// declared by an installed app. This is used while constructing the
    /// router so configuration errors fail daemon startup, before dispatch.
    pub fn validate_app_endpoint_bindings(
        &self,
        mount: &str,
        bindings: &BTreeMap<String, String>,
    ) -> Result<(), PetalError> {
        let hash = self.resolve_petal_mount(mount)?;
        self.petal_net_policy(&hash)?
            .with_endpoint_bindings(bindings)?;
        Ok(())
    }

    pub fn load_petal_route_index(&self, mount: &str) -> Result<RouteIndex, PetalError> {
        let hash = self.resolve_petal_mount(mount)?;
        self.store.load_route_index(&hash)
    }

    pub fn petal_route(
        &self,
        mount: &str,
        op: DispatchOp,
        path: &str,
    ) -> Result<PetalRouteMatch, PetalError> {
        validate_runtime_route_path(path)?;
        let hash = self.resolve_petal_mount(mount)?;
        let index = self.store.load_route_index(&hash)?;
        let Some(matched) = match_index_for_op(&index, op, path) else {
            return Err(PetalError::NotFound(app_path(mount, path)));
        };
        let required_op = route_op(op);
        if !matched.route.ops.contains(&required_op) {
            return Err(PetalError::ModeUnsupported(format!(
                "Petal route {} does not support {required_op:?}",
                matched.route.route_id
            )));
        }
        Ok(PetalRouteMatch {
            hash,
            route: matched.route.clone(),
            params: matched.params,
        })
    }

    pub async fn petal_route_runtime_metadata(
        &self,
        mount: &str,
        op: DispatchOp,
        path: &str,
        opts: RunOptions,
    ) -> Result<(PetalRouteMatch, InstallRouteMetadata), PetalError> {
        let matched = self.petal_route(mount, op, path)?;
        let wasm = self
            .store
            .read_route_artifact(&matched.hash, &matched.route.route_id)?;
        let declared_sign_intents = self.petal_sign_intents(&matched.hash)?;
        let metadata = self
            .runtime_petal_route_metadata(
                &matched,
                mount,
                path,
                &wasm,
                &declared_sign_intents,
                &opts,
            )
            .await?;
        enforce_runtime_route_op(op, &matched, &metadata)?;
        Ok((matched, metadata))
    }

    pub fn petal_has_descendant(&self, mount: &str, path: &str) -> Result<bool, PetalError> {
        validate_runtime_route_path(path)?;
        let index = self.load_petal_route_index(mount)?;
        Ok(index
            .routes
            .iter()
            .any(|route| route_has_descendant(&route.pattern, path)))
    }

    pub fn petal_static_list(
        &self,
        mount: &str,
        path: &str,
    ) -> Result<Vec<crate::DispatchEntry>, PetalError> {
        validate_runtime_route_path(path)?;
        let index = self.load_petal_route_index(mount)?;
        Ok(static_list_entries(&index, path))
    }

    pub fn petal_document(&self, mount: &str, name: &str) -> Result<Vec<u8>, PetalError> {
        if !PETAL_DOCUMENT_NAMES.contains(&name) {
            return Err(PetalError::NotFound(app_path(mount, name)));
        }
        let hash = self.resolve_petal_mount(mount)?;
        let path = self.store.package_path(&hash)?.join("source").join(name);
        match std::fs::read(path) {
            Ok(bytes) => Ok(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(PetalError::NotFound(app_path(mount, name)))
            }
            Err(err) => Err(PetalError::Io(err)),
        }
    }

    pub async fn dispatch_petal_route(
        &self,
        mount: &str,
        mut request: DispatchRequest,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
    ) -> Result<DispatchOutput, PetalError> {
        let matched = self.petal_route(mount, request.op, &request.path)?;
        let route_params = matched.params.clone();
        request.ctx.extend(route_params.clone());
        request
            .ctx
            .push(("bloom.route_id".into(), matched.route.route_id.clone()));

        let wasm = self
            .store
            .read_route_artifact(&matched.hash, &matched.route.route_id)?;
        let declared_sign_intents = self.petal_sign_intents(&matched.hash)?;
        let runtime_metadata = self
            .runtime_petal_route_metadata(
                &matched,
                mount,
                &request.path,
                &wasm,
                &declared_sign_intents,
                &opts,
            )
            .await?;
        enforce_runtime_route_op(request.op, &matched, &runtime_metadata)?;
        let mut caps = runtime_metadata
            .required_caps
            .iter()
            .map(|cap| {
                petal_capability(cap).ok_or_else(|| {
                    PetalError::InvalidWasm(format!(
                        "Petal route {} has unknown required cap {cap:?}",
                        matched.route.route_id
                    ))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if let Some(mask) = cap_mask {
            caps = caps.intersection(&mask).copied().collect();
        }
        let mut opts = opts;
        if opts.private_store_root.is_none() {
            opts.private_store_root = Some(self.store.private_data_root());
        }
        let declared = self
            .petal_net_policy(&matched.hash)?
            .with_endpoint_bindings(&opts.endpoint_bindings)?;
        opts.net_policy = Some(match opts.net_policy {
            Some(mask) => declared.intersect(&mask),
            None => declared,
        });
        opts.sign_intents = Some(route_sign_intents(
            declared_sign_intents,
            runtime_metadata.sign_intent.as_deref(),
            opts.sign_intents,
        ));
        let declared_store_policy = self.petal_store_policy(&matched.hash)?;
        opts.store_namespaces = Some(match opts.store_namespaces {
            Some(mask) => declared_store_policy.intersect(&mask),
            None => declared_store_policy,
        });
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

    async fn runtime_petal_route_metadata(
        &self,
        matched: &PetalRouteMatch,
        mount: &str,
        path: &str,
        wasm: &[u8],
        declared_sign_intents: &BTreeSet<String>,
        opts: &RunOptions,
    ) -> Result<InstallRouteMetadata, PetalError> {
        if matched.route.abi != RouteAbi::ComponentBloomRoute010 || matched.params.is_empty() {
            return Ok(matched.route.install_metadata.clone());
        }
        let key = Self::runtime_metadata_key(matched, path);
        if let Some(metadata) = self.runtime_metadata.lock().get(&key).cloned() {
            return Ok(metadata);
        }
        let metadata = self
            .vm
            .component_route_metadata(
                wasm,
                BTreeSet::new(),
                Arc::new(DenyHost),
                &matched.hash,
                mount,
                path,
                matched.params.clone(),
                opts.clone(),
            )
            .await?;
        let metadata =
            narrow_runtime_route_metadata(&matched.route, &metadata, declared_sign_intents)?;
        self.runtime_metadata.lock().put(key, metadata.clone());
        Ok(metadata)
    }

    fn petal_net_policy(&self, hash: &str) -> Result<NetPolicy, PetalError> {
        let manifest = std::fs::read(self.store.package_path(hash)?.join("source/petal.toml"))?;
        NetPolicy::from_manifest_toml(&manifest)
    }

    fn petal_sign_intents(&self, hash: &str) -> Result<BTreeSet<String>, PetalError> {
        let manifest = std::fs::read(self.store.package_path(hash)?.join("source/petal.toml"))?;
        sign_intents_from_manifest_toml(&manifest)
    }

    fn petal_store_policy(
        &self,
        hash: &str,
    ) -> Result<crate::policy::StoreNamespacePolicy, PetalError> {
        let manifest = std::fs::read(self.store.package_path(hash)?.join("source/petal.toml"))?;
        store_policy_from_manifest_toml(&manifest)
    }
}

/// Match `prefix` against installed hashes: `None` when nothing
/// matches, the full hash when exactly one does, and an error when
/// the prefix is ambiguous.
fn resolve_hash_prefix(
    prefix: &str,
    hashes: impl IntoIterator<Item = String>,
) -> Result<Option<String>, PetalError> {
    let mut matched: Option<String> = None;
    for hash in hashes {
        if !hash.starts_with(prefix) {
            continue;
        }
        if matched.is_some() {
            return Err(PetalError::InvalidHash(format!(
                "{prefix} is ambiguous: matches multiple installed petals"
            )));
        }
        matched = Some(hash);
    }
    Ok(matched)
}

fn route_op(op: DispatchOp) -> RouteOp {
    match op {
        DispatchOp::Lookup => RouteOp::Lookup,
        DispatchOp::List => RouteOp::List,
        DispatchOp::Read => RouteOp::Read,
        DispatchOp::Write => RouteOp::Write,
    }
}

fn enforce_runtime_route_op(
    op: DispatchOp,
    matched: &PetalRouteMatch,
    metadata: &InstallRouteMetadata,
) -> Result<(), PetalError> {
    if op == DispatchOp::Write && metadata.mode & 0o222 == 0 {
        return Err(PetalError::ModeUnsupported(format!(
            "Petal route {} is not writable at runtime",
            matched.route.route_id
        )));
    }
    Ok(())
}

fn match_index_for_op<'a>(
    index: &'a RouteIndex,
    op: DispatchOp,
    path: &str,
) -> Option<crate::package::RouteIndexMatch<'a>> {
    match op {
        DispatchOp::Lookup => index
            .match_route(path)
            .or_else(|| match_special_route(index, path, "$lookup")),
        DispatchOp::List | DispatchOp::Read | DispatchOp::Write => index.match_route(path),
    }
}

fn match_special_route<'a>(
    index: &'a RouteIndex,
    path: &str,
    special: &str,
) -> Option<crate::package::RouteIndexMatch<'a>> {
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
            "invalid Petal runtime route path {path:?}"
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

fn petal_capability(cap: &str) -> Option<Capability> {
    match cap {
        "bloom:http" => Some(Capability::NetFetch),
        "bloom:store" => Some(Capability::Store),
        "bloom:sign" => Some(Capability::Sign),
        "bloom:chain" => Some(Capability::Chain),
        "bloom:tx.outbox" => Some(Capability::TxOutbox),
        "bloom:private-input" => Some(Capability::PrivateInput),
        "bloom:vfs.read" => Some(Capability::VfsRead),
        "bloom:vfs.write" => Some(Capability::VfsWrite),
        _ => Capability::parse(cap),
    }
}

fn route_sign_intents(
    declared_sign_intents: BTreeSet<String>,
    route_sign_intent: Option<&str>,
    runtime_mask: Option<BTreeSet<String>>,
) -> BTreeSet<String> {
    let route_limited = match route_sign_intent {
        Some(intent) if declared_sign_intents.contains(intent) => {
            BTreeSet::from([intent.to_string()])
        }
        Some(_) => BTreeSet::new(),
        None => declared_sign_intents,
    };
    match runtime_mask {
        Some(mask) => route_limited.intersection(&mask).cloned().collect(),
        None => route_limited,
    }
}

fn app_path(mount: &str, path: &str) -> String {
    if path.is_empty() {
        format!("petals/{mount}")
    } else {
        format!("petals/{mount}/{path}")
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
    use crate::abi::DispatchResponse;
    use tempfile::TempDir;

    fn runner() -> (TempDir, PetalRunner) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let vm = PetalVm::new().unwrap();
        (dir, PetalRunner::new(store, reg, vm))
    }

    fn install_echo_app(dir: &TempDir, r: &PetalRunner) -> String {
        let package = dir.path().join("echo-app");
        write_package_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"

[consent]
summary = "Echo values for discovery tests."

[caps]
allowed = ["bloom:vfs.read"]
"#,
        );
        write_package_file(&package, "README.md", b"# echo");
        write_package_file(&package, "AGENTS.md", b"# echo agents");
        write_package_file(
            &package,
            "petal/echo/message.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        let (result, _, _) = r.store().install_petal_package_dir(&package).unwrap();
        result.hash
    }

    #[test]
    fn uninstall_accepts_ls_hash_prefix() {
        let (dir, r) = runner();
        let hash = install_echo_app(&dir, &r);
        assert!(r.uninstall(&hash[..crate::store::HASH_PREFIX_LEN]).unwrap());
        assert!(!r.store().contains_package(&hash));
    }

    #[test]
    fn uninstall_accepts_petal_name() {
        let (dir, r) = runner();
        let hash = install_echo_app(&dir, &r);
        assert!(r.uninstall("echo").unwrap());
        assert!(!r.store().contains_package(&hash));
    }

    #[test]
    fn resolve_accepts_installed_package_hash_and_petal_mount() {
        let (dir, r) = runner();
        let hash = install_echo_app(&dir, &r);

        assert_eq!(r.resolve(&hash).unwrap(), hash);
        assert_eq!(r.resolve("echo").unwrap(), hash);
    }

    #[test]
    fn installed_petal_discovery_reads_retained_manifest_metadata() {
        let (dir, r) = runner();
        install_echo_app(&dir, &r);

        let installed = r.installed_petal_discovery().unwrap();
        assert_eq!(
            installed,
            vec![PetalDiscovery {
                name: "echo".into(),
                summary: Some("Echo values for discovery tests.".into()),
                capabilities: vec!["bloom:vfs.read".into()],
            }]
        );
    }

    #[test]
    fn uninstall_accepts_petname_and_unsets_it() {
        let (dir, r) = runner();
        let hash = install_echo_app(&dir, &r);
        r.registry().set("mypetal", &hash).unwrap();
        assert!(r.uninstall("mypetal").unwrap());
        assert!(!r.store().contains_package(&hash));
        assert!(r.registry().lookup("mypetal").is_none());
    }

    #[test]
    fn uninstall_unknown_target_returns_false() {
        let (_dir, r) = runner();
        assert!(!r.uninstall("nope").unwrap());
        // Hash-prefix shaped, but nothing installed matches it.
        assert!(!r.uninstall("0123456789ab").unwrap());
    }

    #[test]
    fn resolve_hash_prefix_requires_unique_match() {
        let a = format!("{}{}", "ab".repeat(6), "0".repeat(52));
        let b = format!("{}{}", "ab".repeat(6), "1".repeat(52));
        let c = "c".repeat(64);
        assert!(matches!(
            resolve_hash_prefix(&"ab".repeat(6), [a.clone(), b, c.clone()]),
            Err(PetalError::InvalidHash(_))
        ));
        assert_eq!(
            resolve_hash_prefix(&a[..13], [a.clone(), c.clone()]).unwrap(),
            Some(a)
        );
        assert_eq!(resolve_hash_prefix("dddddddddddd", [c]).unwrap(), None);
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
    async fn vfs_host_denies_petals_subtree_to_prevent_petal_recursion() {
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(StaticHandler) as _)
            .build();
        let host = VfsHost::new(Arc::new(vfs));
        assert!(matches!(
            host.vfs_read("petals/demo/file").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_write("petals/demo/file", b"x").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_list("petals/demo").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_list("../wallets").await,
            Err(HostError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn component_petal_routes_use_component_runner() {
        let (dir, r) = runner();
        let package = dir.path().join("component-app");
        write_package_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(&package, "README.md", b"# echo");
        write_package_file(&package, "AGENTS.md", b"# echo agents");
        write_package_file(
            &package,
            "petal/echo/message.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        r.store().install_petal_package_dir(&package).unwrap();

        let out = r
            .dispatch_petal_route(
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
            .unwrap();
        assert_eq!(out.response, DispatchResponse::Read(b"component".to_vec()));
    }

    #[tokio::test]
    async fn dynamic_component_petal_routes_evaluate_runtime_metadata() {
        let (dir, r) = runner();
        let package = dir.path().join("dynamic-component-app");
        write_package_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(&package, "README.md", b"# echo");
        write_package_file(&package, "AGENTS.md", b"# echo agents");
        write_package_file(
            &package,
            "petal/echo/[name].txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        let (_, _, index) = r.store().install_petal_package_dir(&package).unwrap();
        let route = &index.routes[0];
        assert_eq!(route.install_metadata.mode, 0o666);
        assert!(route.install_metadata.side_effecting_read);
        assert!(route.install_metadata.write_async);

        let (_, runtime_metadata) = r
            .petal_route_runtime_metadata(
                "echo",
                DispatchOp::Read,
                "alice.txt",
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(runtime_metadata.mode, 0o444);
        assert!(!runtime_metadata.write_async);

        let out = r
            .dispatch_petal_route(
                "echo",
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "alice.txt".into(),
                    body: Vec::new(),
                    ctx: Vec::new(),
                },
                Arc::new(crate::host::DenyHost),
                None,
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(out.response, DispatchResponse::Read(b"component".to_vec()));
    }

    #[tokio::test]
    async fn dynamic_route_metadata_cannot_require_unimported_cap() {
        let (dir, r) = runner();
        let package = dir.path().join("unimported-cap-app");
        write_package_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "example"

[caps]
allowed = ["bloom:store", "bloom:vfs.read"]

[store]
namespaces = ["wallets"]
"#,
        );
        write_package_file(&package, "README.md", b"# example");
        write_package_file(&package, "AGENTS.md", b"# example agents");
        // The component's runtime metadata claims bloom:vfs.read, but the
        // artifact never imports the vfs interface, so the install-time
        // capability ceiling is bloom:store only.
        write_package_file(
            &package,
            "petal/example/[wallet]/$index.wasm",
            &crate::package::route_fixtures::dynamic_dir_route_component(
                true,
                crate::package::route_fixtures::FixtureVfsImport::None,
                &["bloom:store", "bloom:vfs.read"],
                None,
            ),
        );
        let (_, _, index) = r.store().install_petal_package_dir(&package).unwrap();
        assert_eq!(
            index.routes[0].install_metadata.required_caps,
            vec!["bloom:store".to_string()]
        );

        let err = r
            .petal_route_runtime_metadata(
                "example",
                DispatchOp::Lookup,
                "alice",
                RunOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("requires missing petal.toml cap bloom:vfs.read"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn dynamic_component_runtime_metadata_can_deny_write() {
        let (dir, r) = runner();
        let package = dir.path().join("dynamic-component-write-app");
        write_package_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(&package, "README.md", b"# echo");
        write_package_file(&package, "AGENTS.md", b"# echo agents");
        write_package_file(
            &package,
            "petal/echo/[name].txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        let (_, _, index) = r.store().install_petal_package_dir(&package).unwrap();
        let route = &index.routes[0];
        assert!(route.ops.contains(&RouteOp::Write));
        assert_eq!(route.install_metadata.mode, 0o666);
        assert!(route.install_metadata.write_async);

        let err = r
            .dispatch_petal_route(
                "echo",
                DispatchRequest {
                    op: DispatchOp::Write,
                    path: "alice.txt".into(),
                    body: b"update".to_vec(),
                    ctx: Vec::new(),
                },
                Arc::new(crate::host::DenyHost),
                None,
                RunOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not writable at runtime"));
    }

    fn write_package_file(root: &std::path::Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn petal_capability_maps_chain_to_local_host_capability() {
        assert_eq!(petal_capability("bloom:chain"), Some(Capability::Chain));
        assert_eq!(
            petal_capability("bloom:tx.outbox"),
            Some(Capability::TxOutbox)
        );
    }

    #[test]
    fn petal_route_sign_intent_narrows_manifest_and_runtime_masks() {
        let declared = BTreeSet::from(["safe.intent".to_string(), "wide.intent".to_string()]);
        assert_eq!(
            route_sign_intents(declared.clone(), Some("safe.intent"), None),
            BTreeSet::from(["safe.intent".to_string()])
        );
        assert_eq!(
            route_sign_intents(
                declared.clone(),
                Some("safe.intent"),
                Some(BTreeSet::from(["wide.intent".to_string()]))
            ),
            BTreeSet::new()
        );
        assert_eq!(
            route_sign_intents(declared.clone(), Some("unknown.intent"), None),
            BTreeSet::new()
        );
        assert_eq!(route_sign_intents(declared.clone(), None, None), declared);
    }
}
