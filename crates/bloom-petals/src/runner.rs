//! High-level petal install / run, gluing the store, registry, and VM.
//!
//! The runner is the only place that bridges a [`PetalVm`] to a
//! surrounding [`bloom_vfs::Vfs`] — petals reach VFS paths via the
//! host imports we install on the runner's VM.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use async_trait::async_trait;
use bloom_broker_api::{ProvenanceCatalog, ProvenanceSubject};
use bloom_vfs::handler::HandlerError;
use bloom_vfs::handlers::wallets::AccountPetalContext;
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

fn deny_apps_subtree(path: &VfsPath) -> Result<(), HostError> {
    if path
        .segments()
        .first()
        .is_some_and(|segment| segment == "petals")
    {
        return Err(HostError::Denied(
            "Petal VFS calls cannot enter the Petal subtree".into(),
        ));
    }
    Ok(())
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
    provenance_catalog: Option<Arc<ProvenanceCatalog>>,
    catalog_shape_error: Option<String>,
    prepared_private_stores: Arc<Mutex<HashSet<String>>>,
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
            provenance_catalog: None,
            catalog_shape_error: None,
            prepared_private_stores: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// The caller supplies the installer-owned catalog loaded through the
    /// Machine trust path. Broker independently verifies record signatures.
    pub fn with_provenance_catalog(mut self, catalog: Option<ProvenanceCatalog>) -> Self {
        self.catalog_shape_error = catalog.as_ref().and_then(|catalog| {
            catalog
                .validate_shape()
                .err()
                .map(|error| error.to_string())
        });
        if let Some(error) = &self.catalog_shape_error {
            tracing::warn!(error, "loaded installer provenance catalog is invalid");
        }
        self.provenance_catalog = catalog.map(Arc::new);
        self
    }

    fn ensure_catalog_shape(&self) -> Result<(), PetalError> {
        if let Some(error) = &self.catalog_shape_error {
            return Err(PetalError::vm(format!(
                "loaded installer provenance catalog is invalid: {error}"
            )));
        }
        Ok(())
    }

    fn lineage_record(&self, hash: &str) -> Option<&bloom_broker_api::ProvenanceRecord> {
        self.provenance_catalog.as_ref()?.records.iter().find(|record| {
            matches!(&record.subject, ProvenanceSubject::Petal { package_hash, .. } if package_hash.to_string() == hash)
                && record.petal_lineage.is_some()
        })
    }

    /// Fail a lineage-backed replacement before owner activation when the
    /// executing daemon has not loaded its successor release information.
    pub fn check_activation(&self, hash: &str, name: &str) -> Result<(), PetalError> {
        let Some(outgoing) = self.store.resolve_petal_owner(name)? else {
            return Ok(());
        };
        if outgoing == hash {
            return Ok(());
        }
        // An invalid catalog cannot tell us whether this replacement needs
        // lineage state. Leave the outgoing owner active until it is repaired.
        self.ensure_catalog_shape()?;
        if self.lineage_record(&outgoing).is_some() && self.lineage_record(hash).is_none() {
            return Err(PetalError::vm(format!(
                "Petal {name} successor release information is missing from the loaded installer catalog"
            )));
        }
        if self
            .lineage_record(hash)
            .and_then(|record| record.petal_lineage.as_ref())
            .is_some_and(|lineage| {
                lineage.active
                    && lineage
                        .predecessor_package_hashes
                        .iter()
                        .any(|listed| listed.to_string() == outgoing)
            })
            && self.lineage_record(&outgoing).is_none()
        {
            return Err(PetalError::vm(format!(
                "Petal {name} predecessor release information is missing from the loaded installer catalog"
            )));
        }
        Ok(())
    }

    /// Bundled release pins are lineage-backed upgrades. Their new catalog
    /// membership must be loaded before switching away from an installed pin.
    pub fn check_default_activation(&self, hash: &str, name: &str) -> Result<(), PetalError> {
        let Some(outgoing) = self.store.resolve_petal_owner(name)? else {
            return Ok(());
        };
        if outgoing == hash {
            return Ok(());
        }
        self.ensure_catalog_shape()?;
        let active = self
            .lineage_record(hash)
            .and_then(|record| record.petal_lineage.as_ref())
            .is_some_and(|lineage| lineage.active);
        if !active {
            return Err(PetalError::vm(format!(
                "Bundled Petal {name} successor release information is missing or inactive in the loaded installer catalog"
            )));
        }
        self.check_activation(hash, name)
    }

    fn prepare_private_store(
        &self,
        hash: &str,
        account: Option<&AccountPetalContext>,
    ) -> Result<(), PetalError> {
        let mut prepared = self.prepared_private_stores.lock();
        if prepared.contains(hash) {
            return Ok(());
        }
        let meta = self.store.load_meta(hash)?;
        let Some(predecessor) = meta.replaced.as_deref() else {
            tracing::info!(
                event = "petal_state.not_carried",
                hash,
                reason = "no_replaced_owner"
            );
            prepared.insert(hash.to_string());
            return Ok(());
        };
        // Existing partitions remain usable after a catalog-load failure.
        // A new partition for a replaced package must not be created while
        // its predecessor relationship cannot be checked. Probe the exact
        // partition selected by this invocation, including numbered accounts.
        let partition = match account.filter(|account| account.number > 0) {
            Some(account) => self.store.private_account_data_root().join(hash).join(
                crate::private_store::account_digest(&account.wallet, account.number),
            ),
            None => self.store.private_data_root().join(hash),
        };
        if self.catalog_shape_error.is_some() {
            if partition.is_dir() {
                return Ok(());
            }
            self.ensure_catalog_shape()?;
        }
        if self.lineage_record(predecessor).is_some() && self.lineage_record(hash).is_none() {
            if partition.is_dir() {
                return Ok(());
            }
            return Err(PetalError::vm(format!(
                "Petal successor {hash} release information is missing from the loaded installer catalog"
            )));
        }
        let Some(record) = self.lineage_record(hash) else {
            tracing::info!(
                event = "petal_state.not_carried",
                hash,
                predecessor,
                reason = "no_lineage"
            );
            prepared.insert(hash.to_string());
            return Ok(());
        };
        let lineage = record
            .petal_lineage
            .as_ref()
            .expect("selected lineage record");
        let predecessor_record = self.lineage_record(predecessor);
        let predecessor_listed = lineage
            .predecessor_package_hashes
            .iter()
            .any(|listed| listed.to_string() == predecessor);
        if lineage.active && predecessor_listed && predecessor_record.is_none() {
            if partition.is_dir() {
                return Ok(());
            }
            return Err(PetalError::vm(format!(
                "Petal predecessor {predecessor} release information is missing from the loaded installer catalog"
            )));
        }
        let predecessor_matches = predecessor_record.is_some_and(|previous| {
            previous.publisher == record.publisher
                && previous
                    .petal_lineage
                    .as_ref()
                    .is_some_and(|membership| membership.lineage_id == lineage.lineage_id)
        });
        let authorised = lineage.active && predecessor_matches && predecessor_listed;
        if !authorised {
            let reason = if !lineage.active {
                "inactive_lineage"
            } else if !predecessor_matches {
                "different_lineage"
            } else {
                "unlisted_predecessor"
            };
            tracing::info!(event = "petal_state.not_carried", hash, predecessor, lineage = %lineage.lineage_id, reason);
            prepared.insert(hash.to_string());
            return Ok(());
        }
        let copied = crate::private_store::carry_forward(
            &self.store.private_data_root(),
            &self.store.private_account_data_root(),
            predecessor,
            hash,
        )
        .map_err(|error| {
            PetalError::vm(format!("Petal private-state carry-forward failed: {error}"))
        })?;
        tracing::info!(event = if copied { "petal_state.carried_forward" } else { "petal_state.not_carried" }, hash, predecessor, lineage = %lineage.lineage_id, reason = if copied { "copied" } else { "predecessor_store_absent_or_successor_exists" });
        prepared.insert(hash.to_string());
        Ok(())
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
    ///
    /// Public so a caller holding the mutation lock can name the exact
    /// outgoing package before removing it, which is what the active-session
    /// guard keys on.
    pub fn resolve_uninstall_hash(&self, target: &str) -> Result<Option<String>, PetalError> {
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
        request: DispatchRequest,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
    ) -> Result<DispatchOutput, PetalError> {
        self.dispatch_petal_route_with_trusted_params(
            mount,
            request,
            host,
            cap_mask,
            opts,
            &[],
            None,
        )
        .await
    }

    /// [`Self::dispatch_petal_route`] with host-trusted parameters appended
    /// next to `bloom.route_id`. An account-scoped router
    /// ([`crate::PetalRouter::for_account`]) is the one caller that appends
    /// them: its routes run with the host provenance facts `bloom.wallet`,
    /// `bloom.account` and `bloom.owner_key_fingerprint`, which guest and
    /// host both read. A
    /// caller-supplied context entry whose name starts with `bloom.` is
    /// rejected before the host appends its own values, so no dispatch path
    /// can shadow a trusted one.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_petal_route_with_trusted_params(
        &self,
        mount: &str,
        mut request: DispatchRequest,
        host: Arc<dyn PetalHost>,
        cap_mask: Option<BTreeSet<Capability>>,
        opts: RunOptions,
        trusted_params: &[(String, String)],
        account: Option<&AccountPetalContext>,
    ) -> Result<DispatchOutput, PetalError> {
        if let Some((name, _)) = request
            .ctx
            .iter()
            .find(|(name, _)| name.starts_with("bloom."))
        {
            return Err(PetalError::InvalidWasm(format!(
                "caller context parameter '{name}' uses the reserved bloom. prefix"
            )));
        }
        for (name, _) in trusted_params {
            if !name.starts_with("bloom.") || name == "bloom.route_id" {
                return Err(PetalError::InvalidWasm(format!(
                    "trusted parameter '{name}' is not a host-owned bloom. name"
                )));
            }
        }
        let matched = self.petal_route(mount, request.op, &request.path)?;
        let mut route_params = matched.params.clone();
        // Components need the host-selected route identity to construct
        // claims that the signing host binds back to this exact route. Keep
        // it in the trusted match output rather than accepting it from the
        // caller-supplied request context.
        route_params.push(("bloom.route_id".into(), matched.route.route_id.clone()));
        // The owner fingerprint is chosen for the matched route, not for the
        // whole Petal: a route that derives or signs in exactly one family
        // carries that family's key, and only an unambiguous account may
        // supply one otherwise. A route the account cannot name simply runs
        // without one; the signing seam resolves the owner from the path.
        if let Some(fingerprint) =
            account.and_then(|account| route_owner_fingerprint(&matched.route, account))
        {
            route_params.push((
                "bloom.owner_key_fingerprint".to_owned(),
                fingerprint.to_owned(),
            ));
        }
        route_params.extend(trusted_params.iter().cloned());
        request.ctx.extend(route_params.clone());

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
        if caps.contains(&Capability::Store) && opts.private_store_root.is_none() {
            self.prepare_private_store(&matched.hash, account)?;
        }
        if opts.private_store_root.is_none() {
            if let Some(account) = account.filter(|account| account.number > 0) {
                opts.private_store_root = Some(self.store.private_account_data_root());
                opts.private_store_account = Some((account.wallet.clone(), account.number));
            } else {
                opts.private_store_root = Some(self.store.private_data_root());
            }
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
        opts.key_derive_scope_declared = matched.route.key_derive_scope_declared;
        opts.key_derive_allowed_routes = matched.route.key_derive_allowed_routes.clone();
        opts.key_derive_operation_classes = matched.route.key_derive_operation_classes.clone();
        opts.key_derive_allowed_crypto_suites =
            matched.route.key_derive_allowed_crypto_suites.clone();
        opts.key_derive_maximum_lifetime_ms = matched.route.key_derive_maximum_lifetime_ms;
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

    /// Whether the package installed at `mount` declares
    /// `[account] aware = true` in its manifest.
    pub fn petal_account_aware(&self, mount: &str) -> Result<bool, PetalError> {
        let hash = self.resolve_petal_mount(mount)?;
        let manifest = std::fs::read(self.store.package_path(&hash)?.join("source/petal.toml"))?;
        crate::package::account_aware_from_manifest_toml(&manifest)
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
        "bloom:key.derive" => Some(Capability::KeyDerive),
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

pub(crate) fn route_has_descendant(pattern: &str, path: &str) -> bool {
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

pub(crate) fn static_list_entries(index: &RouteIndex, path: &str) -> Vec<crate::DispatchEntry> {
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

/// The owner fingerprint one route's dispatch carries. The route's
/// key-derive suites name a family when they name exactly one; otherwise
/// only an account with a single family key can supply one, and a route
/// the account cannot name runs without a fingerprint.
fn route_owner_fingerprint<'a>(
    route: &crate::package::RouteIndexRecord,
    account: &'a AccountPetalContext,
) -> Option<&'a str> {
    let (mut evm, mut solana) = (false, false);
    for suite in &route.key_derive_allowed_crypto_suites {
        if suite.starts_with("secp256k1") {
            evm = true;
        } else if suite.starts_with("ed25519") {
            solana = true;
        }
    }
    match (evm, solana) {
        (true, false) => account.evm_fingerprint.as_deref(),
        (false, true) => account.solana_fingerprint.as_deref(),
        _ => match (&account.evm_fingerprint, &account.solana_fingerprint) {
            (Some(fingerprint), None) | (None, Some(fingerprint)) => Some(fingerprint.as_str()),
            _ => None,
        },
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

    #[tokio::test]
    async fn caller_context_never_uses_the_reserved_bloom_prefix() {
        let (_dir, r) = runner();
        let host = Arc::new(RejectingHost);
        let error = r
            .dispatch_petal_route_with_trusted_params(
                "echo",
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "message.txt".into(),
                    body: Vec::new(),
                    ctx: vec![("bloom.wallet".into(), "forged".into())],
                },
                host,
                None,
                RunOptions::default(),
                &[],
                None,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&error, PetalError::InvalidWasm(message) if message.contains("reserved bloom.")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn trusted_params_must_be_host_owned_bloom_names() {
        let (_dir, r) = runner();
        let host = Arc::new(RejectingHost);
        let error = r
            .dispatch_petal_route_with_trusted_params(
                "echo",
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "message.txt".into(),
                    body: Vec::new(),
                    ctx: Vec::new(),
                },
                host,
                None,
                RunOptions::default(),
                &[("wallet".into(), "alice".into())],
                None,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(&error, PetalError::InvalidWasm(message) if message.contains("host-owned")),
            "{error:?}"
        );
    }

    #[test]
    fn installed_manifest_declares_account_awareness() {
        let (dir, r) = runner();
        install_echo_app(&dir, &r);
        assert!(
            !r.petal_account_aware("echo").unwrap(),
            "absence of [account] means unaware"
        );

        let package = dir.path().join("aware-app");
        write_package_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "aware"

[consent]
summary = "Account-aware echo."

[caps]
allowed = ["bloom:vfs.read"]

[account]
aware = true
"#,
        );
        write_package_file(&package, "README.md", b"# aware");
        write_package_file(&package, "AGENTS.md", b"# aware agents");
        write_package_file(
            &package,
            "petal/aware/message.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        let (result, _, _) = r.store().install_petal_package_dir(&package).unwrap();
        assert!(r.petal_account_aware("aware").unwrap());
        assert_eq!(r.resolve("aware").unwrap(), result.hash);
    }
    /// A host the dispatch must never reach in the rejection tests.
    struct RejectingHost;

    #[async_trait::async_trait]
    impl PetalHost for RejectingHost {
        async fn vfs_lookup(&self, _path: &str) -> Result<HostVfsEntry, HostError> {
            Err(HostError::Denied("rejecting host".into()))
        }
        async fn vfs_read(&self, _path: &str) -> Result<Vec<u8>, HostError> {
            Err(HostError::Denied("rejecting host".into()))
        }
        async fn vfs_list(&self, _path: &str) -> Result<Vec<HostVfsEntry>, HostError> {
            Err(HostError::Denied("rejecting host".into()))
        }
        async fn vfs_write(&self, _path: &str, _bytes: &[u8]) -> Result<(), HostError> {
            Err(HostError::Denied("rejecting host".into()))
        }
    }

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

    fn install_echo_successor(dir: &TempDir, r: &PetalRunner) -> String {
        let package = dir.path().join("echo-successor");
        write_package_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[consent]
summary = "Successor."
[caps]
allowed = ["bloom:store"]
[store]
namespaces = ["settings"]
"#,
        );
        write_package_file(&package, "README.md", b"# successor");
        write_package_file(&package, "AGENTS.md", b"# successor agents");
        write_package_file(
            &package,
            "petal/echo/message.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
        r.store()
            .install_petal_package_dir(&package)
            .unwrap()
            .0
            .hash
    }

    fn lineage_record(
        hash: &str,
        lineage: &str,
        publisher: &str,
        active: bool,
        predecessors: &[&str],
    ) -> bloom_broker_api::ProvenanceRecord {
        use bloom_broker_api::{
            Base64UrlBytes, DecimalU64, Digest32, PetalLineageMembership, ProvenanceOperationClass,
            Token,
        };
        bloom_broker_api::ProvenanceRecord {
            subject: ProvenanceSubject::Petal {
                package_hash: Digest32::new(hash.to_owned()).unwrap(),
                route: "message".into(),
            },
            publisher: Token::new(publisher).unwrap(),
            petal_lineage: Some(PetalLineageMembership {
                lineage_id: lineage.into(),
                release_sequence: DecimalU64::new(if active { 2 } else { 1 }),
                predecessor_package_hashes: predecessors
                    .iter()
                    .map(|hash| Digest32::new((*hash).to_owned()).unwrap())
                    .collect(),
                controller_key_id: Token::new("controller").unwrap(),
                controller_signature: Base64UrlBytes::from_bytes(&[1; 64]),
                active,
            }),
            operation_classes: vec![ProvenanceOperationClass {
                operation_class: Token::new("petal.run").unwrap(),
                fee_asset: None,
            }],
            installer_key_id: Token::new("installer").unwrap(),
            installer_signature: Base64UrlBytes::from_bytes(&[2; 64]),
        }
    }

    fn catalog(records: Vec<bloom_broker_api::ProvenanceRecord>) -> ProvenanceCatalog {
        ProvenanceCatalog {
            schema: "bloom.provenance-catalog.1".into(),
            records,
        }
    }

    #[test]
    fn lineage_activation_requires_loaded_successor_record() {
        let (dir, runner) = runner();
        let predecessor = install_echo_app(&dir, &runner);
        let successor = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let lineage = "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let runner = runner.with_provenance_catalog(Some(catalog(vec![lineage_record(
            &predecessor,
            lineage,
            "publisher",
            true,
            &[],
        )])));
        assert!(runner.check_activation(successor, "echo").is_err());
        assert_eq!(
            runner
                .store()
                .resolve_petal_owner("echo")
                .unwrap()
                .as_deref(),
            Some(predecessor.as_str())
        );
        assert!(!runner.store().private_data_root().join(successor).exists());
    }

    #[test]
    fn lineage_activation_requires_loaded_predecessor_proof() {
        let (dir, runner) = runner();
        let predecessor = install_echo_app(&dir, &runner);
        let successor = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let lineage = "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let runner = runner.with_provenance_catalog(Some(catalog(vec![lineage_record(
            successor,
            lineage,
            "publisher",
            true,
            &[predecessor.as_str()],
        )])));
        assert!(runner.check_activation(successor, "echo").is_err());
        assert_eq!(
            runner
                .store()
                .resolve_petal_owner("echo")
                .unwrap()
                .as_deref(),
            Some(predecessor.as_str())
        );
    }

    #[test]
    fn bundled_default_replacement_requires_active_loaded_membership() {
        let (dir, runner) = runner();
        let predecessor = install_echo_app(&dir, &runner);
        let successor = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(runner.check_default_activation(successor, "echo").is_err());
        let lineage = "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let inactive = runner.clone().with_provenance_catalog(Some(catalog(vec![
            lineage_record(&predecessor, lineage, "publisher", false, &[]),
            lineage_record(
                successor,
                lineage,
                "publisher",
                false,
                &[predecessor.as_str()],
            ),
        ])));
        assert!(
            inactive
                .check_default_activation(successor, "echo")
                .is_err()
        );
        let active = runner.with_provenance_catalog(Some(catalog(vec![
            lineage_record(&predecessor, lineage, "publisher", false, &[]),
            lineage_record(
                successor,
                lineage,
                "publisher",
                true,
                &[predecessor.as_str()],
            ),
        ])));
        active.check_default_activation(successor, "echo").unwrap();
    }

    #[test]
    fn loaded_catalog_shape_error_refuses_activation() {
        let (dir, runner) = runner();
        install_echo_app(&dir, &runner);
        let invalid = ProvenanceCatalog {
            schema: "invalid".into(),
            records: vec![],
        };
        let runner = runner.with_provenance_catalog(Some(invalid));
        assert!(
            runner
                .check_activation(
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "echo"
                )
                .is_err()
        );
    }

    #[test]
    fn malformed_catalog_preserves_existing_packages_but_refuses_fresh_replacement_state() {
        let (dir, runner) = runner();
        let predecessor = install_echo_app(&dir, &runner);
        let invalid = ProvenanceCatalog {
            schema: "invalid".into(),
            records: vec![],
        };
        let runner = runner.with_provenance_catalog(Some(invalid));
        runner.check_activation(&predecessor, "echo").unwrap();
        runner.prepare_private_store(&predecessor, None).unwrap();
        let successor = install_echo_successor(&dir, &runner);
        let data =
            crate::private_store::PrivateStore::open(runner.store().private_data_root()).unwrap();
        assert!(runner.prepare_private_store(&successor, None).is_err());
        assert!(!runner.store().private_data_root().join(&successor).exists());
        // A daemon restart can encounter an already-initialized successor.
        // Its usable partition must not be disabled by a later bad catalog.
        data.put(&successor, "settings/value", b"existing", false)
            .unwrap();
        runner.prepare_private_store(&successor, None).unwrap();
        assert_eq!(data.get(&successor, "settings/value").unwrap(), b"existing");
        let account = AccountPetalContext {
            wallet: "wallet-one".into(),
            number: 1,
            evm_fingerprint: None,
            solana_fingerprint: None,
            freshness: serde_json::from_str("\"fresh\"").unwrap(),
        };
        assert!(
            runner
                .prepare_private_store(&successor, Some(&account))
                .is_err()
        );
        let account_data = crate::private_store::PrivateStore::open_account(
            runner.store().private_account_data_root(),
            &account.wallet,
            account.number,
        )
        .unwrap();
        account_data
            .put(&successor, "settings/value", b"account-existing", false)
            .unwrap();
        runner
            .prepare_private_store(&successor, Some(&account))
            .unwrap();
        assert_eq!(
            account_data.get(&successor, "settings/value").unwrap(),
            b"account-existing"
        );
    }

    #[test]
    fn missing_successor_release_refuses_fresh_store_even_after_activation_bypass() {
        let (dir, runner) = runner();
        let predecessor = install_echo_app(&dir, &runner);
        let successor = install_echo_successor(&dir, &runner);
        let lineage = "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let runner = runner.with_provenance_catalog(Some(catalog(vec![lineage_record(
            &predecessor,
            lineage,
            "publisher",
            false,
            &[],
        )])));
        assert!(runner.prepare_private_store(&successor, None).is_err());
        assert!(!runner.store().private_data_root().join(&successor).exists());
    }

    #[test]
    fn lineage_carry_forward_requires_same_lineage_and_predecessor_membership() {
        let lineage = "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other_lineage = "pln1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        for (case, previous_record, next_lineage, active, listed, should_copy) in [
            ("authorised", true, lineage, true, true, true),
            ("inactive", true, lineage, false, true, false),
            ("unlisted", true, lineage, true, false, false),
            ("foreign", true, other_lineage, true, true, false),
            ("missing_previous_proof", false, lineage, true, true, false),
        ] {
            let (dir, runner) = runner();
            let predecessor = install_echo_app(&dir, &runner);
            let data = crate::private_store::PrivateStore::open(runner.store().private_data_root())
                .unwrap();
            data.put(&predecessor, "settings/value", b"old", false)
                .unwrap();
            let successor = install_echo_successor(&dir, &runner);
            let mut records = Vec::new();
            if previous_record {
                records.push(lineage_record(
                    &predecessor,
                    lineage,
                    "publisher",
                    false,
                    &[],
                ));
            }
            let predecessors = if listed {
                vec![predecessor.as_str()]
            } else {
                vec![]
            };
            records.push(lineage_record(
                &successor,
                next_lineage,
                "publisher",
                active,
                &predecessors,
            ));
            let runner = runner.with_provenance_catalog(Some(catalog(records)));
            if case == "missing_previous_proof" {
                assert!(runner.prepare_private_store(&successor, None).is_err());
                assert!(!runner.store().private_data_root().join(&successor).exists());
                assert_eq!(data.get(&predecessor, "settings/value").unwrap(), b"old");
                continue;
            }
            runner.prepare_private_store(&successor, None).unwrap();
            assert_eq!(
                runner.store().private_data_root().join(&successor).exists(),
                should_copy,
                "{case}"
            );
            if should_copy {
                assert_eq!(data.get(&successor, "settings/value").unwrap(), b"old");
                data.put(&successor, "settings/value", b"new", false)
                    .unwrap();
                runner.prepare_private_store(&successor, None).unwrap();
                assert_eq!(
                    data.get(&successor, "settings/value").unwrap(),
                    b"new",
                    "{case} repeated use"
                );
            }
            assert_eq!(
                data.get(&predecessor, "settings/value").unwrap(),
                b"old",
                "{case} predecessor unchanged"
            );
        }
    }

    #[test]
    fn local_package_without_lineage_keeps_empty_successor_store() {
        let (dir, runner) = runner();
        let predecessor = install_echo_app(&dir, &runner);
        let successor = install_echo_successor(&dir, &runner);
        let runner = runner.with_provenance_catalog(Some(catalog(vec![lineage_record(
            &"a".repeat(64),
            "pln1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "other-publisher",
            true,
            &[],
        )])));
        runner.check_activation(&successor, "echo").unwrap();
        runner.prepare_private_store(&successor, None).unwrap();
        assert_eq!(
            runner
                .store()
                .load_meta(&successor)
                .unwrap()
                .replaced
                .as_deref(),
            Some(predecessor.as_str())
        );
        assert!(!runner.store().private_data_root().join(successor).exists());
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

    struct StaticHandler(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait::async_trait]
    impl Handler for StaticHandler {
        async fn lookup(&self, path: &VfsPath) -> Result<bloom_vfs::Entry, HandlerError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if path.is_root() {
                Ok(bloom_vfs::Entry::dir(""))
            } else {
                Ok(bloom_vfs::Entry::read_only_file("x"))
            }
        }

        async fn read(&self, _path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(b"reachable".to_vec())
        }

        async fn list(&self, _path: &VfsPath) -> Result<Vec<bloom_vfs::Entry>, HandlerError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![])
        }

        async fn write(&self, _path: &VfsPath, _data: &[u8]) -> Result<(), HandlerError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn vfs_host_denies_normalized_petal_subtree_before_dispatch() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(StaticHandler(calls.clone())) as _)
            .mount("wallets", Arc::new(StaticHandler(calls.clone())) as _)
            .build();
        let host = VfsHost::new(Arc::new(vfs));
        assert!(matches!(
            host.vfs_lookup("/./petals/demo/wallets/w/1/file").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_read("wallets/../petals/demo/wallets/w/1/file")
                .await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_list("petals/demo").await,
            Err(HostError::Denied(_))
        ));
        assert!(matches!(
            host.vfs_write("petals/demo/file", b"x").await,
            Err(HostError::Denied(_))
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "denial must happen before VFS dispatch"
        );
        assert_eq!(
            host.vfs_read("petals/../wallets/w/1/account.json")
                .await
                .unwrap(),
            b"reachable"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
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
