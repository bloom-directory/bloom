//! Experimental v2 file-driven local app package scanner.
//!
//! This is intentionally incremental: it scans `app/<name>/.../*.wasm`
//! route trees and prepares content-addressed package records. Route
//! artifacts must be `bloom:route@0.1.0` components.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use wasm_compose::{
    composer::ComponentComposer,
    config::{Config as ComposeConfig, Dependency as ComposeDependency},
};
use wasmparser::{
    CanonicalFunction, ComponentAlias, ComponentDefinedType, ComponentExternalKind,
    ComponentFuncResult, ComponentFuncType, ComponentOuterAliasKind, ComponentType,
    ComponentTypeRef as WasmComponentTypeRef, ComponentValType, InstanceTypeDeclaration, Parser,
    Payload, PrimitiveValType as ComponentPrimitiveValType, TypeBounds as WasmComponentTypeBounds,
    Validator,
};

use crate::error::PetalError;
use crate::host::DenyHost;
use crate::policy::StoreNamespacePolicy;
use crate::vm::{ComponentRouteEntryKind, ComponentRouteMetadata, PetalVm, RunOptions};

pub const ROUTE_INDEX_SCHEMA: &str = "bloom.petal.route-index.v1";
pub const BUILD_MANIFEST_SCHEMA: &str = "bloom.petal.build-manifest.v1";
const PACKAGE_DIGEST_PREFIX: &[u8] = b"bloom.petal.package.v2\0";
const TAR_NAME_LEN: usize = 100;
const TAR_PREFIX_LEN: usize = 155;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalAppPackage {
    pub name: String,
    pub app_root: String,
    pub routes: Vec<RouteRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
    pub route_id: String,
    pub pattern: String,
    pub source_path: PathBuf,
    pub params: Vec<String>,
    pub specificity: RouteSpecificity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RouteSpecificity {
    pub segment_count: usize,
    pub static_segment_count: usize,
    pub file_score: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch<'a> {
    pub route: &'a RouteRecord,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteIndexMatch<'a> {
    pub route: &'a RouteIndexRecord,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Deserialize)]
struct PetalToml {
    #[serde(default)]
    schema: Option<String>,
    name: String,
    #[serde(default)]
    consent: ConsentPolicy,
    #[serde(default)]
    caps: PetalCaps,
    #[serde(default)]
    net: NetPolicyToml,
    #[serde(default)]
    sign: SignPolicy,
    #[serde(default)]
    store: StorePolicyToml,
}

#[derive(Debug, Default, Deserialize)]
struct ConsentPolicy {
    #[serde(default)]
    summary: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PetalCaps {
    #[serde(default)]
    allowed: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NetPolicyToml {
    #[serde(default)]
    allow: Vec<NetAllowToml>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct NetAllowToml {
    host: String,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SignPolicy {
    #[serde(default)]
    allowed_intents: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct StorePolicyToml {
    #[serde(default)]
    namespaces: Vec<String>,
    #[serde(default)]
    secret_namespaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteValidation {
    abi: RouteAbi,
    required_caps: Vec<String>,
    has_write_export: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPackageFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAppPackage {
    pub hash: String,
    pub name: String,
    pub files: Vec<NormalizedPackageFile>,
    pub route_index: RouteIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildManifest {
    pub schema: String,
    pub source_package_hash: String,
    pub routes: Vec<BuildManifestRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildManifestRoute {
    pub route_id: String,
    pub pattern: String,
    pub source_path: String,
    pub source_hash: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub abi: RouteAbi,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteSidecarToml {
    abi: RouteSidecarAbi,
    component: String,
    #[serde(default)]
    imports: Vec<String>,
    #[serde(default)]
    ops: Vec<RouteOp>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RouteSidecarAbi {
    Component,
}

impl RouteSidecarAbi {
    fn route_abi(self) -> RouteAbi {
        match self {
            RouteSidecarAbi::Component => RouteAbi::ComponentBloomRoute010,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteSidecar {
    path: String,
    app_name: String,
    abi: RouteSidecarAbi,
    component: String,
    imports: Vec<String>,
    ops: Vec<RouteOp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConsentSummary {
    pub name: String,
    pub app_mount: String,
    pub package_summary: Option<String>,
    pub docs: Vec<String>,
    pub capabilities: Vec<String>,
    pub network: Vec<AppConsentNetRule>,
    pub sign_intents: Vec<String>,
    pub store_namespaces: Vec<AppConsentStoreNamespace>,
    pub routes: Vec<AppConsentRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConsentNetRule {
    pub host: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConsentStoreNamespace {
    pub namespace: String,
    pub secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConsentRoute {
    pub path: String,
    pub kind: RouteEntryKind,
    pub ops: Vec<RouteOp>,
    pub required_caps: Vec<String>,
    pub cache_ttl_ms: Option<u64>,
    pub side_effecting_read: bool,
    pub write_async: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteIndex {
    pub schema: String,
    pub package_hash: String,
    pub name: String,
    pub app_root: String,
    pub policy_hash: String,
    pub routes: Vec<RouteIndexRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteIndexRecord {
    pub route_id: String,
    pub pattern: String,
    pub source_path: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub abi: RouteAbi,
    pub kind: RouteEntryKind,
    pub ops: Vec<RouteOp>,
    pub params: Vec<String>,
    pub specificity: [usize; 3],
    pub install_metadata: InstallRouteMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteAbi {
    #[serde(rename = "component:bloom:route@0.1.0")]
    ComponentBloomRoute010,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteEntryKind {
    Dir,
    File,
    Symlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteOp {
    Lookup,
    List,
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallRouteMetadata {
    pub mode: u32,
    pub cache_ttl_ms: Option<u64>,
    pub side_effecting_read: bool,
    pub write_async: bool,
    pub executable: bool,
    pub required_caps: Vec<String>,
    pub sign_intent: Option<String>,
}

impl RouteSpecificity {
    pub fn as_array(self) -> [usize; 3] {
        [
            self.segment_count,
            self.static_segment_count,
            self.file_score,
        ]
    }
}

impl PetalAppPackage {
    pub fn scan_dir(root: impl AsRef<Path>) -> Result<Self, PetalError> {
        let root = root.as_ref();
        require_file(root.join("petal.toml"))?;
        require_file(root.join("README.md"))?;
        require_file(root.join("AGENTS.md"))?;

        let petal_toml = std::fs::read_to_string(root.join("petal.toml"))?;
        let manifest: PetalToml = toml::from_str(&petal_toml)?;
        validate_app_name(&manifest.name)?;

        let app_root = root.join("app").join(&manifest.name);
        if !app_root.is_dir() {
            return Err(PetalError::InvalidWasm(format!(
                "v2 package missing app/{}/ route root",
                manifest.name
            )));
        }

        let mut routes = Vec::new();
        scan_routes(&app_root, &app_root, &mut routes)?;
        routes.sort_by(|a, b| a.pattern.cmp(&b.pattern));
        for (idx, route) in routes.iter_mut().enumerate() {
            route.route_id = format!("r{:06}", idx + 1);
        }
        validate_route_conflicts(&routes)?;

        Ok(Self {
            name: manifest.name.clone(),
            app_root: manifest.name,
            routes,
        })
    }

    pub fn match_route(&self, path: &str) -> Option<RouteMatch<'_>> {
        let path = normalize_request_path(path)?;
        let mut best: Option<RouteMatch<'_>> = None;
        for route in &self.routes {
            let Some(params) = match_pattern(&route.pattern, path) else {
                continue;
            };
            let candidate = RouteMatch { route, params };
            if best
                .as_ref()
                .map(|best| route.specificity > best.route.specificity)
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }
        best
    }
}

impl PreparedAppPackage {
    pub fn from_dir(root: impl AsRef<Path>) -> Result<Self, PetalError> {
        Self::from_files(collect_package_dir(root.as_ref())?)
    }

    pub fn from_petal_tar(path: impl AsRef<Path>) -> Result<Self, PetalError> {
        Self::from_reader(std::fs::File::open(path)?)
    }

    pub fn from_reader(reader: impl Read) -> Result<Self, PetalError> {
        Self::from_files(read_package_tar(reader)?)
    }

    pub fn from_files(files: Vec<NormalizedPackageFile>) -> Result<Self, PetalError> {
        let files = normalize_files(files)?;
        let hash = package_hash(&files);
        let manifest_bytes = file_bytes(&files, "petal.toml")?;
        let manifest_toml = std::str::from_utf8(manifest_bytes)
            .map_err(|_| PetalError::InvalidWasm("petal.toml is not utf-8".into()))?;
        let manifest: PetalToml = toml::from_str(manifest_toml)?;
        if manifest.schema.as_deref() != Some("bloom.petal.local-app.v2") {
            return Err(PetalError::InvalidWasm(
                "v2 package petal.toml must set schema = \"bloom.petal.local-app.v2\"".into(),
            ));
        }
        validate_app_name(&manifest.name)?;
        file_bytes(&files, "README.md")?;
        file_bytes(&files, "AGENTS.md")?;
        let app_root = format!("app/{}", manifest.name);
        validate_single_app_root(&files, &manifest.name)?;
        let allowed_caps = manifest
            .caps
            .allowed
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let allowed_sign_intents = manifest
            .sign
            .allowed_intents
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        validate_sign_policy(&allowed_caps, &allowed_sign_intents)?;
        let store_policy = store_policy_from_manifest(&manifest);
        validate_store_policy(&allowed_caps, &store_policy)?;
        let route_files = route_records_from_files(&files, &app_root)?;
        if route_files.is_empty() {
            return Err(PetalError::InvalidWasm(format!(
                "v2 package app/{}/ contains no .wasm routes",
                manifest.name
            )));
        }
        let policy_hash = hex::encode(blake3::hash(manifest_bytes).as_bytes());
        let mut route_index = RouteIndex {
            schema: ROUTE_INDEX_SCHEMA.to_string(),
            package_hash: hash.clone(),
            name: manifest.name.clone(),
            app_root: manifest.name.clone(),
            policy_hash,
            routes: Vec::with_capacity(route_files.len()),
        };
        for route in route_files {
            let source_path = route.source_path.to_string_lossy().replace('\\', "/");
            let source_bytes = file_bytes(&files, &source_path)?;
            let artifact_path = format!("artifacts/routes/{}.wasm", route.route_id);
            let artifact_bytes = route_artifact_bytes_from_files(
                &files,
                &manifest.name,
                &route.route_id,
                &source_path,
                &artifact_path,
            )?;
            let sidecar = route_sidecar(&files, &manifest.name, &source_path)?;
            let validation = if let Some(sidecar) = &sidecar {
                let package_imports = sidecar_package_import_names(sidecar, &route.route_id)?;
                let source_validation = validate_route_wasm_with_package_imports(
                    &source_path,
                    source_bytes,
                    &allowed_caps,
                    &allowed_sign_intents,
                    &package_imports,
                )?;
                if source_validation.abi != sidecar.abi.route_abi() {
                    return Err(PetalError::InvalidWasm(format!(
                        "v2 route sidecar {} declares {:?} but source route validates as {:?}",
                        sidecar.path, sidecar.abi, source_validation.abi
                    )));
                }
                let sidecar_source_validation = validate_route_wasm_with_package_imports(
                    &sidecar.component,
                    file_bytes(&files, &sidecar.component)?,
                    &allowed_caps,
                    &allowed_sign_intents,
                    &package_imports,
                )?;
                if sidecar_source_validation.abi != source_validation.abi {
                    return Err(PetalError::InvalidWasm(format!(
                        "v2 route sidecar {} component ABI does not match source route",
                        sidecar.path
                    )));
                }
                let artifact_validation = validate_composed_route_artifact_wasm(
                    &artifact_path,
                    &artifact_bytes,
                    &allowed_caps,
                    &allowed_sign_intents,
                )?;
                if artifact_validation.abi != source_validation.abi {
                    return Err(PetalError::InvalidWasm(format!(
                        "v2 package artifact {} ABI does not match source route",
                        route.route_id
                    )));
                }
                artifact_validation
            } else {
                let source_validation = validate_route_wasm(
                    &source_path,
                    source_bytes,
                    &allowed_caps,
                    &allowed_sign_intents,
                )?;
                if optional_file_bytes(&files, &artifact_path).is_some() {
                    let artifact_validation = validate_route_wasm(
                        &artifact_path,
                        &artifact_bytes,
                        &allowed_caps,
                        &allowed_sign_intents,
                    )?;
                    if artifact_validation != source_validation {
                        return Err(PetalError::InvalidWasm(format!(
                            "v2 package artifact {} ABI/caps do not match source route",
                            route.route_id
                        )));
                    }
                }
                source_validation
            };
            let (kind, mut ops) = route_kind_and_ops(&source_path);
            if let Some(sidecar) = &sidecar
                && !sidecar.ops.is_empty()
            {
                ops = sidecar.ops.clone();
            }
            let mut install_metadata = install_metadata_for_route(
                &hash,
                &manifest.name,
                &route,
                kind,
                &validation,
                &artifact_bytes,
                &allowed_caps,
                &allowed_sign_intents,
            )?;
            if kind == RouteEntryKind::File && ops.contains(&RouteOp::Write) {
                install_metadata.mode |= 0o222;
            }
            if kind == RouteEntryKind::File
                && install_metadata.mode & 0o222 != 0
                && !ops.contains(&RouteOp::Write)
            {
                ops.push(RouteOp::Write);
            }
            route_index.routes.push(RouteIndexRecord {
                route_id: route.route_id,
                pattern: route.pattern,
                source_path,
                artifact_path,
                artifact_hash: hex::encode(blake3::hash(&artifact_bytes).as_bytes()),
                abi: validation.abi,
                kind,
                ops,
                params: route.params,
                specificity: route.specificity.as_array(),
                install_metadata,
            });
        }

        Ok(Self {
            hash,
            name: manifest.name,
            files,
            route_index,
        })
    }

    pub fn write_petal_tar(&self, writer: impl Write) -> Result<(), PetalError> {
        verify_prepared_package(self)?;
        write_package_tar(&self.files, writer)
    }
}

#[allow(clippy::too_many_arguments)]
fn install_metadata_for_route(
    package_hash: &str,
    app_root: &str,
    route: &RouteRecord,
    route_kind: RouteEntryKind,
    validation: &RouteValidation,
    artifact_bytes: &[u8],
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<InstallRouteMetadata, PetalError> {
    let mut metadata = InstallRouteMetadata {
        mode: if validation.abi == RouteAbi::ComponentBloomRoute010 && validation.has_write_export {
            0o666
        } else {
            0o444
        },
        cache_ttl_ms: None,
        side_effecting_read: validation.abi == RouteAbi::ComponentBloomRoute010
            && !route.params.is_empty(),
        write_async: validation.abi == RouteAbi::ComponentBloomRoute010
            && validation.has_write_export
            && !route.params.is_empty(),
        executable: false,
        required_caps: validation.required_caps.clone(),
        sign_intent: None,
    };

    if validation.abi != RouteAbi::ComponentBloomRoute010 || !route.params.is_empty() {
        return Ok(metadata);
    }
    let component_metadata =
        evaluate_static_component_metadata(package_hash, app_root, route, artifact_bytes)?;
    validate_component_metadata_policy(
        &route.route_id,
        route_kind,
        &component_metadata,
        &validation.required_caps,
        allowed_caps,
        allowed_sign_intents,
    )?;
    metadata.mode = component_metadata.mode;
    metadata.cache_ttl_ms = component_metadata.cache_ttl_ms;
    metadata.side_effecting_read = component_metadata.side_effecting_read;
    metadata.write_async = component_metadata.write_async;
    metadata.executable = component_metadata.executable;
    metadata.required_caps = component_metadata.required_caps;
    metadata.sign_intent = component_metadata.sign_intent;
    Ok(metadata)
}

pub fn narrow_runtime_route_metadata(
    route: &RouteIndexRecord,
    metadata: &ComponentRouteMetadata,
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<InstallRouteMetadata, PetalError> {
    let install = &route.install_metadata;
    let install_caps = install
        .required_caps
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    validate_component_metadata_policy(
        &route.route_id,
        route.kind,
        metadata,
        &install.required_caps,
        &install_caps,
        allowed_sign_intents,
    )?;
    if metadata.mode & !install.mode != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route {} runtime metadata mode widens install-time mode",
            route.route_id
        )));
    }
    if !install.side_effecting_read && metadata.side_effecting_read {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route {} runtime metadata widens side-effecting-read",
            route.route_id
        )));
    }
    if !install.write_async && metadata.write_async {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route {} runtime metadata widens write-async",
            route.route_id
        )));
    }
    match (install.cache_ttl_ms, metadata.cache_ttl_ms) {
        (None, Some(_)) => {
            return Err(PetalError::InvalidWasm(format!(
                "v2 route {} runtime metadata widens cacheability",
                route.route_id
            )));
        }
        (Some(max), Some(ttl)) if ttl > max => {
            return Err(PetalError::InvalidWasm(format!(
                "v2 route {} runtime metadata widens cache ttl",
                route.route_id
            )));
        }
        _ => {}
    }
    if let Some(install_intent) = &install.sign_intent
        && metadata.sign_intent.as_ref() != Some(install_intent)
    {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route {} runtime metadata widens sign intent",
            route.route_id
        )));
    }
    Ok(InstallRouteMetadata {
        mode: metadata.mode,
        cache_ttl_ms: metadata.cache_ttl_ms,
        side_effecting_read: metadata.side_effecting_read,
        write_async: metadata.write_async,
        executable: metadata.executable,
        required_caps: metadata.required_caps.clone(),
        sign_intent: metadata.sign_intent.clone(),
    })
}

fn evaluate_static_component_metadata(
    package_hash: &str,
    app_root: &str,
    route: &RouteRecord,
    artifact_bytes: &[u8],
) -> Result<ComponentRouteMetadata, PetalError> {
    let wasm = artifact_bytes.to_vec();
    let package_hash = package_hash.to_string();
    let app_root = app_root.to_string();
    let path = route.pattern.clone();
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(PetalError::Io)?;
        runtime.block_on(async move {
            PetalVm::new()?
                .component_route_metadata(
                    &wasm,
                    BTreeSet::new(),
                    Arc::new(DenyHost),
                    &package_hash,
                    &app_root,
                    &path,
                    Vec::new(),
                    RunOptions {
                        deterministic_env: true,
                        ..RunOptions::default()
                    },
                )
                .await
        })
    });
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(PetalError::vm(
            "component route metadata evaluator panicked",
        )),
    }
}

fn validate_component_metadata_policy(
    route_id: &str,
    route_kind: RouteEntryKind,
    metadata: &ComponentRouteMetadata,
    import_required_caps: &[String],
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<(), PetalError> {
    let metadata_kind = match metadata.kind {
        ComponentRouteEntryKind::Dir => RouteEntryKind::Dir,
        ComponentRouteEntryKind::File => RouteEntryKind::File,
        ComponentRouteEntryKind::Symlink => RouteEntryKind::Symlink,
    };
    if metadata_kind != route_kind {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route {route_id} metadata kind {:?} does not match route kind {:?}",
            metadata_kind, route_kind
        )));
    }
    if metadata.executable {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route {route_id} metadata executable=true is not supported"
        )));
    }
    if metadata.mode & !0o777 != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route {route_id} metadata mode must be a unix permission mode"
        )));
    }
    let import_caps = import_required_caps.iter().collect::<BTreeSet<_>>();
    for cap in &metadata.required_caps {
        if !allowed_caps.contains(cap) {
            return Err(PetalError::InvalidWasm(format!(
                "v2 route {route_id} metadata requires missing petal.toml cap {cap}"
            )));
        }
        if !import_caps.contains(cap) {
            return Err(PetalError::InvalidWasm(format!(
                "v2 route {route_id} metadata required cap {cap} was not declared by route imports"
            )));
        }
    }
    if let Some(intent) = &metadata.sign_intent {
        if !metadata.required_caps.iter().any(|cap| cap == "bloom:sign") {
            return Err(PetalError::InvalidWasm(format!(
                "v2 route {route_id} metadata sign_intent requires bloom:sign"
            )));
        }
        if !allowed_sign_intents.contains(intent) {
            return Err(PetalError::InvalidWasm(format!(
                "v2 route {route_id} metadata sign_intent {intent:?} is not allowed"
            )));
        }
        validate_sign_intent(intent)?;
    }
    Ok(())
}

pub fn sign_intents_from_v2_manifest_toml(bytes: &[u8]) -> Result<BTreeSet<String>, PetalError> {
    let manifest_toml = std::str::from_utf8(bytes)
        .map_err(|_| PetalError::InvalidWasm("petal.toml is not utf-8".into()))?;
    let manifest: PetalToml = toml::from_str(manifest_toml)?;
    let allowed_caps = manifest
        .caps
        .allowed
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let allowed_sign_intents = manifest
        .sign
        .allowed_intents
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    validate_sign_policy(&allowed_caps, &allowed_sign_intents)?;
    Ok(allowed_sign_intents)
}

pub fn store_policy_from_v2_manifest_toml(
    bytes: &[u8],
) -> Result<StoreNamespacePolicy, PetalError> {
    let manifest_toml = std::str::from_utf8(bytes)
        .map_err(|_| PetalError::InvalidWasm("petal.toml is not utf-8".into()))?;
    let manifest: PetalToml = toml::from_str(manifest_toml)?;
    let allowed_caps = manifest
        .caps
        .allowed
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let policy = store_policy_from_manifest(&manifest);
    validate_store_policy(&allowed_caps, &policy)?;
    Ok(policy)
}

pub fn build_app_package_dir(root: impl AsRef<Path>) -> Result<PreparedAppPackage, PetalError> {
    let root = root.as_ref();
    PetalAppPackage::scan_dir(root)?;
    validate_generated_artifact_paths(root)?;
    remove_generated_artifacts(root)?;
    let source_package = PreparedAppPackage::from_dir(root)?;
    let manifest = build_manifest_for_package(&source_package)?;

    for route in &source_package.route_index.routes {
        let artifact = route_artifact_bytes(&source_package, route)?;
        write_package_file(root, &route.artifact_path, &artifact)?;
    }
    write_package_file(
        root,
        "artifacts/build-manifest.json",
        &serde_json::to_vec_pretty(&manifest)?,
    )?;

    PreparedAppPackage::from_dir(root)
}

pub fn app_consent_summary(package: &PreparedAppPackage) -> Result<AppConsentSummary, PetalError> {
    let manifest_bytes = file_bytes(&package.files, "petal.toml")?;
    let manifest_toml = std::str::from_utf8(manifest_bytes)
        .map_err(|_| PetalError::InvalidWasm("petal.toml is not utf-8".into()))?;
    let manifest: PetalToml = toml::from_str(manifest_toml)?;
    let mut capabilities = manifest.caps.allowed.clone();
    capabilities.sort();
    capabilities.dedup();

    let mut sign_intents = manifest.sign.allowed_intents.clone();
    sign_intents.sort();
    sign_intents.dedup();

    let secret_namespaces = manifest
        .store
        .secret_namespaces
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut store_namespace_names = manifest.store.namespaces.clone();
    store_namespace_names.extend(secret_namespaces.iter().cloned());
    store_namespace_names.sort();
    store_namespace_names.dedup();
    let store_namespaces = store_namespace_names
        .into_iter()
        .map(|namespace| AppConsentStoreNamespace {
            secret: secret_namespaces.contains(&namespace),
            namespace,
        })
        .collect();

    let network = manifest
        .net
        .allow
        .into_iter()
        .map(|rule| AppConsentNetRule {
            host: rule.host,
            methods: rule
                .methods
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect(),
            paths: if rule.paths.is_empty() {
                vec!["/*".to_string()]
            } else {
                rule.paths
            },
        })
        .collect();

    let routes = package
        .route_index
        .routes
        .iter()
        .map(|route| AppConsentRoute {
            path: if route.pattern.is_empty() {
                format!("/apps/{}", package.name)
            } else {
                format!("/apps/{}/{}", package.name, route.pattern)
            },
            kind: route.kind,
            ops: route.ops.clone(),
            required_caps: route.install_metadata.required_caps.clone(),
            cache_ttl_ms: route.install_metadata.cache_ttl_ms,
            side_effecting_read: route.install_metadata.side_effecting_read,
            write_async: route.install_metadata.write_async,
        })
        .collect();

    Ok(AppConsentSummary {
        name: package.name.clone(),
        app_mount: format!("apps/{}/", package.name),
        package_summary: manifest.consent.summary,
        docs: vec!["README.md".into(), "AGENTS.md".into()],
        capabilities,
        network,
        sign_intents,
        store_namespaces,
        routes,
    })
}

fn build_manifest_for_package(package: &PreparedAppPackage) -> Result<BuildManifest, PetalError> {
    let mut routes = Vec::with_capacity(package.route_index.routes.len());
    for route in &package.route_index.routes {
        let source = package
            .files
            .iter()
            .find(|file| file.path == route.source_path)
            .ok_or_else(|| {
                PetalError::InvalidWasm(format!(
                    "route index source missing from package: {}",
                    route.source_path
                ))
            })?;
        let artifact = route_artifact_bytes(package, route)?;
        let source_hash = hex::encode(blake3::hash(&source.bytes).as_bytes());
        let artifact_hash = hex::encode(blake3::hash(&artifact).as_bytes());
        routes.push(BuildManifestRoute {
            route_id: route.route_id.clone(),
            pattern: route.pattern.clone(),
            source_path: route.source_path.clone(),
            source_hash,
            artifact_path: route.artifact_path.clone(),
            artifact_hash,
            abi: route.abi,
        });
    }
    Ok(BuildManifest {
        schema: BUILD_MANIFEST_SCHEMA.to_string(),
        source_package_hash: package.hash.clone(),
        routes,
    })
}

pub(crate) fn route_artifact_bytes(
    package: &PreparedAppPackage,
    route: &RouteIndexRecord,
) -> Result<Vec<u8>, PetalError> {
    route_artifact_bytes_from_files(
        &package.files,
        &package.name,
        &route.route_id,
        &route.source_path,
        &route.artifact_path,
    )
}

fn route_artifact_bytes_from_files(
    files: &[NormalizedPackageFile],
    app_name: &str,
    route_id: &str,
    source_path: &str,
    artifact_path: &str,
) -> Result<Vec<u8>, PetalError> {
    let sidecar = route_sidecar(files, app_name, source_path)?;
    let generated_artifact = optional_file_bytes(files, artifact_path);
    let expected = if let Some(sidecar) = sidecar {
        let expected = route_sidecar_artifact(files, route_id, &sidecar)?;
        if let Some(artifact) = generated_artifact {
            if blake3::hash(artifact) != blake3::hash(&expected) {
                return Err(PetalError::InvalidWasm(format!(
                    "v2 package artifact {route_id} does not match route sidecar composition"
                )));
            }
            return Ok(artifact.to_vec());
        }
        expected
    } else {
        file_bytes(files, source_path)?.to_vec()
    };
    Ok(generated_artifact
        .map(|artifact| artifact.to_vec())
        .unwrap_or(expected))
}

fn route_sidecar_artifact(
    files: &[NormalizedPackageFile],
    route_id: &str,
    sidecar: &RouteSidecar,
) -> Result<Vec<u8>, PetalError> {
    let component = file_bytes(files, &sidecar.component)?.to_vec();
    if sidecar.imports.is_empty() {
        return Ok(component);
    }
    compose_route_component(files, route_id, sidecar)
}

fn compose_route_component(
    files: &[NormalizedPackageFile],
    route_id: &str,
    sidecar: &RouteSidecar,
) -> Result<Vec<u8>, PetalError> {
    let tmp = tempfile::tempdir().map_err(PetalError::Io)?;
    let root = tmp.path();
    write_package_file(
        root,
        &sidecar.component,
        file_bytes(files, &sidecar.component)?,
    )?;
    let mut config = ComposeConfig {
        dir: root.to_path_buf(),
        disallow_imports: false,
        ..ComposeConfig::default()
    };
    for import in &sidecar.imports {
        write_package_file(root, import, file_bytes(files, import)?)?;
        let path = PathBuf::from(import);
        for name in sidecar_import_names(sidecar, import, route_id)? {
            insert_compose_dependency(&mut config, &name, &path, route_id)?;
        }
    }
    ComponentComposer::new(&root.join(&sidecar.component), &config)
        .compose()
        .map_err(|e| {
            PetalError::InvalidWasm(format!(
                "v2 route {route_id} component composition failed: {e}"
            ))
        })
}

fn insert_compose_dependency(
    config: &mut ComposeConfig,
    name: &str,
    path: &Path,
    route_id: &str,
) -> Result<(), PetalError> {
    if let Some(existing) = config.dependencies.get(name) {
        if existing.path != path {
            return Err(PetalError::InvalidWasm(format!(
                "v2 route {route_id} sidecar maps dependency {name:?} to both {} and {}",
                existing.path.display(),
                path.display()
            )));
        }
        return Ok(());
    }
    config.dependencies.insert(
        name.to_string(),
        ComposeDependency {
            path: path.to_path_buf(),
        },
    );
    Ok(())
}

fn sidecar_package_import_names(
    sidecar: &RouteSidecar,
    route_id: &str,
) -> Result<BTreeSet<String>, PetalError> {
    let mut names = BTreeSet::new();
    for import in &sidecar.imports {
        names.extend(sidecar_import_names(sidecar, import, route_id)?);
    }
    Ok(names)
}

fn sidecar_import_names(
    sidecar: &RouteSidecar,
    import: &str,
    route_id: &str,
) -> Result<Vec<String>, PetalError> {
    let stem = Path::new(import)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            PetalError::InvalidWasm(format!(
                "v2 route {route_id} sidecar import {import:?} has no utf-8 stem"
            ))
        })?;
    let mut names = vec![stem.to_string()];
    if let Some(path_alias) = import.strip_suffix(".wasm") {
        names.push(path_alias.to_string());
    }
    names.push(format!("bloom:{}/{stem}", sidecar.app_name));
    names.push(format!("bloom:{}/{stem}@0.1.0", sidecar.app_name));
    Ok(names)
}

fn route_sidecar(
    files: &[NormalizedPackageFile],
    app_name: &str,
    source_path: &str,
) -> Result<Option<RouteSidecar>, PetalError> {
    let Some(stem) = source_path.strip_suffix(".wasm") else {
        return Ok(None);
    };
    let path = format!("{stem}.route.toml");
    let Some(bytes) = optional_file_bytes(files, &path) else {
        return Ok(None);
    };
    let toml = std::str::from_utf8(bytes)
        .map_err(|_| PetalError::InvalidWasm(format!("v2 route sidecar {path} is not utf-8")))?;
    let parsed: RouteSidecarToml = toml::from_str(toml)?;
    validate_route_sidecar_path(&path, &parsed.component, true)?;
    for import in &parsed.imports {
        validate_route_sidecar_path(&path, import, false)?;
    }
    Ok(Some(RouteSidecar {
        path,
        app_name: app_name.to_string(),
        abi: parsed.abi,
        component: parsed.component,
        imports: parsed.imports,
        ops: parsed.ops,
    }))
}

fn validate_route_sidecar_path(
    sidecar_path: &str,
    rel: &str,
    primary: bool,
) -> Result<(), PetalError> {
    validate_route_sidecar_wasm_path(sidecar_path, rel)?;
    let allowed = if primary {
        rel.starts_with("modules/") || rel.starts_with("components/")
    } else {
        rel.starts_with("components/")
    };
    if !allowed {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route sidecar {sidecar_path} path {rel:?} must be package-local under {}",
            if primary {
                "modules/ or components/"
            } else {
                "components/"
            }
        )));
    }
    Ok(())
}

fn validate_route_sidecar_wasm_path(sidecar_path: &str, rel: &str) -> Result<(), PetalError> {
    validate_package_path(rel)?;
    if !rel.ends_with(".wasm") {
        return Err(PetalError::InvalidWasm(format!(
            "v2 route sidecar {sidecar_path} path {rel:?} must point to a .wasm component"
        )));
    }
    Ok(())
}

fn validate_generated_artifact_paths(root: &Path) -> Result<(), PetalError> {
    let artifacts = root.join("artifacts");
    if let Ok(meta) = std::fs::symlink_metadata(&artifacts)
        && !meta.is_dir()
    {
        return Err(PetalError::InvalidWasm(
            "v2 package artifacts path must be a directory".into(),
        ));
    }

    let routes = artifacts.join("routes");
    if let Ok(meta) = std::fs::symlink_metadata(&routes)
        && !meta.is_dir()
    {
        return Err(PetalError::InvalidWasm(
            "v2 package artifacts/routes path must be a directory".into(),
        ));
    }

    let manifest = artifacts.join("build-manifest.json");
    if let Ok(meta) = std::fs::symlink_metadata(&manifest)
        && !meta.is_file()
    {
        return Err(PetalError::InvalidWasm(
            "v2 package artifacts/build-manifest.json path must be a file".into(),
        ));
    }
    Ok(())
}

fn remove_generated_artifacts(root: &Path) -> Result<(), PetalError> {
    let artifacts = root.join("artifacts");
    let routes = artifacts.join("routes");
    match std::fs::remove_dir_all(&routes) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PetalError::Io(e)),
    }?;

    let manifest = artifacts.join("build-manifest.json");
    match std::fs::remove_file(&manifest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(PetalError::Io(e)),
    }?;
    match std::fs::remove_dir(&artifacts) {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(PetalError::Io(e)),
    }
}

fn route_kind_and_ops(source_path: &str) -> (RouteEntryKind, Vec<RouteOp>) {
    match source_path.rsplit('/').next().unwrap_or_default() {
        "$index.wasm" => (RouteEntryKind::Dir, vec![RouteOp::Lookup, RouteOp::Read]),
        "$list.wasm" => (RouteEntryKind::Dir, vec![RouteOp::List]),
        "$lookup.wasm" => (RouteEntryKind::File, vec![RouteOp::Lookup]),
        _ => (RouteEntryKind::File, vec![RouteOp::Lookup, RouteOp::Read]),
    }
}

impl RouteIndex {
    pub fn match_route(&self, path: &str) -> Option<RouteIndexMatch<'_>> {
        let path = normalize_request_path(path)?;
        let mut best: Option<RouteIndexMatch<'_>> = None;
        for route in &self.routes {
            let Some(params) = match_pattern(&route.pattern, path) else {
                continue;
            };
            let candidate = RouteIndexMatch { route, params };
            if best
                .as_ref()
                .map(|best| route.specificity > best.route.specificity)
                .unwrap_or(true)
            {
                best = Some(candidate);
            }
        }
        best
    }
}

pub fn package_hash(files: &[NormalizedPackageFile]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PACKAGE_DIGEST_PREFIX);
    for file in files {
        let path = file.path.as_bytes();
        hasher.update(&(path.len() as u32).to_le_bytes());
        hasher.update(path);
        hasher.update(&(file.bytes.len() as u64).to_le_bytes());
        hasher.update(blake3::hash(&file.bytes).as_bytes());
    }
    hex::encode(hasher.finalize().as_bytes())
}

pub fn verify_prepared_package(package: &PreparedAppPackage) -> Result<(), PetalError> {
    let files = normalize_files(package.files.clone())?;
    let rebuilt = PreparedAppPackage::from_files(files)?;
    if package.hash != rebuilt.hash {
        return Err(PetalError::InvalidHash(package.hash.clone()));
    }
    if package.name != rebuilt.name || package.route_index != rebuilt.route_index {
        return Err(PetalError::InvalidWasm(
            "v2 prepared package route index does not match rebuilt package".into(),
        ));
    }
    for route in &package.route_index.routes {
        validate_route_id_arg(&route.route_id)?;
    }
    Ok(())
}

pub fn validate_package_path(path: &str) -> Result<(), PetalError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|b| b == 0)
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(PetalError::InvalidWasm(format!(
            "invalid v2 package path {path:?}"
        )));
    }
    if !path_fits_ustar(path) {
        return Err(PetalError::InvalidWasm(format!(
            "v2 package path {path:?} is too long for strict .petal.tar archives"
        )));
    }
    Ok(())
}

fn path_fits_ustar(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() <= TAR_NAME_LEN {
        return true;
    }
    path.rmatch_indices('/').any(|(idx, _)| {
        idx <= TAR_PREFIX_LEN && bytes.len().saturating_sub(idx + 1) <= TAR_NAME_LEN
    })
}

fn collect_package_dir(root: &Path) -> Result<Vec<NormalizedPackageFile>, PetalError> {
    let mut files = Vec::new();
    collect_package_dir_inner(root, root, &mut files)?;
    Ok(files)
}

fn write_package_file(root: &Path, rel: &str, bytes: &[u8]) -> Result<(), PetalError> {
    validate_package_path(rel)?;
    let path = root.join(rel);
    let parent = path.parent().ok_or_else(|| {
        PetalError::InvalidWasm(format!("v2 package output path has no parent: {rel}"))
    })?;
    std::fs::create_dir_all(parent)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn collect_package_dir_inner(
    root: &Path,
    dir: &Path,
    files: &mut Vec<NormalizedPackageFile>,
) -> Result<(), PetalError> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            if should_skip_package_dir(root, &path) {
                continue;
            }
            collect_package_dir_inner(root, &path, files)?;
        } else if ty.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| PetalError::InvalidWasm("package file escaped root".into()))?;
            let rel = path_to_package_string(rel)?;
            validate_package_path(&rel)?;
            files.push(NormalizedPackageFile {
                path: rel,
                bytes: std::fs::read(&path)?,
            });
        } else {
            return Err(PetalError::InvalidWasm(format!(
                "v2 package contains non-regular file {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn should_skip_package_dir(root: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(root) else {
        return false;
    };
    matches!(
        rel.components()
            .next()
            .and_then(|component| component.as_os_str().to_str()),
        Some(".git" | ".jj" | "target")
    ) || path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "target")
}

fn read_package_tar(reader: impl Read) -> Result<Vec<NormalizedPackageFile>, PetalError> {
    let mut archive = tar::Archive::new(reader);
    let mut files = Vec::new();
    let entries = archive.entries()?.raw(true);
    let mut seen_paths = BTreeSet::new();
    for entry in entries {
        let mut entry = entry?;
        validate_tar_entry_header(&entry)?;
        let ty = entry.header().entry_type();
        let path = tar_path_to_string(entry.path_bytes().as_ref())?;
        let normalized_path = archive_entry_path(&path, ty)?;
        if !seen_paths.insert(normalized_path.clone()) {
            return Err(PetalError::InvalidWasm(format!(
                "duplicate v2 package archive path {:?}",
                normalized_path
            )));
        }
        if ty.is_dir() {
            continue;
        }
        if !ty.is_file() {
            return Err(PetalError::InvalidWasm(format!(
                "v2 package archive entry {:?} is not a regular file or directory",
                entry.path_bytes()
            )));
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        files.push(NormalizedPackageFile {
            path: normalized_path,
            bytes,
        });
    }
    Ok(files)
}

fn write_package_tar(
    files: &[NormalizedPackageFile],
    writer: impl Write,
) -> Result<(), PetalError> {
    let files = normalize_files(files.to_vec())?;
    let mut builder = tar::Builder::new(writer);
    for file in &files {
        let mut header = tar::Header::new_ustar();
        header.set_size(file.bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, &file.path, file.bytes.as_slice())?;
    }
    builder.finish()?;
    Ok(())
}

fn validate_tar_entry_header(entry: &tar::Entry<'_, impl Read>) -> Result<(), PetalError> {
    let header = entry.header();
    let ty = header.entry_type();
    let path = entry.path_bytes();
    let path = path.as_ref();
    if ty.is_pax_global_extensions()
        || ty.is_pax_local_extensions()
        || ty.is_gnu_longname()
        || ty.is_gnu_longlink()
    {
        return Err(PetalError::InvalidWasm(format!(
            "v2 package archive entry {:?} uses unsupported extended metadata",
            path
        )));
    }
    let mode = header.mode().map_err(|e| {
        PetalError::InvalidWasm(format!(
            "v2 package archive entry {:?} has invalid mode: {e}",
            path
        ))
    })?;
    if ty.is_file() {
        let allowed_mode = mode == 0o644
            || (mode == 0o755
                && tar_path_to_string(path)
                    .map(|p| p.starts_with("artifacts/"))
                    .unwrap_or(false));
        if !allowed_mode {
            return Err(PetalError::InvalidWasm(format!(
                "v2 package archive file {:?} has unsupported mode {mode:o}",
                path
            )));
        }
    } else if ty.is_dir() && mode != 0o755 && mode != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "v2 package archive directory {:?} has unsupported mode {mode:o}",
            path
        )));
    }
    let uid = header.uid().map_err(|e| {
        PetalError::InvalidWasm(format!(
            "v2 package archive entry {:?} has invalid uid: {e}",
            path
        ))
    })?;
    let gid = header.gid().map_err(|e| {
        PetalError::InvalidWasm(format!(
            "v2 package archive entry {:?} has invalid gid: {e}",
            path
        ))
    })?;
    if uid != 0 || gid != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "v2 package archive entry {:?} has nonzero owner metadata",
            path
        )));
    }
    if header
        .username_bytes()
        .map(|name| !name.is_empty())
        .unwrap_or(false)
        || header
            .groupname_bytes()
            .map(|name| !name.is_empty())
            .unwrap_or(false)
    {
        return Err(PetalError::InvalidWasm(format!(
            "v2 package archive entry {:?} has textual owner metadata",
            path
        )));
    }
    let mtime = header.mtime().map_err(|e| {
        PetalError::InvalidWasm(format!(
            "v2 package archive entry {:?} has invalid mtime: {e}",
            path
        ))
    })?;
    if mtime != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "v2 package archive entry {:?} has nonzero mtime",
            path
        )));
    }
    if let Some(gnu) = header.as_gnu() {
        let atime = gnu.atime().map_err(|e| {
            PetalError::InvalidWasm(format!(
                "v2 package archive entry {:?} has invalid atime: {e}",
                path
            ))
        })?;
        let ctime = gnu.ctime().map_err(|e| {
            PetalError::InvalidWasm(format!(
                "v2 package archive entry {:?} has invalid ctime: {e}",
                path
            ))
        })?;
        if atime != 0 || ctime != 0 {
            return Err(PetalError::InvalidWasm(format!(
                "v2 package archive entry {:?} has nonzero atime/ctime",
                path
            )));
        }
    }
    Ok(())
}

fn archive_entry_path(path: &str, ty: tar::EntryType) -> Result<String, PetalError> {
    if ty.is_dir() {
        if path.ends_with("//") {
            return Err(PetalError::InvalidWasm(format!(
                "invalid v2 package path {path:?}"
            )));
        }
        if let Some(path) = path.strip_suffix('/') {
            validate_package_path(path)?;
            Ok(path.to_string())
        } else {
            validate_package_path(path)?;
            Ok(path.to_string())
        }
    } else {
        validate_package_path(path)?;
        Ok(path.to_string())
    }
}

fn normalize_files(
    mut files: Vec<NormalizedPackageFile>,
) -> Result<Vec<NormalizedPackageFile>, PetalError> {
    for file in &files {
        validate_package_path(&file.path)?;
    }
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    for pair in files.windows(2) {
        if pair[0].path == pair[1].path {
            return Err(PetalError::InvalidWasm(format!(
                "duplicate v2 package path {:?}",
                pair[0].path
            )));
        }
    }
    Ok(files)
}

fn file_bytes<'a>(files: &'a [NormalizedPackageFile], path: &str) -> Result<&'a [u8], PetalError> {
    files
        .binary_search_by(|file| file.path.as_str().cmp(path))
        .ok()
        .map(|idx| files[idx].bytes.as_slice())
        .ok_or_else(|| PetalError::InvalidWasm(format!("v2 package missing required file {path}")))
}

fn optional_file_bytes<'a>(files: &'a [NormalizedPackageFile], path: &str) -> Option<&'a [u8]> {
    files
        .binary_search_by(|file| file.path.as_str().cmp(path))
        .ok()
        .map(|idx| files[idx].bytes.as_slice())
}

fn route_records_from_files(
    files: &[NormalizedPackageFile],
    app_root: &str,
) -> Result<Vec<RouteRecord>, PetalError> {
    let prefix = format!("{app_root}/");
    let mut routes = Vec::new();
    let mut has_app_file = false;
    for file in files {
        if let Some(rel) = file.path.strip_prefix(&prefix) {
            has_app_file = true;
            if rel.ends_with(".wasm") {
                let pattern = route_pattern_from_rel(rel)?;
                routes.push(RouteRecord {
                    route_id: String::new(),
                    params: route_params(&pattern)?,
                    specificity: specificity(&pattern),
                    pattern,
                    source_path: PathBuf::from(&file.path),
                });
            }
        }
    }
    if !has_app_file {
        return Err(PetalError::InvalidWasm(format!(
            "v2 package missing {app_root}/ route root"
        )));
    }
    routes.sort_by(|a, b| a.pattern.as_bytes().cmp(b.pattern.as_bytes()));
    for (idx, route) in routes.iter_mut().enumerate() {
        route.route_id = format!("r{:06}", idx + 1);
    }
    validate_route_conflicts(&routes)?;
    Ok(routes)
}

fn validate_single_app_root(
    files: &[NormalizedPackageFile],
    expected: &str,
) -> Result<(), PetalError> {
    for file in files {
        let Some(rest) = file.path.strip_prefix("app/") else {
            continue;
        };
        let root = rest.split('/').next().unwrap_or_default();
        if root != expected {
            return Err(PetalError::InvalidWasm(format!(
                "v2 package has extra app root {root:?}; expected only app/{expected}/"
            )));
        }
    }
    Ok(())
}

fn route_pattern_from_rel(rel: &str) -> Result<String, PetalError> {
    let mut segments = rel.split('/').collect::<Vec<_>>();
    for segment in &segments {
        let segment = *segment;
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(PetalError::InvalidWasm(format!(
                "route path contains invalid segment {segment:?}"
            )));
        }
    }
    let Some(last) = segments.last_mut() else {
        return Err(PetalError::InvalidWasm("empty route path".into()));
    };
    let Some(last_without_wasm) = last.strip_suffix(".wasm") else {
        return Err(PetalError::InvalidWasm("route leaf is not .wasm".into()));
    };
    match last_without_wasm {
        "$index" => {
            segments.pop();
            Ok(segments.join("/"))
        }
        "$list" | "$lookup" => {
            *last = last_without_wasm;
            Ok(segments.join("/"))
        }
        other => {
            *last = other;
            Ok(segments.join("/"))
        }
    }
}

fn path_to_package_string(path: &Path) -> Result<String, PetalError> {
    let mut out = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(segment) = component else {
            return Err(PetalError::InvalidWasm(
                "package path contains non-normal segment".into(),
            ));
        };
        out.push(
            segment
                .to_str()
                .ok_or_else(|| PetalError::InvalidWasm("package path is not utf-8".into()))?,
        );
    }
    Ok(out.join("/"))
}

fn tar_path_to_string(path: &[u8]) -> Result<String, PetalError> {
    let path = std::str::from_utf8(path)
        .map_err(|_| PetalError::InvalidWasm("archive path is not utf-8".into()))?;
    Ok(path.to_string())
}

fn validate_route_wasm(
    path: &str,
    wasm: &[u8],
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<RouteValidation, PetalError> {
    validate_route_wasm_inner(path, wasm, allowed_caps, allowed_sign_intents, None, false)
}

fn validate_route_wasm_with_package_imports(
    path: &str,
    wasm: &[u8],
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
    allowed_package_imports: &BTreeSet<String>,
) -> Result<RouteValidation, PetalError> {
    validate_route_wasm_inner(
        path,
        wasm,
        allowed_caps,
        allowed_sign_intents,
        Some(allowed_package_imports),
        false,
    )
}

fn validate_composed_route_artifact_wasm(
    path: &str,
    wasm: &[u8],
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<RouteValidation, PetalError> {
    validate_route_wasm_inner(path, wasm, allowed_caps, allowed_sign_intents, None, true)
}

fn validate_route_wasm_inner(
    path: &str,
    wasm: &[u8],
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
    allowed_package_imports: Option<&BTreeSet<String>>,
    allow_untyped_component_alias_exports: bool,
) -> Result<RouteValidation, PetalError> {
    Validator::new()
        .validate_all(wasm)
        .map_err(|e| PetalError::InvalidWasm(format!("{path}: invalid route wasm: {e}")))?;

    let mut saw_component = false;
    let mut component_types = Vec::new();
    let mut component_func_type_indices = Vec::new();
    let mut component_instance_route_type_imports = Vec::new();
    let mut component_exports = Vec::new();
    let mut required_caps = BTreeSet::new();
    let mut parse_depth = 0usize;
    for payload in Parser::new(0).parse_all(wasm) {
        let payload = payload.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?;
        let current_depth = parse_depth;
        match payload {
            Payload::Version { encoding, .. } => {
                if current_depth == 0 {
                    saw_component |= matches!(encoding, wasmparser::Encoding::Component);
                }
            }
            Payload::ComponentTypeSection(reader) => {
                if current_depth != 0 {
                    continue;
                }
                for ty in reader {
                    component_types.push(ComponentTypeEntry::Type(
                        ty.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?,
                    ));
                }
            }
            Payload::ComponentImportSection(reader) => {
                if current_depth != 0 {
                    continue;
                }
                for import in reader {
                    let import =
                        import.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?;
                    let name = import.name.0;
                    let kind = import.ty.kind();
                    if kind == ComponentExternalKind::Type {
                        let route_type = match import.ty {
                            WasmComponentTypeRef::Type(WasmComponentTypeBounds::Eq(index)) => {
                                component_route_type_import(name).filter(|route_type| {
                                    is_component_route_type_index(
                                        &component_types,
                                        index,
                                        route_type,
                                    )
                                })
                            }
                            _ => None,
                        };
                        let Some(route_type) = route_type else {
                            return Err(PetalError::InvalidWasm(format!(
                                "{path}: component route imports unsupported host item {name:?}"
                            )));
                        };
                        component_types.push(ComponentTypeEntry::RouteType(route_type));
                        continue;
                    }
                    if kind != ComponentExternalKind::Instance {
                        return Err(PetalError::InvalidWasm(format!(
                            "{path}: component route import {name:?} must be an interface instance"
                        )));
                    }
                    if allowed_package_imports
                        .is_some_and(|package_imports| package_imports.contains(name))
                    {
                        component_instance_route_type_imports.push(false);
                        continue;
                    }
                    let Some(caps) = component_import_caps(name) else {
                        return Err(PetalError::InvalidWasm(format!(
                            "{path}: component route imports unsupported host item {name:?}"
                        )));
                    };
                    let host_interface = component_host_interface(name);
                    let route_types_instance = if caps.is_empty()
                        && name == "bloom:route/types@0.1.0"
                    {
                        match import.ty {
                            WasmComponentTypeRef::Instance(type_index)
                                if is_route_types_instance(type_index, &component_types) =>
                            {
                                true
                            }
                            _ => {
                                return Err(PetalError::InvalidWasm(format!(
                                    "{path}: component route import {name:?} has invalid bloom:route@0.1.0 types"
                                )));
                            }
                        }
                    } else {
                        match (host_interface, import.ty) {
                            (Some(interface), WasmComponentTypeRef::Instance(type_index))
                                if is_host_interface_instance(
                                    interface,
                                    type_index,
                                    &component_types,
                                ) => {}
                            (Some(_), _) => {
                                return Err(PetalError::InvalidWasm(format!(
                                    "{path}: component route import {name:?} has invalid Bloom WIT interface shape"
                                )));
                            }
                            (None, _) => {}
                        }
                        false
                    };
                    for cap in caps {
                        if *cap == "bloom:sign" && allowed_sign_intents.is_empty() {
                            return Err(PetalError::InvalidWasm(format!(
                                "{path}: component route import {name:?} requires [sign].allowed_intents"
                            )));
                        }
                        if !allowed_caps.contains(*cap) {
                            return Err(PetalError::InvalidWasm(format!(
                                "{path}: component route import {name:?} requires missing petal.toml cap {cap}",
                            )));
                        }
                        required_caps.insert((*cap).to_string());
                    }
                    component_instance_route_type_imports.push(route_types_instance);
                }
            }
            Payload::ComponentCanonicalSection(reader) => {
                if current_depth != 0 {
                    continue;
                }
                for func in reader {
                    let func = func.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?;
                    if let CanonicalFunction::Lift { type_index, .. } = func {
                        component_func_type_indices.push(type_index);
                    }
                }
            }
            Payload::ComponentAliasSection(reader) => {
                if current_depth != 0 {
                    continue;
                }
                for alias in reader {
                    let alias =
                        alias.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?;
                    match alias {
                        ComponentAlias::InstanceExport {
                            kind: ComponentExternalKind::Type,
                            instance_index,
                            name,
                            ..
                        } => component_types.push(
                            component_instance_route_type_imports
                                .get(instance_index as usize)
                                .copied()
                                .unwrap_or(false)
                                .then(|| component_route_type_import(name))
                                .flatten()
                                .map(ComponentTypeEntry::RouteType)
                                .unwrap_or(ComponentTypeEntry::Unknown),
                        ),
                        ComponentAlias::InstanceExport {
                            kind: ComponentExternalKind::Func,
                            ..
                        } => component_func_type_indices.push(u32::MAX),
                        ComponentAlias::Outer {
                            kind: ComponentOuterAliasKind::Type,
                            ..
                        } => component_types.push(ComponentTypeEntry::Unknown),
                        ComponentAlias::CoreInstanceExport { .. }
                        | ComponentAlias::Outer { .. } => {}
                        ComponentAlias::InstanceExport { .. } => {}
                    }
                }
            }
            Payload::ComponentExportSection(reader) => {
                if current_depth != 0 {
                    continue;
                }
                for export in reader {
                    let export =
                        export.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?;
                    let name = export.name.0;
                    if component_route_export(name).is_some()
                        && export.kind != ComponentExternalKind::Func
                    {
                        return Err(PetalError::InvalidWasm(format!(
                            "{path}: component route export {name:?} must be a function"
                        )));
                    }
                    if export.kind == ComponentExternalKind::Func {
                        let type_index = match export.ty {
                            Some(WasmComponentTypeRef::Func(type_index)) => Some(type_index),
                            Some(_) => None,
                            None => component_func_type_indices
                                .get(export.index as usize)
                                .copied(),
                        };
                        if let Some(type_index) = type_index {
                            component_func_type_indices.push(type_index);
                        }
                        component_exports.push(ComponentRouteExport {
                            name: name.to_string(),
                            type_index,
                        });
                    }
                }
            }
            Payload::ModuleSection { .. } | Payload::ComponentSection { .. } => {
                parse_depth += 1;
            }
            Payload::End(_) => {
                parse_depth = parse_depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    if saw_component {
        let has_write_export = validate_component_route_exports(
            path,
            &component_exports,
            &component_func_type_indices,
            &component_types,
            allow_untyped_component_alias_exports,
        )?;
        return Ok(RouteValidation {
            abi: RouteAbi::ComponentBloomRoute010,
            required_caps: required_caps.into_iter().collect(),
            has_write_export,
        });
    }

    Err(PetalError::InvalidWasm(format!(
        "{path}: v2 routes must be bloom:route@0.1.0 components"
    )))
}

#[derive(Debug)]
struct ComponentRouteExport {
    name: String,
    type_index: Option<u32>,
}

#[derive(Debug)]
enum ComponentTypeEntry<'a> {
    Type(ComponentType<'a>),
    RouteType(&'static str),
    Unknown,
}

fn validate_component_route_exports(
    path: &str,
    exports: &[ComponentRouteExport],
    func_type_indices: &[u32],
    types: &[ComponentTypeEntry<'_>],
    allow_untyped_alias_exports: bool,
) -> Result<bool, PetalError> {
    let has_write_export =
        component_route_export_type("write", exports, func_type_indices).is_some();
    if component_route_export_type("metadata", exports, func_type_indices).is_none() {
        return Err(PetalError::InvalidWasm(format!(
            "{path}: component route missing bloom:route@0.1.0 metadata export"
        )));
    }
    for required in required_component_handler_exports(path) {
        if component_route_export_type(required, exports, func_type_indices).is_none() {
            return Err(PetalError::InvalidWasm(format!(
                "{path}: component route missing bloom:route@0.1.0 {required:?} export"
            )));
        }
    }
    for export in exports {
        let Some(expected) = component_route_export(&export.name) else {
            continue;
        };
        let type_index = component_route_export_type(&export.name, exports, func_type_indices)
            .ok_or_else(|| {
                PetalError::InvalidWasm(format!(
                    "{path}: component route export {:?} is missing a function type",
                    export.name
                ))
            })?;
        if allow_untyped_alias_exports && type_index == u32::MAX {
            continue;
        }
        let ty = component_func_type(path, type_index, types)?;
        validate_component_route_func_sig(path, expected, ty, types)?;
    }
    Ok(has_write_export)
}

fn component_route_export_type(
    name: &str,
    exports: &[ComponentRouteExport],
    _func_type_indices: &[u32],
) -> Option<u32> {
    exports
        .iter()
        .find(|export| export.name == name)
        .and_then(|export| export.type_index)
}

fn required_component_handler_exports(path: &str) -> &'static [&'static str] {
    match path.rsplit('/').next().unwrap_or_default() {
        "$index.wasm" => &["lookup", "read"],
        "$list.wasm" => &["list"],
        "$lookup.wasm" => &["lookup"],
        _ => &["lookup", "read"],
    }
}

fn component_route_export(name: &str) -> Option<&'static str> {
    match name {
        "metadata" => Some("metadata"),
        "lookup" => Some("lookup"),
        "list" => Some("list"),
        "read" => Some("read"),
        "write" => Some("write"),
        _ => None,
    }
}

fn component_route_type_import(name: &str) -> Option<&'static str> {
    match name {
        "ctx" => Some("ctx"),
        "entry-kind" => Some("entry-kind"),
        "entry" => Some("entry"),
        "route-meta" => Some("route-meta"),
        "route-error" => Some("route-error"),
        _ => None,
    }
}

fn component_import_caps(name: &str) -> Option<&'static [&'static str]> {
    let (package, interface, version) = component_import_package_interface(name)?;
    if version != "0.1.0" {
        return None;
    }
    match (package, interface) {
        ("bloom:route", "types") => Some(&[]),
        ("bloom:http", "fetch") => Some(&["bloom:http"]),
        ("bloom:store", "kv") => Some(&["bloom:store"]),
        ("bloom:sign", "signing") => Some(&["bloom:sign"]),
        // Fail closed until the production daemon host mediates chain reads.
        // The VM can link this interface for future/runtime tests, but v2
        // install validation must not accept apps that will deny at runtime.
        ("bloom:vfs", "readwrite") => Some(&["bloom:vfs.read", "bloom:vfs.write"]),
        ("bloom:env", "runtime") => Some(&[]),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum ComponentHostInterface {
    HttpFetch,
    StoreKv,
    SignSigning,
    ChainRead,
    VfsReadwrite,
    EnvRuntime,
}

fn component_host_interface(name: &str) -> Option<ComponentHostInterface> {
    let (package, interface, version) = component_import_package_interface(name)?;
    if version != "0.1.0" {
        return None;
    }
    match (package, interface) {
        ("bloom:http", "fetch") => Some(ComponentHostInterface::HttpFetch),
        ("bloom:store", "kv") => Some(ComponentHostInterface::StoreKv),
        ("bloom:sign", "signing") => Some(ComponentHostInterface::SignSigning),
        ("bloom:chain", "read") => Some(ComponentHostInterface::ChainRead),
        ("bloom:vfs", "readwrite") => Some(ComponentHostInterface::VfsReadwrite),
        ("bloom:env", "runtime") => Some(ComponentHostInterface::EnvRuntime),
        _ => None,
    }
}

fn component_import_package_interface(name: &str) -> Option<(&str, &str, &str)> {
    let (_, rest) = name.split_once(':')?;
    let (package_rest, interface) = rest.split_once('/')?;
    let (interface, version) = interface.split_once('@')?;
    Some((
        &name[..("bloom:".len() + package_rest.len())],
        interface,
        version,
    ))
}

fn component_func_type<'a>(
    path: &str,
    type_index: u32,
    types: &'a [ComponentTypeEntry<'a>],
) -> Result<&'a ComponentFuncType<'a>, PetalError> {
    match types.get(type_index as usize) {
        Some(ComponentTypeEntry::Type(ComponentType::Func(ty))) => Ok(ty),
        _ => Err(PetalError::InvalidWasm(format!(
            "{path}: component route export references missing function type {type_index}"
        ))),
    }
}

fn validate_component_route_func_sig(
    path: &str,
    export: &str,
    ty: &ComponentFuncType<'_>,
    types: &[ComponentTypeEntry<'_>],
) -> Result<(), PetalError> {
    let params = ty.params.as_ref();
    match export {
        "metadata" | "lookup" | "list" | "read" => {
            if params.len() != 1 || params[0].0 != "ctx" || !is_route_ctx(&params[0].1, types, 0) {
                return Err(PetalError::InvalidWasm(format!(
                    "{path}: component route export {export:?} has invalid bloom:route@0.1.0 params"
                )));
            }
        }
        "write" => {
            if params.len() != 2
                || params[0].0 != "ctx"
                || !is_route_ctx(&params[0].1, types, 0)
                || params[1].0 != "body"
                || !is_list_of(&params[1].1, types, is_u8, 0)
            {
                return Err(PetalError::InvalidWasm(format!(
                    "{path}: component route export {export:?} has invalid bloom:route@0.1.0 params"
                )));
            }
        }
        _ => return Ok(()),
    }

    let Some((_, result_ty)) = single_component_result(&ty.results) else {
        return Err(PetalError::InvalidWasm(format!(
            "{path}: component route export {export:?} must return a single result"
        )));
    };
    let ok = match export {
        "metadata" => RouteOkType::RouteMeta,
        "lookup" => RouteOkType::Entry,
        "list" => RouteOkType::EntryList,
        "read" => RouteOkType::Bytes,
        "write" => RouteOkType::Unit,
        _ => unreachable!("route exports checked above"),
    };
    if !is_route_result(result_ty, types, ok, 0) {
        return Err(PetalError::InvalidWasm(format!(
            "{path}: component route export {export:?} has invalid bloom:route@0.1.0 result"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RouteOkType {
    RouteMeta,
    Entry,
    EntryList,
    Bytes,
    Unit,
}

fn single_component_result<'a>(
    result: &'a ComponentFuncResult<'a>,
) -> Option<(Option<&'a str>, &'a ComponentValType)> {
    let mut iter = result.iter();
    let first = iter.next()?;
    iter.next().is_none().then_some(first)
}

fn is_route_result(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    ok: RouteOkType,
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Result { ok: result_ok, err } = defined else {
            return false;
        };
        let ok_matches = match (ok, result_ok) {
            (RouteOkType::Unit, None) => true,
            (RouteOkType::RouteMeta, Some(ty)) => is_route_meta(ty, types, depth),
            (RouteOkType::Entry, Some(ty)) => is_route_entry(ty, types, depth),
            (RouteOkType::EntryList, Some(ty)) => is_list_of(ty, types, is_route_entry, depth),
            (RouteOkType::Bytes, Some(ty)) => is_list_of(ty, types, is_u8, depth),
            _ => false,
        };
        ok_matches && err.is_some_and(|ty| is_route_error(&ty, types, depth))
    })
}

fn with_defined_type(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
    f: impl FnOnce(&ComponentDefinedType<'_>, &[ComponentTypeEntry<'_>], usize) -> bool,
) -> bool {
    if depth > 32 {
        return false;
    }
    let ComponentValType::Type(index) = ty else {
        return false;
    };
    match types.get(*index as usize) {
        Some(ComponentTypeEntry::Type(ComponentType::Defined(defined))) => {
            f(defined, types, depth + 1)
        }
        _ => false,
    }
}

fn is_route_type_import(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    expected: &str,
) -> bool {
    let ComponentValType::Type(index) = ty else {
        return false;
    };
    matches!(
        types.get(*index as usize),
        Some(ComponentTypeEntry::RouteType(name)) if *name == expected
    )
}

fn is_component_route_type_index(
    types: &[ComponentTypeEntry<'_>],
    index: u32,
    expected: &str,
) -> bool {
    matches!(
        types.get(index as usize),
        Some(ComponentTypeEntry::RouteType(name)) if *name == expected
    )
}

fn cloned_component_type_entry<'a>(
    types: &[ComponentTypeEntry<'a>],
    index: u32,
) -> Option<ComponentTypeEntry<'a>> {
    match types.get(index as usize)? {
        ComponentTypeEntry::Type(ty) => Some(ComponentTypeEntry::Type(ty.clone())),
        ComponentTypeEntry::RouteType(name) => Some(ComponentTypeEntry::RouteType(name)),
        ComponentTypeEntry::Unknown => Some(ComponentTypeEntry::Unknown),
    }
}

fn is_route_types_instance<'a>(type_index: u32, types: &[ComponentTypeEntry<'a>]) -> bool {
    let Some(ComponentTypeEntry::Type(ComponentType::Instance(declarations))) =
        types.get(type_index as usize)
    else {
        return false;
    };

    let mut local_types = Vec::new();
    let mut ctx = None;
    let mut entry_kind = None;
    let mut entry = None;
    let mut route_error = None;
    let mut route_meta = None;
    let mut exported_types = BTreeSet::new();

    for declaration in declarations.as_ref() {
        match declaration {
            InstanceTypeDeclaration::Type(ty) => {
                local_types.push(ComponentTypeEntry::Type(ty.clone()));
            }
            InstanceTypeDeclaration::Export { name, ty } => {
                let Some(route_type) = component_route_type_import(name.0) else {
                    return false;
                };
                let WasmComponentTypeRef::Type(WasmComponentTypeBounds::Eq(index)) = *ty else {
                    return false;
                };
                if !exported_types.insert(route_type) {
                    return false;
                }
                match route_type {
                    "ctx" => ctx = Some(index),
                    "entry-kind" => entry_kind = Some(index),
                    "entry" => entry = Some(index),
                    "route-error" => route_error = Some(index),
                    "route-meta" => route_meta = Some(index),
                    _ => unreachable!("route type import names checked above"),
                }
                let Some(entry) = cloned_component_type_entry(&local_types, index) else {
                    return false;
                };
                local_types.push(entry);
            }
            InstanceTypeDeclaration::CoreType(_) | InstanceTypeDeclaration::Alias(_) => {
                return false;
            }
        }
    }

    route_type_export_matches(ctx, &local_types, is_route_ctx)
        && route_type_export_matches(entry_kind, &local_types, is_entry_kind)
        && route_type_export_matches(entry, &local_types, is_route_entry)
        && route_type_export_matches(route_error, &local_types, is_route_error)
        && route_type_export_matches(route_meta, &local_types, is_route_meta)
}

#[derive(Clone, Copy)]
enum HostTypeExport {
    HttpRequest,
    HttpResponse,
    ChainRequest,
    ChainResponse,
    VfsEntryKind,
    VfsEntry,
}

#[derive(Clone, Copy)]
enum HostFuncExport {
    HttpFetch,
    StoreGet,
    StorePut,
    StorePutNew,
    StoreList,
    StoreDelete,
    StoreDeleteIfValue,
    SignHash,
    ChainCall,
    VfsLookup,
    VfsList,
    VfsRead,
    VfsWrite,
    EnvNowMs,
    EnvRandomBytes,
}

fn is_host_interface_instance<'a>(
    interface: ComponentHostInterface,
    type_index: u32,
    types: &[ComponentTypeEntry<'a>],
) -> bool {
    let Some(ComponentTypeEntry::Type(ComponentType::Instance(declarations))) =
        types.get(type_index as usize)
    else {
        return false;
    };

    let mut local_types = Vec::new();
    let mut exported_types = BTreeSet::new();
    let mut exported_funcs = BTreeSet::new();

    for declaration in declarations.as_ref() {
        match declaration {
            InstanceTypeDeclaration::Type(ty) => {
                local_types.push(ComponentTypeEntry::Type(ty.clone()));
            }
            InstanceTypeDeclaration::Export { name, ty } => match *ty {
                WasmComponentTypeRef::Type(WasmComponentTypeBounds::Eq(index)) => {
                    let Some(expected) = host_type_export(interface, name.0) else {
                        return false;
                    };
                    if !host_type_export_matches(expected, index, &local_types)
                        || !exported_types.insert(name.0)
                    {
                        return false;
                    }
                    let Some(entry) = cloned_component_type_entry(&local_types, index) else {
                        return false;
                    };
                    local_types.push(entry);
                }
                WasmComponentTypeRef::Func(func_type_index) => {
                    let Some(expected) = host_func_export(interface, name.0) else {
                        return false;
                    };
                    if !host_func_export_matches(expected, func_type_index, &local_types)
                        || !exported_funcs.insert(name.0)
                    {
                        return false;
                    }
                }
                _ => return false,
            },
            InstanceTypeDeclaration::CoreType(_) | InstanceTypeDeclaration::Alias(_) => {
                return false;
            }
        }
    }

    required_host_type_exports(interface)
        .iter()
        .all(|name| exported_types.contains(name))
        && required_host_func_exports(interface)
            .iter()
            .all(|name| exported_funcs.contains(name))
}

fn host_type_export(interface: ComponentHostInterface, name: &str) -> Option<HostTypeExport> {
    match (interface, name) {
        (ComponentHostInterface::HttpFetch, "request") => Some(HostTypeExport::HttpRequest),
        (ComponentHostInterface::HttpFetch, "response") => Some(HostTypeExport::HttpResponse),
        (ComponentHostInterface::ChainRead, "request") => Some(HostTypeExport::ChainRequest),
        (ComponentHostInterface::ChainRead, "response") => Some(HostTypeExport::ChainResponse),
        (ComponentHostInterface::VfsReadwrite, "entry-kind") => Some(HostTypeExport::VfsEntryKind),
        (ComponentHostInterface::VfsReadwrite, "entry") => Some(HostTypeExport::VfsEntry),
        _ => None,
    }
}

fn host_func_export(interface: ComponentHostInterface, name: &str) -> Option<HostFuncExport> {
    match (interface, name) {
        (ComponentHostInterface::HttpFetch, "fetch") => Some(HostFuncExport::HttpFetch),
        (ComponentHostInterface::StoreKv, "get") => Some(HostFuncExport::StoreGet),
        (ComponentHostInterface::StoreKv, "put") => Some(HostFuncExport::StorePut),
        (ComponentHostInterface::StoreKv, "put-new") => Some(HostFuncExport::StorePutNew),
        (ComponentHostInterface::StoreKv, "list") => Some(HostFuncExport::StoreList),
        (ComponentHostInterface::StoreKv, "delete") => Some(HostFuncExport::StoreDelete),
        (ComponentHostInterface::StoreKv, "delete-if-value") => {
            Some(HostFuncExport::StoreDeleteIfValue)
        }
        (ComponentHostInterface::SignSigning, "sign-hash") => Some(HostFuncExport::SignHash),
        (ComponentHostInterface::ChainRead, "call") => Some(HostFuncExport::ChainCall),
        (ComponentHostInterface::VfsReadwrite, "lookup") => Some(HostFuncExport::VfsLookup),
        (ComponentHostInterface::VfsReadwrite, "list") => Some(HostFuncExport::VfsList),
        (ComponentHostInterface::VfsReadwrite, "read") => Some(HostFuncExport::VfsRead),
        (ComponentHostInterface::VfsReadwrite, "write") => Some(HostFuncExport::VfsWrite),
        (ComponentHostInterface::EnvRuntime, "now-ms") => Some(HostFuncExport::EnvNowMs),
        (ComponentHostInterface::EnvRuntime, "random-bytes") => {
            Some(HostFuncExport::EnvRandomBytes)
        }
        _ => None,
    }
}

fn required_host_type_exports(interface: ComponentHostInterface) -> &'static [&'static str] {
    match interface {
        ComponentHostInterface::HttpFetch => &["request", "response"],
        ComponentHostInterface::ChainRead => &["request", "response"],
        ComponentHostInterface::VfsReadwrite => &["entry-kind", "entry"],
        ComponentHostInterface::EnvRuntime => &[],
        ComponentHostInterface::StoreKv | ComponentHostInterface::SignSigning => &[],
    }
}

fn required_host_func_exports(interface: ComponentHostInterface) -> &'static [&'static str] {
    match interface {
        ComponentHostInterface::HttpFetch => &["fetch"],
        ComponentHostInterface::StoreKv => {
            &["get", "put", "put-new", "list", "delete", "delete-if-value"]
        }
        ComponentHostInterface::SignSigning => &["sign-hash"],
        ComponentHostInterface::ChainRead => &["call"],
        ComponentHostInterface::VfsReadwrite => &["lookup", "list", "read", "write"],
        ComponentHostInterface::EnvRuntime => &["now-ms", "random-bytes"],
    }
}

fn host_type_export_matches(
    expected: HostTypeExport,
    index: u32,
    types: &[ComponentTypeEntry<'_>],
) -> bool {
    let ty = ComponentValType::Type(index);
    match expected {
        HostTypeExport::HttpRequest => is_http_request(&ty, types, 0),
        HostTypeExport::HttpResponse => is_http_response(&ty, types, 0),
        HostTypeExport::ChainRequest => is_chain_request(&ty, types, 0),
        HostTypeExport::ChainResponse => is_chain_response(&ty, types, 0),
        HostTypeExport::VfsEntryKind => is_entry_kind(&ty, types, 0),
        HostTypeExport::VfsEntry => is_route_entry(&ty, types, 0),
    }
}

fn host_func_export_matches(
    expected: HostFuncExport,
    type_index: u32,
    types: &[ComponentTypeEntry<'_>],
) -> bool {
    let Some(ComponentTypeEntry::Type(ComponentType::Func(ty))) = types.get(type_index as usize)
    else {
        return false;
    };
    let params = ty.params.as_ref();
    match expected {
        HostFuncExport::HttpFetch => {
            params_match(params, types, &[("req", is_http_request)])
                && result_matches(&ty.results, types, HostOkType::HttpResponse)
        }
        HostFuncExport::StoreGet => {
            params_match(
                params,
                types,
                &[("namespace", is_string_type), ("key", is_string_type)],
            ) && result_matches(&ty.results, types, HostOkType::OptionalBytes)
        }
        HostFuncExport::StorePut => {
            params_match(
                params,
                types,
                &[
                    ("namespace", is_string_type),
                    ("key", is_string_type),
                    ("value", is_byte_list),
                    ("secret", is_bool_type),
                ],
            ) && result_matches(&ty.results, types, HostOkType::Unit)
        }
        HostFuncExport::StorePutNew => {
            params_match(
                params,
                types,
                &[
                    ("namespace", is_string_type),
                    ("key", is_string_type),
                    ("value", is_byte_list),
                    ("secret", is_bool_type),
                ],
            ) && result_matches(&ty.results, types, HostOkType::Unit)
        }
        HostFuncExport::StoreList => {
            params_match(
                params,
                types,
                &[("namespace", is_string_type), ("prefix", is_string_type)],
            ) && result_matches(&ty.results, types, HostOkType::StringList)
        }
        HostFuncExport::StoreDelete => {
            params_match(
                params,
                types,
                &[("namespace", is_string_type), ("key", is_string_type)],
            ) && result_matches(&ty.results, types, HostOkType::Unit)
        }
        HostFuncExport::StoreDeleteIfValue => {
            params_match(
                params,
                types,
                &[
                    ("namespace", is_string_type),
                    ("key", is_string_type),
                    ("expected", is_byte_list),
                ],
            ) && result_matches(&ty.results, types, HostOkType::Unit)
        }
        HostFuncExport::SignHash => {
            params_match(
                params,
                types,
                &[
                    ("wallet", is_string_type),
                    ("hash32", is_byte_list),
                    ("intent", is_string_type),
                ],
            ) && result_matches(&ty.results, types, HostOkType::Bytes)
        }
        HostFuncExport::ChainCall => {
            params_match(params, types, &[("req", is_chain_request)])
                && result_matches(&ty.results, types, HostOkType::ChainResponse)
        }
        HostFuncExport::VfsLookup => {
            params_match(params, types, &[("path", is_string_type)])
                && result_matches(&ty.results, types, HostOkType::VfsEntry)
        }
        HostFuncExport::VfsList => {
            params_match(params, types, &[("path", is_string_type)])
                && result_matches(&ty.results, types, HostOkType::VfsEntryList)
        }
        HostFuncExport::VfsRead => {
            params_match(params, types, &[("path", is_string_type)])
                && result_matches(&ty.results, types, HostOkType::Bytes)
        }
        HostFuncExport::VfsWrite => {
            params_match(
                params,
                types,
                &[("path", is_string_type), ("body", is_byte_list)],
            ) && result_matches(&ty.results, types, HostOkType::Unit)
        }
        HostFuncExport::EnvNowMs => {
            params.is_empty() && result_matches(&ty.results, types, HostOkType::U64)
        }
        HostFuncExport::EnvRandomBytes => {
            params_match(params, types, &[("len", is_u32_type)])
                && result_matches(&ty.results, types, HostOkType::Bytes)
        }
    }
}

type ValPredicate = fn(&ComponentValType, &[ComponentTypeEntry<'_>], usize) -> bool;

fn params_match(
    params: &[(&str, ComponentValType)],
    types: &[ComponentTypeEntry<'_>],
    expected: &[(&str, ValPredicate)],
) -> bool {
    params.len() == expected.len()
        && params
            .iter()
            .zip(expected)
            .all(|((name, ty), (expected_name, predicate))| {
                name == expected_name && predicate(ty, types, 0)
            })
}

#[derive(Clone, Copy)]
enum HostOkType {
    Unit,
    Bytes,
    OptionalBytes,
    StringList,
    HttpResponse,
    ChainResponse,
    VfsEntry,
    VfsEntryList,
    U64,
}

fn result_matches(
    result: &ComponentFuncResult<'_>,
    types: &[ComponentTypeEntry<'_>],
    ok: HostOkType,
) -> bool {
    let Some((_, result_ty)) = single_component_result(result) else {
        return false;
    };
    with_defined_type(result_ty, types, 0, |defined, types, depth| {
        let ComponentDefinedType::Result { ok: result_ok, err } = defined else {
            return false;
        };
        let ok_matches = match (ok, result_ok) {
            (HostOkType::Unit, None) => true,
            (HostOkType::Bytes, Some(ty)) => is_byte_list(ty, types, depth),
            (HostOkType::OptionalBytes, Some(ty)) => is_option_of(ty, types, is_byte_list, depth),
            (HostOkType::StringList, Some(ty)) => is_list_of(ty, types, is_string_type, depth),
            (HostOkType::HttpResponse, Some(ty)) => is_http_response(ty, types, depth),
            (HostOkType::ChainResponse, Some(ty)) => is_chain_response(ty, types, depth),
            (HostOkType::VfsEntry, Some(ty)) => is_route_entry(ty, types, depth),
            (HostOkType::VfsEntryList, Some(ty)) => is_list_of(ty, types, is_route_entry, depth),
            (HostOkType::U64, Some(ty)) => is_u64(ty, types, depth),
            _ => false,
        };
        ok_matches && err.is_some_and(|ty| is_string(&ty))
    })
}

fn route_type_export_matches(
    index: Option<u32>,
    types: &[ComponentTypeEntry<'_>],
    predicate: fn(&ComponentValType, &[ComponentTypeEntry<'_>], usize) -> bool,
) -> bool {
    index.is_some_and(|index| predicate(&ComponentValType::Type(index), types, 0))
}

fn is_route_ctx(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    if is_route_type_import(ty, types, "ctx") {
        return true;
    }
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 5
            && fields[0].0 == "app-root"
            && is_string(&fields[0].1)
            && fields[1].0 == "package-hash"
            && is_string(&fields[1].1)
            && fields[2].0 == "path"
            && is_string(&fields[2].1)
            && fields[3].0 == "params"
            && is_list_of(&fields[3].1, types, is_string_tuple, depth)
            && fields[4].0 == "actor"
            && is_option_of(&fields[4].1, types, is_string_type, depth)
    })
}

fn is_route_entry(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    if is_route_type_import(ty, types, "entry") {
        return true;
    }
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 5
            && fields[0].0 == "name"
            && is_string(&fields[0].1)
            && fields[1].0 == "kind"
            && is_entry_kind(&fields[1].1, types, depth)
            && fields[2].0 == "mode"
            && is_u32(&fields[2].1)
            && fields[3].0 == "size"
            && is_option_of(&fields[3].1, types, is_u64, depth)
            && fields[4].0 == "link-target"
            && is_option_of(&fields[4].1, types, is_string_type, depth)
    })
}

fn is_route_meta(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    if is_route_type_import(ty, types, "route-meta") {
        return true;
    }
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 10
            && fields[0].0 == "kind"
            && is_entry_kind(&fields[0].1, types, depth)
            && fields[1].0 == "mode"
            && is_u32(&fields[1].1)
            && fields[2].0 == "cache-ttl-ms"
            && is_option_of(&fields[2].1, types, is_u64, depth)
            && fields[3].0 == "side-effecting-read"
            && is_bool(&fields[3].1)
            && fields[4].0 == "write-async"
            && is_bool(&fields[4].1)
            && fields[5].0 == "description"
            && is_option_of(&fields[5].1, types, is_string_type, depth)
            && fields[6].0 == "consent-summary"
            && is_option_of(&fields[6].1, types, is_string_type, depth)
            && fields[7].0 == "required-caps"
            && is_list_of(&fields[7].1, types, is_string_type, depth)
            && fields[8].0 == "sign-intent"
            && is_option_of(&fields[8].1, types, is_string_type, depth)
            && fields[9].0 == "executable"
            && is_bool(&fields[9].1)
    })
}

fn is_route_error(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    if is_route_type_import(ty, types, "route-error") {
        return true;
    }
    with_defined_type(ty, types, depth, |defined, _types, _depth| {
        let ComponentDefinedType::Variant(cases) = defined else {
            return false;
        };
        let expected = [
            "not-found",
            "not-a-dir",
            "denied",
            "invalid",
            "backend",
            "unsupported",
        ];
        cases.as_ref().len() == expected.len()
            && cases.iter().zip(expected).all(|(case, expected_name)| {
                case.name == expected_name && case.ty.as_ref().is_some_and(is_string)
            })
    })
}

fn is_entry_kind(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    if is_route_type_import(ty, types, "entry-kind") {
        return true;
    }
    with_defined_type(ty, types, depth, |defined, _types, _depth| {
        matches!(
            defined,
            ComponentDefinedType::Enum(tags) if tags.as_ref() == ["dir", "file", "symlink"]
        )
    })
}

fn is_list_of(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    item: fn(&ComponentValType, &[ComponentTypeEntry<'_>], usize) -> bool,
    depth: usize,
) -> bool {
    with_defined_type(
        ty,
        types,
        depth,
        |defined, types, depth| matches!(defined, ComponentDefinedType::List(inner) if item(inner, types, depth)),
    )
}

fn is_option_of(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    inner: fn(&ComponentValType, &[ComponentTypeEntry<'_>], usize) -> bool,
    depth: usize,
) -> bool {
    with_defined_type(
        ty,
        types,
        depth,
        |defined, types, depth| matches!(defined, ComponentDefinedType::Option(option) if inner(option, types, depth)),
    )
}

fn is_string_tuple(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    with_defined_type(ty, types, depth, |defined, _types, _depth| {
        matches!(
            defined,
            ComponentDefinedType::Tuple(items)
                if items.as_ref().len() == 2 && is_string(&items[0]) && is_string(&items[1])
        )
    })
}

fn is_http_request(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 4
            && fields[0].0 == "method"
            && is_string(&fields[0].1)
            && fields[1].0 == "url"
            && is_string(&fields[1].1)
            && fields[2].0 == "headers"
            && is_list_of(&fields[2].1, types, is_string_tuple, depth)
            && fields[3].0 == "body"
            && is_byte_list(&fields[3].1, types, depth)
    })
}

fn is_http_response(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 3
            && fields[0].0 == "status"
            && is_u16(&fields[0].1)
            && fields[1].0 == "headers"
            && is_list_of(&fields[1].1, types, is_string_tuple, depth)
            && fields[2].0 == "body"
            && is_byte_list(&fields[2].1, types, depth)
    })
}

fn is_chain_request(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    with_defined_type(ty, types, depth, |defined, _types, _depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 3
            && fields[0].0 == "chain"
            && is_string(&fields[0].1)
            && fields[1].0 == "method"
            && is_string(&fields[1].1)
            && fields[2].0 == "params-json"
            && is_string(&fields[2].1)
    })
}

fn is_chain_response(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, _types, _depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 1 && fields[0].0 == "result-json" && is_string(&fields[0].1)
    })
}

fn is_byte_list(ty: &ComponentValType, types: &[ComponentTypeEntry<'_>], depth: usize) -> bool {
    is_list_of(ty, types, is_u8, depth)
}

fn is_bool_type(ty: &ComponentValType, _types: &[ComponentTypeEntry<'_>], _depth: usize) -> bool {
    is_bool(ty)
}

fn is_bool(ty: &ComponentValType) -> bool {
    matches!(
        ty,
        ComponentValType::Primitive(ComponentPrimitiveValType::Bool)
    )
}

fn is_string(ty: &ComponentValType) -> bool {
    matches!(
        ty,
        ComponentValType::Primitive(ComponentPrimitiveValType::String)
    )
}

fn is_string_type(ty: &ComponentValType, _types: &[ComponentTypeEntry<'_>], _depth: usize) -> bool {
    is_string(ty)
}

fn is_u8(ty: &ComponentValType, _types: &[ComponentTypeEntry<'_>], _depth: usize) -> bool {
    matches!(
        ty,
        ComponentValType::Primitive(ComponentPrimitiveValType::U8)
    )
}

fn is_u16(ty: &ComponentValType) -> bool {
    matches!(
        ty,
        ComponentValType::Primitive(ComponentPrimitiveValType::U16)
    )
}

fn is_u32(ty: &ComponentValType) -> bool {
    matches!(
        ty,
        ComponentValType::Primitive(ComponentPrimitiveValType::U32)
    )
}

fn is_u32_type(ty: &ComponentValType, _types: &[ComponentTypeEntry<'_>], _depth: usize) -> bool {
    is_u32(ty)
}

fn is_u64(ty: &ComponentValType, _types: &[ComponentTypeEntry<'_>], _depth: usize) -> bool {
    matches!(
        ty,
        ComponentValType::Primitive(ComponentPrimitiveValType::U64)
    )
}

fn validate_route_id_arg(route_id: &str) -> Result<(), PetalError> {
    let valid = route_id.len() == 7
        && route_id.starts_with('r')
        && route_id[1..].bytes().all(|b| b.is_ascii_digit())
        && route_id != "r000000";
    if valid {
        Ok(())
    } else {
        Err(PetalError::InvalidWasm(format!(
            "invalid route id {route_id:?}"
        )))
    }
}

fn require_file(path: PathBuf) -> Result<(), PetalError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(PetalError::InvalidWasm(format!(
            "v2 package missing required file {}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unknown>")
        )))
    }
}

fn validate_app_name(name: &str) -> Result<(), PetalError> {
    let valid = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.bytes().any(|b| b == 0)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err(PetalError::InvalidWasm(format!(
            "invalid v2 app name {name:?}"
        )))
    }
}

fn validate_sign_policy(
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<(), PetalError> {
    if allowed_caps.contains("bloom:sign") && allowed_sign_intents.is_empty() {
        return Err(PetalError::InvalidWasm(
            "v2 package cap bloom:sign requires [sign].allowed_intents".into(),
        ));
    }
    for intent in allowed_sign_intents {
        validate_sign_intent(intent)?;
    }
    Ok(())
}

fn store_policy_from_manifest(manifest: &PetalToml) -> StoreNamespacePolicy {
    StoreNamespacePolicy::from_namespaces(
        manifest.store.namespaces.iter().cloned(),
        manifest.store.secret_namespaces.iter().cloned(),
    )
}

fn validate_store_policy(
    allowed_caps: &BTreeSet<String>,
    policy: &StoreNamespacePolicy,
) -> Result<(), PetalError> {
    if allowed_caps.contains("bloom:store") && policy.is_empty() {
        return Err(PetalError::InvalidWasm(
            "v2 package cap bloom:store requires [store].namespaces or [store].secret_namespaces"
                .into(),
        ));
    }
    for namespace in policy.namespaces() {
        validate_store_namespace(namespace)?;
    }
    Ok(())
}

fn validate_store_namespace(namespace: &str) -> Result<(), PetalError> {
    if namespace.is_empty() || namespace.len() > 128 {
        return Err(PetalError::InvalidWasm(
            "v2 store namespace must be 1..128 bytes".into(),
        ));
    }
    if namespace.contains('/')
        || !namespace
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(PetalError::InvalidWasm(format!(
            "v2 store namespace {namespace:?} contains an unsupported byte"
        )));
    }
    Ok(())
}

fn validate_sign_intent(intent: &str) -> Result<(), PetalError> {
    if intent.is_empty() || intent.len() > 128 {
        return Err(PetalError::InvalidWasm(
            "v2 sign intent must be 1..128 bytes".into(),
        ));
    }
    if !intent
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
    {
        return Err(PetalError::InvalidWasm(format!(
            "v2 sign intent {intent:?} contains an unsupported byte"
        )));
    }
    Ok(())
}

fn scan_routes(
    app_root: &Path,
    dir: &Path,
    routes: &mut Vec<RouteRecord>,
) -> Result<(), PetalError> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            scan_routes(app_root, &path, routes)?;
        } else if ty.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".wasm"))
                .unwrap_or(false)
        {
            let pattern = route_pattern(app_root, &path)?;
            routes.push(RouteRecord {
                route_id: String::new(),
                params: route_params(&pattern)?,
                specificity: specificity(&pattern),
                pattern,
                source_path: path,
            });
        }
    }
    Ok(())
}

fn route_pattern(app_root: &Path, wasm_path: &Path) -> Result<String, PetalError> {
    let rel = wasm_path
        .strip_prefix(app_root)
        .map_err(|_| PetalError::InvalidWasm("route escaped app root".into()))?;
    let mut parts = Vec::new();
    for component in rel.components() {
        let std::path::Component::Normal(seg) = component else {
            return Err(PetalError::InvalidWasm(
                "route path contains non-normal segment".into(),
            ));
        };
        let seg = seg
            .to_str()
            .ok_or_else(|| PetalError::InvalidWasm("route path is not utf-8".into()))?;
        if seg.contains('\\') || seg.bytes().any(|b| b == 0) {
            return Err(PetalError::InvalidWasm(format!(
                "route path contains invalid segment {seg:?}"
            )));
        }
        parts.push(seg.to_string());
    }
    let Some(last) = parts.last_mut() else {
        return Err(PetalError::InvalidWasm("empty route path".into()));
    };
    *last = last
        .strip_suffix(".wasm")
        .ok_or_else(|| PetalError::InvalidWasm("route leaf is not .wasm".into()))?
        .to_string();
    match last.as_str() {
        "$index" => {
            parts.pop();
        }
        "$list" | "$lookup" => {}
        _ => {}
    }
    Ok(parts.join("/"))
}

fn route_params(pattern: &str) -> Result<Vec<String>, PetalError> {
    let mut params = Vec::new();
    for segment in pattern.split('/') {
        if let Some((param, _suffix)) = dynamic_segment(segment)? {
            if params.iter().any(|existing| existing == param) {
                return Err(PetalError::InvalidWasm(format!(
                    "duplicate route param {param:?} in {pattern:?}"
                )));
            }
            params.push(param.to_string());
        }
    }
    Ok(params)
}

fn specificity(pattern: &str) -> RouteSpecificity {
    let segments = pattern.split('/').collect::<Vec<_>>();
    RouteSpecificity {
        segment_count: segments.len(),
        static_segment_count: segments
            .iter()
            .filter(|segment| !segment.starts_with('['))
            .count(),
        file_score: usize::from(!pattern.ends_with('/')),
    }
}

fn validate_route_conflicts(routes: &[RouteRecord]) -> Result<(), PetalError> {
    for (idx, a) in routes.iter().enumerate() {
        for b in routes.iter().skip(idx + 1) {
            if a.specificity == b.specificity && patterns_overlap(&a.pattern, &b.pattern)? {
                return Err(PetalError::InvalidWasm(format!(
                    "conflicting v2 routes {:?} and {:?}",
                    a.pattern, b.pattern
                )));
            }
        }
    }
    Ok(())
}

fn normalize_request_path(path: &str) -> Option<&str> {
    if path.is_empty() {
        return Some(path);
    }
    if path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|b| b == 0)
        || path
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return None;
    }
    Some(path)
}

fn match_pattern(pattern: &str, path: &str) -> Option<Vec<(String, String)>> {
    let pattern_segments = pattern.split('/').collect::<Vec<_>>();
    let path_segments = path.split('/').collect::<Vec<_>>();
    if pattern_segments.len() != path_segments.len() {
        return None;
    }
    let mut params = Vec::new();
    for (pattern, value) in pattern_segments.iter().zip(path_segments) {
        match dynamic_segment(pattern).ok()? {
            Some((param, suffix)) => {
                let bound = value.strip_suffix(suffix)?;
                if bound.is_empty() {
                    return None;
                }
                params.push((param.to_string(), bound.to_string()));
            }
            None if *pattern == value => {}
            None => return None,
        }
    }
    Some(params)
}

fn patterns_overlap(a: &str, b: &str) -> Result<bool, PetalError> {
    let a = a.split('/').collect::<Vec<_>>();
    let b = b.split('/').collect::<Vec<_>>();
    if a.len() != b.len() {
        return Ok(false);
    }
    for (a, b) in a.into_iter().zip(b) {
        if !segments_overlap(a, b)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn segments_overlap(a: &str, b: &str) -> Result<bool, PetalError> {
    match (dynamic_segment(a)?, dynamic_segment(b)?) {
        (None, None) => Ok(a == b),
        (Some((_param, suffix)), None) => Ok(b.ends_with(suffix)),
        (None, Some((_param, suffix))) => Ok(a.ends_with(suffix)),
        (Some((_a_param, a_suffix)), Some((_b_param, b_suffix))) => Ok(a_suffix == b_suffix
            || a_suffix.ends_with(b_suffix)
            || b_suffix.ends_with(a_suffix)),
    }
}

fn dynamic_segment(segment: &str) -> Result<Option<(&str, &str)>, PetalError> {
    if !segment.starts_with('[') {
        return Ok(None);
    }
    let Some(end) = segment.find(']') else {
        return Err(PetalError::InvalidWasm(format!(
            "dynamic route segment missing ]: {segment:?}"
        )));
    };
    let param = &segment[1..end];
    if param.is_empty()
        || !param
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err(PetalError::InvalidWasm(format!(
            "invalid route param in segment {segment:?}"
        )));
    }
    Ok(Some((param, &segment[end + 1..])))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use wasm_encoder::{
        CanonicalOption, CodeSection, ComponentBuilder, ComponentExportKind, ComponentTypeRef,
        ExportKind, ExportSection, Function, FunctionSection, InstanceType, Instruction, Module,
        PrimitiveValType, TypeSection,
    };

    #[test]
    fn v2_scanner_matches_static_and_dynamic_routes() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "app/echo/hello.txt.wasm", b"\0asm");
        write_package_file(tmp.path(), "app/echo/[name].txt.wasm", b"\0asm");

        let package = PetalAppPackage::scan_dir(tmp.path()).unwrap();
        assert_eq!(package.name, "echo");
        assert_eq!(package.routes.len(), 2);

        let static_match = package.match_route("hello.txt").unwrap();
        assert_eq!(static_match.route.pattern, "hello.txt");
        assert!(static_match.params.is_empty());

        let dynamic_match = package.match_route("alice.txt").unwrap();
        assert_eq!(dynamic_match.route.pattern, "[name].txt");
        assert_eq!(dynamic_match.params, vec![("name".into(), "alice".into())]);
        assert!(package.match_route("../alice.txt").is_none());
    }

    #[test]
    fn v2_scanner_rejects_equal_specificity_dynamic_conflicts() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "app/echo/[name].txt.wasm", b"\0asm");
        write_package_file(tmp.path(), "app/echo/[wallet].txt.wasm", b"\0asm");

        let err = PetalAppPackage::scan_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("conflicting v2 routes"));
    }

    #[test]
    fn v2_scanner_rejects_paths_too_long_for_strict_archive() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        let file_name = format!("{}.wasm", "a".repeat(TAR_NAME_LEN + 1));
        write_package_file(
            tmp.path(),
            &format!("app/echo/{file_name}"),
            route_component_no_imports(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("too long for strict .petal.tar"));
    }

    #[test]
    fn v2_tar_and_dir_inputs_share_normalized_hash() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package(tmp.path());
        let dir = PreparedAppPackage::from_dir(tmp.path()).unwrap();
        let wasm = route_component_no_imports();
        let tar = PreparedAppPackage::from_reader(std::io::Cursor::new(package_tar_bytes(vec![
            ("README.md", b"# echo".as_slice()),
            ("AGENTS.md", b"# echo agents".as_slice()),
            (
                "petal.toml",
                br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#
                .as_slice(),
            ),
            ("app/echo/hello.txt.wasm", wasm),
        ])))
        .unwrap();

        assert_eq!(dir.hash, tar.hash);
        assert_eq!(dir.route_index.routes, tar.route_index.routes);
        assert_eq!(dir.route_index.routes[0].route_id, "r000001");
    }

    #[test]
    fn v2_app_consent_summary_includes_manifest_policy_docs_and_routes() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"

[consent]
summary = "Expose echo routes and use mediated host capabilities."

[caps]
allowed = ["bloom:http", "bloom:store", "bloom:sign"]

[[net.allow]]
host = "api.example.com"
methods = ["get"]
paths = ["/status"]

[sign]
allowed_intents = ["echo.test"]

[store]
namespaces = ["orders"]
secret_namespaces = ["credentials"]
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "app/echo/hello.txt.wasm",
            route_component_no_imports(),
        );

        let package = PreparedAppPackage::from_dir(tmp.path()).unwrap();
        let summary = app_consent_summary(&package).unwrap();

        assert_eq!(summary.name, "echo");
        assert_eq!(summary.app_mount, "apps/echo/");
        assert_eq!(
            summary.package_summary.as_deref(),
            Some("Expose echo routes and use mediated host capabilities.")
        );
        assert_eq!(summary.docs, vec!["README.md", "AGENTS.md"]);
        assert_eq!(
            summary.capabilities,
            vec!["bloom:http", "bloom:sign", "bloom:store"]
        );
        assert_eq!(summary.network.len(), 1);
        assert_eq!(summary.network[0].host, "api.example.com");
        assert_eq!(summary.network[0].methods, vec!["GET"]);
        assert_eq!(summary.network[0].paths, vec!["/status"]);
        assert_eq!(summary.sign_intents, vec!["echo.test"]);
        assert_eq!(
            summary.store_namespaces,
            vec![
                AppConsentStoreNamespace {
                    namespace: "credentials".into(),
                    secret: true,
                },
                AppConsentStoreNamespace {
                    namespace: "orders".into(),
                    secret: false,
                },
            ]
        );
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/apps/echo/hello.txt");
        assert_eq!(summary.routes[0].ops, vec![RouteOp::Lookup, RouteOp::Read]);
    }

    #[test]
    fn v2_write_petal_tar_emits_installable_deterministic_archive() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package(tmp.path());
        let package = PreparedAppPackage::from_dir(tmp.path()).unwrap();

        let mut first = Vec::new();
        package.write_petal_tar(&mut first).unwrap();
        let mut second = Vec::new();
        package.write_petal_tar(&mut second).unwrap();
        assert_eq!(first, second);

        let from_tar = PreparedAppPackage::from_reader(std::io::Cursor::new(first)).unwrap();
        assert_eq!(from_tar.hash, package.hash);
        assert_eq!(from_tar.route_index, package.route_index);
    }

    #[test]
    fn v2_write_petal_tar_uses_strict_headers_for_ustar_split_paths() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        let route_path = format!(
            "app/echo/{}/hello.txt.wasm",
            "nested-static-segment".repeat(4)
        );
        assert!(route_path.len() > TAR_NAME_LEN);
        write_package_file(tmp.path(), &route_path, route_component_no_imports());
        let package = PreparedAppPackage::from_dir(tmp.path()).unwrap();

        let mut tar_bytes = Vec::new();
        package.write_petal_tar(&mut tar_bytes).unwrap();

        let mut archive = tar::Archive::new(std::io::Cursor::new(&tar_bytes));
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let ty = entry.header().entry_type();
            assert!(!ty.is_pax_global_extensions());
            assert!(!ty.is_pax_local_extensions());
            assert!(!ty.is_gnu_longname());
            assert!(!ty.is_gnu_longlink());
        }
        let from_tar = PreparedAppPackage::from_reader(std::io::Cursor::new(tar_bytes)).unwrap();
        assert_eq!(from_tar.hash, package.hash);
    }

    #[test]
    fn v2_build_app_package_dir_writes_artifacts_and_manifest_deterministically() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package(tmp.path());

        let first = build_app_package_dir(tmp.path()).unwrap();
        let artifact_path = tmp.path().join("artifacts/routes/r000001.wasm");
        let manifest_path = tmp.path().join("artifacts/build-manifest.json");
        let source = std::fs::read(tmp.path().join("app/echo/hello.txt.wasm")).unwrap();
        let artifact = std::fs::read(&artifact_path).unwrap();
        assert_eq!(artifact, source);

        let manifest: BuildManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest.schema, BUILD_MANIFEST_SCHEMA);
        assert_eq!(manifest.routes.len(), 1);
        assert_eq!(manifest.routes[0].route_id, "r000001");
        assert_eq!(manifest.routes[0].source_path, "app/echo/hello.txt.wasm");
        assert_eq!(
            manifest.routes[0].artifact_path,
            "artifacts/routes/r000001.wasm"
        );
        let source_hash = hex::encode(blake3::hash(&source).as_bytes());
        assert_eq!(manifest.routes[0].source_hash, source_hash);
        assert_eq!(manifest.routes[0].artifact_hash, source_hash);
        assert_ne!(manifest.source_package_hash, first.hash);
        assert!(
            first
                .files
                .iter()
                .any(|file| file.path == "artifacts/build-manifest.json")
        );
        assert!(
            first
                .files
                .iter()
                .any(|file| file.path == "artifacts/routes/r000001.wasm")
        );

        let second = build_app_package_dir(tmp.path()).unwrap();
        assert_eq!(second.hash, first.hash);
        assert_eq!(second.route_index, first.route_index);
    }

    #[test]
    fn v2_build_app_package_dir_replaces_stale_generated_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package(tmp.path());
        write_package_file(
            tmp.path(),
            "artifacts/routes/r000001.wasm",
            b"stale invalid wasm",
        );
        write_package_file(
            tmp.path(),
            "artifacts/build-manifest.json",
            b"stale invalid manifest",
        );

        let package = build_app_package_dir(tmp.path()).unwrap();
        let route = &package.route_index.routes[0];
        let artifact = std::fs::read(tmp.path().join(&route.artifact_path)).unwrap();
        let source = std::fs::read(tmp.path().join(&route.source_path)).unwrap();
        assert_eq!(artifact, source);
    }

    #[cfg(unix)]
    #[test]
    fn v2_build_app_package_dir_rejects_symlinked_artifacts_without_deleting_target() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write_v2_package(tmp.path());
        std::fs::write(outside.path().join("sentinel"), b"keep").unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("artifacts")).unwrap();

        let err = build_app_package_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("non-regular file")
                || err
                    .to_string()
                    .contains("artifacts path must be a directory"),
            "{err}"
        );
        assert_eq!(
            std::fs::read(outside.path().join("sentinel")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn v2_route_sidecar_builds_artifact_from_module_component() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.wasm",
            route_component_no_imports(),
        );
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.route.toml",
            br#"abi = "component"
component = "modules/message.wasm"
"#,
        );
        write_package_file(
            tmp.path(),
            "modules/message.wasm",
            route_component_metadata(),
        );

        let package = build_app_package_dir(tmp.path()).unwrap();
        let route = &package.route_index.routes[0];
        let artifact = std::fs::read(tmp.path().join(&route.artifact_path)).unwrap();
        assert_eq!(artifact, route_component_metadata());
        assert_eq!(
            route.artifact_hash,
            hex::encode(blake3::hash(route_component_metadata()).as_bytes())
        );
        assert_eq!(route.install_metadata.cache_ttl_ms, Some(2000));
        let manifest: BuildManifest = serde_json::from_slice(
            &std::fs::read(tmp.path().join("artifacts/build-manifest.json")).unwrap(),
        )
        .unwrap();
        assert_ne!(
            manifest.routes[0].source_hash,
            manifest.routes[0].artifact_hash
        );
    }

    #[test]
    fn v2_route_sidecar_rejects_non_component_paths() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(tmp.path(), route_component_metadata());
        write_package_file(
            tmp.path(),
            "app/echo/hello.txt.route.toml",
            br#"abi = "component"
component = "app/echo/hello.txt.wasm"
"#,
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("modules/ or components/"));
    }

    #[test]
    fn v2_route_sidecar_still_requires_valid_route_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "app/echo/message.txt.wasm", b"not wasm");
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.route.toml",
            br#"abi = "component"
component = "modules/message.wasm"
"#,
        );
        write_package_file(
            tmp.path(),
            "modules/message.wasm",
            route_component_metadata(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid route wasm"));
    }

    #[test]
    fn v2_route_sidecar_rejects_mismatched_generated_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.wasm",
            route_component_no_imports(),
        );
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.route.toml",
            br#"abi = "component"
component = "modules/message.wasm"
"#,
        );
        write_package_file(
            tmp.path(),
            "modules/message.wasm",
            route_component_metadata(),
        );
        write_package_file(
            tmp.path(),
            "artifacts/routes/r000001.wasm",
            route_component_no_imports(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match route sidecar composition")
        );
    }

    #[test]
    fn v2_route_sidecar_rejects_missing_import_component() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.wasm",
            route_component_no_imports(),
        );
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.route.toml",
            br#"abi = "component"
component = "modules/message.wasm"
imports = ["components/missing.wasm"]
"#,
        );
        write_package_file(
            tmp.path(),
            "modules/message.wasm",
            route_component_metadata(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("components/missing.wasm"));
    }

    #[test]
    fn v2_route_sidecar_composes_package_local_import_alias() {
        let root = wat::parse_str(
            r#"
(component
  (import "bloom:echo/helper@0.1.0" (instance))
)
"#,
        )
        .unwrap();
        let helper = wat::parse_str(
            r#"
(component
  (instance)
  (export "bloom:echo/helper@0.1.0" (instance 0))
)
"#,
        )
        .unwrap();
        let files = normalize_files(vec![
            NormalizedPackageFile {
                path: "components/helper.wasm".into(),
                bytes: helper,
            },
            NormalizedPackageFile {
                path: "modules/root.wasm".into(),
                bytes: root.clone(),
            },
        ])
        .unwrap();
        let sidecar = RouteSidecar {
            path: "app/echo/message.txt.route.toml".into(),
            app_name: "echo".into(),
            abi: RouteSidecarAbi::Component,
            component: "modules/root.wasm".into(),
            imports: vec!["components/helper.wasm".into()],
            ops: Vec::new(),
        };

        let composed = route_sidecar_artifact(&files, "r000001", &sidecar).unwrap();
        Validator::new().validate_all(&composed).unwrap();
        assert_ne!(blake3::hash(&root), blake3::hash(&composed));
    }

    #[test]
    fn v2_route_sidecar_builds_route_with_package_local_import() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.wasm",
            route_component_package_import(),
        );
        write_package_file(
            tmp.path(),
            "app/echo/message.txt.route.toml",
            br#"abi = "component"
component = "modules/message.wasm"
imports = ["components/helper.wasm"]
"#,
        );
        write_package_file(
            tmp.path(),
            "modules/message.wasm",
            route_component_package_import(),
        );
        write_package_file(
            tmp.path(),
            "components/helper.wasm",
            &package_local_helper_component(),
        );

        let package = build_app_package_dir(tmp.path()).unwrap();
        let route = &package.route_index.routes[0];
        let artifact = std::fs::read(tmp.path().join(&route.artifact_path)).unwrap();
        Validator::new().validate_all(&artifact).unwrap();
        assert_ne!(
            blake3::hash(route_component_package_import()),
            blake3::hash(&artifact)
        );
        assert_eq!(
            route.artifact_hash,
            hex::encode(blake3::hash(&artifact).as_bytes())
        );
    }

    #[test]
    fn v2_tar_rejects_duplicate_and_traversal_paths() {
        let duplicate =
            PreparedAppPackage::from_reader(std::io::Cursor::new(package_tar_bytes(vec![
                (
                    "petal.toml",
                    br#"schema = "bloom.petal.local-app.v2" name = "x""#,
                ),
                (
                    "petal.toml",
                    br#"schema = "bloom.petal.local-app.v2" name = "x""#,
                ),
            ])))
            .unwrap_err();
        assert!(
            duplicate
                .to_string()
                .contains("duplicate v2 package archive path")
        );

        let traversal = PreparedAppPackage::from_reader(std::io::Cursor::new(
            raw_package_tar_bytes("../petal.toml", b"x"),
        ))
        .unwrap_err();
        assert!(traversal.to_string().contains("invalid v2 package path"));
    }

    #[test]
    fn v2_tar_rejects_non_normal_mode_and_metadata() {
        let bad_mode = PreparedAppPackage::from_reader(std::io::Cursor::new(
            raw_package_tar_entry("petal.toml", b"x", 0o777, 0, 0, 0),
        ))
        .unwrap_err();
        assert!(bad_mode.to_string().contains("unsupported mode"));

        let bad_owner = PreparedAppPackage::from_reader(std::io::Cursor::new(
            raw_package_tar_entry("petal.toml", b"x", 0o644, 1, 0, 0),
        ))
        .unwrap_err();
        assert!(bad_owner.to_string().contains("nonzero owner"));

        let bad_mtime = PreparedAppPackage::from_reader(std::io::Cursor::new(
            raw_package_tar_entry("petal.toml", b"x", 0o644, 0, 0, 1),
        ))
        .unwrap_err();
        assert!(bad_mtime.to_string().contains("nonzero mtime"));

        let bad_names = PreparedAppPackage::from_reader(std::io::Cursor::new(
            raw_tar_entry_with_names("petal.toml", b"x", "user", "group"),
        ))
        .unwrap_err();
        assert!(bad_names.to_string().contains("textual owner metadata"));

        let malformed_uid = PreparedAppPackage::from_reader(std::io::Cursor::new(
            raw_tar_entry_with_malformed_uid("petal.toml", b"x"),
        ))
        .unwrap_err();
        assert!(malformed_uid.to_string().contains("invalid uid"));

        let bad_atime = PreparedAppPackage::from_reader(std::io::Cursor::new(
            raw_tar_entry_with_times("petal.toml", b"x", 1, 0),
        ))
        .unwrap_err();
        assert!(bad_atime.to_string().contains("nonzero atime/ctime"));
    }

    #[test]
    fn v2_tar_rejects_bad_or_duplicate_directory_entries() {
        let bad_dir = PreparedAppPackage::from_reader(std::io::Cursor::new(raw_dir_tar_entry(
            "../bad/", 0o755,
        )))
        .unwrap_err();
        assert!(bad_dir.to_string().contains("invalid v2 package path"));

        let duplicate_dir =
            PreparedAppPackage::from_reader(std::io::Cursor::new(raw_multi_entry_tar(vec![
                RawTarEntry::dir("app/", 0o755),
                RawTarEntry::dir("app/", 0o755),
            ])))
            .unwrap_err();
        assert!(
            duplicate_dir
                .to_string()
                .contains("duplicate v2 package archive path")
        );

        let empty_segment_dir = PreparedAppPackage::from_reader(std::io::Cursor::new(
            raw_dir_tar_entry("app//", 0o755),
        ))
        .unwrap_err();
        assert!(
            empty_segment_dir
                .to_string()
                .contains("invalid v2 package path")
        );
    }

    #[test]
    fn v2_tar_rejects_pax_extension_entries() {
        let pax = PreparedAppPackage::from_reader(std::io::Cursor::new(raw_multi_entry_tar(vec![
            RawTarEntry::pax("pax", b"13 atime=1\n"),
            RawTarEntry::file("petal.toml", b"x", 0o644, 0, 0, 0),
        ])))
        .unwrap_err();
        assert!(pax.to_string().contains("unsupported extended metadata"));
    }

    #[test]
    fn v2_rejects_extra_app_roots() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package(tmp.path());
        write_package_file(
            tmp.path(),
            "app/other/hello.txt.wasm",
            route_component_no_imports(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("extra app root"));
    }

    #[test]
    fn v2_special_route_files_normalize_patterns() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
            route_component_no_imports(),
        );
        std::fs::rename(
            tmp.path().join("app/echo/hello.txt.wasm"),
            tmp.path().join("app/echo/$index.wasm"),
        )
        .unwrap();
        write_package_file(
            tmp.path(),
            "app/echo/items/$list.wasm",
            route_component_no_imports(),
        );
        write_package_file(
            tmp.path(),
            "app/echo/items/[id]/$lookup.wasm",
            route_component_no_imports(),
        );

        let package = PetalAppPackage::scan_dir(tmp.path()).unwrap();
        let patterns = package
            .routes
            .iter()
            .map(|route| route.pattern.as_str())
            .collect::<Vec<_>>();
        assert_eq!(patterns, vec!["", "items/$list", "items/[id]/$lookup"]);
    }

    #[test]
    fn v2_root_index_route_matches_empty_path() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "app/echo/$index.wasm", b"\0asm");

        let package = PetalAppPackage::scan_dir(tmp.path()).unwrap();
        let matched = package.match_route("").unwrap();
        assert_eq!(matched.route.pattern, "");
    }

    #[test]
    fn v2_component_routes_are_validated_as_bloom_route_010() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(tmp.path(), route_component_no_imports());

        let package = PreparedAppPackage::from_dir(tmp.path()).unwrap();
        let route = &package.route_index.routes[0];
        assert_eq!(route.abi, RouteAbi::ComponentBloomRoute010);
        assert!(route.install_metadata.required_caps.is_empty());
    }

    #[test]
    fn v2_static_component_metadata_is_cached_in_route_index() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(tmp.path(), route_component_metadata());

        let package = PreparedAppPackage::from_dir(tmp.path()).unwrap();
        let route = &package.route_index.routes[0];
        let metadata = &route.install_metadata;
        assert_eq!(metadata.mode, 0o640);
        assert_eq!(metadata.cache_ttl_ms, Some(2000));
        assert!(metadata.side_effecting_read);
        assert!(metadata.write_async);
        assert!(!metadata.executable);
        assert!(metadata.required_caps.is_empty());
        assert_eq!(metadata.sign_intent, None);
        assert!(route.ops.contains(&RouteOp::Write));
    }

    #[test]
    fn v2_static_component_metadata_rejects_executable_routes() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(tmp.path(), route_component_executable());

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("executable=true"));
    }

    #[test]
    fn v2_runtime_component_metadata_can_only_narrow_install_metadata() {
        let route = RouteIndexRecord {
            route_id: "r000001".into(),
            pattern: "[name].txt".into(),
            source_path: "app/echo/[name].txt.wasm".into(),
            artifact_path: "artifacts/routes/r000001.wasm".into(),
            artifact_hash: "00".repeat(32),
            abi: RouteAbi::ComponentBloomRoute010,
            kind: RouteEntryKind::File,
            ops: vec![RouteOp::Lookup, RouteOp::Read, RouteOp::Write],
            params: vec!["name".into()],
            specificity: [1, 0, 1],
            install_metadata: InstallRouteMetadata {
                mode: 0o666,
                cache_ttl_ms: Some(5000),
                side_effecting_read: true,
                write_async: true,
                executable: false,
                required_caps: vec!["bloom:http".into(), "bloom:store".into()],
                sign_intent: None,
            },
        };
        let metadata = ComponentRouteMetadata {
            kind: ComponentRouteEntryKind::File,
            mode: 0o444,
            cache_ttl_ms: Some(1000),
            side_effecting_read: false,
            write_async: false,
            executable: false,
            required_caps: vec!["bloom:store".into()],
            sign_intent: None,
        };

        let narrowed = narrow_runtime_route_metadata(&route, &metadata, &BTreeSet::new()).unwrap();
        assert_eq!(narrowed.mode, 0o444);
        assert_eq!(narrowed.cache_ttl_ms, Some(1000));
        assert_eq!(narrowed.required_caps, vec!["bloom:store".to_string()]);
    }

    #[test]
    fn v2_runtime_component_metadata_rejects_widening() {
        let route = RouteIndexRecord {
            route_id: "r000001".into(),
            pattern: "[name].txt".into(),
            source_path: "app/echo/[name].txt.wasm".into(),
            artifact_path: "artifacts/routes/r000001.wasm".into(),
            artifact_hash: "00".repeat(32),
            abi: RouteAbi::ComponentBloomRoute010,
            kind: RouteEntryKind::File,
            ops: vec![RouteOp::Lookup, RouteOp::Read],
            params: vec!["name".into()],
            specificity: [1, 0, 1],
            install_metadata: InstallRouteMetadata {
                mode: 0o444,
                cache_ttl_ms: None,
                side_effecting_read: false,
                write_async: false,
                executable: false,
                required_caps: vec!["bloom:store".into()],
                sign_intent: None,
            },
        };
        let metadata = ComponentRouteMetadata {
            kind: ComponentRouteEntryKind::File,
            mode: 0o644,
            cache_ttl_ms: Some(1000),
            side_effecting_read: false,
            write_async: false,
            executable: false,
            required_caps: vec!["bloom:store".into()],
            sign_intent: None,
        };

        let err = narrow_runtime_route_metadata(&route, &metadata, &BTreeSet::new()).unwrap_err();
        assert!(err.to_string().contains("widens install-time mode"));
    }

    #[test]
    fn v2_component_routes_reject_wrong_route_export_signatures() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(
            tmp.path(),
            &route_component(&["metadata", "lookup", "read"], &[]),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid bloom:route@0.1.0"));
    }

    #[test]
    fn v2_component_routes_require_metadata_export() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(tmp.path(), &route_component(&["read"], &[]));

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("metadata export"));
    }

    #[test]
    fn v2_component_routes_ignore_nested_route_exports_for_abi_validation() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(tmp.path(), &route_component_with_nested_route_exports());

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("metadata export"));
    }

    #[test]
    fn v2_component_routes_require_handler_for_route_kind() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "app/echo/$list.wasm",
            &route_component(&["metadata", "read"], &[]),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("\"list\" export"));
    }

    #[test]
    fn v2_component_regular_file_routes_require_lookup_and_read_exports() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(tmp.path(), &route_component(&["metadata", "read"], &[]));

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("\"lookup\" export"));
    }

    #[test]
    fn v2_component_imports_require_declared_caps_and_record_them() {
        let wasm = route_component_http();

        let missing = tempfile::tempdir().unwrap();
        write_v2_package_with_route(missing.path(), wasm);
        let err = PreparedAppPackage::from_dir(missing.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires missing petal.toml cap bloom:http")
        );

        let allowed = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            allowed.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:http"]
"#,
            wasm,
        );
        let package = PreparedAppPackage::from_dir(allowed.path()).unwrap();
        assert_eq!(
            package.route_index.routes[0].install_metadata.required_caps,
            vec!["bloom:http".to_string()]
        );
    }

    #[test]
    fn v2_component_chain_imports_fail_closed_until_host_exists() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:chain"]
"#,
            &route_component(&["metadata", "read"], &["bloom:chain/read@0.1.0"]),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported host item"));
        assert!(err.to_string().contains("bloom:chain/read@0.1.0"));
    }

    #[test]
    fn v2_component_imports_require_exact_bloom_wit_versions() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:http"]
"#,
            &route_component(&["metadata", "read"], &["bloom:http/fetch@999.0.0"]),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported host item"));
    }

    #[test]
    fn v2_component_imports_must_be_interface_instances() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:http"]
"#,
            &route_component_with_func_import("bloom:http/fetch@0.1.0"),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("must be an interface instance"));
    }

    #[test]
    fn v2_component_imports_require_bloom_wit_interface_shapes() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:http"]
"#,
            &route_component(&["metadata", "read"], &["bloom:http/fetch@0.1.0"]),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid Bloom WIT interface shape")
        );
    }

    #[test]
    fn v2_component_routes_reject_non_bloom_imports() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(
            tmp.path(),
            &route_component(&["metadata", "read"], &["wasi:http/outgoing-handler@0.2.0"]),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported host item"));
    }

    #[test]
    fn v2_component_sign_imports_require_intent_policy() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:sign"]
"#,
            route_component_sign(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("[sign].allowed_intents"));

        let allowed = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            allowed.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:sign"]

[sign]
allowed_intents = ["test.intent"]
"#,
            route_component_sign(),
        );

        let package = PreparedAppPackage::from_dir(allowed.path()).unwrap();
        assert_eq!(
            package.route_index.routes[0].install_metadata.required_caps,
            vec!["bloom:sign".to_string()]
        );
    }

    #[test]
    fn v2_store_cap_requires_declared_namespaces() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:store"]
"#,
            route_component_no_imports(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("[store].namespaces"));

        let allowed = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            allowed.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:store"]

[store]
namespaces = ["orders"]
secret_namespaces = ["credentials"]
"#,
            route_component_no_imports(),
        );
        let policy = store_policy_from_v2_manifest_toml(
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:store"]

[store]
namespaces = ["orders"]
secret_namespaces = ["credentials"]
"#,
        )
        .unwrap();
        assert!(policy.namespaces().contains("orders"));
        assert!(policy.namespaces().contains("credentials"));
        assert!(policy.secret_namespaces().contains("credentials"));
        PreparedAppPackage::from_dir(allowed.path()).unwrap();
    }

    #[test]
    fn v2_store_namespaces_reject_ambiguous_path_segments() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:store"]

[store]
namespaces = ["orders/archive"]
"#,
            route_component_no_imports(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported byte"));

        let drive = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            drive.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:store"]

[store]
namespaces = ["C:"]
"#,
            route_component_no_imports(),
        );

        let err = PreparedAppPackage::from_dir(drive.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported byte"));
    }

    fn write_package_file(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn write_v2_package(root: &Path) {
        write_v2_package_with_route(root, route_component_no_imports());
    }

    fn write_v2_package_with_route(root: &Path, route: &[u8]) {
        write_v2_package_with_manifest_and_route(
            root,
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
            route,
        );
    }

    fn write_v2_package_with_manifest_and_route(root: &Path, manifest: &[u8], route: &[u8]) {
        write_package_file(root, "petal.toml", manifest);
        write_package_file(root, "README.md", b"# echo");
        write_package_file(root, "AGENTS.md", b"# echo agents");
        write_package_file(root, "app/echo/hello.txt.wasm", route);
    }

    fn route_component_no_imports() -> &'static [u8] {
        include_bytes!("../tests/fixtures/route_component_no_imports.wasm")
    }

    fn route_component_http() -> &'static [u8] {
        include_bytes!("../tests/fixtures/route_component_http.wasm")
    }

    fn route_component_sign() -> &'static [u8] {
        include_bytes!("../tests/fixtures/route_component_sign.wasm")
    }

    fn route_component_metadata() -> &'static [u8] {
        include_bytes!("../tests/fixtures/route_component_metadata.wasm")
    }

    fn route_component_package_import() -> &'static [u8] {
        include_bytes!("../tests/fixtures/route_component_package_import.wasm")
    }

    fn route_component_executable() -> &'static [u8] {
        include_bytes!("../tests/fixtures/route_component_executable.wasm")
    }

    fn package_local_helper_component() -> Vec<u8> {
        wat::parse_str(
            r#"
(component
  (instance)
  (export "bloom:echo/helper@0.1.0" (instance 0))
)
"#,
        )
        .unwrap()
    }

    fn route_component(exports: &[&str], imports: &[&str]) -> Vec<u8> {
        route_component_builder(exports, imports).finish()
    }

    fn route_component_with_func_import(import: &str) -> Vec<u8> {
        let mut builder = ComponentBuilder::default();
        let (func_type, mut ty) = builder.type_function();
        ty.params(std::iter::empty::<(&str, PrimitiveValType)>())
            .results(std::iter::empty::<(&str, PrimitiveValType)>());
        builder.import(import, ComponentTypeRef::Func(func_type));
        builder.finish()
    }

    fn route_component_with_nested_route_exports() -> Vec<u8> {
        let mut builder = ComponentBuilder::default();
        builder.component(route_component_builder(&["metadata", "read"], &[]));
        builder.finish()
    }

    fn route_component_builder(exports: &[&str], imports: &[&str]) -> ComponentBuilder {
        let mut builder = ComponentBuilder::default();
        let (func_type, mut ty) = builder.type_function();
        ty.params(std::iter::empty::<(&str, PrimitiveValType)>())
            .results(std::iter::empty::<(&str, PrimitiveValType)>());

        let instance_type = builder.type_instance(&InstanceType::new());
        for import in imports {
            builder.import(import, ComponentTypeRef::Instance(instance_type));
        }

        let module = route_component_core_module(exports);
        let module = builder.core_module(&module);
        let instance = builder.core_instantiate(module, std::iter::empty::<(&str, _)>());
        for export in exports {
            let core_func = builder.core_alias_export(
                instance,
                &format!("__bloom_route_{export}"),
                ExportKind::Func,
            );
            let func =
                builder.lift_func(core_func, func_type, std::iter::empty::<CanonicalOption>());
            builder.export(export, ComponentExportKind::Func, func, None);
        }
        builder
    }

    fn route_component_core_module(exports: &[&str]) -> Module {
        let mut types = TypeSection::new();
        types.ty().function([], []);

        let mut functions = FunctionSection::new();
        let mut export_section = ExportSection::new();
        let mut code = CodeSection::new();
        for (idx, export) in exports.iter().enumerate() {
            functions.function(0);
            export_section.export(
                &format!("__bloom_route_{export}"),
                ExportKind::Func,
                idx as u32,
            );
            let mut function = Function::new([]);
            function.instruction(&Instruction::End);
            code.function(&function);
        }

        let mut module = Module::new();
        module
            .section(&types)
            .section(&functions)
            .section(&export_section)
            .section(&code);
        module
    }

    fn package_tar_bytes(entries: Vec<(&str, &[u8])>) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut out);
            for (path, body) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(0);
                set_gnu_times(&mut header, 0, 0);
                header.set_cksum();
                builder.append_data(&mut header, path, body).unwrap();
            }
            builder.finish().unwrap();
        }
        out
    }

    fn raw_package_tar_bytes(path: &str, body: &[u8]) -> Vec<u8> {
        raw_package_tar_entry(path, body, 0o644, 0, 0, 0)
    }

    fn raw_package_tar_entry(
        path: &str,
        body: &[u8],
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
    ) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_gid(gid);
        header.set_mtime(mtime);
        set_gnu_times(&mut header, 0, 0);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_cksum();

        let mut out = Vec::new();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(body);
        let pad = (512 - (body.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0, pad));
        out.extend(std::iter::repeat_n(0, 1024));
        out
    }

    fn raw_tar_entry_with_names(
        path: &str,
        body: &[u8],
        username: &str,
        groupname: &str,
    ) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        set_gnu_times(&mut header, 0, 0);
        header.set_username(username).unwrap();
        header.set_groupname(groupname).unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_cksum();

        let mut out = Vec::new();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(body);
        let pad = (512 - (body.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0, pad));
        out.extend(std::iter::repeat_n(0, 1024));
        out
    }

    fn raw_tar_entry_with_malformed_uid(path: &str, body: &[u8]) -> Vec<u8> {
        let mut out = raw_package_tar_entry(path, body, 0o644, 0, 0, 0);
        out[108..116].copy_from_slice(b"zzzzzzz\0");
        out[148..156].fill(b' ');
        let checksum: u32 = out[..512]
            .iter()
            .enumerate()
            .map(|(idx, byte)| {
                if (148..156).contains(&idx) {
                    b' ' as u32
                } else {
                    *byte as u32
                }
            })
            .sum();
        let checksum = format!("{checksum:06o}\0 ");
        out[148..156].copy_from_slice(checksum.as_bytes());
        out
    }

    fn raw_tar_entry_with_times(path: &str, body: &[u8], atime: u64, ctime: u64) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.as_gnu_mut().unwrap().set_atime(atime);
        header.as_gnu_mut().unwrap().set_ctime(ctime);
        header.set_entry_type(tar::EntryType::Regular);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        header.set_cksum();

        let mut out = Vec::new();
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(body);
        let pad = (512 - (body.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0, pad));
        out.extend(std::iter::repeat_n(0, 1024));
        out
    }

    fn raw_dir_tar_entry(path: &str, mode: u32) -> Vec<u8> {
        raw_multi_entry_tar(vec![RawTarEntry::dir(path, mode)])
    }

    struct RawTarEntry<'a> {
        path: &'a str,
        body: &'a [u8],
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
        ty: tar::EntryType,
    }

    impl<'a> RawTarEntry<'a> {
        fn file(path: &'a str, body: &'a [u8], mode: u32, uid: u64, gid: u64, mtime: u64) -> Self {
            Self {
                path,
                body,
                mode,
                uid,
                gid,
                mtime,
                ty: tar::EntryType::Regular,
            }
        }

        fn dir(path: &'a str, mode: u32) -> Self {
            Self {
                path,
                body: b"",
                mode,
                uid: 0,
                gid: 0,
                mtime: 0,
                ty: tar::EntryType::Directory,
            }
        }

        fn pax(path: &'a str, body: &'a [u8]) -> Self {
            Self {
                path,
                body,
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                ty: tar::EntryType::XHeader,
            }
        }
    }

    fn raw_multi_entry_tar(entries: Vec<RawTarEntry<'_>>) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(entry.body.len() as u64);
            header.set_mode(entry.mode);
            header.set_uid(entry.uid);
            header.set_gid(entry.gid);
            header.set_mtime(entry.mtime);
            set_gnu_times(&mut header, 0, 0);
            header.set_entry_type(entry.ty);
            header.as_mut_bytes()[..entry.path.len()].copy_from_slice(entry.path.as_bytes());
            header.set_cksum();
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(entry.body);
            let pad = (512 - (entry.body.len() % 512)) % 512;
            out.extend(std::iter::repeat_n(0, pad));
        }
        out.extend(std::iter::repeat_n(0, 1024));
        out
    }

    fn set_gnu_times(header: &mut tar::Header, atime: u64, ctime: u64) {
        let gnu = header.as_gnu_mut().unwrap();
        gnu.set_atime(atime);
        gnu.set_ctime(ctime);
    }
}
