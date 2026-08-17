//! Experimental Petal file-driven Petal package scanner.
//!
//! This is intentionally incremental: it scans `petal/<name>/.../*.wasm`
//! route trees and prepares content-addressed package records. Route
//! artifacts must be `bloom:route@0.1.0` components.

use std::collections::{BTreeMap, BTreeSet};
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
    ComponentFuncType, ComponentOuterAliasKind, ComponentType,
    ComponentTypeRef as WasmComponentTypeRef, ComponentValType, InstanceTypeDeclaration, Parser,
    Payload, PrimitiveValType as ComponentPrimitiveValType, TypeBounds as WasmComponentTypeBounds,
    Validator,
};

use crate::error::PetalError;
use crate::host::DenyHost;
use crate::policy::StoreNamespacePolicy;
use crate::vm::{ComponentRouteEntryKind, ComponentRouteMetadata, PetalVm, RunOptions};

pub use bloom_petal_contract::{BUILD_MANIFEST_SCHEMA, ROUTE_INDEX_SCHEMA, ROUTE_PACKAGE};
use bloom_petal_contract::{
    HostInterface as ContractHostInterface, PACKAGE_DIGEST_PREFIX, PACKAGE_SCHEMA,
};
const TAR_NAME_LEN: usize = 100;
const TAR_PREFIX_LEN: usize = 155;

pub fn contract_wit_digest() -> String {
    bloom_petal_contract::wit_digest()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalPackage {
    pub name: String,
    pub petal_root: String,
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
#[serde(deny_unknown_fields)]
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
    key: KeyPolicyToml,
    #[serde(default)]
    store: StorePolicyToml,
    #[serde(default, rename = "source")]
    _source: Option<SourcePolicyToml>,
    #[serde(default, rename = "build")]
    _build: Option<BuildPolicyToml>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentPolicy {
    #[serde(default)]
    summary: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PetalCaps {
    #[serde(default)]
    allowed: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetPolicyToml {
    #[serde(default)]
    allow: Vec<NetAllowToml>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetAllowToml {
    #[serde(default)]
    binding: Option<String>,
    host: String,
    #[serde(default)]
    methods: Vec<String>,
    paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignPolicy {
    #[serde(default)]
    allowed_intents: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPolicyToml {
    #[serde(default, rename = "derive")]
    derive_routes: Vec<KeyDerivePolicyToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyDerivePolicyToml {
    route: String,
    operation_classes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorePolicyToml {
    #[serde(default)]
    namespaces: Vec<String>,
    #[serde(default)]
    secret_namespaces: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePolicyToml {
    #[serde(rename = "kind")]
    _kind: String,
    #[serde(rename = "repository")]
    _repository: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildPolicyToml {
    #[serde(rename = "command")]
    _command: String,
    #[serde(default, rename = "outputs")]
    _outputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestNetRule {
    pub binding: Option<String>,
    pub host: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
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
pub struct PreparedPetalPackage {
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
    petal_name: String,
    abi: RouteSidecarAbi,
    component: String,
    imports: Vec<String>,
    ops: Vec<RouteOp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalConsentSummary {
    pub name: String,
    pub petal_mount: String,
    pub package_summary: Option<String>,
    pub docs: Vec<String>,
    pub capabilities: Vec<String>,
    pub network: Vec<PetalConsentNetRule>,
    pub sign_intents: Vec<String>,
    pub store_namespaces: Vec<PetalConsentStoreNamespace>,
    pub routes: Vec<PetalConsentRoute>,
}

/// Agent-facing identity and capability metadata retained in an installed
/// package's `source/petal.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalDiscovery {
    pub name: String,
    pub summary: Option<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalConsentNetRule {
    pub binding: Option<String>,
    pub host: String,
    /// Operator-configured HTTPS origin replacing `host` for this binding.
    /// `None` means the declared host remains effective.
    pub effective_origin: Option<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalConsentStoreNamespace {
    pub namespace: String,
    pub secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetalConsentRoute {
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
    pub petal_root: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_derive_operation_classes: Vec<String>,
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

impl PetalPackage {
    pub fn scan_dir(root: impl AsRef<Path>) -> Result<Self, PetalError> {
        let root = root.as_ref();
        require_file(root.join("petal.toml"))?;
        require_file(root.join("README.md"))?;
        require_file(root.join("AGENTS.md"))?;

        let petal_toml = std::fs::read_to_string(root.join("petal.toml"))?;
        let manifest: PetalToml = toml::from_str(&petal_toml)?;
        validate_petal_name(&manifest.name)?;

        let petal_root = root.join("petal").join(&manifest.name);
        if !petal_root.is_dir() {
            return Err(PetalError::InvalidWasm(format!(
                "Petal package missing petal/{}/ route root",
                manifest.name
            )));
        }

        let mut routes = Vec::new();
        scan_routes(&petal_root, &petal_root, &mut routes)?;
        routes.sort_by(|a, b| a.pattern.cmp(&b.pattern));
        for (idx, route) in routes.iter_mut().enumerate() {
            route.route_id = format!("r{:06}", idx + 1);
        }
        validate_route_conflicts(&routes)?;

        Ok(Self {
            name: manifest.name.clone(),
            petal_root: manifest.name,
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

impl PreparedPetalPackage {
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
        if manifest.schema.as_deref() != Some(PACKAGE_SCHEMA) {
            return Err(PetalError::InvalidWasm(format!(
                "Petal package petal.toml must set schema = {PACKAGE_SCHEMA:?}"
            )));
        }
        validate_petal_name(&manifest.name)?;
        file_bytes(&files, "README.md")?;
        file_bytes(&files, "AGENTS.md")?;
        let petal_root = format!("petal/{}", manifest.name);
        validate_single_petal_root(&files, &manifest.name)?;
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
        validate_net_policy(&allowed_caps, &manifest.net)?;
        let route_files = route_records_from_files(&files, &petal_root)?;
        if route_files.is_empty() {
            return Err(PetalError::InvalidWasm(format!(
                "Petal package petal/{}/ contains no .wasm routes",
                manifest.name
            )));
        }
        let key_derive_operation_classes =
            validate_key_derive_policy(&manifest.key, &route_files, &allowed_sign_intents)?;
        let policy_hash = hex::encode(blake3::hash(manifest_bytes).as_bytes());
        let mut route_index = RouteIndex {
            schema: ROUTE_INDEX_SCHEMA.to_string(),
            package_hash: hash.clone(),
            name: manifest.name.clone(),
            petal_root: manifest.name.clone(),
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
                        "Petal route sidecar {} declares {:?} but source route validates as {:?}",
                        sidecar.path, sidecar.abi, source_validation.abi
                    )));
                }
                let sidecar_source_validation = validate_route_wasm_with_package_imports(
                    &source_path,
                    file_bytes(&files, &sidecar.component)?,
                    &allowed_caps,
                    &allowed_sign_intents,
                    &package_imports,
                )?;
                if sidecar_source_validation.abi != source_validation.abi {
                    return Err(PetalError::InvalidWasm(format!(
                        "Petal route sidecar {} component ABI does not match source route",
                        sidecar.path
                    )));
                }
                let artifact_validation = validate_composed_route_artifact_wasm(
                    &source_path,
                    &artifact_bytes,
                    &allowed_caps,
                    &allowed_sign_intents,
                )?;
                if artifact_validation.abi != source_validation.abi {
                    return Err(PetalError::InvalidWasm(format!(
                        "Petal package artifact {} ABI does not match source route",
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
                            "Petal package artifact {} ABI/caps do not match source route",
                            route.route_id
                        )));
                    }
                }
                source_validation
            };
            let route_key_derive_operation_classes = key_derive_operation_classes
                .get(&route.pattern)
                .cloned()
                .unwrap_or_default();
            if !route_key_derive_operation_classes.is_empty()
                && !validation
                    .required_caps
                    .iter()
                    .any(|cap| cap == "bloom:key.derive")
            {
                return Err(PetalError::InvalidWasm(format!(
                    "Petal [[key.derive]] route {:?} does not import bloom:key.derive",
                    route.pattern
                )));
            }
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
            validate_writable_route_has_write_export(
                &route.route_id,
                kind,
                &ops,
                &install_metadata,
                &validation,
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
                key_derive_operation_classes: route_key_derive_operation_classes,
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
    petal_root: &str,
    route: &RouteRecord,
    route_kind: RouteEntryKind,
    validation: &RouteValidation,
    artifact_bytes: &[u8],
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<InstallRouteMetadata, PetalError> {
    let mut metadata = InstallRouteMetadata {
        // Conservative ceiling for routes whose metadata cannot be
        // evaluated at install time (parameterized routes): it must be
        // kind-compatible so runtime metadata can narrow it — a directory
        // needs traversal bits a file ceiling would strip.
        mode: if route_kind == RouteEntryKind::Dir {
            0o777
        } else if validation.abi == RouteAbi::ComponentBloomRoute010 && validation.has_write_export
        {
            0o666
        } else {
            0o444
        },
        cache_ttl_ms: None,
        side_effecting_read: validation.abi == RouteAbi::ComponentBloomRoute010
            && !route.params.is_empty(),
        write_async: validation.abi == RouteAbi::ComponentBloomRoute010
            && validation.has_write_export,
        executable: false,
        required_caps: validation.required_caps.clone(),
        sign_intent: None,
    };

    if validation.abi != RouteAbi::ComponentBloomRoute010 {
        return Ok(metadata);
    }
    if !route.params.is_empty()
        && !validation
            .required_caps
            .iter()
            .any(|cap| cap == "bloom:sign")
    {
        return Ok(metadata);
    }
    let component_metadata = evaluate_component_metadata(
        package_hash,
        petal_root,
        &route.pattern,
        artifact_bytes,
        route
            .params
            .iter()
            .map(|name| (name.clone(), "provenance".to_string()))
            .collect(),
    )?;
    validate_component_metadata_policy(
        &route.route_id,
        route_kind,
        &component_metadata,
        None,
        allowed_caps,
        allowed_sign_intents,
    )?;
    if component_metadata.sign_intent.is_some()
        && !validation
            .required_caps
            .iter()
            .any(|cap| cap == "bloom:sign")
    {
        return Err(PetalError::InvalidWasm(format!(
            "Petal route {} metadata sign_intent is not backed by a signing import",
            route.route_id
        )));
    }
    metadata.sign_intent = component_metadata.sign_intent.clone();
    if !route.params.is_empty() {
        return Ok(metadata);
    }
    metadata.mode = component_metadata.mode;
    metadata.cache_ttl_ms = component_metadata.cache_ttl_ms;
    metadata.side_effecting_read = component_metadata.side_effecting_read;
    metadata.write_async |= component_metadata.write_async;
    metadata.executable = component_metadata.executable;
    metadata.required_caps = component_metadata
        .required_caps
        .into_iter()
        .filter(|cap| validation.required_caps.contains(cap))
        .collect();
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
        Some(&install.required_caps),
        &install_caps,
        allowed_sign_intents,
    )?;
    if metadata.mode & !install.mode != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "Petal route {} runtime metadata mode widens install-time mode",
            route.route_id
        )));
    }
    if !install.side_effecting_read && metadata.side_effecting_read {
        return Err(PetalError::InvalidWasm(format!(
            "Petal route {} runtime metadata widens side-effecting-read",
            route.route_id
        )));
    }
    if !install.write_async && metadata.write_async {
        return Err(PetalError::InvalidWasm(format!(
            "Petal route {} runtime metadata widens write-async",
            route.route_id
        )));
    }
    match (install.cache_ttl_ms, metadata.cache_ttl_ms) {
        // Parameterized routes never evaluate component metadata at
        // install time, so their install-time `None` means "unevaluated"
        // rather than "not cacheable" and is not a TTL ceiling. Caching
        // still stays off for them: the router only caches through the
        // install metadata, which keeps `side_effecting_read = true`.
        (None, Some(_)) if route.params.is_empty() => {
            return Err(PetalError::InvalidWasm(format!(
                "Petal route {} runtime metadata widens cacheability",
                route.route_id
            )));
        }
        (Some(max), Some(ttl)) if ttl > max => {
            return Err(PetalError::InvalidWasm(format!(
                "Petal route {} runtime metadata widens cache ttl",
                route.route_id
            )));
        }
        _ => {}
    }
    if let Some(install_intent) = &install.sign_intent
        && metadata.sign_intent.as_ref() != Some(install_intent)
    {
        return Err(PetalError::InvalidWasm(format!(
            "Petal route {} runtime metadata widens sign intent",
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

fn evaluate_component_metadata(
    package_hash: &str,
    petal_root: &str,
    path: &str,
    artifact_bytes: &[u8],
    route_params: Vec<(String, String)>,
) -> Result<ComponentRouteMetadata, PetalError> {
    let wasm = artifact_bytes.to_vec();
    let package_hash = package_hash.to_string();
    let petal_root = petal_root.to_string();
    let path = path.to_string();
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
                    &petal_root,
                    &path,
                    route_params,
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
    required_cap_ceiling: Option<&[String]>,
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
            "Petal route {route_id} metadata kind {:?} does not match route kind {:?}",
            metadata_kind, route_kind
        )));
    }
    if metadata.executable {
        return Err(PetalError::InvalidWasm(format!(
            "Petal route {route_id} metadata executable=true is not supported"
        )));
    }
    if metadata.mode & !0o777 != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "Petal route {route_id} metadata mode must be a unix permission mode"
        )));
    }
    let cap_ceiling = required_cap_ceiling.map(|caps| caps.iter().collect::<BTreeSet<_>>());
    for cap in &metadata.required_caps {
        if !allowed_caps.contains(cap) {
            return Err(PetalError::InvalidWasm(format!(
                "Petal route {route_id} metadata requires missing petal.toml cap {cap}"
            )));
        }
        if cap_ceiling
            .as_ref()
            .is_some_and(|ceiling| !ceiling.contains(cap))
        {
            return Err(PetalError::InvalidWasm(format!(
                "Petal route {route_id} metadata required cap {cap} widens its capability ceiling"
            )));
        }
    }
    if let Some(intent) = &metadata.sign_intent {
        if !metadata.required_caps.iter().any(|cap| cap == "bloom:sign") {
            return Err(PetalError::InvalidWasm(format!(
                "Petal route {route_id} metadata sign_intent requires bloom:sign"
            )));
        }
        if !allowed_sign_intents.contains(intent) {
            return Err(PetalError::InvalidWasm(format!(
                "Petal route {route_id} metadata sign_intent {intent:?} is not allowed"
            )));
        }
        validate_sign_intent(intent)?;
    }
    Ok(())
}

pub fn sign_intents_from_manifest_toml(bytes: &[u8]) -> Result<BTreeSet<String>, PetalError> {
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

pub(crate) fn net_rules_from_manifest_toml(
    bytes: &[u8],
) -> Result<Vec<ManifestNetRule>, PetalError> {
    let manifest_toml = std::str::from_utf8(bytes)
        .map_err(|_| PetalError::InvalidWasm("petal.toml is not utf-8".into()))?;
    let manifest: PetalToml = toml::from_str(manifest_toml)?;
    let allowed_caps = manifest
        .caps
        .allowed
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    validate_net_policy(&allowed_caps, &manifest.net)?;
    Ok(manifest
        .net
        .allow
        .into_iter()
        .map(|rule| ManifestNetRule {
            binding: rule.binding,
            host: rule.host,
            methods: rule.methods,
            paths: rule.paths,
        })
        .collect())
}

pub fn store_policy_from_manifest_toml(bytes: &[u8]) -> Result<StoreNamespacePolicy, PetalError> {
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

pub fn build_petal_package_dir(root: impl AsRef<Path>) -> Result<PreparedPetalPackage, PetalError> {
    build_petal_package_dir_guarded(root, || Ok(()))
}

pub fn build_petal_package_dir_guarded<F>(
    root: impl AsRef<Path>,
    commit_guard: F,
) -> Result<PreparedPetalPackage, PetalError>
where
    F: FnOnce() -> Result<(), PetalError>,
{
    let root = root.as_ref();
    PetalPackage::scan_dir(root)?;
    validate_generated_artifact_paths(root)?;
    let source_files = collect_package_dir(root)?
        .into_iter()
        .filter(|file| {
            file.path != "artifacts/build-manifest.json"
                && !file.path.starts_with("artifacts/routes/")
        })
        .collect::<Vec<_>>();
    let source_package = PreparedPetalPackage::from_files(source_files.clone())?;
    let manifest = build_manifest_for_package(&source_package)?;
    let parent = root
        .parent()
        .ok_or_else(|| PetalError::InvalidWasm("Petal package directory has no parent".into()))?;
    let staged = tempfile::tempdir_in(parent)?;

    for route in &source_package.route_index.routes {
        let artifact = route_artifact_bytes(&source_package, route)?;
        write_package_file(staged.path(), &route.artifact_path, &artifact)?;
    }
    write_package_file(
        staged.path(),
        "artifacts/build-manifest.json",
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    let mut final_files = source_files;
    final_files.extend(collect_package_dir(staged.path())?);
    let package = PreparedPetalPackage::from_files(final_files)?;

    commit_guard()?;
    commit_generated_artifacts(root, staged.path())?;
    Ok(package)
}

fn commit_generated_artifacts(root: &Path, staged_root: &Path) -> Result<(), PetalError> {
    let artifacts = root.join("artifacts");
    std::fs::create_dir_all(&artifacts)?;
    let backup =
        tempfile::tempdir_in(root.parent().ok_or_else(|| {
            PetalError::InvalidWasm("Petal package directory has no parent".into())
        })?)?;
    let routes = artifacts.join("routes");
    let manifest = artifacts.join("build-manifest.json");
    let backup_routes = backup.path().join("routes");
    let backup_manifest = backup.path().join("build-manifest.json");
    let staged_routes = staged_root.join("artifacts/routes");
    let staged_manifest = staged_root.join("artifacts/build-manifest.json");

    let had_routes = routes.exists();
    let had_manifest = manifest.exists();
    if had_routes {
        std::fs::rename(&routes, &backup_routes)?;
    }
    if had_manifest && let Err(error) = std::fs::rename(&manifest, &backup_manifest) {
        if had_routes {
            let _ = std::fs::rename(&backup_routes, &routes);
        }
        return Err(error.into());
    }

    let install_result = (|| -> Result<(), std::io::Error> {
        if staged_routes.exists() {
            std::fs::rename(&staged_routes, &routes)?;
        }
        std::fs::rename(&staged_manifest, &manifest)?;
        Ok(())
    })();
    if let Err(error) = install_result {
        let _ = std::fs::remove_dir_all(&routes);
        let _ = std::fs::remove_file(&manifest);
        if had_routes {
            let _ = std::fs::rename(&backup_routes, &routes);
        }
        if had_manifest {
            let _ = std::fs::rename(&backup_manifest, &manifest);
        }
        return Err(error.into());
    }
    Ok(())
}

pub fn petal_consent_summary(
    package: &PreparedPetalPackage,
) -> Result<PetalConsentSummary, PetalError> {
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
        .map(|namespace| PetalConsentStoreNamespace {
            secret: secret_namespaces.contains(&namespace),
            namespace,
        })
        .collect();

    let network = manifest
        .net
        .allow
        .into_iter()
        .map(|rule| PetalConsentNetRule {
            binding: rule.binding,
            host: rule.host,
            effective_origin: None,
            methods: rule
                .methods
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect(),
            paths: rule.paths,
        })
        .collect();

    let routes = package
        .route_index
        .routes
        .iter()
        .map(|route| PetalConsentRoute {
            path: if route.pattern.is_empty() {
                format!("/petals/{}", package.name)
            } else {
                format!("/petals/{}/{}", package.name, route.pattern)
            },
            kind: route.kind,
            ops: route.ops.clone(),
            required_caps: route.install_metadata.required_caps.clone(),
            cache_ttl_ms: route.install_metadata.cache_ttl_ms,
            side_effecting_read: route.install_metadata.side_effecting_read,
            write_async: route.install_metadata.write_async,
        })
        .collect();

    Ok(PetalConsentSummary {
        name: package.name.clone(),
        petal_mount: format!("petals/{}/", package.name),
        package_summary: manifest.consent.summary,
        docs: vec!["README.md".into(), "AGENTS.md".into()],
        capabilities,
        network,
        sign_intents,
        store_namespaces,
        routes,
    })
}

/// Read the discovery fields agents need directly from an installed package
/// manifest. Installed packages retain the validated source `petal.toml`, so
/// this remains the single source of truth for both consent and documentation.
pub fn petal_discovery_from_manifest_toml(bytes: &[u8]) -> Result<PetalDiscovery, PetalError> {
    let manifest_toml = std::str::from_utf8(bytes)
        .map_err(|_| PetalError::InvalidWasm("petal.toml is not utf-8".into()))?;
    let manifest: PetalToml = toml::from_str(manifest_toml)?;
    let mut capabilities = manifest.caps.allowed;
    capabilities.sort();
    capabilities.dedup();
    Ok(PetalDiscovery {
        name: manifest.name,
        summary: manifest.consent.summary,
        capabilities,
    })
}

/// Apply daemon-owned endpoint overrides to a consent summary while enforcing
/// that every configured binding was declared by the manifest. The declared
/// host remains visible alongside the effective origin.
pub fn apply_petal_consent_endpoint_bindings(
    summary: &mut PetalConsentSummary,
    bindings: &BTreeMap<String, String>,
) -> Result<(), PetalError> {
    for (binding, origin) in bindings {
        crate::policy::validate_binding_name(binding)?;
        crate::policy::endpoint_origin_host(origin)?;
        if !summary
            .network
            .iter()
            .any(|rule| rule.binding.as_deref() == Some(binding.as_str()))
        {
            return Err(PetalError::InvalidWasm(format!(
                "endpoint override {binding:?} is not declared by the petal manifest"
            )));
        }
    }
    for rule in &mut summary.network {
        rule.effective_origin = rule
            .binding
            .as_ref()
            .and_then(|binding| bindings.get(binding))
            .cloned();
    }
    Ok(())
}

fn build_manifest_for_package(package: &PreparedPetalPackage) -> Result<BuildManifest, PetalError> {
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
    package: &PreparedPetalPackage,
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
    petal_name: &str,
    route_id: &str,
    source_path: &str,
    artifact_path: &str,
) -> Result<Vec<u8>, PetalError> {
    let sidecar = route_sidecar(files, petal_name, source_path)?;
    let generated_artifact = optional_file_bytes(files, artifact_path);
    let expected = if let Some(sidecar) = sidecar {
        let expected = route_sidecar_artifact(files, route_id, &sidecar)?;
        if let Some(artifact) = generated_artifact {
            if blake3::hash(artifact) != blake3::hash(&expected) {
                return Err(PetalError::InvalidWasm(format!(
                    "Petal package artifact {route_id} does not match route sidecar composition"
                )));
            }
            return Ok(artifact.to_vec());
        }
        expected
    } else {
        let source = file_bytes(files, source_path)?;
        if let Some(artifact) = generated_artifact
            && artifact != source
        {
            return Err(PetalError::InvalidWasm(format!(
                "Petal package artifact {route_id} does not match its route source"
            )));
        }
        source.to_vec()
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
                "Petal route {route_id} component composition failed: {e}"
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
                "Petal route {route_id} sidecar maps dependency {name:?} to both {} and {}",
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
                "Petal route {route_id} sidecar import {import:?} has no utf-8 stem"
            ))
        })?;
    let mut names = vec![stem.to_string()];
    if let Some(path_alias) = import.strip_suffix(".wasm") {
        names.push(path_alias.to_string());
    }
    names.push(format!("bloom:{}/{stem}", sidecar.petal_name));
    names.push(format!("bloom:{}/{stem}@0.1.0", sidecar.petal_name));
    Ok(names)
}

fn route_sidecar(
    files: &[NormalizedPackageFile],
    petal_name: &str,
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
        .map_err(|_| PetalError::InvalidWasm(format!("Petal route sidecar {path} is not utf-8")))?;
    let parsed: RouteSidecarToml = toml::from_str(toml)?;
    validate_route_sidecar_path(&path, &parsed.component, true)?;
    for import in &parsed.imports {
        validate_route_sidecar_path(&path, import, false)?;
    }
    Ok(Some(RouteSidecar {
        path,
        petal_name: petal_name.to_string(),
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
            "Petal route sidecar {sidecar_path} path {rel:?} must be package-local under {}",
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
            "Petal route sidecar {sidecar_path} path {rel:?} must point to a .wasm component"
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
            "Petal package artifacts path must be a directory".into(),
        ));
    }

    let routes = artifacts.join("routes");
    if let Ok(meta) = std::fs::symlink_metadata(&routes)
        && !meta.is_dir()
    {
        return Err(PetalError::InvalidWasm(
            "Petal package artifacts/routes path must be a directory".into(),
        ));
    }

    let manifest = artifacts.join("build-manifest.json");
    if let Ok(meta) = std::fs::symlink_metadata(&manifest)
        && !meta.is_file()
    {
        return Err(PetalError::InvalidWasm(
            "Petal package artifacts/build-manifest.json path must be a file".into(),
        ));
    }
    Ok(())
}

fn route_kind_and_ops(source_path: &str) -> (RouteEntryKind, Vec<RouteOp>) {
    match source_path.rsplit('/').next().unwrap_or_default() {
        "$index.wasm" => (
            RouteEntryKind::Dir,
            vec![RouteOp::Lookup, RouteOp::List, RouteOp::Read],
        ),
        "$lookup.wasm" => (RouteEntryKind::File, vec![RouteOp::Lookup]),
        _ => (RouteEntryKind::File, vec![RouteOp::Lookup, RouteOp::Read]),
    }
}

fn validate_writable_route_has_write_export(
    route_id: &str,
    kind: RouteEntryKind,
    ops: &[RouteOp],
    install_metadata: &InstallRouteMetadata,
    validation: &RouteValidation,
) -> Result<(), PetalError> {
    if kind == RouteEntryKind::File
        && (ops.contains(&RouteOp::Write) || install_metadata.mode & 0o222 != 0)
        && !validation.has_write_export
    {
        return Err(PetalError::InvalidWasm(format!(
            "Petal route {route_id} advertises write but has no write export"
        )));
    }
    Ok(())
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

pub fn verify_prepared_package(package: &PreparedPetalPackage) -> Result<(), PetalError> {
    let files = normalize_files(package.files.clone())?;
    let rebuilt = PreparedPetalPackage::from_files(files)?;
    if package.hash != rebuilt.hash {
        return Err(PetalError::InvalidHash(package.hash.clone()));
    }
    if package.name != rebuilt.name || package.route_index != rebuilt.route_index {
        return Err(PetalError::InvalidWasm(
            "Petal prepared package route index does not match rebuilt package".into(),
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
            "invalid Petal package path {path:?}"
        )));
    }
    if !path_fits_ustar(path) {
        return Err(PetalError::InvalidWasm(format!(
            "Petal package path {path:?} is too long for strict .petal.tar archives"
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
        PetalError::InvalidWasm(format!("Petal package output path has no parent: {rel}"))
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
                "Petal package contains non-regular file {}",
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
                "duplicate Petal package archive path {:?}",
                normalized_path
            )));
        }
        if ty.is_dir() {
            continue;
        }
        if !ty.is_file() {
            return Err(PetalError::InvalidWasm(format!(
                "Petal package archive entry {:?} is not a regular file or directory",
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
            "Petal package archive entry {:?} uses unsupported extended metadata",
            path
        )));
    }
    let mode = header.mode().map_err(|e| {
        PetalError::InvalidWasm(format!(
            "Petal package archive entry {:?} has invalid mode: {e}",
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
                "Petal package archive file {:?} has unsupported mode {mode:o}",
                path
            )));
        }
    } else if ty.is_dir() && mode != 0o755 && mode != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "Petal package archive directory {:?} has unsupported mode {mode:o}",
            path
        )));
    }
    let uid = header.uid().map_err(|e| {
        PetalError::InvalidWasm(format!(
            "Petal package archive entry {:?} has invalid uid: {e}",
            path
        ))
    })?;
    let gid = header.gid().map_err(|e| {
        PetalError::InvalidWasm(format!(
            "Petal package archive entry {:?} has invalid gid: {e}",
            path
        ))
    })?;
    if uid != 0 || gid != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "Petal package archive entry {:?} has nonzero owner metadata",
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
            "Petal package archive entry {:?} has textual owner metadata",
            path
        )));
    }
    let mtime = header.mtime().map_err(|e| {
        PetalError::InvalidWasm(format!(
            "Petal package archive entry {:?} has invalid mtime: {e}",
            path
        ))
    })?;
    if mtime != 0 {
        return Err(PetalError::InvalidWasm(format!(
            "Petal package archive entry {:?} has nonzero mtime",
            path
        )));
    }
    if let Some(gnu) = header.as_gnu() {
        let atime = gnu.atime().map_err(|e| {
            PetalError::InvalidWasm(format!(
                "Petal package archive entry {:?} has invalid atime: {e}",
                path
            ))
        })?;
        let ctime = gnu.ctime().map_err(|e| {
            PetalError::InvalidWasm(format!(
                "Petal package archive entry {:?} has invalid ctime: {e}",
                path
            ))
        })?;
        if atime != 0 || ctime != 0 {
            return Err(PetalError::InvalidWasm(format!(
                "Petal package archive entry {:?} has nonzero atime/ctime",
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
                "invalid Petal package path {path:?}"
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
                "duplicate Petal package path {:?}",
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
        .ok_or_else(|| {
            PetalError::InvalidWasm(format!("Petal package missing required file {path}"))
        })
}

fn optional_file_bytes<'a>(files: &'a [NormalizedPackageFile], path: &str) -> Option<&'a [u8]> {
    files
        .binary_search_by(|file| file.path.as_str().cmp(path))
        .ok()
        .map(|idx| files[idx].bytes.as_slice())
}

fn route_records_from_files(
    files: &[NormalizedPackageFile],
    petal_root: &str,
) -> Result<Vec<RouteRecord>, PetalError> {
    let prefix = format!("{petal_root}/");
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
            "Petal package missing {petal_root}/ route root"
        )));
    }
    routes.sort_by(|a, b| a.pattern.as_bytes().cmp(b.pattern.as_bytes()));
    for (idx, route) in routes.iter_mut().enumerate() {
        route.route_id = format!("r{:06}", idx + 1);
    }
    validate_route_conflicts(&routes)?;
    Ok(routes)
}

fn validate_single_petal_root(
    files: &[NormalizedPackageFile],
    expected: &str,
) -> Result<(), PetalError> {
    for file in files {
        let Some(rest) = file.path.strip_prefix("petal/") else {
            continue;
        };
        let root = rest.split('/').next().unwrap_or_default();
        if root != expected {
            return Err(PetalError::InvalidWasm(format!(
                "Petal package has extra petal root {root:?}; expected only petal/{expected}/"
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
    if segments.is_empty() {
        return Err(PetalError::InvalidWasm("empty route path".into()));
    }
    if let Some(reserved) = segments[..segments.len() - 1]
        .iter()
        .find(|segment| segment.starts_with('$'))
    {
        return Err(PetalError::InvalidWasm(format!(
            "reserved route segment {reserved:?} is only allowed as a recognized route leaf"
        )));
    }
    let last = segments
        .last_mut()
        .expect("route path was checked as non-empty");
    let Some(last_without_wasm) = last.strip_suffix(".wasm") else {
        return Err(PetalError::InvalidWasm("route leaf is not .wasm".into()));
    };
    match last_without_wasm {
        "$index" => {
            segments.pop();
            Ok(segments.join("/"))
        }
        "$lookup" => {
            *last = last_without_wasm;
            Ok(segments.join("/"))
        }
        other if other.starts_with('$') => Err(PetalError::InvalidWasm(format!(
            "unsupported reserved route file {other}.wasm"
        ))),
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
            Payload::Version { encoding, .. } if current_depth == 0 => {
                saw_component |= matches!(encoding, wasmparser::Encoding::Component);
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
                    let name = import.name.name;
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
                    let mut caps = caps.to_vec();
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
                                ) =>
                            {
                                if matches!(interface, ComponentHostInterface::VfsReadwrite) {
                                    caps = vfs_readwrite_import_caps(type_index, &component_types);
                                }
                            }
                            (Some(_), _) => {
                                return Err(PetalError::InvalidWasm(format!(
                                    "{path}: component route import {name:?} has invalid Bloom WIT interface shape"
                                )));
                            }
                            (None, _) => {}
                        }
                        false
                    };
                    for cap in &caps {
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
                    let name = export.name.name;
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
        "{path}: Petal routes must be bloom:route@0.1.0 components"
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
        "$index.wasm" => &["lookup", "list", "read"],
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
    if matches!(
        name,
        "bloom:sign/signing@0.1.0" | "bloom:sign/signing@0.2.0"
    ) {
        return Some(&["bloom:sign"]);
    }
    if name == "bloom:key/derive@0.1.0" {
        return Some(&["bloom:key.derive"]);
    }
    bloom_petal_contract::capabilities_for_import(name)
}

#[derive(Clone, Copy)]
enum ComponentHostInterface {
    HttpFetch,
    StoreKv,
    SignSigningV1,
    SignSigningV2,
    KeyDerive,
    TxOutbox,
    ChainRead,
    VfsReadwrite,
    EnvRuntime,
}

fn component_host_interface(name: &str) -> Option<ComponentHostInterface> {
    if name == "bloom:sign/signing@0.1.0" {
        return Some(ComponentHostInterface::SignSigningV1);
    }
    if name == "bloom:sign/signing@0.2.0" {
        return Some(ComponentHostInterface::SignSigningV2);
    }
    if name == "bloom:key/derive@0.1.0" {
        return Some(ComponentHostInterface::KeyDerive);
    }
    match bloom_petal_contract::host_interface(name)? {
        ContractHostInterface::HttpFetch => Some(ComponentHostInterface::HttpFetch),
        ContractHostInterface::StoreKv => Some(ComponentHostInterface::StoreKv),
        ContractHostInterface::SignSigning => Some(ComponentHostInterface::SignSigningV2),
        ContractHostInterface::KeyDerive => Some(ComponentHostInterface::KeyDerive),
        ContractHostInterface::TxOutbox => Some(ComponentHostInterface::TxOutbox),
        ContractHostInterface::ChainRead => Some(ComponentHostInterface::ChainRead),
        ContractHostInterface::VfsReadwrite => Some(ComponentHostInterface::VfsReadwrite),
        ContractHostInterface::EnvRuntime => Some(ComponentHostInterface::EnvRuntime),
        ContractHostInterface::RouteTypes => None,
    }
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

    let Some(result_ty) = single_component_result(&ty.result) else {
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

fn single_component_result(result: &Option<ComponentValType>) -> Option<&ComponentValType> {
    result.as_ref()
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
                let Some(route_type) = component_route_type_import(name.name) else {
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
    EvmTransaction,
    OutboxApprovalRequired,
    StagedTransaction,
    OutboxInspection,
    SignApprovalRequired,
    SignApprovalPending,
    SignResultStructured,
    SafeSignResultStructured,
    SignRequestStructured,
    ScopedPayloadSignRequestStructured,
    PayloadSignItemStructured,
    PayloadBatchSignRequestStructured,
    PetalSignSelector,
    SignBatchResultStructured,
    PayloadBatchSignResultStructured,
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
    SignHashStructured,
    SignHashesStructured,
    SafeSignPayloadStructured,
    PayloadBatchSignStructured,
    PetalKeyRequest,
    EvmTxStage,
    EvmTxConfirm,
    EvmTxInspect,
    ChainCall,
    VfsLookup,
    VfsList,
    VfsRead,
    VfsWrite,
    EnvNowMs,
    EnvRandomBytes,
    EnvSetting,
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
                    let Some(expected) = host_type_export(interface, name.name) else {
                        return false;
                    };
                    if !host_type_export_matches(expected, index, &local_types)
                        || !exported_types.insert(name.name)
                    {
                        return false;
                    }
                    let Some(entry) = cloned_component_type_entry(&local_types, index) else {
                        return false;
                    };
                    local_types.push(entry);
                }
                WasmComponentTypeRef::Func(func_type_index) => {
                    let Some(expected) = host_func_export(interface, name.name) else {
                        return false;
                    };
                    if !host_func_export_matches(expected, func_type_index, &local_types)
                        || !exported_funcs.insert(name.name)
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

    !exported_types.is_empty() || !exported_funcs.is_empty()
}

/// Capabilities actually reachable through a `bloom:vfs/readwrite@0.1.0`
/// import: a component that only imports the read-side functions must not
/// be granted (or forced to declare) `bloom:vfs.write`, and vice versa.
/// The instance shape has already been validated by
/// [`is_host_interface_instance`]; unknown shapes fall back to the full
/// capability set so this can only ever narrow.
fn vfs_readwrite_import_caps(
    type_index: u32,
    types: &[ComponentTypeEntry<'_>],
) -> Vec<&'static str> {
    let Some(ComponentTypeEntry::Type(ComponentType::Instance(declarations))) =
        types.get(type_index as usize)
    else {
        return vec!["bloom:vfs.read", "bloom:vfs.write"];
    };
    let mut caps = Vec::new();
    for declaration in declarations.as_ref() {
        let InstanceTypeDeclaration::Export {
            name,
            ty: WasmComponentTypeRef::Func(_),
        } = declaration
        else {
            continue;
        };
        let cap = match host_func_export(ComponentHostInterface::VfsReadwrite, name.name) {
            Some(HostFuncExport::VfsLookup | HostFuncExport::VfsList | HostFuncExport::VfsRead) => {
                "bloom:vfs.read"
            }
            Some(HostFuncExport::VfsWrite) => "bloom:vfs.write",
            _ => continue,
        };
        if !caps.contains(&cap) {
            caps.push(cap);
        }
    }
    caps
}

fn host_type_export(interface: ComponentHostInterface, name: &str) -> Option<HostTypeExport> {
    match (interface, name) {
        (ComponentHostInterface::HttpFetch, "request") => Some(HostTypeExport::HttpRequest),
        (ComponentHostInterface::HttpFetch, "response") => Some(HostTypeExport::HttpResponse),
        (ComponentHostInterface::ChainRead, "request") => Some(HostTypeExport::ChainRequest),
        (ComponentHostInterface::ChainRead, "response") => Some(HostTypeExport::ChainResponse),
        (ComponentHostInterface::VfsReadwrite, "entry-kind") => Some(HostTypeExport::VfsEntryKind),
        (ComponentHostInterface::VfsReadwrite, "entry") => Some(HostTypeExport::VfsEntry),
        (ComponentHostInterface::TxOutbox, "evm-transaction") => {
            Some(HostTypeExport::EvmTransaction)
        }
        (ComponentHostInterface::TxOutbox, "approval-required") => {
            Some(HostTypeExport::OutboxApprovalRequired)
        }
        (ComponentHostInterface::TxOutbox, "staged-transaction") => {
            Some(HostTypeExport::StagedTransaction)
        }
        (ComponentHostInterface::TxOutbox, "inspection") => Some(HostTypeExport::OutboxInspection),
        (ComponentHostInterface::SignSigningV1, "approval-required") => {
            Some(HostTypeExport::SignApprovalRequired)
        }
        (ComponentHostInterface::SignSigningV1, "sign-result") => {
            Some(HostTypeExport::SignResultStructured)
        }
        (ComponentHostInterface::SignSigningV2, "approval-pending") => {
            Some(HostTypeExport::SignApprovalPending)
        }
        (ComponentHostInterface::SignSigningV2, "sign-result") => {
            Some(HostTypeExport::SafeSignResultStructured)
        }
        (ComponentHostInterface::SignSigningV1, "sign-request") => {
            Some(HostTypeExport::SignRequestStructured)
        }
        (ComponentHostInterface::SignSigningV2, "payload-sign-request") => {
            Some(HostTypeExport::ScopedPayloadSignRequestStructured)
        }
        (ComponentHostInterface::SignSigningV2, "selector") => {
            Some(HostTypeExport::PetalSignSelector)
        }
        (ComponentHostInterface::SignSigningV2, "payload-sign-item") => {
            Some(HostTypeExport::PayloadSignItemStructured)
        }
        (ComponentHostInterface::SignSigningV2, "payload-batch-sign-request") => {
            Some(HostTypeExport::PayloadBatchSignRequestStructured)
        }
        (ComponentHostInterface::SignSigningV2, "sign-batch-result") => {
            Some(HostTypeExport::PayloadBatchSignResultStructured)
        }
        (ComponentHostInterface::SignSigningV1, "sign-batch-result") => {
            Some(HostTypeExport::SignBatchResultStructured)
        }
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
        (ComponentHostInterface::SignSigningV1, "sign-hash") => {
            Some(HostFuncExport::SignHashStructured)
        }
        (ComponentHostInterface::SignSigningV1, "sign-hashes") => {
            Some(HostFuncExport::SignHashesStructured)
        }
        (ComponentHostInterface::SignSigningV2, "sign-payload") => {
            Some(HostFuncExport::SafeSignPayloadStructured)
        }
        (ComponentHostInterface::SignSigningV2, "sign-payload-batch") => {
            Some(HostFuncExport::PayloadBatchSignStructured)
        }
        (ComponentHostInterface::KeyDerive, "request") => Some(HostFuncExport::PetalKeyRequest),
        (ComponentHostInterface::TxOutbox, "stage") => Some(HostFuncExport::EvmTxStage),
        (ComponentHostInterface::TxOutbox, "confirm") => Some(HostFuncExport::EvmTxConfirm),
        (ComponentHostInterface::TxOutbox, "inspect") => Some(HostFuncExport::EvmTxInspect),
        (ComponentHostInterface::ChainRead, "call") => Some(HostFuncExport::ChainCall),
        (ComponentHostInterface::VfsReadwrite, "lookup") => Some(HostFuncExport::VfsLookup),
        (ComponentHostInterface::VfsReadwrite, "list") => Some(HostFuncExport::VfsList),
        (ComponentHostInterface::VfsReadwrite, "read") => Some(HostFuncExport::VfsRead),
        (ComponentHostInterface::VfsReadwrite, "write") => Some(HostFuncExport::VfsWrite),
        (ComponentHostInterface::EnvRuntime, "now-ms") => Some(HostFuncExport::EnvNowMs),
        (ComponentHostInterface::EnvRuntime, "random-bytes") => {
            Some(HostFuncExport::EnvRandomBytes)
        }
        (ComponentHostInterface::EnvRuntime, "setting") => Some(HostFuncExport::EnvSetting),
        _ => None,
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
        HostTypeExport::EvmTransaction => is_evm_transaction(&ty, types, 0),
        HostTypeExport::OutboxApprovalRequired => is_outbox_approval_required(&ty, types, 0),
        HostTypeExport::StagedTransaction => is_staged_transaction(&ty, types, 0),
        HostTypeExport::OutboxInspection => is_outbox_inspection(&ty, types, 0),
        HostTypeExport::SignApprovalRequired => is_approval_required(&ty, types, 0),
        HostTypeExport::SignApprovalPending => is_approval_pending(&ty, types, 0),
        HostTypeExport::SignResultStructured => is_sign_result_petal(&ty, types, 0),
        HostTypeExport::SafeSignResultStructured => is_safe_sign_result_petal(&ty, types, 0),
        HostTypeExport::SignRequestStructured => is_sign_request_petal(&ty, types, 0),
        HostTypeExport::ScopedPayloadSignRequestStructured => {
            is_scoped_payload_sign_request_petal(&ty, types, 0)
        }
        HostTypeExport::PayloadSignItemStructured => is_payload_sign_item_petal(&ty, types, 0),
        HostTypeExport::PayloadBatchSignRequestStructured => {
            is_payload_batch_sign_request_petal(&ty, types, 0)
        }
        HostTypeExport::PetalSignSelector => is_exact_reusable_selector(&ty, types, 0),
        HostTypeExport::SignBatchResultStructured => is_sign_batch_result_petal(&ty, types, 0),
        HostTypeExport::PayloadBatchSignResultStructured => {
            is_payload_batch_sign_result_petal(&ty, types, 0)
        }
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
                && result_matches(&ty.result, types, HostOkType::HttpResponse)
        }
        HostFuncExport::StoreGet => {
            params_match(
                params,
                types,
                &[("namespace", is_string_type), ("key", is_string_type)],
            ) && result_matches(&ty.result, types, HostOkType::OptionalBytes)
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
            ) && result_matches(&ty.result, types, HostOkType::Unit)
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
            ) && result_matches(&ty.result, types, HostOkType::Unit)
        }
        HostFuncExport::StoreList => {
            params_match(
                params,
                types,
                &[("namespace", is_string_type), ("prefix", is_string_type)],
            ) && result_matches(&ty.result, types, HostOkType::StringList)
        }
        HostFuncExport::StoreDelete => {
            params_match(
                params,
                types,
                &[("namespace", is_string_type), ("key", is_string_type)],
            ) && result_matches(&ty.result, types, HostOkType::Unit)
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
            ) && result_matches(&ty.result, types, HostOkType::Unit)
        }
        HostFuncExport::SignHashStructured => {
            params_match(
                params,
                types,
                &[
                    ("wallet", is_string_type),
                    ("hash32", is_byte_list),
                    ("intent", is_string_type),
                ],
            ) && result_matches(&ty.result, types, HostOkType::SignResultStructured)
        }
        HostFuncExport::SignHashesStructured => {
            params_match(
                params,
                types,
                &[("requests", |ty, types, depth| {
                    is_list_of(ty, types, is_sign_request_petal, depth)
                })],
            ) && result_matches(&ty.result, types, HostOkType::SignBatchResultStructured)
        }
        HostFuncExport::SafeSignPayloadStructured => {
            params_match(
                params,
                types,
                &[("request", is_scoped_payload_sign_request_petal)],
            ) && result_matches(&ty.result, types, HostOkType::SafeSignResultStructured)
        }
        HostFuncExport::PayloadBatchSignStructured => {
            params_match(
                params,
                types,
                &[("request", is_payload_batch_sign_request_petal)],
            ) && result_matches(
                &ty.result,
                types,
                HostOkType::PayloadBatchSignResultStructured,
            )
        }
        HostFuncExport::PetalKeyRequest => {
            params_match(params, types, &[("request", is_byte_list)])
                && result_matches(&ty.result, types, HostOkType::Bytes)
        }
        HostFuncExport::EvmTxStage => {
            params_match(params, types, &[("tx", is_evm_transaction)])
                && result_matches(&ty.result, types, HostOkType::StagedTransaction)
        }
        HostFuncExport::EvmTxConfirm => {
            params_match(
                params,
                types,
                &[
                    ("wallet", is_string_type),
                    ("chain", is_string_type),
                    ("outbox-id", is_string_type),
                    ("acknowledge-warnings", is_bool_type),
                ],
            ) && result_matches(&ty.result, types, HostOkType::StagedTransaction)
        }
        HostFuncExport::EvmTxInspect => {
            params_match(
                params,
                types,
                &[
                    ("wallet", is_string_type),
                    ("chain", is_string_type),
                    ("outbox-id", is_string_type),
                ],
            ) && result_matches(&ty.result, types, HostOkType::OutboxInspection)
        }
        HostFuncExport::ChainCall => {
            params_match(params, types, &[("req", is_chain_request)])
                && result_matches(&ty.result, types, HostOkType::ChainResponse)
        }
        HostFuncExport::VfsLookup => {
            params_match(params, types, &[("path", is_string_type)])
                && result_matches(&ty.result, types, HostOkType::VfsEntry)
        }
        HostFuncExport::VfsList => {
            params_match(params, types, &[("path", is_string_type)])
                && result_matches(&ty.result, types, HostOkType::VfsEntryList)
        }
        HostFuncExport::VfsRead => {
            params_match(params, types, &[("path", is_string_type)])
                && result_matches(&ty.result, types, HostOkType::Bytes)
        }
        HostFuncExport::VfsWrite => {
            params_match(
                params,
                types,
                &[("path", is_string_type), ("body", is_byte_list)],
            ) && result_matches(&ty.result, types, HostOkType::Unit)
        }
        HostFuncExport::EnvNowMs => {
            params.is_empty() && result_matches(&ty.result, types, HostOkType::U64)
        }
        HostFuncExport::EnvRandomBytes => {
            params_match(params, types, &[("len", is_u32_type)])
                && result_matches(&ty.result, types, HostOkType::Bytes)
        }
        HostFuncExport::EnvSetting => {
            params_match(params, types, &[("key", is_string_type)])
                && result_matches(&ty.result, types, HostOkType::OptionalString)
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
    OptionalString,
    StringList,
    HttpResponse,
    ChainResponse,
    VfsEntry,
    VfsEntryList,
    U64,
    SignResultStructured,
    SafeSignResultStructured,
    SignBatchResultStructured,
    PayloadBatchSignResultStructured,
    StagedTransaction,
    OutboxInspection,
}

fn result_matches(
    result: &Option<ComponentValType>,
    types: &[ComponentTypeEntry<'_>],
    ok: HostOkType,
) -> bool {
    let Some(result_ty) = single_component_result(result) else {
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
            (HostOkType::OptionalString, Some(ty)) => {
                is_option_of(ty, types, is_string_type, depth)
            }
            (HostOkType::StringList, Some(ty)) => is_list_of(ty, types, is_string_type, depth),
            (HostOkType::HttpResponse, Some(ty)) => is_http_response(ty, types, depth),
            (HostOkType::ChainResponse, Some(ty)) => is_chain_response(ty, types, depth),
            (HostOkType::VfsEntry, Some(ty)) => is_route_entry(ty, types, depth),
            (HostOkType::VfsEntryList, Some(ty)) => is_list_of(ty, types, is_route_entry, depth),
            (HostOkType::U64, Some(ty)) => is_u64(ty, types, depth),
            (HostOkType::SignResultStructured, Some(ty)) => is_sign_result_petal(ty, types, depth),
            (HostOkType::SafeSignResultStructured, Some(ty)) => {
                is_safe_sign_result_petal(ty, types, depth)
            }
            (HostOkType::SignBatchResultStructured, Some(ty)) => {
                is_sign_batch_result_petal(ty, types, depth)
            }
            (HostOkType::PayloadBatchSignResultStructured, Some(ty)) => {
                is_payload_batch_sign_result_petal(ty, types, depth)
            }
            (HostOkType::StagedTransaction, Some(ty)) => is_staged_transaction(ty, types, depth),
            (HostOkType::OutboxInspection, Some(ty)) => is_outbox_inspection(ty, types, depth),
            _ => false,
        };
        ok_matches && err.is_some_and(|ty| is_string(&ty))
    })
}

fn is_sign_result_petal(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Variant(cases) = defined else {
            return false;
        };
        cases.as_ref().len() == 2
            && cases[0].name == "signature"
            && cases[0]
                .ty
                .as_ref()
                .is_some_and(|ty| is_byte_list(ty, types, depth))
            && cases[1].name == "approval-required"
            && cases[1]
                .ty
                .as_ref()
                .is_some_and(|ty| is_approval_required(ty, types, depth))
    })
}

fn is_safe_sign_result_petal(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Variant(cases) = defined else {
            return false;
        };
        cases.as_ref().len() == 2
            && cases[0].name == "signature"
            && cases[0]
                .ty
                .as_ref()
                .is_some_and(|ty| is_byte_list(ty, types, depth))
            && cases[1].name == "approval-pending"
            && cases[1]
                .ty
                .as_ref()
                .is_some_and(|ty| is_approval_pending(ty, types, depth))
    })
}

fn is_sign_request_petal(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 3
            && fields[0].0 == "wallet"
            && is_string(&fields[0].1)
            && fields[1].0 == "hash32"
            && is_byte_list(&fields[1].1, types, depth)
            && fields[2].0 == "intent"
            && is_string(&fields[2].1)
    })
}

fn is_scoped_payload_sign_request_petal(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        let fields = fields.as_ref();
        fields.len() == 12
            && fields[0].0 == "wallet"
            && is_string(&fields[0].1)
            && fields[1].0 == "preimage"
            && is_byte_list(&fields[1].1, types, depth)
            && fields[2].0 == "claimed-hash"
            && is_byte_list(&fields[2].1, types, depth)
            && fields[3].0 == "signature-algorithm"
            && is_string(&fields[3].1)
            && fields[4].0 == "operation-class"
            && is_string(&fields[4].1)
            && fields[5].0 == "petal-use-claim-jcs"
            && is_byte_list(&fields[5].1, types, depth)
            && fields[6].0 == "claim-assurance-evidence"
            && is_option_of(&fields[6].1, types, is_byte_list, depth)
            && fields[7].0 == "approval-hint"
            && is_option_of(&fields[7].1, types, is_string_type, depth)
            && fields[8].0 == "action"
            && is_option_of(&fields[8].1, types, is_byte_list, depth)
            && fields[9].0 == "advisory"
            && is_option_of(&fields[9].1, types, is_byte_list, depth)
            && fields[10].0 == "selector"
            && is_exact_reusable_selector(&fields[10].1, types, depth)
            && fields[11].0 == "key-ref-jcs"
            && is_option_of(&fields[11].1, types, is_byte_list, depth)
    })
}

fn is_exact_reusable_selector(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, _, _| {
        matches!(
            defined,
            ComponentDefinedType::Enum(names)
                if names.as_ref() == ["exact", "reusable"]
        )
    })
}

fn is_payload_sign_item_petal(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        let fields = fields.as_ref();
        fields.len() == 2
            && fields[0].0 == "preimage"
            && is_byte_list(&fields[0].1, types, depth)
            && fields[1].0 == "claimed-hash"
            && is_byte_list(&fields[1].1, types, depth)
    })
}

fn is_payload_batch_sign_request_petal(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        let fields = fields.as_ref();
        fields.len() == 11
            && fields[0].0 == "wallet"
            && is_string(&fields[0].1)
            && fields[1].0 == "payloads"
            && is_list_of(&fields[1].1, types, is_payload_sign_item_petal, depth)
            && fields[2].0 == "signature-algorithm"
            && is_string(&fields[2].1)
            && fields[3].0 == "operation-class"
            && is_string(&fields[3].1)
            && fields[4].0 == "petal-use-claim-jcs"
            && is_byte_list(&fields[4].1, types, depth)
            && fields[5].0 == "claim-assurance-evidence"
            && is_option_of(&fields[5].1, types, is_byte_list, depth)
            && fields[6].0 == "approval-hint"
            && is_option_of(&fields[6].1, types, is_string_type, depth)
            && fields[7].0 == "action"
            && is_option_of(&fields[7].1, types, is_byte_list, depth)
            && fields[8].0 == "advisory"
            && is_option_of(&fields[8].1, types, is_byte_list, depth)
            && fields[9].0 == "selector"
            && is_exact_reusable_selector(&fields[9].1, types, depth)
            && fields[10].0 == "key-ref-jcs"
            && is_option_of(&fields[10].1, types, is_byte_list, depth)
    })
}

fn is_sign_batch_result_petal(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Variant(cases) = defined else {
            return false;
        };
        cases.as_ref().len() == 2
            && cases[0].name == "signatures"
            && cases[0]
                .ty
                .as_ref()
                .is_some_and(|ty| is_list_of(ty, types, is_byte_list, depth))
            && cases[1].name == "approval-required"
            && cases[1]
                .ty
                .as_ref()
                .is_some_and(|ty| is_approval_required(ty, types, depth))
    })
}

fn is_payload_batch_sign_result_petal(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Variant(cases) = defined else {
            return false;
        };
        cases.as_ref().len() == 2
            && cases[0].name == "signatures"
            && cases[0]
                .ty
                .as_ref()
                .is_some_and(|ty| is_list_of(ty, types, is_byte_list, depth))
            && cases[1].name == "approval-pending"
            && cases[1]
                .ty
                .as_ref()
                .is_some_and(|ty| is_approval_pending(ty, types, depth))
    })
}

fn is_approval_required(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 3
            && fields[0].0 == "action-id"
            && is_string(&fields[0].1)
            && fields[1].0 == "ceremony-url"
            && is_string(&fields[1].1)
            && fields[2].0 == "expires-ms"
            && is_u64(&fields[2].1, types, depth)
    })
}

fn is_approval_pending(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 2
            && fields[0].0 == "action-id"
            && is_string(&fields[0].1)
            && fields[1].0 == "expires-ms"
            && is_u64(&fields[1].1, types, depth)
    })
}

fn is_evm_transaction(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 8
            && fields[0].0 == "wallet"
            && is_string(&fields[0].1)
            && fields[1].0 == "chain"
            && is_string(&fields[1].1)
            && fields[2].0 == "to"
            && is_string(&fields[2].1)
            && fields[3].0 == "value-wei"
            && is_string(&fields[3].1)
            && fields[4].0 == "data-hex"
            && is_string(&fields[4].1)
            && fields[5].0 == "nonce"
            && is_option_of(&fields[5].1, types, is_u64, depth)
            && fields[6].0 == "max-fee-per-gas"
            && is_option_of(&fields[6].1, types, is_string_type, depth)
            && fields[7].0 == "max-priority-fee-per-gas"
            && is_option_of(&fields[7].1, types, is_string_type, depth)
    })
}

fn is_outbox_approval_required(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 2
            && fields[0].0 == "action-id"
            && is_string(&fields[0].1)
            && fields[1].0 == "expires-ms"
            && is_u64(&fields[1].1, types, depth)
    })
}

fn is_staged_transaction(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 3
            && fields[0].0 == "outbox-id"
            && is_string(&fields[0].1)
            && fields[1].0 == "plan-md"
            && is_string(&fields[1].1)
            && fields[2].0 == "approval"
            && is_option_of(&fields[2].1, types, is_outbox_approval_required, depth)
    })
}

fn is_outbox_inspection(
    ty: &ComponentValType,
    types: &[ComponentTypeEntry<'_>],
    depth: usize,
) -> bool {
    with_defined_type(ty, types, depth, |defined, types, depth| {
        let ComponentDefinedType::Record(fields) = defined else {
            return false;
        };
        fields.as_ref().len() == 4
            && fields[0].0 == "outbox-id"
            && is_string(&fields[0].1)
            && fields[1].0 == "state"
            && is_string(&fields[1].1)
            && fields[2].0 == "tx-hash"
            && is_option_of(&fields[2].1, types, is_string_type, depth)
            && fields[3].0 == "receipt-json"
            && is_option_of(&fields[3].1, types, is_string_type, depth)
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
            && fields[0].0 == "petal-root"
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
            "Petal package missing required file {}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unknown>")
        )))
    }
}

fn validate_petal_name(name: &str) -> Result<(), PetalError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(PetalError::InvalidWasm(format!(
            "invalid Petal name {name:?}; expected only ASCII letters, digits, '-' or '_'"
        )))
    }
}

fn validate_sign_policy(
    allowed_caps: &BTreeSet<String>,
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<(), PetalError> {
    if allowed_caps.contains("bloom:sign") && allowed_sign_intents.is_empty() {
        return Err(PetalError::InvalidWasm(
            "Petal package cap bloom:sign requires [sign].allowed_intents".into(),
        ));
    }
    for intent in allowed_sign_intents {
        validate_sign_intent(intent)?;
    }
    Ok(())
}

fn validate_key_derive_policy(
    policy: &KeyPolicyToml,
    routes: &[RouteRecord],
    allowed_sign_intents: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<String>>, PetalError> {
    let route_patterns = routes
        .iter()
        .map(|route| route.pattern.as_str())
        .collect::<BTreeSet<_>>();
    let mut declarations = BTreeMap::new();
    for declaration in &policy.derive_routes {
        if !route_patterns.contains(declaration.route.as_str()) {
            return Err(PetalError::InvalidWasm(format!(
                "Petal [[key.derive]] declares unknown route {:?}",
                declaration.route
            )));
        }
        if declaration.operation_classes.is_empty() {
            return Err(PetalError::InvalidWasm(format!(
                "Petal [[key.derive]] route {:?} operation_classes must be non-empty",
                declaration.route
            )));
        }

        let mut classes = BTreeSet::new();
        for operation_class in &declaration.operation_classes {
            validate_sign_intent(operation_class)?;
            if !allowed_sign_intents.contains(operation_class) {
                return Err(PetalError::InvalidWasm(format!(
                    "Petal [[key.derive]] operation class {operation_class:?} is not declared in [sign].allowed_intents"
                )));
            }
            if !classes.insert(operation_class.clone()) {
                return Err(PetalError::InvalidWasm(format!(
                    "Petal [[key.derive]] route {:?} has duplicate operation class {operation_class:?}",
                    declaration.route
                )));
            }
        }
        if declarations
            .insert(declaration.route.clone(), classes.into_iter().collect())
            .is_some()
        {
            return Err(PetalError::InvalidWasm(format!(
                "Petal [[key.derive]] has a duplicate declaration for route {:?}",
                declaration.route
            )));
        }
    }
    Ok(declarations)
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
            "Petal package cap bloom:store requires [store].namespaces or [store].secret_namespaces"
                .into(),
        ));
    }
    for namespace in policy.namespaces() {
        validate_store_namespace(namespace)?;
    }
    Ok(())
}

fn validate_net_policy(
    allowed_caps: &BTreeSet<String>,
    policy: &NetPolicyToml,
) -> Result<(), PetalError> {
    if allowed_caps.contains("bloom:http") && policy.allow.is_empty() {
        return Err(PetalError::InvalidWasm(
            "Petal package cap bloom:http requires at least one [[net.allow]] rule".into(),
        ));
    }
    for rule in &policy.allow {
        if rule.host.trim().is_empty() || rule.methods.is_empty() {
            return Err(PetalError::InvalidWasm(
                "Petal [[net.allow]] rules require a host and at least one method".into(),
            ));
        }
        if rule.host.trim() != rule.host || url::Host::parse(&rule.host).is_err() {
            return Err(PetalError::InvalidWasm(format!(
                "Petal [[net.allow]] host {:?} must be a bare DNS name or IP address without a scheme, path, or port",
                rule.host
            )));
        }
        if rule.methods.iter().any(|method| method.trim().is_empty()) {
            return Err(PetalError::InvalidWasm(
                "Petal [[net.allow]] methods must be non-empty".into(),
            ));
        }
        if let Some(binding) = rule.binding.as_deref() {
            crate::policy::validate_binding_name(binding)?;
        }
        if rule.paths.is_empty() || rule.paths.iter().any(|path| path.trim().is_empty()) {
            return Err(PetalError::InvalidWasm(
                "Petal [[net.allow]] paths must be explicit and non-empty; use \"/*\" for all paths"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_store_namespace(namespace: &str) -> Result<(), PetalError> {
    if namespace.is_empty() || namespace.len() > 128 {
        return Err(PetalError::InvalidWasm(
            "Petal store namespace must be 1..128 bytes".into(),
        ));
    }
    if namespace.contains('/')
        || !namespace
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(PetalError::InvalidWasm(format!(
            "Petal store namespace {namespace:?} contains an unsupported byte"
        )));
    }
    Ok(())
}

fn validate_sign_intent(intent: &str) -> Result<(), PetalError> {
    if intent.is_empty() || intent.len() > 128 {
        return Err(PetalError::InvalidWasm(
            "Petal sign intent must be 1..128 bytes".into(),
        ));
    }
    if !intent
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
    {
        return Err(PetalError::InvalidWasm(format!(
            "Petal sign intent {intent:?} contains an unsupported byte"
        )));
    }
    Ok(())
}

fn scan_routes(
    petal_root: &Path,
    dir: &Path,
    routes: &mut Vec<RouteRecord>,
) -> Result<(), PetalError> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            scan_routes(petal_root, &path, routes)?;
        } else if ty.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".wasm"))
                .unwrap_or(false)
        {
            let pattern = route_pattern(petal_root, &path)?;
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

fn route_pattern(petal_root: &Path, wasm_path: &Path) -> Result<String, PetalError> {
    let rel = wasm_path
        .strip_prefix(petal_root)
        .map_err(|_| PetalError::InvalidWasm("route escaped petal root".into()))?;
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
    if parts.is_empty() {
        return Err(PetalError::InvalidWasm("empty route path".into()));
    }
    if let Some(reserved) = parts[..parts.len() - 1]
        .iter()
        .find(|segment| segment.starts_with('$'))
    {
        return Err(PetalError::InvalidWasm(format!(
            "reserved route segment {reserved:?} is only allowed as a recognized route leaf"
        )));
    }
    let last = parts
        .last_mut()
        .expect("route path was checked as non-empty");
    *last = last
        .strip_suffix(".wasm")
        .ok_or_else(|| PetalError::InvalidWasm("route leaf is not .wasm".into()))?
        .to_string();
    match last.as_str() {
        "$index" => {
            parts.pop();
        }
        "$lookup" => {}
        other if other.starts_with('$') => {
            return Err(PetalError::InvalidWasm(format!(
                "unsupported reserved route file {other}.wasm"
            )));
        }
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
                    "conflicting Petal routes {:?} and {:?}",
                    a.pattern, b.pattern
                )));
            }
            if file_route_shadows_descendant(a, b)? || file_route_shadows_descendant(b, a)? {
                return Err(PetalError::InvalidWasm(format!(
                    "file route shadows descendant Petal route: {:?} and {:?}",
                    a.pattern, b.pattern
                )));
            }
        }
    }
    Ok(())
}

fn file_route_shadows_descendant(
    candidate: &RouteRecord,
    descendant: &RouteRecord,
) -> Result<bool, PetalError> {
    if candidate
        .source_path
        .file_name()
        .and_then(|name| name.to_str())
        == Some("$index.wasm")
    {
        return Ok(false);
    }
    let candidate_segments = candidate.pattern.split('/').collect::<Vec<_>>();
    let descendant_segments = descendant.pattern.split('/').collect::<Vec<_>>();
    if candidate_segments.len() >= descendant_segments.len() {
        return Ok(false);
    }
    for (candidate, descendant) in candidate_segments.into_iter().zip(descendant_segments) {
        if !segment_covers(candidate, descendant)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Returns whether every path segment matched by `descendant` is also matched
/// by `candidate`. Shadowing needs containment, not mere overlap: a reserved
/// static route such as `new` overlaps `[id]`, but only for one value and must
/// not make all `[id]/...` descendants invalid.
fn segment_covers(candidate: &str, descendant: &str) -> Result<bool, PetalError> {
    match (dynamic_segment(candidate)?, dynamic_segment(descendant)?) {
        (None, None) => Ok(candidate == descendant),
        (Some((_param, suffix)), None) => Ok(descendant
            .strip_suffix(suffix)
            .is_some_and(|bound| !bound.is_empty())),
        (None, Some(_)) => Ok(false),
        (
            Some((_candidate_param, candidate_suffix)),
            Some((_descendant_param, descendant_suffix)),
        ) => Ok(descendant_suffix.ends_with(candidate_suffix)),
    }
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
pub(crate) mod route_fixtures {
    //! Hand-written `bloom:route@0.1.0` component fixtures with working
    //! canonical-ABI handlers, used to exercise parameterized-route
    //! installation and runtime metadata narrowing end-to-end.

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum FixtureVfsImport {
        None,
        ReadOnly,
        ReadWrite,
    }

    const STRINGS_BASE: u32 = 512;
    const META_RESULT: u32 = 1024;
    const LOOKUP_RESULT: u32 = 1152;
    const LIST_RESULT: u32 = 1280;
    const READ_RESULT: u32 = 1344;
    const WRITE_RESULT: u32 = 1408;
    const EMPTY_LIST_PTR: u32 = 2048;
    const ENTRY_NAME: &str = "alice";
    pub(crate) const LOOKUP_ENTRY_SIZE: u64 = 7;

    /// Builds a directory (`$index`) route component whose `metadata`
    /// export reports `kind = dir`, `mode = 0o755`,
    /// `cache-ttl-ms = some(30000)` and `required-caps = metadata_caps`,
    /// and whose `lookup` export returns a dir entry named "alice" with
    /// mode `0o755` and size [`LOOKUP_ENTRY_SIZE`].
    pub(crate) fn dynamic_dir_route_component(
        import_store: bool,
        vfs: FixtureVfsImport,
        metadata_caps: &[&str],
        package_import: Option<&str>,
    ) -> Vec<u8> {
        build_dynamic_dir_route_component(
            import_store,
            vfs,
            metadata_caps,
            package_import,
            false,
            true,
            false,
            false,
            false,
        )
    }

    pub(crate) fn dynamic_side_effecting_dir_route_component(
        import_store: bool,
        vfs: FixtureVfsImport,
        metadata_caps: &[&str],
        package_import: Option<&str>,
    ) -> Vec<u8> {
        build_dynamic_dir_route_component(
            import_store,
            vfs,
            metadata_caps,
            package_import,
            true,
            true,
            false,
            false,
            false,
        )
    }

    pub(crate) fn dynamic_dir_route_component_without_list() -> Vec<u8> {
        build_dynamic_dir_route_component(
            false,
            FixtureVfsImport::None,
            &[],
            None,
            false,
            false,
            false,
            false,
            false,
        )
    }

    pub(crate) fn dynamic_file_lookup_route_component() -> Vec<u8> {
        build_dynamic_dir_route_component(
            false,
            FixtureVfsImport::None,
            &[],
            None,
            false,
            false,
            false,
            false,
            true,
        )
    }

    /// Builds a writable route which advertises asynchronous writes but
    /// traps from its write handler. This exercises error propagation at the
    /// VFS/router boundary without depending on a host capability failure.
    pub(crate) fn async_failing_write_route_component() -> Vec<u8> {
        build_dynamic_dir_route_component(
            false,
            FixtureVfsImport::None,
            &[],
            None,
            false,
            true,
            true,
            true,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_dynamic_dir_route_component(
        import_store: bool,
        vfs: FixtureVfsImport,
        metadata_caps: &[&str],
        package_import: Option<&str>,
        side_effecting_read: bool,
        include_list: bool,
        write_async: bool,
        trap_write: bool,
        file_route: bool,
    ) -> Vec<u8> {
        // String table for the metadata cap names and the lookup entry name.
        let mut strings = Vec::new();
        let mut cap_locs = Vec::new();
        for cap in metadata_caps {
            cap_locs.push((STRINGS_BASE + strings.len() as u32, cap.len() as u32));
            strings.extend_from_slice(cap.as_bytes());
        }
        let name_ptr = STRINGS_BASE + strings.len() as u32;
        strings.extend_from_slice(ENTRY_NAME.as_bytes());
        let caps_array = (STRINGS_BASE + strings.len() as u32 + 3) & !3;
        let mut caps_array_bytes = Vec::new();
        for (ptr, len) in &cap_locs {
            caps_array_bytes.extend_from_slice(&ptr.to_le_bytes());
            caps_array_bytes.extend_from_slice(&len.to_le_bytes());
        }

        // Canonical-ABI encoding of result<route-meta, route-error>.
        let mut meta = vec![0u8; 88];
        meta[8] = u8::from(file_route); // kind: dir (0) or file (1)
        let mode: u32 = if file_route { 0o666 } else { 0o755 };
        meta[12..16].copy_from_slice(&mode.to_le_bytes());
        meta[16] = 1; // cache-ttl-ms: some
        meta[24..32].copy_from_slice(&30_000u64.to_le_bytes());
        meta[32] = u8::from(side_effecting_read);
        meta[33] = u8::from(write_async);
        meta[60..64].copy_from_slice(&caps_array.to_le_bytes());
        meta[64..68].copy_from_slice(&(metadata_caps.len() as u32).to_le_bytes());

        // Canonical-ABI encoding of result<entry, route-error>.
        let mut lookup = vec![0u8; 56];
        lookup[8..12].copy_from_slice(&name_ptr.to_le_bytes());
        lookup[12..16].copy_from_slice(&(ENTRY_NAME.len() as u32).to_le_bytes());
        lookup[16] = u8::from(file_route); // kind: dir (0) or file (1)
        lookup[20..24].copy_from_slice(&mode.to_le_bytes());
        lookup[24] = 1; // size: some
        lookup[32..40].copy_from_slice(&LOOKUP_ENTRY_SIZE.to_le_bytes());

        // result<list<entry>, route-error> and result<list<u8>, route-error>
        // with empty ok lists, and result<_, route-error> ok.
        let mut empty_list = vec![0u8; 16];
        empty_list[4..8].copy_from_slice(&EMPTY_LIST_PTR.to_le_bytes());
        let write = vec![0u8; 16];

        let store_import = if import_store {
            r#"
  (type $store-ty (instance
    (type (list u8))
    (type (option 0))
    (type (result 1 (error string)))
    (type (func (param "namespace" string) (param "key" string) (result 2)))
    (export "get" (func (type 3)))
  ))
  (import "bloom:store/kv@0.1.0" (instance (type $store-ty)))
"#
        } else {
            ""
        };
        let vfs_import = match vfs {
            FixtureVfsImport::None => "",
            FixtureVfsImport::ReadOnly => {
                r#"
  (type $vfs-ty (instance
    (type (list u8))
    (type (result 0 (error string)))
    (type (func (param "path" string) (result 1)))
    (export "read" (func (type 2)))
  ))
  (import "bloom:vfs/readwrite@0.1.0" (instance (type $vfs-ty)))
"#
            }
            FixtureVfsImport::ReadWrite => {
                r#"
  (type $vfs-ty (instance
    (type (list u8))
    (type (result 0 (error string)))
    (type (func (param "path" string) (result 1)))
    (export "read" (func (type 2)))
    (type (result (error string)))
    (type (func (param "path" string) (param "body" 0) (result 3)))
    (export "write" (func (type 4)))
  ))
  (import "bloom:vfs/readwrite@0.1.0" (instance (type $vfs-ty)))
"#
            }
        };
        let package_import = package_import
            .map(|name| format!("  (import {name:?} (instance))\n"))
            .unwrap_or_default();
        let core_list_func = if include_list {
            r#"(func $list (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      i32.const 1280)"#
        } else {
            ""
        };
        let core_list_export = if include_list {
            r#"(export "list" (func $list))"#
        } else {
            ""
        };
        let core_list_alias = if include_list {
            r#"(alias core export $main-instance "list" (core func $core-list))"#
        } else {
            ""
        };
        let core_write_func = if trap_write {
            r#"(func $write (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      unreachable)"#
        } else {
            r#"(func $write (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      i32.const 1408)"#
        };
        let component_list_export = if include_list {
            r#"(type $entry-list (list $entry-import))
  (type $list-result (result $entry-list (error $route-error-import)))
  (type $list-fn (func (param "ctx" $ctx-import) (result $list-result)))
  (func $list (type $list-fn) (canon lift (core func $core-list) (memory $mem) (realloc $realloc) string-encoding=utf8))
  (export "list" (func $list))"#
        } else {
            ""
        };

        let wat = format!(
            r#"(component
{store_import}{vfs_import}
  (type $route-types-ty (instance
    (type (tuple string string))
    (type (list 0))
    (type (option string))
    (type (record (field "petal-root" string) (field "package-hash" string) (field "path" string) (field "params" 1) (field "actor" 2)))
    (export "ctx" (type (eq 3)))
    (type (enum "dir" "file" "symlink"))
    (export "entry-kind" (type (eq 5)))
    (type (option u64))
    (type (record (field "name" string) (field "kind" 6) (field "mode" u32) (field "size" 7) (field "link-target" 2)))
    (export "entry" (type (eq 8)))
    (type (variant (case "not-found" string) (case "not-a-dir" string) (case "denied" string) (case "invalid" string) (case "backend" string) (case "unsupported" string)))
    (export "route-error" (type (eq 10)))
    (type (list string))
    (type (record (field "kind" 6) (field "mode" u32) (field "cache-ttl-ms" 7) (field "side-effecting-read" bool) (field "write-async" bool) (field "description" 2) (field "consent-summary" 2) (field "required-caps" 12) (field "sign-intent" 2) (field "executable" bool)))
    (export "route-meta" (type (eq 13)))
  ))
  (import "bloom:route/types@0.1.0" (instance $route-types (type $route-types-ty)))
{package_import}  (alias export $route-types "ctx" (type $ctx))
  (import "ctx" (type $ctx-import (eq $ctx)))
  (alias export $route-types "entry" (type $entry))
  (import "entry" (type $entry-import (eq $entry)))
  (alias export $route-types "route-error" (type $route-error))
  (import "route-error" (type $route-error-import (eq $route-error)))
  (alias export $route-types "route-meta" (type $route-meta))
  (import "route-meta" (type $route-meta-import (eq $route-meta)))
  (core module $main
    (memory (;0;) 1)
    (global $heap (mut i32) (i32.const 4096))
    (func $realloc (param i32 i32 i32 i32) (result i32)
      (local $ptr i32)
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
      local.set $ptr
      local.get $ptr
      local.get 3
      i32.add
      global.set $heap
      local.get $ptr
    )
    (func $metadata (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      i32.const {META_RESULT})
    (func $lookup (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      i32.const {LOOKUP_RESULT})
    {core_list_func}
    (func $read (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      i32.const {READ_RESULT})
    {core_write_func}
    (export "memory" (memory 0))
    (export "cabi_realloc" (func $realloc))
    (export "metadata" (func $metadata))
    (export "lookup" (func $lookup))
    {core_list_export}
    (export "read" (func $read))
    (export "write" (func $write))
    {strings_data}
    {caps_array_data}
    {meta_data}
    {lookup_data}
    {list_data}
    {read_data}
    {write_data}
  )
  (core instance $main-instance (instantiate $main))
  (alias core export $main-instance "memory" (core memory $mem))
  (alias core export $main-instance "cabi_realloc" (core func $realloc))
  (alias core export $main-instance "metadata" (core func $core-metadata))
  (alias core export $main-instance "lookup" (core func $core-lookup))
  {core_list_alias}
  (alias core export $main-instance "read" (core func $core-read))
  (alias core export $main-instance "write" (core func $core-write))
  (type $meta-result (result $route-meta-import (error $route-error-import)))
  (type $meta-fn (func (param "ctx" $ctx-import) (result $meta-result)))
  (func $metadata (type $meta-fn) (canon lift (core func $core-metadata) (memory $mem) (realloc $realloc) string-encoding=utf8))
  (export "metadata" (func $metadata))
  (type $lookup-result (result $entry-import (error $route-error-import)))
  (type $lookup-fn (func (param "ctx" $ctx-import) (result $lookup-result)))
  (func $lookup (type $lookup-fn) (canon lift (core func $core-lookup) (memory $mem) (realloc $realloc) string-encoding=utf8))
  (export "lookup" (func $lookup))
  {component_list_export}
  (type $bytes (list u8))
  (type $read-result (result $bytes (error $route-error-import)))
  (type $read-fn (func (param "ctx" $ctx-import) (result $read-result)))
  (func $read (type $read-fn) (canon lift (core func $core-read) (memory $mem) (realloc $realloc) string-encoding=utf8))
  (export "read" (func $read))
  (type $write-result (result (error $route-error-import)))
  (type $write-fn (func (param "ctx" $ctx-import) (param "body" $bytes) (result $write-result)))
  (func $write (type $write-fn) (canon lift (core func $core-write) (memory $mem) (realloc $realloc) string-encoding=utf8))
  (export "write" (func $write))
)
"#,
            strings_data = data_segment(STRINGS_BASE, &strings),
            caps_array_data = data_segment(caps_array, &caps_array_bytes),
            meta_data = data_segment(META_RESULT, &meta),
            lookup_data = data_segment(LOOKUP_RESULT, &lookup),
            list_data = data_segment(LIST_RESULT, &empty_list),
            read_data = data_segment(READ_RESULT, &empty_list),
            write_data = data_segment(WRITE_RESULT, &write),
        );
        wat::parse_str(&wat).unwrap()
    }

    fn data_segment(addr: u32, bytes: &[u8]) -> String {
        let escaped = bytes
            .iter()
            .map(|byte| format!("\\{byte:02x}"))
            .collect::<String>();
        format!("(data (i32.const {addr}) \"{escaped}\")")
    }
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
    fn petal_scanner_matches_static_and_dynamic_routes() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "petal/echo/hello.txt.wasm", b"\0asm");
        write_package_file(tmp.path(), "petal/echo/[name].txt.wasm", b"\0asm");

        let package = PetalPackage::scan_dir(tmp.path()).unwrap();
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
    fn legacy_package_schema_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
            route_component_no_imports(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("must set schema = \"bloom.petal.package.v1\"")
        );
    }

    #[test]
    fn petal_scanner_rejects_equal_specificity_dynamic_conflicts() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "petal/echo/[name].txt.wasm", b"\0asm");
        write_package_file(tmp.path(), "petal/echo/[wallet].txt.wasm", b"\0asm");

        let err = PetalPackage::scan_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("conflicting Petal routes"));
    }

    #[test]
    fn petal_names_match_runtime_configuration_grammar() {
        for valid in ["echo", "Echo2", "my-petal", "my_petal"] {
            validate_petal_name(valid).unwrap();
        }
        for invalid in ["", "foo.bar", "foo/bar", "foo\\bar", "petal💮"] {
            let err = validate_petal_name(invalid).unwrap_err();
            assert!(
                err.to_string()
                    .contains("expected only ASCII letters, digits, '-' or '_'")
            );
        }

        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "foo.bar"
"#,
            route_component_no_imports(),
        );
        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid Petal name \"foo.bar\""));
    }

    #[test]
    fn petal_scanner_rejects_file_routes_that_shadow_descendants() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "petal/echo/foo.wasm", b"\0asm");
        write_package_file(tmp.path(), "petal/echo/foo/bar.wasm", b"\0asm");

        let err = PetalPackage::scan_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("file route shadows descendant"));

        std::fs::remove_file(tmp.path().join("petal/echo/foo.wasm")).unwrap();
        write_package_file(tmp.path(), "petal/echo/foo/$index.wasm", b"\0asm");
        PetalPackage::scan_dir(tmp.path()).unwrap();
    }

    #[test]
    fn petal_scanner_allows_reserved_static_route_beside_dynamic_descendants() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "petal/echo/fund/[wallet]/new.wasm", b"\0asm");
        write_package_file(
            tmp.path(),
            "petal/echo/fund/[wallet]/[id]/approval.json.wasm",
            b"\0asm",
        );

        let package = PetalPackage::scan_dir(tmp.path()).unwrap();
        let new_fund = package.match_route("fund/alice/new").unwrap();
        assert_eq!(new_fund.route.pattern, "fund/[wallet]/new");
        assert_eq!(new_fund.params, vec![("wallet".into(), "alice".into())]);

        let approval = package
            .match_route("fund/alice/position-1/approval.json")
            .unwrap();
        assert_eq!(approval.route.pattern, "fund/[wallet]/[id]/approval.json");
        assert_eq!(
            approval.params,
            vec![
                ("wallet".into(), "alice".into()),
                ("id".into(), "position-1".into()),
            ]
        );
    }

    #[test]
    fn petal_scanner_rejects_paths_too_long_for_strict_archive() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        let file_name = format!("{}.wasm", "a".repeat(TAR_NAME_LEN + 1));
        write_package_file(
            tmp.path(),
            &format!("petal/echo/{file_name}"),
            route_component_no_imports(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("too long for strict .petal.tar"));
    }

    #[test]
    fn petal_tar_and_dir_inputs_share_normalized_hash() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());
        let dir = PreparedPetalPackage::from_dir(tmp.path()).unwrap();
        let wasm = route_component_no_imports();
        let tar = PreparedPetalPackage::from_reader(std::io::Cursor::new(package_tar_bytes(vec![
            ("README.md", b"# echo".as_slice()),
            ("AGENTS.md", b"# echo agents".as_slice()),
            (
                "petal.toml",
                br#"schema = "bloom.petal.package.v1"
name = "echo"
"#
                .as_slice(),
            ),
            ("petal/echo/hello.txt.wasm", wasm),
        ])))
        .unwrap();

        assert_eq!(dir.hash, tar.hash);
        assert_eq!(dir.route_index.routes, tar.route_index.routes);
        assert_eq!(dir.route_index.routes[0].route_id, "r000001");
    }

    #[test]
    fn petal_consent_summary_includes_manifest_policy_docs_and_routes() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
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
            "petal/echo/hello.txt.wasm",
            route_component_no_imports(),
        );

        let package = PreparedPetalPackage::from_dir(tmp.path()).unwrap();
        let summary = petal_consent_summary(&package).unwrap();

        assert_eq!(summary.name, "echo");
        assert_eq!(summary.petal_mount, "petals/echo/");
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
                PetalConsentStoreNamespace {
                    namespace: "credentials".into(),
                    secret: true,
                },
                PetalConsentStoreNamespace {
                    namespace: "orders".into(),
                    secret: false,
                },
            ]
        );
        assert_eq!(summary.routes.len(), 1);
        assert_eq!(summary.routes[0].path, "/petals/echo/hello.txt");
        assert_eq!(summary.routes[0].ops, vec![RouteOp::Lookup, RouteOp::Read]);
    }

    #[test]
    fn petal_manifest_rejects_network_hosts_with_scheme_or_port() {
        for host in ["https://api.example.com", "api.example.com:443"] {
            let tmp = tempfile::tempdir().unwrap();
            write_package_file(
                tmp.path(),
                "petal.toml",
                format!(
                    r#"schema = "bloom.petal.package.v1"
name = "echo"

[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = {host:?}
methods = ["get"]
paths = ["/*"]
"#
                )
                .as_bytes(),
            );
            write_package_file(tmp.path(), "README.md", b"# echo");
            write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
            write_package_file(
                tmp.path(),
                "petal/echo/hello.txt.wasm",
                route_component_http(),
            );

            let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
            assert!(
                err.to_string()
                    .contains("must be a bare DNS name or IP address")
            );
        }
    }

    #[test]
    fn petal_write_petal_tar_emits_installable_deterministic_archive() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());
        let package = PreparedPetalPackage::from_dir(tmp.path()).unwrap();

        let mut first = Vec::new();
        package.write_petal_tar(&mut first).unwrap();
        let mut second = Vec::new();
        package.write_petal_tar(&mut second).unwrap();
        assert_eq!(first, second);

        let from_tar = PreparedPetalPackage::from_reader(std::io::Cursor::new(first)).unwrap();
        assert_eq!(from_tar.hash, package.hash);
        assert_eq!(from_tar.route_index, package.route_index);
    }

    #[test]
    fn petal_write_petal_tar_uses_strict_headers_for_ustar_split_paths() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        let route_path = format!(
            "petal/echo/{}/hello.txt.wasm",
            "nested-static-segment".repeat(4)
        );
        assert!(route_path.len() > TAR_NAME_LEN);
        write_package_file(tmp.path(), &route_path, route_component_no_imports());
        let package = PreparedPetalPackage::from_dir(tmp.path()).unwrap();

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
        let from_tar = PreparedPetalPackage::from_reader(std::io::Cursor::new(tar_bytes)).unwrap();
        assert_eq!(from_tar.hash, package.hash);
    }

    #[test]
    fn petal_build_petal_package_dir_writes_artifacts_and_manifest_deterministically() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());

        let first = build_petal_package_dir(tmp.path()).unwrap();
        let artifact_path = tmp.path().join("artifacts/routes/r000001.wasm");
        let manifest_path = tmp.path().join("artifacts/build-manifest.json");
        let source = std::fs::read(tmp.path().join("petal/echo/hello.txt.wasm")).unwrap();
        let artifact = std::fs::read(&artifact_path).unwrap();
        assert_eq!(artifact, source);

        let manifest: BuildManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest.schema, BUILD_MANIFEST_SCHEMA);
        assert_eq!(manifest.routes.len(), 1);
        assert_eq!(manifest.routes[0].route_id, "r000001");
        assert_eq!(manifest.routes[0].source_path, "petal/echo/hello.txt.wasm");
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

        let second = build_petal_package_dir(tmp.path()).unwrap();
        assert_eq!(second.hash, first.hash);
        assert_eq!(second.route_index, first.route_index);
    }

    #[test]
    fn petal_build_petal_package_dir_replaces_stale_generated_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());
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

        let package = build_petal_package_dir(tmp.path()).unwrap();
        let route = &package.route_index.routes[0];
        let artifact = std::fs::read(tmp.path().join(&route.artifact_path)).unwrap();
        let source = std::fs::read(tmp.path().join(&route.source_path)).unwrap();
        assert_eq!(artifact, source);
    }

    #[test]
    fn cancelled_petal_build_preserves_existing_generated_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());
        write_package_file(
            tmp.path(),
            "artifacts/routes/r000001.wasm",
            b"previous artifact",
        );
        write_package_file(
            tmp.path(),
            "artifacts/build-manifest.json",
            b"previous manifest",
        );

        let error = build_petal_package_dir_guarded(tmp.path(), || {
            Err(PetalError::vm("cancelled before commit"))
        })
        .unwrap_err();

        assert!(error.to_string().contains("cancelled before commit"));
        assert_eq!(
            std::fs::read(tmp.path().join("artifacts/routes/r000001.wasm")).unwrap(),
            b"previous artifact"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("artifacts/build-manifest.json")).unwrap(),
            b"previous manifest"
        );
    }

    #[cfg(unix)]
    #[test]
    fn petal_build_petal_package_dir_rejects_symlinked_artifacts_without_deleting_target() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());
        std::fs::write(outside.path().join("sentinel"), b"keep").unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("artifacts")).unwrap();

        let err = build_petal_package_dir(tmp.path()).unwrap_err();
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
    fn petal_route_sidecar_builds_artifact_from_module_component() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.wasm",
            route_component_no_imports(),
        );
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.route.toml",
            br#"abi = "component"
component = "modules/message.wasm"
"#,
        );
        write_package_file(
            tmp.path(),
            "modules/message.wasm",
            route_component_metadata(),
        );

        let package = build_petal_package_dir(tmp.path()).unwrap();
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
    fn petal_lookup_sidecar_component_is_validated_as_lookup_route() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        let lookup_only = route_fixtures::dynamic_file_lookup_route_component();
        write_package_file(tmp.path(), "petal/echo/$lookup.wasm", &lookup_only);
        write_package_file(
            tmp.path(),
            "petal/echo/$lookup.route.toml",
            br#"abi = "component"
component = "components/lookup.wasm"
"#,
        );
        write_package_file(tmp.path(), "components/lookup.wasm", &lookup_only);

        let package = build_petal_package_dir(tmp.path()).unwrap();
        assert!(package.route_index.routes[0].ops.contains(&RouteOp::Lookup));
        assert!(!package.route_index.routes[0].ops.contains(&RouteOp::Read));
    }

    #[test]
    fn petal_route_sidecar_rejects_non_component_paths() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(tmp.path(), route_component_metadata());
        write_package_file(
            tmp.path(),
            "petal/echo/hello.txt.route.toml",
            br#"abi = "component"
component = "petal/echo/hello.txt.wasm"
"#,
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("modules/ or components/"));
    }

    #[test]
    fn petal_route_sidecar_still_requires_valid_route_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "petal/echo/message.txt.wasm", b"not wasm");
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.route.toml",
            br#"abi = "component"
component = "modules/message.wasm"
"#,
        );
        write_package_file(
            tmp.path(),
            "modules/message.wasm",
            route_component_metadata(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid route wasm"));
    }

    #[test]
    fn petal_route_sidecar_rejects_mismatched_generated_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.wasm",
            route_component_no_imports(),
        );
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.route.toml",
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

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match route sidecar composition")
        );
    }

    #[test]
    fn petal_route_without_sidecar_rejects_stale_generated_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());
        write_package_file(
            tmp.path(),
            "artifacts/routes/r000001.wasm",
            route_component_metadata(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("does not match its route source"));
    }

    #[test]
    fn petal_sidecar_artifact_is_validated_as_an_index_route() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "petal/echo/$index.wasm",
            &route_fixtures::dynamic_dir_route_component(
                false,
                route_fixtures::FixtureVfsImport::None,
                &[],
                None,
            ),
        );
        write_package_file(
            tmp.path(),
            "petal/echo/$index.route.toml",
            br#"abi = "component"
component = "modules/index.wasm"
"#,
        );
        write_package_file(
            tmp.path(),
            "modules/index.wasm",
            &route_fixtures::dynamic_dir_route_component_without_list(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing bloom:route@0.1.0 \"list\" export"),
            "{err}"
        );
    }

    #[test]
    fn petal_route_sidecar_rejects_missing_import_component() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.wasm",
            route_component_no_imports(),
        );
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.route.toml",
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

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("components/missing.wasm"));
    }

    #[test]
    fn petal_route_sidecar_composes_package_local_import_alias() {
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
            path: "petal/echo/message.txt.route.toml".into(),
            petal_name: "echo".into(),
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
    fn petal_route_sidecar_builds_route_with_package_local_import() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.wasm",
            route_component_package_import(),
        );
        write_package_file(
            tmp.path(),
            "petal/echo/message.txt.route.toml",
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

        let package = build_petal_package_dir(tmp.path()).unwrap();
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
    fn petal_tar_rejects_duplicate_and_traversal_paths() {
        let duplicate =
            PreparedPetalPackage::from_reader(std::io::Cursor::new(package_tar_bytes(vec![
                (
                    "petal.toml",
                    br#"schema = "bloom.petal.package.v1" name = "x""#,
                ),
                (
                    "petal.toml",
                    br#"schema = "bloom.petal.package.v1" name = "x""#,
                ),
            ])))
            .unwrap_err();
        assert!(
            duplicate
                .to_string()
                .contains("duplicate Petal package archive path")
        );

        let traversal = PreparedPetalPackage::from_reader(std::io::Cursor::new(
            raw_package_tar_bytes("../petal.toml", b"x"),
        ))
        .unwrap_err();
        assert!(traversal.to_string().contains("invalid Petal package path"));
    }

    #[test]
    fn petal_tar_rejects_non_normal_mode_and_metadata() {
        let bad_mode = PreparedPetalPackage::from_reader(std::io::Cursor::new(
            raw_package_tar_entry("petal.toml", b"x", 0o777, 0, 0, 0),
        ))
        .unwrap_err();
        assert!(bad_mode.to_string().contains("unsupported mode"));

        let bad_owner = PreparedPetalPackage::from_reader(std::io::Cursor::new(
            raw_package_tar_entry("petal.toml", b"x", 0o644, 1, 0, 0),
        ))
        .unwrap_err();
        assert!(bad_owner.to_string().contains("nonzero owner"));

        let bad_mtime = PreparedPetalPackage::from_reader(std::io::Cursor::new(
            raw_package_tar_entry("petal.toml", b"x", 0o644, 0, 0, 1),
        ))
        .unwrap_err();
        assert!(bad_mtime.to_string().contains("nonzero mtime"));

        let bad_names = PreparedPetalPackage::from_reader(std::io::Cursor::new(
            raw_tar_entry_with_names("petal.toml", b"x", "user", "group"),
        ))
        .unwrap_err();
        assert!(bad_names.to_string().contains("textual owner metadata"));

        let malformed_uid = PreparedPetalPackage::from_reader(std::io::Cursor::new(
            raw_tar_entry_with_malformed_uid("petal.toml", b"x"),
        ))
        .unwrap_err();
        assert!(malformed_uid.to_string().contains("invalid uid"));

        let bad_atime = PreparedPetalPackage::from_reader(std::io::Cursor::new(
            raw_tar_entry_with_times("petal.toml", b"x", 1, 0),
        ))
        .unwrap_err();
        assert!(bad_atime.to_string().contains("nonzero atime/ctime"));
    }

    #[test]
    fn petal_tar_rejects_bad_or_duplicate_directory_entries() {
        let bad_dir = PreparedPetalPackage::from_reader(std::io::Cursor::new(raw_dir_tar_entry(
            "../bad/", 0o755,
        )))
        .unwrap_err();
        assert!(bad_dir.to_string().contains("invalid Petal package path"));

        let duplicate_dir =
            PreparedPetalPackage::from_reader(std::io::Cursor::new(raw_multi_entry_tar(vec![
                RawTarEntry::dir("petal/", 0o755),
                RawTarEntry::dir("petal/", 0o755),
            ])))
            .unwrap_err();
        assert!(
            duplicate_dir
                .to_string()
                .contains("duplicate Petal package archive path")
        );

        let empty_segment_dir = PreparedPetalPackage::from_reader(std::io::Cursor::new(
            raw_dir_tar_entry("petal//", 0o755),
        ))
        .unwrap_err();
        assert!(
            empty_segment_dir
                .to_string()
                .contains("invalid Petal package path")
        );
    }

    #[test]
    fn petal_tar_rejects_pax_extension_entries() {
        let pax =
            PreparedPetalPackage::from_reader(std::io::Cursor::new(raw_multi_entry_tar(vec![
                RawTarEntry::pax("pax", b"13 atime=1\n"),
                RawTarEntry::file("petal.toml", b"x", 0o644, 0, 0, 0),
            ])))
            .unwrap_err();
        assert!(pax.to_string().contains("unsupported extended metadata"));
    }

    #[test]
    fn petal_rejects_extra_petal_roots() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());
        write_package_file(
            tmp.path(),
            "petal/other/hello.txt.wasm",
            route_component_no_imports(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("extra petal root"));
    }

    #[test]
    fn petal_index_and_lookup_route_files_normalize_patterns() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
            route_component_no_imports(),
        );
        std::fs::rename(
            tmp.path().join("petal/echo/hello.txt.wasm"),
            tmp.path().join("petal/echo/$index.wasm"),
        )
        .unwrap();
        write_package_file(
            tmp.path(),
            "petal/echo/items/[id]/$lookup.wasm",
            route_component_no_imports(),
        );

        let package = PetalPackage::scan_dir(tmp.path()).unwrap();
        let patterns = package
            .routes
            .iter()
            .map(|route| route.pattern.as_str())
            .collect::<Vec<_>>();
        assert_eq!(patterns, vec!["", "items/[id]/$lookup"]);
    }

    #[test]
    fn petal_unknown_reserved_route_files_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package(tmp.path());
        write_package_file(
            tmp.path(),
            "petal/echo/items/$reserved.wasm",
            route_component_no_imports(),
        );

        let err = PetalPackage::scan_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported reserved route file"));
    }

    #[test]
    fn petal_reserved_route_segments_are_rejected_for_directories_and_archives() {
        for reserved in ["$private", "$index"] {
            let tmp = tempfile::tempdir().unwrap();
            write_petal_package(tmp.path());
            write_package_file(
                tmp.path(),
                &format!("petal/echo/{reserved}/bar.wasm"),
                route_component_no_imports(),
            );

            let scan_err = PetalPackage::scan_dir(tmp.path()).unwrap_err();
            assert!(scan_err.to_string().contains("reserved route segment"));
            let package_err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
            assert!(package_err.to_string().contains("reserved route segment"));

            let tar = package_tar_bytes(vec![
                ("README.md", b"# echo".as_slice()),
                ("AGENTS.md", b"# echo agents".as_slice()),
                (
                    "petal.toml",
                    br#"schema = "bloom.petal.package.v1"
name = "echo"
"#
                    .as_slice(),
                ),
                (
                    &format!("petal/echo/{reserved}/bar.wasm"),
                    route_component_no_imports(),
                ),
            ]);
            let tar_err = PreparedPetalPackage::from_reader(std::io::Cursor::new(tar)).unwrap_err();
            assert!(
                tar_err.to_string().contains("reserved route segment"),
                "unexpected archive error: {tar_err}"
            );
        }
    }

    #[test]
    fn petal_root_index_route_matches_empty_path() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(tmp.path(), "petal/echo/$index.wasm", b"\0asm");

        let package = PetalPackage::scan_dir(tmp.path()).unwrap();
        let matched = package.match_route("").unwrap();
        assert_eq!(matched.route.pattern, "");
    }

    #[test]
    fn petal_component_routes_are_validated_as_bloom_route_010() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(tmp.path(), route_component_no_imports());

        let package = PreparedPetalPackage::from_dir(tmp.path()).unwrap();
        let route = &package.route_index.routes[0];
        assert_eq!(route.abi, RouteAbi::ComponentBloomRoute010);
        assert!(route.install_metadata.required_caps.is_empty());
    }

    #[test]
    fn petal_static_component_metadata_is_cached_in_route_index() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(tmp.path(), route_component_metadata());

        let package = PreparedPetalPackage::from_dir(tmp.path()).unwrap();
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
    fn petal_writable_routes_require_write_export() {
        let validation = RouteValidation {
            abi: RouteAbi::ComponentBloomRoute010,
            required_caps: Vec::new(),
            has_write_export: false,
        };
        let metadata = InstallRouteMetadata {
            mode: 0o444,
            cache_ttl_ms: None,
            side_effecting_read: false,
            write_async: false,
            executable: false,
            required_caps: Vec::new(),
            sign_intent: None,
        };
        let err = validate_writable_route_has_write_export(
            "r000001",
            RouteEntryKind::File,
            &[RouteOp::Lookup, RouteOp::Write],
            &metadata,
            &validation,
        )
        .unwrap_err();
        assert!(err.to_string().contains("has no write export"));

        let metadata = InstallRouteMetadata {
            mode: 0o644,
            ..metadata
        };
        let err = validate_writable_route_has_write_export(
            "r000001",
            RouteEntryKind::File,
            &[RouteOp::Lookup, RouteOp::Read],
            &metadata,
            &validation,
        )
        .unwrap_err();
        assert!(err.to_string().contains("has no write export"));
    }

    #[test]
    fn petal_static_component_metadata_rejects_executable_routes() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(tmp.path(), route_component_executable());

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("executable=true"));
    }

    #[test]
    fn petal_runtime_component_metadata_can_only_narrow_install_metadata() {
        let route = RouteIndexRecord {
            route_id: "r000001".into(),
            pattern: "[name].txt".into(),
            source_path: "petal/echo/[name].txt.wasm".into(),
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
            key_derive_operation_classes: Vec::new(),
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
    fn petal_runtime_component_metadata_rejects_widening() {
        let route = RouteIndexRecord {
            route_id: "r000001".into(),
            pattern: "[name].txt".into(),
            source_path: "petal/echo/[name].txt.wasm".into(),
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
            key_derive_operation_classes: Vec::new(),
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
    fn petal_component_routes_reject_wrong_route_export_signatures() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(
            tmp.path(),
            &route_component(&["metadata", "lookup", "read"], &[]),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid bloom:route@0.1.0"));
    }

    #[test]
    fn petal_component_routes_require_metadata_export() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(tmp.path(), &route_component(&["read"], &[]));

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("metadata export"));
    }

    #[test]
    fn petal_component_routes_ignore_nested_route_exports_for_abi_validation() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(tmp.path(), &route_component_with_nested_route_exports());

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("metadata export"));
    }

    #[test]
    fn petal_component_index_routes_require_list_handler() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(
            tmp.path(),
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        write_package_file(
            tmp.path(),
            "petal/echo/$index.wasm",
            &route_component(&["metadata", "lookup", "read"], &[]),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("\"list\" export"));
    }

    #[test]
    fn petal_component_regular_file_routes_require_lookup_and_read_exports() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(tmp.path(), &route_component(&["metadata", "read"], &[]));

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("\"lookup\" export"));
    }

    fn route_for_pattern<'a>(index: &'a RouteIndex, pattern: &str) -> &'a RouteIndexRecord {
        index
            .routes
            .iter()
            .find(|route| route.pattern == pattern)
            .unwrap_or_else(|| panic!("no route with pattern {pattern:?}"))
    }

    fn write_dynamic_dir_package(root: &Path, manifest: &[u8], route: &[u8]) {
        write_package_file(root, "petal.toml", manifest);
        write_package_file(root, "README.md", b"# example");
        write_package_file(root, "AGENTS.md", b"# example agents");
        write_package_file(root, "petal/example/[wallet]/$index.wasm", route);
    }

    const DYNAMIC_DIR_MANIFEST: &[u8] = br#"schema = "bloom.petal.package.v1"
name = "example"

[caps]
allowed = ["bloom:store", "bloom:vfs.read"]

[store]
namespaces = ["wallets"]
"#;

    #[test]
    fn petal_parameterized_dir_route_records_imported_caps_ceiling() {
        let tmp = tempfile::tempdir().unwrap();
        write_dynamic_dir_package(
            tmp.path(),
            DYNAMIC_DIR_MANIFEST,
            &route_fixtures::dynamic_dir_route_component(
                true,
                route_fixtures::FixtureVfsImport::ReadOnly,
                &["bloom:store", "bloom:vfs.read"],
                None,
            ),
        );

        let package = PreparedPetalPackage::from_dir(tmp.path()).unwrap();
        let route = route_for_pattern(&package.route_index, "[wallet]");

        assert_eq!(route.kind, RouteEntryKind::Dir);
        assert_eq!(
            route.install_metadata.required_caps,
            vec!["bloom:store".to_string(), "bloom:vfs.read".to_string()]
        );
        assert_eq!(route.install_metadata.mode, 0o777);
    }

    #[test]
    fn petal_vfs_import_caps_follow_imported_functions() {
        // A read+write vfs import must keep requiring bloom:vfs.write ...
        let tmp = tempfile::tempdir().unwrap();
        write_dynamic_dir_package(
            tmp.path(),
            DYNAMIC_DIR_MANIFEST,
            &route_fixtures::dynamic_dir_route_component(
                true,
                route_fixtures::FixtureVfsImport::ReadWrite,
                &["bloom:store", "bloom:vfs.read"],
                None,
            ),
        );
        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires missing petal.toml cap bloom:vfs.write"),
            "{err}"
        );

        // ... and records both vfs caps when the manifest allows them.
        let allowed = tempfile::tempdir().unwrap();
        write_dynamic_dir_package(
            allowed.path(),
            br#"schema = "bloom.petal.package.v1"
name = "example"

[caps]
allowed = ["bloom:store", "bloom:vfs.read", "bloom:vfs.write"]

[store]
namespaces = ["wallets"]
"#,
            &route_fixtures::dynamic_dir_route_component(
                true,
                route_fixtures::FixtureVfsImport::ReadWrite,
                &["bloom:store", "bloom:vfs.read"],
                None,
            ),
        );
        let package = PreparedPetalPackage::from_dir(allowed.path()).unwrap();
        assert_eq!(
            route_for_pattern(&package.route_index, "[wallet]")
                .install_metadata
                .required_caps,
            vec![
                "bloom:store".to_string(),
                "bloom:vfs.read".to_string(),
                "bloom:vfs.write".to_string()
            ]
        );
    }

    #[test]
    fn petal_parameterized_route_imports_still_require_manifest_caps() {
        let tmp = tempfile::tempdir().unwrap();
        write_dynamic_dir_package(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "example"

[caps]
allowed = ["bloom:store"]

[store]
namespaces = ["wallets"]
"#,
            &route_fixtures::dynamic_dir_route_component(
                true,
                route_fixtures::FixtureVfsImport::ReadOnly,
                &["bloom:store", "bloom:vfs.read"],
                None,
            ),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires missing petal.toml cap bloom:vfs.read"),
            "{err}"
        );
    }

    #[test]
    fn petal_composed_parameterized_route_records_imported_caps_ceiling() {
        let tmp = tempfile::tempdir().unwrap();
        let route = route_fixtures::dynamic_dir_route_component(
            true,
            route_fixtures::FixtureVfsImport::ReadOnly,
            &["bloom:store", "bloom:vfs.read"],
            Some("bloom:example/helper@0.1.0"),
        );
        write_dynamic_dir_package(tmp.path(), DYNAMIC_DIR_MANIFEST, &route);
        write_package_file(
            tmp.path(),
            "petal/example/[wallet]/$index.route.toml",
            br#"abi = "component"
component = "modules/index.wasm"
imports = ["components/helper.wasm"]
"#,
        );
        write_package_file(tmp.path(), "modules/index.wasm", &route);
        write_package_file(
            tmp.path(),
            "components/helper.wasm",
            &wat::parse_str(
                r#"
(component
  (instance)
  (export "bloom:example/helper@0.1.0" (instance 0))
)
"#,
            )
            .unwrap(),
        );

        let package = PreparedPetalPackage::from_dir(tmp.path()).unwrap();
        let route = route_for_pattern(&package.route_index, "[wallet]");
        assert_eq!(route.kind, RouteEntryKind::Dir);
        assert_eq!(
            route.install_metadata.required_caps,
            vec!["bloom:store".to_string(), "bloom:vfs.read".to_string()]
        );
    }

    #[test]
    fn petal_runtime_metadata_cache_ttl_is_unrestricted_only_for_parameterized_routes() {
        let record = |params: Vec<String>| RouteIndexRecord {
            route_id: "r000001".into(),
            pattern: "[name].txt".into(),
            source_path: "petal/echo/[name].txt.wasm".into(),
            artifact_path: "artifacts/routes/r000001.wasm".into(),
            artifact_hash: "00".repeat(32),
            abi: RouteAbi::ComponentBloomRoute010,
            kind: RouteEntryKind::File,
            ops: vec![RouteOp::Lookup, RouteOp::Read],
            params,
            specificity: [1, 0, 1],
            install_metadata: InstallRouteMetadata {
                mode: 0o444,
                cache_ttl_ms: None,
                side_effecting_read: true,
                write_async: false,
                executable: false,
                required_caps: Vec::new(),
                sign_intent: None,
            },
            key_derive_operation_classes: Vec::new(),
        };
        let metadata = ComponentRouteMetadata {
            kind: ComponentRouteEntryKind::File,
            mode: 0o444,
            cache_ttl_ms: Some(1000),
            side_effecting_read: false,
            write_async: false,
            executable: false,
            required_caps: Vec::new(),
            sign_intent: None,
        };

        let narrowed = narrow_runtime_route_metadata(
            &record(vec!["name".into()]),
            &metadata,
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(narrowed.cache_ttl_ms, Some(1000));

        let err = narrow_runtime_route_metadata(&record(Vec::new()), &metadata, &BTreeSet::new())
            .unwrap_err();
        assert!(err.to_string().contains("widens cacheability"), "{err}");
    }

    #[test]
    fn petal_component_imports_require_declared_caps_and_record_them() {
        let wasm = route_component_http();

        let missing = tempfile::tempdir().unwrap();
        write_petal_package_with_route(missing.path(), wasm);
        let err = PreparedPetalPackage::from_dir(missing.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires missing petal.toml cap bloom:http")
        );

        let allowed = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            allowed.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["get"]
paths = ["/*"]
"#,
            wasm,
        );
        let package = PreparedPetalPackage::from_dir(allowed.path()).unwrap();
        assert_eq!(
            package.route_index.routes[0].install_metadata.required_caps,
            vec!["bloom:http".to_string()]
        );
    }

    #[test]
    fn petal_http_cap_requires_a_usable_network_allow_rule() {
        let missing = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            missing.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:http"]
"#,
            route_component_http(),
        );
        let err = PreparedPetalPackage::from_dir(missing.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("requires at least one [[net.allow]]")
        );

        let empty_methods = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            empty_methods.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
paths = ["/*"]
"#,
            route_component_http(),
        );
        let err = PreparedPetalPackage::from_dir(empty_methods.path()).unwrap_err();
        assert!(err.to_string().contains("host and at least one method"));
    }

    #[test]
    fn petal_network_policy_rejects_unknown_fields_and_implicit_wildcards() {
        for (extra, expected) in [
            (r#"path = ["/orders"]"#, "unknown field `path`"),
            ("paths = []", "paths must be explicit and non-empty"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let manifest = format!(
                r#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["get"]
{extra}
"#
            );
            write_petal_package_with_manifest_and_route(
                tmp.path(),
                manifest.as_bytes(),
                route_component_http(),
            );
            let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[test]
    fn petal_manifest_accepts_source_metadata_and_rejects_unknown_policy_fields() {
        let valid = r#"schema = "bloom.petal.package.v1"
name = "polymarket"

[source]
kind = "github"
repository = "bloom-directory/bloom-petal-polymarket"

[build]
command = "scripts/build.sh"
outputs = ["petal/polymarket"]

[consent]
summary = "Polymarket routes"

[caps]
allowed = ["bloom:http", "bloom:sign", "bloom:store"]

[[net.allow]]
binding = "clob"
host = "clob.polymarket.com"
methods = ["get"]
paths = ["/orders"]

[sign]
allowed_intents = ["polymarket.order"]

[store]
namespaces = ["state"]
secret_namespaces = ["secrets"]
"#;
        toml::from_str::<PetalToml>(valid).expect("valid GitHub source manifest");

        for (section, field) in [
            ("consent", "summry"),
            ("caps", "allowd"),
            ("sign", "allowed_intent"),
            ("key", "derivations"),
            ("store", "namespace"),
            ("source", "repo"),
            ("build", "output"),
        ] {
            let manifest = format!("name = \"echo\"\n[{section}]\n{field} = []\n");
            let err = toml::from_str::<PetalToml>(&manifest).unwrap_err();
            assert!(
                err.to_string().contains("unknown field"),
                "{section}.{field} should fail closed: {err}"
            );
        }
    }

    #[test]
    fn petal_consent_preserves_named_endpoint_bindings() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
binding = "clob"
host = "clob.example.com"
methods = ["post"]
paths = ["/orders"]
"#,
            route_component_http(),
        );
        let package = PreparedPetalPackage::from_dir(tmp.path()).unwrap();
        let consent = petal_consent_summary(&package).unwrap();
        assert_eq!(consent.network.len(), 1);
        assert_eq!(consent.network[0].binding.as_deref(), Some("clob"));
        assert_eq!(consent.network[0].effective_origin, None);
        assert_eq!(consent.network[0].paths, vec!["/orders"]);

        let mut consent = consent;
        apply_petal_consent_endpoint_bindings(
            &mut consent,
            &BTreeMap::from([(
                "clob".to_string(),
                "https://clob.internal.example".to_string(),
            )]),
        )
        .unwrap();
        assert_eq!(
            consent.network[0].effective_origin.as_deref(),
            Some("https://clob.internal.example")
        );

        let err = apply_petal_consent_endpoint_bindings(
            &mut consent,
            &BTreeMap::from([(
                "undeclared".to_string(),
                "https://other.example".to_string(),
            )]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("is not declared"));
    }

    #[test]
    fn petal_component_chain_import_requires_declared_chain_capability() {
        assert_eq!(
            component_import_caps("bloom:chain/read@0.1.0"),
            Some(&["bloom:chain" as &str][..])
        );
        assert_eq!(component_import_caps("bloom:chain/read@9.9.9"), None);
    }

    #[test]
    fn petal_component_imports_require_exact_bloom_wit_versions() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["get"]
paths = ["/*"]
"#,
            &route_component(&["metadata", "read"], &["bloom:http/fetch@999.0.0"]),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported host item"));
    }

    #[test]
    fn petal_component_signing_versions_are_explicit_and_other_versions_fail_closed() {
        assert_eq!(
            component_import_caps("bloom:sign/signing@0.1.0"),
            Some(&["bloom:sign"][..])
        );
        assert!(matches!(
            component_host_interface("bloom:sign/signing@0.1.0"),
            Some(ComponentHostInterface::SignSigningV1)
        ));
        assert_eq!(
            component_import_caps("bloom:sign/signing@0.2.0"),
            Some(&["bloom:sign"][..])
        );
        assert!(matches!(
            component_host_interface("bloom:sign/signing@0.2.0"),
            Some(ComponentHostInterface::SignSigningV2)
        ));
        assert!(component_import_caps("bloom:sign/signing@0.3.0").is_none());
        assert!(component_host_interface("bloom:sign/signing@0.3.0").is_none());
        assert!(component_import_caps("bloom:sign/signing@0.4.0").is_none());
        assert!(component_host_interface("bloom:sign/signing@0.4.0").is_none());
        assert!(component_import_caps("bloom:sign/signing@9.9.9").is_none());
        assert!(component_host_interface("bloom:sign/signing@9.9.9").is_none());
    }

    #[test]
    fn petal_component_key_derivation_version_and_capability_are_explicit() {
        assert_eq!(
            component_import_caps("bloom:key/derive@0.1.0"),
            Some(&["bloom:key.derive"][..])
        );
        assert!(matches!(
            component_host_interface("bloom:key/derive@0.1.0"),
            Some(ComponentHostInterface::KeyDerive)
        ));
        assert!(component_import_caps("bloom:key/derive@0.2.0").is_none());
        assert!(component_host_interface("bloom:key/derive@0.2.0").is_none());
        assert!(host_import_instance_matches(
            ComponentHostInterface::KeyDerive,
            r#"(component
              (type $interface
                (instance
                  (type $bytes (list u8))
                  (type $outcome (result $bytes (error string)))
                  (type $request
                    (func (param "request" $bytes) (result $outcome)))
                  (export "request" (func (type $request)))))
              (import "bloom:key/derive@0.1.0"
                (instance (type $interface))))"#,
        ));
    }

    #[test]
    fn petal_component_signing_recognizes_its_exported_nominal_types() {
        let interface = ComponentHostInterface::SignSigningV2;
        assert!(matches!(
            host_type_export(interface, "approval-pending"),
            Some(HostTypeExport::SignApprovalPending)
        ));
        assert!(matches!(
            host_type_export(interface, "sign-result"),
            Some(HostTypeExport::SafeSignResultStructured)
        ));
    }

    #[test]
    fn petal_component_signing_v2_accepts_the_safe_atomic_batch_shape() {
        assert!(host_import_instance_matches(
            ComponentHostInterface::SignSigningV2,
            r#"(component
              (type $interface
                (instance
                  (type $bytes (list u8))
                  (type $approval (record
                    (field "action-id" string)
                    (field "expires-ms" u64)))
                  (export "approval-pending" (type $approval-export (eq $approval)))
                  (type $selector (enum "exact" "reusable"))
                  (export "selector" (type $selector-export (eq $selector)))
                  (type $item (record
                    (field "preimage" $bytes)
                    (field "claimed-hash" $bytes)))
                  (export "payload-sign-item" (type $item-export (eq $item)))
                  (type $maybe-bytes (option $bytes))
                  (type $maybe-string (option string))
                  (type $request (record
                    (field "wallet" string)
                    (field "payloads" (list $item-export))
                    (field "signature-algorithm" string)
                    (field "operation-class" string)
                    (field "petal-use-claim-jcs" $bytes)
                    (field "claim-assurance-evidence" $maybe-bytes)
                    (field "approval-hint" $maybe-string)
                    (field "action" $maybe-bytes)
                    (field "advisory" $maybe-bytes)
                    (field "selector" $selector-export)
                    (field "key-ref-jcs" $maybe-bytes)))
                  (export "payload-batch-sign-request" (type $request-export (eq $request)))
                  (type $batch-result (variant
                    (case "signatures" (list $bytes))
                    (case "approval-pending" $approval-export)))
                  (export "sign-batch-result" (type $batch-result-export (eq $batch-result)))
                  (type $outcome (result $batch-result-export (error string)))
                  (type $sign (func
                    (param "request" $request-export)
                    (result $outcome)))
                  (export "sign-payload-batch" (func (type $sign)))))
              (import "bloom:sign/signing@0.2.0"
                (instance (type $interface))))"#,
        ));
    }

    #[test]
    fn petal_component_outbox_recognizes_inspection_type_and_function() {
        let interface = ComponentHostInterface::TxOutbox;
        assert!(matches!(
            host_type_export(interface, "inspection"),
            Some(HostTypeExport::OutboxInspection)
        ));
        assert!(matches!(
            host_func_export(interface, "inspect"),
            Some(HostFuncExport::EvmTxInspect)
        ));
    }

    #[test]
    fn petal_component_imports_must_be_interface_instances() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["get"]
paths = ["/*"]
"#,
            &route_component_with_func_import("bloom:http/fetch@0.1.0"),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("must be an interface instance"));
    }

    #[test]
    fn petal_component_imports_require_bloom_wit_interface_shapes() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["get"]
paths = ["/*"]
"#,
            &route_component(&["metadata", "read"], &["bloom:http/fetch@0.1.0"]),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid Bloom WIT interface shape")
        );
    }

    #[test]
    fn petal_component_imports_accept_narrowed_bloom_interfaces() {
        assert!(host_import_instance_matches(
            ComponentHostInterface::EnvRuntime,
            r#"
(component
  (type (instance
    (type (list u8))
    (type (result 0 (error string)))
    (type (func (param "len" u32) (result 1)))
    (export "random-bytes" (func (type 2)))
  ))
  (import "bloom:env/runtime@0.1.0" (instance (type 0)))
)
"#,
        ));
        assert!(host_import_instance_matches(
            ComponentHostInterface::StoreKv,
            r#"
(component
  (type (instance
    (type (list u8))
    (type (option 0))
    (type (result 1 (error string)))
    (type (func (param "namespace" string) (param "key" string) (result 2)))
    (export "get" (func (type 3)))
  ))
  (import "bloom:store/kv@0.1.0" (instance (type 0)))
)
"#,
        ));
        assert!(host_import_instance_matches(
            ComponentHostInterface::VfsReadwrite,
            r#"
(component
  (type (instance
    (type (list u8))
    (type (result 0 (error string)))
    (type (func (param "path" string) (result 1)))
    (export "read" (func (type 2)))
  ))
  (import "bloom:vfs/readwrite@0.1.0" (instance (type 0)))
)
"#,
        ));
    }

    #[test]
    fn petal_component_routes_reject_non_bloom_imports() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_route(
            tmp.path(),
            &route_component(&["metadata", "read"], &["wasi:http/outgoing-handler@0.2.0"]),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported host item"));
    }

    #[test]
    fn petal_component_sign_imports_require_intent_policy() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:sign"]
"#,
            route_component_sign(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("[sign].allowed_intents"));

        let allowed = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            allowed.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:sign"]

[sign]
allowed_intents = ["test.intent"]
"#,
            route_component_sign(),
        );

        PreparedPetalPackage::from_dir(allowed.path()).unwrap();
    }

    #[test]
    fn petal_key_derive_policy_is_route_scoped_in_the_immutable_index() {
        let package = prepared_triad_fixture_with_manifest(
            br#"schema = "bloom.petal.package.v1"
name = "triad-authority-fixture"
[caps]
allowed = ["bloom:key.derive", "bloom:sign", "bloom:store"]

[sign]
allowed_intents = ["fixture.unrelated", "fixture.secondary", "fixture.payload"]

[store]
namespaces = ["fixture-public"]

[[key.derive]]
route = "session.json"
operation_classes = ["fixture.secondary", "fixture.payload"]
"#,
        )
        .unwrap();

        let route = &package.route_index.routes[0];
        assert_eq!(route.pattern, "session.json");
        assert_eq!(
            route.key_derive_operation_classes,
            vec![
                "fixture.payload".to_string(),
                "fixture.secondary".to_string()
            ]
        );
        assert!(
            !route
                .key_derive_operation_classes
                .contains(&"fixture.unrelated".to_string())
        );

        let serialized = serde_json::to_value(route).unwrap();
        assert_eq!(
            serialized["key_derive_operation_classes"],
            serde_json::json!(["fixture.payload", "fixture.secondary"])
        );
        let mut legacy = serialized;
        legacy
            .as_object_mut()
            .unwrap()
            .remove("key_derive_operation_classes");
        let legacy: RouteIndexRecord = serde_json::from_value(legacy).unwrap();
        assert!(legacy.key_derive_operation_classes.is_empty());
    }

    #[test]
    fn petal_key_derive_policy_rejects_ambiguous_or_broadened_authority() {
        let cases = [
            (
                "unknown route",
                r#"[[key.derive]]
route = "missing.json"
operation_classes = ["fixture.payload"]
"#,
                "unknown route",
            ),
            (
                "duplicate route",
                r#"[[key.derive]]
route = "session.json"
operation_classes = ["fixture.payload"]

[[key.derive]]
route = "session.json"
operation_classes = ["fixture.payload"]
"#,
                "duplicate declaration",
            ),
            (
                "empty classes",
                r#"[[key.derive]]
route = "session.json"
operation_classes = []
"#,
                "operation_classes must be non-empty",
            ),
            (
                "duplicate classes",
                r#"[[key.derive]]
route = "session.json"
operation_classes = ["fixture.payload", "fixture.payload"]
"#,
                "duplicate operation class",
            ),
            (
                "invalid class",
                r#"[[key.derive]]
route = "session.json"
operation_classes = ["fixture/payload"]
"#,
                "unsupported byte",
            ),
            (
                "undeclared class",
                r#"[[key.derive]]
route = "session.json"
operation_classes = ["fixture.undeclared"]
"#,
                "is not declared in [sign].allowed_intents",
            ),
            (
                "unknown declaration field",
                r#"[[key.derive]]
route = "session.json"
operation_class = ["fixture.payload"]
operation_classes = ["fixture.payload"]
"#,
                "unknown field `operation_class`",
            ),
        ];

        for (label, declaration, expected) in cases {
            let manifest = format!(
                r#"schema = "bloom.petal.package.v1"
name = "triad-authority-fixture"
[caps]
allowed = ["bloom:key.derive", "bloom:sign", "bloom:store"]

[sign]
allowed_intents = ["fixture.payload"]

[store]
namespaces = ["fixture-public"]

{declaration}"#
            );
            let error = prepared_triad_fixture_with_manifest(manifest.as_bytes()).unwrap_err();
            assert!(error.to_string().contains(expected), "{label}: {error}");
        }

        let no_import = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            no_import.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:key.derive"]

[sign]
allowed_intents = ["fixture.payload"]

[[key.derive]]
route = "hello.txt"
operation_classes = ["fixture.payload"]
"#,
            route_component_no_imports(),
        );
        let error = PreparedPetalPackage::from_dir(no_import.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not import bloom:key.derive"),
            "{error}"
        );
    }

    #[test]
    fn petal_store_cap_requires_declared_namespaces() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:store"]
"#,
            route_component_no_imports(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("[store].namespaces"));

        let allowed = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            allowed.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:store"]

[store]
namespaces = ["orders"]
secret_namespaces = ["credentials"]
"#,
            route_component_no_imports(),
        );
        let policy = store_policy_from_manifest_toml(
            br#"schema = "bloom.petal.package.v1"
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
        PreparedPetalPackage::from_dir(allowed.path()).unwrap();
    }

    #[test]
    fn petal_store_namespaces_reject_ambiguous_path_segments() {
        let tmp = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:store"]

[store]
namespaces = ["orders/archive"]
"#,
            route_component_no_imports(),
        );

        let err = PreparedPetalPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported byte"));

        let drive = tempfile::tempdir().unwrap();
        write_petal_package_with_manifest_and_route(
            drive.path(),
            br#"schema = "bloom.petal.package.v1"
name = "echo"
[caps]
allowed = ["bloom:store"]

[store]
namespaces = ["C:"]
"#,
            route_component_no_imports(),
        );

        let err = PreparedPetalPackage::from_dir(drive.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported byte"));
    }

    fn write_package_file(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn write_petal_package(root: &Path) {
        write_petal_package_with_route(root, route_component_no_imports());
    }

    fn write_petal_package_with_route(root: &Path, route: &[u8]) {
        write_petal_package_with_manifest_and_route(
            root,
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
            route,
        );
    }

    fn write_petal_package_with_manifest_and_route(root: &Path, manifest: &[u8], route: &[u8]) {
        write_package_file(root, "petal.toml", manifest);
        write_package_file(root, "README.md", b"# echo");
        write_package_file(root, "AGENTS.md", b"# echo agents");
        write_package_file(root, "petal/echo/hello.txt.wasm", route);
    }

    fn prepared_triad_fixture_with_manifest(
        manifest: &[u8],
    ) -> Result<PreparedPetalPackage, PetalError> {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/triad-authority-petal");
        let mut files = collect_package_dir(&fixture)?;
        files
            .iter_mut()
            .find(|file| file.path == "petal.toml")
            .expect("fixture manifest")
            .bytes = manifest.to_vec();
        PreparedPetalPackage::from_files(files)
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
        let (func_type, mut ty) = builder.type_function(None);
        ty.params(std::iter::empty::<(&str, PrimitiveValType)>());
        ty.result(None);
        builder.import(import, ComponentTypeRef::Func(func_type));
        builder.finish()
    }

    fn route_component_with_nested_route_exports() -> Vec<u8> {
        let mut builder = ComponentBuilder::default();
        builder.component(None, route_component_builder(&["metadata", "read"], &[]));
        builder.finish()
    }

    fn host_import_instance_matches(interface: ComponentHostInterface, source: &str) -> bool {
        let wasm = wat::parse_str(source).unwrap();
        let mut component_types = Vec::new();
        for payload in Parser::new(0).parse_all(&wasm) {
            match payload.unwrap() {
                Payload::ComponentTypeSection(reader) => {
                    for ty in reader {
                        component_types.push(ComponentTypeEntry::Type(ty.unwrap()));
                    }
                }
                Payload::ComponentImportSection(reader) => {
                    for import in reader {
                        let import = import.unwrap();
                        if let WasmComponentTypeRef::Instance(type_index) = import.ty {
                            return is_host_interface_instance(
                                interface,
                                type_index,
                                &component_types,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn route_component_builder(exports: &[&str], imports: &[&str]) -> ComponentBuilder {
        let mut builder = ComponentBuilder::default();
        let (func_type, mut ty) = builder.type_function(None);
        ty.params(std::iter::empty::<(&str, PrimitiveValType)>());
        ty.result(None);

        let instance_type = builder.type_instance(None, &InstanceType::new());
        for import in imports {
            builder.import(*import, ComponentTypeRef::Instance(instance_type));
        }

        let module = route_component_core_module(exports);
        let module = builder.core_module(None, &module);
        let instance = builder.core_instantiate(None, module, std::iter::empty::<(&str, _)>());
        for export in exports {
            let core_func = builder.core_alias_export(
                None,
                instance,
                &format!("__bloom_route_{export}"),
                ExportKind::Func,
            );
            let func = builder.lift_func(
                None,
                core_func,
                func_type,
                std::iter::empty::<CanonicalOption>(),
            );
            builder.export(*export, ComponentExportKind::Func, func, None);
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
