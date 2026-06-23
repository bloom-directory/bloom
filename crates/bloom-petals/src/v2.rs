//! Experimental v2 file-driven local app package scanner.
//!
//! This is intentionally incremental: it scans `app/<name>/.../*.wasm`
//! route trees, prepares content-addressed package records, and supports the
//! existing `petal_dispatch` compatibility ABI while the component runner
//! matures.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wasmparser::{ExternalKind, FuncType, Parser, Payload, TypeRef, ValType, Validator};

use crate::error::PetalError;

pub const ROUTE_INDEX_SCHEMA: &str = "bloom.petal.route-index.v1";
const PACKAGE_DIGEST_PREFIX: &[u8] = b"bloom.petal.package.v2\0";

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
    caps: PetalCaps,
}

#[derive(Debug, Default, Deserialize)]
struct PetalCaps {
    #[serde(default)]
    allowed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteValidation {
    abi: RouteAbi,
    required_caps: Vec<String>,
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
    #[serde(rename = "compat:petal-dispatch-v1")]
    CompatPetalDispatchV1,
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
            let validation = validate_route_wasm(&source_path, source_bytes, &allowed_caps)?;
            let artifact_path = format!("artifacts/routes/{}.wasm", route.route_id);
            let (kind, ops) = route_kind_and_ops(&source_path);
            route_index.routes.push(RouteIndexRecord {
                route_id: route.route_id,
                pattern: route.pattern,
                source_path,
                artifact_path,
                artifact_hash: hex::encode(blake3::hash(source_bytes).as_bytes()),
                abi: validation.abi,
                kind,
                ops,
                params: route.params,
                specificity: route.specificity.as_array(),
                install_metadata: InstallRouteMetadata {
                    mode: 0o444,
                    cache_ttl_ms: None,
                    side_effecting_read: false,
                    write_async: false,
                    executable: false,
                    required_caps: validation.required_caps,
                    sign_intent: None,
                },
            });
        }

        Ok(Self {
            hash,
            name: manifest.name,
            files,
            route_index,
        })
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
    Ok(())
}

fn collect_package_dir(root: &Path) -> Result<Vec<NormalizedPackageFile>, PetalError> {
    let mut files = Vec::new();
    collect_package_dir_inner(root, root, &mut files)?;
    Ok(files)
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
) -> Result<RouteValidation, PetalError> {
    Validator::new()
        .validate_all(wasm)
        .map_err(|e| PetalError::InvalidWasm(format!("{path}: invalid route wasm: {e}")))?;

    let mut has_memory_export = false;
    let mut types = Vec::new();
    let mut func_type_indices = Vec::new();
    let mut imported_func_count = 0usize;
    let mut alloc_export: Option<u32> = None;
    let mut dispatch_export: Option<u32> = None;
    let mut saw_component = false;
    let mut required_caps = BTreeSet::new();
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))? {
            Payload::Version { encoding, .. } => {
                saw_component = matches!(encoding, wasmparser::Encoding::Component);
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export =
                        export.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?;
                    match (export.name, export.kind) {
                        ("memory", ExternalKind::Memory) => has_memory_export = true,
                        ("petal_alloc", ExternalKind::Func) => alloc_export = Some(export.index),
                        ("petal_dispatch", ExternalKind::Func) => {
                            dispatch_export = Some(export.index)
                        }
                        _ => {}
                    }
                }
            }
            Payload::TypeSection(reader) => {
                for ty in reader.into_iter_err_on_gc_types() {
                    types.push(ty.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?);
                }
            }
            Payload::FunctionSection(reader) => {
                for type_index in reader {
                    func_type_indices.push(
                        type_index.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?,
                    );
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import =
                        import.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?;
                    let TypeRef::Func(_type_index) = import.ty else {
                        return Err(PetalError::InvalidWasm(format!(
                            "{path}: compatibility route import {}.{} must be a function",
                            import.module, import.name
                        )));
                    };
                    let TypeRef::Func(type_index) = import.ty else {
                        unreachable!("checked above");
                    };
                    let import_type = types.get(type_index as usize).ok_or_else(|| {
                        PetalError::InvalidWasm(format!(
                            "{path}: compatibility route import {}.{} references missing function type",
                            import.module, import.name
                        ))
                    })?;
                    imported_func_count += 1;
                    let Some(cap) = compat_import_cap(import.module, import.name) else {
                        return Err(PetalError::InvalidWasm(format!(
                            "{path}: compatibility route imports unsupported host function {}.{}",
                            import.module, import.name
                        )));
                    };
                    if cap == "bloom:sign" {
                        return Err(PetalError::InvalidWasm(format!(
                            "{path}: compatibility route import {}.{} is unsupported until v2 sign-intent policy enforcement is implemented",
                            import.module, import.name
                        )));
                    }
                    validate_compat_import_sig(path, import.module, import.name, import_type)?;
                    if !allowed_caps.contains(cap) {
                        return Err(PetalError::InvalidWasm(format!(
                            "{path}: compatibility route import {}.{} requires missing petal.toml cap {cap}",
                            import.module, import.name
                        )));
                    }
                    required_caps.insert(cap.to_string());
                }
            }
            Payload::ComponentExportSection(reader) => {
                for export in reader {
                    export.map_err(|e| PetalError::InvalidWasm(format!("{path}: {e}")))?;
                }
            }
            Payload::StartSection { func, .. } => {
                return Err(PetalError::InvalidWasm(format!(
                    "{path}: compatibility route declares start function {func}; start sections are not allowed"
                )));
            }
            _ => {}
        }
    }

    if saw_component {
        return Err(PetalError::InvalidWasm(format!(
            "{path}: component route validation for bloom:route@0.1.0 is not implemented yet"
        )));
    }

    if !has_memory_export {
        return Err(PetalError::InvalidWasm(format!(
            "{path}: compatibility route missing Memory export \"memory\""
        )));
    }
    let alloc_type = exported_func_type(
        path,
        "petal_alloc",
        alloc_export,
        imported_func_count,
        &func_type_indices,
        &types,
    )?;
    let dispatch_type = exported_func_type(
        path,
        "petal_dispatch",
        dispatch_export,
        imported_func_count,
        &func_type_indices,
        &types,
    )?;
    validate_func_sig(
        path,
        "petal_alloc",
        alloc_type,
        &[ValType::I32],
        &[ValType::I32],
    )?;
    validate_func_sig(
        path,
        "petal_dispatch",
        dispatch_type,
        &[ValType::I32, ValType::I32],
        &[ValType::I64],
    )?;
    Ok(RouteValidation {
        abi: RouteAbi::CompatPetalDispatchV1,
        required_caps: required_caps.into_iter().collect(),
    })
}

fn exported_func_type<'a>(
    path: &str,
    name: &str,
    export_index: Option<u32>,
    imported_func_count: usize,
    func_type_indices: &[u32],
    types: &'a [FuncType],
) -> Result<&'a FuncType, PetalError> {
    let Some(export_index) = export_index else {
        return Err(PetalError::InvalidWasm(format!(
            "{path}: compatibility route missing Func export {name:?}"
        )));
    };
    let export_index = export_index as usize;
    if export_index < imported_func_count {
        return Err(PetalError::InvalidWasm(format!(
            "{path}: compatibility route export {name:?} must be defined by the route module"
        )));
    }
    let local_index = export_index - imported_func_count;
    let Some(type_index) = func_type_indices.get(local_index).copied() else {
        return Err(PetalError::InvalidWasm(format!(
            "{path}: compatibility route export {name:?} references missing function"
        )));
    };
    types.get(type_index as usize).ok_or_else(|| {
        PetalError::InvalidWasm(format!(
            "{path}: compatibility route export {name:?} references missing function type"
        ))
    })
}

fn validate_func_sig(
    path: &str,
    name: &str,
    ty: &FuncType,
    params: &[ValType],
    results: &[ValType],
) -> Result<(), PetalError> {
    if ty.params() == params && ty.results() == results {
        Ok(())
    } else {
        Err(PetalError::InvalidWasm(format!(
            "{path}: compatibility route export {name:?} has invalid signature"
        )))
    }
}

fn validate_compat_import_sig(
    path: &str,
    module: &str,
    name: &str,
    ty: &FuncType,
) -> Result<(), PetalError> {
    let Some((params, results)) = compat_import_signature(module, name) else {
        return Ok(());
    };
    validate_func_sig(path, &format!("{module}.{name}"), ty, params, results)
}

fn compat_import_signature(
    module: &str,
    name: &str,
) -> Option<(&'static [ValType], &'static [ValType])> {
    match (module, name) {
        ("bloom", "vfs_read" | "vfs_write") => Some((
            &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
            &[ValType::I32],
        )),
        (
            "bloom.v1",
            "vfs_read" | "vfs_write" | "vfs_list" | "http_fetch" | "sign_hash" | "store_get"
            | "store_list" | "store_del_if_value",
        ) => Some((
            &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
            &[ValType::I32],
        )),
        ("bloom.v1", "store_put" | "store_put_new") => Some((
            &[
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
                ValType::I32,
            ],
            &[ValType::I32],
        )),
        ("bloom.v1", "store_del") => Some((&[ValType::I32, ValType::I32], &[ValType::I32])),
        _ => None,
    }
}

fn compat_import_cap(module: &str, name: &str) -> Option<&'static str> {
    match (module, name) {
        ("bloom", "vfs_read") | ("bloom.v1", "vfs_read" | "vfs_list") => Some("bloom:vfs.read"),
        ("bloom", "vfs_write") | ("bloom.v1", "vfs_write") => Some("bloom:vfs.write"),
        ("bloom.v1", "http_fetch") => Some("bloom:http"),
        ("bloom.v1", "sign_hash") => Some("bloom:sign"),
        (
            "bloom.v1",
            "store_get" | "store_put" | "store_put_new" | "store_del" | "store_del_if_value"
            | "store_list",
        ) => Some("bloom:store"),
        _ => None,
    }
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
    use std::sync::Arc;

    use crate::abi::{DispatchOp, DispatchRequest, DispatchResponse};
    use crate::host::DenyHost;
    use crate::vm::{PetalVm, RunOptions};

    use super::*;

    #[test]
    fn v2_scanner_matches_static_and_dynamic_routes() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
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
    fn v2_tar_and_dir_inputs_share_normalized_hash() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package(tmp.path());
        let dir = PreparedAppPackage::from_dir(tmp.path()).unwrap();
        let wasm = compat_wasm("hello");
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
            ("app/echo/hello.txt.wasm", wasm.as_slice()),
        ])))
        .unwrap();

        assert_eq!(dir.hash, tar.hash);
        assert_eq!(dir.route_index.routes, tar.route_index.routes);
        assert_eq!(dir.route_index.routes[0].route_id, "r000001");
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
    fn v2_compat_routes_reject_unsupported_imports() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(
            tmp.path(),
            &wat::parse_str(
                r#"
                (module
                  (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024))
                  (func (export "petal_dispatch") (param i32 i32) (result i64) (i64.const 0)))
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported host function"));
        assert!(err.to_string().contains("wasi_snapshot_preview1.fd_write"));
    }

    #[test]
    fn v2_compat_routes_require_correct_export_kinds() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(
            tmp.path(),
            &wat::parse_str(
                r#"
                (module
                  (memory 1)
                  (global $petal_dispatch (export "petal_dispatch") i64 (i64.const 0))
                  (export "memory" (memory 0))
                  (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024)))
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing Func export \"petal_dispatch\"")
        );
    }

    #[test]
    fn v2_compat_routes_require_dispatch_signatures() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(
            tmp.path(),
            &wat::parse_str(
                r#"
                (module
                  (memory (export "memory") 1)
                  (func (export "petal_alloc") (param i64) (result i32) (i32.const 1024))
                  (func (export "petal_dispatch") (param i32 i32) (result i64) (i64.const 0)))
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("export \"petal_alloc\" has invalid signature")
        );
    }

    #[test]
    fn v2_compat_routes_require_valid_wasm() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(
            tmp.path(),
            &wat::parse_str(
                r#"
                (module
                  (memory (export "memory") 1)
                  (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024))
                  (func (export "petal_dispatch") (param i32 i32) (result i64)))
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid route wasm"));
    }

    #[test]
    fn v2_compat_routes_reject_start_sections() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(
            tmp.path(),
            &wat::parse_str(
                r#"
                (module
                  (memory (export "memory") 1)
                  (func $init)
                  (start $init)
                  (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024))
                  (func (export "petal_dispatch") (param i32 i32) (result i64) (i64.const 0)))
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("start sections are not allowed"));
    }

    #[test]
    fn v2_compat_imports_must_be_functions() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:http"]
"#,
            &wat::parse_str(
                r#"
                (module
                  (import "bloom.v1" "http_fetch" (memory 1))
                  (memory (export "memory") 1)
                  (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024))
                  (func (export "petal_dispatch") (param i32 i32) (result i64) (i64.const 0)))
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("must be a function"));
    }

    #[test]
    fn v2_compat_imports_require_host_signatures() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:http"]
"#,
            &wat::parse_str(
                r#"
                (module
                  (import "bloom.v1" "http_fetch" (func $http_fetch (param i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024))
                  (func (export "petal_dispatch") (param i32 i32) (result i64) (i64.const 0)))
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("export \"bloom.v1.http_fetch\" has invalid signature")
        );
    }

    #[test]
    fn v2_compat_imports_accept_legacy_bloom_vfs_namespace() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:vfs.read"]
"#,
            &wat::parse_str(
                r#"
                (module
                  (import "bloom" "vfs_read"
                    (func $vfs_read (param i32 i32 i32 i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024))
                  (func (export "petal_dispatch") (param i32 i32) (result i64) (i64.const 0)))
                "#,
            )
            .unwrap(),
        );

        let package = PreparedAppPackage::from_dir(tmp.path()).unwrap();
        assert_eq!(
            package.route_index.routes[0].install_metadata.required_caps,
            vec!["bloom:vfs.read".to_string()]
        );
    }

    #[test]
    fn v2_compat_sign_imports_are_rejected_until_intent_policy_exists() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_manifest_and_route(
            tmp.path(),
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:sign"]
"#,
            &wat::parse_str(
                r#"
                (module
                  (import "bloom.v1" "sign_hash"
                    (func $sign_hash (param i32 i32 i32 i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024))
                  (func (export "petal_dispatch") (param i32 i32) (result i64) (i64.const 0)))
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("sign-intent policy"));
    }

    #[test]
    fn v2_rejects_extra_app_roots() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package(tmp.path());
        write_package_file(
            tmp.path(),
            "app/other/hello.txt.wasm",
            &compat_wasm("wrong root"),
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
            &compat_wasm("index"),
        );
        std::fs::rename(
            tmp.path().join("app/echo/hello.txt.wasm"),
            tmp.path().join("app/echo/$index.wasm"),
        )
        .unwrap();
        write_package_file(
            tmp.path(),
            "app/echo/items/$list.wasm",
            &compat_wasm("list"),
        );
        write_package_file(
            tmp.path(),
            "app/echo/items/[id]/$lookup.wasm",
            &compat_wasm("lookup"),
        );

        let package = PreparedAppPackage::from_dir(tmp.path()).unwrap();
        let patterns = package
            .route_index
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
    fn v2_compat_imports_require_declared_caps_and_record_them() {
        let wasm = wat::parse_str(
            r#"
            (module
              (import "bloom.v1" "http_fetch"
                (func $http_fetch (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "petal_alloc") (param i32) (result i32) (i32.const 1024))
              (func (export "petal_dispatch") (param i32 i32) (result i64) (i64.const 0)))
            "#,
        )
        .unwrap();

        let missing = tempfile::tempdir().unwrap();
        write_v2_package_with_route(missing.path(), &wasm);
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
            &wasm,
        );
        let package = PreparedAppPackage::from_dir(allowed.path()).unwrap();
        assert_eq!(
            package.route_index.routes[0].install_metadata.required_caps,
            vec!["bloom:http".to_string()]
        );
    }

    #[test]
    fn v2_component_routes_are_rejected_until_wit_validation_exists() {
        let tmp = tempfile::tempdir().unwrap();
        write_v2_package_with_route(
            tmp.path(),
            &wat::parse_str(
                r#"
                (component)
                "#,
            )
            .unwrap(),
        );

        let err = PreparedAppPackage::from_dir(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("component route validation"));
    }

    #[tokio::test]
    async fn v2_route_dispatches_through_compat_petal_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        write_package_file(tmp.path(), "petal.toml", br#"name = "echo""#);
        write_package_file(tmp.path(), "README.md", b"# echo");
        write_package_file(tmp.path(), "AGENTS.md", b"# echo agents");
        let wasm = wat::parse_str(compat_read_wat("hello v2")).unwrap();
        write_package_file(tmp.path(), "app/echo/[name].txt.wasm", &wasm);

        let package = PetalAppPackage::scan_dir(tmp.path()).unwrap();
        let matched = package.match_route("alice.txt").unwrap();
        assert_eq!(matched.params, vec![("name".into(), "alice".into())]);

        let route_wasm = std::fs::read(&matched.route.source_path).unwrap();
        let output = PetalVm::new()
            .unwrap()
            .dispatch(
                &route_wasm,
                DispatchRequest {
                    op: DispatchOp::Read,
                    path: "alice.txt".into(),
                    body: Vec::new(),
                    ctx: matched.params,
                },
                BTreeSet::new(),
                Arc::new(DenyHost),
                "v2-test-package",
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            output.response,
            DispatchResponse::Read(b"hello v2".to_vec())
        );
    }

    fn write_package_file(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn write_v2_package(root: &Path) {
        write_v2_package_with_route(root, &compat_wasm("hello"));
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

    fn compat_wasm(body: &str) -> Vec<u8> {
        wat::parse_str(compat_read_wat(body)).unwrap()
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

    fn compat_read_wat(body: &str) -> String {
        let body = body.as_bytes();
        let mut response = vec![2];
        response.extend_from_slice(&(body.len() as u32).to_le_bytes());
        response.extend_from_slice(body);
        let escaped = response
            .iter()
            .map(|byte| format!("\\{byte:02x}"))
            .collect::<String>();
        format!(
            r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const 0) "{escaped}")
              (func (export "petal_alloc") (param i32) (result i32)
                (i32.const 1024))
              (func (export "petal_dispatch") (param i32 i32) (result i64)
                (i64.const {packed})))
            "#,
            packed = response.len()
        )
    }
}
