//! Content-addressed object store for petal wasm.
//!
//! Layout on disk (rooted at `<base>`):
//!
//! ```text
//! <base>/objects/<hash>      — raw wasm bytes
//! <base>/meta/<hash>.json    — PetalMeta (size, installed_at, name, caps)
//! <base>/packages/<hash>/    — prepared Petal package
//! <base>/owners/<name>.json  — authoritative Petal package hash
//! ```
//!
//! Hash is hex-encoded BLAKE3 of the wasm bytes. Writes are atomic
//! (write-to-tempfile + rename); reads are unbuffered. The store does
//! not validate that the bytes are valid wasm — that's the VM's job.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::PetalError;
use crate::meta::{Capability, PetalMeta, PetalMode, PetalPackageMeta, PetalSourceProvenance};
use crate::package::{
    PreparedPetalPackage, ROUTE_INDEX_SCHEMA, RouteIndex, route_artifact_bytes,
    verify_prepared_package,
};

const OBJECTS: &str = "objects";
const META: &str = "meta";
const PACKAGES: &str = "packages";
const OWNERS: &str = "owners";
const SOURCE: &str = "source";
const ARTIFACTS_ROUTES: &str = "artifacts/routes";
const ROUTE_INDEX: &str = "route-index.json";

/// Filesystem-backed petal object store.
#[derive(Debug, Clone)]
pub struct PetalStore {
    base: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResult {
    pub hash: String,
    pub size: u64,
    /// True if this hash already existed in the store; false if newly
    /// written. Either way `meta` reflects the on-disk record after
    /// installation (which may have been updated to add a name / caps).
    pub already_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppOwner {
    name: String,
    hash: String,
}

impl PetalStore {
    /// Open (or create) a store rooted at `base`. Creates the
    /// `objects/` and `meta/` subdirectories if missing.
    pub fn open(base: impl Into<PathBuf>) -> Result<Self, PetalError> {
        let base = base.into();
        std::fs::create_dir_all(base.join(OBJECTS))?;
        std::fs::create_dir_all(base.join(META))?;
        std::fs::create_dir_all(base.join(PACKAGES))?;
        std::fs::create_dir_all(base.join(OWNERS))?;
        let store = Self { base };
        store.reconcile_petal_owners()?;
        Ok(store)
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Root for per-petal private data. In the normal daemon layout,
    /// `base` is `~/.bloom/petals/store`, so this returns
    /// `~/.bloom/petals/data`.
    pub fn private_data_root(&self) -> PathBuf {
        self.base
            .parent()
            .map(|p| p.join("data"))
            .unwrap_or_else(|| self.base.join("data"))
    }

    fn object_path(&self, hash: &str) -> PathBuf {
        self.base.join(OBJECTS).join(hash)
    }

    fn meta_path(&self, hash: &str) -> PathBuf {
        self.base.join(META).join(format!("{hash}.json"))
    }

    fn package_path_unchecked(&self, hash: &str) -> PathBuf {
        self.base.join(PACKAGES).join(hash)
    }

    pub fn package_path(&self, hash: &str) -> Result<PathBuf, PetalError> {
        validate_hash_arg(hash)?;
        Ok(self.package_path_unchecked(hash))
    }

    fn package_tmp_path(&self, hash: &str) -> PathBuf {
        self.base.join(PACKAGES).join(format!(".{hash}.tmp"))
    }

    fn owner_path(&self, name: &str) -> PathBuf {
        self.base.join(OWNERS).join(format!("{name}.json"))
    }

    fn route_index_path_unchecked(&self, hash: &str) -> PathBuf {
        self.package_path_unchecked(hash).join(ROUTE_INDEX)
    }

    pub fn route_index_path(&self, hash: &str) -> Result<PathBuf, PetalError> {
        validate_hash_arg(hash)?;
        Ok(self.route_index_path_unchecked(hash))
    }

    /// Install raw wasm bytes. The store assigns the content hash.
    /// If a petal with the same hash is already present, its metadata
    /// is updated only when the requested mode and caps match the
    /// existing install.
    pub fn install(
        &self,
        wasm: &[u8],
        name: Option<&str>,
        caps: &BTreeSet<Capability>,
        mode: PetalMode,
    ) -> Result<(InstallResult, PetalMeta), PetalError> {
        let hash = hex::encode(blake3::hash(wasm).as_bytes());
        let obj_path = self.object_path(&hash);
        let already_present = obj_path.exists();

        // Check the mode constraint before writing — a cross-mode reinstall
        // should fail without touching the object dir.
        let mut meta = match self.load_meta(&hash) {
            Ok(existing) => {
                if existing.mode != mode {
                    return Err(PetalError::ModeConflict {
                        existing: existing.mode,
                    });
                }
                if existing.caps != *caps {
                    return Err(PetalError::CapMismatch);
                }
                existing
            }
            Err(PetalError::NotFound(_)) => PetalMeta {
                hash: hash.clone(),
                size: wasm.len() as u64,
                installed_at_ms: now_ms(),
                name: None,
                caps: BTreeSet::new(),
                mode,
                petal: None,
                source: None,
            },
            Err(e) => return Err(e),
        };

        if !already_present {
            atomic_write(&obj_path, wasm)?;
        }
        if let Some(n) = name {
            meta.name = Some(n.to_string());
        }
        meta.caps = caps.clone();
        meta.size = wasm.len() as u64;
        self.write_meta(&meta)?;

        Ok((
            InstallResult {
                hash: hash.clone(),
                size: wasm.len() as u64,
                already_present,
            },
            meta,
        ))
    }

    pub fn install_petal_package_dir(
        &self,
        root: impl AsRef<Path>,
    ) -> Result<(InstallResult, PetalMeta, RouteIndex), PetalError> {
        self.install_prepared_petal_package(PreparedPetalPackage::from_dir(root)?)
    }

    pub fn install_petal_package_tar(
        &self,
        archive: impl AsRef<Path>,
    ) -> Result<(InstallResult, PetalMeta, RouteIndex), PetalError> {
        self.install_prepared_petal_package(PreparedPetalPackage::from_petal_tar(archive)?)
    }

    pub fn install_prepared_petal_package(
        &self,
        package: PreparedPetalPackage,
    ) -> Result<(InstallResult, PetalMeta, RouteIndex), PetalError> {
        self.install_prepared_petal_package_with_source(package, None)
    }

    pub fn install_prepared_petal_package_with_source(
        &self,
        package: PreparedPetalPackage,
        source: Option<PetalSourceProvenance>,
    ) -> Result<(InstallResult, PetalMeta, RouteIndex), PetalError> {
        self.install_prepared_petal_package_with_source_guarded(package, source, || Ok(()))
    }

    pub fn install_prepared_petal_package_with_source_guarded<F>(
        &self,
        package: PreparedPetalPackage,
        source: Option<PetalSourceProvenance>,
        commit_guard: F,
    ) -> Result<(InstallResult, PetalMeta, RouteIndex), PetalError>
    where
        F: Fn() -> Result<(), PetalError>,
    {
        verify_prepared_package(&package)?;
        let hash = package.hash.clone();
        validate_hash_arg(&hash)?;
        let package_path = self.package_path_unchecked(&hash);
        let already_present = package_path.exists();
        let size = package
            .files
            .iter()
            .map(|file| file.bytes.len() as u64)
            .sum();

        let existing_meta = match self.load_meta(&hash) {
            Ok(existing) => {
                if existing.mode != PetalMode::Local {
                    return Err(PetalError::ModeConflict {
                        existing: existing.mode,
                    });
                }
                Some(existing)
            }
            Err(PetalError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };

        if !already_present {
            let tmp = self.package_tmp_path(&hash);
            match std::fs::remove_dir_all(&tmp) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(PetalError::Io(e)),
            }
            std::fs::create_dir_all(tmp.join(SOURCE))?;
            std::fs::create_dir_all(tmp.join(ARTIFACTS_ROUTES))?;
            for file in &package.files {
                write_package_file(&tmp.join(SOURCE), &file.path, &file.bytes)?;
            }
            for route in &package.route_index.routes {
                let artifact = checked_route_artifact_bytes(&package, route)?;
                write_package_file(&tmp, &route.artifact_path, &artifact)?;
            }
            let index_bytes = serde_json::to_vec_pretty(&package.route_index)?;
            atomic_write(&tmp.join(ROUTE_INDEX), &index_bytes)?;
            std::fs::rename(&tmp, &package_path)?;
        } else {
            self.verify_existing_petal_package(&package)?;
        }

        let mut meta = match existing_meta {
            Some(existing) => existing,
            None => PetalMeta {
                hash: hash.clone(),
                size,
                installed_at_ms: now_ms(),
                name: None,
                caps: BTreeSet::new(),
                mode: PetalMode::Local,
                petal: None,
                source: None,
            },
        };
        meta.name = Some(package.name.clone());
        meta.size = size;
        meta.caps.clear();
        meta.mode = PetalMode::Local;
        meta.petal = Some(PetalPackageMeta {
            name: package.name.clone(),
            petal_root: package.route_index.petal_root.clone(),
            route_index_schema: ROUTE_INDEX_SCHEMA.to_string(),
        });
        meta.source = source;
        commit_guard()?;
        self.write_meta(&meta)?;

        // This atomic rename is the installation commit point. Before it,
        // readers continue to resolve the previous package; after it, they
        // resolve only this fully prepared and verified package.
        commit_guard()?;
        self.write_petal_owner(&package.name, &hash)?;

        // Keep prior package data until the next store open. A request that
        // resolved the old owner immediately before the commit can therefore
        // still finish safely. Reconciliation later removes the unreachable
        // content-addressed package.

        Ok((
            InstallResult {
                hash,
                size,
                already_present,
            },
            meta,
            package.route_index,
        ))
    }

    fn verify_existing_petal_package(
        &self,
        package: &PreparedPetalPackage,
    ) -> Result<(), PetalError> {
        let hash = &package.hash;
        let stored_index = self.load_route_index(hash)?;
        if stored_index != package.route_index {
            return Err(PetalError::InvalidWasm(format!(
                "existing Petal package {hash} route index does not match validated package"
            )));
        }
        for file in &package.files {
            let stored = std::fs::read(
                self.package_path_unchecked(hash)
                    .join(SOURCE)
                    .join(&file.path),
            )?;
            if stored != file.bytes {
                return Err(PetalError::InvalidWasm(format!(
                    "existing Petal package {hash} source file {:?} does not match package hash",
                    file.path
                )));
            }
        }
        for route in &package.route_index.routes {
            let artifact = self.read_route_artifact(hash, &route.route_id)?;
            let artifact_hash = hex::encode(blake3::hash(&artifact).as_bytes());
            if artifact_hash != route.artifact_hash {
                return Err(PetalError::InvalidWasm(format!(
                    "existing Petal package {hash} artifact {} hash mismatch",
                    route.route_id
                )));
            }
        }
        Ok(())
    }

    /// Read raw wasm bytes for a petal.
    pub fn read_wasm(&self, hash: &str) -> Result<Vec<u8>, PetalError> {
        validate_hash_arg(hash)?;
        let path = self.object_path(hash);
        match std::fs::read(&path) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(PetalError::NotFound(hash.to_string()))
            }
            Err(e) => Err(PetalError::Io(e)),
        }
    }

    pub fn load_route_index(&self, hash: &str) -> Result<RouteIndex, PetalError> {
        validate_hash_arg(hash)?;
        let path = self.route_index_path_unchecked(hash);
        match std::fs::read(&path) {
            Ok(b) => {
                let index: RouteIndex = serde_json::from_slice(&b)?;
                Ok(index)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(PetalError::NotFound(hash.to_string()))
            }
            Err(e) => Err(PetalError::Io(e)),
        }
    }

    pub fn read_route_artifact(&self, hash: &str, route_id: &str) -> Result<Vec<u8>, PetalError> {
        validate_hash_arg(hash)?;
        validate_route_id_arg(route_id)?;
        let path = self
            .package_path_unchecked(hash)
            .join(format!("{ARTIFACTS_ROUTES}/{route_id}.wasm"));
        match std::fs::read(&path) {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(PetalError::NotFound(format!("{hash}:{route_id}")))
            }
            Err(e) => Err(PetalError::Io(e)),
        }
    }

    /// Load metadata for a petal.
    pub fn load_meta(&self, hash: &str) -> Result<PetalMeta, PetalError> {
        validate_hash_arg(hash)?;
        let path = self.meta_path(hash);
        match std::fs::read(&path) {
            Ok(b) => {
                let m: PetalMeta = serde_json::from_slice(&b)?;
                Ok(m)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(PetalError::NotFound(hash.to_string()))
            }
            Err(e) => Err(PetalError::Io(e)),
        }
    }

    pub(crate) fn write_meta(&self, meta: &PetalMeta) -> Result<(), PetalError> {
        let body = serde_json::to_vec_pretty(meta)?;
        atomic_write(&self.meta_path(&meta.hash), &body)?;
        Ok(())
    }

    /// Whether the store has this hash on disk.
    pub fn contains(&self, hash: &str) -> bool {
        self.contains_wasm(hash)
    }

    pub fn contains_wasm(&self, hash: &str) -> bool {
        is_valid_hex_hash(hash) && self.object_path(hash).exists()
    }

    pub fn contains_package(&self, hash: &str) -> bool {
        is_valid_hex_hash(hash) && self.package_path_unchecked(hash).exists()
    }

    /// List every installed petal hash (unordered).
    pub fn list_hashes(&self) -> Result<Vec<String>, PetalError> {
        let mut out = BTreeSet::new();
        collect_meta_hashes(self.base.join(META), &mut out)?;
        out.retain(|hash| self.object_path(hash).exists());
        Ok(out.into_iter().collect())
    }

    /// List authoritative installed app-package hashes. Unreachable package
    /// data awaiting startup reconciliation is intentionally omitted.
    pub fn list_package_hashes(&self) -> Result<Vec<String>, PetalError> {
        Ok(self
            .list_petal_owners()?
            .into_iter()
            .map(|(_, hash)| hash)
            .collect())
    }

    fn list_physical_package_hashes(&self) -> Result<Vec<String>, PetalError> {
        let mut out = BTreeSet::new();
        collect_meta_hashes(self.base.join(META), &mut out)?;
        out.retain(|hash| self.package_path_unchecked(hash).exists());
        Ok(out.into_iter().collect())
    }

    /// List the single authoritative package owner for each installed app.
    pub fn list_petal_owners(&self) -> Result<Vec<(String, String)>, PetalError> {
        let mut owners = Vec::new();
        for entry in std::fs::read_dir(self.base.join(OWNERS))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if file_name.starts_with('.') || !file_name.ends_with(".json") {
                continue;
            }
            let owner: AppOwner = serde_json::from_slice(&std::fs::read(entry.path())?)?;
            validate_owner(&owner)?;
            if file_name.strip_suffix(".json") != Some(owner.name.as_str()) {
                return Err(PetalError::InvalidWasm(format!(
                    "app owner record name does not match file {file_name:?}"
                )));
            }
            if !self.package_path_unchecked(&owner.hash).is_dir() {
                return Err(PetalError::NotFound(owner.hash));
            }
            owners.push((owner.name, owner.hash));
        }
        owners.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(owners)
    }

    pub fn resolve_petal_owner(&self, name: &str) -> Result<Option<String>, PetalError> {
        validate_owner_name(name)?;
        let bytes = match std::fs::read(self.owner_path(name)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(PetalError::Io(e)),
        };
        let owner: AppOwner = serde_json::from_slice(&bytes)?;
        validate_owner(&owner)?;
        if owner.name != name {
            return Err(PetalError::InvalidWasm(format!(
                "app owner record name mismatch: expected {name:?}, found {:?}",
                owner.name
            )));
        }
        if !self.package_path_unchecked(&owner.hash).is_dir() {
            return Err(PetalError::NotFound(owner.hash));
        }
        Ok(Some(owner.hash))
    }

    fn write_petal_owner(&self, name: &str, hash: &str) -> Result<(), PetalError> {
        validate_owner_name(name)?;
        validate_hash_arg(hash)?;
        let owner = AppOwner {
            name: name.to_string(),
            hash: hash.to_string(),
        };
        atomic_write(&self.owner_path(name), &serde_json::to_vec_pretty(&owner)?)?;
        Ok(())
    }

    fn remove_petal_owner_for_hash(&self, hash: &str) -> Result<(), PetalError> {
        for (name, owner_hash) in self.list_petal_owners()? {
            if owner_hash != hash {
                continue;
            }
            match std::fs::remove_file(self.owner_path(&name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(PetalError::Io(e)),
            }
        }
        Ok(())
    }

    /// Recover interrupted installs. Existing valid owner records always win:
    /// an owner swap is the commit point. Stores created before owner records
    /// existed are migrated by selecting the newest package for each app.
    fn reconcile_petal_owners(&self) -> Result<(), PetalError> {
        for entry in std::fs::read_dir(self.base.join(OWNERS))? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with('.') {
                match std::fs::remove_file(entry.path()) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(PetalError::Io(e)),
                }
            }
        }

        let mut packages = Vec::new();
        for hash in self.list_physical_package_hashes()? {
            let meta = self.load_meta(&hash)?;
            if let Some(app) = meta.petal {
                packages.push((app.name, hash, meta.installed_at_ms));
            }
        }
        packages.sort_by(|a, b| {
            (a.0.as_str(), a.2, a.1.as_str()).cmp(&(b.0.as_str(), b.2, b.1.as_str()))
        });

        let mut names = packages
            .iter()
            .map(|(name, _, _)| name.clone())
            .collect::<BTreeSet<_>>();
        for entry in std::fs::read_dir(self.base.join(OWNERS))? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            if validate_owner_name(name).is_ok() {
                names.insert(name.to_string());
            }
        }
        for name in names {
            let candidates = packages
                .iter()
                .filter(|(candidate, _, _)| candidate == &name)
                .collect::<Vec<_>>();
            let current = self.resolve_petal_owner(&name).ok().flatten();
            let owner = current
                .filter(|hash| candidates.iter().any(|(_, candidate, _)| candidate == hash))
                .or_else(|| candidates.last().map(|(_, hash, _)| hash.clone()));
            let Some(owner) = owner else {
                let _ = std::fs::remove_file(self.owner_path(&name));
                continue;
            };
            self.write_petal_owner(&name, &owner)?;
            for (_, hash, _) in candidates {
                if hash != &owner {
                    let _ = self.remove_package_data(hash);
                }
            }
        }
        Ok(())
    }

    /// Remove an installed petal's object and metadata. Returns `true`
    /// if anything was removed, `false` if the hash was not installed.
    /// The caller is responsible for clearing any registry entries that
    /// point at this hash.
    ///
    /// Not safe under concurrent mutation: the `had` snapshot is taken
    /// before the removes, and a non-NotFound IO error between the two
    /// unlinks can leave the store with only one of the two files.
    pub fn uninstall(&self, hash: &str) -> Result<bool, PetalError> {
        validate_hash_arg(hash)?;
        self.remove_petal_owner_for_hash(hash)?;
        self.remove_package_data(hash)
    }

    fn remove_package_data(&self, hash: &str) -> Result<bool, PetalError> {
        let obj_path = self.object_path(hash);
        let meta_path = self.meta_path(hash);
        let package_path = self.package_path_unchecked(hash);
        let had = obj_path.exists() || meta_path.exists() || package_path.exists();
        for p in [&obj_path, &meta_path] {
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(PetalError::Io(e)),
            }
        }
        match std::fs::remove_dir_all(package_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(PetalError::Io(e)),
        }
        Ok(had)
    }

    /// List hashes whose meta records have the given mode. Ignores
    /// objects with missing metadata (which would be a corruption).
    pub fn list_hashes_by_mode(&self, mode: PetalMode) -> Result<Vec<String>, PetalError> {
        let mut out = Vec::new();
        for hash in self.list_hashes()? {
            if !self.object_path(&hash).exists() {
                continue;
            }
            match self.load_meta(&hash) {
                Ok(m) if m.mode == mode => out.push(hash),
                Ok(_) => {}
                Err(PetalError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("path has no parent"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("path has no file name"))?;
    let mut tmp = dir.to_path_buf();
    tmp.push(format!(".{}.tmp", file_name.to_string_lossy()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn write_package_file(root: &Path, rel: &str, data: &[u8]) -> Result<(), PetalError> {
    crate::package::validate_package_path(rel)?;
    let path = root.join(rel);
    let parent = path
        .parent()
        .ok_or_else(|| PetalError::InvalidWasm(format!("path has no parent: {rel}")))?;
    std::fs::create_dir_all(parent)?;
    atomic_write(&path, data)?;
    Ok(())
}

fn checked_route_artifact_bytes(
    package: &PreparedPetalPackage,
    route: &crate::package::RouteIndexRecord,
) -> Result<Vec<u8>, PetalError> {
    let artifact = route_artifact_bytes(package, route)?;
    let artifact_hash = hex::encode(blake3::hash(&artifact).as_bytes());
    if artifact_hash != route.artifact_hash {
        return Err(PetalError::InvalidWasm(format!(
            "Petal package artifact {} hash mismatch",
            route.route_id
        )));
    }
    Ok(artifact)
}

fn collect_meta_hashes(dir: PathBuf, out: &mut BTreeSet<String>) -> Result<(), PetalError> {
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(PetalError::Io(e)),
    };
    for entry in rd {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(hash) = name.strip_suffix(".json") else {
            continue;
        };
        if is_valid_hex_hash(hash) {
            out.insert(hash.to_string());
        }
    }
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A valid BLAKE3 hex hash: exactly 64 lowercase hex chars.
pub fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Length of the hash prefix `petal ls` prints, and the minimum
/// prefix length accepted when resolving an uninstall target.
pub const HASH_PREFIX_LEN: usize = 12;

/// True when `s` is shaped like a partial content hash: lowercase
/// hex, at least [`HASH_PREFIX_LEN`] and fewer than 64 chars.
pub fn is_hex_hash_prefix(s: &str) -> bool {
    (HASH_PREFIX_LEN..64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_hash_arg(hash: &str) -> Result<(), PetalError> {
    if is_valid_hex_hash(hash) {
        Ok(())
    } else {
        Err(PetalError::InvalidHash(hash.to_string()))
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

fn validate_owner_name(name: &str) -> Result<(), PetalError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(PetalError::InvalidWasm(format!(
            "invalid app owner name {name:?}"
        )))
    }
}

fn validate_owner(owner: &AppOwner) -> Result<(), PetalError> {
    validate_owner_name(&owner.name)?;
    validate_hash_arg(&owner.hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{PetalMode, PetalSourceProvenance};
    use crate::package::PreparedPetalPackage;
    use tempfile::TempDir;

    fn store() -> (TempDir, PetalStore) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn install_writes_object_and_meta() {
        let (_d, store) = store();
        let mut caps = BTreeSet::new();
        caps.insert(Capability::VfsRead);
        let (r, m) = store
            .install(b"hello-wasm", Some("greet"), &caps, PetalMode::Local)
            .unwrap();
        assert_eq!(r.size, 10);
        assert!(!r.already_present);
        assert!(store.contains(&r.hash));
        assert_eq!(m.name.as_deref(), Some("greet"));
        assert!(m.has_cap(Capability::VfsRead));
    }

    #[test]
    fn install_is_idempotent_on_hash_when_caps_match() {
        let (_d, store) = store();
        let mut caps_a = BTreeSet::new();
        caps_a.insert(Capability::VfsRead);
        let (r1, _) = store
            .install(b"x", Some("a"), &caps_a, PetalMode::Local)
            .unwrap();
        let (r2, m) = store
            .install(b"x", Some("b"), &caps_a, PetalMode::Local)
            .unwrap();
        assert_eq!(r1.hash, r2.hash);
        assert!(r2.already_present);
        // Name overwritten on second install.
        assert_eq!(m.name.as_deref(), Some("b"));
        assert!(m.has_cap(Capability::VfsRead));
        assert!(!m.has_cap(Capability::VfsWrite));
    }

    #[test]
    fn reinstall_same_hash_same_mode_with_different_caps_is_cap_mismatch() {
        let (_d, store) = store();
        let mut caps_a = BTreeSet::new();
        caps_a.insert(Capability::VfsRead);
        let (r1, m1) = store
            .install(b"x", Some("a"), &caps_a, PetalMode::Local)
            .unwrap();

        let mut caps_b = BTreeSet::new();
        caps_b.insert(Capability::VfsWrite);
        let err = store
            .install(b"x", Some("b"), &caps_b, PetalMode::Local)
            .unwrap_err();

        assert!(matches!(err, PetalError::CapMismatch));
        let m2 = store.load_meta(&r1.hash).unwrap();
        assert_eq!(m2.name, m1.name);
        assert_eq!(m2.caps, caps_a);
    }

    #[test]
    fn read_unknown_hash_is_not_found() {
        let (_d, store) = store();
        let err = store.read_wasm("00".repeat(32).as_str()).unwrap_err();
        assert!(matches!(err, PetalError::NotFound(_)));
    }

    #[test]
    fn list_hashes_filters_non_hash_entries() {
        let (d, store) = store();
        let (r, _) = store
            .install(b"abc", None, &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        // Drop a stray file that does NOT look like a hash.
        std::fs::write(d.path().join(OBJECTS).join("README"), b"junk").unwrap();
        std::fs::create_dir_all(d.path().join(PACKAGES).join("a".repeat(64))).unwrap();
        let hashes = store.list_hashes().unwrap();
        assert_eq!(hashes, vec![r.hash]);
    }

    #[test]
    fn is_valid_hex_hash_rejects_wrong_length_and_uppercase() {
        assert!(is_valid_hex_hash(&"a".repeat(64)));
        assert!(!is_valid_hex_hash(&"a".repeat(63)));
        assert!(!is_valid_hex_hash(&"a".repeat(65)));
        assert!(!is_valid_hex_hash(&"A".repeat(64)));
        assert!(!is_valid_hex_hash(&"g".repeat(64)));
    }

    #[test]
    fn install_records_mode() {
        let (_d, store) = store();
        let (_r, m) = store
            .install(b"abc", Some("a"), &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        assert_eq!(m.mode, PetalMode::Local);
    }

    #[test]
    fn install_same_hash_same_mode_is_idempotent() {
        let (_d, store) = store();
        let (r1, _) = store
            .install(b"qqq", Some("a"), &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        let (r2, m) = store
            .install(b"qqq", Some("b"), &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        assert_eq!(r1.hash, r2.hash);
        assert!(r2.already_present);
        assert_eq!(m.name.as_deref(), Some("b"));
        assert_eq!(m.mode, PetalMode::Local);
    }

    #[test]
    fn uninstall_removes_object_and_meta() {
        let (_d, store) = store();
        let (r, _) = store
            .install(b"toremove", None, &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        assert!(store.contains(&r.hash));
        let removed = store.uninstall(&r.hash).unwrap();
        assert!(removed);
        assert!(!store.contains(&r.hash));
        assert!(matches!(
            store.load_meta(&r.hash),
            Err(PetalError::NotFound(_))
        ));
    }

    #[test]
    fn uninstall_missing_returns_false() {
        let (_d, store) = store();
        let absent = "0".repeat(64);
        assert!(!store.uninstall(&absent).unwrap());
    }

    #[test]
    fn list_hashes_by_mode_filters_correctly() {
        let (_d, store) = store();
        let (rl, _) = store
            .install(b"local-bytes", None, &BTreeSet::new(), PetalMode::Local)
            .unwrap();
        let locals = store.list_hashes_by_mode(PetalMode::Local).unwrap();
        assert_eq!(locals, vec![rl.hash]);
    }

    #[test]
    fn install_petal_package_writes_package_tree_index_and_meta() {
        let (d, store) = store();
        let package = d.path().join("pkg");
        write_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&package, "README.md", b"# echo");
        write_file(&package, "AGENTS.md", b"# echo agents");
        let wasm = route_component_wasm();
        write_file(&package, "petal/echo/[name].txt.wasm", wasm);

        let (result, meta, index) = store.install_petal_package_dir(&package).unwrap();

        assert!(!result.already_present);
        assert_eq!(meta.name.as_deref(), Some("echo"));
        assert_eq!(meta.petal.as_ref().unwrap().petal_root, "echo");
        assert!(
            store
                .package_path(&result.hash)
                .unwrap()
                .join("source/petal.toml")
                .is_file()
        );
        assert_eq!(index.routes.len(), 1);
        let route = &index.routes[0];
        assert_eq!(route.route_id, "r000001");
        assert_eq!(route.pattern, "[name].txt");
        assert_eq!(route.abi, crate::package::RouteAbi::ComponentBloomRoute010);
        assert_eq!(
            store
                .read_route_artifact(&result.hash, &route.route_id)
                .unwrap(),
            wasm
        );
        let loaded = store.load_route_index(&result.hash).unwrap();
        assert_eq!(loaded, index);
        assert!(!store.contains(&result.hash));
        assert!(store.contains_package(&result.hash));
        assert!(!store.list_hashes().unwrap().contains(&result.hash));
        assert!(store.list_package_hashes().unwrap().contains(&result.hash));
        assert!(
            !store
                .list_hashes_by_mode(PetalMode::Local)
                .unwrap()
                .contains(&result.hash),
            "Petal package-only installs must not appear as legacy single-Wasm Petals"
        );

        let (again, _, _) = store.install_petal_package_dir(&package).unwrap();
        assert_eq!(again.hash, result.hash);
        assert!(again.already_present);
    }

    #[test]
    fn install_petal_package_persists_source_provenance() {
        let (d, store) = store();
        let package_dir = d.path().join("pkg");
        write_file(
            &package_dir,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&package_dir, "README.md", b"# echo");
        write_file(&package_dir, "AGENTS.md", b"# echo agents");
        write_file(
            &package_dir,
            "petal/echo/[name].txt.wasm",
            route_component_wasm(),
        );

        let package = PreparedPetalPackage::from_dir(&package_dir).unwrap();
        let provenance = PetalSourceProvenance {
            source_kind: "github".into(),
            url: "https://github.com/bloom-directory/bloom-petal-echo".into(),
            owner: "bloom-directory".into(),
            repo: "bloom-petal-echo".into(),
            requested_ref: "v0.1.0".into(),
            resolved_commit: "0123456789abcdef".into(),
            selected_tag: Some("v0.1.0".into()),
            package_hash: package.hash.clone(),
        };
        let (result, meta, _) = store
            .install_prepared_petal_package_with_source(package, Some(provenance.clone()))
            .unwrap();

        assert_eq!(meta.source.as_ref(), Some(&provenance));
        let loaded = store.load_meta(&result.hash).unwrap();
        assert_eq!(loaded.source.as_ref(), Some(&provenance));
    }

    #[test]
    fn cancelled_prepared_install_does_not_publish_an_owner() {
        let (d, store) = store();
        let package_dir = d.path().join("cancelled-pkg");
        write_file(
            &package_dir,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&package_dir, "README.md", b"# echo");
        write_file(&package_dir, "AGENTS.md", b"# echo agents");
        write_file(
            &package_dir,
            "petal/echo/[name].txt.wasm",
            route_component_wasm(),
        );
        let package = PreparedPetalPackage::from_dir(&package_dir).unwrap();

        let error = store
            .install_prepared_petal_package_with_source_guarded(package, None, || {
                Err(PetalError::vm("cancelled before commit"))
            })
            .unwrap_err();

        assert!(error.to_string().contains("cancelled before commit"));
        assert_eq!(store.resolve_petal_owner("echo").unwrap(), None);
        assert!(store.list_package_hashes().unwrap().is_empty());
    }

    #[test]
    fn install_petal_package_uses_packaged_route_artifact_when_present() {
        let (d, store) = store();
        let package = d.path().join("pkg");
        write_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&package, "README.md", b"# echo");
        write_file(&package, "AGENTS.md", b"# echo agents");
        let source = route_component_wasm();
        let artifact = route_component_wasm();
        write_file(&package, "petal/echo/hello.txt.wasm", source);
        write_file(&package, "artifacts/routes/r000001.wasm", artifact);

        let (result, _, index) = store.install_petal_package_dir(&package).unwrap();
        assert_eq!(
            index.routes[0].artifact_hash,
            hex::encode(blake3::hash(artifact).as_bytes())
        );
        assert_eq!(
            store
                .read_route_artifact(&result.hash, &index.routes[0].route_id)
                .unwrap(),
            artifact
        );
    }

    #[test]
    fn reinstall_petal_package_rejects_tampered_existing_artifact() {
        let (d, store) = store();
        let package = d.path().join("pkg");
        write_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&package, "README.md", b"# echo");
        write_file(&package, "AGENTS.md", b"# echo agents");
        write_file(
            &package,
            "petal/echo/hello.txt.wasm",
            route_component_wasm(),
        );

        let (result, _, index) = store.install_petal_package_dir(&package).unwrap();
        let route_id = &index.routes[0].route_id;
        std::fs::write(
            store
                .package_path(&result.hash)
                .unwrap()
                .join(format!("artifacts/routes/{route_id}.wasm")),
            b"tampered",
        )
        .unwrap();

        let err = store.install_petal_package_dir(&package).unwrap_err();
        assert!(err.to_string().contains("artifact"));
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn install_petal_package_replaces_same_petal_name() {
        let (d, store) = store();
        let first = d.path().join("pkg-a");
        write_file(
            &first,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&first, "README.md", b"# echo");
        write_file(&first, "AGENTS.md", b"# echo agents");
        write_file(&first, "petal/echo/one.txt.wasm", route_component_wasm());
        let (first_install, _, _) = store.install_petal_package_dir(&first).unwrap();
        let first_hash = first_install.hash;

        let second = d.path().join("pkg-b");
        write_file(
            &second,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&second, "README.md", b"# echo");
        write_file(&second, "AGENTS.md", b"# echo agents");
        write_file(&second, "petal/echo/two.txt.wasm", route_component_wasm());

        let (replacement, meta, index) = store.install_petal_package_dir(&second).unwrap();
        assert_ne!(replacement.hash, first_hash);
        assert_eq!(meta.petal.as_ref().unwrap().name, "echo");
        assert_eq!(index.routes[0].pattern, "two.txt");
        assert!(store.contains_package(&first_hash));
        assert!(store.contains_package(&replacement.hash));
        assert_eq!(
            store.list_petal_owners().unwrap(),
            vec![("echo".to_string(), replacement.hash)]
        );

        let reopened = PetalStore::open(d.path()).unwrap();
        assert!(!reopened.contains_package(&first_hash));
    }

    #[test]
    fn prepared_replacement_is_invisible_until_owner_commit() {
        let (d, store) = store();
        let first_hash = install_test_app(&d, &store, "first", "one.txt");

        let staged_root = TempDir::new().unwrap();
        let staged_store = PetalStore::open(staged_root.path().join("store")).unwrap();
        let staged_hash = install_test_app(&staged_root, &staged_store, "second", "two.txt");
        copy_dir(
            &staged_store.package_path(&staged_hash).unwrap(),
            &store.package_path(&staged_hash).unwrap(),
        );
        std::fs::copy(
            staged_store.meta_path(&staged_hash),
            store.meta_path(&staged_hash),
        )
        .unwrap();

        assert!(store.contains_package(&staged_hash));
        assert_eq!(
            store.resolve_petal_owner("echo").unwrap(),
            Some(first_hash.clone())
        );
        assert_eq!(
            store.list_package_hashes().unwrap(),
            vec![first_hash.clone()]
        );

        // Reopening treats the uncommitted package as garbage and preserves
        // the old authoritative owner.
        let reopened = PetalStore::open(d.path()).unwrap();
        assert_eq!(
            reopened.resolve_petal_owner("echo").unwrap(),
            Some(first_hash)
        );
        assert!(!reopened.contains_package(&staged_hash));
    }

    #[test]
    fn committed_replacement_survives_interrupted_cleanup() {
        let (d, store) = store();
        let first_hash = install_test_app(&d, &store, "first", "one.txt");

        let staged_root = TempDir::new().unwrap();
        let staged_store = PetalStore::open(staged_root.path().join("store")).unwrap();
        let staged_hash = install_test_app(&staged_root, &staged_store, "second", "two.txt");
        copy_dir(
            &staged_store.package_path(&staged_hash).unwrap(),
            &store.package_path(&staged_hash).unwrap(),
        );
        std::fs::copy(
            staged_store.meta_path(&staged_hash),
            store.meta_path(&staged_hash),
        )
        .unwrap();

        // Simulate interruption after the atomic owner rename and before old
        // package cleanup.
        store.write_petal_owner("echo", &staged_hash).unwrap();
        assert!(store.contains_package(&first_hash));
        assert_eq!(
            store.list_package_hashes().unwrap(),
            vec![staged_hash.clone()]
        );

        let reopened = PetalStore::open(d.path()).unwrap();
        assert_eq!(
            reopened.resolve_petal_owner("echo").unwrap(),
            Some(staged_hash)
        );
        assert!(!reopened.contains_package(&first_hash));
    }

    #[test]
    fn reopening_migrates_legacy_package_and_removes_stale_owner_temp() {
        let (d, store) = store();
        let hash = install_test_app(&d, &store, "legacy", "one.txt");
        std::fs::remove_file(store.owner_path("echo")).unwrap();
        let stale = d.path().join(OWNERS).join(".echo.json.tmp");
        std::fs::write(&stale, b"partial").unwrap();

        let reopened = PetalStore::open(d.path()).unwrap();
        assert_eq!(reopened.resolve_petal_owner("echo").unwrap(), Some(hash));
        assert!(!stale.exists());
    }

    #[test]
    fn package_store_rejects_invalid_hash_and_route_id_paths() {
        let (_d, store) = store();
        assert!(matches!(
            store.package_path("../escape"),
            Err(PetalError::InvalidHash(_))
        ));
        assert!(matches!(
            store.read_wasm("../escape"),
            Err(PetalError::InvalidHash(_))
        ));
        assert!(matches!(
            store.load_route_index("../escape"),
            Err(PetalError::InvalidHash(_))
        ));
        assert!(matches!(
            store.uninstall("../escape"),
            Err(PetalError::InvalidHash(_))
        ));
        assert!(!store.contains("../escape"));
        assert!(matches!(
            store.read_route_artifact(&"a".repeat(64), "../r000001"),
            Err(PetalError::InvalidWasm(_))
        ));
        assert!(matches!(
            store.read_route_artifact(&"a".repeat(64), "r000000"),
            Err(PetalError::InvalidWasm(_))
        ));
    }

    #[test]
    fn install_prepared_petal_package_rejects_forged_hash_before_paths() {
        let (d, store) = store();
        let package_dir = d.path().join("pkg");
        write_file(
            &package_dir,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&package_dir, "README.md", b"# echo");
        write_file(&package_dir, "AGENTS.md", b"# echo agents");
        write_file(
            &package_dir,
            "petal/echo/hello.txt.wasm",
            route_component_wasm(),
        );

        let mut package = PreparedPetalPackage::from_dir(&package_dir).unwrap();
        package.hash = "../escape".to_string();

        let err = store.install_prepared_petal_package(package).unwrap_err();
        assert!(matches!(err, PetalError::InvalidHash(hash) if hash == "../escape"));
        assert!(!d.path().join("packages").join("escape").exists());
    }

    #[test]
    fn install_prepared_petal_package_rejects_forged_route_index() {
        let (d, store) = store();
        let package_dir = d.path().join("pkg");
        write_file(
            &package_dir,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&package_dir, "README.md", b"# echo");
        write_file(&package_dir, "AGENTS.md", b"# echo agents");
        write_file(
            &package_dir,
            "petal/echo/hello.txt.wasm",
            route_component_wasm(),
        );

        let mut package = PreparedPetalPackage::from_dir(&package_dir).unwrap();
        package.route_index.routes[0].pattern = "../escape".to_string();

        let err = store.install_prepared_petal_package(package).unwrap_err();
        assert!(
            err.to_string()
                .contains("route index does not match rebuilt package")
        );
    }

    fn write_file(root: &Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn install_test_app(
        temp: &TempDir,
        store: &PetalStore,
        package_dir: &str,
        route: &str,
    ) -> String {
        let package = temp.path().join(package_dir);
        write_file(
            &package,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "echo"
"#,
        );
        write_file(&package, "README.md", b"# echo");
        write_file(&package, "AGENTS.md", b"# echo agents");
        write_file(
            &package,
            &format!("petal/echo/{route}.wasm"),
            route_component_wasm(),
        );
        store.install_petal_package_dir(package).unwrap().0.hash
    }

    fn copy_dir(source: &Path, target: &Path) {
        std::fs::create_dir_all(target).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let destination = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir(&entry.path(), &destination);
            } else {
                std::fs::copy(entry.path(), destination).unwrap();
            }
        }
    }

    fn route_component_wasm() -> &'static [u8] {
        include_bytes!("../tests/fixtures/route_component_no_imports.wasm")
    }
}
