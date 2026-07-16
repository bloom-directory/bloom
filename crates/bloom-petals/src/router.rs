//! VFS router for installed Petal packages.
//!
//! The daemon mounts this handler at `petals/`. The first path segment selects
//! an installed Petal package; the remaining path is passed to the matched
//! Petal route artifact.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use async_trait::async_trait;
use bloom_proto::config::PetalRuntimeConfig;
use bloom_vfs::handler::{Entry, EntryKind, Handler, HandlerError};
use bloom_vfs::path::VfsPath;

use crate::abi::{DispatchEntry, DispatchEntryKind, DispatchOp, DispatchRequest, DispatchResponse};
use crate::error::PetalError;
use crate::host::PetalHost;
use crate::runner::PetalRunner;
use crate::vm::{COMPONENT_NOT_A_DIR_CODE, COMPONENT_UNSUPPORTED_CODE, RunOptions};

#[derive(Clone)]
pub struct PetalRouter {
    runner: PetalRunner,
    host: Arc<dyn PetalHost>,
    runtime_petals: BTreeMap<String, PetalRuntimeConfig>,
}

impl PetalRouter {
    pub fn new(runner: PetalRunner, host: Arc<dyn PetalHost>) -> Self {
        Self {
            runner,
            host,
            runtime_petals: BTreeMap::new(),
        }
    }

    /// Retained temporarily for daemon API compatibility. Petal writes are
    /// synchronous in this iteration so VFS callers receive execution errors.
    pub fn with_async_write_switch(self, _enabled: Arc<AtomicBool>) -> Self {
        self
    }

    pub fn with_runtime_petals(
        mut self,
        runtime_petals: BTreeMap<String, PetalRuntimeConfig>,
    ) -> Result<Self, PetalError> {
        for (mount, app) in &runtime_petals {
            if app.endpoints.is_empty() {
                continue;
            }
            match self
                .runner
                .validate_app_endpoint_bindings(mount, &app.endpoints)
            {
                Ok(()) | Err(PetalError::NotFound(_)) => {}
                Err(err) => return Err(err),
            }
        }
        self.runtime_petals = runtime_petals;
        Ok(self)
    }

    fn run_options(&self, mount: &str) -> RunOptions {
        let Some(app) = self.runtime_petals.get(mount) else {
            return RunOptions::default();
        };
        let mut runtime_settings = app.values.clone();
        runtime_settings.extend(
            app.endpoints
                .iter()
                .map(|(key, value)| (format!("endpoint.{key}"), value.clone())),
        );
        RunOptions {
            runtime_settings,
            endpoint_bindings: app.endpoints.clone(),
            ..RunOptions::default()
        }
    }

    fn mount_path(path: &VfsPath) -> Result<(&str, String), HandlerError> {
        let [mount, rest @ ..] = path.segments() else {
            return Err(HandlerError::NotFound(path.to_string_path()));
        };
        let rest = rest.join("/");
        Ok((mount, rest))
    }

    fn is_petal(&self, mount: &str) -> bool {
        self.runner.resolve_petal_mount(mount).is_ok()
    }

    async fn dispatch_petal(
        &self,
        mount: &str,
        op: DispatchOp,
        path: String,
        body: Vec<u8>,
    ) -> Result<DispatchResponse, HandlerError> {
        let out = self
            .runner
            .dispatch_petal_route(
                mount,
                DispatchRequest {
                    op,
                    path,
                    body,
                    ctx: Vec::new(),
                },
                self.host.clone(),
                None,
                self.run_options(mount),
            )
            .await
            .map_err(map_petal_err)?;
        Ok(out.response)
    }
}

#[async_trait]
impl Handler for PetalRouter {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [mount] => {
                if !self.is_petal(mount) {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                Ok(Entry::dir(mount))
            }
            _ => {
                let (mount, rest) = Self::mount_path(path)?;
                if !self.is_petal(mount) {
                    return Err(HandlerError::NotFound(path.to_string_path()));
                }
                match self
                    .dispatch_petal(mount, DispatchOp::Lookup, rest.clone(), Vec::new())
                    .await
                {
                    Ok(DispatchResponse::Lookup(entry)) => entry_to_vfs(entry),
                    Ok(DispatchResponse::Error { code, message }) => {
                        Err(dispatch_error(code, message, path.to_string_path()))
                    }
                    Ok(other) => Err(unexpected_response("lookup", other)),
                    Err(HandlerError::NotFound(_))
                        if self
                            .runner
                            .petal_has_descendant(mount, &rest)
                            .map_err(map_petal_err)? =>
                    {
                        let name = path
                            .segments()
                            .last()
                            .map(String::as_str)
                            .unwrap_or_default();
                        Ok(Entry::dir(name))
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let (mount, rest) = Self::mount_path(path)?;
        if !self.is_petal(mount) {
            return Err(HandlerError::NotFound(path.to_string_path()));
        }
        match self
            .dispatch_petal(mount, DispatchOp::Read, rest, Vec::new())
            .await?
        {
            DispatchResponse::Read(bytes) => Ok(bytes),
            DispatchResponse::Error { code, message } => {
                Err(dispatch_error(code, message, path.to_string_path()))
            }
            other => Err(unexpected_response("read", other)),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let (mount, rest) = Self::mount_path(path)?;
        if rest.is_empty() {
            return Err(HandlerError::PermissionDenied);
        }
        if !self.is_petal(mount) {
            return Err(HandlerError::NotFound(path.to_string_path()));
        }
        match self
            .dispatch_petal(mount, DispatchOp::Write, rest, data.to_vec())
            .await?
        {
            DispatchResponse::Write => Ok(()),
            DispatchResponse::Error { code, message } => {
                Err(dispatch_error(code, message, path.to_string_path()))
            }
            other => Err(unexpected_response("write", other)),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        match path.segments() {
            [] => {
                let mut mounts = BTreeMap::new();
                for (mount, _hash) in self.runner.local_petal_mounts().map_err(map_petal_err)? {
                    mounts.insert(mount, ());
                }
                Ok(mounts.into_keys().map(|mount| Entry::dir(&mount)).collect())
            }
            [mount] if self.is_petal(mount) => {
                match self
                    .dispatch_petal(mount, DispatchOp::List, String::new(), Vec::new())
                    .await
                {
                    Ok(DispatchResponse::List(entries)) => {
                        entries.into_iter().map(entry_to_vfs).collect()
                    }
                    Ok(DispatchResponse::Error { code, message }) => {
                        Err(dispatch_error(code, message, path.to_string_path()))
                    }
                    Ok(other) => Err(unexpected_response("list", other)),
                    Err(HandlerError::NotFound(_)) => self
                        .runner
                        .petal_static_list(mount, "")
                        .map_err(map_petal_err)?
                        .into_iter()
                        .map(entry_to_vfs)
                        .collect(),
                    Err(e) => Err(e),
                }
            }
            [mount] => Err(HandlerError::NotFound(mount.to_string())),
            _ => {
                let (mount, rest) = Self::mount_path(path)?;
                if self.is_petal(mount) {
                    return match self
                        .dispatch_petal(mount, DispatchOp::List, rest.clone(), Vec::new())
                        .await
                    {
                        Ok(DispatchResponse::List(entries)) => {
                            entries.into_iter().map(entry_to_vfs).collect()
                        }
                        Ok(DispatchResponse::Error { code, message }) => {
                            Err(dispatch_error(code, message, path.to_string_path()))
                        }
                        Ok(other) => Err(unexpected_response("list", other)),
                        Err(HandlerError::NotFound(_)) => self
                            .runner
                            .petal_static_list(mount, &rest)
                            .map_err(map_petal_err)?
                            .into_iter()
                            .map(entry_to_vfs)
                            .collect(),
                        Err(e) => Err(e),
                    };
                }
                Err(HandlerError::NotFound(path.to_string_path()))
            }
        }
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        if let Ok((mount, rest)) = Self::mount_path(path)
            && self.is_petal(mount)
        {
            return self
                .runner
                .petal_route_effective_metadata(mount, DispatchOp::Read, &rest)
                .ok()
                .filter(|(_, metadata)| !metadata.side_effecting_read)
                .and_then(|(_, metadata)| metadata.cache_ttl_ms)
                .map(Duration::from_millis);
        }
        None
    }

    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        if let Ok((mount, rest)) = Self::mount_path(path)
            && self.is_petal(mount)
        {
            return self
                .runner
                .petal_route_effective_metadata(mount, DispatchOp::Read, &rest)
                .ok()
                .map(|(_, metadata)| metadata.side_effecting_read)
                .unwrap_or(false);
        }
        false
    }
}

fn entry_to_vfs(entry: DispatchEntry) -> Result<Entry, HandlerError> {
    validate_entry_name(&entry.name)?;
    if entry.kind == DispatchEntryKind::Symlink {
        let Some(target) = entry.link_target.as_deref() else {
            return Err(HandlerError::invalid("symlink entry missing link target"));
        };
        validate_link_target(target)?;
    }
    let (kind, default_mode) = match entry.kind {
        DispatchEntryKind::Dir => (EntryKind::Dir, 0o755),
        DispatchEntryKind::File => (EntryKind::File, 0o444),
        DispatchEntryKind::WritableFile => (EntryKind::File, 0o644),
        DispatchEntryKind::ExecutableFile => (EntryKind::File, 0o555),
        DispatchEntryKind::Symlink => (EntryKind::Symlink, 0o777),
    };
    Ok(Entry {
        name: entry.name,
        kind,
        size: entry.size,
        mode: if entry.mode == 0 {
            default_mode
        } else {
            entry.mode
        },
        link_target: entry.link_target,
        modified: None,
    })
}

fn validate_entry_name(name: &str) -> Result<(), HandlerError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(HandlerError::invalid(format!(
            "dispatch entry name must be a normal path segment: {name:?}"
        )));
    }
    if name.contains('/') || name.contains('\\') || name.bytes().any(|b| b == 0) {
        return Err(HandlerError::invalid(format!(
            "dispatch entry name must be a single path segment: {name:?}"
        )));
    }
    Ok(())
}

fn validate_link_target(target: &str) -> Result<(), HandlerError> {
    if target.is_empty() || target.starts_with('/') {
        return Err(HandlerError::invalid(format!(
            "dispatch symlink target must be mount-relative: {target:?}"
        )));
    }
    if target.contains('\\') || target.bytes().any(|b| b == 0) {
        return Err(HandlerError::invalid(format!(
            "dispatch symlink target contains invalid bytes: {target:?}"
        )));
    }
    if target
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(HandlerError::invalid(format!(
            "dispatch symlink target must not contain dot or empty segments: {target:?}"
        )));
    }
    Ok(())
}

fn dispatch_error(code: i32, message: String, path: String) -> HandlerError {
    match code {
        -1 => HandlerError::NotFound(if message.is_empty() { path } else { message }),
        -2 => HandlerError::PermissionDenied,
        -3 => HandlerError::Invalid(message),
        -4 => HandlerError::Backend(message),
        COMPONENT_NOT_A_DIR_CODE => {
            HandlerError::NotADir(if message.is_empty() { path } else { message })
        }
        COMPONENT_UNSUPPORTED_CODE => HandlerError::Unsupported(message),
        _ => HandlerError::Backend(format!("petal dispatch error {code}: {message}")),
    }
}

fn unexpected_response(op: &str, response: DispatchResponse) -> HandlerError {
    HandlerError::Backend(format!(
        "petal dispatch {op} returned unexpected response: {response:?}"
    ))
}

fn map_petal_err(e: PetalError) -> HandlerError {
    match e {
        PetalError::NotFound(s) => HandlerError::NotFound(s),
        PetalError::InvalidHash(s) => HandlerError::invalid(format!("hash: {s}")),
        PetalError::InvalidName(s) => HandlerError::invalid(format!("name: {s}")),
        PetalError::InvalidWasm(s) => HandlerError::invalid(format!("wasm: {s}")),
        PetalError::CapabilityDenied { petal, cap } => {
            HandlerError::Backend(format!("capability denied: petal={petal} cap={cap}"))
        }
        PetalError::Vm(s) => HandlerError::Backend(format!("vm: {s}")),
        PetalError::Io(e) => HandlerError::Io(e),
        PetalError::Serde(s) => HandlerError::Backend(format!("serde: {s}")),
        PetalError::ModeCapMismatch { mode, cap } => HandlerError::invalid(format!(
            "mode/cap mismatch: mode={mode:?} disallows cap={cap}"
        )),
        PetalError::CapMismatch => HandlerError::invalid(
            "cap mismatch: petal already installed with different capabilities".to_string(),
        ),
        PetalError::ModeConflict { existing } => {
            HandlerError::invalid(format!("mode conflict: existing={existing}"))
        }
        PetalError::ModeUnsupported(s) => HandlerError::invalid(format!("mode unsupported: {s}")),
        PetalError::ChainCall(s) => HandlerError::Backend(format!("chain call: {s}")),
        PetalError::ChainCallTrap { detail, fuel_used } => HandlerError::Backend(format!(
            "chain call trapped after {fuel_used} fuel: {detail}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bloom_vfs::{Handler, Vfs, VfsPath};
    use tempfile::TempDir;

    use super::*;
    use crate::host::DenyHost;
    use crate::registry::NameRegistry;
    use crate::store::PetalStore;
    use crate::vm::PetalVm;

    fn runner() -> (TempDir, PetalRunner) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let vm = PetalVm::new().unwrap();
        (dir, PetalRunner::new(store, reg, vm))
    }

    fn write_package_file(root: &std::path::Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn write_demo_package(root: &std::path::Path) {
        write_package_file(
            root,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "demo"
"#,
        );
        write_package_file(root, "README.md", b"# demo");
        write_package_file(root, "AGENTS.md", b"# demo agents");
        write_package_file(
            root,
            "petal/demo/hello.txt.wasm",
            include_bytes!("../tests/fixtures/route_component_no_imports.wasm"),
        );
    }

    fn write_dynamic_dir_package(root: &std::path::Path, side_effecting_read: bool) {
        write_package_file(
            root,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "example"

[caps]
allowed = ["bloom:store", "bloom:vfs.read"]

[store]
namespaces = ["wallets"]
"#,
        );
        write_package_file(root, "README.md", b"# example");
        write_package_file(root, "AGENTS.md", b"# example agents");
        let route = if side_effecting_read {
            crate::package::route_fixtures::dynamic_side_effecting_dir_route_component(
                true,
                crate::package::route_fixtures::FixtureVfsImport::ReadOnly,
                &["bloom:store", "bloom:vfs.read"],
                None,
            )
        } else {
            crate::package::route_fixtures::dynamic_dir_route_component(
                true,
                crate::package::route_fixtures::FixtureVfsImport::ReadOnly,
                &["bloom:store", "bloom:vfs.read"],
                None,
            )
        };
        write_package_file(root, "petal/example/[wallet]/$index.wasm", &route);
    }

    fn write_async_failing_package(root: &std::path::Path) {
        write_package_file(
            root,
            "petal.toml",
            br#"schema = "bloom.petal.package.v1"
name = "example"
"#,
        );
        write_package_file(root, "README.md", b"# example");
        write_package_file(root, "AGENTS.md", b"# example agents");
        write_package_file(
            root,
            "petal/example/[wallet].txt.wasm",
            &crate::package::route_fixtures::async_failing_write_route_component(),
        );
    }

    #[tokio::test]
    async fn parameterized_dir_route_lookup_uses_component_runtime_metadata() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_dynamic_dir_package(&package, false);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let route_path = VfsPath::parse("/example/alice").unwrap();
        assert!(router.is_read_side_effecting(&route_path));
        assert_eq!(router.cache_ttl(&route_path), None);
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(router.clone()))
            .build();

        let entry = vfs
            .lookup(&VfsPath::parse("/petals/example/alice").unwrap())
            .await
            .unwrap();
        assert_eq!(entry.name, "alice");
        assert_eq!(entry.kind, bloom_vfs::EntryKind::Dir);
        assert_eq!(entry.mode, 0o755);
        // The size comes from the component's lookup handler, proving the
        // dynamic route dispatched instead of falling back to a static
        // route-index directory entry.
        assert_eq!(
            entry.size,
            crate::package::route_fixtures::LOOKUP_ENTRY_SIZE
        );
        assert!(!router.is_read_side_effecting(&route_path));
        assert_eq!(router.cache_ttl(&route_path), Some(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn parameterized_side_effecting_route_remains_fail_closed_after_lookup() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_dynamic_dir_package(&package, true);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let route_path = VfsPath::parse("/example/alice").unwrap();
        assert!(router.is_read_side_effecting(&route_path));
        let vfs = Vfs::builder()
            .mount("petals", Arc::new(router.clone()))
            .build();

        vfs.lookup(&VfsPath::parse("/petals/example/alice").unwrap())
            .await
            .unwrap();

        assert!(router.is_read_side_effecting(&route_path));
        assert_eq!(router.cache_ttl(&route_path), None);
    }

    #[tokio::test]
    async fn mounted_petals_vfs_dispatches_installed_petal_routes() {
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        runner.store().install_petal_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let vfs = Vfs::builder().mount("petals", Arc::new(router)).build();

        let apps = vfs.list(&VfsPath::parse("/petals").unwrap()).await.unwrap();
        assert!(apps.iter().any(|entry| entry.name == "demo"));

        let app_entries = vfs
            .list(&VfsPath::parse("/petals/demo").unwrap())
            .await
            .unwrap();
        assert!(app_entries.iter().any(|entry| entry.name == "hello.txt"));

        let bytes = vfs
            .read(&VfsPath::parse("/petals/demo/hello.txt").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"component");
    }

    #[test]
    fn router_rejects_undeclared_endpoint_override_before_dispatch() {
        let (dir, runner) = runner();
        let package = dir.path().join("demo-app");
        write_demo_package(&package);
        runner.store().install_petal_package_dir(&package).unwrap();

        let runtime_petals = BTreeMap::from([(
            "demo".to_string(),
            PetalRuntimeConfig {
                endpoints: BTreeMap::from([(
                    "clob".to_string(),
                    "https://clob.internal.example".to_string(),
                )]),
                values: BTreeMap::new(),
            },
        )]);
        let err = match PetalRouter::new(runner, Arc::new(DenyHost))
            .with_runtime_petals(runtime_petals)
        {
            Ok(_) => panic!("undeclared endpoint override unexpectedly accepted"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("endpoint override \"clob\" is not declared"),
            "unexpected router construction error: {err}"
        );
    }

    #[tokio::test]
    async fn write_async_route_errors_are_returned_to_the_vfs_caller() {
        let (dir, runner) = runner();
        let package = dir.path().join("example-app");
        write_async_failing_package(&package);
        runner.store().install_petal_package_dir(&package).unwrap();

        // A true switch used to detach this write and return Ok immediately.
        // The compatibility method is now deliberately a no-op.
        let router = PetalRouter::new(runner, Arc::new(DenyHost))
            .with_async_write_switch(Arc::new(AtomicBool::new(true)));
        let vfs = Vfs::builder().mount("petals", Arc::new(router)).build();

        let error = vfs
            .write(
                &VfsPath::parse("/petals/example/alice.txt").unwrap(),
                b"payload",
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("component route write"),
            "unexpected write error: {error}"
        );
    }
}
