//! VFS router for local petal-provided apps.
//!
//! The daemon mounts this handler at `apps/`. The first path segment selects
//! an installed local petal mount from its embedded manifest; the remaining
//! path is passed to the petal's `petal_dispatch` export.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bloom_petal_manifest::local::EndpointSpec;
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
}

impl PetalRouter {
    pub fn new(runner: PetalRunner, host: Arc<dyn PetalHost>) -> Self {
        Self { runner, host }
    }

    fn mount_path(path: &VfsPath) -> Result<(&str, String), HandlerError> {
        let [mount, rest @ ..] = path.segments() else {
            return Err(HandlerError::NotFound(path.to_string_path()));
        };
        let rest = rest.join("/");
        Ok((mount, rest))
    }

    fn endpoint_hint(&self, path: &VfsPath) -> Option<EndpointSpec> {
        let (mount, rest) = Self::mount_path(path).ok()?;
        if rest.is_empty() {
            return None;
        }
        let manifest = self.runner.local_manifest_for_mount(mount).ok()?;
        manifest
            .endpoint
            .into_iter()
            .filter(|endpoint| endpoint_matches(&endpoint.path, &rest))
            .max_by_key(|endpoint| endpoint_specificity(&endpoint.path))
    }

    async fn dispatch(
        &self,
        mount: &str,
        op: DispatchOp,
        path: String,
        body: Vec<u8>,
    ) -> Result<DispatchResponse, HandlerError> {
        let out = self
            .runner
            .dispatch_mount(
                mount,
                DispatchRequest {
                    op,
                    path,
                    body,
                    ctx: Vec::new(),
                },
                self.host.clone(),
                None,
                RunOptions::default(),
            )
            .await
            .map_err(map_petal_err)?;
        Ok(out.response)
    }

    fn is_v2_app(&self, mount: &str) -> bool {
        self.runner.resolve_app_mount(mount).is_ok()
    }

    async fn dispatch_v2(
        &self,
        mount: &str,
        op: DispatchOp,
        path: String,
        body: Vec<u8>,
    ) -> Result<DispatchResponse, HandlerError> {
        let out = self
            .runner
            .dispatch_app_route(
                mount,
                DispatchRequest {
                    op,
                    path,
                    body,
                    ctx: Vec::new(),
                },
                self.host.clone(),
                None,
                RunOptions::default(),
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
                if !self.is_v2_app(mount) {
                    self.runner.resolve_mount(mount).map_err(map_petal_err)?;
                }
                Ok(Entry::dir(mount))
            }
            _ => {
                let (mount, rest) = Self::mount_path(path)?;
                if self.is_v2_app(mount) {
                    match self
                        .dispatch_v2(mount, DispatchOp::Lookup, rest.clone(), Vec::new())
                        .await
                    {
                        Ok(DispatchResponse::Lookup(entry)) => return entry_to_vfs(entry),
                        Ok(DispatchResponse::Error { code, message }) => {
                            return Err(dispatch_error(code, message, path.to_string_path()));
                        }
                        Ok(other) => return Err(unexpected_response("lookup", other)),
                        Err(HandlerError::NotFound(_))
                            if self
                                .runner
                                .local_app_has_descendant(mount, &rest)
                                .map_err(map_petal_err)? =>
                        {
                            let name = path
                                .segments()
                                .last()
                                .map(String::as_str)
                                .unwrap_or_default();
                            return Ok(Entry::dir(name));
                        }
                        Err(e) => return Err(e),
                    }
                }
                match self
                    .dispatch(mount, DispatchOp::Lookup, rest, Vec::new())
                    .await?
                {
                    DispatchResponse::Lookup(entry) => entry_to_vfs(entry),
                    DispatchResponse::Error { code, message } => {
                        Err(dispatch_error(code, message, path.to_string_path()))
                    }
                    other => Err(unexpected_response("lookup", other)),
                }
            }
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let (mount, rest) = Self::mount_path(path)?;
        if rest.is_empty() {
            return Err(HandlerError::NotAFile(path.to_string_path()));
        }
        if self.is_v2_app(mount) {
            return match self
                .dispatch_v2(mount, DispatchOp::Read, rest, Vec::new())
                .await?
            {
                DispatchResponse::Read(bytes) => Ok(bytes),
                DispatchResponse::Error { code, message } => {
                    Err(dispatch_error(code, message, path.to_string_path()))
                }
                other => Err(unexpected_response("read", other)),
            };
        }
        match self
            .dispatch(mount, DispatchOp::Read, rest, Vec::new())
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
        if self.is_v2_app(mount) {
            let (_, runtime_metadata) = self
                .runner
                .local_app_route_runtime_metadata(
                    mount,
                    DispatchOp::Write,
                    &rest,
                    RunOptions::default(),
                )
                .await
                .map_err(map_petal_err)?;
            if runtime_metadata.write_async {
                let runner = self.runner.clone();
                let host = self.host.clone();
                let mount = mount.to_string();
                let request = DispatchRequest {
                    op: DispatchOp::Write,
                    path: rest,
                    body: data.to_vec(),
                    ctx: Vec::new(),
                };
                tokio::spawn(async move {
                    let result = runner
                        .dispatch_app_route(&mount, request, host, None, RunOptions::default())
                        .await;
                    if let Err(e) = result {
                        tracing::warn!(
                            mount = %mount,
                            error = %e,
                            "async v2 petal write failed"
                        );
                    }
                });
                return Ok(());
            }
            return match self
                .dispatch_v2(mount, DispatchOp::Write, rest, data.to_vec())
                .await?
            {
                DispatchResponse::Write => Ok(()),
                DispatchResponse::Error { code, message } => {
                    Err(dispatch_error(code, message, path.to_string_path()))
                }
                other => Err(unexpected_response("write", other)),
            };
        }
        let hint = self.endpoint_hint(path);
        if !hint.as_ref().map(|hint| hint.write).unwrap_or(false) {
            return Err(HandlerError::PermissionDenied);
        }
        if hint
            .as_ref()
            .map(|hint| hint.async_dispatch)
            .unwrap_or(false)
        {
            let runner = self.runner.clone();
            let host = self.host.clone();
            let mount = mount.to_string();
            let dispatch_path = rest;
            let body = data.to_vec();
            tokio::spawn(async move {
                let result = runner
                    .dispatch_mount(
                        &mount,
                        DispatchRequest {
                            op: DispatchOp::Write,
                            path: dispatch_path,
                            body,
                            ctx: Vec::new(),
                        },
                        host,
                        None,
                        RunOptions::default(),
                    )
                    .await;
                match result {
                    Ok(out) => match out.response {
                        DispatchResponse::Write => {}
                        DispatchResponse::Error { code, message } => {
                            tracing::warn!(
                                mount = %mount,
                                code,
                                error = %message,
                                "async petal write returned error"
                            );
                        }
                        other => {
                            tracing::warn!(
                                mount = %mount,
                                response = ?other,
                                "async petal write returned unexpected response"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            mount = %mount,
                            error = %e,
                            "async petal write failed"
                        );
                    }
                }
            });
            return Ok(());
        }
        match self
            .dispatch(mount, DispatchOp::Write, rest, data.to_vec())
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
                for (mount, _hash) in self.runner.local_mounts().map_err(map_petal_err)? {
                    mounts.insert(mount, ());
                }
                for (mount, _hash) in self.runner.local_app_mounts().map_err(map_petal_err)? {
                    mounts.insert(mount, ());
                }
                Ok(mounts.into_keys().map(|mount| Entry::dir(&mount)).collect())
            }
            [mount] if self.is_v2_app(mount) => {
                match self
                    .dispatch_v2(mount, DispatchOp::List, String::new(), Vec::new())
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
                        .local_app_static_list(mount, "")
                        .map_err(map_petal_err)?
                        .into_iter()
                        .map(entry_to_vfs)
                        .collect(),
                    Err(e) => Err(e),
                }
            }
            [mount] => {
                match self
                    .dispatch(mount, DispatchOp::List, String::new(), Vec::new())
                    .await?
                {
                    DispatchResponse::List(entries) => {
                        entries.into_iter().map(entry_to_vfs).collect()
                    }
                    DispatchResponse::Error { code, message } => {
                        Err(dispatch_error(code, message, path.to_string_path()))
                    }
                    other => Err(unexpected_response("list", other)),
                }
            }
            _ => {
                let (mount, rest) = Self::mount_path(path)?;
                if self.is_v2_app(mount) {
                    return match self
                        .dispatch_v2(mount, DispatchOp::List, rest.clone(), Vec::new())
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
                            .local_app_static_list(mount, &rest)
                            .map_err(map_petal_err)?
                            .into_iter()
                            .map(entry_to_vfs)
                            .collect(),
                        Err(e) => Err(e),
                    };
                }
                match self
                    .dispatch(mount, DispatchOp::List, rest, Vec::new())
                    .await?
                {
                    DispatchResponse::List(entries) => {
                        entries.into_iter().map(entry_to_vfs).collect()
                    }
                    DispatchResponse::Error { code, message } => {
                        Err(dispatch_error(code, message, path.to_string_path()))
                    }
                    other => Err(unexpected_response("list", other)),
                }
            }
        }
    }

    fn cache_ttl(&self, path: &VfsPath) -> Option<Duration> {
        if let Ok((mount, rest)) = Self::mount_path(path)
            && self.is_v2_app(mount)
        {
            return self
                .runner
                .local_app_route(mount, DispatchOp::Read, &rest)
                .ok()
                .filter(|matched| !matched.route.install_metadata.side_effecting_read)
                .and_then(|matched| matched.route.install_metadata.cache_ttl_ms)
                .map(Duration::from_millis);
        }
        self.endpoint_hint(path)
            .filter(|hint| !hint.read_side_effecting)
            .and_then(|hint| hint.cache_ttl_ms)
            .map(Duration::from_millis)
    }

    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        if let Ok((mount, rest)) = Self::mount_path(path)
            && self.is_v2_app(mount)
        {
            return self
                .runner
                .local_app_route(mount, DispatchOp::Read, &rest)
                .ok()
                .map(|matched| matched.route.install_metadata.side_effecting_read)
                .unwrap_or(false);
        }
        self.endpoint_hint(path)
            .map(|hint| hint.read_side_effecting)
            .unwrap_or(false)
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

fn endpoint_matches(glob: &str, path: &str) -> bool {
    let glob_segs: Vec<&str> = glob.split('/').collect();
    let path_segs: Vec<&str> = path.split('/').collect();
    if glob_segs.len() != path_segs.len() {
        return false;
    }
    glob_segs
        .iter()
        .zip(path_segs)
        .all(|(glob, path)| match *glob {
            "*" => true,
            _ if glob.ends_with('*') => path.starts_with(glob.trim_end_matches('*')),
            _ => *glob == path,
        })
}

fn endpoint_specificity(glob: &str) -> (usize, usize, usize) {
    let mut literal_bytes = 0;
    let mut exact_segments = 0;
    let mut wildcard_segments = 0;
    for segment in glob.split('/') {
        if segment == "*" || segment.ends_with('*') {
            wildcard_segments += 1;
            literal_bytes += segment.trim_end_matches('*').len();
        } else {
            exact_segments += 1;
            literal_bytes += segment.len();
        }
    }
    (
        literal_bytes,
        exact_segments,
        usize::MAX - wildcard_segments,
    )
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
    use super::*;
    use crate::abi::{
        DispatchEntryKind, HttpRequest, HttpResponse, encode_dispatch_response, encode_http_request,
    };
    use crate::host::{DenyHost, PetalHost};
    use crate::meta::PetalMode;
    use crate::policy::NetPolicy;
    use crate::registry::NameRegistry;
    use crate::store::PetalStore;
    use crate::vm::PetalVm;
    use parking_lot::Mutex;
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    fn runner() -> (TempDir, PetalRunner) {
        let dir = TempDir::new().unwrap();
        let store = PetalStore::open(dir.path().join("store")).unwrap();
        let reg = Arc::new(NameRegistry::open(dir.path().join("reg")).unwrap());
        let vm = PetalVm::new().unwrap();
        (dir, PetalRunner::new(store, reg, vm))
    }

    fn wat_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("\\{b:02x}")).collect()
    }

    fn dispatch_wat(response: DispatchResponse) -> Vec<u8> {
        let response = encode_dispatch_response(&response);
        let wat = format!(
            r#"
        (module
          (memory (export "memory") 1)
          (global $heap (mut i32) (i32.const 1024))
          (data (i32.const 64) "{}")
          (func (export "petal_alloc") (param $len i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $heap))
            (global.set $heap (i32.add (global.get $heap) (local.get $len)))
            (local.get $ptr))
          (func (export "petal_dispatch") (param $ptr i32) (param $len i32) (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (i32.const 64)) (i64.const 32))
              (i64.extend_i32_u (i32.const {}))))
        )
    "#,
            wat_bytes(&response),
            response.len()
        );
        wat::parse_str(&wat).unwrap()
    }

    fn http_dispatch_wat(req: &HttpRequest) -> Vec<u8> {
        let req = encode_http_request(req);
        let wat = format!(
            r#"
        (module
          (import "bloom.v1" "http_fetch"
            (func $http_fetch (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (global $heap (mut i32) (i32.const 1024))
          (data (i32.const 0) "{}")
          (data (i32.const 400) "\02\01\00\00\00\00")
          (func (export "petal_alloc") (param $len i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $heap))
            (global.set $heap (i32.add (global.get $heap) (local.get $len)))
            (local.get $ptr))
          (func (export "petal_dispatch") (param $ptr i32) (param $len i32) (result i64)
            (local $code i32)
            (local.set $code
              (call $http_fetch
                (i32.const 0)
                (i32.const {})
                (i32.const 2048)
                (i32.const 4096)))
            (i32.store8 (i32.const 405) (local.get $code))
            (i64.or
              (i64.shl (i64.extend_i32_u (i32.const 400)) (i64.const 32))
              (i64.extend_i32_u (i32.const 6))))
        )
    "#,
            wat_bytes(&req),
            req.len()
        );
        wat::parse_str(&wat).unwrap()
    }

    fn embedded_app(response: DispatchResponse, mount: &str) -> Vec<u8> {
        embedded_app_with_manifest_tail(response, mount, "")
    }

    fn write_v2_package_route(root: &std::path::Path, route: &str, wasm: &[u8]) {
        write_v2_package_route_with_manifest(
            root,
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
"#,
            route,
            wasm,
        );
    }

    fn write_v2_package_route_with_manifest(
        root: &std::path::Path,
        manifest: &[u8],
        route: &str,
        wasm: &[u8],
    ) {
        write_test_file(root, "petal.toml", manifest);
        write_test_file(root, "README.md", b"# echo");
        write_test_file(root, "AGENTS.md", b"# echo agents");
        write_test_file(root, route, wasm);
    }

    fn write_test_file(root: &std::path::Path, rel: &str, body: &[u8]) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn embedded_app_with_manifest_tail(
        response: DispatchResponse,
        mount: &str,
        manifest_tail: &str,
    ) -> Vec<u8> {
        let manifest = format!(
            r#"
schema = "bloom.petal.local.v1"
name = "{mount}"
[provides]
kind = "vfs"
mount = "{mount}"
caps = []
{manifest_tail}
"#
        );
        bloom_petal_manifest::embed_local_manifest_section(
            &dispatch_wat(response),
            manifest.as_bytes(),
        )
        .unwrap()
    }

    #[derive(Default)]
    struct HttpHost {
        calls: Mutex<Vec<HttpRequest>>,
    }

    #[async_trait::async_trait]
    impl PetalHost for HttpHost {
        async fn vfs_read(&self, _path: &str) -> Result<Vec<u8>, crate::host::HostError> {
            Err(crate::host::HostError::Denied("vfs".into()))
        }

        async fn vfs_list(&self, _path: &str) -> Result<Vec<String>, crate::host::HostError> {
            Err(crate::host::HostError::Denied("vfs".into()))
        }

        async fn vfs_write(
            &self,
            _path: &str,
            _bytes: &[u8],
        ) -> Result<(), crate::host::HostError> {
            Err(crate::host::HostError::Denied("vfs".into()))
        }

        async fn http_fetch(
            &self,
            req: HttpRequest,
            policy: NetPolicy,
            max_response_bytes: usize,
        ) -> Result<HttpResponse, crate::host::HostError> {
            policy.check(&req.method, &req.url)?;
            self.calls.lock().push(req);
            let response = HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"ok".to_vec(),
            };
            assert!(response.body.len() <= max_response_bytes);
            Ok(response)
        }
    }

    #[tokio::test]
    async fn root_lists_manifest_mounts() {
        let (_d, runner_with_no_write) = runner();
        runner_with_no_write
            .install(
                &embedded_app(DispatchResponse::Write, "demo"),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner_with_no_write, Arc::new(DenyHost));
        let entries = router.list(&VfsPath::root()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "demo");
        assert_eq!(entries[0].kind, EntryKind::Dir);
    }

    #[tokio::test]
    async fn root_lists_v2_app_packages() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/hello.txt.wasm",
            &dispatch_wat(DispatchResponse::Read(b"hello".to_vec())),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let entries = router.list(&VfsPath::root()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "echo");
        assert_eq!(entries[0].kind, EntryKind::Dir);
    }

    #[tokio::test]
    async fn read_dispatches_to_mount_relative_path() {
        let (_d, runner_with_write) = runner();
        runner_with_write
            .install(
                &embedded_app(DispatchResponse::Read(b"hello".to_vec()), "demo"),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner_with_write, Arc::new(DenyHost));
        let bytes = router
            .read(&VfsPath::parse("demo/file.txt").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[tokio::test]
    async fn read_dispatches_to_v2_route_artifact() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/hello.txt.wasm",
            &dispatch_wat(DispatchResponse::Read(b"hello-v2".to_vec())),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let bytes = router
            .read(&VfsPath::parse("echo/hello.txt").unwrap())
            .await
            .unwrap();
        assert_eq!(bytes, b"hello-v2");
    }

    #[tokio::test]
    async fn v2_http_routes_use_manifest_net_policy() {
        let (d, allowed_runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route_with_manifest(
            &package,
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/markets*"]
"#,
            "app/echo/market.txt.wasm",
            &http_dispatch_wat(&HttpRequest {
                method: "GET".into(),
                url: "https://api.example.com/markets/1".into(),
                headers: Vec::new(),
                body: Vec::new(),
            }),
        );
        allowed_runner
            .store()
            .install_app_package_dir(&package)
            .unwrap();

        let host = Arc::new(HttpHost::default());
        let router = PetalRouter::new(allowed_runner, host.clone());
        let bytes = router
            .read(&VfsPath::parse("echo/market.txt").unwrap())
            .await
            .unwrap();
        assert!(bytes[0] > 0);
        assert_eq!(host.calls.lock().len(), 1);

        let (d, denied_runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route_with_manifest(
            &package,
            br#"schema = "bloom.petal.local-app.v2"
name = "echo"
[caps]
allowed = ["bloom:http"]

[[net.allow]]
host = "api.example.com"
methods = ["GET"]
paths = ["/markets*"]
"#,
            "app/echo/market.txt.wasm",
            &http_dispatch_wat(&HttpRequest {
                method: "GET".into(),
                url: "https://evil.example.com/markets/1".into(),
                headers: Vec::new(),
                body: Vec::new(),
            }),
        );
        denied_runner
            .store()
            .install_app_package_dir(&package)
            .unwrap();

        let host = Arc::new(HttpHost::default());
        let router = PetalRouter::new(denied_runner, host.clone());
        let bytes = router
            .read(&VfsPath::parse("echo/market.txt").unwrap())
            .await
            .unwrap();
        assert_ne!(bytes, vec![0]);
        assert!(host.calls.lock().is_empty());
    }

    #[tokio::test]
    async fn v2_static_dirs_are_inferred_from_route_index() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/nested/file.txt.wasm",
            &dispatch_wat(DispatchResponse::Read(b"nested".to_vec())),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let entry = router
            .lookup(&VfsPath::parse("echo/nested").unwrap())
            .await
            .unwrap();
        assert_eq!(entry.name, "nested");
        assert_eq!(entry.kind, EntryKind::Dir);

        let entries = router.list(&VfsPath::parse("echo").unwrap()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "nested");
        assert_eq!(entries[0].kind, EntryKind::Dir);

        let nested_entries = router
            .list(&VfsPath::parse("echo/nested").unwrap())
            .await
            .unwrap();
        assert_eq!(nested_entries.len(), 1);
        assert_eq!(nested_entries[0].name, "file.txt");
        assert_eq!(nested_entries[0].kind, EntryKind::File);
    }

    #[tokio::test]
    async fn v2_list_dispatches_to_special_list_route() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/$list.wasm",
            &dispatch_wat(DispatchResponse::List(vec![DispatchEntry {
                name: "dynamic.txt".into(),
                kind: DispatchEntryKind::File,
                size: 7,
                mode: 0,
                ttl_hint_ms: None,
                link_target: None,
            }])),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let entries = router.list(&VfsPath::parse("echo").unwrap()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "dynamic.txt");
        assert_eq!(entries[0].kind, EntryKind::File);
        assert_eq!(entries[0].size, 7);
    }

    #[tokio::test]
    async fn v2_special_routes_are_not_user_addressable() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/$list.wasm",
            &dispatch_wat(DispatchResponse::Read(b"hidden".to_vec())),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let err = router
            .read(&VfsPath::parse("echo/$list").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::Invalid(_)));
    }

    #[tokio::test]
    async fn v2_read_only_routes_do_not_accept_writes() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/hello.txt.wasm",
            &dispatch_wat(DispatchResponse::Write),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let err = router
            .write(&VfsPath::parse("echo/hello.txt").unwrap(), b"x")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            HandlerError::Invalid(_) | HandlerError::PermissionDenied
        ));
    }

    #[tokio::test]
    async fn v2_index_routes_are_listed_as_directories() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/nested/$index.wasm",
            &dispatch_wat(DispatchResponse::Read(b"index".to_vec())),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let entries = router.list(&VfsPath::parse("echo").unwrap()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "nested");
        assert_eq!(entries[0].kind, EntryKind::Dir);

        let nested_entries = router
            .list(&VfsPath::parse("echo/nested").unwrap())
            .await
            .unwrap();
        assert!(nested_entries.is_empty());
    }

    #[tokio::test]
    async fn v2_special_probe_does_not_match_dynamic_file_route() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/items/[id].wasm",
            &dispatch_wat(DispatchResponse::Read(b"dynamic".to_vec())),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let entries = router.list(&VfsPath::parse("echo").unwrap()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "items");
        assert_eq!(entries[0].kind, EntryKind::Dir);

        let item_entries = router
            .list(&VfsPath::parse("echo/items").unwrap())
            .await
            .unwrap();
        assert!(item_entries.is_empty());
    }

    #[tokio::test]
    async fn v2_lookup_prefers_exact_static_route_over_dynamic_lookup() {
        let (d, runner) = runner();
        let package = d.path().join("pkg");
        write_v2_package_route(
            &package,
            "app/echo/items/static.wasm",
            &dispatch_wat(DispatchResponse::Lookup(DispatchEntry {
                name: "static".into(),
                kind: DispatchEntryKind::File,
                size: 1,
                mode: 0,
                ttl_hint_ms: None,
                link_target: None,
            })),
        );
        write_test_file(
            &package,
            "app/echo/items/[id]/$lookup.wasm",
            &dispatch_wat(DispatchResponse::Lookup(DispatchEntry {
                name: "dynamic".into(),
                kind: DispatchEntryKind::File,
                size: 2,
                mode: 0,
                ttl_hint_ms: None,
                link_target: None,
            })),
        );
        runner.store().install_app_package_dir(&package).unwrap();

        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let entry = router
            .lookup(&VfsPath::parse("echo/items/static").unwrap())
            .await
            .unwrap();
        assert_eq!(entry.name, "static");
        assert_eq!(entry.size, 1);
    }

    #[tokio::test]
    async fn lookup_maps_dispatch_entry_metadata() {
        let (_d, runner_with_no_write) = runner();
        runner_with_no_write
            .install(
                &embedded_app(
                    DispatchResponse::Lookup(DispatchEntry {
                        name: "run".into(),
                        kind: DispatchEntryKind::ExecutableFile,
                        size: 7,
                        mode: 0,
                        ttl_hint_ms: None,
                        link_target: None,
                    }),
                    "demo",
                ),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner_with_no_write, Arc::new(DenyHost));
        let entry = router
            .lookup(&VfsPath::parse("demo/run").unwrap())
            .await
            .unwrap();
        assert_eq!(entry.name, "run");
        assert_eq!(entry.kind, EntryKind::File);
        assert_eq!(entry.mode, 0o555);
        assert_eq!(entry.size, 7);
    }

    #[tokio::test]
    async fn dispatch_error_maps_to_handler_error() {
        let (_d, runner_with_write) = runner();
        runner_with_write
            .install(
                &embedded_app(
                    DispatchResponse::Error {
                        code: -1,
                        message: "missing".into(),
                    },
                    "demo",
                ),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner_with_write, Arc::new(DenyHost));
        let err = router
            .read(&VfsPath::parse("demo/nope").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(s) if s == "missing"));
    }

    #[tokio::test]
    async fn write_requires_declared_writable_endpoint() {
        let (_d, runner_with_no_write) = runner();
        runner_with_no_write
            .install(
                &embedded_app(DispatchResponse::Write, "demo"),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner_with_no_write, Arc::new(DenyHost));
        let err = router
            .write(&VfsPath::parse("demo/hidden").unwrap(), b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::PermissionDenied));

        let (_d, runner_with_write) = runner();
        runner_with_write
            .install(
                &embedded_app_with_manifest_tail(
                    DispatchResponse::Write,
                    "demo",
                    r#"
[[endpoint]]
path = "writable"
write = true
"#,
                ),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner_with_write, Arc::new(DenyHost));
        router
            .write(&VfsPath::parse("demo/writable").unwrap(), b"x")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn async_writable_endpoint_returns_after_enqueue() {
        let (_d, runner) = runner();
        runner
            .install(
                &embedded_app_with_manifest_tail(
                    DispatchResponse::Error {
                        code: -4,
                        message: "background failure".into(),
                    },
                    "demo",
                    r#"
[[endpoint]]
path = "writable"
write = true
async = true
"#,
                ),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        router
            .write(&VfsPath::parse("demo/writable").unwrap(), b"x")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn side_effecting_reads_are_not_cacheable() {
        let (_d, runner) = runner();
        runner
            .install(
                &embedded_app_with_manifest_tail(
                    DispatchResponse::Read(b"secret".to_vec()),
                    "demo",
                    r#"
[[endpoint]]
path = "sign"
cache_ttl_ms = 60000
read_side_effecting = true
"#,
                ),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let path = VfsPath::parse("demo/sign").unwrap();
        assert!(router.is_read_side_effecting(&path));
        assert_eq!(router.cache_ttl(&path), None);
    }

    #[tokio::test]
    async fn dispatch_entry_names_must_be_plain_segments() {
        let (_d, runner) = runner();
        runner
            .install(
                &embedded_app(
                    DispatchResponse::Lookup(DispatchEntry {
                        name: "../wallets".into(),
                        kind: DispatchEntryKind::File,
                        size: 0,
                        mode: 0,
                        ttl_hint_ms: None,
                        link_target: None,
                    }),
                    "demo",
                ),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let err = router
            .lookup(&VfsPath::parse("demo/bad").unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::Invalid(_)));
    }

    #[tokio::test]
    async fn symlink_targets_must_stay_mount_relative() {
        for target in ["/wallets/alice", "../wallets", "ok/../wallets", "bad\\path"] {
            let (_d, runner) = runner();
            runner
                .install(
                    &embedded_app(
                        DispatchResponse::Lookup(DispatchEntry {
                            name: "link".into(),
                            kind: DispatchEntryKind::Symlink,
                            size: 0,
                            mode: 0,
                            ttl_hint_ms: None,
                            link_target: Some(target.into()),
                        }),
                        "demo",
                    ),
                    None,
                    &BTreeSet::new(),
                    PetalMode::Local,
                )
                .unwrap();
            let router = PetalRouter::new(runner, Arc::new(DenyHost));
            let err = router
                .lookup(&VfsPath::parse("demo/link").unwrap())
                .await
                .unwrap_err();
            assert!(
                matches!(err, HandlerError::Invalid(_)),
                "expected invalid symlink target {target:?}, got {err:?}"
            );
        }

        let (_d, runner) = runner();
        runner
            .install(
                &embedded_app(
                    DispatchResponse::Lookup(DispatchEntry {
                        name: "link".into(),
                        kind: DispatchEntryKind::Symlink,
                        size: 0,
                        mode: 0,
                        ttl_hint_ms: None,
                        link_target: Some("child/file".into()),
                    }),
                    "demo",
                ),
                None,
                &BTreeSet::new(),
                PetalMode::Local,
            )
            .unwrap();
        let router = PetalRouter::new(runner, Arc::new(DenyHost));
        let entry = router
            .lookup(&VfsPath::parse("demo/link").unwrap())
            .await
            .unwrap();
        assert_eq!(entry.link_target.as_deref(), Some("child/file"));
    }

    #[test]
    fn endpoint_globs_are_segment_scoped() {
        assert!(endpoint_matches("markets*", "markets-open"));
        assert!(endpoint_matches("markets/*", "markets/123"));
        assert!(!endpoint_matches("markets/*", "markets/123/outcomes"));
        assert!(!endpoint_matches("markets*", "other"));
    }

    #[test]
    fn component_route_error_codes_preserve_vfs_semantics() {
        assert!(matches!(
            dispatch_error(
                COMPONENT_NOT_A_DIR_CODE,
                "plain-file".into(),
                "demo/plain-file".into()
            ),
            HandlerError::NotADir(path) if path == "plain-file"
        ));
        assert!(matches!(
            dispatch_error(COMPONENT_UNSUPPORTED_CODE, "write".into(), "demo/file".into()),
            HandlerError::Unsupported(op) if op == "write"
        ));
    }

    #[test]
    fn endpoint_specificity_prefers_exact_paths() {
        assert!(endpoint_specificity("markets/123") > endpoint_specificity("markets/*"));
        assert!(endpoint_specificity("markets-open") > endpoint_specificity("markets*"));
    }
}
