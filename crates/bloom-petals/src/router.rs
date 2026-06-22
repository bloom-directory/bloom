//! VFS router for local petal-provided apps.
//!
//! The daemon mounts this handler at `apps/`. The first path segment selects
//! an installed local petal mount from its embedded manifest; the remaining
//! path is passed to the petal's `petal_dispatch` export.

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
use crate::vm::RunOptions;

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
}

#[async_trait]
impl Handler for PetalRouter {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        match path.segments() {
            [] => Ok(Entry::dir("")),
            [mount] => {
                self.runner.resolve_mount(mount).map_err(map_petal_err)?;
                Ok(Entry::dir(mount))
            }
            _ => {
                let (mount, rest) = Self::mount_path(path)?;
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
        if !self
            .endpoint_hint(path)
            .map(|hint| hint.write)
            .unwrap_or(false)
        {
            return Err(HandlerError::PermissionDenied);
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
            [] => self
                .runner
                .local_mounts()
                .map(|mounts| {
                    mounts
                        .into_iter()
                        .map(|(mount, _hash)| Entry::dir(&mount))
                        .collect()
                })
                .map_err(map_petal_err),
            [mount] => match self
                .dispatch(mount, DispatchOp::List, String::new(), Vec::new())
                .await?
            {
                DispatchResponse::List(entries) => entries.into_iter().map(entry_to_vfs).collect(),
                DispatchResponse::Error { code, message } => {
                    Err(dispatch_error(code, message, path.to_string_path()))
                }
                other => Err(unexpected_response("list", other)),
            },
            _ => {
                let (mount, rest) = Self::mount_path(path)?;
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
        self.endpoint_hint(path)
            .filter(|hint| !hint.read_side_effecting)
            .and_then(|hint| hint.cache_ttl_ms)
            .map(Duration::from_millis)
    }

    fn is_read_side_effecting(&self, path: &VfsPath) -> bool {
        self.endpoint_hint(path)
            .map(|hint| hint.read_side_effecting)
            .unwrap_or(false)
    }
}

fn entry_to_vfs(entry: DispatchEntry) -> Result<Entry, HandlerError> {
    validate_entry_name(&entry.name)?;
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

fn dispatch_error(code: i32, message: String, path: String) -> HandlerError {
    match code {
        -1 => HandlerError::NotFound(if message.is_empty() { path } else { message }),
        -2 => HandlerError::PermissionDenied,
        -3 => HandlerError::Invalid(message),
        -4 => HandlerError::Backend(message),
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
    use crate::abi::{DispatchEntryKind, encode_dispatch_response};
    use crate::host::DenyHost;
    use crate::meta::PetalMode;
    use crate::registry::NameRegistry;
    use crate::store::PetalStore;
    use crate::vm::PetalVm;
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

    fn embedded_app(response: DispatchResponse, mount: &str) -> Vec<u8> {
        embedded_app_with_manifest_tail(response, mount, "")
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

    #[test]
    fn endpoint_globs_are_segment_scoped() {
        assert!(endpoint_matches("markets*", "markets-open"));
        assert!(endpoint_matches("markets/*", "markets/123"));
        assert!(!endpoint_matches("markets/*", "markets/123/outcomes"));
        assert!(!endpoint_matches("markets*", "other"));
    }

    #[test]
    fn endpoint_specificity_prefers_exact_paths() {
        assert!(endpoint_specificity("markets/123") > endpoint_specificity("markets/*"));
        assert!(endpoint_specificity("markets-open") > endpoint_specificity("markets*"));
    }
}
