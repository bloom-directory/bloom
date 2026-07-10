//! `watch/` — VFS surface for the subscription executor.
//!
//! Path layout (relative to the `watch` mount point):
//!
//! - `watch/`                         — list: `new` plus every active id
//! - `watch/new`                      — write a TOML [`WatchSpec`] to register
//! - `watch/<id>/`                    — list: `spec.toml`, `live`,
//!   `history.jsonl`, plus any rotated `history.jsonl.<n>` segments
//! - `watch/<id>/spec.toml`           — read TOML serialisation of the spec
//! - `watch/<id>/live`                — read current jsonl tail
//! - `watch/<id>/history.jsonl`       — read latest archive
//! - `watch/<id>/history.jsonl.<n>`   — read older archives
//! - `watch/<id>/delete`              — write any bytes to remove the watch
//!
//! A `<id>` is unique across wallets in practice because
//! [`bloom_watch::WatchRegistry::allocate_id`] increments globally; the
//! handler resolves an id by scanning every wallet's specs.

use std::sync::Arc;

use async_trait::async_trait;

use bloom_proto::HomeDir;
use bloom_watch::{WatchExecutor, WatchKind, WatchRegistry, WatchSpec};

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

#[derive(Clone)]
pub struct WatchHandler {
    pub registry: Arc<WatchRegistry>,
    pub executor: Arc<WatchExecutor>,
    pub home: HomeDir,
}

impl WatchHandler {
    pub fn new(registry: Arc<WatchRegistry>, executor: Arc<WatchExecutor>, home: HomeDir) -> Self {
        Self {
            registry,
            executor,
            home,
        }
    }

    fn err_be(e: impl std::fmt::Display) -> HandlerError {
        HandlerError::backend(e.to_string())
    }

    fn resolve_id(&self, id: &str) -> Result<WatchSpec, HandlerError> {
        self.registry
            .find_by_id(id)
            .ok_or_else(|| HandlerError::not_found(format!("watch '{}'", id)))
    }

    fn watch_dir(&self, spec: &WatchSpec) -> std::path::PathBuf {
        WatchExecutor::watch_dir_for_spec(&self.home, spec)
    }

    /// True iff `name` looks like `history.jsonl` or `history.jsonl.<u32>`.
    fn is_history_segment(name: &str) -> bool {
        if name == "history.jsonl" {
            return true;
        }
        if let Some(n) = name.strip_prefix("history.jsonl.") {
            return n.parse::<u32>().is_ok();
        }
        false
    }

    fn list_history_segments(&self, spec: &WatchSpec) -> Vec<String> {
        let dir = self.watch_dir(spec);
        let mut out: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for r in rd.flatten() {
                if let Some(n) = r.file_name().to_str()
                    && Self::is_history_segment(n)
                {
                    out.push(n.to_string());
                }
            }
        }
        out.sort();
        out
    }
}

#[async_trait]
impl Handler for WatchHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let r = self.lookup_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "watch.lookup_err");
        }
        r
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let r = self.read_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "watch.read_err");
        }
        r
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let r = self.write_inner(path, data).await;
        if let Err(e) = &r {
            tracing::debug!(
                path = %path.to_string_path(),
                bytes = data.len(),
                error = %e,
                "watch.write_err"
            );
        }
        r
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let r = self.list_inner(path).await;
        if let Err(e) = &r {
            tracing::debug!(path = %path.to_string_path(), error = %e, "watch.list_err");
        }
        r
    }
}

impl WatchHandler {
    async fn lookup_inner(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => Ok(Entry::dir("")),
            1 => match segs[0].as_str() {
                "new" => Ok(Entry::writable_file("new")),
                id => {
                    let _ = self.resolve_id(id)?;
                    Ok(Entry::dir(id))
                }
            },
            2 => {
                let _ = self.resolve_id(&segs[0])?;
                match segs[1].as_str() {
                    "spec.toml" => Ok(Entry::file("spec.toml")),
                    "live" => Ok(Entry::file("live")),
                    "delete" => Ok(Entry::writable_file("delete")),
                    n if Self::is_history_segment(n) => Ok(Entry::file(n)),
                    _ => Err(HandlerError::not_found(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::not_found(path.to_string_path())),
        }
    }

    async fn read_inner(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = path.segments();
        if segs.len() == 1 && segs[0] == "new" {
            return Ok(b"# write a TOML watch spec to subscribe\n# examples (one of the kinds):\n#   printf 'kind = \"head\"\\nchain = \"anvil\"\\n' > /bloom/watch/new\n#   printf 'kind = \"addr\"\\nchain = \"anvil\"\\naddress = \"0x...\"\\n' > /bloom/watch/new\n#   printf 'kind = \"log\"\\nchain = \"anvil\"\\naddress = \"0x...\"\\ntopics = []\\n' > /bloom/watch/new\n# optional: id = \"...\", wallet = \"...\", note = \"...\"\n".to_vec());
        }
        match segs.len() {
            2 => {
                let spec = self.resolve_id(&segs[0])?;
                match segs[1].as_str() {
                    "spec.toml" => {
                        let body = toml::to_string_pretty(&spec).map_err(Self::err_be)?;
                        Ok(body.into_bytes())
                    }
                    "live" => {
                        let p = WatchExecutor::live_path_for_spec(&self.home, &spec);
                        match std::fs::read(&p) {
                            Ok(b) => Ok(b),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                            Err(e) => Err(HandlerError::Io(e)),
                        }
                    }
                    n if Self::is_history_segment(n) => {
                        let p = self.watch_dir(&spec).join(n);
                        match std::fs::read(&p) {
                            Ok(b) => Ok(b),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                            Err(e) => Err(HandlerError::Io(e)),
                        }
                    }
                    _ => Err(HandlerError::NotAFile(path.to_string_path())),
                }
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write_inner(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = path.segments();
        match segs {
            [seg] if seg == "new" => {
                let body = std::str::from_utf8(data)
                    .map_err(|_| HandlerError::invalid("non-utf8 spec"))?;
                let parsed: NewSpec = toml::from_str(body).map_err(Self::err_be)?;
                let id = match parsed.id.clone() {
                    Some(s) if !s.is_empty() => s,
                    _ => self.registry.allocate_id(),
                };
                let wallet = parsed
                    .wallet
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "default".to_string());
                let note = parsed.note.clone();
                let kind = parsed.to_kind()?;
                let spec = WatchSpec {
                    id,
                    wallet,
                    created_ms: now_ms(),
                    kind,
                    note,
                };
                self.registry.add(spec).map_err(Self::err_be)?;
                Ok(())
            }
            [id, fname] if fname == "delete" => {
                let spec = self.resolve_id(id)?;
                self.registry
                    .remove(&spec.wallet, &spec.id)
                    .map_err(Self::err_be)?;
                let dir = self.watch_dir(&spec);
                if dir.exists() {
                    let _ = std::fs::remove_dir_all(&dir);
                }
                Ok(())
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list_inner(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = path.segments();
        match segs.len() {
            0 => {
                let mut out = vec![Entry::writable_file("new")];
                for s in self.registry.list_all() {
                    out.push(Entry::dir(&s.id));
                }
                Ok(out)
            }
            1 => {
                let spec = self.resolve_id(&segs[0])?;
                let mut out = vec![
                    Entry::file("spec.toml"),
                    Entry::file("live"),
                    Entry::writable_file("delete"),
                ];
                for n in self.list_history_segments(&spec) {
                    out.push(Entry::file(&n));
                }
                Ok(out)
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

fn now_ms() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Inbound TOML schema for `watch/new`. Mirrors [`WatchKind`] with a
/// flat shape so users can write it ergonomically:
///
/// ```toml
/// kind = "balance"
/// wallet = "alice"
/// address = "0x..."
/// threshold_wei = "0"
/// comparator = ">"
/// ```
#[derive(serde::Deserialize)]
struct NewSpec {
    kind: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    wallet: Option<String>,
    // balance
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    threshold_wei: Option<String>,
    #[serde(default)]
    comparator: Option<String>,
    // block / gas / event
    #[serde(default)]
    chain: Option<String>,
    #[serde(default)]
    threshold_gwei: Option<f64>,
    #[serde(default)]
    contract: Option<String>,
    #[serde(default)]
    topic0: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

impl NewSpec {
    fn to_kind(&self) -> Result<WatchKind, HandlerError> {
        match self.kind.as_str() {
            "balance" => Ok(WatchKind::Balance {
                address: self
                    .address
                    .clone()
                    .ok_or_else(|| HandlerError::invalid("balance: missing address"))?,
                threshold_wei: self
                    .threshold_wei
                    .clone()
                    .unwrap_or_else(|| "0".to_string()),
                comparator: self.comparator.clone().unwrap_or_else(|| ">".to_string()),
            }),
            "block" => Ok(WatchKind::Block {
                chain: self
                    .chain
                    .clone()
                    .ok_or_else(|| HandlerError::invalid("block: missing chain"))?,
            }),
            "gas_price" => Ok(WatchKind::GasPrice {
                chain: self
                    .chain
                    .clone()
                    .ok_or_else(|| HandlerError::invalid("gas_price: missing chain"))?,
                threshold_gwei: self.threshold_gwei.unwrap_or(0.0),
            }),
            "event" => Ok(WatchKind::Event {
                chain: self
                    .chain
                    .clone()
                    .ok_or_else(|| HandlerError::invalid("event: missing chain"))?,
                contract: self
                    .contract
                    .clone()
                    .ok_or_else(|| HandlerError::invalid("event: missing contract"))?,
                topic0: self
                    .topic0
                    .clone()
                    .ok_or_else(|| HandlerError::invalid("event: missing topic0"))?,
            }),
            other => Err(HandlerError::invalid(format!(
                "unknown watch kind: {other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_evm::ChainRegistry;
    use tempfile::tempdir;

    fn build_handler() -> (WatchHandler, tempfile::TempDir) {
        let tmp = tempdir().unwrap();
        let home = HomeDir::at(tmp.path());
        home.ensure().unwrap();
        let registry = Arc::new(WatchRegistry::new(home.watch_dir()).unwrap());
        let exec = Arc::new(WatchExecutor::new(
            ChainRegistry::default(),
            registry.clone(),
            home.clone(),
        ));
        (WatchHandler::new(registry, exec, home), tmp)
    }

    #[tokio::test]
    async fn list_root_includes_new() {
        let (h, _t) = build_handler();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "new");
    }

    #[tokio::test]
    async fn read_new_returns_help_text() {
        // Same motivation as simulate/new: a write-only path that errors
        // on read causes WARN spam at every getattr. Returning help
        // text gives the kernel a stable size to cache.
        let (h, _t) = build_handler();
        let bytes = h.read(&VfsPath::parse("new").unwrap()).await.unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("watch"), "help text should mention watch: {s}");
        assert!(s.contains("kind"), "help text should mention kind: {s}");
    }

    #[tokio::test]
    async fn write_new_then_list_shows_id() {
        let (h, _t) = build_handler();
        let toml = r#"
kind = "gas_price"
wallet = "alice"
chain = "anvil"
threshold_gwei = 25.0
"#;
        h.write(&VfsPath::parse("new").unwrap(), toml.as_bytes())
            .await
            .unwrap();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"new"));
        // Some allocated id w-NNNN should appear.
        assert!(names.iter().any(|n| n.starts_with("w-")));
    }

    #[tokio::test]
    async fn read_spec_toml_round_trips() {
        let (h, _t) = build_handler();
        let toml = r#"
kind = "block"
wallet = "bob"
chain = "anvil"
"#;
        h.write(&VfsPath::parse("new").unwrap(), toml.as_bytes())
            .await
            .unwrap();
        let id = h.registry.list_all().into_iter().next().unwrap().id.clone();
        let body = h
            .read(&VfsPath::parse(&format!("{id}/spec.toml")).unwrap())
            .await
            .unwrap();
        let s = String::from_utf8(body).unwrap();
        assert!(s.contains("wallet = \"bob\""));
        assert!(s.contains("kind = \"block\""));
    }

    #[tokio::test]
    async fn read_live_for_unknown_id_404s() {
        let (h, _t) = build_handler();
        let res = h
            .read(&VfsPath::parse("does-not-exist/live").unwrap())
            .await;
        assert!(matches!(res, Err(HandlerError::NotFound(_))));
    }

    #[tokio::test]
    async fn delete_removes_spec_and_dir() {
        let (h, _t) = build_handler();
        let toml = "kind = \"block\"\nwallet = \"alice\"\nchain = \"anvil\"\n";
        h.write(&VfsPath::parse("new").unwrap(), toml.as_bytes())
            .await
            .unwrap();
        let spec = h.registry.list_all().into_iter().next().unwrap();
        // Touch the live file so a per-watch dir exists.
        let dir = WatchExecutor::watch_dir_for_spec(&h.home, &spec);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("live"), b"hi\n").unwrap();

        h.write(
            &VfsPath::parse(&format!("{}/delete", spec.id)).unwrap(),
            b"yes",
        )
        .await
        .unwrap();
        assert!(h.registry.list_all().is_empty());
        assert!(!dir.exists());
    }

    #[test]
    fn is_history_segment_recognises_numbered_rotations() {
        assert!(WatchHandler::is_history_segment("history.jsonl"));
        assert!(WatchHandler::is_history_segment("history.jsonl.1"));
        assert!(WatchHandler::is_history_segment("history.jsonl.42"));
        assert!(!WatchHandler::is_history_segment("history.jsonl.x"));
        assert!(!WatchHandler::is_history_segment("live"));
        assert!(!WatchHandler::is_history_segment("history.json"));
    }
}
