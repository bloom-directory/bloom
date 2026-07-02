//! Central Action Outbox handler.
//!
//! Exposes the spec's `/outbox/{pending,sent,failed}/<action_id>/` VFS tree.
//! Every user-verified value movement or authority change has a corresponding
//! action here. Venue directories (`/requests`, `/wallets`, etc.) project onto
//! these central actions.
//!
//! File layout per action (spec §7.1):
//! ```text
//! intent.json, intent_hash, plan.md, policy_check.json,
//! challenge.json, approval.json, status.json, result.json
//! ```

use std::path::PathBuf;

use async_trait::async_trait;

use crate::handler::{Entry, Handler, HandlerError};
use crate::path::VfsPath;

const STATES: &[&str] = &["pending", "sent", "failed"];
const ACTION_FILES: &[&str] = &[
    "intent.json",
    "intent_hash",
    "plan.md",
    "policy_check.json",
    "challenge.json",
    "approval.json",
    "status.json",
    "result.json",
];

/// Filesystem store for central actions.
#[derive(Clone)]
pub struct CentralOutbox {
    root: PathBuf,
}

impl CentralOutbox {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn state_dir(&self, state: &str) -> PathBuf {
        self.root.join(state)
    }

    fn action_dir(&self, state: &str, action_id: &str) -> PathBuf {
        self.state_dir(state).join(action_id)
    }

    /// Create a new pending action with the provided projection files.
    pub fn stage(
        &self,
        action_id: &str,
        intent_json: &[u8],
        intent_hash: &str,
        plan_md: &str,
        policy_check_json: &[u8],
    ) -> std::io::Result<()> {
        let dir = self.action_dir("pending", action_id);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("intent.json"), intent_json)?;
        std::fs::write(dir.join("intent_hash"), format!("{intent_hash}\n"))?;
        std::fs::write(dir.join("plan.md"), plan_md)?;
        std::fs::write(dir.join("policy_check.json"), policy_check_json)?;
        std::fs::write(
            dir.join("status.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "action_id": action_id,
                "state": "pending",
            }))
            .unwrap_or_default(),
        )?;
        Ok(())
    }

    /// Move an action from one state to another (atomic rename).
    pub fn transition(&self, action_id: &str, from: &str, to: &str) -> std::io::Result<()> {
        let from_dir = self.action_dir(from, action_id);
        let to_dir = self.action_dir(to, action_id);
        if !from_dir.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("action {action_id} not found in {from}"),
            ));
        }
        std::fs::create_dir_all(self.state_dir(to))?;
        std::fs::rename(&from_dir, &to_dir)
    }

    /// Write a result file for an action.
    pub fn write_result(
        &self,
        action_id: &str,
        state: &str,
        result_json: &[u8],
    ) -> std::io::Result<()> {
        let dir = self.action_dir(state, action_id);
        std::fs::write(dir.join("result.json"), result_json)
    }

    /// Find which state an action is in, scanning all states.
    pub fn find_state(&self, action_id: &str) -> Option<&str> {
        STATES
            .iter()
            .find(|s| self.action_dir(s, action_id).exists())
            .copied()
    }
}

pub struct OutboxHandler {
    outbox: CentralOutbox,
}

impl OutboxHandler {
    pub fn new(outbox: CentralOutbox) -> Self {
        Self { outbox }
    }
}

fn validate_action_id(id: &str) -> Result<(), HandlerError> {
    if id.is_empty()
        || id == "latest"
        || id.contains('/')
        || id.contains('\\')
        || id.contains('\0')
        || id.contains("..")
    {
        return Err(HandlerError::invalid(format!("invalid action id: {id}")));
    }
    Ok(())
}

fn match_segs(path: &VfsPath) -> Vec<&str> {
    path.segments().iter().map(|s| s.as_str()).collect()
}

#[async_trait]
impl Handler for OutboxHandler {
    async fn lookup(&self, path: &VfsPath) -> Result<Entry, HandlerError> {
        let segs = match_segs(path);
        match segs.as_slice() {
            [] => Ok(Entry::dir("outbox")),
            [state] if STATES.contains(state) => Ok(Entry::dir(state)),
            ["latest"] => {
                let pending = self.outbox.state_dir("pending");
                if !pending.exists() {
                    return Err(HandlerError::NotFound("outbox/latest".into()));
                }
                let mut entries: Vec<_> = std::fs::read_dir(&pending)
                    .map_err(|e| HandlerError::backend(e.to_string()))?
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let intent = e.path().join("intent.json");
                        std::fs::metadata(&intent)
                            .and_then(|m| m.modified())
                            .ok()
                            .map(|mtime| (mtime, e.file_name()))
                    })
                    .collect();
                entries.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
                let (_, name) = entries
                    .first()
                    .ok_or_else(|| HandlerError::NotFound("no pending actions".into()))?;
                Ok(Entry::dir(name.to_string_lossy().as_ref()))
            }
            [state, action_id] if STATES.contains(state) => {
                validate_action_id(action_id)?;
                let dir = self.outbox.action_dir(state, action_id);
                if !dir.exists() {
                    return Err(HandlerError::NotFound(format!(
                        "/outbox/{state}/{action_id}"
                    )));
                }
                Ok(Entry::dir(action_id))
            }
            [state, action_id, file] if STATES.contains(state) => {
                validate_action_id(action_id)?;
                if !ACTION_FILES.contains(file) {
                    return Err(HandlerError::NotFound(format!(
                        "/outbox/{state}/{action_id}/{file}"
                    )));
                }
                let fpath = self.outbox.action_dir(state, action_id).join(file);
                if !fpath.exists() {
                    return Err(HandlerError::NotFound(format!(
                        "/outbox/{state}/{action_id}/{file}"
                    )));
                }
                Ok(Entry::writable_file(file))
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = match_segs(path);
        match segs.as_slice() {
            [state, action_id, file] if STATES.contains(state) => {
                validate_action_id(action_id)?;
                let fpath = self.outbox.action_dir(state, action_id).join(file);
                std::fs::read(&fpath).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        HandlerError::NotFound(fpath.to_string_lossy().to_string())
                    } else {
                        HandlerError::backend(e.to_string())
                    }
                })
            }
            _ => Err(HandlerError::NotAFile(path.to_string_path())),
        }
    }

    async fn write(&self, path: &VfsPath, data: &[u8]) -> Result<(), HandlerError> {
        let segs = match_segs(path);
        match segs.as_slice() {
            ["pending", action_id, "approval.json"] => {
                validate_action_id(action_id)?;
                let dir = self.outbox.action_dir("pending", action_id);
                if !dir.exists() {
                    return Err(HandlerError::NotFound(format!(
                        "/outbox/pending/{action_id}"
                    )));
                }
                std::fs::write(dir.join("approval.json"), data)
                    .map_err(|e| HandlerError::backend(e.to_string()))?;
                Ok(())
            }
            _ => Err(HandlerError::PermissionDenied),
        }
    }

    async fn list(&self, path: &VfsPath) -> Result<Vec<Entry>, HandlerError> {
        let segs = match_segs(path);
        match segs.as_slice() {
            [] => Ok(STATES
                .iter()
                .map(|s| Entry::dir(s))
                .chain(std::iter::once(Entry::dir("latest")))
                .collect()),
            [state] if STATES.contains(state) => {
                let dir = self.outbox.state_dir(state);
                if !dir.exists() {
                    return Ok(Vec::new());
                }
                let mut entries: Vec<Entry> = std::fs::read_dir(&dir)
                    .map_err(|e| HandlerError::backend(e.to_string()))?
                    .filter_map(|e| e.ok())
                    .map(|e| Entry::dir(e.file_name().to_string_lossy().as_ref()))
                    .collect();
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(entries)
            }
            [state, action_id] if STATES.contains(state) => {
                validate_action_id(action_id)?;
                let dir = self.outbox.action_dir(state, action_id);
                if !dir.exists() {
                    return Err(HandlerError::NotFound(format!(
                        "/outbox/{state}/{action_id}"
                    )));
                }
                let entries: Vec<Entry> = ACTION_FILES
                    .iter()
                    .filter(|f| dir.join(*f).exists())
                    .map(|f| Entry::writable_file(f))
                    .collect();
                Ok(entries)
            }
            _ => Err(HandlerError::NotADir(path.to_string_path())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler() -> OutboxHandler {
        let tmp = tempfile::tempdir().unwrap();
        OutboxHandler::new(CentralOutbox::new(tmp.path().to_path_buf()))
    }

    #[tokio::test]
    async fn lookup_root_lists_states() {
        let h = handler();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"pending"));
        assert!(names.contains(&"sent"));
        assert!(names.contains(&"failed"));
        assert!(names.contains(&"latest"));
    }

    #[tokio::test]
    async fn stage_and_read_action() {
        let h = handler();
        h.outbox
            .stage(
                "act-001",
                br#"{"action":"test"}"#,
                "abc123",
                "Plan text",
                b"[]",
            )
            .unwrap();
        let p = VfsPath::parse("pending/act-001/intent.json").unwrap();
        let data = h.read(&p).await.unwrap();
        assert_eq!(data, br#"{"action":"test"}"#);

        let p = VfsPath::parse("pending/act-001/intent_hash").unwrap();
        let data = h.read(&p).await.unwrap();
        assert!(String::from_utf8_lossy(&data).contains("abc123"));
    }

    #[tokio::test]
    async fn write_approval_only() {
        let h = handler();
        h.outbox
            .stage("act-002", b"{}", "hash", "plan", b"[]")
            .unwrap();

        // approval.json is writable
        let p = VfsPath::parse("pending/act-002/approval.json").unwrap();
        h.write(&p, b"approval data").await.unwrap();
        let data = h.read(&p).await.unwrap();
        assert_eq!(data, b"approval data");

        // intent.json is NOT writable
        let p = VfsPath::parse("pending/act-002/intent.json").unwrap();
        assert!(h.write(&p, b"x").await.is_err());
    }

    #[tokio::test]
    async fn transition_moves_action() {
        let h = handler();
        h.outbox
            .stage("act-003", b"{}", "hash", "plan", b"[]")
            .unwrap();
        assert!(h.outbox.find_state("act-003") == Some("pending"));

        h.outbox.transition("act-003", "pending", "sent").unwrap();
        assert!(h.outbox.find_state("act-003") == Some("sent"));

        let p = VfsPath::parse("sent/act-003/intent.json").unwrap();
        assert!(h.read(&p).await.is_ok());
    }

    #[tokio::test]
    async fn invalid_action_id_rejected() {
        let h = handler();
        let p = VfsPath::parse("pending/../etc/intent.json").unwrap();
        assert!(h.lookup(&p).await.is_err());
    }

    #[tokio::test]
    async fn latest_returns_most_recently_staged() {
        let h = handler();
        h.outbox.stage("act-old", b"{}", "h1", "p1", b"[]").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(15));
        h.outbox.stage("act-new", b"{}", "h2", "p2", b"[]").unwrap();

        let entry = h.lookup(&VfsPath::parse("latest").unwrap()).await.unwrap();
        assert_eq!(entry.name, "act-new");
    }

    #[tokio::test]
    async fn latest_ignores_later_artefact_writes() {
        let h = handler();
        h.outbox.stage("act-old", b"{}", "h1", "p1", b"[]").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(15));
        h.outbox.stage("act-new", b"{}", "h2", "p2", b"[]").unwrap();

        // Simulate writing an approval into the older action — this must
        // NOT bump its position in the latest ordering, because latest
        // tracks staging time, not modification time.
        let approval_dir = h.outbox.action_dir("pending", "act-old");
        std::fs::write(approval_dir.join("approval.json"), b"{}").unwrap();

        let entry = h.lookup(&VfsPath::parse("latest").unwrap()).await.unwrap();
        assert_eq!(
            entry.name, "act-new",
            "latest must reflect staging order, not artefact-write order"
        );
    }

    #[tokio::test]
    async fn latest_not_found_when_empty() {
        let h = handler();
        let result = h.lookup(&VfsPath::parse("latest").unwrap()).await;
        assert!(result.is_err());
    }
}
