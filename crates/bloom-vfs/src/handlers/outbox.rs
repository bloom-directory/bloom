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
use bloom_auth_api::petal_identity::label_petal_digest;

use crate::handler::{
    Entry, EntryKind, Handler, HandlerError, entry_for_fs_path, entry_from_fs_dir_entry,
};
use crate::path::VfsPath;

const STATES: &[&str] = &["pending", "sent", "failed"];
const ACTION_FILES: &[&str] = &[
    "intent.json",
    "intent_hash",
    "plan.md",
    "policy_check.json",
    "challenge.json",
    "approval_challenge.json",
    "approval.json",
    "status.json",
    "result.json",
];

/// Filesystem store for central actions.
#[derive(Clone)]
pub struct CentralOutbox {
    root: PathBuf,
}

/// Petal identity attached to a staged central action.
///
/// Forwarded by callers (EVM/Hyperliquid/Polymarket/Wallets/Requests) once
/// WS-4..9 wires them up. Today, every first-party `petal_digest` is a
/// placeholder; once reproducible build/source digests land, the same field
/// can carry a real `build`-labelled digest without changing this struct.
#[derive(Debug, Clone, Default)]
pub struct StagedPetalIdentity {
    pub petal_id: String,
    pub petal_digest: String,
    pub petal_version: String,
}

impl StagedPetalIdentity {
    /// True iff the identity carries a non-empty `petal_id`. The
    /// fail-closed behaviour in `stage_with_identity` keys off this check.
    pub fn is_present(&self) -> bool {
        !self.petal_id.is_empty()
    }
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
    ///
    /// Backwards-compatible thin wrapper around [`CentralOutbox::stage_with_identity`]
    /// that stages the action with an empty `StagedPetalIdentity`. The resulting
    /// `status.json` carries `"petal_digest_kind": null` and omits the digest
    /// and version fields — see the fail-closed note on `stage_with_identity`.
    pub fn stage(
        &self,
        action_id: &str,
        intent_json: &[u8],
        intent_hash: &str,
        plan_md: &str,
        policy_check_json: &[u8],
    ) -> std::io::Result<()> {
        self.stage_with_identity(
            action_id,
            intent_json,
            intent_hash,
            plan_md,
            policy_check_json,
            &StagedPetalIdentity::default(),
        )
    }

    /// Create a new pending action with the provided projection files and
    /// Petal identity. The `status.json` written alongside the action
    /// includes Petal identity fields so operators can correlate the staged
    /// action with the Petal that produced it.
    ///
    /// `petal_digest_kind` is derived from `petal_digest` via
    /// [`bloom_auth_api::petal_identity::label_petal_digest`] and is either
    /// `"placeholder"` (current first-party reality) or `"build"` (planned
    /// for reproducible-build/source digests). Spec §11.10 requires that
    /// placeholder digests are surfaced as such so they are not mistaken
    /// for code attestation.
    ///
    /// **Fail-closed when identity is empty.** If `identity.petal_id` is
    /// empty (the default `StagedPetalIdentity`), the resulting
    /// `status.json` is written with:
    /// - `"petal_id": ""`
    /// - `"petal_digest_kind": null`
    /// - `petal_digest` and `petal_version` are OMITTED (not faked).
    ///
    /// Existing WS-4..9 callers will start passing real identities; until
    /// then, every staged action records `null` kind and no digest/version.
    pub fn stage_with_identity(
        &self,
        action_id: &str,
        intent_json: &[u8],
        intent_hash: &str,
        plan_md: &str,
        policy_check_json: &[u8],
        identity: &StagedPetalIdentity,
    ) -> std::io::Result<()> {
        let dir = self.action_dir("pending", action_id);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("intent.json"), intent_json)?;
        std::fs::write(dir.join("intent_hash"), format!("{intent_hash}\n"))?;
        std::fs::write(dir.join("plan.md"), plan_md)?;
        std::fs::write(dir.join("policy_check.json"), policy_check_json)?;

        let status_json = if identity.is_present() {
            serde_json::json!({
                "action_id": action_id,
                "state": "pending",
                "petal_id": identity.petal_id,
                "petal_digest": identity.petal_digest,
                "petal_digest_kind": label_petal_digest(&identity.petal_digest),
                "petal_version": identity.petal_version,
            })
        } else {
            // Fail-closed: empty petal_id means no Petal identity was
            // supplied. Record `petal_id: ""` and `petal_digest_kind: null`,
            // and OMIT `petal_digest` / `petal_version` so the record does
            // not pretend to know which build or version of a Petal
            // produced the action.
            serde_json::json!({
                "action_id": action_id,
                "state": "pending",
                "petal_id": "",
                "petal_digest_kind": serde_json::Value::Null,
            })
        };

        std::fs::write(
            dir.join("status.json"),
            serde_json::to_vec_pretty(&status_json).unwrap_or_default(),
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
        std::fs::rename(&from_dir, &to_dir)?;
        self.write_status_state(action_id, to)?;
        Ok(())
    }

    fn write_status_state(&self, action_id: &str, state: &str) -> std::io::Result<()> {
        let path = self.action_dir(state, action_id).join("status.json");
        let mut status = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .unwrap_or_else(|_| serde_json::json!({})),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
            Err(e) => return Err(e),
        };
        if !status.is_object() {
            status = serde_json::json!({});
        }
        let obj = status.as_object_mut().expect("status is object");
        obj.insert("action_id".to_string(), serde_json::json!(action_id));
        obj.insert("state".to_string(), serde_json::json!(state));
        std::fs::write(path, serde_json::to_vec_pretty(&status).unwrap_or_default())
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

    /// Write a runtime-generated artifact into an existing central action
    /// directory. This is intentionally allowlisted so callers cannot use the
    /// projection as an arbitrary file writer.
    pub fn write_action_file(
        &self,
        action_id: &str,
        state: &str,
        file: &str,
        data: &[u8],
    ) -> std::io::Result<()> {
        validate_action_id(action_id)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        if !matches!(
            file,
            "approval_challenge.json" | "approval.json" | "result.json" | "status.json"
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("runtime artifact '{file}' is not writable"),
            ));
        }
        let dir = self.action_dir(state, action_id);
        if !dir.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("action {action_id} not found in {state}"),
            ));
        }
        std::fs::write(dir.join(file), data)
    }

    /// Read a runtime-generated artifact from an existing central action
    /// directory. Uses the same allowlist as [`CentralOutbox::write_action_file`].
    pub fn read_action_file(
        &self,
        action_id: &str,
        state: &str,
        file: &str,
    ) -> std::io::Result<Vec<u8>> {
        validate_action_id(action_id)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        if !matches!(
            file,
            "approval_challenge.json" | "approval.json" | "result.json" | "status.json"
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("runtime artifact '{file}' is not readable"),
            ));
        }
        let dir = self.action_dir(state, action_id);
        if !dir.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("action {action_id} not found in {state}"),
            ));
        }
        std::fs::read(dir.join(file))
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

    fn latest_pending_action_id(&self) -> Result<Option<String>, HandlerError> {
        let pending = self.outbox.state_dir("pending");
        if !pending.exists() {
            return Ok(None);
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
        entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        Ok(entries
            .first()
            .map(|(_, name)| name.to_string_lossy().into_owned()))
    }

    fn latest_target(&self) -> Result<Option<String>, HandlerError> {
        Ok(self
            .latest_pending_action_id()?
            .map(|id| format!("pending/{id}")))
    }

    fn file_entry_for_path(
        &self,
        path: impl AsRef<std::path::Path>,
        name: &str,
        writable: bool,
    ) -> Result<Entry, HandlerError> {
        let mut entry = entry_for_fs_path(path, name, EntryKind::File)?;
        if writable {
            entry.mode = 0o644;
        }
        Ok(entry)
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
                let target = self
                    .latest_target()?
                    .ok_or_else(|| HandlerError::NotFound("outbox/latest".into()))?;
                Ok(Entry::symlink("latest", &target))
            }
            ["latest", file] => {
                let action_id = self
                    .latest_pending_action_id()?
                    .ok_or_else(|| HandlerError::NotFound("outbox/latest".into()))?;
                if !ACTION_FILES.contains(file) {
                    return Err(HandlerError::NotFound(format!("/outbox/latest/{file}")));
                }
                let fpath = self.outbox.action_dir("pending", &action_id).join(file);
                if !fpath.exists() {
                    return Err(HandlerError::NotFound(format!("/outbox/latest/{file}")));
                }
                self.file_entry_for_path(fpath, file, *file == "approval.json")
            }
            [state, action_id] if STATES.contains(state) => {
                validate_action_id(action_id)?;
                let dir = self.outbox.action_dir(state, action_id);
                if !dir.exists() {
                    return Err(HandlerError::NotFound(format!(
                        "/outbox/{state}/{action_id}"
                    )));
                }
                entry_for_fs_path(dir, action_id, EntryKind::Dir)
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
                self.file_entry_for_path(
                    fpath,
                    file,
                    *file == "approval.json" && *state == "pending",
                )
            }
            _ => Err(HandlerError::NotFound(path.to_string_path())),
        }
    }

    async fn read(&self, path: &VfsPath) -> Result<Vec<u8>, HandlerError> {
        let segs = match_segs(path);
        match segs.as_slice() {
            ["latest"] => {
                let target = self
                    .latest_target()?
                    .ok_or_else(|| HandlerError::NotFound("outbox/latest".into()))?;
                Ok(format!("{target}\n").into_bytes())
            }
            ["latest", file] => {
                let action_id = self
                    .latest_pending_action_id()?
                    .ok_or_else(|| HandlerError::NotFound("outbox/latest".into()))?;
                if !ACTION_FILES.contains(file) {
                    return Err(HandlerError::NotFound(format!("/outbox/latest/{file}")));
                }
                let fpath = self.outbox.action_dir("pending", &action_id).join(file);
                std::fs::read(&fpath).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        HandlerError::NotFound(fpath.to_string_lossy().to_string())
                    } else {
                        HandlerError::backend(e.to_string())
                    }
                })
            }
            [state, action_id, file] if STATES.contains(state) => {
                validate_action_id(action_id)?;
                if !ACTION_FILES.contains(file) {
                    return Err(HandlerError::NotFound(format!(
                        "/outbox/{state}/{action_id}/{file}"
                    )));
                }
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
            ["latest", "approval.json"] => {
                let action_id = self
                    .latest_pending_action_id()?
                    .ok_or_else(|| HandlerError::NotFound("outbox/latest".into()))?;
                let dir = self.outbox.action_dir("pending", &action_id);
                if !dir.exists() {
                    return Err(HandlerError::NotFound(format!(
                        "/outbox/pending/{action_id}"
                    )));
                }
                std::fs::write(dir.join("approval.json"), data)
                    .map_err(|e| HandlerError::backend(e.to_string()))?;
                Ok(())
            }
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
            [] => {
                let mut entries: Vec<Entry> = STATES.iter().map(|s| Entry::dir(s)).collect();
                if let Some(target) = self.latest_target()? {
                    entries.push(Entry::symlink("latest", &target));
                }
                Ok(entries)
            }
            [state] if STATES.contains(state) => {
                let dir = self.outbox.state_dir(state);
                if !dir.exists() {
                    return Ok(Vec::new());
                }
                let mut entries: Vec<Entry> = std::fs::read_dir(&dir)
                    .map_err(|e| HandlerError::backend(e.to_string()))?
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        entry_from_fs_dir_entry(&e, &name, EntryKind::Dir).ok()
                    })
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
                let mut entries: Vec<Entry> = std::fs::read_dir(&dir)
                    .map_err(|e| HandlerError::backend(e.to_string()))?
                    .filter_map(|e| e.ok())
                    .map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        let metadata = e.metadata().ok();
                        if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                            let entry = if state == &"pending" && name == "approval.json" {
                                Entry::writable_file(&name)
                            } else {
                                Entry::file(&name)
                            };
                            metadata
                                .as_ref()
                                .map_or(entry.clone(), |m| entry.with_fs_metadata(m))
                        } else {
                            let entry = Entry::dir(&name);
                            metadata
                                .as_ref()
                                .map_or(entry.clone(), |m| entry.with_fs_metadata(m))
                        }
                    })
                    .collect();
                entries.sort_by(|a, b| a.name.cmp(&b.name));
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
    async fn lookup_root_lists_states_without_latest_when_empty() {
        let h = handler();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"pending"));
        assert!(names.contains(&"sent"));
        assert!(names.contains(&"failed"));
        assert!(!names.contains(&"latest"));
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
    async fn entries_surface_action_artifact_modified_times() {
        let h = handler();
        h.outbox
            .stage("act-time", b"{}", "hash", "plan", b"[]")
            .unwrap();
        let action_dir = h.outbox.action_dir("pending", "act-time");
        let dir_modified = std::fs::metadata(&action_dir).unwrap().modified().unwrap();
        let intent_path = action_dir.join("intent.json");
        let intent_modified = std::fs::metadata(&intent_path).unwrap().modified().unwrap();

        let action_entry = h
            .lookup(&VfsPath::parse("pending/act-time").unwrap())
            .await
            .unwrap();
        assert_eq!(action_entry.modified, Some(dir_modified));

        let file_entry = h
            .lookup(&VfsPath::parse("pending/act-time/intent.json").unwrap())
            .await
            .unwrap();
        assert_eq!(file_entry.modified, Some(intent_modified));

        let listed_action = h
            .list(&VfsPath::parse("pending").unwrap())
            .await
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == "act-time")
            .expect("action listed");
        assert_eq!(listed_action.modified, Some(dir_modified));
    }

    #[tokio::test]
    async fn read_rejects_unadvertised_action_files() {
        let h = handler();
        h.outbox
            .stage("act-extra", b"{}", "hash", "plan", b"[]")
            .unwrap();
        let dir = h.outbox.action_dir("pending", "act-extra");
        std::fs::write(dir.join("debug-secret.txt"), b"hidden").unwrap();

        let p = VfsPath::parse("pending/act-extra/debug-secret.txt").unwrap();
        let err = h.read(&p).await.unwrap_err();
        assert!(matches!(err, HandlerError::NotFound(_)), "{err}");
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
    async fn approval_challenge_is_visible_and_read_only() {
        let h = handler();
        h.outbox
            .stage("act-approval", b"{}", "hash", "plan", b"[]")
            .unwrap();
        let dir = h.outbox.action_dir("pending", "act-approval");
        std::fs::write(dir.join("approval_challenge.json"), b"{\"challenge\":true}").unwrap();
        std::fs::write(dir.join("approval.json"), b"{}").unwrap();

        let entries = h
            .list(&VfsPath::parse("pending/act-approval").unwrap())
            .await
            .unwrap();
        let challenge = entries
            .iter()
            .find(|entry| entry.name == "approval_challenge.json")
            .expect("approval_challenge.json is listed");
        assert_eq!(challenge.mode, 0o444);

        let approval = entries
            .iter()
            .find(|entry| entry.name == "approval.json")
            .expect("approval.json is listed");
        assert_eq!(approval.mode, 0o644);

        let p = VfsPath::parse("pending/act-approval/approval_challenge.json").unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.mode, 0o444);
        assert!(h.write(&p, b"{}").await.is_err());
    }

    #[test]
    fn write_action_file_allows_approval_json_and_rejects_arbitrary() {
        let h = handler();
        h.outbox
            .stage("act-central-approval", b"{}", "hash", "plan", b"[]")
            .unwrap();

        // The daemon's Mode 3 ceremony mirrors approval.json into the central
        // projection through this path — it must be allowlisted (regression: it
        // was silently rejected, so approval.json never reached the central dir).
        h.outbox
            .write_action_file("act-central-approval", "pending", "approval.json", b"{}")
            .expect("approval.json must be a runtime-writable central artifact");
        let dir = h.outbox.action_dir("pending", "act-central-approval");
        assert!(dir.join("approval.json").exists());

        // The allowlist still fails closed for anything else.
        let err = h
            .outbox
            .write_action_file("act-central-approval", "pending", "secrets.json", b"{}")
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn approval_json_is_writable_only_while_pending() {
        let h = handler();
        h.outbox
            .stage("act-sent", b"{}", "hash", "plan", b"[]")
            .unwrap();
        let pending_dir = h.outbox.action_dir("pending", "act-sent");
        std::fs::write(pending_dir.join("approval.json"), b"{}").unwrap();
        h.outbox.transition("act-sent", "pending", "sent").unwrap();

        let p = VfsPath::parse("sent/act-sent/approval.json").unwrap();
        let entry = h.lookup(&p).await.unwrap();
        assert_eq!(entry.mode, 0o444);
        assert!(h.write(&p, b"{}").await.is_err());
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
    async fn transition_updates_canonical_status_state() {
        let h = handler();
        h.outbox
            .stage("act-status", b"{}", "hash", "plan", b"[]")
            .unwrap();

        h.outbox
            .transition("act-status", "pending", "sent")
            .unwrap();

        let status_path = VfsPath::parse("sent/act-status/status.json").unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&h.read(&status_path).await.unwrap())
                .expect("status.json parses");
        assert_eq!(status["action_id"], "act-status");
        assert_eq!(status["state"], "sent");
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

        let entries = h.list(&VfsPath::root()).await.unwrap();
        let latest = entries
            .iter()
            .find(|entry| entry.name == "latest")
            .expect("latest is listed when there is a pending action");
        assert_eq!(latest.link_target.as_deref(), Some("pending/act-new"));

        let entry = h.lookup(&VfsPath::parse("latest").unwrap()).await.unwrap();
        assert_eq!(entry.name, "latest");
        assert_eq!(entry.link_target.as_deref(), Some("pending/act-new"));

        let plan = h
            .read(&VfsPath::parse("latest/plan.md").unwrap())
            .await
            .unwrap();
        assert_eq!(plan, b"p2");
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
            entry.link_target.as_deref(),
            Some("pending/act-new"),
            "latest must reflect staging order, not artefact-write order"
        );
    }

    #[tokio::test]
    async fn latest_not_found_when_empty() {
        let h = handler();
        let entries = h.list(&VfsPath::root()).await.unwrap();
        assert!(
            entries.iter().all(|entry| entry.name != "latest"),
            "empty outbox must not advertise a latest entry that lookup cannot resolve"
        );

        let result = h.lookup(&VfsPath::parse("latest").unwrap()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn latest_deterministic_on_same_mtime() {
        let h = handler();
        h.outbox
            .stage("act-zeta", b"{}", "h1", "p1", b"[]")
            .unwrap();
        h.outbox
            .stage("act-alpha", b"{}", "h2", "p2", b"[]")
            .unwrap();

        // Force identical mtimes so the secondary sort key (lexicographic
        // ascending action_id) is the sole discriminator.
        let fixed = std::time::SystemTime::UNIX_EPOCH;
        for id in ["act-zeta", "act-alpha"] {
            let p = h.outbox.action_dir("pending", id).join("intent.json");
            let times = std::fs::FileTimes::new().set_modified(fixed);
            if let Ok(f) = std::fs::File::open(&p) {
                let _ = f.set_times(times);
            }
        }

        let entry = h.lookup(&VfsPath::parse("latest").unwrap()).await.unwrap();
        assert_eq!(
            entry.link_target.as_deref(),
            Some("pending/act-alpha"),
            "on identical mtime, tie-breaker is lexicographic ascending action_id"
        );
    }

    #[tokio::test]
    async fn latest_excludes_sent_and_failed() {
        let h = handler();
        h.outbox.stage("act-a", b"{}", "h1", "p1", b"[]").unwrap();
        h.outbox.transition("act-a", "pending", "sent").unwrap();

        let result = h.lookup(&VfsPath::parse("latest").unwrap()).await;
        assert!(
            result.is_err(),
            "latest must not return actions that have transitioned out of pending"
        );
        let entries = h.list(&VfsPath::root()).await.unwrap();
        assert!(
            entries.iter().all(|entry| entry.name != "latest"),
            "latest must not be listed after the only pending action leaves pending"
        );
    }

    fn read_status(outbox: &CentralOutbox, action_id: &str) -> serde_json::Value {
        let path = outbox.action_dir("pending", action_id).join("status.json");
        let bytes = std::fs::read(&path).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn status_json_labels_placeholder_petal_digest() {
        let h = handler();
        let identity = StagedPetalIdentity {
            petal_id: "evm-wallet".into(),
            petal_digest: "first-party-placeholder:evm-wallet:v0".into(),
            petal_version: "v0".into(),
        };
        h.outbox
            .stage_with_identity("act-pp", b"{}", "h1", "p1", b"[]", &identity)
            .unwrap();

        let status = read_status(&h.outbox, "act-pp");
        assert_eq!(status["action_id"], "act-pp");
        assert_eq!(status["state"], "pending");
        assert_eq!(status["petal_id"], "evm-wallet");
        assert_eq!(
            status["petal_digest"],
            "first-party-placeholder:evm-wallet:v0"
        );
        assert_eq!(status["petal_digest_kind"], "placeholder");
        assert_eq!(status["petal_version"], "v0");
    }

    #[tokio::test]
    async fn status_json_labels_build_petal_digest() {
        let h = handler();
        let identity = StagedPetalIdentity {
            petal_id: "evm-wallet".into(),
            petal_digest: "sha256:abcdef0123456789".into(),
            petal_version: "v1".into(),
        };
        h.outbox
            .stage_with_identity("act-build", b"{}", "h1", "p1", b"[]", &identity)
            .unwrap();

        let status = read_status(&h.outbox, "act-build");
        assert_eq!(status["action_id"], "act-build");
        assert_eq!(status["state"], "pending");
        assert_eq!(status["petal_id"], "evm-wallet");
        assert_eq!(status["petal_digest"], "sha256:abcdef0123456789");
        assert_eq!(status["petal_digest_kind"], "build");
        assert_eq!(status["petal_version"], "v1");
    }

    #[tokio::test]
    async fn stage_with_empty_identity_writes_null_kind() {
        let h = handler();
        // Existing `stage(...)` path with default identity.
        h.outbox
            .stage("act-empty", b"{}", "h1", "p1", b"[]")
            .unwrap();
        let status = read_status(&h.outbox, "act-empty");
        assert_eq!(status["action_id"], "act-empty");
        assert_eq!(status["state"], "pending");
        assert_eq!(status["petal_id"], "");
        assert!(status["petal_digest_kind"].is_null());
        // The digest and version keys are omitted in the fail-closed branch.
        assert!(
            status.get("petal_digest").is_none(),
            "petal_digest must be omitted when petal_id is empty: {status}"
        );
        assert!(
            status.get("petal_version").is_none(),
            "petal_version must be omitted when petal_id is empty: {status}"
        );

        // Also exercise the explicit `stage_with_identity` with default.
        let id = StagedPetalIdentity::default();
        assert!(!id.is_present());
        h.outbox
            .stage_with_identity("act-empty-2", b"{}", "h2", "p2", b"[]", &id)
            .unwrap();
        let status2 = read_status(&h.outbox, "act-empty-2");
        assert_eq!(status2["petal_id"], "");
        assert!(status2["petal_digest_kind"].is_null());
        assert!(status2.get("petal_digest").is_none());
        assert!(status2.get("petal_version").is_none());
    }
}
