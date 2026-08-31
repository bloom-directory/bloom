//! Persistence for staged / sent / failed Solana transfers.
//!
//! Layout (identical to `bloom-tx`'s outbox):
//! `<home>/.solana-outbox/<wallet>/<chain>/{pending,sent,failed}/<id>/...`
//!
//! `intent.json` contains only public transfer facts and is atomically updated
//! when state changes; the mined-outcome sibling is `receipt.json`, written
//! only by the reconciliation loop. Broadcast attempts carry a marker
//! (`broadcast_attempted.json`) plus a `raw_tx` blob whose hash is bound into
//! the marker, so a retry can never substitute different bytes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{
    RECEIPT_FILE, SolanaReceipt, SolanaSentEntry, SolanaTxStatus, StagedSolanaTransfer,
};

#[derive(Debug, Error)]
pub enum OutboxError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("staged transfer '{id}' is in '{actual}', not '{expected}'")]
    StateMismatch {
        id: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("invalid id '{0}'")]
    InvalidId(String),
    #[error("invalid wallet '{0}'")]
    InvalidWallet(String),
    #[error("invalid chain '{0}'")]
    InvalidChain(String),
    #[error("raw transaction bytes do not match the recorded hash")]
    RawTxHashMismatch,
    #[error("outbox target already exists: {0}")]
    TargetExists(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolanaOutboxState {
    Pending,
    Sent,
    Failed,
}

impl SolanaOutboxState {
    pub fn dirname(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Failed => "failed",
        }
    }

    /// Map a status to its on-disk state — the single source of truth the
    /// engine's transition points derive their target state from (see
    /// `SolanaTransferEngine::broadcast`), rather than each call site
    /// hardcoding a state literal that could drift from the `status` field
    /// it's paired with.
    pub fn from_status(s: &SolanaTxStatus) -> Self {
        match s {
            SolanaTxStatus::Pending => Self::Pending,
            SolanaTxStatus::Sent | SolanaTxStatus::Success => Self::Sent,
            SolanaTxStatus::Failed | SolanaTxStatus::Cancelled | SolanaTxStatus::Expired => {
                Self::Failed
            }
        }
    }

    /// Parse an on-disk directory name back into a state (used by the VFS
    /// projection).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "sent" => Some(Self::Sent),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// A located entry: its persisted state, staged record, and directory.
#[derive(Debug, Clone)]
pub struct SolanaOutboxEntry {
    pub state: SolanaOutboxState,
    pub staged: StagedSolanaTransfer,
    pub dir: PathBuf,
}

/// A broadcast attempt's durable marker, mirroring `bloom-tx`'s
/// `BroadcastAttempt` (without a nonce — Solana has none).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolanaBroadcastAttempt {
    pub schema: String,
    pub signature: String,
    pub raw_tx_blake3: String,
    pub raw_tx_path: String,
    pub fee_payer: String,
    pub destination: String,
    pub lamports: u64,
    pub blockhash: String,
    pub created_ms: u128,
}

pub const BROADCAST_ATTEMPT_FILE: &str = "broadcast_attempted.json";
pub const BROADCAST_RAW_TX: &str = "raw_tx";
pub const APPROVAL_CHALLENGE_FILE: &str = "approval_challenge.json";
const PRIVATE_SIGNATURE_FILE: &str = ".signature";
const PRIVATE_APPROVAL_FILE: &str = "approval.json";
const BROADCAST_SCHEMA: &str = "bloom.solana-broadcast-attempt/1";

#[derive(Clone)]
pub struct SolanaOutbox {
    inner: Arc<OutboxInner>,
}

struct OutboxInner {
    root: PathBuf,
}

impl SolanaOutbox {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, OutboxError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self {
            inner: Arc::new(OutboxInner { root }),
        })
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    fn validate_segment(seg: &str) -> Result<(), OutboxError> {
        if seg.is_empty() || seg.contains('/') || seg.contains('\\') || seg == "." || seg == ".." {
            return Err(OutboxError::InvalidWallet(seg.into()));
        }
        Ok(())
    }

    pub fn wallet_chain_dir(&self, wallet: &str, chain: &str) -> Result<PathBuf, OutboxError> {
        Self::validate_segment(wallet).map_err(|_| OutboxError::InvalidWallet(wallet.into()))?;
        Self::validate_segment(chain).map_err(|_| OutboxError::InvalidChain(chain.into()))?;
        Ok(self.inner.root.join(wallet).join(chain))
    }

    fn state_dir(
        &self,
        wallet: &str,
        chain: &str,
        state: SolanaOutboxState,
    ) -> Result<PathBuf, OutboxError> {
        Ok(self.wallet_chain_dir(wallet, chain)?.join(state.dirname()))
    }

    /// Allocate a collision-resistant id. It carries no process-local counter,
    /// so a daemon restart cannot reuse an existing outbox identity.
    pub fn allocate_id(&self) -> String {
        let mut bytes = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        format!("sol-{}", hex::encode(bytes))
    }

    /// Persist a staged transfer in `pending/<id>/` along with its plan file.
    /// `intent.json` excludes the private pre-broadcast signature;
    /// `plan.md` is caller-owned.
    pub fn write_pending(
        &self,
        staged: &StagedSolanaTransfer,
        plan_md: &str,
    ) -> Result<PathBuf, OutboxError> {
        Self::validate_segment(&staged.id)
            .map_err(|_| OutboxError::InvalidId(staged.id.clone()))?;
        let parent = self.state_dir(&staged.wallet, &staged.chain, SolanaOutboxState::Pending)?;
        fs::create_dir_all(&parent)?;
        let dir = parent.join(&staged.id);
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(OutboxError::TargetExists(dir.display().to_string()));
            }
            Err(error) => return Err(error.into()),
        }
        let mut public = staged.clone();
        let legacy_signature = public.signature.take();
        write_atomic(
            dir.join("intent.json"),
            &serde_json::to_vec_pretty(&public)?,
        )?;
        write_atomic(dir.join("plan.md"), plan_md.as_bytes())?;
        if let Some(signature) = legacy_signature {
            write_private_atomic(&dir.join(PRIVATE_SIGNATURE_FILE), signature.as_bytes())?;
        }
        sync_dir(&dir)?;
        sync_dir(&parent)?;
        Ok(dir)
    }

    /// Write the broadcast-attempt marker and its raw-tx blob (mode 0600),
    /// binding the raw bytes' blake3 hash into the marker.
    pub fn write_broadcast_attempt(
        &self,
        entry: &SolanaOutboxEntry,
        signature: &str,
        raw_tx: &[u8],
        created_ms: u128,
    ) -> Result<(), OutboxError> {
        let raw_blake3 = blake3_hash(raw_tx);
        let attempt = SolanaBroadcastAttempt {
            schema: BROADCAST_SCHEMA.to_string(),
            signature: signature.to_string(),
            raw_tx_blake3: raw_blake3,
            raw_tx_path: BROADCAST_RAW_TX.to_string(),
            fee_payer: entry.staged.fee_payer.clone(),
            destination: entry.staged.destination.clone(),
            lamports: entry.staged.lamports,
            blockhash: entry.staged.blockhash.clone(),
            created_ms,
        };
        write_atomic(
            entry.dir.join(BROADCAST_ATTEMPT_FILE),
            &serde_json::to_vec_pretty(&attempt)?,
        )?;
        let path = entry.dir.join(BROADCAST_RAW_TX);
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        file.write_all(raw_tx)?;
        file.sync_all()?;
        let _ = fs::remove_file(entry.dir.join(PRIVATE_SIGNATURE_FILE));
        sync_dir(&entry.dir)?;
        Ok(())
    }

    /// Read the recorded raw-tx bytes for an entry, verifying their blake3
    /// hash against the marker (a retry cannot substitute different bytes).
    pub fn read_broadcast_raw_tx(&self, entry: &SolanaOutboxEntry) -> Result<Vec<u8>, OutboxError> {
        let attempt: SolanaBroadcastAttempt =
            serde_json::from_slice(&fs::read(entry.dir.join(BROADCAST_ATTEMPT_FILE))?)?;
        let raw = fs::read(entry.dir.join(BROADCAST_RAW_TX))?;
        if blake3_hash(&raw) != attempt.raw_tx_blake3 {
            return Err(OutboxError::RawTxHashMismatch);
        }
        Ok(raw)
    }

    /// Move `pending/<id>` → `<new_state>/<id>` (atomic via `fs::rename`).
    pub fn transition(
        &self,
        entry: &SolanaOutboxEntry,
        new_state: SolanaOutboxState,
    ) -> Result<PathBuf, OutboxError> {
        if entry.state == new_state {
            return Ok(entry.dir.clone());
        }
        let target_parent = self.state_dir(&entry.staged.wallet, &entry.staged.chain, new_state)?;
        fs::create_dir_all(&target_parent)?;
        let target = target_parent.join(&entry.staged.id);
        if target.exists() {
            return Err(OutboxError::TargetExists(target.display().to_string()));
        }
        fs::rename(&entry.dir, &target)?;
        if matches!(
            new_state,
            SolanaOutboxState::Sent | SolanaOutboxState::Failed
        ) {
            let _ = fs::remove_file(target.join(BROADCAST_RAW_TX));
            let _ = fs::remove_file(target.join(PRIVATE_SIGNATURE_FILE));
            let _ = fs::remove_file(target.join(PRIVATE_APPROVAL_FILE));
            let _ = fs::remove_file(target.join(APPROVAL_CHALLENGE_FILE));
        }
        sync_dir(&target_parent)?;
        Ok(target)
    }

    /// Overwrite `intent.json` for an already-located entry in place (same
    /// directory, updated payload) — used to keep the persisted `status`
    /// field in sync with the entry's actual on-disk state after a
    /// transition, e.g. once a broadcast succeeds.
    pub fn rewrite_intent(&self, entry: &SolanaOutboxEntry) -> Result<(), OutboxError> {
        let mut public = entry.staged.clone();
        public.signature = None;
        write_atomic(
            entry.dir.join("intent.json"),
            &serde_json::to_vec_pretty(&public)?,
        )?;
        Ok(())
    }

    /// Search for `id` across pending/sent/failed, returning the first hit.
    pub fn read(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
    ) -> Result<SolanaOutboxEntry, OutboxError> {
        for state in [
            SolanaOutboxState::Pending,
            SolanaOutboxState::Sent,
            SolanaOutboxState::Failed,
        ] {
            let dir = self.state_dir(wallet, chain, state)?.join(id);
            if dir.join("intent.json").exists() {
                let staged = serde_json::from_slice(&fs::read(dir.join("intent.json"))?)?;
                return Ok(SolanaOutboxEntry { state, staged, dir });
            }
        }
        Err(OutboxError::NotFound(id.into()))
    }

    /// Read `id` from whichever projection can still be restaged, returning
    /// the entry together with the state it was found in.
    ///
    /// A stale transfer is swept from `pending` into `failed`, so recovery has
    /// to be reachable from both. Callers that only looked in `pending` would
    /// report a state error for exactly the case the restage path exists to
    /// serve. This deliberately applies no status policy: *whether* a given
    /// entry may be restaged is the engine's decision, and keeping the lookup
    /// in one place stops the two layers from disagreeing about where to look.
    pub fn read_restageable(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
    ) -> Result<(SolanaOutboxEntry, SolanaOutboxState), OutboxError> {
        for state in [SolanaOutboxState::Pending, SolanaOutboxState::Failed] {
            if let Ok(entry) = self.read_in_state(wallet, chain, id, state) {
                return Ok((entry, state));
            }
        }
        Err(OutboxError::NotFound(id.into()))
    }

    /// Read `id` only if it currently lives in `expected`, mirroring
    /// `bloom-tx`'s fail-closed state check.
    pub fn read_in_state(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
        expected: SolanaOutboxState,
    ) -> Result<SolanaOutboxEntry, OutboxError> {
        let dir = self.state_dir(wallet, chain, expected)?.join(id);
        if dir.join("intent.json").exists() {
            let staged = serde_json::from_slice(&fs::read(dir.join("intent.json"))?)?;
            return Ok(SolanaOutboxEntry {
                state: expected,
                staged,
                dir,
            });
        }
        for other in [
            SolanaOutboxState::Pending,
            SolanaOutboxState::Sent,
            SolanaOutboxState::Failed,
        ] {
            if other == expected {
                continue;
            }
            if self
                .state_dir(wallet, chain, other)?
                .join(id)
                .join("intent.json")
                .exists()
            {
                return Err(OutboxError::StateMismatch {
                    id: id.to_string(),
                    expected: expected.dirname(),
                    actual: other.dirname(),
                });
            }
        }
        Err(OutboxError::NotFound(id.into()))
    }

    pub fn list(
        &self,
        wallet: &str,
        chain: &str,
        state: SolanaOutboxState,
    ) -> Result<Vec<String>, OutboxError> {
        let dir = self.state_dir(wallet, chain, state)?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                out.push(name.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Walk every `<root>/<wallet>/<chain>/sent/<id>/` and return a
    /// [`SolanaSentEntry`] per entry whose `intent.json` parses and has a
    /// recorded signature. Malformed entries are skipped with a warning.
    pub fn walk_all_sent(&self) -> Result<Vec<SolanaSentEntry>, OutboxError> {
        let mut out = Vec::new();
        if !self.inner.root.exists() {
            return Ok(out);
        }
        for w in fs::read_dir(&self.inner.root)? {
            let w = w?;
            if !w.file_type()?.is_dir() {
                continue;
            }
            let wname = match w.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            for c in fs::read_dir(w.path())? {
                let c = c?;
                if !c.file_type()?.is_dir() {
                    continue;
                }
                let cname = match c.file_name().into_string() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let sent = c.path().join("sent");
                if !sent.exists() {
                    continue;
                }
                for ent in fs::read_dir(&sent)? {
                    let ent = match ent {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(error = %e, path = %sent.display(), "solana_outbox.walk_sent.readdir_failed");
                            continue;
                        }
                    };
                    let dir = ent.path();
                    let intent_path = dir.join("intent.json");
                    if !intent_path.exists() {
                        continue;
                    }
                    match parse_sent_entry(&wname, &cname, &dir, &intent_path) {
                        Some(se) => out.push(se),
                        None => {
                            tracing::warn!(path = %dir.display(), "solana_outbox.walk_sent.skip_malformed")
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Write a sibling artefact next to an existing sent entry.
    pub fn write_sent_sibling(
        &self,
        entry: &SolanaSentEntry,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), OutboxError> {
        let dir = self
            .state_dir(&entry.wallet, &entry.chain, SolanaOutboxState::Sent)?
            .join(&entry.id);
        fs::create_dir_all(&dir)?;
        self.write_artefact(&dir, name, bytes)
    }

    fn write_artefact(&self, dir: &Path, name: &str, body: &[u8]) -> Result<(), OutboxError> {
        if name.contains('/') || name.contains('\\') {
            return Err(OutboxError::InvalidId(name.into()));
        }
        write_atomic(dir.join(name), body)?;
        Ok(())
    }

    /// Read the mined-outcome `receipt.json` for an entry in any state.
    pub fn read_receipt(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
    ) -> Result<Option<SolanaReceipt>, OutboxError> {
        let entry = match self.read(wallet, chain, id) {
            Ok(e) => e,
            Err(OutboxError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let path = entry.dir.join(RECEIPT_FILE);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(&path)?)?))
    }

    /// Record the transaction signature on a still-pending entry. The
    /// replayable signature stays in a private sidecar until broadcast
    /// succeeds; it is never projected through public `intent.json`.
    pub fn record_signature(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
        signature: &str,
    ) -> Result<SolanaOutboxEntry, OutboxError> {
        let entry = self.read_in_state(wallet, chain, id, SolanaOutboxState::Pending)?;
        write_private_atomic(
            &entry.dir.join(PRIVATE_SIGNATURE_FILE),
            signature.as_bytes(),
        )?;
        Ok(entry)
    }

    /// Read the private pre-broadcast signature, with a compatibility fallback
    /// for entries written by the pre-sidecar format.
    pub fn recorded_signature(
        &self,
        entry: &SolanaOutboxEntry,
    ) -> Result<Option<String>, OutboxError> {
        let path = entry.dir.join(PRIVATE_SIGNATURE_FILE);
        if path.exists() {
            return Ok(Some(String::from_utf8(fs::read(path)?).map_err(|_| {
                OutboxError::Other("recorded signature is not UTF-8".into())
            })?));
        }
        Ok(entry.staged.signature.clone())
    }

    /// Atomically persist the sanitized, public preflight result next to a
    /// pending entry. It follows the entry across a successful transition.
    pub fn write_simulation(
        &self,
        entry: &SolanaOutboxEntry,
        body: &[u8],
    ) -> Result<(), OutboxError> {
        if entry.state != SolanaOutboxState::Pending {
            return Err(OutboxError::StateMismatch {
                id: entry.staged.id.clone(),
                expected: SolanaOutboxState::Pending.dirname(),
                actual: entry.state.dirname(),
            });
        }
        self.write_artefact(&entry.dir, "simulation.json", body)
    }

    /// Atomically persist the approval-resume projection as a private host
    /// artifact. The wallet VFS never exposes this file.
    pub fn write_approval(
        &self,
        entry: &SolanaOutboxEntry,
        body: &[u8],
    ) -> Result<(), OutboxError> {
        if entry.state != SolanaOutboxState::Pending {
            return Err(OutboxError::StateMismatch {
                id: entry.staged.id.clone(),
                expected: SolanaOutboxState::Pending.dirname(),
                actual: entry.state.dirname(),
            });
        }
        write_private_atomic(&entry.dir.join(PRIVATE_APPROVAL_FILE), body)
    }

    /// Atomically publish the sanitized owner-visible approval projection next
    /// to a pending transfer. Unlike the compatibility-only private approval
    /// sidecar, this file is intentionally readable through the wallet VFS.
    pub fn write_approval_challenge(
        &self,
        entry: &SolanaOutboxEntry,
        body: &[u8],
    ) -> Result<(), OutboxError> {
        if entry.state != SolanaOutboxState::Pending {
            return Err(OutboxError::StateMismatch {
                id: entry.staged.id.clone(),
                expected: SolanaOutboxState::Pending.dirname(),
                actual: entry.state.dirname(),
            });
        }
        self.write_artefact(&entry.dir, APPROVAL_CHALLENGE_FILE, body)
    }

    /// Remove a completed or superseded approval projection so a stale
    /// ceremony URL is never advertised after signing succeeds.
    pub fn clear_approval_challenge(&self, entry: &SolanaOutboxEntry) -> Result<(), OutboxError> {
        match fs::remove_file(entry.dir.join(APPROVAL_CHALLENGE_FILE)) {
            Ok(()) => sync_dir(&entry.dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Link an expired entry to its freshly staged successor without copying
    /// any private approval or signing material into public artifacts.
    pub fn write_restage_advice(
        &self,
        entry: &SolanaOutboxEntry,
        replacement_id: &str,
    ) -> Result<(), OutboxError> {
        let advice = serde_json::json!({
            "schema": "bloom.solana-restage-advice/1",
            "reason": "blockhash_expired",
            "replacement_id": replacement_id,
            "wallet": &entry.staged.wallet,
            "chain": &entry.staged.chain,
        });
        self.write_artefact(
            &entry.dir,
            "restage_advice.json",
            &serde_json::to_vec_pretty(&advice)?,
        )?;
        self.write_artefact(
            &entry.dir,
            "restage.md",
            format!(
                "The staged blockhash expired. Replacement: `{replacement_id}`. Review its fresh intent and plan before confirming.\n"
            )
            .as_bytes(),
        )
    }

    /// Cancel a still-pending entry. A locally recorded signature does not
    /// imply submission, so signed pending entries remain cancellable.
    pub fn cancel(&self, wallet: &str, chain: &str, id: &str) -> Result<(), OutboxError> {
        let entry = self.read_in_state(wallet, chain, id, SolanaOutboxState::Pending)?;
        let mut staged = entry.staged.clone();
        staged.status = SolanaTxStatus::Cancelled;
        let entry = SolanaOutboxEntry {
            state: entry.state,
            staged: staged.clone(),
            dir: entry.dir.clone(),
        };
        let new_dir = self.transition(&entry, SolanaOutboxState::Failed)?;
        let mut public = staged;
        public.signature = None;
        write_atomic(
            new_dir.join("intent.json"),
            &serde_json::to_vec_pretty(&public)?,
        )?;
        write_atomic(new_dir.join("cancel.txt"), b"cancelled by user")?;
        Ok(())
    }

    /// Remove pending entries whose expiry has elapsed.
    pub fn sweep_expired(&self, now_ms: u128) -> Result<usize, OutboxError> {
        let mut count = 0;
        if !self.inner.root.exists() {
            return Ok(0);
        }
        for w in fs::read_dir(&self.inner.root)? {
            let w = w?;
            if !w.file_type()?.is_dir() {
                continue;
            }
            for c in fs::read_dir(w.path())? {
                let c = c?;
                if !c.file_type()?.is_dir() {
                    continue;
                }
                let pending = c.path().join("pending");
                if !pending.exists() {
                    continue;
                }
                for ent in fs::read_dir(&pending)? {
                    let ent = ent?;
                    let intent_path = ent.path().join("intent.json");
                    if !intent_path.exists() {
                        continue;
                    }
                    let staged: StagedSolanaTransfer =
                        serde_json::from_slice(&fs::read(&intent_path)?)?;
                    // A signed pending entry may represent a broadcast whose
                    // RPC response was lost. Keep it retryable and visible;
                    // expiry alone must not turn it into a false failure.
                    let entry = SolanaOutboxEntry {
                        state: SolanaOutboxState::Pending,
                        staged,
                        dir: ent.path(),
                    };
                    if self.recorded_signature(&entry)?.is_none()
                        && entry.staged.expires_ms != 0
                        && now_ms >= entry.staged.expires_ms
                    {
                        let mut expired = entry.clone();
                        expired.staged.status = SolanaTxStatus::Expired;
                        let dir = self.transition(&expired, SolanaOutboxState::Failed)?;
                        expired.state = SolanaOutboxState::Failed;
                        expired.dir = dir;
                        self.rewrite_intent(&expired)?;
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }
}

fn blake3_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn write_atomic(path: impl AsRef<Path>, body: &[u8]) -> Result<(), OutboxError> {
    write_atomic_with_mode(path.as_ref(), body, 0o600)
}

fn write_private_atomic(path: &Path, body: &[u8]) -> Result<(), OutboxError> {
    write_atomic_with_mode(path, body, 0o600)
}

fn write_atomic_with_mode(path: &Path, body: &[u8], mode: u32) -> Result<(), OutboxError> {
    let parent = path
        .parent()
        .ok_or_else(|| OutboxError::Other("outbox artifact has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let mut random = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| OutboxError::Other("outbox artifact name is not UTF-8".into()))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", hex::encode(random)));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(&temporary)?;
    if let Err(error) = (|| -> Result<(), std::io::Error> {
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_dir(parent)?;
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), OutboxError> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn parse_sent_entry(
    wallet: &str,
    chain: &str,
    dir: &Path,
    intent_path: &Path,
) -> Option<SolanaSentEntry> {
    let bytes = fs::read(intent_path).ok()?;
    let staged: StagedSolanaTransfer = serde_json::from_slice(&bytes).ok()?;
    let signature = fs::read(dir.join(BROADCAST_ATTEMPT_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SolanaBroadcastAttempt>(&bytes).ok())
        .map(|attempt| attempt.signature)
        .or_else(|| {
            fs::read(dir.join(PRIVATE_SIGNATURE_FILE))
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
        .or(staged.signature.clone())?;
    let sent_at = fs::metadata(intent_path).ok()?.modified().ok()?;
    let mined = dir.join(RECEIPT_FILE).exists();
    Some(SolanaSentEntry {
        wallet: wallet.to_string(),
        chain: chain.to_string(),
        id: staged.id,
        signature,
        fee_payer: staged.fee_payer,
        destination: staged.destination,
        lamports: staged.lamports,
        blockhash: staged.blockhash,
        last_valid_block_height: staged.last_valid_block_height,
        sent_at,
        mined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn staged(id: &str) -> StagedSolanaTransfer {
        StagedSolanaTransfer {
            id: id.into(),
            wallet: "alice".into(),
            chain: "solana-devnet".into(),
            fee_payer: "11111111111111111111111111111111".into(),
            account_fingerprint: None,
            account_derivation_path: None,
            destination: "11111111111111111111111111111111".into(),
            lamports: 1,
            fee_lamports: 5000,
            genesis_hash: "devnet".into(),
            blockhash: "blockhash".into(),
            last_valid_block_height: 10,
            message_b64: "AA==".into(),
            payload_digest_hex: "00".repeat(32),
            signature: Some("sig".into()),
            created_ms: 1,
            expires_ms: 0,
            status: SolanaTxStatus::Sent,
            action_id: None,
        }
    }

    /// Place `id` directly into `state` with the given status.
    fn place(root: &std::path::Path, id: &str, state: SolanaOutboxState, status: SolanaTxStatus) {
        let dir = root
            .join("alice/solana-devnet")
            .join(state.dirname())
            .join(id);
        fs::create_dir_all(&dir).unwrap();
        let mut entry = staged(id);
        entry.status = status;
        fs::write(dir.join("intent.json"), serde_json::to_vec(&entry).unwrap()).unwrap();
    }

    #[test]
    fn a_restageable_entry_is_found_in_pending_and_in_failed() {
        let td = tempdir().unwrap();
        let root = td.path().join(".solana-outbox");
        place(
            &root,
            "0001",
            SolanaOutboxState::Pending,
            SolanaTxStatus::Pending,
        );
        // The sweeper moves a stale entry here; recovery must still find it.
        place(
            &root,
            "0002",
            SolanaOutboxState::Failed,
            SolanaTxStatus::Expired,
        );
        let outbox = SolanaOutbox::new(&root).unwrap();

        let (pending, found_in) = outbox
            .read_restageable("alice", "solana-devnet", "0001")
            .expect("a pending entry is restageable");
        assert_eq!(found_in, SolanaOutboxState::Pending);
        assert_eq!(pending.staged.id, "0001");

        // The regression: looking only in `pending` reported a state error for
        // precisely the swept entry the restage path exists to recover.
        let (failed, found_in) = outbox
            .read_restageable("alice", "solana-devnet", "0002")
            .expect("a swept entry must remain reachable from failed");
        assert_eq!(found_in, SolanaOutboxState::Failed);
        assert_eq!(failed.staged.id, "0002");
        assert_eq!(failed.staged.status, SolanaTxStatus::Expired);
    }

    #[test]
    fn the_lookup_applies_no_status_policy_and_reports_an_absent_id() {
        let td = tempdir().unwrap();
        let root = td.path().join(".solana-outbox");
        // A policy refusal also lands in `failed`. The lookup still finds it —
        // refusing to revive it is the engine's decision, made on the status —
        // so that the caller can report why rather than "no such transfer".
        place(
            &root,
            "0003",
            SolanaOutboxState::Failed,
            SolanaTxStatus::Failed,
        );
        let outbox = SolanaOutbox::new(&root).unwrap();

        let (refused, found_in) = outbox
            .read_restageable("alice", "solana-devnet", "0003")
            .expect("the lookup is state-based, not status-based");
        assert_eq!(found_in, SolanaOutboxState::Failed);
        assert_eq!(refused.staged.status, SolanaTxStatus::Failed);

        // `sent` is terminal and is never a restage source.
        place(&root, "0004", SolanaOutboxState::Sent, SolanaTxStatus::Sent);
        let outbox = SolanaOutbox::new(&root).unwrap();
        assert!(matches!(
            outbox.read_restageable("alice", "solana-devnet", "0004"),
            Err(OutboxError::NotFound(_))
        ));
        assert!(matches!(
            outbox.read_restageable("alice", "solana-devnet", "nope"),
            Err(OutboxError::NotFound(_))
        ));
    }
}
