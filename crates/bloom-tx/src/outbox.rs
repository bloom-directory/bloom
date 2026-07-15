//! Persistence for staged / sent / failed txs under the home dir.
//!
//! Layout: `<home>/outbox/<wallet>/<chain>/{pending,sent,failed}/<id>/...`

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use bloom_auth_api::petal_identity::{
    FIRST_PARTY_PETAL_VERSION_V0, PETAL_ID_EVM_WALLET, PLACEHOLDER_DIGEST_EVM_WALLET,
};
use bloom_proto::{StagedTx, TxStatus};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A parsed view of a `<root>/<wallet>/<chain>/sent/<id>/intent.json` entry.
/// Used by background scanners (e.g. `BumpScanner`) that walk all sent entries.
#[derive(Debug, Clone)]
pub struct SentEntry {
    pub wallet: String,
    pub chain: String,
    /// Outbox id (e.g. `"0001-12345"`), NOT the tx hash.
    pub id: String,
    /// Parsed from `staged.tx_hash`; entries without a hash are skipped.
    pub hash: alloy::primitives::B256,
    pub from: alloy::primitives::Address,
    pub to: alloy::primitives::Address,
    pub value: alloy::primitives::U256,
    /// Raw hex string from `staged.data_hex`.
    pub data: String,
    pub nonce: u64,
    pub fees: bloom_mempool::TxFees,
    /// `intent.json` mtime — used as a stable proxy for when the tx was
    /// sent. The directory's mtime is unreliable because background
    /// scanners (e.g. `BumpScanner`) write sibling artefacts into the
    /// same dir, which would otherwise reset dwell calculations.
    pub sent_at: std::time::SystemTime,
    /// `true` when `staged.status` is `Success` or `Reverted`.
    pub mined: bool,
}

/// Filename of the mined-outcome sibling artefact, written by the
/// reconciliation loop next to a `sent/<id>/` entry. We never mutate the
/// write-once `intent.json` (its mtime is the `sent_at` proxy), so the mined
/// status lives here instead.
pub const RECEIPT_FILE: &str = "receipt.json";

/// Persistent record of a sent tx's mined outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinedReceipt {
    /// `"success"` or `"reverted"`.
    pub outcome: String,
    pub tx_hash: String,
    #[serde(default)]
    pub block_number: Option<u64>,
    /// Decoded revert reason (best-effort) when `outcome == "reverted"`.
    #[serde(default)]
    pub revert_reason: Option<String>,
}

impl MinedReceipt {
    pub fn is_success(&self) -> bool {
        self.outcome == "success"
    }
}

#[derive(Debug, Error)]
pub enum OutboxError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
    /// Caller asked for `id` in `expected` but it actually lives in `actual`.
    /// The op was refused so the caller can't accidentally operate on a tx
    /// that has already moved past the expected state.
    #[error("staged tx '{id}' is in '{actual}', not '{expected}'")]
    StateMismatch {
        id: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("staged tx '{id}' expired at {expired_at} (now {now})")]
    StagedExpired {
        id: String,
        expired_at: u128,
        now: u128,
    },
    #[error("invalid id '{0}'")]
    InvalidId(String),
    #[error("invalid wallet '{0}'")]
    InvalidWallet(String),
    #[error("invalid chain '{0}'")]
    InvalidChain(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxState {
    Pending,
    Sent,
    Failed,
}

impl OutboxState {
    pub fn dirname(&self) -> &'static str {
        match self {
            OutboxState::Pending => "pending",
            OutboxState::Sent => "sent",
            OutboxState::Failed => "failed",
        }
    }
    pub fn from_status(s: &TxStatus) -> Self {
        match s {
            TxStatus::Pending => OutboxState::Pending,
            TxStatus::Sent | TxStatus::Success | TxStatus::Reverted => OutboxState::Sent,
            TxStatus::Failed | TxStatus::Cancelled => OutboxState::Failed,
        }
    }
    /// Parse the on-disk dir name back into an [`OutboxState`].
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(OutboxState::Pending),
            "sent" => Some(OutboxState::Sent),
            "failed" => Some(OutboxState::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboxEntry {
    pub state: OutboxState,
    pub staged: StagedTx,
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct CentralActionIdentity<'a> {
    pub petal_id: &'a str,
    pub petal_digest: &'a str,
    pub petal_version: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastTransport {
    PublicRpc,
    PrivateRpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastAttemptKind {
    Confirm,
    Replacement,
    CancelReplacement,
}

impl BroadcastAttemptKind {
    pub fn marker_name(self) -> &'static str {
        match self {
            Self::Confirm => "broadcast_attempted.json",
            Self::Replacement => "replacement_broadcast_attempted.json",
            Self::CancelReplacement => "cancel_broadcast_attempted.json",
        }
    }

    pub fn raw_name(self) -> &'static str {
        match self {
            Self::Confirm => "raw_tx",
            Self::Replacement => "replacement_raw_tx",
            Self::CancelReplacement => "cancel_raw_tx",
        }
    }

    const ALL: [Self; 3] = [Self::Confirm, Self::Replacement, Self::CancelReplacement];
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastAttempt {
    pub schema: String,
    pub tx_hash: String,
    pub raw_tx_blake3: String,
    pub raw_tx_path: String,
    pub from: String,
    pub to: String,
    pub nonce: u64,
    pub chain_id: u64,
    pub created_ms: u128,
    pub transport: BroadcastTransport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_provider: Option<String>,
}

pub struct SameNonceAttemptQuery<'a> {
    pub wallet: &'a str,
    pub chain: &'a str,
    pub from: &'a str,
    pub chain_id: u64,
    pub nonce: u64,
    pub excluding_id: &'a str,
    pub excluding_kind: BroadcastAttemptKind,
}

/// Projection interface for the central outbox. When attached to an
/// [`Outbox`], every staged / transitioned EVM tx is mirrored into the
/// central action store under a stable `action_id`, giving the daemon a
/// single unified view across all surfaces.
pub trait CentralOutboxProjection: Send + Sync {
    /// Allocate (or look up) a central action_id for the given
    /// `(surface, venue_local_id)` pair.
    fn allocate_action_id(
        &self,
        surface: &str,
        venue_local_id: &str,
        wallet: &str,
        staged_at_ms: u64,
    ) -> Result<String, String>;

    /// Create the pending action directory with the standard files.
    fn stage_action(
        &self,
        action_id: &str,
        intent_json: &[u8],
        plan_md: &str,
        policy_check_json: &[u8],
        identity: CentralActionIdentity<'_>,
    ) -> Result<(), String>;

    /// Move the action from one state to another.
    fn transition_action(&self, action_id: &str, from: &str, to: &str) -> Result<(), String>;

    /// Write a runtime-generated artifact under a central action directory.
    fn write_action_file(
        &self,
        action_id: &str,
        state: &str,
        file: &str,
        data: &[u8],
    ) -> Result<(), String>;

    /// Read a runtime-generated artifact from a central action directory.
    fn read_action_file(&self, action_id: &str, state: &str, file: &str)
    -> Result<Vec<u8>, String>;
}

#[derive(Clone)]
pub struct Outbox {
    inner: Arc<OutboxInner>,
}

struct OutboxInner {
    root: PathBuf,
    next_id: RwLock<u64>,
    projection: Option<Arc<dyn CentralOutboxProjection>>,
}

impl Outbox {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, OutboxError> {
        Self::new_inner(root, None)
    }

    /// Create an outbox that mirrors every stage/transition into the
    /// central action store via `projection`.
    pub fn new_with_projection(
        root: impl Into<PathBuf>,
        projection: Arc<dyn CentralOutboxProjection>,
    ) -> Result<Self, OutboxError> {
        Self::new_inner(root, Some(projection))
    }

    fn new_inner(
        root: impl Into<PathBuf>,
        projection: Option<Arc<dyn CentralOutboxProjection>>,
    ) -> Result<Self, OutboxError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self {
            inner: Arc::new(OutboxInner {
                root,
                next_id: RwLock::new(1),
                projection,
            }),
        })
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    /// Mirror a runtime-generated action artifact into the central outbox
    /// projection, when one is attached.
    pub fn write_central_action_artifact(
        &self,
        action_id: &str,
        state: OutboxState,
        file: &str,
        data: &[u8],
    ) -> Result<(), OutboxError> {
        if file != "approval_challenge.json"
            && file != "approval.json"
            && file != "result.json"
            && file != "status.json"
        {
            return Err(OutboxError::Other(format!(
                "central artifact '{file}' is not runtime-writable"
            )));
        }
        if let Some(projection) = &self.inner.projection {
            projection
                .write_action_file(action_id, state.dirname(), file, data)
                .map_err(OutboxError::Other)?;
        }
        Ok(())
    }

    /// Read a runtime-generated action artifact from the central outbox
    /// projection, when one is attached.
    pub fn read_central_action_artifact(
        &self,
        action_id: &str,
        state: OutboxState,
        file: &str,
    ) -> Result<Option<Vec<u8>>, OutboxError> {
        if file != "approval_challenge.json"
            && file != "approval.json"
            && file != "result.json"
            && file != "status.json"
        {
            return Err(OutboxError::Other(format!(
                "central artifact '{file}' is not runtime-readable"
            )));
        }
        if let Some(projection) = &self.inner.projection {
            match projection.read_action_file(action_id, state.dirname(), file) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.contains("not found") => Ok(None),
                Err(e) => Err(OutboxError::Other(e)),
            }
        } else {
            Ok(None)
        }
    }

    /// Mirror a runtime-generated pending action artifact into the central
    /// outbox projection, when one is attached.
    pub fn write_central_pending_artifact(
        &self,
        action_id: &str,
        file: &str,
        data: &[u8],
    ) -> Result<(), OutboxError> {
        self.write_central_action_artifact(action_id, OutboxState::Pending, file, data)
    }

    /// Move the central projected action, if a projection is attached.
    pub fn transition_central_action(
        &self,
        action_id: &str,
        from: OutboxState,
        to: OutboxState,
    ) -> Result<(), OutboxError> {
        if let Some(projection) = &self.inner.projection {
            projection
                .transition_action(action_id, from.dirname(), to.dirname())
                .map_err(OutboxError::Other)?;
        }
        Ok(())
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
        state: OutboxState,
    ) -> Result<PathBuf, OutboxError> {
        Ok(self.wallet_chain_dir(wallet, chain)?.join(state.dirname()))
    }

    /// Allocate a fresh id like `0001-tx`.
    pub fn allocate_id(&self) -> String {
        let mut g = self.inner.next_id.write();
        let id = *g;
        *g = id.wrapping_add(1);
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() % 100_000)
            .unwrap_or(0);
        format!("{:04}-{:05}", id, suffix)
    }

    /// Persist a staged tx in `pending/<id>/` along with its derived
    /// artefacts. The caller owns plan.md / policy_check.json content.
    /// When a central outbox projection is attached, also stages a
    /// central action and stamps the returned `action_id` into
    /// `intent.json`.
    pub fn write_pending(&self, staged: &StagedTx, plan_md: &str) -> Result<PathBuf, OutboxError> {
        let mut staged = staged.clone();

        // Project to central outbox if a projection is wired.
        if let Some(proj) = &self.inner.projection {
            let action_id = proj
                .allocate_action_id("evm", &staged.id, &staged.wallet, staged.created_ms as u64)
                .map_err(OutboxError::Other)?;
            staged.action_id = Some(action_id.clone());

            let intent_json = serde_json::to_vec_pretty(&staged)?;
            let policy_check_json = serde_json::to_vec_pretty(&staged.policy_checks)?;
            proj.stage_action(
                &action_id,
                &intent_json,
                plan_md,
                &policy_check_json,
                CentralActionIdentity {
                    petal_id: PETAL_ID_EVM_WALLET,
                    petal_digest: PLACEHOLDER_DIGEST_EVM_WALLET,
                    petal_version: FIRST_PARTY_PETAL_VERSION_V0,
                },
            )
            .map_err(OutboxError::Other)?;
        }

        let dir = self
            .state_dir(&staged.wallet, &staged.chain, OutboxState::Pending)?
            .join(&staged.id);
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("intent.json"), serde_json::to_vec_pretty(&staged)?)?;
        fs::write(dir.join("plan.md"), plan_md.as_bytes())?;
        fs::write(
            dir.join("policy_check.json"),
            serde_json::to_vec_pretty(&staged.policy_checks)?,
        )?;
        Ok(dir)
    }

    /// Write a `nonce_conflict.json` artefact next to a pending tx, used
    /// when stage detects that `(from, nonce)` collides with an
    /// externally-observed pending tx in the mempool index. The pending
    /// dir must already exist (typically written by `write_pending`
    /// immediately before).
    pub fn write_nonce_conflict(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
        body: &serde_json::Value,
    ) -> Result<PathBuf, OutboxError> {
        let dir = self
            .state_dir(wallet, chain, OutboxState::Pending)?
            .join(id);
        fs::create_dir_all(&dir)?;
        let path = dir.join("nonce_conflict.json");
        fs::write(&path, serde_json::to_vec_pretty(body)?)?;
        Ok(path)
    }

    /// Write a `mev_risk.json` artefact next to a pending tx with the
    /// stage-time output of `bloom_mempool::heuristic::evaluate`. The
    /// pending dir must already exist (typically written by
    /// `write_pending` immediately before). Mirrors
    /// [`Self::write_nonce_conflict`].
    pub fn write_mev_risk(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
        report: &bloom_mempool::MevRiskReport,
    ) -> Result<PathBuf, OutboxError> {
        let dir = self
            .state_dir(wallet, chain, OutboxState::Pending)?
            .join(id);
        fs::create_dir_all(&dir)?;
        let path = dir.join("mev_risk.json");
        fs::write(&path, serde_json::to_vec_pretty(report)?)?;
        Ok(path)
    }

    pub fn write_broadcast_attempt(
        &self,
        entry: &OutboxEntry,
        kind: BroadcastAttemptKind,
        attempt: &BroadcastAttempt,
    ) -> Result<PathBuf, OutboxError> {
        let path = entry.dir.join(kind.marker_name());
        fs::write(&path, serde_json::to_vec_pretty(attempt)?)?;
        Ok(path)
    }

    pub fn read_broadcast_attempt(
        &self,
        entry: &OutboxEntry,
        kind: BroadcastAttemptKind,
    ) -> Result<Option<BroadcastAttempt>, OutboxError> {
        let path = entry.dir.join(kind.marker_name());
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
    }

    pub fn write_broadcast_raw_tx(
        &self,
        entry: &OutboxEntry,
        kind: BroadcastAttemptKind,
        raw: &[u8],
    ) -> Result<PathBuf, OutboxError> {
        let path = entry.dir.join(kind.raw_name());
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&path)?;
        file.write_all(raw)?;
        Ok(path)
    }

    pub fn read_broadcast_raw_tx(
        &self,
        entry: &OutboxEntry,
        kind: BroadcastAttemptKind,
        attempt: &BroadcastAttempt,
    ) -> Result<Vec<u8>, OutboxError> {
        let expected = kind.raw_name();
        if attempt.raw_tx_path != expected {
            return Err(OutboxError::InvalidId(format!(
                "broadcast raw path '{}' did not match expected '{}'",
                attempt.raw_tx_path, expected
            )));
        }
        let raw = fs::read(entry.dir.join(expected))?;
        let got = blake3::hash(&raw).to_hex().to_string();
        if got != attempt.raw_tx_blake3 {
            return Err(OutboxError::InvalidId(format!(
                "broadcast raw tx hash mismatch for {}",
                entry.staged.id
            )));
        }
        Ok(raw)
    }

    pub fn remove_broadcast_raw_tx(
        &self,
        entry: &OutboxEntry,
        kind: BroadcastAttemptKind,
    ) -> Result<(), OutboxError> {
        let path = entry.dir.join(kind.raw_name());
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn broadcast_attempts_for_nonce(
        &self,
        query: SameNonceAttemptQuery<'_>,
    ) -> Result<Vec<(String, OutboxState, BroadcastAttemptKind, BroadcastAttempt)>, OutboxError>
    {
        let mut out = Vec::new();
        for state in [OutboxState::Pending, OutboxState::Sent, OutboxState::Failed] {
            let dir = self.state_dir(query.wallet, query.chain, state)?;
            if !dir.exists() {
                continue;
            }
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let id = entry.file_name().to_string_lossy().to_string();
                for kind in BroadcastAttemptKind::ALL {
                    if id == query.excluding_id && kind == query.excluding_kind {
                        continue;
                    }
                    let path = entry.path().join(kind.marker_name());
                    if !path.exists() {
                        continue;
                    }
                    let attempt: BroadcastAttempt = serde_json::from_slice(&fs::read(path)?)?;
                    if attempt.chain_id == query.chain_id
                        && attempt.nonce == query.nonce
                        && attempt.from.eq_ignore_ascii_case(query.from)
                    {
                        out.push((id.clone(), state, kind, attempt));
                    }
                }
            }
        }
        Ok(out)
    }

    /// Return the highest nonce among all `pending/<wallet>/<chain>/<id>/intent.json`
    /// entries whose `from` address matches `addr`. Returns `None` when the pending
    /// directory is empty or doesn't exist yet (no staged txs for this sender).
    ///
    /// Called by `TxEngine::stage()` under a per-(wallet, chain, from) async mutex
    /// to compute the auto-increment next nonce when multiple txs are staged
    /// before any are broadcast (e.g. a DeFi `approve` → `swap` bundle, which
    /// must occupy consecutive nonces).
    ///
    /// This counts *every* pending entry for `addr`, whether or not it has
    /// broadcast yet — that is what keeps sequential staging contiguous. The
    /// hazard it creates (a staged-but-never-broadcast entry reserving a slot,
    /// so a later tx broadcasts into a gap that never fills and is stranded) is
    /// caught at broadcast time by the nonce-gap guard in
    /// [`TxEngine::assert_nonce_not_ahead_of_chain`], not here — reservation
    /// stays optimistic, broadcast stays safe. Callers that need an exact nonce
    /// bypass this entirely via the intent `nonce` override.
    ///
    /// Scans all pending entries for `addr` on each call — acceptable for
    /// single-user CLI where the pending queue is small.
    pub fn highest_pending_nonce(
        &self,
        wallet: &str,
        chain: &str,
        addr: alloy::primitives::Address,
    ) -> Result<Option<u64>, OutboxError> {
        let dir = self.state_dir(wallet, chain, OutboxState::Pending)?;
        if !dir.exists() {
            return Ok(None);
        }
        let mut max_nonce: Option<u64> = None;
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let intent_path = entry.path().join("intent.json");
            if !intent_path.exists() {
                continue;
            }
            let staged: StagedTx = serde_json::from_slice(&fs::read(&intent_path)?)?;
            if staged.from.parse::<alloy::primitives::Address>().ok() == Some(addr) {
                max_nonce = Some(max_nonce.map_or(staged.nonce, |m| m.max(staged.nonce)));
            }
        }
        Ok(max_nonce)
    }

    /// Search for `id` across pending/sent/failed and return the first hit.
    /// Prefer [`Self::read_in_state`] when the caller knows where the entry
    /// is supposed to be — this method exists for diagnostics and is the
    /// reason fix #2 had to plumb state through confirm/replace/cancel.
    pub fn read(&self, wallet: &str, chain: &str, id: &str) -> Result<OutboxEntry, OutboxError> {
        for state in [OutboxState::Pending, OutboxState::Sent, OutboxState::Failed] {
            let dir = self.state_dir(wallet, chain, state)?.join(id);
            let intent = dir.join("intent.json");
            if intent.exists() {
                let staged: StagedTx = serde_json::from_slice(&fs::read(&intent)?)?;
                return Ok(OutboxEntry { state, staged, dir });
            }
        }
        Err(OutboxError::NotFound(id.into()))
    }

    /// Read `id` only if it currently lives in `expected`. Returns
    /// `NotFound` if the id doesn't exist in *that* state — even if it
    /// exists elsewhere — and `StateMismatch` if it lives in a different
    /// state. Callers that must guarantee a tx is still pending (confirm,
    /// replace, cancel) MUST use this rather than [`Self::read`].
    pub fn read_in_state(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
        expected: OutboxState,
    ) -> Result<OutboxEntry, OutboxError> {
        let dir = self.state_dir(wallet, chain, expected)?.join(id);
        let intent = dir.join("intent.json");
        if intent.exists() {
            let staged: StagedTx = serde_json::from_slice(&fs::read(&intent)?)?;
            return Ok(OutboxEntry {
                state: expected,
                staged,
                dir,
            });
        }
        // Differentiate "exists in another state" vs "totally absent" so
        // callers (and humans reading errors) can tell which case it is.
        for other in [OutboxState::Pending, OutboxState::Sent, OutboxState::Failed] {
            if other == expected {
                continue;
            }
            let other_dir = self.state_dir(wallet, chain, other)?.join(id);
            if other_dir.join("intent.json").exists() {
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
        state: OutboxState,
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

    /// Move pending/<id> → <new_state>/<id> (atomic via fs::rename).
    /// When a central outbox projection is attached and the entry has an
    /// `action_id`, the central action is transitioned as well.
    pub fn transition(
        &self,
        entry: &OutboxEntry,
        new_state: OutboxState,
    ) -> Result<PathBuf, OutboxError> {
        if entry.state == new_state {
            return Ok(entry.dir.clone());
        }
        let target_parent = self.state_dir(&entry.staged.wallet, &entry.staged.chain, new_state)?;
        fs::create_dir_all(&target_parent)?;
        let target = target_parent.join(&entry.staged.id);
        if target.exists() {
            fs::remove_dir_all(&target)?;
        }
        fs::rename(&entry.dir, &target)?;

        // Project transition to central outbox.
        if let (Some(proj), Some(action_id)) = (&self.inner.projection, &entry.staged.action_id) {
            let from_str = match entry.state {
                OutboxState::Pending => "pending",
                OutboxState::Sent => "sent",
                OutboxState::Failed => "failed",
            };
            let to_str = match new_state {
                OutboxState::Pending => "pending",
                OutboxState::Sent => "sent",
                OutboxState::Failed => "failed",
            };
            if let Err(e) = proj.transition_action(action_id, from_str, to_str) {
                let rollback = fs::rename(&target, &entry.dir);
                let rollback_detail = match rollback {
                    Ok(()) => "wallet outbox transition rolled back".to_string(),
                    Err(err) => format!("wallet outbox rollback failed: {err}"),
                };
                return Err(OutboxError::Other(format!(
                    "central outbox transition failed for action {action_id} ({from_str}->{to_str}): {e}; {rollback_detail}"
                )));
            }
        }

        if matches!(new_state, OutboxState::Sent | OutboxState::Failed) {
            for kind in BroadcastAttemptKind::ALL {
                let _ = fs::remove_file(target.join(kind.raw_name()));
            }
        }

        Ok(target)
    }

    /// Public accessor for `<root>/<wallet>/<chain>/sent/<id>/`.
    /// Used by external scanners (e.g. `bump_scanner`) that need to write
    /// sibling artefacts next to a persisted sent entry.
    pub fn sent_dir(&self, wallet: &str, chain: &str, id: &str) -> Result<PathBuf, OutboxError> {
        Ok(self.state_dir(wallet, chain, OutboxState::Sent)?.join(id))
    }

    /// Walk every `<root>/<wallet>/<chain>/sent/<id>/` directory and
    /// return a `SentEntry` per entry whose `intent.json` parses and
    /// has a `tx_hash` set. Malformed entries are skipped with a
    /// `tracing::warn!`. This is best-effort and intended for
    /// background scanners.
    pub fn walk_all_sent(&self) -> Result<Vec<SentEntry>, OutboxError> {
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
                            tracing::warn!(error = %e, path = %sent.display(), "outbox.walk_sent.readdir_entry_failed");
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
                            tracing::warn!(path = %dir.display(), "outbox.walk_sent.skip_malformed")
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    /// Write a sibling artefact file next to an existing sent entry.
    /// Creates the directory if needed (e.g. after an external
    /// `fs::rename` that didn't pre-create the target).
    pub fn write_sent_sibling(
        &self,
        entry: &SentEntry,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), OutboxError> {
        let dir = self.sent_dir(&entry.wallet, &entry.chain, &entry.id)?;
        fs::create_dir_all(&dir)?;
        self.write_artefact(&dir, name, bytes)?;
        Ok(())
    }

    pub fn write_artefact(&self, dir: &Path, name: &str, body: &[u8]) -> Result<(), OutboxError> {
        if name.contains('/') || name.contains('\\') {
            return Err(OutboxError::InvalidId(name.into()));
        }
        fs::write(dir.join(name), body)?;
        Ok(())
    }

    /// Set `depends_on` on a still-pending entry by rewriting its
    /// `intent.json`. Used by the DeFi layer to record that a route must not
    /// broadcast until its preceding approve has mined successfully.
    pub fn set_pending_depends_on(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
        dep_id: &str,
    ) -> Result<(), OutboxError> {
        let entry = self.read_in_state(wallet, chain, id, OutboxState::Pending)?;
        let mut staged = entry.staged;
        staged.depends_on = Some(dep_id.to_string());
        fs::write(
            entry.dir.join("intent.json"),
            serde_json::to_vec_pretty(&staged)?,
        )?;
        Ok(())
    }

    /// Read the mined-outcome `receipt.json` for an entry in any state, if the
    /// reconciliation loop has written one yet.
    pub fn read_receipt(
        &self,
        wallet: &str,
        chain: &str,
        id: &str,
    ) -> Result<Option<MinedReceipt>, OutboxError> {
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

    pub fn cancel(&self, wallet: &str, chain: &str, id: &str) -> Result<(), OutboxError> {
        let entry = self.read_in_state(wallet, chain, id, OutboxState::Pending)?;
        let mut staged = entry.staged.clone();
        staged.status = TxStatus::Cancelled;
        let entry = OutboxEntry {
            state: entry.state,
            staged: staged.clone(),
            dir: entry.dir.clone(),
        };
        let new_dir = self.transition(&entry, OutboxState::Failed)?;
        fs::write(
            new_dir.join("intent.json"),
            serde_json::to_vec_pretty(&staged)?,
        )?;
        fs::write(new_dir.join("cancel.txt"), b"cancelled by user")?;
        Ok(())
    }

    /// Remove pending entries that have expired.
    pub fn sweep_expired(&self, now_ms: u128) -> Result<usize, OutboxError> {
        let mut count = 0;
        if !self.inner.root.exists() {
            return Ok(0);
        }
        for w in fs::read_dir(&self.inner.root)? {
            let w = w?;
            let wname = match w.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if !w.file_type()?.is_dir() {
                continue;
            }
            for c in fs::read_dir(w.path())? {
                let c = c?;
                let cname = match c.file_name().into_string() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
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
                    let staged: StagedTx = serde_json::from_slice(&fs::read(&intent_path)?)?;
                    if staged.expires_ms != 0 && now_ms >= staged.expires_ms {
                        let entry = OutboxEntry {
                            state: OutboxState::Pending,
                            staged: staged.clone(),
                            dir: ent.path(),
                        };
                        match self.transition(&entry, OutboxState::Failed) {
                            Ok(_) => {
                                tracing::debug!(
                                    id = %staged.id,
                                    wallet = %staged.wallet,
                                    chain = %staged.chain,
                                    expired_at = staged.expires_ms,
                                    now_ms,
                                    "outbox.sweep_expired"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    id = %staged.id,
                                    wallet = %staged.wallet,
                                    chain = %staged.chain,
                                    error = %e,
                                    "outbox.sweep_transition_failed"
                                );
                            }
                        }
                        count += 1;
                    }
                }
                let _ = (wname.clone(), cname.clone());
            }
        }
        Ok(count)
    }

    /// Sum the `usd_value` of every staged tx for `wallet` whose
    /// `created_ms >= since_ms`, across all chains and all states.
    ///
    /// Used by the policy engine to enforce `caps.per_day_usd`. We
    /// include pending entries (not just sent) on purpose: a pending
    /// stage represents committed user intent and should count
    /// against the rolling cap, otherwise stacking many pending
    /// stages becomes a trivial bypass.
    ///
    /// Entries without a `usd_value` (oracle wasn't available when
    /// they were staged) contribute zero — the rule then degrades
    /// to "best-effort sum of priced sends".
    pub fn sum_usd_since(&self, wallet: &str, since_ms: u128) -> Result<f64, OutboxError> {
        Self::validate_segment(wallet).map_err(|_| OutboxError::InvalidWallet(wallet.into()))?;
        let wallet_dir = self.inner.root.join(wallet);
        if !wallet_dir.exists() {
            return Ok(0.0);
        }
        let mut total = 0.0f64;
        for c in fs::read_dir(&wallet_dir)? {
            let c = c?;
            if !c.file_type()?.is_dir() {
                continue;
            }
            for state in [OutboxState::Pending, OutboxState::Sent, OutboxState::Failed] {
                let state_dir = c.path().join(state.dirname());
                if !state_dir.exists() {
                    continue;
                }
                for ent in fs::read_dir(&state_dir)? {
                    let ent = ent?;
                    let intent_path = ent.path().join("intent.json");
                    if !intent_path.exists() {
                        continue;
                    }
                    let staged: StagedTx = serde_json::from_slice(&fs::read(&intent_path)?)?;
                    if staged.created_ms >= since_ms
                        && let Some(u) = staged.usd_value
                    {
                        total += u;
                    }
                }
            }
        }
        Ok(total)
    }
}

/// Parse a single `<root>/<wallet>/<chain>/sent/<id>/intent.json` into a
/// [`SentEntry`]. Returns `None` if the file can't be parsed or is missing
/// required fields (no `tx_hash`, unparseable addresses, no fee fields).
fn parse_sent_entry(
    wallet: &str,
    chain: &str,
    dir: &Path,
    intent_path: &Path,
) -> Option<SentEntry> {
    let bytes = fs::read(intent_path).ok()?;
    let staged: StagedTx = serde_json::from_slice(&bytes).ok()?;
    let hash_str = staged.tx_hash.as_deref()?; // skip if no hash
    let hash: alloy::primitives::B256 = hash_str.parse().ok()?;
    let from: alloy::primitives::Address = staged.from.parse().ok()?;
    let to: alloy::primitives::Address = staged.to.parse().ok()?;
    let value: alloy::primitives::U256 = staged.value_wei.parse().ok()?;
    let fees = if let Some(mfp) = staged.max_fee_per_gas.as_deref() {
        let max_fee_per_gas = mfp.parse::<u128>().ok()?;
        let max_priority_fee_per_gas = staged
            .max_priority_fee_per_gas
            .as_deref()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        bloom_mempool::TxFees::Eip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }
    } else {
        let gp = staged.gas_price.as_deref()?;
        bloom_mempool::TxFees::Legacy {
            gas_price: gp.parse::<u128>().ok()?,
        }
    };
    // intent.json is written once at entry creation and never modified;
    // its mtime is therefore a stable proxy for when the tx was sent.
    // The directory's mtime is unsuitable because BumpScanner writes
    // sibling artefacts (bump.tx, cancel.tx, bump_advice.json) into the
    // same dir on every scan, which would reset dwell-based stuck
    // detection.
    let sent_at = fs::metadata(dir.join("intent.json"))
        .ok()
        .and_then(|m| m.modified().ok())
        .unwrap_or_else(std::time::SystemTime::now);
    // The mined outcome is recorded as a `receipt.json` sibling (the write-once
    // intent.json is never mutated). Treat either signal as mined.
    let mined = dir.join(RECEIPT_FILE).exists()
        || matches!(staged.status, TxStatus::Success | TxStatus::Reverted);
    Some(SentEntry {
        wallet: wallet.to_string(),
        chain: chain.to_string(),
        id: staged.id,
        hash,
        from,
        to,
        value,
        data: staged.data_hex,
        nonce: staged.nonce,
        fees,
        sent_at,
        mined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_proto::TxStatus;

    fn fake_staged(id: &str) -> StagedTx {
        StagedTx {
            id: id.into(),
            wallet: "alice".into(),
            chain: "anvil".into(),
            chain_id: 31337,
            from: "0x0000000000000000000000000000000000000001".into(),
            to: "0x0000000000000000000000000000000000000002".into(),
            value_wei: "0".into(),
            data_hex: "0x".into(),
            gas_limit: 21000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_price: None,
            nonce: 0,
            policy_checks: vec![],
            created_ms: 0,
            expires_ms: 0,
            status: TxStatus::Pending,
            tx_hash: None,
            token: None,
            nft: None,
            usd_value: None,
            depends_on: None,
            action_id: None,
        }
    }

    #[test]
    fn write_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("0001-test");
        ob.write_pending(&staged, "# plan").unwrap();
        let read = ob.read("alice", "anvil", "0001-test").unwrap();
        assert_eq!(read.staged.id, "0001-test");
        assert_eq!(read.state, OutboxState::Pending);
    }

    #[test]
    fn set_pending_depends_on_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        ob.write_pending(&fake_staged("route"), "# plan").unwrap();
        ob.set_pending_depends_on("alice", "anvil", "route", "approve")
            .unwrap();
        let read = ob.read("alice", "anvil", "route").unwrap();
        assert_eq!(read.staged.depends_on.as_deref(), Some("approve"));
    }

    #[test]
    fn read_receipt_reflects_written_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let mut staged = fake_staged("dep");
        staged.tx_hash = Some(format!("{:#x}", alloy::primitives::B256::repeat_byte(7)));
        // parse_sent_entry requires a fee field + tx_hash to surface the entry.
        staged.max_fee_per_gas = Some("100".into());
        staged.max_priority_fee_per_gas = Some("10".into());
        ob.write_pending(&staged, "# plan").unwrap();
        let entry = ob.read("alice", "anvil", "dep").unwrap();
        ob.transition(&entry, OutboxState::Sent).unwrap();
        // No receipt yet.
        assert!(ob.read_receipt("alice", "anvil", "dep").unwrap().is_none());
        // Walk sees it as not-yet-mined.
        assert!(!ob.walk_all_sent().unwrap()[0].mined);
        // Write a success receipt → read_receipt + mined both reflect it.
        let rec = MinedReceipt {
            outcome: "success".into(),
            tx_hash: staged.tx_hash.clone().unwrap(),
            block_number: Some(123),
            revert_reason: None,
        };
        let se = &ob.walk_all_sent().unwrap()[0];
        ob.write_sent_sibling(se, RECEIPT_FILE, &serde_json::to_vec(&rec).unwrap())
            .unwrap();
        let got = ob.read_receipt("alice", "anvil", "dep").unwrap().unwrap();
        assert!(got.is_success());
        assert!(ob.walk_all_sent().unwrap()[0].mined);
    }

    #[test]
    fn transition_pending_to_sent() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("a");
        ob.write_pending(&staged, "# plan").unwrap();
        let entry = ob.read("alice", "anvil", "a").unwrap();
        let _new_dir = ob.transition(&entry, OutboxState::Sent).unwrap();
        let after = ob.read("alice", "anvil", "a").unwrap();
        assert_eq!(after.state, OutboxState::Sent);
    }

    #[test]
    fn artefact_survives_transition_to_sent() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("art");
        ob.write_pending(&staged, "# plan").unwrap();
        let entry = ob.read("alice", "anvil", "art").unwrap();
        ob.write_artefact(&entry.dir, "review_intent.json", b"{\"title\":\"x\"}")
            .unwrap();
        // pending → sent renames the dir; the artifact must ride along.
        ob.transition(&entry, OutboxState::Sent).unwrap();
        let sent_dir = ob.sent_dir("alice", "anvil", "art").unwrap();
        let body = std::fs::read(sent_dir.join("review_intent.json")).unwrap();
        assert_eq!(body, b"{\"title\":\"x\"}");
    }

    #[test]
    fn highest_pending_nonce_auto_increments_over_all_pending() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let from: alloy::primitives::Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        // No pending entries → no reservation (caller falls back to chain nonce).
        assert_eq!(
            ob.highest_pending_nonce("alice", "anvil", from).unwrap(),
            None
        );

        // Every pending entry counts, broadcast or not — a bundle staged before
        // any broadcast (approve at 0, swap at 1) must keep consecutive nonces.
        let mut a = fake_staged("0001-a");
        a.nonce = 0;
        ob.write_pending(&a, "# plan").unwrap();
        assert_eq!(
            ob.highest_pending_nonce("alice", "anvil", from).unwrap(),
            Some(0)
        );
        let mut b = fake_staged("0002-b");
        b.nonce = 1;
        ob.write_pending(&b, "# plan").unwrap();
        assert_eq!(
            ob.highest_pending_nonce("alice", "anvil", from).unwrap(),
            Some(1),
            "reservation advances so the next stage gets nonce 2"
        );
    }

    #[test]
    fn broadcast_attempt_and_raw_tx_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("attempt");
        ob.write_pending(&staged, "# plan").unwrap();
        let entry = ob.read("alice", "anvil", "attempt").unwrap();
        let raw = b"\x02\xc0";
        let attempt = BroadcastAttempt {
            schema: "bloom.broadcast_attempted.v1".into(),
            tx_hash: "0xabababababababababababababababababababababababababababababababab".into(),
            raw_tx_blake3: blake3::hash(raw).to_hex().to_string(),
            raw_tx_path: BroadcastAttemptKind::Confirm.raw_name().into(),
            from: staged.from.clone(),
            to: staged.to.clone(),
            nonce: staged.nonce,
            chain_id: staged.chain_id,
            created_ms: 1,
            transport: BroadcastTransport::PublicRpc,
            private_provider: None,
        };

        ob.write_broadcast_raw_tx(&entry, BroadcastAttemptKind::Confirm, raw)
            .unwrap();
        ob.write_broadcast_attempt(&entry, BroadcastAttemptKind::Confirm, &attempt)
            .unwrap();

        let read = ob
            .read_broadcast_attempt(&entry, BroadcastAttemptKind::Confirm)
            .unwrap()
            .unwrap();
        assert_eq!(read.tx_hash, attempt.tx_hash);
        let read_raw = ob
            .read_broadcast_raw_tx(&entry, BroadcastAttemptKind::Confirm, &read)
            .unwrap();
        assert_eq!(read_raw, raw);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(entry.dir.join("raw_tx"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn broadcast_raw_tx_is_removed_on_transition() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("raw-cleanup");
        ob.write_pending(&staged, "# plan").unwrap();
        let entry = ob.read("alice", "anvil", "raw-cleanup").unwrap();
        ob.write_broadcast_raw_tx(&entry, BroadcastAttemptKind::Confirm, b"\x01")
            .unwrap();
        ob.transition(&entry, OutboxState::Sent).unwrap();
        let sent_dir = ob.sent_dir("alice", "anvil", "raw-cleanup").unwrap();
        assert!(!sent_dir.join("raw_tx").exists());
    }

    #[test]
    fn outbox_cancel_local_discard_does_not_write_broadcast_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        ob.write_pending(&fake_staged("local-cancel"), "p").unwrap();
        ob.cancel("alice", "anvil", "local-cancel").unwrap();
        let entry = ob.read("alice", "anvil", "local-cancel").unwrap();
        assert_eq!(entry.state, OutboxState::Failed);
        assert!(!entry.dir.join("broadcast_attempted.json").exists());
        assert!(!entry.dir.join("raw_tx").exists());
    }

    #[test]
    fn outbox_cancel_local_discard_requires_pending() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        ob.write_pending(&fake_staged("sent-cancel"), "p").unwrap();
        let entry = ob.read("alice", "anvil", "sent-cancel").unwrap();
        ob.transition(&entry, OutboxState::Sent).unwrap();

        let err = ob.cancel("alice", "anvil", "sent-cancel").unwrap_err();
        assert!(matches!(err, OutboxError::StateMismatch { .. }));
        let entry = ob.read("alice", "anvil", "sent-cancel").unwrap();
        assert_eq!(entry.state, OutboxState::Sent);
    }

    #[test]
    fn broadcast_attempts_for_nonce_finds_other_kind_same_id() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("same-id");
        ob.write_pending(&staged, "# plan").unwrap();
        let entry = ob.read("alice", "anvil", "same-id").unwrap();
        let attempt = BroadcastAttempt {
            schema: "bloom.broadcast_attempted.v1".into(),
            tx_hash: "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".into(),
            raw_tx_blake3: blake3::hash(b"x").to_hex().to_string(),
            raw_tx_path: BroadcastAttemptKind::Replacement.raw_name().into(),
            from: staged.from.clone(),
            to: staged.to.clone(),
            nonce: staged.nonce,
            chain_id: staged.chain_id,
            created_ms: 1,
            transport: BroadcastTransport::PublicRpc,
            private_provider: None,
        };
        ob.write_broadcast_attempt(&entry, BroadcastAttemptKind::Replacement, &attempt)
            .unwrap();

        let hits = ob
            .broadcast_attempts_for_nonce(SameNonceAttemptQuery {
                wallet: "alice",
                chain: "anvil",
                from: &staged.from,
                chain_id: staged.chain_id,
                nonce: staged.nonce,
                excluding_id: "same-id",
                excluding_kind: BroadcastAttemptKind::Confirm,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2, BroadcastAttemptKind::Replacement);
    }

    #[test]
    fn cancel_moves_to_failed() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        ob.write_pending(&fake_staged("c"), "p").unwrap();
        ob.cancel("alice", "anvil", "c").unwrap();
        let after = ob.read("alice", "anvil", "c").unwrap();
        assert_eq!(after.state, OutboxState::Failed);
        assert_eq!(after.staged.status, TxStatus::Cancelled);
    }

    #[test]
    fn invalid_wallet_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        assert!(ob.wallet_chain_dir("../etc", "anvil").is_err());
    }

    #[test]
    fn sweep_expires() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let mut s = fake_staged("x");
        s.expires_ms = 100;
        ob.write_pending(&s, "p").unwrap();
        let n = ob.sweep_expired(200).unwrap();
        assert_eq!(n, 1);
        let entry = ob.read("alice", "anvil", "x").unwrap();
        assert_eq!(entry.state, OutboxState::Failed);
    }

    /// Fix #8: `read_in_state` must NotFound an id that exists in a
    /// different state, even though the older `read` would have returned
    /// it. This protects callers from accidentally operating on a tx
    /// that has already moved on.
    #[test]
    fn read_in_state_rejects_wrong_state() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        ob.write_pending(&fake_staged("a"), "p").unwrap();
        let entry = ob.read("alice", "anvil", "a").unwrap();
        ob.transition(&entry, OutboxState::Sent).unwrap();
        // Same id but asking for pending — must NotFound (StateMismatch
        // technically, depending on whether other states have it).
        let r = ob.read_in_state("alice", "anvil", "a", OutboxState::Pending);
        assert!(matches!(r, Err(OutboxError::StateMismatch { .. })));
        // And the sent state must succeed.
        let r2 = ob
            .read_in_state("alice", "anvil", "a", OutboxState::Sent)
            .unwrap();
        assert_eq!(r2.state, OutboxState::Sent);
    }

    /// Fix #8: A nonexistent id is NotFound (not StateMismatch).
    #[test]
    fn read_in_state_missing_id_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let r = ob.read_in_state("alice", "anvil", "ghost", OutboxState::Pending);
        assert!(matches!(r, Err(OutboxError::NotFound(_))));
    }

    /// `sum_usd_since` ignores entries older than the cutoff and entries
    /// without a usd_value, and aggregates across chains and states.
    #[test]
    fn sum_usd_since_aggregates_across_chains_and_states() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();

        // Recent: anvil + base, both sent. Stale: too old. Unpriced: no contribution.
        let mut a = fake_staged("a");
        a.created_ms = 2_000;
        a.usd_value = Some(100.0);
        ob.write_pending(&a, "p").unwrap();
        ob.transition(&ob.read("alice", "anvil", "a").unwrap(), OutboxState::Sent)
            .unwrap();

        let mut b = fake_staged("b");
        b.chain = "base".into();
        b.created_ms = 2_500;
        b.usd_value = Some(50.0);
        ob.write_pending(&b, "p").unwrap();

        let mut c = fake_staged("c");
        c.created_ms = 100; // before cutoff
        c.usd_value = Some(999.0);
        ob.write_pending(&c, "p").unwrap();

        let mut d = fake_staged("d");
        d.created_ms = 3_000;
        d.usd_value = None; // unpriced
        ob.write_pending(&d, "p").unwrap();

        let total = ob.sum_usd_since("alice", 1_000).unwrap();
        assert!((total - 150.0).abs() < 1e-6, "got {total}");
    }

    #[test]
    fn sum_usd_since_unknown_wallet_returns_zero() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let total = ob.sum_usd_since("alice", 0).unwrap();
        assert_eq!(total, 0.0);
    }

    #[test]
    fn write_mev_risk_writes_to_pending_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("0001-mev");
        ob.write_pending(&staged, "p").unwrap();

        let report = bloom_mempool::MevRiskReport {
            risk: bloom_mempool::MevRisk::Low,
            checks: vec![],
            advice: String::new(),
        };
        let path = ob
            .write_mev_risk("alice", "anvil", "0001-mev", &report)
            .unwrap();

        let expected = dir
            .path()
            .join("alice")
            .join("anvil")
            .join("pending")
            .join("0001-mev")
            .join("mev_risk.json");
        assert_eq!(path, expected);
        assert!(path.exists());

        let read_body: bloom_mempool::MevRiskReport =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(read_body.risk, bloom_mempool::MevRisk::Low);
        assert!(read_body.checks.is_empty());
        assert!(read_body.advice.is_empty());
    }

    #[test]
    fn write_nonce_conflict_writes_to_pending_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("0001-conflict");
        ob.write_pending(&staged, "p").unwrap();

        let body = serde_json::json!({
            "conflict_nonce": 7,
            "external_hash": "0xabababababababababababababababababababababababababababababababab",
            "external_observed_at": 1_700_000_000u64,
            "advice": "use a different nonce",
        });
        let path = ob
            .write_nonce_conflict("alice", "anvil", "0001-conflict", &body)
            .unwrap();

        let expected = dir
            .path()
            .join("alice")
            .join("anvil")
            .join("pending")
            .join("0001-conflict")
            .join("nonce_conflict.json");
        assert_eq!(path, expected);
        assert!(path.exists());

        let read_body: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(read_body, body);
    }

    // --- Central outbox projection tests ---

    use std::sync::Mutex;

    struct MockProjection {
        allocated: Mutex<Vec<(String, String)>>, // (surface, venue_local_id)
        staged: Mutex<Vec<String>>,              // action_ids staged
        transitions: Mutex<Vec<(String, String, String)>>, // (id, from, to)
        fail_transition: Mutex<Option<String>>,
        action_files: Mutex<Vec<(String, String, String)>>,
    }

    impl MockProjection {
        fn new() -> Self {
            Self {
                allocated: Mutex::new(vec![]),
                staged: Mutex::new(vec![]),
                transitions: Mutex::new(vec![]),
                fail_transition: Mutex::new(None),
                action_files: Mutex::new(vec![]),
            }
        }
    }

    impl CentralOutboxProjection for MockProjection {
        fn allocate_action_id(
            &self,
            surface: &str,
            venue_local_id: &str,
            _wallet: &str,
            _staged_at_ms: u64,
        ) -> Result<String, String> {
            let mut g = self.allocated.lock().unwrap();
            let n = g.len();
            g.push((surface.to_string(), venue_local_id.to_string()));
            Ok(format!("act-{n:04}"))
        }

        fn stage_action(
            &self,
            action_id: &str,
            _intent_json: &[u8],
            _plan_md: &str,
            _policy_check_json: &[u8],
            identity: CentralActionIdentity<'_>,
        ) -> Result<(), String> {
            self.staged.lock().unwrap().push(format!(
                "{}:{}:{}:{}",
                action_id, identity.petal_id, identity.petal_digest, identity.petal_version
            ));
            Ok(())
        }

        fn transition_action(&self, action_id: &str, from: &str, to: &str) -> Result<(), String> {
            if let Some(err) = self.fail_transition.lock().unwrap().clone() {
                return Err(err);
            }
            self.transitions.lock().unwrap().push((
                action_id.to_string(),
                from.to_string(),
                to.to_string(),
            ));
            Ok(())
        }

        fn write_action_file(
            &self,
            action_id: &str,
            state: &str,
            file: &str,
            _data: &[u8],
        ) -> Result<(), String> {
            self.action_files.lock().unwrap().push((
                action_id.to_string(),
                state.to_string(),
                file.to_string(),
            ));
            Ok(())
        }

        fn read_action_file(
            &self,
            _action_id: &str,
            _state: &str,
            _file: &str,
        ) -> Result<Vec<u8>, String> {
            Err("not found".into())
        }
    }

    #[test]
    fn projection_round_trips_stage_and_transition() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockProjection::new());
        let ob = Outbox::new_with_projection(dir.path(), mock.clone()).unwrap();

        let staged = fake_staged("0001-evm");
        ob.write_pending(&staged, "# plan").unwrap();

        // action_id should be stamped into intent.json.
        let entry = ob.read("alice", "anvil", "0001-evm").unwrap();
        assert_eq!(
            entry.staged.action_id.as_deref(),
            Some("act-0000"),
            "action_id should be stamped into the staged tx"
        );

        // Mock should have recorded the allocation + stage.
        assert_eq!(mock.allocated.lock().unwrap().len(), 1);
        let staged_actions = mock.staged.lock().unwrap();
        assert_eq!(staged_actions.len(), 1);
        assert_eq!(
            staged_actions[0],
            format!(
                "act-0000:{PETAL_ID_EVM_WALLET}:{PLACEHOLDER_DIGEST_EVM_WALLET}:{FIRST_PARTY_PETAL_VERSION_V0}"
            )
        );
        drop(staged_actions);

        // Transition to sent.
        ob.transition(&entry, OutboxState::Sent).unwrap();

        // Mock should have recorded the transition.
        let ts = mock.transitions.lock().unwrap();
        assert_eq!(ts.len(), 1, "one transition should be projected");
        assert_eq!(ts[0].0, "act-0000");
        assert_eq!(ts[0].1, "pending");
        assert_eq!(ts[0].2, "sent");
    }

    #[test]
    fn projection_skipped_when_no_action_id() {
        // Without a projection, no action_id is set.
        let dir = tempfile::tempdir().unwrap();
        let ob = Outbox::new(dir.path()).unwrap();
        let staged = fake_staged("no-proj");
        ob.write_pending(&staged, "# plan").unwrap();
        let entry = ob.read("alice", "anvil", "no-proj").unwrap();
        assert!(entry.staged.action_id.is_none());
    }

    #[test]
    fn projection_writes_runtime_artifacts_in_final_state() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockProjection::new());
        let ob = Outbox::new_with_projection(dir.path(), mock.clone()).unwrap();

        ob.write_central_action_artifact("act-final", OutboxState::Sent, "result.json", b"{}")
            .unwrap();

        let files = mock.action_files.lock().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "act-final");
        assert_eq!(files[0].1, "sent");
        assert_eq!(files[0].2, "result.json");
    }

    #[test]
    fn projection_transition_failure_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mock = Arc::new(MockProjection::new());
        *mock.fail_transition.lock().unwrap() = Some("projection store offline".into());
        let ob = Outbox::new_with_projection(dir.path(), mock).unwrap();

        let staged = fake_staged("0001-evm");
        ob.write_pending(&staged, "# plan").unwrap();
        let entry = ob.read("alice", "anvil", "0001-evm").unwrap();
        let err = ob.transition(&entry, OutboxState::Sent).unwrap_err();

        assert!(
            err.to_string().contains("central outbox transition failed"),
            "{err}"
        );
        assert!(
            err.to_string().contains("projection store offline"),
            "{err}"
        );
        assert!(
            ob.read("alice", "anvil", "0001-evm").is_ok(),
            "wallet outbox should remain retryable in pending after projection failure"
        );
    }
}
