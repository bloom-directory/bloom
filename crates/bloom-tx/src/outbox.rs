//! Persistence for staged / sent / failed txs under the home dir.
//!
//! Layout: `<home>/outbox/<wallet>/<chain>/{pending,sent,failed}/<id>/...`

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use bloom_proto::{StagedTx, TxStatus};
use parking_lot::RwLock;
use thiserror::Error;

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

#[derive(Clone)]
pub struct Outbox {
    inner: Arc<OutboxInner>,
}

struct OutboxInner {
    root: PathBuf,
    next_id: RwLock<u64>,
}

impl Outbox {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, OutboxError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self {
            inner: Arc::new(OutboxInner {
                root,
                next_id: RwLock::new(1),
            }),
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
    pub fn write_pending(&self, staged: &StagedTx, plan_md: &str) -> Result<PathBuf, OutboxError> {
        let dir = self
            .state_dir(&staged.wallet, &staged.chain, OutboxState::Pending)?
            .join(&staged.id);
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("intent.json"), serde_json::to_vec_pretty(staged)?)?;
        fs::write(dir.join("plan.md"), plan_md.as_bytes())?;
        fs::write(
            dir.join("policy_check.json"),
            serde_json::to_vec_pretty(&staged.policy_checks)?,
        )?;
        Ok(dir)
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
        Ok(target)
    }

    pub fn write_artefact(&self, dir: &Path, name: &str, body: &[u8]) -> Result<(), OutboxError> {
        if name.contains('/') || name.contains('\\') {
            return Err(OutboxError::InvalidId(name.into()));
        }
        fs::write(dir.join(name), body)?;
        Ok(())
    }

    pub fn cancel(&self, wallet: &str, chain: &str, id: &str) -> Result<(), OutboxError> {
        let entry = self.read(wallet, chain, id)?;
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
}
