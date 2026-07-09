//! Bounded policy sessions for batch signing.
//!
//! One passkey ceremony mints an [`ActiveSession`] scoped by *wallet*,
//! *chains*, *expiry*, *max total USD*, and an explicit *pending-tx-id
//! allowlist*. Subsequent confirms that fall inside those bounds are
//! authorized without a fresh per-tx ceremony; anything outside re-prompts.
//! The bounds are the security envelope.
//!
//! The store lives on the [`crate::tx_engine::TxEngine`] (where confirms are
//! authorized) — **not** on the keystore's unlocked-signer cache, which has an
//! unbounded lifetime. A session therefore expires independently and can never
//! resurrect a locked key.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use parking_lot::RwLock;

pub type SessionId = String;

/// A live, bounded authorization minted by one ceremony.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub id: SessionId,
    pub wallet: String,
    /// Chain ids this session may authorize.
    pub chains: BTreeSet<u64>,
    /// Unix-ms expiry; confirms at or after this are not covered.
    pub expires_ms: u128,
    /// Total spend cap in micro-USD across the session.
    pub max_micro_usd: i128,
    /// Micro-USD already debited by authorized confirms.
    pub spent_micro_usd: i128,
    /// Exact **chain-qualified** outbox ids this session may broadcast, keyed
    /// `"{chain_id}:{outbox_id}"`. Outbox ids are unique only within a chain, so
    /// qualifying by chain prevents a same-id tx on another listed chain from
    /// being authorized by a session minted for a different chain's tx.
    pub allowed_pending_ids: BTreeSet<String>,
}

/// Build the chain-qualified allowlist key for an outbox id.
pub fn pending_key(chain_id: u64, outbox_id: &str) -> String {
    format!("{chain_id}:{outbox_id}")
}

/// Thread-safe store of active sessions. Cheap to clone (shares the inner
/// lock), so it can be a `TxEngine` field cloned across handlers.
#[derive(Default, Clone)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<SessionId, ActiveSession>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mint(&self, session: ActiveSession) {
        self.inner.write().insert(session.id.clone(), session);
    }

    pub fn revoke(&self, id: &str) -> bool {
        self.inner.write().remove(id).is_some()
    }

    /// Revoke a session only if it belongs to `wallet`. Prevents one wallet's
    /// path from revoking another wallet's session by guessing its id (session
    /// ids embed the owning wallet but are otherwise opaque to callers). Returns
    /// `false` when the id is unknown *or* owned by a different wallet.
    pub fn revoke_for(&self, wallet: &str, id: &str) -> bool {
        let mut guard = self.inner.write();
        match guard.get(id) {
            Some(s) if s.wallet == wallet => {
                guard.remove(id);
                true
            }
            _ => false,
        }
    }

    pub fn prune_expired(&self, now_ms: u128) {
        self.inner.write().retain(|_, s| s.expires_ms > now_ms);
    }

    /// Live (unexpired) sessions, for the read surface.
    pub fn active(&self, now_ms: u128) -> Vec<ActiveSession> {
        self.inner
            .read()
            .values()
            .filter(|s| s.expires_ms > now_ms)
            .cloned()
            .collect()
    }

    /// Atomically authorize a confirm against a covering session and debit its
    /// budget. Returns `Some((session_id, debited_micro_usd))` when covered
    /// (the caller refunds on a subsequent submit failure), else `None`.
    ///
    /// Coverage: same wallet, not expired, `chain_id` allowed, `pending_id` in
    /// the allowlist, and — when the tx's USD value is known — `spent + value
    /// <= max`. The check and debit happen under one write lock, so two
    /// concurrent confirms cannot both pass against the same pre-debit budget.
    ///
    /// Unpriced txs (`tx_micro_usd == None`) are handled by `value_moving`: a
    /// value-moving tx with no USD valuation **fails closed** (no session covers
    /// it) rather than debiting 0 and slipping the dollar cap — otherwise a
    /// burst of unpriced transfers could drain a wallet under a priced budget.
    /// A value-neutral unpriced tx (no native value/token/NFT/calldata) is bound
    /// by the explicit id allowlist alone and debits 0.
    pub fn authorize_and_debit(
        &self,
        wallet: &str,
        chain_id: u64,
        pending_id: &str,
        tx_micro_usd: Option<i128>,
        value_moving: bool,
        now_ms: u128,
    ) -> Option<(SessionId, i128)> {
        let key = pending_key(chain_id, pending_id);
        let mut guard = self.inner.write();
        for s in guard.values_mut() {
            if s.wallet != wallet
                || s.expires_ms <= now_ms
                || !s.chains.contains(&chain_id)
                || !s.allowed_pending_ids.contains(&key)
            {
                continue;
            }
            let debit = match tx_micro_usd {
                Some(v) => {
                    if s.spent_micro_usd.saturating_add(v) > s.max_micro_usd {
                        // This session can't afford it; keep looking — another
                        // session might also cover this id.
                        continue;
                    }
                    s.spent_micro_usd = s.spent_micro_usd.saturating_add(v);
                    v
                }
                // Unpriced value-moving tx: we can't debit it against the dollar
                // cap, so no session may silently cover it (fail closed).
                None if value_moving => continue,
                // Unpriced value-neutral tx: the explicit id allowlist is the
                // bound; debit 0.
                None => 0,
            };
            return Some((s.id.clone(), debit));
        }
        None
    }

    /// Return a previously-debited amount to a session (e.g. the submit failed
    /// after authorization).
    pub fn refund(&self, id: &str, micro_usd: i128) {
        if let Some(s) = self.inner.write().get_mut(id) {
            s.spent_micro_usd = s.spent_micro_usd.saturating_sub(micro_usd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: &str, max: i128, ids: &[&str]) -> ActiveSession {
        ActiveSession {
            id: id.into(),
            wallet: "alice".into(),
            chains: BTreeSet::from([42161, 8453]),
            expires_ms: 10_000,
            max_micro_usd: max,
            spent_micro_usd: 0,
            // Tests authorize on chain 42161; allowlist holds chain-qualified keys.
            allowed_pending_ids: ids.iter().map(|s| pending_key(42161, s)).collect(),
        }
    }

    #[test]
    fn does_not_authorize_same_id_on_a_different_chain() {
        let store = SessionStore::new();
        // Minted for base:0001-a (chain 8453); both chains are in `chains`.
        let mut s = session("s1", 10_000_000, &[]);
        s.allowed_pending_ids = BTreeSet::from([pending_key(8453, "0001-a")]);
        store.mint(s);
        // The same bare id on Arbitrum (42161) must NOT be authorized.
        assert!(
            store
                .authorize_and_debit("alice", 42161, "0001-a", Some(1), true, 1)
                .is_none()
        );
        // The exact (chain, id) it was minted for is authorized.
        assert!(
            store
                .authorize_and_debit("alice", 8453, "0001-a", Some(1), true, 1)
                .is_some()
        );
    }

    #[test]
    fn covers_allowed_id_on_allowed_chain_before_expiry() {
        let store = SessionStore::new();
        store.mint(session("s1", 10_000_000, &["0001-a"]));
        assert!(
            store
                .authorize_and_debit("alice", 42161, "0001-a", Some(1_000_000), true, 1)
                .is_some()
        );
    }

    #[test]
    fn rejects_expired_wrong_chain_and_unlisted_id() {
        let store = SessionStore::new();
        store.mint(session("s1", 10_000_000, &["0001-a"]));
        // expired
        assert!(
            store
                .authorize_and_debit("alice", 42161, "0001-a", Some(1), true, 99_999)
                .is_none()
        );
        // chain not in set
        assert!(
            store
                .authorize_and_debit("alice", 1, "0001-a", Some(1), true, 1)
                .is_none()
        );
        // id not in allowlist
        assert!(
            store
                .authorize_and_debit("alice", 42161, "0009-z", Some(1), true, 1)
                .is_none()
        );
        // wrong wallet
        assert!(
            store
                .authorize_and_debit("bob", 42161, "0001-a", Some(1), true, 1)
                .is_none()
        );
    }

    #[test]
    fn budget_is_consumed_cumulatively() {
        let store = SessionStore::new();
        store.mint(session("s1", 10_000_000, &["a", "b"]));
        assert!(
            store
                .authorize_and_debit("alice", 42161, "a", Some(7_000_000), true, 1)
                .is_some()
        );
        // Second confirm would exceed the $10 cap → refused.
        assert!(
            store
                .authorize_and_debit("alice", 42161, "b", Some(4_000_000), true, 1)
                .is_none()
        );
        // A smaller one still fits.
        assert!(
            store
                .authorize_and_debit("alice", 42161, "b", Some(3_000_000), true, 1)
                .is_some()
        );
    }

    #[test]
    fn refund_restores_budget() {
        let store = SessionStore::new();
        store.mint(session("s1", 10_000_000, &["a"]));
        let (id, amt) = store
            .authorize_and_debit("alice", 42161, "a", Some(9_000_000), true, 1)
            .unwrap();
        store.refund(&id, amt);
        // Full budget available again.
        assert!(
            store
                .authorize_and_debit("alice", 42161, "a", Some(9_000_000), true, 1)
                .is_some()
        );
    }

    #[test]
    fn unpriced_value_moving_tx_fails_closed() {
        let store = SessionStore::new();
        store.mint(session("s1", 10_000_000, &["a"]));
        // No USD valuation + value-moving → no session may cover it.
        assert!(
            store
                .authorize_and_debit("alice", 42161, "a", None, true, 1)
                .is_none()
        );
        // No USD valuation + value-neutral → covered by the id allowlist, debit 0.
        let (_, debit) = store
            .authorize_and_debit("alice", 42161, "a", None, false, 1)
            .expect("value-neutral unpriced tx is covered");
        assert_eq!(debit, 0);
    }

    #[test]
    fn revoke_and_prune_remove_sessions() {
        let store = SessionStore::new();
        store.mint(session("s1", 1, &["a"]));
        assert!(store.revoke("s1"));
        assert!(!store.revoke("s1"));
        store.mint(session("s2", 1, &["a"]));
        store.prune_expired(99_999); // past expiry
        assert!(store.active(1).is_empty());
    }

    #[test]
    fn revoke_for_is_wallet_scoped() {
        let store = SessionStore::new();
        store.mint(session("s1", 1, &["a"])); // owned by "alice"
        // A different wallet path cannot revoke alice's session by id.
        assert!(!store.revoke_for("bob", "s1"));
        // Unknown id is also rejected.
        assert!(!store.revoke_for("alice", "nope"));
        // The owning wallet can revoke it.
        assert!(store.revoke_for("alice", "s1"));
        assert!(!store.revoke_for("alice", "s1"));
    }
}
