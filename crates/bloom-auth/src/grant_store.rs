//! In-memory [`GrantStore`] implementation for the Sealed Approval service.
//!
//! The store is intentionally process-local and never persisted
//! ([`SealedApprovalGrant`] is `!Serialize` / `!Deserialize`); on restart a
//! new approval ceremony is required.
//!
//! Invariants maintained end-to-end (each method holds the parking-lot mutex
//! from entry to return, so concurrent callers cannot double-spend a grant):
//!
//! - At most one live grant per
//!   `(wallet, action_id, petal_id, petal_digest)` tuple at any `now_ms`.
//! - "Live" means `now_ms < expiry_ms && !revoked
//!   && consumed_signature_count < max_signatures`.
//! - The secondary index (`live_by_tuple`) is a fast-path mirror of the
//!   "is there a live grant for this tuple" predicate: it only ever points
//!   to live grants, and is updated atomically alongside `by_id` mutations.

use async_trait::async_trait;
use bloom_auth_api::{AuthApiError, GrantStore, SealedAction, SealedApprovalGrant};
use parking_lot::Mutex;
use std::collections::HashMap;

/// In-memory [`GrantStore`].
#[derive(Default)]
pub struct InMemoryGrantStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Primary index: `grant_id` → grant snapshot.
    by_id: HashMap<String, SealedApprovalGrant>,
    /// Secondary index: tuple key → `grant_id`. Only ever points to a live
    /// grant (invariant maintained by every mutator).
    live_by_tuple: HashMap<TupleKey, String>,
    /// Monotonic counter used to derive unique `grant_id`s even when two
    /// mints of the same sealed action happen at the same `now_ms`.
    next_grant_seq: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TupleKey {
    wallet: String,
    action_id: String,
    petal_id: String,
    petal_digest: String,
}

impl TupleKey {
    fn from_action(action: &SealedAction) -> Self {
        Self {
            wallet: action.wallet().to_string(),
            action_id: action.action_id().to_string(),
            petal_id: action.petal_id().to_string(),
            petal_digest: action.petal_digest().to_string(),
        }
    }

    fn from_grant(grant: &SealedApprovalGrant) -> Self {
        Self {
            wallet: grant.wallet.clone(),
            action_id: grant.action_id.clone(),
            petal_id: grant.petal_id.clone(),
            petal_digest: grant.petal_digest.clone(),
        }
    }
}

impl InMemoryGrantStore {
    /// Construct an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

fn next_grant_id(inner: &mut Inner, action: &SealedAction, now_ms: u64) -> String {
    let seq = inner.next_grant_seq;
    inner.next_grant_seq = inner.next_grant_seq.saturating_add(1);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bloom.grant_id.v1");
    hasher.update(action.wallet().as_bytes());
    hasher.update(action.action_id().as_bytes());
    hasher.update(&now_ms.to_be_bytes());
    hasher.update(&seq.to_be_bytes());
    let hex = hasher.finalize().to_hex().to_string();
    let grant_id = format!("grant-{}", &hex[..32]);
    if inner.by_id.contains_key(&grant_id) {
        // Defensive: collision between BLAKE3-derived id and an existing
        // row would only be possible after a restart that rewound the
        // counter, but bump the counter forward anyway and try once more.
        let seq2 = inner.next_grant_seq;
        inner.next_grant_seq = inner.next_grant_seq.saturating_add(1);
        let mut h = blake3::Hasher::new();
        h.update(b"bloom.grant_id.v1");
        h.update(&seq2.to_be_bytes());
        let hex2 = h.finalize().to_hex().to_string();
        format!("grant-{}", &hex2[..32])
    } else {
        grant_id
    }
}

#[async_trait]
impl GrantStore for InMemoryGrantStore {
    async fn mint(
        &self,
        sealed: &SealedAction,
        approval_expiry_ms: u64,
        now_ms: u64,
    ) -> Result<SealedApprovalGrant, AuthApiError> {
        let mut inner = self.inner.lock();
        let tuple = TupleKey::from_action(sealed);
        // Reject if a live grant already exists for this tuple.
        if let Some(existing_id) = inner.live_by_tuple.get(&tuple).cloned() {
            let still_live = inner
                .by_id
                .get(&existing_id)
                .map(|g| g.is_active_at(now_ms))
                .unwrap_or(false);
            if still_live {
                return Err(AuthApiError::Denied(format!(
                    "a live grant already exists for the (wallet, action_id, petal_id, petal_digest) tuple (grant_id={existing_id})"
                )));
            }
            // Stale secondary index entry — drop it so the mint can proceed.
            inner.live_by_tuple.remove(&tuple);
        }
        let grant_id = next_grant_id(&mut inner, sealed, now_ms);
        let grant = SealedApprovalGrant::mint(&grant_id, sealed, approval_expiry_ms, now_ms)?;
        inner.live_by_tuple.insert(tuple, grant.grant_id.clone());
        inner.by_id.insert(grant.grant_id.clone(), grant.clone());
        Ok(grant)
    }

    async fn consume_signature(
        &self,
        grant_id: &str,
        intent: &str,
        now_ms: u64,
    ) -> Result<SealedApprovalGrant, AuthApiError> {
        let mut inner = self.inner.lock();
        let grant = inner
            .by_id
            .get_mut(grant_id)
            .ok_or_else(|| AuthApiError::NotFound(format!("grant {grant_id}")))?;
        if grant.revoked {
            return Err(AuthApiError::Denied("grant is revoked".into()));
        }
        if now_ms >= grant.expiry_ms {
            return Err(AuthApiError::Denied("grant has expired".into()));
        }
        if grant.consumed_signature_count >= grant.max_signatures {
            return Err(AuthApiError::Denied(
                "grant has no remaining signatures".into(),
            ));
        }
        if !grant
            .daemon_terms
            .allowed_sign_intents
            .iter()
            .any(|s| s == intent)
        {
            return Err(AuthApiError::Denied(format!(
                "intent {intent} is not allowed by this grant's daemon terms"
            )));
        }
        grant.consumed_signature_count = grant.consumed_signature_count.saturating_add(1);
        let snapshot = grant.clone();
        if !snapshot.is_active_at(now_ms) {
            // Grant is no longer live; clear the secondary index entry so a
            // re-mint for the same tuple is allowed.
            let tuple = TupleKey::from_grant(&snapshot);
            inner.live_by_tuple.remove(&tuple);
        }
        Ok(snapshot)
    }

    async fn revoke(&self, grant_id: &str, _now_ms: u64) -> Result<(), AuthApiError> {
        let mut inner = self.inner.lock();
        if let Some(grant) = inner.by_id.get_mut(grant_id) {
            if !grant.revoked {
                grant.revoked = true;
                let tuple = TupleKey::from_grant(grant);
                inner.live_by_tuple.remove(&tuple);
            }
        }
        Ok(())
    }

    async fn revoke_all_for_wallet(
        &self,
        wallet: &str,
        now_ms: u64,
    ) -> Result<usize, AuthApiError> {
        let mut inner = self.inner.lock();
        let mut count = 0usize;
        for grant in inner.by_id.values_mut() {
            if grant.wallet == wallet && !grant.revoked {
                grant.revoked = true;
                count += 1;
            }
        }
        // Sweep the secondary index to drop any entries whose grant is no
        // longer live (revoked or expired at `now_ms`). Collect the ids to
        // drop first to avoid borrowing `inner` from inside the closure.
        let stale_ids: Vec<TupleKey> = inner
            .live_by_tuple
            .iter()
            .filter_map(|(tuple, id)| {
                let still_live = inner
                    .by_id
                    .get(id)
                    .map(|g| g.is_active_at(now_ms))
                    .unwrap_or(false);
                if still_live {
                    None
                } else {
                    Some(tuple.clone())
                }
            })
            .collect();
        for tuple in stale_ids {
            inner.live_by_tuple.remove(&tuple);
        }
        Ok(count)
    }

    async fn get_active(
        &self,
        wallet: &str,
        action_id: &str,
        petal_id: &str,
        petal_digest: &str,
        now_ms: u64,
    ) -> Result<Option<SealedApprovalGrant>, AuthApiError> {
        let inner = self.inner.lock();
        let tuple = TupleKey {
            wallet: wallet.to_string(),
            action_id: action_id.to_string(),
            petal_id: petal_id.to_string(),
            petal_digest: petal_digest.to_string(),
        };
        if let Some(id) = inner.live_by_tuple.get(&tuple) {
            if let Some(grant) = inner.by_id.get(id) {
                if grant.is_active_at(now_ms) {
                    return Ok(Some(grant.clone()));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_auth_api::{
        AssuranceLevel, CanonicalEnvelope, CanonicalIntentHeader, DaemonGrantTerms, ExecutorKind,
        PetalPolicySnapshot, SealedAction,
        petal_identity::{
            FIRST_PARTY_PETAL_VERSION_V0, PETAL_ID_PAID_HTTP, PLACEHOLDER_DIGEST_PAID_HTTP,
        },
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn envelope_for(surface: &str, action_id: &str) -> CanonicalEnvelope {
        CanonicalEnvelope::new(
            CanonicalIntentHeader {
                schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
                wallet: "my-wallet".into(),
                surface: surface.into(),
                action_id: action_id.into(),
                petal_id: PETAL_ID_PAID_HTTP.into(),
                petal_digest: PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
                executor_kind: ExecutorKind::FirstParty,
                network: "base".into(),
                account: "default".into(),
                action_kind: "x402_payment".into(),
                value_movement: true,
                authority_change: false,
                expires_ms: 1_000_000,
            },
            "paid_http",
            "paid_http.v1",
            br#"{"amount":"1.00"}"#.to_vec(),
        )
    }

    fn terms(max_signatures: u32) -> DaemonGrantTerms {
        DaemonGrantTerms {
            max_ttl_secs: 120,
            max_signatures,
            allowed_sign_intents: vec!["evm.tx.sign".into(), "x402.sign".into()],
            assurance: AssuranceLevel::Standard,
            extra: BTreeMap::new(),
        }
    }

    fn sealed_action(max_signatures: u32) -> SealedAction {
        SealedAction::new(
            envelope_for("requests", "req_1"),
            "plan".into(),
            Vec::new(),
            terms(max_signatures),
            PetalPolicySnapshot::minimal(&envelope_for("requests", "req_1").header),
            100,
        )
        .unwrap()
    }

    fn sealed_action_for(action_id: &str, max_signatures: u32) -> SealedAction {
        let env = envelope_for("requests", action_id);
        SealedAction::new(
            env,
            "plan".into(),
            Vec::new(),
            terms(max_signatures),
            PetalPolicySnapshot::minimal(&envelope_for("requests", action_id).header),
            100,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn mint_unique_per_tuple() {
        let store = InMemoryGrantStore::new();
        let action = sealed_action(2);
        let first = store.mint(&action, 1_000_000, 200).await.unwrap();
        assert_eq!(first.consumed_signature_count, 0);
        assert!(!first.revoked);

        let err = store.mint(&action, 1_000_000, 300).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("live grant"),
            "second mint for active tuple must error with a message containing 'live grant': {msg}"
        );
    }

    #[tokio::test]
    async fn mint_allows_reissue_after_consume_exhaustion() {
        let store = InMemoryGrantStore::new();
        let action = sealed_action(2);
        let first = store.mint(&action, 1_000_000, 200).await.unwrap();
        // Exhaust the grant.
        store
            .consume_signature(&first.grant_id, "evm.tx.sign", 300)
            .await
            .unwrap();
        store
            .consume_signature(&first.grant_id, "evm.tx.sign", 301)
            .await
            .unwrap();
        // The exhausted grant is no longer live; a re-mint for the same
        // tuple must succeed.
        let second = store
            .mint(&action, 1_000_000, 400)
            .await
            .expect("re-mint after exhaustion must succeed");
        assert_ne!(second.grant_id, first.grant_id);
        assert_eq!(second.consumed_signature_count, 0);
    }

    #[tokio::test]
    async fn consume_signature_rejects_disallowed_intent() {
        let store = InMemoryGrantStore::new();
        let action = sealed_action(2);
        let grant = store.mint(&action, 1_000_000, 200).await.unwrap();
        let err = store
            .consume_signature(&grant.grant_id, "polymarket.order.v1", 300)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not allowed"), "{err}");
    }

    #[tokio::test]
    async fn consume_signature_rejects_expired() {
        let store = InMemoryGrantStore::new();
        let action = sealed_action(2);
        let grant = store.mint(&action, 500, 200).await.unwrap();
        // grant.expiry_ms is 200 + 120_000 = 120_200
        let err = store
            .consume_signature(&grant.grant_id, "evm.tx.sign", 200_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn consume_signature_rejects_revoked() {
        let store = InMemoryGrantStore::new();
        let action = sealed_action(2);
        let grant = store.mint(&action, 1_000_000, 200).await.unwrap();
        store.revoke(&grant.grant_id, 250).await.unwrap();
        let err = store
            .consume_signature(&grant.grant_id, "evm.tx.sign", 300)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
    }

    #[tokio::test]
    async fn consume_signature_rejects_over_count() {
        let store = InMemoryGrantStore::new();
        let action = sealed_action(2);
        let grant = store.mint(&action, 1_000_000, 200).await.unwrap();
        store
            .consume_signature(&grant.grant_id, "evm.tx.sign", 300)
            .await
            .unwrap();
        store
            .consume_signature(&grant.grant_id, "evm.tx.sign", 301)
            .await
            .unwrap();
        // Both signatures are consumed (max_signatures=2); the third call
        // must be rejected.
        let err = store
            .consume_signature(&grant.grant_id, "evm.tx.sign", 302)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no remaining signatures"), "{err}");
    }

    #[tokio::test]
    async fn revoke_all_for_wallet_rejects_count() {
        let store = InMemoryGrantStore::new();
        // Three live grants for my-wallet.
        for id in ["req_1", "req_2", "req_3"] {
            let action = sealed_action_for(id, 2);
            store.mint(&action, 1_000_000, 200).await.unwrap();
        }
        // A grant for a different wallet (uses a different sealed action
        // header to keep tuple keys distinct).
        let other_env = CanonicalEnvelope::new(
            CanonicalIntentHeader {
                schema: bloom_auth_api::CANONICAL_INTENT_HEADER_SCHEMA_V1.into(),
                wallet: "other-wallet".into(),
                surface: "requests".into(),
                action_id: "req_other".into(),
                petal_id: PETAL_ID_PAID_HTTP.into(),
                petal_digest: PLACEHOLDER_DIGEST_PAID_HTTP.into(),
                petal_version: FIRST_PARTY_PETAL_VERSION_V0.into(),
                executor_kind: ExecutorKind::FirstParty,
                network: "base".into(),
                account: "default".into(),
                action_kind: "x402_payment".into(),
                value_movement: true,
                authority_change: false,
                expires_ms: 1_000_000,
            },
            "paid_http",
            "paid_http.v1",
            br#"{"amount":"1.00"}"#.to_vec(),
        );
        let other = SealedAction::new(
            other_env.clone(),
            "plan".into(),
            Vec::new(),
            terms(2),
            PetalPolicySnapshot::minimal(&other_env.header),
            100,
        )
        .unwrap();
        store.mint(&other, 1_000_000, 200).await.unwrap();

        let count = store.revoke_all_for_wallet("my-wallet", 300).await.unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn get_active_returns_none_for_revoked_or_expired() {
        let store = InMemoryGrantStore::new();
        let action = sealed_action(2);
        let grant = store.mint(&action, 1_000_000, 200).await.unwrap();

        // Live → Some.
        let active = store
            .get_active(
                "my-wallet",
                "req_1",
                PETAL_ID_PAID_HTTP,
                PLACEHOLDER_DIGEST_PAID_HTTP,
                300,
            )
            .await
            .unwrap();
        assert!(active.is_some());
        assert_eq!(active.unwrap().grant_id, grant.grant_id);

        // Revoked → None.
        store.revoke(&grant.grant_id, 350).await.unwrap();
        let revoked = store
            .get_active(
                "my-wallet",
                "req_1",
                PETAL_ID_PAID_HTTP,
                PLACEHOLDER_DIGEST_PAID_HTTP,
                400,
            )
            .await
            .unwrap();
        assert!(revoked.is_none(), "revoked grant must not be active");
    }

    #[tokio::test]
    async fn concurrency_two_callers_cannot_double_consume_grant() {
        let store = Arc::new(InMemoryGrantStore::new());
        let action = sealed_action(3);
        let grant = store.mint(&action, 1_000_000, 200).await.unwrap();
        let grant_id = grant.grant_id.clone();

        const N: usize = 20;
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let store = store.clone();
            let id = grant_id.clone();
            handles.push(tokio::spawn(async move {
                store.consume_signature(&id, "evm.tx.sign", 300).await
            }));
        }
        let mut successes = 0usize;
        let mut failures = 0usize;
        for h in handles {
            match h.await.unwrap() {
                Ok(_) => successes += 1,
                Err(_) => failures += 1,
            }
        }
        assert_eq!(
            successes, 3,
            "exactly max_signatures concurrent consumers should succeed"
        );
        assert_eq!(
            failures,
            N - 3,
            "the remaining concurrent consumers should fail"
        );
    }
}
