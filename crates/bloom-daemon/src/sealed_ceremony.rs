//! Sealed approval ceremony orchestrator: drives the one-ceremony flow that
//! mints a grant AND caches the decrypted signer so subsequent `sign_hash`
//! calls within the same grant skip the WebAuthn ceremony.

use bloom_auth_api::{AuditEvent, SealedApprovalGrant, SignedApproval, UnsignedApproval};
use bloom_keystore::petal_host::SignerCache;
use bloom_proto::CeremonyIntent;
use bloom_vfs::{AuthServices, HandlerError};

/// Run the one-ceremony sealed approval flow:
/// 1. Call `keystore.sealed_approval_ceremony` → (assertion, signer).
/// 2. Build `SignedApproval` from the assertion via `into_signed`.
/// 3. Call `verify_and_mint_grant` to mint the grant.
/// 4. Cache the signer keyed by `grant_id`.
/// 5. Return the grant plus the persisted approval artifact.
///
/// The caller (daemon IPC handler) must have already staged the unsigned
/// approval and constructed the [`UnsignedApproval`]. The `signer_cache` must
/// be the same `Arc<SignerCache>` wired into
/// `KeystorePetalHost::with_signer_cache`.
pub async fn run_sealed_approval_ceremony(
    keystore: &bloom_keystore::Keystore,
    services: &AuthServices,
    unsigned: UnsignedApproval,
    intent: Option<CeremonyIntent>,
    now_ms: u64,
    signer_cache: &SignerCache,
) -> Result<(SealedApprovalGrant, SignedApproval), HandlerError> {
    let wallet = unsigned.wallet.clone();

    // 1. Run the single ceremony.
    let (assertion, signer) = keystore
        .sealed_approval_ceremony_with_intent(&wallet, &unsigned, intent)
        .await
        .map_err(|e| HandlerError::Backend(format!("sealed_approval_ceremony: {e}")))?;

    // 2. Build the signed approval.
    let signed = unsigned.into_signed(assertion);

    // 3. Verify + mint the grant.
    let grant = services
        .require_approval_verifier()?
        .verify_and_mint_grant(
            signed.clone(),
            services.require_grant_store()?.as_ref(),
            now_ms,
        )
        .await
        .map_err(|e| HandlerError::Backend(format!("verify_and_mint_grant: {e}")))?;

    // 4. Cache the signer for this grant.
    signer_cache.insert(
        grant.grant_id.clone(),
        signer,
        wallet.clone(),
        grant.expiry_ms,
    );
    signer_cache.prune_expired(now_ms);

    // 5. Audit.
    if let Some(host) = services.petal_host() {
        let _ = host
            .audit(AuditEvent {
                kind: "sealed.ceremony.complete".into(),
                wallet: Some(wallet),
                action_id: Some(grant.action_id.clone()),
                message: format!("grant {} minted via sealed ceremony", grant.grant_id),
            })
            .await;
    }

    Ok((grant, signed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use std::sync::Arc;

    fn test_signer() -> Arc<PrivateKeySigner> {
        Arc::new(PrivateKeySigner::random())
    }

    #[test]
    fn signer_cache_insert_and_get() {
        let cache = SignerCache::new();
        let signer = test_signer();
        cache.insert("grant-1".into(), signer.clone(), "my-wallet".into(), 10_000);
        let got = cache
            .get("grant-1")
            .expect("inserted grant must be present");
        assert_eq!(got.address(), signer.address());
    }

    #[test]
    fn signer_cache_drop_on_completion_removes_entry() {
        let cache = SignerCache::new();
        cache.insert("grant-1".into(), test_signer(), "my-wallet".into(), 10_000);
        assert!(cache.get("grant-1").is_some());
        cache.drop_on_completion("grant-1");
        assert!(cache.get("grant-1").is_none());
    }

    #[test]
    fn signer_cache_prune_expired_removes_past_entries() {
        let cache = SignerCache::new();
        cache.insert("grant-old".into(), test_signer(), "my-wallet".into(), 1_000);
        cache.insert(
            "grant-live".into(),
            test_signer(),
            "my-wallet".into(),
            10_000,
        );
        cache.prune_expired(5_000);
        assert!(cache.get("grant-old").is_none());
        assert!(cache.get("grant-live").is_some());
    }

    #[test]
    fn signer_cache_revoke_for_wallet_removes_only_that_wallet() {
        let cache = SignerCache::new();
        cache.insert("grant-a".into(), test_signer(), "my-wallet".into(), 10_000);
        cache.insert(
            "grant-b".into(),
            test_signer(),
            "other-wallet".into(),
            10_000,
        );
        cache.revoke_for_wallet("my-wallet");
        assert!(cache.get("grant-a").is_none());
        assert!(cache.get("grant-b").is_some());
    }

    #[test]
    fn signer_cache_get_returns_none_for_missing_grant() {
        let cache = SignerCache::new();
        assert!(cache.get("nope").is_none());
    }
}
