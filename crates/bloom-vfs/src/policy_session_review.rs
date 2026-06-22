//! One-time approval markers for bounded policy-session mints.
//!
//! Minting a policy session creates *future* signing authority, so the mint must
//! prove the exact session envelope was human-reviewed — not merely that the
//! daemon happened to be unlocked. The IPC ceremony lane (writer) persists a
//! marker keyed by the reviewed-intent hash after a successful review/unlock; the
//! VFS mint handler (verifier) consumes it before minting. Both resolve the same
//! location from the home dir and key by [`bloom_proto::policy_session_mint_intent`]'s
//! `intent_hash`, so the value compared is identical on both sides.
//!
//! Markers are one-time (consumed on mint) so an approval can't be replayed to
//! mint twice.

use std::path::{Path, PathBuf};

/// Path of the approval marker for `(wallet, intent_hash)` under `home`.
pub fn review_marker_path(home: &Path, wallet: &str, intent_hash: &str) -> PathBuf {
    home.join("policy_session_reviews")
        .join(wallet)
        .join(format!("{intent_hash}.json"))
}

/// Persist a one-time approval marker after a successful mint ceremony.
pub fn persist_review_approved(
    home: &Path,
    wallet: &str,
    intent_hash: &str,
) -> std::io::Result<()> {
    let path = review_marker_path(home, wallet, intent_hash);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::json!({
        "schema": "bloom.review_approved.v1",
        "intent_hash": intent_hash,
        "wallet": wallet,
    });
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&body).map_err(|e| std::io::Error::other(e.to_string()))?,
    )
}

/// Verify and CONSUME the approval marker for `intent_hash`. Returns `true` iff a
/// matching marker existed; the marker is removed either way so it can't be
/// replayed.
pub fn consume_review_approved(home: &Path, wallet: &str, intent_hash: &str) -> bool {
    let path = review_marker_path(home, wallet, intent_hash);
    let ok = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| {
                v.get("intent_hash")
                    .and_then(|h| h.as_str())
                    .map(|h| h == intent_hash)
            })
            .unwrap_or(false),
        Err(_) => false,
    };
    let _ = std::fs::remove_file(&path);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_round_trips_and_is_one_time() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        assert!(!consume_review_approved(home, "alice", "abc123"));
        persist_review_approved(home, "alice", "abc123").unwrap();
        // Wrong wallet / hash does not match.
        assert!(!consume_review_approved(home, "bob", "abc123"));
        persist_review_approved(home, "alice", "abc123").unwrap();
        assert!(!consume_review_approved(home, "alice", "deadbeef"));
        // Correct match consumes once.
        persist_review_approved(home, "alice", "abc123").unwrap();
        assert!(consume_review_approved(home, "alice", "abc123"));
        assert!(!consume_review_approved(home, "alice", "abc123"));
    }
}
