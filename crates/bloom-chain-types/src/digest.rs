//! Domain-separated BLAKE3 helpers.
//!
//! The bloom-chain spec (§4.2) requires every digest to carry a domain tag:
//!
//! ```text
//! hash_kind(b) = BLAKE3("bloom-chain.v0." || kind || ":" || b)
//! ```
//!
//! The [`blake3_tagged`] helper implements this pattern.  All higher-level
//! functions in this crate call it rather than constructing raw BLAKE3 digests.

use crate::types::Hash32;

/// Compute a domain-separated BLAKE3 digest.
///
/// Hashes `tag.as_bytes() || payload` and returns the 32-byte result as a
/// [`Hash32`].  The `tag` should include any trailing colon, e.g. `"tx:"`.
pub fn blake3_tagged(tag: &str, payload: &[u8]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(tag.as_bytes());
    h.update(payload);
    Hash32(*h.finalize().as_bytes())
}

/// Domain tags used across the codebase (spec §4.2).
pub mod tags {
    pub const ADDR: &str = "bloom-chain.v0.addr:";
    pub const TX: &str = "bloom-chain.v0.tx:";
    pub const TX_HASH: &str = "bloom-chain.v0.tx_hash:";
    pub const BLOCK_HEADER: &str = "bloom-chain.v0.block_header:";
    pub const STATE_ROOT: &str = "bloom-chain.v0.state_root:";
    pub const PETAL: &str = "bloom-chain.v0.petal:";
    pub const STORAGE_KEY: &str = "bloom-chain.v0.storage_key:";
    pub const STORAGE_VALUE: &str = "bloom-chain.v0.storage_value:";
    pub const CODE_ROOT: &str = "bloom-chain.v0.code_root:";
    pub const ACCOUNTS_ROOT: &str = "bloom-chain.v0.accounts_root:";
    pub const RECEIPTS_ROOT: &str = "bloom-chain.v0.receipts_root:";
    pub const VOTE: &str = "bloom-chain.v0.vote:";
    pub const PROPOSAL: &str = "bloom-chain.v0.proposal:";
    pub const FRAME: &str = "bloom-chain.v0.frame:";

    // ----- Bloom-native contracts (spec §16.2, §16.3) -----
    //
    // Phase 1: tags are reserved. The Object and OwnershipIndex tries
    // are empty in Phase 1 (no PTBs are executed yet), so their roots
    // are zero, but the tag constants live here so commitments stay
    // domain-separated when Phase 2 activates real PTB execution.

    /// Root tag of the per-account Object trie. Mirrors
    /// `bloom_objects::store::OBJECT_ROOT_TAG`.
    pub const OBJECT_ROOT: &str = "bloom-chain.v0.object_root:";
    /// Value tag for leaves of the Object trie. Mirrors
    /// `bloom_objects::store::OBJECT_LEAF_TAG`.
    pub const OBJECT_LEAF: &str = "bloom-chain.v0.object_leaf:";
    /// Root tag of the per-account OwnershipIndex trie. Mirrors
    /// `bloom_objects::store::OWNERSHIP_ROOT_TAG`.
    pub const OWNERSHIP_ROOT: &str = "bloom-chain.v0.ownership_root:";
    /// Value tag for leaves of the OwnershipIndex trie. Mirrors
    /// `bloom_objects::store::OWNERSHIP_LEAF_TAG`.
    pub const OWNERSHIP_LEAF: &str = "bloom-chain.v0.ownership_leaf:";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_is_deterministic() {
        let a = blake3_tagged("tx:", b"hello");
        let b = blake3_tagged("tx:", b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn tag_distinguishes_same_payload() {
        let a = blake3_tagged("tx:", b"hello");
        let b = blake3_tagged("block_header:", b"hello");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_payload_works() {
        let h = blake3_tagged("tx:", b"");
        assert_ne!(h, Hash32([0u8; 32]));
    }
}
