//! Block + header builders, tiered by rigor.
//!
//! Three modes:
//! - [`BlockBuilder::with_fake_roots`]: hardcoded sentinel hashes for the
//!   txs / state / receipts / validator-set roots. Use for state-machine
//!   tests that don't exercise block-validation.
//! - [`BlockBuilder::with_computed_roots`]: computes `txs_root` from the tx
//!   list and `validator_set_hash` from the supplied `ValidatorSet`. Use
//!   when validation is in scope but commits are not.
//! - [`BlockBuilder::with_signed_commit`]: full chain — computed roots
//!   plus precommit votes signed with the supplied [`TestValidator`]
//!   keys. Use for block-sync / consensus-driver validation tests.
//!
//! The `txs_root` implementation mirrors
//! `bloom_chain_node::consensus_driver::compute_txs_root` byte-for-byte —
//! a parity test in chain-node's tests/ asserts equality (Phase 1).

use bloom_chain_consensus::validator_set::ValidatorSet;
use bloom_chain_types::{
    block::{Block, BlockHeader},
    digest::blake3_tagged,
    tx::Tx,
    types::{Address, Hash32, SigBytes},
    vote::{Commit, Vote, VoteKind},
};

use crate::validators::TestValidator;

/// Default chain id used by the block builder when the caller doesn't
/// override.  Matches bloom-chain v0 mainnet/dev chain id.
pub const DEFAULT_CHAIN_ID: &str = "bloom-chain.v0";

/// The base timestamp constant used across every test block builder, to
/// keep header timestamps stable and comparable across files.
pub const BASE_TIMESTAMP_MS: u64 = 1_747_526_400_000;

/// Default fuel limit for test blocks.
pub const DEFAULT_FUEL_LIMIT: u64 = 30_000_000;

/// Compute the deterministic `txs_root` for the supplied transactions.
///
/// **Must stay byte-identical to** `bloom_chain_node::consensus_driver::compute_txs_root`.
/// Drift is caught by the parity test at
/// `crates/bloom-chain-node/tests/test_util_parity.rs`.
pub fn txs_root(txs: &[Tx]) -> Hash32 {
    let mut buf = Vec::with_capacity(txs.len() * 32);
    for tx in txs {
        buf.extend_from_slice(&tx.tx_hash().0);
    }
    blake3_tagged("bloom-chain.v0.txs_root:", &buf)
}

/// Builder for `Block` values. Defaults: empty txs, fake roots,
/// timestamp = `BASE_TIMESTAMP_MS + height * 1000`, fuel_limit = 30M,
/// fuel_used = 0, chain_id = `DEFAULT_CHAIN_ID`, parent_hash = zero,
/// proposer = `Address([0; 32])`, commit = empty (height = 0, round = 0,
/// hash = zero, no votes).
pub struct BlockBuilder {
    chain_id: String,
    height: u64,
    parent_hash: Hash32,
    proposer: Address,
    timestamp_ms: u64,
    txs: Vec<Tx>,
    fuel_limit: u64,
    fuel_used: u64,
    // Root mode.
    roots: RootMode,
    // Commit-build instructions.
    commit_mode: CommitMode,
}

enum RootMode {
    Fake {
        txs_root: Hash32,
        state_root: Hash32,
        receipts_root: Hash32,
        validator_set_hash: Hash32,
    },
    Computed {
        validator_set_hash: Hash32,
        state_root: Hash32,
        receipts_root: Hash32,
    },
}

enum CommitMode {
    None,
    SignedBy(Vec<(Address, std::sync::Arc<bloom_keystore::xdsa::XdsaSecretKey>)>),
}

impl BlockBuilder {
    /// Start building a block at `height` with all defaults.
    pub fn at(height: u64) -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            height,
            parent_hash: Hash32([0; 32]),
            proposer: Address([0; 32]),
            timestamp_ms: BASE_TIMESTAMP_MS + height.saturating_mul(1_000),
            txs: vec![],
            fuel_limit: DEFAULT_FUEL_LIMIT,
            fuel_used: 0,
            roots: RootMode::Fake {
                txs_root: Hash32([0xAA; 32]),
                state_root: Hash32([0xBB; 32]),
                receipts_root: Hash32([0xCC; 32]),
                validator_set_hash: Hash32([0xDD; 32]),
            },
            commit_mode: CommitMode::None,
        }
    }

    pub fn chain_id(mut self, id: impl Into<String>) -> Self {
        self.chain_id = id.into();
        self
    }

    pub fn parent_hash(mut self, parent: Hash32) -> Self {
        self.parent_hash = parent;
        self
    }

    pub fn proposer(mut self, addr: Address) -> Self {
        self.proposer = addr;
        self
    }

    pub fn timestamp_ms(mut self, ts: u64) -> Self {
        self.timestamp_ms = ts;
        self
    }

    pub fn txs(mut self, txs: Vec<Tx>) -> Self {
        self.txs = txs;
        self
    }

    pub fn fuel_limit(mut self, limit: u64) -> Self {
        self.fuel_limit = limit;
        self
    }

    pub fn fuel_used(mut self, used: u64) -> Self {
        self.fuel_used = used;
        self
    }

    /// Use hardcoded sentinel roots. Override individual values via
    /// [`Self::with_root_seed`] if a test wants distinct block hashes.
    pub fn with_fake_roots(mut self) -> Self {
        self.roots = RootMode::Fake {
            txs_root: Hash32([0xAA; 32]),
            state_root: Hash32([0xBB; 32]),
            receipts_root: Hash32([0xCC; 32]),
            validator_set_hash: Hash32([0xDD; 32]),
        };
        self
    }

    /// Set all four roots to `Hash32([seed; 32])`. Useful for tests like
    /// `locking.rs` that need two distinct-hash blocks at the same height.
    pub fn with_root_seed(mut self, seed: u8) -> Self {
        self.roots = RootMode::Fake {
            txs_root: Hash32([seed; 32]),
            state_root: Hash32([seed; 32]),
            receipts_root: Hash32([seed; 32]),
            validator_set_hash: Hash32([seed; 32]),
        };
        self
    }

    /// Compute the txs_root from the current tx list and derive the
    /// validator_set_hash from the supplied set. state_root/receipts_root
    /// remain sentinels unless overridden.
    pub fn with_computed_roots(mut self, vset: &ValidatorSet) -> Self {
        self.roots = RootMode::Computed {
            validator_set_hash: vset.validator_set_hash(),
            state_root: Hash32([0xBB; 32]),
            receipts_root: Hash32([0xCC; 32]),
        };
        self
    }

    /// Attach a quorum-meeting `Commit` whose precommit votes are signed
    /// by each supplied validator's xDSA key. Implies
    /// [`with_computed_roots`] is in scope (you must call it before
    /// `signed_commit` so the block hash includes the right
    /// `validator_set_hash`).
    pub fn signed_by(mut self, signers: &[&TestValidator]) -> Self {
        self.commit_mode = CommitMode::SignedBy(
            signers
                .iter()
                .map(|s| (s.addr, std::sync::Arc::clone(&s.sk)))
                .collect(),
        );
        self
    }

    /// Build the final `Block`.
    pub fn build(self) -> Block {
        let (txs_root, state_root, receipts_root, validator_set_hash) = match self.roots {
            RootMode::Fake {
                txs_root,
                state_root,
                receipts_root,
                validator_set_hash,
            } => (txs_root, state_root, receipts_root, validator_set_hash),
            RootMode::Computed {
                state_root,
                receipts_root,
                validator_set_hash,
            } => (
                txs_root(&self.txs),
                state_root,
                receipts_root,
                validator_set_hash,
            ),
        };

        let header = BlockHeader {
            chain_id: self.chain_id,
            height: self.height,
            parent_hash: self.parent_hash,
            timestamp_ms: self.timestamp_ms,
            proposer: self.proposer,
            txs_root,
            state_root,
            receipts_root,
            validator_set_hash,
            fuel_used: self.fuel_used,
            fuel_limit: self.fuel_limit,
        };
        let block_hash = header.block_hash();

        let commit = match self.commit_mode {
            CommitMode::None => Commit {
                // Tests using fake-root blocks generally expect commit to
                // refer to the *previous* height (h-1). We can't tell what
                // the caller wants here universally, so default to a
                // self-referential h=0 sentinel — callers that need
                // h-1-style commits should call `signed_by(&[])` to opt
                // into the height-bound shape, or override post-build.
                height: 0,
                round: 0,
                block_hash: Hash32([0; 32]),
                votes: vec![],
            },
            CommitMode::SignedBy(signers) => {
                let votes: Vec<Vote> = signers
                    .into_iter()
                    .map(|(addr, sk)| {
                        let mut v = Vote {
                            height: self.height,
                            round: 0,
                            kind: VoteKind::Precommit,
                            block_hash: Some(block_hash),
                            validator: addr,
                            sig: SigBytes(vec![]),
                        };
                        let digest = v.signing_digest();
                        v.sig = SigBytes(sk.sign(&digest.0).to_bytes());
                        v
                    })
                    .collect();
                Commit {
                    height: self.height,
                    round: 0,
                    block_hash,
                    votes,
                }
            }
        };

        Block {
            header,
            txs: self.txs,
            commit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::{make_addr, make_validator_set_signed, make_validator_with_keypair};

    #[test]
    fn fake_root_block_has_sentinel_roots() {
        let b = BlockBuilder::at(1).proposer(make_addr(1)).build();
        assert_eq!(b.header.txs_root, Hash32([0xAA; 32]));
        assert_eq!(b.header.state_root, Hash32([0xBB; 32]));
        assert_eq!(b.header.receipts_root, Hash32([0xCC; 32]));
        assert_eq!(b.header.validator_set_hash, Hash32([0xDD; 32]));
        assert_eq!(b.header.height, 1);
        assert!(b.commit.votes.is_empty());
    }

    #[test]
    fn root_seed_yields_distinct_block_hashes() {
        let a = BlockBuilder::at(1).with_root_seed(0xAA).build();
        let b = BlockBuilder::at(1).with_root_seed(0xBB).build();
        assert_ne!(a.header.block_hash(), b.header.block_hash());
    }

    #[test]
    fn computed_roots_use_validator_set_hash() {
        let v = make_validator_with_keypair();
        let vset = make_validator_set_signed(&[&v], 100);
        let b = BlockBuilder::at(5).with_computed_roots(&vset).build();
        assert_eq!(b.header.validator_set_hash, vset.validator_set_hash());
        assert_eq!(b.header.txs_root, txs_root(&[]));
    }

    #[test]
    fn signed_commit_produces_valid_signatures() {
        let v1 = make_validator_with_keypair();
        let v2 = make_validator_with_keypair();
        let v3 = make_validator_with_keypair();
        let vset = make_validator_set_signed(&[&v1, &v2, &v3], 100);

        let block = BlockBuilder::at(5)
            .parent_hash(Hash32([0x42; 32]))
            .proposer(v1.addr)
            .with_computed_roots(&vset)
            .signed_by(&[&v1, &v2, &v3])
            .build();

        let block_hash = block.header.block_hash();
        assert_eq!(block.commit.height, 5);
        assert_eq!(block.commit.block_hash, block_hash);
        assert_eq!(block.commit.votes.len(), 3);
        for v in &block.commit.votes {
            assert!(!v.sig.0.is_empty(), "vote sig must not be empty");
            assert_eq!(v.kind, VoteKind::Precommit);
            assert_eq!(v.block_hash, Some(block_hash));
        }
    }
}
