//! Signer trait used by the consensus engine to authenticate outgoing
//! Vote / Proposal messages.
//!
//! The consensus crate must not depend on `bloom-keystore`, so the real xDSA
//! signer lives in `bloom-chain-node`. This crate defines the trait the engine
//! uses, plus a no-op test signer.

use bloom_chain_types::types::SigBytes;

/// Sign an arbitrary message (typically the canonical signing digest of a
/// Vote or Proposal).
///
/// Returns the bytes that should populate the message's `sig` field. Real
/// production signers produce composite ML-DSA-65 + Ed25519 signatures via
/// `bloom-keystore::xdsa`; tests can use [`NoopSigner`] which produces empty
/// signatures.
pub trait Signer: Send + Sync + 'static {
    /// Sign `msg` and return the resulting [`SigBytes`].
    fn sign(&self, msg: &[u8]) -> SigBytes;
}

/// A signer that returns an empty signature. Use only in tests where the
/// signature path is not under test — the consensus engine treats `None`
/// signer equivalently in production paths.
#[derive(Clone, Debug, Default)]
pub struct NoopSigner;

impl Signer for NoopSigner {
    fn sign(&self, _msg: &[u8]) -> SigBytes {
        SigBytes(vec![])
    }
}
