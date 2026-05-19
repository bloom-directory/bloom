//! Signature verifier trait and test implementations.
//!
//! This crate does not depend on bloom-keystore. The real xDSA verifier is
//! wired in by the node crate, which implements `SigVerifier` using the
//! actual ML-DSA-65 + Ed25519 composite scheme.

use bloom_chain_types::types::{PubKeyBytes, SigBytes};

/// Verify a signature over an arbitrary message.
///
/// Implementors must verify both components of the composite xDSA scheme
/// (ML-DSA-65 and Ed25519). Both must verify; failure of either fails the
/// whole check.
pub trait SigVerifier: Send + Sync + 'static {
    /// Returns `true` iff `sig` is a valid composite xDSA signature of `msg`
    /// under `pubkey`.
    fn verify(&self, pubkey: &PubKeyBytes, msg: &[u8], sig: &SigBytes) -> bool;
}

// ---------------------------------------------------------------------------
// Test implementations
// ---------------------------------------------------------------------------

/// A verifier that accepts every signature unconditionally.
///
/// Use in unit tests and simulations where cryptographic correctness is
/// not the property under test.
#[derive(Clone, Debug, Default)]
pub struct NoopVerifier;

impl SigVerifier for NoopVerifier {
    fn verify(&self, _pubkey: &PubKeyBytes, _msg: &[u8], _sig: &SigBytes) -> bool {
        true
    }
}

/// A verifier that rejects every signature.
///
/// Use in negative-path tests to confirm that invalid-signature paths are
/// exercised.
#[derive(Clone, Debug, Default)]
pub struct RejectAllVerifier;

impl SigVerifier for RejectAllVerifier {
    fn verify(&self, _pubkey: &PubKeyBytes, _msg: &[u8], _sig: &SigBytes) -> bool {
        false
    }
}
