//! Production PTB signature verifier.
//!
//! Implements [`bloom_script::SignatureVerifier`] using `ed25519-dalek`.
//!
//! # Why Ed25519 (and not the full xDSA composite)?
//!
//! The outer chain `Tx` envelope carries the **full** 1984-byte xDSA
//! composite public key (ML-DSA-65 + Ed25519) alongside its 3373-byte
//! signature (see `bloom_chain_node::consensus_driver::XdsaVerifier`).
//!
//! The PTB wire format, however, treats each `signers` slot as a fixed
//! 32-byte identifier (see `bloom_script::types::PqPubkey`'s docs and
//! spec §7.1) — far too small to embed a composite PQ key.
//!
//! Two designs are open for closing this gap:
//!
//! 1. **Phase-1 (this verifier).** Treat the 32-byte signer slot as a
//!    raw Ed25519 public key. The Ed25519 key length happens to be
//!    exactly 32 bytes, so the wire format fits without modification.
//!    Signers carry 64-byte Ed25519 signatures in
//!    `PtbTx.signatures[i]`. This is sufficient to enforce spec §7.2
//!    step 1 (the security goal of *this* P0-3 fix) today, and matches
//!    `AlwaysOkVerifier`'s test-side shape so existing PTB fixtures
//!    that already use 32-byte signer slots and 64-byte signature
//!    placeholders only need to swap stub bytes for real Ed25519 keys.
//! 2. **Phase-2 (planned).** Introduce a chain-resident map from the
//!    32-byte signer identifier (an *address*, derived from the full
//!    composite key per spec §4.3) to the full xDSA public key, and
//!    verify against the composite scheme. This matches the outer-tx
//!    envelope's PQ posture and is what the TODO in
//!    `petal_executor.rs:611-617` was tracking.
//!
//! Choosing (1) for Phase 1 lets the production path enforce
//! cryptographic signature checks **today** without (a) inventing an
//! on-chain registry the chain doesn't have yet or (b) widening the
//! PTB wire format. The Phase-2 migration is a verifier swap behind
//! the same [`SignatureVerifier`] trait.

use bloom_script::SignatureVerifier;
use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey as Ed25519VerifyingKey};

/// Production PTB signature verifier — Ed25519 over the PTB signing
/// digest. The 32-byte `pubkey` parameter is interpreted as an Ed25519
/// public key (see crate-level docs for the rationale and the planned
/// Phase-2 migration to composite xDSA via an on-chain key registry).
#[derive(Clone, Copy, Default, Debug)]
pub struct Ed25519PtbVerifier;

impl Ed25519PtbVerifier {
    /// Construct a stateless verifier.
    pub const fn new() -> Self {
        Self
    }
}

impl SignatureVerifier for Ed25519PtbVerifier {
    fn verify(&self, digest: &[u8; 32], pubkey: &[u8; 32], signature: &[u8]) -> bool {
        // Ed25519 signatures are fixed-length 64 bytes; reject anything
        // else without attempting key decode.
        let Ok(sig_arr): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        // Decoding fails for points outside the prime-order subgroup or
        // for non-canonical encodings — both are correctly rejected.
        let Ok(vk) = Ed25519VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let sig = Ed25519Sig::from_bytes(&sig_arr);
        vk.verify(digest, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn fresh_key_pair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn accepts_valid_signature() {
        let (sk, pk) = fresh_key_pair();
        let digest = [0x11u8; 32];
        let sig = sk.sign(&digest).to_bytes();
        let v = Ed25519PtbVerifier::new();
        assert!(v.verify(&digest, &pk, &sig));
    }

    #[test]
    fn rejects_flipped_signature_byte() {
        let (sk, pk) = fresh_key_pair();
        let digest = [0x11u8; 32];
        let mut sig = sk.sign(&digest).to_bytes();
        sig[0] ^= 0x01;
        let v = Ed25519PtbVerifier::new();
        assert!(!v.verify(&digest, &pk, &sig));
    }

    #[test]
    fn rejects_wrong_pubkey() {
        let (sk, _) = fresh_key_pair();
        let (_, wrong_pk) = fresh_key_pair();
        let digest = [0x11u8; 32];
        let sig = sk.sign(&digest).to_bytes();
        let v = Ed25519PtbVerifier::new();
        assert!(!v.verify(&digest, &wrong_pk, &sig));
    }

    #[test]
    fn rejects_signature_of_wrong_length() {
        let (sk, pk) = fresh_key_pair();
        let digest = [0x11u8; 32];
        let mut sig = sk.sign(&digest).to_bytes().to_vec();
        sig.push(0);
        let v = Ed25519PtbVerifier::new();
        assert!(!v.verify(&digest, &pk, &sig));
    }

    #[test]
    fn rejects_pubkey_that_is_not_a_valid_curve_point() {
        // All-zero bytes do not decode to a valid Ed25519 verifying key
        // (small-subgroup / identity rejection).
        let v = Ed25519PtbVerifier::new();
        assert!(!v.verify(&[0u8; 32], &[0u8; 32], &[0u8; 64]));
    }

    #[test]
    fn rejects_digest_mutation() {
        let (sk, pk) = fresh_key_pair();
        let digest = [0x11u8; 32];
        let sig = sk.sign(&digest).to_bytes();
        let mut bad_digest = digest;
        bad_digest[0] ^= 0xFF;
        let v = Ed25519PtbVerifier::new();
        assert!(!v.verify(&bad_digest, &pk, &sig));
    }
}
