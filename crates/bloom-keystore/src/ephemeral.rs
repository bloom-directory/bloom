//! Ephemeral agent (API-wallet) keys for bounded Hyperliquid sessions.
//!
//! A session approves a fresh Hyperliquid agent wallet that can **trade but not
//! withdraw** — so a leaked agent key can only place orders within the live
//! policy, never drain funds. The key is generated here and held by the daemon
//! **in memory** for the session's lifetime, then dropped on expiry/stop. Each
//! session generates a new key; addresses are never reused.
//!
//! At-rest persistence is optional via [`EphemeralAgentKey::seal`] /
//! [`EphemeralAgentKey::open`], which encrypt the raw key under a caller-held
//! 32-byte KEK (ChaCha20-Poly1305). The default daemon model is in-memory only
//! — nothing on disk to leak — but a daemon that wants sessions to survive a
//! restart can seal the key under a KEK it controls.

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use std::sync::Arc;

use crate::KeystoreError;

/// A freshly generated, daemon-held agent key. Cheap to clone (shares the
/// inner signer). The underlying k256 secret zeroizes when the last clone drops.
#[derive(Clone)]
pub struct EphemeralAgentKey {
    signer: Arc<PrivateKeySigner>,
}

impl EphemeralAgentKey {
    /// Generate a fresh agent key.
    pub fn generate() -> Self {
        Self {
            signer: Arc::new(PrivateKeySigner::random()),
        }
    }

    /// The agent wallet address (what gets approved on-chain via `approveAgent`).
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// A signer handle for trading through this agent.
    pub fn signer(&self) -> Arc<PrivateKeySigner> {
        self.signer.clone()
    }

    /// Encrypt the raw key under a 32-byte KEK. Layout: `nonce(12) || ct`.
    pub fn seal(&self, kek: &[u8; 32]) -> Result<Vec<u8>, KeystoreError> {
        let secret = self.signer.to_bytes(); // 32-byte field element
        let cipher = ChaCha20Poly1305::new(Key::from_slice(kek));
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), secret.as_slice())
            .map_err(|e| KeystoreError::Aead(e.to_string()))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Recover a sealed key with the same KEK. Fails on a wrong KEK / tampered
    /// blob (AEAD authentication).
    pub fn open(blob: &[u8], kek: &[u8; 32]) -> Result<Self, KeystoreError> {
        if blob.len() < 12 + 16 {
            return Err(KeystoreError::Aead("sealed agent key too short".into()));
        }
        let (nonce_bytes, ct) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(kek));
        // Hold the decrypted secret in a Zeroizing buffer so the plaintext is
        // wiped on drop (including the error paths below).
        let secret = zeroize::Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(nonce_bytes), ct)
                .map_err(|e| KeystoreError::Aead(e.to_string()))?,
        );
        let arr = zeroize::Zeroizing::new(
            <[u8; 32]>::try_from(secret.as_slice())
                .map_err(|_| KeystoreError::Aead("sealed agent key wrong length".into()))?,
        );
        let signer = PrivateKeySigner::from_bytes(&(*arr).into())
            .map_err(|e| KeystoreError::Signer(e.to_string()))?;
        Ok(Self {
            signer: Arc::new(signer),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_distinct_addresses() {
        let a = EphemeralAgentKey::generate();
        let b = EphemeralAgentKey::generate();
        assert_ne!(a.address(), b.address());
    }

    #[test]
    fn open_rejects_tampered_and_short_blobs() {
        let kek = [9u8; 32];
        let mut blob = EphemeralAgentKey::generate().seal(&kek).unwrap();
        // Flip a ciphertext byte → AEAD auth must fail.
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(EphemeralAgentKey::open(&blob, &kek).is_err());
        // Too-short blob is rejected before any decrypt.
        assert!(EphemeralAgentKey::open(&[0u8; 8], &kek).is_err());
    }

    #[test]
    fn seal_open_round_trips() {
        let kek = [7u8; 32];
        let key = EphemeralAgentKey::generate();
        let blob = key.seal(&kek).unwrap();
        let recovered = EphemeralAgentKey::open(&blob, &kek).unwrap();
        assert_eq!(recovered.address(), key.address());
    }

    #[test]
    fn open_with_wrong_kek_fails() {
        let key = EphemeralAgentKey::generate();
        let blob = key.seal(&[1u8; 32]).unwrap();
        assert!(EphemeralAgentKey::open(&blob, &[2u8; 32]).is_err());
    }
}
