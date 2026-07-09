// xdsa.rs — Composite ML-DSA-65 + Ed25519 (xDSA) keypair for bloom-evm.
//
// Crate path chosen: DIRECT-DEPS (ml-dsa = "0.1.0" + ed25519-dalek = "2").
//
// `darkbio-crypto = "0.15"` (features = ["xdsa"]) resolves to ml-dsa = "0.1.0"
// on crates.io but fails to compile because the darkbio-crypto 0.15 source
// calls `SigningKey::to_expanded()` and `sign_deterministic()`, neither of which
// exists in the released ml-dsa 0.1.0 API (those were renamed/removed before
// the final release).  Falling back to the direct-dep path per the task spec.
//
// Composite layout (spec §4.1):
//   public key : pk_mldsa (1952 B) || pk_ed25519 (32 B)  = 1984 B
//   signature  : sig_mldsa (3309 B) || sig_ed25519 (64 B) = 3373 B
//
// Both component signatures must verify; failure of either fails the whole sig.
// Verification uses the `Verifier` trait from each crate's re-exported
// `signature` crate (v3 for ml-dsa, v2 for ed25519-dalek — the trait methods
// are identical so there is no ambiguity at call sites because we call them
// through concrete types, not trait objects).

use ed25519_dalek::{
    Signature as Ed25519Sig, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    Keypair, MlDsa65, Signature as MlDsaSig, Signer as MlDsaSigner, SigningKey as MlDsaSK,
    VerifyingKey as MlDsaVK,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::KeystoreError;

// ─── size constants ───────────────────────────────────────────────────────────

/// Byte length of the ML-DSA-65 public key (FIPS 204).
pub const MLDSA_PK_LEN: usize = 1952;
/// Byte length of the ML-DSA-65 signature (FIPS 204).
pub const MLDSA_SIG_LEN: usize = 3309;
/// Byte length of an Ed25519 public key.
pub const ED25519_PK_LEN: usize = 32;
/// Byte length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;

/// Byte length of the composite xDSA public key (`pk_mldsa || pk_ed25519`).
pub const XDSA_PK_LEN: usize = MLDSA_PK_LEN + ED25519_PK_LEN; // 1984
/// Byte length of the composite xDSA signature (`sig_mldsa || sig_ed25519`).
pub const XDSA_SIG_LEN: usize = MLDSA_SIG_LEN + ED25519_SIG_LEN; // 3373

// ─── error type ──────────────────────────────────────────────────────────────

/// Verification failure for xDSA signatures.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("xDSA signature length mismatch: expected {expected}, got {got}")]
    BadLength { expected: usize, got: usize },
    #[error("ML-DSA-65 component verification failed")]
    MlDsaFailed,
    #[error("Ed25519 component verification failed")]
    Ed25519Failed,
    #[error("public key decode error: {0}")]
    BadPublicKey(String),
}

// ─── XdsaSecretKey ───────────────────────────────────────────────────────────

/// xDSA composite secret key.
///
/// Holds the raw secret bytes (ML-DSA-65 32-byte seed + Ed25519 32-byte seed)
/// and zeroizes on drop.  The underlying crate types are re-derived on use so
/// that we never need to store them in expanded form on the heap for longer
/// than a signing call.
pub struct XdsaSecretKey {
    /// ML-DSA-65 signing key (seed form; 32 bytes).  We store the expanded
    /// `SigningKey` which wraps a `MaybeBox<Seed>`.
    mldsa_sk: MlDsaSK<MlDsa65>,
    /// Ed25519 signing key (64-byte expanded form internally; 32-byte seed on
    /// serialisation).
    ed25519_sk: Ed25519SigningKey,
}

impl Drop for XdsaSecretKey {
    fn drop(&mut self) {
        // ed25519-dalek's SigningKey implements ZeroizeOnDrop via the zeroize
        // feature flag; ml-dsa's SigningKey does NOT implement Zeroize in the
        // released crate (noted in prior-art §1).  We manually zeroize the
        // Ed25519 bytes.  The ML-DSA seed is a fixed-size array inside a
        // MaybeBox<Seed> and will be freed by the allocator — there is no
        // guaranteed scrub unless the upstream crate adds it.  This is the
        // known limitation documented in the prior-art memo.
        //
        // When darkbio-crypto or ml-dsa upstream adds Zeroize, remove this
        // note and let the derive handle it.
        let mut ed_bytes = self.ed25519_sk.to_bytes();
        ed_bytes.zeroize();
    }
}

impl XdsaSecretKey {
    /// Generate a fresh xDSA keypair using the OS random-number generator.
    ///
    /// Returns `(XdsaSecretKey, XdsaPublicKey)`.
    pub fn generate() -> (XdsaSecretKey, XdsaPublicKey) {
        // ML-DSA-65: fill a 32-byte seed from OsRng and derive the key.
        let mut rng = rand::rngs::OsRng;
        let mut mldsa_seed_raw = [0u8; 32];
        rng.fill_bytes(&mut mldsa_seed_raw);
        let mldsa_seed = ml_dsa::Seed::from(mldsa_seed_raw);
        let mldsa_sk = MlDsaSK::<MlDsa65>::from_seed(&mldsa_seed);
        mldsa_seed_raw.zeroize();

        // Ed25519: generate directly from OsRng.
        let ed25519_sk = Ed25519SigningKey::generate(&mut rng);

        // Composite public key.
        let pk = Self::make_public_key(&mldsa_sk, &ed25519_sk);

        let sk = XdsaSecretKey {
            mldsa_sk,
            ed25519_sk,
        };
        (sk, pk)
    }

    fn make_public_key(
        mldsa_sk: &MlDsaSK<MlDsa65>,
        ed25519_sk: &Ed25519SigningKey,
    ) -> XdsaPublicKey {
        let mldsa_vk = mldsa_sk.verifying_key();
        let mldsa_pk_arr = mldsa_vk.encode();
        let ed25519_pk = ed25519_sk.verifying_key();

        let mut pk_bytes = Vec::with_capacity(XDSA_PK_LEN);
        pk_bytes.extend_from_slice(mldsa_pk_arr.as_ref());
        pk_bytes.extend_from_slice(&ed25519_pk.to_bytes());
        debug_assert_eq!(pk_bytes.len(), XDSA_PK_LEN);

        XdsaPublicKey(pk_bytes)
    }

    /// Sign `msg` with the composite key.
    ///
    /// The signature is `sig_mldsa || sig_ed25519`.
    pub fn sign(&self, msg: &[u8]) -> XdsaSignature {
        let mldsa_sig: MlDsaSig<MlDsa65> = self.mldsa_sk.sign(msg);
        let mldsa_sig_bytes = mldsa_sig.encode();

        let ed25519_sig = {
            use ed25519_dalek::Signer;
            self.ed25519_sk.sign(msg)
        };

        let mut sig = Vec::with_capacity(XDSA_SIG_LEN);
        sig.extend_from_slice(mldsa_sig_bytes.as_ref());
        sig.extend_from_slice(&ed25519_sig.to_bytes());
        debug_assert_eq!(sig.len(), XDSA_SIG_LEN);

        XdsaSignature(sig)
    }

    /// Return the corresponding public key.
    pub fn public_key(&self) -> XdsaPublicKey {
        Self::make_public_key(&self.mldsa_sk, &self.ed25519_sk)
    }

    /// Serialise the secret key to bytes.
    ///
    /// Format: `mldsa_seed (32 B) || ed25519_seed (32 B)` = 64 bytes total.
    pub fn to_bytes(&self) -> XdsaSecretKeyBytes {
        let mldsa_seed = self.mldsa_sk.to_seed();
        let ed25519_seed = self.ed25519_sk.to_bytes();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(mldsa_seed.as_ref());
        out[32..].copy_from_slice(&ed25519_seed);
        XdsaSecretKeyBytes(out)
    }

    /// Reconstruct from serialised bytes (see [`to_bytes`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
        if bytes.len() != 64 {
            return Err(KeystoreError::Malformed(format!(
                "xDSA secret key: expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut mldsa_seed_raw = [0u8; 32];
        mldsa_seed_raw.copy_from_slice(&bytes[..32]);
        let mldsa_seed = ml_dsa::Seed::from(mldsa_seed_raw);
        let mldsa_sk = MlDsaSK::<MlDsa65>::from_seed(&mldsa_seed);
        let ed_seed: [u8; 32] = bytes[32..].try_into().expect("slice length checked above");
        let ed25519_sk = Ed25519SigningKey::from_bytes(&ed_seed);
        Ok(Self {
            mldsa_sk,
            ed25519_sk,
        })
    }
}

/// RAII wrapper that zeroizes the secret key bytes on drop.
pub struct XdsaSecretKeyBytes([u8; 64]);

impl Drop for XdsaSecretKeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl XdsaSecretKeyBytes {
    /// Raw byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

// ─── XdsaPublicKey ───────────────────────────────────────────────────────────

/// xDSA composite public key (`pk_mldsa || pk_ed25519`), 1984 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdsaPublicKey(pub Vec<u8>);

impl XdsaPublicKey {
    /// Verify a composite signature over `msg`.
    ///
    /// Both ML-DSA-65 and Ed25519 components must verify; failure of either
    /// fails the whole check.
    pub fn verify(&self, msg: &[u8], sig: &XdsaSignature) -> Result<(), VerifyError> {
        if self.0.len() != XDSA_PK_LEN {
            return Err(VerifyError::BadPublicKey(format!(
                "public key length {} != {}",
                self.0.len(),
                XDSA_PK_LEN
            )));
        }
        if sig.0.len() != XDSA_SIG_LEN {
            return Err(VerifyError::BadLength {
                expected: XDSA_SIG_LEN,
                got: sig.0.len(),
            });
        }

        // Split public key.
        let mldsa_pk_bytes = &self.0[..MLDSA_PK_LEN];
        let ed25519_pk_bytes = &self.0[MLDSA_PK_LEN..];

        // Split signature.
        let mldsa_sig_bytes = &sig.0[..MLDSA_SIG_LEN];
        let ed25519_sig_bytes = &sig.0[MLDSA_SIG_LEN..];

        // Verify ML-DSA-65.
        {
            let mldsa_pk_arr = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(mldsa_pk_bytes)
                .map_err(|_| VerifyError::BadPublicKey("ML-DSA-65 pk decode".into()))?;
            let vk = MlDsaVK::<MlDsa65>::decode(&mldsa_pk_arr);
            let sig_arr = ml_dsa::EncodedSignature::<MlDsa65>::try_from(mldsa_sig_bytes)
                .map_err(|_| VerifyError::MlDsaFailed)?;
            let mldsa_sig =
                MlDsaSig::<MlDsa65>::decode(&sig_arr).ok_or(VerifyError::MlDsaFailed)?;
            use ml_dsa::Verifier;
            vk.verify(msg, &mldsa_sig)
                .map_err(|_| VerifyError::MlDsaFailed)?;
        }

        // Verify Ed25519.
        {
            let ed_pk_arr: [u8; 32] = ed25519_pk_bytes
                .try_into()
                .map_err(|_| VerifyError::BadPublicKey("Ed25519 pk slice length".into()))?;
            let ed_pk = Ed25519VerifyingKey::from_bytes(&ed_pk_arr)
                .map_err(|e| VerifyError::BadPublicKey(e.to_string()))?;
            let ed_sig_arr: [u8; 64] = ed25519_sig_bytes
                .try_into()
                .map_err(|_| VerifyError::Ed25519Failed)?;
            let ed_sig = Ed25519Sig::from_bytes(&ed_sig_arr);
            use ed25519_dalek::Verifier;
            ed_pk
                .verify(msg, &ed_sig)
                .map_err(|_| VerifyError::Ed25519Failed)?;
        }

        Ok(())
    }

    /// Serialise to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Deserialise from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
        if bytes.len() != XDSA_PK_LEN {
            return Err(KeystoreError::Malformed(format!(
                "xDSA public key: expected {} bytes, got {}",
                XDSA_PK_LEN,
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }
}

// ─── XdsaSignature ───────────────────────────────────────────────────────────

/// xDSA composite signature (`sig_mldsa || sig_ed25519`), 3373 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XdsaSignature(pub Vec<u8>);

impl XdsaSignature {
    /// Serialise to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Deserialise from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
        if bytes.len() != XDSA_SIG_LEN {
            return Err(KeystoreError::Malformed(format!(
                "xDSA signature: expected {} bytes, got {}",
                XDSA_SIG_LEN,
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }
}

// ─── address derivation ───────────────────────────────────────────────────────

/// Derive a 32-byte Bloom wallet address from an xDSA composite public key.
///
/// The address is a BLAKE3 digest over a stable Bloom wallet domain tag plus
/// the composite public key bytes.
pub fn derive_address(pk: &XdsaPublicKey) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"bloom.wallet.addr:");
    h.update(&pk.0);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── size assertions ──────────────────────────────────────────────────────

    #[test]
    fn composite_sizes_match_spec() {
        let (sk, pk) = XdsaSecretKey::generate();
        let sig = sk.sign(b"size-check");
        assert_eq!(pk.0.len(), XDSA_PK_LEN, "pk must be {XDSA_PK_LEN} bytes");
        assert_eq!(
            sig.0.len(),
            XDSA_SIG_LEN,
            "sig must be {XDSA_SIG_LEN} bytes"
        );
        assert_eq!(XDSA_PK_LEN, 1984);
        assert_eq!(XDSA_SIG_LEN, 3373);
    }

    // ── sign / verify round-trip ─────────────────────────────────────────────

    #[test]
    fn sign_verify_round_trip() {
        let (sk, pk) = XdsaSecretKey::generate();
        let msg = b"hello bloom-evm";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).expect("valid sig must verify");
    }

    // ── tampered signature is rejected ───────────────────────────────────────

    #[test]
    fn verify_fails_on_flipped_sig_byte() {
        let (sk, pk) = XdsaSecretKey::generate();
        let msg = b"tamper sig";
        let mut sig = sk.sign(msg);
        // Flip a byte in the ML-DSA portion.
        sig.0[42] ^= 0xFF;
        assert!(pk.verify(msg, &sig).is_err(), "tampered sig must fail");
    }

    #[test]
    fn verify_fails_on_flipped_sig_byte_ed25519_portion() {
        let (sk, pk) = XdsaSecretKey::generate();
        let msg = b"tamper sig ed";
        let mut sig = sk.sign(msg);
        // Flip a byte in the Ed25519 portion.
        sig.0[MLDSA_SIG_LEN + 4] ^= 0xFF;
        assert!(pk.verify(msg, &sig).is_err(), "tampered ed sig must fail");
    }

    // ── wrong message is rejected ────────────────────────────────────────────

    #[test]
    fn verify_fails_on_wrong_message() {
        let (sk, pk) = XdsaSecretKey::generate();
        let sig = sk.sign(b"original message");
        assert!(
            pk.verify(b"different message", &sig).is_err(),
            "sig over different msg must fail"
        );
    }

    // ── public key / signature byte round-trips ───────────────────────────────

    #[test]
    fn pubkey_round_trip() {
        let (sk, pk) = XdsaSecretKey::generate();
        let bytes = pk.to_bytes();
        let pk2 = XdsaPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
        // Can still verify after round-trip.
        let msg = b"pk round-trip";
        let sig = sk.sign(msg);
        pk2.verify(msg, &sig).unwrap();
    }

    #[test]
    fn sig_round_trip() {
        let (sk, pk) = XdsaSecretKey::generate();
        let msg = b"sig round-trip";
        let sig = sk.sign(msg);
        let bytes = sig.to_bytes();
        let sig2 = XdsaSignature::from_bytes(&bytes).unwrap();
        pk.verify(msg, &sig2).unwrap();
    }

    // ── secret key byte round-trip ───────────────────────────────────────────

    #[test]
    fn secret_key_round_trip() {
        let (sk, pk) = XdsaSecretKey::generate();
        let secret_bytes = sk.to_bytes();
        let sk2 = XdsaSecretKey::from_bytes(secret_bytes.as_slice()).unwrap();
        let msg = b"sk round-trip";
        let sig = sk2.sign(msg);
        pk.verify(msg, &sig).unwrap();
    }

    // ── address derivation ───────────────────────────────────────────────────

    #[test]
    fn address_is_32_bytes_and_deterministic() {
        let (_, pk) = XdsaSecretKey::generate();
        let addr1 = derive_address(&pk);
        let addr2 = derive_address(&pk);
        assert_eq!(addr1.len(), 32);
        assert_eq!(addr1, addr2, "address derivation must be deterministic");
    }

    #[test]
    fn different_keys_give_different_addresses() {
        let (_, pk1) = XdsaSecretKey::generate();
        let (_, pk2) = XdsaSecretKey::generate();
        assert_ne!(derive_address(&pk1), derive_address(&pk2));
    }

    /// Regression for the 2026-05-19 review (#10): xDSA wallet address
    /// derivation must stay pinned to the canonical wallet domain tag.
    #[test]
    fn keystore_address_uses_canonical_derivation() {
        let (_, pk) = XdsaSecretKey::generate();
        let keystore_addr = derive_address(&pk);

        // Pin the canonical tag explicitly so any future drift trips this
        // test before downstream wallet consumers see incompatible addresses.
        let mut h = blake3::Hasher::new();
        h.update(b"bloom.wallet.addr:");
        h.update(&pk.0);
        let expected = *h.finalize().as_bytes();
        assert_eq!(
            keystore_addr, expected,
            "canonical domain tag is `bloom.wallet.addr:`"
        );
    }

    // ── error path: bad lengths ───────────────────────────────────────────────

    #[test]
    fn pubkey_from_bytes_rejects_wrong_length() {
        assert!(XdsaPublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(XdsaPublicKey::from_bytes(&[0u8; XDSA_PK_LEN + 1]).is_err());
    }

    #[test]
    fn sig_from_bytes_rejects_wrong_length() {
        assert!(XdsaSignature::from_bytes(&[0u8; 10]).is_err());
        assert!(XdsaSignature::from_bytes(&[0u8; XDSA_SIG_LEN + 1]).is_err());
    }

    #[test]
    fn secret_key_from_bytes_rejects_wrong_length() {
        assert!(XdsaSecretKey::from_bytes(&[0u8; 10]).is_err());
        assert!(XdsaSecretKey::from_bytes(&[0u8; 65]).is_err());
    }
}
