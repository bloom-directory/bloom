//! Production PTB signature verifier.
//!
//! PTB signer slots are fixed 32-byte values. In production they are Bloom
//! addresses, not embedded public keys. The verifier resolves each address
//! through chain state's xDSA key registry, then verifies the full composite
//! ML-DSA-65 + Ed25519 signature over the canonical PTB signing digest.

use bloom_chain_state::State;
use bloom_chain_types::types::Address;
use bloom_keystore::xdsa::{XdsaPublicKey, XdsaSignature};
use bloom_script::SignatureVerifier;

/// Production PTB signature verifier: signer slot = address, signature =
/// composite xDSA signature, public key = resolved from chain key registry.
pub struct XdsaPtbVerifier<'a> {
    state: &'a State,
}

impl<'a> XdsaPtbVerifier<'a> {
    /// Construct a verifier over the current chain state.
    pub const fn new(state: &'a State) -> Self {
        Self { state }
    }
}

impl SignatureVerifier for XdsaPtbVerifier<'_> {
    fn verify(&self, digest: &[u8; 32], signer: &[u8; 32], signature: &[u8]) -> bool {
        let addr = Address(*signer);
        let Some(pubkey) = self.state.get_pubkey(&addr) else {
            return false;
        };
        let Ok(pk) = XdsaPublicKey::from_bytes(&pubkey.0) else {
            return false;
        };
        let Ok(sig) = XdsaSignature::from_bytes(signature) else {
            return false;
        };
        pk.verify(digest, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_keystore::xdsa::XdsaSecretKey;

    fn state_with_key() -> (State, XdsaSecretKey, Address) {
        let (sk, pk) = XdsaSecretKey::generate();
        let addr = Address::from_pubkey_bytes(&pk.0);
        let mut state = State::new();
        state.register_pubkey(addr, bloom_chain_types::types::PubKeyBytes(pk.to_bytes()));
        (state, sk, addr)
    }

    #[test]
    fn accepts_valid_xdsa_signature_from_registered_key() {
        let (state, sk, addr) = state_with_key();
        let digest = [0x11u8; 32];
        let sig = sk.sign(&digest).to_bytes();

        assert!(XdsaPtbVerifier::new(&state).verify(&digest, &addr.0, &sig));
    }

    #[test]
    fn rejects_flipped_signature_byte() {
        let (state, sk, addr) = state_with_key();
        let digest = [0x11u8; 32];
        let mut sig = sk.sign(&digest).to_bytes();
        sig[0] ^= 0x01;

        assert!(!XdsaPtbVerifier::new(&state).verify(&digest, &addr.0, &sig));
    }

    #[test]
    fn rejects_unregistered_signer_address() {
        let (_state_with_key, sk, _addr) = state_with_key();
        let empty_state = State::new();
        let digest = [0x11u8; 32];
        let sig = sk.sign(&digest).to_bytes();

        assert!(!XdsaPtbVerifier::new(&empty_state).verify(&digest, &[0x55; 32], &sig));
    }

    #[test]
    fn rejects_signature_of_wrong_length() {
        let (state, sk, addr) = state_with_key();
        let digest = [0x11u8; 32];
        let mut sig = sk.sign(&digest).to_bytes();
        sig.push(0);

        assert!(!XdsaPtbVerifier::new(&state).verify(&digest, &addr.0, &sig));
    }

    #[test]
    fn rejects_digest_mutation() {
        let (state, sk, addr) = state_with_key();
        let digest = [0x11u8; 32];
        let sig = sk.sign(&digest).to_bytes();
        let mut bad_digest = digest;
        bad_digest[0] ^= 0xFF;

        assert!(!XdsaPtbVerifier::new(&state).verify(&bad_digest, &addr.0, &sig));
    }
}
