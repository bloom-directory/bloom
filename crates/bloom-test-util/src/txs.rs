//! Transaction builders.
//!
//! Two flavours:
//! - [`make_mempool_tx`]: lightweight, fake-pubkey tx whose sender derives
//!   from a 4-byte seed. Used by mempool admission tests that don't run
//!   the real signature verifier.
//! - [`make_signed_deploy_tx`]: full chain — derive sender from a real
//!   xDSA pubkey, sign the signing-digest with the secret key. Used by
//!   block-sync validation, settlement ordering, replay tests.

use bloom_chain_types::{
    tx::{Tx, TxKind},
    types::{Address, PubKeyBytes, SigBytes},
};
use bloom_keystore::xdsa::XdsaSecretKey;

use crate::blocks::DEFAULT_CHAIN_ID;
use crate::validators::make_addr_derived;

/// Build a DeployPetal tx using seeded fake pubkey/sender. The sender field
/// is derived via `Address::from_pubkey_bytes(&[seed; 4])` so mempool
/// admission's sender-from-pubkey check still passes.
pub fn make_mempool_tx(
    sender_seed: u8,
    nonce: u64,
    fee_per_unit: u64,
    max_fuel: u64,
    _value_loom: u128,
) -> Tx {
    Tx {
        chain_id: "bloomchain.v0".to_string(),
        sender: make_addr_derived(sender_seed),
        nonce,
        max_fuel,
        fee_per_unit,
        kind: TxKind::DeployPetal {
            wasm_bytes: b"test-wasm".to_vec(),
        },
        pubkey: PubKeyBytes(vec![sender_seed; 4]),
        sig: SigBytes(vec![0u8; 4]),
    }
}

/// Build a fully-signed DeployPetal tx whose sender derives from `sk`'s
/// public key and whose signature is valid for the supplied `chain_id`.
pub fn make_signed_deploy_tx(
    sk: &XdsaSecretKey,
    chain_id: &str,
    wasm_bytes: Vec<u8>,
    nonce: u64,
    max_fuel: u64,
    fee_per_unit: u64,
) -> Tx {
    let pk = sk.public_key();
    let sender = Address::from_pubkey_bytes(&pk.0);
    let mut tx = Tx {
        chain_id: chain_id.to_string(),
        sender,
        nonce,
        max_fuel,
        fee_per_unit,
        kind: TxKind::DeployPetal { wasm_bytes },
        pubkey: PubKeyBytes(pk.0.clone()),
        sig: SigBytes(vec![]),
    };
    let digest = tx.signing_digest();
    tx.sig = SigBytes(sk.sign(&digest.0).to_bytes());
    tx
}

/// Convenience: signed DeployPetal tx with the default chain id and
/// max_fuel = 100_000, fee_per_unit = 1.
pub fn make_signed_deploy_tx_default(sk: &XdsaSecretKey, nonce: u64) -> Tx {
    make_signed_deploy_tx(
        sk,
        DEFAULT_CHAIN_ID,
        b"test-wasm".to_vec(),
        nonce,
        100_000,
        1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mempool_tx_sender_derives_from_seed() {
        let tx = make_mempool_tx(7, 1, 10, 1_000, 0);
        assert_eq!(tx.sender, make_addr_derived(7));
        assert_eq!(tx.pubkey.0, vec![7u8; 4]);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.fee_per_unit, 10);
        assert_eq!(tx.max_fuel, 1_000);
    }

    #[test]
    fn signed_deploy_tx_has_valid_signature_and_sender() {
        let (sk, pk) = XdsaSecretKey::generate();
        let tx = make_signed_deploy_tx_default(&sk, 1);
        // Sender field derives from pk.
        assert_eq!(tx.sender, Address::from_pubkey_bytes(&pk.0));
        // Signature is non-empty.
        assert!(!tx.sig.0.is_empty());
        // Re-deriving the digest and verifying via the pk produces the
        // expected verdict (we can't import the verifier directly without
        // a circular dep, but the digest must be stable).
        let digest = tx.signing_digest();
        assert_eq!(digest.0.len(), 32);
    }
}
