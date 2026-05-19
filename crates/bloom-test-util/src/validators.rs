//! Address + validator-set builders.
//!
//! Two address shapes show up across the chain tests:
//!
//! - [`make_addr`]: `Address([seed; 32])` — used wherever the test doesn't
//!   need addresses derived from real pubkeys (consensus state-machine tests,
//!   round-robin proposer formulas, locking tests).
//! - [`make_addr_derived`]: `Address::from_pubkey_bytes(&[seed; 4])` — used
//!   by mempool tests where admission re-derives the sender from
//!   `tx.pubkey` and the seeded `pubkey` shape must hash to the same address.
//!
//! Real-key validators carry an [`Arc<XdsaSecretKey>`] and sign blocks via
//! [`super::TestSigner`].

use std::sync::Arc;

use bloom_chain_consensus::validator_set::{Validator, ValidatorSet};
use bloom_chain_types::types::{Address, PubKeyBytes};
use bloom_keystore::xdsa::{XdsaPublicKey, XdsaSecretKey};

/// Deterministic 32-byte address: every byte is `seed`.
pub fn make_addr(seed: u8) -> Address {
    Address([seed; 32])
}

/// Address derived from a 4-byte `[seed; 4]` pubkey, matching what mempool
/// admission computes when a tx carries `pubkey = vec![seed; 4]`. Useful
/// for tests that build txs with seeded fake pubkeys and need the sender
/// field to round-trip through `Address::from_pubkey_bytes`.
pub fn make_addr_derived(seed: u8) -> Address {
    Address::from_pubkey_bytes(&[seed; 4])
}

/// Build a validator set with `n` validators, each with `power` voting
/// power. Pubkeys are 4-byte `[i; 4]` placeholders — these validators
/// CANNOT sign real votes/commits. Use for state-machine tests where no
/// signature is exercised.
pub fn make_validator_set_fake(n: u8, power: u64) -> ValidatorSet {
    ValidatorSet::new(
        (0u8..n)
            .map(|i| Validator {
                address: make_addr(i),
                pubkey: PubKeyBytes(vec![i; 4]),
                voting_power: power,
            })
            .collect(),
    )
    .expect("fake validator set construction must succeed")
}

/// A validator with a real xDSA keypair, usable for block/commit signing.
#[derive(Clone)]
pub struct TestValidator {
    pub sk: Arc<XdsaSecretKey>,
    pub pk: XdsaPublicKey,
    pub addr: Address,
}

/// Mint a fresh xDSA keypair and derive the canonical chain address.
pub fn make_validator_with_keypair() -> TestValidator {
    let (sk, pk) = XdsaSecretKey::generate();
    let addr = Address::from_pubkey_bytes(&pk.0);
    TestValidator {
        sk: Arc::new(sk),
        pk,
        addr,
    }
}

/// Build a validator set from real-keypair validators, each with `power`.
pub fn make_validator_set_signed(vals: &[&TestValidator], power: u64) -> ValidatorSet {
    ValidatorSet::new(
        vals.iter()
            .map(|v| Validator {
                address: v.addr,
                pubkey: PubKeyBytes(v.pk.0.clone()),
                voting_power: power,
            })
            .collect(),
    )
    .expect("signed validator set construction must succeed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_addr_is_deterministic() {
        assert_eq!(make_addr(7), Address([7; 32]));
    }

    #[test]
    fn make_addr_derived_matches_pubkey_bytes_derivation() {
        let direct = Address::from_pubkey_bytes(&[3u8; 4]);
        assert_eq!(make_addr_derived(3), direct);
    }

    #[test]
    fn fake_validator_set_proposer_formula_works() {
        let vs = make_validator_set_fake(4, 100);
        // proposer_for(0, 0) = validators[0] = addr(0)
        assert_eq!(vs.proposer_for(0, 0).address, make_addr(0));
        assert_eq!(vs.proposer_for(1, 0).address, make_addr(1));
        assert_eq!(vs.proposer_for(3, 1).address, make_addr(0)); // (3+1)%4 = 0
    }

    #[test]
    fn signed_validator_set_uses_real_pubkeys() {
        let v1 = make_validator_with_keypair();
        let v2 = make_validator_with_keypair();
        let vset = make_validator_set_signed(&[&v1, &v2], 100);
        // Validator addresses are distinct (different keypairs).
        assert_ne!(v1.addr, v2.addr);
        // ValidatorSet contains both, in order.
        let proposer = vset.proposer_for(0, 0);
        assert_eq!(proposer.address, v1.addr);
    }
}
