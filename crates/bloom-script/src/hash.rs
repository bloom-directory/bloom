//! Signing-digest for a [`crate::types::PtbTx`] (spec §7.2 step 1).
//!
//! Signers cover the canonical encoding of the PTB with the
//! `signatures` field cleared. The resulting digest is wrapped in a
//! BLAKE3 domain tag so the bytes can never be replayed as some other
//! chain message.

use crate::encode::encode_ptb_without_sigs;
use crate::types::PtbTx;

/// Domain tag for the PTB signing digest (spec §7.2 step 1).
pub const PTB_HASH_TAG: &str = "bloom-chain.v0.ptb_hash:";

/// Compute `blake3_tagged(PTB_HASH_TAG, canonical_encode(tx_without_sigs))`.
///
/// The function panics only if the inner encoder hits a
/// length-overflow (a u32 byte-vec or u16 string length that does not
/// fit). In practice every PTB the chain accepts honours those widths
/// already (validator enforces an upper bound on command + arg counts).
pub fn ptb_hash(tx: &PtbTx) -> [u8; 32] {
    let mut buf = Vec::new();
    encode_ptb_without_sigs(&mut buf, tx).expect("PTB encoding within width bounds");
    let mut h = blake3::Hasher::new();
    h.update(PTB_HASH_TAG.as_bytes());
    h.update(&buf);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Command, MoveCmd, PetalRef};
    use bloom_chain_types::Hash32;
    use bloom_objects::ObjectId;

    fn sample() -> PtbTx {
        PtbTx {
            signers: vec![[1u8; 32]],
            commands: vec![Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/a".to_string(),
                    hash: Some(Hash32([0; 32])),
                },
                function: "f".to_string(),
                type_args: vec![],
                args: vec![],
            })],
            gas_payer: ObjectId([0; 32]),
            gas_budget: 1,
            gas_price: 1,
            expiry_block: 100,
            signatures: vec![],
        }
    }

    #[test]
    fn deterministic() {
        let tx = sample();
        assert_eq!(ptb_hash(&tx), ptb_hash(&tx));
    }

    #[test]
    fn signatures_excluded() {
        let mut a = sample();
        let mut b = sample();
        a.signatures = vec![crate::types::PqSignature(vec![1, 2, 3])];
        b.signatures = vec![crate::types::PqSignature(vec![9, 9, 9])];
        assert_eq!(
            ptb_hash(&a),
            ptb_hash(&b),
            "signature contents must not affect signing digest"
        );
    }

    #[test]
    fn signer_change_alters_digest() {
        let mut a = sample();
        let mut b = sample();
        a.signers = vec![[1u8; 32]];
        b.signers = vec![[2u8; 32]];
        assert_ne!(ptb_hash(&a), ptb_hash(&b));
    }

    #[test]
    fn command_change_alters_digest() {
        let a = sample();
        let mut b = sample();
        b.gas_budget = 999;
        assert_ne!(ptb_hash(&a), ptb_hash(&b));
    }

    #[test]
    fn tag_is_distinct() {
        // Different tag bytes must produce different digests for the same payload.
        let tx = sample();
        let mut buf = Vec::new();
        encode_ptb_without_sigs(&mut buf, &tx).unwrap();
        let with_tag = {
            let mut h = blake3::Hasher::new();
            h.update(PTB_HASH_TAG.as_bytes());
            h.update(&buf);
            *h.finalize().as_bytes()
        };
        let no_tag = *blake3::hash(&buf).as_bytes();
        assert_ne!(with_tag, no_tag);
    }

    #[test]
    fn tag_matches_spec() {
        assert_eq!(PTB_HASH_TAG, "bloom-chain.v0.ptb_hash:");
    }
}
