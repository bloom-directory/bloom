//! Legacy-message construction for the Solana native transfer.
//!
//! Construction deliberately uses the pinned Anza reference crates
//! (`solana-message` + `solana-system-interface`) — the *construction parser*
//! — while the independent `solana-system-transfer-v1` verifier (compiled into
//! Broker, `bloom-solana` there) uses its own parser. The two must never share
//! parsing code; a bug in this constructor cannot silently pass the verifier
//! because the verifier re-parses from scratch.

use thiserror::Error;

/// Errors building the canonical legacy transfer message.
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("lamports amount is zero")]
    ZeroLamports,
    #[error("message is not a canonical legacy message: {0}")]
    MalformedMessage(String),
}

/// Build the canonical legacy single-signer System Program transfer message:
/// `account_keys = [fee_payer, destination, system_program]`, one
/// `transfer(lamports)` instruction, header `{ 1, 0, 1 }`, and the recent
/// blockhash. Returns the serialized message bytes — the exact Ed25519
/// signing input (Solana signs the raw message bytes; no pre-hash).
pub fn build_transfer_message(
    fee_payer: &[u8; 32],
    destination: &[u8; 32],
    lamports: u64,
    blockhash: &[u8; 32],
) -> Result<Vec<u8>, MessageError> {
    if lamports == 0 {
        return Err(MessageError::ZeroLamports);
    }
    use solana_message::{Address, Hash, Message};
    use solana_system_interface::instruction::transfer;

    let from = Address::from(*fee_payer);
    let to = Address::from(*destination);
    let blockhash = Hash::new_from_array(*blockhash);
    let instruction = transfer(&from, &to, lamports);
    let message = Message::new_with_blockhash(&[instruction], Some(&from), &blockhash);
    Ok(message.serialize())
}

/// Verify a 64-byte Ed25519 signature over the raw serialized message bytes
/// against the fee payer's public key — the local check Bloom performs before
/// recording a signature as valid (mirrors the honest-runtime proof: the
/// signature must verify over exactly the bytes the message encodes).
pub fn verify_signature(fee_payer: &[u8; 32], message_bytes: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(key) = VerifyingKey::from_bytes(fee_payer) else {
        return false;
    };
    key.verify(message_bytes, &Signature::from_bytes(signature))
        .is_ok()
}

/// Assemble the signed transaction — `[signature] || message` in the Solana
/// wire format (`sendTransaction`'s expected input). The message must be the
/// canonical legacy message the constructor produced.
pub fn assemble_transaction(
    message_bytes: &[u8],
    signature: &[u8; 64],
) -> Result<Vec<u8>, MessageError> {
    use solana_message::Message;
    use solana_transaction::{Signature, Transaction};
    let message: Message = wincode::deserialize(message_bytes)
        .map_err(|e| MessageError::MalformedMessage(e.to_string()))?;
    let transaction = Transaction {
        signatures: vec![Signature::from(*signature)],
        message,
    };
    wincode::serialize(&transaction).map_err(|e| MessageError::MalformedMessage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloom_broker_api::solana_vectors::{
        BLOCKHASH_HEX, DESTINATION, FEE_PAYER, LAMPORTS, MESSAGE_HEX, SIGNATURE_HEX,
    };

    fn base58_to_bytes(s: &str) -> [u8; 32] {
        bs58::decode(s).into_vec().unwrap().try_into().unwrap()
    }
    fn fee_payer() -> [u8; 32] {
        base58_to_bytes(FEE_PAYER)
    }
    fn destination() -> [u8; 32] {
        base58_to_bytes(DESTINATION)
    }
    fn blockhash() -> [u8; 32] {
        hex::decode(BLOCKHASH_HEX).unwrap().try_into().unwrap()
    }
    fn message_bytes() -> Vec<u8> {
        hex::decode(MESSAGE_HEX).unwrap()
    }
    fn signature() -> [u8; 64] {
        hex::decode(SIGNATURE_HEX).unwrap().try_into().unwrap()
    }

    #[test]
    fn reproduces_golden_message_bytes() {
        let bytes =
            build_transfer_message(&fee_payer(), &destination(), LAMPORTS, &blockhash()).unwrap();
        assert_eq!(hex::encode(&bytes), MESSAGE_HEX);
        assert_eq!(bytes.len(), 150);
    }

    #[test]
    fn rejects_zero_lamports() {
        assert!(matches!(
            build_transfer_message(&fee_payer(), &destination(), 0, &blockhash()),
            Err(MessageError::ZeroLamports)
        ));
    }

    #[test]
    fn golden_signature_verifies_over_raw_message() {
        assert!(verify_signature(
            &fee_payer(),
            &message_bytes(),
            &signature()
        ));
    }

    #[test]
    fn golden_signature_passes_anza_transaction_verify() {
        use solana_message::{Address, Hash, Message};
        use solana_system_interface::instruction::transfer;
        use solana_transaction::{Signature, Transaction};

        let from = Address::from(fee_payer());
        let to = Address::from(destination());
        let blockhash = Hash::new_from_array(blockhash());
        let ix = transfer(&from, &to, 1_000_000_000);
        let message = Message::new_with_blockhash(&[ix], Some(&from), &blockhash);
        let tx = Transaction {
            signatures: vec![Signature::from(signature())],
            message,
        };
        tx.verify()
            .expect("golden signature must verify against the Anza reference");
    }

    #[test]
    fn assembles_signed_transaction_that_verifies() {
        let tx_bytes = assemble_transaction(&message_bytes(), &signature()).unwrap();
        // The wire form `sendTransaction` accepts: a short-vec signature
        // count, the 64-byte signature, then the message.
        let transaction: solana_transaction::Transaction = wincode::deserialize(&tx_bytes).unwrap();
        transaction
            .verify()
            .expect("assembled transaction must verify");
        assert_eq!(transaction.signatures.len(), 1);
        assert_eq!(tx_bytes[0], 1, "single-signer signature count prefix");
        assert_eq!(
            &tx_bytes[1..65],
            &signature(),
            "signature follows the count"
        );
    }

    #[test]
    fn tampered_message_fails_verification() {
        let mut bytes = message_bytes();
        bytes[0] ^= 0xff;
        assert!(!verify_signature(&fee_payer(), &bytes, &signature()));
    }

    /// Deterministic pseudo-random sweep (the coverage-guided libFuzzer
    /// target in `fuzz/` is the real fuzzer; this runs in CI) proving the
    /// codec is total — no arbitrary input panics — and that successful
    /// constructor/assembler outputs round-trip through the pinned Anza
    /// reference.
    #[test]
    fn codec_is_total_on_arbitrary_input() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed_c0de);
        let fp = [0x11u8; 32];
        let dest = [0x22u8; 32];
        let blockhash = [0x42u8; 32];
        for _ in 0..500 {
            let mut data = vec![0u8; rng.gen_range(0..300)];
            rng.fill(&mut data[..]);
            let lamports = rng.r#gen::<u64>();
            if let Ok(message) = build_transfer_message(&fp, &dest, lamports, &blockhash) {
                let parsed: solana_message::Message = wincode::deserialize(&message).unwrap();
                assert_eq!(
                    parsed.serialize(),
                    message,
                    "non-canonical constructor output"
                );
            }
            let _ = verify_signature(&fp, &data, &[0u8; 64]);
            if let Ok(tx) = assemble_transaction(&data, &[0u8; 64]) {
                let parsed: solana_transaction::Transaction = wincode::deserialize(&tx).unwrap();
                assert_eq!(parsed.signatures.len(), 1);
            }
        }
    }
}
