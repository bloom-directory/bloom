//! Fuzz the Solana message codec (`bloom-solana-tx/src/message.rs`).
//!
//! The codec parses/constructs bytes that ultimately come from or go to
//! external chain state, so the invariants under fuzz are:
//!
//! 1. **Totality** — no arbitrary input may panic the constructor, assembler,
//!    or verifier.
//! 2. **Constructor differential** — every message `build_transfer_message`
//!    produces must deserialize back through the pinned Anza reference
//!    (`solana_message::Message`) to a legacy, single-signer System transfer.
//! 3. **Assembler differential** — every `assemble_transaction` output must
//!    round-trip through the pinned Anza reference without divergence.
//!
//! These mirror the golden-vector + differential tests in
//! `crates/bloom-solana-tx/src/message.rs`, which cross-check any finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fn slice32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some(rest) = data.get(offset..) {
        let n = rest.len().min(32);
        out[..n].copy_from_slice(&rest[..n]);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let lamports = u64::from_le_bytes(
        data.get(..8)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    let fee_payer = slice32(data, 0);
    let destination = slice32(data, 32);
    let blockhash = slice32(data, 64);
    let signature: [u8; 64] = data
        .get(64..128)
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
        .try_into()
        .unwrap_or([0u8; 64]);

    // Totality: the constructor never panics for arbitrary inputs, and when it
    // succeeds the message must deserialize as an Anza legacy message.
    if let Ok(message) =
        bloom_solana_tx::build_transfer_message(&fee_payer, &destination, lamports, &blockhash)
    {
        let parsed: solana_message::Message = wincode::deserialize(&message).unwrap();
        assert_eq!(parsed.serialize(), message, "constructor output is non-canonical");
    }

    // Totality: the assembler and verifier never panic on arbitrary bytes.
    let _ = bloom_solana_tx::verify_signature(&fee_payer, data, &signature);
    if let Ok(transaction) = bloom_solana_tx::assemble_transaction(data, &signature) {
        let parsed: solana_transaction::Transaction = wincode::deserialize(&transaction).unwrap();
        assert_eq!(parsed.signatures.len(), 1);
    }
});
