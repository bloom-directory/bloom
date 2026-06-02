//! Category: property
//!
//! End-to-end SSZ round-trip property tests and golden vectors.

use bloom_chain_types::frame::{FrameError, MAX_PAYLOAD_LEN, decode_frame, encode_frame};
use bloom_chain_types::receipt::{InvariantRecord, Log, Receipt, receipts_root};
use bloom_chain_types::ssz::{Decode, Encode};
use bloom_chain_types::tx::{Tx, TxKind};
use bloom_chain_types::types::{Address, Hash32, PubKeyBytes, SigBytes};
use bloom_chain_types::vote::{Vote, VoteKind};

use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Proptest strategies
// ---------------------------------------------------------------------------

fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    proptest::array::uniform32(any::<u8>())
}

fn arb_address() -> impl Strategy<Value = Address> {
    arb_bytes32().prop_map(Address)
}

fn arb_hash32() -> impl Strategy<Value = Hash32> {
    arb_bytes32().prop_map(Hash32)
}

fn arb_vec_u8(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max_len)
}

fn arb_pubkey() -> impl Strategy<Value = PubKeyBytes> {
    arb_vec_u8(64).prop_map(PubKeyBytes)
}

fn arb_sig() -> impl Strategy<Value = SigBytes> {
    arb_vec_u8(64).prop_map(SigBytes)
}

fn arb_tx_kind() -> impl Strategy<Value = TxKind> {
    prop_oneof![
        arb_vec_u8(256).prop_map(|ptb_bytes| TxKind::SubmitPtb { ptb_bytes }),
        arb_vec_u8(256).prop_map(|wasm_bytes| TxKind::DeployPetal { wasm_bytes }),
    ]
}

fn arb_tx() -> impl Strategy<Value = Tx> {
    (
        "[a-z]{3,16}",
        arb_address(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        arb_tx_kind(),
        arb_pubkey(),
        arb_sig(),
    )
        .prop_map(
            |(chain_id, sender, nonce, max_fuel, fee_per_unit, kind, pubkey, sig)| Tx {
                chain_id,
                sender,
                nonce,
                max_fuel,
                fee_per_unit,
                kind,
                pubkey,
                sig,
            },
        )
}

fn arb_vote_kind() -> impl Strategy<Value = VoteKind> {
    prop_oneof![Just(VoteKind::Prevote), Just(VoteKind::Precommit)]
}

fn arb_opt_hash32() -> impl Strategy<Value = Option<Hash32>> {
    prop_oneof![Just(None), arb_hash32().prop_map(Some)]
}

fn arb_vote() -> impl Strategy<Value = Vote> {
    (
        any::<u64>(),
        any::<u32>(),
        arb_vote_kind(),
        arb_opt_hash32(),
        arb_address(),
        arb_sig(),
    )
        .prop_map(|(height, round, kind, block_hash, validator, sig)| Vote {
            height,
            round,
            kind,
            block_hash,
            validator,
            sig,
        })
}

fn arb_log() -> impl Strategy<Value = Log> {
    (
        arb_address(),
        prop::collection::vec(arb_hash32(), 0..=4),
        arb_vec_u8(64),
    )
        .prop_map(|(address, topics, data)| Log {
            address,
            topics,
            data,
        })
}

fn arb_invariant_record() -> impl Strategy<Value = InvariantRecord> {
    (any::<u16>(), 0u8..=2, arb_vec_u8(32)).prop_map(|(cmd_idx, verdict, name)| InvariantRecord {
        cmd_idx,
        verdict,
        name,
    })
}

fn arb_receipt() -> impl Strategy<Value = Receipt> {
    (
        arb_hash32(),
        any::<bool>(),
        any::<u64>(),
        arb_vec_u8(64),
        prop::collection::vec(arb_log(), 0..=3),
        prop::collection::vec(arb_invariant_record(), 0..=3),
    )
        .prop_map(
            |(tx_hash, success, fuel_used, return_data, logs, invariant_outcomes)| Receipt {
                tx_hash,
                success,
                fuel_used,
                return_data,
                logs,
                invariant_outcomes,
            },
        )
}

// ---------------------------------------------------------------------------
// Property tests: SSZ round-trips
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_address_ssz_roundtrip(addr in arb_address()) {
        let bytes = addr.as_ssz_bytes();
        let decoded = Address::from_ssz_bytes(&bytes).unwrap();
        prop_assert_eq!(addr, decoded);
    }

    #[test]
    fn prop_hash32_ssz_roundtrip(h in arb_hash32()) {
        let bytes = h.as_ssz_bytes();
        let decoded = Hash32::from_ssz_bytes(&bytes).unwrap();
        prop_assert_eq!(h, decoded);
    }

    #[test]
    fn prop_address_display_parse_roundtrip(addr in arb_address()) {
        let s = addr.to_string();
        let parsed: Address = s.parse().unwrap();
        prop_assert_eq!(addr, parsed);
    }

    #[test]
    fn prop_tx_ssz_roundtrip(tx in arb_tx()) {
        let bytes = tx.as_ssz_bytes();
        let decoded = Tx::from_ssz_bytes(&bytes).expect("round-trip decode");
        prop_assert_eq!(tx, decoded);
    }

    #[test]
    fn prop_tx_signing_digest_stable(tx in arb_tx()) {
        // Encode/decode and verify digest is the same.
        let d1 = tx.signing_digest();
        let bytes = tx.as_ssz_bytes();
        let tx2 = Tx::from_ssz_bytes(&bytes).unwrap();
        let d2 = tx2.signing_digest();
        prop_assert_eq!(d1, d2);
    }

    #[test]
    fn prop_vote_ssz_roundtrip(vote in arb_vote()) {
        let bytes = vote.as_ssz_bytes();
        let decoded = Vote::from_ssz_bytes(&bytes).unwrap();
        prop_assert_eq!(vote, decoded);
    }

    #[test]
    fn prop_receipt_ssz_roundtrip(receipt in arb_receipt()) {
        let bytes = receipt.as_ssz_bytes();
        let decoded = Receipt::from_ssz_bytes(&bytes).unwrap();
        prop_assert_eq!(receipt, decoded);
    }

    #[test]
    fn prop_receipts_root_deterministic(receipts in prop::collection::vec(arb_receipt(), 0..=5)) {
        let r1 = receipts_root(&receipts);
        let r2 = receipts_root(&receipts);
        prop_assert_eq!(r1, r2);
    }

    #[test]
    fn prop_frame_roundtrip(payload in arb_vec_u8(1024)) {
        let framed = encode_frame(&payload).unwrap();
        let (consumed, decoded) = decode_frame(&framed).unwrap();
        prop_assert_eq!(consumed, framed.len());
        prop_assert_eq!(decoded, payload.as_slice());
    }
}

// ---------------------------------------------------------------------------
// Frame: specific rejection tests
// ---------------------------------------------------------------------------

#[test]
fn decode_frame_rejects_oversized() {
    let len_bytes = ((MAX_PAYLOAD_LEN + 1) as u32).to_be_bytes();
    let mut buf: Vec<u8> = len_bytes.to_vec();
    buf.extend(std::iter::repeat_n(0u8, MAX_PAYLOAD_LEN + 1));
    assert!(matches!(
        decode_frame(&buf),
        Err(FrameError::FrameLengthTooLarge { .. })
    ));
}

// ---------------------------------------------------------------------------
// Golden vector: fixed Tx + expected tx_hash
// ---------------------------------------------------------------------------

/// A hardcoded "golden" Tx used to catch future encoding drift.
///
/// If this test fails, the SSZ encoding or BLAKE3 domain tags have changed
/// in a consensus-breaking way.
#[test]
fn golden_tx_hash() {
    let tx = Tx {
        chain_id: "bloomchain.v0".to_string(),
        sender: Address([0u8; 32]),
        nonce: 1,
        max_fuel: 1_000_000,
        fee_per_unit: 1,
        kind: TxKind::SubmitPtb {
            ptb_bytes: b"golden-ptb".to_vec(),
        },
        pubkey: PubKeyBytes(vec![0xAB; 4]),
        sig: SigBytes(vec![0xCD; 4]),
    };

    // Compute the hash and record it. The first time this runs you'll see the
    // actual value; subsequent runs verify it hasn't changed.
    let hash = tx.tx_hash();
    let hash_hex = hex::encode(hash.0);

    // Golden value — generated from a reference run and locked here.
    // If you change the SSZ layout or domain tags, update this constant and
    // leave a comment explaining the reason.
    const GOLDEN_TX_HASH: &str = "714d072a4aba715910e0cbfed51066617ab9588ecacee7476099a412d8725a10";

    assert_eq!(
        hash_hex, GOLDEN_TX_HASH,
        "tx_hash golden vector mismatch — SSZ encoding or domain tag has changed!\n\
         Actual: {hash_hex}\n\
         Expected: {GOLDEN_TX_HASH}\n\
         If this is intentional, update GOLDEN_TX_HASH."
    );
}
