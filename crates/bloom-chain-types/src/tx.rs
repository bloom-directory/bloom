//! Transaction types for bloom-chain v0.
//!
//! The canonical encoding is SSZ (spec §7.2).  Signing and hashing use
//! domain-separated BLAKE3 (spec §7.3).

use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder};

use crate::digest::{blake3_tagged, tags};
use crate::types::{Address, Hash32, PubKeyBytes, SigBytes, decode_string, encode_string};

// ---------------------------------------------------------------------------
// TxKind
// ---------------------------------------------------------------------------

/// The variant of a bloom-chain transaction.
///
/// Variant selectors are part of the wire format and must remain stable:
///
/// | selector | variant              |
/// |----------|----------------------|
/// | 0        | retired `Transfer`   |
/// | 1        | `SubmitPtb`          |
/// | 2        | `DeployPetal`        |
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TxKind {
    /// Submit a Programmable Transaction Block.
    ///
    /// # Why an opaque byte vector
    ///
    /// The structured PTB type (`bloom_script::types::PtbTx`) lives in
    /// the `bloom-script` crate, which already depends on
    /// `bloom-chain-types` for [`Hash32`]. Embedding `PtbTx` here
    /// directly would form a dependency cycle.
    ///
    /// The wire format is unaffected: `ptb_bytes` is the canonical
    /// PTB encoding (as produced by `bloom_script::encode_ptb`),
    /// length-prefixed by the SSZ container framing here. Higher
    /// layers (mempool, executor) decode via `bloom_script::decode_ptb`.
    ///
    /// The executor decodes and validates the inner PTB before running it atomically.
    SubmitPtb { ptb_bytes: Vec<u8> },
    /// Deploy a Bloom-native petal wasm module.
    ///
    /// The wasm must carry a `bloom_petal_manifest_v0` custom section. The
    /// executor stores the code by content hash and binds the manifest's
    /// `module_path` in the chain VFS registry.
    DeployPetal { wasm_bytes: Vec<u8> },
}

/// Retired selector byte for the removed native-LOOM `Transfer` transaction.
const TX_KIND_TRANSFER_RETIRED: u8 = 0;
/// Selector byte written as the first byte of a `TxKind` SSZ encoding.
/// Matches SSZ union convention: 1 = SubmitPtb, 2 = DeployPetal.
const TX_KIND_SUBMIT_PTB: u8 = 1;
const TX_KIND_DEPLOY_PETAL: u8 = 2;

impl Encode for TxKind {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        1 + match self {
            TxKind::SubmitPtb { ptb_bytes } => {
                // Single variable field: just the canonical PTB byte vector,
                // encoded as a top-level Vec<u8> in SSZ (length-prefixed by
                // the outer container framing in `from_ssz_bytes`).
                ptb_bytes.len()
            }
            TxKind::DeployPetal { wasm_bytes } => wasm_bytes.len(),
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            TxKind::SubmitPtb { ptb_bytes } => {
                buf.push(TX_KIND_SUBMIT_PTB);
                // Single variable field after the selector: the canonical
                // PTB bytes encoded as a bare SSZ Vec<u8>. The framing of
                // the outer `Tx` container already covers length-prefix
                // via the variable-field offset machinery, so here we
                // just append the raw bytes directly. Decode mirrors this
                // by reading the post-selector remainder as the full
                // ptb_bytes payload.
                buf.extend_from_slice(ptb_bytes);
            }
            TxKind::DeployPetal { wasm_bytes } => {
                buf.push(TX_KIND_DEPLOY_PETAL);
                buf.extend_from_slice(wasm_bytes);
            }
        }
    }
}

impl Decode for TxKind {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError::InvalidByteLength {
                len: 0,
                expected: 1,
            });
        }
        let selector = bytes[0];
        let rest = &bytes[1..];
        match selector {
            TX_KIND_TRANSFER_RETIRED => Err(DecodeError::BytesInvalid(
                "retired TxKind::Transfer selector".to_string(),
            )),
            TX_KIND_SUBMIT_PTB => {
                // The rest of the bytes are the canonical PTB byte vector.
                // No further framing — the outer SSZ container has already
                // length-delimited the kind's payload.
                Ok(TxKind::SubmitPtb {
                    ptb_bytes: rest.to_vec(),
                })
            }
            TX_KIND_DEPLOY_PETAL => Ok(TxKind::DeployPetal {
                wasm_bytes: rest.to_vec(),
            }),
            _ => Err(DecodeError::BytesInvalid(format!(
                "unknown TxKind selector: {selector}"
            ))),
        }
    }
}

impl TxKind {
    /// Returns `true` iff this transaction is a `SubmitPtb` (spec §16.1).
    ///
    /// Convenience for executor / mempool routing.
    pub fn is_submit_ptb(&self) -> bool {
        matches!(self, TxKind::SubmitPtb { .. })
    }

    pub fn is_deploy_petal(&self) -> bool {
        matches!(self, TxKind::DeployPetal { .. })
    }
}

// ---------------------------------------------------------------------------
// Tx — full transaction envelope
// ---------------------------------------------------------------------------

/// A bloom-chain transaction envelope (spec §7.1).
///
/// The `sig` field is excluded from the signing digest but included in the
/// tx hash.  See [`Tx::signing_digest`] and [`Tx::tx_hash`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub chain_id: String,
    pub sender: Address,
    pub nonce: u64,
    pub max_fuel: u64,
    pub fee_per_unit: u64,
    pub kind: TxKind,
    pub pubkey: PubKeyBytes,
    pub sig: SigBytes,
}

// ---------------------------------------------------------------------------
// Helper: encode the "pre-signature" portion of Tx (all fields except `sig`).
// ---------------------------------------------------------------------------

/// Encodes the tx fields that are covered by the signing digest, in SSZ format.
///
/// This is the portion that gets hashed for both `signing_digest` and `tx_hash`
/// (the difference is which tag is used, and for `tx_hash` the full `Tx` is hashed).
fn encode_tx_presig(tx: &Tx, buf: &mut Vec<u8>) {
    // Container with:
    //   chain_id    (variable, Vec<u8>)
    //   sender      (fixed 32)
    //   nonce       (fixed 8)
    //   max_fuel    (fixed 8)
    //   fee_per_unit (fixed 8)
    //   kind        (variable)
    //   pubkey      (variable)
    let fixed_len = 4 + 32 + 8 + 8 + 8 + 4 + 4usize; // offsets for variable fields + fixed
    let mut enc = SszEncoder::container(buf, fixed_len);
    // chain_id as UTF-8 bytes (variable)
    enc.append_parameterized(false, |b| encode_string(&tx.chain_id, b));
    // sender (fixed 32)
    enc.append(&tx.sender);
    // nonce (fixed 8)
    enc.append(&tx.nonce);
    // max_fuel (fixed 8)
    enc.append(&tx.max_fuel);
    // fee_per_unit (fixed 8)
    enc.append(&tx.fee_per_unit);
    // kind (variable)
    enc.append(&tx.kind);
    // pubkey (variable)
    enc.append(&tx.pubkey);
    enc.finalize();
}

impl Tx {
    /// Returns the signing digest per spec §7.3:
    /// `blake3("bloom-chain.v0.tx:" || ssz_encode(tx_without_sig))`
    ///
    /// This is what the xDSA key signs.
    pub fn signing_digest(&self) -> Hash32 {
        let mut buf = Vec::new();
        encode_tx_presig(self, &mut buf);
        blake3_tagged(tags::TX, &buf)
    }

    /// Returns the full tx hash per spec §7.2:
    /// `blake3("bloom-chain.v0.tx_hash:" || ssz_encode(tx))`
    pub fn tx_hash(&self) -> Hash32 {
        let bytes = self.as_ssz_bytes();
        blake3_tagged(tags::TX_HASH, &bytes)
    }
}

// ---------------------------------------------------------------------------
// SSZ Encode / Decode for Tx
// ---------------------------------------------------------------------------

impl Encode for Tx {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // Approximate: we need to account for fixed portions + variable portions.
        // Offsets: chain_id(4) + sender(32) + nonce(8) + max_fuel(8) + fee_per_unit(8)
        //        + kind(4) + pubkey(4) + sig(4) = variable offsets
        let fixed = 4 + 32 + 8 + 8 + 8 + 4 + 4 + 4usize;
        fixed
            + self.chain_id.len()
            + self.kind.ssz_bytes_len()
            + self.pubkey.ssz_bytes_len()
            + self.sig.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Container fields (in order):
        //   chain_id  (variable)
        //   sender    (fixed 32)
        //   nonce     (fixed 8)
        //   max_fuel  (fixed 8)
        //   fee_per_unit (fixed 8)
        //   kind      (variable)
        //   pubkey    (variable)
        //   sig       (variable)
        let fixed_len = 4 + 32 + 8 + 8 + 8 + 4 + 4 + 4usize;
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append_parameterized(false, |b| encode_string(&self.chain_id, b));
        enc.append(&self.sender);
        enc.append(&self.nonce);
        enc.append(&self.max_fuel);
        enc.append(&self.fee_per_unit);
        enc.append(&self.kind);
        enc.append(&self.pubkey);
        enc.append(&self.sig);
        enc.finalize();
    }
}

impl Decode for Tx {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        // chain_id (variable)
        builder.register_type::<Vec<u8>>()?;
        // sender (fixed 32)
        builder.register_type::<Address>()?;
        // nonce (fixed 8)
        builder.register_type::<u64>()?;
        // max_fuel (fixed 8)
        builder.register_type::<u64>()?;
        // fee_per_unit (fixed 8)
        builder.register_type::<u64>()?;
        // kind (variable)
        builder.register_type::<TxKind>()?;
        // pubkey (variable)
        builder.register_type::<PubKeyBytes>()?;
        // sig (variable)
        builder.register_type::<SigBytes>()?;

        let mut decoder = builder.build()?;
        let chain_id_bytes: Vec<u8> = decoder.decode_next()?;
        let chain_id = decode_string(&chain_id_bytes)?;
        let sender: Address = decoder.decode_next()?;
        let nonce: u64 = decoder.decode_next()?;
        let max_fuel: u64 = decoder.decode_next()?;
        let fee_per_unit: u64 = decoder.decode_next()?;
        let kind: TxKind = decoder.decode_next()?;
        let pubkey: PubKeyBytes = decoder.decode_next()?;
        let sig: SigBytes = decoder.decode_next()?;

        Ok(Tx {
            chain_id,
            sender,
            nonce,
            max_fuel,
            fee_per_unit,
            kind,
            pubkey,
            sig,
        })
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

    fn sample_tx() -> Tx {
        Tx {
            chain_id: "bloomchain.v0".to_string(),
            sender: Address([1u8; 32]),
            nonce: 1,
            max_fuel: 1_000_000,
            fee_per_unit: 1,
            kind: TxKind::SubmitPtb {
                ptb_bytes: b"sample-ptb".to_vec(),
            },
            pubkey: PubKeyBytes(vec![3u8; 16]),
            sig: SigBytes(vec![4u8; 16]),
        }
    }

    #[test]
    fn tx_ssz_roundtrip() {
        let tx = sample_tx();
        let bytes = tx.as_ssz_bytes();
        let decoded = Tx::from_ssz_bytes(&bytes).expect("decode should succeed");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn tx_signing_digest_is_stable() {
        let tx = sample_tx();
        let d1 = tx.signing_digest();
        let d2 = tx.signing_digest();
        assert_eq!(d1, d2, "signing_digest must be deterministic");
    }

    #[test]
    fn tx_hash_is_stable() {
        let tx = sample_tx();
        let h1 = tx.tx_hash();
        let h2 = tx.tx_hash();
        assert_eq!(h1, h2, "tx_hash must be deterministic");
    }

    #[test]
    fn signing_digest_differs_from_tx_hash() {
        let tx = sample_tx();
        assert_ne!(
            tx.signing_digest(),
            tx.tx_hash(),
            "signing digest and tx hash must use distinct domain tags"
        );
    }

    // -----------------------------------------------------------------------
    // SubmitPtb (spec §16.1, Phase 1 stub)
    // -----------------------------------------------------------------------

    fn sample_submit_ptb_tx() -> Tx {
        Tx {
            chain_id: "bloomchain.v0".to_string(),
            sender: Address([0x42u8; 32]),
            nonce: 7,
            max_fuel: 100_000,
            fee_per_unit: 1,
            kind: TxKind::SubmitPtb {
                // Opaque canonical PTB bytes. The decoder treats this as
                // a black box; only `bloom-script::decode_ptb` interprets.
                ptb_bytes: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            },
            pubkey: PubKeyBytes(vec![0xAAu8; 16]),
            sig: SigBytes(vec![0xBBu8; 16]),
        }
    }

    #[test]
    fn tx_submit_ptb_ssz_roundtrip() {
        let tx = sample_submit_ptb_tx();
        let bytes = tx.as_ssz_bytes();
        let decoded = Tx::from_ssz_bytes(&bytes).expect("decode should succeed");
        assert_eq!(tx, decoded);
        match &decoded.kind {
            TxKind::SubmitPtb { ptb_bytes } => {
                assert_eq!(ptb_bytes, &[0x01, 0x02, 0x03, 0x04, 0x05]);
            }
            other => panic!("expected SubmitPtb, got {other:?}"),
        }
    }

    #[test]
    fn tx_submit_ptb_kind_alone_ssz_roundtrip() {
        // The TxKind enum encodes selector + payload independently of
        // the outer Tx envelope; verify the union directly.
        let kind = TxKind::SubmitPtb {
            ptb_bytes: b"hello-ptb".to_vec(),
        };
        let bytes = kind.as_ssz_bytes();
        // First byte must be the selector (1).
        assert_eq!(bytes[0], TX_KIND_SUBMIT_PTB);
        let decoded = TxKind::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(kind, decoded);
    }

    #[test]
    fn tx_submit_ptb_empty_payload_roundtrip() {
        // Zero-length canonical PTB bytes still round-trip cleanly.
        let kind = TxKind::SubmitPtb { ptb_bytes: vec![] };
        let bytes = kind.as_ssz_bytes();
        let decoded = TxKind::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(kind, decoded);
    }

    #[test]
    fn tx_deploy_petal_kind_alone_ssz_roundtrip() {
        let kind = TxKind::DeployPetal {
            wasm_bytes: b"\0asm fake".to_vec(),
        };
        let bytes = kind.as_ssz_bytes();
        assert_eq!(bytes[0], TX_KIND_DEPLOY_PETAL);
        let decoded = TxKind::from_ssz_bytes(&bytes).expect("decode");
        assert_eq!(kind, decoded);
        assert!(decoded.is_deploy_petal());
    }

    #[test]
    fn tx_submit_ptb_selector_is_three() {
        // Wire-format anchor: retired Transfer, SubmitPtb, DeployPetal.
        assert_eq!(TX_KIND_TRANSFER_RETIRED, 0);
        assert_eq!(TX_KIND_SUBMIT_PTB, 1);
        assert_eq!(TX_KIND_DEPLOY_PETAL, 2);
    }

    #[test]
    fn retired_transfer_selector_is_rejected() {
        let mut retired = vec![TX_KIND_TRANSFER_RETIRED];
        retired.extend_from_slice(&[0u8; 48]);
        let err = TxKind::from_ssz_bytes(&retired).expect_err("must reject retired transfer");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("retired TxKind::Transfer selector"),
            "got: {msg}"
        );
    }

    #[test]
    fn tx_submit_ptb_hash_is_stable() {
        let tx = sample_submit_ptb_tx();
        let h1 = tx.tx_hash();
        let h2 = tx.tx_hash();
        assert_eq!(h1, h2, "tx_hash must be deterministic for SubmitPtb");
        // And the signing digest is independently stable + distinct.
        assert_ne!(
            tx.signing_digest(),
            tx.tx_hash(),
            "TX vs TX_HASH domain tags must keep digests apart"
        );
    }

    #[test]
    fn is_submit_ptb_helper() {
        let ptb = TxKind::SubmitPtb {
            ptb_bytes: vec![1, 2, 3],
        };
        assert!(ptb.is_submit_ptb());
    }

    #[test]
    fn unknown_selector_still_rejected() {
        // Defence: an unknown selector byte must error, not silently
        // round-trip as a new variant.
        let bad = [99u8, 0u8, 0u8, 0u8];
        let err = TxKind::from_ssz_bytes(&bad).expect_err("must reject unknown selector");
        let msg = format!("{err:?}");
        assert!(msg.contains("unknown TxKind selector"), "got: {msg}");
    }
}
