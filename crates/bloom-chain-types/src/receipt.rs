//! Transaction receipts and logs for bloom-chain v0 (spec §8.3).

use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder};

use crate::digest::{blake3_tagged, tags};
use crate::types::{Address, Hash32};

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

/// A single log entry emitted by a petal during execution.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<Hash32>,
    pub data: Vec<u8>,
}

impl Encode for Log {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // address(32, fixed) + topics_offset(4) + data_offset(4)
        // + topics_content + data_content
        32 + 4 + 4 + self.topics.len() * 32 + self.data.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let fixed_len = 32 + 4 + 4usize;
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append(&self.address);
        enc.append(&self.topics);
        enc.append(&self.data);
        enc.finalize();
    }
}

impl Decode for Log {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<Address>()?; // address
        builder.register_type::<Vec<Hash32>>()?; // topics
        builder.register_type::<Vec<u8>>()?; // data

        let mut decoder = builder.build()?;
        Ok(Log {
            address: decoder.decode_next()?,
            topics: decoder.decode_next()?,
            data: decoder.decode_next()?,
        })
    }
}

// ---------------------------------------------------------------------------
// InvariantRecord
// ---------------------------------------------------------------------------

/// A single invariant evaluation recorded in a receipt (ADR-002). Lets a
/// receipt pinpoint which invariant was satisfied / violated / could not
/// be decided, so the social/trust-scoring layer reads verdicts directly
/// from consensus state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct InvariantRecord {
    /// Command index that triggered the evaluation.
    pub cmd_idx: u16,
    /// Verdict: 0 = satisfied, 1 = violated, 2 = indeterminate.
    pub verdict: u8,
    /// Invariant name (UTF-8 bytes; matches the `#[invariant]` attribute).
    pub name: Vec<u8>,
}

impl Encode for InvariantRecord {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // cmd_idx(2, fixed) + verdict(1, fixed) + name_offset(4) + name content
        2 + 1 + 4 + self.name.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let fixed_len = 2 + 1 + 4usize;
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append(&self.cmd_idx);
        enc.append(&self.verdict);
        enc.append(&self.name);
        enc.finalize();
    }
}

impl Decode for InvariantRecord {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<u16>()?; // cmd_idx
        builder.register_type::<u8>()?; // verdict
        builder.register_type::<Vec<u8>>()?; // name

        let mut decoder = builder.build()?;
        Ok(InvariantRecord {
            cmd_idx: decoder.decode_next()?,
            verdict: decoder.decode_next()?,
            name: decoder.decode_next()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

/// The receipt for a single executed transaction.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: Hash32,
    pub success: bool,
    pub fuel_used: u64,
    pub return_data: Vec<u8>,
    pub logs: Vec<Log>,
    /// Per-invariant verdicts recorded during execution (ADR-002),
    /// including on success. Empty for transactions that fire no invariants.
    ///
    /// NOTE: adding this field is a deliberate change to the SSZ `Receipt`
    /// encoding and therefore to `receipts_root` — a consensus-format break,
    /// not backward-compatible. Acceptable pre-mainnet; there is no version
    /// discriminant, so old and new receipts are not cross-decodable.
    pub invariant_outcomes: Vec<InvariantRecord>,
}

impl Encode for Receipt {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // tx_hash(32) + success(1) + fuel_used(8) + return_data_offset(4)
        // + logs_offset(4) + invariant_outcomes_offset(4)
        // + return_data.len() + logs_content + outcomes_content
        let logs_len: usize = self.logs.iter().map(|l| 4 + l.ssz_bytes_len()).sum();
        let outcomes_len: usize = self
            .invariant_outcomes
            .iter()
            .map(|r| 4 + r.ssz_bytes_len())
            .sum();
        32 + 1 + 8 + 4 + 4 + 4 + self.return_data.len() + logs_len + outcomes_len
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Fields: tx_hash(32), success(1), fuel_used(8), return_data(var),
        // logs(var), invariant_outcomes(var)
        let fixed_len = 32 + 1 + 8 + 4 + 4 + 4usize;
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append(&self.tx_hash);
        enc.append(&self.success);
        enc.append(&self.fuel_used);
        enc.append(&self.return_data);
        enc.append(&self.logs);
        enc.append(&self.invariant_outcomes);
        enc.finalize();
    }
}

impl Decode for Receipt {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<Hash32>()?; // tx_hash
        builder.register_type::<bool>()?; // success
        builder.register_type::<u64>()?; // fuel_used
        builder.register_type::<Vec<u8>>()?; // return_data
        builder.register_type::<Vec<Log>>()?; // logs
        builder.register_type::<Vec<InvariantRecord>>()?; // invariant_outcomes

        let mut decoder = builder.build()?;
        Ok(Receipt {
            tx_hash: decoder.decode_next()?,
            success: decoder.decode_next()?,
            fuel_used: decoder.decode_next()?,
            return_data: decoder.decode_next()?,
            logs: decoder.decode_next()?,
            invariant_outcomes: decoder.decode_next()?,
        })
    }
}

// ---------------------------------------------------------------------------
// receipts_root
// ---------------------------------------------------------------------------

/// Computes the receipts root for a block (spec §6.1):
/// `blake3("bloom-chain.v0.receipts_root:" || ssz_encode(receipts))`
///
/// For v0 this is a flat hash over the concatenated SSZ-encoded receipts,
/// not a Merkle tree.
pub fn receipts_root(receipts: &[Receipt]) -> Hash32 {
    // Encode as a variable-length list of receipts.
    let bytes = receipts.to_vec().as_ssz_bytes();
    blake3_tagged(tags::RECEIPTS_ROOT, &bytes)
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Hash32};
    use ssz::{Decode, Encode};

    fn sample_log() -> Log {
        Log {
            address: Address([0xAA; 32]),
            topics: vec![Hash32([0x01; 32]), Hash32([0x02; 32])],
            data: vec![1, 2, 3, 4, 5],
        }
    }

    fn sample_receipt() -> Receipt {
        Receipt {
            tx_hash: Hash32([0xBB; 32]),
            success: true,
            fuel_used: 50_000,
            return_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            logs: vec![sample_log()],
            invariant_outcomes: vec![InvariantRecord {
                cmd_idx: 3,
                verdict: 0,
                name: b"pool_k_non_decreasing".to_vec(),
            }],
        }
    }

    #[test]
    fn log_ssz_roundtrip() {
        let log = sample_log();
        let bytes = log.as_ssz_bytes();
        let decoded = Log::from_ssz_bytes(&bytes).expect("decode log");
        assert_eq!(log, decoded);
    }

    #[test]
    fn log_empty_topics_and_data() {
        let log = Log {
            address: Address([0u8; 32]),
            topics: vec![],
            data: vec![],
        };
        let bytes = log.as_ssz_bytes();
        let decoded = Log::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(log, decoded);
    }

    #[test]
    fn receipt_ssz_roundtrip() {
        let receipt = sample_receipt();
        let bytes = receipt.as_ssz_bytes();
        let decoded = Receipt::from_ssz_bytes(&bytes).expect("decode receipt");
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn receipt_failed_tx() {
        let receipt = Receipt {
            tx_hash: Hash32([0u8; 32]),
            success: false,
            fuel_used: 1_000_000,
            return_data: b"out of fuel".to_vec(),
            logs: vec![],
            // A violated invariant is recorded even on the failing receipt.
            invariant_outcomes: vec![InvariantRecord {
                cmd_idx: 0,
                verdict: 1,
                name: b"pool_k_non_decreasing".to_vec(),
            }],
        };
        let bytes = receipt.as_ssz_bytes();
        let decoded = Receipt::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn invariant_record_ssz_roundtrip() {
        for rec in [
            InvariantRecord {
                cmd_idx: 7,
                verdict: 2,
                name: b"guard".to_vec(),
            },
            InvariantRecord {
                cmd_idx: 0,
                verdict: 0,
                name: vec![],
            },
        ] {
            let bytes = rec.as_ssz_bytes();
            let decoded = InvariantRecord::from_ssz_bytes(&bytes).unwrap();
            assert_eq!(rec, decoded);
        }
    }

    #[test]
    fn receipt_empty_invariant_outcomes_roundtrip() {
        let receipt = Receipt {
            tx_hash: Hash32([0x07; 32]),
            success: true,
            fuel_used: 1,
            return_data: vec![],
            logs: vec![],
            invariant_outcomes: vec![],
        };
        let bytes = receipt.as_ssz_bytes();
        assert_eq!(Receipt::from_ssz_bytes(&bytes).unwrap(), receipt);
    }

    #[test]
    fn receipts_root_is_deterministic() {
        let receipts = vec![sample_receipt(), sample_receipt()];
        let r1 = receipts_root(&receipts);
        let r2 = receipts_root(&receipts);
        assert_eq!(r1, r2);
    }

    #[test]
    fn receipts_root_empty_list() {
        let empty: Vec<Receipt> = vec![];
        let h = receipts_root(&empty);
        // Should not panic and should return a valid hash.
        assert_ne!(h, Hash32([0u8; 32]));
    }
}
