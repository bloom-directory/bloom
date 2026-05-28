//! Block header and block types for bloom-chain v0 (spec §8).

use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder};

use crate::digest::{blake3_tagged, tags};
use crate::tx::Tx;
use crate::types::{Address, Hash32, decode_string, encode_string};
use crate::vote::Commit;

// ---------------------------------------------------------------------------
// BlockHeader
// ---------------------------------------------------------------------------

/// The header of a bloom-chain block (spec §8.1).
///
/// `block_hash()` hashes the SSZ-encoded header with the `block_header` domain.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub chain_id: String,
    pub height: u64,
    pub parent_hash: Hash32,
    pub timestamp_ms: u64,
    pub proposer: Address,
    pub txs_root: Hash32,
    pub state_root: Hash32,
    pub receipts_root: Hash32,
    pub validator_set_hash: Hash32,
    pub fuel_used: u64,
    pub fuel_limit: u64,
}

impl BlockHeader {
    /// Returns the block hash per spec §8.1:
    /// `blake3("bloom-chain.v0.block_header:" || ssz_encode(header))`
    pub fn block_hash(&self) -> Hash32 {
        let bytes = self.as_ssz_bytes();
        blake3_tagged(tags::BLOCK_HEADER, &bytes)
    }
}

impl Encode for BlockHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // chain_id(offset=4) + height(8) + parent_hash(32) + timestamp_ms(8)
        // + proposer(32) + txs_root(32) + state_root(32) + receipts_root(32)
        // + validator_set_hash(32) + fuel_used(8) + fuel_limit(8)
        // + chain_id.len() (variable)
        4 + 8 + 32 + 8 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + self.chain_id.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // chain_id (variable), all others fixed.
        let fixed_len = 4 + 8 + 32 + 8 + 32 + 32 + 32 + 32 + 32 + 8 + 8usize;
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append_parameterized(false, |b| encode_string(&self.chain_id, b));
        enc.append(&self.height);
        enc.append(&self.parent_hash);
        enc.append(&self.timestamp_ms);
        enc.append(&self.proposer);
        enc.append(&self.txs_root);
        enc.append(&self.state_root);
        enc.append(&self.receipts_root);
        enc.append(&self.validator_set_hash);
        enc.append(&self.fuel_used);
        enc.append(&self.fuel_limit);
        enc.finalize();
    }
}

impl Decode for BlockHeader {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<Vec<u8>>()?; // chain_id
        builder.register_type::<u64>()?; // height
        builder.register_type::<Hash32>()?; // parent_hash
        builder.register_type::<u64>()?; // timestamp_ms
        builder.register_type::<Address>()?; // proposer
        builder.register_type::<Hash32>()?; // txs_root
        builder.register_type::<Hash32>()?; // state_root
        builder.register_type::<Hash32>()?; // receipts_root
        builder.register_type::<Hash32>()?; // validator_set_hash
        builder.register_type::<u64>()?; // fuel_used
        builder.register_type::<u64>()?; // fuel_limit

        let mut decoder = builder.build()?;
        let chain_id_bytes: Vec<u8> = decoder.decode_next()?;
        let chain_id = decode_string(&chain_id_bytes)?;
        Ok(BlockHeader {
            chain_id,
            height: decoder.decode_next()?,
            parent_hash: decoder.decode_next()?,
            timestamp_ms: decoder.decode_next()?,
            proposer: decoder.decode_next()?,
            txs_root: decoder.decode_next()?,
            state_root: decoder.decode_next()?,
            receipts_root: decoder.decode_next()?,
            validator_set_hash: decoder.decode_next()?,
            fuel_used: decoder.decode_next()?,
            fuel_limit: decoder.decode_next()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Block
// ---------------------------------------------------------------------------

/// A full bloom-chain block (header + txs + commit).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
    pub commit: Commit,
}

impl Encode for Block {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // All three fields are variable-length.
        4 + 4
            + 4
            + self.header.ssz_bytes_len()
            + self.txs.ssz_bytes_len()
            + self.commit.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let fixed_len = 4 + 4 + 4usize; // three offsets
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append(&self.header);
        enc.append(&self.txs);
        enc.append(&self.commit);
        enc.finalize();
    }
}

impl Decode for Block {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<BlockHeader>()?;
        builder.register_type::<Vec<Tx>>()?;
        builder.register_type::<Commit>()?;

        let mut decoder = builder.build()?;
        Ok(Block {
            header: decoder.decode_next()?,
            txs: decoder.decode_next()?,
            commit: decoder.decode_next()?,
        })
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{Tx, TxKind};
    use crate::types::{Address, Hash32, PubKeyBytes, SigBytes};
    use crate::vote::{Commit, Vote, VoteKind};
    use ssz::{Decode, Encode};

    fn sample_header() -> BlockHeader {
        BlockHeader {
            chain_id: "bloomchain.v0".to_string(),
            height: 1,
            parent_hash: Hash32([0u8; 32]),
            timestamp_ms: 1_747_526_400_000,
            proposer: Address([0x01; 32]),
            txs_root: Hash32([0x02; 32]),
            state_root: Hash32([0x03; 32]),
            receipts_root: Hash32([0x04; 32]),
            validator_set_hash: Hash32([0x05; 32]),
            fuel_used: 100_000,
            fuel_limit: 30_000_000,
        }
    }

    fn sample_commit() -> Commit {
        Commit {
            height: 1,
            round: 0,
            block_hash: Hash32([0xBB; 32]),
            votes: vec![Vote {
                height: 1,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some(Hash32([0xBB; 32])),
                validator: Address([0x10; 32]),
                sig: SigBytes(vec![0xFF; 8]),
            }],
        }
    }

    #[test]
    fn block_header_ssz_roundtrip() {
        let hdr = sample_header();
        let bytes = hdr.as_ssz_bytes();
        let decoded = BlockHeader::from_ssz_bytes(&bytes).expect("decode header");
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn block_hash_is_deterministic() {
        let hdr = sample_header();
        assert_eq!(hdr.block_hash(), hdr.block_hash());
    }

    #[test]
    fn block_hash_changes_with_content() {
        let hdr1 = sample_header();
        let mut hdr2 = sample_header();
        hdr2.height = 2;
        assert_ne!(hdr1.block_hash(), hdr2.block_hash());
    }

    #[test]
    fn block_ssz_roundtrip() {
        let tx = Tx {
            chain_id: "bloomchain.v0".to_string(),
            sender: Address([1u8; 32]),
            nonce: 1,
            max_fuel: 1_000_000,
            fee_per_unit: 1,
            kind: TxKind::SubmitPtb {
                ptb_bytes: b"sample-ptb".to_vec(),
            },
            pubkey: PubKeyBytes(vec![3u8; 8]),
            sig: SigBytes(vec![4u8; 8]),
        };
        let block = Block {
            header: sample_header(),
            txs: vec![tx],
            commit: sample_commit(),
        };
        let bytes = block.as_ssz_bytes();
        let decoded = Block::from_ssz_bytes(&bytes).expect("decode block");
        assert_eq!(block, decoded);
    }
}
