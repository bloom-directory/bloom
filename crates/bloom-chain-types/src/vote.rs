//! Consensus message types: `Vote`, `Proposal`, `Commit`.
//!
//! Tendermint-style BFT messages for bloom-chain v0 (spec §9).

use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder};

use crate::digest::{blake3_tagged, tags};
use crate::types::{Address, Hash32, SigBytes};

// ---------------------------------------------------------------------------
// VoteKind
// ---------------------------------------------------------------------------

/// The kind of a consensus vote.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

impl Encode for VoteKind {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn ssz_bytes_len(&self) -> usize {
        1
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            VoteKind::Prevote => buf.push(0),
            VoteKind::Precommit => buf.push(1),
        }
    }
}

impl Decode for VoteKind {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        1
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != 1 {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: 1,
            });
        }
        match bytes[0] {
            0 => Ok(VoteKind::Prevote),
            1 => Ok(VoteKind::Precommit),
            v => Err(DecodeError::BytesInvalid(format!(
                "unknown VoteKind byte: {v}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Vote
// ---------------------------------------------------------------------------

/// A single validator vote in the Tendermint-style BFT round.
///
/// `block_hash = None` indicates a nil vote.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub round: u32,
    pub kind: VoteKind,
    pub block_hash: Option<Hash32>,
    pub validator: Address,
    pub sig: SigBytes,
}

impl Vote {
    /// Returns the signing digest for this vote (spec §9):
    /// `blake3("bloom-chain.v0.vote:" || ssz_encode(vote_without_sig))`
    pub fn signing_digest(&self) -> Hash32 {
        let mut buf = Vec::new();
        encode_vote_presig(self, &mut buf);
        blake3_tagged(tags::VOTE, &buf)
    }
}

/// Encode the pre-signature portion of a Vote (all fields except `sig`).
fn encode_vote_presig(vote: &Vote, buf: &mut Vec<u8>) {
    // Fields: height (fixed 8), round (fixed 4), kind (fixed 1),
    //         block_hash (variable Option<Hash32>), validator (fixed 32)
    let fixed_len = 8 + 4 + 1 + 4 + 32usize; // 4 = offset for block_hash variable
    let mut enc = SszEncoder::container(buf, fixed_len);
    enc.append(&vote.height);
    enc.append(&vote.round);
    enc.append(&vote.kind);
    enc.append(&vote.block_hash);
    enc.append(&vote.validator);
    enc.finalize();
}

impl Encode for Vote {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // height(8) + round(4) + kind(1) + block_hash_offset(4) + validator(32) + sig_offset(4)
        // + block_hash_content + sig_content
        let block_hash_len = match &self.block_hash {
            None => 1,
            Some(_) => 1 + 32,
        };
        8 + 4 + 1 + 4 + 32 + 4 + block_hash_len + self.sig.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Fields: height(8), round(4), kind(1), block_hash(var), validator(32), sig(var)
        let fixed_len = 8 + 4 + 1 + 4 + 32 + 4usize;
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append(&self.height);
        enc.append(&self.round);
        enc.append(&self.kind);
        enc.append(&self.block_hash);
        enc.append(&self.validator);
        enc.append(&self.sig);
        enc.finalize();
    }
}

impl Decode for Vote {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<u64>()?; // height
        builder.register_type::<u32>()?; // round
        builder.register_type::<VoteKind>()?; // kind
        builder.register_type::<Option<Hash32>>()?; // block_hash
        builder.register_type::<Address>()?; // validator
        builder.register_type::<SigBytes>()?; // sig

        let mut decoder = builder.build()?;
        Ok(Vote {
            height: decoder.decode_next()?,
            round: decoder.decode_next()?,
            kind: decoder.decode_next()?,
            block_hash: decoder.decode_next()?,
            validator: decoder.decode_next()?,
            sig: decoder.decode_next()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Proposal
// ---------------------------------------------------------------------------

/// A block proposal broadcast by the round proposer.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash32,
    /// Polka round: `-1` means no polka round (no previous round's lock).
    pub pol_round: i32,
    pub proposer: Address,
    pub sig: SigBytes,
}

impl Proposal {
    /// Returns the signing digest for this proposal (spec §9):
    /// `blake3("bloom-chain.v0.proposal:" || ssz_encode(proposal_without_sig))`
    pub fn signing_digest(&self) -> Hash32 {
        let mut buf = Vec::new();
        encode_proposal_presig(self, &mut buf);
        blake3_tagged(tags::PROPOSAL, &buf)
    }
}

/// Encode the pre-signature portion of a Proposal (all fields except `sig`).
fn encode_proposal_presig(proposal: &Proposal, buf: &mut Vec<u8>) {
    // Fields: height (8) + round (4) + block_hash (32) + pol_round (4) + proposer (32).
    // All fixed-length, so encode flat (no offsets needed).
    let fixed_len = 8 + 4 + 32 + 4 + 32usize;
    let mut enc = SszEncoder::container(buf, fixed_len);
    enc.append(&proposal.height);
    enc.append(&proposal.round);
    enc.append(&proposal.block_hash);
    enc.append_parameterized(true, |b| {
        b.extend_from_slice(&proposal.pol_round.to_le_bytes());
    });
    enc.append(&proposal.proposer);
    enc.finalize();
}

impl Encode for Proposal {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // height(8) + round(4) + block_hash(32) + pol_round(4) + proposer(32) + sig_offset(4)
        8 + 4 + 32 + 4 + 32 + 4 + self.sig.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Fields: height(8), round(4), block_hash(32), pol_round(4), proposer(32), sig(var)
        let fixed_len = 8 + 4 + 32 + 4 + 32 + 4usize;
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append(&self.height);
        enc.append(&self.round);
        enc.append(&self.block_hash);
        // pol_round is i32; encode as little-endian 4 bytes (same as u32).
        enc.append_parameterized(true, |b| {
            b.extend_from_slice(&self.pol_round.to_le_bytes());
        });
        enc.append(&self.proposer);
        enc.append(&self.sig);
        enc.finalize();
    }
}

impl Decode for Proposal {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<u64>()?; // height
        builder.register_type::<u32>()?; // round
        builder.register_type::<Hash32>()?; // block_hash
        builder.register_type_parameterized(true, 4)?; // pol_round (i32)
        builder.register_type::<Address>()?; // proposer
        builder.register_type::<SigBytes>()?; // sig

        let mut decoder = builder.build()?;
        let height: u64 = decoder.decode_next()?;
        let round: u32 = decoder.decode_next()?;
        let block_hash: Hash32 = decoder.decode_next()?;
        let pol_round: i32 = decoder.decode_next_with(|b| {
            if b.len() != 4 {
                return Err(DecodeError::InvalidByteLength {
                    len: b.len(),
                    expected: 4,
                });
            }
            let mut arr = [0u8; 4];
            arr.copy_from_slice(b);
            Ok(i32::from_le_bytes(arr))
        })?;
        let proposer: Address = decoder.decode_next()?;
        let sig: SigBytes = decoder.decode_next()?;

        Ok(Proposal {
            height,
            round,
            block_hash,
            pol_round,
            proposer,
            sig,
        })
    }
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

/// A set of ≥ 2f+1 Precommit votes that finalised a block.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash32,
    pub votes: Vec<Vote>,
}

impl Encode for Commit {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        // height(8) + round(4) + block_hash(32) + votes_offset(4) + votes_content
        let votes_len: usize = self.votes.iter().map(|v| 4 + v.ssz_bytes_len()).sum();
        8 + 4 + 32 + 4 + votes_len
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // Fields: height(8), round(4), block_hash(32), votes(var)
        let fixed_len = 8 + 4 + 32 + 4usize;
        let mut enc = SszEncoder::container(buf, fixed_len);
        enc.append(&self.height);
        enc.append(&self.round);
        enc.append(&self.block_hash);
        enc.append(&self.votes);
        enc.finalize();
    }
}

impl Decode for Commit {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<u64>()?; // height
        builder.register_type::<u32>()?; // round
        builder.register_type::<Hash32>()?; // block_hash
        builder.register_type::<Vec<Vote>>()?; // votes

        let mut decoder = builder.build()?;
        Ok(Commit {
            height: decoder.decode_next()?,
            round: decoder.decode_next()?,
            block_hash: decoder.decode_next()?,
            votes: decoder.decode_next()?,
        })
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

    fn sample_vote() -> Vote {
        Vote {
            height: 10,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(Hash32([0xAB; 32])),
            validator: Address([0x01; 32]),
            sig: SigBytes(vec![0xCC; 16]),
        }
    }

    #[test]
    fn vote_kind_ssz_roundtrip() {
        for kind in [VoteKind::Prevote, VoteKind::Precommit] {
            let bytes = kind.as_ssz_bytes();
            assert_eq!(bytes.len(), 1);
            let decoded = VoteKind::from_ssz_bytes(&bytes).unwrap();
            assert_eq!(kind, decoded);
        }
    }

    #[test]
    fn vote_ssz_roundtrip() {
        let vote = sample_vote();
        let bytes = vote.as_ssz_bytes();
        let decoded = Vote::from_ssz_bytes(&bytes).expect("decode should succeed");
        assert_eq!(vote, decoded);
    }

    #[test]
    fn vote_nil_ssz_roundtrip() {
        let vote = Vote {
            block_hash: None,
            ..sample_vote()
        };
        let bytes = vote.as_ssz_bytes();
        let decoded = Vote::from_ssz_bytes(&bytes).expect("decode nil vote");
        assert_eq!(vote, decoded);
    }

    #[test]
    fn vote_signing_digest_is_stable() {
        let vote = sample_vote();
        assert_eq!(vote.signing_digest(), vote.signing_digest());
    }

    #[test]
    fn proposal_ssz_roundtrip() {
        let proposal = Proposal {
            height: 5,
            round: 1,
            block_hash: Hash32([0xBB; 32]),
            pol_round: -1,
            proposer: Address([0x02; 32]),
            sig: SigBytes(vec![0xDD; 8]),
        };
        let bytes = proposal.as_ssz_bytes();
        let decoded = Proposal::from_ssz_bytes(&bytes).expect("decode proposal");
        assert_eq!(proposal, decoded);
    }

    #[test]
    fn proposal_pol_round_positive() {
        let proposal = Proposal {
            height: 5,
            round: 2,
            block_hash: Hash32([0xBB; 32]),
            pol_round: 1,
            proposer: Address([0x02; 32]),
            sig: SigBytes(vec![0xDD; 8]),
        };
        let bytes = proposal.as_ssz_bytes();
        let decoded = Proposal::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(decoded.pol_round, 1);
    }

    #[test]
    fn commit_ssz_roundtrip() {
        let commit = Commit {
            height: 10,
            round: 0,
            block_hash: Hash32([0xCC; 32]),
            votes: vec![sample_vote(), sample_vote()],
        };
        let bytes = commit.as_ssz_bytes();
        let decoded = Commit::from_ssz_bytes(&bytes).expect("decode commit");
        assert_eq!(commit, decoded);
    }
}
