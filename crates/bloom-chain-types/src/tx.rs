//! Transaction types for bloom-chain v0.
//!
//! The canonical encoding is SSZ (spec §7.2).  Signing and hashing use
//! domain-separated BLAKE3 (spec §7.3).

use serde::{Deserialize, Serialize};
use ssz::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder};

use crate::digest::{blake3_tagged, tags};
use crate::types::{
    decode_string, encode_string, Address, Hash32, PubKeyBytes, SigBytes,
};

// ---------------------------------------------------------------------------
// TxKind
// ---------------------------------------------------------------------------

/// The variant of a bloom-chain transaction (spec §7.1).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TxKind {
    /// Transfer native LOOM from sender to `to`.
    Transfer { to: Address, amount_loom: u128 },
    /// Deploy a new wasm petal (contract).
    Deploy {
        wasm: Vec<u8>,
        salt: [u8; 32],
        init_args: Vec<u8>,
    },
    /// Call an existing petal.
    Call {
        to: Address,
        calldata: Vec<u8>,
        value_loom: u128,
    },
}

/// Selector byte written as the first byte of a `TxKind` SSZ encoding.
/// Matches SSZ union convention: 0 = Transfer, 1 = Deploy, 2 = Call.
const TX_KIND_TRANSFER: u8 = 0;
const TX_KIND_DEPLOY: u8 = 1;
const TX_KIND_CALL: u8 = 2;

impl Encode for TxKind {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        1 + match self {
            TxKind::Transfer { .. } => {
                // to (32) + amount_loom (16)
                <Address as Encode>::ssz_fixed_len() + 16
            }
            TxKind::Deploy {
                wasm,
                salt: _,
                init_args,
            } => {
                // Variable: salt(32) is fixed, wasm and init_args are variable.
                // Body = 2 offsets (4 each) + 32 (salt) + wasm.len() + init_args.len()
                4 + 4 + 32 + wasm.len() + init_args.len()
            }
            TxKind::Call {
                calldata,
                value_loom: _,
                ..
            } => {
                // to (32, fixed) + offset for calldata (4) + value_loom (16) + calldata.len()
                32 + 4 + 16 + calldata.len()
            }
        }
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        match self {
            TxKind::Transfer { to, amount_loom } => {
                buf.push(TX_KIND_TRANSFER);
                to.ssz_append(buf);
                amount_loom.ssz_append(buf);
            }
            TxKind::Deploy {
                wasm,
                salt,
                init_args,
            } => {
                buf.push(TX_KIND_DEPLOY);
                // Container with salt (fixed), wasm (variable), init_args (variable).
                // Fixed portion: 2 variable offsets (4 bytes each) + 32 bytes salt = 40 bytes.
                let fixed_len = 4 + 4 + 32usize;
                let mut enc = SszEncoder::container(buf, fixed_len);
                enc.append(wasm);
                enc.append_parameterized(true, |b| b.extend_from_slice(salt));
                enc.append(init_args);
                enc.finalize();
            }
            TxKind::Call {
                to,
                calldata,
                value_loom,
            } => {
                buf.push(TX_KIND_CALL);
                // Container with to (fixed 32), calldata (variable), value_loom (fixed 16).
                let fixed_len = 32 + 4 + 16usize;
                let mut enc = SszEncoder::container(buf, fixed_len);
                enc.append(to);
                enc.append(calldata);
                enc.append(value_loom);
                enc.finalize();
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
            TX_KIND_TRANSFER => {
                // rest = to (32) || amount_loom (16)
                if rest.len() != 32 + 16 {
                    return Err(DecodeError::InvalidByteLength {
                        len: rest.len(),
                        expected: 48,
                    });
                }
                let to = Address::from_ssz_bytes(&rest[..32])?;
                let amount_loom = u128::from_ssz_bytes(&rest[32..48])?;
                Ok(TxKind::Transfer { to, amount_loom })
            }
            TX_KIND_DEPLOY => {
                // Container: wasm (var), salt (fixed 32), init_args (var)
                let mut builder = SszDecoderBuilder::new(rest);
                builder.register_type::<Vec<u8>>()?;
                builder.register_type_parameterized(true, 32)?;
                builder.register_type::<Vec<u8>>()?;
                let mut decoder = builder.build()?;
                let wasm: Vec<u8> = decoder.decode_next()?;
                let salt_bytes: Vec<u8> =
                    decoder.decode_next_with(|b| Ok(b.to_vec()))?;
                if salt_bytes.len() != 32 {
                    return Err(DecodeError::InvalidByteLength {
                        len: salt_bytes.len(),
                        expected: 32,
                    });
                }
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&salt_bytes);
                let init_args: Vec<u8> = decoder.decode_next()?;
                Ok(TxKind::Deploy {
                    wasm,
                    salt,
                    init_args,
                })
            }
            TX_KIND_CALL => {
                // Container: to (fixed 32), calldata (var), value_loom (fixed 16)
                let mut builder = SszDecoderBuilder::new(rest);
                builder.register_type::<Address>()?;
                builder.register_type::<Vec<u8>>()?;
                builder.register_type::<u128>()?;
                let mut decoder = builder.build()?;
                let to: Address = decoder.decode_next()?;
                let calldata: Vec<u8> = decoder.decode_next()?;
                let value_loom: u128 = decoder.decode_next()?;
                Ok(TxKind::Call {
                    to,
                    calldata,
                    value_loom,
                })
            }
            _ => Err(DecodeError::BytesInvalid(format!(
                "unknown TxKind selector: {selector}"
            ))),
        }
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
            kind: TxKind::Transfer {
                to: Address([2u8; 32]),
                amount_loom: 1_000_000_000_000_000_000u128,
            },
            pubkey: PubKeyBytes(vec![3u8; 16]),
            sig: SigBytes(vec![4u8; 16]),
        }
    }

    #[test]
    fn tx_transfer_ssz_roundtrip() {
        let tx = sample_tx();
        let bytes = tx.as_ssz_bytes();
        let decoded = Tx::from_ssz_bytes(&bytes).expect("decode should succeed");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn tx_deploy_ssz_roundtrip() {
        let tx = Tx {
            chain_id: "bloomchain.v0".to_string(),
            sender: Address([1u8; 32]),
            nonce: 2,
            max_fuel: 5_000_000,
            fee_per_unit: 2,
            kind: TxKind::Deploy {
                wasm: vec![0x00, 0x61, 0x73, 0x6d],
                salt: [0xAA; 32],
                init_args: vec![1, 2, 3],
            },
            pubkey: PubKeyBytes(vec![5u8; 16]),
            sig: SigBytes(vec![6u8; 16]),
        };
        let bytes = tx.as_ssz_bytes();
        let decoded = Tx::from_ssz_bytes(&bytes).expect("decode should succeed");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn tx_call_ssz_roundtrip() {
        let tx = Tx {
            chain_id: "bloomchain.v0".to_string(),
            sender: Address([1u8; 32]),
            nonce: 3,
            max_fuel: 2_000_000,
            fee_per_unit: 3,
            kind: TxKind::Call {
                to: Address([7u8; 32]),
                calldata: vec![0xDE, 0xAD, 0xBE, 0xEF],
                value_loom: 0,
            },
            pubkey: PubKeyBytes(vec![8u8; 16]),
            sig: SigBytes(vec![9u8; 16]),
        };
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
}
