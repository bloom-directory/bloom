//! `Account` struct per bloom-chain spec §5.1.
//!
//! # SSZ layout (fixed-size, 106 bytes)
//!
//! | Field              | Bytes | Notes                                  |
//! |--------------------|-------|----------------------------------------|
//! | `nonce`            | 8     | u64 LE                                 |
//! | code_present       | 1     | 0 = None, 1 = Some                     |
//! | `code_hash`        | 32    | only meaningful when code_present == 1 |
//! | `storage_root`     | 32    | zero hash when no storage              |
//! | manifest_present   | 1     | 0 = None, 1 = Some                     |
//! | `manifest_hash`    | 32    | meaningful when manifest_present == 1  |
//!
//! Total: 106 bytes (fixed — no variable-length fields). The
//! `manifest_hash` slot is the v1 on-chain anchor for off-chain manifest
//! verification. The chain does not interpret its bytes; off-chain tooling can
//! compare it against the blake3 of a published manifest.

use bloom_chain_types::Hash32;
use ssz::{Decode, DecodeError, Encode};

/// An on-chain account (spec §5.1).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Account {
    /// Next expected tx nonce for this account (monotonic).
    pub nonce: u64,
    /// `None` for EOAs; `Some(hash)` for petal contracts.
    pub code_hash: Option<Hash32>,
    /// Root of this account's storage trie (zero if empty).
    pub storage_root: Hash32,
    /// `None` for EOAs and contracts without an anchored manifest;
    /// `Some(hash)` when the publisher anchored a manifest. The chain does
    /// not interpret the bytes — off-chain tools verify a published manifest
    /// matches by recomputing its blake3.
    pub manifest_hash: Option<Hash32>,
}

impl Account {
    /// The canonical SSZ byte length for an `Account`.
    pub const SSZ_LEN: usize = 8 + 1 + 32 + 32 + 1 + 32;

    /// Construct the empty/zero account (spec §5.1 definition).
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        }
    }

    /// True iff this account matches the empty-account definition:
    /// `nonce=0, code_hash=None, storage_root=zero, manifest_hash=None`.
    ///
    /// Empty accounts are not materialised in the trie (spec §5.1).
    pub fn is_empty(&self) -> bool {
        self.nonce == 0
            && self.code_hash.is_none()
            && self.storage_root == Hash32([0u8; 32])
            && self.manifest_hash.is_none()
    }
}

// ---------------------------------------------------------------------------
// Manual SSZ Encode / Decode
// ---------------------------------------------------------------------------

impl Encode for Account {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        Self::SSZ_LEN
    }

    fn ssz_bytes_len(&self) -> usize {
        Self::SSZ_LEN
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // nonce (8 bytes LE)
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        // code_hash discriminant + bytes
        match &self.code_hash {
            None => {
                buf.push(0u8);
                buf.extend_from_slice(&[0u8; 32]);
            }
            Some(h) => {
                buf.push(1u8);
                buf.extend_from_slice(&h.0);
            }
        }
        // storage_root (32 bytes)
        buf.extend_from_slice(&self.storage_root.0);
        // manifest_hash discriminant + bytes
        match &self.manifest_hash {
            None => {
                buf.push(0u8);
                buf.extend_from_slice(&[0u8; 32]);
            }
            Some(h) => {
                buf.push(1u8);
                buf.extend_from_slice(&h.0);
            }
        }
    }
}

impl Decode for Account {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        Self::SSZ_LEN
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::SSZ_LEN {
            return Err(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: Self::SSZ_LEN,
            });
        }

        let nonce = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let discriminant = bytes[8];
        let code_hash = match discriminant {
            0 => None,
            1 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes[9..41]);
                Some(Hash32(arr))
            }
            _ => {
                return Err(DecodeError::BytesInvalid(format!(
                    "invalid code_hash discriminant: {discriminant}"
                )));
            }
        };

        let mut storage_arr = [0u8; 32];
        storage_arr.copy_from_slice(&bytes[41..73]);
        let storage_root = Hash32(storage_arr);

        let manifest_discriminant = bytes[73];
        let manifest_hash = match manifest_discriminant {
            0 => None,
            1 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes[74..106]);
                Some(Hash32(arr))
            }
            _ => {
                return Err(DecodeError::BytesInvalid(format!(
                    "invalid manifest_hash discriminant: {manifest_discriminant}"
                )));
            }
        };

        Ok(Account {
            nonce,
            code_hash,
            storage_root,
            manifest_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};

    #[test]
    fn empty_account_is_empty() {
        let a = Account::empty();
        assert!(a.is_empty());
    }

    #[test]
    fn non_empty_account_not_is_empty() {
        let mut a = Account::empty();
        a.nonce = 1;
        assert!(!a.is_empty());

        let mut b = Account::empty();
        b.code_hash = Some(Hash32([1u8; 32]));
        assert!(!b.is_empty());

        let mut c = Account::empty();
        c.manifest_hash = Some(Hash32([2u8; 32]));
        assert!(!c.is_empty());
    }

    #[test]
    fn ssz_roundtrip_eoa() {
        let a = Account {
            nonce: 42,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
            manifest_hash: None,
        };
        let bytes = a.as_ssz_bytes();
        assert_eq!(bytes.len(), Account::SSZ_LEN);
        let decoded = Account::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn ssz_roundtrip_contract() {
        let a = Account {
            nonce: 1,
            code_hash: Some(Hash32([0xAB; 32])),
            storage_root: Hash32([0xCD; 32]),
            manifest_hash: None,
        };
        let bytes = a.as_ssz_bytes();
        assert_eq!(bytes.len(), Account::SSZ_LEN);
        let decoded = Account::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn ssz_roundtrip_contract_with_manifest_hash() {
        let a = Account {
            nonce: 1,
            code_hash: Some(Hash32([0xAB; 32])),
            storage_root: Hash32([0xCD; 32]),
            manifest_hash: Some(Hash32([0xEF; 32])),
        };
        let bytes = a.as_ssz_bytes();
        assert_eq!(bytes.len(), Account::SSZ_LEN);
        let decoded = Account::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(a, decoded);
        assert_eq!(decoded.manifest_hash, Some(Hash32([0xEF; 32])));
    }

    #[test]
    fn ssz_rejects_bad_discriminant() {
        let mut bytes = Account::empty().as_ssz_bytes();
        bytes[8] = 2; // invalid code_hash discriminant
        assert!(Account::from_ssz_bytes(&bytes).is_err());
    }

    #[test]
    fn ssz_rejects_bad_manifest_discriminant() {
        let mut bytes = Account::empty().as_ssz_bytes();
        bytes[73] = 2; // invalid manifest_hash discriminant
        assert!(Account::from_ssz_bytes(&bytes).is_err());
    }
}
