//! `Account` struct per bloom-chain spec §5.1.
//!
//! # SSZ layout (fixed-size, 89 bytes)
//!
//! | Field         | Bytes | Notes                                      |
//! |---------------|-------|--------------------------------------------|
//! | `nonce`       | 8     | u64 LE                                     |
//! | `loom`        | 16    | u128 LE (bloomweis)                        |
//! | code_present  | 1     | 0 = None, 1 = Some                         |
//! | `code_hash`   | 32    | only meaningful when code_present == 1     |
//! | `storage_root`| 32    | zero hash when no storage                  |
//!
//! Total: 89 bytes (fixed — no variable-length fields).

use bloom_chain_types::Hash32;
use ssz::{Decode, DecodeError, Encode};

/// An on-chain account (spec §5.1).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Account {
    /// Next expected tx nonce for this account (monotonic).
    pub nonce: u64,
    /// Native LOOM balance in bloomweis.
    pub loom: u128,
    /// `None` for EOAs; `Some(hash)` for petal contracts.
    pub code_hash: Option<Hash32>,
    /// Root of this account's storage trie (zero if empty).
    pub storage_root: Hash32,
}

impl Account {
    /// The canonical SSZ byte length for an `Account`.
    pub const SSZ_LEN: usize = 8 + 16 + 1 + 32 + 32;

    /// Construct the empty/zero account (spec §5.1 definition).
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            loom: 0,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
        }
    }

    /// True iff this account matches the empty-account definition:
    /// `nonce=0, loom=0, code_hash=None, storage_root=zero`.
    ///
    /// Empty accounts are not materialised in the trie (spec §5.1).
    pub fn is_empty(&self) -> bool {
        self.nonce == 0
            && self.loom == 0
            && self.code_hash.is_none()
            && self.storage_root == Hash32([0u8; 32])
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
        // loom (16 bytes LE)
        buf.extend_from_slice(&self.loom.to_le_bytes());
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
        let loom = u128::from_le_bytes(bytes[8..24].try_into().unwrap());

        let discriminant = bytes[24];
        let code_hash = match discriminant {
            0 => None,
            1 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes[25..57]);
                Some(Hash32(arr))
            }
            _ => {
                return Err(DecodeError::BytesInvalid(
                    format!("invalid code_hash discriminant: {discriminant}"),
                ));
            }
        };

        let mut storage_arr = [0u8; 32];
        storage_arr.copy_from_slice(&bytes[57..89]);
        let storage_root = Hash32(storage_arr);

        Ok(Account {
            nonce,
            loom,
            code_hash,
            storage_root,
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
        a.loom = 100;
        assert!(!a.is_empty());

        let mut b = Account::empty();
        b.nonce = 1;
        assert!(!b.is_empty());

        let mut c = Account::empty();
        c.code_hash = Some(Hash32([1u8; 32]));
        assert!(!c.is_empty());
    }

    #[test]
    fn ssz_roundtrip_eoa() {
        let a = Account {
            nonce: 42,
            loom: 1_000_000,
            code_hash: None,
            storage_root: Hash32([0u8; 32]),
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
            loom: 0,
            code_hash: Some(Hash32([0xAB; 32])),
            storage_root: Hash32([0xCD; 32]),
        };
        let bytes = a.as_ssz_bytes();
        assert_eq!(bytes.len(), Account::SSZ_LEN);
        let decoded = Account::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn ssz_rejects_bad_discriminant() {
        let mut bytes = Account::empty().as_ssz_bytes();
        bytes[24] = 2; // invalid discriminant
        assert!(Account::from_ssz_bytes(&bytes).is_err());
    }
}
