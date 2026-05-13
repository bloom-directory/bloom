//! EIP-137 namehash implementation.
//!
//! v1 normalizes via simple ASCII lowercase. Full UTS-46 normalization is
//! deferred — names containing non-ASCII or punycode-required characters
//! will produce a node that may or may not match the canonical ENS node
//! and should be rejected by the caller before reaching here.

use sha3::{Digest, Keccak256};

/// Compute the EIP-137 namehash of an ENS name.
///
/// `namehash("")` returns the zero node. Each label is lowercased (ASCII)
/// and keccak256'd, then folded into the parent node:
///
/// `node = keccak256(parent || keccak256(label))`
pub fn namehash(name: &str) -> [u8; 32] {
    let mut node = [0u8; 32];
    if name.is_empty() {
        return node;
    }
    // Iterate labels in reverse (TLD first).
    let lower = name.to_ascii_lowercase();
    for label in lower.split('.').rev() {
        let label_hash = keccak256(label.as_bytes());
        let mut hasher = Keccak256::new();
        hasher.update(node);
        hasher.update(label_hash);
        node = hasher.finalize().into();
    }
    node
}

/// Compute keccak256 of a byte slice.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let v = hex::decode(s).expect("valid hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn empty_name_is_zero_node() {
        assert_eq!(namehash(""), [0u8; 32]);
    }

    #[test]
    fn eth_tld() {
        assert_eq!(
            namehash("eth"),
            hex32("0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae")
        );
    }

    #[test]
    fn foo_dot_eth() {
        assert_eq!(
            namehash("foo.eth"),
            hex32("0xde9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f")
        );
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(namehash("FOO.ETH"), namehash("foo.eth"));
        assert_eq!(namehash("Foo.Eth"), namehash("foo.eth"));
    }
}
