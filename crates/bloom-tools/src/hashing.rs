//! Additional hash helpers: sha256, blake3.

use sha2::{Digest, Sha256};

/// SHA-256 of arbitrary bytes, returned as 0x-prefixed hex.
pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let out = hasher.finalize();
    format!("0x{}", hex::encode(out))
}

/// BLAKE3 of arbitrary bytes, returned as 0x-prefixed hex.
pub fn blake3_hex(input: &[u8]) -> String {
    let h = blake3::hash(input);
    format!("0x{}", hex::encode(h.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        // SHA-256 of empty string
        assert_eq!(
            sha256_hex(b""),
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn blake3_empty() {
        // BLAKE3 of empty string (32-byte output)
        assert_eq!(
            blake3_hex(b""),
            "0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }
}
