//! Generic encoding helpers: hex and base64.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::ToolsError;

/// Encode bytes as 0x-prefixed lowercase hex.
pub fn hex_encode(data: &[u8]) -> String {
    format!("0x{}", hex::encode(data))
}

/// Decode a hex string (with or without 0x prefix) into bytes.
///
/// Strict: rejects internal whitespace and any non-hex characters.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, ToolsError> {
    let trimmed = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err(ToolsError::Hex(
            "whitespace not allowed in hex input".into(),
        ));
    }
    hex::decode(trimmed).map_err(|e| ToolsError::Hex(e.to_string()))
}

/// Encode bytes as standard base64 (with padding).
pub fn base64_encode(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

/// Decode a base64 string into bytes.
///
/// Strict: rejects internal whitespace.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, ToolsError> {
    if s.chars().any(|c| c.is_whitespace()) {
        return Err(ToolsError::Invalid(
            "whitespace not allowed in base64 input".into(),
        ));
    }
    BASE64_STANDARD
        .decode(s.as_bytes())
        .map_err(|e| ToolsError::Invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        assert_eq!(encoded, "0x68656c6c6f20776f726c64");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_no_prefix() {
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            hex_decode("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn hex_decode_strict_no_whitespace() {
        assert!(hex_decode("dead beef").is_err());
        assert!(hex_decode("0x dead").is_err());
    }

    #[test]
    fn base64_round_trip() {
        let data = b"hello world";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_decode_strict_no_whitespace() {
        // Standard "aGVsbG8=" with whitespace must fail under strict mode.
        assert!(base64_decode("aGVs bG8=").is_err());
        assert!(base64_decode("aGVsbG8=\n").is_err());
    }
}
