//! Event-topic derivation.
//!
//! An event topic prefix is the first 4 bytes of `blake3(event_signature)`,
//! the same rule used for method selectors. The signature is the canonical
//! event string, e.g. `"Transfer(address,address,u256)"`. Event log data is
//! packed by concatenating each declared field using the fixed-width rules
//! from `crate::encode` (address=32B, u256=32B, u128=16B, u64=8B, bool=1B).

/// Derive a 4-byte event topic prefix from a canonical event signature.
pub fn event_topic(sig: &str) -> [u8; 4] {
    let h = blake3::hash(sig.as_bytes());
    let b = h.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_is_blake3_prefix() {
        let sig = "Transfer(address,address,u256)";
        let s = event_topic(sig);
        let full = blake3::hash(sig.as_bytes());
        assert_eq!(&s[..], &full.as_bytes()[..4]);
    }

    #[test]
    fn topics_match_selector_rule() {
        // Same hashing rule used for method selectors.
        let s_method = crate::selector::selector("Transfer(address,address,u256)");
        let s_event = event_topic("Transfer(address,address,u256)");
        assert_eq!(s_method, s_event);
    }
}
