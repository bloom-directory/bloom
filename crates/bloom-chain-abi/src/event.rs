//! Event-topic derivation.
//!
//! An event topic prefix is the first 4 bytes of `blake3(event_signature)`,
//! the same rule used for method selectors. The signature is the canonical
//! event string, e.g. `"Transfer(address,address,u256)"`. Event log data is
//! packed by concatenating each declared field using the fixed-width rules
//! from `crate::encode` (address=32B, u256=32B, u128=16B, u64=8B, bool=1B).

extern crate alloc;

/// Derive a 4-byte event topic prefix from a canonical event signature.
pub fn event_topic(sig: &str) -> [u8; 4] {
    let h = blake3::hash(sig.as_bytes());
    let b = h.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

/// Derive a 4-byte event topic prefix from an event name and an ordered list
/// of canonical type-name strings.
///
/// `event_signature_topic("Transfer", &["address", "address", "u256"])`
/// reconstructs the canonical signature `"Transfer(address,address,u256)"`
/// before hashing. Shared by the `contract!` macro (for compile-time topic
/// derivation) and by tests verifying byte-compat with hand-rolled topic
/// tables.
pub fn event_signature_topic(name: &str, type_strs: &[&str]) -> [u8; 4] {
    let mut sig = alloc::string::String::with_capacity(
        name.len() + 2 + type_strs.iter().map(|t| t.len() + 1).sum::<usize>(),
    );
    sig.push_str(name);
    sig.push('(');
    for (i, t) in type_strs.iter().enumerate() {
        if i > 0 {
            sig.push(',');
        }
        sig.push_str(t);
    }
    sig.push(')');
    event_topic(&sig)
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

    #[test]
    fn signature_topic_builds_canonical_form() {
        let a = event_topic("Transfer(address,address,u256)");
        let b = event_signature_topic("Transfer", &["address", "address", "u256"]);
        assert_eq!(a, b);
    }

    #[test]
    fn signature_topic_empty_field_list() {
        let a = event_topic("Ping()");
        let b = event_signature_topic("Ping", &[]);
        assert_eq!(a, b);
    }
}
