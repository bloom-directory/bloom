//! Method-selector derivation.
//!
//! A selector is the first 4 bytes of `blake3(method_string)`. The method
//! string is the canonical signature, e.g. `"erc20.transfer(address,u256)"`.
//! This rule is shared by the `contract!` macro (which embeds selectors at
//! expansion time) and by build scripts that pre-compute selector tables.

/// Derive a 4-byte method selector from a canonical method signature.
pub fn selector(method: &str) -> [u8; 4] {
    let h = blake3::hash(method.as_bytes());
    let b = h.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_blake3_prefix() {
        let m = "erc20.transfer(address,u256)";
        let s = selector(m);
        let full = blake3::hash(m.as_bytes());
        assert_eq!(&s[..], &full.as_bytes()[..4]);
    }

    #[test]
    fn selector_is_deterministic() {
        let a = selector("factory.create_pair(address,address)");
        let b = selector("factory.create_pair(address,address)");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_signatures_have_distinct_selectors() {
        let a = selector("erc20.transfer(address,u256)");
        let b = selector("erc20.transfer_from(address,address,u256)");
        assert_ne!(a, b);
    }
}
