//! Runtime helpers used by the `#[event]` macro at the emit site.
//!
//! Two operations are non-obvious:
//!
//! 1. **Indexed-topic encoding.** Solidity-style indexed fields produce a
//!    32-byte topic per field; primitives are right-aligned big-endian and
//!    composite types are hashed (blake3) to a 32-byte digest. We use the
//!    [`IndexedTopic`] trait so each concrete primitive picks its own
//!    encoding without runtime branching.
//! 2. **Event signature canonicalisation.** Handled at macro expansion time
//!    (see `bloom-contract-macros::event_attr`) — this module only carries
//!    the emit-side runtime support.

use core::marker::PhantomData;

use alloc::vec::Vec;
use blake3::Hasher;

use crate::abi::{AbiEncode, Encoder};
use crate::types::{Address, Hash32, U256};

/// 32-byte topic word.
pub type Topic = [u8; 32];

/// Produces the 32-byte indexed-topic for a single value.
///
/// Implemented for primitives (right-aligned BE) and types that already have
/// a natural 32-byte representation (`U256`, `Address`, `Hash32`). For any
/// other `AbiEncode` value (`Vec<u8>`, `String`, structs, …) the blanket
/// fallback hashes the encoded bytes with blake3 — matching Solidity's
/// "hash dynamic indexed types" behavior.
pub trait IndexedTopic {
    fn indexed_topic(&self) -> Topic;
}

impl IndexedTopic for U256 {
    fn indexed_topic(&self) -> Topic { self.0 }
}
impl IndexedTopic for Address {
    fn indexed_topic(&self) -> Topic { self.0 }
}
impl IndexedTopic for Hash32 {
    fn indexed_topic(&self) -> Topic { self.0 }
}

macro_rules! indexed_int {
    ($($t:ty)+) => { $(
        impl IndexedTopic for $t {
            fn indexed_topic(&self) -> Topic {
                let mut out = [0u8; 32];
                let bytes = self.to_be_bytes();
                let start = 32 - bytes.len();
                out[start..].copy_from_slice(&bytes);
                out
            }
        }
    )+ };
}
indexed_int!(u8 u16 u32 u64 u128);

impl IndexedTopic for bool {
    fn indexed_topic(&self) -> Topic {
        let mut out = [0u8; 32];
        out[31] = if *self { 1 } else { 0 };
        out
    }
}

/// Helper used by the `#[event]` macro at the emit site — dispatches to the
/// type's [`IndexedTopic`] impl when one exists, otherwise hashes the
/// ABI-encoded bytes via blake3.
///
/// The macro can't know at expansion time whether a field implements
/// `IndexedTopic` directly, so it always calls this helper and relies on the
/// trait-method-vs-blanket disambiguation below.
pub fn topic_from_value<T: ToIndexedTopic>(value: &T) -> Topic {
    value.to_indexed_topic()
}

/// Internal trait specialised through a marker type. Users / macros should
/// invoke [`topic_from_value`] rather than implementing this directly.
pub trait ToIndexedTopic {
    fn to_indexed_topic(&self) -> Topic;
}

impl<T: IndexedTopic> ToIndexedTopic for T {
    fn to_indexed_topic(&self) -> Topic {
        IndexedTopic::indexed_topic(self)
    }
}

/// Hash any `AbiEncode` value into a 32-byte topic via
/// `blake3(abi_encode(value))`. Used by the macro when the field type does
/// not have a primitive `IndexedTopic` impl. Wraps the value in a marker
/// newtype so it doesn't collide with the primitive blanket above.
///
/// Callers reach this through [`topic_from_value`] when the static type
/// resolves to [`DynamicIndexed`].
pub struct DynamicIndexed<'a, T: AbiEncode + ?Sized>(pub &'a T, pub PhantomData<()>);

impl<T: AbiEncode + ?Sized> ToIndexedTopic for DynamicIndexed<'_, T> {
    fn to_indexed_topic(&self) -> Topic {
        let mut enc = Encoder::new();
        if AbiEncode::encode_into(self.0, &mut enc).is_err() {
            return [0u8; 32];
        }
        let bytes: Vec<u8> = enc.finish();
        let mut h = Hasher::new();
        h.update(&bytes);
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_indexed_topic_is_right_aligned_be() {
        let v: u64 = 0x0102_0304_0506_0708;
        let t = v.indexed_topic();
        assert_eq!(&t[..24], &[0u8; 24]);
        assert_eq!(&t[24..], &v.to_be_bytes());
    }

    #[test]
    fn address_indexed_topic_is_verbatim_bytes() {
        let a = Address::from([7u8; 32]);
        assert_eq!(a.indexed_topic(), [7u8; 32]);
    }

    #[test]
    fn bool_indexed_topic_uses_last_byte() {
        let t = true.indexed_topic();
        let f = false.indexed_topic();
        assert_eq!(t[31], 1);
        assert_eq!(f[31], 0);
        assert_eq!(&t[..31], &[0u8; 31]);
    }
}
