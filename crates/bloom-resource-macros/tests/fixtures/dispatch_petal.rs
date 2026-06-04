// End-to-end shim-dispatch fixture exercising the macro-emitted
// `__petal_<fn>` ABI on the host. Each `pub fn` covers a different
// arg/return shape:
//
// - `id(x: u128) -> u128` — pure const arg + const return.
// - `blob_len(blob: Bytes) -> u128` — built-in bytes value arg.
// - `requires_signer(s: &Signer) -> u32` — signer arg + primitive return.
// - `double_coin(c: Coin<u128>) -> u128` — object arg consumed as a
//   `Coin<T>` wrapper, return derived from the host-mocked handle.

use bloom_resource::{Bytes, Coin, Signer};
use bloom_resource_macros as bloom;

#[bloom::petal(path = "/test/dispatch", version = "0.1.0")]
pub mod dispatch {
    use super::*;

    pub fn id(x: u128) -> u128 {
        x
    }

    pub fn blob_len(blob: Bytes) -> u128 {
        blob.0.len() as u128
    }

    pub fn requires_signer(s: &Signer) -> u32 {
        s.index() as u32
    }

    pub fn double_coin(c: Coin<u128>) -> u128 {
        // `Coin<u128>` is a thin handle wrapper in this crate; for the
        // purposes of the shim test we surface the handle's raw value
        // doubled so the host-side mock can confirm the wrapping route
        // ran cleanly.
        (c.handle().as_raw() as u128) * 2
    }
}
