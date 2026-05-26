// Minimal `#[bloom::petal]` smoke fixture covering the most common
// macro shapes: phantom-generic object, signer arg, generic fn.

use bloom_resource::{Coin, Signer, UID};
use bloom_resource_macros as bloom;
use std::marker::PhantomData;

#[bloom::petal(path = "/test/minimal", version = "0.1.0")]
pub mod minimal {
    use super::*;

    #[bloom::object(abilities = "key, store")]
    pub struct Pool {
        id: UID,
        reserve_a: u128,
        reserve_b: u128,
    }

    #[bloom::object(abilities = "key, store", phantom = "T")]
    pub struct Vault<T> {
        id: UID,
        value: u128,
        _marker: PhantomData<T>,
    }

    pub fn deposit(_signer: &Signer, _amount: u128) {}

    pub fn split<T>(_c: Coin<T>) {}
}

