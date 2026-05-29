//! `/bloom/petals/dex/wallet` — minimal settlement petal for the DeFi pipe demo.
//!
//! The pipe front-door emits only Move commands (never builtin
//! `TransferObjects`), so the final "deliver the swapped coin to a
//! recipient" stage of a swap pipeline must go through a petal Move export.
//! `receive` is that settlement stage: it takes a `Coin<Erased>` — typically
//! the Use-ref output of an upstream swap — and transfers it to `recipient`.
//!
//! `object.transfer` carries no defining-petal restriction (any petal
//! holding a valid handle may re-owner the row), so this non-defining wallet
//! petal can settle a coin minted upstream by the pool petal. That is the
//! Phase F linchpin (spec §6 litmus 5.1 / 5.2).

#![deny(missing_docs)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use bloom_resource_macros as bloom;

/// `Result`-typed host-side variants, exposed for host-side unit tests and
/// non-wasm callers (mirrors the `ops` pattern in the fungible/pool petals).
pub mod ops {
    use bloom_objects::Owner;
    use bloom_resource::host;
    use bloom_resource::{PetalError, RuntimeHandle};

    /// Transfer the coin at `coin_handle` to `recipient` (32-byte address)
    /// via the host `object.transfer` import.
    pub fn receive(coin_handle: RuntimeHandle, recipient: [u8; 32]) -> Result<(), PetalError> {
        host::object_transfer(coin_handle, &Owner::Address(recipient))
    }
}

/// Petal entry points for `/bloom/petals/dex/wallet`.
#[bloom::petal(path = "/bloom/petals/dex/wallet", version = "0.1.0")]
pub mod wallet {
    use crate::ops;
    use bloom_resource::{Coin, Erased};

    /// 32-byte chain address — the recipient of a settled coin. Kept as a
    /// local alias so the petal depends only on `bloom-resource` /
    /// `bloom-objects` (spec §3.2), matching the fungible petal's `Address`.
    pub type Address = [u8; 32];

    /// Settle `coin` to `recipient`.
    ///
    /// Uses `object.transfer` (no defining-petal restriction), so the coin
    /// may have been minted upstream by a different petal (the pool's swap
    /// output threaded in via a PTB Use-ref).
    pub fn receive(coin: Coin<Erased>, recipient: Address) {
        ops::receive(coin.handle(), recipient).expect("receive host failure");
    }
}
