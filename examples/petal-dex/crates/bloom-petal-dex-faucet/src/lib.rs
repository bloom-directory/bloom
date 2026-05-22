//! `/bloom/dex/faucet` — test faucet petal for the DeFi pipe demo.
//!
//! On a live chain, genesis only emits `Coin<LOOM>` (see
//! `bloom_chain_node::genesis::Genesis::apply_to_state`), and the PTB
//! validator does **not** treat `Erased` as a wildcard — a `Coin<LOOM>` row
//! will not match a `Coin<Erased>` arg (`bloom_script::validator::
//! type_tags_match`). The DEX pool's `create_pool` / `swap_exact_in` exports
//! take `Coin<Erased>`, so a freshly-bootstrapped chain has no coin to feed
//! them.
//!
//! `mint` closes that gap: it `object.create`s a fresh `Coin<Erased>` of the
//! requested value and returns it as a borrow-table row (a PTB Use-ref),
//! which is then spliced atomically into a downstream `create_pool` / swap
//! command within the same transaction. It is the on-chain analog of the
//! in-process `seed_erased_coin` test helper.
//!
//! It mirrors exactly how the pool mints its swap *output* coin
//! (`host::object_create(&Coin<Erased> tag, &coin_payload(...))`), so the
//! minted coin's on-chain tag is byte-identical to what the pool produces and
//! threads into `Coin<Erased>` args identically (the Phase F linchpin, spec
//! §6 litmus 5.1 / 5.2).
//!
//! NOTE: this is a *test/demo* faucet — anyone may mint unbacked value. It is
//! deployed only in example / acceptance contexts, never as protocol stdlib.

#![deny(missing_docs)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use bloom_resource_macros as bloom;

/// `Result`-typed host-side variants, exposed for host-side unit tests and
/// non-wasm callers (mirrors the `ops` pattern in the pool / wallet petals).
pub mod ops {
    use bloom_objects::{ObjectId, TypeTag};
    use bloom_resource::abi::RetWriter;
    use bloom_resource::host;
    use bloom_resource::{PetalError, RuntimeHandle};

    /// Build a `Concrete` `TypeTag` with the self-petal sentinel hash
    /// (`[0u8; 32]`); the chain stamps the real petal hash on `object.create`.
    fn concrete(name: &str, args: Vec<TypeTag>) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: args,
        }
    }

    /// `TypeTag` for `Coin<Erased>` — byte-identical to the pool's
    /// `tags::coin_tag`, so a minted coin threads into `Coin<Erased>` args
    /// exactly like a pool swap output does.
    pub fn coin_erased_tag() -> TypeTag {
        concrete("Coin", vec![concrete("Erased", vec![])])
    }

    /// `Coin<T>` payload: 32-byte id placeholder (host fills on create) + a
    /// 16-byte big-endian `u128` value. Matches the pool's `coin_payload`.
    fn coin_payload(value: u128) -> Vec<u8> {
        let mut w = RetWriter::with_capacity(48);
        w.write_object_id(&ObjectId([0u8; 32]));
        w.write_u128(value);
        w.finish()
    }

    /// Mint a fresh `Coin<Erased>` worth `value`, returning its handle.
    pub fn mint(value: u128) -> Result<RuntimeHandle, PetalError> {
        host::object_create(&coin_erased_tag(), &coin_payload(value))
    }
}

/// Petal entry points for `/bloom/dex/faucet`.
#[bloom::petal(path = "/bloom/dex/faucet", version = "0.1.0")]
pub mod faucet {
    use crate::ops;
    use bloom_resource::{Coin, Erased};

    /// Mint a fresh `Coin<Erased>` worth `value`.
    ///
    /// Returns the coin as a borrow-table row (PTB Use-ref) so it can be
    /// threaded atomically into a downstream `create_pool` / swap command in
    /// the same transaction — the on-chain analog of `seed_erased_coin`.
    pub fn mint(value: u128) -> Coin<Erased> {
        let h = ops::mint(value).expect("faucet mint host failure");
        Coin::from_handle(h)
    }
}
