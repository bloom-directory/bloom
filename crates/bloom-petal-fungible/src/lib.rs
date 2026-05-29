//! `/bloom/petals/core/fungible` petal — the canonical fungible-token petal
//! shipped as part of the Bloom standard library.
//!
//! Implements:
//! - `LOOM` — the phantom witness type for native LOOM (spec §9.1).
//! - `MintCap<T>` / `BurnCap<T>` — capability tokens authorizing
//!   `mint` / `burn` on a `Coin<T>` (spec §5).
//! - `Supply<T>` — running total minted supply per currency (spec §14.4).
//! - `EpochZero` — linear cap consumed by `mint_genesis`; only the
//!   genesis pipeline ever holds one (spec §9.3).
//!
//! Public entry points (declared inside the `fungible` petal mod):
//! - `create_currency<T>` — mint a fresh capability triple.
//! - `mint<T>` / `burn<T>` — cap-gated value creation and destruction.
//! - `split<T>` / `merge<T>` — value reshuffling between `Coin<T>` objects.
//! - `transfer<T>` — move a `Coin<T>` to a new address owner.
//! - `value<T>` — read the `u128` value field of a `Coin<T>`.
//! - `mint_genesis` — single-use LOOM minter gated by `EpochZero`.
//!
//! The petal does **not** define a `Coin<T>` struct itself: the runtime
//! crate `bloom-resource` already owns `Coin<T>` as a typed handle
//! wrapper (see `crates/bloom-resource/src/coin.rs`). The on-chain
//! payload encoding for a `Coin<T>` object is fixed by this petal:
//! 32-byte `ObjectId` followed by 16-byte big-endian `u128` value.
//!
//! Error model: per spec §11.1, the macro-generated wasm shim returns
//! `i32` where `0` = success and a non-zero value = typed error code.
//! User-facing Rust functions therefore return the raw success type;
//! failures propagate via `panic!`, which the chain VM traps and turns
//! into an abort. The crate-public [`ops`] module exposes
//! `Result`-typed variants for host-side unit tests.

#![deny(missing_docs)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use bloom_resource_macros as bloom;

/// `Result`-typed variants of every fungible petal operation, exposed
/// for host-side integration tests and for callers that want to thread
/// `PetalError` rather than rely on the wasm-boundary panic→abort
/// conversion.
///
/// Each function returns the success value as a raw [`bloom_resource::RuntimeHandle`]
/// (or `()`) and the host-import error as a [`bloom_resource::PetalError`].
pub mod ops {
    use bloom_objects::{AccessMode, ObjectId, Owner, TypeTag};
    use bloom_resource::abi::RetWriter;
    use bloom_resource::host;
    use bloom_resource::{PetalError, RuntimeHandle};

    // -----------------------------------------------------------------
    // Payload helpers
    // -----------------------------------------------------------------

    /// Canonical-encoded payload for a freshly minted `Coin<T>`. The
    /// `id` is zeroed because the host fills it in on `object_create`.
    pub fn coin_payload(value: u128) -> Vec<u8> {
        let mut w = RetWriter::with_capacity(48);
        w.write_object_id(&ObjectId([0u8; 32]));
        w.write_u128(value);
        w.finish()
    }

    /// Canonical-encoded payload for a fresh `Supply<T>` (id placeholder
    /// + total).
    pub fn supply_payload(total: u128) -> Vec<u8> {
        let mut w = RetWriter::with_capacity(48);
        w.write_object_id(&ObjectId([0u8; 32]));
        w.write_u128(total);
        w.finish()
    }

    /// Canonical-encoded payload for a brand-new capability object —
    /// just the `id` placeholder.
    pub fn cap_payload() -> Vec<u8> {
        let mut w = RetWriter::with_capacity(32);
        w.write_object_id(&ObjectId([0u8; 32]));
        w.finish()
    }

    /// Decode the `value` (low 16 bytes after the 32-byte `id`) from a
    /// `Coin<T>` payload as read back from the borrow table.
    pub fn decode_coin_value(bytes: &[u8]) -> Result<u128, PetalError> {
        if bytes.len() < 48 {
            return Err(PetalError::InvalidArgs);
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&bytes[32..48]);
        Ok(u128::from_be_bytes(buf))
    }

    /// Decode the `total` field of a `Supply<T>` payload (same layout
    /// as a `Coin<T>` value field).
    pub fn decode_supply_total(bytes: &[u8]) -> Result<u128, PetalError> {
        decode_coin_value(bytes)
    }

    /// Re-encode a `Coin<T>` / `Supply<T>` payload with a new value,
    /// preserving the 32-byte `id` prefix.
    pub fn rewrite_value(existing: &[u8], new_value: u128) -> Result<Vec<u8>, PetalError> {
        if existing.len() < 48 {
            return Err(PetalError::InvalidArgs);
        }
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&existing[..32]);
        out.extend_from_slice(&new_value.to_be_bytes());
        Ok(out)
    }

    // -----------------------------------------------------------------
    // TypeTag builders (zero petal_hash placeholder, per spec §8.2)
    // -----------------------------------------------------------------

    fn type_tag_with_arg(name: &str, arg: &TypeTag) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![arg.clone()],
        }
    }

    fn type_tag_no_args(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: vec![],
        }
    }

    /// `TypeTag::Generic { idx: 0 }` — the first generic-param slot
    /// of the calling petal function, used wherever the surface API
    /// says `<T>`.
    pub fn type_tag_t() -> TypeTag {
        TypeTag::Generic { idx: 0 }
    }

    /// The canonical `TypeTag` for `Coin<LOOM>` with the zero
    /// `petal_hash` sentinel (used at genesis before the fungible petal
    /// is deployed; see spec §9.3 and the EpochZero note).
    ///
    /// Both the `Coin` and `LOOM` type tags carry `petal_hash = [0u8;32]`
    /// — the on-chain sentinel for "fungible petal, not yet hashed".
    pub fn type_tag_coin_loom() -> TypeTag {
        type_tag_with_arg("Coin", &type_tag_no_args("LOOM"))
    }

    // -----------------------------------------------------------------
    // Operations
    // -----------------------------------------------------------------

    /// Create a fresh `(MintCap<T>, BurnCap<T>, Supply<T>)` triple.
    /// Returns the three host borrow-table handles in declaration
    /// order: `(mint_handle, burn_handle, supply_handle)`.
    pub fn create_currency() -> Result<(RuntimeHandle, RuntimeHandle, RuntimeHandle), PetalError> {
        let t = type_tag_t();
        let mint_tag = type_tag_with_arg("MintCap", &t);
        let burn_tag = type_tag_with_arg("BurnCap", &t);
        let supply_tag = type_tag_with_arg("Supply", &t);

        let mint_handle = host::object_create(&mint_tag, &cap_payload())?;
        let burn_handle = host::object_create(&burn_tag, &cap_payload())?;
        let supply_handle = host::object_create(&supply_tag, &supply_payload(0))?;
        Ok((mint_handle, burn_handle, supply_handle))
    }

    /// Mint `amount` units of `Coin<T>` and increment the running
    /// `Supply<T>` total. Returns the newly minted coin's handle.
    ///
    /// Errors:
    /// - `Custom(1)` on `Supply` overflow.
    /// - any host import error from the read/create/mutate sequence.
    pub fn mint(supply_handle: RuntimeHandle, amount: u128) -> Result<RuntimeHandle, PetalError> {
        let supply_bytes = host::object_read(supply_handle)?;
        let current = decode_supply_total(&supply_bytes)?;
        let next = current.checked_add(amount).ok_or(PetalError::Custom(1))?;

        let coin_handle = host::object_create(
            &type_tag_with_arg("Coin", &type_tag_t()),
            &coin_payload(amount),
        )?;

        let new_supply_bytes = rewrite_value(&supply_bytes, next)?;
        host::object_mutate(supply_handle, &new_supply_bytes)?;
        Ok(coin_handle)
    }

    /// Burn `coin` (consuming it) and decrement the running
    /// `Supply<T>` total by the coin's value.
    pub fn burn(
        supply_handle: RuntimeHandle,
        coin_handle: RuntimeHandle,
    ) -> Result<(), PetalError> {
        let coin_bytes = host::object_read(coin_handle)?;
        let coin_value = decode_coin_value(&coin_bytes)?;

        let supply_bytes = host::object_read(supply_handle)?;
        let current = decode_supply_total(&supply_bytes)?;
        let next = current
            .checked_sub(coin_value)
            .ok_or(PetalError::InsufficientBalance)?;

        host::object_delete(coin_handle)?;
        let new_supply_bytes = rewrite_value(&supply_bytes, next)?;
        host::object_mutate(supply_handle, &new_supply_bytes)?;
        Ok(())
    }

    /// Split `amount` units off the coin at `coin_handle` into a new
    /// `Coin<T>`. Shrinks the original. Returns the new coin's handle.
    pub fn split(coin_handle: RuntimeHandle, amount: u128) -> Result<RuntimeHandle, PetalError> {
        let coin_bytes = host::object_read(coin_handle)?;
        let current = decode_coin_value(&coin_bytes)?;
        let remaining = current
            .checked_sub(amount)
            .ok_or(PetalError::InsufficientBalance)?;

        let new_handle = host::object_create(
            &type_tag_with_arg("Coin", &type_tag_t()),
            &coin_payload(amount),
        )?;

        let new_bytes = rewrite_value(&coin_bytes, remaining)?;
        host::object_mutate(coin_handle, &new_bytes)?;
        Ok(new_handle)
    }

    /// Merge `other_handle` into `dst_handle`, deleting `other`. The
    /// sum is checked; overflow → `Custom(1)`.
    pub fn merge(dst_handle: RuntimeHandle, other_handle: RuntimeHandle) -> Result<(), PetalError> {
        let dst_bytes = host::object_read(dst_handle)?;
        let other_bytes = host::object_read(other_handle)?;
        let dst_value = decode_coin_value(&dst_bytes)?;
        let other_value = decode_coin_value(&other_bytes)?;
        let total = dst_value
            .checked_add(other_value)
            .ok_or(PetalError::Custom(1))?;

        host::object_delete(other_handle)?;
        let new_dst_bytes = rewrite_value(&dst_bytes, total)?;
        host::object_mutate(dst_handle, &new_dst_bytes)?;
        Ok(())
    }

    /// Transfer the coin at `coin_handle` to `recipient`.
    pub fn transfer(coin_handle: RuntimeHandle, recipient: [u8; 32]) -> Result<(), PetalError> {
        host::object_transfer(coin_handle, &Owner::Address(recipient))
    }

    /// Read the `u128` value field of a `Coin<T>` without consuming it.
    pub fn value(coin_handle: RuntimeHandle) -> Result<u128, PetalError> {
        let bytes = host::object_read(coin_handle)?;
        decode_coin_value(&bytes)
    }

    /// Mint `amount` LOOM into a single fresh `Coin<LOOM>` object
    /// transferred to `recipient` (spec §9.3 genesis flow).
    pub fn mint_genesis(amount: u128, recipient: [u8; 32]) -> Result<(), PetalError> {
        let loom_tag = type_tag_no_args("LOOM");
        let coin_handle =
            host::object_create(&type_tag_with_arg("Coin", &loom_tag), &coin_payload(amount))?;
        host::object_transfer(coin_handle, &Owner::Address(recipient))
    }

    /// Borrow a `Supply<T>` (or any object) row in `Mutable` mode by
    /// id. Exposed so PTBs that produced a `Supply<T>` in an earlier
    /// command can refer to it positionally in a later command.
    pub fn borrow_supply_mut(supply_id: ObjectId) -> Result<RuntimeHandle, PetalError> {
        host::object_borrow(&supply_id, AccessMode::Mutable)
    }
}

/// The `/bloom/petals/core/fungible` petal module. Declares the on-chain
/// objects (`LOOM`, `MintCap<T>`, `BurnCap<T>`, `Supply<T>`, `EpochZero`)
/// and the public entry points (`create_currency`, `mint`, `burn`,
/// `split`, `merge`, `transfer`, `value`, `mint_genesis`).
#[bloom::petal(path = "/bloom/petals/core/fungible", version = "0.1.0")]
pub mod fungible {
    use crate::ops;
    use bloom_resource::{Capability, Coin, Resource, Signer, UID};
    use core::marker::PhantomData;

    /// 32-byte post-quantum chain address; the recipient of a transfer
    /// or genesis allocation. Wire-equivalent to `bloom_chain_types::Address`
    /// but kept as a local type alias to keep this petal independent of
    /// the chain crate (spec §3.2: "petals depend only on `bloom-resource`
    /// + `bloom-objects` + their macros").
    pub type Address = [u8; 32];

    // -----------------------------------------------------------------
    // Witness / cap / state declarations
    // -----------------------------------------------------------------

    /// Phantom-only marker for native LOOM. Never instantiated; appears
    /// only inside `Coin<LOOM>` / `Balance<LOOM>` positions (spec §9.1).
    #[bloom::object(no_abilities)]
    pub struct LOOM {}

    /// Mint authority for `Coin<T>`. Holding a `&MintCap<T>` in a PTB
    /// arg authorises `mint::<T>` (spec §5).
    #[bloom::capability(phantom = "T")]
    pub struct MintCap<T> {
        /// On-chain object identifier.
        pub id: UID,
        /// Phantom marker — `T` only flows through the type tag.
        pub _phantom: PhantomData<T>,
    }

    /// Burn authority for `Coin<T>`.
    #[bloom::capability(phantom = "T")]
    pub struct BurnCap<T> {
        /// On-chain object identifier.
        pub id: UID,
        /// Phantom marker.
        pub _phantom: PhantomData<T>,
    }

    /// Running total supply tracker per currency type `T`. Updated by
    /// `mint` and `burn` so off-chain indexers can answer total-supply
    /// queries without scanning every `Coin<T>`.
    ///
    /// Linear (`key + store`, no `drop`, no `copy`) — once created via
    /// `create_currency` it must be shared or transferred, never quietly
    /// dropped.
    #[bloom::object(abilities = "key, store", phantom = "T")]
    pub struct Supply<T> {
        /// On-chain object identifier.
        pub id: UID,
        /// Total currently-minted supply (mint - burn).
        pub total: u128,
        /// Phantom marker.
        pub _phantom: PhantomData<T>,
    }

    /// Single-use capability consumed by `mint_genesis`. Linear and
    /// no-drop — the genesis pipeline `object.delete`s it after the
    /// final allocation (spec §9.3).
    ///
    /// Note: `#[capability]` would imply `copy`, which would break the
    /// "single use" property. We instead spell out the abilities as
    /// `key + store` (no `copy`, no `drop`) explicitly.
    #[bloom::object(abilities = "key, store")]
    pub struct EpochZero {
        /// On-chain object identifier.
        pub id: UID,
    }

    // -----------------------------------------------------------------
    // Public petal entry points
    // -----------------------------------------------------------------
    //
    // Per spec §11.1, the macro-generated wasm shim catches panics and
    // turns them into the non-zero abort code. The Rust signatures
    // therefore return the raw success value. Each entry point is a
    // thin wrapper over the corresponding crate::ops::* function.
    //
    // The petal manifest models single returns cleanly today; the
    // tuple-return shape of `create_currency` is therefore exposed in
    // three small wrappers (one per cap) so the manifest stays valid.
    // Real PTBs assemble the triple by calling all three and threading
    // results with `Use(cmd, ret)` references.

    /// Create the `MintCap<T>` half of a fresh fungible-currency triple
    /// (`MintCap<T>`, `BurnCap<T>`, `Supply<T>`). Per spec §5.3,
    /// capabilities are minted at type-creation time by `create_currency`
    /// and cannot be granted in isolation afterwards.
    ///
    /// PTBs that need all three capabilities call this once and thread
    /// the return values via `Use(cmd, ret)` references to downstream
    /// commands. There is no separate `create_burn_cap` entry point —
    /// the `BurnCap<T>` is an inseparable part of the triple (spec §14.1).
    pub fn create_currency<T>(_signer: &Signer) -> Capability<MintCap<T>> {
        let (mint, _burn, _supply) = ops::create_currency().expect("create_currency host failure");
        Capability::from_handle(mint)
    }

    /// Mint `amount` units of `Coin<T>` against the `MintCap<T>` proof
    /// of authority. Updates the `Supply<T>` total in lockstep.
    ///
    /// The `supply` argument is the `Supply<T>` object that tracks total
    /// issuance for this currency, taken as an object handle in the
    /// handle/tag model (spec §11.2). The macro materializes it from the
    /// arg's `ObjectId` via `object.borrow(id, Mutable)`; `supply.handle()`
    /// returns that borrow-table handle for `ops::mint` (spec §14.1
    /// compliance — every mint updates the supply tracker via the real
    /// runtime handle).
    pub fn mint<T>(
        _cap: &Capability<MintCap<T>>,
        supply: &mut Resource<Supply<T>>,
        amount: u128,
    ) -> Coin<T> {
        let supply_handle = supply.handle();
        let coin_handle = ops::mint(supply_handle, amount).expect("mint host failure");
        Coin::from_handle(coin_handle)
    }

    /// Burn `coin` (consuming it) against the `BurnCap<T>` authority,
    /// decrementing the `Supply<T>` total by the coin's value.
    ///
    /// `supply` is taken as an object handle (spec §11.2); `supply.handle()`
    /// returns the borrow-table handle the macro materialized for it
    /// (spec §14.1 compliance).
    pub fn burn<T>(_cap: &Capability<BurnCap<T>>, supply: &mut Resource<Supply<T>>, coin: Coin<T>) {
        let supply_handle = supply.handle();
        ops::burn(supply_handle, coin.handle()).expect("burn host failure");
    }

    /// Split `amount` units off `coin` into a freshly minted `Coin<T>`,
    /// shrinking the original. Returns the new coin.
    ///
    /// Reverts with `InsufficientBalance` if `coin.value < amount`.
    pub fn split<T>(coin: &mut Coin<T>, amount: u128) -> Coin<T> {
        let new_handle = ops::split(coin.handle(), amount).expect("split host failure");
        Coin::from_handle(new_handle)
    }

    /// Merge `other` into `dst`, consuming `other`. The total value is
    /// checked-added; overflow panics with petal-custom code `1`.
    pub fn merge<T>(dst: &mut Coin<T>, other: Coin<T>) {
        ops::merge(dst.handle(), other.handle()).expect("merge host failure");
    }

    /// Transfer `coin` to `recipient`. Consumes the coin row.
    pub fn transfer<T>(coin: Coin<T>, recipient: Address) {
        ops::transfer(coin.handle(), recipient).expect("transfer host failure");
    }

    /// Read the `u128` value field of a `Coin<T>` without consuming it.
    pub fn value<T>(coin: &Coin<T>) -> u128 {
        ops::value(coin.handle()).expect("value host failure")
    }

    /// Mint the initial LOOM supply (spec §9.3). Gated by `EpochZero`,
    /// which only the genesis pipeline ever holds; the cap is `delete`d
    /// after the final genesis allocation, permanently disabling this
    /// entry point until a governance petal mints a fresh cap.
    ///
    /// Spec §9.3 / §5: the `EpochZero` capability is verified via
    /// `cap::check` before any minting proceeds. An invalid or
    /// mistyped `EpochZero` handle causes an immediate panic (which the
    /// wasm VM traps and converts to an abort). This prevents any
    /// caller that doesn't actually hold a valid `EpochZero` object from
    /// succeeding even if the Rust type system is satisfied by a
    /// fabricated `Capability<EpochZero>` wrapper.
    pub fn mint_genesis(epoch: &Capability<EpochZero>, amount: u128, recipient: Address) {
        let epoch_tag = {
            use bloom_objects::TypeTag;
            TypeTag::Concrete {
                petal_hash: [0u8; 32],
                type_name: "EpochZero".to_string(),
                type_args: vec![],
            }
        };
        assert!(
            epoch.check(&epoch_tag),
            "mint_genesis: EpochZero capability check failed — \
             caller does not hold a valid EpochZero cap (spec §9.3)"
        );
        ops::mint_genesis(amount, recipient).expect("mint_genesis host failure");
    }
}
