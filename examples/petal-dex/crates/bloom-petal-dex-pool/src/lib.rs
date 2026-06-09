//! `/bloom/petals/dex/pool` petal — strategy-generic DEX pool.
//!
//! Defines:
//! - `Pool<A, B, S>` — the shared pool object holding two coin reserves
//!   and strategy-specific configuration.
//! - `LpPosition<A, B, S>` — a linear position (LP shares) in a
//!   `Pool<A, B, S>`.
//!
//! The actual swap and liquidity math is fully delegated to
//! `bloom_dex_math::SwapStrategy`, so any `S: SwapStrategy` (CPMM,
//! Stableswap, etc.) can be plugged in without changing this petal.
//!
//! ## Design note — `S::Params` in struct fields
//!
//! The `#[bloom::object]` macro rejects bare generic type parameters in
//! struct field position unless they are (a) declared `phantom = "…"` in
//! the attribute, or (b) wrapped in `Resource<T>` (spec §11.2). Because
//! `S::Params` is an *associated-type projection*, not a Rust generic
//! parameter of the struct, it can't be wrapped as `Resource<S::Params>`.
//!
//! We therefore use **workaround (1)**: the params are serialized to
//! `Vec<u8>` (canonical `vector<u8>` bytes) and stored in
//! `params_bytes: Vec<u8>`. Strategies must implement
//! [`ParamCodec`] (two tiny functions) so the pool can encode on `create`
//! and decode on every operation. `ConstantProductParams` (30 bps,
//! 2-byte big-endian) is the reference impl.
//!
//! ## Petal entry points
//!
//! Declared inside `pub mod pool` with
//! `#[bloom::petal(path = "/bloom/petals/dex/pool", version = "0.1.0")]`.

#![deny(missing_docs)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use bloom_resource_macros as bloom;

// ─── Codec trait for strategy params ─────────────────────────────────────────

/// Encode/decode strategy-specific `Params` to/from a byte buffer.
///
/// Implemented for every `SwapStrategy::Params` type you want to store in a
/// `Pool`. The default wire format is up to the strategy author — for
/// `ConstantProductParams` it is a single 2-byte big-endian `u16` (fee_bps).
pub trait ParamCodec: Sized {
    /// Encode `self` into a freshly allocated `Vec<u8>`.
    fn encode(&self) -> Vec<u8>;

    /// Decode from a byte slice. Returns `None` on short/malformed input.
    fn decode(bytes: &[u8]) -> Option<Self>;
}

impl ParamCodec for bloom_dex_math::ConstantProductParams {
    fn encode(&self) -> Vec<u8> {
        self.fee_bps.to_be_bytes().to_vec()
    }
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 2 {
            return None;
        }
        let fee_bps = u16::from_be_bytes([bytes[0], bytes[1]]);
        if fee_bps >= bloom_dex_math::MAX_FEE_BPS {
            return None;
        }
        Some(Self { fee_bps })
    }
}

// ─── Pool payload helpers (host-side math; no host imports) ──────────────────

/// Payload codec helpers used by both `ops` and the unit tests.
pub mod payload {
    use bloom_objects::{ObjectId, TypeTag};
    use bloom_resource::{BloomType, UID};

    // Layout of `Pool<A, B, S>` payload written to the chain:
    //   [ id          : 32 bytes ]   ← ObjectId placeholder (host fills on create)
    //   [ reserve_a   : 16 bytes BE ]
    //   [ reserve_b   : 16 bytes BE ]
    //   [ lp_supply   : 16 bytes BE ]
    //   [ k_last      : 16 bytes BE ]
    //   [ params_bytes: ULEB128 count + raw u8 elements ]
    //   [ coin_a_tag  : canonical TypeTag ]
    //   [ coin_b_tag  : canonical TypeTag ]
    //   total: 84 + len(params) + len(tags) bytes

    /// Decoded pool payload fields:
    /// `(reserve_a, reserve_b, lp_supply, k_last, params_bytes, coin_a_tag, coin_b_tag)`.
    pub type DecodedPool = (u128, u128, u128, u128, Vec<u8>, TypeTag, TypeTag);

    /// Encode a `Pool` payload.
    #[allow(clippy::too_many_arguments)]
    pub fn pool_payload(
        id: &ObjectId,
        reserve_a: u128,
        reserve_b: u128,
        lp_supply: u128,
        k_last: u128,
        params_bytes: &[u8],
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Vec<u8> {
        crate::pool::Pool {
            id: UID::from_object_id(*id),
            reserve_a,
            reserve_b,
            lp_supply,
            k_last,
            params_bytes: params_bytes.to_vec(),
            coin_a_tag: coin_a_tag.clone(),
            coin_b_tag: coin_b_tag.clone(),
        }
        .canonical_encode()
    }

    /// Decode fields from a `Pool` payload slice.
    ///
    /// Returns `(reserve_a, reserve_b, lp_supply, k_last, params_bytes, coin_a_tag, coin_b_tag)` or
    /// `None` if the buffer is too short / malformed.
    pub fn decode_pool(bytes: &[u8]) -> Option<DecodedPool> {
        let pool = crate::pool::Pool::canonical_decode(bytes).ok()?;
        Some((
            pool.reserve_a,
            pool.reserve_b,
            pool.lp_supply,
            pool.k_last,
            pool.params_bytes,
            pool.coin_a_tag,
            pool.coin_b_tag,
        ))
    }

    // Layout of `LpPosition<A, B, S>` payload:
    //   [ id      : 32 bytes ]
    //   [ pool_id : 32 bytes ]
    //   [ shares  : 16 bytes BE ]
    //   total: 80 bytes

    /// Encode an `LpPosition` payload.
    pub fn lp_payload(id: &ObjectId, pool_id: &ObjectId, shares: u128) -> Vec<u8> {
        crate::pool::LpPosition {
            id: UID::from_object_id(*id),
            pool_id: *pool_id,
            shares,
        }
        .canonical_encode()
    }

    /// Decode fields from an `LpPosition` payload slice.
    ///
    /// Returns `(pool_id, shares)` or `None` on malformed input.
    pub fn decode_lp(bytes: &[u8]) -> Option<(ObjectId, u128)> {
        let lp = crate::pool::LpPosition::canonical_decode(bytes).ok()?;
        Some((lp.pool_id, lp.shares))
    }
}

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors emitted by pool entry points (panics on wasm → abort code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// Swap output would be below the caller's `min_out` guard.
    SlippageExceeded,
    /// The pool has insufficient liquidity for this operation.
    InsufficientLiquidity,
    /// Delegated math computation returned an error.
    MathFailed(bloom_dex_math::MathError),
    /// A position's `pool_id` does not match the pool being operated on.
    WrongPool,
    /// A coin type tag does not match the pool's stored pair binding.
    TokenTypeMismatch,
}

impl core::fmt::Display for PoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PoolError::SlippageExceeded => write!(f, "slippage exceeded"),
            PoolError::InsufficientLiquidity => write!(f, "insufficient liquidity"),
            PoolError::MathFailed(e) => write!(f, "math failed: {e}"),
            PoolError::WrongPool => write!(f, "wrong pool"),
            PoolError::TokenTypeMismatch => write!(f, "token type mismatch"),
        }
    }
}

impl From<bloom_dex_math::MathError> for PoolError {
    fn from(e: bloom_dex_math::MathError) -> Self {
        PoolError::MathFailed(e)
    }
}

// ─── Private type-tag helpers ─────────────────────────────────────────────────

mod tags {
    use bloom_objects::TypeTag;

    pub fn concrete(name: &str, args: Vec<TypeTag>) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: args,
        }
    }

    /// `TypeTag` for the (non-generic) `Pool` object — the on-chain shape
    /// the `#[bloom::object] struct Pool` declares in the handle/tag model
    /// (spec §11.2). Token identities `A`/`B` ride on the coin objects'
    /// own tags, not the pool's, so the pool carries no type args.
    pub fn pool_tag() -> TypeTag {
        concrete("Pool", vec![])
    }

    /// `TypeTag` for the (non-generic) `LpPosition` object.
    pub fn lp_position_tag() -> TypeTag {
        concrete("LpPosition", vec![])
    }

    pub fn coin_tag(inner: TypeTag) -> TypeTag {
        concrete("Coin", vec![inner])
    }
}

// ─── Inner-level operations (host-aware, Result-typed) ───────────────────────

/// `Result`-typed inner operations — each issues the minimal set of host
/// imports and returns `Err(PoolError)` rather than panicking.
///
/// The `#[bloom::petal]` entry points in `mod pool` are thin `expect`-wrappers
/// over these, exactly mirroring the `bloom-petal-fungible` split.
pub mod ops {
    use bloom_dex_math::SwapStrategy;
    use bloom_objects::{ObjectId, TypeTag};
    use bloom_resource::host;
    use bloom_resource::{PetalError, RuntimeHandle};

    use crate::{ParamCodec, PoolError, payload, tags};

    // ── Pool payload r/w helpers ─────────────────────────────────────────────

    /// Decode a pool handle's payload from the borrow table.
    pub fn read_pool(pool_handle: RuntimeHandle) -> Result<payload::DecodedPool, PetalError> {
        let bytes = host::object_read(pool_handle)?;
        payload::decode_pool(&bytes).ok_or(PetalError::InvalidArgs)
    }

    /// Re-encode and mutate a pool back into the borrow table.
    pub fn write_pool(
        pool_handle: RuntimeHandle,
        existing_bytes: &[u8],
        fields: &payload::DecodedPool,
    ) -> Result<(), PetalError> {
        // Preserve the 32-byte id prefix from the existing payload.
        if existing_bytes.len() < 32 {
            return Err(PetalError::InvalidArgs);
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&existing_bytes[..32]);
        let id = ObjectId(id_bytes);
        let (reserve_a, reserve_b, lp_supply, k_last, params_bytes, coin_a_tag, coin_b_tag) =
            fields;
        let new_payload = payload::pool_payload(
            &id,
            *reserve_a,
            *reserve_b,
            *lp_supply,
            *k_last,
            params_bytes,
            coin_a_tag,
            coin_b_tag,
        );
        host::object_mutate(pool_handle, &new_payload)
    }

    // ── Operations ───────────────────────────────────────────────────────────

    /// Create a new `Pool<A, B, S>` and an initial `LpPosition<A, B, S>`.
    ///
    /// Returns `(pool_handle, lp_handle)`.
    pub fn create_pool<S>(
        coin_a_handle: RuntimeHandle,
        coin_b_handle: RuntimeHandle,
        params: &S::Params,
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Result<(RuntimeHandle, RuntimeHandle), PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        // Read coin values.
        let a_bytes =
            host::object_read(coin_a_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let b_bytes =
            host::object_read(coin_b_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let value_a = decode_coin_value(&a_bytes)?;
        let value_b = decode_coin_value(&b_bytes)?;

        // Initial LP mint (sqrt path; lp_supply = 0).
        let (taken_a, taken_b, lp_minted) =
            S::add_liquidity(0, 0, value_a, value_b, 0).map_err(PoolError::MathFailed)?;
        let lp_supply = initial_lp_supply(lp_minted)?;

        let k_last = checked_k_last(taken_a, taken_b)?;
        let params_bytes = params.encode();

        let pool_payload = payload::pool_payload(
            &ObjectId([0u8; 32]),
            taken_a,
            taken_b,
            lp_supply,
            k_last,
            &params_bytes,
            coin_a_tag,
            coin_b_tag,
        );

        let pool_handle = host::object_create(&tags::pool_tag(), &pool_payload)
            .map_err(|_| PoolError::InsufficientLiquidity)?;
        let pool_id = host::object_id(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let pool_payload = payload::pool_payload(
            &pool_id,
            taken_a,
            taken_b,
            lp_supply,
            k_last,
            &params_bytes,
            coin_a_tag,
            coin_b_tag,
        );
        host::object_mutate(pool_handle, &pool_payload)
            .map_err(|_| PoolError::InsufficientLiquidity)?;

        let lp_payload = payload::lp_payload(&ObjectId([0u8; 32]), &pool_id, lp_minted);
        let lp_handle = host::object_create(&tags::lp_position_tag(), &lp_payload)
            .map_err(|_| PoolError::InsufficientLiquidity)?;
        let lp_id = host::object_id(lp_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let lp_payload = payload::lp_payload(&lp_id, &pool_id, lp_minted);
        host::object_mutate(lp_handle, &lp_payload)
            .map_err(|_| PoolError::InsufficientLiquidity)?;

        // Consume the input coins (fully taken on initial deposit).
        host::object_delete(coin_a_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        host::object_delete(coin_b_handle).map_err(|_| PoolError::InsufficientLiquidity)?;

        Ok((pool_handle, lp_handle))
    }

    /// Add liquidity to an existing pool.
    ///
    /// Returns `(lp_handle, leftover_a_handle, leftover_b_handle)` where the
    /// optional handles are `None` if all of the coin was consumed.
    pub fn add_liquidity<S>(
        pool_handle: RuntimeHandle,
        coin_a_handle: RuntimeHandle,
        coin_b_handle: RuntimeHandle,
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Result<(RuntimeHandle, Option<RuntimeHandle>, Option<RuntimeHandle>), PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes, stored_a_tag, stored_b_tag) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;
        ensure_pool_pair(&stored_a_tag, &stored_b_tag, coin_a_tag, coin_b_tag)?;

        let a_bytes =
            host::object_read(coin_a_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let b_bytes =
            host::object_read(coin_b_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let value_a = decode_coin_value(&a_bytes)?;
        let value_b = decode_coin_value(&b_bytes)?;

        let (taken_a, taken_b, lp_minted) =
            S::add_liquidity(reserve_a, reserve_b, value_a, value_b, lp_supply)
                .map_err(PoolError::MathFailed)?;

        let new_reserve_a = reserve_a
            .checked_add(taken_a)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let new_reserve_b = reserve_b
            .checked_add(taken_b)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let new_lp_supply = lp_supply
            .checked_add(lp_minted)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let new_k_last = checked_k_last(new_reserve_a, new_reserve_b)?;

        write_pool(
            pool_handle,
            &pool_raw,
            &(
                new_reserve_a,
                new_reserve_b,
                new_lp_supply,
                new_k_last,
                params_bytes.clone(),
                stored_a_tag.clone(),
                stored_b_tag.clone(),
            ),
        )
        .map_err(|_| PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;

        // Mint the LP position; set pool_id from pool payload prefix.
        let pool_id_bytes = {
            let mut b = [0u8; 32];
            b.copy_from_slice(&pool_raw[..32]);
            ObjectId(b)
        };
        let lp_payload = payload::lp_payload(&ObjectId([0u8; 32]), &pool_id_bytes, lp_minted);
        let lp_handle = host::object_create(&tags::lp_position_tag(), &lp_payload)
            .map_err(|_| PoolError::InsufficientLiquidity)?;
        let lp_id = host::object_id(lp_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let lp_payload = payload::lp_payload(&lp_id, &pool_id_bytes, lp_minted);
        host::object_mutate(lp_handle, &lp_payload)
            .map_err(|_| PoolError::InsufficientLiquidity)?;

        // Handle unused coin remainders.
        let leftover_a = if taken_a < value_a {
            let leftover_amount = value_a - taken_a;
            host::object_delete(coin_a_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
            let leftover_payload = coin_payload(leftover_amount);
            Some(
                host::object_create(&tags::coin_tag(stored_a_tag.clone()), &leftover_payload)
                    .map_err(|_| PoolError::InsufficientLiquidity)?,
            )
        } else {
            host::object_delete(coin_a_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
            None
        };

        let leftover_b = if taken_b < value_b {
            let leftover_amount = value_b - taken_b;
            host::object_delete(coin_b_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
            let leftover_payload = coin_payload(leftover_amount);
            Some(
                host::object_create(&tags::coin_tag(stored_b_tag.clone()), &leftover_payload)
                    .map_err(|_| PoolError::InsufficientLiquidity)?,
            )
        } else {
            host::object_delete(coin_b_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
            None
        };

        Ok((lp_handle, leftover_a, leftover_b))
    }

    /// Remove liquidity by burning an `LpPosition`.
    ///
    /// Returns `(coin_a_handle, coin_b_handle)` with proportional amounts.
    pub fn remove_liquidity<S>(
        pool_handle: RuntimeHandle,
        lp_handle: RuntimeHandle,
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Result<(RuntimeHandle, RuntimeHandle), PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes, stored_a_tag, stored_b_tag) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;
        ensure_pool_pair(&stored_a_tag, &stored_b_tag, coin_a_tag, coin_b_tag)?;

        let lp_bytes = host::object_read(lp_handle).map_err(|_| PoolError::WrongPool)?;
        let (lp_pool_id, shares) = payload::decode_lp(&lp_bytes).ok_or(PoolError::WrongPool)?;
        let pool_id = pool_id_from_payload(&pool_raw).ok_or(PoolError::WrongPool)?;
        if lp_pool_id != pool_id {
            return Err(PoolError::WrongPool);
        }

        let (amount_a, amount_b) = S::remove_liquidity(reserve_a, reserve_b, lp_supply, shares)
            .map_err(PoolError::MathFailed)?;

        let new_reserve_a = reserve_a
            .checked_sub(amount_a)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let new_reserve_b = reserve_b
            .checked_sub(amount_b)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let new_lp_supply = lp_supply
            .checked_sub(shares)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let new_k_last = checked_k_last(new_reserve_a, new_reserve_b)?;

        write_pool(
            pool_handle,
            &pool_raw,
            &(
                new_reserve_a,
                new_reserve_b,
                new_lp_supply,
                new_k_last,
                params_bytes.clone(),
                stored_a_tag.clone(),
                stored_b_tag.clone(),
            ),
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;

        // Consume the LP position.
        host::object_delete(lp_handle).map_err(|_| PoolError::InsufficientLiquidity)?;

        // Mint the two output coins.
        let coin_a_handle = host::object_create(
            &tags::coin_tag(stored_a_tag.clone()),
            &coin_payload(amount_a),
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;
        let coin_b_handle = host::object_create(
            &tags::coin_tag(stored_b_tag.clone()),
            &coin_payload(amount_b),
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;

        Ok((coin_a_handle, coin_b_handle))
    }

    /// Swap exact `amount_in` of `Coin<A>` for at-least `min_out` of `Coin<B>`.
    ///
    /// Returns `coin_b_handle` with the output amount.
    pub fn swap_exact_in<S>(
        pool_handle: RuntimeHandle,
        coin_in_handle: RuntimeHandle,
        min_out: u128,
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Result<RuntimeHandle, PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes, stored_a_tag, stored_b_tag) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;
        ensure_pool_pair(&stored_a_tag, &stored_b_tag, coin_a_tag, coin_b_tag)?;

        let params = S::Params::decode(&params_bytes).ok_or(PoolError::MathFailed(
            bloom_dex_math::MathError::ZeroReserves,
        ))?;

        let in_bytes =
            host::object_read(coin_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let amount_in = decode_coin_value(&in_bytes)?;

        let (new_reserve_a, new_reserve_b, amount_out) =
            S::apply_swap(reserve_a, reserve_b, amount_in, &params)
                .map_err(PoolError::MathFailed)?;

        if amount_out < min_out {
            return Err(PoolError::SlippageExceeded);
        }

        let new_k_last = checked_k_last(new_reserve_a, new_reserve_b)?;

        write_pool(
            pool_handle,
            &pool_raw,
            &(
                new_reserve_a,
                new_reserve_b,
                lp_supply,
                new_k_last,
                params_bytes.clone(),
                stored_a_tag.clone(),
                stored_b_tag.clone(),
            ),
        )
        .map_err(|_| PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;

        // Consume coin_in.
        host::object_delete(coin_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;

        // Mint coin_out.
        let coin_b_handle = host::object_create(
            &tags::coin_tag(stored_b_tag.clone()),
            &coin_payload(amount_out),
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;

        Ok(coin_b_handle)
    }

    /// Swap exact `amount_in` of `Coin<B>` for at-least `min_out` of `Coin<A>`.
    ///
    /// Mirror of `swap_exact_in` with A and B reversed.
    pub fn swap_exact_in_reverse<S>(
        pool_handle: RuntimeHandle,
        coin_in_handle: RuntimeHandle,
        min_out: u128,
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Result<RuntimeHandle, PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes, stored_a_tag, stored_b_tag) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;
        ensure_pool_pair(&stored_a_tag, &stored_b_tag, coin_a_tag, coin_b_tag)?;

        let params = S::Params::decode(&params_bytes).ok_or(PoolError::MathFailed(
            bloom_dex_math::MathError::ZeroReserves,
        ))?;

        let in_bytes =
            host::object_read(coin_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let amount_in = decode_coin_value(&in_bytes)?;

        // B→A swap: reserve_in=reserve_b, reserve_out=reserve_a.
        let (new_reserve_b, new_reserve_a, amount_out) =
            S::apply_swap(reserve_b, reserve_a, amount_in, &params)
                .map_err(PoolError::MathFailed)?;

        if amount_out < min_out {
            return Err(PoolError::SlippageExceeded);
        }

        let new_k_last = checked_k_last(new_reserve_a, new_reserve_b)?;

        write_pool(
            pool_handle,
            &pool_raw,
            &(
                new_reserve_a,
                new_reserve_b,
                lp_supply,
                new_k_last,
                params_bytes.clone(),
                stored_a_tag.clone(),
                stored_b_tag.clone(),
            ),
        )
        .map_err(|_| PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;

        // Consume coin_in.
        host::object_delete(coin_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;

        // Mint coin_a_out.
        let coin_a_handle = host::object_create(
            &tags::coin_tag(stored_a_tag.clone()),
            &coin_payload(amount_out),
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;

        Ok(coin_a_handle)
    }

    /// Swap at-most `max_in` of `Coin<A>` for exactly `amount_out` of `Coin<B>`.
    ///
    /// Returns `(coin_b_handle, leftover_coin_a_handle)`. The leftover is
    /// `None` if `max_in` was fully consumed (exact match on input).
    pub fn swap_exact_out<S>(
        pool_handle: RuntimeHandle,
        max_in_handle: RuntimeHandle,
        amount_out: u128,
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Result<(RuntimeHandle, Option<RuntimeHandle>), PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes, stored_a_tag, stored_b_tag) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;
        ensure_pool_pair(&stored_a_tag, &stored_b_tag, coin_a_tag, coin_b_tag)?;

        let params = S::Params::decode(&params_bytes).ok_or(PoolError::MathFailed(
            bloom_dex_math::MathError::ZeroReserves,
        ))?;

        if amount_out == 0 || amount_out >= reserve_b {
            return Err(PoolError::InsufficientLiquidity);
        }

        let max_in_bytes =
            host::object_read(max_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let max_in_value = decode_coin_value(&max_in_bytes)?;

        // Compute exact amount_in required for `amount_out`.
        let exact_in =
            compute_exact_in_for_out::<S>(reserve_a, reserve_b, amount_out, max_in_value, &params)?;

        if max_in_value < exact_in {
            return Err(PoolError::SlippageExceeded);
        }

        let new_reserve_a = reserve_a
            .checked_add(exact_in)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let new_reserve_b = reserve_b
            .checked_sub(amount_out)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let new_k_last = checked_k_last(new_reserve_a, new_reserve_b)?;

        write_pool(
            pool_handle,
            &pool_raw,
            &(
                new_reserve_a,
                new_reserve_b,
                lp_supply,
                new_k_last,
                params_bytes.clone(),
                stored_a_tag.clone(),
                stored_b_tag.clone(),
            ),
        )
        .map_err(|_| PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;

        // Mint output coin.
        let coin_b_handle = host::object_create(
            &tags::coin_tag(stored_b_tag.clone()),
            &coin_payload(amount_out),
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;

        // Handle leftover of max_in.
        let leftover = if exact_in < max_in_value {
            let leftover_amount = max_in_value - exact_in;
            host::object_delete(max_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
            let leftover_payload = coin_payload(leftover_amount);
            Some(
                host::object_create(&tags::coin_tag(stored_a_tag.clone()), &leftover_payload)
                    .map_err(|_| PoolError::InsufficientLiquidity)?,
            )
        } else {
            host::object_delete(max_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
            None
        };

        Ok((coin_b_handle, leftover))
    }

    /// Read `(reserve_a, reserve_b)` from a pool handle (read-only quote helper).
    pub fn reserves(pool_handle: RuntimeHandle) -> Result<(u128, u128), PoolError> {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, ..) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;
        Ok((reserve_a, reserve_b))
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Decode the `u128` value field of a `Coin<T>` payload.
    fn decode_coin_value(bytes: &[u8]) -> Result<u128, PoolError> {
        bloom_petal_fungible::ops::decode_coin_value(bytes)
            .map_err(|_| PoolError::InsufficientLiquidity)
    }

    /// Coin payload: 16-byte u128 value.
    fn coin_payload(value: u128) -> Vec<u8> {
        bloom_petal_fungible::ops::coin_payload(value)
    }

    fn pool_id_from_payload(bytes: &[u8]) -> Option<ObjectId> {
        if bytes.len() < 32 {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes[..32]);
        Some(ObjectId(id))
    }

    fn checked_k_last(reserve_a: u128, reserve_b: u128) -> Result<u128, PoolError> {
        reserve_a
            .checked_mul(reserve_b)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))
    }

    fn initial_lp_supply(lp_minted: u128) -> Result<u128, PoolError> {
        lp_minted
            .checked_add(bloom_dex_math::MINIMUM_LIQUIDITY)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))
    }

    fn ensure_pool_pair(
        stored_a_tag: &TypeTag,
        stored_b_tag: &TypeTag,
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Result<(), PoolError> {
        if stored_a_tag != coin_a_tag || stored_b_tag != coin_b_tag {
            return Err(PoolError::TokenTypeMismatch);
        }
        Ok(())
    }

    /// Compute the exact input amount required to receive `amount_out` of
    /// `Coin<B>` using strategy `S`.
    ///
    /// Uses a bounded binary search up to the caller-provided maximum input.
    fn compute_exact_in_for_out<S: SwapStrategy>(
        reserve_in: u128,
        reserve_out: u128,
        amount_out: u128,
        max_in: u128,
        params: &S::Params,
    ) -> Result<u128, PoolError> {
        if reserve_out <= amount_out {
            return Err(PoolError::InsufficientLiquidity);
        }
        if max_in == 0 {
            return Err(PoolError::SlippageExceeded);
        }
        let denom = reserve_out - amount_out;
        // Ceiling division for no-fee lower bound.
        let numerator = reserve_in
            .checked_mul(amount_out)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let lower = (numerator / denom).saturating_add(1).min(max_in);
        let max_out = match S::quote(reserve_in, reserve_out, max_in, params) {
            Ok(out) => out,
            Err(bloom_dex_math::MathError::InsufficientLiquidity)
            | Err(bloom_dex_math::MathError::ZeroAmountIn) => {
                return Err(PoolError::SlippageExceeded);
            }
            Err(e) => return Err(PoolError::MathFailed(e)),
        };
        if max_out < amount_out {
            return Err(PoolError::SlippageExceeded);
        }

        let mut lo = lower;
        let mut hi = max_in;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match S::quote(reserve_in, reserve_out, mid, params) {
                Ok(out) if out >= amount_out => hi = mid,
                Ok(_) | Err(bloom_dex_math::MathError::InsufficientLiquidity) => lo = mid + 1,
                Err(e) => return Err(PoolError::MathFailed(e)),
            }
        }
        Ok(lo)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use bloom_dex_math::{ConstantProduct, ConstantProductParams};

        #[test]
        fn exact_out_solver_handles_high_fee_bounds() {
            let params = ConstantProductParams { fee_bps: 9999 };

            assert_eq!(
                compute_exact_in_for_out::<ConstantProduct>(1000, 1000, 1, 20_000, &params),
                Ok(10_011)
            );
            assert_eq!(
                compute_exact_in_for_out::<ConstantProduct>(1000, 1000, 1, 10_010, &params),
                Err(PoolError::SlippageExceeded)
            );
        }

        #[test]
        fn checked_k_last_overflow_is_math_error() {
            assert_eq!(
                checked_k_last(u128::MAX, 2),
                Err(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))
            );
            assert_eq!(checked_k_last(11, 13), Ok(143));
        }

        #[test]
        fn initial_lp_supply_includes_locked_minimum() {
            assert_eq!(
                initial_lp_supply(5_000),
                Ok(5_000 + bloom_dex_math::MINIMUM_LIQUIDITY)
            );
        }
    }
}

// ─── Petal module — public entry points ──────────────────────────────────────

/// The `/bloom/petals/dex/pool` petal. Declares the on-chain objects and the
/// public entry points for pool lifecycle operations.
#[bloom::petal(path = "/bloom/petals/dex/pool", version = "0.1.0")]
pub mod pool {
    use bloom_objects::{ObjectId, TypeTag};
    use bloom_resource::{Coin, Resource, UID};

    use bloom_dex_math::{ConstantProduct, ConstantProductParams};

    use crate::{ParamCodec, ops};

    // ── On-chain object declarations ─────────────────────────────────────────

    /// DEX pool holding two coin reserves plus strategy-specific params.
    ///
    /// ## Field layout in the canonical payload
    ///
    /// `id (32) | reserve_a (16) | reserve_b (16) | lp_supply (16) |
    ///  k_last (16) | params_bytes (ULEB128 count + raw u8 elements) |
    ///  coin_a_tag | coin_b_tag`
    ///
    /// `reserve_a` and `reserve_b` are the raw u128 balances of the two
    /// token reserves stored as integers (not as `Coin` objects) because
    /// consuming a coin means deleting it from the borrow table; the pool
    /// accumulates raw values instead.
    ///
    /// In the handle/tag model (spec §11.2) the pool is operated on as an
    /// opaque on-chain object — there is no `Pool<A, B, S>` Rust generic.
    /// The two token identities `A`/`B` are persisted as canonical
    /// [`TypeTag`] values, and generic entrypoints compare their runtime coin
    /// tags against this stored pair before mutating reserves. The swap
    /// strategy is `ConstantProduct`, whose fee params live serialized in
    /// `params_bytes` (decoded via [`ParamCodec`]).
    #[bloom::object(abilities = "key, store")]
    pub struct Pool {
        /// On-chain object identifier.
        pub id: UID,
        /// Raw balance of token A in this pool.
        pub reserve_a: u128,
        /// Raw balance of token B in this pool.
        pub reserve_b: u128,
        /// Total LP shares currently outstanding.
        pub lp_supply: u128,
        /// Last-recorded k = reserve_a * reserve_b (for fee accounting).
        pub k_last: u128,
        /// Strategy-specific params, serialized via `ParamCodec`.
        pub params_bytes: Vec<u8>,
        /// Runtime type tag bound to the pool's token A side.
        pub coin_a_tag: TypeTag,
        /// Runtime type tag bound to the pool's token B side.
        pub coin_b_tag: TypeTag,
    }

    /// An LP position in a `Pool`.
    ///
    /// ## Field layout
    ///
    /// `id (32) | pool_id (32) | shares (16)`
    #[bloom::object(abilities = "key, store")]
    pub struct LpPosition {
        /// On-chain object identifier.
        pub id: UID,
        /// The pool this position belongs to.
        pub pool_id: ObjectId,
        /// LP share count.
        pub shares: u128,
    }

    // ── Entry points ─────────────────────────────────────────────────────────

    /// Create a fresh `Pool` and issue an initial `LpPosition`.
    ///
    /// Computes the initial LP shares via the `ConstantProduct` sqrt path.
    /// `MINIMUM_LIQUIDITY` is permanently locked in the pool's total LP supply;
    /// only the remaining minted shares are issued to the caller. `coin_a` and
    /// `coin_b` are consumed, and the LP position is returned alongside the pool.
    ///
    /// In the handle/tag model (spec §11.2) the exports take coin *handles*
    /// (`Coin<A>`/`Coin<B>` — the concrete on-chain token identities are
    /// supplied as runtime type args) and return the created objects as
    /// `Resource` handles, which the macro encodes as `ObjectId`s for
    /// cross-command threading.
    ///
    /// `params_bytes` is the `ConstantProduct` configuration serialized with
    /// [`ParamCodec::encode`] (e.g. `ConstantProductParams { fee_bps: 30 }`).
    /// Decoding it here rather than projecting an associated type keeps the
    /// signature free of types the petal macro cannot lower to a `TypeTag`.
    pub fn create_pool<A, B>(
        coin_a: Coin<A>,
        coin_b: Coin<B>,
        params_bytes: Vec<u8>,
    ) -> (Resource<Pool>, Resource<LpPosition>) {
        let params = ConstantProductParams::decode(&params_bytes)
            .expect("create_pool: invalid params_bytes — could not decode ConstantProductParams");
        let coin_a_tag = Coin::<A>::type_tag(0).expect("create_pool: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("create_pool: B tag must be bound");

        let (pool_h, lp_h) = ops::create_pool::<ConstantProduct>(
            coin_a.handle(),
            coin_b.handle(),
            &params,
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("create_pool host failure");
        (Resource::from_handle(pool_h), Resource::from_handle(lp_h))
    }

    /// Add liquidity to `pool`. Returns the new `LpPosition` and any
    /// un-consumed coin remainders.
    #[allow(clippy::type_complexity)]
    pub fn add_liquidity<A, B>(
        pool: &mut Resource<Pool>,
        coin_a: Coin<A>,
        coin_b: Coin<B>,
    ) -> (Resource<LpPosition>, Option<Coin<A>>, Option<Coin<B>>) {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("add_liquidity: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("add_liquidity: B tag must be bound");
        let (lp_h, la, lb) = ops::add_liquidity::<ConstantProduct>(
            pool.handle(),
            coin_a.handle(),
            coin_b.handle(),
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("add_liquidity host failure");
        (
            Resource::from_handle(lp_h),
            la.map(Coin::from_handle),
            lb.map(Coin::from_handle),
        )
    }

    /// Remove liquidity by consuming `position`. Returns `(Coin, Coin)`
    /// with proportional amounts of each reserve token.
    pub fn remove_liquidity<A, B>(
        pool: &mut Resource<Pool>,
        position: Resource<LpPosition>,
    ) -> (Coin<A>, Coin<B>) {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("remove_liquidity: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("remove_liquidity: B tag must be bound");
        let (ca, cb) = ops::remove_liquidity::<ConstantProduct>(
            pool.handle(),
            position.handle(),
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("remove_liquidity host failure");
        (Coin::from_handle(ca), Coin::from_handle(cb))
    }

    /// Swap exact `coin_in` (token A) for at-least `min_out` of token B.
    // `target = "Pool"` makes this fire after *every* Pool mutation, so the
    // predicate must hold across all of them — not just swaps. The
    // disjunct `!(after.lp_supply == before.lp_supply)` exempts liquidity
    // events (add/remove_liquidity), where `k` legitimately moves with the
    // reserves; on a pure swap `lp_supply` is unchanged, so `k` must not drop.
    #[invariant(
        name = "pool_k_non_decreasing",
        target = "Pool",
        pred = |before, after| after.reserve_a * after.reserve_b >= before.k_last
            || !(after.lp_supply == before.lp_supply)
    )]
    pub fn swap_exact_in<A, B>(
        coin_in: Coin<A>,
        pool: &mut Resource<Pool>,
        min_out: u128,
    ) -> Coin<B> {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("swap_exact_in: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("swap_exact_in: B tag must be bound");
        let out_h = ops::swap_exact_in::<ConstantProduct>(
            pool.handle(),
            coin_in.handle(),
            min_out,
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("swap_exact_in host failure");
        Coin::from_handle(out_h)
    }

    /// Swap exact `coin_in` (token B) for at-least `min_out` of token A.
    pub fn swap_exact_in_reverse<A, B>(
        coin_in: Coin<B>,
        pool: &mut Resource<Pool>,
        min_out: u128,
    ) -> Coin<A> {
        let coin_a_tag =
            Coin::<A>::type_tag(0).expect("swap_exact_in_reverse: A tag must be bound");
        let coin_b_tag =
            Coin::<B>::type_tag(1).expect("swap_exact_in_reverse: B tag must be bound");
        let out_h = ops::swap_exact_in_reverse::<ConstantProduct>(
            pool.handle(),
            coin_in.handle(),
            min_out,
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("swap_exact_in_reverse host failure");
        Coin::from_handle(out_h)
    }

    /// Swap at-most `max_in` (token A) for exactly `amount_out` of token B.
    ///
    /// Returns `(Coin, Option<Coin>)` where the option is the unconsumed
    /// remainder of `max_in` (if any).
    pub fn swap_exact_out<A, B>(
        pool: &mut Resource<Pool>,
        max_in: Coin<A>,
        amount_out: u128,
    ) -> (Coin<B>, Option<Coin<A>>) {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("swap_exact_out: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("swap_exact_out: B tag must be bound");
        let (cb_h, la) = ops::swap_exact_out::<ConstantProduct>(
            pool.handle(),
            max_in.handle(),
            amount_out,
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("swap_exact_out host failure");
        (Coin::from_handle(cb_h), la.map(Coin::from_handle))
    }

    /// Read `(reserve_a, reserve_b)` from a pool (read-only; for off-chain
    /// quoting).
    pub fn reserves(pool: &Resource<Pool>) -> (u128, u128) {
        ops::reserves(pool.handle()).expect("reserves host failure")
    }
}
