//! `/bloom/petals/dex/router` petal — multi-hop DEX routing.
//!
//! Exposes `quote_Nhop` (pure read-only quote) and `swap_Nhop` (executes a
//! multi-hop swap) for N ∈ {1, 2, 3}.
//!
//! ## No `petal.call` in v0
//!
//! Because the v0 host does not provide a cross-petal call import, the router
//! cannot delegate to `bloom-petal-dex-pool::pool::swap_exact_in` at runtime.
//! Instead it **inlines the swap math** by:
//!
//! 1. Reading the pool object's payload via `host::object_read`.
//! 2. Decoding reserves + params using helpers from `bloom-petal-dex-pool::payload`
//!    (shared through the `rlib` dependency).
//! 3. Computing the swap via `bloom_dex_math::SwapStrategy::apply_swap`.
//! 4. Writing the updated payload back via `host::object_mutate`.
//!
//! The pool payload format is defined in `bloom-petal-dex-pool::payload` (and
//! documented in that crate's source). The router re-uses those helpers
//! directly rather than duplicating the encoding.
//!
//! ## Petal entry points
//!
//! Declared inside `pub mod router` with
//! `#[bloom::petal(path = "/bloom/petals/dex/router", version = "0.1.0")]`.

#![deny(missing_docs)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use bloom_resource_macros as bloom;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors emitted by router entry points (panics on wasm → abort code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterError {
    /// Swap output is below the caller's `min_out` guard.
    SlippageExceeded {
        /// Amount expected (the `min_out` argument).
        expected: u128,
        /// Amount that would actually be received.
        got: u128,
    },
    /// Zero hops requested (unused in current API but reserved).
    ZeroHops,
    /// Delegated math computation returned an error.
    MathFailed(bloom_dex_math::MathError),
    /// Input coin has zero value.
    EmptyInput,
    /// Pool payload could not be decoded.
    PoolPayloadDecode,
    /// Strategy params could not be decoded from `params_bytes`.
    ParamDecode,
    /// A route reused the same pool for both hops.
    SamePoolRoute,
    /// The input coin could not be deleted after a hop.
    ObjectDeleteFailed,
    /// A route type tag does not match a pool's stored pair binding.
    TokenTypeMismatch,
}

impl core::fmt::Display for RouterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RouterError::SlippageExceeded { expected, got } => {
                write!(f, "slippage exceeded: expected {expected}, got {got}")
            }
            RouterError::ZeroHops => write!(f, "zero hops"),
            RouterError::MathFailed(e) => write!(f, "math failed: {e}"),
            RouterError::EmptyInput => write!(f, "empty input coin"),
            RouterError::PoolPayloadDecode => write!(f, "pool payload decode error"),
            RouterError::ParamDecode => write!(f, "strategy params decode error"),
            RouterError::SamePoolRoute => write!(f, "same pool route"),
            RouterError::ObjectDeleteFailed => write!(f, "object delete failed"),
            RouterError::TokenTypeMismatch => write!(f, "token type mismatch"),
        }
    }
}

impl From<bloom_dex_math::MathError> for RouterError {
    fn from(e: bloom_dex_math::MathError) -> Self {
        RouterError::MathFailed(e)
    }
}

// ─── Inner-level operations (host-aware, Result-typed) ───────────────────────

/// `Result`-typed inner operations.
///
/// These are the building blocks for the petal entry points. They issue host
/// imports directly and return `Err(RouterError)` on failure rather than
/// panicking. The `#[bloom::petal]` entry points are thin `expect`-wrappers.
pub mod ops {
    use bloom_dex_math::SwapStrategy;
    use bloom_objects::{ObjectId, TypeTag};
    use bloom_petal_dex_pool::{ParamCodec, payload};
    use bloom_resource::{RuntimeHandle, host};

    use crate::RouterError;

    // ── Pool payload helpers ─────────────────────────────────────────────────

    /// Decoded pool data: `(reserve_a, reserve_b, lp_supply, k_last, params_bytes, raw_bytes)`.
    ///
    /// `raw_bytes` is the original payload, needed to preserve the 32-byte id
    /// prefix when writing back.
    type PoolData = (u128, u128, u128, u128, Vec<u8>, TypeTag, TypeTag, Vec<u8>);

    /// Read and decode a pool handle's payload into [`PoolData`].
    pub fn read_pool(pool_handle: RuntimeHandle) -> Result<PoolData, RouterError> {
        let raw = host::object_read(pool_handle).map_err(|_| RouterError::PoolPayloadDecode)?;
        let (reserve_a, reserve_b, lp_supply, k_last, params_bytes, coin_a_tag, coin_b_tag) =
            payload::decode_pool(&raw).ok_or(RouterError::PoolPayloadDecode)?;
        Ok((
            reserve_a,
            reserve_b,
            lp_supply,
            k_last,
            params_bytes,
            coin_a_tag,
            coin_b_tag,
            raw,
        ))
    }

    /// Write updated pool reserves back to the borrow table.
    pub fn write_pool(
        pool_handle: RuntimeHandle,
        raw_bytes: &[u8],
        fields: &payload::DecodedPool,
    ) -> Result<(), RouterError> {
        if raw_bytes.len() < 32 {
            return Err(RouterError::PoolPayloadDecode);
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&raw_bytes[..32]);
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
        host::object_mutate(pool_handle, &new_payload).map_err(|_| RouterError::PoolPayloadDecode)
    }

    // ── Coin helpers ─────────────────────────────────────────────────────────

    /// Decode the `u128` value field of a `Coin<T>` payload.
    ///
    /// `Coin<T>` layout: `value (16 bytes BE)`.
    pub fn decode_coin_value(bytes: &[u8]) -> Result<u128, RouterError> {
        bloom_petal_fungible::ops::decode_coin_value(bytes).map_err(|_| RouterError::EmptyInput)
    }

    /// Build a `Coin<T>` payload with the given value.
    pub fn coin_payload(value: u128) -> Vec<u8> {
        bloom_petal_fungible::ops::coin_payload(value)
    }

    /// Create a new coin with the given value in the borrow table.
    pub fn coin_erased_tag() -> TypeTag {
        coin_tag(TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "Erased".to_string(),
            type_args: vec![],
        })
    }

    /// Build the object type tag for `Coin<inner>`.
    pub fn coin_tag(inner: TypeTag) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "Coin".to_string(),
            type_args: vec![inner],
        }
    }

    /// Create a new type-erased coin with the given value in the borrow table.
    fn create_coin(inner_type_tag: &TypeTag, value: u128) -> Result<RuntimeHandle, RouterError> {
        host::object_create(&coin_tag(inner_type_tag.clone()), &coin_payload(value))
            .map_err(|_| RouterError::MathFailed(bloom_dex_math::MathError::InsufficientLiquidity))
    }

    // ── Per-hop swap kernel ──────────────────────────────────────────────────

    /// Perform one swap hop: A→B.
    ///
    /// - Reads pool payload, decodes strategy params via `S::Params::decode`.
    /// - Calls `S::apply_swap` to compute the output.
    /// - Writes updated reserves back via `host::object_mutate`.
    /// - Deletes the input coin object; creates a fresh output coin using the
    ///   pool's stored output type tag.
    /// - Returns `(amount_out, new_coin_b_handle)`.
    pub fn hop<S>(
        pool_handle: RuntimeHandle,
        coin_in_handle: RuntimeHandle,
        min_out: u128,
        coin_in_tag: &TypeTag,
        coin_out_tag: &TypeTag,
    ) -> Result<(u128, RuntimeHandle), RouterError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let (
            reserve_a,
            reserve_b,
            lp_supply,
            _k_last,
            params_bytes,
            stored_in_tag,
            stored_out_tag,
            raw,
        ) = read_pool(pool_handle)?;
        ensure_pool_pair(&stored_in_tag, &stored_out_tag, coin_in_tag, coin_out_tag)?;

        let params = S::Params::decode(&params_bytes).ok_or(RouterError::ParamDecode)?;

        let coin_bytes = host::object_read(coin_in_handle).map_err(|_| RouterError::EmptyInput)?;
        let amount_in = decode_coin_value(&coin_bytes)?;

        if amount_in == 0 {
            return Err(RouterError::EmptyInput);
        }

        let (new_reserve_a, new_reserve_b, amount_out) =
            S::apply_swap(reserve_a, reserve_b, amount_in, &params)?;

        if amount_out < min_out {
            return Err(RouterError::SlippageExceeded {
                expected: min_out,
                got: amount_out,
            });
        }

        let new_k_last = checked_k_last(new_reserve_a, new_reserve_b)?;

        write_pool(
            pool_handle,
            &raw,
            &(
                new_reserve_a,
                new_reserve_b,
                lp_supply,
                new_k_last,
                params_bytes.clone(),
                stored_in_tag.clone(),
                stored_out_tag.clone(),
            ),
        )?;

        // Consume coin_in.
        host::object_delete(coin_in_handle).map_err(|_| RouterError::ObjectDeleteFailed)?;

        // Mint coin_out using the output side of the pool's stored pair binding.
        let coin_out = create_coin(&stored_out_tag, amount_out)?;

        Ok((amount_out, coin_out))
    }

    /// Reject a two-hop route that reuses the same pool on both hops.
    pub fn ensure_distinct_pools(
        pool1_handle: RuntimeHandle,
        pool2_handle: RuntimeHandle,
    ) -> Result<(), RouterError> {
        if pool1_handle == pool2_handle {
            return Err(RouterError::SamePoolRoute);
        }
        Ok(())
    }

    /// Reject a route that reuses any pool handle.
    pub fn ensure_all_distinct_pools(
        pool1_handle: RuntimeHandle,
        pool2_handle: RuntimeHandle,
        pool3_handle: RuntimeHandle,
    ) -> Result<(), RouterError> {
        ensure_distinct_pools(pool1_handle, pool2_handle)?;
        ensure_distinct_pools(pool1_handle, pool3_handle)?;
        ensure_distinct_pools(pool2_handle, pool3_handle)
    }

    /// Reject route type tags that do not match a pool's stored pair.
    pub fn ensure_pool_pair(
        stored_a_tag: &TypeTag,
        stored_b_tag: &TypeTag,
        coin_a_tag: &TypeTag,
        coin_b_tag: &TypeTag,
    ) -> Result<(), RouterError> {
        if stored_a_tag != coin_a_tag || stored_b_tag != coin_b_tag {
            return Err(RouterError::TokenTypeMismatch);
        }
        Ok(())
    }

    // ── Quote helpers (pure, no host writes) ─────────────────────────────────

    /// Compute quoted output for a single hop A→B (read-only).
    pub fn quote_one<S>(
        pool_handle: RuntimeHandle,
        amount_in: u128,
        coin_in_tag: &TypeTag,
        coin_out_tag: &TypeTag,
    ) -> Result<u128, RouterError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let (
            reserve_a,
            reserve_b,
            _lp_supply,
            _k_last,
            params_bytes,
            stored_in_tag,
            stored_out_tag,
            _raw,
        ) = read_pool(pool_handle)?;
        ensure_pool_pair(&stored_in_tag, &stored_out_tag, coin_in_tag, coin_out_tag)?;
        let params = S::Params::decode(&params_bytes).ok_or(RouterError::ParamDecode)?;
        Ok(S::quote(reserve_a, reserve_b, amount_in, &params)?)
    }

    fn checked_k_last(reserve_a: u128, reserve_b: u128) -> Result<u128, RouterError> {
        reserve_a
            .checked_mul(reserve_b)
            .ok_or(RouterError::MathFailed(bloom_dex_math::MathError::Overflow))
    }
}

// ─── Petal module — public entry points ──────────────────────────────────────

/// The `/bloom/petals/dex/router` petal. Multi-hop quote and swap operations.
///
/// ## Swap model
///
/// All `swap_Nhop` functions:
/// - Take `&mut Resource<Pool>` object handles — the macro arranges a Mutable
///   borrow and materializes the handle from each arg's `ObjectId`.
/// - Take a linear typed `Coin` input that is fully consumed, using
///   runtime type args to bind each hop to the pool's stored token tags.
/// - Return a freshly minted typed `Coin`, encoded by the macro as an
///   `ObjectId` for cross-command threading.
/// - The `min_out` guard applies to the **final** output only; intermediate
///   hops use `0` (the outer slippage check makes this safe).
///
/// ## Inline math
///
/// There is no `petal.call` in v0. The router re-implements the per-hop
/// swap kernel by reading/writing pool payloads via `ops::hop::<ConstantProduct>`,
/// which uses `bloom-petal-dex-pool::payload` helpers (shared `rlib` dep) and
/// `bloom-dex-math::SwapStrategy::apply_swap`. `ConstantProduct` is the only
/// strategy; its fee params live serialized in each pool's `params_bytes`.
#[bloom::petal(path = "/bloom/petals/dex/router", version = "0.1.0")]
pub mod router {
    use bloom_dex_math::ConstantProduct;
    use bloom_petal_dex_pool::pool::Pool;
    use bloom_resource::{Coin, Resource};

    use crate::ops;

    // ── quote_1hop ───────────────────────────────────────────────────────────

    /// Predict the output of a single-hop swap A→B without changing state.
    ///
    /// Returns `amount_out` for the given `amount_in`. Reads the pool reserves
    /// and strategy params, calls `ConstantProduct::quote`, and returns the
    /// result.
    pub fn quote_1hop<A, B>(pool: &Resource<Pool>, amount_in: u128) -> u128 {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("quote_1hop: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("quote_1hop: B tag must be bound");
        ops::quote_one::<ConstantProduct>(pool.handle(), amount_in, &coin_a_tag, &coin_b_tag)
            .expect("quote_1hop: host failure")
    }

    // ── quote_2hop ───────────────────────────────────────────────────────────

    /// Predict the output of a two-hop swap A→B→C without changing state.
    ///
    /// Chains a quote on `pool1` then `pool2`, threading the intermediate
    /// amount through.
    pub fn quote_2hop<A, B, C>(
        pool1: &Resource<Pool>,
        pool2: &Resource<Pool>,
        amount_in: u128,
    ) -> u128 {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("quote_2hop: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("quote_2hop: B tag must be bound");
        let coin_c_tag = Coin::<C>::type_tag(2).expect("quote_2hop: C tag must be bound");
        ops::ensure_distinct_pools(pool1.handle(), pool2.handle())
            .expect("quote_2hop: same pool route");
        let mid =
            ops::quote_one::<ConstantProduct>(pool1.handle(), amount_in, &coin_a_tag, &coin_b_tag)
                .expect("quote_2hop: pool1 quote failure");
        ops::quote_one::<ConstantProduct>(pool2.handle(), mid, &coin_b_tag, &coin_c_tag)
            .expect("quote_2hop: pool2 quote failure")
    }

    // ── quote_3hop ───────────────────────────────────────────────────────────

    /// Predict the output of a three-hop swap A→B→C→D without changing state.
    ///
    /// Chains three sequential quotes through pools 1, 2, 3.
    pub fn quote_3hop<A, B, C, D>(
        pool1: &Resource<Pool>,
        pool2: &Resource<Pool>,
        pool3: &Resource<Pool>,
        amount_in: u128,
    ) -> u128 {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("quote_3hop: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("quote_3hop: B tag must be bound");
        let coin_c_tag = Coin::<C>::type_tag(2).expect("quote_3hop: C tag must be bound");
        let coin_d_tag = Coin::<D>::type_tag(3).expect("quote_3hop: D tag must be bound");
        ops::ensure_all_distinct_pools(pool1.handle(), pool2.handle(), pool3.handle())
            .expect("quote_3hop: same pool route");
        let mid1 =
            ops::quote_one::<ConstantProduct>(pool1.handle(), amount_in, &coin_a_tag, &coin_b_tag)
                .expect("quote_3hop: pool1 quote failure");
        let mid2 =
            ops::quote_one::<ConstantProduct>(pool2.handle(), mid1, &coin_b_tag, &coin_c_tag)
                .expect("quote_3hop: pool2 quote failure");
        ops::quote_one::<ConstantProduct>(pool3.handle(), mid2, &coin_c_tag, &coin_d_tag)
            .expect("quote_3hop: pool3 quote failure")
    }

    // ── swap_1hop ────────────────────────────────────────────────────────────

    /// Execute a single-hop swap A→B.
    ///
    /// Consumes `coin_in`. Returns a freshly minted output coin.
    /// Panics if `amount_out < min_out` (slippage guard).
    pub fn swap_1hop<A, B>(pool: &mut Resource<Pool>, coin_in: Coin<A>, min_out: u128) -> Coin<B> {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("swap_1hop: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("swap_1hop: B tag must be bound");
        let (_amount_out, coin_out_handle) = ops::hop::<ConstantProduct>(
            pool.handle(),
            coin_in.handle(),
            min_out,
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("swap_1hop: host failure");
        Coin::from_handle(coin_out_handle)
    }

    // ── swap_2hop ────────────────────────────────────────────────────────────

    /// Execute a two-hop swap A→B→C.
    ///
    /// Consumes `coin_in`. The intermediate coin is created and immediately
    /// consumed inside this function — it never escapes. Returns a freshly
    /// minted output coin. The `min_out` guard applies to the final output
    /// only; the intermediate hop uses `min_out = 0`.
    pub fn swap_2hop<A, B, C>(
        pool1: &mut Resource<Pool>,
        pool2: &mut Resource<Pool>,
        coin_in: Coin<A>,
        min_out: u128,
    ) -> Coin<C> {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("swap_2hop: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("swap_2hop: B tag must be bound");
        let coin_c_tag = Coin::<C>::type_tag(2).expect("swap_2hop: C tag must be bound");
        ops::ensure_distinct_pools(pool1.handle(), pool2.handle())
            .expect("swap_2hop: same pool route");
        // Hop 1: A→B (min_out=0; slippage checked at final output).
        let (_mid_amount, coin_mid_handle) = ops::hop::<ConstantProduct>(
            pool1.handle(),
            coin_in.handle(),
            0,
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("swap_2hop: hop 1 failure");

        // Hop 2: B→C (min_out = user's slippage bound).
        let (_final_amount, coin_out_handle) = ops::hop::<ConstantProduct>(
            pool2.handle(),
            coin_mid_handle,
            min_out,
            &coin_b_tag,
            &coin_c_tag,
        )
        .expect("swap_2hop: hop 2 failure");

        Coin::from_handle(coin_out_handle)
    }

    // ── swap_3hop ────────────────────────────────────────────────────────────

    /// Execute a three-hop swap A→B→C→D.
    ///
    /// Consumes `coin_in`. Both intermediate coins are created and consumed
    /// atomically inside this function. Returns a freshly minted output coin.
    /// The `min_out` guard applies to the final output only.
    pub fn swap_3hop<A, B, C, D>(
        pool1: &mut Resource<Pool>,
        pool2: &mut Resource<Pool>,
        pool3: &mut Resource<Pool>,
        coin_in: Coin<A>,
        min_out: u128,
    ) -> Coin<D> {
        let coin_a_tag = Coin::<A>::type_tag(0).expect("swap_3hop: A tag must be bound");
        let coin_b_tag = Coin::<B>::type_tag(1).expect("swap_3hop: B tag must be bound");
        let coin_c_tag = Coin::<C>::type_tag(2).expect("swap_3hop: C tag must be bound");
        let coin_d_tag = Coin::<D>::type_tag(3).expect("swap_3hop: D tag must be bound");
        ops::ensure_all_distinct_pools(pool1.handle(), pool2.handle(), pool3.handle())
            .expect("swap_3hop: same pool route");
        // Hop 1: A→B.
        let (_mid1_amount, coin_mid1_handle) = ops::hop::<ConstantProduct>(
            pool1.handle(),
            coin_in.handle(),
            0,
            &coin_a_tag,
            &coin_b_tag,
        )
        .expect("swap_3hop: hop 1 failure");

        // Hop 2: B→C.
        let (_mid2_amount, coin_mid2_handle) = ops::hop::<ConstantProduct>(
            pool2.handle(),
            coin_mid1_handle,
            0,
            &coin_b_tag,
            &coin_c_tag,
        )
        .expect("swap_3hop: hop 2 failure");

        // Hop 3: C→D (min_out = user's slippage bound).
        let (_final_amount, coin_out_handle) = ops::hop::<ConstantProduct>(
            pool3.handle(),
            coin_mid2_handle,
            min_out,
            &coin_c_tag,
            &coin_d_tag,
        )
        .expect("swap_3hop: hop 3 failure");

        Coin::from_handle(coin_out_handle)
    }
}
