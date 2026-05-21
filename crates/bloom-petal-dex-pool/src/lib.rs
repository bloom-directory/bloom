//! `/bloom/dex/pool` petal — strategy-generic DEX pool.
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
//! `Vec<u8>` (length-prefixed, using `bloom_resource::abi::RetWriter`)
//! and stored in `params_bytes: Vec<u8>`. Strategies must implement
//! [`ParamCodec`] (two tiny functions) so the pool can encode on `create`
//! and decode on every operation. `ConstantProductParams` (30 bps,
//! 2-byte big-endian) is the reference impl.
//!
//! ## Petal entry points
//!
//! Declared inside `pub mod pool` with
//! `#[bloom::petal(path = "/bloom/dex/pool", version = "0.1.0")]`.

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
        if bytes.len() < 2 {
            return None;
        }
        let fee_bps = u16::from_be_bytes([bytes[0], bytes[1]]);
        Some(Self { fee_bps })
    }
}

// ─── Pool payload helpers (host-side math; no host imports) ──────────────────

/// Payload codec helpers used by both `ops` and the unit tests.
pub mod payload {
    use bloom_objects::ObjectId;
    use bloom_resource::abi::{ArgReader, RetWriter};

    // Layout of `Pool<A, B, S>` payload written to the chain:
    //   [ id          : 32 bytes ]   ← ObjectId placeholder (host fills on create)
    //   [ reserve_a   : 16 bytes BE ]
    //   [ reserve_b   : 16 bytes BE ]
    //   [ lp_supply   : 16 bytes BE ]
    //   [ k_last      : 16 bytes BE ]
    //   [ params_bytes: 4 BE len + raw ]
    //   total: 84 + len(params) bytes

    /// Encode a `Pool` payload.
    pub fn pool_payload(
        id: &ObjectId,
        reserve_a: u128,
        reserve_b: u128,
        lp_supply: u128,
        k_last: u128,
        params_bytes: &[u8],
    ) -> Vec<u8> {
        let mut w = RetWriter::with_capacity(84 + params_bytes.len());
        w.write_object_id(id);
        w.write_u128(reserve_a);
        w.write_u128(reserve_b);
        w.write_u128(lp_supply);
        w.write_u128(k_last);
        w.write_bytes(params_bytes);
        w.finish()
    }

    /// Decode fields from a `Pool` payload slice.
    ///
    /// Returns `(reserve_a, reserve_b, lp_supply, k_last, params_bytes)` or
    /// `None` if the buffer is too short / malformed.
    pub fn decode_pool(bytes: &[u8]) -> Option<(u128, u128, u128, u128, Vec<u8>)> {
        let mut r = ArgReader::new(bytes);
        r.read_object_id().ok()?; // skip id
        let reserve_a = r.read_u128().ok()?;
        let reserve_b = r.read_u128().ok()?;
        let lp_supply = r.read_u128().ok()?;
        let k_last = r.read_u128().ok()?;
        let params = r.read_bytes().ok()?;
        Some((reserve_a, reserve_b, lp_supply, k_last, params))
    }

    // Layout of `LpPosition<A, B, S>` payload:
    //   [ id      : 32 bytes ]
    //   [ pool_id : 32 bytes ]
    //   [ shares  : 16 bytes BE ]
    //   total: 80 bytes

    /// Encode an `LpPosition` payload.
    pub fn lp_payload(id: &ObjectId, pool_id: &ObjectId, shares: u128) -> Vec<u8> {
        let mut w = RetWriter::with_capacity(80);
        w.write_object_id(id);
        w.write_object_id(pool_id);
        w.write_u128(shares);
        w.finish()
    }

    /// Decode fields from an `LpPosition` payload slice.
    ///
    /// Returns `(pool_id, shares)` or `None` on malformed input.
    pub fn decode_lp(bytes: &[u8]) -> Option<(ObjectId, u128)> {
        let mut r = ArgReader::new(bytes);
        r.read_object_id().ok()?; // skip own id
        let pool_id = r.read_object_id().ok()?;
        let shares = r.read_u128().ok()?;
        Some((pool_id, shares))
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
}

impl core::fmt::Display for PoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PoolError::SlippageExceeded => write!(f, "slippage exceeded"),
            PoolError::InsufficientLiquidity => write!(f, "insufficient liquidity"),
            PoolError::MathFailed(e) => write!(f, "math failed: {e}"),
            PoolError::WrongPool => write!(f, "wrong pool"),
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

    pub fn generic(idx: u16) -> TypeTag {
        TypeTag::Generic { idx }
    }

    /// `TypeTag` for `Pool<A, B, S>` using generic indices 0, 1, 2.
    pub fn pool_tag() -> TypeTag {
        concrete("Pool", vec![generic(0), generic(1), generic(2)])
    }

    /// `TypeTag` for `LpPosition<A, B, S>` using generic indices 0, 1, 2.
    pub fn lp_position_tag() -> TypeTag {
        concrete("LpPosition", vec![generic(0), generic(1), generic(2)])
    }

    /// `TypeTag` for `Coin<Generic{idx}>`.
    pub fn coin_tag(idx: u16) -> TypeTag {
        concrete("Coin", vec![generic(idx)])
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
    use bloom_objects::ObjectId;
    use bloom_resource::host;
    use bloom_resource::{PetalError, RuntimeHandle, abi::RetWriter};

    use crate::{ParamCodec, PoolError, payload, tags};

    // ── Pool payload r/w helpers ─────────────────────────────────────────────

    /// Decode a pool handle's payload from the borrow table.
    pub fn read_pool(
        pool_handle: RuntimeHandle,
    ) -> Result<(u128, u128, u128, u128, Vec<u8>), PetalError> {
        let bytes = host::object_read(pool_handle)?;
        payload::decode_pool(&bytes).ok_or(PetalError::InvalidArgs)
    }

    /// Re-encode and mutate a pool back into the borrow table.
    pub fn write_pool(
        pool_handle: RuntimeHandle,
        existing_bytes: &[u8],
        reserve_a: u128,
        reserve_b: u128,
        lp_supply: u128,
        k_last: u128,
        params_bytes: &[u8],
    ) -> Result<(), PetalError> {
        // Preserve the 32-byte id prefix from the existing payload.
        if existing_bytes.len() < 32 {
            return Err(PetalError::InvalidArgs);
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&existing_bytes[..32]);
        let id = ObjectId(id_bytes);
        let new_payload =
            payload::pool_payload(&id, reserve_a, reserve_b, lp_supply, k_last, params_bytes);
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

        let k_last = taken_a.saturating_mul(taken_b);
        let params_bytes = params.encode();

        let pool_payload = payload::pool_payload(
            &ObjectId([0u8; 32]),
            taken_a,
            taken_b,
            lp_minted,
            k_last,
            &params_bytes,
        );
        let lp_payload = payload::lp_payload(
            &ObjectId([0u8; 32]),
            &ObjectId([0u8; 32]), // pool_id filled by host on creation
            lp_minted,
        );

        let pool_handle = host::object_create(&tags::pool_tag(), &pool_payload)
            .map_err(|_| PoolError::InsufficientLiquidity)?;
        let lp_handle = host::object_create(&tags::lp_position_tag(), &lp_payload)
            .map_err(|_| PoolError::InsufficientLiquidity)?;

        // Consume the input coins (fully taken on initial deposit).
        let _ = host::object_delete(coin_a_handle);
        let _ = host::object_delete(coin_b_handle);

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
    ) -> Result<(RuntimeHandle, Option<RuntimeHandle>, Option<RuntimeHandle>), PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;

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
        let new_k_last = new_reserve_a.saturating_mul(new_reserve_b);

        write_pool(
            pool_handle,
            &pool_raw,
            new_reserve_a,
            new_reserve_b,
            new_lp_supply,
            new_k_last,
            &params_bytes,
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

        // Handle unused coin remainders.
        let leftover_a = if taken_a < value_a {
            let leftover_amount = value_a - taken_a;
            let new_a_bytes = rewrite_coin_value(&a_bytes, taken_a);
            let _ = host::object_mutate(coin_a_handle, &new_a_bytes);
            let leftover_payload = coin_payload(&ObjectId([0u8; 32]), leftover_amount);
            host::object_create(&tags::coin_tag(0), &leftover_payload).ok()
        } else {
            let _ = host::object_delete(coin_a_handle);
            None
        };

        let leftover_b = if taken_b < value_b {
            let leftover_amount = value_b - taken_b;
            let new_b_bytes = rewrite_coin_value(&b_bytes, taken_b);
            let _ = host::object_mutate(coin_b_handle, &new_b_bytes);
            let leftover_payload = coin_payload(&ObjectId([0u8; 32]), leftover_amount);
            host::object_create(&tags::coin_tag(1), &leftover_payload).ok()
        } else {
            let _ = host::object_delete(coin_b_handle);
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
    ) -> Result<(RuntimeHandle, RuntimeHandle), PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;

        let lp_bytes = host::object_read(lp_handle).map_err(|_| PoolError::WrongPool)?;
        let (_pool_id, shares) = payload::decode_lp(&lp_bytes).ok_or(PoolError::WrongPool)?;

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
        let new_k_last = new_reserve_a.saturating_mul(new_reserve_b);

        write_pool(
            pool_handle,
            &pool_raw,
            new_reserve_a,
            new_reserve_b,
            new_lp_supply,
            new_k_last,
            &params_bytes,
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;

        // Consume the LP position.
        let _ = host::object_delete(lp_handle);

        // Mint the two output coins.
        let coin_a_handle = host::object_create(
            &tags::coin_tag(0),
            &coin_payload(&ObjectId([0u8; 32]), amount_a),
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;
        let coin_b_handle = host::object_create(
            &tags::coin_tag(1),
            &coin_payload(&ObjectId([0u8; 32]), amount_b),
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
    ) -> Result<RuntimeHandle, PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;

        let params = S::Params::decode(&params_bytes).ok_or(PoolError::MathFailed(
            bloom_dex_math::MathError::ZeroReserves,
        ))?;

        let in_bytes =
            host::object_read(coin_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let amount_in = decode_coin_value(&in_bytes)?;

        let (_new_ri, _new_ro, amount_out) =
            S::apply_swap(reserve_a, reserve_b, amount_in, &params)
                .map_err(PoolError::MathFailed)?;

        if amount_out < min_out {
            return Err(PoolError::SlippageExceeded);
        }

        let new_reserve_a = reserve_a
            .checked_add(amount_in)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let new_reserve_b = reserve_b
            .checked_sub(amount_out)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let new_k_last = new_reserve_a.saturating_mul(new_reserve_b);

        write_pool(
            pool_handle,
            &pool_raw,
            new_reserve_a,
            new_reserve_b,
            lp_supply,
            new_k_last,
            &params_bytes,
        )
        .map_err(|_| PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;

        // Consume coin_in.
        let _ = host::object_delete(coin_in_handle);

        // Mint coin_out.
        let coin_b_handle = host::object_create(
            &tags::coin_tag(1),
            &coin_payload(&ObjectId([0u8; 32]), amount_out),
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
    ) -> Result<RuntimeHandle, PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;

        let params = S::Params::decode(&params_bytes).ok_or(PoolError::MathFailed(
            bloom_dex_math::MathError::ZeroReserves,
        ))?;

        let in_bytes =
            host::object_read(coin_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let amount_in = decode_coin_value(&in_bytes)?;

        // B→A swap: reserve_in=reserve_b, reserve_out=reserve_a.
        let (_new_ri, _new_ro, amount_out) =
            S::apply_swap(reserve_b, reserve_a, amount_in, &params)
                .map_err(PoolError::MathFailed)?;

        if amount_out < min_out {
            return Err(PoolError::SlippageExceeded);
        }

        let new_reserve_b = reserve_b
            .checked_add(amount_in)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let new_reserve_a = reserve_a
            .checked_sub(amount_out)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let new_k_last = new_reserve_a.saturating_mul(new_reserve_b);

        write_pool(
            pool_handle,
            &pool_raw,
            new_reserve_a,
            new_reserve_b,
            lp_supply,
            new_k_last,
            &params_bytes,
        )
        .map_err(|_| PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;

        // Consume coin_in.
        let _ = host::object_delete(coin_in_handle);

        // Mint coin_a_out.
        let coin_a_handle = host::object_create(
            &tags::coin_tag(0),
            &coin_payload(&ObjectId([0u8; 32]), amount_out),
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
    ) -> Result<(RuntimeHandle, Option<RuntimeHandle>), PoolError>
    where
        S: SwapStrategy,
        S::Params: ParamCodec,
    {
        let pool_raw =
            host::object_read(pool_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let (reserve_a, reserve_b, lp_supply, _k_last, params_bytes) =
            payload::decode_pool(&pool_raw).ok_or(PoolError::InsufficientLiquidity)?;

        let params = S::Params::decode(&params_bytes).ok_or(PoolError::MathFailed(
            bloom_dex_math::MathError::ZeroReserves,
        ))?;

        if amount_out == 0 || amount_out >= reserve_b {
            return Err(PoolError::InsufficientLiquidity);
        }

        // Compute exact amount_in required for `amount_out`.
        let exact_in = compute_exact_in_for_out::<S>(reserve_a, reserve_b, amount_out, &params)?;

        let max_in_bytes =
            host::object_read(max_in_handle).map_err(|_| PoolError::InsufficientLiquidity)?;
        let max_in_value = decode_coin_value(&max_in_bytes)?;

        if max_in_value < exact_in {
            return Err(PoolError::SlippageExceeded);
        }

        let new_reserve_a = reserve_a
            .checked_add(exact_in)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let new_reserve_b = reserve_b
            .checked_sub(amount_out)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let new_k_last = new_reserve_a.saturating_mul(new_reserve_b);

        write_pool(
            pool_handle,
            &pool_raw,
            new_reserve_a,
            new_reserve_b,
            lp_supply,
            new_k_last,
            &params_bytes,
        )
        .map_err(|_| PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;

        // Mint output coin.
        let coin_b_handle = host::object_create(
            &tags::coin_tag(1),
            &coin_payload(&ObjectId([0u8; 32]), amount_out),
        )
        .map_err(|_| PoolError::InsufficientLiquidity)?;

        // Handle leftover of max_in.
        let leftover = if exact_in < max_in_value {
            let leftover_amount = max_in_value - exact_in;
            let new_max_bytes = rewrite_coin_value(&max_in_bytes, exact_in);
            let _ = host::object_mutate(max_in_handle, &new_max_bytes);
            let leftover_payload = coin_payload(&ObjectId([0u8; 32]), leftover_amount);
            host::object_create(&tags::coin_tag(0), &leftover_payload).ok()
        } else {
            let _ = host::object_delete(max_in_handle);
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

    /// Decode the `u128` value field (bytes 32..48) of a `Coin<T>` payload.
    fn decode_coin_value(bytes: &[u8]) -> Result<u128, PoolError> {
        if bytes.len() < 48 {
            return Err(PoolError::InsufficientLiquidity);
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&bytes[32..48]);
        Ok(u128::from_be_bytes(buf))
    }

    /// Re-encode a `Coin<T>` payload with a new value, preserving the 32-byte id.
    fn rewrite_coin_value(existing: &[u8], new_value: u128) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        let id_len = 32.min(existing.len());
        out.extend_from_slice(&existing[..id_len]);
        if id_len < 32 {
            out.resize(32, 0);
        }
        out.extend_from_slice(&new_value.to_be_bytes());
        out
    }

    /// Coin payload: 32-byte id placeholder + 16-byte u128 value.
    fn coin_payload(id: &ObjectId, value: u128) -> Vec<u8> {
        let mut w = RetWriter::with_capacity(48);
        w.write_object_id(id);
        w.write_u128(value);
        w.finish()
    }

    /// Compute the exact input amount required to receive `amount_out` of
    /// `Coin<B>` using strategy `S`.
    ///
    /// Uses an iterative approach starting from the no-fee lower bound and
    /// bumping up until `S::quote(...) >= amount_out`.
    fn compute_exact_in_for_out<S: SwapStrategy>(
        reserve_in: u128,
        reserve_out: u128,
        amount_out: u128,
        params: &S::Params,
    ) -> Result<u128, PoolError> {
        if reserve_out <= amount_out {
            return Err(PoolError::InsufficientLiquidity);
        }
        let denom = reserve_out - amount_out;
        // Ceiling division for no-fee lower bound.
        let numerator = reserve_in
            .checked_mul(amount_out)
            .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
        let mut guess = numerator / denom + 1; // +1 for fee headroom

        // Bump until the quoted output meets `amount_out`.
        for _ in 0..64u8 {
            match S::quote(reserve_in, reserve_out, guess, params) {
                Ok(out) if out >= amount_out => return Ok(guess),
                Ok(_) => {
                    guess = guess
                        .checked_add(1)
                        .ok_or(PoolError::MathFailed(bloom_dex_math::MathError::Overflow))?;
                }
                Err(e) => return Err(PoolError::MathFailed(e)),
            }
        }
        Err(PoolError::MathFailed(
            bloom_dex_math::MathError::InsufficientLiquidity,
        ))
    }
}

// ─── Petal module — public entry points ──────────────────────────────────────

/// The `/bloom/dex/pool` petal. Declares the on-chain objects and the
/// public entry points for pool lifecycle operations.
#[bloom::petal(path = "/bloom/dex/pool", version = "0.1.0")]
pub mod pool {
    use bloom_dex_math::SwapStrategy;
    use bloom_objects::ObjectId;
    use bloom_resource::{Coin, UID};
    use core::marker::PhantomData;

    use crate::{ParamCodec, ops};

    // ── On-chain object declarations ─────────────────────────────────────────

    /// DEX pool holding two coin reserves plus strategy-specific params.
    ///
    /// ## Field layout in the canonical payload
    ///
    /// `id (32) | reserve_a (16) | reserve_b (16) | lp_supply (16) |
    ///  k_last (16) | params_bytes (4-len + raw)`
    ///
    /// `reserve_a` and `reserve_b` are the raw u128 balances of the two
    /// token reserves stored as integers (not as `Coin<A>` / `Coin<B>`
    /// objects) because consuming a coin means deleting it from the
    /// borrow table; the pool accumulates raw values instead.
    ///
    /// `params_bytes` stores the strategy params serialized via [`ParamCodec`].
    /// See the crate-level doc for why this workaround is used instead of
    /// the direct `S::Params` associated-type projection.
    #[bloom::object(abilities = "key, store", phantom = "A, B, S")]
    pub struct Pool<A, B, S> {
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
        /// Phantom marker for A.
        pub _phantom_a: PhantomData<A>,
        /// Phantom marker for B.
        pub _phantom_b: PhantomData<B>,
        /// Phantom marker for S.
        pub _phantom_s: PhantomData<S>,
    }

    /// An LP position in a `Pool<A, B, S>`.
    ///
    /// ## Field layout
    ///
    /// `id (32) | pool_id (32) | shares (16)`
    #[bloom::object(abilities = "key, store", phantom = "A, B, S")]
    pub struct LpPosition<A, B, S> {
        /// On-chain object identifier.
        pub id: UID,
        /// The pool this position belongs to.
        pub pool_id: ObjectId,
        /// LP share count.
        pub shares: u128,
        /// Phantom marker for A.
        pub _phantom_a: PhantomData<A>,
        /// Phantom marker for B.
        pub _phantom_b: PhantomData<B>,
        /// Phantom marker for S.
        pub _phantom_s: PhantomData<S>,
    }

    // ── Entry points ─────────────────────────────────────────────────────────

    /// Create a fresh `Pool<A, B, S>` and issue an initial `LpPosition<A, B, S>`.
    ///
    /// Computes the initial LP shares as `floor(sqrt(value_a * value_b))` via
    /// `S::add_liquidity(0, 0, value_a, value_b, 0)` (the sqrt path).
    /// `coin_a` and `coin_b` are consumed; the LP position is returned to the
    /// caller alongside the pool object.
    ///
    /// `params_bytes` is the strategy-specific configuration serialized with
    /// [`ParamCodec::encode`]. Callers encode their `S::Params` value before
    /// passing it here (e.g. `ConstantProductParams { fee_bps: 30 }.encode()`).
    /// This avoids an associated-type projection in the function signature,
    /// which the petal macro cannot lower to a manifest `TypeTag`.
    pub fn create_pool<A, B, S: SwapStrategy>(
        coin_a: Coin<A>,
        coin_b: Coin<B>,
        params_bytes: Vec<u8>,
    ) -> (Pool<A, B, S>, LpPosition<A, B, S>)
    where
        S::Params: ParamCodec,
    {
        // Decode the params to pass to the math strategy.
        let params = S::Params::decode(&params_bytes)
            .expect("create_pool: invalid params_bytes — could not decode S::Params");

        let (pool_h, lp_h) = ops::create_pool::<S>(coin_a.handle(), coin_b.handle(), &params)
            .expect("create_pool host failure");
        let _ = pool_h;
        let _ = lp_h;
        // The macro shim returns the on-chain objects via the ret buffer;
        // the Rust struct values here are placeholders for the type system.
        let pool = Pool {
            id: UID::default(),
            reserve_a: 0,
            reserve_b: 0,
            lp_supply: 0,
            k_last: 0,
            params_bytes,
            _phantom_a: PhantomData,
            _phantom_b: PhantomData,
            _phantom_s: PhantomData,
        };
        let lp = LpPosition {
            id: UID::default(),
            pool_id: ObjectId([0u8; 32]),
            shares: 0,
            _phantom_a: PhantomData,
            _phantom_b: PhantomData,
            _phantom_s: PhantomData,
        };
        (pool, lp)
    }

    /// Add liquidity to `pool`. Returns the new `LpPosition` and any
    /// un-consumed coin remainders.
    #[allow(clippy::type_complexity)]
    pub fn add_liquidity<A, B, S: SwapStrategy>(
        _pool: &mut Pool<A, B, S>,
        coin_a: Coin<A>,
        coin_b: Coin<B>,
    ) -> (LpPosition<A, B, S>, Option<Coin<A>>, Option<Coin<B>>)
    where
        S::Params: ParamCodec,
    {
        // The pool handle is passed by the PTB executor as arg 0 in Mutable
        // mode. On the wasm execution path the macro shim decodes the real
        // handle before calling this function. The `RuntimeHandle::from_raw(0)`
        // is a placeholder that works on the wasm path where handle 0 is the
        // pool arg; host-side tests should call `ops::add_liquidity` directly.
        let pool_handle = bloom_resource::RuntimeHandle::from_raw(0);
        let (lp_h, la, lb) = ops::add_liquidity::<S>(pool_handle, coin_a.handle(), coin_b.handle())
            .expect("add_liquidity host failure");
        let _ = lp_h;
        let lp = LpPosition {
            id: UID::default(),
            pool_id: ObjectId([0u8; 32]),
            shares: 0,
            _phantom_a: PhantomData,
            _phantom_b: PhantomData,
            _phantom_s: PhantomData,
        };
        let leftover_a = la.map(Coin::from_handle);
        let leftover_b = lb.map(Coin::from_handle);
        (lp, leftover_a, leftover_b)
    }

    /// Remove liquidity by consuming `position`. Returns `(Coin<A>, Coin<B>)`
    /// with proportional amounts.
    pub fn remove_liquidity<A, B, S: SwapStrategy>(
        _pool: &mut Pool<A, B, S>,
        _position: LpPosition<A, B, S>,
    ) -> (Coin<A>, Coin<B>)
    where
        S::Params: ParamCodec,
    {
        let pool_handle = bloom_resource::RuntimeHandle::from_raw(0);
        let lp_handle = bloom_resource::RuntimeHandle::from_raw(1);
        let (ca, cb) = ops::remove_liquidity::<S>(pool_handle, lp_handle)
            .expect("remove_liquidity host failure");
        (Coin::from_handle(ca), Coin::from_handle(cb))
    }

    /// Swap exact `coin_in` of `Coin<A>` for at-least `min_out` of `Coin<B>`.
    pub fn swap_exact_in<A, B, S: SwapStrategy>(
        _pool: &mut Pool<A, B, S>,
        coin_in: Coin<A>,
        min_out: u128,
    ) -> Coin<B>
    where
        S::Params: ParamCodec,
    {
        let pool_handle = bloom_resource::RuntimeHandle::from_raw(0);
        let out_h = ops::swap_exact_in::<S>(pool_handle, coin_in.handle(), min_out)
            .expect("swap_exact_in host failure");
        Coin::from_handle(out_h)
    }

    /// Swap exact `coin_in` of `Coin<B>` for at-least `min_out` of `Coin<A>`.
    pub fn swap_exact_in_reverse<A, B, S: SwapStrategy>(
        _pool: &mut Pool<A, B, S>,
        coin_in: Coin<B>,
        min_out: u128,
    ) -> Coin<A>
    where
        S::Params: ParamCodec,
    {
        let pool_handle = bloom_resource::RuntimeHandle::from_raw(0);
        let out_h = ops::swap_exact_in_reverse::<S>(pool_handle, coin_in.handle(), min_out)
            .expect("swap_exact_in_reverse host failure");
        Coin::from_handle(out_h)
    }

    /// Swap at-most `max_in` of `Coin<A>` for exactly `amount_out` of `Coin<B>`.
    ///
    /// Returns `(Coin<B>, Option<Coin<A>>)` where the option is the unconsumed
    /// remainder of `max_in` (if any).
    pub fn swap_exact_out<A, B, S: SwapStrategy>(
        _pool: &mut Pool<A, B, S>,
        max_in: Coin<A>,
        amount_out: u128,
    ) -> (Coin<B>, Option<Coin<A>>)
    where
        S::Params: ParamCodec,
    {
        let pool_handle = bloom_resource::RuntimeHandle::from_raw(0);
        let (cb_h, la) = ops::swap_exact_out::<S>(pool_handle, max_in.handle(), amount_out)
            .expect("swap_exact_out host failure");
        (Coin::from_handle(cb_h), la.map(Coin::from_handle))
    }

    /// Read `(reserve_a, reserve_b)` from a pool (read-only; for off-chain
    /// quoting).
    pub fn reserves<A, B, S: SwapStrategy>(_pool: &Pool<A, B, S>) -> (u128, u128)
    where
        S::Params: ParamCodec,
    {
        let pool_handle = bloom_resource::RuntimeHandle::from_raw(0);
        ops::reserves(pool_handle).expect("reserves host failure")
    }
}
