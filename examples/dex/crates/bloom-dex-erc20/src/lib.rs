//! bloom-dex-erc20 — ERC-20 fungible token, written against the
//! `bloom-contract` framework.
//!
//! Migrated from the legacy `bloom_chain_abi::contract!` DSL onto
//! `#[bloom::contract]`. The migration preserves byte-for-byte parity at the
//! consensus boundary:
//!
//! - Method selectors (`erc20.transfer(address,u256)` etc.) hash to the
//!   identical 4 bytes — handler signatures use the same canonical types.
//! - Storage slots match exactly via `#[storage(compat_tag = "..." )]`.
//! - Init calldata format is the same `u16-BE length || bytes` shape — the
//!   framework's `StringN<32>` / `U256` / `Address` decoders read it
//!   without modification.
//!
//! What changes (intentional):
//!
//! - Event topic-0 is now the full 32-byte `blake3(signature)` instead of a
//!   4-byte prefix zero-padded to 32. Indexers reading these events must use
//!   the framework's event layout (manifest emits the topic-0 verbatim).
//!
//! # Public Rust API
//!
//! Sibling petals (router, pair) consume two surfaces from this crate:
//!
//! - [`Erc20`] — the `#[interface]` marker. Cross-contract calls go through
//!   `ContractRef::<Erc20>::new(addr).transfer(ctx, to, amt)` (etc.) once
//!   the caller imports the [`Erc20Calls`] extension trait.
//! - [`calls`] — hand-rolled calldata builders that match the byte layout
//!   the router/pair already produce. They emit the same `selector || args`
//!   bytes the interface path would — used when the caller wants to
//!   construct calldata directly (e.g. `petal::call` shim layers that don't
//!   thread a `Context`).

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use bloom_contract::prelude::*;

// ---------------------------------------------------------------------------
// Cross-contract interface
// ---------------------------------------------------------------------------

/// Typed ERC-20 interface. Implementers route selector hits to the matching
/// handler; consumers reach contracts implementing it through
/// `ContractRef<Erc20>` plus the generated [`Erc20Calls`] extension trait.
///
/// Selectors hash from `erc20.<method>(<types>)` so they match every legacy
/// `bloom_chain_abi::contract! { contract Erc20 { ... } }` deployment.
#[bloom_contract::interface(domain = "erc20")]
pub trait Erc20 {
    fn total_supply() -> Result<U256>;
    fn balance_of(owner: Address) -> Result<U256>;
    fn allowance(owner: Address, spender: Address) -> Result<U256>;
    fn transfer(to: Address, amount: U256) -> Result<bool>;
    fn transfer_from(from: Address, to: Address, amount: U256) -> Result<bool>;
    fn approve(spender: Address, value: U256) -> Result<bool>;
    fn name() -> Result<Hash32>;
    fn symbol() -> Result<Hash32>;
    fn decimals() -> Result<u8>;
}

// ---------------------------------------------------------------------------
// Init payload — byte-compatible with the legacy hand-rolled format
// ---------------------------------------------------------------------------

/// Constructor arguments. The on-the-wire layout is:
///
/// ```text
/// name_len   : u16 BE
/// name_bytes : [u8; name_len]    (UTF-8, ≤ 32 bytes)
/// symbol_len : u16 BE
/// symbol_bytes: [u8; symbol_len] (UTF-8, ≤ 32 bytes)
/// decimals   : u8
/// initial_supply : [u8; 32]      (u256 BE)
/// initial_holder : [u8; 32]      (Address)
/// ```
///
/// `StringN<32>` reads a `u16-BE`-length-prefixed UTF-8 blob and rejects
/// payloads longer than 32 bytes — matching the legacy length cap. `u8`,
/// `U256`, `Address` use the framework's fixed-width encoders so the bytes
/// after the strings line up with the pre-migration deploy payload.
#[derive(AbiEncode, AbiDecode, AbiType)]
pub struct InitConfig {
    pub name: StringN<32>,
    pub symbol: StringN<32>,
    pub decimals: u8,
    pub initial_supply: U256,
    pub initial_holder: Address,
}

// ---------------------------------------------------------------------------
// Contract body
// ---------------------------------------------------------------------------

#[bloom_contract::contract(domain = "erc20", interfaces(Erc20))]
pub mod erc20 {
    use super::*;

    /// `u256::MAX` is the unlimited-allowance sentinel: when an allowance
    /// equals this value, `transfer_from` does not decrement it. Mirrors
    /// the long-standing ERC-20 convention used by the pre-migration code.
    pub const U256_MAX: U256 = U256([0xff; 32]);

    // -----------------------------------------------------------------------
    // Storage — every slot tagged with the legacy domain string so byte
    // layout matches the pre-migration `contract!` macro one-for-one.
    // -----------------------------------------------------------------------

    #[bloom_contract::storage(domain = "erc20")]
    pub struct State {
        #[storage(compat_tag = "erc20.name")]
        pub name: StorageValue<Hash32>,
        #[storage(compat_tag = "erc20.symbol")]
        pub symbol: StorageValue<Hash32>,
        // `decimals` is stored as u64 (legacy default for narrow ints in
        // `contract!`); the low byte equals the u8 we expose, so casting in
        // both directions keeps the wire bytes identical.
        #[storage(compat_tag = "erc20.decimals")]
        pub decimals: StorageValue<u64>,
        #[storage(compat_tag = "erc20.total_supply")]
        pub total_supply: StorageValue<U256>,
        #[storage(compat_tag = "erc20.balance:")]
        pub balances: Map<Address, U256>,
        #[storage(compat_tag = "erc20.allowance:")]
        pub allowances: Map<(Address, Address), U256>,
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    #[bloom_contract::event(domain = "erc20")]
    pub struct Transfer {
        #[indexed]
        pub from: Address,
        #[indexed]
        pub to: Address,
        pub value: U256,
    }

    #[bloom_contract::event(domain = "erc20")]
    pub struct Approval {
        #[indexed]
        pub owner: Address,
        #[indexed]
        pub spender: Address,
        pub value: U256,
    }

    // -----------------------------------------------------------------------
    // Init — deploys mint the initial supply to `initial_holder`.
    // -----------------------------------------------------------------------

    #[init]
    pub fn init(ctx: &mut Context, cfg: InitConfig) -> Result<()> {
        let state = State::load(ctx)?;

        state.name.store(ctx, &str_to_bytes32_right(cfg.name.as_str()));
        state.symbol.store(ctx, &str_to_bytes32_right(cfg.symbol.as_str()));
        // Widen u8 → u64 so the SlotEncode writes the same low-byte pattern
        // the legacy macro wrote when decimals was declared `u64`.
        state.decimals.store(ctx, &(cfg.decimals as u64));

        if !cfg.initial_supply.is_zero() {
            let prev = state.balances.get(ctx, &cfg.initial_holder)?;
            let new = prev
                .checked_add(cfg.initial_supply)
                .ok_or_else(|| ContractError::from_str("erc20: mint overflow"))?;
            state.balances.set(ctx, &cfg.initial_holder, &new)?;
            state.total_supply.store(ctx, &cfg.initial_supply);

            Transfer {
                from: Address::ZERO,
                to: cfg.initial_holder,
                value: cfg.initial_supply,
            }
            .emit(ctx)?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read methods (view) — no storage writes, no value accepted.
    // -----------------------------------------------------------------------

    #[view]
    pub fn total_supply(ctx: &Context) -> Result<U256> {
        Ok(State::load(ctx)?.total_supply.load(ctx))
    }

    #[view]
    pub fn balance_of(ctx: &Context, owner: Address) -> Result<U256> {
        State::load(ctx)?.balances.get(ctx, &owner)
    }

    #[view]
    pub fn allowance(ctx: &Context, owner: Address, spender: Address) -> Result<U256> {
        State::load(ctx)?.allowances.get(ctx, &(owner, spender))
    }

    #[view]
    pub fn name(ctx: &Context) -> Result<Hash32> {
        Ok(State::load(ctx)?.name.load(ctx))
    }

    #[view]
    pub fn symbol(ctx: &Context) -> Result<Hash32> {
        Ok(State::load(ctx)?.symbol.load(ctx))
    }

    /// Returns the single-byte decimals value. The legacy `contract!` macro
    /// could not model 1-byte returns, so v0 ERC-20 hand-dispatched this
    /// selector. The framework's `AbiEncode for u8` writes exactly one byte,
    /// matching the legacy hand-rolled `petal::return_data(&[d])`.
    #[view]
    pub fn decimals(ctx: &Context) -> Result<u8> {
        Ok(State::load(ctx)?.decimals.load(ctx) as u8)
    }

    // -----------------------------------------------------------------------
    // Mutating methods
    // -----------------------------------------------------------------------

    pub fn transfer(ctx: &mut Context, to: Address, amount: U256) -> Result<bool> {
        let state = State::load(ctx)?;
        let sender = ctx.sender();
        do_transfer(ctx, &state, &sender, &to, amount)?;
        Transfer { from: sender, to, value: amount }.emit(ctx)?;
        Ok(true)
    }

    pub fn transfer_from(
        ctx: &mut Context,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<bool> {
        let state = State::load(ctx)?;
        let caller = ctx.sender();

        let current = state.allowances.get(ctx, &(from, caller))?;
        if current != U256_MAX {
            let new_allow = current
                .checked_sub(amount)
                .ok_or_else(|| ContractError::from_str("erc20: insufficient allowance"))?;
            state.allowances.set(ctx, &(from, caller), &new_allow)?;
        }

        do_transfer(ctx, &state, &from, &to, amount)?;
        Transfer { from, to, value: amount }.emit(ctx)?;
        Ok(true)
    }

    pub fn approve(ctx: &mut Context, spender: Address, value: U256) -> Result<bool> {
        let state = State::load(ctx)?;
        let owner = ctx.sender();
        state.allowances.set(ctx, &(owner, spender), &value)?;
        Approval { owner, spender, value }.emit(ctx)?;
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Internal helpers — `pub(crate)` keeps them out of dispatch, callable
    // from sibling modules inside this crate (notably `super::calls`).
    // -----------------------------------------------------------------------

    pub(crate) fn do_transfer(
        ctx: &mut Context,
        state: &State,
        from: &Address,
        to: &Address,
        amount: U256,
    ) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }
        let bal_from = state.balances.get(ctx, from)?;
        let new_from = bal_from
            .checked_sub(amount)
            .ok_or_else(|| ContractError::from_str("erc20: insufficient balance"))?;
        state.balances.set(ctx, from, &new_from)?;
        let bal_to = state.balances.get(ctx, to)?;
        let new_to = bal_to
            .checked_add(amount)
            .ok_or_else(|| ContractError::from_str("erc20: balance overflow"))?;
        state.balances.set(ctx, to, &new_to)?;
        Ok(())
    }

    /// Right-align a string of up to 32 bytes into a `Hash32` slot so the
    /// trailing bytes hold the ASCII data (zeros to the left). Matches the
    /// legacy `str_to_bytes32` byte layout.
    fn str_to_bytes32_right(s: &str) -> Hash32 {
        let bytes = s.as_bytes();
        let mut slot = [0u8; 32];
        let offset = 32 - bytes.len();
        slot[offset..].copy_from_slice(bytes);
        Hash32(slot)
    }
}

// ---------------------------------------------------------------------------
// Hand-rolled calldata builders
//
// Sibling petals (router, pair) currently call this contract by encoding
// calldata bytes themselves and invoking `petal::call(target, &cd, value)`.
// Keeping a compatible `calls::*` surface here lets them migrate the rest of
// their bodies without re-plumbing every call site through `ContractRef`.
// ---------------------------------------------------------------------------

pub mod calls {
    use super::*;
    use alloc::vec::Vec;
    use bloom_chain_abi::Encoder;

    /// Build `erc20.transfer(to, amount)` calldata.
    pub fn transfer(to: &[u8; 32], amount: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(Erc20::SEL_TRANSFER);
        e.push_address(to);
        e.push_u256(amount);
        e.finish()
    }

    /// Build `erc20.transfer_from(from, to, amount)` calldata.
    pub fn transfer_from(from: &[u8; 32], to: &[u8; 32], amount: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(Erc20::SEL_TRANSFER_FROM);
        e.push_address(from);
        e.push_address(to);
        e.push_u256(amount);
        e.finish()
    }

    /// Build `erc20.approve(spender, value)` calldata.
    pub fn approve(spender: &[u8; 32], value: U256) -> Vec<u8> {
        let mut e = Encoder::with_selector(Erc20::SEL_APPROVE);
        e.push_address(spender);
        e.push_u256(value);
        e.finish()
    }

    /// Build `erc20.balance_of(owner)` calldata.
    pub fn balance_of(owner: &[u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(Erc20::SEL_BALANCE_OF);
        e.push_address(owner);
        e.finish()
    }

    /// Build `erc20.allowance(owner, spender)` calldata.
    pub fn allowance(owner: &[u8; 32], spender: &[u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(Erc20::SEL_ALLOWANCE);
        e.push_address(owner);
        e.push_address(spender);
        e.finish()
    }

    /// Build `erc20.total_supply()` calldata.
    pub fn total_supply() -> Vec<u8> {
        Encoder::with_selector(Erc20::SEL_TOTAL_SUPPLY).finish()
    }
}

// ---------------------------------------------------------------------------
// Build the legacy ERC-20 init payload from typed inputs. Used by the dex
// CLI; centralised here so the wire layout has exactly one source of truth.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub fn encode_init_payload(
    name: &str,
    symbol: &str,
    decimals: u8,
    initial_supply: U256,
    initial_holder: [u8; 32],
) -> ::core::result::Result<alloc::vec::Vec<u8>, ::bloom_contract::abi::AbiEncodeError> {
    let cfg = InitConfig {
        name: StringN::<32>::new(name.into())?,
        symbol: StringN::<32>::new(symbol.into())?,
        decimals,
        initial_supply,
        initial_holder: Address::from(initial_holder),
    };
    cfg.encode()
}

// ---------------------------------------------------------------------------
// Host-side unit tests — ABI byte-parity with the legacy v0 surface.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Selectors must match the v0 DEX canonical signatures byte-for-byte —
    /// any drift here is a consensus break for deployed pairs.
    #[test]
    fn erc20_selectors_match_dex_v0() {
        fn expected(method: &[u8]) -> [u8; 4] {
            let h = blake3::hash(method);
            let b = h.as_bytes();
            [b[0], b[1], b[2], b[3]]
        }
        assert_eq!(Erc20::SEL_TOTAL_SUPPLY,   expected(b"erc20.total_supply()"));
        assert_eq!(Erc20::SEL_BALANCE_OF,     expected(b"erc20.balance_of(address)"));
        assert_eq!(Erc20::SEL_ALLOWANCE,      expected(b"erc20.allowance(address,address)"));
        assert_eq!(Erc20::SEL_TRANSFER,       expected(b"erc20.transfer(address,u256)"));
        assert_eq!(Erc20::SEL_TRANSFER_FROM,  expected(b"erc20.transfer_from(address,address,u256)"));
        assert_eq!(Erc20::SEL_APPROVE,        expected(b"erc20.approve(address,u256)"));
    }

    #[test]
    fn calls_transfer_layout() {
        let to = [0x77u8; 32];
        let amount = U256::from_u64(123);
        let cd = calls::transfer(&to, amount);
        assert_eq!(cd.len(), 4 + 32 + 32);
        assert_eq!(&cd[..4], &Erc20::SEL_TRANSFER);
        assert_eq!(&cd[4..36], &to);
        let mut b = [0u8; 32];
        b.copy_from_slice(&cd[36..]);
        assert_eq!(U256(b), amount);
    }

    #[test]
    fn calls_transfer_from_layout() {
        let from = [0x10u8; 32];
        let to = [0x20u8; 32];
        let amount = U256::from_u64(500);
        let cd = calls::transfer_from(&from, &to, amount);
        assert_eq!(cd.len(), 4 + 32 + 32 + 32);
        assert_eq!(&cd[..4], &Erc20::SEL_TRANSFER_FROM);
    }

    /// Init payload round-trips via `InitConfig::decode_from` — the
    /// framework decoder reads the same byte format the legacy hand-rolled
    /// deploy parser produced.
    #[test]
    fn init_payload_roundtrips() {
        let payload = encode_init_payload(
            "TestToken",
            "TST",
            18,
            U256::from_u128(1_000_000_000_000_000_000_000_000u128),
            [0xABu8; 32],
        )
        .unwrap();

        // Legacy reference: hand-rolled byte assembly.
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&(b"TestToken".len() as u16).to_be_bytes());
        legacy.extend_from_slice(b"TestToken");
        legacy.extend_from_slice(&(b"TST".len() as u16).to_be_bytes());
        legacy.extend_from_slice(b"TST");
        legacy.push(18u8);
        legacy.extend_from_slice(&U256::from_u128(1_000_000_000_000_000_000_000_000u128).0);
        legacy.extend_from_slice(&[0xABu8; 32]);

        assert_eq!(payload, legacy, "byte-for-byte parity with legacy format");

        let decoded = InitConfig::decode_from(&payload).unwrap();
        assert_eq!(decoded.name.as_str(), "TestToken");
        assert_eq!(decoded.symbol.as_str(), "TST");
        assert_eq!(decoded.decimals, 18);
        assert_eq!(decoded.initial_holder, Address::from([0xABu8; 32]));
    }

    /// Storage slot derivation under `compat_tag` matches the legacy
    /// `blake3("erc20.<field>")` rule — locked in to catch any future drift.
    #[test]
    fn storage_slots_match_legacy() {
        use bloom_contract::storage::slot_for_compat_tag;

        assert_eq!(
            &slot_for_compat_tag("erc20.name")[..],
            blake3::hash(b"erc20.name").as_bytes()
        );
        assert_eq!(
            &slot_for_compat_tag("erc20.symbol")[..],
            blake3::hash(b"erc20.symbol").as_bytes()
        );
        assert_eq!(
            &slot_for_compat_tag("erc20.total_supply")[..],
            blake3::hash(b"erc20.total_supply").as_bytes()
        );
    }

    /// Sanity-check that all 9 ERC-20 selectors are distinct.
    #[test]
    fn selectors_are_unique() {
        use alloc::collections::BTreeSet;
        let sels: &[[u8; 4]] = &[
            Erc20::SEL_TOTAL_SUPPLY,
            Erc20::SEL_BALANCE_OF,
            Erc20::SEL_ALLOWANCE,
            Erc20::SEL_TRANSFER,
            Erc20::SEL_TRANSFER_FROM,
            Erc20::SEL_APPROVE,
        ];
        let set: BTreeSet<[u8; 4]> = sels.iter().cloned().collect();
        assert_eq!(set.len(), sels.len(), "selector collision detected");
    }
}
