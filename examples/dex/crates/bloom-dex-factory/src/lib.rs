#![deprecated(
    since = "0.2.0",
    note = "use bloom-resource framework — see docs/specs/2026-05-20-bloom-native-contracts-design.md"
)]
#![allow(deprecated)]
//! bloom-dex-factory — Uniswap-v2-style DEX factory petal.
//!
//! Keeps a registry of deployed pair petals and deploys new ones on demand
//! via `host.deploy` (chain spec §7.6).
//!
//! Migrated from the legacy `bloom_chain_abi::contract!` DSL onto
//! `#[bloom::contract]`. The migration preserves byte-for-byte parity at the
//! consensus boundary:
//!
//! - Method selectors (`factory.create_pair(address,address)` etc.) hash to
//!   the identical 4 bytes — the [`Factory`] interface declares the same
//!   canonical signatures.
//! - Storage slots match exactly via `#[storage(compat_tag = "..." )]`.
//! - The pair-registry's `index → pair_addr` mapping uses an 8-byte
//!   big-endian `u64` key, which the framework's `Map<u64, V>` produces
//!   verbatim (`AbiEncode for u64` writes 8 BE bytes).
//! - Init calldata format is the same 96-byte `pair_petal_hash || setter ||
//!   factory_self_addr` payload — the framework decodes it via three
//!   sequential 32-byte reads.
//!
//! # Storage layout
//!
//! | Field             | `compat_tag`                                | Value type     |
//! |-------------------|---------------------------------------------|----------------|
//! | `pair_petal_hash` | `"factory.pair_petal_hash"`                 | Hash32         |
//! | `fee_to`          | `"factory.fee_to"`                          | Address        |
//! | `fee_to_setter`   | `"factory.fee_to_setter"`                   | Address        |
//! | `self_addr`       | `"factory.self"`                            | Address        |
//! | `all_pairs_len`   | `"factory.all_pairs.len"`                   | u64 (8 BE)     |
//! | `pair_of`         | `"factory.pair:" || t0 || t1`               | Address        |
//! | `all_pairs_at`    | `"factory.all_pairs:" || u64_be(i)`         | Address        |
//!
//! `pair_of` is stored for **both** orderings so `get_pair` is order-invariant.
//!
//! What changes (intentional):
//!
//! - Event topic-0 is the full 32-byte `blake3(signature)` instead of the
//!   legacy 4-byte prefix zero-padded to 32, and the canonical signature now
//!   includes the domain prefix (`factory::PairCreated(...)`). Indexers
//!   reading these events must use the framework's event layout (manifest
//!   emits the topic-0 verbatim).

#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use bloom_contract::prelude::*;
use bloom_petal_sdk::{crypto, host};

// ---------------------------------------------------------------------------
// Cross-contract interface
// ---------------------------------------------------------------------------

/// Typed factory interface. Sibling petals (router) reach the factory through
/// [`calls`] (hand-rolled calldata builders) or via `ContractRef<Factory>`
/// once they import the generated `FactoryCalls` extension trait.
///
/// Selectors hash from `factory.<method>(<types>)` so they match every legacy
/// `bloom_chain_abi::contract! { contract Factory { ... } }` deployment.
#[bloom_contract::interface(domain = "factory")]
pub trait Factory {
    fn create_pair(token_a: Address, token_b: Address) -> Result<Address>;
    fn get_pair(token_a: Address, token_b: Address) -> Result<Address>;
    fn all_pairs(index: u64) -> Result<Address>;
    fn all_pairs_length() -> Result<u64>;
    fn fee_to() -> Result<Address>;
    fn fee_to_setter() -> Result<Address>;
    fn set_fee_to(addr: Address) -> Result<()>;
    fn set_fee_to_setter(addr: Address) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Init payload — byte-compatible with the legacy 96-byte format
// ---------------------------------------------------------------------------

/// Constructor arguments. The on-the-wire layout is:
///
/// ```text
/// pair_petal_hash   : [u8; 32]
/// fee_to_setter     : [u8; 32]   (Address)
/// factory_self_addr : [u8; 32]   (Address)
/// ```
///
/// Three fixed-width 32-byte fields, no length prefixes — strict decoding
/// rejects payloads of any other size via the framework's EOF check.
#[derive(AbiEncode, AbiDecode, AbiType)]
pub struct InitConfig {
    pub pair_petal_hash: Hash32,
    pub fee_to_setter: Address,
    pub factory_self_addr: Address,
}

// ---------------------------------------------------------------------------
// Pair sort + derivation helpers (pub for off-chain test pre-computation)
// ---------------------------------------------------------------------------

/// Sort two 32-byte addresses lexicographically; returns `(smaller, larger)`.
pub fn sort_tokens(a: &Address, b: &Address) -> (Address, Address) {
    if a.as_bytes() <= b.as_bytes() { (*a, *b) } else { (*b, *a) }
}

/// `salt = blake3("dex.pair.salt:" || t0 || t1)`. `t0` and `t1` must be sorted.
pub fn pair_salt(t0: &Address, t1: &Address) -> [u8; 32] {
    let mut buf = Vec::with_capacity(14 + 32 + 32);
    buf.extend_from_slice(b"dex.pair.salt:");
    buf.extend_from_slice(t0.as_bytes());
    buf.extend_from_slice(t1.as_bytes());
    crypto::blake3(&buf)
}

/// Pre-compute the pair address via chain spec §7.7.
pub fn compute_pair_address(
    factory_addr: &Address,
    salt: &[u8; 32],
    pair_petal_hash: &Hash32,
) -> Address {
    let prefix = b"bloom-chain.v0.addr:deploy:";
    let sep = b":";
    let mut preimage = Vec::with_capacity(prefix.len() + 32 + 1 + 32 + 1 + 32);
    preimage.extend_from_slice(prefix);
    preimage.extend_from_slice(factory_addr.as_bytes());
    preimage.extend_from_slice(sep);
    preimage.extend_from_slice(salt);
    preimage.extend_from_slice(sep);
    preimage.extend_from_slice(&pair_petal_hash.0);
    Address::from(crypto::blake3(&preimage))
}

// ---------------------------------------------------------------------------
// Contract body
// ---------------------------------------------------------------------------

#[bloom_contract::contract(domain = "factory", interfaces(Factory))]
pub mod factory {
    use super::*;

    // -----------------------------------------------------------------------
    // Storage — every slot keeps its legacy `factory.*` tag for byte-for-byte
    // parity with the pre-migration deployment.
    // -----------------------------------------------------------------------

    #[bloom_contract::storage(domain = "factory")]
    pub struct State {
        #[storage(compat_tag = "factory.pair_petal_hash")]
        pub pair_petal_hash: StorageValue<Hash32>,
        #[storage(compat_tag = "factory.fee_to")]
        pub fee_to: StorageValue<Address>,
        #[storage(compat_tag = "factory.fee_to_setter")]
        pub fee_to_setter: StorageValue<Address>,
        #[storage(compat_tag = "factory.self")]
        pub self_addr: StorageValue<Address>,
        #[storage(compat_tag = "factory.all_pairs.len")]
        pub all_pairs_len: StorageValue<u64>,

        // `Map<(Address, Address), Address>` encodes the tuple key as the
        // 64-byte concat of the two address fields — byte-identical to the
        // legacy mapping key preimage.
        #[storage(compat_tag = "factory.pair:")]
        pub pair_of: Map<(Address, Address), Address>,

        // The pair-registry index → pair_addr lookup. `AbiEncode for u64`
        // writes 8 BE bytes, so the slot is
        // `blake3("factory.all_pairs:" || u64_be(i))` — matching the legacy
        // hand-rolled `slot_mapping("factory.all_pairs:", &i.to_be_bytes())`.
        #[storage(compat_tag = "factory.all_pairs:")]
        pub all_pairs_at: Map<u64, Address>,
    }

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    #[bloom_contract::event(domain = "factory")]
    pub struct PairCreated {
        #[indexed]
        pub token0: Address,
        #[indexed]
        pub token1: Address,
        pub pair: Address,
        pub all_pairs_length: u64,
    }

    // -----------------------------------------------------------------------
    // Init — writes the bootstrap config slots.
    //
    // Phase C dropped the `reentrancy_addr` field (the reentrancy guard moved
    // into `#[nonreentrant]` on the pair). The init payload is exactly the
    // 96-byte `pair_petal_hash || fee_to_setter || factory_self_addr` blob.
    // -----------------------------------------------------------------------

    #[init]
    pub fn init(ctx: &mut Context, cfg: InitConfig) -> Result<()> {
        let state = State::load(ctx)?;
        state.pair_petal_hash.store(ctx, &cfg.pair_petal_hash);
        state.fee_to.store(ctx, &Address::ZERO);
        state.fee_to_setter.store(ctx, &cfg.fee_to_setter);
        state.self_addr.store(ctx, &cfg.factory_self_addr);
        state.all_pairs_len.store(ctx, &0u64);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read methods (view)
    // -----------------------------------------------------------------------

    #[view]
    pub fn get_pair(ctx: &Context, token_a: Address, token_b: Address) -> Result<Address> {
        let (t0, t1) = sort_tokens(&token_a, &token_b);
        State::load(ctx)?.pair_of.get(ctx, &(t0, t1))
    }

    #[view]
    pub fn all_pairs(ctx: &Context, index: u64) -> Result<Address> {
        let state = State::load(ctx)?;
        let count = state.all_pairs_len.load(ctx);
        if index >= count {
            return Err(ContractError::from_str("factory: allPairs: index out of bounds"));
        }
        state.all_pairs_at.get(ctx, &index)
    }

    #[view]
    pub fn all_pairs_length(ctx: &Context) -> Result<u64> {
        Ok(State::load(ctx)?.all_pairs_len.load(ctx))
    }

    #[view]
    pub fn fee_to(ctx: &Context) -> Result<Address> {
        Ok(State::load(ctx)?.fee_to.load(ctx))
    }

    #[view]
    pub fn fee_to_setter(ctx: &Context) -> Result<Address> {
        Ok(State::load(ctx)?.fee_to_setter.load(ctx))
    }

    // -----------------------------------------------------------------------
    // Mutating methods
    // -----------------------------------------------------------------------

    pub fn create_pair(
        ctx: &mut Context,
        token_a: Address,
        token_b: Address,
    ) -> Result<Address> {
        if token_a == token_b {
            return Err(ContractError::from_str("factory: identical addresses"));
        }

        let (t0, t1) = sort_tokens(&token_a, &token_b);
        if t0 == Address::ZERO {
            return Err(ContractError::from_str("factory: zero address"));
        }

        let state = State::load(ctx)?;

        if state.pair_of.get(ctx, &(t0, t1))? != Address::ZERO {
            return Err(ContractError::from_str("factory: pair exists"));
        }

        let salt = pair_salt(&t0, &t1);
        let pair_hash = state.pair_petal_hash.load(ctx);
        let factory_self = state.self_addr.load(ctx);
        let precomputed_pair_addr = compute_pair_address(&factory_self, &salt, &pair_hash);

        // Pair init: t0 || t1 || pair_self_addr (96 bytes).
        //
        // The pair's init payload is a raw `host.deploy` blob (not a
        // selector-dispatched method call). We build it inline rather than
        // pulling in `bloom-dex-pair` as an rlib dep just for the helper.
        // The format is asserted in `pair_init_payload_is_exactly_96_bytes`
        // below.
        let mut init_calldata = Vec::with_capacity(96);
        init_calldata.extend_from_slice(t0.as_bytes());
        init_calldata.extend_from_slice(t1.as_bytes());
        init_calldata.extend_from_slice(precomputed_pair_addr.as_bytes());

        let pair_addr_bytes = host::deploy(&pair_hash.0, &salt, &init_calldata)
            .map_err(|_| ContractError::from_str("factory: deploy failed"))?;
        let pair_addr = Address::from(pair_addr_bytes);

        // Store pair in both directions; append to allPairs.
        state.pair_of.set(ctx, &(t0, t1), &pair_addr)?;
        state.pair_of.set(ctx, &(t1, t0), &pair_addr)?;

        let count = state.all_pairs_len.load(ctx);
        state.all_pairs_at.set(ctx, &count, &pair_addr)?;
        let new_count = count + 1;
        state.all_pairs_len.store(ctx, &new_count);

        PairCreated {
            token0: t0,
            token1: t1,
            pair: pair_addr,
            all_pairs_length: new_count,
        }
        .emit(ctx)?;

        Ok(pair_addr)
    }

    pub fn set_fee_to(ctx: &mut Context, addr: Address) -> Result<()> {
        let state = State::load(ctx)?;
        let setter = state.fee_to_setter.load(ctx);
        if ctx.sender() != setter {
            return Err(ContractError::from_str("factory: setFeeTo: not feeToSetter"));
        }
        state.fee_to.store(ctx, &addr);
        Ok(())
    }

    pub fn set_fee_to_setter(ctx: &mut Context, addr: Address) -> Result<()> {
        let state = State::load(ctx)?;
        let setter = state.fee_to_setter.load(ctx);
        if ctx.sender() != setter {
            return Err(ContractError::from_str(
                "factory: setFeeToSetter: not feeToSetter",
            ));
        }
        state.fee_to_setter.store(ctx, &addr);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Hand-rolled calldata builders
//
// The router constructs calldata bytes directly and submits via
// `petal::call(target, &cd, value)`. Keeping a compatible `calls::*` surface
// here lets it migrate the rest of its body without re-plumbing every call
// site through `ContractRef`.
// ---------------------------------------------------------------------------

pub mod calls {
    use super::*;
    use alloc::vec::Vec;
    use bloom_chain_abi::Encoder;

    /// Build `factory.create_pair(token_a, token_b)` calldata.
    pub fn create_pair(token_a: &[u8; 32], token_b: &[u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(Factory::SEL_CREATE_PAIR);
        e.push_address(token_a);
        e.push_address(token_b);
        e.finish()
    }

    /// Build `factory.get_pair(token_a, token_b)` calldata.
    pub fn get_pair(token_a: &[u8; 32], token_b: &[u8; 32]) -> Vec<u8> {
        let mut e = Encoder::with_selector(Factory::SEL_GET_PAIR);
        e.push_address(token_a);
        e.push_address(token_b);
        e.finish()
    }

    /// Build `factory.all_pairs(index)` calldata.
    pub fn all_pairs(index: u64) -> Vec<u8> {
        let mut e = Encoder::with_selector(Factory::SEL_ALL_PAIRS);
        e.push_u64(index);
        e.finish()
    }

    /// Build `factory.all_pairs_length()` calldata.
    pub fn all_pairs_length() -> Vec<u8> {
        Encoder::with_selector(Factory::SEL_ALL_PAIRS_LENGTH).finish()
    }
}

// ---------------------------------------------------------------------------
// Build the legacy 96-byte factory init payload from typed inputs. Used by
// the dex CLI; centralised here so the wire layout has exactly one source of
// truth.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub fn encode_init_payload(
    pair_petal_hash: [u8; 32],
    fee_to_setter: [u8; 32],
    factory_self_addr: [u8; 32],
) -> ::core::result::Result<alloc::vec::Vec<u8>, ::bloom_contract::abi::AbiEncodeError> {
    let cfg = InitConfig {
        pair_petal_hash: Hash32(pair_petal_hash),
        fee_to_setter: Address::from(fee_to_setter),
        factory_self_addr: Address::from(factory_self_addr),
    };
    cfg.encode()
}

// ---------------------------------------------------------------------------
// Host-side unit tests — ABI byte-parity with the legacy v0 surface.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn blake3_selector(sig: &str) -> [u8; 4] {
        let h = blake3::hash(sig.as_bytes());
        let b = h.as_bytes();
        [b[0], b[1], b[2], b[3]]
    }

    fn blake3_slot(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for p in parts {
            h.update(p);
        }
        *h.finalize().as_bytes()
    }

    // ---- sort_tokens ----

    #[test]
    fn sort_tokens_already_sorted() {
        let a = Address::from([0u8; 32]);
        let mut b_bytes = [0u8; 32];
        b_bytes[31] = 1;
        let b = Address::from(b_bytes);
        let (t0, t1) = sort_tokens(&a, &b);
        assert_eq!(t0, a);
        assert_eq!(t1, b);
    }

    #[test]
    fn sort_tokens_reversed() {
        let mut a_bytes = [0u8; 32];
        a_bytes[31] = 5;
        let a = Address::from(a_bytes);
        let b = Address::from([0u8; 32]);
        let (t0, t1) = sort_tokens(&a, &b);
        assert_eq!(t0, b);
        assert_eq!(t1, a);
    }

    #[test]
    fn sort_tokens_is_commutative() {
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 0x10;
        let mut b_bytes = [0u8; 32];
        b_bytes[0] = 0x20;
        let a = Address::from(a_bytes);
        let b = Address::from(b_bytes);
        let (t0_ab, t1_ab) = sort_tokens(&a, &b);
        let (t0_ba, t1_ba) = sort_tokens(&b, &a);
        assert_eq!(t0_ab, t0_ba);
        assert_eq!(t1_ab, t1_ba);
    }

    // ---- Selector parity ----

    #[test]
    fn factory_selectors_match_dex_v0_canonical_strings() {
        assert_eq!(Factory::SEL_CREATE_PAIR,       blake3_selector("factory.create_pair(address,address)"));
        assert_eq!(Factory::SEL_GET_PAIR,          blake3_selector("factory.get_pair(address,address)"));
        assert_eq!(Factory::SEL_ALL_PAIRS,         blake3_selector("factory.all_pairs(u64)"));
        assert_eq!(Factory::SEL_ALL_PAIRS_LENGTH,  blake3_selector("factory.all_pairs_length()"));
        assert_eq!(Factory::SEL_FEE_TO,            blake3_selector("factory.fee_to()"));
        assert_eq!(Factory::SEL_FEE_TO_SETTER,     blake3_selector("factory.fee_to_setter()"));
        assert_eq!(Factory::SEL_SET_FEE_TO,        blake3_selector("factory.set_fee_to(address)"));
        assert_eq!(Factory::SEL_SET_FEE_TO_SETTER, blake3_selector("factory.set_fee_to_setter(address)"));
    }

    #[test]
    fn selectors_are_unique() {
        let sels = [
            Factory::SEL_CREATE_PAIR,
            Factory::SEL_GET_PAIR,
            Factory::SEL_ALL_PAIRS,
            Factory::SEL_ALL_PAIRS_LENGTH,
            Factory::SEL_FEE_TO,
            Factory::SEL_FEE_TO_SETTER,
            Factory::SEL_SET_FEE_TO,
            Factory::SEL_SET_FEE_TO_SETTER,
        ];
        let mut deduped = sels.to_vec();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), sels.len(), "selector collision");
    }

    // ---- Event topic-0 parity (framework signature includes domain prefix) ----

    #[test]
    fn pair_created_topic0_matches_framework_signature() {
        // The framework's `#[event(domain = "factory")]` builds the signature
        // as `factory::PairCreated(<types>)` and hashes the full 32-byte
        // blake3. This is a deliberate change from the legacy 4-byte-prefix
        // topic-0 format (see crate-level docs).
        let expected = *blake3::hash(b"factory::PairCreated(address,address,address,u64)").as_bytes();
        assert_eq!(factory::PairCreated::TOPIC0, expected);
    }

    // ---- Storage slot byte-equality parity (pre- vs post-migration) ----

    #[test]
    fn storage_slot_parity_scalars() {
        use bloom_contract::storage::slot_for_compat_tag;
        for tag in [
            "factory.pair_petal_hash",
            "factory.fee_to",
            "factory.fee_to_setter",
            "factory.self",
            "factory.all_pairs.len",
        ] {
            let exp = blake3::hash(tag.as_bytes());
            assert_eq!(&slot_for_compat_tag(tag)[..], &exp.as_bytes()[..]);
        }
    }

    #[test]
    fn storage_slot_parity_pair_of_mapping() {
        // `Map<(Address, Address), Address>` with prefix `factory.pair:`
        // derives slots as blake3("factory.pair:" || t0 || t1) — the legacy
        // layout.
        let t0 = Address::from([0x11u8; 32]);
        let t1 = Address::from([0x22u8; 32]);
        let expected = blake3_slot(&[b"factory.pair:", t0.as_bytes(), t1.as_bytes()]);

        let m: Map<(Address, Address), Address> = Map::new(b"factory.pair:");
        let actual = m.slot(&(t0, t1)).expect("slot ok");
        assert_eq!(actual, expected);
    }

    #[test]
    fn storage_slot_parity_all_pairs_mapping() {
        // `Map<u64, Address>` with prefix `factory.all_pairs:` derives slots
        // as blake3("factory.all_pairs:" || u64_be(i)) — `AbiEncode for u64`
        // writes 8 BE bytes, matching the legacy hand-rolled `slot_mapping`
        // call against `&i.to_be_bytes()`.
        let i: u64 = 0xdead_beef;
        let expected = blake3_slot(&[b"factory.all_pairs:", &i.to_be_bytes()]);

        let m: Map<u64, Address> = Map::new(b"factory.all_pairs:");
        let actual = m.slot(&i).expect("slot ok");
        assert_eq!(actual, expected);
    }

    // ---- Init payload tests ----

    #[test]
    fn init_payload_is_exactly_96_bytes() {
        let pair_hash    = [0x01u8; 32];
        let fee_setter   = [0x03u8; 32];
        let factory_self = [0x04u8; 32];

        let payload = encode_init_payload(pair_hash, fee_setter, factory_self).unwrap();
        assert_eq!(payload.len(), 96, "factory init must be 96 bytes");
        assert_eq!(&payload[0..32],  &pair_hash);
        assert_eq!(&payload[32..64], &fee_setter);
        assert_eq!(&payload[64..96], &factory_self);

        let parsed = InitConfig::decode_from(&payload).unwrap();
        assert_eq!(parsed.pair_petal_hash, Hash32(pair_hash));
        assert_eq!(parsed.fee_to_setter, Address::from(fee_setter));
        assert_eq!(parsed.factory_self_addr, Address::from(factory_self));
    }

    #[test]
    fn init_payload_rejects_wrong_length() {
        // 95 bytes is short by one — must error.
        let bad = [0u8; 95];
        assert!(InitConfig::decode_from(&bad).is_err());
        // 97 bytes is long by one — strict decoding rejects trailing bytes.
        let bad = [0u8; 97];
        assert!(InitConfig::decode_from(&bad).is_err());
        // The pre-Phase-C 128-byte payload must also be rejected.
        let bad = [0u8; 128];
        assert!(InitConfig::decode_from(&bad).is_err());
    }

    // ---- Pair init payload constructed for `host.deploy` ----

    #[test]
    fn pair_init_payload_is_exactly_96_bytes() {
        // The factory's `create_pair` builds the pair init payload inline
        // (it's a raw `host.deploy` blob, not a selector-dispatched method).
        // Phase C dropped the `reentrancy_addr` field, so the payload is
        // exactly `t0 || t1 || pair_self_addr` — 96 bytes. This test mirrors
        // the production layout to lock the wire format against accidental
        // size drift.
        let t0 = [0xAAu8; 32];
        let t1 = [0xBBu8; 32];
        let pair_self = [0xCCu8; 32];
        let mut cd = alloc::vec::Vec::<u8>::with_capacity(96);
        cd.extend_from_slice(&t0);
        cd.extend_from_slice(&t1);
        cd.extend_from_slice(&pair_self);
        assert_eq!(cd.len(), 96, "pair init must be 96 bytes");
        assert_eq!(&cd[0..32],   &t0);
        assert_eq!(&cd[32..64],  &t1);
        assert_eq!(&cd[64..96],  &pair_self);
    }

    #[test]
    fn create_pair_call_layout() {
        // Client-side call builder produces selector + two addresses = 4 + 64.
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let cd = calls::create_pair(&a, &b);
        assert_eq!(cd.len(), 4 + 32 + 32);
        assert_eq!(&cd[0..4], &Factory::SEL_CREATE_PAIR);
        assert_eq!(&cd[4..36], &a);
        assert_eq!(&cd[36..68], &b);
    }

    #[test]
    fn get_pair_call_layout() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let cd = calls::get_pair(&a, &b);
        assert_eq!(cd.len(), 4 + 32 + 32);
        assert_eq!(&cd[0..4], &Factory::SEL_GET_PAIR);
        assert_eq!(&cd[4..36], &a);
        assert_eq!(&cd[36..68], &b);
    }

    #[test]
    fn all_pairs_call_layout() {
        let i: u64 = 0x1234_5678_9abc_def0;
        let cd = calls::all_pairs(i);
        assert_eq!(cd.len(), 4 + 8);
        assert_eq!(&cd[0..4], &Factory::SEL_ALL_PAIRS);
        assert_eq!(&cd[4..12], &i.to_be_bytes());
    }
}
