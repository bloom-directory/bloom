//! Event-topic parity self-test for the `contract!` macro.
//!
//! Mirrors `selector_parity.rs` but for `event ...` declarations. The macro
//! emits one `<EVENT>_TOPIC: [u8; 4]` and `<EVENT>_SIG: &str` per event under
//! `<contract>::abi::events`. The test asserts the topic byte-equals
//! `blake3(sig)[..4]`, and a proptest fuzz fans out across ≥1000 random
//! event-signature strings to confirm the recipe.

use bloom_chain_abi::contract;
use proptest::prelude::*;

contract! {
    contract Demo {
        // No methods needed for topic parity; an empty Handler is still
        // emitted, which is fine.
        event Transfer(#[indexed] from: Address, #[indexed] to: Address, value: U256);
        event Approval(#[indexed] owner: Address, #[indexed] spender: Address, value: U256);
        event Mint(#[indexed] sender: Address, amount0: U256, amount1: U256);
        event Burn(
            #[indexed] sender: Address,
            amount0: U256,
            amount1: U256,
            #[indexed] to: Address,
        );
        event Swap(
            #[indexed] sender: Address,
            a0_in: U256,
            a1_in: U256,
            a0_out: U256,
            a1_out: U256,
            #[indexed] to: Address,
        );
        event Sync(reserve0: u128, reserve1: u128);
        event PairCreated(
            #[indexed] token0: Address,
            #[indexed] token1: Address,
            pair: Address,
            index: u64,
        );
    }
}

// Trait must have at least a Handler impl reference for compilation, but no
// methods are declared so the trait body is empty. We need to instantiate
// the trait to silence the unused-trait warning.
struct DemoStub;
impl demo::Handler for DemoStub {}

#[test]
fn every_emitted_topic_matches_blake3_of_sig() {
    let pairs: &[(&[u8; 4], &str)] = &[
        (
            &demo::abi::events::TRANSFER_TOPIC,
            demo::abi::events::TRANSFER_SIG,
        ),
        (
            &demo::abi::events::APPROVAL_TOPIC,
            demo::abi::events::APPROVAL_SIG,
        ),
        (&demo::abi::events::MINT_TOPIC, demo::abi::events::MINT_SIG),
        (&demo::abi::events::BURN_TOPIC, demo::abi::events::BURN_SIG),
        (&demo::abi::events::SWAP_TOPIC, demo::abi::events::SWAP_SIG),
        (&demo::abi::events::SYNC_TOPIC, demo::abi::events::SYNC_SIG),
        (
            &demo::abi::events::PAIR_CREATED_TOPIC,
            demo::abi::events::PAIR_CREATED_SIG,
        ),
    ];
    for (topic, sig) in pairs {
        let full = blake3::hash(sig.as_bytes());
        assert_eq!(
            &topic[..],
            &full.as_bytes()[..4],
            "topic for `{sig}` doesn't match blake3 prefix",
        );
    }
}

#[test]
fn canonical_event_sigs_are_correct() {
    assert_eq!(
        demo::abi::events::TRANSFER_SIG,
        "Transfer(address,address,u256)"
    );
    assert_eq!(
        demo::abi::events::APPROVAL_SIG,
        "Approval(address,address,u256)"
    );
    assert_eq!(demo::abi::events::MINT_SIG, "Mint(address,u256,u256)");
    assert_eq!(
        demo::abi::events::BURN_SIG,
        "Burn(address,u256,u256,address)"
    );
    assert_eq!(
        demo::abi::events::SWAP_SIG,
        "Swap(address,u256,u256,u256,u256,address)"
    );
    assert_eq!(demo::abi::events::SYNC_SIG, "Sync(u128,u128)");
    assert_eq!(
        demo::abi::events::PAIR_CREATED_SIG,
        "PairCreated(address,address,address,u64)"
    );
}

// ---- proptest fuzz: random event-sig strings hash with the same recipe. ---

fn arb_event_name() -> impl Strategy<Value = String> {
    "[A-Z][a-zA-Z]{0,15}".prop_map(|s| s)
}

fn arb_type() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("address"),
        Just("u256"),
        Just("u128"),
        Just("u64"),
        Just("bool"),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn fuzz_event_topic_recipe_parity(
        name in arb_event_name(),
        types in proptest::collection::vec(arb_type(), 0..6),
    ) {
        let mut sig = String::new();
        sig.push_str(&name);
        sig.push('(');
        for (i, t) in types.iter().enumerate() {
            if i > 0 { sig.push(','); }
            sig.push_str(t);
        }
        sig.push(')');

        let topic_runtime = bloom_chain_abi::event_topic(&sig);
        let topic_helper = bloom_chain_abi::event_signature_topic(
            &name,
            &types.to_vec(),
        );
        let full = blake3::hash(sig.as_bytes());

        prop_assert_eq!(&topic_runtime[..], &full.as_bytes()[..4]);
        prop_assert_eq!(topic_runtime, topic_helper);
    }
}

// silence unused warning for the stub
#[allow(dead_code)]
fn _ensure_stub_compiles() -> DemoStub {
    DemoStub
}
