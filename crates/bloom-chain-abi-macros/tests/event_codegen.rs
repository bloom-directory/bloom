//! Event-codegen smoke test: the macro emits compiling `emit_*` functions
//! with the documented signatures.

use bloom_chain_abi::contract;

contract! {
    contract Bar {
        event Transfer(#[indexed] from: Address, #[indexed] to: Address, value: U256);
        event Sync(reserve0: u128, reserve1: u128);
    }
}

struct BarStub;
impl bar::Handler for BarStub {}

#[test]
fn event_emit_fns_have_expected_shapes() {
    // We don't invoke them — `log::emit` panics on host — but referencing
    // their fn-pointer types proves they exist with the correct shape.
    let _: fn(&[u8; 32], &[u8; 32], &bloom_chain_abi::U256) = bar::abi::events::emit_transfer;
    let _: fn(u128, u128) = bar::abi::events::emit_sync;
}

#[test]
fn event_topic_consts_are_emitted() {
    // TRANSFER_TOPIC must be `blake3("Transfer(address,address,u256)")[..4]`.
    let h = blake3::hash(b"Transfer(address,address,u256)");
    assert_eq!(&bar::abi::events::TRANSFER_TOPIC[..], &h.as_bytes()[..4]);

    let h = blake3::hash(b"Sync(u128,u128)");
    assert_eq!(&bar::abi::events::SYNC_TOPIC[..], &h.as_bytes()[..4]);
}

#[allow(dead_code)]
fn _ensure_stub_compiles() -> BarStub {
    BarStub
}
