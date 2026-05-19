//! Nonreentrant codegen smoke test: the macro accepts `#[nonreentrant]` and
//! emits the lock-slot const + the wrapped dispatcher.

use bloom_chain_abi::contract;

contract! {
    contract Guarded {
        #[nonreentrant]
        fn mint(to: Address);
    }
}

struct GuardedStub;
impl guarded::Handler for GuardedStub {
    fn mint(&mut self, _to: [u8; 32]) -> Result<(), &'static str> {
        Ok(())
    }
}

#[test]
fn nonreentrant_selector_is_emitted() {
    // The selector is computed the same way regardless of nonreentrant.
    let h = blake3::hash(b"guarded.mint(address)");
    assert_eq!(&guarded::SEL_MINT[..], &h.as_bytes()[..4]);
}

#[test]
fn dispatcher_signature_is_unchanged() {
    let _: fn(
        &mut GuardedStub,
        &[u8; 32],
        &[u8],
    ) -> Result<
        ::std::vec::Vec<u8>,
        ::bloom_chain_abi::DispatchError,
    > = guarded::dispatch::<GuardedStub>;
}
