// Generic-dispatch fixture exercising runtime type-erased dispatch
// (spec §5). Each `pub fn` is generic; the macro emits a *real*
// `__petal_<fn>` export (no `NotImplemented` stub) that decodes the
// leading `Arg::TypeArg(TypeTag)` slots from calldata, binds them into
// the per-call `bloom_resource::TypeArgs` context, and dispatches to the
// user body monomorphized over `bloom_resource::Erased`.
//
// - `identity<T>(c: Coin<T>) -> Coin<T>` — returns the coin handle
//   unchanged; proves the generic export runs and threads the linear
//   handle through.
// - `echo_tag<T>() -> u128` — resolves `Coin::<T>::type_tag(0)` from the
//   bound context and returns 1 if it matches a fixed expected tag, 0
//   otherwise; lets the test assert the runtime tag binding directly.
// - `wrap<A, B>(c: Coin<A>) -> Coin<B>` — reads the input coin's balance
//   via the host object API, mints an output coin stamped with the
//   *runtime* tag of `B` (index 1), and returns its handle; proves the
//   output object carries the correct runtime type-tag.

use bloom_resource::Coin;
use bloom_resource_macros as bloom;

#[bloom::petal(path = "/test/generic", version = "0.1.0")]
pub mod generic {
    use super::*;
    use bloom_resource::host;

    pub fn identity<T>(c: Coin<T>) -> Coin<T> {
        c
    }

    pub fn echo_tag<T>() -> u128 {
        // Resolve T's runtime tag (generic param index 0) and compare it
        // to the fixture's expected "USDC" tag.
        let expected = bloom_objects::TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: "USDC".to_string(),
            type_args: Vec::new(),
        };
        match Coin::<T>::type_tag(0) {
            Some(tag) if tag == expected => 1,
            _ => 0,
        }
    }

    pub fn wrap<A, B>(c: Coin<A>) -> Coin<B> {
        // Read the input coin's payload (mocked) to prove the body
        // operates on handles, not concrete Rust types.
        let _payload = host::object_read(c.handle()).unwrap_or_default();
        // Stamp the output coin with the *runtime* tag of B (the second
        // type-arg, generic param index 1).
        let out_tag = Coin::<B>::type_tag(1).expect("B tag must be bound");
        let out_handle = host::object_create(&out_tag, &[]).expect("create output coin");
        Coin::<B>::from_handle(out_handle)
    }
}
