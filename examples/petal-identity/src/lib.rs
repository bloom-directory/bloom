//! `/bloom/petals/test/identity` — trivial generic identity petal.
//!
//! De-risk fixture for **Phase A** (generic-dispatch monomorphization,
//! spec §5): the smallest possible petal that exercises *runtime
//! type-erased dispatch*. A generic `pub fn` like
//! `identity<T>(c: Coin<T>) -> Coin<T>` compiles to a single non-generic
//! `__petal_identity` wasm export. The concrete `T` is not known at
//! compile time — it arrives at call time as the leading
//! `Arg::TypeArg(TypeTag)` slot of the calldata, which the macro-emitted
//! shim binds into the per-call [`bloom_resource::TypeArgs`] context. The
//! body resolves `T`'s concrete tag at runtime via
//! `Coin::<T>::type_tag(idx)`.
//!
//! The petal carries no AMM/DeFi logic — it only proves the dispatch
//! machinery so the heavier petals (the DEX swap in Phase E) can build on
//! a verified foundation.
//!
//! ## Functions
//!
//! - `identity<T>(c: Coin<T>) -> Coin<T>` — returns the coin handle
//!   unchanged. Proves the generic export runs and threads the linear
//!   handle through without ever naming the concrete `T`.
//! - `echo_tag<T>() -> u128` — resolves `T`'s runtime tag via
//!   `Coin::<T>::type_tag(0)` and returns its encoded byte length. Lets a
//!   caller observe that the runtime type-arg binding reached the body
//!   (a non-zero result means a tag was bound).

#![deny(missing_docs)]
#![cfg_attr(target_arch = "wasm32", no_main)]

use bloom_resource_macros as bloom;

/// Petal body for `/bloom/petals/test/identity`.
///
/// Every `pub fn` inside this module becomes a `__petal_<name>` wasm
/// export. The generic fns emit a *real* export doing runtime
/// type-erased dispatch (spec §5), not a `NotImplemented` stub.
#[bloom::petal(path = "/bloom/petals/test/identity", version = "0.1.0")]
pub mod identity {
    use bloom_resource::Coin;

    /// Return the input coin unchanged.
    ///
    /// The shim monomorphizes this over `bloom_resource::Erased`; the
    /// concrete `T` lives only in the runtime type-tag the caller passed
    /// as the leading `Arg::TypeArg`. Returning `c` simply threads the
    /// (linear) borrow-table handle straight back out.
    pub fn identity<T>(c: Coin<T>) -> Coin<T> {
        c
    }

    /// Resolve `T`'s runtime [`bloom_objects::TypeTag`] (generic-param
    /// index 0) and return its canonical-encoded byte length, or `0` if
    /// no tag was bound for the current call.
    ///
    /// A non-zero result proves the macro shim decoded the leading
    /// `Arg::TypeArg` and bound it into the per-call `TypeArgs` context
    /// that `Coin::<T>::type_tag(0)` reads from.
    pub fn echo_tag<T>() -> u128 {
        match Coin::<T>::type_tag(0) {
            Some(tag) => match tag.encode_canonical() {
                Ok(bytes) => bytes.len() as u128,
                Err(_) => 0,
            },
            None => 0,
        }
    }
}
