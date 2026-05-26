//! Per-call type-argument context for generic petal dispatch (spec §5,
//! §11.2 "Generic dispatch").
//!
//! A generic petal fn like `identity<T>(c: Coin<T>) -> Coin<T>` is
//! compiled to **one** `__petal_identity` wasm export — there is no
//! per-monomorphization symbol. The concrete type arguments (`T`, ...)
//! arrive at runtime as the leading `Arg::TypeArg(TypeTag)` slots in the
//! calldata. The macro-emitted shim decodes those tags, **binds** them
//! into this thread-local context for the duration of the user-fn call,
//! and the phantom-typed wrappers (`Coin<T>`, `Capability<T>`) resolve
//! their concrete `TypeTag` from here by generic-parameter position
//! instead of from a compile-time const.
//!
//! ## Why a thread-local
//!
//! The wasm chain VM runs one petal call at a time on a single guest
//! thread; there is no concurrency inside a petal. A thread-local keeps
//! the wrapper API (`Coin::<T>::type_tag(idx)`) free of an explicit
//! context parameter while still being correctly scoped per call.
//!
//! ## Lifecycle
//!
//! ```ignore
//! let _guard = TypeArgs::bind(decoded_tags); // shim sets the context
//! let out = user_fn(coin);                    // body resolves tags
//! // `_guard` drops here (even on panic) → previous context restored
//! ```
//!
//! [`TypeArgsGuard`] is a strict RAII guard: it stacks the previous
//! binding on construction and restores it on `Drop`, so the context is
//! always cleared even if the user body panics (host shim catches the
//! unwind). Nested binds (a petal calling another generic helper that
//! also binds) restore correctly LIFO.

use bloom_objects::TypeTag;

#[cfg(not(target_arch = "wasm32"))]
use std::cell::RefCell;

#[cfg(target_arch = "wasm32")]
use core::cell::RefCell;

/// Compile-time-only stand-in type the macro-emitted `__petal_<fn>`
/// shim substitutes for every generic parameter when it invokes a
/// generic user fn (spec §5 generic dispatch).
///
/// At runtime all `Coin<T>` / `Capability<T>` values are uniform object
/// handles — the concrete `T` lives only in the object's `type_tag`,
/// which the petal resolves through [`current_type_arg`]. The shim is
/// itself a non-generic wasm export, so it cannot name the user's `T`;
/// it monomorphizes the user fn over `Erased` instead. `Erased` carries
/// no data and is never constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erased {}

thread_local! {
    /// The type-args bound for the *currently executing* petal call,
    /// in positional (generic-parameter-index) order. Empty when no
    /// generic call is in flight.
    static CURRENT_TYPE_ARGS: RefCell<Vec<TypeTag>> = const { RefCell::new(Vec::new()) };
}

/// Resolve the concrete [`TypeTag`] bound to generic-parameter index
/// `idx` for the currently executing petal call.
///
/// Returns `None` when no call is in flight or when `idx` is out of
/// range for the bound vector (e.g. the calldata carried fewer
/// `Arg::TypeArg` slots than the fn declares).
pub fn current_type_arg(idx: u16) -> Option<TypeTag> {
    CURRENT_TYPE_ARGS.with(|c| c.borrow().get(idx as usize).cloned())
}

/// Number of type-args bound for the current call (0 outside a generic
/// dispatch).
pub fn current_type_arg_count() -> usize {
    CURRENT_TYPE_ARGS.with(|c| c.borrow().len())
}

/// Per-call binding handle for the type-argument context.
///
/// Construct one with [`TypeArgs::bind`] at the top of a generic petal
/// shim; hold it for the duration of the user-fn call. Dropping it
/// restores whatever context was active before (LIFO), so nested
/// generic dispatch and panics both leave the context consistent.
pub struct TypeArgs;

impl TypeArgs {
    /// Bind `tags` as the current call's type-args and return an RAII
    /// guard. The previous binding is stashed in the guard and restored
    /// on `Drop`.
    #[must_use = "the type-args binding is cleared as soon as the guard is dropped"]
    pub fn bind(tags: Vec<TypeTag>) -> TypeArgsGuard {
        let previous = CURRENT_TYPE_ARGS.with(|c| {
            let mut slot = c.borrow_mut();
            core::mem::replace(&mut *slot, tags)
        });
        TypeArgsGuard { previous }
    }
}

/// RAII guard returned by [`TypeArgs::bind`]. Restores the prior
/// type-args context when dropped.
pub struct TypeArgsGuard {
    previous: Vec<TypeTag>,
}

impl Drop for TypeArgsGuard {
    fn drop(&mut self) {
        let previous = core::mem::take(&mut self.previous);
        CURRENT_TYPE_ARGS.with(|c| {
            *c.borrow_mut() = previous;
        });
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn concrete(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: Vec::new(),
        }
    }

    #[test]
    fn no_binding_resolves_to_none() {
        assert_eq!(current_type_arg(0), None);
        assert_eq!(current_type_arg_count(), 0);
    }

    #[test]
    fn bind_exposes_tags_by_index() {
        let _g = TypeArgs::bind(vec![concrete("USDC"), concrete("LOOM")]);
        assert_eq!(current_type_arg_count(), 2);
        assert_eq!(current_type_arg(0), Some(concrete("USDC")));
        assert_eq!(current_type_arg(1), Some(concrete("LOOM")));
        assert_eq!(current_type_arg(2), None, "out-of-range index is None");
    }

    #[test]
    fn guard_clears_context_on_drop() {
        {
            let _g = TypeArgs::bind(vec![concrete("USDC")]);
            assert_eq!(current_type_arg(0), Some(concrete("USDC")));
        }
        // Guard dropped — context is empty again.
        assert_eq!(current_type_arg(0), None);
        assert_eq!(current_type_arg_count(), 0);
    }

    #[test]
    fn nested_binds_restore_lifo() {
        let _outer = TypeArgs::bind(vec![concrete("A")]);
        assert_eq!(current_type_arg(0), Some(concrete("A")));
        {
            let _inner = TypeArgs::bind(vec![concrete("B"), concrete("C")]);
            assert_eq!(current_type_arg(0), Some(concrete("B")));
            assert_eq!(current_type_arg(1), Some(concrete("C")));
        }
        // Inner dropped: outer binding is back.
        assert_eq!(current_type_arg(0), Some(concrete("A")));
        assert_eq!(current_type_arg(1), None);
    }

    #[test]
    fn context_is_restored_after_panic_unwind() {
        // A panic inside a bound scope must still restore the previous
        // (empty) context once the guard unwinds.
        let result = std::panic::catch_unwind(|| {
            let _g = TypeArgs::bind(vec![concrete("USDC")]);
            panic!("boom");
        });
        assert!(result.is_err());
        assert_eq!(
            current_type_arg(0),
            None,
            "context must be cleared after a panic unwinds the guard"
        );
    }
}
