//! `Capability<T>` — typed handle wrapper for capability-shaped objects
//! (spec §5).
//!
//! A capability is just an object whose type carries proof-of-authority
//! semantics; presence of `&Capability<T>` in an arg position
//! authorizes the operation the petal defines for it. The runtime
//! check is delegated to `host::cap_check` — this wrapper just gives
//! petals a typed handle.

use core::marker::PhantomData;

use bloom_objects::TypeTag;

use crate::handle::RuntimeHandle;
use crate::host;

/// Typed handle to a borrowed capability object.
pub struct Capability<T> {
    pub(crate) handle: RuntimeHandle,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T> core::fmt::Debug for Capability<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Capability")
            .field("handle", &self.handle)
            .finish()
    }
}

impl<T> Capability<T> {
    /// Wrap a borrow-table handle.
    pub fn from_handle(h: RuntimeHandle) -> Self {
        Self {
            handle: h,
            _phantom: PhantomData,
        }
    }

    /// Underlying borrow-table handle.
    pub fn handle(&self) -> RuntimeHandle {
        self.handle
    }

    /// Verify against the executor that the capability's type tag
    /// matches the expected `tag`. Returns the host-side boolean.
    pub fn check(&self, expected: &TypeTag) -> bool {
        host::cap_check(self.handle, expected)
    }

    /// Resolve the **runtime** `TypeTag` of the inner capability type
    /// `T` for the currently executing generic petal call (spec §5).
    ///
    /// Like [`crate::Coin::type_tag`], `T` is a compile-time phantom; the
    /// petal body supplies `idx` (the position of `T` among the fn's
    /// generic parameters) and the tag is read from the per-call
    /// [`crate::type_args`] context. Returns `None` outside a generic
    /// dispatch or for an out-of-range `idx`.
    pub fn type_tag(idx: u16) -> Option<TypeTag> {
        crate::type_args::current_type_arg(idx)
    }
}

impl<T> Copy for Capability<T> {}
impl<T> Clone for Capability<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for Capability<T> {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl<T> Eq for Capability<T> {}

/// Marker trait that capability types implement so macros and other
/// adapters can recognize them. The `#[capability]` attribute macro
/// in `bloom-resource-macros` blanket-impls this for the annotated
/// struct.
pub trait CapabilityMarker {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostResponse, test_hooks};

    struct MintAuth;

    #[test]
    fn from_handle_and_handle() {
        let cap: Capability<MintAuth> = Capability::from_handle(RuntimeHandle::from_raw(11));
        assert_eq!(cap.handle(), RuntimeHandle::from_raw(11));
    }

    #[test]
    fn copy_clone_eq() {
        let a: Capability<MintAuth> = Capability::from_handle(RuntimeHandle::from_raw(2));
        let b = a;
        #[allow(clippy::clone_on_copy)]
        let c = a.clone();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn check_routes_through_host_cap_check() {
        test_hooks::clear();
        test_hooks::set_responder(|_| HostResponse::IntReturn(1));
        let cap: Capability<MintAuth> = Capability::from_handle(RuntimeHandle::from_raw(5));
        let tag = TypeTag::Concrete {
            petal_hash: [0; 32],
            type_name: "MintCap".to_string(),
            type_args: vec![],
        };
        assert!(cap.check(&tag));
    }

    #[test]
    fn check_returns_false_on_zero_int_return() {
        test_hooks::clear();
        test_hooks::set_responder(|_| HostResponse::IntReturn(0));
        let cap: Capability<MintAuth> = Capability::from_handle(RuntimeHandle::from_raw(5));
        let tag = TypeTag::Generic { idx: 0 };
        assert!(!cap.check(&tag));
    }
}
