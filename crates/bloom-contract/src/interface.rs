//! Typed cross-contract interfaces.
//!
//! The `#[bloom::interface(domain = "...")]` proc-macro turns a trait
//! declaration into:
//!
//! - A marker trait carrying the canonical [`ContractInterface::ABI_DOMAIN`].
//! - Per-method 4-byte selector constants (`SEL_<METHOD>`).
//! - A [`METHODS`] descriptor slice consumed by the manifest emitter and the
//!   `interfaces(...)` argument of `#[bloom::contract]`.
//! - An inherent impl on [`ContractRef<TraitMarker>`] with typed call helpers
//!   that encode arguments, forward through `ctx.raw_call`, and decode the
//!   return value.

use crate::types::Address;
use core::marker::PhantomData;

/// Marker trait implemented by every type generated from a
/// `#[bloom::interface]` declaration. Carries the canonical ABI domain (the
/// prefix used inside selector signatures, e.g. `"erc20"`).
pub trait ContractInterface {
    /// Canonical ABI domain (`"erc20"` etc.). Forms the first segment of the
    /// `domain.method(types)` signature hashed for selectors.
    const ABI_DOMAIN: &'static str;

    /// Descriptor row for every trait method, in source order.
    const METHODS: &'static [InterfaceMethod];
}

/// One row in [`ContractInterface::METHODS`]. The manifest emitter renders
/// these directly; the contract-side dispatcher uses them to alias the
/// interface's selectors back into the implementing handlers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceMethod {
    /// Method identifier (e.g. `"balance_of"`).
    pub name: &'static str,
    /// Canonical signature `domain.method(types)`.
    pub signature: &'static str,
    /// First four bytes of `blake3(signature)`.
    pub selector: [u8; 4],
}

/// Typed reference to a deployed contract that implements interface `I`.
///
/// The `#[bloom::interface]` macro emits one inherent impl per trait, so the
/// runtime carrier here only owns the address and the marker type.
#[derive(Clone, Copy)]
pub struct ContractRef<I: ContractInterface> {
    pub address: Address,
    _marker: PhantomData<I>,
}

impl<I: ContractInterface> ContractRef<I> {
    #[inline]
    pub const fn new(address: Address) -> Self {
        Self { address, _marker: PhantomData }
    }

    #[inline]
    pub const fn address(&self) -> &Address {
        &self.address
    }
}
