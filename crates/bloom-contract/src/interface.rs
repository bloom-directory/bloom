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
use bloom_petal_sdk::value::LoomValue;
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
/// runtime carrier here only owns the address, the optional attached value,
/// and the marker type.
///
/// Use [`Self::with_value`] to attach native LOOM to the next call — that
/// returns a modified `Copy` of the ref, so the original (zero-value) handle
/// stays unchanged for subsequent calls.
#[derive(Clone, Copy)]
pub struct ContractRef<I: ContractInterface> {
    pub address: Address,
    pub value: LoomValue,
    _marker: PhantomData<I>,
}

impl<I: ContractInterface> ContractRef<I> {
    #[inline]
    pub const fn new(address: Address) -> Self {
        Self {
            address,
            value: LoomValue::ZERO,
            _marker: PhantomData,
        }
    }

    #[inline]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Return a `Copy` of this ref with `value` attached to the next call.
    /// Used to reach `#[payable]` interface methods.
    #[inline]
    pub const fn with_value(self, value: LoomValue) -> Self {
        Self {
            address: self.address,
            value,
            _marker: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Compile-time conformance check
// ---------------------------------------------------------------------------

/// Outcome of a conformance check between an interface's `METHODS` and a
/// contract's local `SELECTORS` table.
///
/// Returned from [`check_conformance`] (a `const fn`), so the
/// `#[bloom::contract]` macro can fold the result into a `const _: () = {}`
/// block and fail compilation with a precise reason. The shape is also
/// useful in runtime tests where const evaluation isn't required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConformanceResult {
    /// Every interface method has a matching local handler (same name +
    /// identical argument-type suffix).
    Ok,
    /// An interface method's name is absent from `SELECTORS`.
    MissingMethod {
        /// Method that was expected but not implemented.
        method: &'static str,
    },
    /// A name matched, but the canonical type list (the `(...)` suffix
    /// of the signature) differed between the interface declaration and
    /// the local handler.
    ArgsMismatch {
        method: &'static str,
        /// The interface's canonical signature.
        interface_signature: &'static str,
        /// The local handler's canonical signature.
        local_signature: &'static str,
    },
}

/// Walk `interface_methods` and confirm each entry corresponds to a row
/// in `locals` with the same method name and identical argument types.
///
/// "Identical argument types" means the byte-suffix of the canonical
/// signature starting at the first `(` matches verbatim. The contract's
/// domain may legitimately differ from the interface's — the dispatcher
/// matches the interface selector and then routes by name, so the local
/// handler's `domain.method` prefix is irrelevant. What can never differ
/// is the type list: if it did, the bytes the caller sent under the
/// interface signature wouldn't decode into the local handler's
/// arguments.
///
/// Both [`InterfaceMethod`] and `SelectorEntry` carry `&'static str`
/// fields with a canonical form like `"erc20.balance_of(address)"`, so
/// the comparison is a `const`-eval byte equality.
pub const fn check_conformance(
    interface_methods: &'static [InterfaceMethod],
    locals: &'static [crate::dispatch::SelectorEntry],
) -> ConformanceResult {
    let mut i = 0;
    while i < interface_methods.len() {
        let m = &interface_methods[i];
        let m_args = arg_suffix(m.signature.as_bytes());

        let mut j = 0;
        let mut matched = false;
        while j < locals.len() {
            let local = &locals[j];
            if bytes_eq(m.name.as_bytes(), local.name.as_bytes()) {
                let l_args = arg_suffix(local.signature.as_bytes());
                if !bytes_eq(m_args, l_args) {
                    return ConformanceResult::ArgsMismatch {
                        method: m.name,
                        interface_signature: m.signature,
                        local_signature: local.signature,
                    };
                }
                matched = true;
                break;
            }
            j += 1;
        }
        if !matched {
            return ConformanceResult::MissingMethod { method: m.name };
        }
        i += 1;
    }
    ConformanceResult::Ok
}

/// Const-context equivalent of `panic!` on a non-`Ok` conformance
/// result. The macro calls this so a single line in the generated
/// `const _: () = { ... }` block triggers a compile error with a
/// precise reason.
///
/// The message includes the offending method name as a static string,
/// which is the most useful identifier const-eval can surface — full
/// signature comparison isn't formattable inside a const fn.
pub const fn assert_conforms(
    interface_methods: &'static [InterfaceMethod],
    locals: &'static [crate::dispatch::SelectorEntry],
) {
    match check_conformance(interface_methods, locals) {
        ConformanceResult::Ok => {}
        ConformanceResult::MissingMethod { method: _ } => {
            panic!(
                "interface conformance check failed: contract declares an \
                 interface but does not implement one of its methods (the \
                 method's name is absent from the local SELECTORS table)"
            );
        }
        ConformanceResult::ArgsMismatch { method: _, .. } => {
            panic!(
                "interface conformance check failed: a method name matches a \
                 local handler but the argument types differ between the \
                 interface declaration and the local implementation"
            );
        }
    }
}

const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Return the byte sub-slice starting at the first `(` in `s`, or an
/// empty slice if absent. The argument type list (the `(...)` suffix of
/// the canonical signature) is what conformance compares.
const fn arg_suffix(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'(' {
            let (_, rest) = s.split_at(i);
            return rest;
        }
        i += 1;
    }
    let (_, rest) = s.split_at(s.len());
    rest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{Mutability, SelectorEntry};

    fn local(name: &'static str, sig: &'static str) -> SelectorEntry {
        SelectorEntry {
            name,
            signature: sig,
            selector: [0; 4],
            mutability: Mutability::Mutating,
            nonreentrant: false,
        }
    }

    fn method(name: &'static str, sig: &'static str) -> InterfaceMethod {
        InterfaceMethod {
            name,
            signature: sig,
            selector: [0; 4],
        }
    }

    #[test]
    fn conformance_passes_when_args_match_under_different_domains() {
        // Interface declares `wloom.deposit()`; contract surfaces it
        // under `erc20.deposit()`. Same arg list (`()`) → conforms.
        const IFACE: &[InterfaceMethod] = &[InterfaceMethod {
            name: "deposit",
            signature: "wloom.deposit()",
            selector: [0; 4],
        }];
        let locals = [local("deposit", "erc20.deposit()")];
        let r = check_conformance(IFACE, Box::leak(Box::new(locals)));
        assert_eq!(r, ConformanceResult::Ok);
    }

    #[test]
    fn conformance_passes_when_args_match_exactly() {
        const IFACE: &[InterfaceMethod] = &[InterfaceMethod {
            name: "balance_of",
            signature: "erc20.balance_of(address)",
            selector: [0; 4],
        }];
        let locals = [local("balance_of", "erc20.balance_of(address)")];
        let r = check_conformance(IFACE, Box::leak(Box::new(locals)));
        assert_eq!(r, ConformanceResult::Ok);
    }

    #[test]
    fn conformance_flags_missing_method() {
        const IFACE: &[InterfaceMethod] = &[InterfaceMethod {
            name: "transfer",
            signature: "erc20.transfer(address,u256)",
            selector: [0; 4],
        }];
        let locals = [local("balance_of", "erc20.balance_of(address)")];
        let r = check_conformance(IFACE, Box::leak(Box::new(locals)));
        assert!(
            matches!(r, ConformanceResult::MissingMethod { method: "transfer" }),
            "got {:?}",
            r
        );
    }

    #[test]
    fn conformance_flags_argument_type_mismatch() {
        // Interface says transfer(address, u256); local says
        // transfer(u256, address). Names match, types disagree.
        let _ = method("ignored", "");
        const IFACE: &[InterfaceMethod] = &[InterfaceMethod {
            name: "transfer",
            signature: "erc20.transfer(address,u256)",
            selector: [0; 4],
        }];
        let locals = [local("transfer", "erc20.transfer(u256,address)")];
        let r = check_conformance(IFACE, Box::leak(Box::new(locals)));
        assert!(
            matches!(
                r,
                ConformanceResult::ArgsMismatch {
                    method: "transfer",
                    ..
                }
            ),
            "got {:?}",
            r,
        );
    }

    #[test]
    fn conformance_runs_in_const_context() {
        // The const-evaluatability is the whole point: the macro emits
        // a `const _: () = assert_conforms(...)` block. Exercise the
        // const path here so we catch any future regression that
        // demotes the function out of `const`.
        const IFACE: &[InterfaceMethod] = &[InterfaceMethod {
            name: "deposit",
            signature: "wloom.deposit()",
            selector: [0; 4],
        }];
        const LOCALS: &[SelectorEntry] = &[SelectorEntry {
            name: "deposit",
            signature: "erc20.deposit()",
            selector: [0; 4],
            mutability: Mutability::Mutating,
            nonreentrant: false,
        }];
        const RESULT: ConformanceResult = check_conformance(IFACE, LOCALS);
        assert_eq!(RESULT, ConformanceResult::Ok);
    }
}
