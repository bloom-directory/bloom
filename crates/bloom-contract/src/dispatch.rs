//! Runtime support for the dispatch tables emitted by `#[bloom::contract]`.
//!
//! Three pieces:
//!
//! - [`SelectorEntry`] — one row in the auto-generated `SELECTORS` table per
//!   `pub fn` handler. The manifest emitter reads it; tooling that introspects
//!   a contract reads it; the generated `__dispatch_call` matches against
//!   `selector` to route into the right handler.
//! - [`Mutability`] — `view` / `mutating` / `payable`. Drives manifest
//!   rendering and the payability check on the hot path.
//! - [`revert_with_bytes`] — escape hatch that lets the dispatcher forward
//!   raw revert bytes (selector + ABI payload from a typed error) to the host
//!   without hand-rolling a `transmute` at each call site.
//!
//! Both `SelectorEntry` and `Mutability` are `const`-friendly so the macro
//! can emit a `pub const SELECTORS: &[SelectorEntry] = &[...]` table.

/// Manifest-rendered mutability classifier for a handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutability {
    /// `#[view]` — handler takes `&Context`, no writes.
    View,
    /// Default — handler takes `&mut Context`, no value attached.
    Mutating,
    /// `#[payable]` — handler accepts non-zero `ctx.value()`.
    Payable,
}

/// One row of the auto-generated selector table.
///
/// The macro emits one entry per `pub fn` handler (excluding `#[internal]`),
/// in source order, so the manifest emitter can iterate the table to render
/// the contract's ABI without re-parsing the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorEntry {
    /// Method identifier (e.g. `"transfer"`).
    pub name: &'static str,
    /// Canonical signature `domain.method(types)` used to derive the
    /// selector. Stored verbatim so the manifest emitter doesn't have to
    /// reconstruct it.
    pub signature: &'static str,
    /// First four bytes of `blake3(signature)`.
    pub selector: [u8; 4],
    /// Mutability classification.
    pub mutability: Mutability,
    /// `true` when the handler was annotated `#[nonreentrant]`. The macro
    /// wires the framework reentrancy lock around such handlers.
    pub nonreentrant: bool,
}

/// Forward a typed-error revert payload to `petal.revert`.
///
/// `#[bloom::contract]` handlers return `Result<T, E: Error>`; on the error
/// branch the dispatcher calls `E::encode_revert(&err)` and hands the bytes
/// to this helper. The chain runtime stores the bytes verbatim and indexers
/// recover the original variant by matching the leading 4 bytes against the
/// contract's manifest.
///
/// Diverges — the underlying host import `petal.revert` does not return.
#[inline]
pub fn revert_with_bytes(data: &[u8]) -> ! {
    ::bloom_petal_sdk::petal::revert_bytes(data);
}
