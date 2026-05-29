//! `/bloom/petals/core/cap` — generic capability primitives (spec §5 + §18).
//!
//! This petal provides `Cap<T>`, a reusable, transferable, optionally
//! revocable capability object that *any* downstream petal can mint
//! instead of defining its own one-off cap struct. The phantom type `T`
//! gives the capability its identity — `Cap<Mint>` and `Cap<Burn>` are
//! distinct types at compile time even though they share the same wire
//! payload shape.
//!
//! ## Revocation
//!
//! Spec §18 resolved capability revocation in v0 as: *the issuer who
//! cares about revocability holds a `RevokeCap<T>` alongside the
//! `Cap<T>` they minted, and calls [`cap::revoke`] to flip a stored
//! `revoked` flag inside the capability's payload*. There is no
//! global revocation list (deferred to v1).
//!
//! ## Inner kinds
//!
//! - `inner_kind = 0` (Open): the cap is unconditionally active.
//! - `inner_kind = 1` (Locked): the cap is held but currently
//!   non-honouring; the issuer can `unlock` it later.
//! - `inner_kind = 2` (ExpireAt): the cap stops honouring at
//!   block height `expires_at_block`.
//!
//! These kinds compose with the boolean `revoked` flag: a revoked cap
//! is inactive regardless of kind.
//!
//! ## Layout
//!
//! `Cap<T>` payload (10 bytes, canonical):
//! - 1 byte: `inner_kind`
//! - 8 bytes BE: `expires_at_block`
//! - 1 byte: `revoked` (`0`/`1`)
//!
//! See `tests/payload_roundtrip.rs` for the wire-level snapshot.

#![deny(missing_docs)]

use bloom_resource_macros as bloom;

/// `Cap` inner-kind: capability is unconditionally active until revoked.
pub const INNER_KIND_OPEN: u8 = 0;
/// `Cap` inner-kind: capability is currently locked.
pub const INNER_KIND_LOCKED: u8 = 1;
/// `Cap` inner-kind: capability expires at `expires_at_block`.
pub const INNER_KIND_EXPIRE_AT: u8 = 2;

/// Length in bytes of the `Cap<T>` canonical payload.
pub const CAP_PAYLOAD_LEN: usize = 10;

/// 32-byte post-quantum address. Re-exported as a path type so that
/// petal function signatures can use it directly (the macro's type-tag
/// lowering only accepts single-segment path types).
pub type Address = [u8; 32];

/// Pure-logic helper: would a cap with these fields honour an auth
/// request at `current_block`?
///
/// The petal-side `cap::is_active<T>` is a thin wrapper around this so
/// the predicate is testable independently of the `Cap<T>` struct
/// (whose fields are intentionally private to the petal).
pub fn is_active_logic(
    inner_kind: u8,
    expires_at_block: u64,
    revoked: bool,
    current_block: u64,
) -> bool {
    if revoked {
        return false;
    }
    match inner_kind {
        INNER_KIND_OPEN => true,
        INNER_KIND_LOCKED => false,
        INNER_KIND_EXPIRE_AT => current_block < expires_at_block,
        _ => false,
    }
}

/// Petal body — every `pub fn` here becomes a `__petal_<name>` wasm
/// export. The petal-level macro embeds a canonical-encoded
/// `PetalManifestV0` (spec §8) as the `bloom_petal_manifest_v0`
/// custom section.
#[bloom::petal(path = "/bloom/petals/core/cap", version = "0.1.0")]
pub mod cap {
    use super::*;
    use bloom_objects::{Owner, TypeTag};
    use bloom_resource::{
        ArgReader, Capability, Resource, RetWriter, RuntimeHandle, Signer, UID, host,
    };
    // Re-export the attribute-style proc-macros under unqualified names
    // so the petal macro's `attr.path().is_ident("object")` matcher
    // recognizes them. (It currently only matches single-segment paths;
    // `#[bloom::object]` is silently ignored.)
    #[allow(unused_imports)]
    use bloom_resource_macros::{capability, object};
    use core::marker::PhantomData;

    /// Reusable, transferable, optionally revocable capability.
    ///
    /// `T` is a phantom marker that distinguishes capabilities at the
    /// type level (`Cap<Mint>` vs `Cap<Burn>`). The on-chain payload is
    /// identical across `T` instantiations; the runtime
    /// `TypeTag::Concrete { type_args: [T_tag], ... }` keeps them
    /// distinct in the object store.
    //
    // In the handle/tag model (spec §11.2) the cap is operated on as an
    // opaque on-chain object: petal entry points take `Resource<Cap<T>>`
    // handles and read/rewrite the payload via `host::object_read` /
    // `host::object_mutate` (see `read_cap_fields` / `write_cap_fields`).
    // The struct below exists only to declare the object's identity,
    // abilities, and payload field layout in the petal manifest — its
    // fields are never constructed or read directly in Rust.
    #[object(abilities = "key, store", phantom = "T")]
    #[allow(dead_code)]
    pub struct Cap<T> {
        /// Globally unique object id. Surfaced into the manifest field
        /// list so the chain-side decoder can identify the row; the
        /// petal body itself doesn't read it (the host owns ID
        /// assignment).
        id: UID,
        /// Inner-kind discriminant — see the `INNER_KIND_*` constants.
        inner_kind: u8,
        /// Block height at which an `ExpireAt` cap stops honouring.
        /// Ignored when `inner_kind != INNER_KIND_EXPIRE_AT`.
        expires_at_block: u64,
        /// Set by [`revoke`] — once true the cap is permanently inactive.
        revoked: bool,
        _marker: PhantomData<T>,
    }

    /// Companion capability minted alongside a [`Cap<T>`] that grants
    /// the holder permission to call [`revoke`].
    ///
    /// `RevokeCap<T>` matches its target cap by phantom type, so a
    /// `RevokeCap<Mint>` cannot be used to revoke a `Cap<Burn>`.
    #[capability(phantom = "T")]
    #[allow(dead_code)]
    pub struct RevokeCap<T> {
        /// Globally unique object id. As with `Cap::id`, surfaced into
        /// the manifest but unused inside the petal body.
        id: UID,
        _marker: PhantomData<T>,
    }

    // -----------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------

    /// Mint a fresh `Cap<T>` together with the matching `RevokeCap<T>`.
    ///
    /// The signer arg threads through to the chain-side ownership
    /// model (the new objects are created on behalf of the signer);
    /// nothing inside the petal needs to inspect it.
    ///
    /// Returns `(cap, revoke_cap)` as object handles. The macro encodes
    /// each as an `ObjectId` in the return envelope for cross-command
    /// threading (spec §11.2). The caller decides what to do with each —
    /// typically `transfer` the cap to a delegate and keep the revoke cap
    /// private.
    pub fn new<T>(_signer: &Signer) -> (Resource<Cap<T>>, Resource<RevokeCap<T>>) {
        // Create the "Open" Cap<T> object + its RevokeCap<T> in the
        // borrow table; the returned handles carry the real object ids.
        let cap_handle =
            create_cap::<T>(INNER_KIND_OPEN, 0, false).expect("host: failed to create Cap<T>");
        let rev_handle = create_revoke_cap::<T>().expect("host: failed to create RevokeCap<T>");

        (
            Resource::from_handle(cap_handle),
            Resource::from_handle(rev_handle),
        )
    }

    // -----------------------------------------------------------------
    // State mutation
    // -----------------------------------------------------------------

    /// Lock the cap. A locked cap reports `is_active = false` until
    /// it is unlocked. Preserves the `revoked` flag.
    pub fn lock<T>(cap: &mut Resource<Cap<T>>) {
        let (_kind, _exp, revoked) = read_cap_fields(cap.handle());
        write_cap_fields(cap.handle(), INNER_KIND_LOCKED, 0, revoked);
    }

    /// Reset a locked cap back to the `Open` kind. No-op for caps that
    /// are already `Open`. Has no effect on the `revoked` flag — a
    /// revoked cap cannot be resurrected.
    pub fn unlock<T>(cap: &mut Resource<Cap<T>>) {
        let (_kind, _exp, revoked) = read_cap_fields(cap.handle());
        write_cap_fields(cap.handle(), INNER_KIND_OPEN, 0, revoked);
    }

    /// Convert the cap into an `ExpireAt` cap that stops honouring at
    /// block height `block`. Calling this on a `Locked` cap unlocks it
    /// (the new kind is `ExpireAt`). Preserves the `revoked` flag.
    pub fn set_expiry<T>(cap: &mut Resource<Cap<T>>, block: u64) {
        let (_kind, _exp, revoked) = read_cap_fields(cap.handle());
        write_cap_fields(cap.handle(), INNER_KIND_EXPIRE_AT, block, revoked);
    }

    /// Permanently mark the cap as revoked. The `RevokeCap<T>` proof
    /// authorizes this operation; the runtime cap-check ensures the
    /// caller actually holds a matching revoke cap. Preserves the
    /// current inner-kind and expiry.
    pub fn revoke<T>(_rc: &Capability<RevokeCap<T>>, cap: &mut Resource<Cap<T>>) {
        let (kind, exp, _revoked) = read_cap_fields(cap.handle());
        write_cap_fields(cap.handle(), kind, exp, true);
    }

    // -----------------------------------------------------------------
    // Introspection
    // -----------------------------------------------------------------

    /// `true` iff the cap currently honours auth requests at
    /// `current_block`. Reads the cap's stored payload.
    pub fn is_active<T>(cap: &Resource<Cap<T>>, current_block: u64) -> bool {
        let (kind, exp, revoked) = read_cap_fields(cap.handle());
        super::is_active_logic(kind, exp, revoked, current_block)
    }

    // -----------------------------------------------------------------
    // Linear-typed destructors
    // -----------------------------------------------------------------

    /// Transfer ownership of the cap to `to`. The cap handle is consumed;
    /// the chain rewrites the owner row in the object store.
    pub fn transfer<T>(cap: Resource<Cap<T>>, to: Address) {
        let _ = host::object_transfer(cap.handle(), &Owner::Address(to));
    }

    /// Permanently delete the cap. The `RevokeCap<T>` is *not* deleted
    /// — issuers who want to fully wipe out a delegation should also
    /// `destroy` the revoke cap.
    pub fn destroy<T>(cap: Resource<Cap<T>>) {
        let _ = host::object_delete(cap.handle());
    }

    // -----------------------------------------------------------------
    // Helpers (private to the petal body)
    // -----------------------------------------------------------------

    /// Build the `TypeTag` for `Cap<T>` at runtime. Because the chain
    /// VM does not monomorphize at PTB-execution time (spec §11.2),
    /// `T` is represented as a `Generic { idx: 0 }` tag — the chain
    /// substitutes the concrete type arg at borrow time.
    fn cap_type_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: bloom_resource::PRIMITIVE_PETAL_HASH,
            type_name: "Cap".to_string(),
            type_args: vec![TypeTag::Generic { idx: 0 }],
        }
    }

    /// Build the `TypeTag` for `RevokeCap<T>` — symmetric with
    /// [`cap_type_tag`].
    fn revoke_cap_type_tag() -> TypeTag {
        TypeTag::Concrete {
            petal_hash: bloom_resource::PRIMITIVE_PETAL_HASH,
            type_name: "RevokeCap".to_string(),
            type_args: vec![TypeTag::Generic { idx: 0 }],
        }
    }

    /// Encode the canonical `Cap<T>` payload (10 bytes).
    fn encode_cap_payload(inner_kind: u8, expires_at_block: u64, revoked: bool) -> Vec<u8> {
        let mut w = RetWriter::new();
        w.write_u8(inner_kind);
        w.write_u64(expires_at_block);
        w.write_bool(revoked);
        w.finish()
    }

    /// Decode a canonical `Cap<T>` payload. Returns `(inner_kind,
    /// expires_at_block, revoked)`.
    fn decode_cap_payload(buf: &[u8]) -> Option<(u8, u64, bool)> {
        let mut r = ArgReader::new(buf);
        let kind = r.read_u8().ok()?;
        let exp = r.read_u64().ok()?;
        let revoked = r.read_bool().ok()?;
        r.expect_eof().ok()?;
        Some((kind, exp, revoked))
    }

    /// Materialize a fresh `Cap<T>` in the borrow table.
    fn create_cap<T>(
        inner_kind: u8,
        expires_at_block: u64,
        revoked: bool,
    ) -> Result<bloom_resource::RuntimeHandle, bloom_resource::PetalError> {
        let _ = PhantomData::<T>;
        let payload = encode_cap_payload(inner_kind, expires_at_block, revoked);
        host::object_create(&cap_type_tag(), &payload)
    }

    /// Materialize a fresh `RevokeCap<T>` in the borrow table.
    fn create_revoke_cap<T>() -> Result<bloom_resource::RuntimeHandle, bloom_resource::PetalError> {
        let _ = PhantomData::<T>;
        // RevokeCap<T> carries no payload beyond its identity; emit an
        // empty buffer (spec §5.1: caps with no extra state encode as
        // zero-length payload).
        host::object_create(&revoke_cap_type_tag(), &[])
    }

    /// Read and decode the `Cap<T>` payload at `handle` into
    /// `(inner_kind, expires_at_block, revoked)`. In the handle/tag model
    /// every mutation reads the live payload first so concurrent fields
    /// (e.g. `revoked`) are preserved rather than clobbered.
    fn read_cap_fields(handle: RuntimeHandle) -> (u8, u64, bool) {
        let buf = host::object_read(handle).expect("cap: object_read failed");
        decode_cap_payload(&buf).expect("cap: malformed Cap<T> payload")
    }

    /// Re-encode the cap fields and write them back to the borrow-table
    /// payload via `object.mutate`. Every `&mut Resource<Cap<T>>`
    /// mutation routes through here.
    fn write_cap_fields(
        handle: RuntimeHandle,
        inner_kind: u8,
        expires_at_block: u64,
        revoked: bool,
    ) {
        let payload = encode_cap_payload(inner_kind, expires_at_block, revoked);
        let _ = host::object_mutate(handle, &payload);
    }
}

// The `#[bloom::petal]` macro re-emits the module body unchanged
// (with petal-recognized attrs stripped) and appends manifest/shim
// items. The user-facing types are accessed via the inner module
// (`bloom_petal_cap::cap::Cap<T>` etc.) — they cannot be re-exported
// at crate root because the petal macro wraps them in a `pub mod cap
// { ... }` whose contents include private helpers we don't want to
// hoist.
