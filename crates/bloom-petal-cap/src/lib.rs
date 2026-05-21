//! `/bloom/core/cap` — generic capability primitives (spec §5 + §18).
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
#[bloom::petal(path = "/bloom/core/cap", version = "0.1.0")]
pub mod cap {
    use super::*;
    use bloom_objects::{Owner, TypeTag};
    use bloom_resource::{ArgReader, Capability, RetWriter, RuntimeHandle, Signer, UID, host};
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
    #[object(abilities = "key, store", phantom = "T")]
    pub struct Cap<T> {
        /// Globally unique object id. Surfaced into the manifest field
        /// list so the chain-side decoder can identify the row; the
        /// petal body itself doesn't read it (the host owns ID
        /// assignment).
        #[allow(dead_code)]
        id: UID,
        /// Inner-kind discriminant — see the `INNER_KIND_*` constants.
        inner_kind: u8,
        /// Block height at which an `ExpireAt` cap stops honouring.
        /// Ignored when `inner_kind != INNER_KIND_EXPIRE_AT`.
        expires_at_block: u64,
        /// Set by [`revoke`] — once true the cap is permanently inactive.
        revoked: bool,
        /// Runtime borrow-table handle assigned by `host::object_create`.
        /// Populated in [`new`] and threaded through to every subsequent
        /// host call so we never need the `INVALID` sentinel fallback.
        #[allow(dead_code)]
        handle: RuntimeHandle,
        _marker: PhantomData<T>,
    }

    /// Companion capability minted alongside a [`Cap<T>`] that grants
    /// the holder permission to call [`revoke`].
    ///
    /// `RevokeCap<T>` matches its target cap by phantom type, so a
    /// `RevokeCap<Mint>` cannot be used to revoke a `Cap<Burn>`.
    #[capability(phantom = "T")]
    pub struct RevokeCap<T> {
        /// Globally unique object id. As with `Cap::id`, surfaced into
        /// the manifest but unused inside the petal body.
        #[allow(dead_code)]
        id: UID,
        /// Runtime borrow-table handle for this RevokeCap, assigned by
        /// `host::object_create` in [`new`].
        #[allow(dead_code)]
        handle: RuntimeHandle,
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
    /// Returns `(cap, revoke_cap)`. The caller decides what to do with
    /// each — typically `transfer` the cap to a delegate and keep the
    /// revoke cap private.
    pub fn new<T>(_signer: &Signer) -> (Cap<T>, RevokeCap<T>) {
        // Encode an "Open" Cap<T> payload + RevokeCap<T> payload.
        let cap_handle = create_cap::<T>(INNER_KIND_OPEN, 0, false)
            .expect("host: failed to create Cap<T>");
        let rev_handle = create_revoke_cap::<T>().expect("host: failed to create RevokeCap<T>");

        (
            Cap {
                id: UID::from_bytes([0u8; 32]),
                inner_kind: INNER_KIND_OPEN,
                expires_at_block: 0,
                revoked: false,
                // Thread the runtime-allocated handle into the struct so
                // transfer/destroy/push_cap_payload can use it directly
                // without falling back to INVALID.
                handle: cap_handle,
                _marker: PhantomData,
            },
            RevokeCap {
                id: UID::from_bytes([0u8; 32]),
                handle: rev_handle,
                _marker: PhantomData,
            },
        )
    }

    // -----------------------------------------------------------------
    // State mutation
    // -----------------------------------------------------------------

    /// Lock the cap. A locked cap reports `is_active = false` until
    /// it is unlocked.
    pub fn lock<T>(cap: &mut Cap<T>) {
        cap.inner_kind = INNER_KIND_LOCKED;
        cap.expires_at_block = 0;
        push_cap_payload::<T>(cap);
    }

    /// Reset a locked cap back to the `Open` kind. No-op for caps that
    /// are already `Open`. Has no effect on the `revoked` flag — a
    /// revoked cap cannot be resurrected.
    pub fn unlock<T>(cap: &mut Cap<T>) {
        cap.inner_kind = INNER_KIND_OPEN;
        cap.expires_at_block = 0;
        push_cap_payload::<T>(cap);
    }

    /// Convert the cap into an `ExpireAt` cap that stops honouring at
    /// block height `block`. Calling this on a `Locked` cap unlocks it
    /// (the new kind is `ExpireAt`).
    pub fn set_expiry<T>(cap: &mut Cap<T>, block: u64) {
        cap.inner_kind = INNER_KIND_EXPIRE_AT;
        cap.expires_at_block = block;
        push_cap_payload::<T>(cap);
    }

    /// Permanently mark the cap as revoked. The `RevokeCap<T>` proof
    /// authorizes this operation; the runtime cap-check ensures the
    /// caller actually holds a matching revoke cap.
    pub fn revoke<T>(_rc: &Capability<RevokeCap<T>>, cap: &mut Cap<T>) {
        cap.revoked = true;
        push_cap_payload::<T>(cap);
    }

    // -----------------------------------------------------------------
    // Introspection
    // -----------------------------------------------------------------

    /// `true` iff the cap currently honours auth requests at
    /// `current_block`.
    pub fn is_active<T>(cap: &Cap<T>, current_block: u64) -> bool {
        super::is_active_logic(cap.inner_kind, cap.expires_at_block, cap.revoked, current_block)
    }

    // -----------------------------------------------------------------
    // Linear-typed destructors
    // -----------------------------------------------------------------

    /// Transfer ownership of the cap to `to`. The cap is consumed by
    /// the petal-side wrapper; the chain rewrites the owner row in the
    /// object store.
    pub fn transfer<T>(cap: Cap<T>, to: Address) {
        // Use the runtime handle stored in the cap struct — populated by
        // `new` from the `host::object_create` return value.
        let _ = host::object_transfer(cap.handle, &Owner::Address(to));
    }

    /// Permanently delete the cap. The `RevokeCap<T>` is *not* deleted
    /// — issuers who want to fully wipe out a delegation should also
    /// `destroy` the revoke cap.
    pub fn destroy<T>(cap: Cap<T>) {
        let _ = host::object_delete(cap.handle);
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
    #[allow(dead_code)] // exercised on the chain-side; not called from
                       // this petal's hot path yet (the user's `&mut
                       // Cap<T>` already holds the decoded fields).
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

    /// Push the cap's current Rust-side fields into the borrow-table
    /// payload via `object.mutate`. The user-visible wrapper for every
    /// `&mut Cap<T>` mutation routes through here.
    fn push_cap_payload<T>(cap: &Cap<T>) {
        let payload = encode_cap_payload(cap.inner_kind, cap.expires_at_block, cap.revoked);
        let _ = host::object_mutate(cap.handle, &payload);
    }

}

// The `#[bloom::petal]` macro re-emits the module body unchanged
// (with petal-recognized attrs stripped) and appends manifest/shim
// items. The user-facing types are accessed via the inner module
// (`bloom_petal_cap::cap::Cap<T>` etc.) — they cannot be re-exported
// at crate root because the petal macro wraps them in a `pub mod cap
// { ... }` whose contents include private helpers we don't want to
// hoist.
