//! Safe wrappers around the chain VM host imports listed in spec
//! §16.2 (and declared as data in `bloom_objects::host_imports`).
//!
//! Every wrapper hides the wasm-ABI pointer/length plumbing behind a
//! `Result<T, PetalError>` whose `Ok` value is already in Rust types
//! (e.g. `Vec<u8>` for `object_read`, `RuntimeHandle` for
//! `object_borrow`, etc.).
//!
//! Compile-time targets:
//! - On `wasm32`: the [`raw`] module declares the actual `extern "C"`
//!   imports under the `"object"` / `"cap"` / `"signer"` / `"ptb"` /
//!   `"log"` modules. Wrappers call those directly. Buffer pointers
//!   for "host writes to me" calls (`object.read`, `signer.address`,
//!   `ptb.command_output`) use guest-side `Vec<u8>` storage; we hand
//!   the host `.as_mut_ptr()` plus capacity, then `set_len` based on
//!   the returned byte count.
//! - On non-wasm targets: a mock implementation routes every call
//!   through a thread-local [`test_hooks`] table so unit tests can
//!   pre-program responses and inspect the recorded call log.
//!
//! ## Safety
//!
//! All `unsafe` blocks here exist solely to call the wasm extern
//! imports and to recover guest-side `Vec<u8>` buffers after the host
//! has written into them. Each block carries an inline `SAFETY:`
//! comment. There is no `unsafe` in the mock path.

use bloom_objects::{AccessMode, ObjectId, Owner, TypeTag};

use crate::error::PetalError;
use crate::handle::RuntimeHandle;

// ===========================================================================
// Wasm extern bindings (chain VM target)
// ===========================================================================

#[cfg(target_arch = "wasm32")]
mod raw {
    //! Raw `extern "C"` host imports.
    //!
    //! Signatures match spec §16.2 exactly. `handle` and length
    //! parameters are `i32`; pointers are `i32` byte offsets into
    //! linear memory (we use Rust `*const u8` / `*mut u8` directly,
    //! which lower to `i32` under the `wasm32` ABI).

    // -------- object.* --------
    #[link(wasm_import_module = "object")]
    unsafe extern "C" {
        #[link_name = "borrow"]
        pub fn object_borrow(id_ptr: *const u8, mode: i32) -> i32;
        #[link_name = "read"]
        pub fn object_read(handle: i32, dst_ptr: *mut u8, dst_cap: i32) -> i32;
        #[link_name = "mutate"]
        pub fn object_mutate(handle: i32, src_ptr: *const u8, src_len: i32) -> i32;
        #[link_name = "create"]
        pub fn object_create(
            type_tag_ptr: *const u8,
            type_tag_len: i32,
            payload_ptr: *const u8,
            payload_len: i32,
        ) -> i32;
        #[link_name = "transfer"]
        pub fn object_transfer(
            handle: i32,
            owner_kind: i32,
            owner_payload_ptr: *const u8,
            owner_payload_len: i32,
        ) -> i32;
        #[link_name = "share"]
        pub fn object_share(handle: i32) -> i32;
        #[link_name = "freeze"]
        pub fn object_freeze(handle: i32) -> i32;
        #[link_name = "delete"]
        pub fn object_delete(handle: i32) -> i32;
        #[link_name = "id"]
        pub fn object_id(handle: i32, out_ptr: *mut u8) -> i32;
    }

    // -------- chain.* (calldata + return/revert ABI bridge) --------
    //
    // These mirror the proven 2-arg `__petal_<fn>(i32, i32) -> i32` VM
    // ABI (chain_vm.rs): the export reads its framed calldata via
    // `msg.calldata.read`, then delivers its framed return envelope by
    // calling `petal.return` (success) or `petal.revert` (abort). Both
    // delivery imports trap to unwind the guest, so they are `-> ()`.
    #[link(wasm_import_module = "chain")]
    unsafe extern "C" {
        #[link_name = "msg.calldata.read"]
        pub fn msg_calldata_read(dst_ptr: *mut u8, offset: i32, len: i32) -> i32;
        #[link_name = "petal.return"]
        pub fn petal_return(ptr: *const u8, len: i32);
        #[link_name = "petal.revert"]
        pub fn petal_revert(ptr: *const u8, len: i32);
    }

    #[link(wasm_import_module = "cap")]
    unsafe extern "C" {
        #[link_name = "check"]
        pub fn cap_check(handle: i32, type_tag_ptr: *const u8, type_tag_len: i32) -> i32;
    }

    #[link(wasm_import_module = "signer")]
    unsafe extern "C" {
        #[link_name = "index"]
        pub fn signer_index() -> i32;
        #[link_name = "address"]
        pub fn signer_address(idx: i32, out_ptr: *mut u8) -> i32;
    }

    #[link(wasm_import_module = "ptb")]
    unsafe extern "C" {
        #[link_name = "command_output"]
        pub fn ptb_command_output(
            cmd_idx: i32,
            ret_idx: i32,
            out_ptr: *mut u8,
            out_cap: i32,
        ) -> i32;
    }

    #[link(wasm_import_module = "log")]
    unsafe extern "C" {
        #[link_name = "emit"]
        pub fn log_emit(
            topic_ptr: *const u8,
            topic_len: i32,
            data_ptr: *const u8,
            data_len: i32,
        ) -> i32;
    }
}

// On wasm32 we re-export the raw symbols under a stable internal alias
// used by the wrappers below.
#[cfg(target_arch = "wasm32")]
use raw as host_extern;

// ===========================================================================
// Recorded-call types (shared by both targets so tests can introspect)
// ===========================================================================

/// Identifier for which host import a recorded call refers to.
///
/// Used by the non-wasm mock to log call sequences for unit tests.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HostCall {
    /// `object.borrow(id, mode)`
    ObjectBorrow {
        /// Canonical-encoded `ObjectId` bytes (32 bytes raw).
        id: ObjectId,
        /// Borrow mode (`ReadOnly` / `Mutable` / `Consume`).
        mode: AccessMode,
    },
    /// `object.read(handle)` — capacity is implicit (mock provides full buffer).
    ObjectRead {
        /// Borrow-table handle.
        handle: RuntimeHandle,
    },
    /// `object.mutate(handle, payload)`
    ObjectMutate {
        /// Borrow-table handle.
        handle: RuntimeHandle,
        /// New canonical-encoded payload bytes.
        payload: Vec<u8>,
    },
    /// `object.create(type_tag, payload)`
    ObjectCreate {
        /// Canonical-encoded `TypeTag` bytes.
        type_tag_bytes: Vec<u8>,
        /// Canonical-encoded payload bytes.
        payload: Vec<u8>,
    },
    /// `object.transfer(handle, owner)`
    ObjectTransfer {
        /// Borrow-table handle.
        handle: RuntimeHandle,
        /// Target owner discriminant (1 byte) + payload (32 or 0 bytes).
        owner_kind: u8,
        /// 32-byte address / object id, or empty for Shared/Immutable.
        owner_payload: Vec<u8>,
    },
    /// `object.share(handle)`
    ObjectShare {
        /// Borrow-table handle.
        handle: RuntimeHandle,
    },
    /// `object.freeze(handle)`
    ObjectFreeze {
        /// Borrow-table handle.
        handle: RuntimeHandle,
    },
    /// `object.delete(handle)`
    ObjectDelete {
        /// Borrow-table handle.
        handle: RuntimeHandle,
    },
    /// `object.id(handle)` — resolve a borrow handle back to the
    /// 32-byte `ObjectId` it points at (used when a Coin/Capability
    /// return must cross a command boundary as an `Object`/`Use` id
    /// rather than the ephemeral borrow handle).
    ObjectId {
        /// Borrow-table handle.
        handle: RuntimeHandle,
    },
    /// `cap.check(handle, type_tag)`
    CapCheck {
        /// Borrow-table handle of the capability object.
        handle: RuntimeHandle,
        /// Canonical-encoded expected `TypeTag` bytes.
        type_tag_bytes: Vec<u8>,
    },
    /// `signer.index()`
    SignerIndex,
    /// `signer.address(idx)`
    SignerAddress {
        /// Zero-based signer index into the PTB's `signers` vector.
        idx: u16,
    },
    /// `ptb.command_output(cmd_idx, ret_idx)`
    PtbCommandOutput {
        /// PTB command index.
        cmd_idx: u16,
        /// Return-value index within that command.
        ret_idx: u16,
    },
    /// `log.emit(topic, data)`
    LogEmit {
        /// Log topic bytes.
        topic: Vec<u8>,
        /// Log data bytes.
        data: Vec<u8>,
    },
}

/// Pre-programmed response a test harness hands back to a wrapper.
///
/// Each variant covers the shape returned by the corresponding host
/// import. The mock dispatcher matches them by name; mismatches abort
/// the test with an explicit message.
#[derive(Debug, Clone)]
pub enum HostResponse {
    /// `i32` return for void-return imports (`mutate`, `transfer`,
    /// `share`, `freeze`, `delete`, `log.emit`). `0` = ok.
    Status(i32),
    /// Handle return for `borrow` and `create`.
    Handle(RuntimeHandle),
    /// Bytes return for `read` and `command_output`.
    Bytes(Vec<u8>),
    /// 32-byte address return for `signer.address`.
    Address([u8; 32]),
    /// `i32` return for `cap.check` and `signer.index`.
    IntReturn(i32),
    /// Wrapper should propagate a `PetalError`.
    Err(PetalError),
}

// ===========================================================================
// Mock host (non-wasm target)
// ===========================================================================

#[cfg(not(target_arch = "wasm32"))]
mod mock {
    use super::{HostCall, HostResponse};
    use crate::error::PetalError;
    use crate::handle::RuntimeHandle;

    thread_local! {
        /// Recorded calls in invocation order.
        pub(super) static CALLS: RefCell<Vec<HostCall>> = const { RefCell::new(Vec::new()) };

        /// Per-test responder. Defaults to a "no responder set" panic
        /// so a forgotten setup is loud rather than silent.
        #[allow(clippy::type_complexity)]
        pub(super) static RESPONDER: RefCell<Box<dyn FnMut(&HostCall) -> HostResponse>> =
            RefCell::new(Box::new(default_responder));
    }

    use std::cell::RefCell;

    fn default_responder(call: &HostCall) -> HostResponse {
        panic!(
            "bloom_resource::host mock invoked without a responder; call was: {:?}\n\
             Hint: use `test_hooks::set_responder(...)` before the test action.",
            call
        );
    }

    pub fn dispatch(call: HostCall) -> HostResponse {
        CALLS.with(|c| c.borrow_mut().push(call.clone()));
        RESPONDER.with(|r| {
            let mut guard = r.borrow_mut();
            guard(&call)
        })
    }

    pub fn clear() {
        CALLS.with(|c| c.borrow_mut().clear());
        RESPONDER.with(|r| {
            *r.borrow_mut() = Box::new(default_responder);
        });
    }

    pub fn set_responder<F>(f: F)
    where
        F: FnMut(&HostCall) -> HostResponse + 'static,
    {
        RESPONDER.with(|r| {
            *r.borrow_mut() = Box::new(f);
        });
    }

    pub fn recorded_calls() -> Vec<HostCall> {
        CALLS.with(|c| c.borrow().clone())
    }

    pub fn last_call() -> Option<HostCall> {
        CALLS.with(|c| c.borrow().last().cloned())
    }

    /// Convenience: every status-shaped call returns `0` ok.
    pub fn ok_responder() -> impl FnMut(&HostCall) -> HostResponse {
        |call: &HostCall| match call {
            HostCall::ObjectBorrow { .. } | HostCall::ObjectCreate { .. } => {
                HostResponse::Handle(RuntimeHandle::from_raw(0))
            }
            HostCall::ObjectRead { .. } | HostCall::PtbCommandOutput { .. } => {
                HostResponse::Bytes(Vec::new())
            }
            HostCall::SignerAddress { .. } | HostCall::ObjectId { .. } => {
                HostResponse::Address([0u8; 32])
            }
            HostCall::SignerIndex | HostCall::CapCheck { .. } => HostResponse::IntReturn(0),
            _ => HostResponse::Status(PetalError::Ok.as_i32()),
        }
    }
}

/// Test-only hooks exposed for host-side unit tests. The same surface
/// is available regardless of target so doctests / examples compile
/// uniformly, but on `wasm32` every call is a no-op (the real host is
/// authoritative).
pub mod test_hooks {
    use super::{HostCall, HostResponse};

    /// Replace the per-thread mock responder.
    ///
    /// Each invocation of any wrapper in this module looks up the
    /// responder and calls it with the materialized `HostCall`; the
    /// returned `HostResponse` is what the wrapper sees.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_responder<F>(f: F)
    where
        F: FnMut(&HostCall) -> HostResponse + 'static,
    {
        super::mock::set_responder(f);
    }

    /// No-op on wasm32 — the real chain VM is authoritative.
    #[cfg(target_arch = "wasm32")]
    pub fn set_responder<F>(_f: F)
    where
        F: FnMut(&HostCall) -> HostResponse + 'static,
    {
    }

    /// Snapshot the recorded call log.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn recorded_calls() -> Vec<HostCall> {
        super::mock::recorded_calls()
    }

    /// No-op on wasm32.
    #[cfg(target_arch = "wasm32")]
    pub fn recorded_calls() -> Vec<HostCall> {
        Vec::new()
    }

    /// Convenience: just the most recent call.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn last_call() -> Option<HostCall> {
        super::mock::last_call()
    }

    /// No-op on wasm32.
    #[cfg(target_arch = "wasm32")]
    pub fn last_call() -> Option<HostCall> {
        None
    }

    /// Reset the call log and responder back to defaults.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn clear() {
        super::mock::clear();
    }

    /// No-op on wasm32.
    #[cfg(target_arch = "wasm32")]
    pub fn clear() {}

    /// Convenience responder that returns generic "ok" shapes for every
    /// call.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn ok_responder() -> impl FnMut(&HostCall) -> HostResponse {
        super::mock::ok_responder()
    }
}

// ===========================================================================
// Helper: interpret a numeric `i32` return as Result<i32, PetalError>.
// ===========================================================================

#[inline]
fn status_to_result(code: i32) -> Result<(), PetalError> {
    if code == 0 {
        Ok(())
    } else if code < 0 {
        Err(PetalError::HostImportFailed)
    } else {
        // The host returned a positive code that maps to a typed error.
        Err(PetalError::from_i32(code))
    }
}

#[inline]
fn handle_to_result(code: i32) -> Result<RuntimeHandle, PetalError> {
    if code < 0 {
        Err(PetalError::HostImportFailed)
    } else {
        Ok(RuntimeHandle::from_raw(code))
    }
}

// ===========================================================================
// Wrappers
// ===========================================================================

/// Borrow an existing object out of the executor's borrow table.
pub fn object_borrow(id: &ObjectId, mode: AccessMode) -> Result<RuntimeHandle, PetalError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::ObjectBorrow { id: *id, mode };
        match mock::dispatch(call) {
            HostResponse::Handle(h) => Ok(h),
            HostResponse::Err(e) => Err(e),
            HostResponse::IntReturn(code) => handle_to_result(code),
            other => panic!("object_borrow expected Handle response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: `id.0` is a 32-byte stack-allocated array; the host
        // only reads it (spec §16.2 contract). We never let the host
        // hold the pointer past this call.
        let code = unsafe { host_extern::object_borrow(id.0.as_ptr(), mode.as_byte() as i32) };
        handle_to_result(code)
    }
}

/// Read the current payload bytes of a borrowed object.
///
/// Performs at most one grow-and-retry: the wrapper passes a small
/// buffer first, and if the host returns a negative "buffer too small"
/// status, retries with the requested capacity.
pub fn object_read(handle: RuntimeHandle) -> Result<Vec<u8>, PetalError> {
    if !handle.is_valid() {
        return Err(PetalError::InvalidHandle);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::ObjectRead { handle };
        match mock::dispatch(call) {
            HostResponse::Bytes(b) => Ok(b),
            HostResponse::Err(e) => Err(e),
            other => panic!("object_read expected Bytes response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        // Strategy: try with a 1 KiB buffer first; if the host returns
        // a negative len indicating "buffer too small", the absolute
        // value is the required capacity (spec §16.2 informal). Grow
        // and retry exactly once.
        const INITIAL_CAP: usize = 1024;
        let mut buf: Vec<u8> = Vec::with_capacity(INITIAL_CAP);
        // SAFETY: `buf.as_mut_ptr()` is unique (we just allocated);
        // the host writes at most `INITIAL_CAP` bytes. If the return
        // is `>= 0`, that's the new length; we use it with set_len.
        let written = unsafe {
            host_extern::object_read(handle.as_raw(), buf.as_mut_ptr(), INITIAL_CAP as i32)
        };
        if written >= 0 {
            // SAFETY: host promises to have written `written` valid
            // bytes into the buffer we owned.
            unsafe { buf.set_len(written as usize) };
            return Ok(buf);
        }
        // Negative = required capacity.
        let needed = (-written) as usize;
        let mut buf2: Vec<u8> = Vec::with_capacity(needed);
        // SAFETY: same invariant as above; we now own `needed` capacity.
        let written2 =
            unsafe { host_extern::object_read(handle.as_raw(), buf2.as_mut_ptr(), needed as i32) };
        if written2 < 0 {
            return Err(PetalError::HostImportFailed);
        }
        // SAFETY: host wrote `written2` bytes.
        unsafe { buf2.set_len(written2 as usize) };
        Ok(buf2)
    }
}

/// Replace the payload bytes of a borrowed object (requires `Mutable`).
pub fn object_mutate(handle: RuntimeHandle, new_payload: &[u8]) -> Result<(), PetalError> {
    if !handle.is_valid() {
        return Err(PetalError::InvalidHandle);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::ObjectMutate {
            handle,
            payload: new_payload.to_vec(),
        };
        match mock::dispatch(call) {
            HostResponse::Status(code) => status_to_result(code),
            HostResponse::Err(e) => Err(e),
            other => panic!("object_mutate expected Status response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let len = i32::try_from(new_payload.len()).map_err(|_| PetalError::InvalidArgs)?;
        // SAFETY: `new_payload` is a borrowed slice; we pass its ptr+len
        // to the host which is only allowed to read.
        let code =
            unsafe { host_extern::object_mutate(handle.as_raw(), new_payload.as_ptr(), len) };
        status_to_result(code)
    }
}

/// Create a new object of the given type with the given payload.
pub fn object_create(type_tag: &TypeTag, payload: &[u8]) -> Result<RuntimeHandle, PetalError> {
    let type_tag_bytes = type_tag
        .encode_canonical()
        .map_err(|_| PetalError::InvalidArgs)?;

    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::ObjectCreate {
            type_tag_bytes,
            payload: payload.to_vec(),
        };
        match mock::dispatch(call) {
            HostResponse::Handle(h) => Ok(h),
            HostResponse::Err(e) => Err(e),
            HostResponse::IntReturn(code) => handle_to_result(code),
            other => panic!("object_create expected Handle response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let tlen = i32::try_from(type_tag_bytes.len()).map_err(|_| PetalError::InvalidArgs)?;
        let plen = i32::try_from(payload.len()).map_err(|_| PetalError::InvalidArgs)?;
        // SAFETY: both buffers are borrowed for the duration of the
        // call; the host is only allowed to read.
        let code = unsafe {
            host_extern::object_create(type_tag_bytes.as_ptr(), tlen, payload.as_ptr(), plen)
        };
        handle_to_result(code)
    }
}

/// Transfer ownership of a borrowed object to a new owner.
pub fn object_transfer(handle: RuntimeHandle, owner: &Owner) -> Result<(), PetalError> {
    if !handle.is_valid() {
        return Err(PetalError::InvalidHandle);
    }
    let owner_kind = owner.kind_byte();
    let owner_payload = owner.payload_bytes();

    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::ObjectTransfer {
            handle,
            owner_kind,
            owner_payload,
        };
        match mock::dispatch(call) {
            HostResponse::Status(code) => status_to_result(code),
            HostResponse::Err(e) => Err(e),
            other => panic!("object_transfer expected Status response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let plen = i32::try_from(owner_payload.len()).map_err(|_| PetalError::InvalidArgs)?;
        // SAFETY: we own `owner_payload` for the duration of the call;
        // `as_ptr()` may be null if the vec is empty, in which case
        // `plen` is `0` and the host MUST NOT dereference it (per
        // spec §16.2: Shared/Immutable kinds carry no payload).
        let code = unsafe {
            host_extern::object_transfer(
                handle.as_raw(),
                owner_kind as i32,
                owner_payload.as_ptr(),
                plen,
            )
        };
        status_to_result(code)
    }
}

/// Shorthand for `transfer(handle, Owner::Shared)`.
pub fn object_share(handle: RuntimeHandle) -> Result<(), PetalError> {
    if !handle.is_valid() {
        return Err(PetalError::InvalidHandle);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        match mock::dispatch(HostCall::ObjectShare { handle }) {
            HostResponse::Status(code) => status_to_result(code),
            HostResponse::Err(e) => Err(e),
            other => panic!("object_share expected Status response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: no buffers; pure i32 -> i32 call.
        let code = unsafe { host_extern::object_share(handle.as_raw()) };
        status_to_result(code)
    }
}

/// Shorthand for `transfer(handle, Owner::Immutable)`.
pub fn object_freeze(handle: RuntimeHandle) -> Result<(), PetalError> {
    if !handle.is_valid() {
        return Err(PetalError::InvalidHandle);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        match mock::dispatch(HostCall::ObjectFreeze { handle }) {
            HostResponse::Status(code) => status_to_result(code),
            HostResponse::Err(e) => Err(e),
            other => panic!("object_freeze expected Status response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: no buffers.
        let code = unsafe { host_extern::object_freeze(handle.as_raw()) };
        status_to_result(code)
    }
}

/// Permanently delete a borrowed object (only the type-defining petal
/// is authorized).
pub fn object_delete(handle: RuntimeHandle) -> Result<(), PetalError> {
    if !handle.is_valid() {
        return Err(PetalError::InvalidHandle);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        match mock::dispatch(HostCall::ObjectDelete { handle }) {
            HostResponse::Status(code) => status_to_result(code),
            HostResponse::Err(e) => Err(e),
            other => panic!("object_delete expected Status response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: no buffers.
        let code = unsafe { host_extern::object_delete(handle.as_raw()) };
        status_to_result(code)
    }
}

/// Resolve a borrow handle back to the 32-byte [`ObjectId`] it points at.
///
/// The return path uses this to encode a Coin/Capability output as the
/// stable on-chain id (32 bytes) rather than the ephemeral 4-byte borrow
/// handle, so the chain executor can thread it into a later command's
/// `Use(...)` → `Object` slot (`exec_transfer` / `exec_split_coins`
/// decode such a slot as a raw `ObjectId`).
pub fn object_id(handle: RuntimeHandle) -> Result<ObjectId, PetalError> {
    if !handle.is_valid() {
        return Err(PetalError::InvalidHandle);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        match mock::dispatch(HostCall::ObjectId { handle }) {
            HostResponse::Address(a) => Ok(ObjectId(a)),
            HostResponse::Err(e) => Err(e),
            other => panic!("object_id expected Address response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let mut out = [0u8; 32];
        // SAFETY: `out` is a stack-allocated 32-byte buffer we hand to
        // the host; host writes exactly 32 bytes on success.
        let code = unsafe { host_extern::object_id(handle.as_raw(), out.as_mut_ptr()) };
        if code < 0 {
            Err(PetalError::HostImportFailed)
        } else {
            Ok(ObjectId(out))
        }
    }
}

/// Check whether a borrowed object matches the expected capability
/// type tag. Returns `true` on match.
pub fn cap_check(handle: RuntimeHandle, expected_type_tag: &TypeTag) -> bool {
    if !handle.is_valid() {
        return false;
    }
    let Ok(type_tag_bytes) = expected_type_tag.encode_canonical() else {
        return false;
    };

    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::CapCheck {
            handle,
            type_tag_bytes,
        };
        match mock::dispatch(call) {
            HostResponse::IntReturn(code) => code == 1,
            HostResponse::Status(code) => code == 1,
            HostResponse::Err(_) => false,
            other => panic!("cap_check expected IntReturn response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let Ok(tlen) = i32::try_from(type_tag_bytes.len()) else {
            return false;
        };
        // SAFETY: `type_tag_bytes` lives for the duration of the call.
        let code =
            unsafe { host_extern::cap_check(handle.as_raw(), type_tag_bytes.as_ptr(), tlen) };
        code == 1
    }
}

/// Index of the primary signer for the current command, or `None` if
/// the command does not declare one.
pub fn signer_index() -> Option<u16> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        match mock::dispatch(HostCall::SignerIndex) {
            HostResponse::IntReturn(code) => i32_to_signer_index(code),
            HostResponse::Status(code) => i32_to_signer_index(code),
            HostResponse::Err(_) => None,
            other => panic!("signer_index expected IntReturn response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: no buffers; nullary host call.
        let code = unsafe { host_extern::signer_index() };
        i32_to_signer_index(code)
    }
}

#[inline]
fn i32_to_signer_index(code: i32) -> Option<u16> {
    if code < 0 {
        None
    } else {
        u16::try_from(code).ok()
    }
}

/// 32-byte post-quantum address of the `idx`-th signer.
pub fn signer_address(idx: u16) -> Result<[u8; 32], PetalError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::SignerAddress { idx };
        match mock::dispatch(call) {
            HostResponse::Address(a) => Ok(a),
            HostResponse::Err(e) => Err(e),
            other => panic!("signer_address expected Address response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let mut out = [0u8; 32];
        // SAFETY: `out` is a stack-allocated 32-byte buffer we hand to
        // the host; host writes exactly 32 bytes on success.
        let code = unsafe { host_extern::signer_address(idx as i32, out.as_mut_ptr()) };
        if code < 0 {
            Err(PetalError::HostImportFailed)
        } else {
            Ok(out)
        }
    }
}

/// Read a typed return value from an earlier command (used by the
/// runtime to thread `Use(...)` references; rarely called from user
/// code directly).
pub fn ptb_command_output(cmd_idx: u16, ret_idx: u16) -> Result<Vec<u8>, PetalError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::PtbCommandOutput { cmd_idx, ret_idx };
        match mock::dispatch(call) {
            HostResponse::Bytes(b) => Ok(b),
            HostResponse::Err(e) => Err(e),
            other => panic!("ptb_command_output expected Bytes response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        // Same grow-and-retry strategy as object_read.
        const INITIAL_CAP: usize = 1024;
        let mut buf: Vec<u8> = Vec::with_capacity(INITIAL_CAP);
        // SAFETY: we just allocated; host writes at most INITIAL_CAP bytes.
        let written = unsafe {
            host_extern::ptb_command_output(
                cmd_idx as i32,
                ret_idx as i32,
                buf.as_mut_ptr(),
                INITIAL_CAP as i32,
            )
        };
        if written >= 0 {
            // SAFETY: host wrote `written` bytes.
            unsafe { buf.set_len(written as usize) };
            return Ok(buf);
        }
        let needed = (-written) as usize;
        let mut buf2: Vec<u8> = Vec::with_capacity(needed);
        // SAFETY: we own `needed` capacity.
        let written2 = unsafe {
            host_extern::ptb_command_output(
                cmd_idx as i32,
                ret_idx as i32,
                buf2.as_mut_ptr(),
                needed as i32,
            )
        };
        if written2 < 0 {
            return Err(PetalError::HostImportFailed);
        }
        // SAFETY: host wrote `written2` bytes.
        unsafe { buf2.set_len(written2 as usize) };
        Ok(buf2)
    }
}

/// Emit a legacy-style indexable log entry.
pub fn log_emit(topic: &[u8], data: &[u8]) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let call = HostCall::LogEmit {
            topic: topic.to_vec(),
            data: data.to_vec(),
        };
        match mock::dispatch(call) {
            HostResponse::Status(_) | HostResponse::Err(_) => {}
            other => panic!("log_emit expected Status response, got {other:?}"),
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let topic_len = topic.len() as i32;
        let data_len = data.len() as i32;
        // SAFETY: both buffers are borrowed for the duration of the
        // call; the host only reads.
        let _ =
            unsafe { host_extern::log_emit(topic.as_ptr(), topic_len, data.as_ptr(), data_len) };
    }
}

// ===========================================================================
// Calldata / return / revert ABI bridge (wasm32 only)
// ===========================================================================
//
// These three wrappers exist only on the chain VM target. The
// macro-emitted `__petal_<fn>(i32, i32) -> i32` export uses them to read
// its framed calldata and to deliver its framed return / abort envelope.
// On non-wasm targets the macro emits a `fn shim(args, ret_buf) -> i32`
// host shim that consumes/produces those buffers directly, so there is
// no mock equivalent here.

/// Read `len` bytes of the current command's calldata, starting at byte
/// `offset`, into a freshly-allocated `Vec<u8>` (wasm32 only).
///
/// Mirrors the VM's `chain.msg.calldata.read(dst, offset, len)` import.
#[cfg(target_arch = "wasm32")]
pub fn calldata_read(offset: i32, len: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    // SAFETY: we just allocated `len` capacity; the host writes at most
    // `len` bytes and returns the count actually written.
    let written = unsafe { host_extern::msg_calldata_read(buf.as_mut_ptr(), offset, len as i32) };
    if written < 0 {
        return Vec::new();
    }
    // SAFETY: host wrote `written` valid bytes into our buffer.
    unsafe { buf.set_len(written as usize) };
    buf
}

/// Deliver a successful framed return envelope to the host and unwind
/// the guest (wasm32 only). The host import traps to terminate the call,
/// so this never returns.
#[cfg(target_arch = "wasm32")]
pub fn petal_return(bytes: &[u8]) -> ! {
    // SAFETY: `bytes` is borrowed for the duration of the call; the host
    // copies it out before trapping. The import does not return.
    unsafe { host_extern::petal_return(bytes.as_ptr(), bytes.len() as i32) };
    // The host import traps; this is unreachable, but the `!` return type
    // demands we never fall through.
    core::unreachable!("chain.petal.return must trap")
}

/// Deliver an abort (revert) envelope to the host and unwind the guest
/// (wasm32 only). The host import traps to terminate the call, so this
/// never returns.
#[cfg(target_arch = "wasm32")]
pub fn petal_revert(bytes: &[u8]) -> ! {
    // SAFETY: same contract as `petal_return`.
    unsafe { host_extern::petal_revert(bytes.as_ptr(), bytes.len() as i32) };
    core::unreachable!("chain.petal.revert must trap")
}

// ===========================================================================
// Tests (mock-driven)
// ===========================================================================

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use bloom_objects::{AccessMode, ObjectId, Owner, TypeTag};

    fn fresh() {
        test_hooks::clear();
    }

    #[test]
    fn object_borrow_records_id_and_mode() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Handle(RuntimeHandle::from_raw(7)));
        let id = ObjectId([0xAB; 32]);
        let h = object_borrow(&id, AccessMode::Mutable).unwrap();
        assert_eq!(h, RuntimeHandle::from_raw(7));
        let calls = test_hooks::recorded_calls();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            HostCall::ObjectBorrow { id: got, mode } => {
                assert_eq!(*got, id);
                assert_eq!(*mode, AccessMode::Mutable);
            }
            other => panic!("expected ObjectBorrow, got {other:?}"),
        }
    }

    #[test]
    fn object_borrow_propagates_err_response() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Err(PetalError::OwnershipDenied));
        let err = object_borrow(&ObjectId([0; 32]), AccessMode::Mutable).unwrap_err();
        assert_eq!(err, PetalError::OwnershipDenied);
    }

    #[test]
    fn object_borrow_negative_int_return_is_error() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::IntReturn(-1));
        let err = object_borrow(&ObjectId([0; 32]), AccessMode::ReadOnly).unwrap_err();
        assert_eq!(err, PetalError::HostImportFailed);
    }

    #[test]
    fn object_read_returns_bytes() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Bytes(vec![1, 2, 3, 4]));
        let bytes = object_read(RuntimeHandle::from_raw(0)).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn object_read_rejects_invalid_handle_before_dispatch() {
        fresh();
        // Responder never runs because the wrapper short-circuits.
        let err = object_read(RuntimeHandle::INVALID).unwrap_err();
        assert_eq!(err, PetalError::InvalidHandle);
        assert!(test_hooks::recorded_calls().is_empty());
    }

    #[test]
    fn object_mutate_passes_payload_bytes() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Status(0));
        let h = RuntimeHandle::from_raw(3);
        object_mutate(h, b"new payload").unwrap();
        match test_hooks::last_call().unwrap() {
            HostCall::ObjectMutate { handle, payload } => {
                assert_eq!(handle, h);
                assert_eq!(payload, b"new payload".to_vec());
            }
            other => panic!("expected ObjectMutate, got {other:?}"),
        }
    }

    #[test]
    fn object_mutate_status_to_typed_error() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Status(PetalError::OwnershipDenied.as_i32()));
        let err = object_mutate(RuntimeHandle::from_raw(0), b"x").unwrap_err();
        assert_eq!(err, PetalError::OwnershipDenied);
    }

    #[test]
    fn object_create_encodes_type_tag_canonical() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Handle(RuntimeHandle::from_raw(5)));
        let tag = TypeTag::Concrete {
            petal_hash: [0xAA; 32],
            type_name: "Coin".to_string(),
            type_args: vec![],
        };
        object_create(&tag, b"payload").unwrap();
        match test_hooks::last_call().unwrap() {
            HostCall::ObjectCreate {
                type_tag_bytes,
                payload,
            } => {
                assert_eq!(type_tag_bytes, tag.encode_canonical().unwrap());
                assert_eq!(payload, b"payload".to_vec());
            }
            other => panic!("expected ObjectCreate, got {other:?}"),
        }
    }

    #[test]
    fn object_id_resolves_handle_to_object_id() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Address([0x5A; 32]));
        let h = RuntimeHandle::from_raw(4);
        let id = object_id(h).unwrap();
        assert_eq!(id, ObjectId([0x5A; 32]));
        match test_hooks::last_call().unwrap() {
            HostCall::ObjectId { handle } => assert_eq!(handle, h),
            other => panic!("expected ObjectId, got {other:?}"),
        }
    }

    #[test]
    fn object_id_rejects_invalid_handle_before_dispatch() {
        fresh();
        let err = object_id(RuntimeHandle::INVALID).unwrap_err();
        assert_eq!(err, PetalError::InvalidHandle);
        assert!(test_hooks::recorded_calls().is_empty());
    }

    #[test]
    fn object_transfer_encodes_address_owner() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Status(0));
        let h = RuntimeHandle::from_raw(2);
        let owner = Owner::Address([0x11; 32]);
        object_transfer(h, &owner).unwrap();
        match test_hooks::last_call().unwrap() {
            HostCall::ObjectTransfer {
                handle,
                owner_kind,
                owner_payload,
            } => {
                assert_eq!(handle, h);
                assert_eq!(owner_kind, bloom_objects::OWNER_KIND_ADDRESS);
                assert_eq!(owner_payload, vec![0x11; 32]);
            }
            other => panic!("expected ObjectTransfer, got {other:?}"),
        }
    }

    #[test]
    fn object_transfer_shared_has_empty_payload() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Status(0));
        object_transfer(RuntimeHandle::from_raw(0), &Owner::Shared).unwrap();
        match test_hooks::last_call().unwrap() {
            HostCall::ObjectTransfer {
                owner_kind,
                owner_payload,
                ..
            } => {
                assert_eq!(owner_kind, bloom_objects::OWNER_KIND_SHARED);
                assert!(owner_payload.is_empty());
            }
            other => panic!("expected ObjectTransfer, got {other:?}"),
        }
    }

    #[test]
    fn object_transfer_immutable_has_empty_payload() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Status(0));
        object_transfer(RuntimeHandle::from_raw(0), &Owner::Immutable).unwrap();
        match test_hooks::last_call().unwrap() {
            HostCall::ObjectTransfer {
                owner_kind,
                owner_payload,
                ..
            } => {
                assert_eq!(owner_kind, bloom_objects::OWNER_KIND_IMMUTABLE);
                assert!(owner_payload.is_empty());
            }
            other => panic!("expected ObjectTransfer, got {other:?}"),
        }
    }

    #[test]
    fn object_transfer_object_owner_carries_id() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Status(0));
        object_transfer(
            RuntimeHandle::from_raw(0),
            &Owner::Object(ObjectId([0x22; 32])),
        )
        .unwrap();
        match test_hooks::last_call().unwrap() {
            HostCall::ObjectTransfer {
                owner_kind,
                owner_payload,
                ..
            } => {
                assert_eq!(owner_kind, bloom_objects::OWNER_KIND_OBJECT);
                assert_eq!(owner_payload, vec![0x22; 32]);
            }
            other => panic!("expected ObjectTransfer, got {other:?}"),
        }
    }

    #[test]
    fn object_share_freeze_delete_record_handles() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Status(0));
        let h = RuntimeHandle::from_raw(9);
        object_share(h).unwrap();
        object_freeze(h).unwrap();
        object_delete(h).unwrap();
        let calls = test_hooks::recorded_calls();
        assert!(matches!(calls[0], HostCall::ObjectShare { handle } if handle == h));
        assert!(matches!(calls[1], HostCall::ObjectFreeze { handle } if handle == h));
        assert!(matches!(calls[2], HostCall::ObjectDelete { handle } if handle == h));
    }

    #[test]
    fn share_freeze_delete_reject_invalid_handle() {
        fresh();
        // No responder needed: short-circuit.
        assert_eq!(
            object_share(RuntimeHandle::INVALID).unwrap_err(),
            PetalError::InvalidHandle
        );
        assert_eq!(
            object_freeze(RuntimeHandle::INVALID).unwrap_err(),
            PetalError::InvalidHandle
        );
        assert_eq!(
            object_delete(RuntimeHandle::INVALID).unwrap_err(),
            PetalError::InvalidHandle
        );
        assert!(test_hooks::recorded_calls().is_empty());
    }

    #[test]
    fn cap_check_returns_true_on_int_return_one() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::IntReturn(1));
        let tag = TypeTag::Concrete {
            petal_hash: [0; 32],
            type_name: "MintCap".to_string(),
            type_args: vec![],
        };
        assert!(cap_check(RuntimeHandle::from_raw(0), &tag));
    }

    #[test]
    fn cap_check_returns_false_on_int_return_zero() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::IntReturn(0));
        let tag = TypeTag::Concrete {
            petal_hash: [0; 32],
            type_name: "MintCap".to_string(),
            type_args: vec![],
        };
        assert!(!cap_check(RuntimeHandle::from_raw(0), &tag));
    }

    #[test]
    fn cap_check_rejects_invalid_handle_without_dispatch() {
        fresh();
        let tag = TypeTag::Generic { idx: 0 };
        assert!(!cap_check(RuntimeHandle::INVALID, &tag));
        assert!(test_hooks::recorded_calls().is_empty());
    }

    #[test]
    fn signer_index_present() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::IntReturn(3));
        assert_eq!(signer_index(), Some(3));
    }

    #[test]
    fn signer_index_absent_on_negative() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::IntReturn(-1));
        assert_eq!(signer_index(), None);
    }

    #[test]
    fn signer_address_returns_payload() {
        fresh();
        let addr = [0x77; 32];
        test_hooks::set_responder(move |_| HostResponse::Address(addr));
        assert_eq!(signer_address(0).unwrap(), addr);
    }

    #[test]
    fn ptb_command_output_decodes_bytes() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Bytes(vec![0x42; 8]));
        let bytes = ptb_command_output(1, 0).unwrap();
        assert_eq!(bytes, vec![0x42; 8]);
        match test_hooks::last_call().unwrap() {
            HostCall::PtbCommandOutput { cmd_idx, ret_idx } => {
                assert_eq!(cmd_idx, 1);
                assert_eq!(ret_idx, 0);
            }
            other => panic!("expected PtbCommandOutput, got {other:?}"),
        }
    }

    #[test]
    fn log_emit_records_topic_and_data() {
        fresh();
        test_hooks::set_responder(|_| HostResponse::Status(0));
        log_emit(b"topic", b"payload");
        match test_hooks::last_call().unwrap() {
            HostCall::LogEmit { topic, data } => {
                assert_eq!(topic, b"topic".to_vec());
                assert_eq!(data, b"payload".to_vec());
            }
            other => panic!("expected LogEmit, got {other:?}"),
        }
    }

    #[test]
    fn ok_responder_handles_every_call_shape() {
        fresh();
        test_hooks::set_responder(test_hooks::ok_responder());
        let _ = object_borrow(&ObjectId([0; 32]), AccessMode::Mutable).unwrap();
        let _ = object_create(&TypeTag::Generic { idx: 0 }, b"").unwrap();
        object_mutate(RuntimeHandle::from_raw(0), b"x").unwrap();
        object_transfer(RuntimeHandle::from_raw(0), &Owner::Shared).unwrap();
        object_share(RuntimeHandle::from_raw(0)).unwrap();
        object_freeze(RuntimeHandle::from_raw(0)).unwrap();
        object_delete(RuntimeHandle::from_raw(0)).unwrap();
        let _ = cap_check(RuntimeHandle::from_raw(0), &TypeTag::Generic { idx: 0 });
        let _ = signer_index();
        let _ = signer_address(0).unwrap();
        let _ = ptb_command_output(0, 0).unwrap();
        log_emit(b"t", b"d");
        // Recorded all calls.
        assert!(test_hooks::recorded_calls().len() >= 12);
    }
}
