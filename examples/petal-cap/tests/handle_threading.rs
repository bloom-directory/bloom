//! Real runtime-handle threading tests for `cap::new`, `cap::transfer`,
//! and `cap::destroy`.
//!
//! Strategy (TDD red → green):
//!   - Pre-program the mock responder so `object_create` returns specific
//!     handle values.
//!   - Call the petal functions.
//!   - Assert the subsequent `object_transfer` / `object_delete` / `object_mutate`
//!     calls received those same handles — not `INVALID` (-1).
//!
//! NOTE: all petal fns that carry a `<T>` type parameter emit a
//! `PetalError::NotImplemented` shim at the wasm export layer (spec §11.2),
//! so we test the *internal* petal logic via the public `cap` module
//! directly. The host-call assertions are the observable proof that the
//! right handle flows through each code path.

use bloom_petal_cap::cap;
use bloom_resource::{
    Resource, RuntimeHandle,
    host::{HostCall, HostResponse, test_hooks},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Marker type — stands in for any `T` the test doesn't care about.
struct Marker;

/// A canonical `Cap<T>` payload (`id || inner_kind || expires_at_block
/// || revoked`) for pre-programming `object_read` responses. In the
/// handle/tag model every mutation reads the live payload first.
fn cap_payload_bytes(inner_kind: u8, expires_at_block: u64, revoked: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(bloom_petal_cap::CAP_PAYLOAD_LEN);
    v.extend_from_slice(&[0u8; 32]);
    v.push(inner_kind);
    v.extend_from_slice(&expires_at_block.to_be_bytes());
    v.push(revoked as u8);
    v
}

/// Sequence responder: drains a vec of responses in order; panics when
/// the vec is exhausted unexpectedly.
fn seq_responder(mut responses: Vec<HostResponse>) -> impl FnMut(&HostCall) -> HostResponse {
    responses.reverse(); // we'll pop from the back
    move |_call: &HostCall| {
        responses
            .pop()
            .expect("seq_responder ran out of pre-programmed responses")
    }
}

// ---------------------------------------------------------------------------
// cap::new — object_create is called and real handles land in the Cap/RevokeCap
// ---------------------------------------------------------------------------

#[test]
fn new_calls_object_create_for_cap_and_revoke_cap() {
    test_hooks::clear();
    // Two object_create calls: one for Cap<T>, one for RevokeCap<T>.
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Handle(RuntimeHandle::from_raw(10)),
        HostResponse::Handle(RuntimeHandle::from_raw(11)),
    ]));

    let signer = bloom_resource::Signer::from_index(0);
    let (_cap, _rev): (Resource<cap::Cap<Marker>>, Resource<cap::RevokeCap<Marker>>) =
        cap::new(&signer);

    let calls = test_hooks::recorded_calls();
    let create_calls: Vec<_> = calls
        .iter()
        .filter(|c| matches!(c, HostCall::ObjectCreate { .. }))
        .collect();
    assert_eq!(
        create_calls.len(),
        2,
        "new<T> must issue exactly 2 object_create calls (cap + revoke_cap), got {:?}",
        calls
    );
}

// ---------------------------------------------------------------------------
// cap::transfer — object_transfer receives the handle returned by create
// ---------------------------------------------------------------------------

#[test]
fn transfer_uses_real_cap_handle() {
    test_hooks::clear();
    // Sequence: create cap (h=42), create revoke_cap (h=43), then
    // object_transfer which we assert receives handle 42.
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Handle(RuntimeHandle::from_raw(42)), // create Cap<T>
        HostResponse::Handle(RuntimeHandle::from_raw(43)), // create RevokeCap<T>
        HostResponse::Status(0),                           // object_transfer
    ]));

    let signer = bloom_resource::Signer::from_index(0);
    let (cap_val, _rev): (Resource<cap::Cap<Marker>>, Resource<cap::RevokeCap<Marker>>) =
        cap::new(&signer);

    // Reset call log so we only inspect the transfer call.
    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Status(0), // object_transfer
    ]));

    let to_addr = [0xABu8; 32];
    cap::transfer(cap_val, to_addr);

    let calls = test_hooks::recorded_calls();
    assert_eq!(calls.len(), 1, "transfer should issue exactly 1 host call");
    match &calls[0] {
        HostCall::ObjectTransfer { handle, .. } => {
            assert_eq!(
                *handle,
                RuntimeHandle::from_raw(42),
                "object_transfer must receive the cap's real handle (42), got {:?}",
                handle
            );
        }
        other => panic!("expected ObjectTransfer, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// cap::destroy — object_delete receives the handle returned by create
// ---------------------------------------------------------------------------

#[test]
fn destroy_uses_real_cap_handle() {
    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Handle(RuntimeHandle::from_raw(77)), // create Cap<T>
        HostResponse::Handle(RuntimeHandle::from_raw(78)), // create RevokeCap<T>
    ]));

    let signer = bloom_resource::Signer::from_index(0);
    let (cap_val, _rev): (Resource<cap::Cap<Marker>>, Resource<cap::RevokeCap<Marker>>) =
        cap::new(&signer);

    // Now test destroy.
    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Status(0), // object_delete
    ]));

    cap::destroy(cap_val);

    let calls = test_hooks::recorded_calls();
    assert_eq!(calls.len(), 1, "destroy should issue exactly 1 host call");
    match &calls[0] {
        HostCall::ObjectDelete { handle } => {
            assert_eq!(
                *handle,
                RuntimeHandle::from_raw(77),
                "object_delete must receive the cap's real handle (77), got {:?}",
                handle
            );
        }
        other => panic!("expected ObjectDelete, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// write_cap_fields (exercised through lock/unlock/set_expiry) uses real handle
// ---------------------------------------------------------------------------

#[test]
fn lock_write_cap_fields_uses_real_handle() {
    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Handle(RuntimeHandle::from_raw(55)), // create Cap<T>
        HostResponse::Handle(RuntimeHandle::from_raw(56)), // create RevokeCap<T>
    ]));

    let signer = bloom_resource::Signer::from_index(0);
    let (mut cap_val, _rev): (Resource<cap::Cap<Marker>>, Resource<cap::RevokeCap<Marker>>) =
        cap::new(&signer);

    // In the handle/tag model `lock` first reads the live payload (to
    // preserve the `revoked` flag) then writes back the locked payload —
    // two host calls, both on the cap's real handle (55).
    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Bytes(cap_payload_bytes(0, 0, false)), // object_read
        HostResponse::Status(0),                             // object_mutate
    ]));

    cap::lock(&mut cap_val);

    let calls = test_hooks::recorded_calls();
    assert_eq!(
        calls.len(),
        2,
        "lock should issue exactly 2 host calls (read + mutate), got {calls:?}"
    );
    match &calls[0] {
        HostCall::ObjectRead { handle } => assert_eq!(
            *handle,
            RuntimeHandle::from_raw(55),
            "object_read must receive the cap's real handle (55), got {handle:?}"
        ),
        other => panic!("expected ObjectRead first, got {other:?}"),
    }
    match &calls[1] {
        HostCall::ObjectMutate { handle, .. } => {
            assert_eq!(
                *handle,
                RuntimeHandle::from_raw(55),
                "object_mutate in write_cap_fields must receive handle 55, got {handle:?}"
            );
        }
        other => panic!("expected ObjectMutate, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// transfer does NOT call object_transfer with INVALID (-1)
// ---------------------------------------------------------------------------

#[test]
fn transfer_never_uses_invalid_handle() {
    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Handle(RuntimeHandle::from_raw(99)),
        HostResponse::Handle(RuntimeHandle::from_raw(100)),
        HostResponse::Status(0),
    ]));

    let signer = bloom_resource::Signer::from_index(0);
    let (cap_val, _rev): (Resource<cap::Cap<Marker>>, Resource<cap::RevokeCap<Marker>>) =
        cap::new(&signer);

    // object_transfer with INVALID would return Err(InvalidHandle) before
    // even reaching the mock. If this panics, the handle was INVALID.
    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![HostResponse::Status(0)]));

    cap::transfer(cap_val, [0u8; 32]);

    // Confirm the transfer call recorded a non-INVALID handle.
    let calls = test_hooks::recorded_calls();
    for call in &calls {
        if let HostCall::ObjectTransfer { handle, .. } = call {
            assert!(
                handle.is_valid(),
                "object_transfer must not be called with INVALID handle, got {:?}",
                handle
            );
        }
    }
}

// ---------------------------------------------------------------------------
// destroy does NOT call object_delete with INVALID (-1)
// ---------------------------------------------------------------------------

#[test]
fn destroy_never_uses_invalid_handle() {
    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![
        HostResponse::Handle(RuntimeHandle::from_raw(33)),
        HostResponse::Handle(RuntimeHandle::from_raw(34)),
    ]));

    let signer = bloom_resource::Signer::from_index(0);
    let (cap_val, _rev): (Resource<cap::Cap<Marker>>, Resource<cap::RevokeCap<Marker>>) =
        cap::new(&signer);

    test_hooks::clear();
    test_hooks::set_responder(seq_responder(vec![HostResponse::Status(0)]));

    cap::destroy(cap_val);

    let calls = test_hooks::recorded_calls();
    for call in &calls {
        if let HostCall::ObjectDelete { handle } = call {
            assert!(
                handle.is_valid(),
                "object_delete must not be called with INVALID handle, got {:?}",
                handle
            );
        }
    }
}
