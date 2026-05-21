//! Fixture-driven integration tests. Each `#[test]` `include!`s a
//! fixture file at the top level, exercising the macros end-to-end on
//! a self-contained petal.
//!
//! Note: `include!` semantics mean every fixture's `pub mod foo` is
//! merged into this test crate's namespace. To avoid name collisions
//! each fixture uses a distinct mod name (`minimal`, `cap`, `inv_test`).

#![allow(dead_code)] // fixture petal structs/fns are exercised purely by their
                     // macro expansion; we don't call them at runtime.

mod minimal_test {
    include!("fixtures/minimal_petal.rs");

    #[test]
    fn manifest_bytes_present() {
        let bytes = minimal::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}

mod capability_test {
    include!("fixtures/capability_petal.rs");

    #[test]
    fn manifest_bytes_present() {
        let bytes = cap::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}

mod invariant_test {
    include!("fixtures/invariant_petal.rs");

    #[test]
    fn manifest_bytes_present() {
        let bytes = inv_test::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}

mod dispatch_test {
    //! Drives the macro-emitted `__petal_<fn>` host shims end-to-end:
    //! builds an args buffer matching each declared arg shape, allocates
    //! a return buffer, calls the shim, and confirms (a) the dispatch
    //! returned 0, (b) the bytes in the return buffer round-trip back
    //! to the expected value, and (c) for object args the right host
    //! call was recorded.
    include!("fixtures/dispatch_petal.rs");

    use bloom_objects::{AccessMode, ObjectId};
    use bloom_resource::abi::{ArgReader, RetWriter};
    use bloom_resource::host::{HostCall, HostResponse, test_hooks};
    use bloom_resource::{PetalError, RuntimeHandle};

    /// Drive a host-side mirror shim with the given args buffer.
    /// Returns the rc and the encoded return bytes the shim appended.
    fn drive_safe_shim(
        shim: fn(&[u8], &mut Vec<u8>) -> i32,
        args: &[u8],
    ) -> (i32, Vec<u8>) {
        let mut ret_buf: Vec<u8> = Vec::new();
        let rc = shim(args, &mut ret_buf);
        (rc, ret_buf)
    }

    #[test]
    fn id_round_trips_u128_const_arg() {
        test_hooks::clear();
        // `id(x: u128) -> u128` — single length-prefixed const arg.
        let mut w = RetWriter::new();
        w.write_bytes(&7777u128.to_be_bytes());
        let args = w.finish();

        let (rc, ret) = drive_safe_shim(dispatch::__bloom_petal_id, &args);
        assert_eq!(rc, 0, "id() should succeed");

        // Decode the return: single length-prefixed u128 → 16 bytes.
        let mut r = ArgReader::new(&ret);
        let bytes = r.read_bytes().unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&bytes);
        assert_eq!(u128::from_be_bytes(a), 7777);
    }

    #[test]
    fn requires_signer_decodes_signer_index_and_returns_u32() {
        test_hooks::clear();
        // `requires_signer(s: &Signer) -> u32` — single u16 signer index arg.
        let mut w = RetWriter::new();
        w.write_u16(5);
        let args = w.finish();

        let (rc, ret) = drive_safe_shim(dispatch::__bloom_petal_requires_signer, &args);
        assert_eq!(rc, 0, "requires_signer() should succeed");

        // Return is a single length-prefixed u32 → 4 bytes containing `5`.
        let mut r = ArgReader::new(&ret);
        let bytes = r.read_bytes().unwrap();
        let mut a = [0u8; 4];
        a.copy_from_slice(&bytes);
        assert_eq!(u32::from_be_bytes(a), 5);
    }

    #[test]
    fn double_coin_borrows_object_and_returns_handle_derived_u128() {
        test_hooks::clear();
        // Pre-program object.borrow to return handle 21.
        test_hooks::set_responder(|call| match call {
            HostCall::ObjectBorrow { mode, .. } => {
                assert_eq!(*mode, AccessMode::Consume);
                HostResponse::Handle(RuntimeHandle::from_raw(21))
            }
            other => panic!("unexpected host call: {other:?}"),
        });

        // `double_coin(c: Coin<u128>)` — single ObjectId arg.
        let mut w = RetWriter::new();
        w.write_object_id(&ObjectId([0xAB; 32]));
        let args = w.finish();

        let (rc, ret) = drive_safe_shim(dispatch::__bloom_petal_double_coin, &args);
        assert_eq!(rc, 0, "double_coin() should succeed");

        // Return is length-prefixed u128 with value 21*2 = 42.
        let mut r = ArgReader::new(&ret);
        let bytes = r.read_bytes().unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&bytes);
        assert_eq!(u128::from_be_bytes(a), 42);

        // Confirm exactly one ObjectBorrow happened with the right id.
        let calls = test_hooks::recorded_calls();
        assert_eq!(calls.len(), 1);
        match calls.into_iter().next().unwrap() {
            HostCall::ObjectBorrow { id, mode } => {
                assert_eq!(id, ObjectId([0xAB; 32]));
                assert_eq!(mode, AccessMode::Consume);
            }
            other => panic!("expected ObjectBorrow, got {other:?}"),
        }
    }

    #[test]
    fn malformed_args_return_invalid_args_error_code() {
        test_hooks::clear();
        // `id` expects a length-prefixed u128 (4-byte len + 16 bytes);
        // we feed only 2 bytes so the reader hits UnexpectedEof.
        let bad = [0u8, 1];
        let (rc, _ret) = drive_safe_shim(dispatch::__bloom_petal_id, &bad);
        assert_eq!(rc, PetalError::InvalidArgs.as_i32());
    }

    #[test]
    fn empty_ret_buf_is_tolerated_when_user_fn_has_no_return() {
        test_hooks::clear();
        // A successful call to `id` (returns u128) still works with a
        // fresh empty `ret_buf`; the helper appends the encoded bytes
        // rather than requiring a pre-sized buffer.
        let mut w = RetWriter::new();
        w.write_bytes(&1u128.to_be_bytes());
        let args = w.finish();
        let mut ret_buf: Vec<u8> = Vec::new();
        let rc = dispatch::__bloom_petal_id(&args, &mut ret_buf);
        assert_eq!(rc, 0);
        assert!(!ret_buf.is_empty(), "expected encoded return bytes");
    }

    #[test]
    fn manifest_bytes_present() {
        // Sanity: the petal still wires its manifest blob alongside the
        // new shim emission.
        let bytes = dispatch::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}
