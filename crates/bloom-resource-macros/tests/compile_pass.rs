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

mod bloom_type_test {
    include!("fixtures/bloom_type_petal.rs");

    use self::bloom_type_fixture::{Quote, Status};
    use bloom_objects::{BUILTIN_TYPE_HASH, TypeTag};

    #[test]
    fn plain_struct_round_trips_variable_width_field() {
        let quote = Quote {
            amount: 42,
            label: "spot".to_string(),
            tags: vec!["a".to_string(), "bc".to_string()],
            raw: vec![1, 2, 3],
            blob: bloom_resource::Bytes::from(vec![4, 5]),
        };
        let bytes = quote.canonical_encode();
        let mut expected = 42u128.to_be_bytes().to_vec();
        expected.push(4);
        expected.extend_from_slice(b"spot");
        expected.extend_from_slice(b"\x02\x01a\x02bc");
        expected.extend_from_slice(b"\x03\x01\x02\x03");
        expected.extend_from_slice(b"\x02\x04\x05");
        assert_eq!(bytes, expected);
        assert_eq!(Quote::canonical_decode(&bytes).unwrap(), quote);
    }

    #[test]
    fn enum_variants_round_trip() {
        let filled = Status::Filled(7, "done".to_string());
        assert_eq!(
            Status::canonical_decode(&filled.canonical_encode()).unwrap(),
            filled
        );
        let named = Status::Named {
            ok: true,
            id: bloom_objects::ObjectId([0xAB; 32]),
        };
        assert_eq!(
            Status::canonical_decode(&named.canonical_encode()).unwrap(),
            named
        );
    }

    #[test]
    fn generated_type_tag_uses_self_sentinel_and_generic_args() {
        match Quote::type_tag() {
            TypeTag::Concrete {
                petal_hash,
                type_name,
                type_args,
            } => {
                assert_eq!(petal_hash, [0u8; 32]);
                assert_eq!(type_name, "Quote");
                assert!(type_args.is_empty());
            }
            other => panic!("expected concrete tag, got {other:?}"),
        }
        match String::type_tag() {
            TypeTag::Concrete { petal_hash, .. } => assert_eq!(petal_hash, BUILTIN_TYPE_HASH),
            other => panic!("expected concrete tag, got {other:?}"),
        }
    }

    #[test]
    fn manifest_records_derived_types() {
        let manifest =
            bloom_petal_manifest::codec::decode(self::bloom_type_fixture::__bloom_manifest_bytes())
                .unwrap();
        assert_eq!(manifest.data_types.len(), 2);
        assert_eq!(manifest.data_types[0].name, "Quote");
        let quote_fields = &manifest.data_types[0].fields;
        assert_eq!(quote_fields[2].name, "tags");
        assert!(matches!(
            &quote_fields[2].ty,
            TypeTag::Concrete {
                petal_hash: BUILTIN_TYPE_HASH,
                type_name,
                type_args,
            } if type_name == "vector" && type_args.len() == 1
        ));
        assert_eq!(quote_fields[3].name, "raw");
        assert!(matches!(
            &quote_fields[3].ty,
            TypeTag::Concrete {
                petal_hash: BUILTIN_TYPE_HASH,
                type_name,
                type_args,
            } if type_name == "vector" && type_args == &vec![u8::type_tag()]
        ));
        assert_eq!(quote_fields[4].name, "blob");
        assert!(matches!(
            &quote_fields[4].ty,
            TypeTag::Concrete {
                petal_hash: BUILTIN_TYPE_HASH,
                type_name,
                type_args,
            } if type_name == "bytes" && type_args.is_empty()
        ));
        assert_eq!(manifest.data_types[1].name, "LocalData");
        assert_eq!(manifest.enum_types.len(), 2);
        assert_eq!(manifest.enum_types[0].name, "Status");
        assert_eq!(manifest.enum_types[1].name, "LocalEnum");
    }
}

mod generic_dispatch_test {
    //! Drives the macro-emitted `__petal_<fn>` host shims for *generic*
    //! petal fns, proving runtime type-erased dispatch (spec §5):
    //!
    //! - The shim reads the leading `Arg::TypeArg(TypeTag)` slots off the
    //!   framed calldata envelope and binds them into the per-call
    //!   `bloom_resource::TypeArgs` context (no `NotImplemented` stub).
    //! - `Coin::<T>::type_tag(idx)` inside the body resolves to the
    //!   *runtime* tag carried in the calldata, not a compile-time const.
    //! - For `wrap<A, B>` the output coin is stamped via
    //!   `object.create` with the runtime tag of `B` (generic-param
    //!   index 1), proving the output object carries the correct runtime
    //!   type-tag.
    //! - Linearity holds: the input coin is borrowed exactly once and a
    //!   returned coin's id is resolved via the `object.id` import so it
    //!   crosses the command boundary as its 32-byte `ObjectId`.
    //!
    //! Calldata is the chain executor's framed envelope (`marshal_args`):
    //! `count(u32 BE)` then per-arg `tag + payload`, built here via
    //! `CallArgsWriter`. Returns are the `unmarshal_outputs` envelope:
    //! `count(u32 BE)` then per-slot length-prefixed bytes, parsed with
    //! a plain `ArgReader`.
    include!("fixtures/generic_dispatch_petal.rs");

    use bloom_objects::{AccessMode, ObjectId, TypeTag};
    use bloom_resource::RuntimeHandle;
    use bloom_resource::abi::{ArgReader, CallArgsWriter};
    use bloom_resource::host::{HostCall, HostResponse, test_hooks};

    fn concrete(name: &str) -> TypeTag {
        TypeTag::Concrete {
            petal_hash: [0u8; 32],
            type_name: name.to_string(),
            type_args: Vec::new(),
        }
    }

    fn drive(shim: fn(&[u8], &mut Vec<u8>) -> i32, args: &[u8]) -> (i32, Vec<u8>) {
        let mut ret_buf: Vec<u8> = Vec::new();
        let rc = shim(args, &mut ret_buf);
        (rc, ret_buf)
    }

    #[test]
    fn identity_threads_handle_and_binds_runtime_type_arg() {
        test_hooks::clear();
        // The shim borrows the input coin object → handle 21, then
        // resolves that handle back to its 32-byte id for the return.
        test_hooks::set_responder(|call| match call {
            HostCall::ObjectBorrow { mode, .. } => {
                assert_eq!(*mode, AccessMode::Consume);
                HostResponse::Handle(RuntimeHandle::from_raw(21))
            }
            HostCall::ObjectId { handle } => {
                assert_eq!(*handle, RuntimeHandle::from_raw(21));
                HostResponse::Address([0xAB; 32])
            }
            other => panic!("unexpected host call: {other:?}"),
        });

        // Framed calldata for `identity<T>(c: Coin<T>)`:
        //   TypeArg(T) | Object(c)
        let mut w = CallArgsWriter::new();
        w.push_type_arg(&concrete("USDC")).unwrap();
        w.push_object(&ObjectId([0xAB; 32]));
        let args = w.finish();

        let (rc, ret) = drive(generic::__bloom_petal_identity, &args);
        assert_eq!(rc, 0, "identity() should dispatch (no NotImplemented stub)");

        // Framed return: count=1, then the coin's 32-byte ObjectId.
        let mut r = ArgReader::new(&ret);
        assert_eq!(r.read_u32().unwrap(), 1, "one return slot");
        assert_eq!(r.read_bytes().unwrap(), vec![0xAB; 32]);
        r.expect_eof().unwrap();

        // Linearity: one borrow for the coin arg, then one id-resolve on
        // the returned coin.
        let calls = test_hooks::recorded_calls();
        assert_eq!(calls.len(), 2, "one borrow + one id-resolve");
        match &calls[0] {
            HostCall::ObjectBorrow { id, mode } => {
                assert_eq!(*id, ObjectId([0xAB; 32]));
                assert_eq!(*mode, AccessMode::Consume);
            }
            other => panic!("expected ObjectBorrow, got {other:?}"),
        }
        match &calls[1] {
            HostCall::ObjectId { handle } => assert_eq!(*handle, RuntimeHandle::from_raw(21)),
            other => panic!("expected ObjectId, got {other:?}"),
        }
    }

    #[test]
    fn echo_tag_resolves_runtime_type_arg_to_one_when_matching() {
        test_hooks::clear();
        // `echo_tag<T>()` takes no positional args; the calldata is just
        // the single leading TypeArg for T.
        let mut w = CallArgsWriter::new();
        w.push_type_arg(&concrete("USDC")).unwrap();
        let args = w.finish();

        let (rc, ret) = drive(generic::__bloom_petal_echo_tag, &args);
        assert_eq!(rc, 0);

        // `echo_tag` returns 1 when `Coin::<T>::type_tag(0)` == the USDC
        // expected tag. Framed return: count=1, then a length-prefixed
        // u128.
        let mut r = ArgReader::new(&ret);
        assert_eq!(r.read_u32().unwrap(), 1);
        let bytes = r.read_bytes().unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&bytes);
        assert_eq!(
            u128::from_be_bytes(a),
            1,
            "runtime tag must resolve to USDC"
        );
    }

    #[test]
    fn echo_tag_resolves_to_zero_for_mismatched_runtime_type_arg() {
        test_hooks::clear();
        // Bind a *different* runtime tag → body must observe the mismatch
        // and return 0, proving it reads the runtime tag, not a const.
        let mut w = CallArgsWriter::new();
        w.push_type_arg(&concrete("LOOM")).unwrap();
        let args = w.finish();

        let (rc, ret) = drive(generic::__bloom_petal_echo_tag, &args);
        assert_eq!(rc, 0);

        let mut r = ArgReader::new(&ret);
        assert_eq!(r.read_u32().unwrap(), 1);
        let bytes = r.read_bytes().unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&bytes);
        assert_eq!(
            u128::from_be_bytes(a),
            0,
            "non-USDC runtime tag must resolve to 0"
        );
    }

    #[test]
    fn wrap_stamps_output_coin_with_runtime_tag_of_second_type_arg() {
        test_hooks::clear();
        // Program the host: borrow → handle 7, read → empty payload,
        // create → handle 99, id(99) → the created coin's 32-byte id.
        test_hooks::set_responder(|call| match call {
            HostCall::ObjectBorrow { .. } => HostResponse::Handle(RuntimeHandle::from_raw(7)),
            HostCall::ObjectRead { .. } => HostResponse::Bytes(Vec::new()),
            HostCall::ObjectCreate { .. } => HostResponse::Handle(RuntimeHandle::from_raw(99)),
            HostCall::ObjectId { handle } => {
                assert_eq!(*handle, RuntimeHandle::from_raw(99));
                HostResponse::Address([0xEF; 32])
            }
            other => panic!("unexpected host call: {other:?}"),
        });

        // Framed calldata for `wrap<A, B>(c: Coin<A>)`:
        //   TypeArg(A) | TypeArg(B) | Object(c)
        let mut w = CallArgsWriter::new();
        w.push_type_arg(&concrete("USDC")).unwrap(); // A (index 0)
        w.push_type_arg(&concrete("LOOM")).unwrap(); // B (index 1)
        w.push_object(&ObjectId([0xCD; 32]));
        let args = w.finish();

        let (rc, ret) = drive(generic::__bloom_petal_wrap, &args);
        assert_eq!(rc, 0, "wrap() should dispatch");

        // Framed return: count=1, then the freshly created coin's id.
        let mut r = ArgReader::new(&ret);
        assert_eq!(r.read_u32().unwrap(), 1);
        assert_eq!(r.read_bytes().unwrap(), vec![0xEF; 32]);
        r.expect_eof().unwrap();

        // The created output object must carry the *runtime* tag of B
        // (LOOM, generic-param index 1) — proving the output stamps the
        // runtime type-arg, not a compile-time const or A's tag.
        let calls = test_hooks::recorded_calls();
        let create = calls
            .iter()
            .find(|c| matches!(c, HostCall::ObjectCreate { .. }))
            .expect("wrap must call object.create");
        match create {
            HostCall::ObjectCreate { type_tag_bytes, .. } => {
                assert_eq!(
                    *type_tag_bytes,
                    concrete("LOOM").encode_canonical().unwrap(),
                    "output coin must be stamped with B's runtime tag (LOOM)"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn manifest_bytes_present() {
        let bytes = generic::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}

mod dispatch_test {
    //! Drives the macro-emitted `__petal_<fn>` host shims end-to-end:
    //! builds the framed calldata envelope matching each declared arg
    //! shape via `CallArgsWriter`, allocates a return buffer, calls the
    //! shim, and confirms (a) the dispatch returned 0, (b) the
    //! count-prefixed return envelope round-trips back to the expected
    //! value, and (c) for object args the right host call was recorded.
    include!("fixtures/dispatch_petal.rs");

    use bloom_objects::{AccessMode, ObjectId};
    use bloom_resource::abi::{ArgReader, CallArgsWriter};
    use bloom_resource::host::{HostCall, HostResponse, test_hooks};
    use bloom_resource::{BloomType, PetalError, RuntimeHandle};

    /// Drive a host-side mirror shim with the given args buffer.
    /// Returns the rc and the encoded return bytes the shim appended.
    fn drive_safe_shim(shim: fn(&[u8], &mut Vec<u8>) -> i32, args: &[u8]) -> (i32, Vec<u8>) {
        let mut ret_buf: Vec<u8> = Vec::new();
        let rc = shim(args, &mut ret_buf);
        (rc, ret_buf)
    }

    #[test]
    fn id_round_trips_u128_const_arg() {
        test_hooks::clear();
        // `id(x: u128) -> u128` — single Const arg.
        let mut w = CallArgsWriter::new();
        w.push_const(&7777u128.to_be_bytes());
        let args = w.finish();

        let (rc, ret) = drive_safe_shim(dispatch::__bloom_petal_id, &args);
        assert_eq!(rc, 0, "id() should succeed");

        // Framed return: count=1, then a length-prefixed u128 → 16 bytes.
        let mut r = ArgReader::new(&ret);
        assert_eq!(r.read_u32().unwrap(), 1);
        let bytes = r.read_bytes().unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&bytes);
        assert_eq!(u128::from_be_bytes(a), 7777);
    }

    #[test]
    fn bytes_arg_decodes_as_canonical_const_value_not_object() {
        test_hooks::clear();
        let blob = bloom_resource::Bytes::from(vec![0xA1, 0xB2, 0xC3]);
        let mut w = CallArgsWriter::new();
        w.push_const(&blob.canonical_encode());
        let args = w.finish();

        let (rc, ret) = drive_safe_shim(dispatch::__bloom_petal_blob_len, &args);
        assert_eq!(rc, 0, "blob_len() should succeed");

        let mut r = ArgReader::new(&ret);
        assert_eq!(r.read_u32().unwrap(), 1);
        let bytes = r.read_bytes().unwrap();
        let mut a = [0u8; 16];
        a.copy_from_slice(&bytes);
        assert_eq!(u128::from_be_bytes(a), 3);
        assert!(
            test_hooks::recorded_calls().is_empty(),
            "Bytes must not be decoded via object.borrow"
        );
    }

    #[test]
    fn requires_signer_decodes_signer_index_and_returns_u32() {
        test_hooks::clear();
        // `requires_signer(s: &Signer) -> u32` — single Signer arg.
        let mut w = CallArgsWriter::new();
        w.push_signer(5);
        let args = w.finish();

        let (rc, ret) = drive_safe_shim(dispatch::__bloom_petal_requires_signer, &args);
        assert_eq!(rc, 0, "requires_signer() should succeed");

        // Framed return: count=1, then a length-prefixed u32 → 4 bytes
        // containing `5`.
        let mut r = ArgReader::new(&ret);
        assert_eq!(r.read_u32().unwrap(), 1);
        let bytes = r.read_bytes().unwrap();
        let mut a = [0u8; 4];
        a.copy_from_slice(&bytes);
        assert_eq!(u32::from_be_bytes(a), 5);
    }

    #[test]
    fn double_coin_borrows_object_and_returns_handle_derived_u128() {
        test_hooks::clear();
        // Pre-program object.borrow to return handle 21. The return is a
        // plain u128 (not a Coin), so no object.id resolve happens.
        test_hooks::set_responder(|call| match call {
            HostCall::ObjectBorrow { mode, .. } => {
                assert_eq!(*mode, AccessMode::Consume);
                HostResponse::Handle(RuntimeHandle::from_raw(21))
            }
            other => panic!("unexpected host call: {other:?}"),
        });

        // `double_coin(c: Coin<u128>)` — single Object arg.
        let mut w = CallArgsWriter::new();
        w.push_object(&ObjectId([0xAB; 32]));
        let args = w.finish();

        let (rc, ret) = drive_safe_shim(dispatch::__bloom_petal_double_coin, &args);
        assert_eq!(rc, 0, "double_coin() should succeed");

        // Framed return: count=1, then a length-prefixed u128 == 21*2 = 42.
        let mut r = ArgReader::new(&ret);
        assert_eq!(r.read_u32().unwrap(), 1);
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
        // The framed envelope opens with a 4-byte count prefix; feeding
        // only 2 bytes makes `CallArgsReader::new` fail to read it.
        let bad = [0u8, 1];
        let (rc, _ret) = drive_safe_shim(dispatch::__bloom_petal_id, &bad);
        assert_eq!(rc, PetalError::InvalidArgs.as_i32());
    }

    #[test]
    fn trailing_calldata_returns_invalid_args_error_code() {
        test_hooks::clear();
        let mut w = CallArgsWriter::new();
        w.push_const(&1u128.to_be_bytes());
        w.push_const(&2u128.to_be_bytes());
        let args = w.finish();
        let (rc, _ret) = drive_safe_shim(dispatch::__bloom_petal_id, &args);
        assert_eq!(rc, PetalError::InvalidArgs.as_i32());
    }

    #[test]
    fn return_envelope_is_count_prefixed() {
        test_hooks::clear();
        // A successful call to `id` (returns u128) produces a
        // count-prefixed envelope: count(4 bytes) + one length-prefixed
        // slot.
        let mut w = CallArgsWriter::new();
        w.push_const(&1u128.to_be_bytes());
        let args = w.finish();
        let mut ret_buf: Vec<u8> = Vec::new();
        let rc = dispatch::__bloom_petal_id(&args, &mut ret_buf);
        assert_eq!(rc, 0);
        assert!(
            ret_buf.len() >= 4,
            "expected count-prefixed return envelope"
        );
        let mut r = ArgReader::new(&ret_buf);
        assert_eq!(r.read_u32().unwrap(), 1, "exactly one return slot");
    }

    #[test]
    fn manifest_bytes_present() {
        // Sanity: the petal still wires its manifest blob alongside the
        // new shim emission.
        let bytes = dispatch::__bloom_manifest_bytes();
        assert!(!bytes.is_empty());
    }
}
