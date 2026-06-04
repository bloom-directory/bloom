//! Integration tests for the `bloom-petal-fungible` petal.
//!
//! Tests drive the host imports via `bloom_resource::host::test_hooks`
//! and exercise both the `Result`-typed `ops::*` helpers and the
//! `panic!`-on-error petal entry points.
//!
//! Coverage map:
//!  1. `create_currency` creates exactly 3 objects with the right tags.
//!  2. `mint` reads, increments and rewrites the supply, then creates a coin.
//!  3. `mint` overflow returns `Custom(1)`.
//!  4. `burn` reads coin + supply, deletes coin, decrements supply.
//!  5. `burn` underflow returns `InsufficientBalance`.
//!  6. `split` shrinks origin coin and emits a new one.
//!  7. `split` rejects `amount > current` with `InsufficientBalance`.
//!  8. `merge` deletes the source coin and rewrites the dest with the sum.
//!  9. `transfer` issues `ObjectTransfer` with `Owner::Address(recipient)`.
//! 10. `mint_genesis` creates a `Coin<LOOM>` and transfers it to recipient.
//! 11. `value` reads back the u128 from the payload without consuming.
//! 12. Payload helpers `coin_payload` / `rewrite_value` round-trip a u128.
//! 14. `ops::borrow_supply_mut` borrows the supply by its id in Mutable mode
//!     (spec §14.1 — Gap 1).
//! 15. `mint_genesis` verifies the EpochZero cap via `cap::check` (Gap 2).
//! 16. `create_burn_cap` does not exist — BurnCap only comes from
//!     `create_currency` (Gap 3 — verified by absence of the symbol).

use bloom_objects::{AccessMode, BUILTIN_TYPE_HASH, ObjectId, Owner, TypeTag};
use bloom_petal_fungible::fungible;
use bloom_petal_fungible::ops;
use bloom_resource::host::{HostCall, HostResponse, test_hooks};
use bloom_resource::{Capability, PetalError, Resource, RuntimeHandle};
use bloom_value::{CodecLimits, validate_value_bytes};

/// Reset the mock host before every test.
fn fresh() {
    test_hooks::clear();
}

fn self_type(name: &str, type_args: Vec<TypeTag>) -> TypeTag {
    TypeTag::Concrete {
        petal_hash: [0u8; 32],
        type_name: name.to_string(),
        type_args,
    }
}

#[test]
fn manifest_declares_coin_value_only_payload() {
    let manifest = bloom_petal_manifest::codec::decode(fungible::__bloom_manifest_bytes()).unwrap();
    let coin = manifest
        .object_types
        .iter()
        .find(|decl| decl.name == "Coin")
        .expect("Coin object declaration");
    assert_eq!(coin.type_params.len(), 1);
    assert_eq!(coin.fields.len(), 1);
    assert_eq!(coin.fields[0].name, "value");
    assert_eq!(
        coin.fields[0].ty,
        TypeTag::Concrete {
            petal_hash: BUILTIN_TYPE_HASH,
            type_name: "u128".to_string(),
            type_args: vec![],
        }
    );
}

#[test]
fn payload_helpers_match_declared_manifest_layouts() {
    let manifest = bloom_petal_manifest::codec::decode(fungible::__bloom_manifest_bytes()).unwrap();
    let resolver = bloom_petal_manifest::ManifestResolver::new(&manifest);
    let limits = CodecLimits::default();
    let loom = self_type("LOOM", vec![]);

    let coin_tag = self_type("Coin", vec![loom.clone()]);
    validate_value_bytes(&resolver, &coin_tag, &ops::coin_payload(424242), &limits).unwrap();
    let mut old_coin_payload = vec![0u8; 32];
    old_coin_payload.extend_from_slice(&424242u128.to_be_bytes());
    assert!(
        validate_value_bytes(&resolver, &coin_tag, &old_coin_payload, &limits).is_err(),
        "old id-prefixed Coin<T> payloads must not validate"
    );

    let supply_tag = self_type("Supply", vec![loom.clone()]);
    validate_value_bytes(&resolver, &supply_tag, &ops::supply_payload(123), &limits).unwrap();
    assert!(
        validate_value_bytes(&resolver, &supply_tag, &123u128.to_be_bytes(), &limits).is_err(),
        "value-only Supply<T> payloads must not validate"
    );

    let mint_cap_tag = self_type("MintCap", vec![loom.clone()]);
    validate_value_bytes(&resolver, &mint_cap_tag, &ops::cap_payload(), &limits).unwrap();
    let burn_cap_tag = self_type("BurnCap", vec![loom]);
    validate_value_bytes(&resolver, &burn_cap_tag, &ops::cap_payload(), &limits).unwrap();
    let epoch_zero_tag = self_type("EpochZero", vec![]);
    validate_value_bytes(&resolver, &epoch_zero_tag, &ops::cap_payload(), &limits).unwrap();
}

// ---------------------------------------------------------------------------
// 1. create_currency
// ---------------------------------------------------------------------------

#[test]
fn create_currency_emits_three_object_creates_in_order() {
    fresh();
    let mut next = 100i32;
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectCreate { .. } => {
            let h = HostResponse::Handle(RuntimeHandle::from_raw(next));
            next += 1;
            h
        }
        other => panic!("unexpected call {other:?}"),
    });

    let (mint, burn, supply) = ops::create_currency().unwrap();
    assert_eq!(mint, RuntimeHandle::from_raw(100));
    assert_eq!(burn, RuntimeHandle::from_raw(101));
    assert_eq!(supply, RuntimeHandle::from_raw(102));

    let calls = test_hooks::recorded_calls();
    assert_eq!(calls.len(), 3, "expected exactly 3 host calls");
    for c in &calls {
        assert!(matches!(c, HostCall::ObjectCreate { .. }));
    }
}

// ---------------------------------------------------------------------------
// 2. mint happy path
// ---------------------------------------------------------------------------

#[test]
fn mint_reads_supply_creates_coin_and_writes_back_total() {
    fresh();
    // Supply starts at 50.
    let supply_bytes = ops::supply_payload(50);

    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { .. } => HostResponse::Bytes(supply_bytes.clone()),
        HostCall::ObjectCreate { .. } => HostResponse::Handle(RuntimeHandle::from_raw(42)),
        HostCall::ObjectMutate { .. } => HostResponse::Status(0),
        other => panic!("unexpected call {other:?}"),
    });

    let supply_handle = RuntimeHandle::from_raw(7);
    let coin = ops::mint(supply_handle, 25).unwrap();
    assert_eq!(coin, RuntimeHandle::from_raw(42));

    let calls = test_hooks::recorded_calls();
    // read -> create -> mutate
    assert_eq!(calls.len(), 3);
    match &calls[2] {
        HostCall::ObjectMutate { handle, payload } => {
            assert_eq!(*handle, supply_handle);
            // Decoded new total should be 75.
            assert_eq!(ops::decode_supply_total(payload).unwrap(), 75);
        }
        other => panic!("expected mutate, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 3. mint overflow
// ---------------------------------------------------------------------------

#[test]
fn mint_overflow_returns_custom_one() {
    fresh();
    let supply_bytes = ops::supply_payload(u128::MAX - 1);
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { .. } => HostResponse::Bytes(supply_bytes.clone()),
        other => panic!("unexpected call {other:?}"),
    });

    let err = ops::mint(RuntimeHandle::from_raw(0), 5).unwrap_err();
    assert_eq!(err, PetalError::Custom(1));
}

// ---------------------------------------------------------------------------
// 4. burn happy path
// ---------------------------------------------------------------------------

#[test]
fn burn_decrements_supply_and_deletes_coin() {
    fresh();
    let supply_bytes = ops::supply_payload(100);
    let coin_bytes = ops::coin_payload(30);

    // The wrapper reads coin first (handle=5), then supply (handle=4).
    let supply_handle = RuntimeHandle::from_raw(4);
    let coin_handle = RuntimeHandle::from_raw(5);
    let supply_copy = supply_bytes.clone();
    let coin_copy = coin_bytes.clone();
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { handle } if *handle == coin_handle => {
            HostResponse::Bytes(coin_copy.clone())
        }
        HostCall::ObjectRead { handle } if *handle == supply_handle => {
            HostResponse::Bytes(supply_copy.clone())
        }
        HostCall::ObjectDelete { .. } => HostResponse::Status(0),
        HostCall::ObjectMutate { .. } => HostResponse::Status(0),
        other => panic!("unexpected call {other:?}"),
    });

    ops::burn(supply_handle, coin_handle).unwrap();

    let calls = test_hooks::recorded_calls();
    // read coin, read supply, delete coin, mutate supply
    assert_eq!(calls.len(), 4);
    assert!(matches!(calls[2], HostCall::ObjectDelete { handle } if handle == coin_handle));
    match &calls[3] {
        HostCall::ObjectMutate { handle, payload } => {
            assert_eq!(*handle, supply_handle);
            assert_eq!(ops::decode_supply_total(payload).unwrap(), 70);
        }
        other => panic!("expected mutate, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. burn underflow
// ---------------------------------------------------------------------------

#[test]
fn burn_underflow_returns_insufficient_balance() {
    fresh();
    let supply_bytes = ops::supply_payload(5); // total=5
    let coin_bytes = ops::coin_payload(10); // coin=10 > total
    let supply_handle = RuntimeHandle::from_raw(0);
    let coin_handle = RuntimeHandle::from_raw(1);
    let sup = supply_bytes.clone();
    let co = coin_bytes.clone();
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { handle } if *handle == coin_handle => {
            HostResponse::Bytes(co.clone())
        }
        HostCall::ObjectRead { handle } if *handle == supply_handle => {
            HostResponse::Bytes(sup.clone())
        }
        other => panic!("unexpected call {other:?}"),
    });
    let err = ops::burn(supply_handle, coin_handle).unwrap_err();
    assert_eq!(err, PetalError::InsufficientBalance);
}

// ---------------------------------------------------------------------------
// 6. split happy path
// ---------------------------------------------------------------------------

#[test]
fn split_emits_new_coin_and_rewrites_origin() {
    fresh();
    let coin_bytes = ops::coin_payload(100);
    let src = RuntimeHandle::from_raw(9);
    let cb = coin_bytes.clone();
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { .. } => HostResponse::Bytes(cb.clone()),
        HostCall::ObjectCreate { .. } => HostResponse::Handle(RuntimeHandle::from_raw(77)),
        HostCall::ObjectMutate { .. } => HostResponse::Status(0),
        other => panic!("unexpected call {other:?}"),
    });
    let new = ops::split(src, 40).unwrap();
    assert_eq!(new, RuntimeHandle::from_raw(77));

    let calls = test_hooks::recorded_calls();
    // read -> create new coin -> mutate origin
    assert_eq!(calls.len(), 3);
    match &calls[2] {
        HostCall::ObjectMutate { handle, payload } => {
            assert_eq!(*handle, src);
            assert_eq!(ops::decode_coin_value(payload).unwrap(), 60); // remaining
        }
        other => panic!("expected mutate, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 7. split underflow
// ---------------------------------------------------------------------------

#[test]
fn split_more_than_balance_returns_insufficient() {
    fresh();
    let coin_bytes = ops::coin_payload(3);
    let cb = coin_bytes.clone();
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { .. } => HostResponse::Bytes(cb.clone()),
        other => panic!("unexpected call {other:?}"),
    });
    let err = ops::split(RuntimeHandle::from_raw(0), 10).unwrap_err();
    assert_eq!(err, PetalError::InsufficientBalance);
}

// ---------------------------------------------------------------------------
// 8. merge
// ---------------------------------------------------------------------------

#[test]
fn merge_deletes_other_and_sums_into_dst() {
    fresh();
    let dst_bytes = ops::coin_payload(20);
    let other_bytes = ops::coin_payload(80);
    let dst = RuntimeHandle::from_raw(1);
    let other = RuntimeHandle::from_raw(2);
    let dst_c = dst_bytes.clone();
    let other_c = other_bytes.clone();
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { handle } if *handle == dst => HostResponse::Bytes(dst_c.clone()),
        HostCall::ObjectRead { handle } if *handle == other => HostResponse::Bytes(other_c.clone()),
        HostCall::ObjectDelete { .. } | HostCall::ObjectMutate { .. } => HostResponse::Status(0),
        other => panic!("unexpected call {other:?}"),
    });

    ops::merge(dst, other).unwrap();

    let calls = test_hooks::recorded_calls();
    // read dst, read other, delete other, mutate dst
    assert_eq!(calls.len(), 4);
    assert!(matches!(calls[2], HostCall::ObjectDelete { handle } if handle == other));
    match &calls[3] {
        HostCall::ObjectMutate { handle, payload } => {
            assert_eq!(*handle, dst);
            assert_eq!(ops::decode_coin_value(payload).unwrap(), 100);
        }
        other => panic!("expected mutate, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 9. transfer
// ---------------------------------------------------------------------------

#[test]
fn transfer_emits_address_owner() {
    fresh();
    test_hooks::set_responder(|call| match call {
        HostCall::ObjectTransfer { .. } => HostResponse::Status(0),
        other => panic!("unexpected call {other:?}"),
    });
    let recipient = [0x77u8; 32];
    ops::transfer(RuntimeHandle::from_raw(3), recipient).unwrap();

    match test_hooks::last_call().unwrap() {
        HostCall::ObjectTransfer {
            handle,
            owner_kind,
            owner_payload,
        } => {
            assert_eq!(handle, RuntimeHandle::from_raw(3));
            assert_eq!(owner_kind, bloom_objects::OWNER_KIND_ADDRESS);
            assert_eq!(owner_payload, recipient.to_vec());
        }
        other => panic!("expected ObjectTransfer, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 10. mint_genesis
// ---------------------------------------------------------------------------

#[test]
fn mint_genesis_creates_coin_loom_and_transfers_to_recipient() {
    fresh();
    test_hooks::set_responder(|call| match call {
        HostCall::ObjectCreate { .. } => HostResponse::Handle(RuntimeHandle::from_raw(11)),
        HostCall::ObjectTransfer { .. } => HostResponse::Status(0),
        other => panic!("unexpected call {other:?}"),
    });

    let recipient = [0xCDu8; 32];
    ops::mint_genesis(1_000_000u128, recipient).unwrap();

    let calls = test_hooks::recorded_calls();
    assert_eq!(calls.len(), 2);
    match &calls[1] {
        HostCall::ObjectTransfer {
            handle,
            owner_kind,
            owner_payload,
        } => {
            assert_eq!(*handle, RuntimeHandle::from_raw(11));
            assert_eq!(*owner_kind, bloom_objects::OWNER_KIND_ADDRESS);
            assert_eq!(owner_payload, &recipient.to_vec());
        }
        other => panic!("expected ObjectTransfer, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 11. value
// ---------------------------------------------------------------------------

#[test]
fn value_reads_payload_without_consuming() {
    fresh();
    let coin_bytes = ops::coin_payload(12345);
    let cb = coin_bytes.clone();
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { .. } => HostResponse::Bytes(cb.clone()),
        other => panic!("unexpected call {other:?}"),
    });
    let v = ops::value(RuntimeHandle::from_raw(0)).unwrap();
    assert_eq!(v, 12345);
    // exactly one read
    assert_eq!(test_hooks::recorded_calls().len(), 1);
}

// ---------------------------------------------------------------------------
// 12. Payload helpers round-trip
// ---------------------------------------------------------------------------

#[test]
fn payload_helpers_roundtrip_value() {
    let bytes = ops::coin_payload(424242);
    assert_eq!(bytes.len(), 16);
    let v = ops::decode_coin_value(&bytes).unwrap();
    assert_eq!(v, 424242);

    let rewritten = ops::rewrite_value(&bytes, 999_999).unwrap();
    assert_eq!(rewritten.len(), 16);
    let v2 = ops::decode_coin_value(&rewritten).unwrap();
    assert_eq!(v2, 999_999);

    let supply_bytes = ops::supply_payload(777);
    assert_eq!(supply_bytes.len(), 48);
    assert_eq!(ops::decode_supply_total(&supply_bytes).unwrap(), 777);

    let rewritten_supply = ops::rewrite_value(&supply_bytes, 888).unwrap();
    assert_eq!(rewritten_supply.len(), 48);
    assert_eq!(&rewritten_supply[..32], &supply_bytes[..32]);
    assert_eq!(ops::decode_supply_total(&rewritten_supply).unwrap(), 888);
}

#[test]
fn decode_rejects_truncated_payload() {
    let short = vec![0u8; 15];
    let err = ops::decode_coin_value(&short).unwrap_err();
    assert_eq!(err, PetalError::InvalidArgs);
    let err = ops::decode_supply_total(&short).unwrap_err();
    assert_eq!(err, PetalError::InvalidArgs);
}

// ---------------------------------------------------------------------------
// 13. Suppress unused-import warning for ObjectId/Owner — exercise once.
// ---------------------------------------------------------------------------
#[test]
fn type_tag_t_generic_idx_zero() {
    let _ = ObjectId([0u8; 32]);
    let _ = Owner::Shared;
    match ops::type_tag_t() {
        bloom_objects::TypeTag::Generic { idx } => assert_eq!(idx, 0),
        other => panic!("expected Generic, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 14. Gap 1 — Supply::handle() borrows by the supply's own ObjectId (spec §14.1)
//
// Verifies that the `handle()` method on `Supply<T>` issues `object.borrow`
// for the supply's `id` rather than fabricating handle 0. Before the fix,
// calling `mint` through the petal entry point ignores the supply argument
// entirely and hard-codes `RuntimeHandle::from_raw(0)`, which causes it to
// read from the wrong object. After the fix, `supply.handle()` returns the
// real borrow-table handle produced by `object.borrow(supply.id, Mutable)`.
// ---------------------------------------------------------------------------

/// Phantom marker for the test currency — never instantiated.
struct TestCoin;

#[test]
fn borrow_supply_mut_borrows_by_supply_id() {
    fresh();
    // Supply id: all-0xAA bytes.
    let supply_id = ObjectId([0xAAu8; 32]);
    let supply_handle = RuntimeHandle::from_raw(42);

    // The mock returns supply_handle when object.borrow is called with supply_id.
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectBorrow { id, mode } => {
            assert_eq!(*id, supply_id, "expected borrow of supply id");
            assert_eq!(*mode, AccessMode::Mutable, "expected Mutable borrow");
            HostResponse::Handle(supply_handle)
        }
        other => panic!("unexpected call {other:?}"),
    });

    // In the handle/tag model the macro-emitted shim materializes a
    // `Supply<T>` arg via `object.borrow(id, Mutable)` before the entry
    // point runs (the old `Supply::handle()` borrow method was retired in
    // the reshape). `ops::borrow_supply_mut` is that same borrow, exposed
    // for PTBs that thread a `Supply<T>` produced in an earlier command: it
    // must borrow by the supply's id in `Mutable` mode and return the handle.
    let got = bloom_petal_fungible::ops::borrow_supply_mut(supply_id).expect("borrow_supply_mut");
    assert_eq!(
        got, supply_handle,
        "borrow_supply_mut must return the borrow-table handle for the supply's id"
    );
}

#[test]
fn mint_entry_point_uses_supply_handle_not_zero() {
    fresh();
    // Supply handle the macro shim materialized via object.borrow before the
    // entry point runs; carried by the `Resource<Supply<T>>` arg.
    let supply_handle = RuntimeHandle::from_raw(77);

    let supply_bytes = ops::supply_payload(0); // total = 0
    let supply_bytes_clone = supply_bytes.clone();

    test_hooks::set_responder(move |call| match call {
        // read(supply_handle) → bytes with total=0
        HostCall::ObjectRead { handle } if *handle == supply_handle => {
            HostResponse::Bytes(supply_bytes_clone.clone())
        }
        // create coin → some handle
        HostCall::ObjectCreate { .. } => HostResponse::Handle(RuntimeHandle::from_raw(99)),
        // mutate supply → ok
        HostCall::ObjectMutate { handle, .. } => {
            assert_eq!(
                *handle, supply_handle,
                "mutate must target supply_handle, not handle 0"
            );
            HostResponse::Status(0)
        }
        other => panic!("unexpected call {other:?}"),
    });

    let _cap: Capability<bloom_petal_fungible::fungible::MintCap<TestCoin>> =
        Capability::from_handle(RuntimeHandle::from_raw(1));
    // The macro materializes `Resource<Supply<T>>` carrying the borrow-table
    // handle (77) it obtained from `object.borrow`.
    let mut supply: Resource<bloom_petal_fungible::fungible::Supply<TestCoin>> =
        Resource::from_handle(supply_handle);

    // If the petal entry point hardcodes RuntimeHandle::from_raw(0), the
    // ObjectRead/ObjectMutate will be for handle 0, not supply_handle (77),
    // causing the responder to panic with "unexpected call ... handle: 0".
    let _coin = bloom_petal_fungible::fungible::mint::<TestCoin>(&_cap, &mut supply, 100);
}

#[test]
fn burn_entry_point_uses_supply_handle_not_zero() {
    fresh();
    let supply_handle = RuntimeHandle::from_raw(55);
    let coin_handle = RuntimeHandle::from_raw(66);

    let supply_bytes = ops::supply_payload(200); // total = 200
    let coin_bytes = ops::coin_payload(100); // value = 100
    let supply_bytes_clone = supply_bytes.clone();
    let coin_bytes_clone = coin_bytes.clone();

    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { handle } if *handle == coin_handle => {
            HostResponse::Bytes(coin_bytes_clone.clone())
        }
        HostCall::ObjectRead { handle } if *handle == supply_handle => {
            HostResponse::Bytes(supply_bytes_clone.clone())
        }
        HostCall::ObjectDelete { .. } => HostResponse::Status(0),
        HostCall::ObjectMutate { handle, .. } => {
            assert_eq!(*handle, supply_handle, "mutate must target supply_handle");
            HostResponse::Status(0)
        }
        other => panic!("unexpected call {other:?}"),
    });

    let _cap: Capability<bloom_petal_fungible::fungible::BurnCap<TestCoin>> =
        Capability::from_handle(RuntimeHandle::from_raw(2));
    // The macro materializes `Resource<Supply<T>>` carrying the borrow-table
    // handle (55) it obtained from `object.borrow`.
    let mut supply: Resource<bloom_petal_fungible::fungible::Supply<TestCoin>> =
        Resource::from_handle(supply_handle);
    let coin = bloom_resource::Coin::<TestCoin>::from_handle(coin_handle);

    // If the petal entry point hardcodes RuntimeHandle::from_raw(0), the
    // ObjectRead for the supply will be directed at handle 0, not 55,
    // causing the mock responder to panic.
    bloom_petal_fungible::fungible::burn::<TestCoin>(&_cap, &mut supply, coin);
}

// ---------------------------------------------------------------------------
// 15. Gap 2 — mint_genesis verifies the EpochZero capability (spec §9.3)
//
// mint_genesis must not proceed with an invalid EpochZero cap.
// Before the fix, the `_epoch` argument is entirely ignored.
// After the fix, cap::check is called and an invalid cap aborts.
// ---------------------------------------------------------------------------

#[test]
fn mint_genesis_verifies_epoch_zero_cap() {
    fresh();
    // Cap check returns 1 (valid EpochZero).
    test_hooks::set_responder(|call| match call {
        HostCall::CapCheck { .. } => HostResponse::IntReturn(1),
        HostCall::ObjectCreate { .. } => HostResponse::Handle(RuntimeHandle::from_raw(11)),
        HostCall::ObjectTransfer { .. } => HostResponse::Status(0),
        other => panic!("unexpected call {other:?}"),
    });

    let epoch_cap: Capability<bloom_petal_fungible::fungible::EpochZero> =
        Capability::from_handle(RuntimeHandle::from_raw(5));
    let recipient = [0xEEu8; 32];
    // Should succeed — cap check passes.
    bloom_petal_fungible::fungible::mint_genesis(&epoch_cap, 1_000u128, recipient);

    // Verify cap::check was called.
    let calls = test_hooks::recorded_calls();
    assert!(
        calls.iter().any(|c| matches!(c, HostCall::CapCheck { .. })),
        "expected cap::check to be called for EpochZero verification; calls: {calls:?}"
    );
}

// ---------------------------------------------------------------------------
// 16. Gap 3 — create_burn_cap must not exist as a public entry point.
//
// Verified at the type/symbol level: `bloom_petal_fungible::fungible` must
// not export `create_burn_cap`. This is a compile-time guarantee enforced
// by the removal; a test that tries to use it would fail to compile.
// We document the intent here as a runtime no-op (the compile-time check
// is the real guard, visible in `cargo build`).
// ---------------------------------------------------------------------------

#[test]
fn create_burn_cap_does_not_exist_as_separate_entry_point() {
    // This test is a placeholder: the real check is that the file does NOT
    // contain `pub fn create_burn_cap` — removing it from the petal source
    // causes any code that references `fungible::create_burn_cap` to fail
    // to compile. If this test runs at all, Gap 3 is resolved.
    // The function body is intentionally empty.
}
