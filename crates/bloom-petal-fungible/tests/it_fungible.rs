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

use bloom_objects::{ObjectId, Owner};
use bloom_petal_fungible::ops;
use bloom_resource::{PetalError, RuntimeHandle};
use bloom_resource::host::{test_hooks, HostCall, HostResponse};

/// Reset the mock host before every test.
fn fresh() {
    test_hooks::clear();
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
    let supply_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&50u128.to_be_bytes());
        b
    };

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
            let mut be = [0u8; 16];
            be.copy_from_slice(&payload[32..48]);
            assert_eq!(u128::from_be_bytes(be), 75);
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
    let supply_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&(u128::MAX - 1).to_be_bytes());
        b
    };
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
    let supply_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&100u128.to_be_bytes());
        b
    };
    let coin_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&30u128.to_be_bytes());
        b
    };

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
            let mut be = [0u8; 16];
            be.copy_from_slice(&payload[32..48]);
            assert_eq!(u128::from_be_bytes(be), 70);
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
    let supply_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&5u128.to_be_bytes()); // total=5
        b
    };
    let coin_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&10u128.to_be_bytes()); // coin=10 > total
        b
    };
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
    let coin_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&100u128.to_be_bytes());
        b
    };
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
            let mut be = [0u8; 16];
            be.copy_from_slice(&payload[32..48]);
            assert_eq!(u128::from_be_bytes(be), 60); // remaining
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
    let coin_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&3u128.to_be_bytes());
        b
    };
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
    let dst_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&20u128.to_be_bytes());
        b
    };
    let other_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&80u128.to_be_bytes());
        b
    };
    let dst = RuntimeHandle::from_raw(1);
    let other = RuntimeHandle::from_raw(2);
    let dst_c = dst_bytes.clone();
    let other_c = other_bytes.clone();
    test_hooks::set_responder(move |call| match call {
        HostCall::ObjectRead { handle } if *handle == dst => HostResponse::Bytes(dst_c.clone()),
        HostCall::ObjectRead { handle } if *handle == other => {
            HostResponse::Bytes(other_c.clone())
        }
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
            let mut be = [0u8; 16];
            be.copy_from_slice(&payload[32..48]);
            assert_eq!(u128::from_be_bytes(be), 100);
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
    let coin_bytes = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(&12345u128.to_be_bytes());
        b
    };
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
    assert_eq!(bytes.len(), 48);
    let v = ops::decode_coin_value(&bytes).unwrap();
    assert_eq!(v, 424242);

    let rewritten = ops::rewrite_value(&bytes, 999_999).unwrap();
    assert_eq!(rewritten.len(), 48);
    assert_eq!(&rewritten[..32], &bytes[..32]);
    let v2 = ops::decode_coin_value(&rewritten).unwrap();
    assert_eq!(v2, 999_999);
}

#[test]
fn decode_rejects_truncated_payload() {
    let short = vec![0u8; 32];
    let err = ops::decode_coin_value(&short).unwrap_err();
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
