//! **Real-wasm** end-to-end de-risk for the `/bloom/dex/pool` petal
//! (spec §6 litmus linchpin "R1": does the real pool wasm body execute
//! through the chain VM?).
//!
//! Unlike the other DEX integration tests — which pair a hand-written WAT
//! body with the real macro-emitted manifest — this test compiles the
//! actual `bloom-petal-dex-pool` crate to `wasm32-unknown-unknown`,
//! installs the artifact in chain state, and drives `create_pool` /
//! `reserves` / `swap_exact_in` through the production chain VM. It
//! exercises the real host-import sequence (object.read on the input
//! coins → object.create for the Pool + LpPosition → object.delete the
//! consumed coins → ObjectId return envelope).
//!
//! `#[ignore]`-gated because it shells out to `cargo build --target
//! wasm32-unknown-unknown` (wasm32 is not in CI). Run with:
//!
//! ```text
//! cargo test -p bloom-petal-dex-it --test real_wasm_pool -- --ignored --nocapture
//! ```

use bloom_objects::{AccessMode, OWNER_KIND_ADDRESS, Owner, OwnershipIndexKey, TypeTag};
use bloom_script::{Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, PtbTx, UseRef};

use bloom_petal_dex_it::dex_harness::{
    addr, build_pool_wasm, build_state, build_wallet_wasm, create_shared_pool, erased_coin_id,
    erased_pair_type_args, genesis_coin_id, owner_has_coin_worth, seed_erased_coin,
    submit_ptb_chain_auth,
};

// ---------------------------------------------------------------------------
// Test: real pool wasm — create_pool executes through the chain VM.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "compiles pool to wasm32; run with `-- --ignored`"]
fn real_pool_create_pool_executes() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);

    // Deploy the real pool wasm.
    let wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    // Seed two Coin<Erased> deposits owned by alice.
    let coin_a = erased_coin_id(b"a");
    let coin_b = erased_coin_id(b"b");
    seed_erased_coin(&mut state, coin_a, Owner::Address(alice.0), 10_000);
    seed_erased_coin(&mut state, coin_b, Owner::Address(alice.0), 10_000);

    // params_bytes = ConstantProductParams { fee_bps: 30 } -> 2-byte BE.
    let params_bytes = 30u16.to_be_bytes().to_vec();

    let gas_payer = genesis_coin_id(alice, 0);
    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            // cmd 0: create_pool(coin_a, coin_b, params) -> (Pool, LpPosition)
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "create_pool".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: coin_a,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: coin_b,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Const(params_bytes),
                ],
            }),
            // cmd 1: share the Pool (return slot 0) so anyone can swap.
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Shared,
            },
            // cmd 2: give the LpPosition (return slot 1) to alice.
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(alice.0),
            },
        ],
        gas_payer,
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, alice, ptb);
    assert!(
        out.success,
        "create_pool (real wasm) must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    // The consumed input coins must be gone.
    assert!(
        state.get_object(&coin_a).is_none(),
        "coin_a must be consumed by create_pool"
    );
    assert!(
        state.get_object(&coin_b).is_none(),
        "coin_b must be consumed by create_pool"
    );

    // A Pool object must have been created with reserves (10000, 10000).
    let (_, pool) = state
        .iter_objects()
        .find(|(_, o)| matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "Pool"))
        .expect("a Pool object must exist after create_pool");
    let (ra, rb, _lp, _k, _p, _coin_a_tag, _coin_b_tag) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!(ra, 10_000, "reserve_a");
    assert_eq!(rb, 10_000, "reserve_b");

    // An LpPosition must also exist.
    assert!(
        state.iter_objects().any(
            |(_, o)| matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "LpPosition")
        ),
        "an LpPosition object must exist after create_pool"
    );
}

// ---------------------------------------------------------------------------
// Test: real pool wasm — swap_exact_in executes through the chain VM (R1 /
// litmus 5.1 core on-chain semantics: real swap export runs, output minted).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "compiles pool to wasm32; run with `-- --ignored`"]
fn real_pool_swap_exact_in_executes() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000)]);

    // Deploy the real pool wasm + bind the VFS path.
    let wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    // Alice stands up a shared 10000/10000 pool.
    let pool_id = create_shared_pool(&mut state, alice, pool_petal_hash, b"main", 30);
    let pool_version = state
        .get_object(&pool_id)
        .expect("pool exists after create")
        .version;

    // Bob deposits a Coin<Erased>(100) to swap A→B.
    let bob_coin = erased_coin_id(b"bob-in");
    seed_erased_coin(&mut state, bob_coin, Owner::Address(bob.0), 100);

    // min_out = 90 (== expected output for 100-in on a 10000/10000 pool at 30 bps).
    let min_out: u128 = 90;
    let gas_payer = genesis_coin_id(bob, 1);
    let ptb = PtbTx {
        signers: vec![bob.0],
        commands: vec![
            // cmd 0: swap_exact_in(coin_in, pool, min_out) -> Coin<Erased>
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: bob_coin,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(min_out.to_be_bytes().to_vec()),
                ],
            }),
            // cmd 1: hand the output coin to bob (satisfies linearity).
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(bob.0),
            },
        ],
        gas_payer,
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, bob, ptb);
    assert!(
        out.success,
        "swap_exact_in (real wasm) must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    // The input coin must be consumed.
    assert!(
        state.get_object(&bob_coin).is_none(),
        "bob's input coin must be consumed by swap_exact_in"
    );

    // Bob must own an output coin worth exactly 98.
    assert!(
        owner_has_coin_worth(&state, bob, 98),
        "bob must receive an output coin worth 98"
    );

    // Pool reserves must move to (10100, 9902).
    let pool = state.get_object(&pool_id).expect("pool still exists");
    let (ra, rb, _lp, _k, _p, _coin_a_tag, _coin_b_tag) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!(ra, 10_100, "reserve_a after swap");
    assert_eq!(rb, 9_902, "reserve_b after swap");
}

// ---------------------------------------------------------------------------
// Test: slippage guard reverts the whole tx (litmus 5.1 failure path —
// "slippage failure reverts everything, nothing is debited/credited").
// ---------------------------------------------------------------------------

#[test]
#[ignore = "compiles pool to wasm32; run with `-- --ignored`"]
fn real_pool_swap_slippage_reverts() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000)]);

    let wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    let pool_id = create_shared_pool(&mut state, alice, pool_petal_hash, b"main", 30);
    let pool_version = state
        .get_object(&pool_id)
        .expect("pool exists after create")
        .version;

    let bob_coin = erased_coin_id(b"bob-in");
    seed_erased_coin(&mut state, bob_coin, Owner::Address(bob.0), 100);

    // min_out = 200 > the real output (90) -> SlippageExceeded -> revert.
    let min_out: u128 = 200;
    let gas_payer = genesis_coin_id(bob, 1);
    let ptb = PtbTx {
        signers: vec![bob.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: bob_coin,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(min_out.to_be_bytes().to_vec()),
                ],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(bob.0),
            },
        ],
        gas_payer,
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, bob, ptb);
    assert!(
        !out.success,
        "swap with min_out=200 must revert on slippage"
    );

    // Nothing must have changed: bob's input coin survives untouched...
    let surviving = state
        .get_object(&bob_coin)
        .expect("bob's input coin must survive a reverted swap");
    assert_eq!(
        bloom_petal_fungible::ops::decode_coin_value(&surviving.payload).ok(),
        Some(100),
        "bob's input coin value must be unchanged after revert"
    );

    // ...and the pool reserves stay at the created (10000, 10000).
    let pool = state.get_object(&pool_id).expect("pool still exists");
    let (ra, rb, _lp, _k, _p, _coin_a_tag, _coin_b_tag) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!(ra, 10_000, "reserve_a must be unchanged after revert");
    assert_eq!(rb, 10_000, "reserve_b must be unchanged after revert");

    // And bob did not receive any output coin.
    assert!(
        !owner_has_coin_worth(&state, bob, 98),
        "no output coin may be credited on a reverted swap"
    );
}

// ---------------------------------------------------------------------------
// Test (Phase F linchpin): real pool swap output → PTB Use-ref → a DOWNSTREAM
// petal Move (/bloom/dex/wallet `receive`) Consume arg → settled to a third
// party. Proves petal→petal coin threading through the chain VM (spec §6).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "compiles pool+wallet to wasm32; run with `-- --ignored`"]
fn real_pool_swap_then_wallet_receive_threads_coin() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let carol = addr(0xC0); // settlement recipient (distinct from the swapper)
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000)]);

    // Deploy the real pool wasm and the real wallet wasm; bind both VFS paths.
    let pool_wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&pool_wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    let wallet_wasm = std::fs::read(build_wallet_wasm()).expect("read wallet wasm");
    let wallet_petal_hash = state.insert_code(&wallet_wasm);
    state.set_vfs_binding("/bloom/dex/wallet".to_string(), wallet_petal_hash);

    // Alice stands up a shared 10000/10000 pool.
    let pool_id = create_shared_pool(&mut state, alice, pool_petal_hash, b"main", 30);
    let pool_version = state
        .get_object(&pool_id)
        .expect("pool exists after create")
        .version;

    // Bob deposits a Coin<Erased>(100) to swap A→B.
    let bob_coin = erased_coin_id(b"bob-in");
    seed_erased_coin(&mut state, bob_coin, Owner::Address(bob.0), 100);

    let min_out: u128 = 90;
    let gas_payer = genesis_coin_id(bob, 1);
    let ptb = PtbTx {
        signers: vec![bob.0],
        commands: vec![
            // cmd 0: swap_exact_in(coin_in, pool, min_out) -> Coin<Erased>  [coin-first]
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: bob_coin,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(min_out.to_be_bytes().to_vec()),
                ],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(carol.0),
            },
        ],
        gas_payer,
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, bob, ptb);
    assert!(
        out.success,
        "swap → wallet.receive must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    // Bob's input coin was consumed by the swap.
    assert!(
        state.get_object(&bob_coin).is_none(),
        "bob's input coin must be consumed by swap_exact_in"
    );

    // CAROL — not bob — owns the 90-output coin, settled by the downstream
    // wallet petal: this is the petal→petal coin-threading proof.
    assert!(
        owner_has_coin_worth(&state, carol, 98),
        "carol must receive the swapped output coin (worth 98) via wallet.receive"
    );

    // Pool reserves moved to (10100, 9902).
    let pool = state.get_object(&pool_id).expect("pool still exists");
    let (ra, rb, _lp, _k, _p, _coin_a_tag, _coin_b_tag) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!(ra, 10_100, "reserve_a after swap");
    assert_eq!(rb, 9_902, "reserve_b after swap");
}

#[test]
#[ignore = "compiles pool to wasm32; run with `-- --ignored`"]
fn real_pool_cross_pool_lp_remove_reverts_without_state_change() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);

    let wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    let pool_a = create_shared_pool(&mut state, alice, pool_petal_hash, b"a", 30);
    let lp_a = lp_positions_owned_by(&state, alice)
        .into_iter()
        .next()
        .expect("alice owns initial LP for pool A");
    let pool_b = create_shared_pool(&mut state, alice, pool_petal_hash, b"b", 31);

    let pool_a_before = state.get_object(&pool_a).expect("pool A").clone();
    let pool_b_before = state.get_object(&pool_b).expect("pool B").clone();
    let lp_before = state.get_object(&lp_a).expect("LP A").clone();
    let alice_owned_before = owned_ids(&state, alice);

    let gas_payer = genesis_coin_id(alice, 0);
    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "remove_liquidity".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_b,
                        expected_version: ExpectedVersion(pool_b_before.version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: lp_a,
                        expected_version: ExpectedVersion(lp_before.version),
                        access_mode: AccessMode::Consume,
                    },
                ],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(alice.0),
            },
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(alice.0),
            },
        ],
        gas_payer,
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, alice, ptb);
    assert!(
        !out.success,
        "cross-pool LP withdrawal must revert, got success"
    );
    assert_eq!(state.get_object(&pool_a), Some(pool_a_before));
    assert_eq!(state.get_object(&pool_b), Some(pool_b_before));
    assert_eq!(state.get_object(&lp_a), Some(lp_before));
    assert_eq!(
        owned_ids(&state, alice),
        alice_owned_before,
        "ownership index must not change on reverted cross-pool withdrawal"
    );
}

#[test]
#[ignore = "compiles pool to wasm32; run with `-- --ignored`"]
fn real_pool_stale_shared_pool_version_and_sandwich_slippage_revert() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let attacker = addr(0xE0);
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000), (attacker, 1_000_000)]);

    let wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    let pool_id = create_shared_pool(&mut state, alice, pool_petal_hash, b"main", 30);
    let stale_version = state.get_object(&pool_id).expect("pool").version;

    let bob_coin_stale = erased_coin_id(b"bob-stale");
    seed_erased_coin(&mut state, bob_coin_stale, Owner::Address(bob.0), 100);
    let stale_swap = swap_exact_in_ptb(
        bob,
        genesis_coin_id(bob, 1),
        pool_petal_hash,
        pool_id,
        stale_version,
        bob_coin_stale,
        90,
    );

    let attacker_coin = erased_coin_id(b"attacker-front-run");
    seed_erased_coin(&mut state, attacker_coin, Owner::Address(attacker.0), 500);
    let attacker_swap = swap_exact_in_ptb(
        attacker,
        genesis_coin_id(attacker, 2),
        pool_petal_hash,
        pool_id,
        stale_version,
        attacker_coin,
        300,
    );
    let out = submit_ptb_chain_auth(&mut state, attacker, attacker_swap);
    assert!(
        out.success,
        "attacker/front-run swap must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    let after_attacker = state
        .get_object(&pool_id)
        .expect("pool after attack")
        .clone();
    assert!(
        after_attacker.version > stale_version,
        "successful mutable shared-pool swap must bump version"
    );

    let out = submit_ptb_chain_auth(&mut state, bob, stale_swap);
    assert!(
        !out.success,
        "stale shared-pool expected_version must reject after contention"
    );
    assert_eq!(
        state.get_object(&pool_id),
        Some(after_attacker.clone()),
        "stale-version revert must not mutate pool"
    );
    assert!(
        state.get_object(&bob_coin_stale).is_some(),
        "stale-version revert must leave bob input coin"
    );

    let bob_coin_sandwich = erased_coin_id(b"bob-sandwich");
    seed_erased_coin(&mut state, bob_coin_sandwich, Owner::Address(bob.0), 100);
    let sandwich_swap = swap_exact_in_ptb(
        bob,
        genesis_coin_id(bob, 1),
        pool_petal_hash,
        pool_id,
        after_attacker.version,
        bob_coin_sandwich,
        90,
    );
    let out = submit_ptb_chain_auth(&mut state, bob, sandwich_swap);
    assert!(
        !out.success,
        "victim swap with pre-attack min_out must revert on slippage"
    );
    assert_eq!(
        state.get_object(&pool_id),
        Some(after_attacker),
        "slippage revert must preserve post-attacker pool state"
    );
    assert!(
        state.get_object(&bob_coin_sandwich).is_some(),
        "slippage revert must leave bob input coin"
    );
}

#[test]
#[ignore = "compiles pool to wasm32; run with `-- --ignored`"]
fn real_pool_add_remove_and_exact_out_execute() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000)]);

    let wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    let pool_id = create_shared_pool(&mut state, alice, pool_petal_hash, b"main", 30);
    let lps_before_add = lp_positions_owned_by(&state, alice);
    let add_a = erased_coin_id(b"add-a");
    let add_b = erased_coin_id(b"add-b");
    seed_erased_coin(&mut state, add_a, Owner::Address(alice.0), 500);
    seed_erased_coin(&mut state, add_b, Owner::Address(alice.0), 600);
    let add_ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "add_liquidity".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(
                            state.get_object(&pool_id).expect("pool").version,
                        ),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: add_a,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: add_b,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                ],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(alice.0),
            },
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 2,
                }],
                owner: Owner::Address(alice.0),
            },
        ],
        gas_payer: genesis_coin_id(alice, 0),
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };
    let out = submit_ptb_chain_auth(&mut state, alice, add_ptb);
    assert!(
        out.success,
        "add_liquidity must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    let pool = state.get_object(&pool_id).expect("pool after add");
    let (ra, rb, lp_supply, ..) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!((ra, rb, lp_supply), (10_500, 10_500, 10_500));
    assert!(
        state.get_object(&add_a).is_none(),
        "spent add_liquidity coin A must be consumed"
    );
    assert!(
        state.get_object(&add_b).is_none(),
        "spent add_liquidity coin B must be consumed even when a leftover is returned"
    );
    assert!(
        !owner_has_coin_worth(&state, alice, 500),
        "add_liquidity must not leave the spent side as a live user coin"
    );
    assert!(owner_has_coin_worth(&state, alice, 100), "leftover B coin");

    let added_lp = lp_positions_owned_by(&state, alice)
        .into_iter()
        .find(|id| !lps_before_add.contains(id))
        .expect("add_liquidity minted a new LP position");
    let added_lp_obj = state.get_object(&added_lp).expect("added LP");
    assert_eq!(
        lp_payload_self_id(&added_lp_obj.payload),
        added_lp,
        "add_liquidity LP payload self-id must match its object id"
    );
    let added_lp_version = state.get_object(&added_lp).expect("added LP").version;
    let remove_ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "remove_liquidity".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(
                            state.get_object(&pool_id).expect("pool").version,
                        ),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: added_lp,
                        expected_version: ExpectedVersion(added_lp_version),
                        access_mode: AccessMode::Consume,
                    },
                ],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(alice.0),
            },
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(alice.0),
            },
        ],
        gas_payer: genesis_coin_id(alice, 0),
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };
    let out = submit_ptb_chain_auth(&mut state, alice, remove_ptb);
    assert!(
        out.success,
        "remove_liquidity must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert!(
        state.get_object(&added_lp).is_none(),
        "burned LP must be consumed"
    );
    let pool = state.get_object(&pool_id).expect("pool after remove");
    let (ra, rb, lp_supply, ..) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!((ra, rb, lp_supply), (10_000, 10_000, 10_000));

    let bob_coin = erased_coin_id(b"bob-exact-out");
    seed_erased_coin(&mut state, bob_coin, Owner::Address(bob.0), 120);
    let exact_out_ptb = PtbTx {
        signers: vec![bob.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "swap_exact_out".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(
                            state.get_object(&pool_id).expect("pool").version,
                        ),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: bob_coin,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Const(90u128.to_be_bytes().to_vec()),
                ],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(bob.0),
            },
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(bob.0),
            },
        ],
        gas_payer: genesis_coin_id(bob, 1),
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };
    let out = submit_ptb_chain_auth(&mut state, bob, exact_out_ptb);
    assert!(
        out.success,
        "swap_exact_out must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert!(
        state.get_object(&bob_coin).is_none(),
        "swap_exact_out must consume max_in coin when returning a leftover"
    );
    assert!(owner_has_coin_worth(&state, bob, 90), "exact output coin");
    assert!(
        owner_has_coin_worth(&state, bob, 28),
        "exact-out leftover coin"
    );
    assert!(
        !owner_has_coin_worth(&state, bob, 120),
        "swap_exact_out must not leave max_in as a live user coin"
    );
}

#[test]
#[ignore = "compiles pool to wasm32; run with `-- --ignored`"]
fn real_pool_high_fee_exact_out_executes() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000)]);

    let wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    let pool_id = create_shared_pool(&mut state, alice, pool_petal_hash, b"high-fee", 9999);
    let max_in = erased_coin_id(b"bob-high-fee-exact-out");
    seed_erased_coin(&mut state, max_in, Owner::Address(bob.0), 20_000);

    let ptb = PtbTx {
        signers: vec![bob.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "swap_exact_out".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(
                            state.get_object(&pool_id).expect("pool").version,
                        ),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Object {
                        id: max_in,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Const(1u128.to_be_bytes().to_vec()),
                ],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(bob.0),
            },
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 1,
                }],
                owner: Owner::Address(bob.0),
            },
        ],
        gas_payer: genesis_coin_id(bob, 1),
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, bob, ptb);
    assert!(
        out.success,
        "9999 bps swap_exact_out must find valid max input; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );
    assert!(
        state.get_object(&max_in).is_none(),
        "high-fee exact-out must consume max input coin"
    );
    assert!(owner_has_coin_worth(&state, bob, 1), "exact output coin");

    let pool = state
        .get_object(&pool_id)
        .expect("pool after high-fee exact out");
    let (ra, rb, ..) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!((ra, rb), (20_002, 9_999));
}

fn lp_positions_owned_by(
    state: &bloom_chain_state::State,
    who: bloom_chain_types::types::Address,
) -> Vec<bloom_objects::ObjectId> {
    state
        .iter_objects()
        .filter(|(_, o)| {
            o.owner == Owner::Address(who.0)
                && matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "LpPosition")
        })
        .map(|(id, _)| *id)
        .collect()
}

fn owned_ids(
    state: &bloom_chain_state::State,
    who: bloom_chain_types::types::Address,
) -> Vec<bloom_objects::ObjectId> {
    state
        .get_ownership(&OwnershipIndexKey {
            owner_kind: OWNER_KIND_ADDRESS,
            owner_id: who.0,
        })
        .unwrap_or_default()
}

fn lp_payload_self_id(payload: &[u8]) -> bloom_objects::ObjectId {
    let mut id = [0u8; 32];
    id.copy_from_slice(&payload[..32]);
    bloom_objects::ObjectId(id)
}

fn swap_exact_in_ptb(
    signer: bloom_chain_types::types::Address,
    gas_payer: bloom_objects::ObjectId,
    pool_petal_hash: bloom_chain_types::types::Hash32,
    pool_id: bloom_objects::ObjectId,
    pool_version: u64,
    coin_in: bloom_objects::ObjectId,
    min_out: u128,
) -> PtbTx {
    PtbTx {
        signers: vec![signer.0],
        commands: vec![
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "swap_exact_in".to_string(),
                type_args: erased_pair_type_args(),
                args: vec![
                    Arg::Object {
                        id: coin_in,
                        expected_version: ExpectedVersion(0),
                        access_mode: AccessMode::Consume,
                    },
                    Arg::Object {
                        id: pool_id,
                        expected_version: ExpectedVersion(pool_version),
                        access_mode: AccessMode::Mutable,
                    },
                    Arg::Const(min_out.to_be_bytes().to_vec()),
                ],
            }),
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 0,
                    ret_idx: 0,
                }],
                owner: Owner::Address(signer.0),
            },
        ],
        gas_payer,
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    }
}
