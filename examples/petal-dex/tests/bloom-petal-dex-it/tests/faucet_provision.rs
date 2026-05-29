//! **Real-wasm** de-risk for the `/bloom/petals/dex/faucet` petal — the live-chain
//! `Coin<Erased>` provisioning linchpin (see
//! `project-live-docker-dex-design`).
//!
//! On a live chain, genesis emits only `Coin<LOOM>` and the PTB validator does
//! not treat `Erased` as a wildcard, so there is no coin to feed the pool's
//! `create_pool` / `swap_exact_in` (both declare `Coin<Erased>`). The faucet's
//! `mint(value) -> Coin<Erased>` closes that gap: it `object.create`s a fresh
//! type-erased coin returned as a borrow-table row (PTB Use-ref), spliced
//! atomically into the next command — the on-chain analog of the in-process
//! `seed_erased_coin` helper.
//!
//! These tests prove, through the production chain VM, that a faucet-minted
//! coin threads into both `create_pool` and `swap_exact_in` exactly like a
//! seeded coin — so the live 4-validator docker acceptance test can provision
//! its pool + swap inputs entirely on-chain.
//!
//! `#[ignore]`-gated (shells out to `cargo build --target
//! wasm32-unknown-unknown`). Run with:
//!
//! ```text
//! cargo test -p bloom-petal-dex-it --test faucet_provision -- --ignored --nocapture
//! ```

use bloom_objects::{AccessMode, Owner, TypeTag};
use bloom_script::{Arg, Command, ExpectedVersion, MoveCmd, PetalRef, PqSignature, PtbTx, UseRef};

use bloom_petal_dex_it::dex_harness::{
    addr, build_faucet_wasm_for_admin, build_pool_wasm, build_state, build_wallet_wasm,
    create_shared_pool, erased_type_tag, faucet_admin_cap_id, genesis_coin_id,
    owner_has_coin_worth, seed_faucet_admin_cap, submit_ptb_chain_auth,
};

/// Deploy the faucet wasm into `state` and bind its VFS path; return its hash.
fn deploy_faucet(
    state: &mut bloom_chain_state::State,
    admin: bloom_chain_types::types::Address,
) -> bloom_chain_types::types::Hash32 {
    let wasm =
        std::fs::read(build_faucet_wasm_for_admin(hex::encode(admin.0))).expect("read faucet wasm");
    let hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/petals/dex/faucet".to_string(), hash);
    hash
}

/// A faucet `mint(admin, value)` Move command.
fn mint_cmd(
    faucet_hash: bloom_chain_types::types::Hash32,
    admin_cap: bloom_objects::ObjectId,
    value: u128,
) -> Command {
    Command::Move(MoveCmd {
        petal: PetalRef {
            path: "/bloom/petals/dex/faucet".to_string(),
            hash: Some(faucet_hash),
        },
        function: "mint".to_string(),
        type_args: vec![],
        args: vec![
            Arg::Signer(0),
            Arg::Object {
                id: admin_cap,
                expected_version: ExpectedVersion(0),
                access_mode: AccessMode::ReadOnly,
            },
            Arg::Const(value.to_be_bytes().to_vec()),
        ],
    })
}

fn ungated_mint_cmd(faucet_hash: bloom_chain_types::types::Hash32, value: u128) -> Command {
    Command::Move(MoveCmd {
        petal: PetalRef {
            path: "/bloom/petals/dex/faucet".to_string(),
            hash: Some(faucet_hash),
        },
        function: "mint".to_string(),
        type_args: vec![],
        args: vec![Arg::Const(value.to_be_bytes().to_vec())],
    })
}

// ---------------------------------------------------------------------------
// Test: faucet.mint ×2 → create_pool, all atomic (no pre-seeded coins).
// ---------------------------------------------------------------------------

#[test]
#[ignore = "compiles faucet+pool to wasm32; run with `-- --ignored`"]
fn faucet_mint_without_admin_cap_reverts() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);

    let faucet_hash = deploy_faucet(&mut state, alice);
    let gas_payer = genesis_coin_id(alice, 0);

    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![ungated_mint_cmd(faucet_hash, 1000)],
        gas_payer,
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, alice, ptb);
    assert!(
        !out.success,
        "faucet.mint without FaucetAdmin capability must revert"
    );
}

#[test]
#[ignore = "compiles faucet to wasm32; run with `-- --ignored`"]
fn faucet_mint_with_non_admin_signer_reverts() {
    let alice = addr(0xA1);
    let bob = addr(0xB0);
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000)]);

    let faucet_hash = deploy_faucet(&mut state, alice);
    let faucet_admin = faucet_admin_cap_id(b"alice");
    seed_faucet_admin_cap(&mut state, faucet_admin, alice);

    let ptb = PtbTx {
        signers: vec![bob.0],
        commands: vec![mint_cmd(faucet_hash, faucet_admin, 1000)],
        gas_payer: genesis_coin_id(bob, 0),
        gas_budget: 2_000_000,
        gas_price: 0,
        expiry_block: 100,
        signatures: vec![PqSignature(vec![0u8; 64])],
    };

    let out = submit_ptb_chain_auth(&mut state, bob, ptb);
    assert!(
        !out.success,
        "non-admin signer must not mint with a read-only admin cap"
    );
}

#[test]
#[ignore = "compiles faucet+pool to wasm32; run with `-- --ignored`"]
fn faucet_mint_then_create_pool() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);

    let faucet_hash = deploy_faucet(&mut state, alice);
    let faucet_admin = faucet_admin_cap_id(b"alice");
    seed_faucet_admin_cap(&mut state, faucet_admin, alice);

    let pool_wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&pool_wasm);
    state.set_vfs_binding("/bloom/petals/dex/pool".to_string(), pool_petal_hash);

    let params_bytes = 30u16.to_be_bytes().to_vec();
    let gas_payer = genesis_coin_id(alice, 0);

    // One atomic PTB: mint two erased coins, then create the pool from them.
    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            // cmd 0: faucet.mint(10000) -> Coin<Erased>  (reserve A)
            mint_cmd(faucet_hash, faucet_admin, 10_000),
            // cmd 1: faucet.mint(10000) -> Coin<Erased>  (reserve B)
            mint_cmd(faucet_hash, faucet_admin, 10_000),
            // cmd 2: create_pool(@0.0, @1.0, params) -> (Pool, LpPosition)
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/petals/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "create_pool".to_string(),
                type_args: vec![erased_type_tag(), erased_type_tag()],
                args: vec![
                    Arg::Use {
                        cmd_idx: 0,
                        ret_idx: 0,
                    },
                    Arg::Use {
                        cmd_idx: 1,
                        ret_idx: 0,
                    },
                    Arg::Const(params_bytes),
                ],
            }),
            // cmd 3: share the Pool so anyone can swap.
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 2,
                    ret_idx: 0,
                }],
                owner: Owner::Shared,
            },
            // cmd 4: give the LpPosition to alice.
            Command::TransferObjects {
                uses: vec![UseRef {
                    cmd_idx: 2,
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
        "faucet.mint ×2 → create_pool must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    // A Pool with reserves (10000, 10000) must exist — provisioned entirely by
    // the faucet, with no `seed_erased_coin`.
    let (_, pool) = state
        .iter_objects()
        .find(|(_, o)| matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "Pool"))
        .expect("a Pool object must exist after create_pool");
    let (ra, rb, _lp, _k, _p, _tag_a, _tag_b) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!(ra, 10_000, "reserve_a");
    assert_eq!(rb, 10_000, "reserve_b");

    assert!(
        state.iter_objects().any(
            |(_, o)| matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "LpPosition")
        ),
        "an LpPosition object must exist after create_pool"
    );
}

// ---------------------------------------------------------------------------
// Test: faucet.mint → swap_exact_in → wallet.receive, all atomic. This is the
// exact PTB shape the live 4-validator docker acceptance test submits.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "compiles faucet+pool+wallet to wasm32; run with `-- --ignored`"]
fn faucet_mint_then_swap_then_receive() {
    let alice = addr(0xA1); // pool creator
    let bob = addr(0xB0); // swapper / gas payer
    let carol = addr(0xC0); // settlement recipient
    let mut state = build_state(&[(alice, 1_000_000), (bob, 1_000_000)]);

    let faucet_hash = deploy_faucet(&mut state, bob);
    let faucet_admin = faucet_admin_cap_id(b"bob");
    seed_faucet_admin_cap(&mut state, faucet_admin, bob);

    let pool_wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&pool_wasm);
    state.set_vfs_binding("/bloom/petals/dex/pool".to_string(), pool_petal_hash);

    let wallet_wasm = std::fs::read(build_wallet_wasm()).expect("read wallet wasm");
    let wallet_petal_hash = state.insert_code(&wallet_wasm);
    state.set_vfs_binding("/bloom/petals/dex/wallet".to_string(), wallet_petal_hash);

    // Alice stands up a shared 10000/10000 pool (setup convenience).
    let pool_id = create_shared_pool(&mut state, alice, pool_petal_hash, b"main", 30);
    let pool_version = state
        .get_object(&pool_id)
        .expect("pool exists after create")
        .version;

    let min_out: u128 = 90;
    let gas_payer = genesis_coin_id(bob, 1);

    // One atomic PTB: faucet-mint the swap input, swap it, settle to carol.
    let ptb = PtbTx {
        signers: vec![bob.0],
        commands: vec![
            // cmd 0: faucet.mint(100) -> Coin<Erased>  (swap input)
            mint_cmd(faucet_hash, faucet_admin, 100),
            // cmd 1: swap_exact_in(@0.0, pool, min_out) -> Coin<Erased>
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/petals/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "swap_exact_in".to_string(),
                type_args: vec![erased_type_tag(), erased_type_tag()],
                args: vec![
                    Arg::Use {
                        cmd_idx: 0,
                        ret_idx: 0,
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
                    cmd_idx: 1,
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
        "faucet.mint → swap → wallet.receive must succeed; revert: {}",
        String::from_utf8_lossy(&out.return_data)
    );

    // Carol owns the 98-output coin, settled by the wallet petal — the full
    // faucet→swap→settle flow, fully on-chain.
    let carol_values = state
        .iter_objects()
        .filter_map(|(_, o)| {
            (o.owner == Owner::Address(carol.0)
                && matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "Coin"))
            .then(|| bloom_petal_fungible::ops::decode_coin_value(&o.payload).ok())
            .flatten()
        })
        .collect::<Vec<_>>();
    let carol_objects = state
        .iter_objects()
        .filter(|(_, o)| o.owner == Owner::Address(carol.0))
        .map(|(_, o)| format!("{:?}", o.type_tag))
        .collect::<Vec<_>>();
    assert!(
        owner_has_coin_worth(&state, carol, 98),
        "carol must receive the swapped output coin (worth 98); got {carol_values:?}; objects {carol_objects:?}"
    );

    // Pool reserves moved to (10100, 9902).
    let pool = state.get_object(&pool_id).expect("pool still exists");
    let (ra, rb, _lp, _k, _p, _tag_a, _tag_b) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!(ra, 10_100, "reserve_a after swap");
    assert_eq!(rb, 9_902, "reserve_b after swap");
}
