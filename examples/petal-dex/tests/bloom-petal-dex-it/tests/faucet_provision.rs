//! **Real-wasm** de-risk for the `/bloom/dex/faucet` petal — the live-chain
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
    addr, build_faucet_wasm, build_pool_wasm, build_state, build_wallet_wasm, create_shared_pool,
    genesis_coin_id, owner_has_coin_worth, submit_ptb_chain_auth,
};

/// Deploy the faucet wasm into `state` and bind its VFS path; return its hash.
fn deploy_faucet(state: &mut bloom_chain_state::State) -> bloom_chain_types::types::Hash32 {
    let wasm = std::fs::read(build_faucet_wasm()).expect("read faucet wasm");
    let hash = state.insert_code(&wasm);
    state.set_vfs_binding("/bloom/dex/faucet".to_string(), hash);
    hash
}

/// A faucet `mint(value)` Move command (no object args — pure mint).
fn mint_cmd(faucet_hash: bloom_chain_types::types::Hash32, value: u128) -> Command {
    Command::Move(MoveCmd {
        petal: PetalRef {
            path: "/bloom/dex/faucet".to_string(),
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
fn faucet_mint_then_create_pool() {
    let alice = addr(0xA1);
    let mut state = build_state(&[(alice, 1_000_000)]);

    let faucet_hash = deploy_faucet(&mut state);

    let pool_wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&pool_wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    let params_bytes = 30u16.to_be_bytes().to_vec();
    let gas_payer = genesis_coin_id(alice, 0);

    // One atomic PTB: mint two erased coins, then create the pool from them.
    let ptb = PtbTx {
        signers: vec![alice.0],
        commands: vec![
            // cmd 0: faucet.mint(1000) -> Coin<Erased>  (reserve A)
            mint_cmd(faucet_hash, 1000),
            // cmd 1: faucet.mint(1000) -> Coin<Erased>  (reserve B)
            mint_cmd(faucet_hash, 1000),
            // cmd 2: create_pool(@0.0, @1.0, params) -> (Pool, LpPosition)
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "create_pool".to_string(),
                type_args: vec![],
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

    // A Pool with reserves (1000, 1000) must exist — provisioned entirely by
    // the faucet, with no `seed_erased_coin`.
    let (_, pool) = state
        .iter_objects()
        .find(|(_, o)| matches!(&o.type_tag, TypeTag::Concrete { type_name, .. } if type_name == "Pool"))
        .expect("a Pool object must exist after create_pool");
    let (ra, rb, _lp, _k, _p) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!(ra, 1000, "reserve_a");
    assert_eq!(rb, 1000, "reserve_b");

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

    let faucet_hash = deploy_faucet(&mut state);

    let pool_wasm = std::fs::read(build_pool_wasm()).expect("read pool wasm");
    let pool_petal_hash = state.insert_code(&pool_wasm);
    state.set_vfs_binding("/bloom/dex/pool".to_string(), pool_petal_hash);

    let wallet_wasm = std::fs::read(build_wallet_wasm()).expect("read wallet wasm");
    let wallet_petal_hash = state.insert_code(&wallet_wasm);
    state.set_vfs_binding("/bloom/dex/wallet".to_string(), wallet_petal_hash);

    // Alice stands up a shared 1000/1000 pool (setup convenience).
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
            mint_cmd(faucet_hash, 100),
            // cmd 1: swap_exact_in(@0.0, pool, min_out) -> Coin<Erased>
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/pool".to_string(),
                    hash: Some(pool_petal_hash),
                },
                function: "swap_exact_in".to_string(),
                type_args: vec![],
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
            // cmd 2: wallet.receive(@1.0, carol) — settle the swap output.
            Command::Move(MoveCmd {
                petal: PetalRef {
                    path: "/bloom/dex/wallet".to_string(),
                    hash: Some(wallet_petal_hash),
                },
                function: "receive".to_string(),
                type_args: vec![],
                args: vec![
                    Arg::Use {
                        cmd_idx: 1,
                        ret_idx: 0,
                    },
                    Arg::Const(carol.0.to_vec()),
                ],
            }),
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

    // Carol owns the 90-output coin, settled by the wallet petal — the full
    // faucet→swap→settle flow, fully on-chain.
    assert!(
        owner_has_coin_worth(&state, carol, 90),
        "carol must receive the swapped output coin (worth 90)"
    );

    // Pool reserves moved to (1100, 910).
    let pool = state.get_object(&pool_id).expect("pool still exists");
    let (ra, rb, _lp, _k, _p) =
        bloom_petal_dex_pool::payload::decode_pool(&pool.payload).expect("decode pool");
    assert_eq!(ra, 1100, "reserve_a after swap");
    assert_eq!(rb, 910, "reserve_b after swap");
}
