# Pre-existing DEX coin-mint regression (master / #26)

**Status:** OPEN — pre-existing on `origin/master`, independent of the invariant
subsystem. Maintainer decision needed (DEX coin-mint model).
**Found:** 2026-06-02, while rebasing the `invariants` branch onto master.
**Owner:** #26 author (VFS namespace endpoints).

## Symptom
The real-wasm DEX acceptance is red:
- `cargo test -p bloom-petal-dex-it --test real_wasm_pool -- --ignored` — every
  swap/liquidity test fails with `petal abort in command 0: code -2`
  (`HostError::Denied` → `"object.create Coin from unauthorized petal"`).
- `docker petal DEX acceptance` (`scripts/test-docker-petal-dex.sh`) likewise.

`create_pool` passes (the Pool is a transient row, born `Mutable`); only
operations that **mint an output `Coin`** (swap, add/remove liquidity) fail.

## Root cause
Coin minting is gated by an allow-list of VFS paths
(`crates/bloom-petals/src/chain_vm.rs`):
- `COIN_MINTER_PATHS` (`chain_vm.rs:937`) and `is_authorized_coin_minter`
  (`:939`) — a petal may `object.create` a `Coin` only if it is bound at one of
  these paths. The gate is at `chain_vm.rs:~1215`.

`#26` (`Add petal VFS namespace endpoints`, e557e74) made **two coupled but
inconsistent** changes:
1. **Narrowed `COIN_MINTER_PATHS`** from the merge-base's 4 entries
   (`CORE_FUNGIBLE_PATH` + `/bloom/dex/{faucet,pool,router}`) down to just
   `[CORE_FUNGIBLE_PATH]`, and **added a unit test locking it in** —
   `object_create_coin_from_example_dex_path_is_denied` (`chain_vm.rs:3107`)
   asserts a petal at `/bloom/petals/dex/faucet` is **denied** Coin creation.
   → So restricting the DEX from minting was *intentional*.
2. **Left the DEX example minting from the pool** — the pool petal still does
   `host::object_create(&tags::coin_tag(...), …)` for swap outputs/leftovers
   (`examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs`).

These contradict: the unit test says the DEX may not mint; the DEX example
requires it to. No value of `COIN_MINTER_PATHS` satisfies both.

## Evidence it is pre-existing on master (not our rebase)
Running master's own test in a clean `origin/master` worktree fails identically:
```
git worktree add /tmp/m origin/master
cd /tmp/m && cargo test -p bloom-petal-dex-it --test real_wasm_pool \
  real_pool_swap_exact_in_executes -- --ignored
# → FAILED: petal abort in command 0: code -2
```
The `acceptance` workflow only runs on push-to-master / manual, so this has not
been gating and likely went unnoticed.

## Options (maintainer's call)
1. **Rework the DEX to comply with the restriction** — pool no longer mints;
   output coins come from the core fungible petal (delegated mint) or by
   transferring/splitting reserve coin objects the pool holds. Matches #26's
   intent + the deny-test. Larger change to `bloom-petal-dex-pool`.
2. **Revert the restriction** — restore the dex paths to `COIN_MINTER_PATHS`
   under the new namespace (`/bloom/petals/dex/{faucet,pool,router}`) and delete
   `object_create_coin_from_example_dex_path_is_denied`. Re-widens a coin-mint
   security boundary #26 deliberately tightened; needs sign-off.

## Interaction with the invariants PR
The invariant subsystem does **not** touch coin minting. To keep that PR green
without making a DEX/security decision, its PR CI gates only the hermetic
`real_inv_wasm` ABI test (`.github/workflows/ci.yml`, job `real-wasm-gates`);
`real_wasm_pool` is intentionally excluded until this is resolved, and the full
`--ignored` acceptance suite stays master-push/manual.
