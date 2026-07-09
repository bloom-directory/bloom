# 2026-05-19 — bloom-chain v0 consensus + state-transition hardening review

Drives the `Harden bloom-chain v0 consensus + state-transition boundaries`
goal. Each item below requires a code fix **and** a regression test that
fails on master and passes on this branch.

## CRITICAL

1. **Authenticate consensus messages at ingress.** Vote / Proposal / Prevote /
   Precommit signatures must be xDSA-verified against the declared validator
   pubkey BEFORE the message enters `ConsensusState`. Replace the empty-
   signature path at `crates/bloom-chain-consensus/src/engine.rs:112` with real
   signing using the node keystore. Audit
   `crates/bloom-chain-consensus/src/state_machine.rs:307` (on_proposal) and
   `crates/bloom-chain-consensus/src/state_machine.rs:373` (on_vote) plus
   `crates/bloom-chain-node/src/node.rs:366` and `:383` to ensure no
   unverified message reaches `state_machine`.
2. **Catch-up block sync must reuse full block validation.** BlockResponse
   handling at `crates/bloom-chain-node/src/node.rs:455` and apply at `:488`
   must validate commit quorum, parent hash, chain id, tx root, validator set
   hash, and header consistency identically to live consensus.
3. **on_proposal must not transition to prevote until the proposed block_hash
   is present in the blocks map.** Block request can be issued, but prevoting
   on unknown blocks (`state_machine.rs:307`) is banned.

## HIGH

4. **Node restart must restore full committed state.** Replay must apply tx
   effects (transfers, deploys, storage writes, fees, refunds, receipts, code)
   from `block_store`, not just proposer emissions
   (`crates/bloom-chain-node/src/node.rs:120`).
5. **apply_block ordering.** Tx `write_set` must be applied BEFORE
   fee/refund settlement, or settlement must be reconciled atomically. Current
   order at `crates/bloom-chain-node/src/consensus_driver.rs:283-294` allows a
   write set touching sender/proposer to overwrite fee accounting. Cover
   transfer-to-self and recipient-is-proposer.
6. **Nested `petal.call` revert semantics.**
   `crates/bloom-petals/src/chain_vm.rs:631` and `:677` must use a child
   snapshot that is discarded on `Err` so reverted child writes/value
   transfers can never leak into the parent — even if the parent ignores the
   negative return.
7. **Install wasmtime ResourceLimiter around chain-mode execution** at
   `crates/bloom-petals/src/chain_vm.rs:1099` so memory growth is bounded at
   runtime, not only by static validation at `:216`.
8. **Mempool `select_for_block_for` must keep per-sender nonce contiguity
   globally** — picking nonce N+1 of sender S without N of sender S is banned
   regardless of fee. Fix `crates/bloom-chain-consensus/src/mempool.rs:185`.
9. **Validator xDSA secrets** at `crates/bloom/src/commands/chain.rs:200 /
   :214 / :829` must be written with mode 0600 (or platform equivalent) and
   chain init must refuse to overwrite existing key files unless `--force`.
10. **Single canonical address derivation domain tag.** Reconcile
    `crates/bloom-keystore/src/xdsa.rs:315` (`addr:account:`) with
    `crates/bloom-chain-node/src/consensus_driver.rs:207`
    (`bloom-chain.v0.addr:`). Wallets and chain validation must agree.

## MEDIUM

11. Mempool admission must reject tx where `sender != derive(pubkey)`.
12. Reconcile revert API between
    `crates/bloom-chain-node/src/petal_executor.rs:132` and
    `crates/bloom-petals/src/chain_vm.rs:1207` (top-level reverts must take a
    single, exercised code path).
13. `block.prevhash` must be threaded into `PetalExecutor` at
    `crates/bloom-chain-node/src/petal_executor.rs:65`.
14. `StateSnapshot::get_code` (`crates/bloom-chain-state/src/state.rs:344`)
    must see staged deploy code so init-time self-calls and same-tx
    deploy-then-call patterns work.
15. `run-validator --config` must validate `config.validator_address ==
    derive(home_keystore_pubkey)` or error at
    `crates/bloom/src/commands/chain.rs:233`.
16. Block-query-by-hash: either implement in RPC
    (`crates/bloom-chain-node/src/rpc.rs:274`) or remove from CLI
    (`crates/bloom/src/commands/chain.rs:407`).

## Design constraint

Establish a single, narrow **validation boundary** entered BEFORE
`ConsensusState` / `apply_block`, covering:

- (a) signature verification
- (b) block header / body root checks
- (c) commit quorum
- (d) parent / height continuity
- (e) tx sender derivation
- (f) state-transition output integrity

Document this boundary in `docs/specs/2026-05-18-bloom-chain-design.md`.

## Adversarial tests required

Under `crates/bloom-chain-consensus/tests/` and `crates/bloom-chain-node/tests/`:

- Forged vote signatures rejected
- BlockResponse with tampered tx root / forged commit / wrong validator set
  hash / wrong parent rejected
- Restart replays full state (deploy + transfer + storage + receipts intact)
- Reverted nested call writes never visible to parent
- Wasm with grow-only memory caught at runtime
- Same-sender nonce 1 selected even when nonce 2 has higher fee
- Tx with `sender != derive(pubkey)` rejected at mempool admit
- Validator key files have mode 0600
- Same-tx deploy-then-call sees staged code

## Working style

- Dispatch parallel agents on independent file groups (consensus auth,
  block-sync validation, restart replay, revert isolation, wasm limiter,
  mempool selection, key file permissions, address derivation, adversarial
  tests can largely be parallelized).
- Do NOT invoke any `superpowers:*` skills.
- Keep DEX under `examples/`.
- Default `RUST_LOG=warn`.

## Acceptance

- All listed bugs have a regression test that fails on master and passes on
  this branch.
- Full `cargo test` suite green.
- `scripts/test-docker-dex.sh` and
  `examples/dex/tests/bloom-dex-it/tests/chain_dex_demo.rs`
  (`dex_v0_acceptance_end_to_end`) still green.
- v0 spec updated with the validation-boundary section.
