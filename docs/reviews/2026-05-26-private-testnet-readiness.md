# 2026-05-26 - Bloom Private Testnet Readiness Audit

## Scope

This audit treats all current "v0 caveats" as invalid for private-testnet
readiness when they affect consensus safety, custody, resource accounting,
state commitment, recovery, or operator safety.

Networking and peer discovery are excluded, but transport-adjacent operator
surfaces such as RPC binding, request bounds, and Docker health checks are in
scope.

The DeX on Bloom is included because it exercises object custody, PTB
execution, wasm admission, gas accounting, persistence, and live multi-validator
behavior.

## Readiness Rule

Bloom is not ready for a private testnet until every P0 blocker below is fixed,
covered by regression tests, and enforced by a dockerized adversarial acceptance
suite. P1 items must also be resolved before opening the network to untrusted
operators or contracts.

## P0 Blockers

### 1. Vote only for valid blocks, not merely known blocks

Current proposal handling allows a block to satisfy the vote gate once it is
present in the engine's `blocks` map. This is insufficient: a Byzantine proposer
can send a malformed `BlockResponse`, then a validly signed proposal for that
hash. Honest validators can prevote/precommit before validating execution.

References:
- `crates/bloom-chain-consensus/src/state_machine.rs`
- `crates/bloom-chain-node/src/node.rs`
- `crates/bloom-chain-node/src/consensus_driver.rs`

Required fix:
- Add a proposal-block validation boundary before a registered block can satisfy
  proposal voting.
- Validate height, chain id, parent hash, expected proposer, tx root,
  validator-set hash, tx signatures, aggregate fuel bounds, and deterministic
  execution outputs.
- Do not enter `Prevote` for an invalid block.

Required tests:
- A registered block with bad tx root, parent, proposer, state root, receipt
  root, or fuel used must emit no prevote.
- The same malformed cases must be rejected on sync/apply.

### 2. Commit headers to actual execution

The block builder currently stamps headers from pre-execution state and zeroes
receipt/fuel fields. Apply computes the real post-state root after validation,
so the signed block hash does not commit to the executed transition.

References:
- `crates/bloom-chain-node/src/node.rs`
- `crates/bloom-chain-node/src/consensus_driver.rs`
- `crates/bloom-chain-types/src/receipt.rs`

Required fix:
- Proposer executes the candidate block on scratch state before proposal.
- Header must include post-state `state_root`, deterministic
  `receipts_root(receipts)`, and actual `fuel_used`.
- Validators must re-execute deterministically and reject mismatches before
  prevote/precommit/apply.

Required tests:
- Tampering `state_root`, `receipts_root`, or `fuel_used` rejects before vote.
- The same tampering rejects before catch-up apply and leaves state unchanged.

### 3. Prevent failed-apply consensus halt

If an invalid block reaches `Action::Commit`, `apply_block` can reject while the
state machine remains in `Step::Commit`. That can halt a validator.

Required fix:
- Make block validity a precondition for precommit/commit action.
- Treat any post-quorum apply failure as fatal or explicitly recover/reset.
  Silent continuation in `Commit` is unsafe.

Required tests:
- Quorum precommits for an invalid block must not leave a node unable to process
  a later valid proposal or round.

### 4. Validate header proposer

The expected proposer may sign a `Proposal` whose block header credits another
address as proposer. Fees and emissions then go to an unchecked address.

Required fix:
- Validate `block.header.proposer == proposal.proposer`.
- Validate `proposal.proposer == validator_set.proposer_for(height, round)`.
- Enforce this before prevote and before apply.

Required tests:
- A proposal signed by the expected proposer but carrying a block with a
  different header proposer is rejected.

### 5. Fix PTB gas accounting

Successful PTBs currently subtract `fuel_remaining` but do not accumulate
`ExecutionReport::fuel_used`. Settlement can charge zero for successful
expensive wasm execution.

References:
- `crates/bloom-script/src/executor.rs`
- `crates/bloom-chain-node/src/petal_executor.rs`

Required fix:
- Accumulate every petal call and invariant `fuel_used`.
- Cap at `gas_budget` and make over-budget execution revert as out-of-fuel.
- Burn/refund gas-payer `Coin<LOOM>` correctly and credit proposer.

Required tests:
- Successful fuel-burning PTB with nonzero gas price must reduce gas-payer coin
  by `fuel_used * gas_price`, bump versions correctly, and credit proposer.
- Reverting fuel-burning PTB must still burn gas according to the agreed policy.

### 6. Enforce object-owned authority

`Owner::Object(_)` is accepted for every access mode at validation, while the
executor does not prove the parent ownership chain. Object-owned DeX reserve or
LP assets can be directly referenced by an attacker PTB.

References:
- `crates/bloom-script/src/validator.rs`
- `crates/bloom-script/src/executor.rs`

Required fix:
- Implement object-owner traversal during validation/execution.
- An object-owned child is accessible only if the owning parent is legitimately
  in scope and authority resolves to signer/shared rules.
- Reject unresolved object-owned roots.

Required tests:
- An attacker cannot mutate, consume, transfer, or delete a pool-owned object
  without proving valid parent authority.

### 7. Authenticate and validate publish/upgrade/deploy

PTB `Publish`, PTB `UpgradePetal`, and legacy `DeployPetal` do not enforce full
path ownership, manifest, chain-wasm, or storage-size checks.

References:
- `crates/bloom-script/src/validator.rs`
- `crates/bloom-script/src/executor.rs`
- `crates/bloom-chain-node/src/petal_executor.rs`
- `crates/bloom-petals/src/chain_vm.rs`

Required fix:
- Enforce owner-cap/path authority for publish and upgrade.
- Reject unauthorized rebinding of existing paths.
- Require valid manifest with `module_path` matching the command/path.
- Call `PetalVm::validate_for_chain` before code insertion.
- Add wasm and storage byte-size limits priced in gas.

Required tests:
- Unauthorized rebinding of `/bloom/dex/pool` fails.
- Wasm with disallowed imports/exports fails with no code/VFS write.
- Missing or mismatched manifest fails with no code/VFS write.

### 8. Fix persistence, pruning, and restart replay

Startup replays from genesis while the block store prunes old blocks. Missing
replay blocks are skipped. The persisted "state blob" is only a JSON-encoded
state-root string, not restorable state.

References:
- `crates/bloom-chain-node/src/node.rs`
- `crates/bloom-chain-node/src/block_store.rs`
- `crates/bloom-chain-node/src/consensus_driver.rs`
- `crates/bloom-chain-state/src/blob.rs`

Required fix:
- Persist full canonical `State::to_blob(...)` snapshots.
- Restore from the latest complete checkpoint, then replay only suffix blocks.
- Fail hard if a required suffix block is missing.
- Make state blob hash/domain semantics explicit and verified.

Required tests:
- Run past the prune window, restart, and assert accounts, storage, code,
  objects, ownership, VFS, and `state_root` match the live node.
- Read indexed state blob, restore with `State::from_blob`, and verify root and
  data match.

### 9. Make object, ownership, and VFS data snapshot-restorable and committed

State snapshots omit objects, ownership rows, and VFS bindings. VFS is explicitly
not committed into `state_root` while path/hash validation uses VFS bindings.

References:
- `crates/bloom-chain-state/src/state.rs`
- `crates/bloom-chain-state/src/blob.rs`
- `crates/bloom-script/src/validator.rs`

Required fix:
- Include objects, ownership index, and VFS bindings in canonical snapshots.
- If VFS path binding is consensus-relevant, include a VFS root in `state_root`.
- Otherwise, make path bindings advisory only and never consensus-validating.

Required tests:
- Commit a PTB that creates/transfers objects and publishes a VFS-bound petal,
  snapshot/restore, and assert `state_root`, `get_object`, `get_ownership`, and
  `vfs_lookup` match.

### 10. Fix DeX cross-pool LP withdrawal

`remove_liquidity` decodes an LP's pool id but does not compare it to the mutable
pool being withdrawn from. LP from Pool A may be usable to withdraw from Pool B.

Reference:
- `examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs`

Required fix:
- Enforce `lp.pool_id == pool.id` before withdrawal math.

Required tests:
- Create two pools and attempt `remove_liquidity(Pool B, lp_from_A)`.
- It must revert and leave both pools, LP objects, ownership rows, and gas
  accounting correct.
- Cover in-process real-wasm/PTB and dockerized adversarial paths.

### 11. Bound attacker-controlled decode allocations

PTB and petal return decoders allocate from untrusted `u32` counts before
proving input length/caps.

References:
- `crates/bloom-script/src/encode.rs`
- `crates/bloom-script/src/executor.rs`

Required fix:
- Define protocol caps for tx bytes, signers, signatures, commands, args, uses,
  type args, return slots, and byte buffers.
- Reject counts before allocation.
- Bound petal return slots to the manifest-declared return count.

Required tests:
- Malformed PTB declaring huge counts must error without large allocation/panic.
- Petal returning a huge output count or wrong output count must revert cleanly.

## P1 Required Before Testnet

### Consensus and block validation

- Enforce aggregate `max_fuel` and computed `fuel_used <= block.fuel_limit`.
- Reject executor output where per-tx fuel exceeds tx cap unless explicitly
  specified and safely clamped.
- Strictly validate commit proofs: every commit vote must be unique, same
  height/round/hash, from a validator, and correctly signed.
- Reject duplicate validator votes, wrong-hash votes, and non-validator votes.
- Track equivocation evidence per `(height, round, kind, validator)`; do not
  silently use first-vote-wins without recording evidence.

### Genesis and operator safety

- Verify `validator.address == Address::from_pubkey_bytes(validator.pubkey)` in
  genesis parsing.
- Verify local keypair pubkey matches the genesis entry for local address.
- Default TCP RPC to loopback.
- Require explicit unsafe flag and/or auth for public RPC binds.
- Add request/connection limits, frame-size limits, timeouts, and max tx bytes
  to RPC.
- Replace Docker `nc` health checks with a real `chain_health` endpoint that
  proves JSON-RPC dispatch, identity, chain id/genesis hash, and height
  progress.
- Reload persisted mempool on restart, re-admit entries under current state, and
  purge stale/invalid transactions.
- Make `chain_submit_tx` parameter parsing strict; no silent casts or dropped
  malformed array entries.

### DeX adversarial coverage

- Shared-pool stale-version and replay test: two signed swaps use the same
  pool version; exactly one commits.
- Bad inner signature/value mutation test: tamper signature or recipient/min_out
  after signing and assert no reserve/output mutation.
- Nonzero gas tests for DeX success, slippage revert, and insufficient gas.
- Restart/catch-up test: stop one validator, execute DeX txs, restart it, and
  verify all four endpoints agree on path bindings, pool version, reserves,
  ownership, and output objects.
- Sandwich/order test: attacker moves price before victim's stale quote; victim
  reverts atomically.
- Fee-bounds test: reject `fee_bps > 10_000` deterministically.
- Docker coverage for `add_liquidity`, `remove_liquidity`, `swap_exact_out`,
  reverse swaps, and two-hop router invariants.

## Required Dockerized Adversarial Suite

Create a dockerized acceptance entrypoint, for example:

```text
scripts/test-docker-adversarial.sh
```

It must provision a 4-validator network and run live RPC/CLI tests for:

- malformed proposal/sync blocks rejected without vote/apply;
- post-execution root/receipt/fuel tampering rejected;
- restart after prune-window/state-snapshot recovery;
- bounded RPC and bounded PTB/petal decode inputs;
- DeX cross-pool LP withdrawal rejection;
- DeX stale shared-object version contention;
- DeX bad inner signatures;
- DeX nonzero gas success/revert/insufficient gas;
- DeX restart/catch-up convergence across all validators.

The suite must fail if any validator diverges in height, block hash, state root,
VFS binding, object root, ownership root, DeX pool reserves, or receipt result.

## Completion Gate

The work is complete only when:

- all P0 blockers are fixed;
- all P1 items are either fixed or explicitly converted into enforced launch
  configuration that makes the unsafe path unreachable;
- all new unit/integration/adversarial tests pass;
- the dockerized adversarial suite passes from a clean checkout;
- `cargo test --workspace` passes;
- ignored acceptance tests pass where their external prerequisites are
  available;
- an adversarial reviewer sub-agent has independently reviewed the final
  implementation and found no remaining private-testnet blockers.
