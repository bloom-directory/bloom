# 2026-05-26 - Branch vs Master Private Testnet Readiness Review

## Scope

Branch reviewed: `feat/bloom-like-petals`

Baseline: `master` / `FETCH_HEAD` at review time

Review objective: identify bugs, logic errors, incomplete features, and
acceptance gaps that remain barriers to a private Bloom testnet. Networking and
peer discovery remain out of scope, but consensus safety, custody, resource
accounting, state commitment/recovery, RPC/operator safety, Docker acceptance,
and DeX adversarial behavior are in scope.

This report consolidates observations from subagent review slices covering:

- consensus and block validity;
- execution, PTB, wasm, gas, and resource accounting;
- state, storage, snapshot, and restart recovery;
- RPC, operator, transport, and Docker safety;
- DeX correctness and adversarial coverage.

## Readiness Rule

Before this branch is suitable for a private testnet with untrusted operators
or contracts:

- every P0 issue below must be fixed and covered by regression tests;
- every P1 issue below must be fixed or made unreachable by enforced launch
  configuration;
- the dockerized adversarial acceptance suite must enforce the fixed behavior;
- an adversarial reviewer must re-check the implementation against this report
  before the goal is considered complete.

## P0 Blockers

### 1. Persistent `MergeCoins` inputs are not deleted

Reference:

- `crates/bloom-script/src/executor.rs:675`

`MergeCoins` drops non-first inputs from the borrow table, but
`BorrowTable::drop_row` only removes the row. It does not emit an object delete
for persistent objects. Commit only deletes `report.object_deletes`, so merged
persistent coins can remain on-chain while their value is also added into the
first coin.

Impact:

Direct coin/resource inflation and stale ownership rows.

Required fix:

- When merging persistent non-first inputs, record `(id, old_owner)` in
  `object_deletes`.
- Rebuild ownership rows consistently.
- Use plain `drop_row` only for transient inputs.

Required tests:

- Merge two persistent coins and assert the non-first input object is absent.
- Assert ownership rows are removed.
- Assert total value is conserved.

### 2. PTB gas payer aliasing can overwrite reservation accounting

References:

- `crates/bloom-chain-node/src/petal_executor.rs:574`
- `crates/bloom-script/src/executor.rs:430`

Gas reservation debits only the runner snapshot, but `ValidatedPtb.objects`
still contains the pre-debit gas-payer object. If the gas payer is also passed
as `Arg::Object`, the executor can preload the pre-debit object into the borrow
table. Later built-ins such as `SplitCoins` can write that stale object back
before refund settlement.

Impact:

Gas burn can be overwritten or inflated. A PTB can use the gas coin as an input
and defeat reservation accounting.

Required fix:

- Prefer rejecting `tx.gas_payer` as any PTB object input.
- Alternatively, update `validated.objects[gas_payer]` to the debited object
  before executor preload and settle from that same row with invariant checks.

Required tests:

- PTB that uses the gas coin as an object input must be rejected before
  execution, or must preserve exact gas reservation accounting.
- Cover split/merge/move attempts involving the gas coin.

### 3. Non-OOF wasm traps can under-report fuel

References:

- `crates/bloom-petals/src/chain_vm.rs:1624`
- `crates/bloom-chain-node/src/chain_petal_runner.rs:196`

`dispatch_chain_call_sync` preserves `fuel_used` for genuine traps, but
`PetalVm::run_chain_call` discards it when converting `SubCallError::Trapped`
into `PetalError`. `ChainPetalRunner` then returns `PetalAbort` without the
actual used fuel unless the error string looks like out-of-fuel.

Impact:

Contracts can burn fuel and then trap for a non-out-of-fuel reason while the
receipt/block reports little or no fuel. This bypasses block fuel accounting
and resource limits.

Required fix:

- Carry trap `fuel_used` through the runner error path and include it in
  `ExecutionReport::fuel_used`.
- If the error type cannot carry this yet, conservatively charge the remaining
  command budget for all traps.

Required tests:

- A wasm petal burns nonzero fuel and then traps for a non-OOF reason.
- The receipt and block commitment must report nonzero fuel.
- Gas payer burn and proposer credit must reflect the charged fuel.

### 4. DeX partial-consume paths mint unbacked coins

References:

- `examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:383`
- `examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:668`

`add_liquidity` mutates the original input coin to the spent amount and also
creates a leftover coin. `swap_exact_out` does the same with `exact_in` plus
leftover. Because persistent consumed objects are written back unless deleted,
the spent amount can remain user-owned while pool reserves are also credited.

Impact:

Users can inflate `Coin<Erased>` supply through normal add-liquidity and
exact-out flows, corrupting reserves and object custody.

Required fix:

- Delete the original input coin and mint only the leftover, or mutate the
  original coin to the leftover amount and ensure the spent amount is not left
  as a user-owned coin.
- Do not ignore `object_create` / `object_delete` errors.

Required tests:

- Add-liquidity partial consume conserves total coin value.
- Exact-out partial consume conserves total coin value.
- Original spent coins are either absent or reduced only to the leftover.
- Cover in-process real-wasm PTB and Docker adversarial paths.

### 5. Block/state persistence ordering is crash-unsafe

References:

- `crates/bloom-chain-node/src/consensus_driver.rs:936`
- `crates/bloom-chain-node/src/consensus_driver.rs:970`

`apply_block` installs the new in-memory state before durable persistence, then
writes blob/index/block afterward. If `blob_store.put`, `state_index.put`, or
`block_store.put` fails, the live state is already advanced while durable
storage is not. Also, `state_index.put` precedes `block_store.put`, so a crash
after the index write but before block write can leave a checkpoint whose block
is missing.

Impact:

A failed disk write or crash can leave the node internally advanced without the
block/index needed to reproduce that state, or can make restart fail.

Required fix:

- Validate on scratch.
- Serialize the blob.
- Write blob and block durably with temp-file plus rename semantics.
- Publish `state_index` last as the commit marker.
- Install in-memory state only after durable writes succeed.
- On restart, treat checkpoints without required block files as incomplete and
  fall back.

Required tests:

- Simulate missing latest block with a newer state index and assert restart
  falls back to an older complete checkpoint.
- Simulate write failure ordering if practical with a fault-injection store or
  isolated unit around commit markers.

### 6. Peer-provided snapshot blobs can cause huge allocation

References:

- `crates/bloom-chain-state/src/blob.rs:347`
- `crates/bloom-chain-node/src/node.rs:1253`

`State::from_blob` allocates `Vec::with_capacity(id_count)` from an untrusted
`u32` in the ownership section before verifying enough bytes remain.
`apply_state_snapshot` feeds peer-provided snapshot blobs directly into this
decoder.

Impact:

A peer can send a bounded-size snapshot frame with `id_count = u32::MAX` and
trigger huge allocation/OOM during snapshot sync.

Required fix:

- Preflight every count and length against remaining bytes before allocation.
- Add protocol caps for section counts, path lengths, object sizes, ownership
  row sizes, and blob total size.
- Reject `id_count > remaining / 32`.
- Avoid `with_capacity` from raw wire counts.

Required tests:

- Malformed snapshot blob with huge ownership `id_count` is rejected without
  large allocation.
- Malformed section counts/path lengths/object sizes are rejected.
- Docker or transport-level adversarial test sends malformed snapshot response
  and proves the node remains live.

## P1 Blockers

### 7. Committed-looking `BlockResponse` can bypass proposal-body validation

References:

- `crates/bloom-chain-node/src/node.rs:662`
- `crates/bloom-chain-node/src/node.rs:680`
- `crates/bloom-chain-consensus/src/state_machine.rs:290`

`BlockResponse` skips proposal-body validation whenever `has_commit` is true,
but still registers the block and resumes pending proposals. A peer can send a
block with a non-empty bogus commit and the same header hash as a valid
proposal, but with invalid body contents.

Impact:

The validator can prevote/precommit the registered body and later abort on
`apply_block` once quorum arrives for the header hash.

Required fix:

- Validate same-height committed-looking `BlockResponse`s before
  `register_block`.
- Run proposal-body/execution validation before allowing
  `try_resume_pending_proposal`.
- Reject bogus commits instead of treating non-empty votes as enough to bypass
  proposal validation.

Required tests:

- Same-height `BlockResponse` with non-empty bogus commit and bad body must not
  resume pending proposal or emit prevote.

### 8. Proposer can equivocate for the same height/round

References:

- `crates/bloom-chain-consensus/src/engine.rs:137`
- `crates/bloom-chain-consensus/src/engine.rs:144`
- `crates/bloom-chain-node/src/node.rs:852`

`maybe_propose()` does not check `state.step == Step::Propose` or whether this
`(height, round)` already has a proposal. The 1s scheduler calls it
unconditionally when the local node is proposer, so a slow round can cause the
proposer to sign and broadcast multiple different proposals for the same
height/round.

Impact:

Proposer equivocation can split prevotes and locks.

Required fix:

- Make proposal emission idempotent per `(height, round)`.
- Only propose in `Step::Propose`.
- Cache/rebroadcast the existing proposal instead of rebuilding a new block.

Required tests:

- Repeated scheduler ticks for the same proposer/height/round produce at most
  one proposal hash.

### 9. Round proposers ignore `valid_block` / polka recovery

References:

- `crates/bloom-chain-consensus/src/engine.rs:149`
- `crates/bloom-chain-consensus/src/engine.rs:153`
- `crates/bloom-chain-consensus/src/state_machine.rs:453`

Round proposers always build a fresh block with `pol_round: -1`, ignoring
`state.valid_block`. If a round gets 2f+1 prevotes and validators lock, but
commit does not complete, later rounds cannot make progress because locked
validators keep prevoting the locked hash while proposers keep proposing
unrelated hashes without a valid polka round.

Impact:

Consensus liveness can fail after a polka/no-commit round.

Required fix:

- When `valid_block` is set, re-propose that block hash/body and set
  `pol_round` to the valid round.

Required tests:

- Simulate "polka but no commit"; next round must recover and commit.

### 10. `SplitCoins` / `MergeCoins` do not enforce `Coin<T>` type shape

Reference:

- `crates/bloom-script/src/executor.rs:570`

`SplitCoins` and `MergeCoins` never verify that source objects are actually
`Coin<T>` types. They only require a 48-byte payload decodable as a value and
then clone the original `type_tag` into new transient objects.

Impact:

Signer-owned resources or capabilities with compatible payload shape can be
split/merged/minted outside their defining petal's constructors and invariants.

Required fix:

- Enforce canonical `Coin<T>` type shape for split/merge built-ins.
- Propagate and check concrete built-in return types during validation.

Required tests:

- Split/merge over non-coin resource with coin-shaped payload is rejected.

### 11. Wasm admission does not validate exact imports/exports

References:

- `crates/bloom-petals/src/chain_vm.rs:232`
- `crates/bloom-chain-node/src/petal_executor.rs:153`

Wasm admission only allow-lists import modules, not import names/signatures,
and it does not verify that manifest-declared functions/invariants have matching
exports. A module can deploy with `import "chain" "missing"` or a manifest
declaring `swap` without `__petal_swap`; deploy succeeds and binds the path,
but calls later fail.

Impact:

Invalid code can permanently bind an unowned path because rebinding is blocked
and upgrade is disabled.

Required fix:

- Validate exact allowed `(module, name, type)` imports.
- Require every manifest function/invariant export to exist with the expected
  ABI before inserting code or VFS bindings.

Required tests:

- Missing host import fails at deploy with no code/VFS write.
- Manifest-declared missing function export fails at deploy with no code/VFS
  write.

### 12. Docker/RPC health is not readiness

References:

- `crates/bloom-chain-node/src/rpc.rs:572`
- `docker-compose.yml:52`
- `scripts/gen-docker-compose.sh:61`

`chain_health` always returns `"ok": true` once RPC is reachable, and Docker
treats any successful `bloom chain health` call as healthy. This does not prove
the node is ready or that consensus is making progress.

Impact:

A validator can be marked healthy while stuck at height 0, stalled after
restart, or not catching up.

Required fix:

- Split liveness and readiness, or add readiness fields that require recent
  height progress, successful state load, and expected local validator identity.
- Docker health should assert readiness, not merely JSON-RPC reachability.

Required tests:

- Health/readiness fails for a node that is RPC-reachable but not making block
  progress.

### 13. Peer transport lacks read/idle timeouts and inbound connection caps

References:

- `crates/bloom-chain-node/src/transport.rs:69`
- `crates/bloom-chain-node/src/transport.rs:336`
- `crates/bloom-chain-node/src/transport.rs:473`

Peer transport frame reads use `read_exact` without read/idle timeouts, and the
inbound accept loop has no total connection cap. A local process or bad
private-testnet peer can open many sockets and send no data, or send a length
prefix and never finish the body, parking tasks indefinitely.

Impact:

Length checks limit each allocation, but not aggregate connection/task
exhaustion.

Required fix:

- Add an inbound connection semaphore / max peer budget.
- Wrap length/body reads in `tokio::time::timeout`.
- Enforce idle deadlines and close peers that exceed per-peer or total budgets.

Required tests:

- Slowloris peer connections are closed.
- Excess inbound connections are rejected or bounded.

### 14. Genesis pubkey base64 decoder is permissive

References:

- `crates/bloom-chain-node/src/genesis.rs:126`
- `crates/bloom-chain-node/src/genesis.rs:319`

The custom genesis pubkey base64 decoder silently ignores trailing input when
length is not divisible by 4 and accepts invalid padding positions. A malformed
validator pubkey can decode to truncated/different bytes instead of being
rejected.

Impact:

Malformed genesis identity binding can be accepted and only fail later during
validator operation.

Required fix:

- Replace the custom decoder with the `base64` crate's standard strict decoder.
- Reject malformed padding/trailing bytes.
- Enforce expected xDSA public key length.

Required tests:

- Malformed base64, invalid padding, and wrong xDSA pubkey length are rejected
  at genesis parse/load time.

### 15. High-fee exact-out swaps can falsely revert

Reference:

- `examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:738`

`solve_exact_in_for_out` only increments 64 times from a no-fee lower-bound
guess. `fee_bps` allows values up to `9999`, where the valid exact input can be
thousands of increments above the no-fee guess.

Impact:

Valid exact-out swaps can falsely revert with `InsufficientLiquidity` for
allowed high-fee pools, making advertised exact-out routing unreliable.

Required fix:

- Use the closed-form constant-product exact-input formula with fee factor and
  ceil division, or binary search within `[1, max_in]`.

Required tests:

- Exact-out succeeds for high-fee pools, including `9999` bps, when liquidity
  and max input are sufficient.

### 16. Checkpoint selection can brick restart on missing latest block

References:

- `crates/bloom-chain-node/src/node.rs:75`
- `crates/bloom-chain-node/src/node.rs:118`

Checkpoint selection only verifies index/blob presence, not whether the
checkpoint's block is present. If it selects height `H` but
`block_store.latest_height()` is `H-1`, startup errors instead of falling back
to an older usable checkpoint.

Impact:

One missing latest block file can brick restart even when an older checkpoint
plus suffix blocks could recover and catch up from peers.

Required fix:

- Define a "complete checkpoint" as index + blob + matching block for
  `height > 0`.
- Scan downward until all required local artifacts are present and verified.

Required tests:

- Latest checkpoint missing its block falls back to older complete checkpoint.

## P2 Issues

### 17. Block validation omits sender/pubkey derivation check

References:

- `crates/bloom-chain-node/src/consensus_driver.rs:316`
- `crates/bloom-chain-node/src/consensus_driver.rs:467`
- `crates/bloom-chain-node/src/consensus_driver.rs:519`

Block validation verifies tx chain id and signature, but not that
`tx.sender == Address::from_pubkey_bytes(tx.pubkey)`, despite comments saying
this is required. Such txs are rejected only during execution as failed
receipts.

Impact:

A proposer can include mempool-invalid, fee-free sender-mismatch txs in
otherwise valid blocks.

Suggested fix:

- Add sender-derivation checks to both `validate_block_for_apply` and
  `validate_block_for_proposal`, mirroring `Mempool::admit`.

### 18. Added LP positions have inconsistent payload self-id

Reference:

- `examples/petal-dex/crates/bloom-petal-dex-pool/src/lib.rs:372`

LP tokens minted by `add_liquidity` keep `ObjectId([0; 32])` inside their
payload. `create_pool` patches created object payload IDs after
`object_create`, but this path does not.

Impact:

Added LP positions have inconsistent object identity in payload versus table
key. Current removal ignores the embedded LP id, but clients/indexers/recovery
code may see malformed LP objects.

Suggested fix:

- After creating the LP object, read `host::object_id(lp_handle)`, rebuild the
  LP payload with that id, and mutate it.

### 19. `chain_health` recomputes expensive roots under state lock

References:

- `crates/bloom-chain-node/src/rpc.rs:572`
- `crates/bloom-chain-state/src/state.rs:431`
- `crates/bloom-chain-state/src/state.rs:462`
- `crates/bloom-chain-state/src/state.rs:518`

`chain_health` computes `state_root`, `object_root`, `ownership_root`, and
`vfs_root` under the live state mutex. `state_root()` already recomputes
several of those roots, so health duplicates expensive full-state trie work.

Impact:

Docker runs this every 2 seconds per validator, and any RPC caller can trigger
the same path, creating avoidable state-lock contention.

Suggested fix:

- Return cached latest committed roots/tip metadata, or use a cheap readiness
  endpoint for Docker.

### 20. VFS comment misstates consensus semantics

Reference:

- `crates/bloom-chain-state/src/state.rs:379`

`set_vfs_binding` documentation still says VFS is not state-root-committed, but
`vfs_root` is now included in `state_root`.

Suggested fix:

- Update the stale comment to match committed VFS behavior.

## Required Final Verification Gate

Before marking a remediation goal complete, run:

- `cargo fmt --all`
- `cargo test --workspace`
- focused tests for every P0/P1 fix;
- ignored/adversarial DeX tests relevant to custody/gas/restart;
- the dockerized adversarial acceptance suite:
  - `./scripts/test-docker-adversarial.sh`

The Docker suite must include, or be extended to include, live 4-validator
coverage for:

- malformed proposal/sync blocks;
- execution-root / receipt-root / fuel-used tampering;
- restart and snapshot recovery after pruning;
- bounded RPC/decode inputs;
- gas-payer alias attempts;
- persistent merge/split custody conservation;
- non-OOF trap fuel charging;
- DeX partial-consume conservation;
- cross-pool LP withdrawal;
- stale shared-object versions;
- bad inner signatures;
- nonzero gas success/revert;
- restart/catch-up convergence.

An adversarial reviewer subagent must inspect the final implementation and
tests against this file and confirm no P0/P1 blockers remain.
