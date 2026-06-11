# Bloom VFS Petal Pipes - design handoff

**Status:** handoff draft
**Date:** 2026-05-21
**Owners:** TBD
**Context:** Follow-up design for the open `feat/bloom-like-petals` PR. The
current PR introduces a sovereign chain, xDSA/BLAKE3 primitives, chain-mode
WASM petals, PTB/object machinery, and local/onchain Petal VFS exposure. This
document captures the proposed next direction: keep the deterministic chain
core, but make the user-facing Petal model UNIX-style paths, stdin/stdout, and
pipes.

## 1. Design thesis

Bloom should expose one conceptual Petal model:

```text
path + stdin -> Petal execution -> stdout + declared state changes
```

Users and agents should not need chain-specific CLI calls to compose Petals.
They should be able to use normal shell-like operations:

```sh
/bloom/petals/foo/mint 100 | /bloom/petals/bar/receive
```

or:

```sh
printf "title: Hello\n\nbody: First post" \
  | /bloom/social/communities/bloom/new
```

Under the hood, Bloom can still lower this into a structured transaction plan
similar to the current PTB model. The public surface is file/path/pipe based;
the consensus surface remains deterministic, typed, signed, and atomic.

## 2. Current PR baseline

The open PR already gives us useful building blocks:

- `bloom-chain-types`: txs, blocks, votes, receipts, BLAKE3-tagged hashing.
- `bloom-keystore`: xDSA composite key support.
- `bloom-chain-state`: accounts, code store, storage, objects, ownership, write
  sets, snapshots.
- `bloom-chain-node`: node, RPC, deploy/call/transfer execution, block/receipt
  persistence.
- `bloom-petals`: local Petal store, WAT-to-WASM install, WASI stdin/stdout
  runtime, VFS handler, chain-mode VM.
- `bloom-script`: PTB wire model and object/command execution machinery.

The mismatch is mostly at the user-facing abstraction:

- Local Petals are stdin/stdout command-style modules.
- Chain Petals are smart-contract-style modules with `init`, `call`, calldata,
  return/revert imports, storage imports, and function dispatch.
- PTB is powerful, but user-visible PTB commands would not feel UNIX-native.
- Chain state is internal accounts/storage/object state, not VFS-shaped state.

The proposed next work should preserve the good internals and add a VFS-pipe
front door.

## 3. Definitions

### Petal endpoint

A Petal endpoint is a virtual executable path:

```text
/bloom/petals/<petal>/<endpoint>
/bloom/social/communities/<name>/new
/bloom/social/threads/<id>/reply
/bloom/defi/pools/usdc-loom/swap
```

Invoking an endpoint means feeding bytes to stdin and receiving bytes from
stdout. The endpoint may also emit typed write intents.

### Packet

A packet is the canonical byte value passed through pipes. Packets should be
typed and linearly consumable when they represent assets or capabilities.

Examples:

- `Token<USDC>`
- `Token<LOOM>`
- `LpToken<ETH-USDC>`
- `StakedPosition<Farm>`
- `ThreadRef`
- `CommentRef`
- `VoteAck`

Human-readable debug formats are allowed, but the committed transaction uses a
canonical binary encoding.

### Transaction plan

A transaction plan is the hidden, canonical form submitted to the chain. It is
similar in spirit to PTB:

```text
command 0: call /bloom/wallets/me/assets/usdc/spend with stdin "1000"
command 1: call /bloom/defi/pools/usdc-loom/swap with stdin output(0)
command 2: call /bloom/defi/pools/loom-eth/swap with stdin output(1)
command 3: call /bloom/wallets/me/receive with stdin output(2)
commit atomically if all commands succeed
```

PTB can be the implementation substrate, but it should not be the default user
interface.

## 4. Architecture

### 4.1 Layers

Use separate layers rather than making POSIX filesystem behavior the consensus
engine:

```text
VFS/path layer
  - paths, listing, reads, writes, executable endpoints
  - human/agent interface

Pipe capture / transaction builder
  - observes endpoint invocations and pipe graphs
  - converts them into a canonical transaction plan

Chain execution layer
  - validates signatures, fuel, object access, ownership, typed packets
  - executes endpoint calls atomically

State layer
  - deterministic object/key-value state
  - BLAKE3 Merkle commitments
  - snapshots and write sets

VFS projection layer
  - renders committed state as directories/files
  - exposes paginated indexes for large collections
```

The VFS is the interface. The chain state remains canonical structured state.

### 4.2 Endpoint dispatch

Path dispatch should replace user-visible ABI/function dispatch.

A Petal implementation may be:

- one tiny WASM binary per endpoint; or
- one larger WASM module with many handlers.

That choice should be hidden from users. In both cases the exposed endpoint is a
virtual executable that uses stdin/stdout.

Example:

```text
/bloom/defi/tokens/usdc/spend
/bloom/defi/tokens/usdc/receive
/bloom/defi/pools/usdc-loom/swap
/bloom/social/threads/<id>/reply
```

If the underlying module is large, the VFS adapter can map the path to an
internal export. The external ABI remains stdin/stdout.

### 4.3 State writes

Endpoints should not directly mutate committed state while the pipe is running.
They should emit typed write intents into a transaction sandbox. The runtime
validates and commits those intents only if the whole plan succeeds.

This keeps shell composition pleasant without giving up blockchain correctness:

- atomicity
- rollback
- fuel accounting
- signature checks
- linear asset/capability consumption
- deterministic state roots

### 4.4 Reads and large listings

Large collections must not be exposed as unbounded directories. `ls` should
return bounded structural affordances, not millions of entries.

For example:

```text
/bloom/social/communities/bloom/
  about
  new
  threads/
    latest/
    hot/
    top/
    by-id/
    search/
```

Then:

```sh
ls /bloom/social/communities/bloom/threads
```

returns:

```text
latest
hot
top
by-id
search
```

Feed contents are readable virtual files or paginated directories:

```sh
cat /bloom/social/communities/bloom/threads/latest/page/000000
cat /bloom/social/communities/bloom/threads/hot/page/000000
cat /bloom/social/communities/bloom/threads/by-id/<thread-id>
```

## 5. DeFi litmus tests

### 5.1 One-hop swap

User-facing command:

```sh
/bloom/wallets/me/assets/usdc/spend amount=1000 \
  | /bloom/defi/pools/usdc-loom/swap min-out=980 \
  | /bloom/wallets/me/receive
```

Expected lowering:

```text
command 0: spend 1000 USDC from signer wallet
command 1: consume Token<USDC>, update pool reserves, emit Token<LOOM>
command 2: deliver Token<LOOM> to wallet
```

Acceptance:

- If slippage check fails, no wallet or pool state changes commit.
- If receive fails, the swap and spend do not commit.
- Output packet cannot be duplicated and spent twice.
- The final receipt can be read as a VFS path and as RPC/chain receipt data.

### 5.2 Two-hop swap

```sh
/bloom/wallets/me/assets/usdc/spend amount=1000 \
  | /bloom/defi/pools/usdc-loom/swap min-out=980 \
  | /bloom/defi/pools/loom-eth/swap min-out=0.30 \
  | /bloom/wallets/me/receive
```

Acceptance:

- Both pools update atomically.
- Intermediate `Token<LOOM>` is not committed to the wallet.
- Failure in either pool reverts the whole plan.

### 5.3 Add liquidity with two inputs

Some DeFi operations are DAG-shaped rather than linear. The design needs named
inputs in addition to simple pipes.

Example shell shape:

```sh
/bloom/defi/pools/eth-usdc/add-liquidity \
  --a <(/bloom/wallets/me/assets/eth/spend amount=0.30) \
  --b <(/bloom/wallets/me/assets/usdc/spend amount=500) \
  --min-lp 10 \
  | /bloom/wallets/me/receive
```

Acceptance:

- The transaction builder captures both process-substitution inputs into one
  transaction plan.
- If either spend fails, no liquidity is added.
- If `min-lp` fails, both spends are reverted.

### 5.4 Swap, LP, stake

```sh
eth=$(
  /bloom/wallets/me/assets/usdc/spend amount=1000 \
    | /bloom/defi/pools/usdc-loom/swap min-out=980 \
    | /bloom/defi/pools/loom-eth/swap min-out=0.30
)

/bloom/defi/pools/eth-usdc/add-liquidity \
  --a "$eth" \
  --b <(/bloom/wallets/me/assets/usdc/spend amount=500) \
  --min-lp 10 \
  | /bloom/defi/farms/eth-usdc/stake \
  | /bloom/wallets/me/receive
```

Acceptance:

- The ergonomic goal is one atomic transaction. If the shell cannot capture
  command substitution safely without committing the first route separately,
  provide a Bloom transaction-session wrapper or VFS transaction staging path.
- The final wallet receives a `StakedPosition`, not raw LP tokens.
- Failure in farming reverts the liquidity add and all upstream spends/swaps.

## 6. Bloombook litmus tests

Bloombook is a minimal Moltbook-like social app for agents and humans:
communities, threads, replies, upvotes/downvotes, feeds, and moderation hooks.

### 6.1 VFS surface

Proposed paths:

```text
/bloom/social/
  communities/
    bloom/
      about
      new
      threads/
        latest/page/000000
        hot/page/000000
        top/day/page/000000
        by-id/<thread-id>
    defi/
      ...
  threads/
    <thread-id>/
      body
      reply
      vote
      comments/page/000000
      comments/by-id/<comment-id>
  agents/
    <agent-id>/
      profile
      karma
      inbox
  feed/
    hot/page/000000
    new/page/000000
```

### 6.2 Canonical objects

Store canonical state as typed objects, then project them into the VFS.

```text
Community {
  id,
  name,
  title,
  moderators,
  created_at
}

Thread {
  id,
  community_id,
  author,
  title,
  body_ref_or_inline,
  created_at,
  score,
  reply_count
}

Comment {
  id,
  thread_id,
  parent_comment_id?,
  author,
  body_ref_or_inline,
  created_at,
  score
}

Vote {
  target_id,
  voter,
  value
}
```

### 6.3 Create thread

```sh
printf "title: Petal ABI\n\nShould invocation be stdin/stdout only?" \
  | /bloom/social/communities/bloom/new
```

Acceptance:

- Creates one `Thread` object.
- Returns a `ThreadRef` packet or thread path on stdout.
- Thread appears in `latest/page/000000`.
- `ls /bloom/social/communities/bloom/threads` remains bounded and does not
  list every thread.

### 6.4 Reply

```sh
printf "Yes. Path dispatch is cleaner than selectors." \
  | /bloom/social/threads/<thread-id>/reply
```

Acceptance:

- Creates one `Comment` object.
- Increments reply count.
- Returns a `CommentRef`.
- Comment appears in paginated comments view.

### 6.5 Vote

```sh
echo +1 > /bloom/social/threads/<thread-id>/vote
echo -1 > /bloom/social/threads/<thread-id>/comments/by-id/<comment-id>/vote
```

Acceptance:

- One active vote per signer per target.
- Changing `+1` to `-1` applies the score delta correctly.
- Repeating the same vote is idempotent.
- Vote updates are visible in feed ranking after index refresh.

### 6.6 Feeds and pagination

```sh
cat /bloom/social/feed/hot/page/000000
cat /bloom/social/communities/bloom/threads/latest/page/000000
cat /bloom/social/threads/<thread-id>/comments/page/000000
```

Acceptance:

- Pages have stable max size.
- Ordering is deterministic.
- Page output is machine-readable NDJSON or canonical packet-list bytes.
- Large communities do not produce unbounded `ls` responses.

## 7. Implementation plan on top of the PR

### Phase 0 - name the direction

- Add this spec to the PR.
- Decide whether `PetalMode::{Local, Onchain, Chain}` stays internal or is
  collapsed in public docs/CLI.
- Decide canonical packet encoding. Candidate: reuse existing canonical codecs
  from `bloom-script`/`bloom-objects` rather than JSON for committed data.

### Phase 1 - VFS executable endpoint abstraction

- Add a VFS concept for executable endpoint entries.
- Expose local Petal execution through VFS paths, not only `bloom petals run`.
- Support stdin/stdout execution for a single endpoint:

```sh
echo hi | /bloom/petals/echo/run
```

- Keep the initial implementation local/offchain if needed.

### Phase 2 - transaction plan builder

- Introduce a transaction-plan representation that can lower to current PTB or
  a new chain tx variant.
- Capture simple linear pipelines:

```sh
A | B | C
```

- Preserve typed outputs as command references rather than raw committed files.
- Enforce all-or-nothing commit.

### Phase 3 - chain endpoint adapter

- Map executable VFS endpoints to chain Petal calls.
- Hide `init`/`call`/function dispatch behind paths.
- Convert endpoint stdin into chain calldata internally.
- Convert chain return bytes into stdout packets.
- Thread write sets through the whole plan.

### Phase 4 - typed asset packets and linearity

- Define `Token<T>`, `LpToken<T>`, `Position<T>`, `Capability<T>`, and social
  reference packets.
- Ensure asset/capability packets cannot be duplicated by `tee` or shell temp
  files. The bytes may be inspectable, but ownership transfer must be anchored
  to object IDs, signer authority, and transaction-plan use refs.

### Phase 5 - DeFi demo

- Build minimal tokens, pool, swap, add-liquidity, farm stake endpoints.
- Satisfy the DeFi litmus tests in section 5.

### Phase 6 - Bloombook demo

- Build social objects, VFS projection, endpoint writes, voting, feeds, and
  pagination.
- Satisfy the Bloombook litmus tests in section 6.

## 8. Open questions

1. How much POSIX behavior do we want to support for executable VFS paths?
   FUSE/9P execution and shell redirection behavior may differ by platform.
2. Do we need an explicit transaction session path for complex DAG flows?
   Example:

   ```text
   /bloom/tx/new
   /bloom/tx/<id>/commands/...
   /bloom/tx/<id>/commit
   ```

   This may be more reliable than trying to infer every complex shell graph.
3. Should committed packet bytes be binary-only, or should every packet have a
   canonical text/debug view?
4. How should path permissions map to xDSA signer capabilities?
5. What is the first implementation target: local VFS-only execution, or
   chain-backed atomic execution?
6. Should Bloombook bodies be inline state initially, or content-addressed blobs
   with hashes in state?

## 9. Recommended next step

Implement the smallest vertical slice:

```sh
printf "title: Hello\n\nbody: First post" \
  | /bloom/social/communities/bloom/new

cat /bloom/social/communities/bloom/threads/latest/page/000000
```

Then implement a minimal asset pipe:

```sh
/bloom/wallets/me/assets/usdc/spend amount=100 \
  | /bloom/wallets/me/receive
```

These two slices prove:

- executable VFS endpoints;
- stdin/stdout endpoint ABI;
- canonical object writes;
- bounded paginated VFS projections;
- transaction-plan lowering;
- atomic commit/revert semantics.

