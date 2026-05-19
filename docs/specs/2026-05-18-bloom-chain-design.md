# bloom-chain — a sovereign BFT chain hosting wasm petals as smart contracts

**Status:** draft
**Date:** 2026-05-18
**Owners:** —
**Addresses:** The "ROOT" / chain half of the Bloom whitepaper, carved out
to a v0 scope: a small sovereign chain where onchain petals act as smart
contracts and a Uniswap-v2-style DEX runs on top. v1+ items (zkVM proofs,
score-weighted LOOM, invariant pruning, `/bloom` VFS, PQ-libp2p,
threshold-MPC keys) are explicitly deferred — see §2.

## 1. Goals

1. **A sovereign chain** with deterministic block production every 1s,
   fixed BFT validator set, honest-majority assumption.
2. **WASM petals as smart contracts.** Petals are already content-
   addressed wasm modules; this spec promotes the existing onchain mode
   to a real execution layer with persistent per-instance state,
   synchronous inter-petal calls, and EVM-style `state.read` /
   `state.write` host imports.
3. **xDSA-based identity end-to-end.** All bloom-chain accounts use
   Composite ML-DSA-65 + Ed25519 per whitepaper §Security. BLAKE3 is the
   single hash function across addresses, state commits, block hashes,
   and tx hashes.
4. **Native LOOM token** with flat per-block emission to validators in
   v0 (score-weighted, petal-based emission is deferred to v1+).
5. **A minimal RPC + CLI surface** sufficient to run a 4-validator local
   network and drive the DEX demo end to end.

## 2. Non-goals (v0)

- **zkVM execution proofs.** Validators re-execute; honest-majority
  assumption stands in for cryptographic verifiability. Tx format
  reserves an optional `execution_proof` byte field, `None` in v0,
  required in v1+.
- **Score-weighted LOOM emission to petals.** Block emission goes flat
  to the proposing validator + a small fee-sharing slice to the rest of
  the set (see §12). The full whitepaper formulae (utility / trust
  indices, effective petal count, halving curve) land in v1+.
- **Invariant / pruning / challenger workflow.** No staking on petals,
  no slashing, no governance. Defer to v1+.
- **`/bloom` VFS surface and namespaces.** No `chains/bloom/...` mirror
  in the existing bloom-eth VFS; no `/bloom/<address>` namespaces; no
  NFS mount of `/bloom`. Reachable purely via the new chain RPC + CLI.
- **PQ-safe libp2p fork.** Validators talk plain TCP with length-
  prefixed frames (§9). The transport is swap-shaped to take a real
  PQ-libp2p later.
- **Threshold-MPC keys.** Each validator and each user holds a single
  xDSA keypair.
- **Flash swaps, validator-set rotation, on-chain governance.** All
  v1+.
- **`chain.read_at` for onchain petals.** Removed; onchain petals are
  pure state-transition functions w.r.t. only their own chain. Offchain
  petals keep their existing capability set unchanged.
- **WASI clock / random.** Removed from onchain mode. Petals get
  `block.timestamp` / `block.number` / `block.prevhash` host imports
  instead. Wasmtime version pinned per chain epoch (§7.5).

## 3. System overview

The new code lands as four workspace crates, plus modifications to
`bloom-keystore` and `bloom-petals`:

| Crate | Role |
|-------|------|
| `bloom-chain-types` | Wire types: `Address`, `Hash`, `Tx`, `Block`, `BlockHeader`, `Vote`, `Proposal`, `StateRoot`. SSZ codecs. No I/O. |
| `bloom-chain-state` | Accounts trie + per-contract storage tries + state-blob store. Merkleized over BLAKE3. Snapshot / GC / load-from-blob. |
| `bloom-chain-consensus` | Tendermint-style BFT round driver, vote aggregation, proposer rotation, validator-set config, mempool. |
| `bloom-chain-node` | Wires consensus + state + petal-execution + TCP transport + RPC. Long-running `bloom chain run-validator` lives here. |
| `bloom-keystore` (modified) | New xDSA keystore alongside existing secp256k1. Algorithm-tagged keys; per-wallet selectable algorithm. |
| `bloom-petals` (modified) | New `link_chain_imports()` linker for the chain runtime: removes `chain.read_at`, adds `state.read/write`, `petal.call`, `block.*`, `msg.*`. Existing onchain/local modes retained for offchain use; the chain runtime is a third "chain" mode of the same VM. |

Top-level binary `bloom` gains a `chain` subcommand tree (§10).

The four chain crates form a layered stack:

```
                +----------------------------+
  CLI / RPC →   |     bloom-chain-node       |
                +----------------------------+
                  │           │            │
                  ▼           ▼            ▼
        +-----------+  +-----------+  +-----------+
        | consensus |  |   state   |  | petal VM  |
        | (Tendermint-|  |  (Merkle  |  | (bloom-   |
        |  style BFT) |  |   tries)  |  |  petals)  |
        +-----------+  +-----------+  +-----------+
                  │           │            │
                  ▼           ▼            ▼
                +----------------------------+
                |     bloom-chain-types      |
                +----------------------------+
```

## 4. Cryptography

### 4.1 Signatures: xDSA (Composite ML-DSA-65 + Ed25519)

Composite signatures per whitepaper §Security. A bloom-chain signature
is the concatenation of:

```
sig = ml_dsa_65_sign(sk_mldsa, m) || ed25519_sign(sk_ed25519, m)
```

A composite public key is `pk_mldsa || pk_ed25519`. Verification
requires both component signatures to verify. Failure of either part
fails the whole signature — there is no degraded mode.

Component sizes (FIPS 204 ML-DSA-65 + RFC 8032 Ed25519):
- pk_mldsa: 1952 bytes
- sk_mldsa: 4032 bytes (encoded form; can be derived from a 32-byte seed)
- sig_mldsa: 3309 bytes
- pk_ed25519: 32 bytes
- sk_ed25519: 32 bytes
- sig_ed25519: 64 bytes

Composite sizes: pk = 1984 B, sig = 3373 B. We accept the size cost in
v0; tx-level optimisations (BLS-style aggregation, sig truncation) are
v1+.

Rust deps (proposed):
- `fips204` crate (or `ml-dsa` from RustCrypto) for ML-DSA-65
- `ed25519-dalek` for Ed25519
- Both pinned in `Cargo.toml` workspace dependencies; version drift is
  a consensus-breaking change and gated by chain epoch (§7.5).

### 4.2 Hash: BLAKE3

Every hash on bloom-chain is BLAKE3-256 over a domain-separated input:

```
hash_kind(b) = BLAKE3("bloom-chain.v0." || kind || ":" || b)
```

Kinds: `addr`, `tx`, `block_header`, `state_root`, `petal`,
`storage_key`, `storage_value`, `code_root`, `accounts_root`,
`receipts_root`, `vote`, `proposal`.

### 4.3 Address derivation

```
address = blake3_addr(pk_composite)
```

A bloom-chain address is the full 32-byte BLAKE3 digest of the composite
public key with the `addr` domain. We do not truncate to 20 bytes;
solidity-compat is not a constraint, and the 32-byte form lets us reuse
the same digest as a hash-tree key without conversion.

Display form is base32 (RFC 4648 lower, no padding) with a four-char
checksum suffix, prefixed `b1`:

```
b1{base32(addr)}{checksum}
```

Total display length: 56 chars + 2 prefix. Round-trip is canonical.

### 4.4 Domain separation discipline

Every digest used as a key, identifier, or commitment carries a domain
tag in its preimage. We reject untagged BLAKE3 outputs across the chain
codebase via a wrapper type `Hash32` that only constructs via a domain-
specific helper.

## 5. Accounts and balances

### 5.1 Accounts trie

A single sparse Merkle tree keyed by `address`, valued at:

```rust
struct Account {
    nonce: u64,        // next tx nonce, monotonic
    loom: u128,        // native LOOM balance (smallest unit)
    code_hash: Option<Hash32>,  // None for EOAs; petal hash for contracts
    storage_root: Hash32,        // empty trie root for EOAs
}
```

The accounts trie is a 256-bit-wide sparse Merkle tree (256-ary
branching) with BLAKE3 hashing and the `accounts_root` domain. Empty
slots collapse to a fixed zero hash; only non-empty paths are stored.

Empty accounts (`nonce=0, loom=0, code_hash=None, storage_root=zero`)
are not materialised — they are spawned on first deposit / first
deployment and pruned on full withdrawal. EOA vs. contract is
distinguished only by whether `code_hash` is `Some`.

### 5.2 Nonces

Strict monotonic per account. A tx with `nonce != account.nonce + 1`
(or `nonce != 1` for a newly spawned account) is rejected at mempool
admit time and never enters a block. Re-submitting a tx with the same
nonce as a pending tx replaces it iff the new tx pays strictly more
fee.

### 5.3 LOOM unit

LOOM has 18 decimals. Smallest unit is `bloomweis` (1 LOOM = 10¹⁸
bloomweis). Genesis allocations and emission rates are expressed in
bloomweis everywhere on the wire.

### 5.4 Genesis

Genesis is a TOML file at `<bloom_home>/chain/genesis.toml`:

```toml
chain_id = "bloomchain.v0"
genesis_time_ms = 1747526400000

[[validators]]
address = "b1abcd...wxyz"
pubkey  = "{base64 composite pubkey}"
voting_power = 100

# ... three more validators

[[allocations]]
address = "b1dev1...0001"
amount  = "1000000000000000000000"  # 1000 LOOM

# ... more dev/test address allocations
```

`genesis_time_ms` becomes block 0's `header.timestamp`. The accounts
trie at block 0 is built deterministically from `[[allocations]]`; the
validator set at block 0 is built from `[[validators]]`. Total voting
power is the sum of `voting_power` fields (not normalised).

## 6. State model

### 6.1 Two Merkle trees per state root

A `StateRoot` is the BLAKE3 hash of two roots concatenated with the
`state_root` domain:

```
state_root = blake3("state_root:" || accounts_root || code_root)
```

- **`accounts_root`** — §5.1. Sparse Merkle tree of accounts; each
  account carries its own `storage_root` (§6.2), so per-contract
  storage is reachable transitively via this tree.
- **`code_root`** — sparse Merkle tree keyed by petal-hash, valued at
  raw wasm bytes (deduped — many contracts can share one code entry).

Receipts are **not** part of `state_root` — they are produced per
block, committed to the block header's separate `receipts_root`
field (§8.1), and discarded from the long-run trie after the 256-
block retention window (§6.3).

### 6.2 Per-contract storage

Each contract instance has an independent 256-bit-wide sparse Merkle
tree keyed by `bytes32` storage keys and valued at `bytes32` storage
words. The root is `account.storage_root`. Keys and values are opaque
to the chain — petals encode whatever they want in them.

Host imports `state.read(key) → value` and `state.write(key, value)`
operate on the current contract instance's storage tree. The runtime
materialises a write set during execution and atomically commits it on
successful return; reverts discard the write set.

### 6.3 State-blob storage

Full state is too large to broadcast each block. Instead:

- Every block produces a new `StateRoot`.
- The full state at that root is serialised to a content-addressed
  blob: a list of (path, leaf) entries plus the trie's intermediate
  hashes, BLAKE3-keyed. Blobs are immutable and named by their hash.
- Validators exchange blobs out-of-band over the gossip transport
  (§9), keyed by blob hash. New validators or restarted ones fetch
  the latest blob, verify it matches the block header's
  `state_root`, and resume.
- Each validator pins the **last 256 state blobs** (≈ 4 min of history
  at 1s blocks). Older blobs are GC'd.

The blob format is shape-compatible with what an IPFS / IPLD store
would accept later — that's the swap path the goal sets aside. v0
transport is plain TCP among validators.

### 6.4 State transition

For each tx `t` in a block, in order:

1. Verify signature; recover sender; check nonce.
2. Debit `t.max_fuel * t.fee_per_unit` LOOM from sender (provisional
   max-fee reservation).
3. Execute the tx — for a `Call` tx, invoke the target's petal under
   the chain runtime with the supplied calldata. The petal may issue
   nested `state.read/write/petal.call` ops. For a `Deploy` tx, create
   the new instance and call its `init` entry point. For a `Transfer`
   tx, no wasm runs.
4. On successful completion, refund unused fuel: credit
   `(max_fuel - fuel_consumed) * fee_per_unit` back to sender; credit
   `fuel_consumed * fee_per_unit` to the proposer's pending-fees
   account.
5. On revert, the entire write set is dropped, but the **full max-fee
   reservation is forfeited** to the proposer (no refund on revert in
   v0; revisit in v1).
6. Append a `Receipt` to the block's receipts list.

The order matters and is part of the consensus protocol. After all txs
are applied, the LOOM emission for the block (§12) is minted and
credited; then the new `state_root` is computed.

## 7. Transaction model

### 7.1 Tx kinds

```rust
enum TxKind {
    Transfer { to: Address, amount_loom: u128 },
    Deploy   { wasm: Vec<u8>, salt: [u8;32], init_args: Vec<u8> },
    Call     { to: Address, calldata: Vec<u8>, value_loom: u128 },
}
```

A `Tx` envelope wraps a `TxKind`:

```rust
struct Tx {
    chain_id: String,         // "bloomchain.v0"
    sender: Address,          // derived from pubkey, included for explicit binding
    nonce: u64,
    max_fuel: u64,
    fee_per_unit: u64,        // bloomweis per fuel unit
    kind: TxKind,
    pubkey: CompositePubKey,  // 1984 bytes, full composite
    sig: CompositeSig,        // 3373 bytes
}
```

`sender` is explicit (not recovered from sig) because xDSA verification
is more expensive than secp256k1 `ecrecover` and we want a sender to
check trivially first (lookup in accounts trie, nonce check) before
running the expensive composite verification. Mismatch between
`sender` and `blake3_addr(pubkey)` fails admission.

### 7.2 Canonical encoding: SSZ

All wire types — txs, blocks, votes, state-blob entries — encode as SSZ
(Simple Serialize, the consensus-layer Ethereum encoding). SSZ gives:
- A fixed canonical bytewise representation
- Built-in Merkleization for hash_tree_root
- A schema we can codegen Rust types for

Tx hash:

```
tx_hash = blake3("tx:" || ssz_encode(tx_without_sig))
```

The sig is excluded from the hash so that signing is a single
operation over the canonical pre-signed form.

### 7.3 Signing

```
sig = xdsa_sign(sk, blake3("tx:" || ssz_encode(tx_without_sig)))
```

The full `tx_hash` is what the user's xDSA key signs. Verification
recomputes the hash from the encoded tx-without-sig, recomputes the
sender address from the pubkey, and verifies both ML-DSA-65 and
Ed25519 components.

### 7.4 Mempool admission

A node admits a tx to its local mempool iff:

1. `chain_id` matches the local config.
2. `blake3_addr(pubkey) == sender`.
3. `nonce == accounts[sender].nonce + 1` (or 1 if account is new).
4. `sender.loom ≥ max_fuel * fee_per_unit + value` for Call/Transfer,
   or `... + 0` for Deploy (deploy fee is fuel-only).
5. xDSA signature verifies.
6. For `Deploy`: `wasm.len() ≤ MAX_WASM_BYTES` (256 KiB), wasm decodes,
   does not import any banned function (§7.6), exports an `init`
   entry point.

Admitted txs gossip among validators via the same TCP transport
(§9). Mempool is bounded per-sender (max 32 pending per address) to
prevent griefing.

### 7.5 Wasmtime version pinning

The exact wasmtime version is part of the chain spec at the epoch
level. Epoch transitions (defined by block number range) may upgrade
the runtime; until then, every validator must execute under the pinned
version. The genesis config carries the v0 wasmtime version string;
mismatch on startup is a fatal node error.

### 7.6 Host imports surface (chain mode)

The chain runtime exposes exactly these imports to onchain petals.
Anything else fails to instantiate the petal at deploy time:

| Import | Signature | Purpose |
|---|---|---|
| `state.read` | `(key_ptr, key_len, out_ptr) -> i64` | Read 32-byte value at key, writing into wasm memory at `out_ptr`; returns length (0 if key absent) or negative error. `key_len` must be exactly 32; per-key values are bytes32 (32 bytes exact). |
| `state.write` | `(key_ptr, key_len, val_ptr, val_len)` | Write value (must be ≤ 32 bytes; padded with zeros at left). `val_len = 0` is equivalent to `state.delete`. |
| `state.delete` | `(key_ptr, key_len)` | Clear key. |
| `petal.call` | `(target_ptr, target_len, calldata_ptr, calldata_len, value_lo, value_hi, retdata_ptr, retdata_max) -> i64` | Synchronous nested call. `value_lo`/`value_hi` carry a u128 LOOM amount. On success copies up to `retdata_max` bytes of callee retdata into wasm memory at `retdata_ptr` and returns the *true* retdata length (caller can detect truncation by comparing to `retdata_max`); on revert returns a negative error code and writes no retdata. |
| `petal.return` | `(data_ptr, data_len) -> !` | Set return data, exit successfully. |
| `petal.revert` | `(reason_ptr, reason_len) -> !` | Discard write set, exit with revert. |
| `block.number` | `() -> u64` | Current block number. |
| `block.timestamp` | `() -> u64` | Header timestamp (ms). |
| `block.prevhash` | `(out_ptr)` | Write 32-byte prev block hash. |
| `msg.sender` | `(out_ptr)` | Write 32-byte sender address. |
| `msg.value` | `() -> (lo:u64, hi:u64)` | Native LOOM passed with the call. |
| `msg.calldata.len` | `() -> u32` | Calldata size. |
| `msg.calldata.read` | `(dst_ptr, offset, len)` | Copy calldata slice. |
| `log.emit` | `(topic_ptr, topic_count, data_ptr, data_len)` | Append a log entry to the current tx's receipt. Host reads `topic_count * 32` contiguous bytes from `topic_ptr` — each topic is exactly 32 bytes. Callers using short selectors (e.g. DEX 4-byte BLAKE3 prefix per DEX spec §10) MUST left-zero-pad to 32 bytes guest-side before calling. |
| `crypto.blake3` | `(in_ptr, in_len, out_ptr)` | Convenience hash (deterministic; no state). |
| `host.deploy` | `(hash_ptr, hash_len, salt_ptr, salt_len, init_ptr, init_len, out_addr_ptr) -> i64` | Petal-initiated deploy. `hash` is a 32-byte BLAKE3 petal hash already present in the `code_root`; `salt` is 32 bytes; `init` is the calldata passed to the deployed petal's `init` entry point. On success, writes the 32-byte instance address to `out_addr_ptr` and returns 0. On error, returns a negative error code. Deployer-of-record (§7.7) is the **calling petal's address**, not the original tx sender. |

**Excluded** (rejected at deploy-time wasm validation): WASI `clock_*`,
`random_*`, `fd_*`, env, args, the original `bloom.vfs_*` and
`bloom.chain_read_at` imports.

### 7.7 Address derivation for deployed contracts

```
instance_address = blake3(
    "bloom-chain.v0.addr:" ||
    "deploy:" || deployer || ":" || salt || ":" || petal_hash)
```

This is the universal §4.2 domain-separation scheme applied with
`kind = "addr"` and inner payload `"deploy:" || deployer || ":" ||
salt || ":" || petal_hash`. `petal_hash` here is the BLAKE3 of the
canonical wasm bytes (same hash the existing petals store uses).
Collision means re-deploying with the same `(deployer, salt,
petal_hash)` re-targets the same address and is rejected if that
address already has `code_hash != None`.

For tx-level `Deploy` (§7.1), `deployer` is the tx sender. For
petal-initiated deploys via `host.deploy` (§7.6), `deployer` is the
calling petal's instance address — this is what makes the deployed-
address fully predictable from the calling contract's perspective and
enables CREATE2-style factory patterns. The original tx sender of the
enclosing transaction is still recorded in receipts.

### 7.8 init entry point

A deployable petal must export `init(calldata_ptr, calldata_len)` in
addition to its callable entry point `call(calldata_ptr, calldata_len)
-> i32`. `init` runs exactly once at deploy time, with `msg.sender` =
deployer, `msg.value` = whatever LOOM the deploy tx carried, and is
allowed to call `state.write` to set up initial storage.

### 7.9 Gas / fuel pricing

Each wasm operation costs wasmtime fuel per its native fuel-cost
schedule, plus a per-host-import surcharge:

| Op | Surcharge (fuel units) |
|---|---|
| `state.read` | 100 |
| `state.write` (new slot) | 5000 |
| `state.write` (existing slot) | 1500 |
| `state.delete` | 500 |
| `petal.call` (per call) | 5000 + callee's fuel |
| `log.emit` | 100 + 8 * data.len + 100 * topic_count |
| `crypto.blake3` | 50 + 4 * in.len |
| `host.deploy` | 10000 + callee's `init` fuel |

Numbers are v0 defaults; tunable in genesis. The runtime stops a tx
when fuel hits zero and reverts; the tx pays its full max-fee
reservation regardless.

## 8. Block model

### 8.1 Header

```rust
struct BlockHeader {
    chain_id: String,
    height: u64,
    parent_hash: Hash32,
    timestamp_ms: u64,
    proposer: Address,
    txs_root: Hash32,           // merkle root of tx hashes in this block
    state_root: Hash32,         // §6.1, post-application
    receipts_root: Hash32,
    validator_set_hash: Hash32, // commits to the active validator set
    fuel_used: u64,
    fuel_limit: u64,            // chain-level cap, e.g. 30M per block
}

block_hash = blake3("block_header:" || ssz_encode(header))
```

### 8.2 Body

```rust
struct BlockBody {
    txs: Vec<Tx>,
    last_commit: Commit,        // votes that finalised the parent
}

struct Commit {
    height: u64,
    block_hash: Hash32,
    votes: Vec<Vote>,           // ≥ 2f+1 precommit signatures
}

struct Vote {
    height: u64,
    round: u32,
    step: VoteStep,             // Prevote | Precommit
    block_hash: Option<Hash32>, // None = nil-vote
    validator: Address,
    sig: CompositeSig,          // over (height, round, step, block_hash)
}
```

A block is valid iff:
- Header fields are well-formed and `parent_hash` matches the previous
  block's hash.
- `txs_root`, `state_root`, `receipts_root` match the values computed
  by re-execution.
- `last_commit` contains votes from validators with combined voting
  power ≥ `2f + 1` (Tendermint quorum), all valid, all for the parent
  block's hash.
- `validator_set_hash` matches the active set at this height.
- `fuel_used ≤ fuel_limit`.

### 8.3 Receipts

```rust
struct Receipt {
    tx_hash: Hash32,
    status: ReceiptStatus,      // Ok | Reverted{reason: Vec<u8>}
    fuel_used: u64,
    logs: Vec<Log>,
    return_data: Vec<u8>,       // empty for Transfer/Deploy
}
```

`receipts_root` is the BLAKE3 Merkle root of `ssz_encode(receipt)` for
each tx, in tx order.

## 9. Validation boundary

Every block or consensus message entering a v0 node passes through one
narrow validation boundary BEFORE it reaches `ConsensusState` (the
per-validator state machine) or `apply_block` (the state-transition
function). The boundary is the single, exhaustive checkpoint where v0
authenticates inputs and refuses anything malformed, forged, or
out-of-context. Inside the boundary, code may assume the invariants
listed below hold; outside it, nothing is trusted.

This section enumerates the boundary; subsequent sections describe what
runs inside it.

### 9.1 What the boundary covers

#### (a) Signature verification

- xDSA signatures on `Vote` (Prevote / Precommit) and `Proposal` are
  verified at ingress against the declared validator's pubkey before the
  message can transition `ConsensusState`. See
  `crates/bloom-chain-consensus/src/auth.rs` (`verify_vote_sig`,
  `verify_proposal_sig`); the dispatch points are
  `crates/bloom-chain-node/src/node.rs::Frame::Vote` and `Frame::Proposal`.
- Outbound consensus messages are signed by `ConsensusEngine::sign_actions`
  in `crates/bloom-chain-consensus/src/engine.rs`. The engine is the
  single chokepoint — every `Action::Broadcast` returned by `step`,
  `maybe_propose`, `try_resume_pending_proposal`, or `enter_next_height`
  is signed before the caller sees it.
- Tx signatures are verified by the mempool admission path
  (`Mempool::admit` in `crates/bloom-chain-consensus/src/mempool.rs`)
  AND re-verified by the apply-time validation boundary
  (`validate_block_for_apply` in
  `crates/bloom-chain-node/src/consensus_driver.rs`) for every tx in
  every block, regardless of whether this node produced the block.
  Re-verification at apply is non-redundant: a malicious proposer can
  build a block out of txs that never traversed `Mempool::admit`, and
  catch-up sync receives whole blocks from peers without any prior
  admit step. Forged-sig and forged-sender txs are therefore caught at
  the boundary before any state transition runs.
- `tx.chain_id` equality with the local chain id is enforced inside
  the boundary for every tx in every committed block — rejecting
  cross-chain replay of a legitimately-signed tx into the wrong chain.
  The header `chain_id` check alone is insufficient because the
  proposer controls the header independently of the body.

#### (b) Block header / body root checks

- The header's `chain_id`, `proposer`, `validator_set_hash`, and
  `fuel_limit` are checked against this node's configured chain.
- `txs_root` is recomputed from `block.txs` and compared to the header;
  any tampering of the body forces a mismatch.
- `receipts_root` is recomputed from the receipts produced by replaying
  the block locally and compared to the header. A divergent state
  transition surfaces here.
- See `crates/bloom-chain-node/src/consensus_driver.rs::apply_block` and
  the catch-up path in `crates/bloom-chain-node/src/node.rs`
  (`Frame::BlockResponse`). Both paths share `apply_block`; catch-up
  does NOT take a faster route.

#### (c) Commit quorum

- Every block we apply (live or catch-up) carries a `Commit` of 2f+1
  matching precommits. Each precommit is xDSA-verified against its
  declared signer, signers must be unique members of the active
  validator set, and the total voting power must reach the 2f+1
  threshold.
- Every commit vote must satisfy `vote.round == commit.round`.
  Tendermint safety requires the 2f+1 quorum to come from a single
  (height, round) tuple — locking and the line-of-prevotes argument
  break otherwise. An attacker who collects one valid precommit per
  round across rounds 0..n for the same `block_hash` and assembles
  them into a single `Commit` must be rejected; this enforcement is
  inside `validate_block_for_apply`.
- An empty-commit body (the proposer's initial dissemination of its own
  block, before round precommits land) is recognised and explicitly
  skipped by the catch-up apply path; only the consensus state machine
  may admit a block with an empty commit, by collecting 2f+1 precommits
  itself.

#### (d) Parent / height continuity

- `block.header.parent_hash` must equal the `block_hash` of the locally
  stored block at `block.header.height - 1`. Catch-up requests refuse
  to apply forward-gap blocks.
- `block.header.height` must equal `engine.height()` exactly at
  apply-time. Replays of already-applied heights are dropped.
- `ConsensusState::on_proposal` refuses to transition to Prevote until
  the proposed `block_hash` is present in `engine.blocks`; unknown-block
  proposals are stashed (`ConsensusState.pending_proposal`) and replayed
  by `try_resume_pending_proposal` once the block frame arrives. This
  closes the "prevote a block we have not validated" hole.
- `enter_next_height` retains blocks for heights ≥ `new_height` to
  avoid wiping the body of the next proposal that arrived ahead of the
  height transition.

#### (e) Tx sender derivation

- `Address` derivation uses one canonical domain tag — `bloom-chain.v0.addr:`
  — defined by `Address::from_pubkey_bytes` in
  `crates/bloom-chain-types/src/types.rs`. The same function is used by
  `bloom-keystore::xdsa` (account-creation) and the chain validation
  path.
- `Mempool::admit` rejects any tx whose declared `sender` is not
  `Address::from_pubkey_bytes(tx.pubkey)`. The check runs after sig
  verify; without it, a valid signature over a forged `sender` would
  pass.
- `apply_block` re-derives the sender for every tx and compares,
  closing the gap for blocks that bypass the local mempool.

#### (f) State-transition output integrity

- Per-tx ordering inside `apply_block_state_transitions`
  (`crates/bloom-chain-node/src/consensus_driver.rs`): the executor's
  `output.write_set` is applied BEFORE refund credit and proposer fee
  credit, so the absolute-set write_set entries cannot clobber the
  settlement balances. `WriteSet` is absolute, not delta — see
  `crates/bloom-chain-state/src/state.rs`.
- Nested `petal.call` and `host.deploy` snapshots are checkpointed
  (`StateSnapshot::clone` before the inner call); on revert, trap, or
  out-of-fuel, the parent's snapshot is restored from the checkpoint,
  not from the mutated child. Reverted child writes and value transfers
  can never leak into the parent, regardless of whether the parent
  inspects the return code.
- Wasm runtime is bounded by a `wasmtime::ResourceLimiter`
  (`ChainLimiter` in `crates/bloom-petals/src/chain_vm.rs`): per-store
  memory growth cap, table cap, and instance / memory / table count
  caps. Static-validation bounds at module load are augmented with this
  runtime cap so a `memory.grow` cannot escape.
- Reverts surface uniformly: the single authoritative revert path is
  `ChainCallOutput { revert_reason: Some(_) }` returned by
  `run_chain_call`; `PetalExecutor` consumes that and emits a failed
  receipt. The `Err` arm is reserved for genuine engine faults
  (traps, out-of-fuel, link errors).
- `StateSnapshot::get_code` consults the in-flight `WriteSet::code`
  staged map before falling back to the committed `CodeStore`, so
  same-tx deploy-then-call patterns work and `init` may call back into
  its own freshly-staged code. Snapshots do not share staged code
  across siblings.

### 9.2 Restart replay

A node that restarts re-enters the boundary for every block in
`block_store` it has not yet replayed onto the in-memory state. The
replay walks blocks in height order, calling the same
`apply_block_state_transitions` as live consensus — there is no separate
"warm-replay" path that could drift. Transfers, deploys, storage
writes, fee accounting, receipts, and code installs are all
reconstructed by replaying the canonical tx effects, not by reading any
out-of-band proposer emission log.

### 9.3 What is NOT inside the boundary

- The mempool ordering / fairness policy is policy, not validation: a
  block with a "bad" tx ordering produces the same boundary verdict as
  a well-ordered one. Per-sender nonce contiguity inside a block IS a
  boundary check (`apply_block` rejects a block that contains nonce N+1
  for a sender without nonce N), but the mempool selector enforces the
  same contiguity proactively to avoid wasted blocks.
- Wasm gas / fuel accounting is a state-transition concern, not a
  validity concern. A block whose txs collectively consume more than
  `fuel_limit` is rejected at the boundary; per-tx fuel accounting is
  re-derived inside `apply_block`.
- Network framing (`Frame::*` SSZ wire format) is checked by the
  transport layer, not the boundary. Malformed frames are dropped before
  reaching the boundary.

### 9.4 Operational consequences

- New consensus message types or new on-chain effects MUST extend the
  boundary explicitly. Adding a "trusted fast path" that bypasses any
  of (a)–(f) is a regression and must not pass review.
- Adversarial regression tests live in
  `crates/bloom-chain-consensus/tests/` and
  `crates/bloom-chain-node/tests/`. Each fix that re-establishes a
  missing boundary check ships with a test that fails on master and
  passes on the post-fix branch; see the file index in those directories
  for the current set.

## 10. Consensus: Tendermint-style BFT over a fixed set

### 10.1 Validator set

Fixed at genesis. Each validator has an `Address`, a `CompositePubKey`,
and a `voting_power` (u64). Total power `Vt = Σ vp_i`. BFT quorum is
`2 * Vt / 3 + 1`. Rotation is v1+.

### 10.2 Round structure

For each height `h`:
1. **Propose** (timeout 500 ms): the proposer for `(h, round)` —
   round-robin by validator index modulo set size, advancing within a
   height on timeout — broadcasts a `Proposal{height, round, block,
   proposer_sig}`.
2. **Prevote** (timeout 500 ms): every validator broadcasts a
   `Vote{step=Prevote}` for the proposed block hash, or nil if the
   proposal was invalid or absent.
3. **Precommit** (timeout 500 ms): if a validator saw `2f+1` prevotes
   for the same hash, it broadcasts `Vote{step=Precommit}` for that
   hash; else nil-precommit.
4. **Commit**: if `2f+1` precommits arrive for the same hash, the
   block is final. That set of precommits becomes the next block's
   `last_commit`. Otherwise, round increments and step 1 repeats with
   the next proposer.

Block cadence is 1s in the steady state. A round takes ~1.5s at
worst-case timeouts; rounds are not required to complete inside one
second of wall clock. If the network is healthy, propose → prevote →
precommit → commit happens well inside the slot.

### 10.3 Locking

A validator that precommits for a block at `(h, r)` locks on that
block: it must prevote for the same block at `(h, r+1, r+2, ...)`
unless `2f+1` prevotes for nil unlock it. Standard Tendermint locking
rules apply; the spec follows Buchman 2016 ("Tendermint: Byzantine
Fault Tolerance in the Age of Blockchains") chapter 3.

### 10.4 Safety / liveness

Safety: no two blocks at the same height can both gather 2f+1
precommits (standard Tendermint argument). Liveness: in the partially
synchronous model under honest-majority and bounded message delay,
some round eventually completes. v0 assumes honest validators and a
healthy network — under crashes or partitions, the chain halts rather
than forks.

### 10.5 Mempool & block construction

The proposer for height `h` selects up to `fuel_limit / min_tx_fuel`
txs from its local mempool, ordered by `(fee_per_unit DESC, nonce ASC
per sender)`. Txs are sequentially applied during the propose step to
fill `state_root` and `receipts_root`. Mempool sync between
validators uses the same TCP gossip transport.

## 11. Networking

### 11.1 Transport

Plain TCP. Each validator listens on a configured port; the validator
set in genesis includes each validator's `(addr, host:port)`.
Validators maintain persistent connections to every other validator,
reconnecting with exponential backoff on drop.

### 11.2 Framing

Length-prefixed frames:

```
+---------+----------+----------+----------------+
| 4 bytes | 1 byte   | 32 bytes | <len> bytes    |
| len     | msg_type | digest   | payload (ssz)  |
+---------+----------+----------+----------------+
```

`digest = blake3("frame:" || msg_type || payload)`. Receivers verify
the digest before parsing the payload — a corrupted frame is dropped
without attempting SSZ decode (cheap denial of trash before expensive
decode).

`msg_type` values: 0 Proposal, 1 Vote, 2 Tx, 3 BlockRequest,
4 BlockResponse, 5 StateBlobRequest, 6 StateBlobResponse, 7 Ping,
8 Pong.

### 11.3 Sync

A starting node loads genesis, then requests the chain head from a
peer (`BlockRequest{height: latest}`), walks forward applying blocks
and fetching state blobs only at checkpoints (every 64 blocks) to
bound replay cost. v0 assumes all validators are bootstrapping from
the same genesis; non-validator client sync is a v1 concern.

### 11.4 Future: PQ-libp2p

The transport is a single `Transport` trait in `bloom-chain-node`.
Swapping to a PQ-libp2p fork later is a one-implementation change
behind the same trait. Encryption-in-transit is not provided in v0 —
TCP only — because validators are running in trusted environments per
the honest-validator assumption. Adding noise-protocol or TLS later
does not change consensus semantics.

## 12. LOOM emission and fees

### 12.1 Per-block emission

A fixed `B0 = 10 LOOM` (10 * 10^18 bloomweis) is minted at the end of
every block and credited to the proposer of that block. v0 ignores
the whitepaper's halving / utility-weighted / trust-weighted formulae
entirely.

### 12.2 Fee accounting

Tx fees (fuel × price) accrue to the proposer. There is no fee
sharing with other validators in v0 — proposing is the only way to
earn LOOM, which under round-robin rotation is uniform across the
set anyway. v1 adds fee sharing and score-weighted distribution to
petals.

### 12.3 Burning

No burning in v0. (Whitepaper §LOOM has burning as part of slashing
and challenger arbitration, both deferred.)

## 13. CLI surface

All under `bloom chain`:

```
bloom chain init [--genesis FILE]            # create a fresh node home
bloom chain run-validator [--config FILE]    # long-running validator
bloom chain submit <tx_file_or_->            # submit a signed tx
bloom chain deploy <wasm_or_wat> [--init-args HEX] [--salt HEX]
                                              # build + sign + submit a Deploy tx
bloom chain call <addr> <calldata_hex> [--value LOOM] [--max-fuel N]
                                              # build + sign + submit a Call tx
bloom chain query account <addr>             # JSON: nonce, balance, code_hash, storage_root
bloom chain query block <height_or_hash>     # JSON: header + tx hashes
bloom chain query tx <hash>                  # JSON: tx + receipt
bloom chain query state <addr> <key_hex>     # raw storage value
bloom chain ls-validators                    # JSON: current validator set
```

The `run-validator` subcommand binds the consensus port + RPC port
(default 26656 / 26657, configurable). Other subcommands talk to a
running node over RPC; the RPC channel is a UDS socket under
`<bloom_home>/chain/rpc.sock` by default with the same JSON-RPC
framing as the existing daemon IPC.

## 14. Interaction with existing bloom-eth surfaces

- **Wallet keys.** Existing `bloom wallet` commands gain an
  `--algo {secp256k1,xdsa}` flag. xDSA is the default for newly created
  wallets; secp256k1 is opt-in for Ethereum-interop wallets. A wallet
  holds one algorithm; multi-algo wallets are v1+.
- **Keystore on disk.** Format extends with an `algorithm` field; old
  files (no field) default to secp256k1 for backward compat. Argon2id
  + chacha20poly1305 envelope is reused; the contents differ per algo.
- **Daemon.** No changes to the existing daemon. `bloom chain
  run-validator` is a separate long-running process from `bloom
  serve`. They share `<bloom_home>` but no in-process state.
- **VFS.** No `chains/bloom/` surface in v0 (explicit non-goal). All
  chain interaction is via `bloom chain ...` subcommands or direct RPC.

## 15. Storage layout

```
<bloom_home>/chain/
├── genesis.toml                  # immutable; consensus-critical
├── config.toml                   # local: listen addr, peer list, log level
├── keystore/<validator>.xdsa     # encrypted validator signing key
├── blocks/                       # height → block (SSZ)
├── state_blobs/<blob_hash>       # content-addressed state snapshots
├── state_index.sqlite            # height → (state_root, blob_hash)
├── mempool.sqlite                # pending txs by (sender, nonce)
└── rpc.sock                      # UDS for client subcommands
```

`blocks/` is rolling-window pruned after 2× the state-blob retention
(512 blocks) — old blocks are recoverable from any peer that's still
pinning them.

## 16. v0 acceptance

A local 4-validator network on one machine:
1. `cargo run -p bloom -- chain init` × 4 with shared genesis.
2. `cargo run -p bloom -- chain run-validator` × 4, each on its own
   port, peering with the other three.
3. Wait for block 5 (≈ 5s) → assert all four nodes converged on the
   same `state_root` at height 5.
4. Run `tests/chain/dex_demo.rs` which:
   a. Deploys the factory petal at address `F`.
   b. Deploys two ERC-20 petals (`A`, `B`) with initial supplies.
   c. Calls `factory.create_pair(A, B) -> P`.
   d. Approves the pair `P` to spend caller's `A` and `B`.
   e. Calls `router.add_liquidity(A, B, …)`; asserts LP balance > 0.
   f. Calls `router.swap_exact_tokens_for_tokens(A, B, …)`; asserts
      output amount matches `x*y=k` formula minus 0.3% fee.
   g. Calls `router.remove_liquidity(…)`; asserts roundtrip ≈
      original (within slippage / fee tolerance).
   h. Reads all balances and `state_root`; asserts post-swap
      `x*y ≥ pre-swap x*y` (CPMM invariant up to fees).
5. Assert LOOM accounting balances: `sum(balances) + sum(pending
   fees) = sum(genesis allocations) + 10 LOOM * blocks_produced`.

## 17. Open questions / future work

- **Validator-to-non-validator sync.** v0 hand-waves this; a real
  light-client / RPC-follower mode is v1.
- **Empty-block policy.** v0 produces an empty block if mempool is
  empty. Worth revisiting (skip-blocks, batched empties) once we have
  metering data.
- **State-blob format.** v0 uses raw SSZ of the entire trie. IPLD /
  CAR migration is in the swap path but unspecified beyond that.
- **Reorg handling.** v0 BFT does not reorg by construction (locking +
  honest majority ⇒ no two finalised blocks at same height). v1+
  validator rotation / fork-choice rules will need to revisit this.
- **Per-import fuel costs (§7.9)** are placeholders; we should
  benchmark each on the actual demo workload before locking.
- **`petal.call` reentrancy.** Allowed in v0 — the runtime maintains
  a depth counter capped at 16. Petals must implement their own
  reentrancy guards (`state.read/write` of a lock flag); v0 ships a
  ReentrancyGuard library petal that v2-style pair contracts use.
- **Native LOOM vs. token-contract LOOM duality.** v0: LOOM lives only
  in the accounts trie; petals cannot mint LOOM. A wrapped-LOOM ERC-20
  petal (so that DEX pairs can include LOOM-as-token) is part of the
  DEX spec, not this one.
