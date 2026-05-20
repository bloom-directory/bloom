# Bloom-native contracts: design

**Status:** draft
**Date:** 2026-05-20
**Owners:** Joshua Richardson
**Supersedes (eventually):** `docs/specs/2026-05-19-contract-macro-v2.md`,
`docs/specs/2026-05-20-bloom-rust-contracts.md`,
`docs/specs/2026-05-18-bloom-dex-design.md`.

This spec defines a second, Bloom-native contract framework that replaces
the EVM-flavored surface in the current `bloom-contract*` crates and the
DEX example. It is built around **linear-typed objects**, **declarative
PTB-style transactions**, **type-defining module petals** (no per-instance
contract state), **capability-based authorization** (no `msg.sender`),
**runtime-checked invariants**, and **path-resolved petal references**.

The current `bloom-contract` stack and the existing `examples/dex/*` +
`examples/wloom` crates stay in the workspace, marked transitional, until
the new framework reaches parity. The chain gains a new tx kind and a
new host-import surface alongside the existing ones; nothing already shipped
is removed in v0.

This design takes Option 2 from the brainstorming session ("execution model
+ macros") while leaving room for Option 3 ("petals-everywhere") later —
the object/PTB surface is the same shape onchain and offchain; only the
runtime that backs the host imports differs.

## 1. Goals

1. **Eliminate EVM tech debt** — no `approve` / `transferFrom`, no reentrancy
   guards, no `u256` for token amounts, no `msg.sender`, no factories, no
   wrapped-native asset, no synchronous nested calls.
2. **One asset vocabulary** — `Coin<phantom T>` (and the broader object
   model) covers LOOM, every fungible, every LP token, every NFT, every
   capability. No special cases for native value.
3. **Atomic, auditable transactions** — a tx is a declarative bundle that
   wallets, agents, and the `/bloom/core/canopy` adversarial model can
   inspect fully before the user signs.
4. **Bloom-paper alignment** — petals are referenced by VFS path with
   optional hash pinning, invariants are a first-class manifest item,
   the same code surface is reusable offchain.
5. **Modular DEX** — pools are parameterized by swap strategy; the v0
   strategy is constant-product, but the chain knows nothing about it.
   New strategies (stable, weighted, RFQ, hooks) land as additional
   petals without chain changes.
6. **Clean coexistence** — the existing `bloom-contract` framework, the
   existing chain spec, and the existing docker DEX e2e all stay green
   throughout. The new framework lives alongside until parity.

## 2. Non-goals (v0)

- **Parallel PTB scheduling.** The object versioning enables it; the
  scheduler does not ship yet. v0 executes PTBs serially.
- **Resolution policies.** Path resolution requires an explicit hash pin
  in v0 (the policy schema is reserved but not consulted).
- **zkVM execution proofs.** The new host imports are designed to be
  zk-friendly; no proof generation in v0.
- **Concentrated liquidity / hooks.** The strategy interface is shaped
  to support them; only CPMM ships in v0.
- **Petals-everywhere unification.** The same object/PTB surface is
  designed to be usable offchain, but the offchain runtime stub is v1+.
- **Cross-chain / bridging.** Out of scope.
- **Replacing the existing `bloom-contract` stack.** It stays as a
  transitional layer; deprecation is a separate decision after parity.
- **Petname / VFS user-facing surface.** PTBs reference petals by VFS
  path, but the path↔name UX layer is `bloom-vfs` / wallet concern,
  not this spec.

## 3. Architectural overview

Three primitives:

- **Petal** — a content-addressed wasm module. Defines object types and
  functions over them. Has *no* per-instance state. Looked up by content
  hash; addressable by VFS path. Replaces "contract instance at an address."
- **Object** — a typed value with `id`, `owner`, `version`, `payload`.
  Linear: every object produced in a PTB must be consumed by tx-end.
  Categories: *owned* (single account owner), *shared* (consensus-coordinated,
  any signer can act on it via inclusion in a PTB), *immutable* (frozen
  after creation, world-readable).
- **PTB** (Programmable Transaction Block) — typed list of commands with
  one or more signers. Outputs of earlier commands feed inputs of later
  ones. Atomic. Replaces "call a contract with calldata, get returndata."

### 3.1 What this kills

| EVM-flavored thing | Replacement |
|---|---|
| `approve` / `transferFrom` | Pass `Coin<T>` objects into the PTB |
| `msg.sender` | `&Signer` args + capability objects |
| Reentrancy guards | Linear types + atomic PTBs make reentrancy non-expressible |
| `u256` token amounts | `u128` for all fungible amounts (LOOM is already u128) |
| Factory + CREATE2 | `Type::new(...)` returns an object; no deploy step |
| WETH-style wrapping | `Coin<LOOM>` is a regular `Coin<T>` |
| 4-byte selector dispatch | Typed PTB commands; functions identified by `(petal, name)` + signature check |
| Per-contract storage slots | Object store, typed records keyed by `ObjectId` |
| Nested synchronous calls | PTB commands; outputs flow forward via use-references |
| `msg.value` plumbing | LOOM is just another `Coin<T>` |

### 3.2 What this preserves

- 32-byte post-quantum addresses (chain spec §4.3) for *signers* / *owners*
- BLAKE3 hashing everywhere
- The current consensus engine, mempool, validator set, fuel accounting model
- The wasm VM (wasmtime + deterministic fuel)
- The existing `Deploy` tx kind keeps working for legacy petals
- The existing `Call` tx kind keeps working for legacy petals
- Per-version content addressing of wasm petals

## 4. Object model

### 4.1 Object structure

```
Object {
  id:         ObjectId,        // 32-byte BLAKE3 of (creator_petal_hash, type_tag, creation_nonce)
  type_tag:   TypeTag,         // petal_hash::TypeName + type-arg vector
  owner:      Owner,           // Address(addr) | Shared | Immutable | Object(parent_id)
  version:    u64,             // increments on every mutation
  payload:    Vec<u8>,         // typed encoding per type_tag
}
```

The `payload` is encoded by the petal that defined the type, via the
`bloom-chain-abi` canonical codec (already specified in chain spec
§7.10.1). Types may nest other objects by-id (not by-value); the chain
walks ownership to enforce linearity.

### 4.2 Object abilities

Each object type declares abilities (compile-time constraints, in the
spirit of Move):

- `key` — has an `id`, can be a top-level object in the store
- `store` — can be nested inside other objects (held by-id)
- `copy` — can be cloned (rare; used for `Capability<T>` types you want
  duplicable like a public read-key, never for value-carrying objects)
- `drop` — can be silently dropped (rare; used for hot-potato patterns)

Default: `key + store`, no `copy`, no `drop`. Coins and pools have these
defaults. Capabilities are typically `key + store + copy` if duplicable,
`key + store` otherwise.

### 4.3 Ownership categories

- **Owned** (`Owner::Address(addr)`) — only the owner can pass the
  object as a `&mut` arg in a PTB. Transfer changes owner.
- **Shared** (`Owner::Shared`) — any signer can pass it as a `&mut`
  arg. Version checked at PTB validation to detect concurrent edits.
  This is how pools, registries, and global state work.
- **Immutable** (`Owner::Immutable`) — read-only forever; can be passed
  as `&` arg by any caller. Used for frozen configs and on-chain
  reference data.
- **Object-owned** (`Owner::Object(parent_id)`) — owned by another
  object. Mutations to the child require mutable access to the parent.
  Lets a `Pool<A,B>` "own" its reserve coins, an LP-position object,
  etc.

### 4.4 Linearity

The PTB executor tracks every object it creates, takes, or borrows.
At tx-end:
- Every object produced by some command and not consumed by another
  command must be either transferred, deposited into another object,
  destroyed via a `delete` call on its defining petal, or shared/frozen.
- Borrows (`&Pool`, `&mut Pool`) end with the command that took them;
  the underlying object remains in the store.
- Coin merging is the canonical "consume two, produce one" example.

Linearity errors (orphan objects) are detected before commit; the PTB
reverts with `LinearityViolation(object_id)`.

### 4.5 Object store

The object store replaces the per-account sparse-Merkle-tree of 32-byte
slots in chain spec §6.2 for any account that holds objects under the
new model.

- Primary index: `ObjectId → Object`
- Secondary index: `Owner → [ObjectId]` (for "what does Alice own?")
- Type index: `TypeTag → [ObjectId]` (for "list all pools")

Indices are kept under their own Merkle commitments and folded into the
chain state root.

Legacy accounts (those with `code_hash != None` deployed under the old
`Deploy` tx kind) keep their existing storage trie. New deploys use the
object store.

## 5. Capabilities

A capability is just an object whose type carries proof-of-authority
semantics:

```rust
pub struct MintCap<phantom T> has key, store {
    id: UID,
    // optionally: max_amount, expiry, scope...
}
```

Possession of a `&MintCap<USDC>` in a PTB command authorizes minting
USDC. The capability can be transferred (it's just an object), locked
into another object, scoped via fields, expired via block-number checks.

Common capability shapes:
- `OwnerCap<Pool>` — admin of a pool (change strategy params, etc.)
- `MintCap<T>` — mint authority for a fungible
- `BurnCap<T>` — burn authority
- `Witness<T>` — one-shot proof that some action happened (linear, no `copy`)
- `Session<T>` — time-bounded delegation (agent session keys)

Capabilities are minted by petal functions at type-creation time
(e.g. `fungible::create_currency<T>` returns `(MintCap<T>, BurnCap<T>)`)
and are otherwise just objects.

## 6. Authorization (replaces `msg.sender`)

Functions declare auth requirements in their argument types:

```rust
// requires that the named signer signed this PTB
fn withdraw<T>(signer: &Signer, vault: &mut Vault<T>, amount: u128) -> Coin<T>;

// requires holding a typed capability
fn mint<T>(cap: &MintCap<T>, amount: u128) -> Coin<T>;

// no auth — pure read
fn quote<A, B>(pool: &Pool<A, B>, amount_in: u128) -> u128;

// auth = owning the object you pass as &mut (implied by ownership rules)
fn split<T>(coin: &mut Coin<T>, amount: u128) -> Coin<T>;
```

There is no `msg.sender`. There is no "the contract is calling me."
Every function knows exactly why it is executing — because of these
signers + these capabilities + these owned-object accesses.

The PTB's `signers` field is a vector of post-quantum xDSA public keys
(chain spec §4.2); each `Signer(i)` reference in a command resolves to
the `i`-th signer. The chain verifies one xDSA signature per distinct
signer (not per command).

## 7. PTBs (Programmable Transaction Blocks)

### 7.1 Wire format

```
PtbTx {
  signers:           Vec<PqPubkey>,            // 32B each
  commands:          Vec<Command>,
  gas_budget:        u64,                      // max fuel
  gas_price:         u128,                     // LOOM per fuel unit
  expiry_block:      u64,                      // tx invalid after this block
  signatures:        Vec<PqSignature>,         // one per signer over the PTB hash
}

Command =
  | Move(MoveCmd)
  | Publish(PublishCmd)              // upload a new wasm petal under a path
  | TransferObjects(Vec<Use>, Owner)
  | MergeCoins(Vec<Use>)             // type-checked sugar for Coin<T>
  | SplitCoins(Use, Vec<u128>)
  | MakeMoveVec(TypeTag, Vec<Use>)
  | UpgradePetal(UpgradeCmd)         // see §10

MoveCmd {
  petal:    PetalRef,                // (path, Option<content_hash>)
  function: String,                  // function name within the petal
  type_args: Vec<TypeTag>,           // generic instantiation
  args:     Vec<Arg>,
}

Arg =
  | Signer(u16)                      // index into signers
  | Const(Vec<u8>)                   // canonical-codec-encoded literal
  | Object(ObjectId, ExpectedVersion, AccessMode)  // existing object
  | Use(CommandIndex, ResultIndex)   // result of an earlier command
  | TypeArg(TypeTag)                 // pass a type as a value

AccessMode = ReadOnly | Mutable | Consume

PetalRef {
  path:     VfsPath,                 // e.g. "/bloom/dex/pool"
  hash:     Option<ContentHash>,     // explicit pin (v0: required)
}
```

`Publish` and `UpgradePetal` are PTB-level commands so petal management
participates in the same atomic + auth model as everything else; they
are not special tx kinds.

### 7.2 Validation pipeline (chain-side, in order)

1. **Signature check.** One xDSA verify per distinct signer over
   `blake3("bloom-ptb.v0:" || canonical_encoding(PtbTx without signatures))`.
2. **Expiry.** `current_block <= expiry_block`.
3. **Petal resolution.** For each `PetalRef`: in v0 the `hash` field is
   required; chain verifies the wasm at `path` resolves to that hash
   (or fetches by hash if the path is unset). Future: consult resolution
   policy.
4. **Function-signature typecheck.** Each command's `args` typecheck
   against the petal's declared function signature, including generic
   instantiation. No 4-byte selector dispatch — the function is looked
   up by name, and the typed args must match exactly.
5. **Object version + access check.** Each `Object(id, expected_version,
   mode)` arg: load the object, verify `version == expected_version`,
   verify `mode` is permitted (Owned objects: only the owner can take
   Mutable or Consume; Shared: any signer can take Mutable; Immutable:
   ReadOnly only).
6. **Gas reservation.** Reserve `gas_budget * gas_price` LOOM from the
   first signer's `Coin<LOOM>` (canonical "gas-payer" object — see §9).
7. **Execute commands in order.** Each command runs in the wasm VM with
   typed args; outputs are linearly tracked.
8. **Invariant check.** After every `MoveCmd`, run that function's
   declared invariants over its `&mut` args. Violation = revert.
9. **Linearity check.** At tx-end, every object produced by some command
   must be consumed by another command or transferred / shared / frozen
   / deleted.
10. **Commit.** Apply object writes, version bumps, ownership changes;
    emit receipt.

Any failure between (1) and (10) reverts the entire PTB. Gas-reservation
failures forfeit the reserved amount to the proposer (anti-DoS); other
failures refund unused gas.

### 7.3 Execution semantics

- Commands execute sequentially in declaration order.
- A `Use(i, j)` references the `j`-th return value of command `i`.
- Within a command, the wasm VM has no access to other commands' values —
  only to its own arguments. The PTB executor manages the value flow.
- Cross-petal calls *inside* a single command's wasm execution are
  permitted (a function can call another petal's function via a host
  import) but discouraged — the canonical composition primitive is the
  PTB itself. Cross-petal inner calls follow the same auth model.

### 7.4 Read-only / dry-run

The PTB encoding is fully analyzable offchain. The same wasm functions
can run against a state snapshot to produce expected outputs without
committing. Wallets and the paper's `/bloom/core/canopy` adversarial
model use this to simulate before signing.

## 8. Petal manifest

The wasm custom section format is extended (additively) over the current
`bloom-contract-metadata` schema. New manifest items:

- `module_path: String` — the canonical `/bloom/...` install path
- `parent_version: Option<ContentHash>` — for upgrade lineage
- `object_types: Vec<ObjectTypeDecl>` — name, abilities, field schema
- `functions: Vec<FunctionDecl>` — name, generics, arg types, return types,
  required signer count, required capabilities, declared invariants
- `capability_types: Vec<CapabilityDecl>`
- `invariant_predicates: Vec<InvariantDecl>` — declared name, target
  type/function, predicate AST, wasm export name for the runtime check
- `required_host_imports: Vec<String>` — must be a subset of the
  chain-allowed import list

The existing manifest items (`abi_methods`, `storage`, `events`,
`errors`) are kept for legacy compatibility but become empty for petals
that opt into the new model via `#[bloom::petal]` (see §11).

## 9. Native LOOM unification

LOOM becomes `Coin<LOOM>` — a regular `Coin<phantom T>` from the
fungible petal at `/bloom/core/fungible`. Concrete impact:

- **Genesis** allocates a single `Coin<LOOM>` object to each initial
  holder. The accounts trie's `loom: u128` field on `Account` becomes
  derived (sum of LOOM coins owned by the address).
- **Gas payment** uses a designated `Coin<LOOM>` referenced in the PTB
  as the *gas-payer object*. The reserved amount is split off pre-execution;
  the change object is created post-execution.
- **`msg.value` semantics** no longer exist. To pay value, you pass a
  `Coin<LOOM>` argument into the function.
- **wLOOM goes away.** Any swap that wants to trade LOOM for USDC just
  passes a `Coin<LOOM>` into `pool::swap`.
- **The fungible petal at `/bloom/core/fungible` is the same one used
  for every other token.** No special petal for native value.

Legacy accounts (those interacting via the old `Call` tx kind) continue
to see the `loom: u128` view via a compatibility layer that re-aggregates
their `Coin<LOOM>` objects on read.

## 10. Petal publishing and upgrades

A petal is published via a `Publish` command inside a PTB:

```
Publish {
  wasm_bytes:    Vec<u8>,
  module_path:   VfsPath,                  // e.g. "/bloom/dex/pool"
  publisher_cap: Option<Use>,              // OwnerCap<Path> if path already exists
  signer:        SignerRef,                // pays for the publish
}
```

First-time publishes at a path mint an `OwnerCap<Path>` capability to
the publisher signer. Subsequent `UpgradePetal` commands at the same
path require a `&OwnerCap<Path>` argument. The cap is itself just an
object — transferable, lockable, burnable.

This makes petal lifecycle a normal object/capability flow rather than
a privileged chain primitive. It also gives the staking / pruning system
a clean target: the `OwnerCap<Path>` is what gets slashed.

## 11. Macros and developer surface

A new crate `bloom-resource-macros` provides:

```rust
#[bloom::petal(path = "/bloom/dex/pool")]
pub mod pool {
    use bloom_resource::{object, capability, Signer, Coin, UID};
    use bloom_fungible::{Coin, MintCap};

    #[object(abilities = "key, store")]
    pub struct Pool<phantom A, phantom B> {
        id: UID,
        reserve_a: Coin<A>,
        reserve_b: Coin<B>,
        lp_supply: u128,
        strategy: Strategy<A, B>,
    }

    #[object(abilities = "key, store")]
    pub struct LpPosition<phantom A, phantom B> {
        id: UID,
        pool_id: ObjectId,
        amount: u128,
    }

    pub fn new<A, B>(
        coin_a: Coin<A>,
        coin_b: Coin<B>,
        strategy: Strategy<A, B>,
    ) -> (Pool<A, B>, LpPosition<A, B>) { ... }

    #[invariant("reserve_product_non_decreasing",
                |p: &Pool<A, B>| p.reserve_a.amount() * p.reserve_b.amount() >= p.k_last())]
    pub fn swap_a_for_b<A, B>(
        pool: &mut Pool<A, B>,
        coin_in: Coin<A>,
        min_out: u128,
    ) -> Coin<B> { ... }

    pub fn add_liquidity<A, B>(
        pool: &mut Pool<A, B>,
        coin_a: Coin<A>,
        coin_b: Coin<B>,
    ) -> LpPosition<A, B> { ... }

    pub fn remove_liquidity<A, B>(
        pool: &mut Pool<A, B>,
        position: LpPosition<A, B>,
    ) -> (Coin<A>, Coin<B>) { ... }
}
```

The macro emits:
- A wasm export per `pub fn` that the PTB executor can call by name
- A manifest entry per `pub fn` and per `#[object]` / `#[capability]`
- A wasm closure export per `#[invariant]` that the runtime calls at
  function exit
- A `bloom-resource` runtime that handles object marshaling, linearity
  bookkeeping, and capability checks

Generic functions are monomorphized at PTB execution time per
`type_args` — the wasm is generic-aware via type-tag arguments,
mirroring how Move handles type parameters.

There is no `#[bloom::contract]` in the new framework. There is no
`storage` block; state is the function arguments. There are no
`#[event]` macros — events become object emissions or capability
witnesses (TBD: thin event-object type for log-only emissions, kept
minimal in v0).

## 12. Invariants

### 12.1 Declaration

```rust
#[invariant(
    name = "reserve_product_non_decreasing",
    target = "Pool<A, B>",
    pred = |p: &Pool<A, B>| p.reserve_a.amount() * p.reserve_b.amount() >= p.k_last()
)]
pub fn swap_a_for_b<A, B>(...) -> Coin<B> { ... }
```

The macro emits:
1. A wasm closure compiled as a separate wasm export `__inv_<idx>(args...) -> i32`
2. A typed predicate AST into the manifest: `(operator, lhs, rhs)`
   over named fields of the target type

### 12.2 Runtime checking

After each `MoveCmd`, the PTB executor:
- For every `&mut` arg whose type has invariants declared in any of the
  current command's function-attached invariants: call the corresponding
  `__inv_<idx>` wasm export with the arg
- If the closure returns 0 (false): revert with
  `InvariantViolation { petal, function, invariant_name }`

This is *runtime* invariant enforcement, not the paper's social arbitration.
The manifest AST is what the social system reads.

### 12.3 Social layer

Invariants in the manifest are machine-readable. A Challenger (paper
§Petals) can:
- Submit a stronger invariant claim
- Provide a witness PTB that violates a declared invariant
- Trigger an arbitration vote

The pruning / slashing flow is out of scope for this spec — covered by
the staking system in v1+. The contract framework's job here is to
*emit* invariants in a machine-readable form so the future social layer
has something to read.

## 13. Path resolution and pinning

In v0, every `PetalRef` in a PTB MUST set the `hash` field. The chain
resolves:

1. Look up wasm by `hash` in the code root.
2. If `path` is set: verify the path-binding in the VFS commits to that
   hash. Else: any path is acceptable.
3. If neither path nor hash resolves: revert `PetalNotFound`.

The PTB encoding reserves space for a `resolution_policy: Option<PolicyRef>`
field that v0 ignores. v1+ enables unpinned references by consulting the
policy. The policy itself is just an object (e.g. `Policy { min_stake: u128,
min_trust_score: u16 }`) signed by the user.

This means: **agents and wallets ship pinning by default in v0.** Path
lookup is informational. The staking-policy story lands in v1.

## 14. The DEX, redesigned

### 14.1 Petal layout

```
/bloom/core/fungible        Coin<T>, supply caps, mint/burn ops
/bloom/core/cap             Capability primitives
/bloom/dex/pool             Pool<A,B>, LpPosition<A,B>, swap_*, add/remove_liquidity
/bloom/dex/strategy/cpmm    Strategy::ConstantProduct (default)
```

v1+ adds:
```
/bloom/dex/strategy/stable    Stableswap
/bloom/dex/strategy/weighted  Balancer-style
/bloom/dex/strategy/clmm      Concentrated liquidity
```

### 14.2 What's gone

- `bloom-dex-erc20` — replaced by `Coin<phantom T>` from
  `/bloom/core/fungible`. Token "deploys" become "create a `(MintCap<T>,
  BurnCap<T>, Supply<T>)` triple via `fungible::create_currency<T>`."
  No allowances. No transfers via approval. No `transfer_from` dance.
- `bloom-dex-factory` — replaced by `pool::new<A, B>`. No factory
  contract. The pool is a *shared object* the user passes around. Many
  pools can exist for the same `(A,B)` pair; clients prefer the one
  with the highest staked LP / trust score (v1 staking).
- `bloom-dex-router` — replaced by users assembling PTBs directly.
  Multi-hop = more commands. Helpers for common patterns live in the
  CLI / SDK, not as an onchain petal.
- `examples/wloom` — gone. LOOM is `Coin<LOOM>`.

### 14.3 A user swap

```
PTB {
  signers: [alice_pq_pubkey],
  commands: [
    SplitCoins(my_usdc_object, [Const(1_000_000)]) -> $coin_in,
    Move(
      petal: PetalRef { path: "/bloom/dex/pool", hash: Some(0xabc...) },
      function: "swap_a_for_b",
      type_args: [TypeTag::Coin(USDC), TypeTag::Coin(LOOM)],
      args: [
        Object(pool_usdc_loom_id, version=42, Mutable),
        Use(0, 0),                       // $coin_in
        Const(950_000),                  // min_out
      ],
    ) -> $coin_out,
    TransferObjects([Use(1, 0)], Owner::Address(alice)),
  ],
  gas_budget: 50_000,
  gas_price: 100,
  expiry_block: current + 100,
}
```

Compared to the current `swap_exact_tokens_for_tokens`:
- No `approve` tx
- No `transferFrom`
- No router contract
- No reentrancy guard
- Single atomic bundle, one signature
- Wallet can show "you will spend ≤1 USDC, receive ≥0.95 LOOM"
  *from the bundle alone*, no contract simulation needed for the bound

### 14.4 Adding liquidity

```
PTB {
  signers: [alice],
  commands: [
    SplitCoins(my_usdc, [Const(1_000)]) -> $usdc,
    SplitCoins(my_loom, [Const(500)])  -> $loom,
    Move(
      petal: PetalRef { path: "/bloom/dex/pool", hash: Some(0xabc...) },
      function: "add_liquidity",
      type_args: [USDC, LOOM],
      args: [
        Object(pool_id, v=42, Mutable),
        Use(0, 0),
        Use(1, 0),
      ],
    ) -> $lp_position,
    TransferObjects([Use(2, 0)], Owner::Address(alice)),
  ],
  ...
}
```

`LpPosition<USDC, LOOM>` is an owned object Alice can later pass into
`remove_liquidity`. No "LP tokens are ERC-20" anymore — LP positions
are just objects.

### 14.5 Pool creation

Pool creation is a normal PTB. Any signer can create a pool for any
pair; the chain does not dedupe. Clients (the DEX UI, agents) prefer
pools by staking / trust score (v1 staking). This avoids enshrining
"the canonical pool per pair" at the protocol level.

```
PTB {
  signers: [bob],
  commands: [
    SplitCoins(bob_usdc, [Const(1_000_000)]) -> $usdc_seed,
    SplitCoins(bob_loom, [Const(500_000)])   -> $loom_seed,
    Move(
      petal: PetalRef { path: "/bloom/dex/strategy/cpmm", hash: ... },
      function: "new",
      type_args: [USDC, LOOM],
      args: [Const(30 /* fee bps */)],
    ) -> $strategy,
    Move(
      petal: PetalRef { path: "/bloom/dex/pool", hash: ... },
      function: "new",
      type_args: [USDC, LOOM],
      args: [Use(0, 0), Use(1, 0), Use(2, 0)],
    ) -> ($pool, $lp_position),
    TransferObjects([Use(3, 0)], Owner::Shared),
    TransferObjects([Use(3, 1)], Owner::Address(bob)),
  ],
  ...
}
```

## 15. New crate layout

```
crates/
  bloom-objects/               object store types, host imports, codec extensions
  bloom-resource/              runtime: linearity, capabilities, object marshaling
  bloom-resource-macros/       #[bloom::petal], #[object], #[capability], #[invariant]
  bloom-script/                PTB types, encoding/decoding, dispatcher, validator
  bloom-petal-fungible/        /bloom/core/fungible (Coin<T>, MintCap, BurnCap)
  bloom-petal-cap/             /bloom/core/cap (capability primitives)
  bloom-petal-dex-pool/        /bloom/dex/pool
  bloom-petal-dex-cpmm/        /bloom/dex/strategy/cpmm
  bloom-petal-dex-it/          new integration tests (parallel to current ones)
```

Workspace `Cargo.toml` adds these as members. Existing crates stay.

## 16. Chain changes

### 16.1 New tx kind

`TxKind::SubmitPtb(PtbTx)` alongside the existing `TxKind::Deploy`,
`TxKind::Call`, `TxKind::Transfer`. The new tx kind is dispatched to the
`bloom-script` executor instead of the legacy `bloom-petals` chain VM.

### 16.2 New host imports

Added to the chain-mode import allowlist:

- `object.borrow(id_ptr, mode) -> handle`
- `object.read(handle, dst_ptr) -> u32`
- `object.mutate(handle, src_ptr, src_len)`
- `object.transfer(handle, owner_kind, owner_ptr)`
- `object.share(handle)`
- `object.freeze(handle)`
- `object.delete(handle)`
- `object.create(type_tag_ptr, type_tag_len, payload_ptr, payload_len) -> handle`
- `cap.check(cap_id_ptr, type_tag_ptr) -> i32`
- `signer.index() -> u16`
- `signer.address(idx, out_ptr)`
- `ptb.command_output(cmd_idx, ret_idx, out_ptr, out_len)`

Existing legacy imports (`state.read`, `state.write`, `petal.call`,
etc.) keep working for legacy petals. New-framework petals are linked
only against the new imports.

### 16.3 State root composition

The chain state root becomes:
```
root = blake3(
  "bloom-chain.v0.state:" ||
  accounts_root || code_root || object_root || ownership_index_root
)
```

`object_root` and `ownership_index_root` are new. `accounts_root` and
`code_root` are unchanged. Legacy account storage tries remain reachable
under the existing path.

### 16.4 Fuel accounting

- `object.borrow`: 200 fuel
- `object.read`: 100 + 4 * len
- `object.mutate`: 1500 + 4 * len (new), 1000 (existing)
- `object.create`: 5000 + 4 * len
- `object.transfer`: 500
- `object.share` / `freeze` / `delete`: 500
- `cap.check`: 100
- `ptb.command_output`: 100 + 4 * len

PTB-level overhead: 200 fuel per command + 100 per arg + 50 per signer
verification (amortized).

Block-level fuel limit remains 30M.

## 17. Migration plan

### Phase 1 — Foundation (current PR cycle)
- `bloom-objects`, `bloom-resource`, `bloom-resource-macros`, `bloom-script`
- `TxKind::SubmitPtb` wired into the chain (rejected for now, no-op)
- New host imports defined, wired into VM linker but unused

### Phase 2 — Fungible petal + first PTBs
- `bloom-petal-fungible`
- `bloom-petal-cap`
- Activate `TxKind::SubmitPtb` execution
- Genesis LOOM migration: at chain bootstrap, convert per-account
  `loom: u128` into `Coin<LOOM>` objects
- Compatibility shim: legacy reads of `account.loom` aggregate the
  owner's `Coin<LOOM>` objects

### Phase 3 — DEX rewrite
- `bloom-petal-dex-pool`, `bloom-petal-dex-cpmm`
- New integration tests in `bloom-petal-dex-it`
- Multi-validator docker e2e test mirroring the current
  `docker_dex_multi_user.rs`

### Phase 4 — Parity + deprecation flag
- All current docker DEX e2e scenarios pass under the new framework
- Old `bloom-contract*` and `examples/dex/*` and `examples/wloom`
  marked `#[deprecated(since = "...", note = "...")]`
- Documentation updated to point new contracts at the new framework

### Phase 5 (v1+) — Old framework removal
- Separate decision after a soak period; not part of this spec.

### Throughout
- Existing chain spec v0 acceptance test (`tests/chain/dex_demo.rs`)
  stays green at every commit.
- Existing docker DEX multi-user test stays green at every commit.

## 18. Open questions / TBD (to resolve during implementation)

- **Event objects vs. log emissions.** The new framework has no
  `#[event]` macro. Approach A: every "log" is an immutable object
  created and frozen in one command. Approach B: keep the legacy
  `log.emit` host import as a parallel surface for cheap append-only
  emissions. Resolve in Phase 2 PR.
- **Generic monomorphization granularity.** Move runs generic functions
  at one-bytecode-per-monomorphization at call time. We can either
  match (more fuel per call) or bake instantiation at publish time
  (larger code root). Resolve in Phase 1 PR after prototype.
- **Object ownership transitions across object owners.** When `Pool<A,B>`
  contains `Coin<A>` and `Coin<B>` as object-owned children, the
  ownership update flow needs precise rules to keep the ownership
  index trie consistent. Specify rigorously in Phase 1 PR.
- **Gas-payer object selection.** The PTB references the gas-payer
  `Coin<LOOM>` explicitly. If insufficient, who pays? v0: hard fail
  pre-execution. v1: optional sponsor field.
- **Capability revocation.** If a capability is leaked, can the issuer
  revoke? v0: only by ownership transfer (issuer must already hold a
  cap-management cap). v1: explicit revocation lists.

## 19. v0 acceptance

1. **Foundation crates build.** All Phase 1 crates compile, pass unit
   tests.
2. **Legacy untouched.** Existing `bloom-contract` workspace tests
   pass unchanged. Existing docker DEX e2e passes unchanged.
3. **Fungible petal works.** A PTB creates a currency, mints, splits,
   merges, transfers, burns. Linearity enforced (orphan = revert).
4. **DEX pool works.** A PTB creates a CPMM pool, adds liquidity, swaps,
   removes liquidity. Invariant violation reverts. `k` non-decreasing
   over many swaps.
5. **Capability auth works.** Mint without `&MintCap` reverts. Transfer
   a cap; new holder can mint; old holder cannot.
6. **Multi-validator parity.** Four-validator docker run executes a
   swap PTB end-to-end and all validators agree on state root.
7. **Atomicity.** A PTB whose second swap reverts rolls back the first
   swap's state changes.
8. **No `msg.sender` in new petals.** Grep for `msg.sender` /
   `msg::sender` in new-framework crates: zero matches.
9. **No `u256` in new petals.** Grep for `U256` / `u256` in new-framework
   crates: zero matches except where explicitly bridging legacy types.
10. **Determinism.** Same PTB sequence on same initial state produces
    same state root on independent validator runs.
