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
| Wallet-side multi-hop routing | On-chain `/bloom/dex/router` petal with `quote_Nhop`/`swap_Nhop` |

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

### 4.4 Linearity bookkeeping

The PTB executor maintains a per-tx **borrow table** with two object
states:

- **Transient** — produced by a command, not yet consumed. Lives only
  in executor memory; never touches the trie.
- **Persistent** — currently stored in the object trie. Loaded into the
  borrow table when borrowed.

Each row carries: `ObjectId`, `TypeTag`, `Owner`, `version`,
`payload_bytes`, `access_mode` (ReadOnly | Mutable | Consume),
`origin_command_idx`, and a `dirty` flag.

State transitions per command:

| Action | Effect on borrow table |
|---|---|
| `object.create` | Insert new transient row (random ObjectId per §4.1). |
| `object.borrow(id, mode)` | Load persistent row from trie (or transient row by id); set `access_mode`. Mutable/Consume require ownership check. |
| `object.mutate` | Set `dirty = true` on the row; update `payload_bytes`. |
| `object.transfer` | Set `Owner`; clear `dirty` flag relative to old owner; reassign owner-index entry on commit. |
| `object.share` / `freeze` | Set `Owner = Shared/Immutable`. |
| `object.delete` | Drop the row; mark trie slot for deletion on commit. |
| Consume by passing to a function arg with `mode=Consume` | Drop the row at end-of-command. |

At end-of-command, the executor runs the **diff-check**:

1. Any row whose `dirty = true` while `access_mode = ReadOnly` →
   `IllegalMutation` revert.
2. Any row with `access_mode = Mutable` whose `version` did not
   increment but whose `payload_bytes` changed → version-bump it (the
   bloom-resource runtime is supposed to call `object.mutate`, which
   sets `dirty`).
3. Run attached invariants (§12.2).

At tx-end, the executor runs the **linearity check**:

1. Every transient row must have been consumed, transferred, shared,
   frozen, or deleted by tx-end.
2. Orphan = `LinearityViolation(object_id)` revert.
3. Borrows of persistent objects with `mode=ReadOnly` or `mode=Mutable`
   are not linearity-tracked (the underlying objects stay in the
   store). `mode=Consume` requires the borrowed object to be consumed
   or re-emitted.

Coin merging is the canonical "consume two, produce one" example;
`SplitCoins` / `MergeCoins` PTB commands are sugar over the same
transient/persistent flow.

### 4.5 Object store

The object store replaces the per-account 32-byte-slot storage tries
for any account that holds objects under the new model.

**Two new `TrieKind` variants** in `bloom-chain-state` (mirroring the
existing `Accounts` / `Storage` / `Code` shape):

| Variant | Key | Value | Tags |
|---|---|---|---|
| `Object` | `ObjectId` (32B) | SSZ-encoded `Object` | root: `"bloom-chain.v0.object_root:"`, leaf: `"bloom-chain.v0.object_leaf:"` |
| `OwnershipIndex` | `(owner_kind: u8, owner_id: 32B)` | SSZ list of owned `ObjectId`s (sorted) | root: `"bloom-chain.v0.ownership_root:"`, leaf: `"bloom-chain.v0.ownership_leaf:"` |

Both use the existing **BLAKE3-tagged-sorted-leaf** commitment
algorithm — a `BTreeMap` whose root is computed as
`blake3_tagged(root_tag, len_u64_le || (key || blake3_tagged(leaf_tag,
value))*)`. Empty tries commit to `Hash32([0; 32])`.

This is a **placeholder** — chain spec §6.2 already documents the
v1 SMT swap-in path; we inherit it. v0 has O(N) root-recomputation per
block in the worst case, which is acknowledged and accepted for the
foundation phase.

**No type-index in the on-chain commitment.** "List all pools" is an
off-chain query served by indexers from receipts; baking a third trie
kind for explorer queries is not justified for v0.

Legacy accounts (those deployed under the old `Deploy` tx kind) keep
their existing `TrieKind::Storage` trie. New-framework petals do not
allocate per-account storage tries — all their state lives as objects.

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
   `blake3_tagged("bloom-chain.v0.ptb_hash:", canonical_encoding(PtbTx
   without signatures))`.
2. **Expiry.** `current_block <= expiry_block`.
3. **Petal resolution.** For each `PetalRef`: in v0 the `hash` field
   is required; chain verifies the wasm at `path` resolves to that
   hash (or fetches by hash if the path is unset). Future: consult
   resolution policy.
4. **Function-signature typecheck.** Each command's `args` typecheck
   against the petal manifest's declared function signature, including
   generic instantiation and `ArgKind` (Signer | Const | Object |
   TypeArg). No 4-byte selector dispatch — function lookup is by name.
5. **Object version + access check.** Each `Object(id, expected_version,
   mode)` arg: load the object, verify `version == expected_version`,
   verify `mode` is permitted (Owned: only the owner can take Mutable
   or Consume; Shared: any signer can take Mutable; Immutable:
   ReadOnly only; Object-owned: borrow chain to a root accessible to
   the signer must exist).
6. **Gas-payer prep.** Lock the PTB's `gas_payer: ObjectId`, verify
   `Owner::Address(first_signer)` and `T = LOOM`, split off
   `gas_budget * gas_price` bloomweis into a runtime-held reservation
   (§9.4).
7. **Execute commands in order.** For each command:
   - Load borrow-table rows for all `Object(...)` args; run command
     in wasm VM; outputs become transient rows.
   - **Diff-check.** Any `dirty` row with `access_mode = ReadOnly` →
     revert.
   - **Invariant check (§12.2).** Run each attached `__inv_<n>` export.
8. **Linearity check (tx-end).** Every transient row must have been
   consumed, transferred, shared, frozen, or deleted. Orphan →
   `LinearityViolation(object_id)` revert.
9. **`Account.loom` reconciliation.** For every address whose
   `Coin<LOOM>` ownership changed, recompute the cache.
10. **Commit.** Persist transient rows to the `Object` trie; update
    `OwnershipIndex`; bump versions; emit receipt; refund unused gas
    into a new `Coin<LOOM>` owned by first signer (merged into the
    gas-payer if still owned).

Any failure between (1) and (10) reverts the entire PTB. Gas-reservation
failures forfeit the reserved amount to the proposer (anti-DoS); other
failures refund unused gas after deducting fuel actually burned.

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

### 8.1 Layout

New-framework petals carry their manifest as a wasm **custom section**,
not as a JSON sidecar. Section name: `bloom_petal_manifest_v0`.
Payload: a `PetalManifestV0` struct encoded with `bloom-chain-abi`'s
canonical codec (the same codec used for object payloads on the wire).

A JSON sidecar `<petal>.petal.json` is still emitted by the build
pipeline as a debugging / explorer convenience, but it is *derived*
from the custom section and is not chain-authoritative. The chain
verifies a petal by computing `blake3` of the custom section bytes and
comparing against the path's `OwnerCap<Path>`-bound hash.

### 8.2 Schema (canonical-codec)

```rust
struct PetalManifestV0 {
    schema_version: u32,                  // = 1 for this layout
    module_path: VfsPath,                 // "/bloom/dex/pool"
    framework_version: SemVer,            // bloom-resource crate version
    parent_version: Option<ContentHash>,  // upgrade lineage
    object_types: Vec<ObjectTypeDecl>,
    capability_types: Vec<CapabilityDecl>,
    functions: Vec<FunctionDecl>,
    invariants: Vec<InvariantDecl>,
    required_host_imports: Vec<HostImportDecl>,
    external_type_refs: Vec<ExternalTypeRef>,  // see §13 path resolution
    fuel_hints: FuelHints,                     // declared upper bounds, opt-in
}

struct ObjectTypeDecl {
    name: String,
    abilities: AbilitySet,                // bitfield: key/store/copy/drop
    type_params: Vec<TypeParamDecl>,      // phantom vs. resource
    fields: Vec<FieldDecl>,
}

struct TypeParamDecl {
    name: String,
    kind: TypeParamKind,                  // Phantom | Resource
    bounds: Vec<TypeTag>,                 // future use
}

struct FunctionDecl {
    name: String,
    type_params: Vec<TypeParamDecl>,
    args: Vec<ArgDecl>,                   // see ArgKind below
    returns: Vec<TypeTag>,
    required_signers: u8,                 // count of distinct Signer args
    required_capabilities: Vec<TypeTag>,  // capability args, by type
    attached_invariants: Vec<InvariantIdx>,
}

enum ArgKind {
    Signer,
    Const(TypeTag),
    Object { ty: TypeTag, mode: AccessMode },
    TypeArg(TypeParamIdx),
}

struct InvariantDecl {
    name: String,
    target: InvariantTarget,              // ObjectType | FunctionExit
    predicate: PredicateAst,              // machine-readable form
    wasm_export: String,                  // "__inv_<idx>"
}

struct HostImportDecl {
    module: String,                       // "object", "cap", "signer", "ptb"
    name: String,                         // "borrow", "read", ...
    signature: WasmFuncSig,               // arg types + return type
}

struct ExternalTypeRef {
    placeholder: String,                  // "$external_0"
    declared_petal_path: VfsPath,         // where the type lives
    declared_type_name: String,
    declared_content_hash: Option<ContentHash>,  // pinned at publish time
}
```

`TypeTag` is recursive (`Concrete(...) | Generic(idx) | External(ref_idx)`)
so generic instantiation flows through the manifest unambiguously.

### 8.3 Build pipeline

`bloom contract build` for a new-framework petal:

1. Compile the crate to wasm.
2. Walk the `#[bloom::petal]` AST (via the proc-macro) to collect the
   manifest struct in memory.
3. Resolve `external_type_refs` against the workspace `petals.lock`
   (a Cargo-lock-shaped file pinning each external petal path to a
   content hash).
4. Canonical-encode the manifest; embed as `bloom_petal_manifest_v0`
   custom section. Strip any leftover legacy `bloom_interfaces` section.
5. Emit the derived `.petal.json` sidecar.
6. Record `wasm_hash = blake3(final_wasm_bytes)` in the build report.

### 8.4 Coexistence with legacy manifest

Legacy `bloom-contract`-style petals continue to carry the JSON sidecar
`Manifest` from `bloom-contract-metadata` (schema_version 2). The chain
distinguishes by inspecting the wasm: if the
`bloom_petal_manifest_v0` custom section exists, the petal is treated
as new-framework and the legacy sidecar is ignored even if present.

## 9. Native LOOM unification

LOOM becomes `Coin<LOOM>` — a regular `Coin<phantom T>` from the
fungible petal at `/bloom/core/fungible`.

### 9.1 LOOM marker type

The `LOOM` witness type lives inside `bloom-petal-fungible` rather than
in its own petal:

```rust
// crates/bloom-petal-fungible/src/lib.rs
#[bloom::petal(path = "/bloom/core/fungible")]
pub mod fungible {
    /// Phantom-only marker; never instantiated. Has no abilities, so it
    /// can only appear in `Coin<LOOM>` / `Balance<LOOM>` positions.
    #[object(no_abilities)]
    pub struct LOOM {}

    /// Mint the initial LOOM supply. Gated by `EpochZero`, which only
    /// the genesis pipeline ever holds; the cap is dropped after
    /// genesis closes, making this entry point permanently unreachable.
    pub fn mint_genesis(
        _: &EpochZero,
        amount: u128,
        recipient: Address,
    ) -> Coin<LOOM> { ... }
}
```

### 9.2 `Account.loom` as denormalized cache

The 122-byte `Account` SSZ layout (chain spec §5.1, including
`loom: u128`) is preserved. After phase 2, `loom` is no longer the
source of truth — it is a denormalized cache of:

```
sum(coin.value for coin in coins_owned_by(addr) where T = LOOM)
```

Every state-transition that creates, splits, merges, transfers, or
destroys a `Coin<LOOM>` whose owner is `Owner::Address(addr)` updates
`accounts[addr].loom` inside the same command's diff-check. A
chain-level invariant `accounts[addr].loom == sum(...)` is enforced at
end-of-block in v0 (full sweep in tests, sampled in steady state).

Reasoning: keeps O(1) balance reads for RPC/explorers, preserves SSZ
wire format, avoids an end-of-block O(N) scan.

### 9.3 Genesis allocation

Fresh genesis (no migration path — chain is unlaunched):

1. Genesis config lists `(address, amount)` pairs.
2. For each pair, the genesis pipeline mints a single `Coin<LOOM>`
   object via `fungible::mint_genesis`, with
   `owner = Owner::Address(address)`, and writes
   `accounts[address].loom = amount`.
3. The `EpochZero` capability is consumed (it is linear, no-drop) at
   the end of the genesis flow, so no further `mint_genesis` calls
   are possible without a governance petal that mints fresh
   capabilities.

Per-holder at genesis: one Coin<LOOM> object. Users split/merge
afterward via fungible petal commands.

### 9.4 Gas-payer model

Every `PtbTx` carries a `gas_payer: ObjectId` referring to a
`Coin<LOOM>` owned by the first signer. Pre-execution:

1. Lock `gas_payer`; verify `Owner::Address(sender)` and `T = LOOM`.
2. Reserve `gas_budget * gas_price` bloomweis by splitting that amount
   into a runtime-held "gas reservation" coin (transient, never
   persisted as an object).
3. Execute the PTB.
4. Refund unused gas into a new `Coin<LOOM>` owned by the sender; if
   `gas_payer` is still owned by the sender at tx-end, the refund coin
   is merged back into it for nicer UX.

Insufficient `gas_payer.value`: hard fail pre-execution. v1 may add an
optional sponsor field.

### 9.5 Legacy `TxKind::Transfer` and `TxKind::Call` compat shim

`TxKind::Transfer` and `TxKind::Call` stay on the wire through phase 3
(per §17). They are translated by the chain into synthetic PTBs before
dispatch:

- `Transfer { to, amount_loom }` →
  ```
  let payer = select_coin(sender, LOOM, amount_loom + gas);
  SplitCoins(payer, [Const(amount_loom)]) -> $pay;
  fungible::transfer<LOOM>(Use(0,0), to);
  ```
- `Call { to, value, calldata, ... }` with `value > 0` →
  prepend a `SplitCoins` from `select_coin(sender, LOOM, value)` and
  thread the resulting `Coin<LOOM>` into the legacy `Call` dispatch
  surface. The legacy callee sees the value as a `Coin<LOOM>` arg via
  a compat trampoline; pre-migration petals that read `msg.value`
  continue to do so against the runtime-aggregated owner balance.

`select_coin(addr, T, min_amount)` is a chain-level helper, not a
petal function — it has to be deterministic across validators and
runs pre-wasm. Algorithm: take the largest matching coin owned by
`addr`; tiebreak by ascending `ObjectId`. If no single coin covers
`min_amount`, the chain synthesizes a `MergeCoins` of the largest few
owned coins first.

### 9.6 What goes away

- `msg.value` plumbing in new petals — pass `Coin<LOOM>` arguments.
- wLOOM — `Coin<LOOM>` is already an object.
- Any per-account "native vs. token" branching.

### 9.7 Removal timeline (cross-ref §17)

| Phase | LOOM state |
|---|---|
| 2 | Genesis emits `Coin<LOOM>`; `Account.loom` becomes derived cache. |
| 3 | New petals use `Coin<LOOM>` only. Legacy `Transfer`/`Call` shim runs unchanged. |
| 4 | `TxKind::Transfer` and `TxKind::Call` removed; only `TxKind::SubmitPtb` remains. `Account.loom` retained as cache for SSZ stability. |

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
    pub struct Pool<phantom A, phantom B, phantom S: SwapStrategy> {
        id: UID,
        reserve_a: Coin<A>,
        reserve_b: Coin<B>,
        lp_supply: u128,
        params: S::Params,            // e.g. ConstantProduct::Params { fee_bps }
        k_last: u128,
    }

    #[object(abilities = "key, store")]
    pub struct LpPosition<phantom A, phantom B> {
        id: UID,
        pool_id: ObjectId,
        amount: u128,
    }

    pub fn new<A, B, S: SwapStrategy>(
        coin_a: Coin<A>,
        coin_b: Coin<B>,
        params: S::Params,
    ) -> (Pool<A, B, S>, LpPosition<A, B>) { ... }

    #[invariant("reserve_product_non_decreasing",
                |p: &Pool<A, B, S>| S::k(p) >= p.k_last)]
    pub fn swap_a_for_b<A, B, S: SwapStrategy>(
        pool: &mut Pool<A, B, S>,
        coin_in: Coin<A>,
        min_out: u128,
    ) -> Coin<B> { ... }

    pub fn add_liquidity<A, B, S: SwapStrategy>(
        pool: &mut Pool<A, B, S>,
        coin_a: Coin<A>,
        coin_b: Coin<B>,
    ) -> LpPosition<A, B> { ... }

    pub fn remove_liquidity<A, B, S: SwapStrategy>(
        pool: &mut Pool<A, B, S>,
        position: LpPosition<A, B>,
    ) -> (Coin<A>, Coin<B>) { ... }
}
```

### 11.1 Macro emission

The macro emits:
- One wasm export per `pub fn`, named `__petal_<fn_name>`. The export
  signature is uniform: `(args_ptr: i32, args_len: i32, ret_ptr: i32,
  ret_cap: i32) -> i32` — the body deserializes args via canonical-codec
  from the runtime-provided buffer, dispatches to the Rust impl, and
  serializes return values back. The return `i32` is `0` on success,
  non-zero on petal-side abort (typed error code).
- One wasm closure export per `#[invariant]`, named `__inv_<n>` with
  signature `(scope_ptr: i32, scope_len: i32) -> i32`. Returns `1`
  (ok) or `0` (violated). Scope buffer is canonical-encoded
  `(invariant_args...)`.
- One manifest entry per `pub fn`, `#[object]`, `#[capability]`,
  `#[invariant]`, declared host import, and external type reference.
- A `bloom-resource` runtime that handles object marshaling, linearity
  bookkeeping, capability checks, and the args/ret buffer codec.

### 11.2 Generics (phantom + non-phantom)

The macro accepts two kinds of type parameters, declared at the type
parameter syntax level:

```rust
// Phantom: T appears only in TypeTags, never in field bytes / args.
#[object(abilities = "key, store")]
pub struct Coin<phantom T> {
    id: UID,
    value: u128,
}

// Non-phantom: T appears in payload bytes; uses the Resource<T> wrapper.
#[object(abilities = "key, store")]
pub struct Box<T> {
    id: UID,
    contents: Resource<T>,         // *not* plain T
}

pub fn unbox<T>(b: Box<T>) -> Resource<T> { b.contents }
```

`Resource<T>` is a runtime-typed wrapper over canonical-encoded bytes
+ a TypeTag. The macro **rejects plain `T` in field or arg position**;
non-phantom generic state must go through `Resource<T>`. This keeps
the type system honest while letting v0 ship without a full
monomorphizing toolchain.

`Resource<T>` is provided by `bloom-resource`:
```rust
pub struct Resource<T> {
    type_tag: TypeTag,
    bytes: Vec<u8>,
    _marker: PhantomData<T>,
}
impl<T> Resource<T> {
    pub fn into<U: BloomType>(self) -> Result<U, TypeMismatch>;
    pub fn from<U: BloomType>(value: U) -> Self;
}
```

Generic functions are monomorphized **at PTB execution time** per
`type_args`: the chain sees one wasm export and passes type tags as
prefix args. The macro generates argument-decode logic that branches
on `TypeTag` only at boundary points (e.g. extracting a `u128` from a
`Resource<U64>`). Per-instantiation wasm bloat is avoided; the price
is a small dispatch overhead per call. Per-publish monomorphization is
deferred to v1 if profiling demands it.

### 11.3 Build pipeline (cross-ref §8.3)

`#[bloom::petal]` is the entry point; the macro runs during the
crate's normal `cargo build`. The `bloom contract build` command
wraps the cargo invocation, then:

1. Strips debug symbols and runs `wasm-opt -O3 --strip-debug`.
2. Embeds the manifest custom section.
3. Resolves `external_type_refs` against `petals.lock`.
4. Computes `blake3(wasm_bytes)`; records in build report.
5. Optionally publishes via the publishing PTB (§10).

### 11.4 What's absent

- No `#[bloom::contract]` macro in the new framework.
- No `storage` block — state is function arguments and object fields.
- No `#[event]` macros in v0. **Events resolved (§18):** for v0 we
  emit logs via a thin `log.emit` host import (legacy semantics, kept
  as a parallel surface) plus a typed `Event<T>` object-as-immutable
  wrapper for petals that want structured indexable emissions. The
  choice is per-petal; mixed petals are fine. v1 collapses to one
  surface after profiling.

## 12. Invariants

### 12.1 Declaration

```rust
#[invariant(
    name = "reserve_product_non_decreasing",
    target = "Pool<A, B, S>",
    pred = |p: &Pool<A, B, S>| S::k(p) >= p.k_last
)]
pub fn swap_a_for_b<A, B, S: SwapStrategy>(...) -> Coin<B> { ... }
```

The macro emits:
1. A wasm closure compiled as a separate wasm export `__inv_<idx>(args...) -> i32`
2. A typed predicate AST into the manifest: `(operator, lhs, rhs)`
   over named fields of the target type

### 12.2 Runtime checking

After each `MoveCmd` returns successfully, the PTB executor walks the
function's `attached_invariants` from the manifest, in declaration
order:

```
for inv in fn_decl.attached_invariants:
    scope = canonical_encode(collect_invariant_args(inv, cmd_args, cmd_returns))
    rc = wasm_call(petal_instance, inv.wasm_export, scope)
    if rc == 0:
        revert(InvariantViolation { petal, function, invariant_name: inv.name })
```

`collect_invariant_args` picks out the `&mut`, `&`, and return slots
that the invariant's `PredicateAst` references. The wasm export
signature is fixed (§11.1) so the runtime never needs per-invariant
glue.

Invariants execute inside the same wasm instance as the function
they're attached to. They consume fuel (declared as 500 + 4*scope_len
per check). They cannot mutate state — the bloom-resource runtime
gives the closure a `&` view of the scope and rejects any
`object.mutate` / `object.create` / `object.transfer` calls during
invariant execution (host-side flag).

This is *runtime* invariant enforcement, not the paper's social
arbitration. The manifest's `PredicateAst` is what the social system
reads.

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

### 13.1 PTB-side: pinned content hashes

In v0, every `PetalRef` in a PTB MUST set the `hash` field. The chain
resolves:

1. Look up wasm by `hash` in the code root.
2. If `path` is set: verify the path-binding in the VFS commits to
   that hash. Else: any path is acceptable.
3. If neither path nor hash resolves: revert `PetalNotFound`.

The PTB encoding reserves space for a
`resolution_policy: Option<PolicyRef>` field that v0 ignores. v1+
enables unpinned references by consulting the policy. The policy
itself is just an object (e.g. `Policy { min_stake: u128,
min_trust_score: u16 }`) signed by the user.

**Agents and wallets ship pinning by default in v0.** Path lookup is
informational. The staking-policy story lands in v1.

### 13.2 Build-side: `petals.lock`

Cross-petal type references (e.g. `bloom-petal-dex-pool` referencing
`Coin<T>` defined in `bloom-petal-fungible`) are resolved at build
time, not at PTB validation time. The workspace root carries a
`petals.lock` file shaped like `Cargo.lock`:

```toml
[[petal]]
path = "/bloom/core/fungible"
content_hash = "blake3:abcd...1234"
manifest_blake3 = "blake3:ef01...beef"
emitted_by = "bloom-petal-fungible 0.1.0"

[[petal]]
path = "/bloom/dex/pool"
content_hash = "..."
depends_on = ["/bloom/core/fungible", "/bloom/core/cap"]
```

`bloom contract build` for a petal:

1. Loads `petals.lock` from the workspace root.
2. For each `external_type_refs` entry the macro emitted, resolves the
   placeholder against the lock entry for the referenced petal.
3. Substitutes the placeholder with the resolved `content_hash` in the
   final manifest custom section.
4. Errors if a referenced petal is missing from the lock.

`petals.lock` is committed to the repo. Updates happen via `bloom
contract update` (analogous to `cargo update`). The chain does not
read `petals.lock`; it only sees the resolved hashes that ended up in
each petal's manifest.

## 14. The DEX, redesigned

### 14.1 Petal layout

```
/bloom/core/fungible        Coin<T>, supply caps, mint/burn ops
/bloom/core/cap             Capability primitives
/bloom/dex/pool             Pool<A,B,S>, LpPosition<A,B>, swap, add/remove_liquidity
/bloom/dex/strategy/cpmm    Strategy = ConstantProduct
/bloom/dex/router           Multi-hop helpers (quote_Nhop, swap_Nhop) for N = 1..3
```

v1+ adds:
```
/bloom/dex/strategy/stable    Stableswap
/bloom/dex/strategy/weighted  Balancer-style
/bloom/dex/strategy/clmm      Concentrated liquidity
/bloom/dex/router-N           Higher-arity routers if profiling demands them
```

Shared math lives in a workspace crate `bloom-dex-math` (not a petal).
Both `bloom-petal-dex-cpmm` and `bloom-petal-dex-router` link it at
compile time. No `petal.call` host import in v0 — keeping multi-hop
math inlined avoids cross-petal call overhead and keeps the router
self-contained.

### 14.2 Pool / Strategy separation

`Pool<A, B, S>` is parameterized by a `Strategy` *type*, not a runtime
object:

```rust
#[object(abilities = "key, store")]
pub struct Pool<phantom A, phantom B, phantom S: SwapStrategy> {
    id: UID,
    reserve_a: Coin<A>,
    reserve_b: Coin<B>,
    lp_supply: u128,
    params: S::Params,                   // strategy-specific (fee bps, etc.)
    k_last: u128,                        // for invariant checking
}
```

The strategy is picked at pool-creation time and frozen in the type
tag, so `Pool<USDC, LOOM, ConstantProduct>` and
`Pool<USDC, LOOM, Stableswap>` are *distinct types* — the router and
indexers can tell them apart without inspecting payload bytes.

`SwapStrategy` is a trait in `bloom-dex-math` exposing pure functions
(`quote`, `apply_swap`, `add_liquidity`, etc.). The pool petal calls
into the trait directly; no host import.

### 14.3 Router petal

`/bloom/dex/router` exposes `quote_Nhop` and `swap_Nhop` for arity N ∈
{1, 2, 3} (covers >99% of real DEX volume). Each operates on a
fixed-arity tuple of `&mut Pool<...>` references and threads coins
through them with linear types:

```rust
pub fn swap_2hop<A, B, C, S1, S2>(
    pool_ab: &mut Pool<A, B, S1>,
    pool_bc: &mut Pool<B, C, S2>,
    coin_in: Coin<A>,
    min_out: u128,
) -> Coin<C> {
    let mid = pool::swap_a_for_b(pool_ab, coin_in, 0);
    pool::swap_a_for_b(pool_bc, mid, min_out)
}
```

The `0` intermediate min-out is safe because the outer `min_out` is
the actual user-facing slippage bound. The router carries a function
attached invariant `all_pools_k_non_decreasing` that re-validates each
touched pool's CPMM invariant after the chain of swaps.

Mixed-strategy paths (e.g. CPMM → Stableswap) are expressible because
each pool's strategy is a separate type parameter. The router does
*not* attempt arbitrary-N composition in v0 — paths longer than 3
hops compose at the PTB level by chaining `swap_3hop` outputs.

### 14.4 What's gone

- `bloom-dex-erc20` — replaced by `Coin<phantom T>` from
  `/bloom/core/fungible`. Token "deploys" become "create a `(MintCap<T>,
  BurnCap<T>, Supply<T>)` triple via `fungible::create_currency<T>`."
  No allowances. No `transfer_from` dance.
- `bloom-dex-factory` — replaced by `pool::new<A, B, S>`. No factory
  contract. The pool is a *shared object* the user passes around.
  Many pools can exist for the same `(A,B,S)`; clients prefer the one
  with the highest staked LP / trust score (v1 staking).
- `bloom-dex-router` (the legacy chain VM one) — replaced by the
  petal at `/bloom/dex/router`. Multi-hop math is on-chain, not in
  wallets or CLIs (no wallet-enshrinement). Wallets just submit PTBs.
- `examples/wloom` — gone. LOOM is `Coin<LOOM>`.

### 14.5 A user swap

```
PTB {
  signers: [alice_pq_pubkey],
  commands: [
    SplitCoins(my_usdc_object, [Const(1_000_000)]) -> $coin_in,
    Move(
      petal: PetalRef { path: "/bloom/dex/pool", hash: Some(0xabc...) },
      function: "swap_a_for_b",
      type_args: [TypeTag::Coin(USDC), TypeTag::Coin(LOOM),
                  TypeTag::ConstantProduct],
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

### 14.6 Adding liquidity

```
PTB {
  signers: [alice],
  commands: [
    SplitCoins(my_usdc, [Const(1_000)]) -> $usdc,
    SplitCoins(my_loom, [Const(500)])  -> $loom,
    Move(
      petal: PetalRef { path: "/bloom/dex/pool", hash: Some(0xabc...) },
      function: "add_liquidity",
      type_args: [USDC, LOOM, ConstantProduct],
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

### 14.7 Pool creation

Pool creation is a normal PTB. Any signer can create a pool for any
pair; the chain does not dedupe. Clients (the DEX UI, agents) prefer
pools by staking / trust score (v1 staking). This avoids enshrining
"the canonical pool per pair" at the protocol level.

Strategy is a *type parameter*, not a runtime object, so pool creation
takes the seeds + the strategy's `Params` (a `Const`):

```
PTB {
  signers: [bob],
  commands: [
    SplitCoins(bob_usdc, [Const(1_000_000)]) -> $usdc_seed,
    SplitCoins(bob_loom, [Const(500_000)])   -> $loom_seed,
    Move(
      petal: PetalRef { path: "/bloom/dex/pool", hash: ... },
      function: "new",
      type_args: [USDC, LOOM, ConstantProduct],
      args: [
        Use(0, 0),                            // $usdc_seed
        Use(1, 0),                            // $loom_seed
        Const(ConstantProduct::Params {       // canonical-codec encoded
          fee_bps: 30,
        }),
      ],
    ) -> ($pool, $lp_position),
    TransferObjects([Use(2, 0)], Owner::Shared),
    TransferObjects([Use(2, 1)], Owner::Address(bob)),
  ],
  ...
}
```

## 15. New crate layout

```
crates/
  bloom-objects/               object store types, host imports, codec extensions
  bloom-resource/              runtime: linearity, capabilities, marshaling, Resource<T>
  bloom-resource-macros/       #[bloom::petal], #[object], #[capability], #[invariant]
  bloom-script/                PTB types, encoding/decoding, dispatcher, validator
  bloom-dex-math/              SwapStrategy trait + pure math (CPMM today; stable/etc. later)
  bloom-petal-fungible/        /bloom/core/fungible (Coin<T>, MintCap, BurnCap, LOOM)
  bloom-petal-cap/             /bloom/core/cap (capability primitives)
  bloom-petal-dex-pool/        /bloom/dex/pool (Pool<A, B, S>, LpPosition<A, B>)
  bloom-petal-dex-cpmm/        /bloom/dex/strategy/cpmm
  bloom-petal-dex-router/      /bloom/dex/router (quote_Nhop, swap_Nhop, N = 1..3)
  bloom-petal-dex-it/          new integration tests (parallel to current ones)
```

`bloom-dex-math` is a normal workspace crate (not a petal); both
`bloom-petal-dex-cpmm` and `bloom-petal-dex-router` link it at compile
time so multi-hop math stays self-contained without cross-petal calls.

Workspace `Cargo.toml` adds these as members. Existing crates stay.

## 16. Chain changes

### 16.1 New tx kind

`TxKind::SubmitPtb(PtbTx)` alongside the existing `TxKind::Deploy`,
`TxKind::Call`, `TxKind::Transfer`. The new tx kind is dispatched to the
`bloom-script` executor instead of the legacy `bloom-petals` chain VM.

### 16.2 New host imports

All new host imports live under the `object`, `cap`, `signer`, and
`ptb` modules and are added to the chain-mode import allowlist.
Signatures are wasm value-type tuples; "handle" is `i32` (an opaque
runtime-local index into the executor's borrow table, never the raw
ObjectId).

| Import | Signature | Notes |
|---|---|---|
| `object.borrow` | `(id_ptr i32, mode i32) -> handle i32` | `mode`: 0=ReadOnly, 1=Mutable, 2=Consume. Pre-resolved against the PTB's `Object(...)` arg slots; mismatched mode aborts. |
| `object.read` | `(handle i32, dst_ptr i32, dst_cap i32) -> len i32` | Negative return = buffer too small (caller resizes and retries). |
| `object.mutate` | `(handle i32, src_ptr i32, src_len i32) -> i32` | Requires `Mutable` borrow. Updates the executor's transient state; not persisted until tx-end commit. |
| `object.create` | `(type_tag_ptr i32, type_tag_len i32, payload_ptr i32, payload_len i32) -> handle i32` | Creator petal must be the type-defining petal; runtime checks. |
| `object.transfer` | `(handle i32, owner_kind i32, owner_payload_ptr i32, owner_payload_len i32) -> i32` | `owner_kind`: 0=Address, 1=Object, 2=Shared, 3=Immutable. Drops `Shared`/`Immutable`-incoming handles. |
| `object.share` | `(handle i32) -> i32` | Shorthand for `transfer(_, Shared, _)`. |
| `object.freeze` | `(handle i32) -> i32` | Shorthand for `transfer(_, Immutable, _)`. |
| `object.delete` | `(handle i32) -> i32` | Permanently removes; only the type-defining petal can call. |
| `cap.check` | `(cap_handle i32, type_tag_ptr i32, type_tag_len i32) -> i32` | Returns 1 if the borrowed object's type tag matches and abilities include the cap marker; 0 otherwise. |
| `signer.index` | `() -> i32` | Returns the current command's "primary signer" index, or -1 if none. |
| `signer.address` | `(idx i32, out_ptr i32) -> i32` | Writes 32-byte PQ address. Returns 0/-1. |
| `ptb.command_output` | `(cmd_idx i32, ret_idx i32, out_ptr i32, out_cap i32) -> len i32` | Read a typed return from an earlier command; used by the runtime to thread `Use(...)` references, rarely called from user code. |
| `log.emit` | `(topic_ptr i32, topic_len i32, data_ptr i32, data_len i32) -> i32` | Legacy-style log emission. Optional per-petal surface (§11.4). |

Encoding for `id_ptr` / `type_tag_ptr` / `payload_ptr`: canonical-codec
bytes as produced by `bloom-chain-abi`. The runtime never asks the
guest to allocate — guest passes pre-allocated buffers and lengths.

Existing legacy imports (`state.read`, `state.write`, `petal.call`,
etc.) keep working for legacy petals. New-framework petals are linked
only against the new imports — the build pipeline rejects new-framework
wasm that imports legacy symbols.

### 16.3 State root composition

The chain state root grows from a 64-byte payload (accounts + code) to
a 128-byte payload (accounts + code + objects + ownership):

```
root = blake3_tagged(
  "bloom-chain.v0.state_root:",
  accounts_root              // unchanged
  || code_root               // unchanged
  || object_root             // new
  || ownership_index_root    // new
)
```

`object_root` and `ownership_index_root` are two new `TrieKind`
variants in `bloom-chain-state`:

- `TrieKind::Object` — primary index `ObjectId -> Object` (SSZ-encoded).
  Tag: `"bloom-chain.v0.object_root:"` / leaves
  `"bloom-chain.v0.object_leaf:"`.
- `TrieKind::OwnershipIndex` — secondary index
  `(owner_kind, owner_id) -> sorted_list<ObjectId>`. Tag:
  `"bloom-chain.v0.ownership_root:"` / leaves
  `"bloom-chain.v0.ownership_leaf:"`.

Both reuse the existing **BLAKE3-tagged-sorted-leaf placeholder**
commitment (a `BTreeMap<key, value>` whose root is
`blake3_tagged(root_tag, len_u64_le || (key || blake3_tagged(value_tag,
value))*)`). This matches the existing `Accounts` / `Storage` / `Code`
trie kinds and means there is no new commitment primitive in v0; the
v1 SMT swap-in path documented in `bloom-chain-state/src/trie.rs`
applies uniformly.

Type-index queries ("list all pools of shape X") are served by an
**off-chain** index built from receipts; the chain does not commit to
them. This avoids a third new trie kind for a query that explorers and
wallets, not consensus, need.

Legacy account storage tries remain reachable under the existing path
(`TrieKind::Storage`); new-framework petals do not allocate storage
tries.

### 16.4 Fuel accounting

- `object.borrow`: 200 fuel
- `object.read`: 100 + 4 * len
- `object.mutate`: 1500 + 4 * len
- `object.create`: 5000 + 4 * len
- `object.transfer`: 500
- `object.share` / `freeze` / `delete`: 500
- `object.delete`: 500
- `cap.check`: 100
- `signer.index` / `signer.address`: 50
- `ptb.command_output`: 100 + 4 * len
- `log.emit`: 200 + 4 * (topic_len + data_len)
- Invariant check: 500 + 4 * scope_len per declared invariant
- Linearity diff-check at command end: 100 per touched object

PTB-level overhead: 200 fuel per command + 100 per arg + 50 per signer
verification (amortized).

Block-level fuel limit remains 30M.

## 17. Migration plan

### Phase 1 — Foundation
- `bloom-objects`, `bloom-resource`, `bloom-resource-macros`,
  `bloom-script`, `bloom-dex-math` (CPMM only).
- Two new `TrieKind` variants (`Object`, `OwnershipIndex`) wired into
  `bloom-chain-state`; state-root payload grows to 128 bytes.
- `TxKind::SubmitPtb(PtbTx)` defined and wired through the chain;
  initially rejected (returns `NotYetActivated` receipt).
- New host imports defined and wired into the VM linker, gated off by
  a feature flag so they're unreachable until phase 2.
- `petals.lock` plumbing in `bloom contract build`; manifest custom
  section emitted by the macro.

### Phase 2 — Fungible petal + first PTBs
- `bloom-petal-fungible` (including `LOOM` marker) and
  `bloom-petal-cap`.
- Activate `TxKind::SubmitPtb` execution.
- Genesis: emit one `Coin<LOOM>` per allocated address; consume the
  `EpochZero` capability at end of genesis flow.
- `Account.loom` becomes a denormalized cache maintained by the
  runtime; end-of-block reconciliation invariant active.

### Phase 3 — DEX rewrite
- `bloom-petal-dex-pool` (parameterized `Pool<A, B, S>`),
  `bloom-petal-dex-cpmm`, `bloom-petal-dex-router` (with
  `quote_Nhop`/`swap_Nhop` for N ∈ {1, 2, 3}).
- New integration tests in `bloom-petal-dex-it`.
- Multi-validator docker e2e test mirroring the current
  `docker_dex_multi_user.rs`, exercising the router on a 2-hop path.

### Phase 4 — Parity + deprecation flag
- All current docker DEX e2e scenarios pass under the new framework
  (parallel suite, both green).
- `TxKind::Transfer` and `TxKind::Call` compat shims continue to run;
  scheduled for removal in phase 5.
- Old `bloom-contract*` and `examples/dex/*` and `examples/wloom`
  marked `#[deprecated(since = "...", note = "...")]`.
- Documentation updated to point new contracts at the new framework.

### Phase 5 (v1+) — Old framework removal
- Drop `TxKind::Transfer` and `TxKind::Call` from the wire format.
- Separate decision after a soak period; not part of this spec.

### Throughout
- Existing chain spec v0 acceptance test (`tests/chain/dex_demo.rs`)
  stays green at every commit.
- Existing docker DEX multi-user test stays green at every commit.

## 18. Open questions resolved in this revision

- **Event objects vs. log emissions** — **Both.** v0 ships `log.emit`
  as a thin parallel host import (§16.2) and a typed `Event<T>` object
  pattern (immutable, frozen at create-time) for petals that want
  structured indexable emissions. The choice is per-petal. v1 may
  collapse to one surface based on indexer feedback.
- **Generic monomorphization granularity** — **Call-time
  monomorphization with `Resource<T>` for non-phantom positions
  (§11.2).** One wasm export per generic `pub fn`; type tags flow as
  prefix args; `Resource<T>` carries runtime-typed payloads. No
  publish-time bytecode explosion. Profiling may justify
  publish-time instantiation in v1.
- **Object ownership transitions across object-owned children** —
  **Resolved in §4.4 (borrow table) and §4.5 (`OwnershipIndex` trie).**
  When a `Pool<A,B,S>` is consumed, its object-owned children are
  loaded as transient rows and must be re-homed by tx-end (each child
  needs an explicit `transfer` / `share` / `freeze` / `delete`).
  The `OwnershipIndex` re-keys at commit.
- **Gas-payer object selection** — **Resolved in §9.4.** The PTB names
  the gas-payer `Coin<LOOM>` explicitly. Insufficient value = hard
  fail pre-execution in v0. v1: optional sponsor field.
- **Capability revocation** — **v0: no explicit revocation.** Issuers
  who want revocability hold a `RevokeCap<Cap>` and pass it into a
  `cap::revoke` function that flips a stored bool inside the
  capability's payload; checking petals consult that bool. v1: native
  revocation lists with shorter on-chain costs.

## 18.1 Open questions deferred to v1+

- **Resolution policy schema.** §13 reserves the field; the policy
  object type and staking integration land in v1.
- **Parallel PTB scheduling.** Object versioning enables it; scheduler
  design is v1+.
- **Wire-format break to drop `Account.loom` and `Account.code_hash`
  after phase 4.** Decision deferred pending operational data.
- **zkVM proofs.** Host imports are zk-friendly; proof generation
  is v1+.

## 19. v0 acceptance

1. **Foundation crates build.** All Phase 1 crates compile, pass unit
   tests.
2. **Legacy untouched.** Existing `bloom-contract` workspace tests
   pass unchanged. Existing docker DEX e2e passes unchanged.
3. **Fungible petal works.** A PTB creates a currency, mints, splits,
   merges, transfers, burns. Linearity enforced (orphan = revert).
4. **`Account.loom` cache consistency.** After arbitrary PTB sequences
   touching `Coin<LOOM>`, the end-of-block invariant
   `accounts[addr].loom == sum(coin.value for coin owned by addr where
   T = LOOM)` holds for every address.
5. **Legacy `Transfer` compat shim.** A `TxKind::Transfer` and a
   `TxKind::SubmitPtb` performing the equivalent `Coin<LOOM>` split +
   transfer produce identical state roots.
6. **DEX pool works.** A PTB creates a `Pool<USDC, LOOM,
   ConstantProduct>`, adds liquidity, swaps, removes liquidity.
   Invariant violation reverts. `k` non-decreasing over many swaps.
7. **Router multi-hop works.** A PTB invokes
   `router::swap_2hop<A, B, C, ConstantProduct, ConstantProduct>` and
   the `all_pools_k_non_decreasing` invariant holds across all
   touched pools.
8. **No wallet-enshrined swap logic.** Wallets / CLIs construct PTBs
   that reference the `/bloom/dex/router` petal for any swap longer
   than 1 hop; multi-hop math does not exist in wallet code.
9. **Capability auth works.** Mint without `&MintCap` reverts.
   Transfer a cap; new holder can mint; old holder cannot.
10. **Multi-validator parity.** Four-validator docker run executes a
    swap PTB end-to-end and all validators agree on state root.
11. **Atomicity.** A PTB whose second swap reverts rolls back the
    first swap's state changes.
12. **Manifest custom section round-trip.** For every new-framework
    petal: extracting `bloom_petal_manifest_v0`, canonical-decoding,
    and re-encoding yields byte-identical output.
13. **`petals.lock` resolution.** `bloom contract build` fails closed
    when a cross-petal type reference is missing from the lock; passes
    when present.
14. **No `msg.sender` in new petals.** Grep for `msg.sender` /
    `msg::sender` in new-framework crates: zero matches.
15. **No `u256` in new petals.** Grep for `U256` / `u256` in
    new-framework crates: zero matches except where explicitly
    bridging legacy types.
16. **Determinism.** Same PTB sequence on same initial state produces
    same state root on independent validator runs.
