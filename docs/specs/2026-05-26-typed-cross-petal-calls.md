# Typed Cross-Petal Calls

Status: draft
Date: 2026-05-26

## Goal

Add cross-petal calls as a typed, method-oriented authoring surface while
keeping the chain execution model deterministic, hash-pinned, fuel-bounded, and
auditable.

Petal authors should write code that feels like:

```rust
let out = petal::pool::swap_exact_in(coin_in, pool, min_out);
```

The macro/runtime lowers that into deterministic chain VM calls. Contract
authors do not pass raw hashes, method names, framed calldata, return pointers,
or buffer capacities.

The v1 design is intentionally conservative:

- Static dependencies only.
- Hash-pinned dependencies only.
- Synchronous fail-fast calls only.
- No catchable mutating calls.
- No dynamic interface registry or governed path dispatch yet.

Interface IDs, governed bindings, and catchable read-only fallbacks are future
extensions, but the manifest should start carrying enough ABI identity to make
that migration straightforward.

## Authoring Model

Add `#[bloom::use_petal]` as metadata consumed by the enclosing
`#[bloom::petal]` macro. It is module-level, repeatable, and must appear on the
same module item as `#[bloom::petal]`:

```rust
#[bloom::petal(path = "/bloom/dex/router", version = "0.1.0")]
#[bloom::use_petal(
    alias = "pool",
    path = "/bloom/dex/pool",
    pinned_hash = "0x...",
    version = "0.1.0",
    functions = [
        "quote_exact_in",
        "quote_exact_in_reverse",
        "swap_exact_in",
        "swap_exact_in_reverse",
        "swap_exact_out",
    ],
)]
pub mod router {
    // generated module is available as `petal::<alias>`
}
```

Rules:

- `alias` must be unique within the caller manifest.
- `alias` and method names must be ASCII `[a-zA-Z_][a-zA-Z0-9_]*`.
- `pinned_hash` is required for chain-mode v1. `path` and `version` are
  human/audit metadata and are checked against the pinned hash's manifest.
- The macro reads a build-time ABI lock input for each dependency. The build
  fails if the callee ABI cannot be found, the pinned hash/path/version do not
  match, a function is missing, or the generated Rust types cannot be named.

The macro generates a local client module:

```rust
petal::pool::quote_exact_in(pool, amount_in) -> u128
petal::pool::swap_exact_in(coin_in, pool, min_out) -> Coin<Erased>
```

Generated client functions:

- Use the callee manifest ABI for argument and return types.
- Encode args with the same `CallArgsWriter` envelope used by PTB Move calls.
- Convert object wrappers to stable `ObjectId`s by calling `object.id(handle)`.
- Invoke one hidden indexed host import, not method-specific imports.
- Decode return slots with the callee manifest return ABI.
- Re-borrow returned object IDs into handles before constructing wrapper return
  values.
- Abort the parent call on callee failure.

## VM ABI

The source-level API is typed and method-oriented. The wasm-level ABI is a
single fixed host import so chain admission can remain table-driven:

```text
module: "petal"
name:   "call"
sig:    (
          dep_idx: i32,
          method_idx: i32,
          args_ptr: i32,
          args_len: i32,
          ret_ptr: i32,
          ret_cap: i32
        ) -> i32
```

`dep_idx` indexes the caller manifest's ordered `uses` table. `method_idx`
indexes that dependency's ordered function list. Generated clients hide both
indices.

Return behavior:

- On success, writes the child return envelope into `ret_ptr[..ret_cap]` and
  returns its byte length.
- If `ret_cap` is too small, returns `-needed_len`. The generated client may
  retry once with a larger buffer. Retrying is buffer-only; the child call must
  not be re-executed for the same logical call.
- On callee revert, wasm trap, host denial, ABI mismatch, out-of-fuel, or
  invariant failure, the host import aborts the parent call. Hand-written wasm
  cannot ignore a child failure by checking a negative return code.

The VM still uses pointer/length scalar plumbing internally because wasm host
imports require scalar ABI. That plumbing is not part of the petal authoring
surface.

## Manifest And Dependency Identity

Introduce a new manifest schema version or a versioned extension section. Do
not append fields silently to the positional `PetalManifest` codec.

Add declared uses:

```rust
pub struct PetalUseDecl {
    pub alias: String,
    pub path: String,
    pub version: Option<String>,
    pub pinned_hash: Hash32,
    pub interface_hash: Hash32,
    pub functions: Vec<PetalUseFunctionDecl>,
}

pub struct PetalUseFunctionDecl {
    pub name: String,
    pub args: Vec<ArgDecl>,
    pub returns: Vec<TypeTag>,
    pub effects: EffectDecl,
}

pub enum EffectDecl {
    Pure,
    View,
    Mutating,
}
```

`interface_hash` is the hash of the canonical ABI surface for the declared
dependency: function names, type params, argument kinds, object access modes,
return type tags, signer/capability requirements, and effect declarations. v1
does not use `interface_hash` for dynamic dispatch, but it gives tools and
future governed registries a stable compatibility identity.

Validation rules:

- Load the caller manifest and every pinned dependency manifest.
- Verify `pinned_hash` exists in the code store.
- Verify the dependency manifest's `module_path` equals `path`.
- Verify the dependency manifest's version equals `version` if provided.
- Verify every declared function exists and its canonical ABI matches.
- Verify the declared `interface_hash`.
- Reject duplicate aliases, duplicate function names, malformed aliases, and
  malformed method names.
- Reject any wasm import from `petal.call` unless the caller manifest has at
  least one declared use.

Dependency closure:

- Validation builds a transitive dependency closure containing the top-level
  PTB petals and all reachable pinned callees.
- The closure is bounded by consensus constants:
  - `MAX_PETAL_DEPENDENCIES_PER_PTB`
  - `MAX_PETAL_USE_DECLS_PER_MANIFEST`
  - `MAX_PETAL_METHODS_PER_USE`
  - `MAX_DEPENDENCY_WASM_BYTES_PER_PTB`
  - `MAX_DEPENDENCY_MANIFEST_BYTES_PER_PTB`
- Dependency cycles are allowed only as runtime call cycles bounded by
  `MAX_PETAL_CALL_DEPTH`; validation must still terminate by tracking visited
  hashes.

Audit output:

- The receipt/simulation trace should include a dependency lock table:
  `alias`, `path`, `pinned_hash`, `manifest_hash`, `interface_hash`, and
  `version`.
- Historical replay uses block-state code by hash. It must not re-resolve a
  mutable path binding from current state.

## Call Frame Semantics

Nested calls run in explicit call frames:

```text
CallFrame {
  caller_hash,
  callee_hash,
  dep_idx,
  method_idx,
  depth,
  fuel_remaining,
  explicit_arg_grants,
  checkpoint,
}
```

The shared `PtbHostCtx` remains the source of truth for the PTB borrow table,
handles, logs, deletes, ownership changes, signers, and command outputs.
However, a child frame may only act on objects explicitly granted through its
cross-call arguments.

Argument grants:

- At cross-call entry, the host decodes child args using the callee manifest.
- For each object arg, the host validates the object exists in the current
  borrow table, matches the expected type tag, and is compatible with the
  callee's declared access mode.
- The child frame receives an explicit grant for that `ObjectId` and access
  mode.
- `object.borrow` inside a child may only borrow object IDs present in the
  frame grants, except for objects the child itself creates during that frame.
- A child `ReadOnly` grant must remain read-only even if the parent had a
  broader mutable row in the PTB borrow table.
- A child `Mutable` or `Consume` grant requires the parent row to have at least
  that authority.

Return handling:

- Object wrapper return slots are stable `ObjectId`s.
- Generated clients re-borrow returned object IDs into handles with the access
  mode needed by the wrapper and downstream use.
- The host validates returned object IDs exist in the live borrow table and
  match the callee manifest return type before handing bytes to the caller.
- Returned objects created by the child are transient PTB objects and remain
  subject to the normal tx-end linearity check.

Command output behavior:

- Child calls do not append top-level `command_outputs`.
- `ptb.command_output` inside a child sees only completed prior PTB commands,
  never the parent command's in-progress return slots.

Object permissions:

- Do not relax `object.mutate`, `object.create`, `object.transfer`,
  `object.share`, `object.freeze`, or `object.delete`.
- Preserve the existing linear-move exception: non-defining petals may delete
  an object explicitly passed with `Consume` authority.
- Cross-petal calls are how one petal asks the type-defining petal to mutate
  its own objects.

## Snapshot, Fuel, Revert, And Invariants

Nested calls must be implemented inside the chain VM/linker call path. Do not
re-enter `ChainPetalRunner` while its outer snapshot mutex is held.

Snapshot rules:

- Before child execution, create a child checkpoint from the current parent
  frame state.
- On child success, child mutations are visible to the parent and to later
  sibling calls in the same PTB command.
- On child failure, abort the parent call and enclosing PTB. v1 does not expose
  catchable mutating failures.
- The enclosing PTB revert rules still discard all non-gas PTB mutations.

Fuel rules:

- Charge a fixed cross-call surcharge plus byte costs for args and returns.
- Child execution receives a budget no greater than the parent's remaining
  fuel after surcharge.
- Subtract `child_fuel_used` from the parent frame immediately on child return,
  revert, or trap.
- On child out-of-fuel, charge the exhausted child budget and abort the parent.
- Module compilation/instantiation must either be precharged or cached from the
  validated dependency set so repeated cross-calls cannot create unmetered DoS.

Invariant rules:

- Callee function-exit invariants run on child success under the same fuel and
  revert rules as top-level Move calls.
- Object invariants attached to callee-owned objects must still fire when those
  objects are mutated by child execution.
- Invariant failure aborts the child, parent, and enclosing PTB.

Diagnostics:

- Add first-class error variants for dependency resolution, dependency ABI
  mismatch, undeclared cross-call, call-depth exceeded, explicit-grant denial,
  child revert, child trap, and child out-of-fuel.
- Error messages should include caller alias, dependency path, pinned hash,
  resolved method, and argument index when applicable.

## Effect Types

Function declarations should carry an effect:

- `Pure`: no object reads/writes, no logs, no signer/ptb access.
- `View`: object reads allowed, no object mutation/create/delete/transfer,
  logs optional by policy.
- `Mutating`: full declared object effects allowed.

v1 cross-petal calls support all three effects, but all failures are fail-fast.
Future catchable `try_view` calls may be added for oracle/risk fallback. Do not
add catchable mutating calls until nested rollback and audit semantics are
fully specified.

Quote functions in the DEX should be `View` and host-enforced read-only.

## DEX Changes

`/bloom/dex/pool` remains the only petal that mutates `Pool` and `LpPosition`.

Add pool quote exports:

```rust
quote_exact_in(pool: &Resource<Pool>, amount_in: u128) -> u128
quote_exact_in_reverse(pool: &Resource<Pool>, amount_in: u128) -> u128
```

Ensure quote exports are declared `View`.

Update `/bloom/dex/router` to declare a pinned pool dependency:

```rust
#[bloom::petal(path = "/bloom/dex/router", version = "0.1.0")]
#[bloom::use_petal(
    alias = "pool",
    path = "/bloom/dex/pool",
    pinned_hash = "0x...",
    functions = [
        "quote_exact_in",
        "quote_exact_in_reverse",
        "swap_exact_in",
        "swap_exact_in_reverse",
        "swap_exact_out",
    ],
)]
pub mod router { ... }
```

Replace router's inline pool logic:

- `quote_Nhop` calls `petal::pool::quote_exact_in*`.
- `swap_1hop` calls `petal::pool::swap_exact_in`.
- `swap_2hop` calls pool for hop 1, receives the intermediate
  `Coin<Erased>`, then calls pool for hop 2.
- `swap_3hop` repeats the same pattern.
- `swap_exact_out` and reverse direction should delegate to pool exports rather
  than duplicate pool math.
- Router no longer decodes pool payloads or calls `object_mutate` on pool
  objects.

This v1 router can keep fixed 1/2/3-hop exports to match the current example.
An arbitrary-length route interface is a follow-up once vectors and route
objects are better established.

MEV note: quote calls and atomic multi-hop execution do not prevent sandwiches.
Slippage and deadline/version guards still belong in router APIs, and private
orderflow remains a separate concern.

## Observability And Simulation

Receipts and simulations should expose a call tree:

```text
caller_hash
callee_hash
alias
method
effect
fuel_used
touched_objects
return_slot_count
revert_source
```

This trace is not top-level command output and is not usable as `Arg::Use`.
It exists for wallets, explorers, auditors, MEV warnings, and DeFi risk
simulation.

## Test Plan

Macro/runtime tests:

- `#[bloom::use_petal]` emits manifest dependency entries.
- Duplicate alias and duplicate method declarations fail.
- Missing ABI lock input fails at compile time.
- Generated clients encode args and decode returns correctly.
- Generated clients lower to hidden `petal.call(dep_idx, method_idx, ...)`.
- Object-return slots are re-borrowed into usable handles.

Manifest/validation tests:

- New manifest schema round-trips.
- Old manifests remain admissible under defined compatibility rules.
- Pinned dependency loads by hash.
- Path/hash mismatch rejects.
- Version mismatch rejects when version is provided.
- Interface hash mismatch rejects.
- Undeclared `petal.call` import rejects.
- Oversized dependency closure rejects.
- Dependency cycles validate without infinite recursion.

Chain VM/security tests:

- Hidden indexed call invokes the correct callee.
- Callee revert/trap/out-of-fuel aborts parent.
- Child fuel is charged against parent remaining fuel.
- Call depth 17 rejects.
- Child invariant failure aborts the PTB.
- Child logs are attributed to child hash.
- Child-created objects can return to parent and then to downstream PTB
  commands.
- Child cannot borrow or mutate an in-scope object that was not explicitly
  granted.
- Mutable parent row passed to read-only child remains read-only in child.
- Read-only parent row passed to mutable child rejects.
- Returned object ID/type mismatch rejects.
- Huge args/returns/logs reject at caps.
- Repeated cross-calls do not repeatedly compile modules without metering or
  cache reuse.

DEX tests:

- Router single-hop swap delegates to pool and succeeds.
- Router two-hop swap delegates twice and remains atomic.
- Second-hop slippage failure reverts first-hop pool mutation.
- Exact-out and reverse-direction routes delegate to pool.
- Quote exports are enforced read-only.
- Router no longer has direct pool payload mutation code.
- Route/pool type mismatch rejects.
- Existing pool lifecycle tests remain green.

Replay/governance tests:

- Historical replay after path rebinding still uses pinned hashes from the
  original block state.
- Unpinned chain-mode dependency is rejected.
- Dependency lock table appears in receipt/simulation output.

## Follow-Ups

These are explicitly out of v1 but should be designed next:

- Interface-based governed dispatch using `interface_hash`.
- Governed path bindings with activation epochs, timelocks, and rollback
  metadata.
- Catchable `try_view` calls for oracle/risk fallback.
- End-of-PTB invariant hooks for lending markets, flash accounting, and reserve
  reconciliation.
- Hot-object/sharded state patterns for high-throughput pools, reserves, and
  oracles.
