# VFS Petal Pipes — Front Door + DeFi Demo

**Status:** design, approved for planning
**Date:** 2026-05-22
**Branch:** `feat/bloom-like-petals`
**Predecessor:** `2026-05-21-vfs-petal-pipes-handoff.md` (the vision)
**Scope of this spec:** the *protocol* front-door layer + a *DeFi smart-contract demo* that proves it (litmus 5.1/5.2). Bloombook is a separate downstream spec.

---

## 1. Goal

Advance Bloom toward the handoff vision — UNIX-style paths, stdin/stdout, and pipes composing Petals into atomic transactions — by building the **front door** on top of machinery that already exists, and proving it with a real on-chain DeFi pipe.

The deep layers are already implemented and tested on a real chain:

- **PTB = the transaction plan.** `bloom-script`'s `PtbTx{ commands, signers, gas_* }` with `Arg::Use{cmd_idx,ret_idx}` is exactly the handoff's "transaction plan", and `Use` is already a DAG edge, not just linear. Atomicity, snapshot rollback, gas reservation/refund, signature checks, and linearity (no double-spend) are implemented and pass end-to-end (`crates/bloom-chain-node/tests/ptb_submit_e2e.rs`, `ptb_atomicity.rs`, `examples/petal-dex/.../single_hop_swap.rs`).
- **The petal ABI is already byte-in/byte-out.** `#[bloom::petal]` emits one `__petal_<fn>` export per public fn with a `(args_ptr,args_len,ret_ptr,ret_cap)` buffer ABI. Dispatch is by name, not a 4-byte selector.
- **The VFS path is already in the manifest.** Each petal's signed `bloom_petal_manifest_v0` carries `module_path` (e.g. `/bloom/dex/pool`) plus its `functions`. `ChainStateIface::resolve_path(path) -> Option<Hash32>` already resolves path → petal.
- **Packets ≈ typed Objects.** `TypeTag::Concrete{type_name,type_args}` already expresses `Token<USDC>`; `Object{id,type_tag,owner,version}` + content-addressed `ObjectId` + the canonical no-float codec + handle-based linearity give the typed/linear packet core.

What is missing is entirely the front door: an executable-endpoint surface, a builder that lowers composition into a `PtbTx`, a serialized packet envelope, bounded/paginated projection, and the agent-facing invocation surface. Plus one petal-side gap: the DEX swap is not yet a real wasm export.

## 2. Principle: protocol vs. petal

A hard line, matching the existing repo rule (petal impls **and** tests live outside `crates/`; protocol crates are chain/VM only):

- **Protocol (in `crates/`)** — the enshrined front-door primitives and the petal-facing interface contract. The subject of this spec.
- **Smart contracts (in `examples/`)** — DeFi (reuse + extend the existing fungible/DEX petals). They *rely on* the protocol; they never extend it. DeFi AMM math lives in the petal, never in the protocol host.

## 3. Architecture

The consensus core, state, and the PTB *executor* do not change semantically. We add a front-door layer that lowers UNIX-ish composition into the `PtbTx` the engine already runs atomically.

```
endpoint paths (manifest module_path + fn)
        │  resolve path → (petal_hash, fn, abi)
        ▼
PtbSession (bloom-ptb-builder)
   ▲   ▲   │ lowers
   │   │   ▼
   │   │  PtbTx{ commands:[Move…], Arg::Use edges } ─▶ validate_ptb ─▶ PtbExecutor (atomic, existing)
   │   └── /bloom/tx/<id>/…        (NFS read/write staging — canonical substrate)
   └────── bloom pipe '<expr>'     (CLI sugar — same PtbSession)
```

### 3.1 Components

**PROTOCOL — new/changed in `crates/`:**

| Unit | Responsibility | Builds on |
|---|---|---|
| `bloom-ptb-builder` (new crate) | `PtbSession`: turn an ordered list of (endpoint-path, args, use-edges) into a **validated** `PtbTx`. Shared by CLI + tx-session — one source of truth. | `bloom-script` `PtbTx/Command/Arg/UseRef`, `validate_ptb` |
| Endpoint resolver (extend `bloom-petal-manifest` and the `ChainStateIface` path hook) | `path → (petal_hash, fn, abi)` derived from the signed manifest (`module_path` + `functions`). Not a new source of truth. | `resolve_path` (`crates/bloom-script/src/chain_iface.rs:157`), `PetalManifestV0.functions` |
| `tx` VFS handler (in `bloom-vfs`) | `/bloom/tx/new`, `/bloom/tx/<id>/{cmd,status,commit,abort}` backed by a `PtbSession`. Pure NFS read/write. | `Handler` trait (`crates/bloom-vfs/src/handler.rs`), `bloom-ptb-builder` |
| Packet envelope (module in `bloom-objects`) | Canonical typed value crossing the pipe boundary as a **reference within the plan** — not bearer bytes. | `TypeTag`, object canonical codec |
| Bounded projection / pagination primitive (in `bloom-vfs`) | `ls` returns bounded affordances; collections project as `page/000000`. Added now, lightly exercised by DeFi; Bloombook leans on it later. | `Handler::list` |
| Generic-dispatch codegen (`bloom-resource-macros`) | Generic petal fns emit a **real** `__petal_<fn>` export doing runtime type-erased dispatch (kills the `NotImplemented` shim). | existing `#[bloom::petal]` shim, `TypeTag::Generic`, PTB `TypeArg` |

**`bloom` CLI:** add `bloom pipe '<expr>'` — parses linear `|` and named `--a <(…)>` inputs into use-edges, drives a `PtbSession`, commits, streams stdout.

**PETAL — in `examples/petal-dex/`:** update pool/router petals so swap/add-liquidity are real wasm exports (AMM math lives in the petal, operating on the uniform `Coin<T>` object layout via host object calls). DeFi integration tests prove litmus 5.1/5.2 through the pipe front door.

### 3.2 The `PtbSession` (canonical substrate)

Both frontends drive the same `PtbSession` type — that is how "CLI over tx-session" stays one source of truth. The NFS handler maps file ops onto a `PtbSession`; the CLI maps a pipe expression onto a `PtbSession`.

```
PtbSession::new()                          -> SessionId
PtbSession::append_command(line) -> Result<cmd_idx, ValidationError>
PtbSession::status()             -> SessionStatus   // resolved endpoints, arg/use typing, est. gas
PtbSession::commit(keystore)     -> Receipt
PtbSession::abort()
```

### 3.3 Tx-session VFS tree (`/bloom/tx/`)

```
new                 # cat → allocates a PtbSession, returns "<id>\n"
<id>/
  cmd               # write a command line → append_command; cat → lists appended cmds
  status            # cat → JSON: resolved endpoints, arg/use typing state, est. gas
  commit            # cat → finalize + sign + submit; returns receipt (NDJSON). Errors leave session intact.
  abort             # write/cat → discard
```

Pure NFS read/write (the handoff's open-question-2 path), so it works over the existing NFSv4.1 mount with no exec verb.

### 3.4 Command-line grammar

One line per command, written to `cmd` (or one stage of a `bloom pipe` expression):

```
<endpoint-path> [arg …] [as <label>]
```

Each arg lowers to an existing `Arg` variant:

- `key=value` / positional literal → `Arg::Const` (canonical-encoded literal)
- `@<cmd>.<ret>` or `@<label>` → `Arg::Use{cmd_idx,ret_idx}` (the pipe edge)
- `obj:<id>[@ver]` → `Arg::Object{id,version,access_mode}`
- `signer:<i>` → `Arg::Signer`
- `type:<type-tag>` → `Arg::TypeArg` (for generic endpoints)

Appending resolves the endpoint path → `(petal_hash, fn)`, builds a `Command::Move`, and runs **incremental validation** against the manifest fn signature (arity/types, plus `Use`-ref typing against prior return slots, mirroring `validator.rs:367-406`). A bad command fails the write with the validator message; the session is unchanged.

`cat commit` assembles `PtbTx{ signers, commands, gas_payer, gas_budget, gas_price, expiry_block }`, auto-selects the signer's `Coin<LOOM>` gas payer (reuse `coin_select`), signs the digest via keystore using composite xDSA, submits through the existing node submit path, blocks for the receipt, and returns it as canonical NDJSON. Failure → existing snapshot-drop atomicity; nothing commits.

### 3.5 CLI lowering (`bloom pipe '<expr>'`)

- Stages separated by `|`; each stage `= <endpoint-path> [arg …]`.
- A stage's primary output auto-binds to the next stage's primary input as `@<prev>.0` — the linear `A|B|C` case.
- Named `--a <(<sub-expr>)>` lowers the sub-expr to its own command(s) and binds the `--a` slot to its final output ref — the **DAG / add-liquidity** case (litmus 5.3).
- The CLI builds a `PtbSession` and commits — behavior identical to the NFS path.

## 4. Packet envelope

A **Packet** is the typed value on a pipe edge, and it is a **reference within the plan**, never bearer bytes:

```
Packet   { type_tag: TypeTag, ref: PacketRef }
PacketRef = Use{ cmd_idx, ret_idx }    // intermediate: resolves only inside THIS plan
          | Object{ id, version }       // a persisted object the signer has access to
```

- Canonical bytes via the existing `bloom-objects` codec (handoff Phase 0: reuse existing codecs, not JSON, for committed data). A human/debug text projection for `cat`/introspection is allowed but is **non-authoritative**.
- **Anti-duplication is the existing executor, not new code.** A `Use`-packet resolves only inside the atomic plan that produced it — copying its bytes (tee/temp file) into a *different* plan resolves to nothing. An `Object`-packet is gated by optimistic version + signer authority (`check_access_mode`, `validator.rs:587-621`). Spending always requires the chain's borrow-table row, enforced by `BorrowTable::linearity_check` (`crates/bloom-script/src/borrow_table.rs:260-263`) + `validate_ptb`. This is exactly Phase 4's "anchored to object IDs, signer authority, and transaction-plan use refs." The envelope is the *serialization*; the guarantee already exists and is tested.
- An endpoint's "stdout" = its command return slots (declared `TypeTag`, already type-checked on `Use`), surfaced via `ExecutionReport.command_outputs`.
- **Phase C implementation note (anti-duplication = existing executor, not new code).** The `bloom-objects::packet` module is *only* a codec + value type — `Packet { type_tag: TypeTag, ref_: PacketRef }` with `PacketRef::Use{cmd_idx,ret_idx} | Object{id,version}`. It enforces nothing at runtime. A `PacketRef::Use` carries only the `(cmd_idx, ret_idx)` coordinate with **no plan identity**, so copying its bytes into a different plan resolves to nothing (there is no such command / its return type is incompatible). The "Use-packet from plan A is rejected in plan B" guarantee lives entirely in `BorrowTable::linearity_check` + `validate_ptb` + the executor's per-plan `command_outputs`. The envelope is the serialization; the invariant is not re-implemented in `bloom-objects`.

## 5. Generic-dispatch monomorphization

**Current state:** `#[bloom::petal]` emits one `__petal_<fn>` per pub fn, but for *generic* functions it emits a `NotImplemented` shim (`bloom-resource-macros` codegen generic branch); the DEX math runs host-side in `ops::*`.

**Change:** generic fns emit a *real* export doing **runtime type-erased dispatch** (Sui/Move-style).

- `swap_exact_in<A,B>(pool, coin_in: Coin<A>, min_out) -> Coin<B>` → one real `__petal_swap_exact_in`.
- Type args `A,B` arrive as `Arg::TypeArg(TypeTag)`, carried as the leading type-args vector in calldata. The manifest fn signature already declares type-param arity and the validator checks it (`typecheck_move_cmd`).
- The body operates on **object handles + type-tags**, not concrete Rust types. `Coin<T>` is already a phantom-typed handle over a uniform object (`payload = {balance: u128, …}`, concrete `T` recorded in the object's `type_tag`). The AMM math is type-agnostic: it reads/mutates `u128` balances via the host object API and uses the tags only to (a) assert the coin types match the pool's declared pair and (b) stamp the output coin's tag.
- **`ops::*` math moves from the host into the petal wasm** (operating on handles). The protocol host gains zero DeFi-specific code — honors §2.

**Codegen mechanics:**

- The macro drops the `NotImplemented` branch; instead it decodes the type-args vec from calldata, binds it into a per-call `TypeArgs` context (thread-local, set by the shim), then calls the user body with handle-typed params.
- Enabling change in `bloom-resource`: phantom-typed wrappers (`Coin<T>`, `Capability<T>`) resolve `type_tag()` from that per-call context instead of a compile-time const. `object_create`/`object_transfer` already take a `TypeTag` argument, so stamping the runtime tag is straightforward.
- `bloom-resource-macros` ensures the generic export lands in the wasm and is listed in the manifest `functions` table (so the endpoint resolver sees it).

**Rejected alternatives:** author-site concrete monomorphization (one export per token pair) cannot work — DEX pools are created for arbitrary pairs at runtime and can't be enumerated at compile time. AMM math as a protocol host import is rejected — it would enshrine DeFi math in the protocol, violating §2.

**De-risk:** build this first against a *trivial* generic petal (`identity<T>(Coin<T>) -> Coin<T>`) before touching the real swap.

## 6. Testing & litmus matrix

TDD throughout — write the failing test first.

**Protocol:**

- `bloom-ptb-builder`: pipe expr & cmd-line grammar → expected `PtbTx` (linear edges, named/DAG edges, label resolution); error cases (dangling `@ref`, type mismatch).
- Endpoint resolver: manifest `module_path`+fn → `(hash, fn, abi)`; unknown path / unknown fn fail closed.
- tx-session handler: `new → cmd (several, incl. bad) → status → commit` over an in-process VFS; `abort` discards; a bad `cmd` leaves the session intact.
- Packet envelope: canonical encode/decode round-trip; a `Use`-packet from plan A is rejected in plan B; debug projection is non-authoritative.
- Generic dispatch: trivial generic petal export runs via PTB `TypeArg`; output object carries the correct runtime type-tag; linearity enforced.

**DeFi demo (`examples/petal-dex/`, real wasm, through the front door):**

- **5.1 one-hop swap** — `spend usdc 1000 | dex/pool/swap min-out=980 | wallet/receive`: real pool export runs, alice debited / bob credited, slippage failure reverts everything, output packet not double-spendable. Run via **both** CLI and tx-session.
- **5.2 two-hop atomic** — `spend | swap | swap | receive`: the case the review flagged as **never combined today**. Both pools update atomically; intermediate `Coin<LOOM>` never committed to the wallet; failure in either pool reverts the whole plan. Headline new proof.
- **5.3 add-liquidity DAG** — *stretch* (the named-input lowering is built regardless): `add-liquidity --a <(spend eth) --b <(spend usdc) --min-lp 10 | receive`.
- **5.4 swap+LP+stake** — **out of scope** (no stake petal exists).

## 7. Phased implementation plan

Ordered so each phase is independently verifiable and the riskiest unit is de-risked first.

- **Phase A — Generic dispatch.** Codegen + `bloom-resource` runtime type-arg binding; prove with a trivial generic petal. Gate: real generic export runs via PTB `TypeArg`, correct output tag, linearity holds.
- **Phase B — Endpoint resolver + `bloom-ptb-builder` + `PtbSession`.** Path→endpoint; cmd-line/pipe grammar → validated `PtbTx`. Gate: builder unit tests green (linear + DAG + errors).
- **Phase C — Packet envelope.** Canonical codec + cross-plan rejection. Gate: round-trip + isolation tests.
- **Phase D — Frontends.** tx-session VFS handler + `bloom pipe` CLI, both over `PtbSession`; bounded-`ls`/`page` projection primitive. Gate: NFS staging flow and CLI flow both commit identically.
- **Phase E — DeFi petals → real exports.** Move `ops::*` math into the pool/router wasm via Phase A. Gate: pool `swap_exact_in` and router hops are real exports listed in the manifest.
- **Phase F — DeFi litmus.** 5.1 + 5.2 end-to-end through both frontends; 5.3 stretch. Gate: all in-scope litmus tests green.

**Dependencies:** A→E, B→D, C→D, (D,E)→F. **A, B, C can run in parallel.**

## 8. Out of scope (explicit)

- Bloombook (social petals, feeds, voting) — separate downstream spec; this spec only adds the bounded-projection/pagination *primitive* it will reuse.
- FUSE/9P exec mounts and kernel-level executable paths — the tx-session VFS substrate sidesteps the NFS no-exec limitation.
- Composite xDSA signing — verified by the production PTB verifier through the chain key registry (`sig_verifier.rs`).
- litmus 5.4 (swap+LP+stake) — no stake petal.
- Replacing or collapsing `PetalMode::{Local,Onchain,Chain}` — the front door targets chain execution; local/offchain unification is not required here.

## 9. Key reuse anchors (do not rebuild)

- `bloom_script::types::{PtbTx, Command, Arg, UseRef}` — the canonical transaction-plan IR (`crates/bloom-script/src/types.rs:74-245`). The builder lowers directly to `Vec<Command>` with `Arg::Use` as pipe edges.
- `PtbExecutor` + `ExecutionReport` (`crates/bloom-script/src/executor.rs`) — the atomic dispatcher; `command_outputs` is the per-command "stdout".
- `validate_ptb` + `ChainStateIface` (`validator.rs:79`, `chain_iface.rs:146-160`) — full pre-execution checks; the builder produces a `PtbTx`, this validates it unchanged.
- `ChainPetalRunner` (`crates/bloom-chain-node/src/chain_petal_runner.rs`) — the real wasm bridge (calldata in / return+revert out / snapshot threading); the chain endpoint adapter wraps it.
- `bloom-objects` `Object`/`TypeTag`/`ObjectId` + canonical codec (`object.rs:97-139`, `type_tag.rs:34-148`, `id.rs:31-42`) — backbone of the Packet envelope.
- `bloom_vfs::Handler` + `Vfs` router (`crates/bloom-vfs/src/handler.rs`, `router.rs`) — the dispatch spine the `tx` handler plugs into.
- `#[bloom::petal]` codegen `emit_petal_shim` + manifest `module_path`/`functions` — the byte-in/byte-out ABI and the path/endpoint source of truth.
