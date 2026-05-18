# bloom: Petals — content-addressed wasm modules in the VFS

**Status:** draft (v0 implemented; onchain/local split designed, not yet built)
**Date:** 2026-05-18
**Owners:** —
**Addresses:** The "petals" concept from the Bloom paper — content-addressed
computation that any participant can install, name, run, and (eventually)
verify. v0 introduces the runtime; this spec also drafts the v1 split
between local and on-chain-replayable petals.

## 1. Goals

1. **A runtime for content-addressed wasm modules** ("petals") that live
   under `~/.bloom/petals/` and are exposed as a subtree of the VFS at
   `public/`. Each petal is identified by the BLAKE3 hash of its
   canonical wasm bytes.
2. **A petname → hash registry** so humans can refer to petals by name
   while the hash remains the source of truth. Names persist in a TOML
   file; renaming is a registry write, not a re-install.
3. **Capability-gated host access** to the daemon's live VFS, so a petal
   can read `/chains/<c>/...` or write `/wallets/<w>/stage/tx` exactly
   when its declared capabilities allow.
4. **CLI + IPC surface**: `bloom petals install / run / ls / name`, plus
   matching JSON-RPC methods on the daemon's UDS socket.
5. **A path to on-chain-style determinism** — a follow-up mode where a
   petal's I/O is restricted enough that its execution is replayable from
   `(petal_hash, input, chain_pins)` alone.

## 2. Non-goals (v0)

- **Petal execution exposed via the VFS itself.** Reads and lists of
  `public/` work; running a petal is via the IPC method `petals.run` or
  the `bloom petals run` CLI. Avoids re-entrancy (a petal whose
  vfs_read touches its own run path) and a "what does it mean to `cat`
  a petal" question we don't want to answer yet.
- **A petal-to-petal call host import.** A petal can read another
  petal's wasm via `vfs_read("public/<hash>/wasm")`, but there's no
  built-in `petal.call(name)` host function. Pipelining is via stdout →
  stdin at the CLI/IPC layer.
- **Bit-for-bit deterministic execution.** v0 is for local use; replay
  guarantees are a v1 concern (§7).
- **On-chain verification of petal output.** Even after the local /
  onchain split lands, the on-chain piece is just an attestation log;
  zk-proof-of-wasm or optimistic verification is a separate project.
- **Per-petal persistent state.** Each `run` is a fresh wasmtime
  instance. State lives in the VFS the petal reads/writes, not in the
  petal.

## 3. What's implemented (v0)

### 3.1 New crate: `bloom-petals`

`crates/bloom-petals/` (~1.5k LOC, 29 unit tests). Modules:

| module           | role                                                              |
| ---------------- | ----------------------------------------------------------------- |
| `meta.rs`        | `Capability` (`VfsRead` / `VfsWrite`), `PetalMeta` serde struct   |
| `error.rs`       | `PetalError` (NotFound, InvalidHash/Name/Wasm, CapDenied, Vm, …)  |
| `store.rs`       | Content-addressed store under `objects/<hash>` + `meta/<hash>.json`; atomic writes; `install` is idempotent on hash and unions caps |
| `registry.rs`    | TOML-backed petname registry (`names.toml`); `validate_name` rejects empty/dot-leading/path-sep/reserved/hash-like names |
| `host.rs`        | `PetalHost` async trait + `HostError` with stable negative wasm codes (-1 NotFound, -2 Denied, -3 Invalid, -4 Backend) |
| `vm.rs`          | Wasmtime-26 engine, async support, fuel + memory limits, WASI preview-1 stdio, capability-gated `bloom.vfs_{read,write}` host imports |
| `handler.rs`     | `PetalsHandler` exposing the `public/` subtree (see §3.3)         |
| `runner.rs`      | `PetalRunner` glues store + registry + VM; `VfsHost` adapter that bridges petals to the daemon's live `Vfs` |

### 3.2 Daemon integration (`bloom-daemon`)

- `Daemon` gains a `petals: PetalRunner` field, materialised under
  `~/.bloom/petals/{store,registry}` at boot.
- `PetalsHandler` mounted at `public/` so the petals subtree is part of
  the standard VFS surface — visible via `bloom vfs ls /public`, an NFS
  mount, etc.
- `IpcServer` gains an opt-in `with_petals(runner)` builder. `bloom
  serve` enables it. New JSON-RPC methods:
  `petals.install`, `petals.run`, `petals.list`, `petals.resolve`,
  `petals.name`.

### 3.3 VFS layout under `public/`

```
public/
  <hash>/                      directory
  <hash>/wasm                  file, read-only, raw wasm bytes
  <hash>/meta.json             file, read-only, PetalMeta
  <name>                       symlink → <hash>
  names/                       directory
  names/<name>                 file, writable; body is the target hash
```

Writing the empty string to `names/<name>` unsets it; writing a 64-char
hex hash binds it (validated against the store). Lookups, listings, and
reads all behave consistently with the rest of the VFS so existing
tools (`bloom vfs ls`, an NFS mount, an agent that already speaks the
VFS) work without changes.

### 3.4 CLI (`bloom`)

```
bloom petals install <path|-> [--name N] [--cap vfs.read] [--cap vfs.write]
bloom petals run <name-or-hash> [--input <file|->] [--cap vfs.read] [--cap vfs.write]
bloom petals ls
bloom petals name <name> [<hash>]    # omit <hash> to unbind
```

`install` accepts a `.wasm` binary or a `.wat` text module (compiled to
wasm in memory before hashing, so the on-disk hash is canonical
regardless of which form was installed).

`run` streams the petal's captured stdout/stderr to the parent process
and propagates the exit code, so petals are first-class composables in
a shell pipeline.

`--cap` at run time *narrows* the petal's declared caps (intersection);
it can't grant capabilities the petal didn't declare at install.

### 3.5 Capability model — current surface

A petal in v0 can do:

**Without any capability:**

- Read stdin (caller-provided bytes).
- Write stdout / stderr (each capped at 1 MiB, captured in-memory).
- WASI preview-1 minus filesystem/networking: `proc_exit`,
  `clock_time_get`, `random_get`. No fd preopens, no sockets.

**With `vfs.read`:**

- `bloom.vfs_read(path_ptr, path_len, dst_ptr, dst_max) -> i32` —
  reads any VFS path the daemon serves. Buffer-too-small is signalled
  by `-(needed + 0x10000)` so petals can distinguish overflow from
  error codes.

**With `vfs.write`:**

- `bloom.vfs_write(path_ptr, path_len, src_ptr, src_len) -> i32` —
  writes to any writable VFS path (`/wallets/<w>/stage/...`,
  `/watch/...`, `/addressbook/...`, `/public/names/<n>`, etc.).

**Hard sandbox boundaries** (no capability unlocks these):

- No real filesystem access (no WASI preopens).
- No sockets / no network.
- No subprocess / exec / env / args inheritance.
- No direct keystore, chain client, or daemon-process access — only
  what the VFS exposes.

**Resource caps per run:**

- 100M fuel units default (configurable via `RunOptions`).
- 16 MiB linear memory (256 pages).
- 1 MiB stdout, 1 MiB stderr.
- Single-threaded; no `wasi-threads`.

### 3.6 Tests

- 29 unit tests in `bloom-petals` covering store atomicity / caps
  unioning, registry persistence + validation, VM end-to-end runs
  (WAT-compiled wasm), capability denial and grant paths, VFS handler
  round-trips, runner install-from-WAT + run-by-name.
- 2 integration tests in `crates/bloom/tests/cli.rs`:
  - `petals_install_then_ls_then_run` — install a WASI petal that
    writes via `fd_write`, confirm `petals ls` shows it under both
    hash and petname, run it by name and by hash, assert stdout.
  - `petals_name_bind_unbind_reflects_in_vfs` — confirm `petals name`
    flips a symlink visible via `vfs ls /public`.
- All existing daemon / VFS / wallet tests pass unchanged.

## 4. Some petals we've imagined

Across the cap matrix, ordered least → most privileged. (Sketches, not
yet built.)

| Petal           | Caps                       | Sketch                                                                 |
| --------------- | -------------------------- | ---------------------------------------------------------------------- |
| `gas-now`       | none                       | Stdin: recent basefees JSON. Stdout: `{verdict, target_gwei, reason}`. Wrapping pipeline `bloom vfs cat /chains/eth/fees | bloom petals run gas-now`. Algorithm itself is content-addressed. |
| `portfolio`     | `vfs.read`                 | Walks `/wallets/*`, joins balances + token holdings + `/prices/...` into a flat NDJSON table. Pure observer.                  |
| `lens`          | none                       | Pure transformation over someone else's published data. "Rank by yield", "redact below $1k", etc. Composes with portfolio.    |
| `safe-send`     | `vfs.read` + `vfs.write`   | Hardens a sloppy send intent: ENS resolve, addressbook lookup, bytecode check on the destination, gas sanity, then writes to `/wallets/<w>/stage/tx`. Confirm gate still owned by the human. |
| `canary`        | `vfs.read` + `vfs.write`   | Reads a config, writes a `/watch/specs/canary-<hash>.toml` spec. Daemon's watch executor picks it up. Bloom-flavoured cron.   |

Pattern: petals feel most natural when their VFS access is narrow and
explicit. The capability model nudges authors toward small, scoped
tools composed by namespace.

## 5. Capability footguns (v0)

`vfs.write` is broad. A petal granted it can:

- Write to `/wallets/<w>/sign/tx` — trigger a signature + broadcast.
  Same blast radius as the wallet itself.
- Write to `/watch/...` to register watchers.
- Write to `/public/names/<n>` — re-point another petal's petname at a
  different hash (squatting / hot-swap).

Practical posture: `vfs.read` is safe to grant to most agents;
`vfs.write` means "this petal acts as you." The `cap_mask` at run
time lets a caller drop caps below what was declared.

## 6. How to grow the capability surface

Two paths, both available:

### 6.1 Static-link Rust crates into the petal (default)

`alloy` and friends compile to `wasm32-wasi`. Pure-compute use of alloy
(keccak, ABI codec, RLP, address parsing, EIP-712 hashing, signature
recovery) needs no host involvement — the petal author just adds the
dep and ships a slightly larger wasm. Daemon never changes.

### 6.2 Add host imports (use sparingly)

About 20 lines per function in `vm.rs::add_bloom_host`, using existing
`get_memory` / `read_bytes` / `write_bytes` helpers and the
`OVERFLOW_BIAS` convention. Async variants via `func_wrap_async` (the
`vfs_*` imports are the templates).

Use only when:

- **Live daemon state** is the answer (chain registry, etherscan
  client, prices client, name resolver, audit log) and the VFS path
  is too expensive or awkward.
- **Privileged operations** that the petal genuinely shouldn't be
  able to do itself — the prime example is signing with the keystore.

**Lock-in cost:** petals are content-addressed. A petal compiled today
against `bloom.foo(...)` must still work in five years. Mitigations:

- Namespace by version (`bloom.v1.keccak256` etc.) so a `v2` can land
  without breaking `v1` petals.
- Prefer stable primitives (hashing, codec selectors). Avoid exposing
  rich types — host functions must traffic in `i32` / byte buffers, and
  the moment you want to pass `alloy::TransactionRequest` you're
  designing a serialization format.

## 7. v1 plan — local vs onchain petals

### 7.1 Motivation

Two natural petal roles, today undifferentiated:

- **Local petals** — `portfolio`, `gas-now`, `safe-send`. Run on the
  user's machine, read live local state (prices, balances, current
  basefee), use wall-clock and OS randomness freely. They're tools
  the user runs.
- **Onchain petals** — deterministic computations over committed
  inputs. Replayable from `(petal_hash, input, chain_pins)` alone. The
  EVM-smart-contract model: anyone with the same inputs reconstructs
  the same output. The audit-trail / on-chain verification story
  needs this.

The boundary is not whether the petal author chooses to be
deterministic — it's whether the host *offers nondeterministic
imports at all*. Wasmtime instantiation fails with "unknown import"
when a wasm module imports an unregistered function, so a clean
import surface enforces the boundary at load time.

### 7.2 Design

**A new `mode: PetalMode` field on `PetalMeta`**, persisted in
`meta.json`. Default: `Local` (backwards-compatible).

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PetalMode {
    Local,    // today's behaviour
    Onchain,  // deterministic, replayable
}
```

**Local mode** keeps the current surface (`bloom.vfs_*`, full WASI
stdio + clock + random) and the existing `Capability::{VfsRead,
VfsWrite}`.

**Onchain mode** gets a stripped surface:

- WASI: only `proc_exit`, `fd_read` (stdin), `fd_write`
  (stdout/stderr). **No** `random_get`, `clock_time_get`,
  `clock_res_get`, `poll_oneoff`, environment, args.
- No `bloom.vfs_*` (touches live local state).
- New host import: `chain.read_at(chain_ptr, chain_len, block, path_ptr, path_len, dst_ptr, dst_max) -> i32`
  — reads a chain-VFS path pinned to a specific block number. Block
  is part of the petal's input, so the read is replayable from chain
  state alone. Backed by the daemon's `ChainClient` against an
  archive node.
- New capability: `Capability::ChainRead`. Mutually exclusive with
  `VfsRead`/`VfsWrite` (a `mode=onchain` petal with `caps=[vfs.write]`
  is an install-time validation error).

**Composition rules:**

- Local can call onchain (read its deterministic output — fine).
- Onchain calling local would taint determinism — if/when we add a
  `petal.call` host import, it must refuse `onchain → local` at the
  daemon level. One-way valve, same model as Solidity calling an
  oracle.

**CLI:**

```
bloom petals install foo.wasm --mode onchain --cap chain.read
```

Default `--mode local` so existing usage is unaffected.

### 7.3 What it takes to ship

Roughly a day's work for the mode split itself:

1. `PetalMode` enum + serde, default `Local`.
2. Branch in `vm.rs` between `add_local_host` (today's
   `add_bloom_host`) and a new `add_onchain_host`. Build a stripped
   `WasiCtxBuilder` for onchain mode.
3. `Capability::ChainRead` variant + validation that mode and caps
   agree.
4. `--mode` flag on install. `petals.install` IPC param.
5. Backing the `chain.read_at` host import with `ChainClient`
   historical-block reads.

### 7.4 What needs more thought

**Wasmtime execution determinism beyond imports.** Even with a clean
import surface, wasmtime isn't bit-identical across versions or CPUs
by default. For true replayability:

- `Config::wasm_relaxed_simd_deterministic(true)`.
- NaN canonicalization (supported, off by default).
- Pin the wasmtime version, or move to a slower-but-deterministic
  executor (wasm-interp, or a future zk-vm target).
- Fuel limits become consensus parameters — choosing a gas schedule.

For the first cut it's fine to ship "intended to be replayable,
currently best-effort." The contract with users is *the import
surface is deterministic*; engine-level determinism is a tracked
follow-up.

**Chain state surface.** `chain.read_at` needs a clean set of pinned
read primitives. Likely: storage slot, balance, nonce, code, ABI-aware
view-fn call (`eth_call` at block). What's the canonical path
namespace? `chains/<c>/at/<block>/state/<addr>/...`? Reuse existing
`/chains` handler paths with a `?block=` query? Open.

**Block-pinning ergonomics.** Onchain petals need to specify the
pinned block somehow. Options:
- As part of stdin (caller's responsibility — most flexible).
- As a separate "world-state header" the petal reads via a fixed
  preamble.
- As a daemon-side parameter to `petals.run` (`block=latest-1`).

**On-chain attestation log.** Even before zk-proof-of-wasm,
`(petal_hash, input_hash, output_hash, block_pin)` is a useful tuple
to commit on-chain. A thin attestation contract per chain would let
anyone *check* a claimed petal run by re-executing locally. Out of
scope for v1 of the split itself.

## 8. Open questions for brainstorming

- Should the `local`/`onchain` distinction be visible in the VFS
  layout? E.g., `public/onchain/<hash>` vs `public/local/<hash>`,
  or just rely on `meta.json.mode` to disambiguate?
- Do onchain petals need their *own* registry, or share the petname
  namespace? Cross-mode squatting is a concern.
- Is there a useful third mode? "Sealed-input local": deterministic
  *given* its stdin, but allowed wall-clock/random for caching /
  exponential backoff against external services. Probably not worth
  the complexity in v1.
- The `chain.read_at` API should probably take a *path* not a
  schema-specific call. What's the smallest sufficient surface?
- How does the user reason about which mode they're running? `bloom
  petals ls` should show mode prominently; `bloom petals run` should
  refuse a local petal in a context that demanded onchain (and vice
  versa).
- Caching: an onchain petal that calls `chain.read_at(eth, 18m,
  /state/0xabc/balance)` returns the same answer forever. Worth
  building a content-addressed read cache from the start.

## 9. Cross-references

- v0 implementation lives across `crates/bloom-petals/`,
  `crates/bloom-daemon/src/{lib,ipc}.rs`, `crates/bloom/src/main.rs`,
  `crates/bloom/tests/cli.rs`.
- Capability model echoes `docs/specs/2026-05-08-bloom-design.md` —
  default-deny, declared at install, narrowable at run.
- The Bloom paper's petname triad (cryptographic key + namespace +
  petname) maps to (`hash`, `public/`, `names/<n>`) here.
