# Petals: Local vs Onchain Modes (v1)

**Status:** Design accepted, ready for implementation.
**Date:** 2026-05-18
**Companion to:** [`docs/specs/2026-05-18-petals-design.md`](../../specs/2026-05-18-petals-design.md) (v0 implementation and v1 sketch).

## 1. Goal

Split petals into two modes so that the deterministic-replay petals — the
ones we eventually want to commit on-chain or run as oracles — are
*structurally* separated from the convenience petals that can touch live
state, the clock, randomness, and the local VFS.

The contract we ship:

- **Onchain petals** see a strictly smaller, deterministic host import
  surface. Their output is a pure function of `(petal_hash, stdin)`.
- **`bloom petals replay`** is the v1-distinguishing piece: a CLI tool
  that re-runs an onchain petal locally and diffs the output hash
  against a recorded one. The replayability contract is *observable*,
  not promised.
- **Local petals** keep today's surface unchanged. Existing v0 installs
  continue to work without migration.

## 2. Non-goals (v1)

- Engine-level bit-exact determinism across wasmtime versions and CPU
  architectures. We turn on the cheap knobs (NaN canonicalization,
  `wasm_relaxed_simd_deterministic`) but do not pin a wasmtime version
  or formalize a gas schedule.
- A content-addressed cache for `chain.read_at` results. Every call hits
  the live archive node. Cache is an obvious follow-up.
- `chain.view_call` (`eth_call`-at-block). When added, it's a chains-VFS
  extension, not a petals one.
- `petal.call` host import for cross-petal composition. When added, it
  must enforce the one-way valve (onchain cannot call local).
- An on-chain attestation contract / commit pipeline. v1 *produces* the
  attestation tuple; on-chain commit is out of scope.
- Migration tooling for v0 installs. Serde defaults handle read-side.

## 3. Background

v0 ships content-addressed wasm petals with a wasmtime VM, WASI
preview-1, BLAKE3 hashing, a TOML petname registry, a VFS handler
mounted at `public/`, daemon integration, JSON-RPC IPC, and CLI
subcommands. See the companion spec for the full v0 picture.

The v0 host import surface includes WASI's clock and random plus
optional `bloom.vfs_read` / `bloom.vfs_write` gated by declared
capabilities. That surface is fine for "portfolio valuation now" or
"gas estimator" petals but cannot be replayed deterministically — and
replay is the property we want for petals that may eventually be
attested on-chain.

The right separation isn't "two crates" or "two runners." The runtime
constraints we enforce are which host imports get linked and which
WASI capabilities the ctx has. A single runner with a mode-branched
linker is the smallest faithful implementation.

## 4. Design

### 4.1 Architecture & data model

Mode is a property of an install record, not of the bytes. A petal's
wasm is content-addressed and mode-agnostic on disk
(`store/<hash>.wasm`). Mode lives in the per-install metadata.

```rust
// crates/bloom-petals/src/meta.rs
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum PetalMode { Local, Onchain }

#[derive(Serialize, Deserialize, Clone)]
pub struct PetalMeta {
    pub hash: Hash,
    pub mode: PetalMode,           // new; serde default = Local
    pub caps: BTreeSet<Capability>,
    // existing fields
}
```

**Capability rules (validated at install):**

- `Local` may declare any subset of `{vfs.read, vfs.write}`. Cannot
  declare `chain.read`.
- `Onchain` may declare `{chain.read}` only. Cannot declare `vfs.read`
  or `vfs.write`.

**Install invariant:** one install per hash. Attempting to install the
same bytes a second time as a different mode returns
`PetalError::ModeConflict { existing: PetalMode }`. Same mode + same
caps = idempotent. Same mode + different caps = `CapMismatch`, advise
uninstall first.

**Single runner, mode-branch in the linker.** `PetalVm::instantiate`
matches on `meta.mode` and calls one of two private functions:

```rust
fn link_imports_for_mode(mode: PetalMode, linker: &mut Linker<StoreData>) -> Result<()> {
    match mode {
        PetalMode::Local   => link_local_imports(linker),   // wraps today's add_bloom_host
        PetalMode::Onchain => link_onchain_imports(linker), // chain.read_at only
    }
}
```

This function is the audit surface for "what can each mode see." The
match is exhaustive — adding a mode means updating this one site.

**WASI ctx is also mode-branched.** Local mode keeps the current
`WasiCtxBuilder` (stdio capture, clock, random, env, args). Onchain
mode builds a stripped ctx: stdio capture only — no clock, no random,
no env, no args, no `poll_oneoff`, no `sched_yield`.

### 4.2 Host import surface

| Import                                             | Local             | Onchain                  |
| -------------------------------------------------- | ----------------- | ------------------------ |
| WASI stdio (stdin read, stdout/stderr write)       | ✓                 | ✓                        |
| WASI `clock_time_get` / `clock_res_get`            | ✓                 | ✗                        |
| WASI `random_get`                                  | ✓                 | ✗                        |
| WASI `environ_*`, `args_*`                         | ✓                 | ✗                        |
| WASI `poll_oneoff`, `sched_yield`                  | ✓                 | ✗                        |
| `bloom.vfs_read` / `bloom.vfs_write`               | gated by caps     | ✗                        |
| `bloom.chain_read_at`                              | ✗                 | gated by `chain.read`    |
| `bloom.log_denied`                                 | ✓                 | ✓                        |

Onchain still gets stdin/stdout because those are the petal's
input/output channel — they are part of the recorded
`(input_hash, output_hash)` tuple the replay tool compares against. They
are not sources of nondeterminism: the daemon supplies stdin, captures
stdout, the petal cannot read after stdout or write to stdin.

**`bloom.chain_read_at` signature:**

```wat
;; (import "bloom" "chain_read_at"
;;   (func (param i32 i32)         ;; path_ptr, path_len  (utf-8 bytes)
;;         (param i64)             ;; block_number
;;         (param i32 i32)         ;; dst_ptr, dst_max
;;         (result i32)))          ;; bytes_written, or err
```

Return convention mirrors the existing `vfs_read`: non-negative = bytes
written; `OVERFLOW_BIAS + needed` = buffer too small, caller retries
with `needed`; small negatives = error codes (`ERR_NOT_FOUND`,
`ERR_CAP_DENIED`, `ERR_CHAIN_UNAVAILABLE`,
`ERR_BLOCK_NOT_PINNABLE`, `ERR_CHAIN_PATH_UNKNOWN`).

**Path namespace** reuses the existing `chains/<chain>/...` VFS schema
unchanged — same paths a local petal would read via
`vfs_read("chains/ethereum/state/0xabc/balance")` are valid here, just
pinned to `block`. The daemon-side implementation routes through
`ChainClient`'s historical-block read methods against an archive node.
Paths the chains VFS doesn't expose (e.g. things requiring an
`eth_call`) return `ERR_CHAIN_PATH_UNKNOWN`. Adding view-call paths is a
chains-VFS extension, not a petals one.

**`block` semantics:** `block = 0` is reserved and rejected
(`ERR_BLOCK_NOT_PINNABLE`) — no "latest" alias inside an onchain petal,
which would break replay. The caller's stdin can compute a block number
from "latest" if it wants, but by the time the petal sees it, it's a
fixed integer.

### 4.3 Storage & VFS layout

On-disk store is unchanged. Wasm blobs at
`~/.bloom/petals/store/<hash>.wasm`. Bytes are mode-agnostic; one blob
corresponds to at most one install record because of the install
invariant.

Meta records live at `~/.bloom/petals/installs/<hash>.toml` — one file
per install, atomic write (write-temp-then-rename). Avoids contention
during install/uninstall and keeps the per-run read path small.

**VFS layout under `public/`:**

```
public/
├── local/
│   ├── <hash>          # one entry per Local install
│   └── <hash>
├── onchain/
│   └── <hash>          # one entry per Onchain install
└── names/
    ├── gas-now         # symlink-style entry → hash (mode read from install record)
    └── portfolio-eth
```

Listing `/public` returns `{local, onchain, names}`. Listing
`/public/local/` returns hashes of installed local petals;
`/public/onchain/` the onchain ones. Listing `/public/names/` returns
petname → hash mappings (one shared registry).

**`PetalsHandler` routing:**

```rust
match path_segments {
    []                 => list_top_level(),     // ["local","onchain","names"]
    ["local"]          => list_installs_filter(PetalMode::Local),
    ["onchain"]        => list_installs_filter(PetalMode::Onchain),
    ["names"]          => list_petnames(),
    ["local", hash]    => stat_install(hash, Some(PetalMode::Local)),
    ["onchain", hash]  => stat_install(hash, Some(PetalMode::Onchain)),
    ["names", name]    => stat_petname(name),
    _                  => ENOENT,
}
```

`stat_install(hash, expected_mode)` returns `ENOENT` if the install's
mode doesn't match the expected one — that's how the path segmentation
is *enforced* rather than merely cosmetic.

**Petname semantics:** `bloom petals run gas-now` resolves through
`names.toml`, looks up the install record for that hash, derives the
mode, and runs in that mode. The petname doesn't carry mode — the
install does.

**Backward-compat:** existing v0 installs (no `mode` field) are read as
`PetalMode::Local`. Serde default handles it. No migration script
needed.

### 4.4 CLI & IPC surface

```
bloom petals install <path> [--name <n>] [--cap <c>]... [--mode local|onchain]
bloom petals run <name-or-hash> [--input <file|->] [--cap <c>]...
bloom petals ls
bloom petals name <name> [<hash>]
bloom petals uninstall <hash>                                            # new
bloom petals replay <name-or-hash> --input <file> --expect <hash> [--block <n>]   # new
```

- `--mode` defaults to `local` (existing usage unaffected).
- `run` has no `--mode`: mode is derived from the install record.
- `ls` gains a `mode` column:

  ```
  HASH       MODE      CAPS              NAME
  b3:abc123  local     vfs.read          gas-now
  b3:def456  onchain   chain.read        portfolio-eth
  ```

- `uninstall` is new: removes `installs/<hash>.toml` and any petname
  pointing at the hash. Needed because the install invariant requires
  uninstall before re-installing under a different mode.

**Install-time validation:**

| Condition                                                       | Error                            |
| --------------------------------------------------------------- | -------------------------------- |
| `--mode onchain` + `--cap vfs.read` (or `vfs.write`)            | `ModeCapMismatch`                |
| `--mode local` + `--cap chain.read`                             | `ModeCapMismatch`                |
| Hash already installed in a different mode                       | `ModeConflict { existing }`      |
| Hash already installed, same mode, different caps                | `CapMismatch { existing }`       |

**IPC methods over the existing Unix-socket JSON-RPC:**

```jsonc
// petals.install
{ "path": "/...", "name": "gas-now", "caps": ["chain.read"], "mode": "onchain" }
// -> { "hash": "b3:abc...", "mode": "onchain" }

// petals.run                  (shape unchanged; mode derived server-side)
{ "name_or_hash": "gas-now", "input_b64": "...", "cap_mask": [...] }
// -> { "stdout_b64": "...", "stderr_b64": "...", "exit": 0, "mode": "onchain" }

// petals.uninstall            (new)
{ "hash": "b3:abc..." }
// -> { "ok": true }

// petals.replay               (new)
{ "name_or_hash": "...", "input_b64": "...", "expect_output_hash": "b3:...", "block": 18000000 }
// -> { "actual_output_hash": "b3:...", "match": true, "exit": 0 }
```

`mode` is echoed in `petals.run` responses so callers can verify they
got what they expected without a separate `petals.info` round-trip.

**`cap_mask` semantics carry over:** at run-time you can narrow the
declared caps (subset of the install's caps), not widen. Onchain
`cap_mask` is therefore `[]` or `[chain.read]`, never anything else.

### 4.5 Replay tooling

The v1-distinguishing piece. Makes the determinism contract
*observable*.

`bloom petals replay <name-or-hash> --input <file> --expect <output-hash> [--block <n>]`:

1. Resolves petal → install record. Errors if `mode != onchain` (replay
   only meaningful for onchain petals).
2. Reads input bytes from `<file>` (or stdin if `-`).
3. Runs the petal under a fresh `PetalVm` instance (the deterministic
   knobs from §4.6 are already on by default — replay does not need a
   special VM config). Stdin = input bytes. `chain.read_at` calls
   served live from `ChainClient`.
4. Hashes captured stdout with BLAKE3 → `actual_output_hash`.
5. Compares to `--expect`. Exit code:
   - `0` → match
   - `1` → mismatch (prints both hashes)
   - `2` → execution error (trap, fuel-exhaust, `ERR_CHAIN_UNAVAILABLE`)

**Attestation tuple, returned for onchain `petals.run` only (null for local):**

```rust
pub struct PetalAttestation {
    pub petal_hash: Hash,
    pub input_hash: Hash,          // BLAKE3 of stdin bytes
    pub output_hash: Hash,         // BLAKE3 of stdout bytes
    pub block_pin: Option<u64>,    // max(block) observed in any chain.read_at
    pub wasmtime_version: String,  // diagnostic only; not enforced
}
```

`PetalAttestation` has no `mode` field because it is only produced for
`Onchain` runs — generating one for a local run would be misleading
(local outputs aren't deterministic).

The companion spec called this out as "useful to commit on-chain." v1
produces the tuple from onchain `petals.run` invocations (returned as
`attestation: PetalAttestation | null` in the IPC response; dumped to a
JSON file via `--attest <path>` on the CLI). On-chain commit is out of
scope for v1.

**`block_pin`** is set by the daemon-side `chain_read_at`
implementation tracking `max(block_observed)` across the run. A replay
can then say "this petal claims to be replayable at block ≥ N" without
the petal itself having to declare a block range. Useful for caching
and archival pinning.

**`--block` flag on `replay`** overrides the historical context. Default
behavior is to honor the explicit block args the petal passes to
`chain.read_at`. The flag exists for:

- Re-running an attestation captured against a now-pruned node (pass a
  different archive endpoint via config; block args unchanged).
- Negative testing: assert the petal *fails* at an earlier block.

For v1 the flag is plumbed through as a per-run "minimum block" the
daemon refuses to read below. Stretch goal — ship without if
time-constrained.

**What replay does NOT do in v1:**

- Cross-machine bit-exact comparison (engine determinism best-effort).
- Snapshotting historical chain reads for offline replay. Every replay
  hits live archive node. `(chain, block, path) → bytes` content-addressed
  cache is the obvious follow-up.

### 4.6 Determinism knobs

Cheap, on by default for both modes:

```rust
let mut cfg = wasmtime::Config::new();
cfg.async_support(true)
   .consume_fuel(true)
   .wasm_relaxed_simd(true)
   .wasm_relaxed_simd_deterministic(true)   // new
   .cranelift_nan_canonicalization(true);   // new
```

Free — no measurable perf cost, no API surface — and they remove the
two largest sources of cross-machine drift. Wasmtime version is *not*
pinned via Cargo policy in v1; it floats with the workspace. The
attestation tuple records the version so a mismatch shows up in
diagnostics rather than as silent drift.

### 4.7 Error handling

Additions only — existing surface unchanged.

```rust
pub enum PetalError {
    // existing variants...
    ModeConflict { existing: PetalMode },
    CapMismatch { existing: BTreeSet<Capability> },
    ModeCapMismatch { mode: PetalMode, cap: Capability },
    BlockNotPinnable,                    // block=0 inside chain_read_at
    ChainUnavailable { chain: String },  // archive node down / no endpoint
    ChainPathUnknown { path: String },   // /chains/ namespace doesn't expose this
}
```

Wasm-side error codes extend the existing `ERR_*` constants:
`ERR_BLOCK_NOT_PINNABLE = -5`, `ERR_CHAIN_UNAVAILABLE = -6`,
`ERR_CHAIN_PATH_UNKNOWN = -7`. `OVERFLOW_BIAS = 0x10000` stays as-is.

## 5. Testing

| Layer                    | Coverage                                                                                                    |
| ------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `meta.rs` unit           | mode serde defaults to Local; capability/mode validation matrix exhaustive                                  |
| `store.rs` unit          | install-twice-same-mode idempotent; install-twice-different-mode → `ModeConflict`; uninstall removes meta + petname |
| `vm.rs` unit             | onchain ctx has no clock/random/env (WAT fixture calls `clock_time_get`, expects trap); local ctx unchanged |
| `vm.rs` unit             | onchain instance does not import `bloom.vfs_*` (link error for fixture that tries)                          |
| `vm.rs` integration      | `chain_read_at` happy path against a mock `ChainClient`; `ERR_BLOCK_NOT_PINNABLE` for `block=0`; `ERR_CHAIN_UNAVAILABLE` when client errors |
| `handler.rs` unit        | `public/{local,onchain,names}/...` routing returns ENOENT when mode mismatches                              |
| `bloom/tests/cli.rs`     | install with `--mode onchain --cap chain.read` → `ls` shows mode; install onchain + `--cap vfs.read` → nonzero, stderr matches `ModeCapMismatch` |
| `bloom/tests/cli.rs`     | `petals replay` against recorded hash returns 0; flipped byte returns 1                                     |

New fixtures: `tests/fixtures/onchain_echo.wat`, `tests/fixtures/mock_chain.toml`.

## 6. Files touched (sizing)

| File                                       | Approx. delta                                          |
| ------------------------------------------ | ------------------------------------------------------ |
| `crates/bloom-petals/src/meta.rs`          | +30 (PetalMode enum, validation)                       |
| `crates/bloom-petals/src/store.rs`         | +50 (install records, ModeConflict path, uninstall)    |
| `crates/bloom-petals/src/vm.rs`            | +120 (link_onchain_imports, chain_read_at, det config) |
| `crates/bloom-petals/src/host.rs`          | +40 (PetalHost::chain_read_at trait method)            |
| `crates/bloom-petals/src/handler.rs`       | +60 (path-segmented routing)                           |
| `crates/bloom-petals/src/runner.rs`        | +30 (attestation tuple, VfsHost wires chain_read_at)   |
| `crates/bloom-daemon/src/ipc.rs`           | +80 (uninstall, replay, attestation in run response)   |
| `crates/bloom/src/main.rs`                 | +60 (--mode, uninstall, replay subcommands)            |
| `crates/bloom/tests/cli.rs`                | +200 (new integration tests + fixtures)                |
| **Total**                                  | **~670 net LOC**                                       |

Roughly the day's work the companion spec estimated, plus the replay
tooling.

## 7. Out of scope (explicit list)

- Engine bit-exact determinism across machines / wasmtime versions.
- Content-addressed cache for `chain_read_at` results.
- `chain.view_call` host import.
- On-chain attestation contract / commit pipeline.
- `petal.call` host import (when added: enforce one-way valve onchain ↛ local).
- Migration tooling for v0 installs.
- Fuel-as-gas-schedule formalization.

## 8. Cross-references

- v0 implementation and earlier v1 sketch:
  [`docs/specs/2026-05-18-petals-design.md`](../../specs/2026-05-18-petals-design.md).
- Capability model echoes
  [`docs/specs/2026-05-08-bloom-design.md`](../../specs/2026-05-08-bloom-design.md)
  — default-deny, declared at install, narrowable at run.
- The Bloom paper's petname triad (cryptographic key + namespace +
  petname) maps to (`hash`, `public/`, `names/<n>`) here.
