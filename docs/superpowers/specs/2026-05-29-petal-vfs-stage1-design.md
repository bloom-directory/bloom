# Stage 1 — Executable Petal Endpoints + View Reads

**Status:** design, approved for planning
**Date:** 2026-05-29
**Surface:** bloom's **own sovereign chain** (petals / PTBs / objects) — *not* the external-EVM client mounts (`chains/`, `wallets/`, `defi/`-Enso)
**Vision:** `2026-05-29-petal-vfs-namespace-vision.md` (Stage 1 of 4)
**Reuses (does not rebuild):**
- `2026-05-29-view-functions-design.md` — the read engine (`chain_view_call` + read-only PTB), already implemented on `feat/view-functions`
- `2026-05-22-vfs-petal-pipes-defi-design.md` — `resolve_endpoint` / manifest `module_path` resolution

---

## 1. Goal

Make a petal's declared path a **navigable, runnable location in the mounted VFS**: you can `ls` a petal, see its view endpoints, and invoke one to get a typed result — the first real "talk to a petal over VFS." Stage 1 delivers this with **zero new chain logic**: an endpoint is an executable shim that shells out to the already-working `bloom chain view-call` CLI.

### Why this is the right first slice

- The read engine (`chain_view_call`) is implemented and tested; the CLI provably drives it. A shim that calls the CLI inherits that proof.
- Treating each endpoint as its own executable process sidesteps the write-then-read correlation problem entirely (each invocation has its own stdin/stdout — no shared-path races, no caller-identity plumbing, which the `Handler` trait does not provide today).
- It forces the two load-bearing namespace decisions (where petals mount; the `/bloom/petals/` invariant) without committing to the harder mutation/composition mechanics, which later stages own.

## 2. The gap today

- The whole VFS is mounted at `/bloom` on the client (`DEFAULT_MOUNT_PATH = "/bloom"`, `crates/bloom/src/main.rs:31`). Existing handlers appear as `/bloom/tx`, `/bloom/public`, `/bloom/chains`, etc.
- Petals declare an **absolute** `module_path` like `/bloom/dex/pool` (`#[bloom::petal(path = …)]` → manifest), but **no handler serves that subtree** — `resolve_path` treats it purely as a chain-state key. So the path is unreachable through the filesystem.
- `EntryKind` is only `Dir | File | Symlink`; there is no executable affordance, though `Entry.mode` already flows through to NFS attrs (`crates/bloom-mount/src/adapter.rs:178`).

## 3. Namespace and the `/bloom/petals/` invariant

**Decision:** every petal lives under `/bloom/petals/<whatever>`. A new top-level **`petals` handler** owns that subtree (appearing at `/bloom/petals` under the existing mount root).

```
/bloom/
  tx/         (exists)
  public/     (exists — petal artifacts: wasm, meta, name registry)
  chains/     (exists — external EVM client surface)
  petals/     (NEW — executable endpoint namespace)
    core/fungible/{balance_of, total_supply, …}     # view endpoints (executable)
    dex/pool/{quote, …}
    dex/router/…
```

**Enforcement.** Petals keep declaring the **full** path (`#[bloom::petal(path = "/bloom/petals/dex/pool")]`). Deploy-time chain-mode admission rejects any `module_path` that does not start with `/bloom/petals/`. The rule is a chain-admission invariant (visible in source, not hidden in the macro).

**Migration** (the "enforce on existing packages" work):

| Package | Old path | New path |
|---|---|---|
| `examples/petal-cap` | `/bloom/core/cap` | `/bloom/petals/core/cap` |
| `examples/petal-dex/.../pool` | `/bloom/dex/pool` | `/bloom/petals/dex/pool` |
| `examples/petal-dex/.../router` | `/bloom/dex/router` | `/bloom/petals/dex/router` |
| `examples/petal-dex/.../faucet` | `/bloom/dex/faucet` | `/bloom/petals/dex/faucet` |
| `examples/petal-dex/.../wallet` | `/bloom/dex/wallet` | `/bloom/petals/dex/wallet` |
| `examples/petal-dex/.../cpmm` | `/bloom/dex/strategy/cpmm` | `/bloom/petals/dex/strategy/cpmm` |
| `crates/bloom-petal-fungible` + `CORE_FUNGIBLE_PATH` (`bloom-script/src/types.rs:278`) | `/bloom/core/fungible` | `/bloom/petals/core/fungible` |
| test consts `POOL_PATH` (`tx_handler.rs`, `ptb-builder/tests.rs`, `pipe.rs`) | `/bloom/dex/pool` | `/bloom/petals/dex/pool` |

Migration is safe because these are example/test petals on no live chain; `module_path` is a signed-manifest field, so the petals are recompiled and their VFS bindings re-derived from the new path.

## 4. Endpoint ABI — executable shim over the CLI

Each **`view`** function is served as an executable file (mode `0o555`). The handler synthesizes the shim content per endpoint, with the path and function baked in:

```sh
#!/bin/sh
# Forward argv flags; if stdin carries a JSON request, pass it through too.
exec bloom chain view-call --path /bloom/petals/dex/pool --function quote "$@"
```

- **Invocation forms (both supported):**
  - argv/flags: `/bloom/petals/dex/pool/quote --arg 100 --at-block 42`
  - stdin JSON: `echo '{"args":[100],"at_block":42}' | /bloom/petals/dex/pool/quote`
  - The shim forwards `"$@"` to the CLI and, when stdin is non-empty, feeds it as the request body. (Exact stdin↔flag plumbing is a `bloom chain view-call` ergonomics detail; the CLI already accepts typed `--arg`/`--at-block`/`--type-arg`/`--fuel-limit`.)
- **Output:** the CLI's typed-JSON stdout, passed straight through (`{ "returns": […], "returns_raw": […], "at_block": …, "fuel_used": … }`).
- **`cat <endpoint>`** returns the shim script text — informative and harmless (it is *not* the result; getting the result requires running it).

**Dependency / tradeoff (accepted for Stage 1):** the shim assumes the client has the `bloom` CLI on `PATH`, configured to reach the daemon (same IPC the human CLI uses). Endpoints are therefore not self-contained binaries. This is acceptable for the dev/agent environment and is the cost of the "provably works" starting point; a self-contained shim or the write-then-read data interface can replace it later without changing the namespace contract.

## 5. Listing and navigation

The `petals` handler implements `lookup`/`list`/`read` over the suffix it receives:

- **Directory tree** (`/bloom/petals`, `/bloom/petals/dex`, `/bloom/petals/dex/pool`): derived from the set of bound petal paths. The handler enumerates bindings via `State::iter_vfs()` (`crates/bloom-chain-state/src/state.rs:404`), filtered to the `/bloom/petals/` prefix, and projects the path segments as directories. A petal path itself (`/bloom/petals/dex/pool`) is a directory whose children are its endpoints.
- **Endpoint leaves**: for the petal bound at a path, load its manifest and list each `view` function as an executable-file `Entry`. **Mutating functions are not materialized in Stage 1** (Stage 2 adds them via the same mechanism).
- **`read` of an endpoint leaf**: returns the synthesized shim bytes (so `execve` and `cat` both work).
- Enumeration must be surfaced through whatever interface the handler holds (extend the handler's chain accessor or `ChainStateIface` with an `iter`/prefix-scan hook — small plumbing; `iter_vfs` already exists on `State`).

Bounded `ls`: petal counts are small for now, but the handler should route large listings through the existing pagination primitive (`bloom-vfs::paginate`) for consistency with the other handlers.

## 6. New/changed units

| Unit | Responsibility | Builds on |
|---|---|---|
| `Entry::executable_file` (+ mode `0o555`) in `bloom-vfs` | An executable-file affordance. `EntryKind` stays `File`; the exec bit rides in `mode` (already passed through by the mount adapter). | `Entry`, `adapter.rs:178` |
| `PetalsEndpointHandler` (new handler in `bloom-vfs`, mirroring `TxHandler`'s placement since both need `ChainStateIface`) | Serve `/bloom/petals/**`: dir tree from bound paths, endpoint leaves from manifest `view` fns, shim bytes on read. | `Handler` trait, `resolve_path`/`load_manifest`, `iter_vfs`, manifest `functions` |
| VFS-binding enumeration hook | Expose `iter_vfs()` (prefix scan) to the handler. | `State::iter_vfs` (`state.rs:404`) |
| `/bloom/petals/` admission invariant | Reject deploys whose `module_path` is outside the prefix. | chain-mode petal admission (alongside the view-purity verifier) |
| Daemon wiring | `vfs_builder.mount("petals", …)` in `bloom-daemon`. | `crates/bloom-daemon/src/lib.rs:430` |
| Petal-path migration | Move 7 declared paths + `CORE_FUNGIBLE_PATH` + test consts under `/bloom/petals/`. | §3 table |

**No changes** to: the read engine (`chain_view_call`, `run_ptb`), the PTB executor, consensus, or the manifest schema. Stage 1 is purely a front-door + a namespace invariant + a migration.

## 7. Testing strategy

- **Admission invariant (unit):** a petal declaring a path outside `/bloom/petals/` is rejected at deploy; one inside is accepted.
- **Handler listing (unit, in-process VFS):** with two petals bound under the prefix, `ls /bloom/petals` shows their path segments; `ls /bloom/petals/dex/pool` lists exactly its `view` functions as executable entries; mutating functions are absent; an unbound path 404s.
- **Shim content (unit):** `read` of an endpoint returns a shim whose baked-in `--path`/`--function` match the resolved endpoint; `Entry.mode == 0o555`.
- **Mount attrs (adapter):** an endpoint entry surfaces NFS attrs with the executable bit set (extends the existing mode-bit assertions around `adapter.rs:1428`).
- **End-to-end (integration, real mount + daemon):** deploy a petal with a `view` function under `/bloom/petals/…`; run the endpoint both via argv and via stdin; assert the typed JSON result equals a direct `chain_view_call`. This is the headline "talk to a petal over VFS" proof.
- **Migration guard:** the existing DEX/fungible/cap example + integration suites pass with the new `/bloom/petals/` paths (proves the rename is complete and consistent).

## 8. Out of scope (deferred to later stages)

- **Mutating endpoints** — Stage 2 (same shim mechanism, submitting CLI command; per-call signer/gas story).
- **NFS-native write-then-read data interface** — the robust fallback for `noexec` mounts / pure file-I/O agents; layered under the same paths later.
- **Pipe composition + typed packets** — Stage 3.
- **State projection** (committed objects/collections as files/pages under the petal path) — Stage 4.
- **Self-contained endpoint binaries** (no client-side `bloom` CLI dependency).
- Anything on the external-EVM surface.
