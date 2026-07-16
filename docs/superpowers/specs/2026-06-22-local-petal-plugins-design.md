# Local Petal Plugins (v1) — Design

Status: historical draft, superseded by
`2026-06-23-petals-v1.md` and
`docs/guides/petals-v1.md`
Date: 2026-06-22
Scope: an initial, piecemeal slice of the off-chain petal vision — **local, WASM-compiled,
content-addressed petals that act as plugins to the main Bloom application** by owning a VFS
subtree the daemon routes into. Explicitly **off-chain only**; no scoring, staking, zk, or
consensus.

---

## 0. Context and motivation

A v0 local-petal system already exists in `bloom-petals`: content-addressed (raw BLAKE3 of
canonical wasm bytes) WASM modules run one-shot via wasmtime, a `stdin → stdout` command model
(`_start`), a `vfs.read`/`vfs.write` capability model with `bloom.vfs_read`/`bloom.vfs_write`
host imports, a petname→hash registry (`names.toml`), and `bloom petals install|run|ls|name|
uninstall` CLI + `petals.*` IPC methods. Petals today are **not** exposed through the VFS;
they run only via IPC/CLI.

This design extends that v0 along three axes, driven by one forcing function — **a petal must be
powerful enough to implement the entire current native Polymarket handler**
(`crates/bloom-vfs/src/handlers/polymarket.rs`, ~2300 lines, backed by `bloom-polymarket`):

1. **VFS-exposed execution as a router.** A petal declares the directory subtree it wants to
   provide; Bloom mounts that subtree and **routes** VFS operations (`lookup`/`list`/`read`/
   `write`) into the petal's WASM. Bloom is the router; the petal is the handler. Petals do not
   own long-lived executables in v1.
2. **A real manifest file per petal**, authored as `petal.toml` and embedded in the wasm so it
   is covered by the content hash.
3. **Network and signing capabilities**, daemon-mediated and gated, so a petal can talk to
   external HTTP APIs (under a declared, enforced allowlist) and obtain signatures from the
   keystore without ever seeing key material.

### Non-goals (v1)

Designed-for but **not built** in this slice:

- Resident/warm petal instances (v1 is one-shot per VFS op).
- Stream-provider kind (`tail -f` / push events). *(Confirmed unnecessary for Polymarket parity:
  the Polymarket crate and handler are entirely request/response — no websockets, no streaming.)*
- RPC-provider / typed-tooling kind.
- Cross-petal `petal.call`.
- Wildcard-host network rules (exact host only in v1).
- Anything on-chain (scoring, staking, LOOM, zkVM, consensus, chain petal
  endpoints, or chain-mode VM). Those components were removed from the current
  branch and are not part of local app petals.
- The canonical-codec envelope — v1 uses a simple length-prefixed binary framing for the
  request/response envelope; the schema-driven codec
  (`2026-06-01-canonical-codec-and-type-system-design.md`) can be adopted later without an ABI
  break.

### Forward-compatibility commitments

Every interface here is chosen so the deferred work drops in without a format or API break:

- The guest exposes a **single `petal_dispatch` entry point**. A future **resident mode** keeps
  the instance warm and calls `petal_dispatch` repeatedly — same ABI.
- The manifest carries an explicit, extensible `provides`/kind declaration. **Stream-provider**
  and **RPC-provider** become additional kinds the router learns; the v1 manifest schema admits
  them as new variants.
- Host imports are **version-namespaced** (`bloom.v1.*`) so content-addressed petals stay valid
  forever; a `v2` import can land beside `v1`.

---

## 1. Architecture & components

```
                         ┌──────────────────────────────────────────┐
   NFS / VFS op          │ Bloom daemon                               │
   (lookup/list/read/    │                                            │
    write on petals/…)     │   Vfs router ── mount "petals/" ──▶ PetalRouter
        ───────────────▶ │                                       │     │
                         │                                       ▼     │
                         │                          resolve mount → petal hash
                         │                                       │     │
                         │                                       ▼     │
                         │                 PetalVm (one-shot instance) │
                         │                   exports: petal_alloc,     │
                         │                            petal_dispatch    │
                         │                   imports (gated):           │
                         │                     vfs_read / vfs_write     │
                         │                     http_fetch  (net.fetch)  │
                         │                     sign_hash   (sign)       │
                         │                     store_*     (store)      │
                         └──────────────────────────────────────────┘
```

### New / changed crates

- **`bloom-petal-sdk`** (proposed, wasm-side). The author-facing Rust library. Wraps the raw `extern "C"` host imports in ergonomic
  Rust (`vfs::read`, `http::fetch`, `sign::hash`, `store::get/put/...`) and provides a
  `#[petal]` entry macro that generates `petal_alloc` + `petal_dispatch` and dispatches into the
  author's `lookup`/`list`/`read`/`write` functions. Authors write a normal crate and build with
  `cargo build --target wasm32-wasip1`.
- **`bloom-petals` Petal package validation** (implemented later). The current branch uses
  `petal.toml` plus route component validation inside `bloom-petals`; the deleted
  `bloom-petal-manifest` crate and on-chain manifest schema are not restored.
- **`bloom-petals`** (extend existing).
  - `PetalVm`: add the **handler execution path** — instantiate, call `petal_dispatch` with a
    request envelope, read the response — alongside the existing `_start` command path.
  - Add the new host imports (`http_fetch`, `sign_hash`, `store_*`) to local-mode linking.
  - Add per-petal private storage backing (`~/.bloom/petals/data/<hash>/`).
  - Extend `PetalMeta` with the parsed manifest, the new caps, and the network policy.
- **`PetalRouter`** (new `Handler`, in `bloom-vfs` or `bloom-daemon`). Mounted at `petals/`.
  Resolves the first path segment to an installed handler-petal (by declared `mount`), then
  routes the VFS op into that petal via `PetalVm`. Enforces namespace isolation (a petal only
  ever sees paths relative to its own mount).

### Structural decisions

- **(a) Manifest is embedded in the wasm, authored as a file.** The author writes `petal.toml`;
  the SDK/build step embeds it as the `bloom_petal_manifest` custom section. The artifact's
  BLAKE3 hash therefore covers the manifest (no sidecar-tampering gap), yet authors still write a
  plain file. At install, Bloom extracts + validates it and records the parsed form in
  `PetalMeta`. *(Rejected alternative: a loose sidecar TOML at install time — simpler, but the
  manifest would not be covered by the content hash, undercutting content-addressing.)*
- **(b) Mount root is `petals/`.** A fresh top-level namespace (`petals/` is the on-chain endpoint
  handler; `public/` is the artifact/names store). Each handler-petal declares a relative
  `mount` (e.g. `polymarket`) and serves the tree under `petals/<mount>/…`. Namespacing under one
  root means a petal cannot shadow native mounts (`wallets/`, `chains/`, …). The Polymarket petal
  lands at `petals/polymarket/`, coexisting with the native `polymarket/` handler until it is ready
  to graduate.

---

## 2. Manifest (`petal.toml`)

Superseded by the Petal package `petal.toml`; manifests are packaged
alongside route artifacts instead of embedded in a single wasm.

```toml
schema = "bloom.petal.package.v1"
name   = "polymarket"

[provides]
kind  = "vfs"            # v1: only "vfs". Future: "stream", "rpc".
mount = "polymarket"      # served under petals/polymarket/

# Capabilities — default-deny. Declared here, narrowable at run time, never widened.
caps = ["vfs.read", "vfs.write", "net.fetch", "sign", "store"]

# Network policy — rule-based, default-deny, enforced at the http_fetch boundary.
[[net.allow]]
host    = "clob.polymarket.com"        # exact host (v1: no wildcards)
methods = ["GET", "POST"]               # omitted ⇒ GET only
paths   = ["/book", "/order", "/auth/*"]# glob/prefix; omitted ⇒ any path

[[net.allow]]
host    = "gamma-api.polymarket.com"
methods = ["GET"]
paths   = ["/markets*", "/events*"]

[[net.allow]]
host    = "data-api.polymarket.com"
methods = ["GET"]

# Optional read-cache / behaviour hints, keyed by path prefix relative to the mount.
[[endpoint]]
path         = "markets/*"
cache_ttl_ms = 5000

[[endpoint]]
path  = "onboard/*/begin"
write = true
async = true            # daemon spawns the dispatch off the COMMIT path, returns immediately
```

### Validation at install

- Schema string recognised; `kind` ∈ {`vfs`} for v1.
- `mount` is a single non-empty segment, not colliding with an already-installed petal mount.
- Every cap in `caps` is known; `net.allow` present iff `net.fetch` is declared; `sign`/`store`
  declared iff used.
- Net rules: `host` is a syntactically valid hostname; `methods` ⊆ {GET, POST, PUT, PATCH,
  DELETE, HEAD}; `paths` are valid globs.
- Hard error on decode/validation failure — no silent fallback.

---

## 3. Capability & enforcement model

Default-deny. Capabilities are declared in the manifest, **may be narrowed at run/mount time**
(via `--cap` / `--net` masks, mirroring v0) and **never widened**. Host imports are
version-namespaced `bloom.v1.*`.

| Capability | Host import(s) | Purpose |
|---|---|---|
| `vfs.read` / `vfs.write` | `vfs_read` / `vfs_write` | read/write public VFS paths (wallet address, chain id, prices, …) — exists in v0 |
| `net.fetch` | `http_fetch(method,url,headers,body) -> response` | HTTP to a manifest-allowlisted host, daemon-mediated and audited |
| `sign` | `sign_hash(wallet, hash32) -> sig65` | request a signature from the keystore; key never enters the petal |
| `store` | `store_get` / `store_put` / `store_list` / `store_del` | private, per-petal key/value storage (secret-capable) |

WASI preview-1 minus filesystem/networking remains available (clock, random, `proc_exit`),
exactly as v0 local mode. No WASI preopens, no sockets — external reach is only through the
explicit host imports above.

### 3.1 Network (`net.fetch`)

Enforced entirely at the `http_fetch` boundary in the daemon; the petal never opens a socket.

- The daemon matches `(method, host, path)` against the declared `net.allow` rules and **rejects
  anything not explicitly allowed** (`Denied`), with the rejection audited.
- **HTTPS only** in v1 (no plaintext).
- **Redirects are re-validated**: a redirect whose target host/path is not in the allowlist is
  not followed (closes the "allowlist a benign host that 302s elsewhere" hole).
- **Response size cap** (default 8 MiB) and **request timeout** (daemon-set) bound a one-shot
  handler.
- **Every call is audited**: method, host, path, status, byte counts. Bodies of `sign`/secret
  traffic are never logged.
- Run-time `--net` mask can narrow the effective allowlist; it can never widen it.

### 3.2 Signing (`sign`)

The current `bloom-polymarket::signer` never owns key hex — it wraps an `Arc<PrivateKeySigner>`
from the keystore and its core primitive is signing a precomputed EIP-712 hash. So the host
import is minimal: **`sign_hash(wallet, hash32) -> sig65`**. The petal computes the EIP-712 struct
hash itself (pure `alloy` compiled into the wasm) and asks the daemon to sign the final 32-byte
hash. The key stays in the keystore; every signature request is audited (wallet, hash, purpose
tag). (Bounding by scoped run-capabilities — see `2026-06-13-scoped-agent-run-capabilities-
roadmap.md` — is a later refinement, not v1.)

### 3.3 Private storage (`store`)

A dedicated key/value API backed by a per-petal directory the daemon owns
(`~/.bloom/petals/data/<hash>/`), **not** a publicly-mounted VFS path. Entries may be flagged
**secret** (written `0o600`, never surfaced in the public VFS), so secrets such as Polymarket API
credentials stay invisible to other agents and handlers — a guarantee a mounted VFS path could
not give.

- `store_put(key, value, secret_flag)` — atomic write (temp + rename).
- `store_put_new(key, value, secret_flag)` — atomic create-if-absent; returns `Denied` if the key
  already exists. Used for lock/sentinel records where replacement would be unsafe.
- `store_get(key) -> value | NotFound`.
- `store_list(prefix) -> [key]`.
- `store_del(key)`.
- `store_del_if_value(key, expected_value)` — compare-delete; removes the key only if its current
  bytes match `expected_value`, otherwise returns `Denied`. Used to release/break lock records
  without deleting another caller's newer lock.

Keys are namespaced per petal hash; one petal cannot read another's store. Maps directly onto
Polymarket's `CredentialStore` (secret), `OrderStore` (salts/intents/receipts), and onboarding
state (`account.json`/`status.json`).

---

## 4. Execution model & handler ABI

**One-shot, stateless, per VFS op in v1.** Each `lookup`/`list`/`read`/`write` instantiates a
fresh WASM instance (compiled module is cached by the wasmtime `Engine`, so instantiation is
cheap), calls the handler, returns the result, and tears down. The petal holds no in-memory state
between calls — durable state lives in `store_*` or the public VFS. Bloom's existing per-path TTL
cache absorbs repeated read cost.

### Guest exports (generated by the `#[petal]` SDK macro)

- `petal_alloc(len) -> ptr` — lets the daemon write the request into guest linear memory.
- `petal_dispatch(req_ptr, req_len) -> u64` — single entry point; returns a packed
  `(ptr << 32) | len` pointing at the response the guest wrote.

A single entry point (rather than four separate exports) is easier to version and is exactly what
a future resident mode reuses.

### Request / response envelope

Simple length-prefixed binary framing in v1 (not the canonical codec).

- **Request**: `{ op: Lookup | List | Read | Write, path (relative to mount), body (writes only),
  ctx }`. `ctx` carries call context such as the acting wallet/account.
- **Response**: a tagged union —
  - `Lookup` → `Entry { kind: Dir|File|WritableFile|ExecutableFile|Symlink, mode, ttl_hint? }`
  - `List` → `[Entry]`
  - `Read` → `bytes`
  - `Write` → `status`
  - `Error` → typed code mapping to the existing host error codes
    (`-1 NotFound`, `-2 Denied`, `-3 Invalid`, `-4 Backend`), with the same `OVERFLOW_BIAS`
    overflow convention as the v0 `vfs_read`/`vfs_write` imports.

Internally the SDK dispatches `petal_dispatch` to the author's `lookup`/`list`/`read`/`write`
functions.

### Async writes

An endpoint flagged `async = true` in the manifest is run off the NFS COMMIT path: on a write the
daemon **spawns** the (still one-shot, still stateless) dispatch on a background task and returns
immediately to the caller. The petal writes progress into `store_*` (or its public output paths)
as it runs to its first blocking point, then exits. This reproduces today's Polymarket onboarding
behaviour (`begin` spawns, runs every incomplete stage idempotently, reports via `status.json`,
re-writing `begin` resumes) without needing a resident instance.

### TTL & side-effecting hints

- Default `cache_ttl_ms` plus optional per-prefix overrides come from the manifest `endpoint`
  entries.
- A `lookup` response may additionally carry a per-path `ttl_hint`.
- `is_read_side_effecting` defaults to false; endpoints that act on read declare it via the
  manifest (`endpoint` entry), matching the existing `Handler::is_read_side_effecting` seam.

### Resource limits

Inherit v0 local-mode limits: 100M fuel, 16 MiB / 256-page memory, single-threaded, per-op. The
`http_fetch` response cap and timeout (§3.1) bound external I/O.

---

## 5. Routing & mount (`PetalRouter`)

A single `Handler` mounted at `petals/`.

- `petals/` `list` → the set of installed handler-petals (by `mount` name).
- `petals/<mount>/…` → resolve `<mount>` to an installed petal hash; strip the `petals/<mount>`
  prefix; pass the remainder as the request `path` into `petal_dispatch`.
- **Namespace isolation**: the petal only ever receives paths relative to its own mount and can
  only act on the outside world through its granted host imports — it cannot escape its subtree
  or shadow native mounts.
- Mount uniqueness is enforced at install (no two installed petals share a `mount`).

CLI/IPC: extend the existing surfaces rather than inventing new ones — `bloom petals install`
learns to extract/validate the embedded manifest and print the install-time consent summary;
`petals.install` / `petals.list` carry the parsed manifest. Mounting a handler-petal makes it
visible under `petals/` automatically; no separate "run" step is needed for the VFS path.

### Install-time consent

`bloom petals install` prints the parsed capabilities and net rules in human-readable form before
trusting the petal, e.g.:

```
petal: polymarket  (hash 9f86…)  mount: petals/polymarket/
  may read/write:  petals/polymarket/**
  may fetch:       GET  gamma-api.polymarket.com/markets*, /events*
                   GET  data-api.polymarket.com/*
                   GET,POST clob.polymarket.com/book, /order, /auth/*
  may sign with:   <wallet>      (EIP-712 hashes; key never leaves keystore)
  private store:   ~/.bloom/petals/data/9f86…   (secret-capable)
```

---

## 6. Validation targets

1. **`polymarket` petal — full port** of the native handler. Reuse the existing
   `bloom-polymarket` logic (gamma/data/clob clients, EIP-712 builders, geoblock, order/onboard
   state machines) recompiled to `wasm32-wasip1`, rewiring the three I/O seams:
   - HTTP → `http_fetch`
   - signing → `sign_hash`
   - `std::fs` persistence (creds/order/onboard) → `store_*`

   Mounts at `petals/polymarket/`. Exercises every v1 capability, the async-write onboarding flow,
   and secret storage.
2. **Misc tools** proving the low end of the surface:
   - `gas-now` — no caps; input→output tool endpoint returning a gas recommendation.
   - `portfolio` — `vfs.read` only; walks `wallets/`, joins balances into a table.
   - `echo`/`hash` — zero-cap smoke-test petal for the harness.

---

## 7. Testing

- **Unit**: manifest parse/validate; custom-section extract; net-policy matcher (incl. redirect
  re-validation and path globs); envelope encode/decode; `store_*` semantics and secret mode
  bits.
- **Host-import integration** (`PetalVm` handler path with a mock `PetalHost`): cap default-deny;
  `--cap`/`--net` narrowing; async-write spawn-and-return; error-code mapping including overflow.
- **Router**: `lookup`/`list`/`read`/`write` dispatch through `petals/<mount>/…`; namespace
  isolation (a petal cannot escape its mount or collide with native mounts).
- **End-to-end**: `gas-now`/`portfolio` run through the router with golden outputs; Polymarket
  against recorded HTTP fixtures. The existing `BLOOM_LIVE_POLYMARKET` live tests stay opt-in.

---

## 8. Open items deferred to the implementation plan

- Exact byte layout of the request/response envelope and the `store_*` / `http_fetch` import
  signatures (ptr/len marshalling, header encoding).
- Whether `PetalRouter` lives in `bloom-vfs` or `bloom-daemon`.
- Migration/coexistence detail for `petals/polymarket/` vs the native `polymarket/` handler during
  the port (parity checklist before graduation).
- `#[petal]` macro surface in `bloom-petal-sdk`.
