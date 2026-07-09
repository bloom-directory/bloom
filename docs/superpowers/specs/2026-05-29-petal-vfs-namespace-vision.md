# Petal VFS Namespace — Overarching Vision (Stages 1–4)

**Status:** vision (north star); not directly implementable — each stage gets its own design → plan → build cycle
**Date:** 2026-05-29
**Surface:** bloom's **own sovereign chain** (petals / PTBs / objects), *not* the external-EVM client surface (`chains/`, `wallets/`, `defi/`-Enso)
**Predecessors:**
- `2026-05-21-vfs-petal-pipes-handoff.md` — the original UNIX-paths/pipes thesis
- `2026-05-22-vfs-petal-pipes-defi-design.md` — the PTB front-door + DeFi demo (the *plan builder* substrate)
- `2026-05-29-view-functions-design.md` — first-class read-only view calls (the *read engine*)

---

## 1. The gap this vision closes

A petal declares a path — `#[bloom::petal(path = "/bloom/dex/pool")]` → `module_path` in its signed manifest. But that path is **not reachable through the mounted filesystem today**. It is a chain-state addressing key consumed by the endpoint resolver, the `chain_view_call` RPC, and the `/bloom/tx/` command grammar. You cannot `cd` to it, `ls` its endpoints, read a view from it, or read its state back.

Two engines already exist and are tested:

- **The read engine** (`view-functions-design`): `chain_view_call` evaluates a read-only PTB against a chosen snapshot and returns typed values. Today it is **RPC/CLI only — no VFS face.**
- **The plan builder** (`vfs-petal-pipes-defi-design`): `bloom-ptb-builder`/`PtbSession` lowers ordered endpoint calls + use-edges into a validated `PtbTx`; the packet envelope + DAG lowering + generic dispatch make composition real. Today its VFS face is the **`/bloom/tx/` staging tree** — a *separate* namespace where you write command *lines* that reference petal paths, not a place you navigate to a petal.

**This vision makes the petal's own declared path a live, navigable, executable location in bloom's native VFS** — and routes reads to the read engine and writes to the plan builder, instead of inventing new engines.

## 2. The model (north star)

The petal's `module_path` becomes its real location under the bloom-native namespace. At/under that path:

```text
<bloom-namespace>/dex/pool/
  quote                 # VIEW endpoint  — read → runs chain_view_call → typed result bytes
  swap                  # MUTATING endpoint — write/invoke → lowers to a tx-plan → submits
  <state projections>/  # objects/collections this petal owns, as bounded paginated dirs/files
```

Three verbs, one location:

- **Read a view endpoint** → invoke a `#[view]` function read-only, get typed bytes back (Stage 1).
- **Invoke a mutating endpoint** → lower a single call to a one-command `PtbSession`, sign, submit, return the receipt (Stage 2).
- **Compose endpoints** → build multi-command atomic plans (linear pipes and named/DAG inputs) rooted in the namespace, reusing the packet envelope and use-edge lowering (Stage 3).
- **Read state back** → the petal's committed object/collection state projected as files/pages under the same path, so you observe results the same way you invoked (Stage 4).

### Decision: mutation happens *at the petal path*

State-changing endpoints are invoked directly at their own path (symmetric with reads), lowering to a single-command tx-plan under the hood. The existing `/bloom/tx/` staging tree remains the door for **explicit multi-command sessions / advanced composition**; single-call mutation no longer requires hand-writing a tx session. (Per-call signer/gas identity is a Stage 2 mechanic, deferred — see §5.)

## 3. Reuse, don't rebuild

The whole point is that the deep machinery exists. New work is the **front door at the petal path**, not new engines.

| Capability | Engine that already exists | What this vision adds |
|---|---|---|
| Read-only invocation, typed ABI, snapshot select | `chain_view_call` + read-only PTB (`run_ptb(ReadOnly)`) | A VFS read at the petal path that calls it (Stage 1) |
| Lower a call/composition to an atomic `PtbTx` | `bloom-ptb-builder` / `PtbSession`, `validate_ptb`, `PtbExecutor` | Path-rooted single-call (Stage 2) and path-rooted composition (Stage 3) |
| Typed/linear packets across pipe edges | packet envelope (`bloom-objects`), use-edges | Pipes driven from navigable paths (Stage 3) |
| Bounded listings | pagination primitive in `bloom-vfs` | Per-petal state projection mapping (Stage 4) |
| byte-in/byte-out endpoint ABI, path→endpoint resolution | `#[bloom::petal]` shim, manifest `module_path`/`functions`, `resolve_endpoint` | The mounted handler that exposes them as filesystem entries |

## 4. The stages

Each stage is an independent design → plan → build cycle with its own brainstorm. Numbered to avoid collision with the pipes-defi spec's internal Phases A–F.

**Stage 1 — Executable endpoints + view reads.** *(the one we build now)*
Make the petal path navigable and read-invokable. Reading a view endpoint runs the existing read engine and returns typed bytes. Settles the load-bearing decisions: the bloom-native **namespace / mount root** (petals declare `/bloom/...` but nothing mounts it today), the **executable-endpoint VFS abstraction** (today `EntryKind` is only Dir/File/Symlink), and the **read-with-arguments ABI** (POSIX `read` takes no args — the core problem). Delivers the first real "talk to a petal over VFS."

**Stage 2 — Direct mutation at the path.**
Invoking a mutating endpoint at its path lowers to a single-command `PtbSession`, signs, submits, returns the receipt. Settles **per-call signer/gas identity**, write-vs-commit semantics, and receipt/error surfacing. Depends on Stage 1's namespace + ABI.

**Stage 3 — Composition (pipes + typed packets).**
Multi-endpoint atomic plans rooted in the namespace — linear `A | B | C` and named/DAG inputs — reusing the packet envelope and use-edge lowering. New part: driving composition from navigable paths, not only `/bloom/tx/` command strings. Depends on Stages 1–2.

**Stage 4 — State projection.**
Render the committed object/collection state a petal owns as bounded, paginated dirs/files under its path, so results are read back the same way they were invoked. Reuses the pagination primitive; new part is the per-petal projection mapping (object types/collections → paths). Mostly parallel — depends only on Stage 1's namespace.

**Dependencies:** 1 → 2 → 3; 4 depends on 1 and otherwise runs in parallel.

## 5. Cross-cutting principles

- **Protocol vs. petal.** The mounted host exposes generic primitives only; DeFi/app math and state shape live in petal wasm and the manifest. (Same hard line as the pipes-defi spec §2.)
- **One engine each.** Reads route to the *one* read engine; plans route to the *one* plan builder. No forked execution pipelines — that drift was exactly the bug the view-functions spec existed to fix.
- **Bloom-native, not EVM.** Dispatch is path + byte-in/byte-out, never selectors/ABI. This is Surface B (bloom's sovereign chain), unrelated to the external-EVM client mounts.
- **Decision-light here.** This doc holds the model. The contested specifics — exact mount root, read-with-args convention, per-call signing/gas, projection mapping — are each settled in the owning stage's brainstorm, not assumed here.

## 6. Out of scope (for the vision)

- Demos / litmus apps (DeFi end-to-end, Bloombook) — downstream, after the stages land.
- The internals each stage settles (see §5) — deferred to that stage.
- Anything on the external-EVM surface (`chains/`, `wallets/`, `defi/`-Enso).
- FUSE/9P kernel-exec mounts — the read/write convention works over the existing NFS no-exec mount.
