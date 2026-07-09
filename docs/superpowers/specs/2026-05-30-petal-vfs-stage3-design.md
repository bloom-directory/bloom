# Stage 3 — Composition (Pipes + Typed Packets)

**Status:** design, approved for planning
**Date:** 2026-05-30
**Surface:** bloom's **own sovereign chain** (petals / PTBs / objects) — *not* the external-EVM client mounts (`chains/`, `wallets/`, `defi/`-Enso)
**Vision:** `2026-05-29-petal-vfs-namespace-vision.md` (Stage 3 of 4)
**Builds on:**
- `2026-05-29-petal-vfs-stage1-design.md` — the namespace, the `PetalsEndpointHandler`, the executable-shim ABI, the `/bloom/petals/` admission invariant
- `2026-05-30-petal-vfs-stage2-design.md` — `bloom chain call`, the shared `gas_select` helper, `load_wallet_key_for_signer`, `ensure_success_receipt`, the POSIX exit-code contract
- `2026-05-22-vfs-petal-pipes-defi-design.md` + `bloom-ptb-builder` — `lower_pipe_expr`, the command grammar, `PtbSession`, `validate_ptb` (the *one* plan builder)
- `bloom pipe` (`crates/bloom/src/commands/pipe.rs`) — `lower_and_build` / `receipt_ndjson`, the lower → sign → submit → receipt path this stage factors a namespace front door out of

---

## 1. Goal

Make multi-endpoint **atomic** plans invokable from the petals namespace. Both composition forms the grammar already supports:

- **Linear:** `…/spend | …/swap | …/receive` — each stage's primary output auto-binds to the next stage's primary input.
- **Named / DAG:** `…/add_liquidity --a <(…/spend_eth)> --b <(…/spend_usdc)>` — each `--name <(…)>` sub-expression lowers first and binds to a named input slot.

Either lowers to **one** validated `PtbTx`, is signed and submitted atomically, and returns a per-command receipt. Stage 3 adds **zero new engine**: it is the same `lower_pipe_expr` → `PtbSession` → `validate_ptb` path `bloom pipe` and `/bloom/tx/` already drive, with Stage 2's auto-gas / `--signer` / POSIX exit-code ergonomics brought to the composition case.

### The load-bearing constraint

Shell-piping the Stage 1/2 shims — `…/spend | …/swap` — does **not** compose atomically. Each shim is its own `execve` submitting its *own* transaction, and the `Handler` trait has no caller identity to correlate separate invocations into one plan. The use-edge / packet model requires all commands to land in a single `PtbSession`. So composition must flow through **one front door** that receives the whole expression — not N piped processes. That front door is a new `bloom chain pipe` command, exposed in the mount as a single reserved executable node `/bloom/petals/.pipe`.

## 2. Settled decisions

| Decision | Choice |
|---|---|
| **Composition surface** | A `bloom chain pipe` CLI command (composition sibling of `chain call`) **plus** a mounted executable node `/bloom/petals/.pipe`. Composition is a first-class mount affordance symmetric with view/call; the node shells to the command. |
| **Signer scope** | Single-signer: the whole plan is authorized by one keystore identity (default or `--signer`), exactly like `chain call`. Multi-party / multi-signer is deferred. |
| **Node placement** | `/bloom/petals/.pipe` — inside the petals namespace, discoverable where you browse petals. The `.pipe` name is **reserved** from petal admission. |
| **Receipt & errors** | NDJSON per-command receipt (reusing `receipt_ndjson`); POSIX-honest exit code (0 only if committed and `success:true`), reason to stderr — the whole plan succeeds or fails atomically. |

## 3. The `bloom chain pipe` command

The composition sibling of `chain call`. Takes a pipe expression (positional `'<expr>'` or stdin) over mounted `/bloom/petals/...` paths, plus the same Stage 2 flags:

| Flag | Default | Meaning |
|---|---|---|
| `--signer <addr>` | sole/default keystore identity | which keystore key signs the whole plan (single-signer) |
| `--gas-payer <object-id>` | **auto-selected** LOOM `Coin` owned by the signer | gas object override |
| `--gas-budget` / `--fuel-limit` | existing `bloom pipe` defaults | cost caps |
| `--dry-run` | off | lower + validate + print the plan; **do not submit** |
| `--no-wait` | off | submit and exit `0` on acceptance without polling |

Pipeline (all reused machinery):

1. **Lower.** `lower_and_build(chain, expr, [signer], gas_payer)` — which already calls `lower_pipe_expr` and then drives one `PtbSession` — produces the validated multi-command `PtbTx`. Linear and named/DAG forms, `@<cmd>.<ret>` use-edges, and typing all come for free.
2. **Auto-gas.** If `--gas-payer` is absent, `gas_select::select_loom_gas_payer_rpc` against the signer (the shared Stage 2 helper).
3. **Sign + submit.** Sign `signing_digest()` with the keystore key (the `load_wallet_key_for_signer` path from Stage 2), wrap in the outer `TxKind::SubmitPtb`, submit, poll the receipt.
4. **Report.** Emit the **NDJSON** per-command receipt (reusing `receipt_ndjson` — the same projection `bloom pipe` and `/bloom/tx/ commit` already stream), and set the exit code from the on-chain outcome via `ensure_success_receipt` (0 only if committed and `success:true`, else non-zero with the reason on stderr). `--no-wait` skips polling and exits 0 on accepted submission, printing the tx hash.

`--dry-run` stops after step 1 and prints the lowered plan. New code is a thin command wrapper; lowering, gas, signing, receipt, and exit-code pieces are all lifted from Stage 2 and the existing pipe path.

`bloom chain pipe` supersedes the validator-only top-level `bloom pipe` (which signs only the validator key and demands an explicit `--gas-payer`); aliasing or retiring that older command is out-of-scope cleanup.

## 4. The mounted `.pipe` node + reservation (`PetalsEndpointHandler`)

**The node.** The handler materializes one synthetic executable leaf at the petals root, `/bloom/petals/.pipe` (mode `0o555`), whose `read`/`cat` yields a shim that forwards everything to the composition command:

```sh
#!/bin/sh
# Bloom petal composition endpoint.
exec bloom chain pipe "$@"
```

Unlike the Stage 1/2 shims, it bakes in no `--path`/`--function` — the whole expression (referencing petal paths) arrives at invocation via argv or stdin. `lookup("/bloom/petals/.pipe")` returns the executable entry; `list("/bloom/petals")` includes `.pipe` alongside the projected petal dirs.

**Reservation.** Petal admission (`validate_chain_petal_admission`, the Stage 1 `/bloom/petals/` invariant) gains one rule: reject any `module_path` whose first segment under `/bloom/petals/` is `.pipe`, so no petal can bind `/bloom/petals/.pipe` or shadow the subtree.

**Containment.** The synthetic node is injected only in `list` / `lookup` / `read` at the petals root. It does not affect the `has_descendant` / directory-wins logic, the pagination path, or endpoint resolution for real petals. Keeping it a single reserved dotfile leaf (not a directory) keeps the change small and the "directories derive from bound paths" projection otherwise intact.

## 5. Testing strategy

- **`bloom chain pipe` (unit):** a linear `A | B | C` and a named/DAG `--a <(…)> --b <(…)>` expression each lower to the expected multi-command `PtbTx` with the right use-edges (reuses the existing pipe-lowering fixtures); `--dry-run` prints the plan without submitting; auto-gas + `--signer`/`--gas-payer` overrides behave as in `chain call`; a `success:false` receipt maps to a non-zero exit. The "CLI and tx-session paths commit identically" invariant still holds.
- **Handler (unit, in-process):** `list /bloom/petals` includes `.pipe` next to the projected petal dirs; `lookup`/`read` of `.pipe` returns a `0o555` shim containing `exec bloom chain pipe`; the node does not perturb existing petal listing, descendant, or pagination tests.
- **Admission (unit):** a petal whose path is `/bloom/petals/.pipe` (or under it) is rejected without writes; a normal petal still deploys — mirrors `deploy_outside_petals_prefix_fails`.
- **End-to-end (Docker — the headline proof):** extend `exercise_live_petal_vfs_mount`. Compose a real multi-command plan over the mount via `echo '<expr>' | /bloom/petals/.pipe` (using the DEX petals — e.g. spend → swap → receive, or a faucet-mint + transfer), assert one atomic tx commits with a multi-command NDJSON receipt, then read a `view` endpoint back to confirm the composed effect. Add a case where one command reverts and assert the whole plan fails atomically with a non-zero exit. Reuses the `docker-petal-vfs` CI job.
- **Migration guard:** existing DEX / pipe / tx-session suites still pass (no grammar or `PtbSession` changes).

## 6. Out of scope (deferred)

- **Multi-party / multi-signer compositions** — Stage 3 authorizes the whole plan with one keystore identity; collecting signatures from multiple parties is a later concern.
- **State projection** (reading committed objects/collections back as files/pages) — Stage 4.
- **Stateful session tree at the petal path** (a `/bloom/tx/`-style incremental `new`→`cmd`→`commit` flow relocated under the namespace) — `.pipe` is a one-shot atomic front door; `/bloom/tx/` remains the door for staged, inspectable multi-step sessions.
- **Retiring/aliasing the older top-level `bloom pipe`** — cleanup, not required for Stage 3.
- **Self-contained endpoint binaries** (no client-side `bloom` CLI dependency) — carried over from Stages 1–2.
- **NFS-native write-then-read composition** (for `noexec` mounts / pure file-I/O agents) — later, under the same paths.
- Anything on the external-EVM surface.
