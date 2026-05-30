# Stage 2 — Direct Mutation at the Petal Path

**Status:** design, approved for planning
**Date:** 2026-05-30
**Surface:** bloom's **own sovereign chain** (petals / PTBs / objects) — *not* the external-EVM client mounts (`chains/`, `wallets/`, `defi/`-Enso)
**Vision:** `2026-05-29-petal-vfs-namespace-vision.md` (Stage 2 of 4)
**Builds on:**
- `2026-05-29-petal-vfs-stage1-design.md` — the namespace, the `petals` handler, the executable-shim ABI, the `/bloom/petals/` admission invariant (all carried over untouched)
- `2026-05-22-vfs-petal-pipes-defi-design.md` — `PtbSession` / `lower_and_build` / `validate_ptb` (the *one* plan builder)
- `bloom pipe` (`crates/bloom/src/commands/pipe.rs`) — the existing lower → sign → submit → poll-receipt path this stage factors a single-call front door out of

---

## 1. Goal

Make a petal's **mutating** endpoints invokable at the same path as its views, so writing state is symmetric with reading it:

```
/bloom/petals/dex/pool/swap --arg '{"kind":"object","id":"<coin-id>"}'
echo '{"args":[{"kind":"object","id":"<coin-id>"}]}' | /bloom/petals/dex/pool/swap
```

Either form signs, submits, and returns the receipt in **one shot**. Stage 2 adds **zero new chain logic** and **zero new execution engine**: a mutating endpoint is an executable shim (mode `0o555`, the exact mechanism Stage 1 established) that shells out to a new `bloom chain call`, which lowers a single endpoint to a one-command `PtbSession` — the same plan builder `bloom pipe` and the `/bloom/tx/` session tree already drive.

### Why this is the right slice

- The plan builder (`PtbSession` / `lower_and_build`), signing, the outer `TxKind::SubmitPtb` envelope, and receipt polling are all implemented and tested in `bloom pipe`. A single-call command factored out of that path inherits the proof.
- `execve` runs on the **client**, so the signing identity is simply whoever's `bloom` CLI/keystore runs the shim. This resolves the vision's "per-call signer identity" worry without the daemon ever needing caller identity (which the `Handler` trait cannot provide — the same constraint that drove Stage 1's shim choice).
- It settles the three decisions the vision (§4) assigned to this stage — signer/gas identity, write-vs-commit semantics, receipt/error surfacing — without committing to multi-command composition (Stage 3) or state projection (Stage 4).

## 2. Settled decisions

| Decision | Choice |
|---|---|
| **Signer & gas identity** | Implicit/zero-config: signer = the CLI's configured keystore identity (the validator key in devnet today); gas = auto-selected LOOM `Coin` owned by the signer. Overridable via `--signer <addr>` and `--gas-payer <object-id>`. |
| **Write-vs-commit** | Execute = commit-now: invoking signs + submits + waits for the receipt atomically. `--dry-run` lowers and prints the validated plan without submitting. Multi-command staging stays at `/bloom/tx/`. |
| **Shim target** | New `bloom chain call` command, the mutating sibling of `view-call` (same `--arg`/`--type-arg` ABI). Routes through the one `PtbSession` builder; `bloom pipe` remains the multi-command door. |
| **Receipt & errors** | POSIX-honest: receipt JSON to stdout; exit code reflects on-chain outcome (0 only if committed and `success:true`); abort/error reason to stderr. |
| **Listing** | Flat and uniform: every endpoint is a `0o555` executable file; the view/mutate split is internal (it only selects which shim bytes are synthesized). No visible distinction in Stage 2. |

## 3. The `bloom chain call` command

A mutating sibling of `view-call` with the same `--path`/`--function`/`--arg`/`--type-arg` ABI and the same stdin-JSON merge (argv authoritative), plus mutation-specific flags:

| Flag | Default | Meaning |
|---|---|---|
| `--signer <addr>` | sole/default keystore identity | which keystore key signs; the secret key must be present in the home keystore |
| `--gas-payer <object-id>` | **auto-selected** LOOM `Coin` owned by the signer | gas object override |
| `--gas-budget` / `--fuel-limit` | existing `bloom pipe` defaults (`max_fuel 10_000_000`, `fee_per_unit 1`) | cost caps |
| `--dry-run` | off | lower + validate + print the plan; **do not submit** |
| `--no-wait` | off | submit and exit `0` on acceptance without polling the receipt |

Pipeline, in order:

1. **Lower.** Build a single-endpoint expression and run it through `lower_and_build` → unsigned one-command `PtbTx`. This is the exact `PtbSession` seam `bloom pipe` uses — no forked execution path.
2. **Auto-gas.** If `--gas-payer` is absent, scan the signer's owned objects for a LOOM `Coin` covering the budget. The selection logic already exists in the `TxHandler` submitter (`submitter_commit_auto_selects_gas...`); lift it into a shared helper both call sites use. Error clearly when no covering coin exists.
3. **Sign + submit.** Sign `signing_digest()` with the keystore key, wrap in the outer `TxKind::SubmitPtb`, submit via `chain_submit_tx`.
4. **Await + report.** Poll the receipt; print it as JSON to stdout; set the exit code from the on-chain outcome (0 only if committed and `success:true`, else non-zero with the reason on stderr). `--no-wait` skips polling and exits 0 on accepted submission, printing the tx hash.

`--dry-run` stops after step 1 and prints the validated plan, reusing `bloom pipe`'s non-submitting projection (`run_pipe` / `receipt_ndjson`). New code is the thin command wrapper plus the shared auto-gas helper; everything else is existing machinery.

## 4. Handler change (`PetalsEndpointHandler`)

Stage 1 filters `manifest.functions` to `view == true` in three spots (`entries_for`, `entries_for_unpaged`, `endpoint_at`). Stage 2 drops that filter so **all** manifest functions materialize as executable `0o555` leaves, and threads the function's `view` flag into shim synthesis:

```rust
fn shim(path: &str, function: &str, view: bool) -> Vec<u8> {
    let subcmd = if view { "view-call" } else { "call" };
    format!(
        "#!/bin/sh\n# Bloom petal {} endpoint.\nexec bloom chain {} \
         --path {} --function {} \"$@\"\n",
        if view { "view" } else { "mutating" },
        subcmd,
        shell_quote(path),
        shell_quote(function)
    )
    .into_bytes()
}
```

- `endpoint_at` returns `(binding, function_name, view_flag)` instead of dropping non-view functions; `read` passes the flag to `shim`.
- Listing/navigation, pagination, the directory-wins-over-endpoint collision rule, and `cat` semantics are **unchanged** — they already treat endpoints uniformly; only the set of materialized leaves and the bytes-on-read differ.
- **No** daemon wiring change, **no** `ChainStateIface` change, **no** new handler. The namespace, mount root, and `/bloom/petals/` admission invariant from Stage 1 all carry over untouched.

## 5. Testing strategy

- **Handler (unit, in-process):** with a petal bound under the prefix exposing one `view` + one mutating function, `ls` lists both as `0o555`; `read` of the view leaf yields a `view-call` shim, `read` of the mutating leaf yields a `call` shim with the baked-in `--path`/`--function`. (Extends Stage 1's handler tests.)
- **`bloom chain call` (unit):** `--dry-run` lowers a single endpoint to a one-command `PtbTx` and prints the plan without submitting; the auto-gas helper selects a covering LOOM coin owned by the signer and errors clearly when none exists; `--signer`/`--gas-payer` overrides take effect; argv/stdin-JSON merge matches `view-call`.
- **Exit-code contract (unit):** a `success:false` receipt maps to a non-zero exit with the abort reason on stderr; `success:true` → exit 0.
- **End-to-end (Docker — the headline proof):** extend the existing `exercise_live_petal_vfs_mount` integration test. Invoke a **mutating** endpoint over the real mount (argv and stdin), then read the petal's `view` endpoint back and assert the state changed — the mutation itself goes through the mounted shim, not a hand-built PTB. Add a revert case asserting non-zero exit. Reuses the `docker-petal-vfs` CI job.
- **Migration guard:** existing DEX / fungible / cap suites still pass (no path changes this stage).

## 6. Out of scope (deferred)

- **Multi-signer calls** — Stage 2 signs with the single keystore identity; functions requiring multiple `&Signer` args are deferred (composition territory).
- **Multi-command composition / pipes rooted at the path** — Stage 3. `bloom pipe` and `/bloom/tx/` remain the multi-command doors.
- **Richer per-caller identity** (deriving the signer from the NFS uid; wallet selection beyond `--signer`) — the client-side CLI identity is the Stage 2 answer.
- **State projection** (reading committed objects/collections back as files/pages) — Stage 4.
- **Self-contained endpoint binaries** (no client-side `bloom` CLI dependency) — carried over from Stage 1.
- **NFS-native write-then-read mutation** (for `noexec` mounts / pure file-I/O agents) — later, under the same paths.
- Anything on the external-EVM surface.
