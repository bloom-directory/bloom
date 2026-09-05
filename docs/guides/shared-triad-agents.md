# Sharing a development triad between agents

This is the agent-facing contract for working against a triad another developer
or agent already owns. The full developer workflow is in
[`DEVELOPMENT.md`](../../DEVELOPMENT.md#share-one-running-triad-between-developers-or-agents).

## Attach; do not relaunch

- One agent owns a triad's lifecycle. Other agents attach to that exact
  instance; they do not start another Machine, Broker, or Signer with the same
  developer root, Machine home, sockets, mount, ports, or custody state.
- Obtain `triad.env` from the lifecycle owner and source it in the shell that
  will run Bloom commands. Treat it as instance-specific and stale after any
  restart. Use `bloom` or `$BLOOM_BIN` from that environment, not a binary from
  another worktree.
- Concurrent public reads are supported. Before any state-changing workflow,
  acquire the instance lease with
  `scripts/triad-dev-with-mutation-lease COMMAND [ARG ...]`. The command must
  include the entire stage/approve/confirm/reconcile/cleanup lifecycle. If the
  lease is busy, coordinate with its owner; do not bypass or replace the lock.
- Only one agent or human drives a ceremony. Do not complete, cancel, retry, or
  reconcile another actor's pending operation.
- Never stop, restart, re-enroll, rebuild in place, or edit the configuration of
  a shared triad unless its lifecycle owner has handed it over. Never inspect,
  copy, or decrypt custody state to make concurrent access easier.

Use a separate Git worktree and `CARGO_TARGET_DIR` for concurrent source work.
Building another worktree does not update the already-running triad; the
lifecycle owner decides when a tested binary replaces a running process.

## Fully isolated parallel triads

Two complete triads may run concurrently when they share nothing authoritative:
use distinct developer roots, identities, Broker and Signer databases, Machine
homes, wallets, audit journals and checkpoints, runtime sockets, mounts, and
ports. Developer-harness builds may set `BLOOM_TRIAD_DEV_CEREMONY_PORT` to a
non-default loopback port; production builds retain the canonical 18734 origin.
The Broker, Signer, debug driver, socket unit, generated ceremony URLs, and
WebAuthn origin checks must all receive the same value.

`scripts/evals/run-harbor-solana-local.sh` is the reference: its default eval
triad lives under `~/bloom-eval-triad` on port 18735 and can coexist with a
normal development triad. Port separation alone is not isolation and never
makes it safe to share custody or audit state between the two.

## Handoff record

Before a mutation, record the triad instance ID, intended workflow, wallet and
chain, and agent responsible for cleanup. On handoff, also name the three tested
repository commits, active binaries, any pending operation or ceremony, and
whether the mutation lease has been released. Never claim a clean handoff until
the workflow's reconciliation and cleanup have finished.
