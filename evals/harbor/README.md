# Bloom Harbor evaluations

## Purpose

Harbor measures how well a real agent uses Bloom: correct, safe, and with the
fewest commands and tokens. Each failure or slow run is a defect in Bloom to
fix: its AGENTS.md, Petal docs, route layout or error messages. Never fix it
by adding hints to the task prompt. Compare reward, commands, tokens and time
before and after each change.

## How a trial works

Each trial starts a real, disposable Machine–Broker–Signer Triad with a fresh
wallet and software passkey, mounts its VFS at `/bloom` in the agent
container, and runs one Harbor agent. A trusted host-side verifier then reads
the Triad's own state; an agent's report is never evidence. Teardown removes
the root. Failed trials keep it for diagnosis; it can hold ceremony
capabilities, so never publish its raw logs.

| Task | Coverage | Passes when |
| --- | --- | --- |
| `solana-transfer` | Settlement on a local validator | exactly one finalized transfer: exact addresses and lamports, fee within the bound |
| `polymarket-limit-order-proposal` | Proposal | exactly one unsigned draft: exact condition and token IDs, integer amounts |
| `<petal>-clarification` | Clarification | the agent's last message asks for the one missing fact, and nothing was staged |

Clarification exists for `solana` (missing chain), `hyperliquid` (missing
network), `polymarket` (missing market) and `near-intents` (missing origin
chain).

**Proposal coverage proves that the agent prepared the right operation, not
that it settles.** The harness approves nothing, and only the stage route is
writable. Only Solana's local validator exercises signing and settlement.

## Run one trial

Build Machine, Broker (with `bloom-broker-debug-driver`) and Signer with the
release profile and `triad-dev-harness`, and export their paths:

```sh
cargo build --release --locked -p bloom --features triad-dev-harness
cargo build --release --locked -p bloom-broker -p bloom-broker-debug-driver --features bloom-broker/triad-dev-harness
cargo build --release --locked -p bloom-signer --features triad-dev-harness
export BLOOM_INTEGRATION_MACHINE_BIN=… BLOOM_INTEGRATION_BROKER_BIN=… \
  BLOOM_INTEGRATION_SIGNER_BIN=… BLOOM_INTEGRATION_DEBUG_DRIVER_BIN=…
scripts/evals/run-harbor.sh solana-transfer codex
```

Use optimized services. Debug Broker and Signer builds make every mounted
read slow: twelve reads took 119 s with debug services and 2.8 s optimized,
which turns agent timing into a measure of the build.

Agents are `claude`, `codex` and `opencode`, using the host's existing
authentication. Harbor 0.21.0 and the agent image are pinned. Every task uses
the same image digest. `BLOOM_EVAL_REASONING_EFFORT` selects Codex reasoning
effort.

Linux needs the launcher's noninteractive NFS mount permission. A host with a
sudo rule for one fixed path sets `BLOOM_EVAL_MOUNTPOINT` to it; the harness
locks it for the trial. See `DEVELOPMENT.md` for launcher prerequisites. The
harness never touches the installed custody Triad.

## Results

Each run writes a summary to `evals/harbor/jobs/summaries/` (or
`$BLOOM_EVAL_JOBS_DIR`):
- reward, coverage and any error;
- tokens and phase timings;
- cleanup outcome;
- source revision and binary hashes.

Read the first trial of each task by hand before running batches. A 0 or a
timeout is a failure.

```sh
scripts/test-harbor-evals.sh                                   # static checks
scripts/evals/run-harbor.sh solana-transfer codex --smoke      # real services, no LLM
```
