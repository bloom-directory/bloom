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

Roots live under `~/.cache/bloom-harbor` by default, or the short directory in
`BLOOM_EVAL_ROOTS_DIR`. On this host they use `/data/codex-scratch/user/hb-1022`,
so retained failures consume disk rather than RAM-backed `/tmp`. Keep the root
short enough for Unix socket paths.

| Task | Coverage | Passes when |
| --- | --- | --- |
| `solana-transfer` | Settlement on a local validator | exactly one finalized transfer: exact addresses and lamports, fee within the bound |
| `polymarket-limit-order-proposal` | Proposal | exactly one unsigned draft: exact condition and token IDs, integer amounts |
| `hyperliquid-order-proposal` | Proposal on testnet | exactly one owner approval request, with BTC buy, limit, size and post-only terms proven against Broker commitments |
| `near-intents-swap-proposal` | Proposal on an Ethereum fork | one verified 1 USDC Ethereum→Arbitrum quote and its exact unsigned USDC deposit |
| `<petal>-clarification` | Clarification | the agent's last message asks for the one missing fact, and nothing was staged |

Clarification exists for `solana` (missing chain), `hyperliquid` (missing
network), `polymarket` (missing market) and `near-intents` (missing origin
chain).

**Proposal coverage proves that the agent prepared the right operation, not
that it settles.** No proposal is approved, signed or submitted. Only Solana's
local validator exercises signing and settlement.

Hyperliquid uses an unfunded fresh wallet and its released owner-order route.
Literal request candidates from tool arguments/observations are untrusted
witnesses: the verifier reconstructs the released MessagePack/EIP-712 payload
and matches both Broker selectors and the payload-batch claim before grading
terms. A missing provable witness is an observability error, not an incorrect
order. Equivalent decimals and optional CLOIDs are accepted when committed.
The committed nonce must fall strictly within two days before and one day
after the signed Broker manifest's issuance time, following the venue's
[nonce rules](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets).
Optional expiry must also be later than that issuance time. Using this trusted
preparation timestamp keeps offline grading deterministic; it does not prove
the order would still be valid when submitted later.

NEAR uses Anvil chain 1 with only a localhost Ethereum RPC, 0.05 fork ETH and
5 fork USDC. The real 1Click service supplies the quote. The released route
combines prepare and stage under a session `confirm` file, so only the fresh
wallet's `swaps/<wallet>/0` namespace is writable over the read-only base.
Two unsigned transitions reach staging; no authenticator is exposed. Extra
sessions, outbox work, approval requests or signing state fail verification.
Teardown discards pending work with its disposable root. Anvil is required.

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
- agent tool-call counts, tokens and phase timings;
- cleanup outcome;
- source revision and binary hashes.

Command counts use the same denominator for every agent: an agent tool call.
A compound call counts once in each applicable read/write category. Bloom
reads/writes are counted only when identifiable from tool arguments; opaque
commands and relative paths remain unclassified. These are attempted calls,
not shell-command totals, physical filesystem operations or RPC counts.
Missing trajectories leave counts unavailable rather than inventing zeros.

Clarification accepts a direct question or an explicit request to choose the
missing fact; punctuation is immaterial. Asking for funds alone does not pass.

Read the first trial of each task by hand before running batches. A 0 or a
timeout is a failure.

```sh
scripts/test-harbor-evals.sh                                   # static checks
scripts/evals/run-harbor.sh solana-transfer codex --smoke      # real services, no LLM
```
