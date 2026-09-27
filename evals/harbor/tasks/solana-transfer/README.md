# Solana native transfer Harbor evaluation

An agent gets one user-style request: send an exact amount of SOL from a Bloom
wallet to a destination and wait for finality. It must discover the wallet's
Solana account through the mounted filesystem, stage the transfer, drive the
fail-closed confirm, retry after the owner's approval, and restage if the
blockhash expires. The verifier grades the chain, not the agent's report.

It runs against a disposable local validator. Preflight refuses an endpoint
whose genesis is mainnet-beta's.

## What bounds it

A transfer has no undo, so the bound is the host approval contract.

- **One fresh destination per trial.** Provision generates a random 32-byte
  address, which no one has ever paid, and sets the wallet policy's allow list
  to exactly that address through an owner ceremony. The policy is
  deny-by-default, so nothing else can be paid.
- **Exact-match approval.** A background approver completes an owner ceremony
  only after reading the staged `intent.json` from host state and matching every
  field: destination, exact lamports, fee payer, signing-account fingerprint and
  derivation path, fee ceiling, and the genesis preflight read from the
  endpoint. A missing field is a refusal.
- **Restage chains only.** After a blockhash expires, the outbox's `restage`
  route stages one replacement and names it in `restage_advice.json`. The
  approver follows that chain from its last approval. It refuses the same
  transfer staged again through `new.tx`: restaging is idempotent, staging
  again is not, and the mounted Solana walkthrough documents the route.
  Ceremonies are capped at three.
- **Exactly one payment.** The verifier requires exactly one finalized
  signature on the destination, from the right account, for the exact amount,
  under the fee ceiling, as a lone System transfer.

Transfers and fee ceilings above 0.02 SOL are refused regardless of
configuration.

## Prerequisites

- Sibling `bloom`, `bloom-broker`, and `bloom-signer` checkouts at revisions the
  Bloom pins accept, and `cargo`, `jq`, `uv` on PATH.
- The Solana CLI (Agave) for the validator and funding.
- Docker for model trials.
- On Linux, the launcher's sudo rule for the evaluation mountpoint
  (DEVELOPMENT.md). The container works through the kernel mount.
- An authenticator seed file (mode `0600`) for the wallet's owner credential.
  The debug driver completes ceremonies with it.

## Prepare once

1. Start a disposable validator, dedicated to this evaluation:

   ```sh
   solana-test-validator --ledger /private/path/to/eval-ledger --reset \
     --limit-ledger-size 1000000 --quiet &
   ```

   The verifier counts the payment from signature history. The default ledger
   limit keeps about a minute of slots, which prunes it too early.
   `1000000` keeps about 7,400 slots (roughly 50 minutes, enough for one trial)
   and caps the ledger near 2 GB. It grows 2–3 GB an hour until then, so keep
   it off a small or RAM-backed `/tmp`.

   Preflight refuses a pruning validator that retains fewer than 4,500 slots.
   The verifier names pruning if it happens mid-trial. Whoever starts the
   validator owns it; the harness never stops it or touches its ledger.

2. Write the evaluation Machine's config, pinning the genesis from
   `solana genesis-hash --url http://127.0.0.1:8899`. A pinned genesis is what
   permits broadcast. A config needs one EVM chain for `default_chain`, and an
   unused local one is enough:

   ```toml
   default_chain = "anvil"

   [chains.anvil]
   name = "anvil"
   chain_id = 31337
   rpc_urls = ["http://127.0.0.1:8545"]

   [solana_chains.solana-local]
   name = "solana-local"
   expected_genesis_base58 = "<genesis>"

   [[solana_chains.solana-local.endpoints]]
   url = "http://127.0.0.1:8899"
   weight = 100
   ```

3. Build the triad in release mode, then launch it with the mount and its own
   ceremony port (port 18734 belongs to an installed custody triad). Debug
   builds take about 20 seconds per signing call, a third of the transfer's
   one-minute blockhash window; release builds take well under a second. The
   launch command stays in the foreground:

   ```sh
   cargo build --release -p bloom --no-default-features --features mount,triad-dev-harness
   cargo build --release --manifest-path ../bloom-broker/Cargo.toml \
     -p bloom-broker --features triad-dev-harness
   cargo build --release --manifest-path ../bloom-signer/Cargo.toml \
     -p bloom-signer --features triad-dev-harness

   export BLOOM_EVAL_TRIAD_ROOT=/private/path/to/eval-triad
   BLOOM_TRIAD_DEV_MACHINE_CONFIG=/private/path/to/machine-config.toml \
   BLOOM_INTEGRATION_MACHINE_BIN="$PWD/target/release/bloom" \
   BLOOM_INTEGRATION_BROKER_BIN="$PWD/../bloom-broker/target/release/bloom-broker" \
   BLOOM_INTEGRATION_SIGNER_BIN="$PWD/../bloom-signer/target/release/bloom-signer" \
   scripts/triad-dev-launch.sh \
     --developer-root "$BLOOM_EVAL_TRIAD_ROOT/developer" \
     --machine-socket "$BLOOM_EVAL_TRIAD_ROOT/runtime/machine.sock" \
     --log-dir "$BLOOM_EVAL_TRIAD_ROOT/logs" \
     --ready-file "$BLOOM_EVAL_TRIAD_ROOT/ready" \
     --mount /private/path/to/empty/mount \
     --ceremony-port 28735
   ```

   In a second terminal, run `source "$BLOOM_EVAL_TRIAD_ROOT/logs/triad.env"`.
   The wrapper reads the mount, Machine home, and ceremony port from that file.

4. Import the evaluation wallet from a dedicated test mnemonic. It must have no
   funds and no public-chain history. Complete the printed ceremony with the
   debug driver, then fund the wallet's Solana address:

   ```sh
   bloom wallet import solana-eval
   bloom-broker/target/debug/bloom-broker-debug-driver complete <ceremony_url> \
     --authenticator-seed-file "$HOME/.config/bloom/eval-authenticator-seed" \
     --sign-count 1 --mnemonic-file /private/path/to/eval-mnemonic
   solana airdrop 2 "$(bloom wallet address solana-eval --profile solana)" \
     --url http://127.0.0.1:8899
   ```

## Run

```sh
export BLOOM_EVAL_AUTHENTICATOR_SEED_FILE="$HOME/.config/bloom/eval-authenticator-seed"
export BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT=2   # first run only; the import used 1

scripts/evals/run-harbor-solana-local.sh smoke             # no LLM
BLOOM_EVAL_SOLANA_SMOKE_RESTAGE=1 \
  scripts/evals/run-harbor-solana-local.sh smoke           # through a real expiry
scripts/evals/run-harbor-solana-local.sh codex --trials 5  # a model, five times
```

- **Smoke.** Stages, confirms, approves, broadcasts, and verifies without an
  LLM. With `BLOOM_EVAL_SOLANA_SMOKE_RESTAGE=1` it waits out the real blockhash
  window, restages, and requires exactly one payment. That takes a few minutes.
- **Agents.** Choose `claude`, `codex`, `glm`, `deepseek`, or `opencode`. Set
  `BLOOM_EVAL_MODEL` for another model and `BLOOM_EVAL_MAX_TURNS` for Claude
  Code's turn cap (default 24 here). The GLM adapter accepts `GLM_API_KEY`,
  `ZAI_API_KEY`, or `ANTHROPIC_AUTH_TOKEN`. `deepseek` and `opencode` need
  `DEEPSEEK_API_KEY`.
- **Trials.** Each trial is independent: its own destination, policy ceremony,
  approver, and cleanup. Each reports one of:
  - `PASS`;
  - `FAIL` — the agent did not earn the reward, including running out of time;
  - `INVALID` — the harness, environment, provider, or cleanup failed, so the
    trial says nothing about the agent.

  A bracketed note gives stagings, approvals, sends, expirations,
  cancellations, and any refusal. The last line is the pass rate over judged
  trials. The exit status is 0 when all pass, 1 when any fail, and 2 when any
  is invalid.

The agent's request names the wallet, destination, chain, and amount. It also
says Bloom is mounted at `/bloom`, and that the owner approves passkey prompts
out of band, so the agent should retry instead of handing back; a one-shot
agent has no turn in which to hear "approved". No path, procedure, or
reporting schema is given. The agent must find the mount-root `AGENTS.md`.

The harness records the next unused WebAuthn counter at
`<seed file>.sign-count`, so later runs need no `SIGN_COUNT`. A stale value is
safe: too low is rejected before anything moves, and too high is accepted.

## Mount contract and cleanup

`/bloom` is bound read-only into the container, and the wallet's
`chains/<chain>/outbox` is over-mounted read-write. The authority boundary is
the VFS mode (only `new.tx`, a pending entry's `confirm`/`cancel`/`restage`,
and an expired entry's `failed/<id>/restage` are writable) plus Broker policy,
the ceremony, and the approver. The container shares host networking to reach
the loopback validator, which also exposes the Machine's loopback NFS export.
That is accepted: nothing signs without the exact-match approval, and the funds
are worthless.

Cleanup is host-owned and fail-closed. Pending entries must drain, since a
staged entry may still hold a broadcastable blockhash. The mount refuses
`cancel` on outbox entries, so the expiry sweep drains them. The sweep keeps a
signed entry that was never sent, so cleanup restages one that is past its
window: the only route that retires it. At most one new entry may be sent, and
it must reconcile to a receipt.

## Known limitation

A staged transfer's blockhash lives about a minute. An agent must inspect,
confirm, wait for approval, and retry inside it. The mounted walkthrough shows
how: confirm and keep retrying in one command. Agents that retry a turn later
often miss the window and restage repeatedly until the ceremony cap. Removing that race is a Machine and Broker design change, tracked in
[pm#58](https://github.com/bloom-directory/pm/issues/58).
