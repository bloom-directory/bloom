# Solana native transfer Harbor evaluation

This task moves native SOL through the wallet's mounted outbox:
the agent discovers the wallet's Solana account, stages a transfer, drives the
fail-closed Sealed Approval confirm, and waits for a finalized receipt.

The Hyperliquid task is safe because its primitive is reversible — place, then
cancel, where the undo is also the proof. A transfer has no undo, so three parts
of that model are replaced.

| Hyperliquid | Solana |
|---|---|
| A bounded agent session caps the loss | The compile-time canary authorization caps it |
| A host-generated CLOID binds the venue record to the trial | A fresh host-controlled destination and an exact host-pinned amount bind it |
| `cancel_all` unwinds the side effect | The host sweeps the destination back; only fees are spent |

Native SOL goes through the triad, not `bloom-petal-solana`, so the Hyperliquid
preflight's package-hash, provenance, delegated-class and lineage checks have no
analogue here and are deliberately absent. The authority chain being verified is
the canary authorization, Broker policy, the passkey ceremony, and semantic
verification.

### Lanes

`local` runs against `solana-test-validator`. It needs no canary, because a
non-mainnet genesis is already permitted to broadcast and the validator's funds
are worthless, and it refuses to be pointed at mainnet-beta. Develop here.

`mainnet-canary` is the real measurement. Public devnet is deliberately skipped:
it buys nothing the local validator does not and its faucets are unreliable. The
lanes are mutually exclusive by construction, since `mainnet_guard` requires the
pinned mainnet-beta genesis before a canary send.

### What the canary gives you

`crates/bloom-proto/src/canary.rs` is a tighter bound than anything the
Hyperliquid task has, and the eval's job is to verify it rather than reinvent it.
Reaching mainnet requires the non-default `mainnet-canary` feature *and*
`BLOOM_MAINNET_CANARY_ARTIFACT` set at build time, or compilation fails, so a
production binary cannot be talked into it by any file, flag, or environment
variable. The authorization is bound to that binary's SHA-256 and to one wallet,
one key, one derivation path, one source, one destination, an **exact** amount
(not a ceiling), a fee ceiling, a balance ceiling, `max_transactions == 1`, and
an expiry, spent through a durable single-use ledger.

Preflight checks every one of those, and additionally enforces transfer and
balance ceilings of its own — independent of the file, so a fat-fingered
authorization cannot widen the blast radius — refuses an authorization with
under ten minutes left, refuses one already marked `.spent`, and refuses any
destination that is not the host-controlled sweep address.

### Prerequisites beyond the Hyperliquid list

- A canary-built Machine (`mainnet-canary` feature, `BLOOM_MAINNET_CANARY_ARTIFACT`
  set) whose SHA-256 matches the authorization, on the mainnet lane only.
- An authorization written by `scripts/solana-canary-auth.sh`, mode `0600`.
- A host-held Solana keypair at mode `0600` whose address is the authorization's
  destination. Cleanup sweeps the lamports back with it, which is what makes the
  eval repeatable. The container never receives this key.
- The Solana CLI on `PATH` for that sweep. Preflight requires it on the mainnet
  lane, because discovering it missing after a broadcast would be too late.
- For a manually managed mainnet lane, a dedicated wallet with exactly one
  active Solana account, no pending outbox entries, and only fully reconciled
  historical sent entries. Reusing that wallet across trials is supported;
  each trial still needs a fresh host-controlled destination so its chain
  evidence remains unambiguous.

### Run

For the local lane, the developer wrapper is the shortest path. Every run
creates a second, disposable local-only triad, including independent identities,
Broker/Signer custody stores, audit journals, Machine home, validator ledger,
owner authenticator, and `solana-eval` wallet. It uses developer ceremony port
18735, so the normal triad may remain live and fully usable on canonical port
18734. The deterministic mnemonic is a public test vector confined to a Machine
configuration containing only `solana-local`; never fund this wallet or add a
public chain. The developer-only origin override is implemented by
[bloom-broker#32](https://github.com/bloom-directory/bloom-broker/pull/32) and
[bloom-signer#25](https://github.com/bloom-directory/bloom-signer/pull/25); the
wrapper verifies those commits before building either authority process.

All authoritative state, sockets, logs, Harbor jobs, and the fresh destination
key live under `/tmp/bloom-solana-evals-$UID` by default. A successful run
removes the authoritative state and retains only logs and Harbor results under
its `completed/` directory; a failed run retains its private diagnostics.
Compiled artifacts are cached under its `build-cache/` directory. Set
`BLOOM_EVAL_RUN_ROOT` or `BLOOM_EVAL_BUILD_ROOT` to relocate those roots.

Each run creates a fresh destination, adds only that destination to its fresh
wallet policy through an owner ceremony, and runs Harbor. Cleanup drains pending
outbox authority before the wrapper stops the triad and discards the local
validator ledger; no persistent policy or test balance remains to restore. On
Linux it prompts for sudo once for the localhost NFS mount and keeps only that
temporary sudo timestamp alive; it does not install a persistent sudoers rule.

Run the deterministic isolated-triad check without an API key, Docker, or a
Harbor installation:

```bash
scripts/evals/run-harbor-solana-local.sh smoke
```

Model trials additionally require Docker and `uv`:

```bash
GLM_API_KEY="$GLM_API_KEY" scripts/evals/run-harbor-solana-local.sh
```

The wrapper defaults to GLM-5.2 through the shared provider adapter. Override
the model with `BLOOM_EVAL_MODEL`, or pass `deepseek`, `opencode`, `codex`, or
`claude` as its sole argument. `deepseek` runs DeepSeek through Claude Code's
Anthropic-compatible adapter; `opencode` runs the same provider through Harbor's
native OpenCode adapter.
Claude Code-backed local Solana trials default to a bounded 24 turns because
discovery, owner approval, possible blockhash restaging, and finality can exceed
the shared adapter's generic 20-turn default. Set `BLOOM_EVAL_MAX_TURNS` to
override it.
The lifecycle lock permits one local Solana eval at a time. Override the
developer-only port with `BLOOM_TRIAD_DEV_CEREMONY_PORT` if 18735 is occupied;
the normal and eval triads must never share a port or authoritative state.

For the manually managed mainnet canary lane, configure the harness directly:

```bash
export BLOOM_EVAL_SOLANA_LANE=mainnet-canary
export BLOOM_EVAL_SOLANA_WALLET_ID=...              # Bloom wallet id
export BLOOM_EVAL_SOLANA_CHAIN=solana-mainnet       # the configured chain key
export BLOOM_EVAL_SOLANA_NETWORK=mainnet-beta
export BLOOM_EVAL_SOLANA_RPC_URL=https://...
export BLOOM_EVAL_BLOOM_MOUNT=/path/to/the/selected/bloom/mount
export BLOOM_EVAL_SOLANA_HOME_ROOT=/path/to/machine/home
export BLOOM_EVAL_SOLANA_MACHINE_BINARY=/path/to/bloom-machine
export BLOOM_EVAL_SOLANA_CANARY_AUTHORIZATION="$HOME/.config/bloom/solana-canary.json"
export BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE="$HOME/.config/bloom/eval-sweep.json"
export BLOOM_EVAL_SOLANA_DESTINATION=...            # that keypair's address
export BLOOM_EVAL_SOLANA_MAINNET_ACK=TRANSFER_SOL_MAINNET_UP_TO_THE_AUTHORIZED_AMOUNT
export BLOOM_EVAL_AUTHENTICATOR_SEED_FILE="$HOME/.config/bloom/eval-authenticator-seed"

# Local files only: no ceremony, mounted write, Docker job, or network call is
# possible in this mode, so it is safe while the wallet is still empty.
scripts/evals/run-harbor.sh solana-transfer --preauthorization-only

scripts/evals/run-harbor.sh solana-transfer claude
scripts/evals/run-harbor.sh solana-transfer codex
scripts/evals/run-harbor.sh solana-transfer glm
scripts/evals/run-harbor.sh solana-transfer deepseek
scripts/evals/run-harbor.sh solana-transfer opencode
```

Set `BLOOM_EVAL_MODEL` to select a different model without changing the
harness. The GLM adapter defaults to `glm-5.2` and accepts `GLM_API_KEY`,
`ZAI_API_KEY`, or `ANTHROPIC_AUTH_TOKEN` from the host; the credential is
forwarded only to Harbor's agent adapter.

`deepseek` and `opencode` both require `DEEPSEEK_API_KEY`. OpenCode model
overrides use `provider/model` form, for example
`BLOOM_EVAL_MODEL=deepseek/deepseek-v4-flash`.

The deterministic `smoke` lane is the protocol conformance fixture: it checks
the real mounted route, approval boundary, broadcast, and verifier without an
LLM. For each model trial the harness renders one concrete sentence containing
only the request a user would make: wallet, destination, network, amount, and a
request to wait for finality. It exposes no eval variables, documentation hint,
procedure, or reporting schema to the agent. The operational workflow must be
discovered from the mounted VFS. The verifier grades independent chain and VFS
state, not an agent-authored report.

This is a controlled representation of a real session, not a byte-for-byte
copy. Harbor runs each CLI in a clean `/app` workspace with a temporary tool
home and non-interactive permissions, while a developer normally has a project,
settings, skills, and prior conversation. The important topology is preserved:
Bloom is a sibling mount at `/bloom`, and every wallet read and write reaches the
real VFS.
The host auto-completes the owner's ceremony only after independently checking
the staged terms. Consequently this eval measures Bloom workflow discovery and
safe execution; it does not measure setup-skill discovery, permission prompts,
or the human approval UI.

`BLOOM_EVAL_SOLANA_HOME_ROOT` is required because the approver watches the
canonical `approval_challenge.json` from stable host state rather than through
the live mount. Current outboxes also project that sanitized resume artifact to
the owner filesystem; the agent must not attempt to complete its ceremony.

### The approval, and why it is watched rather than pre-driven

The Hyperliquid host completes every ceremony during provision, before Harbor
starts. Here the agent drives the confirm, so its ceremony appears while the
container is running. A background approver polls for it and completes it **only
after** checking the staged intent against the exact authorized destination,
amount, fee payer, and fee ceiling. It is never a rubber stamp for whatever the
agent staged, and it is independent of the canary: the approver refuses at
approval, the canary refuses again at broadcast.

### The mount contract

`/bloom` is bound read-only and the wallet's `chains/<chain>/outbox` subtree is
over-mounted read-write. A pending entry's id is allocated by the daemon when the
agent stages, so its `confirm` path cannot be enumerated before the container
starts. The Docker flag is defence in depth; the authority boundary is the VFS
mode — everything under `outbox/` is `0444` except `new.tx` and a pending entry's
`confirm`, `cancel` and `restage` — plus Broker policy, the ceremony, and the
canary. Provision refuses when the outbox is absent, because Docker silently
creates an empty directory at a missing bind source and would mask the real one.

### Cleanup

Host-owned, ordered, and fail-closed. Pending entries are cancelled and the
directory must drain, since a residual staged entry still holds a broadcastable
blockhash. `sent/` must hold zero or one reconciled entry. On mainnet, the
destination is then swept back to the source and the drain is confirmed from the
chain rather than from the CLI's exit code. The sweep runs whenever the addresses
are known, not only when a `sent/` entry exists: a broadcast the outbox failed to
record still moved funds, and that is the worst case in which to skip it. The
local wrapper instead destroys its disposable validator ledger.

The container's own cleanup cancels staged entries and nothing else. There is no
post-broadcast undo to delegate, and giving a container a path that moves funds
would defeat the bound the eval rests on.

### WebAuthn counters

The harness records the next unused counter beside the seed file it belongs to,
at `<seed file>.sign-count`, rather than leaving it to be tracked by hand. The
record is keyed to the credential because a signature counter belongs to one
authenticator, not to the machine: two evals may be configured with different
seed files, and a shared record would carry one credential's counter into the
other's run. `BLOOM_EVAL_SIGN_COUNT_FILE` overrides the location.
It is written the moment a counter is consumed, before the ceremony's result is
even inspected, because the Broker accepts the counter before a ceremony can
fail. Set `BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT` to override or to seed the first
run; the recorded value never moves backwards, and falling back to it prints a
line naming the counter and the file it came from, so it is never silent. A
stale record is safe in both directions: too low is rejected by the Broker and
fails the run without moving anything, and too high is simply accepted, since
counters only have to increase.

A Solana transfer spends far fewer counters than a Hyperliquid session. A live
local-validator run of `bloom-it`'s `solana_workflow` shows one signing call for
the confirm, plus key derivation on first use, against Hyperliquid's three. The
harness caps the count rather than asserting it.

### Validate against a live chain

```bash
solana-test-validator --ledger /tmp/bloom-eval-ledger --reset --quiet &
scripts/evals/test-solana-live.sh
```

`scripts/test-harbor-evals.sh` drives the verifier against a deterministic fake
RPC, which proves the logic but not that it matches what a Solana node actually
returns. This runs the same code against a real validator with real transfers,
and exercises the host sweep, which cannot be tested at all without a chain. It
accepts the exact transfer from independent chain evidence, pays the destination
a second time and confirms the previously valid transfer is then rejected, and
finally sweeps the destination and confirms the drain from the chain. It refuses
any endpoint that is not local, and refuses the mainnet-beta genesis outright.

### What live runs have confirmed

Before spending model tokens, run the deterministic mounted lifecycle gate:

```sh
scripts/evals/run-harbor-solana-local.sh smoke
```

It needs no provider API key. It uses the same preflight, authority,
mounted-route, host approval, broadcast, reconciliation, verifier, and cleanup
path as a paid trial; only the LLM is replaced by a fixed driver. The mainnet
lane additionally exercises the host sweep that returns transferred funds.

The temporary wallet policy names the destination under the stable `solana`
authority namespace. `solana-local` is the VFS/configuration name; cluster
identity is bound separately by the pinned genesis hash and signed blockhash.

`cargo test -p bloom-it --test solana_workflow -- --ignored` drives a real
`Daemon` against `solana-test-validator`. Running it settled the outbox
behaviour this task depends on:

- the first `confirm` is refused with a permission error, and `confirm` is
  exposed at mode `644`;
- dynamic write sinks must be addressed directly: editor-style atomic writes
  target an invalid sibling such as `confirm.tmp`, while buffered shell writes
  can hide a late NFS error unless the writer forces it before reporting success;
- `intent.json` carries `fee_payer`, `destination`, `lamports`, `fee_lamports`,
  `blockhash`, and — for a staged entry — `account_fingerprint` (hex) and
  `account_derivation_path`, which is what lets the approver check the signing
  identity and not just the amount;
- `receipt.json` is exactly `{outcome, signature, slot, confirmation_status}`,
  reaching `success` / `finalized`;
- `broadcast_attempted.json` carries the signature, fee payer, destination,
  lamports, and blockhash;
- pending ids look like `sol-<32 hex>`, so nothing may assume a numeric id.

`scripts/evals/test-solana-live.sh` settled the chain-facing half:

- the verifier's `jsonParsed` expectations match a real node's response exactly,
  including `program`, `programId`, `parsed.type`, `info`, `meta.fee` and an
  empty `innerInstructions`;
- the verifier requires the exact source, destination, amount, transaction
  shape, finality, and fee ceiling from chain data rather than agent claims;
- the freshness binding holds: paying the destination a second time invalidates
  a transfer that passed moments earlier;
- the host sweep drains a funded destination and returns the lamports, and a
  second sweep over an empty one correctly does nothing;
- a faucet credit is confirmed well before it is finalized, which is why every
  balance this eval reads is a finalized one.

The key fingerprint is lowercase hex: the wire crate declares
`fixed_lower_hex!(Digest32, 32, ...)`.

### Paid-agent status

The task has been attempted through Harbor against a mounted Machine. That run
proved the dynamic outbox mount, staging, and first fail-closed confirm, then
exposed a harness drift bug: Bloom emitted the canonical
`approval_challenge.json` while the host approver still watched the obsolete
private `approval.json`. The watcher now follows the canonical artifact.

The deterministic smoke command above is the release gate for the remaining
live questions before another paid run or any mainnet use:

- whether the configured timeouts suit finalization in that setting;
- whether the corrected background approver drives the real ceremony correctly.

Everything else is covered: the verifier, the freshness binding and the sweep
against a live chain, and the canary preflight, approver match logic, mount
construction and container boundary offline.
