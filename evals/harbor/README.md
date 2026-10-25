# Bloom Harbor evaluations

Each trial starts a real, disposable Machine–Broker–Signer Triad with a fresh
software passkey. Solana also starts a new local validator ledger. No policy
restore, receipt recovery or cross-run passkey counter file is needed. The
counter increases before every ceremony attempt within a trial.

| Task | Coverage | Evidence |
| --- | --- | --- |
| `solana-transfer` | Local settlement | Exactly one finalized native transfer, exact addresses and lamports, bounded fee |
| `hyperliquid-order-cancel` | Venue order lifecycle | Independently observed canceled ALO order, exact account, asset ID, price, size and CLOID |
| `polymarket-limit-order-proposal` | Proposal only | Exactly one unsigned draft, exact condition/token IDs and base-unit order terms |
| `<petal>-clarification` | Clarification | Final question asks for the one missing fact; no staged work |

Clarification Petals are `solana`, `hyperliquid`, `polymarket` and `near-intents`.
These cases require no funding. The host checks the actual Harbor trajectory;
an agent-authored claim that it asked is not evidence.

Each fixture has one wallet and account. Clarification omits only the transfer
chain, Hyperliquid network, Polymarket market, or NEAR Intents origin chain.
The NEAR request specifies its output chain and recipient; the Hyperliquid
request specifies perpetuals. An assumed chain/network remains a failure even
when the agent correctly discovers the fixture's only wallet.

Proposal and clarification grading uses Harbor's host-verifier API to read the
same live projections through the disposable Machine's IPC endpoint. This
avoids slow mount path lookups during grading and records the actual reward
inside Harbor, including the final clarification question. The agent still
uses the ordinary mounted filesystem. Verification timeouts are unchanged.
The Docker environment skips Harbor's recursive ownership repair for `/bloom`:
its entries are live virtual projections, not host files. Log ownership repair
still runs, and writable Bloom command routes stay writable.

NEAR's positive swap-proposal task is not implemented yet. The real spike on
the released v0.1.4 package rejected an unfunded fresh wallet before creating
a proposal: it requires native gas and the origin asset even when nothing is
signed. A dedicated funded import fixture is needed before its successful
spike, verifier and agent trials can be completed. Do not count a failed quote
or onboarding request as a swap proposal.

## Run one trial

Supply the exact four candidate binaries using
`BLOOM_INTEGRATION_MACHINE_BIN`, `BLOOM_INTEGRATION_BROKER_BIN`,
`BLOOM_INTEGRATION_SIGNER_BIN` and `BLOOM_INTEGRATION_DEBUG_DRIVER_BIN`.
Build all three services with the **release profile** and `triad-dev-harness`;
Machine also needs `mount`. Point the variables above at those optimized
executables, including the Broker debug driver's release-profile executable.
For example, run the corresponding command in each selected checkout:

```sh
# Machine (default features include mount)
cargo build --release --locked -p bloom --features triad-dev-harness
# Broker and its software-authenticator driver
cargo build --release --locked -p bloom-broker -p bloom-broker-debug-driver --features bloom-broker/triad-dev-harness
# Signer (default features include the local backend)
cargo build --release --locked -p bloom-signer --features triad-dev-harness
```

Debug Broker/Signer builds make authenticated account refreshes expensive.
Mounted metadata lookups repeat those live refreshes: a controlled comparison
of the same revisions measured 119 seconds for twelve Hyperliquid child stats
with debug services and 2.8 seconds with all three services optimized. Optimizing
only Machine still took 111 seconds. Keep custody freshness checks and task
limits intact; use representative optimized services for agent timing.

See `DEVELOPMENT.md` for launcher prerequisites and revision selection.
The harness never selects or stops the installed custody Triad.

```sh
scripts/evals/run-harbor.sh solana-transfer codex
scripts/evals/run-harbor.sh polymarket-limit-order-proposal claude
scripts/evals/run-harbor.sh near-intents-clarification opencode
```

Agents are Claude Code, Codex and OpenCode. Harbor 0.21.0 and the shared agent
image are pinned. The image digest includes eval-images#9's OpenCode 1.18.26.
The OpenCode adapter uses that installed binary instead of downloading NVM
and reinstalling the CLI during every trial.
Existing agent authentication is handled by Harbor; never copy credentials
into a task or the mounted Bloom tree. `BLOOM_EVAL_REASONING_EFFORT` optionally
selects Codex reasoning effort using the existing supported values.

Linux needs the launcher's noninteractive NFS mount/unmount permissions. By
default, the mountpoint is inside the fresh trial root. A host with a narrowly
scoped existing sudo rule can set `BLOOM_EVAL_MOUNTPOINT` to that exact path.
It must be empty and unmounted; the harness holds a mountpoint lock for its
lifetime. State and validator ledgers remain separate for every trial.

## Hyperliquid funding

Set `BLOOM_EVAL_HYPERLIQUID_TESTNET_MNEMONIC_FILE` to a dedicated, funded
testnet wallet's mode-0600 file. The host imports it through Broker's real
`bloom wallet import` ceremony. Only the address/funds are reused: custody
state and the software passkey are new. BTC's numeric asset ID is discovered
from the selected venue's metadata rather than assuming mainnet's ID.

If no testnet fixture is configured, the authorized fallback is an imported
dedicated mainnet wallet selected with
`BLOOM_EVAL_HYPERLIQUID_MAINNET_MNEMONIC_FILE`. The existing $11 order cap,
post-only order, exact session authority and cleanup checks remain. The
harness never silently switches away from a configured testnet fixture.

The reused venue account must have no orders, positions or foreign API agent.
Its stable eval agent name is replaced on subsequent runs, rather than
accumulating new venue agents. `BLOOM_EVAL_AGENT_NAME` can explicitly select
an existing eval agent name. A venue lock still serializes this shared funded
wallet. This is distinct from the removed unresolved-policy recovery lock.

## Proposal boundary and cleanup

Polymarket can create an order draft without balance or onboarding. Its task
exposes only draft creation as writable; it supplies no signing allowance or
auto-approver. The verifier checks the authoritative draft and numbered-account
projection, chain ID, condition ID, token ID and integer amounts. Display
labels and agent-written reports cannot earn a pass.

An unposted Polymarket draft has no cancel route and no CLOB order. Teardown
discards that draft with its disposable root. Solana teardown stops its
approver, Triad and validator. Hyperliquid first cancels residual orders,
closes residual positions and stops its bounded session; it preserves custody
if that cleanup fails. Cleanup failures fail the trial.

Successful trials remove their private root with ordinary, non-forced
recursive removal. Failed trials preserve it for diagnosis. It can contain
credentials and ceremony capabilities: never publish raw service logs or
copy private state into evidence.

## Verification and evidence

```sh
scripts/test-harbor-evals.sh
scripts/evals/run-harbor.sh solana-transfer codex --smoke
scripts/evals/run-harbor.sh polymarket-limit-order-proposal codex --smoke
```

The smoke flag uses real services and the mounted VFS without calling an LLM.
It is not a Harbor agent trial. The full acceptance gate remains one manually
reviewed real trial per positive task per agent, plus the clarification cases.
Do not launch batches before reviewing the first runs.

Summaries under ignored `evals/harbor/jobs/summaries/` record coverage, run
kind, source revision, binary hashes, verifier reward, token usage, timings
and cleanup outcome. `BLOOM_EVAL_JOBS_DIR` selects a different evidence root.
Copy only public summaries and selected public receipts to `shared/`.
