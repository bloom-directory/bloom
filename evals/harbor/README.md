# Bloom agent evaluations with Harbor

Bloom's first Harbor task evaluates an agent's ability to use an already-running
Bloom machine to place and cancel a bounded Hyperliquid order.

## Current task

`tasks/hyperliquid-order-cancel` runs on Hyperliquid **mainnet** with a dedicated
wallet. Each trial must:

- use a host-created, owner-approved, BTC-only agent session capped at $11
  notional, 1x leverage, and a 30-minute expiry;
- set BTC leverage to 1 before placing the order;
- place one post-only BTC buy 5% below the current mark, with notional between
  Hyperliquid's $10 minimum and the $11 cap;
- confirm the order rests, cancel it, confirm no matching order remains, and
  leave the session active for harness-owned cleanup.

The v0 verifier intentionally grades the agent's strict `result.json` report,
as agreed for the first eval slice. It checks task parameters and arithmetic but
is **not yet independent venue evidence**. A follow-up should grade Bloom/venue
audit data outside the agent-controlled container.

## Prerequisites

- Linux with Docker, `uvx`, `jq`, `flock`, Claude Code and/or Codex auth. Use a
  dedicated, revocable model credential for evals rather than an unrelated
  production credential.
- A running Bloom triad mounted at `/bloom`, with the Hyperliquid Petal installed.
- A dedicated mainnet wallet created with the deterministic Broker debug-driver
  credential. Do not use a wallet with any open order or position.
- A built `bloom-broker-debug-driver` from the sibling `bloom-broker` repository.
- The debug driver must include `--authenticator-seed-file` support from
  [`bloom-broker#1`](https://github.com/bloom-directory/bloom-broker/pull/1).
- A mode-`0600` file containing the matching authenticator seed.

No wallet key, API wallet key, credential seed, or model credential is committed.
The host runner invokes the debug driver before Harbor starts. The agent
container receives the complete `/bloom` tree read-only so discovery matches the
normal installed-agent experience. Docker over-mounts only that session's
`order.json`, `cancel.json`, `update_leverage.json`, and `cancel_all` action files
read-write; the session's `stop` route remains read-only and host-owned. The
container never receives the debug driver or authenticator seed. Harbor's agent
adapters necessarily make the selected model credential available to the
installed CLI process. Because that process also needs public provider egress,
the model credential is not confined from the evaluated process; use a dedicated
revocable credential. Harbor uses its public Docker bridge so the installed
agent can reach its model provider, but it does not join the host network.

This gives the task full filesystem visibility without making every Bloom
capability writable. The host-created session supplies a second hard boundary:
BTC only, $11 maximum notional, 1x maximum leverage, 30-minute expiry, and one
serialized attempt.

## Run

```bash
export BLOOM_EVAL_WALLET=0x... # dedicated, lowercase address
export BLOOM_EVAL_AUTHENTICATOR_SEED_FILE="$HOME/.config/bloom/eval-authenticator-seed"
export BLOOM_EVAL_MAINNET_ACK=PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD

# Claude Code / Sonnet 5
export CLAUDE_CODE_OAUTH_TOKEN=... # or ANTHROPIC_API_KEY
scripts/evals/run-harbor-hyperliquid.sh claude

# Codex / GPT-5.6 Terra
# Uses OPENAI_API_KEY when set; otherwise ~/.codex/auth.json.
scripts/evals/run-harbor-hyperliquid.sh codex
```

The runner pins Harbor 0.21.0 by default. Override with `HARBOR_VERSION` only
after running the static tests and a dry environment build.

## Safety and cleanup

The runner fails closed unless the exact mainnet acknowledgement is set,
`/bloom` is a real mount, the dedicated wallet has no open orders or positions,
the debug driver and protected seed file exist, and Docker is available. It uses
`flock`, `--n-concurrent 1`, one attempt, and no retries.

A unique session ID and client order ID are generated per trial. The runner
creates the exact bounded session, completes its passkey ceremony on the host,
retries the byte-identical request, and validates the resulting session before
starting Harbor. Cleanup runs:

1. in the task after the agent;
2. in the Harbor verifier; and
3. from the host runner's exit/signal trap.

The task and verifier invoke `cancel_all` and verify that the client order ID is
absent. Only the host trap can write `stop`; after cancellation checks pass it
stops the session and verifies the stopped state. Any cleanup failure fails the
run and operators must inspect the wallet before another trial. Cleanup never
attempts `close_all`, because this eval must not alter positions.

## Validate without trading

```bash
scripts/test-harbor-evals.sh
uvx --from harbor==0.21.0 harbor run \
  --path evals/harbor/tasks/hyperliquid-order-cancel \
  --agent codex --model gpt-5.6-terra --print-config
```

The first command tests valid and adversarial reports, shell syntax, task TOML,
and the full-tree/read-only plus action-file/read-write mount contract.
`--print-config` resolves Harbor configuration without
starting an agent or touching Hyperliquid.

## Self-contained triad follow-up

The repository already has a multi-stage image for the `bloom` CLI, while the
normative Linux triad packaging relies on three principals, systemd-owned Unix
sockets, root-owned manifests, and deliberately non-transitive groups. Building
separate Machine, Broker, and Signer images can make Harbor trials reproducible,
but it should be a follow-up rather than part of this host-backed eval:

1. add one runtime image per service binary;
2. preserve the Machine→Broker→Signer boundary with separate state volumes and
   Unix-socket volumes rather than collapsing the services into one container;
3. run the Machine's NFS export and mount it into a dedicated volume shared with
   the Harbor main container at `/bloom`;
4. keep Broker ceremony credentials and Signer key state out of the agent
   container; and
5. add a deterministic local/testnet fixture before considering a mainnet lane.

That mode would complement this task: composed images test reproducibility and
service wiring; the current host-backed mode tests the machine users actually
have installed.
