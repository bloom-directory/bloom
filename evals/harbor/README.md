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

The verifier validates the agent's strict `result.json` report and independently
queries Hyperliquid `orderStatus` first by the host-generated CLOID and then by
the returned venue order ID. It requires the venue record to be a canceled BTC
ALO buy and binds its immutable price, original size, and order ID back to the
report; agent-authored status fields are not accepted as placement or
cancellation evidence.

## Prerequisites

- Linux or macOS with Docker, `uv`, and Claude Code and/or Codex auth. The
  repository scripts obtain their isolated Python 3.12 runtime through `uv`; no
  ambient Python installation is required. Use
  a dedicated, revocable model credential for evals rather than an unrelated
  production credential. macOS works when its NFS 4.1 client can mount the
  Machine export; this is per-machine, so verify with `--mount` before relying
  on it.
- A running Bloom triad mounted at the path supplied as
  `BLOOM_EVAL_BLOOM_MOUNT`, with the Hyperliquid Petal installed. Every full
  environment-driven eval requires this variable; `/bloom` is conventional but
  is never selected implicitly. A
  home-directory mount avoids needing `/etc/synthetic.conf` on macOS, whose
  sealed system volume will not accept a bare `mkdir /bloom`.
- A dedicated mainnet wallet created with the deterministic Broker debug-driver
  credential. Do not use a wallet with any open order or position.
- A built `bloom-broker-debug-driver` from the sibling `bloom-broker` repository.
- The debug driver must include `--authenticator-seed-file` support from
  [`bloom-broker#1`](https://github.com/bloom-directory/bloom-broker/pull/1).
- Broker PR #1 must be at commit
  `7b2ca77c1182dbf1a94dc6a4b738ff8cade9517b` or later so authority and
  ceremony mutations verify the dedicated audit journal, not another SQLite DB.
- A mode-`0600` file containing the matching authenticator seed.
- The immutable Machine owner record for the installed Hyperliquid Petal. This
  is normally `.../state/machine/petals/store/owners/hyperliquid.json`; pass its
  exact host path as `BLOOM_EVAL_PETAL_OWNER_RECORD`.
- The Machine Petal store and signed provenance catalog. The installed route
  index must bind the exact package hash and give only the session-creation
  route the delegated `hyperliquid.agent_action` class. Its installer-signed
  provenance record must contain exactly that class plus
  `hyperliquid.approve_agent`, with active lineage. Every downstream session
  action route must attest `bloom:sign` and `hyperliquid.agent_action` at
  runtime.
- The dedicated wallet's active Broker policy must contain no funding
  destinations and allow only the exact installed Hyperliquid package hash.

No wallet key, API wallet key, credential seed, or model credential is committed.
The Python host harness invokes the debug driver before Harbor starts. The agent
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

## Context-free operator workflow

Use `operate-harbor-hyperliquid.sh` for live runs. It replaces the manual policy
and counter bookkeeping below with one recoverable lifecycle. Its state file is
local, mode `0600`, and atomically updated; it contains wallet identifiers and
paths to credentials, never a credential or authenticator seed. The exact
default handoff is `evals/harbor/operator-state.json`. It is inside the checkout
so a new agent finds it without shell history or a guessed custom path, but is
gitignored and must never be added to a commit. `uv` is the only Python
prerequisite: every operator command uses an isolated Python 3.12 environment.

The state schema is `bloom.eval.operator-state.v1`. It records
`wallet_id`, `wallet_address`, `package_hash`, `model`, optional `agent_name`,
`next_sign_count`, `pending_policy_recovery`, discovered `paths`, source
`lineage`, and triad `binaries` with SHA-256 digests. `paths` contains the triad
root, Machine mount, owner record, Petal store, provenance catalog,
authenticator-seed file path, debug-driver path, lock/job directories, and the
three sibling source repositories. The seed and model credential are never
stored. `purpose`, `handoff`, and `field_guide` make the JSON self-describing;
`handoff.safe_fields` lists the fields intended for the designated eval
operator, while `required_secret_path_fields` names the required seed *path*
without storing its contents. `recovery` records the exact protected state,
policy-backup, summary, and marker locations. The operator rejects a moved file
with stale recovery locations. Do not edit this file by hand; rerun `init` only
when status reports no pending recovery.

The generated handoff is ordinary JSON and can be passed directly to
`json.load`. Its shape is:

```json
{
  "schema": "bloom.eval.operator-state.v1",
  "purpose": "Protected local handoff for cold-start and repeat-agent Hyperliquid Harbor eval operation; contains identifiers and secret paths, never secret contents.",
  "handoff": {
    "agent_readable": true,
    "contains_secret_contents": false,
    "safe_fields": ["schema", "purpose", "handoff", "field_guide", "created_at", "updated_at", "wallet_id", "wallet_address", "package_hash", "model", "agent_name", "next_sign_count", "pending_policy_recovery", "paths", "lineage", "binaries", "recovery"],
    "required_secret_path_fields": ["paths.authenticator_seed_file"],
    "resume_instruction": "Run status first; recover pending policy state; never guess a counter."
  },
  "field_guide": {"paths": "...", "lineage": "...", "next_sign_count": "...", "pending_policy_recovery": "..."},
  "created_at": "<UTC timestamp>",
  "updated_at": "<UTC timestamp>",
  "wallet_id": "<dedicated wallet id>",
  "wallet_address": "<dedicated wallet address>",
  "package_hash": "<installed package hash>",
  "model": "codex",
  "agent_name": null,
  "next_sign_count": 2,
  "pending_policy_recovery": null,
  "paths": {"triad_root": "<absolute path>", "bloom_mount": "<absolute path>", "authenticator_seed_file": "<absolute secret-file path>"},
  "lineage": {"bloom": {"revision": "<commit>", "dirty": false}, "broker": {"revision": "<commit>", "dirty": false}, "signer": {"revision": "<commit>", "dirty": false}, "petal_contract_revision": "<commit>", "hyperliquid_petal": {"revision": "<commit>", "dirty": false}},
  "binaries": {"bloom": {"path": "<absolute path>", "sha256": "<digest>"}},
  "recovery": {"state_file": "<absolute default handoff path>", "policy_backup_file": "<absolute protected backup path>", "summary_directory": "<absolute summary directory>", "marker_field": "pending_policy_recovery"}
}
```

The abbreviated `paths` and `binaries` objects above document the format; `init`
always writes the complete validated objects described in the preceding
paragraph. Never construct or seed the file with secret contents.

If the triad is not already running, start it in one terminal with a private,
persistent developer root and an empty mount directory. These values are local
operator choices and must not be committed:

```bash
export BLOOM_EVAL_TRIAD_ROOT=/private/path/to/persistent/eval-triad
export BLOOM_EVAL_BLOOM_MOUNT=/private/path/to/empty/mount
mkdir -p "$BLOOM_EVAL_TRIAD_ROOT" "$BLOOM_EVAL_BLOOM_MOUNT"

BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE=../bloom-petal-hyperliquid \
scripts/triad-dev-launch.sh \
  --developer-root "$BLOOM_EVAL_TRIAD_ROOT" \
  --mount "$BLOOM_EVAL_BLOOM_MOUNT" \
  --machine-socket "$BLOOM_EVAL_TRIAD_ROOT/runtime/machine.sock" \
  --log-dir "$BLOOM_EVAL_TRIAD_ROOT/logs" \
  --ready-file "$BLOOM_EVAL_TRIAD_ROOT/ready"
```

In another terminal, initialize protected state. The wallet address, installed
owner record, Petal store, and signed provenance catalog are discovered from the
wallet id, mount, and triad root. Initialization verifies a Broker-confirmed,
deny-by-default, empty dedicated wallet; the installed Hyperliquid lineage; the
source revisions of Bloom, Broker, Signer, and the Hyperliquid Petal; Bloom's
pinned Petal contract revision; and hashes of the triad/debug-driver binaries.
This command creates or refreshes the default handoff at
`evals/harbor/operator-state.json`:

```bash
scripts/evals/operate-harbor-hyperliquid.sh init \
  --triad-root "$BLOOM_EVAL_TRIAD_ROOT" \
  --mount "$BLOOM_EVAL_BLOOM_MOUNT" \
  --wallet-id DEDICATED_EVAL_WALLET_ID \
  --seed-file /private/path/to/authenticator-seed \
  --sign-count NEXT_SAFE_COUNTER \
  --model codex

# Read-only: no ceremony, mounted write, Docker job, or venue call.
scripts/evals/operate-harbor-hyperliquid.sh status

scripts/evals/operate-harbor-hyperliquid.sh run \
  --ack PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD
```

The run command refuses changed source or binary lineage, stages only the exact
installed package into the wallet policy, persists each next safe WebAuthn
counter atomically, runs and cleans up the bounded session, and restores the
original deny-by-default policy from a protected backup in an unconditional
cleanup path. If the process or machine is interrupted, do not run `init` or
guess a counter. Restart the same triad and run:

```bash
scripts/evals/operate-harbor-hyperliquid.sh recover \
  --ack PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD
scripts/evals/operate-harbor-hyperliquid.sh status
```

Recovery replays the exact saved policy bytes and continues from the atomically
persisted next candidate counter. A counter is advanced after every ceremony
attempt that reached the Broker: gaps are valid, while reuse after an ambiguous
transport result is unsafe. The protected backup and recovery marker are
cleared only after the deny-by-default policy is visible again.

Each run writes a mode-`0600` JSON summary beside the operator state, under
`harbor-summaries/`. It includes source lineage, installed package hash,
Harbor/model configuration, reward, trial errors/retries, monotonic phase and
total timings, and the cleanup/policy postconditions. It deliberately excludes
wallet identifiers, credential paths, ceremony URLs, and secrets.

For an existing checkout, a repeat agent must start with the default
`status` command. If the handoff reports pending recovery, the agent runs
`recover` with the explicit mainnet acknowledgement before doing anything else;
it must not rerun `init`, infer a counter, or copy the handoff to a different
path. `--state /private/path/to/state.json` remains available on every command
for deliberately managed non-default deployments, but it is not needed for the
standard cold-start handoff. `BLOOM_EVAL_BLOOM_MOUNT` is never hard-coded by the
operator; all host paths are derived from the initialized state.

The operator and evaluated agent exercise the mounted drive exclusively through
ordinary filesystem operations. They must not invoke `bloom vfs`, connect to a
Machine RPC endpoint, or use another transport as a fallback. A mount that
returns `EPERM`, times out, or otherwise cannot serve a standard read or write is
an eval-environment failure and must be repaired or remounted before retrying.
This is intentional: the eval covers the installed NFS filesystem experience,
not the semantically equivalent direct CLI path.

## Low-level/manual run

The following environment-driven workflow remains available for harness
development and diagnosis. Prefer the operator workflow for a full live eval.
Mount selection is mandatory and deliberately not auto-discovered because more
than one Bloom mount may exist.

```bash
export BLOOM_EVAL_WALLET=0x... # dedicated, lowercase address
export BLOOM_EVAL_WALLET_ID=... # dedicated Bloom wallet ID
export BLOOM_EVAL_BLOOM_MOUNT=/bloom # or the triad's exact custom --mount path
export BLOOM_EVAL_PETAL_OWNER_RECORD=/path/to/state/machine/petals/store/owners/hyperliquid.json
export BLOOM_EVAL_PETAL_STORE=/path/to/state/machine/petals/store
export BLOOM_EVAL_PROVENANCE_CATALOG=/path/to/config/provenance-catalog.json
export BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["hash"])' \
  "$BLOOM_EVAL_PETAL_OWNER_RECORD")
export BLOOM_EVAL_AUTHENTICATOR_SEED_FILE="$HOME/.config/bloom/eval-authenticator-seed"
# Strictly greater than this credential's last accepted WebAuthn signature counter.
# Registration with the deterministic debug driver consumes counter 1, so the
# first post-registration ceremony uses 2. Increment after every completion.
export BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT=2
export BLOOM_EVAL_MAINNET_ACK=PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD
# Optional. The eval registers its Hyperliquid API agent under a name derived
# from the wallet id, so each run replaces the previous agent rather than the
# account accumulating one per run. Set this only to adopt an agent that is
# already registered under a different name, which is the one case a derived
# name cannot reconcile: Hyperliquid replaces a named agent but offers no safe
# removal, since a deregistered agent's nonce state may be pruned and
# re-registering that address is then replay-unsafe. Preflight matches this
# name exactly and rejects any other agent.
# export BLOOM_EVAL_AGENT_NAME=be-...

# Run this while the wallet remains deny-by-default. It reads only immutable
# local package/provenance files: no policy inspection, ceremony, mounted write,
# agent, Docker job, or external call is possible in this mode.
scripts/evals/run-harbor-hyperliquid.sh --preauthorization-only

# Claude Code / Sonnet 5
export CLAUDE_CODE_OAUTH_TOKEN=... # or ANTHROPIC_API_KEY
scripts/evals/run-harbor-hyperliquid.sh claude

# Codex / GPT-5.6 Terra
# Uses OPENAI_API_KEY when set; otherwise ~/.codex/auth.json.
scripts/evals/run-harbor-hyperliquid.sh codex
```

### Reproduce the package-only wallet policy

The example at `evals/harbor/policies/hyperliquid-only.example.json` matches the
package hash used by the verified local run. Bloom package IDs are BLAKE3
digests, not SHA-256 values. Always derive the current hash from the immutable
installed owner record as shown above. Copy the example to a private temporary
file, replace `wallet_id`, and retain those exact canonical bytes for both
writes. Save and validate the original deny-by-default policy before staging so
it can be restored after the trial:

```bash
policy_file=$(mktemp)
original_policy=$(mktemp)
trap 'rm -f "$policy_file" "$original_policy"' EXIT
cat "$BLOOM_EVAL_BLOOM_MOUNT/wallets/$BLOOM_EVAL_WALLET_ID/policy.json" >"$original_policy"
python3 - "$BLOOM_EVAL_WALLET_ID" "$BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH" "$policy_file" "$original_policy" <<'PY'
import json, pathlib, sys
source = pathlib.Path("evals/harbor/policies/hyperliquid-only.example.json")
policy = json.loads(source.read_text())
policy["wallet_id"] = sys.argv[1]
policy["allowed_petal_packages"] = [sys.argv[2]]
pathlib.Path(sys.argv[3]).write_text(
    json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n"
)
original = json.loads(pathlib.Path(sys.argv[4]).read_text())
expected_original = dict(policy, allowed_petal_packages=[])
if original != expected_original:
    raise SystemExit("original eval-wallet policy is not deny-by-default")
PY

# First write stages validation and returns the owner-approval boundary. The
# pending entry is published asynchronously, so listing the pending directory
# immediately after the write can still observe nothing, particularly over an
# NFS mount. Resolve the staged action through `policy-updates/latest`, which
# points at the most recently staged pending action and is absent whenever none
# is pending, then confirm it is bound to these exact proposed bytes.
cp "$policy_file" "$BLOOM_EVAL_BLOOM_MOUNT/wallets/$BLOOM_EVAL_WALLET_ID/policy.json"
challenge="$BLOOM_EVAL_BLOOM_MOUNT/wallets/$BLOOM_EVAL_WALLET_ID/policy-updates/latest/approval_challenge.json"
# Allow a generous window: publication is fast on a warm Machine but has taken
# well over ten seconds on the first staged update after a restart.
for _ in $(seq 1 120); do
  [ -r "$challenge" ] && break
  sleep 0.5
done
[ -r "$challenge" ] || { echo "no policy-update ceremony was staged" >&2; exit 1; }
proposed_digest=$(python3 -c \
  'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read().rstrip(b"\n")).hexdigest())' \
  "$policy_file")
python3 - "$challenge" "$proposed_digest" <<'PY'
import json, sys
projection = json.load(open(sys.argv[1]))
if projection["proposed_policy_digest"] != sys.argv[2]:
    raise SystemExit("staged ceremony is bound to different canonical policy bytes")
PY
action_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["operation_id"])' "$challenge")
ceremony_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ceremony_url"])' "$challenge")

bloom-broker-debug-driver complete "$ceremony_url" \
  --authenticator-seed-file "$BLOOM_EVAL_AUTHENTICATOR_SEED_FILE" \
  --sign-count "$BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT"

# Commit by replaying byte-identical bytes, then verify the public projection.
cp "$policy_file" "$BLOOM_EVAL_BLOOM_MOUNT/wallets/$BLOOM_EVAL_WALLET_ID/policy.json"
cat "$BLOOM_EVAL_BLOOM_MOUNT/wallets/$BLOOM_EVAL_WALLET_ID/addresses.json"
cat "$BLOOM_EVAL_BLOOM_MOUNT/wallets/$BLOOM_EVAL_WALLET_ID/policy.json"

# After the eval, repeat this same stage/approve/byte-identical replay process
# with "$original_policy" and the next strictly greater WebAuthn counter. Verify
# policy.json equals original_policy and addresses.json reports broker_verified.
```

The policy ceremony consumes the configured WebAuthn counter. Increment
`BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT` before starting the eval session. If a
proposal expires or is cancelled, query or cancel it by its exact action ID and
replay its byte-identical policy once to reconcile the mounted lifecycle before
staging different bytes.

A session consumes more than one counter, so the next run does not simply start
one higher. Creating a session stages three owner ceremonies — the Signer key
derivation, one reusable approval for the key's typed action routes, then the
`approve_agent` signature that registers the agent with the venue — and each
completion must use a strictly greater counter than the last accepted one.
Starting from `BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT=N`, a session therefore
consumes `N`, `N+1`, and `N+2`, and the next run must start at `N+3` or above.
The harness reports the first counter it did not consume in its failure text;
prefer that value over recounting by hand. A counter that is not strictly
greater than the last accepted one is rejected, which fails the run without
placing an order.

The launcher pins Harbor 0.21.0 by default and then delegates to the reusable
Python harness under `evals/harbor/harness`. The harness uses Harbor's public
`JobConfig`, `Job.create()`, and `Job.run()` API rather than spawning the Harbor
CLI. Shared locking, lifecycle, result validation, signal handling, and cleanup
live in `core.py`; each eval supplies its own prerequisite, capability,
mount/environment, and cleanup implementation. New evals should add another
`EvalDefinition` and register it in `harness/__main__.py`, not copy the
Hyperliquid runner. Override `HARBOR_VERSION` only after running the static tests
and a dry environment build.

Both host orchestration and task execution use the mounted Bloom tree directly.
The host harness performs reads with standard `cat`, listings with normal
directory operations, and writes through the mounted path. The evaluated task
is explicitly prohibited from invoking `bloom vfs` or any Machine RPC fallback.

The task pins the multi-architecture `bloom-eval-agent-base` manifest by digest.
That image provides Node.js and the Codex and Claude Code CLIs, so Harbor detects
the selected agent on `PATH` instead of installing it in every disposable trial
container. Preflight pulls that immutable digest before creating the bounded
mainnet session, so a cold or unavailable image cannot consume the session's
30-minute authority window. Update the digest deliberately when upgrading
either CLI.

## Safety and cleanup

The runner fails closed unless the exact mainnet acknowledgement, wallet ID,
installed package hash, delegated class, downstream signing-route metadata,
installer-signature material, active lineage, and next WebAuthn signature
counter are set. The wallet policy must match that package-only authority exactly,
the configured Bloom path is a real mount, the dedicated wallet has no open orders or positions,
the debug driver and protected seed file exist, and Docker is available. It uses
an advisory file lock, Harbor concurrency 1, one attempt, and no retries.

A unique session ID and client order ID are generated per trial. The runner
creates the exact bounded session, completes its passkey ceremony on the host,
retries the byte-identical request, and validates the resulting session before
starting Harbor. Cleanup runs:

1. in the task after the agent;
2. in the Harbor verifier; and
3. from the Python host harness's unconditional cleanup block.

The task and verifier invoke `cancel_all` and verify that the client order ID is
absent. Only the host harness can write `stop`; after cancellation checks pass it
stops the session and verifies the stopped state. Any cleanup failure fails the
run and operators must inspect the wallet before another trial. Cleanup never
ignores a filled order: after `cancel_all` it invokes host-only `close_all` only
when an independent clearinghouse projection shows a residual position, then
requires zero orders and positions before stopping.

Hyperliquid does not expose a documented API-wallet revoke action through the
official exchange API, and the current Petal has no revoke-agent route. A
durable stopped session retires Bloom-side use of its key; restoring the original
deny-by-default wallet policy is therefore a mandatory final authority boundary.
If session persistence is missing, any new `extra_agents.json` entry is treated
as an orphan and cleanup fails rather than claiming success.

## Validate without trading

```bash
scripts/test-harbor-evals.sh
```

This tests valid and adversarial reports, shell syntax, task TOML, lifecycle
failure paths, byte-identical ceremony retries, the full-tree/read-only plus
action-file/read-write mount contract, and configuration against Harbor 0.21.0's
actual Python API. It does not start an agent or touch Hyperliquid.

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

## Additional evaluations

The [native SOL transfer evaluation](tasks/solana-transfer/README.md) has its
own operator guide because its irreversible transfer, compile-time canary,
host sweep, and outbox approval model differ materially from Hyperliquid's
reversible order/cancel workflow.
