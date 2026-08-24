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

- Linux or macOS with Docker, `uv`, Python 3.11 or newer (`scripts/test-harbor-evals.sh`
  reads task TOML with `tomllib`), Claude Code and/or Codex auth. Use
  a dedicated, revocable model credential for evals rather than an unrelated
  production credential. macOS works when its NFS 4.1 client can mount the
  Machine export; this is per-machine, so verify with `--mount` before relying
  on it.
- A running Bloom triad mounted at `/bloom`, with the Hyperliquid Petal
  installed. Set `BLOOM_EVAL_BLOOM_MOUNT` when the mount is somewhere else; the
  `/bloom` paths throughout this document are then relative to that value. A
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

## Run

```bash
export BLOOM_EVAL_WALLET=0x... # dedicated, lowercase address
export BLOOM_EVAL_WALLET_ID=... # dedicated Bloom wallet ID
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
cat "/bloom/wallets/$BLOOM_EVAL_WALLET_ID/policy.json" >"$original_policy"
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
cp "$policy_file" "/bloom/wallets/$BLOOM_EVAL_WALLET_ID/policy.json"
challenge="/bloom/wallets/$BLOOM_EVAL_WALLET_ID/policy-updates/latest/approval_challenge.json"
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
cp "$policy_file" "/bloom/wallets/$BLOOM_EVAL_WALLET_ID/policy.json"
cat "/bloom/wallets/$BLOOM_EVAL_WALLET_ID/addresses.json"
cat "/bloom/wallets/$BLOOM_EVAL_WALLET_ID/policy.json"

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

## Safety and cleanup

The runner fails closed unless the exact mainnet acknowledgement, wallet ID,
installed package hash, delegated class, downstream signing-route metadata,
installer-signature material, active lineage, and next WebAuthn signature
counter are set. The wallet policy must match that package-only authority exactly,
`/bloom` is a real mount, the dedicated wallet has no open orders or positions,
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
