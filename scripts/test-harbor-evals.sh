#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
task="${repo_root}/evals/harbor/tasks/hyperliquid-order-cancel"
verifier="${task}/tests/verify_result.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python_cmd=(uv run --isolated --no-project --python 3.12 python)

wallet="0x1111111111111111111111111111111111111111"
session="bloom-eval-test"
cloid="0x22222222222222222222222222222222"
export BLOOM_EVAL_WALLET="$wallet" BLOOM_EVAL_SESSION_ID="$session" BLOOM_EVAL_CLOID="$cloid"

# Serve deterministic orderStatus responses so the verifier's HTTP trust
# boundary is exercised without touching mainnet. Production does not set the
# URL override and queries https://api.hyperliquid.xyz/info directly.
cat >"$tmp/fake_hyperliquid.py" <<'PY'
import json
import os
import pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer

wallet = os.environ["BLOOM_EVAL_WALLET"]
cloid = os.environ["BLOOM_EVAL_CLOID"]
order = {
    "coin": "BTC",
    "side": "B",
    "limitPx": "95000",
    "sz": "0",
    "oid": 123,
    "timestamp": 1,
    "triggerCondition": "N/A",
    "isTrigger": False,
    "triggerPx": "0",
    "children": [],
    "isPositionTpsl": False,
    "reduceOnly": False,
    "orderType": "Limit",
    "origSz": "0.00011",
    "tif": "Alo",
    "cloid": cloid,
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length))
        if (
            request.get("type") == "orderStatus"
            and request.get("user") == wallet
            and request.get("oid") in (cloid, 123)
        ):
            response = {
                "status": "order",
                "order": {
                    "order": order,
                    "status": "canceled",
                    "statusTimestamp": 2,
                },
            }
        else:
            response = {"status": "unknownOid"}
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


server = HTTPServer(("127.0.0.1", 0), Handler)
pathlib.Path(os.environ["FAKE_HYPERLIQUID_PORT_FILE"]).write_text(
    str(server.server_port)
)
server.serve_forever()
PY
port_file="$tmp/fake-hyperliquid.port"
FAKE_HYPERLIQUID_PORT_FILE="$port_file" "${python_cmd[@]}" "$tmp/fake_hyperliquid.py" &
fake_hyperliquid_pid=$!
trap 'kill "$fake_hyperliquid_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
for _ in $(seq 1 50); do
  [ -s "$port_file" ] && break
  sleep 0.1
done
[ -s "$port_file" ] || { echo "fake Hyperliquid server did not start" >&2; exit 1; }
export BLOOM_EVAL_HYPERLIQUID_INFO_URL="http://127.0.0.1:$(cat "$port_file")/info"

cat >"$tmp/good.json" <<EOF
{"schema":"bloom.eval.hyperliquid_order_cancel.v1","status":"complete","network":"mainnet","wallet":"$wallet","session_id":"$session","asset":"BTC","asset_id":0,"side":"buy","leverage":1,"post_only":true,"mark_price":"100000","limit_price":"95000","size":"0.00011","notional_usd":"10.45","cloid":"$cloid","order_status":"resting","order_id":123,"cancel_status":"success","matching_open_orders_after_cancel":0,"session_left_active_for_harness_cleanup":true}
EOF
"${python_cmd[@]}" "$verifier" "$tmp/good.json"

"${python_cmd[@]}" - "$tmp/good.json" "$tmp" "$verifier" <<'PY'
import json, os, pathlib, subprocess, sys
source = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = pathlib.Path(sys.argv[2])
verifier = sys.argv[3]
mutations = {
    "too-small": {"size": "0.0001", "notional_usd": "9.5"},
    "too-large": {"size": "0.00012", "notional_usd": "11.4"},
    "not-otm": {"limit_price": "96000", "notional_usd": "10.56"},
    "too-far-below-target": {"limit_price": "94999", "notional_usd": "10.44989"},
    "not-post-only": {"post_only": False},
    "wrong-leverage": {"leverage": 2},
    "not-cancelled": {"matching_open_orders_after_cancel": 1},
    "wrong-cloid": {"cloid": "0x33333333333333333333333333333333"},
    "no-cleanup-handoff": {"session_left_active_for_harness_cleanup": False},
    "extra-field": {"unexpected": True},
}
for name, values in mutations.items():
    report = source | values
    path = root / f"{name}.json"
    path.write_text(json.dumps(report))
    result = subprocess.run([sys.executable, verifier, str(path)], env=os.environ, capture_output=True, text=True)
    if result.returncode == 0:
        raise SystemExit(f"invalid fixture passed: {name}")
PY

"${python_cmd[@]}" - <<PY
import sys
import tomllib
from pathlib import Path
sys.path.insert(0, str(Path("${repo_root}/evals/harbor")))
from harness.hyperliquid_order_cancel import EVAL_IMAGE

with Path("${task}/task.toml").open("rb") as handle:
    task = tomllib.load(handle)
assert task["task"]["name"] == "bloom/hyperliquid-order-cancel"
assert task["environment"]["network_mode"] == "public"
assert task["environment"]["docker_image"] == EVAL_IMAGE
assert task["agent"]["timeout_sec"] == 900.0
PY

bash -n "${repo_root}/scripts/evals/run-harbor-hyperliquid.sh"
bash -n "${repo_root}/scripts/evals/operate-harbor-hyperliquid.sh"
git -C "$repo_root" check-ignore -q evals/harbor/operator-state.json
! grep -En 'BLOOM_EVAL_VFS_|VfsTransport|bloom vfs' \
  "${repo_root}/evals/harbor/harness"/*.py
grep -Fq '`bloom vfs`, the `bloom` executable' \
  "${task}/instruction.md"
bash -n "${task}/tests/test.sh"
PYTHONPATH="${repo_root}/evals/harbor" "${python_cmd[@]}" -m unittest discover \
  -s "${repo_root}/evals/harbor/harness_tests" -v

# Validate our programmatic configuration against the exact Harbor API version
# used by the launcher. This does not start Docker or touch Hyperliquid.
TMP_JOB_DIR="$tmp/job-plan" PYTHONPATH="${repo_root}/evals/harbor" \
  uv run --isolated --no-project --with harbor==0.21.0 python - <<'PY'
import asyncio
import os
from pathlib import Path

from harbor.job_plan import JobPlan
from harbor.models.environment_type import EnvironmentType
from harbor.models.job.config import JobConfig, RetryConfig
from harbor.models.trial.config import AgentConfig, EnvironmentConfig, TaskConfig, VerifierConfig

config = JobConfig(
    job_name="api-smoke",
    jobs_dir=Path(os.environ["TMP_JOB_DIR"]),
    n_attempts=1,
    n_concurrent_trials=1,
    retry=RetryConfig(max_retries=0),
    agents=[AgentConfig(name="codex", model_name="gpt-5.6-terra", n_concurrent=1)],
    environment=EnvironmentConfig(
        type=EnvironmentType.DOCKER,
        mounts=[{"type":"bind", "source":"/tmp", "target":"/bloom", "read_only":True}],
    ),
    verifier=VerifierConfig(),
    tasks=[TaskConfig(path=Path("evals/harbor/tasks/hyperliquid-order-cancel").resolve())],
)
assert config.n_attempts == 1
assert config.n_concurrent_trials == 1
assert config.retry.max_retries == 0
assert config.environment.mounts[0]["read_only"] is True
plan = asyncio.run(JobPlan.from_config(config))
assert len(plan.trial_configs) == 1
assert plan.trial_configs[0].task.path.name == "hyperliquid-order-cancel"
assert plan.trial_configs[0].environment.mounts[0]["read_only"] is True
PY

printf '%s\n' 'Hyperliquid static checks passed; checking the Solana transfer task.'

# --- Solana transfer task -------------------------------------------------
solana_task="${repo_root}/evals/harbor/tasks/solana-transfer"
bash -n "${repo_root}/scripts/evals/run-harbor.sh"
bash -n "${repo_root}/scripts/evals/run-harbor-solana-local.sh"
bash -n "${solana_task}/tests/test.sh"

# The isolated Broker and Signer PRs were rebased during development. Keep the
# launcher pinned to their reviewed current heads rather than stale hashes that
# no checkout can satisfy.
grep -Fq 'db4f6fc1da95dad5cadb042819c7bc1333a2c699' \
  "${repo_root}/scripts/evals/run-harbor-solana-local.sh"
grep -Fq 'de55f4131cd1a90e352830b8bb1d08b3f6aa3901' \
  "${repo_root}/scripts/evals/run-harbor-solana-local.sh"
grep -Fq -- '--arg chain solana --arg destination' \
  "${repo_root}/scripts/evals/run-harbor-solana-local.sh"
grep -Fq 'developer_root="${run_root}/developer"' \
  "${repo_root}/scripts/evals/run-harbor-solana-local.sh"
grep -Fq 'ledger="${run_root}/validator-ledger"' \
  "${repo_root}/scripts/evals/run-harbor-solana-local.sh"
grep -Fq 'build_root="${BLOOM_EVAL_BUILD_ROOT:-${run_base}/build-cache}"' \
  "${repo_root}/scripts/evals/run-harbor-solana-local.sh"
grep -Fq 'rm -r -- "$run_root"' \
  "${repo_root}/scripts/evals/run-harbor-solana-local.sh"
if grep -Fq 'export BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE=' \
  "${repo_root}/scripts/evals/run-harbor-solana-local.sh"; then
  printf '%s\n' 'the disposable local lane must not retain mainnet sweep state' >&2
  exit 1
fi

python3 - <<SOLTOML
import sys
import tomllib
from pathlib import Path
sys.path.insert(0, str(Path("${repo_root}/evals/harbor")))
from harness.hyperliquid_order_cancel import EVAL_IMAGE

with Path("${solana_task}/task.toml").open("rb") as handle:
    task = tomllib.load(handle)
assert task["task"]["name"] == "bloom/solana-transfer"
assert task["environment"]["network_mode"] == "public"
# Both tasks ride the same pinned agent base image. Drift here means one of
# them silently stopped matching the image the harness actually pulls.
assert task["environment"]["docker_image"] == EVAL_IMAGE
# The agent stages, hits the approval boundary, waits for an out-of-band owner
# approval, retries, then waits for finalization.
assert task["agent"]["timeout_sec"] >= 1200.0
instruction = Path("${solana_task}/instruction.md").read_text()
solana_guide = Path("${repo_root}/crates/bloom-vfs/src/docs/solana.md").read_text()
solana_harness = Path("${repo_root}/evals/harbor/harness/solana_transfer.py").read_text()
assert instruction == "This file is replaced with a concrete, user-like request for every trial.\n"
assert "Using Bloom, send exactly" in solana_harness
assert "agent_env={}" in solana_harness
assert "/bloom/AGENTS.md" not in instruction
assert "result.json" not in instruction
assert "os.fsync" in solana_guide
assert "account_fingerprint" in solana_guide
assert "approval_challenge.json" in solana_guide
assert "broadcast_attempted.json" in solana_guide
assert "validity clock starts" in solana_guide
assert "start a bounded serial retry loop immediately" in solana_guide
SOLTOML

# Serve deterministic Solana RPC responses so the verifier's trust boundary is
# exercised without touching a cluster. Production points the URL at a node.
cat >"$tmp/fake_solana.py" <<'SOLSERVER'
import json
import os
import pathlib
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

SOURCE = os.environ["BLOOM_EVAL_SOLANA_SOURCE"]
DESTINATION = os.environ["BLOOM_EVAL_SOLANA_DESTINATION"]
LAMPORTS = int(os.environ["BLOOM_EVAL_SOLANA_LAMPORTS"])
SIGNATURE = "5" * 87
SLOT = 301442118
FEE = 5000


def result_for(method):
    if method == "getSignaturesForAddress":
        return [{"signature": SIGNATURE, "err": None}]
    if method == "getTransaction":
        return {
            "slot": SLOT,
            "meta": {"err": None, "fee": FEE, "innerInstructions": []},
            "transaction": {
                "message": {
                    "instructions": [
                        {
                            "programId": "11111111111111111111111111111111",
                            "program": "system",
                            "parsed": {
                                "type": "transfer",
                                "info": {
                                    "source": SOURCE,
                                    "destination": DESTINATION,
                                    "lamports": LAMPORTS,
                                },
                            },
                        }
                    ]
                }
            },
        }
    return None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        payload = {
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": result_for(body["method"]),
        }
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        pass


sock = socket.socket()
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
sock.close()
pathlib.Path(os.environ["FAKE_SOLANA_PORT_FILE"]).write_text(str(port))
HTTPServer(("127.0.0.1", port), Handler).serve_forever()
SOLSERVER

solana_port_file="$tmp/solana-port"
export BLOOM_EVAL_SOLANA_NETWORK="mainnet-beta"
export BLOOM_EVAL_SOLANA_CHAIN="solana-mainnet"
export BLOOM_EVAL_SOLANA_WALLET_ID="eval-solana"
export BLOOM_EVAL_SOLANA_SOURCE="9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
export BLOOM_EVAL_SOLANA_DESTINATION="6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu"
export BLOOM_EVAL_SOLANA_LAMPORTS="1003517"
export BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS="10000"

FAKE_SOLANA_PORT_FILE="$solana_port_file" python3 "$tmp/fake_solana.py" &
fake_solana_pid=$!
trap 'kill "$fake_hyperliquid_pid" "$fake_solana_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
for _ in $(seq 1 100); do
  [ -s "$solana_port_file" ] && break
  sleep 0.1
done
[ -s "$solana_port_file" ] || { printf '%s\n' 'fake Solana RPC did not start' >&2; exit 1; }
export BLOOM_EVAL_SOLANA_RPC_URL="http://127.0.0.1:$(cat "$solana_port_file")/"

python3 - "${solana_task}/tests/verify_result.py" <<'SOLCASES'
import os
import subprocess
import sys

verifier = sys.argv[1]


def run(**changes):
    env = dict(os.environ)
    env.update(changes)
    return subprocess.run([sys.executable, verifier], env=env, capture_output=True)


result = run()
if result.returncode != 0:
    raise SystemExit(
        "valid Solana transfer rejected: " + result.stderr.decode(errors="replace")
    )

adversarial = {
    "wrong-amount": {"BLOOM_EVAL_SOLANA_LAMPORTS": "1"},
    "wrong-destination": {
        "BLOOM_EVAL_SOLANA_DESTINATION": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
    },
    "wrong-source": {
        "BLOOM_EVAL_SOLANA_SOURCE": "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu"
    },
    "fee-over-ceiling": {"BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS": "1"},
}
for name, environment in adversarial.items():
    if run(**environment).returncode == 0:
        raise SystemExit(f"invalid Solana expectation passed: {name}")
SOLCASES

printf '%s\n' 'Solana static checks passed.'
printf '%s\n' 'Harbor eval static tests passed.'
