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

# --- bloom/safe-transfer-fork -------------------------------------------------
#
# Serve deterministic chain responses so the verifier's evidence path runs
# without a fork. Production sets BLOOM_EVAL_EVM_RPC_URL to the trial's own
# disposable chain.
safe_task="${repo_root}/evals/harbor/tasks/safe-transfer-fork"
safe_verifier="${safe_task}/tests/verify_result.py"
safe_tmp="$tmp/safe"
mkdir -p "$safe_tmp"

cat >"$safe_tmp/fake_chain.py" <<'PY'
import json
import os
import pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer

SAFE = "0xd1710d21b67fd9da7495759c707afcbc384b0a55"
RECIPIENT = "0x4000000000000000000000000000000000000000"
OUTER = "0xe1ea0ceb" + "00" * 26 + "df2b"
SAFE_TX_HASH = "0x8cc5033b" + "00" * 26 + "0874"
VALUE = 500000000000000000
BLOCK = 0x18CE2B1
EXECUTION_SUCCESS = (
    "0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e"
)
# execTransaction(RECIPIENT, VALUE, 0x, 0, 0, 0, 0, 0x0, 0x0, <65-byte sig>)
INPUT = (
    "0x6a761202"
    "0000000000000000000000004000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000006f05b59d3b20000"
    "0000000000000000000000000000000000000000000000000000000000000140"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000160"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000041"
    "1111111111111111111111111111111111111111111111111111111111111111"
    "111111111111111111111111111111111111111111111111111111111111111f"
    "0000000000000000000000000000000000000000000000000000000000000000"
)
# Balances chosen so the delta across the receipt block is exactly VALUE, and
# the Safe nonce advances by exactly one.
BALANCES = {hex(BLOCK - 1): 0, hex(BLOCK): VALUE}
NONCES = {hex(BLOCK - 1): 0, hex(BLOCK): 1}


def result(request):
    method = request.get("method")
    params = request.get("params") or []
    if method == "eth_getTransactionReceipt":
        if params[0] != OUTER:
            return None
        return {
            "status": "0x1",
            "to": SAFE,
            "blockNumber": hex(BLOCK),
            "logs": [
                {
                    "address": SAFE,
                    "topics": [EXECUTION_SUCCESS],
                    "data": SAFE_TX_HASH + "00" * 32,
                }
            ],
        }
    if method == "eth_getTransactionByHash":
        return {"input": INPUT} if params[0] == OUTER else None
    if method == "eth_getBalance":
        if params[0].lower() != RECIPIENT:
            return "0x0"
        return hex(BALANCES.get(params[1], 0))
    if method == "eth_call":
        call, block = params[0], params[1]
        if call.get("to", "").lower() != SAFE or call.get("data") != "0xaffed0e0":
            return "0x" + "00" * 32
        return "0x" + f"{NONCES.get(block, 0):064x}"
    return None


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length))
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result(request)}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


server = HTTPServer(("127.0.0.1", 0), Handler)
pathlib.Path(os.environ["FAKE_CHAIN_PORT_FILE"]).write_text(str(server.server_port))
server.serve_forever()
PY

safe_port_file="$safe_tmp/fake-chain.port"
FAKE_CHAIN_PORT_FILE="$safe_port_file" "${python_cmd[@]}" "$safe_tmp/fake_chain.py" &
fake_chain_pid=$!
trap 'kill "$fake_hyperliquid_pid" "$fake_chain_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
for _ in $(seq 1 50); do
  [ -s "$safe_port_file" ] && break
  sleep 0.1
done
[ -s "$safe_port_file" ] || { echo "fake chain server did not start" >&2; exit 1; }

safe_address="0xd1710d21b67fd9da7495759c707afcbc384b0a55"
outer_hash="0xe1ea0ceb$(printf '0%.0s' $(seq 1 52))df2b"
safe_tx_hash="0x8cc5033b$(printf '0%.0s' $(seq 1 52))0874"
export BLOOM_EVAL_EVM_RPC_URL="http://127.0.0.1:$(cat "$safe_port_file")"
export BLOOM_EVAL_CHAIN_ID="1"
export BLOOM_EVAL_WALLET_ID="safeowner"
export BLOOM_EVAL_SAFE_ID="treasury"
export BLOOM_EVAL_SAFE_ADDRESS="$safe_address"
export BLOOM_EVAL_TRANSACTION_ID="payment1"
export BLOOM_EVAL_RECIPIENT="0x4000000000000000000000000000000000000000"
export BLOOM_EVAL_VALUE_WEI="500000000000000000"

cat >"$safe_tmp/good.json" <<EOF
{"schema":"bloom.eval.safe_transfer_fork.v1","status":"complete","chain_id":1,"wallet_id":"safeowner","safe_id":"treasury","safe_address":"$safe_address","transaction_id":"payment1","recipient":"0x4000000000000000000000000000000000000000","value_wei":"500000000000000000","safe_nonce":0,"safe_tx_hash":"$safe_tx_hash","execution_tx_hash":"$outer_hash","phase":"executed"}
EOF
"${python_cmd[@]}" "$safe_verifier" "$safe_tmp/good.json"

"${python_cmd[@]}" - "$safe_tmp/good.json" "$safe_tmp" "$safe_verifier" <<'PY'
import json, os, pathlib, subprocess, sys
source = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = pathlib.Path(sys.argv[2])
verifier = sys.argv[3]
mutations = {
    # The two hashes are the heart of the task: neither may stand in for the
    # other, and neither may name something the chain does not show.
    "swapped-hashes": {
        "safe_tx_hash": source["execution_tx_hash"],
        "execution_tx_hash": source["safe_tx_hash"],
    },
    "same-hash-twice": {"execution_tx_hash": source["safe_tx_hash"]},
    "unknown-outer-hash": {"execution_tx_hash": "0x" + "ab" * 32},
    "wrong-safe-tx-hash": {"safe_tx_hash": "0x" + "cd" * 32},
    # Claiming completion from a state that is only a broadcast.
    "staged-not-reconciled": {"phase": "execution_staged"},
    "not-complete": {"status": "pending"},
    # Claiming a different action than the chain shows.
    "wrong-recipient": {"recipient": "0x5000000000000000000000000000000000000000"},
    "wrong-amount": {"value_wei": "400000000000000000"},
    "wrong-safe": {"safe_address": "0x1000000000000000000000000000000000000000"},
    "wrong-chain": {"chain_id": 31337},
    # The nonce the Safe actually consumed was 0.
    "wrong-nonce": {"safe_nonce": 1},
    # Identity of the objects the harness named.
    "wrong-wallet": {"wallet_id": "someone-else"},
    "wrong-transaction-id": {"transaction_id": "payment2"},
    "extra-field": {"unexpected": True},
}
for name, values in mutations.items():
    report = source | values
    path = root / f"{name}.json"
    path.write_text(json.dumps(report))
    result = subprocess.run([sys.executable, verifier, str(path)], env=os.environ, capture_output=True, text=True)
    if result.returncode == 0:
        raise SystemExit(f"invalid fixture passed: {name}")
for name in ("schema", "phase", "safe_nonce"):
    report = {key: value for key, value in source.items() if key != name}
    path = root / f"missing-{name}.json"
    path.write_text(json.dumps(report))
    result = subprocess.run([sys.executable, verifier, str(path)], env=os.environ, capture_output=True, text=True)
    if result.returncode == 0:
        raise SystemExit(f"report missing {name} passed")
PY

"${python_cmd[@]}" - <<PY
import sys
import tomllib
from pathlib import Path
sys.path.insert(0, str(Path("${repo_root}/evals/harbor")))
from harness.safe_transfer_fork import (
    AGENT_TIMEOUT_SECONDS,
    EVAL_IMAGE,
    REPORT_FIELDS,
    REPORT_SCHEMA,
    TASK_NAME,
)

with Path("${safe_task}/task.toml").open("rb") as handle:
    task = tomllib.load(handle)
assert task["task"]["name"] == TASK_NAME
assert task["environment"]["network_mode"] == "public"
assert task["environment"]["docker_image"] == EVAL_IMAGE
assert task["agent"]["timeout_sec"] == AGENT_TIMEOUT_SECONDS

# The schema and its exact field set live in three places: the module, the
# verifier and the instruction. Drift between them is a silent grading change.
verifier_source = Path("${safe_verifier}").read_text()
instruction = Path("${safe_task}/instruction.md").read_text()
assert f'SCHEMA = "{REPORT_SCHEMA}"' in verifier_source
assert REPORT_SCHEMA in instruction
for field in REPORT_FIELDS:
    assert f'"{field}"' in verifier_source, field
    assert f'"{field}"' in instruction, field
PY

bash -n "${safe_task}/tests/test.sh"
grep -Fq '`bloom vfs`, the `bloom` executable' "${safe_task}/instruction.md"

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
printf '%s\n' 'Harbor eval static tests passed.'
