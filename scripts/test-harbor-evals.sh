#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
task="${repo_root}/evals/harbor/tasks/hyperliquid-order-cancel"
verifier="${task}/tests/verify_result.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

wallet="0x1111111111111111111111111111111111111111"
session="bloom-eval-test"
cloid="0x22222222222222222222222222222222"
export BLOOM_EVAL_WALLET="$wallet" BLOOM_EVAL_SESSION_ID="$session" BLOOM_EVAL_CLOID="$cloid"

cat >"$tmp/good.json" <<EOF
{"schema":"bloom.eval.hyperliquid_order_cancel.v1","status":"complete","network":"mainnet","wallet":"$wallet","session_id":"$session","asset":"BTC","asset_id":0,"side":"buy","leverage":1,"post_only":true,"mark_price":"100000","limit_price":"95000","size":"0.00011","notional_usd":"10.45","cloid":"$cloid","order_status":"resting","order_id":123,"cancel_status":"success","matching_open_orders_after_cancel":0,"session_left_active_for_harness_cleanup":true}
EOF
python3 "$verifier" "$tmp/good.json"

python3 - "$tmp/good.json" "$tmp" "$verifier" <<'PY'
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

python3 - <<PY
import tomllib
from pathlib import Path
with Path("${task}/task.toml").open("rb") as handle:
    task = tomllib.load(handle)
assert task["task"]["name"] == "bloom/hyperliquid-order-cancel"
assert task["environment"]["network_mode"] == "public"
assert task["agent"]["timeout_sec"] == 900.0
PY

bash -n "${repo_root}/scripts/evals/run-harbor-hyperliquid.sh"
bash -n "${task}/tests/test.sh"
PYTHONPATH="${repo_root}/evals/harbor" python3 -m unittest discover \
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
