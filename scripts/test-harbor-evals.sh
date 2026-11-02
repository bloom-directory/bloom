#!/usr/bin/env bash
# Static checks for the Harbor evals. No Docker, Triad or venue is started.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
evals="${repo_root}/evals/harbor"
tmp="$(mktemp -d)"
trap 'rm -r "$tmp"' EXIT

bash -n "${repo_root}/scripts/evals/run-harbor.sh"
for script in "${evals}"/tasks/*/tests/test.sh; do
  bash -n "$script"
done

PYTHONPATH="$evals" uv run --isolated --no-project --python 3.12 --with-requirements "$evals/requirements.txt" python -m unittest \
  discover -s "${evals}/harness_tests" -v

# Every task uses the one digest-pinned agent image, and the harness's Harbor
# extension points load under the exact Harbor version the launcher uses.
TMP_JOB_DIR="$tmp" PYTHONPATH="$evals" EVALS="$evals" \
  uv run --isolated --no-project --python 3.12 --with-requirements "$evals/requirements.txt" python - <<'PY'
import asyncio
import os
import tomllib
from pathlib import Path

from harbor.agents.factory import AgentFactory
from harbor.environments.factory import EnvironmentFactory
from harbor.models.task.task import Task
from harbor.models.trial.config import AgentConfig, EnvironmentConfig, VerifierConfig
from harbor.models.trial.paths import TrialPaths
from harbor.verifier.factory import VerifierFactory

evals = Path(os.environ["EVALS"])
jobs = Path(os.environ["TMP_JOB_DIR"])
images = {
    tomllib.loads(path.read_text())["environment"]["docker_image"]
    for path in evals.glob("tasks/*/task.toml")
}
assert len(images) == 1 and "@sha256:" in next(iter(images)), images

task = Task(evals / "tasks/polymarket-limit-order-proposal")
verifier = VerifierFactory.create_verifier_from_config(
    VerifierConfig(
        import_path="harness.host_verifier:HostProjectionVerifier",
        kwargs={"mount_root": "/tmp/unstarted-test-mount"},
    ),
    task=task,
    trial_paths=TrialPaths(jobs / "verifier"),
    environment=None,
)
assert type(verifier).__name__ == "HostProjectionVerifier"
agent = AgentFactory.create_agent_from_config(
    AgentConfig(
        import_path="harness.image_opencode:ImageOpenCode",
        model_name="deepseek/deepseek-v4-flash",
        kwargs={"version": "1.18.26"},
    ),
    logs_dir=jobs / "agent",
)
assert type(agent).__name__ == "ImageOpenCode"
environment = EnvironmentFactory.create_environment_from_config(
    EnvironmentConfig(import_path="harness.environment:BloomDockerEnvironment"),
    environment_dir=evals / "tasks/polymarket-limit-order-proposal/environment",
    environment_name="unstarted",
    session_id="unstarted",
    trial_paths=TrialPaths(jobs / "environment"),
    task_env_config=task.config.environment,
)
# Ownership repair must never walk the live /bloom mount; these return
# without touching Docker.
asyncio.run(environment._chown_to_host_user("/bloom", recursive=True))
asyncio.run(environment._chown_to_host_user("/bloom/wallets/harbor/policy.json"))
PY
printf '%s\n' 'Harbor eval static tests passed.'
