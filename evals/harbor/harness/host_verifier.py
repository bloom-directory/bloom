"""Grade live public projections on the trusted host through Harbor's API."""

import asyncio
import json
import os
import subprocess
import sys

from harbor.models.verifier.result import VerifierResult
from harbor.verifier.base import BaseVerifier

from .clarification import asks_for_market
from .core import EvalError


class HostProjectionVerifier(BaseVerifier):
    def __init__(self, *, mount_root, clarification=False, **kwargs):
        super().__init__(**kwargs)
        self.mount_root = mount_root
        self.clarification = clarification

    def _check(self):
        env = (
            os.environ
            | self.override_env
            | {
                "BLOOM_EVAL_MOUNT_ROOT": self.mount_root,
                "BLOOM_EVAL_TRAJECTORY_FILE": str(
                    self.trial_paths.agent_dir / "trajectory.json"
                ),
            }
        )
        directory = self.trial_paths.verifier_dir
        directory.mkdir(parents=True, exist_ok=True)
        passed = True
        if self.clarification:
            passed = asks_for_market(
                json.loads(
                    (self.trial_paths.agent_dir / "trajectory.json").read_bytes()
                )
            )
        if passed:
            result = subprocess.run(
                [sys.executable, str(self.task.paths.tests_dir / "verify_result.py")],
                env=env,
                capture_output=True,
                timeout=110,
                check=False,
            )
            (directory / "stdout.txt").write_bytes(result.stdout)
            (directory / "stderr.txt").write_bytes(result.stderr)
            if result.returncode not in (0, 1):
                raise EvalError("public projections unavailable; see verifier stderr")
            passed = result.returncode == 0
        reward = float(passed)
        (directory / "reward.txt").write_text(f"{reward}\n")
        return VerifierResult(rewards={"reward": reward})

    async def verify(self):
        return await asyncio.to_thread(self._check)
