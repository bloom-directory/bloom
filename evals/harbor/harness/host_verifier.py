"""Grade live public projections on the trusted host through Harbor's API."""

import asyncio
import json
import os
import subprocess
import sys

from harbor.models.verifier.result import VerifierResult
from harbor.verifier.base import BaseVerifier

from .clarification import asks_for_selection
from .core import EvalError


class HostProjectionVerifier(BaseVerifier):
    def __init__(self, *, mount_root, clarification_petal=None, **kwargs):
        super().__init__(**kwargs)
        self.mount_root = mount_root
        self.clarification_petal = clarification_petal

    def _check(self):
        env = (
            os.environ | self.override_env | {"BLOOM_EVAL_MOUNT_ROOT": self.mount_root}
        )
        directory = self.trial_paths.verifier_dir
        directory.mkdir(parents=True, exist_ok=True)
        passed = True
        if self.clarification_petal:
            trajectory = json.loads(
                (self.trial_paths.agent_dir / "trajectory.json").read_bytes()
            )
            passed = asks_for_selection(
                trajectory,
                self.clarification_petal,
                json.loads(
                    self.override_env.get("BLOOM_EVAL_CLARIFICATION_CHOICES", "[]")
                ),
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
