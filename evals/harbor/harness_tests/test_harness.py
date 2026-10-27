from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from harness.core import (
    REASONING_EFFORT_ENV,
    AgentSpec,
    EvalDefinition,
    EvalError,
    EvalEvidence,
    EvalRunContext,
    reasoning_effort,
    run_eval,
)
from harness.disposable import DisposableTriad


class FakeDefinition(EvalDefinition):
    name = "fake"

    def __init__(
        self, root: Path, *, provision_error: BaseException | None = None
    ) -> None:
        self.root = root
        self.provision_error = provision_error
        self.events: list[str] = []

    def preflight(self) -> None:
        self.events.append("preflight")

    def provision(self, agent_name: str) -> EvalRunContext:
        self.events.append(f"provision:{agent_name}")
        if self.provision_error is not None:
            raise self.provision_error
        return EvalRunContext(
            "fake", self.root, "fake-job", self.root / "jobs", [], {}, {}
        )

    def cleanup(self) -> None:
        self.events.append("cleanup")


class HarnessLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.auth = mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test"})
        self.auth.start()

    def tearDown(self) -> None:
        self.auth.stop()
        self.temp.cleanup()

    def passing_result(self) -> SimpleNamespace:
        trial = SimpleNamespace(
            exception_info=None,
            verifier_result=SimpleNamespace(rewards={"reward": 1}),
        )
        return SimpleNamespace(
            stats=SimpleNamespace(n_errored_trials=0, n_cancelled_trials=0),
            trial_results=[trial],
        )

    def test_run_eval_orders_lifecycle_and_cleans_up(self) -> None:
        definition = FakeDefinition(self.root)

        async def runner(_context: EvalRunContext, agent: AgentSpec) -> object:
            definition.events.append(f"harbor:{agent.harbor_name}")
            return self.passing_result()

        timings: dict[str, float] = {}
        result = run_eval(
            definition, "codex", harbor_runner=runner, phase_timings=timings
        )
        self.assertEqual(
            definition.events,
            ["preflight", "provision:codex", "harbor:codex", "cleanup"],
        )
        self.assertEqual(result, self.passing_result())
        self.assertEqual(
            set(timings),
            {
                "preflight_seconds",
                "authority_provisioning_seconds",
                "harbor_seconds",
                "session_cleanup_seconds",
            },
        )

    def test_cleanup_runs_when_provision_fails_after_starting(self) -> None:
        definition = FakeDefinition(
            self.root, provision_error=EvalError("provision failed")
        )

        async def runner(_context: EvalRunContext, _agent: AgentSpec) -> object:
            self.fail("Harbor must not run")

        with self.assertRaisesRegex(EvalError, "provision failed"):
            run_eval(definition, "codex", harbor_runner=runner)
        self.assertEqual(definition.events, ["preflight", "provision:codex", "cleanup"])

    def test_cleanup_failure_is_not_hidden_by_run_failure(self) -> None:
        definition = FakeDefinition(self.root)
        definition.cleanup = mock.Mock(side_effect=EvalError("cleanup failed"))

        async def runner(_context: EvalRunContext, _agent: AgentSpec) -> object:
            raise EvalError("run failed")

        with self.assertRaisesRegex(EvalError, "run failed.*cleanup also failed"):
            run_eval(definition, "codex", harbor_runner=runner)

    def test_zero_reward_retains_result_with_successful_or_failed_cleanup(self) -> None:
        for cleanup_fails in (False, True):
            with self.subTest(cleanup_fails=cleanup_fails):
                definition = FakeDefinition(self.root)
                if cleanup_fails:
                    definition.cleanup = mock.Mock(side_effect=EvalError("residual order"))
                result = self.passing_result()
                result.trial_results[0].verifier_result.rewards = {"reward": 0}
                async def runner(_context, _agent, result=result):
                    return result
                evidence = EvalEvidence()
                with self.assertRaisesRegex(EvalError, "passing reward"):
                    run_eval(definition, "codex", harbor_runner=runner, evidence=evidence)
                self.assertIs(evidence.result, result)
                self.assertEqual(evidence.cleanup_succeeded, not cleanup_fails)
                self.assertEqual(evidence.cleanup_error, "residual order" if cleanup_fails else None)


class ReasoningEffortTests(unittest.TestCase):
    def test_unset_keeps_harbor_default(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(REASONING_EFFORT_ENV, None)
            self.assertIsNone(reasoning_effort("codex"))
            self.assertIsNone(reasoning_effort("claude"))

    def test_codex_accepts_known_efforts(self) -> None:
        for effort in ("low", "medium", "high", "xhigh"):
            with mock.patch.dict(os.environ, {REASONING_EFFORT_ENV: effort}):
                self.assertEqual(reasoning_effort("codex"), effort)

    def test_unknown_effort_and_other_agents_are_refused(self) -> None:
        with (
            mock.patch.dict(os.environ, {REASONING_EFFORT_ENV: "max"}),
            self.assertRaisesRegex(EvalError, "must be one of"),
        ):
            reasoning_effort("codex")
        with (
            mock.patch.dict(os.environ, {REASONING_EFFORT_ENV: "medium"}),
            self.assertRaisesRegex(EvalError, "only to the codex agent"),
        ):
            reasoning_effort("claude")


class TeardownTests(unittest.TestCase):
    def test_stuck_launcher_and_child_are_killed_and_root_kept(self):
        # A launcher that ignores SIGTERM while waiting on a child.
        launcher = subprocess.Popen(
            ["bash", "-c", "trap '' TERM; sleep 300 & echo $!; wait"],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        child = int(launcher.stdout.readline())
        launcher.stdout.close()
        with tempfile.TemporaryDirectory() as directory:
            triad = DisposableTriad(Path(directory))
            triad.stop_timeout = 0.5
            triad.root = Path(directory) / "root"
            triad.root.mkdir()
            triad.launcher = launcher
            triad.mount_lock = open(Path(directory) / "lock", "w")
            with self.assertRaisesRegex(EvalError, "ignored SIGTERM.*preserving"):
                triad.close()
            self.assertIsNotNone(launcher.poll())
            self.assertIsNone(triad.mount_lock)
            self.assertTrue(triad.root.is_dir())
        for _ in range(50):
            if not Path(f"/proc/{child}").exists():
                break
            time.sleep(0.1)
        self.assertFalse(Path(f"/proc/{child}").exists(), "child survived teardown")


if __name__ == "__main__":
    unittest.main()
