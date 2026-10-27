"""The release report fails only on smoke failures, auth errors and regressions."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[3] / "scripts/evals/release-report.py"
SPEC = importlib.util.spec_from_file_location("release_report", SCRIPT)
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)

BASELINE = (
    "| Task | Agent | Reward | Tool calls | Input / cached tokens | Output tokens | Seconds |\n"
    "| --- | --- | ---: | ---: | --- | ---: | ---: |\n"
    "| solana-transfer | opencode | 1 | 19 | 486,150 / 463,104 | 2,681 | 110 |\n"
    "| solana-transfer | codex | 0 | 6 | 157,247 / 135,424 | 1,594 | 78 |\n"
)


def summary(task, agent, *, smoke=False, passed=True, reward=1, error=None, trial=None):
    return {
        "task": task,
        "agent": agent,
        "run_kind": "deterministic-smoke" if smoke else "Harbor-agent-trial",
        "passed": passed,
        "error": error if error else None if passed else "EvalError: boom",
        "rewards": {} if smoke else {"reward": reward},
        "usage": None if smoke else {"n_input_tokens": 1200, "n_cache_tokens": 1000, "n_output_tokens": 30},
        "tool_calls": None if smoke else 17,
        "timings": {"total_seconds": 12.5},
        "trial_uri": f"file:///runner/harbor-jobs/{trial}" if trial else None,
    }


class ReleaseReportTest(unittest.TestCase):
    def run_report(self, *summaries, trajectory=None, flags=()):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(BASELINE)
            (root / "jobs/summaries").mkdir(parents=True)
            for n, s in enumerate(summaries):
                (root / "jobs/summaries" / f"{n}.json").write_text(json.dumps(s))
            if trajectory:
                name, steps = trajectory
                (root / "jobs" / name / "agent").mkdir(parents=True)
                (root / "jobs" / name / "agent/trajectory.json").write_text(json.dumps({"steps": steps}))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = report.main([*flags, str(root / "README.md"), str(root / "jobs/summaries")])
            return code, out.getvalue()

    def test_passing_run_leads_with_the_verdict_and_baseline_deltas(self):
        code, out = self.run_report(summary("solana-transfer", "opencode", smoke=True), summary("solana-transfer", "opencode"))
        self.assertEqual(code, 0)
        self.assertIn("- **opencode**: smoke pass · 1/1 tasks (baseline 1/1)", out)
        self.assertIn("| solana-transfer | opencode | pass |", out)
        self.assertIn("| solana-transfer | opencode | 1 | 17 (19) | 1,200 / 1,000 | 30 | 12 (110) |", out)
        self.assertNotIn("Failed", out)

    def test_regression_fails_and_quotes_the_agent(self):
        code, out = self.run_report(
            summary("solana-transfer", "opencode", passed=False, reward=0, trial="t1"),
            trajectory=("t1", [{"source": "user", "message": "do it"}, {"source": "agent", "message": "I could  not find\nthe funds | sorry"}]),
        )
        self.assertEqual(code, 1)
        self.assertIn("REGRESSION", out)
        self.assertIn("Agent: “I could not find the funds \\| sorry”", out)
        self.assertIn("- solana-transfer with opencode passed in the baseline and failed now", out)

    def test_retry_keeps_the_passing_attempt(self):
        code, out = self.run_report(
            summary("solana-transfer", "opencode", passed=False, reward=0),
            summary("solana-transfer", "opencode"),
        )
        self.assertEqual(code, 0)
        self.assertIn("passed on retry", out)
        self.assertNotIn("REGRESSION", out)

    def test_two_failures_is_one_regression(self):
        code, out = self.run_report(
            summary("solana-transfer", "opencode", passed=False, reward=0),
            summary("solana-transfer", "opencode", passed=False, reward=0),
        )
        self.assertEqual(code, 1)
        self.assertIn("REGRESSION, passed in baseline. failed twice", out)
        self.assertEqual(out.count("passed in the baseline and failed now"), 1)

    def test_baseline_failure_is_not_a_regression(self):
        code, out = self.run_report(summary("solana-transfer", "codex", passed=False, reward=0))
        self.assertEqual(code, 0)
        self.assertNotIn("REGRESSION", out)
        self.assertIn("- **codex**: no smoke · 0/1 tasks (baseline 0/1)", out)

    def test_auth_error_is_a_config_error_not_a_regression(self):
        code, out = self.run_report(summary("solana-transfer", "opencode", passed=False, reward=None, error="EvalError: Codex auth is missing"))
        self.assertEqual(code, 1)
        self.assertNotIn("REGRESSION", out)
        self.assertIn("config error: EvalError: Codex auth is missing", out)

    def test_agent_without_baseline_rows_says_so(self):
        code, out = self.run_report(summary("solana-transfer", "claude-opus", passed=False, reward=0))
        self.assertEqual(code, 0)
        self.assertIn("- **claude-opus**: no smoke · 0/1 tasks (no baseline)", out)

    def test_smoke_failure_fails(self):
        code, out = self.run_report(summary("solana-transfer", "codex", smoke=True, passed=False))
        self.assertEqual(code, 1)
        self.assertIn("smoke FAILED", out)

    def test_cleanup_failure_with_full_reward_fails(self):
        s = summary("solana-transfer", "opencode")
        s["passed"], s["error"] = False, "EvalError: cleanup failed"
        code, out = self.run_report(s)
        self.assertEqual(code, 1)
        self.assertIn("REGRESSION, passed in baseline. failed: EvalError: cleanup failed", out)

    def test_missing_expected_cell_fails(self):
        flags = ("--agents", "opencode", "--tasks", "solana-transfer polymarket-clarification")
        code, out = self.run_report(summary("solana-transfer", "opencode", smoke=True), summary("solana-transfer", "opencode"), flags=flags)
        self.assertEqual(code, 1)
        self.assertIn("| polymarket-clarification | opencode | – | – | – | – | 0 | MISSING: no summary", out)
        self.assertIn("- polymarket-clarification with opencode: no summary", out)

    def test_smoke_without_trials_fails(self):
        flags = ("--agents", "codex", "--tasks", "solana-transfer")
        code, out = self.run_report(summary("solana-transfer", "codex", smoke=True), flags=flags)
        self.assertEqual(code, 1)
        self.assertIn("- **codex**: smoke pass · 0/1 tasks", out)
        self.assertIn("- solana-transfer with codex: no summary", out)

    def test_missing_smoke_fails(self):
        code, out = self.run_report(summary("solana-transfer", "codex"), flags=("--agents", "codex", "--tasks", "solana-transfer"))
        self.assertEqual(code, 1)
        self.assertIn("- codex: no smoke summary", out)

    def test_workflow_matrix_matches_the_harness(self):
        from harness.__main__ import AGENTS, DEFINITIONS

        workflow = (SCRIPT.parents[2] / ".github/workflows/release-evals.yml").read_text()
        tasks_line = next(line for line in workflow.splitlines() if line.startswith("  TASKS:"))
        self.assertEqual(set(tasks_line.split(":", 1)[1].split()), set(DEFINITIONS))
        allowlist = next(line for line in workflow.splitlines() if "IN(" in line)
        for agent in AGENTS:
            self.assertIn(f'"{agent}"', allowlist)

    def test_no_summaries_fails(self):
        self.assertEqual(self.run_report()[0], 1)


if __name__ == "__main__":
    unittest.main()
