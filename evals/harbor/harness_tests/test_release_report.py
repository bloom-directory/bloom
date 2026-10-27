"""The release report fails only on smoke failures and baseline regressions."""

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

BASELINE = "| Task | Agent | Reward |\n| --- | --- | ---: |\n| solana-transfer | opencode | 1 |\n| solana-transfer | codex | 0 |\n"


def summary(task, agent, *, smoke=False, passed=True, reward=1):
    return {
        "task": task,
        "agent": agent,
        "run_kind": "deterministic-smoke" if smoke else "Harbor-agent-trial",
        "passed": passed,
        "error": None if passed else "EvalError: boom",
        "rewards": {} if smoke else {"reward": reward},
        "usage": None if smoke else {"n_input_tokens": 1200, "n_cache_tokens": 1000, "n_output_tokens": 30},
        "tool_calls": None if smoke else 7,
        "timings": {"total_seconds": 12.5},
    }


class ReleaseReportTest(unittest.TestCase):
    def run_report(self, *summaries):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text(BASELINE)
            (root / "s").mkdir()
            for n, s in enumerate(summaries):
                (root / "s" / f"{n}.json").write_text(json.dumps(s))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = report.main([str(root / "README.md"), str(root / "s")])
            return code, out.getvalue()

    def test_passing_run_is_a_table(self):
        code, out = self.run_report(summary("solana-transfer", "opencode", smoke=True), summary("solana-transfer", "opencode"))
        self.assertEqual(code, 0)
        self.assertIn("| solana-transfer | opencode | pass |", out)
        self.assertIn("| solana-transfer | opencode | 1 | 7 | 1,200 / 1,000 | 30 | 12 |", out)

    def test_regression_fails(self):
        code, out = self.run_report(summary("solana-transfer", "opencode", passed=False, reward=0))
        self.assertEqual(code, 1)
        self.assertIn("REGRESSION", out)

    def test_baseline_failure_is_not_a_regression(self):
        code, out = self.run_report(summary("solana-transfer", "codex", passed=False, reward=0))
        self.assertEqual(code, 0)
        self.assertNotIn("REGRESSION", out)

    def test_smoke_failure_fails(self):
        code, out = self.run_report(summary("solana-transfer", "codex", smoke=True, passed=False))
        self.assertEqual(code, 1)
        self.assertIn("smoke failed", out)

    def test_no_summaries_fails(self):
        self.assertEqual(self.run_report()[0], 1)


if __name__ == "__main__":
    unittest.main()
