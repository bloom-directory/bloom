#!/usr/bin/env python3
"""Summarize Harbor trial summaries against the recorded baseline.

    release-report.py <baselines/README.md> <summaries dir>...

Prints one Markdown table and exits 1 when a smoke did not pass or an agent
that passed a task in the baseline no longer does. Nothing else fails.
"""

import json
import sys
from pathlib import Path


def baseline_passes(readme: Path) -> set[tuple[str, str]]:
    passes = set()
    for line in readme.read_text().splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[2] == "1":
            passes.add((cells[0], cells[1]))
    return passes


def reward(summary: dict) -> float | None:
    rewards = summary.get("rewards") or {}
    if "reward" in rewards:
        return float(rewards["reward"])
    return float(next(iter(rewards.values()))) if rewards else None


def fmt(value, thousands: bool = False) -> str:
    if value is None:
        return "–"
    return f"{int(value):,}" if thousands else str(value)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    baseline = baseline_passes(Path(argv[0]))
    summaries = sorted(
        (json.loads(path.read_text()) for root in argv[1:] for path in sorted(Path(root).glob("*.json"))),
        key=lambda s: (s["agent"], s["run_kind"] != "deterministic-smoke", s["task"]),
    )
    failures = []
    rows = ["| Task | Agent | Reward | Tool calls | Input / cached tokens | Output tokens | Seconds | Note |", "| --- | --- | ---: | ---: | --- | ---: | ---: | --- |"]
    for s in summaries:
        smoke = s["run_kind"] == "deterministic-smoke"
        score = reward(s)
        passed = s["passed"] if smoke else score == 1
        note = s.get("error") or ""
        if smoke:
            note = "smoke, no model" + (f": {note}" if note else "")
            if not passed:
                failures.append(f"{s['agent']} smoke failed: {s.get('error')}")
        elif not passed and (s["task"], s["agent"]) in baseline:
            note = f"REGRESSION: passed in baseline. {note}".strip()
            failures.append(f"{s['task']} with {s['agent']} passed in the baseline and failed now")
        usage = s.get("usage") or {}
        tokens = "–" if usage.get("n_input_tokens") is None else f"{fmt(usage['n_input_tokens'], True)} / {fmt(usage.get('n_cache_tokens') or 0, True)}"
        rows.append(
            f"| {s['task']} | {s['agent']} | {'pass' if smoke and passed else fmt(None if score is None else int(score) if score == int(score) else score)} "
            f"| {fmt(s.get('tool_calls'))} | {tokens} | {fmt(usage.get('n_output_tokens'), True)} "
            f"| {int(s['timings']['total_seconds'])} | {note} |"
        )
    print("## Release evals\n")
    print("\n".join(rows))
    if failures:
        print("\n**Failed:**\n" + "\n".join(f"- {f}" for f in failures))
    elif not summaries:
        print("\nNo summaries found.")
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
