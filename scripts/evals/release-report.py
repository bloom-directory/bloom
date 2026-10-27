#!/usr/bin/env python3
"""Summarize Harbor trial summaries against the recorded baseline.

    release-report.py <baselines/README.md> <summaries dir>...

Prints a verdict per agent, then every trial in a collapsed table with the
baseline's number in parentheses. A cell run more than once keeps its best
attempt. Exits 1 when a smoke did not pass, an agent could not authenticate,
or an agent that passed a task in the baseline no longer does. Nothing else
fails. RUN_URL, when set, links the artifacts.
"""

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

AUTH = "auth is missing"


def baseline(readme: Path) -> dict[tuple[str, str], dict]:
    cells = {}
    for line in readme.read_text().splitlines():
        c = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(c) >= 7 and c[2] in ("0", "1"):
            cells[(c[0], c[1])] = {"passed": c[2] == "1", "tool_calls": c[3], "seconds": c[6]}
    return cells


def reward(s: dict) -> float | None:
    r = s.get("rewards") or {}
    value = r.get("reward") if "reward" in r else next(iter(r.values()), None)
    return None if value is None else float(value)


def passed(s: dict) -> bool:
    return bool(s["passed"]) if s["run_kind"] == "deterministic-smoke" else reward(s) == 1


def last_agent_message(s: dict, root: Path) -> str:
    uri = s.get("trial_uri")
    if not uri:
        return ""
    name = Path(unquote(urlparse(uri).path)).name
    for trajectory in root.rglob(f"{name}/agent/trajectory.json"):
        try:
            steps = json.loads(trajectory.read_bytes())["steps"]
            text = next((x.get("message") for x in reversed(steps) if x.get("source") == "agent" and x.get("message")), "")
            text = re.sub(r"\s+", " ", text).replace("|", "\\|").strip()
            return text if len(text) <= 160 else text[:157] + "..."
        except (OSError, ValueError, KeyError, TypeError):
            return ""
    return ""


def num(value, base=None, thousands=False) -> str:
    if value is None:
        return "–"
    text = f"{int(value):,}" if thousands else str(value)
    return f"{text} ({base})" if base not in (None, "", text) else text


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    base = baseline(Path(argv[0]))
    cells: dict[tuple, list] = {}
    for root in argv[1:]:
        for path in sorted(Path(root).glob("*.json")):
            s = json.loads(path.read_text())
            s["_root"] = Path(root).parent
            cells.setdefault((s["agent"], s["run_kind"] != "deterministic-smoke", s["task"]), []).append(s)
    verdicts, failures, rows = {}, [], []
    for (agent, is_trial, task), attempts in sorted(cells.items()):
        s = next((a for a in attempts if passed(a)), attempts[-1])
        ok = passed(s)
        v = verdicts.setdefault(agent, {"smoke": None, "passed": 0, "tasks": 0, "base": 0, "config": None})
        note = ""
        if not is_trial:
            v["smoke"] = ok
            note = "smoke, no model" + ("" if ok else f": {s.get('error')}")
            if not ok:
                failures.append(f"{agent} smoke failed: {s.get('error')}")
        else:
            v["tasks"] += 1
            v["passed"] += ok
            v["base"] += base.get((task, agent), {}).get("passed", False)
            error = s.get("error") or ""
            if AUTH in error:
                v["config"] = error
                note = error
            elif ok:
                note = "passed on retry" if len(attempts) > 1 else ""
            else:
                note = ("failed twice" if len(attempts) > 1 else "failed") + (f": {error}" if error else "")
                if base.get((task, agent), {}).get("passed"):
                    note = "REGRESSION, passed in baseline. " + note
                    failures.append(f"{task} with {agent} passed in the baseline and failed now")
            message = last_agent_message(s, s["_root"])
            if message:
                note = f"{note} Agent: “{message}”".strip()
        b = base.get((task, agent), {})
        usage = s.get("usage") or {}
        tokens = "–" if usage.get("n_input_tokens") is None else f"{num(usage['n_input_tokens'], thousands=True)} / {num(usage.get('n_cache_tokens') or 0, thousands=True)}"
        score = "pass" if not is_trial and ok else num(None if reward(s) is None else int(reward(s)) if reward(s) == int(reward(s)) else reward(s))
        rows.append(
            f"| {task} | {agent} | {score} | {num(s.get('tool_calls'), b.get('tool_calls') if is_trial else None)} | {tokens} "
            f"| {num(usage.get('n_output_tokens'), thousands=True)} | {num(int(s['timings']['total_seconds']), b.get('seconds') if is_trial else None)} | {note} |"
        )
    print("## Release evals\n")
    for agent, v in verdicts.items():
        smoke = "smoke pass" if v["smoke"] else "smoke FAILED" if v["smoke"] is False else "no smoke"
        line = f"- **{agent}**: {smoke} · {v['passed']}/{v['tasks']} tasks (baseline {v['base']}/{v['tasks']})"
        if v["config"]:
            line += f" · config error: {v['config']}"
            failures.append(f"{agent} could not authenticate: {v['config']}")
        print(line)
    if failures:
        print("\n**Failed:**\n" + "\n".join(f"- {f}" for f in dict.fromkeys(failures)))
    if os.environ.get("RUN_URL"):
        print(f"\nTrajectories and service logs: {os.environ['RUN_URL']}")
    if not rows:
        print("\nNo summaries found.")
        return 1
    print("\n<details><summary>Every trial, baseline in parentheses</summary>\n")
    print("| Task | Agent | Reward | Tool calls | Input / cached tokens | Output tokens | Seconds | Note |")
    print("| --- | --- | ---: | ---: | --- | ---: | ---: | --- |")
    print("\n".join(rows) + "\n\n</details>")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
