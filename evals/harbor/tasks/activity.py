"""Agent activity and shared checks for the casual read verifiers.

Activity comes from the agent's trajectory (ATIF `trajectory.json`, the smoke
witness in `BLOOM_EVAL_TRAJECTORY_FILE`) or Codex's JSON event log. Verifiers
grade only the final agent message and count only real tool calls.
"""

import json
import os
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path

FAILED_OUTPUT = re.compile(
    r"no such file|not found|error|refused|permission denied|unavailable",
    re.IGNORECASE,
)


@dataclass
class Command:
    text: str
    output: str | None = None
    exit_code: int | None = None

    def ok(self) -> bool:
        if self.exit_code is not None:
            return self.exit_code == 0
        return self.output is None or FAILED_OUTPUT.search(self.output) is None


@dataclass
class Activity:
    commands: list[Command] = field(default_factory=list)
    final: str = ""

    def read(self, pattern: str) -> bool:
        """True when a successful command touched a path matching `pattern`."""
        path = re.compile(pattern)
        return any(c.ok() and path.search(c.text) for c in self.commands)


def _command_text(arguments) -> str:
    if isinstance(arguments, dict):
        return str(arguments.get("command") or arguments.get("cmd") or json.dumps(arguments))
    return str(arguments or "")


def _from_trajectory(data: dict) -> Activity:
    activity = Activity()
    for step in data.get("steps", []):
        if step.get("source") != "agent":
            continue
        results = {
            r.get("source_call_id"): r.get("content")
            for r in (step.get("observation") or {}).get("results", [])
        }
        for call in step.get("tool_calls") or []:
            output = results.get(call.get("tool_call_id"))
            activity.commands.append(
                Command(_command_text(call.get("arguments")), None if output is None else str(output))
            )
        if step.get("message"):
            activity.final = step["message"]
    return activity


def _from_codex(text: str) -> Activity:
    activity = Activity()
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") != "item.completed":
            continue
        item = event.get("item", {})
        if item.get("type") == "agent_message":
            activity.final = item.get("text", "")
        elif item.get("type") == "command_execution":
            activity.commands.append(
                Command(item.get("command", ""), item.get("aggregated_output"), item.get("exit_code"))
            )
        elif item.get("type") == "mcp_tool_call":
            activity.commands.append(Command(json.dumps(item.get("arguments"))))
    return activity


def get_agent_activity(logs_dir: Path | None = None) -> Activity:
    witness = os.environ.get("BLOOM_EVAL_TRAJECTORY_FILE")
    if witness and Path(witness).exists():
        return _from_trajectory(json.loads(Path(witness).read_text()))
    logs_dir = logs_dir or Path(os.environ.get("AGENT_LOGS_DIR", "/logs/agent"))
    if (logs_dir / "trajectory.json").exists():
        return _from_trajectory(json.loads((logs_dir / "trajectory.json").read_text()))
    if (logs_dir / "codex.txt").exists():
        return _from_codex((logs_dir / "codex.txt").read_text())
    return Activity()


NUMBER = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w.])")
HEX = re.compile(r"0x[0-9a-fA-F]+")


def amounts(text: str) -> list[Decimal]:
    """Decimal numbers in `text`, ignoring hex strings such as addresses."""
    found = []
    for raw in NUMBER.findall(HEX.sub(" ", text.replace(",", ""))):
        try:
            found.append(Decimal(raw))
        except InvalidOperation:
            pass
    return found


def first_amount(text: str) -> Decimal:
    found = amounts(text)
    if not found:
        raise ValueError(f"no amount in {text!r}")
    return found[0]


def clauses(text: str) -> list[str]:
    """Split an answer into clauses so each amount stays with its own subject."""
    return [c for c in re.split(r"[;\n|•]|,\s|\.\s|\band\b", text) if c.strip()]


def mentions(text: str, word: str) -> bool:
    return re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE) is not None


GIVE_UP = re.compile(
    r"cannot determine|could not determine|unable to determine|can't determine"
    r"|cannot access|can't access|don['’]t have access|failed to (?:retrieve|find|list)",
    re.IGNORECASE,
)

# A question Bloom state can answer: one wallet, the funded chains, the network.
ASKS = re.compile(
    r"\b(which|what) (wallet|address|account|chain|network)s?\b[^.!\n]*\?", re.IGNORECASE
)


def run(verify) -> int:
    """Exit 0 on pass, 1 on a wrong answer, 2 when trusted truth is unreadable."""
    import sys

    try:
        problem = verify()
    except OSError as error:
        print(f"projection unavailable: {error}", file=sys.stderr)
        return 2
    except ValueError as error:
        print(f"fixture invalid: {error}", file=sys.stderr)
        return 2
    if problem:
        print(problem, file=sys.stderr)
        return 1
    return 0
