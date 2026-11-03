#!/usr/bin/env python3
"""Grade casual-supported-chains task."""

import json
import os
import sys
from pathlib import Path


def get_agent_activity(logs_dir: Path | None = None) -> tuple[int, str]:
    if logs_dir is None:
        logs_dir = Path(os.environ.get("AGENT_LOGS_DIR", "/logs/agent"))

    num_commands = 0
    messages = []

    traj_path = logs_dir / "trajectory.json"
    if traj_path.exists():
        try:
            data = json.loads(traj_path.read_text())
            for step in data.get("steps", []):
                if step.get("source") == "agent":
                    num_commands += len(step.get("tool_calls") or [])
                    msg = step.get("message")
                    if msg:
                        messages.append(msg)
            return num_commands, " ".join(messages)
        except Exception:
            pass

    codex_path = logs_dir / "codex.txt"
    if codex_path.exists():
        try:
            for line in codex_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if ev.get("type") == "item.completed":
                    item = ev.get("item", {})
                    itype = item.get("type")
                    if itype == "agent_message":
                        messages.append(item.get("text", ""))
                    elif itype in ("command_execution", "mcp_tool_call"):
                        num_commands += 1
            return num_commands, " ".join(messages)
        except Exception:
            pass

    return 0, ""


def verify() -> bool:
    commands, text = get_agent_activity()
    if commands == 0:
        print("Agent executed 0 commands; read is required to list supported chains", file=sys.stderr)
        return False
    lower = text.lower()
    if any(q in lower for q in ["do you mean blockchain networks", "what are you trying to do"]):
        print("Agent asked clarifying questions instead of listing supported chains", file=sys.stderr)
        return False
    if not ("ethereum" in lower and ("arbitrum" in lower or "optimism" in lower or "base" in lower or "polygon" in lower or "solana" in lower)):
        print("Agent did not list supported chains", file=sys.stderr)
        return False
    return True


if __name__ == "__main__":
    if verify():
        sys.exit(0)
    sys.exit(1)
