"""Parse agent activity from logs directory or explicit witness file."""

import json
import os
from pathlib import Path


def get_agent_activity(logs_dir: Path | None = None) -> tuple[int, str]:
    traj_env = os.environ.get("BLOOM_EVAL_TRAJECTORY_FILE")
    if traj_env and Path(traj_env).exists():
        try:
            data = json.loads(Path(traj_env).read_text())
            num_commands = 0
            messages = []
            for step in data.get("steps", []):
                if step.get("source") == "agent":
                    num_commands += len(step.get("tool_calls") or [])
                    msg = step.get("message")
                    if msg:
                        messages.append(msg)
            return max(num_commands, 1 if data.get("steps") else 0), " ".join(messages)
        except Exception:
            pass

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
