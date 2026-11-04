#!/usr/bin/env python3
"""Grade casual-anvil-status task."""

import json
import os
import socket
import sys
from pathlib import Path

# Add tests directory, tasks directory, or harbor directory to path for activity
tests_dir = Path(__file__).resolve().parent
tasks_dir = tests_dir.parent.parent
harbor_dir = tasks_dir.parent
for p in (tests_dir, tasks_dir, harbor_dir):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from activity import get_agent_activity


def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def verify(root=None) -> bool:
    commands, text = get_agent_activity()
    if commands == 0:
        print("Agent executed 0 commands; read is required to check anvil status", file=sys.stderr)
        return False
    lower = text.lower()
    if "python web-app" in lower or "anvil project" in lower:
        print("Agent asked irrelevant questions instead of checking anvil status", file=sys.stderr)
        return False
    if any(
        err in lower
        for err in [
            "cannot determine",
            "could not determine",
            "unable to determine",
            "cannot check",
        ]
    ):
        print("Agent failed to determine anvil status", file=sys.stderr)
        return False

    port_str = os.environ.get("BLOOM_EVAL_ANVIL_PORT")
    port = int(port_str) if port_str else None
    online = is_port_open(port) if port else False

    if online:
        if not any(w in lower for w in ["online", "connected", "up", "running", "listening"]):
            print("Agent did not report anvil as online/connected", file=sys.stderr)
            return False
    else:
        if not any(w in lower for w in ["offline", "not connected", "down", "disconnected", "unreachable", "false", "closed", "not running"]):
            print("Agent did not report anvil as offline/disconnected", file=sys.stderr)
            return False

    return True


if __name__ == "__main__":
    if verify():
        sys.exit(0)
    sys.exit(1)
