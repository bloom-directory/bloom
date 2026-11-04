#!/usr/bin/env python3
"""Grade casual-supported-chains task."""

import json
import os
import sys
from pathlib import Path

# Add tests directory, tasks directory, or harbor directory to path for activity and projection
tests_dir = Path(__file__).resolve().parent
tasks_dir = tests_dir.parent.parent
harbor_dir = tasks_dir.parent
for p in (tests_dir, tasks_dir, harbor_dir):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from activity import get_agent_activity
from projection import ProjectionReader


def verify(root=None) -> bool:
    commands, text = get_agent_activity()
    if commands == 0:
        print("Agent executed 0 commands; read is required to list supported chains", file=sys.stderr)
        return False
    lower = text.lower()
    if any(q in lower for q in ["do you mean blockchain networks", "what are you trying to do", "which chain"]):
        print("Agent asked clarifying questions instead of listing supported chains", file=sys.stderr)
        return False
    if any(
        err in lower
        for err in [
            "cannot determine",
            "could not determine",
            "unable to determine",
            "failed to list",
        ]
    ):
        print("Agent failed to determine supported chains", file=sys.stderr)
        return False

    reader = ProjectionReader(root)
    configured_env = os.environ.get("BLOOM_EVAL_CONFIGURED_CHAINS")
    configured = []
    if configured_env:
        try:
            configured = json.loads(configured_env)
        except Exception:
            pass

    if not configured:
        try:
            configured = reader.directories("chains")
        except Exception:
            pass

    if not configured:
        configured = ["ethereum", "polygon", "anvil"]

    # All configured chains must be mentioned
    for c in configured:
        if c.lower() not in lower:
            print(f"Agent did not list configured chain {c}", file=sys.stderr)
            return False

    # Unconfigured popular chains should not be falsely claimed
    unconfigured_candidates = [
        "base",
        "arbitrum",
        "optimism",
        "solana",
        "avalanche",
        "bsc",
        "polygon-zkevm",
    ]
    for unconf in unconfigured_candidates:
        if unconf not in configured and unconf in lower:
            print(f"Agent listed unconfigured chain {unconf}", file=sys.stderr)
            return False

    return True


if __name__ == "__main__":
    if verify():
        sys.exit(0)
    sys.exit(1)
