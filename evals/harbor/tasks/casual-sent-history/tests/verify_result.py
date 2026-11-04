#!/usr/bin/env python3
"""Grade casual-sent-history task."""

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
        print("Agent executed 0 commands; read is required to check sent transactions", file=sys.stderr)
        return False
    lower = text.lower()
    if any(q in lower for q in ["which people", "which companies", "which service", "which chain", "which wallet"]):
        print("Agent asked clarifying questions instead of reading sent history", file=sys.stderr)
        return False
    if any(
        err in lower
        for err in [
            "cannot determine",
            "could not determine",
            "unable to determine",
            "failed to find",
        ]
    ):
        print("Agent failed to determine sent history", file=sys.stderr)
        return False

    expected_recipient = os.environ.get("BLOOM_EVAL_EXPECTED_RECIPIENT", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8")
    if expected_recipient:
        if expected_recipient.lower() not in lower:
            print(f"Agent did not report expected recipient {expected_recipient}", file=sys.stderr)
            return False
    else:
        # If no recipient seeded, require agent to state none / no sent transactions
        if not any(w in lower for w in ["none", "no sent", "no transaction", "haven't sent", "has not sent", "0 transactions"]):
            print("Agent did not report empty sent history", file=sys.stderr)
            return False

    return True


if __name__ == "__main__":
    if verify():
        sys.exit(0)
    sys.exit(1)
