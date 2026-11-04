#!/usr/bin/env python3
"""Grade casual-eth-in-main task."""

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
        print(
            "Agent executed 0 commands; read is required to report balance",
            file=sys.stderr,
        )
        return False
    lower = text.lower()
    if any(
        q in lower
        for q in [
            "which address",
            "what address",
            "which ethereum address",
            "which chain",
        ]
    ):
        print("Agent asked unnecessary clarification", file=sys.stderr)
        return False
    if any(
        err in lower
        for err in [
            "cannot determine",
            "could not determine",
            "unable to determine",
            "cannot find",
        ]
    ):
        print("Agent failed to determine balance", file=sys.stderr)
        return False

    reader = ProjectionReader(root)
    wallet = os.environ.get("BLOOM_EVAL_WALLET", "main")
    chain = os.environ.get("BLOOM_EVAL_CHAIN", "ethereum")
    expected_amount = os.environ.get("BLOOM_EVAL_EXPECTED_BALANCE", "2.5")

    try:
        balance_raw = reader.read_text(
            f"wallets/{wallet}/0/chains/{chain}/balance"
        ).strip()
    except Exception:
        balance_raw = ""

    if wallet not in lower:
        print(f"Agent did not mention wallet {wallet}", file=sys.stderr)
        return False
    if chain not in lower and "eth" not in lower:
        print(f"Agent did not mention chain {chain}", file=sys.stderr)
        return False
    if expected_amount not in text and (not balance_raw or balance_raw not in text) and "0.05" not in text:
        print(
            f"Agent did not report expected balance {expected_amount}", file=sys.stderr
        )
        return False
    return True


if __name__ == "__main__":
    if verify():
        sys.exit(0)
    sys.exit(1)
