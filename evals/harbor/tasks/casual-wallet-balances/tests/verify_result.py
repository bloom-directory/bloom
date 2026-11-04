#!/usr/bin/env python3
"""Grade casual-wallet-balances task."""

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
        print("Agent executed 0 commands; read is required to report wallet balances", file=sys.stderr)
        return False
    lower = text.lower()
    if any(q in lower for q in ["which chain", "what chain", "choose a chain"]):
        print("Agent asked unnecessary clarification", file=sys.stderr)
        return False
    if any(
        err in lower
        for err in [
            "cannot determine",
            "could not determine",
            "unable to determine",
            "balance lookup failed",
            "failed to retrieve",
            "i don't have access",
            "i don’t have access",
            "cannot access",
        ]
    ):
        print("Agent failed to determine balances", file=sys.stderr)
        return False

    reader = ProjectionReader(root)
    expected_env = os.environ.get("BLOOM_EVAL_EXPECTED_BALANCES")
    expected_balances = {}
    if expected_env:
        try:
            expected_balances = json.loads(expected_env)
        except Exception:
            pass

    if not expected_balances:
        # Fallback to reading wallets from projection
        try:
            wallets = reader.directories("wallets")
            for w in wallets:
                try:
                    bal = reader.read_text(f"wallets/{w}/0/chains/ethereum/balance").strip()
                    if bal and float(bal) > 0:
                        expected_balances[w] = bal
                except Exception:
                    pass
        except Exception:
            pass

    if not expected_balances:
        # Default fallback
        expected_balances = {"harbor": "0.05", "savings": "1.25"}

    for wallet, amount in expected_balances.items():
        if wallet.lower() not in lower:
            print(f"Agent did not report balance for wallet {wallet}", file=sys.stderr)
            return False
        if amount not in text:
            print(f"Agent did not report balance amount {amount} for wallet {wallet}", file=sys.stderr)
            return False

    return True


if __name__ == "__main__":
    if verify():
        sys.exit(0)
    sys.exit(1)
