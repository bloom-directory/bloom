#!/usr/bin/env python3
"""Grade casual-eth-in-main: the main wallet's Ethereum ETH balance."""

import sys
from pathlib import Path

# The harness copies activity.py and projection.py next to this file; in the
# source tree they live in tasks/ and evals/harbor/.
here = Path(__file__).resolve().parent
for p in (here, here.parent.parent, here.parent.parent.parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from activity import GIVE_UP, ASKS, amounts, first_amount, get_agent_activity, mentions, run
from projection import ProjectionReader


def verify(root=None):
    activity = get_agent_activity()
    final = activity.final
    if not activity.read(r"wallets/main/0/(chains/ethereum/balance|holdings)"):
        return "no successful read of main's Ethereum balance"
    if GIVE_UP.search(final) or ASKS.search(final):
        return "final answer gave up or asked a question"
    reader = ProjectionReader(root)
    expected = first_amount(reader.read_text("wallets/main/0/chains/ethereum/balance"))
    if not mentions(final, "main"):
        return "final answer does not name wallet main"
    if expected not in amounts(final):
        return f"final answer does not report main's balance {expected}"
    return None


if __name__ == "__main__":
    sys.exit(run(verify))
