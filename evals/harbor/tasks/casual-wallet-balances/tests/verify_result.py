#!/usr/bin/env python3
"""Grade casual-wallet-balances: every wallet's Ethereum ETH balance, each with its own amount."""

import sys
from pathlib import Path

# The harness copies activity.py and projection.py next to this file; in the
# source tree they live in tasks/ and evals/harbor/.
here = Path(__file__).resolve().parent
for p in (here, here.parent.parent, here.parent.parent.parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from activity import GIVE_UP, ASKS, amounts, clauses, first_amount, get_agent_activity, mentions, run
from projection import ProjectionReader


def wallets(reader):
    """Wallet names that have a projected account 0."""
    names = []
    for name in reader.directories("wallets"):
        try:
            reader.read_json(f"wallets/{name}/0/account.json")
        except (FileNotFoundError, NotADirectoryError):
            continue
        names.append(name)
    if not names:
        raise ValueError("no wallet is projected")
    return names


def verify(root=None):
    activity = get_agent_activity()
    final = activity.final
    if not activity.read(r"wallets/[^/\s]+/0/(chains/ethereum/balance|holdings)|wallet list|ls\s+\S*wallets"):
        return "no successful wallet balance read"
    if GIVE_UP.search(final) or ASKS.search(final):
        return "final answer gave up or asked for a chain"
    reader = ProjectionReader(root)
    expected = {
        name: first_amount(reader.read_text(f"wallets/{name}/0/chains/ethereum/balance"))
        for name in wallets(reader)
    }
    for name, amount in expected.items():
        own = [
            c for c in clauses(final)
            if mentions(c, name) and not any(mentions(c, n) for n in expected if n != name)
        ]
        if not own:
            return f"final answer has no clause for wallet {name} alone"
        if not any(amount in amounts(c) for c in own):
            return f"final answer does not attribute {amount} to wallet {name}"
    return None


if __name__ == "__main__":
    sys.exit(run(verify))
