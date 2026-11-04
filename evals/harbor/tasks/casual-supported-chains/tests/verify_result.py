#!/usr/bin/env python3
"""Grade casual-supported-chains: the configured chains, and only those."""

import re
import sys
from pathlib import Path

# The harness copies activity.py and projection.py next to this file; in the
# source tree they live in tasks/ and evals/harbor/.
here = Path(__file__).resolve().parent
for p in (here, here.parent.parent, here.parent.parent.parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from activity import GIVE_UP, ASKS, get_agent_activity, mentions, run
from projection import ProjectionReader


# Chains an agent might name that this fixture does not configure.
KNOWN = ("ethereum", "polygon", "anvil", "base", "arbitrum", "optimism",
         "solana", "avalanche", "bsc", "gnosis", "linea", "tempo", "hyperliquid")


def verify(root=None):
    activity = get_agent_activity()
    final = activity.final
    if not activity.read(r"(^|[\s/])(bloom/)?(status/)?chains\b"):
        return "no successful read of the chain list"
    if GIVE_UP.search(final) or ASKS.search(final):
        return "final answer gave up or asked a question"
    configured = ProjectionReader(root).directories("chains")
    if not configured:
        raise ValueError("no chain is projected")
    missing = [c for c in configured if not mentions(final, c)]
    if missing:
        return f"final answer omits configured chains {missing}"
    extra = [c for c in KNOWN if c not in configured and mentions(final, c)]
    if extra:
        return f"final answer names unconfigured chains {extra}"
    return None


if __name__ == "__main__":
    sys.exit(run(verify))
