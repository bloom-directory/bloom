#!/usr/bin/env python3
"""Grade casual-sent-history: the recipients of sent transactions."""

import re
import sys
from pathlib import Path

# The harness copies activity.py and projection.py next to this file; in the
# source tree they live in tasks/ and evals/harbor/.
here = Path(__file__).resolve().parent
for p in (here, here.parent.parent, here.parent.parent.parent):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from activity import GIVE_UP, ASKS, get_agent_activity, run
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


ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")


def verify(root=None):
    activity = get_agent_activity()
    final = activity.final
    if not activity.read(r"outbox/sent|activity"):
        return "no successful read of sent transactions"
    if GIVE_UP.search(final) or ASKS.search(final):
        return "final answer gave up or asked a question"
    reader = ProjectionReader(root)
    recipients = set()
    for name in wallets(reader):
        for chain in reader.directories(f"wallets/{name}/0/chains"):
            sent = f"wallets/{name}/0/chains/{chain}/outbox/sent"
            for entry in reader.directories(sent):
                intent = reader.read_json(f"{sent}/{entry}/intent.json")
                recipients.add(str(intent.get("to") or intent["recipient"]).lower())
    if not recipients:
        raise ValueError("no sent transaction is projected")
    reported = {a.lower() for a in ADDRESS.findall(final)}
    if not recipients <= reported:
        return f"final answer omits recipients {sorted(recipients - reported)}"
    if reported - recipients:
        return f"final answer names addresses that were not sent to {sorted(reported - recipients)}"
    return None


if __name__ == "__main__":
    sys.exit(run(verify))
