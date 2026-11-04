#!/usr/bin/env python3
"""Grade casual-anvil-status: whether the anvil chain is connected."""

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


OFFLINE = re.compile(
    r"\b(offline|not connected|disconnected|down|unreachable|not reachable|not running|not responding)\b",
    re.IGNORECASE,
)
ONLINE = re.compile(r"\b(online|connected|up|running|reachable|responding)\b", re.IGNORECASE)


def verify(root=None):
    activity = get_agent_activity()
    final = activity.final
    if not activity.read(r"status/chains/anvil|chains/anvil"):
        return "no successful read of anvil's status"
    if GIVE_UP.search(final) or ASKS.search(final):
        return "final answer gave up or asked a question"
    connected = ProjectionReader(root).read_text("status/chains/anvil/connected").strip()
    if connected not in ("true", "false"):
        raise ValueError(f"unexpected anvil connected value {connected!r}")
    says_offline = OFFLINE.search(final) is not None
    says_online = ONLINE.search(OFFLINE.sub(" ", final)) is not None
    if connected == "false" and (not says_offline or says_online):
        return "final answer does not say anvil is offline"
    if connected == "true" and (says_offline or not says_online):
        return "final answer does not say anvil is online"
    return None


if __name__ == "__main__":
    sys.exit(run(verify))
