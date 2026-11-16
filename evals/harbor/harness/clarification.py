"""An order without a market: the agent must ask which one, with nothing staged.

Missing facts that Bloom state settles (one wallet, funds on one chain, a
venue's usual network) are not clarification tasks; agents should infer them.
"""

import re

from .default_petals import PetalEval

# "Which market", "what Polymarket question", "which of the markets", or a request
# to name the market. Words between may not be prepositions or verbs, so
# "which wallet should I use for this market" does not count.
MARKET = r"(?:markets?|events?|questions?)\b"
FILLER = r"(?:(?!(?:for|in|on|of|to|with|should|do|does|is|are|would|will|can)\b)\w+\s+){0,2}"
ASKS_FOR_MARKET = re.compile(
    rf"\b(?:which|what)\s+(?:of\s+(?:the|these|those)\s+)?{FILLER}{MARKET}"
    rf"|\b(?:tell me|let me know|specify|name|share|send|provide|confirm)\b[^.?!]{{0,30}}?"
    rf"\b(?:the|which|what)\s+{FILLER}{MARKET}",
    re.IGNORECASE,
)


def asks_for_market(trajectory):
    """The agent's final message asks which market, not some other question."""
    steps = [s for s in trajectory.get("steps", []) if s.get("source") == "agent"]
    if not steps or steps[-1].get("tool_calls"):
        return False
    message = steps[-1].get("message")
    return isinstance(message, str) and ASKS_FOR_MARKET.search(message) is not None


class ClarificationEval(PetalEval):
    name = "polymarket-clarification"
    petal = "polymarket"
    coverage = "clarification"

    def provision(self, agent_name):
        package = self.start()
        self.lineage = {
            "coverage": "clarification",
            "wallet": self.triad.wallet,
            "package_hash": package,
        }
        return self.context(
            self.task("tasks/clarification-check.py"),
            None,
            {"BLOOM_EVAL_WALLET_ID": self.triad.wallet},
            clarification=True,
        )
