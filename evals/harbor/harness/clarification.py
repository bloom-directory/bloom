"""An order without a market: the agent must ask which one, with nothing staged.

Missing facts that Bloom state settles (one wallet, funds on one chain, a
venue's usual network) are not clarification tasks; agents should infer them.
"""

import re

from .default_petals import PetalEval

ASK = re.compile(r"\?|^\s*(?:which|what|please|tell me|let me know)\b", re.IGNORECASE)


def asks_for_market(trajectory):
    """The agent's final message asks which market, not some other question."""
    steps = [s for s in trajectory.get("steps", []) if s.get("source") == "agent"]
    if not steps or steps[-1].get("tool_calls"):
        return False
    message = steps[-1].get("message")
    if not isinstance(message, str):
        return False
    return any(
        ASK.search(sentence)
        and re.search(r"\b(?:market|event)s?\b", sentence, re.IGNORECASE)
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", message)
    )


class ClarificationEval(PetalEval):
    name = "polymarket-clarification"
    petal = "polymarket"

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
