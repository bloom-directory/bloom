"""An order without a market: the agent must ask which one, with nothing staged.

Missing facts that Bloom state settles (one wallet, funds on one chain, a
venue's usual network) are not clarification tasks; agents should infer them.
"""

import json
import os
import re
import secrets
import shutil
from pathlib import Path

from .core import EvalDefinition, EvalRunContext
from .disposable import DisposableTriad

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


class ClarificationEval(EvalDefinition):
    name = "polymarket-clarification"

    def __init__(self, repo, environ=None):
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )
        self.trial = self.name + "-" + secrets.token_hex(8)

    def preflight(self):
        self.triad.preflight()

    def provision(self, agent_name):
        self.triad.start()
        self.triad.require_petal("polymarket")
        owner = self.triad.home / "petals/store/owners/polymarket.json"
        self.lineage = {
            "coverage": "clarification",
            "wallet": self.triad.wallet,
            "package_hash": json.loads(owner.read_bytes())["hash"],
        }
        self.jobs.mkdir(parents=True, exist_ok=True)
        task = self.jobs / self.trial
        shutil.copytree(self.repo / "evals/harbor/tasks" / self.name, task)
        for source, target in (
            ("projection.py", "projection.py"),
            ("tasks/clarification-check.py", "clarification_check.py"),
        ):
            shutil.copy2(self.repo / "evals/harbor" / source, task / "tests" / target)
        return EvalRunContext(
            self.name,
            task,
            self.trial,
            self.jobs,
            [{"type": "bind", "source": str(self.triad.mount), "target": "/bloom"}],
            {},
            self.triad.projection_env() | {"BLOOM_EVAL_WALLET_ID": self.triad.wallet},
            host_verifier_root=self.triad.mount,
            clarification=True,
        )

    def cleanup(self):
        self.triad.close(preserve=self.failed)
