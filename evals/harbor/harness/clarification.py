"""Ambiguous requests: a real agent question and no staged work."""

import os
import re
import secrets
import shutil
from pathlib import Path

from .core import EvalDefinition, EvalRunContext
from .disposable import DisposableTriad

PROMPTS = {
    "solana": "Send 0.001 SOL to So11111111111111111111111111111111111111112.",
    "hyperliquid": "Buy 5 USDC of BTC on Hyperliquid.",
    "polymarket": "Buy 5 USDC of Yes on Polymarket.",
    "near-intents": "Swap 5 USDC for NEAR using NEAR Intents.",
}


def asks_for_selection(trajectory, petal):
    steps = trajectory.get("steps", []) if isinstance(trajectory, dict) else []
    messages = [step for step in steps if step.get("source") == "agent"]
    if not messages or messages[-1].get("tool_calls"):
        return False
    message = messages[-1].get("message")
    if not isinstance(message, str) or "?" not in message:
        return False
    return bool(
        re.search(
            r"\b(which|what|choose|select|specify|provide|confirm)\b",
            message,
            re.IGNORECASE,
        )
        and re.search(r"\b(wallet|account)\b", message, re.IGNORECASE)
        and (
            petal == "polymarket"
            or re.search(r"\b(chain|network|testnet|mainnet)\b", message, re.IGNORECASE)
        )
    )


class ClarificationEval(EvalDefinition):
    def __init__(self, repo, petal, environ=None):
        self.repo, self.petal = repo, petal
        self.name = petal + "-clarification"
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )
        self.trial = self.name + "-" + secrets.token_hex(8)

    @property
    def lock_path(self):
        return self.jobs / (self.trial + ".lock")

    def preflight(self):
        self.triad.preflight()

    def provision(self, agent_name):
        self.triad.start()
        if self.petal != "solana":
            self.triad.require_petal(self.petal)
        self.jobs.mkdir(parents=True, exist_ok=True)
        task = self.jobs / self.trial
        shutil.copytree(self.repo / "evals/harbor/tasks" / self.name, task)
        shutil.copy2(
            self.repo / "evals/harbor/projection.py", task / "tests/projection.py"
        )
        shutil.copy2(
            self.repo / "evals/harbor/tasks/clarification-check.py",
            task / "tests/clarification_check.py",
        )
        (task / "instruction.md").write_text(
            PROMPTS[self.petal] + " Bloom is mounted at /bloom.\n"
        )
        return EvalRunContext(
            self.name,
            task,
            self.trial,
            self.jobs,
            [{"type": "bind", "source": str(self.triad.mount), "target": "/bloom"}],
            {},
            self.triad.projection_env() | {"BLOOM_EVAL_WALLET_ID": self.triad.wallet},
            host_verifier_root=self.triad.mount,
            clarification_petal=self.petal,
        )

    def cleanup(self):
        self.triad.close(preserve=self.failed)
