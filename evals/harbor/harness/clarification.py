"""Ambiguous requests: a real agent question and no staged work."""

import json
import os
import re
import secrets
import shutil
from pathlib import Path

from .core import EvalDefinition, EvalRunContext
from .disposable import DisposableTriad

PROMPTS = {
    "solana": "Send 0.001 SOL to 3p2cqDBH9SVdyDFVcXnEBXHYCcrC3JBSjmZAjTrWyu66.",
    "hyperliquid": "Buy 11 USDC of BTC on Hyperliquid.",
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
    requested = []
    network_choice = False
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", message):
        if "?" not in sentence:
            continue
        network_choice |= bool(
            re.search(r"\bmainnet\b", sentence, re.IGNORECASE)
            and re.search(r"\btestnet\b", sentence, re.IGNORECASE)
        )
        for ask in re.finditer(
            r"\b(which|what|choose|select|specify|provide|confirm)\b",
            sentence,
            re.IGNORECASE,
        ):
            phrase = re.sub(
                r"^\s+(is|are)\s+", " ", sentence[ask.end() :], flags=re.IGNORECASE
            )
            # Keep the requested noun phrase, not a later clause naming a
            # default account/network: "Which market should I buy using ...?"
            requested.append(
                re.split(
                    r"\b(should|would|shall|do|does|can|could|will|is|are|use|uses|using)\b",
                    phrase,
                    maxsplit=1,
                    flags=re.IGNORECASE,
                )[0]
            )
    subjects = " ".join(requested)
    return bool(re.search(r"\b(wallet|account)\b", subjects, re.IGNORECASE)) and (
        petal == "polymarket"
        or network_choice
        or bool(re.search(r"\b(chain|network)\b", subjects, re.IGNORECASE))
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
        self.lineage = {
            "coverage": "clarification",
            "petal": self.petal,
            "wallet": self.triad.wallet,
            "account": 0,
        }
        if self.petal != "solana":
            owner = self.triad.home / "petals/store/owners" / f"{self.petal}.json"
            self.lineage["package_hash"] = json.loads(owner.read_bytes())["hash"]
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
