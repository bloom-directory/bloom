"""Ambiguous requests: an actual request for the missing fact, with no work staged."""

import json
import os
import re
import secrets
import shutil
from pathlib import Path

from .core import EvalDefinition, EvalRunContext
from .disposable import DisposableTriad

PROMPTS = {
    "solana": "Send 1 USDC to 0x1234567890123456789012345678901234567890.",
    "hyperliquid": "Buy 11 USDC of BTC perpetuals on Hyperliquid.",
    "polymarket": "Buy 5 USDC of Yes on Polymarket.",
    "near-intents": "Swap 5 USDC for USDC on Arbitrum using NEAR Intents, sending the output to {recipient}.",
}

MISSING_FACT_WORDS = {
    "solana": {"chain", "network"},
    "hyperliquid": {"network", "environment", "mainnet", "testnet"},
    "polymarket": {"market", "event"},
    "near-intents": {"chain", "network"},
}


def asks_for_selection(trajectory, petal, choices=()):
    steps = trajectory.get("steps", []) if isinstance(trajectory, dict) else []
    messages = [step for step in steps if step.get("source") == "agent"]
    if not messages or messages[-1].get("tool_calls"):
        return False
    message = messages[-1].get("message")
    if not isinstance(message, str):
        return False
    words = MISSING_FACT_WORDS.get(petal, set())
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", message):
        if petal == "hyperliquid" and re.fullmatch(
            r"\s*(?:(?:do you (?:mean|want|prefer)|should I use|would you like|is it)\s+)?"
            r"(?:Hyperliquid\s+)?(?:mainnet or testnet|testnet or mainnet)\s*\??\s*",
            sentence,
            re.IGNORECASE,
        ):
            return True
        imperative = re.search(
            r"(?:^|\band\s+)(?:please\s+)?(?:choose|select|specify|provide)\b"
            r"|^\s*(?:please\s+tell|I\s+need|which\b|what\b)",
            sentence,
            re.IGNORECASE,
        )
        if "?" not in sentence and (
            not imperative
            or re.search(
                r"\b(?:I|we)\s+(?:will|shall|would|can|could|selected|chose)\b",
                sentence[: imperative.end()],
                re.IGNORECASE,
            )
        ):
            continue
        for ask in re.finditer(
            r"\b(which|what|choose|select|specify|provide)\b",
            sentence,
            re.IGNORECASE,
        ):
            phrase = re.sub(
                r"^\s+(is|are)\s+", " ", sentence[ask.end() :], flags=re.IGNORECASE
            )
            # Match the fact being requested, not an assumed default in a
            # later clause: "Which recipient should I use on Ethereum?"
            subject = re.split(
                r"\b(should|would|shall|do|does|can|could|will|is|are|use|uses|using|for|on|in|with|from)\b",
                phrase,
                maxsplit=1,
                flags=re.IGNORECASE,
            )[0].lower()
            if (
                petal == "hyperliquid"
                and re.search(r"\b(wallet|account)\b", subject)
                and not re.search(r"\b(network|environment)\b", subject)
            ):
                continue
            if (
                petal == "near-intents"
                and re.search(r"\b(destination|target|output|recipient)\b", subject)
                and not re.search(r"\b(origin|source)\b", subject)
            ):
                continue
            if words.intersection(re.findall(r"\b[a-z]+\b", subject)):
                return True
            if (
                petal in {"solana", "near-intents"}
                and sum(
                    bool(re.search(r"\b" + re.escape(choice.lower()) + r"\b", subject))
                    for choice in choices
                )
                >= 2
            ):
                return True
    return False


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
        chains = [
            line.split("\t")[0]
            for line in self.triad.cli(
                "vfs", "ls", f"/wallets/{self.triad.wallet}/0/chains"
            ).splitlines()
            if line.endswith("\tDir")
        ]
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
        prompt = PROMPTS[self.petal]
        if self.petal == "near-intents":
            account = self.triad.read(f"/wallets/{self.triad.wallet}/0/account.json")
            prompt = prompt.format(recipient=account["evm"]["address"])
        (task / "instruction.md").write_text(prompt + " Bloom is mounted at /bloom.\n")
        return EvalRunContext(
            self.name,
            task,
            self.trial,
            self.jobs,
            [{"type": "bind", "source": str(self.triad.mount), "target": "/bloom"}],
            {},
            self.triad.projection_env()
            | {
                "BLOOM_EVAL_WALLET_ID": self.triad.wallet,
                "BLOOM_EVAL_CLARIFICATION_CHOICES": json.dumps(chains),
            },
            host_verifier_root=self.triad.mount,
            clarification_petal=self.petal,
        )

    def cleanup(self):
        self.triad.close(preserve=self.failed)
