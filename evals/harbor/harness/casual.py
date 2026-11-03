"""Casual operator read evaluations on a disposable Triad."""

from __future__ import annotations

import os
import secrets
import shutil
from pathlib import Path

from .core import EvalDefinition, EvalRunContext
from .disposable import DisposableTriad


class CasualEval(EvalDefinition):
    coverage = "casual-read"

    def __init__(self, repo: Path, environ: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )
        self.trial = f"{self.name}-{secrets.token_hex(8)}"

    def preflight(self) -> None:
        self.triad.preflight()

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(solana=True)
        self.jobs.mkdir(parents=True, exist_ok=True)
        task = self.jobs / self.trial
        shutil.copytree(self.repo / "evals/harbor/tasks" / self.name, task)
        mounts = [
            {
                "type": "bind",
                "source": str(self.triad.mount),
                "target": "/bloom",
                "read_only": True,
            }
        ]
        return EvalRunContext(
            self.name,
            task,
            self.trial,
            self.jobs,
            mounts,
            {},
            {},
        )

    def cleanup(self) -> None:
        self.triad.close(preserve=self.failed)


class CasualWalletBalancesEval(CasualEval):
    name = "casual-wallet-balances"


class CasualEthInMainEval(CasualEval):
    name = "casual-eth-in-main"


class CasualSupportedChainsEval(CasualEval):
    name = "casual-supported-chains"


class CasualSentHistoryEval(CasualEval):
    name = "casual-sent-history"


class CasualAnvilStatusEval(CasualEval):
    name = "casual-anvil-status"
