"""Casual operator read evaluations on a disposable Triad."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
from pathlib import Path

from .core import EvalDefinition, EvalRunContext
from .disposable import DisposableTriad


class CasualEval(EvalDefinition):
    coverage = "casual-read"
    needs_solana = False

    def __init__(self, repo: Path, environ: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )
        self.trial = f"{self.name}-{secrets.token_hex(8)}"
        self.witness: Path | None = None
        # Configure an anvil chain on a port nothing listens on, so it is offline.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            self.triad.anvil_port = probe.getsockname()[1]

    def preflight(self) -> None:
        self.triad.preflight()

    def task(self) -> Path:
        self.jobs.mkdir(parents=True, exist_ok=True)
        task = self.jobs / self.trial
        shutil.copytree(self.repo / "evals/harbor/tasks" / self.name, task)
        task_tests = task / "tests"
        task_tests.mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            self.repo / "evals/harbor/tasks/activity.py", task_tests / "activity.py"
        )
        shutil.copy2(
            self.repo / "evals/harbor/projection.py", task_tests / "projection.py"
        )
        return task

    def context(self, task: Path, verifier_env: dict[str, str]) -> EvalRunContext:
        if self.witness is None and self.triad.root is not None:
            self.witness = self.triad.root / "smoke-witness.json"
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
            self.triad.projection_env()
            | verifier_env
            | {
                "BLOOM_EVAL_TRAJECTORY_FILE": str(self.witness),
                "BLOOM_EVAL_MOUNT_ROOT": str(self.triad.mount),
            },
            host_verifier_root=self.triad.mount,
        )

    def cleanup(self) -> None:
        self.triad.close(preserve=self.failed)


class CasualWalletBalancesEval(CasualEval):
    name = "casual-wallet-balances"

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(solana=self.needs_solana, ethereum_fork=True)
        self.triad.enroll_wallet("savings")
        addr = self.triad.read("/wallets/savings/0/account.json")["evm"]["address"]
        self.triad.fork_rpc("anvil_setBalance", addr, hex(int(1.25 * 10**18)))
        task = self.task()
        return self.context(
            task,
            {},
        )

    def smoke(self) -> None:
        witness = {
            "steps": [
                {
                    "source": "agent",
                    "tool_calls": [
                        {
                            "tool": "bash",
                            "arguments": "bloom vfs cat /wallets/harbor/0/chains/ethereum/balance",
                        }
                    ],
                    "message": "Wallet harbor has 0.05 ETH and wallet savings has 1.25 ETH on ethereum.",
                }
            ]
        }
        self.witness.write_text(json.dumps(witness))


class CasualEthInMainEval(CasualEval):
    name = "casual-eth-in-main"

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(solana=self.needs_solana, ethereum_fork=True)
        self.triad.enroll_wallet("main")
        addr = self.triad.read("/wallets/main/0/account.json")["evm"]["address"]
        self.triad.fork_rpc("anvil_setBalance", addr, hex(int(2.5 * 10**18)))
        task = self.task()
        return self.context(
            task,
            {},
        )

    def smoke(self) -> None:
        witness = {
            "steps": [
                {
                    "source": "agent",
                    "tool_calls": [
                        {
                            "tool": "bash",
                            "arguments": "bloom vfs cat /wallets/main/0/chains/ethereum/balance",
                        }
                    ],
                    "message": "Wallet main holds 2.5 ETH on ethereum.",
                }
            ]
        }
        self.witness.write_text(json.dumps(witness))


class CasualSupportedChainsEval(CasualEval):
    name = "casual-supported-chains"

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(solana=self.needs_solana)
        task = self.task()
        return self.context(
            task,
            {},
        )

    def smoke(self) -> None:
        witness = {
            "steps": [
                {
                    "source": "agent",
                    "tool_calls": [
                        {"tool": "bash", "arguments": "bloom vfs ls /chains"}
                    ],
                    "message": "Supported chains are ethereum, polygon, and anvil.",
                }
            ]
        }
        self.witness.write_text(json.dumps(witness))


class CasualSentHistoryEval(CasualEval):
    name = "casual-sent-history"

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(solana=self.needs_solana)
        wallet = self.triad.wallet
        recipient = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
        sent_dir = (
            self.triad.home / "outbox" / wallet / "ethereum" / "sent" / "0001-seed"
        )
        sent_dir.mkdir(parents=True, exist_ok=True)
        intent = {
            "id": "0001-seed",
            "wallet": wallet,
            "chain": "ethereum",
            "to": recipient,
            "value_wei": "100000000000000000",
            "status": "sent",
        }
        (sent_dir / "intent.json").write_text(json.dumps(intent))
        task = self.task()
        return self.context(
            task,
            {},
        )

    def smoke(self) -> None:
        recipient = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
        witness = {
            "steps": [
                {
                    "source": "agent",
                    "tool_calls": [
                        {
                            "tool": "bash",
                            "arguments": "bloom vfs ls /wallets/harbor/0/chains/ethereum/outbox/sent",
                        }
                    ],
                    "message": f"You have sent transactions to {recipient}.",
                }
            ]
        }
        self.witness.write_text(json.dumps(witness))


class CasualAnvilStatusEval(CasualEval):
    name = "casual-anvil-status"

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(solana=self.needs_solana)
        task = self.task()
        return self.context(
            task,
            {},
        )

    def smoke(self) -> None:
        witness = {
            "steps": [
                {
                    "source": "agent",
                    "tool_calls": [
                        {
                            "tool": "bash",
                            "arguments": "bloom vfs cat /status/chains/anvil/connected",
                        }
                    ],
                    "message": "Anvil is offline and not connected.",
                }
            ]
        }
        self.witness.write_text(json.dumps(witness))
