"""Disposable local-chain transfer: one intent, one approval, one payment."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from .core import EvalDefinition, EvalError, EvalRunContext
from .disposable import DisposableTriad


def matching_transfer(intent: Any, expected: dict[str, Any], fee_limit: int) -> bool:
    return (
        isinstance(intent, dict)
        and all(
            type(intent.get(key)) is type(value) and intent.get(key) == value
            for key, value in expected.items()
        )
        and type(intent.get("fee_lamports")) is int
        and 0 <= intent["fee_lamports"] <= fee_limit
    )


class SolanaTransferEval(EvalDefinition):
    name = "solana-transfer"

    def __init__(self, repo: Path, environ: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.stop = threading.Event()
        self.approver: threading.Thread | None = None
        self.approval_error: BaseException | None = None
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )

    def preflight(self) -> None:
        self.triad.preflight()
        for binary in ("solana-test-validator", "solana", "solana-keygen"):
            if shutil.which(binary) is None:
                raise EvalError(f"{binary} is required")

    def _approve(self) -> None:
        approved: str | None = None
        deadline = time.monotonic() + 3600
        try:
            while not self.stop.wait(0.2):
                if time.monotonic() >= deadline:
                    raise EvalError("transfer approver timed out")
                pending = (
                    self.triad.home
                    / ".solana-outbox"
                    / self.triad.wallet
                    / "solana-local/pending"
                )
                entries = list(pending.iterdir()) if pending.exists() else []
                if len(entries) > 1:
                    raise EvalError("more than one pending transfer")
                for entry in entries:
                    if approved is not None and entry.name != approved:
                        raise EvalError("a second transfer was staged after approval")
                    try:
                        intent = json.loads((entry / "intent.json").read_bytes())
                        challenge = json.loads(
                            (entry / "approval_challenge.json").read_bytes()
                        )
                    except FileNotFoundError:
                        continue
                    if not matching_transfer(intent, self.expected, self.fee_limit):
                        raise EvalError(
                            "pending transfer differs from the authorized contract"
                        )
                    if approved is None:
                        self.triad.driver.complete(challenge["ceremony_url"])
                        approved = entry.name
        except Exception as error:  # noqa: BLE001 -- propagate worker errors to the owning trial
            self.approval_error = error

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(solana=True)
        wallet = self.triad.wallet
        accounts = self.triad.read(f"/wallets/{wallet}/accounts.json")
        children = [
            item
            for item in accounts["accounts"]
            if item.get("derivation_profile") == "bip44-solana-slip10-ed25519-v1"
            and item.get("lifecycle") == "ACTIVE"
        ]
        if len(children) != 1 or type(children[0].get("number")) is not int:
            raise EvalError(
                "fresh wallet must have exactly one active numbered Solana child"
            )
        child = children[0]
        number = str(child["number"])
        self.base = f"/wallets/{wallet}/{number}/chains/solana-local/outbox"
        source = self.triad.cli(
            "wallet", "address", wallet, "--profile", "solana"
        ).strip()
        key = self.triad.root / "recipient.json"
        self.triad._run(
            [
                "solana-keygen",
                "new",
                "--no-bip39-passphrase",
                "--silent",
                "--outfile",
                str(key),
            ]
        )
        destination = self.triad._run(["solana-keygen", "pubkey", str(key)]).strip()
        self.lamports, self.fee_limit = 1_000_000, 10_000
        self.expected = {
            "genesis_hash": self.triad.genesis,
            "destination": destination,
            "lamports": self.lamports,
            "fee_payer": source,
            "account_fingerprint": child["public_key_fingerprint"],
            "account_derivation_path": child["path"],
        }
        self.lineage = self.expected | {
            "wallet": wallet,
            "account": int(number),
            "coverage": "settlement",
        }
        self.triad._run(["solana", "airdrop", "2", source, "--url", self.triad.rpc_url])
        self.triad.set_policy(
            packages=[], destinations=[{"chain": "solana", "destination": destination}]
        )
        self.jobs.mkdir(parents=True, exist_ok=True)
        trial = f"solana-{agent_name}-{secrets.token_hex(8)}"
        task = self.jobs / trial
        shutil.copytree(self.repo / "evals/harbor/tasks/solana-transfer", task)
        (task / "instruction.md").write_text(
            f"Using Bloom mounted at /bloom, send exactly 0.001 SOL from wallet `{wallet}` "
            f"account {number} on `solana-local` to `{destination}`. Wait for finalization "
            "and report the result. The owner will approve the matching ceremony; retry "
            "the same confirmation after approval.\n"
        )
        self.approver = threading.Thread(target=self._approve, daemon=True)
        self.approver.start()
        verifier_env = {
            "BLOOM_EVAL_SOLANA_SOURCE": source,
            "BLOOM_EVAL_SOLANA_WALLET_ID": wallet,
            "BLOOM_EVAL_SOLANA_ACCOUNT": number,
            "BLOOM_EVAL_SOLANA_CHAIN": "solana-local",
            "BLOOM_EVAL_SOLANA_DESTINATION": destination,
            "BLOOM_EVAL_SOLANA_LAMPORTS": str(self.lamports),
            "BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS": str(self.fee_limit),
            "BLOOM_EVAL_SOLANA_RPC_URL": self.triad.rpc_url,
            "BLOOM_EVAL_SOLANA_GENESIS": self.triad.genesis,
        }
        return EvalRunContext(
            self.name,
            task,
            trial,
            self.jobs,
            [
                {
                    "type": "bind",
                    "source": str(self.triad.mount),
                    "target": "/bloom",
                    "read_only": True,
                },
                {
                    "type": "bind",
                    "source": str(self.triad.mount) + self.base,
                    "target": "/bloom" + self.base,
                },
            ],
            {},
            verifier_env,
            [
                self.repo
                / "evals/harbor/tasks/solana-transfer/docker-compose.local.yaml"
            ],
        )

    def validate_result(self, result: Any) -> None:
        if self.approval_error is not None:
            raise EvalError(f"transfer approver failed: {self.approval_error}")
        super().validate_result(result)

    def smoke(self) -> None:
        body = json.dumps(
            {"destination": self.expected["destination"], "lamports": self.lamports}
        )
        if not self.triad.write_mounted(self.base + "/new.tx", body):
            raise EvalError("smoke could not stage a mounted transfer")
        pending = self.triad.cli("vfs", "ls", self.base + "/pending").splitlines()
        if len(pending) != 1:
            raise EvalError("smoke expected exactly one pending transfer")
        entry = pending[0].split("\t")[0]
        confirm = self.base + f"/pending/{entry}/confirm"
        if self.triad.write_mounted(confirm, "y"):
            raise EvalError("first confirmation bypassed approval")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.approval_error is not None:
                raise EvalError(f"approver failed: {self.approval_error}")
            if self.triad.write_mounted(confirm, "y"):
                return
            time.sleep(0.5)
        raise EvalError("smoke confirmation timed out")

    def cleanup(self) -> None:
        self.stop.set()
        if self.approver is not None:
            self.approver.join(timeout=60)
            if self.approver.is_alive():
                raise EvalError("transfer approver did not stop; preserving its Triad")
        self.triad.close(preserve=self.failed)
        if self.approval_error is not None:
            raise EvalError(f"transfer approver failed: {self.approval_error}")
