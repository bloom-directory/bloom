"""Disposable local-chain transfer: one intent, one approval, one payment."""

from __future__ import annotations

import json
import shutil
import time
from typing import Any

from .core import EvalError, EvalRunContext
from .transfer import TransferEval


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


class SolanaTransferEval(TransferEval):
    name = "solana-transfer"

    def preflight(self) -> None:
        self.triad.preflight()
        for binary in ("solana-test-validator", "solana", "solana-keygen"):
            if shutil.which(binary) is None:
                raise EvalError(f"{binary} is required")

    def pending(self) -> list[tuple[str, Any, Any]]:
        directory = (
            self.triad.home / ".solana-outbox" / self.triad.wallet / "solana-local/pending"
        )
        entries = []
        for entry in list(directory.iterdir()) if directory.exists() else []:
            try:
                intent = json.loads((entry / "intent.json").read_bytes())
                challenge = json.loads((entry / "approval_challenge.json").read_bytes())
            except FileNotFoundError:
                intent = challenge = None
            entries.append((entry.name, intent, challenge))
        return entries

    def matches(self, intent: Any) -> bool:
        return matching_transfer(intent, self.expected, self.fee_limit)

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
        trial, task = self.task(
            agent_name,
            "Using Bloom mounted at /bloom, send exactly 0.001 SOL to "
            f"`{destination}` and wait until it is finalized. I will approve it when asked.\n",
        )
        self.start_approver()
        return self.context(
            trial,
            task,
            self.base,
            {
                "BLOOM_EVAL_SOLANA_SOURCE": source,
                "BLOOM_EVAL_SOLANA_WALLET_ID": wallet,
                "BLOOM_EVAL_SOLANA_ACCOUNT": number,
                "BLOOM_EVAL_SOLANA_CHAIN": "solana-local",
                "BLOOM_EVAL_SOLANA_DESTINATION": destination,
                "BLOOM_EVAL_SOLANA_LAMPORTS": str(self.lamports),
                "BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS": str(self.fee_limit),
                "BLOOM_EVAL_SOLANA_RPC_URL": self.triad.rpc_url,
                "BLOOM_EVAL_SOLANA_GENESIS": self.triad.genesis,
            },
        )

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
