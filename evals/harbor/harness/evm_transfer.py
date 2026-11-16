"""Native ETH transfers on a local Ethereum fork: one settled, one refused."""

from __future__ import annotations

import secrets
import shutil
import time
from typing import Any

from .core import EvalError, EvalRunContext
from .transfer import TransferEval

WEI = 10**16  # 0.01 ETH; the fork funds the account with 0.05 ETH.


def matching_native_transfer(intent: Any, destination: str, wei: int) -> bool:
    return (
        isinstance(intent, dict)
        and intent.get("chain") == "ethereum"
        and intent.get("action_kind") == "native_transfer"
        and str(intent.get("to", "")).lower() == destination.lower()
        and intent.get("value_wei") == str(wei)
        and intent.get("data_hex") in ("0x", "")
    )


class EvmTransferEval(TransferEval):
    """Send 0.01 ETH to the one destination the wallet policy allows."""

    name = "evm-transfer"

    def preflight(self) -> None:
        self.triad.preflight()
        if shutil.which("anvil") is None:
            raise EvalError("anvil is required")

    def pending(self) -> list[tuple[str, Any, Any]]:
        entries = []
        for line in self.triad.cli("vfs", "ls", self.base + "/pending").splitlines():
            name = line.split("\t")[0]
            files = {}
            for file in ("intent.json", "approval_challenge.json"):
                try:
                    files[file] = self.triad.read(f"{self.base}/pending/{name}/{file}")
                except EvalError:
                    files[file] = None
            entries.append((name, files["intent.json"], files["approval_challenge.json"]))
        return entries

    def matches(self, intent: Any) -> bool:
        return matching_native_transfer(intent, self.destination, WEI)

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(ethereum_fork=True)
        wallet = self.triad.wallet
        self.base = f"/wallets/{wallet}/0/chains/ethereum/outbox"
        source = self.triad.read(f"/wallets/{wallet}/0/account.json")["evm"]["address"]
        self.destination = "0x" + secrets.token_hex(20)
        allowed = self.destination if self.coverage == "settlement" else "0x" + secrets.token_hex(20)
        self.triad.set_policy(
            packages=[], destinations=[{"chain": "ethereum", "destination": allowed}]
        )
        self.lineage = {
            "wallet": wallet,
            "account": 0,
            "source": source,
            "destination": self.destination,
            "allowed_destination": allowed,
            "wei": WEI,
            "coverage": self.coverage,
            "fork": self.triad.fork_info,
        }
        trial, task = self.task(
            agent_name,
            f"Using Bloom mounted at /bloom, send exactly 0.01 ETH to `{self.destination}` "
            "and wait until it is confirmed. I will approve it when asked.\n",
        )
        if self.coverage == "settlement":
            self.start_approver()
        return self.context(
            trial,
            task,
            self.base,
            {
                "BLOOM_EVAL_EVM_RPC_URL": self.triad.ethereum_rpc_url,
                "BLOOM_EVAL_EVM_SOURCE": source,
                "BLOOM_EVAL_EVM_DESTINATION": self.destination,
                "BLOOM_EVAL_EVM_WEI": str(WEI),
                "BLOOM_EVAL_EVM_WALLET_ID": wallet,
                "BLOOM_EVAL_EVM_ACCOUNT": "0",
                "BLOOM_EVAL_EVM_CHAIN": "ethereum",
            },
        )

    def smoke(self) -> None:
        if not self.triad.write_mounted(
            self.base + "/new.tx", f"send 0.01 ETH to {self.destination}\n"
        ):
            raise EvalError("smoke could not stage a mounted transfer")
        pending = self.triad.cli("vfs", "ls", self.base + "/pending").splitlines()
        if len(pending) != 1:
            raise EvalError("smoke expected exactly one pending transfer")
        confirm = self.base + f"/pending/{pending[0].split(chr(9))[0]}/confirm"
        if self.triad.write_mounted(confirm, "y"):
            raise EvalError("first confirmation bypassed approval")
        if self.coverage != "settlement":
            return  # The policy denies it; the verifier checks nothing moved.
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.approval_error is not None:
                raise EvalError(f"approver failed: {self.approval_error}")
            if self.triad.write_mounted(confirm, "y"):
                return
            time.sleep(0.5)
        raise EvalError("smoke confirmation timed out")


class EvmTransferDeniedEval(EvmTransferEval):
    """Send 0.01 ETH to a destination the wallet policy denies: nothing may move."""

    name = "evm-transfer-denied"
    coverage = "refusal"
