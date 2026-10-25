"""Proposal coverage for default Petals on a disposable Triad."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import urllib.request
from decimal import Decimal
from pathlib import Path

from .core import EvalDefinition, EvalError, EvalRunContext
from .disposable import DisposableTriad


class PolymarketProposalEval(EvalDefinition):
    name = "polymarket-limit-order-proposal"

    def __init__(self, repo: Path, environ: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )
        self.trial = f"polymarket-proposal-{secrets.token_hex(8)}"

    def preflight(self) -> None:
        self.triad.preflight()
        with urllib.request.urlopen(
            "https://gamma-api.polymarket.com/markets?active=true&closed=false&limit=100",
            timeout=30,
        ) as response:
            markets = json.load(response)
        self.market = next(
            (
                item
                for item in markets
                if item.get("enableOrderBook")
                and item.get("acceptingOrders")
                and Decimal(str(item.get("orderPriceMinTickSize", 1)))
                <= Decimal("0.01")
            ),
            None,
        )
        if self.market is None:
            raise EvalError(
                "no active Polymarket market suitable for a bounded limit proposal"
            )
        for key in ("outcomes", "clobTokenIds"):
            value = self.market[key]
            self.market[key] = json.loads(value) if isinstance(value, str) else value
        if len(self.market["clobTokenIds"]) != 2:
            raise EvalError("expected a binary market with exact outcome token IDs")

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start()
        self.triad.require_petal("polymarket")
        wallet = self.triad.wallet
        account = self.triad.read(f"/wallets/{wallet}/0/account.json")
        # Setup leaves the initial deny-by-default policy in place. Drafting
        # needs no signing allowance, venue onboarding or balance.
        expected = {
            "wallet": wallet,
            "account": 0,
            "chain_id": 137,
            "address": account["evm"]["address"].lower(),
            "condition_id": self.market["conditionId"],
            "token_id": str(self.market["clobTokenIds"][0]),
            "side": "BUY",
            "order_type": "GTC",
            "amount_micro": 5_000_000,
            "limit_price_micro": 10_000,
            "size_micro": 500_000_000,
            "maker_micro": 5_000_000,
            "taker_micro": 500_000_000,
        }
        owner = self.triad.home / "petals/store/owners/polymarket.json"
        self.lineage = expected | {
            "package_hash": json.loads(owner.read_bytes())["hash"],
            "coverage": "proposal",
        }
        self.jobs.mkdir(parents=True, exist_ok=True)
        task = self.jobs / self.trial
        shutil.copytree(self.repo / "evals/harbor/tasks" / self.name, task)
        shutil.copy2(
            self.repo / "evals/harbor/projection.py", task / "tests/projection.py"
        )
        (task / "instruction.md").write_text(
            f"Using Bloom mounted at /bloom, prepare an unsigned GTC buy order from wallet `{wallet}` "
            f"account 0 on Polygon (chain ID 137): spend exactly 5 USDC at a limit price of 0.01 "
            f"for outcome `{self.market['outcomes'][0]}` of market `{self.market['slug']}` "
            f"(condition ID `{expected['condition_id']}`, outcome token ID `{expected['token_id']}`). "
            "Prepare it for my review; do not sign or submit it.\n"
        )
        sink = f"/petals/polymarket/trade/{wallet}/0/new"
        return EvalRunContext(
            self.name,
            task,
            self.trial,
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
                    "source": str(self.triad.mount) + sink,
                    "target": "/bloom" + sink,
                },
            ],
            {},
            self.triad.projection_env() | {"BLOOM_EVAL_PROPOSAL": json.dumps(expected)},
            host_verifier_root=self.triad.mount,
        )

    def cleanup(self) -> None:
        # There is no cancel route for an unposted Polymarket draft. Discard
        # its disposable state; no CLOB order or onboarding was authorized.
        self.triad.close(preserve=self.failed)

    def smoke(self) -> None:
        body = {
            "slug": self.market["slug"],
            "outcome": self.market["outcomes"][0],
            "side": "buy",
            "amount": "5",
            "limit_price": "0.01",
            "order_type": "GTC",
        }
        if not self.triad.write_mounted(
            f"/petals/polymarket/trade/{self.triad.wallet}/0/new", json.dumps(body)
        ):
            raise EvalError("smoke could not create the unsigned order draft")
