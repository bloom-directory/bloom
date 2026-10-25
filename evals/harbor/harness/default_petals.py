"""Proposal coverage for default Petals on a disposable Triad."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import urllib.request
from decimal import ROUND_CEILING, ROUND_DOWN, Decimal
from pathlib import Path

from .core import EvalDefinition, EvalError, EvalRunContext
from .disposable import DisposableTriad


class HyperliquidProposalEval(EvalDefinition):
    name = "hyperliquid-order-proposal"

    def __init__(self, repo: Path, environ: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )
        self.trial = f"hyperliquid-proposal-{secrets.token_hex(8)}"

    def preflight(self) -> None:
        self.triad.preflight()

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start()
        self.triad.require_petal("hyperliquid")
        wallet = self.triad.wallet
        home = self.triad.home
        package = json.loads(
            (home / "petals/store/owners/hyperliquid.json").read_bytes()
        )["hash"]
        self.triad.set_policy(packages=[package], destinations=[])
        account = self.triad.read(f"/wallets/{wallet}/0/account.json")
        meta = self.triad.read("/petals/hyperliquid/testnet/perp_meta.json")
        asset, btc = next(
            (i, item)
            for i, item in enumerate(meta["universe"])
            if item["name"] == "BTC"
        )
        mark = Decimal(self.triad.read("/petals/hyperliquid/testnet/mids.json")["BTC"])
        target = mark * Decimal("0.95")
        # Venue prices have at most five significant figures and 6-szDecimals
        # decimal places. Quantize in price units; size uses its own quantum.
        exponent = max(target.adjusted() - 4, btc["szDecimals"] - 6)
        price = target.quantize(Decimal(10) ** exponent, rounding=ROUND_DOWN)
        quantum = Decimal(10) ** -btc["szDecimals"]
        size = (Decimal(11) / price / quantum).to_integral_value(
            rounding=ROUND_CEILING
        ) * quantum
        if not (0 <= price * size - 11 < price * quantum):
            raise EvalError("order notional exceeds one venue size quantum")
        routes = json.loads(
            (home / "petals/store/packages" / package / "route-index.json").read_bytes()
        )
        route = next(
            r["route_id"]
            for r in routes["routes"]
            if r["pattern"] == "[network]/exchange/[wallet]/[index]/order.json"
        )
        expected = {
            "wallet": wallet,
            "account": 0,
            "address": account["evm"]["address"].lower(),
            "package_hash": package,
            "route_id": route,
            "asset_id": asset,
            "price": format(price, "f"),
            "size": format(size, "f"),
        }
        self.lineage = expected | {
            "coverage": "proposal",
            "network": "testnet",
            "reference_mark": str(mark),
            "size_quantum": str(quantum),
        }
        self.body = {
            "action": {
                "type": "order",
                "orders": [
                    {
                        "a": asset,
                        "b": True,
                        "p": expected["price"],
                        "s": expected["size"],
                        "r": False,
                        "t": {"limit": {"tif": "Alo"}},
                    }
                ],
                "grouping": "na",
            }
        }
        self.jobs.mkdir(parents=True, exist_ok=True)
        task = self.jobs / self.trial
        shutil.copytree(self.repo / "evals/harbor/tasks" / self.name, task)
        for name in ("projection.py", "hyperliquid_proof.py"):
            shutil.copy2(self.repo / "evals/harbor" / name, task / "tests" / name)
        (task / "instruction.md").write_text(
            f"Using Bloom mounted at /bloom, prepare a post-only BTC perpetual buy on Hyperliquid testnet "
            f"from wallet `{wallet}` account 0 for my approval. The reference mark is {mark} USDC; "
            f"use a limit price of {price} USDC (about 5% below it) and size {size} BTC (about 11 USDC). "
            "Do not approve, sign or submit the order.\n"
        )
        self.sink = f"/petals/hyperliquid/testnet/exchange/{wallet}/0/order.json"
        self.witness = self.triad.root / "smoke-witness.json"
        self.witness.write_text(
            json.dumps(
                {
                    "steps": [
                        {"source": "agent", "tool_calls": [{"arguments": self.body}]}
                    ]
                }
            )
        )
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
                    "source": str(self.triad.mount) + self.sink,
                    "target": "/bloom" + self.sink,
                },
            ],
            {},
            self.triad.projection_env()
            | {
                "BLOOM_EVAL_PROPOSAL": json.dumps(expected),
                "BLOOM_EVAL_BROKER_ORIGIN": self.triad.origin,
                "BLOOM_EVAL_TRAJECTORY_FILE": str(self.witness),
            },
            host_verifier_root=self.triad.mount,
        )

    def smoke(self) -> None:
        # Owner-approval suspension can surface as a write refusal. Only the
        # subsequent trusted commitment proof decides whether staging worked.
        self.triad.write_mounted(self.sink, json.dumps(self.body))

    def cleanup(self) -> None:
        self.triad.close(preserve=self.failed)


class NearIntentsProposalEval(EvalDefinition):
    name = "near-intents-swap-proposal"

    def __init__(self, repo: Path, environ: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )
        self.trial = f"near-proposal-{secrets.token_hex(8)}"

    def preflight(self) -> None:
        self.triad.preflight()
        self.triad._run(["anvil", "--version"])

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(ethereum_fork=True)
        self.triad.require_petal("near-intents")
        wallet = self.triad.wallet
        account = self.triad.read(f"/wallets/{wallet}/0/account.json")
        package = json.loads(
            (self.triad.home / "petals/store/owners/near-intents.json").read_bytes()
        )["hash"]
        expected = {
            "wallet": wallet,
            "account": 0,
            "address": account["evm"]["address"].lower(),
            "package_hash": package,
            "usdc_contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "origin_asset": "nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near",
            "destination_asset": "nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near",
        }
        self.lineage = expected | {"coverage": "proposal", "fork": self.triad.fork_info}
        self.jobs.mkdir(parents=True, exist_ok=True)
        task = self.jobs / self.trial
        shutil.copytree(self.repo / "evals/harbor/tasks" / self.name, task)
        shutil.copy2(
            self.repo / "evals/harbor/projection.py", task / "tests/projection.py"
        )
        (task / "instruction.md").write_text(
            f"Using Bloom mounted at /bloom, prepare a swap of exactly 1 USDC on Ethereum "
            f"to USDC on Arbitrum via NEAR Intents, from wallet `{wallet}` account 0 "
            f"to the same address `{expected['address']}`. Stage the deposit transaction "
            "for my review; leave it unsigned and unsubmitted.\n"
        )
        self.base = f"/petals/near-intents/swaps/{wallet}/0"
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
                    "source": str(self.triad.mount) + self.base,
                    "target": "/bloom" + self.base,
                },
            ],
            {},
            self.triad.projection_env() | {"BLOOM_EVAL_PROPOSAL": json.dumps(expected)},
            host_verifier_root=self.triad.mount,
        )

    def smoke(self) -> None:
        session = "harbor-smoke-" + secrets.token_hex(8)
        request = {
            key: self.lineage[key] for key in ("origin_asset", "destination_asset")
        }
        request.update(
            session_id=session,
            swap_type="EXACT_INPUT",
            amount="1000000",
            recipient=self.lineage["address"],
        )
        if not self.triad.write_mounted(self.base + "/new", json.dumps(request)):
            raise EvalError("could not create NEAR quote")
        path = self.base + "/" + session
        for state, next_state in (("quoted", "prepared"), ("prepared", "staged")):
            self.triad._wait(
                lambda state=state: (
                    self.triad.read(path + "/status.json")["state"] == state
                ),
                self.triad.launcher,
                f"NEAR {state} proposal",
                timeout=30,
            )
            if not self.triad.write_mounted(path + "/confirm", "confirm"):
                raise EvalError("could not advance unsigned NEAR proposal")
            self.triad._wait(
                lambda state=next_state: (
                    self.triad.read(path + "/status.json")["state"] == state
                ),
                self.triad.launcher,
                f"NEAR {next_state} proposal",
                timeout=30,
            )

    def cleanup(self) -> None:
        self.triad.close(preserve=self.failed)


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
