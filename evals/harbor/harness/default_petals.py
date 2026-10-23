"""Disposable custody around the existing bounded Hyperliquid task."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import urllib.request
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

from .core import EvalDefinition, EvalError, EvalRunContext
from .disposable import DisposableTriad, private_file
from .hyperliquid_order_cancel import MAINNET_ACK, HyperliquidOrderCancelEval


class DisposableHyperliquidEval(EvalDefinition):
    name = "hyperliquid-order-cancel"

    def __init__(self, repo: Path, environ: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        testnet = self.env.get("BLOOM_EVAL_HYPERLIQUID_TESTNET_MNEMONIC_FILE")
        mainnet = self.env.get("BLOOM_EVAL_HYPERLIQUID_MAINNET_MNEMONIC_FILE")
        self.network = "testnet" if testnet else "mainnet"
        self.mnemonic = Path(testnet or mainnet) if (testnet or mainnet) else None
        self.definition: HyperliquidOrderCancelEval | None = None

    @property
    def lock_path(self) -> Path:
        # The imported wallet still shares venue state across disposable roots.
        # Serialize it even though Solana needs no cross-run recovery lock.
        return Path("/tmp/bloom-harbor-hyperliquid.lock")

    def preflight(self) -> None:
        self.triad.preflight()
        if self.mnemonic is None:
            raise EvalError(
                "provide a funded testnet mnemonic file via "
                "BLOOM_EVAL_HYPERLIQUID_TESTNET_MNEMONIC_FILE, or the dedicated "
                "mainnet fallback via BLOOM_EVAL_HYPERLIQUID_MAINNET_MNEMONIC_FILE"
            )
        private_file(self.mnemonic)

    def provision(self, agent_name: str) -> EvalRunContext:
        self.triad.start(mnemonic=self.mnemonic)
        self.triad.require_petal("hyperliquid")
        store = self.triad.home / "petals/store"
        owner = store / "owners/hyperliquid.json"
        package = json.loads(owner.read_bytes())["hash"]
        wallet = self.triad.wallet
        account = self.triad.read(f"/wallets/{wallet}/0/account.json")
        address = account["evm"]["address"].lower()
        self.lineage = {
            "package_hash": package,
            "network": self.network,
            "wallet": wallet,
            "account": 0,
            "address": address,
        }
        metadata = self.triad.read(f"/petals/hyperliquid/{self.network}/perp_meta.json")
        universe = metadata.get("universe") if isinstance(metadata, dict) else None
        if not isinstance(universe, list):
            raise EvalError("venue metadata has no asset universe")
        btc = [
            index
            for index, asset in enumerate(universe)
            if isinstance(asset, dict) and asset.get("name") == "BTC"
        ]
        if len(btc) != 1:
            raise EvalError("venue must identify exactly one BTC asset")
        self.triad.set_policy(packages=[package], destinations=[])
        env = self.triad.env | {
            "BLOOM_EVAL_NETWORK": self.network,
            "BLOOM_EVAL_ASSET_ID": str(btc[0]),
            "BLOOM_EVAL_WALLET": address,
            "BLOOM_EVAL_WALLET_ID": wallet,
            "BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH": package,
            "BLOOM_EVAL_PETAL_OWNER_RECORD": str(owner),
            "BLOOM_EVAL_PETAL_STORE": str(store),
            "BLOOM_EVAL_PROVENANCE_CATALOG": str(
                self.triad.root / "dev/config/provenance-catalog.json"
            ),
            "BLOOM_EVAL_BLOOM_MOUNT": str(self.triad.mount),
            "BLOOM_EVAL_CEREMONY_ORIGIN": self.triad.origin,
            "BLOOM_EVAL_DEBUG_DRIVER_BIN": str(self.triad.driver.binary),
            "BLOOM_EVAL_AUTHENTICATOR_SEED_FILE": str(self.triad.driver.seed),
            "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT": str(self.triad.driver.counter),
            "BLOOM_EVAL_AGENT_NAME": self.env.get("BLOOM_EVAL_AGENT_NAME")
            or "be-" + hashlib.sha256(address.encode()).hexdigest()[:8],
        }
        if self.network == "mainnet":
            env["BLOOM_EVAL_MAINNET_ACK"] = MAINNET_ACK
        self.definition = HyperliquidOrderCancelEval(self.repo, env)
        self.definition.preflight()
        context = self.definition.provision(agent_name)
        task = context.jobs_dir / (context.job_name + "-" + self.triad.root.name)
        shutil.copytree(context.task_dir, task)
        instruction = (task / "instruction.md").read_text()
        instruction = instruction.replace("mainnet", self.network)
        instruction = instruction.replace("asset ID `0`", f"asset ID `{btc[0]}`")
        instruction = instruction.replace('"asset_id": 0', f'"asset_id": {btc[0]}')
        (task / "instruction.md").write_text(instruction)
        return replace(
            context,
            task_dir=task,
            job_name=context.job_name + "-" + self.triad.root.name,
        )

    def cleanup(self) -> None:
        # Venue cleanup must succeed before erasing the only local authority
        # able to cancel a residual order or close a position.
        if self.definition is not None:
            self.definition.cleanup()
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

    @property
    def lock_path(self) -> Path:
        return self.jobs / (self.trial + ".lock")

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
            "Leave the draft ready for my review. Do not onboard, sign, post or fund anything.\n"
            f"\nCreate the review draft through `/bloom/petals/polymarket/trade/{wallet}/0/new`. "
            "This write-only route accepts JSON fields `slug`, `outcome`, `side`, "
            "`amount` (USDC decimal string), `limit_price` (decimal string), and "
            "`order_type` (`GTC`). Read the resulting `drafts/<id>/order.json` and "
            "`plan.md`, then report the draft ID and its terms. Stop at the unsigned "
            "review draft; posting eligibility and onboarding are outside this request.\n"
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
