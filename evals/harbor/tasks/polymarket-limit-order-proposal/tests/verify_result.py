#!/usr/bin/env python3
"""Proposal coverage only: inspect the Petal's unsigned order draft."""

import json
import os
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(draft, expected):
    require(isinstance(draft, dict), "draft must be an object")
    for key in (
        "wallet",
        "condition_id",
        "token_id",
        "side",
        "order_type",
        "amount_micro",
        "limit_price_micro",
        "size_micro",
        "maker_micro",
        "taker_micro",
    ):
        require(
            type(draft.get(key)) is type(expected[key])
            and draft.get(key) == expected[key],
            f"wrong {key}",
        )
    require(draft.get("status") == "review", "draft is not awaiting review")
    require(draft.get("marketable") is False, "expected a limit order")
    require(
        draft.get("salt") is None and draft.get("clob_order_id") is None,
        "order has advanced past an unsigned proposal",
    )


def verify(root=None):
    root = root or Path(os.environ.get("BLOOM_EVAL_MOUNT_ROOT", "/bloom"))
    expected = json.loads(os.environ["BLOOM_EVAL_PROPOSAL"])
    wallet, number = expected["wallet"], expected["account"]
    account = json.loads(
        (root / f"wallets/{wallet}/{number}/account.json").read_bytes()
    )
    require(
        account.get("schema") == "bloom.account.v1"
        and account.get("wallet") == wallet
        and type(account.get("number")) is int
        and account["number"] == number
        and account.get("freshness") == "fresh",
        "wrong or stale account",
    )
    evm = account.get("evm", {})
    require(
        evm.get("state") == "active"
        and evm.get("address", "").lower() == expected["address"],
        "wrong account address",
    )
    require(
        int((root / "chains/polygon/chain_id").read_text().strip())
        == expected["chain_id"],
        "wrong chain ID",
    )
    base = root / f"petals/polymarket/trade/{wallet}/{number}"
    drafts = list((base / "drafts").iterdir())
    require(len(drafts) == 1, "expected exactly one draft")
    require(not list((base / "receipts").iterdir()), "unexpected posted receipt")
    draft = json.loads((drafts[0] / "order.json").read_bytes())
    validate(draft, expected)


if __name__ == "__main__":
    try:
        verify()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"invalid Polymarket proposal: {error}", file=sys.stderr)
        raise SystemExit(1)
