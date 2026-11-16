#!/usr/bin/env python3
"""Proposal coverage only: inspect the Petal's unsigned order draft."""

import json
import os
import sys

from projection import ProjectionReader


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
    reader = ProjectionReader(root)
    expected = json.loads(os.environ["BLOOM_EVAL_PROPOSAL"])
    wallet, number = expected["wallet"], expected["account"]
    account = reader.read_json(f"wallets/{wallet}/{number}/account.json")
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
    base = f"petals/polymarket/trade/{wallet}/{number}"
    drafts = reader.directories(base + "/drafts")
    require(len(drafts) == 1, "expected exactly one draft")
    require(not reader.directories(base + "/receipts"), "unexpected posted receipt")
    draft = reader.read_json(base + f"/drafts/{drafts[0]}/order.json")
    validate(draft, expected)


if __name__ == "__main__":
    try:
        verify()
    except (ValueError, KeyError, TypeError) as error:
        print(f"invalid Polymarket proposal: {error}", file=sys.stderr)
        raise SystemExit(1)
    except OSError as error:
        print(f"projection unavailable: {error}", file=sys.stderr)
        raise SystemExit(2)
