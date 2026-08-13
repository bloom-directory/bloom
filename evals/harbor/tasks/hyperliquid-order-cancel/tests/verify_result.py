#!/usr/bin/env python3
"""Validate the v0 agent-reported result for the Bloom Hyperliquid eval."""

from __future__ import annotations

import json
import os
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

SCHEMA = "bloom.eval.hyperliquid_order_cancel.v1"
CLOID_RE = re.compile(r"^0x[0-9a-f]{32}$")
WALLET_RE = re.compile(r"^0x[0-9a-f]{40}$")


class InvalidReport(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidReport(message)


def decimal(value: object, name: str) -> Decimal:
    if not isinstance(value, str):
        raise InvalidReport(f"{name} must be a canonical decimal string")
    require(re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?", value) is not None, f"{name} is not canonical")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise InvalidReport(f"{name} is not a decimal") from error
    require(parsed > 0, f"{name} must be positive")
    return parsed


def hyperliquid_btc_price_floor(value: Decimal) -> Decimal:
    """Floor a positive BTC perp price to the nearest valid price.

    BTC prices may have one decimal place and at most five significant figures;
    integer prices are explicitly valid regardless of significant figures.
    """
    tenth = (value // Decimal("0.1")) * Decimal("0.1")
    significant_figures = len(tenth.normalize().as_tuple().digits)
    if significant_figures <= 5:
        return tenth
    return value // Decimal(1)


def validate(report_value: object, expected_wallet: str, expected_session: str, expected_cloid: str) -> None:
    if not isinstance(report_value, dict):
        raise InvalidReport("report must be an object")
    report: dict[str, object] = report_value
    required = {
        "schema", "status", "network", "wallet", "session_id", "asset", "asset_id",
        "side", "leverage", "post_only", "mark_price", "limit_price", "size", "notional_usd",
        "cloid", "order_status", "order_id", "cancel_status",
        "matching_open_orders_after_cancel", "session_left_active_for_harness_cleanup",
    }
    require(set(report) == required, "report fields do not exactly match the v1 schema")
    require(report["schema"] == SCHEMA, "wrong schema")
    require(report["status"] == "complete", "task is not complete")
    require(report["network"] == "mainnet", "wrong network")
    require(isinstance(report["wallet"], str) and WALLET_RE.fullmatch(report["wallet"]) is not None, "invalid wallet")
    require(report["wallet"] == expected_wallet, "wrong wallet")
    require(report["session_id"] == expected_session, "wrong session")
    require(report["asset"] == "BTC" and report["asset_id"] == 0, "wrong asset")
    require(report["side"] == "buy", "wrong side")
    require(report["leverage"] == 1, "BTC leverage was not set to 1")
    require(report["post_only"] is True, "order was not post-only")
    cloid = report["cloid"]
    require(isinstance(cloid, str) and cloid == expected_cloid and CLOID_RE.fullmatch(cloid) is not None, "wrong cloid")

    mark = decimal(report["mark_price"], "mark_price")
    price = decimal(report["limit_price"], "limit_price")
    size_raw = report["size"]
    size = decimal(size_raw, "size")
    claimed_notional = decimal(report["notional_usd"], "notional_usd")
    require(isinstance(size_raw, str) and len(size_raw.partition(".")[2]) <= 5, "BTC size exceeds five decimals")
    target = mark * Decimal("0.95")
    expected_price = hyperliquid_btc_price_floor(target)
    require(price == expected_price, "limit price is not the 5%-below-mark target rounded down to a valid BTC tick")
    computed_notional = price * size
    require(Decimal(10) <= computed_notional <= Decimal(11), "computed notional is outside $10..$11")
    require(abs(claimed_notional - computed_notional) <= Decimal("0.01"), "reported notional differs from price times size")

    require(report["order_status"] == "resting", "order did not rest on the book")
    require(isinstance(report["order_id"], int) and report["order_id"] > 0, "invalid order id")
    require(report["cancel_status"] == "success", "cancel did not succeed")
    require(report["matching_open_orders_after_cancel"] == 0, "matching order remains open")
    require(report["session_left_active_for_harness_cleanup"] is True, "session was not handed to harness cleanup")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_result.py RESULT.json", file=sys.stderr)
        return 2
    expected_wallet = os.environ.get("BLOOM_EVAL_WALLET", "")
    expected_session = os.environ.get("BLOOM_EVAL_SESSION_ID", "")
    expected_cloid = os.environ.get("BLOOM_EVAL_CLOID", "")
    try:
        report = json.loads(Path(sys.argv[1]).read_text())
        validate(report, expected_wallet, expected_session, expected_cloid)
    except (OSError, json.JSONDecodeError, InvalidReport) as error:
        print(f"invalid Bloom eval report: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
