#!/usr/bin/env python3
"""Validate the report against independent Hyperliquid order evidence."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

SCHEMA = "bloom.eval.hyperliquid_order_cancel.v1"
CLOID_RE = re.compile(r"^0x[0-9a-f]{32}$")
WALLET_RE = re.compile(r"^0x[0-9a-f]{40}$")
HYPERLIQUID_INFO_URL = "https://api.hyperliquid.xyz/info"
VENUE_TIMEOUT_SECONDS = 30


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


def venue_decimal(value: object, name: str) -> Decimal:
    """Parse Hyperliquid's fixed-point wire form without requiring JCS style."""
    if not isinstance(value, str):
        raise InvalidReport(f"{name} must be a decimal string")
    require(
        re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", value) is not None,
        f"{name} is not a fixed-point decimal",
    )
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


def fetch_order_status(wallet: str, oid: str | int) -> object:
    """Read order status from Hyperliquid, outside the agent's report boundary."""
    endpoint = os.environ.get("BLOOM_EVAL_HYPERLIQUID_INFO_URL", HYPERLIQUID_INFO_URL)
    body = json.dumps(
        {"type": "orderStatus", "user": wallet, "oid": oid},
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=VENUE_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise InvalidReport(
                    f"Hyperliquid order-status query returned HTTP {response.status}"
                )
            return json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise InvalidReport(f"could not read Hyperliquid order status: {error}") from error


def venue_order(value: object, expected_cloid: str) -> dict[str, Any]:
    """Require a canceled ALO BTC order carrying the trusted run CLOID."""
    require(isinstance(value, dict), "Hyperliquid order-status response is not an object")
    envelope: dict[str, Any] = value
    require(envelope.get("status") == "order", "Hyperliquid did not find the expected CLOID")
    lifecycle = envelope.get("order")
    require(isinstance(lifecycle, dict), "Hyperliquid response has no order lifecycle")
    require(lifecycle.get("status") == "canceled", "expected order is not canceled at Hyperliquid")
    order = lifecycle.get("order")
    require(isinstance(order, dict), "Hyperliquid response has no order details")
    require(order.get("cloid") == expected_cloid, "Hyperliquid order has the wrong CLOID")
    require(order.get("coin") == "BTC", "Hyperliquid order is not BTC")
    require(order.get("side") == "B", "Hyperliquid order is not a buy")
    require(order.get("tif") == "Alo", "Hyperliquid order is not post-only ALO")
    require(order.get("orderType") == "Limit", "Hyperliquid order is not a limit order")
    require(order.get("reduceOnly") is False, "Hyperliquid order is unexpectedly reduce-only")
    require(order.get("isTrigger") is False, "Hyperliquid order is unexpectedly a trigger")
    require(
        isinstance(order.get("oid"), int) and order["oid"] > 0,
        "Hyperliquid order has no valid venue order id",
    )
    venue_decimal(order.get("limitPx"), "Hyperliquid limitPx")
    venue_decimal(order.get("origSz"), "Hyperliquid origSz")
    return order


def validate(
    report_value: object,
    expected_wallet: str,
    expected_session: str,
    expected_cloid: str,
    venue_value: object,
) -> None:
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

    # The report is agent-authored. Grade placement and cancellation from the
    # venue record found by the host-generated CLOID, then bind its immutable
    # order id and submitted terms back to the report. A fabricated report for
    # an order that never existed (or was never canceled) cannot pass.
    observed = venue_order(venue_value, expected_cloid)
    require(report["order_id"] == observed["oid"], "reported order id differs from Hyperliquid")
    require(
        price == venue_decimal(observed["limitPx"], "Hyperliquid limitPx"),
        "reported price differs from Hyperliquid",
    )
    require(
        size == venue_decimal(observed["origSz"], "Hyperliquid origSz"),
        "reported size differs from Hyperliquid",
    )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_result.py RESULT.json", file=sys.stderr)
        return 2
    expected_wallet = os.environ.get("BLOOM_EVAL_WALLET", "")
    expected_session = os.environ.get("BLOOM_EVAL_SESSION_ID", "")
    expected_cloid = os.environ.get("BLOOM_EVAL_CLOID", "")
    try:
        report = json.loads(Path(sys.argv[1]).read_text())
        evidence = fetch_order_status(expected_wallet, expected_cloid)
        observed = venue_order(evidence, expected_cloid)
        # Querying again by the venue-assigned id prevents a proxy or malformed
        # response from making the CLOID and numeric order-id views disagree.
        oid_evidence = fetch_order_status(expected_wallet, observed["oid"])
        oid_observed = venue_order(oid_evidence, expected_cloid)
        require(
            oid_observed["oid"] == observed["oid"],
            "Hyperliquid CLOID and order-id queries returned different orders",
        )
        validate(report, expected_wallet, expected_session, expected_cloid, evidence)
    except (OSError, json.JSONDecodeError, InvalidReport) as error:
        print(f"invalid Bloom eval report: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
