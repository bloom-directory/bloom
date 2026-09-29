#!/usr/bin/env python3
"""Validate the report against independent Hyperliquid maxBuilderFee evidence."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "bloom.eval.hyperliquid_approve_builder_fee.v1"
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
WALLET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
HYPERLIQUID_INFO_URLS = {
    "mainnet": "https://api.hyperliquid.xyz/info",
    "testnet": "https://api.hyperliquid-testnet.xyz/info",
}
VENUE_TIMEOUT_SECONDS = 30


class InvalidReport(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidReport(message)


def fetch_max_builder_fee(user: str, builder: str, network: str) -> object:
    """Read the live approved fee from Hyperliquid, outside the agent's report."""
    default_endpoint = HYPERLIQUID_INFO_URLS.get(network)
    if default_endpoint is None:
        raise InvalidReport(f"unsupported network {network!r}")
    endpoint = os.environ.get("BLOOM_EVAL_HYPERLIQUID_INFO_URL", default_endpoint)
    body = json.dumps(
        {"type": "maxBuilderFee", "user": user, "builder": builder},
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
                    f"Hyperliquid maxBuilderFee query returned HTTP {response.status}"
                )
            return json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise InvalidReport(f"could not read Hyperliquid maxBuilderFee: {error}") from error


def validate(
    report_value: object,
    expected_network: str,
    expected_wallet: str,
    expected_wallet_id: str,
    expected_builder: str,
    expected_max_fee_tenths_bps: int,
    expected_nonce: int,
    venue_max_fee_tenths_bps: int,
) -> None:
    if not isinstance(report_value, dict):
        raise InvalidReport("report must be an object")
    report: dict[str, object] = report_value
    required = {
        "schema", "status", "network", "wallet", "wallet_id", "builder",
        "max_fee_tenths_bps", "nonce", "hyperliquid_response",
        "observed_max_builder_fee",
    }
    require(set(report) == required, "report fields do not exactly match the v1 schema")
    require(report["schema"] == SCHEMA, "wrong schema")
    require(report["status"] == "complete", "task is not complete")
    require(report["network"] == expected_network, "wrong network")
    require(
        isinstance(report["wallet"], str) and ADDRESS_RE.fullmatch(report["wallet"]) is not None,
        "invalid wallet address",
    )
    require(report["wallet"] == expected_wallet, "wrong wallet")
    require(
        isinstance(report["wallet_id"], str) and WALLET_ID_RE.fullmatch(report["wallet_id"]) is not None,
        "invalid wallet id",
    )
    require(report["wallet_id"] == expected_wallet_id, "wrong wallet id")
    require(
        isinstance(report["builder"], str) and ADDRESS_RE.fullmatch(report["builder"]) is not None,
        "invalid builder address",
    )
    require(report["builder"] == expected_builder, "wrong builder")
    require(
        isinstance(report["max_fee_tenths_bps"], int)
        and not isinstance(report["max_fee_tenths_bps"], bool)
        and report["max_fee_tenths_bps"] == expected_max_fee_tenths_bps,
        "wrong max_fee_tenths_bps",
    )
    require(
        isinstance(report["nonce"], int)
        and not isinstance(report["nonce"], bool)
        and report["nonce"] == expected_nonce,
        "wrong nonce",
    )

    hyperliquid_response = report["hyperliquid_response"]
    require(isinstance(hyperliquid_response, dict), "hyperliquid_response must be an object")
    require(
        hyperliquid_response.get("status") == "ok",
        "Hyperliquid did not accept the approveBuilderFee action",
    )

    observed = report["observed_max_builder_fee"]
    require(
        isinstance(observed, int) and not isinstance(observed, bool),
        "observed_max_builder_fee must be an integer",
    )
    require(
        observed >= expected_max_fee_tenths_bps,
        "reported observed_max_builder_fee is below the requested approval",
    )

    # The report is agent-authored. Grade the actual approval from Hyperliquid's
    # own maxBuilderFee record, found independently by this verifier, not from
    # the agent's self-reported reading of it. A fabricated report for an
    # approval that never took effect cannot pass.
    require(
        venue_max_fee_tenths_bps >= expected_max_fee_tenths_bps,
        "Hyperliquid does not currently report the requested approval for this builder",
    )
    require(
        report["observed_max_builder_fee"] == venue_max_fee_tenths_bps,
        "reported observed_max_builder_fee differs from the independently queried value",
    )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_result.py RESULT.json", file=sys.stderr)
        return 2
    expected_network = os.environ.get("BLOOM_EVAL_NETWORK", "")
    expected_wallet = os.environ.get("BLOOM_EVAL_WALLET", "")
    expected_wallet_id = os.environ.get("BLOOM_EVAL_WALLET_ID", "")
    expected_builder = os.environ.get("BLOOM_EVAL_BUILDER", "")
    try:
        expected_max_fee_tenths_bps = int(
            os.environ.get("BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS", "")
        )
        expected_nonce = int(os.environ.get("BLOOM_EVAL_APPROVAL_NONCE", ""))
    except ValueError:
        print(
            "invalid Bloom eval report: BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS and "
            "BLOOM_EVAL_APPROVAL_NONCE must be integers",
            file=sys.stderr,
        )
        return 1
    try:
        report = json.loads(Path(sys.argv[1]).read_text())
        venue_value = fetch_max_builder_fee(expected_wallet, expected_builder, expected_network)
        require(
            isinstance(venue_value, int) and not isinstance(venue_value, bool),
            "Hyperliquid maxBuilderFee response is not an integer",
        )
        validate(
            report,
            expected_network,
            expected_wallet,
            expected_wallet_id,
            expected_builder,
            expected_max_fee_tenths_bps,
            expected_nonce,
            venue_value,
        )
    except (OSError, json.JSONDecodeError, InvalidReport) as error:
        print(f"invalid Bloom eval report: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
