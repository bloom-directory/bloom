#!/usr/bin/env python3
"""Grade a native ETH transfer from the local fork's own state.

Runs on the trusted host: the agent container has no route to the fork. A
fresh destination holding exactly the amount, and a source nonce of exactly
one, prove one transfer of the right size to the right address.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from projection import ProjectionReader


class InvalidTransfer(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidTransfer(message)


def need(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise InvalidTransfer(f"{name} is not set for the verifier")
    return value


def rpc(method: str, params: list) -> int:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        need("BLOOM_EVAL_EVM_RPC_URL"), data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise InvalidTransfer(f"could not call {method}: {error}") from error
    result = payload.get("result")
    require(isinstance(result, str) and result.startswith("0x"), f"{method} failed: {payload}")
    return int(result, 16)


def verify() -> None:
    outbox = (
        f"wallets/{need('BLOOM_EVAL_EVM_WALLET_ID')}/{need('BLOOM_EVAL_EVM_ACCOUNT')}"
        f"/chains/{need('BLOOM_EVAL_EVM_CHAIN')}/outbox"
    )
    reader = ProjectionReader()
    # A missing listing is not evidence that pending is empty.
    require("pending" in reader.entries(outbox), "outbox has no pending listing")
    require(not reader.entries(outbox + "/pending"), "a transfer is still pending")
    source, destination = need("BLOOM_EVAL_EVM_SOURCE"), need("BLOOM_EVAL_EVM_DESTINATION")
    require(rpc("eth_getTransactionCount", [source, "latest"]) == 1, "the source did not send exactly one transaction")
    balance = rpc("eth_getBalance", [destination, "latest"])
    require(balance == int(need("BLOOM_EVAL_EVM_WEI")), f"destination holds {balance} wei, not the amount")


def main() -> int:
    try:
        verify()
    except InvalidTransfer as error:
        print(f"invalid Bloom transfer: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"projection unavailable: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
