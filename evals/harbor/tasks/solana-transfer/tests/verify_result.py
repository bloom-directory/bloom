#!/usr/bin/env python3
"""Grade a native SOL transfer from independent on-chain evidence."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

BASE58 = "[1-9A-HJ-NP-Za-km-z]"
ADDRESS_RE = re.compile(f"^{BASE58}{{32,44}}$")
SIGNATURE_RE = re.compile(f"^{BASE58}{{86,88}}$")
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
RPC_TIMEOUT_SECONDS = 30


class InvalidTransfer(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidTransfer(message)


def lamports(value: object, name: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{name} must be an integer number of lamports",
    )
    assert isinstance(value, int)
    require(value >= 0, f"{name} must not be negative")
    return value


def need(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise InvalidTransfer(f"{name} is not set for the verifier")
    return value


def rpc(method: str, params: list[Any]) -> Any:
    endpoint = need("BLOOM_EVAL_SOLANA_RPC_URL")
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=RPC_TIMEOUT_SECONDS) as response:
            require(response.status == 200, f"Solana {method} returned HTTP {response.status}")
            payload = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise InvalidTransfer(f"could not call Solana {method}: {error}") from error
    if "error" in payload:
        raise InvalidTransfer(f"Solana {method} failed: {payload['error']}")
    require("result" in payload, f"Solana {method} returned no result")
    return payload["result"]


def verify() -> None:
    source = need("BLOOM_EVAL_SOLANA_SOURCE")
    destination = need("BLOOM_EVAL_SOLANA_DESTINATION")
    require(ADDRESS_RE.fullmatch(source) is not None, "expected source is malformed")
    require(
        ADDRESS_RE.fullmatch(destination) is not None,
        "expected destination is malformed",
    )
    try:
        expected_lamports = int(need("BLOOM_EVAL_SOLANA_LAMPORTS"))
        max_fee = int(need("BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS"))
    except ValueError as error:
        raise InvalidTransfer(f"lamport expectation is not an integer: {error}") from error

    signatures = rpc("getSignaturesForAddress", [destination, {"limit": 10}])
    require(isinstance(signatures, list), "signature history is not a list")
    require(
        len(signatures) == 1,
        f"fresh destination has {len(signatures)} signatures; expected exactly one",
    )
    entry = signatures[0]
    require(isinstance(entry, dict), "signature entry is not an object")
    require(entry.get("err") is None, "the destination transaction failed")
    signature = entry.get("signature")
    require(
        isinstance(signature, str) and SIGNATURE_RE.fullmatch(signature) is not None,
        "destination signature is malformed",
    )

    result = rpc(
        "getTransaction",
        [
            signature,
            {
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0,
                "commitment": "finalized",
            },
        ],
    )
    require(isinstance(result, dict), "transaction is not finalized")
    meta = result.get("meta")
    require(isinstance(meta, dict), "transaction has no metadata")
    require(meta.get("err") is None, f"transaction failed on chain: {meta.get('err')}")
    fee = lamports(meta.get("fee"), "on-chain fee")
    require(fee <= max_fee, "on-chain fee exceeds the authorized ceiling")
    require(not meta.get("innerInstructions"), "transaction carries inner instructions")

    transaction = result.get("transaction")
    require(isinstance(transaction, dict), "transaction body is missing")
    message = transaction.get("message")
    require(isinstance(message, dict), "transaction message is missing")
    instructions = message.get("instructions")
    require(isinstance(instructions, list), "transaction instructions are missing")
    require(len(instructions) == 1, f"expected one instruction, found {len(instructions)}")
    instruction = instructions[0]
    require(isinstance(instruction, dict), "instruction is not an object")
    require(instruction.get("programId") == SYSTEM_PROGRAM_ID, "not a System transfer")
    require(instruction.get("program") == "system", "instruction is not parsed as system")
    parsed = instruction.get("parsed")
    require(isinstance(parsed, dict) and parsed.get("type") == "transfer", "not a transfer")
    info = parsed.get("info")
    require(isinstance(info, dict), "transfer info is missing")
    require(info.get("source") == source, "transfer source is not the eval wallet")
    require(info.get("destination") == destination, "transfer destination is wrong")
    require(
        lamports(info.get("lamports"), "on-chain lamports") == expected_lamports,
        "transfer amount is wrong",
    )
    slot = result.get("slot")
    require(
        isinstance(slot, int) and not isinstance(slot, bool) and slot > 0,
        "transaction slot is missing",
    )


def main() -> int:
    if len(sys.argv) != 1:
        print("usage: verify_result.py", file=sys.stderr)
        return 2
    try:
        verify()
    except InvalidTransfer as error:
        print(f"invalid Bloom transfer: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
