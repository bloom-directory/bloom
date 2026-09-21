#!/usr/bin/env python3
"""Grade a Safe native transfer from chain evidence, not from the report.

The report is an agent-authored transcript. Everything that decides the reward
is read back from the chain through the verifier's own RPC: the outer receipt,
the Safe's own `ExecutionSuccess` event, the decoded `execTransaction`
arguments, the recipient's balance across the exact block, and the Safe nonce
before and after. An agent that writes a plausible report for a transfer it
never made cannot pass, and neither can one whose Safe emitted
`ExecutionFailure` inside a successful outer transaction.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "bloom.eval.safe_transfer_fork.v1"
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
UINT_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
RPC_TIMEOUT_SECONDS = 30

EXECUTION_SUCCESS_TOPIC = (
    "0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e"
)
EXECUTION_FAILURE_TOPIC = (
    "0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23"
)
EXEC_TRANSACTION_SELECTOR = "6a761202"
# `nonce()` on the Safe singleton.
NONCE_SELECTOR = "0xaffed0e0"


class InvalidReport(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidReport(message)


def rpc(method: str, params: list[Any]) -> Any:
    endpoint = os.environ.get("BLOOM_EVAL_EVM_RPC_URL", "")
    require(bool(endpoint), "BLOOM_EVAL_EVM_RPC_URL is not set")
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
            if response.status != 200:
                raise InvalidReport(f"{method} returned HTTP {response.status}")
            payload = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise InvalidReport(f"could not read the chain: {error}") from error
    if "error" in payload:
        raise InvalidReport(f"{method} failed: {payload['error']}")
    return payload.get("result")


def quantity(value: object, name: str) -> int:
    """Parse an RPC hex quantity."""
    require(
        isinstance(value, str) and value.startswith("0x") and len(value) > 2,
        f"{name} is not a hex quantity",
    )
    try:
        return int(value, 16)
    except ValueError as error:
        raise InvalidReport(f"{name} is not a hex quantity") from error


def uint_string(value: object, name: str) -> int:
    require(
        isinstance(value, str) and UINT_RE.fullmatch(value) is not None,
        f"{name} must be a canonical decimal string",
    )
    return int(value)


def address(value: object, name: str) -> str:
    require(
        isinstance(value, str) and ADDRESS_RE.fullmatch(value.lower()) is not None,
        f"{name} is not an EVM address",
    )
    return value.lower()


def tx_hash(value: object, name: str) -> str:
    require(
        isinstance(value, str) and HASH_RE.fullmatch(value.lower()) is not None,
        f"{name} is not a 32-byte hash",
    )
    return value.lower()


def word(data: str, index: int) -> str:
    """One 32-byte ABI word of `data`, which excludes any selector."""
    start = index * 64
    require(len(data) >= start + 64, "calldata is shorter than its declared arguments")
    return data[start : start + 64]


def word_address(data: str, index: int) -> str:
    value = word(data, index)
    require(value[:24] == "0" * 24, "an address argument has dirty high bytes")
    return "0x" + value[24:]


def word_uint(data: str, index: int) -> int:
    return int(word(data, index), 16)


def decoded_exec_transaction(input_hex: object) -> dict[str, Any]:
    """Decode the outer `execTransaction` call the executor broadcast.

    Only the static head is decoded. `data` and `signatures` are dynamic; their
    offsets are read so that the bytes length of `data` can be checked, which is
    what proves the inner call carried no calldata.
    """
    require(isinstance(input_hex, str) and input_hex.startswith("0x"), "no transaction input")
    body = input_hex[2:].lower()
    require(
        body[:8] == EXEC_TRANSACTION_SELECTOR,
        "outer transaction does not call execTransaction",
    )
    args = body[8:]
    data_offset = word_uint(args, 2)
    require(data_offset % 32 == 0, "data offset is not word-aligned")
    data_length_at = data_offset * 2
    require(len(args) >= data_length_at + 64, "data offset points past the calldata")
    return {
        "to": word_address(args, 0),
        "value": word_uint(args, 1),
        "data_length": int(args[data_length_at : data_length_at + 64], 16),
        "operation": word_uint(args, 3),
        "safe_tx_gas": word_uint(args, 4),
        "base_gas": word_uint(args, 5),
        "gas_price": word_uint(args, 6),
        "gas_token": word_address(args, 7),
        "refund_receiver": word_address(args, 8),
    }


def safe_nonce(safe: str, block: str) -> int:
    result = rpc("eth_call", [{"to": safe, "data": NONCE_SELECTOR}, block])
    require(isinstance(result, str) and len(result) == 66, "Safe nonce read is malformed")
    return int(result, 16)


def balance(account: str, block: str) -> int:
    return quantity(rpc("eth_getBalance", [account, block]), "balance")


def chain_evidence(report: dict[str, object], expected: dict[str, str]) -> None:
    """Everything that decides the reward, read from the chain."""
    safe = address(expected["safe_address"], "expected safe_address")
    recipient = address(expected["recipient"], "expected recipient")
    value = int(expected["value_wei"])
    outer = tx_hash(report["execution_tx_hash"], "execution_tx_hash")
    inner = tx_hash(report["safe_tx_hash"], "safe_tx_hash")

    receipt = rpc("eth_getTransactionReceipt", [outer])
    require(isinstance(receipt, dict), "the reported outer transaction has no receipt")
    require(quantity(receipt.get("status"), "receipt status") == 1, "outer transaction reverted")
    require(
        address(receipt.get("to"), "receipt to") == safe,
        "outer transaction did not call this Safe",
    )
    block_number = quantity(receipt.get("blockNumber"), "receipt blockNumber")
    block_hex = hex(block_number)
    previous_hex = hex(block_number - 1)

    # A Safe catches a failing inner call and still returns successfully, so a
    # status-1 receipt is not evidence that the transfer happened.
    logs = receipt.get("logs")
    require(isinstance(logs, list), "receipt has no logs")
    safe_logs = [
        log
        for log in logs
        if isinstance(log, dict) and address(log.get("address"), "log address") == safe
    ]
    failures = [
        log for log in safe_logs if (log.get("topics") or [None])[0] == EXECUTION_FAILURE_TOPIC
    ]
    require(not failures, "the Safe emitted ExecutionFailure: the inner call did not succeed")
    successes = [
        log for log in safe_logs if (log.get("topics") or [None])[0] == EXECUTION_SUCCESS_TOPIC
    ]
    require(len(successes) == 1, "expected exactly one ExecutionSuccess from this Safe")
    emitted = successes[0].get("data")
    require(
        isinstance(emitted, str) and len(emitted) >= 2 + 64,
        "ExecutionSuccess carries no Safe transaction hash",
    )
    require(
        "0x" + emitted[2:66].lower() == inner,
        "the Safe executed a different Safe transaction hash than the report names",
    )

    # The exact action, decoded from the bytes the executor actually broadcast.
    transaction = rpc("eth_getTransactionByHash", [outer])
    require(isinstance(transaction, dict), "the outer transaction is not on chain")
    call = decoded_exec_transaction(transaction.get("input"))
    require(call["to"] == recipient, "execTransaction targeted a different recipient")
    require(call["value"] == value, "execTransaction moved a different amount")
    require(call["data_length"] == 0, "a native transfer must carry no calldata")
    require(call["operation"] == 0, "a native transfer must be a call, not a delegatecall")
    require(
        call["safe_tx_gas"] == 0 and call["base_gas"] == 0 and call["gas_price"] == 0,
        "Safe gas reimbursement fields must be zero",
    )
    require(
        int(call["gas_token"], 16) == 0 and int(call["refund_receiver"], 16) == 0,
        "Safe gas token and refund receiver must be unset",
    )

    # Effects: the recipient gained exactly the transfer, and the Safe consumed
    # exactly one nonce. `value` is asserted against the balance delta rather
    # than only against the calldata so a Safe funded by some other path in the
    # same block cannot pass.
    require(
        balance(recipient, block_hex) - balance(recipient, previous_hex) == value,
        "the recipient's balance did not change by exactly the transfer",
    )
    before = safe_nonce(safe, previous_hex)
    after = safe_nonce(safe, block_hex)
    require(after == before + 1, "the Safe nonce did not advance by exactly one")
    reported_nonce = report["safe_nonce"]
    require(
        isinstance(reported_nonce, int) and reported_nonce == before,
        "the reported Safe nonce is not the one this transaction consumed",
    )


def validate(report_value: object, expected: dict[str, str]) -> None:
    require(isinstance(report_value, dict), "report must be an object")
    report: dict[str, object] = report_value
    required = {
        "schema",
        "status",
        "chain_id",
        "wallet_id",
        "safe_id",
        "safe_address",
        "transaction_id",
        "recipient",
        "value_wei",
        "safe_nonce",
        "safe_tx_hash",
        "execution_tx_hash",
        "phase",
    }
    require(set(report) == required, "report fields do not exactly match the v1 schema")
    require(report["schema"] == SCHEMA, "wrong schema")
    require(report["status"] == "complete", "task is not complete")
    # The Petal's own terminal phase. "executed" is the only outbox state that
    # means the receipt was seen and reconciled; "execution_staged" is a
    # broadcast that nobody has confirmed.
    require(report["phase"] == "executed", "the transaction was not reconciled to executed")
    require(
        isinstance(report["chain_id"], int)
        and report["chain_id"] == int(expected["chain_id"]),
        "wrong chain id",
    )
    for field in ("wallet_id", "safe_id", "transaction_id"):
        value = report[field]
        require(
            isinstance(value, str) and SEGMENT_RE.fullmatch(value) is not None,
            f"{field} is not a safe path segment",
        )
        require(value == expected[field], f"wrong {field}")
    require(
        address(report["safe_address"], "safe_address") == address(
            expected["safe_address"], "expected safe_address"
        ),
        "wrong Safe address",
    )
    require(
        address(report["recipient"], "recipient") == address(
            expected["recipient"], "expected recipient"
        ),
        "wrong recipient",
    )
    require(
        uint_string(report["value_wei"], "value_wei") == int(expected["value_wei"]),
        "wrong transfer amount",
    )
    # Two hashes, never interchangeable: one authorizes, one settles.
    require(
        tx_hash(report["safe_tx_hash"], "safe_tx_hash")
        != tx_hash(report["execution_tx_hash"], "execution_tx_hash"),
        "safe_tx_hash and execution_tx_hash must not be the same hash",
    )
    chain_evidence(report, expected)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_result.py RESULT.json", file=sys.stderr)
        return 2
    expected = {
        "chain_id": os.environ.get("BLOOM_EVAL_CHAIN_ID", ""),
        "wallet_id": os.environ.get("BLOOM_EVAL_WALLET_ID", ""),
        "safe_id": os.environ.get("BLOOM_EVAL_SAFE_ID", ""),
        "safe_address": os.environ.get("BLOOM_EVAL_SAFE_ADDRESS", ""),
        "transaction_id": os.environ.get("BLOOM_EVAL_TRANSACTION_ID", ""),
        "recipient": os.environ.get("BLOOM_EVAL_RECIPIENT", ""),
        "value_wei": os.environ.get("BLOOM_EVAL_VALUE_WEI", ""),
    }
    try:
        for name, value in expected.items():
            require(bool(value), f"the harness did not supply {name}")
        require(
            UINT_RE.fullmatch(expected["chain_id"]) is not None
            and UINT_RE.fullmatch(expected["value_wei"]) is not None,
            "the harness supplied a malformed chain id or amount",
        )
        report = json.loads(Path(sys.argv[1]).read_text())
        validate(report, expected)
    except (OSError, json.JSONDecodeError, InvalidReport) as error:
        print(f"invalid Bloom eval report: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
