"""Chain-evidence branches the deterministic fixture server cannot produce.

`scripts/test-harbor-evals.sh` drives the verifier against one fixed chain, so
it exercises the happy path and every report-shaped mutation. These tests vary
the chain instead: a Safe that swallowed a failing inner call, a receipt with no
Safe event at all, a delegatecall, and gas reimbursement turned back on.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

VERIFIER = Path(__file__).parents[1] / "tasks/safe-transfer-fork/tests/verify_result.py"
SPEC = importlib.util.spec_from_file_location("safe_transfer_verify_result", VERIFIER)
assert SPEC is not None and SPEC.loader is not None
verify_result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_result)

SAFE = "0x" + "a1" * 20
RECIPIENT = "0x" + "40" * 20
OUTER = "0x" + "e1" * 32
INNER = "0x" + "8c" * 32
VALUE = 500000000000000000
BLOCK = 0x100

EXECUTION_SUCCESS = verify_result.EXECUTION_SUCCESS_TOPIC
EXECUTION_FAILURE = verify_result.EXECUTION_FAILURE_TOPIC

# execTransaction(RECIPIENT, VALUE, "", CALL, 0, 0, 0, 0x0, 0x0, <65-byte sig>)
def exec_input(
    *,
    to: str = RECIPIENT,
    value: int = VALUE,
    operation: int = 0,
    safe_tx_gas: int = 0,
    gas_token: str = "0x" + "00" * 20,
    data: bytes = b"",
) -> str:
    head_words = 10
    data_offset = head_words * 32
    signature = b"\x11" * 65
    signature_offset = data_offset + 32 + 32 * ((len(data) + 31) // 32)

    def padded(raw: bytes) -> str:
        chunks = 32 * ((len(raw) + 31) // 32)
        return raw.ljust(chunks, b"\x00").hex()

    words = [
        f"{int(to, 16):064x}",
        f"{value:064x}",
        f"{data_offset:064x}",
        f"{operation:064x}",
        f"{safe_tx_gas:064x}",
        f"{0:064x}",
        f"{0:064x}",
        f"{int(gas_token, 16):064x}",
        f"{0:064x}",
        f"{signature_offset:064x}",
    ]
    tail = f"{len(data):064x}" + padded(data)
    tail += f"{len(signature):064x}" + padded(signature)
    return "0x6a761202" + "".join(words) + tail


class SafeTransferEvidenceTests(unittest.TestCase):
    expected = {
        "chain_id": "1",
        "wallet_id": "safeowner",
        "safe_id": "treasury",
        "safe_address": SAFE,
        "transaction_id": "payment1",
        "recipient": RECIPIENT,
        "value_wei": str(VALUE),
    }

    def report(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "bloom.eval.safe_transfer_fork.v1",
            "status": "complete",
            "chain_id": 1,
            "wallet_id": "safeowner",
            "safe_id": "treasury",
            "safe_address": SAFE,
            "transaction_id": "payment1",
            "recipient": RECIPIENT,
            "value_wei": str(VALUE),
            "safe_nonce": 0,
            "safe_tx_hash": INNER,
            "execution_tx_hash": OUTER,
            "phase": "executed",
        }
        value.update(changes)
        return value

    def chain(
        self,
        *,
        logs: list[dict[str, Any]] | None = None,
        input_hex: str | None = None,
        recipient_delta: int = VALUE,
        nonce_after: int = 1,
        receipt_to: str = SAFE,
        receipt_status: str = "0x1",
    ):
        if logs is None:
            logs = [
                {
                    "address": SAFE,
                    "topics": [EXECUTION_SUCCESS],
                    "data": INNER + "00" * 32,
                }
            ]
        if input_hex is None:
            input_hex = exec_input()

        def fake_rpc(method: str, params: list[Any]) -> Any:
            if method == "eth_getTransactionReceipt":
                return {
                    "status": receipt_status,
                    "to": receipt_to,
                    "blockNumber": hex(BLOCK),
                    "logs": logs,
                }
            if method == "eth_getTransactionByHash":
                return {"input": input_hex}
            if method == "eth_getBalance":
                return hex(recipient_delta if params[1] == hex(BLOCK) else 0)
            if method == "eth_call":
                return "0x" + f"{(nonce_after if params[1] == hex(BLOCK) else 0):064x}"
            raise AssertionError(f"unexpected RPC {method}")

        return mock.patch.object(verify_result, "rpc", side_effect=fake_rpc)

    def assert_rejected(self, fragment: str, **chain: Any) -> None:
        with self.chain(**chain):
            with self.assertRaises(verify_result.InvalidReport) as caught:
                verify_result.validate(self.report(), self.expected)
        self.assertIn(fragment, str(caught.exception))

    def test_a_consistent_transfer_passes(self) -> None:
        with self.chain():
            verify_result.validate(self.report(), self.expected)

    def test_a_swallowed_inner_failure_is_not_a_transfer(self) -> None:
        """A Safe returns successfully even when its inner call reverts, so a
        status-1 outer receipt proves nothing on its own."""
        self.assert_rejected(
            "ExecutionFailure",
            logs=[
                {
                    "address": SAFE,
                    "topics": [EXECUTION_FAILURE],
                    "data": INNER + "00" * 32,
                }
            ],
        )

    def test_a_receipt_without_a_safe_event_is_rejected(self) -> None:
        self.assert_rejected("exactly one ExecutionSuccess", logs=[])

    def test_an_event_from_another_contract_does_not_count(self) -> None:
        self.assert_rejected(
            "exactly one ExecutionSuccess",
            logs=[
                {
                    "address": "0x" + "bb" * 20,
                    "topics": [EXECUTION_SUCCESS],
                    "data": INNER + "00" * 32,
                }
            ],
        )

    def test_an_event_for_another_safe_transaction_is_rejected(self) -> None:
        self.assert_rejected(
            "different Safe transaction hash",
            logs=[
                {
                    "address": SAFE,
                    "topics": [EXECUTION_SUCCESS],
                    "data": "0x" + "cd" * 32 + "00" * 32,
                }
            ],
        )

    def test_a_delegatecall_is_not_a_native_transfer(self) -> None:
        self.assert_rejected("delegatecall", input_hex=exec_input(operation=1))

    def test_calldata_is_not_a_native_transfer(self) -> None:
        self.assert_rejected("no calldata", input_hex=exec_input(data=b"\xde\xad\xbe\xef"))

    def test_gas_reimbursement_must_stay_off(self) -> None:
        self.assert_rejected(
            "gas reimbursement", input_hex=exec_input(safe_tx_gas=21000)
        )
        self.assert_rejected(
            "gas token", input_hex=exec_input(gas_token="0x" + "cc" * 20)
        )

    def test_the_recipient_must_actually_receive_the_amount(self) -> None:
        self.assert_rejected("balance did not change", recipient_delta=VALUE - 1)

    def test_the_safe_must_consume_exactly_one_nonce(self) -> None:
        self.assert_rejected("advance by exactly one", nonce_after=2)

    def test_an_outer_transaction_to_another_contract_is_rejected(self) -> None:
        self.assert_rejected("did not call this Safe", receipt_to="0x" + "bb" * 20)

    def test_a_reverted_outer_transaction_is_rejected(self) -> None:
        self.assert_rejected("reverted", receipt_status="0x0")


if __name__ == "__main__":
    unittest.main()
