"""Adversarial tests for independent Solana transfer verification."""

from __future__ import annotations

import copy
import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock

VERIFIER = Path(__file__).parents[1] / "tasks/solana-transfer/tests/verify_result.py"
SPEC = importlib.util.spec_from_file_location("solana_verify_result", VERIFIER)
assert SPEC is not None and SPEC.loader is not None
verify_result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_result)

SOURCE = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
DESTINATION = "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu"
SIGNATURE = "5" * 87
LAMPORTS = 1_003_517
FEE = 5_000
SLOT = 301_442_118
DEFAULT = object()

ENV = {
    "BLOOM_EVAL_SOLANA_RPC_URL": "http://127.0.0.1:1/",
    "BLOOM_EVAL_SOLANA_SOURCE": SOURCE,
    "BLOOM_EVAL_SOLANA_DESTINATION": DESTINATION,
    "BLOOM_EVAL_SOLANA_LAMPORTS": str(LAMPORTS),
    "BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS": "10000",
}


def signatures_result(count: int = 1, err: object = None) -> list[dict[str, object]]:
    return [{"signature": SIGNATURE, "err": err} for _ in range(count)]


def transaction_result(**overrides: object) -> dict[str, object]:
    info = {"source": SOURCE, "destination": DESTINATION, "lamports": LAMPORTS}
    info.update(overrides.pop("info", {}))  # type: ignore[arg-type]
    meta = {"err": None, "fee": FEE, "innerInstructions": []}
    meta.update(overrides.pop("meta", {}))  # type: ignore[arg-type]
    instructions = overrides.pop(
        "instructions",
        [
            {
                "programId": "11111111111111111111111111111111",
                "program": "system",
                "parsed": {"type": "transfer", "info": info},
            }
        ],
    )
    result = {
        "slot": SLOT,
        "meta": meta,
        "transaction": {"message": {"instructions": instructions}},
    }
    result.update(overrides)
    return result


class SolanaVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = mock.patch.dict(os.environ, ENV, clear=False)
        environment.start()
        self.addCleanup(environment.stop)

    def run_verifier(
        self,
        *,
        signatures: object = DEFAULT,
        transaction: object = DEFAULT,
        environment: dict[str, str] | None = None,
    ) -> int:
        responses = {
            "getSignaturesForAddress": (
                signatures_result() if signatures is DEFAULT else signatures
            ),
            "getTransaction": (
                transaction_result() if transaction is DEFAULT else transaction
            ),
        }

        def fake_rpc(method: str, _params: list[object]) -> object:
            return responses[method]

        with mock.patch.dict(os.environ, environment or {}, clear=False):
            with mock.patch.object(verify_result, "rpc", side_effect=fake_rpc):
                with mock.patch.object(verify_result.sys, "argv", ["verify_result.py"]):
                    return verify_result.main()

    def test_the_exact_finalized_transfer_passes(self) -> None:
        self.assertEqual(self.run_verifier(), 0)

    def test_no_destination_signature_is_rejected(self) -> None:
        self.assertEqual(self.run_verifier(signatures=[]), 1)

    def test_a_destination_paid_twice_is_rejected(self) -> None:
        self.assertEqual(self.run_verifier(signatures=signatures_result(2)), 1)

    def test_a_failed_destination_transaction_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(signatures=signatures_result(err={"InstructionError": []})),
            1,
        )

    def test_an_unfinalized_transaction_is_rejected(self) -> None:
        self.assertEqual(self.run_verifier(transaction=None), 1)

    def test_a_transaction_failure_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(
                transaction=transaction_result(meta={"err": {"InstructionError": []}})
            ),
            1,
        )

    def test_wrong_amount_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(transaction=transaction_result(info={"lamports": 1})), 1
        )

    def test_wrong_source_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(transaction=transaction_result(info={"source": DESTINATION})),
            1,
        )

    def test_wrong_destination_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(transaction=transaction_result(info={"destination": SOURCE})),
            1,
        )

    def test_fee_above_the_ceiling_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(transaction=transaction_result(meta={"fee": 10_001})), 1
        )

    def test_a_non_system_program_is_rejected(self) -> None:
        instruction = {
            "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "program": "spl-token",
            "parsed": {"type": "transfer", "info": {}},
        }
        self.assertEqual(
            self.run_verifier(transaction=transaction_result(instructions=[instruction])),
            1,
        )

    def test_a_non_transfer_system_instruction_is_rejected(self) -> None:
        instruction = copy.deepcopy(
            transaction_result()["transaction"]["message"]["instructions"][0]  # type: ignore[index]
        )
        instruction["parsed"]["type"] = "advanceNonce"  # type: ignore[index]
        self.assertEqual(
            self.run_verifier(transaction=transaction_result(instructions=[instruction])),
            1,
        )

    def test_extra_instructions_are_rejected(self) -> None:
        base = transaction_result()["transaction"]["message"]["instructions"]  # type: ignore[index]
        self.assertEqual(
            self.run_verifier(transaction=transaction_result(instructions=list(base) * 2)),
            1,
        )

    def test_inner_instructions_are_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(
                transaction=transaction_result(
                    meta={"innerInstructions": [{"index": 0, "instructions": []}]}
                )
            ),
            1,
        )

    def test_boolean_slot_is_rejected(self) -> None:
        self.assertEqual(self.run_verifier(transaction=transaction_result(slot=True)), 1)

    def test_expected_amount_must_match_chain(self) -> None:
        self.assertEqual(
            self.run_verifier(environment={"BLOOM_EVAL_SOLANA_LAMPORTS": "1"}), 1
        )


if __name__ == "__main__":
    unittest.main()
