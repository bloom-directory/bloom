"""Adversarial tests for the Solana transfer verifier.

Every case here answers one question: can a report that is not backed by the
exact authorized transfer be made to pass? The honest report must pass and each
variation must not.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import tempfile
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
WALLET_ID = "eval-solana"
CHAIN = "solana-mainnet"
NETWORK = "mainnet-beta"
FINGERPRINT = "a3f1c09b2e7d4856"
DERIVATION = "m/44'/501'/0'/0'"
LAMPORTS = 1_003_517
FEE = 5_000
MAX_FEE = 10_000
SLOT = 301_442_118

# `None` is a meaningful RPC result (an unfinalized transaction), so the
# "use the default" marker has to be something else.
DEFAULT = object()

ENV = {
    "BLOOM_EVAL_SOLANA_RPC_URL": "http://127.0.0.1:1/",
    "BLOOM_EVAL_SOLANA_NETWORK": NETWORK,
    "BLOOM_EVAL_SOLANA_CHAIN": CHAIN,
    "BLOOM_EVAL_SOLANA_WALLET_ID": WALLET_ID,
    "BLOOM_EVAL_SOLANA_SOURCE": SOURCE,
    "BLOOM_EVAL_SOLANA_DESTINATION": DESTINATION,
    "BLOOM_EVAL_SOLANA_KEY_FINGERPRINT": FINGERPRINT,
    "BLOOM_EVAL_SOLANA_DERIVATION_PATH": DERIVATION,
    "BLOOM_EVAL_SOLANA_LAMPORTS": str(LAMPORTS),
    "BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS": str(MAX_FEE),
}


def good_report() -> dict[str, object]:
    return {
        "schema": "bloom.eval.solana_transfer.v1",
        "status": "complete",
        "network": NETWORK,
        "chain": CHAIN,
        "wallet_id": WALLET_ID,
        "source_address": SOURCE,
        "key_fingerprint": FINGERPRINT,
        "derivation_path": DERIVATION,
        "destination": DESTINATION,
        "lamports": LAMPORTS,
        "fee_lamports": FEE,
        "blockhash": "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N",
        "pending_id": "0001",
        "signature": SIGNATURE,
        "slot": SLOT,
        "confirmation_status": "finalized",
        "outcome": "success",
        "pending_entries_after": 0,
        "confirm_failed_before_approval": True,
    }


def signatures_result(count: int = 1, err: object = None) -> list[dict[str, object]]:
    return [{"signature": SIGNATURE, "err": err} for _ in range(count)]


def transaction_result(**overrides: object) -> dict[str, object]:
    info = {
        "source": SOURCE,
        "destination": DESTINATION,
        "lamports": LAMPORTS,
    }
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
        self.env = mock.patch.dict(os.environ, ENV, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_verifier(
        self,
        report: object,
        *,
        signatures: object = DEFAULT,
        transaction: object = DEFAULT,
    ) -> int:
        path = self.root / "result.json"
        path.write_text(json.dumps(report))
        responses = {
            "getSignaturesForAddress": (
                signatures_result() if signatures is DEFAULT else signatures
            ),
            "getTransaction": (
                transaction_result() if transaction is DEFAULT else transaction
            ),
        }

        def fake_rpc(method: str, params: list[object]) -> object:
            return responses[method]

        with mock.patch.object(verify_result, "rpc", side_effect=fake_rpc):
            with mock.patch.object(verify_result.sys, "argv", ["v", str(path)]):
                return verify_result.main()

    # --- the honest case -------------------------------------------------

    def test_a_truthful_report_backed_by_the_chain_passes(self) -> None:
        self.assertEqual(self.run_verifier(good_report()), 0)

    # --- report-shape rejections ----------------------------------------

    def test_extra_field_is_rejected(self) -> None:
        report = good_report()
        report["note"] = "hello"
        self.assertEqual(self.run_verifier(report), 1)

    def test_missing_field_is_rejected(self) -> None:
        report = good_report()
        del report["slot"]
        self.assertEqual(self.run_verifier(report), 1)

    def test_incomplete_status_is_rejected(self) -> None:
        report = good_report()
        report["status"] = "partial"
        self.assertEqual(self.run_verifier(report), 1)

    def test_float_lamports_is_rejected(self) -> None:
        # Lamports are integers; a float has already lost precision.
        report = good_report()
        report["lamports"] = float(LAMPORTS)
        self.assertEqual(self.run_verifier(report), 1)

    def test_boolean_slot_is_rejected(self) -> None:
        # bool is a subclass of int in Python; the check must exclude it.
        report = good_report()
        report["slot"] = True
        self.assertEqual(self.run_verifier(report), 1)

    def test_not_observing_the_approval_boundary_is_rejected(self) -> None:
        report = good_report()
        report["confirm_failed_before_approval"] = False
        self.assertEqual(self.run_verifier(report), 1)

    def test_residual_pending_entries_are_rejected(self) -> None:
        report = good_report()
        report["pending_entries_after"] = 1
        self.assertEqual(self.run_verifier(report), 1)

    def test_unfinalized_reconciliation_is_rejected(self) -> None:
        report = good_report()
        report["confirmation_status"] = "confirmed"
        self.assertEqual(self.run_verifier(report), 1)

    def test_wrong_wallet_id_is_rejected(self) -> None:
        report = good_report()
        report["wallet_id"] = "another-wallet"
        self.assertEqual(self.run_verifier(report), 1)

    def test_wrong_derivation_path_is_rejected(self) -> None:
        report = good_report()
        report["derivation_path"] = "m/44'/501'/1'/0'"
        self.assertEqual(self.run_verifier(report), 1)

    def test_malformed_address_is_rejected(self) -> None:
        report = good_report()
        report["destination"] = "0OIl-not-base58"
        self.assertEqual(self.run_verifier(report), 1)

    def test_fee_above_the_authorized_ceiling_is_rejected(self) -> None:
        report = good_report()
        report["fee_lamports"] = MAX_FEE + 1
        self.assertEqual(
            self.run_verifier(
                report, transaction=transaction_result(meta={"fee": MAX_FEE + 1})
            ),
            1,
        )

    # --- report versus chain disagreement --------------------------------

    def test_report_disagreeing_with_the_chain_signature_is_rejected(self) -> None:
        report = good_report()
        report["signature"] = "4" * 87
        self.assertEqual(self.run_verifier(report), 1)

    def test_report_disagreeing_with_the_chain_slot_is_rejected(self) -> None:
        report = good_report()
        report["slot"] = SLOT + 1
        self.assertEqual(self.run_verifier(report), 1)

    def test_report_disagreeing_with_the_chain_fee_is_rejected(self) -> None:
        report = good_report()
        report["fee_lamports"] = FEE + 1
        self.assertEqual(self.run_verifier(report), 1)

    # --- chain-evidence rejections ---------------------------------------

    def test_a_destination_with_no_signature_is_rejected(self) -> None:
        self.assertEqual(self.run_verifier(good_report(), signatures=[]), 1)

    def test_a_destination_paid_twice_is_rejected(self) -> None:
        # The authorization is single-use; two payments mean something moved
        # funds that this trial did not authorize.
        self.assertEqual(
            self.run_verifier(good_report(), signatures=signatures_result(count=2)), 1
        )

    def test_a_failed_destination_transaction_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(
                good_report(), signatures=signatures_result(err={"InstructionError": []})
            ),
            1,
        )

    def test_an_unfinalized_transaction_is_rejected(self) -> None:
        # getTransaction at `finalized` returns null when it is not finalized.
        self.assertEqual(self.run_verifier(good_report(), transaction=None), 1)

    def test_a_transaction_that_failed_on_chain_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(
                good_report(),
                transaction=transaction_result(meta={"err": {"InstructionError": []}}),
            ),
            1,
        )

    def test_a_wrong_amount_on_chain_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(
                good_report(), transaction=transaction_result(info={"lamports": 1})
            ),
            1,
        )

    def test_a_wrong_source_on_chain_is_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(
                good_report(),
                transaction=transaction_result(info={"source": DESTINATION}),
            ),
            1,
        )

    def test_a_non_system_program_is_rejected(self) -> None:
        instruction = {
            "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "program": "spl-token",
            "parsed": {"type": "transfer", "info": {}},
        }
        self.assertEqual(
            self.run_verifier(
                good_report(), transaction=transaction_result(instructions=[instruction])
            ),
            1,
        )

    def test_a_non_transfer_system_instruction_is_rejected(self) -> None:
        instruction = copy.deepcopy(
            transaction_result()["transaction"]["message"]["instructions"][0]  # type: ignore[index]
        )
        instruction["parsed"]["type"] = "advanceNonce"  # type: ignore[index]
        self.assertEqual(
            self.run_verifier(
                good_report(), transaction=transaction_result(instructions=[instruction])
            ),
            1,
        )

    def test_extra_instructions_are_rejected(self) -> None:
        # A native transfer is exactly one instruction. Anything riding along
        # in the same transaction was not what the ceremony approved.
        base = transaction_result()["transaction"]["message"]["instructions"]  # type: ignore[index]
        self.assertEqual(
            self.run_verifier(
                good_report(),
                transaction=transaction_result(instructions=list(base) * 2),
            ),
            1,
        )

    def test_inner_instructions_are_rejected(self) -> None:
        self.assertEqual(
            self.run_verifier(
                good_report(),
                transaction=transaction_result(
                    meta={"innerInstructions": [{"index": 0, "instructions": []}]}
                ),
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
