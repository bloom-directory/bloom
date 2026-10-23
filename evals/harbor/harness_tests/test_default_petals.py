import copy
import importlib.util
import unittest
from pathlib import Path

from harness.clarification import asks_for_selection
from harness.solana_transfer import matching_transfer

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "polymarket_verifier",
    ROOT / "tasks/polymarket-limit-order-proposal/tests/verify_result.py",
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ProposalTests(unittest.TestCase):
    def setUp(self):
        self.expected = {
            "wallet": "harbor",
            "condition_id": "0x" + "1" * 64,
            "token_id": "123",
            "side": "BUY",
            "order_type": "GTC",
            "amount_micro": 5_000_000,
            "limit_price_micro": 10_000,
            "size_micro": 500_000_000,
            "maker_micro": 5_000_000,
            "taker_micro": 500_000_000,
        }
        self.draft = self.expected | {
            "status": "review",
            "marketable": False,
            "salt": None,
            "clob_order_id": None,
        }

    def test_unsigned_order_matches_ids_and_base_units(self):
        verifier.validate(self.draft, self.expected)

    def test_wrong_identity_terms_and_posted_orders_are_rejected(self):
        mutations = {
            "wallet": "other",
            "condition_id": "0x" + "2" * 64,
            "token_id": "456",
            "side": "sell",
            "order_type": "FAK",
            "amount_micro": 5_000_001,
            "limit_price_micro": 10_001,
            "size_micro": 499_999_999,
            "maker_micro": 5_000_001,
            "taker_micro": 499_999_999,
            "status": "posted",
            "marketable": True,
            "salt": "1",
            "clob_order_id": "order",
        }
        for key, value in mutations.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                verifier.validate(self.draft | {key: value}, self.expected)

    def test_missing_ids_and_numeric_coercion_cannot_borrow_display_labels(self):
        for key in self.expected:
            draft = dict(self.draft)
            del draft[key]
            draft.update(question="correct market", outcome="Yes")
            with self.subTest(key=key), self.assertRaises(ValueError):
                verifier.validate(draft, self.expected)
        with self.assertRaises(ValueError):
            verifier.validate(self.draft | {"amount_micro": "5000000"}, self.expected)


class ApprovalTests(unittest.TestCase):
    def test_wrong_account_chain_or_fee_never_matches(self):
        expected = {
            "genesis_hash": "genesis",
            "fee_payer": "source",
            "destination": "dest",
            "lamports": 1_000_000,
            "account_fingerprint": "abcd",
            "account_derivation_path": "m/44'/501'/0'/0'",
        }
        intent = expected | {"fee_lamports": 5000}
        self.assertTrue(matching_transfer(intent, expected, 10000))
        for key, value in expected.items():
            changed = copy.deepcopy(intent)
            changed[key] = "other" if isinstance(value, str) else value + 1
            with self.subTest(key=key):
                self.assertFalse(matching_transfer(changed, expected, 10000))
            del changed[key]
            self.assertFalse(matching_transfer(changed, expected, 10000))
        for fee in (-1, True, "5000", 10001, None):
            self.assertFalse(
                matching_transfer(intent | {"fee_lamports": fee}, expected, 10000)
            )


class ClarificationTests(unittest.TestCase):
    def trajectory(self, message, **changes):
        return {"steps": [{"source": "agent", "message": message} | changes]}

    def test_question_must_select_account_and_network(self):
        self.assertTrue(
            asks_for_selection(
                self.trajectory("Which wallet and network should I use?"), "hyperliquid"
            )
        )
        for message in (
            "Done.",
            "Proceed?",
            "Which wallet?",
            "Which chain?",
            "I used the default wallet and network.",
        ):
            self.assertFalse(
                asks_for_selection(self.trajectory(message), "near-intents")
            )

    def test_tool_arguments_and_user_questions_are_not_agent_questions(self):
        self.assertFalse(
            asks_for_selection(
                self.trajectory(
                    "Which account and chain?", tool_calls=[{"function_name": "bash"}]
                ),
                "solana",
            )
        )
        self.assertFalse(
            asks_for_selection(
                {"steps": [{"source": "user", "message": "Which wallet and chain?"}]},
                "solana",
            )
        )
