import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness.clarification import asks_for_selection
from harness.core import EvalError, _agent_spec
from harness.disposable import CeremonyDriver
from harness.solana_transfer import matching_transfer

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "polymarket_verifier",
    ROOT / "tasks/polymarket-limit-order-proposal/tests/verify_result.py",
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
check_spec = importlib.util.spec_from_file_location(
    "clarification_check", ROOT / "tasks/clarification-check.py"
)
checker = importlib.util.module_from_spec(check_spec)
check_spec.loader.exec_module(checker)


class HostBoundaryTests(unittest.TestCase):
    def test_failed_driver_attempts_still_advance_the_counter(self):
        with tempfile.TemporaryDirectory() as directory:
            seed = Path(directory) / "seed"
            seed.write_text("test-only-seed")
            seed.chmod(0o600)
            driver = CeremonyDriver(
                Path("/usr/bin/false"), seed, "http://localhost:28735"
            )
            url = "http://localhost:28735/ceremony/" + "A" * 43
            for count in (2, 3):
                with self.assertRaises(EvalError):
                    driver.complete(url)
                self.assertEqual(driver.counter, count)
            with self.assertRaises(EvalError):
                driver.complete(url.replace("28735", "28736"))
            self.assertEqual(driver.counter, 3)

    def test_codex_auth_uses_a_path_instead_of_a_numeric_secret_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".codex").mkdir()
            auth = root / ".codex/auth.json"
            auth.write_text("{}")
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch("pathlib.Path.home", return_value=root),
            ):
                spec = _agent_spec("codex")
            self.assertEqual(spec.env, {"CODEX_AUTH_JSON_PATH": str(auth)})

    def test_absent_mount_and_staged_work_cannot_pass_as_no_pending_work(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"BLOOM_EVAL_WALLET_ID": "harbor"}),
        ):
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                checker.verify(root)
            account = root / "wallets/harbor/0/account.json"
            account.parent.mkdir(parents=True)
            account.write_text(
                json.dumps(
                    {
                        "schema": "bloom.account.v1",
                        "wallet": "harbor",
                        "number": 0,
                        "freshness": "fresh",
                        "evm": {"state": "active"},
                    }
                )
            )
            checker.verify(root)
            registration = root / "wallets/registrations/harbor/status.json"
            registration.parent.mkdir(parents=True)
            completed = {
                "schema": "bloom.machine-wallet-registration-projection.1",
                "requested_name": "harbor",
                "ceremony_kind": "wallet_registration",
                "ceremony_state": "COMPLETED",
            }
            registration.write_text(json.dumps(completed))
            checker.verify(root)
            registration.write_text(
                json.dumps(completed | {"ceremony_state": "AWAITING_USER"})
            )
            with self.assertRaises(ValueError):
                checker.verify(root)
            registration.write_text(json.dumps(completed))
            for relative in (
                "wallets/harbor/0/chains/ethereum/outbox/pending/one",
                "wallets/harbor/policy-updates/pending/one",
                "petals/polymarket/trade/harbor/0/drafts/one",
                "wallets/registrations/other",
                "wallets/recoveries/harbor",
                "wallets/harbor/passkeys/enrollments/one",
            ):
                pending = root / relative
                pending.mkdir(parents=True)
                with self.assertRaises(ValueError):
                    checker.verify(root)
                pending.rmdir()


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

    def test_each_missing_fact_passes_without_a_wallet_question(self):
        for petal, question in (
            ("solana", "Which chain should I use for the USDC transfer?"),
            ("hyperliquid", "Mainnet or testnet?"),
            ("polymarket", "Which market should I buy Yes in?"),
            ("near-intents", "Which origin chain holds your USDC?"),
        ):
            with self.subTest(petal=petal):
                self.assertTrue(asks_for_selection(self.trajectory(question), petal))

    def test_each_assumed_default_fails_even_with_an_unrelated_question(self):
        for petal, message in (
            ("solana", "I will use Ethereum. Which wallet should I use?"),
            ("hyperliquid", "I will use mainnet. Where should the funds come from?"),
            ("polymarket", "I chose the election market. Which wallet should I use?"),
            (
                "near-intents",
                "I will spend Ethereum USDC. Which recipient should I use?",
            ),
        ):
            with self.subTest(petal=petal):
                self.assertFalse(asks_for_selection(self.trajectory(message), petal))

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

    def test_questions_cannot_borrow_a_missing_fact_from_a_later_clause(self):
        for petal, message in (
            (
                "near-intents",
                "I selected wallet harbor on mainnet. Which token do you want?",
            ),
            ("solana", "Which recipient should I use on the Ethereum chain?"),
            ("near-intents", "Which destination chain should receive the USDC?"),
            ("polymarket", "Which wallet should I use for the election market?"),
            ("polymarket", "Which wallet for this market?"),
            ("hyperliquid", "Which wallet should I use on mainnet?"),
            ("hyperliquid", "Which mainnet account should I use?"),
            ("hyperliquid", "I selected mainnet rather than testnet. Shall I proceed?"),
        ):
            with self.subTest(message=message):
                self.assertFalse(asks_for_selection(self.trajectory(message), petal))
        for message in (
            "Which Hyperliquid network should I use?",
            "Do you mean mainnet or testnet?",
            "What environment should I use?",
        ):
            with self.subTest(message=message):
                self.assertTrue(
                    asks_for_selection(self.trajectory(message), "hyperliquid")
                )

    def test_market_question_is_valid_despite_a_single_assumed_wallet(self):
        self.assertTrue(
            asks_for_selection(
                self.trajectory(
                    "I will use wallet harbor account 0. Which market should I buy?"
                ),
                "polymarket",
            )
        )

    def test_no_question_is_not_clarification(self):
        for message in (
            "Done.",
            "I selected the default network.",
            "Proceed?",
            "Which wallet?",
        ):
            self.assertFalse(
                asks_for_selection(self.trajectory(message), "hyperliquid")
            )

    def test_imperative_missing_fact_requests_need_no_question_mark(self):
        for petal, message in (
            ("solana", "Please specify the source chain before I proceed."),
            ("hyperliquid", "Please choose the Hyperliquid network."),
            ("polymarket", "Provide the market to buy Yes in."),
            ("near-intents", "Specify the origin chain for your USDC."),
        ):
            self.assertTrue(asks_for_selection(self.trajectory(message), petal))
        self.assertTrue(
            asks_for_selection(
                self.trajectory(
                    "Fund the intended chain and specify Ethereum, Polygon, or Arc, then I can proceed."
                ),
                "solana",
                choices=("ethereum", "polygon", "arc"),
            )
        )

    def test_funding_requests_and_self_selection_statements_still_fail(self):
        for message in (
            "Fund the account on Ethereum before I proceed.",
            "I will select the Ethereum chain.",
            "I can choose a network myself.",
            "I selected mainnet. Please provide funds.",
        ):
            self.assertFalse(asks_for_selection(self.trajectory(message), "solana"))

    def test_conditional_chain_request_leaves_named_choices_unresolved(self):
        for message in (
            "Please fund the intended network and specify it if not Ethereum or Polygon.",
            "Specify the chain unless Ethereum or Polygon.",
            "If not Ethereum or Polygon, specify the chain.",
        ):
            with self.subTest(message=message):
                self.assertFalse(
                    asks_for_selection(
                        self.trajectory(message),
                        "solana",
                        choices=("ethereum", "polygon", "arc"),
                    )
                )
