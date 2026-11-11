import copy
import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "near_verifier",
    Path(__file__).parents[1]
    / "tasks/near-intents-swap-proposal/tests/verify_result.py",
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class NearProposalTests(unittest.TestCase):
    def setUp(self):
        self.expected = {
            "wallet": "harbor",
            "address": "0x" + "1" * 40,
            "usdc_contract": "0x" + "2" * 40,
            "package_hash": "released-package",
            "origin_asset": "eth-usdc",
            "destination_asset": "arb-usdc",
        }
        e = self.expected
        self.request = {
            "session_id": "trial-session",
            "origin_asset": e["origin_asset"],
            "destination_asset": e["destination_asset"],
            "swap_type": "EXACT_INPUT",
            "amount": "1000000",
            "recipient": e["address"],
        }
        self.status = {
            "wallet": "harbor",
            "id": "trial-session",
            "state": "staged",
            "quote_verified": True,
            "origin_tx_hash": None,
            "outbox_id": "entry",
        }
        self.outbox = {
            "id": "entry",
            "chain": "ethereum",
            "account": {"number": 0},
            "outbox_root": "/wallets/harbor/0/chains/ethereum/outbox",
            "tx_hash": None,
        }
        self.quote = {
            "verified": True,
            "quote_request": {
                "originAsset": e["origin_asset"],
                "destinationAsset": e["destination_asset"],
                "amount": "1000000",
                "swapType": "EXACT_INPUT",
                "recipient": e["address"],
                "refundTo": e["address"],
                "depositType": "ORIGIN_CHAIN",
                "recipientType": "DESTINATION_CHAIN",
            },
            "quote": {"amountIn": "1000000", "depositAddress": "0x" + "3" * 40},
        }
        self.intent = {
            "id": "entry",
            "wallet": "harbor",
            "chain": "ethereum",
            "chain_id": 1,
            "from": e["address"],
            "to": e["usdc_contract"],
            "value_wei": "0",
            "status": "pending",
            "tx_hash": None,
            "execution_origin": {
                "petal_id": "petal:near-intents",
                "petal_digest": e["package_hash"],
            },
            "data_hex": "0xa9059cbb" + ("3" * 40).rjust(64, "0") + f"{1000000:064x}",
        }

    def args(self):
        return [
            self.request,
            self.status,
            self.outbox,
            self.quote,
            self.intent,
            self.expected,
        ]

    def test_exact_unsigned_deposit_and_destination_pass(self):
        verifier.validate(*self.args())

    def test_wrong_origin_destination_recipient_amount_and_signed_state_fail(self):
        mutations = [
            (0, "origin_asset", "polygon-usdc"),
            (0, "destination_asset", "arb-usdt"),
            (0, "recipient", "other"),
            (0, "amount", "1000001"),
            (1, "state", "approval_required"),
            (1, "origin_tx_hash", "hash"),
            (2, "id", "other"),
            (2, "account", {"number": 1}),
            (2, "tx_hash", "hash"),
            (4, "chain_id", 42161),
            (4, "chain", "arbitrum"),
            (4, "from", "other"),
            (4, "to", "other"),
            (4, "status", "sent"),
            (4, "tx_hash", "hash"),
            (4, "value_wei", "1"),
            (4, "data_hex", self.intent["data_hex"][:-1] + "1"),
            (
                4,
                "execution_origin",
                {"petal_id": "petal:near-intents", "petal_digest": "other"},
            ),
        ]
        for index, key, value in mutations:
            args = copy.deepcopy(self.args())
            args[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                verifier.validate(*args)

    def test_quote_echo_is_bound_beyond_matching_deposit_calldata(self):
        for key, value in (
            ("originAsset", "polygon-usdc"),
            ("destinationAsset", "near-usdc"),
            ("destinationAsset", "arb-usdt"),
            ("recipient", "other"),
            ("refundTo", "other"),
            ("amount", "1000001"),
        ):
            args = copy.deepcopy(self.args())
            args[3]["quote_request"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verifier.validate(*args)

    def test_counts_and_approval_work_are_rejected(self):
        base = "petals/near-intents/swaps/harbor/0"
        pending = "wallets/harbor/0/chains/ethereum/outbox/pending"
        values = {
            f"{base}/trial-session/{name}.json": value
            for name, value in (
                ("request", self.request),
                ("status", self.status),
                ("outbox", self.outbox),
                ("quote", self.quote),
            )
        }
        values.update(
            {
                pending + "/entry/intent.json": self.intent,
                "chains/ethereum/chain_id": 1,
                "wallets/harbor/0/account.json": {
                    "wallet": "harbor",
                    "number": 0,
                    "freshness": "fresh",
                    "evm": {"address": self.expected["address"]},
                },
            }
        )
        values[f"{base}/extra/status.json"] = {"state": "quoted"}
        reader = mock.Mock()
        reader.read_json.side_effect = values.__getitem__
        for bad_path in (
            None,
            base,
            pending,
            "petal-signing-requests",
            "wallets/harbor/policy-updates/pending",
            "wallets/harbor/0/chains/ethereum/outbox/sent",
        ):

            def directories(path, bad=bad_path):
                result = {
                    base: ["trial-session"],
                    pending: ["entry"],
                    "wallets/harbor/0/chains": ["ethereum"],
                }.get(path, [])
                return result + ["extra"] if path == bad else result

            reader.directories.side_effect = directories
            reader.entries.side_effect = lambda path, bad=bad_path: (
                {"extra.json": "File"} if path == bad else {}
            )
            with (
                mock.patch.object(verifier, "ProjectionReader", return_value=reader),
                mock.patch.dict(
                    os.environ, {"BLOOM_EVAL_PROPOSAL": json.dumps(self.expected)}
                ),
            ):
                if bad_path is None:
                    verifier.verify(Path("fixture"))
                else:
                    with self.subTest(path=bad_path), self.assertRaises(ValueError):
                        verifier.verify(Path("fixture"))

    def test_failed_or_quoted_swap_is_rejected_before_absent_outbox_read(self):
        base = "petals/near-intents/swaps/harbor/0"
        values = {
            "chains/ethereum/chain_id": 1,
            "wallets/harbor/0/account.json": {
                "wallet": "harbor",
                "number": 0,
                "freshness": "fresh",
                "evm": {"address": self.expected["address"]},
            },
        }
        reader = mock.Mock()
        reader.entries.return_value = {}
        reader.directories.side_effect = lambda path: (
            ["trial-session"] if path == base else []
        )
        reader.read_json.side_effect = values.__getitem__
        for state in ("quote_failed", "quoted"):
            values[base + "/trial-session/status.json"] = {"state": state}
            with (
                mock.patch.object(verifier, "ProjectionReader", return_value=reader),
                mock.patch.dict(
                    os.environ, {"BLOOM_EVAL_PROPOSAL": json.dumps(self.expected)}
                ),
                self.subTest(state=state),
                self.assertRaisesRegex(ValueError, "staged"),
            ):
                verifier.verify(Path("fixture"))

    def test_a_retry_after_a_failed_quote_passes(self):
        base = "petals/near-intents/swaps/harbor/0"
        pending = "wallets/harbor/0/chains/ethereum/outbox/pending"
        values = {
            f"{base}/trial-session/{name}.json": value
            for name, value in (
                ("request", self.request),
                ("status", self.status),
                ("outbox", self.outbox),
                ("quote", self.quote),
            )
        } | {
            f"{base}/failed/status.json": {"state": "quote_failed"},
            f"{base}/dropped/status.json": {"state": "abandoned"},
            pending + "/entry/intent.json": self.intent,
            "chains/ethereum/chain_id": 1,
            "wallets/harbor/0/account.json": {
                "wallet": "harbor",
                "number": 0,
                "freshness": "fresh",
                "evm": {"address": self.expected["address"]},
            },
        }
        reader = mock.Mock()
        reader.read_json.side_effect = values.__getitem__
        reader.entries.return_value = {}
        reader.directories.side_effect = lambda path: {
            base: ["failed", "trial-session", "dropped"],
            pending: ["entry"],
            "wallets/harbor/0/chains": ["ethereum"],
        }.get(path, [])
        with (
            mock.patch.object(verifier, "ProjectionReader", return_value=reader),
            mock.patch.dict(
                os.environ, {"BLOOM_EVAL_PROPOSAL": json.dumps(self.expected)}
            ),
        ):
            verifier.verify(Path("fixture"))
