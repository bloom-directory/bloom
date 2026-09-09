from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness.core import EvalError
from harness.hyperliquid_approve_builder_fee import (
    OPERATION_CLASS,
    ROUTE_PATTERN,
    HyperliquidApproveBuilderFeeEval,
)


class HyperliquidApproveBuilderFeeDefinitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.mount = self.root / "bloom"
        self.wallet = "0x" + "a" * 40
        self.wallet_id = "eval-wallet"
        self.builder = "0x" + "b" * 40
        self.package_hash = "c" * 64
        self.driver = self.root / "driver"
        self.owner_record = self.root / "hyperliquid-owner.json"
        self.owner_record.write_text(
            json.dumps({"name": "hyperliquid", "hash": self.package_hash})
        )
        self.owner_record.chmod(0o644)
        self.petal_store = self.root / "petal-store"
        route_dir = self.petal_store / "packages" / self.package_hash
        route_dir.mkdir(parents=True)
        self.route_index = route_dir / "route-index.json"
        self.route_index.write_text(
            json.dumps(
                {
                    "schema": "bloom.petal.route-index.v1",
                    "package_hash": self.package_hash,
                    "routes": [
                        {
                            "route_id": "r000035",
                            "pattern": ROUTE_PATTERN,
                            "install_metadata": {
                                "required_caps": ["bloom:http", "bloom:sign", "bloom:store"],
                                "sign_intent": OPERATION_CLASS,
                            },
                        }
                    ],
                }
            )
        )
        self.route_index.chmod(0o644)
        self.provenance_catalog = self.root / "provenance-catalog.json"
        signature = base64.urlsafe_b64encode(b"\x01" * 64).rstrip(b"=").decode()
        self.provenance_catalog.write_text(
            json.dumps(
                {
                    "schema": "bloom.provenance-catalog.1",
                    "records": [
                        {
                            "subject": {
                                "kind": "petal",
                                "package_hash": self.package_hash,
                                "route": "r000035",
                            },
                            "publisher": "bloom-installer",
                            "operation_classes": [
                                {"operation_class": OPERATION_CLASS, "fee_asset": None}
                            ],
                            "installer_key_id": "developer-installer",
                            "installer_signature": signature,
                        }
                    ],
                }
            )
        )
        self.provenance_catalog.chmod(0o600)
        self.seed = self.root / "seed"
        self.seed.write_text("seed")
        self.seed.chmod(0o600)
        self.env = {
            "BLOOM_EVAL_NETWORK": "testnet",
            "BLOOM_EVAL_WALLET": self.wallet,
            "BLOOM_EVAL_WALLET_ID": self.wallet_id,
            "BLOOM_EVAL_BUILDER": self.builder,
            "BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS": "10",
            "BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH": self.package_hash,
            "BLOOM_EVAL_PETAL_OWNER_RECORD": str(self.owner_record),
            "BLOOM_EVAL_PETAL_STORE": str(self.petal_store),
            "BLOOM_EVAL_PROVENANCE_CATALOG": str(self.provenance_catalog),
            "BLOOM_EVAL_NETWORK_ACK": "APPROVE_BUILDER_FEE_TESTNET",
            "BLOOM_EVAL_AUTHENTICATOR_SEED_FILE": str(self.seed),
            "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT": "4",
            "BLOOM_EVAL_DEBUG_DRIVER_BIN": str(self.driver),
            "BLOOM_EVAL_BLOOM_MOUNT": str(self.mount),
            "BLOOM_EVAL_JOBS_DIR": str(self.root / "jobs"),
            "BLOOM_EVAL_LOCK_FILE": str(self.root / "eval.lock"),
        }
        self.definition = HyperliquidApproveBuilderFeeEval(self.repo, self.env)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_installed_package_hash_must_match_owner_record(self) -> None:
        self.owner_record.write_text(
            json.dumps({"name": "hyperliquid", "hash": "d" * 64})
        )
        with self.assertRaisesRegex(
            EvalError, "does not match the installed owner record"
        ):
            self.definition._require_installed_package_hash()

    def test_installed_route_and_provenance_satisfy_preauthorization_gate(
        self,
    ) -> None:
        self.definition.preauthorization_preflight()

    def test_preauthorization_rejects_broadened_or_mismatched_authority(self) -> None:
        base_routes = json.loads(self.route_index.read_text())
        base_catalog = json.loads(self.provenance_catalog.read_text())

        for case in (
            "missing record",
            "provenance record for wrong route",
            "wrong operation class",
            "extra operation class",
            "mismatched route-index package",
            "mismatched provenance package",
            "wrong sign intent",
            "duplicate route",
        ):
            routes = copy.deepcopy(base_routes)
            catalog = copy.deepcopy(base_catalog)
            if case == "missing record":
                catalog["records"] = []
            elif case == "provenance record for wrong route":
                catalog["records"][0]["subject"]["route"] = "r999999"
            elif case == "wrong operation class":
                catalog["records"][0]["operation_classes"] = [
                    {"operation_class": "hyperliquid.usd_send", "fee_asset": None}
                ]
            elif case == "extra operation class":
                catalog["records"][0]["operation_classes"].append(
                    {"operation_class": "hyperliquid.usd_send", "fee_asset": None}
                )
            elif case == "mismatched route-index package":
                routes["package_hash"] = "d" * 64
            elif case == "mismatched provenance package":
                catalog["records"][0]["subject"]["package_hash"] = "d" * 64
            elif case == "wrong sign intent":
                routes["routes"][0]["install_metadata"]["sign_intent"] = (
                    "hyperliquid.usd_send"
                )
            elif case == "duplicate route":
                routes["routes"].append(copy.deepcopy(routes["routes"][0]))

            self.route_index.write_text(json.dumps(routes))
            self.provenance_catalog.write_text(json.dumps(catalog))
            with self.subTest(case=case), self.assertRaises(EvalError):
                self.definition.preauthorization_preflight()

    def test_preauthorization_does_not_require_or_inspect_temporary_policy(
        self,
    ) -> None:
        self.definition._require_exact_wallet_policy = mock.Mock(
            side_effect=AssertionError("temporary policy must remain unopened")
        )
        self.definition._write_route = mock.Mock(
            side_effect=AssertionError("preauthorization must not write mounted routes")
        )
        self.definition.preauthorization_preflight()
        self.definition._require_exact_wallet_policy.assert_not_called()
        self.definition._write_route.assert_not_called()

    def test_preauthorization_rejects_malformed_package_hash(self) -> None:
        self.definition.package_hash = "not-a-blake3-hash"
        with self.assertRaisesRegex(
            EvalError, "must be a lowercase BLAKE3"
        ):
            self.definition.preauthorization_preflight()


if __name__ == "__main__":
    unittest.main()
