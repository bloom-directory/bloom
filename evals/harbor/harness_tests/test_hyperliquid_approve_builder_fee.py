from __future__ import annotations

import base64
import copy
import json
import subprocess
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


class BuilderFeeFixture:
    """Shared on-disk fixture: installed package, route index, provenance."""

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
                            "petal_lineage": {
                                "lineage_id": "pln1_" + "a" * 52,
                                "release_sequence": "1",
                                "predecessor_package_hashes": [],
                                "controller_key_id": "developer-controller",
                                "controller_signature": signature,
                                "active": True,
                            },
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


class HyperliquidApproveBuilderFeeDefinitionTests(BuilderFeeFixture, unittest.TestCase):
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
            "fee-bearing operation class",
            "missing installer signature",
            "inactive lineage",
            "malformed lineage id",
            "missing controller signature",
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
            elif case == "fee-bearing operation class":
                # Broker denies this route's DeclaredFee::None claims with
                # FEE_REQUIRED once its class carries a fee asset.
                catalog["records"][0]["operation_classes"] = [
                    {
                        "operation_class": OPERATION_CLASS,
                        "fee_asset": {"chain": "hyperliquid", "asset": "usdc"},
                    }
                ]
            elif case == "missing installer signature":
                catalog["records"][0]["installer_signature"] = ""
            elif case == "inactive lineage":
                catalog["records"][0]["petal_lineage"]["active"] = False
            elif case == "malformed lineage id":
                catalog["records"][0]["petal_lineage"]["lineage_id"] = "not-a-lineage"
            elif case == "missing controller signature":
                catalog["records"][0]["petal_lineage"]["controller_signature"] = ""

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


class BuilderFeeCeremonyLifecycleTests(BuilderFeeFixture, unittest.TestCase):
    """The grant/revoke lifecycle around WebAuthn counters and cleanup."""

    def drive(
        self, *, statuses: list[str] | None = None
    ) -> tuple[HyperliquidApproveBuilderFeeEval, list[int]]:
        """Wire a definition whose ceremony completion always succeeds.

        Returns the definition and the list that records every `--sign-count`
        the debug driver was invoked with, in order.
        """
        definition = self.definition
        counters: list[int] = []
        ceremony = "http://localhost:18734/ceremony/" + "A" * 43
        definition._write_route = mock.Mock(
            return_value=subprocess.CompletedProcess([], 0, b"", b"")
        )
        definition._pending_builder_fee_ceremony = mock.Mock(return_value=ceremony)
        pending = list(statuses or ["approved_retry_required"])
        definition._builder_fee_request_status = mock.Mock(
            side_effect=lambda: pending.pop(0) if pending else "signed"
        )

        def run(command: list[str], **_kwargs: object) -> object:
            counters.append(int(command[command.index("--sign-count") + 1]))
            return subprocess.CompletedProcess(command, 0, b"", b"")

        self.driver_runs = mock.patch.object(
            subprocess, "run", side_effect=run
        )
        self.driver_runs.start()
        self.addCleanup(self.driver_runs.stop)
        return definition, counters

    def test_grant_then_cleanup_uses_strictly_increasing_driver_counters(
        self,
    ) -> None:
        definition, counters = self.drive()
        definition._observed_max_builder_fee = mock.Mock(return_value=0)
        definition._read_json = mock.Mock(return_value={"status": "ok"})

        definition.provision("codex")
        definition.cleanup()

        self.assertEqual(len(counters), 2, "grant and revoke each spend one")
        self.assertEqual(counters, sorted(set(counters)))
        # Starts at the configured counter and never reuses it.
        self.assertEqual(counters[0], 4)
        self.assertGreater(counters[1], counters[0])
        self.assertEqual(definition.sign_count, counters[-1] + 1)

    def test_provision_leaves_the_submitting_write_to_the_agent(self) -> None:
        definition, _counters = self.drive()
        definition._observed_max_builder_fee = mock.Mock(return_value=0)

        definition.provision("codex")

        # One staging write only: the byte-identical replay that reaches the
        # venue is the agent's job, otherwise its write is a Petal no-op and
        # grading falls back to host-established state.
        self.assertEqual(definition._write_route.call_count, 1)

    def test_provision_refuses_a_residual_venue_approval(self) -> None:
        definition, _counters = self.drive()
        definition._observed_max_builder_fee = mock.Mock(return_value=10)
        with self.assertRaisesRegex(EvalError, "already approves"):
            definition.provision("codex")

    def test_provision_fails_closed_when_the_approval_is_not_staged(self) -> None:
        definition, _counters = self.drive(statuses=["awaiting_owner_approval"])
        definition._observed_max_builder_fee = mock.Mock(return_value=0)
        with self.assertRaisesRegex(EvalError, "was not staged"):
            definition.provision("codex")

    def test_ambiguous_grant_still_schedules_cleanup(self) -> None:
        definition, _counters = self.drive(statuses=["awaiting_owner_approval"])
        definition._observed_max_builder_fee = mock.Mock(return_value=0)
        with self.assertRaises(EvalError):
            definition.provision("codex")
        # The approval may be live even though provisioning reported failure,
        # so the revoke must still be owed.
        self.assertTrue(definition.cleanup_needed)

    def test_cleanup_is_a_noop_before_any_side_effecting_write(self) -> None:
        definition, counters = self.drive()
        definition.cleanup()
        self.assertEqual(counters, [])


if __name__ == "__main__":
    unittest.main()
