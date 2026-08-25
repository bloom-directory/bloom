from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from harness import hyperliquid_order_cancel
from harness.core import AgentSpec, EvalDefinition, EvalError, EvalRunContext, run_eval
from harness.hyperliquid_order_cancel import (
    ACTION_FILES,
    MAINNET_ACK,
    HyperliquidOrderCancelEval,
    session_key_slot,
)


class FakeDefinition(EvalDefinition):
    name = "fake"

    def __init__(
        self, root: Path, *, provision_error: BaseException | None = None
    ) -> None:
        self.root = root
        self.provision_error = provision_error
        self.events: list[str] = []

    @property
    def lock_path(self) -> Path:
        return self.root / "eval.lock"

    def preflight(self) -> None:
        self.events.append("preflight")

    def provision(self, agent_name: str) -> EvalRunContext:
        self.events.append(f"provision:{agent_name}")
        if self.provision_error is not None:
            raise self.provision_error
        return EvalRunContext(
            "fake", self.root, "fake-job", self.root / "jobs", [], {}, {}
        )

    def cleanup(self) -> None:
        self.events.append("cleanup")


class HarnessLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.auth = mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test"})
        self.auth.start()

    def tearDown(self) -> None:
        self.auth.stop()
        self.temp.cleanup()

    def passing_result(self) -> SimpleNamespace:
        trial = SimpleNamespace(
            exception_info=None,
            verifier_result=SimpleNamespace(rewards={"reward": 1}),
        )
        return SimpleNamespace(
            stats=SimpleNamespace(n_errored_trials=0, n_cancelled_trials=0),
            trial_results=[trial],
        )

    def test_run_eval_orders_lifecycle_and_cleans_up(self) -> None:
        definition = FakeDefinition(self.root)

        async def runner(_context: EvalRunContext, agent: AgentSpec) -> object:
            definition.events.append(f"harbor:{agent.harbor_name}")
            return self.passing_result()

        run_eval(definition, "codex", harbor_runner=runner)
        self.assertEqual(
            definition.events,
            ["preflight", "provision:codex", "harbor:codex", "cleanup"],
        )

    def test_cleanup_runs_when_provision_fails_after_starting(self) -> None:
        definition = FakeDefinition(
            self.root, provision_error=EvalError("provision failed")
        )

        async def runner(_context: EvalRunContext, _agent: AgentSpec) -> object:
            self.fail("Harbor must not run")

        with self.assertRaisesRegex(EvalError, "provision failed"):
            run_eval(definition, "codex", harbor_runner=runner)
        self.assertEqual(definition.events, ["preflight", "provision:codex", "cleanup"])

    def test_cleanup_failure_is_not_hidden_by_run_failure(self) -> None:
        definition = FakeDefinition(self.root)
        definition.cleanup = mock.Mock(side_effect=EvalError("cleanup failed"))

        async def runner(_context: EvalRunContext, _agent: AgentSpec) -> object:
            raise EvalError("run failed")

        with self.assertRaisesRegex(EvalError, "run failed.*cleanup also failed"):
            run_eval(definition, "codex", harbor_runner=runner)


class HyperliquidDefinitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.mount = self.root / "bloom"
        self.wallet = "0x" + "a" * 40
        self.wallet_id = "eval-wallet"
        self.package_hash = "b" * 64
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
        action_routes = (
            "[network]/agent_sessions/[wallet]/[session]/cancel.json",
            "[network]/agent_sessions/[wallet]/[session]/cancel_all",
            "[network]/agent_sessions/[wallet]/[session]/close_all",
            "[network]/agent_sessions/[wallet]/[session]/order.json",
            "[network]/agent_sessions/[wallet]/[session]/schedule_cancel.json",
            "[network]/agent_sessions/[wallet]/[session]/update_leverage.json",
        )
        self.route_index.write_text(
            json.dumps(
                {
                    "schema": "bloom.petal.route-index.v1",
                    "package_hash": self.package_hash,
                    "routes": [
                        {
                            "route_id": "r000021",
                            "pattern": "[network]/agent_sessions/[wallet]/new.json",
                            "install_metadata": {
                                "required_caps": [
                                    "bloom:http",
                                    "bloom:key.derive",
                                    "bloom:sign",
                                    "bloom:store",
                                ],
                                "sign_intent": "hyperliquid.approve_agent",
                            },
                            "key_derive_operation_classes": [
                                "hyperliquid.agent_action"
                            ],
                        }
                    ]
                    + [
                        {
                            "route_id": f"r{index:06d}",
                            "pattern": pattern,
                            "install_metadata": {
                                "required_caps": [
                                    "bloom:http",
                                    "bloom:sign",
                                    "bloom:store",
                                ],
                                "sign_intent": "hyperliquid.agent_action",
                            },
                        }
                        for index, pattern in enumerate(action_routes, start=1)
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
                                "route": "r000021",
                            },
                            "petal_lineage": {
                                "lineage_id": "pln1_" + "a" * 52,
                                "release_sequence": "1",
                                "predecessor_package_hashes": [],
                                "controller_key_id": "developer-controller",
                                "controller_signature": signature,
                                "active": True,
                            },
                            "publisher": "bloom-installer",
                            "operation_classes": [
                                {
                                    "operation_class": "hyperliquid.agent_action",
                                    "fee_asset": None,
                                },
                                {
                                    "operation_class": "hyperliquid.approve_agent",
                                    "fee_asset": None,
                                },
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
            "BLOOM_EVAL_WALLET": self.wallet,
            "BLOOM_EVAL_WALLET_ID": self.wallet_id,
            "BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH": self.package_hash,
            "BLOOM_EVAL_PETAL_OWNER_RECORD": str(self.owner_record),
            "BLOOM_EVAL_PETAL_STORE": str(self.petal_store),
            "BLOOM_EVAL_PROVENANCE_CATALOG": str(self.provenance_catalog),
            "BLOOM_EVAL_MAINNET_ACK": MAINNET_ACK,
            "BLOOM_EVAL_AUTHENTICATOR_SEED_FILE": str(self.seed),
            "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT": "4",
            "BLOOM_EVAL_DEBUG_DRIVER_BIN": str(self.driver),
            "BLOOM_EVAL_BLOOM_MOUNT": str(self.mount),
            "BLOOM_EVAL_JOBS_DIR": str(self.root / "jobs"),
            "BLOOM_EVAL_LOCK_FILE": str(self.root / "eval.lock"),
        }
        self.definition = HyperliquidOrderCancelEval(self.repo, self.env)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_read_json_retries_transient_malformed_nfs_snapshot(self) -> None:
        malformed = subprocess.CompletedProcess([], 0, b'{"status":"old"}{"status":"new"}', b"")
        valid = subprocess.CompletedProcess([], 0, b'{"status":"new"}', b"")
        with (
            mock.patch.object(
                hyperliquid_order_cancel.subprocess,
                "run",
                side_effect=[malformed, valid],
            ) as run,
            mock.patch.object(hyperliquid_order_cancel.time, "sleep") as sleep,
        ):
            self.assertEqual(
                self.definition._read_json(self.mount / "projection.json"),
                {"status": "new"},
            )
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(0.2)

    def test_missing_seed_variable_fails_closed(self) -> None:
        env = dict(self.env)
        del env["BLOOM_EVAL_AUTHENTICATOR_SEED_FILE"]
        definition = HyperliquidOrderCancelEval(self.repo, env)
        with self.assertRaisesRegex(EvalError, "AUTHENTICATOR_SEED_FILE is required"):
            definition.preflight()

    def test_missing_sign_count_fails_closed(self) -> None:
        env = dict(self.env)
        del env["BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT"]
        definition = HyperliquidOrderCancelEval(self.repo, env)
        with self.assertRaisesRegex(EvalError, "SIGN_COUNT must be an integer"):
            definition.preflight()

    def test_out_of_range_sign_count_fails_closed(self) -> None:
        env = dict(self.env)
        env["BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT"] = "0"
        definition = HyperliquidOrderCancelEval(self.repo, env)
        with self.assertRaisesRegex(EvalError, "must be between 1 and 4294967295"):
            definition.preflight()

    def test_malformed_position_size_fails_closed(self) -> None:
        self.definition._read_json = mock.Mock(
            side_effect=[[], {"assetPositions": [{"position": {"szi": "unknown"}}]}]
        )
        with self.assertRaisesRegex(EvalError, "position size is not numeric"):
            self.definition._require_empty_wallet()

    def test_exact_wallet_policy_accepts_matching_broker_projection(self) -> None:
        policy = {
            "allowed_destinations": [],
            "allowed_petal_packages": [self.package_hash],
            "maximum_approval_lifetime_ms": 2_592_000_000,
            "required_verifiers": [],
            "wallet_id": self.wallet_id,
        }
        digest = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.definition._read_json = mock.Mock(
            side_effect=[
                {
                    "owner": self.wallet,
                    "policy_status": "broker_verified",
                    "freshness": "fresh",
                    "policy_digest": digest,
                },
                policy,
            ]
        )

        self.definition._require_exact_wallet_policy()

    def test_exact_wallet_policy_rejects_funding_destination(self) -> None:
        policy = {
            "wallet_id": self.wallet_id,
            "allowed_destinations": [
                {"chain": "arbitrum", "destination": "0x" + "c" * 40}
            ],
            "allowed_petal_packages": [self.package_hash],
        }
        self.definition._read_json = mock.Mock(
            side_effect=[
                {
                    "owner": self.wallet,
                    "policy_status": "broker_verified",
                    "freshness": "fresh",
                    "policy_digest": "d" * 64,
                },
                policy,
            ]
        )

        with self.assertRaisesRegex(
            EvalError, "does not match the exact bounded policy"
        ):
            self.definition._require_exact_wallet_policy()

    def test_exact_wallet_policy_rejects_extra_verifier(self) -> None:
        policy = {
            "allowed_destinations": [],
            "allowed_petal_packages": [self.package_hash],
            "maximum_approval_lifetime_ms": 2_592_000_000,
            "required_verifiers": ["unexpected"],
            "wallet_id": self.wallet_id,
        }
        digest = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.definition._read_json = mock.Mock(
            side_effect=[
                {
                    "owner": self.wallet,
                    "policy_status": "broker_verified",
                    "freshness": "fresh",
                    "policy_digest": digest,
                },
                policy,
            ]
        )
        with self.assertRaisesRegex(
            EvalError, "does not match the exact bounded policy"
        ):
            self.definition._require_exact_wallet_policy()

    def test_installed_package_hash_must_match_owner_record(self) -> None:
        self.owner_record.write_text(
            json.dumps({"name": "hyperliquid", "hash": "c" * 64})
        )
        with self.assertRaisesRegex(
            EvalError, "does not match the installed owner record"
        ):
            self.definition._require_installed_package_hash()

    def test_active_installed_lineage_satisfies_preauthorization_gate(self) -> None:
        self.definition.preauthorization_preflight()

    def test_preauthorization_rejects_broadened_or_mismatched_authority(self) -> None:
        base_routes = json.loads(self.route_index.read_text())
        base_catalog = json.loads(self.provenance_catalog.read_text())

        for case in (
            "missing record",
            "missing delegated route class",
            "overbroad delegated route class",
            "delegated class on wrong route",
            "provenance record for wrong route",
            "missing installer-signed delegated class",
            "overbroad installer-signed delegated class",
            "missing installer signature",
            "downstream route missing bloom:sign",
            "downstream route has wrong operation class",
            "mismatched route-index package",
            "mismatched provenance package",
        ):
            routes = copy.deepcopy(base_routes)
            catalog = copy.deepcopy(base_catalog)
            if case == "missing record":
                catalog["records"] = []
            elif case == "missing delegated route class":
                routes["routes"][0]["key_derive_operation_classes"] = []
            elif case == "overbroad delegated route class":
                routes["routes"][0]["key_derive_operation_classes"].append(
                    "hyperliquid.order"
                )
            elif case == "delegated class on wrong route":
                routes["routes"][0]["key_derive_operation_classes"] = []
                routes["routes"][1]["key_derive_operation_classes"] = [
                    "hyperliquid.agent_action"
                ]
            elif case == "provenance record for wrong route":
                catalog["records"][0]["subject"]["route"] = "r999999"
            elif case == "missing installer-signed delegated class":
                catalog["records"][0]["operation_classes"] = [
                    {
                        "operation_class": "hyperliquid.approve_agent",
                        "fee_asset": None,
                    }
                ]
            elif case == "overbroad installer-signed delegated class":
                catalog["records"][0]["operation_classes"].append(
                    {"operation_class": "hyperliquid.order", "fee_asset": None}
                )
            elif case == "missing installer signature":
                catalog["records"][0]["installer_signature"] = ""
            elif case == "downstream route missing bloom:sign":
                routes["routes"][1]["install_metadata"]["required_caps"].remove(
                    "bloom:sign"
                )
            elif case == "downstream route has wrong operation class":
                routes["routes"][1]["install_metadata"]["sign_intent"] = (
                    "hyperliquid.cancel"
                )
            elif case == "mismatched route-index package":
                routes["package_hash"] = "c" * 64
            elif case == "mismatched provenance package":
                catalog["records"][0]["subject"]["package_hash"] = "c" * 64

            self.route_index.write_text(json.dumps(routes))
            self.provenance_catalog.write_text(json.dumps(catalog))
            with self.subTest(case=case), self.assertRaises(EvalError):
                self.definition.preauthorization_preflight()

    def test_preauthorization_rejects_inactive_installed_lineage(self) -> None:
        catalog = json.loads(self.provenance_catalog.read_text())
        catalog["records"][0]["petal_lineage"]["active"] = False
        self.provenance_catalog.write_text(json.dumps(catalog))
        with self.assertRaisesRegex(EvalError, "does not have active Petal lineage"):
            self.definition.preauthorization_preflight()

    def test_preauthorization_does_not_require_or_inspect_temporary_policy(self) -> None:
        self.definition._require_exact_wallet_policy = mock.Mock(
            side_effect=AssertionError("temporary policy must remain unopened")
        )
        self.definition._write_route = mock.Mock(
            side_effect=AssertionError("preauthorization must not write mounted routes")
        )
        self.definition.preauthorization_preflight()
        self.definition._require_exact_wallet_policy.assert_not_called()
        self.definition._write_route.assert_not_called()

    def test_pending_key_ceremony_is_resolved_from_exact_owner_projection(self) -> None:
        ceremony = "http://localhost:18734/ceremony/" + "A" * 43
        self.definition.session_id = "exact-session"
        root = self.mount / "petal-key-requests"
        root.mkdir(parents=True)
        (root / ("d" * 64 + ".json")).write_text(
            json.dumps(
                {
                    "schema": "bloom.machine.petal-key-request.v2",
                    "key_slot": session_key_slot("exact-session"),
                    "scope": {
                        "wallet_id": self.wallet_id,
                        "package_hash": self.package_hash,
                    },
                    "status": "awaiting_user",
                    "ceremony_url": ceremony,
                }
            )
        )
        (root / ("e" * 64 + ".json")).write_text(
            json.dumps(
                {
                    "schema": "bloom.machine.petal-key-request.v2",
                    "key_slot": session_key_slot("other-session"),
                    "scope": {
                        "wallet_id": self.wallet_id,
                        "package_hash": self.package_hash,
                    },
                    "status": "awaiting_user",
                    "ceremony_url": "http://localhost:18734/ceremony/" + "B" * 43,
                }
            )
        )

        self.assertEqual(self.definition._pending_petal_key_ceremony(), ceremony)

    def test_session_key_slot_is_a_case_sensitive_lowercase_broker_token(self) -> None:
        upper = session_key_slot(
            "bloom-eval-codex-20260814T150000Z-0123456789abcdef"
        )
        lower = session_key_slot(
            "bloom-eval-codex-20260814t150000z-0123456789abcdef"
        )

        self.assertEqual(len(upper), 64)
        self.assertRegex(upper, r"^[a-z0-9-]{64}$")
        self.assertNotEqual(upper, lower)

    def test_session_completes_three_ceremonies_with_increasing_counters(self) -> None:
        # Creating a session stages key derivation, reusable route authority,
        # and then agent approval. Completing only the first leaves it pending.
        writes: list[tuple[Path, bytes]] = []
        pending = ["key", "authority", "approve"]

        def write(path: Path, body: bytes, _timeout: int) -> SimpleNamespace:
            writes.append((path, body))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        def key_ceremony() -> str | None:
            if not pending or pending[0] not in {"key", "authority"}:
                return None
            marker = "k" if pending[0] == "key" else "r"
            return "http://localhost:18734/ceremony/" + marker * 28

        def approve_ceremony() -> str | None:
            return (
                "http://localhost:18734/ceremony/" + "a" * 28
                if pending and pending[0] == "approve"
                else None
            )

        def read(path: Path, timeout: int = 20) -> object:
            del timeout
            if path.name == "status.json" and not pending:
                request = json.loads(writes[0][1])
                return {
                    "schema": "bloom.hyperliquid_agent_session.v1",
                    "network": "mainnet",
                    "wallet": self.wallet_id,
                    "id": request["id"],
                    "max_notional_usd": "11",
                    "max_leverage": 1,
                    "assets": ["0"],
                    "stopped": False,
                }
            return None

        counters: list[str] = []

        def fake_run(cmd, **kwargs):
            del kwargs
            counters.append(cmd[cmd.index("--sign-count") + 1])
            if pending:
                pending.pop(0)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        self.definition._write_route = mock.Mock(side_effect=write)
        self.definition._read_json_if_exists = mock.Mock(side_effect=read)
        self.definition._pending_petal_key_ceremony = mock.Mock(
            side_effect=key_ceremony
        )
        self.definition._pending_agent_approval_ceremony = mock.Mock(
            side_effect=approve_ceremony
        )

        with mock.patch(
            "harness.hyperliquid_order_cancel.subprocess.run", side_effect=fake_run
        ):
            self.definition.provision("codex")

        # All ceremonies ran, and no WebAuthn counter was reused: the venue
        # rejects any counter that is not strictly greater than the last.
        self.assertEqual(len(counters), 3)
        base = int(self.definition.sign_count_value)
        self.assertEqual(counters, [str(base), str(base + 1), str(base + 2)])
        self.assertEqual(self.definition.next_sign_count, base + 3)

    def test_session_route_is_addressed_by_wallet_id_not_owner_address(self) -> None:
        written: list[tuple[Path, bytes]] = []

        def write(path: Path, body: bytes, _timeout: int) -> SimpleNamespace:
            written.append((path, body))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        def read(path: Path, timeout: int = 20) -> object:
            del timeout
            if path.name == "status.json":
                request = __import__("json").loads(written[0][1])
                return {
                    "schema": "bloom.hyperliquid_agent_session.v1",
                    "network": "mainnet",
                    "wallet": self.wallet_id,
                    "id": request["id"],
                    "max_notional_usd": "11",
                    "max_leverage": 1,
                    "assets": ["0"],
                    "stopped": False,
                }
            raise AssertionError(path)

        self.definition._write_route = mock.Mock(side_effect=write)
        self.definition._read_json_if_exists = mock.Mock(side_effect=read)
        context = self.definition.provision("codex")

        # Owner signing for approve_agent validates the `[wallet]` segment as a
        # Broker token: 1-64 bytes of [a-z0-9._/-] that must begin with a
        # lowercase letter. An on-chain address begins with a digit, so passing
        # one here fails inside Broker as an unqualified permission error.
        route_parts = written[0][0].parts
        segment = route_parts[route_parts.index("agent_sessions") + 1]
        self.assertEqual(segment, self.definition.wallet_id)
        self.assertNotEqual(segment, self.definition.wallet)
        self.assertRegex(segment, r"^[a-z][a-z0-9._/-]{0,63}$")

        # The address does not travel in the body at all: the Petal recovers it
        # from the owner's approveAgent signature.
        request = __import__("json").loads(written[0][1])
        self.assertNotIn("owner_address", request)

        # The container's bind-mount targets must agree with the host paths, and
        # the agent needs both identifiers to address sessions and account reads.
        for mount in context.mounts[1:]:
            self.assertIn(f"/agent_sessions/{self.definition.wallet_id}/", mount["target"])
        self.assertEqual(
            context.agent_env["BLOOM_EVAL_WALLET_ID"], self.definition.wallet_id
        )
        self.assertEqual(context.agent_env["BLOOM_EVAL_WALLET"], self.definition.wallet)

    def test_provision_creates_session_then_builds_least_authority_mounts(self) -> None:
        written: list[tuple[Path, bytes]] = []

        def write(path: Path, body: bytes, _timeout: int) -> SimpleNamespace:
            written.append((path, body))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        def read(path: Path, timeout: int = 20) -> object:
            del timeout
            if path.name == "status.json":
                request = __import__("json").loads(written[0][1])
                return {
                    "schema": "bloom.hyperliquid_agent_session.v1",
                    "network": "mainnet",
                    "wallet": self.wallet_id,
                    "id": request["id"],
                    "max_notional_usd": "11",
                    "max_leverage": 1,
                    "assets": ["0"],
                    "stopped": False,
                }
            raise AssertionError(path)

        self.definition._write_route = mock.Mock(side_effect=write)
        self.definition._read_json_if_exists = mock.Mock(side_effect=read)
        context = self.definition.provision("codex")

        request = __import__("json").loads(written[0][1])
        # The wallet id is the route parameter, not a body field: carrying it
        # in both places let them disagree, deriving a key for one wallet while
        # state was recorded and signing attempted under another.
        self.assertNotIn("wallet_id", request)
        # Same for the owner address, which additionally fed the venue reads
        # behind max_leverage, cancel_all and close_all: a caller-chosen value
        # aimed those checks at an account the session never traded on.
        self.assertNotIn("owner_address", request)
        self.assertLessEqual(len(request["agent_name"]), 16)
        # Stable for the wallet, so Hyperliquid replaces the previous agent by
        # name instead of the account accumulating one per run.
        self.assertEqual(request["agent_name"], self.definition.agent_name)
        self.assertEqual(request["max_notional_usd"], "11")
        self.assertEqual(request["max_leverage"], 1)
        self.assertEqual(request["assets"], ["0"])
        self.assertEqual(context.mounts[0]["target"], "/bloom")
        self.assertTrue(context.mounts[0]["read_only"])
        self.assertEqual(
            [Path(mount["target"]).name for mount in context.mounts[1:]],
            list(ACTION_FILES),
        )
        self.assertTrue(all("read_only" not in mount for mount in context.mounts[1:]))
        self.assertNotIn(
            "stop", [Path(mount["target"]).name for mount in context.mounts]
        )
        self.assertNotIn(str(self.seed), str(context.mounts))
        self.assertNotIn(str(self.driver), str(context.mounts))

    def test_cleanup_before_session_creation_verifies_no_orphan_state(self) -> None:
        self.definition.session_id = "not-created"
        self.definition.session_base = self.mount / "not-created"
        self.definition._require_empty_wallet = mock.Mock()
        self.definition._read_session_status = mock.Mock(return_value=None)
        self.definition._pending_petal_key_ceremony = mock.Mock(return_value=None)
        self.definition._pending_agent_approval_ceremony = mock.Mock(return_value=None)
        self.definition._write_route = mock.Mock()

        self.definition.cleanup()

        self.definition._require_empty_wallet.assert_called_once_with()
        self.definition._read_session_status.assert_called_once_with()
        self.definition._pending_petal_key_ceremony.assert_called_once_with()
        self.definition._pending_agent_approval_ceremony.assert_called_once_with()
        self.definition._write_route.assert_not_called()

    def test_cleanup_fails_on_orphan_venue_agent(self) -> None:
        self.definition.session_id = "not-created"
        self.definition.session_base = self.mount / "not-created"
        self.definition._read_session_status = mock.Mock(return_value=None)
        self.definition._pending_petal_key_ceremony = mock.Mock(return_value=None)
        self.definition._require_empty_wallet = mock.Mock(
            side_effect=EvalError("dedicated wallet retains a Hyperliquid API agent")
        )
        with self.assertRaisesRegex(EvalError, "retains a Hyperliquid API agent"):
            self.definition.cleanup()

    def test_cleanup_fails_on_pending_agent_approval_ceremony(self) -> None:
        # Creating a session stages three owner ceremonies. Once key derivation
        # and reusable authority complete, `approve_agent` can sit awaiting approval while the durable
        # session still does not exist: the key projection is consumed, and the
        # wallet looks empty because the agent was never registered at the venue.
        # Cleanup used to report success and leave that ceremony open.
        self.definition.session_id = "not-created"
        self.definition.session_base = self.mount / "not-created"
        self.definition._read_session_status = mock.Mock(return_value=None)
        self.definition._pending_petal_key_ceremony = mock.Mock(return_value=None)
        self.definition._pending_agent_approval_ceremony = mock.Mock(
            return_value="http://localhost:18734/ceremony/" + "B" * 43
        )
        self.definition._require_empty_wallet = mock.Mock()

        with self.assertRaisesRegex(
            EvalError, "agent approval ceremony is still awaiting user action"
        ):
            self.definition.cleanup()

    def test_cleanup_polls_postconditions_after_accepted_writes(self) -> None:
        # A mounted write returns once accepted for dispatch, so the first read
        # after `cancel_all`, `close_all`, or `stop` can still observe the
        # pre-write state. Reading once turned that into a spurious failure,
        # which then skipped `stop` and left the session live.
        self.definition.session_id = "created"
        self.definition.session_base = self.mount / "created"
        self.definition._read_session_status = mock.Mock(
            return_value={"stopped": False}
        )
        # open_orders: stale, stale, then settled. status.json: stale then stopped.
        self.definition._read_json = mock.Mock(
            side_effect=[
                [{"oid": 1}],
                [{"oid": 1}],
                [],
                {"stopped": False},
                {"stopped": True},
            ]
        )
        self.definition._nonzero_positions = mock.Mock(return_value=[])
        self.definition._require_no_orders_or_positions = mock.Mock()
        self.definition._write_route = mock.Mock(
            return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        )

        with mock.patch.object(hyperliquid_order_cancel.time, "sleep"):
            self.definition.cleanup()

        routes = [
            call.args[0].name for call in self.definition._write_route.call_args_list
        ]
        self.assertEqual(routes, ["cancel_all", "stop"])

    def test_cleanup_reports_failure_when_postcondition_never_settles(self) -> None:
        # Polling must not paper over a genuine failure: a budget that expires
        # still fails cleanup.
        self.definition.session_id = "created"
        self.definition.session_base = self.mount / "created"
        self.definition._read_session_status = mock.Mock(
            return_value={"stopped": False}
        )
        self.definition._read_json = mock.Mock(return_value=[{"oid": 1}])
        self.definition._nonzero_positions = mock.Mock(return_value=[])
        self.definition._require_no_orders_or_positions = mock.Mock()
        self.definition._write_route = mock.Mock(
            return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        )

        with mock.patch.object(hyperliquid_order_cancel.time, "sleep"):
            with self.assertRaisesRegex(EvalError, "still has open orders"):
                self.definition.cleanup()

    def test_cleanup_closes_residual_position_before_stopping(self) -> None:
        self.definition.session_id = "created"
        self.definition.session_base = self.mount / "created"
        self.definition._read_session_status = mock.Mock(
            return_value={"stopped": False}
        )
        self.definition._read_json = mock.Mock(side_effect=[[], {"stopped": True}])
        self.definition._nonzero_positions = mock.Mock(
            side_effect=[[{"position": {"szi": "0.0001"}}], []]
        )
        self.definition._require_no_orders_or_positions = mock.Mock()
        self.definition._write_route = mock.Mock(
            return_value=SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        )

        self.definition.cleanup()

        routes = [
            call.args[0].name for call in self.definition._write_route.call_args_list
        ]
        self.assertEqual(routes, ["cancel_all", "close_all", "stop"])

    def test_provision_accepts_durable_session_after_ambiguous_retry(self) -> None:
        ceremony = "http://localhost:18734/ceremony/" + "A" * 43
        writes: list[bytes] = []

        def write(_path: Path, body: bytes, _timeout: int) -> SimpleNamespace:
            writes.append(body)
            if len(writes) == 1:
                return SimpleNamespace(
                    returncode=1, stdout=ceremony.encode(), stderr=b""
                )
            return SimpleNamespace(returncode=1, stdout=b"ambiguous", stderr=b"")

        reads = 0

        def read(_path: Path, timeout: int = 20) -> object:
            nonlocal reads
            del timeout
            reads += 1
            if reads == 1:
                return None
            request = json.loads(writes[0])
            return {
                "schema": "bloom.hyperliquid_agent_session.v1",
                "network": "mainnet",
                "wallet": self.wallet_id,
                "id": request["id"],
                "max_notional_usd": "11",
                "max_leverage": 1,
                "assets": ["0"],
                "stopped": False,
            }

        self.definition._write_route = mock.Mock(side_effect=write)
        self.definition._read_json_if_exists = mock.Mock(side_effect=read)
        with mock.patch("harness.hyperliquid_order_cancel.subprocess.run") as run:
            run.return_value = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            self.definition.provision("claude")
        self.assertEqual(writes[0], writes[1])
        run.assert_called_once_with(
            [
                str(self.driver),
                "complete",
                ceremony,
                "--authenticator-seed-file",
                str(self.seed),
                "--sign-count",
                "4",
            ],
            check=False,
            capture_output=True,
            timeout=45,
        )

    def test_provision_accepts_durable_session_after_error_without_url(self) -> None:
        written: list[bytes] = []

        def write(_path: Path, body: bytes, _timeout: int) -> SimpleNamespace:
            written.append(body)
            return SimpleNamespace(returncode=1, stdout=b"transport error", stderr=b"")

        def read(_path: Path) -> object:
            request = json.loads(written[0])
            return {
                "schema": "bloom.hyperliquid_agent_session.v1",
                "network": "mainnet",
                "wallet": self.wallet_id,
                "id": request["id"],
                "max_notional_usd": "11",
                "max_leverage": 1,
                "assets": ["0"],
                "stopped": False,
            }

        self.definition._write_route = mock.Mock(side_effect=write)
        self.definition._read_json_if_exists = mock.Mock(side_effect=read)
        self.definition._pending_petal_key_ceremony = mock.Mock(return_value=None)

        context = self.definition.provision("codex")

        self.assertEqual(context.eval_name, "hyperliquid-order-cancel")
        self.assertTrue(self.definition.session_created)
        self.assertEqual(len(written), 1)

    def test_provision_redacts_live_ceremony_url_from_failure(self) -> None:
        ceremony = "http://localhost:18734/ceremony/" + "A" * 43
        self.definition._write_route = mock.Mock(
            side_effect=[
                SimpleNamespace(returncode=1, stdout=ceremony.encode(), stderr=b""),
                SimpleNamespace(returncode=1, stdout=b"retry failed", stderr=b""),
            ]
        )
        self.definition._read_session_status = mock.Mock(return_value=None)
        with mock.patch("harness.hyperliquid_order_cancel.subprocess.run") as run:
            run.return_value = SimpleNamespace(
                returncode=1, stdout=ceremony.encode(), stderr=b"driver failed"
            )
            with self.assertRaises(EvalError) as raised:
                self.definition.provision("codex")
        self.assertNotIn(ceremony, str(raised.exception))
        self.assertIn("[REDACTED_CEREMONY_URL]", str(raised.exception))

    def test_agent_name_is_stable_for_the_wallet(self) -> None:
        # Hyperliquid replaces a named agent when approveAgent arrives under the
        # same name. A name that varied per run would accumulate agents, and
        # clearing them would require deregistration, after which HyperCore may
        # prune nonce state and re-registering the address is replay-unsafe.
        first = self.definition.agent_name
        second = HyperliquidOrderCancelEval(self.repo, dict(self.env)).agent_name
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 16)
        other_env = dict(self.env)
        other_env["BLOOM_EVAL_WALLET_ID"] = "another-eval-wallet"
        other = HyperliquidOrderCancelEval(self.repo, other_env).agent_name
        self.assertNotEqual(first, other, "distinct wallets must not share an agent name")
    def test_agent_name_override_adopts_an_existing_agent(self) -> None:
        # A wallet carrying an agent from an earlier naming scheme cannot be
        # reconciled by a derived name, and the old agent cannot be safely
        # removed. Naming it keeps preflight an exact match rather than
        # widening it to a pattern.
        env = dict(self.env)
        env["BLOOM_EVAL_AGENT_NAME"] = "be-cla-da335ada"
        definition = HyperliquidOrderCancelEval(self.repo, env)
        self.assertEqual(definition.agent_name, "be-cla-da335ada")
        self.assertNotEqual(definition.agent_name, self.definition.agent_name)

        definition._require_no_orders_or_positions = mock.Mock()
        definition._read_json = mock.Mock(
            return_value=[{"name": "be-cla-da335ada", "address": "0x" + "e" * 40}]
        )
        definition._require_empty_wallet()

        definition._read_json = mock.Mock(
            return_value=[{"name": "be-other", "address": "0x" + "f" * 40}]
        )
        with self.assertRaisesRegex(EvalError, "this eval did not create"):
            definition._require_empty_wallet()

        over_long = dict(self.env)
        over_long["BLOOM_EVAL_AGENT_NAME"] = "b" * 17
        with self.assertRaisesRegex(EvalError, "at most 16 characters"):
            _ = HyperliquidOrderCancelEval(self.repo, over_long).agent_name

    def test_preflight_tolerates_this_evals_agent_but_not_a_foreign_one(self) -> None:
        own = [{"name": self.definition.agent_name, "address": "0x" + "c" * 40}]
        foreign = [{"name": "someone-else", "address": "0x" + "d" * 40}]
        self.definition._require_no_orders_or_positions = mock.Mock()
        self.definition._read_json = mock.Mock(return_value=own)
        self.definition._require_empty_wallet()
        self.definition._read_json = mock.Mock(return_value=foreign)
        with self.assertRaisesRegex(EvalError, "this eval did not create"):
            self.definition._require_empty_wallet()
        self.definition._read_json = mock.Mock(return_value=own + foreign)
        with self.assertRaisesRegex(EvalError, "this eval did not create"):
            self.definition._require_empty_wallet()

    def test_eval_image_is_pulled_by_immutable_digest(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="pulled", stderr="")
        with mock.patch.object(
            hyperliquid_order_cancel.subprocess, "run", return_value=completed
        ) as run:
            self.definition._pull_eval_image()

        self.assertEqual(
            run.call_args.args[0],
            ["docker", "pull", hyperliquid_order_cancel.EVAL_IMAGE],
        )
        self.assertIn("@sha256:", hyperliquid_order_cancel.EVAL_IMAGE)

    def test_eval_image_pull_fails_closed(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="manifest unavailable"
        )
        with mock.patch.object(
            hyperliquid_order_cancel.subprocess, "run", return_value=completed
        ):
            with self.assertRaisesRegex(
                EvalError, "pinned Harbor eval image: manifest unavailable"
            ):
                self.definition._pull_eval_image()


if __name__ == "__main__":
    unittest.main()
