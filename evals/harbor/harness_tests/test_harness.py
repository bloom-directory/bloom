from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from harness.core import AgentSpec, EvalDefinition, EvalError, EvalRunContext, run_eval
from harness.hyperliquid_order_cancel import (
    ACTION_FILES,
    MAINNET_ACK,
    HyperliquidOrderCancelEval,
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
        self.seed = self.root / "seed"
        self.seed.write_text("seed")
        self.seed.chmod(0o600)
        self.env = {
            "BLOOM_EVAL_WALLET": self.wallet,
            "BLOOM_EVAL_WALLET_ID": self.wallet_id,
            "BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH": self.package_hash,
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

        with self.assertRaisesRegex(EvalError, "must not retain funding destinations"):
            self.definition._require_exact_wallet_policy()

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
                    "wallet": self.wallet,
                    "id": request["id"],
                    "max_notional_usd": "11",
                    "max_leverage": 1,
                    "assets": ["0"],
                    "stopped": False,
                }
            raise AssertionError(path)

        self.definition._write_route = mock.Mock(side_effect=write)
        self.definition._read_json = mock.Mock(side_effect=read)
        context = self.definition.provision("codex")

        request = __import__("json").loads(written[0][1])
        self.assertLessEqual(len(request["agent_name"]), 16)
        self.assertTrue(request["agent_name"].startswith("be-cod-"))
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

    def test_cleanup_before_session_creation_only_verifies_empty_wallet(self) -> None:
        self.definition.session_id = "not-created"
        self.definition.session_base = self.mount / "not-created"
        self.definition._require_empty_wallet = mock.Mock()
        self.definition._read_json_if_exists = mock.Mock(return_value=None)
        self.definition._write_route = mock.Mock()

        self.definition.cleanup()

        self.definition._require_empty_wallet.assert_called_once_with()
        self.definition._read_json_if_exists.assert_called_once_with(
            self.definition.session_base / "status.json"
        )
        self.definition._write_route.assert_not_called()

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

        def read(_path: Path, timeout: int = 20) -> object:
            del timeout
            request = json.loads(writes[0])
            return {
                "schema": "bloom.hyperliquid_agent_session.v1",
                "network": "mainnet",
                "wallet": self.wallet,
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
                "wallet": self.wallet,
                "id": request["id"],
                "max_notional_usd": "11",
                "max_leverage": 1,
                "assets": ["0"],
                "stopped": False,
            }

        self.definition._write_route = mock.Mock(side_effect=write)
        self.definition._read_json_if_exists = mock.Mock(side_effect=read)

        context = self.definition.provision("codex")

        self.assertEqual(context.eval_name, "hyperliquid-order-cancel")
        self.assertTrue(self.definition.session_created)
        self.assertEqual(len(written), 1)


if __name__ == "__main__":
    unittest.main()
