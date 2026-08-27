from __future__ import annotations

import json
import stat
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from harness.core import EvalError
from harness.operator import (
    DEFAULT_STATE_RELATIVE,
    STATE_PURPOSE,
    STATE_SCHEMA,
    PolicyLifecycle,
    StateStore,
    atomic_write,
    canonical_json,
    definition_env,
    handoff_metadata,
    initialize,
    parser,
    redact,
    require_no_pending_owner_requests,
)


class OperatorStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "state.json")
        handoff, recovery = handoff_metadata(self.store)
        self.state = {
            "schema": STATE_SCHEMA,
            "purpose": STATE_PURPOSE,
            "handoff": handoff,
            "field_guide": {
                "paths": "paths",
                "lineage": "lineage",
                "next_sign_count": "counter",
                "pending_policy_recovery": "recovery marker",
            },
            "recovery": recovery,
            "next_sign_count": 7,
            "wallet_id": "eval-wallet",
            "wallet_address": "0x" + "a" * 40,
            "package_hash": "b" * 64,
            "model": "codex",
            "agent_name": None,
            "pending_policy_recovery": None,
            "paths": {
                "triad_root": str(self.root / "triad"),
                "bloom_mount": str(self.root / "mount"),
                "petal_owner_record": str(self.root / "owner.json"),
                "petal_store": str(self.root / "store"),
                "provenance_catalog": str(self.root / "catalog.json"),
                "authenticator_seed_file": str(self.root / "seed"),
                "debug_driver": str(self.root / "driver"),
                "lock_file": str(self.root / "lock"),
                "jobs_dir": str(self.root / "jobs"),
            },
        }
        self.store.write(self.state)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_state_is_mode_0600_and_counter_update_is_atomic(self) -> None:
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)
        self.store.update_counter(8)
        self.assertEqual(self.store.read()["next_sign_count"], 8)
        self.assertFalse(list(self.root.glob(".state.json.new-*")))
        with self.assertRaisesRegex(EvalError, "non-advancing"):
            self.store.update_counter(8)

    def test_default_handoff_is_repository_local_and_self_describing(self) -> None:
        args = parser(self.root).parse_args(["status"])
        self.assertEqual(args.state, self.root / DEFAULT_STATE_RELATIVE)
        with self.store.path.open() as handle:
            directly_ingested = json.load(handle)
        loaded = self.store.read()
        self.assertEqual(directly_ingested, loaded)
        self.assertEqual(loaded["purpose"], STATE_PURPOSE)
        self.assertTrue(loaded["handoff"]["agent_readable"])
        self.assertFalse(loaded["handoff"]["contains_secret_contents"])
        self.assertEqual(
            loaded["handoff"]["required_secret_path_fields"],
            ["paths.authenticator_seed_file"],
        )

    def test_operator_launcher_uses_only_isolated_uv_python_312(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        launcher = (
            repo_root / "scripts/evals/operate-harbor-hyperliquid.sh"
        ).read_text()
        self.assertNotIn("exec python3", launcher)
        self.assertEqual(launcher.count("exec uv run --isolated --no-project"), 2)
        self.assertEqual(launcher.count("--python 3.12"), 2)

    def test_state_rejects_stale_recovery_locations(self) -> None:
        state = self.store.read()
        state["recovery"]["policy_backup_file"] = str(self.root / "wrong.json")
        self.store.write(state)
        with self.assertRaisesRegex(EvalError, "recovery locations"):
            self.store.read()

    def test_state_rejects_broad_permissions_and_symlinks(self) -> None:
        self.store.path.chmod(0o644)
        with self.assertRaisesRegex(EvalError, "mode 0600"):
            self.store.read()
        self.store.path.unlink()
        target = self.root / "target.json"
        atomic_write(target, canonical_json(self.state))
        self.store.path.symlink_to(target)
        with self.assertRaisesRegex(EvalError, "non-symlink"):
            self.store.read()

    def test_definition_environment_honors_non_default_mount(self) -> None:
        env = definition_env(self.state)
        self.assertEqual(env["BLOOM_EVAL_BLOOM_MOUNT"], str(self.root / "mount"))
        self.assertEqual(
            env["BLOOM_EVAL_PETAL_OWNER_RECORD"], str(self.root / "owner.json")
        )
        self.assertNotIn("BLOOM_EVAL_AGENT_NAME", env)

    def test_redaction_removes_identifiers_paths_and_ceremony_urls(self) -> None:
        ceremony = "http://localhost:18734/ceremony/" + "A" * 43
        message = redact(
            EvalError(
                f"{self.state['wallet_id']} {self.state['wallet_address']} "
                f"{self.state['paths']['authenticator_seed_file']} {ceremony}"
            ),
            self.state,
        )
        self.assertNotIn(self.state["wallet_id"], message)
        self.assertNotIn(self.state["wallet_address"], message)
        self.assertNotIn(str(self.root), message)
        self.assertNotIn(ceremony, message)

    def test_init_cannot_replace_state_while_policy_recovery_is_pending(self) -> None:
        atomic_write(self.store.backup_path, b"{}\n")
        with self.assertRaisesRegex(EvalError, "recovery is pending"):
            initialize(Namespace(state=self.store.path), self.root)


class FakePolicyDefinition:
    def __init__(self, root: Path) -> None:
        self.bloom_mount = root / "mount"
        self.wallet_root = self.bloom_mount / "wallets/eval-wallet"
        self.wallet_root.mkdir(parents=True)
        self.driver = root / "driver"
        self.seed_file = root / "seed"
        self.sign_count_value = "7"

    def _read_json(self, path: Path, timeout: int = 45) -> object:
        del timeout
        return json.loads(path.read_bytes())

    def _write_route(self, path: Path, body: bytes, timeout: int) -> object:
        del timeout
        path.write_bytes(body)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


class PolicyRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "state.json")
        handoff, recovery = handoff_metadata(self.store)
        self.state = {
            "schema": STATE_SCHEMA,
            "purpose": STATE_PURPOSE,
            "handoff": handoff,
            "field_guide": {
                "paths": "paths",
                "lineage": "lineage",
                "next_sign_count": "counter",
                "pending_policy_recovery": "recovery marker",
            },
            "recovery": recovery,
            "next_sign_count": 7,
            "wallet_id": "eval-wallet",
            "package_hash": "b" * 64,
            "pending_policy_recovery": None,
        }
        self.store.write(self.state)
        self.definition = FakePolicyDefinition(self.root)
        self.original = {
            "allowed_destinations": [],
            "allowed_petal_packages": [],
            "maximum_approval_lifetime_ms": 2_592_000_000,
            "required_verifiers": [],
            "wallet_id": "eval-wallet",
        }
        self.policy_path = self.definition.wallet_root / "policy.json"
        self.policy_path.write_bytes(canonical_json(self.original))
        self.lifecycle = PolicyLifecycle(
            self.store,
            self.state,
            self.definition,  # type: ignore[arg-type]
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_activation_persists_backup_before_policy_mutation(self) -> None:
        observed: list[bool] = []

        def fail(_target: bytes) -> None:
            observed.append(self.store.backup_path.exists())
            raise EvalError("interrupted")

        self.lifecycle.apply = mock.Mock(side_effect=fail)
        with self.assertRaisesRegex(EvalError, "interrupted"):
            self.lifecycle.activate()
        self.assertEqual(observed, [True])
        self.assertEqual(stat.S_IMODE(self.store.backup_path.stat().st_mode), 0o600)
        self.assertIsNotNone(self.store.read()["pending_policy_recovery"])

    def test_restore_uses_exact_backup_then_clears_recovery_marker(self) -> None:
        atomic_write(self.store.backup_path, canonical_json(self.original) + b"\n")
        pending = self.store.read()
        pending["pending_policy_recovery"] = {
            "operation_id": None,
            "target_digest": "x",
        }
        self.store.write(pending)
        applied: list[bytes] = []
        self.lifecycle.apply = mock.Mock(side_effect=applied.append)

        self.lifecycle.restore()

        self.assertEqual(applied, [canonical_json(self.original)])
        self.assertFalse(self.store.backup_path.exists())
        self.assertIsNone(self.store.read()["pending_policy_recovery"])

    def test_failed_ceremony_advances_candidate_before_error(self) -> None:
        target = canonical_json(dict(self.original, allowed_petal_packages=["b" * 64]))
        challenge = {
            "operation_id": "operation",
            "ceremony_url": "http://localhost:18734/ceremony/" + "A" * 43,
        }
        self.lifecycle._wait_challenge = mock.Mock(return_value=challenge)
        with (
            mock.patch(
                "harness.operator.subprocess.run",
                return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b""),
            ),
            self.assertRaisesRegex(EvalError, "next candidate is 8"),
        ):
            self.lifecycle.apply(target)
        self.assertEqual(self.store.read()["next_sign_count"], 8)

    def test_init_rejects_matching_pending_owner_request(self) -> None:
        request_root = self.root / "mount/petal-signing-requests"
        request_root.mkdir(parents=True)
        (request_root / ("a" * 64 + ".json")).write_text(
            json.dumps(
                {
                    "status": "awaiting_owner_approval",
                    "wallet": "eval-wallet",
                    "package_hash": "b" * 64,
                }
            )
        )
        with self.assertRaisesRegex(EvalError, "owner ceremony is pending"):
            require_no_pending_owner_requests(
                self.definition,  # type: ignore[arg-type]
                "eval-wallet",
                "b" * 64,
            )


if __name__ == "__main__":
    unittest.main()
