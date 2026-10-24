import copy
import tempfile
import unittest
from pathlib import Path

from harness.core import EvalError
from harness.installed import InstalledProjection, InstalledWallet


class Fixture:
    def __init__(self):
        self.listings = {
            "/wallets/main": {"0": "Dir", "1": "Dir"},
            "/petal-signing-requests": {},
            "/petal-key-requests": {},
            "/wallets/main/policy-updates/pending": {},
            "/wallets/main/passkeys/enrollments": {},
            "/wallets/main/sealed-approvals": {},
            "/wallets/recoveries": {},
            "/wallets/registrations": {},
            "/outbox/pending": {"evm-foreign": "Dir"},
        }
        self.records = {
            "/wallets/main/0/account.json": {
                "wallet": "main",
                "number": 0,
                "freshness": "fresh",
                "evm": {"state": "active", "address": InstalledWallet.expected_address},
            },
            "/wallets/main/projection.json": {
                "freshness": "fresh",
                "wallet": {
                    "wallet_id": "main",
                    "policy_version": "12",
                    "policy_digest": "a" * 64,
                },
            },
            "/outbox/pending/evm-foreign/intent.json": {
                "wallet": "primary",
                "id": "foreign",
            },
        }
        for account in (0, 1):
            self.listings[f"/wallets/main/{account}/chains"] = {
                "ethereum": "Dir",
                "base": "Dir",
            }
            self.listings[f"/petals/near-intents/swaps/main/{account}"] = {}
            for chain in ("ethereum", "base"):
                root = f"/wallets/main/{account}/chains/{chain}/outbox"
                self.listings[root] = {
                    state: "Dir" for state in ("pending", "sent", "failed")
                }
                for state in ("pending", "sent", "failed"):
                    self.listings[root + "/" + state] = {}
        self.cancelled = []

    def version(self):
        return "fixture-0.4.0"

    def refresh(self, session):
        self.records[session + "/outbox.json"]["state"] = "failed"
        self.records[session + "/status.json"]["state"] = "deposit_failed"

    def entries(self, path):
        return copy.deepcopy(self.listings[path])

    def read_json(self, path):
        return copy.deepcopy(self.records[path])

    def stage(self):
        session = "/petals/near-intents/swaps/main/0/trial"
        root = "/wallets/main/0/chains/ethereum/outbox"
        self.listings["/petals/near-intents/swaps/main/0"]["trial"] = "Dir"
        self.records[session + "/status.json"] = {
            "id": "trial",
            "wallet": "main",
            "state": "staged",
        }
        self.records[session + "/outbox.json"] = {
            "id": "trial-tx",
            "outbox_root": root,
            "state": "pending",
            "tx_hash": None,
        }
        path = root + "/pending/trial-tx"
        self.listings[root + "/pending"]["trial-tx"] = "Dir"
        intent = {
            "wallet": "main",
            "id": "trial-tx",
            "tx_hash": None,
            "status": "pending",
        }
        self.records[path + "/intent.json"] = intent
        self.listings["/outbox/pending"]["evm-trial-tx"] = "Dir"
        self.records["/outbox/pending/evm-trial-tx/intent.json"] = intent
        return session, path

    def cancel(self, path):
        self.cancelled.append(path)
        root, entry_id = path.rsplit("/", 1)
        del self.listings[root][entry_id]
        self.listings[root.removesuffix("/pending") + "/failed"][entry_id] = "Dir"
        self.records[path.replace("/pending/", "/failed/") + "/intent.json"] = (
            self.records[path + "/intent.json"] | {"status": "cancelled"}
        )
        del self.listings["/outbox/pending"]["evm-" + entry_id]


class InstalledWalletTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.reader = Fixture()
        self.guard = InstalledWallet(self.reader, session_id="trial")
        self.guard.lock_path = Path(self.directory.name) / "main.lock"

    def tearDown(self):
        self.guard.close()
        self.directory.cleanup()

    def test_pending_on_any_account_and_non_origin_chain_refuses_start(self):
        for account, chain in ((0, "ethereum"), (0, "base"), (1, "base")):
            with self.subTest(account=account, chain=chain):
                path = f"/wallets/main/{account}/chains/{chain}/outbox/pending"
                self.reader.listings[path]["existing"] = "Dir"
                with self.assertRaisesRegex(EvalError, "already has pending"):
                    self.guard.begin()
                self.assertIsNone(self.guard.lock)
                self.assertEqual(self.reader.cancelled, [])
                self.reader.listings[path].clear()

    def test_incomplete_inventory_fails_closed(self):
        del self.reader.listings["/wallets/main/1/chains/base/outbox"]["pending"]
        with self.assertRaisesRegex(EvalError, "incomplete"):
            self.guard.begin()
        self.assertEqual(self.reader.cancelled, [])

    def test_pending_signing_and_ceremonies_refuse_start(self):
        name = "b" * 64 + ".json"
        path = "/petal-signing-requests/" + name
        self.reader.listings["/petal-signing-requests"][name] = "File"
        self.reader.records[path] = {
            "wallet": "main",
            "status": "awaiting_owner_approval",
        }
        with self.assertRaisesRegex(EvalError, "pending Petal"):
            self.guard.begin()
        self.reader.records[path]["status"] = "signed"
        self.reader.listings["/wallets/main/policy-updates/pending"]["policy-trial"] = (
            "Dir"
        )
        with self.assertRaisesRegex(EvalError, "pending policy"):
            self.guard.begin()

    def test_other_wallet_pending_work_is_preserved(self):
        self.guard.begin()
        self.guard.cancel_owned()
        self.assertIn("evm-foreign", self.reader.listings["/outbox/pending"])
        self.assertEqual(self.reader.cancelled, [])

    def test_only_trusted_new_swap_record_can_attribute_cleanup(self):
        self.guard.begin()
        session, path = self.reader.stage()
        self.assertEqual(self.guard.attribute_near(session), path)
        self.guard.cancel_owned()
        self.assertEqual(self.reader.cancelled, [path])
        self.assertIn("evm-foreign", self.reader.listings["/outbox/pending"])
        self.guard.close()
        self.guard.begin()
        self.assertEqual(self.guard.before["machine_version"], "fixture-0.4.0")
        self.guard.cancel_owned()
        self.assertEqual(self.reader.cancelled, [path])

    def test_wrong_endpoint_or_main_address_refuses_start(self):
        with self.assertRaisesRegex(EvalError, "endpoint differs"):
            InstalledProjection(endpoint="unix:/tmp/another-machine.sock")
        self.reader.records["/wallets/main/0/account.json"]["evm"]["address"] = (
            "0x" + "1" * 40
        )
        with self.assertRaisesRegex(EvalError, "wrong main account"):
            self.guard.begin()
        self.assertEqual(self.reader.cancelled, [])

    def test_foreign_addition_after_snapshot_preserves_all_pending_work(self):
        self.guard.begin()
        session, _ = self.reader.stage()
        self.guard.attribute_near(session)
        self.reader.listings["/wallets/main/1/chains/base/outbox/pending"][
            "user-race"
        ] = "Dir"
        with self.assertRaisesRegex(EvalError, "unattributed outbox"):
            self.guard.cancel_owned()
        self.assertEqual(self.reader.cancelled, [])

    def test_changed_attribution_is_preserved(self):
        self.guard.begin()
        session, _ = self.reader.stage()
        self.guard.attribute_near(session)
        self.reader.records[session + "/outbox.json"]["id"] = "user-entry"
        with self.assertRaisesRegex(EvalError, "ownership changed"):
            self.guard.cancel_owned()
        self.assertEqual(self.reader.cancelled, [])

    def test_unrelated_new_session_cannot_be_claimed_as_trial_work(self):
        self.guard.begin()
        session, _ = self.reader.stage()
        self.guard.session_id = "different-trial"
        with self.assertRaisesRegex(EvalError, "new trusted"):
            self.guard.attribute_near(session)
        self.assertEqual(self.reader.cancelled, [])

    def test_staged_session_even_without_outbox_inventory_refuses_start(self):
        session = "/petals/near-intents/swaps/main/1/old-user-swap"
        self.reader.listings["/petals/near-intents/swaps/main/1"]["old-user-swap"] = (
            "Dir"
        )
        self.reader.records[session + "/status.json"] = {
            "id": "old-user-swap",
            "state": "staged",
            "wallet": "main",
        }
        with self.assertRaisesRegex(EvalError, "unresolved NEAR"):
            self.guard.begin()
        self.assertEqual(self.reader.cancelled, [])

    def test_policy_change_is_detected_before_cleanup(self):
        self.guard.begin()
        session, _ = self.reader.stage()
        self.guard.attribute_near(session)
        self.reader.records["/wallets/main/projection.json"]["wallet"][
            "policy_version"
        ] = "13"
        with self.assertRaisesRegex(EvalError, "policy changed"):
            self.guard.cancel_owned()
        self.assertEqual(self.reader.cancelled, [])

    def test_preexisting_swap_cannot_be_claimed_as_trial_work(self):
        session, _ = self.reader.stage()
        self.guard.before = self.guard.snapshot()
        with self.assertRaisesRegex(EvalError, "new trusted"):
            self.guard.attribute_near(session)
        self.assertEqual(self.reader.cancelled, [])

    def test_agent_mount_only_exposes_the_exact_stage_sink_for_writes(self):
        mounts = self.guard.mounts()
        self.assertTrue(mounts[0]["read_only"])
        self.assertEqual(
            mounts[1]["target"], "/bloom/petals/near-intents/swaps/main/0/new"
        )
        self.assertFalse(mounts[1]["read_only"])
