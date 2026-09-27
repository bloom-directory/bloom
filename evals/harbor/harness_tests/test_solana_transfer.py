"""Tests for the Solana transfer eval definition.

The chain identity check, the per-trial destination and policy, and the
background approver's match and replacement-lineage checks are the places
where a mistake would approve a transfer nobody configured, so they carry most
of the coverage here.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from harness.core import EvalDefinition, EvalError, _agent_spec
from harness.solana_transfer import (
    HARNESS_MAX_TRANSFER_LAMPORTS,
    LOCAL_HISTORY_MIN_SLOTS,
    MAX_TRANSFER_CEREMONIES,
    MAINNET_GENESIS_HASH,
    SolanaTransferEval,
)

SOURCE = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
DESTINATION = "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu"
WALLET_ID = "eval-solana"
CHAIN = "solana-local"
FINGERPRINT = "a" * 64
LOCAL_GENESIS = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
DERIVATION = "m/44'/501'/0'/0'"
TRANSFER = 1_000_000
FEE_CAP = 10_000


class SolanaEvalTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()

        mount = Path(self.env()["BLOOM_EVAL_BLOOM_MOUNT"])
        account_root = mount / "wallets" / WALLET_ID / "0" / "chains" / CHAIN
        outbox = account_root / "outbox"
        outbox.mkdir(parents=True)
        (outbox / "new.tx").write_text("")
        # The authenticated account projection the identity resolution reads:
        # one active Solana child, numbered account directory 0.
        (mount / "wallets" / WALLET_ID / "accounts.json").write_text(
            json.dumps(
                {
                    "wallet_id": WALLET_ID,
                    "accounts": [
                        {
                            "derivation_profile": "bip44-solana-slip10-ed25519-v1",
                            "lifecycle": "ACTIVE",
                            "public_key_fingerprint": FINGERPRINT,
                            "path": DERIVATION,
                            "number": 0,
                        }
                    ],
                }
            )
        )
        (account_root / "address").write_text(SOURCE + "\n")

    def env(self, **overrides: str) -> dict[str, str]:
        value = {
            "BLOOM_EVAL_SOLANA_WALLET_ID": WALLET_ID,
            "BLOOM_EVAL_SOLANA_CHAIN": CHAIN,
            "BLOOM_EVAL_SOLANA_RPC_URL": "http://127.0.0.1:8899",
            "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT": "2",
            "BLOOM_EVAL_BLOOM_MOUNT": str(self.root / "bloom"),
        }
        value.update(overrides)
        return value

    def make(self, **overrides: str) -> SolanaTransferEval:
        return SolanaTransferEval(self.repo, self.env(**overrides))

    def provision(self, definition: SolanaTransferEval, agent: str = "codex"):
        """Provision with the fixed test destination and no live policy
        ceremony or approver thread."""
        with mock.patch.object(
            definition, "_fresh_destination", return_value=DESTINATION
        ), mock.patch.object(definition, "_allow_only_destination"), mock.patch.object(
            definition, "_start_approver"
        ):
            return definition.provision(agent)


class ChainIdentityTests(SolanaEvalTestCase):
    """A label saying local is insufficient; the chain answers for itself."""

    def test_a_mainnet_endpoint_is_refused(self) -> None:
        definition = self.make()
        with mock.patch.object(definition, "_rpc", return_value=MAINNET_GENESIS_HASH):
            with self.assertRaisesRegex(EvalError, "serves the mainnet-beta genesis"):
                definition._require_chain_identity()

    def test_a_non_mainnet_genesis_is_accepted(self) -> None:
        definition = self.make()
        with mock.patch.object(definition, "_rpc", return_value="Eth2Val" * 6):
            definition._require_chain_identity()

    def test_an_unreadable_genesis_is_rejected(self) -> None:
        definition = self.make()
        with mock.patch.object(definition, "_rpc", return_value=None):
            with self.assertRaisesRegex(EvalError, "genesis hash"):
                definition._require_chain_identity()


class PreflightTests(SolanaEvalTestCase):
    def test_the_full_eval_requires_an_explicit_mount_selection(self) -> None:
        definition = self.make(BLOOM_EVAL_BLOOM_MOUNT="")
        with self.assertRaisesRegex(EvalError, "BLOOM_EVAL_BLOOM_MOUNT is required"):
            definition.preflight()

    def test_an_amount_above_the_ceiling_is_rejected(self) -> None:
        definition = self.make(
            BLOOM_EVAL_SOLANA_LAMPORTS=str(HARNESS_MAX_TRANSFER_LAMPORTS + 1)
        )
        with self.assertRaisesRegex(EvalError, "exceeds the harness"):
            definition.preflight()

    def test_a_fee_ceiling_above_the_harness_ceiling_is_rejected(self) -> None:
        definition = self.make(
            BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS=str(HARNESS_MAX_TRANSFER_LAMPORTS + 1)
        )
        with self.assertRaisesRegex(EvalError, "fee ceiling"):
            definition.preflight()

    def test_a_fee_ceiling_must_be_positive(self) -> None:
        definition = self.make(BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS="0")
        with self.assertRaisesRegex(EvalError, "positive integer"):
            definition.preflight()

    def test_a_complete_configuration_passes(self) -> None:
        home = self.root / "home"
        home.mkdir()
        definition = self.make(BLOOM_EVAL_SOLANA_HOME_ROOT=str(home))
        answers = {"getGenesisHash": LOCAL_GENESIS, "getSlot": 300, "getFirstAvailableBlock": 0}
        with mock.patch.object(
            definition, "_rpc", side_effect=lambda method, _params: answers[method]
        ), mock.patch("shutil.which", return_value="/usr/bin/bloom"), mock.patch(
            "os.path.ismount", return_value=True
        ), mock.patch("harness.core.CeremonyDriver.preflight"):
            definition.preflight()
        self.assertEqual(definition.lamports, 1_000_000)
        self.assertEqual(definition.genesis_hash, LOCAL_GENESIS)
        self.assertEqual(definition.history_start_slot, 300)
        self.assertEqual(definition.source_address, SOURCE)

    def test_the_bloom_cli_is_required(self) -> None:
        home = self.root / "home"
        home.mkdir()
        definition = self.make(BLOOM_EVAL_SOLANA_HOME_ROOT=str(home))
        answers = {"getGenesisHash": LOCAL_GENESIS, "getSlot": 300, "getFirstAvailableBlock": 0}
        with mock.patch.object(
            definition, "_rpc", side_effect=lambda method, _params: answers[method]
        ), mock.patch("shutil.which", return_value=None):
            with self.assertRaisesRegex(EvalError, "bloom CLI"):
                definition.preflight()

    def test_preauthorization_only_is_the_read_only_preflight(self) -> None:
        definition = self.make(BLOOM_EVAL_SOLANA_RPC_URL="")
        with self.assertRaisesRegex(EvalError, "RPC_URL is required"):
            definition.preauthorization_preflight()


class LocalIdentityTests(SolanaEvalTestCase):
    def test_local_identity_comes_from_the_authenticated_account_projection(self) -> None:
        definition = self.make()
        projection = {
            "wallet_id": WALLET_ID,
            "accounts": [
                {
                    "derivation_profile": "bip44-solana-slip10-ed25519-v1",
                    "lifecycle": "ACTIVE",
                    "public_key_fingerprint": FINGERPRINT,
                    "path": DERIVATION,
                    "number": 0,
                }
            ],
        }
        with mock.patch.object(definition.mount, "read_json", return_value=projection):
            with mock.patch.object(
                definition.mount, "read_text", return_value=SOURCE + "\n"
            ):
                definition._load_local_account_identity()

        self.assertEqual(definition.source_address, SOURCE)
        self.assertEqual(definition.key_fingerprint, FINGERPRINT)
        self.assertEqual(definition.derivation_path, DERIVATION)
        self.assertEqual(definition.account_dir, "0")

    def test_local_identity_refuses_multiple_active_solana_accounts(self) -> None:
        definition = self.make()
        account = {
            "derivation_profile": "bip44-solana-slip10-ed25519-v1",
            "lifecycle": "ACTIVE",
            "public_key_fingerprint": FINGERPRINT,
            "path": DERIVATION,
            "number": 0,
        }
        projection = {"wallet_id": WALLET_ID, "accounts": [account, account]}
        with mock.patch.object(definition.mount, "read_json", return_value=projection):
            with self.assertRaisesRegex(EvalError, "exactly one active"):
                definition._load_local_account_identity()

class ApproverMatchTests(SolanaEvalTestCase):
    """The approver runs while the agent is live, so it must never rubber-stamp
    whatever the agent staged."""

    def setUp(self) -> None:
        super().setUp()
        self.home = self.root / "home"
        self.definition = self.make(BLOOM_EVAL_SOLANA_HOME_ROOT=str(self.home))
        self.definition.destination = DESTINATION
        self.definition.lamports = TRANSFER
        self.definition.max_fee_lamports = FEE_CAP
        self.definition.source_address = SOURCE
        self.definition.key_fingerprint = FINGERPRINT
        self.definition.derivation_path = DERIVATION
        self.definition.genesis_hash = LOCAL_GENESIS
        # `HomeDir::solana_outbox_dir` is `<home>/.solana-outbox`, and entries
        # live at `<root>/<wallet>/<chain>/<state>/<id>/`.
        self.entry = (
            self.home / ".solana-outbox" / WALLET_ID / CHAIN / "pending" / "0001"
        )
        self.entry.mkdir(parents=True)

    def stage(self, pending_id: str = "0001", **overrides: object) -> Path:
        # Field names and the hex fingerprint encoding are those of
        # `StagedSolanaTransfer`, confirmed against a live local validator run.
        intent: dict[str, object] = {
            "destination": DESTINATION,
            "lamports": TRANSFER,
            "fee_payer": SOURCE,
            "fee_lamports": 5000,
            "account_fingerprint": FINGERPRINT,
            "account_derivation_path": DERIVATION,
            "genesis_hash": LOCAL_GENESIS,
        }
        intent.update(overrides)
        entry = self.entry.parent / pending_id
        entry.mkdir(parents=True, exist_ok=True)
        (entry / "intent.json").write_text(json.dumps(intent))
        return entry

    def matches(self) -> bool:
        return self.definition._ceremony_matches_authorized_transfer("0001")

    def test_the_configured_transfer_matches(self) -> None:
        self.stage()
        self.assertTrue(self.matches())

    def test_another_destination_does_not_match(self) -> None:
        self.stage(destination=SOURCE)
        self.assertFalse(self.matches())

    def test_another_amount_does_not_match(self) -> None:
        self.stage(lamports=TRANSFER + 1)
        self.assertFalse(self.matches())

    def test_another_cluster_does_not_match(self) -> None:
        # The genesis the harness checked is the one it approves: an intent
        # the Machine staged against another cluster is refused.
        self.stage(genesis_hash=MAINNET_GENESIS_HASH)
        self.assertFalse(self.matches())

    def test_a_missing_genesis_does_not_match(self) -> None:
        self.stage(genesis_hash=None)
        self.assertFalse(self.matches())

    def test_another_fee_payer_does_not_match(self) -> None:
        self.stage(fee_payer=DESTINATION)
        self.assertFalse(self.matches())

    def test_a_fee_above_the_ceiling_does_not_match(self) -> None:
        self.stage(fee_lamports=FEE_CAP + 1)
        self.assertFalse(self.matches())

    def test_a_missing_fee_cannot_borrow_the_ceiling(self) -> None:
        self.stage(fee_lamports=None)
        self.assertFalse(self.matches())

    def test_another_signing_account_does_not_match(self) -> None:
        # A second active child must never have a message approved that was
        # staged against the first.
        self.stage(account_fingerprint="b" * 64)
        self.assertFalse(self.matches())

    def test_a_missing_signing_account_pin_does_not_match(self) -> None:
        # Omitting identity fields must never silently bypass the check.
        self.stage(account_fingerprint=None)
        self.assertFalse(self.matches())

    def test_a_missing_derivation_path_does_not_match(self) -> None:
        self.stage(account_derivation_path=None)
        self.assertFalse(self.matches())

    def test_another_derivation_path_does_not_match(self) -> None:
        self.stage(account_derivation_path="m/44'/501'/9'/0'")
        self.assertFalse(self.matches())

    def test_the_fingerprint_comparison_ignores_hex_case(self) -> None:
        self.stage(account_fingerprint=FINGERPRINT.upper())
        self.assertTrue(self.matches())

    def test_a_missing_intent_does_not_match(self) -> None:
        self.assertFalse(self.matches())


class ReplacementLineageTests(ApproverMatchTests):
    """A restaged replacement is the same payment only when the outbox's own
    restage advice says so."""

    def advice(self, replacement_id: str) -> dict[str, object]:
        return {
            "schema": "bloom.solana-restage-advice/1",
            "reason": "blockhash_expired",
            "replacement_id": replacement_id,
            "wallet": WALLET_ID,
            "chain": CHAIN,
        }

    def publish_advice(self, expired_id: str, replacement_id: str) -> None:
        expired = self.home / ".solana-outbox" / WALLET_ID / CHAIN / "failed" / expired_id
        expired.mkdir(parents=True, exist_ok=True)
        (expired / "restage_advice.json").write_text(
            json.dumps(self.advice(replacement_id))
        )

    def test_a_lineaged_replacement_is_accepted(self) -> None:
        self.definition._approved_lineage.append("0001")
        self.publish_advice("0001", "0002")
        self.assertTrue(self.definition._replacement_is_authorized("0002"))

    def test_a_replacement_restaged_again_before_approval_is_accepted(self) -> None:
        # 0001 approved and expired; its replacement 0002 expired before it
        # was approved and was restaged to 0003. The chain still reaches 0003.
        self.definition._approved_lineage.append("0001")
        self.publish_advice("0001", "0002")
        self.publish_advice("0002", "0003")
        self.assertTrue(self.definition._replacement_is_authorized("0003"))

    def test_a_chain_that_never_reaches_the_entry_is_refused(self) -> None:
        self.definition._approved_lineage.append("0001")
        self.publish_advice("0001", "0002")
        self.publish_advice("0002", "0003")
        # 0003 has no advice yet, so 0009 is not reached: wait, not accept.
        self.assertIsNone(self.definition._replacement_is_authorized("0009"))

    def test_a_replacement_for_a_different_id_is_refused(self) -> None:
        self.definition._approved_lineage.append("0001")
        self.publish_advice("0001", "0009")
        self.assertFalse(self.definition._replacement_is_authorized("0002"))

    def test_an_entry_without_lineage_is_refused(self) -> None:
        # A fresh second staging with an identical destination and amount is
        # a new payment attempt, not a replacement.
        self.assertFalse(self.definition._replacement_is_authorized("0002"))

    def test_an_unpublished_advice_is_not_yet_an_approval(self) -> None:
        self.definition._approved_lineage.append("0001")
        self.assertIsNone(self.definition._replacement_is_authorized("0002"))

    def test_a_wrong_advice_schema_is_an_error(self) -> None:
        self.definition._approved_lineage.append("0001")
        failed = self.home / ".solana-outbox" / WALLET_ID / CHAIN / "failed" / "0001"
        failed.mkdir(parents=True, exist_ok=True)
        (failed / "restage_advice.json").write_text(
            json.dumps({"schema": "bloom.something-else/1"})
        )
        with self.assertRaisesRegex(EvalError, "unexpected schema"):
            self.definition._replacement_is_authorized("0002")

    def test_the_approver_accepts_only_the_lineaged_successor(self) -> None:
        # 0001 was approved, then expired and was restaged into 0002.
        self.stage("0001")
        replacement = self.stage("0002")
        self.publish_advice("0001", "0002")
        url_repl = "http://localhost:18734/ceremony/" + "B" * 43
        (replacement / "approval_challenge.json").write_text(
            json.dumps({"ceremony_url": url_repl})
        )
        self.definition._approved_lineage.append("0001")
        definition = self.definition

        def complete(url: str) -> None:
            definition._approver_stop.set()

        ceremonies = SimpleNamespace(
            completed=set(), next_sign_count=4, complete=mock.Mock(side_effect=complete)
        )

        with mock.patch.object(
            self.definition,
            "_pending_confirm_ceremony",
            side_effect=lambda _id: url_repl,
        ):
            definition._approve_loop(ceremonies)

        ceremonies.complete.assert_called_once_with(url_repl)
        self.assertEqual(definition._approved_lineage, ["0001", "0002"])

    def test_the_approver_refuses_a_second_fresh_staging(self) -> None:
        first = self.stage("0001")
        second = self.stage("0002")
        first_url = "http://localhost:18734/ceremony/" + "A" * 43
        second_url = "http://localhost:18734/ceremony/" + "B" * 43
        (first / "approval_challenge.json").write_text(
            json.dumps({"ceremony_url": first_url})
        )
        (second / "approval_challenge.json").write_text(
            json.dumps({"ceremony_url": second_url})
        )
        # The lineage continues elsewhere, so the second staging is a new
        # payment attempt and must be refused at once.
        self.publish_advice("0001", "0009")
        ceremonies = SimpleNamespace(
            completed=set(), next_sign_count=3, complete=mock.Mock()
        )

        self.definition._approve_loop(ceremonies)

        ceremonies.complete.assert_called_once_with(first_url)
        self.assertIn(
            "0002 does not continue the approved replacement lineage",
            self.definition._approver_refusal or "",
        )

    def test_a_replacement_without_advice_waits_within_the_grace(self) -> None:
        # No advice has landed yet: inside the grace the approver polls rather
        # than refusing, and a short budget surfaces as an expiry.
        self.definition._approved_lineage.append("0001")
        replacement = self.stage("0002")
        url = "http://localhost:18734/ceremony/" + "B" * 43
        (replacement / "approval_challenge.json").write_text(
            json.dumps({"ceremony_url": url})
        )
        ceremonies = SimpleNamespace(
            completed=set(), next_sign_count=3, complete=mock.Mock()
        )

        with mock.patch("harness.solana_transfer.APPROVER_BUDGET_SECONDS", 0.2):
            self.definition._approve_loop(ceremonies)

        ceremonies.complete.assert_not_called()
        error = self.definition._approver_error
        self.assertIsNotNone(error)
        assert error is not None
        self.assertIn("budget expired", error)

    def test_an_approval_past_the_cap_is_refused_with_its_reason(self) -> None:
        self.definition._approved_lineage.append("0001")
        self.definition._approver_completed = MAX_TRANSFER_CEREMONIES
        self.publish_advice("0001", "0002")
        replacement = self.stage("0002")
        url = "http://localhost:18734/ceremony/" + "C" * 43
        (replacement / "approval_challenge.json").write_text(
            json.dumps({"ceremony_url": url})
        )
        ceremonies = SimpleNamespace(
            completed=set(), next_sign_count=3, complete=mock.Mock()
        )

        self.definition._approve_loop(ceremonies)

        ceremonies.complete.assert_not_called()
        self.assertIn("past the cap", self.definition._approver_refusal or "")

    def test_a_fresh_staging_is_refused_after_the_grace(self) -> None:
        # The predecessor expired but was never restaged, so no advice will
        # ever land: refuse with the reason instead of idling out the budget.
        self.definition._approved_lineage.append("0001")
        replacement = self.stage("0002")
        url = "http://localhost:18734/ceremony/" + "B" * 43
        (replacement / "approval_challenge.json").write_text(
            json.dumps({"ceremony_url": url})
        )
        ceremonies = SimpleNamespace(
            completed=set(), next_sign_count=3, complete=mock.Mock()
        )

        with mock.patch("harness.solana_transfer.RESTAGE_ADVICE_GRACE_SECONDS", 0.0):
            self.definition._approve_loop(ceremonies)

        ceremonies.complete.assert_not_called()
        self.assertIn(
            "no restage advice names it", self.definition._approver_refusal or ""
        )


class BudgetExpiryTests(ApproverMatchTests):
    """A budget expiry must read as a budget expiry, never as agent failure."""

    def run_loop(self) -> None:
        with mock.patch("harness.solana_transfer.APPROVER_BUDGET_SECONDS", -1):
            self.definition._approve_loop(mock.Mock())

    def test_an_unapproved_staging_is_recorded_on_expiry(self) -> None:
        self.run_loop()
        error = self.definition._approver_error
        self.assertIsNotNone(error)
        assert error is not None
        self.assertIn("budget expired", error)
        self.assertIn("1 pending", error)

    def test_an_empty_outbox_expires_silently(self) -> None:
        self.entry.rmdir()
        self.run_loop()
        self.assertIsNone(self.definition._approver_error)

    def test_a_stopped_approver_expires_silently(self) -> None:
        self.definition._approver_stop.set()
        self.run_loop()
        self.assertIsNone(self.definition._approver_error)


class CeremonyDiscoveryTests(ApproverMatchTests):
    """The host watches the canonical approval challenge in outbox state."""

    def test_no_approval_file_yet_means_no_ceremony(self) -> None:
        self.assertIsNone(self.definition._pending_confirm_ceremony("0001"))

    def test_the_ceremony_url_is_read_from_the_approval_challenge(self) -> None:
        url = "http://localhost:18734/ceremony/" + "A" * 43
        (self.entry / "approval_challenge.json").write_text(
            json.dumps({"approval_id": "a" * 64, "ceremony_url": url})
        )
        self.assertEqual(self.definition._pending_confirm_ceremony("0001"), url)

    def test_a_malformed_ceremony_url_is_refused(self) -> None:
        (self.entry / "approval_challenge.json").write_text(
            json.dumps({"approval_id": "a" * 64, "ceremony_url": "http://evil/x"})
        )
        with self.assertRaisesRegex(EvalError, "invalid ceremony URL"):
            self.definition._pending_confirm_ceremony("0001")

    def test_a_torn_write_reads_as_not_yet_published(self) -> None:
        # The file is written atomically, so unparseable bytes mean a rename
        # caught in flight, not corruption.
        (self.entry / "approval_challenge.json").write_text('{"ceremony_ur')
        self.assertIsNone(self.definition._pending_confirm_ceremony("0001"))

    def test_host_state_listing_finds_the_staged_entry(self) -> None:
        self.assertEqual(self.definition._list_host_state("pending"), ["0001"])
        self.assertEqual(self.definition._list_host_state("sent"), [])


class ProvisionTests(SolanaEvalTestCase):
    def test_the_outbox_is_over_mounted_read_write_over_a_read_only_tree(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.lamports = TRANSFER
        definition.source_address = SOURCE
        definition.account_dir = "0"
        context = self.provision(definition)

        self.assertEqual(len(context.mounts), 2)
        tree, outbox = context.mounts
        self.assertEqual(tree["target"], "/bloom")
        self.assertTrue(tree["read_only"])
        # The pending entry id does not exist until the agent stages, so the
        # confirm path cannot be enumerated ahead of time; the subtree is.
        self.assertEqual(
            outbox["target"],
            f"/bloom/wallets/{WALLET_ID}/0/chains/{CHAIN}/outbox",
        )
        self.assertNotIn("read_only", outbox)

    def test_the_agent_is_not_handed_the_identity_it_must_discover(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.account_dir = "0"
        definition.key_fingerprint = FINGERPRINT
        context = self.provision(definition)

        self.assertEqual(context.agent_env, {})
        instruction = (context.task_dir / "instruction.md").read_text()
        self.assertIn("Using Bloom, send exactly", instruction)
        self.assertIn(WALLET_ID, instruction)
        self.assertIn(DESTINATION, instruction)
        # Only the mount root, as a user's own setup would say; the wallet's
        # account path and identity stay for the agent to discover.
        self.assertIn("Bloom is mounted at `/bloom`.", instruction)
        # The owner approves out of band; a one-shot agent cannot hand back.
        self.assertIn("retry once it's approved", instruction)
        self.assertNotIn("/bloom/", instruction)
        self.assertNotIn("BLOOM_EVAL_", instruction)
        self.assertNotIn("result.json", instruction)
        # The verifier needs all of it to grade independently.
        self.assertEqual(context.verifier_env["BLOOM_EVAL_SOLANA_SOURCE"], SOURCE)
        self.assertIn("BLOOM_EVAL_SOLANA_RPC_URL", context.verifier_env)

    def test_the_container_shares_host_loopback_with_the_verifier(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.account_dir = "0"
        context = self.provision(definition)

        self.assertEqual(len(context.extra_docker_compose), 1)
        self.assertEqual(
            context.extra_docker_compose[0].name, "docker-compose.local.yaml"
        )

    def test_the_trial_task_copy_lives_under_the_ignored_jobs_dir(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.account_dir = "0"
        context = self.provision(definition)

        self.assertEqual(context.task_dir.parent, definition.jobs_dir)


class LocalHistoryTests(SolanaEvalTestCase):
    """solana-test-validator prunes to about a minute of slots by default,
    after which the verifier cannot count the payment."""

    def window(self, slot: int, first: int) -> SolanaTransferEval:
        definition = self.make()
        answers = {"getSlot": slot, "getFirstAvailableBlock": first}
        with mock.patch.object(
            definition, "_rpc", side_effect=lambda method, _params: answers[method]
        ):
            definition._require_local_history_window()
        return definition

    def test_a_validator_not_yet_pruning_is_accepted_and_its_slot_recorded(self) -> None:
        definition = self.window(slot=300, first=0)
        self.assertEqual(definition.history_start_slot, 300)

    def test_a_pruning_validator_that_retains_a_trial_is_accepted(self) -> None:
        self.window(slot=20_000, first=20_000 - LOCAL_HISTORY_MIN_SLOTS)

    def test_a_pruning_validator_with_a_short_window_is_refused(self) -> None:
        # The default ledger limit: about 130 slots.
        with self.assertRaisesRegex(EvalError, "--limit-ledger-size 1000000"):
            self.window(slot=9368, first=9240)

    def test_the_verifier_is_told_where_history_must_start(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.account_dir = "0"
        definition.history_start_slot = 300
        context = self.provision(definition)
        self.assertEqual(
            context.verifier_env["BLOOM_EVAL_SOLANA_HISTORY_FROM_SLOT"], "300"
        )


class FreshDestinationTests(unittest.TestCase):
    def test_each_trial_gets_a_distinct_32_byte_address(self) -> None:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        seen = set()
        for _ in range(50):
            address = SolanaTransferEval._fresh_destination()
            number = 0
            for char in address:
                number = number * 58 + alphabet.index(char)
            leading = len(address) - len(address.lstrip("1"))
            decoded = b"\0" * leading + number.to_bytes((number.bit_length() + 7) // 8, "big")
            self.assertEqual(len(decoded), 32, address)
            seen.add(address)
        self.assertEqual(len(seen), 50)


class AllowOnlyDestinationTests(SolanaEvalTestCase):
    """Each trial allows exactly its own destination, through an owner
    ceremony on the harness's counter sequence."""

    URL = "http://localhost:18734/ceremony/" + "P" * 43
    OPERATION = "ab" * 32

    def projection(self, allowed: list[dict[str, str]]) -> str:
        # Broker encodes the canonical policy as URL-safe base64 without
        # padding; a standard decoder rejects it.
        policy = {"wallet_id": WALLET_ID, "allowed_destinations": allowed, "note": "?>"}
        encoded = base64.urlsafe_b64encode(json.dumps(policy).encode()).decode().rstrip("=")
        return json.dumps({"policy": {"canonical_policy": encoded}})

    def run_allow(self, committed: list[dict[str, str]], staged: str | None = None):
        definition = self.make()
        definition.destination = DESTINATION
        proposals: list[object] = []
        replies = {
            "projection": [
                self.projection([{"chain": "solana", "destination": SOURCE}]),
                self.projection(committed),
            ],
        }

        def bloom(*args: str) -> str:
            if args[:2] == ("wallet", "projection"):
                return replies["projection"].pop(0)
            if args[:2] == ("wallet", "update-policy"):
                proposals.append(json.loads(Path(args[-1]).read_text()))
                return staged if staged is not None else (
                    f"operation_id: {self.OPERATION}\nceremony_kind: PolicyUpdate\n"
                    f"ceremony_url: {self.URL}\n"
                )
            if args[:2] == ("wallet", "commit-policy"):
                self.assertEqual(args[2], self.OPERATION)
                return ""
            raise AssertionError(args)

        ceremonies = SimpleNamespace(complete=mock.Mock())
        with mock.patch.object(definition, "_bloom", side_effect=bloom):
            definition._allow_only_destination(ceremonies)
        return proposals, ceremonies

    def test_only_this_trials_destination_is_allowed(self) -> None:
        allowed = [{"chain": "solana", "destination": DESTINATION}]
        proposals, ceremonies = self.run_allow(allowed)
        # The previous trial's destination is dropped, not accumulated.
        self.assertEqual(proposals[0]["allowed_destinations"], allowed)
        ceremonies.complete.assert_called_once_with(self.URL)

    def test_a_policy_that_did_not_take_is_refused(self) -> None:
        with self.assertRaisesRegex(EvalError, "does not allow this trial"):
            self.run_allow([{"chain": "solana", "destination": SOURCE}])

    def test_no_ceremony_is_completed_without_a_staged_one(self) -> None:
        with self.assertRaisesRegex(EvalError, "did not stage a ceremony"):
            self.run_allow([], staged="operation_id: nope\n")


class TrialNoteTests(SolanaEvalTestCase):
    def test_the_note_counts_only_this_trials_entries(self) -> None:
        home = self.root / "home"
        definition = self.make(BLOOM_EVAL_SOLANA_HOME_ROOT=str(home))
        outbox = home / ".solana-outbox" / WALLET_ID / CHAIN

        def entry(state: str, entry_id: str, status: str) -> None:
            path = outbox / state / entry_id
            path.mkdir(parents=True)
            (path / "intent.json").write_text(json.dumps({"status": status}))

        entry("failed", "old", "expired")
        definition._baseline_entries = {"old"}
        entry("failed", "a", "expired")
        entry("failed", "b", "cancelled")
        entry("sent", "c", "sent")
        definition._approver_completed = 2
        definition._approver_refusal = "staged entry d does not match"
        self.assertEqual(
            definition.trial_note(),
            "3 staged, 2 approved, 1 sent, 1 expired unsent, 1 cancelled, "
            "refused: staged entry d does not match",
        )

    def test_a_refusal_is_the_agents_outcome_not_a_cleanup_failure(self) -> None:
        definition = self.make()
        definition._approver_refusal = "staged entry x does not match"
        with mock.patch.object(definition, "_stop_approver"):
            with mock.patch.object(definition, "_list_state", return_value=[]):
                definition.cleanup()


class ApproverBudgetTests(unittest.TestCase):
    def test_the_approver_outlasts_environment_build_and_agent(self) -> None:
        import tomllib

        from harness.solana_transfer import APPROVER_BUDGET_SECONDS

        task = Path(__file__).resolve().parent.parent / "tasks/solana-transfer/task.toml"
        config = tomllib.loads(task.read_text())
        needed = (
            config["environment"]["build_timeout_sec"] + config["agent"]["timeout_sec"]
        )
        self.assertGreaterEqual(APPROVER_BUDGET_SECONDS, needed)


class TurnBudgetTests(unittest.TestCase):
    def test_solana_declares_more_turns_than_the_shared_default(self) -> None:
        self.assertEqual(EvalDefinition.default_max_turns, "20")
        self.assertEqual(SolanaTransferEval.default_max_turns, "24")

    def test_the_eval_default_reaches_the_agent_and_the_operator_wins(self) -> None:
        auth = {"DEEPSEEK_API_KEY": "test-deepseek-key"}
        with mock.patch.dict(os.environ, auth, clear=True):
            spec = _agent_spec("deepseek", SolanaTransferEval.default_max_turns)
            self.assertNotIn("BLOOM_EVAL_MAX_TURNS", os.environ)
        self.assertEqual(spec.kwargs["max_turns"], 24)
        with mock.patch.dict(
            os.environ, {**auth, "BLOOM_EVAL_MAX_TURNS": "7"}, clear=True
        ):
            spec = _agent_spec("deepseek", SolanaTransferEval.default_max_turns)
        self.assertEqual(spec.kwargs["max_turns"], 7)


class ReusedWalletCleanupTests(SolanaEvalTestCase):
    def test_cleanup_accepts_an_entry_that_expires_during_cancel(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.account_dir = "0"
        pending_reads = 0

        def listing(state: str) -> list[str]:
            nonlocal pending_reads
            if state == "pending":
                pending_reads += 1
                return ["expiring"] if pending_reads == 1 else []
            return []

        with mock.patch.object(definition, "_stop_approver"):
            with mock.patch.object(definition, "_list_state", side_effect=listing):
                with mock.patch.object(
                    definition.mount,
                    "write_route",
                    return_value=SimpleNamespace(returncode=1),
                ):
                    definition.cleanup()

    def test_cleanup_ignores_reconciled_history_and_checks_only_this_trial(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.account_dir = "0"
        definition._baseline_sent = {"historical"}

        def listing(state: str) -> list[str]:
            if state == "pending":
                return []
            if state == "sent":
                return ["historical", "current"]
            return []

        with mock.patch.object(definition, "_stop_approver"):
            with mock.patch.object(definition, "_list_state", side_effect=listing):
                with mock.patch.object(
                    definition.mount,
                    "read_json_if_listed",
                    return_value={"outcome": "success"},
                ) as receipt:
                    definition.cleanup()

        self.assertEqual(receipt.call_count, 1)
        self.assertIn("current", str(receipt.call_args))

    def test_cleanup_fails_if_historical_sent_state_disappears(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.account_dir = "0"
        definition._baseline_sent = {"historical"}
        with mock.patch.object(definition, "_list_state", return_value=[]):
            with self.assertRaisesRegex(EvalError, "historical sent entries"):
                definition.cleanup()


class ContainerBoundaryTests(SolanaEvalTestCase):
    """Whatever else changes, these must never end up inside the container."""

    def context(self):
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.account_dir = "0"
        definition.lamports = TRANSFER
        return definition, self.provision(definition)

    def test_no_host_secret_reaches_the_agent(self) -> None:
        definition, context = self.context()
        secrets_on_host = [
            str(definition.seed_file),  # authenticator seed
            str(definition.driver),  # debug driver
            str(definition.home_root),  # private outbox state
        ]
        rendered = json.dumps(
            {
                "env": dict(context.agent_env),
                "mounts": [dict(m) for m in context.mounts],
            }
        )
        for secret in secrets_on_host:
            if secret and secret != ".":
                self.assertNotIn(secret, rendered)

    def test_the_agent_gets_no_rpc_endpoint(self) -> None:
        # Reaching the chain directly would let the agent observe or act
        # outside the mount, which is the surface under test.
        _definition, context = self.context()
        self.assertNotIn("BLOOM_EVAL_SOLANA_RPC_URL", context.agent_env)

    def test_only_the_outbox_is_writable(self) -> None:
        _definition, context = self.context()
        writable = [m for m in context.mounts if not m.get("read_only")]
        self.assertEqual(len(writable), 1)
        self.assertTrue(writable[0]["target"].endswith("/outbox"))


if __name__ == "__main__":
    unittest.main()

