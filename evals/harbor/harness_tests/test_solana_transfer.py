"""Tests for the Solana transfer eval definition.

The mainnet parameter preflight, the chain identity check, and the background
approver's match and replacement-lineage checks are the places where a mistake
would let real funds move in a way nobody configured, so they carry most of
the coverage here.
"""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from harness.core import EvalError
from harness.solana_transfer import (
    HARNESS_MAX_BALANCE_LAMPORTS,
    HARNESS_MAX_TRANSFER_LAMPORTS,
    MAINNET_ACK,
    MAINNET_GENESIS_HASH,
    SolanaTransferEval,
    trial_amount,
)

SOURCE = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
DESTINATION = "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu"
WALLET_ID = "eval-solana"
CHAIN = "solana-mainnet"
FINGERPRINT = "a" * 64
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

        self.sweep = self.root / "sweep.json"
        self.sweep.write_text("[1,2,3]")
        self.sweep.chmod(0o600)

        outbox = (
            Path(self.env()["BLOOM_EVAL_BLOOM_MOUNT"])
            / "wallets" / WALLET_ID / "chains" / CHAIN / "outbox"
        )
        outbox.mkdir(parents=True)
        (outbox / "new.tx").write_text("")

    def env(self, **overrides: str) -> dict[str, str]:
        value = {
            "BLOOM_EVAL_SOLANA_LANE": "local",
            "BLOOM_EVAL_SOLANA_WALLET_ID": WALLET_ID,
            "BLOOM_EVAL_SOLANA_CHAIN": CHAIN,
            "BLOOM_EVAL_SOLANA_NETWORK": "localnet",
            "BLOOM_EVAL_SOLANA_RPC_URL": "http://127.0.0.1:8899",
            "BLOOM_EVAL_SOLANA_DESTINATION": DESTINATION,
            "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT": "2",
            "BLOOM_EVAL_BLOOM_MOUNT": str(self.root / "bloom"),
        }
        value.update(overrides)
        return value

    def make(self, **overrides: str) -> SolanaTransferEval:
        return SolanaTransferEval(self.repo, self.env(**overrides))

    def mainnet_env(self, **overrides: str) -> dict[str, str]:
        value = self.env()
        value.update(
            BLOOM_EVAL_SOLANA_LANE="mainnet",
            BLOOM_EVAL_SOLANA_NETWORK="mainnet-beta",
            BLOOM_EVAL_SOLANA_RPC_URL="https://api.mainnet-beta.solana.com",
            BLOOM_EVAL_SOLANA_MAINNET_ACK=MAINNET_ACK,
            BLOOM_EVAL_SOLANA_SOURCE=SOURCE,
            BLOOM_EVAL_SOLANA_KEY_FINGERPRINT=FINGERPRINT,
            BLOOM_EVAL_SOLANA_DERIVATION_PATH=DERIVATION,
            BLOOM_EVAL_SOLANA_LAMPORTS=str(TRANSFER),
            BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS=str(FEE_CAP),
            BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE=str(self.sweep),
            BLOOM_EVAL_SOLANA_HOME_ROOT=str(self.root),
        )
        value.update(overrides)
        return value

    def make_mainnet(self, **overrides: str) -> SolanaTransferEval:
        return SolanaTransferEval(self.repo, self.mainnet_env(**overrides))

    def accept_mainnet_identity(self, definition: SolanaTransferEval) -> None:
        """Mock the sweep-keypair inspection and the RPC genesis answer."""
        return mock.patch.multiple(
            definition,
            _rpc=mock.DEFAULT,
            _require_sweep_keypair=mock.DEFAULT,
            _require_sweep_tool=mock.DEFAULT,
            **{"_rpc.return_value": MAINNET_GENESIS_HASH},
        )


class MainnetParameterTests(SolanaEvalTestCase):
    """The mainnet lane has no authorization file: the operator configures
    the whole transfer contract, and every field is required."""

    def preflight_ok(self, definition: SolanaTransferEval) -> None:
        with mock.patch.object(definition, "_rpc", return_value=MAINNET_GENESIS_HASH):
            with mock.patch.object(definition, "_require_sweep_keypair"):
                with mock.patch.object(definition, "_require_sweep_tool"):
                    with mock.patch.object(definition, "_require_sign_count", return_value=2):
                        with mock.patch("harness.core.CeremonyDriver.preflight"):
                            with mock.patch("os.path.ismount", return_value=True):
                                definition.preflight()

    def test_a_fully_configured_mainnet_lane_is_accepted(self) -> None:
        definition = self.make_mainnet()
        self.preflight_ok(definition)
        self.assertEqual(definition.lamports, TRANSFER)
        self.assertEqual(definition.source_address, SOURCE)
        self.assertEqual(definition.key_fingerprint, FINGERPRINT)

    def test_the_mainnet_acknowledgement_is_required(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_MAINNET_ACK="yes")
        with self.assertRaisesRegex(EvalError, "MAINNET_ACK"):
            self.preflight_ok(definition)

    def test_the_mainnet_lane_requires_the_mainnet_network_label(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_NETWORK="localnet")
        with self.assertRaisesRegex(EvalError, "requires network mainnet-beta"):
            self.preflight_ok(definition)

    def test_a_malformed_source_is_rejected(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_SOURCE="not-base58-0OIl")
        with self.assertRaisesRegex(EvalError, "SOURCE must be a base58"):
            self.preflight_ok(definition)

    def test_a_missing_source_is_rejected(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_SOURCE="")
        with self.assertRaisesRegex(EvalError, "SOURCE must be a base58"):
            self.preflight_ok(definition)

    def test_a_malformed_fingerprint_is_rejected(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_KEY_FINGERPRINT="ZZZ")
        with self.assertRaisesRegex(EvalError, "FINGERPRINT"):
            self.preflight_ok(definition)

    def test_a_malformed_derivation_path_is_rejected(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_DERIVATION_PATH="m/0")
        with self.assertRaisesRegex(EvalError, "DERIVATION_PATH"):
            self.preflight_ok(definition)

    def test_a_missing_amount_is_rejected(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_LAMPORTS="")
        with self.assertRaisesRegex(EvalError, "LAMPORTS must be a positive integer"):
            self.preflight_ok(definition)

    def test_a_non_integer_amount_is_rejected(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_LAMPORTS="1.5")
        with self.assertRaisesRegex(EvalError, "LAMPORTS must be a positive integer"):
            self.preflight_ok(definition)

    def test_an_amount_above_the_harness_ceiling_is_rejected(self) -> None:
        definition = self.make_mainnet(
            BLOOM_EVAL_SOLANA_LAMPORTS=str(HARNESS_MAX_TRANSFER_LAMPORTS + 1)
        )
        with self.assertRaisesRegex(EvalError, "exceeds the harness ceiling"):
            self.preflight_ok(definition)

    def test_a_fee_ceiling_above_the_harness_ceiling_is_rejected(self) -> None:
        definition = self.make_mainnet(
            BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS=str(HARNESS_MAX_TRANSFER_LAMPORTS + 1)
        )
        with self.assertRaisesRegex(EvalError, "exceeds the harness ceiling"):
            self.preflight_ok(definition)

    def test_the_ceilings_themselves_are_accepted(self) -> None:
        definition = self.make_mainnet(
            BLOOM_EVAL_SOLANA_LAMPORTS=str(HARNESS_MAX_TRANSFER_LAMPORTS),
            BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS=str(HARNESS_MAX_TRANSFER_LAMPORTS),
        )
        self.preflight_ok(definition)
        self.assertEqual(definition.lamports, HARNESS_MAX_TRANSFER_LAMPORTS)

    def test_a_missing_destination_is_rejected(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_DESTINATION="")
        with self.assertRaisesRegex(EvalError, "DESTINATION must be a base58"):
            self.preflight_ok(definition)

    def test_the_sweep_keypair_is_required(self) -> None:
        definition = self.make_mainnet(BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE="")
        with self.assertRaisesRegex(EvalError, "SWEEP_KEYPAIR_FILE is required"):
            definition._require_sweep_keypair()

    def test_the_sweep_keypair_must_control_the_destination(self) -> None:
        definition = self.make_mainnet()
        with mock.patch(
            "harness.solana_transfer.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=SOURCE + "\n", stderr=""),
        ):
            with self.assertRaisesRegex(EvalError, "not controlled"):
                definition._require_sweep_keypair()


class ChainIdentityTests(SolanaEvalTestCase):
    """A label saying local is insufficient; the chain answers for itself."""

    def test_the_mainnet_lane_requires_the_pinned_genesis(self) -> None:
        definition = self.make_mainnet()
        with mock.patch.object(definition, "_rpc", return_value="TstGenesis" * 4):
            with self.assertRaisesRegex(EvalError, "requires a mainnet-beta endpoint"):
                definition._require_chain_identity()

    def test_the_mainnet_lane_accepts_mainnet_genesis(self) -> None:
        definition = self.make_mainnet()
        with mock.patch.object(definition, "_rpc", return_value=MAINNET_GENESIS_HASH):
            definition._require_chain_identity()

    def test_the_local_lane_refuses_a_mainnet_endpoint(self) -> None:
        definition = self.make()
        with mock.patch.object(definition, "_rpc", return_value=MAINNET_GENESIS_HASH):
            with self.assertRaisesRegex(EvalError, "refuses mainnet-beta endpoints"):
                definition._require_chain_identity()

    def test_the_local_lane_accepts_a_non_mainnet_genesis(self) -> None:
        definition = self.make()
        with mock.patch.object(definition, "_rpc", return_value="Eth2Val" * 6):
            definition._require_chain_identity()

    def test_an_unreadable_genesis_is_rejected(self) -> None:
        definition = self.make()
        with mock.patch.object(definition, "_rpc", return_value=None):
            with self.assertRaisesRegex(EvalError, "genesis hash"):
                definition._require_chain_identity()


class LanePreflightTests(SolanaEvalTestCase):
    def test_the_full_eval_requires_an_explicit_mount_selection(self) -> None:
        definition = self.make(BLOOM_EVAL_BLOOM_MOUNT="")
        with self.assertRaisesRegex(EvalError, "BLOOM_EVAL_BLOOM_MOUNT is required"):
            definition.preflight()

    def test_an_unknown_lane_is_rejected(self) -> None:
        with self.assertRaisesRegex(EvalError, "unknown lane"):
            self.make(BLOOM_EVAL_SOLANA_LANE="mainnet-canary").preflight()

    def test_the_local_lane_refuses_to_be_pointed_at_mainnet(self) -> None:
        # The single most dangerous misconfiguration this eval could have.
        with self.assertRaisesRegex(EvalError, "must not be pointed at mainnet-beta"):
            self.make(BLOOM_EVAL_SOLANA_NETWORK="mainnet-beta").preflight()

    def test_a_local_base_amount_above_the_ceiling_is_rejected(self) -> None:
        definition = self.make(
            BLOOM_EVAL_SOLANA_BASE_LAMPORTS=str(HARNESS_MAX_TRANSFER_LAMPORTS + 1)
        )
        with self.assertRaisesRegex(EvalError, "exceeds the harness"):
            definition.preflight()

    def test_a_local_fee_ceiling_must_be_positive(self) -> None:
        definition = self.make(BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS="0")
        with self.assertRaisesRegex(EvalError, "positive integer"):
            definition.preflight()

    def test_preauthorization_only_is_the_read_only_preflight(self) -> None:
        # No authorization file exists anymore; the mode runs the same
        # read-only preflight, on either lane.
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
                }
            ],
        }
        with mock.patch.object(definition.mount, "read_json", return_value=projection):
            with mock.patch(
                "harness.solana_transfer.subprocess.run",
                return_value=SimpleNamespace(stdout=SOURCE + "\n"),
            ):
                definition._load_local_account_identity()

        self.assertEqual(definition.source_address, SOURCE)
        self.assertEqual(definition.key_fingerprint, FINGERPRINT)
        self.assertEqual(definition.derivation_path, DERIVATION)

    def test_local_identity_refuses_multiple_active_solana_accounts(self) -> None:
        definition = self.make()
        account = {
            "derivation_profile": "bip44-solana-slip10-ed25519-v1",
            "lifecycle": "ACTIVE",
            "public_key_fingerprint": FINGERPRINT,
            "path": DERIVATION,
        }
        projection = {"wallet_id": WALLET_ID, "accounts": [account, account]}
        with mock.patch.object(definition.mount, "read_json", return_value=projection):
            with self.assertRaisesRegex(EvalError, "exactly one active"):
                definition._load_local_account_identity()

    def test_a_configured_source_must_match_the_projected_account(self) -> None:
        mount = Path(self.env()["BLOOM_EVAL_BLOOM_MOUNT"])
        outbox = mount / "wallets" / WALLET_ID / "chains" / CHAIN / "outbox"
        outbox.mkdir(parents=True, exist_ok=True)
        (outbox / "new.tx").write_text("")
        definition = self.make(
            BLOOM_EVAL_SOLANA_HOME_ROOT=str(self.root),
            BLOOM_EVAL_SOLANA_SOURCE=DESTINATION,  # not the projected address
        )

        def projected_identity() -> None:
            definition.source_address = SOURCE

        with mock.patch("os.path.ismount", return_value=True):
            with mock.patch.object(definition, "_require_chain_identity"):
                with mock.patch.object(definition, "_require_sign_count", return_value=2):
                    with mock.patch("harness.core.CeremonyDriver.preflight"):
                        with mock.patch.object(
                            definition,
                            "_load_local_account_identity",
                            side_effect=projected_identity,
                        ):
                            with self.assertRaisesRegex(EvalError, "does not match"):
                                definition.preflight()


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
        self.assertFalse(self.definition._replacement_is_authorized("0002"))

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
        ceremonies = SimpleNamespace(
            completed=set(), next_sign_count=3, complete=mock.Mock()
        )

        self.definition._approve_loop(ceremonies)

        ceremonies.complete.assert_called_once_with(first_url)
        self.assertIn(
            "0002 does not continue the approved replacement lineage",
            self.definition._approver_error or "",
        )


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
        with mock.patch.object(definition, "_start_approver"):
            context = definition.provision("codex")

        self.assertEqual(len(context.mounts), 2)
        tree, outbox = context.mounts
        self.assertEqual(tree["target"], "/bloom")
        self.assertTrue(tree["read_only"])
        # The pending entry id does not exist until the agent stages, so the
        # confirm path cannot be enumerated ahead of time; the subtree is.
        self.assertEqual(
            outbox["target"], f"/bloom/wallets/{WALLET_ID}/chains/{CHAIN}/outbox"
        )
        self.assertNotIn("read_only", outbox)

    def test_the_agent_is_not_handed_the_identity_it_must_discover(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.key_fingerprint = FINGERPRINT
        with mock.patch.object(definition, "_start_approver"):
            context = definition.provision("codex")

        self.assertEqual(context.agent_env, {})
        instruction = (context.task_dir / "instruction.md").read_text()
        self.assertIn("Using Bloom, send exactly", instruction)
        self.assertIn(WALLET_ID, instruction)
        self.assertIn(DESTINATION, instruction)
        self.assertNotIn("/bloom", instruction)
        self.assertNotIn("BLOOM_EVAL_", instruction)
        self.assertNotIn("result.json", instruction)
        # The verifier needs all of it to grade independently.
        self.assertEqual(context.verifier_env["BLOOM_EVAL_SOLANA_SOURCE"], SOURCE)
        self.assertIn("BLOOM_EVAL_SOLANA_RPC_URL", context.verifier_env)

    def test_local_lane_shares_host_loopback_with_the_verifier(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        with mock.patch.object(definition, "_start_approver"):
            context = definition.provision("codex")

        self.assertEqual(len(context.extra_docker_compose), 1)
        self.assertEqual(
            context.extra_docker_compose[0].name, "docker-compose.local.yaml"
        )

    def test_mainnet_lane_does_not_receive_host_networking(self) -> None:
        definition = self.make_mainnet()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        with mock.patch.object(definition, "_start_approver"):
            context = definition.provision("codex")

        self.assertEqual(context.extra_docker_compose, [])


class TrialAmountTests(unittest.TestCase):
    def test_the_tail_is_deterministic_and_bounded(self) -> None:
        first = trial_amount(1_000_000, "trial-a")
        self.assertEqual(first, trial_amount(1_000_000, "trial-a"))
        self.assertGreaterEqual(first, 1_000_000)
        self.assertLess(first, 1_010_000)

    def test_different_trials_get_different_tails(self) -> None:
        amounts = {trial_amount(1_000_000, f"trial-{i}") for i in range(50)}
        self.assertGreater(len(amounts), 40)


class SweepTests(SolanaEvalTestCase):
    """Cleanup's sweep is what makes the mainnet eval repeatable: the transfer
    cannot be undone, but the destination is host-controlled, so the lamports
    come back and only the fees are actually spent."""

    def setUp(self) -> None:
        super().setUp()
        self.definition = self.make_mainnet()
        self.definition.destination = DESTINATION
        self.definition.source_address = SOURCE

    def test_an_empty_destination_needs_no_sweep(self) -> None:
        with mock.patch.object(self.definition, "_balance", return_value=0) as balance:
            self.assertIsNone(self.definition.sweep_destination())
        balance.assert_called_once()

    def test_a_funded_destination_is_drained_and_confirmed(self) -> None:
        balances = [TRANSFER, 0]
        with mock.patch.object(
            self.definition, "_balance", side_effect=lambda _a: balances.pop(0)
        ):
            with mock.patch(
                "harness.solana_transfer.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=0, stdout='{"signature":"sig-1"}', stderr=""
                ),
            ) as run:
                self.assertEqual(self.definition.sweep_destination(), "sig-1")
        command = run.call_args.args[0]
        self.assertIn("transfer", command)
        self.assertIn(SOURCE, command)
        self.assertIn("ALL", command)
        self.assertIn(str(self.sweep), command)

    def test_a_failed_sweep_is_an_error(self) -> None:
        with mock.patch.object(self.definition, "_balance", return_value=TRANSFER):
            with mock.patch(
                "harness.solana_transfer.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=1, stdout="", stderr="insufficient funds"
                ),
            ):
                with self.assertRaisesRegex(EvalError, "insufficient funds"):
                    self.definition.sweep_destination()

    def test_a_sweep_that_does_not_drain_is_an_error(self) -> None:
        # The CLI's exit code is not evidence; the chain is.
        with mock.patch.object(self.definition, "_balance", return_value=TRANSFER):
            with mock.patch(
                "harness.solana_transfer.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stdout="{}", stderr=""),
            ):
                with mock.patch.object(self.definition.mount, "poll_until", return_value=False):
                    with self.assertRaisesRegex(EvalError, "did not drain"):
                        self.definition.sweep_destination()

    def test_a_missing_solana_cli_is_caught_in_preflight(self) -> None:
        # Discovering this after a mainnet broadcast would be too late.
        with mock.patch(
            "harness.solana_transfer.subprocess.run",
            side_effect=FileNotFoundError("no solana"),
        ):
            with self.assertRaisesRegex(EvalError, "required for host cleanup"):
                self.definition._require_sweep_tool()


class ReusedWalletCleanupTests(SolanaEvalTestCase):
    def test_local_cleanup_discards_the_ledger_instead_of_sweeping(self) -> None:
        definition = self.make()
        with mock.patch.object(definition, "_stop_approver"):
            with mock.patch.object(definition, "_list_state", return_value=[]):
                with mock.patch.object(definition, "sweep_destination") as sweep:
                    definition.cleanup()
        sweep.assert_not_called()

    def test_cleanup_accepts_an_entry_that_expires_during_cancel(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
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
                    with mock.patch.object(
                        definition, "sweep_destination", return_value=None
                    ):
                        definition.cleanup()

    def test_cleanup_ignores_reconciled_history_and_checks_only_this_trial(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
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
                    with mock.patch.object(definition, "sweep_destination", return_value=None):
                        definition.cleanup()

        self.assertEqual(receipt.call_count, 1)
        self.assertIn("current", str(receipt.call_args))

    def test_cleanup_fails_if_historical_sent_state_disappears(self) -> None:
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition._baseline_sent = {"historical"}
        with mock.patch.object(definition, "_stop_approver"):
            with mock.patch.object(definition, "_list_state", return_value=[]):
                with mock.patch.object(definition, "sweep_destination", return_value=None):
                    with self.assertRaisesRegex(EvalError, "historical sent entries"):
                        definition.cleanup()

    def test_mainnet_cleanup_sweeps_after_mounted_cancel_failure(self) -> None:
        definition = self.make_mainnet()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        with mock.patch.object(definition, "_stop_approver"):
            with mock.patch.object(definition, "_list_state", return_value=["stuck"]):
                with mock.patch.object(
                    definition.mount,
                    "write_route",
                    side_effect=EvalError("mounted cancel timed out"),
                ):
                    with mock.patch.object(
                        definition, "sweep_destination", return_value=None
                    ) as sweep:
                        with self.assertRaisesRegex(EvalError, "mounted cleanup"):
                            definition.cleanup()

        sweep.assert_called_once_with()


class ContainerBoundaryTests(SolanaEvalTestCase):
    """Whatever else changes, these must never end up inside the container."""

    def context(self):
        definition = self.make()
        definition.destination = DESTINATION
        definition.source_address = SOURCE
        definition.lamports = TRANSFER
        with mock.patch.object(definition, "_start_approver"):
            return definition, definition.provision("codex")

    def test_no_host_secret_reaches_the_agent(self) -> None:
        definition, context = self.context()
        secrets_on_host = [
            str(self.sweep),  # sweeping key: the eval's only route back
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
