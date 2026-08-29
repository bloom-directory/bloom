"""Tests for the Solana transfer eval definition.

The authorization preflight and the background approver's match check are the
two places where a mistake would let real funds move in a way nobody
authorized, so they carry most of the coverage here.
"""

from __future__ import annotations

import hashlib
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
    SolanaTransferEval,
    trial_amount,
)

SOURCE = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
DESTINATION = "6dmNQ5jwLeLk5REvio1JcMshcbvkYMwy26sJ8pbkvStu"
WALLET_ID = "eval-solana"
CHAIN = "solana-mainnet"
FINGERPRINT = "a3f1c09b2e7d4856"
DERIVATION = "m/44'/501'/0'/0'"
TRANSFER = 1_000_000
FEE_CAP = 10_000
BALANCE_CAP = 2_000_000


class SolanaEvalTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()

        self.machine = self.root / "bloom-machine"
        self.machine.write_bytes(b"machine-binary")
        self.artifact = hashlib.sha256(b"machine-binary").hexdigest()

        self.sweep = self.root / "sweep.json"
        self.sweep.write_text("[1,2,3]")
        self.sweep.chmod(0o600)

        self.auth_path = self.root / "canary.json"
        self.write_auth()

    def auth(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "bloom.solana-mainnet-canary/1",
            "artifact_sha256": self.artifact,
            "chain": CHAIN,
            "wallet": WALLET_ID,
            "key_fingerprint": FINGERPRINT,
            "derivation_path": DERIVATION,
            "source_address": SOURCE,
            "destination": DESTINATION,
            "max_balance_lamports": BALANCE_CAP,
            "transfer_lamports": TRANSFER,
            "max_fee_lamports": FEE_CAP,
            "max_transactions": 1,
            "expires_ms": int(time.time() * 1000) + 3_600_000,
        }
        value.update(overrides)
        return value

    def write_auth(self, **overrides: object) -> None:
        self.auth_path.write_text(json.dumps(self.auth(**overrides)))
        self.auth_path.chmod(0o600)

    def env(self, **overrides: str) -> dict[str, str]:
        value = {
            "BLOOM_EVAL_SOLANA_LANE": "mainnet-canary",
            "BLOOM_EVAL_SOLANA_WALLET_ID": WALLET_ID,
            "BLOOM_EVAL_SOLANA_CHAIN": CHAIN,
            "BLOOM_EVAL_SOLANA_NETWORK": "mainnet-beta",
            "BLOOM_EVAL_SOLANA_RPC_URL": "https://api.mainnet-beta.solana.com",
            "BLOOM_EVAL_SOLANA_DESTINATION": DESTINATION,
            "BLOOM_EVAL_SOLANA_CANARY_AUTHORIZATION": str(self.auth_path),
            "BLOOM_EVAL_SOLANA_MACHINE_BINARY": str(self.machine),
            "BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE": str(self.sweep),
            "BLOOM_EVAL_SOLANA_MAINNET_ACK": MAINNET_ACK,
            "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT": "2",
            "BLOOM_EVAL_BLOOM_MOUNT": str(self.root / "bloom"),
        }
        value.update(overrides)
        return value

    def make(self, **overrides: str) -> SolanaTransferEval:
        return SolanaTransferEval(self.repo, self.env(**overrides))


class AuthorizationPreflightTests(SolanaEvalTestCase):
    def test_a_well_formed_authorization_is_accepted(self) -> None:
        auth = self.make().authorization_preflight()
        self.assertEqual(auth["transfer_lamports"], TRANSFER)

    def test_a_world_readable_authorization_is_rejected(self) -> None:
        self.auth_path.chmod(0o644)
        with self.assertRaisesRegex(EvalError, "must have mode 0600"):
            self.make().authorization_preflight()

    def test_an_unknown_schema_is_rejected(self) -> None:
        self.write_auth(schema="bloom.solana-mainnet-canary/2")
        with self.assertRaisesRegex(EvalError, "schema is not"):
            self.make().authorization_preflight()

    def test_more_than_one_permitted_transaction_is_rejected(self) -> None:
        # Bloom enforces this too. The harness refuses independently so a
        # widened file never reaches it.
        self.write_auth(max_transactions=2)
        with self.assertRaisesRegex(EvalError, "exactly one transaction"):
            self.make().authorization_preflight()

    def test_an_already_spent_authorization_is_rejected(self) -> None:
        self.auth_path.with_name(self.auth_path.name + ".spent").write_text("")
        with self.assertRaisesRegex(EvalError, "already spent"):
            self.make().authorization_preflight()

    def test_an_expired_authorization_is_rejected(self) -> None:
        self.write_auth(expires_ms=int(time.time() * 1000) - 1)
        with self.assertRaisesRegex(EvalError, "expires too soon"):
            self.make().authorization_preflight()

    def test_an_authorization_expiring_mid_trial_is_rejected(self) -> None:
        self.write_auth(expires_ms=int(time.time() * 1000) + 60_000)
        with self.assertRaisesRegex(EvalError, "expires too soon"):
            self.make().authorization_preflight()

    def test_a_mismatched_artifact_digest_is_rejected(self) -> None:
        self.write_auth(artifact_sha256="0" * 64)
        with self.assertRaisesRegex(EvalError, "bound to a different artifact"):
            self.make().authorization_preflight()

    def test_a_modified_machine_binary_is_rejected(self) -> None:
        # The same file, rebuilt: the authorization no longer describes it.
        self.machine.write_bytes(b"machine-binary-rebuilt")
        with self.assertRaisesRegex(EvalError, "bound to a different artifact"):
            self.make().authorization_preflight()

    def test_a_transfer_above_the_harness_ceiling_is_rejected(self) -> None:
        self.write_auth(
            transfer_lamports=HARNESS_MAX_TRANSFER_LAMPORTS + 1,
            max_balance_lamports=HARNESS_MAX_BALANCE_LAMPORTS,
        )
        with self.assertRaisesRegex(EvalError, "exceeds the harness ceiling"):
            self.make().authorization_preflight()

    def test_a_balance_cap_above_the_harness_ceiling_is_rejected(self) -> None:
        self.write_auth(max_balance_lamports=HARNESS_MAX_BALANCE_LAMPORTS + 1)
        with self.assertRaisesRegex(EvalError, "exceeds the harness ceiling"):
            self.make().authorization_preflight()

    def test_a_transfer_exceeding_its_own_balance_cap_is_rejected(self) -> None:
        self.write_auth(transfer_lamports=BALANCE_CAP, max_fee_lamports=FEE_CAP)
        with self.assertRaisesRegex(EvalError, "exceeds the authorized balance cap"):
            self.make().authorization_preflight()

    def test_an_authorization_for_another_chain_is_rejected(self) -> None:
        self.write_auth(chain="solana-devnet")
        with self.assertRaisesRegex(EvalError, "is for chain"):
            self.make().authorization_preflight()

    def test_an_authorization_for_another_wallet_is_rejected(self) -> None:
        self.write_auth(wallet="other-wallet")
        with self.assertRaisesRegex(EvalError, "is for wallet"):
            self.make().authorization_preflight()

    def test_a_malformed_destination_is_rejected(self) -> None:
        self.write_auth(destination="not-base58-0OIl")
        with self.assertRaisesRegex(EvalError, "malformed destination"):
            self.make().authorization_preflight()

    def test_a_destination_the_host_cannot_sweep_is_rejected(self) -> None:
        # A destination the host holds no key for turns a recoverable trial
        # into an unrecoverable one.
        with self.assertRaisesRegex(EvalError, "not the host-controlled"):
            self.make(
                BLOOM_EVAL_SOLANA_DESTINATION=SOURCE
            ).authorization_preflight()

    def test_a_world_readable_sweep_keypair_is_rejected(self) -> None:
        self.sweep.chmod(0o644)
        with self.assertRaisesRegex(EvalError, "sweep keypair must have mode 0600"):
            self.make().authorization_preflight()

    def test_a_missing_authorization_is_rejected(self) -> None:
        with self.assertRaisesRegex(EvalError, "is required"):
            self.make(
                BLOOM_EVAL_SOLANA_CANARY_AUTHORIZATION=""
            ).authorization_preflight()


class LanePreflightTests(SolanaEvalTestCase):
    def test_an_unknown_lane_is_rejected(self) -> None:
        with self.assertRaisesRegex(EvalError, "unknown lane"):
            self.make(BLOOM_EVAL_SOLANA_LANE="devnet").preflight()

    def test_the_mainnet_lane_requires_the_acknowledgement(self) -> None:
        with self.assertRaisesRegex(EvalError, "MAINNET_ACK"):
            self.make(BLOOM_EVAL_SOLANA_MAINNET_ACK="no").preflight()

    def test_the_local_lane_refuses_to_be_pointed_at_mainnet(self) -> None:
        # The single most dangerous misconfiguration this eval could have.
        with self.assertRaisesRegex(EvalError, "must not be pointed at mainnet-beta"):
            self.make(
                BLOOM_EVAL_SOLANA_LANE="local",
                BLOOM_EVAL_SOLANA_NETWORK="mainnet-beta",
            ).preflight()

    def test_preauthorization_only_is_a_mainnet_lane_mode(self) -> None:
        with self.assertRaisesRegex(EvalError, "mainnet-canary lane"):
            self.make(
                BLOOM_EVAL_SOLANA_LANE="local"
            ).preauthorization_preflight()


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
        # `HomeDir::solana_outbox_dir` is `<home>/.solana-outbox`, and entries
        # live at `<root>/<wallet>/<chain>/<state>/<id>/`.
        self.entry = (
            self.home / ".solana-outbox" / WALLET_ID / CHAIN / "pending" / "0001"
        )
        self.entry.mkdir(parents=True)

    def stage(self, **overrides: object) -> None:
        intent: dict[str, object] = {
            "destination": DESTINATION,
            "lamports": TRANSFER,
            "fee_payer": SOURCE,
            "fee_lamports": 5000,
        }
        intent.update(overrides)
        (self.entry / "intent.json").write_text(json.dumps(intent))

    def matches(self) -> bool:
        return self.definition._ceremony_matches_authorized_transfer("0001")

    def test_the_authorized_transfer_matches(self) -> None:
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

    def test_a_missing_intent_does_not_match(self) -> None:
        self.assertFalse(self.matches())


class CeremonyDiscoveryTests(ApproverMatchTests):
    """The Solana outbox publishes no `ceremony.json` through the mount: the
    confirm route writes a private `approval.json` beside the staged entry and
    returns a bare permission error. The host reads that file directly."""

    def test_no_approval_file_yet_means_no_ceremony(self) -> None:
        self.assertIsNone(self.definition._pending_confirm_ceremony("0001"))

    def test_the_ceremony_url_is_read_from_the_private_approval_file(self) -> None:
        url = "http://localhost:18734/ceremony/" + "A" * 43
        (self.entry / "approval.json").write_text(
            json.dumps({"approval_id": "a" * 64, "ceremony_url": url})
        )
        self.assertEqual(self.definition._pending_confirm_ceremony("0001"), url)

    def test_a_malformed_ceremony_url_is_refused(self) -> None:
        (self.entry / "approval.json").write_text(
            json.dumps({"approval_id": "a" * 64, "ceremony_url": "http://evil/x"})
        )
        with self.assertRaisesRegex(EvalError, "invalid ceremony URL"):
            self.definition._pending_confirm_ceremony("0001")

    def test_a_torn_write_reads_as_not_yet_published(self) -> None:
        # The file is written atomically, so unparseable bytes mean a rename
        # caught in flight, not corruption.
        (self.entry / "approval.json").write_text('{"ceremony_ur')
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

        self.assertNotIn("BLOOM_EVAL_SOLANA_SOURCE", context.agent_env)
        self.assertNotIn("BLOOM_EVAL_SOLANA_KEY_FINGERPRINT", context.agent_env)
        self.assertNotIn("BLOOM_EVAL_SOLANA_RPC_URL", context.agent_env)
        # The verifier needs all of it to grade independently.
        self.assertEqual(context.verifier_env["BLOOM_EVAL_SOLANA_SOURCE"], SOURCE)
        self.assertIn("BLOOM_EVAL_SOLANA_RPC_URL", context.verifier_env)


class TrialAmountTests(unittest.TestCase):
    def test_the_tail_is_deterministic_and_bounded(self) -> None:
        first = trial_amount(1_000_000, "trial-a")
        self.assertEqual(first, trial_amount(1_000_000, "trial-a"))
        self.assertGreaterEqual(first, 1_000_000)
        self.assertLess(first, 1_010_000)

    def test_different_trials_get_different_tails(self) -> None:
        amounts = {trial_amount(1_000_000, f"trial-{i}") for i in range(50)}
        self.assertGreater(len(amounts), 40)


if __name__ == "__main__":
    unittest.main()


class SweepTests(SolanaEvalTestCase):
    """Cleanup's sweep is what makes the eval repeatable: the transfer cannot
    be undone, but the destination is host-controlled, so the lamports come
    back and only the fees are actually spent."""

    def setUp(self) -> None:
        super().setUp()
        self.definition = self.make()
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
