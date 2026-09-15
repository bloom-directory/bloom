from __future__ import annotations

import base64
import copy
import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from harness.core import COUNTER_EXHAUSTED, COUNTER_MAX, CounterSidecar, EvalError
from harness.hyperliquid_approve_builder_fee import (
    OPERATION_CLASS,
    ROUTE_PATTERN,
    HyperliquidApproveBuilderFeeEval,
)
from harness import hyperliquid_order_cancel
from harness.hyperliquid_order_cancel import (
    MAINNET_ACK,
    MAX_SESSION_CEREMONIES,
    HyperliquidOrderCancelEval,
)

HARBOR = Path(__file__).resolve().parents[1]


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


class AddressValidationTests(BuilderFeeFixture, unittest.TestCase):
    """Hostile addresses must be refused before they reach a path.

    `BLOOM_EVAL_WALLET` and `BLOOM_EVAL_BUILDER` are interpolated straight
    into `max_builder_fee_path`, so a value carrying path metacharacters
    would read somewhere other than the venue projection this eval treats
    as independent evidence. An absolute value is the worst case: pathlib
    discards everything to its left, so the read escapes the mount
    entirely rather than merely moving within it.
    """

    HOSTILE = {
        "traversal": "../../../../etc/passwd",
        "absolute": "/etc/passwd",
        "trailing newline": "0x" + "a" * 40 + "\n",
        "leading newline": "\n" + "0x" + "a" * 40,
        "trailing slash segment": "0x" + "a" * 40 + "/..",
        "glob": "0x" + "a" * 39 + "*",
        "shell metacharacters": "0x" + "a" * 39 + ";id",
        "nul byte": "0x" + "a" * 40 + "\x00",
        "uppercase": "0X" + "A" * 40,
        "empty": "",
    }

    def test_preflight_rejects_a_wallet_carrying_path_metacharacters(self) -> None:
        for case, value in self.HOSTILE.items():
            self.env["BLOOM_EVAL_WALLET"] = value
            definition = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
            with self.subTest(case=case):
                with self.assertRaisesRegex(EvalError, "BLOOM_EVAL_WALLET"):
                    definition.preflight()

    def test_preflight_rejects_a_builder_carrying_path_metacharacters(self) -> None:
        for case, value in self.HOSTILE.items():
            self.env["BLOOM_EVAL_BUILDER"] = value
            definition = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
            with self.subTest(case=case):
                with self.assertRaisesRegex(EvalError, "BLOOM_EVAL_BUILDER"):
                    definition.preflight()

    def test_a_hostile_address_would_have_escaped_the_mount(self) -> None:
        """Why the check above matters, not just that it fires."""
        self.env["BLOOM_EVAL_WALLET"] = "/etc/passwd"
        escaped = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        self.assertFalse(
            escaped.max_builder_fee_path.is_relative_to(self.mount),
            "an absolute wallet escapes the mount, so preflight must refuse it",
        )
        # The validated address stays where the venue projection lives.
        self.assertTrue(self.definition.max_builder_fee_path.is_relative_to(self.mount))


class CounterDurabilityTests(BuilderFeeFixture, unittest.TestCase):
    """A counter that cannot be recorded must stop the run before it starts."""

    def test_preflight_fails_when_the_counter_sidecar_cannot_be_written(self) -> None:
        def unwritable() -> None:
            raise OSError(30, "Read-only file system")

        self.definition.counter_durability_check = unwritable
        with self.assertRaisesRegex(EvalError, "counter sidecar is not writable"):
            self.definition.preflight()

    def test_preflight_reports_an_eval_error_from_the_sidecar_unchanged(self) -> None:
        self.definition.counter_durability_check = mock.Mock(
            side_effect=EvalError("operator state recovery locations are stale")
        )
        with self.assertRaisesRegex(EvalError, "recovery locations are stale"):
            self.definition.preflight()

    def test_reserve_counter_commits_before_returning(self) -> None:
        committed: list[int] = []
        self.definition.counter_committed = committed.append
        self.assertEqual(self.definition.reserve_counter(4), 5)
        self.assertEqual(committed, [5], "the spend is recorded, not just returned")
        self.assertEqual(self.definition.next_sign_count, 5)

    def test_reserve_counter_works_without_an_operator_sidecar(self) -> None:
        self.definition.counter_committed = None
        self.assertEqual(self.definition.reserve_counter(9), 10)
        self.assertEqual(self.definition.next_sign_count, 10)

    def test_a_sidecar_commit_failure_aborts_before_the_driver_runs(self) -> None:
        # reserve_counter must propagate, not swallow: a counter that could
        # not be recorded is exactly the one that must not be spent.
        self.definition.counter_committed = mock.Mock(
            side_effect=EvalError("refusing a non-advancing authenticator counter update")
        )
        with self.assertRaisesRegex(EvalError, "non-advancing"):
            self.definition.reserve_counter(4)


class CounterSidecarRestartTests(BuilderFeeFixture, unittest.TestCase):
    """A spent counter must survive the process that spent it."""

    def sidecar(self) -> CounterSidecar:
        return CounterSidecar(self.root / "counters" / "builder-fee.counter.json")

    def test_next_process_resumes_at_the_counter_the_last_one_reserved(self) -> None:
        # Process 1: two ceremonies, exactly as a grant and a revoke spend.
        first = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        first.attach_counter_sidecar(self.sidecar())
        counter = first._require_sign_count()
        self.assertEqual(counter, 4, "starts at the configured counter")
        counter = first.reserve_counter(counter)
        counter = first.reserve_counter(counter)
        self.assertEqual(counter, 6)

        # Process 2: same environment, same unchanged
        # BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT=4. Before the sidecar this
        # replayed counter 4 and Broker rejected the assertion.
        second = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        second.attach_counter_sidecar(self.sidecar())
        self.assertEqual(
            second._require_sign_count(),
            6,
            "a new process must not reuse a counter the last one spent",
        )

    def test_a_raised_environment_counter_still_wins(self) -> None:
        first = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        first.attach_counter_sidecar(self.sidecar())
        first.reserve_counter(first._require_sign_count())

        self.env["BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT"] = "99"
        second = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        second.attach_counter_sidecar(self.sidecar())
        self.assertEqual(second._require_sign_count(), 99)

    def test_an_interrupted_ceremony_still_burns_its_counter(self) -> None:
        # Reservation commits before the driver runs, so a process killed
        # mid-assertion leaves the counter recorded as spent. A gap is safe;
        # reuse is not.
        first = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        first.attach_counter_sidecar(self.sidecar())
        first.reserve_counter(first._require_sign_count())
        del first  # the process dies before the driver returns

        second = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        second.attach_counter_sidecar(self.sidecar())
        self.assertEqual(second._require_sign_count(), 5)

    def test_the_sidecar_refuses_to_move_a_counter_backwards(self) -> None:
        sidecar = self.sidecar()
        sidecar.write(9)
        with self.assertRaisesRegex(EvalError, "non-advancing"):
            sidecar.write(8)
        self.assertEqual(sidecar.read(), 9)

    def test_a_malformed_sidecar_is_refused_not_ignored(self) -> None:
        sidecar = self.sidecar()
        sidecar.path.parent.mkdir(parents=True, exist_ok=True)
        for case, body in {
            "not json": b"{",
            "wrong schema": b'{"schema":"other","next_sign_count":3}',
            "missing field": b'{"schema":"bloom.eval.counter-sidecar.v1"}',
            "not an integer": (
                b'{"schema":"bloom.eval.counter-sidecar.v1","next_sign_count":"3"}'
            ),
            "out of range": (
                b'{"schema":"bloom.eval.counter-sidecar.v1","next_sign_count":0}'
            ),
        }.items():
            sidecar.path.write_bytes(body)
            with self.subTest(case=case), self.assertRaises(EvalError):
                sidecar.read()

    def test_a_written_sidecar_is_mode_0600_and_leaves_no_temporary(self) -> None:
        sidecar = self.sidecar()
        sidecar.write(5)
        self.assertEqual(stat.S_IMODE(sidecar.path.stat().st_mode), 0o600)
        self.assertFalse(list(sidecar.path.parent.glob(".*.new-*")))


class CredentialSidecarTests(BuilderFeeFixture, unittest.TestCase):
    """Counters are spent per authenticator, so every eval shares one record."""

    def credential(self) -> CounterSidecar:
        return CounterSidecar.for_credential(self.seed, self.root / "counters")

    def test_evals_sharing_a_seed_share_one_sidecar(self) -> None:
        same = self.credential().path
        self.assertEqual(CounterSidecar.for_credential(self.seed, self.root / "counters").path, same)
        # A copy of the same seed elsewhere is the same credential.
        copied = self.root / "seed-copy"
        copied.write_bytes(self.seed.read_bytes())
        self.assertEqual(CounterSidecar.for_credential(copied, self.root / "counters").path, same)
        # A different seed is a different credential.
        other = self.root / "other-seed"
        other.write_text("a different authenticator")
        self.assertNotEqual(CounterSidecar.for_credential(other, self.root / "counters").path, same)

    def test_the_sidecar_name_does_not_expose_the_seed(self) -> None:
        name = self.credential().path.name
        seed = self.seed.read_bytes()
        self.assertNotIn(seed.decode(), name)
        self.assertNotIn(hashlib.sha256(seed).hexdigest()[:24], name)

    def test_order_cancel_and_builder_fee_never_sign_with_the_same_counter(self) -> None:
        # The reported bug: both evals read the same unchanged configured
        # counter, then reserve. Keyed per eval, both signed with it.
        path = self.credential().path
        fee = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        cancel = HyperliquidOrderCancelEval(self.repo, self.env)
        for definition in (fee, cancel):
            definition.attach_counter_sidecar(CounterSidecar(path))
        fee_start, cancel_start = fee._require_sign_count(), cancel._require_sign_count()
        self.assertEqual(fee_start, cancel_start, "both begin from the same configured counter")
        signed_by_fee = fee.reserve_counter(fee_start) - 1
        signed_by_cancel = cancel.reserve_counter(cancel_start) - 1
        self.assertNotEqual(signed_by_fee, signed_by_cancel)
        self.assertEqual({signed_by_fee, signed_by_cancel}, {4, 5})

    def test_a_reservation_waits_for_another_process_holding_the_lock(self) -> None:
        sidecar = self.credential()
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import sys, time\nfrom pathlib import Path\nfrom harness.core import CounterSidecar\n"
             f"s = CounterSidecar(Path({str(sidecar.path)!r}))\n"
             "with s.locked():\n    print('held', flush=True)\n    time.sleep(1.0)\n"],
            cwd=HARBOR, stdout=subprocess.PIPE, text=True,
        )
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.wait)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        started = time.monotonic()
        self.assertEqual(sidecar.reserve(4), 4)
        self.assertGreaterEqual(
            time.monotonic() - started, 0.7,
            "reserve must block while another process holds the credential lock",
        )

    def test_concurrent_processes_each_sign_with_a_distinct_counter(self) -> None:
        sidecar = self.credential()
        code = (
            "from pathlib import Path\nfrom harness.core import CounterSidecar\n"
            f"print(CounterSidecar(Path({str(sidecar.path)!r})).reserve(4))\n"
        )
        workers = [
            subprocess.Popen([sys.executable, "-c", code], cwd=HARBOR,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(8)
        ]
        signed = sorted(int(w.communicate(timeout=60)[0].strip()) for w in workers)
        self.assertEqual(signed, list(range(4, 12)), "no two processes may share a counter")
        self.assertEqual(sidecar.read(), 12)


class CounterBlockReservationTests(BuilderFeeFixture, unittest.TestCase):
    """A run owns its whole ceremony budget before it can create authority."""

    def sidecar(self) -> CounterSidecar:
        return CounterSidecar.for_credential(self.seed, self.root / "counters")

    def fee(self, count: int | str = 4) -> HyperliquidApproveBuilderFeeEval:
        self.env["BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT"] = str(count)
        definition = HyperliquidApproveBuilderFeeEval(self.repo, self.env)
        definition.attach_counter_sidecar(CounterSidecar(self.sidecar().path))
        return definition

    def cancel(self, count: int | str = 4) -> HyperliquidOrderCancelEval:
        self.env["BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT"] = str(count)
        definition = HyperliquidOrderCancelEval(self.repo, self.env)
        definition.attach_counter_sidecar(CounterSidecar(self.sidecar().path))
        return definition

    def test_the_whole_budget_is_recorded_before_any_ceremony(self) -> None:
        fee = self.fee()
        self.assertEqual(fee.reserve_run_counters(fee._require_sign_count()), 4)
        self.assertEqual(self.sidecar().read(), 6, "grant and revoke are both claimed up front")

    def test_reserving_again_in_the_same_run_claims_nothing_more(self) -> None:
        fee = self.fee()
        first = fee.reserve_run_counters(fee._require_sign_count())
        self.assertEqual(fee.reserve_run_counters(first), first)
        self.assertEqual(self.sidecar().read(), 6)

    def test_a_run_cannot_sign_outside_its_reserved_range(self) -> None:
        fee = self.fee()
        counter = fee.reserve_run_counters(fee._require_sign_count())
        counter = fee.reserve_counter(counter)  # grant signs 4
        counter = fee.reserve_counter(counter)  # revoke signs 5
        with self.assertRaisesRegex(EvalError, "outside its reserved range"):
            fee.reserve_counter(counter)

    def test_a_competing_eval_cannot_take_the_counter_cleanup_needs(self) -> None:
        # The reported race: five counters remain. Builder-fee needs 2 and
        # order-cancel needs 4, and both pass the advisory capacity check.
        start = COUNTER_MAX - 4
        fee, cancel = self.fee(start), self.cancel(start)
        fee_start, cancel_start = fee._require_sign_count(), cancel._require_sign_count()
        self.assertEqual((fee_start, cancel_start), (start, start))

        # Builder-fee finishes preflight first and signs its grant.
        counter = fee.reserve_counter(fee.reserve_run_counters(fee_start))
        grant = counter - 1

        # Order-cancel's preflight can no longer claim four counters, so it is
        # refused before creating any authority of its own.
        with self.assertRaisesRegex(EvalError, "including its cleanup"):
            cancel.reserve_run_counters(cancel_start)

        # Builder-fee's mandatory revoke still has its counter.
        revoke = fee.reserve_counter(counter) - 1
        self.assertEqual((grant, revoke), (start, start + 1))

    def test_when_the_other_eval_reserves_first_builder_fee_is_refused_before_granting(self) -> None:
        start = COUNTER_MAX - 4
        cancel, fee = self.cancel(start), self.fee(start)
        cancel.reserve_run_counters(cancel._require_sign_count())
        with self.assertRaisesRegex(EvalError, "including its cleanup"):
            fee.reserve_run_counters(fee._require_sign_count())

    def test_insufficient_capacity_writes_nothing(self) -> None:
        sidecar = self.sidecar()
        sidecar.write(COUNTER_MAX)
        with self.assertRaisesRegex(EvalError, "including its cleanup"):
            sidecar.reserve_block(4, 2)
        self.assertEqual(sidecar.read(), COUNTER_MAX)

    def test_concurrent_processes_get_disjoint_ranges(self) -> None:
        sidecar = self.sidecar()
        code = (
            "from pathlib import Path\nfrom harness.core import CounterSidecar\n"
            f"print(CounterSidecar(Path({str(sidecar.path)!r})).reserve_block(4, 2))\n"
        )
        workers = [
            subprocess.Popen([sys.executable, "-c", code], cwd=HARBOR,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for _ in range(6)
        ]
        starts = sorted(int(w.communicate(timeout=60)[0].strip()) for w in workers)
        self.assertEqual(starts, [4, 6, 8, 10, 12, 14], "no two runs may share a counter")
        self.assertEqual(sidecar.read(), 16)

    def test_a_block_reservation_waits_for_another_process_holding_the_lock(self) -> None:
        sidecar = self.sidecar()
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import time\nfrom pathlib import Path\nfrom harness.core import CounterSidecar\n"
             f"s = CounterSidecar(Path({str(sidecar.path)!r}))\n"
             "with s.locked():\n    print('held', flush=True)\n    time.sleep(1.0)\n"],
            cwd=HARBOR, stdout=subprocess.PIPE, text=True,
        )
        self.addCleanup(holder.stdout.close)
        self.addCleanup(holder.wait)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        started = time.monotonic()
        self.assertEqual(sidecar.reserve_block(4, 2), 4)
        self.assertGreaterEqual(time.monotonic() - started, 0.7)

    def test_order_cancel_preflight_claims_the_budget_as_its_last_step(self) -> None:
        # Same wiring for order-cancel: after the empty-wallet check and
        # immediately before provision() creates the session.
        self.env["BLOOM_EVAL_MAINNET_ACK"] = MAINNET_ACK
        cancel = self.cancel()
        cancel.network_root.mkdir(parents=True)
        (cancel.network_root / "mids.json").write_text("{}")
        (cancel.network_root / "perp_meta.json").write_text("{}")
        (cancel.network_root.parent / "README.md").write_text("installed")
        self.driver.write_text("#!/bin/sh\n")
        self.driver.chmod(0o755)
        order: list[str] = []
        cancel.preauthorization_preflight = mock.Mock()
        cancel._require_exact_wallet_policy = mock.Mock()
        cancel._pull_eval_image = mock.Mock()
        cancel._require_empty_wallet = mock.Mock(
            side_effect=lambda: order.append("empty-wallet-check")
        )
        reserve = cancel.reserve_run_counters

        def recording_reserve(start: int) -> int:
            order.append("reserve")
            return reserve(start)

        cancel.reserve_run_counters = recording_reserve
        driver_usage = subprocess.CompletedProcess(
            [], 0, stdout="usage: complete URL --authenticator-seed-file PATH", stderr=""
        )
        with (
            mock.patch.object(hyperliquid_order_cancel.os.path, "ismount", return_value=True),
            mock.patch.object(hyperliquid_order_cancel.subprocess, "run", return_value=driver_usage),
        ):
            cancel.preflight()
        self.assertEqual(order, ["empty-wallet-check", "reserve"], "reservation must be the last step")
        self.assertEqual(cancel.sign_count, 4)
        self.assertEqual(self.sidecar().read(), 4 + MAX_SESSION_CEREMONIES)

    def test_builder_fee_preflight_claims_the_budget_as_its_last_step(self) -> None:
        # Wiring: preflight() itself must reserve, after every other check
        # and immediately before provision() can create authority.
        (self.mount / "petals/hyperliquid/testnet").mkdir(parents=True)
        (self.mount / "petals/hyperliquid/README.md").write_text("installed")
        self.driver.write_text("#!/bin/sh\n")
        self.driver.chmod(0o755)
        fee = self.fee()
        order: list[str] = []
        fee.preauthorization_preflight = mock.Mock()
        fee._require_exact_wallet_policy = mock.Mock()
        fee._pull_eval_image = mock.Mock()
        fee._pending_builder_fee_ceremony = mock.Mock(
            side_effect=lambda: order.append("pending-check")
        )
        reserve = fee.reserve_run_counters

        def recording_reserve(start: int) -> int:
            order.append("reserve")
            return reserve(start)

        fee.reserve_run_counters = recording_reserve
        with mock.patch.object(
            subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")
        ):
            fee.preflight()
        self.assertEqual(order, ["pending-check", "reserve"], "reservation must be the last step")
        self.assertEqual(fee.sign_count, 4)
        self.assertEqual(self.sidecar().read(), 6)


class CounterCapacityTests(BuilderFeeFixture, unittest.TestCase):
    """A run must never start without a counter left for its own cleanup."""

    def fee(self, count: int | str) -> HyperliquidApproveBuilderFeeEval:
        self.env["BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT"] = str(count)
        return HyperliquidApproveBuilderFeeEval(self.repo, self.env)

    def test_builder_fee_refuses_the_last_counter_because_cleanup_needs_another(self) -> None:
        # The reported bug: 4294967295 was accepted, the grant spent it, and
        # the mandatory revoke then needed the invalid 4294967296.
        with self.assertRaisesRegex(EvalError, "including its cleanup"):
            self.fee(COUNTER_MAX)._require_sign_count()
        self.assertEqual(self.fee(COUNTER_MAX - 1)._require_sign_count(), COUNTER_MAX - 1)

    def test_order_cancel_reserves_room_for_every_session_ceremony(self) -> None:
        budget = MAX_SESSION_CEREMONIES
        last_start = COUNTER_MAX - budget + 1
        for count, ok in ((last_start, True), (last_start + 1, False)):
            self.env["BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT"] = str(count)
            definition = HyperliquidOrderCancelEval(self.repo, self.env)
            with self.subTest(count=count):
                if ok:
                    self.assertEqual(definition._require_sign_count(), count)
                else:
                    with self.assertRaisesRegex(EvalError, "including its cleanup"):
                        definition._require_sign_count()

    def test_capacity_is_checked_on_the_resumed_counter(self) -> None:
        # A low configured counter must not hide a sidecar that is near the top.
        sidecar = CounterSidecar(self.root / "counters" / "near-top.counter.json")
        sidecar.write(COUNTER_MAX)
        definition = self.fee(4)
        definition.attach_counter_sidecar(sidecar)
        with self.assertRaisesRegex(EvalError, "including its cleanup"):
            definition._require_sign_count()

    def test_a_run_at_the_top_can_still_record_its_final_revoke(self) -> None:
        sidecar = CounterSidecar(self.root / "counters" / "top.counter.json")
        definition = self.fee(COUNTER_MAX - 1)
        definition.attach_counter_sidecar(sidecar)
        grant = definition.reserve_counter(definition._require_sign_count()) - 1
        revoke = definition.reserve_counter(grant + 1) - 1
        self.assertEqual((grant, revoke), (COUNTER_MAX - 1, COUNTER_MAX))
        self.assertEqual(sidecar.read(), COUNTER_EXHAUSTED, "exhaustion is recorded, not rejected")
        with self.assertRaisesRegex(EvalError, "exhausted"):
            sidecar.reserve(COUNTER_EXHAUSTED)
        # And the next run refuses at preflight instead of mid-ceremony.
        follow_up = self.fee(4)
        follow_up.attach_counter_sidecar(sidecar)
        with self.assertRaisesRegex(EvalError, "including its cleanup"):
            follow_up._require_sign_count()

    def test_an_eval_without_a_declared_budget_is_refused(self) -> None:
        definition = self.fee(4)
        definition.CEREMONY_BUDGET = None
        with self.assertRaisesRegex(EvalError, "ceremony budget"):
            definition._require_sign_count()


class WalletBindingTests(BuilderFeeFixture, unittest.TestCase):
    """The wallet id must be proven to own the address the verifier reads."""

    def wire(self, addresses: object, policy: object | None = None) -> None:
        expected = {
            "allowed_destinations": [],
            "allowed_petal_packages": [self.package_hash],
            "maximum_approval_lifetime_ms": 2_592_000_000,
            "required_verifiers": [],
            "wallet_id": self.wallet_id,
        }
        body = expected if policy is None else policy
        if isinstance(addresses, dict) and "policy_digest" not in addresses:
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            addresses["policy_digest"] = hashlib.sha256(canonical).hexdigest()

        def read(path: Path, timeout: int = 20) -> object:
            del timeout
            return addresses if path.name == "addresses.json" else body

        self.definition._read_json = mock.Mock(side_effect=read)

    def good_addresses(self) -> dict[str, object]:
        return {
            "owner": self.wallet,
            "policy_status": "broker_verified",
            "freshness": "fresh",
        }

    def test_a_matching_projection_is_accepted(self) -> None:
        self.wire(self.good_addresses())
        self.definition._require_exact_wallet_policy()

    def test_a_wallet_id_owning_a_different_address_is_refused(self) -> None:
        addresses = self.good_addresses()
        addresses["owner"] = "0x" + "9" * 40
        self.wire(addresses)
        with self.assertRaisesRegex(EvalError, "does not own"):
            self.definition._require_exact_wallet_policy()

    def test_an_unverified_or_stale_projection_is_refused(self) -> None:
        for case, patch, expected in (
            ("unverified", {"policy_status": "unverified"}, "not Broker-verified"),
            ("stale", {"freshness": "stale"}, "stale"),
            ("no owner", {"owner": None}, "does not own"),
        ):
            addresses = self.good_addresses()
            addresses.update(patch)
            self.wire(addresses)
            with self.subTest(case=case), self.assertRaisesRegex(EvalError, expected):
                self.definition._require_exact_wallet_policy()

    def test_a_policy_edited_underneath_its_projection_is_refused(self) -> None:
        addresses = self.good_addresses()
        addresses["policy_digest"] = "0" * 64
        self.wire(addresses)
        with self.assertRaisesRegex(EvalError, "digest does not match"):
            self.definition._require_exact_wallet_policy()

    def test_a_non_object_projection_is_refused(self) -> None:
        self.wire(["not", "an", "object"])
        with self.assertRaisesRegex(EvalError, "not a JSON object"):
            self.definition._require_exact_wallet_policy()


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


class FakeVenue:
    """Models the parts of the Petal/Broker contract cleanup depends on.

    Specifically: an owner approval covers one exact request body, is
    single-use (`max_operations: 1`), and only a write covered by a live
    approval reaches the venue. An uncovered write stages a fresh ceremony
    instead of doing anything, which is what makes the retry after the
    ceremony -- not the first write -- the one that moves maxBuilderFee.
    """

    CEREMONY = "http://localhost:18734/ceremony/" + "C" * 43

    def __init__(self, definition: HyperliquidApproveBuilderFeeEval) -> None:
        self.definition = definition
        self.max_builder_fee = 0
        # request_id -> {"body": bytes, "status": str}
        self.requests: dict[str, dict[str, object]] = {}
        self._next_id = 0

    def stage_approval(self, body: bytes, status: str = "approved_retry_required") -> str:
        self._next_id += 1
        request_id = f"{self._next_id:064x}"
        self.requests[request_id] = {"body": body, "status": status}
        return request_id

    def write(self, _route: object, body: bytes, _timeout: object) -> object:
        """Consume a live approval for these exact bytes, or stage one."""
        for entry in self.requests.values():
            if entry["body"] == body and entry["status"] == "approved_retry_required":
                entry["status"] = "signed"
                self.max_builder_fee = json.loads(body)["max_fee_tenths_bps"]
                return subprocess.CompletedProcess([], 0, b"", b"")
        # No live approval: the venue is untouched. A body never approved
        # stages a new ceremony; a replay of an already-consumed request
        # stages nothing it can complete on its own either -- both leave
        # maxBuilderFee alone, which is the property under test.
        if not any(entry["body"] == body for entry in self.requests.values()):
            self.stage_approval(body, "awaiting_owner_approval")
            return subprocess.CompletedProcess([], 0, self.CEREMONY.encode(), b"")
        return subprocess.CompletedProcess([], 0, b"", b"rejected: no live approval")

    def complete_ceremony(self, command: list[str], **_kwargs: object) -> object:
        """Stand in for the WebAuthn debug driver."""
        for entry in self.requests.values():
            if entry["status"] == "awaiting_owner_approval":
                entry["status"] = "approved_retry_required"
        return subprocess.CompletedProcess(command, 0, b"", b"")

    def records(self) -> list[dict[str, object]]:
        return [
            {"request_id": rid, "status": entry["status"]}
            for rid, entry in self.requests.items()
        ]

    def pending_ceremony(self) -> str | None:
        awaiting = any(
            entry["status"] == "awaiting_owner_approval"
            for entry in self.requests.values()
        )
        return self.CEREMONY if awaiting else None

    def install(self, test: unittest.TestCase) -> None:
        d = self.definition
        d._write_route = mock.Mock(side_effect=self.write)
        d._builder_fee_requests = mock.Mock(side_effect=self.records)
        d._pending_builder_fee_ceremony = mock.Mock(side_effect=self.pending_ceremony)
        d._observed_max_builder_fee = mock.Mock(
            side_effect=lambda: self.max_builder_fee
        )
        d._read_json = mock.Mock(return_value={"status": "ok"})
        patcher = mock.patch.object(
            subprocess, "run", side_effect=self.complete_ceremony
        )
        patcher.start()
        test.addCleanup(patcher.stop)


class BuilderFeeCeremonyLifecycleTests(BuilderFeeFixture, unittest.TestCase):
    """The grant/revoke lifecycle around WebAuthn counters and cleanup."""

    def venue(self) -> "FakeVenue":
        """A Petal/venue stand-in that honours single-use approvals."""
        return FakeVenue(self.definition)

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
        # One staged request, whose status walks `statuses` and then settles
        # on "signed" -- the state a grant the agent consumed ends in.
        request_id = "b" * 64

        def requests() -> list[dict[str, object]]:
            status = pending.pop(0) if pending else "signed"
            return [{"request_id": request_id, "status": status}]

        definition._builder_fee_requests = mock.Mock(side_effect=requests)

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

    def test_provision_refuses_a_lower_nonzero_baseline_it_would_erase(self) -> None:
        # Cleanup revokes to zero, not to the prior value, so an approval
        # below the target (3 < 10) would be silently erased.
        definition, counters = self.drive()
        definition._observed_max_builder_fee = mock.Mock(return_value=3)
        with self.assertRaisesRegex(EvalError, "already approves 3"):
            definition.provision("codex")
        definition._write_route.assert_not_called()
        self.assertEqual(counters, [], "no ceremony may run")
        self.assertFalse(definition.cleanup_needed, "nothing was staged, so nothing to revoke")

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

    def test_the_driver_signs_with_the_counter_the_shared_sidecar_hands_out(self) -> None:
        # Between this run choosing its start and reaching the ceremony,
        # another eval on the same authenticator spends counters 4..6. The
        # driver must sign with 7, not replay the 4 this run had in hand.
        definition, counters = self.drive()
        definition._observed_max_builder_fee = mock.Mock(return_value=0)
        sidecar = CounterSidecar(self.root / "counters" / "shared.counter.json")
        definition.attach_counter_sidecar(sidecar)
        definition.sign_count = 4
        sidecar.write(7)

        definition.provision("codex")

        self.assertEqual(counters, [7], "the driver replayed a counter another eval spent")
        self.assertEqual(sidecar.read(), 8)

    def test_cleanup_is_a_noop_before_any_side_effecting_write(self) -> None:
        definition, counters = self.drive()
        definition.cleanup()
        self.assertEqual(counters, [])

    def test_cleanup_retires_a_grant_the_agent_never_submitted(self) -> None:
        """An abandoned staged grant must not survive cleanup.

        Revoking under a different nonce leaves the original approved request
        executable, so a later replay could restore the fee after cleanup
        observed zero.
        """
        definition = self.definition
        venue = self.venue()
        venue.install(self)

        # Stage the grant exactly as provision() does, then leave it: the
        # agent never performs the write that would consume it.
        max_fee = int(definition.max_fee_tenths_bps_value)
        definition.nonce = 4242
        grant_body = definition._request_body(max_fee, definition.nonce)
        definition.staged_request_id = venue.stage_approval(grant_body)
        definition.cleanup_needed = True
        self.assertEqual(venue.max_builder_fee, 0, "agent never submitted")

        definition.cleanup()

        # The staged grant is spent, not merely outnumbered.
        self.assertEqual(
            definition._request_status(definition.staged_request_id), "signed"
        )
        self.assertEqual(venue.max_builder_fee, 0, "venue ends revoked")

        # Replaying the original approved bytes must not restore the fee.
        venue.write(None, grant_body, None)
        self.assertEqual(
            venue.max_builder_fee,
            0,
            "a consumed single-use approval cannot be replayed to re-grant",
        )


if __name__ == "__main__":
    unittest.main()
