"""Tests for the shared mount and ceremony helpers in `harness.core`.

These are the pieces every live eval reuses, so they are tested directly rather
than only through whichever eval happens to exercise them first.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from harness.core import (
    CeremonyDriver,
    EvalError,
    MountedTree,
    SignCountStore,
    poll_until,
    resolve_sign_count,
)


class PollUntilTests(unittest.TestCase):
    def test_returns_true_as_soon_as_the_predicate_holds(self) -> None:
        calls = []

        def predicate() -> bool:
            calls.append(1)
            return len(calls) == 2

        self.assertTrue(poll_until(predicate, attempts=5, delay=0))
        self.assertEqual(len(calls), 2)

    def test_returns_false_when_the_budget_is_spent(self) -> None:
        self.assertFalse(poll_until(lambda: False, attempts=3, delay=0))

    def test_treats_an_eval_error_as_not_yet_until_the_last_attempt(self) -> None:
        calls = []

        def predicate() -> bool:
            calls.append(1)
            if len(calls) < 3:
                raise EvalError("mid-settle read failed")
            return True

        self.assertTrue(poll_until(predicate, attempts=5, delay=0))

    def test_reraises_when_the_last_attempt_still_fails(self) -> None:
        def predicate() -> bool:
            raise EvalError("never clears")

        with self.assertRaisesRegex(EvalError, "never clears"):
            poll_until(predicate, attempts=2, delay=0)


class MountedTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mount = MountedTree(read_timeout=1, read_attempts=3)

    def test_read_json_parses_a_mounted_file(self) -> None:
        path = self.root / "status.json"
        path.write_text(json.dumps({"stopped": False}))
        self.assertEqual(self.mount.read_json(path), {"stopped": False})

    def test_read_json_retries_a_torn_snapshot(self) -> None:
        # A projection can be replaced while NFS is serving the read, which
        # surfaces as truncated JSON. That is transient, not corruption.
        responses = [
            SimpleNamespace(stdout=b'{"stopp'),
            SimpleNamespace(stdout=b'{"stopped": true}'),
        ]
        with mock.patch("harness.core.subprocess.run", side_effect=responses):
            with mock.patch("harness.core.time.sleep"):
                observed = self.mount.read_json(self.root / "x")
        self.assertEqual(observed, {"stopped": True})

    def test_read_json_retries_a_timeout(self) -> None:
        responses = [
            subprocess.TimeoutExpired(cmd="cat", timeout=1),
            SimpleNamespace(stdout=b"[]"),
        ]

        def run(*_args, **_kwargs):
            item = responses.pop(0)
            if isinstance(item, BaseException):
                raise item
            return item

        with mock.patch("harness.core.subprocess.run", side_effect=run):
            with mock.patch("harness.core.time.sleep"):
                self.assertEqual(self.mount.read_json(self.root / "x"), [])

    def test_read_json_fails_closed_after_the_attempt_budget(self) -> None:
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(stdout=b"not json"),
        ):
            with mock.patch("harness.core.time.sleep"):
                with self.assertRaisesRegex(EvalError, "after 3 attempts"):
                    self.mount.read_json(self.root / "x")

    def test_read_json_if_listed_requires_the_parent_listing(self) -> None:
        # A dynamic route can make `stat` succeed for an identifier that was
        # never created, so the listing is the durable existence boundary.
        sessions = self.root / "sessions"
        (sessions / "real").mkdir(parents=True)
        (sessions / "real" / "status.json").write_text('{"ok": true}')

        self.assertEqual(
            self.mount.read_json_if_listed(
                sessions / "real" / "status.json", sessions, "real"
            ),
            {"ok": True},
        )
        self.assertIsNone(
            self.mount.read_json_if_listed(
                sessions / "ghost" / "status.json", sessions, "ghost"
            )
        )

    def test_read_json_if_listed_returns_none_for_a_missing_listing_dir(self) -> None:
        self.assertIsNone(
            self.mount.read_json_if_listed(
                self.root / "absent" / "s.json", self.root / "absent", "s"
            )
        )

    def test_write_route_writes_the_exact_bytes(self) -> None:
        path = self.root / "new.tx"
        result = self.mount.write_route(path, b'{"lamports":1}', timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(path.read_bytes(), b'{"lamports":1}')

    def test_write_route_surfaces_a_hung_mount_as_an_eval_error(self) -> None:
        with mock.patch(
            "harness.core.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="write", timeout=1),
        ):
            with self.assertRaisesRegex(EvalError, "route write to .* failed"):
                self.mount.write_route(self.root / "new.tx", b"x", timeout=1)


class CeremonyDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seed = self.root / "seed"
        self.seed.write_bytes(b"seed-material")
        self.seed.chmod(0o600)
        self.driver = self.root / "driver"
        self.driver.write_text("#!/bin/sh\nexit 0\n")
        self.driver.chmod(0o755)
        self.url = "http://localhost:18734/ceremony/" + "A" * 43

    def make(self, start: int = 2) -> CeremonyDriver:
        return CeremonyDriver(self.driver, self.seed, start)

    def test_preflight_names_an_unset_seed_variable_as_such(self) -> None:
        # An unset path lstats as `.` and would otherwise be reported as "not a
        # regular file", which points the operator at the wrong problem.
        driver = CeremonyDriver(self.driver, Path(""), 2)
        with self.assertRaisesRegex(EvalError, "not configured"):
            driver.preflight()

    def test_preflight_rejects_a_world_readable_seed(self) -> None:
        self.seed.chmod(0o644)
        with self.assertRaisesRegex(EvalError, "must have mode 0600"):
            self.make().preflight()

    def test_preflight_rejects_an_empty_seed(self) -> None:
        self.seed.write_bytes(b"")
        self.seed.chmod(0o600)
        with self.assertRaisesRegex(EvalError, "seed file is empty"):
            self.make().preflight()

    def test_preflight_rejects_a_symlinked_seed(self) -> None:
        link = self.root / "seed-link"
        link.symlink_to(self.seed)
        driver = CeremonyDriver(self.driver, link, 2)
        with self.assertRaisesRegex(EvalError, "regular non-symlink file"):
            driver.preflight()

    def test_preflight_rejects_a_missing_driver(self) -> None:
        driver = CeremonyDriver(self.root / "absent", self.seed, 2)
        with self.assertRaisesRegex(EvalError, "missing or not executable"):
            driver.preflight()

    def test_preflight_requires_seed_file_support(self) -> None:
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(stdout="usage: driver", stderr=""),
        ):
            with self.assertRaisesRegex(EvalError, "lacks --authenticator-seed-file"):
                self.make().preflight()

    def test_preflight_accepts_a_driver_advertising_the_flag(self) -> None:
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(
                stdout="usage: --authenticator-seed-file PATH", stderr=""
            ),
        ):
            self.make().preflight()

    def test_complete_advances_the_counter_and_records_the_url(self) -> None:
        driver = self.make(start=2)
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=b"ok", stderr=b""),
        ) as run:
            driver.complete(self.url)
        self.assertEqual(run.call_args.args[0][-1], "2")
        self.assertEqual(driver.next_sign_count, 3)
        self.assertIn(self.url, driver.completed)

    def test_a_failed_ceremony_still_consumes_its_counter(self) -> None:
        # The Broker accepts the counter before the ceremony can fail, so a
        # failure must not tempt the next run into reusing it.
        driver = self.make(start=5)
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout=b"denied", stderr=b""),
        ):
            with self.assertRaisesRegex(EvalError, "next unused counter is 6"):
                driver.complete(self.url)
        self.assertEqual(driver.next_sign_count, 6)
        self.assertNotIn(self.url, driver.completed)

    def test_complete_makes_exactly_one_attempt(self) -> None:
        # A consumed or absent ceremony is CEREMONY_REPLAY with retry "never",
        # so a second attempt cannot succeed and only burns another counter.
        driver = self.make()
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b""),
        ) as run:
            with self.assertRaises(EvalError):
                driver.complete(self.url)
        self.assertEqual(run.call_count, 1)

    def test_failure_output_never_leaks_a_live_ceremony_url(self) -> None:
        driver = self.make()
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(
                returncode=1, stdout=self.url.encode(), stderr=b""
            ),
        ):
            with self.assertRaises(EvalError) as raised:
                driver.complete(self.url)
        self.assertNotIn(self.url, str(raised.exception))
        self.assertIn("[REDACTED_CEREMONY_URL]", str(raised.exception))

    def test_redact_replaces_every_occurrence(self) -> None:
        text = f"first {self.url} second {self.url}"
        self.assertNotIn(self.url, CeremonyDriver.redact(text))
        redacted = CeremonyDriver.redact(text)
        self.assertEqual(redacted.count("[REDACTED_CEREMONY_URL]"), 2)


if __name__ == "__main__":
    unittest.main()


class SignCountStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "nested" / "sign-count"
        self.store = SignCountStore(self.path)

    def test_an_absent_record_reads_as_none(self) -> None:
        self.assertIsNone(self.store.read())

    def test_a_written_counter_round_trips(self) -> None:
        self.store.write(7)
        self.assertEqual(self.store.read(), 7)

    def test_the_counter_never_moves_backwards(self) -> None:
        # A concurrent or earlier run may already have consumed further than
        # this one knows about, and lowering the record would cause reuse.
        self.store.write(10)
        self.store.write(4)
        self.assertEqual(self.store.read(), 10)

    def test_a_non_integer_record_fails_closed(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text("banana")
        with self.assertRaisesRegex(EvalError, "does not contain an integer"):
            self.store.read()

    def test_an_out_of_range_record_fails_closed(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text("0")
        with self.assertRaisesRegex(EvalError, "out-of-range"):
            self.store.read()

    def test_the_environment_wins_over_the_record(self) -> None:
        self.store.write(3)
        self.assertEqual(resolve_sign_count("11", self.store, "VAR"), 11)

    def test_the_record_is_used_when_the_environment_is_unset(self) -> None:
        self.store.write(3)
        self.assertEqual(resolve_sign_count("", self.store, "VAR"), 3)

    def test_neither_source_fails_closed_with_guidance(self) -> None:
        with self.assertRaisesRegex(EvalError, "no counter has been recorded"):
            resolve_sign_count("", self.store, "VAR")

    def test_the_driver_records_a_consumed_counter_before_judging_it(self) -> None:
        # The Broker accepts the counter before a ceremony can fail, so a
        # failure must still leave it spent.
        seed = Path(self.temp.name) / "seed"
        seed.write_bytes(b"x")
        seed.chmod(0o600)
        driver_path = Path(self.temp.name) / "driver"
        driver_path.write_text("#!/bin/sh\nexit 0\n")
        driver_path.chmod(0o755)
        driver = CeremonyDriver(driver_path, seed, 5, store=self.store)
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout=b"", stderr=b""),
        ):
            with self.assertRaises(EvalError):
                driver.complete("http://localhost:18734/ceremony/" + "A" * 43)
        self.assertEqual(self.store.read(), 6)

    def test_a_record_failure_is_not_reported_as_a_ceremony_failure(self) -> None:
        # A ceremony that succeeded must never be reported as one that failed:
        # the caller would unwind state that was actually created.
        seed = Path(self.temp.name) / "seed2"
        seed.write_bytes(b"x")
        seed.chmod(0o600)
        driver_path = Path(self.temp.name) / "driver2"
        driver_path.write_text("#!/bin/sh\nexit 0\n")
        driver_path.chmod(0o755)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("banana")  # unreadable record
        driver = CeremonyDriver(driver_path, seed, 5, store=self.store)
        url = "http://localhost:18734/ceremony/" + "A" * 43
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=b"ok", stderr=b""),
        ):
            with self.assertRaises(EvalError) as raised:
                driver.complete(url)
        message = str(raised.exception)
        self.assertIn("succeeded but its counter could not be recorded", message)
        self.assertIn("SIGN_COUNT=6", message)
        # The ceremony really did happen, so it must be remembered as consumed.
        self.assertIn(url, driver.completed)
        self.assertEqual(driver.next_sign_count, 6)

    def test_a_failed_ceremony_still_reports_as_a_ceremony_failure(self) -> None:
        seed = Path(self.temp.name) / "seed3"
        seed.write_bytes(b"x")
        seed.chmod(0o600)
        driver_path = Path(self.temp.name) / "driver3"
        driver_path.write_text("#!/bin/sh\nexit 1\n")
        driver_path.chmod(0o755)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("banana")
        driver = CeremonyDriver(driver_path, seed, 5, store=self.store)
        with mock.patch(
            "harness.core.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout=b"denied", stderr=b""),
        ):
            with self.assertRaisesRegex(EvalError, "ceremony failed at sign count 5"):
                driver.complete("http://localhost:18734/ceremony/" + "A" * 43)

    def test_the_record_is_keyed_to_the_seed_file(self) -> None:
        seed = Path(self.temp.name) / "eval-authenticator-seed"
        store = SignCountStore.for_seed_file(seed)
        self.assertEqual(store.path, seed.with_name(seed.name + ".sign-count"))

    def test_two_credentials_get_two_records(self) -> None:
        # A signature counter belongs to a credential, not to the machine.
        a = SignCountStore.for_seed_file(Path(self.temp.name) / "seed-a")
        b = SignCountStore.for_seed_file(Path(self.temp.name) / "seed-b")
        self.assertNotEqual(a.path, b.path)

    def test_an_explicit_override_wins(self) -> None:
        store = SignCountStore.for_seed_file(Path("/seed"), "/tmp/elsewhere")
        self.assertEqual(store.path, Path("/tmp/elsewhere"))

    def test_an_unconfigured_seed_yields_a_store_that_holds_nothing(self) -> None:
        # `Path("")` is `.`, and `with_name` on it raises ValueError. Reporting
        # the missing seed file is the seed validation's job, not this one's,
        # so the store must get out of the way rather than crash on the way past.
        store = SignCountStore.for_seed_file(Path(""))
        self.assertIsNone(store.path)
        self.assertIsNone(store.read())
        store.write(5)  # no-op, must not raise
        with self.assertRaisesRegex(EvalError, "no counter has been recorded"):
            resolve_sign_count("", store, "VAR")
