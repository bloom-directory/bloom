from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

VERIFIER = (
    Path(__file__).parents[1]
    / "tasks/hyperliquid-approve-builder-fee/tests/verify_result.py"
)
SPEC = importlib.util.spec_from_file_location(
    "hyperliquid_approve_builder_fee_verify_result", VERIFIER
)
assert SPEC is not None and SPEC.loader is not None
verify_result = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_result)


class Response:
    status = 200

    def __init__(self, value: object) -> None:
        self.value = value

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def read(self) -> bytes:
        return json.dumps(self.value).encode()


class ApproveBuilderFeeVerifierTests(unittest.TestCase):
    network = "testnet"
    wallet = "0x" + "1" * 40
    wallet_id = "eval-wallet"
    builder = "0x" + "2" * 40
    max_fee_tenths_bps = 10
    nonce = 1_700_000_000_000

    def report(self, **changes: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": "bloom.eval.hyperliquid_approve_builder_fee.v1",
            "status": "complete",
            "network": self.network,
            "wallet": self.wallet,
            "wallet_id": self.wallet_id,
            "builder": self.builder,
            "max_fee_tenths_bps": self.max_fee_tenths_bps,
            "nonce": self.nonce,
            "hyperliquid_response": {"status": "ok"},
            "observed_max_builder_fee": self.max_fee_tenths_bps,
        }
        value.update(changes)
        return value

    def validate(self, report: dict[str, object], venue_max_fee_tenths_bps: int) -> None:
        verify_result.validate(
            report,
            self.network,
            self.wallet,
            self.wallet_id,
            self.builder,
            self.max_fee_tenths_bps,
            self.nonce,
            venue_max_fee_tenths_bps,
        )

    def test_valid_report_is_bound_to_the_venues_own_max_builder_fee(self) -> None:
        self.validate(self.report(), self.max_fee_tenths_bps)

    def test_agent_claims_cannot_replace_venue_evidence(self) -> None:
        with self.assertRaisesRegex(
            verify_result.InvalidReport,
            "Hyperliquid does not currently report the requested approval",
        ):
            self.validate(self.report(), self.max_fee_tenths_bps - 1)

    def test_reported_observed_fee_must_match_the_independently_queried_value(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            verify_result.InvalidReport,
            "differs from the independently queried value",
        ):
            self.validate(
                self.report(observed_max_builder_fee=self.max_fee_tenths_bps + 5),
                self.max_fee_tenths_bps,
            )

    def test_hyperliquid_rejection_cannot_pass_even_with_matching_venue_state(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            verify_result.InvalidReport,
            "did not accept the approveBuilderFee action",
        ):
            self.validate(
                self.report(hyperliquid_response={"status": "err"}),
                self.max_fee_tenths_bps,
            )

    def test_field_and_identity_mismatches_are_rejected(self) -> None:
        for changes, message in (
            ({"network": "mainnet"}, "wrong network"),
            ({"wallet": "0x" + "3" * 40}, "wrong wallet"),
            ({"wallet_id": "someone-elses-wallet"}, "wrong wallet id"),
            ({"builder": "0x" + "4" * 40}, "wrong builder"),
            ({"max_fee_tenths_bps": self.max_fee_tenths_bps + 1}, "wrong max_fee_tenths_bps"),
            ({"max_fee_tenths_bps": str(self.max_fee_tenths_bps)}, "wrong max_fee_tenths_bps"),
            ({"nonce": self.nonce + 1}, "wrong nonce"),
            ({"extra_field": "unexpected"}, "do not exactly match"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                verify_result.InvalidReport, message
            ):
                self.validate(self.report(**changes), self.max_fee_tenths_bps)

    def test_main_grades_against_a_live_queried_venue_value(self) -> None:
        calls: list[dict[str, object]] = []

        def urlopen(request: object, timeout: int) -> Response:
            self.assertEqual(timeout, verify_result.VENUE_TIMEOUT_SECONDS)
            calls.append(json.loads(request.data))  # type: ignore[attr-defined]
            return Response(self.max_fee_tenths_bps)

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "result.json"
            report_path.write_text(json.dumps(self.report()))
            with (
                mock.patch.object(
                    verify_result.urllib.request, "urlopen", side_effect=urlopen
                ),
                mock.patch.object(
                    verify_result.sys, "argv", ["verify_result.py", str(report_path)]
                ),
                mock.patch.dict(
                    verify_result.os.environ,
                    {
                        "BLOOM_EVAL_NETWORK": self.network,
                        "BLOOM_EVAL_WALLET": self.wallet,
                        "BLOOM_EVAL_WALLET_ID": self.wallet_id,
                        "BLOOM_EVAL_BUILDER": self.builder,
                        "BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS": str(
                            self.max_fee_tenths_bps
                        ),
                        "BLOOM_EVAL_APPROVAL_NONCE": str(self.nonce),
                    },
                ),
            ):
                self.assertEqual(verify_result.main(), 0)
        self.assertEqual(
            calls,
            [
                {
                    "type": "maxBuilderFee",
                    "user": self.wallet,
                    "builder": self.builder,
                }
            ],
        )

    def test_main_fails_closed_on_a_non_ok_venue_http_status(self) -> None:
        class ErrorResponse(Response):
            status = 500

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "result.json"
            report_path.write_text(json.dumps(self.report()))
            with (
                mock.patch.object(
                    verify_result.urllib.request,
                    "urlopen",
                    return_value=ErrorResponse(self.max_fee_tenths_bps),
                ),
                mock.patch.object(
                    verify_result.sys, "argv", ["verify_result.py", str(report_path)]
                ),
                mock.patch.dict(
                    verify_result.os.environ,
                    {
                        "BLOOM_EVAL_NETWORK": self.network,
                        "BLOOM_EVAL_WALLET": self.wallet,
                        "BLOOM_EVAL_WALLET_ID": self.wallet_id,
                        "BLOOM_EVAL_BUILDER": self.builder,
                        "BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS": str(
                            self.max_fee_tenths_bps
                        ),
                        "BLOOM_EVAL_APPROVAL_NONCE": str(self.nonce),
                    },
                ),
            ):
                self.assertEqual(verify_result.main(), 1)


if __name__ == "__main__":
    unittest.main()
