from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


VERIFIER = (
    Path(__file__).parents[1]
    / "tasks/hyperliquid-order-cancel/tests/verify_result.py"
)
SPEC = importlib.util.spec_from_file_location("hyperliquid_verify_result", VERIFIER)
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


class HyperliquidVerifierTests(unittest.TestCase):
    wallet = "0x" + "1" * 40
    session = "bloom-eval-test"
    cloid = "0x" + "2" * 32

    def venue_evidence(self, **changes: object) -> dict[str, object]:
        order = {
            "coin": "BTC",
            "side": "B",
            "limitPx": "95000",
            "sz": "0",
            "oid": 123,
            "timestamp": 1,
            "triggerCondition": "N/A",
            "isTrigger": False,
            "triggerPx": "0",
            "children": [],
            "isPositionTpsl": False,
            "reduceOnly": False,
            "orderType": "Limit",
            "origSz": "0.00011",
            "tif": "Alo",
            "cloid": self.cloid,
        }
        order.update(changes)
        return {
            "status": "order",
            "order": {
                "order": order,
                "status": "canceled",
                "statusTimestamp": 2,
            },
        }

    def report(self) -> dict[str, object]:
        return {
            "schema": "bloom.eval.hyperliquid_order_cancel.v1",
            "status": "complete",
            "network": "mainnet",
            "wallet": self.wallet,
            "session_id": self.session,
            "asset": "BTC",
            "asset_id": 0,
            "side": "buy",
            "leverage": 1,
            "post_only": True,
            "mark_price": "100000",
            "limit_price": "95000",
            "size": "0.00011",
            "notional_usd": "10.45",
            "cloid": self.cloid,
            "order_status": "resting",
            "order_id": 123,
            "cancel_status": "success",
            "matching_open_orders_after_cancel": 0,
            "session_left_active_for_harness_cleanup": True,
        }

    def test_valid_report_is_bound_to_canceled_venue_order(self) -> None:
        verify_result.validate(
            self.report(), self.wallet, self.session, self.cloid, self.venue_evidence()
        )

    def test_agent_claims_cannot_replace_venue_cancellation_evidence(self) -> None:
        evidence = self.venue_evidence()
        evidence["order"]["status"] = "open"  # type: ignore[index]
        with self.assertRaisesRegex(
            verify_result.InvalidReport, "not canceled at Hyperliquid"
        ):
            verify_result.validate(
                self.report(), self.wallet, self.session, self.cloid, evidence
            )

    def test_venue_cloid_and_order_terms_are_required(self) -> None:
        for changes, message in (
            ({"cloid": "0x" + "3" * 32}, "wrong CLOID"),
            ({"tif": "Gtc"}, "not post-only"),
            ({"oid": 456}, "order id differs"),
            ({"limitPx": "94999"}, "price differs"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                verify_result.InvalidReport, message
            ):
                verify_result.validate(
                    self.report(),
                    self.wallet,
                    self.session,
                    self.cloid,
                    self.venue_evidence(**changes),
                )

    def test_main_queries_by_trusted_cloid_then_venue_oid(self) -> None:
        evidence = self.venue_evidence()
        calls: list[object] = []

        def urlopen(request: object, timeout: int) -> Response:
            self.assertEqual(timeout, verify_result.VENUE_TIMEOUT_SECONDS)
            body = json.loads(request.data)  # type: ignore[attr-defined]
            calls.append(body["oid"])
            return Response(evidence)

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
                        "BLOOM_EVAL_WALLET": self.wallet,
                        "BLOOM_EVAL_SESSION_ID": self.session,
                        "BLOOM_EVAL_CLOID": self.cloid,
                    },
                ),
            ):
                self.assertEqual(verify_result.main(), 0)
        self.assertEqual(calls, [self.cloid, 123])


if __name__ == "__main__":
    unittest.main()
