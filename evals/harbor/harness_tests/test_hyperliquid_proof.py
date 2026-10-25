import copy
import json
import unittest

from hyperliquid_proof import Unavailable, commitments, validate_proposal


class HyperliquidProofTests(unittest.TestCase):
    def setUp(self):
        self.body = {
            "action": {
                "type": "order",
                "orders": [
                    {
                        "a": 3,
                        "b": True,
                        "p": "77112",
                        "s": "0.00015",
                        "r": False,
                        "t": {"limit": {"tif": "Alo"}},
                    }
                ],
                "grouping": "na",
            }
        }
        self.expected = {
            "wallet": "harbor",
            "package_hash": "package",
            "route_id": "owner-route",
            "address": "0x1234",
            "asset_id": 3,
            "price": "77112",
            "size": "0.00015",
        }
        self.account = {
            "wallet": "harbor",
            "number": 0,
            "freshness": "fresh",
            "evm": {"address": "0x1234", "key_ref": {"fingerprint": "fresh-key"}},
        }
        self.nonce = 1792888375157

    def proposal(self, body=None, network="testnet"):
        body = self.body if body is None else body
        payload, signing_hash, batch = commitments(
            body, body.get("nonce", self.nonce), network
        )
        request = {k: self.expected[k] for k in ("wallet", "package_hash", "route_id")}
        request.update(
            request_id="machine-request",
            approval_id="broker-approval",
            payload_digest=payload,
            status="awaiting_owner_approval",
        )
        manifest = {
            "issued_at_ms": str(self.nonce),
            "approval_id": request["approval_id"],
            "exact_payload_digests": [payload],
            "exact_hashes": [signing_hash],
            "petal_use_claim": {
                "package_hash": "package",
                "route": "owner-route",
                "payload_digest": batch,
                "ordered_hashes": [signing_hash],
            },
        }
        review = {
            "review_manifest": manifest,
            "signer_contribution": {"key_ref": self.account["evm"]["key_ref"]},
        }
        # Matches Codex's nested wrapper, with no assumptions about a shell parser.
        trajectory = {
            "steps": [
                {
                    "source": "agent",
                    "tool_calls": [
                        {
                            "arguments": {
                                "code": "await tools.exec_command("
                                + json.dumps(
                                    {
                                        "cmd": "echo '"
                                        + json.dumps(body)
                                        + "' > /bloom/order.json"
                                    }
                                )
                                + ")"
                            }
                        }
                    ],
                }
            ]
        }
        pending = [
            {
                "action_id": request["request_id"],
                "nonce": self.nonce,
                "completed": False,
            }
        ]
        return [request], self.account, self.expected, review, trajectory, pending

    def test_released_live_golden_vector(self):
        self.assertEqual(
            commitments(self.body, self.nonce, "testnet"),
            (
                "0803e214d9027c3ec50e3602896c2a4a190769090b81a3b76413dfe7045bc832",
                "83c7f90582553c6872f6ac290a2606d9700c9d50abca619045da070064966c56",
                "8d789410d52d96427e07528c746cf05b8a5368a2f31356c505b53d8d3447404e",
            ),
        )
        validate_proposal(*self.proposal())

    def test_actual_wrong_terms_are_rejected_after_successful_proof(self):
        for field, value in (
            ("a", 4),
            ("b", False),
            ("p", "77113"),
            ("s", "0.00016"),
            ("r", True),
            ("t", {"limit": {"tif": "Ioc"}}),
        ):
            body = copy.deepcopy(self.body)
            body["action"]["orders"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_proposal(*self.proposal(body))
        with self.assertRaises(ValueError):
            validate_proposal(*self.proposal(network="mainnet"))

    def test_equivalent_decimals_cloid_and_explicit_nonce_pass_when_committed(self):
        body = copy.deepcopy(self.body)
        body["action"]["orders"][0].update(p="77112.0", s="0.000150", c="0x" + "1" * 32)
        body["nonce"] = self.nonce + 1
        args = self.proposal(body)
        args[-1].clear()
        validate_proposal(*args)

    def test_committed_future_expiry_passes_but_expired_order_fails(self):
        body = copy.deepcopy(self.body)
        body["expiresAfter"] = self.nonce + 60_000
        validate_proposal(*self.proposal(body))
        for expiry, valid in (
            (self.nonce - 1, False),
            (self.nonce, False),
            (self.nonce + 1, True),
        ):
            body["expiresAfter"] = expiry
            with self.subTest(expiry=expiry):
                if valid:
                    validate_proposal(*self.proposal(body))
                else:
                    with self.assertRaises(ValueError):
                        validate_proposal(*self.proposal(body))

    def test_nonce_window_is_strict_and_relative_to_trusted_issuance(self):
        for offset, valid in (
            (-172800001, False),
            (-172800000, False),
            (-172799999, True),
            (86399999, True),
            (86400000, False),
            (86400001, False),
            (-62888375157, False),
        ):
            body = copy.deepcopy(self.body)
            body["nonce"] = self.nonce + offset
            with self.subTest(offset=offset):
                if valid:
                    validate_proposal(*self.proposal(body))
                else:
                    with self.assertRaises(ValueError):
                        validate_proposal(*self.proposal(body))
        args = self.proposal()
        del args[3]["review_manifest"]["issued_at_ms"]
        with self.assertRaises(Unavailable):
            validate_proposal(*args)

    def test_missing_duplicate_wrong_account_and_advanced_requests_fail(self):
        for count in (0, 2):
            args = self.proposal()
            args[0][:] = args[0] * count
            with self.assertRaises(ValueError):
                validate_proposal(*args)
        for key, value in (
            ("wallet", "other"),
            ("route_id", "agent-route"),
            ("package_hash", "other"),
            ("status", "signed"),
        ):
            args = self.proposal()
            args[0][0][key] = value
            with self.assertRaises(ValueError):
                validate_proposal(*args)
        args = self.proposal()
        args[3]["signer_contribution"]["key_ref"] = {"fingerprint": "account-1"}
        with self.assertRaises(ValueError):
            validate_proposal(*args)

    def test_each_commitment_and_nonce_link_is_mandatory(self):
        for key in ("exact_payload_digests", "exact_hashes"):
            args = self.proposal()
            args[3]["review_manifest"][key] = ["wrong"]
            with self.assertRaises(Unavailable):
                validate_proposal(*args)
        for key in ("payload_digest", "ordered_hashes"):
            args = self.proposal()
            args[3]["review_manifest"]["petal_use_claim"][key] = "wrong"
            with self.assertRaises(Unavailable):
                validate_proposal(*args)
        args = self.proposal()
        args[-1][0]["action_id"] = "broker-approval"  # Wrong identifier namespace.
        with self.assertRaises(Unavailable):
            validate_proposal(*args)

    def test_final_report_without_tool_witness_is_observability_failure(self):
        args = self.proposal()
        args[4]["steps"] = [{"source": "agent", "message": json.dumps(self.body)}]
        with self.assertRaises(Unavailable):
            validate_proposal(*args)


if __name__ == "__main__":
    unittest.main()
