"""Tests for casual operator read evaluation checks."""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HARBOR_DIR = Path(__file__).resolve().parent.parent


def load_module(task_name: str):
    path = HARBOR_DIR / "tasks" / task_name / "tests" / "verify_result.py"
    spec = importlib.util.spec_from_file_location(
        f"verify_{task_name.replace('-', '_')}", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


eth_mod = load_module("casual-eth-in-main")
balances_mod = load_module("casual-wallet-balances")
chains_mod = load_module("casual-supported-chains")
sent_mod = load_module("casual-sent-history")
anvil_mod = load_module("casual-anvil-status")


class CasualVerifierTests(unittest.TestCase):
    def test_zero_commands_rejected_for_all_casual_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Which address?", "tool_calls": []}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertFalse(eth_mod.verify())
                self.assertFalse(balances_mod.verify())
                self.assertFalse(chains_mod.verify())
                self.assertFalse(sent_mod.verify())
                self.assertFalse(anvil_mod.verify())

    def test_valid_eth_in_main_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Wallet main holds 0.05 ETH on ethereum.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertTrue(eth_mod.verify())

    def test_eth_in_main_cannot_determine_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "I cannot determine the ETH balance.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertFalse(eth_mod.verify())

    def test_unnecessary_chain_clarification_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Which chain would you like to check?", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertFalse(balances_mod.verify())
                self.assertFalse(eth_mod.verify())

    def test_wallet_balances_balance_lookup_failed_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Balance lookup failed for the wallets.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertFalse(balances_mod.verify())

    def test_wallet_balances_missing_wallet_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Wallet harbor has 0.05 ETH on ethereum.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_LOGS_DIR": str(tmp_path),
                    "BLOOM_EVAL_EXPECTED_BALANCES": json.dumps(
                        {"harbor": "0.05", "savings": "1.25"}
                    ),
                },
            ):
                self.assertFalse(balances_mod.verify())

    def test_valid_wallet_balances_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Wallet harbor has 0.05 ETH and wallet savings has 1.25 ETH.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_LOGS_DIR": str(tmp_path),
                    "BLOOM_EVAL_EXPECTED_BALANCES": json.dumps(
                        {"harbor": "0.05", "savings": "1.25"}
                    ),
                },
            ):
                self.assertTrue(balances_mod.verify())

    def test_supported_chains_ethereum_and_base_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Supported chains are Ethereum and Base.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_LOGS_DIR": str(tmp_path),
                    "BLOOM_EVAL_CONFIGURED_CHAINS": json.dumps(
                        ["ethereum", "polygon", "anvil"]
                    ),
                },
            ):
                self.assertFalse(chains_mod.verify())

    def test_valid_supported_chains_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Supported chains are ethereum, polygon, and anvil.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_LOGS_DIR": str(tmp_path),
                    "BLOOM_EVAL_CONFIGURED_CHAINS": json.dumps(
                        ["ethereum", "polygon", "anvil"]
                    ),
                },
            ):
                self.assertTrue(chains_mod.verify())

    def test_sent_history_cannot_determine_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "I could not determine that.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertFalse(sent_mod.verify())

    def test_sent_history_missing_recipient_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "I checked your transactions.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_LOGS_DIR": str(tmp_path),
                    "BLOOM_EVAL_EXPECTED_RECIPIENT": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
                },
            ):
                self.assertFalse(sent_mod.verify())

    def test_valid_sent_history_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Sent transactions to 0x70997970c51812dc3a010c7d01b50e0d17dc79c8.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_LOGS_DIR": str(tmp_path),
                    "BLOOM_EVAL_EXPECTED_RECIPIENT": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
                },
            ):
                self.assertTrue(sent_mod.verify())

    def test_anvil_cannot_determine_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "I cannot determine if anvil is offline.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertFalse(anvil_mod.verify())

    def test_valid_anvil_offline_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Anvil is currently offline and not connected.", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertTrue(anvil_mod.verify())


if __name__ == "__main__":
    unittest.main()
