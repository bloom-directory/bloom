"""Tests for casual operator read evaluation checks."""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HARBOR_DIR = Path(__file__).resolve().parent.parent


def load_module(task_name: str):
    path = HARBOR_DIR / "tasks" / task_name / "tests" / "verify_result.py"
    spec = importlib.util.spec_from_file_location(f"verify_{task_name.replace('-', '_')}", path)
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

    def test_unnecessary_chain_clarification_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "trajectory.json").write_text(
                '{"steps": [{"source": "agent", "message": "Which chain would you like to check?", "tool_calls": [{"tool": "bash"}]}]}'
            )
            with mock.patch.dict(os.environ, {"AGENT_LOGS_DIR": str(tmp_path)}):
                self.assertFalse(balances_mod.verify())
                self.assertFalse(eth_mod.verify())

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
