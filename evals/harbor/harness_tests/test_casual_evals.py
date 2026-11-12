"""Casual read verifiers: real reads, final answer only, truth from the projection."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness.disposable import DisposableTriad

HARBOR_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HARBOR_DIR / "tasks"))
import activity  # noqa: E402


def load(task):
    path = HARBOR_DIR / "tasks" / task / "tests" / "verify_result.py"
    spec = importlib.util.spec_from_file_location(task.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ETH = load("casual-eth-in-main")
BALANCES = load("casual-wallet-balances")
CHAINS = load("casual-supported-chains")
SENT = load("casual-sent-history")
ANVIL = load("casual-anvil-status")
RECIPIENT = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"


def step(message=None, *commands):
    return {
        "source": "agent",
        "message": message,
        "tool_calls": [{"arguments": {"command": c}} for c in commands],
    }


class Verifiers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "projection"
        self.write("wallets/main/0/account.json", "{}")
        self.write("wallets/main/0/chains/ethereum/balance", "2.5 ETH\n")
        self.write("wallets/savings/0/account.json", "{}")
        self.write("wallets/savings/0/chains/ethereum/balance", "1.25 ETH\n")
        self.write(
            f"wallets/main/0/chains/ethereum/outbox/sent/0001/intent.json",
            json.dumps({"to": RECIPIENT}),
        )
        for chain in ("ethereum", "polygon", "anvil"):
            (self.root / "chains" / chain).mkdir(parents=True, exist_ok=True)
        self.write("status/chains/anvil/connected", "false\n")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def check(self, module, *steps):
        witness = Path(self.tmp.name) / "trajectory.json"
        witness.write_text(json.dumps({"steps": list(steps)}))
        with mock.patch.dict(os.environ, {"BLOOM_EVAL_TRAJECTORY_FILE": str(witness)}):
            return module.verify(self.root)

    def test_no_read_fails_every_task(self):
        answers = {
            ETH: "Wallet main holds 2.5 ETH.",
            BALANCES: "main has 2.5 ETH. savings has 1.25 ETH.",
            CHAINS: "ethereum, polygon, anvil",
            SENT: f"You sent to {RECIPIENT}.",
            ANVIL: "Anvil is offline.",
        }
        for module, answer in answers.items():
            self.assertIsNotNone(self.check(module, step(answer)))
            self.assertIsNotNone(self.check(module, step(None, "pwd"), step(answer)))

    def test_eth_in_main_uses_projected_balance(self):
        read = "bloom vfs cat /wallets/main/0/chains/ethereum/balance"
        self.assertIsNone(self.check(ETH, step(None, read), step("Wallet main holds 2.5 ETH.")))
        self.assertIsNotNone(self.check(ETH, step(None, read), step("main has 0.05 ETH")))
        self.write("wallets/main/0/chains/ethereum/balance", "3.1 ETH\n")
        self.assertIsNotNone(self.check(ETH, step(None, read), step("main has 2.5 ETH")))

    def test_only_the_final_message_counts(self):
        read = "bloom vfs cat /wallets/main/0/chains/ethereum/balance"
        self.assertIsNotNone(
            self.check(ETH, step("main has 2.5 ETH", read), step("Correction: main has 999 ETH"))
        )

    def test_failed_read_does_not_count(self):
        logs = Path(self.tmp.name) / "logs"
        logs.mkdir()
        events = [
            {"type": "item.completed", "item": {"type": "command_execution",
             "command": "cat /bloom/wallets/main/0/chains/ethereum/balance", "exit_code": 1}},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "main has 2.5 ETH"}},
        ]
        (logs / "codex.txt").write_text("\n".join(json.dumps(e) for e in events))
        with mock.patch.dict(os.environ, {"BLOOM_EVAL_TRAJECTORY_FILE": "", "AGENT_LOGS_DIR": str(logs)}):
            found = activity.get_agent_activity()
            self.assertEqual(len(found.commands), 1)
            self.assertIsNotNone(ETH.verify(self.root))

    def test_wallet_balances_must_pair_wallet_and_amount(self):
        read = "bloom vfs cat /wallets/main/0/chains/ethereum/balance"
        self.assertIsNone(self.check(BALANCES, step(None, read), step("main: 2.5 ETH\nsavings: 1.25 ETH")))
        self.assertIsNotNone(self.check(BALANCES, step(None, read), step("main 1.25 ETH; savings 2.5 ETH")))
        self.assertIsNotNone(self.check(BALANCES, step(None, read), step("main has 2.5 ETH")))

    def test_supported_chains_match_projection(self):
        read = "bloom vfs ls /chains"
        self.assertIsNone(self.check(CHAINS, step(None, read), step("ethereum, polygon and anvil (from the database)")))
        self.assertIsNotNone(self.check(CHAINS, step(None, read), step("ethereum, polygon, anvil, base")))
        self.assertIsNotNone(self.check(CHAINS, step(None, read), step("ethereum and polygon")))

    def test_sent_history_reads_sent_entries(self):
        read = "bloom vfs ls /wallets/main/0/chains/ethereum/outbox/sent"
        self.assertIsNone(self.check(SENT, step(None, read), step(f"You sent ETH to {RECIPIENT}.")))
        self.assertIsNotNone(self.check(SENT, step(None, read), step("You have not sent anything.")))
        other = "0x" + "1" * 40
        self.assertIsNotNone(self.check(SENT, step(None, read), step(f"Sent to {RECIPIENT} and {other}.")))

    def test_anvil_status_matches_projection(self):
        read = "bloom vfs cat /status/chains/anvil/connected"
        self.assertIsNone(self.check(ANVIL, step(None, read), step("Anvil is offline: not connected.")))
        self.assertIsNotNone(self.check(ANVIL, step(None, read), step("Anvil is up and running.")))
        self.write("status/chains/anvil/connected", "true\n")
        self.assertIsNone(self.check(ANVIL, step(None, read), step("Anvil is connected.")))

    def test_unnecessary_question_fails(self):
        read = "bloom vfs cat /wallets/main/0/chains/ethereum/balance"
        self.assertIsNotNone(self.check(BALANCES, step(None, read), step("Which chain should I check?")))


class ForkLifecycle(unittest.TestCase):
    def test_fork_start_checks_rpc_and_funds_the_default_wallet(self):
        with tempfile.TemporaryDirectory() as directory:
            triad = DisposableTriad(
                Path("/repo"),
                {"BLOOM_EVAL_ROOTS_DIR": directory, "BLOOM_INTEGRATION_DEBUG_DRIVER_BIN": "/x"},
            )
            ceremony = "http://localhost:1/ceremony/" + "a" * 43
            rpc_calls = []

            def cli(*args):
                if args[:2] == ("wallet", "new"):
                    return ceremony
                return triad.ethereum_rpc_url + "\n"

            process = mock.Mock(poll=mock.Mock(return_value=None))
            with mock.patch.object(triad, "preflight"), \
                    mock.patch("harness.disposable.subprocess.Popen", return_value=process), \
                    mock.patch.object(triad, "_wait", return_value=True), \
                    mock.patch.object(triad, "cli", side_effect=cli) as called, \
                    mock.patch.object(triad, "read", return_value={"evm": {"address": "0xabc"}}), \
                    mock.patch.object(triad, "fork_rpc", side_effect=lambda *a: rpc_calls.append(a)), \
                    mock.patch.object(triad, "_run", return_value="anvil 1.0\n"), \
                    mock.patch("harness.disposable.CeremonyDriver") as driver:
                driver.return_value.complete.return_value = {"wallet_id": "harbor"}
                triad.start(ethereum_fork=True)
            self.assertIn(mock.call("vfs", "cat", "/status/chains/ethereum/rpc_url"), called.mock_calls)
            self.assertIn(("anvil_setBalance", "0xabc", hex(5 * 10**16)), rpc_calls)
            self.assertEqual(triad.fork_info["eth_wei"], 5 * 10**16)
            self.assertNotIn("[chains.anvil]", (triad.root / "machine.toml").read_text())


if __name__ == "__main__":
    unittest.main()
