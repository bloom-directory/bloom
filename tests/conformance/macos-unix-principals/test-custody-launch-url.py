import base64
import importlib.util
from pathlib import Path
import unittest
import sys
from urllib.parse import urlencode

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("custody_launch", Path(__file__).with_name("custody-launch-url.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CustodyLaunchTests(unittest.TestCase):
    token = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    bridge = "http://127.0.0.1:28744/onboarding/" + "1" * 64 + "/"

    def test_only_known_ui_fragment_is_removed_and_capability_is_preserved(self):
        plain = f"http://localhost:18734/ceremony/{self.token}"
        self.assertEqual(module.custody_launch_url(plain), plain)
        self.assertEqual(module.custody_launch_url(plain + "#" + urlencode({"setup": self.bridge})), plain)
        fragment_capability = f"http://localhost:18734/ceremony/#cap={self.token}"
        self.assertEqual(module.custody_launch_url(fragment_capability), fragment_capability)

    def test_unexpected_authority_and_routing_are_rejected(self):
        plain = f"http://localhost:18734/ceremony/{self.token}"
        setup = urlencode({"setup": self.bridge})
        invalid = [
            plain + "#cap=" + self.token,
            plain + "#other=value",
            plain + "#" + setup + "&" + setup,
            plain + "?query=value#" + setup,
            plain + "?#" + setup,
            plain + "#" + urlencode({"setup": self.bridge.replace("127.0.0.1:", "user@127.0.0.1:")}),
            plain + "#" + urlencode({"setup": self.bridge + "#fragment"}),
            plain.replace("localhost", "attacker.example") + "#" + setup,
            plain.replace(self.token, "short") + "#" + setup,
            plain + "/extra#" + setup,
            plain + "#" + urlencode({"setup": self.bridge.replace("127.0.0.1", "attacker.example")}),
            plain + "#" + urlencode({"setup": self.bridge + "?query=value"}),
            plain + "#" + urlencode({"setup": self.bridge.replace("1" * 64, "short")}),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.custody_launch_url(value)


if __name__ == "__main__":
    unittest.main()
