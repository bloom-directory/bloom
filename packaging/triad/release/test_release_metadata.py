import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "metadata", Path(__file__).with_name("release-metadata.py")
)
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


class ReleaseMetadataTests(unittest.TestCase):
    def setUp(self):
        self.matrix = {
            "bundles": [dict.fromkeys(("machine", "broker", "signer"), "0.3.0")],
            "protocols": {
                "machine_broker": {"major": 1, "minor_min": 4, "minor_max": 4},
                "broker_signer": {"major": 1, "minor_min": 2, "minor_max": 4},
            },
        }

    def test_equal_versions(self):
        metadata.check_versions(self.matrix, "0.3.0")

    def test_each_mismatched_binary_is_rejected(self):
        for component in ("machine", "broker", "signer"):
            with self.subTest(component=component):
                self.matrix["bundles"][0][component] = "0.1.0"
                with self.assertRaisesRegex(ValueError, component):
                    metadata.check_versions(self.matrix, "0.3.0")
                self.matrix["bundles"][0][component] = "0.3.0"

    def test_ambiguous_bundle_is_rejected(self):
        self.matrix["bundles"] *= 2
        with self.assertRaises(ValueError):
            metadata.check_versions(self.matrix, "0.3.0")

    @patch.object(metadata, "git", return_value="abcdef123456789 fix <thing>\n123456abcdef789 merge branch")
    def test_notes_include_ranges_and_all_commits(self, git):
        body = metadata.notes(self.matrix, "0.3.0", "owner/bloom", "abc", "v0.2.0")
        self.assertIn("Machine → Broker: `1.4`", body)
        self.assertIn("Broker → Signer: `1.2`–`1.4`", body)
        self.assertIn("fix \\<thing\\>", body)
        self.assertIn("merge branch", body)
        self.assertIn("refs/tags/v0.2.0..abc", git.call_args.args)

    @patch.object(metadata, "git", return_value="abc initial")
    def test_first_release(self, git):
        self.assertIn("First release", metadata.notes(self.matrix, "0.3.0", "o/r", "abc", None))
        self.assertEqual(git.call_args.args[-2:], ("abc", "--"))

    @patch.object(metadata.subprocess, "run")
    @patch.object(metadata, "git", return_value="ancestor")
    def test_retry_ignores_newer_draft_and_prereleases(self, git, run):
        run.return_value.returncode = 0
        releases = [
            {"tag_name": f"v0.{i}.0", "published_at": str(i),
             "draft": i == 2, "prerelease": i == 3}
            for i in range(1, 7)
        ]
        self.assertEqual(metadata.previous_release(releases, "v0.4.0", "target"), "v0.1.0")

    @patch.object(metadata.subprocess, "run")
    @patch.object(metadata, "git", return_value="unrelated")
    def test_non_ancestor_is_excluded(self, git, run):
        run.return_value.returncode = 1
        release = {"tag_name": "v0.1.0", "published_at": "1", "draft": False, "prerelease": False}
        self.assertIsNone(metadata.previous_release([release], "v0.2.0", "target"))


if __name__ == "__main__":
    unittest.main()
