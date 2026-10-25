import json
import unittest

from harness.metrics import trajectory_counts


class CommandCountsTests(unittest.TestCase):
    def counts(self, *calls):
        return trajectory_counts({"steps": [{"source": "agent", "tool_calls": calls}]})

    def call(self, name, **arguments):
        return {"function_name": name, "arguments": arguments}

    def test_native_calls_and_compound_shell_calls_share_one_denominator(self):
        result = self.counts(
            self.call("Read", file_path="/bloom/AGENTS.md"),
            self.call("bash", command="cat /bloom/a /bloom/b; printf x > /bloom/new"),
            self.call("Write", file_path="/bloom/new", content="body"),
        )
        self.assertEqual(
            result,
            {
                "agent_tool_calls": 3,
                "shell_tool_calls": 1,
                "bloom_read_tool_calls": 2,
                "bloom_write_tool_calls": 2,
                "bloom_unclassified_tool_calls": 0,
            },
        )

    def test_codex_wrapper_is_decoded_without_running_it(self):
        command = json.dumps({"cmd": "cat /bloom/a > /tmp/copy"})
        result = self.counts(
            self.call("exec", input="await tools.exec_command(" + command + ")")
        )
        self.assertEqual(result["agent_tool_calls"], 1)
        self.assertEqual(result["bloom_read_tool_calls"], 1)
        self.assertEqual(result["bloom_write_tool_calls"], 0)

    def test_output_sink_does_not_count_as_a_read(self):
        result = self.counts(
            self.call("bash", command="cat > /bloom/new <<'EOF'\n{}\nEOF")
        )
        self.assertEqual(result["bloom_read_tool_calls"], 0)
        self.assertEqual(result["bloom_write_tool_calls"], 1)

    def test_opaque_code_and_relative_paths_are_explicit_unknowns(self):
        result = self.counts(
            self.call("exec", input="opaque(`/bloom/a`)"),
            self.call("bash", command="cd /bloom && python3 inspect.py"),
            self.call("bash", command='cat "$BLOOM/a"'),
        )
        self.assertEqual(result["agent_tool_calls"], 3)
        self.assertEqual(result["bloom_unclassified_tool_calls"], 3)

    def test_user_calls_observations_and_similarly_named_paths_do_not_count(self):
        result = trajectory_counts(
            {
                "steps": [
                    {
                        "source": "user",
                        "tool_calls": [self.call("Read", file_path="/bloom/a")],
                    },
                    {
                        "source": "agent",
                        "tool_calls": [self.call("Read", file_path="/bloomer/a")],
                        "observation": {"results": [{"content": "/bloom/a"}]},
                    },
                ]
            }
        )
        self.assertEqual(result["agent_tool_calls"], 1)
        self.assertEqual(result["bloom_read_tool_calls"], 0)
