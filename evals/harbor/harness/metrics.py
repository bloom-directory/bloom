"""Comparable attempted tool-call counts; never infer kernel or RPC I/O."""

import json
import re

MOUNT = re.compile(r"/bloom(?=/|[\s\"'`]|$)")
READ = re.compile(
    r"\b(?:cat|ls|find|rg|grep|sed|head|tail|stat|wc|readlink)\b[^;&|\n]*?/bloom(?:/|\b)"
)
WRITE = re.compile(
    r"(?:>>?|\btee(?:\s+-\w+)*|\btouch|\btruncate|\bmkdir(?:\s+-\w+)*)\s*[\"']?/bloom(?:/|\b)"
)


def trajectory_counts(trajectory):
    counts = dict.fromkeys(
        (
            "agent_tool_calls",
            "shell_tool_calls",
            "bloom_read_tool_calls",
            "bloom_write_tool_calls",
            "bloom_unclassified_tool_calls",
        ),
        0,
    )
    for step in trajectory.get("steps", []):
        if step.get("source") != "agent":
            continue
        for call in step.get("tool_calls", []):
            counts["agent_tool_calls"] += 1
            name = call.get("function_name", "").rsplit(".", 1)[-1].lower()
            args = call.get("arguments", {})
            if not isinstance(args, dict):
                args = {"input": args}
            text = json.dumps(args)
            commands = []
            for key in ("command", "cmd"):
                if isinstance(args.get(key), str):
                    commands.append(args[key])
            # Codex's exec wrapper commonly contains JSON arguments to nested
            # exec_command calls. Decode strings, not executable JavaScript.
            source = args.get("input", "")
            if isinstance(source, str):
                for match in re.finditer(r'(?:"cmd"|\bcmd)\s*:\s*(")', source):
                    try:
                        command, _ = json.JSONDecoder().raw_decode(
                            source[match.start(1) :]
                        )
                    except ValueError:
                        continue
                    commands.append(command)
            if commands:
                counts["shell_tool_calls"] += 1
            bloom = bool(MOUNT.search(text)) or "$BLOOM" in text or "${BLOOM}" in text
            if not bloom:
                continue
            read = name in {"read", "read_file"}
            write = name in {"write", "write_file", "edit", "apply_patch"}
            for command in commands:
                # A read redirected to /tmp remains a Bloom read, while
                # `cat > /bloom/new` is only a write-bearing call.
                without_outputs = re.sub(
                    r">{1,2}\s*(?:\"[^\"]*\"|'[^']*'|[^\s;&|]+)", "", command
                )
                read |= bool(READ.search(without_outputs))
                write |= bool(WRITE.search(command))
            counts["bloom_read_tool_calls"] += int(read)
            counts["bloom_write_tool_calls"] += int(write)
            counts["bloom_unclassified_tool_calls"] += int(not read and not write)
    return counts
