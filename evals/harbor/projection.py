"""Read public grading projections through IPC, or a local fixture tree."""

import json
import os
import subprocess
from pathlib import Path


class ProjectionReader:
    def __init__(self, root=None):
        self.root = root or Path(os.environ.get("BLOOM_EVAL_MOUNT_ROOT", "/bloom"))
        self.endpoint = (
            None
            if root is not None
            else os.environ.get("BLOOM_EVAL_PROJECTION_RPC_ENDPOINT")
        )

    def _cli(self, *args):
        command = [
            os.environ["BLOOM_EVAL_PROJECTION_BIN"],
            "--home",
            os.environ["BLOOM_EVAL_PROJECTION_HOME"],
            "--connect",
            self.endpoint,
            "vfs",
            *args,
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=45, check=False
            )
        except subprocess.SubprocessError:
            raise OSError(f"public projection read timed out for {args[-1]}") from None
        if result.returncode:
            if (
                "not found" in result.stderr.lower()
                or "no such file" in result.stderr.lower()
            ):
                raise FileNotFoundError(args[-1])
            raise OSError(
                f"public projection read failed for {args[-1]} "
                f"(exit {result.returncode}): {result.stderr.strip()[-300:]}"
            )
        return result.stdout

    def read_json(self, path):
        text = (
            self._cli("cat", "/" + path)
            if self.endpoint
            else (self.root / path).read_text()
        )
        return json.loads(text)

    def entries(self, path):
        try:
            if not self.endpoint:
                return {
                    entry.name: "Dir" if entry.is_dir() else "File"
                    for entry in (self.root / path).iterdir()
                }
            result = {}
            for line in self._cli("ls", "/" + path).splitlines():
                name, _, kind = line.partition("\t")
                if (
                    not name
                    or "/" in name
                    or name in (".", "..")
                    or kind not in ("Dir", "File", "Symlink")
                ):
                    raise OSError(f"malformed public directory projection: {line!r}")
                result[name] = kind
            return result
        except FileNotFoundError:
            return {}

    def directories(self, path):
        return [name for name, kind in self.entries(path).items() if kind == "Dir"]
