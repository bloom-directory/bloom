#!/usr/bin/env python3
"""Exercise real Machine/Broker binaries with disposable developer enrollment.

Build all inputs with triad-dev-harness; supply their absolute paths through
BLOOM_PM80_{MACHINE,BROKER,RELEASED_MACHINE,RELEASED_BROKER,SIGNER}_BIN.
Released inputs must use the v0.4.0 compatibility revisions. This is diagnostic
process evidence, not production bundle/containment conformance or owner consent.
The launcher adapter retains its templates/runtime rather than deleting them.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import sqlite3
import subprocess
import tempfile
import time


def binary(name):
    path = Path(os.environ[f"BLOOM_PM80_{name}_BIN"]).resolve(strict=True)
    if not os.access(path, os.X_OK):
        raise ValueError(f"not executable: {path}")
    return path


def available_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def run_case(evidence, launcher, name, machine, broker, signer, compatible):
    root = evidence / name
    root.mkdir(mode=0o700)
    config = root / "machine.toml"
    # A valid isolated chain directory, without external RPC or credentials.
    config.write_text('[chains.ethereum]\nname = "ethereum"\nchain_id = 1\n'
                      'rpc_urls = ["http://127.0.0.1:1"]\nallow_broadcast = false\n')
    config.chmod(0o600)
    endpoint, ready = root / "m.sock", root / "ready"
    log_dir = root / "logs"
    env = os.environ.copy()
    env.update({
        "BLOOM_INTEGRATION_MACHINE_BIN": str(machine),
        "BLOOM_INTEGRATION_BROKER_BIN": str(broker),
        "BLOOM_INTEGRATION_SIGNER_BIN": str(signer),
        "BLOOM_TRIAD_DEV_MACHINE_CONFIG": str(config),
        "BLOOM_TRIAD_DEV_BUILD_PETALS": "0",
        "BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE": "0",
    })
    command = ["bash", str(launcher), "--developer-root", str(root),
               "--machine-socket", str(endpoint), "--log-dir", str(log_dir),
               "--ready-file", str(ready), "--ceremony-port", str(available_port()),
               "--remote-upstream-port", str(available_port())]
    with (root / "launcher.log").open("w") as output:
        child = subprocess.Popen(command, env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 90
            refused_at_startup = False
            while not ready.exists():
                if not compatible:
                    logs = "".join(path.read_text() for path in
                                   (root / "launcher.log", log_dir / "machine.log") if path.exists())
                    refusal = re.search(
                        r'method["=: ]+broker\.readiness.*protocol_error_code["=: ]+UNSUPPORTED_VERSION', logs)
                    if refusal:
                        (root / "negotiation.log").write_text(refusal.group(0) + "\n")
                        refused_at_startup = True
                        break
                if child.poll() is not None:
                    raise RuntimeError(f"{name}: launcher exited; inspect {root}/launcher.log")
                if time.monotonic() > deadline:
                    raise TimeoutError(f"{name}: readiness timeout; inspect {log_dir}")
                time.sleep(0.2)
            request_exit = None
            if not refused_at_startup:
                request = subprocess.run(
                    [str(machine), "--home", str(root / "state/machine"), "--connect",
                     f"unix:{endpoint}", "vfs", "ls", "/wallets"],
                    env=env, capture_output=True, text=True, timeout=20,
                )
                request_exit = request.returncode
                (root / "request.log").write_text(request.stdout + request.stderr)
                if compatible and request_exit:
                    raise RuntimeError(f"{name}: compatible wallet read failed")
                if not compatible:
                    raise AssertionError(f"{name}: incompatible pair reached readiness")
        finally:
            if child.poll() is None:
                child.terminate()  # Launcher stops only its recorded service processes/units.
            child.wait(timeout=30)

    counts = {}
    required = {"policies", "pending_petal_key_scopes", "petal_key_scopes",
                "approvals", "operations", "ceremony_sessions"}
    seen = set()
    # Broker consolidates legacy authority.db into its journal-backed store.
    for database in (root / "state/broker").glob("*.db"):
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as store:
            tables = {row[0] for row in store.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            for table in sorted(required & tables):
                seen.add(table)
                counts[f"{database.name}:{table}"] = store.execute(
                    f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    if seen != required or any(counts.values()):
        raise AssertionError(f"{name}: unexpected authority mutation: {counts}")
    return {"name": name, "compatible": compatible, "wallet_read_exit": request_exit,
            "refused_at_startup": refused_at_startup,
            "authority_rows": counts}


def main():
    source = Path(__file__).resolve().parent.parent
    evidence = Path(tempfile.mkdtemp(prefix="pm80-wire-", dir="/tmp"))
    original = (source / "scripts/triad-dev-launch.sh").read_text()
    # Keep service/configuration behavior intact. Preserve disposable evidence
    # instead of invoking either recursive forced cleanup in the stock launcher.
    assert original.count('rm -rf -- "$template_dir"') == 1
    assert original.count('rm -rf -- "$runtime_dir"') == 1
    adapted = original.replace('rm -rf -- "$template_dir"', ': "retained templates"')
    adapted = adapted.replace('rm -rf -- "$runtime_dir"', ': "retained runtime"')
    root_line = 'repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"'
    assert adapted.count(root_line) == 1
    adapted = adapted.replace(root_line, "repo_root=" + shlex.quote(str(source)))
    launcher = evidence / "launcher.sh"
    launcher.write_text(adapted)
    bins = {name: binary(name) for name in
            ("MACHINE", "BROKER", "RELEASED_MACHINE", "RELEASED_BROKER", "SIGNER")}
    records = []
    for name, machine, broker, compatible in (
        ("new-pair", bins["MACHINE"], bins["BROKER"], True),
        ("old-machine", bins["RELEASED_MACHINE"], bins["BROKER"], False),
        ("old-broker", bins["MACHINE"], bins["RELEASED_BROKER"], False),
    ):
        records.append(run_case(evidence, launcher, name, machine, broker, bins["SIGNER"], compatible))
    result = {"diagnostic_features": ["triad-dev-harness"], "cases": records,
              "binary_sha256": {name: hashlib.file_digest(path.open("rb"), "sha256").hexdigest()
                                for name, path in bins.items()}}
    (evidence / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Passed; disposable evidence retained at {evidence}")


if __name__ == "__main__":
    main()
