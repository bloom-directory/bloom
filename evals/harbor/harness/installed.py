"""Stage-only access to the installed wallet, with attributable cleanup."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from .core import EvalError


class InstalledProjection:
    """Use the existing authenticated Machine connection, never its auth files."""

    def __init__(self, binary="bloom"):
        self.binary = binary

    def command(self, *args):
        try:
            result = subprocess.run(
                [self.binary, "vfs", *args],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise EvalError("installed Machine inventory unavailable") from None
        if result.returncode:
            raise EvalError(f"installed Machine inventory failed: {args[-1]}")
        return result.stdout

    def entries(self, path):
        entries = {}
        for line in self.command("ls", path).splitlines():
            fields = line.split("\t")
            if (
                len(fields) != 2
                or fields[1] not in ("File", "Dir")
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", fields[0])
                or fields[0] in (".", "..")
                or fields[0] in entries
            ):
                raise EvalError("malformed installed Machine inventory")
            entries[fields[0]] = fields[1]
        return entries

    def read_json(self, path):
        try:
            value = json.loads(self.command("cat", path))
        except ValueError:
            raise EvalError(f"malformed installed projection: {path}") from None
        if not isinstance(value, dict):
            raise EvalError(f"malformed installed projection: {path}")
        return value

    def cancel(self, pending_path):
        self.command("write", pending_path + "/cancel", "--data", "cancel")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class InstalledWallet:
    """A cooperative lock is not ownership: cleanup needs a trusted swap ID."""

    lock_path = Path("/tmp/bloom-harbor-installed-main.lock")
    terminal = frozenset(
        {
            "signed",
            "completed",
            "consumed",
            "cancelled",
            "canceled",
            "expired",
            "revoked",
            "exhausted",
            "failed",
            "derived",
        }
    )

    def __init__(self, reader=None, mount=Path("/home/user/bloom"), session_id=None):
        self.reader = reader or InstalledProjection()
        self.mount = mount
        self.before = None
        self.lock = None
        self.owned = {}
        self.session_id = session_id

    def directories(self, path):
        return sorted(
            name for name, kind in self.reader.entries(path).items() if kind == "Dir"
        )

    def snapshot(self):
        projection = self.reader.read_json("/wallets/main/projection.json")
        wallet = projection.get("wallet", {})
        if (
            projection.get("freshness") != "fresh"
            or wallet.get("wallet_id") != "main"
            or not str(wallet.get("policy_version", "")).isdigit()
            or not re.fullmatch(r"[0-9a-f]{64}", wallet.get("policy_digest", ""))
        ):
            raise EvalError("installed wallet has no fresh policy projection")
        accounts = [
            name
            for name in self.directories("/wallets/main")
            if re.fullmatch(r"0|[1-9][0-9]*", name)
        ]
        if "0" not in accounts:
            raise EvalError("installed account inventory is incomplete")
        outboxes = {}
        for account in accounts:
            chains = self.directories(f"/wallets/main/{account}/chains")
            if not chains:
                raise EvalError("installed chain inventory is incomplete")
            for chain in chains:
                root = f"/wallets/main/{account}/chains/{chain}/outbox"
                states = self.directories(root)
                if not {"pending", "sent", "failed"}.issubset(states):
                    raise EvalError("installed outbox inventory is incomplete")
                for state in states:
                    path = root + "/" + state
                    outboxes[path] = tuple(sorted(self.reader.entries(path)))
        requests = {}
        for root in ("/petal-signing-requests", "/petal-key-requests"):
            for name, kind in self.reader.entries(root).items():
                if kind != "File" or not re.fullmatch(r"[0-9a-f]{64}\.json", name):
                    raise EvalError("installed request inventory is incomplete")
                path = root + "/" + name
                record = self.reader.read_json(path)
                owner = record.get("wallet", record.get("wallet_id"))
                if not isinstance(owner, str):
                    raise EvalError("Petal request has no wallet attribution")
                requests[path] = record
        controls = {}
        for root in (
            "/wallets/main/policy-updates/pending",
            "/wallets/main/passkeys/enrollments",
        ):
            controls[root] = tuple(sorted(self.reader.entries(root)))
        approvals = {}
        for name in self.directories("/wallets/main/sealed-approvals"):
            path = f"/wallets/main/sealed-approvals/{name}/status.json"
            approvals[path] = self.reader.read_json(path)
        central = {}
        for name in self.directories("/outbox/pending"):
            record = self.reader.read_json(f"/outbox/pending/{name}/intent.json")
            if not isinstance(record.get("wallet"), str):
                raise EvalError("central pending work has no wallet attribution")
            central[name] = record
        recoveries = {}
        for root in ("/wallets/recoveries", "/wallets/registrations"):
            for name in self.directories(root):
                record = self.reader.read_json(f"{root}/{name}/status.json")
                if record.get("requested_name") == "main":
                    recoveries[f"{root}/{name}"] = record
        sessions = {}
        for account in accounts:
            root = f"/petals/near-intents/swaps/main/{account}"
            for name in self.directories(root):
                path = root + "/" + name
                sessions[path] = self.reader.read_json(path + "/status.json")
        return {
            "policy": (
                wallet["policy_version"],
                wallet["policy_digest"],
                wallet.get("wallet_revocation_epoch"),
            ),
            "outboxes": outboxes,
            "requests": requests,
            "controls": controls,
            "approvals": approvals,
            "central": central,
            "recoveries": recoveries,
            "sessions": sessions,
        }

    def refuse_pending(self, snapshot):
        if any(
            ids
            for path, ids in snapshot["outboxes"].items()
            if path.endswith("/pending")
        ):
            raise EvalError("main already has pending outbox work; preserving it")
        if any(snapshot["controls"].values()):
            raise EvalError("main already has pending policy or enrollment work")
        if any(record["wallet"] == "main" for record in snapshot["central"].values()):
            raise EvalError("main already has pending central work; preserving it")
        for record in snapshot["requests"].values():
            if (
                record.get("wallet", record.get("wallet_id")) == "main"
                and record.get("status") not in self.terminal
            ):
                raise EvalError("main already has pending Petal signing or key work")
        for record in snapshot["approvals"].values():
            if str(record.get("state", "")).lower() not in self.terminal | {"active"}:
                raise EvalError("main already has an unresolved approval ceremony")
        for record in snapshot["recoveries"].values():
            if str(record.get("ceremony_state", "")).lower() not in self.terminal:
                raise EvalError("main already has a wallet ceremony")
        for record in snapshot["sessions"].values():
            if record.get("state") not in {
                "quote_failed",
                "settled_success",
                "settled_refunded",
                "settled_failed",
                "abandoned",
            }:
                raise EvalError("main already has unresolved NEAR swap work")

    def begin(self):
        descriptor = os.open(
            self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        self.lock = os.fdopen(descriptor, "w")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.before = self.snapshot()
            self.refuse_pending(self.before)
        except BaseException:
            self.close()
            raise
        return self.before

    def attribute_near(self, session_path):
        """Bind cleanup to a new Petal-owned record read through host IPC."""
        if (
            self.before is None
            or not re.fullmatch(
                r"/petals/near-intents/swaps/main/0/[A-Za-z0-9_-]+", session_path
            )
            or session_path in self.before["sessions"]
            or session_path.rsplit("/", 1)[1] != self.session_id
        ):
            raise EvalError("trial swap has no new trusted record")
        status = self.reader.read_json(session_path + "/status.json")
        record = self.reader.read_json(session_path + "/outbox.json")
        root = record.get("outbox_root", "")
        entry_id = record.get("id", "")
        if (
            status.get("id") != session_path.rsplit("/", 1)[1]
            or status.get("wallet") != "main"
            or not re.fullmatch(r"/wallets/main/0/chains/[a-z0-9-]+/outbox", root)
            or root + "/pending" not in self.before["outboxes"]
            or not re.fullmatch(r"[A-Za-z0-9_-]+", entry_id)
            or record.get("state") != "pending"
            or record.get("tx_hash") is not None
        ):
            raise EvalError("trial swap has ambiguous outbox attribution")
        path = root + "/pending/" + entry_id
        intent = self.reader.read_json(path + "/intent.json")
        if (
            intent.get("id") != entry_id
            or intent.get("wallet") != "main"
            or intent.get("tx_hash") is not None
        ):
            raise EvalError("trial swap has ambiguous intent attribution")
        self.owned[path] = (session_path, digest(record), digest(intent))
        return path

    def assert_only_owned_changes(self, current, *, cancelled=False):
        if self.before is None:
            raise EvalError("installed trial has no baseline")
        for key in ("policy", "requests", "controls", "approvals", "recoveries"):
            if current[key] != self.before[key]:
                raise EvalError(
                    f"unrelated installed-wallet {key} changed; preserving work"
                )
        expected = dict(self.before["outboxes"])
        for path in self.owned:
            root, entry_id = path.rsplit("/", 1)
            if cancelled:
                root = root.removesuffix("/pending") + "/failed"
            expected[root] = tuple(sorted((*expected[root], entry_id)))
        if current["outboxes"] != expected:
            raise EvalError("unattributed outbox change; preserving all pending work")
        session_paths = {owned[0] for owned in self.owned.values()}
        if set(current["sessions"]) != set(self.before["sessions"]) | session_paths:
            raise EvalError("unattributed swap change; preserving all pending work")
        for path, record in self.before["sessions"].items():
            if current["sessions"].get(path) != record:
                raise EvalError("existing swap changed; preserving all pending work")
        central = dict(current["central"])
        for path in self.owned:
            entry_id = path.rsplit("/", 1)[1]
            name = "evm-" + entry_id
            record = central.get(name)
            if (
                not cancelled
                and record
                and record.get("id") == entry_id
                and record.get("wallet") == "main"
            ):
                del central[name]
        if central != self.before["central"]:
            raise EvalError(
                "unattributed central work changed; preserving all pending work"
            )

    def cancel_owned(self):
        current = self.snapshot()
        self.assert_only_owned_changes(current)
        # Validate every attribution before cancelling even the first entry.
        for path, (session, record_digest, intent_digest) in self.owned.items():
            if (
                digest(self.reader.read_json(session + "/outbox.json")) != record_digest
                or digest(self.reader.read_json(path + "/intent.json")) != intent_digest
            ):
                raise EvalError("trial ownership changed; preserving all pending work")
        for path in self.owned:
            self.reader.cancel(path)
        after = self.snapshot()
        self.assert_only_owned_changes(after, cancelled=True)
        for path in self.owned:
            terminal_path = path.replace("/outbox/pending/", "/outbox/failed/")
            intent = self.reader.read_json(terminal_path + "/intent.json")
            if intent.get("status") != "cancelled" or intent.get("tx_hash") is not None:
                raise EvalError("trial entry did not cancel without broadcast")

    def mounts(self):
        return [
            {
                "type": "bind",
                "source": str(self.mount),
                "target": "/bloom",
                "read_only": True,
            },
            {
                "type": "bind",
                "source": str(self.mount / "petals/near-intents/swaps/main/0/new"),
                "target": "/bloom/petals/near-intents/swaps/main/0/new",
                "read_only": False,
            },
        ]

    def close(self):
        if self.lock is not None:
            self.lock.close()
            self.lock = None
