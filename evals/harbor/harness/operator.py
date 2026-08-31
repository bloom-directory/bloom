"""Stateful, recoverable operator workflow for the live Hyperliquid eval."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .core import EvalError, run_eval
from .hyperliquid_order_cancel import (
    MAINNET_ACK,
    PACKAGE_HASH,
    WALLET,
    WALLET_ID,
    HyperliquidOrderCancelEval,
)

STATE_SCHEMA = "bloom.eval.operator-state.v1"
SUMMARY_SCHEMA = "bloom.eval.run-summary.v1"
STATE_PURPOSE = (
    "Protected local handoff for cold-start and repeat-agent Hyperliquid Harbor "
    "eval operation; contains identifiers and secret paths, never secret contents."
)
DEFAULT_STATE_RELATIVE = Path("evals/harbor/operator-state.json")
SAFE_HANDOFF_FIELDS = [
    "schema",
    "purpose",
    "handoff",
    "field_guide",
    "created_at",
    "updated_at",
    "wallet_id",
    "wallet_address",
    "package_hash",
    "model",
    "agent_name",
    "next_sign_count",
    "pending_policy_recovery",
    "paths",
    "lineage",
    "binaries",
    "recovery",
]
POLICY_KEYS = {
    "allowed_destinations",
    "allowed_petal_packages",
    "maximum_approval_lifetime_ms",
    "required_verifiers",
    "wallet_id",
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.new-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def handoff_metadata(store: StateStore) -> tuple[dict[str, Any], dict[str, str]]:
    return (
        {
            "agent_readable": True,
            "contains_secret_contents": False,
            "safe_fields": SAFE_HANDOFF_FIELDS,
            "required_secret_path_fields": ["paths.authenticator_seed_file"],
            "resume_instruction": (
                "Run status first; run recover when pending_policy_recovery is "
                "non-null or the protected policy backup exists; never guess a counter."
            ),
        },
        {
            "state_file": str(store.path),
            "policy_backup_file": str(store.backup_path),
            "summary_directory": str(store.summary_dir),
            "marker_field": "pending_policy_recovery",
        },
    )


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()

    @property
    def backup_path(self) -> Path:
        return self.path.with_name(f"{self.path.stem}.policy-backup.json")

    @property
    def summary_dir(self) -> Path:
        return self.path.parent / "harbor-summaries"

    def read(self) -> dict[str, Any]:
        try:
            metadata = self.path.lstat()
        except OSError as error:
            raise EvalError("operator state is unavailable; run init") from error
        if not stat.S_ISREG(metadata.st_mode) or self.path.is_symlink():
            raise EvalError("operator state must be a regular non-symlink file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise EvalError("operator state must have mode 0600")
        try:
            value = json.loads(self.path.read_bytes())
        except (OSError, json.JSONDecodeError) as error:
            raise EvalError("operator state is invalid") from error
        if not isinstance(value, dict) or value.get("schema") != STATE_SCHEMA:
            raise EvalError("operator state has an unsupported schema")
        if value.get("purpose") != STATE_PURPOSE:
            raise EvalError("operator state is missing its handoff purpose")
        handoff = value.get("handoff")
        if (
            not isinstance(handoff, dict)
            or handoff.get("contains_secret_contents") is not False
            or handoff.get("agent_readable") is not True
            or handoff.get("safe_fields") != SAFE_HANDOFF_FIELDS
            or handoff.get("required_secret_path_fields")
            != ["paths.authenticator_seed_file"]
        ):
            raise EvalError("operator state has invalid handoff metadata")
        recovery = value.get("recovery")
        _, expected_recovery = handoff_metadata(self)
        if recovery != expected_recovery:
            raise EvalError("operator state recovery locations are stale or invalid")
        field_guide = value.get("field_guide")
        if not isinstance(field_guide, dict) or any(
            not isinstance(field_guide.get(field), str)
            for field in (
                "paths",
                "lineage",
                "next_sign_count",
                "pending_policy_recovery",
            )
        ):
            raise EvalError("operator state is missing its field guide")
        return value

    def write(self, value: dict[str, Any]) -> None:
        atomic_write(self.path, canonical_json(value) + b"\n")

    def update_counter(self, next_counter: int) -> None:
        state = self.read()
        current = state.get("next_sign_count")
        if not isinstance(current, int) or next_counter <= current:
            raise EvalError("refusing a non-advancing authenticator counter update")
        state["next_sign_count"] = next_counter
        state["updated_at"] = datetime.now(UTC).isoformat()
        self.write(state)


def git_lineage(path: Path) -> dict[str, Any]:
    try:
        revision = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "-C", str(path), "status", "--porcelain"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvalError("could not determine a required source revision") from error
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise EvalError("a required source revision is invalid")
    return {"revision": revision, "dirty": dirty}


def petal_contract_revision(repo_root: Path) -> str:
    lock = (repo_root / "Cargo.lock").read_text()
    match = re.search(
        r'name = "bloom-petal-contract".*?source = "git\+[^#]+#([0-9a-f]{40})"',
        lock,
        re.DOTALL,
    )
    if match is None:
        raise EvalError("Bloom's Petal contract revision is absent from Cargo.lock")
    return match.group(1)


def discover_lineage(
    repo_root: Path, broker_repo: Path, signer_repo: Path, hyperliquid_repo: Path
) -> dict[str, Any]:
    return {
        "bloom": git_lineage(repo_root),
        "broker": git_lineage(broker_repo),
        "signer": git_lineage(signer_repo),
        "petal_contract_revision": petal_contract_revision(repo_root),
        "hyperliquid_petal": git_lineage(hyperliquid_repo),
    }


def safe_json(path: Path) -> Any:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise EvalError("required discovery input is not a regular file")
        return json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise EvalError("required discovery input is unavailable or invalid") from error


def expected_deny_policy(wallet_id: str) -> dict[str, Any]:
    return {
        "allowed_destinations": [],
        "allowed_petal_packages": [],
        "maximum_approval_lifetime_ms": 2_592_000_000,
        "required_verifiers": [],
        "wallet_id": wallet_id,
    }


def require_deny_policy(definition: HyperliquidOrderCancelEval, wallet_id: str) -> None:
    expected = expected_deny_policy(wallet_id)
    if definition._read_json(definition.wallet_root / "policy.json") != expected:
        raise EvalError("eval wallet policy is not deny-by-default")


def require_no_pending_owner_requests(
    definition: HyperliquidOrderCancelEval, wallet_id: str, package_hash: str
) -> None:
    for root_name, statuses in (
        ("petal-key-requests", {"awaiting_user"}),
        ("petal-signing-requests", {"awaiting_owner_approval"}),
    ):
        root = definition.bloom_mount / root_name
        try:
            names = os.listdir(root)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise EvalError("could not inspect pending owner requests") from error
        for name in names:
            if re.fullmatch(r"[0-9a-f]{64}\.json", name) is None:
                continue
            try:
                record = definition._read_json(root / name)
            except EvalError:
                continue
            if not isinstance(record, dict) or record.get("status") not in statuses:
                continue
            scope = record.get("scope")
            scoped_wallet = scope.get("wallet_id") if isinstance(scope, dict) else None
            scoped_package = (
                scope.get("package_hash") if isinstance(scope, dict) else None
            )
            if (record.get("wallet") == wallet_id or scoped_wallet == wallet_id) and (
                record.get("package_hash") == package_hash
                or scoped_package == package_hash
            ):
                raise EvalError(
                    "a matching owner ceremony is pending; reconcile it before init"
                )


def definition_env(state: dict[str, Any]) -> dict[str, str]:
    paths = state["paths"]
    return dict(
        os.environ,
        BLOOM_EVAL_WALLET=state["wallet_address"],
        BLOOM_EVAL_WALLET_ID=state["wallet_id"],
        BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH=state["package_hash"],
        BLOOM_EVAL_PETAL_OWNER_RECORD=paths["petal_owner_record"],
        BLOOM_EVAL_PETAL_STORE=paths["petal_store"],
        BLOOM_EVAL_PROVENANCE_CATALOG=paths["provenance_catalog"],
        BLOOM_EVAL_AUTHENTICATOR_SEED_FILE=paths["authenticator_seed_file"],
        BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT=str(state["next_sign_count"]),
        BLOOM_EVAL_DEBUG_DRIVER_BIN=paths["debug_driver"],
        BLOOM_EVAL_BLOOM_MOUNT=paths["bloom_mount"],
        BLOOM_EVAL_LOCK_FILE=paths["lock_file"],
        BLOOM_EVAL_JOBS_DIR=paths["jobs_dir"],
        BLOOM_EVAL_MAINNET_ACK=MAINNET_ACK,
        **(
            {"BLOOM_EVAL_AGENT_NAME": state["agent_name"]}
            if state.get("agent_name")
            else {}
        ),
    )


def redact(error: BaseException, state: dict[str, Any] | None) -> str:
    text = str(error)
    if state is None:
        return text
    sensitive = [state.get("wallet_address"), state.get("wallet_id")]
    sensitive.extend(state.get("paths", {}).values())
    for value in sorted(
        (v for v in sensitive if isinstance(v, str)), key=len, reverse=True
    ):
        text = text.replace(value, "[REDACTED]")
    text = re.sub(r"http://localhost:18734/ceremony/[A-Za-z0-9_-]+", "[REDACTED]", text)
    return text


class PolicyLifecycle:
    def __init__(
        self,
        store: StateStore,
        state: dict[str, Any],
        definition: HyperliquidOrderCancelEval,
    ) -> None:
        self.store = store
        self.state = state
        self.definition = definition
        self.policy_path = definition.wallet_root / "policy.json"

    def _read_policy(self) -> tuple[dict[str, Any], bytes]:
        value = self.definition._read_json(self.policy_path)
        if not isinstance(value, dict) or set(value) != POLICY_KEYS:
            raise EvalError("wallet policy has an unsupported shape")
        return value, canonical_json(value)

    def _persist_pending(self, operation_id: str | None, digest: str) -> None:
        current = self.store.read()
        existing = current.get("pending_policy_recovery")
        if existing is not None and not isinstance(existing, dict):
            raise EvalError("policy recovery marker is invalid")
        pending = {
            "operation_id": operation_id,
            "target_digest": digest,
        }
        if isinstance(existing, dict) and "backup_digest" in existing:
            pending["backup_digest"] = existing["backup_digest"]
        current["pending_policy_recovery"] = pending
        self.store.write(current)
        self.state = current

    def _bind_backup_digest(self, digest: str) -> None:
        current = self.store.read()
        pending = current.get("pending_policy_recovery")
        if pending is None:
            pending = {"operation_id": None, "target_digest": digest}
        elif not isinstance(pending, dict):
            raise EvalError("policy recovery marker is invalid")
        else:
            pending = dict(pending)
        bound_digest = pending.get("backup_digest")
        if bound_digest is not None:
            if not isinstance(bound_digest, str) or not re.fullmatch(
                r"[0-9a-f]{64}", bound_digest
            ):
                raise EvalError("protected policy backup digest is invalid")
            if bound_digest != digest:
                raise EvalError("protected policy backup digest does not match")
            return
        pending["backup_digest"] = digest
        current["pending_policy_recovery"] = pending
        self.store.write(current)
        self.state = current

    def _advance_counter(self, value: int) -> None:
        self.store.update_counter(value)
        self.state = self.store.read()
        self.definition.sign_count_value = str(value)

    def _wait_challenge(self, expected_digest: str) -> dict[str, Any] | None:
        challenge = (
            self.definition.wallet_root
            / "policy-updates/latest/approval_challenge.json"
        )
        for _ in range(120):
            try:
                value = self.definition._read_json(challenge, timeout=2)
            except EvalError:
                value = None
            if isinstance(value, dict):
                operation_id = value.get("operation_id")
                ceremony_url = value.get("ceremony_url")
                if (
                    value.get("proposed_policy_digest") == expected_digest
                    and isinstance(operation_id, str)
                    and isinstance(ceremony_url, str)
                ):
                    return value
                # `latest` may still project the preceding completed ceremony
                # while the asynchronous policy command publishes the new
                # challenge, or a matching prepared projection may not have a
                # live Broker ceremony URL yet. Never complete an incomplete
                # or mismatched ceremony; keep polling within this bound.
            time.sleep(0.5)
        return None

    def _wait_for_policy_commit(self, expected: bytes, previous: bytes) -> None:
        last_read_error: EvalError | None = None
        for attempt in range(60):
            try:
                _, current = self._read_policy()
            except EvalError as error:
                # Mounted policy reads can transiently fail while the
                # asynchronous command handler publishes the Broker-backed
                # projection. Retry only within this bounded commit window.
                last_read_error = error
            else:
                last_read_error = None
                if current == expected:
                    return
                if current != previous:
                    raise EvalError(
                        "wallet policy changed to unexpected canonical bytes"
                    )
            if attempt + 1 < 60:
                time.sleep(0.2)
        if last_read_error is not None:
            raise EvalError(
                "exact policy commit did not become visible after transient read failures"
            ) from last_read_error
        raise EvalError("exact policy commit did not become visible")

    def _commit_policy_replay(
        self, target: bytes, expected: bytes, previous: bytes
    ) -> None:
        last_read_error: EvalError | None = None
        for attempt in range(5):
            replay = self.definition._write_route(self.policy_path, target, 120)
            if replay.returncode == 0:
                self._wait_for_policy_commit(expected, previous)
                return
            # A failed mounted write is ambiguous: the asynchronous command
            # may still have reached Machine. Resolve that ambiguity from the
            # canonical Broker-backed projection before replaying exact bytes.
            try:
                _, current = self._read_policy()
            except EvalError as error:
                last_read_error = error
            else:
                last_read_error = None
                if current == expected:
                    return
                if current != previous:
                    raise EvalError(
                        "wallet policy changed to unexpected canonical bytes"
                    )
            if attempt + 1 < 5:
                time.sleep(0.5)
        if last_read_error is not None:
            raise EvalError(
                "completed policy replay remained ambiguous after transient read failures"
            ) from last_read_error
        raise EvalError(
            "completed policy could not be committed by bounded byte-identical replay"
        )

    def _matching_pending_policy_updates(self, expected_digest: str) -> list[str]:
        pending_root = self.definition.wallet_root / "policy-updates/pending"
        try:
            action_dirs = sorted(path for path in pending_root.iterdir() if path.is_dir())
        except FileNotFoundError:
            return []
        except OSError as error:
            raise EvalError("could not enumerate pending policy updates") from error
        matches: list[str] = []
        for action_dir in action_dirs:
            try:
                challenge = self.definition._read_json(
                    action_dir / "approval_challenge.json", timeout=2
                )
            except EvalError as error:
                raise EvalError(
                    "could not reconcile a pending policy-update projection"
                ) from error
            if not isinstance(challenge, dict):
                raise EvalError("pending policy-update challenge is invalid")
            operation_id = challenge.get("operation_id")
            if not isinstance(operation_id, str) or operation_id != action_dir.name:
                raise EvalError("pending policy-update operation identity is invalid")
            if challenge.get("proposed_policy_digest") == expected_digest:
                matches.append(operation_id)
        return matches

    def _policy_update_status(self, state: str, operation_id: str) -> dict[str, Any]:
        try:
            status = self.definition._read_json(
                self.definition.wallet_root
                / "policy-updates"
                / state
                / operation_id
                / "status.json",
                timeout=2,
            )
        except (EvalError, OSError) as error:
            raise EvalError(
                f"stored policy-update operation has no {state} projection"
            ) from error
        if (
            not isinstance(status, dict)
            or status.get("action_id") != operation_id
            or status.get("state") != state
        ):
            raise EvalError(f"stored {state} policy-update projection is invalid")
        return status

    def _reconcile_succeeded_policy_update(
        self,
        operation_id: str,
        target: bytes,
        expected: bytes,
        previous: bytes,
    ) -> None:
        for attempt in range(5):
            replay = self.definition._write_route(self.policy_path, target, 120)
            confirmation_attempts = 10 if replay.returncode == 0 else 1
            for confirmation_attempt in range(confirmation_attempts):
                try:
                    confirmed = self._policy_update_status("confirmed", operation_id)
                except EvalError:
                    confirmed = None
                if confirmed is not None:
                    if confirmed.get("ceremony_state") != "SUCCEEDED":
                        raise EvalError(
                            "reconciled policy-update projection is not successful"
                        )
                    self._wait_for_policy_commit(expected, previous)
                    return
                if confirmation_attempt + 1 < confirmation_attempts:
                    time.sleep(0.2)
            if replay.returncode == 0:
                raise EvalError(
                    "policy replay succeeded without a confirmed operation projection"
                )
            if attempt + 1 < 5:
                time.sleep(0.5)
        raise EvalError("succeeded policy update could not be reconciled")

    def _resolve_pending_policy_update(
        self, target: bytes, expected: bytes, previous: bytes
    ) -> None:
        pending = self.store.read().get("pending_policy_recovery")
        if not isinstance(pending, dict):
            raise EvalError("policy recovery marker is invalid")
        expected_digest = pending.get("target_digest")
        operation_id = pending.get("operation_id")
        if not isinstance(expected_digest, str):
            raise EvalError("policy recovery target digest is invalid")
        if operation_id is not None and not isinstance(operation_id, str):
            raise EvalError("policy recovery operation ID is invalid")

        matches = self._matching_pending_policy_updates(expected_digest)
        if operation_id is None:
            if len(matches) > 1:
                raise EvalError("multiple matching pending policy updates require recovery")
            if not matches:
                return
            operation_id = matches[0]
            self._persist_pending(operation_id, expected_digest)
        elif operation_id not in matches:
            # A terminal cancellation is safe because it never installed the
            # authority. A confirmed operation is also safe to restore over:
            # its ceremony has already been consumed, so it cannot later
            # broaden authority again after the deny policy is committed.
            try:
                failed = self._policy_update_status("failed", operation_id)
            except EvalError:
                failed = None
            if isinstance(failed, dict) and failed.get("ceremony_state") in {
                "CANCELLED",
                "EXPIRED",
                "FAILED",
            }:
                return
            try:
                confirmed = self._policy_update_status("confirmed", operation_id)
            except EvalError as error:
                raise EvalError(
                    "stored policy-update operation is neither pending nor terminal"
                ) from error
            if (
                confirmed.get("ceremony_state") != "SUCCEEDED"
            ):
                raise EvalError("stored confirmed policy-update projection is invalid")
            return

        for attempt in range(20):
            try:
                status = self._policy_update_status("pending", operation_id)
            except EvalError as pending_error:
                try:
                    failed = self._policy_update_status("failed", operation_id)
                except EvalError:
                    failed = None
                if isinstance(failed, dict) and failed.get("ceremony_state") in {
                    "CANCELLED",
                    "EXPIRED",
                    "FAILED",
                }:
                    return
                try:
                    confirmed = self._policy_update_status("confirmed", operation_id)
                except EvalError:
                    confirmed = None
                if (
                    isinstance(confirmed, dict)
                    and confirmed.get("ceremony_state") == "SUCCEEDED"
                ):
                    return
                raise pending_error
            ceremony_state = status.get("ceremony_state")
            if ceremony_state == "SUCCEEDED" and status.get("status") == "ready_to_commit":
                self._reconcile_succeeded_policy_update(
                    operation_id, target, expected, previous
                )
                return
            if ceremony_state == "AWAITING_USER":
                cancel_path = (
                    self.definition.wallet_root
                    / "policy-updates/pending"
                    / operation_id
                    / "cancel"
                )
                cancelled = self.definition._write_route(cancel_path, b"cancel\n", 30)
                if cancelled.returncode != 0:
                    # Completion can race cancellation. Re-read the
                    # Broker-backed projection and reconcile it on this same
                    # recovery attempt if it became successful.
                    if attempt + 1 < 20:
                        time.sleep(0.25)
                        continue
                    raise EvalError(
                        "policy-update cancellation was not confirmed by the mount"
                    )
                failed = self._policy_update_status("failed", operation_id)
                if failed.get("ceremony_state") != "CANCELLED":
                    raise EvalError("policy-update cancellation projection is invalid")
                if operation_id in self._matching_pending_policy_updates(expected_digest):
                    raise EvalError("cancelled policy update remains live")
                return
            if ceremony_state in {"CANCELLED", "EXPIRED", "FAILED"}:
                failed = self._policy_update_status("failed", operation_id)
                if failed.get("ceremony_state") != ceremony_state:
                    raise EvalError("terminal policy-update projection is invalid")
                return
            if attempt + 1 < 20:
                time.sleep(0.25)
        raise EvalError("pending policy update did not become recoverable")

    def apply(self, target: bytes) -> None:
        try:
            expected = json.loads(target)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as error:
            raise EvalError("policy update target is invalid JSON") from error
        if not isinstance(expected, dict) or set(expected) != POLICY_KEYS:
            raise EvalError("policy update target has an unsupported shape")
        expected_bytes = canonical_json(expected)
        if target.rstrip(b"\n") != expected_bytes:
            raise EvalError("policy update target is not canonical JSON")
        _, previous_bytes = self._read_policy()
        if previous_bytes == expected_bytes:
            return
        digest = hashlib.sha256(expected_bytes).hexdigest()
        self.definition._write_route(self.policy_path, target, 120)
        challenge = self._wait_challenge(digest)
        if challenge is None:
            _, current_bytes = self._read_policy()
            if current_bytes == expected_bytes:
                return
            raise EvalError("no matching policy-update ceremony was published")
        operation_id = challenge.get("operation_id")
        ceremony_url = challenge.get("ceremony_url")
        if not isinstance(operation_id, str) or not isinstance(ceremony_url, str):
            raise EvalError("policy-update challenge is incomplete")
        self._persist_pending(operation_id, digest)
        counter = int(self.store.read()["next_sign_count"])
        # Persist the next unused counter before the assertion can leave this
        # process. A timeout or interruption after Broker accepts it must not
        # allow a later recovery attempt to reuse the consumed value.
        self._advance_counter(counter + 1)
        try:
            completed = subprocess.run(
                [
                    str(self.definition.driver),
                    "complete",
                    ceremony_url,
                    "--authenticator-seed-file",
                    str(self.definition.seed_file),
                    "--sign-count",
                    str(counter),
                ],
                check=False,
                capture_output=True,
                timeout=45,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(
                f"policy ceremony transport failed at counter {counter}; "
                f"next candidate is {counter + 1}"
            ) from error
        if completed.returncode != 0:
            raise EvalError(
                f"policy ceremony failed at counter {counter}; "
                f"next candidate is {counter + 1}"
            )
        self._commit_policy_replay(target, expected_bytes, previous_bytes)

    def activate(self) -> None:
        original, original_bytes = self._read_policy()
        expected_original = expected_deny_policy(self.state["wallet_id"])
        if original != expected_original:
            raise EvalError("eval wallet is not deny-by-default before activation")
        atomic_write(self.store.backup_path, original_bytes + b"\n")
        self._bind_backup_digest(hashlib.sha256(original_bytes).hexdigest())
        active = dict(original, allowed_petal_packages=[self.state["package_hash"]])
        active_bytes = canonical_json(active)
        self._persist_pending(None, hashlib.sha256(active_bytes).hexdigest())
        self.apply(active_bytes)

    def restore(self) -> None:
        try:
            metadata = self.store.backup_path.lstat()
        except OSError as error:
            raise EvalError("protected policy backup is missing") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise EvalError("protected policy backup is unsafe")
        try:
            raw_backup = self.store.backup_path.read_bytes()
        except OSError as error:
            raise EvalError("protected policy backup is unreadable") from error
        backup = raw_backup.rstrip(b"\n")
        if raw_backup not in (backup, backup + b"\n"):
            raise EvalError("protected policy backup is not canonical JSON")
        try:
            backup_value = json.loads(backup)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise EvalError("protected policy backup is invalid JSON") from error
        if (
            backup_value != expected_deny_policy(self.state["wallet_id"])
            or canonical_json(backup_value) != backup
        ):
            raise EvalError("protected policy backup is not the expected policy")
        self._bind_backup_digest(hashlib.sha256(backup).hexdigest())
        pending = self.store.read().get("pending_policy_recovery")
        if not isinstance(pending, dict):
            raise EvalError("policy recovery marker is invalid")
        target_digest = pending.get("target_digest")
        if not isinstance(target_digest, str):
            raise EvalError("policy recovery target digest is invalid")
        active = canonical_json(
            dict(backup_value, allowed_petal_packages=[self.state["package_hash"]])
        )
        active_digest = hashlib.sha256(active).hexdigest()
        backup_digest = hashlib.sha256(backup).hexdigest()
        if target_digest == active_digest:
            recovery_target, recovery_previous = active, backup
        elif target_digest == backup_digest:
            recovery_target, recovery_previous = backup, active
        else:
            raise EvalError("policy recovery target digest is not reconstructible")
        self._resolve_pending_policy_update(
            recovery_target,
            recovery_target,
            recovery_previous,
        )
        self.apply(backup)
        pending = self.store.read().get("pending_policy_recovery")
        if not isinstance(pending, dict):
            raise EvalError("policy recovery marker disappeared before verification")
        target_digest = pending.get("target_digest")
        if not isinstance(target_digest, str):
            raise EvalError("policy recovery target digest is invalid")
        if self._matching_pending_policy_updates(target_digest):
            raise EvalError("matching policy-update challenge remains live after recovery")
        current = self.store.read()
        current["pending_policy_recovery"] = None
        self.store.write(current)
        self.store.backup_path.unlink()
        self.state = current


def initialize(args: argparse.Namespace, repo_root: Path) -> None:
    store = StateStore(args.state)
    if store.backup_path.exists():
        raise EvalError(
            "policy recovery is pending; init cannot replace operator state"
        )
    if store.path.exists() and store.read().get("pending_policy_recovery") is not None:
        raise EvalError(
            "policy recovery is pending; init cannot replace operator state"
        )
    mount = args.mount.expanduser().resolve()
    triad_root = args.triad_root.expanduser().resolve()
    machine_home = triad_root / "state/machine"
    owner_record = machine_home / "petals/store/owners/hyperliquid.json"
    petal_store = machine_home / "petals/store"
    catalog = triad_root / "config/provenance-catalog.json"
    if not os.path.ismount(mount):
        raise EvalError("configured Bloom path is not an active mount")
    addresses = safe_json(mount / "wallets" / args.wallet_id / "addresses.json")
    owner = addresses.get("owner") if isinstance(addresses, dict) else None
    if not isinstance(owner, str) or WALLET.fullmatch(owner.lower()) is None:
        raise EvalError("wallet owner projection is invalid")
    if (
        addresses.get("wallet") != args.wallet_id
        or addresses.get("policy_status") != "broker_verified"
    ):
        raise EvalError(
            "wallet projection is not Broker-verified for the selected wallet"
        )
    owner_data = safe_json(owner_record)
    package_hash = owner_data.get("hash") if isinstance(owner_data, dict) else None
    if (
        owner_data.get("name") != "hyperliquid"
        or not isinstance(package_hash, str)
        or PACKAGE_HASH.fullmatch(package_hash) is None
    ):
        raise EvalError("installed Hyperliquid owner record is invalid")
    broker_repo = args.broker_repo.expanduser().resolve()
    signer_repo = args.signer_repo.expanduser().resolve()
    hyperliquid_repo = args.hyperliquid_repo.expanduser().resolve()
    lineage = discover_lineage(repo_root, broker_repo, signer_repo, hyperliquid_repo)
    binaries = {}
    for name, path in {
        "bloom": repo_root / "target/debug/bloom",
        "broker": broker_repo / "target/debug/bloom-broker",
        "signer": signer_repo / "target/debug/bloom-signer",
        "debug_driver": args.debug_driver.expanduser().resolve(),
    }.items():
        if not path.is_file():
            raise EvalError(f"required {name} binary is unavailable")
        binaries[name] = {"path": str(path), "sha256": sha256_file(path)}
    if not WALLET_ID.fullmatch(args.wallet_id):
        raise EvalError("wallet id has an invalid shape")
    handoff, recovery = handoff_metadata(store)
    state = {
        "schema": STATE_SCHEMA,
        "purpose": STATE_PURPOSE,
        "handoff": handoff,
        "field_guide": {
            "paths": (
                "Absolute local paths for the triad, mount, source repositories, "
                "artifacts, and secret material; paths are not secret contents."
            ),
            "lineage": (
                "Exact source revisions and dirty-state observations captured at init."
            ),
            "next_sign_count": (
                "First authenticator counter candidate that has not been reused."
            ),
            "pending_policy_recovery": (
                "Null only when no package-policy restoration is pending."
            ),
            "agent_name": (
                "Optional stable venue agent name override; null uses deterministic derivation."
            ),
            "recovery": (
                "Protected state, policy-backup, summary, and marker locations."
            ),
        },
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
        "wallet_id": args.wallet_id,
        "wallet_address": owner.lower(),
        "package_hash": package_hash,
        "model": args.model,
        "agent_name": args.agent_name,
        "next_sign_count": args.sign_count,
        "pending_policy_recovery": None,
        "paths": {
            "triad_root": str(triad_root),
            "bloom_mount": str(mount),
            "petal_owner_record": str(owner_record),
            "petal_store": str(petal_store),
            "provenance_catalog": str(catalog),
            "authenticator_seed_file": str(args.seed_file.expanduser().resolve()),
            "debug_driver": str(args.debug_driver.expanduser().resolve()),
            "lock_file": str(store.path.parent / "harbor-mainnet.lock"),
            "jobs_dir": str(repo_root / "evals/harbor/jobs"),
            "broker_repo": str(broker_repo),
            "signer_repo": str(signer_repo),
            "hyperliquid_repo": str(hyperliquid_repo),
        },
        "lineage": lineage,
        "binaries": binaries,
        "recovery": recovery,
    }
    definition = HyperliquidOrderCancelEval(repo_root, definition_env(state))
    definition.preauthorization_preflight()
    require_deny_policy(definition, args.wallet_id)
    require_no_pending_owner_requests(definition, args.wallet_id, package_hash)
    definition._require_empty_wallet()
    store.write(state)
    print(
        "Bloom Harbor operator state initialized; protected state and prerequisites verified"
    )


def validate_lineage(state: dict[str, Any], repo_root: Path) -> None:
    paths = state["paths"]
    actual = discover_lineage(
        repo_root,
        Path(paths["broker_repo"]),
        Path(paths["signer_repo"]),
        Path(paths["hyperliquid_repo"]),
    )
    if actual != state["lineage"]:
        raise EvalError("source lineage changed; re-run init before creating authority")
    for name, expected in state["binaries"].items():
        try:
            actual_digest = sha256_file(Path(expected["path"]))
        except OSError as error:
            raise EvalError(
                f"{name} binary is unavailable; re-run init before creating authority"
            ) from error
        if actual_digest != expected["sha256"]:
            raise EvalError(
                f"{name} binary changed; re-run init before creating authority"
            )


def status(store: StateStore, repo_root: Path) -> None:
    state = store.read()
    checks: dict[str, bool] = {}
    checks["policy_recovery_clear"] = (
        state.get("pending_policy_recovery") is None and not store.backup_path.exists()
    )
    checks["mount_active"] = os.path.ismount(state["paths"]["bloom_mount"])
    try:
        validate_lineage(state, repo_root)
        checks["lineage_current"] = True
    except EvalError:
        checks["lineage_current"] = False
    if checks["lineage_current"]:
        try:
            definition = HyperliquidOrderCancelEval(repo_root, definition_env(state))
            definition.preauthorization_preflight()
            require_deny_policy(definition, state["wallet_id"])
            checks["preauthorization"] = True
            checks["deny_by_default"] = True
        except EvalError:
            checks["preauthorization"] = False
            checks["deny_by_default"] = False
    else:
        checks["preauthorization"] = False
        checks["deny_by_default"] = False
    report = {
        "schema": "bloom.eval.operator-status.v1",
        "ready": all(checks.values()),
        "model": state["model"],
        "next_sign_count_set": isinstance(state.get("next_sign_count"), int),
        "checks": checks,
        "lineage": state["lineage"],
    }
    print(json.dumps(report, sort_keys=True, indent=2))


def result_summary(result: Any) -> dict[str, Any]:
    stats = result.stats
    rewards: dict[str, Any] = {}
    if result.trial_results and result.trial_results[0].verifier_result is not None:
        rewards = dict(result.trial_results[0].verifier_result.rewards)
    return {
        "rewards": rewards,
        "errored_trials": stats.n_errored_trials,
        "cancelled_trials": stats.n_cancelled_trials,
        "retries": getattr(stats, "n_retried_trials", 0),
    }


def run_or_recover(
    args: argparse.Namespace, repo_root: Path, recover_only: bool
) -> None:
    store = StateStore(args.state)
    state = store.read()
    if args.ack != MAINNET_ACK:
        raise EvalError(f"explicit acknowledgement must equal {MAINNET_ACK}")
    lock_path = Path(state["paths"]["lock_file"])
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    started_total = time.monotonic()
    timings: dict[str, float] = {}
    outcome = "failed"
    result: Any | None = None
    error_text: str | None = None
    definition = HyperliquidOrderCancelEval(
        repo_root,
        definition_env(state),
        counter_committed=store.update_counter,
    )
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise EvalError(
                "another Hyperliquid eval holds the operator lock"
            ) from error
        policy = PolicyLifecycle(store, state, definition)
        try:
            if recover_only:
                if not store.backup_path.exists():
                    raise EvalError("no interrupted policy lifecycle requires recovery")
                phase = time.monotonic()
                policy.restore()
                timings["policy_restoration_seconds"] = time.monotonic() - phase
                outcome = "recovered"
            else:
                if store.backup_path.exists() or state.get("pending_policy_recovery"):
                    raise EvalError(
                        "interrupted policy lifecycle exists; run recover first"
                    )
                # Source and binary lineage protect a new eval run, but are not
                # prerequisites for restoring the exact digest-bound policy
                # backup after a branch switch or rebuild.
                validate_lineage(state, repo_root)
                try:
                    phase = time.monotonic()
                    try:
                        policy.activate()
                    finally:
                        timings["policy_activation_seconds"] = (
                            time.monotonic() - phase
                        )
                    refreshed = store.read()
                    definition.sign_count_value = str(refreshed["next_sign_count"])
                    result = run_eval(
                        definition,
                        state["model"],
                        acquire_lock=False,
                        phase_timings=timings,
                    )
                finally:
                    if store.backup_path.exists():
                        phase = time.monotonic()
                        try:
                            policy.restore()
                        finally:
                            timings["policy_restoration_seconds"] = (
                                time.monotonic() - phase
                            )
                outcome = "passed"
        except BaseException as error:
            error_text = redact(error, state)
            raise
        finally:
            timings.update(definition.phase_timings)
            timings["total_seconds"] = time.monotonic() - started_total
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            summary = {
                "schema": SUMMARY_SCHEMA,
                "finished_at": datetime.now(UTC).isoformat(),
                "outcome": outcome,
                "model": state["model"],
                "harbor_version": os.environ.get("HARBOR_VERSION", "0.21.0"),
                "package_hash": state["package_hash"],
                "lineage": state["lineage"],
                "timings": {key: round(value, 6) for key, value in timings.items()},
                "result": result_summary(result) if result is not None else None,
                "error": error_text,
                "final_state": {
                    "open_orders": 0 if outcome == "passed" else None,
                    "positions": 0 if outcome == "passed" else None,
                    "session_stopped": True if outcome == "passed" else None,
                    "policy_restored": not store.backup_path.exists(),
                    "counter_reconciled": store.read().get("pending_policy_recovery")
                    is None,
                },
            }
            atomic_write(
                store.summary_dir / f"hyperliquid-{stamp}.json",
                canonical_json(summary) + b"\n",
            )
    print(
        "Bloom Harbor operator recovery completed"
        if recover_only
        else "Bloom Harbor eval completed; timed summary written"
    )


def parser(repo_root: Path) -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Operate the full Bloom Hyperliquid Harbor eval safely"
    )
    commands = value.add_subparsers(dest="command", required=True)
    default_state = repo_root / DEFAULT_STATE_RELATIVE
    init = commands.add_parser(
        "init", help="discover and validate protected local eval state"
    )
    init.add_argument("--state", type=Path, default=default_state)
    init.add_argument("--triad-root", type=Path, required=True)
    init.add_argument("--mount", type=Path, required=True)
    init.add_argument("--wallet-id", required=True)
    init.add_argument("--seed-file", type=Path, required=True)
    init.add_argument("--sign-count", type=int, required=True)
    init.add_argument("--model", choices=("claude", "codex"), required=True)
    init.add_argument("--agent-name")
    init.add_argument(
        "--broker-repo", type=Path, default=repo_root.parent / "bloom-broker"
    )
    init.add_argument(
        "--signer-repo", type=Path, default=repo_root.parent / "bloom-signer"
    )
    init.add_argument(
        "--hyperliquid-repo",
        type=Path,
        default=repo_root.parent / "bloom-petal-hyperliquid",
    )
    init.add_argument(
        "--debug-driver",
        type=Path,
        default=repo_root.parent
        / "bloom-broker/target/debug/bloom-broker-debug-driver",
    )
    status_command = commands.add_parser(
        "status", help="report read-only readiness without external calls"
    )
    status_command.add_argument("--state", type=Path, default=default_state)
    for name in ("run", "recover"):
        command = commands.add_parser(name)
        command.add_argument("--state", type=Path, default=default_state)
        command.add_argument("--ack", required=True)
    return value


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(
        os.environ.get("BLOOM_EVAL_REPO_ROOT", Path(__file__).resolve().parents[3])
    ).resolve()
    args = parser(repo_root).parse_args(argv)
    state: dict[str, Any] | None = None
    try:
        if args.command == "init":
            state = {
                "wallet_id": args.wallet_id,
                "paths": {
                    "triad_root": str(args.triad_root),
                    "bloom_mount": str(args.mount),
                    "authenticator_seed_file": str(args.seed_file),
                    "debug_driver": str(args.debug_driver),
                    "broker_repo": str(args.broker_repo),
                    "signer_repo": str(args.signer_repo),
                    "hyperliquid_repo": str(args.hyperliquid_repo),
                },
            }
            initialize(args, repo_root)
        elif args.command == "status":
            status(StateStore(args.state), repo_root)
        else:
            state = StateStore(args.state).read()
            run_or_recover(args, repo_root, args.command == "recover")
    except (EvalError, KeyboardInterrupt) as error:
        print(f"Bloom Harbor operator: {redact(error, state)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
