"""Host-side lifecycle for the bounded Hyperliquid order/cancel evaluation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .core import EvalDefinition, EvalError, EvalRunContext

MAINNET_ACK = "PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD"
CEREMONY_URL = re.compile(r"http://localhost:18734/ceremony/[A-Za-z0-9_-]{43}")
WALLET = re.compile(r"0x[0-9a-f]{40}")
WALLET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
PACKAGE_HASH = re.compile(r"[0-9a-f]{64}")
LINEAGE_ID = re.compile(r"pln1_[a-z2-7]{52}")
BASE64URL = re.compile(r"[A-Za-z0-9_-]+")
HYPERLIQUID_SESSION_ROUTE = "[network]/agent_sessions/[wallet]/new.json"
ACTION_FILES = ("order.json", "cancel.json", "update_leverage.json", "cancel_all")


def session_key_slot(session_id: str) -> str:
    digest = hashlib.sha256(
        b"bloom-hyperliquid-session-key/v1\0" + session_id.encode()
    ).hexdigest()
    return f"hyperliquid-{digest[:52]}"


class HyperliquidOrderCancelEval(EvalDefinition):
    name = "hyperliquid-order-cancel"

    def __init__(self, repo_root: Path, environ: dict[str, str] | None = None) -> None:
        self.repo_root = repo_root.resolve()
        self.env = dict(os.environ if environ is None else environ)
        self.wallet = self.env.get("BLOOM_EVAL_WALLET", "")
        self.wallet_id = self.env.get("BLOOM_EVAL_WALLET_ID", "")
        self.package_hash = self.env.get("BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH", "")
        self.owner_record_value = self.env.get("BLOOM_EVAL_PETAL_OWNER_RECORD", "")
        self.owner_record = Path(self.owner_record_value)
        self.petal_store_value = self.env.get("BLOOM_EVAL_PETAL_STORE", "")
        self.petal_store = Path(self.petal_store_value)
        self.provenance_catalog_value = self.env.get(
            "BLOOM_EVAL_PROVENANCE_CATALOG", ""
        )
        self.provenance_catalog = Path(self.provenance_catalog_value)
        self.bloom_mount = Path(self.env.get("BLOOM_EVAL_BLOOM_MOUNT", "/bloom"))
        self.driver = Path(
            self.env.get(
                "BLOOM_EVAL_DEBUG_DRIVER_BIN",
                str(
                    self.repo_root.parent
                    / "bloom-broker/target/debug/bloom-broker-debug-driver"
                ),
            )
        )
        self.seed_file_value = self.env.get("BLOOM_EVAL_AUTHENTICATOR_SEED_FILE", "")
        self.seed_file = Path(self.seed_file_value)
        self.sign_count_value = self.env.get("BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT", "")
        self.sign_count: int | None = None
        self.jobs_dir = Path(
            self.env.get(
                "BLOOM_EVAL_JOBS_DIR", str(self.repo_root / "evals/harbor/jobs")
            )
        )
        self._lock_path = Path(
            self.env.get("BLOOM_EVAL_LOCK_FILE", "/tmp/bloom-harbor-mainnet.lock")
        )
        self.session_id: str | None = None
        self.session_base: Path | None = None
        self.session_created = False

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    def _require_sign_count(self) -> int:
        try:
            sign_count = int(self.sign_count_value)
        except ValueError as error:
            raise EvalError(
                "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT must be an integer"
            ) from error
        if sign_count < 1 or sign_count > 0xFFFF_FFFF:
            raise EvalError(
                "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT must be between 1 and 4294967295"
            )
        return sign_count

    @property
    def network_root(self) -> Path:
        return self.bloom_mount / "petals/hyperliquid/mainnet"

    @property
    def user_root(self) -> Path:
        return self.network_root / "users" / self.wallet

    @property
    def wallet_root(self) -> Path:
        return self.bloom_mount / "wallets" / self.wallet_id

    def _read_json(self, path: Path, timeout: int = 20) -> Any:
        try:
            completed = subprocess.run(
                ["cat", str(path)],
                check=True,
                capture_output=True,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"could not read {path}: {error}") from error
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise EvalError(f"{path} is not valid JSON: {error}") from error

    def _write_route(
        self, path: Path, body: bytes, timeout: int
    ) -> subprocess.CompletedProcess[bytes]:
        writer = (
            "import pathlib,sys; "
            "pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())"
        )
        try:
            return subprocess.run(
                [sys.executable, "-c", writer, str(path)],
                input=body,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"route write to {path} failed: {error}") from error

    def _read_json_if_exists(self, path: Path) -> Any | None:
        # Dynamic Petal routes can make getattr/stat succeed for arbitrary
        # session IDs. The parent listing is the durable existence boundary.
        try:
            session_ids = os.listdir(path.parent.parent)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EvalError(f"could not list {path.parent.parent}: {error}") from error
        if path.parent.name not in session_ids:
            return None
        return self._read_json(path)

    def _pending_petal_key_ceremony(self) -> str | None:
        if self.session_id is None:
            raise EvalError("session ID is unavailable while resolving Petal key ceremony")
        root = self.bloom_mount / "petal-key-requests"
        try:
            names = sorted(os.listdir(root))
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EvalError(
                f"could not list owner Petal key requests: {error}"
            ) from error
        matches: list[str] = []
        for name in names:
            if re.fullmatch(r"[0-9a-f]{64}\.json", name) is None:
                continue
            record = self._read_json(root / name)
            scope = record.get("scope") if isinstance(record, dict) else None
            if not isinstance(scope, dict):
                continue
            if (
                record.get("schema") != "bloom.machine.petal-key-request.v2"
                or record.get("key_slot") != session_key_slot(self.session_id)
                or scope.get("wallet_id") != self.wallet_id
                or scope.get("package_hash") != self.package_hash
            ):
                continue
            ceremony_url = record.get("ceremony_url")
            if record.get("status") == "awaiting_user" and isinstance(
                ceremony_url, str
            ):
                if CEREMONY_URL.fullmatch(ceremony_url) is None:
                    raise EvalError(
                        "owner Petal key request has an invalid ceremony URL"
                    )
                matches.append(ceremony_url)
        if len(matches) > 1:
            raise EvalError("multiple Petal key ceremonies match the exact session")
        return matches[0] if matches else None

    def _redact_ceremony_urls(self, output: str) -> str:
        return CEREMONY_URL.sub("[REDACTED_CEREMONY_URL]", output)

    def _read_session_status(self, attempts: int = 3) -> Any | None:
        if self.session_base is None:
            return None
        for attempt in range(attempts):
            status_data = self._read_json_if_exists(self.session_base / "status.json")
            if status_data is not None:
                return status_data
            if attempt + 1 < attempts:
                time.sleep(0.2)
        return None

    def _require_installed_package_hash(self) -> None:
        if not self.owner_record_value:
            raise EvalError("BLOOM_EVAL_PETAL_OWNER_RECORD is required")
        try:
            metadata = self.owner_record.lstat()
        except OSError as error:
            raise EvalError(f"Petal owner record is unavailable: {error}") from error
        if not stat.S_ISREG(metadata.st_mode) or self.owner_record.is_symlink():
            raise EvalError("Petal owner record must be a regular non-symlink file")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise EvalError("Petal owner record must not be group/other writable")
        try:
            record = json.loads(self.owner_record.read_bytes())
        except (OSError, json.JSONDecodeError) as error:
            raise EvalError(f"Petal owner record is invalid: {error}") from error
        if not isinstance(record, dict) or record != {
            "name": "hyperliquid",
            "hash": self.package_hash,
        }:
            raise EvalError(
                "configured Hyperliquid BLAKE3 does not match the installed owner record"
            )

    def _read_local_json(self, path: Path, label: str) -> Any:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise EvalError(f"{label} is unavailable: {error}") from error
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise EvalError(f"{label} must be a regular non-symlink file")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise EvalError(f"{label} must not be group/other writable")
        if metadata.st_size > 8 * 1024 * 1024:
            raise EvalError(f"{label} exceeds the 8 MiB inspection limit")
        try:
            return json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as error:
            raise EvalError(f"{label} is invalid: {error}") from error

    def _require_active_petal_lineage(self) -> None:
        if not self.petal_store_value:
            raise EvalError("BLOOM_EVAL_PETAL_STORE is required")
        if not self.provenance_catalog_value:
            raise EvalError("BLOOM_EVAL_PROVENANCE_CATALOG is required")
        route_index = self._read_local_json(
            self.petal_store / "packages" / self.package_hash / "route-index.json",
            "installed Hyperliquid route index",
        )
        routes = route_index.get("routes") if isinstance(route_index, dict) else None
        if (
            not isinstance(route_index, dict)
            or route_index.get("schema") != "bloom.petal.route-index.v1"
            or not isinstance(routes, list)
        ):
            raise EvalError("installed Hyperliquid route index has an unsupported shape")
        matches = [
            route
            for route in routes
            if isinstance(route, dict)
            and route.get("pattern") == HYPERLIQUID_SESSION_ROUTE
        ]
        if len(matches) != 1:
            raise EvalError(
                "installed Hyperliquid package must contain exactly one agent-session route"
            )
        route = matches[0]
        route_id = route.get("route_id")
        metadata = route.get("install_metadata")
        required_caps = metadata.get("required_caps") if isinstance(metadata, dict) else None
        if (
            not isinstance(route_id, str)
            or re.fullmatch(r"r[0-9]{6}", route_id) is None
            or not isinstance(metadata, dict)
            or metadata.get("sign_intent") != "hyperliquid.approve_agent"
            or not isinstance(required_caps, list)
            or any(not isinstance(capability, str) for capability in required_caps)
            or not {"bloom:key.derive", "bloom:sign"}.issubset(set(required_caps))
        ):
            raise EvalError(
                "installed Hyperliquid agent-session route lacks its exact custody bindings"
            )

        catalog = self._read_local_json(
            self.provenance_catalog, "Machine provenance catalog"
        )
        records = catalog.get("records") if isinstance(catalog, dict) else None
        if (
            not isinstance(catalog, dict)
            or catalog.get("schema") != "bloom.provenance-catalog.1"
            or not isinstance(records, list)
        ):
            raise EvalError("Machine provenance catalog has an unsupported shape")
        matching_records = [
            record
            for record in records
            if isinstance(record, dict)
            and record.get("subject")
            == {
                "kind": "petal",
                "package_hash": self.package_hash,
                "route": route_id,
            }
        ]
        if not matching_records:
            raise EvalError(
                "installed Hyperliquid agent-session route has no installer-provenance record"
            )
        if len(matching_records) != 1:
            raise EvalError(
                "installed Hyperliquid agent-session route has duplicate provenance records"
            )
        lineage = matching_records[0].get("petal_lineage")
        if not isinstance(lineage, dict) or lineage.get("active") is not True:
            raise EvalError(
                "installed Hyperliquid agent-session route does not have active Petal lineage"
            )
        release_sequence = lineage.get("release_sequence")
        if isinstance(release_sequence, str):
            release_sequence_valid = (
                re.fullmatch(r"[1-9][0-9]*", release_sequence) is not None
                and len(release_sequence) <= 20
                and int(release_sequence) <= 0xFFFF_FFFF_FFFF_FFFF
            )
        else:
            release_sequence_valid = (
                isinstance(release_sequence, int)
                and not isinstance(release_sequence, bool)
                and 0 < release_sequence <= 0xFFFF_FFFF_FFFF_FFFF
            )
        if (
            not isinstance(lineage.get("lineage_id"), str)
            or LINEAGE_ID.fullmatch(lineage["lineage_id"]) is None
            or not release_sequence_valid
            or not isinstance(lineage.get("controller_key_id"), str)
            or not isinstance(lineage.get("controller_signature"), str)
            or BASE64URL.fullmatch(lineage["controller_signature"]) is None
        ):
            raise EvalError(
                "installed Hyperliquid agent-session route has malformed Petal lineage"
            )

    def preauthorization_preflight(self) -> None:
        if not PACKAGE_HASH.fullmatch(self.package_hash):
            raise EvalError(
                "BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH must be a lowercase BLAKE3"
            )
        self._require_installed_package_hash()
        self._require_active_petal_lineage()

    def _require_exact_wallet_policy(self) -> None:
        if not WALLET_ID.fullmatch(self.wallet_id):
            raise EvalError("BLOOM_EVAL_WALLET_ID must be a lowercase wallet ID")
        if not PACKAGE_HASH.fullmatch(self.package_hash):
            raise EvalError(
                "BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH must be a lowercase BLAKE3"
            )

        addresses = self._read_json(self.wallet_root / "addresses.json")
        owner = addresses.get("owner") if isinstance(addresses, dict) else None
        if not isinstance(owner, str) or owner.lower() != self.wallet:
            raise EvalError("BLOOM_EVAL_WALLET_ID does not own BLOOM_EVAL_WALLET")
        if addresses.get("policy_status") != "broker_verified":
            raise EvalError("eval wallet policy is not Broker-verified")
        if addresses.get("freshness") != "fresh":
            raise EvalError("eval wallet policy projection is stale")

        policy = self._read_json(self.wallet_root / "policy.json")
        if not isinstance(policy, dict):
            raise EvalError("eval wallet policy is not a JSON object")
        expected_policy = {
            "allowed_destinations": [],
            "allowed_petal_packages": [self.package_hash],
            "maximum_approval_lifetime_ms": 2_592_000_000,
            "required_verifiers": [],
            "wallet_id": self.wallet_id,
        }
        if policy != expected_policy:
            raise EvalError(
                "eval wallet policy does not match the exact bounded policy"
            )
        canonical = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        if addresses.get("policy_digest") != digest:
            raise EvalError(
                "eval wallet policy digest does not match its public projection"
            )

    def _nonzero_positions(self) -> list[dict[str, Any]]:
        clearinghouse = self._read_json(self.user_root / "clearinghouse.json")
        positions = (
            clearinghouse.get("assetPositions")
            if isinstance(clearinghouse, dict)
            else None
        )
        if not isinstance(positions, list):
            raise EvalError("clearinghouse projection has no assetPositions array")
        nonzero_positions: list[dict[str, Any]] = []
        for item in positions:
            if not isinstance(item, dict):
                raise EvalError("clearinghouse contains a malformed position entry")
            position = item.get("position", item)
            if not isinstance(position, dict) or "szi" not in position:
                raise EvalError("clearinghouse position has no size")
            try:
                size = Decimal(str(position["szi"]))
            except (InvalidOperation, TypeError, ValueError) as error:
                raise EvalError("clearinghouse position size is not numeric") from error
            if not size.is_finite():
                raise EvalError("clearinghouse position size is not finite")
            if size != 0:
                nonzero_positions.append(item)
        return nonzero_positions

    def _require_no_orders_or_positions(self) -> None:
        orders = self._read_json(self.user_root / "open_orders.json")
        if not isinstance(orders, list):
            raise EvalError("open-orders projection is not a JSON array")
        if orders:
            raise EvalError(
                "dedicated wallet already has an open order; use an empty eval wallet"
            )

        if self._nonzero_positions():
            raise EvalError(
                "dedicated wallet has an open position; use an empty eval wallet"
            )

    def _require_empty_wallet(self) -> None:
        self._require_no_orders_or_positions()
        agents = self._read_json(self.user_root / "extra_agents.json")
        if not isinstance(agents, list):
            raise EvalError("extra-agents projection is not a JSON array")
        if agents:
            raise EvalError("dedicated wallet retains a Hyperliquid API agent")

    def preflight(self) -> None:
        if not WALLET.fullmatch(self.wallet):
            raise EvalError("BLOOM_EVAL_WALLET must be a lowercase 0x address")
        if self.env.get("BLOOM_EVAL_MAINNET_ACK") != MAINNET_ACK:
            raise EvalError(
                f"set BLOOM_EVAL_MAINNET_ACK={MAINNET_ACK} to authorize this mainnet trial"
            )
        if not self.seed_file_value:
            raise EvalError("BLOOM_EVAL_AUTHENTICATOR_SEED_FILE is required")
        self.sign_count = self._require_sign_count()
        try:
            seed_stat = self.seed_file.lstat()
        except OSError as error:
            raise EvalError(
                f"authenticator seed file is unavailable: {error}"
            ) from error
        if not stat.S_ISREG(seed_stat.st_mode) or self.seed_file.is_symlink():
            raise EvalError(
                "authenticator seed file must be a regular non-symlink file"
            )
        if stat.S_IMODE(seed_stat.st_mode) != 0o600:
            raise EvalError("authenticator seed file must have mode 0600")
        if seed_stat.st_size == 0:
            raise EvalError("authenticator seed file is empty")
        if not self.driver.is_file() or not os.access(self.driver, os.X_OK):
            raise EvalError(f"debug driver is missing or not executable: {self.driver}")
        try:
            usage = subprocess.run(
                [str(self.driver)],
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"could not inspect debug driver: {error}") from error
        if "--authenticator-seed-file" not in usage.stdout + usage.stderr:
            raise EvalError(
                "debug driver lacks --authenticator-seed-file support; "
                "build bloom-broker PR #1 or newer"
            )
        if not os.path.ismount(self.bloom_mount):
            raise EvalError(f"Bloom is not mounted at {self.bloom_mount}")
        for relative, label in (
            ("mids.json", "Hyperliquid mainnet Petal is not installed"),
            ("perp_meta.json", "Hyperliquid perpetual metadata route is missing"),
            ("../README.md", "Hyperliquid Petal README is missing"),
        ):
            if not (self.network_root / relative).exists():
                raise EvalError(label)
        self.preauthorization_preflight()
        self._require_exact_wallet_policy()
        try:
            subprocess.run(
                ["docker", "info"], check=True, capture_output=True, timeout=20
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"Docker daemon is unavailable: {error}") from error
        self._require_empty_wallet()

    def provision(self, agent_name: str) -> EvalRunContext:
        sign_count = self.sign_count or self._require_sign_count()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        random_hex = secrets.token_hex(8)
        self.session_id = f"bloom-eval-{agent_name}-{stamp}-{random_hex}"
        cloid = "0x" + hashlib.sha256(self.session_id.encode()).hexdigest()[:32]
        self.session_base = (
            self.network_root / "agent_sessions" / self.wallet / self.session_id
        )
        request = {
            "id": self.session_id,
            "wallet_id": self.wallet_id,
            "agent_name": f"be-{agent_name[:3]}-{random_hex[:8]}",
            "duration_ms": 1_800_000,
            "max_notional_usd": "11",
            "max_leverage": 1,
            "assets": ["0"],
        }
        body = json.dumps(request, separators=(",", ":")).encode()
        new_route = self.network_root / "agent_sessions" / self.wallet / "new.json"

        first = self._write_route(new_route, body, 45)
        output = (first.stdout + first.stderr).decode(errors="replace")
        status_data: Any | None = None
        ceremony_url: str | None = None
        output_match = CEREMONY_URL.search(output)

        # Mounted Petal writes are asynchronous. A zero write exit code means
        # accepted for dispatch, not that the route completed successfully.
        # Wait for one of the two durable owner-visible outcomes regardless of
        # the write result: a bounded session or a key-derivation ceremony.
        for _ in range(50):
            status_data = self._read_json_if_exists(self.session_base / "status.json")
            if status_data is not None:
                break
            ceremony_url = (
                output_match.group(0)
                if output_match is not None
                else self._pending_petal_key_ceremony()
            )
            if ceremony_url is not None:
                break
            time.sleep(0.2)

        if status_data is None and ceremony_url is not None:
            try:
                completed = subprocess.run(
                    [
                        str(self.driver),
                        "complete",
                        ceremony_url,
                        "--authenticator-seed-file",
                        str(self.seed_file),
                        "--sign-count",
                        str(sign_count),
                    ],
                    check=False,
                    capture_output=True,
                    timeout=45,
                )
                output += (completed.stdout + completed.stderr).decode(errors="replace")
            except (OSError, subprocess.SubprocessError) as error:
                raise EvalError(
                    "debug-driver ceremony completion failed: "
                    + self._redact_ceremony_urls(str(error))
                ) from error
            if completed.returncode != 0:
                raise EvalError(
                    "session key ceremony failed: " + self._redact_ceremony_urls(output)
                )

            # Replay byte-identical session terms only after the owner ceremony
            # succeeds; WebAuthn counter reuse is never attempted.
            retry = self._write_route(new_route, body, 45)
            output += (retry.stdout + retry.stderr).decode(errors="replace")
            for _ in range(50):
                status_data = self._read_json_if_exists(
                    self.session_base / "status.json"
                )
                if status_data is not None:
                    break
                time.sleep(0.2)

        if status_data is None:
            raise EvalError(
                "session creation failed without durable session or ceremony readback: "
                + self._redact_ceremony_urls(output)
            )

        self.session_created = True
        expected = {
            "schema": "bloom.hyperliquid_agent_session.v1",
            "network": "mainnet",
            "wallet": self.wallet,
            "id": self.session_id,
            "max_notional_usd": "11",
            "max_leverage": 1,
            "assets": ["0"],
            "stopped": False,
        }
        if not isinstance(status_data, dict) or any(
            status_data.get(key) != value for key, value in expected.items()
        ):
            raise EvalError("created session does not match the bounded contract")

        mounts: list[dict[str, Any]] = [
            {
                "type": "bind",
                "source": str(self.bloom_mount),
                "target": "/bloom",
                "read_only": True,
            }
        ]
        container_base = (
            f"/bloom/petals/hyperliquid/mainnet/agent_sessions/"
            f"{self.wallet}/{self.session_id}"
        )
        mounts.extend(
            {
                "type": "bind",
                "source": str(self.session_base / action),
                "target": f"{container_base}/{action}",
            }
            for action in ACTION_FILES
        )
        runtime_env = {
            "BLOOM_EVAL_WALLET": self.wallet,
            "BLOOM_EVAL_SESSION_ID": self.session_id,
            "BLOOM_EVAL_CLOID": cloid,
        }
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        return EvalRunContext(
            eval_name=self.name,
            task_dir=self.repo_root / "evals/harbor/tasks/hyperliquid-order-cancel",
            job_name=f"bloom-hyperliquid-{agent_name}-{stamp}",
            jobs_dir=self.jobs_dir,
            mounts=mounts,
            agent_env=runtime_env,
            verifier_env=runtime_env,
        )

    def cleanup(self) -> None:
        if self.session_base is None or self.session_id is None:
            return
        failures: list[str] = []
        status_data = self._read_session_status()
        if status_data is None:
            try:
                if self._pending_petal_key_ceremony() is not None:
                    failures.append(
                        "matching Petal key ceremony is still awaiting user action"
                    )
            except EvalError as error:
                failures.append(str(error))
            try:
                self._require_empty_wallet()
            except EvalError as error:
                failures.append(str(error))
            if failures:
                raise EvalError(
                    f"residual-state cleanup failed for {self.session_id}: "
                    + "; ".join(failures)
                )
            return

        self.session_created = True
        stopped = isinstance(status_data, dict) and status_data.get("stopped") is True
        if not stopped:
            cancel = self._write_route(
                self.session_base / "cancel_all", b"host-cleanup", 30
            )
            if cancel.returncode != 0:
                failures.append("session cancel_all failed")

        try:
            orders = self._read_json(self.user_root / "open_orders.json")
            if not isinstance(orders, list) or orders:
                failures.append("dedicated wallet still has open orders")
        except EvalError as error:
            failures.append(str(error))

        try:
            positions = self._nonzero_positions()
            if positions and not stopped:
                closed = self._write_route(
                    self.session_base / "close_all", b"host-cleanup", 45
                )
                if closed.returncode != 0:
                    failures.append("session close_all failed")
                elif self._nonzero_positions():
                    failures.append("dedicated wallet still has an open position")
            elif positions:
                failures.append("stopped session cannot close the residual position")
        except EvalError as error:
            failures.append(str(error))

        if not failures and not stopped:
            stopped_result = self._write_route(
                self.session_base / "stop", b"host-cleanup", 10
            )
            if stopped_result.returncode != 0:
                failures.append("session stop failed")

        try:
            final_status = self._read_json(self.session_base / "status.json")
            if (
                not isinstance(final_status, dict)
                or final_status.get("stopped") is not True
            ):
                failures.append("session is not stopped")
        except EvalError as error:
            failures.append(str(error))

        try:
            self._require_no_orders_or_positions()
        except EvalError as error:
            failures.append(str(error))

        if failures:
            raise EvalError(
                f"residual-state cleanup failed for {self.session_id}: "
                + "; ".join(failures)
            )
