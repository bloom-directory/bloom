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
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .core import EvalDefinition, EvalError, EvalRunContext

MAINNET_ACK = "PLACE_AND_CANCEL_BTC_MAINNET_UP_TO_11_USD"
CEREMONY_URL = re.compile(r"http://localhost:18734/ceremony/[A-Za-z0-9_-]{43}")
WALLET = re.compile(r"0x[0-9a-f]{40}")
ACTION_FILES = ("order.json", "cancel.json", "update_leverage.json", "cancel_all")


class HyperliquidOrderCancelEval(EvalDefinition):
    name = "hyperliquid-order-cancel"

    def __init__(self, repo_root: Path, environ: dict[str, str] | None = None) -> None:
        self.repo_root = repo_root.resolve()
        self.env = dict(os.environ if environ is None else environ)
        self.wallet = self.env.get("BLOOM_EVAL_WALLET", "")
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

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    @property
    def network_root(self) -> Path:
        return self.bloom_mount / "petals/hyperliquid/mainnet"

    @property
    def user_root(self) -> Path:
        return self.network_root / "users" / self.wallet

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

    def _require_empty_wallet(self) -> None:
        orders = self._read_json(self.user_root / "open_orders.json")
        if not isinstance(orders, list):
            raise EvalError("open-orders projection is not a JSON array")
        if orders:
            raise EvalError(
                "dedicated wallet already has an open order; use an empty eval wallet"
            )

        clearinghouse = self._read_json(self.user_root / "clearinghouse.json")
        positions = (
            clearinghouse.get("assetPositions")
            if isinstance(clearinghouse, dict)
            else None
        )
        if not isinstance(positions, list):
            raise EvalError("clearinghouse projection has no assetPositions array")
        for item in positions:
            if not isinstance(item, dict):
                raise EvalError("clearinghouse contains a malformed position entry")
            position = item.get("position", item)
            if not isinstance(position, dict) or "szi" not in position:
                raise EvalError("clearinghouse position has no size")
            raw_size = position["szi"]
            try:
                size = Decimal(str(raw_size))
            except (InvalidOperation, TypeError, ValueError) as error:
                raise EvalError("clearinghouse position size is not numeric") from error
            if not size.is_finite():
                raise EvalError("clearinghouse position size is not finite")
            nonzero = size != 0
            if nonzero:
                raise EvalError(
                    "dedicated wallet has an open position; use an empty eval wallet"
                )

    def preflight(self) -> None:
        if not WALLET.fullmatch(self.wallet):
            raise EvalError("BLOOM_EVAL_WALLET must be a lowercase 0x address")
        if self.env.get("BLOOM_EVAL_MAINNET_ACK") != MAINNET_ACK:
            raise EvalError(
                f"set BLOOM_EVAL_MAINNET_ACK={MAINNET_ACK} to authorize this mainnet trial"
            )
        if not self.seed_file_value:
            raise EvalError("BLOOM_EVAL_AUTHENTICATOR_SEED_FILE is required")
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
        try:
            subprocess.run(
                ["docker", "info"], check=True, capture_output=True, timeout=20
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"Docker daemon is unavailable: {error}") from error
        self._require_empty_wallet()

    def provision(self, agent_name: str) -> EvalRunContext:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        random_hex = secrets.token_hex(8)
        self.session_id = f"bloom-eval-{agent_name}-{stamp}-{random_hex}"
        cloid = "0x" + hashlib.sha256(self.session_id.encode()).hexdigest()[:32]
        self.session_base = (
            self.network_root / "agent_sessions" / self.wallet / self.session_id
        )
        request = {
            "id": self.session_id,
            "agent_name": f"be-{agent_name}-{random_hex}",
            "duration_ms": 1_800_000,
            "max_notional_usd": "11",
            "max_leverage": 1,
            "assets": ["0"],
        }
        body = json.dumps(request, separators=(",", ":")).encode()
        new_route = self.network_root / "agent_sessions" / self.wallet / "new.json"

        first = self._write_route(new_route, body, 45)
        if first.returncode != 0:
            output = (first.stdout + first.stderr).decode(errors="replace")
            match = CEREMONY_URL.search(output)
            if match is None:
                raise EvalError(
                    "session creation failed without a canonical ceremony URL: "
                    + output
                )
            try:
                subprocess.run(
                    [
                        str(self.driver),
                        "complete",
                        match.group(0),
                        "--authenticator-seed-file",
                        str(self.seed_file),
                    ],
                    check=True,
                    capture_output=True,
                    timeout=45,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise EvalError(
                    f"debug-driver ceremony completion failed: {error}"
                ) from error
            retry = self._write_route(new_route, body, 45)
            if retry.returncode != 0:
                detail = (retry.stdout + retry.stderr).decode(errors="replace")
                raise EvalError(f"session creation retry failed: {detail}")

        status_data = self._read_json(self.session_base / "status.json")
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
        status_data: Any = {}
        try:
            status_data = self._read_json(self.session_base / "status.json")
        except EvalError as error:
            failures.append(str(error))

        if not (isinstance(status_data, dict) and status_data.get("stopped") is True):
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

        if not failures:
            try:
                status_data = self._read_json(self.session_base / "status.json")
            except EvalError:
                status_data = {}
            if not (
                isinstance(status_data, dict) and status_data.get("stopped") is True
            ):
                stopped = self._write_route(
                    self.session_base / "stop", b"host-cleanup", 10
                )
                if stopped.returncode != 0:
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

        if failures:
            raise EvalError(
                f"residual-state cleanup failed for {self.session_id}: "
                + "; ".join(failures)
            )
