"""Host-side lifecycle for the Hyperliquid approve_builder_fee evaluation.

Unlike hyperliquid-order-cancel, this action has no session or delegated
signing key: `approve_builder_fee.json` is owner-signed on every call, with
no way for a sandboxed agent container to complete the WebAuthn ceremony it
requires. So this harness completes the one ceremony itself, in provision(),
before the agent starts — exactly like session creation completes its
ceremonies before handing control to the agent in hyperliquid-order-cancel.
The agent then reissues the identical write (same nonce), which the Petal's
own idempotent pending-nonce record resolves without a further ceremony, and
reads back the result. cleanup() revokes the approval the same way it was
granted, using the max_fee_tenths_bps=0 revocation path.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .core import EvalDefinition, EvalError, EvalRunContext

CEREMONY_URL = re.compile(r"http://localhost:18734/ceremony/[A-Za-z0-9_-]{43}")
NETWORKS = ("mainnet", "testnet")
ADDRESS = re.compile(r"0x[0-9a-f]{40}")
WALLET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
PACKAGE_HASH = re.compile(r"[0-9a-f]{64}")
ROUTE_PATTERN = "[network]/exchange/[wallet]/approve_builder_fee.json"
OPERATION_CLASS = "hyperliquid.approve_builder_fee"
# Matches the venue caps enforced in route/src/protocol.rs: 0.1% perps / 1%
# spot, expressed in tenths of a basis point. This harness only ever grants
# and revokes, so the wider spot cap bounds the request it will accept.
MAX_FEE_TENTHS_BPS = 1000
# A single ceremony is expected for both the grant and the revoke. This caps
# a misbehaving route rather than describing a normal multi-ceremony flow, as
# in hyperliquid-order-cancel.
MAX_CEREMONIES_PER_ACTION = 1
CEREMONY_DISCOVERY_ATTEMPTS = 600
VENUE_READ_TIMEOUT_SECONDS = 45
VENUE_READ_ATTEMPTS = 3
WRITE_TIMEOUT_SECONDS = 120
VENUE_SETTLE_ATTEMPTS = 12
VENUE_SETTLE_DELAY_SECONDS = 5.0
EVAL_IMAGE = (
    "ghcr.io/bloom-directory/bloom-eval-agent-base@"
    "sha256:20988c7f8a6751c25e0115c2136710a885bef69d245e077d2ae3b2cc2c0837fd"
)
EVAL_IMAGE_PULL_TIMEOUT_SECONDS = 600


class HyperliquidApproveBuilderFeeEval(EvalDefinition):
    name = "hyperliquid-approve-builder-fee"

    def __init__(
        self,
        repo_root: Path,
        environ: dict[str, str] | None = None,
        *,
        counter_committed: Callable[[int], None] | None = None,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.env = dict(os.environ if environ is None else environ)
        self.network = self.env.get("BLOOM_EVAL_NETWORK", "testnet")
        self.wallet = self.env.get("BLOOM_EVAL_WALLET", "")
        self.wallet_id = self.env.get("BLOOM_EVAL_WALLET_ID", "")
        self.builder = self.env.get("BLOOM_EVAL_BUILDER", "")
        self.max_fee_tenths_bps_value = self.env.get(
            "BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS", ""
        )
        self.package_hash = self.env.get("BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH", "")
        self.owner_record_value = self.env.get("BLOOM_EVAL_PETAL_OWNER_RECORD", "")
        self.owner_record = Path(self.owner_record_value)
        self.petal_store_value = self.env.get("BLOOM_EVAL_PETAL_STORE", "")
        self.petal_store = Path(self.petal_store_value)
        self.provenance_catalog_value = self.env.get(
            "BLOOM_EVAL_PROVENANCE_CATALOG", ""
        )
        self.provenance_catalog = Path(self.provenance_catalog_value)
        self.bloom_mount_value = self.env.get("BLOOM_EVAL_BLOOM_MOUNT", "").strip()
        self.bloom_mount = Path(self.bloom_mount_value)
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
        # The first counter this run has not consumed. This eval spends one per
        # ceremony (one to grant in provision, one to revoke in cleanup), so
        # the operator's next run must start at or above this.
        self.next_sign_count: int | None = None
        self.jobs_dir = Path(
            self.env.get(
                "BLOOM_EVAL_JOBS_DIR", str(self.repo_root / "evals/harbor/jobs")
            )
        )
        self._lock_path = Path(
            self.env.get(
                "BLOOM_EVAL_LOCK_FILE", "/tmp/bloom-harbor-approve-builder-fee.lock"
            )
        )
        self.nonce: int | None = None
        self.granted = False
        self.counter_committed = counter_committed
        self.phase_timings: dict[str, float] = {}

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
        return self.bloom_mount / "petals/hyperliquid" / self.network

    @property
    def wallet_root(self) -> Path:
        return self.bloom_mount / "wallets" / self.wallet_id

    @property
    def exchange_root(self) -> Path:
        return self.network_root / "exchange" / self.wallet_id

    @property
    def max_builder_fee_path(self) -> Path:
        return (
            self.network_root
            / "users"
            / self.wallet
            / "max_builder_fee"
            / f"{self.builder}.json"
        )

    def _read_json(self, path: Path, timeout: int = VENUE_READ_TIMEOUT_SECONDS) -> Any:
        # Reads under the Petal are live venue round-trips, not local file
        # reads; latency is the venue's, not the disk's. See the identical
        # comment in hyperliquid_order_cancel.py for the timing rationale.
        last_error: BaseException | None = None
        for attempt in range(VENUE_READ_ATTEMPTS):
            try:
                completed = subprocess.run(
                    ["cat", str(path)],
                    check=True,
                    capture_output=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as error:
                last_error = error
                if attempt + 1 < VENUE_READ_ATTEMPTS:
                    time.sleep(1.0)
                continue
            except (OSError, subprocess.SubprocessError) as error:
                raise EvalError(f"could not read {path}: {error}") from error
            try:
                return json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                last_error = error
                if attempt + 1 < VENUE_READ_ATTEMPTS:
                    time.sleep(0.2)
                continue
        raise EvalError(
            f"could not read {path} after {VENUE_READ_ATTEMPTS} attempts "
            f"of {timeout}s: {last_error}"
        ) from last_error

    def _write_route(
        self, path: Path, body: bytes, timeout: int
    ) -> subprocess.CompletedProcess[bytes]:
        writer = (
            "import pathlib,sys; "
            "pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())"
        )
        try:
            return subprocess.run(
                ["python3", "-c", writer, str(path)],
                input=body,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"route write to {path} failed: {error}") from error

    def _redact_ceremony_urls(self, output: str) -> str:
        return CEREMONY_URL.sub("[REDACTED_CEREMONY_URL]", output)

    def _pending_builder_fee_ceremony(self) -> str | None:
        """Resolve the owner signing request this action's write staged.

        Unlike hyperliquid-order-cancel's agent-approval ceremony, there is no
        session id to bind against. Scope as tightly as the projection allows:
        exact wallet, exact package hash, exact operation class. Grant and
        revoke are indistinguishable at this layer (both are
        hyperliquid.approve_builder_fee); the caller only ever has one
        in flight, so this refuses to act rather than guess if it ever finds
        more than one.
        """
        root = self.bloom_mount / "petal-signing-requests"
        try:
            names = sorted(os.listdir(root))
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EvalError(
                f"could not list owner Petal signing requests: {error}"
            ) from error
        matches: list[str] = []
        for name in names:
            if re.fullmatch(r"[0-9a-f]{64}\.json", name) is None:
                continue
            try:
                record = self._read_json(root / name)
            except EvalError:
                continue
            if not isinstance(record, dict):
                continue
            if (
                record.get("schema") != "bloom.machine.petal-signing-request.v1"
                or record.get("status") != "awaiting_owner_approval"
                or record.get("wallet") != self.wallet_id
                or record.get("package_hash") != self.package_hash
                or record.get("operation_class") != OPERATION_CLASS
            ):
                continue
            ceremony_url = record.get("ceremony_url")
            if not isinstance(ceremony_url, str):
                continue
            if CEREMONY_URL.fullmatch(ceremony_url) is None:
                raise EvalError(
                    "owner Petal signing request has an invalid ceremony URL"
                )
            matches.append(ceremony_url)
        if len(matches) > 1:
            raise EvalError(
                "multiple approve_builder_fee ceremonies match the exact wallet"
            )
        return matches[0] if matches else None

    def _require_local_json(self, path: Path, label: str) -> Any:
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

    def _require_installed_package_hash(self) -> None:
        if not self.owner_record_value:
            raise EvalError("BLOOM_EVAL_PETAL_OWNER_RECORD is required")
        record = self._require_local_json(self.owner_record, "Petal owner record")
        if not isinstance(record, dict) or record != {
            "name": "hyperliquid",
            "hash": self.package_hash,
        }:
            raise EvalError(
                "configured Hyperliquid package hash does not match the installed owner record"
            )

    def _require_builder_fee_provenance(self) -> None:
        """Confirm the installed route can carry the fee this eval will grant.

        Bloom's provenance catalog currently records fee_asset: null for every
        Petal operation class (see bloom-directory/bloom#<TODO: platform
        fee_asset issue>). approve_builder_fee.json's own DeclaredFee is
        `{"kind":"none"}` regardless (approving a cap charges nothing itself),
        so that gap does not block this specific route the way it blocks
        order.json with a nonzero builder fee. This check only confirms the
        route is installed and owned under the expected operation class; it
        intentionally does not assert a non-null fee_asset, since nothing in
        the current toolchain can produce one.
        """
        if not self.provenance_catalog_value:
            raise EvalError("BLOOM_EVAL_PROVENANCE_CATALOG is required")
        route_index = self._require_local_json(
            self.petal_store / "packages" / self.package_hash / "route-index.json",
            "installed Hyperliquid route index",
        )
        routes = route_index.get("routes") if isinstance(route_index, dict) else None
        if (
            not isinstance(route_index, dict)
            or route_index.get("schema") != "bloom.petal.route-index.v1"
            or route_index.get("package_hash") != self.package_hash
            or not isinstance(routes, list)
        ):
            raise EvalError(
                "installed Hyperliquid route index has an unsupported shape or package hash"
            )
        matches = [
            route
            for route in routes
            if isinstance(route, dict) and route.get("pattern") == ROUTE_PATTERN
        ]
        if len(matches) != 1:
            raise EvalError(
                "installed Hyperliquid package must contain exactly one approve_builder_fee route"
            )
        route = matches[0]
        metadata = route.get("install_metadata")
        if not isinstance(metadata, dict) or metadata.get("sign_intent") != OPERATION_CLASS:
            raise EvalError(
                "installed approve_builder_fee route lacks its exact owner-sign intent"
            )
        route_id = route.get("route_id")
        catalog = self._require_local_json(
            self.provenance_catalog, "Machine provenance catalog"
        )
        records = catalog.get("records") if isinstance(catalog, dict) else None
        if not isinstance(catalog, dict) or not isinstance(records, list):
            raise EvalError("Machine provenance catalog has an unsupported shape")
        matching_records = [
            record
            for record in records
            if isinstance(record, dict)
            and record.get("subject")
            == {"kind": "petal", "package_hash": self.package_hash, "route": route_id}
        ]
        if len(matching_records) != 1:
            raise EvalError(
                "installed approve_builder_fee route has no unique installer-provenance record"
            )
        operation_classes = matching_records[0].get("operation_classes")
        if operation_classes != [{"operation_class": OPERATION_CLASS, "fee_asset": None}]:
            raise EvalError(
                "installed approve_builder_fee route provenance does not match the expected operation class"
            )

    def _require_exact_wallet_policy(self) -> None:
        policy = self._read_json(self.wallet_root / "policy.json")
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

    def preflight(self) -> None:
        if not self.bloom_mount_value:
            raise EvalError("BLOOM_EVAL_BLOOM_MOUNT is required")
        if not ADDRESS.fullmatch(self.wallet):
            raise EvalError("BLOOM_EVAL_WALLET must be a lowercase 0x address")
        if not WALLET_ID.fullmatch(self.wallet_id):
            raise EvalError("BLOOM_EVAL_WALLET_ID must be a lowercase wallet ID")
        if not ADDRESS.fullmatch(self.builder):
            raise EvalError("BLOOM_EVAL_BUILDER must be a lowercase 0x address")
        try:
            max_fee = int(self.max_fee_tenths_bps_value)
        except ValueError as error:
            raise EvalError(
                "BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS must be an integer"
            ) from error
        if not 1 <= max_fee <= MAX_FEE_TENTHS_BPS:
            raise EvalError(
                f"BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS must be 1..={MAX_FEE_TENTHS_BPS}"
            )
        if not PACKAGE_HASH.fullmatch(self.package_hash):
            raise EvalError(
                "BLOOM_EVAL_HYPERLIQUID_PACKAGE_HASH must be a lowercase BLAKE3"
            )
        if self.network not in NETWORKS:
            raise EvalError(f"BLOOM_EVAL_NETWORK must be one of {NETWORKS}")
        expected_ack = f"APPROVE_BUILDER_FEE_{self.network.upper()}"
        if self.env.get("BLOOM_EVAL_NETWORK_ACK") != expected_ack:
            raise EvalError(
                f"set BLOOM_EVAL_NETWORK_ACK={expected_ack} to authorize this {self.network} trial"
            )
        if not self.seed_file_value:
            raise EvalError("BLOOM_EVAL_AUTHENTICATOR_SEED_FILE is required")
        self.sign_count = self._require_sign_count()
        try:
            seed_stat = self.seed_file.lstat()
        except OSError as error:
            raise EvalError(f"authenticator seed file is unavailable: {error}") from error
        if not stat.S_ISREG(seed_stat.st_mode) or self.seed_file.is_symlink():
            raise EvalError("authenticator seed file must be a regular non-symlink file")
        if stat.S_IMODE(seed_stat.st_mode) != 0o600:
            raise EvalError("authenticator seed file must have mode 0600")
        if seed_stat.st_size == 0:
            raise EvalError("authenticator seed file is empty")
        if not self.driver.is_file() or not os.access(self.driver, os.X_OK):
            raise EvalError(f"debug driver is missing or not executable: {self.driver}")
        if not self.bloom_mount.is_dir():
            raise EvalError(f"Bloom mount is not a directory: {self.bloom_mount}")
        if not (self.network_root.parent / "README.md").exists():
            raise EvalError("Hyperliquid Petal is not installed")
        if not self.network_root.exists():
            raise EvalError(f"Hyperliquid {self.network} routes are not installed")
        self._require_installed_package_hash()
        self._require_builder_fee_provenance()
        self._require_exact_wallet_policy()
        try:
            subprocess.run(["docker", "info"], check=True, capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"Docker daemon is unavailable: {error}") from error
        started = time.monotonic()
        self._pull_eval_image()
        self.phase_timings["image_pull_seconds"] = time.monotonic() - started
        # Refuse to start if a prior run's approval or revocation is still
        # mid-flight; completing a stale ceremony from an earlier process
        # would consume its counter without this run ever having reserved it.
        pending = self._pending_builder_fee_ceremony()
        if pending is not None:
            raise EvalError(
                "a prior approve_builder_fee ceremony is still awaiting owner action"
            )

    def _pull_eval_image(self) -> None:
        try:
            subprocess.run(
                ["docker", "pull", EVAL_IMAGE],
                check=True,
                capture_output=True,
                timeout=EVAL_IMAGE_PULL_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"could not pull the eval image: {error}") from error

    def _drive_action(
        self, route: Path, body: bytes, counter: int
    ) -> tuple[int, str]:
        """Write `body` to `route`, completing at most one owner ceremony.

        Returns the next unused WebAuthn sign count and the combined
        subprocess output for error reporting. Raises if the route neither
        resolves nor stages a ceremony within budget, or if the ceremony
        fails.
        """
        first = self._write_route(route, body, WRITE_TIMEOUT_SECONDS)
        output = (first.stdout + first.stderr).decode(errors="replace")
        last_output = output

        for _ in range(MAX_CEREMONIES_PER_ACTION):
            ceremony_url: str | None = None
            for _ in range(CEREMONY_DISCOVERY_ATTEMPTS):
                match = CEREMONY_URL.search(last_output)
                ceremony_url = (
                    match.group(0)
                    if match is not None
                    else self._pending_builder_fee_ceremony()
                )
                if ceremony_url is not None:
                    break
                time.sleep(0.2)
            if ceremony_url is None:
                return counter, output

            # One attempt only, matching hyperliquid_order_cancel.py: Broker
            # marks a consumed or absent ceremony CEREMONY_REPLAY with retry
            # "never", so a retry here cannot succeed and only burns another
            # WebAuthn counter. The counter is reserved durably before
            # invoking the driver, since the assertion may reach Broker even
            # if this process is interrupted before it returns.
            attempted_counter = counter
            counter = attempted_counter + 1
            if self.counter_committed is not None:
                self.counter_committed(counter)
            self.next_sign_count = counter
            try:
                completed = subprocess.run(
                    [
                        str(self.driver),
                        "complete",
                        ceremony_url,
                        "--authenticator-seed-file",
                        str(self.seed_file),
                        "--sign-count",
                        str(attempted_counter),
                    ],
                    check=False,
                    capture_output=True,
                    timeout=45,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise EvalError(
                    "debug-driver ceremony completion failed at sign count "
                    f"{attempted_counter} (next unused counter is {counter}): "
                    + self._redact_ceremony_urls(str(error))
                ) from error
            output += (completed.stdout + completed.stderr).decode(errors="replace")
            if completed.returncode != 0:
                raise EvalError(
                    f"ceremony failed at sign count {attempted_counter} "
                    f"(next unused counter is {counter}): "
                    + self._redact_ceremony_urls(output)
                )

            retry = self._write_route(route, body, WRITE_TIMEOUT_SECONDS)
            last_output = (retry.stdout + retry.stderr).decode(errors="replace")
            output += last_output

        return counter, output

    def _grant_or_revoke(self, max_fee_tenths_bps: int, nonce: int) -> dict[str, Any]:
        route = self.exchange_root / "approve_builder_fee.json"
        body = json.dumps(
            {
                "builder": self.builder,
                "max_fee_tenths_bps": max_fee_tenths_bps,
                "nonce": nonce,
            },
            separators=(",", ":"),
        ).encode()
        counter = self.sign_count or self._require_sign_count()
        counter, output = self._drive_action(route, body, counter)

        response = None
        for attempt in range(VENUE_SETTLE_ATTEMPTS):
            try:
                response = self._read_json(self.exchange_root / "last_response.json")
                break
            except EvalError:
                if attempt + 1 == VENUE_SETTLE_ATTEMPTS:
                    raise
                time.sleep(VENUE_SETTLE_DELAY_SECONDS)
        if not isinstance(response, dict) or response.get("status") != "ok":
            raise EvalError(
                "approve_builder_fee did not reach a successful Hyperliquid "
                f"response: {self._redact_ceremony_urls(output)}"
            )

        def observed_matches() -> bool:
            observed = self._read_json(self.max_builder_fee_path)
            if not isinstance(observed, int) or isinstance(observed, bool):
                return False
            if max_fee_tenths_bps > 0:
                return observed >= max_fee_tenths_bps
            return observed == 0

        settled = False
        for attempt in range(VENUE_SETTLE_ATTEMPTS):
            try:
                if observed_matches():
                    settled = True
                    break
            except EvalError:
                pass
            if attempt + 1 < VENUE_SETTLE_ATTEMPTS:
                time.sleep(VENUE_SETTLE_DELAY_SECONDS)
        if not settled:
            raise EvalError(
                "Hyperliquid maxBuilderFee never reflected the requested change"
            )
        return response

    def provision(self, agent_name: str) -> EvalRunContext:
        max_fee = int(self.max_fee_tenths_bps_value)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        # A deterministic, run-scoped nonce so the agent can reissue the exact
        # same write and hit the Petal's idempotent completed-nonce path
        # instead of staging a second ceremony it has no way to complete.
        self.nonce = int(
            hashlib.sha256(
                f"bloom-eval-approve-builder-fee/{self.wallet_id}/{stamp}".encode()
            ).hexdigest()[:12],
            16,
        )
        self._grant_or_revoke(max_fee, self.nonce)
        self.granted = True

        mounts: list[dict[str, Any]] = [
            {
                "type": "bind",
                "source": str(self.bloom_mount),
                "target": "/bloom",
                "read_only": True,
            },
            {
                "type": "bind",
                "source": str(self.exchange_root / "approve_builder_fee.json"),
                "target": (
                    f"/bloom/petals/hyperliquid/{self.network}/exchange/"
                    f"{self.wallet_id}/approve_builder_fee.json"
                ),
            },
        ]
        runtime_env = {
            "BLOOM_EVAL_NETWORK": self.network,
            "BLOOM_EVAL_WALLET": self.wallet,
            "BLOOM_EVAL_WALLET_ID": self.wallet_id,
            "BLOOM_EVAL_BUILDER": self.builder,
            "BLOOM_EVAL_BUILDER_MAX_FEE_TENTHS_BPS": str(max_fee),
            "BLOOM_EVAL_APPROVAL_NONCE": str(self.nonce),
        }
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        return EvalRunContext(
            eval_name=self.name,
            task_dir=self.repo_root / "evals/harbor/tasks/hyperliquid-approve-builder-fee",
            job_name=f"bloom-hyperliquid-approve-builder-fee-{agent_name}-{stamp}",
            jobs_dir=self.jobs_dir,
            mounts=mounts,
            agent_env=runtime_env,
            verifier_env=runtime_env,
        )

    def cleanup(self) -> None:
        if not self.granted or self.nonce is None:
            return
        # Revoke with a fresh nonce so this is a distinct signed action, not a
        # replay of the grant. Leaving the run unrevoked would accumulate a
        # live builder approval on the dedicated wallet on every eval run.
        revoke_nonce = self.nonce + 1
        self._grant_or_revoke(0, revoke_nonce)
