"""Host-side lifecycle for the bounded Hyperliquid order/cancel evaluation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Callable
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
HYPERLIQUID_AGENT_ACTION = "hyperliquid.agent_action"
HYPERLIQUID_SESSION_ACTION_ROUTES = (
    "[network]/agent_sessions/[wallet]/[session]/cancel.json",
    "[network]/agent_sessions/[wallet]/[session]/cancel_all",
    "[network]/agent_sessions/[wallet]/[session]/close_all",
    "[network]/agent_sessions/[wallet]/[session]/order.json",
    "[network]/agent_sessions/[wallet]/[session]/schedule_cancel.json",
    "[network]/agent_sessions/[wallet]/[session]/update_leverage.json",
)
ACTION_FILES = ("order.json", "cancel.json", "update_leverage.json", "cancel_all")
# Session creation currently stages three owner ceremonies: key derivation, a
# reusable typed-route approval, then venue agent approval. The cap bounds a
# misbehaving route rather than describing the expected count.
MAX_SESSION_CEREMONIES = 4
# Session writes can return before Machine publishes the owner-visible
# ceremony, especially while the NFS adapter is busy validating a large Petal.
# Keep discovery within the route's 120-second write budget rather than giving
# up after the previous fixed 10-second window.
CEREMONY_DISCOVERY_ATTEMPTS = 600
# Petal reads are live venue round-trips, not disk reads.
VENUE_READ_TIMEOUT_SECONDS = 45
VENUE_READ_ATTEMPTS = 3
# Writing a session route stages owner ceremonies and makes venue calls before
# the mount returns, so it inherits the same latency as a read and then some.
SESSION_WRITE_TIMEOUT_SECONDS = 120
# Mounted Petal writes are accepted for dispatch, not completed, when the write
# returns. Cleanup therefore polls each postcondition rather than reading once.
# Venue-backed postconditions (orders, positions) cost a live Hyperliquid round
# trip each and degrade badly when issued concurrently (see bloom#172), so they
# get few attempts spaced widely apart. `status.json` is a local store read and
# can be polled tightly.
VENUE_SETTLE_ATTEMPTS = 6
VENUE_SETTLE_DELAY_SECONDS = 5.0
STATUS_SETTLE_ATTEMPTS = 50
STATUS_SETTLE_DELAY_SECONDS = 0.2
EVAL_IMAGE = (
    "ghcr.io/bloom-directory/bloom-eval-agent-base@"
    "sha256:20988c7f8a6751c25e0115c2136710a885bef69d245e077d2ae3b2cc2c0837fd"
)
EVAL_IMAGE_PULL_TIMEOUT_SECONDS = 600


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
        self.agent_name_override = self.env.get("BLOOM_EVAL_AGENT_NAME", "").strip()
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
        # The first counter this run has not consumed. A session spends one per
        # ceremony, so the operator's next run must start at or above this.
        self.next_sign_count: int | None = None
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

    def _read_json(self, path: Path, timeout: int = VENUE_READ_TIMEOUT_SECONDS) -> Any:
        # Reads under the Petal are not local file reads: they are live venue
        # round-trips made by wasm and returned over the mount, so their latency
        # is the venue's, not the disk's. Observed between 0.1s and 8s for the
        # same path minutes apart. A single tight timeout loses whole runs to
        # latency the harness does not control, so allow more time and retry a
        # timeout rather than failing the run on one slow fetch. Owner-visible
        # projections can also be replaced while NFS is serving a read; retry
        # a malformed snapshot rather than treating that transient overlap as
        # durable corruption.
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
                [sys.executable, "-c", writer, str(path)],
                input=body,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"route write to {path} failed: {error}") from error

    def _poll_until(
        self,
        predicate: Callable[[], bool],
        attempts: int,
        delay: float,
    ) -> bool:
        """Poll `predicate` until it holds or the budget is spent.

        Returns True as soon as it holds. An `EvalError` from the predicate is
        treated as "not yet": a read that fails mid-settle should be retried
        within the budget, and the caller reports the failure if it never
        clears.
        """
        for attempt in range(attempts):
            try:
                if predicate():
                    return True
            except EvalError:
                if attempt == attempts - 1:
                    raise
            if attempt < attempts - 1:
                time.sleep(delay)
        return False

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

    def _pending_agent_approval_ceremony(self) -> str | None:
        """Resolve the owner approval that registers the session's API agent.

        Creating a session stages three owner ceremonies: the Signer key
        derivation and reusable route approval, both published under
        `petal-key-requests`, and then the `approve_agent` signature, published
        here. This projection carries no
        session id, so bind it as tightly as the available fields allow and
        refuse to act when more than one candidate matches.
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
            # An expired signing request stays listed but stops rendering, so
            # reading it fails with an IO error. A record this scan cannot read
            # is not a candidate for completion; refusing to scan at all would
            # let one stale entry block every later run.
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
                or record.get("operation_class") != "hyperliquid.approve_agent"
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
            raise EvalError("multiple agent-approval ceremonies match the exact wallet")
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

    @staticmethod
    def _is_base64url_signature(value: Any) -> bool:
        if not isinstance(value, str) or BASE64URL.fullmatch(value) is None:
            return False
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, binascii.Error):
            return False
        return len(decoded) == 64

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
            or route_index.get("package_hash") != self.package_hash
            or not isinstance(routes, list)
        ):
            raise EvalError(
                "installed Hyperliquid route index has an unsupported shape or package hash"
            )
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
        delegated_classes = route.get("key_derive_operation_classes")
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
        if delegated_classes != [HYPERLIQUID_AGENT_ACTION]:
            raise EvalError(
                "installed Hyperliquid agent-session route lacks the exact delegated operation class"
            )

        for candidate in routes:
            if not isinstance(candidate, dict):
                raise EvalError("installed Hyperliquid route index contains a malformed route")
            if candidate is not route and candidate.get("key_derive_operation_classes") not in (
                None,
                [],
            ):
                raise EvalError(
                    "installed Hyperliquid delegated operation class is scoped to the wrong route"
                )

        action_route_ids: set[str] = set()
        for pattern in HYPERLIQUID_SESSION_ACTION_ROUTES:
            action_matches = [
                candidate for candidate in routes if candidate.get("pattern") == pattern
            ]
            if len(action_matches) != 1:
                raise EvalError(
                    f"installed Hyperliquid package must contain exactly one child-key action route for {pattern}"
                )
            action_route = action_matches[0]
            action_route_id = action_route.get("route_id")
            action_metadata = action_route.get("install_metadata")
            action_caps = (
                action_metadata.get("required_caps")
                if isinstance(action_metadata, dict)
                else None
            )
            if (
                not isinstance(action_route_id, str)
                or re.fullmatch(r"r[0-9]{6}", action_route_id) is None
                or action_route_id == route_id
                or action_route_id in action_route_ids
                or not isinstance(action_caps, list)
                or any(not isinstance(capability, str) for capability in action_caps)
                or "bloom:sign" not in action_caps
                or not isinstance(action_metadata, dict)
                or action_metadata.get("sign_intent") != HYPERLIQUID_AGENT_ACTION
            ):
                raise EvalError(
                    f"installed Hyperliquid child-key action route {pattern} lacks bloom:sign or its exact operation class"
                )
            action_route_ids.add(action_route_id)

        unexpected_agent_action_routes = [
            candidate.get("pattern")
            for candidate in routes
            if isinstance(candidate.get("install_metadata"), dict)
            and candidate["install_metadata"].get("sign_intent")
            == HYPERLIQUID_AGENT_ACTION
            and candidate.get("pattern") not in HYPERLIQUID_SESSION_ACTION_ROUTES
        ]
        if unexpected_agent_action_routes:
            raise EvalError(
                "installed Hyperliquid package grants the child-key operation class to unexpected routes"
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
        record = matching_records[0]
        operation_classes = record.get("operation_classes")
        expected_operation_classes = [
            {"operation_class": HYPERLIQUID_AGENT_ACTION, "fee_asset": None},
            {"operation_class": "hyperliquid.approve_agent", "fee_asset": None},
        ]
        if operation_classes != expected_operation_classes:
            raise EvalError(
                "installed Hyperliquid agent-session provenance lacks the exact installer-signed operation classes"
            )
        if (
            not isinstance(record.get("publisher"), str)
            or not record["publisher"]
            or not isinstance(record.get("installer_key_id"), str)
            or not record["installer_key_id"]
            or not self._is_base64url_signature(record.get("installer_signature"))
        ):
            raise EvalError(
                "installed Hyperliquid agent-session provenance lacks installer signature material"
            )

        lineage = record.get("petal_lineage")
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
            or not lineage["controller_key_id"]
            or not self._is_base64url_signature(lineage.get("controller_signature"))
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

    @property
    def agent_name(self) -> str:
        """The venue-side name this eval registers its API agent under.

        Hyperliquid replaces a named agent when a new `approveAgent` arrives
        under the same name, so a name that is stable for the wallet means each
        run supersedes its predecessor instead of adding to the account. A name
        that varied per run would accumulate agents, and clearing them would
        mean deregistration, after which HyperCore may prune the agent's nonce
        state and re-registering that address becomes replay-unsafe.

        `BLOOM_EVAL_AGENT_NAME` adopts an existing agent instead of deriving a
        new one. A wallet that already carries an agent from an earlier naming
        scheme cannot otherwise be reconciled: the old name will never match a
        derived one, and the old agent cannot be safely removed. Naming it
        explicitly keeps the preflight check an exact match rather than
        widening it to a pattern, and records which agent the operator intends
        this eval to take over.
        """
        if self.agent_name_override:
            if len(self.agent_name_override) > 16:
                raise EvalError("BLOOM_EVAL_AGENT_NAME must be at most 16 characters")
            return self.agent_name_override
        digest = hashlib.sha256(
            b"bloom-eval-hyperliquid-agent/v1\0" + self.wallet_id.encode()
        ).hexdigest()
        return f"be-{digest[:8]}"

    def _require_empty_wallet(self) -> None:
        self._require_no_orders_or_positions()
        agents = self._read_json(self.user_root / "extra_agents.json")
        if not isinstance(agents, list):
            raise EvalError("extra-agents projection is not a JSON array")
        # This eval's own agent may legitimately still be registered: it is
        # superseded by name on the next run and is never deregistered. Any
        # other agent is delegated authority this eval did not create, and the
        # wallet is not safe to use.
        foreign = [
            agent
            for agent in agents
            if not isinstance(agent, dict) or agent.get("name") != self.agent_name
        ]
        if foreign:
            raise EvalError(
                "dedicated wallet retains a Hyperliquid API agent this eval did not create"
            )

    def _pull_eval_image(self) -> None:
        """Make the immutable Harbor image ready before creating authority."""
        try:
            completed = subprocess.run(
                ["docker", "pull", EVAL_IMAGE],
                check=False,
                capture_output=True,
                text=True,
                timeout=EVAL_IMAGE_PULL_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"could not pull pinned Harbor eval image: {error}") from error
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise EvalError(f"could not pull pinned Harbor eval image: {detail}")

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
        # Harbor otherwise discovers a missing image only after provision() has
        # created the bounded mainnet session and started its 30-minute clock.
        # Pulling the immutable digest here fails before any authority exists.
        self._pull_eval_image()
        self._require_empty_wallet()

    def provision(self, agent_name: str) -> EvalRunContext:
        sign_count = self.sign_count or self._require_sign_count()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        random_hex = secrets.token_hex(8)
        self.session_id = f"bloom-eval-{agent_name}-{stamp}-{random_hex}"
        cloid = "0x" + hashlib.sha256(self.session_id.encode()).hexdigest()[:32]
        # The `[wallet]` path segment is a Bloom wallet id, not an on-chain
        # address. Owner signing for `approve_agent` validates that segment as a
        # Broker token, which must start with a lowercase letter, so a `0x…`
        # address fails deep inside signing as an unqualified permission error.
        self.session_base = (
            self.network_root / "agent_sessions" / self.wallet_id / self.session_id
        )
        request = {
            "id": self.session_id,
            # Neither the wallet id nor the owner address is carried here. The
            # wallet id is the route parameter, and the owner address is
            # recovered by the Petal from the approveAgent signature; sending
            # either let the body disagree with the wallet actually being used.
            "agent_name": self.agent_name,
            "duration_ms": 1_800_000,
            "max_notional_usd": "11",
            "max_leverage": 1,
            "assets": ["0"],
        }
        body = json.dumps(request, separators=(",", ":")).encode()
        new_route = self.network_root / "agent_sessions" / self.wallet_id / "new.json"

        first = self._write_route(new_route, body, SESSION_WRITE_TIMEOUT_SECONDS)
        output = (first.stdout + first.stderr).decode(errors="replace")
        last_output = output
        status_data: Any | None = None

        # Creating a session stages more than one owner ceremony: the Signer
        # key derivation, the reusable typed-route approval, then the
        # `approve_agent` signature that registers the agent with the venue.
        # Completing only the first leaves the session
        # permanently pending, so drive ceremonies until a bounded session
        # exists. Each WebAuthn completion must use a strictly greater counter
        # than the last accepted one, so the counter advances per ceremony and
        # is never reused.
        counter = sign_count
        # A ceremony's owner-visible projection lags its completion, so the same
        # ceremony can still resolve as pending immediately after it succeeded.
        # Completing it twice fails against a consumed session, so remember what
        # this provision has already driven and wait for the session instead.
        completed_ceremonies: set[str] = set()
        for _ in range(MAX_SESSION_CEREMONIES):
            ceremony_url: str | None = None
            # Mounted Petal writes are asynchronous. A zero write exit code
            # means accepted for dispatch, not that the route completed.
            for _ in range(CEREMONY_DISCOVERY_ATTEMPTS):
                status_data = self._read_json_if_exists(
                    self.session_base / "status.json"
                )
                if status_data is not None:
                    break
                match = CEREMONY_URL.search(last_output)
                ceremony_url = (
                    match.group(0)
                    if match is not None
                    else (
                        self._pending_petal_key_ceremony()
                        or self._pending_agent_approval_ceremony()
                    )
                )
                if ceremony_url is not None and ceremony_url not in completed_ceremonies:
                    break
                ceremony_url = None
                time.sleep(0.2)

            if status_data is not None or ceremony_url is None:
                break

            # One attempt only. The Broker marks a consumed or absent ceremony
            # CEREMONY_REPLAY with retry "never", so a second attempt cannot
            # succeed and only burns another WebAuthn counter. An earlier
            # revision retried here on the theory that a freshly published
            # ceremony URL might not yet resolve; that theory was wrong, and the
            # retries turned one failure into three.
            try:
                completed = subprocess.run(
                    [
                        str(self.driver),
                        "complete",
                        ceremony_url,
                        "--authenticator-seed-file",
                        str(self.seed_file),
                        "--sign-count",
                        str(counter),
                    ],
                    check=False,
                    capture_output=True,
                    timeout=45,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise EvalError(
                    "debug-driver ceremony completion failed: "
                    + self._redact_ceremony_urls(str(error))
                ) from error
            output += (completed.stdout + completed.stderr).decode(errors="replace")
            counter += 1
            self.next_sign_count = counter
            if completed.returncode != 0:
                raise EvalError(
                    f"session ceremony failed at sign count {counter - 1} "
                    f"(next unused counter is {counter}): "
                    + self._redact_ceremony_urls(output)
                )
            completed_ceremonies.add(ceremony_url)

            # Replay byte-identical session terms only after the owner ceremony
            # succeeds; WebAuthn counter reuse is never attempted.
            retry = self._write_route(new_route, body, SESSION_WRITE_TIMEOUT_SECONDS)
            last_output = (retry.stdout + retry.stderr).decode(errors="replace")
            output += last_output

        if status_data is None:
            raise EvalError(
                "session creation failed without durable session or ceremony "
                f"readback after consuming sign counts {sign_count}..{counter - 1} "
                f"(next unused counter is {counter}): "
                + self._redact_ceremony_urls(output)
            )

        self.session_created = True
        expected = {
            # The session's status projection does not carry a schema tag. The
            # Petal's Session type has one, but the status route builds its JSON
            # field by field and omits it, so requiring it here fails every
            # session. The bounded terms below are what this check exists to
            # enforce; the schema tag would be a useful addition to the
            # projection, but asserting a field the surface never emits is not a
            # check, it is an outage.
            "network": "mainnet",
            # The session records the `[wallet]` route parameter, which is a
            # Bloom wallet id. The on-chain address is reported separately as
            # `agent_address`.
            "wallet": self.wallet_id,
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
            f"{self.wallet_id}/{self.session_id}"
        )
        mounts.extend(
            {
                "type": "bind",
                "source": str(self.session_base / action),
                "target": f"{container_base}/{action}",
            }
            for action in ACTION_FILES
        )
        # Both identifiers are required and are not interchangeable. Session
        # routes are addressed by wallet id; Hyperliquid account queries under
        # `users/[account]/` are addressed by the on-chain address.
        runtime_env = {
            "BLOOM_EVAL_WALLET": self.wallet,
            "BLOOM_EVAL_WALLET_ID": self.wallet_id,
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
            # Both projections have to be checked. Creating a session stages two
            # owner ceremonies, and the second one outlives the first: once key
            # derivation completes, `approve_agent` can sit awaiting approval
            # while `session.json` still does not exist. The key projection is
            # then already consumed and `_require_empty_wallet` passes, because
            # the agent was never registered at the venue. Checking only the key
            # ceremony reports a clean cleanup over an open owner ceremony.
            for pending, label in (
                (self._pending_petal_key_ceremony, "Petal key"),
                (self._pending_agent_approval_ceremony, "agent approval"),
            ):
                try:
                    if pending() is not None:
                        failures.append(
                            f"matching {label} ceremony is still awaiting user action"
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
            def no_open_orders() -> bool:
                orders = self._read_json(self.user_root / "open_orders.json")
                return isinstance(orders, list) and not orders

            if not self._poll_until(
                no_open_orders, VENUE_SETTLE_ATTEMPTS, VENUE_SETTLE_DELAY_SECONDS
            ):
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
                elif not self._poll_until(
                    lambda: not self._nonzero_positions(),
                    VENUE_SETTLE_ATTEMPTS,
                    VENUE_SETTLE_DELAY_SECONDS,
                ):
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
            def session_stopped() -> bool:
                final_status = self._read_json(self.session_base / "status.json")
                return (
                    isinstance(final_status, dict)
                    and final_status.get("stopped") is True
                )

            if not self._poll_until(
                session_stopped, STATUS_SETTLE_ATTEMPTS, STATUS_SETTLE_DELAY_SECONDS
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
