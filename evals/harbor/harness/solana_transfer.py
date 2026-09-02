"""Host-side lifecycle for the bounded Solana native-transfer evaluation.

The Hyperliquid eval is safe because its primitive is reversible: place, then
cancel, where the undo is also the proof. A SOL transfer has no undo, so three
parts of that safety model are replaced here.

* The bound is the compile-time canary authorization rather than a bounded
  venue session. It pins one artifact, one wallet, one key, one destination, an
  exact amount, a fee ceiling, a balance ceiling, and a single use.
* The binding between the chain record and this trial is a fresh
  host-controlled destination plus that exact amount, rather than a
  host-generated client order id.
* Cleanup sweeps the destination back to the source with a host-held key, so
  only the fee is actually spent. The container never sees that key.

`--lane local` drops the canary requirement and runs against a local validator,
because a non-mainnet genesis is already permitted to broadcast. `--lane
mainnet-canary` requires the authorization and the acknowledgement.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .core import (
    CEREMONY_URL,
    CeremonyDriver,
    EvalDefinition,
    EvalError,
    EvalRunContext,
    MountedTree,
    SignCountStore,
    resolve_sign_count,
)

MAINNET_ACK = "TRANSFER_SOL_MAINNET_UP_TO_THE_AUTHORIZED_AMOUNT"
AUTHORIZATION_SCHEMA = "bloom.solana-mainnet-canary/1"
MAINNET_NETWORK = "mainnet-beta"

BASE58 = "[1-9A-HJ-NP-Za-km-z]"
ADDRESS = re.compile(f"{BASE58}{{32,44}}")
WALLET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
CHAIN_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
FINGERPRINT = re.compile(r"[0-9a-f]{16,64}")
DERIVATION = re.compile(r"m/44'/501'/\d+'/0'")

# A ceiling the harness enforces independently of the authorization file, so a
# fat-fingered authorization cannot widen the blast radius. 0.05 SOL.
HARNESS_MAX_BALANCE_LAMPORTS = 50_000_000
HARNESS_MAX_TRANSFER_LAMPORTS = 20_000_000
# Refuse an authorization that is about to expire mid-trial.
MIN_AUTHORIZATION_WINDOW_MS = 10 * 60 * 1000

# Mounted chain reads wait on an RPC round trip, not a disk.
CHAIN_READ_TIMEOUT_SECONDS = 45
CHAIN_READ_ATTEMPTS = 3
ROUTE_WRITE_TIMEOUT_SECONDS = 120

# The agent drives the confirm, so its ceremony is published while Harbor is
# running. The approver polls for it rather than the host completing every
# ceremony up front the way the Hyperliquid provision does.
APPROVER_POLL_SECONDS = 2.0
APPROVER_BUDGET_SECONDS = 420.0
# One confirm ceremony, plus at most one first-use key derivation. The cap
# bounds a misbehaving route rather than describing the expected count.
MAX_TRANSFER_CEREMONIES = 3

RPC_TIMEOUT_SECONDS = 30
SWEEP_TIMEOUT_SECONDS = 180
SWEEP_SETTLE_ATTEMPTS = 20
SWEEP_SETTLE_DELAY_SECONDS = 3.0

PENDING_DRAIN_ATTEMPTS = 30
PENDING_DRAIN_DELAY_SECONDS = 2.0
RECEIPT_SETTLE_ATTEMPTS = 45
RECEIPT_SETTLE_DELAY_SECONDS = 2.0
SMOKE_CONFIRM_BUDGET_SECONDS = 45.0


def trial_amount(base_lamports: int, trial_id: str) -> int:
    """Give the amount a per-trial low-order tail.

    The tail turns the amount itself into a fingerprint, so the destination's
    single transaction can be matched on value as well as on address. It stays
    well inside the authorized ceiling because the caller picks `base`.
    """
    tail = int(hashlib.sha256(trial_id.encode()).hexdigest()[:4], 16) % 10_000
    return base_lamports + tail


class SolanaTransferEval(EvalDefinition):
    name = "solana-transfer"

    def __init__(self, repo_root: Path, environ: dict[str, str] | None = None) -> None:
        self.repo_root = repo_root.resolve()
        self.env = dict(os.environ if environ is None else environ)
        self.lane = self.env.get("BLOOM_EVAL_SOLANA_LANE", "mainnet-canary")
        self.wallet_id = self.env.get("BLOOM_EVAL_SOLANA_WALLET_ID", "")
        self.chain = self.env.get("BLOOM_EVAL_SOLANA_CHAIN", "")
        self.network = self.env.get("BLOOM_EVAL_SOLANA_NETWORK", "")
        self.rpc_url = self.env.get("BLOOM_EVAL_SOLANA_RPC_URL", "")
        self.bloom_mount_value = self.env.get("BLOOM_EVAL_BLOOM_MOUNT", "").strip()
        self.bloom_mount = Path(self.bloom_mount_value)
        self.authorization_value = self.env.get(
            "BLOOM_EVAL_SOLANA_CANARY_AUTHORIZATION", ""
        )
        self.authorization_path = Path(self.authorization_value)
        self.machine_binary = Path(self.env.get("BLOOM_EVAL_SOLANA_MACHINE_BINARY", ""))
        # The Machine's home root, on the host filesystem. The approver reads
        # the canonical approval challenge here so its decision is unaffected
        # by mount latency or a projection changing during a read.
        self.home_root = Path(self.env.get("BLOOM_EVAL_SOLANA_HOME_ROOT", ""))
        self.solana_cli = self.env.get("BLOOM_EVAL_SOLANA_CLI", "solana")
        self.sweep_keypair = Path(
            self.env.get("BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE", "")
        )
        self.driver = Path(
            self.env.get(
                "BLOOM_EVAL_DEBUG_DRIVER_BIN",
                str(
                    self.repo_root.parent
                    / "bloom-broker/target/debug/bloom-broker-debug-driver"
                ),
            )
        )
        self.seed_file = Path(
            self.env.get("BLOOM_EVAL_AUTHENTICATOR_SEED_FILE", "")
        )
        self.sign_count_value = self.env.get("BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT", "")
        self.sign_count: int | None = None
        self.next_sign_count: int | None = None
        self.jobs_dir = Path(
            self.env.get(
                "BLOOM_EVAL_JOBS_DIR", str(self.repo_root / "evals/harbor/jobs")
            )
        )
        self._lock_path = Path(
            self.env.get("BLOOM_EVAL_LOCK_FILE", "/tmp/bloom-harbor-solana.lock")
        )
        self.authorization: dict[str, Any] | None = None
        self.destination = ""
        self.lamports = 0
        self.max_fee_lamports = 0
        self.source_address = ""
        self.key_fingerprint = ""
        self.derivation_path = ""
        self.trial_id: str | None = None
        self.mount = MountedTree(
            read_timeout=CHAIN_READ_TIMEOUT_SECONDS,
            read_attempts=CHAIN_READ_ATTEMPTS,
        )
        self._approver: threading.Thread | None = None
        self._approver_stop = threading.Event()
        self._approver_error: str | None = None
        self._approver_completed = 0
        self._baseline_sent: set[str] = set()

    # ---- paths ---------------------------------------------------------

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    @property
    def sign_counts(self) -> SignCountStore:
        return SignCountStore.for_seed_file(
            self.seed_file, self.env.get("BLOOM_EVAL_SIGN_COUNT_FILE", "")
        )

    @property
    def wallet_root(self) -> Path:
        return self.bloom_mount / "wallets" / self.wallet_id

    @property
    def chain_root(self) -> Path:
        return self.wallet_root / "chains" / self.chain

    @property
    def outbox_root(self) -> Path:
        return self.chain_root / "outbox"

    @property
    def host_outbox_root(self) -> Path:
        """The Solana outbox on the host filesystem, not through the mount.

        `HomeDir::solana_outbox_dir` is `<home>/.solana-outbox`, and entries
        live at `<root>/<wallet>/<chain>/<state>/<id>/`.
        """
        return self.home_root / ".solana-outbox" / self.wallet_id / self.chain

    def _host_entry(self, state: str, entry_id: str) -> Path:
        return self.host_outbox_root / state / entry_id

    # ---- small helpers -------------------------------------------------

    def _require_sign_count(self) -> int:
        return resolve_sign_count(
            self.sign_count_value,
            self.sign_counts,
            "BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT",
        )

    def _list_state(self, state: str) -> list[str]:
        try:
            return sorted(os.listdir(self.outbox_root / state))
        except FileNotFoundError:
            return []
        except OSError as error:
            raise EvalError(f"could not list outbox/{state}: {error}") from error

    def _list_host_state(self, state: str) -> list[str]:
        """List outbox entries from the host state directory.

        The approver uses this rather than the mount: its decision must not be
        delayed by a live chain read behind a directory listing.
        """
        try:
            return sorted(os.listdir(self.host_outbox_root / state))
        except FileNotFoundError:
            return []
        except OSError as error:
            raise EvalError(f"could not list host outbox/{state}: {error}") from error

    def _read_private_json(self, path: Path, label: str) -> Any:
        """Read a local, immutable host file. Never a mounted path."""
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise EvalError(f"could not read {label}: {error}") from error
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise EvalError(f"{label} is not valid JSON: {error}") from error

    def _load_local_account_identity(self) -> None:
        """Resolve the one active Solana child from Broker's public projection."""
        projection = self.mount.read_json(self.wallet_root / "accounts.json")
        if not isinstance(projection, dict) or projection.get("wallet_id") != self.wallet_id:
            raise EvalError("wallet accounts projection does not match the selected wallet")
        accounts = projection.get("accounts")
        if not isinstance(accounts, list):
            raise EvalError("wallet accounts projection has no account list")
        solana = [
            account
            for account in accounts
            if isinstance(account, dict)
            and account.get("derivation_profile")
            == "bip44-solana-slip10-ed25519-v1"
            and account.get("lifecycle") == "ACTIVE"
        ]
        if len(solana) != 1:
            raise EvalError(
                "local eval wallet must have exactly one active Solana account; "
                f"found {len(solana)}"
            )
        account = solana[0]
        fingerprint = account.get("public_key_fingerprint")
        path = account.get("path")
        if not isinstance(fingerprint, str) or FINGERPRINT.fullmatch(fingerprint) is None:
            raise EvalError("Solana account projection has a malformed fingerprint")
        if not isinstance(path, str) or DERIVATION.fullmatch(path) is None:
            raise EvalError("Solana account projection has a malformed derivation path")
        address_path = self.chain_root / "accounts" / fingerprint / "address"
        try:
            completed = subprocess.run(
                ["cat", str(address_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=CHAIN_READ_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"could not read Solana account address: {error}") from error
        address = completed.stdout.strip()
        if ADDRESS.fullmatch(address) is None:
            raise EvalError("Solana account projection has a malformed address")
        self.source_address = address
        self.key_fingerprint = fingerprint
        self.derivation_path = path

    def _require_sweep_keypair(self) -> None:
        """Prove the host controls the configured cleanup destination."""
        if not str(self.sweep_keypair):
            raise EvalError("BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE is required")
        try:
            keypair_stat = self.sweep_keypair.lstat()
        except OSError as error:
            raise EvalError(f"sweep keypair is unavailable: {error}") from error
        if not stat.S_ISREG(keypair_stat.st_mode) or self.sweep_keypair.is_symlink():
            raise EvalError("sweep keypair must be a regular non-symlink file")
        if stat.S_IMODE(keypair_stat.st_mode) != 0o600:
            raise EvalError("sweep keypair must have mode 0600")
        try:
            completed = subprocess.run(
                [self.solana_cli, "address", "--keypair", str(self.sweep_keypair)],
                capture_output=True,
                check=False,
                text=True,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"could not inspect sweep keypair address: {error}") from error
        if completed.returncode != 0:
            raise EvalError(
                "could not inspect sweep keypair address: "
                + (completed.stderr or completed.stdout).strip()
            )
        observed = completed.stdout.strip()
        if observed != self.destination:
            raise EvalError(
                "BLOOM_EVAL_SOLANA_DESTINATION is not controlled by the configured "
                "sweep keypair"
            )

    # ---- authorization -------------------------------------------------

    def authorization_preflight(self) -> dict[str, Any]:
        """Validate the canary authorization from local files only.

        No ceremony, no mounted write, no Docker job, and no chain call is
        possible in this mode, so it is safe to run while the wallet is still
        empty and before any authority exists.
        """
        if not self.authorization_value:
            raise EvalError(
                "BLOOM_EVAL_SOLANA_CANARY_AUTHORIZATION is required on the "
                "mainnet-canary lane"
            )
        try:
            auth_stat = self.authorization_path.lstat()
        except OSError as error:
            raise EvalError(f"canary authorization is unavailable: {error}") from error
        if not stat.S_ISREG(auth_stat.st_mode) or self.authorization_path.is_symlink():
            raise EvalError(
                "canary authorization must be a regular non-symlink file"
            )
        if stat.S_IMODE(auth_stat.st_mode) != 0o600:
            raise EvalError("canary authorization must have mode 0600")

        auth = self._read_private_json(self.authorization_path, "canary authorization")
        if not isinstance(auth, dict):
            raise EvalError("canary authorization is not an object")

        if auth.get("schema") != AUTHORIZATION_SCHEMA:
            raise EvalError(f"canary authorization schema is not {AUTHORIZATION_SCHEMA}")
        # `max_transactions` must be exactly 1. Bloom enforces this too; the
        # harness refuses independently so a widened file never reaches it.
        if auth.get("max_transactions") != 1:
            raise EvalError("canary authorization must permit exactly one transaction")

        spent = self.authorization_path.with_name(self.authorization_path.name + ".spent")
        if spent.exists():
            raise EvalError(
                f"canary authorization is already spent ({spent}); issue a new one"
            )

        expires = auth.get("expires_ms")
        if not isinstance(expires, int):
            raise EvalError("canary authorization has no integer expires_ms")
        remaining = expires - int(time.time() * 1000)
        if remaining < MIN_AUTHORIZATION_WINDOW_MS:
            raise EvalError(
                "canary authorization expires too soon to run a trial "
                f"({remaining}ms left); issue a new one"
            )

        for field, pattern, label in (
            ("chain", CHAIN_NAME, "chain"),
            ("wallet", WALLET_ID, "wallet"),
            ("source_address", ADDRESS, "source address"),
            ("destination", ADDRESS, "destination"),
            ("key_fingerprint", FINGERPRINT, "key fingerprint"),
            ("derivation_path", DERIVATION, "derivation path"),
        ):
            value = auth.get(field)
            if not isinstance(value, str) or pattern.fullmatch(value) is None:
                raise EvalError(f"canary authorization has a malformed {label}")

        if auth["chain"] != self.chain:
            raise EvalError(
                f"canary authorization is for chain '{auth['chain']}', not '{self.chain}'"
            )
        if auth["wallet"] != self.wallet_id:
            raise EvalError(
                f"canary authorization is for wallet '{auth['wallet']}', "
                f"not '{self.wallet_id}'"
            )

        transfer = auth.get("transfer_lamports")
        balance_cap = auth.get("max_balance_lamports")
        fee_cap = auth.get("max_fee_lamports")
        for value, label in (
            (transfer, "transfer_lamports"),
            (balance_cap, "max_balance_lamports"),
            (fee_cap, "max_fee_lamports"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise EvalError(f"canary authorization has a malformed {label}")
        assert isinstance(transfer, int) and isinstance(balance_cap, int)
        assert isinstance(fee_cap, int)

        # The harness ceiling is independent of the file on purpose.
        if transfer > HARNESS_MAX_TRANSFER_LAMPORTS:
            raise EvalError(
                f"authorized transfer {transfer} exceeds the harness ceiling "
                f"{HARNESS_MAX_TRANSFER_LAMPORTS}"
            )
        if balance_cap > HARNESS_MAX_BALANCE_LAMPORTS:
            raise EvalError(
                f"authorized balance cap {balance_cap} exceeds the harness ceiling "
                f"{HARNESS_MAX_BALANCE_LAMPORTS}"
            )
        if transfer + fee_cap > balance_cap:
            raise EvalError(
                "authorized transfer plus fee exceeds the authorized balance cap"
            )

        self._require_artifact_binding(auth)
        self._require_host_controlled_destination(auth)
        self.authorization = auth
        return auth

    def _require_artifact_binding(self, auth: dict[str, Any]) -> None:
        """Bind the authorization to the exact Machine binary that will run."""
        digest = auth.get("artifact_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise EvalError("canary authorization has a malformed artifact_sha256")
        if not str(self.machine_binary):
            raise EvalError(
                "BLOOM_EVAL_SOLANA_MACHINE_BINARY is required so the authorization's "
                "artifact digest can be checked against the binary that will run"
            )
        if not self.machine_binary.is_file():
            raise EvalError(f"Machine binary is missing: {self.machine_binary}")
        observed = hashlib.sha256(self.machine_binary.read_bytes()).hexdigest()
        if observed != digest:
            raise EvalError(
                "canary authorization is bound to a different artifact: "
                f"authorization {digest}, binary {observed}"
            )

    def _require_host_controlled_destination(self, auth: dict[str, Any]) -> None:
        """Refuse any destination the host cannot sweep back from.

        A destination the host does not hold the key for turns a bounded,
        recoverable trial into an unrecoverable one.
        """
        expected = self.env.get("BLOOM_EVAL_SOLANA_DESTINATION", "")
        if not expected:
            raise EvalError("BLOOM_EVAL_SOLANA_DESTINATION is required")
        if auth["destination"] != expected:
            raise EvalError(
                "canary authorization destination is not the host-controlled "
                "sweep address"
            )
        self.destination = expected
        self._require_sweep_keypair()

    # ---- preflight -----------------------------------------------------

    def preflight(self) -> None:
        if not self.bloom_mount_value:
            raise EvalError("BLOOM_EVAL_BLOOM_MOUNT is required for a full eval")
        if self.lane not in ("local", "mainnet-canary"):
            raise EvalError(f"unknown lane {self.lane!r}; use local or mainnet-canary")
        if WALLET_ID.fullmatch(self.wallet_id) is None:
            raise EvalError("BLOOM_EVAL_SOLANA_WALLET_ID is required and must be a token")
        if CHAIN_NAME.fullmatch(self.chain) is None:
            raise EvalError("BLOOM_EVAL_SOLANA_CHAIN is required and must be a token")
        if not self.rpc_url:
            raise EvalError("BLOOM_EVAL_SOLANA_RPC_URL is required")

        # Lane and network are checked before anything else. They are the
        # "did the operator mean this" gates, and burying them behind a seed
        # file or driver check would answer a dangerous misconfiguration with
        # an unrelated error message.
        if self.lane == "mainnet-canary":
            if self.env.get("BLOOM_EVAL_SOLANA_MAINNET_ACK") != MAINNET_ACK:
                raise EvalError(
                    f"set BLOOM_EVAL_SOLANA_MAINNET_ACK={MAINNET_ACK} to authorize "
                    "this mainnet trial"
                )
            if self.network != MAINNET_NETWORK:
                raise EvalError(
                    f"the mainnet-canary lane requires network {MAINNET_NETWORK}"
                )
            auth = self.authorization_preflight()
            self.destination = auth["destination"]
            self.lamports = auth["transfer_lamports"]
            self.max_fee_lamports = auth["max_fee_lamports"]
            self.source_address = auth["source_address"]
            self.key_fingerprint = auth["key_fingerprint"]
            self.derivation_path = auth["derivation_path"]
        else:
            # The local lane needs no canary: a non-mainnet genesis is already
            # permitted to broadcast, and the validator's funds are worthless.
            if self.network == MAINNET_NETWORK:
                raise EvalError(
                    "the local lane must not be pointed at mainnet-beta; use the "
                    "mainnet-canary lane"
                )
            self.destination = self.env.get("BLOOM_EVAL_SOLANA_DESTINATION", "")
            if ADDRESS.fullmatch(self.destination) is None:
                raise EvalError("BLOOM_EVAL_SOLANA_DESTINATION must be a base58 address")

        # The approver reads the canonical host-side approval challenge the
        # confirm route stages. Current outboxes also project a sanitized copy
        # to the owner filesystem; the host copy remains the stable boundary
        # for matching the exact authorized intent before approval.
        if not str(self.home_root):
            raise EvalError(
                "BLOOM_EVAL_SOLANA_HOME_ROOT is required so the host approver "
                "can read stable outbox state"
            )
        if not self.home_root.is_dir():
            raise EvalError(f"Machine home root is not a directory: {self.home_root}")

        self.sign_count = self._require_sign_count()
        CeremonyDriver(self.driver, self.seed_file, self.sign_count).preflight()

        # Cleanup must be able to return the lamports. Discovering that the
        # sweep tool or key is missing after a broadcast is too late, including
        # on the local lane where unattended repeated trials depend on cleanup.
        self._require_sweep_tool()
        self._require_sweep_keypair()

        if not os.path.ismount(self.bloom_mount):
            raise EvalError(f"Bloom is not mounted at {self.bloom_mount}")
        # Docker silently creates an empty directory at a missing bind source,
        # which would mask the real outbox and fail baffingly inside the
        # container. Refuse before constructing the mount instead.
        if not self.outbox_root.is_dir():
            raise EvalError(
                f"wallet outbox is not present at {self.outbox_root}; the wallet "
                "may not have this Solana chain configured"
            )
        if not (self.outbox_root / "new.tx").exists():
            raise EvalError(f"{self.outbox_root}/new.tx is missing; the chain is not writable")

        if self.lane == "local":
            self._load_local_account_identity()

        pending = self._list_state("pending")
        if pending:
            raise EvalError(
                f"dedicated wallet already has {len(pending)} outbox/pending "
                "entries; inspect and clear them before a trial"
            )
        # Reconciled sent entries are immutable history, not live authority.
        # Snapshot them so this trial can safely reuse the wallet while cleanup
        # reasons only about entries created after preflight.
        self._baseline_sent = set(self._list_state("sent"))
        for sent_id in self._baseline_sent:
            receipt = self.mount.read_json_if_listed(
                self.outbox_root / "sent" / sent_id / "receipt.json",
                self.outbox_root / "sent",
                sent_id,
            )
            if not isinstance(receipt, dict) or receipt.get("outcome") is None:
                raise EvalError(
                    f"historical sent entry {sent_id} has not reconciled to a receipt"
                )

    def preauthorization_preflight(self) -> None:
        """Local-file-only validation, for use before any authority exists."""
        if self.lane != "mainnet-canary":
            raise EvalError("--authorization-only applies to the mainnet-canary lane")
        self.authorization_preflight()

    # ---- background approver -------------------------------------------

    def _pending_confirm_ceremony(self, pending_id: str) -> str | None:
        """The ceremony URL staged by a failed confirm, if one is published.

        Current Solana outboxes publish `approval_challenge.json` as the
        canonical resume projection. Read the host-side copy rather than the
        mount so approval matching cannot be delayed or confused by NFS.
        """
        approval = self._read_host_json(
            self._host_entry("pending", pending_id) / "approval_challenge.json"
        )
        if not isinstance(approval, dict):
            return None
        url = approval.get("ceremony_url")
        if url is None:
            return None
        if not isinstance(url, str) or CEREMONY_URL.fullmatch(url) is None:
            raise EvalError("staged approval has an invalid ceremony URL")
        return url

    def _read_host_json(self, path: Path) -> Any | None:
        """Read a host-side outbox artifact, or None when it does not exist."""
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EvalError(f"could not read {path}: {error}") from error
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # The file is written atomically, so a torn read means we caught a
            # rename in flight. Treat it as not-yet-published.
            return None

    def _ceremony_matches_authorized_transfer(self, pending_id: str) -> bool:
        """Refuse to approve anything but the exact authorized transfer.

        The approver runs while the agent is live, so it must never be a
        rubber stamp for whatever the agent happened to stage. This is an
        independent check from the canary: the canary refuses at broadcast,
        this refuses at approval.

        The staged intent is read from the host state directory rather than
        through the mount, so the decision cannot be affected by mount latency
        or by a projection replaced mid-read.
        """
        intent = self._read_host_json(
            self._host_entry("pending", pending_id) / "intent.json"
        )
        if not isinstance(intent, dict):
            return False
        if intent.get("destination") != self.destination:
            return False
        if intent.get("lamports") != self.lamports:
            return False
        if self.source_address and intent.get("fee_payer") != self.source_address:
            return False
        fee = intent.get("fee_lamports")
        if self.max_fee_lamports and (
            not isinstance(fee, int) or fee > self.max_fee_lamports
        ):
            return False
        # The staged entry pins the exact derived child it was built for, so the
        # approver can check the same signing identity the canary will check
        # again at broadcast. A second active child must never be able to have a
        # message approved that was staged against the first.
        fingerprint = intent.get("account_fingerprint")
        if self.key_fingerprint and isinstance(fingerprint, str):
            if fingerprint.lower() != self.key_fingerprint.lower():
                return False
        derivation = intent.get("account_derivation_path")
        if self.derivation_path and isinstance(derivation, str):
            if derivation != self.derivation_path:
                return False
        return True

    def _approve_loop(self, ceremonies: CeremonyDriver) -> None:
        deadline = time.monotonic() + APPROVER_BUDGET_SECONDS
        while not self._approver_stop.is_set() and time.monotonic() < deadline:
            try:
                pending = self._list_host_state("pending")
                for pending_id in pending:
                    url = self._pending_confirm_ceremony(pending_id)
                    if url is None or url in ceremonies.completed:
                        continue
                    if not self._ceremony_matches_authorized_transfer(pending_id):
                        self._approver_error = (
                            f"staged entry {pending_id} does not match the authorized "
                            "transfer; refusing to approve it"
                        )
                        return
                    ceremonies.complete(url)
                    self._approver_completed += 1
                    self.next_sign_count = ceremonies.next_sign_count
                    if self._approver_completed >= MAX_TRANSFER_CEREMONIES:
                        return
            except EvalError as error:
                self._approver_error = CeremonyDriver.redact(str(error))
                self.next_sign_count = ceremonies.next_sign_count
                return
            self._approver_stop.wait(APPROVER_POLL_SECONDS)

    def _start_approver(self, sign_count: int) -> None:
        ceremonies = CeremonyDriver(
            self.driver, self.seed_file, sign_count, store=self.sign_counts
        )
        self.next_sign_count = ceremonies.next_sign_count
        self._approver = threading.Thread(
            target=self._approve_loop,
            args=(ceremonies,),
            name="bloom-solana-approver",
            daemon=True,
        )
        self._approver.start()

    def _stop_approver(self) -> None:
        self._approver_stop.set()
        if self._approver is not None:
            self._approver.join(timeout=30)
            self._approver = None

    # ---- host sweep ----------------------------------------------------

    def _require_sweep_tool(self) -> None:
        try:
            version = subprocess.run(
                [self.solana_cli, "--version"],
                capture_output=True,
                check=False,
                text=True,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(
                f"the Solana CLI ({self.solana_cli}) is required for host cleanup "
                f"but could not be run: {error}"
            ) from error
        if version.returncode != 0:
            raise EvalError(
                f"the Solana CLI ({self.solana_cli}) is required for host cleanup "
                f"but failed: {version.stderr.strip()}"
            )

    def _rpc(self, method: str, params: list[Any]) -> Any:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self.rpc_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=RPC_TIMEOUT_SECONDS) as response:
                payload = json.loads(response.read())
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
            raise EvalError(f"Solana {method} failed: {error}") from error
        if "error" in payload:
            raise EvalError(f"Solana {method} returned an error: {payload['error']}")
        return payload.get("result")

    def _balance(self, address: str) -> int:
        result = self._rpc("getBalance", [address, {"commitment": "finalized"}])
        if not isinstance(result, dict) or not isinstance(result.get("value"), int):
            raise EvalError(f"could not read the finalized balance of {address}")
        return result["value"]

    def sweep_destination(self) -> str | None:
        """Return the destination's lamports to the source.

        This is what makes the eval economically reversible and therefore
        repeatable: the transfer itself cannot be undone, but the destination
        is host-controlled, so the lamports come back and only the fees are
        actually spent. The container never sees this key.

        Returns the sweep signature, or None when there was nothing to sweep.
        """
        balance = self._balance(self.destination)
        if balance == 0:
            return None
        # `ALL` drains the account and lets the CLI compute the fee, which
        # avoids leaving dust behind or over-spending on a hand-computed
        # amount. The destination is a plain system account with no rent-exempt
        # reserve to preserve, so draining it fully is correct.
        command = [
            self.solana_cli,
            "transfer",
            self.source_address,
            "ALL",
            "--from",
            str(self.sweep_keypair),
            "--fee-payer",
            str(self.sweep_keypair),
            "--keypair",
            str(self.sweep_keypair),
            "--url",
            self.rpc_url,
            "--commitment",
            "finalized",
            "--allow-unfunded-recipient",
            "--output",
            "json",
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, check=False, text=True, timeout=SWEEP_TIMEOUT_SECONDS
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"host sweep failed to run: {error}") from error
        if completed.returncode != 0:
            raise EvalError(
                "host sweep failed: " + (completed.stderr or completed.stdout).strip()
            )
        signature = None
        try:
            parsed = json.loads(completed.stdout)
            if isinstance(parsed, dict):
                signature = parsed.get("signature")
        except json.JSONDecodeError:
            signature = completed.stdout.strip() or None

        # Confirm from the chain rather than trusting the CLI's exit code.
        if not self.mount.poll_until(
            lambda: self._balance(self.destination) == 0,
            SWEEP_SETTLE_ATTEMPTS,
            SWEEP_SETTLE_DELAY_SECONDS,
        ):
            raise EvalError(
                f"host sweep did not drain {self.destination}; "
                f"{self._balance(self.destination)} lamports remain"
            )
        return signature

    # ---- provision -----------------------------------------------------

    def provision(self, agent_name: str) -> EvalRunContext:
        sign_count = self.sign_count or self._require_sign_count()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.trial_id = f"bloom-eval-{agent_name}-{stamp}-{secrets.token_hex(8)}"

        if self.lane == "local":
            # Only the local lane may choose its own amount; on the canary lane
            # the authorization pins it and the harness must not deviate.
            base = int(self.env.get("BLOOM_EVAL_SOLANA_BASE_LAMPORTS", "1000000"))
            self.lamports = trial_amount(base, self.trial_id)
            self.max_fee_lamports = int(
                self.env.get("BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS", "10000")
            )

        mounts: list[dict[str, Any]] = [
            {
                "type": "bind",
                "source": str(self.bloom_mount),
                "target": "/bloom",
                "read_only": True,
            },
            # The pending entry id is allocated by the daemon when the agent
            # stages, so the confirm path cannot be enumerated before the
            # container starts. Over-mount the outbox subtree instead. The
            # Docker read-only flag is defence in depth; the authority boundary
            # is the VFS mode -- everything under outbox/ is 0444 except
            # new.tx and a pending entry's confirm/cancel/restage -- plus
            # Broker policy, the passkey ceremony, and the canary.
            {
                "type": "bind",
                "source": str(self.outbox_root),
                "target": (
                    f"/bloom/wallets/{self.wallet_id}/chains/{self.chain}/outbox"
                ),
            },
        ]

        verifier_env = {
            "BLOOM_EVAL_SOLANA_WALLET_ID": self.wallet_id,
            "BLOOM_EVAL_SOLANA_CHAIN": self.chain,
            "BLOOM_EVAL_SOLANA_RPC_URL": self.rpc_url,
            "BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS": str(self.max_fee_lamports),
            "BLOOM_EVAL_SOLANA_SOURCE": self.source_address,
            "BLOOM_EVAL_SOLANA_DESTINATION": self.destination,
            "BLOOM_EVAL_SOLANA_LAMPORTS": str(self.lamports),
        }

        self._start_approver(sign_count)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        task_dir = self.jobs_dir.parent / "tasks" / self.trial_id
        task_template = Path(__file__).resolve().parent.parent / "tasks/solana-transfer"
        shutil.copytree(task_template, task_dir)
        whole, fractional = divmod(self.lamports, 1_000_000_000)
        sol = (
            str(whole)
            if fractional == 0
            else f"{whole}.{fractional:09d}".rstrip("0")
        )
        (task_dir / "instruction.md").write_text(
            f"Using Bloom, send exactly {sol} SOL from my `{self.wallet_id}` wallet "
            f"to `{self.destination}` on `{self.chain}`. Wait until it is finalized "
            "and tell me the result.\n"
        )
        extra_docker_compose: list[Path] = []
        if self.lane == "local":
            # The local validator deliberately listens on host loopback. Harbor's
            # verifier otherwise sees its container's loopback and cannot inspect
            # the transfer it is grading. Keep this override local-only: the
            # mainnet lane neither needs nor receives host networking.
            extra_docker_compose.append(
                self.repo_root
                / "evals/harbor/tasks/solana-transfer/docker-compose.local.yaml"
            )
        return EvalRunContext(
            eval_name=self.name,
            task_dir=task_dir,
            job_name=f"bloom-solana-{agent_name}-{stamp}",
            jobs_dir=self.jobs_dir,
            mounts=mounts,
            agent_env={},
            verifier_env=verifier_env,
            extra_docker_compose=extra_docker_compose,
        )

    async def run_smoke(self, context: EvalRunContext, _agent: Any) -> Any:
        """Exercise the real mounted lifecycle without invoking an LLM.

        This is intentionally inside the normal preflight/provision/cleanup
        envelope. A pass proves the mount, route writes, approval watcher,
        ceremony, broadcast, reconciliation, verifier, and sweep all agree.
        """
        staged = json.dumps(
            {"destination": self.destination, "lamports": self.lamports},
            separators=(",", ":"),
        ).encode()
        created = self.mount.write_route(
            self.outbox_root / "new.tx", staged, ROUTE_WRITE_TIMEOUT_SECONDS
        )
        if created.returncode != 0:
            raise EvalError(
                "smoke could not stage new.tx: "
                + (created.stderr or created.stdout).decode(errors="replace").strip()
            )
        if not self.mount.poll_until(
            lambda: len(self._list_state("pending")) == 1, 20, 0.25
        ):
            raise EvalError("smoke stage did not create exactly one pending entry")
        pending_id = self._list_state("pending")[0]
        entry = self.outbox_root / "pending" / pending_id
        intent = self.mount.read_json(entry / "intent.json")
        if not isinstance(intent, dict) or not self._ceremony_matches_authorized_transfer(
            pending_id
        ):
            raise EvalError("smoke staged intent does not match the authorized transfer")
        try:
            plan = subprocess.run(
                ["cat", str(entry / "plan.md")],
                check=True,
                capture_output=True,
                timeout=CHAIN_READ_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"smoke could not read plan.md: {error}") from error
        if not plan.stdout.strip():
            raise EvalError("smoke plan.md is empty")

        first = self.mount.write_route(
            entry / "confirm", b"y", ROUTE_WRITE_TIMEOUT_SECONDS
        )
        if first.returncode == 0:
            raise EvalError("smoke first confirm bypassed the approval boundary")
        if not self.mount.poll_until(
            lambda: self._pending_confirm_ceremony(pending_id) is not None, 20, 0.25
        ):
            raise EvalError("smoke confirm did not publish approval_challenge.json")

        deadline = time.monotonic() + SMOKE_CONFIRM_BUDGET_SECONDS
        confirmed = False
        while time.monotonic() < deadline:
            attempt = self.mount.write_route(
                entry / "confirm", b"y", ROUTE_WRITE_TIMEOUT_SECONDS
            )
            if attempt.returncode == 0:
                confirmed = True
                break
            if self._approver_error is not None:
                raise EvalError(f"smoke approver failed: {self._approver_error}")
            await asyncio.sleep(0.5)
        if not confirmed:
            raise EvalError("smoke confirm did not succeed before the blockhash deadline")
        if not self.mount.poll_until(
            lambda: pending_id in self._list_state("sent"), 30, 0.5
        ):
            raise EvalError("smoke confirmed entry did not move to outbox/sent")

        sent = self.outbox_root / "sent" / pending_id
        attempted = self.mount.read_json(sent / "broadcast_attempted.json")
        if not isinstance(attempted, dict):
            raise EvalError("smoke broadcast_attempted.json is malformed")
        for field in ("fee_payer", "destination", "lamports", "blockhash"):
            if attempted.get(field) != intent.get(field):
                raise EvalError(
                    f"smoke broadcast attempt disagrees with staged intent on {field}"
                )
        receipt: Any = None

        def receipt_finalized() -> bool:
            nonlocal receipt
            receipt = self.mount.read_json_if_listed(
                sent / "receipt.json", sent, "receipt.json"
            )
            return (
                isinstance(receipt, dict)
                and receipt.get("outcome") == "success"
                and receipt.get("confirmation_status") == "finalized"
            )

        if not self.mount.poll_until(receipt_finalized, 45, 1.0):
            raise EvalError("smoke receipt did not reconcile to success/finalized")
        assert isinstance(receipt, dict)
        if receipt.get("signature") != attempted.get("signature"):
            raise EvalError("smoke receipt signature differs from broadcast attempt")
        verifier = subprocess.run(
            [
                sys.executable,
                str(context.task_dir / "tests/verify_result.py"),
            ],
            env={**os.environ, **context.verifier_env},
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if verifier.returncode != 0:
            raise EvalError(
                "deterministic smoke verifier failed: "
                + (verifier.stderr or verifier.stdout).strip()
            )
        trial = SimpleNamespace(
            exception_info=None,
            verifier_result=SimpleNamespace(rewards={"smoke": 1.0}),
        )
        return SimpleNamespace(
            stats=SimpleNamespace(n_errored_trials=0, n_cancelled_trials=0),
            trial_results=[trial],
        )

    # ---- cleanup -------------------------------------------------------

    def cleanup(self) -> None:
        """Host-owned, ordered, and fail-closed.

        Only the host moves funds. There is no post-broadcast undo to hand a
        container, and giving one a path to move funds would defeat the bound
        this eval rests on.
        """
        self._stop_approver()
        failures: list[str] = []
        if self._approver_error is not None:
            failures.append(f"approver: {self._approver_error}")

        # 1. Drain pending. A residual staged entry still holds a broadcastable
        #    blockhash, so it is never an acceptable end state.
        for pending_id in self._list_state("pending"):
            self.mount.write_route(
                self.outbox_root / "pending" / pending_id / "cancel",
                b"host-cleanup",
                ROUTE_WRITE_TIMEOUT_SECONDS,
            )
            # A concurrent expiry sweep can move an entry to failed/ after the
            # listing but before this write. In that case cancel correctly
            # fails because the route moved, while the cleanup postcondition
            # is already satisfied. Judge the state after settling below.
        if not self.mount.poll_until(
            lambda: not self._list_state("pending"),
            PENDING_DRAIN_ATTEMPTS,
            PENDING_DRAIN_DELAY_SECONDS,
        ):
            remaining = self._list_state("pending")
            failures.append(
                "outbox/pending did not drain"
                + (f": {', '.join(remaining)}" if remaining else "")
            )

        # 2. Zero or one sent entry, and if one, it must have reconciled.
        all_sent = set(self._list_state("sent"))
        missing_history = self._baseline_sent - all_sent
        if missing_history:
            failures.append("historical sent entries disappeared during the trial")
        sent = sorted(all_sent - self._baseline_sent)
        if len(sent) > 1:
            failures.append(
                f"outbox/sent has {len(sent)} entries; the authorization permits one"
            )
        for sent_id in sent:
            def reconciled(entry: str = sent_id) -> bool:
                receipt = self.mount.read_json_if_listed(
                    self.outbox_root / "sent" / entry / "receipt.json",
                    self.outbox_root / "sent",
                    entry,
                )
                return isinstance(receipt, dict) and receipt.get("outcome") is not None

            if not self.mount.poll_until(
                reconciled, RECEIPT_SETTLE_ATTEMPTS, RECEIPT_SETTLE_DELAY_SECONDS
            ):
                failures.append(f"sent entry {sent_id} never reconciled to a receipt")

        # 3. Sweep the destination back to the source.
        #
        # This is what makes the eval repeatable. The transfer cannot be undone,
        # but the destination is host-controlled, so the lamports come back and
        # only the fees are actually spent. It runs unconditionally rather than
        # only when a `sent/` entry exists: a broadcast that the outbox failed
        # to record still moved funds, and that is exactly the case where
        # skipping the sweep would be worst.
        if self.source_address and self.destination:
            try:
                signature = self.sweep_destination()
                if signature is not None:
                    self.sweep_signature = signature
            except EvalError as error:
                failures.append(f"host sweep: {error}")
        else:
            failures.append(
                "cannot sweep: the source or destination address is unknown"
            )

        if failures:
            raise EvalError(
                f"residual-state cleanup failed for {self.trial_id}: "
                + "; ".join(failures)
            )
