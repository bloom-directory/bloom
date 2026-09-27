"""Host-side lifecycle for the native SOL transfer evaluation.

The Hyperliquid eval is safe because its primitive is reversible: place, then
cancel, where the undo is also the proof. A SOL transfer has no undo, so the
bound is the host approval contract instead. For each trial the harness picks
a fresh random destination, allows only it in the wallet policy, and completes
an owner ceremony only for a staged intent that matches the exact transfer:
destination, lamports, fee payer, fee ceiling, signing account, and genesis. A
restaged replacement is approved only when the outbox's own
`restage_advice.json` chain leads to it. The verifier then requires exactly one
finalized payment on chain.

It runs against a disposable local validator only; the endpoint's genesis is
checked, and mainnet-beta is refused.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
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

# The cluster identity this eval refuses. This is the chain's own answer to
# `getGenesisHash`, not a configuration label, so pointing the eval at a
# mainnet endpoint fails here.
MAINNET_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"

BASE58 = "[1-9A-HJ-NP-Za-km-z]"
ADDRESS = re.compile(f"{BASE58}{{32,44}}")
WALLET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
CHAIN_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
FINGERPRINT = re.compile(r"[0-9a-f]{16,64}")
DERIVATION = re.compile(r"m/44'/501'/\d+'/0'")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# A ceiling the harness enforces on the transfer and fee independently of
# anything the operator configures, so a fat-fingered parameter cannot widen
# the blast radius: 0.02 SOL.
HARNESS_MAX_TRANSFER_LAMPORTS = 20_000_000

# Mounted chain reads wait on an RPC round trip, not a disk.
CHAIN_READ_TIMEOUT_SECONDS = 45
CHAIN_READ_ATTEMPTS = 3
ROUTE_WRITE_TIMEOUT_SECONDS = 120

# The agent drives the confirm, so its ceremony is published while Harbor is
# running. The approver polls for it rather than the host completing every
# ceremony up front the way the Hyperliquid provision does.
# Every second of approval latency comes out of the agent's ~60 s blockhash
# window.
APPROVER_POLL_SECONDS = 1.0
# The approver starts at provision, before Harbor builds the environment and
# runs the agent, and is stopped when the trial ends. It must outlast both
# task.toml timeouts: an approver that quits first silently fails any agent
# that needs longer, including one following the documented restage path.
APPROVER_BUDGET_SECONDS = 1800.0
# One confirm ceremony, plus at most one first-use key derivation and one
# blockhash-expiry re-approval. The cap bounds a misbehaving route rather
# than describing the expected count.
MAX_TRANSFER_CEREMONIES = 3
# The restage route stages the replacement, then writes the predecessor's
# advice in the same call, so an entry can briefly exist without advice. Past
# this grace, a confirmable entry with no advice was staged fresh, not
# restaged, and is refused.
RESTAGE_ADVICE_GRACE_SECONDS = 10.0
# Bounds the restage chain the approver follows from its last approval.
MAX_RESTAGE_HOPS = 10
# Slots of history a local validator must retain to cover one trial: the
# environment build plus the agent timeout (1800 s) at ~2.5 slots per second.
LOCAL_HISTORY_MIN_SLOTS = 4500

RPC_TIMEOUT_SECONDS = 30
PENDING_DRAIN_ATTEMPTS = 30
PENDING_DRAIN_DELAY_SECONDS = 2.0
RECEIPT_SETTLE_ATTEMPTS = 45
RECEIPT_SETTLE_DELAY_SECONDS = 2.0
SMOKE_CONFIRM_BUDGET_SECONDS = 45.0
# Waiting out a local validator's real blockhash window dominates the restage
# smoke; opt into it with BLOOM_EVAL_SOLANA_SMOKE_RESTAGE=1.
SMOKE_RESTAGE_ENV = "BLOOM_EVAL_SOLANA_SMOKE_RESTAGE"
SMOKE_RESTAGE_WAIT_ATTEMPTS = 600
SMOKE_RESTAGE_WAIT_DELAY_SECONDS = 1.0

class SolanaTransferEval(EvalDefinition):
    name = "solana-transfer"
    # Discovery, owner approval, possible blockhash restaging, and finality
    # can exceed the shared 20-turn default.
    default_max_turns = "24"

    def __init__(self, repo_root: Path, environ: dict[str, str] | None = None) -> None:
        self.repo_root = repo_root.resolve()
        self.env = dict(os.environ if environ is None else environ)
        self.wallet_id = self.env.get("BLOOM_EVAL_SOLANA_WALLET_ID", "")
        self.chain = self.env.get("BLOOM_EVAL_SOLANA_CHAIN", "")
        self.rpc_url = self.env.get("BLOOM_EVAL_SOLANA_RPC_URL", "")
        self.bloom_mount_value = self.env.get("BLOOM_EVAL_BLOOM_MOUNT", "").strip()
        self.bloom_mount = Path(self.bloom_mount_value)
        # The Machine's home root, on the host filesystem. The approver reads
        # the canonical approval challenge here so its decision is unaffected
        # by mount latency or a projection changing during a read.
        self.home_root = Path(self.env.get("BLOOM_EVAL_SOLANA_HOME_ROOT", ""))
        # The bloom CLI stages each trial's policy change; triad.env puts the
        # evaluation triad's build first on PATH and names its Machine socket.
        self.bloom_bin = self.env.get("BLOOM_EVAL_BLOOM_BIN", "bloom")
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
        self.destination = ""
        self.lamports = 0
        self.max_fee_lamports = 0
        self.source_address = ""
        self.key_fingerprint = ""
        self.derivation_path = ""
        # Set by _require_chain_identity; empty matches no staged intent.
        self.genesis_hash = ""
        # The slot preflight saw, from which the validator's history must survive.
        self.history_start_slot: int | None = None
        # Numbered account directory the vfs projects the wallet under
        # (`wallets/<wallet>/<n>/...`); resolved from the authenticated
        # account projection in _load_local_account_identity.
        self.account_dir = ""
        self.trial_id: str | None = None
        self.mount = MountedTree(
            read_timeout=CHAIN_READ_TIMEOUT_SECONDS,
            read_attempts=CHAIN_READ_ATTEMPTS,
        )
        self._approver: threading.Thread | None = None
        self._approver_stop = threading.Event()
        # A harness fault (driver, IO): the trial cannot be judged.
        self._approver_error: str | None = None
        # A staging the approver refused (wrong transfer, not a restage, past
        # the cap): the agent's outcome, not a fault.
        self._approver_refusal: str | None = None
        self._approver_completed = 0
        # The approved replacement lineage, oldest first. Entries are outbox
        # ids whose staged intent matched the configured transfer and whose
        # succession is documented by the outbox's own restage advice.
        self._approved_lineage: list[str] = []
        self._baseline_sent: set[str] = set()
        # Every host outbox entry that existed at preflight, so the trial
        # summary counts only this trial's stagings.
        self._baseline_entries: set[str] = set()

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
        # Chain views live under the numbered account directory
        # (wallets/<wallet>/<n>/chains/...); the wallet directory itself has
        # no chains/ per the vfs wallets handler.
        return self.wallet_root / self.account_dir / "chains" / self.chain

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
        return sorted(self.mount.list_dir(self.outbox_root / state))

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
        number = account.get("number")
        if not isinstance(number, int) or number < 0:
            raise EvalError(
                "Solana account projection has no numbered account directory"
            )
        # Set before the chain-level reads: they resolve through chain_root,
        # which is only correct once the numbered directory is known.
        self.account_dir = str(number)
        fingerprint = account.get("public_key_fingerprint")
        path = account.get("path")
        if not isinstance(fingerprint, str) or FINGERPRINT.fullmatch(fingerprint) is None:
            raise EvalError("Solana account projection has a malformed fingerprint")
        if not isinstance(path, str) or DERIVATION.fullmatch(path) is None:
            raise EvalError("Solana account projection has a malformed derivation path")
        # The account's per-chain address is projected at the chain level
        # (chains/<chain>/address), not under an accounts/ subtree.
        address_path = self.chain_root / "address"
        try:
            address = self.mount.read_text(
                address_path, CHAIN_READ_TIMEOUT_SECONDS
            ).strip()
        except EvalError as error:
            raise EvalError(f"could not read Solana account address: {error}") from error
        if ADDRESS.fullmatch(address) is None:
            raise EvalError("Solana account projection has a malformed address")
        self.source_address = address
        self.key_fingerprint = fingerprint
        self.derivation_path = path

    # ---- transfer parameters and chain identity ------------------------

    @staticmethod
    def _positive_lamports(name: str, value: str) -> int:
        amount = int(value) if value.isdigit() else 0
        if amount <= 0:
            raise EvalError(f"{name} must be a positive integer number of lamports")
        return amount

    def _require_chain_identity(self) -> None:
        """Check the configured endpoint's actual cluster identity.

        A network label is operator input, not evidence: a mainnet endpoint
        must never masquerade as the disposable local validator.
        """
        observed = self._rpc("getGenesisHash", [])
        if not isinstance(observed, str) or not observed:
            raise EvalError("could not read the endpoint's genesis hash")
        # The approver requires every staged intent to carry this same
        # genesis, so the identity checked here is the one approved.
        self.genesis_hash = observed
        if observed == MAINNET_GENESIS_HASH:
            raise EvalError(
                "the eval runs against a disposable local validator; the "
                "configured RPC serves the mainnet-beta genesis"
            )

    def _require_local_history_window(self) -> None:
        """The verifier proves "exactly one payment" from signature history.
        solana-test-validator keeps only ~10,000 shreds by default, about a
        minute of slots, so a payment made early in a trial is pruned before
        the verifier runs and a correct trial scores zero. A validator that is
        already pruning must retain a whole trial; one that is not yet pruning
        cannot be judged here, so the verifier re-checks against the slot
        recorded now and names pruning as the reason if it happened."""
        slot = self._rpc("getSlot", [])
        first = self._rpc("getFirstAvailableBlock", [])
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (slot, first)):
            raise EvalError("could not read the local validator's history window")
        if first > 0 and slot - first < LOCAL_HISTORY_MIN_SLOTS:
            raise EvalError(
                f"the local validator retains only {slot - first} slots of history; "
                f"a trial needs {LOCAL_HISTORY_MIN_SLOTS}. Restart it with "
                "--reset --limit-ledger-size 1000000"
            )
        self.history_start_slot = slot

    def preflight(self) -> None:
        if not self.bloom_mount_value:
            raise EvalError("BLOOM_EVAL_BLOOM_MOUNT is required")
        if WALLET_ID.fullmatch(self.wallet_id) is None:
            raise EvalError("BLOOM_EVAL_SOLANA_WALLET_ID is required and must be a token")
        if CHAIN_NAME.fullmatch(self.chain) is None:
            raise EvalError("BLOOM_EVAL_SOLANA_CHAIN is required and must be a token")
        if not self.rpc_url:
            raise EvalError("BLOOM_EVAL_SOLANA_RPC_URL is required")
        lamports = self._positive_lamports(
            "BLOOM_EVAL_SOLANA_LAMPORTS",
            self.env.get("BLOOM_EVAL_SOLANA_LAMPORTS", "1000000"),
        )
        max_fee = self._positive_lamports(
            "BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS",
            self.env.get("BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS", "10000"),
        )
        for name, value in (("transfer", lamports), ("fee ceiling", max_fee)):
            if value > HARNESS_MAX_TRANSFER_LAMPORTS:
                raise EvalError(
                    f"configured {name} {value} exceeds the harness ceiling "
                    f"{HARNESS_MAX_TRANSFER_LAMPORTS}"
                )
        # Preflight is the single place the amount is decided, so the ceiling
        # above covers the exact on-chain value.
        self.lamports = lamports
        self.max_fee_lamports = max_fee

        # Chain identity is checked from the chain itself, not from labels.
        self._require_chain_identity()
        self._require_local_history_window()

        # The approver reads the canonical host-side approval challenge the
        # confirm route stages; the host copy is the stable boundary for
        # matching the exact configured intent before approval.
        if not str(self.home_root):
            raise EvalError(
                "BLOOM_EVAL_SOLANA_HOME_ROOT is required so the host approver "
                "can read stable outbox state"
            )
        if not self.home_root.is_dir():
            raise EvalError(f"Machine home root is not a directory: {self.home_root}")
        if shutil.which(self.bloom_bin) is None:
            raise EvalError(
                f"the bloom CLI ({self.bloom_bin!r}) is required to allow each "
                "trial's destination; source triad.env or set BLOOM_EVAL_BLOOM_BIN"
            )

        self.sign_count = self._require_sign_count()
        CeremonyDriver(self.driver, self.seed_file, self.sign_count).preflight()

        if not os.path.ismount(self.bloom_mount):
            raise EvalError(f"Bloom is not mounted at {self.bloom_mount}")
        self._load_local_account_identity()
        # Docker silently creates an empty directory at a missing bind source,
        # which would mask the real outbox and fail bafflingly inside the
        # container. Refuse before constructing the mount.
        if not self.outbox_root.is_dir():
            raise EvalError(
                f"wallet outbox is not present at {self.outbox_root}; the "
                "wallet may not have this Solana chain configured"
            )
        if not (self.outbox_root / "new.tx").exists():
            raise EvalError(
                f"{self.outbox_root}/new.tx is missing; the chain is not writable"
            )

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
        self._baseline_entries = {
            entry
            for state in ("pending", "sent", "failed")
            for entry in self._list_host_state(state)
        }

    def preauthorization_preflight(self) -> None:
        """Read-only validation, for use before any authority exists.

        Preflight performs no ceremony, no mounted write, no Docker job, and
        no state change; its only network traffic is the RPC identity and
        history reads.
        """
        self.preflight()

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

    def _ceremony_matches_authorized_transfer(self, pending_id: str) -> bool:
        """Refuse to approve anything but the exact configured transfer.

        The approver runs while the agent is live, so it must never be a
        rubber stamp for whatever the agent happened to stage.

        The staged intent is read from the host state directory rather than
        through the mount, so the decision cannot be affected by mount latency
        or by a projection replaced mid-read. Every authoritative field is
        required: a staged intent that omits the signing account or the fee
        cannot silently pass by absence.
        """
        intent = self._read_host_json(
            self._host_entry("pending", pending_id) / "intent.json"
        )
        if not isinstance(intent, dict):
            return False
        if intent.get("genesis_hash") != self.genesis_hash:
            return False
        if intent.get("destination") != self.destination:
            return False
        if intent.get("lamports") != self.lamports:
            return False
        if intent.get("fee_payer") != self.source_address:
            return False
        fee = intent.get("fee_lamports")
        if not isinstance(fee, int) or isinstance(fee, bool):
            return False
        if self.max_fee_lamports and fee > self.max_fee_lamports:
            return False
        # The staged entry pins the exact derived child it was built for, so
        # the approver can check the same signing identity the engine checks
        # again at signing. A second active child must never be able to have a
        # message approved that was staged against the first, and an intent
        # that omits the pin cannot borrow the configured identity.
        fingerprint = intent.get("account_fingerprint")
        if self.key_fingerprint:
            if not isinstance(fingerprint, str) or (
                fingerprint.lower() != self.key_fingerprint.lower()
            ):
                return False
        derivation = intent.get("account_derivation_path")
        if self.derivation_path:
            if derivation != self.derivation_path:
                return False
        return True

    def _restage_advice(self, entry_id: str) -> dict[str, Any] | None:
        """The outbox's restage advice for an approved entry, if published.

        `SolanaTransferEngine::restage_expired` moves the expired entry to
        `failed` and writes `restage_advice.json` naming the replacement id.
        The restage route write only returns after that advice lands, so a
        replacement can never reach a confirmable state before its advice
        exists: absence here means the predecessor was never restaged.
        """
        for state in ("failed", "pending"):
            advice = self._read_host_json(
                self._host_entry(state, entry_id) / "restage_advice.json"
            )
            if isinstance(advice, dict):
                if advice.get("schema") != "bloom.solana-restage-advice/1":
                    raise EvalError(
                        f"restage advice for {entry_id} has an unexpected schema"
                    )
                return advice
        return None

    def _replacement_is_authorized(self, pending_id: str) -> bool | None:
        """Decide whether a differently-named pending entry may be approved.

        Only restage successions are authorized: starting from the last
        approved entry, each expired entry's own outbox advice names its
        replacement, and this entry is reached by following that chain. A
        replacement may itself expire before it is approved and be restaged
        again, so the chain can run through unapproved entries. An entry
        staged fresh - no advice names it - is a new payment attempt and is
        refused.

        Returns None when an entry on the chain has no advice yet: the
        restage operation writes the advice just after it stages the
        replacement, so absence is briefly "wait". The approver refuses once
        the grace passes.
        """
        if not self._approved_lineage:
            return False
        current = self._approved_lineage[-1]
        for _ in range(MAX_RESTAGE_HOPS):
            advice = self._restage_advice(current)
            if advice is None:
                return None
            named = advice.get("replacement_id")
            if not isinstance(named, str):
                return False
            if named == pending_id:
                return True
            current = named
        return False

    def _approve_loop(self, ceremonies: CeremonyDriver) -> None:
        deadline = time.monotonic() + APPROVER_BUDGET_SECONDS
        awaiting_advice: dict[str, float] = {}
        while not self._approver_stop.is_set() and time.monotonic() < deadline:
            try:
                for pending_id in self._list_host_state("pending"):
                    url = self._pending_confirm_ceremony(pending_id)
                    if url is None:
                        continue
                    if url in ceremonies.completed:
                        continue
                    if pending_id in self._approved_lineage:
                        continue
                    if not self._ceremony_matches_authorized_transfer(pending_id):
                        self._approver_refusal = (
                            f"staged entry {pending_id} does not match the configured "
                            "transfer; refusing to approve it"
                        )
                        return
                    if self._approved_lineage:
                        lineage_decision = self._replacement_is_authorized(pending_id)
                        if lineage_decision is None:
                            # The replacement is staged but its restage advice
                            # has not landed yet; poll again, but only briefly:
                            # the route writes the advice in the same call.
                            first_seen = awaiting_advice.setdefault(
                                pending_id, time.monotonic()
                            )
                            if (
                                time.monotonic() - first_seen
                                < RESTAGE_ADVICE_GRACE_SECONDS
                            ):
                                continue
                            lineage_decision = False
                        if not lineage_decision:
                            self._approver_refusal = (
                                f"staged entry {pending_id} does not continue the approved "
                                "replacement lineage (no restage advice names it); "
                                "refusing to approve it"
                            )
                            return
                    if self._approver_completed >= MAX_TRANSFER_CEREMONIES:
                        # Say why the agent's next approval never comes; a
                        # silent stop reads as an approver that hung.
                        self._approver_refusal = (
                            f"staged entry {pending_id} needs a ceremony past the "
                            f"cap of {MAX_TRANSFER_CEREMONIES}; each restaged "
                            "entry expired before its confirm was retried"
                        )
                        return
                    ceremonies.complete(url)
                    self._approved_lineage.append(pending_id)
                    self._approver_completed += 1
                    self.next_sign_count = ceremonies.next_sign_count
            except EvalError as error:
                self._approver_error = CeremonyDriver.redact(str(error))
                self.next_sign_count = ceremonies.next_sign_count
                return
            except Exception as error:  # noqa: BLE001 -- a dead thread must leave a trace
                # An unexpected failure must leave the same trace an expected
                # one does: a thread that dies quietly masquerades as an agent
                # that never staged.
                self._approver_error = (
                    f"approver failed: {CeremonyDriver.redact(str(error))}"
                )
                return
            self._approver_stop.wait(APPROVER_POLL_SECONDS)
        if (
            self._approver_error is None
            and self._approver_refusal is None
            and not self._approver_stop.is_set()
        ):
            # The budget ran out on its own. Record it only when entries went
            # unapproved, so a trial the agent never staged stays silent and a
            # slow staging reads as a budget expiry, never as agent failure.
            try:
                unapproved = [
                    entry
                    for entry in self._list_host_state("pending")
                    if entry not in self._approved_lineage
                ]
            except EvalError:
                unapproved = []
            if unapproved:
                self._approver_error = (
                    "approver budget expired with "
                    f"{len(unapproved)} pending entries unapproved"
                )

    def _start_approver(self, ceremonies: CeremonyDriver) -> None:
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

    # ---- chain RPC and per-trial destination ----------------------------

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

    @staticmethod
    def _fresh_destination() -> str:
        """A random 32-byte address. No one holds its key and nothing has ever
        paid it, so it is fresh by construction and ties the chain record to
        this trial alone."""
        raw = secrets.token_bytes(32)
        number = int.from_bytes(raw, "big")
        encoded = ""
        while number:
            number, digit = divmod(number, 58)
            encoded = BASE58_ALPHABET[digit] + encoded
        leading_zeros = len(raw) - len(raw.lstrip(b"\0"))
        return "1" * leading_zeros + encoded

    def _bloom(self, *args: str) -> str:
        try:
            completed = subprocess.run(
                [self.bloom_bin, "-q", *args],
                env=self.env,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(f"bloom {' '.join(args[:2])} failed: {error}") from error
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise EvalError(
                f"bloom {' '.join(args[:2])} failed: {CeremonyDriver.redact(detail)}"
            )
        return completed.stdout

    def _allowed_destinations(self) -> Any:
        projection = json.loads(self._bloom("wallet", "projection", self.wallet_id))
        canonical = projection.get("policy", {}).get("canonical_policy")
        if not isinstance(canonical, str):
            raise EvalError("wallet projection has no canonical policy")
        # Broker's Base64UrlBytes: URL-safe alphabet, no padding.
        try:
            return json.loads(
                base64.urlsafe_b64decode(canonical + "=" * (-len(canonical) % 4))
            )
        except (ValueError, json.JSONDecodeError) as error:
            raise EvalError(f"wallet projection policy is malformed: {error}") from error

    def _allow_only_destination(self, ceremonies: CeremonyDriver) -> None:
        """Allow this trial's destination, and only it, in the wallet policy.

        Policy is deny-by-default and the eval wallet is dedicated, so the
        previous trial's allowance is dropped rather than accumulated. The
        owner ceremony runs through the same counter sequence the approver
        continues, so no counter is ever tracked by hand.
        """
        policy = self._allowed_destinations()
        policy["allowed_destinations"] = [
            {"chain": "solana", "destination": self.destination}
        ]
        with tempfile.TemporaryDirectory() as scratch:
            proposal = Path(scratch) / "policy.json"
            proposal.write_text(json.dumps(policy))
            staged = self._bloom(
                "wallet", "update-policy", self.wallet_id, "--file", str(proposal)
            )
        fields = dict(
            line.split(": ", 1) for line in staged.splitlines() if ": " in line
        )
        url = fields.get("ceremony_url", "").strip()
        operation = fields.get("operation_id", "").strip()
        if CEREMONY_URL.fullmatch(url) is None or re.fullmatch("[0-9a-f]{64}", operation) is None:
            raise EvalError("bloom wallet update-policy did not stage a ceremony")
        ceremonies.complete(url)
        self._bloom("wallet", "commit-policy", operation)
        allowed = self._allowed_destinations().get("allowed_destinations")
        if allowed != policy["allowed_destinations"]:
            raise EvalError("the committed wallet policy does not allow this trial's destination")

    # ---- provision -----------------------------------------------------

    def provision(self, agent_name: str) -> EvalRunContext:
        sign_count = self.sign_count or self._require_sign_count()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.trial_id = f"bloom-eval-{agent_name}-{stamp}-{secrets.token_hex(8)}"
        ceremonies = CeremonyDriver(
            self.driver, self.seed_file, sign_count, store=self.sign_counts
        )
        self.destination = self._fresh_destination()
        self._allow_only_destination(ceremonies)

        # The amount was fixed by preflight; provision must not re-derive it.
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
            # Broker policy, the passkey ceremony, and the exact-match host
            # approver.
            {
                "type": "bind",
                "source": str(self.outbox_root),
                "target": (
                    f"/bloom/wallets/{self.wallet_id}/{self.account_dir}"
                    f"/chains/{self.chain}/outbox"
                ),
            },
        ]

        verifier_env = {
            "BLOOM_EVAL_SOLANA_WALLET_ID": self.wallet_id,
            "BLOOM_EVAL_SOLANA_ACCOUNT": self.account_dir,
            "BLOOM_EVAL_SOLANA_CHAIN": self.chain,
            "BLOOM_EVAL_SOLANA_RPC_URL": self.rpc_url,
            "BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS": str(self.max_fee_lamports),
            "BLOOM_EVAL_SOLANA_SOURCE": self.source_address,
            "BLOOM_EVAL_SOLANA_DESTINATION": self.destination,
            "BLOOM_EVAL_SOLANA_LAMPORTS": str(self.lamports),
        }
        if self.history_start_slot is not None:
            verifier_env["BLOOM_EVAL_SOLANA_HISTORY_FROM_SLOT"] = str(
                self.history_start_slot
            )

        self._start_approver(ceremonies)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        # Trial task copies live under the ignored jobs dir, never under the
        # repo's tasks/ tree: each run litters a README copy plus an
        # instruction naming the destination.
        task_dir = self.jobs_dir / self.trial_id
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
            "and tell me the result. Bloom is mounted at `/bloom`. I'll approve "
            "any passkey prompt myself; don't wait for my reply — retry once "
            "it's approved.\n"
        )
        # The local validator listens on host loopback. Harbor's verifier
        # otherwise sees its container's loopback and cannot inspect the
        # transfer it is grading.
        extra_docker_compose = [
            self.repo_root / "evals/harbor/tasks/solana-transfer/docker-compose.local.yaml"
        ]
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
        ceremony, broadcast, reconciliation, verifier, and cleanup all agree.

        With BLOOM_EVAL_SOLANA_SMOKE_RESTAGE=1 the smoke instead delays
        approval past the staged blockhash's real expiry, drives the outbox's
        documented restage path, and requires the replacement to settle into
        exactly one finalized payment under the same approver.
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
            raise EvalError("smoke staged intent does not match the configured transfer")
        try:
            plan_text = self.mount.read_text(
                entry / "plan.md", CHAIN_READ_TIMEOUT_SECONDS
            )
        except EvalError as error:
            raise EvalError(f"smoke could not read plan.md: {error}") from error
        if not plan_text.strip():
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

        if self.env.get(SMOKE_RESTAGE_ENV, "") == "1":
            pending_id, entry, intent = await self._smoke_restage(
                context, pending_id, entry, intent
            )
        elif not await self._smoke_confirm(entry):
            raise EvalError(
                "smoke confirm did not succeed before the blockhash deadline"
            )

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

    async def _smoke_confirm(self, entry: Path) -> bool:
        """Retry the confirm write until the approver has completed the
        ceremony and Bloom accepts it."""
        deadline = time.monotonic() + SMOKE_CONFIRM_BUDGET_SECONDS
        while time.monotonic() < deadline:
            attempt = self.mount.write_route(
                entry / "confirm", b"y", ROUTE_WRITE_TIMEOUT_SECONDS
            )
            if attempt.returncode == 0:
                return True
            reason = self._approver_error or self._approver_refusal
            if reason is not None:
                raise EvalError(f"smoke approver failed: {reason}")
            await asyncio.sleep(0.5)
        return False

    async def _smoke_restage(
        self, context: EvalRunContext, pending_id: str, entry: Path, intent: Any
    ) -> tuple[str, Path, Any]:
        """Hold the confirm past the real blockhash expiry, then restage.

        The approver completes the staged ceremony on sight, but the smoke
        deliberately never retries the confirm: once the live block height
        passes the staged blockhash's window, the outbox refuses to sign, and
        the documented recovery is the restage route. That publishes
        `restage_advice.json` naming the replacement, and the approver follows
        that lineage to approve exactly the replacement. Acceptance requires
        exactly one finalized payment in total.
        """
        # The engine refuses a restage until the live block height has really
        # passed the staged blockhash's window, so the write itself is the
        # expiry gate: retry until the chain, not an estimate, says it expired.
        # A concurrent expiry sweep can move the entry to `failed/` first, and
        # the route is reachable from both states, so follow the entry.
        def restage_after_expiry() -> bool:
            location = next(
                (
                    state
                    for state in ("pending", "failed")
                    if pending_id in self._list_state(state)
                ),
                None,
            )
            if location is None:
                return False
            restage = self.mount.write_route(
                self.outbox_root / location / pending_id / "restage",
                b"y",
                ROUTE_WRITE_TIMEOUT_SECONDS,
            )
            return restage.returncode == 0

        if not self.mount.poll_until(
            restage_after_expiry,
            SMOKE_RESTAGE_WAIT_ATTEMPTS,
            SMOKE_RESTAGE_WAIT_DELAY_SECONDS,
        ):
            raise EvalError(
                "smoke restage: the restage write never succeeded, so the staged "
                "blockhash never expired; cannot exercise the replacement path"
            )
        if not self.mount.poll_until(
            lambda: len(self._list_state("pending")) == 1
            and self._list_state("pending")[0] != pending_id,
            20,
            0.25,
        ):
            raise EvalError("smoke restage did not publish exactly one replacement entry")
        replacement_id = self._list_state("pending")[0]
        advice = self.mount.read_json_if_listed(
            self.outbox_root / "failed" / pending_id / "restage_advice.json",
            self.outbox_root / "failed" / pending_id,
            "restage_advice.json",
        )
        if not isinstance(advice, dict) or advice.get("replacement_id") != replacement_id:
            raise EvalError(
                "smoke restage advice does not name the replacement the outbox staged"
            )
        replacement_entry = self.outbox_root / "pending" / replacement_id
        replacement_intent = self.mount.read_json(
            replacement_entry / "intent.json"
        )
        if not isinstance(replacement_intent, dict):
            raise EvalError("smoke replacement intent is malformed")
        # The replacement re-quotes the fee, so compare the transfer facts
        # the approver matches on; the fee only has its ceiling here.
        for field in ("destination", "lamports", "fee_payer"):
            if replacement_intent.get(field) != intent.get(field):
                raise EvalError(
                    f"smoke replacement changed the transfer's {field}"
                )
        if not await self._smoke_confirm(replacement_entry):
            raise EvalError(
                "smoke replacement confirm did not succeed before the blockhash deadline"
            )
        return replacement_id, replacement_entry, replacement_intent

    # ---- cleanup -------------------------------------------------------

    def cleanup(self) -> None:
        """Host-owned, ordered, and fail-closed.

        Pending entries are cancelled and must drain, and at most one new
        entry may be sent and reconciled. There is no post-broadcast undo; the
        local validator's funds are worthless.
        """
        self._stop_approver()
        failures: list[str] = []
        if self._approver_error is not None:
            failures.append(f"approver: {self._approver_error}")
        mounted_error: BaseException | None = None
        try:
            # 1. Drain pending. A residual staged entry still holds a
            #    broadcastable blockhash, so it is never an acceptable end state.
            for pending_id in self._list_state("pending"):
                self.mount.write_route(
                    self.outbox_root / "pending" / pending_id / "cancel",
                    b"host-cleanup",
                    ROUTE_WRITE_TIMEOUT_SECONDS,
                )
                # A concurrent expiry sweep can move an entry to failed/ after
                # the listing but before this write. In that case cancel
                # correctly fails because the route moved, while the cleanup
                # postcondition is already satisfied. Judge the state below.
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
            if self._baseline_sent - all_sent:
                failures.append("historical sent entries disappeared during the trial")
            sent = sorted(all_sent - self._baseline_sent)
            if len(sent) > 1:
                failures.append(
                    f"outbox/sent has {len(sent)} entries; the configured transfer "
                    "permits one"
                )
            for sent_id in sent:

                def reconciled(entry: str = sent_id) -> bool:
                    receipt = self.mount.read_json_if_listed(
                        self.outbox_root / "sent" / entry / "receipt.json",
                        self.outbox_root / "sent",
                        entry,
                    )
                    return (
                        isinstance(receipt, dict)
                        and receipt.get("outcome") is not None
                    )

                if not self.mount.poll_until(
                    reconciled, RECEIPT_SETTLE_ATTEMPTS, RECEIPT_SETTLE_DELAY_SECONDS
                ):
                    failures.append(
                        f"sent entry {sent_id} never reconciled to a receipt"
                    )
        except BaseException as error:  # noqa: BLE001 -- report after the checks
            mounted_error = error

        if mounted_error is not None:
            if isinstance(mounted_error, EvalError):
                failures.append(f"mounted cleanup: {mounted_error}")
            else:
                raise mounted_error.with_traceback(mounted_error.__traceback__)

        if failures:
            raise EvalError(
                f"residual-state cleanup failed for {self.trial_id}: "
                + "; ".join(failures)
            )

    def trial_note(self) -> str:
        """One line on what the trial did, read from host outbox state.

        The reward says whether one correct payment landed; this says why not:
        stagings, approvals, entries that expired or were cancelled unsent,
        and any staging the approver refused.
        """
        created: dict[str, int] = {}
        expired = cancelled = 0
        for state in ("pending", "sent", "failed"):
            for entry in self._list_host_state(state):
                if entry in self._baseline_entries:
                    continue
                created[state] = created.get(state, 0) + 1
                if state == "failed":
                    intent = self._read_host_json(self._host_entry(state, entry) / "intent.json")
                    status = intent.get("status") if isinstance(intent, dict) else None
                    expired += status == "expired"
                    cancelled += status == "cancelled"
        parts = [
            f"{sum(created.values())} staged",
            f"{self._approver_completed} approved",
            f"{created.get('sent', 0)} sent",
            f"{expired} expired unsent",
            f"{cancelled} cancelled",
        ]
        if self._approver_refusal is not None:
            parts.append(f"refused: {self._approver_refusal}")
        return ", ".join(parts)
