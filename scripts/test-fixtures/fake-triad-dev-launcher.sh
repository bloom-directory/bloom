#!/usr/bin/env bash
# Deterministic mounted-filesystem double for the triad developer runner.
set -euo pipefail

socket=""
mount_dir=""
ready_file=""
machine_home=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --machine-socket)
      socket="$2"
      shift 2
      ;;
    --mount)
      mount_dir="$2"
      shift 2
      ;;
    --ready-file)
      ready_file="$2"
      shift 2
      ;;
    --machine-home)
      machine_home="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[ -n "$socket" ] && [ -n "$mount_dir" ] && [ -n "$ready_file" ] && [ -n "$machine_home" ]

exec python3 - "$socket" "$mount_dir" "$ready_file" "$machine_home" <<'PY'
import json
import hashlib
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

socket_path = Path(sys.argv[1])
mount = Path(sys.argv[2])
state = Path(os.environ.get("BLOOM_FAKE_STATE", "/tmp/bloom-fake-state"))
ready_file = Path(sys.argv[3])
machine_home = Path(sys.argv[4])
wallet = "test-passkey"
address = "0x0000000000000000000000000000000000000001"
session = "manual-mainnet-integration"
pm_signing_abi = os.environ.get("BLOOM_FAKE_PM_SIGNING_ABI", "0.4.0")
fixture_package_hash = "2f11ee17f612fbc43f34f81771c53760f56768959624d29fd63b8e4285f5a9ac"
fixture_provenance_digest = "66" * 32
mutate_approval_policy_digest = (
    os.environ.get("BLOOM_FAKE_MUTATE_APPROVAL_POLICY_DIGEST", "0") == "1"
)
state.mkdir(parents=True, exist_ok=True)
state.joinpath("machine-home").write_text(str(machine_home))
projection = machine_home / "cache/wallet-projections.json"
if projection.is_file():
    state.joinpath("wallet-projection-copy").write_bytes(projection.read_bytes())
fixture_key_ref = {
    "backend": "local",
    "backend_instance": "fixture",
    "locator": "wallet/test-passkey/petals/fixture",
    "key_spec": "secp256k1",
    "public_key_fingerprint": "44" * 32,
    "derivation": {
        "scheme": "bip32-secp256k1",
        "root_key_id": "wallet-root",
        "path": "m/44'/60'/0'/18734/1",
    },
}


def write(relative, body):
    path = mount / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def write_json(relative, value):
    return write(relative, json.dumps(value) + "\n")


def fifo(relative, callback):
    path = mount / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    os.mkfifo(path)

    def consume():
        while True:
            try:
                with path.open() as stream:
                    payload = stream.read()
                callback(payload)
            except (FileNotFoundError, OSError):
                return

    threading.Thread(target=consume, daemon=True).start()
    return path


write(f"wallets/{wallet}/kind", "passkey\n")
write(f"wallets/{wallet}/0/address", address + "\n")
initial_policy = {
    "wallet_id": wallet,
    "maximum_approval_lifetime_ms": 900000,
    "allowed_petal_packages": [],
    "allowed_destinations": [],
    "required_verifiers": [],
}
policy_path = write_json(f"wallets/{wallet}/policy.json", initial_policy)
addresses_path = write_json(
    f"wallets/{wallet}/0/addresses.json",
    {
        "wallet": wallet,
        "kind": "passkey",
        "owner": address,
        "signer": address,
        "policy_status": "broker_verified",
        "policy_version": "0",
        "policy_digest": hashlib.sha256(
            json.dumps(initial_policy, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest(),
        "wallet_revocation_epoch": "0",
        "roles": {},
    },
)
write_json(
    "petals/polymarket/meta/route-contract.json",
    {
        "schema": "fake.route-contract.v1",
        "abi": "0.1",
        "interfaces": [f"bloom:sign/signing@{pm_signing_abi}"],
    },
)
write_json(
    f"petals/polymarket/onboard/{wallet}/status.json",
    {"stage": "complete", "tradeable": True},
)
write_json(
    f"petals/polymarket/account/{wallet}/status.json",
    {"status": "ready", "tradeable": True},
)
write_json(
    f"petals/polymarket/account/{wallet}/buying_power.json",
    {
        "spendable": {"asset": "pUSD", "raw": "20000000"},
        "can_trade_now": True,
        "funding_needed": False,
    },
)
write_json(
    "petals/polymarket/markets/fixture/market.json",
    {"slug": "fixture", "question": "Fixture?", "outcomes": ["Yes", "No"]},
)
write_json(
    "petals/polymarket/markets/fixture/prices.json",
    {"Yes": "0.5", "No": "0.5"},
)
(mount / f"petals/polymarket/trade/{wallet}/drafts").mkdir(parents=True)
(mount / f"petals/polymarket/trade/{wallet}/receipts").mkdir(parents=True)

policy_committed = threading.Event()
committed_policy_digest = None


def policy_loop():
    global committed_policy_digest
    staged = None
    action_id = "policy-update-" + "77" * 32
    while True:
        try:
            value = json.loads(policy_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            time.sleep(0.01)
            continue
        if fixture_package_hash not in value.get("allowed_petal_packages", []):
            time.sleep(0.01)
            continue
        if staged is None:
            staged = value
            state.joinpath("policy-prepared").touch()
            write_json(
                f"wallets/{wallet}/policy-updates/latest/approval_challenge.json",
                {
                    "schema": "bloom.machine-policy-update-projection.1",
                    "ceremony_kind": "policy_update",
                    "ceremony_url": "http://127.0.0.1:18734/fixture-policy",
                    "ceremony_expires_at_ms": "9999999999999",
                },
            )
            write_json(
                f"wallets/{wallet}/policy-updates/latest/status.json",
                {"status": "awaiting_custody", "ceremony_kind": "policy_update", "action_id": action_id},
            )
            write_json(f"wallets/{wallet}/policy.json", initial_policy)
            time.sleep(0.2)
            write_json(
                f"wallets/{wallet}/policy-updates/latest/status.json",
                {"status": "ready_to_commit", "ceremony_kind": "policy_update", "action_id": action_id},
            )
        elif value == staged:
            canonical = json.dumps(value, separators=(",", ":"), sort_keys=True)
            committed_policy_digest = hashlib.sha256(canonical.encode()).hexdigest()
            write(f"wallets/{wallet}/policy.json", canonical + "\n")
            addresses = json.loads(addresses_path.read_text())
            addresses["policy_version"] = "1"
            addresses["policy_digest"] = (
                "99" * 32 if mutate_approval_policy_digest else committed_policy_digest
            )
            write_json(f"wallets/{wallet}/0/addresses.json", addresses)
            write_json(
                f"wallets/{wallet}/policy-updates/confirmed/{action_id}/status.json",
                {"status": "confirmed", "ceremony_kind": "policy_update", "action_id": action_id},
            )
            state.joinpath("policy-committed").touch()
            policy_committed.set()
            return
        time.sleep(0.01)


threading.Thread(target=policy_loop, daemon=True).start()

fixture_session = write_json(
    "petals/triad-authority-fixture/session.json",
    {"schema": "bloom.triad-authority-fixture.result.v1", "state": "empty"},
)
(mount / "petal-key-requests").mkdir(parents=True, exist_ok=True)
approval_id = "55" * 32
approval_active = threading.Event()
fixture_request_id = None
approval_new = write_json(
    f"wallets/{wallet}/sealed-approvals/new.json",
    {"schema": "bloom.approval_prepare_request.v1", "write": "request"},
)
write_json(
    f"wallets/{wallet}/sealed-approvals/active.json",
    {"schema": "bloom.sealed_approvals.active.v1", "wallet_id": wallet, "approvals": []},
)


def approval_loop():
    while True:
        try:
            value = json.loads(approval_new.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            time.sleep(0.01)
            continue
        if "operation_id" not in value:
            time.sleep(0.01)
            continue
        terms = value.get("terms", {})
        subject = terms.get("subject", {})
        selector = terms.get("selector", {})
        limits = terms.get("limits", {})
        issued = terms.get("issued_at_ms")
        not_before = terms.get("not_before_ms")
        expires = terms.get("expires_at_ms")
        expected_operation_id = (
            hashlib.sha256(f"{fixture_request_id}:approval".encode()).hexdigest()
            if fixture_request_id is not None
            else None
        )
        expected_nonce = (
            hashlib.sha256(f"{fixture_request_id}:nonce".encode()).hexdigest()[:32]
            if fixture_request_id is not None
            else None
        )
        plan = {
            "wallet_id": wallet,
            "package_hash": fixture_package_hash,
            "route": "r000001",
            "operation_class": "fixture.payload",
            "payload_sha256": hashlib.sha256(b"fixture payload").hexdigest(),
        }
        expected_plan_digest = hashlib.sha256(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        canonical_decimal_interval = (
            isinstance(issued, str)
            and isinstance(not_before, str)
            and isinstance(expires, str)
            and issued.isdigit()
            and not_before.isdigit()
            and expires.isdigit()
            and (issued == "0" or not issued.startswith("0"))
            and (not_before == "0" or not not_before.startswith("0"))
            and (expires == "0" or not expires.startswith("0"))
            and issued == not_before
            and int(expires) - int(issued) == 240000
            and abs(int(issued) - int(time.time() * 1000)) < 10000
        )
        if (
            set(value) != {"operation_id", "canonical_plan_facts_digest", "terms"}
            or value.get("operation_id") != expected_operation_id
            or value.get("canonical_plan_facts_digest") != expected_plan_digest
            or set(terms) != {
                "subject", "wallet_id", "key_ref", "allowed_crypto_suites", "selector",
                "limits", "activation_mode", "wallet_revocation_epoch", "policy_version",
                "policy_digest", "provenance_digest", "request_nonce", "issued_at_ms",
                "not_before_ms", "expires_at_ms", "renewal_of",
            }
            or subject != {
                "kind": "petal",
                "package_hash": fixture_package_hash,
                "route": "r000001",
                "agent_id": None,
            }
            or terms.get("wallet_id") != wallet
            or terms.get("key_ref") != fixture_key_ref
            or terms.get("allowed_crypto_suites") != ["secp256k1-sha256-recoverable"]
            or selector != {
                "kind": "petal",
                "package_hash": fixture_package_hash,
                "route": "r000001",
                "allowed_operation_classes": ["fixture.payload"],
                "required_claim_assurance": "machine_asserted",
            }
            or limits != {
                "max_operations": "1",
                "max_signatures": "1",
                "operation_rate_limits": [],
                "signature_rate_limits": [],
                "value_limits": [],
            }
            or terms.get("activation_mode") != {"kind": "boot_bound"}
            or terms.get("wallet_revocation_epoch") != "0"
            or terms.get("policy_version") != "1"
            or terms.get("policy_digest") != committed_policy_digest
            or terms.get("provenance_digest") != fixture_provenance_digest
            or terms.get("request_nonce") != expected_nonce
            or not canonical_decimal_interval
            or terms.get("renewal_of", "missing") is not None
        ):
            state.joinpath("approval-invalid").touch()
            return
        state.joinpath("approval-prepared").touch()
        write_json(
            f"wallets/{wallet}/sealed-approvals/new.json",
            {
                "approval_id": approval_id,
                "ceremony_url": "http://127.0.0.1:18734/fixture-sign",
                "ceremony_expires_at_ms": "9999999999999",
            },
        )
        time.sleep(0.2)
        write_json(
            f"wallets/{wallet}/sealed-approvals/active.json",
            {
                "schema": "bloom.sealed_approvals.active.v1",
                "wallet_id": wallet,
                "approvals": [
                    {"approval_id": approval_id, "wallet_id": wallet, "state": "active"}
                ],
            },
        )
        state.joinpath("approval-active").touch()
        approval_active.set()
        return


threading.Thread(target=approval_loop, daemon=True).start()


def fixture_loop():
    global fixture_request_id
    stage = 0
    while True:
        try:
            value = json.loads(fixture_session.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            time.sleep(0.01)
            continue
        if "request_id" not in value:
            time.sleep(0.01)
            continue
        request_id = value["request_id"]
        if fixture_request_id is None:
            fixture_request_id = request_id
        operation_id = "11" * 32
        scope_digest = "22" * 32
        if stage == 0:
            if not policy_committed.is_set():
                write_json(
                    "petals/triad-authority-fixture/session.json",
                    {"stage": "key_request_failed", "error": "POLICY_DENIED"},
                )
                continue
            write_json(
                "petal-key-requests/" + "33" * 32 + ".json",
                {
                    "schema": "bloom.machine.petal-key-request.v1",
                    "request_id": request_id,
                    "scope": {
                        "wallet_id": wallet,
                        "package_hash": fixture_package_hash,
                        "route": "r000001",
                        "agent_id": None,
                        "purpose": "fixture.payload",
                        "allowed_crypto_suites": ["secp256k1-sha256-recoverable"],
                        "maximum_lifetime_ms": "900000",
                        "custody_operation_id": operation_id,
                    },
                    "scope_digest": scope_digest,
                    "provenance_digest": fixture_provenance_digest,
                    "status": "awaiting_user",
                    "ceremony_url": "http://127.0.0.1:18734/fixture-key",
                    "ceremony_expires_at_ms": 9999999999999,
                },
            )
            write_json(
                "petals/triad-authority-fixture/session.json",
                {
                    "schema": "bloom.triad-authority-fixture.result.v1",
                    "stage": "key",
                    "outcome": {
                        "state": "pending",
                        "operation_id": operation_id,
                        "scope_digest": scope_digest,
                    },
                },
            )
        elif stage == 1:
            key_record = json.loads(
                (mount / ("petal-key-requests/" + "33" * 32 + ".json")).read_text()
            )
            key_record["status"] = "succeeded"
            key_record["ceremony_url"] = None
            key_record["public_key"] = {
                "key_ref": fixture_key_ref,
                "canonical_public_key": "Ag",
                "addresses": [address],
                "supported_crypto_suites": ["secp256k1-sha256-recoverable"],
            }
            write_json("petal-key-requests/" + "33" * 32 + ".json", key_record)
            write_json(
                "petals/triad-authority-fixture/session.json",
                {
                    "schema": "bloom.triad-authority-fixture.result.v1",
                    "stage": "signing_failed",
                    "error": "APPROVAL_NOT_FOUND: payload signing requires an approval hint",
                },
            )
        else:
            if value.get("approval_hint") != approval_id or not approval_active.is_set():
                write_json(
                    "petals/triad-authority-fixture/session.json",
                    {"stage": "signing_failed", "error": "APPROVAL_NOT_FOUND"},
                )
                continue
            write_json(
                "petals/triad-authority-fixture/session.json",
                {
                    "schema": "bloom.triad-authority-fixture.result.v1",
                    "stage": "complete",
                    "public_key": {
                        "key_ref_jcs": [123, 125],
                        "addresses": [address],
                    },
                    "signature_hex": "ab" * 65,
                },
            )
            state.joinpath("fixture-signed").touch()
        stage += 1
        time.sleep(0.01)


threading.Thread(target=fixture_loop, daemon=True).start()

def handle_pm_new(_payload):
    state.joinpath("pm-draft-staged").touch()
    root = f"petals/polymarket/trade/{wallet}/drafts/draft-1"
    Path(mount / root).mkdir(parents=True, exist_ok=True)
    write(f"{root}/plan.md", "# Fixture Polymarket plan\n")
    write_json(f"{root}/policy_check.json", {"policy_deny": False, "policy_status": "pass"})
    write_json(
        f"{root}/quote.json",
        {"status": "revalidated", "amount": "1", "limit_price": "0.5"},
    )
    write_json(
        f"{root}/review_intent.json",
        {"status": "final_review_staged", "posting_enabled": True},
    )
    fifo(f"{root}/revalidate", lambda _payload: None)
    post_count = 0

    def handle_post(_post_payload):
        nonlocal post_count
        if post_count == 0:
            write_json(
                f"{root}/approval.json",
                {
                    "action_id": "pm-fixture",
                    "ceremony_url": "http://127.0.0.1:18734/fixture",
                    "expires_ms": 9999999999999,
                },
            )
        else:
            state.joinpath("pm-posted").touch()
            write_json(
                f"petals/polymarket/trade/{wallet}/receipts/draft-1/receipt.json",
                {
                    "draft_id": "draft-1",
                    "clob_status": "matched",
                    "filled_size_micro": 1000000,
                },
            )
        post_count += 1

    fifo(f"{root}/post", handle_post)


fifo(f"petals/polymarket/trade/{wallet}/new", handle_pm_new)

time.sleep(float(os.environ.get("BLOOM_FAKE_STARTUP_DELAY_SECS", "0")))
try:
    socket_path.unlink()
except FileNotFoundError:
    pass
listener = socket.socket(socket.AF_UNIX)
listener.bind(str(socket_path))
listener.listen(1)
ready_file.write_text("ready\n")
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True:
    time.sleep(1)
PY
