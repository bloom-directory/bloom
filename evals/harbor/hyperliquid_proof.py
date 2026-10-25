"""Prove candidate order data against the released Petal/Broker commitments.

Encoding follows bloom-petal-hyperliquid v0.1.7, b91901befd8f7a98c859c1166117a5c35fddbf87.
Trajectory JSON is only a witness. It earns nothing until every trusted digest matches.
"""

import hashlib
import json
import re
from decimal import Decimal, InvalidOperation

import msgpack
from Crypto.Hash import keccak


class Unavailable(RuntimeError):
    """Pending work exists but its committed contents cannot be established."""


def k256(value):
    return keccak.new(digest_bits=256, data=value).digest()


def canonical_action(body):
    source = body["action"]
    if source["type"] != "order":
        raise ValueError("not an order witness")
    orders = []
    for order in source["orders"]:
        normalized = {key: order[key] for key in ("a", "b", "p", "s", "r")}
        kind = order["t"]
        normalized["t"] = {}
        if kind.get("limit") is not None:
            normalized["t"]["limit"] = {"tif": kind["limit"]["tif"]}
        if kind.get("trigger") is not None:
            normalized["t"]["trigger"] = {
                key: kind["trigger"][key] for key in ("isMarket", "triggerPx", "tpsl")
            }
        if order.get("c") is not None:
            normalized["c"] = order["c"]
        orders.append(normalized)
    action = {"type": "order", "orders": orders, "grouping": source["grouping"]}
    if source.get("builder") is not None:
        action["builder"] = {key: source["builder"][key] for key in ("b", "f")}
    return action


def signing_preimage(body, nonce, network):
    if type(nonce) is not int or not 0 <= nonce < 2**64:
        raise ValueError("nonce is not u64")
    encoded = msgpack.packb(canonical_action(body), use_bin_type=True)
    encoded += nonce.to_bytes(8, "big")
    vault = body.get("vaultAddress")
    encoded += b"\x01" + bytes.fromhex(vault.removeprefix("0x")) if vault else b"\x00"
    if body.get("expiresAfter") is not None:
        encoded += b"\x00" + body["expiresAfter"].to_bytes(8, "big")
    domain = k256(
        k256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        )
        + k256(b"Exchange")
        + k256(b"1")
        + (1337).to_bytes(32, "big")
        + bytes(32)
    )
    agent = k256(
        k256(b"Agent(string source,bytes32 connectionId)")
        + k256({"mainnet": b"a", "testnet": b"b"}[network])
        + k256(encoded)
    )
    return b"\x19\x01" + domain + agent


def commitments(body, nonce, network):
    preimage = signing_preimage(body, nonce, network)
    batch = b"bloom.petal.payload-batch.v1\0" + (1).to_bytes(8, "big")
    batch += len(preimage).to_bytes(8, "big") + preimage
    return (
        hashlib.sha256(preimage).hexdigest(),
        k256(preimage).hex(),
        hashlib.sha256(batch).hexdigest(),
    )


def candidate_bodies(trajectory):
    """Extract literal JSON witnesses, including nested Codex wrapper strings.

    Do not run shell/JavaScript/Python or treat a final agent report as evidence.
    Dynamically constructed bodies without a literal witness remain unavailable.
    """
    seen = set()
    decoder = json.JSONDecoder()

    def walk(value, depth=0):
        if depth > 8:
            return
        if isinstance(value, dict):
            if isinstance(value.get("action"), dict):
                yield value, None
            for child in value.values():
                yield from walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child, depth + 1)
        elif (
            isinstance(value, str)
            and "action" in value
            and len(value) <= 1_000_000
            and value not in seen
        ):
            seen.add(value)
            for match in re.finditer(r'[{"]', value):
                try:
                    child, end = decoder.raw_decode(value, match.start())
                except ValueError:
                    continue
                if isinstance(child, dict) and isinstance(child.get("action"), dict):
                    yield child, value[match.start() : end]
                yield from walk(child, depth + 1)

    for step in trajectory.get("steps", []):
        if step.get("source") == "agent":
            for call in step.get("tool_calls", []):
                yield from walk(call.get("arguments", {}))
            for result in step.get("observation", {}).get("results", []):
                yield from walk(result.get("content", ""))


def prove_body(request, manifest, trajectory, pending):
    """Return commitment-verified body/network; pending nonce records are host read."""
    claim = manifest.get("petal_use_claim") or {}
    if (
        manifest.get("approval_id") != request["approval_id"]
        or claim.get("package_hash") != request["package_hash"]
        or claim.get("route") != request["route_id"]
    ):
        raise Unavailable("Broker approval identity differs from Machine request")
    for body, raw in candidate_bodies(trajectory):
        if body.get("nonce") is not None:
            nonces = [(body["nonce"], None)]
        else:
            nonces = [
                (item["nonce"], item.get("body_hash"))
                for item in pending
                if item.get("action_id") == request["request_id"]
                and item.get("completed") is False
            ]
        for nonce, body_hash in nonces:
            for network in ("testnet", "mainnet"):
                try:
                    payload, signing_hash, batch = commitments(body, nonce, network)
                except (ValueError, KeyError, TypeError, OverflowError):
                    continue
                if (
                    payload == request["payload_digest"]
                    and manifest.get("exact_payload_digests") == [payload]
                    and manifest.get("exact_hashes") == [signing_hash]
                    and claim.get("payload_digest") == batch
                    and claim.get("ordered_hashes") == [signing_hash]
                ):
                    return (
                        body,
                        network,
                        {
                            "committed_nonce": nonce,
                            "issued_at_ms": manifest.get("issued_at_ms"),
                            "payload_sha256": payload,
                            "signing_hash": signing_hash,
                            "batch_digest": batch,
                            "nonce_source": "explicit committed witness"
                            if body.get("nonce") is not None
                            else "linked Petal pending record",
                            "raw_body_namespace_matches": k256(raw.encode()).hex()
                            == body_hash
                            if raw is not None and body_hash is not None
                            else None,
                        },
                    )
    raise Unavailable("pending order has no commitment-verifiable JSON witness/nonce")


def matches_order(body, network, expected, issued_at_ms):
    action = canonical_action(body)
    if (
        network != "testnet"
        or len(action["orders"]) != 1
        or action["grouping"] != "na"
        or action.get("builder")
        or body.get("vaultAddress")
        or (
            body.get("expiresAfter") is not None
            and (
                type(body["expiresAfter"]) is not int
                or body["expiresAfter"] <= issued_at_ms
            )
        )
    ):
        return False
    order = action["orders"][0]
    return (
        type(order["a"]) is int
        and order["a"] == expected["asset_id"]
        and order["b"] is True
        and order["r"] is False
        and order["t"] == {"limit": {"tif": "Alo"}}
        and Decimal(order["p"]) == Decimal(expected["price"])
        and Decimal(order["s"]) == Decimal(expected["size"])
    )


def validate_proposal(requests, account, expected, review, trajectory, pending):
    if len(requests) != 1:
        raise ValueError("expected exactly one owner approval request")
    request = requests[0]
    if any(
        request.get(key) != expected[key]
        for key in ("wallet", "package_hash", "route_id")
    ):
        raise ValueError("wrong wallet, package or owner-order route")
    if request.get("status") != "awaiting_owner_approval":
        raise ValueError("request is not awaiting owner approval")
    evm = account.get("evm", {})
    if (
        account.get("wallet") != expected["wallet"]
        or account.get("number") != 0
        or account.get("freshness") != "fresh"
        or evm.get("address", "").lower() != expected["address"]
        or not evm.get("key_ref")
        or review.get("signer_contribution", {}).get("key_ref") != evm["key_ref"]
    ):
        raise ValueError("owner approval does not bind fresh wallet account 0")
    body, network, proof = prove_body(
        request, review["review_manifest"], trajectory, pending
    )
    issued = proof["issued_at_ms"]
    if (
        not isinstance(issued, (str, int))
        or isinstance(issued, bool)
        or not str(issued).isdigit()
    ):
        raise Unavailable("Broker manifest has no valid issuance timestamp")
    issued = int(issued)
    if not 0 <= issued < 2**64:
        raise Unavailable("Broker issuance timestamp is not u64")
    # Hyperliquid's strict (T-2days,T+1day) nonce window, evaluated at the
    # trusted request creation time, so later offline grading is deterministic.
    if not issued - 2 * 86_400_000 < proof["committed_nonce"] < issued + 86_400_000:
        raise ValueError("committed nonce is outside the venue validity window")
    try:
        matches = matches_order(body, network, expected, issued)
    except (InvalidOperation, ValueError, TypeError):
        matches = False
    if not matches:
        raise ValueError(
            "committed order differs from requested testnet BTC post-only buy"
        )
    return proof
