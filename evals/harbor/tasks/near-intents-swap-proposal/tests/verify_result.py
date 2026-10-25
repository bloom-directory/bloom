"""Verify a signed upstream quote and the exact unsigned fork deposit proposal."""

import json
import os
import sys
from pathlib import Path

from projection import ProjectionReader


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(request, status, outbox, quote, intent, expected):
    address = expected["address"]
    for key in ("origin_asset", "destination_asset"):
        require(request.get(key) == expected[key], f"wrong {key}")
    require(
        request.get("swap_type") == "EXACT_INPUT"
        and request.get("amount") == "1000000",
        "wrong swap amount/type",
    )
    require(
        request.get("recipient", "").lower() == address, "wrong destination recipient"
    )
    echo = quote["quote_request"]
    for key, value in {
        "originAsset": expected["origin_asset"],
        "destinationAsset": expected["destination_asset"],
        "amount": "1000000",
        "swapType": "EXACT_INPUT",
        "depositType": "ORIGIN_CHAIN",
        "recipientType": "DESTINATION_CHAIN",
    }.items():
        require(echo.get(key) == value, f"wrong quoted {key}")
    require(
        echo.get("recipient", "").lower() == address
        and echo.get("refundTo", "").lower() == address,
        "wrong quote recipient/refund",
    )
    require(
        quote.get("verified") is True and status.get("quote_verified") is True,
        "quote is not verified",
    )
    require(
        status.get("state") == "staged" and status.get("origin_tx_hash") is None,
        "session advanced past unsigned staging",
    )
    require(
        status.get("wallet") == expected["wallet"]
        and status.get("id") == request.get("session_id"),
        "wrong session identity",
    )
    require(
        outbox.get("id") == status.get("outbox_id") == intent.get("id"),
        "outbox linkage differs",
    )
    require(
        outbox.get("chain") == "ethereum" and outbox.get("account") == {"number": 0},
        "wrong outbox chain/account",
    )
    require(
        outbox.get("outbox_root")
        == f"/wallets/{expected['wallet']}/0/chains/ethereum/outbox",
        "wrong outbox root",
    )
    require(
        outbox.get("tx_hash") is None
        and intent.get("tx_hash") is None
        and intent.get("status") == "pending",
        "deposit is not unsigned pending work",
    )
    require(
        intent.get("wallet") == expected["wallet"]
        and intent.get("chain") == "ethereum"
        and type(intent.get("chain_id")) is int
        and intent["chain_id"] == 1,
        "wrong intent wallet/chain",
    )
    require(
        intent.get("from", "").lower() == address
        and intent.get("to", "").lower() == expected["usdc_contract"],
        "wrong deposit sender/contract",
    )
    origin = intent.get("execution_origin", {})
    require(
        origin.get("petal_id") == "petal:near-intents"
        and origin.get("petal_digest") == expected["package_hash"],
        "wrong Petal execution origin",
    )
    require(
        intent.get("value_wei") == "0" and quote["quote"].get("amountIn") == "1000000",
        "wrong native/deposit amount",
    )
    deposit = quote["quote"]["depositAddress"].lower().removeprefix("0x")
    require(
        len(deposit) == 40 and all(c in "0123456789abcdef" for c in deposit),
        "invalid deposit address",
    )
    calldata = "0xa9059cbb" + deposit.rjust(64, "0") + f"{1000000:064x}"
    require(
        intent.get("data_hex", "").lower() == calldata, "wrong USDC transfer calldata"
    )


def verify(root=None):
    reader = ProjectionReader(root)
    expected = json.loads(os.environ["BLOOM_EVAL_PROPOSAL"])
    wallet = expected["wallet"]
    account = reader.read_json(f"wallets/{wallet}/0/account.json")
    require(
        account.get("wallet") == wallet
        and account.get("number") == 0
        and account.get("freshness") == "fresh"
        and account.get("evm", {}).get("address", "").lower() == expected["address"],
        "wrong/stale account",
    )
    require(reader.read_json("chains/ethereum/chain_id") == 1, "wrong chain ID")
    require(not reader.entries("petal-signing-requests"), "unexpected signing request")
    require(not reader.entries("petal-key-requests"), "unexpected key request")
    for state in ("pending", "confirmed", "failed"):
        require(
            not reader.entries(f"wallets/{wallet}/policy-updates/{state}"),
            "unexpected policy approval request",
        )
    require(
        not reader.directories(f"wallets/{wallet}/sealed-approvals"),
        "unexpected sealed approval",
    )
    base = f"petals/near-intents/swaps/{wallet}/0"
    sessions = reader.directories(base)
    require(len(sessions) == 1, "expected exactly one swap session")
    base += "/" + sessions[0]
    outbox = reader.read_json(base + "/outbox.json")
    request = reader.read_json(base + "/request.json")
    require(
        request.get("session_id") == sessions[0],
        "session directory differs from request identity",
    )
    if root is None:
        # Metadata only: ceremony.json can contain a capability. Its existence,
        # not its contents, proves this trial advanced beyond plain staging.
        entry = (
            Path(os.environ["BLOOM_EVAL_PROJECTION_HOME"])
            / "outbox"
            / wallet
            / "ethereum/pending"
            / outbox["id"]
        )
        require(entry.is_dir(), "native outbox entry unavailable")
        require(
            not any(
                path.name == "ceremony.json" or "broadcast" in path.name
                for path in entry.iterdir()
            ),
            "unexpected signing/broadcast state",
        )
    root_path = f"wallets/{wallet}/0/chains/ethereum/outbox"
    require(
        reader.directories(root_path + "/pending") == [outbox["id"]],
        "expected exactly one matching pending entry",
    )
    for chain in reader.directories(f"wallets/{wallet}/0/chains"):
        for state in ("pending", "confirmed", "failed", "sent"):
            if chain == "ethereum" and state == "pending":
                continue
            require(
                not reader.directories(
                    f"wallets/{wallet}/0/chains/{chain}/outbox/{state}"
                ),
                "unexpected extra/advanced outbox work",
            )
    validate(
        request,
        reader.read_json(base + "/status.json"),
        outbox,
        reader.read_json(base + "/quote.json"),
        reader.read_json(root_path + f"/pending/{outbox['id']}/intent.json"),
        expected,
    )


if __name__ == "__main__":
    try:
        verify()
    except (ValueError, KeyError, TypeError) as error:
        print(f"invalid NEAR proposal: {error}", file=sys.stderr)
        raise SystemExit(1)
    except OSError as error:
        print(f"NEAR projection unavailable ({type(error).__name__})", file=sys.stderr)
        raise SystemExit(2)
