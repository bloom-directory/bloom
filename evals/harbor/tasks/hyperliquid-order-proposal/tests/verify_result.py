#!/usr/bin/env python3
"""Commitment-verified owner order proposal; never approve or sign."""

import json
import os
import stat
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from hyperliquid_proof import Unavailable, validate_proposal
from projection import ProjectionReader


def verify():
    reader = ProjectionReader()
    expected = json.loads(os.environ["BLOOM_EVAL_PROPOSAL"])
    requests = [
        reader.read_json("petal-signing-requests/" + name)
        for name, kind in reader.entries("petal-signing-requests").items()
        if kind == "File"
    ]
    if len(requests) != 1:
        raise ValueError("expected exactly one owner approval request")
    request = requests[0]
    url = urlsplit(request["ceremony_url"])
    if f"{url.scheme}://{url.netloc}" != os.environ["BLOOM_EVAL_BROKER_ORIGIN"]:
        raise Unavailable("approval review is not on the owned Broker")
    review_request = urllib.request.Request(
        f"{url.scheme}://{url.netloc}/api/session",
        headers={"x-bloom-ceremony-token": url.path.rsplit("/", 1)[1]},
    )
    with urllib.request.urlopen(review_request, timeout=15) as response:
        review = json.load(response)
    home = Path(os.environ["BLOOM_EVAL_PROJECTION_HOME"])
    root = home / "petals/data-accounts" / expected["package_hash"]
    pending = []
    for path in root.glob(
        f"v1-*/state/state/exchange/pending/testnet/{expected['wallet']}/order.json/*/nonce.json"
    ):
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o644:
            raise Unavailable("nonce record is not a regular public file")
        pending.append(json.loads(path.read_bytes()) | {"body_hash": path.parent.name})
    account = reader.read_json(f"wallets/{expected['wallet']}/0/account.json")
    trajectory = json.loads(Path(os.environ["BLOOM_EVAL_TRAJECTORY_FILE"]).read_bytes())
    proof = validate_proposal(requests, account, expected, review, trajectory, pending)
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    try:
        verify()
    except ValueError as error:
        print(f"invalid Hyperliquid proposal: {error}", file=sys.stderr)
        raise SystemExit(1)
    except (Unavailable, OSError, KeyError, TypeError) as error:
        # No URLs or raw responses: the Broker request contains a capability.
        print(
            f"Hyperliquid proof unavailable ({type(error).__name__})", file=sys.stderr
        )
        raise SystemExit(2)
