#!/usr/bin/env python3
"""Exercise the compiled Safe Petal through a disposable real-service triad.

Only run against a local Anvil fork and an isolated developer triad. The wallet
is imported from the public acceptance mnemonic, never a funded wallet.
"""
import argparse
import json
import re
import subprocess
import time
import urllib.request
from pathlib import Path


class Acceptance:
    def __init__(self, args):
        self.args = args
        self.root = Path(args.root)
        self.state_file = self.root / "acceptance-state.json"
        self.state = json.loads(self.state_file.read_text()) if self.state_file.exists() else {"count": 0, "results": []}

    def save(self):
        self.state_file.write_text(json.dumps(self.state, indent=2) + "\n")

    def result(self, name, **details):
        self.state["results"].append({"test": name, "status": "passed", **details})
        self.save()
        print("PASS", name, flush=True)

    def cli(self, *args, data=None, check=True):
        command = [self.args.bloom, "--home", str(self.root / "dev/home"), "--connect", "unix:" + str(self.root / "m.sock"), *args]
        p = subprocess.run(command, input=data, text=True, capture_output=True, timeout=180)
        if check and p.returncode:
            raise RuntimeError(f"Bloom {args[:2]} exited {p.returncode}: {p.stderr[-1800:]}")
        return p

    def read(self, path):
        return json.loads(self.cli("vfs", "cat", path).stdout)

    def write(self, path, value=None, check=True):
        return self.cli("vfs", "write", path, data=json.dumps(value) if value is not None else "", check=check)

    def rpc(self, method, params):
        request = urllib.request.Request(self.args.rpc, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=90) as response:
            data = json.load(response)
        if "error" in data:
            raise RuntimeError(f"{method}: {data['error']}")
        return data["result"]

    def complete(self, url, mnemonic=None):
        assert url.startswith("http://localhost:" + str(self.args.ceremony_port) + "/ceremony/")
        self.state["count"] += 1
        self.save()
        command = [self.args.driver, "complete", url, "safe-fork-1007", "--sign-count", str(self.state["count"])]
        if mnemonic:
            command += ["--mnemonic-file", str(mnemonic)]
        p = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if p.returncode:
            raise RuntimeError("Disposable ceremony failed: " + p.stderr[-1600:])
        return json.loads(p.stdout)

    def setup(self):
        assert self.args.rpc.startswith("http://127.0.0.1:")
        assert "anvil" in self.rpc("web3_clientVersion", []).lower()
        self.state["chain_id"] = int(self.rpc("eth_chainId", []), 16)
        self.state.setdefault("fork_block", int(self.rpc("eth_blockNumber", []), 16))
        if "wallet" not in self.state:
            mnemonic = self.root / "public-fixture-mnemonic.txt"
            mnemonic.write_text(" ".join(["abandon"] * 23 + ["art"]) + "\n")
            mnemonic.chmod(0o600)
            p = self.cli("wallet", "import", "safeaccept")
            url = re.search(r"ceremony_url: (\S+)", p.stdout).group(1)
            result = self.complete(url, mnemonic)
            self.state["wallet"] = result["wallet_id"]
            self.save()
        wallet = self.state["wallet"]
        addresses = []
        for account in [0, 1]:
            address = self.cli("vfs", "cat", f"/wallets/{wallet}/{account}/address.evm").stdout.strip()
            assert re.fullmatch(r"0x[0-9a-fA-F]{40}", address)
            addresses.append(address)
            self.rpc("anvil_setBalance", [address, hex(10**20)])
        assert addresses[0] != addresses[1]
        self.state["addresses"] = addresses
        self.save()
        self.result("two distinct Bloom accounts available", addresses=addresses)

    def policy(self, destinations, clear_signing=None):
        wallet = self.state["wallet"]
        policy = self.read(f"/wallets/{wallet}/policy.json")
        policy["allowed_destinations"] = destinations
        if clear_signing is not None:
            policy["clear_signing"] = clear_signing
        # The package permission is added explicitly once the installed hash is known.
        if self.state.get("package_hash"):
            policy["allowed_petal_packages"] = [self.state["package_hash"]]
        path = self.root / "fixture-policy.json"
        path.write_text(json.dumps(policy))
        p = self.cli("wallet", "update-policy", wallet, "--file", str(path))
        url = re.search(r"ceremony_url: (\S+)", p.stdout).group(1)
        operation = re.search(r"operation_id: (\S+)", p.stdout).group(1)
        self.complete(url)
        self.cli("wallet", "commit-policy", operation)

    def txpath(self, account, name, leaf):
        return f"/petals/safe/transactions/{self.state['wallet']}/{account}/{name}/{leaf}"

    def status(self, account, name):
        return self.read(self.txpath(account, name, "status.json"))

    def draft(self, account, name, safe_id, transaction, nonce=None):
        request = {"safe_id": safe_id, "transaction": transaction}
        if nonce is not None:
            request["nonce"] = str(nonce)
        self.write(self.txpath(account, name, "draft.json"), request)
        return self.status(account, name)

    def sign(self, account, name):
        self.write(self.txpath(account, name, "confirm.json"))
        status = self.status(account, name)
        if status["phase"] == "approval_required":
            action = status["approval_action_id"]
            projection = self.read(f"/petal-signing-requests/{action}.json")
            self.complete(projection["ceremony_url"])
            self.write(self.txpath(account, name, "confirm.json"))
        status = self.status(account, name)
        assert status["phase"] in ["signed", "proposed"], status
        return status

    def confirm_outbox(self, account, outbox):
        path = f"/wallets/{self.state['wallet']}/{account}/chains/base/outbox/pending/{outbox}"
        p = self.cli("vfs", "write", path + "/confirm", data="y", check=False)
        if p.returncode:
            challenge = self.read(path + "/approval_challenge.json")
            self.complete(challenge["ceremony_url"])
            p = self.cli("vfs", "write", path + "/confirm", data="y", check=False)
        if p.returncode:
            raise RuntimeError("Outbox confirmation failed: " + p.stderr[-1200:] + p.stdout[-1200:])

    def execute(self, account, name):
        self.write(self.txpath(account, name, "execute.json"), {})
        status = self.status(account, name)
        self.confirm_outbox(account, status["outbox_id"])
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            status = self.status(account, name)
            if status["phase"] == "executed":
                txhash = status["execution_tx_hash"]
                receipt = self.rpc("eth_getTransactionReceipt", [txhash])
                assert int(receipt["status"], 16) == 1
                assert receipt["from"].lower() == self.state["addresses"][account].lower()
                self.result(name, account=account, safe_tx_hash=status["safe_tx_hash"], execution_tx_hash=txhash, sender=receipt["from"])
                return status
            if status["phase"] in ["execution_failed", "execution_cancelled", "nonce_conflict"]:
                raise RuntimeError(str(status))
            time.sleep(1)
        raise TimeoutError(name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--bloom", required=True)
    parser.add_argument("--driver", required=True)
    parser.add_argument("--rpc", default="http://127.0.0.1:29546")
    parser.add_argument("--ceremony-port", type=int, default=29547)
    parser.add_argument("phase", choices=["setup"])
    args = parser.parse_args()
    Acceptance(args).setup()


if __name__ == "__main__":
    main()
