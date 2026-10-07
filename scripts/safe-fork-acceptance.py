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
        token = url.rsplit('/', 1)[1]
        request = urllib.request.Request(f"http://localhost:{self.args.ceremony_port}/api/session", headers={"X-Bloom-Ceremony-Token": token})
        with urllib.request.urlopen(request, timeout=30) as response:
            session = json.load(response)
        review = session.get('review_manifest')
        if review:
            evidence = self.root/'reviews'
            evidence.mkdir(exist_ok=True)
            (evidence/f"review-{self.state['count']+1}.json").write_text(json.dumps(review, indent=2))
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
        account_one = self.cli("vfs", "cat", f"/wallets/{wallet}/1/address.evm", check=False)
        if account_one.returncode:
            self.write(f"/wallets/{wallet}/new", {"request_id": "safe-account-one"})
            creation = self.read(f"/wallets/{wallet}/new")
            request = next(r for r in creation["requests"] if r["request_id"] == "safe-account-one")
            self.complete(request["ceremony_url"])
            for _ in range(30):
                creation = self.read(f"/wallets/{wallet}/new")
                if any(r.get("state") == "created" and r.get("number") == 1 for r in creation["requests"]):
                    break
                time.sleep(1)
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
        previous = json.dumps(policy, sort_keys=True)
        policy["allowed_destinations"] = destinations
        if clear_signing is not None:
            policy["clear_signing"] = clear_signing
        # The package permission is added explicitly once the installed hash is known.
        if self.state.get("package_hash"):
            policy["allowed_petal_packages"] = [self.state["package_hash"]]
        if json.dumps(policy, sort_keys=True) == previous:
            return
        path = self.root / "fixture-policy.json"
        path.write_text(json.dumps(policy))
        p = self.cli("wallet", "update-policy", wallet, "--file", str(path))
        url = re.search(r"ceremony_url: (\S+)", p.stdout).group(1)
        operation = re.search(r"operation_id: (\S+)", p.stdout).group(1)
        self.complete(url)
        self.cli("wallet", "commit-policy", operation)

    def permissions(self):
        self.state['package_hash'] = re.search(r'^hash: ([0-9a-f]{64})', (self.root/'logs/petal-install.log').read_text()).group(1)
        destinations = [{"chain": "evm-8453", "destination": "exact"}]
        for address in ['0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67','0x14f2982d601c9458f93bd70b218933a6f8165e7b'] + list(self.state.get('safes', {}).values()):
            destinations.append({"chain": "base", "destination": address})
        self.policy(destinations)
        self.save()

    def create_safe(self, account, name, version, owners=None, threshold=1):
        path = f"/petals/safe/deployments/{self.state['wallet']}/{account}/{name}.json"
        existing = self.cli('vfs', 'cat', path, check=False)
        if existing.returncode:
            self.write(path, {"chain": "base", "version": version, "owners": owners or [self.state['addresses'][account]], "threshold": str(threshold), "salt_nonce": "20261007"})
        deployment = self.read(path)
        if not deployment.get('deployed'):
            self.confirm_outbox(account, deployment['deployment']['outbox_id'])
        for _ in range(60):
            deployment = self.read(path)
            if deployment.get('deployed'):
                break
            time.sleep(1)
        assert deployment.get('deployed'), deployment
        address = deployment['deployment']['safe_address']
        self.state.setdefault('safes', {})[name] = address
        self.save()
        self.rpc('anvil_setBalance', [address, hex(10**19)])
        self.write(f"/petals/safe/safes/{self.state['wallet']}/{account}/{name}.json", {"chain": "base", "safe_address": address})
        self.result('create and bind '+name, account=account, version=version, safe=address)

    def basic(self):
        self.permissions()
        self.create_safe(0, 'safe0', '1.4.1')
        self.create_safe(1, 'safe1', '1.5.0')
        self.permissions()
        recipient = '0x4000000000000000000000000000000000000000'
        for account in [0, 1]:
            name = 'account'+str(account)+'-transfer'
            before = int(self.rpc('eth_getBalance', [recipient, 'latest']), 16)
            self.draft(account, name, 'safe'+str(account), {"kind": "native_transfer", "to": recipient, "value": "1000000000000000"})
            self.sign(account, name)
            self.execute(account, name)
            assert int(self.rpc('eth_getBalance', [recipient, 'latest']), 16) - before == 10**15
            self.result(name+' exact balance delta')

    def refused(self, name, path, value=None):
        p = self.write(path, value, check=False)
        assert p.returncode != 0, name+' unexpectedly succeeded'
        self.result(name, error=p.stderr.strip())

    def transfer(self, account, name, safe, value='1000000000000', nonce=None):
        self.draft(account, name, safe, {"kind": "native_transfer", "to": '0x4000000000000000000000000000000000000000', "value": value}, nonce)
        self.sign(account, name)
        return self.execute(account, name)

    def native_call(self, account, to, data):
        root = f"/wallets/{self.state['wallet']}/{account}/chains/base/outbox"
        before = self.cli('vfs', 'ls', root+'/pending').stdout.splitlines()
        self.write(root+'/new.tx', {"kind":"raw", "to":to, "data":data, "value":"0 wei", "chain":"base"})
        after = self.cli('vfs', 'ls', root+'/pending').stdout.splitlines()
        names = [line.split()[0] for line in after if line not in before and 'Dir' in line]
        assert len(names) == 1, names
        self.confirm_outbox(account, names[0])
        txhash = self.cli('vfs','cat',root+'/sent/'+names[0]+'/tx_hash').stdout.strip()
        receipt = self.rpc('eth_getTransactionReceipt',[txhash])
        assert int(receipt['status'],16)==1
        assert receipt['from'].lower()==self.state['addresses'][account].lower()
        self.result('co-owner on-chain approval through Bloom', execution_tx_hash=txhash)

    def lifecycle(self):
        wallet = self.state['wallet']; recipient='0x4000000000000000000000000000000000000000'
        self.refused('wrong account cannot bind Safe',f'/petals/safe/safes/{wallet}/1/wrong-owner.json',{'chain':'base','safe_address':self.state['safes']['safe0']})
        before=int(self.rpc('eth_getBalance',[recipient,'latest']),16)
        self.draft(1,'batch','safe1',{'kind':'batch','calls':[{'to':recipient,'value':'1000000000000','data':'0x'},{'to':recipient,'value':'2000000000000','data':'0x'}]})
        self.sign(1,'batch'); self.execute(1,'batch')
        assert int(self.rpc('eth_getBalance',[recipient,'latest']),16)-before == 3*10**12
        self.result('batch exact balance delta')
        initcode='0x6001600c60003960016000f300'; salt='0x'+'0'*63+'7'
        self.draft(1,'deploy-contract','safe1',{'kind':'create2','value':'0','initcode':initcode,'salt':salt})
        self.sign(1,'deploy-contract'); self.execute(1,'deploy-contract')
        prediction=subprocess.check_output(['cast','create2','--deployer',self.state['safes']['safe1'],'--salt',salt,'--init-code',initcode],text=True)
        predicted=re.findall(r'0x[0-9a-fA-F]{40}',prediction)[-1]
        assert self.rpc('eth_getCode',[predicted,'latest'])=='0x00'
        self.result('deployed contract code',address=predicted)
        current=int(self.status(0,'account0-transfer')['current_safe_nonce'])
        self.draft(0,'queue-first','safe0',{'kind':'native_transfer','to':recipient,'value':'1000000000000'},current)
        self.draft(0,'queue-second','safe0',{'kind':'native_transfer','to':recipient,'value':'1000000000000'},current+1)
        self.sign(0,'queue-first'); self.sign(0,'queue-second')
        self.refused('future nonce cannot execute early',self.txpath(0,'queue-second','execute.json'),{})
        self.execute(0,'queue-first'); self.execute(0,'queue-second')
        self.draft(0,'cancelled-payment','safe0',{'kind':'native_transfer','to':recipient,'value':'1000000000000'})
        self.sign(0,'cancelled-payment')
        self.draft(0,'cancel-replacement','safe0',{'kind':'rejection'})
        self.sign(0,'cancel-replacement'); self.execute(0,'cancel-replacement')
        self.refused('cancelled payment cannot execute',self.txpath(0,'cancelled-payment','execute.json'),{})
        self.create_safe(0,'multisig','1.4.1',self.state['addresses'],2)
        self.permissions()
        self.draft(0,'two-owner','multisig',{'kind':'native_transfer','to':recipient,'value':'1000000000000'})
        signed=self.sign(0,'two-owner')
        self.refused('one signature cannot spend from two-owner Safe',self.txpath(0,'two-owner','execute.json'),{})
        data=subprocess.check_output(['cast','calldata','approveHash(bytes32)',signed['safe_tx_hash']],text=True).strip()
        self.native_call(1,self.state['safes']['multisig'],data)
        self.execute(0,'two-owner')
        self.draft(0,'stale-config','safe0',{'kind':'native_transfer','to':recipient,'value':'1000000000000'})
        self.draft(0,'add-owner','safe0',{'kind':'add_owner','owner':self.state['addresses'][1],'threshold':'2'})
        self.sign(0,'add-owner'); self.execute(0,'add-owner')
        self.refused('configuration change blocks old draft',self.txpath(0,'stale-config','confirm.json'))
        self.result('lifecycle matrix complete')

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
            review = json.loads((self.root/'reviews'/f"review-{self.state['count']}.json").read_text())['safe_review']
            assert review['owner'].lower() == self.state['addresses'][account].lower()
            assert review['safe_tx_hash'].lower() == status['safe_tx_hash'].lower()
            assert int(review['chain_id']) == self.state['chain_id']
            self.write(self.txpath(account, name, "confirm.json"))
        status = self.status(account, name)
        assert status["phase"] in ["signed", "proposed"], status
        return status

    def confirm_outbox(self, account, outbox):
        path = f"/wallets/{self.state['wallet']}/{account}/chains/base/outbox/pending/{outbox}"
        p = self.cli("vfs", "write", path + "/confirm", data="y", check=False)
        if p.returncode:
            challenge = self.read(path + "/ceremony.json")
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
    parser.add_argument("phase", choices=["setup", "basic", "lifecycle"])
    args = parser.parse_args()
    getattr(Acceptance(args), args.phase)()


if __name__ == "__main__":
    main()
