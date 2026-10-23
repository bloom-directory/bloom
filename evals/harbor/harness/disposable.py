"""One real Triad and software authenticator per Harbor trial.

Secrets remain on the host. Import phrases go only to Broker's ceremony
driver; the Machine and the agent never receive them.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .core import EvalError

CEREMONY = re.compile(r"http://localhost:[0-9]+/ceremony/[A-Za-z0-9_-]{43}")


def private_file(path: Path) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise EvalError(f"{path} must be a regular file with mode 0600")
    if metadata.st_uid != os.getuid() or metadata.st_size == 0:
        raise EvalError(f"{path} must be nonempty and owned by the current user")


def free_port() -> int:
    # The launcher owns the eventual bind. A collision fails rather than
    # taking over a listener that appeared between selection and startup.
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


class CeremonyDriver:
    def __init__(self, binary: Path, seed: Path, origin: str) -> None:
        self.binary, self.seed, self.origin = binary, seed, origin
        self.counter = 1

    def complete(self, url: str, mnemonic: Path | None = None) -> dict[str, Any]:
        if CEREMONY.fullmatch(url) is None or not url.startswith(
            self.origin + "/ceremony/"
        ):
            raise EvalError("ceremony does not belong to this trial's Triad")
        used = self.counter
        if used > 0xFFFF_FFFF:
            raise EvalError("authenticator counter exhausted")
        self.counter += 1  # Reserve before every attempt, including failures.
        command = [
            str(self.binary),
            "complete",
            url,
            "--authenticator-seed-file",
            str(self.seed),
            "--sign-count",
            str(used),
        ]
        if mnemonic is not None:
            private_file(mnemonic)
            command.extend(["--mnemonic-file", str(mnemonic)])
        try:
            result = subprocess.run(
                command, capture_output=True, timeout=45, check=False
            )
        except (OSError, subprocess.SubprocessError) as error:
            # Exceptions may contain argv, including the ceremony capability.
            raise EvalError(
                f"ceremony attempt {used} failed ({type(error).__name__})"
            ) from None
        if result.returncode:
            raise EvalError(
                f"ceremony attempt {used} failed (exit {result.returncode})"
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise EvalError("ceremony driver returned invalid JSON") from None


class DisposableTriad:
    def __init__(self, repo: Path, env: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if env is None else env)
        self.root: Path | None = None
        self.launcher: subprocess.Popen[bytes] | None = None
        self.validator: subprocess.Popen[bytes] | None = None
        self.driver: CeremonyDriver | None = None
        self.rpc_url = ""
        self.genesis = ""
        self.wallet = ""
        self.mount_lock = None

    def preflight(self) -> None:
        for role in ("MACHINE", "BROKER", "SIGNER", "DEBUG_DRIVER"):
            name = f"BLOOM_INTEGRATION_{role}_BIN"
            binary = Path(self.env.get(name, ""))
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise EvalError(f"{name} must name the exact executable under test")

    def _run(self, command: list[str], *, timeout: int = 120) -> str:
        try:
            result = subprocess.run(
                command, env=self.env, capture_output=True, timeout=timeout, check=False
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(
                f"{Path(command[0]).name} failed ({type(error).__name__})"
            ) from None
        if result.returncode:
            detail = CEREMONY.sub("[ceremony]", result.stderr.decode(errors="replace"))
            raise EvalError(
                f"{Path(command[0]).name} exited {result.returncode}: {detail[-1500:]}"
            )
        return result.stdout.decode()

    def cli(self, *args: str) -> str:
        return self._run([self.env["BLOOM_INTEGRATION_MACHINE_BIN"], *args])

    def projection_env(self) -> dict[str, str]:
        return {
            "BLOOM_EVAL_PROJECTION_BIN": self.env["BLOOM_INTEGRATION_MACHINE_BIN"],
            "BLOOM_EVAL_PROJECTION_HOME": str(self.home),
            "BLOOM_EVAL_PROJECTION_RPC_ENDPOINT": self.env["BLOOM_RPC_ENDPOINT"],
        }

    def read(self, path: str) -> Any:
        return json.loads(self.cli("vfs", "cat", path))

    def write(self, path: str, body: str) -> None:
        self.cli("vfs", "write", path, "--data", body)

    def write_mounted(self, path: str, body: str) -> bool:
        writer = (
            "import os,sys; f=open(sys.argv[1],'wb',buffering=0); "
            "f.write(sys.stdin.buffer.read()); os.fsync(f.fileno()); f.close()"
        )
        result = subprocess.run(
            ["python3", "-c", writer, str(self.mount) + path],
            input=body.encode(),
            capture_output=True,
            timeout=120,
            check=False,
        )
        return result.returncode == 0

    def _wait(
        self,
        predicate: Any,
        process: subprocess.Popen[bytes],
        label: str,
        timeout: int = 300,
    ) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise EvalError(
                    f"{label} exited before becoming ready; logs: {self.root}"
                )
            try:
                value = predicate()
                if value:
                    return value
            except (EvalError, OSError, json.JSONDecodeError):
                pass
            time.sleep(0.2)
        raise EvalError(
            f"{label} did not become ready within {timeout}s; logs: {self.root}"
        )

    def start(
        self, *, solana: bool = False, mount: bool = True, mnemonic: Path | None = None
    ) -> None:
        self.preflight()
        if mnemonic is not None:
            private_file(mnemonic)
        self.root = Path(tempfile.mkdtemp(prefix="bhe-", dir="/tmp"))
        self.root.chmod(0o700)
        self.home = self.root / "dev/home"
        self.mount = Path(
            self.env.get("BLOOM_EVAL_MOUNTPOINT", str(self.root / "mount"))
        )
        if mount and self.mount != self.root / "mount":
            if (
                not self.mount.is_absolute()
                or self.mount.is_symlink()
                or os.path.ismount(self.mount)
            ):
                raise EvalError(
                    "explicit eval mountpoint must be an unmounted absolute directory"
                )
            self.mount.mkdir(parents=True, exist_ok=True)
            if any(self.mount.iterdir()):
                raise EvalError("explicit eval mountpoint must be empty")
            descriptor = os.open(
                str(self.mount) + ".harbor.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            self.mount_lock = os.fdopen(descriptor, "w")
            try:
                fcntl.flock(self.mount_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise EvalError(
                    "another trial owns the explicit eval mountpoint"
                ) from None
        self.origin = f"http://localhost:{free_port()}"
        seed = self.root / "auth.seed"
        seed.write_text(secrets.token_hex(32))
        seed.chmod(0o600)
        self.driver = CeremonyDriver(
            Path(self.env["BLOOM_INTEGRATION_DEBUG_DRIVER_BIN"]), seed, self.origin
        )
        config = f'nfs_listen_addr = "127.0.0.1:{free_port()}"\n'
        # Use an explicit public chain set, never copy an operator config.
        config += (
            'default_chain = "ethereum"\n[chains.ethereum]\nname = "ethereum"\n'
            'chain_id = 1\nrpc_urls = ["https://ethereum-rpc.publicnode.com"]\n'
            'display_name = "Ethereum"\nnative_symbol = "ETH"\nnative_decimals = 18\n'
            '[chains.polygon]\nname = "polygon"\nchain_id = 137\n'
            'rpc_urls = ["https://polygon-bor-rpc.publicnode.com"]\n'
            'display_name = "Polygon"\nnative_symbol = "POL"\nnative_decimals = 18\n'
        )
        if solana:
            port = free_port()
            self.rpc_url = f"http://127.0.0.1:{port}"
            with (self.root / "validator.log").open("wb") as log:
                self.validator = subprocess.Popen(
                    [
                        "solana-test-validator",
                        "--ledger",
                        str(self.root / "ledger"),
                        "--rpc-port",
                        str(port),
                        "--faucet-port",
                        str(free_port()),
                        "--bind-address",
                        "127.0.0.1",
                        "--limit-ledger-size",
                        "20000",
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
            self.genesis = self._wait(
                lambda: self._run(
                    ["solana", "genesis-hash", "--url", self.rpc_url], timeout=5
                ).strip(),
                self.validator,
                "local validator",
            )
            if self.genesis == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d":
                raise EvalError("local validator returned mainnet genesis")
            config += (
                '[solana_chains.solana-local]\nname = "solana-local"\n'
                f'expected_genesis_base58 = "{self.genesis}"\n'
                "[[solana_chains.solana-local.endpoints]]\n"
                f'url = "{self.rpc_url}"\nweight = 100\n'
            )
        config_path = self.root / "machine.toml"
        config_path.write_text(config)
        config_path.chmod(0o600)
        self.env.update(
            {
                "BLOOM_TRIAD_DEV_MACHINE_CONFIG": str(config_path),
                "BLOOM_HOME": str(self.home),
                "BLOOM_RPC_ENDPOINT": f"unix:{self.root}/machine.sock",
            }
        )
        command = [
            str(self.repo / "scripts/triad-dev-launch.sh"),
            "--developer-root",
            str(self.root / "dev"),
            "--machine-home",
            str(self.home),
            "--machine-socket",
            str(self.root / "machine.sock"),
            "--log-dir",
            str(self.root / "logs"),
            "--ready-file",
            str(self.root / "ready"),
            "--ceremony-port",
            self.origin.rsplit(":", 1)[1],
        ]
        if mount:
            command.extend(["--mount", str(self.mount)])
        with (self.root / "launcher.log").open("wb") as log:
            self.launcher = subprocess.Popen(
                command, env=self.env, stdout=log, stderr=subprocess.STDOUT
            )
        self._wait(lambda: (self.root / "ready").exists(), self.launcher, "Triad")
        launch = self.cli("wallet", "import" if mnemonic else "new", "harbor")
        url = CEREMONY.search(launch)
        if url is None:
            raise EvalError("wallet enrollment returned no ceremony")
        result = self.driver.complete(url.group(), mnemonic)
        self.wallet = result["wallet_id"]

    def set_policy(
        self, *, packages: list[str], destinations: list[dict[str, str]]
    ) -> None:
        policy = self.read(f"/wallets/{self.wallet}/policy.json")
        policy.update(
            allowed_petal_packages=packages, allowed_destinations=destinations
        )
        path = self.root / "policy.json"
        path.write_text(json.dumps(policy))
        launch = self.cli("wallet", "update-policy", self.wallet, "--file", str(path))
        url = CEREMONY.search(launch)
        operation = re.search(r"^operation_id: ([0-9a-f]{64})$", launch, re.MULTILINE)
        if url is None or operation is None:
            raise EvalError("policy setup returned no exact operation and ceremony")
        self.driver.complete(url.group())
        self.cli("wallet", "commit-policy", operation[1])
        if self.read(f"/wallets/{self.wallet}/policy.json") != policy:
            raise EvalError("setup policy differs from its committed projection")

    def require_petal(self, name: str) -> str:
        # Do not execute Petal routes while startup is installing packages:
        # a busy VM rejects package changes. The owner record is published
        # when the package commits; only then read its mounted documentation.
        owner = self.home / "petals/store/owners" / f"{name}.json"
        return self._wait(
            lambda: owner.is_file()
            and self.cli("vfs", "cat", f"/petals/{name}/README.md"),
            self.launcher,
            f"default Petal {name}",
        )

    def close(self, *, preserve: bool = False) -> None:
        failures = []
        for process in (self.launcher, self.validator):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    failures.append(f"owned process {process.pid} did not stop")
        if failures:
            raise EvalError("; ".join(failures))
        if self.mount_lock is not None:
            self.mount_lock.close()
            self.mount_lock = None
        if self.root is not None and not preserve:
            if os.path.ismount(self.mount):
                raise EvalError(
                    f"disposable mount remains active at {self.mount}; preserving root"
                )
            # Ordinary recursive removal, never forced; an unexpected mount or
            # permissions problem is a cleanup failure and preserves evidence.
            result = subprocess.run(
                ["rm", "-r", "--one-file-system", "--", str(self.root)],
                capture_output=True,
                timeout=45,
                check=False,
            )
            if result.returncode:
                raise EvalError(f"could not remove disposable root {self.root}")
