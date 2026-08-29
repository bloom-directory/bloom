"""Generic lifecycle and Harbor API integration for live Bloom evaluations."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class EvalError(RuntimeError):
    """A fail-closed evaluation error suitable for operator display."""


# The Broker publishes owner ceremonies at a fixed local origin with a
# base64url-encoded 32-byte secret. The shape is Broker-wide, not specific to
# any one Petal or chain, so every eval that drives a passkey ceremony matches
# and redacts it the same way.
CEREMONY_URL = re.compile(r"http://localhost:18734/ceremony/[A-Za-z0-9_-]{43}")

# Mounted reads are not local file reads. Under a Petal they are live venue
# round-trips made by wasm; under a chain outbox they can wait on an RPC. Both
# are the network's latency, not the disk's, so the defaults are generous and a
# timeout is retried rather than failing the run.
DEFAULT_READ_TIMEOUT_SECONDS = 45
DEFAULT_READ_ATTEMPTS = 3


def poll_until(
    predicate: Callable[[], bool],
    attempts: int,
    delay: float,
) -> bool:
    """Poll `predicate` until it holds or the budget is spent.

    Returns True as soon as it holds. An `EvalError` from the predicate is
    treated as "not yet": a read that fails mid-settle should be retried within
    the budget, and the caller reports the failure if it never clears.
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


class MountedTree:
    """Reads and writes against a live Bloom mount.

    Every method here treats the mount as a remote, asynchronous surface rather
    than a filesystem: reads are retried, writes are dispatched through a
    subprocess so a hung mount cannot block the harness indefinitely, and
    existence is decided by a parent listing rather than by `stat`.
    """

    def __init__(
        self,
        *,
        read_timeout: int = DEFAULT_READ_TIMEOUT_SECONDS,
        read_attempts: int = DEFAULT_READ_ATTEMPTS,
    ) -> None:
        self.read_timeout = read_timeout
        self.read_attempts = read_attempts

    def read_json(self, path: Path, timeout: int | None = None) -> Any:
        """Read and parse JSON, retrying timeouts and torn snapshots.

        Owner-visible projections can be replaced while NFS is serving a read,
        so a malformed snapshot is retried rather than treated as durable
        corruption.
        """
        budget = self.read_timeout if timeout is None else timeout
        last_error: BaseException | None = None
        for attempt in range(self.read_attempts):
            try:
                completed = subprocess.run(
                    ["cat", str(path)],
                    check=True,
                    capture_output=True,
                    timeout=budget,
                )
            except subprocess.TimeoutExpired as error:
                last_error = error
                if attempt + 1 < self.read_attempts:
                    time.sleep(1.0)
                continue
            except (OSError, subprocess.SubprocessError) as error:
                raise EvalError(f"could not read {path}: {error}") from error
            try:
                return json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                last_error = error
                if attempt + 1 < self.read_attempts:
                    time.sleep(0.2)
                continue
        raise EvalError(
            f"could not read {path} after {self.read_attempts} attempts "
            f"of {budget}s: {last_error}"
        ) from last_error

    def read_json_if_listed(
        self, path: Path, listing_dir: Path, name: str
    ) -> Any | None:
        """Read `path` only when `name` actually appears in `listing_dir`.

        Dynamic routes can make `stat` succeed for identifiers that were never
        created, so a parent listing is the durable existence boundary. Returns
        None when the listing directory is absent or does not contain `name`.
        """
        try:
            listed = os.listdir(listing_dir)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EvalError(f"could not list {listing_dir}: {error}") from error
        if name not in listed:
            return None
        return self.read_json(path)

    def write_route(
        self, path: Path, body: bytes, timeout: int
    ) -> subprocess.CompletedProcess[bytes]:
        """Write one complete payload to a mounted write sink.

        The write runs in a subprocess so the timeout is enforceable: a mounted
        route write stages ceremonies and can make network calls before it
        returns. A zero exit code means accepted for dispatch, never completed.
        """
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

    @staticmethod
    def poll_until(
        predicate: Callable[[], bool], attempts: int, delay: float
    ) -> bool:
        return poll_until(predicate, attempts, delay)


class CeremonyDriver:
    """Completes Broker owner ceremonies with strictly increasing counters.

    Every WebAuthn completion must use a counter strictly greater than the last
    accepted one, so the counter advances per ceremony and is never reused. The
    driver owns that bookkeeping rather than leaving it to each eval, and
    reports the first counter it did not consume so an operator never has to
    recount by hand.
    """

    def __init__(
        self,
        driver: Path,
        seed_file: Path,
        start_count: int,
        *,
        timeout: int = 45,
    ) -> None:
        self.driver = driver
        self.seed_file = seed_file
        self.counter = start_count
        self.timeout = timeout
        self.completed: set[str] = set()

    @property
    def next_sign_count(self) -> int:
        """The first counter this run has not consumed."""
        return self.counter

    @staticmethod
    def redact(output: str) -> str:
        return CEREMONY_URL.sub("[REDACTED_CEREMONY_URL]", output)

    def preflight(self) -> None:
        """Validate the seed file and driver without consuming a counter."""
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

    def complete(self, ceremony_url: str) -> str:
        """Complete one ceremony. Exactly one attempt, then the counter moves.

        The Broker marks a consumed or absent ceremony CEREMONY_REPLAY with
        retry "never", so a second attempt cannot succeed and only burns
        another counter. Retrying here once turned one failure into three.
        """
        try:
            completed = subprocess.run(
                [
                    str(self.driver),
                    "complete",
                    ceremony_url,
                    "--authenticator-seed-file",
                    str(self.seed_file),
                    "--sign-count",
                    str(self.counter),
                ],
                check=False,
                capture_output=True,
                timeout=self.timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(
                "debug-driver ceremony completion failed: " + self.redact(str(error))
            ) from error
        output = (completed.stdout + completed.stderr).decode(errors="replace")
        used = self.counter
        self.counter += 1
        if completed.returncode != 0:
            raise EvalError(
                f"ceremony failed at sign count {used} "
                f"(next unused counter is {self.counter}): " + self.redact(output)
            )
        self.completed.add(ceremony_url)
        return output


@dataclass(frozen=True)
class AgentSpec:
    harbor_name: str
    model: str
    env: Mapping[str, str] = field(default_factory=dict)


AGENTS: dict[str, AgentSpec] = {
    # Model ids are the API's, not the marketing names: "sonnet-5" is rejected
    # with a 404 unrecognized_model, which surfaces as an errored Harbor trial
    # rather than a configuration error.
    "claude": AgentSpec("claude-code", "claude-sonnet-5"),
    "codex": AgentSpec("codex", "gpt-5.6-terra"),
}


@dataclass(frozen=True)
class EvalRunContext:
    eval_name: str
    task_dir: Path
    job_name: str
    jobs_dir: Path
    mounts: Sequence[Mapping[str, Any]]
    agent_env: Mapping[str, str]
    verifier_env: Mapping[str, str]


class EvalDefinition(ABC):
    """Trusted host-side lifecycle for one kind of Harbor evaluation.

    New evaluations implement this interface while reusing locking, agent setup,
    Harbor job construction, result handling, signals, and cleanup.
    """

    name: str

    @property
    @abstractmethod
    def lock_path(self) -> Path:
        """Global lock that serializes this live side-effect domain."""

    @abstractmethod
    def preflight(self) -> None:
        """Validate prerequisites without creating external authority."""

    @abstractmethod
    def provision(self, agent_name: str) -> EvalRunContext:
        """Create the least-authority capability and return Harbor inputs."""

    @abstractmethod
    def cleanup(self) -> None:
        """Remove residual side effects and revoke the provisioned capability."""

    def validate_result(self, result: Any) -> None:
        """Fail unless Harbor completed one error-free, positively graded trial."""
        stats = result.stats
        if stats.n_errored_trials or stats.n_cancelled_trials:
            raise EvalError(
                "Harbor reported "
                f"{stats.n_errored_trials} errored and "
                f"{stats.n_cancelled_trials} cancelled trials"
            )
        trials = result.trial_results
        if len(trials) != 1:
            raise EvalError(f"expected exactly one Harbor trial, got {len(trials)}")
        trial = trials[0]
        if trial.exception_info is not None:
            raise EvalError(
                "Harbor trial failed with "
                f"{trial.exception_info.exception_type}: "
                f"{trial.exception_info.exception_message}"
            )
        if trial.verifier_result is None:
            raise EvalError("Harbor trial returned no verifier result")
        rewards = trial.verifier_result.rewards
        if not rewards or any(float(value) <= 0 for value in rewards.values()):
            raise EvalError(
                f"Harbor verifier did not award a passing reward: {rewards}"
            )


async def run_harbor_job(context: EvalRunContext, agent: AgentSpec) -> Any:
    """Run one task through Harbor's public 0.21 Job API."""
    from harbor.job import Job
    from harbor.models.environment_type import EnvironmentType
    from harbor.models.job.config import JobConfig, RetryConfig
    from harbor.models.trial.config import (
        AgentConfig,
        EnvironmentConfig,
        TaskConfig,
        VerifierConfig,
    )

    shared_env = dict(context.agent_env)
    shared_env.update(agent.env)
    config = JobConfig(
        job_name=context.job_name,
        jobs_dir=context.jobs_dir,
        n_attempts=1,
        n_concurrent_trials=1,
        retry=RetryConfig(max_retries=0),
        agents=[
            AgentConfig(
                name=agent.harbor_name,
                model_name=agent.model,
                n_concurrent=1,
                env=shared_env,
            )
        ],
        environment=EnvironmentConfig(
            type=EnvironmentType.DOCKER,
            mounts=list(context.mounts),
        ),
        verifier=VerifierConfig(env=dict(context.verifier_env)),
        tasks=[TaskConfig(path=context.task_dir)],
    )
    job = await Job.create(config)
    return await job.run()


HarborRunner = Callable[[EvalRunContext, AgentSpec], Coroutine[Any, Any, Any]]


def _agent_spec(name: str) -> AgentSpec:
    try:
        spec = AGENTS[name]
    except KeyError as error:
        raise EvalError(
            f"unsupported agent {name!r}; choose: {', '.join(AGENTS)}"
        ) from error

    if name == "claude":
        if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_CODE_OAUTH_TOKEN")):
            raise EvalError(
                "Claude auth is missing; set ANTHROPIC_API_KEY or "
                "CLAUDE_CODE_OAUTH_TOKEN"
            )
        if os.getenv("CLAUDE_CODE_OAUTH_TOKEN") and not os.getenv("ANTHROPIC_API_KEY"):
            return AgentSpec(spec.harbor_name, spec.model, {"CLAUDE_FORCE_OAUTH": "1"})
    if name == "codex" and not os.getenv("OPENAI_API_KEY"):
        auth_file = Path.home() / ".codex" / "auth.json"
        if not auth_file.is_file():
            raise EvalError("Codex auth is missing")
        return AgentSpec(spec.harbor_name, spec.model, {"CODEX_FORCE_AUTH_JSON": "1"})
    return spec


def run_eval(
    definition: EvalDefinition,
    agent_name: str,
    *,
    harbor_runner: HarborRunner = run_harbor_job,
    acquire_lock: bool = True,
    phase_timings: dict[str, float] | None = None,
) -> Any:
    """Execute one provisioned eval and guarantee outer cleanup."""
    agent = _agent_spec(agent_name)
    definition.lock_path.parent.mkdir(parents=True, exist_ok=True)
    timings = phase_timings if phase_timings is not None else {}

    def execute() -> Any:
        started = time.monotonic()
        definition.preflight()
        timings["preflight_seconds"] = time.monotonic() - started
        provision_started = False
        run_error: BaseException | None = None
        result: Any | None = None
        previous_term_handler = signal.getsignal(signal.SIGTERM)

        def terminate(_signum: int, _frame: object) -> None:
            raise KeyboardInterrupt("received SIGTERM")

        signal.signal(signal.SIGTERM, terminate)
        try:
            provision_started = True
            started = time.monotonic()
            context = definition.provision(agent_name)
            timings["authority_provisioning_seconds"] = time.monotonic() - started
            started = time.monotonic()
            result = asyncio.run(harbor_runner(context, agent))
            timings["harbor_seconds"] = time.monotonic() - started
            definition.validate_result(result)
        except BaseException as error:  # noqa: BLE001 -- cleanup must cover interrupts
            run_error = error
        finally:
            signal.signal(signal.SIGTERM, previous_term_handler)
            if provision_started:
                started = time.monotonic()
                try:
                    definition.cleanup()
                    timings["session_cleanup_seconds"] = time.monotonic() - started
                except BaseException as cleanup_error:
                    timings["session_cleanup_seconds"] = time.monotonic() - started
                    if run_error is not None:
                        raise EvalError(
                            f"evaluation failed ({run_error}); cleanup also failed: "
                            f"{cleanup_error}"
                        ) from cleanup_error
                    raise

        if run_error is not None:
            raise run_error
        return result

    if not acquire_lock:
        return execute()

    with definition.lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise EvalError(
                f"another {definition.name} eval holds {definition.lock_path}"
            ) from error

        return execute()
