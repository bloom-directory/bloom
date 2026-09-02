"""Generic lifecycle and Harbor API integration for live Bloom evaluations."""

from __future__ import annotations

import asyncio
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import signal
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
_ceremony_port = os.environ.get("BLOOM_TRIAD_DEV_CEREMONY_PORT", "18734")
if not _ceremony_port.isdigit() or not 1 <= int(_ceremony_port) <= 65535:
    raise RuntimeError("BLOOM_TRIAD_DEV_CEREMONY_PORT must be an integer from 1 to 65535")
CEREMONY_URL = re.compile(
    rf"http://localhost:{re.escape(_ceremony_port)}/ceremony/[A-Za-z0-9_-]{{43}}"
)

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


class SignCountStore:
    """Durable record of the next unused WebAuthn signature counter.

    A counter that is not strictly greater than the last accepted one is
    rejected, which fails a run without doing anything. Tracking that by hand
    across two evals that share one authenticator is a reliable way to lose
    runs, so the harness records it instead. The file holds a single integer.
    """

    def __init__(self, path: Path | None) -> None:
        self.path = path

    @classmethod
    def for_seed_file(cls, seed_file: Path, override: str = "") -> SignCountStore:
        """Record the counter beside the credential it belongs to.

        A signature counter belongs to one authenticator, not to the machine.
        Two evals may be configured with different seed files, so a single
        shared record would carry one credential's counter into the other's
        run. Deriving the path from the seed file makes the association
        structural rather than something an operator has to remember.

        With no seed file configured there is nothing to key a record to. That
        is an error, but it is the seed-file validation's error to report, so
        this yields a store that simply holds nothing rather than raising a
        `ValueError` from `Path(".")` on the way past.
        """
        if override:
            return cls(Path(override))
        if not str(seed_file) or str(seed_file) == ".":
            return cls(None)
        return cls(seed_file.with_name(seed_file.name + ".sign-count"))

    def read(self) -> int | None:
        if self.path is None:
            return None
        try:
            raw = self.path.read_text().strip()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EvalError(f"could not read {self.path}: {error}") from error
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError as error:
            raise EvalError(
                f"{self.path} does not contain an integer sign count"
            ) from error
        if value < 1 or value > 0xFFFF_FFFF:
            raise EvalError(f"{self.path} holds an out-of-range sign count {value}")
        return value

    def write(self, value: int) -> None:
        if self.path is None:
            return
        # Never move the recorded counter backwards: a concurrent or earlier
        # run may already have consumed further than this one knows about.
        current = self.read()
        if current is not None and value <= current:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + ".tmp")
            temporary.write_text(f"{value}\n")
            temporary.replace(self.path)
        except OSError as error:
            raise EvalError(f"could not record the sign count: {error}") from error


def resolve_sign_count(env_value: str, store: SignCountStore, variable: str) -> int:
    """Take the counter from the environment when set, else from the store."""
    if env_value:
        try:
            value = int(env_value)
        except ValueError as error:
            raise EvalError(f"{variable} must be an integer") from error
    else:
        recorded = store.read()
        if recorded is None:
            where = "" if store.path is None else f" at {store.path}"
            raise EvalError(
                f"{variable} is not set and no counter has been recorded"
                f"{where}; set it once from the authenticator's last "
                "accepted signature counter plus one"
            )
        # Say so rather than proceeding silently. These evals move real funds,
        # and the counter is one of the few numbers an operator is expected to
        # be deliberate about; taking it from a file should still be visible.
        print(
            f"{variable} is unset; using the recorded counter {recorded} "
            f"from {store.path}",
            file=sys.stderr,
        )
        value = recorded
    if value < 1 or value > 0xFFFF_FFFF:
        raise EvalError(f"{variable} must be between 1 and 4294967295")
    return value


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
        store: SignCountStore | None = None,
    ) -> None:
        self.driver = driver
        self.seed_file = seed_file
        self.counter = start_count
        self.timeout = timeout
        self.store = store
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
        # `Path("")` is `.`, whose lstat succeeds as a directory and then fails
        # the regular-file check. That reports the wrong problem: the operator
        # did not misconfigure the path, they never set it.
        if not str(self.seed_file) or str(self.seed_file) == ".":
            raise EvalError("the authenticator seed file is not configured")
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
        used = self.counter
        self.counter = used + 1

        # Reserve the counter durably before invoking the driver. The assertion
        # may reach Broker even when the local process times out or is
        # interrupted, so persisting after subprocess completion can reuse a
        # counter that Broker has already accepted. If persistence fails, do
        # not attempt the ceremony at all.
        if self.store is not None:
            self.store.write(self.counter)

        try:
            completed = subprocess.run(
                [
                    str(self.driver),
                    "complete",
                    ceremony_url,
                    "--authenticator-seed-file",
                    str(self.seed_file),
                    "--sign-count",
                    str(used),
                ],
                check=False,
                capture_output=True,
                timeout=self.timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise EvalError(
                f"debug-driver ceremony completion failed at sign count {used} "
                f"(next unused counter is {self.counter}): "
                + self.redact(str(error))
            ) from error
        output = (completed.stdout + completed.stderr).decode(errors="replace")
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
    # Z.AI exposes GLM Coding Plan through an Anthropic-compatible endpoint,
    # so Harbor can run it with its existing Claude Code adapter.
    "glm": AgentSpec("claude-code", "glm-5.2"),
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

    agent_env = dict(spec.env)
    if name == "claude":
        if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_CODE_OAUTH_TOKEN")):
            raise EvalError(
                "Claude auth is missing; set ANTHROPIC_API_KEY or "
                "CLAUDE_CODE_OAUTH_TOKEN"
            )
        if os.getenv("CLAUDE_CODE_OAUTH_TOKEN") and not os.getenv("ANTHROPIC_API_KEY"):
            agent_env["CLAUDE_FORCE_OAUTH"] = "1"
    if name == "glm":
        api_key = (
            os.getenv("GLM_API_KEY")
            or os.getenv("ZAI_API_KEY")
            or os.getenv("ANTHROPIC_AUTH_TOKEN")
        )
        if not api_key:
            raise EvalError(
                "GLM Coding Plan auth is missing; set GLM_API_KEY, "
                "ZAI_API_KEY, or ANTHROPIC_AUTH_TOKEN"
            )
        agent_env.update(
            ANTHROPIC_AUTH_TOKEN=api_key,
            ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic",
            API_TIMEOUT_MS="3000000",
        )
    if name == "codex" and not os.getenv("OPENAI_API_KEY"):
        auth_file = Path.home() / ".codex" / "auth.json"
        if not auth_file.is_file():
            raise EvalError("Codex auth is missing")
        agent_env["CODEX_FORCE_AUTH_JSON"] = "1"

    model = os.getenv("BLOOM_EVAL_MODEL", spec.model).strip()
    if not model:
        raise EvalError("BLOOM_EVAL_MODEL must not be empty")
    return AgentSpec(spec.harbor_name, model, agent_env)


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
