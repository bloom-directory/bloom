"""Generic lifecycle and Harbor API integration for live Bloom evaluations."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import os
import signal
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class EvalError(RuntimeError):
    """A fail-closed evaluation error suitable for operator display."""


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


class CounterSidecar:
    """A durable next-unused-WebAuthn-counter file for direct runs.

    The operator lifecycle persists counters in its own state file. A run
    started straight from `python -m harness` has no such file, so without
    this every ceremony advanced the counter in memory only: the next
    process re-read the unchanged `BLOOM_EVAL_AUTHENTICATOR_SIGN_COUNT`,
    replayed a spent counter, and Broker rejected the assertion.

    The file holds one integer and is written atomically through a
    temporary in the same directory, so an interrupted write leaves either
    the old value or the new one, never a truncated file. Reads take the
    larger of the environment value and the recorded one: an operator
    raising the environment counter is honoured, while a recorded counter
    is never silently rolled back.
    """

    SCHEMA = "bloom.eval.counter-sidecar.v1"

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser()

    def read(self) -> int | None:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise EvalError(f"counter sidecar is unreadable: {error}") from error
        try:
            value = json.loads(raw)
            counter = value["next_sign_count"]
            schema = value["schema"]
        except (json.JSONDecodeError, TypeError, KeyError) as error:
            raise EvalError(f"counter sidecar is malformed: {error}") from error
        if schema != self.SCHEMA:
            raise EvalError(f"counter sidecar has unexpected schema {schema!r}")
        if not isinstance(counter, int) or isinstance(counter, bool):
            raise EvalError("counter sidecar next_sign_count is not an integer")
        if not 1 <= counter <= 0xFFFF_FFFF:
            raise EvalError("counter sidecar next_sign_count is out of range")
        return counter

    def write(self, next_counter: int) -> None:
        recorded = self.read()
        if recorded is not None and next_counter < recorded:
            # Never move a counter backwards: the lower value may already
            # have been accepted by Broker, and reusing it reads as a replay.
            raise EvalError("refusing a non-advancing counter sidecar update")
        body = json.dumps(
            {"schema": self.SCHEMA, "next_sign_count": next_counter},
            sort_keys=True,
            separators=(",", ":"),
        ).encode() + b"\n"
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.path.with_name(f".{self.path.name}.new-{os.getpid()}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary.exists():
                temporary.unlink()

    def verify_writable(self) -> None:
        """Prove a commit can land, without moving the counter."""
        recorded = self.read()
        if recorded is None:
            # Nothing recorded yet: prove the directory accepts a write by
            # creating and removing the same temporary a commit would use.
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            probe = self.path.with_name(f".{self.path.name}.probe-{os.getpid()}")
            descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            probe.unlink()
            return
        self.write(recorded)


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
    def preauthorization_preflight(self) -> None:
        """Verify installed ownership and provenance; never inspect wallet policy."""

    @abstractmethod
    def provision(self, agent_name: str) -> EvalRunContext:
        """Create the least-authority capability and return Harbor inputs."""

    @abstractmethod
    def cleanup(self) -> None:
        """Remove residual side effects and revoke the provisioned capability."""

    # ---- WebAuthn counter reservation -------------------------------------
    #
    # Every ceremony this harness drives spends one authenticator counter.
    # Broker rejects a reused counter as a replay, so a counter must be
    # treated as spent from the moment the driver could possibly reach
    # Broker -- not once it returns. Both live Hyperliquid evals reserve
    # through these two methods so the durability rule has one definition.

    #: Set by the operator to persist the next unused counter durably.
    #: `None` when the eval is driven without an operator state file.
    counter_committed: Callable[[int], None] | None = None
    #: Set by the operator to prove that persistence works, without
    #: advancing anything. `None` when there is no sidecar to check.
    counter_durability_check: Callable[[], None] | None = None
    #: The first counter this run has not consumed.
    next_sign_count: int | None = None

    def attach_counter_sidecar(self, sidecar: "CounterSidecar") -> None:
        """Persist this run's counters to `sidecar`.

        Wires commit, durability check, and the resume floor together, so a
        direct run gets the same never-reuse guarantee the operator
        lifecycle provides through its own state file.
        """
        self.counter_committed = sidecar.write
        self.counter_durability_check = sidecar.verify_writable
        self.counter_floor = sidecar.read

    #: Returns a durably recorded next-unused counter, if one exists.
    counter_floor: Callable[[], int | None] | None = None

    def resume_counter(self, configured: int) -> int:
        """The first counter safe to attempt this process.

        Takes the larger of the configured counter and any durably recorded
        one. A recorded counter is the record of what a previous process
        already spent, so starting below it replays; an operator raising
        the configured value above it is still honoured.
        """
        if self.counter_floor is None:
            return configured
        recorded = self.counter_floor()
        if recorded is None:
            return configured
        return max(configured, recorded)

    def require_counter_durability(self) -> None:
        """Fail preflight unless a reserved counter can actually be persisted.

        `reserve_counter` commits before invoking the driver precisely so an
        interrupted run cannot reuse a counter. That guarantee is only as
        good as the sidecar write behind `counter_committed`: if the
        operator state file is read-only, or its directory is not writable,
        the commit raises *after* the assertion may already have reached
        Broker. The counter is then spent at Broker but not recorded, and
        the next run starts from a counter Broker will reject as a replay.

        Checking it here converts that into a clean refusal before any
        authority is created. An eval driven without an operator state file
        has nothing to verify and is left alone.
        """
        if self.counter_durability_check is None:
            return
        try:
            self.counter_durability_check()
        except EvalError:
            raise
        except Exception as error:  # noqa: BLE001 - reported, not swallowed
            raise EvalError(
                "authenticator counter sidecar is not writable, so a spent "
                f"counter could not be recorded: {error}"
            ) from error

    def reserve_counter(self, counter: int) -> int:
        """Durably reserve `counter` and return the next unused one.

        Commits *before* the caller invokes the driver: the assertion may
        reach Broker even if this process is interrupted or times out
        before the subprocess returns, so persisting afterwards is too late
        to guarantee the counter is never reused.
        """
        reserved = counter + 1
        if self.counter_committed is not None:
            self.counter_committed(reserved)
        self.next_sign_count = reserved
        return reserved

    # ---- Wallet identity binding ------------------------------------------

    def require_wallet_binding(
        self,
        addresses: Any,
        owner_address: str,
        *,
        label: str = "BLOOM_EVAL_WALLET",
    ) -> None:
        """Fail unless the wallet id actually owns `owner_address`.

        These evals address two different things by two different
        identifiers: writes go to the Bloom wallet id, while the venue
        projection that supplies independent evidence is keyed by the
        on-chain address. Nothing else ties them together, so without this
        an eval can authorize one wallet and grade another -- and still
        look entirely consistent, because each half is valid on its own.

        The projection's own trust markers are checked here too: a policy
        that Broker has not verified, or a stale projection, is not
        evidence about the wallet this run is about to touch.
        """
        if not isinstance(addresses, dict):
            raise EvalError("eval wallet addresses projection is not a JSON object")
        owner = addresses.get("owner")
        if not isinstance(owner, str) or owner.lower() != owner_address:
            raise EvalError(f"BLOOM_EVAL_WALLET_ID does not own {label}")
        if addresses.get("policy_status") != "broker_verified":
            raise EvalError("eval wallet policy is not Broker-verified")
        if addresses.get("freshness") != "fresh":
            raise EvalError("eval wallet policy projection is stale")

    @staticmethod
    def require_policy_digest(addresses: Mapping[str, Any], policy: Any) -> None:
        """Fail unless the policy's digest matches its public projection.

        Binds the policy bytes this eval validated to the digest Broker
        published, so a policy file edited underneath the projection is
        refused rather than trusted.
        """
        canonical = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        if addresses.get("policy_digest") != hashlib.sha256(canonical).hexdigest():
            raise EvalError(
                "eval wallet policy digest does not match its public projection"
            )

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
