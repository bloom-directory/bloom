"""Generic lifecycle and Harbor API integration for live Bloom evaluations."""

from __future__ import annotations

import asyncio
import fcntl
import os
import signal
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
) -> None:
    """Execute one provisioned eval and guarantee outer cleanup."""
    agent = _agent_spec(agent_name)
    definition.lock_path.parent.mkdir(parents=True, exist_ok=True)

    with definition.lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise EvalError(
                f"another {definition.name} eval holds {definition.lock_path}"
            ) from error

        definition.preflight()
        context: EvalRunContext | None = None
        provision_started = False
        run_error: BaseException | None = None
        previous_term_handler = signal.getsignal(signal.SIGTERM)

        def terminate(_signum: int, _frame: object) -> None:
            raise KeyboardInterrupt("received SIGTERM")

        signal.signal(signal.SIGTERM, terminate)
        try:
            provision_started = True
            context = definition.provision(agent_name)
            result = asyncio.run(harbor_runner(context, agent))
            definition.validate_result(result)
        except BaseException as error:  # noqa: BLE001 -- cleanup must cover interrupts
            run_error = error
        finally:
            signal.signal(signal.SIGTERM, previous_term_handler)
            if provision_started:
                try:
                    definition.cleanup()
                except BaseException as cleanup_error:
                    if run_error is not None:
                        raise EvalError(
                            f"evaluation failed ({run_error}); cleanup also failed: "
                            f"{cleanup_error}"
                        ) from cleanup_error
                    raise

        if run_error is not None:
            raise run_error
