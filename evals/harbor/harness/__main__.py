"""One launcher for disposable Harbor trials."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from .clarification import PROMPTS, ClarificationEval
from .core import AGENTS, EvalError, EvalEvidence, run_eval
from .default_petals import PolymarketProposalEval
from .disposable import CEREMONY
from .solana_transfer import SolanaTransferEval


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Run one real Bloom Harbor trial")
    value.add_argument(
        "eval",
        choices=(
            "solana-transfer",
            "polymarket-limit-order-proposal",
            *(name + "-clarification" for name in PROMPTS),
        ),
    )
    value.add_argument("agent", choices=tuple(AGENTS))
    value.add_argument(
        "--smoke", action="store_true", help="exercise real services without an LLM"
    )
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    repo = Path(
        os.environ.get("BLOOM_EVAL_REPO_ROOT", Path(__file__).resolve().parents[3])
    )
    definitions = {
        "solana-transfer": SolanaTransferEval,
        "polymarket-limit-order-proposal": PolymarketProposalEval,
    }
    if args.eval.endswith("-clarification"):
        definition = ClarificationEval(repo, args.eval.removesuffix("-clarification"))
    else:
        definition = definitions[args.eval](repo)
    evidence = EvalEvidence()
    source_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    source_diff = subprocess.run(
        ["git", "diff", "--binary", "HEAD"], cwd=repo, capture_output=True, check=True
    ).stdout
    timings: dict[str, float] = {}
    started = time.monotonic()
    failure = None
    try:
        kwargs = {}
        if args.smoke:
            if not hasattr(definition, "smoke"):
                raise EvalError("this task has no deterministic smoke")

            async def smoke_runner(context, _agent):
                await asyncio.to_thread(definition.smoke)
                env = (
                    os.environ
                    | dict(context.verifier_env)
                    | {"BLOOM_EVAL_MOUNT_ROOT": str(definition.triad.mount)}
                )
                deadline = time.monotonic() + 90
                while True:
                    verifier = await asyncio.to_thread(
                        subprocess.run,
                        [
                            sys.executable,
                            str(context.task_dir / "tests/verify_result.py"),
                        ],
                        env=env,
                        timeout=180,
                        check=False,
                        capture_output=True,
                    )
                    if not verifier.returncode:
                        break
                    if time.monotonic() >= deadline:
                        print(verifier.stderr.decode(errors="replace"), file=sys.stderr)
                        raise EvalError("real-service smoke verifier failed")
                    await asyncio.sleep(1)
                trial = SimpleNamespace(
                    exception_info=None,
                    verifier_result=SimpleNamespace(rewards={"reward": 1}),
                    agent_result=None,
                    trial_uri="deterministic-smoke",
                )
                return SimpleNamespace(
                    stats=SimpleNamespace(n_errored_trials=0, n_cancelled_trials=0),
                    trial_results=[trial],
                )

            kwargs["harbor_runner"] = smoke_runner
        run_eval(
            definition, args.agent, evidence=evidence, phase_timings=timings, **kwargs
        )
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 -- every failed run needs an honest summary
        failure = f"{type(error).__name__}: {CEREMONY.sub('[ceremony]', str(error))}"
        print(f"Bloom Harbor eval: {failure}", file=sys.stderr)
    finally:
        timings["total_seconds"] = time.monotonic() - started
        summary = {
            "task": args.eval,
            "agent": args.agent,
            "model": AGENTS[args.agent].model,
            "run_kind": "deterministic-smoke" if args.smoke else "Harbor-agent-trial",
            "coverage": (
                "clarification"
                if args.eval.endswith("-clarification")
                else "proposal"
                if args.eval.endswith("-proposal")
                else "settlement"
            ),
            "passed": failure is None,
            "error": failure,
            "cleanup_succeeded": evidence.cleanup_succeeded,
            "cleanup_error": evidence.cleanup_error,
            "timings": timings,
            "retained_root": str(definition.triad.root)
            if failure is not None
            else None,
            "source_commit": source_commit,
            "source_diff_sha256": hashlib.sha256(source_diff).hexdigest()
            if source_diff
            else None,
            "lineage": getattr(definition, "lineage", None),
        }
        binaries = {}
        for role in ("MACHINE", "BROKER", "SIGNER", "DEBUG_DRIVER"):
            binary = os.environ.get(f"BLOOM_INTEGRATION_{role}_BIN")
            if binary and Path(binary).is_file():
                with Path(binary).open("rb") as stream:
                    binaries[role.lower()] = hashlib.file_digest(
                        stream, "sha256"
                    ).hexdigest()
        summary["binary_sha256"] = binaries
        if evidence.result is not None:
            trials = evidence.result.trial_results
            if trials:
                trial = trials[0]
                if trial.exception_info is not None:
                    summary["exception_type"] = trial.exception_info.exception_type
                verifier = trial.verifier_result
                summary["rewards"] = dict(verifier.rewards or {}) if verifier else {}
                agent = trial.agent_result
                if agent is not None:
                    summary["usage"] = {
                        name: getattr(agent, name, None)
                        for name in (
                            "n_input_tokens",
                            "n_output_tokens",
                            "n_cache_tokens",
                            "cost_usd",
                        )
                    }
                summary["trial_uri"] = str(trial.trial_uri)
        root = (
            Path(os.environ.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs")))
            / "summaries"
        )
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{args.eval}-{args.agent}-{secrets.token_hex(8)}.json"
        path.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"Summary: {path}")
    return int(failure is not None)


if __name__ == "__main__":
    raise SystemExit(main())
