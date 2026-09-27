"""Command-line entry point for Bloom's reusable Harbor evaluation harness."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

from .core import AGENTS, AgentFailure, AgentSpec, EvalDefinition, EvalError, run_eval
from .hyperliquid_order_cancel import HyperliquidOrderCancelEval
from .solana_transfer import SolanaTransferEval

# One registry. The CLI choices are derived from it so a new eval cannot be
# added to one and forgotten in the other.
DEFINITIONS: dict[str, Callable[[Path], EvalDefinition]] = {
    "hyperliquid-order-cancel": HyperliquidOrderCancelEval,
    "solana-transfer": SolanaTransferEval,
}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Run a live Bloom evaluation through Harbor"
    )
    value.add_argument(
        "eval",
        choices=tuple(DEFINITIONS),
        help="host-side evaluation definition",
    )
    value.add_argument("agent", nargs="?", choices=tuple(AGENTS))
    value.add_argument(
        "--preauthorization-only",
        action="store_true",
        help=(
            "verify installed ownership, delegated provenance, action-route signing "
            "metadata, and active lineage without inspecting wallet policy "
            "(hyperliquid-order-cancel); or run the read-only solana-transfer "
            "preflight: configuration, mount, wallet, driver, and chain identity"
        ),
    )
    value.add_argument(
        "--smoke-only",
        action="store_true",
        help="run the deterministic Solana lifecycle without an LLM or API key",
    )
    value.add_argument(
        "--trials",
        type=int,
        default=1,
        help="independent trials to run, one after another (default 1)",
    )
    return value


def run_trials(
    make: Callable[[], EvalDefinition], trials: int, run: Callable[[EvalDefinition], None]
) -> int:
    """Run independent trials and report each as PASS, FAIL, or INVALID.

    FAIL is the agent's outcome. INVALID means the harness, environment, or
    cleanup failed, so that trial says nothing about the agent and is left out
    of the pass rate.
    """
    counts = {"PASS": 0, "FAIL": 0, "INVALID": 0}
    for number in range(1, trials + 1):
        definition = make()
        detail = ""
        try:
            run(definition)
            verdict = "PASS"
        except AgentFailure as error:
            verdict, detail = "FAIL", str(error)
        except EvalError as error:
            verdict, detail = "INVALID", str(error)
        counts[verdict] += 1
        note = getattr(definition, "trial_note", None)
        if callable(note):
            try:
                text = note()
            except EvalError:
                text = ""
            if text:
                detail = f"{detail} [{text}]" if detail else f"[{text}]"
        print(
            f"trial {number}/{trials}: {verdict}" + (f": {detail}" if detail else ""),
            file=sys.stderr if verdict != "PASS" else sys.stdout,
        )
    judged = counts["PASS"] + counts["FAIL"]
    print(
        f"{definition.name}: passed {counts['PASS']} of {judged} judged trials"
        + (f"; {counts['INVALID']} invalid" if counts["INVALID"] else "")
    )
    if counts["INVALID"]:
        return 2
    return 0 if counts["FAIL"] == 0 else 1


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    repo_root = Path(
        os.environ.get("BLOOM_EVAL_REPO_ROOT", Path(__file__).resolve().parents[3])
    )

    def make() -> EvalDefinition:
        return DEFINITIONS[args.eval](repo_root)

    definition = make()
    try:
        if args.trials < 1:
            raise EvalError("--trials must be at least 1")
        if args.preauthorization_only and args.smoke_only:
            raise EvalError("choose only one of --preauthorization-only or --smoke-only")
        if args.preauthorization_only:
            if args.agent is not None:
                raise EvalError(
                    "--preauthorization-only does not accept an agent argument"
                )
            definition.preauthorization_preflight()
            print(f"Bloom Harbor preauthorization verified for {definition.name}")
        elif args.smoke_only:
            if args.agent is not None:
                raise EvalError("--smoke-only does not accept an agent argument")
            if not isinstance(definition, SolanaTransferEval):
                raise EvalError("--smoke-only is supported only for solana-transfer")

            def smoke(each: EvalDefinition) -> None:
                assert isinstance(each, SolanaTransferEval)
                run_eval(
                    each,
                    "smoke",
                    harbor_runner=each.run_smoke,
                    agent_spec=AgentSpec("smoke", "deterministic"),
                )

            return run_trials(make, args.trials, smoke)
        else:
            if args.agent is None:
                raise EvalError(
                    "an agent is required unless --preauthorization-only is set"
                )
            agent = args.agent
            return run_trials(make, args.trials, lambda each: run_eval(each, agent))
    except (EvalError, KeyboardInterrupt) as error:
        print(f"Bloom Harbor eval: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
