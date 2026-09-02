"""Command-line entry point for Bloom's reusable Harbor evaluation harness."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from pathlib import Path

from .core import EvalDefinition, EvalError, run_eval
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
    value.add_argument("agent", nargs="?", choices=("claude", "codex", "glm"))
    value.add_argument(
        "--preauthorization-only",
        action="store_true",
        help=(
            "verify installed ownership, delegated provenance, action-route signing "
            "metadata, and active lineage without inspecting wallet policy "
            "(hyperliquid-order-cancel); or validate the canary authorization from "
            "local files only (solana-transfer)"
        ),
    )
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    repo_root = Path(
        os.environ.get("BLOOM_EVAL_REPO_ROOT", Path(__file__).resolve().parents[3])
    )
    definition = DEFINITIONS[args.eval](repo_root)
    try:
        if args.preauthorization_only:
            if args.agent is not None:
                raise EvalError(
                    "--preauthorization-only does not accept an agent argument"
                )
            definition.preauthorization_preflight()
            print(f"Bloom Harbor preauthorization verified for {definition.name}")
        else:
            if args.agent is None:
                raise EvalError(
                    "an agent is required unless --preauthorization-only is set"
                )
            run_eval(definition, args.agent)
    except (EvalError, KeyboardInterrupt) as error:
        print(f"Bloom Harbor eval: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
