"""Command-line entry point for Bloom's reusable Harbor evaluation harness."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .core import EvalError, run_eval
from .hyperliquid_order_cancel import HyperliquidOrderCancelEval


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Run a live Bloom evaluation through Harbor"
    )
    value.add_argument(
        "eval",
        choices=("hyperliquid-order-cancel",),
        help="host-side evaluation definition",
    )
    value.add_argument("agent", choices=("claude", "codex"))
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    repo_root = Path(
        os.environ.get("BLOOM_EVAL_REPO_ROOT", Path(__file__).resolve().parents[3])
    )
    definitions = {
        "hyperliquid-order-cancel": lambda: HyperliquidOrderCancelEval(repo_root)
    }
    try:
        run_eval(definitions[args.eval](), args.agent)
    except (EvalError, KeyboardInterrupt) as error:
        print(f"Bloom Harbor eval: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
