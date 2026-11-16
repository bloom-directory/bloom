"""Owner-approved transfers: one intent, one approval, one payment."""

from __future__ import annotations

import os
import secrets
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from .core import EvalDefinition, EvalError, EvalRunContext
from .disposable import DisposableTriad


class TransferEval(EvalDefinition):
    """A disposable Triad whose owner approves exactly one matching transfer."""

    coverage = "settlement"

    def __init__(self, repo: Path, environ: dict[str, str] | None = None) -> None:
        self.repo = repo
        self.env = dict(os.environ if environ is None else environ)
        self.triad = DisposableTriad(repo, self.env)
        self.stop = threading.Event()
        self.approver: threading.Thread | None = None
        self.approval_error: BaseException | None = None
        self.jobs = Path(
            self.env.get("BLOOM_EVAL_JOBS_DIR", str(repo / "evals/harbor/jobs"))
        )

    def preflight(self) -> None:
        self.triad.preflight()

    def pending(self) -> list[tuple[str, Any, Any]]:
        """Each pending entry with its intent and approval challenge, or None."""
        raise NotImplementedError

    def matches(self, intent: Any) -> bool:
        """Whether a pending intent is the one transfer the owner authorized."""
        raise NotImplementedError

    def _approve(self) -> None:
        approved: str | None = None
        deadline = time.monotonic() + 3600
        try:
            while not self.stop.wait(0.2):
                if time.monotonic() >= deadline:
                    raise EvalError("transfer approver timed out")
                entries = self.pending()
                if len(entries) > 1:
                    raise EvalError("more than one pending transfer")
                for name, intent, challenge in entries:
                    if approved is not None and name != approved:
                        raise EvalError("a second transfer was staged after approval")
                    if intent is None or challenge is None:
                        continue
                    if not self.matches(intent):
                        raise EvalError(
                            "pending transfer differs from the authorized contract"
                        )
                    if approved is None:
                        self.triad.driver.complete(challenge["ceremony_url"])
                        approved = name
        except Exception as error:  # noqa: BLE001 -- propagate worker errors to the owning trial
            self.approval_error = error

    def task(self, agent_name: str, instruction: str) -> tuple[str, Path]:
        """Copy the task directory for this trial and write its instruction."""
        self.jobs.mkdir(parents=True, exist_ok=True)
        trial = f"{self.name}-{agent_name}-{secrets.token_hex(8)}"
        task = self.jobs / trial
        shutil.copytree(self.repo / "evals/harbor/tasks" / self.name, task)
        shutil.copy2(self.repo / "evals/harbor/projection.py", task / "tests")
        (task / "instruction.md").write_text(instruction)
        return trial, task

    def context(
        self, trial: str, task: Path, sink: str, verifier_env: dict[str, str]
    ) -> EvalRunContext:
        """Mount Bloom read-only except for one account outbox; grade on the host."""
        mount = str(self.triad.mount)
        return EvalRunContext(
            self.name,
            task,
            trial,
            self.jobs,
            [
                {"type": "bind", "source": mount, "target": "/bloom", "read_only": True},
                {"type": "bind", "source": mount + sink, "target": "/bloom" + sink},
            ],
            {},
            self.triad.projection_env() | verifier_env,
            # The agent container keeps Docker's isolated network and never
            # reaches the loopback chain or NFS export.
            host_verifier_root=self.triad.mount,
        )

    def start_approver(self) -> None:
        self.approver = threading.Thread(target=self._approve, daemon=True)
        self.approver.start()

    def validate_result(self, result: Any) -> None:
        if self.approval_error is not None:
            raise EvalError(f"transfer approver failed: {self.approval_error}")
        super().validate_result(result)

    def cleanup(self) -> None:
        self.stop.set()
        hung = False
        if self.approver is not None:
            self.approver.join(timeout=60)
            hung = self.approver.is_alive()
        errors = []
        # Always stop the services; a hung approver preserves the root for inspection.
        try:
            self.triad.close(preserve=self.failed or hung)
        except EvalError as error:
            errors.append(str(error))
        if hung:
            errors.append("transfer approver did not stop; its Triad root is preserved")
        if self.approval_error is not None:
            errors.append(f"transfer approver failed: {self.approval_error}")
        if errors:
            raise EvalError("; ".join(errors))
