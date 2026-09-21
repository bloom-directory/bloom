"""Task contract for the Safe native-transfer evaluation on an EVM fork.

This module holds the constants the task directory and its verifier are bound
to, so a drift between `task.toml`, `instruction.md` and the grading code fails
the static checks rather than a live run.

It deliberately does not yet define an :class:`~harness.core.EvalDefinition`.
Provisioning a trial means standing up a forked chain, deploying a disposable
Safe through the canonical factory, installing the Safe Petal into a running
Machine and writing an owner policy that permits exactly one exact signature and
one outbox destination. Those steps depend on the Safe review path landing
(bloom#224, bloom-broker#37, bloom-petal-safe#2); writing them against unlanded
route shapes would encode guesses. The task contract below is stable, and the
verifier grades from chain evidence that does not change with those PRs.
"""

from __future__ import annotations

EVAL_IMAGE = (
    "ghcr.io/bloom-directory/bloom-eval-agent-base@"
    "sha256:20988c7f8a6751c25e0115c2136710a885bef69d245e077d2ae3b2cc2c0837fd"
)

TASK_NAME = "bloom/safe-transfer-fork"
REPORT_SCHEMA = "bloom.eval.safe_transfer_fork.v1"
AGENT_TIMEOUT_SECONDS = 1800.0

#: `ExecutionSuccess(bytes32 txHash, uint256 payment)`, emitted by the Safe
#: itself on a successful `execTransaction`. Its unindexed first word is the
#: Safe transaction hash, which is what ties an outer receipt to the exact
#: owner authorization rather than to "some call the Safe made".
EXECUTION_SUCCESS_TOPIC = (
    "0x442e715f626346e8c54381002da614f62bee8d27386535b2521ec8540898556e"
)
#: `ExecutionFailure(bytes32,uint256)`. A Safe whose inner call reverts still
#: produces a successful outer receipt, so grading has to reject this topic
#: explicitly instead of trusting the receipt status alone.
EXECUTION_FAILURE_TOPIC = (
    "0x23428b18acfb3ea64b08dc0c1d296ea9c09702c09083ca5272e64d115b687d23"
)
#: `execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)`
EXEC_TRANSACTION_SELECTOR = "0x6a761202"

#: Environment the harness supplies to both the agent and the verifier. The
#: verifier reads the chain through `BLOOM_EVAL_EVM_RPC_URL` directly, outside
#: the agent's report boundary.
REQUIRED_ENV = (
    "BLOOM_EVAL_EVM_RPC_URL",
    "BLOOM_EVAL_CHAIN_ID",
    "BLOOM_EVAL_WALLET_ID",
    "BLOOM_EVAL_SAFE_ID",
    "BLOOM_EVAL_SAFE_ADDRESS",
    "BLOOM_EVAL_TRANSACTION_ID",
    "BLOOM_EVAL_RECIPIENT",
    "BLOOM_EVAL_VALUE_WEI",
)

#: Exactly the fields a passing report carries.
REPORT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "chain_id",
        "wallet_id",
        "safe_id",
        "safe_address",
        "transaction_id",
        "recipient",
        "value_wei",
        "safe_nonce",
        "safe_tx_hash",
        "execution_tx_hash",
        "phase",
    }
)
