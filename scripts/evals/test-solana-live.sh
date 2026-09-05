#!/usr/bin/env bash
# Exercise the Solana eval's chain-facing halves against a real cluster.
#
# `scripts/test-harbor-evals.sh` drives the verifier against a deterministic
# fake RPC, which proves the logic but not that the logic matches what a Solana
# node actually returns. This runs the same code against a live validator with
# real transfers, and exercises the host sweep, which cannot be tested at all
# without a chain.
#
# It never touches mainnet: it refuses any endpoint that is not local, and the
# lamports it moves come from a local faucet.
#
# Usage:
#   solana-test-validator --ledger /tmp/bloom-eval-ledger --reset --quiet &
#   scripts/evals/test-solana-live.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
rpc="${SOLANA_RPC_URL:-http://127.0.0.1:8899}"
verifier="${repo_root}/evals/harbor/tasks/solana-transfer/tests/verify_result.py"
lamports=1003517

# This script funds accounts from a faucet and drains them again. Pointed at a
# real cluster it would do neither safely, so refuse anything but a local node.
case "$rpc" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) printf '%s\n' "refusing a non-local endpoint: $rpc" >&2; exit 2 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

rpc_call() {
  curl -s -m 20 -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$rpc"
}

if ! rpc_call getHealth 'null' | grep -q '"ok"'; then
  printf '%s\n' "no healthy validator at $rpc; start solana-test-validator first" >&2
  exit 1
fi

genesis=$(rpc_call getGenesisHash 'null' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
if [ "$genesis" = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d" ]; then
  printf '%s\n' 'that endpoint is Solana mainnet-beta; refusing' >&2
  exit 2
fi
printf '%s\n' "validator genesis $genesis (not mainnet-beta)"

solana-keygen new --no-bip39-passphrase --force -s -o "$tmp/src.json" >/dev/null
solana-keygen new --no-bip39-passphrase --force -s -o "$tmp/dst.json" >/dev/null
chmod 600 "$tmp/src.json" "$tmp/dst.json"
src=$(solana-keygen pubkey "$tmp/src.json")
dst=$(solana-keygen pubkey "$tmp/dst.json")

solana airdrop 2 "$src" --url "$rpc" >/dev/null
# The airdrop is confirmed well before it is finalized, and every balance this
# eval reads is a finalized one.
until [ "$(solana balance "$src" --url "$rpc" --commitment finalized)" != "0 SOL" ]; do
  sleep 2
done

solana transfer "$dst" 0.001003517 --from "$tmp/src.json" --keypair "$tmp/src.json" \
  --url "$rpc" --commitment finalized --allow-unfunded-recipient >/dev/null
printf '%s\n' "staged a real transfer of ${lamports} lamports to a fresh destination"

signature=$(rpc_call getSignaturesForAddress "[\"$dst\",{\"limit\":10}]" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"][0]["signature"])')
slot=$(rpc_call getTransaction \
  "[\"$signature\",{\"encoding\":\"jsonParsed\",\"maxSupportedTransactionVersion\":0,\"commitment\":\"finalized\"}]" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["slot"])')

export BLOOM_EVAL_SOLANA_RPC_URL="$rpc"
export BLOOM_EVAL_SOLANA_NETWORK="local"
export BLOOM_EVAL_SOLANA_CHAIN="solana-local"
export BLOOM_EVAL_SOLANA_WALLET_ID="eval-solana"
export BLOOM_EVAL_SOLANA_SOURCE="$src"
export BLOOM_EVAL_SOLANA_DESTINATION="$dst"
export BLOOM_EVAL_SOLANA_LAMPORTS="$lamports"
export BLOOM_EVAL_SOLANA_MAX_FEE_LAMPORTS="10000"

python3 "$verifier"
printf '%s\n' 'the exact transfer was accepted against the live chain'

# The whole verification design rests on the destination being fresh, so paying
# it twice must invalidate a transfer that was valid a moment ago.
solana transfer "$dst" 0.0001 --from "$tmp/src.json" --keypair "$tmp/src.json" \
  --url "$rpc" --commitment finalized --allow-unfunded-recipient >/dev/null
if python3 "$verifier" >/dev/null 2>&1; then
  printf '%s\n' 'a destination paid twice still passed; the freshness binding is broken' >&2
  exit 1
fi
printf '%s\n' 'a destination paid twice is rejected'

# The sweep is what makes the eval repeatable, and it cannot be tested without a
# chain. Drain the destination and confirm from the chain, not the exit code.
PYTHONPATH="${repo_root}/evals/harbor" python3 - "$tmp" "$src" "$dst" "$rpc" <<'PY'
import pathlib, sys
from harness.solana_transfer import SolanaTransferEval

tmp, src, dst, rpc = sys.argv[1:5]
definition = SolanaTransferEval(
    pathlib.Path("."),
    {
        "BLOOM_EVAL_SOLANA_RPC_URL": rpc,
        "BLOOM_EVAL_SOLANA_SWEEP_KEYPAIR_FILE": f"{tmp}/dst.json",
    },
)
definition.source_address = src
definition.destination = dst

before = definition._balance(dst)
if before == 0:
    raise SystemExit("nothing to sweep; the fixture did not fund the destination")
if definition.sweep_destination() is None:
    raise SystemExit("sweep reported nothing to do over a funded destination")
if definition._balance(dst) != 0:
    raise SystemExit("sweep did not drain the destination")
if definition.sweep_destination() is not None:
    raise SystemExit("a second sweep over an empty destination did work")
print(f"swept {before} lamports back and confirmed the drain from the chain")
PY

printf '%s\n' 'Solana live-chain checks passed.'
