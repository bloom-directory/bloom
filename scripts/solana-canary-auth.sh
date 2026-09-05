#!/usr/bin/env bash
# Write a Solana mainnet canary authorization file for the given binary.
#
# usage: scripts/solana-canary-auth.sh <out.json> <bloom-binary> <chain> <wallet> \
#          <key_fingerprint_hex> <derivation_path> <source_address> <destination> \
#          <transfer_lamports> [max_fee_lamports=10000] [max_balance_lamports=transfer+fee+0] [ttl_seconds=3600]
#
# Then run the Machine with BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION=<out.json>.
# One file authorizes exactly one transaction; rerun for the next one.
set -euo pipefail

if [ $# -lt 9 ]; then
  sed -n '2,9p' "$0" >&2
  exit 2
fi

out=$1 bin=$2 chain=$3 wallet=$4 fp=$5 path=$6 src=$7 dst=$8 transfer=$9
fee=${10:-10000}
balance=${11:-$((transfer + fee))}
ttl=${12:-3600}

[ -x "$bin" ] || { echo "not an executable: $bin" >&2; exit 1; }
[ -e "$out.spent" ] && { echo "$out.spent exists: that authorization is already used" >&2; exit 1; }
[ "$src" != "$dst" ] || { echo "destination must differ from source" >&2; exit 1; }
case "$path" in "m/44'/501'/"*"'/0'") ;; *) echo "derivation_path must be m/44'/501'/<account>'/0'" >&2; exit 1;; esac
[ $((transfer + fee)) -le "$balance" ] || { echo "transfer + fee exceeds max_balance" >&2; exit 1; }

sha=$(sha256sum "$bin" | cut -d' ' -f1)
expires=$(( $(date +%s) * 1000 + ttl * 1000 ))

cat > "$out" <<EOF
{
  "schema": "bloom.solana-mainnet-canary/1",
  "artifact_sha256": "$sha",
  "chain": "$chain",
  "wallet": "$wallet",
  "key_fingerprint": "$fp",
  "derivation_path": "$path",
  "source_address": "$src",
  "destination": "$dst",
  "max_balance_lamports": $balance,
  "transfer_lamports": $transfer,
  "max_fee_lamports": $fee,
  "max_transactions": 1,
  "expires_ms": $expires
}
EOF
chmod 0600 "$out"
echo "wrote $out (artifact $sha, expires in ${ttl}s)"
echo "export BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION=$out"
