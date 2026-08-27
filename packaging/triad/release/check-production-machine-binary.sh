#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 MACHINE_BINARY" >&2
  exit 64
fi

binary="$1"
if [[ ! -f "$binary" || ! -x "$binary" ]]; then
  echo "production Machine binary is not an executable file: $binary" >&2
  exit 66
fi

while IFS= read -r marker; do
  if LC_ALL=C grep -aF "$marker" "$binary" >/dev/null; then
    echo "forbidden developer/canary marker in production Machine binary: $marker" >&2
    exit 1
  else
    status=$?
  fi
  if [[ "$status" -ne 1 ]]; then
    echo "failed to scan production Machine binary for marker: $marker" >&2
    exit "$status"
  fi
done <<'EOF'
BLOOM_TRIAD_DEVELOPER_ROOT
triad-dev-harness
unsafe-debug-signer
unsafe-debug-approver
BLOOM_MAINNET_CANARY_ARTIFACT
BLOOM_SOLANA_MAINNET_CANARY_AUTHORIZATION
NON-PRODUCTION-MAINNET-CANARY
mainnet-canary
EOF

echo "Production Machine binary contains no developer or canary capability"
