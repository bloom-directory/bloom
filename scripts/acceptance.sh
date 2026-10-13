#!/usr/bin/env bash
# Current custody acceptance entrypoint.
#
# Wallet secrets live only in Signer. Registration, BIP-39 import, derived-key
# projection, staging, approval, and signing cross the real Machine/Broker/
# Signer boundaries exercised by the projection-fidelity suite. The raw-scalar
# and BIP-39 transfer suites complete the cross-process custody picture the
# fidelity lane does not reach: imported-secret spending on a live EVM chain,
# derived AccountAllocate completion (projected only after its ceremony), and
# spending from the canonical derived EVM child.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
"${repo_root}/scripts/test-triad-projection-fidelity.sh" "$@"
"${repo_root}/scripts/test-raw-key-import-transfer.sh"
"${repo_root}/scripts/test-bip39-import-transfer.sh"
