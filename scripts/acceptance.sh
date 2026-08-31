#!/usr/bin/env bash
# Current custody acceptance entrypoint.
#
# Wallet secrets live only in Signer. Registration, BIP-39 import, derived-key
# projection, staging, approval, and signing cross the real Machine/Broker/
# Signer boundaries exercised by the projection-fidelity suite.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec "${repo_root}/scripts/test-triad-projection-fidelity.sh" "$@"
