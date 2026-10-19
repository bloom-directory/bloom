#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
installer="$root/packaging/triad/release/install-macos.sh"
# Exercise the actual installer guard without running installation or cleanup.
guard="$(awk '/^require_supported_macos\(\)/,/^}/' "$installer")"
[[ -n "$guard" ]]
eval "$guard"
die() { echo "$*" >&2; exit 65; }

for version in 26 26.0 26.1.9 27.0; do
  require_supported_macos "$version"
done

for version in 15.7.9 25.99 '' malformed 26invalid; do
  if diagnostic="$(require_supported_macos "$version" 2>&1)"; then
    echo "unsupported version accepted: '$version'" >&2
    exit 1
  else
    status=$?
  fi
  [[ "$status" == 65 ]]
  [[ "$diagnostic" == *'Bloom requires macOS 26 or later'* ]]
  [[ "$diagnostic" == *"this Mac runs macOS '$version'"* ]]
  [[ "$diagnostic" == *'NFSv4.1'* ]]
  # Installed Bloom has no unmounted configuration to point users at.
  [[ "$diagnostic" != *'unmounted'* ]]
done

echo 'macOS native mount preflight passed'
