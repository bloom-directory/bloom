#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
installer="$root/packaging/triad/release/install-macos.sh"
# Exercise the actual installer guard without running installation or cleanup.
guard="$(awk '/^require_native_macos_mount\(\)/,/^}/' "$installer")"
[[ -n "$guard" ]]
eval "$guard"
die() { echo "$*" >&2; exit 65; }

for version in 26 26.0 26.1.9 27.0; do
  require_native_macos_mount "$version"
done

for version in 15.7.9 25.99 '' malformed 26invalid; do
  if diagnostic="$(require_native_macos_mount "$version" 2>&1)"; then
    echo "unsupported version accepted: '$version'" >&2
    exit 1
  else
    status=$?
  fi
  [[ "$status" == 65 ]]
  [[ "$diagnostic" == *'macOS 26 or later for NFSv4.1'* ]]
  [[ "$diagnostic" == *"found '$version'"* ]]
  [[ "$diagnostic" == *'unmounted CLI'* ]]
done

echo 'macOS native mount preflight passed'
