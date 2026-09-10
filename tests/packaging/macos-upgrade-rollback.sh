#!/usr/bin/env bash
set -Eeuo pipefail
workspace="$(cd "$(dirname "$0")/../.." && pwd -P)"
installer="$workspace/packaging/triad/release/install-macos.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
die() { echo "$*" >&2; exit 65; }
eval "$(sed -n '/^restore_macos_upgrade_state()/,/^}/p' "$installer")"
root_prefix="$work/root"
upgrade_transaction="$work/transaction"
mkdir -p "$root_prefix/private/etc/newsyslog.d" "$root_prefix/private/etc/pf.anchors" "$root_prefix/config" "$upgrade_transaction"
ln -s private/etc "$root_prefix/etc"
live=true
for etc_path in etc private/etc; do
  printf 'old rotation\n' >"$root_prefix/etc/newsyslog.d/bloom-501.conf"
  printf 'old PF\n' >"$root_prefix/etc/pf.anchors/com.bloom.triad.501"
  printf 'old config\n' >"$root_prefix/config/service.json"
  (cd "$root_prefix" && tar -cpf "$upgrade_transaction/rollback-state.tar" \
    "$etc_path/newsyslog.d/bloom-501.conf" "$etc_path/pf.anchors/com.bloom.triad.501" config)
  printf 'new rotation\n' >"$root_prefix/etc/newsyslog.d/bloom-501.conf"
  printf 'new PF\n' >"$root_prefix/etc/pf.anchors/com.bloom.triad.501"
  printf 'new config\n' >"$root_prefix/config/service.json"
  restore_macos_upgrade_state
  [[ "$(cat "$root_prefix/etc/newsyslog.d/bloom-501.conf")" == 'old rotation' ]]
  [[ "$(cat "$root_prefix/etc/pf.anchors/com.bloom.triad.501")" == 'old PF' ]]
  [[ "$(cat "$root_prefix/config/service.json")" == 'old config' ]]
  [[ -L "$root_prefix/etc" ]]
done
echo 'macOS rollback restores legacy and canonical etc archive paths'
