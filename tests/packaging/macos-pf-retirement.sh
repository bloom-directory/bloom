#!/usr/bin/env bash
# Exercise the actual installer functions with PF mocked; never changes host PF.
set -Eeuo pipefail
workspace="$(cd "$(dirname "$0")/../.." && pwd -P)"
installer="$workspace/packaging/triad/release/install-macos.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export TMPDIR="$work"
die() { echo "$*" >&2; exit 65; }
eval "$(sed -n '/^cleanup_legacy_pf()/,/^}/p' "$installer")"
eval "$(sed -n '/^disable_legacy_network_guard()/,/^}/p' "$installer")"
root_prefix="$work/root"
mkdir -p "$root_prefix/etc/pf.anchors"
live=true
pfctl() {
  printf '%s\n' "$*" >>"$work/calls"
  case "$*" in
    '-s Anchors') printf '  com.apple\n  other-vendor\n'; [[ "${no_bloom_anchor:-false}" == true ]] || printf '  com.bloom.triad\n' ;;
    '-a com.bloom.triad -s Anchors') printf '  com.bloom.triad/501\n  com.bloom.triad/502\n  com.bloom.triad/504\n' ;;
    '-a com.bloom.triad/501 -F rules'|'-a com.bloom.triad/502 -F rules'|'-a com.bloom.triad/503 -F rules'|'-a com.bloom.triad/504 -F rules')
      [[ "${fail_flush:-false}" != true ]] ;;
    *) echo "unexpected global PF operation: $*" >&2; return 1 ;;
  esac
}
cat >"$work/foreign" <<'CONF'
# Preserve system and third-party settings exactly.
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
anchor "other-vendor"
CONF
seed() {
  cp "$work/foreign" "$root_prefix/etc/pf.conf"
  for uid in 501 502; do
    cat >>"$root_prefix/etc/pf.conf" <<CONF
# BEGIN BLOOM TRIAD $uid
anchor "com.bloom.triad/$uid"
load anchor "com.bloom.triad/$uid" from "/etc/pf.anchors/com.bloom.triad.$uid"
# END BLOOM TRIAD $uid
CONF
    printf 'old Bloom rule\n' >"$root_prefix/etc/pf.anchors/com.bloom.triad.$uid"
  done
  # Orphan on disk and orphan 504 in the loaded ruleset are both discovered.
  printf 'orphan\n' >"$root_prefix/etc/pf.anchors/com.bloom.triad.503"
  printf 'foreign\n' >"$root_prefix/etc/pf.anchors/other-vendor"
  : >"$work/calls"
}
seed
cleanup_legacy_pf
cmp "$work/foreign" "$root_prefix/etc/pf.conf"
for uid in 501 502 503 504; do
  [[ ! -e "$root_prefix/etc/pf.anchors/com.bloom.triad.$uid" ]]
  grep -Fx -- "-a com.bloom.triad/$uid -F rules" "$work/calls" >/dev/null
done
[[ "$(cat "$root_prefix/etc/pf.anchors/other-vendor")" == foreign ]]
cleanup_legacy_pf
cmp "$work/foreign" "$root_prefix/etc/pf.conf"

# Uninstalling one legacy login must not break other still-old enrollments.
seed
cleanup_legacy_pf 501
[[ ! -e "$root_prefix/etc/pf.anchors/com.bloom.triad.501" ]]
[[ -f "$root_prefix/etc/pf.anchors/com.bloom.triad.502" ]]
grep -Fx '# BEGIN BLOOM TRIAD 502' "$root_prefix/etc/pf.conf" >/dev/null
! grep -F -- '-a com.bloom.triad/502 -F' "$work/calls"

# A kernel flush failure keeps the persistent evidence for a retry.
seed
cp "$root_prefix/etc/pf.conf" "$work/before"
if ( fail_flush=true; cleanup_legacy_pf ); then exit 1; fi
cmp "$work/before" "$root_prefix/etc/pf.conf"
[[ -f "$root_prefix/etc/pf.anchors/com.bloom.triad.501" ]]
cleanup_legacy_pf

# Refuse malformed managed blocks and symlinks before ANY live mutation.
seed
printf '# BEGIN BLOOM TRIAD 505\nforeign configuration\n' >>"$root_prefix/etc/pf.conf"
cp "$root_prefix/etc/pf.conf" "$work/before"
if ( cleanup_legacy_pf ); then exit 1; fi
cmp "$work/before" "$root_prefix/etc/pf.conf"
[[ ! -s "$work/calls" ]]
rm "$root_prefix/etc/pf.conf"
ln -s "$work/foreign" "$root_prefix/etc/pf.conf"
if ( cleanup_legacy_pf ); then exit 1; fi
[[ ! -s "$work/calls" ]]
rm "$root_prefix/etc/pf.conf"
seed

# Staged installation must not invoke host PF, even with legacy files present.
live=false
cleanup_legacy_pf
[[ ! -s "$work/calls" ]]
cmp "$work/foreign" "$root_prefix/etc/pf.conf"

# Production JSON migration preserves all unrelated (including custody) fields.
# plutil mutation is a macOS-only production operation.
if [[ "$(uname -s)" == Darwin ]]; then
  live=true
  broker_config="$work/broker"; signer_config="$work/signer"
  mkdir "$broker_config" "$signer_config"
  for directory in "$broker_config" "$signer_config"; do
    printf '{"network_containment":{"maximum_age_ms":5000},"key":"test-only","other":{"n":7}}\n' >"$directory/config.json"
  done
  disable_legacy_network_guard
  disable_legacy_network_guard
  for directory in "$broker_config" "$signer_config"; do
    grep -Eq '"network_containment"[[:space:]]*:[[:space:]]*null' "$directory/config.json"
    [[ "$(plutil -extract key raw -o - "$directory/config.json")" == test-only ]]
    [[ "$(plutil -extract other.n raw -o - "$directory/config.json")" == 7 ]]
  done
fi
# Fresh host without a Bloom namespace performs no child query or mutation.
live=true
: >"$work/calls"
no_bloom_anchor=true
cleanup_legacy_pf
[[ "$(cat "$work/calls")" == '-s Anchors' ]]
# Failed activation owns only files created by this attempt. Legacy PF state
# must survive both rollback paths, including when no other enrollment remains.
for rollback in rollback_failed_fresh rollback_failed_restore; do
  (
    eval "$(sed -n "/^$rollback()/,/^}/p" "$installer")"
    root_prefix="$work/$rollback"
    mkdir -p "$root_prefix/etc/pf.anchors"
    seed
    cp "$root_prefix/etc/pf.conf" "$root_prefix/pf.conf.before"
    cp "$root_prefix/etc/pf.anchors/com.bloom.triad.501" "$root_prefix/anchor.before"
    live=true
    login_uid=501
    variable="$root_prefix/var"
    config="$root_prefix/config"
    runtime="$variable/run/bloom/501"
    log_root="$variable/log/bloom/501"
    enrollments="$root_prefix/enrollments"
    enrollment="$enrollments/501.json"
    pf_anchor="$root_prefix/etc/pf.anchors/com.bloom.triad.501"
    broker_plist="$root_prefix/broker.plist"
    signer_plist="$root_prefix/signer.plist"
    containment_plist="$root_prefix/containment.plist"
    session_plist="$root_prefix/session.plist"
    machine_plist="$root_prefix/machine.plist"
    newsyslog_config="$root_prefix/newsyslog.conf"
    cli_link="$root_prefix/bloom"
    restore_pending=true
    mkdir -p "$config" "$runtime" "$log_root" "$enrollments" "$variable/db/bloom/501"
    for file in "$broker_plist" "$signer_plist" "$containment_plist" \
      "$session_plist" "$machine_plist" "$newsyslog_config" "$enrollment" "$cli_link"; do
      printf 'attempt-owned\n' >"$file"
    done
    launchctl() { printf '%s\n' "$*" >>"$root_prefix/launchctl-calls"; }
    has_active_enrollments() { return 1; }
    remove_cli_link() { rm -f "$cli_link"; }
    "$rollback"
    cmp "$root_prefix/pf.conf.before" "$root_prefix/etc/pf.conf"
    cmp "$root_prefix/anchor.before" "$pf_anchor"
    [[ ! -s "$work/calls" ]]
    [[ ! -e "$enrollment" && ! -e "$broker_plist" && ! -e "$signer_plist" ]]
    [[ ! -e "$runtime" && ! -e "$log_root" && ! -e "$cli_link" ]]
    if [[ "$rollback" == rollback_failed_restore ]]; then
      [[ "$restore_pending" == false && -d "$config" ]]
    else
      [[ ! -e "$config" && ! -e "$variable/db/bloom/501" ]]
    fi
  )
done
echo 'macOS PF retirement and legacy migration passed'
