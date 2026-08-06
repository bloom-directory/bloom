#!/usr/bin/env bash
set -Eeuo pipefail

# Self-contained macOS installer. Keep this file readable and below 500 lines:
# it is intentionally suitable for `curl ... | sudo bash -s -- ...`.

die() { echo "$*" >&2; exit 65; }
usage() {
  cat >&2 <<'EOF'
usage:
  install-macos.sh install ROOT LOGIN_UID LOGIN_USER PAYLOAD_DIR
  install-macos.sh uninstall ROOT LOGIN_UID delete-bloom-login-LOGIN_UID

Staged-root tests also supply BLOOM_MACOS_{BROKER,SIGNER}_{UID,GID},
BLOOM_MACOS_{MACHINE_BROKER,BROKER_SIGNER,REVOKE}_GID, and
BLOOM_RELEASE_DIGEST.
EOF
  exit 64
}

[[ $# -gt 0 ]] || usage
action="$1"; shift
live=false
lock=""
scratch=""
created_users=""
created_groups=""

cleanup() {
  rc=$?
  [[ -z "$scratch" || ! -d "$scratch" ]] || rm -rf -- "$scratch"
  if ((rc != 0)) && $live; then
    for user in $created_users; do dscl . -delete "/Users/$user" 2>/dev/null || true; done
    for group in $created_groups; do dscl . -delete "/Groups/$group" 2>/dev/null || true; done
    dsmemberutil flushcache 2>/dev/null || true
  fi
  if [[ -n "$lock" && -d "$lock" ]]; then rm -f "$lock/pid"; rmdir "$lock" 2>/dev/null || true; fi
  ((rc == 0)) || echo "macOS installer failed (status $rc)" >&2
  exit "$rc"
}
trap cleanup EXIT

root_and_uid() {
  [[ -d "$1" ]] || die "installer root is not a directory"
  [[ "$2" =~ ^[1-9][0-9]*$ ]] || { echo "LOGIN_UID must be positive decimal" >&2; exit 64; }
  root="$(cd "$1" && pwd -P)"; root_prefix="${root%/}"; login_uid="$2"
  [[ "$root" != / ]] || live=true
  if $live; then
    [[ "$EUID" -eq 0 && "$(uname -s)" == Darwin ]] || die "live installation requires root on macOS"
  fi
}

lock_installer() {
  lock=/private/var/run/bloom-triad-installer.lock
  if ! mkdir -m 0700 "$lock" 2>/dev/null; then
    [[ -d "$lock" && ! -L "$lock" && "$(stat -f '%u:%Lp' "$lock")" == 0:700 ]] || die "unsafe installer lock"
    old="$(<"$lock/pid" 2>/dev/null || true)"
    [[ ! "$old" =~ ^[1-9][0-9]*$ ]] || ! kill -0 "$old" 2>/dev/null || { echo "another Bloom installer is active" >&2; exit 75; }
    rm -f "$lock/pid"; rmdir "$lock" || exit 75; mkdir -m 0700 "$lock" || exit 75
  fi
  chown root:wheel "$lock"; printf '%s\n' "$$" >"$lock/pid"; chmod 0600 "$lock/pid"
}

field() { plutil -extract "$2" raw -o - "$1"; }
record_exists() { dscl . -read "/$1/$2" >/dev/null 2>&1; }
next_id() {
  dscl . -list "/$1" "$2" | awk '$NF~/^[0-9]+$/&&$NF>m{m=$NF} END{if(m>=2147483646)exit 1;print m+1}'
}
new_group() {
  record_exists Groups "$1" && die "refusing to adopt pre-existing group $1"
  dscl . -create "/Groups/$1"; dscl . -create "/Groups/$1" PrimaryGroupID "$2"
  dscl . -create "/Groups/$1" RealName "Bloom isolated service group"; created_groups="$created_groups $1"
}
new_user() {
  record_exists Users "$1" && die "refusing to adopt pre-existing user $1"
  dscl . -create "/Users/$1"; dscl . -create "/Users/$1" UniqueID "$2"
  dscl . -create "/Users/$1" PrimaryGroupID "$3"; dscl . -create "/Users/$1" RealName "Bloom isolated service"
  dscl . -create "/Users/$1" NFSHomeDirectory /var/empty; dscl . -create "/Users/$1" UserShell /usr/bin/false
  dscl . -create "/Users/$1" IsHidden 1; dscl . -create "/Users/$1" AuthenticationAuthority ';DisabledUser;'
  created_users="$created_users $1"
}
join_group() { dseditgroup -o edit -a "$2" -t user "$1"; }

load_names() {
  broker_user="bloom-broker-$login_uid"; broker_group="$broker_user"
  signer_user="bloom-signer-$login_uid"; signer_group="$signer_user"
  machine_broker_group="bloom-machine-broker-$login_uid"
  broker_signer_group="bloom-broker-signer-$login_uid"; revoke_group="bloom-revoke-$login_uid"
}

load_ids() {
  BLOOM_MACOS_BROKER_UID="$(field "$enrollment" broker_uid)"
  BLOOM_MACOS_SIGNER_UID="$(field "$enrollment" signer_uid)"
  BLOOM_MACOS_BROKER_GID="$(field "$enrollment" broker_gid)"
  BLOOM_MACOS_SIGNER_GID="$(field "$enrollment" signer_gid)"
  BLOOM_MACOS_MACHINE_BROKER_GID="$(field "$enrollment" machine_broker_gid)"
  BLOOM_MACOS_BROKER_SIGNER_GID="$(field "$enrollment" broker_signer_gid)"
  BLOOM_MACOS_REVOKE_GID="$(field "$enrollment" revoke_gid)"
}

allocate_accounts() {
  BLOOM_MACOS_BROKER_GID="$(next_id Groups PrimaryGroupID)"; new_group "$broker_group" "$BLOOM_MACOS_BROKER_GID"
  BLOOM_MACOS_SIGNER_GID="$(next_id Groups PrimaryGroupID)"; new_group "$signer_group" "$BLOOM_MACOS_SIGNER_GID"
  BLOOM_MACOS_MACHINE_BROKER_GID="$(next_id Groups PrimaryGroupID)"; new_group "$machine_broker_group" "$BLOOM_MACOS_MACHINE_BROKER_GID"
  BLOOM_MACOS_BROKER_SIGNER_GID="$(next_id Groups PrimaryGroupID)"; new_group "$broker_signer_group" "$BLOOM_MACOS_BROKER_SIGNER_GID"
  BLOOM_MACOS_REVOKE_GID="$(next_id Groups PrimaryGroupID)"; new_group "$revoke_group" "$BLOOM_MACOS_REVOKE_GID"
  BLOOM_MACOS_BROKER_UID="$(next_id Users UniqueID)"; new_user "$broker_user" "$BLOOM_MACOS_BROKER_UID" "$BLOOM_MACOS_BROKER_GID"
  BLOOM_MACOS_SIGNER_UID="$(next_id Users UniqueID)"; new_user "$signer_user" "$BLOOM_MACOS_SIGNER_UID" "$BLOOM_MACOS_SIGNER_GID"
  for pair in "$machine_broker_group:$login_user" "$machine_broker_group:$broker_user" \
    "$broker_signer_group:$broker_user" "$broker_signer_group:$signer_user" \
    "$revoke_group:$login_user" "$revoke_group:$broker_user" "$revoke_group:$signer_user"; do
    join_group "${pair%%:*}" "${pair#*:}"
  done
  dsmemberutil flushcache
}

verify_payload() {
  for path in bin/bloom bin/bloom-broker bin/bloom-signer bin/bloom-signer-migrate PLATFORM_CLAIM; do [[ -f "$payload/$path" ]] || die "payload missing $path"; done
  claim="$(<"$payload/PLATFORM_CLAIM")"
  if $live; then
    case "$claim" in
      macos-unix-principals) ;;
      macos-unix-principals-w0)
        [[ "${BLOOM_RUN_MACOS_UNIX_W0:-}" == true ]] || die "W0 bundle requires disposable-host opt in" ;;
      *) die "live installation requires a macOS Unix-principal bundle" ;;
    esac
    for path in SHA256SUMS RELEASE_PUBLIC_KEY.pem RELEASE_SIGNATURE; do [[ -f "$payload/$path" && ! -L "$payload/$path" ]] || die "payload missing $path"; done
    pinned="${BLOOM_RELEASE_PUBLIC_KEY:-}"; [[ -f "$pinned" && ! -L "$pinned" ]] || die "BLOOM_RELEASE_PUBLIC_KEY must pin a local key"
    [[ "$(stat -f '%u:%Lp' "$pinned")" == 0:* ]] || die "pinned release key must be root owned"
    (( (8#$(stat -f '%Lp' "$pinned") & 022) == 0 )) || die "pinned release key is writable"
    cmp "$pinned" "$payload/RELEASE_PUBLIC_KEY.pem" >/dev/null || die "payload release key is not pinned"
    read -r kt kb extra <"$pinned"; [[ "$kt" == ssh-ed25519 && -z "${extra:-}" ]] || die "invalid release key"
    scratch="$(mktemp -d)"; printf 'bloom-release %s %s\n' "$kt" "$kb" >"$scratch/allowed"; chmod 0600 "$scratch/allowed"
    ssh-keygen -Y verify -f "$scratch/allowed" -I bloom-release -n bloom-release-payload-v1 \
      -s "$payload/RELEASE_SIGNATURE" <"$payload/SHA256SUMS" >/dev/null
    (cd "$payload" && shasum -a 256 -c SHA256SUMS >/dev/null)
    BLOOM_RELEASE_DIGEST="$(shasum -a 256 "$payload/SHA256SUMS" | awk '{print $1}')"
  else
    [[ "$claim" == test-unclaimed && "${BLOOM_ALLOW_TEST_UNCLAIMED:-}" == true ]] || die "staged install requires test-unclaimed"
    [[ "${BLOOM_RELEASE_DIGEST:-}" =~ ^[0-9a-f]{64}$ ]] || die "invalid staged release digest"
    for n in BROKER_UID SIGNER_UID BROKER_GID SIGNER_GID MACHINE_BROKER_GID BROKER_SIGNER_GID REVOKE_GID; do
      v="BLOOM_MACOS_$n"; [[ "${!v:-}" =~ ^[1-9][0-9]*$ ]] || die "$v must be positive decimal"
    done
  fi
}

render() {
  src="$1"; dst="$2"; mode="$3"; mkdir -p "$(dirname "$dst")"; tmp="$dst.new.$$"
  sed -e "s|@LOGIN_UID@|$login_uid|g" -e "s|@LOGIN_USER@|$login_user|g" \
    -e "s|@BLOOM_BROKER_USER@|$broker_user|g" -e "s|@BLOOM_BROKER_GROUP@|$broker_group|g" \
    -e "s|@BLOOM_SIGNER_USER@|$signer_user|g" -e "s|@BLOOM_SIGNER_GROUP@|$signer_group|g" \
    -e "s|@BLOOM_BROKER_UID@|$BLOOM_MACOS_BROKER_UID|g" -e "s|@BLOOM_SIGNER_UID@|$BLOOM_MACOS_SIGNER_UID|g" \
    -e "s|@MACHINE_BROKER_GID@|$BLOOM_MACOS_MACHINE_BROKER_GID|g" -e "s|@BROKER_SIGNER_GID@|$BLOOM_MACOS_BROKER_SIGNER_GID|g" \
    -e "s|@REVOKE_GID@|$BLOOM_MACOS_REVOKE_GID|g" -e "s|@SESSION_SOCKET_GID@|$BLOOM_MACOS_REVOKE_GID|g" \
    -e "s|@BLOOM_MACHINE_BINARY@|$machine_binary|g" -e "s|@BLOOM_BROKER_BINARY@|$broker_binary|g" \
    -e "s|@BLOOM_SIGNER_BINARY@|$signer_binary|g" -e "s|@BLOOM_BROKER_IDENTITY@|$broker_config/identity.json|g" \
    -e "s|@BLOOM_BROKER_CONFIG@|$broker_config/config.json|g" -e "s|@BLOOM_SIGNER_IDENTITY@|$signer_config/identity.json|g" \
    -e "s|@BLOOM_SIGNER_CONFIG@|$signer_config/config.json|g" -e "s|@BLOOM_EDGE_MANIFEST@|$config/edge-manifest.json|g" \
    -e "s|@BLOOM_AUTHORITY_EDGE_HISTORY@|$config/authority-edge-history.json|g" \
    -e "s|@BLOOM_BROKER_AUDIT_CHECKPOINT_DIR@|$broker_state/audit-checkpoints|g" \
    -e "s|@BLOOM_SIGNER_AUDIT_CHECKPOINT_DIR@|$signer_state/audit-checkpoints|g" \
    -e "s|@BLOOM_BROKER_STATE_DIR@|$broker_state|g" -e "s|@BLOOM_SIGNER_STATE_DIR@|$signer_state|g" \
    -e "s|@BLOOM_BROKER_SOCKET@|$runtime/machine-broker/broker.sock|g" \
    -e "s|@BLOOM_SIGNER_SOCKET@|$runtime/broker-signer/signer.sock|g" \
    -e "s|@BLOOM_BROKER_CONTROL_SOCKET@|$runtime/revoke/broker/control.sock|g" \
    -e "s|@BLOOM_SIGNER_CONTROL_SOCKET@|$runtime/revoke/signer/control.sock|g" \
    -e "s|@BLOOM_SESSION_SOCKET@|$runtime/session/session.sock|g" \
    -e "s|@BLOOM_BROKER_STARTUP_STATUS@|$runtime/status/broker-startup.json|g" \
    -e "s|@BLOOM_CONTAINMENT_STATUS@|$runtime/containment/status.json|g" \
    -e "s|@BLOOM_PROVENANCE_CATALOG@|$config/provenance-catalog.json|g" \
    -e "s|@BLOOM_BROKER_LOG@|$broker_state/broker.log|g" -e "s|@BLOOM_SIGNER_LOG@|$signer_state/signer.log|g" \
    "$src" >"$tmp"; chmod "$mode" "$tmp"; mv -f "$tmp" "$dst"
}

paths() {
  product="$root_prefix/Library/Application Support/BloomTriad"; enrollments="$product/enrollments"
  enrollment="$enrollments/$login_uid.json"; release_base="$root_prefix/usr/local/libexec/bloom"
  config="$product/config/$login_uid"; broker_config="$config/broker"; signer_config="$config/signer"
  machine_config="$config/machine"; session_config="$config/session"; installer_config="$config/installer"
  if $live; then variable=/private/var; else variable="$root_prefix/var"; fi
  broker_state="$variable/db/bloom/$login_uid/broker"; signer_state="$variable/db/bloom/$login_uid/signer"
  machine_state="$variable/db/bloom/$login_uid/machine"; runtime="$variable/run/bloom/$login_uid"
  broker_plist="$root_prefix/Library/LaunchDaemons/com.bloom.broker.$login_uid.plist"
  signer_plist="$root_prefix/Library/LaunchDaemons/com.bloom.signer.$login_uid.plist"
  containment_plist="$root_prefix/Library/LaunchDaemons/com.bloom.containment.plist"
  session_plist="$root_prefix/Library/LaunchAgents/com.bloom.session.plist"
  pf_anchor="$root_prefix/etc/pf.anchors/com.bloom.triad.$login_uid"
}

pf_reference() {
  op="$1"; begin="# BEGIN BLOOM TRIAD $login_uid"; end="# END BLOOM TRIAD $login_uid"
  tmp="$(mktemp /etc/pf.conf.bloom.XXXXXX)"
  awk -v b="$begin" -v e="$end" '$0==b{skip=1;next}$0==e{skip=0;next}!skip{print}' /etc/pf.conf >"$tmp"
  if [[ "$op" == add ]]; then printf '\n%s\nanchor "com.bloom.triad/%s"\nload anchor "com.bloom.triad/%s" from "%s"\n%s\n' \
    "$begin" "$login_uid" "$login_uid" "$pf_anchor" "$end" >>"$tmp"; fi
  pfctl -nf "$tmp"; chown root:wheel "$tmp"; chmod 0644 "$tmp"; mv "$tmp" /etc/pf.conf; pfctl -f /etc/pf.conf
  pfctl -s info 2>/dev/null | grep -F 'Status: Disabled' >/dev/null && pfctl -E >/dev/null || true
}

write_enrollment() {
  state="$1"; tmp="$enrollment.new.$$"
  printf '{"schema":"bloom.macos-enrollment.1","state":"%s","login_uid":%s,"login_user":"%s","broker_user":"%s","broker_uid":%s,"broker_group":"%s","broker_gid":%s,"signer_user":"%s","signer_uid":%s,"signer_group":"%s","signer_gid":%s,"machine_broker_group":"%s","machine_broker_gid":%s,"broker_signer_group":"%s","broker_signer_gid":%s,"revoke_group":"%s","revoke_gid":%s,"release_digest":"%s"}\n' \
    "$state" "$login_uid" "$login_user" "$broker_user" "$BLOOM_MACOS_BROKER_UID" "$broker_group" "$BLOOM_MACOS_BROKER_GID" \
    "$signer_user" "$BLOOM_MACOS_SIGNER_UID" "$signer_group" "$BLOOM_MACOS_SIGNER_GID" "$machine_broker_group" \
    "$BLOOM_MACOS_MACHINE_BROKER_GID" "$broker_signer_group" "$BLOOM_MACOS_BROKER_SIGNER_GID" "$revoke_group" \
    "$BLOOM_MACOS_REVOKE_GID" "$BLOOM_RELEASE_DIGEST" >"$tmp"
  chmod 0644 "$tmp"; $live && chown root:wheel "$tmp"; mv -f "$tmp" "$enrollment"
}

install_release() {
  release="$release_base/releases/$BLOOM_RELEASE_DIGEST"; mkdir -p "$release_base/releases"
  if [[ -e "$release" ]]; then
    [[ -d "$release" && ! -L "$release" ]] || die "invalid digest-named release"
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      [[ -f "$release/$binary" && ! -L "$release/$binary" ]] && cmp "$payload/bin/$binary" "$release/$binary" >/dev/null || \
        die "digest-named release does not match the verified payload"
    done
  else
    stage="$release_base/.release.$$.new"; mkdir "$stage"
    install -m 0755 "$payload/bin/bloom" "$stage/bloom"; install -m 0755 "$payload/bin/bloom-broker" "$stage/bloom-broker"
    install -m 0755 "$payload/bin/bloom-signer" "$stage/bloom-signer"; install -m 0755 "$payload/bin/bloom-signer-migrate" "$stage/bloom-signer-migrate"
    $live && chown -R root:wheel "$stage"; mv "$stage" "$release"
  fi
  old_current="$(readlink "$release_base/current" 2>/dev/null || true)"; ln -s "releases/$BLOOM_RELEASE_DIGEST" "$release_base/current.new.$$"
  $live && chown -h root:wheel "$release_base/current.new.$$"; mv -f "$release_base/current.new.$$" "$release_base/current"
  machine_binary="$release_base/current/bloom"; broker_binary="$release_base/current/bloom-broker"; signer_binary="$release_base/current/bloom-signer"
}

install_config() {
  mkdir -p "$enrollments" "$broker_config" "$signer_config" "$machine_config" "$session_config" "$installer_config" \
    "$broker_state/audit-checkpoints" "$signer_state/audit-checkpoints" "$machine_state/audit-checkpoints" \
    "$runtime/machine-broker" "$runtime/broker-signer" "$runtime/revoke/broker" "$runtime/revoke/signer" \
    "$runtime/session" "$runtime/containment" "$runtime/status"
  for directory in "$enrollments" "$broker_config" "$signer_config" "$machine_config" "$session_config" \
    "$installer_config" "$broker_state" "$signer_state" "$machine_state" "$broker_state/audit-checkpoints" \
    "$signer_state/audit-checkpoints" "$machine_state/audit-checkpoints" "$runtime" "$runtime/machine-broker" \
    "$runtime/broker-signer" "$runtime/revoke" "$runtime/revoke/broker" "$runtime/revoke/signer" "$runtime/session" \
    "$runtime/containment" "$runtime/status"; do
    [[ -d "$directory" && ! -L "$directory" ]] || die "security directory is missing or substituted: $directory"
  done
  chmod 0711 "$config" "$runtime" "$runtime/revoke"
  chmod 0700 "$broker_config" "$signer_config" "$machine_config" "$session_config" "$installer_config" \
    "$broker_state" "$signer_state" "$machine_state" "$broker_state/audit-checkpoints" \
    "$signer_state/audit-checkpoints" "$machine_state/audit-checkpoints"
  chmod 0710 "$runtime/machine-broker" "$runtime/broker-signer" "$runtime/revoke/broker" \
    "$runtime/revoke/signer" "$runtime/session"
  chmod 0755 "$runtime/containment"; chmod 0750 "$runtime/status"
  if [[ ! -f "$config/edge-manifest.json" ]]; then
    if $live; then
      scratch="$(mktemp -d "$product/.material.XXXXXX")"; templates="$scratch/templates"; material="$scratch/material"
      mkdir -m 0700 "$templates" "$material"; cp "$payload/installer/macos/config/"* "$templates/"
      "$machine_binary" --triad-render-macos-enrollment "$templates" "$material" "$login_uid" \
        "$BLOOM_MACOS_BROKER_UID" "$BLOOM_MACOS_SIGNER_UID" "$BLOOM_MACOS_REVOKE_GID" "$BLOOM_RELEASE_DIGEST"
      source_config="$material"
    else source_config="$payload/config"; fi
    render "$source_config/edge-manifest.json" "$config/edge-manifest.json" 0644
    render "$source_config/broker.json" "$broker_config/config.json" 0600
    render "$source_config/signer.json" "$signer_config/config.json" 0600
    for pair in "machine-identity.json:$machine_config/identity.json" "broker-identity.json:$broker_config/identity.json" \
      "signer-identity.json:$signer_config/identity.json" "revoke-identity.json:$machine_config/revoke-identity.json" \
      "session-identity.json:$session_config/identity.json" "installer-identity.json:$installer_config/identity.json" \
      "provenance-catalog.json:$config/provenance-catalog.json"; do install -m 0600 "$source_config/${pair%%:*}" "${pair#*:}"; done
    printf '{"schema":"bloom.machine-audit-trust.v1","predecessors":[]}\n' >"$config/machine-audit-history.json"
    printf '{"schema":"bloom.authority-edge-application-history.1","historical_keys":[],"handovers":[]}\n' >"$config/authority-edge-history.json"
    chmod 0644 "$config/"{machine-audit-history,authority-edge-history,provenance-catalog}.json
  else
    old_digest="$(field "$enrollment" release_digest)"
    [[ "$old_digest" == "$BLOOM_RELEASE_DIGEST" ]] || die "in-place upgrades were removed; uninstall explicitly before changing releases"
  fi
}

install_assets() {
  base="$payload/installer/macos"
  render "$base/launchdaemons/com.bloom.broker.plist.in" "$broker_plist" 0644
  render "$base/launchdaemons/com.bloom.signer.plist.in" "$signer_plist" 0644
  render "$base/launchdaemons/com.bloom.containment.plist.in" "$containment_plist" 0644
  render "$base/launchagents/com.bloom.session.plist.in" "$session_plist" 0644
  render "$base/pf/com.bloom.login.conf.in" "$pf_anchor" 0600
}

secure_ownership() {
  chown -R root:wheel "$release_base" "$product"; chown root:wheel "$broker_plist" "$signer_plist" "$containment_plist" "$session_plist" "$pf_anchor"
  chown -R "$broker_user:$broker_group" "$broker_config" "$broker_state"
  chown -R "$signer_user:$signer_group" "$signer_config" "$signer_state"
  chown -R "$login_user:$machine_broker_group" "$machine_config" "$machine_state"
  chown -R "$login_user:$revoke_group" "$session_config" "$runtime/session"
  chown -R root:wheel "$installer_config"; chown root:wheel "$config/edge-manifest.json" "$config/"*.json
  chown root:wheel "$runtime" "$runtime/containment" "$runtime/revoke"
  chown "$broker_user:$machine_broker_group" "$runtime/machine-broker" "$runtime/status"
  chown "$signer_user:$broker_signer_group" "$runtime/broker-signer"
  chown "$broker_user:$revoke_group" "$runtime/revoke/broker"; chown "$signer_user:$revoke_group" "$runtime/revoke/signer"
}

start_and_check() {
  plutil -lint "$broker_plist" "$signer_plist" "$containment_plist" "$session_plist" >/dev/null; pfctl -nf "$pf_anchor"
  launchctl bootout system/com.bloom.containment 2>/dev/null || true; launchctl bootstrap system "$containment_plist"
  "$machine_binary" --triad-pf-monitor-once
  for label in "gui/$login_uid/com.bloom.session" "system/com.bloom.broker.$login_uid" "system/com.bloom.signer.$login_uid"; do launchctl bootout "$label" 2>/dev/null || true; done
  launchctl bootstrap "gui/$login_uid" "$session_plist"; launchctl bootstrap system "$signer_plist"; launchctl bootstrap system "$broker_plist"
  health_output="$(mktemp "$scratch/health-check.XXXXXX")"
  for _ in {1..20}; do
    if sudo -n -u "$login_user" -- "$machine_binary" --triad-health-check "$BLOOM_RELEASE_DIGEST" >"$health_output" 2>&1; then return; fi
    sleep 1
  done
  cat "$health_output" >&2
  die "Bloom triad activation failed for login UID $login_uid"
}

case "$action" in
  install)
    [[ $# -eq 4 ]] || usage; root_and_uid "$1" "$2"; login_user="$3"; payload="$(cd "$4" && pwd -P)"
    [[ "$login_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "unsafe LOGIN_USER" >&2; exit 64; }
    $live && { lock_installer; [[ "$(id -u "$login_user")" == "$login_uid" ]] || die "LOGIN_USER does not match LOGIN_UID"; }
    load_names; paths; verify_payload
    fresh=true
    if [[ -e "$enrollment" ]]; then [[ -f "$enrollment" && ! -L "$enrollment" ]] || die "invalid enrollment"; fresh=false; load_ids; fi
    $live && $fresh && allocate_accounts
    install_release; install_config; write_enrollment activating; install_assets
    if $live; then secure_ownership; pf_reference add; start_and_check; write_enrollment active; created_users=""; created_groups=""; fi
    echo "Bloom macOS enrollment installed"
    ;;
  uninstall)
    [[ $# -eq 3 ]] || usage; root_and_uid "$1" "$2"; [[ "$3" == "delete-bloom-login-$login_uid" ]] || { echo "uninstall confirmation mismatch" >&2; exit 64; }
    $live && lock_installer; load_names; paths; [[ -f "$enrollment" && ! -L "$enrollment" ]] || die "enrollment missing"; login_user="$(field "$enrollment" login_user)"; load_ids
    if $live; then
      for label in "system/com.bloom.broker.$login_uid" "system/com.bloom.signer.$login_uid" "gui/$login_uid/com.bloom.session"; do launchctl bootout "$label" 2>/dev/null || true; done
      pf_reference remove
    fi
    rm -f "$broker_plist" "$signer_plist" "$pf_anchor" "$enrollment"; rm -rf "$config" "$variable/db/bloom/$login_uid" "$runtime"
    if $live; then
      for name in "$broker_user" "$signer_user"; do dscl . -delete "/Users/$name"; done
      for name in "$broker_group" "$signer_group" "$machine_broker_group" "$broker_signer_group" "$revoke_group"; do dscl . -delete "/Groups/$name"; done
      dsmemberutil flushcache
      if ! find "$enrollments" -type f -name '*.json' -maxdepth 1 | grep . >/dev/null; then
        launchctl bootout system/com.bloom.containment 2>/dev/null || true; rm -f "$containment_plist" "$session_plist"; rm -rf "$release_base"
      fi
    fi
    echo "Bloom macOS enrollment permanently removed"
    ;;
  *) usage ;;
esac
