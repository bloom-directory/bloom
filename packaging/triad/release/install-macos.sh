#!/usr/bin/env bash
set -Eeuo pipefail

# Self-contained macOS installer. Keep this file readable and below 800 lines:
# it is intentionally suitable for `curl ... | sudo bash -s -- ...`.

die() { echo "$*" >&2; exit 65; }
usage() {
  cat >&2 <<'EOF'
usage:
  install-macos.sh install ROOT LOGIN_UID LOGIN_USER PAYLOAD_DIR
  install-macos.sh restore ROOT LOGIN_UID LOGIN_USER PAYLOAD_DIR
  install-macos.sh uninstall --retain-custody ROOT LOGIN_UID
  install-macos.sh uninstall ROOT LOGIN_UID delete-bloom-login-LOGIN_UID

Staged-root tests also supply BLOOM_MACOS_{BROKER,SIGNER}_{UID,GID},
BLOOM_MACOS_{MACHINE_BROKER,BROKER_SIGNER,REVOKE}_GID, and
BLOOM_MACOS_LOG_GID and BLOOM_RELEASE_DIGEST.
EOF
  exit 64
}

[[ $# -gt 0 ]] || usage
action="$1"; shift
live=false
lock=""
scratch=""
payload_scratch=""
created_users=""
created_groups=""
upgrade_transaction=""
restore_pending=false

cleanup() {
  rc=$?
  if ((rc != 0)) && $restore_pending; then
    rollback_failed_restore || echo "automatic macOS custody-restore cleanup remains incomplete" >&2
  fi
  [[ -z "$scratch" || ! -d "$scratch" ]] || rm -rf -- "$scratch"
  [[ -z "$payload_scratch" || ! -d "$payload_scratch" ]] || rm -rf -- "$payload_scratch"
  if ((rc != 0)) && $live; then
    rollback_failed=false
    for user in $created_users; do
      dscl . -delete "/Users/$user" 2>/dev/null || { echo "failed to remove incomplete service user $user" >&2; rollback_failed=true; }
    done
    for group in $created_groups; do
      dscl . -delete "/Groups/$group" 2>/dev/null || { echo "failed to remove incomplete service group $group" >&2; rollback_failed=true; }
    done
    dsmemberutil flushcache 2>/dev/null || true
    if $rollback_failed; then
      echo "incomplete service-account rollback will be recovered by the next installer run" >&2
    fi
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
    old="$(cat "$lock/pid" 2>/dev/null || true)"
    [[ ! "$old" =~ ^[1-9][0-9]*$ ]] || ! kill -0 "$old" 2>/dev/null || { echo "another Bloom installer is active" >&2; exit 75; }
    rm -f "$lock/pid"; rmdir "$lock" || exit 75; mkdir -m 0700 "$lock" || exit 75
  fi
  chown root:wheel "$lock"; printf '%s\n' "$$" >"$lock/pid"; chmod 0600 "$lock/pid"
}

snapshot_live_payload() {
  local source_payload="$payload"
  payload_scratch="$(mktemp -d /private/var/tmp/bloom-macos-payload.XXXXXX)"
  chmod 0700 "$payload_scratch"
  cp -R "$source_payload/." "$payload_scratch/"
  if find "$payload_scratch" \
    \( -type l -o \( ! -type f ! -type d \) \) -print -quit | grep -q .
  then
    die "payload contains a symlink or non-regular entry"
  fi
  chown -R root:wheel "$payload_scratch"
  payload="$payload_scratch"
}

prepare_verified_payload_for_execution() {
  $live || return 0
  xattr -dr com.apple.quarantine "$payload" || die "could not remove quarantine from the verified payload"
  for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
    if xattr -p com.apple.quarantine "$payload/bin/$binary" >/dev/null 2>&1; then
      die "verified payload binary remains quarantined: $binary"
    fi
  done
  "$payload/bin/bloom" --version >/dev/null || die "verified Bloom candidate cannot execute on this Mac"
}

field() {
  if command -v plutil >/dev/null 2>&1; then
    plutil -extract "$2" raw -o - "$1"
  else
    die "plutil is required for live macOS installation"
  fi
}
record_exists() { dscl . -read "/$1/$2" >/dev/null 2>&1; }
next_id() {
  dscl . -list "/$1" "$2" | awk '$NF~/^[0-9]+$/&&$NF>m{m=$NF} END{if(m>=2147483646)exit 1;print m+1}'
}
new_group() {
  record_exists Groups "$1" && die "refusing to adopt pre-existing group $1"
  dscl . -create "/Groups/$1"; created_groups="$created_groups $1"
  dscl . -create "/Groups/$1" PrimaryGroupID "$2"
  dscl . -create "/Groups/$1" RealName "Bloom isolated service group"
}
new_user() {
  record_exists Users "$1" && die "refusing to adopt pre-existing user $1"
  dscl . -create "/Users/$1"; created_users="$created_users $1"
  dscl . -create "/Users/$1" UniqueID "$2"
  dscl . -create "/Users/$1" PrimaryGroupID "$3"; dscl . -create "/Users/$1" RealName "Bloom isolated service"
  dscl . -create "/Users/$1" NFSHomeDirectory /var/empty; dscl . -create "/Users/$1" UserShell /usr/bin/false
  dscl . -create "/Users/$1" IsHidden 1; dscl . -create "/Users/$1" AuthenticationAuthority ';DisabledUser;'
}
join_group() { dseditgroup -o edit -a "$2" -t user "$1"; }

load_names() {
  broker_user="bloom-broker-$login_uid"; broker_group="$broker_user"
  signer_user="bloom-signer-$login_uid"; signer_group="$signer_user"
  machine_broker_group="bloom-machine-broker-$login_uid"
  broker_signer_group="bloom-broker-signer-$login_uid"; revoke_group="bloom-revoke-$login_uid"
  log_group="bloom-log-$login_uid"
}

adopt_existing_log_group() {
  local gid user_uuid real_name
  gid="$(dscl . -read "/Groups/$log_group" PrimaryGroupID | awk 'NR==1{print $2}')"
  user_uuid="$(dscl . -read "/Users/$login_user" GeneratedUID | awk 'NR==1{print $2}')"
  real_name="$(dscl . -read "/Groups/$log_group" RealName | awk 'NR==1{sub(/^RealName:[[:space:]]*/,"");if(length)print;next}{sub(/^[[:space:]]*/,"");print}')"
  [[ "$gid" =~ ^[1-9][0-9]*$ && "$user_uuid" =~ ^[0-9A-Fa-f-]+$ && \
    "$real_name" == "Bloom isolated service group" && \
    "$(dscl . -read "/Groups/$log_group" GroupMembers 2>/dev/null)" == "GroupMembers: $user_uuid" && \
    "$(dscl . -read "/Groups/$log_group" GroupMembership 2>/dev/null)" == "GroupMembership: $login_user" ]] ||
    die "pre-existing log group does not match the Bloom enrollment"
  [[ -z "$(dscl . -read "/Groups/$log_group" NestedGroups 2>/dev/null)" ]] ||
    die "pre-existing log group has nested members"
  dscl . -list /Groups PrimaryGroupID | awk -v gid="$gid" '$NF==gid{n++} END{exit n==1?0:1}' ||
    die "pre-existing log group GID is not unique"
  BLOOM_MACOS_LOG_GID="$gid"
}

persist_legacy_log_identity() {
  local legacy_state legacy_digest candidate_digest="$BLOOM_RELEASE_DIGEST"
  legacy_state="$(field "$enrollment" state)"; legacy_digest="$(field "$enrollment" release_digest)"
  BLOOM_RELEASE_DIGEST="$legacy_digest"; write_enrollment "$legacy_state"; BLOOM_RELEASE_DIGEST="$candidate_digest"
}

load_ids() {
  BLOOM_MACOS_BROKER_UID="$(field "$enrollment" broker_uid)"
  BLOOM_MACOS_SIGNER_UID="$(field "$enrollment" signer_uid)"
  BLOOM_MACOS_BROKER_GID="$(field "$enrollment" broker_gid)"
  BLOOM_MACOS_SIGNER_GID="$(field "$enrollment" signer_gid)"
  BLOOM_MACOS_MACHINE_BROKER_GID="$(field "$enrollment" machine_broker_gid)"
  BLOOM_MACOS_BROKER_SIGNER_GID="$(field "$enrollment" broker_signer_gid)"
  BLOOM_MACOS_REVOKE_GID="$(field "$enrollment" revoke_gid)"
  if recorded_log_gid="$(field "$enrollment" log_gid 2>/dev/null)"; then
    BLOOM_MACOS_LOG_GID="$recorded_log_gid"
    return
  fi
  if [[ "$action" == uninstall ]]; then BLOOM_MACOS_LOG_GID=""; return; fi
  if $live; then
    if record_exists Groups "$log_group"; then adopt_existing_log_group
    else
      BLOOM_MACOS_LOG_GID="$(next_id Groups PrimaryGroupID)"; new_group "$log_group" "$BLOOM_MACOS_LOG_GID"
      join_group "$log_group" "$login_user"; dsmemberutil flushcache
    fi
  else
    [[ "${BLOOM_MACOS_LOG_GID:-}" =~ ^[1-9][0-9]*$ ]] || die "BLOOM_MACOS_LOG_GID must be positive decimal"
  fi
  persist_legacy_log_identity
  created_groups="${created_groups/ $log_group/}"
}

allocate_accounts() {
  BLOOM_MACOS_BROKER_GID="$(next_id Groups PrimaryGroupID)"; new_group "$broker_group" "$BLOOM_MACOS_BROKER_GID"
  BLOOM_MACOS_SIGNER_GID="$(next_id Groups PrimaryGroupID)"; new_group "$signer_group" "$BLOOM_MACOS_SIGNER_GID"
  BLOOM_MACOS_MACHINE_BROKER_GID="$(next_id Groups PrimaryGroupID)"; new_group "$machine_broker_group" "$BLOOM_MACOS_MACHINE_BROKER_GID"
  BLOOM_MACOS_BROKER_SIGNER_GID="$(next_id Groups PrimaryGroupID)"; new_group "$broker_signer_group" "$BLOOM_MACOS_BROKER_SIGNER_GID"
  BLOOM_MACOS_REVOKE_GID="$(next_id Groups PrimaryGroupID)"; new_group "$revoke_group" "$BLOOM_MACOS_REVOKE_GID"
  BLOOM_MACOS_LOG_GID="$(next_id Groups PrimaryGroupID)"; new_group "$log_group" "$BLOOM_MACOS_LOG_GID"
  BLOOM_MACOS_BROKER_UID="$(next_id Users UniqueID)"; new_user "$broker_user" "$BLOOM_MACOS_BROKER_UID" "$BLOOM_MACOS_BROKER_GID"
  BLOOM_MACOS_SIGNER_UID="$(next_id Users UniqueID)"; new_user "$signer_user" "$BLOOM_MACOS_SIGNER_UID" "$BLOOM_MACOS_SIGNER_GID"
  for pair in "$machine_broker_group:$login_user" "$machine_broker_group:$broker_user" \
    "$broker_signer_group:$broker_user" "$broker_signer_group:$signer_user" \
    "$revoke_group:$login_user" "$revoke_group:$broker_user" "$revoke_group:$signer_user"; do
    join_group "${pair%%:*}" "${pair#*:}"
  done
  join_group "$log_group" "$login_user"
  dsmemberutil flushcache
}

recover_interrupted_fresh_accounts() {
  local found=false name value
  [[ ! -e "$enrollment" && ! -e "$config/edge-manifest.json" ]] || return 0
  for name in "$broker_user" "$signer_user"; do
    record_exists Users "$name" || continue
    found=true
    value="$(dscl . -read "/Users/$name" 2>/dev/null)"
    [[ "$value" == *$'RealName:\n Bloom isolated service\n'* && "$value" == *"NFSHomeDirectory: /var/empty"* && \
      "$value" == *"UserShell: /usr/bin/false"* && "$value" == *"dsAttrTypeNative:IsHidden: 1"* ]] ||
      die "pre-existing user $name is not a recoverable incomplete Bloom service account"
  done
  for name in "$broker_group" "$signer_group" "$machine_broker_group" "$broker_signer_group" "$revoke_group" "$log_group"; do
    record_exists Groups "$name" || continue
    found=true
    value="$(dscl . -read "/Groups/$name" 2>/dev/null)"
    [[ "$value" == *$'RealName:\n Bloom isolated service group\n'* ]] ||
      die "pre-existing group $name is not a recoverable incomplete Bloom service group"
  done
  $found || return 0
  echo "recovering an interrupted fresh Bloom account allocation" >&2
  for name in "$broker_user" "$signer_user"; do record_exists Users "$name" && dscl . -delete "/Users/$name"; done
  for name in "$broker_group" "$signer_group" "$machine_broker_group" "$broker_signer_group" "$revoke_group" "$log_group"; do
    record_exists Groups "$name" && dscl . -delete "/Groups/$name"
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
      test-unclaimed)
        [[ "${BLOOM_ALLOW_TEST_UNCLAIMED:-}" == true ]] ||
          die "test-unclaimed bundle requires explicit candidate opt in" ;;
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
    for n in BROKER_UID SIGNER_UID BROKER_GID SIGNER_GID MACHINE_BROKER_GID BROKER_SIGNER_GID REVOKE_GID LOG_GID; do
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
    -e "s|@BLOOM_BROKER_LOG_PATH@|$broker_log|g" -e "s|@BLOOM_SIGNER_LOG_PATH@|$signer_log|g" \
    -e "s|@BLOOM_BROKER_BOOTSTRAP_LOG@|$broker_bootstrap_log|g" -e "s|@BLOOM_SIGNER_BOOTSTRAP_LOG@|$signer_bootstrap_log|g" \
    -e "s|@BLOOM_LOG_READER_GID@|$BLOOM_MACOS_LOG_GID|g" \
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
  log_root="$variable/log/bloom/$login_uid"; broker_log="$log_root/broker.jsonl"; signer_log="$log_root/signer.jsonl"
  broker_bootstrap_log="$log_root/broker-bootstrap.log"; signer_bootstrap_log="$log_root/signer-bootstrap.log"
  broker_plist="$root_prefix/Library/LaunchDaemons/com.bloom.broker.$login_uid.plist"
  signer_plist="$root_prefix/Library/LaunchDaemons/com.bloom.signer.$login_uid.plist"
  containment_plist="$root_prefix/Library/LaunchDaemons/com.bloom.containment.plist"
  session_plist="$root_prefix/Library/LaunchAgents/com.bloom.session.plist"
  machine_plist="$root_prefix/Library/LaunchAgents/com.bloom.machine.plist"
  pf_anchor="$root_prefix/etc/pf.anchors/com.bloom.triad.$login_uid"
  newsyslog_config="$root_prefix/etc/newsyslog.d/bloom-$login_uid.conf"
}

current_release_digest() {
  local target
  if [[ ! -e "$release_base/current" && ! -L "$release_base/current" ]]; then return 0; fi
  [[ -L "$release_base/current" ]] || die "shared current release is not a symlink"
  target="$(readlink "$release_base/current")"
  [[ "$target" =~ ^releases/([0-9a-f]{64})$ && -d "$release_base/$target" ]] || die "shared current release is invalid"
  printf '%s\n' "${BASH_REMATCH[1]}"
}

has_active_enrollments() {
  local record
  for record in "$enrollments"/*.json; do
    [[ -f "$record" && ! -L "$record" ]] && return 0
  done
  return 1
}

validate_active_release_set() {
  local expected_digest="$1" record state digest
  for record in "$enrollments"/*.json; do
    [[ -e "$record" || -L "$record" ]] || continue
    [[ -f "$record" && ! -L "$record" ]] || die "installed enrollment record is unsafe"
    [[ "$(field "$record" schema)" == bloom.macos-enrollment.1 ]] || die "unsupported installed enrollment schema"
    state="$(field "$record" state)"
    [[ "$state" == active || "$state" == activating ]] || die "installed enrollment set is not active"
    digest="$(field "$record" release_digest)"
    [[ "$expected_digest" =~ ^[0-9a-f]{64}$ && "$digest" =~ ^[0-9a-f]{64}$ ]] ||
      die "installed enrollment set has an invalid release"
    [[ -n "$upgrade_transaction" || "$digest" == "$expected_digest" ]] ||
      die "installed enrollment set does not match the shared release"
  done
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

rollback_failed_restore() {
  if $live; then
    for label in "gui/$login_uid/com.bloom.machine" "system/com.bloom.broker.$login_uid" "system/com.bloom.signer.$login_uid" "gui/$login_uid/com.bloom.session"; do
      launchctl bootout "$label" 2>/dev/null || true
    done
    pf_reference remove || return 1
  fi
  rm -f "$broker_plist" "$signer_plist" "$pf_anchor" "$newsyslog_config" "$enrollments/$login_uid.json"
  rm -rf "$runtime" "$log_root"
  restore_pending=false
}

write_enrollment() {
  state="$1"; tmp="$enrollment.new.$$"
  if [[ -n "${BLOOM_MACOS_LOG_GID:-}" ]]; then
    log_fields=",\"log_group\":\"$log_group\",\"log_gid\":$BLOOM_MACOS_LOG_GID"
  else
    log_fields=""
  fi
  printf '{"schema":"bloom.macos-enrollment.1","state":"%s","login_uid":%s,"login_user":"%s","broker_user":"%s","broker_uid":%s,"broker_group":"%s","broker_gid":%s,"signer_user":"%s","signer_uid":%s,"signer_group":"%s","signer_gid":%s,"machine_broker_group":"%s","machine_broker_gid":%s,"broker_signer_group":"%s","broker_signer_gid":%s,"revoke_group":"%s","revoke_gid":%s%s,"release_digest":"%s"}\n' \
    "$state" "$login_uid" "$login_user" "$broker_user" "$BLOOM_MACOS_BROKER_UID" "$broker_group" "$BLOOM_MACOS_BROKER_GID" \
    "$signer_user" "$BLOOM_MACOS_SIGNER_UID" "$signer_group" "$BLOOM_MACOS_SIGNER_GID" "$machine_broker_group" \
    "$BLOOM_MACOS_MACHINE_BROKER_GID" "$broker_signer_group" "$BLOOM_MACOS_BROKER_SIGNER_GID" "$revoke_group" \
    "$BLOOM_MACOS_REVOKE_GID" "$log_fields" "$BLOOM_RELEASE_DIGEST" >"$tmp"
  chmod 0644 "$tmp"; $live && chown root:wheel "$tmp"; mv -f "$tmp" "$enrollment"
}

compat_field() {
  section="$1"; key="$2"
  awk -v section="[$section]" -v key="$key" '
    $0 == section { inside=1; next }
    inside && /^\[/ { exit }
    inside && $1 == key && $2 == "=" { gsub(/"/, "", $3); print $3; exit }
  ' "$payload/compatibility-v1.toml"
}

preflight_compatibility() {
  compatibility="$payload/compatibility-v1.toml"
  [[ -f "$compatibility" && ! -L "$compatibility" ]] || die "payload missing compatibility-v1.toml"
  grep -Fx 'schema = "bloom.triad-compatibility/1"' "$compatibility" >/dev/null || die "unsupported or malformed compatibility metadata"
  candidate_machine_state=""; candidate_broker_state=""; candidate_signer_state=""
  candidate_machine_floor=""; candidate_broker_floor=""; candidate_signer_floor=""
  for component in machine broker signer; do
    current="$(compat_field "state.$component" current)"
    floor="$(compat_field "state.$component" downgrade_floor)"
    [[ "$current" =~ ^[1-9][0-9]*$ && "$floor" =~ ^[1-9][0-9]*$ && "$floor" -le "$current" ]] || die "malformed $component state compatibility metadata"
    case "$component" in
      machine) candidate_machine_state="$current"; candidate_machine_floor="$floor" ;;
      broker) candidate_broker_state="$current"; candidate_broker_floor="$floor" ;;
      signer) candidate_signer_state="$current"; candidate_signer_floor="$floor" ;;
    esac
  done
  for dependency in broker_commit signer_commit service_runtime_commit petal_contract_commit; do
    revision="$(compat_field revisions "$dependency")"
    [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || die "compatibility metadata does not pin $dependency to a full commit"
  done
  state_record="$product/state-schema"
  if [[ -e "$state_record" ]]; then
    [[ -f "$state_record" && ! -L "$state_record" ]] || die "installed state-schema record is unsafe"
    while IFS='=' read -r component installed; do
      [[ "$component" =~ ^(machine|broker|signer)$ && "$installed" =~ ^[1-9][0-9]*$ ]] || die "installed state-schema record is malformed"
      case "$component" in
        machine) candidate="$candidate_machine_state"; floor="$candidate_machine_floor" ;;
        broker) candidate="$candidate_broker_state"; floor="$candidate_broker_floor" ;;
        signer) candidate="$candidate_signer_state"; floor="$candidate_signer_floor" ;;
      esac
      ((candidate >= installed)) || die "$component state-schema downgrade rejected before activation"
      ((installed >= floor)) || die "$component installed state is below the candidate migration floor"
    done < "$state_record"
  fi
}

write_state_schema() {
  tmp="$product/state-schema.new.$$"
  printf 'machine=%s\nbroker=%s\nsigner=%s\n' "$candidate_machine_state" "$candidate_broker_state" "$candidate_signer_state" >"$tmp"
  chmod 0644 "$tmp"; $live && chown root:wheel "$tmp"; mv -f "$tmp" "$product/state-schema"
}

install_release() {
  release="$release_base/releases/$BLOOM_RELEASE_DIGEST"; mkdir -p "$release_base/releases"
  if [[ -e "$release" ]]; then
    [[ -d "$release" && ! -L "$release" ]] || die "invalid digest-named release"
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      if [[ ! -f "$release/$binary" || -L "$release/$binary" ]] || ! cmp "$payload/bin/$binary" "$release/$binary" >/dev/null; then
        die "digest-named release does not match the verified payload"
      fi
    done
  else
    stage="$release_base/.release.$$.new"; mkdir "$stage"
    install -m 0755 "$payload/bin/bloom" "$stage/bloom"; install -m 0755 "$payload/bin/bloom-broker" "$stage/bloom-broker"
    install -m 0755 "$payload/bin/bloom-signer" "$stage/bloom-signer"; install -m 0755 "$payload/bin/bloom-signer-migrate" "$stage/bloom-signer-migrate"
    $live && chown -R root:wheel "$stage"; mv "$stage" "$release"
  fi
  machine_binary="$release_base/current/bloom"; broker_binary="$release_base/current/bloom-broker"; signer_binary="$release_base/current/bloom-signer"
}

switch_release() {
  local digest="$1"; [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || die "invalid release switch digest"
  [[ -d "$release_base/releases/$digest" && ! -L "$release_base/releases/$digest" ]] || die "release switch target is missing"
  ln -s "releases/$digest" "$release_base/current.new.$$"
  $live && chown -h root:wheel "$release_base/current.new.$$"
  # BSD mv otherwise follows a destination symlink to a directory and moves
  # the candidate link inside the old immutable release.
  if [[ "$(uname -s)" == Darwin ]]; then
    mv -fh "$release_base/current.new.$$" "$release_base/current"
  else
    # Staged-root conformance runs on Linux. GNU mv spells the same
    # no-dereference destination replacement guarantee as -T.
    mv -fT "$release_base/current.new.$$" "$release_base/current"
  fi
  machine_binary="$release_base/current/bloom"; broker_binary="$release_base/current/bloom-broker"; signer_binary="$release_base/current/bloom-signer"
}

install_config() {
  mkdir -p "$enrollments" "$broker_config" "$signer_config" "$machine_config" "$session_config" "$installer_config" \
    "$broker_state/audit-checkpoints" "$signer_state/audit-checkpoints" "$machine_state/audit-checkpoints" \
    "$runtime/machine-broker" "$runtime/broker-signer" "$runtime/revoke/broker" "$runtime/revoke/signer" \
    "$runtime/session" "$runtime/containment" "$runtime/status" "$variable/log/bloom" "$log_root"
  for directory in "$enrollments" "$broker_config" "$signer_config" "$machine_config" "$session_config" \
    "$installer_config" "$broker_state" "$signer_state" "$machine_state" "$broker_state/audit-checkpoints" \
    "$signer_state/audit-checkpoints" "$machine_state/audit-checkpoints" "$runtime" "$runtime/machine-broker" \
    "$runtime/broker-signer" "$runtime/revoke" "$runtime/revoke/broker" "$runtime/revoke/signer" "$runtime/session" \
    "$runtime/containment" "$runtime/status" "$variable/log/bloom" "$log_root"; do
    [[ -d "$directory" && ! -L "$directory" ]] || die "security directory is missing or substituted: $directory"
  done
  chmod 0711 "$config" "$runtime" "$runtime/revoke"
  chmod 0700 "$broker_config" "$signer_config" "$machine_config" "$session_config" "$installer_config" \
    "$broker_state" "$signer_state" "$machine_state" "$broker_state/audit-checkpoints" \
    "$signer_state/audit-checkpoints" "$machine_state/audit-checkpoints"
  chmod 0710 "$runtime/machine-broker" "$runtime/broker-signer" "$runtime/revoke/broker" \
    "$runtime/revoke/signer" "$runtime/session"
  chmod 0755 "$runtime/containment"; chmod 0750 "$runtime/status"
  # Service principals traverse to their owner-writable file; only the log
  # group can read it. No principal can replace entries in this root directory.
  chmod 0711 "$variable/log/bloom" "$log_root"
  for service_log in "$broker_log" "$signer_log" "$broker_bootstrap_log" "$signer_bootstrap_log"; do
    if [[ ! -e "$service_log" ]]; then install -m 0640 /dev/null "$service_log"; fi
    [[ -f "$service_log" && ! -L "$service_log" ]] || die "service log is missing or substituted: $service_log"
    chmod 0640 "$service_log"
  done
  if [[ ! -f "$config/edge-manifest.json" ]]; then
    if $live; then
      scratch="$(mktemp -d "$product/.material.XXXXXX")"; templates="$scratch/templates"; material="$scratch/material"
      mkdir -m 0700 "$templates" "$material"; cp "$payload/installer/macos/config/"* "$templates/"
      "$machine_binary" init triad-render-macos-enrollment "$templates" "$material" "$login_uid" \
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
    [[ -f "$broker_config/identity.json" && -f "$signer_config/identity.json" ]] || die "installed custody metadata is incomplete"
  fi
}

validate_installed_security_inputs() {
  local edge_manifest="$config/edge-manifest.json"
  [[ -e "$edge_manifest" || -L "$edge_manifest" ]] || return 0
  [[ -f "$edge_manifest" && ! -L "$edge_manifest" ]] ||
    die "installed edge manifest is missing or substituted"
  if $live; then
    [[ "$(stat -f '%u:%Lp:%l' "$edge_manifest")" == 0:644:1 ]] ||
      die "installed edge manifest has unsafe owner, mode, or link count"
  fi
}

install_assets() {
  base="$payload/installer/macos"
  render "$base/launchdaemons/com.bloom.broker.plist.in" "$broker_plist" 0644
  render "$base/launchdaemons/com.bloom.signer.plist.in" "$signer_plist" 0644
  render "$base/launchdaemons/com.bloom.containment.plist.in" "$containment_plist" 0644
  render "$base/launchagents/com.bloom.session.plist.in" "$session_plist" 0644
  render "$base/launchagents/com.bloom.machine.plist.in" "$machine_plist" 0644
  render "$base/pf/com.bloom.login.conf.in" "$pf_anchor" 0600
  mkdir -p "$(dirname "$newsyslog_config")"
  newsyslog_tmp="$newsyslog_config.new.$$"
  printf '%s %s:%s 640 5 1024 * BN\n%s %s:%s 640 5 1024 * BN\n%s %s:%s 640 2 128 * BN\n%s %s:%s 640 2 128 * BN\n' \
    "$broker_log" "$broker_user" "$log_group" "$signer_log" "$signer_user" "$log_group" \
    "$broker_bootstrap_log" "$broker_user" "$log_group" "$signer_bootstrap_log" "$signer_user" "$log_group" >"$newsyslog_tmp"
  chmod 0644 "$newsyslog_tmp"; mv -f "$newsyslog_tmp" "$newsyslog_config"
}

secure_ownership() {
  chown -R root:wheel "$release_base"
  chown root:wheel "$product" "$enrollments" "$config" "$broker_plist" "$signer_plist" "$containment_plist" "$session_plist" "$machine_plist" "$pf_anchor" "$newsyslog_config"
  chown -R "$broker_user:$broker_group" "$broker_config" "$broker_state"
  chown -R "$signer_user:$signer_group" "$signer_config" "$signer_state"
  chown -R "$login_user:$machine_broker_group" "$machine_config" "$machine_state"
  chown -R "$login_user:$revoke_group" "$session_config" "$runtime/session"
  chown -R root:wheel "$installer_config"; chown root:wheel "$config/edge-manifest.json" "$config/"*.json
  chown root:wheel "$runtime" "$runtime/containment" "$runtime/revoke"
  chown "$broker_user:$machine_broker_group" "$runtime/machine-broker" "$runtime/status"
  chown "$signer_user:$broker_signer_group" "$runtime/broker-signer"
  chown "$broker_user:$revoke_group" "$runtime/revoke/broker"; chown "$signer_user:$revoke_group" "$runtime/revoke/signer"
  chown root:"$log_group" "$log_root"
  chown "$broker_user:$log_group" "$broker_log"; chown "$signer_user:$log_group" "$signer_log"
  chown "$broker_user:$log_group" "$broker_bootstrap_log"; chown "$signer_user:$log_group" "$signer_bootstrap_log"
}

reload_launchd_job() {
  local domain="$1" label="$2" plist="$3"
  launchctl bootout "$domain/$label" 2>/dev/null || true
  if ! launchctl bootstrap "$domain" "$plist" 2>/dev/null; then
    if ! launchctl print "$domain/$label" >/dev/null 2>&1; then
      echo "Bloom installed, but launchd deferred $label" >&2
      return 0
    fi
  fi
  launchctl kickstart -k "$domain/$label" 2>/dev/null ||
    echo "Bloom installed, but launchd deferred $label" >&2
}

reload_current_enrollment() {
  plutil -lint "$broker_plist" "$signer_plist" "$containment_plist" "$session_plist" "$machine_plist" >/dev/null; pfctl -nf "$pf_anchor"
  reload_launchd_job system com.bloom.containment "$containment_plist"
  "$machine_binary" serve triad-pf-monitor-once 2>/dev/null ||
    echo "Bloom installed, but containment readiness is deferred" >&2
  reload_launchd_job "gui/$login_uid" com.bloom.session "$session_plist"
  reload_launchd_job system "com.bloom.signer.$login_uid" "$signer_plist"
  reload_launchd_job system "com.bloom.broker.$login_uid" "$broker_plist"
  reload_launchd_job "gui/$login_uid" com.bloom.machine "$machine_plist"
}

stop_all_enrollments() {
  $live || return 0
  launchctl bootout system/com.bloom.containment 2>/dev/null || true
  for record in "$enrollments"/*.json; do
    [[ -f "$record" && ! -L "$record" ]] || continue
    uid="${record##*/}"; uid="${uid%.json}"; [[ "$uid" =~ ^[1-9][0-9]*$ ]] || return 65
    for label in "gui/$uid/com.bloom.machine" "gui/$uid/com.bloom.session" "system/com.bloom.broker.$uid" "system/com.bloom.signer.$uid"; do launchctl bootout "$label" 2>/dev/null || true; done
  done
}

rewrite_all_enrollments() {
  local digest="$1" state="$2" record
  # Provision every enrollment first. Ownership is a separate pass so
  # securing one enrollment cannot disturb an enrollment already repaired.
  for record in "$enrollments"/*.json; do
    [[ -f "$record" && ! -L "$record" ]] || continue
    login_uid="${record##*/}"; login_uid="${login_uid%.json}"; enrollment="$record"
    login_user="$(field "$record" login_user)"; load_names; paths; load_ids
    BLOOM_RELEASE_DIGEST="$digest"; write_enrollment "$state"
    if $live; then
      plutil -replace build_digest -string "$digest" "$broker_config/config.json"
      plutil -replace build_digest -string "$digest" "$signer_config/config.json"
    fi
    install_config
    install_assets
  done
  if $live; then
    for record in "$enrollments"/*.json; do
      [[ -f "$record" && ! -L "$record" ]] || continue
      login_uid="${record##*/}"; login_uid="${login_uid%.json}"; enrollment="$record"
      login_user="$(field "$record" login_user)"; load_names; paths; load_ids
      secure_ownership
    done
  fi
}

reload_installed_set() {
  local record uid; $live || return 0
  reload_launchd_job system com.bloom.containment "$containment_plist"
  "$release_base/current/bloom" serve triad-pf-monitor-once 2>/dev/null ||
    echo "Bloom installed, but containment readiness is deferred" >&2
  for record in "$enrollments"/*.json; do
    [[ -f "$record" && ! -L "$record" ]] || continue
    uid="${record##*/}"; uid="${uid%.json}"
    reload_launchd_job "gui/$uid" com.bloom.session "$root_prefix/Library/LaunchAgents/com.bloom.session.plist"
    reload_launchd_job system "com.bloom.signer.$uid" "$root_prefix/Library/LaunchDaemons/com.bloom.signer.$uid.plist"
    reload_launchd_job system "com.bloom.broker.$uid" "$root_prefix/Library/LaunchDaemons/com.bloom.broker.$uid.plist"
    reload_launchd_job "gui/$uid" com.bloom.machine "$root_prefix/Library/LaunchAgents/com.bloom.machine.plist"
  done
}

find_interrupted_upgrade() {
  local recorded_old recorded_new
  upgrade_transaction="$product/upgrade-transaction"
  [[ -e "$upgrade_transaction" ]] || { upgrade_transaction=""; return 0; }
  [[ -d "$upgrade_transaction" && ! -L "$upgrade_transaction" ]] || die "invalid interrupted Bloom upgrade"
  grep -Fx bloom.macos-upgrade-transaction.2 "$upgrade_transaction/schema" >/dev/null || die "invalid interrupted Bloom upgrade"
  recorded_old="$(<"$upgrade_transaction/old-digest")"
  recorded_new="$(<"$upgrade_transaction/new-digest")"
  [[ "$recorded_old" =~ ^[0-9a-f]{64}$ && "$recorded_new" =~ ^[0-9a-f]{64}$ ]] || die "invalid interrupted Bloom upgrade"
  echo "resuming interrupted Bloom macOS upgrade toward the requested release" >&2
}

upgrade_release() {
  local old="$1" new="$2"
  upgrade_transaction="$product/upgrade-transaction"
  if [[ ! -e "$upgrade_transaction" ]]; then
    mkdir -m 0700 "$upgrade_transaction"
  fi
  [[ -d "$upgrade_transaction" && ! -L "$upgrade_transaction" ]] || die "invalid interrupted Bloom upgrade"
  printf '%s\n' bloom.macos-upgrade-transaction.2 >"$upgrade_transaction/schema"
  printf '%s\n' "$old" >"$upgrade_transaction/old-digest"
  printf '%s\n' "$new" >"$upgrade_transaction/new-digest"
  chmod 0600 "$upgrade_transaction"/*; $live && chown -R root:wheel "$upgrade_transaction"; sync
  stop_all_enrollments
  rewrite_all_enrollments "$new" activating
  switch_release "$new"
  rewrite_all_enrollments "$new" active
  write_state_schema
  reload_installed_set
  rm -rf -- "$upgrade_transaction"; upgrade_transaction=""
}

case "$action" in
  install|restore)
    [[ $# -eq 4 ]] || usage; root_and_uid "$1" "$2"; login_user="$3"; payload="$(cd "$4" && pwd -P)"
    [[ "$login_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "unsafe LOGIN_USER" >&2; exit 64; }
    $live && { lock_installer; [[ "$(id -u "$login_user")" == "$login_uid" ]] || die "LOGIN_USER does not match LOGIN_UID"; launchctl print "gui/$login_uid" >/dev/null 2>&1 || die "LOGIN_USER has no active GUI domain"; snapshot_live_payload; }
    requested_uid="$login_uid"; requested_user="$login_user"; load_names; paths; verify_payload; preflight_compatibility; prepare_verified_payload_for_execution
    find_interrupted_upgrade
    login_uid="$requested_uid"; login_user="$requested_user"; load_names; paths
    shared_digest="$(current_release_digest)"
    validate_active_release_set "$shared_digest"
    had_active=false; has_active_enrollments && had_active=true
    if [[ "$action" == restore && "$had_active" == true && "$shared_digest" != "$BLOOM_RELEASE_DIGEST" ]]; then
      die "restore cannot change the shared release used by active enrollments"
    fi
    fresh=true
    restoring=false
    if [[ "$action" == restore ]]; then
      retained="$product/retained/$login_uid.json"
      [[ ! -e "$enrollment" && -f "$retained" && ! -L "$retained" ]] || die "retained custody record is missing or already active"
      [[ "$(field "$retained" schema)" == bloom.macos-enrollment.1 && "$(field "$retained" state)" == retained ]] || die "retained custody record is incompatible"
      [[ "$(field "$retained" login_user)" == "$login_user" ]] || die "retained custody login identity mismatch"
      [[ "$(field "$retained" release_digest)" == "$BLOOM_RELEASE_DIGEST" ]] || die "restore requires the exact signed retained release"
      mkdir -p "$enrollments"; cp -p "$retained" "$enrollment"; fresh=false; restoring=true; restore_pending=true; load_ids
    elif [[ -e "$enrollment" ]]; then
      [[ -f "$enrollment" && ! -L "$enrollment" ]] || die "invalid enrollment"
      [[ "$(field "$enrollment" schema)" == bloom.macos-enrollment.1 ]] || die "unsupported installed enrollment schema"
      fresh=false; load_ids
    fi
    $live && $fresh && recover_interrupted_fresh_accounts
    validate_installed_security_inputs
    if [[ "$fresh" == true && "$had_active" == true && "$shared_digest" != "$BLOOM_RELEASE_DIGEST" ]]; then
      die "new enrollment cannot change the shared release used by active enrollments"
    fi
    $live && $fresh && allocate_accounts
    install_release
    if [[ "$had_active" == true && "$shared_digest" != "$BLOOM_RELEASE_DIGEST" && "$restoring" == false ]]; then
      upgrade_release "$shared_digest" "$BLOOM_RELEASE_DIGEST"
      echo "Bloom macOS release upgraded atomically"
      exit 0
    fi
    if [[ -n "$upgrade_transaction" ]]; then
      upgrade_release "$shared_digest" "$BLOOM_RELEASE_DIGEST"
      echo "Bloom macOS release upgraded atomically"
      exit 0
    fi
    switch_release "$BLOOM_RELEASE_DIGEST"; install_config; write_enrollment activating; install_assets
    if $live; then secure_ownership; pf_reference add; write_enrollment active; reload_current_enrollment; created_users=""; created_groups=""; fi
    write_state_schema
    if $restoring; then rm -f "$retained"; restore_pending=false; echo "Bloom macOS retained custody restored"; else echo "Bloom macOS enrollment installed or repaired"; fi
    ;;
  uninstall)
    retain=false
    if [[ "${1:-}" == --retain-custody ]]; then retain=true; shift; [[ $# -eq 2 ]] || usage; else [[ $# -eq 3 ]] || usage; fi
    root_and_uid "$1" "$2"
    $retain || [[ "$3" == "delete-bloom-login-$login_uid" ]] || { echo "permanent purge confirmation mismatch" >&2; exit 64; }
    $live && lock_installer; load_names; paths; retained="$product/retained/$login_uid.json"
    if $retain && [[ -f "$retained" && ! -e "$enrollment" ]]; then echo "Bloom macOS custody is already retained"; exit 0; fi
    record="$enrollment"; [[ -f "$record" && ! -L "$record" ]] || { record="$retained"; $retain && die "enrollment missing"; }
    [[ -f "$record" && ! -L "$record" ]] || die "enrollment or retained custody record missing"
    enrollment="$record"; login_user="$(field "$record" login_user)"; BLOOM_RELEASE_DIGEST="$(field "$record" release_digest)"; load_ids
    if $live; then
      for label in "gui/$login_uid/com.bloom.machine" "system/com.bloom.broker.$login_uid" "system/com.bloom.signer.$login_uid" "gui/$login_uid/com.bloom.session"; do launchctl bootout "$label" 2>/dev/null || true; done
      pf_reference remove
    fi
    rm -f "$broker_plist" "$signer_plist" "$pf_anchor" "$newsyslog_config"
    if $retain; then
      mkdir -p "$product/retained"; enrollment="$retained"; write_enrollment retained
      rm -f "$enrollments/$login_uid.json"; rm -rf "$runtime" "$log_root"
      echo "Bloom macOS runtime removed; custody retained for restore"
    else
      rm -f "$enrollments/$login_uid.json" "$retained"; rm -rf "$config" "$variable/db/bloom/$login_uid" "$runtime" "$log_root"
    fi
    if $live && ! $retain; then
      for name in "$broker_user" "$signer_user"; do dscl . -delete "/Users/$name"; done
      for name in "$broker_group" "$signer_group" "$machine_broker_group" "$broker_signer_group" "$revoke_group"; do dscl . -delete "/Groups/$name"; done
      record_exists Groups "$log_group" && dscl . -delete "/Groups/$log_group"
      dsmemberutil flushcache
    fi
    if ! find "$enrollments" -type f -name '*.json' -maxdepth 1 2>/dev/null | grep . >/dev/null; then
      $live && launchctl bootout system/com.bloom.containment 2>/dev/null || true; rm -f "$containment_plist" "$session_plist" "$machine_plist"
      if ! find "$product/retained" -type f -name '*.json' -maxdepth 1 2>/dev/null | grep . >/dev/null; then rm -rf "$release_base"; fi
    fi
    $retain || echo "Bloom macOS enrollment permanently purged; custody is unrecoverable"
    ;;
  *) usage ;;
esac
