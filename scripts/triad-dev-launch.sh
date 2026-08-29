#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
broker_repo="$(cd "${repo_root}/../bloom-broker" && pwd -P)"
signer_repo="$(cd "${repo_root}/../bloom-signer" && pwd -P)"
developer_root=""
machine_home=""
mount_dir=""
machine_socket=""
log_dir=""
ready_file=""
services_only=0
install_authority_fixture="${BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE:-0}"
build_integration_petals="${BLOOM_TRIAD_DEV_BUILD_PETALS:-1}"
socket_timeout_seconds="${BLOOM_TRIAD_DEV_SOCKET_TIMEOUT_SECONDS:-30}"

die() { printf 'triad developer launcher: %s\n' "$*" >&2; exit 1; }
need_value() { [ "$#" -ge 2 ] || die "$1 requires a value"; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --developer-root) need_value "$@"; developer_root="$2"; shift 2 ;;
    --machine-home) need_value "$@"; machine_home="$2"; shift 2 ;;
    --mount) need_value "$@"; mount_dir="$2"; shift 2 ;;
    --machine-socket) need_value "$@"; machine_socket="$2"; shift 2 ;;
    --log-dir) need_value "$@"; log_dir="$2"; shift 2 ;;
    --ready-file) need_value "$@"; ready_file="$2"; shift 2 ;;
    --services-only) services_only=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done
required_paths=("$developer_root" "$machine_socket" "$log_dir" "$ready_file")
for value in "${required_paths[@]}"; do
  [ -n "$value" ] ||
    die "developer root, Machine socket, log dir, and ready file are required"
done
if [ "$services_only" -eq 1 ] && [ -n "$mount_dir" ]; then
  die "--services-only cannot be combined with --mount"
fi
case "$install_authority_fixture" in
  0|1) ;;
  *) die "BLOOM_TRIAD_DEV_AUTHORITY_FIXTURE must be 0 or 1" ;;
esac
case "$build_integration_petals" in
  0|1) ;;
  *) die "BLOOM_TRIAD_DEV_BUILD_PETALS must be 0 or 1" ;;
esac
case "$socket_timeout_seconds" in
  ''|*[!0-9]*|0) die "BLOOM_TRIAD_DEV_SOCKET_TIMEOUT_SECONDS must be a positive integer" ;;
esac
socket_wait_attempts=$((socket_timeout_seconds * 10))

[ "$(id -u)" -ne 0 ] || die "developer harness refuses root"
host_os="$(uname -s)"
case "$host_os" in
  Darwin|Linux) ;;
  *) die "developer harness requires Linux or macOS" ;;
esac

command -v jq >/dev/null 2>&1 || die "jq is required"
user_unit_dir=""
if [ "$host_os" = Linux ]; then
  command -v systemctl >/dev/null 2>&1 || die "Linux developer services require systemctl"
  user_runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  [ -d "$user_runtime_dir" ] && [ ! -L "$user_runtime_dir" ] ||
    die "Linux developer services require a real user runtime directory"
  [ "$(stat -c %u "$user_runtime_dir")" = "$(id -u)" ] ||
    die "Linux developer user runtime directory has the wrong owner"
  export XDG_RUNTIME_DIR="$user_runtime_dir"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${user_runtime_dir}/bus"
  systemctl --user show-environment >/dev/null 2>&1 ||
    die "Linux developer services require an active systemd user manager (enable linger for this dedicated developer user)"
  user_unit_dir="${user_runtime_dir}/systemd/user"
  mkdir -p "$user_unit_dir"
  [ -d "$user_unit_dir" ] && [ ! -L "$user_unit_dir" ] ||
    die "Linux developer systemd user unit directory is unsafe"
  [ "$(stat -c %u "$user_unit_dir")" = "$(id -u)" ] ||
    die "Linux developer systemd user unit directory has the wrong owner"
  chmod 0700 "$user_unit_dir"
fi
umask 077
mkdir -p "$developer_root"
chmod 0700 "$developer_root"
developer_root="$(cd "$developer_root" && pwd -P)"
if [ -z "$machine_home" ]; then
  machine_home="${developer_root}/state/machine"
fi
mkdir -p "$machine_home" "$log_dir" \
  "$(dirname "$machine_socket")" "$(dirname "$ready_file")"
machine_home="$(cd "$machine_home" && pwd -P)"
case "$machine_home" in
  "${developer_root}"/*) ;;
  *) die "Machine home must be inside the developer root so its persistent identity and audit journal share one lifetime" ;;
esac
if [ -d "${HOME}/.bloom" ]; then
  canonical_machine_home="$(cd "${HOME}/.bloom" && pwd -P)"
else
  canonical_machine_home="$(cd "$HOME" && pwd -P)/.bloom"
fi
[ "$machine_home" != "$canonical_machine_home" ] ||
  die "refusing to use canonical ~/.bloom as the mutable developer Machine home"
if [ -n "$mount_dir" ]; then
  mkdir -p "$mount_dir"
  mount_dir="$(cd "$mount_dir" && pwd -P)"
  if [ "$host_os" = Linux ]; then
    command -v sudo >/dev/null 2>&1 || die "Linux developer mounts require sudo"
    mount_nfs_bin="$(command -v mount.nfs4 || true)"
    umount_bin="$(command -v umount || true)"
    [ -n "$mount_nfs_bin" ] || die "Linux developer mounts require mount.nfs4"
    [ -n "$umount_bin" ] || die "Linux developer mounts require umount"
    mount_probe_opts="actimeo=0,vers=4.1,proto=tcp,port=1,rsize=65536,wsize=65536,timeo=10"
    sudo -n -l -- "$mount_nfs_bin" -o "$mount_probe_opts" \
      "127.0.0.1:/" "$mount_dir" >/dev/null 2>&1 ||
      die "Linux developer mount privilege is not installed for $mount_dir"
    sudo -n -l -- "$umount_bin" -l -f "$mount_dir" >/dev/null 2>&1 ||
      die "Linux developer unmount privilege is not installed for $mount_dir"
  fi
fi
log_dir="$(cd "$log_dir" && pwd -P)"
machine_socket="$(cd "$(dirname "$machine_socket")" && pwd -P)/$(basename "$machine_socket")"
ready_file="$(cd "$(dirname "$ready_file")" && pwd -P)/$(basename "$ready_file")"
if [ -e "$machine_socket" ] || [ -L "$machine_socket" ]; then
  die "machine socket path already exists: $machine_socket"
fi
if [ -e "$ready_file" ] || [ -L "$ready_file" ]; then
  die "ready file path already exists: $ready_file"
fi

bloom_bin="${BLOOM_INTEGRATION_MACHINE_BIN:-${repo_root}/target/debug/bloom}"
broker_bin="${BLOOM_INTEGRATION_BROKER_BIN:-${broker_repo}/target/debug/bloom-broker}"
signer_bin="${BLOOM_INTEGRATION_SIGNER_BIN:-${signer_repo}/target/debug/bloom-signer}"
config_dir="${developer_root}/config"
authority_edge_history="${config_dir}/authority-edge-history.json"
if [ "$host_os" = Linux ]; then
  for unit_value in \
    "$developer_root" "$config_dir" "$log_dir" "$authority_edge_history" \
    "$broker_bin" "$signer_bin"
  do
    case "$unit_value" in
      *[!A-Za-z0-9_./:@+-]*)
        die "Linux developer systemd unit paths may contain only ASCII letters, digits, and _./:@+-" ;;
    esac
  done
fi
if [ -z "${BLOOM_INTEGRATION_MACHINE_BIN:-}" ]; then
  (cd "$repo_root" && cargo build -p bloom --no-default-features --features mount,triad-dev-harness)
fi

if [ -z "${BLOOM_INTEGRATION_BROKER_BIN:-}" ]; then
  (cd "$broker_repo" && cargo build -p bloom-broker --features triad-dev-harness)
fi
if [ -z "${BLOOM_INTEGRATION_SIGNER_BIN:-}" ]; then
  (cd "$signer_repo" && cargo build -p bloom-signer --features triad-dev-harness)
fi
for binary in "$bloom_bin" "$broker_bin" "$signer_bin"; do
  [ -x "$binary" ] || die "required binary is not executable: $binary"
done
bloom_bin_dir="$(cd "$(dirname "$bloom_bin")" && pwd -P)"
bloom_bin="${bloom_bin_dir}/$(basename "$bloom_bin")"

release_digest="$(
  shasum -a 256 "$bloom_bin" "$broker_bin" "$signer_bin" |
    awk '{print $1}' | shasum -a 256 | awk '{print $1}'
)"
fixture_root="${repo_root}/tests/fixtures/triad-authority-petal"
fixture_hash=""
if [ "$install_authority_fixture" -eq 1 ]; then
  # The catalog must be signed before Machine starts, while package building is
  # intentionally daemon-only. Pin the fixture's reviewed package hash here,
  # then prove it against the daemon build before installing the fixture.
  fixture_hash="2f11ee17f612fbc43f34f81771c53760f56768959624d29fd63b8e4285f5a9ac"
fi
if [ ! -f "${config_dir}/edge-manifest.json" ]; then
  [ ! -e "$config_dir" ] || die "incomplete developer config already exists: $config_dir"
  template_dir="$(mktemp -d "${developer_root}/templates.XXXXXX")"
  chmod 0700 "$template_dir"
  for name in edge-manifest.json.in broker.json.in signer.json.in provenance-catalog.unsigned.json; do
    template_source="${repo_root}/packaging/triad/macos/config/${name}"
    if [ "$host_os" = Linux ] && [ "$name" = edge-manifest.json.in ]; then
      template_source="${repo_root}/packaging/triad/linux/config/${name}"
    fi
    cp "$template_source" "${template_dir}/${name}"
    chmod 0600 "${template_dir}/${name}"
  done
  case "$(uname -s)" in
    Darwin) developer_trusted_time_source="macos-managed-timed" ;;
    Linux) developer_trusted_time_source="linux-chrony-nts" ;;
    *) die "developer triad launcher supports only Darwin and Linux" ;;
  esac
  sed "s/\"trusted_time_source\": \"macos-managed-timed\"/\"trusted_time_source\": \"${developer_trusted_time_source}\"/" \
    "${template_dir}/edge-manifest.json.in" > "${template_dir}/edge-manifest.json.in.new"
  chmod 0600 "${template_dir}/edge-manifest.json.in.new"
  mv -f "${template_dir}/edge-manifest.json.in.new" "${template_dir}/edge-manifest.json.in"
  if [ "$install_authority_fixture" -eq 1 ]; then
    catalog="${template_dir}/provenance-catalog.unsigned.json"
    catalog_new="${catalog}.new"
    jq --arg package_hash "$fixture_hash" '.records += [{
      subject: {kind:"petal", package_hash:$package_hash, route:"r000001"},
      publisher:"bloom-developer-fixture",
      operation_classes:[{operation_class:"fixture.payload", fee_asset:null}],
      installer_key_id:"unsigned-template",
      installer_signature:""
    }]' "$catalog" > "$catalog_new"
    chmod 0600 "$catalog_new"
    mv -f "$catalog_new" "$catalog"
  fi
  mkdir "$config_dir"
  chmod 0700 "$config_dir"
  "$bloom_bin" init triad-render-developer-enrollment \
    "$template_dir" "$config_dir" "$release_digest"
  rm -rf -- "$template_dir"
fi

if [ ! -e "$authority_edge_history" ]; then
  printf '%s\n' \
    '{' \
    '  "schema": "bloom.authority-edge-application-history.1",' \
    '  "historical_keys": [],' \
    '  "handovers": []' \
    '}' > "$authority_edge_history"
  chmod 0600 "$authority_edge_history"
fi
export BLOOM_AUTHORITY_EDGE_HISTORY="$authority_edge_history"

for name in edge-manifest.json machine-identity.json broker-identity.json \
  signer-identity.json session-identity.json broker.json signer.json \
  provenance-catalog.json
do
  [ -f "${config_dir}/${name}" ] || die "developer config is missing ${name}"
  [ ! -L "${config_dir}/${name}" ] || die "developer config contains a symlink: ${name}"
  chmod 0600 "${config_dir}/${name}"
done
if [ "$install_authority_fixture" -eq 1 ]; then
  jq -e --arg package_hash "$fixture_hash" '
    any(.records[]; .subject.kind == "petal" and
        .subject.package_hash == $package_hash and .subject.route == "r000001")
  ' "${config_dir}/provenance-catalog.json" >/dev/null ||
    die "developer enrollment predates the current fixture; create a fresh developer root"
fi
hyperliquid_package="${BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE:-}"
if [ -n "$hyperliquid_package" ]; then
  [ -d "$hyperliquid_package" ] ||
    die "integration Petal package is missing: $hyperliquid_package"
  if [ "$build_integration_petals" -eq 1 ]; then
    [ -x "${hyperliquid_package}/scripts/build.sh" ] ||
      die "integration Petal build script is missing: ${hyperliquid_package}/scripts/build.sh"
    (cd "$hyperliquid_package" && scripts/build.sh)
  fi
  "$bloom_bin" init triad-enroll-developer-petal-provenance \
    "$config_dir" "$hyperliquid_package"
fi
mkdir -p "${developer_root}/state/broker" "${developer_root}/state/signer"
chmod 0700 "${developer_root}/state" \
  "${developer_root}/state/broker" "${developer_root}/state/signer"

runtime_dir="$(mktemp -d "${developer_root}/runtime.XXXXXX")"
runtime_dir="$(cd "$runtime_dir" && pwd -P)"
chmod 0700 "$runtime_dir"
for endpoint in session signer broker; do
  mkdir "${runtime_dir}/${endpoint}"
  chgrp "$(id -g)" "${runtime_dir}/${endpoint}"
  chmod 0710 "${runtime_dir}/${endpoint}"
done
session_socket="${runtime_dir}/session/session.sock"
signer_socket="${runtime_dir}/signer/signer.sock"
signer_control_socket="${runtime_dir}/signer/control.sock"
broker_socket="${runtime_dir}/broker/broker.sock"
broker_control_socket="${runtime_dir}/broker/control.sock"
unit_token="$(basename "$runtime_dir")"
unit_prefix="bloom-triad-dev-$(id -u)-${unit_token}"
signer_service_unit="${unit_prefix}-signer.service"
broker_service_unit="${unit_prefix}-broker.service"
broker_ceremony_socket_unit="${unit_prefix}-broker-ceremony.socket"
broker_checkpoint_dir="${developer_root}/audit-checkpoints/broker"
signer_checkpoint_dir="${developer_root}/audit-checkpoints/signer"
machine_checkpoint_dir="${machine_home}/audit-checkpoints/machine"
mkdir -p "$broker_checkpoint_dir" "$signer_checkpoint_dir" "$machine_checkpoint_dir"
chmod 0700 "$broker_checkpoint_dir" "$signer_checkpoint_dir" "$machine_checkpoint_dir"
export BLOOM_MACHINE_AUDIT_CHECKPOINT_DIR="$machine_checkpoint_dir"

rewrite_broker_config() {
  source="${config_dir}/broker.json"
  temporary="${source}.new.$$"
  jq --arg signer_socket "$signer_socket" --arg digest "$release_digest" \
    '.signer_socket_path = $signer_socket | .build_digest = $digest |
     .network_containment = null | .maximum_requests_per_window = 10000' \
    "$source" > "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$source"
}
rewrite_signer_config() {
  source="${config_dir}/signer.json"
  temporary="${source}.new.$$"
  jq --arg digest "$release_digest" \
    '.build_digest = $digest | .network_containment = null |
     .maximum_requests_per_window = 10000' "$source" > "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$source"
}
rewrite_broker_config
rewrite_signer_config

env_file="${log_dir}/triad.env"
{
  printf 'export BLOOM_TRIAD_DEVELOPER_ROOT=%q\n' "$developer_root"
  printf 'export BLOOM_TRIAD_DEVELOPER_RUNTIME=%q\n' "$runtime_dir"
  printf 'export BLOOM_HOME=%q\n' "$machine_home"
  printf 'export BLOOM_BIN=%q\n' "$bloom_bin"
  printf 'export PATH=%q:"$PATH"\n' "$bloom_bin_dir"
  printf 'export BLOOM_RPC_ENDPOINT=%q\n' "unix:${machine_socket}"
  printf 'export BLOOM_BROKER_SOCKET=%q\n' "$broker_socket"
  printf 'export BLOOM_BROKER_AUDIT_CHECKPOINT_DIR=%q\n' "$broker_checkpoint_dir"
  printf 'export BLOOM_SIGNER_AUDIT_CHECKPOINT_DIR=%q\n' "$signer_checkpoint_dir"
  printf 'export BLOOM_MACHINE_AUDIT_CHECKPOINT_DIR=%q\n' "$machine_checkpoint_dir"
  printf 'export BLOOM_AUTHORITY_EDGE_HISTORY=%q\n' "$authority_edge_history"
  printf 'export BLOOM_MACHINE_IDENTITY=%q\n' "${config_dir}/machine-identity.json"
  printf 'export BLOOM_EDGE_MANIFEST=%q\n' "${config_dir}/edge-manifest.json"
  printf 'export BLOOM_PROVENANCE_CATALOG=%q\n' "${config_dir}/provenance-catalog.json"
} > "$env_file"
chmod 0600 "$env_file"
session_pid=""; signer_pid=""; broker_pid=""; machine_pid=""
systemd_units_installed=0
stop_linux_authority_units() {
  [ "$host_os" = Linux ] || return 0
  systemctl --user stop "$broker_service_unit" "$signer_service_unit" >/dev/null 2>&1 || true
  systemctl --user stop "$broker_ceremony_socket_unit" >/dev/null 2>&1 || true
  if [ "$systemd_units_installed" -eq 1 ]; then
    rm -f -- \
      "${user_unit_dir}/${broker_ceremony_socket_unit}" \
      "${user_unit_dir}/${broker_service_unit}" \
      "${user_unit_dir}/${signer_service_unit}"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    systemd_units_installed=0
  fi
}
cleanup() {
  status=$?
  trap - EXIT
  trap '' INT TERM HUP
  rm -f -- "$ready_file"
  if [ "$host_os" = Linux ]; then
    stop_linux_authority_units
  fi
  for pid in "$machine_pid" "$broker_pid" "$signer_pid" "$session_pid"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
  done
  for pid in "$machine_pid" "$broker_pid" "$signer_pid" "$session_pid"; do
    if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || true; fi
  done
  rm -f -- "$machine_socket"
  case "$runtime_dir" in
    "${developer_root}/runtime."*) rm -rf -- "$runtime_dir" ;;
    *) printf 'refusing to remove unexpected runtime: %s\n' "$runtime_dir" >&2 ;;
  esac
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

wait_for_socket() {
  path="$1"; pid="$2"; label="$3"
  attempts=0
  while [ ! -S "$path" ]; do
    kill -0 "$pid" 2>/dev/null || {
      tail -n 80 "${log_dir}/${label}.log" >&2 || true
      if [ "$label" = machine ] && [ -n "$mount_dir" ]; then
        mount_fallback_hint
      fi
      die "$label exited before publishing its socket"
    }
    attempts=$((attempts + 1))
    [ "$attempts" -lt "$socket_wait_attempts" ] || {
      if [ "$label" = machine ] && [ -n "$mount_dir" ]; then
        mount_fallback_hint
      fi
      die "$label did not publish its socket"
    }
    sleep 0.1
  done
}

mount_fallback_hint() {
  if [ "$host_os" = Linux ]; then
    printf '%s\n' \
      'Check the exact Linux developer mount sudo policy, or restart without --mount and use bloom vfs commands.' >&2
  else
    printf '%s\n' \
      'If this macOS version cannot mount NFS 4.1, restart without --mount and use bloom vfs commands.' >&2
  fi
}

wait_for_machine_ipc() {
  attempts=0
  while ! BLOOM_RPC_ENDPOINT="unix:${machine_socket}" \
    "$bloom_bin" --home "$machine_home" vfs ls / >/dev/null 2>&1
  do
    kill -0 "$machine_pid" 2>/dev/null || {
      tail -n 80 "${log_dir}/machine.log" >&2 || true
      die "Machine exited before its IPC endpoint became ready"
    }
    attempts=$((attempts + 1))
    [ "$attempts" -lt 300 ] || die "Machine socket did not pass its IPC readiness probe"
    sleep 0.1
  done
}

supervise_services() {
  while :; do
    if ! kill -0 "$session_pid" 2>/dev/null; then
      tail -n 80 "${log_dir}/session.log" >&2 || true
      die "session exited while supervising triad services"
    fi
    if [ "$host_os" = Linux ]; then
      for label in signer broker; do
        case "$label" in
          signer) unit="$signer_service_unit" ;;
          broker) unit="$broker_service_unit" ;;
        esac
        if ! systemctl --user is-active --quiet "$unit"; then
          tail -n 80 "${log_dir}/${label}.log" >&2 || true
          systemctl --user status "$unit" --no-pager >&2 || true
          die "$label exited while supervising triad services"
        fi
      done
    else
      for label in signer broker; do
        case "$label" in
          signer) pid="$signer_pid" ;;
          broker) pid="$broker_pid" ;;
        esac
        if ! kill -0 "$pid" 2>/dev/null; then
          tail -n 80 "${log_dir}/${label}.log" >&2 || true
          die "$label exited while supervising triad services"
        fi
      done
    fi
    sleep 0.25
  done
}

write_linux_socket_unit() {
  unit="$1"; description="$2"; path="$3"; descriptor="$4"; service="$5"
  {
    printf '%s\n' '[Unit]' "Description=$description" '' '[Socket]'
    printf 'ListenStream=%s\n' "$path"
    printf 'FileDescriptorName=%s\n' "$descriptor"
    printf 'Service=%s\n' "$service"
    printf '%s\n' 'SocketMode=0600' 'DirectoryMode=0700' 'RemoveOnStop=yes' 'Accept=no'
  } > "${user_unit_dir}/${unit}"
  chmod 0600 "${user_unit_dir}/${unit}"
}

start_linux_authority_services() {
  # Mark ownership before the first write so the EXIT trap removes even a
  # partially rendered unit set.
  systemd_units_installed=1
  write_linux_socket_unit "$broker_ceremony_socket_unit" \
    'Bloom developer Broker ceremony listener' '127.0.0.1:18734' broker-ceremony "$broker_service_unit"

  : > "${log_dir}/signer.log"
  {
    printf '%s\n' '[Unit]' 'Description=Bloom developer Signer' '' \
      '[Service]' 'Type=simple' 'UMask=0077'
    printf 'ExecStart=%s\n' "$signer_bin"
    printf 'StandardOutput=append:%s\n' "${log_dir}/signer.log"
    printf 'StandardError=append:%s\n' "${log_dir}/signer.log"
    printf 'Environment=%s\n' \
      "BLOOM_TRIAD_DEVELOPER_ROOT=$developer_root" \
      "BLOOM_SIGNER_IDENTITY=${config_dir}/signer-identity.json" \
      "BLOOM_EDGE_MANIFEST=${config_dir}/edge-manifest.json" \
      "BLOOM_SIGNER_CONFIG=${config_dir}/signer.json" \
      "BLOOM_SIGNER_AUDIT_CHECKPOINT_DIR=$signer_checkpoint_dir" \
      "BLOOM_AUTHORITY_EDGE_HISTORY=$authority_edge_history" \
      "BLOOM_SESSION_SOCKET=$session_socket" \
      "BLOOM_SIGNER_SOCKET=$signer_socket" \
      "BLOOM_SIGNER_CONTROL_SOCKET=$signer_control_socket"
  } > "${user_unit_dir}/${signer_service_unit}"
  chmod 0600 "${user_unit_dir}/${signer_service_unit}"

  : > "${log_dir}/broker.log"
  {
    printf '%s\n' '[Unit]' 'Description=Bloom developer Broker' \
      "Requires=$broker_ceremony_socket_unit" \
      "After=$signer_service_unit" '' \
      '[Service]' 'Type=simple' 'UMask=0077'
    printf 'ExecStart=%s\n' "$broker_bin"
    printf 'StandardOutput=append:%s\n' "${log_dir}/broker.log"
    printf 'StandardError=append:%s\n' "${log_dir}/broker.log"
    printf 'Environment=%s\n' \
      "BLOOM_TRIAD_DEVELOPER_ROOT=$developer_root" \
      "BLOOM_BROKER_IDENTITY=${config_dir}/broker-identity.json" \
      "BLOOM_EDGE_MANIFEST=${config_dir}/edge-manifest.json" \
      "BLOOM_BROKER_CONFIG=${config_dir}/broker.json" \
      "BLOOM_BROKER_AUDIT_CHECKPOINT_DIR=$broker_checkpoint_dir" \
      "BLOOM_AUTHORITY_EDGE_HISTORY=$authority_edge_history" \
      "BLOOM_SESSION_SOCKET=$session_socket" \
      "BLOOM_BROKER_SOCKET=$broker_socket" \
      "BLOOM_BROKER_CONTROL_SOCKET=$broker_control_socket" \
      'BLOOM_BROKER_CEREMONY_ACTIVATION_NAME=broker-ceremony'
    printf 'Sockets=%s\n' "$broker_ceremony_socket_unit"
  } > "${user_unit_dir}/${broker_service_unit}"
  chmod 0600 "${user_unit_dir}/${broker_service_unit}"

  systemctl --user daemon-reload
  systemctl --user start "$broker_ceremony_socket_unit"
  systemctl --user start "$signer_service_unit"
  signer_pid="$(systemctl --user show "$signer_service_unit" -p MainPID --value)"
  [ "$signer_pid" -gt 0 ] ||
    die "Linux developer Signer did not publish a main process"
  wait_for_socket "$signer_socket" "$signer_pid" signer

  systemctl --user start "$broker_service_unit"
  broker_pid="$(systemctl --user show "$broker_service_unit" -p MainPID --value)"
  [ "$broker_pid" -gt 0 ] ||
    die "Linux developer Broker did not publish a main process"
  wait_for_socket "$broker_socket" "$broker_pid" broker
  wait_for_socket "$broker_control_socket" "$broker_pid" broker
  systemctl --user is-active --quiet "$signer_service_unit" "$broker_service_unit"
}

BLOOM_TRIAD_DEVELOPER_ROOT="$developer_root" \
BLOOM_TRIAD_DEVELOPER_RUNTIME="$runtime_dir" \
  "$bloom_bin" serve session-sentinel >"${log_dir}/session.log" 2>&1 &
session_pid=$!
wait_for_socket "$session_socket" "$session_pid" session

if [ "$host_os" = Linux ]; then
  start_linux_authority_services
else
  env -u BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS \
  -u BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST \
  BLOOM_TRIAD_DEVELOPER_ROOT="$developer_root" \
  BLOOM_SIGNER_IDENTITY="${config_dir}/signer-identity.json" \
  BLOOM_EDGE_MANIFEST="${config_dir}/edge-manifest.json" \
  BLOOM_SIGNER_CONFIG="${config_dir}/signer.json" \
  BLOOM_SIGNER_SOCKET="$signer_socket" \
  BLOOM_SIGNER_CONTROL_SOCKET="$signer_control_socket" \
  BLOOM_SIGNER_AUDIT_CHECKPOINT_DIR="$signer_checkpoint_dir" \
  BLOOM_SESSION_SOCKET="$session_socket" \
    "$signer_bin" >"${log_dir}/signer.log" 2>&1 &
  signer_pid=$!
  wait_for_socket "$signer_socket" "$signer_pid" signer

  env -u BLOOM_OPERATOR_ACCEPT_CLOCK_UTC_MS \
  -u BLOOM_OPERATOR_CONFIRM_EXPIRING_APPROVALS_DIGEST \
  BLOOM_TRIAD_DEVELOPER_ROOT="$developer_root" \
  BLOOM_BROKER_IDENTITY="${config_dir}/broker-identity.json" \
  BLOOM_EDGE_MANIFEST="${config_dir}/edge-manifest.json" \
  BLOOM_BROKER_CONFIG="${config_dir}/broker.json" \
  BLOOM_BROKER_SOCKET="$broker_socket" \
  BLOOM_BROKER_CONTROL_SOCKET="$broker_control_socket" \
  BLOOM_BROKER_AUDIT_CHECKPOINT_DIR="$broker_checkpoint_dir" \
  BLOOM_SESSION_SOCKET="$session_socket" \
    "$broker_bin" >"${log_dir}/broker.log" 2>&1 &
  broker_pid=$!
  wait_for_socket "$broker_socket" "$broker_pid" broker
fi

machine_config="${machine_home}/config.toml"
if [ ! -e "$machine_config" ]; then
  canonical_machine_config="${BLOOM_TRIAD_DEV_MACHINE_CONFIG:-${HOME}/.bloom/config.toml}"
  [ -f "$canonical_machine_config" ] && [ ! -L "$canonical_machine_config" ] ||
    die "canonical Machine config is not a regular file: $canonical_machine_config"
  cp "$canonical_machine_config" "$machine_config"
  chmod 0600 "$machine_config"
fi

# Developer Petals are installed through the launched Machine below. Do not
# download or advertise a stale production release merely to make this isolated
# harness ready.
[ -f "$machine_config" ] || die "Machine did not create its configuration"
machine_config_new="${machine_config}.new.$$"
awk '
  $0 == "[petals]" {
    saw_petals = 1
    in_petals = 1
    print
    next
  }
  in_petals && $0 ~ /^preinstalled = \[/ {
    print "preinstalled = []"
    replaced_preinstalled = 1
    if ($0 !~ /\]/) skipping = 1
    next
  }
  skipping {
    if ($0 == "]") skipping = 0
    next
  }
  in_petals && $0 ~ /^\[/ {
    if (!replaced_preinstalled) print "preinstalled = []"
    in_petals = 0
  }
  { print }
  END {
    if (in_petals && !replaced_preinstalled) print "preinstalled = []"
    if (!saw_petals) {
      print ""
      print "[petals]"
      print "preinstalled = []"
    }
  }
' "$machine_config" > "$machine_config_new"
chmod 0600 "$machine_config_new"
mv -f "$machine_config_new" "$machine_config"

if [ "$services_only" -eq 1 ]; then
  printf 'ready\n' > "$ready_file"
  printf '%s\n' \
    'Bloom triad services are ready; Machine is developer-managed.' \
    'Source triad.env to put the selected debug bloom binary first on PATH;' \
    'then use bloom directly in that terminal:' \
    "  source ${env_file}" \
    "  cd ${repo_root}" \
    '  cargo build -p bloom --no-default-features --features mount,triad-dev-harness' \
    '  bloom serve --endpoint "$BLOOM_RPC_ENDPOINT"'
  supervise_services
fi

mount_is_live() {
  mount | grep -F " on ${mount_dir} " >/dev/null 2>&1
}

start_machine() {
  rm -f -- "$machine_socket"
  machine_args=(--home "$machine_home" serve --endpoint "unix:${machine_socket}")
  if [ -n "$mount_dir" ]; then
    machine_args+=(--mount "$mount_dir")
  fi
  BLOOM_TRIAD_DEVELOPER_ROOT="$developer_root" \
  BLOOM_BROKER_SOCKET="$broker_socket" \
  BLOOM_MACHINE_IDENTITY="${config_dir}/machine-identity.json" \
  BLOOM_EDGE_MANIFEST="${config_dir}/edge-manifest.json" \
  BLOOM_PROVENANCE_CATALOG="${config_dir}/provenance-catalog.json" \
    "$bloom_bin" "${machine_args[@]}" \
      >>"${log_dir}/machine.log" 2>&1 &
  machine_pid=$!
  printf '%s\n' "$machine_pid" > "${log_dir}/machine.pid"
  chmod 0600 "${log_dir}/machine.pid"
  wait_for_socket "$machine_socket" "$machine_pid" machine
  wait_for_machine_ipc
  if [ -n "$mount_dir" ]; then
    mount_attempts=0
    while ! mount_is_live; do
      kill -0 "$machine_pid" 2>/dev/null || {
        tail -n 80 "${log_dir}/machine.log" >&2 || true
        mount_fallback_hint
        die "Machine exited before its requested kernel mount became ready"
      }
      mount_attempts=$((mount_attempts + 1))
      [ "$mount_attempts" -lt 300 ] || {
        mount_fallback_hint
        die "Machine socket became ready but its requested kernel mount did not"
      }
      sleep 0.1
    done
  fi
}

: > "${log_dir}/machine.log"
start_machine

machine_cli() {
  BLOOM_RPC_ENDPOINT="unix:${machine_socket}" \
  BLOOM_TRIAD_DEVELOPER_ROOT="$developer_root" \
  BLOOM_BROKER_SOCKET="$broker_socket" \
  BLOOM_MACHINE_IDENTITY="${config_dir}/machine-identity.json" \
  BLOOM_EDGE_MANIFEST="${config_dir}/edge-manifest.json" \
  BLOOM_PROVENANCE_CATALOG="${config_dir}/provenance-catalog.json" \
    "$bloom_bin" --home "$machine_home" "$@"
}

if [ "$install_authority_fixture" -eq 1 ]; then
  machine_cli petals build "$fixture_root" >"${log_dir}/fixture-build.log" 2>&1
  built_fixture_hash="$(sed -n 's/^hash: //p' "${log_dir}/fixture-build.log")"
  [ "$built_fixture_hash" = "$fixture_hash" ] || {
    cat "${log_dir}/fixture-build.log" >&2
    die "authority fixture package hash drifted from its signed provenance record"
  }
  machine_cli petals install "$fixture_root" >"${log_dir}/fixture-install.log" 2>&1
fi

for integration_petal in \
  "${BLOOM_TRIAD_DEV_POLYMARKET_PACKAGE:-}" \
  "${BLOOM_TRIAD_DEV_HYPERLIQUID_PACKAGE:-}"
do
  [ -n "$integration_petal" ] || continue
  [ -d "$integration_petal" ] || die "integration Petal package is missing: $integration_petal"
  package_name="$(basename "$integration_petal")"
  machine_cli petals install "$integration_petal" >"${log_dir}/${package_name}-install.log" 2>&1
done

kill -0 "$machine_pid" 2>/dev/null || die "Machine exited before readiness could be published"
printf 'ready\n' > "$ready_file"
if [ -z "$mount_dir" ]; then
  printf '%s\n' \
    'Bloom is ready without a kernel mount.' \
    'Source triad.env to put the selected debug bloom binary first on PATH;' \
    'then use bloom directly in that terminal:' \
    "  source ${env_file}" \
    '  bloom vfs ls /' \
    '  bloom vfs cat /next.md'
else
  while kill -0 "$machine_pid" 2>/dev/null; do
    if ! mount_is_live; then
      printf 'triad developer launcher: Machine mount disappeared; restarting Machine only\n' >&2
      kill "$machine_pid" 2>/dev/null || true
      wait "$machine_pid" 2>/dev/null || true
      machine_pid=""
      start_machine
      printf 'ready\n' > "$ready_file"
    fi
    sleep 1
  done
fi
wait "$machine_pid"
