#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  install-linux.sh install ROOT LOGIN_UID LOGIN_USER PAYLOAD_DIR
  install-linux.sh rotate-config ROOT LOGIN_UID PRINCIPAL CONFIG_JSON
  install-linux.sh uninstall ROOT LOGIN_UID CONFIRM_TOKEN
EOF
  exit 64
}

[[ $# -ge 1 ]] || usage
action="$1"
shift
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

validate_root_uid() {
  root="$1"
  login_uid="$2"
  [[ -d "$root" ]] || {
    echo "installer root is not a directory" >&2
    exit 66
  }
  [[ "$login_uid" =~ ^[1-9][0-9]*$ ]] || {
    echo "LOGIN_UID must be a positive decimal UID" >&2
    exit 64
  }
  root="$(cd "$root" && pwd -P)"
}

atomic_install() {
  source_file="$1"
  destination="$2"
  mode="$3"
  mkdir -p "$(dirname "$destination")"
  temporary="${destination}.new.$$"
  install -m "$mode" "$source_file" "$temporary"
  mv -f "$temporary" "$destination"
}

sha256_digest() {
  input="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$input" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$input" | awk '{print $1}'
  else
    echo "Linux installation requires sha256sum or shasum" >&2
    return 69
  fi
}

case "$action" in
  install)
    [[ $# -eq 4 ]] || usage
    validate_root_uid "$1" "$2"
    login_user="$3"
    payload="$(cd "$4" && pwd -P)"
    if [[ "$root" == "/" && "$(id -u)" -ne 0 ]]; then
      echo "Linux installation requires root" >&2
      exit 77
    fi
    platform_claim="$(<"$payload/PLATFORM_CLAIM")"
    if [[ "$platform_claim" != "linux" ]] &&
      [[ ! ("$platform_claim" == "test-unclaimed" &&
        "${BLOOM_ALLOW_TEST_UNCLAIMED:-}" == "true") ]]
    then
      echo "bundle is not approved for Linux installation" >&2
      exit 65
    fi
    [[ "$login_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || {
      echo "LOGIN_USER is not a safe account name" >&2
      exit 64
    }
    for required in \
      bin/bloom \
      bin/bloom-broker \
      bin/bloom-signer \
      bin/bloom-signer-migrate \
      SHA256SUMS \
      installer/linux/config/edge-manifest.json.in \
      installer/linux/config/broker.json.in \
      installer/linux/config/signer.json.in \
      installer/linux/config/provenance-catalog.unsigned.json \
      installer/linux/config/nts-servers.conf \
      installer/linux/bin/bloom \
      installer/linux/systemd-user/bloom-session.service
    do
      test -f "$payload/$required" || {
        echo "payload is missing $required" >&2
        exit 66
      }
    done
    installed_config_root="$root/etc/bloom/$login_uid"
    fresh_install=true
    if [[ -e "$installed_config_root/edge-manifest.json" ]]; then
      fresh_install=false
      for installed_relative in \
        edge-manifest.json \
        broker/identity.json \
        signer/identity.json \
        machine/identity.json \
        machine/revoke-identity.json \
        session/identity.json \
        installer-identity.json \
        provenance-catalog.json
      do
        [[ -f "$installed_config_root/$installed_relative" && \
          ! -L "$installed_config_root/$installed_relative" ]] || {
          echo "installed Linux enrollment is incomplete; refusing replacement" >&2
          exit 65
        }
      done
    fi
    if [[ "$root" == "/" ]] && [[ -x "$root/usr/libexec/bloom/bloom-broker" ]]; then
      systemctl stop "bloom-session@$login_uid.path" 2>/dev/null || true
      systemctl stop "bloom-broker-ceremony@$login_uid.socket" 2>/dev/null || true
      systemctl stop "bloom-broker@$login_uid.service"
      systemctl stop "bloom-signer@$login_uid.service"
    fi

    binary_root="$root/usr/libexec/bloom"
    mkdir -p "$binary_root"
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      atomic_install "$payload/bin/$binary" "$binary_root/$binary" 0755
    done
    atomic_install "$payload/installer/linux/bin/bloom" "$root/usr/bin/bloom" 0755

    sysusers="$root/usr/lib/sysusers.d/bloom-$login_uid.conf"
    tmpfiles="$root/usr/lib/tmpfiles.d/bloom-$login_uid.conf"
    mkdir -p "$(dirname "$sysusers")" "$(dirname "$tmpfiles")"
    sed \
      -e "s/@LOGIN_UID@/$login_uid/g" \
      -e "s/@LOGIN_USER@/$login_user/g" \
      "$script_dir/linux/sysusers.d/bloom-login.conf.in" > "$sysusers.new"
    chmod 0644 "$sysusers.new"
    mv -f "$sysusers.new" "$sysusers"
    sed \
      -e "s/@LOGIN_UID@/$login_uid/g" \
      -e "s/@LOGIN_USER@/$login_user/g" \
      "$script_dir/linux/tmpfiles.d/bloom-login.conf.in" > "$tmpfiles.new"
    chmod 0644 "$tmpfiles.new"
    mv -f "$tmpfiles.new" "$tmpfiles"

    unit_root="$root/usr/lib/systemd/system"
    mkdir -p "$unit_root"
    atomic_install \
      "$script_dir/linux/systemd/bloom-broker-ceremony@.socket" \
      "$unit_root/bloom-broker-ceremony@.socket" \
      0644
    atomic_install \
      "$script_dir/linux/systemd/bloom-session@.path" \
      "$unit_root/bloom-session@.path" \
      0644
    for obsolete_socket in \
      bloom-signer-rpc \
      bloom-signer-control \
      bloom-broker-rpc \
      bloom-broker-control
    do
      rm -f -- "$unit_root/$obsolete_socket@.socket"
    done
    user_unit_root="$root/usr/lib/systemd/user"
    atomic_install \
      "$payload/installer/linux/systemd-user/bloom-session.service" \
      "$user_unit_root/bloom-session.service" \
      0644
    sed \
      -e "s|@BLOOM_BROKER_BINARY@|/usr/libexec/bloom/bloom-broker|g" \
      "$script_dir/linux/systemd/bloom-broker@.service.in" \
      > "$unit_root/bloom-broker@.service.new"
    chmod 0644 "$unit_root/bloom-broker@.service.new"
    mv -f "$unit_root/bloom-broker@.service.new" "$unit_root/bloom-broker@.service"
    sed \
      -e "s|@BLOOM_SIGNER_BINARY@|/usr/libexec/bloom/bloom-signer|g" \
      "$script_dir/linux/systemd/bloom-signer@.service.in" \
      > "$unit_root/bloom-signer@.service.new"
    chmod 0644 "$unit_root/bloom-signer@.service.new"
    mv -f "$unit_root/bloom-signer@.service.new" "$unit_root/bloom-signer@.service"

    nts_servers="$payload/installer/linux/config/nts-servers.conf"
    if grep -Ev '^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|[0-9a-fA-F:]+)$' \
      "$nts_servers" >/dev/null ||
      [[ "$(LC_ALL=C sort -u "$nts_servers" | sed '/^$/d' | wc -l | tr -d ' ')" -lt 2 ]]
    then
      echo "at least two distinct reviewed NTS server names are required" >&2
      exit 65
    fi
    chrony_target="$root/etc/chrony/conf.d/bloom-nts.conf"
    mkdir -p "$(dirname "$chrony_target")"
    {
      echo "authselectmode require"
      while IFS= read -r server; do
        test -n "$server" && printf 'server %s iburst nts\n' "$server"
      done < "$nts_servers"
      echo "minsources 2"
      echo "rtcsync"
    } > "$chrony_target.new"
    chmod 0644 "$chrony_target.new"
    mv -f "$chrony_target.new" "$chrony_target"
    enrollment_scratch=""
    trap 'if [[ -n "${enrollment_scratch:-}" && -d "$enrollment_scratch" ]]; then find "$enrollment_scratch" -depth -delete; fi' EXIT
    source_config=""
    if [[ "$root" == "/" ]]; then
      systemd-sysusers "$sysusers"
      systemd-tmpfiles --create "$tmpfiles"
    fi
    if [[ "$fresh_install" == true ]]; then
      if [[ "$root" == "/" ]]; then
        broker_uid="$(id -u "bloom-broker-$login_uid")"
        signer_uid="$(id -u "bloom-signer-$login_uid")"
        session_gid="$(getent group "bloom-session-$login_uid" | cut -d: -f3)"
        for generated_id in "$broker_uid" "$signer_uid" "$session_gid"; do
          [[ "$generated_id" =~ ^[1-9][0-9]*$ ]] || {
            echo "Linux service identity allocation failed" >&2
            exit 65
          }
        done
        release_digest="$(sha256_digest "$payload/SHA256SUMS")"
        [[ "$release_digest" =~ ^[0-9a-f]{64}$ ]] || {
          echo "signed payload release digest is invalid" >&2
          exit 65
        }
        enrollment_scratch="$(mktemp -d /var/tmp/bloom-linux-enrollment.XXXXXX)"
        chmod 0700 "$enrollment_scratch"
        mkdir -m 0700 "$enrollment_scratch/templates" "$enrollment_scratch/material"
        for template in \
          edge-manifest.json.in \
          broker.json.in \
          signer.json.in \
          provenance-catalog.unsigned.json
        do
          install -m 0644 \
            "$payload/installer/linux/config/$template" \
            "$enrollment_scratch/templates/$template"
        done
        "$binary_root/bloom" init triad-render-linux-enrollment \
          "$enrollment_scratch/templates" \
          "$enrollment_scratch/material" \
          "$login_uid" \
          "$broker_uid" \
          "$signer_uid" \
          "$session_gid" \
          "$release_digest"
        source_config="$enrollment_scratch/material"
      else
        source_config="$payload/config"
      fi
      for generated in \
        edge-manifest.json broker.json signer.json \
        machine-identity.json broker-identity.json signer-identity.json \
        revoke-identity.json session-identity.json installer-identity.json \
        provenance-catalog.json
      do
        [[ -f "$source_config/$generated" && ! -L "$source_config/$generated" ]] || {
          echo "generated Linux enrollment is missing $generated" >&2
          exit 65
        }
      done
    fi

    config_root="$root/etc/bloom/$login_uid"
    mkdir -p \
      "$config_root/broker" \
      "$config_root/signer" \
      "$config_root/machine" \
      "$config_root/session"
    chmod 0711 "$config_root"
    chmod 0700 \
      "$config_root/broker" \
      "$config_root/signer" \
      "$config_root/machine" \
      "$config_root/session"
    if [[ "$fresh_install" == true ]]; then
      atomic_install "$source_config/edge-manifest.json" "$config_root/edge-manifest.json" 0644
      atomic_install "$source_config/broker.json" "$config_root/broker/config.json" 0600
      atomic_install "$source_config/signer.json" "$config_root/signer/config.json" 0600
      atomic_install "$source_config/broker-identity.json" "$config_root/broker/identity.json" 0600
      atomic_install "$source_config/signer-identity.json" "$config_root/signer/identity.json" 0600
      atomic_install "$source_config/machine-identity.json" "$config_root/machine/identity.json" 0600
      atomic_install "$source_config/revoke-identity.json" "$config_root/machine/revoke-identity.json" 0600
      atomic_install "$source_config/session-identity.json" "$config_root/session/identity.json" 0600
      atomic_install "$source_config/installer-identity.json" "$config_root/installer-identity.json" 0600
      atomic_install "$source_config/provenance-catalog.json" "$config_root/provenance-catalog.json" 0644
      enrollment_root="$root/etc/bloom/enrollments"
      mkdir -p "$enrollment_root"
      chmod 0755 "$enrollment_root"
      enrollment_source="$config_root/.enrollment.source.$$"
      printf '{"schema":"bloom.linux-enrollment.1","state":"active","login_uid":%s,"login_user":"%s","release_digest":"%s"}\n' \
        "$login_uid" "$login_user" "${release_digest:-test-unclaimed}" > "$enrollment_source"
      atomic_install "$enrollment_source" "$enrollment_root/$login_uid.json" 0644
      rm -f -- "$enrollment_source"
    fi
    machine_audit_history_source="$config_root/.machine-audit-history.source.$$"
    printf '%s\n' \
      '{' \
      '  "schema": "bloom.machine-audit-trust.v1",' \
      '  "predecessors": []' \
      '}' > "$machine_audit_history_source"
    if [[ ! -e "$config_root/machine-audit-history.json" ]]; then
      atomic_install \
        "$machine_audit_history_source" \
        "$config_root/machine-audit-history.json" \
        0644
    fi
    rm -f -- "$machine_audit_history_source"
    authority_edge_history_source="$config_root/.authority-edge-history.source.$$"
    printf '%s\n' \
      '{' \
      '  "schema": "bloom.authority-edge-application-history.1",' \
      '  "historical_keys": [],' \
      '  "handovers": []' \
      '}' > "$authority_edge_history_source"
    if [[ ! -e "$config_root/authority-edge-history.json" ]]; then
      atomic_install \
        "$authority_edge_history_source" \
        "$config_root/authority-edge-history.json" \
        0644
    fi
    rm -f -- "$authority_edge_history_source"
    if [[ "$root" == "/" ]]; then
      chown "bloom-broker-$login_uid:bloom-broker-$login_uid" \
        "$config_root/broker/config.json" \
        "$config_root/broker/identity.json"
      chown "bloom-signer-$login_uid:bloom-signer-$login_uid" \
        "$config_root/signer/config.json" \
        "$config_root/signer/identity.json"
      chown "$login_user:$login_user" \
        "$config_root/machine/identity.json" \
        "$config_root/machine/revoke-identity.json" \
        "$config_root/session/identity.json"
    fi
    dropin_root="$unit_root/bloom-signer@$login_uid.service.d"
    if [[ -e "$payload/credentials/aws-credentials" || -e "$payload/config/aws-kms-ip-allow.conf" ]]; then
      test -f "$payload/credentials/aws-credentials" &&
        test -f "$payload/config/aws-kms-ip-allow.conf" || {
          echo "AWS KMS credentials and reviewed IP allowlist must be supplied together" >&2
          exit 66
        }
      if ! grep -Eq '^IPAddressAllow=[0-9a-fA-F:.]+/[0-9]+$' \
        "$payload/config/aws-kms-ip-allow.conf" ||
        grep -Eq '(^|=)(any|0\.0\.0\.0/0|::/0)$' \
          "$payload/config/aws-kms-ip-allow.conf" ||
        grep -Ev '^(IPAddressAllow=[0-9a-fA-F:.]+/[0-9]+|[[:space:]]*)$' \
          "$payload/config/aws-kms-ip-allow.conf" >/dev/null
      then
        echo "AWS KMS IP allowlist is empty, wildcard, or malformed" >&2
        exit 65
      fi
      atomic_install \
        "$payload/credentials/aws-credentials" \
        "$config_root/signer/aws-credentials" \
        0600
      mkdir -p "$dropin_root"
      awk \
        -v allowlist="$payload/config/aws-kms-ip-allow.conf" \
        '{
          if ($0 == "@AWS_KMS_IP_ALLOW_DIRECTIVES@") {
            while ((getline line < allowlist) > 0) print line
            close(allowlist)
          } else {
            print
          }
        }' \
        "$script_dir/linux/systemd/instance-dropins/bloom-signer@LOGIN_UID.service.d/50-aws-kms.conf.in" |
        sed '/@AWS_KMS_IP_ALLOW_DIRECTIVES@/d' \
        > "$dropin_root/50-aws-kms.conf.new"
      chmod 0644 "$dropin_root/50-aws-kms.conf.new"
      mv -f "$dropin_root/50-aws-kms.conf.new" "$dropin_root/50-aws-kms.conf"
      if [[ "$root" == "/" ]]; then
        chown "bloom-signer-$login_uid:bloom-signer-$login_uid" \
          "$config_root/signer/aws-credentials"
      fi
    else
      rm -f -- \
        "$config_root/signer/aws-credentials" \
        "$dropin_root/50-aws-kms.conf"
      rmdir "$dropin_root" 2>/dev/null || true
    fi

    if [[ "$root" == "/" ]]; then
      systemctl daemon-reload
      user_runtime="/run/user/$login_uid"
      user_bus="$user_runtime/bus"
      [[ -d "$user_runtime" && -S "$user_bus" ]] || {
        echo "an active systemd user session is required to start Bloom" >&2
        exit 69
      }
      runuser -u "$login_user" -- env \
        XDG_RUNTIME_DIR="$user_runtime" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_bus" \
        systemctl --user daemon-reload
      runuser -u "$login_user" -- env \
        XDG_RUNTIME_DIR="$user_runtime" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_bus" \
        systemctl --user enable bloom-session.service
      systemctl disable --now \
        "bloom-signer-rpc@$login_uid.socket" \
        "bloom-signer-control@$login_uid.socket" \
        "bloom-broker-rpc@$login_uid.socket" \
        "bloom-broker-control@$login_uid.socket" \
        2>/dev/null || true
      systemctl enable --now \
        "bloom-broker-ceremony@$login_uid.socket" \
        "bloom-session@$login_uid.path"
      printf '%s\n' \
        "BLOOM_BIN=/usr/bin/bloom" \
        "BLOOM_INSTALL_MODE=triad-linux-systemd" \
        "BLOOM_RELOGIN_REQUIRED=1"
    fi
    ;;
  rotate-config)
    [[ $# -eq 4 ]] || usage
    validate_root_uid "$1" "$2"
    principal="$3"
    config="$4"
    [[ "$principal" == "broker" || "$principal" == "signer" ]] || usage
    test -f "$config" || {
      echo "replacement config is missing" >&2
      exit 66
    }
    destination="$root/etc/bloom/$login_uid/$principal/config.json"
    test -d "$(dirname "$destination")" || {
      echo "principal is not installed" >&2
      exit 66
    }
    command -v python3 >/dev/null || {
      echo "Linux config rotation requires python3 for closed-field validation" >&2
      exit 69
    }
    python3 - "$destination" "$config" "$principal" <<'PY'
import json
import pathlib
import sys

old_path, new_path, principal = sys.argv[1:]
try:
    old = json.loads(pathlib.Path(old_path).read_text())
    new = json.loads(pathlib.Path(new_path).read_text())
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"invalid Linux {principal} config rotation JSON: {error}")
if not isinstance(old, dict) or not isinstance(new, dict):
    raise SystemExit("Linux config rotation requires JSON objects")

operational = {
    "maximum_connections",
    "maximum_in_flight_mutations",
    "maximum_requests_per_window",
    "request_window_ms",
    "maximum_journal_admissions_per_window",
    "journal_window_ms",
    "control_maximum_connections",
    "control_maximum_in_flight_mutations",
    "control_maximum_requests_per_window",
    "control_request_window_ms",
    "control_maximum_journal_admissions_per_window",
    "control_journal_window_ms",
}
missing = object()
for field in sorted(set(old) | set(new)):
    if field not in operational and old.get(field, missing) != new.get(field, missing):
        raise SystemExit(
            f"Linux config rotation may not change authority or identity field: {field}"
        )
PY
    atomic_install "$config" "$destination" 0600
    if [[ "$root" == "/" ]]; then
      chown "bloom-$principal-$login_uid:bloom-$principal-$login_uid" "$destination"
      systemctl restart "bloom-$principal@$login_uid.service"
    fi
    ;;
  uninstall)
    [[ $# -eq 3 ]] || usage
    validate_root_uid "$1" "$2"
    expected="delete-bloom-login-$login_uid"
    [[ "$3" == "$expected" ]] || {
      echo "uninstall confirmation must equal $expected" >&2
      exit 64
    }
    if [[ "$root" == "/" ]]; then
      login_user="$(getent passwd "$login_uid" | cut -d: -f1)"
      user_runtime="/run/user/$login_uid"
      if [[ -n "$login_user" && -S "$user_runtime/bus" ]]; then
        runuser -u "$login_user" -- env \
          XDG_RUNTIME_DIR="$user_runtime" \
          DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
          systemctl --user disable --now bloom-session.service
      fi
      systemctl stop \
        "bloom-broker@$login_uid.service" \
        "bloom-signer@$login_uid.service"
      systemctl disable --now \
        "bloom-broker-ceremony@$login_uid.socket" \
        "bloom-session@$login_uid.path"
    fi
    config_target="$root/etc/bloom/$login_uid"
    state_target="$root/var/lib/bloom/$login_uid"
    run_target="$root/run/bloom/$login_uid"
    rm -rf -- "$config_target" "$state_target" "$run_target"
    rm -f -- \
      "$root/etc/bloom/enrollments/$login_uid.json" \
      "$root/usr/lib/sysusers.d/bloom-$login_uid.conf" \
      "$root/usr/lib/tmpfiles.d/bloom-$login_uid.conf" \
      "$root/usr/lib/systemd/system/bloom-signer@$login_uid.service.d/50-aws-kms.conf"
    rmdir "$root/usr/lib/systemd/system/bloom-signer@$login_uid.service.d" \
      2>/dev/null || true
    if [[ "$root" == "/" ]]; then
      systemctl daemon-reload
    fi
    ;;
  *)
    usage
    ;;
esac
