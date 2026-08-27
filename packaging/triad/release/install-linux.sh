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

case "$action" in
  install)
    [[ $# -eq 4 ]] || usage
    validate_root_uid "$1" "$2"
    login_user="$3"
    payload="$(cd "$4" && pwd -P)"
    test -f "$payload/ARTIFACT_CLASS" || {
      echo "payload is missing ARTIFACT_CLASS" >&2
      exit 66
    }
    artifact_class="$(<"$payload/ARTIFACT_CLASS")"
    canary_class='solana-mainnet-''canary-v1'
    case "$artifact_class" in
      production) ;;
      "$canary_class")
        [[ "${BLOOM_ALLOW_SOLANA_MAINNET_CANARY_BUNDLE:-}" == "true" ]] || {
          echo "Solana mainnet canary installation was not explicitly enabled" >&2
          exit 65
        }
        ;;
      *)
        echo "payload has an unknown artifact class" >&2
        exit 65
        ;;
    esac
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
      config/edge-manifest.json \
      config/broker.json \
      config/signer.json \
      config/broker-identity.json \
      config/signer-identity.json \
      config/nts-servers.conf
    do
      test -f "$payload/$required" || {
        echo "payload is missing $required" >&2
        exit 66
      }
    done
    installed_config_root="$root/etc/bloom/$login_uid"
    if [[ -e "$installed_config_root/edge-manifest.json" ]]; then
      for identity_pair in \
        "edge-manifest.json:edge-manifest.json" \
        "broker/identity.json:broker-identity.json" \
        "signer/identity.json:signer-identity.json"
      do
        installed_relative="${identity_pair%%:*}"
        payload_relative="${identity_pair#*:}"
        installed_identity="$installed_config_root/$installed_relative"
        payload_identity="$payload/config/$payload_relative"
        [[ -f "$installed_identity" && ! -L "$installed_identity" ]] || {
          echo "installed Linux transport identity set is incomplete; refusing replacement" >&2
          exit 65
        }
        cmp -s "$installed_identity" "$payload_identity" || {
          echo "Linux install may not replace transport identities; use the explicit coordinated identity-rotation path" >&2
          exit 65
        }
      done
    fi
    active_units=()
    if [[ "$root" == "/" ]] && [[ -x "$root/usr/libexec/bloom/bloom-broker" ]]; then
      while IFS= read -r unit; do
        test -n "$unit" && active_units+=("$unit")
      done < <(
        systemctl list-units --state=active --plain --no-legend \
          'bloom-broker@*.service' \
          'bloom-signer@*.service' \
          'bloom-*@*.socket' |
          awk '{print $1}'
      )
      if [[ ${#active_units[@]} -gt 0 ]]; then
        systemctl stop "${active_units[@]}"
      fi
    fi

    binary_root="$root/usr/libexec/bloom"
    mkdir -p "$binary_root"
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      atomic_install "$payload/bin/$binary" "$binary_root/$binary" 0755
    done

    sysusers="$root/usr/lib/sysusers.d/bloom-$login_uid.conf"
    tmpfiles="$root/usr/lib/tmpfiles.d/bloom-$login_uid.conf"
    mkdir -p "$(dirname "$sysusers")" "$(dirname "$tmpfiles")"
    sed \
      -e "s/@LOGIN_UID@/$login_uid/g" \
      -e "s/@LOGIN_USER@/$login_user/g" \
      "$script_dir/linux/sysusers.d/bloom-login.conf.in" > "$sysusers.new"
    chmod 0644 "$sysusers.new"
    mv -f "$sysusers.new" "$sysusers"
    sed -e "s/@LOGIN_UID@/$login_uid/g" \
      "$script_dir/linux/tmpfiles.d/bloom-login.conf.in" > "$tmpfiles.new"
    chmod 0644 "$tmpfiles.new"
    mv -f "$tmpfiles.new" "$tmpfiles"

    unit_root="$root/usr/lib/systemd/system"
    mkdir -p "$unit_root"
    for source in "$script_dir"/linux/systemd/*.socket; do
      atomic_install "$source" "$unit_root/$(basename "$source")" 0644
    done
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

    nts_servers="$payload/config/nts-servers.conf"
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

    config_root="$root/etc/bloom/$login_uid"
    mkdir -p "$config_root/broker" "$config_root/signer"
    chmod 0711 "$config_root"
    chmod 0700 "$config_root/broker" "$config_root/signer"
    atomic_install "$payload/ARTIFACT_CLASS" "$config_root/ARTIFACT_CLASS" 0644
    atomic_install "$payload/config/edge-manifest.json" "$config_root/edge-manifest.json" 0644
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
    atomic_install "$payload/config/broker.json" "$config_root/broker/config.json" 0600
    atomic_install "$payload/config/signer.json" "$config_root/signer/config.json" 0600
    atomic_install \
      "$payload/config/broker-identity.json" \
      "$config_root/broker/identity.json" \
      0600
    atomic_install \
      "$payload/config/signer-identity.json" \
      "$config_root/signer/identity.json" \
      0600
    if [[ "$root" == "/" ]]; then
      systemd-sysusers "$sysusers"
      systemd-tmpfiles --create "$tmpfiles"
      chown "bloom-broker-$login_uid:bloom-broker-$login_uid" \
        "$config_root/broker/config.json" \
        "$config_root/broker/identity.json"
      chown "bloom-signer-$login_uid:bloom-signer-$login_uid" \
        "$config_root/signer/config.json" \
        "$config_root/signer/identity.json"
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
      systemctl enable --now \
        "bloom-signer-rpc@$login_uid.socket" \
        "bloom-signer-control@$login_uid.socket" \
        "bloom-broker-rpc@$login_uid.socket" \
        "bloom-broker-control@$login_uid.socket" \
        "bloom-broker-ceremony@$login_uid.socket"
      if [[ ${#active_units[@]} -gt 0 ]]; then
        systemctl start "${active_units[@]}"
      fi
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
      systemctl stop \
        "bloom-broker@$login_uid.service" \
        "bloom-signer@$login_uid.service"
      systemctl disable --now \
        "bloom-signer-rpc@$login_uid.socket" \
        "bloom-signer-control@$login_uid.socket" \
        "bloom-broker-rpc@$login_uid.socket" \
        "bloom-broker-control@$login_uid.socket" \
        "bloom-broker-ceremony@$login_uid.socket"
    fi
    config_target="$root/etc/bloom/$login_uid"
    state_target="$root/var/lib/bloom/$login_uid"
    run_target="$root/run/bloom/$login_uid"
    rm -rf -- "$config_target" "$state_target" "$run_target"
    rm -f -- \
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
