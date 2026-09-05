#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage:
  install-linux.sh install ROOT LOGIN_UID LOGIN_USER PAYLOAD_DIR
  install-linux.sh uninstall --retain-custody ROOT LOGIN_UID
  install-linux.sh uninstall ROOT LOGIN_UID CONFIRM_TOKEN
EOF
  exit 64
}

[[ $# -ge 1 ]] || usage
action="$1"
shift
payload_scratch=""
enrollment_scratch=""
upgrade_transaction=""
upgrade_transaction_scratch=""
upgrade_rollback_required=false

cleanup_scratch() {
  status=$?
  trap - EXIT
  if [[ "$upgrade_rollback_required" == true ]]; then
    rollback_linux_upgrade || status=$?
  fi
  for scratch_path in "$payload_scratch" "$enrollment_scratch" "$upgrade_transaction_scratch"; do
    if [[ -n "$scratch_path" && -d "$scratch_path" ]]; then
      find "$scratch_path" -depth -delete
    fi
  done
  exit "$status"
}
trap cleanup_scratch EXIT

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

materialize_linux_layout() {
  layout_config="$1"
  layout_uid="$2"

  systemd-tmpfiles --create "$layout_config"
  for required_directory in \
    "/run/bloom/$layout_uid/broker" \
    "/run/bloom/$layout_uid/broker/rpc" \
    "/run/bloom/$layout_uid/broker/control" \
    "/run/bloom/$layout_uid/signer" \
    "/run/bloom/$layout_uid/signer/rpc" \
    "/run/bloom/$layout_uid/signer/control" \
    "/run/bloom/$layout_uid/session" \
    "/var/lib/bloom/$layout_uid/broker" \
    "/var/lib/bloom/$layout_uid/signer" \
    "/var/lib/bloom/$layout_uid/machine"
  do
    if [[ ! -d "$required_directory" || -L "$required_directory" ]]; then
      echo "Linux installation failed to materialize $required_directory" >&2
      return 73
    fi
  done
}

numericize_linux_tmpfiles_ownership() {
  layout_config="$1"
  layout_uid="$2"
  broker_name="bloom-broker-$layout_uid"
  signer_name="bloom-signer-$layout_uid"
  machine_broker_name="bloom-machine-broker-$layout_uid"
  broker_signer_name="bloom-broker-signer-$layout_uid"
  revoke_name="bloom-revoke-$layout_uid"
  session_name="bloom-session-$layout_uid"

  broker_uid="$(id -u "$broker_name")"
  broker_gid="$(id -g "$broker_name")"
  signer_uid="$(id -u "$signer_name")"
  signer_gid="$(id -g "$signer_name")"
  machine_broker_gid="$(getent group "$machine_broker_name" | cut -d: -f3)"
  broker_signer_gid="$(getent group "$broker_signer_name" | cut -d: -f3)"
  revoke_gid="$(getent group "$revoke_name" | cut -d: -f3)"
  session_gid="$(getent group "$session_name" | cut -d: -f3)"
  for numeric_identity in \
    "$broker_uid" "$broker_gid" "$signer_uid" "$signer_gid" \
    "$machine_broker_gid" "$broker_signer_gid" "$revoke_gid" "$session_gid"
  do
    [[ "$numeric_identity" =~ ^[1-9][0-9]*$ ]] || {
      echo "Linux service identity allocation failed" >&2
      return 65
    }
  done

  numeric_config="${layout_config}.numeric.$$"
  awk \
    -v broker_name="$broker_name" \
    -v broker_uid="$broker_uid" \
    -v broker_gid="$broker_gid" \
    -v signer_name="$signer_name" \
    -v signer_uid="$signer_uid" \
    -v signer_gid="$signer_gid" \
    -v machine_broker_name="$machine_broker_name" \
    -v machine_broker_gid="$machine_broker_gid" \
    -v broker_signer_name="$broker_signer_name" \
    -v broker_signer_gid="$broker_signer_gid" \
    -v revoke_name="$revoke_name" \
    -v revoke_gid="$revoke_gid" \
    -v session_name="$session_name" \
    -v session_gid="$session_gid" \
    '{
      if ($4 == broker_name) $4 = broker_uid
      if ($5 == broker_name) $5 = broker_gid
      if ($4 == signer_name) $4 = signer_uid
      if ($5 == signer_name) $5 = signer_gid
      if ($5 == machine_broker_name) $5 = machine_broker_gid
      if ($5 == broker_signer_name) $5 = broker_signer_gid
      if ($5 == revoke_name) $5 = revoke_gid
      if ($5 == session_name) $5 = session_gid
      print
    }' "$layout_config" > "$numeric_config"
  chmod 0644 "$numeric_config"
  mv -f "$numeric_config" "$layout_config"
}

fstab_escape_path() {
  local value="$1"
  value="${value//\\/\\134}"
  value="${value// /\\040}"
  value="${value//$'\t'/\\011}"
  printf '%s' "$value"
}

preserve_file_mode() {
  local source="$1"
  local destination="$2"
  local mode

  if chmod --reference="$source" "$destination" 2>/dev/null; then
    return 0
  fi
  if mode="$(stat -f '%Lp' "$source" 2>/dev/null)"; then
    chmod "$mode" "$destination"
    return 0
  fi
  if mode="$(stat -c '%a' "$source" 2>/dev/null)"; then
    chmod "$mode" "$destination"
    return 0
  fi
  echo "unable to preserve file mode for $source" >&2
  return 69
}

numeric_file_uid() {
  if [[ "$(uname -s)" == Darwin ]]; then
    stat -f '%u' "$1"
  else
    stat -c '%u' "$1"
  fi
}

numeric_file_mode() {
  if [[ "$(uname -s)" == Darwin ]]; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

install_linux_mount_authorization() {
  local install_root="$1"
  local mount_uid="$2"
  local mount_gid="$3"
  local login_home="$4"
  local nfs_port="$5"
  local fstab="$install_root/etc/fstab"
  local marker="x-bloom.login-uid=$mount_uid"
  local mount_path="${login_home%/}/bloom"
  local rooted_mount_path="${install_root%/}$mount_path"
  local escaped_mount_path
  local replacement

  [[ "$login_home" == /* && "$login_home" != "/" && \
    "$login_home" != *$'\n'* && "$login_home" != *$'\r'* ]] || {
    echo "LOGIN_USER home is not a safe absolute path" >&2
    return 65
  }
  if [[ -L "$rooted_mount_path" || \
    ( -e "$rooted_mount_path" && ! -d "$rooted_mount_path" ) ]]
  then
    echo "Bloom mount path is not a real directory: $mount_path" >&2
    return 65
  fi
  mkdir -p "$rooted_mount_path"
  # The fstab `user` option delegates this one mount entry to an unprivileged
  # caller. Keep the target private so only the enrolled login can traverse it.
  chmod 0700 "$rooted_mount_path"
  if [[ "$install_root" == "/" ]]; then
    chown "$mount_uid:$mount_gid" "$rooted_mount_path"
  fi

  [[ ! -L "$fstab" && ( ! -e "$fstab" || -f "$fstab" ) ]] || {
    echo "Linux fstab is missing, substituted, or not a regular file" >&2
    return 65
  }
  mkdir -p "$(dirname "$fstab")"
  replacement="${fstab}.new.$$"
  if [[ -f "$fstab" ]]; then
    awk -v marker="$marker" \
      'length($0) < length(marker) || substr($0, length($0) - length(marker) + 1) != marker { print }' \
      "$fstab" > "$replacement"
    preserve_file_mode "$fstab" "$replacement"
  else
    : > "$replacement"
    chmod 0644 "$replacement"
  fi
  escaped_mount_path="$(fstab_escape_path "$mount_path")"
  [[ "$nfs_port" =~ ^[0-9]+$ ]] && ((nfs_port >= 20000 && nfs_port <= 60999)) || {
    echo "Bloom NFS port is outside the enrolled range" >&2
    return 65
  }
  printf '127.0.0.1:/ %s nfs4 noauto,user,nosuid,nodev,noexec,actimeo=0,vers=4.1,proto=tcp,port=%s,rsize=65536,wsize=65536,timeo=10 0 0 # %s\n' \
    "$escaped_mount_path" "$nfs_port" "$marker" >> "$replacement"
  mv -f "$replacement" "$fstab"
}

linux_record_string() {
  local record="$1"
  local key="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$record"
}

linux_record_number() {
  local record="$1"
  local key="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p" "$record"
}

linux_nfs_port_is_listening() {
  local candidate="$1"
  local table port_hex
  port_hex="$(printf '%04X' "$candidate")"
  for table in /proc/net/tcp /proc/net/tcp6; do
    [[ -r "$table" ]] || continue
    if awk -v port="$port_hex" '
      NR > 1 {
        split($2, address, ":")
        if (toupper(address[2]) == port && $4 == "0A") found = 1
      }
      END { exit found ? 0 : 1 }
    ' "$table"
    then
      return 0
    fi
  done
  return 1
}

write_linux_record() {
  local record="$1" state="$2" uid="$3" user="$4" digest="$5" port="$6"
  local replacement="${record}.new.$$"

  printf '{"schema":"bloom.linux-enrollment.1","state":"%s","login_uid":%s,"login_user":"%s","release_digest":"%s","nfs_port":%s}\n' \
    "$state" "$uid" "$user" "$digest" "$port" > "$replacement"
  chmod 0644 "$replacement"
  mv -f "$replacement" "$record"
}

rewrite_linux_fstab_port() {
  local install_root="$1" uid="$2" port="$3"
  local fstab="$install_root/etc/fstab" marker="x-bloom.login-uid=$uid"
  local replacement

  [[ -e "$fstab" ]] || return 0
  [[ -f "$fstab" && ! -L "$fstab" ]] || {
    echo "Linux fstab is substituted or not a regular file" >&2
    return 65
  }
  replacement="${fstab}.new.$$"
  awk -v marker="$marker" -v port="$port" '
    {
      if (length($0) >= length(marker) &&
          substr($0, length($0) - length(marker) + 1) == marker) {
        sub(/port=[0-9]+/, "port=" port)
      }
      print
    }
  ' "$fstab" > "$replacement"
  preserve_file_mode "$fstab" "$replacement"
  mv -f "$replacement" "$fstab"
}

migrate_legacy_linux_records() {
  local install_root="$1" directory record uid state user digest port candidate
  local other other_port used machine_environment

  for directory in enrollments retained; do
    for record in "$install_root/etc/bloom/$directory"/*.json; do
      [[ -e "$record" || -L "$record" ]] || continue
      [[ -f "$record" && ! -L "$record" ]] || {
        echo "installed Linux enrollment record is unsafe" >&2
        return 65
      }
      port="$(linux_record_number "$record" nfs_port)"
      [[ -z "$port" ]] || continue
      uid="$(linux_record_number "$record" login_uid)"
      state="$(linux_record_string "$record" state)"
      user="$(linux_record_string "$record" login_user)"
      digest="$(linux_record_string "$record" release_digest)"
      [[ "$(linux_record_string "$record" schema)" == bloom.linux-enrollment.1 && \
        "$uid" =~ ^[1-9][0-9]*$ && "$user" =~ ^[a-z_][a-z0-9_-]*$ && \
        "$digest" =~ ^[0-9a-f]{64}$ && \
        ( "$state" == active || "$state" == retained ) ]] || {
        echo "installed Linux enrollment record is malformed" >&2
        return 65
      }
      port=""
      for ((candidate = 20000; candidate <= 60999; candidate++)); do
        used=false
        for other in \
          "$install_root/etc/bloom/enrollments"/*.json \
          "$install_root/etc/bloom/retained"/*.json
        do
          [[ -f "$other" && ! -L "$other" ]] || continue
          other_port="$(linux_record_number "$other" nfs_port)"
          if [[ "$other_port" == "$candidate" ]]; then
            used=true
            break
          fi
        done
        if [[ "$used" == false ]]; then
          port="$candidate"
          break
        fi
      done
      [[ -n "$port" ]] || {
        echo "no per-login Bloom NFS port is available" >&2
        return 69
      }
      write_linux_record "$record" "$state" "$uid" "$user" "$digest" "$port"
      rewrite_linux_fstab_port "$install_root" "$uid" "$port"
      if [[ -d "$install_root/etc/bloom/$uid" && \
        ! -L "$install_root/etc/bloom/$uid" ]]
      then
        machine_environment="$install_root/etc/bloom/$uid/.machine-env.source.$$"
        printf 'BLOOM_NFS_LISTEN=127.0.0.1:%s\nBLOOM_RELEASE_DIGEST=%s\n' \
          "$port" "$digest" > "$machine_environment"
        atomic_install \
          "$machine_environment" \
          "$install_root/etc/bloom/$uid/machine.env" \
          0644
        rm -f -- "$machine_environment"
      fi
    done
  done
}

validated_release_digest=""

validate_linux_release_set() {
  local install_root="$1"
  local directory record filename_uid record_uid record_state record_digest record_port counterpart
  local principal service_config service_digest prior_uid owner
  local port_owners=""

  validated_release_digest=""

  for directory in enrollments retained; do
    for record in "$install_root/etc/bloom/$directory"/*.json; do
      [[ -e "$record" || -L "$record" ]] || continue
      [[ -f "$record" && ! -L "$record" ]] || {
        echo "installed Linux enrollment record is unsafe" >&2
        return 65
      }
      filename_uid="${record##*/}"
      filename_uid="${filename_uid%.json}"
      record_uid="$(linux_record_number "$record" login_uid)"
      record_state="$(linux_record_string "$record" state)"
      record_digest="$(linux_record_string "$record" release_digest)"
      record_port="$(linux_record_number "$record" nfs_port)"
      [[ "$(linux_record_string "$record" schema)" == bloom.linux-enrollment.1 && \
        "$record_uid" == "$filename_uid" && "$record_uid" =~ ^[1-9][0-9]*$ && \
        "$record_digest" =~ ^[0-9a-f]{64}$ && \
        "$record_port" =~ ^[0-9]+$ ]] || {
        echo "installed Linux enrollment record is malformed" >&2
        return 65
      }
      if [[ "$directory" == enrollments ]]; then
        [[ "$record_state" == active ]] || {
          echo "installed Linux enrollment is not active" >&2
          return 65
        }
      else
        [[ "$record_state" == retained ]] || {
          echo "retained Linux enrollment record is invalid" >&2
          return 65
        }
      fi
      ((record_port >= 20000 && record_port <= 60999)) || {
        echo "installed Linux enrollment NFS port is invalid" >&2
        return 65
      }
      prior_uid=""
      for owner in $port_owners; do
        [[ "$owner" != "$record_port:"* ]] || prior_uid="${owner#*:}"
      done
      [[ -z "$prior_uid" || "$prior_uid" == "$record_uid" ]] || {
        echo "installed Linux enrollments reuse an NFS port" >&2
        return 65
      }
      port_owners="$port_owners $record_port:$record_uid"
      if [[ -z "$validated_release_digest" ]]; then
        validated_release_digest="$record_digest"
      fi
      [[ "$record_digest" == "$validated_release_digest" ]] || {
        echo "installed Linux enrollments use different releases" >&2
        return 65
      }
      for principal in broker signer; do
        service_config="$install_root/etc/bloom/$record_uid/$principal/config.json"
        [[ -f "$service_config" && ! -L "$service_config" ]] || {
          echo "installed Linux enrollment is incomplete; refusing replacement" >&2
          return 65
        }
        service_digest="$(linux_record_string "$service_config" build_digest)"
        [[ "$service_digest" == "$record_digest" ]] || {
          echo "installed Linux service build digest is inconsistent" >&2
          return 65
        }
      done
      counterpart=retained
      [[ "$directory" == retained ]] && counterpart=enrollments
      [[ ! -e "$install_root/etc/bloom/$counterpart/$filename_uid.json" && \
        ! -L "$install_root/etc/bloom/$counterpart/$filename_uid.json" ]] || {
        echo "Linux login has both active and retained enrollment records" >&2
        return 65
      }
    done
  done
}

replace_linux_json_digest() {
  local config="$1" digest="$2" replacement
  replacement="${config}.new.$$"

  [[ -f "$config" && ! -L "$config" ]] || {
    echo "installed Linux service configuration is missing or unsafe" >&2
    return 65
  }
  awk -v digest="$digest" '
    BEGIN { changed = 0 }
    {
      if ($0 ~ /"build_digest"[[:space:]]*:[[:space:]]*"[0-9a-f]+"/) {
        sub(/"build_digest"[[:space:]]*:[[:space:]]*"[0-9a-f]+"/,
            "\"build_digest\":\"" digest "\"")
        changed++
      }
      print
    }
    END { if (changed != 1) exit 65 }
  ' "$config" > "$replacement" || {
    rm -f -- "$replacement"
    echo "installed Linux service build digest cannot be updated" >&2
    return 65
  }
  preserve_file_mode "$config" "$replacement"
  chown --reference="$config" "$replacement" 2>/dev/null || true
  mv -f "$replacement" "$config"
}

rewrite_linux_release_set() {
  local install_root="$1" digest="$2" active_state="$3"
  local directory record uid state user port principal machine_environment

  for directory in enrollments retained; do
    for record in "$install_root/etc/bloom/$directory"/*.json; do
      [[ -f "$record" && ! -L "$record" ]] || continue
      uid="$(linux_record_number "$record" login_uid)"
      state="$(linux_record_string "$record" state)"
      user="$(linux_record_string "$record" login_user)"
      port="$(linux_record_number "$record" nfs_port)"
      for principal in broker signer; do
        replace_linux_json_digest \
          "$install_root/etc/bloom/$uid/$principal/config.json" \
          "$digest"
      done
      machine_environment="$install_root/etc/bloom/$uid/.machine-env.source.$$"
      printf 'BLOOM_NFS_LISTEN=127.0.0.1:%s\nBLOOM_RELEASE_DIGEST=%s\n' \
        "$port" "$digest" > "$machine_environment"
      atomic_install \
        "$machine_environment" \
        "$install_root/etc/bloom/$uid/machine.env" \
        0644
      rm -f -- "$machine_environment"
      if [[ "$directory" == enrollments ]]; then
        state="$active_state"
      else
        state=retained
      fi
      write_linux_record "$record" "$state" "$uid" "$user" "$digest" "$port"
    done
  done
}

install_linux_release() {
  local install_root="$1" payload="$2" digest="$3"
  local release_base="$install_root/usr/libexec/bloom"
  local release="$release_base/releases/$digest" stage binary

  mkdir -p "$release_base/releases"
  if [[ -e "$release" || -L "$release" ]]; then
    [[ -d "$release" && ! -L "$release" ]] || {
      echo "installed Linux release is unsafe" >&2
      return 65
    }
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      [[ -f "$release/$binary" && ! -L "$release/$binary" ]] && \
        cmp -s "$payload/bin/$binary" "$release/$binary" || {
          echo "installed Linux release does not match signed payload" >&2
          return 65
        }
    done
    return 0
  fi
  stage="$release_base/.release.$$.new"
  mkdir "$stage"
  for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
    install -m 0755 "$payload/bin/$binary" "$stage/$binary"
  done
  mv "$stage" "$release"
}

capture_legacy_linux_release() {
  local install_root="$1" digest="$2"
  local release_base="$install_root/usr/libexec/bloom"
  local release="$release_base/releases/$digest" stage binary target

  [[ -n "$digest" ]] || return 0
  if [[ -e "$release_base/current" || -L "$release_base/current" ]]; then
    [[ -L "$release_base/current" ]] || {
      echo "installed Linux current release is unsafe" >&2
      return 65
    }
    target="$(readlink "$release_base/current")"
    [[ "$target" == "releases/$digest" && \
      -d "$release_base/$target" && ! -L "$release_base/$target" ]] || {
      echo "installed Linux current release is inconsistent" >&2
      return 65
    }
    return 0
  fi
  [[ ! -e "$release" && ! -L "$release" ]] || return 0
  stage="$release_base/.legacy.$$.new"
  mkdir -p "$stage"
  for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
    [[ -f "$release_base/$binary" && ! -L "$release_base/$binary" ]] || {
      rm -rf -- "$stage"
      echo "legacy Linux release is incomplete" >&2
      return 65
    }
    install -m 0755 "$release_base/$binary" "$stage/$binary"
  done
  mkdir -p "$release_base/releases"
  mv "$stage" "$release"
}

switch_linux_release() {
  local install_root="$1" digest="$2"
  local release_base="$install_root/usr/libexec/bloom"
  local replacement="$release_base/current.new.$$"

  [[ -d "$release_base/releases/$digest" && \
    ! -L "$release_base/releases/$digest" ]] || {
    echo "Linux release switch target is missing" >&2
    return 65
  }
  ln -s "releases/$digest" "$replacement"
  mv -fT "$replacement" "$release_base/current"
}

stop_linux_release_set() {
  local install_root="$1" record uid user user_runtime
  [[ "$install_root" == "/" ]] || return 0

  for record in "$install_root/etc/bloom/enrollments"/*.json; do
    [[ -f "$record" && ! -L "$record" ]] || continue
    uid="$(linux_record_number "$record" login_uid)"
    user="$(linux_record_string "$record" login_user)"
    user_runtime="/run/user/$uid"
    if [[ -S "$user_runtime/bus" ]]; then
      runuser -u "$user" -- env \
        XDG_RUNTIME_DIR="$user_runtime" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
        systemctl --user stop bloom-machine.service bloom-session.service \
        2>/dev/null || true
    fi
    systemctl stop "bloom-session@$uid.path" 2>/dev/null || true
    systemctl stop "bloom-broker-ceremony@$uid.socket" 2>/dev/null || true
    systemctl stop "bloom-broker@$uid.service"
    systemctl stop "bloom-signer@$uid.service"
  done
}

preflight_linux_release_set() {
  local install_root="$1" record uid user_runtime
  [[ "$install_root" == "/" ]] || return 0

  for record in "$install_root/etc/bloom/enrollments"/*.json; do
    [[ -f "$record" && ! -L "$record" ]] || continue
    uid="$(linux_record_number "$record" login_uid)"
    user_runtime="/run/user/$uid"
    [[ -d "$user_runtime" && -S "$user_runtime/bus" ]] || {
      echo "Linux release upgrade requires an active session for enrolled UID $uid" >&2
      return 69
    }
  done
}

linux_release_units_active() {
  local uid="$1" user="$2" user_runtime="$3" unit
  for unit in \
    "bloom-session@$uid.path" \
    "bloom-broker@$uid.service" \
    "bloom-signer@$uid.service"
  do
    systemctl is-active --quiet "$unit" || return 1
  done
  for unit in bloom-session.service bloom-machine.service; do
    runuser -u "$user" -- env \
      XDG_RUNTIME_DIR="$user_runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
      systemctl --user is-active --quiet "$unit" || return 1
  done
}

require_linux_triad_health() {
  local install_root="$1" uid="$2" user="$3" digest="$4"
  local user_runtime="/run/user/$uid" home attempt
  home="$(getent passwd "$uid" | cut -d: -f6)"
  [[ "$home" == /* && "$home" != "/" ]] || {
    echo "cannot resolve home for $user" >&2
    return 1
  }
  for ((attempt = 0; attempt < 20; attempt++)); do
    if linux_release_units_active "$uid" "$user" "$user_runtime" &&
      runuser -u "$user" -- env \
        XDG_RUNTIME_DIR="$user_runtime" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
        "$install_root/usr/bin/bloom" --home "$home/.bloom" \
          serve triad-health-check "$digest" >/dev/null 2>&1
    then
      return 0
    fi
    sleep 0.5
  done
  echo "Bloom Linux release failed authenticated activation for UID $uid" >&2
  systemctl is-active \
    "bloom-session@$uid.path" \
    "bloom-broker@$uid.service" \
    "bloom-signer@$uid.service" >&2 || true
  runuser -u "$user" -- env \
    XDG_RUNTIME_DIR="$user_runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
    systemctl --user is-active \
      bloom-session.service bloom-machine.service >&2 || true
  runuser -u "$user" -- env \
    XDG_RUNTIME_DIR="$user_runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
    "$install_root/usr/bin/bloom" --home "$home/.bloom" \
      serve triad-health-check "$digest"
}

start_linux_release_set() {
  local install_root="$1" record uid user digest user_runtime
  [[ "$install_root" == "/" ]] || return 0

  systemctl daemon-reload
  for record in "$install_root/etc/bloom/enrollments"/*.json; do
    [[ -f "$record" && ! -L "$record" ]] || continue
    uid="$(linux_record_number "$record" login_uid)"
    user="$(linux_record_string "$record" login_user)"
    digest="$(linux_record_string "$record" release_digest)"
    user_runtime="/run/user/$uid"
    systemctl enable --now "bloom-session@$uid.path"
    if [[ -S "$user_runtime/bus" ]]; then
      runuser -u "$user" -- env \
        XDG_RUNTIME_DIR="$user_runtime" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
        systemctl --user daemon-reload
      runuser -u "$user" -- env \
        XDG_RUNTIME_DIR="$user_runtime" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
        systemctl --user start bloom-session.service bloom-machine.service
    fi
    require_linux_triad_health "$install_root" "$uid" "$user" "$digest"
  done
}

upgrade_root=""
upgrade_old_digest=""

begin_linux_upgrade() {
  local install_root="$1" old_digest="$2" new_digest="$3"
  local transaction_root="$install_root/var/lib/bloom"
  mkdir -p "$transaction_root"
  [[ -d "$transaction_root" && ! -L "$transaction_root" ]] || {
    echo "Linux upgrade transaction root is unsafe" >&2
    return 65
  }
  upgrade_transaction="$transaction_root/upgrade-transaction"
  [[ ! -e "$upgrade_transaction" && ! -L "$upgrade_transaction" ]] || {
    echo "an interrupted Linux upgrade must be recovered first" >&2
    return 65
  }
  upgrade_transaction_scratch="${upgrade_transaction}.new.$$"
  mkdir -m 0700 "$upgrade_transaction_scratch"
  printf '%s\n' bloom.linux-upgrade-transaction.1 > "$upgrade_transaction_scratch/schema"
  printf '%s\n' "$old_digest" > "$upgrade_transaction_scratch/old-digest"
  printf '%s\n' "$new_digest" > "$upgrade_transaction_scratch/new-digest"
  chmod 0600 "$upgrade_transaction_scratch"/*
  sync
  mv -T "$upgrade_transaction_scratch" "$upgrade_transaction"
  upgrade_transaction_scratch=""
  sync
  upgrade_root="$install_root"
  upgrade_old_digest="$old_digest"
  upgrade_rollback_required=true
}

rollback_linux_upgrade() {
  local rollback_status=0
  [[ -n "$upgrade_root" && -n "$upgrade_old_digest" ]] || return 0
  stop_linux_release_set "$upgrade_root" || rollback_status=$?
  switch_linux_release "$upgrade_root" "$upgrade_old_digest" || rollback_status=$?
  rewrite_linux_release_set "$upgrade_root" "$upgrade_old_digest" active || rollback_status=$?
  start_linux_release_set "$upgrade_root" || rollback_status=$?
  if ((rollback_status == 0)); then
    rm -rf -- "$upgrade_transaction"
    upgrade_rollback_required=false
  fi
  return "$rollback_status"
}

finish_linux_upgrade() {
  rm -rf -- "$upgrade_transaction"
  upgrade_rollback_required=false
  upgrade_transaction=""
  upgrade_root=""
  upgrade_old_digest=""
}

recover_interrupted_linux_upgrade() {
  local install_root="$1" requested_digest="$2"
  local transaction="$install_root/var/lib/bloom/upgrade-transaction"
  local schema old_digest new_digest

  [[ -e "$transaction" || -L "$transaction" ]] || return 0
  [[ -d "$transaction" && ! -L "$transaction" ]] || {
    echo "invalid interrupted Linux upgrade" >&2
    return 65
  }
  schema="$(<"$transaction/schema")"
  old_digest="$(<"$transaction/old-digest")"
  new_digest="$(<"$transaction/new-digest")"
  [[ "$schema" == bloom.linux-upgrade-transaction.1 && \
    "$old_digest" =~ ^[0-9a-f]{64}$ && \
    "$new_digest" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid interrupted Linux upgrade" >&2
    return 65
  }
  preflight_linux_release_set "$install_root"
  upgrade_transaction="$transaction"
  upgrade_root="$install_root"
  upgrade_old_digest="$old_digest"
  upgrade_rollback_required=true
  if [[ "$new_digest" == "$requested_digest" ]]; then
    echo "completing interrupted Bloom Linux upgrade" >&2
    switch_linux_release "$install_root" "$new_digest"
    rewrite_linux_release_set "$install_root" "$new_digest" active
    start_linux_release_set "$install_root"
    finish_linux_upgrade
  else
    echo "rolling back interrupted Bloom Linux upgrade" >&2
    rollback_linux_upgrade
  fi
}

allocate_linux_nfs_port() {
  local install_root="$1"
  local selected_uid="$2"
  local record record_uid record_port candidate used

  for record in \
    "$install_root/etc/bloom/enrollments/$selected_uid.json" \
    "$install_root/etc/bloom/retained/$selected_uid.json"
  do
    if [[ -f "$record" && ! -L "$record" ]]; then
      linux_record_number "$record" nfs_port
      return 0
    fi
  done
  for ((candidate = 20000; candidate <= 60999; candidate++)); do
    used=false
    for record in \
      "$install_root/etc/bloom/enrollments"/*.json \
      "$install_root/etc/bloom/retained"/*.json
    do
      [[ -f "$record" && ! -L "$record" ]] || continue
      record_uid="$(linux_record_number "$record" login_uid)"
      record_port="$(linux_record_number "$record" nfs_port)"
      if [[ "$record_uid" != "$selected_uid" && "$record_port" == "$candidate" ]]; then
        used=true
        break
      fi
    done
    if [[ "$used" == false ]] && ! linux_nfs_port_is_listening "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "no per-login Bloom NFS port is available" >&2
  return 69
}

remove_linux_mount_authorization() {
  local install_root="$1"
  local mount_uid="$2"
  local fstab="$install_root/etc/fstab"
  local marker="x-bloom.login-uid=$mount_uid"
  local replacement

  [[ -e "$fstab" ]] || return 0
  [[ -f "$fstab" && ! -L "$fstab" ]] || {
    echo "Linux fstab is substituted or not a regular file" >&2
    return 65
  }
  replacement="${fstab}.new.$$"
  awk -v marker="$marker" \
    'length($0) < length(marker) || substr($0, length($0) - length(marker) + 1) != marker { print }' \
    "$fstab" > "$replacement"
  preserve_file_mode "$fstab" "$replacement"
  mv -f "$replacement" "$fstab"
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

verify_sha256_manifest() {
  manifest="$1"
  manifest_dir="$(dirname "$manifest")"
  manifest_name="$(basename "$manifest")"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$manifest_dir" && sha256sum -c "$manifest_name" >/dev/null)
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$manifest_dir" && shasum -a 256 -c "$manifest_name" >/dev/null)
  else
    echo "Linux installation requires sha256sum or shasum" >&2
    return 69
  fi
}

manifest_authenticates_path() {
  awk -v wanted="$2" '
    $2 == wanted || $2 == "*" wanted { found = 1 }
    END { exit !found }
  ' "$1"
}

verify_release_payload() {
  payload_to_verify="$1"
  expected_pin_uid="$2"
  for signed_path in SHA256SUMS RELEASE_PUBLIC_KEY.pem RELEASE_SIGNATURE; do
    [[ -f "$payload_to_verify/$signed_path" && \
      ! -L "$payload_to_verify/$signed_path" ]] || {
      echo "payload is missing authenticated $signed_path" >&2
      return 65
    }
  done

  pinned_key="${BLOOM_RELEASE_PUBLIC_KEY:-}"
  [[ -f "$pinned_key" && ! -L "$pinned_key" ]] || {
    echo "BLOOM_RELEASE_PUBLIC_KEY must name a separately installed public key" >&2
    return 65
  }
  [[ "$(numeric_file_uid "$pinned_key")" == "$expected_pin_uid" ]] || {
    echo "pinned release key has the wrong owner" >&2
    return 65
  }
  pinned_mode="$(numeric_file_mode "$pinned_key")"
  [[ "$pinned_mode" =~ ^[0-7]{3,4}$ ]] && \
    (( (8#$pinned_mode & 022) == 0 )) || {
    echo "pinned release key must not be group or world writable" >&2
    return 65
  }
  cmp -s "$pinned_key" "$payload_to_verify/RELEASE_PUBLIC_KEY.pem" || {
    echo "payload release key does not match the pinned key" >&2
    return 65
  }
  read -r key_type key_body key_extra < "$pinned_key"
  [[ "$key_type" == ssh-ed25519 && -n "$key_body" && -z "${key_extra:-}" ]] || {
    echo "pinned release key is not a bare ssh-ed25519 public key" >&2
    return 65
  }
  command -v ssh-keygen >/dev/null 2>&1 || {
    echo "Linux installation requires the system ssh-keygen verifier" >&2
    return 69
  }

  allowed_signers="$(mktemp)"
  chmod 0600 "$allowed_signers"
  printf 'bloom-release %s %s\n' "$key_type" "$key_body" > "$allowed_signers"
  if ! ssh-keygen -Y verify \
    -f "$allowed_signers" \
    -I bloom-release \
    -n bloom-release-payload-v1 \
    -s "$payload_to_verify/RELEASE_SIGNATURE" \
    < "$payload_to_verify/SHA256SUMS" >/dev/null
  then
    rm -f -- "$allowed_signers"
    echo "payload release signature is invalid" >&2
    return 65
  fi
  rm -f -- "$allowed_signers"
  verify_sha256_manifest "$payload_to_verify/SHA256SUMS" || {
    echo "payload file authentication failed" >&2
    return 65
  }
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
    payload_authenticated=false
    if [[ "$root" == "/" ]]; then
      payload_scratch="$(mktemp -d /var/tmp/bloom-linux-payload.XXXXXX)"
      chmod 0700 "$payload_scratch"
      cp -R -- "$payload/." "$payload_scratch/"
      if find "$payload_scratch" \
        \( -type l -o \( ! -type f ! -type d \) \) -print -quit | grep -q .
      then
        echo "payload contains a symlink or non-regular entry" >&2
        exit 65
      fi
      chown -R 0:0 "$payload_scratch"
      payload="$payload_scratch"
      verify_release_payload "$payload" 0
      payload_authenticated=true
    elif [[ "${BLOOM_TEST_VERIFY_RELEASE_PAYLOAD:-}" == "true" ]]; then
      pin_owner_uid=0
      pin_owner_uid="$(id -u)"
      verify_release_payload "$payload" "$pin_owner_uid"
      payload_authenticated=true
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
    login_gid="$login_uid"
    login_home="/home/$login_user"
    if [[ "$root" == "/" ]]; then
      actual_login_uid="$(id -u -- "$login_user" 2>/dev/null)" || {
        echo "LOGIN_USER does not resolve to a local account" >&2
        exit 65
      }
      [[ "$actual_login_uid" == "$login_uid" ]] || {
        echo "LOGIN_USER does not match LOGIN_UID" >&2
        exit 65
      }
      login_gid="$(id -g -- "$login_user" 2>/dev/null)" || {
        echo "LOGIN_USER primary group cannot be resolved" >&2
        exit 65
      }
      [[ "$login_gid" =~ ^[0-9]+$ ]] || {
        echo "LOGIN_USER primary GID is invalid" >&2
        exit 65
      }
      login_home="$(getent passwd "$login_uid" | cut -d: -f6)"
    fi
    [[ "$login_home" == /* && "$login_home" != "/" && \
      "$login_home" != *$'\n'* && "$login_home" != *$'\r'* ]] || {
      echo "LOGIN_USER home is not a safe absolute path" >&2
      exit 65
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
      installer/linux/bin/bloom \
      installer/linux/bin/bloom-uninstall \
      installer/linux/sysusers.d/bloom-login.conf.in \
      installer/linux/tmpfiles.d/bloom-login.conf.in \
      installer/linux/systemd/bloom-broker-ceremony@.socket \
      installer/linux/systemd/bloom-session@.path \
      installer/linux/systemd/bloom-broker@.service.in \
      installer/linux/systemd/bloom-signer@.service.in \
      installer/linux/systemd/instance-dropins/bloom-signer@LOGIN_UID.service.d/50-aws-kms.conf.in \
      installer/linux/systemd-user/bloom-session.service \
      installer/linux/systemd-user/bloom-machine.service \
      installer/release/install-linux.sh
    do
      [[ -f "$payload/$required" && ! -L "$payload/$required" ]] || {
        echo "payload is missing $required" >&2
        exit 66
      }
    done
    if $payload_authenticated &&
      [[ -e "$payload/credentials/aws-credentials" || \
        -e "$payload/config/aws-kms-ip-allow.conf" ]]
    then
      for overlay_path in \
        ./credentials/aws-credentials \
        ./config/aws-kms-ip-allow.conf
      do
        manifest_authenticates_path "$payload/SHA256SUMS" "$overlay_path" || {
          echo "optional signer overlay is not authenticated: $overlay_path" >&2
          exit 65
        }
      done
    fi
    release_digest="$(sha256_digest "$payload/SHA256SUMS")"
    [[ "$release_digest" =~ ^[0-9a-f]{64}$ ]] || {
      echo "signed payload release digest is invalid" >&2
      exit 65
    }
    recover_interrupted_linux_upgrade "$root" "$release_digest"
    migrate_legacy_linux_records "$root"
    validate_linux_release_set "$root"
    shared_release_digest="$validated_release_digest"
    release_upgrade=false
    if [[ -n "$shared_release_digest" && \
      "$shared_release_digest" != "$release_digest" ]]
    then
      [[ -f "$root/etc/bloom/enrollments/$login_uid.json" && \
        ! -L "$root/etc/bloom/enrollments/$login_uid.json" ]] || {
        echo "a different Linux release must be installed through an active enrollment" >&2
        exit 65
      }
      release_upgrade=true
    fi
    if [[ "$release_upgrade" == true ]]; then
      preflight_linux_release_set "$root"
    fi
    capture_legacy_linux_release "$root" "$shared_release_digest"
    install_linux_release "$root" "$payload" "$release_digest"
    if [[ "$release_upgrade" == true ]]; then
      begin_linux_upgrade "$root" "$shared_release_digest" "$release_digest"
      stop_linux_release_set "$root"
      rewrite_linux_release_set "$root" "$release_digest" activating
      switch_linux_release "$root" "$release_digest"
    else
      switch_linux_release "$root" "$release_digest"
    fi
    nfs_port="$(allocate_linux_nfs_port "$root" "$login_uid")"
    installed_config_root="$root/etc/bloom/$login_uid"
    installed_state_root="$root/var/lib/bloom/$login_uid"
    fresh_install=true
    if [[ -e "$installed_config_root/edge-manifest.json" || \
      -L "$installed_config_root/edge-manifest.json" ]]
    then
      fresh_install=false
      for installed_relative in \
        edge-manifest.json \
        broker/config.json \
        broker/identity.json \
        signer/config.json \
        signer/identity.json \
        machine/identity.json \
        machine/revoke-identity.json \
        session/identity.json \
        installer-identity.json \
        provenance-catalog.json \
        machine.env
      do
        [[ -f "$installed_config_root/$installed_relative" && \
          ! -L "$installed_config_root/$installed_relative" ]] || {
          echo "installed Linux enrollment is incomplete; refusing replacement" >&2
          exit 65
        }
      done
    elif [[ -e "$installed_config_root" || -L "$installed_config_root" || \
      -e "$installed_state_root" || -L "$installed_state_root" ]]
    then
      echo "residual Linux enrollment state exists without a manifest; refusing fresh installation" >&2
      exit 65
    fi
    if [[ "$root" == "/" && -S "/run/user/$login_uid/bus" ]]; then
      runuser -u "$login_user" -- env \
        XDG_RUNTIME_DIR="/run/user/$login_uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$login_uid/bus" \
        systemctl --user stop bloom-machine.service 2>/dev/null || true
    fi
    if [[ "$fresh_install" == false && "$release_upgrade" == false && "$root" == "/" ]] && \
      [[ -x "$root/usr/libexec/bloom/current/bloom-broker" ]]
    then
      systemctl stop "bloom-session@$login_uid.path" 2>/dev/null || true
      systemctl stop "bloom-broker-ceremony@$login_uid.socket" 2>/dev/null || true
      systemctl stop "bloom-broker@$login_uid.service"
      systemctl stop "bloom-signer@$login_uid.service"
    fi

    binary_root="$root/usr/libexec/bloom/current"
    atomic_install "$payload/installer/linux/bin/bloom" "$root/usr/bin/bloom" 0755
    atomic_install \
      "$payload/installer/linux/bin/bloom-uninstall" \
      "$root/usr/bin/bloom-uninstall" \
      0755
    atomic_install \
      "$payload/installer/release/install-linux.sh" \
      "$root/usr/libexec/bloom/bloom-linux-maintenance" \
      0755

    sysusers="$root/usr/lib/sysusers.d/bloom-$login_uid.conf"
    tmpfiles="$root/usr/lib/tmpfiles.d/bloom-$login_uid.conf"
    mkdir -p "$(dirname "$sysusers")" "$(dirname "$tmpfiles")"
    sed \
      -e "s/@LOGIN_UID@/$login_uid/g" \
      -e "s/@LOGIN_USER@/$login_user/g" \
      "$payload/installer/linux/sysusers.d/bloom-login.conf.in" > "$sysusers.new"
    chmod 0644 "$sysusers.new"
    mv -f "$sysusers.new" "$sysusers"
    sed \
      -e "s/@LOGIN_UID@/$login_uid/g" \
      -e "s/@LOGIN_GID@/$login_gid/g" \
      "$payload/installer/linux/tmpfiles.d/bloom-login.conf.in" > "$tmpfiles.new"
    chmod 0644 "$tmpfiles.new"
    mv -f "$tmpfiles.new" "$tmpfiles"

    unit_root="$root/usr/lib/systemd/system"
    mkdir -p "$unit_root"
    atomic_install \
      "$payload/installer/linux/systemd/bloom-broker-ceremony@.socket" \
      "$unit_root/bloom-broker-ceremony@.socket" \
      0644
    atomic_install \
      "$payload/installer/linux/systemd/bloom-session@.path" \
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
    atomic_install \
      "$payload/installer/linux/systemd-user/bloom-machine.service" \
      "$user_unit_root/bloom-machine.service" \
      0644
    sed \
      -e "s|@BLOOM_BROKER_BINARY@|/usr/libexec/bloom/current/bloom-broker|g" \
      "$payload/installer/linux/systemd/bloom-broker@.service.in" \
      > "$unit_root/bloom-broker@.service.new"
    chmod 0644 "$unit_root/bloom-broker@.service.new"
    mv -f "$unit_root/bloom-broker@.service.new" "$unit_root/bloom-broker@.service"
    sed \
      -e "s|@BLOOM_SIGNER_BINARY@|/usr/libexec/bloom/current/bloom-signer|g" \
      "$payload/installer/linux/systemd/bloom-signer@.service.in" \
      > "$unit_root/bloom-signer@.service.new"
    chmod 0644 "$unit_root/bloom-signer@.service.new"
    mv -f "$unit_root/bloom-signer@.service.new" "$unit_root/bloom-signer@.service"

    source_config=""
    if [[ "$root" == "/" ]]; then
      systemd-sysusers "$sysusers"
      # tmpfiles may run before NSS observes identities just created by
      # sysusers. Persist numeric ownership so no service directory is
      # silently skipped because a fresh account name is unresolved.
      numericize_linux_tmpfiles_ownership "$tmpfiles" "$login_uid"
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

    mkdir -p "$installed_config_root"
    chmod 0711 "$installed_config_root"
    machine_environment="$installed_config_root/.machine-env.source.$$"
    printf 'BLOOM_NFS_LISTEN=127.0.0.1:%s\nBLOOM_RELEASE_DIGEST=%s\n' \
      "$nfs_port" "$release_digest" > "$machine_environment"
    atomic_install "$machine_environment" "$installed_config_root/machine.env" 0644
    rm -f -- "$machine_environment"
    install_linux_mount_authorization \
      "$root" "$login_uid" "$login_gid" "$login_home" "$nfs_port"

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
    elif [[ "$root" == "/" ]]; then
      provenance_candidate="$config_root/.provenance-catalog.source.$$"
      rm -f -- "$provenance_candidate"
      "$binary_root/bloom" init triad-refresh-provenance-catalog \
        "$payload/installer/linux/config/provenance-catalog.unsigned.json" \
        "$config_root/installer-identity.json" \
        "$provenance_candidate"
      atomic_install "$provenance_candidate" "$config_root/provenance-catalog.json" 0644
      rm -f -- "$provenance_candidate"
    fi
    enrollment_root="$root/etc/bloom/enrollments"
    mkdir -p "$enrollment_root"
    chmod 0755 "$enrollment_root"
    enrollment_source="$config_root/.enrollment.source.$$"
    printf '{"schema":"bloom.linux-enrollment.1","state":"active","login_uid":%s,"login_user":"%s","release_digest":"%s","nfs_port":%s}\n' \
      "$login_uid" "$login_user" "$release_digest" "$nfs_port" > "$enrollment_source"
    atomic_install "$enrollment_source" "$enrollment_root/$login_uid.json" 0644
    rm -f -- \
      "$enrollment_source" \
      "$root/etc/bloom/retained/$login_uid.json"
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
      chown "$login_uid:$login_gid" \
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
        "$payload/installer/linux/systemd/instance-dropins/bloom-signer@LOGIN_UID.service.d/50-aws-kms.conf.in" |
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

    if [[ "$release_upgrade" == true ]]; then
      rewrite_linux_release_set "$root" "$release_digest" active
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
        systemctl --user enable bloom-session.service bloom-machine.service
      systemctl disable --now \
        "bloom-signer-rpc@$login_uid.socket" \
        "bloom-signer-control@$login_uid.socket" \
        "bloom-broker-rpc@$login_uid.socket" \
        "bloom-broker-control@$login_uid.socket" \
        2>/dev/null || true
      # The fixed ceremony port is per-host, not per login. Keep the socket
      # demand-started by the selected login's session path rather than
      # enabling every installed login's socket at boot.
      systemctl disable --now \
        "bloom-broker-ceremony@$login_uid.socket" \
        2>/dev/null || true
      # Materialize the package-owned runtime and state layout at the final
      # activation boundary. Nothing between this check and path activation
      # may remove the directories named by ReadWritePaths in the services.
      materialize_linux_layout "$tmpfiles" "$login_uid"
      if [[ "$release_upgrade" == true ]]; then
        start_linux_release_set "$root"
        finish_linux_upgrade
      else
        systemctl enable --now "bloom-session@$login_uid.path"
      fi
      printf '%s\n' \
        "BLOOM_BIN=/usr/bin/bloom" \
        "BLOOM_INSTALL_MODE=triad-linux-systemd" \
        "BLOOM_RELOGIN_REQUIRED=$([[ "$release_upgrade" == true ]] && printf 0 || printf 1)"
    elif [[ "$release_upgrade" == true ]]; then
      finish_linux_upgrade
    fi
    ;;
  uninstall)
    retain_custody=false
    if [[ "${1:-}" == "--retain-custody" ]]; then
      retain_custody=true
      shift
      [[ $# -eq 2 ]] || usage
    else
      [[ $# -eq 3 ]] || usage
    fi
    validate_root_uid "$1" "$2"
    if [[ "$retain_custody" == false ]]; then
      expected="delete-bloom-login-$login_uid"
      [[ "$3" == "$expected" ]] || {
        echo "uninstall confirmation must equal $expected" >&2
        exit 64
      }
    fi
    config_target="$root/etc/bloom/$login_uid"
    state_target="$root/var/lib/bloom/$login_uid"
    run_target="$root/run/bloom/$login_uid"
    [[ -d "$config_target" || -d "$state_target" || \
      -f "$root/etc/bloom/enrollments/$login_uid.json" || \
      -f "$root/etc/bloom/retained/$login_uid.json" ]] || {
      echo "Bloom enrollment $login_uid is not installed" >&2
      exit 66
    }
    if [[ "$root" == "/" ]]; then
      login_record="$(getent passwd "$login_uid" || true)"
      login_user="$(printf '%s\n' "$login_record" | cut -d: -f1)"
      login_home="$(printf '%s\n' "$login_record" | cut -d: -f6)"
      user_runtime="/run/user/$login_uid"
      if [[ -n "$login_user" && -S "$user_runtime/bus" ]]; then
        runuser -u "$login_user" -- env \
          XDG_RUNTIME_DIR="$user_runtime" \
          DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
          systemctl --user stop \
          bloom-machine.service bloom-session.service \
          2>/dev/null || true
        for stopped_user_unit in bloom-machine.service bloom-session.service; do
          if runuser -u "$login_user" -- env \
            XDG_RUNTIME_DIR="$user_runtime" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
            systemctl --user is-active --quiet "$stopped_user_unit"
          then
            echo "refusing to uninstall while $stopped_user_unit is still active" >&2
            exit 70
          fi
        done
        runuser -u "$login_user" -- env \
          XDG_RUNTIME_DIR="$user_runtime" \
          DBUS_SESSION_BUS_ADDRESS="unix:path=$user_runtime/bus" \
          systemctl --user disable bloom-machine.service bloom-session.service \
          2>/dev/null || true
      fi
      if [[ -n "$login_user" && "$login_home" == /* && "$login_home" != "/" ]]; then
        runuser -u "$login_user" -- rm -f -- \
          "$login_home/.config/systemd/user/default.target.wants/bloom-machine.service" \
          "$login_home/.config/systemd/user/default.target.wants/bloom-session.service"
        if [[ "$retain_custody" == false ]]; then
          runuser -u "$login_user" -- rm -rf -- "$login_home/.bloom"
        fi
      fi
      # Remove every activation source before stopping Broker or Signer. If
      # the session path remains active while those services stop, it can
      # immediately start both again and leave Signer alive after its unit and
      # account have been removed.
      systemctl disable --now \
        "bloom-broker-ceremony@$login_uid.socket" \
        "bloom-session@$login_uid.path" \
        2>/dev/null || true
      systemctl disable \
        "bloom-broker@$login_uid.service" \
        "bloom-signer@$login_uid.service" \
        2>/dev/null || true
      systemctl stop \
        "bloom-broker@$login_uid.service" \
        "bloom-signer@$login_uid.service" \
        2>/dev/null || true
      for stopped_unit in \
        "bloom-broker-ceremony@$login_uid.socket" \
        "bloom-session@$login_uid.path" \
        "bloom-broker@$login_uid.service" \
        "bloom-signer@$login_uid.service"
      do
        if systemctl is-active --quiet "$stopped_unit"; then
          echo "refusing to uninstall while $stopped_unit is still active" >&2
          exit 70
        fi
      done
    fi
    remove_linux_mount_authorization "$root" "$login_uid"
    rm -rf -- "$run_target"
    if [[ "$retain_custody" == true ]]; then
      custody_record="$root/etc/bloom/enrollments/$login_uid.json"
      if [[ ! -f "$custody_record" || -L "$custody_record" ]]; then
        custody_record="$root/etc/bloom/retained/$login_uid.json"
      fi
      [[ -f "$custody_record" && ! -L "$custody_record" ]] || {
        echo "Linux custody record is missing or unsafe" >&2
        exit 65
      }
      retained_login_user="$(linux_record_string "$custody_record" login_user)"
      retained_release_digest="$(linux_record_string "$custody_record" release_digest)"
      retained_nfs_port="$(linux_record_number "$custody_record" nfs_port)"
      [[ "$retained_login_user" =~ ^[a-z_][a-z0-9_-]*$ && \
        "$retained_release_digest" =~ ^[0-9a-f]{64}$ && \
        "$retained_nfs_port" =~ ^[0-9]+$ ]] || {
        echo "Linux custody record is malformed" >&2
        exit 65
      }
      retained_root="$root/etc/bloom/retained"
      mkdir -p "$retained_root"
      chmod 0755 "$retained_root"
      retained_source="$retained_root/.retained-$login_uid.$$"
      printf '{"schema":"bloom.linux-enrollment.1","state":"retained","login_uid":%s,"login_user":"%s","release_digest":"%s","nfs_port":%s}\n' \
        "$login_uid" "$retained_login_user" "$retained_release_digest" \
        "$retained_nfs_port" > "$retained_source"
      atomic_install "$retained_source" "$retained_root/$login_uid.json" 0644
      rm -f -- "$retained_source"
    else
      rm -rf -- "$config_target" "$state_target"
      rm -f -- "$root/etc/bloom/retained/$login_uid.json"
    fi
    rm -f -- \
      "$root/etc/bloom/enrollments/$login_uid.json" \
      "$root/usr/lib/sysusers.d/bloom-$login_uid.conf" \
      "$root/usr/lib/tmpfiles.d/bloom-$login_uid.conf" \
      "$root/usr/lib/systemd/system/bloom-signer@$login_uid.service.d/50-aws-kms.conf"
    rmdir "$root/usr/lib/systemd/system/bloom-signer@$login_uid.service.d" \
      2>/dev/null || true
    rmdir "$root/etc/bloom/enrollments" "$root/etc/bloom/retained" \
      2>/dev/null || true

    if [[ "$root" == "/" && "$retain_custody" == false ]]; then
      if command -v userdel >/dev/null 2>&1; then
        for service_user in "bloom-broker-$login_uid" "bloom-signer-$login_uid"; do
          if getent passwd "$service_user" >/dev/null; then
            userdel "$service_user" 2>/dev/null || \
              echo "warning: could not remove service user $service_user" >&2
          fi
        done
      fi
      if command -v groupdel >/dev/null 2>&1; then
        for service_group in \
          "bloom-broker-$login_uid" \
          "bloom-signer-$login_uid" \
          "bloom-machine-broker-$login_uid" \
          "bloom-broker-signer-$login_uid" \
          "bloom-revoke-$login_uid" \
          "bloom-session-$login_uid"
        do
          if getent group "$service_group" >/dev/null; then
            groupdel "$service_group" 2>/dev/null || \
              echo "warning: could not remove service group $service_group" >&2
          fi
        done
      fi
    fi

    active_enrollment=false
    for enrollment in "$root"/etc/bloom/enrollments/*.json; do
      if [[ -f "$enrollment" ]]; then
        active_enrollment=true
        break
      fi
    done
    if [[ "$active_enrollment" == false ]]; then
      rm -f -- \
        "$root/usr/bin/bloom" \
        "$root/usr/libexec/bloom/current" \
        "$root/usr/libexec/bloom/bloom" \
        "$root/usr/libexec/bloom/bloom-broker" \
        "$root/usr/libexec/bloom/bloom-signer" \
        "$root/usr/libexec/bloom/bloom-signer-migrate" \
        "$root/usr/lib/systemd/system/bloom-broker@.service" \
        "$root/usr/lib/systemd/system/bloom-signer@.service" \
        "$root/usr/lib/systemd/system/bloom-broker-ceremony@.socket" \
        "$root/usr/lib/systemd/system/bloom-session@.path" \
        "$root/usr/lib/systemd/user/bloom-machine.service" \
        "$root/usr/lib/systemd/user/bloom-session.service"
    fi

    retained_custody=false
    for retained in "$root"/etc/bloom/retained/*.json; do
      if [[ -f "$retained" ]]; then
        retained_custody=true
        break
      fi
    done
    if [[ "$active_enrollment" == false && "$retained_custody" == false ]]; then
      rm -f -- \
        "$root/usr/bin/bloom-uninstall" \
        "$root/usr/libexec/bloom/bloom-linux-maintenance"
      rm -rf -- "$root/usr/libexec/bloom/releases"
      rmdir "$root/usr/libexec/bloom" "$root/etc/bloom" \
        2>/dev/null || true
    fi
    if [[ "$root" == "/" ]]; then
      systemctl daemon-reload
    fi
    ;;
  *)
    usage
    ;;
esac
