#!/bin/sh
set -eu

# Bloom review-before-execute setup.
#
# This script downloads, verifies, and stages the latest published stable Bloom triad
# release for the current platform. It never elevates privilege, never handles
# a password, and never starts a Bloom service. After staging it prints the
# captured values for one narrow, reviewed privileged handoff (pkexec/osascript,
# or user-run sudo as a Linux fallback).
#
# Run as root on Linux it first resolves the non-root Bloom login user and
# re-runs itself as that login; see the headless section below.
#
# Supported production targets and their signed release artifacts:
#
#   Linux x86_64   bloom-triad-linux-x86_64.tar.gz    claim linux
#   Linux aarch64  bloom-triad-linux-aarch64.tar.gz   claim linux
#   macOS arm64    bloom-triad-macos-aarch64.tar.gz   claim macos-unix-principals
#
# Each artifact ships .sha256, .sig, and .pub sidecars signed by the reviewed
# Bloom release key. Upstream release note: the tag workflow publishes the
# Linux x86_64 and aarch64 assets, and the macOS aarch64 asset is signed and
# attached to the same release tag by its native release lane. If an expected
# asset is absent from the resolved release the download below fails and
# nothing is installed.

sha256_file() {
  digest_input=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$digest_input" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$digest_input" | awk '{print $1}'
  else
    printf '%s\n' "A SHA-256 tool (sha256sum or shasum) is required." >&2
    return 1
  fi
}

verify_release_signature() {
  signature_namespace=$1
  signature_input=$2
  signature_file=$3
  /usr/bin/ssh-keygen \
    -Y verify \
    -f "$allowed_signers" \
    -I bloom-release \
    -n "$signature_namespace" \
    -s "$signature_file" \
    < "$signature_input" >/dev/null
}

resolve_triad_target() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Linux)
      case "$arch" in
        x86_64|amd64)
          platform_slug="linux-x86_64"
          production_asset="bloom-triad-linux-x86_64.tar.gz"
          ;;
        arm64|aarch64)
          platform_slug="linux-aarch64"
          production_asset="bloom-triad-linux-aarch64.tar.gz"
          ;;
        *)
          printf '%s\n' \
            "Bloom setup supports Linux x86_64 and aarch64; this machine reports: $arch" >&2
          exit 1
          ;;
      esac
      production_platform_claim="linux"
      payload_installer_path="installer/release/install-linux.sh"
      install_mode="triad-linux-systemd"
      ;;
    Darwin)
      case "$arch" in
        arm64|aarch64) ;;
        *)
          printf '%s\n' \
            "Bloom setup supports macOS arm64; this machine reports: $arch" >&2
          exit 1
          ;;
      esac
      platform_slug="macos-aarch64"
      production_asset="bloom-triad-macos-aarch64.tar.gz"
      production_platform_claim="macos-unix-principals"
      payload_installer_path="installer/release/install-macos.sh"
      install_mode="triad-macos-launchd"
      ;;
    *)
      printf '%s\n' \
        "Bloom supports Linux x86_64, Linux aarch64, and macOS arm64. Windows is not supported; use Bloom through a cloud agent on a supported platform, such as OpenClaw, Hermes, or GrokBot." >&2
      exit 1
      ;;
  esac
}

require_triad_environment() {
  for required_command in \
    awk cat chmod cmp cp curl dirname grep id mkdir mktemp mv rm tar uname
  do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      printf '%s\n' "$required_command is required to prepare Bloom." >&2
      exit 1
    fi
  done
  if [ ! -x /usr/bin/ssh-keygen ]; then
    printf '%s\n' "/usr/bin/ssh-keygen is required to verify Bloom release signatures." >&2
    exit 1
  fi

  case "$os" in
    Linux)
      for required_system_command in \
        getent runuser systemctl systemd-sysusers systemd-tmpfiles
      do
        if ! command -v "$required_system_command" >/dev/null 2>&1; then
          printf '%s\n' \
            "$required_system_command is required for the Bloom Linux installer." >&2
          exit 1
        fi
      done
      if [ ! -S "/run/user/$login_uid/bus" ]; then
        printf '%s\n' "An active systemd user session is required to install Bloom." >&2
        exit 1
      fi
      ;;
    Darwin)
      for required_system_command in \
        dscl dseditgroup dsmemberutil launchctl pfctl plutil shasum xattr
      do
        if ! command -v "$required_system_command" >/dev/null 2>&1; then
          printf '%s\n' \
            "$required_system_command is required for the Bloom macOS installer." >&2
          exit 1
        fi
      done
      # The packaged macOS installer bootstraps the Machine and session
      # LaunchAgents into this login's GUI domain and refuses to install
      # without it.
      if ! launchctl print "gui/$login_uid" >/dev/null 2>&1; then
        printf '%s\n' "An active macOS login session is required to install Bloom." >&2
        exit 1
      fi
      ;;
  esac
}

# Headless Linux staging as the Bloom login user.
#
# An authorized agent on a headless Linux host already holds administrative
# access but has no interactive login to stage as, and Machine never runs as
# root. Run as root, this script resolves which non-root login Bloom belongs
# to, prepares that login's systemd user session, and re-runs itself unchanged
# as that login. It still never elevates, never installs, never touches wallet
# state, and the privileged installer still verifies its own root-owned copy.
#
#   BLOOM_LOGIN_USER=<login>        use this existing non-root login
#   BLOOM_PREPARE_LOGIN_USER=1      authorize creating the dedicated "bloom"
#                                   login when this host has no Bloom login
#   BLOOM_SYSTEM_ROOT=<dir>         test-only: any root other than / resolves
#                                   the login, reports the plan, and changes
#                                   nothing

headless_default_login=bloom

headless_blocker() {
  printf 'Bloom headless setup blocker: %s\n' "$1" >&2
  exit 1
}

headless_record_field() {
  # headless_record_field FILE KEY KIND: one scalar from a single-line Linux
  # enrollment record, which only the privileged installer writes.
  case "$3" in
    string)
      sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" |
        awk 'NR == 1 { print }'
      ;;
    *)
      sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$1" |
        awk 'NR == 1 { print }'
      ;;
  esac
}

headless_verify_login() {
  # headless_verify_login NAME [UID]: confirm NAME is a real non-root login in
  # this host's password database, optionally at an exact UID. Sets
  # headless_user, headless_uid, headless_home, and headless_shell.
  # Disagreement fails closed.
  verify_name=$1
  verify_uid=${2:-}
  headless_verify_detail=
  # The privileged Linux installer's own login-name charset.
  case "$verify_name" in
    ''|[!a-z_]*|*[!a-z0-9_-]*) return 1 ;;
  esac
  verify_entry=$(getent passwd "$verify_name" 2>/dev/null) || return 1
  verify_entry=$(printf '%s\n' "$verify_entry" | awk 'NR == 1 { print }')
  IFS=: read -r entry_name entry_password entry_uid entry_gid entry_comment \
    entry_home entry_shell <<HEADLESS_PASSWD_ENTRY
$verify_entry
HEADLESS_PASSWD_ENTRY
  [ "$entry_name" = "$verify_name" ] || return 1
  case "$entry_uid" in
    ''|*[!0-9]*|0) return 1 ;;
  esac
  if [ -n "$verify_uid" ] && [ "$entry_uid" != "$verify_uid" ]; then
    return 1
  fi
  case "$entry_home" in
    /) return 1 ;;
    /*) ;;
    *) return 1 ;;
  esac
  # The privileged installer resolves this login's home by UID, so a second
  # account sharing the UID would be installed for instead of this one. An
  # aliased UID is ambiguous: fail closed rather than pick one.
  verify_uid_entry=$(getent passwd "$entry_uid" 2>/dev/null) || return 1
  verify_uid_name=$(printf '%s\n' "$verify_uid_entry" |
    awk -F: 'NR == 1 { print $1 }')
  if [ "$verify_uid_name" != "$entry_name" ]; then
    headless_verify_detail="UID $entry_uid is shared with $verify_uid_name"
    return 1
  fi
  headless_user=$entry_name
  headless_uid=$entry_uid
  headless_home=$entry_home
  headless_shell=$entry_shell
  return 0
}

headless_require_adoptable_login() {
  # A login Bloom is adopting for the first time has to be a real interactive
  # login. Bloom's own Broker and Signer principals and other system accounts
  # are created with a no-login shell, so an account that only shares the name
  # is reported instead of adopted. An existing enrollment or retained custody
  # record is authority on its own and is never re-judged here.
  case "$headless_shell" in
    */nologin|*/false)
      headless_blocker "$headless_user is not an interactive login on this host (login shell $headless_shell); set BLOOM_LOGIN_USER to the login Bloom should run as"
      ;;
  esac
  if [ ! -d "$headless_home" ]; then
    headless_blocker "$headless_user has no home directory at $headless_home; set BLOOM_LOGIN_USER to the login Bloom should run as"
  fi
}

headless_pair_names() {
  pair_names=
  for pair in $1; do
    if [ -n "$pair_names" ]; then
      pair_names="$pair_names, "
    fi
    pair_names="$pair_names${pair%:*}"
  done
  printf '%s' "$pair_names"
}

headless_known_logins() {
  # The logins this host already knows: active enrollments, and custody
  # retained by an uninstall. An unrecognized record stops the run. The
  # privileged installer's own validation is what is mirrored here: the
  # schema it writes, the state its directory means, and a record whose
  # login UID is the one its file name claims.
  headless_active=
  headless_retained=
  for record_directory in enrollments retained; do
    if [ "$record_directory" = enrollments ]; then
      expected_state=active
    else
      expected_state=retained
    fi
    for record in "$headless_etc/$record_directory"/*.json; do
      if [ -L "$record" ] || { [ -e "$record" ] && [ ! -f "$record" ]; }; then
        headless_blocker "unrecognized Bloom enrollment record: $record"
      fi
      if [ ! -f "$record" ]; then
        continue
      fi
      record_schema=$(headless_record_field "$record" schema string)
      record_state=$(headless_record_field "$record" state string)
      record_user=$(headless_record_field "$record" login_user string)
      record_uid=$(headless_record_field "$record" login_uid number)
      record_name=${record##*/}
      record_name=${record_name%.json}
      if [ "$record_schema" != bloom.linux-enrollment.1 ]; then
        headless_blocker "unrecognized Bloom enrollment record schema: $record"
      fi
      if [ "$record_state" != "$expected_state" ]; then
        headless_blocker "unrecognized Bloom enrollment record: $record"
      fi
      case "$record_user" in
        ''|[!a-z_]*|*[!a-z0-9_-]*)
          headless_blocker "Bloom enrollment record names an invalid login: $record"
          ;;
      esac
      case "$record_uid" in
        ''|*[!0-9]*|0)
          headless_blocker "Bloom enrollment record names an invalid login UID: $record"
          ;;
      esac
      if [ "$record_uid" != "$record_name" ]; then
        headless_blocker "Bloom enrollment record names login UID $record_uid: $record"
      fi
      if [ "$record_state" = active ]; then
        headless_active="$headless_active $record_user:$record_uid"
      else
        headless_retained="$headless_retained $record_user:$record_uid"
      fi
    done
  done
}

headless_prepare_login() {
  # Only reached with explicit authorization and no Bloom login on the host.
  headless_user=$headless_default_login
  headless_uid=
  headless_home=
  headless_created=$headless_default_login
  if [ "$headless_live" != 1 ]; then
    return 0
  fi
  if ! command -v useradd >/dev/null 2>&1; then
    headless_blocker \
      "useradd is required to prepare the dedicated '$headless_default_login' login"
  fi
  if ! useradd --create-home --shell /bin/sh --comment "Bloom login" \
    "$headless_default_login"
  then
    headless_blocker \
      "could not create the dedicated '$headless_default_login' login"
  fi
  if ! headless_verify_login "$headless_default_login"; then
    headless_blocker \
      "the dedicated '$headless_default_login' login is not a usable non-root login${headless_verify_detail:+: $headless_verify_detail}"
  fi
  headless_require_adoptable_login
}

resolve_headless_login() {
  requested_login=${BLOOM_LOGIN_USER:-}
  if [ -n "$requested_login" ]; then
    case "$requested_login" in
      [!a-z_]*|*[!a-z0-9_-]*)
        headless_blocker "BLOOM_LOGIN_USER is not a valid login name: $requested_login"
        ;;
    esac
  fi
  headless_known_logins
  headless_created=
  selected=
  if [ -n "$headless_active" ]; then
    # Upgrade: Bloom is already installed for a login. Reuse exactly that
    # login; never create or substitute another one.
    headless_source=enrolled
    for pair in $headless_active; do
      if [ -n "$requested_login" ] && [ "$requested_login" != "${pair%:*}" ]; then
        continue
      fi
      if [ -n "$selected" ]; then
        headless_blocker "this host has more than one enrolled Bloom login ($(headless_pair_names "$headless_active")); set BLOOM_LOGIN_USER to the one to upgrade"
      fi
      selected=$pair
    done
    if [ -z "$selected" ]; then
      headless_blocker "Bloom is enrolled for $(headless_pair_names "$headless_active") on this host, not $requested_login; upgrade the enrolled login instead of replacing it"
    fi
  elif [ -n "$requested_login" ]; then
    headless_source=existing
    selected="$requested_login:"
    for pair in $headless_retained; do
      if [ "${pair%:*}" != "$requested_login" ]; then
        continue
      fi
      if [ "$headless_source" = retained ]; then
        headless_blocker "this host has more than one retained Bloom custody record for $requested_login; nothing was changed"
      fi
      # Reinstalling for a login whose custody an uninstall retained: bind the
      # recorded UID, and report it as retained rather than as a plain first
      # install for a login that happens to exist.
      headless_source=retained
      selected=$pair
    done
  elif [ -n "$headless_retained" ]; then
    headless_blocker "Bloom custody is retained for $(headless_pair_names "$headless_retained") on this host; set BLOOM_LOGIN_USER to that login to reinstall for it rather than preparing another"
  elif getent passwd "$headless_default_login" >/dev/null 2>&1; then
    # An account already holds the dedicated name. Adopt it only if it is a
    # usable login; never fall through to creating or substituting another.
    headless_source=existing
    selected="$headless_default_login:"
  elif [ "${BLOOM_PREPARE_LOGIN_USER:-}" = 1 ]; then
    headless_source=prepared
  else
    headless_blocker "this host has no Bloom login user: set BLOOM_LOGIN_USER to an existing non-root login, or rerun with BLOOM_PREPARE_LOGIN_USER=1 to create the dedicated '$headless_default_login' login"
  fi

  # Creating the dedicated login, and enabling a lingering systemd user
  # session for any login, is only ever done with this authorization.
  if [ "${BLOOM_PREPARE_LOGIN_USER:-}" = 1 ]; then
    headless_session_prepare=1
  fi

  if [ "$headless_source" = prepared ]; then
    headless_prepare_login
    return 0
  fi
  if ! headless_verify_login "${selected%:*}" "${selected#*:}"; then
    case "$headless_source" in
      enrolled|retained)
        headless_blocker "the $headless_source Bloom login ${selected%:*} (UID ${selected#*:}) does not match this host's password database; nothing was changed${headless_verify_detail:+: $headless_verify_detail}"
        ;;
    esac
    headless_blocker "${selected%:*} is not a usable non-root login on this host${headless_verify_detail:+: $headless_verify_detail}"
  fi
  if [ "$headless_source" = existing ]; then
    headless_require_adoptable_login
  fi
}

resolve_headless_tmpdir() {
  # Staging runs as the Bloom login, which may not be able to write the
  # TMPDIR this process inherited.
  headless_tmpdir=
  headless_home_tmpdir=
  if [ -n "$headless_home" ]; then
    headless_home_tmpdir="$headless_home/.cache/bloom/tmp"
  fi
  for candidate in "${TMPDIR:-}" /tmp /var/tmp "$headless_home_tmpdir"; do
    if [ -z "$candidate" ]; then
      continue
    fi
    case "$candidate" in
      /*) ;;
      *) continue ;;
    esac
    case "$candidate" in
      *'
'*) continue ;;
    esac
    if [ "$candidate" = "$headless_home_tmpdir" ]; then
      runuser -u "$headless_user" -- /bin/sh -c '
        mkdir -p "$1" && chmod 700 "$1"
      ' bloom-headless-tmpdir "$candidate" >/dev/null 2>&1 || continue
    fi
    if runuser -u "$headless_user" -- /bin/sh -c '
      probe=$(mktemp -d "$1/bloom-tmpdir-probe.XXXXXX") && rmdir "$probe"
    ' bloom-headless-tmpdir "$candidate" >/dev/null 2>&1
    then
      headless_tmpdir=$candidate
      return 0
    fi
  done
  headless_blocker "no temporary directory is writable by $headless_user (tried ${TMPDIR:+$TMPDIR, }/tmp, /var/tmp${headless_home_tmpdir:+, $headless_home_tmpdir})"
}

report_headless_tmpdir() {
  # Readiness checks run as this login too, so report the directory it can
  # actually write rather than leaving them to guess one.
  if [ -n "$headless_tmpdir" ]; then
    printf 'BLOOM_HEADLESS_TMPDIR=%s\n' "$headless_tmpdir"
  fi
}

start_headless_login_session() {
  if [ "$headless_live" != 1 ]; then
    return 0
  fi
  if [ -S "/run/user/$headless_uid/bus" ]; then
    return 0
  fi
  if [ "$headless_session_prepare" != 1 ]; then
    # Lingering is persistent state on an account Bloom did not prepare.
    headless_blocker "$headless_user has no systemd user session at /run/user/$headless_uid/bus: start that login's session, or rerun with BLOOM_PREPARE_LOGIN_USER=1 to authorize a lingering one for it"
  fi
  for required_command in loginctl sleep; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      headless_blocker \
        "$required_command is required to start the Bloom login's systemd user session"
    fi
  done
  if ! loginctl enable-linger "$headless_user" >/dev/null 2>&1; then
    headless_blocker \
      "could not enable a lingering systemd user session for $headless_user"
  fi
  headless_waited=0
  while [ ! -S "/run/user/$headless_uid/bus" ]; do
    if [ "$headless_waited" -ge 30 ]; then
      headless_blocker "no systemd user session appeared for $headless_user at /run/user/$headless_uid/bus"
    fi
    sleep 1
    headless_waited=$((headless_waited + 1))
  done
}

stage_as_headless_login() {
  headless_user=
  headless_uid=
  headless_home=
  headless_shell=
  headless_tmpdir=
  headless_session_prepare=0
  headless_verify_detail=
  system_root=${BLOOM_SYSTEM_ROOT:-/}
  case "$system_root" in
    /*) ;;
    *) headless_blocker "BLOOM_SYSTEM_ROOT must be an absolute path" ;;
  esac
  if [ "$system_root" = / ]; then
    headless_live=1
    headless_etc=/etc/bloom
  else
    headless_live=0
    if [ ! -d "$system_root" ]; then
      headless_blocker "BLOOM_SYSTEM_ROOT is not a directory: $system_root"
    fi
    headless_etc="${system_root%/}/etc/bloom"
  fi
  for required_command in env getent runuser sed; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
      headless_blocker "$required_command is required to stage Bloom as its login user"
    fi
  done
  if [ ! -f "$0" ] || [ ! -r "$0" ]; then
    headless_blocker \
      "run this script from a file path so it can be re-run as the Bloom login user"
  fi

  resolve_headless_login
  if [ "$headless_live" = 1 ] || [ -z "$headless_created" ]; then
    resolve_headless_tmpdir
  fi

  if [ "$headless_live" != 1 ]; then
    printf 'BLOOM_HEADLESS_PLAN=1\n'
    printf 'BLOOM_HEADLESS_LOGIN=%s\n' "$headless_source"
    if [ -n "$headless_created" ]; then
      printf 'BLOOM_HEADLESS_CREATE_LOGIN=%s\n' "$headless_created"
    fi
    if [ "$headless_session_prepare" = 1 ]; then
      printf 'BLOOM_HEADLESS_PREPARE_SESSION=1\n'
    fi
    printf 'BLOOM_LOGIN_USER=%s\n' "$headless_user"
    if [ -n "$headless_uid" ]; then
      printf 'BLOOM_LOGIN_UID=%s\n' "$headless_uid"
      printf 'BLOOM_LOGIN_HOME=%s\n' "$headless_home"
    fi
    report_headless_tmpdir
    exit 0
  fi

  start_headless_login_session
  printf 'BLOOM_HEADLESS_LOGIN=%s\n' "$headless_source"
  report_headless_tmpdir
  # Re-run these exact bytes as the Bloom login, with only that login's
  # environment. Root opens the script; the login user never needs to read it.
  exec runuser -u "$headless_user" -- env -i \
    HOME="$headless_home" \
    LOGNAME="$headless_user" \
    PATH="${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}" \
    TMPDIR="$headless_tmpdir" \
    USER="$headless_user" \
    XDG_RUNTIME_DIR="/run/user/$headless_uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$headless_uid/bus" \
    /bin/sh -s < "$0"
}

resolve_latest_release() {
  # Resolve GitHub's latest stable release once, then use that tag for every
  # download. Never mix assets fetched through a moving latest/download URL.
  release_tag_prefix="https://github.com/bloom-directory/bloom/releases/tag/"
  if ! release_url=$(curl -fsSL \
    --proto '=https' --proto-redir '=https' --max-redirs 5 \
    --connect-timeout 10 --max-time 60 \
    -o /dev/null -w '%{url_effective}' \
    "https://github.com/bloom-directory/bloom/releases/latest"); then
    printf '%s\n' "Could not resolve Bloom's latest stable release." >&2
    exit 1
  fi
  case "$release_url" in
    "$release_tag_prefix"*) triad_release_tag=${release_url#"$release_tag_prefix"} ;;
    *)
      printf '%s\n' "Bloom's latest release did not resolve to the expected repository tag URL." >&2
      exit 1
      ;;
  esac
  # Keep the tag a single safe URL/path component. Reject encoded separators,
  # traversal, query strings, and unexpected redirect responses.
  case "$triad_release_tag" in
    ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._+-]*)
      printf '%s\n' "Bloom's latest release tag is malformed or unsupported." >&2
      exit 1
      ;;
  esac
}

stage_triad() {
  pinned_release_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFY9na4hytUNsW+8LWu//HrX9TaPU7H7Vg0GRWcZM+uP"
  triad_release_base="https://github.com/bloom-directory/bloom/releases/download/$triad_release_tag"
  triad_asset="$production_asset"
  expected_platform_claim="$production_platform_claim"
  install_stage=${BLOOM_INSTALL_STAGE:-"$HOME/.cache/bloom/install/$triad_release_tag-$platform_slug"}

  case "$HOME" in
    /*) ;;
    *)
      printf '%s\n' "HOME must be an absolute path." >&2
      exit 1
      ;;
  esac
  if [ "$HOME" = / ]; then
    printf '%s\n' "Bloom will not stage an installation below the filesystem root." >&2
    exit 1
  fi
  case "$install_stage" in
    "$HOME"/*) ;;
    *)
      printf '%s\n' "BLOOM_INSTALL_STAGE must be below HOME." >&2
      exit 1
      ;;
  esac
  case "$install_stage" in
    *'
'*)
      printf '%s\n' "BLOOM_INSTALL_STAGE must not contain a newline." >&2
      exit 1
      ;;
  esac

  tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/bloom-triad-setup.XXXXXX")
  staged_new="$install_stage.new.$$"
  allowed_signers="$tmp_dir/allowed_signers"
  public_key="$tmp_dir/bloom-release-v1.pub"
  printf '%s\n' "$pinned_release_key" > "$public_key"
  printf 'bloom-release %s\n' "$(cat "$public_key")" > "$allowed_signers"
  chmod 600 "$public_key" "$allowed_signers"

  archive="$tmp_dir/$triad_asset"
  checksum="$tmp_dir/$triad_asset.sha256"
  signature="$tmp_dir/$triad_asset.sig"
  curl -fsSL "$triad_release_base/$triad_asset" -o "$archive"
  curl -fsSL "$triad_release_base/$triad_asset.sha256" -o "$checksum"
  curl -fsSL "$triad_release_base/$triad_asset.sig" -o "$signature"

  verify_release_signature \
    bloom-release-archive-v1 \
    "$checksum" \
    "$signature"
  expected=$(awk -v file="$triad_asset" \
    '$2 == file || $2 == "*" file { print $1; exit }' "$checksum")
  if ! printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$'; then
    printf '%s\n' "The signed Bloom archive checksum is malformed." >&2
    exit 1
  fi
  actual=$(sha256_file "$archive")
  if [ "$actual" != "$expected" ]; then
    printf '%s\n' "Bloom release checksum verification failed." >&2
    exit 1
  fi

  if ! tar -tzf "$archive" | awk '
    BEGIN { valid = 1 }
    /^\// || /(^|\/)\.\.($|\/)/ { valid = 0 }
    $0 !~ /^bloom-triad(\/|$)/ { valid = 0 }
    END { exit valid ? 0 : 1 }
  '; then
    printf '%s\n' "Bloom release archive contains an unsafe path." >&2
    exit 1
  fi
  rm -rf -- "$staged_new"
  mkdir -p "$(dirname "$install_stage")"
  chmod 700 "$(dirname "$install_stage")"
  mkdir -m 700 "$staged_new"
  tar -xzf "$archive" -C "$staged_new"
  payload="$staged_new/bloom-triad"
  for required_payload in \
    PLATFORM_CLAIM \
    RELEASE_PUBLIC_KEY.pem \
    RELEASE_SIGNATURE \
    SHA256SUMS \
    "$payload_installer_path"
  do
    if [ ! -f "$payload/$required_payload" ] || [ -L "$payload/$required_payload" ]; then
      printf '%s\n' "Bloom release is missing $required_payload." >&2
      exit 1
    fi
  done
  if ! cmp -s "$public_key" "$payload/RELEASE_PUBLIC_KEY.pem"; then
    printf '%s\n' "Bloom payload release key does not match the reviewed key." >&2
    exit 1
  fi
  verify_release_signature \
    bloom-release-payload-v1 \
    "$payload/SHA256SUMS" \
    "$payload/RELEASE_SIGNATURE"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$payload" && sha256sum -c SHA256SUMS >/dev/null)
  else
    (cd "$payload" && shasum -a 256 -c SHA256SUMS >/dev/null)
  fi
  if [ "$(cat "$payload/PLATFORM_CLAIM")" != "$expected_platform_claim" ]; then
    printf '%s\n' "Bloom release has the wrong platform claim." >&2
    exit 1
  fi

  # The checks above only fail early. Root trusts none of this stage: the
  # privileged command in references/install.md copies it, verifies it again
  # with the same release key, and only then runs the signed installer.

  # Replace only a stage this script made: owned by the user, with an intact
  # marker naming a release tag and the payload beside it.
  stage_marker="$install_stage/.bloom-triad-stage"
  if [ -L "$install_stage" ] || { [ -e "$install_stage" ] && {
    [ ! -O "$install_stage" ] || [ -L "$stage_marker" ] || [ ! -O "$stage_marker" ] ||
      [ ! -d "$install_stage/bloom-triad" ] ||
      ! grep -qx 'v[0-9][0-9A-Za-z.+-]*' "$stage_marker"; }; }
  then
    printf '%s\n' "Bloom will not replace an unrecognized installation stage: $install_stage" >&2
    exit 1
  fi
  printf '%s\n' "$triad_release_tag" > "$staged_new/.bloom-triad-stage"
  rm -rf -- "$install_stage"
  mv "$staged_new" "$install_stage"
  staged_new=
  printf 'BLOOM_INSTALL_MODE=%s\n' "$install_mode"
  printf 'BLOOM_RELEASE_TAG=%s\n' "$triad_release_tag"
  printf 'BLOOM_STAGE=%s\n' "$install_stage"
  printf 'BLOOM_LOGIN_UID=%s\n' "$login_uid"
  printf 'BLOOM_LOGIN_USER=%s\n' "$login_user"
}

main() {
  login_uid=$(id -u)
  login_user=$(id -un)
  tmp_dir=
  staged_new=

  cleanup() {
    if [ -n "$tmp_dir" ]; then
      rm -rf "$tmp_dir"
    fi
    if [ -n "$staged_new" ]; then
      rm -rf -- "$staged_new"
    fi
  }
  trap cleanup EXIT HUP INT TERM

  resolve_triad_target
  if [ "$os" = Linux ] && [ "$login_uid" = 0 ]; then
    # Either re-runs this script as the Bloom login user or stops with a
    # blocker; it never stages for root.
    stage_as_headless_login
  fi
  require_triad_environment
  resolve_latest_release
  stage_triad
}

main "$@"
