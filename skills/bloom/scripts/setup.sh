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
  require_triad_environment
  resolve_latest_release
  stage_triad
}

main "$@"
