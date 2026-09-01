#!/bin/bash
set -Eeuo pipefail

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export CARGO_TARGET_DIR="$HOME/Library/Caches/bloom-w0-target"

readonly shared_root="/Volumes/My Shared Files"
readonly output_root="$shared_root/output"
readonly source_bundle_root="$output_root/source-bundles"
readonly local_source_root="$HOME/Library/Caches/bloom-w0-sources"
readonly main_root="$local_source_root/bloom"
readonly broker_root="$local_source_root/bloom-broker"
readonly signer_root="$local_source_root/bloom-signer"
readonly payload="$output_root/verified/bloom-triad"
readonly distribution="$output_root/triad-dist/bloom-triad-test-unclaimed.tar.gz"
readonly evidence_dir="$output_root/evidence"
readonly release_pin="/private/var/db/bloom-w0-release-key.pem"
readonly disposable_marker="/private/var/db/bloom-w0-disposable-host"

cleanup() {
  local status=$?
  trap - EXIT
  /usr/bin/sudo /bin/rm -f "$disposable_marker" "$release_pin"
  exit "$status"
}
trap cleanup EXIT

refresh_local_source() {
  local name="$1"
  local bundle="$source_bundle_root/$name.bundle"
  local target="$local_source_root/$name"
  local temporary="$local_source_root/.$name.$$.new"
  local replacement_path
  [[ -f "$bundle" && ! -L "$bundle" ]] || {
    echo "missing Tart source bundle: $bundle" >&2
    return 69
  }
  [[ ! -L "$local_source_root" ]] || {
    echo "unsafe Tart local source-cache symlink: $local_source_root" >&2
    return 65
  }
  mkdir -p "$local_source_root"
  [[ -d "$local_source_root" && ! -L "$local_source_root" ]] || {
    echo "unsafe Tart local source-cache root: $local_source_root" >&2
    return 65
  }
  for replacement_path in "$temporary" "$target"; do
    [[ ! -L "$replacement_path" ]] || {
      echo "unsafe Tart local source replacement symlink: $replacement_path" >&2
      return 65
    }
  done
  if [[ -e "$temporary" ]]; then
    chmod -R u+w "$temporary"
    find "$temporary" -depth -delete
  fi
  git clone --quiet "$bundle" "$temporary"
  git -C "$temporary" fsck --no-dangling >/dev/null
  if [[ -e "$target" ]]; then
    chmod -R u+w "$target"
    find "$target" -depth -delete
  fi
  mv "$temporary" "$target"
}

refresh_local_source bloom
refresh_local_source bloom-broker
refresh_local_source bloom-signer

[[ "$(uname -s)" == "Darwin" ]] || {
  echo "Tart W0 execution requires Darwin" >&2
  exit 69
}
for path in "$main_root" "$broker_root" "$signer_root" "$payload"; do
  [[ -e "$path" ]] || {
    echo "missing Tart W0 input: $path" >&2
    exit 69
  }
done

login_uid="$(id -u)"
login_user="$(id -un)"
/bin/launchctl print "gui/$login_uid" >/dev/null

printf '%s\n' bloom-macos-unix-w0-disposable-v1 |
  /usr/bin/sudo /usr/bin/tee "$disposable_marker" >/dev/null
/usr/bin/sudo /usr/sbin/chown root:wheel "$disposable_marker"
/usr/bin/sudo /bin/chmod 0644 "$disposable_marker"

/usr/bin/sudo /usr/sbin/systemsetup -setusingnetworktime on
/usr/bin/sudo /usr/sbin/systemsetup -getusingnetworktime |
  /usr/bin/grep -Fx "Network Time: On"
/usr/bin/sudo /bin/launchctl print system/com.apple.timed >/dev/null
/usr/bin/sudo /usr/bin/install \
  -o root \
  -g wheel \
  -m 0644 \
  "$payload/RELEASE_PUBLIC_KEY.pem" \
  "$release_pin"

mkdir -p "$evidence_dir"

/usr/bin/sudo /usr/bin/env \
  BLOOM_RUN_MACOS_UNIX_W0=true \
  BLOOM_RELEASE_PUBLIC_KEY="$release_pin" \
  BLOOM_MACOS_INSTALLED_ACCEPTANCE_MAIN_ROOT="$main_root" \
  BLOOM_MACOS_INSTALLED_ACCEPTANCE_BROKER_ROOT="$broker_root" \
  BLOOM_MACOS_INSTALLED_ACCEPTANCE_SIGNER_ROOT="$signer_root" \
  BLOOM_MACOS_W0_EVIDENCE_DIR="$evidence_dir" \
  BLOOM_MACOS_ACCEPTANCE_CARGO="$HOME/.cargo/bin/cargo" \
  BLOOM_MACOS_ACCEPTANCE_CARGO_HOME="$HOME/.cargo" \
  BLOOM_MACOS_ACCEPTANCE_RUSTUP_HOME="$HOME/.rustup" \
  BLOOM_MACOS_ACCEPTANCE_CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
  "$main_root/tests/conformance/macos-unix-principals/run-disposable.sh" \
  "$payload" \
  "$login_uid" \
  "$login_user"

subject="$(
  "$main_root/packaging/triad/release/macos-conformance-subject.sh" \
    "$payload"
)"
archive_sha="$(
  /usr/bin/shasum -a 256 "$distribution" |
    /usr/bin/awk '{print $1}'
)"
{
  printf 'schema=bloom.macos-w0-subject.1\n'
  printf 'release_subject_digest=%s\n' "$subject"
  printf 'w0_candidate_archive_sha256=%s\n' "$archive_sha"
  /bin/cat "$payload/SOURCE_REVISIONS"
} >"$output_root/macos-w0-subject.txt"

echo "local Tart macOS W0 completed successfully"
