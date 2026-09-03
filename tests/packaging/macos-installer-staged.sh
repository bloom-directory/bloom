#!/usr/bin/env bash
set -Eeuo pipefail

workspace="$(cd "$(dirname "$0")/../.." && pwd -P)"
installer="$workspace/packaging/triad/release/install-macos.sh"
work="$(mktemp -d)"
trap 'find "$work" -depth -delete' EXIT
digest_a="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
digest_b="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

make_payload() {
  local target="$1" marker="$2" name
  mkdir -p "$target/bin" "$target/config" "$target/installer"
  cp -R "$workspace/packaging/triad/macos" "$target/installer/macos"
  mkdir -p "$target/installer/release"
  cp "$installer" "$target/installer/release/install-macos.sh"
  cp "$workspace/packaging/triad/release/compatibility-v1.toml" "$target/"
  printf 'test-unclaimed\n' >"$target/PLATFORM_CLAIM"
  for name in bloom bloom-broker bloom-signer bloom-signer-migrate; do
    printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$marker" >"$target/bin/$name"
    chmod 0755 "$target/bin/$name"
  done
  for name in edge-manifest.json broker.json signer.json machine-identity.json \
    broker-identity.json signer-identity.json revoke-identity.json \
    session-identity.json installer-identity.json provenance-catalog.json
  do
    printf '{}\n' >"$target/config/$name"
  done
}

run_installer() {
  local digest="$1"; shift
  BLOOM_ALLOW_TEST_UNCLAIMED=true \
    BLOOM_MACOS_BROKER_UID=250501 BLOOM_MACOS_SIGNER_UID=250502 \
    BLOOM_MACOS_BROKER_GID=260499 BLOOM_MACOS_SIGNER_GID=260500 \
    BLOOM_MACOS_MACHINE_BROKER_GID=260501 \
    BLOOM_MACOS_BROKER_SIGNER_GID=260502 BLOOM_MACOS_REVOKE_GID=260503 \
    BLOOM_MACOS_LOG_GID=260504 BLOOM_RELEASE_DIGEST="$digest" \
    "$installer" "$@"
}

payload_a="$work/payload-a"
payload_b="$work/payload-b"
make_payload "$payload_a" release-a
make_payload "$payload_b" release-b

# Foreign CLI entries fail before release, enrollment, or custody paths exist.
for conflict in file symlink directory; do
  root="$work/conflict-$conflict"
  mkdir -p "$root/usr/local/bin"
  case "$conflict" in
    file) printf 'foreign\n' >"$root/usr/local/bin/bloom" ;;
    symlink) ln -s /opt/foreign/bloom "$root/usr/local/bin/bloom" ;;
    directory) mkdir "$root/usr/local/bin/bloom" ;;
  esac
  if run_installer "$digest_a" install "$root" 501 releaseuser "$payload_a"; then
    echo "installer overwrote a foreign CLI $conflict" >&2
    exit 1
  fi
  [[ ! -e "$root/usr/local/libexec/bloom" ]]
  [[ ! -e "$root/Library/Application Support/BloomTriad" ]]
done

root="$work/lifecycle-root"
legacy="$root/Users/releaseuser/.local/bin/bloom"
mkdir -p "$(dirname "$legacy")"
printf 'old Bloom\n' >"$legacy"

# Fresh install exposes the exact relative link and removes only the staged
# login's supported legacy entry after enrollment convergence.
run_installer "$digest_a" install "$root" 501 releaseuser "$payload_a"
[[ -L "$root/usr/local/bin/bloom" ]]
[[ "$(readlink "$root/usr/local/bin/bloom")" == ../libexec/bloom/current/bloom ]]
[[ ! -e "$legacy" && ! -L "$legacy" ]]
[[ "$(readlink "$root/usr/local/libexec/bloom/current")" == "releases/$digest_a" ]]

# The exact managed link is accepted and same-digest repair is idempotent.
run_installer "$digest_a" install "$root" 501 releaseuser "$payload_a"
[[ "$(readlink "$root/usr/local/bin/bloom")" == ../libexec/bloom/current/bloom ]]

# Upgrade leaves the stable PATH entry following the new current release.
run_installer "$digest_b" install "$root" 501 releaseuser "$payload_b"
[[ "$(readlink "$root/usr/local/libexec/bloom/current")" == "releases/$digest_b" ]]
[[ "$("$root/usr/local/bin/bloom")" == release-b ]]

# Retaining the final active enrollment removes the command; restore recreates
# it without requiring release-tree deletion.
"$installer" uninstall --retain-custody "$root" 501
[[ ! -e "$root/usr/local/bin/bloom" && ! -L "$root/usr/local/bin/bloom" ]]
[[ -d "$root/usr/local/libexec/bloom" ]]
run_installer "$digest_b" restore "$root" 501 releaseuser "$payload_b"
[[ "$(readlink "$root/usr/local/bin/bloom")" == ../libexec/bloom/current/bloom ]]

# A second active login shares the command. Partial removal keeps it; removal
# of the final active login removes it even when the first custody is retained.
run_installer "$digest_b" install "$root" 502 seconduser "$payload_b"
"$installer" uninstall --retain-custody "$root" 501
[[ -L "$root/usr/local/bin/bloom" ]]
"$installer" uninstall "$root" 502 delete-bloom-login-502
[[ ! -e "$root/usr/local/bin/bloom" && ! -L "$root/usr/local/bin/bloom" ]]

# A legacy symlink is unlinked without following its target, and staged mode
# cannot touch a same-named entry outside the staged root.
root="$work/symlink-root"
outside="$work/outside-home/.local/bin/bloom"
legacy="$root/Users/releaseuser/.local/bin/bloom"
mkdir -p "$(dirname "$legacy")" "$(dirname "$outside")"
printf 'outside\n' >"$outside"
ln -s "$outside" "$legacy"
run_installer "$digest_a" install "$root" 501 releaseuser "$payload_a"
[[ ! -L "$legacy" && -f "$outside" ]]

# An unexpected object is never deleted. Cleanup fails after the enrollment
# and CLI have converged, documenting the non-rollback post-activation policy.
root="$work/unsafe-legacy-root"
legacy="$root/Users/releaseuser/.local/bin/bloom"
mkdir -p "$legacy"
if run_installer "$digest_a" install "$root" 501 releaseuser "$payload_a"; then
  echo "installer accepted an unsafe legacy CLI object" >&2
  exit 1
fi
[[ -d "$legacy" ]]
[[ -f "$root/Library/Application Support/BloomTriad/enrollments/501.json" ]]
[[ -L "$root/usr/local/bin/bloom" ]]

echo "staged macOS installer CLI lifecycle passed"
