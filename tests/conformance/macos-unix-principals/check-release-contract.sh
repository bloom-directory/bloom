#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 2 ]] || {
  echo 'usage: check-release-contract.sh PAYLOAD MAIN_ROOT' >&2
  exit 64
}
payload="$(cd "$1" && pwd -P)"
main_root="$(cd "$2" && pwd -P)"
release_dir="$main_root/packaging/triad/release"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/staging/bin"
for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
  cp "$payload/bin/$binary" "$work/staging/bin/$binary"
done

# An optional conformance report must not block production-claim assembly.
# This ephemeral key exercises the format, not production release authorization.
/usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$work/release-key"
archive="$work/production-claim.tar.gz"
env \
  BLOOM_PLATFORM_CLAIM=macos-unix-principals \
  BLOOM_MACOS_CONFORMANCE_REPORT= \
  BLOOM_MACOS_CONFORMANCE_SIGNATURE= \
  BLOOM_MACOS_CONFORMANCE_PUBLIC_KEY= \
  BLOOM_MACOS_CONFORMANCE_KEY_SHA256= \
  BLOOM_MACHINE_SHA="$(sed -n 's/^BLOOM_MACHINE_SHA=//p' "$payload/SOURCE_REVISIONS")" \
  BLOOM_BROKER_SHA="$(sed -n 's/^BLOOM_BROKER_SHA=//p' "$payload/SOURCE_REVISIONS")" \
  BLOOM_SIGNER_SHA="$(sed -n 's/^BLOOM_SIGNER_SHA=//p' "$payload/SOURCE_REVISIONS")" \
  "$release_dir/build-bundle.sh" \
  "$work/staging" "$archive" "$work/release-key" 1700000000
"$release_dir/verify-bundle.sh" \
  "$archive" "$archive.sha256" "$archive.sig" "$archive.pub"
tar -tzf "$archive" > "$work/entries"
if grep -E '^bloom-triad/MACOS_CONFORMANCE_REPORT\.(json|pub|sig)$' "$work/entries"; then
  echo 'report-free contract check unexpectedly included a conformance report' >&2
  exit 1
fi
[[ "$(tar -xOzf "$archive" bloom-triad/PLATFORM_CLAIM)" == macos-unix-principals ]]

# A production claim and self-consistent signatures cannot replace the pin.
if "$release_dir/verify-bundle.sh" \
  "$archive" "$archive.sha256" "$archive.sig" \
  "$release_dir/bloom-release-v1.pub" > "$work/untrusted-key.log" 2>&1
then
  echo 'production-claim archive signed by an untrusted key was accepted' >&2
  exit 1
fi
echo 'report-free macOS release contract and reviewed-key rejection passed'
