#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 ARCHIVE SHA256_FILE SIGNATURE PUBLIC_KEY" >&2
  exit 64
fi

archive="$1"
checksum="$2"
signature="$3"
public_key="$4"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

"$script_dir/ssh-ed25519-verify.sh" \
  "$public_key" \
  bloom-release-archive-v1 \
  "$checksum" \
  "$signature"
(
  cd "$(dirname "$archive")"
  shasum -a 256 -c "$(basename "$checksum")"
)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf "$archive" -C "$work"
payload="$work/bloom-triad"
for required in \
  bin/bloom \
  bin/bloom-broker \
  bin/bloom-signer \
  bin/bloom-signer-migrate \
  PLATFORM_CLAIM \
  compatibility-v1.toml \
  installer/release/install-linux.sh \
  installer/release/install-macos.sh \
  installer/release/macos-conformance-subject.sh \
  installer/release/sign-macos-conformance-report.sh \
  installer/release/ssh-ed25519-verify.sh \
  installer/release/verify-macos-conformance.sh \
  SOURCE_REVISIONS \
  RELEASE_PUBLIC_KEY.pem \
  RELEASE_SIGNATURE \
  SHA256SUMS
do
  test -f "$payload/$required" || {
    echo "bundle is missing $required" >&2
    exit 65
  }
done
"$script_dir/ssh-ed25519-verify.sh" \
  "$payload/RELEASE_PUBLIC_KEY.pem" \
  bloom-release-payload-v1 \
  "$payload/SHA256SUMS" \
  "$payload/RELEASE_SIGNATURE"
(
  cd "$payload"
  shasum -a 256 -c SHA256SUMS
)
compatibility="$payload/compatibility-v1.toml"
compat_value() {
  local section="$1" key="$2"
  awk -v section="[$section]" -v key="$key" '
    /^\[/ { active = ($0 == section) }
    active && $1 == key && $2 == "=" { print $3 }
  ' "$compatibility"
}
require_compat_value() {
  local section="$1" key="$2" expected="$3" actual
  actual="$(compat_value "$section" "$key")"
  [[ "$actual" == "$expected" ]] || {
    echo "bundle compatibility has invalid $section.$key" >&2
    exit 65
  }
}
for authority_edge in machine_broker broker_signer; do
  require_compat_value "protocols.$authority_edge" major 1
  require_compat_value "protocols.$authority_edge" minor_min 3
  require_compat_value "protocols.$authority_edge" minor_max 3
done
for support_edge in signer_control session; do
  require_compat_value "protocols.$support_edge" major 1
  require_compat_value "protocols.$support_edge" minor_min 0
  require_compat_value "protocols.$support_edge" minor_max 1
done
require_compat_value revisions broker_commit '"90dc9adeabf8fb23a1528a3095913fc242b9fe33"'
require_compat_value revisions signer_commit '"3ddddb5b8f15d7c2a82c0aed418a0fe3e46ae0ad"'
require_compat_value revisions service_runtime_commit '"155560173e65fa6635cc87a43986f4fa6ea9c4e0"'
require_compat_value revisions petal_contract_commit '"61938d0c127cfe03c7e3e55baed0ba1439bc5ca2"'
for state_owner in machine broker signer; do
  require_compat_value "state.$state_owner" current 1
  require_compat_value "state.$state_owner" downgrade_floor 1
done
if grep -Eq '^[[:space:]]*(protocol_major|protocol_minor_min|protocol_minor_max)[[:space:]]*=' "$compatibility"; then
  echo "bundle compatibility must not declare a global protocol range" >&2
  exit 65
fi
platform_claim="$(<"$payload/PLATFORM_CLAIM")"
case "$platform_claim" in
  linux)
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      file -b "$payload/bin/$binary" | grep -F 'ELF ' >/dev/null || {
        echo "Linux bundle contains a non-ELF production binary" >&2
        exit 65
      }
    done
    ;;
  macos-unix-principals-w0)
    [[ "$(uname -s)" == "Darwin" ]] &&
      [[ "${BLOOM_ALLOW_MACOS_UNIX_W0:-}" == "true" ]] || {
      echo "macOS W0 bundle requires its disposable Darwin verification lane" >&2
      exit 65
    }
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      file -b "$payload/bin/$binary" | grep -F 'Mach-O ' >/dev/null || {
        echo "macOS W0 bundle contains a non-Mach-O production binary" >&2
        exit 65
      }
    done
    ;;
  macos-unix-principals)
    [[ "$(uname -s)" == "Darwin" ]] || {
      echo "production macOS bundles are verified only on Darwin" >&2
      exit 69
    }
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      file -b "$payload/bin/$binary" | grep -F 'Mach-O ' >/dev/null || {
        echo "production macOS bundle contains a non-Mach-O binary" >&2
        exit 65
      }
    done
    "$payload/installer/release/verify-macos-conformance.sh" "$payload"
    ;;
  test-unclaimed)
    [[ "${BLOOM_ALLOW_TEST_UNCLAIMED:-}" == "true" ]] || {
      echo "test-unclaimed bundle verification was not explicitly enabled" >&2
      exit 65
    }
    ;;
  *)
    echo "bundle has no verifiable production platform claim" >&2
    exit 65
    ;;
esac
if [[ "$platform_claim" == "macos-unix-principals" ||
  "$platform_claim" == "macos-unix-principals-w0" ]]
then
  if find "$payload" -type f \
    \( -name '*identity*.json' -o -name '*credentials*' \) |
    grep . >/dev/null
  then
    echo "macOS Unix-principal bundle contains a private identity-shaped file" >&2
    exit 65
  fi
  if LC_ALL=C grep -aER \
    '"[^"]*(private_key_seed_hex|signing_seed_hex|state_authentication_key_hex)"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' \
    "$payload" >/dev/null
  then
    echo "macOS Unix-principal bundle contains private key material" >&2
    exit 65
  fi
fi
