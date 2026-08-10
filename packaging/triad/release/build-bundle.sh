#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 STAGING_DIR OUTPUT_ARCHIVE ED25519_SIGNING_KEY SOURCE_DATE_EPOCH" >&2
  exit 64
fi

staging="$(cd "$1" && pwd -P)"
output="$2"
signing_key="$3"
source_date_epoch="$4"
tar_command="${TAR:-tar}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

python3 "$script_dir/check-legacy-hash-only-routes.py"

machine_artifact_paths() {
  local root="$1"
  local candidate
  for candidate in \
    "$root/bin/bloom" \
    "$root/bin/bloom-machine" \
    "$root/machine" \
    "$root/config/machine" \
    "$root/share/bloom/machine" \
    "$root/lib/bloom/machine" \
    "$root/libexec/bloom/machine"
  do
    [[ ! -e "$candidate" && ! -L "$candidate" ]] || printf '%s\n' "$candidate"
  done
}

reject_machine_legacy_authority_files() {
  local root="$1"
  local scope="$2"
  local path relative
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    relative="${path#"$root/"}"
    echo "forbidden $scope legacy authority file: $relative" >&2
    return 1
  done < <(
    while IFS= read -r machine_path; do
      [[ -d "$machine_path" ]] || continue
      find "$machine_path" \
        \( -type f -o -type d \) \
        \( -name 'auth.sqlite' -o -name 'keystore' -o -name 'signer-cache' -o \
           -name 'policy-session' -o -name 'ceremony_server' -o \
           -name 'registration.rs' -o -name 'sealed_ceremony.rs' -o \
           -name 'sign_hash.rs' \) -print
    done < <(machine_artifact_paths "$root")
  )
}

reject_legacy_authority_symbols() {
  local binary="$1"
  local file_description symbol status
  # Scripts are used by the unit-level bundle fixtures. Real release binaries
  # are Mach-O or ELF and must pass both their symbol table (when retained) and
  # printable-string scans. A stripped table is not treated as proof of
  # cleanliness; the resolved Cargo graph is checked before the release build.
  if ! file_description="$(file -b -- "$binary")"; then
    echo "failed to inspect production binary format: $binary" >&2
    return 1
  fi
  if [[ ! "$file_description" =~ ^(Mach-O|ELF)[[:space:]] ]]; then
    return
  fi
  if ! symbol="$(nm -a -- "$binary" 2>&1)"; then
    echo "failed to inspect production binary symbols: $binary" >&2
    return 1
  fi
  if symbol="$(LC_ALL=C grep -E -m1 \
    'KeystorePetalHost|StoreApprovalVerifier|KeystoreApprovalSignatureVerifier|SignerCache|EphemeralAgentKey|RegistrationCoordinator|AuthServices|InMemoryGrantStore|sign_hash_sync' <<<"$symbol")"; then
    status=0
  else
    status=$?
  fi
  case "$status" in
    0) ;;
    1) symbol="" ;;
    *)
      echo "failed to scan production binary symbols: $binary" >&2
      return 1
      ;;
  esac
  if [[ -n "$symbol" ]]; then
    echo "forbidden production Machine symbol in bin/$(basename "$binary"): $symbol" >&2
    return 1
  fi
}

require_binary_format() {
  local binary="$1"
  local expected_format="$2"
  local file_description
  if ! file_description="$(file -b -- "$binary")"; then
    echo "failed to inspect production binary format: $binary" >&2
    return 1
  fi
  if [[ "$file_description" != *"$expected_format"* ]]; then
    echo "$(basename "$binary") is not a $expected_format production binary" >&2
    return 1
  fi
}

reject_markers_in_paths() {
  local scope="$1"
  shift
  local marker path status
  while IFS= read -r marker; do
    [[ -z "$marker" ]] && continue
    for path in "$@"; do
      [[ ! -e "$path" && ! -L "$path" ]] && continue
      if LC_ALL=C grep -aR -F "$marker" "$path" >/dev/null; then
        echo "forbidden $scope marker: $marker" >&2
        return 1
      else
        status=$?
      fi
      if [[ "$status" -ne 1 ]]; then
        echo "failed to scan $scope for marker: $marker" >&2
        return 1
      fi
    done
  done
}

reject_global_debug_markers() {
  local root="$1"
  local scope="$2"
  reject_markers_in_paths "$scope" "$root" <<'EOF'
bloom-broker-debug-driver
assert-machine-secret-confinement
broker-audit-test-1
accepting_verifier
mint_approval
BLOOM_TRIAD_DEVELOPER_ROOT
unsafe-debug-signer
unsigned-audit-test-seam
audit-test-seam
local-integration
triad-dev-harness
triad-authority-fixture
test-only-release-key
test_credential
EOF
}

reject_global_debug_artifact_files() {
  local root="$1"
  local scope="$2"
  local path relative
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    relative="${path#"$root/"}"
    echo "forbidden $scope debug/test artifact: $relative" >&2
    return 1
  done < <(find "$root" \( -type f -o -type d \) \
    \( -name 'bloom-broker-debug-driver' -o \
       -name 'broker-audit-test-1' -o \
       -name 'triad-authority-fixture' -o \
       -name 'test-only-release-key' -o \
       -name 'test_credential' \) -print)
}

reject_machine_authority_markers() {
  local root="$1"
  local scope="$2"
  local -a paths=()
  while IFS= read -r path; do
    paths+=("$path")
  done < <(machine_artifact_paths "$root")
  ((${#paths[@]} > 0)) || return 0
  reject_markers_in_paths "$scope" "${paths[@]}" <<'EOF'
bloom.sign-hash
bloom-keystore
bloom-auth
bloom-auth-api
bloom-hyperliquid
ApprovalVerifier
AuthStoreWriter
GrantStore
InMemoryGrantStore
KeystorePetalHost
StoreApprovalVerifier
KeystoreApprovalSignatureVerifier
SignerCache
EphemeralAgentKey
RegistrationCoordinator
AuthServices
policy-session
EOF
}

[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
  echo "SOURCE_DATE_EPOCH must be an unsigned decimal integer" >&2
  exit 64
}
for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
  test -f "$staging/bin/$binary" || {
    echo "missing production binary: bin/$binary" >&2
    exit 66
  }
done
reject_machine_legacy_authority_files "$staging" "production Machine artifact"
reject_legacy_authority_symbols "$staging/bin/bloom"
reject_global_debug_artifact_files "$staging" "production"
reject_global_debug_markers "$staging" "production artifact"
reject_machine_authority_markers "$staging" "production Machine artifact"
machine_version="$(sed -n -E 's/^machine = "([^"]+)"$/\1/p' "$script_dir/compatibility-v1.toml")"
broker_version="$(sed -n -E 's/^broker = "([^"]+)"$/\1/p' "$script_dir/compatibility-v1.toml")"
signer_version="$(sed -n -E 's/^signer = "([^"]+)"$/\1/p' "$script_dir/compatibility-v1.toml")"
for identity in \
  "bloom:$machine_version" \
  "bloom-broker:$broker_version" \
  "bloom-signer:$signer_version"
do
  binary="${identity%%:*}"
  expected="${identity#*:}"
  actual="$("$staging/bin/$binary" --version | awk '{print $2}')"
  [[ "$actual" == "$expected" ]] || {
    echo "$binary version $actual is outside the compatibility matrix ($expected)" >&2
    exit 65
  }
done
test -f "$signing_key" || {
  echo "missing Ed25519 bundle signing key" >&2
  exit 66
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
payload="$work/bloom-triad"
mkdir -p "$payload"
cp -R "$staging/." "$payload/"
platform_claim="${BLOOM_PLATFORM_CLAIM:-test-unclaimed}"
case "$platform_claim" in
  linux)
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      require_binary_format "$staging/bin/$binary" 'ELF ' || exit 65
    done
    ;;
  macos-unix-principals-w0)
    [[ "$(uname -s)" == "Darwin" ]] &&
      [[ "${BLOOM_ALLOW_MACOS_UNIX_W0:-}" == "true" ]] || {
      echo "macOS W0 claim requires its disposable Darwin build lane" >&2
      exit 65
    }
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      require_binary_format "$staging/bin/$binary" 'Mach-O ' || exit 65
    done
    ;;
  macos-unix-principals)
    [[ "$(uname -s)" == "Darwin" ]] || {
      echo "production macOS claim requires a Darwin release builder" >&2
      exit 69
    }
    for binary in bloom bloom-broker bloom-signer bloom-signer-migrate; do
      require_binary_format "$staging/bin/$binary" 'Mach-O ' || exit 65
    done
    for evidence_name in \
      BLOOM_MACOS_CONFORMANCE_REPORT \
      BLOOM_MACOS_CONFORMANCE_SIGNATURE \
      BLOOM_MACOS_CONFORMANCE_PUBLIC_KEY
    do
      evidence_path="${!evidence_name:-}"
      [[ -f "$evidence_path" && ! -L "$evidence_path" ]] || {
        echo "$evidence_name must name a regular conformance input" >&2
        exit 66
      }
    done
    [[ "${BLOOM_MACOS_CONFORMANCE_KEY_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {
      echo "BLOOM_MACOS_CONFORMANCE_KEY_SHA256 must pin the reviewed conformance key" >&2
      exit 66
    }
    ;;
  test-unclaimed)
    [[ "${BLOOM_ALLOW_TEST_UNCLAIMED:-}" == "true" ]] || {
      echo "test-unclaimed bundles require BLOOM_ALLOW_TEST_UNCLAIMED=true" >&2
      exit 65
    }
    ;;
  *)
    echo "BLOOM_PLATFORM_CLAIM is invalid" >&2
    exit 64
    ;;
esac
printf '%s\n' "$platform_claim" > "$payload/PLATFORM_CLAIM"
install -m 0644 "$script_dir/compatibility-v1.toml" "$payload/compatibility-v1.toml"
mkdir -p "$payload/installer/release"
cp -R "$script_dir/../linux" "$payload/installer/linux"
mkdir -p "$payload/installer/macos"
# W0 is source-tree conformance tooling, not an installed product component.
# Copy the reviewed installer inputs individually so debug drivers, hostile
# listeners, VM orchestration, and acceptance markers can never enter a signed
# production payload through the macOS directory wholesale.
for macos_input in "$script_dir"/../macos/*; do
  [[ "$(basename "$macos_input")" == "w0" ]] && continue
  cp -R "$macos_input" "$payload/installer/macos/"
done
install -m 0755 \
  "$script_dir/install-linux.sh" \
  "$script_dir/install-macos.sh" \
  "$script_dir/macos-conformance-subject.sh" \
  "$script_dir/sign-macos-conformance-report.sh" \
  "$script_dir/verify-macos-conformance.sh" \
  "$script_dir/ssh-ed25519-verify.sh" \
  "$payload/installer/release/"
install -m 0755 "$script_dir/verify-bundle.sh" "$payload/installer/release/"
reject_machine_legacy_authority_files "$payload" "packaged Machine artifact"
reject_legacy_authority_symbols "$payload/bin/bloom"
reject_global_debug_artifact_files "$payload" "packaged"

if [[ "$platform_claim" == "macos-unix-principals" ]]; then
  install -m 0644 \
    "$BLOOM_MACOS_CONFORMANCE_REPORT" \
    "$payload/MACOS_CONFORMANCE_REPORT.json"
  install -m 0644 \
    "$BLOOM_MACOS_CONFORMANCE_SIGNATURE" \
    "$payload/MACOS_CONFORMANCE_REPORT.sig"
  install -m 0644 \
    "$BLOOM_MACOS_CONFORMANCE_PUBLIC_KEY" \
    "$payload/MACOS_CONFORMANCE_REPORT.pub"
fi

if [[ "$platform_claim" == "macos-unix-principals" ||
  "$platform_claim" == "macos-unix-principals-w0" ]]
then
  if identity_shaped_files="$(find "$payload" -type f \
    \( -name '*identity*.json' -o -name '*credentials*' \) -print)"; then
    :
  else
    echo "failed to scan bundle for identity-shaped files" >&2
    exit 65
  fi
  if [[ -n "$identity_shaped_files" ]]; then
    echo "macOS Unix-principal bundle contains a private identity-shaped file" >&2
    exit 65
  fi
  if LC_ALL=C grep -aER \
    '"[^"]*(private_key_seed_hex|signing_seed_hex|state_authentication_key_hex)"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' \
    "$payload" >/dev/null
  then
    echo "macOS Unix-principal bundle contains private key material" >&2
    exit 65
  else
    grep_status=$?
    if [[ "$grep_status" -ne 1 ]]; then
      echo "failed to scan bundle for private key material" >&2
      exit 65
    fi
  fi
fi

reject_global_debug_markers "$payload" "packaged artifact"
reject_machine_authority_markers "$payload" "packaged Machine artifact"

for revision_name in BLOOM_MACHINE_SHA BLOOM_BROKER_SHA BLOOM_SIGNER_SHA; do
  revision="${!revision_name:-}"
  [[ "$revision" =~ ^[0-9a-f]{7,64}$ ]] || {
    echo "$revision_name must be a lowercase git commit ID" >&2
    exit 64
  }
  printf '%s=%s\n' "$revision_name" "$revision"
done | LC_ALL=C sort > "$payload/SOURCE_REVISIONS"

if [[ "$platform_claim" == "macos-unix-principals" ]]; then
  "$script_dir/verify-macos-conformance.sh" \
    "$payload" \
    "$BLOOM_MACOS_CONFORMANCE_KEY_SHA256"
fi

"$script_dir/ssh-ed25519-public-key.sh" \
  "$signing_key" \
  "$payload/RELEASE_PUBLIC_KEY.pem"
(
  cd "$payload"
  find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.new ! -name RELEASE_SIGNATURE -print |
    LC_ALL=C sort |
    while IFS= read -r file; do
      shasum -a 256 "$file"
    done
) > "$payload/SHA256SUMS.new"
mv "$payload/SHA256SUMS.new" "$payload/SHA256SUMS"
"$script_dir/ssh-ed25519-sign.sh" \
  "$signing_key" \
  bloom-release-payload-v1 \
  "$payload/SHA256SUMS" \
  "$payload/RELEASE_SIGNATURE"
# The single-quoted expression is Perl source, not a shell interpolation.
# shellcheck disable=SC2016
find "$payload" -print0 |
  xargs -0 perl -e '$timestamp = shift; utime $timestamp, $timestamp, @ARGV' \
    "$source_date_epoch"

mkdir -p "$(dirname "$output")"
output_dir="$(cd "$(dirname "$output")" && pwd -P)"
output="$output_dir/$(basename "$output")"
archive_tmp="$work/archive.tar"
(
  cd "$work"
  find bloom-triad -print | LC_ALL=C sort > archive-files
  "$tar_command" \
  --format=ustar \
  --uid=0 \
  --gid=0 \
  --uname=root \
  --gname=root \
  --no-recursion \
  -cf "$archive_tmp" \
  -T archive-files
)
gzip -n -9 < "$archive_tmp" > "$output"
(
  cd "$output_dir"
  shasum -a 256 "$(basename "$output")" > "$(basename "$output").sha256"
)
"$script_dir/ssh-ed25519-sign.sh" \
  "$signing_key" \
  bloom-release-archive-v1 \
  "$output.sha256" \
  "$output.sig"
"$script_dir/ssh-ed25519-public-key.sh" "$signing_key" "$output.pub"
