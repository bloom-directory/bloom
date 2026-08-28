#!/usr/bin/env bash
set -euo pipefail

main_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
broker_root="${BLOOM_BROKER_ROOT:-$main_root/../bloom-broker}"
signer_root="${BLOOM_SIGNER_ROOT:-$main_root/../bloom-signer}"
test_key=false
output_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-signing-key)
      test_key=true
      shift
      ;;
    --output-dir)
      [[ $# -ge 2 && -n "$2" ]] || {
        echo "--output-dir requires a directory" >&2
        exit 64
      }
      output_dir="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [--test-signing-key] [--output-dir DIR]" >&2
      exit 64
      ;;
  esac
done
$test_key || {
  echo "the release gate requires --test-signing-key; use the isolated candidate-signing lane for production" >&2
  exit 64
}

compat_revision() {
  local key="$1"
  sed -n -E "s/^$key = \"([0-9a-f]{40})\"$/\\1/p" \
    "$main_root/packaging/triad/release/compatibility-v1.toml"
}
expected_broker_sha="$(compat_revision broker_commit)"
expected_signer_sha="$(compat_revision signer_commit)"
[[ -n "$expected_broker_sha" && -n "$expected_signer_sha" ]] || {
  echo "compatibility matrix does not contain full Broker and Signer revisions" >&2
  exit 65
}
[[ "$(git -C "$broker_root" rev-parse HEAD)" == "$expected_broker_sha" ]] || {
  echo "Broker checkout does not match compatibility matrix revision" >&2
  exit 65
}
[[ "$(git -C "$signer_root" rev-parse HEAD)" == "$expected_signer_sha" ]] || {
  echo "Signer checkout does not match compatibility matrix revision" >&2
  exit 65
}
for root in "$main_root" "$broker_root" "$signer_root"; do
  test -f "$root/Cargo.toml" || {
    echo "missing triad workspace: $root" >&2
    exit 66
  }
  git -C "$root" diff --quiet
  git -C "$root" diff --cached --quiet
  while IFS= read -r untracked; do
    case "$root/$untracked" in
      "$main_root/docs/.DS_Store"|\
      "$main_root/docs/specs/2026-07-23-triad-process-architecture.md"|\
      "$main_root/docs/specs/2026-07-24-triad-implementability-review.md")
        ;;
      *)
        echo "untracked input prevents source attribution: $root/$untracked" >&2
        exit 65
        ;;
    esac
  done < <(git -C "$root" ls-files --others --exclude-standard)
done

"$main_root/packaging/triad/release/check-machine-authority-boundary.sh" --require-clean
python3 "$main_root/packaging/triad/release/check-legacy-hash-only-routes.py"
python3 "$main_root/packaging/triad/release/check-external-pins.py" --remote \
  "$main_root/Cargo.toml" "$broker_root/Cargo.toml" "$signer_root/Cargo.toml"
python3 "$main_root/packaging/triad/release/check-default-petal-releases.py" --remote

resolved_machine_features="$(cargo tree --manifest-path "$main_root/Cargo.toml" -p bloom -e normal,build,features --prefix none)"
for forbidden_feature in unsigned-audit-test-seam audit-test-seam; do
  if grep -F "feature \"$forbidden_feature\"" <<<"$resolved_machine_features" >/dev/null; then
    echo "forbidden production Machine feature resolved: $forbidden_feature" >&2
    exit 65
  fi
done

for root in "$main_root" "$broker_root" "$signer_root"; do
  (
    cd "$root"
    cargo fmt --all -- --check
  )
done
(
  cd "$main_root"
  cargo clippy --workspace --all-targets --locked -- -D warnings
)

cargo build --manifest-path "$main_root/Cargo.toml" --release -p bloom --locked
cargo build --manifest-path "$broker_root/Cargo.toml" --release -p bloom-broker --locked
cargo build --manifest-path "$signer_root/Cargo.toml" --release -p bloom-signer --locked

work="$(mktemp -d)"
trap 'find "$work" -depth -delete' EXIT
mkdir -p "$work/staging/bin" "$work/dist-a" "$work/dist-b"
cp "$main_root/target/release/bloom" "$work/staging/bin/"
cp "$broker_root/target/release/bloom-broker" "$work/staging/bin/"
cp "$signer_root/target/release/bloom-signer" "$work/staging/bin/"
cp "$signer_root/target/release/bloom-signer-migrate" "$work/staging/bin/"
signing_key="$work/test-only-release-key"
/usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$signing_key"
export BLOOM_PLATFORM_CLAIM="test-unclaimed"
export BLOOM_ALLOW_TEST_UNCLAIMED="true"
artifact_name="bloom-triad-test-unclaimed.tar.gz"

export BLOOM_MACHINE_SHA BLOOM_BROKER_SHA BLOOM_SIGNER_SHA
BLOOM_MACHINE_SHA="$(git -C "$main_root" rev-parse HEAD)"
BLOOM_BROKER_SHA="$(git -C "$broker_root" rev-parse HEAD)"
BLOOM_SIGNER_SHA="$(git -C "$signer_root" rev-parse HEAD)"
builder="$main_root/packaging/triad/release/build-bundle.sh"
verifier="$main_root/packaging/triad/release/verify-bundle.sh"
for output in \
  "$work/dist-a/$artifact_name" \
  "$work/dist-b/$artifact_name"
do
  "$builder" "$work/staging" "$output" "$signing_key" "${SOURCE_DATE_EPOCH:-1700000000}"
  "$verifier" "$output" "$output.sha256" "$output.sig" "$output.pub"
done
cmp "$work/dist-a/$artifact_name" "$work/dist-b/$artifact_name"
mkdir -p "$work/verified"
tar -xzf "$work/dist-a/$artifact_name" -C "$work/verified"
bundle="$work/verified/bloom-triad"
grep -Fx "BLOOM_MACHINE_SHA=$BLOOM_MACHINE_SHA" "$bundle/SOURCE_REVISIONS" >/dev/null
grep -Fx "BLOOM_BROKER_SHA=$BLOOM_BROKER_SHA" "$bundle/SOURCE_REVISIONS" >/dev/null
grep -Fx "BLOOM_SIGNER_SHA=$BLOOM_SIGNER_SHA" "$bundle/SOURCE_REVISIONS" >/dev/null
for binary in bloom bloom-broker bloom-signer; do
  test "$("$bundle/bin/$binary" --version)" = \
    "$("$work/staging/bin/$binary" --version)"
done
for root in "$main_root" "$broker_root" "$signer_root"; do
  (
    cd "$root"
    if [[ "$root" == "$main_root" && "$(uname -s)" != "Darwin" ]]; then
      BLOOM_ACCEPTANCE_BUNDLE_ROOT="$bundle" \
        cargo test --workspace --locked -- --skip macos_
    else
      BLOOM_ACCEPTANCE_BUNDLE_ROOT="$bundle" cargo test --workspace --locked
    fi
  )
done
install_payload="$work/install-payload"
cp -R "$bundle" "$install_payload"
if [[ "$BLOOM_PLATFORM_CLAIM" == "macos-unix-principals" ]]; then
  "$bundle/installer/release/verify-macos-conformance.sh" "$bundle"
else
  mkdir -p "$install_payload/config"
  for config in \
    edge-manifest.json \
    broker.json \
    signer.json \
    machine-identity.json \
    broker-identity.json \
    signer-identity.json \
    revoke-identity.json \
    session-identity.json \
    installer-identity.json \
    provenance-catalog.json
  do
    printf '{}\n' > "$install_payload/config/$config"
  done
  mkdir -p "$work/linux-root"
  "$install_payload/installer/release/install-linux.sh" \
    install "$work/linux-root" 1000 releaseuser "$install_payload"
  test -x "$work/linux-root/usr/libexec/bloom/bloom-broker"
  test -f "$work/linux-root/etc/bloom/1000/signer/config.json"
  "$install_payload/installer/release/install-linux.sh" \
    uninstall "$work/linux-root" 1000 delete-bloom-login-1000
  test ! -e "$work/linux-root/etc/bloom/1000"

  mkdir -p "$work/macos-root"
  release_digest="$(shasum -a 256 "$install_payload/SHA256SUMS" | awk '{print $1}')"
  BLOOM_ALLOW_TEST_UNCLAIMED=true \
    BLOOM_MACOS_BROKER_UID=250501 \
    BLOOM_MACOS_SIGNER_UID=250502 \
    BLOOM_MACOS_BROKER_GID=260499 \
    BLOOM_MACOS_SIGNER_GID=260500 \
    BLOOM_MACOS_MACHINE_BROKER_GID=260501 \
    BLOOM_MACOS_BROKER_SIGNER_GID=260502 \
    BLOOM_MACOS_REVOKE_GID=260503 \
    BLOOM_RELEASE_DIGEST="$release_digest" \
    "$install_payload/installer/release/install-macos.sh" \
      install "$work/macos-root" 501 releaseuser "$install_payload"
  test -x "$work/macos-root/usr/local/libexec/bloom/current/bloom-broker"
  test -f \
    "$work/macos-root/Library/Application Support/BloomTriad/enrollments/501.json"
  "$install_payload/installer/release/install-macos.sh" \
    uninstall "$work/macos-root" 501 delete-bloom-login-501
  test ! -e \
    "$work/macos-root/Library/Application Support/BloomTriad/enrollments/501.json"
fi
if [[ -n "$output_dir" ]]; then
  mkdir -p "$output_dir"
  output_dir="$(cd "$output_dir" && pwd -P)"
  for suffix in "" .sha256 .sig .pub; do
    [[ ! -e "$output_dir/$artifact_name$suffix" ]] || {
      echo "release output already exists: $output_dir/$artifact_name$suffix" >&2
      exit 65
    }
  done
  for suffix in "" .sha256 .sig .pub; do
    install -m 0644 \
      "$work/dist-a/$artifact_name$suffix" \
      "$output_dir/$artifact_name$suffix"
  done
  echo "Bloom triad release artifact: $output_dir/$artifact_name"
fi
echo "Bloom triad release gate passed for $BLOOM_MACHINE_SHA / $BLOOM_BROKER_SHA / $BLOOM_SIGNER_SHA"
