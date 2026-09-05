#!/usr/bin/env bash
set -euo pipefail

main_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
broker_root="${BLOOM_BROKER_ROOT:-$main_root/../bloom-broker}"
signer_root="${BLOOM_SIGNER_ROOT:-$main_root/../bloom-signer}"
test_key=false
if [[ "${1:-}" == "--test-signing-key" ]]; then
  test_key=true
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--test-signing-key]" >&2
  exit 64
fi

for root in "$main_root" "$broker_root" "$signer_root"; do
  test -f "$root/Cargo.toml" || {
    echo "missing triad workspace: $root" >&2
    exit 66
  }
  git -C "$root" diff --quiet
  git -C "$root" diff --cached --quiet
  if [[ -n "$(git -C "$root" ls-files --others --exclude-standard)" ]]; then
    echo "untracked input prevents source attribution: $root" >&2
    git -C "$root" ls-files --others --exclude-standard >&2
    exit 65
  fi
done

"$main_root/packaging/triad/release/check-machine-authority-boundary.sh" --require-clean
python3 "$main_root/packaging/triad/release/check-legacy-hash-only-routes.py"
python3 "$main_root/packaging/triad/release/check-external-pins.py" --remote \
  "$main_root/Cargo.toml" "$broker_root/Cargo.toml" "$signer_root/Cargo.toml"
python3 "$main_root/packaging/triad/release/check-default-petal-releases.py" --remote

for root in "$main_root" "$broker_root" "$signer_root"; do
  (
    cd "$root"
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
  )
done

# Preserve proof that the ordinary production build remains incapable of the
# mainnet canary before deliberately compiling the separate artifact class.
cargo build --manifest-path "$main_root/Cargo.toml" --release -p bloom --locked \
  --no-default-features --features mount,bytecode-decompile
"$main_root/packaging/triad/release/check-production-machine-binary.sh" \
  "$main_root/target/release/bloom"

BLOOM_MAINNET_CANARY_ARTIFACT=1 \
  cargo build --manifest-path "$main_root/Cargo.toml" --release -p bloom --locked \
    --no-default-features --features mount,bytecode-decompile,mainnet-canary
cargo build --manifest-path "$broker_root/Cargo.toml" --release -p bloom-broker --locked
cargo build --manifest-path "$signer_root/Cargo.toml" --release -p bloom-signer --locked

work="$(mktemp -d)"
trap 'find "$work" -depth -delete' EXIT
mkdir -p "$work/staging/bin" "$work/dist-a" "$work/dist-b"
cp "$main_root/target/release/bloom" "$work/staging/bin/"
cp "$broker_root/target/release/bloom-broker" "$work/staging/bin/"
cp "$signer_root/target/release/bloom-signer" "$work/staging/bin/"
cp "$signer_root/target/release/bloom-signer-migrate" "$work/staging/bin/"

if $test_key; then
  signing_key="$work/test-only-release-key"
  /usr/bin/ssh-keygen -q -t ed25519 -N '' -f "$signing_key"
  export BLOOM_PLATFORM_CLAIM="test-unclaimed"
  export BLOOM_ALLOW_TEST_UNCLAIMED="true"
else
  signing_key="${TRIAD_RELEASE_SIGNING_KEY:-}"
  test -f "$signing_key" || {
    echo "TRIAD_RELEASE_SIGNING_KEY must name the reviewed Ed25519 release key" >&2
    exit 66
  }
  [[ "$(uname -s)" == Linux ]] || {
    echo "the Solana mainnet canary release gate requires Linux" >&2
    exit 69
  }
  export BLOOM_PLATFORM_CLAIM="linux"
fi

export BLOOM_ARTIFACT_CLASS="solana-mainnet-canary-v1"
export BLOOM_ALLOW_SOLANA_MAINNET_CANARY_BUNDLE="true"
export BLOOM_MACHINE_SHA BLOOM_BROKER_SHA BLOOM_SIGNER_SHA
BLOOM_MACHINE_SHA="$(git -C "$main_root" rev-parse HEAD)"
BLOOM_BROKER_SHA="$(git -C "$broker_root" rev-parse HEAD)"
BLOOM_SIGNER_SHA="$(git -C "$signer_root" rev-parse HEAD)"
builder="$main_root/packaging/triad/release/build-bundle.sh"
verifier="$main_root/packaging/triad/release/verify-bundle.sh"

# A canary Machine is never accepted by the production-default builder path.
if env -u BLOOM_ARTIFACT_CLASS \
  "$builder" "$work/staging" "$work/production-must-refuse.tar.gz" \
    "$signing_key" "${SOURCE_DATE_EPOCH:-1700000000}" 2>"$work/production-refusal.log"
then
  echo "production bundle builder accepted a canary Machine" >&2
  exit 65
fi
grep -F "forbidden production artifact marker" "$work/production-refusal.log" >/dev/null

for output in \
  "$work/dist-a/bloom-triad-solana-canary.tar.gz" \
  "$work/dist-b/bloom-triad-solana-canary.tar.gz"
do
  "$builder" "$work/staging" "$output" "$signing_key" \
    "${SOURCE_DATE_EPOCH:-1700000000}"
  if env -u BLOOM_ALLOW_SOLANA_MAINNET_CANARY_BUNDLE \
    "$verifier" "$output" "$output.sha256" "$output.sig" "$output.pub"
  then
    echo "canary bundle verified without the explicit opt in" >&2
    exit 65
  fi
  "$verifier" "$output" "$output.sha256" "$output.sig" "$output.pub"
done
cmp "$work/dist-a/bloom-triad-solana-canary.tar.gz" \
  "$work/dist-b/bloom-triad-solana-canary.tar.gz"

mkdir -p "$work/verified"
tar -xzf "$work/dist-a/bloom-triad-solana-canary.tar.gz" -C "$work/verified"
bundle="$work/verified/bloom-triad"
grep -Fx "solana-mainnet-canary-v1" "$bundle/ARTIFACT_CLASS" >/dev/null
grep -Fx "BLOOM_MACHINE_SHA=$BLOOM_MACHINE_SHA" "$bundle/SOURCE_REVISIONS" >/dev/null
grep -Fx "BLOOM_BROKER_SHA=$BLOOM_BROKER_SHA" "$bundle/SOURCE_REVISIONS" >/dev/null
grep -Fx "BLOOM_SIGNER_SHA=$BLOOM_SIGNER_SHA" "$bundle/SOURCE_REVISIONS" >/dev/null

BLOOM_MAINNET_CANARY_ARTIFACT=1 \
  cargo test --manifest-path "$main_root/Cargo.toml" -p bloom-proto --locked \
    --features mainnet-canary --lib canary::
BLOOM_MAINNET_CANARY_ARTIFACT=1 \
  cargo test --manifest-path "$main_root/Cargo.toml" -p bloom-solana --locked \
    --features mainnet-canary --test mainnet_canary_gate
BLOOM_MAINNET_CANARY_ARTIFACT=1 \
  cargo test --manifest-path "$main_root/Cargo.toml" -p bloom-solana-tx --locked \
    --features mainnet-canary

install_payload="$work/install-payload"
cp -R "$bundle" "$install_payload"
mkdir -p "$install_payload/config" "$work/linux-root"
for config in \
  edge-manifest.json \
  broker.json \
  signer.json \
  broker-identity.json \
  signer-identity.json
do
  printf '{}\n' >"$install_payload/config/$config"
done
printf 'time.cloudflare.com\ntime.nist.gov\n' \
  >"$install_payload/config/nts-servers.conf"
if env -u BLOOM_ALLOW_SOLANA_MAINNET_CANARY_BUNDLE \
  "$install_payload/installer/release/install-linux.sh" \
    install "$work/linux-root" 1000 releaseuser "$install_payload"
then
  echo "Linux installer accepted a canary bundle without the explicit opt in" >&2
  exit 65
fi
"$install_payload/installer/release/install-linux.sh" \
  install "$work/linux-root" 1000 releaseuser "$install_payload"
cmp "$bundle/ARTIFACT_CLASS" "$work/linux-root/etc/bloom/1000/ARTIFACT_CLASS"
cmp "$bundle/bin/bloom" "$work/linux-root/usr/libexec/bloom/bloom"

archive="$work/dist-a/bloom-triad-solana-canary.tar.gz"
archive_sha256="$(shasum -a 256 "$archive" | awk '{print $1}')"
binary_sha256="$(shasum -a 256 "$bundle/bin/bloom" | awk '{print $1}')"
echo "Bloom Solana mainnet canary release gate passed"
echo "source revisions: $BLOOM_MACHINE_SHA / $BLOOM_BROKER_SHA / $BLOOM_SIGNER_SHA"
echo "archive SHA-256: $archive_sha256"
echo "Machine SHA-256: $binary_sha256"
