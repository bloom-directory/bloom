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
readonly staging_root="$output_root/triad-staging"
readonly distribution_root="$output_root/triad-dist"
readonly verified_root="$output_root/verified"
readonly release_key="$output_root/w0-release-key"

[[ "$(uname -s)" == "Darwin" ]] || {
  echo "Tart W0 guest build requires Darwin" >&2
  exit 69
}
for path in "$source_bundle_root" "$output_root"; do
  [[ -d "$path" ]] || {
    echo "missing Tart shared directory: $path" >&2
    exit 69
  }
done
for command_name in cargo git jq ssh-keygen tar; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "missing Tart W0 guest build dependency: $command_name" >&2
    exit 69
  }
done

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

mkdir -p \
  "$staging_root/bin" \
  "$distribution_root" \
  "$verified_root"

cargo build \
  --manifest-path "$main_root/Cargo.toml" \
  --release \
  -p bloom \
  --locked
cargo build \
  --manifest-path "$broker_root/Cargo.toml" \
  --release \
  -p bloom-broker \
  --locked
cargo build \
  --manifest-path "$signer_root/Cargo.toml" \
  --release \
  -p bloom-signer \
  --locked

cp "$CARGO_TARGET_DIR/release/bloom" "$staging_root/bin/"
cp "$CARGO_TARGET_DIR/release/bloom-broker" "$staging_root/bin/"
cp "$CARGO_TARGET_DIR/release/bloom-signer" "$staging_root/bin/"
cp "$CARGO_TARGET_DIR/release/bloom-signer-migrate" "$staging_root/bin/"

ssh-keygen -q -t ed25519 -N '' -f "$release_key"

export BLOOM_PLATFORM_CLAIM=macos-unix-principals-w0
export BLOOM_ALLOW_MACOS_UNIX_W0=true
export BLOOM_MACHINE_SHA
export BLOOM_BROKER_SHA
export BLOOM_SIGNER_SHA
BLOOM_MACHINE_SHA="$(git -C "$main_root" rev-parse HEAD)"
BLOOM_BROKER_SHA="$(git -C "$broker_root" rev-parse HEAD)"
BLOOM_SIGNER_SHA="$(git -C "$signer_root" rev-parse HEAD)"

"$main_root/packaging/triad/release/build-bundle.sh" \
  "$staging_root" \
  "$distribution_root/bloom-triad.tar.gz" \
  "$release_key" \
  1700000000
"$main_root/packaging/triad/release/verify-bundle.sh" \
  "$distribution_root/bloom-triad.tar.gz" \
  "$distribution_root/bloom-triad.tar.gz.sha256" \
  "$distribution_root/bloom-triad.tar.gz.sig" \
  "$distribution_root/bloom-triad.tar.gz.pub"

tar -xzf \
  "$distribution_root/bloom-triad.tar.gz" \
  -C "$verified_root"

echo "local Tart W0 candidate built at $verified_root/bloom-triad"
