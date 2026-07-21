#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-$repo_root/dist}"
catalog_source="$repo_root/crates/bloom/src/github_source.rs"
commit="$(sed -n -E 's/^const POLYMARKET_PARITY_COMMIT: &str = "([0-9a-f]{40})";/\1/p' "$catalog_source")"

if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "could not read POLYMARKET_PARITY_COMMIT from $catalog_source" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/bloom-preinstalled-polymarket.XXXXXX")"
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

git clone --quiet --no-checkout \
  https://github.com/bloom-directory/bloom-petal-polymarket.git \
  "$work_dir/source"
git -C "$work_dir/source" checkout --quiet --detach "$commit"
"$work_dir/source/scripts/build.sh"

mkdir -p "$output_dir"
archive="$output_dir/polymarket-$commit.petal.tar"
cargo run --quiet --locked --manifest-path "$repo_root/Cargo.toml" -p bloom -- \
  petals build "$work_dir/source" --out "$archive"
gzip -n -9 "$archive"
echo "$archive.gz"
